// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* SentinelAI M3B replay harness: runs the SAME event-handling code as the BPF program
 * (sentinel_core.h) in userspace, driven by a synthetic event script, with bounded arrays standing
 * in for the BPF maps. It prints the same line protocol as the loader, so fixture tests exercise the
 * correlation logic, the dump format and the Python parser end to end without loading BPF.
 *
 * Script (one command per line; '#' starts a comment):
 *   cfg <cgroup_id> <cgroup_level> <netns_inum> <lat_stale_ns> <sirq_stale_ns>   (first command)
 *   t <ns>                      set the clock (must not go backwards unless "t! <ns>")
 *   cpu <n>                     set the current CPU (< ncpu)
 *   wakeup <tid> <in_target>    sched_wakeup
 *   wakeup_new <tid> <in_target>
 *   switch <prev_tid> <next_tid>
 *   sirq_entry <vec> / sirq_exit <vec>
 *   retrans <netns_inum>
 *   kfree <netns_inum> <reason>  (number, or a skb_drop_reason name from the kernel BTF)
 *   dump                        print one sample line
 *
 * Usage: sentinel_replay [--ncpu N] [--wake-capacity N] [--serve] SCRIPT
 *   --serve: run the script up to each "dump", and print that sample only when an 's' arrives on
 *   stdin (the loader's request protocol); 'q' or EOF ends.
 */
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "sentinel_host.h"

#define SN_REPLAY_MAX_CPUS 64

static __u64 r_now;
static __u32 r_cpu;
static int r_ncpu = 4;
static struct sn_cfg r_cfg;

/* LRU map: fixed capacity, least-recently-used entry evicted on insert when full */
static int r_cap = SN_WAKE_MAX;
static __u32 r_key[SN_WAKE_MAX];
static struct sn_wake r_val[SN_WAKE_MAX];
static __u64 r_age[SN_WAKE_MAX];
static int r_used[SN_WAKE_MAX];
static __u64 r_clock;

static struct sn_hist r_hist[SN_REPLAY_MAX_CPUS];
static __u64 r_stats[SN_REPLAY_MAX_CPUS][SN_ST_MAX];
static struct sn_sirq_start r_sstart[SN_REPLAY_MAX_CPUS];
static struct sn_sirq_acc r_sacc[SN_REPLAY_MAX_CPUS][SN_NR_VEC];
static __u64 r_retrans[SN_REPLAY_MAX_CPUS];
static __u64 r_kfree[SN_REPLAY_MAX_CPUS][SN_KFREE_SLOTS + 1];

static int r_find(__u32 k)
{
	int i;

	for (i = 0; i < r_cap; i++)
		if (r_used[i] && r_key[i] == k)
			return i;
	return -1;
}

static struct sn_wake *r_lookup(__u32 k)
{
	int i = r_find(k);

	if (i < 0)
		return NULL;
	r_age[i] = ++r_clock;
	return &r_val[i];
}

static int r_update(__u32 k, struct sn_wake *w, int flags)
{
	int i = r_find(k), j, victim = -1;

	if (i >= 0) {
		if (flags == 1)
			return -SN_EEXIST;
		r_val[i] = *w;
		r_age[i] = ++r_clock;
		return 0;
	}
	for (j = 0; j < r_cap; j++) {
		if (!r_used[j]) {
			victim = j;
			break;
		}
		if (victim < 0 || r_age[j] < r_age[victim])
			victim = j;
	}
	r_used[victim] = 1;
	r_key[victim] = k;
	r_val[victim] = *w;
	r_age[victim] = ++r_clock;
	return 0;
}

static int r_delete(__u32 k)
{
	int i = r_find(k);

	if (i < 0)
		return -ENOENT;
	r_used[i] = 0;
	return 0;
}

#define SN_NOW() (r_now)
#define SN_CPU() (r_cpu)
#define SN_CFG(f) (r_cfg.f)
#define SN_ANY 0
#define SN_NOEXIST 1
#define SN_WAKE_LOOKUP(tid) r_lookup((tid))
#define SN_WAKE_UPDATE(tid, w, flg) r_update((tid), (w), (flg))
#define SN_WAKE_DELETE(tid) r_delete((tid))
#define SN_HIST() (&r_hist[r_cpu])
#define SN_STAT(i) ((i) < SN_ST_MAX ? &r_stats[r_cpu][(i)] : NULL)
#define SN_SIRQ_START() (&r_sstart[r_cpu])
#define SN_SIRQ_ACC(v) ((v) < SN_NR_VEC ? &r_sacc[r_cpu][(v)] : NULL)
#define SN_RETRANS() (&r_retrans[r_cpu])
#define SN_KFREE(s) ((s) <= SN_KFREE_SLOTS ? &r_kfree[r_cpu][(s)] : NULL)

#include "sentinel_core.h"

static char r_names[SN_KFREE_SLOTS][SN_REASON_NAME];
static struct sn_state r_state;

static void r_collect(struct sn_state *st)
{
	int c, i;

	memset(st, 0, sizeof(*st));
	st->ncpu = r_ncpu;
	for (c = 0; c < r_ncpu; c++) {
		for (i = 0; i < SN_HIST_BUCKETS; i++)
			st->hist[i] += r_hist[c].slots[i];
		for (i = 0; i < SN_ST_MAX; i++)
			st->stats[i] += r_stats[c][i];
		for (i = 0; i < SN_NR_VEC; i++)
			st->sirq[c][i] = r_sacc[c][i];
		st->retrans += r_retrans[c];
		for (i = 0; i <= SN_KFREE_SLOTS; i++)
			st->kfree[i] += r_kfree[c][i];
	}
}

static int r_reason(const char *s, __u32 *out)
{
	char *end;
	unsigned long v;
	int i;

	errno = 0;
	v = strtoul(s, &end, 10);
	if (!errno && !*end && *s) {
		*out = (__u32)v;
		return 0;
	}
	for (i = 0; i < SN_KFREE_SLOTS; i++)
		if (r_names[i][0] && !strcmp(r_names[i], s)) {
			*out = (__u32)i;
			return 0;
		}
	return -1;
}

static void r_die(int line, const char *msg)
{
	fprintf(stderr, "sentinel_replay: line %d: %s\n", line, msg);
	exit(65);
}

/* wait for a request on stdin in --serve mode: 1 = sample requested, 0 = stop */
static int r_wait_request(void)
{
	char c;

	for (;;) {
		ssize_t n = read(STDIN_FILENO, &c, 1);

		if (n <= 0 || c == 'q')
			return 0;
		if (c == 's')
			return 1;
	}
}

int main(int argc, char **argv)
{
	unsigned long long a, b, c, d, e;
	char line[256], cmd[32], arg1[96];
	int serve = 0, lineno = 0, have_cfg = 0, i;
	__u64 seq = 0;
	FILE *f;

	for (i = 1; i < argc - 1; i++) {
		if (!strcmp(argv[i], "--serve")) {
			serve = 1;
		} else if (!strcmp(argv[i], "--ncpu") && i + 1 < argc - 1) {
			r_ncpu = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--wake-capacity") && i + 1 < argc - 1) {
			r_cap = atoi(argv[++i]);
		} else {
			fprintf(stderr, "sentinel_replay: unknown option %s\n", argv[i]);
			return 64;
		}
	}
	if (argc < 2 || r_ncpu < 1 || r_ncpu > SN_REPLAY_MAX_CPUS || r_cap < 1 || r_cap > SN_WAKE_MAX) {
		fprintf(stderr, "usage: sentinel_replay [--ncpu N<=64] [--wake-capacity N] [--serve] SCRIPT\n");
		return 64;
	}
	if (sn_reason_names(r_names) < 0) {
		sn_print_terminal(stdout, "unavailable", "kernel BTF skb_drop_reason not readable");
		return 2;
	}
	f = fopen(argv[argc - 1], "r");
	if (!f) {
		fprintf(stderr, "sentinel_replay: cannot open script\n");
		return 66;
	}
	while (fgets(line, sizeof(line), f)) {
		char *hash = strchr(line, '#');
		int n;

		lineno++;
		if (hash)
			*hash = 0;
		n = sscanf(line, "%31s %95s %llu %llu %llu %llu", cmd, arg1, &b, &c, &d, &e);
		if (n <= 0)
			continue;
		a = strtoull(n >= 2 ? arg1 : "0", NULL, 10);
		if (!have_cfg && strcmp(cmd, "cfg"))
			r_die(lineno, "cfg must come first");
		if (!strcmp(cmd, "cfg") && n == 6) {
			r_cfg.cgroup_id = a;
			r_cfg.cgroup_level = (__u32)b;
			r_cfg.netns_inum = (__u32)c;
			r_cfg.lat_stale_ns = d;
			r_cfg.sirq_stale_ns = e;
			have_cfg = 1;
			sn_print_meta(stdout, "sentinel_replay", &r_cfg, r_ncpu, r_names);
		} else if (!strcmp(cmd, "t") && n == 2) {
			if (a < r_now)
				r_die(lineno, "clock went backwards (use t! to force)");
			r_now = a;
		} else if (!strcmp(cmd, "t!") && n == 2) {
			r_now = a;
		} else if (!strcmp(cmd, "cpu") && n == 2) {
			if (a >= (unsigned long long)r_ncpu)
				r_die(lineno, "cpu out of range");
			r_cpu = (__u32)a;
		} else if (!strcmp(cmd, "wakeup") && n == 3) {
			sn_on_wakeup((__u32)a, (int)b, 0);
		} else if (!strcmp(cmd, "wakeup_new") && n == 3) {
			sn_on_wakeup((__u32)a, (int)b, 1);
		} else if (!strcmp(cmd, "switch") && n == 3) {
			sn_on_switch((__u32)a, (__u32)b);
		} else if (!strcmp(cmd, "sirq_entry") && n == 2) {
			sn_on_softirq_entry((__u32)a);
		} else if (!strcmp(cmd, "sirq_exit") && n == 2) {
			sn_on_softirq_exit((__u32)a);
		} else if (!strcmp(cmd, "retrans") && n == 2) {
			sn_on_retransmit((__u32)a);
		} else if (!strcmp(cmd, "kfree") && n >= 2) {
			char rs[96];
			__u32 reason;

			if (sscanf(line, "%*s %*s %95s", rs) != 1 || r_reason(rs, &reason))
				r_die(lineno, "unknown kfree reason");
			sn_on_kfree((__u32)a, reason);
		} else if (!strcmp(cmd, "dump") && n == 1) {
			if (serve && !r_wait_request())
				break;
			r_collect(&r_state);
			sn_print_sample(stdout, &r_state, ++seq, r_now);
		} else {
			r_die(lineno, "malformed command");
		}
	}
	fclose(f);
	if (serve)
		sn_print_terminal(stdout, "end", "script finished");
	return 0;
}
