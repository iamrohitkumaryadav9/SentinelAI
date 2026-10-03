// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* SentinelAI M3B loader: opens, configures, loads and attaches the CO-RE skeleton, then answers
 * sample requests on stdin with cumulative counters on stdout (protocol: sentinel_host.h).
 *
 * Modes
 *   --version        print compiled and linked libbpf versions; no BPF object is touched
 *   --check-open     open the embedded object (ELF + BTF parse) and list programs/maps; no load
 *   (default)        load + attach (requires CAP_BPF + CAP_PERFMON or root), then serve requests
 *
 * Observation only: no diagnosis, no thresholds. Bounded: no queue (one request -> one line), the
 * process exits at --max-seconds, on stdin EOF / "q", or on SIGINT/SIGTERM. Fails closed: any
 * error prints an "unavailable" line and exits non-zero; it never prints fabricated counters.
 */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "sentinel_host.h"
#include "sentinel.skel.h"

#define SN_MAX_SECONDS_LIMIT 86400

static volatile sig_atomic_t sn_stop;

static void sn_on_signal(int sig)
{
	(void)sig;
	sn_stop = 1;
}

static int sn_silent(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_WARN)
		return vfprintf(stderr, fmt, args);
	return 0;
}

static __u64 sn_mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static int sn_parse_u64(const char *s, unsigned long long max, unsigned long long *out)
{
	char *end;
	unsigned long long v;

	if (!s || !*s || *s == '-')
		return -1;
	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno || *end || v > max)
		return -1;
	*out = v;
	return 0;
}

static int sn_version(void)
{
	int ok = libbpf_major_version() == LIBBPF_MAJOR_VERSION && libbpf_minor_version() == LIBBPF_MINOR_VERSION;

	printf("{\"producer\":\"sentinel_loader\",\"version\":\"%s\",\"libbpf_compiled\":\"%d.%d\","
	       "\"libbpf_linked\":\"%u.%u\",\"libbpf_linked_string\":\"%s\",\"match\":%s}\n",
	       SN_VERSION, LIBBPF_MAJOR_VERSION, LIBBPF_MINOR_VERSION, libbpf_major_version(),
	       libbpf_minor_version(), libbpf_version_string(), ok ? "true" : "false");
	return ok ? 0 : 3;
}

static int sn_check_open(void)
{
	struct sentinel_bpf *skel;
	struct bpf_program *p;
	struct bpf_map *m;
	int first = 1;

	skel = sentinel_bpf__open();
	if (!skel) {
		sn_print_terminal(stdout, "unavailable", "skeleton open failed");
		return 2;
	}
	printf("{\"producer\":\"sentinel_loader\",\"opened\":true,\"programs\":[");
	bpf_object__for_each_program(p, skel->obj) {
		printf("%s[\"%s\",\"%s\"]", first ? "" : ",", bpf_program__name(p), bpf_program__section_name(p));
		first = 0;
	}
	printf("],\"maps\":[");
	first = 1;
	bpf_object__for_each_map(m, skel->obj) {
		printf("%s[\"%s\",%u,%u]", first ? "" : ",", bpf_map__name(m), bpf_map__type(m),
		       bpf_map__max_entries(m));
		first = 0;
	}
	printf("]}\n");
	sentinel_bpf__destroy(skel);
	return 0;
}

/* sum per-CPU map values into the cumulative state */
static int sn_read(struct sentinel_bpf *skel, struct sn_state *st, int ncpu)
{
	static struct sn_hist hist[SN_MAX_CPUS];
	static struct sn_sirq_acc acc[SN_MAX_CPUS];
	static __u64 v[SN_MAX_CPUS];
	__u32 k, c, i;

	memset(st->hist, 0, sizeof(st->hist));
	memset(st->stats, 0, sizeof(st->stats));
	memset(st->kfree, 0, sizeof(st->kfree));
	st->retrans = 0;
	st->ncpu = ncpu;
	k = 0;
	if (bpf_map__lookup_elem(skel->maps.sn_hist, &k, sizeof(k), hist, sizeof(hist[0]) * ncpu, 0))
		return -1;
	for (c = 0; c < (__u32)ncpu; c++)
		for (i = 0; i < SN_HIST_BUCKETS; i++)
			st->hist[i] += hist[c].slots[i];
	for (k = 0; k < SN_ST_MAX; k++) {
		if (bpf_map__lookup_elem(skel->maps.sn_stats, &k, sizeof(k), v, sizeof(v[0]) * ncpu, 0))
			return -1;
		for (c = 0; c < (__u32)ncpu; c++)
			st->stats[k] += v[c];
	}
	for (k = 0; k < SN_NR_VEC; k++) {
		if (bpf_map__lookup_elem(skel->maps.sn_sirq_acc, &k, sizeof(k), acc, sizeof(acc[0]) * ncpu, 0))
			return -1;
		for (c = 0; c < (__u32)ncpu; c++)
			st->sirq[c][k] = acc[c];
	}
	k = 0;
	if (bpf_map__lookup_elem(skel->maps.sn_retrans, &k, sizeof(k), v, sizeof(v[0]) * ncpu, 0))
		return -1;
	for (c = 0; c < (__u32)ncpu; c++)
		st->retrans += v[c];
	for (k = 0; k <= SN_KFREE_SLOTS; k++) {
		if (bpf_map__lookup_elem(skel->maps.sn_kfree, &k, sizeof(k), v, sizeof(v[0]) * ncpu, 0))
			return -1;
		for (c = 0; c < (__u32)ncpu; c++)
			st->kfree[k] += v[c];
	}
	return 0;
}

static void sn_usage(void)
{
	fprintf(stderr, "usage: sentinel_loader --version | --check-open |\n"
			"       sentinel_loader --cgroup-id N --cgroup-level L --netns-inum I --max-seconds S\n"
			"                       [--lat-stale-ms MS] [--sirq-stale-ms MS]\n");
}

int main(int argc, char **argv)
{
	unsigned long long cgid = 0, level = ~0ULL, netns = 0, maxs = 0, lat_ms = 10000, sirq_ms = 1000;
	static char names[SN_KFREE_SLOTS][SN_REASON_NAME];
	static struct sn_state st;
	struct sentinel_bpf *skel = NULL;
	struct sn_cfg cfg;
	__u64 deadline, seq = 0;
	int i, ncpu, rc = 0;

	libbpf_set_print(sn_silent);
	if (argc == 2 && !strcmp(argv[1], "--version"))
		return sn_version();
	if (argc == 2 && !strcmp(argv[1], "--check-open"))
		return sn_check_open();
	for (i = 1; i + 1 < argc; i += 2) {
		unsigned long long *dst = NULL, max = 0;

		if (!strcmp(argv[i], "--cgroup-id")) { dst = &cgid; max = ~0ULL; }
		else if (!strcmp(argv[i], "--cgroup-level")) { dst = &level; max = SN_MAX_CGROUP_LEVEL; }
		else if (!strcmp(argv[i], "--netns-inum")) { dst = &netns; max = 0xffffffffULL; }
		else if (!strcmp(argv[i], "--max-seconds")) { dst = &maxs; max = SN_MAX_SECONDS_LIMIT; }
		else if (!strcmp(argv[i], "--lat-stale-ms")) { dst = &lat_ms; max = 600000; }
		else if (!strcmp(argv[i], "--sirq-stale-ms")) { dst = &sirq_ms; max = 600000; }
		if (!dst || sn_parse_u64(argv[i + 1], max, dst)) {
			sn_usage();
			sn_print_terminal(stdout, "unavailable", "invalid arguments");
			return 64;
		}
	}
	if (i != argc || cgid == 0 || level == ~0ULL || netns == 0 || maxs == 0 || lat_ms == 0 || sirq_ms == 0) {
		sn_usage();
		sn_print_terminal(stdout, "unavailable", "missing target configuration");
		return 64;
	}
	ncpu = libbpf_num_possible_cpus();
	if (ncpu <= 0 || ncpu > SN_MAX_CPUS) {
		sn_print_terminal(stdout, "unavailable", "unsupported possible-CPU count");
		return 2;
	}
	if (sn_reason_names(names) < 0) {
		sn_print_terminal(stdout, "unavailable", "kernel BTF skb_drop_reason not readable");
		return 2;
	}
	signal(SIGINT, sn_on_signal);
	signal(SIGTERM, sn_on_signal);
	signal(SIGPIPE, SIG_IGN);

	skel = sentinel_bpf__open();
	if (!skel) {
		sn_print_terminal(stdout, "unavailable", "skeleton open failed");
		return 2;
	}
	cfg.cgroup_id = cgid;
	cfg.cgroup_level = (__u32)level;
	cfg.netns_inum = (__u32)netns;
	cfg.lat_stale_ns = lat_ms * 1000000ULL;
	cfg.sirq_stale_ns = sirq_ms * 1000000ULL;
	memcpy((void *)&skel->rodata->sn_cfg, &cfg, sizeof(cfg));
	if (sentinel_bpf__load(skel)) {
		sn_print_terminal(stdout, "unavailable", "BPF load failed (privileges or verifier)");
		rc = 2;
		goto out;
	}
	if (sentinel_bpf__attach(skel)) {
		sn_print_terminal(stdout, "unavailable", "BPF attach failed");
		rc = 2;
		goto out;
	}
	sn_print_meta(stdout, "sentinel_loader", &cfg, ncpu, names);
	deadline = sn_mono_ns() + maxs * 1000000000ULL;
	while (!sn_stop) {
		struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
		__u64 now = sn_mono_ns();
		char buf[64];
		ssize_t n;
		int left_ms;

		if (now >= deadline) {
			sn_print_terminal(stdout, "end", "max-seconds reached");
			break;
		}
		left_ms = (int)((deadline - now) / 1000000ULL);
		if (left_ms > 1000)
			left_ms = 1000;
		if (poll(&pfd, 1, left_ms) <= 0)
			continue;
		n = read(STDIN_FILENO, buf, sizeof(buf));
		if (n <= 0) {
			sn_print_terminal(stdout, "end", "stdin closed");
			break;
		}
		for (i = 0; i < n && !sn_stop; i++) {
			if (buf[i] == 'q') {
				sn_stop = 1;
				sn_print_terminal(stdout, "end", "quit requested");
			} else if (buf[i] == 's') {
				if (sn_read(skel, &st, ncpu)) {
					sn_print_terminal(stdout, "unavailable", "map read failed");
					rc = 2;
					sn_stop = 1;
					break;
				}
				sn_print_sample(stdout, &st, ++seq, sn_mono_ns());
			}
		}
	}
out:
	sentinel_bpf__destroy(skel);
	return rc;
}
