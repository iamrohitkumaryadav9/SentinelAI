/* SentinelAI M3B: userspace side shared by the loader and the replay harness.
 * Line protocol (JSON, one object per line, version SN_PROTOCOL_VERSION):
 *   meta    once, first line: producer, configuration, histogram geometry, vector / reason / stat names
 *   sample  on each request: cumulative counters since attach (never deltas, never reset)
 *   unavailable / end   terminal lines with a reason
 * The Python collector (sentinelai.collectors.ebpf) parses and validates this strictly.
 */
#ifndef SENTINEL_HOST_H
#define SENTINEL_HOST_H

#include <stdio.h>
#include <string.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_version.h>

#include "sentinel_shared.h"

#if !defined(LIBBPF_MAJOR_VERSION) || LIBBPF_MAJOR_VERSION != 1 || LIBBPF_MINOR_VERSION < 4
#error "SentinelAI M3B requires the libbpf >= 1.4 headers (kernel-headers archive); refusing to build"
#endif

#define SN_MAX_CPUS 1024
#define SN_REASON_NAME 64

static const char *const sn_vec_names[SN_NR_VEC] = {
	"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU",
};

static const char *const sn_stat_names[SN_ST_MAX] = {
	"wake_recorded", "wake_repeat", "wake_new", "wake_new_replaced", "wake_update_failed",
	"wake_cancelled_running", "lat_recorded", "lat_migrated", "lat_stale", "lat_negative",
	"sirq_recorded", "sirq_unmatched_exit", "sirq_mismatch", "sirq_entry_overwritten", "sirq_invalid_vec",
	"sirq_stale", "sirq_negative", "retrans_other_netns", "retrans_unattributed", "kfree_other_netns",
	"kfree_unattributed", "kfree_overflow",
};

/* cumulative state summed over CPUs (softirq kept per CPU) */
struct sn_state {
	__u64 hist[SN_HIST_BUCKETS];
	__u64 stats[SN_ST_MAX];
	__u64 retrans;
	__u64 kfree[SN_KFREE_SLOTS + 1];
	int ncpu;
	struct sn_sirq_acc sirq[SN_MAX_CPUS][SN_NR_VEC];
};

/* skb_drop_reason names from the running kernel's BTF (value -> name without the SKB_DROP_REASON_ /
 * SKB_ prefix). Values without a name stay empty. Returns the number of names, or -1. */
static int sn_reason_names(char names[SN_KFREE_SLOTS][SN_REASON_NAME])
{
	const struct btf_type *t;
	struct btf_enum *e;
	struct btf *btf;
	int id, i, n = 0;

	memset(names, 0, sizeof(char) * SN_KFREE_SLOTS * SN_REASON_NAME);
	btf = btf__load_vmlinux_btf();
	if (!btf)
		return -1;
	id = btf__find_by_name_kind(btf, "skb_drop_reason", BTF_KIND_ENUM);
	if (id < 0) {
		btf__free(btf);
		return -1;
	}
	t = btf__type_by_id(btf, id);
	e = btf_enum(t);
	for (i = 0; i < btf_vlen(t); i++, e++) {
		const char *name = btf__name_by_offset(btf, e->name_off);
		__u32 v = (__u32)e->val;

		if (!name || v >= SN_KFREE_SLOTS)
			continue;
		if (!strncmp(name, "SKB_DROP_REASON_", 16))
			name += 16;
		else if (!strncmp(name, "SKB_", 4))
			name += 4;
		if (!strcmp(name, "MAX"))
			continue;
		snprintf(names[v], SN_REASON_NAME, "%s", name);
		n++;
	}
	btf__free(btf);
	return n;
}

static void sn_print_meta(FILE *f, const char *producer, const struct sn_cfg *cfg, int ncpu,
			  char names[SN_KFREE_SLOTS][SN_REASON_NAME])
{
	int i, first = 1;

	fprintf(f, "{\"v\":%d,\"type\":\"meta\",\"producer\":\"%s\",\"version\":\"%s\",\"libbpf\":\"%u.%u\","
		   "\"ncpu\":%d,\"cfg\":{\"cgroup_id\":%llu,\"cgroup_level\":%u,\"netns_inum\":%u,"
		   "\"lat_stale_ns\":%llu,\"sirq_stale_ns\":%llu},"
		   "\"hist\":{\"sub_bits\":%d,\"max_msb\":%d,\"buckets\":%d},\"kfree_slots\":%d,\"vectors\":[",
		SN_PROTOCOL_VERSION, producer, SN_VERSION, libbpf_major_version(), libbpf_minor_version(), ncpu,
		(unsigned long long)cfg->cgroup_id, cfg->cgroup_level, cfg->netns_inum,
		(unsigned long long)cfg->lat_stale_ns, (unsigned long long)cfg->sirq_stale_ns,
		SN_HIST_SUB_BITS, SN_HIST_MAX_MSB, SN_HIST_BUCKETS, SN_KFREE_SLOTS);
	for (i = 0; i < SN_NR_VEC; i++)
		fprintf(f, "%s\"%s\"", i ? "," : "", sn_vec_names[i]);
	fprintf(f, "],\"reasons\":[");
	for (i = 0; i < SN_KFREE_SLOTS; i++) {
		if (!names[i][0])
			continue;
		fprintf(f, "%s[%d,\"%s\"]", first ? "" : ",", i, names[i]);
		first = 0;
	}
	fprintf(f, "],\"stats\":[");
	for (i = 0; i < SN_ST_MAX; i++)
		fprintf(f, "%s\"%s\"", i ? "," : "", sn_stat_names[i]);
	fprintf(f, "]}\n");
	fflush(f);
}

static void sn_print_sample(FILE *f, const struct sn_state *s, __u64 seq, __u64 mono_ns)
{
	int i, c, first = 1;

	fprintf(f, "{\"v\":%d,\"type\":\"sample\",\"seq\":%llu,\"mono_ns\":%llu,\"sched\":{\"hist\":[",
		SN_PROTOCOL_VERSION, (unsigned long long)seq, (unsigned long long)mono_ns);
	for (i = 0; i < SN_HIST_BUCKETS; i++) {
		if (!s->hist[i])
			continue;
		fprintf(f, "%s[%d,%llu]", first ? "" : ",", i, (unsigned long long)s->hist[i]);
		first = 0;
	}
	fprintf(f, "]},\"softirq\":[");
	for (c = 0; c < s->ncpu; c++)
		for (i = 0; i < SN_NR_VEC; i++)
			fprintf(f, "%s[%d,%d,%llu,%llu]", (c || i) ? "," : "", c, i,
				(unsigned long long)s->sirq[c][i].ns, (unsigned long long)s->sirq[c][i].count);
	fprintf(f, "],\"retrans\":%llu,\"kfree\":[", (unsigned long long)s->retrans);
	first = 1;
	for (i = 0; i <= SN_KFREE_SLOTS; i++) {
		if (!s->kfree[i])
			continue;
		fprintf(f, "%s[%d,%llu]", first ? "" : ",", i, (unsigned long long)s->kfree[i]);
		first = 0;
	}
	fprintf(f, "],\"stats\":{");
	for (i = 0; i < SN_ST_MAX; i++)
		fprintf(f, "%s\"%s\":%llu", i ? "," : "", sn_stat_names[i], (unsigned long long)s->stats[i]);
	fprintf(f, "}}\n");
	fflush(f);
}

static void sn_print_terminal(FILE *f, const char *type, const char *reason)
{
	fprintf(f, "{\"v\":%d,\"type\":\"%s\",\"reason\":\"%s\"}\n", SN_PROTOCOL_VERSION, type, reason);
	fflush(f);
}

#endif /* SENTINEL_HOST_H */
