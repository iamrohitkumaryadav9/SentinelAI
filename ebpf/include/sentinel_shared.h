/* SentinelAI M3B: constants and pure arithmetic shared by the BPF program, the loader and the
 * userspace replay harness. Nothing here judges a value: no thresholds, no labels.
 */
#ifndef SENTINEL_SHARED_H
#define SENTINEL_SHARED_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define SN_PROTOCOL_VERSION 1
#define SN_VERSION "m3b-1.0.0"

/* ---- bounded state (every map is fixed-size) */
#define SN_WAKE_MAX 16384              /* LRU hash: pending target wakeups, keyed by tid */
#define SN_NR_VEC 10                   /* NR_SOFTIRQS on 6.8 (HI .. RCU), verified in BTF */
#define SN_KFREE_SLOTS 128             /* core skb_drop_reason values (< SKB_DROP_REASON_MAX = 95) */
#define SN_KFREE_OVERFLOW SN_KFREE_SLOTS   /* one extra slot: reason >= SN_KFREE_SLOTS (subsystem reasons) */
#define SN_MAX_CGROUP_LEVEL 64
#define SN_EEXIST 17                   /* EEXIST: map update with NOEXIST on an existing key */

/* ---- latency histogram: log-linear, 2^SUB_BITS sub-buckets per power of two.
 * Values below 2^SUB_BITS ns are exact; above, a bucket spans 1/16 of its octave (<= 6.25 % width).
 */
#define SN_HIST_SUB_BITS 4
#define SN_HIST_SUB (1 << SN_HIST_SUB_BITS)
#define SN_HIST_MAX_MSB 35
#define SN_HIST_BUCKETS (SN_HIST_SUB + (SN_HIST_MAX_MSB - SN_HIST_SUB_BITS + 1) * SN_HIST_SUB)   /* 528 */
#define SN_HIST_CLAMP ((1ULL << (SN_HIST_MAX_MSB + 1)) - 1)

/* ---- defaults (overridable by the loader / harness configuration) */
#define SN_DEFAULT_LAT_STALE_NS (10ULL * 1000000000ULL)    /* wakeup older than 10 s at switch: discarded */
#define SN_DEFAULT_SIRQ_STALE_NS (1ULL * 1000000000ULL)    /* softirq handler longer than 1 s: discarded */

/* ---- self-observation counters (per CPU; summed by the loader). Order is protocol. */
enum sn_stat {
	SN_ST_WAKE_RECORDED = 0,       /* target wakeup stored */
	SN_ST_WAKE_REPEAT,             /* wakeup while a wakeup of that tid is pending: earliest kept */
	SN_ST_WAKE_NEW,                /* sched_wakeup_new stored (replaces any pending entry: new task) */
	SN_ST_WAKE_NEW_REPLACED,       /* ... and a pending entry of a previous holder of the tid existed */
	SN_ST_WAKE_UPDATE_FAILED,      /* map update failed for another reason */
	SN_ST_WAKE_CANCELLED_RUNNING,  /* pending wakeup of a task switched OUT: it was running (no wait) */
	SN_ST_LAT_RECORDED,            /* wakeup -> switch-in latency added to the histogram */
	SN_ST_LAT_MIGRATED,            /* ... woken on one CPU, switched in on another */
	SN_ST_LAT_STALE,               /* latency above the stale cut-off: discarded */
	SN_ST_LAT_NEGATIVE,            /* switch timestamp before the wakeup timestamp: discarded */
	SN_ST_SIRQ_RECORDED,           /* matched softirq entry/exit added */
	SN_ST_SIRQ_UNMATCHED_EXIT,     /* exit without a pending entry (e.g. attached mid-softirq) */
	SN_ST_SIRQ_MISMATCH,           /* exit vector differs from the pending entry vector */
	SN_ST_SIRQ_ENTRY_OVERWRITTEN,  /* entry while an entry was pending (lost exit) */
	SN_ST_SIRQ_INVALID_VEC,        /* vector >= NR_SOFTIRQS */
	SN_ST_SIRQ_STALE,              /* duration above the stale cut-off: discarded */
	SN_ST_SIRQ_NEGATIVE,           /* exit timestamp before entry timestamp: discarded */
	SN_ST_RETRANS_OTHER_NETNS,     /* retransmission in another netns (not target evidence) */
	SN_ST_RETRANS_UNATTRIBUTED,    /* retransmission whose netns could not be read */
	SN_ST_KFREE_OTHER_NETNS,       /* kfree_skb in another netns */
	SN_ST_KFREE_UNATTRIBUTED,      /* kfree_skb with neither skb->dev nor skb->sk netns */
	SN_ST_KFREE_OVERFLOW,          /* reason >= SN_KFREE_SLOTS, counted in the overflow slot */
	SN_ST_MAX
};

/* ---- map values */
struct sn_wake {
	__u64 ts;      /* bpf_ktime_get_ns() at wakeup (CLOCK_MONOTONIC, all CPUs) */
	__u32 cpu;     /* CPU that ran the wakeup */
	__u32 pad;
};

struct sn_hist {
	__u64 slots[SN_HIST_BUCKETS];
};

struct sn_sirq_start {
	__u64 ts;
	__u32 vec;
	__u32 active;
};

struct sn_sirq_acc {
	__u64 ns;      /* cumulative matched softirq execution time */
	__u64 count;   /* cumulative matched entry/exit pairs */
};

/* configuration: .rodata of the BPF object, set by the loader before load */
struct sn_cfg {
	__u64 cgroup_id;       /* kernfs id (inode) of the target cgroup v2 directory */
	__u32 cgroup_level;    /* depth of the target cgroup (root = 0); descendants are included */
	__u32 netns_inum;      /* ns.inum of the target network namespace */
	__u64 lat_stale_ns;
	__u64 sirq_stale_ns;
};

/* ---- pure arithmetic */
static __always_inline __u32 sn_log2_u64(__u64 v)
{
	__u32 r = 0;

	if (v >> 32) { v >>= 32; r += 32; }
	if (v >> 16) { v >>= 16; r += 16; }
	if (v >> 8) { v >>= 8; r += 8; }
	if (v >> 4) { v >>= 4; r += 4; }
	if (v >> 2) { v >>= 2; r += 2; }
	if (v >> 1) { r += 1; }
	return r;
}

static __always_inline __u32 sn_hist_index(__u64 v)
{
	__u32 msb;

	if (v < SN_HIST_SUB)
		return (__u32)v;
	if (v > SN_HIST_CLAMP)
		v = SN_HIST_CLAMP;
	msb = sn_log2_u64(v);
	return SN_HIST_SUB + (msb - SN_HIST_SUB_BITS) * SN_HIST_SUB +
	       (__u32)((v >> (msb - SN_HIST_SUB_BITS)) & (SN_HIST_SUB - 1));
}

/* inclusive value range [lo, hi] of bucket i (host side only uses these; mirrored in Python) */
static __always_inline __u64 sn_hist_lo(__u32 i)
{
	__u32 g, s;

	if (i < SN_HIST_SUB)
		return i;
	g = (i - SN_HIST_SUB) / SN_HIST_SUB;
	s = (i - SN_HIST_SUB) % SN_HIST_SUB;
	return ((__u64)(SN_HIST_SUB + s)) << g;
}

static __always_inline __u64 sn_hist_hi(__u32 i)
{
	if (i < SN_HIST_SUB)
		return i;
	return sn_hist_lo(i) + (1ULL << ((i - SN_HIST_SUB) / SN_HIST_SUB)) - 1;
}

#endif /* SENTINEL_SHARED_H */
