/* SentinelAI M3B: event-handling logic, written once and compiled twice: into the BPF program
 * (maps = BPF maps) and into the userspace replay harness (maps = bounded arrays), so the fixture
 * tests exercise exactly the correlation code that runs in the kernel.
 *
 * Observation only. The handlers count and time what the kernel reports; they never decide what
 * a value means (no thresholds, no labels, no diagnosis).
 *
 * The includer defines, before including this file:
 *   SN_NOW()                     u64 monotonic ns
 *   SN_CPU()                     u32 current CPU
 *   SN_CFG(field)                configuration (struct sn_cfg)
 *   SN_WAKE_LOOKUP(tid)          struct sn_wake * or NULL
 *   SN_WAKE_UPDATE(tid, w, flg)  0 on success, -SN_EEXIST if flg == SN_NOEXIST and the key exists
 *   SN_WAKE_DELETE(tid)          0 if an entry was deleted
 *   SN_HIST()                    struct sn_hist * of this CPU, or NULL
 *   SN_STAT(i)                   __u64 * of this CPU, or NULL
 *   SN_SIRQ_START()              struct sn_sirq_start * of this CPU, or NULL
 *   SN_SIRQ_ACC(vec)             struct sn_sirq_acc * of this CPU, or NULL
 *   SN_RETRANS()                 __u64 * of this CPU, or NULL
 *   SN_KFREE(slot)               __u64 * of this CPU, or NULL
 *   SN_ANY, SN_NOEXIST           update flags
 */
#ifndef SENTINEL_CORE_H
#define SENTINEL_CORE_H

#include "sentinel_shared.h"

/* Same definition as libbpf's bpf_helpers.h, for the userspace build of this file. */
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

static __always_inline void sn_count(__u32 i)
{
	__u64 *s = SN_STAT(i);

	if (s)
		*s += 1;
}

/* sched_wakeup / sched_wakeup_new for task tid (in_target: the task is in the target cgroup subtree).
 * tid 0 is the per-CPU idle task (every CPU's idle task has pid 0) and is never correlated.
 * A plain wakeup keeps the EARLIEST pending timestamp (BPF_NOEXIST). wakeup_new always replaces:
 * a new task never inherits a pending entry left by an earlier holder of the same tid.
 */
static __always_inline void sn_on_wakeup(__u32 tid, int in_target, int is_new)
{
	struct sn_wake w = {};
	int r;

	if (tid == 0 || !in_target)
		return;
	w.ts = SN_NOW();
	w.cpu = SN_CPU();
	if (is_new) {
		if (SN_WAKE_LOOKUP(tid))
			sn_count(SN_ST_WAKE_NEW_REPLACED);
		if (SN_WAKE_UPDATE(tid, &w, SN_ANY)) {
			sn_count(SN_ST_WAKE_UPDATE_FAILED);
			return;
		}
		sn_count(SN_ST_WAKE_NEW);
		return;
	}
	r = SN_WAKE_UPDATE(tid, &w, SN_NOEXIST);
	if (r == -SN_EEXIST) {
		sn_count(SN_ST_WAKE_REPEAT);
		return;
	}
	if (r) {
		sn_count(SN_ST_WAKE_UPDATE_FAILED);
		return;
	}
	sn_count(SN_ST_WAKE_RECORDED);
}

/* sched_switch prev -> next on the current CPU.
 * 1. A task being switched OUT was running, so any pending wakeup of it (a wakeup that found the
 *    task still running, e.g. ttwu_runnable) did not make it wait: the entry is cancelled. Without
 *    this, its next real wakeup would be measured from a stale timestamp.
 * 2. A task switched IN with a pending wakeup: latency = now - wakeup ts, added to this CPU's
 *    histogram unless negative or above the stale cut-off. Woken on one CPU and run on another
 *    (migration) is fine: the timestamp is global CLOCK_MONOTONIC.
 * A switch-in without a pending wakeup (preempted task re-run, non-target task, evicted entry)
 * records nothing: only wakeup -> switch is measured (contract locator).
 */
static __always_inline void sn_on_switch(__u32 prev_tid, __u32 next_tid)
{
	struct sn_wake *w;
	struct sn_hist *h;
	__u64 now, ts, d, i;
	__u32 wcpu;

	now = SN_NOW();
	if (prev_tid != 0 && SN_WAKE_DELETE(prev_tid) == 0)
		sn_count(SN_ST_WAKE_CANCELLED_RUNNING);
	if (next_tid == 0)
		return;
	w = SN_WAKE_LOOKUP(next_tid);
	if (!w)
		return;
	ts = w->ts;
	wcpu = w->cpu;
	SN_WAKE_DELETE(next_tid);
	if (ts > now) {
		sn_count(SN_ST_LAT_NEGATIVE);
		return;
	}
	d = now - ts;
	if (d > SN_CFG(lat_stale_ns)) {
		sn_count(SN_ST_LAT_STALE);
		return;
	}
	if (wcpu != SN_CPU())
		sn_count(SN_ST_LAT_MIGRATED);
	h = SN_HIST();
	if (!h)
		return;
	/* R1.1: a 64-bit index, so the clamp and the array offset use one register. A __u32 index let clang 14
	 * zero-extend a copy for the comparison and re-extend the original for the access, and the verifier
	 * rejected the unlinked offset (R0 unbounded memory access). barrier_var pins the clamped value as the
	 * one that is indexed; it emits no instruction. 0 <= i <= SN_HIST_BUCKETS - 1 holds at the access.
	 */
	i = sn_hist_index(d);
	if (i >= SN_HIST_BUCKETS)
		i = SN_HIST_BUCKETS - 1;
	barrier_var(i);
	h->slots[i] += 1;
	sn_count(SN_ST_LAT_RECORDED);
}

/* softirq_entry / softirq_exit: softirqs do not nest on one CPU, so one pending entry per CPU. */
static __always_inline void sn_on_softirq_entry(__u32 vec)
{
	struct sn_sirq_start *s;

	if (vec >= SN_NR_VEC) {
		sn_count(SN_ST_SIRQ_INVALID_VEC);
		return;
	}
	s = SN_SIRQ_START();
	if (!s)
		return;
	if (s->active)
		sn_count(SN_ST_SIRQ_ENTRY_OVERWRITTEN);
	s->ts = SN_NOW();
	s->vec = vec;
	s->active = 1;
}

static __always_inline void sn_on_softirq_exit(__u32 vec)
{
	struct sn_sirq_start *s;
	struct sn_sirq_acc *a;
	__u64 now, d;

	if (vec >= SN_NR_VEC) {
		sn_count(SN_ST_SIRQ_INVALID_VEC);
		return;
	}
	s = SN_SIRQ_START();
	if (!s)
		return;
	if (!s->active) {
		sn_count(SN_ST_SIRQ_UNMATCHED_EXIT);
		return;
	}
	s->active = 0;
	if (s->vec != vec) {
		sn_count(SN_ST_SIRQ_MISMATCH);
		return;
	}
	now = SN_NOW();
	if (s->ts > now) {
		sn_count(SN_ST_SIRQ_NEGATIVE);
		return;
	}
	d = now - s->ts;
	if (d > SN_CFG(sirq_stale_ns)) {
		sn_count(SN_ST_SIRQ_STALE);
		return;
	}
	a = SN_SIRQ_ACC(vec);
	if (!a)
		return;
	a->ns += d;
	a->count += 1;
	sn_count(SN_ST_SIRQ_RECORDED);
}

/* tcp_retransmit_skb: one event per retransmitted skb (NOT segments). netns 0 = unreadable. */
static __always_inline void sn_on_retransmit(__u32 netns)
{
	__u64 *c;

	if (netns == 0) {
		sn_count(SN_ST_RETRANS_UNATTRIBUTED);
		return;
	}
	if (netns != SN_CFG(netns_inum)) {
		sn_count(SN_ST_RETRANS_OTHER_NETNS);
		return;
	}
	c = SN_RETRANS();
	if (c)
		*c += 1;
}

/* kfree_skb: counted per kernel drop reason, unchanged. The reason is never interpreted here. */
static __always_inline void sn_on_kfree(__u32 netns, __u32 reason)
{
	__u32 slot = reason;
	__u64 *c;

	if (netns == 0) {
		sn_count(SN_ST_KFREE_UNATTRIBUTED);
		return;
	}
	if (netns != SN_CFG(netns_inum)) {
		sn_count(SN_ST_KFREE_OTHER_NETNS);
		return;
	}
	if (reason >= SN_KFREE_SLOTS) {
		slot = SN_KFREE_OVERFLOW;
		sn_count(SN_ST_KFREE_OVERFLOW);
	}
	c = SN_KFREE(slot);
	if (c)
		*c += 1;
}

#endif /* SENTINEL_CORE_H */
