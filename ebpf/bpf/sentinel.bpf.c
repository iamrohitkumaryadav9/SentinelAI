// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* SentinelAI M3B kernel observer (CO-RE, tp_btf). Observation only: in-kernel bounded aggregation of
 * scheduler wakeup->switch latency, softirq execution time, TCP retransmitted skbs and kfree_skb drops.
 * No ring buffer: userspace reads cumulative per-CPU maps on demand, so the per-event cost is a few
 * map operations and nothing is queued.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sentinel_shared.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile struct sn_cfg sn_cfg = {
	.cgroup_id = 0,
	.cgroup_level = 0,
	.netns_inum = 0,
	.lat_stale_ns = SN_DEFAULT_LAT_STALE_NS,
	.sirq_stale_ns = SN_DEFAULT_SIRQ_STALE_NS,
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, SN_WAKE_MAX);
	__type(key, __u32);
	__type(value, struct sn_wake);
} sn_wake SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sn_hist);
} sn_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SN_ST_MAX);
	__type(key, __u32);
	__type(value, __u64);
} sn_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sn_sirq_start);
} sn_sirq_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SN_NR_VEC);
	__type(key, __u32);
	__type(value, struct sn_sirq_acc);
} sn_sirq_acc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sn_retrans SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SN_KFREE_SLOTS + 1);
	__type(key, __u32);
	__type(value, __u64);
} sn_kfree SEC(".maps");

static __always_inline void *sn_lookup(void *map, __u32 key)
{
	return bpf_map_lookup_elem(map, &key);
}

static __always_inline int sn_wake_update(__u32 tid, struct sn_wake *w, __u64 flags)
{
	return bpf_map_update_elem(&sn_wake, &tid, w, flags);
}

static __always_inline int sn_wake_delete(__u32 tid)
{
	return bpf_map_delete_elem(&sn_wake, &tid);
}

#define SN_NOW() bpf_ktime_get_ns()
#define SN_CPU() bpf_get_smp_processor_id()
#define SN_CFG(f) (sn_cfg.f)
#define SN_ANY BPF_ANY
#define SN_NOEXIST BPF_NOEXIST
#define SN_WAKE_LOOKUP(tid) ((struct sn_wake *)sn_lookup(&sn_wake, (tid)))
#define SN_WAKE_UPDATE(tid, w, flg) sn_wake_update((tid), (w), (flg))
#define SN_WAKE_DELETE(tid) sn_wake_delete((tid))
#define SN_HIST() ((struct sn_hist *)sn_lookup(&sn_hist, 0))
#define SN_STAT(i) ((__u64 *)sn_lookup(&sn_stats, (i)))
#define SN_SIRQ_START() ((struct sn_sirq_start *)sn_lookup(&sn_sirq_start, 0))
#define SN_SIRQ_ACC(v) ((struct sn_sirq_acc *)sn_lookup(&sn_sirq_acc, (v)))
#define SN_RETRANS() ((__u64 *)sn_lookup(&sn_retrans, 0))
#define SN_KFREE(s) ((__u64 *)sn_lookup(&sn_kfree, (s)))

#include "sentinel_core.h"

/* Is task p in the target cgroup or one of its descendants (cgroup v2)?
 * cgroup->ancestors[level] is the cgroup itself, so ancestors[target_level] is the task's ancestor at
 * the target's depth; it is the target iff its kernfs id matches.
 */
static __always_inline int sn_task_in_target(struct task_struct *p)
{
	struct cgroup *cg, *anc = NULL, **base;
	__u32 lvl = sn_cfg.cgroup_level;
	int cl;

	if (sn_cfg.cgroup_id == 0 || lvl > SN_MAX_CGROUP_LEVEL)
		return 0;
	cg = BPF_CORE_READ(p, cgroups, dfl_cgrp);
	if (!cg)
		return 0;
	cl = BPF_CORE_READ(cg, level);
	if (cl < 0 || (__u32)cl < lvl)
		return 0;
	base = (struct cgroup **)__builtin_preserve_access_index(&cg->ancestors[0]);
	if (bpf_probe_read_kernel(&anc, sizeof(anc), base + lvl))
		return 0;
	if (!anc)
		return 0;
	return BPF_CORE_READ(anc, kn, id) == sn_cfg.cgroup_id;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sn_sched_wakeup, struct task_struct *p)
{
	sn_on_wakeup((__u32)BPF_CORE_READ(p, pid), sn_task_in_target(p), 0);
	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sn_sched_wakeup_new, struct task_struct *p)
{
	sn_on_wakeup((__u32)BPF_CORE_READ(p, pid), sn_task_in_target(p), 1);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sn_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next,
	     unsigned int prev_state)
{
	sn_on_switch((__u32)BPF_CORE_READ(prev, pid), (__u32)BPF_CORE_READ(next, pid));
	return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(sn_softirq_entry, unsigned int vec_nr)
{
	sn_on_softirq_entry(vec_nr);
	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(sn_softirq_exit, unsigned int vec_nr)
{
	sn_on_softirq_exit(vec_nr);
	return 0;
}

SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(sn_tcp_retransmit_skb, const struct sock *sk, const struct sk_buff *skb)
{
	__u32 ns = 0;

	if (sk)
		ns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	sn_on_retransmit(ns);
	return 0;
}

/* netns attribution: skb->dev's namespace, else the owning socket's; neither -> unattributed */
SEC("tp_btf/kfree_skb")
int BPF_PROG(sn_kfree_skb, struct sk_buff *skb, void *location, enum skb_drop_reason reason)
{
	__u32 ns = 0;

	if (BPF_CORE_READ(skb, dev))
		ns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);
	if (ns == 0 && BPF_CORE_READ(skb, sk))
		ns = BPF_CORE_READ(skb, sk, __sk_common.skc_net.net, ns.inum);
	sn_on_kfree(ns, (__u32)reason);
	return 0;
}
