# Phase 1C — M3B Report: eBPF Kernel Evidence Layer (audit stage)

| | |
|---|---|
| Base | `628c71101dec92c75bdd1a71b665be9ac7b99973` (M3A-C1). `git status`: `?? experiments/faultlab/` only |
| Status | **Stopped at the audit (brief §1).** No M3B code was written and nothing was committed, because two stop conditions in the brief are triggered (§15 privileges, §20/§27 contract gaps). |
| Gate | **M3B GATE: NO-GO** |

## A. Environment (audited, nothing modified)

| Item | Value |
|---|---|
| Kernel | `6.8.0-138-generic` (Ubuntu 22.04 HWE) |
| clang / LLVM | Ubuntu clang 14.0.0, LLVM 14 (`llc` present) |
| bpftool | v7.4.0, built with libbpf v1.4 |
| libbpf (system dev package) | `libbpf-dev` 1:0.5.0 (headers in `/usr/include/bpf`; skeletons and ring buffer supported) |
| BTF | `/sys/kernel/btf/vmlinux` present and world-readable (6.1 MB, 331k type records) |
| BPF filesystem | `/sys/fs/bpf` mounted (`bpf`, mode 700, root) |
| tracefs | `/sys/kernel/tracing` mounted, mode 700 (root only) |
| Reference tooling | bpftrace 0.14.0, bpfcc-tools 0.18.0 (Phase 1A smoke only) |
| `kernel.unprivileged_bpf_disabled` | **2** (unprivileged `bpf()` permanently disabled until reboot) |
| `kernel.perf_event_paranoid` | **4** (Ubuntu: unprivileged perf events disabled) |
| This session | uid 1000 (`iiitd`), **CapEff = 0**, `sudo -n` → "a password is required" |

**Tracepoints present** (verified through BTF `btf_trace_*` typedefs, since tracefs isn't readable unprivileged):

| Tracepoint | Payload fields (BTF) |
|---|---|
| `sched_wakeup`, `sched_wakeup_new` | `pid`, `prio`, `target_cpu` |
| `sched_switch` | `prev_pid`, `prev_state`, `next_pid` |
| `softirq_entry`, `softirq_exit` | `vec` |
| `kfree_skb` | `skbaddr`, `location`, `protocol`, **`reason`** |
| `tcp_retransmit_skb` | `skaddr`, `skbaddr`, ports, addresses, `state`, `family` |

`enum skb_drop_reason` has 97 values, including `NOT_SPECIFIED`, `QDISC_DROP`, `CPU_BACKLOG`, `NETFILTER_DROP` and `TC_EGRESS`. These map directly onto the contract qualifier pattern `^[A-Z0-9_]+$` (prefix `SKB_DROP_REASON_` stripped).

The toolchain and kernel are therefore **capable** of a libbpf CO-RE implementation (`bpftool btf dump … format c` → vmlinux.h, `clang -target bpf`, `bpftool gen skeleton`, ring buffer / per-CPU maps).

## Blocker 1 — Privilege (brief §15)

Loading and attaching any BPF program on this host needs root, or `CAP_BPF` + `CAP_PERFMON`:
- `unprivileged_bpf_disabled = 2`;
- `perf_event_paranoid = 4`;
- this session has no capabilities and no non-interactive sudo.

The brief forbids weakening these settings, and I did not touch them.

Consequences:
- no BPF program can be loaded or verifier-checked from this session;
- K1–K4, the "real evidence" (§H), the performance gate (§23) and "real eBPF attachment works" can't be produced;
- the GO criteria "real eBPF attachment works" and "required kernel evidence is actually observed" therefore can't be met.

Building the whole collector blind (BPF programs no verifier has accepted) and then declaring NO-GO would ship unvalidated kernel code. I stopped at the audit instead.

**Decision needed — choose one:**

| Option | What it involves | Effect on host security |
|---|---|---|
| **P-a** (recommended) | I build everything that can be built and checked unprivileged: BPF objects compiled against BTF, the loader, the aggregator, every fixture test, and every static safety test. I also write one read-only validation script. **You run it interactively with `sudo`**, as with Phase 1A's `privileged_smoke.sh`, and paste the output. The gate is decided on that output. | No persistent change |
| **P-b** | You grant `cap_bpf,cap_perfmon+ep` to one dedicated loader binary (`setcap`, once, as root). The collector then runs unprivileged in normal operation. | A persistent, targeted change. It is a security-configuration decision, so it is yours, not mine. |
| **P-c** | Defer M3B. | None |

## Blocker 2 — Contract gaps (brief §20, §27: stop and report, don't change the contract)

The registry (`contract 0.3.0-draft`) registers exactly **two** EBPF-sourced features:

| Feature | Avail. | Unit | Aggregations | Scope | Qualifier |
|---|---|---|---|---|---|
| `sched.latency_hist.target` | P | ms | **P50, P99** | cgroup | — |
| `net.drop.kfree_skb` | P | packets/s | RATE | netns | `reason` (`^[A-Z0-9_]+$`) |

Against the brief's required evidence:

| Brief item | Contract status | Gap |
|---|---|---|
| **B1** wakeup→switch latency | `sched.latency_hist.target` (source EBPF) matches exactly. Not `sched.run_delay_excess.target`, which is a PROC/DERIVED feature that M2 uses. | **G-1 (minor).** The brief asks for p50/p90/p99/p999/max/mean/count; the contract allows **P50 and P99 only**. The others can't be represented without a contract change. B1 is implementable within the contract as P50 and P99. Note that M2 doesn't use this feature in any rule today, so it adds evidence without changing any diagnosis. |
| **B2** softirq time / rate | No EBPF-sourced softirq feature. `softirq.frac.percpu` (jiffies from `/proc/stat`) and `softirq.net_rx/tx_rate.percpu` (`/proc/softirqs`) are registered with source **PROC only**. | **G-2.** Emitting eBPF softirq time under these features would violate their registered source (M1 rejects it), and it is a different quantity: traced ns per vector versus jiffy-sampled fraction. Needs either an EBPF source added with defined semantics, or a new feature (for example a per-vector softirq time). |
| **B3** TCP retransmissions | `tcp.retrans_rate` is registered with source **PROC only** (`/proc/net/snmp RetransSegs`, segments/s). | **G-3.** The `tcp_retransmit_skb` tracepoint counts retransmitted **skbs**, not segments: one skb can carry several segments under TSO/GSO. It is also attributable per socket/target, which `/proc/net/snmp` isn't. Using it under `tcp.retrans_rate` would change the unit semantics. Needs a contract decision (for example a per-target `tcp.retrans_skbs.target` feature). |
| **B4** kernel drops | `net.drop.kfree_skb` (source EBPF, `reason` qualifier) matches exactly. M2 already treats only `KFREE_REASONS_LOSS` reasons as loss, and `NOT_SPECIFIED` at most as WEAK support. | None. The kernel exposes `reason` reliably (6.8), so B4 is implementable within the contract. |

**Lab environment (K3, K4).** No lab-owned virtual interface or namespace exists on this host (only `lo`, `docker0`, `enp0s31f6`). Generating softirq load and TCP retransmissions in a controlled lab needs a veth pair or netns, plus impairment (for example netem) on that lab interface only. All of that needs root, and it is a network change that every milestone so far has forbidden. It needs your explicit authorisation, limited to lab-owned virtual interfaces and never `enp0s31f6`.

## What M3B can be within the current contract

If you choose P-a, the contract-legal scope is:

1. **B1** `sched.latency_hist.target` (P50/P99 ms, cgroup scope):
   - `tp_btf` on `sched_wakeup`, `sched_wakeup_new` and `sched_switch`;
   - a bounded `BPF_MAP_TYPE_LRU_HASH` keyed by tid (wake timestamp, CPU, cgroup id), with a stale-entry age cut-off;
   - a per-CPU log2/linear histogram for the target cgroup only;
   - counters for seen, missed, evicted and stale events.
2. **B4** `net.drop.kfree_skb` per `reason` (netns scope):
   - `tp_btf/kfree_skb`, with netns read through CO-RE (`skb->dev->nd_net` / `skb->sk`);
   - a per-CPU array indexed by reason (bounded by the enum size), with ring-buffer loss counters.
3. B2 and B3 only after G-2 and G-3 are decided.

## Gate

**M3B GATE: NO-GO**

Blockers:
1. **Privileges.** eBPF can't be loaded or attached from this session (`CapEff = 0`, `unprivileged_bpf_disabled = 2`, `perf_event_paranoid = 4`, no non-interactive sudo). Weakening any of these is forbidden, and I didn't.
2. **Contract gaps G-2 and G-3.** B2 (softirq) and B3 (retransmission) have no EBPF-sourced contract feature, and B3's tracepoint has different units. G-1 (B1 quantiles limited to P50/P99) is minor.
3. **No lab environment** for K3/K4, and creating one needs root plus a network-change authorisation.

Nothing on the host was modified. No code was written and nothing was committed. This report is the only new file, left uncommitted.

**STOP.** Awaiting your decisions: privilege model (P-a / P-b / P-c), G-2 and G-3, and lab-namespace authorisation for K3/K4.
