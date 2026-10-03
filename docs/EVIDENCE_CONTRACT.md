# SentinelAI Evidence Contract

| Field | Value |
|---|---|
| Contract ID | `sentinelai.evidence-contract` |
| Version | **0.5.0-draft** (M3B-C1: measurement identity includes the aggregation for multi-aggregation features; see the revision history below) |
| Date | 2026-10-03 |
| Status | DESIGN; schema implemented in M1 (schema version `0.2.0`). Every numeric threshold is an **uncalibrated parameter** (§6). |
| Consumers | Deterministic rule engine, ML classifier, tests, and (later) the LLM orchestrator |
| Normative keywords | **MUST**, **MUST NOT**, **SHOULD** and **MAY** carry their RFC 2119 meaning |

This contract defines what SentinelAI may claim about a performance incident, and what evidence each claim requires. It is written so that two independent implementations given the same telemetry produce the same evidence items and the same diagnostic decision.


### Revision history

| Version | Change |
|---|---|
| 0.1.0-draft | Initial contract (implemented by M1, commit `33aed1b`) |
| **0.2.0-draft** | Pre-M2 correction approved from `PHASE_1C_PRE_M2_AUDIT.md`:<br>**R-1** unlimited CPU quota represented by the new feature `throttle.quota_limited` (Unit `boolean`); CT.R1 now reads it (§4.2, §8.2).<br>**R-2** `mem.reclaim.target` defined as Δ`pgscan` only (§4.6).<br>**R-3** `Measurement.qualifier` for registry-declared dimensions (`kfree_skb` reason, `app.events` code) (§4.3, §4.7, §10.3, §10.5).<br>**R-4** every parameter is typed (`number` / `reason_set`), numeric thresholds reference `number` only; `τ_DISAGREE` added (§6).<br>**R-5** `DiagnosticResult.flags` (`IMPACT_NOT_MEASURED`, `ML_DISAGREEMENT`) (§10.6, §10.7).<br>Version number decided by the reviewer (see §12). |
| **0.3.0-draft** | C-1 resolution (found by M2, `docs/PHASE_1C_M2_REPORT.md` §15; resolved in `docs/PHASE_1C_C1_REPORT.md`):<br>**C-1** RT.R2 becomes a **Primary** clause (§8): it is required for `tcp_retransmissions` to be the *decision*, not for it to be *contributing*. When local loss is proven (RT.R2 FALSE), `tcp_retransmissions` with RT.R0 and RT.R1 TRUE is CONTRIBUTING under PR-1 when `network_packet_loss` is the decision (§8.5, §9, §10.7 I2/I4). The RT.R2 predicate itself is unchanged.<br>**C-3** `throttle.quota_limited` added to the AB.R3 feature list, so AB.R3 can cite the CT.R1 measurement (§8.7).<br>Schema version unchanged (`0.2.0`): no field of any evidence object changes. |
| **0.4.0-draft** | M3B-C0 (gaps from the M3B audit, `docs/PHASE_1C_M3B_REPORT.md`; resolved in `docs/PHASE_1C_M3B_C0_REPORT.md`). **Additive only**: two new EBPF-sourced features; no existing feature, clause, predicate, parameter or precedence rule changes, and M2 consumes neither feature.<br>**G-2** `softirq.exec_time.percpu` (§4.5): softirq execution time from `irq:softirq_entry`/`softirq_exit`, per CPU and per `vector` qualifier, in cores (CPU-s/s).<br>**G-3** `tcp.retrans_skb_rate` (§4.4): `tcp:tcp_retransmit_skb` events per second (retransmitted skbs/s) in the target netns. It is distinct from `tcp.retrans_rate` (RetransSegs, segments/s), which is unchanged.<br>**G-1** accepted: `sched.latency_hist.target` keeps P50/P99 only.<br>Schema version unchanged (`0.2.0`). |
| **0.5.0-draft** | M3B-C1 (contradiction found by the M3B build audit; resolved in `docs/PHASE_1C_M3B_C1_REPORT.md`). **Identity only**: `sched.latency_hist.target` registers P50 and P99, but `measurement_id` did not include the aggregation, so both percentiles of one scope and window had the same id and could not coexist in a snapshot (the same latent defect affected `app.latency_ms` P50/P99 and `tcp.srtt_ms` P50/P90).<br>**C1-1** §10.3: the aggregation is an identity input **exactly when the feature registers more than one aggregation**. Every single-aggregation id is byte-identical to 0.4.0. No feature, unit, source, qualifier, clause, predicate, parameter or precedence rule changes. Schema version unchanged (`0.2.0`); rules unchanged (`m2-1.1.0`). |

---

## 1. Scope and principles

**P1. Evidence first.** A root-cause label can be asserted **only** when its *required evidence* (§8) is satisfied by measured data with provenance. No component, including an ML model or an LLM, may assert a label whose required evidence is not met.

**P2. Absence is not presence.** A missing measurement is never evidence *for* any label. "Everything else looks normal" is never evidence for `application_bottleneck` or any other label.

**P3. Baseline-relative.** Wherever a meaningful baseline exists, evidence is judged on deviation from baseline, with an absolute floor that stops ratios exploding near zero. Raw values alone are used only where the quantity has a fixed physical meaning, for example a throttled-period ratio in [0, 1].

**P4. Magnitude matters.** A non-zero counter is not proof. In particular, `kfree_skb > 0` is **not** packet-loss evidence (§8.4).

**P5. No residual label.** No label is assigned by elimination. `INSUFFICIENT_EVIDENCE` is the only outcome for "no label's required evidence is met".

**P6. Determinism.** The evidence items and decision are a pure function of (measurements, baseline, contract version, parameter set). There is no randomness and no wall-clock dependence beyond the declared window.

**P7. Traceability.** Every evidence item references measurements, and every measurement carries provenance down to a file and field or a collector event (§11).

**P8. LLM-independent.** The contract is evaluated without any language model.

---

## 2. Terminology

| Term | Definition |
|---|---|
| **Target** | The entity whose degradation is being diagnosed: one workload, identified by a cgroup path, its process/thread IDs, its network namespace and its cpuset. Every snapshot has exactly one target. |
| **Scope** | Where a measurement comes from: `host`, `cpu:<n>`, `cpuset` (the target's CPUs), `cgroup:<path>`, `netns:<target>`, `iface:<netns>/<name>`, `socket:<netns>/<5-tuple>`, `app:<target>`. |
| **Observation scope** | The set of scopes the target's operator can observe. Counters outside it (for example a remote router's qdisc) **MUST NOT** appear in the target's snapshot. |
| **Window** | The interval [t_start, t_end) over which a measurement is aggregated. Default sampling period is 1 s; the analysis window length `W` is a parameter (§6). |
| **Baseline** | A reference distribution for the same feature, target and scope, from a declared *baseline window* free of the incident (§5). |
| **Measurement** | One feature value for one scope and window, with its baseline, deviation, quality and provenance (§10.3). |
| **Predicate** | A named, deterministic boolean or three-valued test over measurements, for example `LOSS.DROP.QDISC` (§7). |
| **Evidence item** | The recorded outcome of evaluating one predicate, with its kind (§3), strength, and the labels it supports or contradicts. |
| **Candidate** | A label under consideration, with its required, supporting, contradictory and missing evidence and its status (§10.6). |
| **Decision** | The single primary label (possibly `INSUFFICIENT_EVIDENCE`), any contributing labels, a confidence level and abstention reasons. |

---

## 3. Evidence kinds

Every evaluated predicate yields exactly one evidence item of one of these kinds.

| Kind | Meaning | Example |
|---|---|---|
| `POSITIVE` | A measured deviation that directly supports one or more labels | Qdisc drop rate far above baseline supports `network_packet_loss` |
| `NEGATIVE` | A measured, in-baseline value that weakens or rules out a label *because it was measured* | All local drop counters measured and at baseline: NEGATIVE for `network_packet_loss` |
| `MISSING` | A measurement the predicate needs could not be obtained (source unavailable, insufficient coverage, insufficient baseline) | `kfree_skb` unavailable (privileged collector not running) |
| `CONFLICTING` | Two or more labels are each supported by POSITIVE evidence and the precedence table (§9) does not resolve them | Strong throttling **and** strong excess run-queue delay of similar magnitude |

**Rules:**
- **E1.** A predicate whose inputs are MISSING **MUST** yield MISSING. It **MUST NOT** yield NEGATIVE: "we could not see drops" ≠ "there were no drops".
- **E2.** A MISSING item **MUST NOT** appear in any label's `supports` list.
- **E3.** A NEGATIVE item for label X **MUST NOT** be counted as POSITIVE for any other label Y.
- **E4.** Each item's `strength` is one of `STRONG`, `MODERATE` or `WEAK` for POSITIVE and NEGATIVE kinds, and `null` for MISSING. Strength comes only from the parameter bands in §6.

---

## 4. Feature registry

Availability codes:

| Code | Meaning |
|---|---|
| `A` | Available now, unprivileged. Verified on this host on 2026-10-02 (Docker container plus host `/proc`/cgroup). |
| `A*` | Available, but this exact read path has **not yet been verified** in a pilot |
| `P` | Requires a privileged collector (eBPF via sudo). Optional. When absent, predicates using it yield MISSING. |
| `L` | FaultLab application instrumentation. Available only once the FaultLab workload is implemented; not available today. |
| `F` | Future. Not collectable in Phase 1C. |

All counters are converted to **rates per second** over the window, from deltas of monotonically increasing counters. A negative delta (counter reset) invalidates that sample (§10.8). Feature IDs are stable identifiers and **MUST NOT** be renamed without a contract version bump.

### 4.1 CPU / scheduler

| Feature ID | Source / locator | Scope | Unit | Aggregation | Avail. |
|---|---|---|---|---|---|
| `cpu.util.host` | `/proc/stat` line `cpu`: (user+nice+system+irq+softirq+steal) / total jiffies | host | fraction 0–1 | mean over W | A |
| `cpu.util.cpuset` | `/proc/stat` lines `cpuN`, N ∈ target cpuset | cpuset | fraction 0–1 | mean over CPUs in set, mean over W | A |
| `cpu.util.percpu` | `/proc/stat` `cpuN` | cpu:N | fraction 0–1 | mean over W | A |
| `cpu.steal.cpuset` | `/proc/stat` `cpuN` steal jiffies / total, N ∈ cpuset | cpuset | fraction 0–1 | mean over W | A |
| `cpu.usage.target` | cgroup `cpu.stat:usage_usec` | cgroup | cores (CPU-s/s) | rate | A |
| `sched.run_delay.target` | `/proc/<pid>/task/<tid>/schedstat` field 2 (ns waiting on a run queue), summed over target threads | cgroup (tasks) | waiting-cores (s/s) | rate | A |
| `sched.run_delay.cpuset` | `/proc/schedstat` `cpuN` field 8 (run_delay ns), N ∈ cpuset | cpuset | waiting-cores | rate, summed | A |
| `sched.run_delay_excess.target` | **Derived:** `max(0, sched.run_delay.target − throttle.time_rate)` | cgroup | waiting-cores | rate | A (derived) |
| `sched.nr_migrations.target` | `/proc/<pid>/task/<tid>/sched:se.nr_migrations`, summed | cgroup (tasks) | migrations/s | rate | A |
| `sched.involuntary_cs.target` | `/proc/<pid>/task/<tid>/status:nonvoluntary_ctxt_switches`, summed | cgroup (tasks) | switches/s | rate | A |
| `sched.ctxt.host` | `/proc/stat:ctxt` | host | switches/s | rate | A |
| `sched.procs_running.host` | `/proc/stat:procs_running` | host | tasks | mean over W | A |
| `psi.cpu.some.target` | cgroup `cpu.pressure` `some total` (µs) | cgroup | stall fraction 0–1 | Δtotal / Δt | A |
| `psi.cpu.some.host` | `/proc/pressure/cpu` `some total` | host | stall fraction 0–1 | Δtotal / Δt | A |
| `sched.latency_hist.target` | eBPF `sched_wakeup` → `sched_switch` histogram | cgroup | ms (p50/p99) | percentile over W | P |

**Verified fact used by this contract (2026-10-02).** For a pure CPU-quota-throttled container, `sched.run_delay.target` (2.823 s) equalled the throttled time (2.823 s). Run-queue delay alone therefore **cannot** separate throttling from contention, so contention evidence uses `sched.run_delay_excess.target`. The equivalence is to be re-checked in the calibration pilot (§6, D-6).

### 4.2 CPU throttling (cgroup v2 CFS bandwidth)

| Feature ID | Source / locator | Scope | Unit | Aggregation | Avail. |
|---|---|---|---|---|---|
| `throttle.quota_limited` | cgroup `cpu.max`: `max` → `0.0` (unlimited), `<quota> <period>` → `1.0` (finite quota) | cgroup | boolean | gauge | A |
| `throttle.quota_cores` | cgroup `cpu.max` → quota/period. **Emitted only when a finite quota exists** (`throttle.quota_limited = 1`); never emitted, and never null, for an unlimited quota. | cgroup | cores | gauge | A |
| `throttle.ratio` | cgroup `cpu.stat`: Δ`nr_throttled` / Δ`nr_periods` | cgroup | fraction 0–1 | over W | A |
| `throttle.time_rate` | cgroup `cpu.stat`: Δ`throttled_usec` / Δt | cgroup | throttled-cores (s/s) | rate | A |
| `throttle.quota_saturation` | **Derived:** `cpu.usage.target / throttle.quota_cores` | cgroup | fraction | over W | A (derived) |

### 4.3 Network: drops (local, within the observation scope)

| Feature ID | Source / locator | Scope | Unit | Aggregation | Avail. |
|---|---|---|---|---|---|
| `net.drop.qdisc` | `tc -s -j qdisc show dev <if>` → `drops` (inside the target netns) | iface | packets/s | rate | A |
| `net.drop.iface_rx` | `/sys/class/net/<if>/statistics/rx_dropped` + `rx_missed_errors` + `rx_fifo_errors` | iface | packets/s | rate | A |
| `net.drop.iface_tx` | `…/tx_dropped` + `tx_fifo_errors` | iface | packets/s | rate | A |
| `net.err.iface` | `…/rx_errors` + `tx_errors` (includes CRC/frame) | iface | packets/s | rate | A |
| `net.drop.softnet` | `/proc/net/softnet_stat` column 2 (dropped), per CPU | cpu:N | packets/s | rate | A |
| `net.drop.socket` | `/proc/net/netstat` TcpExt `TCPBacklogDrop` + `TCPRcvQDrop` (target netns) | netns | packets/s | rate | A |
| `net.drop.netfilter` | Packet counters of declared lab netfilter/tc-police rules (FaultLab only) | netns | packets/s | rate | L |
| `net.drop.kfree_skb` | eBPF `skb:kfree_skb`, **by drop reason**, filtered to the target netns. Each measurement carries a **qualifier** `reason` (pattern `^[A-Z0-9_]+$`); a total over reasons is not representable (§10.3). | netns | packets/s per reason | rate | P |
| `net.pkts.iface` | `…/rx_packets` + `tx_packets` (denominator) | iface | packets/s | rate | A |
| `net.bytes.iface` | `…/rx_bytes`, `tx_bytes` (throughput) | iface | bytes/s | rate | A |

### 4.4 Network: TCP behaviour (target netns)

| Feature ID | Source / locator | Scope | Unit | Aggregation | Avail. |
|---|---|---|---|---|---|
| `tcp.retrans_rate` | `/proc/net/snmp` `Tcp: RetransSegs` (parsed **by header name**) | netns | segments/s | rate | A |
| `tcp.retrans_frac` | Δ`RetransSegs` / Δ`OutSegs` | netns | fraction | over W | A |
| `tcp.out_segs_rate` | `Tcp: OutSegs` (volume / data-quality denominator) | netns | segments/s | rate | A |
| `tcp.timeouts_rate` | `/proc/net/netstat` `TcpExt: TCPTimeouts` | netns | events/s | rate | A |
| `tcp.fast_retrans_rate` | `TcpExt: TCPFastRetrans` | netns | events/s | rate | A |
| `tcp.syn_retrans_rate` | `TcpExt: TCPSynRetrans` | netns | events/s | rate | A |
| `tcp.srtt_ms` | `ss -tin` (`rtt:` srtt) over the target's established sockets | socket | ms | median and p90 over sockets, mean over W | A* |
| `tcp.cwnd` | `ss -tin` `cwnd:` | socket | segments | median over sockets | A* |
| `tcp.retrans_skb_rate` | **EBPF** `tcp:tcp_retransmit_skb` events whose socket is in the target netns (v0.4.0). One event per retransmitted **skb**; an skb can carry several segments (TSO/GSO), so this is **not** segments/s and **not** `tcp.retrans_rate`. No per-socket or per-target attribution is promised. | netns | retransmitted skbs/s (unit `events_per_second`) | rate | P |

### 4.5 Softirq

| Feature ID | Source / locator | Scope | Unit | Aggregation | Avail. |
|---|---|---|---|---|---|
| `softirq.frac.percpu` | `/proc/stat` `cpuN` softirq jiffies / total jiffies | cpu:N | fraction 0–1 | over W | A |
| `softirq.net_rx_rate.percpu` | `/proc/softirqs` `NET_RX` column N | cpu:N | events/s | rate | A |
| `softirq.net_tx_rate.percpu` | `/proc/softirqs` `NET_TX` column N | cpu:N | events/s | rate | A |
| `softirq.exec_time.percpu` | **EBPF** `irq:softirq_entry` → `irq:softirq_exit` on CPU N (kernel monotonic ns), per vector: Σ(exit − entry) / Δt (v0.4.0). Each measurement carries a **qualifier** `vector` from the closed set {`HI`, `TIMER`, `NET_TX`, `NET_RX`, `BLOCK`, `IRQ_POLL`, `TASKLET`, `SCHED`, `HRTIMER`, `RCU`}. **Network** softirq time is only `NET_RX` and `NET_TX`; total softirq time is the sum over all vectors. It is never equated with network softirq time. It is **not** the `/proc/stat` jiffy fraction (`softirq.frac.percpu`), **not** the `/proc/softirqs` event counts, and **not** CPU utilisation. | cpu:N | softirq-cores (CPU-s/s) per vector (unit `cores`) | rate | P |
| `softnet.time_squeeze.percpu` | `/proc/net/softnet_stat` column 3 (hex) | cpu:N | events/s | rate | A |
| `softnet.processed.percpu` | `/proc/net/softnet_stat` column 1 (hex) | cpu:N | packets/s | rate | A |
| `softirq.imbalance` | **Derived:** max_N / median_N of `softirq.frac.percpu` over the relevant CPUs | cpuset/host | ratio | over W | A (derived) |
| `softirq.relevant_cpu_max` | **Derived:** max of `softirq.frac.percpu` over the CPUs the target ran on (cpuset ∪ CPUs observed in task `/proc/<tid>/stat` field 39) | cpuset | fraction | over W | A (derived) |

### 4.6 Memory

| Feature ID | Source / locator | Scope | Unit | Aggregation | Avail. |
|---|---|---|---|---|---|
| `mem.util.target` | cgroup `memory.current` / `memory.max` (`max` → use the host MemTotal) | cgroup | fraction | mean over W | A |
| `mem.available.host` | `/proc/meminfo` `MemAvailable` / `MemTotal` | host | fraction | mean over W | A |
| `psi.mem.some.target` | cgroup `memory.pressure` `some total` | cgroup | stall fraction | Δtotal / Δt | A |
| `psi.mem.full.target` | cgroup `memory.pressure` `full total` | cgroup | stall fraction | Δtotal / Δt | A |
| `psi.mem.some.host` | `/proc/pressure/memory` `some total` | host | stall fraction | Δtotal / Δt | A |
| `mem.reclaim.target` | cgroup `memory.stat` Δ(`pgscan`): reclaim effort. `pgsteal` is **not** part of this feature. | cgroup | pages/s | rate | A |
| `mem.reclaim_direct.host` | `/proc/vmstat` `pgscan_direct` | host | pages/s | rate | A |
| `mem.refault.target` | `memory.stat` `workingset_refault_anon` + `workingset_refault_file` | cgroup | pages/s | rate | A |
| `mem.majfault.target` | `memory.stat` `pgmajfault` | cgroup | faults/s | rate | A |
| `mem.events.high` | cgroup `memory.events:high` | cgroup | events/s | rate | A |
| `mem.events.oom_kill` | cgroup `memory.events:oom_kill` | cgroup | events (count in W) | delta | A |
| `mem.swap.target` | cgroup `memory.swap.current` | cgroup | bytes | gauge | A |
| `mem.swap_io.host` | `/proc/vmstat` `pswpin`, `pswpout` | host | pages/s | rate | A |

### 4.7 Application

These are the only application features SentinelAI may use. All are `L`: they exist **only** once the FaultLab workload (design §6) is implemented. **None is collectable today.** Free-text log lines are **never** features.

| Feature ID | Source | Unit | Aggregation | Avail. |
|---|---|---|---|---|
| `app.latency_ms` | Workload metrics endpoint: request latency histogram | ms | p50, p99 over W | L |
| `app.throughput` | Completed requests | req/s | rate | L |
| `app.error_rate` | Failed / total requests | fraction | over W | L |
| `app.queue_wait_ms` | Time from request admission to worker start | ms | p99 over W | L |
| `app.pool_utilization` | Busy workers / pool size | fraction | mean over W | L |
| `app.pool_rejections` | Requests rejected because the queue was full | req/s | rate | L |
| `app.lock_wait_ms` | Time waiting on the workload's instrumented lock | ms | p99 over W | L |
| `app.dependency_latency_ms` | Latency of the instrumented downstream call | ms | p99 over W | L |
| `app.events` | **Structured** log events with a closed set of codes (`POOL_EXHAUSTED`, `QUEUE_FULL`, `LOCK_WAIT_EXCEEDED`, `DEPENDENCY_TIMEOUT`), counted. Each measurement carries a **qualifier** `code` from that closed set (§10.3). | events/s per code | rate | L |
| (future) real-service metrics | Prometheus/OpenTelemetry from production services | — | — | F |

`app.latency_ms` (p99) is the **impact signal**: it establishes that an incident exists. It is never by itself evidence for any root-cause label.

---

## 5. Baselines and deviation

**Baseline window.** By default this is the **within-run pre-incident window** of length `B` seconds, immediately before the incident window, for the same target and scope. If no clean pre-incident window exists, a *reference baseline* recorded for the same target configuration MAY be used. The snapshot then records `baseline.method = "reference"` and its ID.

**Statistics.** Per-second samples are taken in the baseline window and aggregated:
- `baseline.median`;
- `baseline.mad` (median absolute deviation);
- `baseline.p99`;
- `baseline.n` (number of samples).

**Deviation.** For each measurement, with current value `x` (aggregated over W) and per-feature noise floor `floor_f` (§6):
- `ratio = x / max(baseline.median, floor_f)`
- `delta = x − baseline.median`
- `robust_z = (x − baseline.median) / max(1.4826 × baseline.mad, floor_f)`

The floor is what stops near-zero baselines from producing huge ratios, for example background `kfree_skb` noise rising from 0.5/s to 3/s.

**Baseline adequacy.** If `baseline.n < N_BASE_MIN` or the baseline coverage is below `COV_MIN`, the baseline is **inadequate**. Every predicate on that feature then yields MISSING with reason `BASELINE_INADEQUATE`.

**Contamination.** A baseline window that overlaps an injected fault (FaultLab ground truth) is invalid. In production the baseline window is declared by the caller; the engine never searches for "a convenient baseline".

---

## 6. Parameters (to be calibrated, not invented)

Every threshold is a named parameter. Values are set **only** by the calibration protocol (design §7.4): clean-control and calibration-split data, never test data. In version 0.1.0 all values are `UNCALIBRATED`. An engine **MUST** refuse to run with any `UNCALIBRATED` parameter, except in unit tests, which supply explicit test values.

| Parameter | Meaning | Constraint / calibration source |
|---|---|---|
| `W`, `B` | Analysis and baseline window lengths (s) | Pilot: shortest windows giving a stable baseline MAD |
| `N_BASE_MIN`, `COV_MIN` | Minimum baseline samples; minimum sample coverage | Pilot |
| `floor_f` (per feature) | Noise floor | Clean controls: p99 of the feature's per-window value across clean runs |
| `Z_STRONG`, `Z_MODERATE` | Robust-z bands for STRONG/MODERATE deviations | Calibration split |
| `R_STRONG`, `R_MODERATE` | Ratio bands | Calibration split |
| `DROP_ABS_MIN` | Minimum drop rate (pkts/s) to count as local loss | Clean-control p99 of the drop features × safety factor |
| `DROP_FRAC_MIN` | Minimum drops / (packets + drops) | Calibration split |
| `KFREE_REASONS_LOSS` | Set of kfree_skb drop reasons attributable to path loss | Declared list, reviewed. `NOT_SPECIFIED` is **excluded**. |
| `RT_FRAC_MIN`, `RT_RATE_MIN` | Minimum retransmission fraction / rate | Calibration split |
| `SEG_MIN` | Minimum `tcp.out_segs_rate` for TCP features to be evaluable | Pilot (data quality) |
| `THR_RATIO_MIN`, `THR_TIME_MIN` | Throttling ratio / throttled-time floor | Calibration split; `THR_RATIO_MIN ∈ (0, 1]` |
| `RDX_MIN` | Minimum excess run-queue delay (waiting-cores) | Calibration split |
| `SAT_MIN` | cpuset utilisation counted as saturated | Calibration split; `∈ (0, 1]` |
| `SI_ABS_MIN`, `SI_RATIO_MIN` | Softirq-fraction floor and ratio for a softirq hotspot | Calibration split |
| `SI_SHARE_MIN` | Softirq share of busy time on the relevant CPUs for softirq to dominate | Calibration split |
| `PSI_MEM_MIN` | Memory PSI `some` stall fraction | Calibration split |
| `RECLAIM_MIN`, `REFAULT_MIN` | Reclaim / refault rates | Calibration split |
| `APP_WAIT_MIN`, `APP_SHARE_MIN` | Application queue/lock/dependency wait floor; minimum share of the latency increase explained by app-level wait | Calibration split |
| `IMPACT_MIN` | Minimum `app.latency_ms` p99 deviation for an incident to exist | Calibration split |
| `DOM_RATIO` | Dominance ratio used by precedence rules (§9) | Calibration split; `> 1` |
| `τ_DISAGREE` | Calibrated ML probability at or above which an ML disagreement is flagged (design §5.4) | Calibration split (train only) |

**Parameter types (v0.2.0).** Every parameter has a type: `KFREE_REASONS_LOSS` is `reason_set` (a set of kfree_skb reason names); all others, including the per-feature `floor_f`, are `number`. A numeric `Threshold` (§10.4) may reference only `number` parameters.

---

## 7. Predicate conventions

A predicate has an ID, input features, a three-valued output (`TRUE`, `FALSE`, `MISSING`) and, for TRUE or FALSE, a strength.

- **Deviation predicate** `DEV(f, scope)`:
  - **TRUE/STRONG** when `robust_z ≥ Z_STRONG ∧ ratio ≥ R_STRONG ∧ x ≥ floor_f`;
  - **TRUE/MODERATE** when the `Z_MODERATE`/`R_MODERATE` bands are met;
  - **FALSE** when measured and below the moderate band (a NEGATIVE item, with strength STRONG if `robust_z < 1`, otherwise WEAK);
  - **MISSING** when the input is missing or the baseline is inadequate.
- **Absolute predicate** `ABS(f, θ)`: TRUE when `x ≥ θ`, FALSE when `x < θ`, MISSING otherwise. Used only for bounded physical quantities.
- **Composite predicates** combine with three-valued Kleene logic:
  - `TRUE ∧ MISSING = MISSING`
  - `FALSE ∧ MISSING = FALSE`
  - `TRUE ∨ MISSING = TRUE`
  - `FALSE ∨ MISSING = MISSING`
- **Completeness predicate** `EVALUATED(S)`: TRUE iff every feature in set S is non-MISSING. Used where a label requires that alternatives were *checked*, not merely not seen.

**Impact gate.** `IMPACT := DEV(app.latency_ms p99, app) ∧ ratio ≥ IMPACT_MIN`.
- If IMPACT is FALSE, the decision is `INSUFFICIENT_EVIDENCE` with reason `NO_IMPACT_OBSERVED`. Candidates are still computed and reported.
- If IMPACT is MISSING (application metrics unavailable), evaluation proceeds, but confidence is capped at `MEDIUM` and reason `IMPACT_NOT_MEASURED` is recorded.

---

## 8. Label contracts

For each label: **Required** is necessary for assertion (all clauses). **Primary** (v0.3.0) is an additional clause necessary for the label to be the **decision**, but not for it to be **CONTRIBUTING**: a Primary clause declares the precedence rule and the primary label under which the label may contribute when that clause is FALSE (§9). Only `tcp_retransmissions` has one (RT.R2). **Supporting** raises confidence and is never required. **Contradictory** lowers confidence or blocks assertion as stated. **Insufficient** gives the conditions that force `INSUFFICIENT_EVIDENCE` for that label. **Confusable** gives the boundary rules.

### 8.1 `cpu_contention`
*Runnable target tasks wait for CPU because the CPUs available to them are saturated by competing work. This includes pinned-CPU hotspots and hypervisor steal.*

- **Required:**
  - **CC.R1** `DEV(sched.run_delay_excess.target)` is TRUE. Waiting beyond what quota throttling explains.
  - **CC.R2** `ABS(cpu.util.cpuset, SAT_MIN)` is TRUE **or** `DEV(cpu.steal.cpuset)` is TRUE.
- **Supporting:** `DEV(sched.involuntary_cs.target)`, `DEV(psi.cpu.some.target)`, `DEV(sched.run_delay.cpuset)`, and other cgroups' CPU usage on the same cpuset above baseline.
- **Contradictory:**
  - **CC.X1** `throttle.ratio ≥ THR_RATIO_MIN`. Resolved by §9 rule PR-3.
  - **CC.X2** Softirq dominance on the relevant CPUs (`SI_SHARE_MIN` met). Resolved by PR-5.
- **Insufficient:** CC.R1 MISSING (task schedstat unavailable) → MISSING for this label. High `cpu.util.*` with CC.R1 FALSE is **NEGATIVE** for `cpu_contention`: utilisation alone never asserts it.
- **Confusable:** `cpu_throttling` (PR-3) and `softirq_overload` (PR-5).

### 8.2 `cpu_throttling`
*The target's cgroup is limited by its CFS quota and its waiting is explained by throttling, not by competing work.*

- **Required:**
  - **CT.R1** `throttle.quota_limited == 1` (a finite quota exists).
  - **CT.R2** `ABS(throttle.ratio, THR_RATIO_MIN)` is TRUE **and** `DEV(throttle.time_rate)` is TRUE.
- **Supporting:** `ABS(throttle.quota_saturation, SAT_MIN)`; `sched.run_delay.target ≈ throttle.time_rate` (excess delay FALSE); impact (latency tail) above baseline while `cpu.util.host` is below `SAT_MIN`.
- **Contradictory:** `DEV(sched.run_delay_excess.target)` TRUE means contention is also present (PR-3).
- **Insufficient:** cgroup `cpu.stat` unavailable → MISSING. Quota `max` (unlimited) → `throttle.quota_limited = 0` (quality OK) → CT.R1 FALSE, which is NEGATIVE. Only an unreadable `cpu.max` makes CT.R1 MISSING.
- **Neutral:** `cpu.util.host` is **neither** supporting nor contradictory. A busy host does not make throttling more or less likely.

### 8.3 `softirq_overload`
*Softirq processing (typically NET_RX) saturates one or more CPUs that the target runs on and delays the target, without proven packet drops attributable to it.*

- **Required:**
  - **SI.R1** `ABS(softirq.relevant_cpu_max, SI_ABS_MIN)` **and** `DEV(softirq.frac.percpu)` on the same CPU with ratio ≥ `SI_RATIO_MIN`.
  - **SI.R2** Impact on the target: `DEV(sched.run_delay_excess.target)` TRUE **or** `DEV(psi.cpu.some.target)` TRUE.
- **Supporting:** a NET_RX (or NET_TX) rate increase on the same CPU; `DEV(softnet.time_squeeze.percpu)` on the same CPU; `softirq.imbalance` above baseline.
- **Contradictory:** SI.R2 FALSE. A softirq increase without impact on the target is not an overload of the target.
- **Insufficient:** a *weak* softirq increase (below `SI_ABS_MIN` or below `SI_RATIO_MIN`) yields SI.R1 FALSE, so the label cannot be asserted. If nothing else is asserted, the decision is `INSUFFICIENT_EVIDENCE`.
- **Confusable:**
  - `cpu_contention`: softirq time **is** busy CPU time, and PR-5 decides by softirq share.
  - `network_packet_loss`: when softnet backlog drops occur on the saturated CPUs, PR-2 applies.

### 8.4 `network_packet_loss`
*Packet drops are **proven by local evidence** within the observation scope, at a magnitude above baseline.*

- **Local-drop predicate `LOSS.LOCAL`** is TRUE iff, for **at least one** source s ∈ {`net.drop.qdisc`, `net.drop.iface_rx`, `net.drop.iface_tx`, `net.err.iface`, `net.drop.softnet` (relevant CPUs), `net.drop.socket`, `net.drop.netfilter`, `net.drop.kfree_skb[r ∈ KFREE_REASONS_LOSS]`}, all three hold:
  - `x_s ≥ DROP_ABS_MIN`
  - `DEV(s)` is TRUE (or baseline median = 0 and `x_s ≥ DROP_ABS_MIN`)
  - `x_s / (net.pkts.iface + x_s) ≥ DROP_FRAC_MIN` (for per-interface sources)
- **Required:** **PL.R1** `LOSS.LOCAL` is TRUE.
- **kfree_skb rule (Phase 1B lesson):**
  - `kfree_skb` with reason `NOT_SPECIFIED` or any reason outside `KFREE_REASONS_LOSS` **never** satisfies PL.R1. It may be recorded only as a WEAK supporting item, and only if it deviates from baseline.
  - `kfree_skb > 0` alone is never evidence.
  - Absolute background noise below `floor_kfree` yields FALSE.
- **Supporting:** `DEV(tcp.retrans_frac)`; a drop in `net.bytes.iface` throughput relative to baseline.
- **Contradictory:** all available local drop sources measured and FALSE → NEGATIVE.
- **Insufficient:** If `EVALUATED({net.drop.qdisc, net.drop.iface_rx, net.drop.iface_tx})` is FALSE (the minimum local drop set is missing), then `network_packet_loss` cannot be asserted **and** cannot be ruled out. That matters for §8.5.
- **Scope rule:** drops outside the observation scope (for example in a remote router namespace) **MUST NOT** be included.

### 8.5 `tcp_retransmissions`
*TCP retransmissions or timeouts are elevated for the target and drive the latency, but **no local packet loss is proven**. Examples: path congestion, or loss outside the observation scope.*

- **Required:**
  - **RT.R0** `tcp.out_segs_rate ≥ SEG_MIN` (enough traffic for the ratios to mean anything).
  - **RT.R1** `ABS(tcp.retrans_frac, RT_FRAC_MIN)` **and** `DEV(tcp.retrans_frac)` TRUE. Optionally `DEV(tcp.timeouts_rate)` may substitute when `RetransSegs` is dominated by RTOs.
  - **RT.R2** *(Primary clause, v0.3.0)* `EVALUATED(min local drop set)` TRUE **and** `LOSS.LOCAL` FALSE. Drops were checked and are not proven. RT.R2 is required for `tcp_retransmissions` to be the **decision**. It is **not** required for `tcp_retransmissions` to be **contributing**: with RT.R2 FALSE (local loss proven) and RT.R0, RT.R1 TRUE, the label is CONTRIBUTING under PR-1 when `network_packet_loss` is the decision. Declared subordination: `PR-1`, primary `network_packet_loss`.
- **Supporting:** `DEV(tcp.srtt_ms)` (RTT increase), `DEV(tcp.timeouts_rate)`, a `tcp.cwnd` decrease, a throughput decrease.
- **Contradictory:** `LOSS.LOCAL` TRUE (RT.R2 FALSE). The label cannot be the decision; it becomes *contributing* under PR-1 when `network_packet_loss` is the decision, and is otherwise `SUPPORTED_NOT_SUFFICIENT`.
- **Insufficient:**
  - RT.R1 TRUE but RT.R2 MISSING (drop counters unavailable) → the engine **cannot distinguish** retransmissions from local loss. The decision is `INSUFFICIENT_EVIDENCE` with reason `LOSS_VS_RETRANS_UNDECIDABLE`. With RT.R2 MISSING the label is neither the decision nor contributing (a MISSING Primary clause never enables the contributing path).
  - RT.R0 FALSE → MISSING (low volume).
- **Boundary with `network_packet_loss`:**

| Evidence | Decision |
|---|---|
| Retransmissions high, local drops measured and not elevated | `tcp_retransmissions` |
| Local drops proven (any qualifying source), retransmissions high | `network_packet_loss` (primary) + `tcp_retransmissions` (contributing) |
| Local drops proven, retransmissions low | `network_packet_loss` |
| Retransmissions high, drop counters missing | `INSUFFICIENT_EVIDENCE` (`LOSS_VS_RETRANS_UNDECIDABLE`) |
| Neither elevated | neither (no NEGATIVE-to-POSITIVE transfer to other labels) |

### 8.6 `memory_pressure`
*The target stalls on memory: reclaim, refaults, swapping or OOM. High usage alone does not qualify.*

- **Required:** **MP.R1** any of:
  - `ABS(psi.mem.some.target, PSI_MEM_MIN)` ∧ `DEV(psi.mem.some.target)`;
  - `mem.events.oom_kill > 0` in W;
  - `DEV(mem.reclaim.target)` ∧ `ABS(mem.reclaim.target, RECLAIM_MIN)` ∧ (`DEV(mem.refault.target)` ∨ `DEV(mem.majfault.target)`).
- **Supporting:** `DEV(mem.events.high)`, `DEV(psi.mem.full.target)`, `DEV(mem.swap_io.host)` attributable to the target (swap growth in `mem.swap.target`), `mem.util.target ≥ SAT_MIN`.
- **Contradictory:** high `mem.util.target` (or low `mem.available.host`) **with** PSI, reclaim and refault all measured at baseline. That is NEGATIVE: "memory used, not pressured" (for example page cache).
- **Insufficient:** cgroup `memory.pressure` and `memory.stat` both unavailable → MISSING.
- **Confusable:** `application_bottleneck`. Application-level waits during reclaim are explained by memory pressure (PR-4).

### 8.7 `application_bottleneck`
*The bottleneck is inside the application (pool, queue, lock or dependency), as shown by **positive application-level evidence**, while infrastructure causes were evaluated and are not asserted.*

- **Required:**
  - **AB.R1** at least one positive application-saturation predicate:
    - `DEV(app.queue_wait_ms)` ∧ `app.queue_wait_ms ≥ APP_WAIT_MIN`, or
    - `DEV(app.lock_wait_ms)` ∧ `≥ APP_WAIT_MIN`, or
    - `DEV(app.dependency_latency_ms)` ∧ `≥ APP_WAIT_MIN`, or
    - `DEV(app.pool_rejections)`, or
    - `DEV(app.events[code])` for a code in the closed set.
  - **AB.R2** the application-level wait explains a share ≥ `APP_SHARE_MIN` of the p99 latency increase.
  - **AB.R3** `EVALUATED` for the infrastructure families {CPU/scheduler, throttling, memory, softirq}, plus network (min local drop set and TCP features) whenever `tcp.out_segs_rate ≥ SEG_MIN`. **None of** the six infrastructure labels is assertable. AB.R3's feature list contains every feature of the infrastructure labels' Required and Primary clauses (v0.3.0 added `throttle.quota_limited`, C-3).
- **Never sufficient:**
  - normal kernel evidence;
  - free-text logs ("slow request", "timeout") without a closed-set event code;
  - `app.latency_ms` or `app.error_rate` increases alone. Those are impact, not cause.
- **Supporting:** `app.pool_utilization ≥ SAT_MIN`; matching closed-set events.
- **Contradictory:** any infrastructure label assertable (PR-4).
- **Insufficient:**
  - application metrics `L` unavailable → MISSING. The label cannot be asserted, and there is **no** elimination fallback.
  - AB.R3 not EVALUATED → `INSUFFICIENT_EVIDENCE` (`CONFOUNDER_NOT_EVALUATED`).

### 8.8 `INSUFFICIENT_EVIDENCE`
A decision, not a fault class. It is returned with one or more **reason codes** (§10.7) when any of these holds:
- no label is assertable (`NO_CANDIDATE`);
- impact was measured and absent (`NO_IMPACT_OBSERVED`);
- the leading candidate's required evidence is MISSING (`REQUIRED_EVIDENCE_MISSING`);
- conflicting assertable labels are not resolved by §9 (`CONFLICT_UNRESOLVED`);
- retransmission versus loss is undecidable (`LOSS_VS_RETRANS_UNDECIDABLE`);
- confounders were not evaluated (`CONFOUNDER_NOT_EVALUATED`);
- data quality is below the snapshot gate (`DATA_QUALITY`).

---

## 9. Precedence and conflict resolution

Precedence is applied **only** among labels whose Required and Primary clauses are all TRUE. The table is closed: any pair not listed is a conflict and yields `INSUFFICIENT_EVIDENCE` (`CONFLICT_UNRESOLVED`), with both candidates reported.

**Subordinate-only labels (v0.3.0).** A label whose Required clauses are all TRUE and whose Primary clause is FALSE (never MISSING) takes no part in pairwise precedence and never creates a conflict. It is CONTRIBUTING iff the primary label named by its Primary clause's declared subordination is the decision (RT.R2: `network_packet_loss`, rule PR-1); otherwise it is `SUPPORTED_NOT_SUFFICIENT`. A label with a MISSING Primary clause is never CONTRIBUTING.

| Rule | Co-assertable labels | Resolution | Rationale |
|---|---|---|---|
| PR-1 | `network_packet_loss` + `tcp_retransmissions` | primary `network_packet_loss`; contributing `tcp_retransmissions` (applied through the RT.R2 subordination, since proven loss makes RT.R2 FALSE) | Proven local drops explain the retransmissions |
| PR-2 | `softirq_overload` + `network_packet_loss`, where **all** qualifying drop sources are softnet drops on the softirq-saturated CPUs (or `kfree_skb` reason `CPU_BACKLOG`) | primary `softirq_overload`; contributing `network_packet_loss` | Backlog drops are a consequence of softirq saturation. *This deliberately differs from the Phase 1B confirmatory convention (C05).* |
| PR-2b | Same pair, with drops from any non-softnet source | `CONFLICT_UNRESOLVED` | Independent mechanisms; no causal claim is made |
| PR-3 | `cpu_throttling` + `cpu_contention` | primary = larger of `throttle.time_rate` and `sched.run_delay_excess.target` if the larger ≥ `DOM_RATIO` × the smaller; otherwise conflict | Both are waiting time for the same tasks, so they compare directly |
| PR-4 | any of {`cpu_contention`, `cpu_throttling`, `memory_pressure`, `softirq_overload`, `network_packet_loss`, `tcp_retransmissions`} + `application_bottleneck` | `application_bottleneck` is not assertable (AB.R3); the infrastructure label stands | Application queues build *because of* infrastructure stalls |
| PR-5 | `softirq_overload` + `cpu_contention` | primary `softirq_overload` if the softirq share of busy time on the relevant CPUs ≥ `SI_SHARE_MIN`; otherwise `cpu_contention` if CC.R1 holds without the softirq CPUs; otherwise conflict | Softirq time is busy time |

Any other co-assertion, for example `memory_pressure` + `cpu_contention`, gives `CONFLICT_UNRESOLVED`.

---

## 10. Evidence object schema (Pydantic v2, `extra="forbid"`)

All models are strict (`ConfigDict(extra="forbid", frozen=True)`). Times are UTC RFC 3339 with milliseconds. Floats are finite (no NaN/inf); missing values are `null` **plus** a quality status, never 0.

### 10.1 Enums
- `Label`:
  - `cpu_contention`, `cpu_throttling`, `softirq_overload`, `network_packet_loss`, `tcp_retransmissions`, `memory_pressure`, `application_bottleneck`, `INSUFFICIENT_EVIDENCE`
- `EvidenceKind`: `POSITIVE`, `NEGATIVE`, `MISSING`, `CONFLICTING`
- `Strength`: `STRONG`, `MODERATE`, `WEAK`
- `Quality`: `OK`, `PARTIAL` (coverage below 1 but ≥ `COV_MIN`), `STALE`, `INVALID` (counter reset or parse error), `MISSING`
- `SourceType`:
  - `PROC`, `SYSFS`, `CGROUPFS`, `TC`, `SS`, `EBPF`, `APP_METRICS`, `APP_EVENTS`, `FAULTLAB_GROUND_TRUTH`, `DERIVED`, `PROMETHEUS` (future)
- `Aggregation`: `RATE`, `MEAN`, `GAUGE`, `DELTA`, `RATIO`, `P50`, `P90`, `P99`, `MAX`
- `Unit`:
  - `fraction`, `cores`, `waiting_cores`, `per_second`, `packets_per_second`, `segments_per_second`, `events_per_second`, `pages_per_second`, `bytes`, `bytes_per_second`, `ms`, `count`, `ratio`, `boolean` (values exactly `0.0` or `1.0`)
- `CandidateStatus`: `ASSERTED`, `CONTRIBUTING`, `SUPPORTED_NOT_SUFFICIENT`, `CONTRADICTED`, `NOT_EVALUABLE`, `NOT_SUPPORTED`
- `ConfidenceLevel`: `HIGH`, `MEDIUM`, `LOW`
- `DiagnosticFlag` (v0.2.0): `IMPACT_NOT_MEASURED`, `ML_DISAGREEMENT`
- `AbstentionReason`: listed in §8.8

### 10.2 `Provenance`
| Field | Type | Req. | Notes |
|---|---|---|---|
| `source` | `SourceType` | ✓ | |
| `locator` | str | ✓ | e.g. `"/sys/fs/cgroup/system.slice/docker-<id>.scope/cpu.stat:throttled_usec"` or `"/proc/net/snmp:Tcp.RetransSegs@netns(pid=1234)"` |
| `collector` | str | ✓ | Collector name |
| `collector_version` | str | ✓ | |
| `privileged` | bool | ✓ | |
| `first_sample_at`, `last_sample_at` | datetime | ✓ | |
| `samples` | int ≥ 0 | ✓ | |
| `derived_from` | list[str] | — | Measurement IDs, required when `source = DERIVED` |

### 10.3 `Measurement`
| Field | Type | Req. | Notes |
|---|---|---|---|
| `measurement_id` | str | ✓ | Deterministic: `sha1(feature_id, scope, window[, qualifier][, aggregation])` truncated to 16 hex. The qualifier is included only when present, so unqualified ids are unchanged from 0.1.0. The aggregation is included **only when the feature registers more than one aggregation** (0.5.0); for every single-aggregation feature it is omitted and the id is unchanged from 0.4.0. For a multi-aggregation feature the aggregation is required, so its percentiles (e.g. P50 and P99) are distinct measurements. |
| `feature_id` | str (registry key) | ✓ | Must exist in the registry for `contract_version` |
| `scope` | str | ✓ | §2 scope syntax |
| `window` | `Window` | ✓ | |
| `aggregation` | `Aggregation` | ✓ | Must match the registry |
| `unit` | `Unit` | ✓ | Must match the registry |
| `value` | float \| null | ✓ | `null` iff `quality ∈ {MISSING, INVALID}` |
| `quality` | `Quality` | ✓ | |
| `coverage` | float 0–1 | ✓ | samples / expected samples |
| `baseline` | `BaselineStat` \| null | ✓ | `null` only if no baseline is applicable |
| `deviation` | `Deviation` \| null | ✓ | `null` iff value or baseline is null |
| `provenance` | `Provenance` | ✓ | |
| `qualifier` | `Qualifier` \| null | — | v0.2.0. `Qualifier` = {`dimension`, `value`}. **Required** iff the registry feature declares a dimension (`net.drop.kfree_skb` → `reason`, `app.events` → `code`, `softirq.exec_time.percpu` → `vector` (v0.4.0, closed set)); the dimension must match and the value must satisfy the declared pattern or closed set; **forbidden** otherwise. Omitted from serialisation when null. |

A `boolean` measurement's value is exactly `0.0` or `1.0` (or null with MISSING/INVALID).

`Window` = {`start`, `end`, `duration_s`, `sample_period_s`}. `BaselineStat` = {`method` ∈ {`within_run`, `reference`}, `window`, `median`, `mad`, `p99`, `n`, `adequate`: bool, `baseline_id`?}. `Deviation` = {`ratio`, `delta`, `robust_z`, `floor_used`}.

### 10.4 `EvidenceItem`
| Field | Type | Req. | Notes |
|---|---|---|---|
| `item_id` | str | ✓ | Deterministic from `predicate_id` + `measurement_ids` |
| `predicate_id` | str | ✓ | e.g. `PL.R1/LOSS.LOCAL[net.drop.qdisc]`, `RT.R2`, `CT.R2` |
| `kind` | `EvidenceKind` | ✓ | |
| `strength` | `Strength` \| null | ✓ | `null` iff kind ∈ {MISSING, CONFLICTING} |
| `measurement_ids` | list[str] ≥ 1 | ✓ | Every ID must exist in the snapshot |
| `observed` | float \| null | ✓ | |
| `threshold` | {`parameter`, `value`} \| null | ✓ | Parameter name and the calibrated value used |
| `supports` | list[Label] | ✓ | Empty for NEGATIVE/MISSING |
| `contradicts` | list[Label] | ✓ | |
| `missing_reason` | str \| null | ✓ | Required iff kind = MISSING |
| `rationale` | str | ✓ | Templated from the predicate definition; no free text |

### 10.5 `EvidenceSnapshot`
| Field | Type | Req. | Notes |
|---|---|---|---|
| `schema_version` | `"0.2.0"` | ✓ | |
| `contract_version` | str | ✓ | |
| `parameter_set_id` | str | ✓ | Hash of the calibrated parameter file |
| `snapshot_id` | str | ✓ | Deterministic from target + window + inputs hash |
| `incident_id` | str \| null | — | |
| `target` | `Target` | ✓ | {`name`, `cgroup_path`, `pids`, `cpuset`, `netns_ref`, `ifaces`} |
| `window` | `Window` | ✓ | Incident window |
| `baseline_window` | `Window` | ✓ | |
| `measurements` | list[`Measurement`] | ✓ | |
| `evidence_items` | list[`EvidenceItem`] | ✓ | |
| `missing_measurements` | list[{`feature_id`, `scope`, `reason`, `qualifier`?}] | ✓ | Explicit; empty list if none. Identity is (`feature_id`, `scope`, `qualifier`). |
| `conflicts` | list[{`labels`, `rule`, `item_ids`}] | ✓ | |
| `data_quality` | `DataQuality` | ✓ | {`overall_coverage`, `sources_unavailable`, `privileged_sources_unavailable`, `baseline_adequate`, `counter_resets`, `gate_passed`: bool} |

### 10.6 `DiagnosticResult`
| Field | Type | Req. | Notes |
|---|---|---|---|
| `snapshot_id` | str | ✓ | |
| `decision` | `Label` | ✓ | |
| `contributing` | list[Label] | ✓ | Labels with status CONTRIBUTING (§9) |
| `abstained` | bool | ✓ | `true` iff `decision = INSUFFICIENT_EVIDENCE` |
| `abstention_reasons` | list[`AbstentionReason`] | ✓ | Non-empty iff `abstained` |
| `confidence_level` | `ConfidenceLevel` | ✓ | Rule-engine ordinal (§10.9). **Not a probability.** |
| `candidates` | list[{`label`, `status`, `required_met`, `required_missing`, `supporting`, `contradicting`, `rules_fired`}] | ✓ | One entry for each of the 7 fault labels, always |
| `rules_fired` | list[str] | ✓ | |
| `ml` | {`model_id`, `probabilities`: dict[Label, float], `calibrated`: bool, `agrees_with_rules`: bool} \| null | — | Advisory only (design §5) |
| `engine` | {`contract_version`, `rules_version`, `parameter_set_id`, `code_commit`} | ✓ | |
| `flags` | list[`DiagnosticFlag`] | — | v0.2.0, default empty, no duplicates. Diagnostic metadata about the decision of record; never abstention reasons, never engine info, never evaluation data. |

### 10.7 Invariants (validated by the schema and by tests)
- **I1.** `abstained ⇔ decision = INSUFFICIENT_EVIDENCE ⇔ abstention_reasons ≠ ∅`.
- **I2.** If `decision ≠ INSUFFICIENT_EVIDENCE`, every Required and Primary clause of `decision` has a POSITIVE item (or, for RT.R2 and AB.R3, the specified FALSE/EVALUATED items).
- **I3.** No MISSING item appears in any `supports`.
- **I4.** No candidate is ASSERTED unless all its Required and Primary items are POSITIVE (or the required negations are satisfied). No candidate is CONTRIBUTING unless all its Required items are POSITIVE; if one of its Primary clauses is unmet, the decision must be that clause's declared primary label and the snapshot must contain a NEGATIVE item of that clause contradicting the candidate (v0.3.0). `required_met`/`required_missing` partition the Required and Primary clauses.
- **I5.** Every `measurement_ids` reference resolves, and every measurement's `feature_id` and `unit` match the registry.
- **I6.** `application_bottleneck` ASSERTED implies at least one POSITIVE item from an `app.*` feature other than `app.latency_ms` or `app.error_rate`.
- **I7.** Same inputs and parameter set give a byte-identical serialised result (sorted keys, fixed float formatting).

Additional schema rules (v0.2.0; consistency checks, not diagnostic logic):
- **Q1.** In a snapshot, `throttle.quota_limited = 0` must not coexist with a non-null `throttle.quota_cores` for the same scope.
- **F1.** `IMPACT_NOT_MEASURED` ∈ `flags` ⇒ `confidence_level ≠ HIGH`.
- **F2.** `ML_DISAGREEMENT` ∈ `flags` ⇒ `ml` is present ∧ `ml.agrees_with_rules = false`.
- **U1.** Measurement identity within a snapshot is (`feature_id`, `scope`, `window`, `qualifier`).

### 10.8 Data quality
- A sample with a negative counter delta is `INVALID`.
- A measurement with `coverage < COV_MIN` is `MISSING`.
- A measurement whose last sample is older than `W` is `STALE`, treated as MISSING by predicates.
- The snapshot gate fails if `overall_coverage < COV_MIN` or `baseline_adequate = false` for every family. The decision is then `INSUFFICIENT_EVIDENCE` (`DATA_QUALITY`).

### 10.9 Rule-engine confidence (ordinal)
- **HIGH:** every Required item is STRONG, there are no contradictory items, impact is measured, and there are no MISSING supporting sources.
- **MEDIUM:** Required met with at least one MODERATE, **or** impact not measured, **or** at least one supporting source MISSING.
- **LOW:** used only for candidates that are not asserted. An asserted decision is never LOW.

These levels are **not** probabilities. Calibrated probabilities come only from the ML layer (design §5) and are reported separately.

---

## 11. Provenance requirements

Every measurement **MUST** be traceable to a source and locator (§10.2). Every evidence item **MUST** list the measurements and the threshold parameter it used. A consumer must be able to answer "why do you believe this?" by following:

`DiagnosticResult.candidates[].supporting` → `EvidenceItem.measurement_ids` → `Measurement.provenance.locator`, together with the raw samples retained by the collector (design §8).

FaultLab ground truth (`FAULTLAB_GROUND_TRUTH`) **MUST NOT** appear in a snapshot's measurements. It is stored separately and used only for evaluation.

## 12. Versioning

- The contract uses semantic versioning.
- **0.5.0-draft note.** M3B-C1 adds the aggregation to the identity of multi-aggregation measurements (§10.3). No feature, clause, predicate, parameter or precedence rule changes, and every single-aggregation id is unchanged, so it is released as a **minor** change: 0.4.0 → 0.5.0. Schema stays `0.2.0`; 0.2.0–0.4.0-draft snapshots (major 0) remain accepted. Limitation: a 0.4.0 snapshot that contains a multi-aggregation measurement carries the aggregation-free id and fails 0.5.0 identity validation. No such snapshot was ever produced (no collector emits `sched.latency_hist.target`, `app.latency_ms` or `tcp.srtt_ms`, and the defect prevented two percentiles from coexisting).
- **0.4.0-draft note.** M3B-C0 adds two features and one qualifier dimension, and changes nothing existing. That is a **minor** change under this section: 0.3.0 → 0.4.0. Schema stays `0.2.0`, and 0.2.0/0.3.0-draft snapshots (major 0) remain accepted.
- **0.3.0-draft governance note.** C-1 changes the role of the Required clause RT.R2, which this section classifies as a major change. Following the 0.2.0-draft precedent (pre-release draft, consumers M1 and M2 only), it is released as `0.3.0-draft`; the reviewer may decide otherwise. The evidence object schema is unchanged, so `schema_version` stays `0.2.0`, and snapshots recorded under `0.2.0-draft` (same major version 0) remain accepted.
- **0.2.0-draft governance note.** R-1 changes the Required clause CT.R1, which this section classifies as a major change. Because the contract is a pre-release draft whose only consumer is M1, the reviewer decided to release the pre-M2 correction as `0.2.0-draft` (schema `0.2.0`). Snapshots with `schema_version` other than `0.2.0` are rejected; there is no migration.
- Adding a feature or parameter is a **minor** bump.
- Changing a Required clause, the precedence table or a label is a **major** bump.
- A snapshot records `contract_version`. An engine **MUST** reject snapshots of a different major version.
