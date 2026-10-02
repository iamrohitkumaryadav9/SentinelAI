# Phase 1C — M3A Report: Real Linux Evidence Collection Layer

| | |
|---|---|
| Milestone | Phase 1C M3A (observation layer only) |
| Before | HEAD `f7fb0c88014905796800c72680e44e2cc0131617`; `git status`: `?? experiments/faultlab/` only |
| Versions | contract `0.3.0-draft`, schema `0.2.0`, rules `m2-1.1.0` (all unchanged); collector `m3a-1.0.0` |
| Gate | **PASS WITH CONDITIONS** (§17) |

---

## 1. Objective

Turn real Linux host telemetry into contract-valid, deterministic `EvidenceSnapshot` measurements that the existing M2 engine can consume:

```
Linux host (/proc, /sys, cgroup v2) → probes (read + parse) → normalisation (rates, coverage, quality, baseline)
  → Measurement → EvidenceSnapshot (0.3.0-draft / 0.2.0) → M2 diagnose() → DiagnosticResult
```

The collector layer **observes only**. It contains no thresholds, labels, evidence items or verdicts. The contract and the M2 engine are unchanged.

## 2. Architecture

New package `src/sentinelai/collectors/`, 1,441 lines. The four concerns are kept separate:

| Concern | Module | Contents |
|---|---|---|
| Acquisition | `reader.py` | `LiveReader`, read-only by construction: `open(path, "rb")`, `listdir`, `readlink`, and every path is checked against an allowlist (`/proc/`, `/sys/`, no `..`). `FixtureReader` serves the same interface for tests. |
| Acquisition | `clock.py` | `SystemClock`, and `ManualClock` for deterministic tests. Only collectors read time. |
| Acquisition | `probes.py` | `sample(reader, target)`: one read of every source per tick, giving numbers or an explicit `Bad(status)` (absent / denied / malformed / unverified) |
| Parsing | `parsers/proc.py`, `parsers/cgroup.py`, `parsers/sysfs.py`, `parsers/_common.py` | Pure text → numbers, or `ParseError`. No defaults and no guessing. |
| Normalisation | `features.py` | Contract feature → computation table: source fields, scope, formula, locator. No thresholds. |
| Normalisation | `normalize.py` | Interval deltas, counter-reset detection, coverage, window value, baseline statistics |
| Measurement construction | `snapshot.py` | `collect()` (the only I/O and time code), `build_snapshot()` (a pure function of the recorded ticks), data quality, missing-measurement list |
| Measurement construction | `target.py` | `resolve_target()`: pids from `cgroup.procs`, nearest `cpuset.cpus.effective`, `netns_ref = pid:<first pid>` |

Supporting files:
- `scripts/m3a_smoke.py`: the real-host smoke run.
- `results/phase1c_m3a/`: smoke artefacts (snapshots, diagnoses, summary).
- `tests/collectors/`: 70 tests.

Public API: `resolve_target`, `collect_snapshot(target, params)` (gives a snapshot plus stats), `collect`, `build_snapshot`, `check_parameters`, `collected_features`.

## 3. Contract feature mapping

The registry has **55 features of availability A/A\***.

**Collected: 52.** Every one is a registered feature with its registered unit, aggregation, scope kind and source; the M1 `Measurement` validator enforces all four.

| Family | Features |
|---|---|
| cpu_sched | `cpu.util.host`, `cpu.util.cpuset`, `cpu.util.percpu`, `cpu.steal.cpuset`, `cpu.usage.target`, `sched.run_delay.target`, `sched.run_delay.cpuset`, `sched.run_delay_excess.target` (derived), `sched.nr_migrations.target`, `sched.involuntary_cs.target`, `sched.ctxt.host`, `sched.procs_running.host`, `psi.cpu.some.target`, `psi.cpu.some.host` |
| cpu_throttling | `throttle.quota_limited`, `throttle.quota_cores`, `throttle.ratio`, `throttle.time_rate`, `throttle.quota_saturation` (derived) |
| network_drops | `net.drop.iface_rx`, `net.drop.iface_tx`, `net.err.iface`, `net.drop.softnet`, `net.drop.socket`, `net.pkts.iface`, `net.bytes.iface` |
| network_tcp | `tcp.retrans_rate`, `tcp.retrans_frac`, `tcp.out_segs_rate`, `tcp.timeouts_rate`, `tcp.fast_retrans_rate`, `tcp.syn_retrans_rate` |
| softirq | `softirq.frac.percpu`, `softirq.net_rx_rate.percpu`, `softirq.net_tx_rate.percpu`, `softnet.time_squeeze.percpu`, `softnet.processed.percpu`, `softirq.imbalance` (derived), `softirq.relevant_cpu_max` (derived) |
| memory | `mem.util.target`, `mem.available.host`, `psi.mem.some.target`, `psi.mem.full.target`, `psi.mem.some.host`, `mem.reclaim.target`, `mem.reclaim_direct.host`, `mem.refault.target`, `mem.majfault.target`, `mem.events.high`, `mem.events.oom_kill`, `mem.swap.target`, `mem.swap_io.host` |

**Registered but deliberately not collected.** These are reported explicitly in every snapshot's `missing_measurements` with a reason; none is silently dropped:

| Feature | Avail. | Reason |
|---|---|---|
| `net.drop.qdisc` | A | Its only registered source is `tc -s -j qdisc show`, and **tc is forbidden in M3A** (see condition C-A) |
| `tcp.srtt_ms`, `tcp.cwnd` | A\* | They need an `ss` collector. They are not Required by any clause (supporting only); the read path is unverified (A\*); target-socket attribution (`ss -p`) needs privileges for other users' processes. Per Step 11, `ss` is not added merely because it is available. |
| `sched.latency_hist.target`, `net.drop.kfree_skb` | P | Need eBPF (forbidden). Recorded in `privileged_sources_unavailable = ["EBPF"]`. kfree_skb isn't listed per scope, because a MissingMeasurement for it needs a reason qualifier and the reason set is open. |
| `net.drop.netfilter`, `app.*` | L | FaultLab or application instrumentation, not available. Every `app.*` feature, including `app.events` for each closed-set code, is listed as missing. |

No Linux metric outside the contract was added. **Not added, for the reviewer:** `/proc/net/dev` holds the same interface sums the contract takes from sysfs, and is readable inside another netns via `/proc/<pid>/net/dev`. The registry allows only SYSFS as the source for those features, so I didn't use it (see C-C).

## 4. Source mapping

| Source | Parser | Features | Notes |
|---|---|---|---|
| `/proc/stat` | `proc_stat` | cpu.util.\*, cpu.steal.cpuset, softirq.frac.percpu, sched.ctxt.host, sched.procs_running.host | busy = user+nice+system+irq+softirq+steal; total = busy+idle+iowait (guest is already in user, so it isn't added) |
| `/proc/schedstat` (v15) | `schedstat` | sched.run_delay.cpuset | cpu line field 8 = run_delay ns |
| `/proc/<pid>/task/<tid>/{schedstat,sched,status,stat}` | `task_*` | sched.run_delay.target, sched.nr_migrations.target, sched.involuntary_cs.target; stat field 39 gives the relevant CPUs | Summed over target threads |
| `/proc/softirqs` | `softirqs` | softirq.net_rx/tx_rate.percpu | Columns by `CPUn` header |
| `/proc/net/softnet_stat` | `softnet_stat` (hex) | net.drop.softnet (col 2), softnet.time_squeeze (col 3), softnet.processed (col 1) | CPU from the cpu-id column, never the row index |
| `/proc/<netns-pid>/net/snmp`, `/netstat` | `snmp_table` (by header name) | tcp.\*, net.drop.socket | Target netns via its pid |
| `/proc/meminfo`, `/proc/vmstat`, `/proc/pressure/{cpu,memory}` | `meminfo`, `vmstat`, `psi` | mem.available.host, mem.reclaim_direct.host, mem.swap_io.host, psi.\*.host | |
| cgroup `cpu.stat`, `cpu.max`, `cpu.pressure` | `cpu_stat`, `cpu_max`, `psi` | cpu.usage.target, throttle.\*, psi.cpu.some.target | |
| cgroup `memory.{current,max,swap.current,pressure,stat,events}` | `single`, `memory_max`, `memory_stat`, `memory_events`, `psi` | mem.\*.target, psi.mem.\*.target | `memory.max = max` → host MemTotal (contract §4.6) |
| `/sys/class/net/<if>/statistics/*` | `counter` | net.drop.iface_rx/tx, net.err.iface, net.pkts.iface, net.bytes.iface | Only when the target netns is verified equal to the collector's (§6) |

Scopes: `host`, `cpuset`, `cpu:N`, `cgroup:<path>`, `netns:<target>`, `iface:<target>/<if>`. These are exactly the M2 engine's scope binding.

## 5. Parser design

**Pure and deterministic.** Parsers take text in and give integers out, or raise `ParseError`. They read no files and hold no global state.

**Headers parsed by name.** `/proc/net/snmp` and `netstat` are parsed by header name, so column order doesn't matter. A header/value length mismatch or duplicate names is rejected.

**Strict.** Each malformed shape is rejected with `ParseError`:
- non-integer or negative counters;
- duplicate keys, CPUs or lines;
- missing aggregate `cpu` line;
- short lines;
- unsupported `schedstat` version (only 15 is accepted);
- a softnet row without a cpu-id column (pre-5.10 rows skip offline CPUs and can't be attributed);
- `cpu.max` with a zero quota or period;
- PSI without `total`.

**Tolerant only where the format is defined to grow.** Extra `/proc/stat` lines and guest columns, other snmp sections, extra `memory.stat` keys, and comm strings with spaces or parentheses in `task/stat` are all handled.

## 6. Data-quality semantics

Contract §10.3 and §10.8, and Step 15 of the prompt. Each rule is tested and covered by a mutant (§11).

| Situation | Result | Never |
|---|---|---|
| File absent or field absent | interval absent → coverage ↓; whole W gives **MISSING** (value null) + MissingMeasurement with reason | 0 |
| Permission denied | as above, reason `denied: …` | 0 |
| Malformed text | interval **INVALID**; whole W gives INVALID (value null) | best-effort guess |
| Counter decreases (reset) | that interval INVALID, counted in `data_quality.counter_resets` (distinct counter × interval). The window value comes from the valid intervals only. | clamped to 0 |
| Coverage < COV_MIN | **MISSING** (§10.8) | a partial number |
| COV_MIN ≤ coverage < 1 | **PARTIAL** | |
| Gauge with no sample in W but samples in the baseline | **STALE**, value = last known, `last_sample_at` older than W | OK |
| Ratio whose denominator didn't advance (0/0), or a zero softirq median | **MISSING**, reason "undefined …" | 0 |
| Fraction outside [0, 1] (for example PSI > 1 s per second) | INVALID; out-of-range baseline samples are dropped | clamped |
| Boolean gauge changes within W (quota added or removed mid-window) | INVALID | averaged |
| `cpu.max = max` | `throttle.quota_limited = 0.0` (a real value); `quota_cores` and `quota_saturation` **not emitted** (§4.2) | |
| `cpu.max` absent (no cpu controller) or unreadable | `quota_limited` **MISSING** | "unlimited" |
| `cpu.max` malformed | INVALID | |
| Target netns can't be compared (root target, `ns/net` unreadable) or differs | interface features MISSING, reason `unverified` (sysfs shows the collector's netns) | the host's counters attributed to the target |
| CPU disappears or appears | its intervals are absent; cpuset features need every cpuset CPU in an interval; no baseline means `baseline = null` | |
| Thread appears or exits | Summed over threads present at both ends of an interval. A new thread is never counted from 0, and an exit is not a reset. | |

Snapshot-level `DataQuality`:

| Field | Definition |
|---|---|
| `overall_coverage` | Mean coverage over attempted measurements |
| `baseline_adequate` | True if at least one feature family has an adequate baseline (§10.8: the gate fails only if *every* family is inadequate) |
| `sources_unavailable` | `TC`, `SS`, `APP_METRICS`, `APP_EVENTS`, plus any source type with no usable measurement |
| `privileged_sources_unavailable` | `["EBPF"]` |
| `gate_passed` | `overall_coverage ≥ COV_MIN ∧ baseline_adequate` |

## 7. Counter-rate semantics

**Sampling.** Ticks are k = 0 … nB+nW, at t0 + k·period with period = 1 s, nB = B/period and nW = W/period (both parameters). Interval k spans ticks k−1 → k. Intervals 1…nB form the baseline window; nB+1…nB+nW form the incident window W.

**Value in W.** Shared-denominator aggregation over the valid intervals:

| Kind | Value |
|---|---|
| Rates | ΣΔ / Σdt |
| Ratios | ΣΔnum / ΣΔden |
| Counts (`mem.events.oom_kill`, DELTA) | ΣΔ |
| Gauges | Sampled at the start of each interval (so in [start, end)): MEAN aggregation is the mean, GAUGE is the last sample, boolean must agree |
| Derived | The contract formula on the window aggregates: excess = max(0, run_delay − throttle.time_rate); saturation = usage / quota_cores; relevant_cpu_max and imbalance over cpuset ∪ CPUs the target's threads ran on in W |

**Timing.** `dt` comes from the monotonic clock. Window bounds are the actual UTC wall times of the ticks, truncated to milliseconds.

**Baseline (§5, `within_run`).** Per-interval values over the baseline window give median, MAD (unscaled), nearest-rank p99 and n. The baseline is adequate iff n ≥ N_BASE_MIN and baseline coverage ≥ COV_MIN.

**Deviation.** `ratio = x/max(median, floor_f)`, `delta`, `robust_z = (x − median)/max(1.4826·MAD, floor_f)`.

**The floors come from the ParameterSet.** The collector refuses to start, before reading anything, unless W, B, COV_MIN, N_BASE_MIN and a positive `floor[f]` for every collected feature are present. That is the §6 refuse-to-run rule, and every missing name is reported together.

## 8. Safety design

**Read-only.** The only file operation is `open(path, "rb")`, plus `listdir` and `readlink`, all behind the `/proc/`, `/sys/` allowlist. The allowlist rejects `/etc`, `/dev`, relative paths, `..` and NUL.

**No processes, network or privileges.** The collector package imports no subprocess, socket or ctypes and spawns nothing. It has no privileged path, no sudo, and doesn't modify cgroups, affinity, qdiscs or links. The smoke script reads the commit hash from `.git` rather than running `git`.

**NIC.** `enp0s31f6` is only *read*, via `/sys/class/net/enp0s31f6/statistics/*`, and only for the session target whose netns is verified. Nothing is written to it.

**Static tests** (`tests/collectors/test_safety.py`) enforce all of this over every collector file:
- banned primitives (subprocess/os.system/exec/spawn/socket/ctypes/os.write/remove/rename/chmod/kill/sched_setaffinity/sudo/nsenter/setns/write_text);
- exactly one `open(..)`, in `reader.py`, in mode `"rb"`;
- no mutating commands (`tc … add|del`, `ip link|route|addr`, netem, ethtool, iptables, nft, docker, systemctl, bpftrace, bcc, ollama), and no reference to the NIC name;
- imports limited to stdlib modules and the project.

## 9. Fixture coverage

`tests/collectors/_world.py` is a synthetic host that renders every source file from counters with known per-tick rates. Every expected value is therefore exact: util 0.75, softirq fraction 0.05, retrans_frac 0.01, run-delay 0.1, quota saturation 0.8, and so on. Faults are injected per tick: absent, denied, malformed, reset, CPU or thread churn, netns mismatch.

| Source | Valid | Missing | Malformed | Reset | Partial | Unexpected field | Unit / range |
|---|---|---|---|---|---|---|---|
| `/proc/stat` | ✓ | ✓ | ✓ | (via features) | ✓ | ✓ (extra lines, guest) | ✓ |
| `/proc/schedstat` | ✓ | — | ✓ (incl. version) | — | — | ✓ (domain lines) | — |
| `/proc/softirqs` | ✓ | — | ✓ | — | — | ✓ (HI etc.) | — |
| `/proc/net/softnet_stat` | ✓ (hex, cpu column) | — | ✓ | — | — | ✓ (no cpu column rejected) | — |
| snmp / netstat | ✓ (by name, any order) | ✓ | ✓ | ✓ | ✓ | ✓ (other sections) | ✓ (0/0 → MISSING) |
| PSI | ✓ | — | ✓ | — | — | ✓ | ✓ (> 1 → INVALID) |
| cgroup cpu (`cpu.stat`, `cpu.max`) | ✓ | ✓ | ✓ | — | — | — | ✓ (boolean, three quota states, mid-window change) |
| cgroup memory | ✓ | ✓ (denied) | ✓ | — | — | ✓ | ✓ (STALE) |
| sysfs interface | ✓ | ✓ | — | — | — | — | ✓ (netns guard) |
| per-task files | ✓ | — | ✓ | ✓ | — | ✓ (comm with spaces) | ✓ (thread churn) |

## 10. Real-host smoke results

`scripts/m3a_smoke.py`, read-only, B = 45 s and W = 10 s (56 ticks, about 55 s per target). The host was idle (`ollama serve` running with no model loaded; load average 0.13). Artefacts are in `results/phase1c_m3a/`.

| | Target A: `cron` | Target B: `self` |
|---|---|---|
| cgroup | `/system.slice/cron.service` | `/user.slice/user-1000.slice/session-136.scope` |
| pids | 1 | 37 |
| cpuset | 0–23 | 0–23 |
| Measurements | 211: **204 OK, 7 MISSING** | 213: **206 OK, 7 MISSING** |
| MISSING | 5 interface features: root target, `ns/net` unreadable, so the netns can't be verified. `throttle.ratio`: no CFS periods (quota unlimited, `quota_limited = 0.0` OK). `softirq.imbalance`: median softirq fraction 0. | 5 throttling features + `run_delay_excess`: the session cgroup has no cpu controller, so `cpu.max` is absent → MISSING, not "unlimited". `softirq.imbalance`: median 0. |
| missing_measurements | 24 | 24 |
| overall_coverage | 0.976 | 0.972 |
| baseline_adequate | true | true |
| counter_resets | 0 | 0 |
| gate_passed | true | true |
| Validation | Snapshot re-validated from its canonical JSON | Snapshot re-validated from its canonical JSON |

The B target's interface features (netns verified) are all OK on `enp0s31f6` (read only).

## 11. M2 integration result

Both real snapshots were accepted by `diagnose()`, using the explicitly labelled parameter set `UNCALIBRATED-m3a-smoke-test-values`. The result has full self-validation of I1–I6 and engine info `0.3.0-draft / m2-1.1.0`.

| Target | Decision | Reasons | Flags | Confidence |
|---|---|---|---|---|
| cron | INSUFFICIENT_EVIDENCE | REQUIRED_EVIDENCE_MISSING | IMPACT_NOT_MEASURED | LOW |
| self | INSUFFICIENT_EVIDENCE | REQUIRED_EVIDENCE_MISSING | IMPACT_NOT_MEASURED | LOW |

That is the expected, legitimate result for an idle host with no application metrics; no incident was manufactured. Network packet loss is NOT_EVALUABLE because the minimum local drop set is incomplete without `net.drop.qdisc`.

application_bottleneck shows SUPPORTED_NOT_SUFFICIENT. This is M2's status rule (AB.R3 "family evaluated" items are POSITIVE), not an assertion: AB.R1 is MISSING.

Fixture integration (`test_integration.py`):
- The normal synthetic host gives INSUFFICIENT_EVIDENCE with IMPACT_NOT_MEASURED.
- A synthetic contention signal (target run-delay 0.1 → 0.9 waiting-cores, cpuset 0.75 → 0.98 busy) is diagnosed **`cpu_contention`** by M2. Collected evidence therefore flows end to end.
- High retransmissions without the qdisc counter give **INSUFFICIENT_EVIDENCE (LOSS_VS_RETRANS_UNDECIDABLE)**. Missing drop evidence never becomes "no loss".
- M2 output on collected input is deterministic.

## 12. Performance

Measured during the smoke run, with no LLM inference running.

| Target | Wall | Collector CPU | CPU share | Peak RSS | Slowest tick read |
|---|---|---|---|---|---|
| cron (1 pid) | 55.0 s | 0.146 s | **0.27 % of one core** | 33 MB | 3.1 ms |
| self (37 pids, more threads) | 55.0 s | 0.934 s | **1.7 % of one core** | 40 MB | 20.0 ms |

Per-thread files dominate cost: 4 reads per thread per tick. RSS is mostly the Python interpreter and pydantic. This is well within the Phase 0 budget (24 CPUs, about 15.7 GB RAM). No optimisation was attempted.

## 13. Test results

| Suite | Result |
|---|---|
| M3A collector tests (`tests/collectors`, 70) | **70 / 70 passed**: parsers 21, quality 27, snapshot/contract/determinism 11, integration 4, safety 6, live 1, plus subtests |
| M1 contract tests (`tests/evidence`) | 192 / 192 passed (unchanged) |
| M2 engine tests (`tests/rules`) | 95 / 95 passed (unchanged) |
| Full repository | **381 run: 380 passed, 0 failed, 1 skipped** (the pre-existing root-only skip) |
| Deterministic replay | 3 builds byte-identical. Shuffled observation order is byte-identical. `collect()` with `ManualClock` and a step reader is byte-identical to `build_snapshot()`. |
| Mutation testing | **19 / 19 killed** against a clean, passing unmutated control |

The mutants covered:
- reset clamped to 0; a missing counter treated as 0; malformed treated as absent;
- the COV_MIN rule removed; STALE replaced by MISSING; an undefined ratio becomes 0;
- netns guard removed; a different netns accepted; unreadable `cpu.max` treated as unlimited; `quota_cores` emitted when unlimited;
- a new thread counted from 0; softnet CPU taken from the row index; boolean disagreement averaged;
- baseline adequacy ignoring N_BASE_MIN; snmp parsed by position;
- the allowlist removed; the parameter check removed; the range check removed; a MISSING measurement not listed.

Three mutants first survived:
- thread churn;
- complete parameter reporting;
- the per-interval range check.

All three were real test gaps. I added exact-value assertions for each rather than accepting the survivors.

No existing test was modified.

## 14. Files changed

All new; no tracked file is modified, and the M1 and M2 code and contract are untouched.

| Path | Purpose |
|---|---|
| `src/sentinelai/collectors/{__init__,errors,clock,reader,probes,features,normalize,snapshot,target}.py` | Collector layer |
| `src/sentinelai/collectors/parsers/{__init__,_common,proc,cgroup,sysfs}.py` | Parsers |
| `tests/collectors/{__init__,_world,test_parsers,test_quality,test_snapshot,test_integration,test_safety,test_live}.py` | Tests |
| `scripts/m3a_smoke.py` | Real-host smoke run |
| `results/phase1c_m3a/{cron,self}_{snapshot,diagnosis}.json`, `summary.json` | Smoke artefacts |
| `docs/PHASE_1C_M3A_REPORT.md` | This report |

`experiments/faultlab/` is untouched and not committed.

## 15. Known limitations (the conditions)

**C-A — `net.drop.qdisc` cannot be collected under the M3A scope.** The contract's only source is `tc -s -j qdisc show`, and M3A forbids tc. Since qdisc is in `min_local_drop_set`:
- on real data, LOSS.LOCAL can be **proven** (iface, softnet and socket drops) but never **ruled out**;
- so RT.R2 is never TRUE and **tcp_retransmissions can never be the decision**: it abstains with LOSS_VS_RETRANS_UNDECIDABLE, which is safe.

Reviewer options:
- (a) authorise a narrowly wrapped read-only `tc -s -j qdisc show dev <if>` (fixed path and arguments, no shell, timeout); or
- (b) read the same counters via rtnetlink `RTM_GETQDISC` (read-only; needs a contract source addition); or
- (c) accept the limitation.

**C-B — No calibrated parameter set exists.** Deviation needs `floor[f]`, and M2 needs every threshold. The smoke run used explicitly labelled **uncalibrated test values**, so its decisions have no diagnostic meaning. Calibration is a later milestone, and the collector and engine refuse to run without a complete set.

**C-C — Target attribution.**
- Interface counters (sysfs) belong to the collector's netns. They are attributed only when the target's `/proc/<pid>/ns/net` is readable and equal, which in practice means the target is owned by the collecting user. For root-owned targets they are MISSING with reason `unverified`.
- `/proc/<pid>/net/dev` would provide them per netns, but needs a contract source change (PROC is not a registered source for those features).

**C-D — Not implemented by scope.**
- `ss` features (srtt, cwnd; supporting only);
- eBPF features;
- application features. `app.latency_ms` is missing, so every real diagnosis carries IMPACT_NOT_MEASURED and is capped at MEDIUM until FaultLab or application metrics exist.

**Minor limitations:**
- A counter that wraps or resets and then grows past its old value within one interval looks like a large positive delta; this can't be detected from two readings.
- `/proc/schedstat` versions other than 15, and softnet rows without the cpu-id column (kernel < 5.10), are rejected (INVALID) rather than guessed.
- Reading thread files has a small time skew within a tick (up to 20 ms for 37 pids).
- Window bounds use actual tick times, so `duration_s` can differ from W by a few milliseconds.

**Interpretations to ratify:**
- interval-level reset semantics;
- STALE only for pure gauges;
- GAUGE = last sample and MEAN = mean;
- relevant CPUs = cpuset ∪ CPUs the target ran on in W;
- the `overall_coverage` and `baseline_adequate` definitions in §6;
- `cpu.max` absent = MISSING.

## 16. Commit hash

One commit: `feat(collectors): implement phase1c real evidence collection`. Its hash is given in the final gate response and by `git log -1`; a commit can't contain its own hash.

## 17. Final gate

**PASS WITH CONDITIONS**

**Met:**
- all collector tests pass, and all existing tests pass unchanged;
- every measurement validates against the contract;
- missing, invalid and stale data never become values or negative evidence;
- counter resets invalidate their interval and are never clamped;
- real-host snapshots for two targets validate, and M2 accepts them;
- fixture replay is byte-identical;
- the static and behavioural safety audit passes, and no prohibited functionality was introduced;
- 19/19 mutants are killed.

**Conditions:**
- C-A (no qdisc counter, so tcp_retransmissions can't be the decision on real data);
- C-B (no calibrated parameters);
- C-C (interface attribution for non-owned targets);
- C-D (ss, eBPF and application features out of scope).

These are coverage limitations imposed by the M3A scope, or work for later milestones. They are not correctness defects: every one fails closed. C-A is the most significant for diagnostic coverage, and resolving it needs a reviewer decision.
