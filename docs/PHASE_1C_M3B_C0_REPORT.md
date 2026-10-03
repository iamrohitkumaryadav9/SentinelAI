# Phase 1C — M3B-C0 Report: eBPF Contract Alignment

| | |
|---|---|
| Base | `628c71101dec92c75bdd1a71b665be9ac7b99973` (M3A-C1) |
| Inspected at HEAD | contract `0.3.0-draft`, schema `0.2.0`, rules `m2-1.1.0`, collector `m3a-1.1.0`; 67 registered features |
| Taxonomies (unchanged) | SourceType {PROC, SYSFS, CGROUPFS, TC, SS, EBPF, APP_METRICS, APP_EVENTS, FAULTLAB_GROUND_TRUTH, DERIVED, PROMETHEUS} · Unit {fraction, cores, waiting_cores, per_second, packets_per_second, segments_per_second, events_per_second, pages_per_second, bytes, bytes_per_second, ms, count, ratio, boolean} · Aggregation {RATE, MEAN, GAUGE, DELTA, RATIO, P50, P90, P99, MAX} · ScopeKind {host, cpu, cpuset, cgroup, netns, iface, socket, app} · qualifier = registry `dimension` (closed `values` or `pattern`) |
| Gate | **M3B-C0 GATE: GO** |

M1's existing validation enforces each new definition: a measurement's unit, aggregation, scope kind and source must match the registry, and its qualifier must be present, with the declared dimension and an accepted value, exactly when the feature declares a dimension. No validator code changed.

## A. G-2 resolution: `softirq.exec_time.percpu`

| Field | Value |
|---|---|
| Source | `EBPF` only (availability P, privileged) |
| Semantics | Observed softirq **execution time** from kernel `irq:softirq_entry` → `irq:softirq_exit` events (kernel monotonic ns) on CPU N, per vector: Σ(exit − entry) over the window ÷ Δt. **Not** the `/proc/stat` jiffy fraction, **not** the `/proc/softirqs` event counts, **not** CPU utilisation. |
| Unit | `cores`: softirq CPU-seconds per second (text: "softirq execution CPU-seconds per second (cores) per vector") |
| Aggregation | `RATE` (kind `counter_rate`) |
| Scope | `cpu` (`cpu:N`). No cgroup attribution is claimed. |
| Qualifier | Required `vector` ∈ {HI, TIMER, NET_TX, NET_RX, BLOCK, IRQ_POLL, TASKLET, SCHED, HRTIMER, RCU}. This is exactly the kernel's softirq set (`HI_SOFTIRQ` … `RCU_SOFTIRQ`, verified in BTF), using the existing qualifier mechanism. |
| Vector semantics | Network softirq time = NET_RX and NET_TX only. Total softirq time = the sum over all vectors. These are never equated, and a measurement without a vector is invalid. |
| Family | `softirq` |

**Why `cores` and RATE rather than accumulated `ms` (DELTA).** Contract §5 builds baselines from **per-second** samples and computes deviation as `x / baseline.median`. An accumulated-ms value over W would be W times larger than its own per-second baseline, giving meaningless ratios. A time rate keeps the window value and the baseline on the same basis, and it matches the existing time-rate features `throttle.time_rate` (cores) and `sched.run_delay.target` (waiting-cores). The brief allows a rate if explicitly defined; it is defined above.

## B. G-3 resolution: `tcp.retrans_skb_rate`

| Field | Value |
|---|---|
| Source | `EBPF` only (availability P, privileged) |
| Semantics | Rate of retransmission events observed through the `tcp:tcp_retransmit_skb` tracepoint whose socket is in the target netns: **one event per retransmitted skb**. An skb can carry several segments (TSO/GSO), so this is **not segments/s** and **not** `tcp.retrans_rate`. |
| Unit | `events_per_second`, text **"retransmitted skbs/s (one event per tcp:tcp_retransmit_skb)"**. No `skbs_per_second` unit exists, and inventing one would be a schema change; `events_per_second` is the closest valid unit, and the unit text states skbs explicitly. |
| Aggregation | `RATE` (kind `counter_rate`) |
| Scope | `netns` only. The tracepoint's socket gives a reliable netns; no per-socket or per-target attribution is promised, and `socket` scope is rejected. |
| Qualifier | None |
| Family | `network_tcp` |

## C. Existing feature preservation

**All 67 pre-existing feature definitions are byte-identical** to commit `628c711`. A test pins the sha256 of their canonical JSON (`c9024e31…`).

**`labels.json`, `predicates.json` and `parameters.json` are identical except for `contract_version`** (golden hashes `bf68c6c8…`, `32986f3e…`, `d70c6294…`). No clause, precedence rule, predicate or parameter changed.

The four named features keep their meaning, and they reject eBPF:

| Feature | Unit | Aggregation | Source | Locator |
|---|---|---|---|---|
| `softirq.frac.percpu` | fraction | RATIO | PROC | `/proc/stat cpuN softirq jiffies / total jiffies` |
| `softirq.net_rx_rate.percpu` | events/s | RATE | PROC | `/proc/softirqs NET_RX column N` |
| `softirq.net_tx_rate.percpu` | events/s | RATE | PROC | `/proc/softirqs NET_TX column N` |
| `tcp.retrans_rate` | **segments/s** | RATE | PROC | `/proc/net/snmp Tcp: RetransSegs` |

Tests show that each of these rejects an EBPF-sourced measurement. They also show that the new features reject PROC sources, proc units (fraction, events/s, segments/s), wrong aggregations, wrong scopes and missing or invalid qualifiers. Measurement IDs never collide between old and new features.

**M2 is unchanged.** `RULES_VERSION` is still `m2-1.1.0`. No clause, supporting predicate or `DEV_FEATURES` entry references the new features. The M3A collectors don't emit them (P features).

**G-1 accepted.** `sched.latency_hist.target` keeps `P50` and `P99` only.

## D. Version

| | Before | After |
|---|---|---|
| Contract | `0.3.0-draft` | `0.4.0-draft` |
| Schema | `0.2.0` | `0.2.0` |
| Rules | `m2-1.1.0` | `m2-1.1.0` |

Per §12, adding features or parameters is a **minor** change, and nothing existing changed: 0.3.0 → 0.4.0. All four contract data files and `version.py` are updated together. The loader rejects any mismatch, which is tested. 0.2.0- and 0.3.0-draft snapshots (major 0) remain accepted.

## E. Tests

```text
M1 (tests/evidence):           207/207   (192 + 15 new in test_revision_v040.py)
M2 (tests/rules):               95/95
M3A (tests/collectors):        111/111   (includes M3A-C1)
M3A-C1 (test_tc.py):            38/38
Full suite:                    437 run: 436 passed, 0 failed, 1 skipped (the pre-existing root-only bpftrace test)
Mutation:                      23/23 killed, 0 survived (clean unmutated control)
```

**Mutants** (all killed):

| # | Mutation |
|---|---|
| 1 | softirq source → PROC |
| 2a–2f | softirq unit → ms; semantics text removed; aggregation → DELTA; scope → cpuset; vector qualifier removed; vector set collapsed to NET_RX/NET_TX |
| 3, 3b | EBPF accepted under `softirq.frac.percpu` / `softirq.net_rx_rate.percpu` |
| 4, 4b | tcp unit → segments/s; unit text says segments |
| 5, 5b | new tcp feature replaced by `tcp.retrans_rate`+EBPF; `tcp.retrans_rate` unit changed |
| 6, 6b | tcp source → PROC; tcp scope → socket |
| 7a, 7b | each new feature removed from the registry |
| 8a, 8b | duplicate feature ID, with and without the duplicate check |
| 9 | measurement source validation bypassed |
| 10, 10b | contract version bumped without the registry; registry left at 0.3.0 |
| 11 | an existing feature silently altered |

**Determinism:**
- registry parse → canonical serialisation is byte-identical;
- measurement IDs are pinned golden values (`b6deeaf7d4a52987` for `softirq.exec_time.percpu@cpu:3[NET_RX]`, `6c8aedfe03f180d6` for `tcp.retrans_skb_rate@netns:A`);
- version metadata is static;
- no timestamps or runtime values are involved.

## F. Files changed

| File | Change |
|---|---|
| `src/sentinelai/diagnostic/contract/data/registry.json` | +2 features; `contract_version` |
| `src/sentinelai/diagnostic/contract/data/{labels,predicates,parameters}.json` | `contract_version` only |
| `src/sentinelai/diagnostic/contract/version.py` | `CONTRACT_VERSION = "0.4.0-draft"` |
| `docs/EVIDENCE_CONTRACT.md` | Header, revision history, §4.4 and §4.5 rows, §10.3 qualifier list, §12 note |
| `tests/evidence/test_revision_v040.py` | New (15 tests) |
| `tests/evidence/test_registry.py`, `test_revision_v020.py` | Exact feature, privileged and dimension sets extended by the two features (still exact equality) |
| `tests/evidence/{test_revision_v030,test_schema}.py`, `tests/rules/{_fixtures,test_determinism}.py`, `tests/collectors/test_snapshot.py` | Current-version strings |
| `docs/PHASE_1C_M3B_REPORT.md` | The reviewed M3B audit report (previously uncommitted; the revision history cites it) |
| `docs/PHASE_1C_M3B_C0_REPORT.md` | This report |

eBPF implementation files: 0. BPF programs: 0. Loader: 0. Network lab: 0. No security setting was changed (`unprivileged_bpf_disabled = 2`, `perf_event_paranoid = 4`), and the host's interfaces are still `lo`, `docker0`, `enp0s31f6`.

## G. Contract limitations (actual)

1. **G-1:** `sched.latency_hist.target` represents only P50 and P99 (accepted).
2. **Unit text carries the skb meaning.** `tcp.retrans_skb_rate` uses unit `events_per_second`, because the unit vocabulary has no skb unit.
3. **No total-softirq measurement.** `softirq.exec_time.percpu` is per vector only; consumers needing total softirq time must sum vectors.
4. **Both new features are observation-only** until a later milestone decides whether M2 uses them. They are availability P, so they are absent unless a privileged collector runs.
5. **Pre-existing observation (not changed here).** `mem.events.oom_kill` uses DELTA (count over W) while §5 baselines are per-second samples. Its deviation ratio is therefore on a different basis. M2 uses it only as `> 0`, so no decision is affected today, but a later contract revision should define DELTA baselines.

## H. Git

One focused commit: `feat(contract): align ebpf evidence features`. Its hash is in the gate response and `git log -1`.

---

## M3B-C0 GATE: GO

- G-2 and G-3 are resolved with EBPF-only, explicitly defined features, and G-1 is accepted.
- Every existing feature, rule, predicate and parameter is byte-identical, and M2 is unchanged.
- M1, M2, M3A, M3A-C1 and the full suite pass.
- 23/23 mutants are killed, and deterministic validation passes.
- No eBPF code was written, the network is unchanged, and no security setting was modified.

**STOP.** M3B implementation, the lab and any eBPF loading wait for explicit authorisation.
