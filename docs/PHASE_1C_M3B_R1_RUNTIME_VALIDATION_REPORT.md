# M3B R1 Runtime Validation — Attempt 2

**Candidate: `f18e9fc`** (fix(ebpf): bound sched histogram index in one register for the verifier; parent `118ee6d`)

| | |
|---|---|
| Checkout under test | `c2ac7e579d7b0b8756b63062f60dae553be3c9bc` (R1 tooling commit; parent `f18e9fc`; no implementation change) |
| Run | `results/phase1c_m3b_r1/20261003T081232Z/` (2026-10-03 08:12:32 UTC), executed by the user: `cd /home/iiitd/sentinelai && sudo bash scripts/m3b_r1_validate.sh`; driver exit code 0 |
| History | **Attempt 1** (`118ee6d`, run `20261003T072203Z`): NO-GO, `sn_sched_switch` rejected by the verifier. See `docs/PHASE_1C_M3B_R1_ATTEMPT1_REPORT.md`. **Preliminary attempt-2 run** (`f18e9fc` with uncommitted tooling, run `20261003T075732Z`): same outcome as below. See `docs/PHASE_1C_M3B_R1_ATTEMPT2_PRELIMINARY_REPORT.md`. Both evidence directories are preserved unmodified. |
| Gate | **M3B R1 RUNTIME GATE: GO** |

## 1. Commit and environment

| Item | Value |
|---|---|
| Kernel | `Linux 6.8.0-138-generic #138~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC` x86_64; 24 possible CPUs |
| `environment.txt` | `commit=c2ac7e5…`, `m3b_candidate=f18e9fc…`; loader `--version`: libbpf compiled 1.4 = linked 1.4, `match: true` |
| Artifacts | `sentinel.bpf.o` sha256 `b0495486…`, `sentinel_loader` `0c70a600…`, `sentinel.skel.h` `6238e0ad…` |
| Host state (read-only) | lockdown `none`; `unprivileged_bpf_disabled=2`, `perf_event_paranoid=4`, `bpf_stats_enabled=0`, `bpf_jit_enable=1`, `ip_forward=1` |
| Target | cgroup `/user.slice/user-1000.slice/session-136.scope` (kernfs id 2129446, level 3; the validation script's own session; 42 pids); host netns (inum 4026531840); no interfaces (so the M3A qdisc read, `tc`, is never run) |
| Contract / schema / rules | `0.5.0-draft` / `0.2.0` / `m2-1.1.0` |

## 2. Tooling commit

`c2ac7e5` "test(ebpf): update M3B R1 runtime validation tooling", directly on `f18e9fc` (neither `118ee6d` nor `f18e9fc` was modified). Six files, +959 lines:

| File | Role |
|---|---|
| `scripts/m3b_r1_validate.sh` | Root-only wrapper. Runs only if `m3b_r1_candidate.py` accepts the checkout and the loader reports libbpf 1.4. Takes read-only host snapshots before and after. |
| `scripts/m3b_r1_validate.py` | Driver: load/attach evidence, end-to-end windows, restart, kill, overhead |
| `scripts/m3b_r1_candidate.py` | HEAD must be `f18e9fc` or a descendant whose only changes are these tooling files, with a clean tracked tree |
| `scripts/m3b_r1_compare.py` | Before/after comparison. Ignores only `gc_timer`, `hello_timer`, `tcn_timer` and `topology_change_timer`, and only on bridge links. |
| `tests/ebpf/test_r1_compare.py`, `tests/ebpf/test_r1_candidate.py` | 8 + 7 tests |

Before committing: tooling tests 15/15, `git diff --cached --check` clean, the staged set exactly these six files (no M3B, M2, contract or FaultLab path).

## 3. Preflight

| Check | Result |
|---|---|
| `git rev-parse HEAD` / `git log -1` | `c2ac7e5` test(ebpf): update M3B R1 runtime validation tooling |
| `git status --short` | Untracked only: R1 reports, R1 evidence, `experiments/faultlab/` (hashes unchanged) |
| `git diff --check` | clean |
| Candidate check | accepted. `git diff --name-only f18e9fc HEAD` lists only tooling files. M2 diff vs `118ee6d`: 0 lines |
| Tests | M3B 114/114 (99 implementation + 15 tooling), M1 228/228, M2 97/97, M3A 111/111, M3A-C1 38/38. **Full suite: 574 run, 573 passed, 0 failed, 1 skipped** (pre-existing root-only bpftrace test) |
| Artifacts vs `f18e9fc` | A clean build of `git archive f18e9fc` uses `/usr/bin/clang-14`, the kernel-headers `libbpf.a` (no `-lbpf`) and BTF from `/sys/kernel/btf/vmlinux`, and its CO-RE `min_core_btf` check passes. All 7 program sections, `.maps`, `.rodata` and `license` are identical to the artifacts used; an in-place rebuild is byte-identical. Loader NEEDED: `libelf.so.1`, `libz.so.1`, `libc.so.6` only. The fixed clamp is present: `r2 = 527; if r2 > r1 goto +1; r1 = 527`. |

## 4. Verifier result

```text
Verifier: PASS — sn_sched_switch and all six other programs
```

The attempt-1 failure (`R0 unbounded memory access`) did **not** recur:
- the loader's stderr is **empty** (libbpf prints a program-load log only on failure);
- it emitted its `meta` line only after `sentinel_bpf__load` and `sentinel_bpf__attach` returned success;
- it ended with `{"type":"end","reason":"quit requested"}` and exit code 0;
- all seven programs exist in the kernel (§5), which requires verifier acceptance.

## 5. Load results (all seven, from the kernel)

| Program (kernel name) | Prog id | Type | xlated bytes | JITed bytes | Load |
|---|---|---|---|---|---|
| sn_sched_wakeup | 68633 | tracing | 1064 | 590 | PASS |
| sn_sched_wakeup_new | 68635 | tracing | 1152 | 640 | PASS |
| sn_sched_switch | 68636 | tracing | 1456 | 827 | PASS |
| sn_softirq_entry | 68637 | tracing | 376 | 219 | PASS |
| sn_softirq_exit | 68638 | tracing | 832 | 486 | PASS |
| sn_tcp_retransmit_skb | 68639 | tracing | 416 | 231 | PASS |
| sn_kfree_skb | 68640 | tracing | 920 | 523 | PASS |

Source: `bpftool -j prog show` while the loader ran, and the loader's own prog fds (`/proc/<pid>/fdinfo`, prog_type 26, one per program).

**Maps (kernel):**

| Map | Type | max_entries | memlock bytes |
|---|---|---|---|
| sn_wake | lru_hash | 16384 | 1,443,520 |
| sn_hist | percpu_array | 1 | 101,768 |
| sn_stats | percpu_array | 22 | 4,784 |
| sn_sirq_start | percpu_array | 1 | 776 |
| sn_sirq_acc | percpu_array | 10 | 4,304 |
| sn_retrans | percpu_array | 1 | 584 |
| sn_kfree | percpu_array | 129 | 26,184 |
| sentinel.rodata | array | 1 | 8,192 |
| **Total** | | | **1,590,112** |

`sn_hist` value size 4224 = 528 buckets × 8 bytes. The `.rodata` configuration reached the kernel: the `meta` line echoes cgroup id 2129446, level 3, netns 4026531840, and stale cut-offs of 10 s (latency) and 1 s (softirq).

## 6. Attachment results (all seven)

| Program | Load | Attach | Evidence |
|---|---|---|---|
| sched_wakeup | PASS | PASS | link 65, `raw_tracepoint`, prog 68633, kernel `tp_name=sched_wakeup` (bpftool and loader fdinfo); fired: 9,329 target wakeups in 3 s |
| sched_wakeup_new | PASS | PASS | link 66, prog 68635, `tp_name=sched_wakeup_new`; fired: 70 new target tasks in 3 s |
| sched_switch | PASS | PASS | link 67, prog 68636, `tp_name=sched_switch`; fired: 9,399 latencies recorded (70 migrated) in 3 s |
| softirq_entry | PASS | PASS | link 68, prog 68637, `tp_name=softirq_entry`; fired: 11,777 matched pairs in 3 s |
| softirq_exit | PASS | PASS | link 69, prog 68638, `tp_name=softirq_exit`; fired (same 11,777 pairs) |
| tcp_retransmit_skb | PASS | PASS | link 70, prog 68639, `tp_name=tcp_retransmit_skb`; **no event** in the clean baseline (0 target, 0 other-netns, 0 unattributed) |
| kfree_skb | PASS | PASS | link 71, prog 68640, `tp_name=kfree_skb`; fired: 107 target-netns and 172 unattributed in 3 s |

Each link's program id matches §5, and each `tp_name` is the approved tracepoint. "Fired" comes from the loader's in-kernel counters, read twice 3 s apart under baseline activity.

## 7. Scheduler validation (`sched.latency_hist.target`)

| Window | Samples in W | P50 (ms) | P99 (ms) | Quality / coverage | negative / stale | migrated | cancelled (running-task wakeup) |
|---|---|---|---|---|---|---|---|
| B0 | 30,924 | 0.000383 | 0.014335 | OK / 1.0 | 0 / 0 | 17 | 3 |
| B1 | 30,231 | 0.000383 | 0.013823 | OK / 1.0 | 0 / 0 | 11 | 7 |
| B2 | 30,229 | 0.000383 | 0.013823 | OK / 1.0 | 0 / 0 | 11 | 5 |
| C (restart) | 30,521 | (valid; 0 problems, 0 mismatches) | | | | | |

- Real observations occurred, and the cumulative histogram counters changed at every sample (monotonic across all 63 phase-B samples).
- The histogram has 528 buckets: the meta line reports `buckets: 528` and the map value is 4224 bytes.
- P50 and P99 are separate measurements in every snapshot. Their IDs differ, and each equals `measurement_id(…, aggregation=P50|P99)`, so the aggregation is retained in identity.
- Values are valid bucket upper edges equal to the nearest-rank quantile recomputed from the raw histograms: 0.000383 ms = 368–383 ns bucket; 0.013823 ms = 13,312–13,823 ns; 0.014335 ms = 13,824–14,335 ns. There were no negative or stale latencies.
- **Scope:**
  - target samples were 3,023–3,092/s, i.e. about 45 % of host context switches in the same windows (M3A `sched.ctxt.host` 6,580–6,917/s);
  - the validation session's cgroup carried most of the activity on a quiet host;
  - no non-target control cgroup was run (§17).
- EvidenceSnapshot accepted every measurement (§11).
- No value was interpreted as throttling or contention; the M2 decision was `INSUFFICIENT_EVIDENCE` with uncalibrated validation parameters.

## 8. Softirq validation (`softirq.exec_time.percpu`)

- **Shape:** every snapshot has 240 softirq measurements (24 CPUs × 10 vectors), each with its own `cpu:N` scope and `vector` qualifier.
- **Entry/exit accounting:** eBPF matched pairs over W compared with the kernel's own `/proc/softirqs` over the same interval:

| Window | NET_RX eBPF / proc | NET_TX | TIMER | RCU |
|---|---|---|---|---|
| B0 | 4,667 / 4,667 | 2 / 2 | 2,591 / 2,591 | 5,643 / 5,643 |
| B1 | 4,437 / 4,436 | 1 / 1 | 2,474 / 2,472 | 5,390 / 5,389 |
| B2 | 4,436 / 4,436 | 2 / 2 | 2,497 / 2,497 | 6,129 / 6,129 |

  B1's differences (1, 2, 1 executions) are softirqs that ran between the two reads, which are not atomic with each other. The largest relative difference is 0.08 % (TIMER, B1).
- **Rates:** every per-CPU, per-vector value equals Σ(exit − entry) / Δt recomputed from the raw lines (0 mismatches in every window).
  - NET_RX was concentrated on CPU 21: 0.00592 / 0.00516 / 0.00510 cores for the 8 MB/s loopback stream.
  - NET_TX is a separate measurement.
  - Non-network vectors (TIMER, RCU, …) are separate measurements and are never added to network time.
  - Softirq time is reported in cores per CPU and vector, never as application CPU time.
- **Robustness counters** were all 0: unmatched exit, mismatch, overwritten entry, invalid vector, negative and stale.

## 9. TCP retransmission validation (`tcp.retrans_skb_rate`)

- The tracepoint is attached (link 70). In the clean baseline it recorded **0** events: 0 target, 0 other-netns, 0 unattributed. `/proc/net/snmp` RetransSegs in the same windows (M3A `tcp.retrans_rate`) was 0.0 segments/s.
- In every window the measurement is `tcp.retrans_skb_rate`, scope `netns:r1` (target netns), unit `events_per_second`, aggregation RATE, value **0.0**, quality OK. That is an observed zero from an attached program, meaning one event per retransmitted skb, of which none occurred.
- It is a measurement separate from `tcp.retrans_rate` (PROC, segments/s), with no segment conversion.
- No retransmission was manufactured. A zero does **not** mean the observer is broken, and it is not evidence that retransmissions are impossible.

## 10. kfree_skb validation (`net.drop.kfree_skb`)

| Window | Reasons observed (packets/s, target netns) | Unattributed in W |
|---|---|---|
| B0 | NOT_SPECIFIED 33.90, NO_SOCKET 0.50, QUEUE_PURGE 0.20, OTHERHOST 0.20 | 344 |
| B1 | NOT_SPECIFIED 31.90, QUEUE_PURGE 0.10, OTHERHOST 0.10 | 172 |
| B2 | NOT_SPECIFIED 31.40, QUEUE_PURGE 0.20, NO_SOCKET 0.10, OTHERHOST 0.10 | 344 |

- Kernel reasons are preserved as `reason` qualifiers, named from the running kernel's BTF.
- A measurement exists only for reasons seen in the run: B1 has three, and B0/B2 have four. No zero-valued measurement was created for any of the other ~90 reasons.
- Rates equal the recomputation from raw slot counts. Scope is `netns:r1` (here the host netns). Skbs with neither a device nor a socket netns are counted as unattributed and never reported as target evidence.
- `NOT_SPECIFIED` remains an observed kernel reason; M2 drew no packet-loss conclusion (decision `INSUFFICIENT_EVIDENCE`). These rates do not prove the presence or absence of packet loss.

## 11. End-to-end EvidenceSnapshot validation (kernel data)

Path: kernel tracepoint → per-CPU maps → libbpf loader → `ProcessEbpfSource` (one request per tick) → strict protocol parser → M3A normalisation → `EvidenceSnapshot` (Pydantic contract validation) → M2 `diagnose`. All on kernel-generated data; the replay harness was not used.

| Check | B0 | B1 | B2 | C |
|---|---|---|---|---|
| Measurements total / EBPF | 455 / 247 | 454 / 246 | 455 / 247 | – / 246 |
| Data-quality problems* | 0 | 0 | 0 | 0 |
| Duplicate measurement ids | 0 | 0 | 0 | 0 |
| Canonical round trip (Pydantic) | identical | identical | identical | identical |
| Deterministic rebuild from the same ticks | identical | identical | identical | – |
| Recomputation from raw lines | 0 mismatches | 0 | 0 | 0 |
| `privileged_sources_unavailable` | `[]` | `[]` | `[]` | – |
| M2 | accepted (`INSUFFICIENT_EVIDENCE`) | accepted | accepted | – |

\* Per EBPF measurement: feature ID ∈ the four, source EBPF, registry unit, registry aggregation, scope kind, qualifier dimension, collector version `m3b-1.0.0`, `privileged=true`, deterministic ID, finite and ≥ 0 (no NaN, Inf or negative), window equals the snapshot window, provenance populated with `first_sample_at ≤ last_sample_at`.

**Windows:** W = 10.0004 / 10.0000 / 10.0007 s.

**Collection latency:**
- eBPF request median 0.50 ms, max 1.62 ms (63 requests);
- slowest whole tick read, M3A sources included: 0.011 s.

## 12. Repeated collection

- **Three consecutive windows on one loader:** 63 samples, sequence strictly increasing, every cumulative counter monotonic, no invalid histogram state.
  - Values are computed from each window's own boundary deltas and are stable across windows: P50 identical; NET_RX CPU 21 0.0059/0.0052/0.0051 cores; NOT_SPECIFIED 33.9/31.9/31.4/s.
  - Recomputation matches every window exactly, so there is no double counting, stale data or cross-window contamination.
- **Restart (C):** a new loader's first sample is seq 1 with 97 latency samples and 300 stat events in total, i.e. fresh maps start from zero. Its snapshot is valid (246 EBPF measurements, 0 problems, 0 mismatches). One collection uses one stream.
- **Termination (D):** `SIGKILL` at 15 s, partway through W (loader exit −9). Later samples became Bad observations, and every EBPF measurement is **MISSING** (coverage 0.4 < `COV_MIN` 0.8), with no value fabricated. `privileged_sources_unavailable = ["EBPF"]`, and the snapshot stays contract-valid (245 EBPF measurements, 0 problems).
- **Clean termination** (A, B, C, E): `q` on stdin, end line `quit requested`, exit 0.

## 13. Cleanup (after successful attach)

```text
BPF cleanup: PASS
```

| Moment | M3B links / programs / maps in the kernel |
|---|---|
| Attached (A) | 7 / 7 / 8 |
| Immediately after clean exit (0 s; B, C, E) | 0 / 7 / 8 |
| 1 s after clean exit (A) | 0 / 0 / 0 |
| 1 s after `SIGKILL` (D) | 0 / 0 / 0 |
| Final, after all phases (wrapper `host_compare`) | 0 / 0 / 0; `sn_programs_left: []` |

- Links disappear when the process exits; program and map memory is released by the kernel asynchronously within 1 s.
- Host-wide BPF program, link and map ids are identical before and after (22 pre-existing programs unchanged).
- Nothing was pinned, and no instrumentation remains. No reboot was used.

## 14. Overhead

**Method:** five alternating 15 s trials, baseline then enabled. Enabled means attached, plus one sample request per second. The workload was the same in both modes: two 1 ms sleep/wake threads, one `/bin/true` per second, 8 MB/s TCP on `lo`.
- Host CPU is the busy share of `/proc/stat` × 24 CPUs; this includes in-kernel BPF execution.
- Loader CPU is utime+stime from `/proc/<pid>/stat`, at 10 ms resolution. RSS and HWM come from `/proc/<pid>/status`, map memory from bpftool `bytes_memlock`, and request latency is timed in the driver.

| Metric | Baseline | Enabled |
|---|---|---|
| Host busy cores, per trial | 0.0513, 0.0407, 0.0380, 0.0407, 0.0447 | 0.0466, 0.0340, 0.0400, 0.0360, 0.0406 |
| Mean / median / sd | 0.0431 / 0.0407 / 0.0052 | 0.0395 / 0.0400 / 0.0049 |
| Paired Δ (enabled − baseline) | | −0.0047, −0.0067, +0.0020, −0.0047, −0.0040; mean −0.0036, median −0.0047, sd 0.0033 |
| Loader CPU per 15 s | | 0.00, 0.01, 0.01, 0.00, 0.00 s (≤ 0.00067 cores) |
| Loader RSS / HWM (kB) | | 2,852–2,884 / 14,660–14,860 |
| BPF map memory | | 1,590,112 bytes (every trial) |
| eBPF request latency (median per trial) | | 0.50–0.60 ms |
| Driver CPU per 15 s | 0.181–0.242 s | 0.191–0.213 s |
| Workload: wakeups/s | 1,897–1,901 | 1,899–1,900 |
| Workload: TCP MB/s | 8.03–8.11 | 8.09–8.12 |

**Interpretation:**
- **No overhead increase is detectable.** The paired difference is negative (mean −0.0036 cores). The observer cannot reduce CPU, so this is drift or noise: each enabled trial follows its baseline. The resolution of this method is about ±0.005 cores. Within it, observer overhead under this workload is below about 0.005 cores (< 1 % of one core, against the < 5 % target).
- The loader process itself used ≤ 0.00067 cores and about 2.9 MB of steady memory; the 14.7 MB high-water mark is from parsing kernel BTF at load.
- The workload throughput was unchanged.

**Not measured:**
- per-program in-kernel run time, which needs `kernel.bpf_stats_enabled=1`, a sysctl change R1 forbids;
- overhead at high event rates. Rates here were about 3.0k target latency samples/s and about 2.4k softirq pairs/s (all vectors).

## 15. Protected-interface validation

From `host_compare.txt` (read-only `ip -j`, `/run/netns`, `/proc/sys` and bpftool snapshots, before vs after):

| Check | Result |
|---|---|
| `enp0s31f6_identical` | **true** |
| `docker0_identical` (configuration; the four bridge countdown timers ignored, bridge links only) | **true** |
| `interfaces_identical`, `interfaces_differing` | true, `[]` (no veth or other interface created) |
| qdisc per interface | before = after: `lo` noqueue, `enp0s31f6` fq_codel, `docker0` noqueue |
| `addresses_identical`, `routes_identical` (IPv4 + IPv6) | true, true |
| `netns_identical` | true (`/run/netns` unchanged) |
| `sysctls_identical` | true |
| BPF progs / links / maps | identical; no `sn_` program left |

No tc, netem, namespace, veth, route, sysctl or cgroup change was made. All experiment traffic was on `127.0.0.1` (`lo`); none was generated on `enp0s31f6` or `docker0`.

## 16. Anomalies

1. **Softirq counter skew in B1** (§8): 1–2 executions out of thousands, from the non-atomic paired reads. Not a defect.
2. **Negative host-CPU delta** (§14): measurement drift, not a real reduction. Reported as "no detectable increase".
3. **Deferred kernel release** (§13): programs and maps are listed for under 1 s after exit, while links are gone at once. This is expected kernel behaviour and is verified released.
4. No load, attach, contract, determinism or cleanup failure. Attempt 1's verifier rejection did not recur.

## 17. Limitations

1. **Retransmission tracepoint firing was not observed:** attached, with zero events in the clean baseline. The path is validated through its zero semantics; non-zero evidence belongs to the separately authorised, isolated FaultLab phase.
2. **The netns filter was not exercised against a second namespace** (target = host netns, other-netns counters 0). Creating a namespace is outside R1.
3. **No negative-control cgroup:** target selection is evidenced by the fixture-tested filter and the 45 % share of host switches, not by a non-target run.
4. **Per-program in-kernel run time was not measured** (`bpf_stats_enabled` left 0). Overhead was measured at one light workload only.
5. **`verified_insns` is not reported** by this bpftool build. Verifier acceptance is proven by successful load and attach with an empty libbpf log.
6. **Validation parameters are uncalibrated.** M2 decisions on these snapshots carry no diagnostic meaning; R1 validates observation, not diagnosis quality.

## 18. Evidence artifacts

| Artifact (`results/phase1c_m3b_r1/20261003T081232Z/`) | Content |
|---|---|
| `r1.json` | Every phase: load/attach (meta line, stderr, return code, bpftool state before, during and after, fdinfo attach targets, 3 s firing counters), windows (checks, cross-checks, measurements), restart, kill, overhead trials |
| `snapshot_B0.json`, `snapshot_B1.json`, `snapshot_B2.json`, `snapshot_C.json` | Canonical runtime EvidenceSnapshots |
| `raw_B.jsonl` | The 64 raw loader lines of phase B (meta + 63 samples) |
| `environment.txt` | Checkout commit, M3B candidate, kernel, loader version, artifact hashes |
| `host_before/`, `host_after/`, `host_compare.txt` | Read-only host state and comparison |
| `driver.log` | Phase progress |

Artifact policy: per the repository's existing rule (`results/` tracked; only `results/**/raw/` ignored, as for the Phase 1A privileged smoke and M3A evidence), all three R1 evidence directories (`20261003T072203Z` attempt 1, `20261003T075732Z` preliminary, `20261003T081232Z` this run; 4.7 MB) are committed unmodified with this report.

**Commands:**
- Privileged, by the user: `cd /home/iiitd/sentinelai && sudo bash scripts/m3b_r1_validate.sh`.
- Unprivileged (preflight and analysis): `git rev-parse/log/status/diff --check`, `scripts/m3b_r1_candidate.py`, `python -m unittest discover -s tests`, `git archive f18e9fc ebpf | tar -x` + `make all` and `llvm-objcopy`/`llvm-objdump` section comparisons, `sentinel_loader --version`, `readelf -d`, and Python reading of `r1.json` and the snapshots.

## 19. Gate decision

| Criterion | Status |
|---|---|
| Verifier accepts all required programs | yes: 7/7, `sn_sched_switch` included; empty libbpf log |
| Attachment succeeds | yes: 7/7 links on the 7 approved tracepoints (bpftool and the loader's kernel fds) |
| Real kernel observations obtained | yes: 6/7 programs fired under baseline activity; retransmission had no event (valid) |
| All four feature paths validated | yes: latency, softirq, kfree with real non-zero data; retransmission via an observed zero |
| Observations reach EvidenceSnapshot | yes: 4 runtime snapshots, 0 contract or data-quality problems, M2 accepted |
| Repeated collection works | yes: 3 windows exact, restart fresh, kill fails closed |
| Cleanup works | yes: all M3B objects released within 1 s; host BPF state identical |
| Overhead measured | yes: no detectable increase (paired Δ −0.0036 ± 0.0033 cores); loader ≤ 0.00067 cores, 2.9 MB RSS, 1.59 MB maps |
| Safety checks pass | yes: `enp0s31f6` and `docker0` unchanged; addresses, routes, netns, sysctls and qdiscs unchanged |
| M2 / contract unchanged | yes: no diff under `src/sentinelai/diagnostic/` |

```text
M3B R1 RUNTIME GATE: GO
```

**STOP.** FaultLab, network namespaces, veth, tc/netem, controlled loss or delay, CPU contention or throttling, memory pressure, K1–K4 and mitigation experiments require separate explicit authorisation.
