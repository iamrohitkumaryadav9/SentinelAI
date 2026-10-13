# Phase 1C M5 pilot report

Status: **pilot complete; ready for the M5 review (§7).**

- **Complete:** PI-0, CTRL, PI-1 in both privilege modes, the PI-6 collectors-on/off pairs and the workload
  instrumentation on/off pairs. All were repeated under the approved working set (§3b).
- **Application and CPU fault classes (PI-8, §3d):** levels found for all five mechanisms under Poisson arrivals
  (not frozen).
- **Network fault class (PI-8, §3e):** levels found for all four faults; PI-2 passes.
- **Memory (§3g):** ground truth and PI-5 met at every candidate; single severity (M-3).
- **OV-4 and OV-5 (§3h):** both feasible, 2 of 2.

What this report shows: the A–R–B lab, the collection pipeline and the CTRL-stage pilot criteria work on this host. It
does **not** validate any fault class, and it does not support any diagnostic claim. M2 was never run on pilot data
(pilot design §7).

## 1. Campaigns

Evidence lives in `results/phase1c_m5_pilot/<campaign>/<run>/` and is committed under AMD-27 (§5). The runner
(`experiments/faultlab/pilot.py`) allows CTRL only after 5/5 PI-0 cycles at the same commit in the same campaign
(`require_pi0`).

| Campaign (UTC) | Commit | Runs | Outcome |
|---|---|---|---|
| `20261011T175343Z` | `cab7b59` | PI0-1 | **FAILED.** Lab checks failed `a_ip_forward`, `b_ip_forward`. The host comparison failed `mounts_identical` (the first `ip netns add` mounted `/run/netns`, and that mount stayed). Fixed in `6c0030d` and `7f6eac7`. |
| `20261012T030504Z` | `7f6eac7` | PI0-1…5, CTRL-900001 | PI-0 5/5 passed. CTRL-900001 **FAILED** (`app_features`, §3). |
| `20261012T040045Z` | `af2a4e7` | PI0-1…5, CTRL-900002…900005 | PI-0 5/5 passed. CTRL 4/4 passed. |
| `20261012T045417Z` | `29d652f` | PI0-1…5; CTRL, PI6OFF, INSTOFF at seeds 900006 and 900007; PI1U-900008, PI1U-900009 | PI-0 5/5 passed. All 8 runs passed (§3a). |
| `20261013T024805Z` | `9934ca0` | PI0-1…5; CTRL-900190, 900191; PI8-900430, 900431 (OV-4 flood, 80,000 pps); PI8-900440, 900441 (OV-5 fill, 768 MiB under M = 2,048 MiB) | All 11 passed their pipeline checks and every PI (§3h). OV-4 producible 2 of 2 (AMD-13); OV-5 feasible 2 of 2 (AMD-15 F1). |
| `20261012T175020Z` | `c4e10d8` | PI0-1…5; CTRL-900180…900183; one re-check per earlier fault PI8-900340…900348; PI8-900360…900367 (`memory.max` 960 / 768 / 512 / 256 MiB, 2 each) | All 26 passed their pipeline checks (§3g); the separate scanner process removes the stall. PI-6 missed in PI8-900344 (throttle features, known) and in 3 memory runs, PI8-900361, 900366 and 900367 (`mem.util.target` coverage 0.978–0.989). Memory effect saturated at every level. |
| `20261012T165705Z` | `c874aa4` | PI0-1…5; CTRL-900170, 900171; PI8-900320 (`memory.max` 960 MiB) | PI-0 5/5, CTRL 2/2 passed. **PI8-900320 FAILED** (app features, client/server reconciliation): the workload stalled under memory pressure (§3f). Campaign closed; an owner decision is pending. |
| `20261012T141516Z` | `dc5b3d5` | PI0-1…5; CTRL-900160…900163; PI8-900240…900271 (network faults) | All 41 passed their pipeline checks (§3e). Every network fault has an effect at every candidate. |
| `20261012T133839Z` | `a0b0aaa` | PI0-1…5; CTRL-900150…900153; PI8-900200 (loss 0.5 % on A egress) | PI-0 5/5 and CTRL 4/4 passed. **PI8-900200 FAILED** across-R reconciliation again: segments are not packets under retransmission (§3d note). Fixed in the next commit; the network runs moved to a new campaign. |
| `20261012T104753Z` | `2280a18` | PI0-1…5; CTRL-900050…900053 under Poisson arrivals; PI8-900060…900082 (application faults, repeated); PI8-900100…900116 (CPU faults; one local-loss run) | 64 of 66 runs passed their pipeline checks (§3d). **PI8-900081 FAILED** (host comparison: an external SSH login change). **PI8-900116 FAILED** (across-R reconciliation under local loss; fixed in `6320943`). Quota runs miss PI-6 coverage on throttle features. |
| `20261012T074028Z` | `82ff593` | PI0-1…5; re-baseline with the FZ-WORKSET working set: CTRL-900010…900013, PI6OFF and INSTOFF at 900010 and 900011, PI1U-900014, PI1U-900015; PI8-900020…900041 (application faults) | PI-0 5/5 passed. All 10 re-baseline runs passed (§3b). All 22 fault runs passed their pipeline checks (§3c): dependency delay has levels; pool shrink and lock hold produced no effect. |

Every privileged invocation ran its own privileged preflight (`preflight.json` in each run directory). Each preflight
was READY and recorded the run's commit.

## 2. PI-0: lab lifecycle (design §6.1)

Criterion: 5/5 cycles with all lab checks passing, cleanup verified, and the host comparison `ok: true`, BPF compared.

| Campaign | Cycles | Lab checks (incl. ip_forward A 0, R 1, B 0) | Ping A↔B, TCP echo A→B | Cleanup | Host comparison | Owned `/run/netns` mount removed |
|---|---|---|---|---|---|---|
| `20261012T030504Z` | 5/5 | pass | pass | verified | ok | yes |
| `20261012T040045Z` | 5/5 | pass | pass | verified | ok | yes |
| `20261012T045417Z` | 5/5 | pass | pass | verified | ok | yes |
| `20261012T074028Z` | 5/5 | pass | pass | verified, working-set directory removed | ok | yes |
| `20261012T104753Z` | 5/5 | pass | pass | verified, working-set directory removed | ok | yes |
| `20261012T133839Z` | 5/5 | pass | pass | verified, working-set directory removed | ok | yes |
| `20261012T141516Z` | 5/5 | pass | pass | verified, working-set directory removed | ok | yes |
| `20261012T165705Z` | 5/5 | pass | pass | verified, working-set directory removed | ok | yes |

Lab setup plus teardown (op-log span): 1.3–1.4 s per cycle.

## 3. CTRL (design §6.2 timeline; FZ-WORKLOAD)

Setup:

- Workload `lock_hold_us 0`, 100 req/s, jitter 0.5, pool 4, queue 32, `cpu_us 2000`, dependency delay 2 ms.
- Timeline: warm-up 15 s, B 45 s, W 90 s, cool-down 20 s.
- Collection: M3A + M3B + app at 1 Hz, run by the root driver.

| Run | Commit | Pipeline (9 checks) | Requests (200 / scheduled) | PI-1 min coverage | PI-6 collector CPU (budget 0.02 core) | PI-7 valid app ticks | Client latency p50 / p99 |
|---|---|---|---|---|---|---|---|
| CTRL-900001 | `7f6eac7` | **FAILED** (`app_features`) | 17000 / 17000 | 1.0 | 0.0020 | 136/136 | 4.41 / 4.59 ms |
| CTRL-900002 | `af2a4e7` | pass | 17000 / 17000 | 1.0 | 0.0020 | 136/136 | 4.43 / 4.62 ms |
| CTRL-900003 | `af2a4e7` | pass | 17000 / 17000 | 1.0 | 0.0019 | 136/136 | 4.42 / 4.62 ms |
| CTRL-900004 | `af2a4e7` | pass | 17000 / 17000 | 1.0 | 0.0020 | 136/136 | 4.38 / 4.61 ms |
| CTRL-900005 | `af2a4e7` | pass | 17000 / 17000 | 1.0 | 0.0019 | 136/136 | 4.38 / 4.58 ms |

The nine pipeline checks: run completed, cleanup, host comparison, BPF released, manifest, byte-identical replay,
app features, client/server reconciliation and across-R reconciliation. In every passing run the server's
completed/rejected/failed deltas equal the client outcomes exactly, and R dropped nothing.

**CTRL-900001 stays a failed evaluation.** Its only failing check was `app_features`: `app.lock_wait_ms` P99 was
MISSING.

- The cause is a mismatch between the evaluator and the approved workload, not between the workload and the evidence.
  FZ-WORKLOAD sets `lock_hold_us 0` ("no lock contention in CTRL"), and the workload records lock waits only while it
  holds the lock.
- `af2a4e7` exempts this single measurement, and only when the run's manifest-verified evidence proves
  `lock_hold_us == 0`. The proof covers `run.json`, the workload's config echo and its hash, both bracketing metrics
  documents, and zero lock-wait observations.
- Every other app feature, quality and scope check is unchanged.
- An offline re-evaluation of CTRL-900001 under `af2a4e7` passes. It does not count: the run was evaluated at
  `7f6eac7`, and its `report.json` is unchanged and pinned (§5).

The exemption is recorded in every report under `checks.app_features.structurally_unavailable`.

## 3a. PI-1 unprivileged, PI-6 pairs, instrumentation pairs (campaign `20261012T045417Z`, `29d652f`)

Same lab, workload, load and timeline as CTRL. Run variants (`pilot.py`):

- `ctrl`: as §3.
- `pi6off`: no collector and no eBPF loader.
- `instoff`: as `pi6off`, with the workload's metrics writer off. No server document exists, so a client-only
  `client_records` check replaces client/server reconciliation.
- `pi1u`: M3A + app collected by a child running as the lab uid (uid/gid 1000, no supplementary groups, `CapEff` 0),
  with no eBPF (the loader needs root).

Every run below passed its own pipeline checks and all its cleanup, host-comparison and BPF-release checks. Each
re-evaluates offline to the same verdict.

| Run | Requests (200 / scheduled) | Collector CPU (core) | PI-1 | Notes |
|---|---|---|---|---|
| CTRL-900006 | 17000 / 17000 | 0.0021 | root, coverage 1.0 | lock-wait exemption applied (§3) |
| CTRL-900007 | 17000 / 17000 | 0.0019 | root, coverage 1.0 | lock-wait exemption applied |
| PI6OFF-900006 | 17000 / 17000 | — (off) | — | client/server reconciliation exact |
| PI6OFF-900007 | 17000 / 17000 | — (off) | — | client/server reconciliation exact |
| INSTOFF-900006 | 17000 / 17000 | — (off) | — | `client_records`: complete, all answered |
| INSTOFF-900007 | 17000 / 17000 | — (off) | — | `client_records`: complete, all answered |
| PI1U-900008 | 17000 / 17000 | 0.0015 | **unprivileged, coverage 1.0, netns verified** | uid 1000, `CapEff` 0, netns link = lab A's inode |
| PI1U-900009 | 17000 / 17000 | 0.0015 | **unprivileged, coverage 1.0, netns verified** | uid 1000, `CapEff` 0, netns link = lab A's inode |

Bytes the collectors wrote per run (ticks + snapshot + raw eBPF): CTRL 6.3–6.5 MB; PI1U 2.4 MB (no eBPF).

**Pairs** (`pilot.py pairs`; client side, off minus on; nearest-rank percentiles over the 200 answers):

| Pair | On p50 / p99 (ms) | Off p50 / p99 (ms) | Δ p50 | Δ p99 |
|---|---|---|---|---|
| Collectors: CTRL-900006 / PI6OFF-900006 | 4.392 / 4.600 | 4.349 / 4.590 | −0.042 | −0.010 |
| Collectors: CTRL-900007 / PI6OFF-900007 | 4.390 / 4.587 | 4.411 / 4.646 | +0.021 | +0.059 |
| Metrics writer: PI6OFF-900006 / INSTOFF-900006 | 4.349 / 4.590 | 4.407 / 4.659 | +0.058 | +0.069 |
| Metrics writer: PI6OFF-900007 / INSTOFF-900007 | 4.411 / 4.646 | 4.337 / 4.591 | −0.074 | −0.055 |

- Throughput is 100.0 req/s in every run. Arrivals are open-loop at a fixed rate and the service never saturated, so
  throughput cannot differ by construction.
- The latency differences change sign between seeds and stay within ±0.08 ms (about ±1.5 %). At this load, neither
  the collectors nor the metrics writer has an effect distinguishable from run-to-run variation.
- The design sets no threshold on these differences (§5.5, §6.7); they are reported, not scored. Two pairs per kind
  cannot bound a small effect.

## 3b. Re-baseline with the working set (campaign `20261012T074028Z`, `82ff593`)

From this campaign on, every run's workload carries the approved FZ-WORKSET working set:
- a 1 GiB file on ext4, scanned one byte per page once per second in 10 slices;
- a 16 MiB anonymous buffer.

As approved in D4, CTRL, PI-1 and PI-6 were repeated under it. All 10 runs passed every check. In every run:
- the working set was configured with the approved values (recorded in the workload's config echo);
- it was removed at cleanup, with the scratch root verified absent;
- the host comparison stayed clean.

| Measurement (4 CTRL runs) | Value |
|---|---|
| Target memory utilisation (`mem.util.target`) | 0.069 of host memory ≈ 1.06 GiB: the file is fully resident |
| Refault, reclaim, major-fault rates; PSI memory some/full; OOM kills | all 0: no memory pressure in CTRL, as intended |
| Client latency p50 / p99 | 4.36–4.42 / 4.60–4.62 ms (before the working set: 4.38–4.43 / 4.58–4.62 ms) |
| PI-1 coverage; PI-6 collector CPU | 1.0; 0.0020–0.0022 core (PI1U: 0.0016) |
| W-window P99 (raw documents): queue wait / dependency latency / lock wait | 0.05 ms / 3.2 ms / no observations (the CTRL maxima for PI-8) |
| Bit rate through R (byte counters, D3) | A→B ≈ 638 kbit/s, B→A ≈ 585 kbit/s, so the approved congestion/police floors (0.5×) are ≈ 319 and ≈ 292 kbit/s |

Pairs (report-only):
- **Collectors on/off:** Δp50 −0.04 to −0.01 ms, Δp99 +0.02 to +0.04 ms.
- **Metrics writer on/off:** Δp50 −0.04 to +0.03 ms, Δp99 +0.02 to +0.03 ms.

Both stay within the variation seen before the working set.

## 3c. PI-8 application faults (campaign `20261012T074028Z`, `82ff593`)

**Setup.**
- 22 `pi8` runs, 2 reps per approved candidate (FZ-INTENSITY-APP): pool P′ 3, 2, 1; lock hold 500, 1,000, 2,000,
  5,000 µs; dependency delay 4, 7, 10, 15 ms.
- Every run passed every pipeline check, including `injection_verified`:
  - each fault was issued right after tick 45 (run time 60 s, AMD-10);
  - the workload's echo read it back within 10–51 ms, which is the R̂ input to the FZ-TTRANS rule.
- All 17,000 requests were answered with 200 in every run. Cleanup, the host comparison and BPF release were ok.

**Effect ground truth.** W-window P99 of the injected mechanism's wait metric, from the raw metrics documents,
compared with the CTRL maximum of the 4 CTRL runs (FZ-PI7) or, for lock hold, with FZ-PI7-LOCK's 0.05 ms:

| Fault | Candidates (weakest → strongest) | W P99 (both reps) | Bar | Ground truth 2/2 | Client p50 (ms) |
|---|---|---|---|---|---|
| Dependency delay | 4 / 7 / 10 / 15 ms | 6.4 / 12.8 / 12.8 / 25.6 ms | 3.2 ms | **all four** | 6.3 / 9.4 / 12.4 / 17.4 |
| Pool shrink | P′ 3 / 2 / 1 | 0.05 ms at every level | 0.05 ms | **none** | 4.4 at every level |
| Lock hold | 500 / 1,000 / 2,000 / 5,000 µs | 0.05 ms at every level | > 0.05 ms | **none** | 4.9 / 5.4 / 6.4 / 9.5 |

`pilot.py levels` (report-only, nothing frozen):
- **Dependency delay:** I1 = 4 ms, I3 = 15 ms, I2 = 7 ms (geometric mean 7.7, rounded toward I1). I2 is itself a
  candidate with 2/2 reps; whether those reps count as AMD-13's I2 confirmation is for the M5 review. No candidate is
  below I1, so I0 (SENS) has no candidate.
- **Pool shrink and lock hold:** no level can be selected.

**Why pool and lock show nothing.** The approved load is open-loop with bounded jitter (FZ-WORKLOAD: λ = 100 /s,
jitter 0.5). Arrival k is placed at (k + U(−0.25, 0.25)) / λ, so consecutive arrivals are never closer than 5.0 ms;
measured, the minimum gap is 5.03 ms and the median 10.0 ms.

- **Pool shrink.** The pool did shrink (`pool_size` 4 → 1 in the W-end document), but a request occupies a worker
  for about 4.4 ms. That is less than the minimum gap, so requests never overlap: 8,992 of 8,993 W-window queue waits
  are in the first bucket.
- **Lock hold.** Even a 5,000 µs hold ends before the next arrival, so the lock is never contended: all 8,976
  acquisitions are in the first bucket. The hold still adds its own duration to every request's latency.
- **The D2 arithmetic.** The ceilings were set at utilisation ≤ 0.5, computed as if arrivals were random. Under this
  arrival process, utilisation below 1 with occupancy below the minimum gap means zero queueing. That premise was
  wrong; this result corrects it. These rows are a property of the approved workload, not a collector or pipeline
  failure.

The FZ-PI7-LOCK rule did what it was approved for: uncontended acquisitions, about 8,990 per run, all at 0.05 ms, did
not count as an effect.

## 3d. Poisson arrivals, application faults again, CPU faults (campaign `20261012T104753Z`, `2280a18`)

From this campaign on, arrivals are Poisson at 100 /s (FZ-ARRIVALS, owner option A after §3c).

**CTRL (4 runs).**
- Every run passed and every request was answered.
- W-window P99: queue wait 3.2 ms (bounded jitter: 0.05 ms), dependency latency 6.4 ms, no lock waits.
- Client latency p50 / p99: 4.64–4.65 / 9.6–10.1 ms.
- A's TCP retransmissions in W: 0 in every run (the CTRL maximum for PI-2).

**PI-8, application faults (22 runs plus one repeat).** All injections were read back in 10–52 ms.

| Fault | Candidates | W P99 of its wait (both valid reps) | Bar | Effect in 2/2 | Levels (not frozen) |
|---|---|---|---|---|---|
| Dependency delay | 4 / 7 / 10 / 15 ms | 12.8 / 12.8 / 25.6 / 25.6 ms | 6.4 ms | all four | I1 4, I2 7, I3 15 ms |
| Lock hold | 500 / 1,000 / 2,000 / 5,000 µs | 6.4 / 6.4 / 12.8 / 25.6 ms | > 0.05 ms | all four | I1 500, I2 1,581, I3 5,000 µs |
| Pool shrink | P′ 3 / 2 / 1 | 3.2 / 3.2 / 12.8 ms | 3.2 ms | P′ = 1 only | I1 = I2 = I3 = 1, I0 = 2 |

With Poisson arrivals all three mechanisms produce waiting; under bounded jitter (§3c) pool shrink and lock hold did
not.

**PI-8, CPU faults (16 runs).**
- All read back within 21 ms.
- Effect ground truth (design §5.8) in every rep:

| Fault | Candidates | Ground truth (both reps) | Levels (not frozen) |
|---|---|---|---|
| Contention (contender `cpu.weight`) | 50 / 100 / 200 / 400 | CPU 18 idle in W ≤ 0.02 % at every weight | I1 50, I2 141, I3 400 |
| Throttling (target `cpu.max`) | 0.20 / 0.15 / 0.10 / 0.075 core | throttled periods 99.3–100 %; usage per period within 0.2 % of the quota | I1 0.20, I2 0.122, I3 0.075 core |

The quota was restored with read-back before each cleanup.

**PI-6 under throttling (all 8 quota runs).**
- **Collector CPU:** stayed within budget.
- **Coverage:** two throttle features miss 0.99. The pipeline checks passed, but each run's PI verdict is `ok: false`.
  - `throttle.quota_cores` at about 0.989. It misses one tick: the boundary tick read just before the quota was
    applied (CPU 18 is unlimited until the fault).
  - `throttle.quota_saturation` at about 0.56: the collector limitation R2-D already documented.
- **Heavier quotas:** two runs (0.10 and 0.075 core) also show `psi.cpu.some.target` below 0.99.
- **For the M5 review:** whether PI-6 should exclude features whose source exists only after the fault starts. The
  rule was not changed during the campaign.

**Failed runs (kept, labelled, excluded from levels).**
- **PI8-900081 (delay 15 ms, rep 2): host comparison failed.** Only `cgroup_dirs_identical` failed. The login session
  cgroup `user.slice/.../session-15.scope` was replaced by `session-30.scope`: systemd-logind logged out SSH session 15
  at 17:46:52 and opened SSH session 30 from 192.168.52.107 at 17:46:56, one second after the run's "before" snapshot.
  Nothing the lab creates or touches changed. The check was not loosened; the rep was repeated as PI8-900082
  (passed).
- **PI8-900116 (loss 0.5 % on A egress): across-R reconciliation failed.** A sent 174,597 segments and R received
  173,925; the 672 were dropped at A's netem qdisc by design. The CTRL invariant cannot hold for a fault that drops
  on the path.
  - **Fix (`6320943`):** the reconciliation now allows missing segments only at the declared fault's hop, and only as
    many as that hop's qdisc drop counter shows.
  - **This run stays failed:** it was evaluated at `2280a18` and has no qdisc counters.
  - **Remaining network-fault runs:** the 31 not yet run move to a new campaign at the fixed commit.
  - **Second failure (campaign `20261012T133839Z`, PI8-900200, the same fault):** 699 segments short against 596 qdisc
    drops. The window's kernel counters showed the reason. A's IP layer sent 92,926 packets; netem passed 92,449 and
    dropped 471; A's interface carried 92,456. TCP, meanwhile, counted 92,737 segments plus 285 retransmissions.
    Segments are not packets once there are retransmissions.
  - **Second fix:** the reconciliation now compares A's IP packet counters with R's packet counters. In the same fix,
    a client network failure under a declared network fault is accounted for: the server must have either never seen
    the request or answered it with the answer lost, bounded by the number of such failures.
  - **PI8-900200 stays failed.**

## 3e. PI-8 network faults (campaign `20261012T141516Z`, `dc5b3d5`)

PI-0 5/5, CTRL 4/4 and all 32 network-fault runs passed every pipeline check, with A's IP packets reconciled
against R in every run (`caf5ff0`). Every run:
- got exactly its intended fault, magnitude and seed (checked from the evidence);
- had its fault read back within 2–19 ms;
- left the host clean.

CTRL: A's retransmissions in W 0 in every run (the PI-2 bar).

| Fault | Candidates (weakest → strongest) | Effect ground truth in W (both reps) | Levels (not frozen) |
|---|---|---|---|
| Loss on A egress (`network_packet_loss`) | 0.5 / 1 / 2 / 5 % | A root qdisc drops 418–3,756 | I1 0.5, I2 1, I3 5 % |
| Police on A ingress (`network_packet_loss`) | 550 / 450 / 350 / 300 kbit/s | A ingress drops 9,322–15,470 | I1 550, I2 407, I3 300 kbit/s |
| Path loss, R toward B (`tcp_retransmissions`) | 0.5 / 1 / 2 / 5 % | A retransmissions 273–2,306, A's local drops 0 (PI-2) | I1 0.5, I2 1, I3 5 % |
| Congestion, netem rate on R toward B (`tcp_retransmissions`) | 600 / 500 / 400 / 320 kbit/s | A retransmissions 86–91 at 600, **2–16 at 500 and below**; A's local drops 0 | I1 600, I2 439, I3 320 kbit/s |

**Client side.**
- Loss and police raise 503s and dependency 504s.
- Police at ≤ 450 kbit/s also produced 1–2 client timeouts per run. Each was accounted for by the server counts
  (`caf5ff0`).
- Congestion and heavy loss saturate the client (`client_saturated`, never sent).

**Congestion, for the M5 review.** The netem queue (limit 1,000) never overflowed, so R dropped nothing. The
congestion shows up as queueing delay, 503 rejections and client saturation. Retransmissions fall as the rate falls,
because less traffic gets through. At 400 kbit/s one rep meets the bar (CTRL maximum 0) with only 2
retransmissions. The rule is met, but the signal is thin; whether it is robust enough for a `tcp_retransmissions`
claim is for the M5 review.

## 3f. Memory pressure, first run (campaign `20261012T165705Z`, `c874aa4`)

PI-0 5/5 and CTRL 2/2 passed; CTRL memory pressure, refaults and OOM all 0.

**PI8-900320 (`memory.max` = 960 MiB, the weakest candidate): FAILED.**
- **What passed:** injection read back in 22 ms; cleanup restored `memory.max` to `max`; host comparison clean; host
  MemAvailable stayed about 13 GiB.
- **The kernel effect is strong:**
  - 103,908 `max` events and 6.68 million refaults in W (about 74,000/s);
  - memory PSI some 3.45 s;
  - `oom_kill` 0, swap 0.
  - Ground truth and PI-5 are both met.
- **The workload stalled:**
  - only 5,932 requests got 200;
  - 1,262 client timeouts;
  - 8,763 arrivals never sent (`client_saturated`);
  - 87 of 136 app ticks valid, so the app features are MISSING.
  - This failed `app_features` and client/server reconciliation.

**Cause.** The FZ-WORKSET scanner is a thread inside the Python workload that touches the file through `mmap`. Below
the working set, the kernel evicts the file in a loop: about 1 GiB is re-read every pass. Each touch is a major fault
taken while the thread holds the interpreter lock, so every request thread waits with it. R2-F's scanner was its own
process, so its target could not stall this way. The stall is an artifact of the in-process scanner, not the
mechanism the class claims (requests slowed by memory pressure). The run is kept as failed; the remaining memory runs
were not started.

## 3g. Scanner as a separate process; memory pressure (campaign `20261012T175020Z`, `c4e10d8`)

The owner chose to run the FZ-WORKSET scanner as its own process (M-2, `0f9fd10`). The workload forks it before the
listener opens; the pilot aborts unless the target holds exactly the workload and its child (`run.json`
`target_processes`).

- **PI-0 5/5 and CTRL 4/4 passed** with the scanner process: 136/136 valid app ticks, PI-1 coverage 1.0, collector
  CPU 0.0022–0.0024 core. CTRL W p99: latency 12.8 ms, queue wait 3.2 ms, dependency latency 6.4 ms (bucket bounds),
  memory PSI and refaults 0.
- **Re-checks, one run per earlier fault at a mid candidate: all 9 passed their pipeline checks**, with injection
  verified and ground truth met in each. W p99 latency: pool P′ 1 25.6 ms; lock hold 2,000 µs 25.6 ms (lock wait
  12.8 ms); dependency delay 7 ms 25.6 ms; contention 100 51.2 ms; quota 10,000 µs 1,638 ms; local loss 1 %
  409.6 ms; police 450 kbit/s 1,638 ms; path loss 1 % 1,638 ms; congestion 500 kbit/s 819 ms. PI8-900344 (quota)
  again misses PI-6 coverage on `throttle.quota_cores` and `throttle.quota_saturation` (§6, known).
- **Memory, all 8 runs passed their pipeline checks; the stall of §3f is gone.** Every rep met ground truth and
  PI-5: the limit was hit (85,000–87,000 `max` events), refaults and memory PSI were above the CTRL maximum (0), no
  OOM kills and no swap. `levels` reports every candidate established 2 of 2 (I1 960, I3 256 MiB, I2 496 MiB
  interpolated, needs confirmation).

| `memory.max` (MiB) | Runs | Refaults in W | Memory PSI some (s) | W p99 latency (ms) |
|---|---|---|---|---|
| 960 | 900360, 900361 | 5.46 M, 5.45 M | 3.07, 3.14 | 25.6, 25.6 |
| 768 | 900362, 900363 | 5.45 M, 5.49 M | 3.19, 3.17 | 25.6, 25.6 |
| 512 | 900364, 900365 | 5.46 M, 5.46 M | 3.12, 3.16 | 12.8, 25.6 |
| 256 | 900366, 900367 | 5.45 M, 5.48 M | 3.10, 3.15 | 12.8, 25.6 |

**Findings for the M5 review (report-only, nothing changed):**
- **The memory effect is saturated, not graded.** All four candidates sit below the 1 GiB file, so the scanner
  re-reads the whole file every pass at any limit; refaults and PSI are the same from 960 to 256 MiB. The kernel
  effect is real, but the candidates do not order by severity, and the service's latency moves by at most one
  histogram bucket. Grading would need candidates around the working set (above and below 1,040 MiB) or a different
  working-set size; that is an FZ-INTENSITY-MEM / FZ-WORKSET question for the owner.
- **`mem.util.target` loses ticks at the limit.** In PI8-900361, 900366 and 900367, 1 or 2 of 90 ticks read
  `memory.current` a few pages above `memory.max` (ratio 1.000004–1.0004). The kernel charges before it reclaims,
  so this is a real reading, but the normaliser rejects any fraction above 1 (`normalize._in_range`). Coverage
  fell to 0.978–0.989, below PI-6's 0.99. The collector is frozen code; whether to cap the ratio at 1.0, accept the
  overshoot, or keep the gap is an owner decision.

## 3h. OV-4 and OV-5 feasibility (campaign `20261013T024805Z`, `9934ca0`)

PI-0 5/5 and CTRL 2/2 passed (CTRL memory refaults, reclaim scans and PSI all 0). Every run met PI-1, PI-6 and
PI-7 (CTRL part).

**OV-4 (AMD-13, FZ-OV): producible in both reps (PI8-900430, PI8-900431).**
- (a) sender and receiver both reported 79,965 pps against the 80,000 pps level (τ = 10 %);
- (b) receiver loss 0;
- (c) the flood client alive at all 90 W ticks by read-back;
- (d) the client allowed only CPU 22, in A's namespace; support and target cpusets disjoint;
- (e) cleanup and the host comparison passed, and across-R reconciliation held with the flood on the path.
- Report-only: softirq share over W was 0.0034–0.0036 on CPU 18 (A) and ≤ 0.0014 on CPUs 22/23, and A's W p99
  latency stayed at the CTRL value (12.8 ms). The increase is far below overload, as OV-4 intends.

**OV-5 (AMD-15 F1, FZ-OV O-1): feasible in both reps (PI8-900440, PI8-900441).**
- fill: 768 MiB written and fsynced, read back in 0.43 s and 0.47 s, writer exit 0 (judged against T_TRANS once
  T_TRANS is frozen; T_cap 30 s met);
- residency 1.0 at every W tick after the fill (r* = 0.9), all 90 W ticks observed;
- `memory.events` high, max and oom_kill deltas 0;
- refaults, reclaim scans and memory PSI 0, equal to the CTRL maxima (labelled non-independent);
- MemAvailable stayed above 4 GiB (no abort);
- utilisation at the W end 0.915 of M; A's W p99 latency at the CTRL value (12.8 ms).
- Note: PI-6 collector CPU in the OV-5 runs was 0.011 core (0.002 in every other run), within the 0.02 budget. The
  figure includes the driver's own per-tick residency read (pilot instrumentation, not a production collector).



| PI | Status | Basis |
|---|---|---|
| PI-0 | **pass** (5/5 at `af2a4e7`) | §2 |
| PI-1 | **pass in both modes.** Driver-root: coverage 1.0 in all 6 CTRL runs at `af2a4e7` and `29d652f`. Unprivileged: coverage 1.0 and netns verified in PI1U-900008 and PI1U-900009. The choice of mode (Q-2) is the owner's. | Design §6.2: 2 runs per mode |
| PI-6 | **pass.** Collector CPU 0.0015–0.0021 core (budget 0.02) and coverage ≥ 0.99 in every collected run. 2 collectors-off pairs complete (§3a, report-only differences). | Design §6.7 |
| Instrumentation | 2 on/off pairs complete; report-only (§3a) | Design §5.5 |
| PI-7 | CTRL part: 136/136 valid app ticks, `app.latency_ms` P99 measured, in every run. Fault part: dependency delay above the CTRL maximum in every rep; pool shrink and lock hold not (§3c). An owner decision is pending. | FZ-PI7, FZ-PI7-LOCK |
| PI-8 (application) | Under Poisson arrivals (§3d): dependency delay I1 4 / I2 7 / I3 15 ms; lock hold 500 / 1,581 / 5,000 µs; pool shrink only P′ = 1. Not frozen. (Under bounded jitter, §3c, pool and lock had no effect.) | FZ-PI8 |
| PI-8 (CPU) | Contention I1 50 / I2 141 / I3 400; throttling 0.20 / 0.122 / 0.075 core; effect in every rep (§3d). Not frozen. | FZ-PI8 |
| PI-8 (network) | Local loss 0.5 / 1 / 5 %; police 550 / 407 / 300 kbit/s; path loss 0.5 / 1 / 5 %; congestion 600 / 439 / 320 kbit/s (thin retransmission signal below 600) (§3e). Not frozen. | FZ-PI8 |
| PI-2 | **pass**: path loss shows A retransmissions above the CTRL maximum while A's local drop counters stay 0, in every rep (§3e) | design §6.3 |
| PI-8 (memory) | Every candidate established 2 of 2, but the effect is saturated (same refaults and PSI at 960…256 MiB) (§3g). Not frozen. | FZ-PI8 |
| PI-5 | **met** in all 8 memory runs: PSI above CTRL, no OOM kills, swap 0 (§3g) | FZ-PI5 |
| OV-4 | **producible** 2 of 2 at 80,000 pps (AMD-13 (a)–(e)) (§3h) | FZ-OV |
| OV-5 | **feasible** 2 of 2 (AMD-15 F1; fill timing judged again once T_TRANS is frozen) (§3h) | FZ-OV O-1 |
| PI-3 | not run | §6 |

## 5. Evidence and integrity (AMD-27)

- **Committed:** every file under `results/phase1c_m5_pilot/<campaign>/<run>/`, for PI-0 cycles and all runs,
  passing and failed: 175 files (about 45 MB) in `92efb56`, plus 181 files (about 36 MB) for campaign
  `20261012T045417Z`.
- **Excluded:** `<run>/lg/client.jsonl` (transport copy) and `<run>/collector/` (the unprivileged collector's
  output, copied into `evidence/`). These are ignored by `.gitignore`. Each excluded copy was verified
  byte-identical to its manifest-covered `evidence/` counterpart before it was excluded.
- `tests/faultlab/test_integrity.py` enforces the following on the committed tree:
  - allowed names only: `<UTC campaign>/<PI0-k | CTRL|PI1U|PI6OFF|INSTOFF-9xxxxx>/[evidence/|logs/]<name>.(json|jsonl|stderr)`;
  - regular files only;
  - append-only history (no edit, delete or retype after commit);
  - every run manifest lists exactly the run's committed `evidence/` files, with matching SHA-256.
- Pinned by SHA-256, so they can never be relabelled: `20261011T175343Z/PI0-1/run.json` (ok false) and
  `20261012T030504Z/CTRL-900001/report.json` (`pipeline_ok` false).
- Committed snapshots are classified `PILOT_RUN` in `tests/runtime/test_corpus.py`. Their parameter set must stay
  unregistered, so M2 cannot evaluate them, and their manifest must verify.
- `tests/runtime/test_raw_replay.py` rebuilds each committed pilot snapshot byte-identically from its committed
  `ticks.jsonl` with `pilot.replay`.

Re-check from a clean checkout:

    .venv/bin/python experiments/faultlab/pilot.py evaluate results/phase1c_m5_pilot/<campaign>/CTRL-<seed>

## 6. Blockers (owner decisions)

- **Application pool shrink and lock hold (§3c): resolved.** The owner chose Poisson arrivals (FZ-ARRIVALS); §3d
  shows all three mechanisms producing waiting.
- **Memory working-set scanner (§3f): resolved.** The owner chose a separate scanner process (M-2); §3g shows no
  stall.
- **Memory grading (§3g): decided (M-3).** Memory is a single-severity class in the pilot; graded levels are left
  to the M5 review.
- **`mem.util.target` above 1 at the limit (§3g): decided (M-4).** Known limitation; the collector stays frozen
  (a cap would change committed snapshots' replay under `m3a-1.1.0`). Left to the M5 review.
- **PI-6 under throttling (§3d), for the M5 review:** whether features whose source exists only after the fault
  starts count towards PI-6 coverage.

- **FZ-INTENSITY: pending only for the PI-8 level freeze**, which is the M5 review's. Every candidate set and
  ceiling is approved (C-1, D2, D3, M-1, FZ-OV, O-1), and every class has run (§3c–§3h).
- **FZ-PI5: resolved** (M-1, approved 2026-10-12); PI-5 met in every memory run (§3g).
- **AMD-13 / AMD-15: resolved.** n_r, τ and the OV-4 level (D5) and the OV-5 sizes (O-1) are approved; OV-4 and OV-5
  ran and are feasible (§3h).
- **FZ-PI7, lock-hold comparison: resolved** by FZ-PI7-LOCK (approved 2026-10-12): the CTRL maximum of
  `app.lock_wait_ms` is 0 ms by rule and a rep needs a measured P99 above 0.05 ms; `levels` applies it (§3d).

## 7. M5 review package

Everything the M5 review needs to decide, in one place. Nothing here is frozen or validated by the pilot itself;
freezing is the review's (FZ-INTENSITY, FZ-PI8).

**7.1 Runs.** 211 run directories over 10 campaigns, all committed (§5). 6 failed and are kept as failed:

| Run | Failure | Resolution |
|---|---|---|
| `20261011T175343Z/PI0-1` | lab forwarding and the `/run/netns` mount (§1) | fixed `6c0030d`, `7f6eac7` |
| `20261012T030504Z/CTRL-900001` | `app_features` lock-wait defect (§3) | fixed `af2a4e7` |
| `20261012T104753Z/PI8-900081` | host comparison: an external SSH login change | external; repeated |
| `20261012T104753Z/PI8-900116` | across-R reconciliation under local loss | fixed `6320943` |
| `20261012T133839Z/PI8-900200` | across-R: segments are not packets under retransmission | fixed `caf5ff0` |
| `20261012T165705Z/PI8-900320` | in-process scanner stalled the workload under `memory.max` | scanner process, M-2 (`c4e10d8`) |

**7.2 PI-8 levels proposed for freezing** (`levels`, first two pipeline-valid reps per candidate, 2 of 2):

| Class | Fault | I1 | I2 | I3 | Campaign |
|---|---|---|---|---|---|
| application | dependency delay (ms) | 4 | 7 | 15 | `20261012T104753Z` |
| application | lock hold (µs) | 500 | 1,581 * | 5,000 | `20261012T104753Z` |
| application | pool shrink (P′) | 1 | — | 1 | `20261012T104753Z` (P′ 2, 3: no effect) |
| CPU contention | contender weight | 50 | 141 * | 400 | `20261012T104753Z` |
| CPU throttling | quota (core) | 0.20 | 0.122 * | 0.075 | `20261012T104753Z` |
| packet loss | netem loss on A (%) | 0.5 | 1 | 5 | `20261012T141516Z` |
| packet loss | police on A (kbit/s) | 550 | 407 * | 300 | `20261012T141516Z` |
| retransmissions | path loss on R (%) | 0.5 | 1 | 5 | `20261012T141516Z` |
| retransmissions | congestion on R (kbit/s) | 600 | 439 * | 320 | `20261012T141516Z` |
| memory pressure | `memory.max` (MiB) | single severity (M-3); effect identical at 960…256 | | | `20261012T175020Z` |

\* interpolated (geometric mean, rounded toward I1): AMD-13 I2 confirmation (n_I2 = 2, tie-break toward I1,
N_att = 2) is still to run once I1 and I3 are frozen.

**7.3 T_TRANS inputs (AMD-9).** Maximum read-back latency R̂_c over the pipeline-valid pilot runs of each class:

| Class | Runs | R̂_c (s) |
|---|---|---|
| application (delay / lock / pool) | 17 / 17 / 13 | 0.041 / 0.052 / 0.051 |
| CPU contention / throttling | 9 / 9 | 0.021 / 0.001 |
| packet loss / retransmissions | 18 / 18 | 0.019 / 0.002 |
| memory pressure | 8 | 0.098 |
| OV-4 / OV-5 (fill) | 2 / 2 | 0.021 / 0.468 |

T_TRANS = ceil(max_c (R̂_c + K_c)) s; the K_c (or the fallback T_fb) are the review's. With every R̂_c below 0.5 s,
T_TRANS is set by K_c.

**7.4 Decisions for the review:**
1. Freeze the PI-8 levels of §7.2 (FZ-INTENSITY, FZ-PI8), then run the I2 confirmations.
2. Pool shrink has an effect only at P′ = 1: accept a single level, or change the candidates.
3. Congestion: the retransmission signal is thin below 600 kbit/s (§3e).
4. PI-6 under throttling: whether features whose source exists only after the fault starts count towards coverage
   (quota runs, §3d, §3g).
5. Memory: graded levels (M-3) and the `mem.util.target` overshoot (M-4).
6. Q-2: collector mode for M6 (both modes pass PI-1, §3a).
7. Design-level items outside the pilot: U-1, U-1b, U-7 (before M6) and U-6 raw-data storage.
