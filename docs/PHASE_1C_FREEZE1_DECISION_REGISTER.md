# Phase 1C Freeze-1 Decision Register

**Status: PARTLY APPROVED.** Rohit Kumar approved 31 of the 33 Freeze-1 decisions on 2026-10-11 (commit `4b6041c`),
and on 2026-10-12 the eight items of the pilot decision package, the arrival-process amendment A-1, the CPU/network candidates C-1
the memory items M-1, the working-set scanner amendment M-2, the memory decisions M-3 and M-4, the OV-5 sizes O-1 and, on 2026-10-13, the M5 review decisions R-1 … R-7 (§5). `FZ-INTENSITY` was closed on 2026-10-13 (R-8)
for what is still unresolved (§4, §5). Approval is recorded only in
[`PHASE_1C_FREEZE1_DECISIONS.json`](PHASE_1C_FREEZE1_DECISIONS.json); this register holds the rationale (§3).
**Owner approval of a design choice is not scientific validation:** every ENG value is still unvalidated until
pilot evidence exists. Revision 1 (Gate 1.1, at `8cff3b8`)
is §1–§2; revision 2 (finalized proposals, 2026-10-11) is §3–§4 and Appendix A.

- No privileged pilot step may run until the decisions it needs are approved and the privileged preflight passes.
- Draft referenced (not modified, untracked, owner-owned): [`PHASE_1C_M4_M5_PILOT_DESIGN.md`](PHASE_1C_M4_M5_PILOT_DESIGN.md)
  (SHA-256 `10e48c7b…`). Line numbers below refer to that file as inspected.

Status tags: **REG** registered in a committed document; **DEC** owner decision recorded in a committed document;
**V** verified in code or committed evidence; **P** proposal (draft or this register); **OPEN** no proposal yet;
**EXT** exists only outside the repository (review reports), not in any file.

## 1. Register

| # | Item | Current value | Source | Status | Approval needed |
|---|---|---|---|---|---|
| 1 | Workload parameters (λ, jitter, P, P′, Q, `cpu_us`, lock hold, dependency delay, poll period, timeout, connection model, publish period) | None for the lab. Rehearsal only: `smoke` P=4, Q=32, `cpu_us`=500, lock 200 µs, publish 0.25 s, λ=40/s; `overload` P=1, Q=2, delay 30 ms, λ=60/s | `experiments/faultlab/rehearsal.py` `PROFILES` **V** (uncalibrated, loopback); draft §5.4 l.304 **P** | OPEN | Values per class, before M5 |
| 2 | I3 ceilings (and I1/I2) | R2 evidence levels: loss 1 %/5 %; quota 0.15/0.075 cores; contender weight 100/400; `memory.high` 768/512 MiB. Rule: I1 lowest with ground truth 2/2, I3 highest within safety limits, I2 geometric mean | draft §6.9 l.538 **P**; R2 levels **V** (committed R2 reports) | P | Ceiling per class and the selection rule, before M5 |
| 3 | PI-5 acceptance | Design: "PSI memory > CTRL range without `oom_kill`". Draft quantification: PSI some > CTRL max, `oom_kill` = 0, swap ≤ 25 pages/s; levels 1024/768/512/384 MiB, 2 reps | design §10 l.431 **REG**; draft §6.6 l.502 **P** | REG (qualitative) / P (numbers) | Quantified criterion and mechanism (see D-2) |
| 3b | PI-8 acceptance | Not in the design (design has PI-1…PI-6). Draft: intensity-selection runs, 48 runs | draft §6.9 l.538 **P** | P — new criterion | Registration of PI-7/PI-8 as design text |
| 4 | `T_TRANS`, `T_cap`, `T_fb` | No numbers. Constraint `T_cap ≤ 90 − 3·W_min` (W_min = 1 s → ≤ 87 s); `T_fb ≤ T_cap`, replaces K_c for a class without an accepted K_c | Stage 3H reports (AMD-9/AMD-10) **EXT**; draft §6.11 l.600 has the older ±*b* rule **P** | OPEN | Values and which T_TRANS rule (draft ±*b* vs AMD-9 R̂_c + K_c) |
| 5 | `COV_MIN`, `N_BASE_MIN`, `SEG_MIN` | `UNCALIBRATED`. Rules: COV_MIN ≤ min CTRL coverage of PI-6-passing runs; N_BASE_MIN = ⌈COV_MIN × B⌉; SEG_MIN = p1 of `tcp.out_segs_rate` in CTRL | contract §6 l.240/248 **REG** (source "Pilot"); `parameters.json` **V**; draft §6.10 l.587–590 **P** | OPEN — depends on U-2 | U-2 (A: pilot sets them; B: M7) |
| 6 | `c_B`, `b` | Placeholders, no values. `c_B`: max CV of baseline MAD over non-overlapping B-second windows, B ∈ {10,20,30,45,60}. `b`: ±band around the fault-phase median of a ground-truth effect series that defines settling | draft §6.10 l.584, §6.11 l.612 **P** | OPEN | Numeric values; `b` may be obsolete if AMD-9 replaces §6.11 |
| 7 | Persistent raw-data staging path | Design: `datasets/faultlab/v1/raw/<run_id>/*.jsonl.gz` (append-only). Pilot: `results/phase1c_m5_pilot/<UTC>/`; `.gitignore` excludes `results/**/raw/`. Rehearsal writes to scratch only | design §8 l.403 **REG**; m4 predicate in `test_r2e.test_candidate` and `_integrity.py` **V**; draft §7 l.621 and U-6 l.750 **P** | OPEN (U-6) | U-6 A (raw in Git) or B (external archive + committed SHA-256 manifest); pilot raw location outside `/tmp` |
| 8 | AMD-1…AMD-17 design text | Exist only in Stage 3H review reports; no repository file contains them | `grep` of `docs/`, `README.md` **V** (absent) | EXT, Pending | Each AMD approved and written into design text |
| 9 | Manifest format | `{"files": {relpath: sha256}}`; integrity checker parses exactly this, requires coverage of every raw file and add-only history | `tests/faultlab/_integrity.py:61–71,131–150` **V**; `rehearsal.py` manifest **V**; design §8 l.404 **REG** | Format V (implemented); adoption for the pilot P | Approve as the pilot/M6 manifest format |
| 10 | Root of trust | Git commit SHA plus committed SHA-256 manifests (dataset version = manifest hash; `artifacts.lock`; `pilot_decisions.json` SHA committed). No signing | design §8 l.405 **REG**; draft §6.10 **P** | P | Approve "unsigned Git commit + SHA-256 manifest" or require signing/external anchor |
| 11 | `failed_injection`, exclusions, host-state equivalence | Outcomes `verified`/`failed_injection`/`aborted`; failed runs excluded and **counted**. Host state compared before/after with the R2-C `compare_host` set; campaign stops on any difference | design §6.5 l.274–276 **REG**; draft §9 l.697–739 **P**; `scripts/r2c_cpu.py:599` **V** | REG (outcomes) / P (procedure) | Exclusion list frozen; AMD-10 deadline rule (M6 only); equivalence set approved |
| 12 | R2-C/R2-D environment failures and pilot validity | 2 accepted failures (`test_r2c`/`test_r2d` `test_dry_run_mutates_nothing`): root `cgroup.subtree_control` lacks `hugetlb rdma misc`. Pilot preflight uses the required-subset rule {cpuset,cpu,memory,pids}, not R2-C exact `ROOT_SUBTREE` | regression at `8cff3b8` (1,231 run, 1,229 pass) **V**; draft §9 l.703 **P**; `scripts/r2f_memory.py:54,501–508` **V** | Accepted limitation (owner, earlier) | Confirm the limitation is acceptable for pilot validity |

## 2. Discrepancies between design, draft and implementation

1. **Memory floor.** Design §9 resource table says the stop floor is `MemAvailable < 2 GiB`; `scripts/safety_check.sh`
   and R2-F use 4 GiB; draft §9 uses 4 GiB. Recommend 4 GiB and a design correction.
2. **PI-5 mechanism.** Design §6.3 l.243 registers `memory.max`; draft §6.6 proposes `memory.high` levels. The Stage 3H
   instruction was to keep `memory.max` as default with `memory.high` only as a conditional fallback.
3. **Topology.** Design §6.1/§9 register Docker containers and bridge networks; decision 2 (design §13 l.487) replaced
   them with three netns plus a lab cgroup. Design §6.1/§9 text not yet revised.
4. **PI-7/PI-8.** Exist only in the draft; the registered pilot (design §10) has PI-1…PI-6.
5. **Pilot role.** Design §10 "fits nothing" vs contract §6 "Pilot" for `W`, `B`, `N_BASE_MIN`, `COV_MIN`, `SEG_MIN`
   (draft G-14, U-2).
6. **T_TRANS rule.** Draft §6.11 (±*b* settling) differs from the AMD-9/AMD-10 form (R̂_c + K_c, `T_fb`, `T_cap`),
   which is not in any file.
7. **Publish period.** `workload.py` default `--publish-s 1.0` equals the 1 Hz collector period; draft §5.4 says 1.0 s;
   rehearsal uses 0.25 s. Freshness at 1 Hz needs a period below the sample period; must be fixed by item 1.
8. **Rehearsal scope.** The rehearsal's target cgroup is the user session, not the lab cgroup; its evidence proves the
   pipeline only, not lab measurements.

## 3. Finalized proposals (revision 2, 2026-10-11) — approval state in the decisions record

Revision 2 turns the §1 items into concrete proposals, prepared under the owner's execution request of
2026-10-11. Rohit Kumar recorded approval of 31 of them in
[`PHASE_1C_FREEZE1_DECISIONS.json`](PHASE_1C_FREEZE1_DECISIONS.json) and committed it himself (`4b6041c`). Each approved
entry has `"status": "approved"`, `"approved_by": "Rohit Kumar"`, a date and a reference.

**Basis labels:**
- **REG:** a registered requirement.
- **MEAS:** a measured fact (evidence cited).
- **ENG:** a new preregistered engineering choice. It is not experimentally validated.
- **UNRES:** cannot be responsibly derived from existing evidence.

| Decision | Proposal | Basis and rationale |
|---|---|---|
| `FZ-WORKLOAD` | Covered in full in the next table. | ENG. The values follow from the measured rehearsal and the R2 quota levels, as the next table explains. |
| `FZ-INTENSITY` | **Rule:** draft PI-8 rule plus AMD-13 I2 confirmation (n_I2 = 2, tie-break toward I1, N_att = 2).<br>**Ceilings with R2 evidence:** netem loss p ≤ 5 % (R2-B); CPU quota ≥ 0.075 core (R2-D T2); contender weight ≤ 400 (R2-C E2).<br>**UNRES:** application P′/lock-hold/dependency-delay, congestion and police rates, memory M floor, OV-4 pps, OV-5 lab cap. | REG rule, MEAS ceilings. The unresolved classes have no evidence, so those classes cannot run. Status `pending`. |
| `FZ-PI5` | **Mechanism:** `memory.max` (design §6.3, AMD-12), with AMD-12b `memory.high` as a contingent fallback.<br>**Criterion:** PSI memory some (W) > CTRL maximum, `oom_kill` delta 0, swap ≤ 25 pages/s in every rep.<br>**UNRES:** the M4 workload has no memory working set (WS_anon, WS_file, scan rate). | REG plus the R2-C swap criterion. **PI-5 cannot run until the workload has a working set.** Status `pending`. |
| `FZ-PI7` | **CTRL:** valid app ticks ≥ 0.99, and `app.latency_ms` P99 with quality OK/PARTIAL.<br>**Application reps:** the injected mechanism's wait metric above the CTRL maximum.<br>**On failure:** decision 5 applies. | Draft §6.8. MEAS: rehearsal app coverage 1.00 in 5/5 runs. |
| `FZ-PI8` | Rule as `FZ-INTENSITY`. 4 candidates × 2 reps per class. Two consecutive verification failures stop a class. | Draft §6.9, AMD-13. |
| `FZ-TTRANS` | **Rule:** AMD-9 (T_TRANS computed after the pilot from read-back latencies).<br>**T_cap = 30 s, T_fb = 15 s.** | ENG, within AMD-9's constraint T_cap ≤ 90 − 3·W_min = 87 s. T_cap = 30 keeps W = ⌊(90 − T_TRANS)/3⌋ ≥ 20 samples; above it the run stops for review. T_fb = 15 is half of T_cap for classes whose K_c is inference only (contention, memory, application). Neither is a physical guarantee (AMD-9). |
| `FZ-DATA-QUALITY` | **U-2 = B:** COV_MIN, N_BASE_MIN and SEG_MIN are set by M7 calibration on the train split. The pilot records coverage and selects nothing. | REG: design §10 "fits nothing" and decision 7. Option B needs no new numeric rule constants, whereas option A needs a rule to round the CTRL coverage minimum. Revision 1 recommended A; this revision changes the recommendation for that reason. Contract §6's "Pilot" source column is revised accordingly. |
| `FZ-CB-B` | **c_B:** withdrawn (AMD-7: B = 45 s, W = ⌊(90 − T_TRANS)/3⌋).<br>**b:** not applicable, because R's drop counters are recorded but not gated. | AMD-7, AMD-9. |
| `FZ-STAGING` | **Pilot evidence:** `/home/iiitd/sentinelai/results/phase1c_m5_pilot/<UTC>/` (ext4, persistent; R2 convention).<br>**Live app-metrics transport:** `/run/sentinelai-lab/app/<run_id>/` (tmpfs, **volatile**; copied into the evidence and removed at cleanup).<br>**M6 raw data:** a persistent path outside the repository (AMD-17), decided before M6. | Draft §7 item 2; AMD-17. `/run` is tmpfs and cannot be the persistent store. |
| `FZ-AMD-01`…`17` | Adopt the Stage 3H texts verbatim (Appendix A). | REG intent: the texts encode the owner's ten decisions of 2026-10-10/11. AMD-6's contract text is not applied to `EVIDENCE_CONTRACT.md`, which is integrity-scoped. |
| `FZ-MANIFEST` | `manifest.json` = `{"files": {"evidence/<path>": "<sha256>"}}`; regular files only; no symlinks; every evidence file listed. Verified by `rehearsal.verify_manifest`. | MEAS (implemented, tested, rehearsal 5/5). Same format as `_integrity.py:61`. |
| `FZ-ROOT-OF-TRUST` | An unsigned Git commit plus the committed SHA-256 manifests. | **What it guarantees:** any change to a committed file, or to evidence relative to its manifest, is detected, *given a trusted copy of the commit ID*.<br>**What it does not guarantee:** it does not authenticate who made a commit; anyone with write access can commit a new manifest; an integrity amendment can admit new paths. The commit ID must be recorded outside the repository (AMD-18 note). |
| `FZ-EXCLUSIONS` | **Outcomes:** `verified` / `failed_injection` / `aborted`. Excluded runs are **counted, never replaced** (AMD-5, AMD-10).<br>**Host-state equivalence:** `compare_host` must-list with BPF compared, plus no lab netns or interface (R2-E additions). | REG design §6.5; MEAS: the R2 harnesses use exactly this. |
| `FZ-R2CD-ENV` | The pilot uses the R2-F required-subset rule ({cpuset, cpu, memory, pids}). The two `test_dry_run_mutates_nothing` failures stay documented environment failures and are not exempted. The pilot needs no `hugetlb`, `rdma` or `misc`. | MEAS: root currently `cpuset cpu io memory pids` (preflight `LAB-ROOT-SUBTREE-R2C`). |
| `FZ-LAB-SPEC` | Covered in full in the lab specification table below. | Draft §5.1, decision 2, Q-4. |
| `FZ-SAFETY-CHECKLIST` | Draft §9 preflight list, protected-state list and abort conditions, plus the proposed additions (`oom_kill` delta, `MemAvailable` < 4 GiB during a run, any host-comparison failure). **Memory floor 4 GiB** (not design §9's stale 2 GiB). | REG/MEAS: `safety_check.sh`, R2-F. |
| `FZ-M4-BASELINE` | `8cff3b8` (M4 rehearsal driver). | MEAS: the last M4 build commit. |

**FZ-WORKLOAD values.** The CTRL workload contract below is a preregistered engineering choice (ENG), not validated.

| Parameter | Value | Rationale |
|---|---|---|
| Arrival rate λ | 100 /s | Demand λ × `cpu_us` = 0.2 core. That is above the highest R2 quota level (0.15 core), so quota faults bite, and well below one core, so CTRL is not saturated. Not yet measured in the lab. |
| Jitter | 0.5 | Rehearsal value; MEAS: arrivals reconciled exactly. |
| Pool P | 4 | Rehearsal value. |
| Pool shrink P′ | 1 | The value used for the `app_pool` fault. |
| Queue Q | 32 | Rehearsal value. |
| `cpu_us` | 2000 | Gives 0.2 core at λ = 100 /s (see λ). |
| Lock hold | 0 µs | No lock contention in CTRL. |
| Lock-wait threshold | 5 ms | Rehearsal value. |
| Dependency delay | 2 ms | Rehearsal value. |
| Dependency timeout | 1000 ms | Rehearsal value. |
| Control-file poll | 0.05 s | Rehearsal value. |
| Publish period | **0.25 s** | Measured: app coverage 1.00 at 1 Hz in 5/5 rehearsal runs. This resolves discrepancy 7 (it must be below the 1 s sample period). |
| Client timeout | 5 s | Rehearsal value. |
| Maximum in-flight requests | 64 | Rehearsal value. |
| Connection model | HTTP/1.1, one request per connection, open loop | Load runs B → R → A; the workload calls its dependency A → R → B. |

**FZ-LAB-SPEC values.**

| Element | Value |
|---|---|
| Namespaces | `sentinel-lab-a`, `sentinel-lab-r`, `sentinel-lab-b` |
| A–R link | veth `sentlab-a0` (A, 10.199.1.1/24) ↔ `sentlab-ra` (R, 10.199.1.254/24) |
| R–B link | veth `sentlab-rb` (R, 10.199.2.254/24) ↔ `sentlab-b0` (B, 10.199.2.2/24) |
| veth queues | single queue |
| Routes | A: 10.199.2.0/24 via 10.199.1.254. B: 10.199.1.0/24 via 10.199.2.254. No default route anywhere. |
| Forwarding | `net.ipv4.ip_forward=1` inside R only; the host value is unchanged |
| Lab cgroup | `/sys/fs/cgroup/sentinel-fl/{target, contender, support}` with `cpuset cpu memory pids` |
| CPU placement | parent CPUs 18, 19, 20, 22, 23; target 18; contender 18; support 19, 20, 22, 23; CPU 21 excluded (NIC IRQ 134) |
| Lab memory | parent `memory.max` 2560 MiB (design §9 budget); `memory.swap.max` 0 on every leaf |
| Process limits | `pids.max` 64 for target; 256 for support |
| CPU quota | `cpu.max` = `max` |
| Placement | workload in A and the target leaf; dependency peer and load generator in B and the support leaf (Q-4 option A); all lab processes run as uid 1000; driver, collectors and loader on CPUs 0–15 |
| Ports | workload 8080; dependency 9000 |

**Measured risk to record before the pilot (MEAS).** In the unprivileged rehearsal, the collector (M3A + app, no M3B)
used 0.0177 and 0.0181 core at 1 Hz (two runs). That is close to PI-6's registered 0.02-core budget before M3B is
added. PI-6 may fail. If it does, the result is reported and the budget is not changed.

**Resolution of the §2 discrepancies (revision 2; approval state in §4):**
1. Use 4 GiB.
2. Use `memory.max` (AMD-12).
3. A–R–B namespaces (decision 2); Docker text superseded.
4. PI-7 and PI-8 as above.
5. U-2 = B.
6. AMD-9.
7. Publish period 0.25 s.
8. Rehearsal evidence is pipeline evidence only. Lab measurements come only from the privileged pilot.

## 4. Approval boundary and execution blockers

- **Approved by Rohit Kumar on 2026-10-11 (31; commit `4b6041c`):**
  - `FZ-WORKLOAD`, `FZ-PI7`, `FZ-PI8`, `FZ-TTRANS`, `FZ-DATA-QUALITY`, `FZ-CB-B`, `FZ-STAGING`;
  - `FZ-AMD-01` … `FZ-AMD-17`;
  - `FZ-MANIFEST`, `FZ-ROOT-OF-TRUST`, `FZ-EXCLUSIONS`, `FZ-R2CD-ENV`, `FZ-LAB-SPEC`, `FZ-SAFETY-CHECKLIST`,
    `FZ-M4-BASELINE`.
- **Pending (2):**
  - `FZ-INTENSITY`: the ceilings without evidence are unresolved.
  - `FZ-PI5`: the workload has no memory working set, so **PI-5 execution is not authorised**.
- Approving AMD-13 and AMD-15 adopts their text only. n_r, τ, the OV-4 level rule and the OV-5 thresholds stay
  unresolved, so OV-4 and OV-5 cannot run.
- Approval is not validation. The workload, T_cap/T_fb and the other ENG values remain preregistered choices until
  pilot evidence exists. PI-6's budget risk (§3) is unchanged.
- **Unresolved; the affected classes cannot run:** application, congestion and memory ceilings; the workload memory
  working set (PI-5); OV-4 (n_r, τ, level rule); OV-5 thresholds.
- **Gate 2 privileged steps need root.** `sudo` requires a password, so this session cannot run them. As in R2, the
  owner runs them with `sudo`.

## 5. Pilot decision package (approved 2026-10-12)

After PI-0, CTRL, PI-1 (both modes) and PI-6 had passed (`docs/PHASE_1C_M5_PILOT_REPORT.md`), the owner was given a
decision package with evidence, options and a recommendation per item, and chose option A for every item. The record
holds each one under its own ID. Tags as in §1; **ENG** values are arithmetic on approved values, not measurements.

| Item | Record ID | Approved | Basis |
|---|---|---|---|
| D0 | `FZ-INTENSITY-R2` | netem loss on A egress ≤ 5 %; CPU quota ≥ 0.075 core; contender weight ≤ 400 | **V** R2-B, R2-D T2, R2-C E2 |
| D1 | `FZ-PI7-LOCK` | CTRL maximum of `app.lock_wait_ms` = 0 ms (every CTRL run proves zero lock acquisitions with `lock_hold_us 0`); a lock-hold rep needs `app.lock_wait_ms` P99 in W measured (OK/PARTIAL) and > 0.05 ms, the first histogram bucket bound, so an uncontended acquisition does not count | **V** CTRL evidence; threshold **ENG** |
| D2 | `FZ-INTENSITY-APP` | Worker utilisation ≤ 0.5 at λ = 100 /s and service time ≈ 4.4 ms (CTRL client p50 4.38–4.43 ms): pool P′ ≥ 1, candidates 3, 2, 1 (only three exist with P = 4; accepted); lock hold ≤ 5,000 µs, candidates 500, 1,000, 2,000, 5,000; dependency delay ≤ 15 ms, candidates 4, 7, 10, 15 | **V** CTRL; ceilings **ENG** |
| D3 | `FZ-INTENSITY-NET` | Path loss (netem on R toward B) ≤ 5 %; congestion and police rate floor = 0.5 × the measured CTRL bit rate in that direction; netem limit ≤ 1,000 packets. Byte counters at R are added first; congestion and police do not run until the bit rate is measured and reported | local loss **V** (R2-B); rates **OPEN** until measured |
| D4 | `FZ-WORKSET` | A preregistered file-backed working set shaped like R2-F (a file scanned at a fixed rate, a small fixed anonymous buffer), always present in the workload, as an FZ-WORKLOAD amendment; CTRL, PI-1 and PI-6 are repeated at that commit. Values (approved the same day, recorded in `FZ-WORKSET`): a 1 GiB file on ext4 at `/var/tmp/sentinelai-lab/<run_id>/ws.bin`, created and `fsync`ed by the workload in its own cgroup before it reports ready, deleted and verified absent at cleanup; `mmap`, `MADV_RANDOM`, one byte per page; the whole file once per second in 10 slices; a 16 MiB anonymous buffer touched each pass; no memory limit in CTRL beyond the lab cap. Deviation from R2-F: R2-F scanned continuously on its own CPU; here the workload shares CPU 18 with request handling (about 2.6 ms CPU per pass) | **V** R2-F mechanism; rate **ENG** |
| D5 | `FZ-OV` | OV-4: n_r = 2, τ = ±10 %, level 80,000 pps (a quarter of R2-E's loss-free maximum of about 320k pps on its topology); OV-5: r* = 0.9, sizes after D4 | **V** R2-E (other topology); **ENG** |
| D5 (Q-5) | `FZ-Q5` | 14 CTRL test runs, so G-Q3 stays gate-valid if OV-4 proves infeasible | pilot design §8.1 |
| Q-2 | `FZ-Q2` | Driver-root collector mode for M6 (keeps M3B eBPF, the validated configuration); unprivileged mode recorded as feasible for M3A + app (PI-1) | **V** PI-1 |

| A-1 | `FZ-ARRIVALS` | Poisson arrivals at 100 /s (exponential gaps from the run seed) replace FZ-WORKLOAD's bounded jitter for every run from the next campaign; CTRL and the application PI-8 runs are repeated under it. Reason: in campaign `20261012T074028Z` the bounded jitter kept arrivals at least 5.03 ms apart, longer than a request's worker occupancy (about 4.4 ms) and every approved lock hold, so pool shrink and lock hold could not produce any waiting (pilot report §3c). Option A of three (B: raise the ceilings; C: dependency delay only) | **V** campaign `20261012T074028Z` |

| C-1 | `FZ-INTENSITY-CPUNET` | **Approved 2026-10-12.** PI-8 candidates within the approved ceilings: contender weight 50, 100, 200, 400 (≤ 400; R2-C 100/400); CPU quota 20,000, 15,000, 10,000, 7,500 µs per 100,000 µs, i.e. 0.20 to 0.075 core (≥ 0.075; R2-D 0.15/0.075); loss on A egress and on R toward B 0.5, 1, 2, 5 % (≤ 5 %; R2-B 1/5 %); congestion (netem rate on R toward B) 600, 500, 400, 320 kbit/s; police on A ingress 550, 450, 350, 300 kbit/s, burst 3,000 bytes (ENG); floors 319 and 292 kbit/s = 0.5 × the CTRL bit rate measured in campaign `20261012T074028Z`; netem limit 1,000 packets | ceilings **V** (R2), floors **V** (byte counters); candidates and burst **ENG** |

| M-1 | `FZ-INTENSITY-MEM`, `FZ-PI5` | Memory floor M ≥ 256 MiB and candidates 960, 768, 512, 256 MiB for `memory.max` on the target (AMD-12; AMD-12b `memory.high` only as the fallback). Basis: in CTRL the workload cgroup holds ≈ 1,080 MiB with the 1 GiB working-set file resident, so ≈ 56 MiB is not the file (the process's own anonymous memory measured at 22 MiB); the floor is ≈ 4.5× that, so a limit forces reclaim, not an OOM kill; 768 and 512 MiB are R2-F's validated levels; 960 MiB sits just below the working set. FZ-PI5 approved as drafted: memory PSI some in W above the CTRL maximum, `oom_kill` delta 0, swap ≤ 25 pages/s in every rep. Memory runs abort on host MemAvailable < 4 GiB or any OOM kill | **V** CTRL, R2-F; floor **ENG** |

| M-2 | `FZ-WORKSET` (amended) | The working-set scan runs in a separate child process forked by the workload before it serves, in the same cgroup. File, `mmap` access, pace and anonymous buffer are unchanged. The target leaf then holds the workload and its scanner (two processes). Reason: in PI8-900320 the in-process scanner held the Python interpreter lock through its major faults under `memory.max`, so every request thread stalled (pilot report §3f); R2-F's scanner was also its own process. CTRL is re-baselined, and one run per other fault class is re-checked under it | **V** campaign `20261012T165705Z` |

| M-3 | `FZ-INTENSITY-MEM` (amended) | Memory is accepted as a single-severity class for the pilot. All four candidates lie below the 1 GiB working set, and campaign `20261012T175020Z` showed the same effect at each (refaults ≈ 5.46 M, memory PSI ≈ 3.1 s, ground truth and PI-5 met 2 of 2, no OOM kills). No further memory campaigns run in the pilot; graded memory levels (candidates around the working set, or a different working-set size) are left to the M5 review | **V** campaign `20261012T175020Z` (pilot report §3g) |

| M-4 | `FZ-INTENSITY-MEM` (amended) | `mem.util.target` above 1 at the limit is a known limitation; the collector stays frozen. At the limit `memory.current` briefly exceeds `memory.max` by a few pages (ratio up to 1.0004); the frozen normaliser (`m3a-1.1.0`) rejects fractions above 1, so 1–2 W ticks lose the feature and PI-6 coverage falls to 0.978–0.989 in some memory runs. A cap at 1.0 would change committed snapshots' byte-identical replay under the same collector version, so it would need a new collector version and an integrity amendment; that is left to the M5 review | **V** PI8-900361, 900366, 900367 |

| O-1 | `FZ-OV` (OV-5 sizes) | OV-5 (AMD-15): A's `memory.max` M = 2,048 MiB for the whole run, a fresh 768 MiB file written and `fsync`ed in A's cgroup after tick 60, lab cap 2,560 MiB (design §9, unchanged), 2 reps. Basis: in CTRL the target holds ≈ 1,080 MiB with the 1 GiB working set resident; with the file resident ≈ 1,848 MiB, utilisation ≈ 0.90 of M with ≈ 200 MiB below M, so the cache fills without reaching the limit. r* = 0.9 and the F1 criteria as approved (D5, AMD-15) | **V** CTRL (campaign `20261012T175020Z`); **ENG** |

**M5 review (owner reply "all A" to the decision sheet, 2026-10-13; pilot report §7):**

| Item | Decision ID | Decision | Basis |
|---|---|---|---|
| R-1 | `FZ-M5-REVIEW` (levels) | PI-8 levels frozen as found (report §7.2). I2 = 7 ms (delay) and 1 % (both losses) are tested candidates, 2 of 2; the interpolated I2s (lock 1,581 µs, contention 141, quota 12,248 µs, police 407 kbit/s, congestion 439 kbit/s) are confirmed under AMD-13 (n_I2 = 2, tie-break toward I1, N_att = 2) | **V** campaigns `20261012T104753Z`, `20261012T141516Z` |
| R-2 | `FZ-TTRANS` (amended) | K_c: throttling 0.1 s, local and path loss 0 s, memory 1 s, application 0.065 s; contention and congestion take T_fb = 15 s. T_TRANS = ⌈15 + 0.021⌉ = 16 s; scored window W = ⌊(90 − 16)/3⌋ = 24 s | **V** read-back latencies (report §7.3); **INF** K_c |
| R-3 | `FZ-M5-REVIEW` (single levels) | Pool shrink: single level P′ = 1 (P′ 2, 3 had no effect) | **V** §3d |
| R-4 | `FZ-M5-REVIEW` (congestion) | Congestion levels kept; the thin retransmission signal below 600 kbit/s is a recorded limitation | **V** §3e |
| R-5 | `FZ-M5-REVIEW` (PI-6) | In quota runs `throttle.quota_cores` and `throttle.quota_saturation` (no source before the fault) are listed, not scored, for PI-6 coverage | **V** §3d, §3g |
| R-6 | `FZ-M5-REVIEW` (memory) | M-3 and M-4 confirmed for M6; memory single level 768 MiB (R2-F's validated level) | **V** §3g |
| R-7 | `FZ-M5-REVIEW`, `FZ-STAGING` | U-1 A (G-Q1 over 7 outcomes, 0.80 kept), U-1b A (softirq's G-Q2 waived, basis R2-E), U-7 A (G-Q1/G-Q4 over single-fault plus CTRL test runs), U-6 A (M6 raw data committed compressed with a SHA-256 manifest) | pilot design §4.5.5, §10 |

| R-8 | `FZ-INTENSITY` | Closed (owner reply "close FZ-Intensity", 2026-10-13) once all five interpolated I2 levels were confirmed 2 of 2 under AMD-13 (campaigns `20261013T035747Z`, `20261013T044701Z`, no tie-break). The record holds the final M6 level table: I1/I2/I3 per fault, single levels for pool (P′ = 1), memory (768 MiB), OV-4 (80,000 pps) and OV-5 (768 MiB) | **V** pilot report §3i, §3j |

**M6 plan (owner reply "all A", 2026-10-13; `FZ-M6-PLAN`):**

| Item | Decision |
|---|---|
| P-1 | A class's seeds are split evenly across its mechanisms (application: delay / lock / pool; loss: netem on A / police; retransmissions: path loss / congestion) |
| P-2 | Memory (768 MiB) and pool (P′ = 1) run their test seeds at the single level; the I2 test-only rule cannot apply to them (limitation) |
| P-3 | SENS I0 = ½ × I1 in injection units (weaker, so within every ceiling) |
| P-4 | OOD deferred; reported as not run |
| P-5 | AMD-29 admits the matrix generator, the M6 batch runner, their tests, `docs/PHASE_1C_M6_*.md` and `datasets/faultlab/v1/matrix.json` (add-only) |
| P-6 | U-8 traceability audit now (read-only); U-5 offline rebuild; U-4 the 6 PI-3 runs in batch 1 |
| P-8 | `FZ-M6-PLAN` (mechanisms) amended (owner reply "A", 2026-10-13, after campaign `20261013T063118Z`): the packet-loss class uses netem on A only. Police is not used in M6: its ingress qdisc next to the root qdisc makes `net.drop.qdisc` unverifiable under the contract, and its eBPF drop reason `TC_INGRESS` counts as loss only if the undeclared `KFREE_REASONS_LOSS` includes it. Police's frozen levels stay recorded |
| P-7 | `FZ-Q2` amended (owner reply "A", 2026-10-13): A's interface `sentlab-a0` is declared on the target and read in A's network namespace, so the minimum local drop set is measured. Every pilot run had `ifaces: []` and a host-namespace collector, so `net.drop.qdisc` / `iface_rx` / `iface_tx` were never collected and RT.R2 could never be evaluated. Frozen collector code unchanged; a validation campaign precedes M6 |

Matrix: 48 single-fault train + 72 test (12 per class, Q-5) + 40 overlap/distractor + 24 CTRL (10 / 14) + 12 SENS =
196 runs. Collection: code pinned for all of M6, only dataset commits between batches, each batch its own campaign with
PI-0; failed_injection excluded and counted, never retried; any other failed run kept as failed and its seed never
reused.

**M7 plan (owner reply "all A", 2026-10-14; `FZ-M7-PLAN`):** the calibration objectives of every contract parameter,
written before calibration (design §7.4), and the training plan.

| Item | Decision |
|---|---|
| C7-1 | Class thresholds: smallest value with ≤ 1 % false positives on train CTRL and other-class windows, keeping ≥ 0.9 recall on the own class; the false-positive limit wins and a recall shortfall is reported |
| C7-2 | Deviation bands: MODERATE = 99th, STRONG = 99.9th percentile of robust_z / ratio over all features in train CTRL windows |
| C7-3 | Noise floors: 99th percentile of each feature in train CTRL windows (design §7.4) |
| C7-4 | `COV_MIN` (largest ≤ 0.99 keeping ≥ 99 % of train measurements usable), `N_BASE_MIN` likewise, `SEG_MIN` (1st percentile of TCP segment rate in train CTRL) |
| C7-5 | `KFREE_REASONS_LOSS` = {`QDISC_DROP`, `TC_INGRESS`} |
| C7-6 | Fractions just above 1 stay a documented limitation (as M-4) |
| C7-7 | Softirq parameters: smallest value with zero firings on all train windows |
| C7-8 | `IMPACT_MIN` (≤ 1 % of train CTRL windows), `DOM_RATIO` (train macro-F1 over {1.25, 1.5, 2, 3}), `τ_ML` (selective risk ≤ 10 % over train folds), `τ_DISAGREE` (same approach) |
| C7-9 | Calibration on train single-fault and CTRL runs; ML training adds train overlap runs except OV-7; SENS and PI-3 never used; test untouched before the lock |
| C7-10 | Baseline 45 s ending at fault onset (AMD-6); three 24 s windows from onset + 16 s (AMD-8); run decision = mode, ties to INS |

**M7 revisions (owner reply "1A, 2A, 3A, 4A", 2026-10-14)**, after a calibration dry run on the train split (no test
data read, no calibration artefact committed). Train run-level result of the dry run: CTRL 10/10, contention 8/8,
loss 7/8, retransmissions 3/8, memory 1/8, application 0/8, throttling 0/8.

| Item | Decision |
|---|---|
| C7-11 | Contract revision: CT.R2 judges `throttle.ratio` as an absolute bounded value (no baseline gate); the deviation stays on `throttle.time_rate`. In FaultLab the quota starts at onset, so the ratio has no baseline and CT.R2 was MISSING in every window |
| C7-12 | `APP_WAIT_MIN`, `APP_SHARE_MIN`: false positives against train CTRL windows only (waits rise under every fault) |
| C7-13 | Memory pressure without latency impact abstains by contract; accepted as a finding, recall reported as it comes out |
| C7-14 | Thin retransmission signal at the weakest levels accepted as recorded under R-4 |

**M7 revisions (owner reply "1B, 2A", 2026-10-14)**, after the contract revision (`afce9c2`, `6a0f2bd`) and a second
train-only dry run (scratch only, nothing committed; train macro-F1 0.70; two thresholds at 0 with no negatives).

| Item | Decision |
|---|---|
| C7-15 | AMD-31 left `src/sentinelai/runtime/pipeline.py` and `src/sentinelai/runtime/replay.py` out of the `test_integrity` allowlist. History is preserved; this record is the approved parent of a minimal follow-up amendment (AMD-31b) adding exactly those two paths |
| C7-16 | A class threshold with no negative windows (dry run: `THR_RATIO_MIN`, `APP_SHARE_MIN`) = 1st percentile (nearest rank) of its own-class train windows; percentile, undefined values and ties defined in the objectives before re-running; train only; a threshold that stays 0 or leaves its clause effectively unconditional stops calibration for review |

**M7 revisions (owner decisions 1–4, 2026-10-14)**, after a training-only investigation of the third dry run
(scratch only; no test, SENS or PI-3 run read).

| Item | Decision |
|---|---|
| C7-17 | `THR_RATIO_MIN` = 0.5, declared engineering value (not calibrated): train ratio is 1.0 in every tick and 0 without a binding quota, so the objective cannot discriminate; 0.99 satisfies the ratio clause, 0.0 does not |
| C7-18 | `APP_SHARE_MIN` = 0.5 (C7-16) accepted; histogram quantisation and no cross-class discrimination documented |
| C7-19 | C7-12 kept; five train retransmission→application run errors and the rate-limiting limitation recorded; no contract v0.7.0 before M8 |
| C7-20 | D-6 recorded as a finding (thread-summed run delay vs per-cgroup throttled time; OV-7 PR-3 caveat); per-thread revision deferred |
| C7-21 | M8 authorised (owner, 2026-10-14) against the lock `afdde9a`; AMD-32 admits exactly `experiments/faultlab/m8.py`, `tests/faultlab/test_m8.py`, `docs/PHASE_1C_M8_*.md` and add-only `datasets/faultlab/v1/m8/evaluation.json`; protocol interpretations committed before any test outcome is read |

Still pending after §5:

- No Freeze-1 parameter decision.
- Design-level items: U-1, U-1b, U-7 and U-6 were decided in R-7. Still open in the pilot design (§10) and outside this
  record: U-4 (PI-3 third quota level), U-5 (M3A-only ablation) and U-8 (G-R2 traceability, before any G-R2 claim).

## Appendix A. AMD-1 … AMD-17 (Stage 3H text, verbatim; adopted by the owner's approval of `FZ-AMD-01` … `FZ-AMD-17`, `4b6041c`)

Source: the Stage 3H design-amendment report of 2026-10-11, reproduced without change. Status in that report:
"PROPOSED, not approved".

**AMD-1: register the softirq waiver.** Prerequisite of AMD-2 to AMD-5.
> "`softirq_overload` test, train, SENS and OOD runs, and OV-11, are removed from the matrix on the basis of R2-E (NOT FEASIBLE). Softirq remains in the contract and the rules, and is disclosed as not validated in FaultLab."

Source: draft decision 4.

**AMD-2: G-Q1′.**
> "Run-level macro F1 ≥ 0.80 over 7 outcomes (6 evaluated fault classes + INS), test split. Valid only if each of the 7 has ≥ 10 verified test runs. A `softirq_overload` prediction counts as an error against the run's true class, and the number of such predictions is reported. The registered 8-outcome G-Q1 is reported and marked not gate-valid."

**AMD-3: G-Q2′.**
> "Recall ≥ 0.70 for each of the 6 evaluated fault classes, with the Wilson lower bound reported alongside (not a pass condition). `softirq_overload` recall: NOT EVALUABLE. It is never scored as 0 and never as passed."

**AMD-4: population B′ (U-7).**
> "G-Q1′, G-Q2′ and G-Q4 use all verified test-split runs except OV-7. OV-7, whose ground truth is an acceptable set, is scored only under §7.2 robustness. G-Q3 uses all verified INS-expected test runs (unchanged)."

**AMD-5: Q-5 provisioning.**
> "Single-fault test seeds per evaluated class: I1 4, I2 4, I3 4. CTRL test 14. Train unchanged. Seeds come from the matrix master seed and are disjoint from train and from the pilot range 900000–909999. Failed runs are excluded and counted, **never replaced**."

**AMD-6: FaultLab baseline placement** (`EVIDENCE_CONTRACT.md` §5).
> "In FaultLab, the within-run baseline is [fault_start − B, fault_start). Incident windows start at fault_start + T_TRANS. The default outside FaultLab is unchanged."

The schema already permits the gap (`models.py:237, 404` **V**).

**AMD-7: W and B** (contract §6 W/B row).
> "B = 45 s (the registered baseline phase). W = ⌊(90 − T_TRANS)/3⌋ s. This replaces 'Pilot: shortest windows giving a stable baseline MAD'."

`c_B` is withdrawn.

**AMD-8: window rule** (design §4.3, §6.5).
> "Three tumbling windows [fault_start + T_TRANS + jW, fault_start + T_TRANS + (j+1)W), j = 0, 1, 2. The leftover L = (90 − T_TRANS) − 3W s at the end of the fault phase is labelled but forms no window and is not scored. Every window is scored; missing data is handled only by the existing COV_MIN / PARTIAL / MISSING / DATA_QUALITY rules. CTRL runs follow the identical schedule with no injection, and their windows are labelled INS. The run-level decision is the mode over the three windows; ties go to INS (as registered)."

**AMD-9: T_TRANS as a mechanism-only operational estimate.**
> "T_TRANS covers only the **fault mechanism**: injection → read-back (R) plus kernel/mechanism response (K). It does **not** cover workload queue response or the completion of in-flight requests.
>
> T_TRANS = ⌈max over evaluated classes c of (R̂_c + K_c)⌉ seconds, where:
> - **R̂_c** is the maximum read-back latency observed in pilot runs of class c (all intensities, I2 confirmation runs included), measured from the scheduled fault-start tick. **R̂_c is an observed estimate, not a physical bound**; tail events larger than R̂_c are possible. Runs whose read-back misses the first window start are excluded and counted (AMD-10).
> - **K_c** is the mechanism response from §1.1 below. A class without an accepted K_c contributes **T_fb**.
> - **T_cap** is a stop ceiling: if T_TRANS > T_cap, stop and request an owner decision. T_fb ≤ T_cap.
> - **T_TRANS, T_cap and T_fb are preregistered operational values. None of them guarantees that the mechanism, or the impact, has settled.**
>
> Report-only sensitivity: every run-level metric is recomputed from windows 2–3 only (ties → INS) and reported beside the primary result. It never replaces it."

### 1.1 Status of each K_c term

| Class | K_c | Status |
|---|---|---|
| Throttling | ≤ one CFS period, read back from `cpu.max`; requires `cpu.max.burst` = 0 by read-back | INF from kernel semantics; value comes from read-back |
| Contention | Sharing begins once all k workers are runnable (activation read-back) | **INF only.** There is no measured bound on scheduler latency |
| Local / path loss | netem acts on the next packet (sub-tick) | INF from netem semantics |
| Congestion | Queue at R fills in limit / (input rate − rate) | Depends on declared parameters (OPEN) |
| Memory | One working-set cycle = WS_file / scan rate | Depends on the workload (OPEN); otherwise T_fb |
| Application | Workload control-file poll period + one request | Depends on the workload (OPEN); otherwise T_fb |

**AMD-10: injection timing and exclusion.**
> "All fault and distractor actions are issued without blocking, in a fixed declared order (faults, then distractors), after tick 60 is collected and before tick 61 is sampled. The issue and read-back timestamps are recorded on one host monotonic clock. An action timestamp earlier than tick 60, an issue error, a partial injection, or a read-back after fault_start + T_TRANS ⇒ `failed_injection`: excluded, counted, no retry."

The fixed issue slot follows the R2-D `WindowClock` precedent **V**.

**AMD-11: per-family OV timing** (§6.4). Faults and distractors run from 60 s to 150 s, issued per AMD-10. Exceptions:
- **OV-8 and OV-9:** collectors / app metrics are disabled for the **whole run**, from tick 0.
- **OV-5:** generator per AMD-15.
- **OV-7:** quota action first, then competitor.
- **The competitor is activated at 60 s and is not pre-staged.** CTRL construction is unchanged.

**AMD-12: memory (PI-5).** §6.3 is unchanged (`memory.max`).
- **Draft PI-5 rewritten:**
  > "Independent variable: `memory.max` at the preregistered candidate M levels. Criterion (registered): PSI memory > CTRL range without `oom_kill`, plus the draft's quantified form."
- **The draft's effect-verification row (l.389)** reads back `memory.max`.
- **AMD-12b (contingent fallback, approved in advance):**
  > "If no candidate M meets PI-5, the memory class switches to `memory.high = H`, `memory.max = H + headroom`, and PI-5 is re-run once within a preregistered run budget. Memory intensity levels are frozen only after the final PI-5 verdict. Evidence under one mechanism is never cited as validating the other."

**AMD-13: PI-8, OV-4 and I2.**
> "**OV-4 is producible if,** in each of n_r reps at the preregistered OV-4 level: (a) iperf3 sender- and receiver-reported pps are within τ of the target; (b) receiver-reported loss = 0; (c) the flood processes are alive throughout [60, 150) by read-back; (d) the flood CPUs are disjoint from A's cpuset by read-back; (e) the host-safety gates hold.
>
> **I2 confirmation:** after I1 and I3 are frozen, I2 (the geometric mean in injection units) is run in n_I2 preregistered reps. If I2 fails injection verification, the preregistered tie-break selects the next candidate magnitude toward a declared direction, for at most N_att attempts. After that the class follows the PI-8 stop rule."

**AMD-14: I3 safety ceilings** (draft l.546: "within the safety limits").
> "Preregistered ceilings: loss p (local and path), police rate floor, congestion rate floor and limit ceiling, contention k, quota floor, memory M floor (> WS_anon) and the lab cap, application P′ / lock-hold / delay ceilings, OV-4 pps."

**ρ band (INF):** no longer needed for T_TRANS under AMD-9. Retain it only if you want I1–I3 kept away from saturation for other reasons.

**AMD-15: contingent removals and OV-5 (F1).**
> "**OV-5 generator:** A `memory.max` = M, `memory.high` unset, swap 0. A fresh file is written and `fsync`ed in A's cgroup after tick 60. `mincore` residency of that file is recorded continuously at 1 Hz. The file is deleted at teardown and the absence of scratch is verified.
>
> **Feasibility (F1, judged after T_TRANS and W are frozen):** fill complete by fault_start + T_TRANS; residency ≥ r* at the end of every scored window; `memory.events` high = max = oom_kill deltas 0; refault, reclaim and PSI within the CTRL range (labelled non-independent); MemAvailable ≥ 4 GiB throughout.
>
> **Removal:** OV-5 is removed if any F1 criterion fails; OV-4 is removed if any AMD-13 OV-4 criterion fails. Removal is applied before matrix generation, and the gate counts are recomputed (§3)."

**AMD-16: G-C1 observation rule.**
> "A calibration observation is a scored window from a verified, non-SENS, non-OOD test run that has finite raw and calibrated probability vectors summing to 1 over the trained classes and one reference label in that set. Gated, DATA_QUALITY and near-empty-vector windows are included, and their counts are reported. OV-7, aborted runs and windows with no snapshot are excluded and counted. The threshold of 200 is unchanged."

**AMD-17: raw data.**
> "Raw data is staged at a persistent path outside the repository (**not `/tmp`**). It is committed to `datasets/faultlab/v1/raw/<run_id>/` only with manifest verification. Raw files are append-only, and the manifest is a superset of every earlier version. The dataset version is the manifest hash, which is also recorded outside the repository."
