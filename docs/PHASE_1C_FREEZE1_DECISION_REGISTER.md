# Phase 1C Gate 1.1 — Freeze-1 Decision Register

**Status: PROPOSED / PENDING OWNER APPROVAL.** Nothing in this register is approved or frozen. Every value here is
either already registered in a committed document (cited) or a proposal awaiting a decision by Rohit Kumar. No value
in this file may be used by a privileged run until it is approved and frozen in `pilot_decisions.json` (draft §6.10).

- Repository state inspected: `8cff3b8` (main, local), read-only.
- The privileged lab pilot is **not authorised**.
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

## 3. Recommendations (P — not approved)

- Items 1, 2, 4, 5, 6: keep OPEN; decide U-2 first (recommend **A**, with rules registered before the pilot), then set
  `c_B`, `T_cap`, `T_fb` and the workload contract numerically; choose the AMD-9 T_TRANS form and retire `b` if so.
- Item 3: adopt the draft quantification with `memory.max` as primary mechanism.
- Item 7: U-6 **B** for pilot raw data (external archive under a persistent non-`/tmp` path, committed manifest);
  revisit A for M6.
- Items 9–10: approve the implemented manifest format and the unsigned Git + SHA-256 root of trust.
- Item 8: write the approved AMD texts into the design before any privileged run.

## 4. Approval boundary

This register freezes nothing. Freeze-1 requires, at minimum, owner decisions on: U-1, U-1b, U-2, U-3 (T_TRANS,
`T_cap`, `T_fb`, `b`/`c_B`), U-6, U-7, Q-1…Q-10, AMD-1…AMD-17, items 1–3b and 9–12 above. Committing this file
also requires an exact-path integrity amendment, because `tests/faultlab/test_r2e.py::test_candidate` accepts no
new `docs/` path of this name.
