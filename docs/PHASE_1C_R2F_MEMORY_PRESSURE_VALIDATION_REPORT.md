# Phase 1C — R2-F Memory Pressure — Final Validation

| | |
|---|---|
| Gate | **R2-F RUNTIME VALIDATION: PASS** — **R2-F CLOSED** |
| Authoritative run | `results/phase1c_r2f/20261004T100422Z/` (2026-10-04 10:04:22 UTC), executed by the user: `cd /home/iiitd/sentinelai && sudo bash scripts/r2f_validate.sh`; calibration feasible, 12/12 evidence runs OK, no aborts |
| Executions | **12 evidence runs + 1 calibration = 13 total executions** |
| Code under test | HEAD `4aa23b8` plus the R2-F tooling: `scripts/r2f_memory.py`, `scripts/r2f_driver.py`, `scripts/r2f_target.py`, `scripts/r2f_validate.sh`, `tests/faultlab/test_r2f.py`; loader `sentinel_loader` m3b-1.0.0 linked to libbpf 1.4 |
| Evidence fingerprint | `475f64dcbffeddfe8c32eff310f295798abc65b5cf4bb4f4c9278e6ca1d52b21` (sha256 over the sorted per-file sha256 list of the run directory; 193 files) |
| Pre-runtime gate | PASS — root evidence `/tmp/r2f_gate_20261004T095947Z` (not part of the repository) |

## Verdict

**PASS.**

## Validated scope

SentinelAI's deterministic evidence-first diagnosis pipeline has been validated under controlled FaultLab
conditions for cgroup memory.high file-backed page-cache refault pressure.

The diagnosis was made through MP.R1's reclaim-and-refault path. This is not a validation of Linux memory pressure in
general (see Limitations).

## 1. Phase boundary

R2-F validates the observation pipeline (M3A, M3B) and M2 against controlled memory pressure only. No change to M1,
M2, M3A, M3B, the evidence contract, thresholds, precedence rules or labels. Not performed: anonymous-memory pressure,
swap-driven pressure, OOM, PSI-threshold exercise, severity estimation, mitigation.

## 2. Design (approved with conditions 1–12; unchanged at runtime)

- **Lab:** `/sys/fs/cgroup/sentinel-r2f/{target,contender}`, controllers `cpuset cpu memory pids`, CPU 18 only,
  `cpu.max` = `max` everywhere.
- **Memory controls:** `memory.swap.max` = 0 on parent, target and contender. Target `memory.high` = H,
  `memory.max` = H + 128 MiB. Parent `memory.max` = 1792 MiB; contender `memory.max` = 64 MiB. Every control was
  written read-before `max` / read-after exact, verified, and only then could the target start. No memory write was
  possible after any spawn.
- **Workload** (`scripts/r2f_target.py`; uid 1000, private netns, CPU 18; one process, one thread):
  - creates a 1 GiB file in its own cgroup on ext4 `/var/tmp/sentinel-r2f/<TS>-<label>/`;
  - maps it with `MADV_RANDOM` and touches one byte per page;
  - scans 256 MiB, or 1 GiB after exactly one SIGUSR1 sent at window start (M1, M2, N1).
- **H:** M1 768 MiB, M2 512 MiB; E0, N1, N2 and calibration 1536 MiB.
- **Matrix:** calibration, E0-open, M1 ×3, M2 ×3, N1 ×2, N2 ×2 (R2-C E2 contender, weight 400, on CPU 18), E0-close.
- **Independent ground truth:**
  - Predicates GP, GC, GD, GM, GI, GL, GCPU, GT, GN and GH, plus GR.
  - Computed by a pure `evaluate()` over saved raw kernel-file inputs; never from M2 and never "MP.R1 became TRUE".
  - Memory pressure requires GP, GC, GD, GM, GCPU, GT, GN, GL and GH, plus GI for M2.
- **Safety thresholds (frozen provenance):**
  - Host MemAvailable ≥ 4 GiB and slice memory/io PSI rise ≤ 0.01: design-derived (the latter is the R2-C
    `SLICE_PSI_RISE_MAX` analogue).
  - Host swap I/O ≤ 25 pages/s: previously validated in R2-C and R2-D.
  - Any lab or host OOM: abort (OOM is never an accepted outcome).
- **Cleanup order:** kill → verify termination → verify the controls this run wrote → loader close → BPF release →
  scratch file → cgroups → host comparison.

## 3. Pre-runtime corrections

- **Preflight controller check (authorised):** the R2-F preflight compared the root `cgroup.subtree_control` for exact
  equality with R2-C's `ROOT_SUBTREE`. After a host reboot the root had `cpuset cpu io memory pids`, so the check blocked
  the runtime. It now requires `REQUIRED_ROOT_CONTROLLERS = {cpuset, cpu, memory, pids}` ⊆ root controllers. Empty,
  unreadable, malformed, duplicate or multi-line input fails. R2-C is unchanged.
- **Verification after the correction:**
  - R2-F tests 63/63; mutation campaign 84/84 real mutants killed (16 target the new check); no-op control survives.
  - Dry-run passes.
  - R2-F verification regression 875/875 (see Limitation 7).

## 3a. Closeout integrity-test maintenance (authorised; no experimental change)

Committing R2-F after R2-E made two existing live-repository integrity tests mutually inconsistent. A rehearsal commit
in a scratch clone showed `test_r2e.py::test_candidate` failing. Both changes are test-only; no R2-E or R2-F
implementation, threshold or evidence was changed:

- `tests/faultlab/test_r2e.py`, `test_candidate` only: besides the R2-E closeout paths, it now also accepts exactly the
  R2-F closeout paths (`scripts/r2f_<name>.py|.sh`, `tests/faultlab/test_r2f.py`, `docs/PHASE_1C_R2F_<NAME>.md`,
  `results/phase1c_r2f/`). Any other later-phase path still fails.
- `tests/faultlab/test_r2f.py`, `test_protected_files_unchanged` only: `test_r2e.py` must equal `4aa23b8`, or `4aa23b8`
  plus exactly those two hunks (also pinned by sha256 `621f10e9…`). It now also requires `results/phase1c_r2b`–`r2e` to
  be unchanged and free of untracked files. The rest of `test_r2f.py` is byte-identical to the runtime version
  (`b9d71bbd…`).

Negative checks in the clone fail as required:
- an extra edit to `test_r2e.py`;
- an altered authorised hunk;
- an R2-E implementation edit;
- an R2-E tracked result edit;
- an untracked file in R2-E results;
- an unrelated later-phase file (R2-E `test_candidate`).

Restoring `test_r2e.py` to `4aa23b8` passes. After the change: R2-F 63/63; mutation 84/84; verification regression on
the rehearsed commit 875/875 (`test_phase1a.py` excluded).

## 4. Results (authoritative run `20261004T100422Z`)

Calibration (E0 configuration, provenance only): **feasible**.
- Ready 1.11 s after file creation; 39 observations after ready.
- Cached cycle median 158.2 µs, lateness median 289.8 µs, p99 425.6 µs; 0 missed of 3722 cycles.
- Steady refault rate 0.0; MemAvailable min 12.52 GiB.

Window values (W = 10 s after the signal; B = the preceding 10 s):

| Run | H (MiB) | Ground truth established | Refault/s W | Majflt/s W | pgscan W | `high` events | memory.current max (MiB) | GI cycle-median ratio W/B | missed W | psi.mem.some.target | CPU 18 idle W | M2 | Confidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| E0-open | 1536 | memory pressure absent | 0 | 0 | 0 | 0 | 1060 | 1.01 | 0 | 0.0000 | 0.974 | INSUFFICIENT_EVIDENCE | LOW |
| M1-1 | 768 | memory pressure | 46408 | 46419 | 460992 | 16163 | 768 | 44.20 | 2 | 0.0211 | 0.631 | memory_pressure | MEDIUM |
| M1-2 | 768 | memory pressure | 46321 | 46348 | 460096 | 16154 | 768 | 45.65 | 2 | 0.0211 | 0.632 | memory_pressure | MEDIUM |
| M1-3 | 768 | memory pressure | 46278 | 46302 | 459776 | 16144 | 768 | 46.34 | 2 | 0.0209 | 0.638 | memory_pressure | MEDIUM |
| M2-1 | 512 | memory pressure (GI held) | 46648 | 46674 | 465216 | 16876 | 512 | 45.21 | 2 | 0.0215 | 0.637 | memory_pressure | MEDIUM |
| M2-2 | 512 | memory pressure (GI held) | 46523 | 46539 | 464000 | 16855 | 512 | 43.36 | 2 | 0.0213 | 0.639 | memory_pressure | MEDIUM |
| M2-3 | 512 | memory pressure (GI held) | 46315 | 46324 | 461760 | 16827 | 512 | 45.01 | 2 | 0.0212 | 0.642 | memory_pressure | MEDIUM |
| N1-1 | 1536 | memory pressure absent | 0 | 0 | 0 | 0 | 1062 | 1.10 | 0 | 0.0000 | 0.971 | INSUFFICIENT_EVIDENCE | LOW |
| N1-2 | 1536 | memory pressure absent | 0 | 0 | 0 | 0 | 1062 | 1.02 | 0 | 0.0000 | 0.972 | INSUFFICIENT_EVIDENCE | LOW |
| N2-1 | 1536 | CPU contention present; memory pressure absent | 0 | 0 | 0 | 0 | 1060 | 0.68 | 0 | 0.0000 | 0.001 | cpu_contention | MEDIUM |
| N2-2 | 1536 | CPU contention present; memory pressure absent | 0 | 0 | 0 | 0 | 1060 | 0.70 | 0 | 0.0000 | 0.001 | cpu_contention | MEDIUM |
| E0-close | 1536 | memory pressure absent | 0 | 0 | 0 | 0 | 1060 | 1.00 | 0 | 0.0000 | 0.974 | INSUFFICIENT_EVIDENCE | LOW |

Ground truth and M2 agree in all 12 evidence runs; there is no disagreement to record.

### M1 (H = 768 MiB, scan expanded to 1 GiB)
- Independent ground truth established 3/3 (all predicates true; GI computed but not required for M1).
- M2 `memory_pressure` 3/3, confidence MEDIUM, flag `IMPACT_NOT_MEASURED`.
- Path: MP.R1 through reclaim-and-refault (DEV ∧ reclaim ≥ RECLAIM_MIN ∧ DEV refault/majfault). The PSI path was not
  required and not met.
- Supporting evidence: `mem.events.high`, `psi.mem.full.target`.

### M2 (H = 512 MiB, scan expanded to 1 GiB)
- Independent ground truth established 3/3, GI held (cycle median 43.4–45.2× baseline; 2 missed deadlines in W).
- M2 `memory_pressure` 3/3, confidence MEDIUM, `IMPACT_NOT_MEASURED`.
- Path: the same reclaim-and-refault path.

### N1 (high memory usage without pressure; H = 1536 MiB, scan expanded to 1 GiB)
- Ground truth: memory pressure absent 2/2. Resident about 1062 MiB (69 % of H); refault, reclaim, major faults and
  memory PSI all 0.
- M2 INSUFFICIENT_EVIDENCE 2/2 (MP.R1 NEGATIVE). Zero `memory_pressure` false positives.

### N2 (R2-C E2 CPU contender on CPU 18)
- Ground truth: CPU contention present (CPU 18 idle 0.001) and memory pressure absent, 2/2.
- M2 `cpu_contention` 2/2 (CC.R1 and CC.R2 met). Zero `memory_pressure` false positives.

### E0-open / E0-close
- Ground truth: memory pressure absent. M2 INSUFFICIENT_EVIDENCE (`REQUIRED_EVIDENCE_MISSING`).
- `application_bottleneck` appears as SUPPORTED_NOT_SUFFICIENT in E0 and N1 because application metrics are not
  collected; it was never asserted.

## 5. Safety

| Check | Result (all 13 executions) |
|---|---|
| Host MemAvailable (≥ 4 GiB) | min 12.51 GiB |
| Host OOM | `oom_kill` delta 0 |
| Lab OOM | `oom` / `oom_kill` 0 in parent, target, contender; `memory.max` events 0 |
| Global reclaim | `pgscan_kswapd` delta 0 |
| Host swap I/O (≤ 25 pages/s) | 0 pages/s; `/swapfile` 0 used throughout |
| Lab swap | `memory.swap.max` = 0 written and read back on all 3 cgroups in every run; `memory.swap.current` 0 at every observation |
| Slice memory/io PSI rise (≤ 0.01) | max 0.0014 |
| Placement (GP) | 0 violations; target on CPU 18 throughout |
| Throttling (GT) | `cpu.max` unlimited; 0 throttled periods |
| Network/softirq (GN) | lab netns quiet; NET_RX on CPU 18 ≈ 0 |
| Foreign CPU on CPU 18 (GCPU) | ≤ 0.012 cores |

No safety abort occurred.

## 6. Cleanup and host integrity

- All 13 executions followed the registered order: terminated → controls_verified → bpf_released (about 0.1 s) →
  scratch_deleted → cgroups_removed. No cleanup errors.
- Wrapper final cleanup: no lab cgroup, process, wrapper or scratch.
- Per-run driver and wrapper host comparisons, and the final comparison, are all OK. As root they include BPF
  programs, maps and links, `vm.*` settings, RPS, scratch and the R2-F lab.
- The host-wide `workingset_refault_file` rise (0 → 6.28 M) is the lab's own refaults reflected in the global counter;
  `pgscan_kswapd` stayed 0.

## 7. Reproducibility

- Evidence directory `results/phase1c_r2f/20261004T100422Z/`; fingerprint `475f64dcbffeddfe…` (full value above);
  runtime commit `4aa23b8`; loader libbpf 1.4.
- Offline ground-truth reproduction (`r2f_memory.py evaluate`) is identical for all 12 evidence runs; GR is reproduced.
- M2 did not mutate any snapshot (`snapshot_unchanged_by_m2` true in all 12); snapshot rebuilds are identical.
- Repeated runs cluster tightly: refault rates within 0.8 % across the six M runs; signal expansion at cycle 2010–2017
  (M) and 2089–2100 (N1).
- Tooling limitation: `r2f_memory.py evaluate` expects a ground-truth window and therefore does not directly evaluate
  the calibration directory (KeyError `window`). This is a tooling limitation, not a runtime failure; it is not fixed
  in this closeout.

## 8. Limitations

1. **No graded severity.** M1 and M2 did not produce meaningfully different observed pressure severity: both showed
   about 46k refaults/s and about a 45× cycle-time increase. Scanning 1 GiB cyclically against any cache limit below
   1 GiB makes nearly every touch miss. This campaign does not demonstrate that M2 caused greater observed severity
   than M1.
2. **PSI path untested.** M2 diagnosed through the reclaim-and-refault path. `psi.mem.some.target` was about 0.021,
   below the registered 0.2 PSI floor. The runtime did not validate PSI-based memory-pressure detection.
3. **OOM path untested.** OOM was intentionally prohibited by the registered safety design.
4. **Narrow pressure mechanism.** Validated: cgroup `memory.high` + file-backed page-cache pressure + reclaim/refault
   thrashing. Not validated: anonymous memory, swap-driven pressure, OOM pressure.
5. **Confidence.** M2 confidence remained MEDIUM, and impact was not measured (`IMPACT_NOT_MEASURED`; no
   application metrics).
6. **Generalisation.** One host (Precision 3660), Ubuntu 22.04, kernel 6.8.0-138 (MGLRU on, zswap off), one
   registered campaign. No cross-host or cross-kernel claim.
7. **Regression scope.** The R2-F verification regression intentionally excluded `tests/test_phase1a.py` (24 tests:
   TestDocker 3, TestEBPF 5, TestGit 3, TestPython 6, TestSystemTools 7). That test performs host/Docker environment
   mutation: its `docker run --rm hello-world` restored root cgroup controllers and gave `docker0` an IPv6 link-local
   address. Result: 899 discovered, 24 excluded, 875 run, 875 passed.
8. **Host baseline.** The host was rebooted after R2-E (boot 2026-10-04 14:12 IST). Swap was 0 used (about 94 % used
   before the reboot). Root controllers had been restored by Docker to `cpuset cpu io memory hugetlb pids rdma misc`.
   This post-reboot state was treated as the R2-F baseline and was not normalised back to the R2-E state.

Also observed: E0 and N1 hold the same resident memory (about 1060 MiB, since file creation charges the whole 1 GiB to
the target). N1 differs from E0 in its active scan range (1 GiB vs 256 MiB), not in resident size.

## 9. Claim boundary

May be stated: **"Validated memory-pressure diagnosis under controlled FaultLab conditions"** — for cgroup
`memory.high` file-backed page-cache refault pressure, using the reclaim-and-refault diagnostic path.

Not claimed: autonomous memory-pressure remediation, production-ready memory diagnosis, PSI validation,
anonymous-memory validation, swap-pressure validation, OOM validation, severity estimation, or general Linux
memory-pressure validation.
