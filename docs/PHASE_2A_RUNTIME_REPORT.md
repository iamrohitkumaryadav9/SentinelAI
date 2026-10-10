# Phase 2A — Runtime Integration Report (2A.1–2A.6)

| | |
|---|---|
| Scope | Integrate the validated Phase 1C components (M1 contract, M2 rules, M3A collectors; M3B parsed only) into one read-only, reproducible runtime: incident context → acquisition → ticks → snapshot → M2 → DiagnosisRecord → write-once artifact store, with offline replay and verification |
| Base | `5dad133` (README commit; code identical to R2-F closeout `0bb1fc6`) |
| Closeout | Phase 2A.6, two commits: (1) runtime source and tests, byte-identical to the source that ran the live acquisition, plus integrity-test maintenance; (2) live-run evidence and provenance, this report, status, README and the corpus-test correction |
| Diagnostic authority | M2 only. No LLM, agent, remediation or new diagnostic rule was added |
| Verdict | **Phase 2A CLOSED.** 2A.1–2A.4 PASS (accepted per closeout); 2A.5 first live acquisition PASS (bounded gate); 2A.6 closeout committed locally in `d119618` and `d6b9333` (not pushed); runtime tests 153/153; documented regression 1,026/1,028 with two known environmental failures (§8) |

## 1. Design decisions

The Phase 2A design review (GO) was delivered in the review session and is summarised here; it was not committed as a
separate document.

- **Q1:** the runtime's default eBPF mode is `required` (the validated configuration is M3A + M3B eBPF). In 2A.4 live
  acquisition refuses `required` explicitly; live runs pass `--ebpf disabled` and are reported as outside the
  validated configuration. Nothing is silently downgraded.
- **Q2:** the default parameter set is `r2c-validation-uncalibrated` (the set used by R2-C, R2-D and R2-F).
- **Q3:** `EvidenceSnapshot.incident_id` stays `None` in v1; the incident identity lives in `context.json`.
- **Forward-only windows:** collection observes B then W from the moment it starts; there is no retrospective mode.

## 2. Phase 2A.1 — pure runtime core

`src/sentinelai/runtime/`: `context.py` (strict `IncidentContext`), `registry.py` (the exact parameter set as literals
with a pinned SHA-256, `880d9af6…07cb`, equal to `scripts/r2c_driver.params()`), `ticks.py` (lossless typed tick
format: bit-exact floats including NaN payloads and `-0.0`, int vs str keys, dict order, `Bad` states), `store.py`
(write-once `ArtifactStore`: O_EXCL | O_NOFOLLOW, registered artifact names only, manifest last), `events.py`
(append-only runtime events, never part of an identity), `report.py` (`DiagnosisRecord`, evidence breakdown,
validated-configuration flag, `Report`), `pipeline.py` (snapshot → M2 → record → artifacts).

**Diagnosis identity:** `diagnosis_id` = SHA-1 (16 hex) of canonical JSON over the input-snapshot SHA-256, the
parameter-set SHA-256, the rules version and the contract version. Wall time, run key, incident ID, events and
`code_commit` are excluded (`code_commit` is recorded beside it).

## 3. Phase 2A.2 — snapshot replay and verification

`runtime/replay.py` and `src/sentinelai/__main__.py`: `verify --run-dir` (manifest, hashes, missing/extra/unregistered
files, completeness) and `replay --run-dir` (re-reads every artifact against the manifest, rebuilds the
`DiagnosisRecord` through M2 and requires byte-identical `diagnosis.json`; a matching diagnosis ID alone is never
success). Invalid input is refused with a category and exit code; it is never turned into an abstention.

**Historical corpus gate:** 68 committed snapshots discovered. 58 replayable R2-C/R2-D/R2-F snapshots reproduce their
recorded M2 output exactly (the drivers' own projections). Excluded with reasons: 7 R2-B snapshots (parameter set
`r2b-validation-uncalibrated` not registered) and 3 M3A smoke snapshots (not FaultLab; no run record).

## 4. Phase 2A.3 — raw-tick replay

`runtime/acquisition.py` defines `acquisition.json` (resolved target, eBPF flag, period, parameter set, tick count and
SHA-256, per-source `Bad` counts, collector versions). `replay --source ticks` decodes `ticks.jsonl`, rebuilds the
snapshot with the unchanged M3A/M3B `build_snapshot`, requires it byte-identical to `snapshot.json`, then runs the
diagnosis comparison. No committed run contained tick streams (the FaultLab drivers never persisted M3A ticks), so
coverage is synthetic M3A worlds (abstention, `memory_pressure`, `network_packet_loss`, `tcp_retransmissions`, with and
without injected faults) plus 70 committed eBPF loader streams combined with the synthetic M3A world (2 M3B-R1 streams
excluded: 63 samples against a 21-tick window).

## 5. Phase 2A.4 — live read-only M3A acquisition

`runtime/live.py` (`acquire`, `run_live`) and `python -m sentinelai diagnose`. Host access is exactly the existing M3A
collectors through `LiveReader` (reads under `/proc` and `/sys`). Refused before any read: `--ebpf required` and
`--iface` (the qdisc source would run the `tc` command, a subprocess). Outcomes: COMPLETE (exit 0) and PARTIAL (exit
11) proceed through the unchanged snapshot and M2 path; FAILED (exit 3) persists an `AcquisitionFailure` record and an
incomplete run with no snapshot and no diagnosis. Tested with injected readers only.

## 6. Phase 2A.5 — first live acquisition (bounded gate)

One authorised run, unprivileged (`iiitd`, uid 1000), against `/system.slice/cron.service` (PID 833,
`/usr/sbin/cron -f -P`), `--ebpf disabled`, no interfaces, `--code-commit 5dad133`.

| Item | Result |
|---|---|
| Exit / acquisition | 11 / PARTIAL (21 ticks, 20.0 s) |
| Diagnosis | `INSUFFICIENT_EVIDENCE` (`REQUIRED_EVIDENCE_MISSING`), LOW, `IMPACT_NOT_MEASURED`; validated configuration: false (no eBPF) |
| `bad_counts` | `cg.cpu.max` absent ×21 and `cg.memory` absent ×21 (unlimited quotas encoded as `Bad(ABSENT)`), `netns` unverified ×21 (namespace readlink denied for a root process); exactly as preflighted |
| Verification | `verify` exit 0; `replay --source ticks` and `--source snapshot` both MATCH with every check true |
| Host | identical before/after in every checked dimension; BPF program state **unverified** (needs root) |

Evidence: `results/phase2a_live/first-live-cron/20261010T145311197997Z-ce8b40286fb96bc5/` (byte-identical copy of
the original run directory, which is kept unchanged outside the repository) and
`results/phase2a_live/first-live-cron/PROVENANCE.json`. The run's `code_commit` (`5dad133`) is the committed base only:
the runtime that executed was uncommitted. `PROVENANCE.json` binds the run to the exact runtime source by SHA-256 and
git blob ID of all 22 runtime source and test files; commit `d119618` contains exactly those blobs (verified 22/22).

This is evidence for the M3A-only plumbing on an idle target. It is not evidence of live diagnostic accuracy.

## 7. Verification summary

| Item | Result |
|---|---|
| Runtime tests (`tests/runtime`) | 153/153 passed (post-commit, at `d6b9333`) |
| Documented regression (README "Usage"; `tests/test_phase1a.py` excluded) | Committed baseline `d6b9333`: 1,028 run, 1,026 passed, 2 known environmental failures (§8); not green. With the later status correction uncommitted: 1,025 passed, because `faultlab.test_r2e.TestStaticAndIntegrity.test_r2c_r2d_m2_m3a_m3b_contract_unchanged` rejects modified tracked files |
| Mutation campaigns | 2A.1 65/65, 2A.2 32/32, 2A.3 24/24, 2A.4 22/22 real mutants killed (no-op controls survived); gaps found by first passes were closed with targeted tests and re-run |
| Static safety | runtime modules: no subprocess, shell, signals, sockets, host writes, sysctl/cgroup/tc/swap strings; only `store.py` creates files; only `live.py` may import the M3A live entry points; eBPF entry points forbidden everywhere |

## 8. Phase 2A.6 closeout

- Live-run evidence copied (all 8 files SHA-256-identical; the original's full fingerprint unchanged) and re-verified
  offline from the repository copy: `verify` exit 0; both replay modes MATCH.
- Commits (local, not pushed), consecutive on `5dad133`:
  - `d11961852854dfe68ad8f7ab930789264b75cef5` (commit 1, 24 paths): runtime source and tests, integrity-test
    maintenance;
  - `d6b93333d3041417aece915a3004274b0ca0bee5` (commit 2, 13 paths): live-run evidence copy, `PROVENANCE.json`, this
    report, `PROJECT_STATUS.json`, README, corpus-test correction. No `src`, `ebpf`, `contract` or `scripts` change.
- Source binding: commit 1 contains all 22 runtime source and test files with exactly the git blob IDs recorded in
  `PROVENANCE.json` (verified 22/22), so commit 1's tree is the exact source of the live run. Commit 2 changes one of
  them, `tests/runtime/test_corpus.py` (test-only, never executed by `diagnose`); the change is recorded in
  `PROVENANCE.json` (`post_run_changes`).
- Corpus-test correction (commit 2): snapshots under `results/phase2a_live/` are classified `LIVE_RUN` and must verify
  and replay as MATCH from both ticks and snapshot. Without it, the committed live-run snapshot fell under the
  M3A-smoke rule (`NOT_FAULTLAB` with an unregistered parameter set) and failed. The smoke-snapshot assertions are
  unchanged.
- Integrity-test maintenance (authorised): `tests/faultlab/test_r2e.py` `test_candidate` accepts exactly the 2A.6 paths
  (`README.md`, `src/sentinelai/__main__.py`, `src/sentinelai/runtime/<name>.py`, `tests/runtime/<name>.py`,
  `docs/PHASE_2A_<NAME>.md`, `results/phase2a_live/…`); the `src`-unchanged assertions in `test_r2e.py`
  (`test_r2c_r2d_m2_m3a_m3b_contract_unchanged`, base `d11e755`) and `test_r2f.py` (`test_protected_files_unchanged`,
  base `4aa23b8`) accept exactly `src/sentinelai/__main__.py` and flat `src/sentinelai/runtime/<name>.py`; `ebpf/` and
  `contract/` stay fully pinned. The R2-F pin covers exactly three hunks of `test_r2e.py` (SHA-256 `305b525f…2dfe`).
- Post-commit verification: the committed evidence copy verifies (exit 0) and replays as MATCH from both ticks and
  snapshot; all 8 artifacts match their `PROVENANCE.json` hashes; the original run directory is unchanged.
- Test results after both commits: runtime suite 153/153 passed. Documented regression: 1,028 run, 1,026 passed, 2
  failed. The two failures are the known environmental ones (R2-C's exact root-controller preflight against the
  post-reboot controller set), kept unchanged rather than weakened:
  - `faultlab.test_r2c.TestDryRun.test_dry_run_mutates_nothing`
  - `faultlab.test_r2d.TestMatrixAndStatic.test_dry_run_mutates_nothing`
- Scope boundaries unchanged by the closeout: live acquisition is M3A-only; the idle cron run establishes no live
  diagnostic accuracy; BPF program/attachment state for the live run is unverified (needs root).

## 9. Incidents and external events during Phase 2A (disclosed)

- 2A.1: a verification clone symlinked the real `ebpf/build`, and its build test rebuilt the artifacts through the
  link. Restored with `make -C ebpf clean all` from the real sources; the loader again reports libbpf 1.4 and the build
  test passes. No clone has symlinked a build directory since.
- 2A.4: the repository was fast-forwarded to two README commits made by the project owner on GitHub (`f932768`,
  `6d404c8`); this caused the R2-E `test_candidate` failure resolved in 2A.6.
- 2A.2: NetworkManager received a DHCPv6 lease on `enp0s31f6` (two `fd31:…` addresses) from the LAN; not caused by
  SentinelAI.
- Every eBPF-test run of `make -C ebpf all` rewrites `ebpf/build/min_core.btf` with identical content (mtime only).

## 10. Limitations

- Live acquisition is M3A-only: eBPF and interface/qdisc sources are refused, so live runs are outside the validated
  configuration. Live eBPF mode and live interface collection need separate designs and approval.
- Only one live run exists: an idle service with no fault. No live diagnostic-accuracy claim is made.
- Cgroups with unlimited `cpu.max` / `memory.max` always produce PARTIAL acquisitions (structural `Bad(ABSENT)`), so a
  PARTIAL status must be read with its `bad_counts`.
- No historical tick corpus; tick replay is proven on synthetic and hybrid streams and on the one live run.
- The registry holds one parameter set; R2-B snapshots are not replayable until `r2b-validation-uncalibrated` is
  registered.
- `--code-commit` must be supplied by the operator (reading git would need a subprocess); there is no packaging
  (`PYTHONPATH=src`).
- BPF program/attachment state was not verified for the live run (needs root).
- Thresholds remain uncalibrated engineering values; M2 confidence remains capped at MEDIUM without application metrics.
