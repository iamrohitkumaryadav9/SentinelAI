# Phase 1C M7 contract revision v0.6.0-draft

Status: **implemented, unvalidated.** Owner decision 1A (FZ-M7-PLAN revision C7-11, recorded in `e6dc3e9`); integrity
amendment AMD-31 (`afce9c2`). No test-split run has been read. This revision changes what the engine requires of a
throttling diagnosis; it validates nothing by itself.

## 1. Why

The train-only calibration dry run (objectives §2, before any artefact was committed) asserted `cpu_throttling` in
0 of 8 train runs. The cause was in the contract, not the data. CT.R2 of v0.5.0 was the conjunction
`ABS(throttle.ratio, THR_RATIO_MIN) ∧ DEV(throttle.time_rate)` inside a baseline-using clause, so the ratio needed an
adequate baseline. In FaultLab the quota is applied at fault onset: before onset the target has no quota, no
throttling periods and so no ratio, which means no baseline can exist. CT.R2 was MISSING in every throttling window.

`throttle.ratio` (throttled periods / periods) is a bounded fraction with a fixed meaning. It needs no baseline.

## 2. Change

| Clause | v0.5.0-draft | v0.6.0-draft |
|---|---|---|
| CT.R1 | `throttle.quota_limited` | unchanged |
| CT.R2 | `ABS(throttle.ratio, THR_RATIO_MIN) ∧ DEV(throttle.time_rate)`, baseline | `DEV(throttle.time_rate)`, baseline |
| CT.R3 | — | `ABS(throttle.ratio, THR_RATIO_MIN)`, required, **no baseline** |

The decision text (C7-11) describes one CT.R2 that judges the ratio without a baseline gate while the deviation stays
on `throttle.time_rate`. The contract records `uses_baseline` per clause, so a clause that is half baselined cannot be
declared honestly. It is therefore implemented as two required clauses. Their conjunction is exactly the decided
condition.

`cpu_throttling` requires CT.R1, CT.R2 and CT.R3. Nothing else changes:
- The registry, predicates and parameters are identical apart from the version string.
- Every other clause is byte-identical.
- The measurement layer (features, ids, collectors) is unchanged.

These are tested in `tests/evidence/test_revision_v060.py`. Rules are `m2-1.2.0`.

## 3. Version-pinned evaluation

Evidence recorded before this revision (R2 campaigns, M2 records, the M5 pilot, the M6 dataset snapshots) carries
`contract_version 0.5.0-draft`. It is never re-read under the new clauses:

- `src/sentinelai/diagnostic/contract/data/archive/0.5.0-draft/` holds the four v0.5.0 data files verbatim (equal to
  their blobs at `e6dc3e9`; add-only under AMD-31).
- `catalog.contract_version(v)` evaluates under the current contract or a version listed in `MEASUREMENT_IDENTICAL`
  (only `0.5.0-draft`). Any other version is refused.
- `rules.diagnose` evaluates a snapshot under the contract it records: for 0.5.0 that means the archived files and the
  verbatim v0.5.0 CT.R2 (`ct_r2_v050`), and its record names rules `m2-1.1.0` (`RULES_BY_CONTRACT`).
- `collectors.build_snapshot(contract_version=…)` and the replays (`runtime/replay.py`, `experiments/faultlab/pilot.py`)
  rebuild a persisted snapshot under the version it recorded, so every committed snapshot still replays
  byte-identically.
- Replay refuses a stored record whose (contract, rules) pair this code does not carry, or whose snapshot records a
  different contract (`PARAMETERS_REFUSED`). It checks the pair before parsing, because a record is parsed under its
  own contract.

Every historical M2 output is reproduced exactly under 0.5.0 (`tests/runtime/test_record.py`,
`tests/runtime/test_replay.py`, the R2 suites).

## 4. Validated configuration

`runtime/report.py` `VALIDATED` is unchanged (rules `m2-1.1.0`, contract `0.5.0-draft`). A snapshot built today
under 0.6.0 is therefore reported as **not validated**, with exactly two reasons: rules m2-1.2.0 and contract
0.6.0-draft differ from the validated pair. This is correct until a campaign validates 0.6.0; M8 is that campaign.

## 5. Checks

- Full suite: 1550 tests. Before the commits, only the three integrity checks failed, each because the working tree
  held uncommitted changes.
- Mutations, each killed by at least one test:
  1. CT.R3 made baseline-gated.
  2. The 0.5.0 evaluator table removed.
  3. 0.5.0 mapped to rules m2-1.2.0.
  4. The replay version gate removed.
  5. The builder's version gate removed.
- Calibration consequence: under v0.5.0 the floor set included `throttle.ratio` (a DEV feature). Under v0.6.0 it does
  not, so a parameter set calibrated for 0.6.0 cannot evaluate 0.5.0 evidence. The engine refuses it as uncalibrated
  (tested), rather than evaluating with a missing floor.
