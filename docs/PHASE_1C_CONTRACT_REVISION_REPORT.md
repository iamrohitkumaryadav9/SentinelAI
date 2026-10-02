# Phase 1C — Contract Revision Report: v0.2.0-draft

| Field | Value |
|---|---|
| Date | 2026-10-02 |
| Scope | Contract revision and M1 schema follow-up **only** (no M2) |
| Decision record | `docs/PHASE_1C_PRE_M2_AUDIT.md` (R-1 … R-5), approved by the reviewer, who also chose the version number |
| Commit | Single commit `feat(contract): revise evidence contract to v0.2.0-draft`. A commit cannot contain its own hash; the hash is in the handover message and `git log`. |
| Gate | **PASS WITH CONDITIONS** (§16) |

## 1. Previous version
Contract **0.1.0-draft**, schema **0.1.0**: M1, commit `33aed1b`.

## 2. New version
Contract **0.2.0-draft**, schema **0.2.0**.
- **Version constants.** `version.py`, plus `contract_version` in all four `data/*.json` files.
- **Semver handling** is unchanged: same-major contract versions are accepted.
- **Old snapshots.** Any `schema_version ≠ "0.2.0"` is rejected, so a 0.1.0 snapshot is not silently accepted. There is no migration machinery.
- **Governance.** §12 classifies R-1 as a major change. The reviewer chose `0.2.0-draft` for this pre-release correction, and that is recorded in `EVIDENCE_CONTRACT.md` §12.

## 3. R-1: unlimited CPU quota
- **`Unit.boolean`.** A measurement value must be exactly `0.0` or `1.0`, or null with MISSING/INVALID. `-1`, `0.5`, `2`, NaN and inf are rejected.
- **New feature `throttle.quota_limited`:**
  - family `cpu_throttling`, scope cgroup, `GAUGE`, source `CGROUPFS`, unit `boolean`;
  - locator `cpu.max`: `max` → 0.0, `<quota> <period>` → 1.0.
- **`throttle.quota_cores`** is redefined as "emitted only when a finite quota exists". The contract no longer says "(null)". An unlimited quota is never a null, sentinel, MISSING or INVALID value.
- **CT.R1** now reads `throttle.quota_limited` ("`throttle.quota_limited == 1`", `uses_baseline = false`). The contract text gives the outcomes: 1 → POSITIVE, 0 → NEGATIVE, unreadable `cpu.max` → MISSING. That is **metadata only; nothing is evaluated.**
- **Consistency rule Q1** (snapshot-level schema check, not a decision): `quota_limited = 0` and a non-null `quota_cores` for the same scope are rejected.

## 4. R-2: `mem.reclaim.target`
- **Changed:** the registry locator is now exactly `cgroup memory.stat Δ(pgscan)`, and the description says pgsteal is not part of the feature. The contract §4.6 row says the same.
- **Unchanged:** the ID, unit, aggregation and source; MP.R1 (verified by test).
- **Not added:** no pgsteal feature, no combined value, no ratio.

## 5. R-3: qualified measurements
- **`Qualifier`** = {`dimension`, `value`}. It is strict and frozen, and both fields are non-empty.
- **Registry `DimensionSpec`** = {`name`, `pattern` | `values`}, exactly one of the two:
  - `net.drop.kfree_skb` → `reason`, pattern `^[A-Z0-9_]+$`;
  - `app.events` → `code`, closed set {`POOL_EXHAUSTED`, `QUEUE_FULL`, `LOCK_WAIT_EXCEEDED`, `DEPENDENCY_TIMEOUT`}.
  - No other feature declares a dimension.
- **`Measurement.qualifier`:**
  - **required** iff the feature declares a dimension;
  - the dimension must match, and the value must satisfy the pattern or closed set;
  - **forbidden** otherwise;
  - a total `kfree_skb` / `app.events` measurement is therefore not representable.
- **`MissingMeasurement.qualifier`** follows the same rules.
- **Identity:**
  - `measurement_id(feature_id, scope, window, qualifier=None)`: the qualifier is part of identity when present, and the key is omitted when absent;
  - snapshot uniqueness is by `measurement_id`;
  - the missing-measurement identity is (`feature_id`, `scope`, `qualifier`).
- **Serialisation:** a null `qualifier` is omitted from `Measurement` and `MissingMeasurement` output, so unqualified objects serialise byte-identically to 0.1.0 (§12).

## 6. R-4: parameter typing and τ_DISAGREE
- **Typed parameters.** `parameters.json` entries are now `{name, type}` with type `number` or `reason_set`.
  - `KFREE_REASONS_LOSS` is `reason_set`; every other parameter, including the per-feature `floor`, is `number`.
  - There are still **no values**, and the status is `UNCALIBRATED`.
- **`Threshold.parameter`** must be a known **`number`** parameter. `Threshold(parameter="KFREE_REASONS_LOSS", value=3.0)` is now rejected.
- **`τ_DISAGREE`** has been added as a symbolic `number` parameter with no value. It is in contract §6 with its design §5.4 meaning.

## 7. R-5: diagnostic flags
- **`DiagnosticFlag`** = {`IMPACT_NOT_MEASURED`, `ML_DISAGREEMENT`}.
- **`DiagnosticResult.flags`:**
  - `Tuple[DiagnosticFlag, ...] = ()`, with duplicates **rejected**;
  - canonical serialisation sorts it, so flag order cannot change bytes.
- **Invariants:**
  - **F1:** `IMPACT_NOT_MEASURED` ⇒ `confidence_level ≠ HIGH`;
  - **F2:** `ML_DISAGREEMENT` ⇒ `ml` is present ∧ `ml.agrees_with_rules = false`.
- **Not included:** flags are not abstention reasons (I1 unchanged) and not part of `EngineInfo`. Nothing computes ML disagreement or uses `τ_DISAGREE`.

## 8. Files changed

| File | Change |
|---|---|
| `src/…/contract/version.py` | Versions 0.2.0 / 0.2.0-draft |
| `src/…/contract/enums.py` | `Unit.boolean`, `DiagnosticFlag` |
| `src/…/contract/catalog.py` | `DimensionSpec`; `FeatureSpec.dimension`; `ParameterSpec`; typed `ParameterCatalog`; `parameter_type()` (replaces `is_parameter()`) |
| `src/…/contract/ids.py` | Qualifier-aware `measurement_id` (unqualified encoding unchanged) |
| `src/…/contract/models.py` | `Qualifier`; qualifier validation and serialisation; boolean values; typed `Threshold`; `MissingMeasurement.qualifier`; Q1; `DiagnosticResult.flags` with F1/F2 |
| `src/…/contract/__init__.py` | Exports `Qualifier`, `DiagnosticFlag` |
| `src/…/contract/data/registry.json` | +`throttle.quota_limited`; `quota_cores` and `mem.reclaim.target` text; `dimension` on every feature (null except two) |
| `src/…/contract/data/labels.json` | CT.R1 features and definition |
| `src/…/contract/data/parameters.json` | Typed entries; +`τ_DISAGREE` |
| `src/…/contract/data/predicates.json` | Version only |
| `tests/evidence/_builders.py` | v0.2.0 versions; qualifier support |
| `tests/evidence/test_{schema,registry,snapshot,invariants}.py` | Updated for v0.2.0 (see §9) |
| `tests/evidence/test_revision_v020.py` | **New:** 34 revision tests |
| `docs/EVIDENCE_CONTRACT.md` | v0.2.0-draft (revision history, §4.2/4.3/4.6/4.7, §6, §8.2, §10.1/10.3/10.5/10.6/10.7, §12) |
| `docs/PHASE_1C_M1_REPORT.md` | A revision note only |
| `docs/PHASE_1C_PRE_M2_AUDIT.md` | Committed unchanged (the decision record) |
| `docs/PHASE_1C_CONTRACT_REVISION_REPORT.md` | This report |

`experiments/faultlab/` is **not** included.

## 9. Tests

| Suite | Ran | Passed | Failed | Skipped |
|---|---|---|---|---|
| Evidence (`tests/evidence/`) | **180** | **180** | 0 | 0 |
| Complete repository | **204** | **203** | 0 | **1** (pre-existing Phase 1A root-only bpftrace attach) |

**New tests:** `test_revision_v020.py`, 34 tests:
- R-1 (7);
- R-2 (2);
- R-3 (12);
- R-4 and τ_DISAGREE (3);
- R-5 (7);
- backward compatibility (3).

**Updated existing tests.** 7 tests encoded 0.1.0 facts that the revision deliberately changes. They were updated **without weakening** any assertion:

| Test | What changed |
|---|---|
| version and contract strings | Now expect 0.2.0 |
| Unit enum set | Now includes `boolean`; the expected `DiagnosticFlag` set was added |
| contract feature list | Includes `throttle.quota_limited` |
| parameter catalog check | Now requires `{name, type}`, with no value field |
| snapshot version test | Now asserts that a **0.1.0** snapshot is rejected, and that 0.3.0 is rejected |
| an I6 test | Builds CT.R1 evidence from `throttle.quota_limited` |

**Test fix during the revision.** One new test initially passed vacuously (the builder auto-declared the missing measurement), so it was rewritten to bypass the auto-fill.

**Mutation check:** 20 validators were disabled one at a time, and **all 20 were caught**. They were:
- **all 13 new checks:** boolean values, Q1, qualifier forbidden/required/dimension/value, qualifier in ID, null-qualifier omission, missing-measurement identity, Threshold type, F1, F2, flag duplicates;
- **7 re-verified M1 checks:** I1, I3, null value, E1, the clause check, the ground-truth source, the templated rationale.

## 10. Invariant status (I1–I7, plus the new rules)

| Invariant | Status | Evidence |
|---|---|---|
| I1 | **PASS** | `TestI1`; `test_flags_do_not_affect_I1` |
| I2 | **PASS** | `TestI2I4` (unchanged) |
| I3 | **PASS** | Item- and candidate-level tests (unchanged) |
| I4 | **PASS** | Structural and cross-object tests (unchanged) |
| I5 | **PASS** | Registry agreement now includes the qualifier/dimension |
| I6 | **PASS** | `TestI6ApplicationBottleneck` (unchanged) |
| I7 | **PASS** | `test_determinism` (13) plus qualified round trip and flag-order tests |
| Q1, F1, F2, U1 (new) | **PASS** | `test_revision_v020` |

## 11. Determinism status
**PASS.**
- Repeated serialisation is byte-identical; so are independent and reordered constructions.
- The JSON round trip is stable, including for qualified measurements.
- Flag order does not change bytes.
- There are no uuid/random/time/now() calls (AST check).
- The qualifier is part of identity deterministically.

## 12. Backward compatibility of unqualified measurement IDs
**PASS.** These reference values were recorded from the **unmodified M1 code** (`33aed1b`) before any change, and `TestBackwardCompatibility` asserts them:

| Object | M1 value | v0.2.0 value |
|---|---|---|
| `measurement_id(cpu.util.host, host, W)` | `f5655a2e95cd366b` | identical |
| `measurement_id(net.drop.kfree_skb, netns:A, W)` (the bare ID function) | `532a853e8f355a90` | identical |
| `measurement_id(app.events, app:A, W)` | `c8c23d8b4047fb0e` | identical |
| `net.drop.qdisc` measurement ID | `4cc0294063ca4300` | identical |
| …its canonical bytes (SHA-256) | `5b9ad19d…dadf8a2` | identical (no `qualifier` key) |
| Evidence item ID | `7ea0ace8a99788e2` | identical |
| Snapshot ID | `4766881871d86cda` | identical |

Same feature, scope and window with qualifier A, with qualifier B, and unqualified produce **three different IDs** (tested). The "omit null qualifier" serialiser is what preserves snapshot IDs: its mutation was caught by the byte test.

## 13. Scope audit
- **Keyword search** over every added line in `src/` and `tests/` (665 lines) for rule, evaluate, classify, decide, faultlab, ebpf, prometheus, kubernetes, ollama, rag, mcp, agent:
  - **0 whole-word hits;**
  - the only substring hits are the existing M1 fields `agrees_with_rules` and `rules_version`.
- **New numeric literals** in contract code and data are only version strings, a `§10.3` reference, and the structural boolean values `0.0`/`1.0` that R-1 requires. **No threshold was introduced.**
- **No M2+ functionality:** no predicate evaluation, precedence logic, classifier, ML, calibration, collector, eBPF, network change or LLM call.

## 14. FaultLab untouched
`experiments/faultlab/` was not read for modification, built, executed, staged, committed or deleted. It remains untracked.

## 15. Deviations
**None** against R-1 … R-5. Two observations, not deviations:
- **O-1 (housekeeping).** `docs/PHASE_1C_DESIGN.md` still names its normative companion as "EVIDENCE_CONTRACT.md v0.1.0-draft" (header table). The design document is outside this revision's permitted changes, so it was left as is.
- **O-2.** The design also references `τ_ML` (design §5.3, the ML abstention threshold), which is not in the parameter registry. It was not added, because only `τ_DISAGREE` was approved. M7 needs it.

## 16. Final gate

**PASS WITH CONDITIONS**

All PASS criteria hold:
- v0.2.0-draft is internally consistent: the document and the implementation were cross-checked mechanically (features, parameters, units, flags, CT.R1);
- R-1 … R-5 are implemented;
- I1–I7 are preserved;
- the tests and determinism checks pass;
- unqualified IDs are backward-identical;
- there is no M2+ functionality and FaultLab is untouched;
- there is one commit, and the working tree holds only the untracked FaultLab directory.

The conditions are documentation and housekeeping only:
1. Update the design document's companion-version reference (O-1) in a later authorised change.
2. Add `τ_ML` to the parameter registry before M7 (O-2).
