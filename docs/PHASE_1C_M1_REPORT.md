# Phase 1C — M1 Report: Evidence Contract + Pydantic Schema

| Field | Value |
|---|---|
| Milestone | M1: evidence contract and schema layer **only** |
| Date | 2026-10-02 |
| Source of truth | `docs/EVIDENCE_CONTRACT.md` v0.1.0-draft, `docs/PHASE_1C_DESIGN.md` |
| Commit | The single M1 commit (`feat(contract): implement phase1c evidence contract`). A commit cannot contain its own hash; the hash is reported in the handover message and by `git log`. |
| Gate | **PASS WITH CONDITIONS** (§12) |

> **Revision note (v0.2.0-draft).** Contract deviations D-1 … D-4 (§6) and gate condition 1 were resolved by the pre-M2 audit (`docs/PHASE_1C_PRE_M2_AUDIT.md`) and the contract revision `0.2.0-draft` (`docs/PHASE_1C_CONTRACT_REVISION_REPORT.md`). This report is otherwise kept as the M1 record (contract 0.1.0-draft, schema 0.1.0).

## 1. Objective

Implement a versioned, strict, deterministic Python representation of the Phase 1C evidence contract: the feature registry, enumerations, strict Pydantic v2 models, invariants I1–I7, deterministic IDs, canonical serialisation and missing-data semantics, with a comprehensive unit test suite.

No rule engine, classifier, collector, FaultLab, ML or LLM component is part of M1.

## 2. Files changed (all new; no existing file modified)

| Path | Purpose |
|---|---|
| `src/sentinelai/__init__.py`, `src/sentinelai/diagnostic/__init__.py` | Package roots |
| `src/sentinelai/diagnostic/contract/__init__.py` | Public API of the contract layer |
| `…/contract/version.py` | `SCHEMA_VERSION = "0.1.0"`, `CONTRACT_VERSION = "0.1.0-draft"`, semver parse, major-version compatibility check |
| `…/contract/enums.py` | All contract enumerations (§10.1) |
| `…/contract/catalog.py` | Strict models and loader for the registry, label clauses, predicates and parameters; predicate-ID grammar; rationale templates; `ContractViolation` |
| `…/contract/models.py` | Window, BaselineStat, Deviation, Provenance, Measurement, Threshold, EvidenceItem, Target, MissingMeasurement, Conflict, DataQuality, EvidenceSnapshot, Candidate, MLAdvisory, EngineInfo, DiagnosticResult |
| `…/contract/validate.py` | `validate_against_snapshot(result, snapshot)`: cross-object invariants I2–I6 |
| `…/contract/ids.py` | Deterministic IDs (measurement, evidence item, snapshot, inputs hash) |
| `…/contract/serialize.py` | Canonical JSON and bytes |
| `…/contract/data/registry.json` | 66 features (contract §4), each with its original unit text |
| `…/contract/data/labels.json` | 16 clauses (Required and Contradictory) as **metadata**; 6 precedence rules as **data, not evaluated** |
| `…/contract/data/predicates.json` | Primitive predicates and the rationale template |
| `…/contract/data/parameters.json` | 28 **symbolic** parameter names; status `UNCALIBRATED`; **no values** |
| `tests/evidence/__init__.py`, `_builders.py`, `test_*.py` (9 files) | M1 test suite (146 tests) |
| `docs/PHASE_1C_M1_REPORT.md` | This report |

No dependencies were added. The contract uses Pydantic 2.13.5 from the existing `.venv` plus the standard library; `requirements.lock` is unchanged.

## 3. Contract implemented

- **Enumerations, values exactly as in the contract:**
  - `Label` (8; `FAULT_LABELS` = the 7 fault mechanisms);
  - `EvidenceKind`, `Strength`, `Quality`, `SourceType` (including future-only `PROMETHEUS`), `Aggregation`, `Unit` (13);
  - `CandidateStatus`, `ConfidenceLevel` (ordinal, not a probability), `AbstentionReason` (7, §8.8), `BaselineMethod`;
  - the registry codes `Availability` and `ScopeKind`.
- **Models.**
  - All use `ConfigDict(extra="forbid", frozen=True, strict=True)`. `strict=True` adds no semantics: it only refuses silent coercion such as `"10"` → `10.0`.
  - Collections are tuples (immutable). Floats are finite. Timestamps are UTC with millisecond precision.
- **Registry.**
  - Unique IDs; valid unit, aggregation, source and scope kinds; contract version recorded.
  - Unknown feature IDs are rejected (`ContractViolation('I5')`).
  - Derived features declare their inputs. Privileged exactly for eBPF features. No feature can have the ground-truth source.
- **Invariants.**
  - I1, plus the structural parts of I2 and I4, are enforced in `DiagnosticResult` and `Candidate`.
  - I3 and I5 are enforced in `EvidenceItem`, `Measurement` and `EvidenceSnapshot`.
  - I2–I6 in full (claims backed by snapshot evidence) are enforced by `validate_against_snapshot`.
  - I7 is canonical serialisation.
- **Deterministic IDs:**
  - `measurement_id`, `item_id` and `snapshot_id` are recomputed and **enforced** in validators, so a fabricated ID is rejected;
  - the encoding is `sha1(canonical_json({"kind": …, named inputs}))[:16]`;
  - `inputs_hash` is SHA-256 of the canonical measurements.
- **Serialisation.** Sorted keys, compact separators, UTF-8, no NaN or inf, shortest round-trip float `repr`, `-0.0` → `0.0`, enums by value, timestamps as `YYYY-MM-DDTHH:MM:SS.mmmZ`, arrays treated as sets and sorted.
- **Versioning:**
  - `schema_version` must be exactly `"0.1.0"`;
  - a `contract_version` with a different **major** version is rejected;
  - minor and patch differences are accepted (contract §12);
  - there is no migration machinery.
- **Rationale:** an `EvidenceItem.rationale` must equal the contract template rendered from the item's own fields. Free text, including LLM text, is rejected.

### Clarifications made to implement the contract

These resolve underspecified points. None changes the contract's meaning.

| # | Point | Resolution |
|---|---|---|
| C-1 | ID byte encoding (§10.3–10.5 name the inputs, not the bytes) | Canonical JSON of a **named-key** object |
| C-2 | Array order | All contract arrays are sets; the canonical form sorts them |
| C-3 | "UTC RFC 3339 with milliseconds" | Non-UTC offsets and sub-millisecond precision are **rejected**, not normalised |
| C-4 | Window of a measurement | Must equal the snapshot window. Within-run baselines must equal `baseline_window`. |
| C-5 | `Quality.OK` coverage | OK requires coverage = 1.0; PARTIAL requires 0 < coverage < 1. `COV_MIN` stays symbolic and is not checked. |
| C-6 | Predicate-ID syntax | `CLAUSE[/PRIMITIVE][[arg]]` or `PRIMITIVE[[arg]]`; arg = feature ID, named set, or `family:<name>` |
| C-7 | `Conflict.rule` for pairs absent from §9 | `null` |
| C-8 | Result structure | When decision ≠ INSUFFICIENT_EVIDENCE, exactly one candidate (the decision) is ASSERTED. `contributing` = the CONTRIBUTING candidates. An abstention has no contributing labels. |
| C-9 | Deviation | Numeric consistency with value, baseline and floor is enforced (contract §5 formulas), so a manufactured deviation is rejected |
| C-10 | Staleness | Enforced both ways: an old last sample must be STALE, and STALE must have an old last sample |
| C-11 | Clause-level evidence direction | A POSITIVE item of a Required clause lists its label in `supports`; one of a Contradictory clause lists it in `contradicts` |
| C-12 | Unit texts | The contract's free-text units are mapped to the `Unit` enum and recorded per feature in `contract_unit_text`. Examples: *throttled-cores* → `cores`, *segments* (cwnd) → `count`, *tasks* → `count`, *migrations/s* → `per_second`, *events (count in W)* → `count`. |

## 4. Tests (M1 suite)

`PYTHONNOUSERSITE=1 .venv/bin/python -m unittest discover -s tests/evidence -t tests`

| Total | Passed | Failed | Skipped |
|---|---|---|---|
| **146** | **146** | 0 | 0 |

| File | Tests | Category |
|---|---|---|
| `test_schema.py` | 25 | Window / timezone / duration / period; Target; Baseline; Provenance; exact enum values; versioning; unknown fields rejected for every model; frozen |
| `test_registry.py` | 15 | Registry equals the contract §4 feature list (transcribed independently); uniqueness; invalid unit, aggregation or source rejected; ground truth excluded; Required clauses equal contract §8; **no numeric threshold anywhere** |
| `test_measurement.py` | 27 | Registry agreement (unit, aggregation, scope, source, privileged); MISSING / INVALID / STALE / PARTIAL / insufficient coverage; counter reset; deviation consistency; baseline overlap; ground-truth source |
| `test_evidence_item.py` | 16 | Strength / missing_reason rules; I3; NEGATIVE never supports; INSUFFICIENT_EVIDENCE never supportable; templated rationale only; deterministic ID; predicate grammar; symbolic parameters |
| `test_snapshot.py` | 17 | I5 references; per-predicate feature restriction; E1 (no POSITIVE/NEGATIVE on MISSING / INVALID / STALE data); baseline required for deviation predicates; missing-measurement declaration; windows; versions; conflicts; derived inputs |
| `test_result.py` | 16 | I1; exactly 7 fault candidates; I2/I4 structural; contributing consistency; confidence ordinal (not a float); ML has no decision field; ML agreement honesty; EngineInfo |
| `test_invariants.py` | 11 | I2, I3, I4, I5 and **I6 (no `application_bottleneck` by elimination)** via `validate_against_snapshot` |
| `test_determinism.py` | 13 | ID known answer (independent encoding); positional-collision regression; order independence; A == B == C serialisation; JSON round trip byte-stable; `-0.0` and int/float canonicalisation; no nondeterministic sources (AST) |
| `test_boundaries.py` | 6 | Ground truth cannot enter a snapshot; ML advisory cannot set the decision; no LLM text as evidence; M1 scope (no decide/evaluate/classify functions, no numeric thresholds in code, no heavy or network imports) |

### Test-quality checks
- **Mutation testing.** 17 critical validators were disabled one at a time.
  - **16 were caught.**
  - **1 survived:** the explicit I6 check in `validate.py`. I6 is also guaranteed by two independently tested layers: AB.R1 items may only reference application-cause features (mutation caught), and an asserted `application_bottleneck` requires a POSITIVE AB.R1 item (mutation caught). The explicit I6 check is therefore defence-in-depth and cannot fail on its own; it is reported, not claimed as independent coverage.
- **A real defect found and fixed during M1.** The first ID implementation passed positional parts through the set-sorting canonicaliser, so swapping `feature_id` and `scope` could collide. The independent known-answer test caught it, and a regression test was added.
- **Test bugs found and fixed:** a naive `": "` check matched rationale text; a "uuid" text check matched a docstring; two invariant tests passed for the wrong reason until they were made to assert the specific violated clause (AB.R1, AB.R3).

## 5. Existing test suite

`PYTHONNOUSERSITE=1 .venv/bin/python -m unittest discover -s tests -t tests`

| Suite | Ran | Passed | Failed | Skipped |
|---|---|---|---|---|
| Phase 1A (`tests/test_phase1a.py`) | 24 | 23 | 0 | 1 |
| M1 (`tests/evidence/`) | 146 | 146 | 0 | 0 |
| **Complete repository** | **170** | **169** | **0** | **1** |

The skip is pre-existing (Phase 1A): the live bpftrace attach requires root (`unprivileged_bpf_disabled=2`). The Phase 1A suite itself runs `docker run --rm hello-world` (via `sg docker`), a 1 s `stress-ng` and a loopback `iperf3`. Those are existing tests, not M1 actions.

## 6. Contract deviations

The written contract has gaps and inconsistencies that M1 **could not implement exactly**. None was resolved by inventing semantics.

| # | Contract section | Issue | M1 behaviour | Needed |
|---|---|---|---|---|
| **D-1** | §4.2 vs §10.3 | §4.2 says an unlimited quota (`cpu.max` = `max`) is a **null** value. §10.3 says a null value occurs **only** for `MISSING`/`INVALID`. | §10.3 enforced strictly. An unlimited quota is **not representable** as a measurement, so CT.R1's "no finite quota" cannot be expressed as NEGATIVE evidence. | A contract decision, e.g. a separate boolean feature `throttle.quota_limited`, or an explicit `unlimited` value state |
| **D-2** | §4.6 `mem.reclaim.target` | One feature ID names two counters (Δ`pgscan`, Δ`pgsteal`) | Registered as the `pgscan` rate. `pgsteal` is not represented (noted in the registry locator). | Split into two feature IDs or define the combination |
| **D-3** | §4.3 `net.drop.kfree_skb`, §4.7 `app.events`, §8.4 | Values are "per reason" / "per code", and §8.4 filters `kfree_skb` by reason (`KFREE_REASONS_LOSS`), but the `Measurement` schema (§10.3) has **no dimension field** | These features are representable only as totals. Reason-qualified `kfree_skb` evidence cannot yet be expressed. | Add a dimension/qualifier to `Measurement` (minor version bump) |
| **D-4** | §7, design §5.4 | `IMPACT_NOT_MEASURED` ("recorded") and `ML_DISAGREEMENT` ("flag added") have **no field** in `DiagnosticResult` (§10.6) | Not implemented; no field was invented | Add a `flags` field or define where they are recorded |

## 7. Scope violations

**NONE.** Specifically:
- no predicate evaluation, rule engine, precedence evaluation, threshold value, classifier, calibration, collector, FaultLab, Docker workload, eBPF, Prometheus, Kubernetes, RAG, MCP, LLM or Ollama call;
- `labels.json` holds Required/Contradictory clause **metadata**, used only to check that a result's claims are backed by evidence. The precedence table is stored as data and **never evaluated**;
- `test_boundaries.TestM1Scope` asserts the absence of decision-making functions, numeric thresholds and heavy or network imports in the contract package.

## 8. Determinism verification

- **Test status:** `test_determinism.py` 13/13 PASS.
- **Covered:**
  - three serialisations of one snapshot are identical (`A == B == C`);
  - independent constructions, including a different input order, are byte-identical;
  - result serialisation is identical;
  - a JSON round trip is byte-stable;
  - the measurement-ID known answer matches an independent sha1 of the documented encoding;
  - swapping inputs does not collide;
  - no `uuid`/`random`/`time`/`now()` appears in the contract code (AST check).

## 9. Invariant verification

| Invariant | Enforcement | Tests | Status |
|---|---|---|---|
| I1 abstained ⇔ INSUFFICIENT_EVIDENCE ⇔ reasons ≠ ∅ | `DiagnosticResult` | `test_result.TestI1` | **PASS** |
| I2 decision backed by its Required evidence | Structural in `DiagnosticResult`; full in `validate_against_snapshot` | `test_result`, `test_invariants.TestI2I4` | **PASS** |
| I3 MISSING never in `supports` | `EvidenceItem`; candidate lists in `validate_against_snapshot` | `test_evidence_item`, `test_invariants.TestI3I5` | **PASS** |
| I4 ASSERTED/CONTRIBUTING only when Required satisfied | Structural in `Candidate`; full in `validate_against_snapshot` | `test_result`, `test_invariants` | **PASS** |
| I5 references resolve; feature_id and unit match registry | `Measurement`, `EvidenceSnapshot`, `validate_against_snapshot` | `test_measurement`, `test_snapshot`, `test_invariants` | **PASS** |
| I6 `application_bottleneck` needs positive app evidence (not `app.latency_ms`/`app.error_rate`) | AB.R1 feature restriction + AB.R1 requirement + explicit check | `test_invariants.TestI6ApplicationBottleneck` (4 tests) | **PASS** (explicit check redundant; see §4) |
| I7 byte-identical serialisation | `serialize.py`, deterministic IDs | `test_determinism` | **PASS** |

## 10. Security / safety review

| Item | Status |
|---|---|
| Root / sudo commands | None |
| Network or qdisc modifications | None. The physical NIC `enp0s31f6` was not touched. |
| Privileged containers | None. The contract code has no Docker usage; the Phase 1A suite's existing `hello-world` is unprivileged. |
| LLM invocation / Ollama | None |
| Cloud API / API keys / secrets | None |
| New dependencies | None |

## 11. Git state

- **Commit:** a single M1 commit `feat(contract): implement phase1c evidence contract`. The hash is in the handover message.
- **Working tree after commit:** clean **except** `experiments/faultlab/`. That directory is untracked, **pre-dates M1** (the Phase 1C feasibility probe) and is intentionally not part of this commit.

## 12. M1 gate

**PASS WITH CONDITIONS**

The implementation is fundamentally correct and every test passes (146/146 M1; 169/170 complete, with the 1 pre-existing root-only skip). Every invariant is implemented and tested, determinism is verified, and there are no scope or safety violations.

Conditions:
1. **Contract inconsistencies D-1 … D-4** (§6) need a contract decision (v0.1.1 or v0.2.0) **before M2**. D-1 (unlimited quota) and D-3 (`kfree_skb` reason dimension) bear directly on M2 adversarial tests ADV-1 and ADV-4.
2. **The working tree is not fully clean:** the pre-existing untracked `experiments/faultlab/` remains. It should be committed as its own change, or removed, by explicit decision.
3. **The explicit I6 check is redundant** (mutation survives); I6 rests on the two tested layers. This is documented here and not hidden.
