# Phase 1C — G-R2 Adversarial Unit Evidence

| | |
|---|---|
| Project | SentinelAI. Owner and author: Rohit Kumar |
| Status | **G-R2: PASS (unit-level gate only)**, decided by Rohit Kumar on 2026-10-11 (§6). This verdict covers only the registered unit-level adversarial gate; it does not mean Phase 1C or FaultLab is complete. §3 and §4 are fresh runs (2026-10-11) in an isolated scratch clone of `0152b9b`. §3a is the primary-repository run (2026-10-11) of the approved, uncommitted integration. §3b is the primary-repository run on commit `f11a1f4` (local, not pushed). §3c is the primary-repository run with the three literal-fixture tests added, before they were committed |
| Provenance | A first version of this record and its tests (2026-10-10) was lost when the host rebooted and `/tmp` was cleared. This record and `tests/rules/test_design_adv.py` were rebuilt and re-run; they are new artifacts, not byte-identical copies of the lost files |
| Gate | G-R2 (PHASE_1C_DESIGN.md §7.5): "**All** adversarial tests ADV-1 … ADV-10 pass (unit level)". Critical: any failure fails Phase 1C |
| Registered requirements | The 12 rows of PHASE_1C_DESIGN.md §7.3 (ADV-1 … ADV-10, plus ADV-3b and ADV-8b), unit level ("U": hand-built `EvidenceSnapshot` fixtures in `tests/rules/`) |
| Interpretations applied | **D-1:** MP.R1 NEGATIVE is ADV-7's "NEGATIVE item"; an unmeasured OOM observation keeps MP.R1 MISSING. **D-1b:** the POSITIVE `ABS[mem.util.target]` supporting item (contract §8.6) is accepted and asserted; the `memory_pressure` candidate stays NOT_SUPPORTED. **D-2:** reason codes follow M2 report §7 (engine `engine.py:604–629`): `REQUIRED_EVIDENCE_MISSING` when the gate passes and families are missing; `DATA_QUALITY` when the gate fails. Recorded in PHASE_1C_DESIGN.md §13 (2026-10-11 entry, committed in `f11a1f4`) |

## 1. Numbering

`tests/rules/test_adversarial.py` implements the Phase 1C M2-prompt list (its line 1), which numbers cases differently
from §7.3 (for example, its ADV-4 is a CPU-backlog/softirq case, while §7.3 ADV-4 is throttling read as contention).
The mapping below is by behaviour. The historical tests are unchanged. The new tests are in
`tests/rules/test_design_adv.py`, one class per §7.3 ID. "Missing-OOM subcase" below is part of the registered ADV-7
row, not a separate §7.3 row.

## 2. Requirement-to-test mapping

| §7.3 | Requirement (expected behaviour) | Tests | Assertions that demonstrate it |
|---|---|---|---|
| ADV-1 | 3/s NOT_SPECIFIED kfree_skb at baseline, **all other drop sources 0** → not `network_packet_loss`; NEGATIVE or WEAK only; `NO_CANDIDATE` if nothing else | literal: `test_design_adv.TestDesignADV01KfreeNoiseAtBaseline.test_literal_fixture_all_other_drop_sources_zero`; derived: `.test_baseline_noise`; `test_adversarial.TestADV1KfreeNoise` (4 tests) | literal: all 8 registered drop sources present at 0 (incl. the three loss-qualifying kfree reasons) give 11 `PL.R1/LOSS.LOCAL[...]` items, all NEGATIVE, none citing the NOT_SPECIFIED measurement; `DEV[net.drop.kfree_skb]` NEGATIVE with no support; `RT.R2/LOSS.LOCAL` NEGATIVE; INS `[NO_CANDIDATE]`; packet loss NOT_SUPPORTED. 5000/s case: WEAK supporting only |
| ADV-2 | `tcp_retransmissions` asserted; RT.R1/RT.R2 as specified | `test_adversarial.TestADV3RetransWithNormalDrops.test_tcp_retransmissions`; `test_c1.TestC1B_RetransNormalLoss.test_tcp_asserted` | decision; ASSERTED with no missing required clause; `RT.R2/LOSS.LOCAL` NEGATIVE |
| ADV-3 | never `network_packet_loss` while LOSS.LOCAL is FALSE | same tests | packet loss NOT_SUPPORTED |
| ADV-3b | drop counters missing → INS `LOSS_VS_RETRANS_UNDECIDABLE` | `test_adversarial.TestADV2RetransWithoutDropCounters` (3 tests) | exact reason list; no "no drops" claim |
| ADV-4 | `cpu_throttling`; with excess run delay ≈ 0, `cpu_contention` NOT_SUPPORTED | `test_design_adv.TestDesignADV04PureThrottling.test_throttling_not_contention` | decision `cpu_throttling`, no reasons, no contributing; CT.R1/CT.R2 POSITIVE; CC.R1/CC.R2 NEGATIVE contradicting contention; CC.X1 POSITIVE supporting throttling and contradicting contention; contention NOT_SUPPORTED |
| ADV-5 | **`cpu.util.*` = 0.95**, run delay and throttling at baseline → neither CPU label; `NO_CANDIDATE` | literal: `test_design_adv.TestDesignADV05UtilisationAlone.test_literal_fixture_all_cpu_util_features`; derived: `.test_utilisation_alone` | literal: `cpu.util.host`, `cpu.util.cpuset` and `cpu.util.percpu` (cpu:2, cpu:3) all 0.95 and present in the snapshot; INS `[NO_CANDIDATE]`; both CPU labels NOT_SUPPORTED; CC.R2 POSITIVE, CC.R1 NEGATIVE, CT.R1 NEGATIVE |
| ADV-6 | weak softirq → not `softirq_overload`; INS if nothing else | `test_design_adv.TestDesignADV06WeakSoftirq.test_below_absolute_floor`, `.test_below_ratio` | both branches (value < `SI_ABS_MIN`; ratio < `SI_RATIO_MIN`): INS `[NO_CANDIDATE]`, SI.R1 NEGATIVE contradicting softirq, SI.R2 POSITIVE |
| ADV-7 | high memory usage → not `memory_pressure`; a NEGATIVE item | `test_design_adv.TestDesignADV07HighMemoryUsage.test_usage_is_not_pressure`; missing-OOM subcase `.test_missing_oom_stays_missing` | MP.R1 NEGATIVE contradicting memory_pressure; `ABS[mem.util.target]` POSITIVE and listed as supporting; candidate NOT_SUPPORTED; INS `[NO_CANDIDATE]`. Missing-OOM subcase: MP.R1 MISSING, nothing contradicts memory_pressure, SUPPORTED_NOT_SUFFICIENT, `[REQUIRED_EVIDENCE_MISSING]` |
| ADV-8 | never `application_bottleneck`; INS (`NO_CANDIDATE` or `REQUIRED_EVIDENCE_MISSING`) | `test_design_adv.TestDesignADV08NoEliminationToApplication` (2 tests); `test_adversarial.TestADV6NoInfraNoAppEvidence` (3 tests); `test_abstention.TestApplicationConfounders.test_confounder_not_evaluated` | normal world `[NO_CANDIDATE]`, NOT_SUPPORTED; all `app.*` absent: `[REQUIRED_EVIDENCE_MISSING]`, `IMPACT_NOT_MEASURED`, AB.R1 and AB.R2 missing, never asserted |
| ADV-8b | `application_bottleneck` with AB.R1–R3 satisfied | `test_adversarial.TestADV7PositiveAppEvidence.test_application_bottleneck`; `test_invariants.TestInvariantsAcrossScenarios.test_i6_application_needs_positive_app_evidence` | decision; POSITIVE non-latency `app.*` item |
| ADV-9 | INS `CONFLICT_UNRESOLVED`, both candidates listed: (a) throttling vs excess delay **of equal magnitude**; (b) softirq + qdisc drops (PR-2b) | (a) literal: `test_design_adv.TestDesignADV09ConflictEqualMagnitude.test_literal_fixture_equal_magnitude`; (a) derived (0.4 vs 0.3): `test_adversarial.TestADV9ThrottlingNoDominance.test_no_arbitrary_choice`; (b) `test_precedence.TestPR2.test_pr2b_non_softirq_drop` | (a) literal: `throttle.time_rate` = `sched.run_delay_excess.target` = 0.4; INS `[CONFLICT_UNRESOLVED]`; one conflict (contention, throttling), rule `PR-3`; both candidates ASSERTED with nothing missing; no contributing. (b) exact reason; conflict rule `PR-2b` |
| ADV-10 | impact high, all families MISSING → INS with the correct reason (D-2) | `test_design_adv.TestDesignADV10AllFamiliesMissing` (3 tests) | absent and MISSING-quality variants with the gate passing: `[REQUIRED_EVIDENCE_MISSING]`; gate failing: `[DATA_QUALITY]`; all 7 candidates NOT_EVALUABLE with nothing met; no contributing |

## 3. Execution results (fresh runs, scratch clone only)

Interpreter `/home/iiitd/sentinelai/.venv/bin/python`, environment `PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1`, run
from the clone's `tests/`; `sentinelai` was imported from the clone's own `src/` (checked).

| Command | Result | Exit |
|---|---|---|
| `-m unittest rules.test_design_adv -v` | 12 run, **OK** | 0 |
| `-m unittest discover -s rules -t .` | 109 run (97 existing + 12 new), **OK** | 0 |

These scratch-clone runs are not the primary regression; the primary-repository results are in §3a.

## 3a. Primary-repository results (2026-10-11, approved integration, uncommitted)

State: `/home/iiitd/sentinelai`, HEAD `0152b9b`, with the approved changes applied and **not committed**:
`docs/PHASE_1C_DESIGN.md` (§13 2026-10-11 entry appended), `tests/faultlab/test_r2e.py` (SHA-256
`3ab31610a4daaa7a04c94566e41c55d34e8524cbd47e0a609382451bc060f003`), `tests/faultlab/test_r2f.py` (matching hunk-2 text
and pin), and the new `tests/rules/test_design_adv.py` and this record. Commands run from `tests/` with
`PYTHONNOUSERSITE=1 ../.venv/bin/python`.

| Command | Result | Exit |
|---|---|---|
| `-m unittest rules.test_design_adv -v` | 12 run, **OK** | 0 |
| `-m unittest discover -s rules -t .` | 109 run, **OK** | 0 |
| `-m unittest faultlab.test_r2f.TestStaticAndIntegrity -v` | 7 run, **OK** (pinned-hunk check passes with the new pin) | 0 |
| `-m unittest faultlab.test_r2e.TestStaticAndIntegrity -v` | 8 run, **1 failure**: `test_r2c_r2d_m2_m3a_m3b_contract_unchanged` | 1 |
| Documented regression (README "Usage": `collectors ebpf evidence rules faultlab runtime`, `tests/test_phase1a.py` excluded) | **1,040 run: 1,037 passed, 3 failed, 0 errors; not green** | 1 |

Per package: collectors 111 OK; ebpf 114 OK; evidence 228 OK; rules 109 OK; faultlab 325 with 3 failures; runtime
153 OK.

Failures, each compared individually with the two previously known failures:

1. `faultlab.test_r2c.TestDryRun.test_dry_run_mutates_nothing` (`test_r2c.py:1155`, `structural_ok` False). The only
   failing preflight check is `preflight.checks.root_subtree_control` (root controllers `cpuset cpu io memory pids`, not
   R2-C's exact `ROOT_SUBTREE`), with the derived `preflight.ok` and `structural_ok`; `zero_mutation.ok` is True with no
   failed items; `bpf_compared` is False (BPF state not comparable unprivileged). **Same as the known environmental
   failure.**
2. `faultlab.test_r2d.TestMatrixAndStatic.test_dry_run_mutates_nothing` (`test_r2d.py:886`): identical failing checks.
   **Same as the known environmental failure.**
3. `faultlab.test_r2e.TestStaticAndIntegrity.test_r2c_r2d_m2_m3a_m3b_contract_unchanged` (`test_r2e.py:1617`):
   `git status --porcelain --untracked-files=no` lists `docs/PHASE_1C_DESIGN.md`, `tests/faultlab/test_r2e.py`,
   `tests/faultlab/test_r2f.py`. **Not one of the two known failures.** It is the test's clean-tracked-tree requirement,
   triggered by the uncommitted integration (and by the pre-existing uncommitted `docs/PHASE_1C_DESIGN.md` edit). Its
   `src`/`ebpf`/`contract` assertions (`test_r2e.py:1613–1616`) precede it and passed. It is expected to pass only once
   the changes are committed; that has not been verified.

`test_candidate` passed: it inspects committed history only, so the new allowlist has not yet been exercised against
a commit in the primary repository (it was exercised in the scratch rehearsal, C0 and N0–N7).

## 3b. Primary-repository results on commit `f11a1f4` (2026-10-11, local, not pushed)

Commit `f11a1f4d9729ad50ef3db5f8bbd01287e1959108` (parent `0152b9b`; author and committer Rohit Kumar) contains exactly
`docs/PHASE_1C_DESIGN.md`, `docs/PHASE_1C_G_R2_EVIDENCE.md` (the §3a version of this record),
`tests/faultlab/test_r2e.py` (SHA-256 `3ab31610a4daaa7a04c94566e41c55d34e8524cbd47e0a609382451bc060f003`),
`tests/faultlab/test_r2f.py` and `tests/rules/test_design_adv.py`. Before the run, `git status --porcelain
--untracked-files=no` was empty; `docs/PHASE_1C_M4_M5_PILOT_DESIGN.md` and `experiments/faultlab/` were untracked and
uncommitted.

| Command (from `tests/`, `PYTHONNOUSERSITE=1 ../.venv/bin/python`) | Result | Exit |
|---|---|---|
| Documented regression (README "Usage": `collectors ebpf evidence rules faultlab runtime`, `tests/test_phase1a.py` excluded) | **1,040 run: 1,038 passed, 2 failed, 0 errors; not green** | 1 |
| `-m unittest faultlab.test_r2e.TestStaticAndIntegrity -v` | 8 run, **OK** (`test_candidate` passes against committed history that includes the four allowlisted paths; `test_r2c_r2d_m2_m3a_m3b_contract_unchanged` passes) | 0 |
| `-m unittest faultlab.test_r2f.TestStaticAndIntegrity -v` | 7 run, **OK** (`test_protected_files_unchanged` passes with the new pin) | 0 |

Per package: collectors 111 OK; ebpf 114 OK; evidence 228 OK; rules 109 OK (including the 12 design-ID tests); faultlab
325 with 2 failures; runtime 153 OK.

Failures, each compared individually with the two previously known failures:

1. `faultlab.test_r2c.TestDryRun.test_dry_run_mutates_nothing` (`test_r2c.py:1155`): the False checks are
   `preflight.checks.root_subtree_control` (root controllers `cpuset cpu io memory pids`), the derived `preflight.ok` and
   `structural_ok`, and `zero_mutation.bpf_compared` (BPF state not comparable unprivileged); `zero_mutation.ok` is True
   with no failed items. **Same as the known environmental failure.**
2. `faultlab.test_r2d.TestMatrixAndStatic.test_dry_run_mutates_nothing` (`test_r2d.py:886`): identical False checks.
   **Same as the known environmental failure.**

The §3a clean-tree failure (`test_r2c_r2d_m2_m3a_m3b_contract_unchanged`) did not recur on the committed state.

## 3c. Primary-repository results with the literal-fixture tests (2026-10-11, uncommitted)

State: HEAD `f11a1f4` plus two uncommitted tracked changes: `tests/rules/test_design_adv.py` (three tests added:
`test_literal_fixture_all_other_drop_sources_zero`, `test_literal_fixture_all_cpu_util_features`,
`test_literal_fixture_equal_magnitude`; no existing test changed) and this record. Commands from `tests/` with
`PYTHONNOUSERSITE=1 ../.venv/bin/python`.

| Command | Result | Exit |
|---|---|---|
| `-m unittest rules.test_design_adv -v` | 15 run (12 + 3 literal), **OK** | 0 |
| `-m unittest discover -s rules -t .` | 112 run, **OK** | 0 |
| Documented regression (README "Usage", `tests/test_phase1a.py` excluded) | **1,043 run: 1,040 passed, 3 failed, 0 errors; not green** | 1 |

Per package: collectors 111 OK; ebpf 114 OK; evidence 228 OK; rules 112 OK; faultlab 325 with 3 failures; runtime
153 OK. Failures, compared individually:

1. `faultlab.test_r2c.TestDryRun.test_dry_run_mutates_nothing` (`test_r2c.py:1155`): False checks
   `preflight.checks.root_subtree_control`, `preflight.ok`, `structural_ok`, `zero_mutation.bpf_compared`;
   `zero_mutation.ok` True with no failed items. **Same as the known environmental failure.**
2. `faultlab.test_r2d.TestMatrixAndStatic.test_dry_run_mutates_nothing` (`test_r2d.py:886`): identical False checks.
   **Same as the known environmental failure.**
3. `faultlab.test_r2e.TestStaticAndIntegrity.test_r2c_r2d_m2_m3a_m3b_contract_unchanged` (`test_r2e.py:1617`): the
   clean-tracked-tree requirement, listing exactly the two uncommitted files above. **Not one of the two known
   failures**; the same by-design condition as §3a item 3. It passed on the clean committed state in §3b; whether it
   passes after these changes are committed has not been verified.

## 4. Mutation evidence (fresh run, scratch clone)

Each mutant changes `src/sentinelai/diagnostic/rules/engine.py` in the clone only, and is restored with `git checkout`;
`src` was verified clean afterwards. "Existing" = the 97 tests of the other `tests/rules` modules. A mutant whose
new-test failures are errors raised before any assertion (contract schema validation) is classified INVALID: it shows
the schema guard working, not the new assertions.

| Mutant | Regression it represents | Verdict | New tests failing | Existing |
|---|---|---|---|---|
| M0 | no-op control | control survives | none | pass |
| M1 | baseline kfree noise becomes WEAK support (ADV-1) | **killed** | `test_baseline_noise` | pass |
| M2′ | CC.X1 evaluated but its item not recorded (ADV-4) | **killed** | `test_throttling_not_contention` | pass |
| M3 | throttled time counted as contention waiting (ADV-4) | **killed** | `test_throttling_not_contention` | 14 FAIL |
| M4′ | utilisation alone makes CC.R1 TRUE (ADV-5) | **killed** | `test_utilisation_alone` | 1 FAIL |
| M5 | no absolute softirq floor (ADV-6) | **killed** | `test_below_absolute_floor` | pass |
| M6 | no softirq ratio check (ADV-6) | **killed** | `test_below_ratio` | pass |
| M7′ | high memory usage makes MP.R1 TRUE (ADV-7) | **killed** | `test_usage_is_not_pressure` | pass |
| M8 | unmeasured OOM treated as FALSE (ADV-7 missing-OOM subcase) | **killed** | `test_missing_oom_stays_missing` | pass |
| M9 | AB.R1 TRUE by elimination without app evidence (ADV-8) | **killed** | 3 tests incl. `test_all_app_metrics_absent` | pass |
| M10 | residual `NO_CANDIDATE` replaced (ADV-1/5/6/7/8) | **killed** | 6 tests | pass |
| M11 | `REQUIRED_EVIDENCE_MISSING` replaced (ADV-7 missing-OOM subcase, ADV-8, ADV-10) | **killed** | 4 tests | 3 FAIL |
| M12 | data-quality gate ignored (ADV-10) | **killed** | `test_absent_gate_failed` | 3 FAIL |
| M2 | CC.X1 contradiction dropped | INVALID (schema: "POSITIVE contradictory item for CC.X1 must list cpu_contention") | — | — |
| M4 | `cpu.util.cpuset` cited inside CC.R1 | INVALID (schema: "item CC.R1 may not use feature cpu.util.cpuset") | — | — |
| M7 | `mem.util.target` cited inside MP.R1 | INVALID (schema: "item MP.R1 may not use feature mem.util.target") | — | — |

12 of 12 valid mutants are killed by assertion failures; none survives; the control survives. Eight (M1, M2′, M5,
M6, M7′, M8, M9, M10) are not detected by the existing tests.

**Literal-fixture tests (fresh run, scratch clone, 2026-10-11).** A copy of the §3c version of
`tests/rules/test_design_adv.py` was run against targeted engine mutants in the scratch clone only:

| Mutant | Regression it represents | Literal test that must fail | Result |
|---|---|---|---|
| L0 | no-op control | none | all three literal tests pass |
| L1 | NOT_SPECIFIED kfree counted as a LOSS.LOCAL source | ADV-1 literal | **killed** (assertion) |
| L2 | a zero-valued drop source treated as MISSING instead of FALSE | ADV-1 literal | **killed** (assertion; ADV-5 literal also fails) |
| L3 | utilisation alone makes CC.R1 TRUE | ADV-5 literal | **killed** (assertion) |
| L4 | PR-3 tie resolved to throttling (no dominance margin) | ADV-9(a) literal | **killed** (assertion) |

## 5. Limitations

- §3/§4 evidence is from a scratch clone. §3a is from the primary repository with the changes uncommitted; §3b is
  from the primary repository on commit `f11a1f4`; §3c is from the primary repository with the literal-fixture tests
  uncommitted. No full regression has yet run on a committed state that includes the literal-fixture tests.
- Fixture fidelity: ADV-1, ADV-5 and ADV-9(a) now each have a test that builds the §7.3 fixture as written (§2,
  "literal"). The earlier tests for these rows, which set only the features the engine reads (ADV-1: softnet, socket,
  netfilter and loss-qualifying kfree sources absent rather than 0; ADV-5: only `cpu.util.cpuset`; ADV-9(a): 0.4 vs
  0.3), are kept as derived scenarios.
- Mutation evidence (§4) exists only for the scratch clone; it was not repeated in the primary repository.
- Unit fixtures use the test parameter set (`tests/rules/_fixtures.py` `TEST_NUMBERS`), not calibrated values.
- ADV-7 rests on interpretation D-1 (no separate contradictory clause exists for `memory_pressure` in `labels.json`).
- ADV-10's expected reason rests on D-2; contract §8.8 and design §5.1 word the reason rules less completely than
  M2 report §7.
- The FaultLab ("F") halves of §7.3 are outside G-R2 (unit level) and remain open (M6; ADV-8 also feeds G-R3).
- `softirq_overload` is unit-tested only; it is unvalidated at FaultLab level (R2-E NOT FEASIBLE under its registered
  design; waiver pre-registered in PHASE_1C_DESIGN.md §13, decision 4).

## 6. Verdict

**G-R2: PASS (unit-level gate only).** Decided by Rohit Kumar on 2026-10-11 on the evidence below. The verdict
applies only to the registered unit-level adversarial gate of PHASE_1C_DESIGN.md §7.5: every §7.3 row, including the
literal ADV-1, ADV-5 and ADV-9(a) fixtures, passes at unit level (§3c).

Registered criterion (PHASE_1C_DESIGN.md §7.5): "**All** adversarial tests ADV-1 … ADV-10 pass (unit level)"; rows
from §7.3; unit = hand-built `EvidenceSnapshot` fixtures in `tests/rules/` with explicit test parameter values. No
other threshold is registered. Assessment against the §3c run (rules 112/112):

| §7.3 row | Fixture as written tested? | Expected behaviour asserted and passing? | Result |
|---|---|---|---|
| ADV-1 | yes (literal test) | yes | PASS |
| ADV-2, ADV-3, ADV-3b | yes | yes | PASS |
| ADV-4 | yes | yes | PASS |
| ADV-5 | yes (literal test) | yes | PASS |
| ADV-6 | yes (both weak branches) | yes | PASS |
| ADV-7 | yes | yes, under D-1/D-1b (committed §13) | PASS |
| ADV-8 | yes (free-text logs are not features) | yes | PASS |
| ADV-8b | yes | yes | PASS |
| ADV-9 | (a) yes (literal test); (b) yes | yes | PASS |
| ADV-10 | yes | yes, under D-2 (committed §13) | PASS |

Limitations of this verdict (in addition to §5):

- The full documented regression is **not green**. The latest run before this record was committed (§3c) was
  1,043 run, 1,040 passed, 3 failed, exit 1: the known R2-C and R2-D dry-run failures, and the clean-tree integrity
  test triggered by the then-uncommitted evidence and test changes. None of the three is a G-R2 test. Whether the
  clean-tree failure clears once these changes are committed must be verified by a post-commit run, not assumed.
- The mutation evidence (§4) comes from the scratch clone, not from a primary-repository mutation run.
- G-R2 PASS does not mean Phase 1C or FaultLab is complete. G-R3 (its FaultLab half) and G-Q1–G-Q4 remain separate,
  unevaluated gates (no M6 data); the FaultLab ("F") halves of §7.3 remain open.
- R2-E remains NOT FEASIBLE under its registered design, and `softirq_overload` remains unvalidated at FaultLab
  level.
