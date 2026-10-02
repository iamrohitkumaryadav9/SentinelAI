# Phase 1C — M2 Report: Deterministic Evidence Rule Engine

| | |
|---|---|
| Milestone | Phase 1C M2 (rule engine only) |
| Base commit | `d98daac` feat(contract): revise evidence contract to v0.2.0-draft |
| Contract | `0.2.0-draft` (schema `0.2.0`), unchanged by M2 |
| Rules version | `m2-1.0.0` |
| Gate | **PASS WITH CONDITIONS** (§18). The condition is contract decision C-1, which is not housekeeping. |

---

## 1. Objective

M2 implements the deterministic evidence rule engine defined by `docs/EVIDENCE_CONTRACT.md` v0.2.0-draft:

- predicate evaluation (DEV, ABS, Kleene logic, EVALUATED, LOSS.LOCAL, IMPACT);
- required and contradictory clause evaluation;
- candidate evaluation;
- precedence PR-1..PR-5 and conflict detection;
- abstention, ordinal confidence and the `IMPACT_NOT_MEASURED` flag;
- `DiagnosticResult` construction;
- a pure deterministic API.

M2 does not implement collectors, FaultLab, ML, an LLM or calibration, and it does not modify the M1 contract.

## 2. Architecture

```
EvidenceSnapshot (measurements only) ─┐
ParameterSet (explicit, complete)  ───┼─> diagnose() ─> Diagnosis(snapshot + EvidenceItems + Conflicts,
code_commit                        ───┘                            DiagnosticResult)
```

New package `src/sentinelai/diagnostic/rules/`. No existing file was modified.

| File | Lines | Role |
|---|---|---|
| `params.py` | 65 | `ParameterSet`: strict Pydantic. Names and types are checked against the contract catalogue, and reason-set values against the kfree_skb reason dimension. `num()`, `reasons()` and `floor()` raise `UncalibratedParameters` when a value is absent. The engine has no defaults. |
| `logic.py` | 130 | `Tri` (TRUE/FALSE/MISSING), `Eval`, the Kleene `k_and`/`k_or`/`k_not`, `usable` (quality and COV_MIN), `dev` (§7 bands), `absolute`, `absolute_b`, `baseline_gate` |
| `engine.py` | 671 | Scope binding (`View`), evidence-item emission (`Ctx.emit`), one evaluator per contract clause, supporting predicates, IMPACT, AB.R3, precedence (`_resolve`), abstention, candidates, confidence, result construction, and the final `validate_against_snapshot` |
| `__init__.py` | 9 | Public API: `diagnose`, `Diagnosis`, `EngineError`, `ParameterSet`, `UncalibratedParameters`, `RULES_VERSION` |

API:

```python
from sentinelai.diagnostic.rules import diagnose, ParameterSet
d = diagnose(snapshot, params, code_commit="<sha>")   # -> Diagnosis(snapshot, result)
```

`code_commit` is an explicit argument. The engine never shells out to git.

**Refusals.** `diagnose` raises in four cases:

| Condition | Error |
|---|---|
| The input already contains evidence items or conflicts (the engine is the only producer of evidence) | `EngineError` |
| `params.parameter_set_id` differs from `snapshot.parameter_set_id` | `EngineError` |
| Any catalogue parameter or `floor[f]` the engine needs is absent (§6 refuse-to-run) | `UncalibratedParameters` |
| A feature has more than one target-bound measurement where the contract defines one | `EngineError` |

**Self-validation.** Every returned `Diagnosis` passes M1's `validate_against_snapshot`, covering I1–I6 and every structural snapshot rule. An engine bug therefore surfaces as an exception, never as a malformed result.

**Rule table check.** At import time the evaluator table is checked against the contract's 16 clauses. A missing or extra rule raises `ImportError`.

## 3. Predicate engine

| Primitive | Implementation (contract §7) |
|---|---|
| Usability | Quality OK or PARTIAL with a value. PARTIAL with coverage < COV_MIN is unusable. MISSING, STALE and INVALID are unusable. An unusable measurement evaluates to MISSING, never FALSE. |
| DEV(f) | Uses the snapshot's own `baseline` and `deviation`, never recomputed. No baseline, an inadequate baseline, or n < N_BASE_MIN gives MISSING. STRONG needs z ≥ Z_STRONG ∧ ratio ≥ R_STRONG ∧ x ≥ floor[f]; MODERATE uses the moderate bands; anything else is FALSE (STRONG if z < 1, else WEAK). |
| ABS(f, θ) | x ≥ θ, giving TRUE or FALSE with strength STRONG (I-1). Inside a baseline-using clause `absolute_b` also requires an adequate baseline, otherwise MISSING (the M1 snapshot rule). |
| Kleene AND/OR/NOT | FALSE dominates AND; TRUE dominates OR; MISSING otherwise propagates. A decided result cites only the operands that decided it (FALSE operands of AND, TRUE operands of OR). An undecided, possibly degraded input is therefore never cited by a POSITIVE or NEGATIVE item. |
| LOSS.LOCAL | Covers every drop source in §8.4. For kfree_skb, only reasons in the parameter `KFREE_REASONS_LOSS` count, and other reasons are at most WEAK *supporting*. Interface sources need `net.pkts.iface` for the drop fraction. The result is TRUE if any source is TRUE. It is FALSE only if the `min_local_drop_set` is complete on every target interface and every usable source is FALSE. Otherwise it is MISSING: absent counters never mean "no drops". |
| EVALUATED | TRUE only when the named family or set was actually evaluated with usable data. |
| IMPACT | DEV(app.latency_ms P99) ∧ ratio ≥ IMPACT_MIN. MISSING sets `IMPACT_NOT_MEASURED`. FALSE gives `NO_IMPACT_OBSERVED`. |

**Scope binding (I-2).** A measurement binds to the target only via these scopes:

- `cgroup:{cgroup_path}`
- `netns:{name}`
- `app:{name}`
- `iface:{name}/{iface ∈ ifaces}`
- `socket:{name}/…`
- `cpu:N` with N in the cpuset
- `cpuset` and `host`

Measurements of other targets are ignored; a test checks this. Measurements are sorted by ID before evaluation.

## 4. Clause evaluation

There is one function per clause in contract §8. Each emits a clause-level item: TRUE gives a POSITIVE item supporting the label, FALSE gives a NEGATIVE item contradicting it, and MISSING gives a MISSING item with a reason. Absent inputs produce no item.

| Clause | Evaluation |
|---|---|
| CC.R1 | DEV(sched.run_delay_excess.target) |
| CC.R2 | ABS(cpu.util.cpuset, SAT_MIN) ∨ DEV(cpu.steal.cpuset) |
| CC.X1 | ABS(throttle.ratio, THR_RATIO_MIN). TRUE supports cpu_throttling and contradicts cpu_contention. |
| CC.X2 | Softirq share (I-5) ≥ SI_SHARE_MIN. TRUE supports softirq_overload and contradicts cpu_contention. |
| CT.R1 | throttle.quota_limited: 1 gives TRUE, 0 gives **FALSE** (a real NEGATIVE: the quota is unlimited), unusable or absent gives MISSING |
| CT.R2 | ABS(throttle.ratio, THR_RATIO_MIN) ∧ DEV(throttle.time_rate) |
| SI.R1 | ABS(relevant_cpu_max, SI_ABS_MIN) ∧ ∃ relevant CPU with x ≥ SI_ABS_MIN ∧ DEV ∧ ratio ≥ SI_RATIO_MIN. The saturated CPUs are recorded for PR-2. |
| SI.R2 | DEV(run_delay_excess) ∨ DEV(psi.cpu.some.target) |
| PL.R1 | LOSS.LOCAL. One item per source (`PL.R1/LOSS.LOCAL[f]`); the qualifying (feature, cpu, reason) tuples are recorded for PR-2. |
| RT.R0 | ABS(tcp.out_segs_rate, SEG_MIN) |
| RT.R1 | ABS(retrans_frac, RT_FRAC_MIN) ∧ DEV(retrans_frac). The optional timeouts substitution is not applied (I-7). |
| RT.R2 | EVALUATED(min_local_drop_set) ∧ ¬LOSS.LOCAL. A FALSE LOSS.LOCAL gives a NEGATIVE item contradicting network_packet_loss. A MISSING LOSS.LOCAL gives a MISSING item. A proven loss gives an `RT.R2` NEGATIVE item contradicting tcp_retransmissions. |
| MP.R1 | (ABS ∧ DEV psi.mem.some) ∨ oom_kill > 0 ∨ (DEV ∧ ABS reclaim ∧ (DEV refault ∨ DEV majfault)) |
| AB.R1 | ∃ app wait: DEV ∧ ABS(APP_WAIT_MIN), or DEV(pool_rejections), or DEV(app.events) |
| AB.R2 | max wait Δ / p99 latency Δ ≥ APP_SHARE_MIN (I-8) |
| AB.R3 | Infrastructure families EVALUATED (I-10) ∧ no infrastructure label assertable. If one is assertable, an `AB.R3` NEGATIVE item contradicts application_bottleneck. |

**Supporting predicates (I-9).** These are evaluated as supporting-only items: they never satisfy a required clause and only affect confidence. Only the predicates expressible with registered features and the defined primitives are implemented. The table is `SUPPORTING` in `engine.py`.

## 5. Candidate evaluation

A label is **assertable** iff every required clause is TRUE. Contradictory clauses never block assertion; they produce contradicting items and feed precedence.

Each candidate's status is the first that applies:

1. **ASSERTED or CONTRIBUTING** if assertable. It is CONTRIBUTING when another label is the decision and there is no conflict; otherwise ASSERTED.
2. **NOT_SUPPORTED** if any required clause is FALSE.
3. **SUPPORTED_NOT_SUFFICIENT** if any POSITIVE item supports it.
4. **NOT_EVALUABLE** otherwise.

`required_met` and `required_missing` partition the required clauses, and `rules_fired` lists the TRUE clauses of that label. `CONTRADICTED` is not produced by M2: the contract defines no rule that produces it.

## 6. Precedence implementation

Precedence comes from contract §9 and only that table; there is no engine-invented ordering. Every assertable pair is resolved. A unique label that wins every pair becomes the decision; any unresolved pair is a `Conflict`.

| Rule | Pair | Behaviour |
|---|---|---|
| PR-1 | network_packet_loss vs tcp_retransmissions | Packet loss wins. This is unreachable in practice: see C-1. |
| PR-2 | softirq_overload vs network_packet_loss | Softirq wins iff **every** qualifying drop source is softnet on a saturated softirq CPU or kfree `CPU_BACKLOG` |
| PR-2b | the same pair, otherwise | Conflict with rule `PR-2b` |
| PR-3 | cpu_throttling vs cpu_contention | Throttling iff time_rate ≥ DOM_RATIO·run_delay_excess; contention iff the reverse holds. Otherwise, or if either value is missing, conflict with rule `PR-3`. |
| PR-4 | application_bottleneck vs any infrastructure label | Infrastructure wins. AB.R3 already makes this pair unreachable, but the resolver still implements PR-4. |
| PR-5 | softirq_overload vs cpu_contention | Softirq iff share ≥ SI_SHARE_MIN. Otherwise conflict with rule `PR-5` (the second branch is not evaluable: I-11). |
| other | any unlisted pair | Conflict with `rule = null` |

`DOM_RATIO`, `SI_SHARE_MIN` and every other threshold come only from the `ParameterSet`.

## 7. Abstention behavior

The checks run in this order; the first that applies gives the reasons.

1. `DATA_QUALITY`: the data-quality gate failed.
2. `NO_IMPACT_OBSERVED`: IMPACT is FALSE.
3. `CONFLICT_UNRESOLVED`: there is any conflict.
4. No decision, with every undecided label accounted for:
   - `LOSS_VS_RETRANS_UNDECIDABLE`: RT.R1 TRUE and RT.R2 MISSING. This also covers network_packet_loss when PL.R1 is MISSING, because that is the same open question.
   - `CONFOUNDER_NOT_EVALUATED`: AB.R1 and AB.R2 TRUE and AB.R3 MISSING.
   - `REQUIRED_EVIDENCE_MISSING`: any other undecided label (no FALSE required clause, some MISSING).
   - `NO_CANDIDATE`: none of the above.

An abstention has `decision = INSUFFICIENT_EVIDENCE`, `abstained = true`, a non-empty reason list, no contributing labels and confidence LOW. Assertable labels in an abstained result keep status ASSERTED so the reader can see what was assertable. M1 validation accepts this.

**Application safety.** application_bottleneck is never chosen by elimination. It needs AB.R1 (positive app.* wait, rejection or event evidence) ∧ AB.R2 ∧ AB.R3. I6 is re-checked by M1 validation, and latency alone gives `REQUIRED_EVIDENCE_MISSING` (test ADV-6).

## 8. Confidence behavior

Confidence is ordinal only (§10.9):

| Confidence | When |
|---|---|
| LOW | Every abstention |
| HIGH | Every required clause of the decision is STRONG ∧ no item contradicts the decision ∧ IMPACT is TRUE ∧ no supporting feature is missing |
| MEDIUM | Any other assertion. An assertion is never LOW. |

`IMPACT_NOT_MEASURED` is set whenever IMPACT is MISSING, so an assertion can then be at most MEDIUM. M2 never produces `ML_DISAGREEMENT`, and `ml` is always `null`.

## 9. Adversarial tests

`tests/rules/test_adversarial.py` (23 tests). Each scenario is the independent "normal world" fixture plus one fault fragment, and asserts exact decisions, contributing labels, reasons, conflict rules and evidence items.

| ADV | Scenario | Expected | Observed | Result |
|---|---|---|---|---|
| 1 | 3/s NOT_SPECIFIED kfree_skb | Not packet loss | Packet loss NOT_SUPPORTED. Even 5000/s NOT_SPECIFIED gives only a WEAK supporting item (§8.4). A qualifying reason below DROP_ABS_MIN is NEGATIVE. | PASS |
| 2 | High retransmissions, drop counters absent or MISSING | INSUFFICIENT_EVIDENCE | INSUFFICIENT_EVIDENCE with exactly [LOSS_VS_RETRANS_UNDECIDABLE]. No item claims "no drops". | PASS |
| 3 | High retransmissions, normal drops | tcp_retransmissions | tcp_retransmissions (MEDIUM). RT.R2/LOSS.LOCAL is NEGATIVE and contradicts packet loss. Low traffic (RT.R0 FALSE) blocks it. | PASS |
| 4 | CPU_BACKLOG kfree + softirq | softirq_overload, loss contributing | softirq_overload, contributing [network_packet_loss], via PR-2 | PASS |
| 5 | Retransmissions + proven drops | network_packet_loss, retransmissions contributing | network_packet_loss (HIGH). Contributing is **empty** and tcp_retransmissions is NOT_SUPPORTED (RT.R2 FALSE). | **PARTIAL: decision PASS, contributing blocked by C-1** |
| 6 | No infrastructure cause, no app evidence | INSUFFICIENT_EVIDENCE, not application | NO_CANDIDATE. Latency only gives REQUIRED_EVIDENCE_MISSING. A wait that doesn't explain the latency makes application NOT_SUPPORTED. | PASS |
| 7 | Positive app evidence, no infrastructure | application_bottleneck | application_bottleneck, with a positive app.queue_wait item. Adding contention gives contention, and AB.R3 NEGATIVE. | PASS |
| 8 | Throttling + contention, dominance | PR-3 resolves | throttling (contributing contention), and the reverse case gives contention (contributing throttling) | PASS |
| 9 | Throttling + contention, no dominance | No arbitrary choice | CONFLICT_UNRESOLVED, conflict (contention, throttling) rule PR-3, nothing contributing. Changing DOM_RATIO (a parameter) changes the outcome. | PASS |
| 10 | Softirq + contention, share ≥ SI_SHARE_MIN | PR-5 resolves | softirq_overload, contributing [cpu_contention]. Share below the threshold gives a PR-5 conflict. | PASS |

Other suites (78 M2 tests in total):

| File | Tests | Covers |
|---|---|---|
| `test_abstention.py` | 19 | NO_IMPACT_OBSERVED (including DEV TRUE but ratio < IMPACT_MIN); IMPACT_NOT_MEASURED (absent, MISSING, inadequate baseline); ML_DISAGREEMENT never produced; no IMPACT items (C-2); DATA_QUALITY and its precedence; MISSING, STALE, INVALID and PARTIAL<COV_MIN never support and never become NEGATIVE; PARTIAL≥COV_MIN is usable; inadequate baseline; absent measurement; unlimited quota gives CT.R1 NEGATIVE; missing quota gives MISSING; CONFOUNDER_NOT_EVALUATED; network families only with traffic; I1 and confidence across scenarios; DEV needs both z and ratio; the MODERATE band |
| `test_precedence.py` | 13 | PR-2 softnet on a saturated CPU; PR-2b (unsaturated CPU, a non-softirq drop, mixed sources); PR-3 inputs; PR-4 (scenario and resolver); PR-1 resolver; every unlisted pair gives (None, None); a three-way case with an unresolved pair; unsupported co-assertion is never CONTRIBUTING; resolved three-way softirq + loss + retransmissions |
| `test_determinism.py` | 10 | Replay A = B = C bytes over 8 scenarios; fresh parameter objects; 5 random permutations per scenario; foreign-target measurements ignored and never cited; input not mutated; engine imports limited to an allowlist with no open/eval/exec/print/clock/env; EngineInfo; duplicate measurement rejected; unique item IDs; repeated kfree reasons are distinct sources |
| `test_refusal.py` | 9 | Each missing parameter refused (including DOM_RATIO, SI_SHARE_MIN, COV_MIN, τ_DISAGREE and a floor); missing reason set; no defaults; unknown, NaN and mistyped parameters; invalid reason values; parameter-ID mismatch; input with evidence; duplicate input |
| `test_invariants.py` | 4 | M1 validation and I7 JSON round-trip over a 13-scenario matrix; item construction (ID derivation, supports only if POSITIVE, POSITIVE/NEGATIVE cite only OK or PARTIAL measurements); I6; candidate partition and status rules |

## 10. Determinism

- No clock, randomness, I/O, environment or unordered iteration influences the result.
  - Measurements are sorted by ID.
  - Items are keyed by deterministic ID and emitted sorted.
  - Precedence iterates `FAULT_LABELS` in contract order.
  - Conflict labels and item lists are sorted.
- The test `test_engine_has_no_io_clock_randomness_or_llm` enforces an import allowlist (`dataclasses`, `enum`, `itertools`, `re`, `typing`, `pydantic`, plus package-relative imports).
- Replay gives byte-identical `canonical_bytes(result) | canonical_bytes(snapshot)` across 3 runs × 8 scenarios.
- 40 permuted inputs (5 per scenario) give identical bytes.
- Evidence-item and candidate ordering cannot be permuted on input: the engine refuses input evidence, and candidates are outputs. Their output order is canonical.

## 11. Mutation testing

The script runs against a scratch copy of `src/` and `tests/` (the repository is never modified). It applies one mutation at a time and runs `tests/rules`.

**Result: 22 of 23 mutants killed.**

Killed:

| Area | Mutants |
|---|---|
| Precedence | PR-1 winner flipped; PR-2 `all`→`any`; PR-3 dominance ignored; PR-3 no-dominance picks contention; PR-5 share ignored; an unlisted pair invents an order; a conflict resolves to the first label |
| Loss and retransmission | kfree reason filter removed; missing drop set treated as no drops; RT.R2 ignores loss |
| Application and gates | AB.R3 ignores evaluation; impact gate removed; data-quality gate removed; IMPACT_NOT_MEASURED never set; unlimited quota becomes MISSING |
| Logic and baselines | Kleene AND treats MISSING as TRUE; Kleene OR treats MISSING as FALSE; COV_MIN ignored; DEV ignores baseline adequacy; DEV ignores ratio |
| Engine boundaries | scope binding removed; parameter refusal removed |

"DEV ignores ratio" first **survived**. I added `TestDevRequiresBothBands` (high z, ratio 1.2: NEGATIVE), and it is now killed.

**Surviving: "measurement order dependence"** (the sort in `View` removed). Under the 2-CPU fixtures this is an equivalent mutant: every output collection is sorted downstream, and summing two floats is order-independent. The observable property (permutation invariance) is tested directly. The sort is kept as defence for float summation over 3 or more CPUs.

## 12. Existing test suite

`PYTHONNOUSERSITE=1 .venv/bin/python -m unittest discover -s tests -t tests` ran **282 tests: 281 passed, 0 failed, 1 skipped**. The skip is the pre-existing root-only test. The 204 pre-M2 tests are unchanged and still pass; 78 are new M2 tests. No existing test or source file was modified.

## 13. Scope audit

| Check | Result |
|---|---|
| `git status --short` before the commit | `?? experiments/faultlab/`, `?? src/sentinelai/diagnostic/rules/` (4 files), `?? tests/rules/` (8 files), and this report |
| `git diff --stat HEAD` (tracked files) | empty. No M1 file, contract file or existing test is modified. |
| Keyword grep over the new files (ollama, openai, anthropic, kubernetes, prometheus, ebpf, bpftrace, bcc, faultlab, docker, subprocess, requests, httpx, agent, mcp, rag) | One hit: `privileged_sources_unavailable=("EBPF",)` in a test fixture. That is the contract's `SourceType` enum value describing data quality, not an eBPF integration. The other hits are this report and the purity test, which name the banned words in order to check for them. |
| Not implemented, as instructed | M3 collectors, eBPF, /proc, /sys, cgroup collection, Prometheus, Kubernetes, FaultLab, fault injection, network changes, ML, training, calibration, LLM, Ollama, RAG, GraphRAG, MCP, agents, remediation, model routing |
| `experiments/faultlab/` | Untouched, unexecuted and not staged |

## 14. Safety audit

M2 made no host changes:

- no network, qdisc or NIC change (enp0s31f6 untouched), and no Docker, sudo or systemd use;
- no package installs; the existing venv (Pydantic 2.13.5) was used;
- no services started.

Tests are pure in-process computation. The mutation script ran only in the session scratchpad.

## 15. Deviations

### Contract contradictions (reported, not resolved; the M1 contract is unchanged)

**C-1: RT.R2 vs PR-1 / §8.5 "retransmissions contributing" (affects ADV-5).**
- RT.R2 is a *required* clause of tcp_retransmissions and requires ¬LOSS.LOCAL.
- When local drops are proven, RT.R2 is FALSE, so tcp_retransmissions has a missing required clause.
- Under I4 and the M1 candidate rules (ASSERTED or CONTRIBUTING ⇒ no required clause missing), it can therefore never be ASSERTED or CONTRIBUTING.
- So PR-1 can never fire on real input, and the expectation "network_packet_loss with retransmissions contributing" is unreachable.

The engine follows the contract literally: packet loss is asserted, tcp_retransmissions is NOT_SUPPORTED, and the `RT.R1` POSITIVE item still records the retransmission signal. A resolution needs a contract decision, which M2 did not invent. Two options for the reviewer:
- (a) make RT.R2 a contradictory clause, or move it to an assert-only gate;
- (b) define a "contributing" path that exempts RT.R2 when packet loss is primary.

**C-2: IMPACT items.**
- IMPACT is a gate, not label evidence.
- A POSITIVE IMPACT item would support no fault label, which the schema forbids (POSITIVE ⇒ supports non-empty).
- M2 therefore emits no IMPACT items. Impact status is carried by `IMPACT_NOT_MEASURED` and `NO_IMPACT_OBSERVED`.

**C-3: AB.R3 feature list omits `throttle.quota_limited`.**
- v0.2.0 added `throttle.quota_limited` to CT.R1 but not to AB.R3's feature list.
- An AB.R3 family item may only cite AB.R3 features.
- The measurement still drives the cpu_throttling family's evaluation, but AB.R3 items cannot cite it, so the engine filters it out of AB.R3 citations.
- This is housekeeping: add the feature to AB.R3 in a later contract revision.

### Interpretations (points the contract leaves open)

| ID | Interpretation |
|---|---|
| I-1 | ABS strength is STRONG (ABS has no bands) |
| I-2 | Scope binding as in §3 |
| I-3 | Candidate status ordering as in §5. `CONTRADICTED` is unused. |
| I-4 | Decided Kleene results cite only their deciding operands |
| I-5 | Softirq share = mean per-CPU softirq fraction over relevant CPUs / cpu.util.cpuset |
| I-6 | The "baseline median = 0" drop branch gives TRUE with strength MODERATE |
| I-7 | The optional timeouts substitution in RT.R1 is not applied |
| I-8 | AB.R2 share = max wait Δ / p99 latency Δ, using only waits with adequate baselines |
| I-9 | The supporting-predicate subset. Skipped as not expressible: other cgroups' usage, reverse-direction drops/cwnd/throughput, run_delay ≈ throttle, impact with low utilisation, attributable swap. |
| I-10 | AB.R3 evaluates the cpu_sched, cpu_throttling, memory and softirq families, plus network_drops and network_tcp only when RT.R0 is TRUE (traffic exists) |
| I-11 | PR-5's second branch ("contention holds without the softirq CPUs") is not evaluable with per-cgroup run_delay_excess, so it is a conflict |
| I-12 | Abstention is LOW confidence; reasons are reported only when abstaining |
| I-13 | Assertable labels in an abstained result keep status ASSERTED |
| I-14 | The whole parameter set is required, including parameters no clause uses (RT_RATE_MIN, THR_TIME_MIN, RDX_MIN, REFAULT_MIN, W, B, τ_DISAGREE), following the §6 refuse-to-run rule |

### Engine bugs found by the tests and fixed (not by weakening tests)

1. AB.R3 cited `throttle.quota_limited` (C-3).
2. Kleene results cited undecided degraded inputs, which made POSITIVE items reference MISSING, STALE or INVALID measurements. Fixed by I-4 and by AB.R3 citing the decisive conjunction.
3. `LOSS_VS_RETRANS_UNDECIDABLE` did not cover the MISSING PL.R1 side of the same question, which added a spurious `REQUIRED_EVIDENCE_MISSING`.

Test corrections: two ADV tests had asserted something stricter than the contract. One forbade the §8.4 WEAK supporting kfree item. The other expected a MISSING item when no measurement exists, but the engine emits no item when there are no inputs. Each was corrected to assert the contract's exact behaviour, not relaxed to pass.

## 16. Known limitations

- **Test-only values.** All parameter values in the tests are test-only. No calibrated parameter set exists, so the engine cannot run on real data until a calibration milestone provides one, and it refuses to run without one.
- **Fixture coverage.** The fixtures use a 2-CPU cpuset and one interface. Multi-interface and wider-cpuset behaviour is implemented but less exercised.
- **`PHASE_1C_DESIGN.md`** still names contract v0.1.0-draft (known housekeeping, not touched in M2).
- **C-1 and C-3** need a contract revision.
- **No live input.** M2 has no collectors, so all inputs are synthetic snapshots.

## 17. Git commit

The commit is `feat(diagnostic): implement phase1c deterministic rule engine`. It contains only:

- `src/sentinelai/diagnostic/rules/{__init__,params,logic,engine}.py`
- `tests/rules/{__init__,_fixtures,test_adversarial,test_abstention,test_precedence,test_determinism,test_refusal,test_invariants}.py`
- `docs/PHASE_1C_M2_REPORT.md`

`experiments/faultlab/` is excluded and remains untracked.

## 18. Final M2 gate

**PASS WITH CONDITIONS**

No FAIL trigger occurred:

- every ADV decision is correct;
- missing evidence is never turned into negative evidence;
- application_bottleneck is never chosen by elimination;
- retransmissions are never treated as packet loss without evidence;
- precedence follows only §9;
- conflicts are never resolved arbitrarily;
- no threshold value was invented;
- output is deterministic;
- all invariants are self-validated;
- no M3, FaultLab, network, ML or LLM work was done;
- no test was weakened.

**Condition (not housekeeping):** C-1 makes ADV-5's "retransmissions contributing" unreachable under the contract as written. The engine follows the contract literally and does not invent a resolution, so ADV-5 passes on the decision but not on the contributing set. Strictly, the PASS WITH CONDITIONS definition is limited to housekeeping. If the reviewer reads ADV-5's contributing expectation as critical, this gate should be **FAIL** until a contract revision resolves C-1. The decision is the reviewer's.

C-3 and the `PHASE_1C_DESIGN.md` version line are housekeeping.
