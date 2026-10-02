# Phase 1C — C-1 Contract Resolution Report

| | |
|---|---|
| Milestone | C-1 contract resolution gate (after M2) |
| Base | `c15e8ae592ced2ebd56a7b18047323e442a410e3` feat(diagnostic): implement phase1c deterministic rule engine |
| Before | contract `0.2.0-draft`, schema `0.2.0`, rules `m2-1.0.0`. `git status`: `?? experiments/faultlab/` only |
| After | contract **`0.3.0-draft`**, schema `0.2.0` (unchanged), rules `m2-1.1.0` |
| Gate | **PASS** (§16) |

---

## 1. C-1 root cause

In v0.2.0, RT.R2 (`EVALUATED(min_local_drop_set) ∧ ¬LOSS.LOCAL`) played two roles at once:

1. **Exclusion for the primary diagnosis.** tcp_retransmissions may be *the* cause only if local loss is ruled out.
2. **A Required clause.** Every candidate that is ASSERTED **or CONTRIBUTING** needs all Required clauses TRUE (I4 and the M1 Candidate rule).

When local loss is proven, RT.R2 is FALSE, so tcp_retransmissions can never be CONTRIBUTING. That left the contract unable to produce its own §8.5 boundary row "local drops proven, retransmissions high → network_packet_loss (primary) + tcp_retransmissions (contributing)", and PR-1 could never fire on real input. §8.5 also already said "Contradictory: LOSS.LOCAL TRUE. The label becomes contributing under PR-1", which contradicted RT.R2 being Required. The contract's *intent* was clear; its *structure* didn't allow it.

## 2. Exact contract semantics before (v0.2.0-draft)

| Item | Definition |
|---|---|
| RT.R0 | `tcp.out_segs_rate ≥ SEG_MIN`. Required. |
| RT.R1 | `ABS(tcp.retrans_frac, RT_FRAC_MIN) ∧ DEV(tcp.retrans_frac)`. Required. |
| RT.R2 | `EVALUATED(min_local_drop_set) ∧ LOSS.LOCAL FALSE`. **Required.** Components: EVALUATED POSITIVE + LOSS.LOCAL NEGATIVE. |
| tcp_retransmissions | Required = {RT.R0, RT.R1, RT.R2} |
| LOSS.LOCAL (§8.4) | TRUE iff a qualifying source has x ≥ DROP_ABS_MIN ∧ (DEV ∨ baseline median = 0) ∧ drop fraction ≥ DROP_FRAC_MIN. kfree_skb counts only for reasons in KFREE_REASONS_LOSS. Missing counters never mean "no drops". |
| ASSERTED / CONTRIBUTING (§10.6, M1 `Candidate`) | Both require every Required clause met (I4) |
| PR-1 (§9) | Loss + tcp co-assertable → primary loss, contributing tcp. "Precedence is applied only among labels whose Required clauses are all TRUE." |
| §8.5 | Contradictory: LOSS.LOCAL TRUE → contributing under PR-1. RT.R2 MISSING → LOSS_VS_RETRANS_UNDECIDABLE. |
| ADV-2 / ADV-3 / ADV-5 | Counters missing → INSUFFICIENT_EVIDENCE (passed). Normal drops → tcp (passed). Proven drops → loss + tcp contributing (**unreachable**: M2 produced loss with tcp NOT_SUPPORTED). |
| I4 | No candidate ASSERTED unless all required items are POSITIVE (or the required negations hold). M1 extended this to CONTRIBUTING. |
| I7 | Byte-identical canonical serialisation |

## 3. Chosen resolution: Option A (RT.R2 becomes a Primary clause)

A new clause role, **Primary**, sits beside Required and Contradictory. A Primary clause is needed for the label to be the **decision**, but not for it to be **CONTRIBUTING**. Each Primary clause declares its **subordination**: the precedence rule and primary label under which the label may contribute when the clause is FALSE.

RT.R2 is the only Primary clause. Its declared subordination is `{rule: PR-1, primary: network_packet_loss}`. **The RT.R2 predicate itself is unchanged.**

| Evidence | v0.2.0 | v0.3.0 |
|---|---|---|
| Retransmissions high, local loss evaluated and FALSE | tcp ASSERTED | tcp ASSERTED (unchanged) |
| Retransmissions high, local loss proven | loss, tcp NOT_SUPPORTED | **loss ASSERTED, tcp CONTRIBUTING (PR-1)** |
| Retransmissions high, local loss unknown | INSUFFICIENT_EVIDENCE (LOSS_VS_RETRANS_UNDECIDABLE) | unchanged |
| Loss proven, retransmissions normal | loss | unchanged |

**Subordinate-only rule (§9).** Precedence still runs only among labels whose Required **and** Primary clauses are TRUE, exactly the v0.2.0 set. A label whose Required clauses are TRUE and whose Primary clause is FALSE (never MISSING):

- takes no part in pairwise precedence;
- never creates a conflict;
- is CONTRIBUTING iff its declared primary is the decision, and SUPPORTED_NOT_SUFFICIENT otherwise.

A label whose Primary clause is MISSING is never CONTRIBUTING.

## 4. Why it was chosen

**Option B rejected** (keep RT.R2 Required, add an exception path "RT.R1 ∧ LOSS.LOCAL TRUE → contributing"):
- It needs a second definition of tcp's evidence beside the clause table, plus an exception to I4 that names a predicate combination.
- The contributing path would duplicate RT.R1 and LOSS.LOCAL logic outside the clause model.
- The exception would be harder for a future reader to audit than a role.

**Option A, first variant, also rejected.** I first let Primary-unmet labels join pairwise precedence. Tests showed two decisions changing that had nothing to do with C-1:
- softirq + CPU_BACKLOG drops + retransmissions went from softirq_overload to a softirq/tcp conflict;
- contention + retransmissions with loss unknown went from cpu_contention to a conflict.

The subordinate-only rule keeps every v0.2.0 decision except the C-1 one.

Against the gate's criteria:

| # | Criterion | How |
|---|---|---|
| 1 | Loss / retransmission distinction | tcp is the decision only with loss evaluated and FALSE |
| 2 | Conservative abstention | Loss unknown keeps RT.R2 MISSING, which gives LOSS_VS_RETRANS_UNDECIDABLE; a MISSING Primary clause never enables contribution |
| 3 | Retransmissions never prove loss | PL.R1 is unchanged and only drop sources satisfy it |
| 4 | ADV-5 reachable | Loss ASSERTED, tcp CONTRIBUTING |
| 5 | Deterministic precedence | The PR table is unchanged; the subordination is data, and its agreement with `_resolve` is checked at import |
| 6 | I1–I7 not weakened | I2 and I4 stay at least as strict (§5); a CONTRIBUTING-without-RT.R2 claim must be backed by a NEGATIVE RT.R2 item and the declared primary as decision |
| 7 | Smallest change | One role change on one clause, one data field, no predicate change, no evidence-object field change |
| 8 | Auditable | The rule is visible in `labels.json` (`"role": "primary"`, `"subordinate": {"rule": "PR-1", ...}`) |

## 5. Exact contract changes (`docs/EVIDENCE_CONTRACT.md`, `labels.json`)

**Header and history.** Version 0.3.0-draft; revision-history row added (C-1, C-3, schema unchanged).

**§8 intro.** Definition of **Primary** clauses and their declared subordination.

**§8.5.** RT.R2 marked Primary, with its subordination (PR-1, network_packet_loss). The Contradictory text now reads "cannot be the decision; contributing under PR-1 when network_packet_loss is the decision, otherwise SUPPORTED_NOT_SUFFICIENT". A MISSING RT.R2 never enables contribution.

**§8.7.** AB.R3's features cover every Required and Primary feature of the infrastructure labels; `throttle.quota_limited` added (C-3).

**§9.** "Precedence among labels whose Required **and Primary** clauses are all TRUE", plus the subordinate-only rule. PR-1 row notes it applies through the RT.R2 subordination.

**§10.7 I2.** "every Required **and Primary** clause of the decision".

**§10.7 I4.**
- ASSERTED needs Required + Primary.
- CONTRIBUTING needs Required. An unmet Primary clause is allowed only when the decision is that clause's declared primary **and** the snapshot has a NEGATIVE item of that clause contradicting the candidate.
- `required_met`/`required_missing` partition Required + Primary.

**§12.** A 0.3.0-draft governance note: by §12 a role change is major. Following the 0.2.0-draft precedent for a pre-release draft it is 0.3.0-draft, and the reviewer may decide otherwise. Schema stays 0.2.0, and 0.2.0-draft snapshots (major 0) remain accepted.

**`labels.json`.**
- RT.R2: `"role": "primary"`, `"subordinate": {"rule": "PR-1", "primary": "network_packet_loss"}`, and the definition text extended.
- AB.R3 features: `+ throttle.quota_limited`.
- `contract_version` set to 0.3.0-draft in all four data files.

## 6. Schema changes

**Evidence objects:** none. EvidenceSnapshot, EvidenceItem, Measurement and DiagnosticResult have no new, removed or renamed fields, so `SCHEMA_VERSION` stays `0.2.0`.

The **contract-catalogue** model and the M1 validation rules change:

| File | Change |
|---|---|
| `catalog.py` | `Clause.role` adds `"primary"`. New `Subordination{rule, primary}` and `Clause.subordinate`. A clause has a subordination **iff** it is Primary, never to itself. The rule must exist and relate both labels. New helpers `contributing_clauses()` (Required) and `primary_clauses()`; `required_clauses()` now returns Required + Primary (what assertion needs). |
| `models.py` | `Candidate`: ASSERTED ⇒ nothing missing. CONTRIBUTING ⇒ only Primary clauses may be missing. A POSITIVE item of a Primary clause supports its label, like a Required one. |
| `validate.py` | CONTRIBUTING candidates are checked against Required clauses. New `_check_subordination`: an unmet Primary clause needs the decision to equal the declared primary and a NEGATIVE item of that clause contradicting the candidate. |
| `version.py` | `CONTRACT_VERSION = "0.3.0-draft"` |

## 7. M2 implementation changes (`engine.py`)

1. **Precedence set unchanged** (Required + Primary TRUE). A new *subordinate-only* set covers Required TRUE with a Primary FALSE and none MISSING. Such a label is CONTRIBUTING iff its declared primary is the decision, otherwise SUPPORTED_NOT_SUFFICIENT.
2. **`_self_check_subordination()` at import.** Each declared subordination must equal what `_resolve` returns for that pair (PR-1 gives network_packet_loss).
3. **C-3.** The AB.R3 citation filter is removed, since the contract now lists the feature.
4. **Bug fix in LOSS.LOCAL.** A FALSE LOSS.LOCAL cited *every* source, including unusable ones. With an unusable non-minimum source (for example `net.drop.netfilter` with quality MISSING), M2 raised a validation error instead of returning a diagnosis. Probing before the edit found this. A FALSE result now cites only the usable sources that decided it.
5. `RULES_VERSION = "m2-1.1.0"`.

The RT.R0, RT.R1 and RT.R2 evaluators and the PR-1 resolver are unchanged.

## 8. Tests added and changed

**New `tests/rules/test_c1.py` (17 tests):**

| Scenario | Checks |
|---|---|
| C1-A (high retransmissions + proven loss) | Loss ASSERTED, tcp CONTRIBUTING, `contributing == (tcp,)`, no conflict, no reasons. PR-1 is the resolving rule and the declared subordination. Exact evidence references: RT.R2 NEGATIVE contradicting tcp is listed in tcp's `contradicting`; RT.R1 is in tcp's `supporting`; the PL.R1 item is in loss's `supporting`. |
| C1-A variants | kfree QDISC_DROP, CPU_BACKLOG and iface_rx sources. NO_IMPACT_OBSERVED and DATA_QUALITY give no contribution. IMPACT_NOT_MEASURED keeps the contribution with the flag. Low traffic gives no contribution. |
| Subordinate only to its declared primary | softirq + backlog + retransmissions: softirq decided, loss contributing, tcp SUPPORTED_NOT_SUFFICIENT, no conflict. A PR-2b conflict keeps tcp out. |
| C1-B (retransmissions + normal loss) | tcp ASSERTED with nothing missing; loss NOT_SUPPORTED. Regression test for the LOSS.LOCAL citation crash. |
| C1-C (loss unknown) | Counters absent, MISSING quality, inadequate baseline, or `net.pkts.iface` absent all give INSUFFICIENT_EVIDENCE with LOSS_VS_RETRANS_UNDECIDABLE, and neither label is ASSERTED or CONTRIBUTING. Contention + retransmissions with loss unknown still gives cpu_contention with tcp not contributing (unchanged from v0.2.0). |
| C1-D (loss without retransmissions) | Retransmissions normal or absent: loss decided, no contribution |
| C1-E (NOT_SPECIFIED only) | At 3/s or 5000/s, with or without retransmissions, it never satisfies PL.R1. With retransmissions, tcp is primary. Only the WEAK `DEV[net.drop.kfree_skb]` supporting item appears. |
| C1-F (determinism) | 6 scenarios × (2 replays + 8 permutations): byte-identical |

**New `tests/evidence/test_revision_v030.py` (12 tests):**
- RT.R2 is Primary with the PR-1 subordination, and its components are unchanged.
- The Required, contributing and Primary clause sets for every label.
- Catalogue rules: a Primary clause must declare a subordination; only a Primary clause may; never to itself; an unknown rule or a rule that doesn't relate the pair is rejected.
- Validation: a backed PR-1 contribution passes. It is rejected without the NEGATIVE RT.R2 item, rejected under any other decision, rejected without an RT.R1 item, and ASSERTED still needs RT.R2.
- C-3: `quota_limited` is in AB.R3, and AB.R3 covers every infrastructure clause feature.
- Versions, and that 0.2.0-draft snapshots are still accepted.

**Changed tests.** These follow the new contract and none is relaxed:
- `test_adversarial` ADV-5: the C-1 placeholder ("tcp NOT_SUPPORTED") is replaced by the **full** expectation, contributing `(tcp,)`, no conflict, exact met/missing clauses.
- `test_invariants`: "CONTRIBUTING ⇒ nothing missing" becomes "CONTRIBUTING ⇒ only Primary clauses missing, and then the decision is the declared primary". This is stricter about *which* clause may be missing.
- `test_precedence` three-way: tcp status changes from NOT_SUPPORTED to SUPPORTED_NOT_SUFFICIENT, and the test now also asserts no conflict. The decision and contributing assertions are unchanged.
- The version strings in `test_registry`, `test_schema` and `test_determinism`, and the `_fixtures` snapshot contract_version.

## 9. Full regression results

| Suite | Result |
|---|---|
| M1 contract tests (`tests/evidence`) | **192 / 192 passed** (180 before + 12 new) |
| M2 engine tests (`tests/rules`) | **95 / 95 passed** (78 before + 17 new) |
| Full repository (`discover -s tests -t tests`) | **311 run: 310 passed, 0 failed, 1 skipped** (the pre-existing root-only skip) |
| ADV-1..ADV-10 | All pass. **ADV-5 now fully passes**, contributing set included. |

## 10. Mutation results

Each mutant ran on a scratch copy of `src/` and `tests/` against `tests/evidence` + `tests/rules`. An **unmutated control run passes**.

The first attempt ran the whole `tests/` tree. The Phase 1A environment tests (git, venv, scripts) fail outside the real repository, which made every mutant look killed. I caught this and replaced that run with the clean-control setup; none of those numbers are used here.

**C-1 focused set: 27 / 27 killed.**

| Area | Mutants |
|---|---|
| RT.R2 semantics | role back to Required; subordination removed; subordinate rule renamed; RT.R2 ignores LOSS.LOCAL; RT.R2 FALSE item not emitted |
| PR-1 | winner flipped; becomes a conflict; flipped with the import self-check in place |
| Contributing path | ignores which label is the decision; admits a MISSING Primary clause; contributes while abstaining; joins pairwise precedence; contributing allowed whenever decided; catalogue allows a Primary without subordination |
| M1 validation and model | subordination check removed; NEGATIVE-Primary evidence not required; any decision accepted; CONTRIBUTING checked against Required + Primary; CONTRIBUTING may miss any clause; ASSERTED may miss a Primary clause |
| LOSS.LOCAL | missing drop set treated as no drops; kfree reason filter removed; FALSE cites unusable sources; undeterminable source ignored |
| Abstention with unknown loss | LOSS_VS_RETRANS never reported; unknown loss lets tcp be primary |
| C-3 | `quota_limited` dropped from AB.R3 |

**Survivors along the way, now resolved:**
- *"ignores which label is the decision"* and *"ignores the PR rule"* first survived as equivalent mutants. The engine checked the same fact twice (`primary is decision` and `_resolve(...) == PR-1`). Fixed by keeping one data-driven condition and moving the contract↔resolver agreement into an import-time self-check.
- *"admits MISSING Primary clause"* first survived for the same reason (a redundant empty-list guard). After restructuring, the MISSING guard is load-bearing and killed.
- *"subordinate without declared subordination"* first survived because no such clause existed. Fixed structurally: a Primary clause must declare a subordination, enforced by the catalogue and tested.

**M2 mutation set re-run: 22 / 23 killed.** That matches M2. The one survivor is the known equivalent "measurement order" mutant, unrelated to the changed semantics.

## 11. Determinism results

- M2 replay and permutation tests: 8 scenarios × 3 replays and 5 permutations each, all pass.
- C1-F: 6 scenarios × 2 replays and 8 permutations, byte-identical.
- The engine import allowlist test still passes (no I/O, clock, randomness or environment).

## 12. C-3 resolution

`throttle.quota_limited` is added to AB.R3's feature list in `labels.json`, and §8.7 now states that AB.R3 covers every Required and Primary feature of the infrastructure labels. A new contract test checks that property for all six infrastructure labels.

The M2 engine's citation filter, the C-3 workaround, is removed. The cpu_throttling family item can now cite the CT.R1 measurement. Throttling semantics are unchanged.

## 13. Files changed

| File | Change |
|---|---|
| `docs/EVIDENCE_CONTRACT.md` | v0.3.0-draft text (§5) |
| `docs/PHASE_1C_C1_REPORT.md` | new: this report |
| `src/sentinelai/diagnostic/contract/catalog.py` | Primary role, Subordination, clause helpers |
| `src/sentinelai/diagnostic/contract/models.py` | Candidate CONTRIBUTING rule; Primary items support their label |
| `src/sentinelai/diagnostic/contract/validate.py` | CONTRIBUTING check, `_check_subordination` |
| `src/sentinelai/diagnostic/contract/version.py` | 0.3.0-draft |
| `src/sentinelai/diagnostic/contract/data/labels.json` | RT.R2 role and subordination, AB.R3 feature, version |
| `src/sentinelai/diagnostic/contract/data/{registry,predicates,parameters}.json` | version only |
| `src/sentinelai/diagnostic/rules/engine.py` | subordinate-only path, self-check, LOSS.LOCAL citation fix, C-3 filter removed, rules version |
| `tests/evidence/test_revision_v030.py` | new (12 tests) |
| `tests/rules/test_c1.py` | new (17 tests) |
| `tests/evidence/test_registry.py`, `tests/evidence/test_schema.py` | version assertions |
| `tests/rules/{_fixtures,test_adversarial,test_determinism,test_invariants,test_precedence}.py` | updated per §8 |

`experiments/faultlab/` is untracked, untouched and not committed. The M2 report is left as the historical record.

## 14. Commit hash

One commit: `fix(contract): resolve retransmission contribution semantics`. Its hash is reported in the final gate response and by `git log -1`; a commit can't contain its own hash.

## 15. Remaining ambiguities (non-blocking)

1. **Version number.** By §12's letter a role change is a major bump. The 0.2.0-draft precedent was followed (0.3.0-draft), and the reviewer may ratify or change it.
2. **Subordinate under a non-primary chain.** With softirq + CPU_BACKLOG drops + retransmissions, tcp is SUPPORTED_NOT_SUFFICIENT, not CONTRIBUTING. Loss is itself only contributing (PR-2), and the contract defines no transitive contribution. This was a deliberate choice not to invent one. If the reviewer wants causal chains, that needs a new §9 rule.
3. **Status of tcp when its primary is not the decision.** It is now SUPPORTED_NOT_SUFFICIENT where M2 reported NOT_SUPPORTED. RT.R2 is no longer required for contributing, so the label's own evidence (RT.R0, RT.R1) is reported as supported but not sufficient.
4. **Housekeeping carried over.** `PHASE_1C_DESIGN.md` still names contract v0.1.0-draft. C-2 (no IMPACT items) is unchanged and outside this gate's scope.

## 16. Safety audit and gate

**Safety.** This milestone made no host changes:
- no network, qdisc or tc change; the NIC enp0s31f6 was not touched;
- no Docker, systemd or kernel changes;
- no packages installed, and FaultLab was not executed.

Work was limited to editing source, data and docs and running tests in-process. Mutation runs used only the session scratchpad.

**Scope.** No M3, collectors, eBPF, Prometheus, Kubernetes, ML, LLM, RAG, MCP, agents, remediation or calibration. The keyword grep over the diff and new files (ollama, openai, anthropic, kubernetes, prometheus, ebpf, bpftrace, bcc, faultlab, docker, subprocess, requests, httpx, agent, mcp, rag) has no hits.

**Gate: PASS.** Every PASS criterion is met:
- C-1 is resolved in the contract, schema rules and engine;
- ADV-5 fully passes;
- I1–I7 hold, with I2 and I4 at least as strict;
- all regression tests pass;
- determinism holds;
- 27/27 focused mutants are killed and no meaningful survivor remains in the changed semantics;
- no scope violation occurred.

The §15 items are reviewer decisions or pre-existing housekeeping, not defects.
