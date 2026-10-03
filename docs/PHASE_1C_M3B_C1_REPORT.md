# Phase 1C — M3B-C1 Report: Measurement-ID Aggregation Collision

| | |
|---|---|
| Base | `deab8336695d2a258c583e7949073f292943e624` (M3B-C0), contract `0.4.0-draft`, schema `0.2.0`, rules `m2-1.1.0` |
| Scope | Contract/model correction only. No M3B code, no BPF, no sudo, no network change. |
| Commit | Not committed; the change is left in the working tree for review. |
| Gate | **M3B-C1 CONTRACT REVISION GATE: GO** |

## A. The contradiction

The M3B build audit found that `sched.latency_hist.target` registers two aggregations, `[P50, P99]`, while §10.3 defined

```text
measurement_id = sha1(feature_id, scope, window[, qualifier])[:16]
```

The aggregation was not an identity input. P50 and P99 of the same cgroup and window therefore had the **same** id (`c65b98c14b00219a` in the audit's reproduction), and `EvidenceSnapshot` rejected the pair as `duplicate measurement ids`. Only one percentile could ever be carried, which contradicts the registry entry and the M3B-C0 decision (G-1: "P50 and P99").

The same latent defect affected the other two multi-aggregation features, `app.latency_ms` (P50, P99) and `tcp.srtt_ms` (P50, P90). The M2 engine already selects by aggregation (`v.one("app.latency_ms", Aggregation.P99)`), so coexistence was intended.

## B. Decision (Option A) and the new rule

The reviewer approved Option A: the aggregation is part of identity **whenever the feature registers more than one aggregation**.

| | Rule |
|---|---|
| Old (≤ 0.4.0) | `sha1(canonical_json({kind, feature_id, scope, window[, qualifier]}))[:16]` |
| New (0.5.0) | `sha1(canonical_json({kind, feature_id, scope, window[, qualifier][, aggregation]}))[:16]`, where `aggregation` (its value string, e.g. `"P99"`) is present **iff** `len(registry[feature_id].aggregations) > 1` |

Properties:

- The registry is the only authority (`ids._identity_aggregation`). No feature is special-cased.
- For a multi-aggregation feature the aggregation is **required**: computing its id without one raises `ValueError` rather than producing an ambiguous id.
- For a single-aggregation feature the aggregation is ignored even if passed, so the id is byte-identical to 0.4.0.
- An unregistered feature keeps the pre-0.5.0 identity. `Measurement` already rejects unknown features (I5).
- Whether an aggregation is *allowed* for a feature is still checked only by `Measurement` (registry agreement). Rejection paths for wrong aggregations are unchanged.
- The aggregation is a named canonical input, like the qualifier. It cannot alias a scope, window or qualifier value.

## C. Files changed

| File | Change |
|---|---|
| `src/sentinelai/diagnostic/contract/ids.py` | New `_identity_aggregation`; `measurement_id(..., qualifier=None, aggregation=None)` |
| `src/sentinelai/diagnostic/contract/models.py` | `Measurement` identity check passes `self.aggregation` |
| `src/sentinelai/collectors/snapshot.py` | Passes the aggregation it already emits (`spec.aggregations[0]`) to `measurement_id`. No emitted id changes (§E). |
| `src/sentinelai/diagnostic/contract/version.py` | `CONTRACT_VERSION = "0.5.0-draft"` |
| `src/sentinelai/diagnostic/contract/data/{registry,labels,predicates,parameters}.json` | `contract_version` only |
| `docs/EVIDENCE_CONTRACT.md` | Header, revision history (0.5.0 row), §10.3 `measurement_id` row, §12 0.5.0 note |
| `tests/evidence/_builders.py`, `tests/rules/_fixtures.py` | Pass the aggregation the builder already chose to `measurement_id`. This is required by the new API, not a change of assertion. |
| `tests/evidence/{test_registry,test_schema,test_revision_v030,test_revision_v040}.py`, `tests/rules/test_determinism.py`, `tests/collectors/test_snapshot.py`, `tests/rules/_fixtures.py` | Current-version strings `0.4.0-draft` → `0.5.0-draft` (the same set M3B-C0 updated) |
| `tests/evidence/test_revision_v050.py` | New, 21 tests |
| `tests/rules/test_m3b_c1.py` | New, 2 tests (M2 with coexisting percentiles) |
| `docs/PHASE_1C_M3B_C1_REPORT.md` | This report |

No existing test assertion was changed other than version strings. Before the builder update, 68 tests errored with the single cause `app.latency_ms registers several aggregations; its measurement id requires one`. Those builders construct `app.latency_ms` at P99, and the error is the new rule correctly refusing an aggregation-free id.

## D. Tests proving the correction (`test_revision_v050.py`, `rules/test_m3b_c1.py`)

| Brief | Test | Result |
|---|---|---|
| A | `sched.latency_hist.target` P50 id ≠ P99 id | pass |
| B | same feature, scope, window and aggregation → same id (repeated; enum ≡ value string) for all 3 features | pass |
| C | `app.latency_ms` P50 ≠ P99; `tcp.srtt_ms` P50 ≠ P90 | pass |
| D | 5 named single-aggregation goldens unchanged; digest over **all 66** single-aggregation ids unchanged; passing the registered aggregation does not change them; earlier-revision goldens (`f5655a2e95cd366b`, `532a853e8f355a90`, `b6deeaf7d4a52987`, `6c8aedfe03f180d6`) hold | pass |
| E | one `EvidenceSnapshot` with `sched.latency_hist.target` P50 **and** P99 (same scope, window, no qualifier) is accepted; one with all 6 multi-aggregation measurements is accepted; true duplicates (same aggregation, or same kfree reason) are still rejected | pass |
| F | no collision across feature × scope × window × aggregation (24 ids, all distinct, none equal to any single-aggregation id); aggregation × qualifier on a patched registry where `net.drop.kfree_skb` registers RATE+MAX (4 distinct ids, none equal to the unpatched ids); P99-as-aggregation vs a scope containing `P99` | pass |
| — | known-answer encoding (`{"aggregation":"P99",...}` named input) | pass |
| — | multi-aggregation id without aggregation → `ValueError` | pass |
| — | every new multi-aggregation id differs from its 0.4.0 aggregation-free id; a measurement carrying the old id, or the other percentile's id, is rejected | pass |
| — | wrong aggregations (`MAX` for latency_hist, `P99` for srtt) still rejected by `Measurement` | pass |
| — | whole `registry.json` minus `contract_version` byte-identical to `deab833` (sha256 `5190131f…`); labels, predicates and parameters pinned by `test_revision_v040` | pass |
| — | versions: contract `0.5.0-draft`, schema `0.2.0`, rules `m2-1.1.0`; 0.4.0-draft still compatible | pass |
| — | M3A emits no multi-aggregation feature (so no collector id changes) | pass |
| M2 | adding an extreme `app.latency_ms` P50 next to P99 changes no decision, flag, confidence, candidate, abstention reason or evidence item (with and without impact); the impact gate reads P99, not P50 | pass |

**Golden-ID results.** All single-aggregation goldens are unchanged. The 66-feature digest is `37bb8ce6…`, computed from the 0.4.0 code before the change and reproduced after it.

**Snapshot coexistence.** `sched.latency_hist.target` P50 + P99 in one snapshot: **accepted**, with 2 distinct ids.

## E. Regression

```text
Focused (test_revision_v050):      21/21
Focused (rules/test_m3b_c1):        2/2
M1 (tests/evidence):              228/228   (207 + 21 new)
M2 (tests/rules):                  97/97    (95 + 2 new)
M3A (tests/collectors):           111/111
M3A-C1 (test_tc.py):               38/38
Full suite:                       460 run: 459 passed, 0 failed, 1 skipped (the pre-existing root-only bpftrace test)
```

## F. Mutation testing

The harness applies each mutant to a fresh copy of `src/` + `tests/` in a scratch directory (the repository is never mutated) and runs the full suite. `tests/test_phase1a.py` is excluded in the copies because it checks the real repository, venv and git; it is not contract logic. The unmutated control passes: 436/436.

| # | Mutant | Result |
|---|---|---|
| M1 | aggregation never part of identity (the old rule) | killed |
| M2 | aggregation always part of identity when given | killed |
| M3 | cardinality threshold `== 1` → `<= 2` | killed |
| M4 | cardinality test inverted | killed |
| M5 | multi-aggregation id without aggregation silently allowed | killed |
| M6 | special case: only `sched.latency_hist.target` keyed | killed |
| M7 | hash key renamed `aggregation` → `agg` | killed |
| M8 | aggregation stored under the `qualifier` key | killed |
| M9 | aggregation hashed lowercased | killed |
| M10 | `Measurement` validator omits the aggregation | killed |
| M11 | `Measurement` validator uses the first registered aggregation | killed |
| M12 | single-aggregation feature keyed when an aggregation is passed | killed |
| M13 | unregistered feature rejected instead of legacy identity | killed |
| M14 | contract version left at `0.4.0-draft` | killed |
| M15 | qualifier dropped when an aggregation is present | killed |

**15/15 killed, 0 survived.**

One further mutant is **equivalent** and is reported separately: E1, the collector omitting `aggregation=` from its `measurement_id` call. It survives, as expected. Every feature M3A emits is single-aggregation, so the argument cannot change any id. It only matters once a collector emits a multi-aggregation feature (M3B's `sched.latency_hist.target`), and M3B's own tests will cover that.

## G. Safety

No `sudo`, no BPF build, load or attach, no namespace or veth, no `tc`, no network change, no capability change, no package installed. The host still shows interfaces `lo`, `enp0s31f6`, `docker0`; `unprivileged_bpf_disabled = 2`; `perf_event_paranoid = 4`; session `CapEff = 0`. No `*.bpf.c`, `*.bpf.o`, `*.skel.h` or `vmlinux.h` exists in the repository. The untracked `experiments/faultlab/docker/{Dockerfile,workload.py}` are untouched.

## H. Limitations (actual)

1. **0.4.0 snapshots containing a multi-aggregation measurement** carry the aggregation-free id and fail 0.5.0 identity validation. None was ever produced: no collector emits these three features, and the defect prevented two percentiles from coexisting. Single-aggregation 0.4.0 snapshots are unaffected.
2. **M2 supporting predicate `DEV[tcp.srtt_ms]`** iterates every `tcp.srtt_ms` measurement. When P50 and P90 coexist it now emits one supporting item per aggregation. This is an observation, not a change: `tcp.srtt_ms` is not collected (no SS collector), the rules are unchanged (`m2-1.1.0`), and no current decision is affected. A later rules revision may choose to pin it to one aggregation.
3. **Derived references.** `Provenance.derived_from` is built from `(feature, scope)` pairs in the M3A collector. Deriving from a multi-aggregation feature would need the aggregation, and it now fails loudly (`ValueError`) rather than producing an ambiguous id. No derived feature references a multi-aggregation feature today.
4. The mutation harness lives in the session scratch directory and is not committed. The mutant table above is its complete list.

---

## M3B-C1 CONTRACT REVISION GATE: GO

- P50 and P99 of `sched.latency_hist.target` coexist in one snapshot.
- `app.latency_ms` and `tcp.srtt_ms` multi-aggregation ids are distinct.
- Every single-aggregation id is unchanged (66-feature golden digest, named goldens, earlier-revision goldens).
- Focused tests, M1, M2, M3A and M3A-C1 pass, and the full suite passes (460 run, 0 failed, 1 pre-existing skip).
- 15/15 mutants killed; 1 equivalent mutant reported.
- No feature, unit, source, qualifier, clause, predicate, parameter, precedence rule, schema or rules version changed.
- No M3B implementation has started.

**STOP.** M3B waits for explicit authorisation.
