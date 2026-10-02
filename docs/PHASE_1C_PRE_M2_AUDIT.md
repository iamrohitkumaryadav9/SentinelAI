# Phase 1C — Pre-M2 Contract Audit & FaultLab Inspection

| Field | Value |
|---|---|
| Date | 2026-10-02 |
| Type | **Read-only audit.** No code, contract or test was modified; nothing was committed. This file is the only new file. |
| Authoritative sources | `docs/EVIDENCE_CONTRACT.md` v0.1.0-draft, `docs/PHASE_1C_DESIGN.md`, M1 implementation `33aed1b` |
| Gate | **GO WITH CONDITIONS** (§13) |

---

## 1. Git state

| Check | Result |
|---|---|
| `git log -1 --oneline` | `33aed1b feat(contract): implement phase1c evidence contract` ✅ |
| `git status --short` | `?? experiments/faultlab/` only ✅ |
| `git show --stat HEAD` | 26 files, 4,827 insertions (M1 files only) ✅ |
| Tracked modifications / staged changes | None ✅ |

## 2. FaultLab inspection (source only; nothing executed)

**Contents:**

| File | Size | Content |
|---|---|---|
| `experiments/faultlab/docker/Dockerfile` | 309 B | `FROM python:3.10-slim`; `apt-get install --no-install-recommends iproute2 iperf3 procps stress-ng`; `COPY workload.py /opt/workload.py` |
| `experiments/faultlab/docker/workload.py` | 67 B | A docstring placeholder only. No executable code. |

**Related host state** (inspected read-only):
- the local image `sentinelai/faultlab:probe` (526 MB, built 21:34 during the Phase 1C feasibility probe);
- no containers or Docker networks from the probe remain (`s1c_*` and `sl_faultlab_*`: none).

**Answers:**

1. **What exists?** An image definition and a placeholder file, nothing more.
2. **Prototype status.** Both files are prototype or feasibility artefacts.
3. **Consistency with design §6.1.** The Dockerfile matches the design's intended image contents (python:3.10-slim plus iproute2, iperf3, procps, stress-ng). There is no workload, load generator, topology, injector, verifier, scenario format or labelling.
4. **Reusable for M4.** Only the Dockerfile skeleton. `workload.py` must be written from scratch.
5. **Conflict with the M1 contract.** None. No file references or produces contract objects.
6. **Host-network, NIC, qdisc or privileged changes.** None in these files. The image *contains* `iproute2` (`tc`), which M4 will use only inside lab namespaces; installing a tool is not an action.
7. **Unsafe or irreversible operations.** None.
8. **Safe to preserve?** **Yes.**

**Issues (non-blocking; to fix when M4 starts, not now):**
- **F-1. Inaccurate comment.** The Dockerfile comment says "*Pinned base by digest at build time (see build log)*", but `FROM python:3.10-slim` is a floating tag and no build log was recorded. The design (§8) requires recording the image digest per run, so M4 must pin the base by digest and pin apt package versions, or record them.
- **F-2. Unrecorded image.** The `sentinelai/faultlab:probe` image was built from an unpinned base. It is not a reproducible artefact and should not be used for M6 data collection.

## 3–6. Contract issues D-1 … D-4

### D-1: unlimited CPU quota

```text
D-1 finding:
  GENUINE internal contradiction in the contract (not an M1 implementation error). The contract
  requires an outcome (CT.R1 NEGATIVE for an unlimited quota) that its own rules make unreachable.

Evidence from contract:
  §4.2  throttle.quota_cores: "cgroup cpu.max → quota/period. The literal `max` means unlimited (`null`)."
  §8.2  CT.R1: "`throttle.quota_cores` is not null (a finite quota exists)."
  §8.2  Insufficient: "Quota `max` (unlimited) → CT.R1 FALSE, which is NEGATIVE."
  §10.3 Measurement.value: "`null` iff `quality ∈ {MISSING, INVALID}`".
  §3 E1 "A predicate whose inputs are MISSING MUST yield MISSING. It MUST NOT yield NEGATIVE."

Conflict:
  Under §10.3 an unlimited quota can only be represented with quality MISSING or INVALID. E1
  then forces CT.R1 = MISSING, contradicting §8.2 (NEGATIVE). Consequence for M2:
  - for every container without a quota (the most common case), cpu_throttling becomes
    NOT_EVALUABLE instead of NOT_SUPPORTED;
  - per design §5.1 step 6, a clean control run whose only non-unsupported candidate is
    cpu_throttling would abstain with REQUIRED_EVIDENCE_MISSING instead of NO_CANDIDATE, so
    normal systems are reported as having missing data;
  - throttle.quota_saturation (usage / quota) is undefined in the same case. It is legitimately
    MISSING, but it shares the same root cause.

  Meaning of `cpu.max = max`: the cgroup has NO CFS bandwidth limit (no quota). It is a
  configuration state, not a measurement failure, so it is neither MISSING nor INVALID.

  The feature conflates two things: quota presence (a configuration state) and the quota size
  (a number that exists only when a quota exists). CT.R1 needs presence; CT.R2 and
  quota_saturation need the size.

Options:
  O1  Add a feature `throttle.quota_limited` (gauge, 1.0 = finite quota, 0.0 = unlimited) with a
      new Unit `boolean` (values restricted to {0.0, 1.0}). CT.R1 := quota_limited == 1.
      `throttle.quota_cores` is emitted only when a quota exists; when quota_limited = 0,
      quota_cores is NOT emitted (absent by definition, not MISSING).
  O2  Add a Quality value `NOT_APPLICABLE` (value null, distinct from MISSING). CT.R1 is FALSE
      when quota_cores is NOT_APPLICABLE. This changes the general missing-data model for all
      features.
  O3  Sentinel numbers (0, the host CPU count, +inf). These violate P2, finite-float validation
      and "never encode a state as a number". Not acceptable.

Recommended contract decision:
  O1. It keeps the general missing-data model (§10.3, E1) untouched, gives "no quota" an
  explicit, measured, positive representation (a configuration read from cpu.max, quality OK),
  and confines the change to the throttling family. O2 would introduce a new general state into
  every predicate's three-valued logic for a single use case.

Required schema change:
  - Unit enum: add `boolean` (validator: value ∈ {0.0, 1.0}).
  - Registry: add `throttle.quota_limited` (family cpu_throttling, scope cgroup, GAUGE, CGROUPFS,
    locator `cpu.max`). Remove "(`null`)" from the §4.2 quota_cores row and state "emitted only
    when quota_limited = 1".
  - Clause CT.R1: features = [throttle.quota_limited]; definition "a finite quota exists
    (quota_limited = 1)". CT.R1 is FALSE (NEGATIVE) when quota_limited = 0, and MISSING only
    when cpu.max is unreadable.
  - Optional invariant (snapshot level): a quota_cores measurement with a value must not
    coexist with quota_limited = 0.

Required test changes:
  - test_registry: the expected feature list gains throttle.quota_limited; CT.R1 features updated.
  - test_schema: the Unit enum gains `boolean`.
  - New tests: boolean value ∉ {0, 1} rejected; an unlimited quota is representable as
    quota_limited = 0 with quality OK; a CT.R1 NEGATIVE item on it is valid;
    quota_cores + quota_limited = 0 together are rejected (if the invariant is adopted).

Version impact:
  Changes the Required clause CT.R1. Per contract §12 that is a MAJOR change.
```

### D-2: `mem.reclaim.target`

```text
D-2 finding:
  GENUINE ambiguity (underspecified feature definition), not a contradiction. M1 resolved it with
  a documented assumption (pgscan) that is safe for the current predicate.

Evidence from contract:
  §4.6  `mem.reclaim.target` | cgroup memory.stat Δ(pgscan), Δ(pgsteal) | pages/s | rate
  §6    RECLAIM_MIN: "Reclaim / refault rates"
  §8.6  MP.R1 (third alternative): DEV(mem.reclaim.target) ∧ ABS(mem.reclaim.target, RECLAIM_MIN)
        ∧ (DEV(mem.refault.target) ∨ DEV(mem.majfault.target))

Conflict:
  One feature ID, two counters, one unit, no combination rule. pgscan (pages scanned by reclaim)
  and pgsteal (pages actually reclaimed) are NOT interchangeable:
  - scan is reclaim EFFORT and rises with pressure even when little is freed;
  - steal is reclaim OUTPUT;
  - their ratio (steal/scan) is reclaim efficiency, and a falling ratio means harder reclaim.
  MP.R1 needs a single "reclaim activity" magnitude. No predicate in §8 uses pgsteal or the
  efficiency ratio.

Options:
  O1  Define mem.reclaim.target := Δpgscan rate (reclaim effort). No new feature.
  O2  O1, plus add `mem.reclaim_steal.target` := Δpgsteal rate as an optional supporting feature
      (minor). MP.R1 is unchanged.
  O3  Split into `mem.reclaim.pgscan` / `mem.reclaim.pgsteal` and rewrite MP.R1. Renaming
      changes a Required clause (major) without a predicate need.
  O4  A derived efficiency ratio: no current predicate needs it.

Recommended contract decision:
  O1, i.e. clarify §4.6 so that mem.reclaim.target is the Δpgscan rate. Adding pgsteal (O2) is
  justified only if a supporting predicate is defined for it; none is today, so it should not be
  added speculatively.

Required registry change:
  Locator / definition text only: "cgroup memory.stat Δ(pgscan)". The M1 registry already
  measures pgscan; only its locator note referencing this audit would be updated. ID, unit,
  aggregation and source are unchanged.

Required predicate impact:
  None. MP.R1 keeps using mem.reclaim.target. RECLAIM_MIN is calibrated on the pgscan rate.

Version impact:
  A clarification of an existing feature's definition with no ID, clause or semantic expansion:
  PATCH under §12's spirit. (§12 names minor/major cases only; a pure clarification is below
  minor.) If O2 is chosen, MINOR (feature addition).
```

### D-3: reason-qualified `kfree_skb` (and per-code `app.events`)

```text
D-3 finding:
  GENUINE schema gap. The contract's packet-loss and precedence rules require a per-reason
  qualifier that the Measurement schema cannot express. The same gap affects app.events (per code).

Evidence from contract:
  §1 P4   "`kfree_skb > 0` is not packet-loss evidence (§8.4)."
  §4.3    net.drop.kfree_skb: "eBPF skb:kfree_skb, by drop reason … packets/s per reason"
  §6      KFREE_REASONS_LOSS: "Set of kfree_skb drop reasons attributable to path loss …
          NOT_SPECIFIED is excluded."
  §8.4    LOSS.LOCAL includes net.drop.kfree_skb[r ∈ KFREE_REASONS_LOSS]. NOT_SPECIFIED or any
          other reason "never satisfies PL.R1"; it may only be a WEAK supporting item.
  §9 PR-2 resolution depends on kfree_skb reason CPU_BACKLOG.
  §4.7 / §8.7 AB.R1: DEV(app.events[code]) "for a code in the closed set" (POOL_EXHAUSTED,
          QUEUE_FULL, LOCK_WAIT_EXCEEDED, DEPENDENCY_TIMEOUT).
  Design ADV-1: fixture "kfree_skb 3/s NOT_SPECIFIED at baseline".

Why total counts are not sufficient:
  - The total mixes benign or unattributable reasons (NOT_SPECIFIED, normal-free paths) with
    loss-attributable ones (e.g. QDISC_DROP, CPU_BACKLOG, NETFILTER_DROP). That is exactly the
    Phase 1B failure (3/s background noise read as proof of loss).
  - If a total could satisfy PL.R1, background noise creates false-positive packet loss.
  - If totals are excluded (the only safe M2 behaviour today), the contract cannot express PL.R1
    via kfree_skb at all, cannot evaluate PR-2's CPU_BACKLOG case, and cannot build the ADV-1
    fixture as specified. AB.R1's per-code app.events predicate is likewise inexpressible.
  Total counts are therefore neither safe as evidence nor sufficient for the specified rules.

Options:
  O1  An optional `qualifier` field on Measurement: {dimension, value}. Each registry feature
      declares whether it has a dimension (kfree_skb: "reason", pattern ^[A-Z0-9_]+$; app.events:
      "code", closed set). It is forbidden for features without a declared dimension.
  O2  One feature ID per reason or code (e.g. net.drop.kfree_skb.qdisc_drop). This multiplies
      registry entries for an open, kernel-version-dependent reason set (dozens of reasons).
  O3  Encode the reason in the scope string (e.g. netns:A#reason=X). This overloads scope
      (location) with a value dimension and breaks scope parsing and semantics.

Recommended contract decision:
  O1: a single, general, registry-governed qualifier. It applies only to features that declare
  a dimension (today exactly net.drop.kfree_skb and app.events), so it cannot leak into other
  features. Unqualified features keep their current representation.

Required Measurement change:
  - Measurement: `qualifier: Optional[Qualifier] = None`, where Qualifier = {dimension: str,
    value: str}, strict and frozen.
  - Validation: qualifier is required iff the registry feature declares a dimension; the
    dimension must match; the value must match the declared closed set or pattern.
  - Identity: measurement_id = sha1({kind, feature_id, scope, window, qualifier}). The qualifier
    key is included only when non-null, so the IDs of all existing unqualified measurements stay
    byte-identical. Snapshot uniqueness and missing_measurements entries become
    (feature_id, scope, qualifier).

Required predicate/registry impact:
  - Registry feature schema: add `dimension: Optional[{name, values | pattern}]`.
  - Predicate grammar: allow a qualified argument, e.g. PL.R1/LOSS.LOCAL[net.drop.kfree_skb],
    with the reason carried by the referenced measurement's qualifier. No grammar change is
    needed if the reason lives on the measurement.
  - Parameter typing (finding A-1, below): KFREE_REASONS_LOSS is set-valued and must be typed
    as such in parameters.json. It must not be usable as a numeric Threshold.

Version impact:
  Adds an optional field and a registry attribute. Existing unqualified objects and IDs are
  unchanged. No Required clause changes (§8.4 already demands reason filtering): MINOR.
```

**Additional finding A-1 (related to D-3).**
- **The gap.** `parameters.json` lists `KFREE_REASONS_LOSS`, a set of reason names (contract §6), alongside numeric parameters, and M1's `Threshold` model is `{parameter, value: float}`. So `Threshold(parameter="KFREE_REASONS_LOSS", value=3.0)` currently validates, which is meaningless.
- **Is it a defect?** It's not a correctness defect in any existing invariant (no M1 object uses it), but parameter *typing* is missing.
- **Fix:** together with D-3. Mark each parameter's type (`number` or `reason_set`) and reject set-valued parameters in `Threshold`. This is a **minor** change.

### D-4: diagnostic flags

```text
D-4 finding:
  GENUINE schema gap. Two named, decision-relevant flags have no field in DiagnosticResult.

Evidence from contract:
  §7    "If IMPACT is MISSING … evaluation proceeds, but confidence is capped at MEDIUM and reason
        `IMPACT_NOT_MEASURED` is recorded."
  §10.9 MEDIUM includes "impact not measured".
  Design §5.4 "If ML disagrees with calibrated probability ≥ τ_DISAGREE, a `ML_DISAGREEMENT` flag
        is added and confidence is lowered by one level, never below MEDIUM for an asserted
        decision."
  §10.6 DiagnosticResult fields: no flags field. AbstentionReason (§8.8) does not contain either.

Semantic role:
  Both are DIAGNOSTIC (production) metadata about the decision of record. Each explains why the
  confidence_level is what it is. They are not abstentions (the decision may be asserted), not
  software provenance, and not evaluation (ground-truth) data.

Options:
  O1  DiagnosticResult.flags: tuple[DiagnosticFlag, ...], a closed enum
      {IMPACT_NOT_MEASURED, ML_DISAGREEMENT}, default (), with invariants:
        IMPACT_NOT_MEASURED ⇒ confidence_level ≠ HIGH;
        ML_DISAGREEMENT ⇒ ml is not null ∧ ml.agrees_with_rules = false.
  O2  Put them in abstention_reasons: wrong. It breaks I1 (an asserted decision would have
      reasons).
  O3  Put them in EngineInfo: wrong. EngineInfo is per-engine provenance, not per-decision state.
  O4  Keep them implicit (derive IMPACT_NOT_MEASURED from the snapshot's IMPACT item, and
      ML_DISAGREEMENT from ml + τ_DISAGREE): the result alone could no longer explain its own
      confidence, and τ_DISAGREE is not recorded anywhere.

Recommended contract decision:
  O1. A closed enum keeps the coupling minimal (two values, each with a checkable invariant).
  Evaluation-only information (ground-truth correctness, FaultLab labels, scores) stays outside
  DiagnosticResult. ML_DISAGREEMENT can be defined now and is only ever set from M7 onward.

Required schema change:
  - enums: DiagnosticFlag {IMPACT_NOT_MEASURED, ML_DISAGREEMENT}
  - DiagnosticResult: flags: Tuple[DiagnosticFlag, ...] = () plus the two invariants above
  - parameters.json: add τ_DISAGREE (symbolic; design §5.4 uses it but contract §6 omits it).
    That is a MINOR parameter addition.

Version impact:
  An optional field with a default: existing results remain valid. MINOR.
```

## 7. Cross-check against M1

| Issue | A. Correctly represents intended contract | B. Exposes ambiguity, remains safe | C. Incorrect semantic assumption | D. Requires modification before M2 |
|---|---|---|---|---|
| D-1 | No: the contract is self-contradictory, and M1 follows §10.3 / E1 | **Yes.** M1 never fabricates a value for an unlimited quota. | No | **Yes.** M2 would mislabel abstention reasons (§3 above). |
| D-2 | Partly: pgscan is the defensible reading | **Yes**, and documented in the registry | No (pgscan is what MP.R1 needs) | **No** (a definition-text clarification only) |
| D-3 | No: reason/code is inexpressible | **Yes.** Totals cannot satisfy anything yet, because M1 has no predicate evaluation. | No | **Yes.** PL.R1 (kfree), PR-2 and the ADV-1 fixture need it. |
| D-4 | No: there is no destination | **Yes.** Nothing is recorded wrongly. | No | **Yes** for IMPACT_NOT_MEASURED (an M2 behaviour); ML_DISAGREEMENT could wait for M7 but costs nothing to add with it. |
| A-1 | Partly | **Yes** (no M1 object uses set-valued parameters) | No | **Yes**, with D-3 |

**Conclusion.** No concrete correctness defect in M1: M1 implements the written contract faithfully. All the problems are contract-level, and their fixes require coordinated contract **and** M1 schema changes before M2.

## 8. M1 test result

`PYTHONNOUSERSITE=1 .venv/bin/python -m unittest discover -s tests/evidence -t tests`: **146 run, 146 passed, 0 failed, 0 skipped.** `git status` is unchanged after the run (only `?? experiments/faultlab/`).

## 9. Exact recommended contract decisions

| # | Decision | Contract sections |
|---|---|---|
| R-1 (D-1) | Add the feature `throttle.quota_limited` (Unit `boolean`, values {0, 1}). CT.R1 := quota_limited = 1. `quota_cores` is emitted only when a quota exists. §4.2 no longer says "(null)". | §4.2, §8.2, §10.1 (Unit) |
| R-2 (D-2) | Define `mem.reclaim.target` := Δ`pgscan` rate. No new feature unless a supporting predicate is defined for pgsteal. | §4.6 |
| R-3 (D-3) | An optional, registry-governed `Measurement.qualifier` {dimension, value}. Dimensions: `net.drop.kfree_skb` → `reason` (pattern), `app.events` → `code` (closed set). Included in `measurement_id` only when present. | §4.3, §4.7, §10.3, §10.5 (uniqueness) |
| R-4 (A-1) | Type every parameter (`number` or `reason_set`); `Threshold` accepts numeric parameters only. Add `τ_DISAGREE`. | §6, §10.4 |
| R-5 (D-4) | `DiagnosticResult.flags` (closed enum {IMPACT_NOT_MEASURED, ML_DISAGREEMENT}) with two invariants | §10.6, §10.7 |
| R-6 (version) | Per §12, R-1 changes a Required clause and is **major**; R-3, R-4 and R-5 are minor; R-2 is a patch-level clarification. Release them **together** as one contract version. | §12 |

**Decision needed from the reviewer.** §12 is explicit: a Required-clause change is a major bump, which gives `1.0.0-draft`. The contract is still a pre-release draft with no consumers besides M1. Whether a draft may instead correct itself within 0.x (as `0.2.0-draft`) is a governance call this audit does not make. Either way, `version.require_compatible` and the tests must follow the chosen number.

## 10. Changes required before M2

1. An approved contract revision covering R-1 … R-5, with `EVIDENCE_CONTRACT.md` updated and the version bumped per R-6.
2. An M1-schema follow-up commit implementing it:
   - Unit `boolean`;
   - the `throttle.quota_limited` feature and the CT.R1 update;
   - the `Qualifier` model, the registry `dimension` attribute and the ID inclusion rule;
   - parameter typing plus `τ_DISAGREE`;
   - `DiagnosticFlag` and `DiagnosticResult.flags` with invariants;
   - the mem.reclaim locator text;
   - matching tests: expected feature list, enums, new negative tests, and a regression proving unqualified IDs are unchanged.
3. Updates to the M1 report and audit trail recording the revision.

## 11. Changes that should NOT be made

- Do not represent an unlimited quota as 0, the host CPU count, `+inf` or any sentinel number, and do not relabel it as MISSING.
- Do not let the total `kfree_skb` count satisfy any Required clause. Do not encode reasons in the scope string. Do not create per-reason feature IDs.
- Do not put diagnostic flags into `abstention_reasons` (that breaks I1) or into `EngineInfo`.
- Do not put evaluation or ground-truth information (FaultLab labels, correctness, scores) into `DiagnosticResult` or `EvidenceSnapshot`.
- Do not sum `pgscan` and `pgsteal`. Do not add pgsteal speculatively.
- Do not add a general `NOT_APPLICABLE` quality for a single use case.
- Do not modify M1 code before the contract revision is approved.
- Do not commit, delete or "clean up" `experiments/faultlab/` without an explicit decision. Do not use the unpinned `sentinelai/faultlab:probe` image for M6 data.

## 12. Safety findings

| Item | Finding |
|---|---|
| Physical NIC `enp0s31f6` | Not touched during this audit or by any FaultLab file |
| Host networking / qdisc / firewall | No changes. FaultLab files contain no network commands. |
| Docker | Read-only listing only. No containers or networks from the probe remain. One local image (`sentinelai/faultlab:probe`, 526 MB, unpinned base). |
| Privileged state / sudo | None |
| LLM / cloud / secrets | None |
| Repository writes | Only this file. No commit. |

## 13. PRE-M2 gate

**GO WITH CONDITIONS**

1. **The ambiguities are real but small.** D-1, D-3, D-4 and A-1 are genuine contract-level gaps, and D-2 is an ambiguity. None can be resolved from existing contract text alone (D-1 is self-contradictory). The decisions R-1 … R-5 are straightforward and localised.
2. **M1 is not defective,** but its schema must be revised in step with the contract before M2. That is why the gate is not GO.
3. **FaultLab is safe** to preserve and doesn't block M2. Issues F-1 and F-2 apply to M4.

**Conditions:**
- (a) The reviewer approves R-1 … R-5 and the version number (R-6).
- (b) The contract document and the M1 schema are updated in a separate, reviewed change, with all M1 tests updated and passing.
- (c) M2 starts only after (a) and (b).
