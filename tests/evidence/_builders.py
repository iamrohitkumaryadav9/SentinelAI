"""Builders producing VALID contract objects through the public API only.

Tests derive invalid objects from these (via model_copy-free reconstruction with changed
fields) and assert rejection. Builders never bypass validation.
"""

from datetime import datetime, timedelta, timezone

from sentinelai.diagnostic.contract import (FAULT_LABELS, BaselineMethod, BaselineStat, Candidate, CandidateStatus,
                                            ConfidenceLevel, DataQuality, Deviation, DiagnosticResult, EngineInfo,
                                            EvidenceItem, EvidenceKind, EvidenceSnapshot, Label, Measurement,
                                            MissingMeasurement, Provenance, Quality, Strength, Target, Threshold,
                                            Window, evidence_item_id, load_contract, measurement_id, snapshot_id)

C = load_contract()
T0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)
PARAM_SET = "test-params-0000"


def ts(s):
    return T0 + timedelta(seconds=s)


def window(start_s=60.0, dur=10.0, period=1.0):
    return Window(start=ts(start_s), end=ts(start_s + dur), duration_s=float(dur), sample_period_s=float(period))


INC = window(60.0, 10.0)
BASE = window(15.0, 45.0)


def baseline(median=1.0, mad=0.5, p99=2.0, n=45, adequate=True, method=BaselineMethod.within_run, bid=None, win=None):
    return BaselineStat(method=method, window=win or BASE, median=median, mad=mad, p99=p99, n=n,
                        adequate=adequate, baseline_id=bid)


def deviation_for(value, b, floor=0.1):
    den_r, den_z = max(b.median, floor), max(1.4826 * b.mad, floor)
    return Deviation(ratio=value / den_r, delta=value - b.median, robust_z=(value - b.median) / den_z, floor_used=floor)


def prov(feature_id, samples=10, last=None, derived_from=(), source=None):
    spec = C.registry.get(feature_id)
    src = source or spec.sources[0]
    return Provenance(source=src, locator=spec.locator, collector="test-collector", collector_version="0.0.0",
                      privileged=spec.privileged, first_sample_at=min(INC.start, last or INC.end), last_sample_at=last or INC.end,
                      samples=samples, derived_from=tuple(derived_from))


def meas(feature_id, scope, value=2.0, quality=Quality.OK, coverage=1.0, base="auto", dev="auto",
         win=INC, aggregation=None, unit=None, provenance=None, qualifier=None):
    spec = C.registry.get(feature_id)
    b = baseline() if base == "auto" else base
    if dev == "auto":
        d = deviation_for(value, b) if (value is not None and b is not None) else None
    else:
        d = dev
    return Measurement(measurement_id=measurement_id(feature_id, scope, win, qualifier), feature_id=feature_id, scope=scope,
                       window=win, aggregation=aggregation or spec.aggregations[0], unit=unit or spec.unit,
                       value=value, quality=quality, coverage=coverage, baseline=b, deviation=d,
                       provenance=provenance or prov(feature_id, samples=0 if value is None else 10), qualifier=qualifier)


def item(predicate_id, kind, measurements, supports=(), contradicts=(), strength="auto", observed=None,
         threshold=None, missing_reason=None):
    if strength == "auto":
        strength = None if kind in (EvidenceKind.MISSING, EvidenceKind.CONFLICTING) else Strength.STRONG
    if kind is EvidenceKind.MISSING and missing_reason is None:
        missing_reason = "source unavailable"
    mids = tuple(m.measurement_id for m in measurements)
    return EvidenceItem(item_id=evidence_item_id(predicate_id, mids), predicate_id=predicate_id, kind=kind,
                        strength=strength, measurement_ids=mids, observed=observed, threshold=threshold,
                        supports=tuple(supports), contradicts=tuple(contradicts), missing_reason=missing_reason,
                        rationale=C.render_rationale(predicate_id, kind, strength, observed, threshold))


TARGET = Target(name="lab-A", cgroup_path="/system.slice/docker-abc.scope", pids=(4321,), cpuset="20-21",
                netns_ref="pid:4321", ifaces=("eth0",))


def dq(**kw):
    d = dict(overall_coverage=1.0, sources_unavailable=(), privileged_sources_unavailable=("EBPF",),
             baseline_adequate=True, counter_resets=0, gate_passed=True)
    d.update(kw)
    return DataQuality(**d)


def snapshot(measurements=(), items=(), missing=(), conflicts=(), target=TARGET, win=INC, base_win=BASE, **kw):
    measurements = tuple(measurements)
    missing = tuple(missing) + tuple(MissingMeasurement(feature_id=m.feature_id, scope=m.scope, reason="unavailable",
                                                        qualifier=m.qualifier)
                                     for m in measurements if m.quality is Quality.MISSING
                                     and (m.feature_id, m.scope, m.qualifier) not in
                                     {(x.feature_id, x.scope, x.qualifier) for x in missing})
    fields = dict(schema_version="0.2.0", contract_version="0.2.0-draft", parameter_set_id=PARAM_SET,
                  snapshot_id=snapshot_id(target, win, measurements), incident_id=None, target=target, window=win,
                  baseline_window=base_win, measurements=measurements, evidence_items=tuple(items),
                  missing_measurements=missing, conflicts=tuple(conflicts), data_quality=dq())
    fields.update(kw)
    return EvidenceSnapshot(**fields)


def candidate(label, status=CandidateStatus.NOT_SUPPORTED, met=(), supporting=(), contradicting=(), rules=()):
    req = [c.clause_id for c in C.labels.required_clauses(label)]
    return Candidate(label=label, status=status, required_met=tuple(met),
                     required_missing=tuple(r for r in req if r not in met), supporting=tuple(supporting),
                     contradicting=tuple(contradicting), rules_fired=tuple(rules))


def all_met(label):
    return tuple(c.clause_id for c in C.labels.required_clauses(label))


ENGINE = EngineInfo(contract_version="0.2.0-draft", rules_version="test", parameter_set_id=PARAM_SET, code_commit="1a0f87b")


def result(snap, decision=Label.INSUFFICIENT_EVIDENCE, cands=None, reasons=None, confidence=None, contributing=(),
           rules=(), ml=None, engine=ENGINE):
    cands = cands or {}
    full = tuple(cands.get(l) or candidate(l) for l in FAULT_LABELS)
    ins = decision is Label.INSUFFICIENT_EVIDENCE
    if reasons is None:
        from sentinelai.diagnostic.contract import AbstentionReason
        reasons = (AbstentionReason.NO_CANDIDATE,) if ins else ()
    return DiagnosticResult(snapshot_id=snap.snapshot_id, decision=decision, contributing=tuple(contributing),
                            abstained=ins, abstention_reasons=tuple(reasons),
                            confidence_level=confidence or (ConfidenceLevel.LOW if ins else ConfidenceLevel.HIGH),
                            candidates=full, rules_fired=tuple(rules), ml=ml, engine=engine)


def rebuild(model, **changes):
    """Re-validate a model with some fields replaced (never mutates; goes through validation)."""
    data = {k: getattr(model, k) for k in type(model).model_fields}
    data.update(changes)
    return type(model)(**data)
