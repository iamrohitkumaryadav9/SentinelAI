"""Strict Pydantic v2 models of the evidence contract (EVIDENCE_CONTRACT.md §10).

All models: ``extra="forbid"``, ``frozen=True``, ``strict=True``. No threshold values and no
predicate evaluation live here (M2). Validators enforce only what the contract states.
"""

import math
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Dict, Optional, Tuple

from pydantic import (AfterValidator, BaseModel, ConfigDict, Field, PlainSerializer, field_validator, model_serializer,
                      model_validator)


from . import ids
from .catalog import load_contract
from .enums import (FAULT_LABELS, AbstentionReason, Aggregation, BaselineMethod, CandidateStatus, ConfidenceLevel,
                    DiagnosticFlag, EvidenceKind, Label, Quality, ScopeKind, SourceType, Strength, Unit)
from .serialize import format_timestamp
from .version import SCHEMA_VERSION, require_compatible

STRICT = ConfigDict(extra="forbid", frozen=True, strict=True)
HEX16 = re.compile(r"^[0-9a-f]{16}$")
_TOL = dict(rel_tol=1e-9, abs_tol=1e-12)


def _utc_ms(dt: datetime) -> datetime:
    """Contract §10: UTC RFC 3339 with milliseconds. Malformed input is rejected, never normalised."""
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware (UTC)")
    if dt.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be in UTC (offset +00:00); other offsets are not normalised")
    if dt.microsecond % 1000:
        raise ValueError("timestamp precision must be milliseconds")
    return dt


UtcTimestamp = Annotated[datetime, AfterValidator(_utc_ms), PlainSerializer(format_timestamp, return_type=str)]
FiniteFloat = Annotated[float, Field(allow_inf_nan=False)]
NonEmptyStr = Annotated[str, Field(min_length=1)]


def _fault_labels(v: Tuple[Label, ...]) -> Tuple[Label, ...]:
    if Label.INSUFFICIENT_EVIDENCE in v:
        raise ValueError("INSUFFICIENT_EVIDENCE is a decision, not a fault label")
    if len(set(v)) != len(v):
        raise ValueError("duplicate labels")
    return v


FaultLabels = Annotated[Tuple[Label, ...], AfterValidator(_fault_labels)]

_SCOPE = re.compile(r"^(?:(host|cpuset)|(cpu):(\d+)|(cgroup):(/\S*)|(netns|app):(\S+)|(iface):(\S+)/(\S+)|(socket):(\S+)/(\S+))$")


def scope_kind(scope: str) -> ScopeKind:
    """Parse contract §2 scope syntax."""
    m = _SCOPE.match(scope or "")
    if not m:
        raise ValueError(f"malformed scope {scope!r}")
    kind = next(g for g in (m.group(1), m.group(2), m.group(4), m.group(6), m.group(8), m.group(11)) if g)
    return ScopeKind(kind)


def _no_dupes(name, seq):
    if len(set(seq)) != len(seq):
        raise ValueError(f"duplicate entries in {name}")


# ============================================================================ window / baseline
class Window(BaseModel):
    model_config = STRICT
    start: UtcTimestamp
    end: UtcTimestamp
    duration_s: FiniteFloat = Field(gt=0)
    sample_period_s: FiniteFloat = Field(gt=0)

    @model_validator(mode="after")
    def _check(self):
        if not self.end > self.start:
            raise ValueError("window end must be after start")
        ms = (self.end - self.start) // timedelta(milliseconds=1)
        if not math.isclose(self.duration_s * 1000.0, ms, rel_tol=0, abs_tol=1e-6):
            raise ValueError(f"duration_s {self.duration_s} disagrees with timestamps ({ms / 1000} s)")
        return self


class BaselineStat(BaseModel):
    model_config = STRICT
    method: BaselineMethod
    window: Window
    median: FiniteFloat
    mad: FiniteFloat = Field(ge=0)
    p99: FiniteFloat
    n: int = Field(ge=1)
    adequate: bool
    baseline_id: Optional[NonEmptyStr] = None

    @model_validator(mode="after")
    def _check(self):
        if self.method is BaselineMethod.reference and self.baseline_id is None:
            raise ValueError("a reference baseline must record its baseline_id (contract §5)")
        if self.p99 < self.median:
            raise ValueError("baseline p99 cannot be below the median")
        return self


class Deviation(BaseModel):
    model_config = STRICT
    ratio: FiniteFloat
    delta: FiniteFloat
    robust_z: FiniteFloat
    floor_used: FiniteFloat = Field(ge=0)


class Provenance(BaseModel):
    model_config = STRICT
    source: SourceType
    locator: NonEmptyStr
    collector: NonEmptyStr
    collector_version: NonEmptyStr
    privileged: bool
    first_sample_at: UtcTimestamp
    last_sample_at: UtcTimestamp
    samples: int = Field(ge=0)
    derived_from: Tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check(self):
        if self.last_sample_at < self.first_sample_at:
            raise ValueError("last_sample_at precedes first_sample_at")
        if (self.source is SourceType.DERIVED) != bool(self.derived_from):
            raise ValueError("derived_from is required exactly when source = DERIVED")
        for mid in self.derived_from:
            if not HEX16.match(mid):
                raise ValueError(f"derived_from entry {mid!r} is not a measurement id")
        _no_dupes("derived_from", self.derived_from)
        return self


# ============================================================================ qualifier
class Qualifier(BaseModel):
    """Value dimension of a measurement (v0.2.0, R-3), e.g. kfree_skb reason or app.events code."""
    model_config = STRICT
    dimension: NonEmptyStr
    value: NonEmptyStr


def _check_qualifier(feature_id, qualifier):
    """Registry-governed: required iff the feature declares a dimension; must match it."""
    spec = load_contract().registry.get(feature_id)
    if spec.dimension is None:
        if qualifier is not None:
            raise ValueError(f"{feature_id} declares no dimension; a qualifier is not allowed")
        return
    if qualifier is None:
        raise ValueError(f"{feature_id} requires a '{spec.dimension.name}' qualifier")
    if qualifier.dimension != spec.dimension.name:
        raise ValueError(f"{feature_id}: qualifier dimension must be '{spec.dimension.name}', got '{qualifier.dimension}'")
    if not spec.dimension.accepts(qualifier.value):
        raise ValueError(f"{feature_id}: '{qualifier.value}' is not a valid {spec.dimension.name}")


# ============================================================================ measurement
class Measurement(BaseModel):
    model_config = STRICT
    measurement_id: str
    feature_id: str
    scope: str
    window: Window
    aggregation: Aggregation
    unit: Unit
    value: Optional[FiniteFloat]
    quality: Quality
    coverage: FiniteFloat = Field(ge=0, le=1)
    baseline: Optional[BaselineStat]
    deviation: Optional[Deviation]
    provenance: Provenance
    qualifier: Optional[Qualifier] = None

    @model_serializer(mode="wrap")
    def _ser(self, handler):
        # An absent qualifier is omitted so unqualified measurements serialise exactly as in v0.1.0.
        data = handler(self)
        if data.get("qualifier") is None:
            data.pop("qualifier", None)
        return data

    @model_validator(mode="after")
    def _check(self):
        c = load_contract()
        spec = c.registry.get(self.feature_id)                      # I5: unknown feature -> error
        _check_qualifier(self.feature_id, self.qualifier)
        if self.unit is not spec.unit:
            raise ValueError(f"I5: unit {self.unit} != registry unit {spec.unit} for {self.feature_id}")
        if self.aggregation not in spec.aggregations:
            raise ValueError(f"aggregation {self.aggregation} not allowed for {self.feature_id}")
        if scope_kind(self.scope) not in spec.scope_kinds:
            raise ValueError(f"scope {self.scope!r} not allowed for {self.feature_id} ({[s.value for s in spec.scope_kinds]})")
        pv = self.provenance
        if pv.source is SourceType.FAULTLAB_GROUND_TRUTH:
            raise ValueError("FAULTLAB_GROUND_TRUTH must never be a diagnostic measurement (contract §11)")
        if pv.source not in spec.sources:
            raise ValueError(f"source {pv.source} not a registered source of {self.feature_id}")
        if pv.privileged != spec.privileged:
            raise ValueError(f"provenance.privileged must be {spec.privileged} for {self.feature_id}")
        if self.measurement_id != ids.measurement_id(self.feature_id, self.scope, self.window, self.qualifier):
            raise ValueError("measurement_id is not the deterministic id of (feature_id, scope, window, qualifier)")
        # missing / invalid semantics (contract §10.3, §10.8): never encode absence as a number
        if (self.value is None) != (self.quality in (Quality.MISSING, Quality.INVALID)):
            raise ValueError("value must be null exactly when quality is MISSING or INVALID")
        if self.quality is Quality.OK and self.coverage != 1.0:
            raise ValueError("quality OK requires full coverage; use PARTIAL for coverage below 1")
        if self.quality is Quality.PARTIAL and not 0.0 < self.coverage < 1.0:
            raise ValueError("quality PARTIAL requires 0 < coverage < 1")
        if self.value is not None and pv.samples < 1:
            raise ValueError("a value requires at least one sample")
        if self.value is not None and spec.non_negative and self.value < 0:
            raise ValueError(f"{self.feature_id} is non-negative; a negative value (e.g. a counter reset) "
                             "must be recorded as quality INVALID with value null")
        if self.value is not None and self.unit is Unit.fraction and self.value > 1.0:
            raise ValueError("a fraction must lie in [0, 1]")
        if self.value is not None and self.unit is Unit.boolean and self.value not in (0.0, 1.0):
            raise ValueError("a boolean measurement must be exactly 0.0 or 1.0 (R-1)")
        # staleness (contract §10.8): last sample older than the window length
        if pv.last_sample_at > self.window.end:
            raise ValueError("provenance.last_sample_at is after the window end")
        age = (self.window.end - pv.last_sample_at).total_seconds()
        if self.quality in (Quality.OK, Quality.PARTIAL) and age > self.window.duration_s:
            raise ValueError("last sample older than the window: quality must be STALE")
        if self.quality is Quality.STALE and age <= self.window.duration_s:
            raise ValueError("quality STALE requires the last sample to be older than the window")
        # baseline / deviation
        if self.baseline and self.baseline.method is BaselineMethod.within_run and self.baseline.window.end > self.window.start:
            raise ValueError("a within-run baseline window must not overlap the measurement window (contract §5)")
        if (self.deviation is None) != (self.value is None or self.baseline is None):
            raise ValueError("deviation must be null exactly when value or baseline is null (contract §10.3)")
        if self.deviation is not None:
            d, b, x = self.deviation, self.baseline, self.value
            den_r, den_z = max(b.median, d.floor_used), max(1.4826 * b.mad, d.floor_used)
            if den_r <= 0 or den_z <= 0:
                raise ValueError("deviation undefined: floor_used must make the denominators positive")
            if not math.isclose(d.delta, x - b.median, **_TOL):
                raise ValueError("deviation.delta != value - baseline.median")
            if not math.isclose(d.ratio, x / den_r, **_TOL):
                raise ValueError("deviation.ratio != value / max(baseline.median, floor)")
            if not math.isclose(d.robust_z, (x - b.median) / den_z, **_TOL):
                raise ValueError("deviation.robust_z != (value - median) / max(1.4826*mad, floor)")
        return self


# ============================================================================ evidence item
class Threshold(BaseModel):
    model_config = STRICT
    parameter: NonEmptyStr
    value: FiniteFloat

    @field_validator("parameter")
    @classmethod
    def _known(cls, v):
        t = load_contract().parameter_type(v)
        if t is None:
            raise ValueError(f"unknown contract parameter {v!r}")
        if t != "number":
            raise ValueError(f"parameter {v!r} is of type {t}; a numeric Threshold may reference number parameters only (R-4)")
        return v


class EvidenceItem(BaseModel):
    model_config = STRICT
    item_id: str
    predicate_id: str
    kind: EvidenceKind
    strength: Optional[Strength]
    measurement_ids: Tuple[str, ...] = Field(min_length=1)
    observed: Optional[FiniteFloat]
    threshold: Optional[Threshold]
    supports: FaultLabels
    contradicts: FaultLabels
    missing_reason: Optional[NonEmptyStr]
    rationale: str

    @model_validator(mode="after")
    def _check(self):
        c = load_contract()
        p = c.parse_predicate(self.predicate_id)
        _no_dupes("measurement_ids", self.measurement_ids)
        if self.item_id != ids.evidence_item_id(self.predicate_id, self.measurement_ids):
            raise ValueError("item_id is not the deterministic id of (predicate_id, measurement_ids)")
        if (self.strength is None) != (self.kind in (EvidenceKind.MISSING, EvidenceKind.CONFLICTING)):
            raise ValueError("strength must be null exactly for MISSING and CONFLICTING items (contract E4)")
        if (self.missing_reason is not None) != (self.kind is EvidenceKind.MISSING):
            raise ValueError("missing_reason is required exactly when kind = MISSING")
        if self.kind in (EvidenceKind.MISSING, EvidenceKind.NEGATIVE) and self.supports:
            raise ValueError("I3: MISSING/NEGATIVE evidence must not support any label (contract E2, E3)")
        if self.kind is EvidenceKind.POSITIVE and not self.supports:
            raise ValueError("POSITIVE evidence must support at least one label")
        if set(self.supports) & set(self.contradicts):
            raise ValueError("a label cannot be both supported and contradicted by one item")
        if p.clause_id and self.kind is EvidenceKind.POSITIVE:
            cl = c.labels.clause(p.clause_id)
            target = self.supports if cl.role == "required" else self.contradicts
            if cl.label not in target:
                raise ValueError(f"POSITIVE {cl.role} item for {p.clause_id} must list {cl.label} in "
                                 f"{'supports' if cl.role == 'required' else 'contradicts'}")
        expect = c.render_rationale(self.predicate_id, self.kind, self.strength, self.observed, self.threshold)
        if self.rationale != expect:
            raise ValueError("rationale must be the contract template rendering, not free text (contract §10.4)")
        return self


# ============================================================================ snapshot
class Target(BaseModel):
    model_config = STRICT
    name: NonEmptyStr
    cgroup_path: NonEmptyStr
    pids: Tuple[Annotated[int, Field(gt=0)], ...]
    cpuset: Optional[str]
    netns_ref: Optional[NonEmptyStr]
    ifaces: Tuple[NonEmptyStr, ...]

    @model_validator(mode="after")
    def _check(self):
        if not self.cgroup_path.startswith("/"):
            raise ValueError("cgroup_path must be absolute")
        _no_dupes("pids", self.pids)
        _no_dupes("ifaces", self.ifaces)
        if self.cpuset is not None and not re.match(r"^\d+(-\d+)?(,\d+(-\d+)?)*$", self.cpuset):
            raise ValueError(f"malformed cpuset {self.cpuset!r}")
        return self


class MissingMeasurement(BaseModel):
    model_config = STRICT
    feature_id: str
    scope: str
    reason: NonEmptyStr
    qualifier: Optional[Qualifier] = None

    @model_serializer(mode="wrap")
    def _ser(self, handler):
        data = handler(self)
        if data.get("qualifier") is None:
            data.pop("qualifier", None)
        return data

    @model_validator(mode="after")
    def _check(self):
        _check_qualifier(self.feature_id, self.qualifier)
        spec = load_contract().registry.get(self.feature_id)
        if scope_kind(self.scope) not in spec.scope_kinds:
            raise ValueError(f"scope {self.scope!r} not allowed for {self.feature_id}")
        return self


class Conflict(BaseModel):
    model_config = STRICT
    labels: FaultLabels = Field(min_length=2)
    rule: Optional[NonEmptyStr]   # a precedence rule id, or null when the pair is not covered by §9
    item_ids: Tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _check(self):
        if self.rule is not None and self.rule not in {p.rule_id for p in load_contract().labels.precedence}:
            raise ValueError(f"unknown precedence rule {self.rule!r}")
        return self


class DataQuality(BaseModel):
    model_config = STRICT
    overall_coverage: FiniteFloat = Field(ge=0, le=1)
    sources_unavailable: Tuple[NonEmptyStr, ...]
    privileged_sources_unavailable: Tuple[NonEmptyStr, ...]
    baseline_adequate: bool
    counter_resets: int = Field(ge=0)
    gate_passed: bool


class EvidenceSnapshot(BaseModel):
    model_config = STRICT
    schema_version: str
    contract_version: str
    parameter_set_id: NonEmptyStr
    snapshot_id: str
    incident_id: Optional[NonEmptyStr] = None
    target: Target
    window: Window
    baseline_window: Window
    measurements: Tuple[Measurement, ...]
    evidence_items: Tuple[EvidenceItem, ...]
    missing_measurements: Tuple[MissingMeasurement, ...]
    conflicts: Tuple[Conflict, ...]
    data_quality: DataQuality

    @model_validator(mode="after")
    def _check(self):
        c = load_contract()
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
        require_compatible(self.contract_version)
        if self.baseline_window.end > self.window.start:
            raise ValueError("baseline_window must end before the incident window starts")
        ms = {m.measurement_id: m for m in self.measurements}
        if len(ms) != len(self.measurements):
            raise ValueError("duplicate measurement ids")
        items = {i.item_id: i for i in self.evidence_items}
        if len(items) != len(self.evidence_items):
            raise ValueError("duplicate evidence item ids")
        for m in self.measurements:
            if m.window != self.window:
                raise ValueError(f"measurement {m.measurement_id} is not aggregated over the snapshot window")
            if m.baseline and m.baseline.method is BaselineMethod.within_run and m.baseline.window != self.baseline_window:
                raise ValueError(f"measurement {m.measurement_id}: within-run baseline must use the snapshot baseline_window")
            for d in m.provenance.derived_from:
                if d not in ms:
                    raise ValueError(f"I5: derived measurement {m.measurement_id} references unknown {d}")
        listed = {(x.feature_id, x.scope, x.qualifier) for x in self.missing_measurements}
        if len(listed) != len(self.missing_measurements):
            raise ValueError("duplicate missing_measurements entries")
        for m in self.measurements:
            if m.quality is Quality.MISSING and (m.feature_id, m.scope, m.qualifier) not in listed:
                raise ValueError(f"MISSING measurement {m.feature_id}@{m.scope} must be listed in missing_measurements")
        # R-1 consistency: an unlimited quota (quota_limited = 0) cannot coexist with a finite quota value.
        unlimited = {m.scope for m in self.measurements if m.feature_id == "throttle.quota_limited" and m.value == 0.0}
        for m in self.measurements:
            if m.feature_id == "throttle.quota_cores" and m.value is not None and m.scope in unlimited:
                raise ValueError(f"{m.scope}: throttle.quota_cores has a value but throttle.quota_limited = 0 (unlimited)")
        for it in self.evidence_items:
            p = c.parse_predicate(it.predicate_id)
            allowed = set(c.predicate_features(p))
            for mid in it.measurement_ids:
                if mid not in ms:
                    raise ValueError(f"I5: evidence item {it.item_id} references unknown measurement {mid}")
                m = ms[mid]
                if m.feature_id not in allowed:
                    raise ValueError(f"item {it.predicate_id} may not use feature {m.feature_id}")
                if it.kind in (EvidenceKind.POSITIVE, EvidenceKind.NEGATIVE):
                    if m.quality in (Quality.MISSING, Quality.INVALID, Quality.STALE):
                        raise ValueError(f"E1: {it.kind} item {it.predicate_id} uses a {m.quality} measurement; "
                                         "it must be a MISSING item")
                    if c.predicate_uses_baseline(p) and (m.baseline is None or not m.baseline.adequate):
                        raise ValueError(f"{it.kind} item {it.predicate_id} needs an adequate baseline "
                                         "(contract §5: otherwise MISSING / BASELINE_INADEQUATE)")
        for cf in self.conflicts:
            for iid in cf.item_ids:
                if iid not in items:
                    raise ValueError(f"conflict references unknown evidence item {iid}")
        if self.snapshot_id != ids.snapshot_id(self.target, self.window, self.measurements):
            raise ValueError("snapshot_id is not the deterministic id of (target, window, measurements)")
        return self


# ============================================================================ result
class Candidate(BaseModel):
    model_config = STRICT
    label: Label
    status: CandidateStatus
    required_met: Tuple[str, ...]
    required_missing: Tuple[str, ...]
    supporting: Tuple[str, ...]
    contradicting: Tuple[str, ...]
    rules_fired: Tuple[str, ...]

    @model_validator(mode="after")
    def _check(self):
        if self.label is Label.INSUFFICIENT_EVIDENCE:
            raise ValueError("INSUFFICIENT_EVIDENCE is not a fault candidate")
        c = load_contract()
        req = {cl.clause_id for cl in c.labels.required_clauses(self.label)}
        met, miss = set(self.required_met), set(self.required_missing)
        for name, seq in (("required_met", self.required_met), ("required_missing", self.required_missing),
                          ("supporting", self.supporting), ("contradicting", self.contradicting),
                          ("rules_fired", self.rules_fired)):
            _no_dupes(name, seq)
        if met & miss or (met | miss) != req:
            raise ValueError(f"required_met and required_missing must partition {sorted(req)}")
        if self.status in (CandidateStatus.ASSERTED, CandidateStatus.CONTRIBUTING) and miss:
            raise ValueError(f"I4: {self.label} cannot be {self.status} with required clauses missing {sorted(miss)}")
        if self.status in (CandidateStatus.NOT_EVALUABLE, CandidateStatus.NOT_SUPPORTED,
                           CandidateStatus.SUPPORTED_NOT_SUFFICIENT) and not miss:
            raise ValueError(f"status {self.status} requires at least one unmet required clause")
        for r in self.rules_fired:
            if c.labels.clause(r).label is not self.label:
                raise ValueError(f"rule {r} does not belong to {self.label}")
        return self


class MLAdvisory(BaseModel):
    """Advisory ML output (design §5.4). It has no decision field and cannot set the decision."""
    model_config = STRICT
    model_id: NonEmptyStr
    probabilities: Dict[Label, Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]]
    calibrated: bool
    agrees_with_rules: bool

    @model_validator(mode="after")
    def _check(self):
        if not self.probabilities:
            raise ValueError("probabilities must not be empty")
        if not math.isclose(sum(self.probabilities.values()), 1.0, abs_tol=1e-6):
            raise ValueError("probabilities must sum to 1")
        return self


class EngineInfo(BaseModel):
    model_config = STRICT
    contract_version: str
    rules_version: NonEmptyStr
    parameter_set_id: NonEmptyStr
    code_commit: str

    @model_validator(mode="after")
    def _check(self):
        require_compatible(self.contract_version)
        if not re.match(r"^[0-9a-f]{7,40}$", self.code_commit):
            raise ValueError("code_commit must be a git hash")
        return self


class DiagnosticResult(BaseModel):
    model_config = STRICT
    snapshot_id: str
    decision: Label
    contributing: FaultLabels
    abstained: bool
    abstention_reasons: Tuple[AbstentionReason, ...]
    confidence_level: ConfidenceLevel
    candidates: Tuple[Candidate, ...]
    rules_fired: Tuple[str, ...]
    ml: Optional[MLAdvisory] = None
    engine: EngineInfo
    flags: Tuple[DiagnosticFlag, ...] = ()

    @model_validator(mode="after")
    def _check(self):
        _no_dupes("flags", self.flags)
        if DiagnosticFlag.IMPACT_NOT_MEASURED in self.flags and self.confidence_level is ConfidenceLevel.HIGH:
            raise ValueError("IMPACT_NOT_MEASURED requires confidence_level != HIGH (contract §7)")
        if DiagnosticFlag.ML_DISAGREEMENT in self.flags and (self.ml is None or self.ml.agrees_with_rules):
            raise ValueError("ML_DISAGREEMENT requires an ml advisory with agrees_with_rules = false")
        if not HEX16.match(self.snapshot_id):
            raise ValueError("snapshot_id must be a deterministic 16-hex id")
        ins = self.decision is Label.INSUFFICIENT_EVIDENCE
        _no_dupes("abstention_reasons", self.abstention_reasons)
        if not (self.abstained == ins == bool(self.abstention_reasons)):
            raise ValueError("I1: abstained <=> decision == INSUFFICIENT_EVIDENCE <=> abstention_reasons non-empty")
        labels = [cd.label for cd in self.candidates]
        if sorted(labels) != sorted(FAULT_LABELS):
            raise ValueError("candidates must contain exactly one entry for each of the seven fault labels")
        by = {cd.label: cd for cd in self.candidates}
        asserted = [cd.label for cd in self.candidates if cd.status is CandidateStatus.ASSERTED]
        if not ins:
            if by[self.decision].status is not CandidateStatus.ASSERTED:
                raise ValueError(f"I2: decision {self.decision} requires its candidate to be ASSERTED")
            if asserted != [self.decision]:
                raise ValueError("exactly one candidate (the decision) may be ASSERTED; others are CONTRIBUTING")
            if self.confidence_level is ConfidenceLevel.LOW:
                raise ValueError("an asserted decision is never LOW confidence (contract §10.9)")
        contributing = {cd.label for cd in self.candidates if cd.status is CandidateStatus.CONTRIBUTING}
        if set(self.contributing) != contributing:
            raise ValueError("contributing must equal the candidates with status CONTRIBUTING")
        if ins and self.contributing:
            raise ValueError("an abstention has no contributing labels")
        c = load_contract()
        _no_dupes("rules_fired", self.rules_fired)
        for r in self.rules_fired:
            c.labels.clause(r)
        if self.ml is not None:
            top = max(self.ml.probabilities.values())
            argmax = [l for l, p in self.ml.probabilities.items() if p == top]
            if len(argmax) == 1 and self.ml.agrees_with_rules != (argmax[0] is self.decision):
                raise ValueError("ml.agrees_with_rules must reflect whether the ML top label equals the rule decision")
        return self
