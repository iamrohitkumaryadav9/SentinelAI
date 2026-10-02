"""Machine-readable contract catalogs: feature registry, label clauses, predicates, parameters.

These describe WHAT features and clauses mean. They contain no thresholds and no evaluation
logic (that is M2). Loaded once from ``data/*.json`` and validated strictly.
"""

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, Literal, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .enums import (FAULT_LABELS, Aggregation, Availability, EvidenceKind, Label, ScopeKind, SourceType, Unit)
from .serialize import format_float
from .version import CONTRACT_VERSION

DATA = Path(__file__).resolve().parent / "data"
STRICT = ConfigDict(extra="forbid", frozen=True, strict=True)

FEATURE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")
CLAUSE_ID_RE = re.compile(r"^[A-Z]{2}\.[RX]\d+$")
_PRIMS = r"DEV|ABS|EVALUATED|LOSS\.LOCAL|IMPACT"
PREDICATE_RE = re.compile(
    rf"^(?:(?P<clause>[A-Z]{{2}}\.[RX]\d+)(?:/(?P<sub>{_PRIMS}))?|(?P<prim>{_PRIMS}))"
    r"(?:\[(?P<arg>[A-Za-z0-9_.:\-]+)\])?$")
CLAUSE_PREFIX_LABEL = {"CC": Label.cpu_contention, "CT": Label.cpu_throttling, "SI": Label.softirq_overload,
                       "PL": Label.network_packet_loss, "RT": Label.tcp_retransmissions,
                       "MP": Label.memory_pressure, "AB": Label.application_bottleneck}


class ContractViolation(ValueError):
    """Raised when a contract invariant is violated. ``invariant`` names it (e.g. 'I4')."""

    def __init__(self, invariant: str, message: str):
        super().__init__(f"[{invariant}] {message}")
        self.invariant = invariant


# --------------------------------------------------------------------------- registry
class DimensionSpec(BaseModel):
    """A value dimension of a feature (v0.2.0, R-3): exactly one of a closed value set or a pattern."""
    model_config = STRICT
    name: str = Field(min_length=1)
    pattern: Optional[str] = None
    values: Optional[Tuple[str, ...]] = None

    @model_validator(mode="after")
    def _check(self):
        if (self.pattern is None) == (self.values is None):
            raise ValueError(f"dimension {self.name}: exactly one of pattern / values is required")
        if self.values is not None and (not self.values or len(set(self.values)) != len(self.values)):
            raise ValueError(f"dimension {self.name}: values must be a non-empty set")
        if self.pattern is not None:
            re.compile(self.pattern)
        return self

    def accepts(self, value: str) -> bool:
        if self.values is not None:
            return value in self.values
        return re.fullmatch(self.pattern, value) is not None


class FeatureSpec(BaseModel):
    model_config = STRICT
    id: str
    family: str
    scope_kinds: Tuple[ScopeKind, ...] = Field(min_length=1)
    unit: Unit
    contract_unit_text: str
    aggregations: Tuple[Aggregation, ...] = Field(min_length=1)
    sources: Tuple[SourceType, ...] = Field(min_length=1)
    availability: Availability
    privileged: bool
    kind: Literal["counter_rate", "gauge", "ratio", "derived", "percentile", "event_count"]
    non_negative: bool
    locator: str = Field(min_length=1)
    derived_from: Tuple[str, ...] = ()
    description: str
    dimension: Optional[DimensionSpec] = None

    @model_validator(mode="after")
    def _check(self):
        if not FEATURE_ID_RE.match(self.id):
            raise ValueError(f"bad feature id {self.id!r}")
        if SourceType.FAULTLAB_GROUND_TRUTH in self.sources:
            raise ValueError(f"{self.id}: ground truth is never a diagnostic feature source (contract §11)")
        derived = self.kind == "derived"
        if derived != (self.sources == (SourceType.DERIVED,)) or derived != bool(self.derived_from):
            raise ValueError(f"{self.id}: derived kind, DERIVED source and derived_from must agree")
        if self.privileged != (self.availability is Availability.P):
            raise ValueError(f"{self.id}: privileged must be true exactly for availability P")
        if len(set(self.aggregations)) != len(self.aggregations) or len(set(self.scope_kinds)) != len(self.scope_kinds):
            raise ValueError(f"{self.id}: duplicate aggregation or scope kind")
        return self


class FeatureRegistry(BaseModel):
    model_config = STRICT
    registry_id: str
    contract_version: str
    features: Tuple[FeatureSpec, ...]
    families: Tuple[str, ...]
    named_sets: Dict[str, Tuple[str, ...]]

    @model_validator(mode="after")
    def _check(self):
        if self.contract_version != CONTRACT_VERSION:
            raise ValueError(f"registry contract_version {self.contract_version} != {CONTRACT_VERSION}")
        ids = [f.id for f in self.features]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate feature ids in registry")
        known = set(ids)
        for f in self.features:
            if f.family not in self.families:
                raise ValueError(f"{f.id}: unknown family {f.family}")
            missing = set(f.derived_from) - known
            if missing:
                raise ValueError(f"{f.id}: derived_from references unknown features {sorted(missing)}")
        for name, members in self.named_sets.items():
            if set(members) - known:
                raise ValueError(f"named set {name} references unknown features")
        return self

    def get(self, feature_id: str) -> FeatureSpec:
        for f in self.features:
            if f.id == feature_id:
                return f
        raise ContractViolation("I5", f"unknown feature_id {feature_id!r} (not in registry {self.contract_version})")

    def has(self, feature_id: str) -> bool:
        return any(f.id == feature_id for f in self.features)

    def family_members(self, family: str) -> Tuple[str, ...]:
        return tuple(f.id for f in self.features if f.family == family)


# --------------------------------------------------------------------------- labels / clauses
class ItemComponent(BaseModel):
    model_config = STRICT
    type: Literal["item"]
    sub: Optional[Literal["DEV", "ABS", "EVALUATED", "LOSS.LOCAL", "IMPACT"]] = None
    kind: Literal["POSITIVE", "NEGATIVE"]


class LabelsNotAssertedComponent(BaseModel):
    model_config = STRICT
    type: Literal["labels_not_asserted"]
    labels: Tuple[Label, ...] = Field(min_length=1)


class Subordination(BaseModel):
    """v0.3.0: when a Primary clause is FALSE, the label may still be CONTRIBUTING, but only under
    precedence rule ``rule`` and only when ``primary`` is the decision (contract §8, §9)."""
    model_config = STRICT
    rule: str
    primary: Label


class Clause(BaseModel):
    model_config = STRICT
    clause_id: str
    label: Label
    role: Literal["required", "primary", "contradictory"]
    uses_baseline: bool
    features: Tuple[str, ...] = Field(min_length=1)
    definition: str = Field(min_length=1)
    components: Tuple[Union[ItemComponent, LabelsNotAssertedComponent], ...] = Field(min_length=1)
    subordinate: Optional[Subordination] = None

    @model_validator(mode="after")
    def _check(self):
        if (self.subordinate is not None) != (self.role == "primary"):
            raise ValueError(f"{self.clause_id}: a Primary clause, and only a Primary clause, declares a subordination")
        if self.subordinate is not None and self.subordinate.primary is self.label:
            raise ValueError(f"{self.clause_id}: a label cannot be subordinate to itself")
        if not CLAUSE_ID_RE.match(self.clause_id):
            raise ValueError(f"bad clause id {self.clause_id}")
        if CLAUSE_PREFIX_LABEL[self.clause_id[:2]] is not self.label:
            raise ValueError(f"clause {self.clause_id} prefix does not match label {self.label}")
        if self.label is Label.INSUFFICIENT_EVIDENCE:
            raise ValueError("INSUFFICIENT_EVIDENCE has no clauses")
        if (self.role == "contradictory") != (self.clause_id[3] == "X"):
            raise ValueError(f"{self.clause_id}: role does not match id (R = required or primary, X = contradictory)")
        return self


class LabelInfo(BaseModel):
    model_config = STRICT
    confusable: Tuple[Label, ...]
    positive_evidence_features: Tuple[str, ...] = ()
    never_sufficient_features: Tuple[str, ...] = ()


class PrecedenceRule(BaseModel):
    model_config = STRICT
    rule_id: str
    labels: Tuple[Label, ...] = Field(min_length=2)
    resolution: str


class LabelContracts(BaseModel):
    model_config = STRICT
    contract_version: str
    labels: Dict[Label, LabelInfo]
    clauses: Tuple[Clause, ...]
    precedence: Tuple[PrecedenceRule, ...]

    @model_validator(mode="after")
    def _check(self):
        if self.contract_version != CONTRACT_VERSION:
            raise ValueError("labels contract_version mismatch")
        if set(self.labels) != set(FAULT_LABELS):
            raise ValueError("label contracts must cover exactly the seven fault labels")
        ids = [c.clause_id for c in self.clauses]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate clause ids")
        for lab in FAULT_LABELS:
            if not any(c.label is lab and c.role == "required" for c in self.clauses):
                raise ValueError(f"{lab} has no required clause")
        pr = [p.rule_id for p in self.precedence]
        if len(pr) != len(set(pr)):
            raise ValueError("duplicate precedence rule ids")
        for p in self.precedence:
            if Label.INSUFFICIENT_EVIDENCE in p.labels:
                raise ValueError("precedence rules relate fault labels only")
        rules = {p.rule_id: p for p in self.precedence}
        for cl in self.clauses:
            s = cl.subordinate
            if s is not None and (s.rule not in rules or not {s.primary, cl.label} <= set(rules[s.rule].labels)):
                raise ValueError(f"{cl.clause_id}: subordination must name a precedence rule relating "
                                 f"{s.primary} and {cl.label}")
        return self

    def clause(self, clause_id: str) -> Clause:
        for c in self.clauses:
            if c.clause_id == clause_id:
                return c
        raise ContractViolation("I4", f"unknown clause {clause_id!r}")

    def required_clauses(self, label: Label) -> Tuple[Clause, ...]:
        """Clauses required for the label to be ASSERTED (the decision): Required and Primary (§8)."""
        return tuple(c for c in self.clauses if c.label is label and c.role in ("required", "primary"))

    def contributing_clauses(self, label: Label) -> Tuple[Clause, ...]:
        """Clauses required for the label to take part in precedence and be CONTRIBUTING: Required only."""
        return tuple(c for c in self.clauses if c.label is label and c.role == "required")

    def primary_clauses(self, label: Label) -> Tuple[Clause, ...]:
        """Clauses needed only for the label to be the primary decision (v0.3.0, §8)."""
        return tuple(c for c in self.clauses if c.label is label and c.role == "primary")


# --------------------------------------------------------------------------- predicates / parameters
class Primitive(BaseModel):
    model_config = STRICT
    uses_baseline: bool
    definition: str


class PredicateCatalog(BaseModel):
    model_config = STRICT
    contract_version: str
    primitives: Dict[str, Primitive]
    rationale_format: str


class ParameterSpec(BaseModel):
    """A symbolic contract parameter (v0.2.0, R-4): name and type only, never a value."""
    model_config = STRICT
    name: str = Field(min_length=1)
    type: Literal["number", "reason_set"]


class ParameterCatalog(BaseModel):
    model_config = STRICT
    contract_version: str
    status: Literal["UNCALIBRATED"]
    parameters: Tuple[ParameterSpec, ...]
    per_feature_parameters: Tuple[ParameterSpec, ...]
    note: str

    @model_validator(mode="after")
    def _check(self):
        names = [p.name for p in self.parameters + self.per_feature_parameters]
        if len(names) != len(set(names)):
            raise ValueError("duplicate parameter names")
        return self


class ParsedPredicate(BaseModel):
    model_config = STRICT
    predicate_id: str
    clause_id: Optional[str]
    primitive: Optional[str]
    arg: Optional[str]


class Contract(BaseModel):
    model_config = STRICT
    registry: FeatureRegistry
    labels: LabelContracts
    predicates: PredicateCatalog
    parameters: ParameterCatalog

    @model_validator(mode="after")
    def _cross(self):
        for c in self.labels.clauses:
            for f in c.features:
                self.registry.get(f)
            for comp in c.components:
                if isinstance(comp, ItemComponent) and comp.sub and comp.sub not in self.predicates.primitives:
                    raise ValueError(f"{c.clause_id}: unknown primitive {comp.sub}")
        for lab, info in self.labels.labels.items():
            for f in info.positive_evidence_features + info.never_sufficient_features:
                self.registry.get(f)
        return self

    # -- predicate ids --------------------------------------------------------------
    def parse_predicate(self, predicate_id: str) -> ParsedPredicate:
        m = PREDICATE_RE.match(predicate_id or "")
        if not m:
            raise ValueError(f"malformed predicate_id {predicate_id!r}")
        clause_id, prim, arg = m.group("clause"), m.group("sub") or m.group("prim"), m.group("arg")
        if clause_id:
            self.labels.clause(clause_id)
        if prim and prim not in self.predicates.primitives:
            raise ValueError(f"unknown primitive {prim}")
        if prim in ("DEV", "ABS") and not (arg and self.registry.has(arg)):
            raise ValueError(f"{predicate_id}: {prim} requires a registered feature argument")
        if prim == "EVALUATED" and not arg:
            raise ValueError(f"{predicate_id}: EVALUATED requires an argument")
        if arg is not None:
            self.allowed_arg_features(arg)  # raises if unknown
            if clause_id and self.registry.has(arg) and arg not in self.labels.clause(clause_id).features:
                raise ValueError(f"{predicate_id}: feature {arg} is not part of clause {clause_id}")
        return ParsedPredicate(predicate_id=predicate_id, clause_id=clause_id, primitive=prim, arg=arg)

    def allowed_arg_features(self, arg: str) -> Tuple[str, ...]:
        if self.registry.has(arg):
            return (arg,)
        if arg in self.registry.named_sets:
            return self.registry.named_sets[arg]
        if arg.startswith("family:") and arg[7:] in self.registry.families:
            return self.registry.family_members(arg[7:])
        raise ValueError(f"unknown predicate argument {arg!r} (feature, named set or family:<name>)")

    def predicate_features(self, p: ParsedPredicate) -> Tuple[str, ...]:
        """Features an evidence item for this predicate may reference."""
        if p.clause_id:
            return self.labels.clause(p.clause_id).features
        if p.primitive == "LOSS.LOCAL":
            return self.labels.clause("PL.R1").features
        if p.primitive == "IMPACT":
            return ("app.latency_ms",)
        return self.allowed_arg_features(p.arg)

    def predicate_uses_baseline(self, p: ParsedPredicate) -> bool:
        if p.primitive:
            return self.predicates.primitives[p.primitive].uses_baseline
        return self.labels.clause(p.clause_id).uses_baseline

    def render_rationale(self, predicate_id, kind, strength, observed, threshold) -> str:
        """Templated rationale (contract §10.4: no free text)."""
        p = self.parse_predicate(predicate_id)
        definition = (self.labels.clause(p.clause_id).definition if p.clause_id
                      else self.predicates.primitives[p.primitive].definition)
        thr = "null" if threshold is None else f"{threshold.parameter}={format_float(threshold.value)}"
        return self.predicates.rationale_format.format(
            definition=definition, predicate_id=predicate_id, kind=EvidenceKind(kind).value,
            strength="null" if strength is None else strength.value,
            observed="null" if observed is None else format_float(observed), threshold=thr)

    def parameter_type(self, name: str) -> Optional[str]:
        """Type of a contract parameter ('number' / 'reason_set'), or None if unknown."""
        for p in self.parameters.parameters:
            if p.name == name:
                return p.type
        m = re.match(r"^(\w+)\[([a-z0-9_.]+)\]$", name)
        if m and self.registry.has(m.group(2)):
            for p in self.parameters.per_feature_parameters:
                if p.name == m.group(1):
                    return p.type
        return None


def _load(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_contract() -> Contract:
    return Contract(registry=FeatureRegistry.model_validate_json((DATA / "registry.json").read_text(), strict=False),
                    labels=LabelContracts.model_validate_json((DATA / "labels.json").read_text(), strict=False),
                    predicates=PredicateCatalog.model_validate_json((DATA / "predicates.json").read_text(), strict=False),
                    parameters=ParameterCatalog.model_validate_json((DATA / "parameters.json").read_text(), strict=False))
