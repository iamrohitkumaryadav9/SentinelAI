"""DiagnosisRecord (M2's DiagnosticResult plus identity and provenance) and the deterministic report.

diagnosis_id = sha1(canonical_json({"kind": "diagnosis", input_snapshot_sha256, parameter_set_sha256,
rules_version, contract_version}))[:16]: the question asked of M2, nothing else. Wall time, run key,
incident_id, events and code_commit are not part of it (code_commit is recorded beside it).
Nothing here interprets the result: every field is copied from M2's output or the input snapshot.
"""

import hashlib
from typing import Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from ..diagnostic.contract import (Conflict, DiagnosticResult, EvidenceKind, EvidenceSnapshot, MissingMeasurement,
                                   SourceType, Strength)
from ..diagnostic.contract.serialize import canonical_bytes, canonical_json
from ..diagnostic.contract.version import CONTRACT_VERSION, SCHEMA_VERSION
from ..diagnostic.rules import RULES_VERSION
from ..diagnostic.rules.params import ParameterSet
from . import registry

STRICT = ConfigDict(extra="forbid", frozen=True, strict=True)
HEX16 = r"^[0-9a-f]{16}$"
HEX64 = r"^[0-9a-f]{64}$"

# the configuration the R2 FaultLab campaigns validated (every R2-C/D/F snapshot; rules m2-1.1.0)
VALIDATED = {"rules_version": "m2-1.1.0", "contract_version": "0.5.0-draft", "schema_version": "0.2.0",
             "collector_versions": frozenset({"m3a-1.1.0", "m3b-1.0.0"})}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def diagnosis_id(*, input_snapshot_sha256: str, parameter_set_sha256: str, rules_version: str,
                 contract_version: str) -> str:
    named = {"kind": "diagnosis", "input_snapshot_sha256": input_snapshot_sha256,
             "parameter_set_sha256": parameter_set_sha256, "rules_version": rules_version,
             "contract_version": contract_version}
    return hashlib.sha1(canonical_json(named).encode("utf-8")).hexdigest()[:16]


class EvidenceRef(BaseModel):
    model_config = STRICT
    item_id: str
    predicate_id: str
    kind: EvidenceKind
    strength: Optional[Strength]
    observed: Optional[float]
    supports: Tuple[str, ...]
    contradicts: Tuple[str, ...]
    measurement_ids: Tuple[str, ...]
    missing_reason: Optional[str]


class EvidenceBreakdown(BaseModel):
    model_config = STRICT
    supporting: Tuple[EvidenceRef, ...]
    negative: Tuple[EvidenceRef, ...]
    missing: Tuple[EvidenceRef, ...]
    missing_measurements: Tuple[MissingMeasurement, ...]
    conflicting: Tuple[EvidenceRef, ...]
    conflicts: Tuple[Conflict, ...]


class ValidatedConfiguration(BaseModel):
    model_config = STRICT
    validated: bool
    reasons: Tuple[str, ...]           # why not, empty when validated


class DiagnosisRecord(BaseModel):
    model_config = STRICT
    diagnosis_id: str = Field(pattern=HEX16)
    snapshot_id: str = Field(pattern=HEX16)
    input_snapshot_sha256: str = Field(pattern=HEX64)
    parameter_set_id: str
    parameter_set_sha256: str = Field(pattern=HEX64)
    rules_version: str
    contract_version: str
    code_commit: str
    result_sha256: str = Field(pattern=HEX64)
    result: DiagnosticResult
    evidence: EvidenceBreakdown
    predicate_ids: Tuple[str, ...]
    validated_configuration: ValidatedConfiguration


def validated_configuration(snapshot: EvidenceSnapshot, parameter_set_id: str,
                            rules_version: str = RULES_VERSION) -> ValidatedConfiguration:
    why = []
    if parameter_set_id not in registry.VALIDATED_PARAMETER_SETS:
        why.append(f"parameter set {parameter_set_id} was not used in the validated campaigns")
    if rules_version != VALIDATED["rules_version"]:
        why.append(f"rules {rules_version} != validated {VALIDATED['rules_version']}")
    if snapshot.contract_version != VALIDATED["contract_version"]:
        why.append(f"contract {snapshot.contract_version} != validated {VALIDATED['contract_version']}")
    if snapshot.schema_version != VALIDATED["schema_version"]:
        why.append(f"schema {snapshot.schema_version} != validated {VALIDATED['schema_version']}")
    versions = {m.provenance.collector_version for m in snapshot.measurements}
    if not versions <= VALIDATED["collector_versions"]:
        why.append(f"collector versions {sorted(versions - VALIDATED['collector_versions'])} not validated")
    if snapshot.data_quality.privileged_sources_unavailable or \
            not any(m.provenance.source is SourceType.EBPF for m in snapshot.measurements):
        why.append("eBPF evidence absent: the validated configuration is M3A + M3B eBPF")
    return ValidatedConfiguration(validated=not why, reasons=tuple(why))


def _ref(i) -> EvidenceRef:
    return EvidenceRef(item_id=i.item_id, predicate_id=i.predicate_id, kind=i.kind, strength=i.strength,
                       observed=i.observed, supports=tuple(l.value for l in i.supports),
                       contradicts=tuple(l.value for l in i.contradicts), measurement_ids=tuple(i.measurement_ids),
                       missing_reason=i.missing_reason)


def breakdown(evaluated: EvidenceSnapshot) -> EvidenceBreakdown:
    items = sorted(evaluated.evidence_items, key=lambda i: (i.predicate_id, i.item_id))
    pick = lambda kind: tuple(_ref(i) for i in items if i.kind is kind)
    return EvidenceBreakdown(supporting=pick(EvidenceKind.POSITIVE), negative=pick(EvidenceKind.NEGATIVE),
                             missing=pick(EvidenceKind.MISSING), missing_measurements=evaluated.missing_measurements,
                             conflicting=pick(EvidenceKind.CONFLICTING), conflicts=evaluated.conflicts)


def build_record(*, input_snapshot: EvidenceSnapshot, input_sha256: str, params: ParameterSet,
                 result: DiagnosticResult, evaluated: EvidenceSnapshot) -> DiagnosisRecord:
    ps_sha = registry.parameter_set_sha256(params)
    eng = result.engine
    did = diagnosis_id(input_snapshot_sha256=input_sha256, parameter_set_sha256=ps_sha,
                       rules_version=eng.rules_version, contract_version=eng.contract_version)
    return DiagnosisRecord(
        diagnosis_id=did, snapshot_id=input_snapshot.snapshot_id, input_snapshot_sha256=input_sha256,
        parameter_set_id=params.parameter_set_id, parameter_set_sha256=ps_sha, rules_version=eng.rules_version,
        contract_version=eng.contract_version, code_commit=eng.code_commit,
        result_sha256=sha256_bytes(canonical_bytes(result)), result=result, evidence=breakdown(evaluated),
        predicate_ids=tuple(sorted({i.predicate_id for i in evaluated.evidence_items})),
        validated_configuration=validated_configuration(input_snapshot, params.parameter_set_id, eng.rules_version))


class Report(BaseModel):
    """Exactly what M2 and the record state; no explanation, no recommendation."""
    model_config = STRICT
    incident_id: str
    snapshot_id: str
    diagnosis_id: str
    decision: str
    contributing: Tuple[str, ...]
    abstained: bool
    abstention_reasons: Tuple[str, ...]
    confidence: str
    flags: Tuple[str, ...]
    rules_fired: Tuple[str, ...]
    supporting: Tuple[str, ...]
    negative: Tuple[str, ...]
    missing: Tuple[str, ...]
    missing_measurements: Tuple[str, ...]
    conflicting: Tuple[str, ...]
    conflicts: Tuple[str, ...]
    versions: dict
    validated_configuration: ValidatedConfiguration


def build_report(record: DiagnosisRecord, incident_id: str) -> Report:
    r, e = record.result, record.evidence
    preds = lambda refs: tuple(x.predicate_id for x in refs)
    return Report(
        incident_id=incident_id, snapshot_id=record.snapshot_id, diagnosis_id=record.diagnosis_id,
        decision=r.decision.value, contributing=tuple(l.value for l in r.contributing), abstained=r.abstained,
        abstention_reasons=tuple(a.value for a in r.abstention_reasons), confidence=r.confidence_level.value,
        flags=tuple(f.value for f in r.flags), rules_fired=tuple(r.rules_fired), supporting=preds(e.supporting),
        negative=preds(e.negative), missing=preds(e.missing),
        missing_measurements=tuple(f"{m.feature_id}@{m.scope}: {m.reason}" for m in e.missing_measurements),
        conflicting=preds(e.conflicting),
        conflicts=tuple(f"{'/'.join(l.value for l in c.labels)} rule={c.rule}" for c in e.conflicts),
        versions={"rules_version": record.rules_version, "contract_version": record.contract_version,
                  "schema_version": SCHEMA_VERSION, "parameter_set_id": record.parameter_set_id,
                  "parameter_set_sha256": record.parameter_set_sha256, "code_commit": record.code_commit,
                  "input_snapshot_sha256": record.input_snapshot_sha256, "result_sha256": record.result_sha256},
        validated_configuration=record.validated_configuration)
