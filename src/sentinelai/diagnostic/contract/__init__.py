"""SentinelAI evidence contract (Phase 1C, milestone M1).

Data types and invariants only. No telemetry collection, no predicate evaluation, no
diagnosis (those are later milestones).
"""

from .catalog import Contract, ContractViolation, FeatureRegistry, FeatureSpec, load_contract
from .enums import (FAULT_LABELS, AbstentionReason, Aggregation, Availability, BaselineMethod, CandidateStatus,
                    ConfidenceLevel, EvidenceKind, Label, Quality, ScopeKind, SourceType, Strength, Unit)
from .ids import evidence_item_id, inputs_hash, measurement_id, snapshot_id
from .models import (BaselineStat, Candidate, Conflict, DataQuality, Deviation, DiagnosticResult, EngineInfo,
                     EvidenceItem, EvidenceSnapshot, Measurement, MissingMeasurement, MLAdvisory, Provenance,
                     Target, Threshold, Window, scope_kind)
from .serialize import canonical_bytes, canonical_json
from .validate import validate_against_snapshot
from .version import CONTRACT_ID, CONTRACT_VERSION, SCHEMA_VERSION

__all__ = [n for n in dir() if not n.startswith("_")]
