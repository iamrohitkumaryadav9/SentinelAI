"""SentinelAI Runtime v1 (Phase 2A): composes the validated M1/M2/M3 components; never replaces them.

2A.1 is the pure core: contracts, the parameter-set registry, lossless ticks, the write-once artifact store,
runtime events, DiagnosisRecord/report and the snapshot -> M2 pipeline. No live collection, no eBPF, no host
change; the only writes are inside the caller's ArtifactStore root. M2 remains the only decision-maker.
"""

from .context import IncidentContext, TargetSpec
from .events import EventLog, RuntimeEvent
from .pipeline import SnapshotInvalid, SnapshotMutated, diagnose_snapshot, run_pure, validate_snapshot
from .registry import DEFAULT_PARAMETER_SET_ID, RegistryIntegrityError, UnknownParameterSet
from .report import DiagnosisRecord, Report, build_report, diagnosis_id
from .store import ArtifactStore, StoreError, verify_run
from .ticks import TickFormatError, decode_ticks, encode_ticks

__all__ = ["ArtifactStore", "DEFAULT_PARAMETER_SET_ID", "DiagnosisRecord", "EventLog", "IncidentContext",
           "RegistryIntegrityError", "Report", "RuntimeEvent", "SnapshotInvalid", "SnapshotMutated", "StoreError",
           "TargetSpec", "TickFormatError", "UnknownParameterSet", "build_report", "decode_ticks", "diagnose_snapshot",
           "diagnosis_id", "encode_ticks", "run_pure", "validate_snapshot", "verify_run"]
