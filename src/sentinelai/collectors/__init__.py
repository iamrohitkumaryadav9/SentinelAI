"""Phase 1C M3A: read-only Linux evidence collection.

Linux host -> probes (acquisition + parsing) -> normalisation -> Measurement -> EvidenceSnapshot.
Collectors observe; the M2 rule engine diagnoses. No eBPF, ss, network changes or privileges; the only
command is the read-only qdisc statistics query in commands/tc.py (M3A-C1).
"""

from .clock import ManualClock, SystemClock
from .errors import Bad, CollectorError, ParseError, Status
from .features import COLLECTOR_VERSION
from .reader import FixtureReader, LiveReader
from .snapshot import (CollectionStats, build_snapshot, check_parameters, collect, collect_snapshot,
                       collected_features)
from .target import resolve_target

__all__ = ["Bad", "CollectionStats", "COLLECTOR_VERSION", "CollectorError", "FixtureReader", "LiveReader",
           "ManualClock", "ParseError", "Status", "SystemClock", "build_snapshot", "check_parameters", "collect",
           "collect_snapshot", "collected_features", "resolve_target"]
