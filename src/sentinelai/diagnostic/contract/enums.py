"""Contract enumerations (EVIDENCE_CONTRACT.md §10.1). Values are normative; do not rename."""

from enum import Enum


class _StrEnum(str, Enum):
    def __str__(self) -> str:  # stable textual form
        return self.value


class Label(_StrEnum):
    cpu_contention = "cpu_contention"
    cpu_throttling = "cpu_throttling"
    softirq_overload = "softirq_overload"
    network_packet_loss = "network_packet_loss"
    tcp_retransmissions = "tcp_retransmissions"
    memory_pressure = "memory_pressure"
    application_bottleneck = "application_bottleneck"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


#: The seven fault mechanisms. INSUFFICIENT_EVIDENCE is a decision, not a fault (contract §8.8).
FAULT_LABELS = tuple(l for l in Label if l is not Label.INSUFFICIENT_EVIDENCE)


class EvidenceKind(_StrEnum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    MISSING = "MISSING"
    CONFLICTING = "CONFLICTING"


class Strength(_StrEnum):
    STRONG = "STRONG"
    MODERATE = "MODERATE"
    WEAK = "WEAK"


class Quality(_StrEnum):
    OK = "OK"
    PARTIAL = "PARTIAL"
    STALE = "STALE"
    INVALID = "INVALID"
    MISSING = "MISSING"


class SourceType(_StrEnum):
    PROC = "PROC"
    SYSFS = "SYSFS"
    CGROUPFS = "CGROUPFS"
    TC = "TC"
    SS = "SS"
    EBPF = "EBPF"
    APP_METRICS = "APP_METRICS"
    APP_EVENTS = "APP_EVENTS"
    FAULTLAB_GROUND_TRUTH = "FAULTLAB_GROUND_TRUTH"
    DERIVED = "DERIVED"
    PROMETHEUS = "PROMETHEUS"  # future source type only; nothing is installed


class Aggregation(_StrEnum):
    RATE = "RATE"
    MEAN = "MEAN"
    GAUGE = "GAUGE"
    DELTA = "DELTA"
    RATIO = "RATIO"
    P50 = "P50"
    P90 = "P90"
    P99 = "P99"
    MAX = "MAX"


class Unit(_StrEnum):
    fraction = "fraction"
    cores = "cores"
    waiting_cores = "waiting_cores"
    per_second = "per_second"
    packets_per_second = "packets_per_second"
    segments_per_second = "segments_per_second"
    events_per_second = "events_per_second"
    pages_per_second = "pages_per_second"
    bytes = "bytes"
    bytes_per_second = "bytes_per_second"
    ms = "ms"
    count = "count"
    ratio = "ratio"


class CandidateStatus(_StrEnum):
    ASSERTED = "ASSERTED"
    CONTRIBUTING = "CONTRIBUTING"
    SUPPORTED_NOT_SUFFICIENT = "SUPPORTED_NOT_SUFFICIENT"
    CONTRADICTED = "CONTRADICTED"
    NOT_EVALUABLE = "NOT_EVALUABLE"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class ConfidenceLevel(_StrEnum):
    """Rule-engine ordinal confidence (contract §10.9). NOT a probability."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AbstentionReason(_StrEnum):
    NO_CANDIDATE = "NO_CANDIDATE"
    NO_IMPACT_OBSERVED = "NO_IMPACT_OBSERVED"
    REQUIRED_EVIDENCE_MISSING = "REQUIRED_EVIDENCE_MISSING"
    CONFLICT_UNRESOLVED = "CONFLICT_UNRESOLVED"
    LOSS_VS_RETRANS_UNDECIDABLE = "LOSS_VS_RETRANS_UNDECIDABLE"
    CONFOUNDER_NOT_EVALUATED = "CONFOUNDER_NOT_EVALUATED"
    DATA_QUALITY = "DATA_QUALITY"


class BaselineMethod(_StrEnum):
    within_run = "within_run"
    reference = "reference"


class Availability(_StrEnum):
    """Feature availability codes (contract §4)."""
    A = "A"
    A_UNVERIFIED = "A*"
    P = "P"
    L = "L"
    F = "F"


class ScopeKind(_StrEnum):
    host = "host"
    cpu = "cpu"
    cpuset = "cpuset"
    cgroup = "cgroup"
    netns = "netns"
    iface = "iface"
    socket = "socket"
    app = "app"
