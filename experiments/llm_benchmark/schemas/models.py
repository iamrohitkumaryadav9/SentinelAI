"""Strict schemas used to machine-validate model output (Phase 1B).

All models forbid extra fields so that invented arguments/fields are detected.
"""

from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

INCIDENT_TYPES = (
    "cpu_contention",
    "cpu_throttling",
    "network_packet_loss",
    "softirq_overload",
    "memory_pressure",
    "tcp_retransmissions",
    "INSUFFICIENT_EVIDENCE",
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=False)


# --- Tool argument schemas --------------------------------------------------
class CpuMetricsArgs(_Strict):
    host: Optional[str] = Field(None, min_length=1, max_length=64)
    window_seconds: Optional[int] = Field(None, ge=10, le=3600)


class NetworkMetricsArgs(_Strict):
    host: Optional[str] = Field(None, min_length=1, max_length=64)
    interface: Optional[str] = Field(None, min_length=1, max_length=16)
    window_seconds: Optional[int] = Field(None, ge=10, le=3600)


class SchedulerLatencyArgs(_Strict):
    cpu: Optional[int] = Field(None, ge=0, le=23)
    percentile: Optional[Literal[50, 90, 99]] = None


class RecentLogsArgs(_Strict):
    service: str = Field(..., min_length=1, max_length=64)
    level: Optional[Literal["error", "warn", "info"]] = None
    limit: Optional[int] = Field(None, ge=1, le=200)


class RunExperimentArgs(_Strict):
    experiment: Literal["baseline", "cpu_stress", "net_delay", "mem_pressure"]
    duration_seconds: int = Field(..., ge=1, le=300)


TOOL_ARG_MODELS = {
    "get_cpu_metrics": CpuMetricsArgs,
    "get_network_metrics": NetworkMetricsArgs,
    "get_scheduler_latency": SchedulerLatencyArgs,
    "get_recent_logs": RecentLogsArgs,
    "run_experiment": RunExperimentArgs,
}


# --- Structured incident diagnosis -----------------------------------------
class IncidentDiagnosis(_Strict):
    incident_type: Literal[INCIDENT_TYPES]  # type: ignore[valid-type]
    severity: int = Field(..., ge=0, le=5)
    hypotheses: List[str] = Field(..., min_length=1, max_length=5)
    evidence_required: List[str] = Field(..., min_length=1, max_length=8)
    next_action: str = Field(..., min_length=1)
    confidence: float = Field(..., ge=0.0, le=1.0)


INCIDENT_FIELDS = tuple(IncidentDiagnosis.model_fields)
