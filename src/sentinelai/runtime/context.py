"""IncidentContext: what the runtime is asked to investigate (Phase 2A).

Collection is forward-looking (baseline window B, then incident window W, from the moment collection
starts; B and W come from the parameter set), so there is no time-range field. The context never reaches
the snapshot: EvidenceSnapshot.incident_id stays None in v1 (decision Q3).
"""

import re
from typing import Literal, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import registry

STRICT = ConfigDict(extra="forbid", frozen=True, strict=True)
SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")      # also a safe single path segment


def check_segment(value: str, what: str) -> str:
    if not isinstance(value, str) or not SEGMENT.fullmatch(value) or value in (".", ".."):
        raise ValueError(f"{what} must match {SEGMENT.pattern}: {value!r}")
    return value


class TargetSpec(BaseModel):
    """Handed unchanged to collectors.resolve_target; pids, cpuset and netns are resolved, never supplied."""
    model_config = STRICT
    name: str = Field(min_length=1)
    cgroup_path: str
    ifaces: Tuple[str, ...] = ()

    @field_validator("cgroup_path")
    @classmethod
    def _cgroup(cls, v):
        if not v.startswith("/") or "\x00" in v or any(p in (".", "..") for p in v.split("/")):
            raise ValueError(f"cgroup_path must be an absolute cgroup path without . or ..: {v!r}")
        return v

    @field_validator("ifaces")
    @classmethod
    def _ifaces(cls, v):
        if len(set(v)) != len(v) or not all(re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", i) for i in v):
            raise ValueError(f"ifaces must be unique interface names: {v!r}")
        return v


class IncidentContext(BaseModel):
    model_config = STRICT
    incident_id: str
    target: TargetSpec
    parameter_set_id: str = registry.DEFAULT_PARAMETER_SET_ID
    ebpf: Literal["required", "disabled"] = "required"
    period_s: Literal[1.0] = 1.0

    @field_validator("incident_id")
    @classmethod
    def _incident(cls, v):
        return check_segment(v, "incident_id")

    @field_validator("period_s", mode="before")
    @classmethod
    def _period(cls, v):
        if type(v) is not float or v != 1.0:          # Literal[1.0] alone accepts int 1 and True
            raise ValueError("period_s is fixed at 1.0 (a float)")
        return v

    @model_validator(mode="after")
    def _check(self):
        if self.parameter_set_id not in registry.known():
            raise ValueError(f"unknown parameter_set_id {self.parameter_set_id!r}")
        return self
