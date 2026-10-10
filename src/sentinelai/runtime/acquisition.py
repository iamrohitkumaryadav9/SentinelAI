"""acquisition.json: what build_snapshot needs besides the ticks, bound to the persisted tick stream (Phase 2A.3).

Data contracts only (no collection here; live collection is runtime/live.py, 2A.4). It describes ticks that were
already acquired, the optional live-collection block, and the FAILED record of an acquisition with no snapshot.
The record carries the resolved M1 Target, whether the ticks carry eBPF observations, the sample period,
the parameter-set id, the identity of ticks.jsonl (count, sha256, format), the per-source Bad-status counts
(missing / denied / malformed / ... observations, never zeros) and the collector versions that produced the
snapshot. Replay checks every field against the stream and against the context before reconstructing.
"""

from collections import Counter
from typing import Dict, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from ..collectors.errors import Bad
from ..diagnostic.contract import EvidenceSnapshot, Target

STRICT = ConfigDict(extra="forbid", frozen=True, strict=True)
FORMAT = "sentinelai.acquisition.v1"
FAILURE_FORMAT = "sentinelai.acquisition-failure.v1"


class AcquisitionFailed(RuntimeError):
    """Live acquisition could not produce a valid snapshot (stage: target | collect | snapshot | evidence)."""

    def __init__(self, stage: str, reason: str, *, target=None, ticks=(), started=None, ended=None):
        self.stage, self.reason, self.target, self.ticks, self.started, self.ended = \
            stage, reason, target, list(ticks), started, ended
        super().__init__(f"acquisition failed at {stage}: {reason}")


class AcquisitionInvalid(ValueError):
    """Ticks, target or flags are inconsistent with the context, or the stream does not reproduce the snapshot."""


class TickStream(BaseModel):
    model_config = STRICT
    format: str
    count: int = Field(ge=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CollectionInfo(BaseModel):
    """2A.4 live acquisition: how the ticks were collected (timing is observational, never part of an identity)."""
    model_config = STRICT
    mode: Literal["live-m3a"]
    reader: str
    started_wall: str
    ended_wall: str
    ticks: int = Field(ge=1)
    wall_s: float = Field(ge=0)
    cpu_s: float = Field(ge=0)
    max_rss_kb: int = Field(ge=0)
    max_tick_read_s: float = Field(ge=0)


class AcquisitionRecord(BaseModel):
    model_config = STRICT
    format: Literal["sentinelai.acquisition.v1"]
    status: Literal["COMPLETE", "PARTIAL"]          # PARTIAL: at least one observation is a Bad state
    target: Target
    ebpf: bool
    period_s: float
    parameter_set_id: str = Field(min_length=1)
    ticks: TickStream
    bad_counts: Dict[str, Dict[str, int]]           # source -> Bad status -> number of Bad observations
    collector_versions: Tuple[str, ...]
    collection: Optional[CollectionInfo] = None     # None: ticks supplied to the pure pipeline (2A.3)


class AcquisitionFailure(BaseModel):
    """acquisition.json of a FAILED acquisition: no snapshot, no diagnosis; the run is left incomplete."""
    model_config = STRICT
    format: Literal["sentinelai.acquisition-failure.v1"]
    status: Literal["FAILED"]
    stage: Literal["target", "collect", "snapshot", "evidence"]
    reason: str = Field(min_length=1)
    target: Optional[Target]
    parameter_set_id: str = Field(min_length=1)
    started_wall: str
    ended_wall: str
    ticks: int = Field(ge=0)
    bad_counts: Dict[str, Dict[str, int]]


def _walk(v, src, tally):
    if type(v) is Bad:
        tally[(src, v.status.value)] += 1
    elif type(v) is dict:
        for x in v.values():
            _walk(x, src, tally)
    elif type(v) in (list, tuple):
        for x in v:
            _walk(x, src, tally)


def bad_counts(ticks) -> Dict[str, Dict[str, int]]:
    tally = Counter()
    for t in ticks:
        for src, v in t.obs.items():
            _walk(v, src, tally)
    out: Dict[str, Dict[str, int]] = {}
    for (src, status), n in sorted(tally.items()):
        out.setdefault(src, {})[status] = n
    return out


def collector_versions(snapshot: EvidenceSnapshot) -> Tuple[str, ...]:
    return tuple(sorted({m.provenance.collector_version for m in snapshot.measurements}))
