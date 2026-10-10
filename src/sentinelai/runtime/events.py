"""Structured runtime events: append-only, observational only.

Events carry wall/monotonic time and identifiers, so they are deliberately kept out of every
deterministic identity and never read by the diagnosis path.
"""

import time
from datetime import datetime, timezone
from typing import Callable, Dict, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from ..diagnostic.contract.serialize import canonical_json

EventKind = Literal["acquisition_started", "acquisition_completed", "acquisition_failed", "snapshot_created",
                    "snapshot_validated", "diagnosis_started", "diagnosis_completed", "runtime_failure"]


class RuntimeEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    seq: int = Field(ge=0)
    kind: EventKind
    wall: str                      # RFC 3339 UTC, microseconds
    mono: float
    refs: Dict[str, str] = {}      # deterministic identifiers (incident_id, snapshot_id, diagnosis_id, ...)
    detail: str = ""


def system_clock() -> Tuple[datetime, float]:
    return datetime.now(timezone.utc), time.monotonic()


class EventLog:
    """Append-only: events can be added, never changed or removed. sink(line) receives each event as written."""

    def __init__(self, clock: Callable[[], Tuple[datetime, float]] = system_clock,
                 sink: Optional[Callable[[str], None]] = None):
        self._clock, self._sink, self._events = clock, sink, []

    def emit(self, kind: str, detail: str = "", **refs: str) -> RuntimeEvent:
        wall, mono = self._clock()
        ev = RuntimeEvent(seq=len(self._events), kind=kind, wall=wall.astimezone(timezone.utc).isoformat(),
                          mono=float(mono), refs={k: str(v) for k, v in refs.items()}, detail=detail)
        self._events.append(ev)
        if self._sink is not None:
            self._sink(canonical_json(ev))
        return ev

    @property
    def events(self) -> Tuple[RuntimeEvent, ...]:
        return tuple(self._events)
