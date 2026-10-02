"""Clocks. Collectors may read time; the M2 engine never does (contract P6)."""

import time
from datetime import datetime, timezone
from typing import List, Protocol, Tuple


def to_ms(dt: datetime) -> datetime:
    """UTC, truncated to milliseconds (contract §10: RFC 3339 with milliseconds)."""
    dt = dt.astimezone(timezone.utc)
    return dt.replace(microsecond=dt.microsecond // 1000 * 1000)


class Clock(Protocol):
    def monotonic(self) -> float: ...
    def wall(self) -> datetime: ...
    def sleep_until(self, mono: float) -> None: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def wall(self) -> datetime:
        return to_ms(datetime.now(timezone.utc))

    def sleep_until(self, mono: float) -> None:
        delay = mono - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class ManualClock:
    """Deterministic clock for fixtures: steps through the given (monotonic, wall) pairs."""

    def __init__(self, ticks: List[Tuple[float, datetime]]):
        self._ticks, self._i = list(ticks), 0

    def monotonic(self) -> float:
        return self._ticks[self._i][0]

    def wall(self) -> datetime:
        return to_ms(self._ticks[self._i][1])

    def sleep_until(self, mono: float) -> None:
        while self._ticks[self._i][0] < mono - 1e-9 and self._i + 1 < len(self._ticks):
            self._i += 1
