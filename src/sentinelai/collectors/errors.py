"""Collector error and observation-status types."""

from dataclasses import dataclass
from enum import Enum


class CollectorError(RuntimeError):
    """A collector configuration or usage error (never used to encode missing data)."""


class ParseError(ValueError):
    """Source text does not have the expected structure. The sample is INVALID, never guessed."""


class Status(str, Enum):
    """Why an observation has no value. Absence is never encoded as a number (contract §10.3)."""
    ABSENT = "absent"            # file or field not present
    DENIED = "denied"            # permission denied
    MALFORMED = "malformed"      # present but not parseable -> INVALID sample
    UNVERIFIED = "unverified"    # readable, but not attributable to the target (e.g. netns unknown)


@dataclass(frozen=True)
class Bad:
    status: Status
    detail: str = ""
