"""Parsers for cgroup v2 files (contract §4.1, §4.2, §4.6)."""

from typing import Dict, Optional, Tuple

from ..errors import ParseError
from ._common import keyed, single_uint, uint


def cpu_stat(text: str) -> Dict[str, int]:
    return keyed(text, "cpu.stat")


def cpu_max(text: str) -> Optional[Tuple[int, int]]:
    """cpu.max -> None for an unlimited quota ('max <period>'), else (quota_us, period_us).
    Unlimited, missing and unreadable are different states: only the first returns None."""
    parts = text.split()
    if len(parts) != 2:
        raise ParseError(f"cpu.max: expected '<quota|max> <period>', got {text!r}")
    period = uint(parts[1], "cpu.max period")
    if period <= 0:
        raise ParseError("cpu.max: period must be positive")
    if parts[0] == "max":
        return None
    quota = uint(parts[0], "cpu.max quota")
    if quota <= 0:
        raise ParseError("cpu.max: quota must be positive")
    return quota, period


def memory_max(text: str) -> Optional[int]:
    """memory.max -> None for 'max' (no limit), else bytes."""
    tok = text.strip()
    if tok == "max":
        return None
    return single_uint(tok, "memory.max")


def memory_stat(text: str) -> Dict[str, int]:
    return keyed(text, "memory.stat")


def memory_events(text: str) -> Dict[str, int]:
    return keyed(text, "memory.events")


def single(text: str, what: str) -> int:
    return single_uint(text, what)


def cpuset_list(text: str) -> Tuple[int, ...]:
    """'0-3,8' -> (0, 1, 2, 3, 8)."""
    tok = text.strip()
    if not tok:
        raise ParseError("cpuset: empty")
    cpus = set()
    for part in tok.split(","):
        a, sep, b = part.partition("-")
        lo = uint(a, "cpuset")
        hi = uint(b, "cpuset") if sep else lo
        if hi < lo:
            raise ParseError(f"cpuset: bad range {part!r}")
        cpus.update(range(lo, hi + 1))
    return tuple(sorted(cpus))
