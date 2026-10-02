import re

from ..errors import ParseError

_INT = re.compile(r"^-?\d+$")
_UINT = re.compile(r"^\d+$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def uint(tok: str, what: str = "value") -> int:
    if not _UINT.match(tok):
        raise ParseError(f"{what}: {tok!r} is not a non-negative integer")
    return int(tok)


def sint(tok: str, what: str = "value") -> int:
    if not _INT.match(tok):
        raise ParseError(f"{what}: {tok!r} is not an integer")
    return int(tok)


def hexint(tok: str, what: str = "value") -> int:
    if not _HEX.match(tok):
        raise ParseError(f"{what}: {tok!r} is not hexadecimal")
    return int(tok, 16)


def keyed(text: str, what: str) -> dict:
    """'key value' lines (cgroup cpu.stat, memory.stat, memory.events, /proc/vmstat)."""
    out = {}
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ParseError(f"{what} line {n}: expected 'key value', got {line!r}")
        if parts[0] in out:
            raise ParseError(f"{what}: duplicate key {parts[0]!r}")
        out[parts[0]] = uint(parts[1], f"{what}:{parts[0]}")
    if not out:
        raise ParseError(f"{what}: empty")
    return out


def single_uint(text: str, what: str) -> int:
    tok = text.strip()
    if not tok or len(tok.split()) != 1:
        raise ParseError(f"{what}: expected a single integer, got {text!r}")
    return uint(tok, what)
