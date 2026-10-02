"""Parsers for /sys/class/net/<if>/statistics/* (contract §4.3)."""

from ._common import single_uint


def counter(text: str, what: str) -> int:
    return single_uint(text, what)
