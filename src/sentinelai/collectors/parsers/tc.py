"""Parser for ``tc -s -j qdisc show dev <if>`` JSON: only what net.drop.qdisc needs (contract §4.3)."""

import json
from dataclasses import dataclass
from typing import Tuple

from ..errors import ParseError


@dataclass(frozen=True)
class Qdisc:
    kind: str
    handle: str
    root: bool
    drops: int


def qdiscs(text: str) -> Tuple[Qdisc, ...]:
    """Validate the JSON and return every qdisc's identity and cumulative drop counter.
    Unknown fields are ignored; missing or mistyped required fields are ParseError (INVALID)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise ParseError(f"tc qdisc: malformed JSON ({exc})")
    if not isinstance(data, list):
        raise ParseError("tc qdisc: top level must be a list")
    out = []
    for i, q in enumerate(data):
        if not isinstance(q, dict):
            raise ParseError(f"tc qdisc[{i}]: not an object")
        kind, handle, drops, root = q.get("kind"), q.get("handle"), q.get("drops"), q.get("root", False)
        if not isinstance(kind, str) or not kind or not isinstance(handle, str) or not handle:
            raise ParseError(f"tc qdisc[{i}]: kind/handle missing or not strings")
        if type(drops) is not int or drops < 0:          # bool and float are rejected
            raise ParseError(f"tc qdisc[{i}]: drops missing or not a non-negative integer")
        if type(root) is not bool:
            raise ParseError(f"tc qdisc[{i}]: root is not a boolean")
        out.append(Qdisc(kind, handle, root, drops))
    return tuple(out)
