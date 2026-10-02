"""Canonical, deterministic serialisation (contract invariant I7).

Canonical form:
  * JSON, keys sorted, separators ``(",", ":")``, UTF-8, no NaN/inf;
  * floats rendered with Python's shortest round-trip ``repr``; ``-0.0`` is rendered as ``0.0``;
  * enums rendered by value; timestamps as ``YYYY-MM-DDTHH:MM:SS.mmmZ`` (models' serialisers);
  * every array is treated as a set and sorted by the canonical encoding of its elements
    (no contract array is order-significant).
"""

import json
import math
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel


def format_timestamp(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}Z"


def format_float(x: float) -> str:
    if not math.isfinite(x):
        raise ValueError("non-finite float in canonical form")
    return repr(0.0 if x == 0 else float(x))


def _canon(obj):
    if isinstance(obj, BaseModel):
        return _canon(obj.model_dump(mode="json"))
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return format_timestamp(obj)
    if isinstance(obj, bool) or obj is None or isinstance(obj, (int, str)):
        return obj
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("non-finite float in canonical form")
        return 0.0 if obj == 0 else obj
    if isinstance(obj, dict):
        return {str(_canon(k)): _canon(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        items = [_canon(v) for v in obj]
        return sorted(items, key=lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    raise TypeError(f"cannot canonicalise {type(obj).__name__}")


def canonical_json(obj) -> str:
    return json.dumps(_canon(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonical_bytes(obj) -> bytes:
    return canonical_json(obj).encode("utf-8")
