"""Lossless tick serialisation (ticks.jsonl), so build_snapshot can be replayed from what was collected.

One tick per line: {"v": FORMAT, "index": int, "mono": <float>, "wall": <datetime>, "obs": <value>}.
Values are typed explicitly, because plain JSON would lose information the snapshot depends on:

  None, bool, int, str     -> the JSON value itself (JSON keeps bool and int apart)
  float                    -> {"f": float.hex(x)}       exact, including -0.0 and +-inf
                              {"nan": "<64-bit hex>"}   NaN with its bit pattern
  dict                     -> {"d": [[key, value], ...]} insertion order kept; key = {"s": str} | {"i": int}
  list / tuple             -> {"l": [...]} / {"t": [...]}
  collectors Bad           -> {"bad": [status, detail]}
  datetime (wall)          -> {"dt": isoformat}        timezone-aware only

Arrays keep their order (unlike the contract's canonical form, which treats arrays as sets). Object keys are
sorted and separators fixed, so the same tick always encodes to the same bytes. Any other type, an unknown
tag or a malformed line raises: nothing is dropped or defaulted.
"""

import json
import math
import struct
from datetime import datetime
from typing import List

from ..collectors.errors import Bad, Status
from ..collectors.normalize import Tick

FORMAT = "sentinelai.ticks.v1"


class TickFormatError(ValueError):
    """A tick or a ticks.jsonl line cannot be encoded/decoded without losing information."""


def _enc_float(x: float):
    if math.isnan(x):
        return {"nan": struct.pack(">d", x).hex()}
    return {"f": x.hex()}


def _enc_key(k):
    if type(k) is str:
        return {"s": k}
    if type(k) is int:
        return {"i": k}
    raise TickFormatError(f"unsupported dict key type {type(k).__name__}")


def encode_value(v):
    t = type(v)
    if v is None or t in (bool, int, str):
        return v
    if t is float:
        return _enc_float(v)
    if t is dict:
        return {"d": [[_enc_key(k), encode_value(x)] for k, x in v.items()]}
    if t is list:
        return {"l": [encode_value(x) for x in v]}
    if t is tuple:
        return {"t": [encode_value(x) for x in v]}
    if t is Bad:
        if type(v.status) is not Status or type(v.detail) is not str:
            raise TickFormatError(f"malformed Bad {v!r}")
        return {"bad": [v.status.value, v.detail]}
    if t is datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise TickFormatError("naive datetime")
        return {"dt": v.isoformat()}
    raise TickFormatError(f"unsupported value type {t.__name__}")


def _one(obj, tags):
    if type(obj) is not dict or len(obj) != 1 or next(iter(obj)) not in tags:
        raise TickFormatError(f"expected one of {sorted(tags)}: {obj!r}"[:200])
    (tag, body), = obj.items()
    return tag, body


def _dec_key(obj):
    tag, body = _one(obj, ("s", "i"))
    if (tag == "s" and type(body) is not str) or (tag == "i" and type(body) is not int):
        raise TickFormatError(f"malformed key {obj!r}")
    return body


def decode_value(obj):
    if obj is None or type(obj) in (bool, int, str):
        return obj
    tag, body = _one(obj, ("f", "nan", "d", "l", "t", "bad", "dt"))
    try:
        if tag == "f":
            if type(body) is not str:
                raise TickFormatError("float body must be a hex string")
            x = float.fromhex(body)
            if math.isnan(x):
                raise TickFormatError("NaN must use the 'nan' tag")
            return x
        if tag == "nan":
            if type(body) is not str or len(body) != 16:
                raise TickFormatError("nan body must be 16 hex digits")
            x = struct.unpack(">d", bytes.fromhex(body))[0]
            if not math.isnan(x):
                raise TickFormatError("'nan' tag with a non-NaN pattern")
            return x
        if tag == "d":
            if type(body) is not list:
                raise TickFormatError("dict body must be a list of pairs")
            out = {}
            for pair in body:
                if type(pair) is not list or len(pair) != 2:
                    raise TickFormatError("dict pair must be [key, value]")
                k = _dec_key(pair[0])
                if k in out:
                    raise TickFormatError(f"duplicate dict key {k!r}")
                out[k] = decode_value(pair[1])
            return out
        if tag in ("l", "t"):
            if type(body) is not list:
                raise TickFormatError("sequence body must be a list")
            items = [decode_value(x) for x in body]
            return items if tag == "l" else tuple(items)
        if tag == "bad":
            if type(body) is not list or len(body) != 2 or type(body[1]) is not str:
                raise TickFormatError("bad body must be [status, detail]")
            return Bad(Status(body[0]), body[1])
        if type(body) is not str:
            raise TickFormatError("dt body must be an ISO string")
        dt = datetime.fromisoformat(body)
        if dt.tzinfo is None:
            raise TickFormatError("naive datetime")
        return dt
    except (ValueError, OverflowError, struct.error) as exc:
        if isinstance(exc, TickFormatError):
            raise
        raise TickFormatError(f"malformed {tag!r} value: {exc}") from None


def _dumps(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def encode_tick(tick: Tick) -> str:
    if type(tick) is not Tick or type(tick.index) is not int or type(tick.mono) is not float \
            or type(tick.wall) is not datetime or type(tick.obs) is not dict:
        raise TickFormatError(f"not a well-formed Tick: {tick!r}"[:200])
    return _dumps({"v": FORMAT, "index": tick.index, "mono": encode_value(tick.mono),
                   "wall": encode_value(tick.wall), "obs": encode_value(tick.obs)})


def decode_tick(line: str) -> Tick:
    try:
        obj = json.loads(line)
    except ValueError as exc:
        raise TickFormatError(f"not JSON: {exc}") from None
    if type(obj) is not dict or set(obj) != {"v", "index", "mono", "wall", "obs"} or obj["v"] != FORMAT:
        raise TickFormatError(f"not a {FORMAT} tick line")
    index, mono, wall, obs = obj["index"], decode_value(obj["mono"]), decode_value(obj["wall"]), decode_value(obj["obs"])
    if type(index) is not int or type(mono) is not float or type(wall) is not datetime or type(obs) is not dict:
        raise TickFormatError("tick fields have the wrong types")
    if _dumps(obj) != line:
        raise TickFormatError("line is not in canonical form")
    return Tick(index, mono, wall, obs)


def encode_ticks(ticks: List[Tick]) -> bytes:
    for k, t in enumerate(ticks):
        if type(t) is not Tick or t.index != k:
            raise TickFormatError(f"tick {k} out of sequence")
    return "".join(encode_tick(t) + "\n" for t in ticks).encode("utf-8")


def decode_ticks(data: bytes) -> List[Tick]:
    text = data.decode("utf-8")
    if text and not text.endswith("\n"):
        raise TickFormatError("ticks.jsonl must end with a newline")
    ticks = [decode_tick(line) for line in text.splitlines()]
    for k, t in enumerate(ticks):
        if t.index != k:
            raise TickFormatError(f"tick {k} out of sequence")
    return ticks
