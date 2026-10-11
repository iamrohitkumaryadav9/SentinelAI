"""Application metrics (app.*): parse, validate and aggregate the workload's metrics document.

Transport-independent: this module never opens files or connections. A reader hands it the document bytes (or a Bad
observation); the reader itself is not part of this module.

Document schema v1 ("sentinelai-app-metrics/1", pilot design §5.5, proposed):
  {"schema": ..., "seq": int, "mono_ns": int, "pid": int, "config_sha256": 64 hex,
   "counters": {"requests_completed_total", "requests_failed_total", "requests_rejected_total": int},
   "events_total": {code: int for the four closed-set codes},
   "pool_size": int >= 1, "pool_busy": int in [0, pool_size],
   "histograms": {"latency" | "queue_wait" | "lock_wait" | "dependency_latency": [19 ints]}}
All integers are non-negative and cumulative since the workload started; histogram lists hold per-bucket counts for the
bucket upper bounds BUCKETS_MS (0.05 * 2^k ms, k = 0..17, then +Inf). Unknown or missing keys, non-integers, booleans,
NaN/Infinity and duplicate keys make the document MALFORMED.

Per-tick observation (observe): a stale document (seq not advanced, or older than STALE_NS) is Bad(ABSENT): no fresh
sample this tick, so coverage drops; a counter decrease, a pid change or a timestamp from the future is
Bad(MALFORMED): the sample is INVALID. Nothing is ever substituted.

Window values (window_values): percentiles are the upper bound of the bucket holding the nearest rank (conservative,
no interpolation); a window with no requests, or a rank in the +Inf bucket, yields no value, never 0.
"""
import json
import math
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple, Union

from .errors import Bad, Status

SCHEMA = "sentinelai-app-metrics/1"
MAX_BYTES = 256 * 1024
STALE_NS = 2_000_000_000
BUCKETS_MS = tuple(0.05 * 2 ** k for k in range(18)) + (math.inf,)
HISTOGRAMS = ("dependency_latency", "latency", "lock_wait", "queue_wait")
COUNTERS = ("requests_completed_total", "requests_failed_total", "requests_rejected_total")
EVENT_CODES = ("DEPENDENCY_TIMEOUT", "LOCK_WAIT_EXCEEDED", "POOL_EXHAUSTED", "QUEUE_FULL")
TOP_KEYS = frozenset({"schema", "seq", "mono_ns", "pid", "config_sha256", "counters", "events_total", "pool_size",
                      "pool_busy", "histograms"})
_SHA256 = re.compile(r"[0-9a-f]{64}")

# (feature, aggregation or qualifier) -> histogram and quantile
PERCENTILES = {("app.latency_ms", "P50"): ("latency", 0.50), ("app.latency_ms", "P99"): ("latency", 0.99),
               ("app.queue_wait_ms", "P99"): ("queue_wait", 0.99), ("app.lock_wait_ms", "P99"): ("lock_wait", 0.99),
               ("app.dependency_latency_ms", "P99"): ("dependency_latency", 0.99)}


@dataclass(frozen=True)
class AppSample:
    seq: int
    mono_ns: int
    pid: int
    config_sha256: str
    counters: Dict[str, int]
    events: Dict[str, int]
    pool_size: int
    pool_busy: int
    histograms: Dict[str, Tuple[int, ...]]


def _malformed(detail: str) -> Bad:
    return Bad(Status.MALFORMED, detail)


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _reject_constant(name):
    raise ValueError(f"non-finite number {name}")


def _count(x, what: str) -> int:
    if type(x) is not int or x < 0:          # bool is not accepted as an integer
        raise ValueError(f"{what} is not a non-negative integer")
    return x


def _exact(d, keys, what: str) -> dict:
    if not isinstance(d, dict) or set(d) != set(keys):
        raise ValueError(f"{what} keys differ from the schema")
    return d


def parse(data: bytes) -> Union[AppSample, Bad]:
    """One metrics document -> AppSample, or Bad(MALFORMED) with the reason. Never raises on bad input."""
    if not isinstance(data, (bytes, bytearray)):
        return _malformed("document is not bytes")
    if len(data) > MAX_BYTES:
        return _malformed(f"document larger than {MAX_BYTES} bytes")
    try:
        doc = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=_no_duplicates,
                         parse_constant=_reject_constant)
        _exact(doc, TOP_KEYS, "document")
        if doc["schema"] != SCHEMA:
            raise ValueError(f"schema {doc['schema']!r}")
        if not isinstance(doc["config_sha256"], str) or not _SHA256.fullmatch(doc["config_sha256"]):
            raise ValueError("config_sha256 is not 64 lowercase hex digits")
        pid = _count(doc["pid"], "pid")
        if pid == 0:
            raise ValueError("pid is 0")
        pool_size, pool_busy = _count(doc["pool_size"], "pool_size"), _count(doc["pool_busy"], "pool_busy")
        if pool_size == 0 or pool_busy > pool_size:
            raise ValueError("pool_busy/pool_size out of range")
        counters = {k: _count(v, k) for k, v in _exact(doc["counters"], COUNTERS, "counters").items()}
        events = {k: _count(v, f"events_total[{k}]")
                  for k, v in _exact(doc["events_total"], EVENT_CODES, "events_total").items()}
        hists = {}
        for name, counts in _exact(doc["histograms"], HISTOGRAMS, "histograms").items():
            if not isinstance(counts, list) or len(counts) != len(BUCKETS_MS):
                raise ValueError(f"histogram {name} does not have {len(BUCKETS_MS)} buckets")
            hists[name] = tuple(_count(c, f"histogram {name}") for c in counts)
        return AppSample(seq=_count(doc["seq"], "seq"), mono_ns=_count(doc["mono_ns"], "mono_ns"), pid=pid,
                         config_sha256=doc["config_sha256"], counters=counters, events=events, pool_size=pool_size,
                         pool_busy=pool_busy, histograms=hists)
    except (UnicodeDecodeError, ValueError, TypeError, KeyError, RecursionError) as exc:
        return _malformed(str(exc) or type(exc).__name__)


def _monotone(prev: AppSample, cur: AppSample) -> Optional[str]:
    for k in COUNTERS:
        if cur.counters[k] < prev.counters[k]:
            return f"counter {k} decreased"
    for k in EVENT_CODES:
        if cur.events[k] < prev.events[k]:
            return f"events_total[{k}] decreased"
    for name in HISTOGRAMS:
        if any(c < p for c, p in zip(cur.histograms[name], prev.histograms[name])):
            return f"histogram {name} decreased"
    return None


def observe(data: Union[bytes, Bad], prev: Optional[AppSample], now_mono_ns: int) -> Union[AppSample, Bad]:
    """One tick's observation. prev is the last *valid* sample (or None); now_mono_ns is the reader's CLOCK_MONOTONIC."""
    if isinstance(data, Bad):
        return data
    s = parse(data)
    if isinstance(s, Bad):
        return s
    if s.mono_ns > now_mono_ns:
        return _malformed("document timestamp is in the future")
    if prev is not None:
        if s.pid != prev.pid:
            return _malformed("workload pid changed (restart; counters reset)")
        if s.seq <= prev.seq:
            return Bad(Status.ABSENT, "stale: seq did not advance")
        if s.mono_ns <= prev.mono_ns:
            return _malformed("seq advanced but mono_ns did not")
        reason = _monotone(prev, s)
        if reason:
            return _malformed(f"{reason} (reset)")
    if now_mono_ns - s.mono_ns > STALE_NS:
        return Bad(Status.ABSENT, "stale: document older than 2 s")
    return s


def percentile(counts: Sequence[int], q: float) -> Tuple[Optional[float], Optional[str]]:
    """Upper bound (ms) of the bucket holding the nearest rank ceil(q * n); (None, reason) when it cannot be given."""
    if not 0.0 < q <= 1.0:
        raise ValueError("q must be in (0, 1]")
    n = sum(counts)
    if n == 0:
        return None, "no requests in the window"
    rank, acc = max(1, math.ceil(q * n)), 0
    for bound, c in zip(BUCKETS_MS, counts):
        acc += c
        if acc >= rank:
            return (None, "rank in the +Inf bucket") if math.isinf(bound) else (bound, None)
    raise AssertionError("unreachable")


def window_values(samples: Sequence[Union[AppSample, Bad]]) -> Dict[Tuple[str, str], Tuple[Optional[float], Optional[str]]]:
    """Window values from one window's per-tick observations, keyed by (feature, aggregation) and, for app.events,
    (feature, code). Counter-based values use the first and last valid samples; every value is (value, None) or
    (None, reason)."""
    valid: List[AppSample] = [s for s in samples if isinstance(s, AppSample)]
    out: Dict[Tuple[str, str], Tuple[Optional[float], Optional[str]]] = {}
    if valid:
        out[("app.pool_utilization", "MEAN")] = (sum(s.pool_busy / s.pool_size for s in valid) / len(valid), None)
    else:
        out[("app.pool_utilization", "MEAN")] = (None, "no valid samples")
    keys = list(PERCENTILES) + [("app.throughput", "RATE"), ("app.error_rate", "RATIO"),
                                ("app.pool_rejections", "RATE")] + [("app.events", c) for c in EVENT_CODES]
    if len(valid) < 2:
        out.update({k: (None, "fewer than two valid samples") for k in keys})
        return out
    a, b = valid[0], valid[-1]
    dt = (b.mono_ns - a.mono_ns) / 1e9
    if dt <= 0 or b.pid != a.pid:
        out.update({k: (None, "valid samples do not span positive time in one workload process") for k in keys})
        return out
    d = {k: b.counters[k] - a.counters[k] for k in COUNTERS}
    for key, (hist, q) in PERCENTILES.items():
        out[key] = percentile([y - x for x, y in zip(a.histograms[hist], b.histograms[hist])], q)
    out[("app.throughput", "RATE")] = (d["requests_completed_total"] / dt, None)
    out[("app.pool_rejections", "RATE")] = (d["requests_rejected_total"] / dt, None)
    total = d["requests_completed_total"] + d["requests_failed_total"]
    out[("app.error_rate", "RATIO")] = ((d["requests_failed_total"] / total, None) if total
                                       else (None, "no completed or failed requests"))
    for c in EVENT_CODES:
        out[("app.events", c)] = ((b.events[c] - a.events[c]) / dt, None)
    return out
