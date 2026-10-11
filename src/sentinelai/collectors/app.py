"""Application metrics (app.*): parse, validate and aggregate the workload's metrics document.

Transport (pilot design §5.5, Q-3 file option): read_metrics(run_id) reads APP_ROOT/<run_id>/metrics.json and nothing
else. Every path component is opened relative to its parent with O_NOFOLLOW, so a symbolic link anywhere in the path
is refused; the final file must be a regular file of at most MAX_BYTES, owned by LAB_UID (the lab workload's identity),
and is opened non-blocking (a FIFO cannot stall the collector). Read-only by construction; no connection is ever made. A partially written document is returned as
read and rejected by parse(), never repaired.

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
import errno
import json
import math
import os
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple, Union

from ..diagnostic.contract import Aggregation, SourceType, Target
from .errors import Bad, CollectorError, Status
from .features import C, Calc, G, H, ratio
from .probes import get

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
APP_ROOT = "/run/sentinelai-lab/app/"
METRICS_FILE = "metrics.json"
RUN_ID = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*-s[0-9]+")          # run_id = <scenario_id>-s<seed> (design §8)
_S_IFMT, _S_IFREG = 0o170000, 0o100000                              # POSIX file-type mask and regular-file type
# The lab workload runs as the lab uid (scripts/r2c_cpu.py LAB_UID, used by every R2 lab process via setpriv; pilot
# design decision 2 runs the workload host-side, not in a container), so it owns the metrics file it writes.
LAB_UID = 1000

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


def _component(name: str, fd, extra: int) -> int:
    """The module's single read site: read-only, never follows a symbolic link, never blocks."""
    return os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | extra, dir_fd=fd)


def read_metrics(run_id: str) -> Union[bytes, Bad]:
    """Bytes of APP_ROOT/<run_id>/metrics.json, or the Bad observation that explains why there are none."""
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise CollectorError(f"invalid run_id {run_id!r}")
    fds: List[int] = []
    try:
        fds.append(_component("/", None, os.O_DIRECTORY))
        for part in [p for p in APP_ROOT.split("/") if p] + [run_id]:
            fds.append(_component(part, fds[-1], os.O_DIRECTORY))
        fds.append(_component(METRICS_FILE, fds[-1], 0))
        st = os.fstat(fds[-1])
        if st.st_mode & _S_IFMT != _S_IFREG:
            return Bad(Status.MALFORMED, "metrics path is not a regular file")
        if st.st_uid != LAB_UID:
            return Bad(Status.REFUSED, f"metrics file owned by uid {st.st_uid}, not the lab uid {LAB_UID}")
        if st.st_size > MAX_BYTES:
            return Bad(Status.MALFORMED, f"document larger than {MAX_BYTES} bytes")
        chunks, n = [], 0
        while n <= MAX_BYTES:                               # the file may grow between fstat and read
            chunk = os.read(fds[-1], MAX_BYTES + 1 - n)
            if not chunk:
                break
            chunks.append(chunk)
            n += len(chunk)
        if n > MAX_BYTES:
            return Bad(Status.MALFORMED, f"document larger than {MAX_BYTES} bytes")
        return b"".join(chunks)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return Bad(Status.REFUSED, "symbolic link or non-directory in the metrics path")
        if exc.errno in (errno.EACCES, errno.EPERM):
            return Bad(Status.DENIED, exc.strerror or "permission denied")
        if exc.errno == errno.ENOENT:
            return Bad(Status.ABSENT, exc.strerror or "not present")
        return Bad(Status.MALFORMED, exc.strerror or "unreadable")
    finally:
        for fd in reversed(fds):
            os.close(fd)


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


# ------------------------------------------------------------------------------------------ snapshot integration
APP_COLLECTOR_VERSION = "m4-app-1.0.0"
APP_FEATURES = ("app.dependency_latency_ms", "app.error_rate", "app.events", "app.latency_ms", "app.lock_wait_ms",
                "app.pool_rejections", "app.pool_utilization", "app.queue_wait_ms", "app.throughput")


def _flatten(s: AppSample) -> dict:
    d = {k: float(v) for k, v in s.counters.items()}
    d.update({f"events.{c}": float(v) for c, v in s.events.items()})
    d.update({f"hist.{h}": {i: float(c) for i, c in enumerate(s.histograms[h]) if c} for h in HISTOGRAMS})
    d["mono_s"] = s.mono_ns / 1e9
    d["pool_util"] = s.pool_busy / s.pool_size
    return d


class AppSource:
    """Per-tick app.* source for collect(): obs["app"] is the flattened valid document of this tick, or the Bad
    observation (absent, refused, stale, malformed, reset) that replaces it. prev is the last valid document."""

    def __init__(self, run_id: str, clock_ns=time.monotonic_ns):
        if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
            raise CollectorError(f"invalid run_id {run_id!r}")
        self.run_id, self.prev, self.clock_ns = run_id, None, clock_ns

    def sample(self) -> dict:
        s = observe(read_metrics(self.run_id), self.prev, self.clock_ns())
        if isinstance(s, Bad):
            return {"app": s}
        self.prev = s
        return {"app": _flatten(s)}


def _quantile(q: float):
    def f(d, dt):
        counts = [d["h"].get(i, 0.0) for i in range(len(BUCKETS_MS))]
        return percentile(counts, q)[0] if sum(counts) > 0 else None
    return f


def _per_doc_second(d, dt):
    """Counter delta over the documents' own time (their mono_ns), not over the collector's tick interval."""
    return d["x"] / d["t"] if d["t"] > 0 else None


def app_calcs(target: Target) -> Tuple[Calc, ...]:
    """The nine registry app.* features for the workload of target (scope app:<target name>)."""
    M, EV, V, A = SourceType.APP_METRICS, SourceType.APP_EVENTS, APP_COLLECTOR_VERSION, f"app:{target.name}"
    loc = "workload metrics.json (sentinelai-app-metrics/1)"
    t = ("t", C((("app", "mono_s"),)))
    no_req = "no requests in the window, or the rank is in the +Inf bucket"
    out = []
    for (feature, agg), (hist, q) in sorted(PERCENTILES.items()):
        out.append(Calc(feature, A, (("h", H("app", f"hist.{hist}")),), _quantile(q), M,
                        f"{loc} histogram {hist}: nearest-rank {agg}, bucket upper bound (ms)", "m4.app.metrics",
                        aggregation=Aggregation(agg), version=V, undefined=no_req))
    out += [Calc("app.throughput", A, (("x", C((("app", "requests_completed_total"),))), t), _per_doc_second, M,
                 f"{loc} requests_completed_total per second", "m4.app.metrics", version=V),
            Calc("app.pool_rejections", A, (("x", C((("app", "requests_rejected_total"),))), t), _per_doc_second, M,
                 f"{loc} requests_rejected_total per second", "m4.app.metrics", version=V),
            Calc("app.error_rate", A,
                 (("n", C((("app", "requests_failed_total"),))),
                  ("d", C((("app", "requests_completed_total"), ("app", "requests_failed_total"))))),
                 ratio, M, f"{loc} failed / (completed + failed)", "m4.app.metrics", version=V,
                 undefined="no completed or failed requests in the window"),
            Calc("app.pool_utilization", A, (("g", G(lambda obs: get(obs, "app", "pool_util"), "app:pool_util")),),
                 lambda d, dt: d["g"], M, f"{loc} pool_busy / pool_size, mean of ticks", "m4.app.metrics", version=V)]
    for code in EVENT_CODES:
        out.append(Calc("app.events", A, (("x", C((("app", f"events.{code}"),))), t), _per_doc_second, EV,
                        f"{loc} events_total[{code}] per second", "m4.app.events", qualifier=("code", code),
                        version=V))
    return tuple(out)
