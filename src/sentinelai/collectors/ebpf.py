"""Phase 1C M3B: eBPF evidence (contract §4.1, §4.4, §4.5) from the loader's line protocol.

The privileged loader (ebpf/loader) aggregates in the kernel and answers each request with one
line of CUMULATIVE counters (ebpf/include/sentinel_host.h). This module is pure: it validates
those lines strictly, turns them into tick observations (counters, never deltas) and defines the
four contract measurements. Rates, window values, coverage, quality and baselines then come from
the same normalisation as every M3A feature.

Fail closed:
  * a malformed line, a protocol/geometry mismatch, a non-advancing sequence or clock, or a loader
    configured for a different target makes every eBPF source Bad for that tick (never zero);
  * an unavailable loader makes every eBPF source Bad (MISSING measurements, never "no events");
  * a kfree_skb reason is reported as the kernel named it; unnamed core values are UNKNOWN_<n> and
    reasons beyond the core enum are UNKNOWN_OVERFLOW. Nothing is interpreted as packet loss here.
Process management lives outside the collector layer (sentinelai.ebpf).
"""

import json
import math
import re
from dataclasses import dataclass
from typing import Dict, Optional, Sequence, Tuple

from ..diagnostic.contract import Aggregation, SourceType, Target, load_contract
from .errors import Bad, Status
from .features import C, Calc, H, rate

EBPF_COLLECTOR_VERSION = "m3b-1.0.0"
PROTOCOL_VERSION = 1
HIST_SUB_BITS, HIST_MAX_MSB = 4, 35
HIST_SUB = 1 << HIST_SUB_BITS
HIST_BUCKETS = HIST_SUB + (HIST_MAX_MSB - HIST_SUB_BITS + 1) * HIST_SUB      # 528
KFREE_SLOTS = 128
VECTORS = ("HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU")
STATS = ("wake_recorded", "wake_repeat", "wake_new", "wake_new_replaced", "wake_update_failed",
         "wake_cancelled_running", "lat_recorded", "lat_migrated", "lat_stale", "lat_negative",
         "sirq_recorded", "sirq_unmatched_exit", "sirq_mismatch", "sirq_entry_overwritten", "sirq_invalid_vec",
         "sirq_stale", "sirq_negative", "retrans_other_netns", "retrans_unattributed", "kfree_other_netns",
         "kfree_unattributed", "kfree_overflow")
EBPF_SOURCES = ("ebpf.sched", "ebpf.softirq", "ebpf.retrans", "ebpf.kfree")
EBPF_FEATURES = ("sched.latency_hist.target", "softirq.exec_time.percpu", "tcp.retrans_skb_rate",
                 "net.drop.kfree_skb")
OVERFLOW_REASON = "UNKNOWN_OVERFLOW"
MAX_LINE = 1 << 22
_REASON = re.compile(r"^[A-Z0-9_]+$")
_U64 = (1 << 64) - 1


class ProtocolError(ValueError):
    """A loader line does not have the exact expected structure."""


# ------------------------------------------------------------------------------------------ histogram
def bucket_lo(i: int) -> int:
    """Inclusive lower bound (ns) of histogram bucket i (mirrors sn_hist_lo in sentinel_shared.h)."""
    if not 0 <= i < HIST_BUCKETS:
        raise ValueError(f"bucket {i} out of range")
    if i < HIST_SUB:
        return i
    g, s = divmod(i - HIST_SUB, HIST_SUB)
    return (HIST_SUB + s) << g


def bucket_hi(i: int) -> int:
    """Inclusive upper bound (ns) of histogram bucket i (mirrors sn_hist_hi)."""
    if i < HIST_SUB:
        return bucket_lo(i)
    return bucket_lo(i) + (1 << ((i - HIST_SUB) // HIST_SUB)) - 1


def bucket_index(v: int) -> int:
    """Bucket of a latency of v ns (mirrors sn_hist_index; used by tests only)."""
    if v < HIST_SUB:
        return v
    v = min(v, (1 << (HIST_MAX_MSB + 1)) - 1)
    msb = v.bit_length() - 1
    return HIST_SUB + (msb - HIST_SUB_BITS) * HIST_SUB + ((v >> (msb - HIST_SUB_BITS)) & (HIST_SUB - 1))


def quantile_ns(hist: Dict[int, float], q: float) -> Optional[int]:
    """Nearest-rank quantile (the project's convention, normalize.baseline_stats: the ceil(q*n)-th
    smallest sample) of a bucketed distribution, reported as the inclusive upper edge of the bucket
    that holds that sample: never below the true value, at most one bucket width (<= 1/16 of the
    octave) above it. None when the distribution is empty (no sample is never 0 ms)."""
    n = sum(hist.values())
    if n <= 0:
        return None
    rank = max(1, math.ceil(q * n))
    seen = 0.0
    for i in sorted(hist):
        seen += hist[i]
        if seen >= rank:
            return bucket_hi(i)
    raise AssertionError("unreachable: rank <= n")


def quantile_ms(q: float):
    def combine(d, dt):
        v = quantile_ns(d["h"], q)
        return None if v is None else v / 1e6
    return combine


# ------------------------------------------------------------------------------------------ protocol
@dataclass(frozen=True)
class EbpfTarget:
    """What the loader must have been configured for (checked against every stream's meta line)."""
    cgroup_id: int
    cgroup_level: int
    netns_inum: int


@dataclass(frozen=True)
class Meta:
    producer: str
    version: str
    libbpf: str
    ncpu: int
    target: EbpfTarget
    lat_stale_ns: int
    sirq_stale_ns: int
    reasons: Tuple[str, ...]           # name of every kfree slot 0..KFREE_SLOTS (index = slot)


@dataclass(frozen=True)
class Sample:
    seq: int
    mono_ns: int
    hist: Dict[int, int]
    softirq: Dict[Tuple[int, int], Tuple[int, int]]   # (cpu, vec) -> (ns, count)
    retrans: int
    kfree: Dict[int, int]
    stats: Dict[str, int]


def _obj(line: str) -> dict:
    if not isinstance(line, str) or len(line) > MAX_LINE:
        raise ProtocolError("line missing or too long")
    try:
        d = json.loads(line)
    except ValueError as exc:
        raise ProtocolError(f"not JSON: {exc}")
    if not isinstance(d, dict) or d.get("v") != PROTOCOL_VERSION:
        raise ProtocolError("not a protocol v1 object")
    return d


def _keys(d: dict, want, what: str):
    if set(d) != set(want):
        raise ProtocolError(f"{what}: keys {sorted(d)} != {sorted(want)}")


def _u(x, what: str, hi: int = _U64) -> int:
    if not isinstance(x, int) or isinstance(x, bool) or not 0 <= x <= hi:
        raise ProtocolError(f"{what}: {x!r} is not an integer in [0, {hi}]")
    return x


def terminal_reason(line: str) -> Optional[str]:
    """The reason of an 'unavailable' / 'end' line, or None for any other line."""
    try:
        d = _obj(line)
    except ProtocolError:
        return None
    if d.get("type") in ("unavailable", "end") and isinstance(d.get("reason"), str):
        return f"{d['type']}: {d['reason']}"
    return None


def parse_meta(line: str) -> Meta:
    d = _obj(line)
    if d.get("type") != "meta":
        raise ProtocolError(terminal_reason(line) or "first line is not a meta line")
    _keys(d, ("v", "type", "producer", "version", "libbpf", "ncpu", "cfg", "hist", "kfree_slots", "vectors",
              "reasons", "stats"), "meta")
    if d["producer"] not in ("sentinel_loader", "sentinel_replay"):
        raise ProtocolError(f"unknown producer {d['producer']!r}")
    if d["version"] != EBPF_COLLECTOR_VERSION:
        raise ProtocolError(f"loader version {d['version']!r} != {EBPF_COLLECTOR_VERSION}")
    if not (isinstance(d["libbpf"], str) and d["libbpf"].startswith("1.")):
        raise ProtocolError(f"loader reports libbpf {d['libbpf']!r}, expected 1.x")
    if d["hist"] != {"sub_bits": HIST_SUB_BITS, "max_msb": HIST_MAX_MSB, "buckets": HIST_BUCKETS}:
        raise ProtocolError(f"histogram geometry {d['hist']} differs from the collector's")
    if d["kfree_slots"] != KFREE_SLOTS or d["vectors"] != list(VECTORS) or d["stats"] != list(STATS):
        raise ProtocolError("kfree slots, vector names or stat names differ from the collector's")
    cfg = d["cfg"]
    if not isinstance(cfg, dict):
        raise ProtocolError("cfg is not an object")
    _keys(cfg, ("cgroup_id", "cgroup_level", "netns_inum", "lat_stale_ns", "sirq_stale_ns"), "cfg")
    names = [None] * KFREE_SLOTS
    if not isinstance(d["reasons"], list):
        raise ProtocolError("reasons is not a list")
    for item in d["reasons"]:
        if not (isinstance(item, list) and len(item) == 2):
            raise ProtocolError("reason entry is not [slot, name]")
        slot, name = _u(item[0], "reason slot", KFREE_SLOTS - 1), item[1]
        if not (isinstance(name, str) and _REASON.match(name)) or names[slot] is not None:
            raise ProtocolError(f"reason {item!r} malformed or duplicated")
        if name == OVERFLOW_REASON or name.startswith("UNKNOWN_"):
            raise ProtocolError(f"kernel reason name {name!r} collides with a collector placeholder")
        names[slot] = name
    if len(set(n for n in names if n)) != len([n for n in names if n]):
        raise ProtocolError("duplicate reason names")
    reasons = tuple(n or f"UNKNOWN_{i}" for i, n in enumerate(names)) + (OVERFLOW_REASON,)
    return Meta(producer=d["producer"], version=d["version"], libbpf=d["libbpf"], ncpu=_u(d["ncpu"], "ncpu", 1024),
                target=EbpfTarget(_u(cfg["cgroup_id"], "cgroup_id"), _u(cfg["cgroup_level"], "cgroup_level", 64),
                                  _u(cfg["netns_inum"], "netns_inum", (1 << 32) - 1)),
                lat_stale_ns=_u(cfg["lat_stale_ns"], "lat_stale_ns"), sirq_stale_ns=_u(cfg["sirq_stale_ns"], "sirq_stale_ns"),
                reasons=reasons)


def parse_sample(line: str, meta: Meta) -> Sample:
    d = _obj(line)
    if d.get("type") != "sample":
        raise ProtocolError(terminal_reason(line) or "not a sample line")
    _keys(d, ("v", "type", "seq", "mono_ns", "sched", "softirq", "retrans", "kfree", "stats"), "sample")
    if not isinstance(d["sched"], dict):
        raise ProtocolError("sched is not an object")
    _keys(d["sched"], ("hist",), "sched")
    hist = {}
    for item in d["sched"]["hist"] if isinstance(d["sched"]["hist"], list) else [None]:
        if not (isinstance(item, list) and len(item) == 2):
            raise ProtocolError("hist entry is not [bucket, count]")
        i = _u(item[0], "bucket", HIST_BUCKETS - 1)
        if i in hist:
            raise ProtocolError(f"duplicate bucket {i}")
        hist[i] = _u(item[1], "bucket count")
    sirq = {}
    for item in d["softirq"] if isinstance(d["softirq"], list) else [None]:
        if not (isinstance(item, list) and len(item) == 4):
            raise ProtocolError("softirq entry is not [cpu, vec, ns, count]")
        key = (_u(item[0], "cpu", meta.ncpu - 1), _u(item[1], "vec", len(VECTORS) - 1))
        if key in sirq:
            raise ProtocolError(f"duplicate softirq entry {key}")
        sirq[key] = (_u(item[2], "softirq ns"), _u(item[3], "softirq count"))
    if len(sirq) != meta.ncpu * len(VECTORS):
        raise ProtocolError("softirq entries do not cover every CPU x vector exactly once")
    kfree = {}
    for item in d["kfree"] if isinstance(d["kfree"], list) else [None]:
        if not (isinstance(item, list) and len(item) == 2):
            raise ProtocolError("kfree entry is not [slot, count]")
        s = _u(item[0], "kfree slot", KFREE_SLOTS)
        if s in kfree:
            raise ProtocolError(f"duplicate kfree slot {s}")
        kfree[s] = _u(item[1], "kfree count")
    if not isinstance(d["stats"], dict):
        raise ProtocolError("stats is not an object")
    _keys(d["stats"], STATS, "stats")
    stats = {k: _u(v, f"stat {k}") for k, v in d["stats"].items()}
    return Sample(seq=_u(d["seq"], "seq"), mono_ns=_u(d["mono_ns"], "mono_ns"), hist=hist, softirq=sirq,
                  retrans=_u(d["retrans"], "retrans"), kfree=kfree, stats=stats)


def bad_obs(status: Status, detail: str) -> dict:
    b = Bad(status, detail)
    return {s: b for s in EBPF_SOURCES}


def sample_obs(meta: Meta, s: Sample) -> dict:
    """Tick observation from one sample: cumulative counters keyed like every other source."""
    return {
        "ebpf.sched": {"hist": {i: float(c) for i, c in s.hist.items()}},
        "ebpf.softirq": {f"cpu{c}.{VECTORS[v]}": float(ns) for (c, v), (ns, _) in s.softirq.items()},
        "ebpf.retrans": {"target": float(s.retrans)},
        # every slot is present (an absent slot is a cumulative 0 of an attached program)
        "ebpf.kfree": {meta.reasons[i]: float(s.kfree.get(i, 0)) for i in range(KFREE_SLOTS + 1)},
    }


class EbpfStream:
    """Validates one loader stream: meta first, then samples whose seq and clock strictly advance."""

    def __init__(self, expect: EbpfTarget):
        self.expect, self.meta, self.failed = expect, None, None
        self.fail_status = Status.ABSENT
        self._last = None

    def start(self, line: str) -> Optional[str]:
        """Consume the first line. Returns None when usable, else the reason the stream is unusable."""
        try:
            meta = parse_meta(line)
        except ProtocolError as exc:
            self.failed = f"loader unavailable: {exc}"
            return self.failed
        if meta.target != self.expect:   # observations of another cgroup / netns: not attributable
            self.failed = f"loader configured for {meta.target}, expected {self.expect}"
            self.fail_status = Status.UNVERIFIED
            return self.failed
        self.meta = meta
        return None

    def observe(self, line: Optional[str]) -> dict:
        if self.meta is None:
            return bad_obs(self.fail_status, self.failed or "eBPF stream not started")
        if line is None:
            return bad_obs(Status.TIMEOUT, "no sample from the eBPF loader")
        try:
            s = parse_sample(line, self.meta)
        except ProtocolError as exc:
            reason = terminal_reason(line)
            if reason:
                return bad_obs(Status.ABSENT, f"eBPF loader {reason}")
            return bad_obs(Status.MALFORMED, f"eBPF sample: {exc}")
        if self._last is not None and (s.seq <= self._last[0] or s.mono_ns <= self._last[1]):
            return bad_obs(Status.MALFORMED, "eBPF sample sequence or clock did not advance")
        self._last = (s.seq, s.mono_ns)
        return sample_obs(self.meta, s)


class FixtureEbpfSource:
    """Serves recorded loader lines (meta first, then one sample per tick). Deterministic, no I/O."""

    def __init__(self, lines: Sequence[str], expect: EbpfTarget):
        self._lines = [l for l in lines if l.strip()]
        self.stream = EbpfStream(expect)
        self._i = 1
        if not self._lines:
            self.stream.failed = "no loader output"
        else:
            self.stream.start(self._lines[0])

    def sample(self) -> dict:
        line = self._lines[self._i] if self._i < len(self._lines) else None
        self._i += 1
        return self.stream.observe(line)


class UnavailableEbpfSource:
    """The eBPF loader could not run (no privileges, no BTF, refused): every eBPF source is Bad."""

    def __init__(self, reason: str, status: Status = Status.DENIED):
        self.reason, self.status = reason, status

    def sample(self) -> dict:
        return bad_obs(self.status, self.reason)


# ------------------------------------------------------------------------------------------ features
_LAT_LOC = ("eBPF tp_btf/sched_wakeup,sched_wakeup_new -> tp_btf/sched_switch for tasks in the target cgroup "
            "subtree; log-linear histogram (16 sub-buckets/octave); {q}: nearest-rank, bucket upper edge")


def ebpf_calcs(target: Target, cpus: Sequence[int], reasons: Sequence[str]) -> Tuple[Calc, ...]:
    """The four contract features (M3B-C0 semantics). cpus: CPUs to report softirq time for;
    reasons: kfree_skb reasons observed in the run (no measurement is invented for unseen reasons)."""
    E, V = SourceType.EBPF, EBPF_COLLECTOR_VERSION
    CG, NS = f"cgroup:{target.cgroup_path}", f"netns:{target.name}"
    none_seen = "no wakeup->switch latency of the target was observed in the window"
    out = [Calc("sched.latency_hist.target", CG, (("h", H("ebpf.sched", "hist")),), quantile_ms(0.50), E,
                _LAT_LOC.format(q="P50"), "m3b.ebpf.sched", aggregation=Aggregation.P50, version=V, undefined=none_seen),
           Calc("sched.latency_hist.target", CG, (("h", H("ebpf.sched", "hist")),), quantile_ms(0.99), E,
                _LAT_LOC.format(q="P99"), "m3b.ebpf.sched", aggregation=Aggregation.P99, version=V, undefined=none_seen),
           Calc("tcp.retrans_skb_rate", NS, (("x", C((("ebpf.retrans", "target"),))),), rate(), E,
                "eBPF tp_btf/tcp_retransmit_skb events (one per retransmitted skb, not segments) whose socket netns "
                "is the target netns", "m3b.ebpf.tcp", version=V)]
    for n in cpus:
        for vec in VECTORS:
            out.append(Calc("softirq.exec_time.percpu", f"cpu:{n}", (("x", C((("ebpf.softirq", f"cpu{n}.{vec}"),))),),
                            rate(1e-9), E, f"eBPF tp_btf/softirq_entry -> softirq_exit on CPU {n}, vector {vec}: "
                            "sum(exit - entry) ns / dt", "m3b.ebpf.softirq", qualifier=("vector", vec), version=V))
    for r in reasons:
        out.append(Calc("net.drop.kfree_skb", NS, (("x", C((("ebpf.kfree", r),))),), rate(), E,
                        f"eBPF tp_btf/kfree_skb with kernel reason {r}; netns of skb->dev, else of skb->sk, "
                        "is the target netns", "m3b.ebpf.kfree", qualifier=("reason", r), version=V))
    return tuple(out)


def softirq_cpus(ticks) -> Tuple[int, ...]:
    """CPUs present in the eBPF softirq source of any tick."""
    out = set()
    for t in ticks:
        s = t.obs.get("ebpf.softirq")
        if isinstance(s, dict):
            out |= {int(k[3:].split(".")[0]) for k in s}
    return tuple(sorted(out))


def observed_reasons(ticks) -> Tuple[str, ...]:
    """kfree_skb reasons whose cumulative count advanced between any two valid ticks of the run."""
    seen = set()
    vals = [t.obs.get("ebpf.kfree") for t in ticks]
    vals = [v for v in vals if isinstance(v, dict)]
    for a, b in zip(vals, vals[1:]):
        seen |= {r for r in b if r in a and b[r] > a[r]}
    return tuple(sorted(seen))


def _check_registry():
    reg = load_contract().registry
    if tuple(reg.get("softirq.exec_time.percpu").dimension.values) != VECTORS:
        raise ImportError("softirq vector names differ from the contract's vector dimension")
    for f in EBPF_FEATURES:
        if reg.get(f).sources != (SourceType.EBPF,):
            raise ImportError(f"{f} is not an EBPF-only feature in the contract")


_check_registry()
