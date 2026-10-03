"""Measurement construction and deterministic EvidenceSnapshot assembly (contract §5, §10.3, §10.5, §10.8).

``collect`` is the only function that does I/O or reads time. ``build_snapshot`` is a pure function of
the recorded ticks, the target and the parameter set: the same ticks give a byte-identical snapshot.
The collector observes; it never diagnoses (no thresholds, no labels, no evidence items).
"""

import resource
import time
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

from ..diagnostic.contract import (BaselineMethod, BaselineStat, DataQuality, Deviation, EvidenceSnapshot,
                                   Measurement, MissingMeasurement, Provenance, Qualifier, Quality, SourceType,
                                   Target, Window, load_contract, measurement_id, snapshot_id)
from ..diagnostic.contract.version import CONTRACT_VERSION, SCHEMA_VERSION
from ..diagnostic.rules.params import ParameterSet, UncalibratedParameters
from .clock import Clock, SystemClock
from .errors import Bad, CollectorError
from .features import APP_REASON, COLLECTOR_VERSION, NOT_COLLECTED, build
from .normalize import Tick, baseline_stats, evaluate
from .probes import get, sample
from .reader import LiveReader

NOT_COLLECTED_SOURCES = ("APP_EVENTS", "APP_METRICS", "SS")
PRIVILEGED_UNAVAILABLE = ("EBPF",)


def window_counts(params: ParameterSet, period: float) -> Tuple[int, int]:
    nB, nW = round(params.num("B") / period), round(params.num("W") / period)
    if nB < 1 or nW < 1:
        raise CollectorError("B and W must each span at least one sample period")
    return nB, nW


def collected_features() -> Tuple[str, ...]:
    """Every feature M3A can emit (for parameter-set completeness checks)."""
    t = Target(name="x", cgroup_path="/x", pids=(1,), cpuset="0", netns_ref="pid:1", ifaces=("x",))
    return tuple(sorted({c.feature for c in build(t, (0,), (0,), (0,), True)}))


def check_parameters(params: ParameterSet) -> None:
    need = [n for n in ("W", "B", "COV_MIN", "N_BASE_MIN") if n not in params.numbers]
    need += [f"floor[{f}]" for f in collected_features() if f"floor[{f}]" not in params.numbers]
    if need:
        raise UncalibratedParameters(need)
    if any(params.floor(f) <= 0 for f in collected_features()):
        raise CollectorError("every floor[f] must be positive (contract §5 deviation denominators)")


# ------------------------------------------------------------------------------------------ collection
@dataclass(frozen=True)
class CollectionStats:
    ticks: int
    wall_s: float
    cpu_s: float
    max_rss_kb: int
    max_tick_read_s: float


def collect(target: Target, params: ParameterSet, reader=None, clock: Optional[Clock] = None,
            period: float = 1.0) -> Tuple[List[Tick], CollectionStats]:
    """Sample every source at t0 + k*period for k = 0 .. nB+nW (baseline window, then W)."""
    check_parameters(params)
    reader, clock = reader or LiveReader(), clock or SystemClock()
    nB, nW = window_counts(params, period)
    r0, w0 = resource.getrusage(resource.RUSAGE_SELF), time.monotonic()
    t0, ticks, worst = clock.monotonic(), [], 0.0
    for k in range(nB + nW + 1):
        clock.sleep_until(t0 + k * period)
        mono, wall = clock.monotonic(), clock.wall()
        s = time.monotonic()
        obs = sample(reader, target)
        worst = max(worst, time.monotonic() - s)
        ticks.append(Tick(k, mono, wall, obs))
    r1 = resource.getrusage(resource.RUSAGE_SELF)
    stats = CollectionStats(len(ticks), time.monotonic() - w0,
                            (r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime), r1.ru_maxrss, worst)
    return ticks, stats


# ------------------------------------------------------------------------------------------ building
def _window(a: datetime, b: datetime, period: float) -> Window:
    if b <= a:
        raise CollectorError("sample wall clock did not advance")
    return Window(start=a, end=b, duration_s=round((b - a).total_seconds(), 3), sample_period_s=period)


def _cpu_ids(ticks) -> set:
    out = set()
    for t in ticks:
        s = t.obs.get("proc.stat")
        if isinstance(s, dict):
            out |= {int(k[3:].split(".")[0]) for k in s if k.startswith("cpu")}
    return out


def _cpuset(target: Target, cpus: set) -> Tuple[int, ...]:
    if target.cpuset is None:
        return tuple(sorted(cpus))
    out = set()
    for part in target.cpuset.split(","):
        a, _, b = part.partition("-")
        out.update(range(int(a), int(b or a) + 1))
    return tuple(sorted(out))


def _relevant(ticks, cpuset, nB) -> Tuple[int, ...]:
    """cpuset ∪ CPUs the target's threads were observed on during W (contract §4.5)."""
    seen = set(cpuset)
    for t in ticks[nB:]:
        p = get(t.obs, "task", "processor")
        if isinstance(p, dict):
            seen |= {int(v) for v in p.values()}
    return tuple(sorted(seen))


def _emit_quota(ticks) -> bool:
    vals = [get(t.obs, "cg.cpu.max", "limited") for t in ticks]
    good = [v for v in vals if not isinstance(v, Bad)]
    return not good or any(v == 1.0 for v in good)   # unlimited throughout: quota_cores is not emitted


def _measurement(calc, ev, ticks, nB, nW, bwin, wwin, params) -> Tuple[Measurement, Optional[str]]:
    spec = load_contract().registry.get(calc.feature)
    cov_min, cov = params.num("COV_MIN"), len(ev.w_valid) / nW
    value, reason = ev.value, None
    if ev.value_invalid:
        quality, value, reason = Quality.INVALID, None, ev.value_reason
    elif not ev.w_valid:
        if ev.stale_tick is not None and value is not None:
            quality = Quality.STALE
        else:
            quality, value = (Quality.INVALID if ev.w_invalid else Quality.MISSING), None
    elif cov < cov_min:
        quality, value, reason = Quality.MISSING, None, f"coverage {cov:.3f} below COV_MIN"
    elif value is None:
        quality, reason = Quality.MISSING, ev.value_reason
    else:
        quality = Quality.OK if len(ev.w_valid) == nW else Quality.PARTIAL
    if quality in (Quality.MISSING, Quality.INVALID) and reason is None:
        reason = sorted(ev.w_reasons.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if ev.w_reasons else "no sample"
    if quality is Quality.STALE:
        cov = 0.0
    baseline = deviation = None
    if ev.b_samples:
        med, mad, p99, n = baseline_stats(ev.b_samples)
        adequate = n >= params.num("N_BASE_MIN") and ev.b_valid / nB >= cov_min
        baseline = BaselineStat(method=BaselineMethod.within_run, window=bwin, median=med, mad=mad, p99=p99, n=n,
                                adequate=adequate)
    if value is not None and baseline is not None:
        fl = params.floor(calc.feature)
        deviation = Deviation(ratio=value / max(baseline.median, fl), delta=value - baseline.median,
                              robust_z=(value - baseline.median) / max(1.4826 * baseline.mad, fl), floor_used=fl)
    if quality is Quality.STALE:
        first = last = ticks[ev.stale_tick].wall
        samples = 1
    elif ev.w_valid:
        lo, hi = min(ev.w_valid), max(ev.w_valid)
        first = ticks[lo - 1].wall
        last = ticks[hi - 1].wall if calc.gauge_only else ticks[hi].wall
        samples = len(ev.w_valid)
    else:
        first = last = wwin.start
        samples = 0
    derived = tuple(sorted(measurement_id(f, s, wwin) for f, s in calc.derived_from))
    prov = Provenance(source=calc.source, locator=calc.locator, collector=calc.collector,
                      collector_version=COLLECTOR_VERSION, privileged=spec.privileged,
                      first_sample_at=first, last_sample_at=last, samples=samples, derived_from=derived)
    agg = spec.aggregations[0]
    m = Measurement(measurement_id=measurement_id(calc.feature, calc.scope, wwin, aggregation=agg),
                    feature_id=calc.feature, scope=calc.scope, window=wwin, aggregation=agg, unit=spec.unit, value=value,
                    quality=quality, coverage=cov, baseline=baseline, deviation=deviation, provenance=prov)
    return m, reason


def build_snapshot(ticks: List[Tick], target: Target, params: ParameterSet, period: float = 1.0) -> EvidenceSnapshot:
    check_parameters(params)
    nB, nW = window_counts(params, period)
    if len(ticks) != nB + nW + 1:
        raise CollectorError(f"expected {nB + nW + 1} ticks, got {len(ticks)}")
    bwin = _window(ticks[0].wall, ticks[nB].wall, period)
    wwin = _window(ticks[nB].wall, ticks[nB + nW].wall, period)
    cpus = _cpu_ids(ticks)
    cpuset = _cpuset(target, cpus)
    calcs = build(target, tuple(sorted(cpus | set(cpuset))), cpuset, _relevant(ticks, cpuset, nB), _emit_quota(ticks))
    reg = load_contract().registry
    measurements, missing, resets = [], {}, set()
    for calc in calcs:
        ev = evaluate(calc, ticks, nB, nW)
        resets |= ev.resets
        m, reason = _measurement(calc, ev, ticks, nB, nW, bwin, wwin, params)
        measurements.append(m)
        if m.quality is Quality.MISSING:
            missing[(m.feature_id, m.scope, None)] = reason
    # registered features M3A does not collect: listed explicitly, never silently absent
    CG, NS, APP = f"cgroup:{target.cgroup_path}", f"netns:{target.name}", f"app:{target.name}"
    scopes = {"sched.latency_hist.target": [CG], "net.drop.netfilter": [NS], "tcp.srtt_ms": [NS], "tcp.cwnd": [NS]}
    for f, reason in NOT_COLLECTED.items():
        for sc in scopes[f]:
            missing[(f, sc, None)] = reason
    for f in reg.features:
        if f.family == "application":
            if f.dimension is None:
                missing[(f.id, APP, None)] = APP_REASON
            else:
                for code in sorted(f.dimension.values or ()):
                    missing[(f.id, APP, code)] = APP_REASON
    mm = tuple(MissingMeasurement(feature_id=f, scope=s, reason=r,
                                  qualifier=None if q is None else Qualifier(dimension=reg.get(f).dimension.name, value=q))
               for (f, s, q), r in sorted(missing.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] or "")))
    measurements.sort(key=lambda m: m.measurement_id)
    dq = _data_quality(measurements, resets, params)
    return EvidenceSnapshot(schema_version=SCHEMA_VERSION, contract_version=CONTRACT_VERSION,
                            parameter_set_id=params.parameter_set_id,
                            snapshot_id=snapshot_id(target, wwin, measurements), target=target, window=wwin,
                            baseline_window=bwin, measurements=tuple(measurements), evidence_items=(),
                            missing_measurements=mm, conflicts=(), data_quality=dq)


def _data_quality(ms, resets, params) -> DataQuality:
    reg = load_contract().registry
    usable = (Quality.OK, Quality.PARTIAL)
    by_source = {}
    for m in ms:
        by_source.setdefault(m.provenance.source.value, []).append(m.quality in usable)
    unavailable = set(NOT_COLLECTED_SOURCES) | {s for s, ok in by_source.items() if not any(ok)}
    families = {}
    for m in ms:
        families.setdefault(reg.get(m.feature_id).family, []).append(bool(m.baseline and m.baseline.adequate))
    cov = sum(m.coverage for m in ms) / len(ms) if ms else 0.0
    adequate = any(any(v) for v in families.values())
    return DataQuality(overall_coverage=cov, sources_unavailable=tuple(sorted(unavailable)),
                       privileged_sources_unavailable=PRIVILEGED_UNAVAILABLE, baseline_adequate=adequate,
                       counter_resets=len(resets), gate_passed=cov >= params.num("COV_MIN") and adequate)


def collect_snapshot(target: Target, params: ParameterSet, reader=None, clock=None, period: float = 1.0):
    ticks, stats = collect(target, params, reader, clock, period)
    return build_snapshot(ticks, target, params, period), stats
