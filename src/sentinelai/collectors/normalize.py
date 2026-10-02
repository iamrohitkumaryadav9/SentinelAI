"""Normalisation: per-tick observations -> window value, coverage, quality and baseline (contract §5, §10.8).

Intervals: interval k (1..nB+nW) spans ticks k-1 .. k. Intervals 1..nB form the baseline window,
nB+1..nB+nW the incident window W. Counters contribute their delta over the interval, gauges their
value at tick k-1 (the start of the interval), so every gauge sample lies in [start, end).

Rules (fail closed):
  * a negative counter delta is a counter reset: that interval is INVALID, never clamped to 0;
  * an absent / denied / unattributable source makes the interval absent, never zero;
  * coverage = valid intervals / expected intervals;
  * no valid interval -> INVALID if any interval was invalid, else MISSING (value null);
  * coverage < COV_MIN -> MISSING (§10.8); coverage < 1 -> PARTIAL; else OK;
  * a pure gauge with no valid sample in W but valid samples in the baseline window -> STALE;
  * an undefined value (ratio with a denominator that did not advance) -> MISSING, never 0.
"""

import math
from collections import Counter as Tally
from dataclasses import dataclass, field
from statistics import median
from typing import Dict, List, Optional, Tuple

from ..diagnostic.contract import Unit, load_contract
from .errors import Bad, Status
from .features import C, G, T, Calc
from .probes import get

INVALID_STATUSES = (Status.MALFORMED,)
RESET = "counter reset"


@dataclass
class Tick:
    index: int
    mono: float
    wall: object          # datetime (UTC, ms)
    obs: dict


@dataclass
class Outcome:
    ok: bool
    values: Optional[dict] = None
    invalid: bool = False
    reason: str = ""


@dataclass
class Evaluation:
    calc: Calc
    w_valid: List[int] = field(default_factory=list)
    w_invalid: int = 0
    w_reasons: Tally = field(default_factory=Tally)
    b_valid: int = 0
    b_samples: List[float] = field(default_factory=list)
    value: Optional[float] = None
    value_reason: str = ""
    value_invalid: bool = False
    stale_tick: Optional[int] = None
    resets: set = field(default_factory=set)


def _reason(b: Bad) -> str:
    return f"{b.status.value}: {b.detail}" if b.detail else b.status.value


def _part(part, a: Tick, b: Tick, resets: set, k: int) -> Outcome:
    if isinstance(part, G):
        v = part.fn(a.obs)
        if isinstance(v, Bad):
            return Outcome(False, invalid=v.status in INVALID_STATUSES, reason=_reason(v))
        return Outcome(True, values=v)
    if isinstance(part, C):
        total = 0.0
        for src, fld in part.terms:
            x, y = get(a.obs, src, fld), get(b.obs, src, fld)
            for v in (x, y):
                if isinstance(v, Bad):
                    return Outcome(False, invalid=v.status in INVALID_STATUSES, reason=_reason(v))
            if y < x:
                resets.add((src, fld, k))
                return Outcome(False, invalid=True, reason=f"{RESET}: {src}:{fld}")
            total += y - x
        return Outcome(True, values=total)
    if isinstance(part, T):
        x, y = get(a.obs, "task", part.field), get(b.obs, "task", part.field)
        for v in (x, y):
            if isinstance(v, Bad):
                return Outcome(False, invalid=v.status in INVALID_STATUSES, reason=_reason(v))
        common = sorted(set(x) & set(y))
        if not common:
            return Outcome(False, reason="absent: no target thread present at both ends of the interval")
        total = 0.0
        for tid in common:
            if y[tid] < x[tid]:
                resets.add(("task", f"{part.field}[{tid}]", k))
                return Outcome(False, invalid=True, reason=f"{RESET}: task {tid} {part.field}")
            total += y[tid] - x[tid]
        return Outcome(True, values=total)
    raise TypeError(part)


def _in_range(calc: Calc, v: Optional[float]) -> bool:
    if v is None:
        return True
    spec = load_contract().registry.get(calc.feature)
    if not math.isfinite(v) or (spec.non_negative and v < 0):
        return False
    if spec.unit is Unit.fraction and v > 1.0:
        return False
    if spec.unit is Unit.boolean and v not in (0.0, 1.0):
        return False
    return True


def evaluate(calc: Calc, ticks: List[Tick], nB: int, nW: int) -> Evaluation:
    ev = Evaluation(calc)
    per_k: Dict[int, Tuple[dict, float]] = {}
    for k in range(1, nB + nW + 1):
        a, b = ticks[k - 1], ticks[k]
        dt = b.mono - a.mono
        vals, bad = {}, None
        for name, part in calc.parts:
            o = _part(part, a, b, ev.resets, k)
            if not o.ok:
                bad = o
                break
            vals[name] = o.values
        sample = None
        if bad is None:
            if dt <= 0:
                bad = Outcome(False, invalid=True, reason="non-increasing sample clock")
            else:
                sample = calc.combine(vals, dt)
                if not _in_range(calc, sample):
                    bad = Outcome(False, invalid=True, reason=f"value out of range for {calc.feature}")
        in_w = k > nB
        if bad is not None:
            if in_w:
                ev.w_reasons[bad.reason] += 1
                ev.w_invalid += int(bad.invalid)
            continue
        per_k[k] = (vals, dt)
        if in_w:
            ev.w_valid.append(k)
        else:
            ev.b_valid += 1
            if sample is not None:
                ev.b_samples.append(sample)
    _window_value(calc, ev, per_k, nB)
    return ev


def _window_value(calc: Calc, ev: Evaluation, per_k, nB: int) -> None:
    if not ev.w_valid:
        if calc.gauge_only:
            base = [k for k in per_k if k <= nB]
            if base:   # source stopped updating: last known value, STALE (§10.8)
                last = max(base)
                ev.stale_tick = last - 1
                ev.value = calc.combine(per_k[last][0], per_k[last][1])
        return
    if calc.gauge_only:
        samples = [calc.combine(*per_k[k]) for k in ev.w_valid]
        if calc.gauge_agg == "last":
            v = samples[-1]
        elif calc.gauge_agg == "bool":
            if len(set(samples)) != 1:
                ev.value_invalid, ev.value_reason = True, "boolean gauge changed within the window"
                return
            v = samples[0]
        else:
            v = sum(samples) / len(samples)
    else:
        agg, dt = {}, 0.0
        for name, part in calc.parts:
            xs = [per_k[k][0][name] for k in ev.w_valid]
            agg[name] = sum(xs) / len(xs) if isinstance(part, G) else sum(xs)
        dt = sum(per_k[k][1] for k in ev.w_valid)
        v = calc.combine(agg, dt)
    if v is None:
        ev.value_reason = calc.undefined
        return
    if not _in_range(calc, v):
        ev.value_invalid, ev.value_reason = True, f"value out of range for {calc.feature}"
        return
    ev.value = v


def baseline_stats(samples: List[float]):
    """(median, MAD, p99 nearest-rank, n) of per-interval baseline samples (contract §5)."""
    xs = sorted(samples)
    n = len(xs)
    med = median(xs)
    mad = median(sorted(abs(x - med) for x in xs))
    p99 = xs[max(0, math.ceil(0.99 * n) - 1)]
    return med, mad, max(p99, med), n
