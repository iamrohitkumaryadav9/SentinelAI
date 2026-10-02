"""Three-valued predicate primitives (EVIDENCE_CONTRACT.md §7). No thresholds live here."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple

from ..contract.enums import Quality, Strength

USABLE = (Quality.OK, Quality.PARTIAL)
_RANK = {Strength.WEAK: 0, Strength.MODERATE: 1, Strength.STRONG: 2}


class Tri(Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    MISSING = "MISSING"


@dataclass(frozen=True)
class Eval:
    tri: Tri
    strength: Optional[Strength] = None          # set for TRUE/FALSE
    reason: Optional[str] = None                 # set for MISSING
    used: Tuple[str, ...] = field(default=())    # measurement ids consulted


def weakest(*s):
    s = [x for x in s if x is not None]
    return min(s, key=_RANK.get) if s else None


def strongest(*s):
    s = [x for x in s if x is not None]
    return max(s, key=_RANK.get) if s else None


def _ids(evs):
    return tuple(sorted({u for e in evs for u in e.used}))


def k_and(*evs: Eval) -> Eval:
    """Kleene AND: FALSE dominates, then MISSING, then TRUE. A FALSE result cites only the FALSE
    operands that decided it (so undecided, possibly degraded inputs are never cited as evidence)."""
    used = _ids(evs)
    false = [e for e in evs if e.tri is Tri.FALSE]
    if false:
        return Eval(Tri.FALSE, strongest(*(e.strength for e in false)), used=_ids(false))
    miss = [e for e in evs if e.tri is Tri.MISSING]
    if miss or not evs:
        return Eval(Tri.MISSING, reason=(miss[0].reason if miss else "no inputs"), used=used)
    return Eval(Tri.TRUE, weakest(*(e.strength for e in evs)), used=used)


def k_or(*evs: Eval) -> Eval:
    """Kleene OR: TRUE dominates, then MISSING, then FALSE. A TRUE result cites only the TRUE operands."""
    used = _ids(evs)
    true = [e for e in evs if e.tri is Tri.TRUE]
    if true:
        return Eval(Tri.TRUE, strongest(*(e.strength for e in true)), used=_ids(true))
    miss = [e for e in evs if e.tri is Tri.MISSING]
    if miss or not evs:
        return Eval(Tri.MISSING, reason=(miss[0].reason if miss else "measurement not present"), used=used)
    return Eval(Tri.FALSE, weakest(*(e.strength for e in evs)), used=used)


def k_not(e: Eval) -> Eval:
    if e.tri is Tri.MISSING:
        return e
    return Eval(Tri.FALSE if e.tri is Tri.TRUE else Tri.TRUE, e.strength, used=e.used)


def usable(m, cov_min: float) -> Optional[str]:
    """None if the measurement may be used, else the reason it may not (contract E1, §10.8)."""
    if m.quality not in USABLE or m.value is None:
        return f"measurement quality {m.quality.value}"
    if m.quality is Quality.PARTIAL and m.coverage < cov_min:
        return "coverage below COV_MIN"
    return None


def dev(m, p) -> Eval:
    """DEV(f, scope) per contract §7, with the snapshot's own baseline/deviation (never recomputed)."""
    if m is None:
        return Eval(Tri.MISSING, reason="measurement not present")
    bad = usable(m, p.num("COV_MIN"))
    if bad:
        return Eval(Tri.MISSING, reason=bad, used=(m.measurement_id,))
    b, d = m.baseline, m.deviation
    if b is None or d is None:
        return Eval(Tri.MISSING, reason="no baseline", used=(m.measurement_id,))
    if not b.adequate or b.n < p.num("N_BASE_MIN"):
        return Eval(Tri.MISSING, reason="BASELINE_INADEQUATE", used=(m.measurement_id,))
    x, floor = m.value, p.floor(m.feature_id)
    if d.robust_z >= p.num("Z_STRONG") and d.ratio >= p.num("R_STRONG") and x >= floor:
        return Eval(Tri.TRUE, Strength.STRONG, used=(m.measurement_id,))
    if d.robust_z >= p.num("Z_MODERATE") and d.ratio >= p.num("R_MODERATE") and x >= floor:
        return Eval(Tri.TRUE, Strength.MODERATE, used=(m.measurement_id,))
    return Eval(Tri.FALSE, Strength.STRONG if d.robust_z < 1 else Strength.WEAK, used=(m.measurement_id,))


def baseline_gate(m, p) -> Optional[Eval]:
    """Inside a baseline-using clause every referenced measurement needs an adequate baseline
    (contract §5; M1 snapshot rule). Returns a MISSING Eval if not, else None."""
    if m is None:
        return Eval(Tri.MISSING, reason="measurement not present")
    if m.baseline is None or not m.baseline.adequate or m.baseline.n < p.num("N_BASE_MIN"):
        return Eval(Tri.MISSING, reason="BASELINE_INADEQUATE", used=(m.measurement_id,))
    return None


def absolute_b(m, theta: float, p) -> Eval:
    """ABS inside a baseline-using clause: MISSING without an adequate baseline."""
    bad = usable(m, p.num("COV_MIN")) if m is not None else None
    if m is not None and bad:
        return Eval(Tri.MISSING, reason=bad, used=(m.measurement_id,))
    return baseline_gate(m, p) or absolute(m, theta, p)


def absolute(m, theta: float, p) -> Eval:
    """ABS(f, θ): TRUE x ≥ θ, FALSE x < θ, MISSING otherwise.

    The contract defines no strength bands for ABS; a crossed/uncrossed absolute bound is recorded
    as STRONG (interpretation I-1 in the M2 report).
    """
    if m is None:
        return Eval(Tri.MISSING, reason="measurement not present")
    bad = usable(m, p.num("COV_MIN"))
    if bad:
        return Eval(Tri.MISSING, reason=bad, used=(m.measurement_id,))
    return Eval(Tri.TRUE if m.value >= theta else Tri.FALSE, Strength.STRONG, used=(m.measurement_id,))
