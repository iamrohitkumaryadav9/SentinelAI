#!/usr/bin/env python3
"""SentinelAI R2-D: controlled CPU-throttling validation — quota guard, schedule, ground truth, cleanup.

The approved design revision (CPU THROTTLING DESIGN REVISION: READY; R2-D design gate approved), on top of R2-C:
  boundary   the R2-C cgroup /sys/fs/cgroup/sentinel-r2c/{target,contender} (r2c_cpu, unchanged)
  quota      the ONLY new mutation: /sys/fs/cgroup/sentinel-r2c/target/cpu.max, exact strings per run:
             E0 none; Q0/C1 {Q_B, MAX}; T1/TC {Q_B, T1, MAX}; T2 {Q_B, T2, MAX}
  schedule   Q_B before tick 0 (non-binding, finite: nr_periods advances, CT.R1 gauge stays 1.0);
             Q_B -> Q_W inside the window callback (after tick NB is collected, before tick NB+1 is sampled);
             Q_W -> MAX after tick NB+NW is collected; MAX again in cleanup before cgroup.kill / rmdir
  truth      R2-C G1 G2 G4 G6 G7 (G3 applied to C1/TC) + GQ (index-exact quota) + GT (throttle counters)
             + GD (demand above the W quota) + GR (restoration)

Every cpu.max write goes through quota_write(): exact path, run allowlist, read-before (expected previous value),
intent log, write, read-after (exact equality), result log. Host and SimHost share it.
R2-C code is imported, never modified: its pure helpers accept the duck-typed Experiment below.
"""

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import r2c_cpu as C  # noqa: E402  (R2-C boundary, guards, ground-truth helpers; unchanged)

REPO = C.REPO
QUOTA_PATH = f"{C.TARGET_DIR}/cpu.max"
MAX = C.CPU_MAX_UNLIMITED                   # "max 100000"
Q_B = "100000 100000"                       # 1.0 core: finite, cannot bind one thread on one CPU
T1 = "15000 100000"                         # 0.15 core
T2 = "7500 100000"                          # 0.075 core
PERIOD_US = 100000
NB, NW = C.NB, C.NW
DOM_RATIO = 2.0                             # validation parameter (r2b NUMBERS), used only to record PR-3 consistency
RESULTS = REPO / "results" / "phase1c_r2d"


@dataclass(frozen=True)
class Experiment:
    kind: str
    contender_cpu: Optional[int]            # R2-C semantics (None: no contender)
    contender_weight: int
    quota_w: Optional[str]                  # quota in force during W; None: no quota at all (E0)


EXPERIMENTS = {
    "E0": Experiment("E0", None, 100, None),
    "Q0": Experiment("Q0", None, 100, Q_B),
    "C1": Experiment("C1", 18, 100, Q_B),      # contender = approved R2-C E1 configuration
    "T1": Experiment("T1", None, 100, T1),
    "T2": Experiment("T2", None, 100, T2),
    "TC": Experiment("TC", 18, 100, T1),
}
MATRIX = ("E0-open", "Q0-1", "Q0-2", "C1-1", "C1-2", "T1-1", "T1-2", "T1-3", "T2-1", "T2-2", "T2-3",
          "TC-1", "TC-2", "TC-3", "E0-close")
THROTTLED = ("T1", "T2", "TC")              # throttling required in W
CONTENDED = ("C1", "TC")                    # contender on CPU 18; G3 applies
TOOLING = C.TOOLING + ("scripts/r2d_cpu.py", "scripts/r2d_driver.py", "scripts/r2d_validate.sh",
                       "tests/faultlab/test_r2d.py")


class R2DRefused(C.R2CRefused):
    """An operation outside the R2-D authorisation."""


class QuotaAbort(C.LabAbort):
    """A cpu.max read-back, schedule or restoration check failed: hard abort."""


def experiment_of(label: str) -> Experiment:
    if label not in MATRIX:
        raise R2DRefused(f"run {label!r} is not in the approved R2-D matrix")
    return EXPERIMENTS[label.split("-")[0]]


def parse_quota(v):
    """'max P' -> (None, P); 'Q P' -> (Q, P); anything else (zero, negative, malformed) -> ValueError."""
    p = str(v).split()
    if len(p) != 2 or not p[1].isdigit() or int(p[1]) <= 0 or (p[0] != "max" and (not p[0].isdigit() or int(p[0]) <= 0)):
        raise ValueError(f"malformed cpu.max value {v!r}")
    return (None if p[0] == "max" else int(p[0])), int(p[1])


def cores(v) -> Optional[float]:
    q, p = parse_quota(v)
    return None if q is None else q / p


def allowed_quota(exp: Experiment) -> set:
    return set() if exp.quota_w is None else {Q_B, exp.quota_w, MAX}


def schedule(exp: Experiment) -> List[tuple]:
    """(moment, value, expected previous) writes of one run, in order."""
    if exp.quota_w is None:
        return []
    out = [("before_tick0", Q_B, MAX)]
    if exp.quota_w != Q_B:
        out.append(("window_callback", exp.quota_w, Q_B))
    out.append(("after_last_w_tick", MAX, exp.quota_w))
    return out


def _is_quota_op(op) -> bool:
    return isinstance(op, tuple) and len(op) >= 2 and op[0] == "write" and "cpu.max" in str(op[1])


def _results_path(p) -> bool:
    s = str(p)
    return s.startswith(str(RESULTS) + "/") and "/../" not in s and "\x00" not in s


def check_spawn(op, exp: Experiment, iters: Optional[int]):
    """R2-C's exact spawn shapes and one-pid structure, with outputs under results/phase1c_r2d."""
    if len(op) != 3 or op[1] not in ("target", "contender", "calibration"):
        raise R2DRefused(f"malformed spawn {op!r}")
    role, argv = op[1], list(op[2])
    if not argv or not _results_path(argv[-1]):
        raise R2DRefused(f"{role} output outside {RESULTS}: {argv[-1:]}")
    if not C.spawn_structure(argv, C.CONTENDER_DIR if role == "contender" else C.TARGET_DIR)["ok"]:
        raise R2DRefused(f"{role} argv breaks the one-pid structure: {argv}")
    if role == "contender":
        if exp.contender_cpu is None or argv != C.contender_argv(argv[-1]):
            raise R2DRefused(f"contender argv not approved for {exp.kind}: {argv}")
    elif role == "target":
        if argv != C.target_argv(iters, argv[-1]):
            raise R2DRefused(f"target argv not approved: {argv}")
    elif argv != C.calibration_argv(argv[-1]):
        raise R2DRefused(f"calibration argv not approved: {argv}")
    return op


def check_op(op, exp: Experiment, iters: Optional[int] = None):
    """R2-D allowlist: the target-leaf cpu.max with the run's exact values; spawns as R2-C with the R2-D results
    directory; every other operation -> R2-C's check_op (which refuses any cpu.max)."""
    if _is_quota_op(op):
        text = repr(op)
        for p in C.PROTECTED:
            if p in text:
                raise R2DRefused(f"protected interface {p} in operation")
        if len(op) != 3 or op[1] != QUOTA_PATH:
            raise R2DRefused(f"cpu.max write outside the target leaf: {op!r}")
        if op[2] not in allowed_quota(exp):
            raise R2DRefused(f"cpu.max value {op[2]!r} not in the {exp.kind} allowlist")
        try:
            parse_quota(op[2])
        except ValueError as exc:
            raise R2DRefused(str(exc))
        return op
    if isinstance(op, tuple) and op and op[0] == "spawn":
        for p in C.PROTECTED:
            if p in repr(op):
                raise R2DRefused(f"protected interface {p} in operation")
        return check_spawn(op, exp, iters)
    return C.check_op(op, exp, iters)


def _strip(v):
    return None if v is None else v.strip()


def quota_write(exp, value, expected_prev, read, write, resolve, log, clock=time.monotonic) -> dict:
    """The single cpu.max write path: validate, read-before, log intent, write, read-after, log result."""
    check_op(("write", QUOTA_PATH, value), exp)
    if resolve(QUOTA_PATH) != QUOTA_PATH:
        raise R2DRefused(f"{QUOTA_PATH} does not resolve to itself (symlink or substitution)")
    prev = _strip(read(QUOTA_PATH))
    if prev != expected_prev:
        log(phase="refused", op=["quota", QUOTA_PATH], value=value, prev=prev, expected_prev=expected_prev)
        raise QuotaAbort(f"cpu.max before write is {prev!r}, expected {expected_prev!r}")
    log(phase="intent", op=["quota", QUOTA_PATH], value=value, prev=prev)
    t0 = clock()
    write(QUOTA_PATH, value)
    t1 = clock()
    post = _strip(read(QUOTA_PATH))
    ok = post == value
    log(phase="result", op=["quota", QUOTA_PATH], value=value, prev=prev, post=post, ok=ok, t0=t0, t1=t1)
    if not ok:
        raise QuotaAbort(f"cpu.max after write is {post!r}, expected {value!r}")
    return {"value": value, "prev": prev, "post": post, "t0": t0, "t1": t1}


def quota_restore(exp, read, write, resolve, log, clock=time.monotonic) -> dict:
    """Restore MAX (cleanup / wrapper). A value outside the run's allowlist is restored if possible and reported."""
    cur = _strip(read(QUOTA_PATH))
    if cur == MAX:
        log(phase="result", op=["quota_restore", QUOTA_PATH], value=MAX, prev=cur, post=cur, ok=True, noop=True)
        return {"ok": True, "noop": True, "prev": cur, "post": cur}
    anomaly = cur not in allowed_quota(exp)
    rec = quota_write(exp, MAX, cur, read, write, resolve, log, clock)
    return {"ok": not anomaly, "noop": False, "prev": cur, "post": rec["post"],
            "anomaly": f"value {cur!r} was not written by this run" if anomaly else None}


class Host:
    """R2-D mutation site. Every operation is validated by r2d check_op first, then executed by R2-C's own executor
    (C.Host._do) and logged like R2-C; cpu.max only through write_quota / restore_quota."""

    _log = C.Host._log

    def __init__(self, exp: Experiment, oplog: str, iters: Optional[int] = None, sysr=None):
        self.exp, self.oplog, self.iters, self.sys = exp, oplog, iters, sysr or C.Sys()

    def apply(self, op, stdout=None, stderr=None):
        if _is_quota_op(op):
            raise R2DRefused("cpu.max is written only through write_quota / restore_quota")
        check_op(op, self.exp, self.iters)
        self._log(phase="intent", op=list(op[:2]))
        try:
            res = C.Host._do(self, op, stdout, stderr)
        except OSError as exc:
            self._log(phase="result", op=list(op[:2]), ok=False, err=str(exc))
            raise
        self._log(phase="result", op=list(op[:2]), ok=True, pid=getattr(res, "pid", None))
        return res

    @staticmethod
    def _write(path, value):
        with open(path, "w") as fh:
            fh.write(value)

    def write_quota(self, value, expected_prev):
        return quota_write(self.exp, value, expected_prev, self.sys.read, self._write, os.path.realpath, self._log)

    def restore_quota(self):
        return quota_restore(self.exp, self.sys.read, self._write, os.path.realpath, self._log)


# ------------------------------------------------------------------------------------------ per-observation checks
def expected_quota(exp: Experiment, k: int, i_w0: int, i_w1: int) -> str:
    """The quota that must be in force at observation k (index-exact schedule, design revision §3)."""
    if exp.quota_w is None:
        return MAX
    if k <= i_w0:
        return Q_B
    if k <= i_w1:
        return exp.quota_w
    return MAX


def immediate_aborts(t: dict, target_expected: str) -> List[str]:
    """Every observation: target quota as currently scheduled; parent and contender unlimited; NIC IRQ off lab CPUs."""
    a = []
    if t["leaves"]["target"]["cpu_max"] != target_expected:
        a.append(f"GQ: target cpu.max {t['leaves']['target']['cpu_max']!r} != scheduled {target_expected!r}")
    for name in ("parent", "contender"):
        if t["leaves"][name]["cpu_max"] != MAX:
            a.append(f"CPU quota: {name} cpu.max = {t['leaves'][name]['cpu_max']!r}")
    if t["nic_irq_eff"] is None or C.parse_cpulist(t["nic_irq_eff"]) & C.EXPERIMENT_CPUS:
        a.append(f"NIC IRQ {C.NIC_IRQ} effective affinity {t['nic_irq_eff']!r} on an experiment CPU")
    return a


# ------------------------------------------------------------------------------------------ GQ / GT / GD
def evaluate_gq(obs, exp, i_w0, i_w1, writes) -> dict:
    """Index-exact quota observations + write order and timing relative to the observations."""
    v = []
    for k, t in enumerate(obs):
        want = expected_quota(exp, k, i_w0, i_w1)
        if t["leaves"]["target"]["cpu_max"] != want:
            v.append(f"obs {k}: target {t['leaves']['target']['cpu_max']!r} != {want!r}")
        for name in ("parent", "contender"):
            if t["leaves"][name]["cpu_max"] != MAX:
                v.append(f"obs {k}: {name} {t['leaves'][name]['cpu_max']!r} != {MAX!r}")
    sched = schedule(exp)
    got = [(w["value"], w["prev"], w["post"]) for w in writes]
    if got != [(val, prev, val) for _, val, prev in sched]:
        v.append(f"writes {got} != schedule {[(val, prev, val) for _, val, prev in sched]}")
    else:
        for (moment, _, _), w in zip(sched, writes):
            if moment == "before_tick0" and not (obs and w["t1"] < obs[0]["mono"]):
                v.append("Q_B written after the first observation")
            if moment == "window_callback" and not (obs[i_w0]["mono"] < w["t0"] and w["t1"] < obs[i_w0 + 1]["mono"]):
                v.append(f"Q_W write [{w['t0']}, {w['t1']}] outside (obs {i_w0}, obs {i_w0 + 1})")
            if moment == "after_last_w_tick":
                if not w["t0"] > obs[i_w1]["mono"]:
                    v.append("MAX restored before the last W observation")
                if len(obs) > i_w1 + 1 and not w["t1"] < obs[i_w1 + 1]["mono"]:
                    v.append("MAX restored after the first recovery observation")
    return {"ok": not v, "violations": v[:20], "n_violations": len(v), "writes": writes}


def _cs(t, key):
    return (t["leaves"]["target"]["cpu_stat"] or {}).get(key)


def _delta(obs, a, b, key):
    x, y = _cs(obs[a], key), _cs(obs[b], key)
    return None if x is None or y is None or y < x else y - x


def evaluate_gt(obs, exp, i_b0, i_w0, i_w1) -> dict:
    """Throttle counters of the target cgroup, read independently at every observation."""
    finite = exp.quota_w is not None
    b = {k: _delta(obs, i_b0, i_w0, k) for k in ("nr_periods", "nr_throttled", "throttled_usec")}
    w = {k: _delta(obs, i_w0, i_w1, k) for k in ("nr_periods", "nr_throttled", "throttled_usec")}
    per_b = [_delta(obs, k, k + 1, "nr_periods") for k in range(i_b0, i_w0)]
    r = {"b": b, "w": w, "b_periods_per_interval": per_b}
    if any(x is None for x in list(b.values()) + list(w.values()) + per_b):
        r.update(ok=None, status="UNAVAILABLE")
        return r
    checks = {"b_not_throttled": b["nr_throttled"] == 0 and b["throttled_usec"] == 0}
    if finite:
        checks["b_periods_every_interval"] = all(x > 0 for x in per_b)
    if exp.kind in THROTTLED:
        checks["w_periods"] = w["nr_periods"] > 0
        checks["w_throttled"] = w["nr_throttled"] >= 1 and w["throttled_usec"] > 0
    else:
        checks["w_not_throttled"] = w["nr_throttled"] == 0 and w["throttled_usec"] == 0
    secs = obs[i_w1]["mono"] - obs[i_w0]["mono"]
    r.update(checks=checks, ok=all(checks.values()), status="EVALUATED",
             ratio_w=(w["nr_throttled"] / w["nr_periods"]) if w["nr_periods"] else None,
             time_rate_w=w["throttled_usec"] / 1e6 / secs if secs > 0 else None)
    return r


def evaluate_gd(obs, exp, i_b0, i_w0, i_w1) -> dict:
    """T1/T2/TC: demand (B usage, non-binding quota) strictly above the W quota, and W usage strictly below B."""
    if exp.kind not in THROTTLED:
        return {"applies": False, "ok": True}
    sb, sw = obs[i_w0]["mono"] - obs[i_b0]["mono"], obs[i_w1]["mono"] - obs[i_w0]["mono"]
    ub, uw = _delta(obs, i_b0, i_w0, "usage_usec"), _delta(obs, i_w0, i_w1, "usage_usec")
    if ub is None or uw is None or sb <= 0 or sw <= 0:
        return {"applies": True, "ok": None, "status": "UNAVAILABLE"}
    usage_b, usage_w, q = ub / 1e6 / sb, uw / 1e6 / sw, cores(exp.quota_w)
    return {"applies": True, "ok": usage_b > q and usage_w < usage_b, "usage_b_cores": usage_b,
            "usage_w_cores": usage_w, "quota_w_cores": q, "status": "EVALUATED"}


def evaluate(obs, i_b0, i_w0, i_w1, exp, expected, in_w, target_out, hz, writes) -> dict:
    """R2-D ground truth. R2-C's G1 G2 G4 G6 G7 are reused unchanged (its quota-free G5 is not used: GQ/GT replace it)."""
    base = C.evaluate_ground_truth(obs, i_b0, i_w0, i_w1, exp, expected, in_w, target_out, hz)
    G = {g: base[g] for g in ("G1", "G2", "G4", "G6", "G7")}
    idle = base["G3"]["cpu18_idle_frac_w"]
    applies = exp.kind in CONTENDED
    G["G3"] = {"applies": applies, "cpu18_idle_frac_w": idle, "threshold": C.G3_IDLE_MAX,
               "ok": (idle is not None and idle <= C.G3_IDLE_MAX) if applies else idle is not None}
    G["GQ"] = evaluate_gq(obs, exp, i_w0, i_w1, writes)
    G["GT"] = evaluate_gt(obs, exp, i_b0, i_w0, i_w1)
    G["GD"] = evaluate_gd(obs, exp, i_b0, i_w0, i_w1)
    req = ["G1", "G2", "G3", "G6", "GQ", "GT", "GD"]
    G["computable"] = all(G[g]["ok"] is not None for g in req) and not G["G7"]["undecided"]
    ok = G["computable"] and all(G[g]["ok"] for g in req) and G["G7"]["ok"]
    G["throttling_established"] = ok if exp.kind in THROTTLED else None
    G["throttling_absent_confirmed"] = ok if exp.kind not in THROTTLED else None
    G["contention_present"] = (G["G2"]["ok"] and G["G3"]["ok"]) if applies else None
    return G


def ground_truth_aborts(G: dict, exp: Experiment) -> List[str]:
    a = []
    if not G["computable"]:
        a.append("independent ground truth unavailable: " + ", ".join(
            [g for g in ("G1", "G2", "G3", "G6", "GQ", "GT", "GD") if G[g]["ok"] is None] +
            [f"G7.{p}" for p in G["G7"]["undecided"]]))
    for g, msg in (("G1", "experiment escaped its boundary"), ("G2", "contender contradicts the fault model"),
                   ("G3", f"CPU {C.TARGET_CPU} not saturated in a contended run"),
                   ("G6", f"foreign busy time on CPU {C.TARGET_CPU}"), ("GQ", "quota schedule violated"),
                   ("GT", "throttle counters contradict the fault model"), ("GD", "demand not above the W quota")):
        if G[g]["ok"] is False:
            detail = G[g].get("violations") or G[g].get("checks") or {k: G[g].get(k) for k in G[g] if k != "ok"}
            a.append(f"{msg} ({g}): {str(detail)[:300]}")
    g7 = G["G7"]
    for part, msg in (("nic_irq_ok", "NIC IRQ moved onto an experiment CPU"),
                      ("memory_events_ok", "memory events in the lab cgroups"),
                      ("memory_psi_ok", "host memory PSI stall in W"), ("swap_ok", "swap I/O in W above the limit"),
                      ("netns_quiet", "network activity in the target's private netns"),
                      ("softirq_ok", "CPU 18 softirq changed")):
        if g7[part] is False:
            a.append(msg)
    return a


# ------------------------------------------------------------------------------------------ metric gate
def predicted_saturation(usage_w_cores: float, exp: Experiment) -> Optional[float]:
    """Documented M3A behaviour: the W gauge of interval NB+1 is tick NB (Q_B), the other NW-1 are Q_W."""
    if exp.quota_w is None:
        return None
    q_mean = (cores(Q_B) + (NW - 1) * cores(exp.quota_w)) / NW
    return usage_w_cores / q_mean


# REQUIRED metrics: (feature, scope, aggregation, rule). Missing / invalid / stale / unusable -> ABORT.
#   usable_baseline   quality OK|PARTIAL (coverage >= COV_MIN), value present, adequate baseline
#   quota_state       quality OK|PARTIAL and value == 1.0 with a quota, 0.0 without (CT.R1)
#   ratio_state       with a quota: usable_baseline (CT.R2 needs the B baseline); E0: MISSING by design
#   usable_value      quality OK|PARTIAL (coverage >= COV_MIN), value present
REQUIRED = (
    ("sched.run_delay_excess.target", "cg", "RATE", "usable_baseline"),
    ("cpu.util.cpuset", "cpuset", "MEAN", "usable_baseline"),
    ("cpu.steal.cpuset", "cpuset", "MEAN", "usable_baseline"),
    ("sched.latency_hist.target", "cg", "P50", "usable_baseline"),
    ("sched.latency_hist.target", "cg", "P99", "usable_baseline"),
    ("throttle.time_rate", "cg", "RATE", "usable_baseline"),
    ("throttle.quota_limited", "cg", "GAUGE", "quota_state"),
    ("throttle.ratio", "cg", "RATIO", "ratio_state"),
    ("softirq.frac.percpu", f"cpu:{C.TARGET_CPU}", "RATIO", "usable_value"),
)
REQUIRED_KEYS = frozenset((f, sc, agg) for f, sc, agg, _ in REQUIRED)
# SUPPORTING metrics: recorded (quality, coverage, value, reason); never required to be present, except where their
# presence or absence contradicts the quota state (below).
SUPPORTING = frozenset({("throttle.quota_saturation", "cg", "RATIO"), ("throttle.quota_cores", "cg", "GAUGE")})
SAT_REL_TOL = 1e-9


def metric_gate(snapshot, exp: Experiment, cov_min: float, n_base_min: float) -> dict:
    """R2-D metric gate. REQUIRED evidence aborts when unusable; SUPPORTING evidence is recorded, and only a
    complete (OK) quota_saturation that contradicts the pre-registered diluted value, or a quota_saturation whose
    presence contradicts the quota state, aborts. Missing / invalid / partial supporting evidence never aborts alone."""
    cg = f"cgroup:{C.TARGET_CGROUP_PATH}"
    ms = snapshot.measurements
    scope = lambda sc: cg if sc == "cg" else sc
    find = lambda f, sc, agg=None: [m for m in ms if m.feature_id == f and m.scope == scope(sc)
                                    and (agg is None or m.aggregation.value == agg)]
    c, aborts = {}, []

    def quality_bad(m):
        if m.quality.value not in ("OK", "PARTIAL") or m.value is None:
            return [f"quality {m.quality.value}"]
        if m.quality.value == "PARTIAL" and m.coverage < cov_min:
            return [f"coverage {m.coverage}"]
        return []

    def baseline_bad(m):
        return [] if m.baseline is not None and m.baseline.adequate and m.baseline.n >= n_base_min else \
            ["baseline inadequate"]

    c["target"] = snapshot.target.cgroup_path == C.TARGET_CGROUP_PATH and snapshot.target.cpuset == str(C.TARGET_CPU)
    if not c["target"]:
        aborts.append("snapshot target is not the R2-D target")
    finite = exp.quota_w is not None
    for f, sc, agg, rule in REQUIRED:
        found = find(f, sc, agg)
        key = f"{f}[{agg}]"
        if len(found) != 1:
            bad = ["not present exactly once"]
        elif rule == "usable_baseline" or (rule == "ratio_state" and finite):
            bad = quality_bad(found[0]) + baseline_bad(found[0])
        elif rule == "ratio_state":                                    # E0: no quota, the ratio is undefined
            bad = [] if found[0].quality.value == "MISSING" and found[0].value is None else \
                [f"has {found[0].quality.value} {found[0].value} without a quota"]
        elif rule == "quota_state":
            want = 1.0 if finite else 0.0
            bad = quality_bad(found[0]) or ([] if found[0].value == want else [f"value {found[0].value} != {want}"])
        else:                                                          # usable_value
            bad = quality_bad(found[0])
        c[key] = not bad
        if bad:
            aborts.append(f"required metric {key} unusable: {', '.join(bad)}")

    missing_reason = {(mm.feature_id, mm.scope): mm.reason for mm in getattr(snapshot, "missing_measurements", ())}
    sup = {}
    for f, sc, agg in sorted(SUPPORTING):
        found = find(f, sc, agg)
        m = found[0] if len(found) == 1 else None
        sup[f] = {"present": m is not None, "quality": m.quality.value if m else None,
                  "coverage": m.coverage if m else None, "value": m.value if m else None,
                  "reason": missing_reason.get((f, scope(sc))), "consistent": None}
        if len(found) > 1:
            aborts.append(f"supporting metric {f} present more than once")
    sat = sup["throttle.quota_saturation"]
    if not finite:
        c["quota_saturation_absent_e0"] = not sat["present"]
        if sat["present"]:
            aborts.append("throttle.quota_saturation emitted without a quota")
    elif not sat["present"]:
        aborts.append("throttle.quota_saturation not emitted although a quota is in force")
    elif sat["quality"] == "OK" and sat["coverage"] == 1.0 and sat["value"] is not None:
        use = find("cpu.usage.target", "cg")
        pred = predicted_saturation(use[0].value, exp) if len(use) == 1 and use[0].value is not None else None
        sat["predicted"] = pred
        sat["consistent"] = pred is not None and abs(sat["value"] - pred) <= SAT_REL_TOL * max(1.0, abs(pred))
        if not sat["consistent"]:
            aborts.append(f"complete throttle.quota_saturation {sat['value']} contradicts the predicted {pred}")
    else:                                                              # PARTIAL / MISSING / INVALID / STALE: record
        sat["status"] = "recorded, not compared (incomplete)"

    net = [(m.feature_id, m.value) for m in ms if m.feature_id.startswith(("net.", "tcp.")) and m.value]
    c["no_network_activity"] = not net
    if net:
        aborts.append(f"network activity in the target netns: {net}")
    c["gate_passed"] = snapshot.data_quality.gate_passed
    if not c["gate_passed"]:
        aborts.append("snapshot data-quality gate failed")
    return {"ok": not aborts, "checks": c, "aborts": aborts, "supporting": sup}


M2_CLAUSES = ("CT.R1", "CT.R2", "CC.R1", "CC.R2", "CC.X1", "CC.X2")


def m2_record(d) -> dict:
    """CT/CC clause items, and PR-3 consistency recomputed from the snapshot's own measurements (recorded only)."""
    items = {i.predicate_id: i for i in d.snapshot.evidence_items if i.predicate_id in M2_CLAUSES}
    kind = lambda c: items[c].kind.value if c in items else None
    both = all(kind(c) == "POSITIVE" for c in ("CT.R1", "CT.R2", "CC.R1", "CC.R2"))
    ms = {m.feature_id: m.value for m in d.snapshot.measurements
          if m.feature_id in ("throttle.time_rate", "sched.run_delay_excess.target")}
    pr3 = None
    if both:
        tt, rd = ms.get("throttle.time_rate"), ms.get("sched.run_delay_excess.target")
        if tt is None or rd is None:
            expect = "CONFLICT"
        elif tt >= DOM_RATIO * rd and tt > rd:
            expect = "cpu_throttling"
        elif rd >= DOM_RATIO * tt and rd > tt:
            expect = "cpu_contention"
        else:
            expect = "CONFLICT"
        dec = d.result.decision.value
        got = "CONFLICT" if any(cf.rule == "PR-3" for cf in d.snapshot.conflicts) else dec
        pr3 = {"time_rate": tt, "run_delay_excess": rd, "expected": expect, "m2": got, "consistent": expect == got}
    return {"clauses": {c: kind(c) for c in M2_CLAUSES}, "both_assertable": both, "pr3": pr3}


# ------------------------------------------------------------------------------------------ cleanup
def quota_written(entries) -> bool:
    return any(e.get("phase") == "intent" and e.get("op", [None])[0] == "quota" for e in entries)


def cleanup(host, sysr, entries, wait_s: float = 5.0, sleep=time.sleep) -> dict:
    """R2-D cleanup: restore MAX on the target leaf (read-back verified) BEFORE R2-C's kill / rmdir cleanup."""
    gr, errors = {"attempted": False}, []
    target_exists = sysr.exists(C.TARGET_DIR)
    if target_exists and (quota_written(entries) or _strip(sysr.read(QUOTA_PATH)) not in (MAX, None)):
        gr["attempted"] = True
        try:
            gr.update(host.restore_quota())
            if not gr.get("ok"):
                errors.append(f"quota restore anomaly: {gr.get('anomaly')}")
        except Exception as exc:                                   # noqa: BLE001 -- NO-GO, cleanup continues
            gr["ok"] = False
            errors.append(f"quota restore failed: {exc!r}")
    elif target_exists:
        gr.update(ok=_strip(sysr.read(QUOTA_PATH)) == MAX, verified_without_write=True)
    else:
        gr.update(ok=True, target_absent=True)
    res = C.cleanup(host, sysr, entries, wait_s=wait_s, sleep=sleep)
    return {"ok": not errors and bool(gr.get("ok")) and res["ok"], "quota_restore": gr, "errors": errors + res["errors"],
            "steps": res["steps"], "verify": res["verify"]}


# ------------------------------------------------------------------------------------------ simulated host
class SimHost(C.SimHost):
    """R2-C's in-memory host + a target-leaf cpu.max file, written through the same quota_write()."""

    def __init__(self, exp, iters=1000, fail_at=None, fail_quota=None):
        super().__init__(exp, iters, fail_at)
        self.fail_quota = fail_quota          # None | "write" | "readback"
        self.events, self.log = [], []

    def apply(self, op, stdout=None, stderr=None):
        if _is_quota_op(op):
            raise R2DRefused("cpu.max is written only through write_quota / restore_quota")
        check_op(op, self.exp, self.iters)
        if op[0] == "spawn":                       # R2-C's SimHost would apply R2-C's results-path check
            self.n += 1
            if self.fail_at == self.n:
                raise OSError(f"injected failure at operation {self.n}: spawn")
            self.applied.append(op)
            leaf = C.CONTENDER_DIR if op[1] == "contender" else C.TARGET_DIR
            if leaf not in self.dirs:
                raise OSError("leaf missing")
            pid, self.next_pid = self.next_pid, self.next_pid + 2
            self.procs[leaf] = self.procs.get(leaf, []) + [pid + 1]
            self.wrappers[pid] = pid + 1
            self.alive |= {pid, pid + 1}
            self.events.append("spawn")
            return type("P", (), {"pid": pid})()
        res = super().apply(op)
        if op[0] == "mkdir" and op[1] == C.TARGET_DIR:
            self.files[QUOTA_PATH] = MAX
        if op[0] == "rmdir" and op[1] == C.TARGET_DIR:
            self.files.pop(QUOTA_PATH, None)
        self.events.append(op[0] if op[0] != "write" else ("cgroup.kill" if op[1].endswith("cgroup.kill") else "write"))
        return res

    def read(self, path):
        if path == QUOTA_PATH:
            return self.files.get(QUOTA_PATH) if C.TARGET_DIR in self.dirs else None
        return super().read(path)

    def _qwrite(self, path, value):
        self.n += 1
        if self.fail_at == self.n or self.fail_quota == "write":
            raise OSError(f"injected cpu.max write failure ({value})")
        self.files[path] = "garbage 1" if self.fail_quota == "readback" else value
        self.events.append(("quota", value))

    def _log(self, **kw):
        self.log.append(kw)

    def write_quota(self, value, expected_prev):
        return quota_write(self.exp, value, expected_prev, self.read, self._qwrite, lambda p: p, self._log)

    def restore_quota(self):
        return quota_restore(self.exp, self.read, self._qwrite, lambda p: p, self._log)


def simulate(exp: Experiment, fail_at=None, stop_after=None) -> dict:
    """Setup, Q_B, (Q_W), then stop at `stop_after` writes (a crash mid-run) or fail at op `fail_at`; cleanup from the
    op log must restore MAX before cgroup.kill and leave nothing behind."""
    sim = SimHost(exp, fail_at=fail_at)
    entries = []

    class Logged:
        def apply(self, op, stdout=None, stderr=None):
            entries.append({"phase": "intent", "op": list(op[:2])})
            res = sim.apply(op)
            entries.append({"phase": "result", "op": list(op[:2]), "ok": True, "pid": getattr(res, "pid", None)})
            return res

        def write_quota(self, value, prev):
            entries.append({"phase": "intent", "op": ["quota", QUOTA_PATH]})
            return sim.write_quota(value, prev)

        def restore_quota(self):
            return sim.restore_quota()

    h = Logged()
    failed = None
    out = str(RESULTS / "sim" / "x.json")
    # the driver's order: setup, target, Q_B | window callback: Q_W (if any), contender (if any) | MAX
    steps = [("op", op) for op in C.setup_plan(exp)] + [("op", ("spawn", "target", C.target_argv(1000, out)))]
    writes = schedule(exp)
    steps += [("quota", w) for w in writes if w[0] == "before_tick0"]
    steps += [("quota", w) for w in writes if w[0] == "window_callback"]
    if exp.contender_cpu is not None:
        steps.append(("op", ("spawn", "contender", C.contender_argv(out))))
    steps += [("quota", w) for w in writes if w[0] == "after_last_w_tick"]
    try:
        nq = 0
        for kind, x in steps:
            if kind == "quota":
                if stop_after is not None and nq >= stop_after:
                    break
                nq += 1
                h.write_quota(x[1], x[2])
            else:
                h.apply(x)
    except (OSError, QuotaAbort) as exc:
        failed = str(exc)
    res = cleanup(h, sim, entries, wait_s=0.0, sleep=lambda s: None)
    ev = sim.events
    restore_first = ("quota", MAX) not in ev or "cgroup.kill" not in ev or \
        max(i for i, e in enumerate(ev) if e == ("quota", MAX)) < ev.index("cgroup.kill")
    clean = not sim.dirs and not sim.alive
    return {"failed_at": failed, "cleanup_ok": res["ok"], "host_clean": clean, "restore_before_kill": restore_first,
            "quota_restore": res["quota_restore"]}


# ------------------------------------------------------------------------------------------ dry run
def dry_run(sysr) -> dict:
    rep = {"mode": "r2d dry-run", "matrix": MATRIX, "quota_path": QUOTA_PATH}
    before = C.host_snapshot(sysr, require_bpf=False)
    rep["preflight"] = C.preflight(sysr)
    rep["schedules"] = {label: schedule(experiment_of(label)) for label in MATRIX}
    acc = {}
    for label in MATRIX:
        exp = experiment_of(label)
        try:
            for op in C.setup_plan(exp) + [("write", QUOTA_PATH, v) for _, v, _ in schedule(exp)]:
                check_op(op, exp)
            acc[label] = True
        except C.R2CRefused as exc:
            acc[label] = str(exc)
    forbidden = [("write", f"{C.LAB_DIR}/cpu.max", Q_B), ("write", f"{C.CONTENDER_DIR}/cpu.max", T1),
                 ("write", f"{C.CG_ROOT}/cpu.max", MAX), ("write", f"{C.CG_ROOT}/system.slice/cpu.max", Q_B),
                 ("write", f"{C.TARGET_DIR}/../cpu.max", Q_B), ("write", QUOTA_PATH, "0 100000"),
                 ("write", QUOTA_PATH, "15000 0"), ("write", QUOTA_PATH, "20000 100000"), ("write", QUOTA_PATH, T2)]
    refused = []
    for op in forbidden:
        try:
            check_op(op, EXPERIMENTS["T1"], 1000)
            refused.append(False)
        except C.R2CRefused:
            refused.append(True)
    try:
        check_op(("write", QUOTA_PATH, Q_B), EXPERIMENTS["E0"])
        refused.append(False)
    except C.R2CRefused:
        refused.append(True)
    rep["allowlist"] = {"planned_accepted": acc, "forbidden_refused": all(refused), "n_forbidden": len(refused)}
    sims = []
    for exp in EXPERIMENTS.values():
        n = len(C.setup_plan(exp)) + 1 + len(schedule(exp)) + (1 if exp.contender_cpu is not None else 0)
        sims += [simulate(exp, f) for f in [None] + list(range(1, n + 1))]
        sims += [simulate(exp, stop_after=s) for s in range(len(schedule(exp)))]
    rep["cleanup_simulation"] = {"cases": len(sims), "ok": all(s["cleanup_ok"] and s["host_clean"] and
                                                               s["restore_before_kill"] for s in sims)}
    rep["r2c_dry_run_reused"] = "preflight, host snapshot/compare, setup plan and spawn guards are R2-C's"
    after = C.host_snapshot(sysr, require_bpf=False)
    rep["zero_mutation"] = C.compare_host(before, after, require_bpf=False)
    rep["structural_ok"] = (rep["preflight"]["ok"] and all(v is True for v in acc.values())
                            and rep["allowlist"]["forbidden_refused"] and rep["cleanup_simulation"]["ok"]
                            and rep["zero_mutation"]["ok"])
    return rep


# ------------------------------------------------------------------------------------------ CLI
def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    sys.path.insert(0, str(REPO / "src"))
    if cmd == "dry-run":
        rep = dry_run(C.Sys())
        print(json.dumps(rep, indent=1, sort_keys=True, default=str))
        return 0 if rep["structural_ok"] else 3
    if cmd == "cleanup":                     # wrapper trap: restore the quota first, from every op log under OUT
        res = {}
        for log in sorted(Path(argv[2]).rglob("ops.jsonl")):
            label = log.parent.name
            exp = experiment_of(label) if label in MATRIX else EXPERIMENTS["E0"]
            res[str(log)] = cleanup(Host(exp, str(log) + ".cleanup"), C.Sys(), C.read_oplog(log))
        v = C.cleanup_state(C.Sys())
        print(json.dumps({"runs": res, "final": v}, indent=1, sort_keys=True, default=str))
        return 0 if v["ok"] and all(r["ok"] for r in res.values()) else 3
    if cmd == "candidate":
        r = C.candidate(argv[2], argv[3])
        print(r["head"] if r["ok"] else r["reason"])
        return 0 if r["ok"] else 3
    if cmd == "criteria":
        print(json.dumps({"r2c_criteria": C.CRITERIA, "quota_path": QUOTA_PATH,
                          "quota": {"Q_B": Q_B, "T1": T1, "T2": T2, "MAX": MAX},
                          "schedules": {k: schedule(e) for k, e in EXPERIMENTS.items()}}, indent=1, sort_keys=True))
        return 0
    if cmd in ("preflight", "host-snapshot", "compare"):
        return C.main(argv)
    raise SystemExit("usage: r2d_cpu.py dry-run | criteria | cleanup OUT | candidate REPO BASE | preflight | "
                     "host-snapshot DIR | compare A B")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
