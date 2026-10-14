"""Phase 1C M7: scored windows, contract-parameter calibration (FZ-M7-PLAN; AMD-30).

    .venv/bin/python experiments/faultlab/m7.py calibrate [--commit HEAD]

Reads only train runs of the committed matrix from the committed raw dataset (the tool refuses any other split) and
applies the objectives of docs/PHASE_1C_M7_CALIBRATION_OBJECTIVES.md (committed before any calibration):

1. data quality (COV_MIN, N_BASE_MIN) from coverage and baseline counts of every measurement;
2. noise floors and deviation bands from train CTRL windows;
3. SEG_MIN, the class thresholds (one false-positive-bounded rule), the softirq parameters, IMPACT_MIN;
4. DOM_RATIO with every other parameter fixed (rule engine, run-level mode of the three windows).

Writes datasets/faultlab/v1/m7/calibration_report.json (add-only, AMD-30): every rule-engine parameter with its
evidence. tau_DISAGREE (combination policy, design §5.4; never read by the rule engine) is set by the ML stage, which
writes params.calibrated.json from exactly these values. Deterministic: nearest-rank percentiles, sorted candidates,
no random choice.
"""
import argparse
import json
import math
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "src"))
import m6 as M6  # noqa: E402

OUT = ROOT / "datasets" / "faultlab" / "v1" / "m7"
PARAMS_OUT, REPORT_OUT = OUT / "params.calibrated.json", OUT / "calibration_report.json"
PARAMS_ID = "m7-calibrated-v1"
B_S, W_S, ONSET_TICK, T_TRANS_S = 45, 24, 45, 16                 # FZ-TTRANS, AMD-6, AMD-8
WINDOW_STARTS = tuple(ONSET_TICK + T_TRANS_S + j * W_S for j in range(3))   # 61, 85, 109
FP_MAX, RECALL_MIN = 0.01, 0.90                                  # C7-1
FLOOR_MIN = 1e-6                                                 # a floor must be positive (contract §5)
DOM_GRID = (1.25, 1.5, 2.0, 3.0)                                 # C7-8
# C7-17: declared engineering values, not calibrated optima (the objective cannot discriminate; see the objectives)
DECLARED = {"THR_RATIO_MIN": 0.5}
KFREE = ("QDISC_DROP", "TC_INGRESS")                             # C7-5
INS = "INSUFFICIENT_EVIDENCE"
TAU_DISAGREE = "τ_DISAGREE"
ENGINE_PLACEHOLDER = 1.0         # tau_DISAGREE while the rule engine runs in calibration: the engine never reads it
CLASSES = ("cpu_contention", "cpu_throttling", "network_packet_loss", "tcp_retransmissions", "memory_pressure",
           "application_bottleneck")
IFACE_DROPS = ("net.drop.qdisc", "net.drop.iface_rx", "net.drop.iface_tx", "net.err.iface")
OTHER_DROPS = ("net.drop.softnet", "net.drop.socket", "net.drop.netfilter")
WAITS = ("app.queue_wait_ms", "app.lock_wait_ms", "app.dependency_latency_ms")


class Refused(SystemExit):
    pass


# ------------------------------------------------------------------------------------------ statistics
def nearest_rank(xs, q):
    """Nearest-rank percentile q in (0, 1] of a non-empty list."""
    s = sorted(xs)
    return s[max(0, math.ceil(q * len(s)) - 1)]


def lower_tail(xs, share):
    """The largest v such that at least `share` of xs are >= v (nearest rank from below)."""
    s = sorted(xs)
    return s[max(0, len(s) - math.ceil(share * len(s)))]


def fp_bounded(pos, neg, fp_max=FP_MAX, recall_min=RECALL_MIN):
    """C7-1: the smallest candidate θ (observed values and 0) with FP(θ) <= fp_max, where a window fires when
    x >= θ; recall reported against recall_min."""
    cands = sorted(set(pos) | set(neg) | {0.0})
    cands.append(math.nextafter(cands[-1], math.inf))             # always one candidate above every value
    share = lambda xs, t: (sum(1 for x in xs if x >= t) / len(xs)) if xs else 0.0
    theta = next(t for t in cands if share(neg, t) <= fp_max)
    rec = share(pos, theta)
    return {"value": theta, "fp": share(neg, theta), "recall": rec if pos else None, "positives": len(pos),
            "negatives": len(neg), "recall_shortfall": bool(pos) and rec < recall_min}


def no_negatives(pos):
    """C7-16: a threshold with no defined negative window is the nearest-rank 1st percentile of its positives
    (k = ceil(0.01 n), duplicates kept; k = 1 for n <= 100); a window fires when x >= θ."""
    if not pos:
        raise Refused("C7-16: a threshold has neither negative nor positive windows with a defined value")
    theta = nearest_rank(pos, 0.01)
    rec = sum(1 for x in pos if x >= theta) / len(pos)
    return {"value": theta, "fp": None, "recall": rec, "positives": len(pos), "negatives": 0,
            "recall_shortfall": rec < RECALL_MIN, "stopped": theta <= 0,
            "limitation": "no negative window: bounded by the positives only, FP not measurable on train (C7-16)"}


def zero_firing(xs):
    """C7-7: the smallest value with no window at or above it."""
    return math.nextafter(max(xs), math.inf) if xs else FLOOR_MIN


# ------------------------------------------------------------------------------------------ data
def train_runs(matrix, families=("SF", "CTRL")):
    """Train runs of the given families; anything that is not train is never returned (C7-9)."""
    out = [r for r in matrix["runs"] if r["family"] in families and r["split"] == "train"]
    if any(r["split"] != "train" for r in out):
        raise Refused("a non-train run reached calibration")
    return out


def load_run(raw_dir: Path):
    """(ticks, target, ebpf) of a committed raw run, unpacked with every SHA-256 checked."""
    from sentinelai.diagnostic.contract import Target
    from sentinelai.runtime.ticks import decode_ticks
    with tempfile.TemporaryDirectory() as t:
        M6.unpack(raw_dir, Path(t) / "r")
        run = json.loads((Path(t) / "r" / "evidence" / "run.json").read_bytes())
        ticks = decode_ticks((Path(t) / "r" / "evidence" / "ticks.jsonl").read_bytes())
    return ticks, Target.model_validate_json(json.dumps(run["target_doc"]), strict=False), bool(run.get("ebpf", True))


def params(numbers, reasons=None):
    from sentinelai.diagnostic.rules.params import ParameterSet
    return ParameterSet(parameter_set_id=PARAMS_ID, numbers=dict(numbers), reason_sets=dict(reasons or {}))


def floor_features():
    """Every feature that needs a floor: what the collector can emit and what the rule engine deviates on
    (net.drop.netfilter and tcp.srtt_ms have no source; they get the minimum floor, C7-3)."""
    from sentinelai.collectors.snapshot import collected_features
    from sentinelai.diagnostic.rules.engine import DEV_FEATURES
    return tuple(sorted(set(collected_features(True, True)) | set(DEV_FEATURES)))


def windows(run_data, numbers):
    """The run's three scored-window snapshots under the given (snapshot-relevant) numbers."""
    from sentinelai.collectors import build_snapshot
    ticks, target, ebpf = run_data
    p = params(numbers)
    return [build_snapshot(ticks, target, p, 1.0, ebpf, True, window_start=s) for s in WINDOW_STARTS]


def usable(m, cov_min):
    return m.value is not None and m.quality.value in ("OK", "PARTIAL") and m.coverage >= cov_min


def values(snap, feature, cov_min, agg=None, scope_prefix=None):
    return [m for m in snap.measurements if m.feature_id == feature and usable(m, cov_min)
            and (agg is None or m.aggregation.value == agg) and (scope_prefix is None or m.scope.startswith(scope_prefix))]


# ------------------------------------------------------------------------------------------ per-window statistics
def x_drop_abs(s, cov):
    xs = [m.value for f in IFACE_DROPS + OTHER_DROPS for m in values(s, f, cov)]
    xs += [m.value for m in values(s, "net.drop.kfree_skb", cov) if m.qualifier and m.qualifier.value in KFREE]
    return max(xs) if xs else None


def x_drop_frac(s, cov):
    pk = {m.scope: m.value for m in values(s, "net.pkts.iface", cov)}
    xs = [m.value / (pk[m.scope] + m.value) for f in IFACE_DROPS for m in values(s, f, cov)
          if m.scope in pk and pk[m.scope] + m.value > 0]
    return max(xs) if xs else None


def x_one(feature, agg=None):
    def f(s, cov):
        xs = [m.value for m in values(s, feature, cov, agg)]
        return max(xs) if xs else None
    return f


def x_rdx(s, cov):
    rd = x_one("sched.run_delay.target")(s, cov)
    tr = x_one("throttle.time_rate")(s, cov) or 0.0
    return None if rd is None else rd - tr


def x_app_wait(s, cov):
    xs = [m.value for f in WAITS for m in values(s, f, cov)]
    return max(xs) if xs else None


def x_app_share(s, cov):
    lat = next(iter(values(s, "app.latency_ms", cov, "P99")), None)
    ok = [m for f in WAITS for m in values(s, f, cov) if m.baseline is not None and m.baseline.adequate]
    if lat is None or lat.baseline is None or not lat.baseline.adequate or not ok:
        return None
    d = lat.value - lat.baseline.median
    return max(m.value - m.baseline.median for m in ok) / d if d > 0 else None


def x_si_abs(s, cov):
    xs = [m.value for f in ("softirq.frac.percpu", "softirq.relevant_cpu_max") for m in values(s, f, cov)]
    return max(xs) if xs else None


def x_si_ratio(s, cov):
    xs = [m.deviation.ratio for m in values(s, "softirq.frac.percpu", cov) if m.deviation is not None]
    return max(xs) if xs else None


def x_si_share(s, cov):
    util = next(iter(values(s, "cpu.util.cpuset", cov)), None)
    per = values(s, "softirq.frac.percpu", cov)
    if util is None or not per or util.value == 0:
        return None
    return (sum(m.value for m in per) / len(per)) / util.value


def x_impact(s, cov):
    lat = next(iter(values(s, "app.latency_ms", cov, "P99")), None)
    return lat.deviation.ratio if lat is not None and lat.deviation is not None else None


# parameter -> (statistic, own class, classes neither positive nor negative)
CTRL_ONLY = tuple(c for c in CLASSES if c != "application_bottleneck")   # C7-12: app waits rise under every fault
THRESHOLDS = {
    "DROP_ABS_MIN": (x_drop_abs, "network_packet_loss", ()),
    "DROP_FRAC_MIN": (x_drop_frac, "network_packet_loss", ()),
    "RT_FRAC_MIN": (x_one("tcp.retrans_frac"), "tcp_retransmissions", ("network_packet_loss",)),
    "RT_RATE_MIN": (x_one("tcp.retrans_rate"), "tcp_retransmissions", ("network_packet_loss",)),
    "THR_TIME_MIN": (x_one("throttle.time_rate"), "cpu_throttling", ()),
    "RDX_MIN": (x_rdx, "cpu_contention", ()),
    "SAT_MIN": (x_one("cpu.util.cpuset"), "cpu_contention", ()),
    "PSI_MEM_MIN": (x_one("psi.mem.some.target"), "memory_pressure", ()),
    "RECLAIM_MIN": (x_one("mem.reclaim.target"), "memory_pressure", ()),
    "REFAULT_MIN": (x_one("mem.refault.target"), "memory_pressure", ()),
    "APP_WAIT_MIN": (x_app_wait, "application_bottleneck", CTRL_ONLY),           # C7-12: negatives are CTRL only
    "APP_SHARE_MIN": (x_app_share, "application_bottleneck", CTRL_ONLY),
}


# ------------------------------------------------------------------------------------------ calibration
def calibrate(matrix, raw_root: Path, engine_commit: str, log=print) -> tuple:
    runs = train_runs(matrix)
    data = {r["run_id"]: load_run(raw_root / r["run_id"]) for r in runs}
    cls = {r["run_id"]: r["class"] for r in runs}                  # None for CTRL
    ff = floor_features()
    rep = {"format": "sentinelai.faultlab.m7.calibration_report.v1", "objectives": "docs/PHASE_1C_M7_CALIBRATION_OBJECTIVES.md",
           "runs": {"sf": sum(1 for r in runs if r["family"] == "SF"), "ctrl": sum(1 for r in runs if r["family"] == "CTRL")},
           "window_starts": list(WINDOW_STARTS), "parameters": {}}

    # 1. data quality
    base = {f"floor[{f}]": FLOOR_MIN for f in ff}
    base.update(B=float(B_S), W=float(W_S), COV_MIN=0.0, N_BASE_MIN=0.0)
    s1 = {rid: windows(d, base) for rid, d in data.items()}
    covs = [m.coverage for ws in s1.values() for s in ws for m in s.measurements]
    ns = [m.baseline.n for ws in s1.values() for s in ws for m in s.measurements if m.baseline is not None]
    cov_min = min(0.99, lower_tail(covs, 0.99))
    n_base = float(lower_tail(ns, 0.99))
    rep["parameters"]["COV_MIN"] = {"value": cov_min, "measurements": len(covs), "rule": "C7-4"}
    rep["parameters"]["N_BASE_MIN"] = {"value": n_base, "baselines": len(ns), "rule": "C7-4"}
    log(f"COV_MIN {cov_min} N_BASE_MIN {n_base}")

    # 2. floors from CTRL windows, then the final window snapshots and the deviation bands
    numbers = dict(base, COV_MIN=cov_min, N_BASE_MIN=n_base)
    s2 = {rid: windows(d, numbers) for rid, d in data.items() if cls[rid] is None}
    floors, floored = {}, []
    for f in ff:
        xs = [m.value for ws in s2.values() for s in ws for m in values(s, f, cov_min)]
        v = nearest_rank(xs, 0.99) if xs else None
        if v is None or v <= 0:
            floored.append(f)
            v = FLOOR_MIN
        floors[f"floor[{f}]"] = v
    numbers.update(floors)
    rep["floors"] = {"rule": "C7-3: p99 of train CTRL windows", "set_to_minimum": sorted(floored), "minimum": FLOOR_MIN}
    snaps = {rid: windows(d, numbers) for rid, d in data.items()}
    ctrl = [s for rid, ws in snaps.items() if cls[rid] is None for s in ws]
    zs = [m.deviation.robust_z for s in ctrl for m in s.measurements if usable(m, cov_min) and m.deviation is not None]
    rs = [m.deviation.ratio for s in ctrl for m in s.measurements if usable(m, cov_min) and m.deviation is not None]
    zm, rm = nearest_rank(zs, 0.99), nearest_rank(rs, 0.99)
    numbers.update(Z_MODERATE=zm, R_MODERATE=rm, Z_STRONG=max(zm, nearest_rank(zs, 0.999)),
                   R_STRONG=max(rm, nearest_rank(rs, 0.999)))
    for k in ("Z_MODERATE", "R_MODERATE", "Z_STRONG", "R_STRONG"):
        rep["parameters"][k] = {"value": numbers[k], "deviations": len(zs), "rule": "C7-2"}

    # 3. SEG_MIN, class thresholds, softirq, IMPACT_MIN
    segs = [x for s in ctrl for x in [x_one("tcp.out_segs_rate")(s, cov_min)] if x is not None]
    numbers["SEG_MIN"] = nearest_rank(segs, 0.01)
    rep["parameters"]["SEG_MIN"] = {"value": numbers["SEG_MIN"], "windows": len(segs), "rule": "C7-4"}
    rep["stopped"] = []
    for name, (stat, own, neither) in THRESHOLDS.items():
        pos, neg, undef_pos, undef_neg = [], [], 0, 0
        for rid, ws in snaps.items():
            c = cls[rid]
            if c in neither:
                continue
            for s in ws:
                x = stat(s, cov_min)
                if x is None:
                    undef_pos, undef_neg = (undef_pos + 1, undef_neg) if c == own else (undef_pos, undef_neg + 1)
                    continue
                (pos if c == own else neg).append(x)
        if neg:
            r = dict(fp_bounded(pos, neg), rule="C7-12" if neither == CTRL_ONLY else "C7-1")
        else:
            r = dict(no_negatives(pos), rule="C7-16")
            if r["stopped"]:
                rep["stopped"].append(f"{name} = {r['value']!r} <= 0 under C7-16: its clause would be effectively "
                                      f"unconditional")
        numbers[name] = r["value"]
        rep["parameters"][name] = dict(r, own_class=own, neither=list(neither), left_out=undef_pos + undef_neg,
                                       undefined={"own_class": undef_pos, "other": undef_neg})
    for name, v in DECLARED.items():                                  # C7-17
        own = [x for rid, ws in snaps.items() if cls[rid] == "cpu_throttling" for s in ws
               for x in [x_one("throttle.ratio")(s, cov_min)] if x is not None]
        other = sum(1 for rid, ws in snaps.items() if cls[rid] != "cpu_throttling" for s in ws
                    if x_one("throttle.ratio")(s, cov_min) is not None)
        numbers[name] = v
        rep["parameters"][name] = {"value": v, "rule": "C7-17: declared engineering value, not calibrated",
                                   "observed_own_class": {"windows": len(own), "min": min(own) if own else None,
                                                          "max": max(own) if own else None},
                                   "other_windows_with_a_value": other}
    every = [s for ws in snaps.values() for s in ws]
    for name, stat in (("SI_ABS_MIN", x_si_abs), ("SI_RATIO_MIN", x_si_ratio), ("SI_SHARE_MIN", x_si_share)):
        xs = [x for s in every for x in [stat(s, cov_min)] if x is not None]
        numbers[name] = zero_firing(xs)
        rep["parameters"][name] = {"value": numbers[name], "windows": len(xs), "rule": "C7-7"}
    imp = [x for s in ctrl for x in [x_impact(s, cov_min)] if x is not None]
    r = fp_bounded([], imp)
    numbers["IMPACT_MIN"] = r["value"]
    rep["parameters"]["IMPACT_MIN"] = dict(r, rule="C7-8")
    reasons = {"KFREE_REASONS_LOSS": KFREE}
    rep["parameters"]["KFREE_REASONS_LOSS"] = {"value": list(KFREE), "rule": "C7-5"}

    # 4. DOM_RATIO by train run-level macro F1 with everything else fixed; a tie goes to the larger value
    scores = {}
    for d in DOM_GRID:
        p = params(dict(numbers, DOM_RATIO=d, **{TAU_DISAGREE: ENGINE_PLACEHOLDER}), reasons)
        truth, pred = [], []
        for rid, ws in snaps.items():
            truth.append(cls[rid] or INS)
            pred.append(run_decision([diagnose(s, p, engine_commit) for s in ws]))
        scores[d] = macro_f1(truth, pred)
    best = max(DOM_GRID, key=lambda d: (scores[d], d))
    numbers["DOM_RATIO"] = best
    rep["parameters"]["DOM_RATIO"] = {"value": best, "train_macro_f1": {str(k): v for k, v in scores.items()},
                                      "rule": "C7-8"}
    missing = sorted(params(dict(numbers, **{TAU_DISAGREE: ENGINE_PLACEHOLDER}), reasons).missing(floor_features()))
    if missing:
        raise Refused(f"calibration left parameters unset: {missing}")
    rep["engine_parameters"] = {"numbers": dict(sorted(numbers.items())), "reason_sets": {k: list(v) for k, v in
                                                                                       reasons.items()}}
    rep["parameters"][TAU_DISAGREE] = {"value": None, "rule": "C7-8: set by the ML stage (combination policy)"}
    p = params(dict(numbers, **{TAU_DISAGREE: ENGINE_PLACEHOLDER}), reasons)
    rep["train_evaluation"] = train_evaluation(
        {rid: [diagnose(s, p, engine_commit) for s in ws] for rid, ws in snaps.items()}, cls,
        {n: (THRESHOLDS[n][0], numbers[n]) for n, v in rep["parameters"].items() if v.get("rule") == "C7-16"},
        [s for ws in snaps.values() for s in ws], cov_min)
    return numbers, reasons, rep


def train_evaluation(decisions, cls, c716, every, cov_min):
    """Objectives §3 "Train evaluation": run-level P/R/F1 per label and macro F1, abstentions, cross-class false
    positives (run and window confusion), and the firing share of each C7-16 threshold over defined train windows."""
    labels = CLASSES + (INS,)
    truth = {rid: cls[rid] or INS for rid in decisions}
    run = {rid: run_decision(ds) for rid, ds in decisions.items()}
    per = {}
    for lab in labels:
        tp = sum(1 for r in run if truth[r] == lab and run[r] == lab)
        fp = sum(1 for r in run if truth[r] != lab and run[r] == lab)
        fn = sum(1 for r in run if truth[r] == lab and run[r] != lab)
        per[lab] = {"runs": sum(1 for r in run if truth[r] == lab), "tp": tp, "fp": fp, "fn": fn,
                    "precision": tp / (tp + fp) if tp + fp else None, "recall": tp / (tp + fn) if tp + fn else None,
                    "f1": 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else 0.0}
    rows = lambda pairs: {t: dict(sorted(Counter(p for tt, p in pairs if tt == t).items())) for t in labels}
    run_pairs = [(truth[r], run[r]) for r in run]
    win_pairs = [(truth[r], d) for r, ds in decisions.items() for d in ds]
    cross = lambda pairs: sum(1 for t, p in pairs if p in CLASSES and p != t)
    fire = {}
    for name, (stat, theta) in c716.items():
        xs = [x for s in every for x in [stat(s, cov_min)] if x is not None]
        fire[name] = {"defined_windows": len(xs), "fires": sum(1 for x in xs if x >= theta),
                      "windows": len(every)}
    return {"per_label": per, "macro_f1": macro_f1([t for t, _ in run_pairs], [p for _, p in run_pairs]),
            "abstentions": {"runs": {t: sum(1 for tt, p in run_pairs if tt == t and p == INS) for t in labels},
                            "windows": {t: sum(1 for tt, p in win_pairs if tt == t and p == INS) for t in labels}},
            "cross_class_false_positives": {"runs": cross(run_pairs), "windows": cross(win_pairs)},
            "confusion_runs": rows(run_pairs), "confusion_windows": rows(win_pairs), "c7_16_firing": fire,
            "window_decisions": {r: list(ds) for r, ds in sorted(decisions.items())}}


def diagnose(snap, p, commit):
    from sentinelai.diagnostic.rules.engine import diagnose as eng
    return eng(snap, p, code_commit=commit).result.decision.value


def run_decision(decisions):
    """AMD-8: the mode over the three windows; a tie goes to INSUFFICIENT_EVIDENCE."""
    c = Counter(decisions).most_common()
    return c[0][0] if len(c) == 1 or c[0][1] > c[1][1] else INS


def macro_f1(truth, pred, labels=CLASSES + (INS,)):
    f1 = []
    for lab in labels:
        tp = sum(1 for t, p in zip(truth, pred) if t == lab and p == lab)
        fp = sum(1 for t, p in zip(truth, pred) if t != lab and p == lab)
        fn = sum(1 for t, p in zip(truth, pred) if t == lab and p != lab)
        f1.append(2 * tp / (2 * tp + fp + fn) if tp + fp + fn else 0.0)
    return sum(f1) / len(f1)


# ------------------------------------------------------------------------------------------ ML (design §5.2–5.4)
# Objectives §3 "ML" (C7-8, C7-9) and the interpretations ML-1 … ML-8 written there before training.
ML_SEED = 20261002                                               # design §8
TAU_DISAGREE_GRID = (0.6, 0.7, 0.8, 0.9)                         # C7-8
RISK_MAX = 0.10                                                  # C7-8: selective risk for τ_ML
OUTER_FOLDS, INNER_FOLDS = 5, 4                                  # ML-4
MODEL_OUT, TRAIN_OUT, LOCK_OUT = OUT / "model.json", OUT / "training_report.json", OUT / "lock.json"
GATES = {"G-Q1 macro F1 >= 0.80": 0.80, "G-Q2 per-class recall >= 0.70": 0.70, "G-C1 ECE <= 0.10": 0.10}
LR_GRID = ({"C": 0.01}, {"C": 0.1}, {"C": 1.0}, {"C": 10.0})                    # most regularised first (ML-4)
RF_GRID = ({"min_samples_leaf": 10}, {"min_samples_leaf": 5}, {"min_samples_leaf": 2}, {"min_samples_leaf": 1})
HGB_GRID = ({"learning_rate": 0.05, "max_leaf_nodes": 7}, {"learning_rate": 0.1, "max_leaf_nodes": 7},
            {"learning_rate": 0.05, "max_leaf_nodes": 15}, {"learning_rate": 0.1, "max_leaf_nodes": 15})


def ml_runs(matrix):
    """C7-9: train SF, CTRL and overlap runs; a run with an acceptable-set ground truth is excluded (design §5.2)."""
    fams = sorted({r["family"] for r in matrix["runs"]} - {"SENS", "PI3"})
    runs = train_runs(matrix, families=tuple(fams))
    use = [r for r in runs if "acceptable" not in r["expected"]]
    return use, sorted(r["run_id"] for r in runs if "acceptable" in r["expected"])


def label_of(run):
    return run["expected"]["primary"] if run["family"] != "CTRL" else INS


def _bounded(spec):
    return spec.unit.value == "fraction" if hasattr(spec.unit, "value") else spec.unit == "fraction"


def _slog(v):
    return math.copysign(math.log1p(abs(v)), v)


def column_key(m):
    """ML-1: a canonical scope is the scope kind (no IDs, cpusets, paths or names: design §5.2 leakage list)."""
    return "|".join((m.feature_id, m.scope.split(":", 1)[0], m.qualifier.value if m.qualifier else "",
                     m.aggregation.value))


def window_columns(snap, cov_min):
    """ML-2: per key (z, log ratio, absolute) of a usable measurement, the largest over instances of the key;
    z enters as sign·log1p(|z|), the absolute value as the value (bounded) or sign·log1p(|value|)."""
    from sentinelai.diagnostic.contract import load_contract
    reg = load_contract().registry
    out = {}
    for m in snap.measurements:
        if not usable(m, cov_min):
            continue
        dev = m.deviation
        z = _slog(dev.robust_z) if dev is not None and dev.robust_z is not None else 0.0
        lr = math.log(max(dev.ratio, 1e-6)) if dev is not None and dev.ratio is not None else 0.0
        a = m.value if _bounded(reg.get(m.feature_id)) else _slog(m.value)
        k = column_key(m)
        out[k] = tuple(max(x, y) for x, y in zip(out[k], (z, lr, a))) if k in out else (z, lr, a)
    return out


def design_matrix(cols_per_window, keys):
    """ML-3: four columns per key (z, log ratio, absolute, missing); neutral fill 0, never imputed from other runs."""
    import numpy as np
    X = np.zeros((len(cols_per_window), 4 * len(keys)))
    for i, c in enumerate(cols_per_window):
        for j, k in enumerate(keys):
            if k in c:
                X[i, 4 * j:4 * j + 3] = c[k]
            else:
                X[i, 4 * j + 3] = 1.0
    return X


def column_names(keys):
    return [f"{k}|{part}" for k in keys for part in ("z", "logratio", "abs", "missing")]


def leakage_audit(names):
    """G-L1 column audit: every part of a column comes from a closed set: a registry feature, one of its scope
    kinds and aggregations, an upper-case closed-set qualifier (or none) and one of the four column parts. A scope
    ID, cpuset, path, name, seed, family, intensity or rule decision cannot pass."""
    from sentinelai.diagnostic.contract import load_contract
    reg = load_contract().registry
    bad = []
    for n in names:
        parts = n.split("|")
        ok = len(parts) == 5 and reg.has(parts[0]) and parts[4] in ("z", "logratio", "abs", "missing")
        if ok:
            spec = reg.get(parts[0])
            kinds = {getattr(k, "value", k) for k in spec.scope_kinds}
            aggs = {getattr(a, "value", a) for a in spec.aggregations}
            ok = parts[1] in kinds and parts[3] in aggs and re.fullmatch(r"(?:[A-Z][A-Z0-9_]*)?", parts[2]) is not None
        if not ok:
            bad.append(n)
    return {"columns": len(names), "rejected": bad, "ok": not bad}


def _base(kind, hp):
    from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    if kind == "logistic_regression":
        return Pipeline([("scale", StandardScaler()),
                         ("lr", LogisticRegression(C=hp["C"], class_weight="balanced", max_iter=10000,
                                                   random_state=ML_SEED))])
    if kind == "random_forest":
        return RandomForestClassifier(n_estimators=500, min_samples_leaf=hp["min_samples_leaf"],
                                      class_weight="balanced", random_state=ML_SEED, n_jobs=1)
    return HistGradientBoostingClassifier(learning_rate=hp["learning_rate"], max_leaf_nodes=hp["max_leaf_nodes"],
                                          class_weight="balanced", early_stopping=False, random_state=ML_SEED)


GRIDS = {"logistic_regression": LR_GRID, "random_forest": RF_GRID, "hist_gradient_boosting": HGB_GRID}


def _splits(groups, idx, k):
    """GroupKFold over the given rows (groups = run id); returned as indices into the full arrays."""
    import numpy as np
    from sklearn.model_selection import GroupKFold
    idx = np.asarray(idx)
    return [(idx[a], idx[b]) for a, b in GroupKFold(n_splits=k).split(idx, groups=np.asarray(groups)[idx])]


def _window_f1(y, pred, labels):
    return macro_f1(list(y), list(pred), labels)


def select_hp(kind, X, y, groups, idx, k, labels):
    """ML-4: the grid value with the best GroupKFold window-level macro F1 of the uncalibrated argmax; ties go to
    the earlier (more regularised) value."""
    best = None
    for hp in GRIDS[kind]:
        pred = {}
        for tr, te in _splits(groups, idx, k):
            m = _base(kind, hp).fit(X[tr], y[tr])
            pred.update(zip(te.tolist(), m.predict(X[te])))
        order = sorted(pred)
        f = _window_f1([y[i] for i in order], [pred[i] for i in order], labels)
        if best is None or f > best[1]:
            best = (hp, f)
    return best


def fit_calibrated(kind, hp, X, y, groups, idx, k):
    """Design §5.3: Platt (sigmoid) calibration, fitted with GroupKFold on the training rows (< 1,000 windows)."""
    from sklearn.calibration import CalibratedClassifierCV
    import numpy as np
    idx = np.asarray(idx)
    pos = {g: i for i, g in enumerate(idx.tolist())}
    cv = [(np.array([pos[i] for i in a]), np.array([pos[i] for i in b])) for a, b in _splits(groups, idx, k)]
    return CalibratedClassifierCV(_base(kind, hp), method="sigmoid", cv=cv, ensemble=False).fit(X[idx], y[idx])


def ece_top(prob, y_idx, bins=10):
    """Design §5.3: expected calibration error, 10 equal-mass bins, top label."""
    import numpy as np
    conf, pred = prob.max(axis=1), prob.argmax(axis=1)
    order = np.argsort(conf, kind="stable")
    rows, e = [], 0.0
    for b in np.array_split(order, bins):
        if len(b) == 0:
            continue
        acc, c = float(np.mean(pred[b] == y_idx[b])), float(np.mean(conf[b]))
        e += len(b) / len(conf) * abs(acc - c)
        rows.append({"windows": int(len(b)), "confidence": c, "accuracy": acc})
    return e, rows


def brier(prob, y_idx):
    import numpy as np
    onehot = np.zeros_like(prob)
    onehot[np.arange(len(y_idx)), y_idx] = 1.0
    return float(np.mean(np.sum((prob - onehot) ** 2, axis=1)))


def tau_ml(conf, correct):
    """C7-8: the smallest probability threshold with selective risk <= 10 % (error among windows kept, max p >= τ);
    candidates are 0 and the observed confidences; none qualifies -> above every confidence (abstain always)."""
    cands = sorted(set(conf) | {0.0})
    for t in cands:
        kept = [c for p, c in zip(conf, correct) if p >= t]
        if kept and 1 - sum(kept) / len(kept) <= RISK_MAX:
            return t
    return math.nextafter(max(cands), math.inf)


def gated(labels_pred, conf, tau, gate_ok):
    """Design §5.3 abstention: INS when max p < τ_ML or the predicted label's Required clauses are not all TRUE."""
    return [INS if p < tau or (lab != INS and not ok.get(lab, False)) else lab
            for lab, p, ok in zip(labels_pred, conf, gate_ok)]


def run_level(run_ids, decisions):
    by = defaultdict(list)
    for r, d in zip(run_ids, decisions):
        by[r].append(d)
    return {r: run_decision(ds) for r, ds in by.items()}


def class_metrics(truth, pred, labels):
    out = {}
    for lab in labels:
        tp = sum(1 for t, p in zip(truth, pred) if t == lab and p == lab)
        fp = sum(1 for t, p in zip(truth, pred) if t != lab and p == lab)
        fn = sum(1 for t, p in zip(truth, pred) if t == lab and p != lab)
        out[lab] = {"precision": tp / (tp + fp) if tp + fp else None, "recall": tp / (tp + fn) if tp + fn else None,
                    "support": tp + fn}
    return out


def evaluate_kind(kind, X, y, groups, run_ids, gate_ok, labels, log=print):
    """Outer GroupKFold validation of one model kind (ML-4): pooled held-out calibrated and uncalibrated
    probabilities, τ_ML from them, raw and gated metrics, the design gates."""
    import numpy as np
    classes = sorted(set(y))
    P, U, chosen = np.zeros((len(y), len(classes))), np.zeros((len(y), len(classes))), []
    for tr, te in _splits(groups, np.arange(len(y)), OUTER_FOLDS):
        hp, _ = select_hp(kind, X, y, groups, tr, INNER_FOLDS, labels)
        chosen.append(hp)
        cal = fit_calibrated(kind, hp, X, y, groups, tr, INNER_FOLDS)
        raw = _base(kind, hp).fit(X[tr], y[tr])
        for M, A in ((cal, P), (raw, U)):
            pr = M.predict_proba(X[te])
            for j, c in enumerate(M.classes_):
                A[te, classes.index(c)] = pr[:, j]
    yi = np.array([classes.index(v) for v in y])
    pred = [classes[i] for i in P.argmax(axis=1)]
    conf = P.max(axis=1).tolist()
    tau = tau_ml(conf, [p == t for p, t in zip(pred, y)])
    g = gated(pred, conf, tau, gate_ok)
    rid = list(run_ids)
    truth_run = run_level(rid, list(y))
    res = {}
    for name, d in (("raw", pred), ("gated", g)):
        rl = run_level(rid, d)
        keys = sorted(rl)
        res[name] = {"run_macro_f1": macro_f1([truth_run[k] for k in keys], [rl[k] for k in keys], labels),
                     "window_macro_f1": macro_f1(list(y), d, labels),
                     "per_class_run": class_metrics([truth_run[k] for k in keys], [rl[k] for k in keys], labels),
                     "abstained_windows": sum(1 for x in d if x == INS)}
    e, rel = ece_top(P, yi)
    eu, _ = ece_top(U, yi)
    rep = {"hyperparameters_per_fold": chosen, "tau_ml": tau, "ece": e, "ece_uncalibrated": eu,
           "brier": brier(P, yi), "brier_uncalibrated": brier(U, yi), "reliability": rel, **res}
    gq2 = all((rep["gated"]["per_class_run"][c]["recall"] or 0.0) >= GATES["G-Q2 per-class recall >= 0.70"]
              for c in CLASSES)
    rep["gates"] = {"G-Q1 macro F1 >= 0.80": rep["gated"]["run_macro_f1"] >= GATES["G-Q1 macro F1 >= 0.80"],
                    "G-Q2 per-class recall >= 0.70": gq2,
                    "G-C1 ECE <= 0.10 and calibrated Brier < uncalibrated": e <= GATES["G-C1 ECE <= 0.10"]
                    and rep["brier"] < rep["brier_uncalibrated"]}
    log(f"{kind}: gated run macro F1 {rep['gated']['run_macro_f1']:.3f} ECE {e:.3f} gates {rep['gates']}")
    return rep, P, classes


# -- JSON model (AMD-30 admits model.json): exact re-implementation of the fitted predict_proba ----------------
def _tree_json(t):
    return {"left": t.children_left.tolist(), "right": t.children_right.tolist(), "feature": t.feature.tolist(),
            "threshold": t.threshold.tolist(), "value": t.value[:, 0, :].tolist()}


def serialise_base(kind, m):
    if kind == "logistic_regression":
        sc, lr = m.named_steps["scale"], m.named_steps["lr"]
        return {"mean": sc.mean_.tolist(), "scale": sc.scale_.tolist(), "coef": lr.coef_.tolist(),
                "intercept": lr.intercept_.tolist(), "response": "decision_function"}
    if kind == "random_forest":
        return {"trees": [_tree_json(e.tree_) for e in m.estimators_], "response": "predict_proba"}
    trees = [[{"nodes": {f: p.nodes[f].tolist() for f in ("value", "feature_idx", "num_threshold",
                                                           "missing_go_to_left", "left", "right", "is_leaf")}}
              for p in it] for it in m._predictors]
    return {"baseline": m._baseline_prediction.ravel().tolist(), "trees": trees, "response": "decision_function"}


def serialise(kind, hp, cal, keys):
    cc = cal.calibrated_classifiers_[0]
    return {"format": "sentinelai.faultlab.m7.model.v1", "kind": kind, "hyperparameters": hp,
            "classes": [str(c) for c in cal.classes_], "keys": list(keys), "columns": column_names(keys),
            "base": serialise_base(kind, cc.estimator),
            "calibrators": [{"a": float(c.a_), "b": float(c.b_)} for c in cc.calibrators], "seed": ML_SEED}


def _response(model, X):
    import numpy as np
    b, kind = model["base"], model["kind"]
    if kind == "logistic_regression":
        Z = (X - np.array(b["mean"])) / np.array(b["scale"])
        return Z @ np.array(b["coef"]).T + np.array(b["intercept"])
    if kind == "random_forest":
        X32 = X.astype(np.float32).astype(np.float64)       # sklearn rounds X to float32, then compares in double
        out = np.zeros((len(X), len(model["classes"])))
        for t in b["trees"]:
            for i, x in enumerate(X32):
                n = 0
                while t["left"][n] != -1:
                    n = t["left"][n] if x[t["feature"][n]] <= t["threshold"][n] else t["right"][n]
                v = np.array(t["value"][n])
                out[i] += v / v.sum()
        return out / len(b["trees"])
    out = np.tile(np.array(b["baseline"]), (len(X), 1))
    for it in b["trees"]:
        for k, tr in enumerate(it):
            nd = tr["nodes"]
            for i, x in enumerate(X):
                n = 0
                while not nd["is_leaf"][n]:
                    v = x[nd["feature_idx"][n]]
                    left = nd["missing_go_to_left"][n] if math.isnan(v) else v <= nd["num_threshold"][n]
                    n = nd["left"][n] if left else nd["right"][n]
                out[i, k] += nd["value"][n]
    return out


def predict_proba_json(model, X):
    """sklearn _CalibratedClassifier.predict_proba (sigmoid, multiclass) on the serialised model."""
    import numpy as np
    f = _response(model, X)
    proba = np.zeros_like(f)
    for k, c in enumerate(model["calibrators"]):
        proba[:, k] = 1.0 / (1.0 + np.exp(c["a"] * f[:, k] + c["b"]))
    den = proba.sum(axis=1)[:, None]
    proba = np.divide(proba, den, out=np.full_like(proba, 1 / proba.shape[1]), where=den != 0)
    proba[(1.0 < proba) & (proba <= 1.0 + 1e-5)] = 1.0
    return proba


def train(matrix, raw_root, report, engine_commit, log=print):
    """ML stage. `report` is the committed calibration_report.json: its engine values fix the windows and the
    contract gate; nothing here changes them."""
    import numpy as np
    import sklearn
    nums = dict(report["engine_parameters"]["numbers"])
    reasons = {k: tuple(v) for k, v in report["engine_parameters"]["reason_sets"].items()}
    p = params(dict(nums, **{TAU_DISAGREE: ENGINE_PLACEHOLDER}), reasons)
    from sentinelai.diagnostic.rules.engine import diagnose as eng
    runs, excluded = ml_runs(matrix)
    rows = []
    for r in runs:
        for s in windows(load_run(raw_root / r["run_id"]), nums):
            res = eng(s, p, code_commit=engine_commit).result
            rows.append({"run": r["run_id"], "family": r["family"], "label": label_of(r), "rules": res.decision.value,
                         "cols": window_columns(s, nums["COV_MIN"]),
                         "gate": {c.label.value: not c.required_missing for c in res.candidates}})
    keys = sorted({k for w in rows for k in w["cols"]})
    X = design_matrix([w["cols"] for w in rows], keys)
    y = np.array([w["label"] for w in rows])
    groups = [w["run"] for w in rows]
    labels = CLASSES + (INS,)
    audit = leakage_audit(column_names(keys))
    if not audit["ok"]:
        raise Refused(f"G-L1 column audit failed: {audit['rejected'][:5]}")
    vals, oof, chosen = {}, {}, None
    for kind in GRIDS:                                               # design §5.3 order; stop at the first passing
        vals[kind], P_k, classes = evaluate_kind(kind, X, y, groups, groups, [w["gate"] for w in rows], labels, log)
        oof[kind] = P_k
        if all(vals[kind]["gates"].values()):
            chosen = kind
            break
    met = chosen is not None
    if not met:                                                      # ML-6: none meets the gates
        chosen = max(vals, key=lambda k: (vals[k]["gated"]["run_macro_f1"], -list(GRIDS).index(k)))
    hp, hp_f1 = select_hp(chosen, X, y, groups, np.arange(len(y)), OUTER_FOLDS, labels)
    cal = fit_calibrated(chosen, hp, X, y, groups, np.arange(len(y)), OUTER_FOLDS)
    model = serialise(chosen, hp, cal, keys)
    pj, ps = predict_proba_json(model, X), cal.predict_proba(X)
    if not (np.allclose(pj, ps, rtol=0, atol=1e-9) and (pj.argmax(1) == ps.argmax(1)).all()):
        raise Refused("serialised model does not reproduce the fitted model")
    tau = vals[chosen]["tau_ml"]
    # τ_DISAGREE (C7-8): highest train macro F1 of the combined policy; the decision of record is the rules'
    # decision (design §5.4), so the policy's decisions do not depend on τ_DISAGREE; ties go to the larger value
    P_oof = oof[chosen]
    ml_pred = [classes[i] for i in P_oof.argmax(axis=1)]
    ml_conf = P_oof.max(axis=1).tolist()
    truth_run = run_level(groups, list(y))
    grid = {}
    for t in TAU_DISAGREE_GRID:
        dec = [w["rules"] for w in rows]                              # decision of record, unchanged
        flags = sum(1 for w, lab, c in zip(rows, ml_pred, ml_conf) if lab != w["rules"] and c >= t)
        rl = run_level(groups, dec)
        ks = sorted(rl)
        grid[str(t)] = {"combined_run_macro_f1": macro_f1([truth_run[k] for k in ks], [rl[k] for k in ks], labels),
                        "ml_disagreement_flags": flags}
    tau_d = max(TAU_DISAGREE_GRID, key=lambda t: (grid[str(t)]["combined_run_macro_f1"], t))
    rules_rl = run_level(groups, [w["rules"] for w in rows])
    ks = sorted(rules_rl)
    training_report = {
        "format": "sentinelai.faultlab.m7.training_report.v1", "objectives": "docs/PHASE_1C_M7_CALIBRATION_OBJECTIVES.md",
        "calibration_report_code_commit": report.get("code_commit"), "versions": {"sklearn": sklearn.__version__,
                                                                                  "numpy": np.__version__},
        "runs": sorted(set(groups)), "excluded_acceptable_set_runs": excluded, "windows": len(y),
        "label_counts": dict(sorted(Counter(y.tolist()).items())), "columns": len(keys) * 4, "leakage_audit": audit,
        "validation": vals, "chosen": {"kind": chosen, "met_gates_on_validation": met, "hyperparameters": hp,
                                       "hp_selection_window_macro_f1": hp_f1},
        "tau_ml": {"value": tau, "rule": "C7-8: smallest threshold with pooled held-out selective risk <= 10 %"},
        "tau_disagree": {"value": tau_d, "grid": grid, "rule": "C7-8; tie to the larger value",
                         "note": "the decision of record is the rules' decision (design §5.4), so every grid value "
                                 "gives the same combined macro F1 and the tie rule decides"},
        "rules_alone_train_run_macro_f1": macro_f1([truth_run[k] for k in ks], [rules_rl[k] for k in ks], labels),
        "serialisation_check": "max |p_json - p_sklearn| <= 1e-9 and identical argmax on every training window",
    }
    if not met:
        training_report["chosen"]["note"] = ("no model kind met every gate on validation; the one with the highest "
                                             "validation gated run macro F1 is used (ML-6)")
    model["tau_ml"] = tau
    return model, training_report, tau_d


def calibrated_params(report, tau_d):
    """Objectives §2 step 6: exactly the committed engine values plus τ_DISAGREE."""
    nums = dict(report["engine_parameters"]["numbers"])
    if TAU_DISAGREE in nums:
        raise Refused("the calibration report already carries τ_DISAGREE")
    out = {"parameter_set_id": PARAMS_ID, "numbers": dict(sorted({**nums, TAU_DISAGREE: tau_d}.items())),
           "reason_sets": report["engine_parameters"]["reason_sets"]}
    if any(out["numbers"][k] != v for k, v in nums.items()):
        raise Refused("an engine value differs from the committed calibration report")
    params(out["numbers"], {k: tuple(v) for k, v in out["reason_sets"].items()})           # validates
    return out


def _committed_unchanged(path: Path):
    rel = str(path.relative_to(ROOT))
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--error-unmatch", rel], capture_output=True)
    dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--", rel], capture_output=True, text=True)
    if tracked.returncode != 0 or dirty.stdout.strip():
        raise Refused(f"{rel} must be committed and unchanged first")


def lock(out: Path) -> dict:
    """lock.json: SHA-256 of every M7 artefact, the matrix and the dataset manifest (design §6.6, §8)."""
    import hashlib
    files = [out / n for n in ("calibration_report.json", "params.calibrated.json", "model.json",
                               "training_report.json")] + [M6.MATRIX, M6.MANIFEST]
    for f in files:
        _committed_unchanged(f)
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                            check=True).stdout.strip()
    return {"format": "sentinelai.faultlab.m7.lock.v1", "commit": commit,
            "sha256": {str(f.relative_to(ROOT)): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}}


# ------------------------------------------------------------------------------------------ CLI
def dump(obj) -> bytes:
    return (json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("calibrate")
    c.add_argument("--out", default=str(OUT))
    t = sub.add_parser("train")
    t.add_argument("--out", default=str(OUT))
    lk = sub.add_parser("lock")
    lk.add_argument("--out", default=str(OUT))
    a = ap.parse_args(argv)
    out = Path(a.out)
    if a.cmd == "train":
        return _train_cli(out)
    if a.cmd == "lock":
        if (out / LOCK_OUT.name).exists():
            raise Refused(f"{out / LOCK_OUT.name} exists; M7 artefacts are add-only (AMD-30)")
        with open(out / LOCK_OUT.name, "xb") as fh:
            fh.write(dump(lock(out)))
        print(json.dumps({"written": str(out / LOCK_OUT.name)}))
        return 0
    if (out / REPORT_OUT.name).exists():
        raise Refused(f"{out / REPORT_OUT.name} exists; M7 artefacts are add-only (AMD-30)")
    matrix = M6.committed_matrix()
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                            check=True).stdout.strip()
    numbers, reasons, rep = calibrate(matrix, M6.RAW, commit)
    rep["code_commit"] = commit
    if rep["stopped"] and out.resolve() == OUT.resolve():   # C7-16 stop rule: never an artefact
        raise Refused(f"calibration stopped for owner review, nothing written: {rep['stopped']}")
    out.mkdir(parents=True, exist_ok=True)
    with open(out / REPORT_OUT.name, "xb") as fh:
        fh.write(dump(rep))
    print(json.dumps({"written": str(out / REPORT_OUT.name), "stopped": rep["stopped"]}))
    return 3 if rep["stopped"] else 0


def _train_cli(out: Path) -> int:
    for n in (MODEL_OUT.name, TRAIN_OUT.name, PARAMS_OUT.name):
        if (out / n).exists():
            raise Refused(f"{out / n} exists; M7 artefacts are add-only (AMD-30)")
    rp = out / REPORT_OUT.name
    if out.resolve() == OUT.resolve():
        _committed_unchanged(rp)                     # objectives §2 step 5: the engine values are committed first
    report = json.loads(rp.read_bytes())
    if report.get("stopped"):
        raise Refused("the calibration report is marked stopped")
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                            check=True).stdout.strip()
    model, rep, tau_d = train(M6.committed_matrix(), M6.RAW, report, commit)
    rep["code_commit"] = commit
    prm = calibrated_params(report, tau_d)
    for n, obj in ((MODEL_OUT.name, model), (TRAIN_OUT.name, rep), (PARAMS_OUT.name, prm)):
        with open(out / n, "xb") as fh:
            fh.write(dump(obj))
    print(json.dumps({"written": [MODEL_OUT.name, TRAIN_OUT.name, PARAMS_OUT.name], "chosen": rep["chosen"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
