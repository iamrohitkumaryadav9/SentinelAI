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
    "THR_RATIO_MIN": (x_one("throttle.ratio"), "cpu_throttling", ()),
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


# ------------------------------------------------------------------------------------------ CLI
def dump(obj) -> bytes:
    return (json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("calibrate")
    c.add_argument("--out", default=str(OUT))
    a = ap.parse_args(argv)
    out = Path(a.out)
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


if __name__ == "__main__":
    sys.exit(main())
