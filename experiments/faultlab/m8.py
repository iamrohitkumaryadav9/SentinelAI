"""Phase 1C M8: the one-time evaluation of the held-out test split (C7-21; AMD-32).

    .venv/bin/python experiments/faultlab/m8.py evaluate                         # the one test run
    .venv/bin/python experiments/faultlab/m8.py evaluate --rehearsal-train --out <scratch>   # train-only rehearsal

Executes docs/PHASE_1C_M8_EVALUATION_PROTOCOL.md (M8-0 … M8-7) with the exact artefacts locked at afdde9a. The
pre-execution checks (M8-0) run before any test raw file is opened; any failure refuses. The test run writes
datasets/faultlab/v1/m8/evaluation.json once (add-only). Nothing locked is read for writing.
"""
import argparse
import hashlib
import json
import math
import os
import random
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "src"))
import m6 as M6  # noqa: E402
import m7 as X  # noqa: E402

LOCK_COMMIT = "afdde9a4a94faf5c762a4a77c74b5a40404823b3"
LOCK = X.OUT / "lock.json"
OUT = ROOT / "datasets" / "faultlab" / "v1" / "m8"
EVAL_OUT = OUT / "evaluation.json"
INS_FAMILIES = ("OV-4", "OV-5", "OV-8", "OV-9", "OV-10")       # M8-1: expected INS, no acceptable set
TREE_SCOPE = ("src", "ebpf", "contract", "scripts", "tests", "datasets")
TEST_COMPOSITION = {"SF": 72, "CTRL": 14, "OV": 20}              # M8-0 (5)
LABELS = X.CLASSES + (X.INS,)
Z95 = 1.96
PERM_REPEATS, PERM_SEED = 5, 20261002                            # M8-4


class Refused(SystemExit):
    pass


def git(*a, check=True):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"}
    return subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True, check=check, env=env)


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ------------------------------------------------------------------------------------------ M8-0, M8-1
def split_runs(matrix, split):
    return sorted((r for r in matrix["runs"] if r["split"] == split), key=lambda r: r["run_id"])


def populations(runs):
    """M8-1: P (SF + CTRL), INS (CTRL + INS-expected overlap runs without an acceptable set), R (all overlap)."""
    P = [r["run_id"] for r in runs if r["family"] in ("SF", "CTRL")]
    INS = [r["run_id"] for r in runs if r["family"] == "CTRL" or
           (r["family"] in INS_FAMILIES and r["expected"]["primary"] == X.INS and "acceptable" not in r["expected"])]
    R = [r["run_id"] for r in runs if r["family"].startswith("OV-")]
    return {"P": P, "INS": INS, "R": R}


def expected(run):
    return X.INS if run["family"] == "CTRL" else run["expected"]["primary"]


def preflight(matrix, split, out: Path, rehearsal: bool) -> dict:
    """M8-0. Returns every check; the caller refuses unless all hold. Reads no raw evidence of the split."""
    c = {}
    c["head_descends_from_lock"] = git("merge-base", "--is-ancestor", LOCK_COMMIT, "HEAD", check=False).returncode == 0
    lock = json.loads(LOCK.read_bytes())
    locked = sorted(lock["sha256"]) + [str(LOCK.relative_to(ROOT))]
    c["locked_paths_unchanged_since_lock"] = git("diff", "--name-only", LOCK_COMMIT, "HEAD", "--", *locked).stdout == ""
    c["locked_hashes_match"] = all(sha256(ROOT / p) == h for p, h in lock["sha256"].items())
    c["no_tracked_modification"] = git("status", "--porcelain", "--untracked-files=no").stdout == ""
    c["no_untracked_in_tree_scope"] = git("ls-files", "--others", "--exclude-standard", "--", *TREE_SCOPE).stdout == ""
    target = out / EVAL_OUT.name
    c["output_absent"] = not target.exists()
    if not rehearsal:
        c["output_never_committed"] = git("log", "--all", "--format=%H", "--", str(EVAL_OUT.relative_to(ROOT))).stdout == ""
    ids = [r["run_id"] for r in matrix["runs"]]
    c["run_ids_unique_across_splits"] = len(ids) == len(set(ids))
    runs = split_runs(matrix, split)
    comp = Counter("OV" if r["family"].startswith("OV-") else r["family"] for r in runs)
    if split == "test":
        c["test_split_composition"] = dict(comp) == TEST_COMPOSITION
    manifest = json.loads(M6.MANIFEST.read_bytes())["files"]
    c["every_run_in_manifest"] = all(any(k.startswith(f"datasets/faultlab/v1/raw/{r['run_id']}/") for k in manifest)
                                     for r in runs)
    model = json.loads((X.OUT / "model.json").read_bytes())
    c["model_column_audit"] = X.leakage_audit(model["columns"])["ok"]
    c["matrix_is_locked_matrix"] = sha256(M6.MATRIX) == lock["sha256"][str(M6.MATRIX.relative_to(ROOT))]
    return c


def verify_raw(run_id: str, manifest: dict):
    """Every raw file of the run is listed in the manifest with its SHA-256, and nothing else is present."""
    pre = f"datasets/faultlab/v1/raw/{run_id}/"
    listed = {k: v for k, v in manifest.items() if k.startswith(pre)}
    present = {str(p.relative_to(ROOT)) for p in (M6.RAW / run_id).glob("*")}
    if set(listed) != present:
        raise Refused(f"{run_id}: raw files differ from the manifest")
    for k, h in listed.items():
        h = h if isinstance(h, str) else h.get("sha256")
        if sha256(ROOT / k) != h:
            raise Refused(f"{k}: SHA-256 differs from the manifest")


# ------------------------------------------------------------------------------------------ metrics (M8-4)
def wilson(k: int, n: int):
    if n == 0:
        return None
    p = k / n
    d = 1 + Z95 ** 2 / n
    centre = (p + Z95 ** 2 / (2 * n)) / d
    half = Z95 * math.sqrt(p * (1 - p) / n + Z95 ** 2 / (4 * n * n)) / d
    return [max(0.0, centre - half), min(1.0, centre + half)]


def system_metrics(truth: dict, dec: dict, ids) -> dict:
    """Run-level metrics of one system on one population (ids)."""
    t = [truth[i] for i in ids]
    d = [dec[i] for i in ids]
    per = {}
    for lab in LABELS:
        tp = sum(1 for a, b in zip(t, d) if a == lab and b == lab)
        asserted = sum(1 for b in d if b == lab)
        support = sum(1 for a in t if a == lab)
        f1 = 2 * tp / (asserted + support) if asserted + support else 0.0
        per[lab] = {"support": support, "predicted": asserted, "tp": tp,
                    "precision": tp / asserted if asserted else None, "precision_ci95": wilson(tp, asserted),
                    "recall": tp / support if support else None, "recall_ci95": wilson(tp, support), "f1": f1}
    conf = {a: dict(sorted(Counter(b for aa, b in zip(t, d) if aa == a).items())) for a in LABELS if a in t}
    named = {"tcp_retransmissions->network_packet_loss": sum(1 for a, b in zip(t, d) if a == "tcp_retransmissions"
                                                             and b == "network_packet_loss"),
             "network_packet_loss->tcp_retransmissions": sum(1 for a, b in zip(t, d) if a == "network_packet_loss"
                                                             and b == "tcp_retransmissions"),
             "cpu_throttling->cpu_contention": sum(1 for a, b in zip(t, d) if a == "cpu_throttling"
                                                   and b == "cpu_contention")}
    fault = [(a, b) for a, b in zip(t, d) if a in X.CLASSES]
    asserted_f = [(a, b) for a, b in fault if b != X.INS]
    cross = sum(1 for a, b in zip(t, d) if b in X.CLASSES and b != a)
    return {"runs": len(ids), "macro_f1": X.macro_f1(t, d, LABELS), "per_class": per, "confusion": conf,
            "named_confusions": named, "cross_class_errors": cross,
            "coverage_fault_runs": len(asserted_f) / len(fault) if fault else None,
            "selective_accuracy": (sum(1 for a, b in asserted_f if a == b) / len(asserted_f)) if asserted_f else None,
            "abstentions": {a: sum(1 for aa, b in zip(t, d) if aa == a and b == X.INS) for a in LABELS if a in t}}


def ins_metrics(dec: dict, ids) -> dict:
    d = [dec[i] for i in ids]
    ab = sum(1 for x in d if x == X.INS)
    return {"runs": len(ids), "abstention_rate": ab / len(ids) if ids else None,
            "false_assertion_rate": (len(ids) - ab) / len(ids) if ids else None,
            "abstention_ci95": wilson(ab, len(ids)), "asserted_labels": dict(Counter(x for x in d if x != X.INS))}


def risk_coverage(conf, correct):
    pts = []
    for t in sorted(set(conf), reverse=True):
        kept = [c for p, c in zip(conf, correct) if p >= t]
        pts.append({"threshold": t, "coverage": len(kept) / len(conf), "risk": 1 - sum(kept) / len(kept)})
    return pts


def gates(sysP: dict, ins: dict, calib: dict, n_windows: int) -> dict:
    out = {}
    min_support = min(sysP["rules"]["per_class"][c]["support"] for c in X.CLASSES)
    for name, key in (("rules alone (primary)", "rules"), ("ML gated (secondary)", "ml_gated")):
        m = sysP[key]
        out[f"G-Q1 macro F1 >= 0.80 | {name}"] = {"value": m["macro_f1"], "pass": m["macro_f1"] >= 0.80,
                                                  "valid": min_support >= 10, "min_runs_per_class": min_support}
        rec = {c: m["per_class"][c]["recall"] for c in X.CLASSES}
        out[f"G-Q2 recall >= 0.70 per fault class | {name}"] = {
            "values": rec, "wilson_lower": {c: m["per_class"][c]["recall_ci95"][0] for c in X.CLASSES},
            "failing": sorted(c for c, v in rec.items() if v is None or v < 0.70),
            "pass": all(v is not None and v >= 0.70 for v in rec.values()), "valid": min_support >= 10}
        i = ins[key]
        out[f"G-Q3 INS abstention >= 0.90 and false assertion <= 0.10 | {name}"] = {
            "abstention": i["abstention_rate"], "false_assertion": i["false_assertion_rate"],
            "pass": i["abstention_rate"] >= 0.90 and i["false_assertion_rate"] <= 0.10, "valid": i["runs"] >= 20}
        out[f"G-Q4 coverage on fault runs >= 0.80 | {name}"] = {"value": m["coverage_fault_runs"],
                                                               "pass": m["coverage_fault_runs"] >= 0.80}
    out["G-C1 ECE <= 0.10 and calibrated Brier < uncalibrated | ML"] = {
        "ece": calib["ece"], "brier": calib["brier"], "brier_uncalibrated": calib["brier_uncalibrated"],
        "pass": calib["ece"] <= 0.10 and calib["brier"] < calib["brier_uncalibrated"], "valid": n_windows >= 200,
        "windows": n_windows}
    return out


# ------------------------------------------------------------------------------------------ combined policy
_LOWER = {"HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}


def combine(result, snapshot, probs: dict, tau_d: float, model_id: str):
    """Design §5.4 / M8-3: attach the ML advisory; flag and lower confidence on a confident disagreement; the
    decision is never changed; the combined result is re-validated by the contract."""
    from sentinelai.diagnostic.contract import ConfidenceLevel, DiagnosticFlag, Label
    from sentinelai.diagnostic.contract.models import DiagnosticResult, MLAdvisory
    from sentinelai.diagnostic.contract.validate import validate_against_snapshot
    top = max(probs, key=lambda k: (probs[k], k))
    agrees = top == result.decision.value
    ml = MLAdvisory(model_id=model_id, probabilities={Label(k): float(v) for k, v in probs.items()}, calibrated=True,
                    agrees_with_rules=agrees)
    flags, conf = tuple(result.flags), result.confidence_level.value
    flagged = (not agrees) and probs[top] >= tau_d
    if flagged:
        flags = flags + (DiagnosticFlag.ML_DISAGREEMENT,)
        new = _LOWER[conf]
        conf = "MEDIUM" if (result.decision.value != X.INS and new == "LOW") else new
    combined = result.model_copy(update={"ml": ml, "flags": flags, "confidence_level": ConfidenceLevel(conf)})
    combined = DiagnosticResult.model_validate_json(combined.model_dump_json(), strict=False)
    validate_against_snapshot(combined, snapshot)
    return combined, flagged


# ------------------------------------------------------------------------------------------ evaluation
def evaluate(matrix, split: str, log=print) -> dict:
    import numpy as np
    from sentinelai.diagnostic.contract.serialize import canonical_bytes
    from sentinelai.diagnostic.contract.validate import validate_against_snapshot
    from sentinelai.diagnostic.rules.engine import diagnose as eng
    prm = json.loads((X.OUT / "params.calibrated.json").read_bytes())
    model = json.loads((X.OUT / "model.json").read_bytes())
    model_id = f"m7-{model['kind']}-{sha256(X.OUT / 'model.json')[:12]}"
    nums = prm["numbers"]
    p = X.params(nums, {k: tuple(v) for k, v in prm["reason_sets"].items()})
    tau_d, tau_ml = nums[X.TAU_DISAGREE], model["tau_ml"]
    commit = git("rev-parse", "HEAD").stdout.strip()
    runs = split_runs(matrix, split)
    pops = populations(runs)
    meta = {r["run_id"]: r for r in runs}
    manifest = json.loads(M6.MANIFEST.read_bytes())["files"]
    use = sorted(set(pops["P"]) | set(pops["INS"]) | set(pops["R"]))
    rows, cols = [], []
    e1_failures, e2_failures = [], []
    for n, rid in enumerate(use):
        verify_raw(rid, manifest)
        for w, s in enumerate(X.windows(X.load_run(M6.RAW / rid), nums)):
            d = eng(s, p, code_commit=commit)
            again = [canonical_bytes(eng(s, p, code_commit=commit).result) for _ in range(2)]
            if any(a != canonical_bytes(d.result) for a in again):
                e2_failures.append([rid, w])
            try:
                validate_against_snapshot(d.result, d.snapshot)
            except Exception as exc:                                             # recorded, never hidden
                e1_failures.append([rid, w, f"rules: {type(exc).__name__}: {exc}"[:300]])
            r = d.result
            rows.append({"run": rid, "window": w, "expected": expected(meta[rid]), "rules": r.decision.value,
                         "confidence": r.confidence_level.value, "contributing": [c.value for c in r.contributing],
                         "abstention_reasons": [a.value for a in r.abstention_reasons],
                         "flags": [f.value for f in r.flags],
                         "gate": {c.label.value: not c.required_missing for c in r.candidates},
                         "_result": r, "_snapshot": d.snapshot})
            cols.append(X.window_columns(s, nums["COV_MIN"]))
        log(f"{n + 1}/{len(use)} {rid}")
    Xm = X.design_matrix(cols, model["keys"])
    P = X.predict_proba_json(model, Xm)
    U = X._response(model, Xm) if model["kind"] == "random_forest" else None
    classes = model["classes"]
    for i, row in enumerate(rows):
        probs = {c: float(P[i, k]) for k, c in enumerate(classes)}
        top = max(probs, key=lambda k: (probs[k], k))
        row["ml_probabilities"] = probs
        row["ml_raw"] = top
        row["ml_gated"] = X.gated([top], [probs[top]], tau_ml, [row["gate"]])[0]
        try:
            comb, flagged = combine(row["_result"], row["_snapshot"], probs, tau_d, model_id)
            row["combined"] = {"decision": comb.decision.value, "confidence": comb.confidence_level.value,
                               "flags": [f.value for f in comb.flags], "agrees_with_rules": comb.ml.agrees_with_rules,
                               "ml_disagreement": flagged}
        except Exception as exc:                                                 # recorded, never hidden
            e1_failures.append([row["run"], row["window"], f"combined: {type(exc).__name__}: {exc}"[:300]])
            row["combined"] = {"decision": row["rules"], "error": str(exc)[:300]}
    truth = {rid: expected(meta[rid]) for rid in use}
    by_run = defaultdict(list)
    for row in rows:
        by_run[row["run"]].append(row)
    dec = {k: {rid: X.run_decision([w[f] for w in ws]) for rid, ws in by_run.items()}
           for k, f in (("rules", "rules"), ("ml_raw", "ml_raw"), ("ml_gated", "ml_gated"))}
    dec["combined"] = {rid: X.run_decision([w["combined"]["decision"] for w in ws]) for rid, ws in by_run.items()}
    sysP = {k: system_metrics(truth, dec[k], pops["P"]) for k in dec}
    inP = set(pops["P"])
    pick = {"rules": lambda w: w["rules"], "ml_raw": lambda w: w["ml_raw"], "ml_gated": lambda w: w["ml_gated"],
            "combined": lambda w: w["combined"]["decision"]}
    for k in dec:
        t = [w["expected"] for w in rows if w["run"] in inP]
        d = [pick[k](w) for w in rows if w["run"] in inP]
        sysP[k]["window"] = {"macro_f1": X.macro_f1(t, d, LABELS),
                             "confusion": {a: dict(sorted(Counter(b for aa, b in zip(t, d) if aa == a).items()))
                                           for a in LABELS if a in t}}
    ins = {k: ins_metrics(dec[k], pops["INS"]) for k in dec}
    pidx = [i for i, w in enumerate(rows) if w["run"] in set(pops["P"])]
    yi = np.array([classes.index(rows[i]["expected"]) for i in pidx])
    PP = P[pidx]
    ece, rel = X.ece_top(PP, yi)
    calib = {"windows": len(pidx), "brier": X.brier(PP, yi), "ece": ece, "reliability": rel}
    if U is not None:
        calib["brier_uncalibrated"] = X.brier(U[pidx], yi)
        calib["ece_uncalibrated"] = X.ece_top(U[pidx], yi)[0]
    conf_raw = [float(PP[j].max()) for j in range(len(pidx))]
    correct = [classes[int(PP[j].argmax())] == rows[i]["expected"] for j, i in enumerate(pidx)]
    rc = {"ml_raw_windows": risk_coverage(conf_raw, correct),
          "rules_operating_point_runs": {"coverage": sysP["rules"]["coverage_fault_runs"],
                                         "risk": 1 - (sysP["rules"]["selective_accuracy"] or 0.0)}}
    rob = {}
    for rid in pops["R"]:
        r = meta[rid]
        okset = sorted({a["primary"] for a in r["expected"].get("acceptable", [])} | {r["expected"]["primary"]}) \
            if "acceptable" in r["expected"] else [r["expected"]["primary"]]
        rob[rid] = {"family": r["family"], "expected": r["expected"], "accepted_primaries": okset,
                    **{k: {"decision": dec[k][rid], "correct": dec[k][rid] in okset} for k in dec},
                    "rules_window_contributing": [w["contributing"] for w in by_run[rid]]}
    fam = defaultdict(lambda: Counter())
    for rid, v in rob.items():
        for k in dec:
            fam[v["family"]][k] += v[k]["correct"]
    pw = [rows[i] for i in pidx]
    disagreement = {"windows": len(pw), "agrees": sum(1 for w in pw if w["combined"].get("agrees_with_rules")),
                    "ml_disagreement_flags": sum(1 for w in pw if w["combined"].get("ml_disagreement")),
                    "confidence_before": dict(Counter(w["confidence"] for w in pw)),
                    "confidence_after": dict(Counter(w["combined"].get("confidence") for w in pw)),
                    "decisions_changed": sum(1 for w in pw if w["combined"]["decision"] != w["rules"])}
    importance = permutation_importance(model, Xm[pidx], [rows[i] for i in pidx], log)
    out = {"format": "sentinelai.faultlab.m8.evaluation.v1", "protocol": "docs/PHASE_1C_M8_EVALUATION_PROTOCOL.md",
           "split": split, "code_commit": commit, "lock_commit": LOCK_COMMIT,
           "locked_sha256": json.loads(LOCK.read_bytes())["sha256"], "model_id": model_id,
           "tau_ml": tau_ml, "tau_disagree": tau_d, "populations": pops, "run_level": dec,
           "systems_P": sysP, "systems_INS": ins, "gates": gates(sysP, ins, calib, len(pidx)), "calibration": calib,
           "risk_coverage": rc, "robustness": {"runs": rob, "correct_by_family": {f: dict(c) for f, c in fam.items()}},
           "disagreement_policy": disagreement, "permutation_importance": importance,
           "G-E1": {"windows": len(rows), "failures": e1_failures, "pass": not e1_failures},
           "G-E2": {"windows": len(rows), "repeats": 3, "failures": e2_failures, "pass": not e2_failures},
           "windows": [{k: v for k, v in w.items() if not k.startswith("_")} for w in rows]}
    return out


def permutation_importance(model, Xp, prow, log=print):
    """M8-4: grouped (whole-run) permutation of each key's four columns; drop in window macro F1 of the raw model."""
    import numpy as np
    truth = [w["expected"] for w in prow]
    runs = sorted({w["run"] for w in prow})
    idx = {(w["run"], w["window"]): i for i, w in enumerate(prow)}
    base_pred = X.predict_proba_json(model, Xp).argmax(axis=1)
    classes = model["classes"]
    base = X.macro_f1(truth, [classes[i] for i in base_pred], LABELS)
    rng = random.Random(PERM_SEED)
    out = {}
    for j, key in enumerate(model["keys"]):
        drops = []
        for _ in range(PERM_REPEATS):
            donor = runs[:]
            rng.shuffle(donor)
            Xq = Xp.copy()
            for a, b in zip(runs, donor):
                for w in range(3):
                    if (a, w) in idx and (b, w) in idx:
                        Xq[idx[(a, w)], 4 * j:4 * j + 4] = Xp[idx[(b, w)], 4 * j:4 * j + 4]
            pred = X.predict_proba_json(model, Xq).argmax(axis=1)
            drops.append(base - X.macro_f1(truth, [classes[i] for i in pred], LABELS))
        out[key] = {"mean_drop": sum(drops) / len(drops), "drops": drops}
    log("permutation importance done")
    top = sorted(out.items(), key=lambda kv: -kv[1]["mean_drop"])
    return {"baseline_window_macro_f1": base, "repeats": PERM_REPEATS, "seed": PERM_SEED,
            "keys": dict(top)}


# ------------------------------------------------------------------------------------------ CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("evaluate")
    e.add_argument("--rehearsal-train", action="store_true", help="M8-7: train split into a scratch directory")
    e.add_argument("--out")
    a = ap.parse_args(argv)
    if a.rehearsal_train:
        if not a.out or Path(a.out).resolve() == OUT.resolve():
            raise Refused("a rehearsal needs a scratch --out outside datasets/faultlab/v1/m8")
        out, split = Path(a.out), "train"
    else:
        if a.out:
            raise Refused("the test evaluation writes only datasets/faultlab/v1/m8/evaluation.json")
        out, split = OUT, "test"
    matrix = M6.committed_matrix()
    checks = preflight(matrix, split, out, a.rehearsal_train)
    print(json.dumps({"preflight": checks}))
    if not all(checks.values()):
        raise Refused(f"M8-0 pre-execution check failed, nothing read: {[k for k, v in checks.items() if not v]}")
    res = evaluate(matrix, split)
    res["preflight"] = checks
    out.mkdir(parents=True, exist_ok=True)
    with open(out / EVAL_OUT.name, "xb") as fh:
        fh.write((json.dumps(res, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode())
    print(json.dumps({"written": str(out / EVAL_OUT.name), "gates": {k: v["pass"] for k, v in res["gates"].items()}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
