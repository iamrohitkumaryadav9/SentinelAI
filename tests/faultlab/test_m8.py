"""Tests of the M8 evaluation tool (experiments/faultlab/m8.py; C7-21; AMD-32). No test run is read here: the
real-matrix checks use only the matrix and the manifest, and every computation is exercised on fixtures."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments" / "faultlab"))
sys.path.insert(0, str(ROOT / "src"))
import m8 as E  # noqa: E402

MATRIX = json.loads((ROOT / "datasets" / "faultlab" / "v1" / "matrix.json").read_text())


class TestPopulations(unittest.TestCase):
    def test_test_split_populations(self):
        pops = E.populations(E.split_runs(MATRIX, "test"))
        self.assertEqual((len(pops["P"]), len(pops["INS"]), len(pops["R"])), (86, 24, 20))
        fam = {r["run_id"]: r["family"] for r in MATRIX["runs"]}
        self.assertEqual({fam[i] for i in pops["P"]}, {"SF", "CTRL"})
        self.assertNotIn("OV-7", {fam[i] for i in pops["INS"]})            # acceptable set: robustness only
        self.assertEqual({r["split"] for r in E.split_runs(MATRIX, "test")}, {"test"})

    def test_rehearsal_populations_are_train(self):
        runs = E.split_runs(MATRIX, "train")
        self.assertEqual({r["split"] for r in runs}, {"train"})
        pops = E.populations(runs)
        self.assertEqual((len(pops["P"]), len(pops["INS"])), (58, 20))

    def test_expected_label(self):
        ctrl = next(r for r in MATRIX["runs"] if r["family"] == "CTRL")
        self.assertEqual(E.expected(ctrl), E.X.INS)


class TestMetrics(unittest.TestCase):
    def test_wilson(self):
        lo, hi = E.wilson(10, 12)
        self.assertAlmostEqual(lo, 0.5520, places=3)
        self.assertAlmostEqual(hi, 0.9530, places=3)
        self.assertEqual(E.wilson(0, 0), None)
        self.assertEqual(E.wilson(5, 5)[1], 1.0)

    def test_system_metrics(self):
        truth = {"a": "cpu_contention", "b": "cpu_contention", "c": "cpu_throttling", "d": E.X.INS}
        dec = {"a": "cpu_contention", "b": E.X.INS, "c": "cpu_contention", "d": E.X.INS}
        m = E.system_metrics(truth, dec, list(truth))
        self.assertEqual(m["named_confusions"]["cpu_throttling->cpu_contention"], 1)
        self.assertEqual(m["cross_class_errors"], 1)
        self.assertAlmostEqual(m["coverage_fault_runs"], 2 / 3)
        self.assertAlmostEqual(m["selective_accuracy"], 1 / 2)
        self.assertEqual(m["per_class"]["cpu_contention"]["precision"], 0.5)
        self.assertEqual(m["abstentions"]["cpu_contention"], 1)
        i = E.ins_metrics({"x": E.X.INS, "y": "cpu_contention"}, ["x", "y"])
        self.assertEqual((i["abstention_rate"], i["false_assertion_rate"]), (0.5, 0.5))

    def test_risk_coverage(self):
        pts = E.risk_coverage([0.9, 0.8, 0.5], [True, False, True])
        self.assertEqual([(p["threshold"], round(p["coverage"], 3), round(p["risk"], 3)) for p in pts],
                         [(0.9, 0.333, 0.0), (0.8, 0.667, 0.5), (0.5, 1.0, 0.333)])

    def test_gates_use_the_predeclared_thresholds(self):
        per = {c: {"support": 12, "recall": 0.75, "recall_ci95": [0.5, 0.9]} for c in E.X.CLASSES}
        sysm = {"macro_f1": 0.8, "per_class": per, "coverage_fault_runs": 0.8}
        ins = {"runs": 24, "abstention_rate": 0.9, "false_assertion_rate": 0.1}
        g = E.gates({"rules": sysm, "ml_gated": sysm}, {"rules": ins, "ml_gated": ins},
                    {"ece": 0.1, "brier": 0.1, "brier_uncalibrated": 0.2}, 258)
        self.assertTrue(all(v["pass"] for v in g.values()))
        per2 = dict(per, memory_pressure={"support": 12, "recall": 0.69, "recall_ci95": [0.4, 0.9]})
        g = E.gates({"rules": dict(sysm, per_class=per2, macro_f1=0.79), "ml_gated": sysm},
                    {"rules": ins, "ml_gated": ins}, {"ece": 0.11, "brier": 0.1, "brier_uncalibrated": 0.2}, 199)
        self.assertFalse(g["G-Q1 macro F1 >= 0.80 | rules alone (primary)"]["pass"])
        self.assertEqual(g["G-Q2 recall >= 0.70 per fault class | rules alone (primary)"]["failing"],
                         ["memory_pressure"])
        c1 = g["G-C1 ECE <= 0.10 and calibrated Brier < uncalibrated | ML"]
        self.assertEqual((c1["pass"], c1["valid"]), (False, False))


class TestCombinedPolicy(unittest.TestCase):
    """Design §5.4: the decision never changes; a confident disagreement flags and lowers confidence, never below
    MEDIUM for an asserted decision; the combined result passes the contract."""

    def diag(self):
        from rules._fixtures import COMMIT, contention, params, run, scenario
        return run(scenario(contention()))

    def test_decision_unchanged_and_contract_valid(self):
        d = self.diag()
        dec = d.result.decision.value
        self.assertEqual(dec, "cpu_contention")
        other = {lab: 0.0 for lab in E.LABELS}
        agree = dict(other, cpu_contention=0.95, cpu_throttling=0.05)
        c, flagged = E.combine(d.result, d.snapshot, agree, 0.9, "m7-test")
        self.assertEqual((c.decision.value, flagged, c.ml.agrees_with_rules, c.confidence_level),
                         (dec, False, True, d.result.confidence_level))
        disagree = dict(other, cpu_throttling=0.95, cpu_contention=0.05)
        c, flagged = E.combine(d.result, d.snapshot, disagree, 0.9, "m7-test")
        self.assertEqual((c.decision.value, flagged, c.ml.agrees_with_rules), (dec, True, False))
        self.assertIn("ML_DISAGREEMENT", [f.value for f in c.flags])
        self.assertNotEqual(c.confidence_level.value, "LOW")             # asserted: never below MEDIUM
        weak = dict(other, cpu_throttling=0.6, cpu_contention=0.4)
        c, flagged = E.combine(d.result, d.snapshot, weak, 0.9, "m7-test")
        self.assertEqual((flagged, c.confidence_level), (False, d.result.confidence_level))   # below τ_DISAGREE


class TestPermutation(unittest.TestCase):
    def test_whole_runs_are_permuted_and_baseline_kept(self):
        import numpy as np
        rows = [{"run": f"r{i}", "window": w, "expected": E.X.INS} for i in range(3) for w in range(3)]
        model = {"keys": ["k"], "classes": [E.X.INS, "cpu_contention"]}
        seen = []
        def fake(m, Xq):
            seen.append(Xq.copy())
            return np.tile([1.0, 0.0], (len(Xq), 1))
        Xp = np.arange(9 * 4, dtype=float).reshape(9, 4)
        with mock.patch.object(E.X, "predict_proba_json", side_effect=fake):
            out = E.permutation_importance(model, Xp, rows, lambda *_: None)
        self.assertEqual(out["keys"]["k"]["mean_drop"], 0.0)
        for Xq in seen[1:]:
            for i in range(3):                                           # each run receives one donor's three windows
                block = Xq[3 * i:3 * i + 3]
                donors = {int(b[0]) // 12 for b in block}
                self.assertEqual(len(donors), 1)
                self.assertEqual([int(b[0]) % 12 for b in block], [0, 4, 8])


class TestPreflightAndCli(unittest.TestCase):
    def test_lock_is_the_m7_lock(self):
        lock = json.loads(E.LOCK.read_bytes())
        self.assertEqual(lock["commit"], "799c148554b494fafa3992766904c39feccf2d13")
        self.assertEqual(len(lock["sha256"]), 6)

    def test_refusals(self):
        with self.assertRaises(SystemExit):
            E.main(["evaluate", "--out", "/tmp/x"])                      # the test run has one fixed output
        with self.assertRaises(SystemExit):
            E.main(["evaluate", "--rehearsal-train"])                    # a rehearsal needs a scratch --out
        with self.assertRaises(SystemExit):
            E.main(["evaluate", "--rehearsal-train", "--out", str(E.OUT)])

    def test_preflight_detects_each_failure(self):
        with tempfile.TemporaryDirectory() as d:
            c = E.preflight(MATRIX, "train", Path(d), True)
            for k in ("head_descends_from_lock", "locked_hashes_match", "model_column_audit",
                      "run_ids_unique_across_splits", "every_run_in_manifest", "matrix_is_locked_matrix"):
                self.assertTrue(c[k], k)
            (Path(d) / "evaluation.json").write_text("{}")
            self.assertFalse(E.preflight(MATRIX, "train", Path(d), True)["output_absent"])
            real = E.sha256
            with mock.patch.object(E, "sha256", side_effect=lambda p: "0" * 64 if p.name == "model.json" else real(p)):
                self.assertFalse(E.preflight(MATRIX, "train", Path(d), True)["locked_hashes_match"])
            dirty = mock.Mock(stdout=" M experiments/faultlab/m7.py\n", returncode=0)
            real_git = E.git
            with mock.patch.object(E, "git", side_effect=lambda *a, **k: dirty if a[0] == "status" else real_git(*a, **k)):
                self.assertFalse(E.preflight(MATRIX, "train", Path(d), True)["no_tracked_modification"])
        bad = {"runs": MATRIX["runs"] + [dict(MATRIX["runs"][0])]}
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(E.preflight(bad, "train", Path(d), True)["run_ids_unique_across_splits"])

    def test_verify_raw_rejects_a_changed_file(self):
        rid = next(r["run_id"] for r in MATRIX["runs"] if r["split"] == "train")
        manifest = json.loads(E.M6.MANIFEST.read_bytes())["files"]
        E.verify_raw(rid, manifest)
        k = next(k for k in manifest if k.startswith(f"datasets/faultlab/v1/raw/{rid}/"))
        with self.assertRaises(SystemExit):
            E.verify_raw(rid, dict(manifest, **{k: "0" * 64}))


if __name__ == "__main__":
    unittest.main()
