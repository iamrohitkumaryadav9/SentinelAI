"""Tests of the M7 calibration tool (experiments/faultlab/m7.py; FZ-M7-PLAN; AMD-30) and of the AMD-6 window gap in
the snapshot builder that M7 uses."""
import json
import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments" / "faultlab"))
sys.path.insert(0, str(ROOT / "src"))
import m7 as X  # noqa: E402

MATRIX = json.loads((ROOT / "datasets" / "faultlab" / "v1" / "matrix.json").read_text())
RAW = ROOT / "datasets" / "faultlab" / "v1" / "raw"


class TestStatistics(unittest.TestCase):
    def test_percentiles(self):
        xs = list(range(1, 101))
        self.assertEqual((X.nearest_rank(xs, 0.99), X.nearest_rank(xs, 0.01), X.nearest_rank(xs, 1.0)), (99, 1, 100))
        self.assertEqual(X.lower_tail(xs, 0.99), 2)                       # 99 of 100 values are >= 2
        self.assertEqual(X.lower_tail([5] * 10, 0.99), 5)

    def test_false_positive_bounded_threshold(self):
        neg = [0.0] * 99 + [10.0]                                         # 1 % of negatives at 10
        r = X.fp_bounded([5.0, 6.0, 7.0], neg)
        self.assertEqual((r["value"], r["fp"], r["recall"], r["recall_shortfall"]), (5.0, 0.01, 1.0, False))
        r = X.fp_bounded([1.0, 2.0], [0.0] * 50 + [3.0] * 50)               # cannot separate: FP limit wins
        self.assertGreater(r["value"], 3.0)
        self.assertEqual((r["fp"], r["recall"], r["recall_shortfall"]), (0.0, 0.0, True))
        r = X.fp_bounded([], [0.0, 0.0])                                  # no positives (IMPACT_MIN)
        self.assertEqual((r["value"], r["recall"]), (math.nextafter(0.0, math.inf), None))

    def test_no_negatives_rule(self):                                     # C7-16
        r = X.no_negatives([0.9, 0.4, 0.7, 0.4])
        self.assertEqual((r["value"], r["recall"], r["fp"], r["negatives"], r["stopped"]), (0.4, 1.0, None, 0, False))
        xs = [float(i) for i in range(1, 201)]                            # n = 200: k = 2, the 2nd smallest
        self.assertEqual(X.no_negatives(xs)["value"], 2.0)
        self.assertEqual(X.no_negatives([3.0, 3.0, 3.0] + [5.0] * 197)["recall"], 1.0)   # ties at θ all fire
        self.assertTrue(X.no_negatives([0.0, 0.5])["stopped"])            # θ <= 0 stops for review
        self.assertTrue(X.no_negatives([-0.2, 0.5])["stopped"])
        with self.assertRaises(SystemExit):
            X.no_negatives([])

    def test_zero_firing_and_run_decision(self):
        self.assertEqual(X.zero_firing([0.1, 0.3]), math.nextafter(0.3, math.inf))
        self.assertEqual(X.zero_firing([]), X.FLOOR_MIN)
        self.assertEqual(X.run_decision(["a", "a", "b"]), "a")
        self.assertEqual(X.run_decision(["a", "b", X.INS]), X.INS)       # AMD-8: ties go to INS
        self.assertEqual(X.run_decision(["a", "a", "a"]), "a")

    def test_macro_f1(self):
        labs = X.CLASSES + (X.INS,)
        self.assertEqual(X.macro_f1(list(labs), list(labs)), 1.0)
        self.assertAlmostEqual(X.macro_f1(["cpu_contention", X.INS], [X.INS, X.INS]), (2 / 3) / 7)


class TestSplits(unittest.TestCase):
    def test_only_train_runs_reach_calibration(self):
        runs = X.train_runs(MATRIX)
        self.assertEqual({r["split"] for r in runs}, {"train"})
        self.assertEqual({r["family"] for r in runs}, {"SF", "CTRL"})
        self.assertEqual(len(runs), 58)                                   # 48 SF + 10 CTRL (C7-9)
        poisoned = {"runs": [dict(MATRIX["runs"][0], split="test", family="SF")]}
        self.assertEqual(X.train_runs(poisoned), [])

    def test_app_thresholds_count_false_positives_against_ctrl_only(self):
        for name in ("APP_WAIT_MIN", "APP_SHARE_MIN"):                    # C7-12
            _, own, neither = X.THRESHOLDS[name]
            self.assertEqual(set(neither) | {own}, set(X.CLASSES))
        self.assertEqual(X.THRESHOLDS["RT_FRAC_MIN"][2], ("network_packet_loss",))   # C7-1 exception unchanged
        self.assertEqual({k for k, (_, _, n) in X.THRESHOLDS.items() if n},
                         {"APP_WAIT_MIN", "APP_SHARE_MIN", "RT_FRAC_MIN", "RT_RATE_MIN"})

    def test_windows_follow_amd_8(self):
        self.assertEqual(X.WINDOW_STARTS, (61, 85, 109))
        self.assertLessEqual(X.WINDOW_STARTS[-1] + X.W_S, 135)            # inside the 136-tick collection


class TestWindowGap(unittest.TestCase):
    """AMD-6 window gap in collectors.build_snapshot (default behaviour unchanged, replay tests cover it)."""

    @classmethod
    def setUpClass(cls):
        r = next(x for x in MATRIX["runs"] if x["split"] == "train" and x["family"] == "CTRL")
        cls.ticks, cls.target, cls.ebpf = X.load_run(RAW / r["run_id"])
        nums = {f"floor[{f}]": 1e-6 for f in X.floor_features()}
        nums.update(B=45.0, W=24.0, COV_MIN=0.5, N_BASE_MIN=1.0)
        cls.p = X.params(nums)

    def build(self, ticks, **kw):
        from sentinelai.collectors import build_snapshot
        from sentinelai.diagnostic.contract import canonical_bytes
        return canonical_bytes(build_snapshot(ticks, self.target, self.p, 1.0, self.ebpf, True, **kw))

    def test_start_at_the_baseline_end_equals_the_contiguous_build(self):
        self.assertEqual(self.build(self.ticks, window_start=45), self.build(self.ticks[:45 + 24 + 1]))

    def test_ticks_in_the_gap_and_after_the_window_are_not_used(self):
        from dataclasses import replace
        t = list(self.ticks)
        bad = replace(t[50], obs={})                                       # an empty observation in the gap
        for i in list(range(46, 61)) + list(range(86, 136)):
            t[i] = bad if i < 61 else replace(t[i], obs={})
        self.assertEqual(self.build(t, window_start=61), self.build(self.ticks, window_start=61))
        t2 = list(self.ticks)
        t2[70] = replace(t2[70], obs={})                                   # inside the window: it matters
        self.assertNotEqual(self.build(t2, window_start=61), self.build(self.ticks, window_start=61))

    def test_window_bounds(self):
        from sentinelai.collectors import build_snapshot
        s = build_snapshot(self.ticks, self.target, self.p, 1.0, self.ebpf, True, window_start=61)
        self.assertAlmostEqual((s.window.end - s.window.start).total_seconds(), 24.0, delta=0.05)   # tick jitter
        self.assertAlmostEqual((s.baseline_window.end - s.baseline_window.start).total_seconds(), 45.0, delta=0.05)
        self.assertAlmostEqual((s.window.start - s.baseline_window.end).total_seconds(), 16.0, delta=0.01)
        from sentinelai.collectors.errors import CollectorError
        for bad in (44, 112, -1, "61"):
            with self.subTest(bad), self.assertRaises(CollectorError):
                build_snapshot(self.ticks, self.target, self.p, 1.0, self.ebpf, True, window_start=bad)


class TestDeclaredThrottleRatio(unittest.TestCase):
    """C7-17: THR_RATIO_MIN = 0.5 is declared, not calibrated; 0.99 satisfies the ratio clause, 0.0 does not."""

    def test_declared_not_calibrated(self):
        self.assertEqual(X.DECLARED, {"THR_RATIO_MIN": 0.5})
        self.assertNotIn("THR_RATIO_MIN", X.THRESHOLDS)

    def test_ratio_clause_at_the_declared_value(self):
        from rules._fixtures import CG, COMMIT, m, params, snapshot
        from sentinelai.diagnostic.contract import Label
        from sentinelai.diagnostic.rules import diagnose
        def ct(ratio):
            ms = [m("throttle.quota_limited", CG, 1.0, base=False), m("throttle.ratio", CG, ratio, base=False),
                  m("throttle.time_rate", CG, 0.5, 0.0, 0.0)]
            d = diagnose(snapshot(ms), params(THR_RATIO_MIN=X.DECLARED["THR_RATIO_MIN"]), code_commit=COMMIT)
            return next(c for c in d.result.candidates if c.label is Label.cpu_throttling)
        self.assertIn("CT.R3", ct(0.99).required_met)
        self.assertIn("CT.R3", ct(0.5).required_met)                     # x >= θ
        self.assertNotIn("CT.R3", ct(0.0).required_met)
        self.assertIn("CT.R3", ct(0.0).required_missing)


class TestMl(unittest.TestCase):
    @staticmethod
    def data(n=60, k=3, f=5, seed=1):
        import numpy as np
        rng = np.random.default_rng(seed)
        y = np.array([["a", "b", "c"][i % k] for i in range(n)])
        Xm = rng.normal(size=(n, f)) + np.array([[{"a": 0, "b": 2, "c": -2}[v]] * f for v in y])
        groups = [f"r{i // 3}" for i in range(n)]                        # three windows per run
        return Xm, y, groups

    def test_serialised_models_reproduce_sklearn(self):
        import numpy as np
        Xm, y, groups = self.data()
        for kind, hp in (("logistic_regression", {"C": 1.0}), ("random_forest", {"min_samples_leaf": 2}),
                         ("hist_gradient_boosting", {"learning_rate": 0.1, "max_leaf_nodes": 7})):
            with self.subTest(kind):
                cal = X.fit_calibrated(kind, hp, Xm, y, groups, np.arange(len(y)), 4)
                model = json.loads(json.dumps(X.serialise(kind, hp, cal, ["k1"])))     # survives JSON
                pj, ps = X.predict_proba_json(model, Xm), cal.predict_proba(Xm)
                self.assertTrue(np.allclose(pj, ps, rtol=0, atol=1e-9), float(abs(pj - ps).max()))
                self.assertTrue((pj.argmax(1) == ps.argmax(1)).all())

    def test_group_splits_never_split_a_run(self):
        import numpy as np
        _, _, groups = self.data()
        for tr, te in X._splits(groups, np.arange(len(groups)), 4):
            self.assertFalse({groups[i] for i in tr} & {groups[i] for i in te})

    def test_tau_ml_and_gating(self):
        self.assertEqual(X.tau_ml([0.9, 0.8, 0.4], [True, True, False]), 0.8)       # risk 0 at 0.8
        self.assertEqual(X.tau_ml([0.9, 0.5], [True, True]), 0.0)                   # risk 0 everywhere
        self.assertGreater(X.tau_ml([0.9, 0.5], [False, False]), 0.9)               # never: abstain always
        g = X.gated(["a", "b", X.INS, "a"], [0.9, 0.9, 0.9, 0.2], 0.5,
                    [{"a": True, "b": True}, {"a": True, "b": False}, {}, {"a": True}])
        self.assertEqual(g, ["a", X.INS, X.INS, X.INS])

    def test_calibration_metrics(self):
        import numpy as np
        p = np.array([[1.0, 0.0], [0.0, 1.0]])
        self.assertEqual(X.brier(p, np.array([0, 1])), 0.0)
        self.assertEqual(X.brier(p, np.array([1, 0])), 2.0)
        self.assertEqual(X.ece_top(p, np.array([0, 1]), bins=2)[0], 0.0)

    def test_columns_carry_no_identifiers(self):
        from types import SimpleNamespace as N
        m = N(feature_id="softirq.frac.percpu", scope="cpu:18", qualifier=N(value="NET_RX"),
              aggregation=N(value="RATIO"))
        self.assertEqual(X.column_key(m), "softirq.frac.percpu|cpu|NET_RX|RATIO")
        self.assertTrue(X.leakage_audit(X.column_names([X.column_key(m)]))["ok"])
        self.assertFalse(X.leakage_audit(["sched.run_delay.target|cgroup:/sentlab/target||RATE|z"])["ok"])
        ok = ["sched.procs_running.host|host||MEAN|z", "sched.run_delay.cpuset|cpuset||RATE|missing",
              "net.drop.kfree_skb|netns|QDISC_DROP|RATE|abs"]
        self.assertTrue(X.leakage_audit(ok)["ok"], X.leakage_audit(ok)["rejected"])       # no false positive on "run"
        for bad in ("softirq.frac.percpu|cpu:18|NET_RX|RATE|z", "softirq.frac.percpu|cpu|18|RATE|z",
                    "seed|host||MEAN|z", "sched.run_delay.target|cgroup||P99|z", "cpu.util.host|host||MEAN|decision",
                    "cpu.util.host|host||MEAN"):
            with self.subTest(bad):
                self.assertFalse(X.leakage_audit([bad])["ok"])
        Xm = X.design_matrix([{"k": (1.0, 2.0, 3.0)}, {}], ["k"])
        self.assertEqual(Xm.tolist(), [[1.0, 2.0, 3.0, 0.0], [0.0, 0.0, 0.0, 1.0]])   # neutral fill + indicator

    def test_ml_runs_are_train_only_and_exclude_acceptable_sets(self):
        runs, excluded = X.ml_runs(MATRIX)
        self.assertEqual({r["split"] for r in runs}, {"train"})
        self.assertNotIn("OV-7", {r["family"] for r in runs})
        self.assertEqual(len(excluded), 2)
        self.assertFalse({"SENS", "PI3"} & {r["family"] for r in runs})
        self.assertEqual(X.label_of(next(r for r in runs if r["family"] == "CTRL")), X.INS)

    def test_calibrated_params_keep_every_engine_value(self):
        rep = {"engine_parameters": {"numbers": {"COV_MIN": 0.9}, "reason_sets": {}}}
        from unittest import mock
        with mock.patch.object(X, "params"):
            out = X.calibrated_params(rep, 0.9)
        self.assertEqual(out["numbers"], {"COV_MIN": 0.9, X.TAU_DISAGREE: 0.9})
        with self.assertRaises(SystemExit):
            X.calibrated_params({"engine_parameters": {"numbers": {X.TAU_DISAGREE: 1.0}, "reason_sets": {}}}, 0.9)


class TestCli(unittest.TestCase):
    def test_stopped_calibration_never_writes_the_artefact(self):        # C7-16 stop rule
        import tempfile
        from unittest import mock
        stopped = ({}, {}, {"stopped": ["THR_RATIO_MIN = 0.0 <= 0"]})
        with mock.patch.object(X, "calibrate", return_value=stopped), \
                mock.patch.object(X.M6, "committed_matrix", return_value={}):
            with tempfile.TemporaryDirectory() as d:
                with mock.patch.object(X, "OUT", Path(d)):
                    with self.assertRaises(SystemExit):
                        X.main(["calibrate", "--out", d])
                    self.assertFalse((Path(d) / "calibration_report.json").exists())
                scratch = Path(d) / "scratch"
                self.assertEqual(X.main(["calibrate", "--out", str(scratch)]), 3)
                self.assertTrue(json.loads((scratch / "calibration_report.json").read_text())["stopped"])

    def test_add_only(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "calibration_report.json").write_text("{}")
            with self.assertRaises(SystemExit):
                X.main(["calibrate", "--out", d])


if __name__ == "__main__":
    unittest.main()
