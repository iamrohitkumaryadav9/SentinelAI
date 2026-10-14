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


class TestCli(unittest.TestCase):
    def test_add_only(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "calibration_report.json").write_text("{}")
            with self.assertRaises(SystemExit):
                X.main(["calibrate", "--out", d])


if __name__ == "__main__":
    unittest.main()
