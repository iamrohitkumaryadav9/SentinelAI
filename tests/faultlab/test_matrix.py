"""Tests of the M6 matrix generator (experiments/faultlab/matrix.py; FZ-M6-PLAN; AMD-29)."""
import collections
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("faultlab_matrix", ROOT / "experiments" / "faultlab" / "matrix.py")
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)
REC = M.load()


class TestMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = M.generate(REC)
        cls.runs = cls.m["runs"]

    def test_deterministic_and_seed_dependent_order(self):
        self.assertEqual(M.dump(M.generate(REC)), M.dump(self.m))
        other = M.generate(REC, master_seed=M.MASTER_SEED + 1)
        self.assertEqual(other["counts"], self.m["counts"])
        self.assertNotEqual([r["family"] for r in other["runs"]], [r["family"] for r in self.runs])

    def test_counts_follow_the_approved_plan(self):
        c = self.m["counts"]
        self.assertEqual(c["total"], 202)                         # 196 (FZ-M6-PLAN) + 6 PI-3 (U-4)
        self.assertEqual(c["by_split"], {"pi3": 6, "sens": 12, "test": 106, "train": 78})
        self.assertEqual(set(c["test_by_class"].values()), {12})  # 10 required + 2 provisioned (Q-5)
        self.assertEqual(set(c["train_by_class"].values()), {8})
        self.assertEqual(c["by_family"]["CTRL"], 24)
        ctrl = collections.Counter(r["split"] for r in self.runs if r["family"] == "CTRL")
        self.assertEqual(ctrl, {"train": 10, "test": 14})          # FZ-Q5
        for fam in (f"OV-{k}" for k in range(1, 11)):
            self.assertEqual(collections.Counter(r["split"] for r in self.runs if r["family"] == fam),
                             {"train": 2, "test": 2}, fam)

    def test_split_rules(self):
        self.assertFalse([r for r in self.runs if r["split"] == "train" and r["intensity"] == "I2"])   # design §6.6
        self.assertTrue([r for r in self.runs if r["split"] == "test" and r["intensity"] == "I2"])
        self.assertFalse([f for r in self.runs for f in r["faults"] if f["type"] == "police_a_ingress"])  # P-8
        self.assertEqual(len({r["run_id"] for r in self.runs}), len(self.runs))
        self.assertTrue(all(100000 <= r["seed"] < 900000 and r["run_id"] == f"M6-s{r['seed']}" for r in self.runs))

    def test_levels_come_from_the_frozen_record(self):
        lv = REC["FZ-INTENSITY"]["value"]["levels"]
        mag = lambda fam, mech, it: sorted({f["magnitude"] for r in self.runs if r["family"] == fam and
                                            r["mechanism"] == mech and r["intensity"] == it for f in r["faults"]})
        self.assertEqual(mag("SF", "app_lock", "I2"), [lv["app_lock_hold_us"]["I2"]])
        self.assertEqual(mag("SF", "cpu_quota", "I3"), [lv["cpu_quota_us"]["I3"]])
        self.assertEqual(mag("SF", "memory_max", "single"), [768])                    # P-2
        self.assertEqual(mag("SF", "app_pool", "single"), [1])
        for mech, i0 in (("cpu_contender", 25), ("cpu_quota", 40000), ("netem_loss_a_egress", 0.25),
                         ("netem_rate_r", 1200), ("memory_max", 1536)):                # P-3: half the strength
            with self.subTest(mech):
                self.assertEqual(mag("SENS", mech, "I0"), [i0])
        self.assertIsInstance(mag("SENS", "netem_loss_a_egress", "I0")[0], float)

    def test_mechanisms_share_runs_and_intensities_evenly(self):
        app = collections.Counter((r["mechanism"], r["split"]) for r in self.runs
                                  if r["family"] == "SF" and r["class"] == "application_bottleneck")
        self.assertEqual({k: v for k, v in app.items() if k[1] == "test"},
                         {("app_dependency_delay", "test"): 4, ("app_lock", "test"): 4, ("app_pool", "test"): 4})
        rt = collections.Counter((r["mechanism"], r["intensity"]) for r in self.runs
                                 if r["family"] == "SF" and r["split"] == "test" and r["class"] == "tcp_retransmissions")
        self.assertEqual(set(rt.values()), {2})
        self.assertEqual(M.spread(["a", "b"], (("I1", "I3"), 2)), [("a", "I1"), ("b", "I3"), ("b", "I1"), ("a", "I3")])

    def test_overlap_families(self):
        by = {r["family"]: r for r in self.runs}
        self.assertEqual(by["OV-8"]["collectors"], {"ifaces": [], "ebpf": False, "app_metrics": True})
        self.assertFalse(by["OV-9"]["collectors"]["app_metrics"])
        self.assertEqual(by["OV-10"]["faults"], [])
        self.assertEqual(by["OV-10"]["distractor"]["kind"], "generic")
        self.assertEqual(by["OV-6"]["distractor"]["kind"], "slow_request")
        self.assertEqual(sorted(f["type"] for f in by["OV-7"]["faults"]), ["cpu_contender", "cpu_quota"])
        self.assertEqual(len(by["OV-7"]["expected"]["acceptable"]), 3)
        self.assertNotIn(18, by["OV-3"]["stress_cpus"])                                 # never the target CPU
        self.assertEqual(by["OV-1"]["bulk_flow_mbit"], 40)
        self.assertEqual(by["OV-2"]["expected"], {"primary": "network_packet_loss",
                                                  "contributing": ["tcp_retransmissions"]})
        for fam in ("OV-4", "OV-5", "OV-8", "OV-9", "OV-10"):
            self.assertEqual(by[fam]["expected"]["primary"], "INSUFFICIENT_EVIDENCE", fam)

    def test_batches(self):
        sizes = collections.Counter(r["batch"] for r in self.runs)
        self.assertEqual(sorted(sizes), [1, 2, 3, 4, 5, 6])
        self.assertLessEqual(max(sizes.values()), 34)
        self.assertEqual([r["family"] for r in self.runs[:6]], ["PI3"] * 6)                    # U-4
        self.assertEqual(sorted(r["intensity"] for r in self.runs[:6]), ["I1", "I1", "I2", "I2", "I3", "I3"])
        self.assertEqual([r["seed"] for r in self.runs], sorted(r["seed"] for r in self.runs))

    def test_check_refuses_broken_matrices(self):
        def broken(edit):
            m = copy.deepcopy(self.m)
            edit(m["runs"])
            with self.assertRaises(SystemExit):
                M.check(m)
        broken(lambda rs: next(r for r in rs if r["split"] == "train" and r["family"] == "SF").update(intensity="I2"))
        broken(lambda rs: rs[10]["faults"].append({"type": "police_a_ingress", "magnitude": 407}))
        broken(lambda rs: rs[11].update(seed=rs[12]["seed"]))
        broken(lambda rs: rs[11].update(seed=900123))
        broken(lambda rs: [rs.remove(r) for r in [r for r in rs if r["family"] == "SF" and r["split"] == "test"
                                                  and r["class"] == "cpu_contention"][:3]])
        broken(lambda rs: rs.insert(0, rs.pop(6)))                                             # PI-3 not first

    def test_unapproved_record_refused(self):
        rec = json.loads((ROOT / "docs/PHASE_1C_FREEZE1_DECISIONS.json").read_text())
        rec["decisions"]["FZ-M6-PLAN"]["status"] = "proposed"
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.json"
            p.write_text(json.dumps(rec))
            with self.assertRaises(SystemExit):
                M.load(p)

    def test_cli_is_add_only_and_checks_regeneration(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "m.json"
            self.assertEqual(M.main(["generate", "--out", str(out)]), 0)
            self.assertEqual(out.read_bytes(), M.dump(self.m))
            with self.assertRaises(SystemExit):
                M.main(["generate", "--out", str(out)])                                       # add-only
            self.assertEqual(M.main(["check", str(out)]), 0)
            out.write_bytes(out.read_bytes().replace(b'"OV-1"', b'"OV-X"', 1))
            self.assertEqual(M.main(["check", str(out)]), 1)


if __name__ == "__main__":
    unittest.main()
