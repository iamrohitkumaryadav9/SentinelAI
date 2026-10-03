"""R2-D tooling: the only new mutation is the target-leaf cpu.max with exact per-run values, written through one
read-before / read-after path on the approved schedule (Q_B before tick 0, Q_W in the window callback after tick NB,
MAX after tick NB+NW, MAX again before removal); GQ/GT/GD/GR and the M3A window semantics are exercised on fakes.
No test creates a cgroup, writes cpu.max on the host, starts a workload or changes affinity."""

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))          # tests/ (both invocation styles)
T = importlib.import_module("faultlab.test_r2c")                          # loads r2c_cpu and the R2-C fakes

C = T.C
ROOT = T.ROOT
_spec = importlib.util.spec_from_file_location("r2d_cpu", ROOT / "scripts" / "r2d_cpu.py")
Q = importlib.util.module_from_spec(_spec)
sys.modules["r2d_cpu"] = Q
_spec.loader.exec_module(Q)
DRIVER = (ROOT / "scripts" / "r2d_driver.py").read_text()
WRAPPER = (ROOT / "scripts" / "r2d_validate.sh").read_text()
MODULE = (ROOT / "scripts" / "r2d_cpu.py").read_text()
R2C_FILES = {p: (ROOT / p).read_bytes() for p in ("scripts/r2c_cpu.py", "scripts/r2c_driver.py", "scripts/r2c_target.py",
                                                  "scripts/r2c_validate.sh")}
OUT = str(Q.RESULTS / "T" / "T1-1")
E = Q.EXPERIMENTS
I_B0, I_W0, I_W1, N_OBS = T.I_B0, T.I_W0, T.I_W1, T.N_OBS


def code_lines(text):
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


# ------------------------------------------------------------------------------------------ A. allowlist
class TestAllowlist(unittest.TestCase):
    def test_exact_values_per_run(self):
        self.assertEqual(Q.QUOTA_PATH, "/sys/fs/cgroup/sentinel-r2c/target/cpu.max")
        self.assertEqual((Q.Q_B, Q.T1, Q.T2, Q.MAX), ("100000 100000", "15000 100000", "7500 100000", "max 100000"))
        self.assertEqual({k: Q.allowed_quota(e) for k, e in E.items()},
                         {"E0": set(), "Q0": {Q.Q_B, Q.MAX}, "C1": {Q.Q_B, Q.MAX}, "T1": {Q.Q_B, Q.T1, Q.MAX},
                          "T2": {Q.Q_B, Q.T2, Q.MAX}, "TC": {Q.Q_B, Q.T1, Q.MAX}})
        for k, e in E.items():
            for v in Q.allowed_quota(e):
                Q.check_op(("write", Q.QUOTA_PATH, v), e)

    def test_refusals(self):
        t1 = E["T1"]
        paths = [f"{C.LAB_DIR}/cpu.max", f"{C.CONTENDER_DIR}/cpu.max", f"{C.CG_ROOT}/cpu.max",
                 f"{C.CG_ROOT}/system.slice/cpu.max", f"{C.CG_ROOT}/user.slice/cpu.max", f"{C.CG_ROOT}/init.scope/cpu.max",
                 f"{C.TARGET_DIR}/../cpu.max", f"{C.TARGET_DIR}/./cpu.max", f"{C.TARGET_DIR}//cpu.max",
                 f"{C.CG_ROOT}/sentinel-r2c/target2/cpu.max", "/tmp/cpu.max", Q.QUOTA_PATH + " ",
                 f"{C.CG_ROOT}/system.slice/sentinel-r2c/target/cpu.max"]
        for p in paths:
            with self.subTest(path=p), self.assertRaises(C.R2CRefused):
                Q.check_op(("write", p, Q.Q_B), t1)
        values = ["0 100000", "15000 0", "max 0", "-1 100000", "15000", "15000 100000 1", "abc 100000", "",
                  "20000 100000", Q.T2, "max 50000", "100000  100000", " 15000 100000", "15000 100000\n"]
        for v in values:
            with self.subTest(value=v), self.assertRaises(C.R2CRefused):
                Q.check_op(("write", Q.QUOTA_PATH, v), t1)
        for v in (Q.Q_B, Q.MAX):                                          # E0 writes nothing
            with self.assertRaises(C.R2CRefused):
                Q.check_op(("write", Q.QUOTA_PATH, v), E["E0"])
        with self.assertRaises(C.R2CRefused):
            Q.check_op(("write", Q.QUOTA_PATH, Q.T1), E["Q0"])
        with self.assertRaises(C.R2CRefused):
            Q.check_op(("write", Q.QUOTA_PATH, Q.Q_B, "x"), t1)

    def test_parse_quota(self):
        self.assertEqual(Q.parse_quota(Q.T1), (15000, 100000))
        self.assertEqual(Q.parse_quota(Q.MAX), (None, 100000))
        self.assertAlmostEqual(Q.cores(Q.T2), 0.075)
        for bad in ("0 100000", "1 0", "x 1", "1", "max"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                Q.parse_quota(bad)

    def test_r2c_ops_still_r2c_guarded_and_spawns_in_r2d_results(self):
        t1 = E["T1"]
        for op in C.setup_plan(t1):
            Q.check_op(op, t1)
        Q.check_op(("spawn", "target", C.target_argv(1000, OUT + "/target.json")), t1, 1000)
        Q.check_op(("spawn", "contender", C.contender_argv(OUT + "/c.cnt")), E["TC"], 1000)
        Q.check_op(("spawn", "calibration", C.calibration_argv(OUT + "/cal.json")), E["E0"])
        bad = [("spawn", "contender", C.contender_argv(OUT + "/c.cnt")),                       # no contender in T1
               ("spawn", "target", C.target_argv(1000, "/tmp/t.json")),                         # outside results
               ("spawn", "target", C.target_argv(1000, str(C.REPO / "results/phase1c_r2c/x/t.json"))),
               ("spawn", "target", C.target_argv(999, OUT + "/t.json")),
               ("spawn", "target", C.target_argv(1000, OUT + "/t.json")[4:]),                    # no wrapper
               ("write", f"{C.TARGET_DIR}/cpu.weight", "400"), ("write", f"{C.CG_ROOT}/cpuset.cpus", "0-23"),
               ("mkdir", f"{C.CG_ROOT}/system.slice/x"), ("exec", "sysctl")]
        for op in bad:
            with self.subTest(op=op[:2]), self.assertRaises(C.R2CRefused):
                Q.check_op(op, t1, 1000)

    def test_quota_never_through_apply(self):
        for host in (Q.Host(E["T1"], "/dev/null", 1000, T.FakeSys()), Q.SimHost(E["T1"])):
            with self.assertRaisesRegex(C.R2CRefused, "only through write_quota"):
                host.apply(("write", Q.QUOTA_PATH, Q.T1))


# ------------------------------------------------------------------------------------------ B. read-before / read-after
class FileSys:
    def __init__(self, value):
        self.value, self.writes = value, []

    def read(self, path):
        return None if self.value is None else self.value + "\n"

    def write(self, path, v):
        self.writes.append(v)
        self.value = v


class TestQuotaWrite(unittest.TestCase):
    def run_write(self, start, value, prev, exp=E["T1"], resolve=lambda p: p, sticky=False):
        fs, log = FileSys(start), []
        write = (lambda p, v: fs.writes.append(v)) if sticky else fs.write
        rec = Q.quota_write(exp, value, prev, fs.read, write, resolve, lambda **k: log.append(k), clock=iter(
            [1.0, 2.0]).__next__)
        return rec, fs, log

    def test_success(self):
        rec, fs, log = self.run_write(Q.MAX, Q.Q_B, Q.MAX)
        self.assertEqual((rec["prev"], rec["post"], rec["t0"], rec["t1"]), (Q.MAX, Q.Q_B, 1.0, 2.0))
        self.assertEqual([l["phase"] for l in log], ["intent", "result"])
        self.assertTrue(log[1]["ok"])

    def test_unexpected_previous_value_never_writes(self):
        for start in (Q.T1, "50000 100000", None, Q.Q_B):
            with self.subTest(start=start):
                fs, log = FileSys(start), []
                with self.assertRaises(Q.QuotaAbort):
                    Q.quota_write(E["T1"], Q.T1 if start == Q.Q_B else Q.Q_B, Q.MAX if start != Q.Q_B else Q.MAX,
                                  fs.read, fs.write, lambda p: p, lambda **k: log.append(k))
                self.assertEqual(fs.writes, [])
                self.assertEqual([l["phase"] for l in log], ["refused"])

    def test_readback_mismatch_aborts(self):
        with self.assertRaises(Q.QuotaAbort):
            self.run_write(Q.MAX, Q.Q_B, Q.MAX, sticky=True)                       # kernel kept the old value

    def test_symlink_or_substitution_refused(self):
        with self.assertRaisesRegex(C.R2CRefused, "resolve"):
            self.run_write(Q.MAX, Q.Q_B, Q.MAX, resolve=lambda p: "/sys/fs/cgroup/system.slice/cpu.max")

    def test_unapproved_value_refused_before_any_read(self):
        fs = FileSys(Q.MAX)
        fs.read = mock.Mock(side_effect=AssertionError("read before validation"))
        with self.assertRaises(C.R2CRefused):
            Q.quota_write(E["T2"], Q.T1, Q.Q_B, fs.read, fs.write, lambda p: p, lambda **k: None)

    def test_host_path_uses_realpath_and_logs(self):
        with tempfile.TemporaryDirectory() as d, mock.patch("os.path.realpath", lambda p: p):
            log = os.path.join(d, "ops.jsonl")
            fake = T.FakeSys({Q.QUOTA_PATH: Q.MAX})
            h = Q.Host(E["T1"], log, 1000, fake)
            with mock.patch.object(Q.Host, "_write", staticmethod(lambda p, v: fake.files.__setitem__(p, v))):
                rec = h.write_quota(Q.Q_B, Q.MAX)
            self.assertEqual(rec["post"], Q.Q_B)
            with open(log) as fh:
                ops = [json.loads(l) for l in fh]
            self.assertEqual([(o["phase"], o["op"][0]) for o in ops], [("intent", "quota"), ("result", "quota")])
        with mock.patch("os.path.realpath", lambda p: "/elsewhere"), self.assertRaises(C.R2CRefused):
            Q.Host(E["T1"], "/dev/null", 1000, T.FakeSys({Q.QUOTA_PATH: Q.MAX})).write_quota(Q.Q_B, Q.MAX)

    def test_restore(self):
        fs, log = FileSys(Q.T1), []
        r = Q.quota_restore(E["T1"], fs.read, fs.write, lambda p: p, lambda **k: log.append(k))
        self.assertTrue(r["ok"])
        self.assertEqual(fs.value, Q.MAX)
        fs = FileSys(Q.MAX)
        self.assertTrue(Q.quota_restore(E["T1"], fs.read, fs.write, lambda p: p, lambda **k: None)["noop"])
        self.assertEqual(fs.writes, [])
        fs = FileSys("33333 100000")                                       # not written by this run
        r = Q.quota_restore(E["T1"], fs.read, fs.write, lambda p: p, lambda **k: None)
        self.assertFalse(r["ok"])
        self.assertEqual(fs.value, Q.MAX)
        fs = FileSys(Q.Q_B)                                                # E0 may never write: restore impossible
        with self.assertRaises(C.R2CRefused):
            Q.quota_restore(E["E0"], fs.read, fs.write, lambda p: p, lambda **k: None)


# ------------------------------------------------------------------------------------------ C. timing (real collector loop)
def run_collect(clock_cls, exp=E["T1"]):
    """The real sentinelai collect() loop with a fake reader / eBPF source; events record the exact ordering."""
    import r2d_driver as DR
    from sentinelai.collectors import FixtureReader, SystemClock, collect
    from sentinelai.diagnostic.contract import Target
    events = []

    class Src:
        def __init__(self):
            self.k = 0

        def sample(self):
            events.append(("obs", self.k))
            self.k += 1
            return {}

    t = Target(name="r2d", cgroup_path=C.TARGET_CGROUP_PATH, pids=(100,), cpuset="18", netns_ref="pid:100", ifaces=())
    with mock.patch.object(SystemClock, "sleep_until", lambda self, mono: None):
        collect(t, DR.params(), FixtureReader({}), clock_cls(lambda: events.append(("write_QW",))), 1.0, Src())
    events.append(("restore_MAX",))
    return events


def order_ok(events):
    i = events.index
    return i(("obs", C.NB)) < i(("write_QW",)) < i(("obs", C.NB + 1)) and \
        i(("obs", C.NB + C.NW)) < i(("restore_MAX",)) and events.count(("write_QW",)) == 1


class TestTiming(unittest.TestCase):
    def test_window_callback_between_tick_nb_and_nb_plus_1(self):
        import r2d_driver as DR
        ev = run_collect(DR.WindowClock)
        self.assertTrue(order_ok(ev), ev)
        self.assertEqual(ev[C.NB + 1], ("write_QW",))

    def test_callback_moved_by_one_fails(self):
        import r2d_driver as DR
        from sentinelai.collectors import SystemClock
        for shift in (-1, +1):
            class Moved(DR.WindowClock):
                def sleep_until(self, mono, shift=shift):
                    if self.calls == C.NB + 1 + shift:
                        self.on_window()
                    self.calls += 1
                    SystemClock.sleep_until(self, mono)
            with self.subTest(shift=shift):
                self.assertFalse(order_ok(run_collect(Moved)))

    def test_gq_timestamps(self):
        w = TWorld(E["T1"])
        obs, _, _ = w.observations()
        ok = Q.evaluate_gq(obs, E["T1"], I_W0, I_W1, w.writes())
        self.assertTrue(ok["ok"], ok)
        cases = {
            "Q_W one callback early": dict(qw=(I_W0 - 0.99, I_W0 - 0.98)),
            "Q_W one callback late": dict(qw=(I_W0 + 1.01, I_W0 + 1.02)),
            "Q_W straddles obs NB+1": dict(qw=(I_W0 + 0.5, I_W0 + 1.5)),
            "MAX before last W obs": dict(mx=(I_W1 - 0.5, I_W1 - 0.49)),
            "MAX after first recovery obs": dict(mx=(I_W1 + 1.5, I_W1 + 1.6)),
            "Q_B after first observation": dict(qb=(0.5, 0.6)),
        }
        for name, kw in cases.items():
            with self.subTest(name):
                self.assertFalse(Q.evaluate_gq(obs, E["T1"], I_W0, I_W1, w.writes(**kw))["ok"])
        self.assertFalse(Q.evaluate_gq(obs, E["T1"], I_W0, I_W1, w.writes()[1:])["ok"])         # Q_B skipped
        self.assertFalse(Q.evaluate_gq(obs, E["T1"], I_W0, I_W1, w.writes()[:2])["ok"])         # restore skipped


# ------------------------------------------------------------------------------------------ fake lab world
class TWorld(T.LabWorld):
    """R2-C's lab world with the R2-D quota schedule and throttle counters (per-second rates, B / W)."""

    def __init__(self, exp, **over):
        thr = exp.kind in Q.THROTTLED
        on18 = exp.contender_cpu == 18
        tw = 150_000 if thr else 220_000
        rq_w = (1_000_000_000 if on18 else tw * 1000 + 20_000_000)
        rates = {"t.periods": (10, 10) if exp.quota_w else (0, 0), "t.throttled": (0, 10 if thr else 0),
                 "t.throttled_usec": (0, 400_000 if thr else 0), "t.usage": (220_000, tw),
                 "c.usage": (0, (980_000 - tw) if on18 else 0), "cpu18.rq": (240_000_000, rq_w)}
        rates.update(over)
        super().__init__(exp, **rates)
        self.cslot = {}                                     # obs index -> target cpu.max override

    def files(self, k):
        f = super().files(k)
        f[f"{C.TARGET_DIR}/cpu.max"] = self.cslot.get(k, Q.expected_quota(self.exp, k, I_W0, I_W1)) + "\n"
        for d in (C.LAB_DIR, C.CONTENDER_DIR):
            f[f"{d}/cpu.max"] = self.cpu_max + "\n"
        return f

    def writes(self, qb=(-0.5, -0.49), qw=(I_W0 + 0.01, I_W0 + 0.02), mx=(I_W1 + 0.01, I_W1 + 0.02)):
        out = []
        for (moment, v, p), (t0, t1) in zip(Q.schedule(self.exp), [qb] + ([qw] if self.exp.quota_w not in (None, Q.Q_B)
                                                                         else []) + [mx]):
            out.append({"value": v, "prev": p, "post": v, "t0": t0, "t1": t1, "moment": moment})
        return out

    def target_out(self, late_b=10_000, late_w=400_000):
        return super().target_out(late_b, late_w)


def evaluate(w, writes=None, target_out=None):
    obs, expected, in_w = w.observations()
    G = Q.evaluate(obs, I_B0, I_W0, I_W1, w.exp, expected, in_w,
                   target_out if target_out is not None else w.target_out(), T.HZ,
                   w.writes() if writes is None else writes)
    return G, Q.ground_truth_aborts(G, w.exp) + C.host_level_aborts(obs, I_B0, I_W0, I_W1), obs


# ------------------------------------------------------------------------------------------ D-G. ground truth
class TestGroundTruth(unittest.TestCase):
    def test_every_run_type_as_designed(self):
        for k, exp in E.items():
            with self.subTest(k):
                G, aborts, _ = evaluate(TWorld(exp))
                self.assertEqual(aborts, [], G)
                self.assertTrue(G["GQ"]["ok"] and G["GT"]["ok"] and G["GD"]["ok"] and G["G6"]["ok"])
                if k in Q.THROTTLED:
                    self.assertTrue(G["throttling_established"])
                    self.assertIsNone(G["throttling_absent_confirmed"])
                    self.assertAlmostEqual(G["GT"]["ratio_w"], 1.0)
                    self.assertAlmostEqual(G["GT"]["time_rate_w"], 0.4)
                    self.assertGreater(G["GD"]["usage_b_cores"], G["GD"]["quota_w_cores"])
                else:
                    self.assertTrue(G["throttling_absent_confirmed"])
                self.assertEqual(G["G3"]["applies"], k in Q.CONTENDED)
                if k in Q.CONTENDED:
                    self.assertTrue(G["contention_present"])
                self.assertAlmostEqual(G["G6"]["foreign_cores_w"], 0.02)

    def test_gq_index_exact(self):
        t1 = E["T1"]
        self.assertEqual([Q.expected_quota(t1, k, I_W0, I_W1) for k in (0, I_W0, I_W0 + 1, I_W1, I_W1 + 1)],
                         [Q.Q_B, Q.Q_B, Q.T1, Q.T1, Q.MAX])
        self.assertEqual({Q.expected_quota(E["E0"], k, I_W0, I_W1) for k in range(N_OBS)}, {Q.MAX})
        cases = {
            "Q_W already at obs NB": {I_W0: Q.T1}, "Q_B still at obs NB+1": {I_W0 + 1: Q.Q_B},
            "MAX before the last W obs": {I_W1: Q.MAX}, "quota still in recovery": {I_W1 + 1: Q.T1},
            "unapproved value": {15: "20000 100000"}, "max during B": {5: Q.MAX},
        }
        for name, slot in cases.items():
            with self.subTest(name):
                w = TWorld(t1)
                w.cslot = slot
                G, aborts, _ = evaluate(w)
                self.assertFalse(G["GQ"]["ok"])
                self.assertTrue(any("(GQ)" in a for a in aborts))
        w = TWorld(t1)
        w.cpu_max = Q.T1                                                       # parent / contender with a quota
        self.assertFalse(evaluate(w)[0]["GQ"]["ok"])

    def test_gt(self):
        cases = {
            "throttling in B": (E["T1"], {"t.throttled": (1, 10)}),
            "throttled time in B": (E["T1"], {"t.throttled_usec": (5, 400_000)}),
            "no throttling in T1 W": (E["T1"], {"t.throttled": (0, 0), "t.throttled_usec": (0, 0)}),
            "no throttled time in T2 W": (E["T2"], {"t.throttled_usec": (0, 0)}),
            "throttling in Q0 W": (E["Q0"], {"t.throttled": (0, 3), "t.throttled_usec": (0, 9_000)}),
            "throttling in C1 W": (E["C1"], {"t.throttled": (0, 1)}),
            "throttling in E0 W": (E["E0"], {"t.throttled_usec": (0, 1)}),
            "missing B period accounting": (E["T1"], {"t.periods": (0, 10)}),
        }
        for name, (exp, rates) in cases.items():
            with self.subTest(name):
                G, aborts, _ = evaluate(TWorld(exp, **rates))
                self.assertFalse(G["GT"]["ok"], G["GT"])
                self.assertTrue(any("(GT)" in a for a in aborts), aborts)
        w = TWorld(E["T1"])
        w.overrides[I_W0 - 3] = {f"{C.TARGET_DIR}/cpu.stat": "usage_usec 1\n"}   # counters unreadable mid-B
        G, aborts, _ = evaluate(w)
        self.assertIsNone(G["GT"]["ok"])
        self.assertTrue(any("ground truth unavailable" in a for a in aborts))

    def test_gd_strict(self):
        G, _, _ = evaluate(TWorld(E["T1"], **{"t.usage": (150_000, 150_000), "cpu18.rq": (170_000_000, 170_000_000)}))
        self.assertFalse(G["GD"]["ok"])                                         # demand == quota: not above
        G, _, _ = evaluate(TWorld(E["T2"], **{"t.usage": (220_000, 220_000), "cpu18.rq": (240_000_000, 240_000_000)}))
        self.assertFalse(G["GD"]["ok"])                                         # W usage not below B
        G, aborts, _ = evaluate(TWorld(E["T1"], **{"t.usage": (140_000, 100_000), "cpu18.rq": (160_000_000,
                                                                                               120_000_000)}))
        self.assertFalse(G["GD"]["ok"])
        self.assertTrue(any("(GD)" in a for a in aborts))
        self.assertFalse(Q.evaluate_gd([], E["Q0"], 0, 0, 0)["applies"])

    def test_g2_g3_g6(self):
        cases = {
            "contender present in T1": TWorld(E["T1"], **{"c.usage": (0, 300_000)}),
            "contender too weak in TC": TWorld(E["TC"], **{"c.usage": (0, 100_000), "cpu18.rq": (240_000_000,
                                                                                                  270_000_000)}),
            "CPU 18 idle in TC": TWorld(E["TC"], **{"cpu18.rq": (240_000_000, 900_000_000), "c.usage": (0, 730_000)}),
            "foreign busy time in T2": TWorld(E["T2"], **{"cpu18.rq": (240_000_000, 300_000_000)}),
            "foreign busy time in B": TWorld(E["Q0"], **{"cpu18.rq": (400_000_000, 240_000_000)}),
        }
        for name, w in cases.items():
            with self.subTest(name):
                _, aborts, _ = evaluate(w)
                self.assertTrue(aborts, name)

    def test_g7_and_host_conditions_still_abort(self):
        for name, w in {"memory PSI": TWorld(E["T1"], **{"mem.psi": (0, 1)}),
                        "swap": TWorld(E["T1"], swap=(0, 26)),
                        "net": TWorld(E["T1"], net=(0, 64)), "slice PSI": TWorld(E["T1"], slice=(0, 10_500))}.items():
            with self.subTest(name):
                self.assertTrue(evaluate(w)[1])

    def test_immediate_checks(self):
        w = TWorld(E["T1"])
        obs, _, _ = w.observations()
        for k, t in enumerate(obs):
            self.assertEqual(Q.immediate_aborts(t, Q.expected_quota(E["T1"], k, I_W0, I_W1)), [], k)
        self.assertTrue(Q.immediate_aborts(obs[I_W0], Q.T1))                   # scheduled value disagrees
        t = dict(obs[3], leaves={**obs[3]["leaves"], "parent": {**obs[3]["leaves"]["parent"], "cpu_max": Q.Q_B}})
        self.assertTrue(Q.immediate_aborts(t, Q.Q_B))


# ------------------------------------------------------------------------------------------ H/I. M3A window semantics
def r2d_snapshot(gauge, rates, window_rates, usage_w=None):
    """The real M3A collector + normaliser on a fixture host; gauge(k) -> target cpu.max text at tick k."""
    from collectors._world import CG as WCG, T0, World
    from sentinelai.collectors import build_snapshot
    from sentinelai.collectors.ebpf import EBPF_COLLECTOR_VERSION, KFREE_SLOTS, EbpfTarget, Meta, Sample, bucket_index, \
        sample_obs
    from sentinelai.collectors.normalize import Tick
    from sentinelai.collectors.probes import sample
    from sentinelai.diagnostic.contract import Target
    import r2d_driver as DR

    class W(World):
        def c(self, key, k, cpu=None):
            if key == "cg.usage_usec" and usage_w is not None:      # per-interval W usage (us per 1 s interval)
                return 1_000_000 + sum(self.rates[key] for j in range(1, min(k, C.NB) + 1)) + \
                    sum(usage_w[j - C.NB - 1] for j in range(C.NB + 1, k + 1))
            return super().c(key, k, cpu)

        def files(self, k):
            f = {p.replace(WCG, C.TARGET_DIR): v for p, v in super().files(k).items()}
            f[f"{C.TARGET_DIR}/cpu.max"] = gauge(k) + "\n"
            return f

    w = W(cpus=(18, 23))
    w.gauges["task.processor"] = 18
    w.rates.update({"Tcp.OutSegs": 0, "Tcp.RetransSegs": 0, "TcpExt.TCPTimeouts": 0, "TcpExt.TCPFastRetrans": 0})
    w.rates.update(rates)
    w.window_rates.update(window_rates)
    t = Target(name="r2d", cgroup_path=C.TARGET_CGROUP_PATH, pids=(100,), cpuset="18", netns_ref="pid:100", ifaces=())
    meta = Meta(producer="sentinel_loader", version=EBPF_COLLECTOR_VERSION, libbpf="1.4", ncpu=24,
                target=EbpfTarget(1, 2, 3), lat_stale_ns=1, sirq_stale_ns=1,
                reasons=tuple(f"R{i}" for i in range(KFREE_SLOTS)) + ("UNKNOWN_OVERFLOW",))
    ticks = []
    for k in range(C.NB + C.NW + 1):
        obs = sample(w.reader(k), t)
        obs.update(sample_obs(meta, Sample(seq=k + 1, mono_ns=k + 1,
                                           hist={bucket_index(10_000): 100 * k, bucket_index(60_000): 2 * k},
                                           softirq={(18, v): (1000 * k, k) for v in range(10)}, retrans=0, kfree={},
                                           stats={})))
        ticks.append(Tick(k, float(k), T0 + timedelta(seconds=k), obs))
    return build_snapshot(ticks, t, DR.params(), 1.0, ebpf=True)


THR_RATES = {"cg.nr_periods": 10, "cg.nr_throttled": 0, "cg.throttled_usec": 0, "cg.usage_usec": 220_000}
THR_W = {"cg.nr_throttled": 10, "cg.throttled_usec": 400_000, "cg.usage_usec": 150_000}


def meas(snap, f):
    return [m for m in snap.measurements if m.feature_id == f and m.scope == f"cgroup:{C.TARGET_CGROUP_PATH}"]


class TestM3AWindowSemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snap = r2d_snapshot(lambda k: Q.T1 if k > C.NB else Q.Q_B, THR_RATES, THR_W)

    def test_two_quota_schedule_keeps_ct_inputs_valid(self):
        (ql,) = meas(self.snap, "throttle.quota_limited")
        self.assertEqual((ql.quality.value, ql.value), ("OK", 1.0))                    # not INVALID
        (tr,) = meas(self.snap, "throttle.ratio")
        self.assertTrue(tr.baseline.adequate)
        self.assertEqual(tr.baseline.median, 0.0)                                       # defined ratio in B
        self.assertAlmostEqual(tr.value, 1.0)
        (tt,) = meas(self.snap, "throttle.time_rate")
        self.assertEqual(tt.baseline.median, 0.0)
        self.assertAlmostEqual(tt.value, 0.4)
        (qc,) = meas(self.snap, "throttle.quota_cores")
        self.assertAlmostEqual(qc.value, 0.15)                                          # 'last' gauge
        (sat,) = meas(self.snap, "throttle.quota_saturation")
        (use,) = meas(self.snap, "cpu.usage.target")
        q_mean = (1.0 + (C.NW - 1) * 0.15) / C.NW                                        # tick NB gauge = Q_B
        self.assertAlmostEqual(sat.value, use.value / q_mean)
        self.assertAlmostEqual(sat.value, Q.predicted_saturation(use.value, E["T1"]))
        self.assertTrue(Q.metric_gate(self.snap, E["T1"], 0.8, 5.0)["ok"], Q.metric_gate(self.snap, E["T1"], 0.8, 5.0))

    def test_m2_ct_clauses_and_no_contention(self):
        import r2d_driver as DR
        from sentinelai.diagnostic.rules import diagnose
        d = diagnose(self.snap, DR.params(), code_commit="7354f40")
        rec = Q.m2_record(d)
        self.assertEqual((rec["clauses"]["CT.R1"], rec["clauses"]["CT.R2"]), ("POSITIVE", "POSITIVE"))
        self.assertEqual(rec["clauses"]["CC.X1"], "POSITIVE")
        self.assertNotEqual(rec["clauses"]["CC.R2"], "POSITIVE")
        self.assertEqual(d.result.decision.value, "cpu_throttling")                     # synthetic fixture only

    def test_e0_and_q0_shapes(self):
        e0 = r2d_snapshot(lambda k: Q.MAX, {**THR_RATES, "cg.nr_periods": 0}, {})
        self.assertTrue(Q.metric_gate(e0, E["E0"], 0.8, 5.0)["ok"], Q.metric_gate(e0, E["E0"], 0.8, 5.0))
        self.assertEqual(meas(e0, "throttle.quota_limited")[0].value, 0.0)
        q0 = r2d_snapshot(lambda k: Q.Q_B, THR_RATES, {})
        g = Q.metric_gate(q0, E["Q0"], 0.8, 5.0)
        self.assertTrue(g["ok"], g)
        self.assertEqual(meas(q0, "throttle.ratio")[0].value, 0.0)

    def test_counterexamples(self):
        cases = {
            "MAX -> Q_W at W (no Q_B)": (lambda k: Q.T1 if k > C.NB else Q.MAX, {**THR_RATES, "cg.nr_periods": 0},
                                        {**THR_W, "cg.nr_periods": 10}, ("throttle.quota_limited", "throttle.ratio")),
            "MAX restored mid-W": (lambda k: Q.MAX if k > C.NB + 5 else (Q.T1 if k > C.NB else Q.Q_B), THR_RATES, THR_W,
                                   ("throttle.quota_limited",)),
            "no quota in B and W ratio undefined": (lambda k: Q.MAX, {**THR_RATES, "cg.nr_periods": 0}, {},
                                                    ("throttle.quota_limited",)),
        }
        for name, (gauge, rates, wrates, broken) in cases.items():
            with self.subTest(name):
                s = r2d_snapshot(gauge, rates, wrates)
                g = Q.metric_gate(s, E["T1"], 0.8, 5.0)
                self.assertFalse(g["ok"])
                for f in broken:
                    self.assertTrue(any(f in a for a in g["aborts"]), (f, g["aborts"]))
        s = r2d_snapshot(lambda k: Q.T1 if k > C.NB + 5 else (Q.T1 if k > C.NB else Q.Q_B), THR_RATES, THR_W)
        self.assertTrue(Q.metric_gate(s, E["T1"], 0.8, 5.0)["ok"])
        # Q_W already in force at tick NB (too early). The mandatory detector is GQ (TestGroundTruth: "Q_W already at
        # obs NB" aborts). The supporting metric adds a check only when it is complete:
        early = r2d_snapshot(lambda k: Q.T1 if k >= C.NB else Q.Q_B, THR_RATES, THR_W)   # usage == quota exactly
        g = Q.metric_gate(early, E["T1"], 0.8, 5.0)
        self.assertEqual(g["supporting"]["throttle.quota_saturation"]["quality"], "INVALID")   # window value > 1
        self.assertTrue(g["ok"], g["aborts"])                                          # incomplete: recorded only
        early = r2d_snapshot(lambda k: Q.T1 if k >= C.NB else Q.Q_B, THR_RATES, {**THR_W, "cg.usage_usec": 140_000})
        g = Q.metric_gate(early, E["T1"], 0.8, 5.0)
        self.assertFalse(g["ok"])                                                      # complete and contradicting
        self.assertTrue(any("contradicts the predicted" in a for a in g["aborts"]))

    def test_invalid_quota_limited_rejected(self):
        from sentinelai.diagnostic.contract import Quality
        ms = [m.model_copy(update={"quality": Quality.INVALID, "value": None}) if m.feature_id ==
              "throttle.quota_limited" else m for m in self.snap.measurements]
        g = Q.metric_gate(SimpleNamespace(measurements=ms, target=self.snap.target,
                                          data_quality=self.snap.data_quality), E["T1"], 0.8, 5.0)
        self.assertFalse(g["ok"])


# ------------------------------------------------------------------------------------------ gate revision (approved)
T1_1_USAGE_W = [150_250, 149_820, 150_260, 150_230, 150_090, 149_820, 149_880, 149_970, 149_520, 150_330]


def edit(snap, feature, aggregation=None, drop=False, **update):
    ms = []
    for m in snap.measurements:
        hit = m.feature_id == feature and (aggregation is None or m.aggregation.value == aggregation)
        if hit and drop:
            continue
        ms.append(m.model_copy(update=update) if hit else m)
    return SimpleNamespace(measurements=ms, target=snap.target, data_quality=snap.data_quality,
                           missing_measurements=snap.missing_measurements)


class TestGateRevision(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t1 = r2d_snapshot(lambda k: Q.T1 if k > C.NB else Q.Q_B, THR_RATES, THR_W)
        cls.e0 = r2d_snapshot(lambda k: Q.MAX, {**THR_RATES, "cg.nr_periods": 0}, {})

    def gate(self, s, exp="T1"):
        return Q.metric_gate(s, E[exp], 0.8, 5.0)

    def test_membership_is_exact(self):
        cg = "cg"
        self.assertEqual(Q.REQUIRED_KEYS, frozenset({
            ("sched.run_delay_excess.target", cg, "RATE"), ("cpu.util.cpuset", "cpuset", "MEAN"),
            ("cpu.steal.cpuset", "cpuset", "MEAN"), ("sched.latency_hist.target", cg, "P50"),
            ("sched.latency_hist.target", cg, "P99"), ("throttle.time_rate", cg, "RATE"),
            ("throttle.quota_limited", cg, "GAUGE"), ("throttle.ratio", cg, "RATIO"),
            ("softirq.frac.percpu", "cpu:18", "RATIO")}))
        self.assertEqual(Q.SUPPORTING, frozenset({("throttle.quota_saturation", cg, "RATIO"),
                                                 ("throttle.quota_cores", cg, "GAUGE")}))
        self.assertFalse(Q.REQUIRED_KEYS & Q.SUPPORTING)
        self.assertIsInstance(Q.SUPPORTING, frozenset)
        self.assertIsInstance(Q.REQUIRED, tuple)
        self.assertEqual({r[3] for r in Q.REQUIRED if r[0] in ("throttle.quota_limited", "throttle.ratio")},
                         {"quota_state", "ratio_state"})
        self.assertEqual(Q.SAT_REL_TOL, 1e-9)

    def test_A_supporting_valid_and_matching(self):
        g = self.gate(self.t1)
        self.assertTrue(g["ok"], g["aborts"])
        rec = g["supporting"]["throttle.quota_saturation"]
        self.assertEqual((rec["quality"], rec["coverage"], rec["consistent"]), ("OK", 1.0, True))
        self.assertAlmostEqual(rec["value"], rec["predicted"])
        self.assertAlmostEqual(g["supporting"]["throttle.quota_cores"]["value"], 0.15)

    def test_B_C_supporting_missing_or_invalid_continue_and_required_still_enforced(self):
        from sentinelai.diagnostic.contract import Quality
        for q in (Quality.MISSING, Quality.INVALID, Quality.STALE):
            with self.subTest(quality=q.value):
                s = edit(self.t1, "throttle.quota_saturation", quality=q, value=None)
                g = self.gate(s)
                self.assertTrue(g["ok"], g["aborts"])
                self.assertEqual(g["supporting"]["throttle.quota_saturation"]["quality"], q.value)
                for f, sc, agg, _ in Q.REQUIRED:                         # each required metric still enforced
                    with self.subTest(quality=q.value, required=(f, agg)):
                        self.assertFalse(self.gate(edit(s, f, agg, drop=True))["ok"])

    def test_D_E_each_required_metric_aborts(self):
        from sentinelai.diagnostic.contract import Quality
        for f, sc, agg, rule in Q.REQUIRED:
            for name, kw in (("absent", dict(drop=True)), ("MISSING", dict(quality=Quality.MISSING, value=None)),
                             ("INVALID", dict(quality=Quality.INVALID, value=None)), ("STALE", dict(quality=Quality.STALE))):
                with self.subTest(metric=(f, agg), state=name):
                    g = self.gate(edit(self.t1, f, agg, **kw))
                    self.assertFalse(g["ok"])
                    self.assertTrue(any(f in a for a in g["aborts"]), g["aborts"])
            if rule in ("usable_baseline", "ratio_state"):
                with self.subTest(metric=(f, agg), state="baseline inadequate"):
                    m = [x for x in self.t1.measurements if x.feature_id == f and x.aggregation.value == agg][0]
                    g = self.gate(edit(self.t1, f, agg, baseline=m.baseline.model_copy(update={"adequate": False})))
                    self.assertFalse(g["ok"])
        g = self.gate(edit(self.e0, "throttle.ratio", quality=Quality.INVALID, value=None), "E0")
        self.assertFalse(g["ok"])                                         # E0 ratio must be MISSING by design
        g = self.gate(edit(self.t1, "throttle.quota_limited", value=0.0))
        self.assertFalse(g["ok"])

    def test_H_t1_1_reproduction_through_real_m3a(self):
        import r2d_driver as DR
        from sentinelai.diagnostic.rules import diagnose
        s = r2d_snapshot(lambda k: Q.T1 if k > C.NB else Q.Q_B, THR_RATES, THR_W, usage_w=T1_1_USAGE_W)
        (sat,) = meas(s, "throttle.quota_saturation")
        self.assertEqual((sat.quality.value, sat.coverage, sat.value), ("MISSING", 0.6, None))   # 4 intervals > 1
        self.assertEqual([m.reason for m in s.missing_measurements if m.feature_id == "throttle.quota_saturation"],
                         ["coverage 0.600 below COV_MIN"])
        g = self.gate(s)
        self.assertTrue(g["ok"], g["aborts"])
        self.assertEqual(g["supporting"]["throttle.quota_saturation"]["reason"], "coverage 0.600 below COV_MIN")
        rec = Q.m2_record(diagnose(s, DR.params(), code_commit="7354f40"))
        self.assertEqual((rec["clauses"]["CT.R1"], rec["clauses"]["CT.R2"]), ("POSITIVE", "POSITIVE"))

    def test_partial_supporting_continues_without_comparison(self):
        usage = [150_000, 149_900, 150_200, 149_900, 149_900, 149_900, 149_900, 149_900, 149_900, 149_900]
        s = r2d_snapshot(lambda k: Q.T1 if k > C.NB else Q.Q_B, THR_RATES, THR_W, usage_w=usage)
        (sat,) = meas(s, "throttle.quota_saturation")
        self.assertEqual((sat.quality.value, sat.coverage), ("PARTIAL", 0.9))
        g = self.gate(s)
        self.assertTrue(g["ok"], g["aborts"])
        self.assertIsNone(g["supporting"]["throttle.quota_saturation"]["consistent"])

    def test_complete_but_contradicting_aborts(self):
        g = self.gate(edit(self.t1, "throttle.quota_saturation", value=0.99))
        self.assertFalse(g["ok"])
        self.assertTrue(any("contradicts the predicted" in a for a in g["aborts"]))
        g = self.gate(edit(self.t1, "cpu.usage.target", drop=True))           # prediction impossible: fail closed
        self.assertFalse(g["ok"])

    def test_quota_state_contradictions_abort(self):
        sat = [m for m in self.t1.measurements if m.feature_id == "throttle.quota_saturation"]
        e0 = SimpleNamespace(measurements=list(self.e0.measurements) + sat, target=self.e0.target,
                             data_quality=self.e0.data_quality, missing_measurements=())
        g = self.gate(e0, "E0")
        self.assertFalse(g["ok"])
        self.assertTrue(any("emitted without a quota" in a for a in g["aborts"]))
        self.assertTrue(self.gate(self.e0, "E0")["ok"])
        g = self.gate(edit(self.t1, "throttle.quota_saturation", drop=True))
        self.assertFalse(g["ok"])                                         # quota in force but never emitted

    def test_supporting_record_persisted(self):
        g = self.gate(self.t1)
        self.assertEqual(set(g["supporting"]), {"throttle.quota_saturation", "throttle.quota_cores"})
        for rec in g["supporting"].values():
            self.assertTrue({"present", "quality", "coverage", "value", "reason", "consistent"} <= set(rec))
        code = "\n".join(code_lines(DRIVER))
        self.assertIn('R["metric_gate"] = Q.metric_gate(snap, exp, NUMBERS["COV_MIN"], NUMBERS["N_BASE_MIN"])', code)
        self.assertLess(code.index('R["metric_gate"] = Q.metric_gate('), code.index("save()\nd = diagnose("))
        self.assertIn('json.dumps(R, indent=1, sort_keys=True, default=str)', code)

    def test_historical_t1_1_stays_abort(self):
        run = Q.RESULTS / "20261003T184854Z" / "T1-1" / "run.json"
        if not run.exists():
            self.skipTest("historical R2-D evidence not present")
        r = json.loads(run.read_text())
        self.assertEqual(r["verdict"], "ABORT")
        self.assertEqual(r["aborts"], ["throttle.quota_saturation [None] != predicted 0.640144575395321"])


# ------------------------------------------------------------------------------------------ PR-3 / provenance
class TestPR3AndProvenance(unittest.TestCase):
    def test_pr3_consistency_record(self):
        sys.path.insert(0, str(ROOT / "tests"))
        from rules._fixtures import contention, run, scenario, throttling
        for parts, expect in (((contention(0.1), throttling(time_rate=0.5)), "cpu_throttling"),
                              ((contention(0.9), throttling(time_rate=0.1)), "cpu_contention"),
                              ((contention(0.3), throttling(time_rate=0.4)), "CONFLICT")):
            with self.subTest(expect=expect):
                rec = Q.m2_record(run(scenario(*parts)))
                self.assertTrue(rec["both_assertable"])
                self.assertEqual(rec["pr3"]["expected"], expect)
                self.assertTrue(rec["pr3"]["consistent"])
        self.assertFalse(Q.m2_record(run(scenario(throttling())))["both_assertable"])

    def test_snapshot_round_trip_and_m2_determinism(self):
        import r2d_driver as DR
        from sentinelai.diagnostic.contract import EvidenceSnapshot
        from sentinelai.diagnostic.contract.serialize import canonical_bytes
        from sentinelai.diagnostic.rules import diagnose
        s = r2d_snapshot(lambda k: Q.T2 if k > C.NB else Q.Q_B, THR_RATES, {**THR_W, "cg.usage_usec": 75_000})
        raw = canonical_bytes(s)
        again = EvidenceSnapshot.model_validate_json(raw, strict=False)
        self.assertEqual(canonical_bytes(again), raw)
        a, b = diagnose(s, DR.params(), code_commit="7354f40"), diagnose(again, DR.params(), code_commit="7354f40")
        self.assertEqual(canonical_bytes(a.result), canonical_bytes(b.result))


# ------------------------------------------------------------------------------------------ G/J. restoration & cleanup
class TestRestorationAndCleanup(unittest.TestCase):
    def test_every_failure_point_restores_before_kill(self):
        for k, exp in E.items():
            n = len(C.setup_plan(exp)) + 1 + len(Q.schedule(exp)) + (1 if exp.contender_cpu is not None else 0)
            for f in [None] + list(range(1, n + 1)):
                with self.subTest(exp=k, fail_at=f):
                    r = Q.simulate(exp, f)
                    self.assertTrue(r["cleanup_ok"] and r["host_clean"] and r["restore_before_kill"], r)
            for s in range(len(Q.schedule(exp))):                                      # driver crash mid-schedule
                with self.subTest(exp=k, crash_after_writes=s):
                    r = Q.simulate(exp, stop_after=s)
                    self.assertTrue(r["cleanup_ok"] and r["host_clean"] and r["restore_before_kill"], r)
                    if s:
                        self.assertTrue(r["quota_restore"]["attempted"])

    def sim_with_quota(self, exp, fail_quota=None):
        sim = Q.SimHost(exp)
        entries = []
        for op in C.setup_plan(exp):
            entries.append({"phase": "intent", "op": list(op[:2])})
            sim.apply(op)
        entries.append({"phase": "intent", "op": ["quota", Q.QUOTA_PATH]})
        sim.write_quota(Q.Q_B, Q.MAX)
        sim.write_quota(exp.quota_w, Q.Q_B)
        sim.fail_quota = fail_quota
        return sim, entries

    def test_failed_restoration_is_nogo(self):
        for mode in ("write", "readback"):
            with self.subTest(mode):
                sim, entries = self.sim_with_quota(E["T1"], mode)
                r = Q.cleanup(sim, sim, entries, wait_s=0.0, sleep=lambda s: None)
                self.assertFalse(r["ok"])
                self.assertFalse(r["quota_restore"]["ok"])

    def test_restore_precedes_kill_and_rmdir(self):
        sim, entries = self.sim_with_quota(E["T2"])
        r = Q.cleanup(sim, sim, entries, wait_s=0.0, sleep=lambda s: None)
        self.assertTrue(r["ok"], r)
        ev = sim.events
        self.assertLess(ev.index(("quota", Q.MAX)), ev.index("cgroup.kill"))
        self.assertLess(ev.index(("quota", Q.MAX)), ev.index("rmdir"))
        self.assertEqual(r["quota_restore"]["post"], Q.MAX)

    def test_foreign_quota_found_in_cleanup_is_reported(self):
        sim, entries = self.sim_with_quota(E["T1"])
        sim.files[Q.QUOTA_PATH] = "33333 100000"
        r = Q.cleanup(sim, sim, entries, wait_s=0.0, sleep=lambda s: None)
        self.assertFalse(r["ok"])
        self.assertTrue(any("anomaly" in e for e in r["errors"]))

    def test_e0_never_writes_and_unexpected_quota_is_nogo(self):
        sim = Q.SimHost(E["E0"])
        entries = []
        for op in C.setup_plan(E["E0"]):
            sim.apply(op)
            entries.append({"phase": "intent", "op": list(op[:2])})
        self.assertTrue(Q.cleanup(sim, sim, entries, wait_s=0.0, sleep=lambda s: None)["ok"])
        sim = Q.SimHost(E["E0"])
        for op in C.setup_plan(E["E0"]):
            sim.apply(op)
        sim.files[Q.QUOTA_PATH] = Q.Q_B                                              # nobody may have set this
        self.assertFalse(Q.cleanup(sim, sim, [{"phase": "intent", "op": ["mkdir", C.LAB_DIR]}],
                                   wait_s=0.0, sleep=lambda s: None)["ok"])

    def test_host_cpu_max_hash_comparison(self):
        base = C.host_snapshot(T.snapshot_sys())
        r = C.compare_host(base, C.host_snapshot(T.snapshot_sys(files={f"{C.CG_ROOT}/system.slice/cpu.max":
                                                                       "15000 100000"})))
        self.assertFalse(r["ok"])
        self.assertIn("cgroup_attrs_identical", r["failed"])
        self.assertTrue(C.compare_host(base, C.host_snapshot(T.snapshot_sys()))["ok"])


# ------------------------------------------------------------------------------------------ matrix / static safety
class TestMatrixAndStatic(unittest.TestCase):
    def test_matrix(self):
        self.assertEqual(Q.MATRIX, ("E0-open", "Q0-1", "Q0-2", "C1-1", "C1-2", "T1-1", "T1-2", "T1-3", "T2-1", "T2-2",
                                    "T2-3", "TC-1", "TC-2", "TC-3", "E0-close"))
        self.assertIn("MATRIX=(" + " ".join(Q.MATRIX) + ")", WRAPPER)
        self.assertEqual({k: (e.contender_cpu, e.contender_weight, e.quota_w) for k, e in E.items()},
                         {"E0": (None, 100, None), "Q0": (None, 100, Q.Q_B), "C1": (18, 100, Q.Q_B),
                          "T1": (None, 100, Q.T1), "T2": (None, 100, Q.T2), "TC": (18, 100, Q.T1)})
        self.assertEqual(Q.schedule(E["T1"]), [("before_tick0", Q.Q_B, Q.MAX), ("window_callback", Q.T1, Q.Q_B),
                                              ("after_last_w_tick", Q.MAX, Q.T1)])
        self.assertEqual(Q.schedule(E["C1"]), [("before_tick0", Q.Q_B, Q.MAX), ("after_last_w_tick", Q.MAX, Q.Q_B)])
        self.assertEqual(Q.schedule(E["E0"]), [])

    def test_r2c_untouched_and_thresholds(self):
        for p, b in R2C_FILES.items():
            self.assertEqual((ROOT / p).read_bytes(), b, p)
        self.assertEqual((C.G2_CONTENDER_MIN_CORES, C.G3_IDLE_MAX, C.G6_FOREIGN_MAX_CORES), (0.4, 0.05, 0.05))

    def test_module_single_write_sites(self):
        code = "\n".join(code_lines(MODULE))
        self.assertEqual(len(re.findall(r"open\([^)]*\"w\"", code)), 1)              # Host._write only
        self.assertNotRegex(code, r"os\.(mkdir|rmdir|kill)\(|subprocess\.|shell\s*=\s*True")
        self.assertIn("check_op((\"write\", QUOTA_PATH, value), exp)", code)

    def test_host_apply_validates_before_executing(self):
        calls = []
        with mock.patch.object(C.Host, "_do", lambda self, op, so, se: calls.append(op)):
            h = Q.Host(E["T1"], "/dev/null", 1000, T.FakeSys())
            for op in (("write", f"{C.CG_ROOT}/system.slice/cpu.weight", "1"), ("mkdir", f"{C.CG_ROOT}/x"),
                       ("spawn", "target", C.target_argv(1000, "/tmp/t.json")), ("kill", 1)):
                with self.subTest(op=op[:2]), self.assertRaises(C.R2CRefused):
                    h.apply(op)
            self.assertEqual(calls, [])
            h.apply(("mkdir", C.LAB_DIR))
            self.assertEqual(calls, [("mkdir", C.LAB_DIR)])

    def test_set_quota_uses_value_in_force(self):
        import r2d_driver as DR
        seen = []
        host = SimpleNamespace(write_quota=lambda v, prev: seen.append((v, prev)) or {"t0": 1, "t1": 2})
        run, writes = SimpleNamespace(quota_now=Q.MAX), []
        for moment, v, prev in Q.schedule(E["T1"]):
            DR.set_quota(host, run, writes, v, lambda *a, **k: None, moment)
        self.assertEqual(seen, [(v, prev) for _, v, prev in Q.schedule(E["T1"])])
        self.assertEqual(run.quota_now, Q.MAX)
        self.assertEqual([w["moment"] for w in writes], ["before_tick0", "window_callback", "after_last_w_tick"])

    def test_wrapper_recovery_restores_through_r2d_cleanup(self):
        code = "\n".join(code_lines(MODULE))
        branch = code[code.index('if cmd == "cleanup":'):code.index('if cmd == "candidate":')]
        self.assertIn('res[str(log)] = cleanup(Host(exp, str(log) + ".cleanup"), C.Sys(), C.read_oplog(log))', branch)
        self.assertIn("exp = experiment_of(label) if label in MATRIX else EXPERIMENTS[\"E0\"]", branch)
        self.assertNotIn("C.cleanup(", branch)

    def test_driver_order(self):
        code = "\n".join(code_lines(DRIVER))
        self.assertNotRegex(code, r"subprocess\.|os\.system|open\([^)]*cpu\.max|\.write_text\([^)]*cgroup")
        self.assertEqual(re.findall(r"set_quota\(host, run, writes, sched\[\"(\w+)\"\]", code),
                         ["before_tick0", "window_callback", "after_last_w_tick"])
        i = code.index
        self.assertTrue(i('set_quota(host, run, writes, sched["before_tick0"]') < i("loader = Recording(") <
                        i('run.observe("warmup")') < i("collect(target, params()"))
        cb = code[i("def on_window():"):i("i_b0 = len(run.obs)")]
        self.assertLess(cb.index("window_callback"), cb.index("run.spawn(\"contender\""))
        self.assertTrue(i('ev("collect_end")') < i('sched["after_last_w_tick"]') < i('host.apply(("kill", contender'))
        fin = code.rindex("finally:")
        self.assertTrue(fin < i("loader.close()", fin) < i("R[\"cleanup\"] = Q.cleanup(host, sysr", fin) <
                        i("C.wait_bpf_released(sysr, base)", fin) < i("after = C.host_snapshot(sysr)", fin) <
                        i("C.compare_host(base, after)", fin))
        self.assertIn("signal.signal(s, signal.SIG_IGN)", code[fin:])
        self.assertIn("Q.immediate_aborts(t, self.quota_now)", code)
        self.assertIn("if self.calls == Q.NB + 1:", code)
        self.assertIn('refuse("--execute not given', code)

    def test_wrapper(self):
        code = "\n".join(code_lines(WRAPPER))
        self.assertIn("trap finish EXIT", code)
        self.assertIn("trap 'finish; exit 130' INT TERM", code)
        self.assertIn('"$PY" "$R2D" cleanup "$OUT"', code)
        self.assertIn("OUT=$REPO/results/phase1c_r2d/$TS", code)
        self.assertEqual(len(re.findall(r"taskset -c 0-15 timeout 180 \"\$PY\" \"\$DRIVER\"", code)), 2)
        for pat in (r"cpu\.max", r"\bsysctl\b", r"/sys/fs/cgroup", r"\bstress", r"enp0s31f6", r"docker0", r"\btc\b",
                    r"\bip (link|addr|route)", r"smp_affinity"):
            self.assertIsNone(re.search(pat, code), pat)

    @unittest.skipUnless(os.path.exists("/sys/devices/system/cpu/cpu23"), "needs the R2-C host topology")
    def test_dry_run_mutates_nothing(self):
        import builtins
        real_open = builtins.open

        def ro_open(path, mode="r", *a, **kw):
            if any(c in mode for c in "wax+"):
                raise AssertionError(f"dry-run opened {path} for writing")
            return real_open(path, mode, *a, **kw)

        def forbidden(*a, **kw):
            raise AssertionError(f"dry-run mutation: {a}")
        with mock.patch("builtins.open", ro_open), mock.patch.object(Q, "Host", forbidden), \
                mock.patch.object(C, "Host", forbidden), mock.patch("os.mkdir", forbidden), \
                mock.patch("os.rmdir", forbidden), mock.patch("os.kill", forbidden):
            rep = Q.dry_run(C.Sys())
        self.assertTrue(rep["structural_ok"], {k: v for k, v in rep.items() if k != "schedules"})
        self.assertTrue(rep["zero_mutation"]["ok"])


if __name__ == "__main__":
    unittest.main()
