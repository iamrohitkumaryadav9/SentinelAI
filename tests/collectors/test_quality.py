"""Data-quality semantics (contract §10.3, §10.8): absence, invalidity, staleness and counter resets are
never turned into numbers, and never into normal-looking values."""

import unittest

from sentinelai.collectors import Bad, Status
from sentinelai.diagnostic.contract import Quality as Q

from ._world import CG, DENIED, NB, NW, W_TICKS, World, build, meas

CGS, NS, IF = "cgroup:/lab/A", "netns:lab", "iface:lab/eth0"
SNMP = "/proc/100/net/snmp"


def missing_reason(snap, feature, scope):
    return [x.reason for x in snap.missing_measurements if x.feature_id == feature and x.scope == scope]


class TestCounterReset(unittest.TestCase):
    def test_reset_interval_excluded_never_zero(self):
        w = World()
        for k in range(15, NB + NW + 1):   # a real reset: the counter restarts from 0 and keeps counting
            w.overrides[(SNMP, k)] = w.files(k)[SNMP].replace(str(w.c("Tcp.OutSegs", k)), str((k - 15) * 1000))
        s = build(w)
        m = meas(s, "tcp.out_segs_rate", NS)
        self.assertIs(m.quality, Q.PARTIAL)                 # only the interval across the reset is invalid
        self.assertAlmostEqual(m.coverage, 0.9)
        self.assertEqual(m.value, 1000.0)                   # the valid intervals' true rate, not diluted, not 0
        self.assertEqual(s.data_quality.counter_resets, 1)

    def test_resets_everywhere_make_the_measurement_invalid(self):
        w = World()
        w.rates["Tcp.OutSegs"] = 1000
        w.window_rates["Tcp.OutSegs"] = -1                  # decreasing during the whole window
        s = build(w)
        m = meas(s, "tcp.out_segs_rate", NS)
        self.assertIs(m.quality, Q.INVALID)
        self.assertIsNone(m.value)
        self.assertIs(meas(s, "tcp.retrans_frac", NS).quality, Q.INVALID)
        self.assertEqual(s.data_quality.counter_resets, NW)   # distinct (counter, interval) resets; OutSegs feeds
                                                              # two features but is counted once per interval

    def test_negative_thread_counter_is_a_reset(self):
        w = World()
        w.window_rates["task.run_delay"] = -10
        s = build(w)
        self.assertIs(meas(s, "sched.run_delay.target", CGS).quality, Q.INVALID)
        self.assertIs(meas(s, "sched.run_delay_excess.target", CGS).quality, Q.INVALID)


class TestMissingIsNotZero(unittest.TestCase):
    def test_absent_file_whole_window(self):
        s = build(World().override(SNMP, range(NB, NB + NW + 1), None))
        for f in ("tcp.out_segs_rate", "tcp.retrans_rate", "tcp.retrans_frac"):
            m = meas(s, f, NS)
            with self.subTest(f):
                self.assertIs(m.quality, Q.MISSING)
                self.assertIsNone(m.value)
                self.assertEqual(m.coverage, 0.0)
                self.assertTrue(missing_reason(s, f, NS))

    def test_absent_drop_counter_is_missing(self):
        w = World().override("/sys/class/net/eth0/statistics/rx_missed_errors", range(NB, NB + NW + 1), None)
        m = meas(build(w), "net.drop.iface_rx", IF)
        self.assertIs(m.quality, Q.MISSING)
        self.assertIsNone(m.value)

    def test_permission_denied(self):
        w = World().override(f"{CG}/memory.stat", range(0, NB + NW + 1), DENIED)
        s = build(w)
        m = meas(s, "mem.reclaim.target", CGS)
        self.assertIs(m.quality, Q.MISSING)
        self.assertIsNone(m.baseline)
        self.assertTrue(missing_reason(s, "mem.reclaim.target", CGS)[0].startswith("denied"))

    def test_one_missing_sample_is_partial(self):
        s = build(World().override(SNMP, [15], None))
        m = meas(s, "tcp.out_segs_rate", NS)
        self.assertIs(m.quality, Q.PARTIAL)
        self.assertAlmostEqual(m.coverage, 0.8)

    def test_coverage_below_cov_min_is_missing(self):
        s = build(World().override(SNMP, [12, 14, 16], None))      # 6 of 10 intervals lost
        m = meas(s, "tcp.out_segs_rate", NS)
        self.assertIs(m.quality, Q.MISSING)
        self.assertIsNone(m.value)
        self.assertIn("below COV_MIN", missing_reason(s, "tcp.out_segs_rate", NS)[0])

    def test_unverifiable_netns_makes_iface_features_missing(self):
        w = World()
        r = w.reader
        def reader(k):
            x = r(k)
            x.links["/proc/100/ns/net"] = DENIED
            return x
        w.reader = reader
        s = build(w)
        for f in ("net.drop.iface_rx", "net.pkts.iface", "net.bytes.iface"):
            m = meas(s, f, IF)
            with self.subTest(f):
                self.assertIs(m.quality, Q.MISSING)
                self.assertIn("unverified", missing_reason(s, f, IF)[0])
        self.assertIs(meas(s, "tcp.out_segs_rate", NS).quality, Q.OK)   # /proc/<pid>/net is the target netns

    def test_different_netns_is_never_attributed(self):
        w = World()
        r = w.reader
        def reader(k):
            x = r(k)
            x.links["/proc/100/ns/net"] = "net:[4026532999]"
            return x
        w.reader = reader
        self.assertIs(meas(build(w), "net.drop.iface_rx", IF).quality, Q.MISSING)


class TestMalformed(unittest.TestCase):
    def test_malformed_whole_window_is_invalid(self):
        s = build(World().override(SNMP, range(NB, NB + NW + 1), "Tcp: garbage\n"))
        m = meas(s, "tcp.out_segs_rate", NS)
        self.assertIs(m.quality, Q.INVALID)
        self.assertIsNone(m.value)

    def test_malformed_single_sample_partial(self):
        s = build(World().override("/proc/stat", [15], "cpu  x\n"))
        m = meas(s, "cpu.util.percpu", "cpu:0")
        self.assertIs(m.quality, Q.PARTIAL)
        self.assertEqual(m.value, 0.75)


class TestStale(unittest.TestCase):
    def test_gauge_source_stops_updating(self):
        s = build(World().override(f"{CG}/memory.current", range(NB, NB + NW + 1), None))
        m = meas(s, "mem.util.target", CGS)
        self.assertIs(m.quality, Q.STALE)            # last value is from before the window
        self.assertEqual(m.value, 0.25)
        self.assertGreater((m.window.end - m.provenance.last_sample_at).total_seconds(), m.window.duration_s)


class TestUndefinedRatios(unittest.TestCase):
    def test_denominator_did_not_advance(self):
        w = World()
        w.window_rates["Tcp.OutSegs"] = 0
        w.window_rates["Tcp.RetransSegs"] = 0
        s = build(w)
        m = meas(s, "tcp.retrans_frac", NS)
        self.assertIs(m.quality, Q.MISSING)                  # 0/0 is not 0
        self.assertIsNone(m.value)
        self.assertEqual(meas(s, "tcp.out_segs_rate", NS).value, 0.0)   # the rate itself is a real 0

    def test_unlimited_quota_has_no_periods(self):
        w = World()
        w.gauges["cg.cpu.max"] = "max 100000"
        w.rates["cg.nr_periods"] = 0
        s = build(w)
        self.assertIs(meas(s, "throttle.ratio", CGS).quality, Q.MISSING)


class TestQuotaStates(unittest.TestCase):
    def test_finite_quota(self):
        s = build(World())
        self.assertEqual(meas(s, "throttle.quota_limited", CGS).value, 1.0)
        self.assertEqual(meas(s, "throttle.quota_cores", CGS).value, 0.5)

    def test_unlimited_quota_is_a_real_zero_and_no_quota_cores(self):
        w = World()
        w.gauges["cg.cpu.max"] = "max 100000"
        s = build(w)
        m = meas(s, "throttle.quota_limited", CGS)
        self.assertEqual((m.quality, m.value), (Q.OK, 0.0))
        self.assertFalse([x for x in s.measurements if x.feature_id in ("throttle.quota_cores",
                                                                         "throttle.quota_saturation")])
        self.assertFalse([x for x in s.missing_measurements if x.feature_id == "throttle.quota_cores"])

    def test_missing_cpu_max_is_missing_not_unlimited(self):
        s = build(World().override(f"{CG}/cpu.max", range(0, NB + NW + 1), None))
        m = meas(s, "throttle.quota_limited", CGS)
        self.assertIs(m.quality, Q.MISSING)
        self.assertIsNone(m.value)
        self.assertIs(meas(s, "throttle.quota_cores", CGS).quality, Q.MISSING)

    def test_unreadable_and_malformed_cpu_max(self):
        for value, expect in ((DENIED, Q.MISSING), ("banana\n", Q.INVALID)):
            with self.subTest(value=value):
                s = build(World().override(f"{CG}/cpu.max", range(0, NB + NW + 1), value))
                self.assertIs(meas(s, "throttle.quota_limited", CGS).quality, expect)

    def test_quota_change_within_window_is_invalid(self):
        w = World()
        for k in range(15, NB + NW + 1):
            w.overrides[(f"{CG}/cpu.max", k)] = "max 100000\n"
        self.assertIs(meas(build(w), "throttle.quota_limited", CGS).quality, Q.INVALID)


class TestTopology(unittest.TestCase):
    def test_cpu_disappears(self):
        w = World()
        w.cpu_ticks[1] = set(range(14, NB + NW + 1))
        s = build(w)
        m = meas(s, "cpu.util.percpu", "cpu:1")
        self.assertIs(m.quality, Q.MISSING)          # 3 of 10 intervals valid
        self.assertIs(meas(s, "cpu.util.cpuset", "cpuset").quality, Q.MISSING)   # cpuset needs all its CPUs
        self.assertIs(meas(s, "cpu.util.percpu", "cpu:0").quality, Q.OK)

    def test_cpu_appears_late(self):
        w = World(cpus=(0, 1, 2))
        w.cpu_ticks[2] = set(range(0, 12))
        s = build(w)
        m = meas(s, "cpu.util.percpu", "cpu:2")
        self.assertIs(m.quality, Q.PARTIAL)
        self.assertIsNone(m.baseline)                # no baseline samples: never a fabricated baseline
        self.assertIsNone(m.deviation)

    def test_thread_churn(self):
        w = World(tids=(100, 101))
        tids = {k: ["100", "101"] if k < 15 else ["100", "102"] for k in range(NB + NW + 1)}
        r = w.reader
        def reader(k):
            x = r(k)
            x.dirs["/proc/100/task"] = tids[k]
            x.files.update({f"/proc/100/task/102/{n}": x.files[f"/proc/100/task/101/{n}"] for n in
                            ("schedstat", "sched", "status", "stat")})
            return x
        w.reader = reader
        m = meas(build(w), "sched.run_delay.target", CGS)
        self.assertIs(m.quality, Q.OK)               # a new or exited thread is neither a reset nor a gap
        # 9 intervals with both threads (0.1) + the churn interval with only tid 100 in common (0.05);
        # a thread that appears is never counted from zero
        self.assertAlmostEqual(m.value, (9 * 0.1 + 0.05) / 10)


class TestOutOfRange(unittest.TestCase):
    def test_impossible_fraction_in_window_is_invalid_never_clamped(self):
        w = World()
        w.window_rates["psi.cpu"] = 1_500_000          # 1.5 s of stall per 1 s: impossible
        m = meas(build(w), "psi.cpu.some.host", "host")
        self.assertIs(m.quality, Q.INVALID)
        self.assertIsNone(m.value)

    def test_impossible_baseline_samples_are_excluded(self):
        w = World()
        w.rates["psi.cpu"] = 1_500_000
        w.window_rates["psi.cpu"] = 10_000
        m = meas(build(w), "psi.cpu.some.host", "host")
        self.assertIs(m.quality, Q.OK)
        self.assertIsNone(m.baseline)                 # no valid baseline sample, never a clamped one


class TestBaseline(unittest.TestCase):
    def test_within_run_baseline(self):
        w = World()
        w.window_rates["Tcp.RetransSegs"] = 100
        s = build(w)
        m = meas(s, "tcp.retrans_frac", NS)
        self.assertEqual(m.value, 0.1)
        self.assertEqual((m.baseline.median, m.baseline.mad, m.baseline.n, m.baseline.adequate), (0.01, 0.0, NB, True))
        self.assertEqual(m.baseline.window, s.baseline_window)
        self.assertAlmostEqual(m.deviation.ratio, 10.0)
        self.assertAlmostEqual(m.deviation.robust_z, (0.1 - 0.01) / 1e-3)

    def test_inadequate_baseline(self):
        s = build(World().override(SNMP, range(1, 7), None))     # 4 of 10 baseline intervals remain
        m = meas(s, "tcp.out_segs_rate", NS)
        self.assertIs(m.quality, Q.OK)
        self.assertFalse(m.baseline.adequate)


if __name__ == "__main__":
    unittest.main()
