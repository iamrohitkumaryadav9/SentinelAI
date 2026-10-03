"""End to end: synthetic kernel events -> replay harness (kernel handler code) -> loader line protocol ->
collector observations -> M3A normalisation -> contract-validated EvidenceSnapshot."""

import math
import unittest

from collectors._world import NB, NW, PSID, T0, TARGET, World, params
from sentinelai.collectors import build_snapshot, collect_snapshot, ManualClock
from sentinelai.collectors.ebpf import (EBPF_FEATURES, FixtureEbpfSource, UnavailableEbpfSource, bucket_hi,
                                        bucket_index)
from sentinelai.collectors.errors import Status
from sentinelai.diagnostic.contract import (Aggregation, EvidenceSnapshot, Quality, SourceType, Unit, load_contract,
                                            measurement_id)
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.diagnostic.rules import diagnose

from ._replay import MS, NETNS, S, TGT, US, Script, ensure_built, lines

REG = load_contract().registry
CG, NS = f"cgroup:{TARGET.cgroup_path}", f"netns:{TARGET.name}"
N_TICKS = NB + NW + 1


def setUpModule():
    ensure_built()


def eparams(**over):
    return params(**{f"floor[{f}]": 1e-3 for f in EBPF_FEATURES}, **over)


def workload(lat_in_w=True, retrans_w=30, kfree_w=True, skip_latency=False):
    """Per tick k (interval k-1 -> k): known softirq time, retransmissions, drops and latencies."""
    sc = Script()
    for k in range(N_TICKS):
        base = k * S
        if k > 0:
            in_w = k > NB
            sc.cpu(0).at(base - 900 * MS).entry("NET_RX").at(base - 898 * MS).exit("NET_RX")        # 2 ms
            sc.at(base - 890 * MS).entry("TIMER").at(base - 889 * MS).exit("TIMER")                 # 1 ms
            sc.cpu(1).at(base - 880 * MS).entry("NET_TX").at(base - 880 * MS + 500 * US).exit("NET_TX")
            for _ in range(retrans_w if in_w else 3):
                sc.retrans(NETNS)
            for _ in range(5):
                sc.kfree(NETNS, "NOT_SPECIFIED")
            for _ in range(2):
                sc.kfree(NETNS, "QDISC_DROP")
            if in_w and kfree_w:
                sc.kfree(NETNS, "TCP_CSUM")
            if not skip_latency and (lat_in_w or not in_w):
                t = base - 800 * MS
                for j in range(100):                     # 98 x 10 us, 2 x 5 ms per interval
                    lat = 5 * MS if j < 2 else 10 * US
                    sc.cpu(0).at(t).wakeup(5000 + j, 1).at(t + lat).switch(0, 5000 + j)
                    t += 6 * MS
        sc.at(base).dump()
    return sc


def ebpf_ticks(sc, world=None, target=TARGET):
    src = FixtureEbpfSource(lines(sc, capacity=256), TGT)
    ticks = (world or World()).ticks(target)
    for t in ticks:
        t.obs.update(src.sample())
    return ticks


def snap(sc=None, ticks=None, **over):
    return build_snapshot(ticks or ebpf_ticks(sc or workload()), TARGET, eparams(**over), ebpf=True)


def find(s, feature, scope, qualifier=None, aggregation=None):
    out = [m for m in s.measurements if m.feature_id == feature and m.scope == scope
           and (qualifier is None or (m.qualifier and m.qualifier.value == qualifier))
           and (aggregation is None or m.aggregation is aggregation)]
    assert len(out) == 1, (feature, scope, qualifier, aggregation, len(out))
    return out[0]


class TestFeatureValues(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = snap()

    def test_softirq_exec_time_per_cpu_and_vector(self):
        for cpu, vec, cores in ((0, "NET_RX", 0.002), (0, "TIMER", 0.001), (1, "NET_TX", 0.0005),
                                (0, "NET_TX", 0.0), (1, "NET_RX", 0.0), (1, "HI", 0.0)):
            with self.subTest(cpu=cpu, vec=vec):
                m = find(self.s, "softirq.exec_time.percpu", f"cpu:{cpu}", vec)
                self.assertAlmostEqual(m.value, cores, places=12)
                self.assertEqual((m.unit, m.aggregation, m.quality), (Unit.cores, Aggregation.RATE, Quality.OK))
                self.assertEqual((m.qualifier.dimension, m.provenance.source), ("vector", SourceType.EBPF))
        cells = [m for m in self.s.measurements if m.feature_id == "softirq.exec_time.percpu"]
        self.assertEqual(len(cells), 2 * 10)                               # every CPU x vector, none merged

    def test_network_and_non_network_softirq_not_conflated(self):
        rx = find(self.s, "softirq.exec_time.percpu", "cpu:0", "NET_RX")
        timer = find(self.s, "softirq.exec_time.percpu", "cpu:0", "TIMER")
        self.assertNotEqual(rx.measurement_id, timer.measurement_id)
        self.assertNotAlmostEqual(rx.value, timer.value)

    def test_retransmitted_skb_rate(self):
        m = find(self.s, "tcp.retrans_skb_rate", NS)
        self.assertAlmostEqual(m.value, 30.0)
        self.assertEqual((m.unit, m.aggregation), (Unit.events_per_second, Aggregation.RATE))
        self.assertNotEqual(m.unit, Unit.segments_per_second)
        self.assertIn("not segments", m.provenance.locator)
        self.assertAlmostEqual(m.baseline.median, 3.0)
        # the /proc RetransSegs feature is a separate measurement with its own source and unit
        segs = find(self.s, "tcp.retrans_rate", NS)
        self.assertEqual((segs.provenance.source, segs.unit), (SourceType.PROC, Unit.segments_per_second))
        self.assertNotEqual(segs.measurement_id, m.measurement_id)

    def test_kfree_reasons_distinct(self):
        got = {m.qualifier.value: m for m in self.s.measurements if m.feature_id == "net.drop.kfree_skb"}
        self.assertEqual(set(got), {"NOT_SPECIFIED", "QDISC_DROP", "TCP_CSUM"})
        self.assertAlmostEqual(got["NOT_SPECIFIED"].value, 5.0)
        self.assertAlmostEqual(got["QDISC_DROP"].value, 2.0)
        self.assertAlmostEqual(got["TCP_CSUM"].value, 1.0)
        self.assertEqual(got["TCP_CSUM"].baseline.median, 0.0)               # absent in baseline: observed zero
        self.assertEqual(len({m.measurement_id for m in got.values()}), 3)
        for m in got.values():
            self.assertEqual((m.unit, m.qualifier.dimension), (Unit.packets_per_second, "reason"))

    def test_latency_p50_and_p99_coexist(self):
        p50 = find(self.s, "sched.latency_hist.target", CG, aggregation=Aggregation.P50)
        p99 = find(self.s, "sched.latency_hist.target", CG, aggregation=Aggregation.P99)
        self.assertNotEqual(p50.measurement_id, p99.measurement_id)
        self.assertEqual(p50.measurement_id, measurement_id("sched.latency_hist.target", CG, self.s.window,
                                                            aggregation=Aggregation.P50))
        # 1000 samples in W: 980 x 10 us, 20 x 5 ms. Nearest rank: P50 = 500th, P99 = 990th.
        self.assertEqual(p50.value, bucket_hi(bucket_index(10 * US)) / 1e6)
        self.assertEqual(p99.value, bucket_hi(bucket_index(5 * MS)) / 1e6)
        self.assertEqual((p50.unit, p99.unit), (Unit.ms, Unit.ms))
        for m in (p50, p99):
            self.assertTrue(m.provenance.privileged)
            self.assertEqual(m.provenance.collector_version, "m3b-1.0.0")

    def test_every_measurement_contract_valid(self):
        again = EvidenceSnapshot.model_validate_json(canonical_bytes(self.s), strict=False)
        self.assertEqual(canonical_bytes(again), canonical_bytes(self.s))
        for m in self.s.measurements:
            if m.provenance.source is SourceType.EBPF:
                spec = REG.get(m.feature_id)
                self.assertIn(m.feature_id, EBPF_FEATURES)
                self.assertIn(m.aggregation, spec.aggregations)
                self.assertIs(m.unit, spec.unit)
        self.assertEqual(self.s.data_quality.privileged_sources_unavailable, ())
        self.assertEqual(self.s.evidence_items, ())                         # the collector never diagnoses

    def test_m2_accepts_the_snapshot(self):
        from rules._fixtures import COMMIT
        from sentinelai.diagnostic.rules import ParameterSet
        from rules._fixtures import TEST_NUMBERS
        from sentinelai.diagnostic.rules.engine import DEV_FEATURES
        nums = dict(TEST_NUMBERS, W=float(NW), B=float(NB), N_BASE_MIN=5.0)
        nums.update({f"floor[{f}]": 1e-3 for f in DEV_FEATURES})
        p = ParameterSet(parameter_set_id=PSID, numbers=nums, reason_sets={"KFREE_REASONS_LOSS": ("QDISC_DROP",)})
        d = diagnose(self.s, p, code_commit=COMMIT)
        self.assertEqual(d.result.snapshot_id, self.s.snapshot_id)


class TestFailClosed(unittest.TestCase):
    def test_unavailable_loader_gives_missing_never_zero(self):
        ticks = World().ticks()
        src = UnavailableEbpfSource("BPF load failed (privileges or verifier)")
        for t in ticks:
            t.obs.update(src.sample())
        s = snap(ticks=ticks)
        ebpf = [m for m in s.measurements if m.provenance.source is SourceType.EBPF]
        self.assertTrue(ebpf)
        for m in ebpf:
            self.assertIs(m.quality, Quality.MISSING)
            self.assertIsNone(m.value)
        self.assertFalse([m for m in ebpf if m.feature_id == "net.drop.kfree_skb"])   # no reason is invented
        self.assertEqual(s.data_quality.privileged_sources_unavailable, ("EBPF",))
        self.assertIn("EBPF", s.data_quality.sources_unavailable)
        listed = {(x.feature_id, x.scope) for x in s.missing_measurements}
        self.assertIn(("sched.latency_hist.target", CG), listed)
        self.assertIn(("tcp.retrans_skb_rate", NS), listed)

    def test_no_latency_samples_in_window_is_missing_not_zero(self):
        s = snap(workload(lat_in_w=False))
        for agg in (Aggregation.P50, Aggregation.P99):
            m = find(s, "sched.latency_hist.target", CG, aggregation=agg)
            self.assertIs(m.quality, Quality.MISSING)
            self.assertIsNone(m.value)
            self.assertIsNotNone(m.baseline)                                 # the baseline did see samples

    def test_zero_retransmissions_observed_is_zero(self):
        m = find(snap(workload(retrans_w=0)), "tcp.retrans_skb_rate", NS)
        self.assertEqual((m.value, m.quality), (0.0, Quality.OK))           # attached and observed: a real zero

    def test_malformed_sample_makes_interval_partial(self):
        ls = lines(workload(), capacity=256)
        ls[NB + 3] = ls[NB + 3][:-5]                                         # tick NB+2: truncated JSON
        src = FixtureEbpfSource(ls, TGT)
        ticks = World().ticks()
        for t in ticks:
            t.obs.update(src.sample())
        s = snap(ticks=ticks)
        m = find(s, "tcp.retrans_skb_rate", NS)
        self.assertIs(m.quality, Quality.PARTIAL)
        self.assertAlmostEqual(m.coverage, 8 / 10)                          # intervals NB+2 and NB+3 lost

    def test_counter_decrease_is_invalid_interval(self):
        ls = lines(workload(), capacity=256)
        import json
        d = json.loads(ls[NB + 5])
        d["retrans"] = 0                                                     # cumulative counter went backwards
        ls[NB + 5] = json.dumps(d)
        src = FixtureEbpfSource(ls, TGT)
        ticks = World().ticks()
        for t in ticks:
            t.obs.update(src.sample())
        s = snap(ticks=ticks)
        m = find(s, "tcp.retrans_skb_rate", NS)
        self.assertIs(m.quality, Quality.PARTIAL)
        self.assertGreaterEqual(s.data_quality.counter_resets, 1)

    def test_histogram_bucket_decrease_is_invalid_interval(self):
        ls = lines(workload(), capacity=256)
        import json
        d = json.loads(ls[NB + 5])
        d["sched"]["hist"] = [[i, max(0, c - 10_000)] for i, c in d["sched"]["hist"]]   # cumulative buckets shrink
        ls[NB + 5] = json.dumps(d)
        src = FixtureEbpfSource(ls, TGT)
        ticks = World().ticks()
        for t in ticks:
            t.obs.update(src.sample())
        s = snap(ticks=ticks)
        m = find(s, "sched.latency_hist.target", CG, aggregation=Aggregation.P99)
        self.assertIs(m.quality, Quality.PARTIAL)
        self.assertGreaterEqual(s.data_quality.counter_resets, 1)

    def test_loader_for_another_target_is_unverified(self):
        from sentinelai.collectors.ebpf import EbpfTarget
        src = FixtureEbpfSource(lines(workload(), capacity=256), EbpfTarget(1, 1, NETNS))
        obs = src.sample()
        self.assertTrue(all(v.status is Status.UNVERIFIED for v in obs.values()))

    def test_no_drops_observed_emits_no_invented_reason(self):
        sc = Script()
        for k in range(N_TICKS):
            sc.at(k * S).dump()
        s = snap(sc)
        self.assertFalse([m for m in s.measurements if m.feature_id == "net.drop.kfree_skb"])
        self.assertEqual(find(s, "tcp.retrans_skb_rate", NS).value, 0.0)


class TestIntegration(unittest.TestCase):
    def test_latency_quantiles_merge_every_window_interval(self):
        """The window distribution is the sum of all W intervals: 10 outliers in W's first interval among 1000
        samples are below the P99 rank (ceil(0.99 * 1010) = 1000), so P99 is the common latency."""
        sc = Script()
        for k in range(N_TICKS):
            if k > NB:
                t = k * S - 900 * MS
                for j in range(110 if k == NB + 1 else 100):
                    lat = 5 * MS if j >= 100 else 10 * US
                    sc.cpu(0).at(t).wakeup(7000 + j, 1).at(t + lat).switch(0, 7000 + j)
                    t += 6 * MS
            sc.at(k * S).dump()
        s = snap(sc)
        self.assertEqual(find(s, "sched.latency_hist.target", CG, aggregation=Aggregation.P99).value,
                         bucket_hi(bucket_index(10 * US)) / 1e6)
        self.assertEqual(find(s, "sched.latency_hist.target", CG, aggregation=Aggregation.P50).value,
                         bucket_hi(bucket_index(10 * US)) / 1e6)

    def test_m3a_measurements_unchanged_by_ebpf(self):
        plain = build_snapshot(World().ticks(), TARGET, eparams())
        with_e = snap()
        a = {m.measurement_id: canonical_bytes(m) for m in plain.measurements}
        b = {m.measurement_id: canonical_bytes(m) for m in with_e.measurements if m.provenance.source is not SourceType.EBPF}
        self.assertEqual(a, b)
        self.assertEqual(plain.data_quality.privileged_sources_unavailable, ("EBPF",))
        listed = {x.feature_id for x in plain.missing_measurements}
        self.assertIn("sched.latency_hist.target", listed)                   # M3A path still reports it missing
        self.assertNotIn("sched.latency_hist.target", {x.feature_id for x in with_e.missing_measurements})

    def test_deterministic_replay(self):
        self.assertEqual(canonical_bytes(snap()), canonical_bytes(snap()))

    def test_collect_with_fixture_source(self):
        """collect() samples the eBPF source at the same ticks as every other source."""
        w = World()

        class Reader:
            k = 0

            def __getattr__(self, name):
                return getattr(w.reader(min(Reader.k, N_TICKS - 1)), name)

        clock_ticks = [(float(k), T0.replace(second=k)) for k in range(N_TICKS)]
        clock = ManualClock(clock_ticks)
        src = FixtureEbpfSource(lines(workload(), capacity=256), TGT)
        orig = src.sample

        def sample():
            out = orig()
            Reader.k += 1
            return out
        src.sample = sample
        s, _ = collect_snapshot(TARGET, eparams(), reader=Reader(), clock=clock, ebpf=src)
        self.assertAlmostEqual(find(s, "tcp.retrans_skb_rate", NS).value, 30.0)

    def test_check_parameters_requires_ebpf_floors(self):
        from sentinelai.diagnostic.rules import UncalibratedParameters
        with self.assertRaises(UncalibratedParameters):
            build_snapshot(ebpf_ticks(workload()), TARGET, params(), ebpf=True)


if __name__ == "__main__":
    unittest.main()
