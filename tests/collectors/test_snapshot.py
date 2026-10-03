"""Contract conformance, completeness and deterministic replay of collected snapshots."""

import random
import unittest
from datetime import timedelta

from sentinelai.collectors import (CollectorError, ManualClock, build_snapshot, collect, collect_snapshot,
                                   collected_features)
from sentinelai.collectors.features import NOT_COLLECTED
from sentinelai.diagnostic.contract import EvidenceSnapshot, Quality, load_contract, scope_kind
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.diagnostic.rules import ParameterSet, UncalibratedParameters

from ._world import NB, NW, PSID, T0, TARGET, World, build, params

REG = load_contract().registry


class TestContract(unittest.TestCase):
    def setUp(self):
        self.s = build()

    def test_round_trip_validates(self):
        again = EvidenceSnapshot.model_validate_json(canonical_bytes(self.s), strict=False)
        self.assertEqual(canonical_bytes(again), canonical_bytes(self.s))

    def test_every_measurement_registered_and_typed(self):
        for m in self.s.measurements:
            spec = REG.get(m.feature_id)
            with self.subTest(f=m.feature_id, scope=m.scope):
                self.assertIs(m.unit, spec.unit)
                self.assertIn(m.aggregation, spec.aggregations)
                self.assertIn(scope_kind(m.scope), spec.scope_kinds)
                self.assertIn(m.provenance.source, spec.sources)
                self.assertFalse(m.provenance.privileged)
                self.assertEqual(m.window, self.s.window)

    def test_every_available_feature_collected_or_explicitly_not(self):
        avail = {f.id for f in REG.features if f.availability in ("A", "A*")}
        self.assertLessEqual(avail, set(collected_features()) | set(NOT_COLLECTED))   # every A/A* feature accounted
        self.assertLessEqual(set(collected_features()), avail)                     # only A features collected
        self.assertEqual(avail - set(collected_features()), {"tcp.srtt_ms", "tcp.cwnd"})   # M3A-C1: qdisc collected
        self.assertFalse(set(collected_features()) & set(NOT_COLLECTED))
        listed = {(x.feature_id, x.scope) for x in self.s.missing_measurements}
        for f in NOT_COLLECTED:
            self.assertTrue(any(lf == f for lf, _ in listed), f)

    def test_collector_never_produces_evidence(self):
        self.assertEqual(self.s.evidence_items, ())
        self.assertEqual(self.s.conflicts, ())
        for m in self.s.measurements:                    # no labels, no verdicts in provenance either
            self.assertNotRegex(m.provenance.locator.lower(), r"incident|pressure detected|overload|loss detected")

    def test_derived_measurements_reference_their_inputs(self):
        ids = {m.measurement_id for m in self.s.measurements}
        derived = [m for m in self.s.measurements if m.provenance.derived_from]
        self.assertEqual({m.feature_id for m in derived},
                         {"sched.run_delay_excess.target", "throttle.quota_saturation", "softirq.relevant_cpu_max",
                          "softirq.imbalance"})
        for m in derived:
            self.assertLessEqual(set(m.provenance.derived_from), ids)

    def test_snapshot_metadata(self):
        self.assertEqual((self.s.schema_version, self.s.contract_version, self.s.parameter_set_id),
                         ("0.2.0", "0.5.0-draft", PSID))
        self.assertEqual(self.s.window.start, T0 + timedelta(seconds=NB))
        self.assertEqual(self.s.window.duration_s, float(NW))
        self.assertEqual(self.s.baseline_window.end, self.s.window.start)
        self.assertEqual(self.s.data_quality.privileged_sources_unavailable, ("EBPF",))
        self.assertNotIn("TC", self.s.data_quality.sources_unavailable)       # M3A-C1: qdisc collected
        self.assertIn("SS", self.s.data_quality.sources_unavailable)


class TestDeterminism(unittest.TestCase):
    def test_replay_byte_identical(self):
        a, b, c = (canonical_bytes(build()) for _ in range(3))
        self.assertEqual(a, b)
        self.assertEqual(b, c)

    def test_file_and_observation_order_irrelevant(self):
        ref = canonical_bytes(build())
        rng = random.Random(7)
        w = World()
        ticks = w.ticks()
        for t in ticks:
            items = list(t.obs.items())
            rng.shuffle(items)
            t.obs = dict(items)
        self.assertEqual(canonical_bytes(build_snapshot(ticks, TARGET, params())), ref)

    def test_collect_loop_with_manual_clock_matches(self):
        w = World()
        clock = ManualClock([(float(k), T0 + timedelta(seconds=k)) for k in range(NB + NW + 1)])

        class StepReader:
            def read(self, p): return w.reader(clock._i).read(p)
            def listdir(self, p): return w.reader(clock._i).listdir(p)
            def readlink(self, p): return w.reader(clock._i).readlink(p)
            def tc_qdisc(self, i): return w.reader(clock._i).tc_qdisc(i)

        snap, stats = collect_snapshot(TARGET, params(), StepReader(), clock)
        self.assertEqual(stats.ticks, NB + NW + 1)
        self.assertEqual(canonical_bytes(snap), canonical_bytes(build()))


class TestParameters(unittest.TestCase):
    def test_refuses_without_floors_before_sampling(self):
        p = params()
        gone = {"floor[tcp.retrans_frac]", "floor[mem.swap.target]", "COV_MIN"}
        nums = {k: v for k, v in p.numbers.items() if k not in gone}
        bad = ParameterSet(parameter_set_id=PSID, numbers=nums, reason_sets=dict(p.reason_sets))
        calls = []

        class Spy:
            def read(self, path): calls.append(path)
        with self.assertRaises(UncalibratedParameters) as cm:
            collect(TARGET, bad, Spy(), ManualClock([(0.0, T0)]))
        self.assertEqual(set(cm.exception.missing), gone)     # every missing parameter, reported together
        self.assertEqual(calls, [])                           # refused before any read

    def test_wrong_tick_count(self):
        with self.assertRaises(CollectorError):
            build_snapshot(World().ticks(n=5), TARGET, params())


if __name__ == "__main__":
    unittest.main()
