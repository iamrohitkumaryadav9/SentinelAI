"""The four M3B measurements match the 0.5.0-draft contract exactly (M3B-C0 / M3B-C1 semantics)."""

import unittest

from collectors._world import TARGET
from sentinelai.collectors.ebpf import EBPF_FEATURES, VECTORS, ebpf_calcs
from sentinelai.diagnostic.contract import (Aggregation, ScopeKind, SourceType, Unit, load_contract, measurement_id,
                                            scope_kind)
from sentinelai.diagnostic.contract.version import CONTRACT_VERSION, SCHEMA_VERSION
from sentinelai.diagnostic.rules import RULES_VERSION

from collectors import _world

REG = load_contract().registry
EXPECTED = {
    "sched.latency_hist.target": (Unit.ms, {Aggregation.P50, Aggregation.P99}, ScopeKind.cgroup, None),
    "softirq.exec_time.percpu": (Unit.cores, {Aggregation.RATE}, ScopeKind.cpu, "vector"),
    "tcp.retrans_skb_rate": (Unit.events_per_second, {Aggregation.RATE}, ScopeKind.netns, None),
    "net.drop.kfree_skb": (Unit.packets_per_second, {Aggregation.RATE}, ScopeKind.netns, "reason"),
}


class TestContractMapping(unittest.TestCase):
    def test_versions(self):
        self.assertEqual((CONTRACT_VERSION, SCHEMA_VERSION, RULES_VERSION), ("0.5.0-draft", "0.2.0", "m2-1.1.0"))

    def test_registry_definitions(self):
        self.assertEqual(set(EBPF_FEATURES), set(EXPECTED))
        for f, (unit, aggs, scope, dim) in EXPECTED.items():
            spec = REG.get(f)
            with self.subTest(f=f):
                self.assertEqual((spec.unit, set(spec.aggregations), spec.scope_kinds, spec.sources, spec.privileged),
                                 (unit, aggs, (scope,), (SourceType.EBPF,), True))
                self.assertEqual(None if spec.dimension is None else spec.dimension.name, dim)

    def test_calcs_cover_every_registered_aggregation_scope_and_qualifier(self):
        calcs = ebpf_calcs(TARGET, (0, 1), ("NOT_SPECIFIED", "QDISC_DROP"))
        by_feature = {}
        for c in calcs:
            by_feature.setdefault(c.feature, []).append(c)
        self.assertEqual(set(by_feature), set(EXPECTED))
        for f, cs in by_feature.items():
            unit, aggs, scope, dim = EXPECTED[f]
            with self.subTest(f=f):
                self.assertEqual({c.aggregation or REG.get(f).aggregations[0] for c in cs}, aggs)
                self.assertTrue(all(scope_kind(c.scope) is scope for c in cs))
                self.assertTrue(all(c.source is SourceType.EBPF for c in cs))
                self.assertTrue(all((c.qualifier[0] if c.qualifier else None) == dim for c in cs))
        self.assertEqual({c.qualifier[1] for c in by_feature["softirq.exec_time.percpu"]}, set(VECTORS))
        self.assertEqual(set(VECTORS), set(REG.get("softirq.exec_time.percpu").dimension.values))
        self.assertEqual(len(by_feature["softirq.exec_time.percpu"]), 2 * len(VECTORS))
        self.assertEqual(len(by_feature["sched.latency_hist.target"]), 2)

    def test_latency_p50_and_p99_ids_differ(self):
        w = _world.T0
        from sentinelai.diagnostic.contract import Window
        from datetime import timedelta
        win = Window(start=w, end=w + timedelta(seconds=10), duration_s=10.0, sample_period_s=1.0)
        sc = f"cgroup:{TARGET.cgroup_path}"
        self.assertNotEqual(measurement_id("sched.latency_hist.target", sc, win, aggregation=Aggregation.P50),
                            measurement_id("sched.latency_hist.target", sc, win, aggregation=Aggregation.P99))

    def test_retrans_skb_feature_is_not_retrans_segments(self):
        calcs = [c for c in ebpf_calcs(TARGET, (), ()) if c.feature.startswith("tcp.")]
        self.assertEqual([c.feature for c in calcs], ["tcp.retrans_skb_rate"])
        self.assertNotEqual(REG.get("tcp.retrans_skb_rate").unit, REG.get("tcp.retrans_rate").unit)

    def test_m2_rules_do_not_read_the_new_ebpf_features(self):
        """M2 is unchanged and never reads softirq.exec_time.percpu, tcp.retrans_skb_rate or
        sched.latency_hist.target (net.drop.kfree_skb was already an M2 input). sched.latency_hist.target appears
        in AB.R3's feature list only as a feature an AB.R3 item may cite; AB.R3 is computed from other clauses."""
        import inspect
        from sentinelai.diagnostic.rules import engine
        new = {"softirq.exec_time.percpu", "tcp.retrans_skb_rate", "sched.latency_hist.target"}
        src = inspect.getsource(engine)
        for f in new:
            self.assertNotIn(f, src)
        self.assertFalse(set(engine.DEV_FEATURES) & new)
        self.assertFalse({f for preds in engine.SUPPORTING.values() for _, f, _ in preds} & new)
        read = {f for cl in load_contract().labels.clauses if cl.clause_id != "AB.R3" for f in cl.features}
        self.assertFalse(read & new)
        self.assertIn("sched.latency_hist.target", load_contract().labels.clause("AB.R3").features)


if __name__ == "__main__":
    unittest.main()
