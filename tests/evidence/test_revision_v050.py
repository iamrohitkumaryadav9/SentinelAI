"""Contract revision v0.5.0-draft (M3B-C1): the aggregation is part of a measurement's identity exactly when
its feature registers more than one aggregation. Single-aggregation ids are byte-identical to v0.4.0."""

import hashlib
import json
import unittest
from types import SimpleNamespace
from unittest import mock

from pydantic import ValidationError

from sentinelai.diagnostic.contract import (Aggregation, Qualifier, load_contract, measurement_id)
from sentinelai.diagnostic.contract import ids as ids_mod
from sentinelai.diagnostic.contract.catalog import DATA, FeatureRegistry
from sentinelai.diagnostic.contract.version import CONTRACT_VERSION, SCHEMA_VERSION, require_compatible

from . import _builders as b

C = load_contract()
LAT, SRTT, APPLAT = "sched.latency_hist.target", "tcp.srtt_ms", "app.latency_ms"
MULTI = {LAT: ("cgroup:/lab", (Aggregation.P50, Aggregation.P99)),
         SRTT: ("netns:A", (Aggregation.P50, Aggregation.P90)),
         APPLAT: ("app:A", (Aggregation.P50, Aggregation.P99))}
SCOPE = {"host": "host", "cpuset": "cpuset", "cpu": "cpu:3", "cgroup": "cgroup:/lab", "netns": "netns:A",
         "app": "app:A", "iface": "iface:A/eth0", "socket": "socket:A/x"}

# Computed with the v0.4.0-draft code (commit deab833) before this revision, over every single-aggregation
# feature at its first scope kind and first qualifier value (recipe: _single_ids below).
GOLDEN_SINGLE_DIGEST = "37bb8ce631150f25cb32bcead6084917f54e2640a59789af84f370e949aa7bfe"
GOLDEN_SINGLE = {("cpu.util.host", "host"): "f5655a2e95cd366b",
                 ("net.drop.kfree_skb", "netns:A"): "077651e772ca43bf",
                 ("tcp.retrans_rate", "netns:A"): "d8ebdfb70679e66e",
                 ("sched.run_delay.target", "cgroup:/lab"): "ff0da3b19c0e8f2d",
                 ("app.events", "app:A"): "e074e7ee3194ed4e"}
# sha256 of registry.json minus contract_version at deab833 (v0.4.0-draft)
GOLDEN_REGISTRY_REST = "5190131fed42e7bb3d19c2219b2457c51287395ce228b6d1fe5cc93e476611da"
# v0.4.0 ids of the multi-aggregation features (no aggregation key): every v0.5.0 id must differ from them.
OLD_MULTI = {LAT: "5ec26362b27cac8f", SRTT: "6287775be48c2128", APPLAT: "fa3c81b1952d4084"}


def _qual(spec):
    if spec.dimension is None:
        return None
    return Qualifier(dimension=spec.dimension.name, value=(spec.dimension.values or ("QDISC_DROP",))[0])


def _single_ids(with_aggregation=False):
    out = {}
    for f in C.registry.features:
        if len(f.aggregations) == 1:
            sc = SCOPE[f.scope_kinds[0].value]
            agg = f.aggregations[0] if with_aggregation else None
            out[f"{f.id}@{sc}"] = measurement_id(f.id, sc, b.INC, _qual(f), agg)
    return out


def _digest(d):
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()


def pct(feature, agg, value, scope=None, win=b.INC):
    return b.meas(feature, scope or MULTI[feature][0], value, aggregation=agg, win=win)


class TestMultiAggregationIdentity(unittest.TestCase):
    def test_registry_multi_aggregation_set(self):
        multi = {f.id for f in C.registry.features if len(f.aggregations) > 1}
        self.assertEqual(multi, set(MULTI))
        for f, (_, aggs) in MULTI.items():
            self.assertEqual(C.registry.get(f).aggregations, aggs)

    def test_a_latency_hist_p50_differs_from_p99(self):
        self.assertNotEqual(measurement_id(LAT, "cgroup:/lab", b.INC, aggregation=Aggregation.P50),
                            measurement_id(LAT, "cgroup:/lab", b.INC, aggregation=Aggregation.P99))

    def test_b_same_inputs_are_deterministic(self):
        for f, (sc, aggs) in MULTI.items():
            for agg in aggs:
                with self.subTest(f=f, agg=agg.value):
                    got = {measurement_id(f, sc, b.window(60.0, 10.0), aggregation=agg) for _ in range(3)}
                    self.assertEqual(len(got), 1)
                    # enum and its string value are the same identity input
                    self.assertEqual(got.pop(), measurement_id(f, sc, b.INC, aggregation=agg.value))

    def test_c_app_latency_and_srtt_distinct(self):
        self.assertNotEqual(measurement_id(APPLAT, "app:A", b.INC, aggregation=Aggregation.P50),
                            measurement_id(APPLAT, "app:A", b.INC, aggregation=Aggregation.P99))
        self.assertNotEqual(measurement_id(SRTT, "netns:A", b.INC, aggregation=Aggregation.P50),
                            measurement_id(SRTT, "netns:A", b.INC, aggregation=Aggregation.P90))

    def test_known_answer_encoding(self):
        """The aggregation is a NAMED input (value string) next to the v0.4.0 inputs."""
        payload = ('{"aggregation":"P99","feature_id":"sched.latency_hist.target","kind":"measurement",'
                   '"scope":"cgroup:/lab","window":{"duration_s":10.0,"end":"2026-10-02T10:01:10.000Z",'
                   '"sample_period_s":1.0,"start":"2026-10-02T10:01:00.000Z"}}')
        self.assertEqual(measurement_id(LAT, "cgroup:/lab", b.INC, aggregation=Aggregation.P99),
                         hashlib.sha1(payload.encode()).hexdigest()[:16])

    def test_multi_aggregation_id_requires_an_aggregation(self):
        for f, (sc, _) in MULTI.items():
            with self.subTest(f=f), self.assertRaises(ValueError):
                measurement_id(f, sc, b.INC)

    def test_new_ids_differ_from_the_v040_ids(self):
        for f, (sc, aggs) in MULTI.items():
            for agg in aggs:
                with self.subTest(f=f, agg=agg.value):
                    self.assertNotEqual(measurement_id(f, sc, b.INC, aggregation=agg), OLD_MULTI[f])

    def test_measurement_with_aggregation_free_id_rejected(self):
        """A multi-aggregation measurement carrying the old (aggregation-free) id is not its deterministic id."""
        good = pct(LAT, Aggregation.P99, 1.2)
        with self.assertRaises(ValidationError):
            b.rebuild(good, measurement_id=OLD_MULTI[LAT])
        p50 = pct(LAT, Aggregation.P50, 0.05)
        with self.assertRaises(ValidationError):                      # P99 value under the P50 id
            b.rebuild(good, measurement_id=p50.measurement_id)

    def test_unregistered_aggregation_still_rejected_by_measurement(self):
        with self.assertRaises(ValidationError):
            pct(LAT, Aggregation.MAX, 1.0)
        with self.assertRaises(ValidationError):
            pct(SRTT, Aggregation.P99, 1.0)


class TestSingleAggregationBackwardCompatibility(unittest.TestCase):
    def test_d_named_goldens_unchanged(self):
        for (f, sc), golden in GOLDEN_SINGLE.items():
            with self.subTest(f=f):
                q = _qual(C.registry.get(f))
                self.assertEqual(measurement_id(f, sc, b.INC, q), golden)
                self.assertEqual(measurement_id(f, sc, b.INC, q, C.registry.get(f).aggregations[0]), golden)

    def test_d_every_single_aggregation_id_unchanged(self):
        self.assertEqual(len(_single_ids()), 66)
        self.assertEqual(_digest(_single_ids()), GOLDEN_SINGLE_DIGEST)
        # passing the registered aggregation does not enter the id of a single-aggregation feature
        self.assertEqual(_single_ids(with_aggregation=True), _single_ids())

    def test_earlier_revision_goldens_still_hold(self):
        w = b.window(60.0, 10.0)
        self.assertEqual(measurement_id("cpu.util.host", "host", w), "f5655a2e95cd366b")          # v0.2.0
        self.assertEqual(measurement_id("net.drop.kfree_skb", "netns:A", w), "532a853e8f355a90")
        self.assertEqual(measurement_id("softirq.exec_time.percpu", "cpu:3", b.INC,
                                        Qualifier(dimension="vector", value="NET_RX")), "b6deeaf7d4a52987")  # v0.4.0
        self.assertEqual(measurement_id("tcp.retrans_skb_rate", "netns:A", b.INC), "6c8aedfe03f180d6")

    def test_m3a_emits_only_single_aggregation_features(self):
        """So no id a collector emits today changes."""
        from sentinelai.collectors import collected_features
        self.assertFalse(set(collected_features()) & set(MULTI))


class TestSnapshotCoexistence(unittest.TestCase):
    def test_e_latency_hist_p50_and_p99_in_one_snapshot(self):
        p50, p99 = pct(LAT, Aggregation.P50, 0.05), pct(LAT, Aggregation.P99, 1.2)
        self.assertEqual((p50.scope, p50.window, p50.qualifier), (p99.scope, p99.window, p99.qualifier))
        s = b.snapshot([p50, p99])
        self.assertEqual({m.aggregation for m in s.measurements}, {Aggregation.P50, Aggregation.P99})
        self.assertEqual(len({m.measurement_id for m in s.measurements}), 2)

    def test_e_every_multi_aggregation_feature_coexists(self):
        ms = [pct(f, agg, 1.0 + i) for f, (_, aggs) in MULTI.items() for i, agg in enumerate(aggs)]
        s = b.snapshot(ms)
        self.assertEqual(len(s.measurements), 6)

    def test_true_duplicates_still_rejected(self):
        p99 = pct(LAT, Aggregation.P99, 1.2)
        with self.assertRaises(ValidationError):
            b.snapshot([p99, pct(LAT, Aggregation.P99, 1.2)])
        kf = b.meas("net.drop.kfree_skb", "netns:A", 3.0, qualifier=Qualifier(dimension="reason", value="QDISC_DROP"))
        with self.assertRaises(ValidationError):
            b.snapshot([kf, kf])


class TestNoAccidentalCollision(unittest.TestCase):
    def test_f_aggregation_vs_feature_scope_window(self):
        wins = (b.INC, b.window(61.0, 10.0))
        scopes = {LAT: ("cgroup:/lab", "cgroup:/lab2"), SRTT: ("netns:A", "netns:B"), APPLAT: ("app:A", "app:B")}
        seen = {}
        for f, (_, aggs) in MULTI.items():
            for sc in scopes[f]:
                for w in wins:
                    for agg in aggs:
                        seen[(f, sc, w.start, agg)] = measurement_id(f, sc, w, aggregation=agg)
        self.assertEqual(len(set(seen.values())), len(seen))
        singles = set(_single_ids().values())
        self.assertFalse(singles & set(seen.values()))

    def test_f_aggregation_vs_qualifier(self):
        """No registered multi-aggregation feature declares a dimension today; exercise the combination on a
        registry where kfree_skb registers two aggregations, so a future feature cannot collide."""
        raw = json.loads((DATA / "registry.json").read_text())
        for f in raw["features"]:
            if f["id"] == "net.drop.kfree_skb":
                f["aggregations"] = ["RATE", "MAX"]
        reg = FeatureRegistry.model_validate_json(json.dumps(raw), strict=False)
        q = lambda v: Qualifier(dimension="reason", value=v)
        with mock.patch.object(ids_mod, "load_contract", return_value=SimpleNamespace(registry=reg)):
            got = {(r, a): measurement_id("net.drop.kfree_skb", "netns:A", b.INC, q(r), a)
                   for r in ("QDISC_DROP", "CPU_BACKLOG") for a in (Aggregation.RATE, Aggregation.MAX)}
            self.assertEqual(len(set(got.values())), 4)
            with self.assertRaises(ValueError):
                measurement_id("net.drop.kfree_skb", "netns:A", b.INC, q("QDISC_DROP"))
        self.assertFalse(set(got.values()) & {measurement_id("net.drop.kfree_skb", "netns:A", b.INC, q("QDISC_DROP")),
                                              measurement_id("net.drop.kfree_skb", "netns:A", b.INC)})

    def test_aggregation_key_cannot_alias_another_input(self):
        """Named canonical inputs: P99 as an aggregation is not P99 as a scope or qualifier value."""
        a = measurement_id(LAT, "cgroup:/lab", b.INC, aggregation=Aggregation.P99)
        self.assertNotEqual(a, measurement_id(LAT, "cgroup:/labP99", b.INC, aggregation=Aggregation.P50))
        self.assertNotEqual(a, measurement_id(LAT, "cgroup:/lab", b.INC, aggregation=Aggregation.P50))


class TestVersioning(unittest.TestCase):
    def test_contract_content_unchanged(self):
        """M3B-C1 changes identity only: the whole registry except contract_version is byte-identical to deab833
        (labels, predicates and parameters are pinned the same way by test_revision_v040)."""
        d = json.loads((DATA / "registry.json").read_text())
        d.pop("contract_version")
        self.assertEqual(hashlib.sha256(json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                                        .encode()).hexdigest(), GOLDEN_REGISTRY_REST)

    def test_minor_bump_only_contract(self):
        from sentinelai.diagnostic.rules import RULES_VERSION
        self.assertEqual((CONTRACT_VERSION, SCHEMA_VERSION, RULES_VERSION), ("0.5.0-draft", "0.2.0", "m2-1.1.0"))
        for name in ("registry.json", "labels.json", "predicates.json", "parameters.json"):
            self.assertEqual(json.loads((DATA / name).read_text())["contract_version"], CONTRACT_VERSION)
        self.assertEqual(require_compatible("0.4.0-draft"), "0.4.0-draft")


if __name__ == "__main__":
    unittest.main()
