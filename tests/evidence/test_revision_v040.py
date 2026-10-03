"""Contract revision v0.4.0-draft (M3B-C0): EBPF-specific features for softirq time (G-2) and retransmitted
skbs (G-3). Additive only: every pre-existing feature, clause, predicate and parameter is unchanged."""

import hashlib
import json
import unittest

from pydantic import ValidationError

from sentinelai.diagnostic.contract import (Aggregation, Qualifier, ScopeKind, SourceType, Unit, load_contract,
                                            measurement_id)
from sentinelai.diagnostic.contract.catalog import DATA, FeatureRegistry
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.diagnostic.contract.version import CONTRACT_VERSION, SCHEMA_VERSION, require_compatible

from . import _builders as b

C = load_contract()
SOFT, RTX = "softirq.exec_time.percpu", "tcp.retrans_skb_rate"
NEW = {SOFT, RTX}
VECTORS = ("HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU")

# sha256 of the canonical JSON of the v0.3.0-draft content (computed from commit 628c711), excluding
# contract_version: the proof that M3B-C0 changed nothing that existed.
GOLDEN = {"registry.features": "c9024e312f565e6484437f092f9ac8c9866d182960cb8b13fe3bfc4a0b541d4b",
          "labels.json": "bf68c6c8c29d1a4c6f0d99bdf55587da0284ffc175e69d6acbfb2e913a983482",
          "predicates.json": "32986f3e1542cf37ff1fa4d49c3aed0ff9ceda1f8a7b338a8a2a73af1d837b27",
          "parameters.json": "d70c62948305289f7e27e0e221616f5bd053e92ca9af79501b2ce96a0acb60e4"}


def _canon_hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode()).hexdigest()


def _raw(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def m(feature, scope, *, unit=None, source=None, qualifier=None, aggregation=None):
    spec = C.registry.get(feature)
    return b.meas(feature, scope, 0.01, unit=unit or spec.unit, aggregation=aggregation,
                  provenance=b.prov(feature, source=source), qualifier=qualifier)


def vec(v):
    return Qualifier(dimension="vector", value=v)


class TestG2SoftirqExecTime(unittest.TestCase):
    def test_definition(self):
        s = C.registry.get(SOFT)
        self.assertEqual((s.sources, s.unit, s.aggregations, s.scope_kinds, s.kind),
                         ((SourceType.EBPF,), Unit.cores, (Aggregation.RATE,), (ScopeKind.cpu,), "counter_rate"))
        self.assertEqual((s.availability.value, s.privileged, s.non_negative, s.family), ("P", True, True, "softirq"))
        self.assertIn("softirq_entry", s.locator)
        self.assertIn("softirq_exit", s.locator)
        for phrase in ("Not the /proc/stat jiffy fraction", "softirq.frac.percpu", "not CPU utilisation",
                       "NET_RX and NET_TX"):
            self.assertIn(phrase, s.description)

    def test_vector_qualifier_closed_set(self):
        d = C.registry.get(SOFT).dimension
        self.assertEqual((d.name, d.values, d.pattern), ("vector", VECTORS, None))
        self.assertLess({"NET_RX", "NET_TX"}, set(d.values))       # network vectors are a strict subset
        m(SOFT, "cpu:3", qualifier=vec("NET_RX"))
        for bad in (None, vec("NET"), vec("net_rx"), Qualifier(dimension="reason", value="NET_RX")):
            with self.subTest(q=bad), self.assertRaises(ValidationError):
                m(SOFT, "cpu:3", qualifier=bad)

    def test_cannot_masquerade_as_proc_softirq_features(self):
        cases = [dict(feature=SOFT, source=SourceType.PROC, qualifier=vec("NET_RX")),          # wrong source
                 dict(feature=SOFT, unit=Unit.fraction, qualifier=vec("NET_RX")),               # jiffy-fraction unit
                 dict(feature=SOFT, unit=Unit.events_per_second, qualifier=vec("NET_RX")),      # /proc/softirqs unit
                 dict(feature=SOFT, aggregation=Aggregation.RATIO, qualifier=vec("NET_RX")),
                 dict(feature="softirq.frac.percpu", source=SourceType.EBPF),                  # eBPF under /proc feature
                 dict(feature="softirq.net_rx_rate.percpu", source=SourceType.EBPF),
                 dict(feature="softirq.net_tx_rate.percpu", source=SourceType.EBPF),
                 dict(feature="softirq.frac.percpu", unit=Unit.cores),
                 dict(feature="softirq.frac.percpu", qualifier=vec("NET_RX"))]                 # no dimension there
        for kw in cases:
            with self.subTest(**{k: str(v) for k, v in kw.items()}), self.assertRaises(ValidationError):
                m(scope="cpu:3", **kw)
        with self.assertRaises(ValidationError):
            m(SOFT, "cpuset", qualifier=vec("NET_RX"))                                         # per-CPU only

    def test_distinct_identity(self):
        ids = {measurement_id(SOFT, "cpu:3", b.INC, vec(v)) for v in VECTORS}
        ids.add(measurement_id("softirq.frac.percpu", "cpu:3", b.INC))
        self.assertEqual(len(ids), len(VECTORS) + 1)


class TestG3RetransSkbRate(unittest.TestCase):
    def test_definition(self):
        t = C.registry.get(RTX)
        self.assertEqual((t.sources, t.unit, t.aggregations, t.scope_kinds, t.kind, t.dimension),
                         ((SourceType.EBPF,), Unit.events_per_second, (Aggregation.RATE,), (ScopeKind.netns,),
                          "counter_rate", None))
        self.assertNotEqual(t.unit, Unit.segments_per_second)
        self.assertIn("skbs/s", t.contract_unit_text)
        self.assertNotIn("segment", t.contract_unit_text)
        self.assertIn("tcp_retransmit_skb", t.locator)
        for phrase in ("NOT segments/s", "NOT tcp.retrans_rate", "No per-socket or per-target attribution"):
            self.assertIn(phrase, t.description)
        self.assertEqual((t.family, t.privileged), ("network_tcp", True))

    def test_not_interchangeable_with_tcp_retrans_rate(self):
        for kw in (dict(feature=RTX, unit=Unit.segments_per_second), dict(feature=RTX, source=SourceType.PROC),
                   dict(feature="tcp.retrans_rate", source=SourceType.EBPF),
                   dict(feature="tcp.retrans_rate", unit=Unit.events_per_second),
                   dict(feature=RTX, qualifier=Qualifier(dimension="reason", value="X"))):
            with self.subTest(**{k: str(v) for k, v in kw.items()}), self.assertRaises(ValidationError):
                m(scope="netns:A", **kw)
        m(RTX, "netns:A")
        self.assertNotEqual(measurement_id(RTX, "netns:A", b.INC), measurement_id("tcp.retrans_rate", "netns:A", b.INC))
        with self.assertRaises(ValidationError):
            m(RTX, "socket:A/10.0.0.1:1-10.0.0.2:2")       # no per-socket attribution promised


class TestPreservation(unittest.TestCase):
    def test_every_existing_feature_unchanged(self):
        feats = [f for f in _raw("registry.json")["features"] if f["id"] not in NEW]
        self.assertEqual(len(feats), 67)
        self.assertEqual(_canon_hash(feats), GOLDEN["registry.features"])

    def test_named_features_keep_their_meaning(self):
        r = C.registry
        exp = {"softirq.frac.percpu": (Unit.fraction, (Aggregation.RATIO,), (SourceType.PROC,), "/proc/stat"),
               "softirq.net_rx_rate.percpu": (Unit.events_per_second, (Aggregation.RATE,), (SourceType.PROC,),
                                              "/proc/softirqs NET_RX"),
               "softirq.net_tx_rate.percpu": (Unit.events_per_second, (Aggregation.RATE,), (SourceType.PROC,),
                                              "/proc/softirqs NET_TX"),
               "tcp.retrans_rate": (Unit.segments_per_second, (Aggregation.RATE,), (SourceType.PROC,),
                                    "/proc/net/snmp Tcp: RetransSegs")}
        for fid, (unit, agg, src, loc) in exp.items():
            f = r.get(fid)
            with self.subTest(fid):
                self.assertEqual((f.unit, f.aggregations, f.sources), (unit, agg, src))
                self.assertTrue(f.locator.startswith(loc))
                self.assertIsNone(f.dimension)

    def test_rules_predicates_parameters_unchanged(self):
        for name in ("labels.json", "predicates.json", "parameters.json"):
            d = _raw(name)
            d.pop("contract_version")
            with self.subTest(name):
                self.assertEqual(_canon_hash(d), GOLDEN[name])

    def test_m2_does_not_consume_the_new_features(self):
        from sentinelai.diagnostic.rules import RULES_VERSION
        from sentinelai.diagnostic.rules.engine import DEV_FEATURES, SUPPORTING
        self.assertEqual(RULES_VERSION, "m2-1.1.0")
        used = {f for cl in C.labels.clauses for f in cl.features}
        used |= {f for preds in SUPPORTING.values() for _, f, _ in preds} | set(DEV_FEATURES)
        self.assertFalse(used & NEW)

    def test_m3a_collectors_do_not_emit_them(self):
        from sentinelai.collectors import collected_features
        self.assertFalse(set(collected_features()) & NEW)


class TestVersioningAndDeterminism(unittest.TestCase):
    def test_minor_bump(self):
        self.assertEqual((CONTRACT_VERSION, SCHEMA_VERSION), ("0.4.0-draft", "0.2.0"))
        for name in ("registry.json", "labels.json", "predicates.json", "parameters.json"):
            self.assertEqual(_raw(name)["contract_version"], CONTRACT_VERSION)
        self.assertEqual(require_compatible("0.3.0-draft"), "0.3.0-draft")   # same major: older snapshots accepted

    def test_registry_metadata_must_match_version(self):
        d = _raw("registry.json")
        d["contract_version"] = "0.3.0-draft"
        with self.assertRaises(ValidationError):
            FeatureRegistry.model_validate_json(json.dumps(d), strict=False)

    def test_duplicate_feature_rejected(self):
        d = _raw("registry.json")
        d["features"].append(next(f for f in d["features"] if f["id"] == SOFT))
        with self.assertRaises(ValidationError):
            FeatureRegistry.model_validate_json(json.dumps(d), strict=False)

    def test_deterministic_serialisation_and_ids(self):
        a = canonical_bytes(FeatureRegistry.model_validate_json((DATA / "registry.json").read_text(), strict=False))
        b2 = canonical_bytes(FeatureRegistry.model_validate_json((DATA / "registry.json").read_text(), strict=False))
        self.assertEqual(a, b2)
        # golden ids: sha1 of named canonical inputs (contract §10.3); no clock, no runtime state
        self.assertEqual(measurement_id(SOFT, "cpu:3", b.INC, vec("NET_RX")), "b6deeaf7d4a52987")
        self.assertEqual(measurement_id(RTX, "netns:A", b.INC), "6c8aedfe03f180d6")


if __name__ == "__main__":
    unittest.main()
