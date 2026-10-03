"""Contract revision v0.2.0-draft: R-1 … R-5, τ_DISAGREE, and backward compatibility with v0.1.0 (M1).

Reference values in TestBackwardCompatibility were recorded from the unmodified M1 implementation
(commit 33aed1b) before this revision was made.
"""

import hashlib
import json
import unittest

from pydantic import ValidationError

from sentinelai.diagnostic.contract import (CandidateStatus, ConfidenceLevel, DiagnosticFlag, EvidenceKind, Label,
                                            MissingMeasurement, MLAdvisory, Qualifier, Quality, Threshold, Unit,
                                            canonical_bytes, load_contract, measurement_id)
from sentinelai.diagnostic.contract.catalog import DATA

from . import _builders as b

C = load_contract()
KFREE_Q = Qualifier(dimension="reason", value="QDISC_DROP")


# =============================================================================== R-1
class TestR1QuotaLimited(unittest.TestCase):
    def test_boolean_unit_and_feature(self):
        self.assertEqual(Unit.boolean.value, "boolean")
        f = C.registry.get("throttle.quota_limited")
        self.assertEqual((f.family, f.unit.value, [a.value for a in f.aggregations], [s.value for s in f.sources],
                          [k.value for k in f.scope_kinds]),
                         ("cpu_throttling", "boolean", ["GAUGE"], ["CGROUPFS"], ["cgroup"]))
        self.assertIn("cpu.max", f.locator)

    def test_only_zero_and_one(self):
        self.assertEqual(b.meas("throttle.quota_limited", "cgroup:/lab", 0.0, base=None).value, 0.0)  # unlimited
        self.assertEqual(b.meas("throttle.quota_limited", "cgroup:/lab", 1.0, base=None).value, 1.0)  # finite quota
        for bad in (-1.0, 0.5, 2.0, float("nan"), float("inf")):
            with self.subTest(value=bad), self.assertRaises(ValidationError):
                b.meas("throttle.quota_limited", "cgroup:/lab", bad, base=None)

    def test_unreadable_cpu_max_is_missing_not_a_sentinel(self):
        m = b.meas("throttle.quota_limited", "cgroup:/lab", None, quality=Quality.MISSING, coverage=0.0, base=None)
        self.assertIsNone(m.value)

    def test_ct_r1_metadata_uses_quota_limited(self):
        ct1 = C.labels.clause("CT.R1")
        self.assertEqual(ct1.features, ("throttle.quota_limited",))
        self.assertFalse(ct1.uses_baseline)
        self.assertNotIn("null", ct1.definition)

    def test_unlimited_quota_supports_a_negative_ct_r1_item(self):
        unl = b.meas("throttle.quota_limited", "cgroup:/lab", 0.0, base=None)
        neg = b.item("CT.R1", EvidenceKind.NEGATIVE, [unl], contradicts=[Label.cpu_throttling])
        s = b.snapshot([unl], [neg])
        self.assertIs(s.evidence_items[0].kind, EvidenceKind.NEGATIVE)

    def test_quota_cores_no_longer_documents_null(self):
        self.assertNotIn("null", C.registry.get("throttle.quota_cores").locator)
        self.assertIn("finite quota", C.registry.get("throttle.quota_cores").locator)

    def test_quota_consistency(self):
        unl = b.meas("throttle.quota_limited", "cgroup:/lab", 0.0, base=None)
        lim = b.meas("throttle.quota_limited", "cgroup:/lab", 1.0, base=None)
        cores = b.meas("throttle.quota_cores", "cgroup:/lab", 0.5, base=None)
        b.snapshot([lim, cores])
        with self.assertRaises(ValidationError):
            b.snapshot([unl, cores])
        other = b.meas("throttle.quota_cores", "cgroup:/other", 0.5, base=None)
        b.snapshot([unl, other])   # different cgroup: no conflict


# =============================================================================== R-2
class TestR2Reclaim(unittest.TestCase):
    def test_reclaim_is_pgscan_only(self):
        f = C.registry.get("mem.reclaim.target")
        self.assertEqual(f.locator, "cgroup memory.stat Δ(pgscan)")
        self.assertNotIn("pgsteal", f.locator)
        self.assertFalse([x for x in C.registry.features if "pgsteal" in x.locator or "steal" in x.id and "mem" in x.id])

    def test_mp_r1_unchanged(self):
        mp = C.labels.clause("MP.R1")
        self.assertEqual(set(mp.features), {"psi.mem.some.target", "mem.events.oom_kill", "mem.reclaim.target",
                                            "mem.refault.target", "mem.majfault.target"})


# =============================================================================== R-3
class TestR3Qualifier(unittest.TestCase):
    def test_qualifier_model_strict(self):
        with self.assertRaises(ValidationError):
            Qualifier(dimension="", value="X")
        with self.assertRaises(ValidationError):
            Qualifier(dimension="reason", value="X", extra=1)

    def test_registry_dimensions(self):
        dims = {f.id: f.dimension for f in C.registry.features if f.dimension}
        self.assertEqual(set(dims), {"net.drop.kfree_skb", "app.events", "softirq.exec_time.percpu"})   # + v0.4.0
        self.assertEqual(dims["net.drop.kfree_skb"].name, "reason")
        self.assertEqual(dims["app.events"].name, "code")
        self.assertEqual(set(dims["app.events"].values),
                         {"POOL_EXHAUSTED", "QUEUE_FULL", "LOCK_WAIT_EXCEEDED", "DEPENDENCY_TIMEOUT"})

    def test_valid_kfree_reasons(self):
        for r in ("QDISC_DROP", "CPU_BACKLOG", "NETFILTER_DROP", "NOT_SPECIFIED"):
            with self.subTest(r=r):
                m = b.meas("net.drop.kfree_skb", "netns:A", 3.0, qualifier=Qualifier(dimension="reason", value=r))
                self.assertEqual(m.qualifier.value, r)

    def test_invalid_kfree_reason(self):
        for r in ("qdisc_drop", "QDISC DROP", "QDISC-DROP", "Ä"):
            with self.subTest(r=r), self.assertRaises(ValidationError):
                b.meas("net.drop.kfree_skb", "netns:A", 3.0, qualifier=Qualifier(dimension="reason", value=r))

    def test_app_event_codes(self):
        b.meas("app.events", "app:A", 2.0, qualifier=Qualifier(dimension="code", value="POOL_EXHAUSTED"))
        with self.assertRaises(ValidationError):
            b.meas("app.events", "app:A", 2.0, qualifier=Qualifier(dimension="code", value="SLOW_REQUEST"))

    def test_missing_qualifier_rejected_for_dimensioned_features(self):
        for fid, scope in (("net.drop.kfree_skb", "netns:A"), ("app.events", "app:A")):
            with self.subTest(f=fid), self.assertRaises(ValidationError):
                b.meas(fid, scope, 3.0)   # a total count is not representable

    def test_wrong_or_unknown_dimension_rejected(self):
        for q in (Qualifier(dimension="code", value="QDISC_DROP"), Qualifier(dimension="color", value="RED")):
            with self.subTest(q=q), self.assertRaises(ValidationError):
                b.meas("net.drop.kfree_skb", "netns:A", 3.0, qualifier=q)

    def test_qualifier_rejected_for_non_dimensioned_features(self):
        with self.assertRaises(ValidationError):
            b.meas("net.drop.qdisc", "iface:A/eth0", 3.0, qualifier=KFREE_Q)

    def test_qualified_ids_differ(self):
        w = b.window()
        a = measurement_id("net.drop.kfree_skb", "netns:A", w, Qualifier(dimension="reason", value="QDISC_DROP"))
        c = measurement_id("net.drop.kfree_skb", "netns:A", w, Qualifier(dimension="reason", value="CPU_BACKLOG"))
        u = measurement_id("net.drop.kfree_skb", "netns:A", w)
        self.assertEqual(len({a, c, u}), 3)

    def test_id_enforced_with_qualifier(self):
        m = b.meas("net.drop.kfree_skb", "netns:A", 3.0, qualifier=KFREE_Q)
        with self.assertRaises(ValidationError):   # id computed without the qualifier is wrong
            b.rebuild(m, measurement_id=measurement_id("net.drop.kfree_skb", "netns:A", m.window))

    def test_snapshot_uniqueness_and_missing_identity(self):
        qd = b.meas("net.drop.kfree_skb", "netns:A", 4100.0, qualifier=KFREE_Q)
        cb = b.meas("net.drop.kfree_skb", "netns:A", 3.0, qualifier=Qualifier(dimension="reason", value="NOT_SPECIFIED"))
        self.assertEqual(len(b.snapshot([qd, cb]).measurements), 2)   # same feature/scope/window, two reasons
        with self.assertRaises(ValidationError):
            b.snapshot([qd, qd])
        miss = b.meas("net.drop.kfree_skb", "netns:A", None, quality=Quality.MISSING, coverage=0.0,
                      qualifier=Qualifier(dimension="reason", value="CPU_BACKLOG"))
        s = b.snapshot([qd, miss])
        self.assertEqual(s.missing_measurements[0].qualifier.value, "CPU_BACKLOG")
        wrong = MissingMeasurement(feature_id="net.drop.kfree_skb", scope="netns:A", reason="x",
                                   qualifier=Qualifier(dimension="reason", value="QDISC_DROP"))
        with self.assertRaises(ValidationError):   # listed under a different reason only: not declared
            b.rebuild(b.snapshot([miss]), missing_measurements=(wrong,))
        with self.assertRaises(ValidationError):   # missing entry without the required qualifier
            MissingMeasurement(feature_id="net.drop.kfree_skb", scope="netns:A", reason="x")

    def test_qualified_round_trip(self):
        s = b.snapshot([b.meas("net.drop.kfree_skb", "netns:A", 4100.0, qualifier=KFREE_Q)])
        raw = canonical_bytes(s)
        self.assertIn(b'"qualifier":{"dimension":"reason","value":"QDISC_DROP"}', raw)
        self.assertEqual(canonical_bytes(type(s).model_validate_json(raw)), raw)


# =============================================================================== R-4 + τ_DISAGREE
class TestR4ParameterTyping(unittest.TestCase):
    def test_every_parameter_typed(self):
        raw = json.loads((DATA / "parameters.json").read_text())
        for p in raw["parameters"] + raw["per_feature_parameters"]:
            self.assertIn(p["type"], ("number", "reason_set"), p)
        self.assertEqual(sorted(p["name"] for p in raw["parameters"] if p["type"] == "reason_set"), ["KFREE_REASONS_LOSS"])

    def test_threshold_numeric_only(self):
        Threshold(parameter="DROP_ABS_MIN", value=1.0)      # value supplied by the test, not the contract
        Threshold(parameter="floor[net.drop.qdisc]", value=1.0)
        with self.assertRaises(ValidationError):
            Threshold(parameter="KFREE_REASONS_LOSS", value=3.0)

    def test_tau_disagree(self):
        self.assertEqual(C.parameter_type("τ_DISAGREE"), "number")
        raw = json.loads((DATA / "parameters.json").read_text())
        self.assertEqual(raw["status"], "UNCALIBRATED")
        entry = [p for p in raw["parameters"] if p["name"] == "τ_DISAGREE"]
        self.assertEqual(entry, [{"name": "τ_DISAGREE", "type": "number"}])   # no value field


# =============================================================================== R-5
def _asserted(label):
    return b.candidate(label, CandidateStatus.ASSERTED, met=b.all_met(label))


class TestR5Flags(unittest.TestCase):
    SNAP = b.snapshot()
    DIS = MLAdvisory(model_id="m", probabilities={Label.memory_pressure: 0.9, Label.cpu_contention: 0.1},
                     calibrated=True, agrees_with_rules=False)

    def test_default_empty(self):
        self.assertEqual(b.result(self.SNAP).flags, ())

    def test_duplicates_rejected(self):
        with self.assertRaises(ValidationError):
            b.rebuild(b.result(self.SNAP), flags=(DiagnosticFlag.IMPACT_NOT_MEASURED,) * 2)

    def test_impact_not_measured_never_high(self):
        r = b.result(self.SNAP, Label.cpu_throttling, cands={Label.cpu_throttling: _asserted(Label.cpu_throttling)},
                     confidence=ConfidenceLevel.MEDIUM)
        b.rebuild(r, flags=(DiagnosticFlag.IMPACT_NOT_MEASURED,))
        with self.assertRaises(ValidationError):
            b.rebuild(b.rebuild(r, confidence_level=ConfidenceLevel.HIGH), flags=(DiagnosticFlag.IMPACT_NOT_MEASURED,))

    def test_ml_disagreement_requires_disagreeing_ml(self):
        base = b.result(self.SNAP)
        with self.assertRaises(ValidationError):   # no ml advisory
            b.rebuild(base, flags=(DiagnosticFlag.ML_DISAGREEMENT,))
        agree = MLAdvisory(model_id="m", probabilities={Label.INSUFFICIENT_EVIDENCE: 0.9, Label.cpu_contention: 0.1},
                           calibrated=True, agrees_with_rules=True)
        with self.assertRaises(ValidationError):   # ml agrees
            b.rebuild(b.result(self.SNAP, ml=agree), flags=(DiagnosticFlag.ML_DISAGREEMENT,))
        ok = b.rebuild(b.result(self.SNAP, ml=self.DIS), flags=(DiagnosticFlag.ML_DISAGREEMENT,))
        self.assertIs(ok.decision, Label.INSUFFICIENT_EVIDENCE)   # the flag never changes the decision

    def test_flags_do_not_affect_I1(self):
        r = b.result(self.SNAP, Label.cpu_throttling, cands={Label.cpu_throttling: _asserted(Label.cpu_throttling)},
                     confidence=ConfidenceLevel.MEDIUM)
        flagged = b.rebuild(r, flags=(DiagnosticFlag.IMPACT_NOT_MEASURED,))
        self.assertFalse(flagged.abstained)
        self.assertEqual(flagged.abstention_reasons, ())
        with self.assertRaises(ValidationError):   # flags are not abstention reasons
            b.rebuild(r, abstention_reasons=("IMPACT_NOT_MEASURED",))

    def test_flags_are_not_engine_info(self):
        self.assertNotIn("flags", type(b.ENGINE).model_fields)

    def test_flag_order_canonical(self):
        r = b.result(self.SNAP, ml=self.DIS, confidence=ConfidenceLevel.LOW)
        a = b.rebuild(r, flags=(DiagnosticFlag.ML_DISAGREEMENT, DiagnosticFlag.IMPACT_NOT_MEASURED))
        c = b.rebuild(r, flags=(DiagnosticFlag.IMPACT_NOT_MEASURED, DiagnosticFlag.ML_DISAGREEMENT))
        self.assertEqual(canonical_bytes(a), canonical_bytes(c))


# =============================================================================== backward compatibility
class TestBackwardCompatibility(unittest.TestCase):
    """Unqualified identities and bytes must equal v0.1.0 (values recorded from M1 commit 33aed1b)."""

    def test_unqualified_measurement_ids_unchanged(self):
        w = b.window(60.0, 10.0)
        self.assertEqual(measurement_id("cpu.util.host", "host", w), "f5655a2e95cd366b")
        self.assertEqual(measurement_id("net.drop.kfree_skb", "netns:A", w), "532a853e8f355a90")
        self.assertEqual(measurement_id("app.events", "app:A", w), "c8c23d8b4047fb0e")

    def test_unqualified_measurement_bytes_item_and_snapshot_ids_unchanged(self):
        qd = b.meas("net.drop.qdisc", "iface:A/eth0", 500.0)
        cpu = b.meas("cpu.util.host", "host", 0.25)
        it = b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.POSITIVE, [qd], supports=[Label.network_packet_loss])
        snap = b.snapshot([qd, cpu], [it])
        self.assertEqual(qd.measurement_id, "4cc0294063ca4300")
        self.assertEqual(hashlib.sha256(canonical_bytes(qd)).hexdigest(),
                         "5b9ad19d38f24991a3c01e8a20b1d223e44de0dac3fc7324dd5b793e7dadf8a2")
        self.assertNotIn(b"qualifier", canonical_bytes(qd))
        self.assertEqual(it.item_id, "7ea0ace8a99788e2")
        self.assertEqual(snap.snapshot_id, "4766881871d86cda")

    def test_existing_unqualified_objects_remain_valid(self):
        for fid, scope, v in (("cpu.util.host", "host", 0.5), ("net.drop.qdisc", "iface:A/eth0", 5.0),
                              ("tcp.retrans_frac", "netns:A", 0.01), ("mem.reclaim.target", "cgroup:/lab", 100.0)):
            with self.subTest(f=fid):
                self.assertIsNone(b.meas(fid, scope, v).qualifier)


if __name__ == "__main__":
    unittest.main()
