"""Measurement model and missing/invalid/stale/partial semantics (contract §5, §10.3, §10.8)."""

import unittest

from pydantic import ValidationError

from sentinelai.diagnostic.contract import Aggregation, Deviation, Quality, SourceType, Unit

from . import _builders as b


class TestMeasurementValid(unittest.TestCase):
    def test_valid(self):
        m = b.meas("net.drop.qdisc", "iface:A/eth0", 120.0)
        self.assertEqual(m.unit, Unit.packets_per_second)
        self.assertEqual(len(m.measurement_id), 16)

    def test_no_baseline_is_representable(self):
        m = b.meas("throttle.ratio", "cgroup:/lab", 0.6, base=None)
        self.assertIsNone(m.baseline)
        self.assertIsNone(m.deviation)


class TestRegistryAgreement(unittest.TestCase):
    def test_unknown_feature(self):
        m = b.meas("cpu.util.host", "host", 0.5)
        with self.assertRaises(ValidationError) as cm:   # through the model, not the builder
            b.rebuild(m, feature_id="cpu.imaginary")
        self.assertIn("unknown feature_id", str(cm.exception))

    def test_unit_must_match_registry(self):
        with self.assertRaises(ValidationError):
            b.meas("net.drop.qdisc", "iface:A/eth0", 1.0, unit=Unit.bytes_per_second)

    def test_aggregation_must_be_allowed(self):
        with self.assertRaises(ValidationError):
            b.meas("net.drop.qdisc", "iface:A/eth0", 1.0, aggregation=Aggregation.P99)

    def test_scope_kind_must_be_allowed(self):
        with self.assertRaises(ValidationError):
            b.meas("net.drop.qdisc", "host", 1.0)   # qdisc drops are per interface

    def test_malformed_scope(self):
        for s in ("", "iface:eth0", "cpu:x", "cgroup:relative", "planet:earth"):
            with self.subTest(scope=s), self.assertRaises(ValidationError):
                b.meas("cpu.util.host", s, 0.5)

    def test_source_must_be_registered(self):
        with self.assertRaises(ValidationError):
            b.meas("net.drop.qdisc", "iface:A/eth0", 1.0, provenance=b.prov("net.drop.qdisc", source=SourceType.PROC))

    def test_privileged_flag_must_match(self):
        p = b.prov("net.drop.kfree_skb")
        self.assertTrue(p.privileged)
        bad = b.prov("net.drop.qdisc")
        with self.assertRaises(ValidationError):
            b.meas("net.drop.kfree_skb", "netns:A", 3.0, provenance=bad.__class__(
                **{**{k: getattr(p, k) for k in type(p).model_fields}, "privileged": False}))

    def test_deterministic_id_enforced(self):
        m = b.meas("cpu.util.host", "host", 0.5)
        with self.assertRaises(ValidationError):
            b.rebuild(m, measurement_id="0123456789abcdef")

    def test_derived_feature_requires_derived_provenance(self):
        src = b.meas("sched.run_delay.target", "cgroup:/lab", 0.4)
        with self.assertRaises(ValidationError):  # registry says DERIVED
            b.meas("sched.run_delay_excess.target", "cgroup:/lab", 0.4)
        ok = b.meas("sched.run_delay_excess.target", "cgroup:/lab", 0.4,
                    provenance=b.prov("sched.run_delay_excess.target", derived_from=(src.measurement_id,)))
        self.assertEqual(ok.provenance.derived_from, (src.measurement_id,))


class TestMissingData(unittest.TestCase):
    def test_missing_is_null_not_zero(self):
        m = b.meas("tcp.retrans_rate", "netns:A", None, quality=Quality.MISSING, coverage=0.0)
        self.assertIsNone(m.value)
        self.assertIsNone(m.deviation)
        with self.assertRaises(ValidationError):  # zero must not stand in for missing
            b.meas("tcp.retrans_rate", "netns:A", 0.0, quality=Quality.MISSING, coverage=0.0)

    def test_null_value_requires_missing_or_invalid(self):
        for q in (Quality.OK, Quality.PARTIAL, Quality.STALE):
            with self.subTest(q=q), self.assertRaises(ValidationError):
                b.meas("tcp.retrans_rate", "netns:A", None, quality=q, coverage=0.5)

    def test_invalid_is_null(self):
        m = b.meas("tcp.retrans_rate", "netns:A", None, quality=Quality.INVALID, coverage=0.9)
        self.assertIs(m.quality, Quality.INVALID)
        with self.assertRaises(ValidationError):
            b.meas("tcp.retrans_rate", "netns:A", 5.0, quality=Quality.INVALID)

    def test_counter_reset_cannot_be_hidden(self):
        # A negative rate (negative counter delta) is not a valid value: it must be INVALID/null.
        with self.assertRaises(ValidationError):
            b.meas("tcp.retrans_rate", "netns:A", -3.0, base=None)
        self.assertIsNone(b.meas("tcp.retrans_rate", "netns:A", None, quality=Quality.INVALID).value)
        self.assertEqual(b.dq(counter_resets=1).counter_resets, 1)
        with self.assertRaises(ValidationError):
            b.dq(counter_resets=-1)

    def test_partial(self):
        self.assertIs(b.meas("cpu.util.host", "host", 0.5, quality=Quality.PARTIAL, coverage=0.8).quality, Quality.PARTIAL)
        for cov in (1.0, 0.0):
            with self.subTest(cov=cov), self.assertRaises(ValidationError):
                b.meas("cpu.util.host", "host", 0.5, quality=Quality.PARTIAL, coverage=cov)

    def test_ok_requires_full_coverage(self):
        with self.assertRaises(ValidationError):
            b.meas("cpu.util.host", "host", 0.5, quality=Quality.OK, coverage=0.9)

    def test_insufficient_coverage_is_missing(self):
        m = b.meas("cpu.util.host", "host", None, quality=Quality.MISSING, coverage=0.2)
        self.assertEqual(m.coverage, 0.2)

    def test_value_requires_samples(self):
        with self.assertRaises(ValidationError):
            b.meas("cpu.util.host", "host", 0.5, provenance=b.prov("cpu.util.host", samples=0))

    def test_stale(self):
        old = b.ts(60 - 5)  # last sample 15 s before window end; window is 10 s
        s = b.meas("cpu.util.host", "host", 0.5, quality=Quality.STALE, provenance=b.prov("cpu.util.host", last=old))
        self.assertIs(s.quality, Quality.STALE)
        with self.assertRaises(ValidationError):  # an old sample cannot be reported as OK
            b.meas("cpu.util.host", "host", 0.5, quality=Quality.OK, provenance=b.prov("cpu.util.host", last=old))
        with self.assertRaises(ValidationError):  # a fresh sample is not STALE
            b.meas("cpu.util.host", "host", 0.5, quality=Quality.STALE)

    def test_future_sample_rejected(self):
        with self.assertRaises(ValidationError):
            b.meas("cpu.util.host", "host", 0.5, provenance=b.prov("cpu.util.host", last=b.ts(80)))

    def test_fraction_bounded(self):
        with self.assertRaises(ValidationError):
            b.meas("cpu.util.host", "host", 1.5)


class TestBaselineAndDeviation(unittest.TestCase):
    def test_deviation_null_iff_value_or_baseline_null(self):
        base = b.baseline()
        with self.assertRaises(ValidationError):  # baseline + value present but no deviation
            b.meas("net.drop.qdisc", "iface:A/eth0", 10.0, base=base, dev=None)
        with self.assertRaises(ValidationError):  # deviation without baseline
            b.meas("net.drop.qdisc", "iface:A/eth0", 10.0, base=None, dev=b.deviation_for(10.0, base))

    def test_manufactured_deviation_rejected(self):
        base = b.baseline(median=1.0, mad=0.5)
        good = b.deviation_for(10.0, base)
        for change in ({"delta": good.delta + 1}, {"ratio": good.ratio * 2}, {"robust_z": 0.0}):
            d = Deviation(**{**good.model_dump(), **change})
            with self.subTest(change=change), self.assertRaises(ValidationError):
                b.meas("net.drop.qdisc", "iface:A/eth0", 10.0, base=base, dev=d)

    def test_zero_floor_with_zero_baseline_rejected(self):
        base = b.baseline(median=0.0, mad=0.0, p99=0.0)
        d = Deviation(ratio=1.0, delta=3.0, robust_z=1.0, floor_used=0.0)
        with self.assertRaises(ValidationError):
            b.meas("net.drop.qdisc", "iface:A/eth0", 3.0, base=base, dev=d)

    def test_within_run_baseline_must_precede_window(self):
        overlap = b.baseline(win=b.window(55.0, 10.0))
        with self.assertRaises(ValidationError):
            b.meas("cpu.util.host", "host", 0.5, base=overlap)


class TestGroundTruthBoundary(unittest.TestCase):
    def test_ground_truth_source_rejected(self):
        p = b.prov("cpu.util.host")
        gt = p.__class__(**{**{k: getattr(p, k) for k in type(p).model_fields}, "source": SourceType.FAULTLAB_GROUND_TRUTH})
        with self.assertRaises(ValidationError) as cm:
            b.meas("cpu.util.host", "host", 0.5, provenance=gt)
        self.assertIn("FAULTLAB_GROUND_TRUTH must never be a diagnostic measurement", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
