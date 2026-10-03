"""Schema tests: Window, Target, BaselineStat, Provenance, enums, versioning, unknown fields."""

import json
import unittest
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from sentinelai.diagnostic.contract import (Aggregation, BaselineMethod, BaselineStat, CandidateStatus, ConfidenceLevel,
                                            DataQuality, Deviation, EvidenceKind, Label, Provenance, Quality,
                                            SourceType, Strength, Target, Unit, Window)
from sentinelai.diagnostic.contract import enums as E
from sentinelai.diagnostic.contract.version import CONTRACT_VERSION, SCHEMA_VERSION, require_compatible

from . import _builders as b

UTC = timezone.utc


class TestWindow(unittest.TestCase):
    def test_valid(self):
        w = b.window(0, 10)
        self.assertEqual(w.duration_s, 10.0)

    def test_end_not_after_start(self):
        with self.assertRaises(ValidationError):
            Window(start=b.ts(10), end=b.ts(10), duration_s=1.0, sample_period_s=1.0)
        with self.assertRaises(ValidationError):
            Window(start=b.ts(10), end=b.ts(5), duration_s=5.0, sample_period_s=1.0)

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValidationError):
            Window(start=datetime(2026, 10, 2, 10, 0, 0), end=b.ts(10), duration_s=10.0, sample_period_s=1.0)

    def test_non_utc_offset_rejected_not_normalised(self):
        ist = timezone(timedelta(hours=5, minutes=30))
        with self.assertRaises(ValidationError):
            Window(start=b.T0.astimezone(ist), end=b.ts(10), duration_s=10.0, sample_period_s=1.0)

    def test_sub_millisecond_rejected(self):
        with self.assertRaises(ValidationError):
            Window(start=b.T0 + timedelta(microseconds=1500), end=b.ts(10), duration_s=10.0, sample_period_s=1.0)

    def test_duration_must_agree(self):
        with self.assertRaises(ValidationError):
            Window(start=b.ts(0), end=b.ts(10), duration_s=9.0, sample_period_s=1.0)

    def test_duration_and_period_positive(self):
        for d, p in ((0.0, 1.0), (-10.0, 1.0), (10.0, 0.0), (10.0, -1.0)):
            with self.subTest(d=d, p=p), self.assertRaises(ValidationError):
                Window(start=b.ts(0), end=b.ts(10), duration_s=d, sample_period_s=p)

    def test_non_finite_rejected(self):
        with self.assertRaises(ValidationError):
            Window(start=b.ts(0), end=b.ts(10), duration_s=float("nan"), sample_period_s=1.0)

    def test_string_timestamps_only_via_json(self):
        with self.assertRaises(ValidationError):  # python mode is strict: no silent parsing
            Window(start="2026-10-02T10:00:00.000Z", end=b.ts(10), duration_s=10.0, sample_period_s=1.0)
        w = Window.model_validate_json(json.dumps({"start": "2026-10-02T10:00:00.000Z", "end": "2026-10-02T10:00:10.000Z",
                                                   "duration_s": 10.0, "sample_period_s": 1.0}))
        self.assertEqual(w.start, b.T0)
        self.assertEqual(w.model_dump(mode="json")["start"], "2026-10-02T10:00:00.000Z")

    def test_json_non_utc_rejected(self):
        with self.assertRaises(ValidationError):
            Window.model_validate_json('{"start":"2026-10-02T15:30:00.000+05:30","end":"2026-10-02T10:00:10.000Z",'
                                       '"duration_s":10.0,"sample_period_s":1.0}')

    def test_numbers_not_coerced_from_strings_or_bools(self):
        with self.assertRaises(ValidationError):
            Window(start=b.ts(0), end=b.ts(10), duration_s="10", sample_period_s=1.0)
        with self.assertRaises(ValidationError):
            Window(start=b.ts(0), end=b.ts(10), duration_s=10.0, sample_period_s=True)


class TestTarget(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(b.TARGET.cpuset, "20-21")

    def test_invalid(self):
        good = dict(name="t", cgroup_path="/x", pids=(1,), cpuset="0-3,8", netns_ref=None, ifaces=("eth0",))
        for change in ({"cgroup_path": "relative/path"}, {"cpuset": "0-3,"}, {"cpuset": "a"}, {"pids": (1, 1)},
                       {"pids": (0,)}, {"ifaces": ("eth0", "eth0")}, {"name": ""}):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                Target(**{**good, **change})
        Target(**{**good, "cpuset": None})  # unrestricted cpuset is representable


class TestBaseline(unittest.TestCase):
    def test_valid_and_inadequate_representable(self):
        self.assertTrue(b.baseline().adequate)
        self.assertFalse(b.baseline(adequate=False, n=2).adequate)

    def test_reference_requires_id(self):
        with self.assertRaises(ValidationError):
            b.baseline(method=BaselineMethod.reference)
        self.assertEqual(b.baseline(method=BaselineMethod.reference, bid="ref-1").baseline_id, "ref-1")

    def test_invalid_stats(self):
        for kw in ({"n": 0}, {"mad": -0.1}, {"median": 2.0, "p99": 1.0}):
            with self.subTest(kw=kw), self.assertRaises(ValidationError):
                b.baseline(**kw)


class TestProvenance(unittest.TestCase):
    def test_derived_requires_derived_from(self):
        with self.assertRaises(ValidationError):
            b.prov("sched.run_delay_excess.target", source=SourceType.DERIVED)
        with self.assertRaises(ValidationError):  # non-derived source with derived_from
            b.prov("cpu.util.host", derived_from=("0123456789abcdef",))
        with self.assertRaises(ValidationError):  # not a measurement id
            b.prov("sched.run_delay_excess.target", derived_from=("bogus",))

    def test_sample_times_ordered(self):
        with self.assertRaises(ValidationError):
            Provenance(source=SourceType.PROC, locator="/proc/stat", collector="c", collector_version="1",
                       privileged=False, first_sample_at=b.ts(70), last_sample_at=b.ts(60), samples=1)

    def test_required_fields(self):
        for missing in ("locator", "collector", "collector_version", "privileged", "samples"):
            d = dict(source=SourceType.PROC, locator="/proc/stat", collector="c", collector_version="1",
                     privileged=False, first_sample_at=b.ts(60), last_sample_at=b.ts(61), samples=1)
            d.pop(missing)
            with self.subTest(missing=missing), self.assertRaises(ValidationError):
                Provenance(**d)


class TestEnums(unittest.TestCase):
    """Enumeration values are normative (contract §10.1). Expected values typed from the contract."""

    def test_labels_exact(self):
        self.assertEqual([l.value for l in Label], [
            "cpu_contention", "cpu_throttling", "softirq_overload", "network_packet_loss", "tcp_retransmissions",
            "memory_pressure", "application_bottleneck", "INSUFFICIENT_EVIDENCE"])
        self.assertEqual(len(E.FAULT_LABELS), 7)
        self.assertNotIn(Label.INSUFFICIENT_EVIDENCE, E.FAULT_LABELS)

    def test_other_enums_exact(self):
        exp = {
            EvidenceKind: {"POSITIVE", "NEGATIVE", "MISSING", "CONFLICTING"},
            Strength: {"STRONG", "MODERATE", "WEAK"},
            Quality: {"OK", "PARTIAL", "STALE", "INVALID", "MISSING"},
            SourceType: {"PROC", "SYSFS", "CGROUPFS", "TC", "SS", "EBPF", "APP_METRICS", "APP_EVENTS",
                         "FAULTLAB_GROUND_TRUTH", "DERIVED", "PROMETHEUS"},
            Aggregation: {"RATE", "MEAN", "GAUGE", "DELTA", "RATIO", "P50", "P90", "P99", "MAX"},
            Unit: {"fraction", "cores", "waiting_cores", "per_second", "packets_per_second", "segments_per_second",
                   "events_per_second", "pages_per_second", "bytes", "bytes_per_second", "ms", "count", "ratio",
                   "boolean"},
            E.DiagnosticFlag: {"IMPACT_NOT_MEASURED", "ML_DISAGREEMENT"},
            CandidateStatus: {"ASSERTED", "CONTRIBUTING", "SUPPORTED_NOT_SUFFICIENT", "CONTRADICTED",
                              "NOT_EVALUABLE", "NOT_SUPPORTED"},
            ConfidenceLevel: {"HIGH", "MEDIUM", "LOW"},
            E.AbstentionReason: {"NO_CANDIDATE", "NO_IMPACT_OBSERVED", "REQUIRED_EVIDENCE_MISSING",
                                 "CONFLICT_UNRESOLVED", "LOSS_VS_RETRANS_UNDECIDABLE", "CONFOUNDER_NOT_EVALUATED",
                                 "DATA_QUALITY"},
        }
        for enum, values in exp.items():
            with self.subTest(enum=enum.__name__):
                self.assertEqual({e.value for e in enum}, values)


class TestVersioning(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(SCHEMA_VERSION, "0.2.0")
        self.assertEqual(CONTRACT_VERSION, "0.5.0-draft")

    def test_major_mismatch_rejected_minor_accepted(self):
        with self.assertRaises(ValueError):
            require_compatible("1.0.0")
        with self.assertRaises(ValueError):
            require_compatible("not-a-version")
        self.assertEqual(require_compatible("0.2.0"), "0.2.0")


class TestUnknownFieldsRejected(unittest.TestCase):
    def test_every_model_forbids_extra_fields(self):
        snap = b.snapshot()
        res = b.result(snap)
        objs = [b.window(), b.baseline(), b.TARGET, b.prov("cpu.util.host"), b.dq(), b.ENGINE,
                b.meas("cpu.util.host", "host", 0.5, base=None), snap, res,
                Deviation(ratio=1.0, delta=0.0, robust_z=0.0, floor_used=0.1)]
        for o in objs:
            with self.subTest(model=type(o).__name__), self.assertRaises(ValidationError):
                data = {k: getattr(o, k) for k in type(o).model_fields}
                data["unexpected_field"] = 1
                type(o)(**data)

    def test_models_are_frozen(self):
        w = b.window()
        with self.assertRaises(ValidationError):
            w.duration_s = 5.0


if __name__ == "__main__":
    unittest.main()
