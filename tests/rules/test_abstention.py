"""Abstention, impact gating, data quality, and missing / stale / invalid / partial measurements."""

import unittest

from sentinelai.diagnostic.contract import (AbstentionReason as AR, CandidateStatus as S, ConfidenceLevel as CL,
                                            DiagnosticFlag, EvidenceKind as K, Label as L)

from ._fixtures import (APP, CG, Aggregation, Quality, app_wait, contention, m, memory, rdx, reasons, run, scenario,
                        status, throttling, items, derived)


def latency(value, median=100.0, **kw):
    return {"app.latency_ms": m("app.latency_ms", APP, value, median, 10.0, agg=Aggregation.P99, **kw)}


class TestImpactGate(unittest.TestCase):
    def test_no_impact_observed(self):
        d = run(scenario(contention(), latency(100.0)))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(reasons(d), ["NO_IMPACT_OBSERVED"])
        self.assertEqual(d.result.flags, ())

    def test_deviation_below_impact_min(self):
        d = run(scenario(contention(), latency(180.0)))     # DEV TRUE (ratio 1.8) but ratio < IMPACT_MIN 2.0
        self.assertEqual(reasons(d), ["NO_IMPACT_OBSERVED"])

    def test_impact_not_measured_flag(self):
        for ov in ({"app.latency_ms": None}, latency(None, quality=Quality.MISSING),
                   latency(900.0, adequate=False)):
            with self.subTest(ov=list(ov)):
                d = run(scenario(contention(), ov))
                self.assertIs(d.result.decision, L.cpu_contention)
                self.assertEqual(d.result.flags, (DiagnosticFlag.IMPACT_NOT_MEASURED,))
                self.assertIs(d.result.confidence_level, CL.MEDIUM)   # never HIGH without measured impact

    def test_ml_disagreement_never_generated(self):
        for ms in (scenario(), scenario(contention()), scenario(contention(), {"app.latency_ms": None}),
                   scenario(contention(0.3), throttling(0.4))):
            d = run(ms)
            self.assertNotIn(DiagnosticFlag.ML_DISAGREEMENT, d.result.flags)
            self.assertIsNone(d.result.ml)

    def test_no_impact_items_emitted_c2(self):
        d = run(scenario(contention()))
        self.assertEqual(items(d, "IMPACT"), [])


class TestDataQuality(unittest.TestCase):
    def test_gate_failed(self):
        d = run(scenario(contention()), gate=False)
        self.assertEqual(reasons(d), ["DATA_QUALITY"])
        self.assertIs(d.result.confidence_level, CL.LOW)
        self.assertEqual(d.result.contributing, ())

    def test_data_quality_precedes_other_reasons(self):
        d = run(scenario(contention(0.3), throttling(0.4), latency(100.0)), gate=False)
        self.assertEqual(reasons(d), ["DATA_QUALITY"])


class TestDegradedMeasurements(unittest.TestCase):
    """MISSING / STALE / INVALID / low-coverage PARTIAL never support anything (I3) and never act as normal."""

    def degraded(self, quality, coverage=1.0):
        return {"sched.run_delay_excess.target": m("sched.run_delay_excess.target", CG,
                                                    None if quality in (Quality.MISSING, Quality.INVALID) else 0.8,
                                                    0.02, 0.005, quality=quality, coverage=coverage,
                                                    derived_from=_rdx_sources())}

    def test_each_degraded_quality(self):
        for q, cov in ((Quality.MISSING, 1.0), (Quality.STALE, 1.0), (Quality.INVALID, 1.0), (Quality.PARTIAL, 0.5)):
            with self.subTest(quality=q.value, coverage=cov):
                d = run(scenario(contention(), self.degraded(q, cov)))
                self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
                self.assertIn(AR.REQUIRED_EVIDENCE_MISSING, d.result.abstention_reasons)
                self.assertIs(status(d, L.cpu_contention), S.SUPPORTED_NOT_SUFFICIENT)   # CC.R2 positive only
                (it,) = [i for i in d.snapshot.evidence_items if i.predicate_id == "CC.R1"]
                self.assertIs(it.kind, K.MISSING)
                self.assertEqual(it.supports, ())

    def test_partial_with_enough_coverage_is_usable(self):
        d = run(scenario(contention(), self.degraded(Quality.PARTIAL, 0.9)))
        self.assertIs(d.result.decision, L.cpu_contention)

    def test_missing_never_becomes_negative(self):
        d = run(scenario(self.degraded(Quality.MISSING)))
        self.assertIs(status(d, L.cpu_contention), S.NOT_SUPPORTED)   # CC.R2 FALSE (util normal), CC.R1 MISSING
        cc = next(c for c in d.result.candidates if c.label is L.cpu_contention)
        self.assertIn("CC.R1", cc.required_missing)
        (it,) = [i for i in d.snapshot.evidence_items if i.predicate_id == "CC.R1"]
        self.assertIs(it.kind, K.MISSING)

    def test_inadequate_baseline_is_missing(self):
        ov = {"sched.run_delay_excess.target": m("sched.run_delay_excess.target", CG, 0.8, 0.02, 0.005,
                                                  adequate=False, derived_from=_rdx_sources())}
        d = run(scenario(contention(), ov))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)

    def test_absent_measurement(self):
        d = run(scenario(contention(), {"sched.run_delay_excess.target": None}))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(reasons(d), ["REQUIRED_EVIDENCE_MISSING"])


def _rdx_sources():
    return tuple(x.measurement_id for x in (m("sched.run_delay.target", CG, 0.0), m("throttle.time_rate", CG, 0.0)))


class TestCpuThrottlingQuota(unittest.TestCase):
    def test_unlimited_quota_is_negative(self):
        d = run(scenario(throttling(), {"throttle.quota_limited": m("throttle.quota_limited", CG, 0.0, base=False)}))
        (it,) = [i for i in d.snapshot.evidence_items if i.predicate_id == "CT.R1"]
        self.assertIs(it.kind, K.NEGATIVE)
        self.assertEqual(it.contradicts, (L.cpu_throttling,))
        self.assertIs(status(d, L.cpu_throttling), S.NOT_SUPPORTED)

    def test_quota_missing_is_missing(self):
        for ov in ({"throttle.quota_limited": None},
                   {"throttle.quota_limited": m("throttle.quota_limited", CG, None, base=False, quality=Quality.MISSING)}):
            with self.subTest(ov=ov):
                d = run(scenario(throttling(), ov))
                self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
                self.assertIs(status(d, L.cpu_throttling), S.SUPPORTED_NOT_SUFFICIENT)
                self.assertIn("CT.R1", next(c for c in d.result.candidates
                                            if c.label is L.cpu_throttling).required_missing)


class TestApplicationConfounders(unittest.TestCase):
    def test_confounder_not_evaluated(self):
        d = run(scenario(app_wait(), {"psi.mem.some.target": None, "mem.events.oom_kill": None,
                                      "mem.reclaim.target": None}))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertIn(AR.CONFOUNDER_NOT_EVALUATED, d.result.abstention_reasons)
        self.assertNotEqual(status(d, L.application_bottleneck), S.ASSERTED)

    def test_network_families_only_with_traffic(self):
        # without RT.R0 traffic the network families are not part of AB.R3 (interpretation I-10)
        ov = {"tcp.out_segs_rate": None, "net.drop.qdisc": None, "net.drop.iface_rx": None, "net.drop.iface_tx": None}
        d = run(scenario(app_wait(), ov))
        self.assertIs(d.result.decision, L.application_bottleneck)


class TestAbstentionInvariants(unittest.TestCase):
    def test_i1_and_confidence(self):
        scen = [scenario(), scenario(contention()), scenario(contention(0.3), throttling(0.4)),
                scenario(contention(), latency(100.0)), scenario(app_wait()), scenario(memory())]
        for ms in scen:
            r = run(ms).result
            with self.subTest(decision=r.decision.value):
                self.assertEqual(r.abstained, r.decision is L.INSUFFICIENT_EVIDENCE)
                self.assertEqual(r.abstained, bool(r.abstention_reasons))
                if r.abstained:
                    self.assertIs(r.confidence_level, CL.LOW)
                    self.assertEqual(r.contributing, ())
                else:
                    self.assertIsNot(r.confidence_level, CL.LOW)


if __name__ == "__main__":
    unittest.main()


class TestDevRequiresBothBands(unittest.TestCase):
    def test_high_z_low_ratio_is_not_a_deviation(self):
        # robust_z ≈ 13.5 but ratio 1.2 < R_MODERATE: DEV FALSE (contract §7 needs both z and ratio)
        d = run(scenario(contention(), rdx(1.2, median=1.0, mad=0.01)))
        (it,) = [i for i in d.snapshot.evidence_items if i.predicate_id == "CC.R1"]
        self.assertIs(it.kind, K.NEGATIVE)
        self.assertIs(status(d, L.cpu_contention), S.NOT_SUPPORTED)

    def test_moderate_band(self):
        d = run(scenario(contention(), rdx(0.04, median=0.02, mad=0.002)))   # ratio 2.0, z >> Z_STRONG
        (it,) = [i for i in d.snapshot.evidence_items if i.predicate_id == "CC.R1"]
        self.assertEqual((it.kind, it.strength.value), (K.POSITIVE, "MODERATE"))
        self.assertIs(d.result.decision, L.cpu_contention)
