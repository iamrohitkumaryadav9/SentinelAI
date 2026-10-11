"""G-R2 unit evidence keyed to the DESIGN adversarial table (docs/PHASE_1C_DESIGN.md §7.3).

The historical tests in test_adversarial.py use the Phase 1C M2-prompt numbering, which differs from §7.3.
This file adds only what §7.3 requires and those tests do not assert. Design ID -> classes here:
ADV-1 TestDesignADV01, ADV-4 TestDesignADV04, ADV-5 TestDesignADV05, ADV-6 TestDesignADV06,
ADV-7 TestDesignADV07 (including its missing-OOM subcase), ADV-8 TestDesignADV08, ADV-10 TestDesignADV10.
ADV-2, ADV-3, ADV-3b, ADV-8b and ADV-9 are covered by existing tests (mapping in docs/PHASE_1C_G_R2_EVIDENCE.md).
Interpretations applied: MP.R1 NEGATIVE is ADV-7's NEGATIVE item (D-1, D-1b); reasons follow M2 report §7 (D-2).
"""

import unittest

from sentinelai.diagnostic.contract import (CandidateStatus as S, DiagnosticFlag, EvidenceKind as K, Label as L)

from ._fixtures import (APP, CG, Aggregation, Quality, derived, kfree_drops, m, reasons, run, scenario, softirq,
                        status, throttling, world)


def item(d, predicate_id):
    """The single evidence item with exactly this predicate id."""
    found = [i for i in d.snapshot.evidence_items if i.predicate_id == predicate_id]
    if len(found) != 1:
        raise AssertionError(f"{predicate_id}: expected exactly one item, found {len(found)}")
    return found[0]


def candidate(d, label):
    return next(c for c in d.result.candidates if c.label is label)


def latency_only():
    """Impact high (p99 900 vs baseline 100) and nothing else measured."""
    return [m("app.latency_ms", APP, 900.0, 100.0, 10.0, agg=Aggregation.P99)]


class TestDesignADV01KfreeNoiseAtBaseline(unittest.TestCase):
    """ADV-1: 3/s NOT_SPECIFIED kfree_skb at baseline, other drops 0 -> not packet loss; NEGATIVE or WEAK only;
    NO_CANDIDATE if nothing else."""

    def test_baseline_noise(self):
        d = run(scenario(kfree_drops("NOT_SPECIFIED", 3.0, median=3.0)))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(reasons(d), ["NO_CANDIDATE"])
        self.assertIs(status(d, L.network_packet_loss), S.NOT_SUPPORTED)
        it = item(d, "DEV[net.drop.kfree_skb]")
        self.assertIs(it.kind, K.NEGATIVE)                  # at baseline: not even WEAK support
        self.assertEqual(it.supports, ())
        self.assertFalse([i for i in d.snapshot.evidence_items
                          if i.predicate_id.startswith("PL.R1/LOSS.LOCAL[net.drop.kfree_skb]")])


class TestDesignADV04PureThrottling(unittest.TestCase):
    """ADV-4: throttling with excess run delay at baseline -> cpu_throttling; cpu_contention NOT_SUPPORTED."""

    def test_throttling_not_contention(self):
        d = run(scenario(throttling()))                      # excess run delay stays at its baseline (world)
        self.assertIs(d.result.decision, L.cpu_throttling)
        self.assertEqual(d.result.abstention_reasons, ())
        self.assertEqual(d.result.contributing, ())
        self.assertIs(status(d, L.cpu_throttling), S.ASSERTED)
        self.assertIs(status(d, L.cpu_contention), S.NOT_SUPPORTED)
        for cid in ("CT.R1", "CT.R2"):
            self.assertIs(item(d, cid).kind, K.POSITIVE, cid)
        for cid in ("CC.R1", "CC.R2"):
            it = item(d, cid)
            self.assertIs(it.kind, K.NEGATIVE, cid)
            self.assertEqual(it.contradicts, (L.cpu_contention,), cid)
        x1 = item(d, "CC.X1")
        self.assertEqual((x1.kind, x1.supports, x1.contradicts), (K.POSITIVE, (L.cpu_throttling,), (L.cpu_contention,)))
        self.assertEqual(set(candidate(d, L.cpu_contention).required_missing), {"CC.R1", "CC.R2"})


class TestDesignADV05UtilisationAlone(unittest.TestCase):
    """ADV-5: cpu.util = 0.95, run delay and throttling at baseline -> neither CPU label; NO_CANDIDATE."""

    def test_utilisation_alone(self):
        d = run(scenario(**{"cpu.util.cpuset": m("cpu.util.cpuset", "cpuset", 0.95, 0.30, 0.05)}))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(reasons(d), ["NO_CANDIDATE"])
        self.assertIs(status(d, L.cpu_contention), S.NOT_SUPPORTED)
        self.assertIs(status(d, L.cpu_throttling), S.NOT_SUPPORTED)
        self.assertIs(item(d, "CC.R2").kind, K.POSITIVE)    # utilisation is high ...
        self.assertIs(item(d, "CC.R1").kind, K.NEGATIVE)    # ... but no excess waiting: never contention
        self.assertIs(item(d, "CT.R1").kind, K.NEGATIVE)


class TestDesignADV06WeakSoftirq(unittest.TestCase):
    """ADV-6: a weak softirq increase -> not softirq_overload; INSUFFICIENT_EVIDENCE if nothing else."""

    def check(self, d):
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(reasons(d), ["NO_CANDIDATE"])
        self.assertIs(status(d, L.softirq_overload), S.NOT_SUPPORTED)
        si1 = item(d, "SI.R1")
        self.assertEqual((si1.kind, si1.contradicts), (K.NEGATIVE, (L.softirq_overload,)))
        self.assertIs(item(d, "SI.R2").kind, K.POSITIVE)     # impact on the target is present; only SI.R1 fails

    def test_below_absolute_floor(self):
        d = run(scenario(softirq(frac=0.3)))                 # ratio 6 >= SI_RATIO_MIN, 0.3 < SI_ABS_MIN 0.5
        self.check(d)

    def test_below_ratio(self):
        s2 = m("softirq.frac.percpu", "cpu:2", 0.6, 0.3, 0.01)    # >= SI_ABS_MIN, ratio 2 < SI_RATIO_MIN 3
        s3 = m("softirq.frac.percpu", "cpu:3", 0.6, 0.3, 0.01)
        d = run(scenario(**{"softirq.frac.percpu@2": s2, "softirq.frac.percpu@3": s3,
                            "softirq.relevant_cpu_max": derived("softirq.relevant_cpu_max", "cpuset", 0.6, [s2, s3],
                                                                0.3, 0.01),
                            "psi.cpu.some.target": m("psi.cpu.some.target", CG, 0.3, 0.01, 0.01)}))
        self.check(d)


class TestDesignADV07HighMemoryUsage(unittest.TestCase):
    """ADV-7: high memory usage with PSI, reclaim and refault at baseline -> not memory_pressure; a NEGATIVE item
    (MP.R1, interpretation D-1). The ABS[mem.util.target] supporting item is POSITIVE (contract §8.6, D-1b).
    Subcase (not a separate §7.3 row): OOM evidence unmeasured -> MP.R1 MISSING, never NEGATIVE (D-1)."""

    UTIL = {"mem.util.target": m("mem.util.target", CG, 0.95, 0.5, 0.05)}

    def test_usage_is_not_pressure(self):
        d = run(scenario(self.UTIL))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(reasons(d), ["NO_CANDIDATE"])
        self.assertIs(status(d, L.memory_pressure), S.NOT_SUPPORTED)
        mp = item(d, "MP.R1")
        self.assertEqual((mp.kind, mp.contradicts), (K.NEGATIVE, (L.memory_pressure,)))
        util = item(d, "ABS[mem.util.target]")
        self.assertEqual((util.kind, util.supports), (K.POSITIVE, (L.memory_pressure,)))
        self.assertIn(util.item_id, candidate(d, L.memory_pressure).supporting)

    def test_missing_oom_stays_missing(self):
        d = run(scenario(self.UTIL, {"mem.events.oom_kill": None}))
        mp = item(d, "MP.R1")
        self.assertIs(mp.kind, K.MISSING)                   # never NEGATIVE without the OOM signal (contract E1)
        self.assertEqual(mp.contradicts, ())
        self.assertFalse([i for i in d.snapshot.evidence_items if L.memory_pressure in i.contradicts])
        self.assertIs(status(d, L.memory_pressure), S.SUPPORTED_NOT_SUFFICIENT)
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(reasons(d), ["REQUIRED_EVIDENCE_MISSING"])


class TestDesignADV08NoEliminationToApplication(unittest.TestCase):
    """ADV-8: normal kernel, app metrics normal or missing -> never application_bottleneck;
    INSUFFICIENT_EVIDENCE with NO_CANDIDATE or REQUIRED_EVIDENCE_MISSING."""

    def test_normal_world_reason(self):
        d = run(scenario())
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(reasons(d), ["NO_CANDIDATE"])
        self.assertIs(status(d, L.application_bottleneck), S.NOT_SUPPORTED)

    def test_all_app_metrics_absent(self):
        d = run(scenario(**{"app.latency_ms": None, "app.queue_wait_ms": None}))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(reasons(d), ["REQUIRED_EVIDENCE_MISSING"])
        self.assertEqual(d.result.flags, (DiagnosticFlag.IMPACT_NOT_MEASURED,))
        # AB.R3 "family evaluated" items are POSITIVE (cf. M3A report l.223), so the status is SUPPORTED_NOT_SUFFICIENT
        self.assertIs(status(d, L.application_bottleneck), S.SUPPORTED_NOT_SUFFICIENT)
        self.assertEqual(set(candidate(d, L.application_bottleneck).required_missing), {"AB.R1", "AB.R2"})


class TestDesignADV10AllFamiliesMissing(unittest.TestCase):
    """ADV-10: impact high, every evidence family missing -> INSUFFICIENT_EVIDENCE with the D-2 reason:
    REQUIRED_EVIDENCE_MISSING when the snapshot gate passes, DATA_QUALITY when it fails."""

    def check(self, d, expected_reasons):
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(reasons(d), expected_reasons)
        self.assertEqual(d.result.contributing, ())
        self.assertEqual(len(d.result.candidates), 7)
        for c in d.result.candidates:
            self.assertIs(c.status, S.NOT_EVALUABLE, c.label.value)
            self.assertEqual(c.required_met, (), c.label.value)

    def test_absent_gate_passed(self):
        self.check(run(latency_only()), ["REQUIRED_EVIDENCE_MISSING"])

    def test_missing_quality_gate_passed(self):
        ms = [x if x.feature_id == "app.latency_ms" else
              m(x.feature_id, x.scope, None, quality=Quality.MISSING, agg=x.aggregation, qualifier=x.qualifier,
                derived_from=x.provenance.derived_from)
              for x in world()]
        self.check(run(ms), ["REQUIRED_EVIDENCE_MISSING"])

    def test_absent_gate_failed(self):
        self.check(run(latency_only(), gate=False), ["DATA_QUALITY"])


if __name__ == "__main__":
    unittest.main()
