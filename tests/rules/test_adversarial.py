"""ADV-1..ADV-10 (Phase 1C M2 prompt). Each scenario is built from the normal world plus one fault fragment."""

import unittest

from sentinelai.diagnostic.contract import Strength, AbstentionReason as AR, CandidateStatus as S, EvidenceKind as K, Label as L

from ._fixtures import (APP, CG, IF, NS, Aggregation, app_wait, contention, kfree_drops, m, memory, no_drop_counters,
                        qdisc_drops, Quality, reasons, retrans, run, scenario, softirq, status, throttling, items)


class TestADV1KfreeNoise(unittest.TestCase):
    """3/s of NOT_SPECIFIED kfree_skb is baseline noise, never packet loss."""

    def test_noise_at_baseline(self):
        d = run(scenario(kfree_drops("NOT_SPECIFIED", 3.0, median=3.0)))
        self.assertNotEqual(d.result.decision, L.network_packet_loss)
        self.assertIs(status(d, L.network_packet_loss), S.NOT_SUPPORTED)

    def test_noise_even_when_new(self):
        # NOT_SPECIFIED is outside KFREE_REASONS_LOSS: it is not a LOSS.LOCAL source at any magnitude
        d = run(scenario(kfree_drops("NOT_SPECIFIED", 5000.0, median=0.0)))
        self.assertNotEqual(d.result.decision, L.network_packet_loss)
        self.assertEqual(items(d, "PL.R1/LOSS.LOCAL[net.drop.kfree_skb]"), [])
        sup = [i for i in d.snapshot.evidence_items if i.kind is K.POSITIVE and L.network_packet_loss in i.supports]
        self.assertEqual([i.predicate_id for i in sup], ["DEV[net.drop.kfree_skb]"])   # §8.4: supporting only
        self.assertEqual(sup[0].strength, Strength.WEAK)
        self.assertNotIn("PL.R1", next(c for c in d.result.candidates if c.label is L.network_packet_loss).required_met)

    def test_qualifying_reason_below_floor_is_not_loss(self):
        d = run(scenario(kfree_drops("QDISC_DROP", 3.0, median=0.0)))
        self.assertIs(status(d, L.network_packet_loss), S.NOT_SUPPORTED)
        (it,) = items(d, "PL.R1/LOSS.LOCAL[net.drop.kfree_skb]")
        self.assertIs(it.kind, K.NEGATIVE)

    def test_reason_set_is_a_parameter(self):
        d = run(scenario(kfree_drops("NOT_SPECIFIED", 5000.0)), KFREE_REASONS_LOSS=("NOT_SPECIFIED",))
        self.assertIs(d.result.decision, L.network_packet_loss)


class TestADV2RetransWithoutDropCounters(unittest.TestCase):
    def test_absent_counters(self):
        d = run(scenario(retrans(), no_drop_counters()))
        r = d.result
        self.assertIs(r.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertTrue(r.abstained)
        self.assertEqual(reasons(d), ["LOSS_VS_RETRANS_UNDECIDABLE"])
        self.assertNotEqual(status(d, L.tcp_retransmissions), S.ASSERTED)
        self.assertIn("RT.R2", next(c for c in r.candidates if c.label is L.tcp_retransmissions).required_missing)

    def test_counters_present_but_missing_quality(self):
        ms = scenario(retrans(), **{"net.drop.qdisc": m("net.drop.qdisc", IF, None, quality=Quality.MISSING)})
        d = run(ms)
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertIn(AR.LOSS_VS_RETRANS_UNDECIDABLE, d.result.abstention_reasons)

    def test_absent_counters_are_never_no_drops(self):
        for ov in (no_drop_counters(), {"net.drop.iface_rx": None}):
            d = run(scenario(retrans(), ov))
            neg = [i for i in d.snapshot.evidence_items if L.network_packet_loss in i.contradicts]
            self.assertEqual(neg, [])                      # no "no drops" claim from absent counters
            ev = items(d, "RT.R2/EVALUATED")
            self.assertTrue(all(i.kind is K.MISSING for i in ev))


class TestADV3RetransWithNormalDrops(unittest.TestCase):
    def test_tcp_retransmissions(self):
        d = run(scenario(retrans()))
        self.assertIs(d.result.decision, L.tcp_retransmissions)
        self.assertIs(status(d, L.network_packet_loss), S.NOT_SUPPORTED)
        (it,) = items(d, "RT.R2/LOSS.LOCAL")
        self.assertIs(it.kind, K.NEGATIVE)
        self.assertEqual(it.contradicts, (L.network_packet_loss,))

    def test_low_traffic_blocks_tcp(self):
        d = run(scenario(retrans(), **{"tcp.out_segs_rate": m("tcp.out_segs_rate", NS, 20.0, mad=5.0)}))
        self.assertIs(status(d, L.tcp_retransmissions), S.NOT_SUPPORTED)


class TestADV4CpuBacklog(unittest.TestCase):
    def test_softirq_primary_loss_contributing(self):
        d = run(scenario(softirq(), kfree_drops("CPU_BACKLOG", 500.0)))
        self.assertIs(d.result.decision, L.softirq_overload)
        self.assertEqual(d.result.contributing, (L.network_packet_loss,))
        self.assertIs(status(d, L.network_packet_loss), S.CONTRIBUTING)


class TestADV5RetransWithProvenDrops(unittest.TestCase):
    """network_packet_loss primary, tcp_retransmissions contributing under PR-1 (contract v0.3.0: RT.R2 is a
    Primary clause; C-1 resolution, docs/PHASE_1C_C1_REPORT.md)."""

    def test_packet_loss_asserted(self):
        d = run(scenario(retrans(), qdisc_drops()))
        self.assertIs(d.result.decision, L.network_packet_loss)

    def test_retransmissions_contributing(self):
        d = run(scenario(retrans(), qdisc_drops()))
        self.assertEqual(d.result.contributing, (L.tcp_retransmissions,))
        self.assertIs(status(d, L.tcp_retransmissions), S.CONTRIBUTING)
        self.assertEqual(d.snapshot.conflicts, ())
        tcp = next(c for c in d.result.candidates if c.label is L.tcp_retransmissions)
        self.assertEqual(set(tcp.required_met), {"RT.R0", "RT.R1"})   # the retransmission signal itself
        self.assertEqual(tcp.required_missing, ("RT.R2",))            # not the primary: local loss proven
        (it,) = [i for i in d.snapshot.evidence_items if i.predicate_id == "RT.R2"]
        self.assertIs(it.kind, K.NEGATIVE)
        self.assertEqual(it.contradicts, (L.tcp_retransmissions,))


class TestADV6NoInfraNoAppEvidence(unittest.TestCase):
    def test_normal_world(self):
        d = run(scenario())
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertNotEqual(status(d, L.application_bottleneck), S.ASSERTED)

    def test_latency_only_is_never_application(self):
        d = run(scenario(**{"app.queue_wait_ms": None}))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertIn(AR.REQUIRED_EVIDENCE_MISSING, d.result.abstention_reasons)
        self.assertNotEqual(status(d, L.application_bottleneck), S.ASSERTED)

    def test_wait_not_explaining_latency(self):
        d = run(scenario(app_wait(120.0)))      # wait Δ 115 of latency Δ 800 < APP_SHARE_MIN
        self.assertIs(status(d, L.application_bottleneck), S.NOT_SUPPORTED)
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)


class TestADV7PositiveAppEvidence(unittest.TestCase):
    def test_application_bottleneck(self):
        d = run(scenario(app_wait()))
        self.assertIs(d.result.decision, L.application_bottleneck)
        app_feats = {d.snapshot.measurements[[x.measurement_id for x in d.snapshot.measurements].index(mid)].feature_id
                     for i in d.snapshot.evidence_items if i.kind is K.POSITIVE and L.application_bottleneck in i.supports
                     for mid in i.measurement_ids}
        self.assertTrue(any(f.startswith("app.") and f not in ("app.latency_ms", "app.error_rate") for f in app_feats))

    def test_infrastructure_cause_blocks_application(self):
        d = run(scenario(app_wait(), contention()))
        self.assertIs(d.result.decision, L.cpu_contention)
        self.assertIs(status(d, L.application_bottleneck), S.NOT_SUPPORTED)
        (it,) = [i for i in d.snapshot.evidence_items if i.predicate_id == "AB.R3"]
        self.assertEqual(it.contradicts, (L.application_bottleneck,))


class TestADV8ThrottlingDominant(unittest.TestCase):
    def test_pr3_resolves_to_throttling(self):
        d = run(scenario(contention(0.1), throttling(time_rate=0.5)))
        self.assertIs(d.result.decision, L.cpu_throttling)
        self.assertEqual(d.result.contributing, (L.cpu_contention,))

    def test_pr3_resolves_to_contention(self):
        d = run(scenario(contention(0.9), throttling(time_rate=0.1)))
        self.assertIs(d.result.decision, L.cpu_contention)
        self.assertEqual(d.result.contributing, (L.cpu_throttling,))


class TestADV9ThrottlingNoDominance(unittest.TestCase):
    def test_no_arbitrary_choice(self):
        d = run(scenario(contention(0.3), throttling(time_rate=0.4)))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(reasons(d), ["CONFLICT_UNRESOLVED"])
        (cf,) = d.snapshot.conflicts
        self.assertEqual(cf.labels, (L.cpu_contention, L.cpu_throttling))
        self.assertEqual(cf.rule, "PR-3")
        self.assertEqual(d.result.contributing, ())

    def test_dom_ratio_is_a_parameter(self):
        d = run(scenario(contention(0.3), throttling(time_rate=0.4)), DOM_RATIO=1.2)
        self.assertIs(d.result.decision, L.cpu_throttling)


class TestADV10SoftirqContention(unittest.TestCase):
    def test_pr5_resolves_to_softirq(self):
        d = run(scenario(contention(), softirq()))
        self.assertIs(d.result.decision, L.softirq_overload)
        self.assertEqual(d.result.contributing, (L.cpu_contention,))

    def test_pr5_insufficient_share_is_conflict(self):
        d = run(scenario(contention(), softirq()), SI_SHARE_MIN=0.95)
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(d.snapshot.conflicts[0].rule, "PR-5")


if __name__ == "__main__":
    unittest.main()
