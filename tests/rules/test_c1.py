"""C-1 resolution (contract v0.3.0-draft): retransmission evidence vs proven local packet loss.

RT.R2 is a Primary clause: required for tcp_retransmissions to be the decision, not for it to be CONTRIBUTING
under PR-1. Scenarios C1-A..C1-F from the C-1 resolution gate, plus boundary cases.
"""

import random
import unittest

from sentinelai.diagnostic.contract import (AbstentionReason as AR, CandidateStatus as S, DiagnosticFlag,
                                            EvidenceKind as K, Label as L, Strength)
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.diagnostic.rules import engine as E

from ._fixtures import (APP, IF, NS, Aggregation, Quality, contention, kfree_drops, m, no_drop_counters, qdisc_drops,
                        reasons, retrans, run, scenario, softirq, status)


def cand(d, label):
    return next(c for c in d.result.candidates if c.label is label)


def preds(d, pid):
    return [i for i in d.snapshot.evidence_items if i.predicate_id == pid]


class TestC1A_RetransAndProvenLoss(unittest.TestCase):
    def test_loss_primary_retrans_contributing(self):
        d = run(scenario(retrans(), qdisc_drops()))
        self.assertIs(d.result.decision, L.network_packet_loss)
        self.assertIs(status(d, L.network_packet_loss), S.ASSERTED)
        self.assertIs(status(d, L.tcp_retransmissions), S.CONTRIBUTING)
        self.assertEqual(d.result.contributing, (L.tcp_retransmissions,))
        self.assertEqual(d.snapshot.conflicts, ())
        self.assertEqual(d.result.abstention_reasons, ())

    def test_pr1_is_the_resolving_rule(self):
        self.assertEqual(E._resolve(None, L.network_packet_loss, L.tcp_retransmissions, {}),
                         (L.network_packet_loss, "PR-1"))
        rt2 = E.load_contract().labels.clause("RT.R2")
        self.assertEqual((rt2.subordinate.rule, rt2.subordinate.primary), ("PR-1", L.network_packet_loss))

    def test_evidence_references(self):
        d = run(scenario(retrans(), qdisc_drops()))
        tcp = cand(d, L.tcp_retransmissions)
        self.assertEqual((set(tcp.required_met), tcp.required_missing), ({"RT.R0", "RT.R1"}, ("RT.R2",)))
        (neg,) = preds(d, "RT.R2")                       # Primary clause shown FALSE: local loss proven
        self.assertEqual((neg.kind, neg.contradicts), (K.NEGATIVE, (L.tcp_retransmissions,)))
        self.assertIn(neg.item_id, tcp.contradicting)
        (rt1,) = preds(d, "RT.R1")
        self.assertIn(rt1.item_id, tcp.supporting)
        loss_items = [i for i in d.snapshot.evidence_items if i.kind is K.POSITIVE
                      and i.predicate_id.startswith("PL.R1/")]
        self.assertEqual([i.predicate_id for i in loss_items], ["PL.R1/LOSS.LOCAL[net.drop.qdisc]"])
        self.assertIn(loss_items[0].item_id, cand(d, L.network_packet_loss).supporting)

    def test_other_qualifying_sources(self):
        for frag in (kfree_drops("QDISC_DROP", 500.0), kfree_drops("CPU_BACKLOG", 500.0),
                     {"net.drop.iface_rx": m("net.drop.iface_rx", IF, 500.0, 0.0, 0.0)}):
            with self.subTest(frag=list(frag)):
                d = run(scenario(retrans(), frag))
                self.assertIs(d.result.decision, L.network_packet_loss)
                self.assertEqual(d.result.contributing, (L.tcp_retransmissions,))

    def test_no_contribution_when_abstaining(self):
        lat = {"app.latency_ms": m("app.latency_ms", APP, 100.0, 100.0, 10.0, agg=Aggregation.P99)}
        for ms, gate, why in ((scenario(retrans(), qdisc_drops(), lat), True, "NO_IMPACT_OBSERVED"),
                              (scenario(retrans(), qdisc_drops()), False, "DATA_QUALITY")):
            with self.subTest(why):
                d = run(ms, gate=gate)
                self.assertEqual(reasons(d), [why])
                self.assertEqual(d.result.contributing, ())
                self.assertIs(status(d, L.tcp_retransmissions), S.SUPPORTED_NOT_SUFFICIENT)

    def test_impact_not_measured_keeps_contribution(self):
        d = run(scenario(retrans(), qdisc_drops(), {"app.latency_ms": None}))
        self.assertIs(d.result.decision, L.network_packet_loss)
        self.assertEqual(d.result.contributing, (L.tcp_retransmissions,))
        self.assertEqual(d.result.flags, (DiagnosticFlag.IMPACT_NOT_MEASURED,))

    def test_low_traffic_no_contribution(self):
        d = run(scenario(retrans(), qdisc_drops(), {"tcp.out_segs_rate": m("tcp.out_segs_rate", NS, 20.0, mad=5.0)}))
        self.assertIs(d.result.decision, L.network_packet_loss)
        self.assertEqual(d.result.contributing, ())
        self.assertIs(status(d, L.tcp_retransmissions), S.NOT_SUPPORTED)

    def test_subordinate_only_when_its_primary_is_the_decision(self):
        # softirq primary (PR-2), loss contributing; tcp's declared primary (loss) is not the decision:
        # tcp is not CONTRIBUTING and creates no softirq/tcp conflict
        d = run(scenario(softirq(), kfree_drops("CPU_BACKLOG", 500.0), retrans()))
        self.assertIs(d.result.decision, L.softirq_overload)
        self.assertEqual(d.result.contributing, (L.network_packet_loss,))
        self.assertIs(status(d, L.tcp_retransmissions), S.SUPPORTED_NOT_SUFFICIENT)
        self.assertEqual(d.snapshot.conflicts, ())

    def test_conflict_on_primary_keeps_subordinate_out(self):
        d = run(scenario(softirq(), qdisc_drops(), retrans()))     # PR-2b conflict softirq/loss
        self.assertEqual(reasons(d), ["CONFLICT_UNRESOLVED"])
        self.assertEqual([c.rule for c in d.snapshot.conflicts], ["PR-2b"])
        self.assertIs(status(d, L.tcp_retransmissions), S.SUPPORTED_NOT_SUFFICIENT)


class TestC1B_RetransNormalLoss(unittest.TestCase):
    def test_tcp_asserted(self):
        d = run(scenario(retrans()))
        self.assertIs(d.result.decision, L.tcp_retransmissions)
        self.assertIs(status(d, L.tcp_retransmissions), S.ASSERTED)
        self.assertEqual(cand(d, L.tcp_retransmissions).required_missing, ())
        self.assertIs(status(d, L.network_packet_loss), S.NOT_SUPPORTED)
        self.assertEqual(d.result.contributing, ())

    def test_unusable_non_minimum_source_does_not_crash(self):
        # regression: LOSS.LOCAL FALSE used to cite the unusable source (invalid NEGATIVE item -> exception)
        d = run(scenario(retrans(), {"net.drop.netfilter": m("net.drop.netfilter", NS, None, quality=Quality.MISSING)}))
        self.assertIs(d.result.decision, L.tcp_retransmissions)
        bad = {x.measurement_id for x in d.snapshot.measurements if x.quality is Quality.MISSING}
        for i in d.snapshot.evidence_items:
            if i.kind in (K.POSITIVE, K.NEGATIVE):
                self.assertFalse(bad & set(i.measurement_ids), i.predicate_id)


class TestC1C_RetransUnknownLoss(unittest.TestCase):
    def test_undecidable(self):
        variants = {
            "absent": no_drop_counters(),
            "missing quality": {"net.drop.qdisc": m("net.drop.qdisc", IF, None, quality=Quality.MISSING)},
            "inadequate baseline": {"net.drop.qdisc": m("net.drop.qdisc", IF, 0.0, 0.0, 0.0, adequate=False)},
            "pkts unavailable": {"net.pkts.iface": None},
        }
        for name, frag in variants.items():
            with self.subTest(name):
                d = run(scenario(retrans(), frag))
                self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
                self.assertIn(AR.LOSS_VS_RETRANS_UNDECIDABLE, d.result.abstention_reasons)
                self.assertNotIn(status(d, L.tcp_retransmissions), (S.ASSERTED, S.CONTRIBUTING))
                self.assertNotIn(status(d, L.network_packet_loss), (S.ASSERTED, S.CONTRIBUTING))

    def test_unknown_loss_never_conflicts_or_contributes(self):
        d = run(scenario(contention(), retrans(), no_drop_counters()))   # unchanged from v0.2.0
        self.assertIs(d.result.decision, L.cpu_contention)
        self.assertEqual(d.result.contributing, ())
        self.assertIs(status(d, L.tcp_retransmissions), S.SUPPORTED_NOT_SUFFICIENT)


class TestC1D_LossWithoutRetrans(unittest.TestCase):
    def test_loss_only(self):
        for frac in (0.001, None):
            frag = retrans(frac) if frac else {"tcp.retrans_frac": None}
            with self.subTest(retrans=frac):
                d = run(scenario(qdisc_drops(), frag))
                self.assertIs(d.result.decision, L.network_packet_loss)
                self.assertEqual(d.result.contributing, ())
                self.assertNotEqual(status(d, L.tcp_retransmissions), S.CONTRIBUTING)


class TestC1E_NotSpecifiedOnly(unittest.TestCase):
    def test_never_proves_loss(self):
        for value, median in ((3.0, 3.0), (5000.0, 0.0)):
            for extra in ({}, retrans()):
                with self.subTest(value=value, retrans=bool(extra)):
                    d = run(scenario(kfree_drops("NOT_SPECIFIED", value, median), extra))
                    self.assertNotIn(status(d, L.network_packet_loss), (S.ASSERTED, S.CONTRIBUTING))
                    self.assertNotIn("PL.R1", cand(d, L.network_packet_loss).required_met)
                    if extra:   # loss ruled out by the counters, so retransmissions are the primary
                        self.assertIs(d.result.decision, L.tcp_retransmissions)

    def test_weak_supporting_only(self):
        d = run(scenario(kfree_drops("NOT_SPECIFIED", 5000.0, 0.0)))
        sup = [i for i in d.snapshot.evidence_items if i.kind is K.POSITIVE and L.network_packet_loss in i.supports]
        self.assertEqual([(i.predicate_id, i.strength) for i in sup], [("DEV[net.drop.kfree_skb]", Strength.WEAK)])


class TestC1F_Determinism(unittest.TestCase):
    SCEN = {"A": scenario(retrans(), qdisc_drops()), "B": scenario(retrans()),
            "C": scenario(retrans(), no_drop_counters()), "D": scenario(qdisc_drops()),
            "E": scenario(retrans(), kfree_drops("NOT_SPECIFIED", 5000.0)),
            "3way": scenario(softirq(), kfree_drops("CPU_BACKLOG", 500.0), retrans())}

    @staticmethod
    def blob(d):
        return canonical_bytes(d.result) + b"|" + canonical_bytes(d.snapshot)

    def test_replay_and_permutation(self):
        rng = random.Random(20261003)
        for name, ms in self.SCEN.items():
            ref = self.blob(run(ms))
            with self.subTest(name):
                self.assertEqual(self.blob(run(ms)), ref)
                self.assertEqual(self.blob(run(ms)), ref)
                for _ in range(8):
                    shuffled = list(ms)
                    rng.shuffle(shuffled)
                    self.assertEqual(self.blob(run(shuffled)), ref)


if __name__ == "__main__":
    unittest.main()
