"""Cross-object invariants I2–I6 via validate_against_snapshot (contract §10.7)."""

import unittest

from pydantic import ValidationError

from sentinelai.diagnostic.contract import (CandidateStatus, ContractViolation, EvidenceKind, Label,
                                            validate_against_snapshot)

from . import _builders as b

A, CONTRIB = CandidateStatus.ASSERTED, CandidateStatus.CONTRIBUTING
POS, NEG, MISS = EvidenceKind.POSITIVE, EvidenceKind.NEGATIVE, EvidenceKind.MISSING


def tcp_evidence(with_negative_loss=True):
    """RT.R0 + RT.R1 + RT.R2 (EVALUATED positive, LOSS.LOCAL negative): what tcp_retransmissions requires."""
    segs = b.meas("tcp.out_segs_rate", "netns:A", 4000.0, base=None)
    frac = b.meas("tcp.retrans_frac", "netns:A", 0.08)
    qd = b.meas("net.drop.qdisc", "iface:A/eth0", 0.0)
    rx = b.meas("net.drop.iface_rx", "iface:A/eth0", 0.0)
    tx = b.meas("net.drop.iface_tx", "iface:A/eth0", 0.0)
    items = [b.item("RT.R0", POS, [segs], supports=[Label.tcp_retransmissions]),
             b.item("RT.R1", POS, [frac], supports=[Label.tcp_retransmissions]),
             b.item("RT.R2/EVALUATED[min_local_drop_set]", POS, [qd, rx, tx], supports=[Label.tcp_retransmissions])]
    if with_negative_loss:
        items.append(b.item("RT.R2/LOSS.LOCAL", NEG, [qd, rx, tx], contradicts=[Label.network_packet_loss]))
    return [segs, frac, qd, rx, tx], items


def tcp_result(snap, items):
    sup = tuple(i.item_id for i in items if i.kind is POS)
    return b.result(snap, Label.tcp_retransmissions,
                    cands={Label.tcp_retransmissions: b.candidate(Label.tcp_retransmissions, A,
                                                                  met=b.all_met(Label.tcp_retransmissions),
                                                                  supporting=sup)})


class TestI2I4(unittest.TestCase):
    def test_backed_decision_passes(self):
        ms, items = tcp_evidence()
        snap = b.snapshot(ms, items)
        validate_against_snapshot(tcp_result(snap, items), snap)

    def test_I2_decision_without_required_evidence(self):
        ms, items = tcp_evidence(with_negative_loss=False)   # local loss never shown to be absent
        snap = b.snapshot(ms, items)
        with self.assertRaises(ContractViolation) as cm:
            validate_against_snapshot(tcp_result(snap, items), snap)
        self.assertEqual(cm.exception.invariant, "I2")

    def test_I2_missing_item_does_not_satisfy_a_clause(self):
        frac = b.meas("tcp.retrans_frac", "netns:A", None, quality=b.Quality.MISSING, coverage=0.0)
        miss = b.item("RT.R1", MISS, [frac])
        snap = b.snapshot([frac], [miss])
        r = b.result(snap, Label.tcp_retransmissions,
                     cands={Label.tcp_retransmissions: b.candidate(Label.tcp_retransmissions, A,
                                                                   met=b.all_met(Label.tcp_retransmissions))})
        with self.assertRaises(ContractViolation):
            validate_against_snapshot(r, snap)

    def test_I4_contributing_candidate_must_be_backed(self):
        qd = b.meas("net.drop.qdisc", "iface:A/eth0", 900.0)
        loss = b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", POS, [qd], supports=[Label.network_packet_loss])
        snap = b.snapshot([qd], [loss])
        r = b.result(snap, Label.network_packet_loss, contributing=(Label.tcp_retransmissions,),
                     cands={Label.network_packet_loss: b.candidate(Label.network_packet_loss, A, met=("PL.R1",),
                                                                   supporting=(loss.item_id,)),
                            Label.tcp_retransmissions: b.candidate(Label.tcp_retransmissions, CONTRIB,
                                                                   met=b.all_met(Label.tcp_retransmissions))})
        with self.assertRaises(ContractViolation) as cm:
            validate_against_snapshot(r, snap)
        self.assertEqual(cm.exception.invariant, "I4")


class TestI3I5(unittest.TestCase):
    def test_I3_missing_item_cannot_be_listed_as_supporting(self):
        frac = b.meas("tcp.retrans_frac", "netns:A", None, quality=b.Quality.MISSING, coverage=0.0)
        miss = b.item("RT.R1", MISS, [frac])
        snap = b.snapshot([frac], [miss])
        r = b.result(snap, cands={Label.tcp_retransmissions: b.candidate(Label.tcp_retransmissions,
                                                                         CandidateStatus.NOT_EVALUABLE,
                                                                         supporting=(miss.item_id,))})
        with self.assertRaises(ContractViolation) as cm:
            validate_against_snapshot(r, snap)
        self.assertEqual(cm.exception.invariant, "I3")

    def test_I5_references_must_resolve(self):
        snap = b.snapshot()
        r = b.result(snap, cands={Label.cpu_contention: b.candidate(Label.cpu_contention,
                                                                    supporting=("0123456789abcdef",))})
        with self.assertRaises(ContractViolation) as cm:
            validate_against_snapshot(r, snap)
        self.assertEqual(cm.exception.invariant, "I5")

    def test_I5_result_must_belong_to_snapshot(self):
        s1 = b.snapshot()
        s2 = b.snapshot([b.meas("cpu.util.host", "host", 0.5)])
        with self.assertRaises(ContractViolation):
            validate_against_snapshot(b.result(s1), s2)


class TestI6ApplicationBottleneck(unittest.TestCase):
    """Phase 1B residual-sink failure: application_bottleneck must never follow from elimination."""

    def _infra_evaluated_item(self):
        cpu = b.meas("cpu.util.cpuset", "cpuset", 0.3)
        return cpu, b.item("AB.R3/EVALUATED[family:cpu_sched]", POS, [cpu], supports=[Label.application_bottleneck])

    def test_impact_features_cannot_be_application_cause_evidence(self):
        lat = b.meas("app.latency_ms", "app:A", 900.0)
        err = b.meas("app.error_rate", "app:A", 0.2)
        for m in (lat, err):
            it = b.item("AB.R1", POS, [m], supports=[Label.application_bottleneck])
            with self.subTest(feature=m.feature_id), self.assertRaises(ValidationError):
                b.snapshot([m], [it])

    def test_kernel_normal_alone_cannot_assert_application_bottleneck(self):
        cpu, ev = self._infra_evaluated_item()
        lat = b.meas("app.latency_ms", "app:A", 900.0)
        share = b.item("AB.R2", POS, [lat], supports=[Label.application_bottleneck])
        snap = b.snapshot([cpu, lat], [ev, share])   # no AB.R1 positive application-saturation evidence
        r = b.result(snap, Label.application_bottleneck,
                     cands={Label.application_bottleneck: b.candidate(Label.application_bottleneck, A,
                                                                      met=b.all_met(Label.application_bottleneck))})
        with self.assertRaises(ContractViolation) as cm:
            validate_against_snapshot(r, snap)
        self.assertIn("AB.R1", str(cm.exception))

    def test_positive_application_evidence_is_accepted(self):
        cpu, ev = self._infra_evaluated_item()
        qw = b.meas("app.queue_wait_ms", "app:A", 450.0)
        lat = b.meas("app.latency_ms", "app:A", 900.0)
        items = [b.item("AB.R1", POS, [qw], supports=[Label.application_bottleneck]),
                 b.item("AB.R2", POS, [lat, qw], supports=[Label.application_bottleneck]), ev]
        snap = b.snapshot([cpu, qw, lat], items)
        r = b.result(snap, Label.application_bottleneck,
                     cands={Label.application_bottleneck: b.candidate(Label.application_bottleneck, A,
                                                                      met=b.all_met(Label.application_bottleneck),
                                                                      supporting=tuple(i.item_id for i in items))})
        validate_against_snapshot(r, snap)

    def test_not_assertable_while_infrastructure_cause_asserted(self):
        cpu, ev = self._infra_evaluated_item()
        qw = b.meas("app.queue_wait_ms", "app:A", 450.0)
        lat = b.meas("app.latency_ms", "app:A", 900.0)
        quota = b.meas("throttle.quota_limited", "cgroup:/lab", 1.0, base=None)   # v0.2.0 R-1: CT.R1
        ratio = b.meas("throttle.ratio", "cgroup:/lab", 0.8)
        trate = b.meas("throttle.time_rate", "cgroup:/lab", 0.6)
        items = [b.item("AB.R1", POS, [qw], supports=[Label.application_bottleneck]),
                 b.item("AB.R2", POS, [lat, qw], supports=[Label.application_bottleneck]), ev,
                 b.item("CT.R1", POS, [quota], supports=[Label.cpu_throttling]),
                 b.item("CT.R2", POS, [ratio, trate], supports=[Label.cpu_throttling])]
        snap = b.snapshot([cpu, qw, lat, quota, ratio, trate], items)
        r = b.result(snap, Label.cpu_throttling, contributing=(Label.application_bottleneck,),
                     cands={Label.cpu_throttling: b.candidate(Label.cpu_throttling, A, met=b.all_met(Label.cpu_throttling)),
                            Label.application_bottleneck: b.candidate(Label.application_bottleneck, CONTRIB,
                                                                      met=b.all_met(Label.application_bottleneck))})
        with self.assertRaises(ContractViolation) as cm:   # AB.R3: an infrastructure label is asserted
            validate_against_snapshot(r, snap)
        self.assertIn("AB.R3", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
