"""EvidenceItem model (contract §3, §10.4)."""

import unittest

from pydantic import ValidationError

from sentinelai.diagnostic.contract import EvidenceItem, EvidenceKind, Label, Strength, Threshold, evidence_item_id

from . import _builders as b

QD = b.meas("net.drop.qdisc", "iface:A/eth0", 500.0)
RT = b.meas("tcp.retrans_frac", "netns:A", 0.08)


class TestEvidenceItem(unittest.TestCase):
    def test_valid_positive(self):
        it = b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.POSITIVE, [QD], supports=[Label.network_packet_loss])
        self.assertEqual(it.supports, (Label.network_packet_loss,))

    def test_strength_rules(self):
        with self.assertRaises(ValidationError):  # POSITIVE requires a strength
            b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.POSITIVE, [QD],
                   supports=[Label.network_packet_loss], strength=None)
        with self.assertRaises(ValidationError):  # MISSING must not carry a strength
            b.item("RT.R1", EvidenceKind.MISSING, [RT], strength=Strength.WEAK)

    def test_missing_reason_exactly_for_missing(self):
        it = b.item("RT.R1", EvidenceKind.MISSING, [RT])
        with self.assertRaises(ValidationError):
            b.rebuild(it, missing_reason=None)
        with self.assertRaises(ValidationError):
            b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.POSITIVE, [QD],
                   supports=[Label.network_packet_loss], missing_reason="n/a")

    def test_I3_missing_never_supports(self):
        with self.assertRaises(ValidationError):
            b.item("RT.R1", EvidenceKind.MISSING, [RT], supports=[Label.tcp_retransmissions])

    def test_negative_never_supports(self):
        with self.assertRaises(ValidationError):
            b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.NEGATIVE, [QD], supports=[Label.tcp_retransmissions])
        ok = b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.NEGATIVE, [QD], contradicts=[Label.network_packet_loss])
        self.assertEqual(ok.supports, ())

    def test_positive_must_support_something(self):
        with self.assertRaises(ValidationError):
            b.item("DEV[tcp.retrans_frac]", EvidenceKind.POSITIVE, [RT])

    def test_required_clause_positive_supports_its_label(self):
        with self.assertRaises(ValidationError):
            b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.POSITIVE, [QD], supports=[Label.tcp_retransmissions])

    def test_contradictory_clause_positive_contradicts_its_label(self):
        th = b.meas("throttle.ratio", "cgroup:/lab", 0.7)
        with self.assertRaises(ValidationError):
            b.item("CC.X1", EvidenceKind.POSITIVE, [th], supports=[Label.cpu_throttling])
        ok = b.item("CC.X1", EvidenceKind.POSITIVE, [th], supports=[Label.cpu_throttling],
                    contradicts=[Label.cpu_contention])
        self.assertIn(Label.cpu_contention, ok.contradicts)

    def test_insufficient_evidence_is_not_a_supportable_label(self):
        with self.assertRaises(ValidationError):
            b.item("DEV[tcp.retrans_frac]", EvidenceKind.POSITIVE, [RT], supports=[Label.INSUFFICIENT_EVIDENCE])

    def test_supports_and_contradicts_disjoint(self):
        with self.assertRaises(ValidationError):
            b.item("DEV[tcp.retrans_frac]", EvidenceKind.POSITIVE, [RT], supports=[Label.tcp_retransmissions],
                   contradicts=[Label.tcp_retransmissions])

    def test_free_text_rationale_rejected(self):
        it = b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.POSITIVE, [QD], supports=[Label.network_packet_loss])
        for text in ("Packets are clearly being dropped.", "LLM: I believe this is packet loss", it.rationale + " "):
            with self.subTest(text=text), self.assertRaises(ValidationError):
                b.rebuild(it, rationale=text)

    def test_rationale_reflects_fields(self):
        it = b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.POSITIVE, [QD], supports=[Label.network_packet_loss],
                    observed=500.0, threshold=Threshold(parameter="DROP_ABS_MIN", value=7.0))
        self.assertIn("predicate=PL.R1/LOSS.LOCAL[net.drop.qdisc]", it.rationale)
        self.assertIn("DROP_ABS_MIN=7.0", it.rationale)  # 7.0 is a test value, not a contract threshold
        with self.assertRaises(ValidationError):  # changing observed without re-rendering is caught
            b.rebuild(it, observed=1.0)

    def test_deterministic_item_id_enforced(self):
        it = b.item("DEV[tcp.retrans_frac]", EvidenceKind.POSITIVE, [RT], supports=[Label.tcp_retransmissions])
        with self.assertRaises(ValidationError):
            b.rebuild(it, item_id="0000000000000000")

    def test_measurement_ids_non_empty_unique(self):
        it = b.item("DEV[tcp.retrans_frac]", EvidenceKind.POSITIVE, [RT], supports=[Label.tcp_retransmissions])
        with self.assertRaises(ValidationError):
            b.rebuild(it, measurement_ids=())
        mids = (RT.measurement_id, RT.measurement_id)
        with self.assertRaises(ValidationError):
            b.rebuild(it, measurement_ids=mids, item_id=evidence_item_id(it.predicate_id, mids))

    def test_malformed_or_unknown_predicates(self):
        for pid in ("XX.R1", "CC.R9", "PL.R1/LOSS.LOCAL[cpu.util.host]", "DEV", "DEV[not.a.feature]",
                    "EVALUATED", "packet loss detected", "PL.R1/MAGIC"):
            with self.subTest(pid=pid), self.assertRaises(Exception):
                b.item(pid, EvidenceKind.POSITIVE, [QD], supports=[Label.network_packet_loss])

    def test_threshold_parameter_must_be_symbolic_contract_parameter(self):
        with self.assertRaises(ValidationError):
            Threshold(parameter="MY_MAGIC_THRESHOLD", value=1.0)
        Threshold(parameter="floor[net.drop.qdisc]", value=1.0)
        with self.assertRaises(ValidationError):
            Threshold(parameter="floor[not.a.feature]", value=1.0)
        with self.assertRaises(ValidationError):
            Threshold(parameter="DROP_ABS_MIN", value=float("inf"))


if __name__ == "__main__":
    unittest.main()
