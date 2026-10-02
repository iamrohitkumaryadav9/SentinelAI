"""DiagnosticResult / Candidate / MLAdvisory / EngineInfo (contract §10.6, §10.7 I1, I2, I4 structural)."""

import unittest

from pydantic import ValidationError

from sentinelai.diagnostic.contract import (FAULT_LABELS, AbstentionReason, CandidateStatus, ConfidenceLevel,
                                            EngineInfo, Label, MLAdvisory)

from . import _builders as b

SNAP = b.snapshot()
A = CandidateStatus.ASSERTED


def asserted(label):
    return b.candidate(label, A, met=b.all_met(label))


class TestI1(unittest.TestCase):
    def test_valid_abstention(self):
        r = b.result(SNAP)
        self.assertTrue(r.abstained)

    def test_equivalences(self):
        cases = [
            dict(decision=Label.INSUFFICIENT_EVIDENCE, abstained=False),
            dict(decision=Label.cpu_throttling, abstained=True),
            dict(abstention_reasons=()),
        ]
        base = b.result(SNAP)
        for ch in cases:
            with self.subTest(change=ch), self.assertRaises(ValidationError):
                b.rebuild(base, **ch)
        ok = b.result(SNAP, Label.cpu_throttling, cands={Label.cpu_throttling: asserted(Label.cpu_throttling)})
        with self.assertRaises(ValidationError):  # reasons without abstention
            b.rebuild(ok, abstention_reasons=(AbstentionReason.NO_CANDIDATE,))


class TestCandidates(unittest.TestCase):
    def test_exactly_seven_fault_candidates(self):
        base = b.result(SNAP)
        with self.assertRaises(ValidationError):
            b.rebuild(base, candidates=base.candidates[:-1])
        with self.assertRaises(ValidationError):
            b.rebuild(base, candidates=base.candidates + (base.candidates[0],))
        with self.assertRaises(ValidationError):
            b.candidate(Label.INSUFFICIENT_EVIDENCE)

    def test_required_partition(self):
        with self.assertRaises(ValidationError):  # met + missing must cover all required clauses
            b.rebuild(b.candidate(Label.tcp_retransmissions), required_missing=("RT.R0",))
        with self.assertRaises(ValidationError):  # foreign clause
            b.rebuild(b.candidate(Label.tcp_retransmissions), required_met=("CC.R1",))

    def test_I4_structural_asserted_requires_all_required_met(self):
        with self.assertRaises(ValidationError):
            b.candidate(Label.tcp_retransmissions, A, met=("RT.R0", "RT.R1"))
        with self.assertRaises(ValidationError):
            b.candidate(Label.tcp_retransmissions, CandidateStatus.CONTRIBUTING, met=("RT.R1",))
        with self.assertRaises(ValidationError):  # NOT_SUPPORTED with everything met is contradictory
            b.candidate(Label.network_packet_loss, CandidateStatus.NOT_SUPPORTED, met=("PL.R1",))

    def test_rules_fired_belong_to_label(self):
        with self.assertRaises(ValidationError):
            b.candidate(Label.cpu_contention, rules=("CT.R2",))
        b.candidate(Label.cpu_contention, rules=("CC.X1",))


class TestDecisionStructure(unittest.TestCase):
    def test_I2_structural_decision_candidate_must_be_asserted(self):
        with self.assertRaises(ValidationError):
            b.result(SNAP, Label.cpu_throttling)

    def test_single_asserted_candidate(self):
        with self.assertRaises(ValidationError):
            b.result(SNAP, Label.network_packet_loss,
                     cands={Label.network_packet_loss: asserted(Label.network_packet_loss),
                            Label.tcp_retransmissions: asserted(Label.tcp_retransmissions)})

    def test_contributing_consistency(self):
        c = {Label.network_packet_loss: asserted(Label.network_packet_loss),
             Label.tcp_retransmissions: b.candidate(Label.tcp_retransmissions, CandidateStatus.CONTRIBUTING,
                                                    met=b.all_met(Label.tcp_retransmissions))}
        ok = b.result(SNAP, Label.network_packet_loss, cands=c, contributing=(Label.tcp_retransmissions,))
        self.assertEqual(ok.contributing, (Label.tcp_retransmissions,))
        with self.assertRaises(ValidationError):
            b.result(SNAP, Label.network_packet_loss, cands=c, contributing=())
        with self.assertRaises(ValidationError):
            b.rebuild(b.result(SNAP), contributing=(Label.cpu_contention,))

    def test_confidence_is_ordinal_not_probability(self):
        with self.assertRaises(ValidationError):
            b.rebuild(b.result(SNAP), confidence_level=0.9)
        with self.assertRaises(ValidationError):  # asserted decision is never LOW
            b.result(SNAP, Label.cpu_throttling, cands={Label.cpu_throttling: asserted(Label.cpu_throttling)},
                     confidence=ConfidenceLevel.LOW)

    def test_rules_fired_known(self):
        with self.assertRaises(ValidationError):
            b.result(SNAP, rules=("ZZ.R1",))

    def test_snapshot_id_format(self):
        with self.assertRaises(ValidationError):
            b.rebuild(b.result(SNAP), snapshot_id="not-an-id")


class TestMLAdvisory(unittest.TestCase):
    P = {Label.cpu_throttling: 0.7, Label.cpu_contention: 0.3}

    def test_ml_has_no_decision_field(self):
        with self.assertRaises(ValidationError):
            MLAdvisory(model_id="m", probabilities=self.P, calibrated=True, agrees_with_rules=False,
                       decision=Label.cpu_throttling)

    def test_probabilities(self):
        with self.assertRaises(ValidationError):
            MLAdvisory(model_id="m", probabilities={Label.cpu_throttling: 0.7}, calibrated=True, agrees_with_rules=False)
        with self.assertRaises(ValidationError):
            MLAdvisory(model_id="m", probabilities={Label.cpu_throttling: 1.2, Label.cpu_contention: -0.2},
                       calibrated=True, agrees_with_rules=False)

    def test_ml_disagreement_does_not_change_decision(self):
        ml = MLAdvisory(model_id="m", probabilities=self.P, calibrated=True, agrees_with_rules=False)
        r = b.result(SNAP, ml=ml)
        self.assertIs(r.decision, Label.INSUFFICIENT_EVIDENCE)  # ML top label is cpu_throttling; rules decide
        with self.assertRaises(ValidationError):  # cannot claim agreement that is false
            b.result(SNAP, ml=MLAdvisory(model_id="m", probabilities=self.P, calibrated=True, agrees_with_rules=True))


class TestEngineInfo(unittest.TestCase):
    def test_engine(self):
        for ch in ({"code_commit": "HEAD"}, {"contract_version": "2.0.0"}, {"rules_version": ""}):
            with self.subTest(ch=ch), self.assertRaises(ValidationError):
                EngineInfo(**{**b.ENGINE.model_dump(), **ch})


if __name__ == "__main__":
    unittest.main()
