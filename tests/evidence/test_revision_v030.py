"""Contract revision v0.3.0-draft: C-1 (RT.R2 is a Primary clause; tcp_retransmissions may be CONTRIBUTING
under PR-1 when local loss is proven) and C-3 (AB.R3 features include throttle.quota_limited)."""

import json
import unittest

from pydantic import ValidationError

from sentinelai.diagnostic.contract import (CandidateStatus, ContractViolation, EvidenceKind, Label, load_contract,
                                            validate_against_snapshot)
from sentinelai.diagnostic.contract.catalog import DATA, Clause, LabelContracts
from sentinelai.diagnostic.contract.version import CONTRACT_VERSION, SCHEMA_VERSION, require_compatible

from . import _builders as b

C = load_contract()
A, CONTRIB = CandidateStatus.ASSERTED, CandidateStatus.CONTRIBUTING
POS, NEG = EvidenceKind.POSITIVE, EvidenceKind.NEGATIVE
TCP, LOSS = Label.tcp_retransmissions, Label.network_packet_loss
INFRA = (Label.cpu_contention, Label.cpu_throttling, Label.softirq_overload, LOSS, TCP, Label.memory_pressure)


class TestClauseRoles(unittest.TestCase):
    def test_rt_r2_is_primary_with_declared_subordination(self):
        rt2 = C.labels.clause("RT.R2")
        self.assertEqual(rt2.role, "primary")
        self.assertEqual((rt2.subordinate.rule, rt2.subordinate.primary), ("PR-1", LOSS))
        self.assertEqual([c.kind for c in rt2.components], ["POSITIVE", "NEGATIVE"])   # predicate unchanged

    def test_clause_sets(self):
        ids = lambda cs: {c.clause_id for c in cs}
        self.assertEqual(ids(C.labels.required_clauses(TCP)), {"RT.R0", "RT.R1", "RT.R2"})
        self.assertEqual(ids(C.labels.contributing_clauses(TCP)), {"RT.R0", "RT.R1"})
        self.assertEqual(ids(C.labels.primary_clauses(TCP)), {"RT.R2"})
        for lab in set(Label) - {Label.INSUFFICIENT_EVIDENCE, TCP}:
            with self.subTest(label=lab.value):
                self.assertEqual(C.labels.primary_clauses(lab), ())
                self.assertEqual(C.labels.required_clauses(lab), C.labels.contributing_clauses(lab))

    def test_subordination_rules(self):
        base = C.labels.clause("RT.R2").model_dump(mode="json")
        clause = lambda d: Clause.model_validate_json(json.dumps(d), strict=False)   # as the loader parses data
        clause(base)
        with self.assertRaises(ValidationError):   # only a Primary clause may be subordinate
            clause({**base, "role": "required"})
        with self.assertRaises(ValidationError):   # a Primary clause must declare its subordination
            clause({**base, "subordinate": None})
        with self.assertRaises(ValidationError):   # not to itself
            clause({**base, "subordinate": {"rule": "PR-1", "primary": "tcp_retransmissions"}})
        data = json.loads((DATA / "labels.json").read_text(encoding="utf-8"))
        LabelContracts.model_validate_json(json.dumps(data), strict=False)
        for bad in ({"rule": "PR-9", "primary": "network_packet_loss"},    # unknown rule
                    {"rule": "PR-3", "primary": "network_packet_loss"}):   # rule does not relate the pair
            d = json.loads(json.dumps(data))
            next(c for c in d["clauses"] if c["clause_id"] == "RT.R2")["subordinate"] = bad
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                LabelContracts.model_validate_json(json.dumps(d), strict=False)


def _tcp_items(rt2_negative=True):
    segs = b.meas("tcp.out_segs_rate", "netns:A", 4000.0, base=None)
    frac = b.meas("tcp.retrans_frac", "netns:A", 0.08)
    qd = b.meas("net.drop.qdisc", "iface:A/eth0", 900.0)
    loss = b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", POS, [qd], supports=[LOSS])
    items = [loss, b.item("RT.R0", POS, [segs], supports=[TCP]), b.item("RT.R1", POS, [frac], supports=[TCP])]
    if rt2_negative:
        items.append(b.item("RT.R2", NEG, [qd], contradicts=[TCP]))
    return [segs, frac, qd], items


def _result(snap, items, decision=LOSS, tcp_met=("RT.R0", "RT.R1")):
    sup = lambda lab: tuple(i.item_id for i in items if i.kind is POS and lab in i.supports)
    cands = {TCP: b.candidate(TCP, CONTRIB, met=tcp_met, supporting=sup(TCP))}
    if decision is LOSS:
        cands[LOSS] = b.candidate(LOSS, A, met=("PL.R1",), supporting=sup(LOSS))
    return b.result(snap, decision, cands=cands, contributing=(TCP,))


class TestContributingSubordinate(unittest.TestCase):
    def test_backed_pr1_contribution_passes(self):
        ms, items = _tcp_items()
        snap = b.snapshot(ms, items)
        validate_against_snapshot(_result(snap, items), snap)

    def test_primary_clause_must_be_shown_false(self):
        ms, items = _tcp_items(rt2_negative=False)
        snap = b.snapshot(ms, items)
        with self.assertRaises(ContractViolation) as cm:
            validate_against_snapshot(_result(snap, items), snap)
        self.assertEqual(cm.exception.invariant, "I4")
        self.assertIn("no NEGATIVE RT.R2 item", str(cm.exception))

    def test_only_under_the_declared_primary(self):
        ms, items = _tcp_items()
        snap = b.snapshot(ms, items)
        mp = Label.memory_pressure   # validated after tcp_retransmissions, so the tcp check is what fires
        r = b.result(snap, mp, contributing=(TCP,),
                     cands={TCP: b.candidate(TCP, CONTRIB, met=("RT.R0", "RT.R1")),
                            mp: b.candidate(mp, A, met=b.all_met(mp))})
        with self.assertRaises(ContractViolation) as cm:
            validate_against_snapshot(r, snap)
        self.assertIn("declared subordinate of the decision", str(cm.exception))

    def test_required_clauses_still_required_for_contributing(self):
        with self.assertRaises(ValidationError):   # RT.R1 missing: never CONTRIBUTING
            b.candidate(TCP, CONTRIB, met=("RT.R0",))
        ms, items = _tcp_items()
        items = [i for i in items if i.predicate_id != "RT.R1"]
        snap = b.snapshot(ms, items)
        with self.assertRaises(ContractViolation) as cm:   # claimed met, but no RT.R1 item
            validate_against_snapshot(_result(snap, items), snap)
        self.assertEqual(cm.exception.invariant, "I4")
        self.assertIn("RT.R1", str(cm.exception))

    def test_asserted_still_needs_primary_clause(self):
        with self.assertRaises(ValidationError):
            b.candidate(TCP, A, met=("RT.R0", "RT.R1"))


class TestC3AbR3Features(unittest.TestCase):
    def test_quota_limited_in_ab_r3(self):
        self.assertIn("throttle.quota_limited", C.labels.clause("AB.R3").features)

    def test_ab_r3_covers_every_infrastructure_clause_feature(self):
        ab = set(C.labels.clause("AB.R3").features)
        for lab in INFRA:
            for cl in C.labels.required_clauses(lab):
                with self.subTest(clause=cl.clause_id):
                    self.assertLessEqual(set(cl.features), ab)


class TestVersion(unittest.TestCase):
    def test_versions(self):
        # v0.4.0-draft (M3B-C0) only adds features; the v0.3.0 C-1/C-3 content tested above is retained
        self.assertEqual((CONTRACT_VERSION, SCHEMA_VERSION), ("0.4.0-draft", "0.2.0"))
        for part in (C.registry, C.labels):
            self.assertEqual(part.contract_version, "0.4.0-draft")

    def test_v020_snapshots_still_accepted(self):
        self.assertEqual(require_compatible("0.2.0-draft"), "0.2.0-draft")
        b.snapshot([b.meas("cpu.util.host", "host", 0.5, base=None)])   # builders emit 0.2.0-draft snapshots


if __name__ == "__main__":
    unittest.main()
