"""Every engine output satisfies I1-I7 and the item construction rules, across a scenario matrix."""

import unittest

from sentinelai.diagnostic.contract import CandidateStatus as S, EvidenceKind as K, Label as L, load_contract
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.diagnostic.contract.validate import validate_against_snapshot
from sentinelai.diagnostic.contract.ids import evidence_item_id

from ._fixtures import (Quality, app_wait, contention, kfree_drops, m, memory, no_drop_counters, qdisc_drops, retrans,
                        run, scenario, softirq, throttling)
from .test_determinism import SCENARIOS

C = load_contract()
MATRIX = dict(SCENARIOS, adv2=scenario(retrans(), no_drop_counters()), throttling=scenario(throttling()),
              noise=scenario(kfree_drops("NOT_SPECIFIED", 3.0, 3.0)), mem=scenario(memory()),
              gate=scenario(contention()))


class TestInvariantsAcrossScenarios(unittest.TestCase):
    def test_validate_round_trip(self):
        for name, ms in MATRIX.items():
            d = run(ms, gate=(name != "gate"))
            with self.subTest(name):
                validate_against_snapshot(d.result, d.snapshot)        # I1-I6 + structural rules
                r2 = type(d.result).model_validate_json(canonical_bytes(d.result))
                self.assertEqual(canonical_bytes(r2), canonical_bytes(d.result))   # I7

    def test_item_construction(self):
        by_id = None
        for name, ms in MATRIX.items():
            d = run(ms)
            by_id = {x.measurement_id: x for x in d.snapshot.measurements}
            for i in d.snapshot.evidence_items:
                with self.subTest(name=name, item=i.predicate_id):
                    self.assertEqual(i.item_id, evidence_item_id(i.predicate_id, i.measurement_ids))
                    if i.kind is not K.POSITIVE:
                        self.assertEqual(i.supports, ())                     # I3
                    if i.kind in (K.POSITIVE, K.NEGATIVE):
                        for mid in i.measurement_ids:
                            self.assertIn(by_id[mid].quality, (Quality.OK, Quality.PARTIAL))
                    self.assertTrue(i.measurement_ids)

    def test_i6_application_needs_positive_app_evidence(self):
        d = run(scenario(app_wait()))
        self.assertIs(d.result.decision, L.application_bottleneck)
        by_id = {x.measurement_id: x for x in d.snapshot.measurements}
        app = [i for i in d.snapshot.evidence_items if i.kind is K.POSITIVE and L.application_bottleneck in i.supports
               and any(by_id[x].feature_id.startswith("app.") and by_id[x].feature_id != "app.latency_ms"
                       for x in i.measurement_ids)]
        self.assertTrue(app)

    def test_candidate_partition_and_rules(self):
        for name, ms in MATRIX.items():
            r = run(ms).result
            for c in r.candidates:
                req = {cl.clause_id for cl in C.labels.required_clauses(c.label)}
                with self.subTest(name=name, label=c.label.value):
                    self.assertEqual(set(c.required_met) | set(c.required_missing), req)
                    self.assertFalse(set(c.required_met) & set(c.required_missing))
                    if c.status is S.ASSERTED:
                        self.assertEqual(c.required_missing, ())
                    if c.status is S.CONTRIBUTING:   # v0.3.0: only an unmet Primary clause, as a declared subordinate
                        prim = {cl.clause_id for cl in C.labels.primary_clauses(c.label)}
                        self.assertLessEqual(set(c.required_missing), prim)
                        for cl in C.labels.primary_clauses(c.label):
                            if cl.clause_id in c.required_missing:
                                self.assertIs(r.decision, cl.subordinate.primary)
                    self.assertNotEqual(c.status, S.CONTRADICTED)   # unused by M2 (report §10)
            self.assertEqual(len(r.candidates), 7)


if __name__ == "__main__":
    unittest.main()
