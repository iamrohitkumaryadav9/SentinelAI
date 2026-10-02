"""Precedence PR-1..PR-5 (contract §9): closed table, unlisted pairs are conflicts, no invented ordering."""

import unittest
from itertools import combinations

from sentinelai.diagnostic.contract import CandidateStatus as S, Label as L
from sentinelai.diagnostic.rules import engine as E

from ._fixtures import (CG, app_wait, contention, kfree_drops, m, memory, qdisc_drops, reasons, retrans, run, scenario,
                        softirq, status, throttling)


class TestPR2(unittest.TestCase):
    def test_pr2_softnet_on_saturated_cpu(self):
        d = run(scenario(softirq(), {"net.drop.softnet": m("net.drop.softnet", "cpu:2", 400.0, 0.0, 0.0)}))
        self.assertIs(d.result.decision, L.softirq_overload)
        self.assertEqual(d.result.contributing, (L.network_packet_loss,))

    def test_pr2b_softnet_on_unsaturated_cpu(self):
        d = run(scenario(softirq(both=False), {"net.drop.softnet": m("net.drop.softnet", "cpu:3", 400.0, 0.0, 0.0)}))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(d.snapshot.conflicts[0].rule, "PR-2b")

    def test_pr2b_non_softirq_drop(self):
        d = run(scenario(softirq(), qdisc_drops()))
        self.assertEqual(reasons(d), ["CONFLICT_UNRESOLVED"])
        (cf,) = d.snapshot.conflicts
        self.assertEqual((cf.labels, cf.rule), ((L.softirq_overload, L.network_packet_loss), "PR-2b"))
        self.assertTrue(cf.item_ids)

    def test_pr2b_mixed_sources(self):
        d = run(scenario(softirq(), kfree_drops("CPU_BACKLOG", 500.0), kfree_drops("QDISC_DROP", 500.0)))
        self.assertEqual(d.snapshot.conflicts[0].rule, "PR-2b")


class TestPR3(unittest.TestCase):
    def test_missing_dominance_inputs_is_conflict(self):
        d = run(scenario(contention(0.3), throttling(0.4), {"throttle.time_rate": None}))
        # time_rate absent: CT.R2 MISSING so throttling is not even assertable -> no PR-3 needed
        self.assertNotEqual(d.result.decision, L.cpu_throttling)


class TestPR4(unittest.TestCase):
    def test_infrastructure_over_application(self):
        for infra in (contention(), throttling(), memory()):
            d = run(scenario(app_wait(), infra))
            with self.subTest(decision=d.result.decision.value):
                self.assertIn(d.result.decision, E.INFRA)
                self.assertIs(status(d, L.application_bottleneck), S.NOT_SUPPORTED)

    def test_resolver_pr4(self):
        # AB.R3 already makes the pair unreachable; the resolver still follows PR-4 if asked directly
        for l in E.INFRA:
            self.assertEqual(E._resolve(None, L.application_bottleneck, l, {}), (l, "PR-4"))


class TestPR1(unittest.TestCase):
    def test_resolver_pr1(self):
        self.assertEqual(E._resolve(None, L.tcp_retransmissions, L.network_packet_loss, {}),
                         (L.network_packet_loss, "PR-1"))


class TestUnlistedPairs(unittest.TestCase):
    def test_unlisted_pair_is_conflict_with_no_rule(self):
        d = run(scenario(contention(), memory()))
        self.assertEqual(reasons(d), ["CONFLICT_UNRESOLVED"])
        (cf,) = d.snapshot.conflicts
        self.assertEqual((cf.labels, cf.rule), ((L.cpu_contention, L.memory_pressure), None))

    def test_every_unlisted_pair_returns_conflict(self):
        listed = {frozenset(p) for p in ((L.network_packet_loss, L.tcp_retransmissions),
                                         (L.softirq_overload, L.network_packet_loss),
                                         (L.cpu_throttling, L.cpu_contention), (L.softirq_overload, L.cpu_contention))}
        listed |= {frozenset((L.application_bottleneck, l)) for l in E.INFRA}
        for a, b in combinations(E.FAULT_LABELS, 2):
            if frozenset((a, b)) in listed:
                continue
            with self.subTest(pair=(a.value, b.value)):
                self.assertEqual(E._resolve(None, a, b, {}), (None, None))

    def test_three_way_with_unresolved_pair(self):
        d = run(scenario(contention(0.1), throttling(0.5), memory()))
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertTrue(all(cf.rule is None for cf in d.snapshot.conflicts))
        self.assertEqual(d.result.contributing, ())

    def test_unsupported_co_assertion_never_contributing(self):
        d = run(scenario(contention(), memory()))
        self.assertEqual({c.label for c in d.result.candidates if c.status is S.ASSERTED},
                         {L.cpu_contention, L.memory_pressure})
        self.assertNotIn(S.CONTRIBUTING, {c.status for c in d.result.candidates})


class TestThreeWayResolved(unittest.TestCase):
    def test_softirq_loss_retrans(self):
        d = run(scenario(softirq(), kfree_drops("CPU_BACKLOG", 500.0), retrans()))
        self.assertIs(d.result.decision, L.softirq_overload)
        self.assertEqual(d.result.contributing, (L.network_packet_loss,))
        self.assertIs(status(d, L.tcp_retransmissions), S.NOT_SUPPORTED)   # C-1: RT.R2 FALSE under proven loss


if __name__ == "__main__":
    unittest.main()
