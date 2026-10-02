"""Pure, deterministic API: replay, permutation, scope binding, input immutability, no I/O in engine code."""

import random
import re
import unittest
from pathlib import Path

from sentinelai.diagnostic.contract import Label as L
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.diagnostic.rules import diagnose

from ._fixtures import (CG, COMMIT, app_wait, contention, kfree_drops, m, memory, params, qdisc_drops, retrans, run,
                        scenario, snapshot, softirq, throttling)

SCENARIOS = {
    "normal": scenario(), "contention": scenario(contention()), "adv4": scenario(softirq(), kfree_drops("CPU_BACKLOG", 500.0)),
    "adv5": scenario(retrans(), qdisc_drops()), "adv7": scenario(app_wait()),
    "adv9": scenario(contention(0.3), throttling(0.4)), "adv10": scenario(contention(), softirq()),
    "unlisted": scenario(contention(), memory()),
}


def blob(d):
    return canonical_bytes(d.result) + b"|" + canonical_bytes(d.snapshot)


class TestReplay(unittest.TestCase):
    def test_a_eq_b_eq_c(self):
        for name, ms in SCENARIOS.items():
            with self.subTest(name):
                a, b, c = (blob(run(ms)) for _ in range(3))
                self.assertEqual(a, b)
                self.assertEqual(b, c)

    def test_fresh_parameter_objects_same_bytes(self):
        snap = snapshot(SCENARIOS["adv10"])
        self.assertEqual(blob(diagnose(snap, params(), code_commit=COMMIT)),
                         blob(diagnose(snap, params(), code_commit=COMMIT)))


class TestPermutation(unittest.TestCase):
    def test_measurement_order_irrelevant(self):
        rng = random.Random(1234)
        for name, ms in SCENARIOS.items():
            ref = blob(run(ms))
            for k in range(5):
                shuffled = list(ms)
                rng.shuffle(shuffled)
                with self.subTest(name=name, k=k):
                    self.assertEqual(blob(run(shuffled)), ref)


class TestScopeBinding(unittest.TestCase):
    def test_other_targets_are_ignored(self):
        foreign = [m("sched.run_delay_excess.target", "cgroup:/lab/B", 5.0, 0.02, 0.005,
                     derived_from=tuple(x.measurement_id for x in (m("sched.run_delay.target", CG, 0.0),
                                                                   m("throttle.time_rate", CG, 0.0)))),
                   m("softirq.frac.percpu", "cpu:7", 0.9, 0.05, 0.01),
                   m("net.drop.qdisc", "iface:B/eth0", 900.0, 0.0, 0.0)]
        a, b = run(scenario()), run(scenario() + foreign)
        self.assertEqual(a.result.decision, b.result.decision)
        self.assertEqual(canonical_bytes(a.result.candidates), canonical_bytes(b.result.candidates))
        used = {mid for i in b.snapshot.evidence_items for mid in i.measurement_ids}
        self.assertFalse(used & {x.measurement_id for x in foreign})


class TestPurity(unittest.TestCase):
    def test_input_snapshot_unchanged(self):
        snap = snapshot(SCENARIOS["adv4"])
        before = canonical_bytes(snap)
        d = diagnose(snap, params(), code_commit=COMMIT)
        self.assertEqual(canonical_bytes(snap), before)
        self.assertEqual(snap.evidence_items, ())
        self.assertEqual(d.snapshot.measurements, snap.measurements)
        self.assertEqual(d.result.snapshot_id, snap.snapshot_id)

    def test_engine_has_no_io_clock_randomness_or_llm(self):
        src = "".join(p.read_text() for p in sorted((Path(__file__).resolve().parents[2] / "src/sentinelai/diagnostic/rules")
                                                   .glob("*.py")))
        imports = re.findall(r"^\s*(?:import|from)\s+([\w.]+)", src, re.M)
        allowed = ("__future__", "dataclasses", "enum", "itertools", "re", "typing", "pydantic")
        self.assertEqual([i for i in imports if i not in allowed and not i.startswith(".")], [])
        self.assertEqual(re.findall(r"\b(?:open|eval|exec|print)\(|datetime\.now|time\.time|os\.environ", src), [])

    def test_engine_info(self):
        e = run(SCENARIOS["contention"]).result.engine
        self.assertEqual((e.contract_version, e.parameter_set_id, e.code_commit), ("0.3.0-draft", "test-params-m2", COMMIT))
        self.assertTrue(e.rules_version)


class TestDuplicates(unittest.TestCase):
    def test_duplicate_measurement_rejected_by_snapshot(self):
        ms = scenario()
        with self.assertRaises(Exception):
            snapshot(ms + [ms[0]])

    def test_item_ids_unique(self):
        for name, ms in SCENARIOS.items():
            ids = [i.item_id for i in run(ms).snapshot.evidence_items]
            with self.subTest(name):
                self.assertEqual(len(ids), len(set(ids)))

    def test_repeated_kfree_reasons_are_distinct_sources(self):
        d = run(scenario(kfree_drops("QDISC_DROP", 500.0), kfree_drops("NETFILTER_DROP", 500.0)))
        self.assertIs(d.result.decision, L.network_packet_loss)
        self.assertEqual(len([i for i in d.snapshot.evidence_items
                              if i.predicate_id == "PL.R1/LOSS.LOCAL[net.drop.kfree_skb]"]), 2)


if __name__ == "__main__":
    unittest.main()
