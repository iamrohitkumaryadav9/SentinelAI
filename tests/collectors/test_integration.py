"""Collected measurements -> EvidenceSnapshot -> M2 diagnose()."""

import unittest

from sentinelai.diagnostic.contract import AbstentionReason as AR, DiagnosticFlag, Label as L
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.diagnostic.rules import diagnose

from ._world import World, build, params

COMMIT = "f7fb0c8"


def run(world=None):
    snap = build(world)
    return snap, diagnose(snap, params(), code_commit=COMMIT)


class TestIntegration(unittest.TestCase):
    def test_normal_host_abstains(self):
        snap, d = run()
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertEqual(d.result.flags, (DiagnosticFlag.IMPACT_NOT_MEASURED,))   # no app metrics in M3A
        self.assertEqual(d.result.engine.parameter_set_id, snap.parameter_set_id)

    def test_collected_contention_is_diagnosed_by_m2(self):
        w = World()
        w.window_rates.update({"task.run_delay": 900_000_000,                  # 0.9 waiting-cores in W
                               "cpu.idle": 2, "cpu.user": 73})                  # cpuset 0.98 busy in W
        w.gauges["cg.cpu.max"] = "max 100000"
        w.rates["cg.nr_periods"] = 0
        snap, d = run(w)
        self.assertIs(d.result.decision, L.cpu_contention)
        self.assertIn(DiagnosticFlag.IMPACT_NOT_MEASURED, d.result.flags)

    def test_retransmissions_without_qdisc_counter_stay_undecidable(self):
        # net.drop.qdisc is not collected in M3A (tc not permitted): the minimum local drop set is never
        # complete, so high retransmissions can never be read as "no local loss"
        w = World()
        w.window_rates["Tcp.RetransSegs"] = 100
        snap, d = run(w)
        self.assertIs(d.result.decision, L.INSUFFICIENT_EVIDENCE)
        self.assertIn(AR.LOSS_VS_RETRANS_UNDECIDABLE, d.result.abstention_reasons)

    def test_m2_output_deterministic_on_collected_input(self):
        a = canonical_bytes(run()[1].result)
        self.assertEqual(a, canonical_bytes(run()[1].result))


if __name__ == "__main__":
    unittest.main()
