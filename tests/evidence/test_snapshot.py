"""EvidenceSnapshot cross-object validation (contract §3 E1, §5, §10.5, §10.7 I5)."""

import unittest

from pydantic import ValidationError

from sentinelai.diagnostic.contract import Conflict, EvidenceKind, Label, MissingMeasurement, Quality, snapshot_id

from . import _builders as b

QD = b.meas("net.drop.qdisc", "iface:A/eth0", 500.0)
CPU = b.meas("cpu.util.host", "host", 0.9)
POS_QD = b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.POSITIVE, [QD], supports=[Label.network_packet_loss])


class TestSnapshot(unittest.TestCase):
    def test_valid(self):
        s = b.snapshot([QD, CPU], [POS_QD])
        self.assertEqual(len(s.snapshot_id), 16)

    def test_I5_measurement_reference_must_resolve(self):
        with self.assertRaises(ValidationError):
            b.snapshot([CPU], [POS_QD])

    def test_item_may_only_use_its_predicates_features(self):
        bad = b.item("PL.R1", EvidenceKind.POSITIVE, [CPU], supports=[Label.network_packet_loss])
        with self.assertRaises(ValidationError):
            b.snapshot([CPU], [bad])

    def test_E1_positive_or_negative_cannot_rest_on_unusable_data(self):
        for q, v, cov in ((Quality.MISSING, None, 0.0), (Quality.INVALID, None, 1.0)):
            m = b.meas("net.drop.qdisc", "iface:A/eth0", v, quality=q, coverage=cov)
            for kind in (EvidenceKind.POSITIVE, EvidenceKind.NEGATIVE):
                it = b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", kind, [m],
                            supports=[Label.network_packet_loss] if kind is EvidenceKind.POSITIVE else [])
                with self.subTest(q=q, kind=kind), self.assertRaises(ValidationError):
                    b.snapshot([m], [it])
        stale = b.meas("net.drop.qdisc", "iface:A/eth0", 500.0, quality=Quality.STALE,
                       provenance=b.prov("net.drop.qdisc", last=b.ts(50)))
        with self.assertRaises(ValidationError):
            b.snapshot([stale], [b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.POSITIVE, [stale],
                                        supports=[Label.network_packet_loss])])

    def test_missing_item_on_missing_measurement_is_the_correct_form(self):
        m = b.meas("net.drop.qdisc", "iface:A/eth0", None, quality=Quality.MISSING, coverage=0.0)
        it = b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.MISSING, [m])
        s = b.snapshot([m], [it])
        self.assertEqual(s.missing_measurements[0].feature_id, "net.drop.qdisc")

    def test_baseline_required_for_deviation_predicates(self):
        no_base = b.meas("net.drop.qdisc", "iface:A/eth0", 500.0, base=None)
        weak_base = b.meas("net.drop.qdisc", "iface:A/eth0", 500.0, base=b.baseline(adequate=False, n=2))
        for m in (no_base, weak_base):
            it = b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.POSITIVE, [m], supports=[Label.network_packet_loss])
            with self.subTest(baseline=m.baseline), self.assertRaises(ValidationError):
                b.snapshot([m], [it])

    def test_absolute_predicate_needs_no_baseline(self):
        segs = b.meas("tcp.out_segs_rate", "netns:A", 4000.0, base=None)
        it = b.item("RT.R0", EvidenceKind.POSITIVE, [segs], supports=[Label.tcp_retransmissions])
        self.assertEqual(len(b.snapshot([segs], [it]).evidence_items), 1)

    def test_missing_measurements_must_be_declared(self):
        m = b.meas("net.drop.qdisc", "iface:A/eth0", None, quality=Quality.MISSING, coverage=0.0)
        s = b.snapshot([m])
        with self.assertRaises(ValidationError):
            b.rebuild(s, missing_measurements=())

    def test_missing_measurement_entry_validated(self):
        with self.assertRaises(ValidationError):
            MissingMeasurement(feature_id="net.drop.nope", scope="host", reason="x")
        with self.assertRaises(ValidationError):
            MissingMeasurement(feature_id="net.drop.qdisc", scope="host", reason="x")  # wrong scope kind

    def test_measurement_window_must_be_snapshot_window(self):
        other = b.meas("cpu.util.host", "host", 0.5, win=b.window(70.0, 10.0), base=b.baseline())
        with self.assertRaises(ValidationError):
            b.snapshot([other])

    def test_baseline_window_rules(self):
        with self.assertRaises(ValidationError):  # baseline window overlapping the incident window
            b.snapshot([], base_win=b.window(55.0, 10.0))
        m = b.meas("cpu.util.host", "host", 0.5, base=b.baseline(win=b.window(0.0, 30.0)))
        with self.assertRaises(ValidationError):  # within-run baseline must be the snapshot's baseline window
            b.snapshot([m])

    def test_duplicates_rejected(self):
        with self.assertRaises(ValidationError):
            b.snapshot([QD, QD])
        with self.assertRaises(ValidationError):
            b.snapshot([QD], [POS_QD, POS_QD])

    def test_snapshot_id_enforced(self):
        s = b.snapshot([QD], [POS_QD])
        with self.assertRaises(ValidationError):
            b.rebuild(s, snapshot_id="ffffffffffffffff")

    def test_versions(self):
        s = b.snapshot([QD])
        with self.assertRaises(ValidationError):  # a v0.1.0 snapshot is not silently accepted (no migration)
            b.rebuild(s, schema_version="0.1.0")
        with self.assertRaises(ValidationError):
            b.rebuild(s, schema_version="0.3.0")
        with self.assertRaises(ValidationError):
            b.rebuild(s, contract_version="1.0.0")
        self.assertEqual(b.rebuild(s, contract_version="0.3.1").contract_version, "0.3.1")  # same major

    def test_conflicts(self):
        th = b.meas("throttle.ratio", "cgroup:/lab", 0.7)
        it = b.item("CT.R2", EvidenceKind.POSITIVE, [th], supports=[Label.cpu_throttling])
        cf = Conflict(labels=(Label.cpu_throttling, Label.cpu_contention), rule="PR-3", item_ids=(it.item_id,))
        b.snapshot([th], [it], conflicts=[cf])
        with self.assertRaises(ValidationError):  # unknown item
            b.snapshot([th], [], conflicts=[cf])
        for bad in (dict(labels=(Label.cpu_throttling,), rule="PR-3"),
                    dict(labels=(Label.cpu_throttling, Label.INSUFFICIENT_EVIDENCE), rule="PR-3"),
                    dict(labels=(Label.cpu_throttling, Label.cpu_contention), rule="PR-99")):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                Conflict(item_ids=(it.item_id,), **bad)
        Conflict(labels=(Label.memory_pressure, Label.cpu_contention), rule=None, item_ids=(it.item_id,))

    def test_derived_measurement_inputs_must_resolve(self):
        src = b.meas("sched.run_delay.target", "cgroup:/lab", 0.4)
        der = b.meas("sched.run_delay_excess.target", "cgroup:/lab", 0.4,
                     provenance=b.prov("sched.run_delay_excess.target", derived_from=(src.measurement_id,)))
        b.snapshot([src, der])
        with self.assertRaises(ValidationError):
            b.snapshot([der])

    def test_snapshot_id_ignores_measurement_order(self):
        self.assertEqual(snapshot_id(b.TARGET, b.INC, [QD, CPU]), snapshot_id(b.TARGET, b.INC, [CPU, QD]))
        self.assertNotEqual(snapshot_id(b.TARGET, b.INC, [QD, CPU]), snapshot_id(b.TARGET, b.INC, [QD]))


if __name__ == "__main__":
    unittest.main()
