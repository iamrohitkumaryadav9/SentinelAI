"""Deterministic IDs and canonical serialisation (contract §10.3–10.5, I7)."""

import hashlib
import json
import unittest
from pathlib import Path

from sentinelai.diagnostic.contract import (DiagnosticResult, EvidenceKind, EvidenceSnapshot, Label, canonical_bytes,
                                            evidence_item_id, measurement_id)

from . import _builders as b

PKG = Path(__file__).resolve().parents[2] / "src" / "sentinelai" / "diagnostic" / "contract"


def build_snapshot(order=1):
    qd = b.meas("net.drop.qdisc", "iface:A/eth0", 500.0)
    cpu = b.meas("cpu.util.host", "host", 0.25)
    rt = b.meas("tcp.retrans_frac", "netns:A", 0.08)
    items = [b.item("PL.R1/LOSS.LOCAL[net.drop.qdisc]", EvidenceKind.POSITIVE, [qd], supports=[Label.network_packet_loss]),
             b.item("DEV[tcp.retrans_frac]", EvidenceKind.POSITIVE, [rt], supports=[Label.tcp_retransmissions])]
    ms = [qd, cpu, rt]
    if order == -1:
        ms, items = ms[::-1], items[::-1]
    return b.snapshot(ms, items)


class TestIds(unittest.TestCase):
    def test_measurement_id_known_answer(self):
        """Documented encoding: sha1(canonical_json({kind, feature_id, scope, window}))[:16], named inputs."""
        w = b.window(60.0, 10.0)
        expected_payload = ('{"feature_id":"cpu.util.host","kind":"measurement","scope":"host","window":'
                            '{"duration_s":10.0,"end":"2026-10-02T10:01:10.000Z","sample_period_s":1.0,'
                            '"start":"2026-10-02T10:01:00.000Z"}}')
        expected = hashlib.sha1(expected_payload.encode()).hexdigest()[:16]
        self.assertEqual(measurement_id("cpu.util.host", "host", w), expected)

    def test_id_inputs_are_positional_safe(self):
        """Regression: swapping inputs must not collide (positional arrays were once sorted)."""
        w = b.window()
        self.assertNotEqual(measurement_id("a.b", "c.d", w), measurement_id("c.d", "a.b", w))

    def test_measurement_id_stable_and_sensitive(self):
        w = b.window()
        ids = {measurement_id("cpu.util.host", "host", w) for _ in range(3)}
        self.assertEqual(len(ids), 1)
        self.assertNotEqual(measurement_id("cpu.util.host", "host", w), measurement_id("cpu.util.host", "cpu:0", w))
        self.assertNotEqual(measurement_id("cpu.util.host", "host", w),
                            measurement_id("cpu.util.host", "host", b.window(61.0, 10.0)))

    def test_evidence_id_order_independent(self):
        self.assertEqual(evidence_item_id("RT.R2/LOSS.LOCAL", ["a" * 16, "b" * 16]),
                         evidence_item_id("RT.R2/LOSS.LOCAL", ["b" * 16, "a" * 16]))
        self.assertNotEqual(evidence_item_id("RT.R2/LOSS.LOCAL", ["a" * 16]), evidence_item_id("RT.R1", ["a" * 16]))

    def test_snapshot_id_reconstruction_identical(self):
        self.assertEqual(build_snapshot().snapshot_id, build_snapshot().snapshot_id)
        self.assertEqual(build_snapshot().snapshot_id, build_snapshot(order=-1).snapshot_id)

    def test_snapshot_id_changes_with_content(self):
        s1 = build_snapshot()
        s2 = b.snapshot([b.meas("cpu.util.host", "host", 0.26)])
        self.assertNotEqual(s1.snapshot_id, s2.snapshot_id)

    def test_no_nondeterministic_sources_in_contract_code(self):
        import ast
        for f in PKG.glob("*.py"):
            tree = ast.parse(f.read_text())
            mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
            mods |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module and n.level == 0}
            self.assertFalse(mods & {"uuid", "random", "secrets", "time"}, f"{f.name} imports {mods}")
            calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
            self.assertFalse(calls & {"now", "utcnow", "today", "urandom"}, f"{f.name} calls {calls & {'now','utcnow','today','urandom'}}")


class TestCanonicalSerialisation(unittest.TestCase):
    def test_I7_three_serialisations_identical(self):
        s = build_snapshot()
        a, bb, c = canonical_bytes(s), canonical_bytes(s), canonical_bytes(s)
        self.assertTrue(a == bb == c)

    def test_I7_independent_constructions_identical(self):
        self.assertEqual(canonical_bytes(build_snapshot()), canonical_bytes(build_snapshot()))
        self.assertEqual(canonical_bytes(build_snapshot()), canonical_bytes(build_snapshot(order=-1)))

    def test_result_serialisation_identical(self):
        s = build_snapshot()
        r1, r2, r3 = b.result(s), b.result(s), b.result(s)
        self.assertTrue(canonical_bytes(r1) == canonical_bytes(r2) == canonical_bytes(r3))

    def test_canonical_form(self):
        txt = canonical_bytes(build_snapshot()).decode()
        d = json.loads(txt)
        self.assertEqual(txt, json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        self.assertEqual(list(d), sorted(d))
        self.assertRegex(d["window"]["start"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
        self.assertEqual(d["evidence_items"][0]["kind"], "POSITIVE")  # enums by value

    def test_negative_zero_and_int_float_canonicalised(self):
        m1 = b.meas("net.drop.qdisc", "iface:A/eth0", 0.0, base=None)
        m2 = b.meas("net.drop.qdisc", "iface:A/eth0", -0.0, base=None)
        m3 = b.meas("net.drop.qdisc", "iface:A/eth0", 0, base=None)
        self.assertTrue(canonical_bytes(m1) == canonical_bytes(m2) == canonical_bytes(m3))

    def test_json_round_trip_is_byte_stable(self):
        s = build_snapshot()
        raw = canonical_bytes(s)
        s2 = EvidenceSnapshot.model_validate_json(raw)
        self.assertEqual(canonical_bytes(s2), raw)
        r = b.result(s)
        self.assertEqual(canonical_bytes(DiagnosticResult.model_validate_json(canonical_bytes(r))), canonical_bytes(r))


if __name__ == "__main__":
    unittest.main()
