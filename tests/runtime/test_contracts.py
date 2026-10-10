"""IncidentContext strictness and the parameter-set registry (exact equality with the validated definition)."""

import sys
import unittest
from pathlib import Path

from pydantic import ValidationError

from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.diagnostic.rules import ParameterSet
from sentinelai.runtime import IncidentContext, TargetSpec, registry
from sentinelai.runtime.registry import RegistryIntegrityError, UnknownParameterSet

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from r2c_driver import params as r2c_params  # noqa: E402  (the validated R2-C/R2-D/R2-F definition)

T = TargetSpec(name="svc", cgroup_path="/system.slice/svc.service", ifaces=("eth0",))


def ctx(**kw):
    return IncidentContext(**{"incident_id": "inc-1", "target": T, **kw})


class TestIncidentContext(unittest.TestCase):
    def test_defaults_are_the_2a0_decisions(self):
        c = ctx()
        self.assertEqual((c.parameter_set_id, c.ebpf, c.period_s), ("r2c-validation-uncalibrated", "required", 1.0))

    def test_frozen(self):
        c = ctx()
        with self.assertRaises(ValidationError):
            c.ebpf = "disabled"
        with self.assertRaises(ValidationError):
            c.target.name = "other"

    def test_extra_fields_rejected(self):
        for extra in ({"window_start": "2026-10-04T10:00:00Z"}, {"time_range": [1, 2]}, {"incident_id_alias": "x"}):
            with self.assertRaises(ValidationError, msg=extra):
                ctx(**extra)
        with self.assertRaises(ValidationError):
            TargetSpec(name="a", cgroup_path="/a", pids=(1,))

    def test_invalid_fields(self):
        bad = [dict(incident_id=""), dict(incident_id="../x"), dict(incident_id="a/b"), dict(incident_id=".."),
               dict(incident_id="/abs"), dict(incident_id=7), dict(ebpf="optional"), dict(ebpf=True),
               dict(period_s=2.0), dict(period_s=1), dict(parameter_set_id=""), dict(parameter_set_id=None)]
        for kw in bad:
            with self.assertRaises(ValidationError, msg=kw):
                ctx(**kw)
        for kw in (dict(cgroup_path="relative"), dict(cgroup_path="/a/../b"), dict(cgroup_path="/a/./b"),
                   dict(name=""), dict(ifaces=("eth0", "eth0")), dict(ifaces=("bad name",))):
            with self.assertRaises(ValidationError, msg=kw):
                TargetSpec(**{"name": "n", "cgroup_path": "/n", **kw})

    def test_unknown_parameter_set_rejected(self):
        for psid in ("r2b-validation-uncalibrated", "test-params-m3a", "R2C-VALIDATION-UNCALIBRATED"):
            with self.assertRaises(ValidationError, msg=psid):
                ctx(parameter_set_id=psid)

    def test_json_round_trip(self):
        c = ctx(ebpf="disabled")
        self.assertEqual(IncidentContext.model_validate_json(c.model_dump_json()), c)


class TestRegistry(unittest.TestCase):
    def test_exactly_the_validated_definition(self):
        got, want = registry.get("r2c-validation-uncalibrated"), r2c_params()
        self.assertEqual(got, want)
        self.assertEqual(canonical_bytes(got), canonical_bytes(want))
        self.assertEqual(got.reason_sets, want.reason_sets)                      # tuple order too
        self.assertEqual(registry.parameter_set_sha256(got),
                         "880d9af62f6e120c227cbc1abc50a8521d8cc62ff059c3bbd8f316dbd56807cb")

    def test_known_and_default(self):
        self.assertEqual(registry.known(), ("r2c-validation-uncalibrated",))
        self.assertEqual(registry.DEFAULT_PARAMETER_SET_ID, "r2c-validation-uncalibrated")
        self.assertEqual(registry.VALIDATED_PARAMETER_SETS, frozenset({"r2c-validation-uncalibrated"}))

    def test_unknown_ids_raise(self):
        for psid in ("r2b-validation-uncalibrated", "", None, "test-params-m3a", 3):
            with self.assertRaises(UnknownParameterSet, msg=psid):
                registry.get(psid)

    def test_deterministic_serialisation(self):
        a, b = registry.get(registry.DEFAULT_PARAMETER_SET_ID), registry.get(registry.DEFAULT_PARAMETER_SET_ID)
        self.assertIsNot(a, b)
        self.assertEqual(canonical_bytes(a), canonical_bytes(b))
        self.assertIsInstance(a, ParameterSet)

    def test_drifted_literal_refused(self):
        numbers, reasons, pin = registry._SETS["r2c-validation-uncalibrated"]
        drifted = dict(numbers, PSI_MEM_MIN=0.21)
        orig = registry._SETS
        registry._SETS = {"r2c-validation-uncalibrated": (drifted, reasons, pin)}
        try:
            with self.assertRaises(RegistryIntegrityError):
                registry.get("r2c-validation-uncalibrated")
        finally:
            registry._SETS = orig

    def test_literals_are_read_only(self):
        numbers, reasons, _ = registry._SETS["r2c-validation-uncalibrated"]
        with self.assertRaises(TypeError):
            numbers["PSI_MEM_MIN"] = 0.0
        with self.assertRaises(TypeError):
            reasons["KFREE_REASONS_LOSS"] = ()


if __name__ == "__main__":
    unittest.main()
