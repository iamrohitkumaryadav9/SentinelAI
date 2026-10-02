"""The engine refuses inputs it cannot evaluate faithfully (contract §6, design §5)."""

import unittest

from pydantic import ValidationError

from sentinelai.diagnostic.rules import EngineError, ParameterSet, UncalibratedParameters, diagnose
from sentinelai.diagnostic.rules.engine import DEV_FEATURES

from ._fixtures import COMMIT, NS, PSID, TEST_NUMBERS, FLOOR, contention, m, params, run, scenario, snapshot


class TestUncalibrated(unittest.TestCase):
    def test_each_missing_number_refused(self):
        snap = snapshot(scenario(contention()))
        for name in ("DOM_RATIO", "SI_SHARE_MIN", "COV_MIN", "Z_STRONG", "τ_DISAGREE", f"floor[{DEV_FEATURES[0]}]"):
            nums = {**TEST_NUMBERS, **{f"floor[{f}]": FLOOR for f in DEV_FEATURES}}
            nums.pop(name)
            ps = ParameterSet(parameter_set_id=PSID, numbers=nums, reason_sets={"KFREE_REASONS_LOSS": ("QDISC_DROP",)})
            with self.subTest(name), self.assertRaises(UncalibratedParameters) as cm:
                diagnose(snap, ps, code_commit=COMMIT)
            self.assertIn(name, str(cm.exception))

    def test_missing_reason_set_refused(self):
        nums = {**TEST_NUMBERS, **{f"floor[{f}]": FLOOR for f in DEV_FEATURES}}
        ps = ParameterSet(parameter_set_id=PSID, numbers=nums, reason_sets={})
        with self.assertRaises(UncalibratedParameters):
            diagnose(snapshot(scenario()), ps, code_commit=COMMIT)

    def test_no_engine_defaults(self):
        with self.assertRaises(UncalibratedParameters):
            ParameterSet(parameter_set_id=PSID, numbers={}, reason_sets={}).num("DOM_RATIO")


class TestParameterSetValidation(unittest.TestCase):
    def test_unknown_parameter(self):
        with self.assertRaises(ValidationError):
            params(NOT_A_PARAMETER=1.0)

    def test_wrong_types(self):
        with self.assertRaises(ValidationError):
            params(DOM_RATIO=float("nan"))
        with self.assertRaises(ValidationError):
            ParameterSet(parameter_set_id=PSID, numbers={"KFREE_REASONS_LOSS": 1.0}, reason_sets={})

    def test_reason_values_validated(self):
        with self.assertRaises(ValidationError):
            params(KFREE_REASONS_LOSS=("not-upper",))


class TestInputRefusal(unittest.TestCase):
    def test_parameter_set_id_mismatch(self):
        ps = params()
        other = ParameterSet(parameter_set_id="other", numbers=dict(ps.numbers), reason_sets=dict(ps.reason_sets))
        with self.assertRaises(EngineError):
            diagnose(snapshot(scenario()), other, code_commit=COMMIT)

    def test_input_with_evidence_refused(self):
        d = run(scenario(contention()))
        with self.assertRaises(EngineError):
            diagnose(d.snapshot, params(), code_commit=COMMIT)

    def test_ambiguous_measurement_refused(self):
        # two P99 and MEAN latency series are distinct; two tcp.out_segs_rate in the same netns are not
        ms = scenario() + [m("tcp.out_segs_rate", "netns:A", 10.0)]
        with self.assertRaises(Exception):   # duplicate id (M1) — the engine never sees an ambiguous pair
            run(ms)


if __name__ == "__main__":
    unittest.main()
