"""Contract revision v0.6.0-draft (FZ-M7-PLAN C7-11, owner decision 1A): CT.R2 of v0.5.0 combined a baselined
ABS(throttle.ratio) with DEV(throttle.time_rate); the ratio has no baseline in FaultLab (the quota is applied at fault
onset), so it is split: CT.R2 = DEV(throttle.time_rate), CT.R3 = ABS(throttle.ratio, THR_RATIO_MIN) without a
baseline. Nothing else changes. Evidence recorded under v0.5.0 is evaluated under v0.5.0 (archived verbatim, rules
m2-1.1.0); any other version is refused."""

import json
import subprocess
import unittest
from pathlib import Path

from sentinelai.diagnostic.contract import CandidateStatus as S, Label as L, load_contract
from sentinelai.diagnostic.contract.catalog import ARCHIVE, DATA, active_contract_version, contract_version
from sentinelai.diagnostic.contract.version import CONTRACT_VERSION, MEASUREMENT_IDENTICAL
from sentinelai.diagnostic.rules import RULES_VERSION, diagnose
from sentinelai.diagnostic.rules.engine import RULES_BY_CONTRACT, ct_r2, ct_r2_v050, ct_r3, evaluators

from rules._fixtures import CG, COMMIT, FLOOR, m, params, snapshot, status

ROOT = Path(__file__).resolve().parents[2]
V050 = "0.5.0-draft"
FILES = ("registry.json", "labels.json", "predicates.json", "parameters.json")


def _raw(d, name):
    return json.loads((d / name).read_text(encoding="utf-8"))


def _throttled(ratio_baseline: bool):
    """A quota-throttled window; with ratio_baseline False the ratio has no baseline (FaultLab: no quota before onset)."""
    ratio = m("throttle.ratio", CG, 0.6, 0.0, 0.0) if ratio_baseline else m("throttle.ratio", CG, 0.6, base=False)
    return [m("throttle.quota_limited", CG, 1.0, base=False), ratio, m("throttle.time_rate", CG, 0.5, 0.0, 0.0)]


class TestVersions(unittest.TestCase):
    def test_versions(self):
        self.assertEqual((CONTRACT_VERSION, RULES_VERSION, MEASUREMENT_IDENTICAL), ("0.6.0-draft", "m2-1.2.0", (V050,)))
        self.assertEqual(RULES_BY_CONTRACT, {"0.6.0-draft": "m2-1.2.0", V050: "m2-1.1.0"})
        for name in FILES:
            self.assertEqual(_raw(DATA, name)["contract_version"], CONTRACT_VERSION, name)
            self.assertEqual(_raw(ARCHIVE / V050, name)["contract_version"], V050, name)

    def test_archive_is_the_committed_v050_verbatim(self):
        if not (ROOT / ".git").exists():
            self.skipTest("not a git checkout")
        for name in FILES:
            blob = subprocess.run(["git", "-C", str(ROOT), "show", f"e6dc3e9:src/sentinelai/diagnostic/contract/data/{name}"],
                                  capture_output=True, check=True).stdout
            self.assertEqual((ARCHIVE / V050 / name).read_bytes(), blob, name)


class TestClauseSplit(unittest.TestCase):
    def test_ct_clauses(self):
        c = load_contract().labels
        r2, r3 = c.clause("CT.R2"), c.clause("CT.R3")
        self.assertEqual((tuple(r2.features), r2.uses_baseline, r2.label), (("throttle.time_rate",), True, L.cpu_throttling))
        self.assertEqual((tuple(r3.features), r3.uses_baseline, r3.label), (("throttle.ratio",), False, L.cpu_throttling))
        self.assertEqual({x.clause_id for x in c.required_clauses(L.cpu_throttling)}, {"CT.R1", "CT.R2", "CT.R3"})

    def test_only_the_ct_clauses_change(self):
        for name in ("registry.json", "predicates.json", "parameters.json"):
            new, old = _raw(DATA, name), _raw(ARCHIVE / V050, name)
            new.pop("contract_version"), old.pop("contract_version")
            self.assertEqual(new, old, name)                              # the measurement layer is identical
        new, old = _raw(DATA, "labels.json"), _raw(ARCHIVE / V050, "labels.json")
        new.pop("contract_version"), old.pop("contract_version")
        nc = {x["clause_id"]: x for x in new.pop("clauses")}
        oc = {x["clause_id"]: x for x in old.pop("clauses")}
        self.assertEqual(new, old)
        self.assertEqual(set(nc) - set(oc), {"CT.R3"})
        self.assertEqual(set(oc) - set(nc), set())
        self.assertEqual({k for k in oc if oc[k] != nc[k]}, {"CT.R2"})


class TestVersionPinnedEvaluation(unittest.TestCase):
    def test_evaluator_tables(self):
        self.assertEqual(active_contract_version(), CONTRACT_VERSION)
        self.assertIs(evaluators()["CT.R2"], ct_r2)
        self.assertIs(evaluators()["CT.R3"], ct_r3)
        with contract_version(V050):
            self.assertEqual(active_contract_version(), V050)
            self.assertIs(evaluators()["CT.R2"], ct_r2_v050)
            self.assertNotIn("CT.R3", evaluators())
            self.assertIsNone(next((x for x in load_contract().labels.clauses if x.clause_id == "CT.R3"), None))
        self.assertEqual(active_contract_version(), CONTRACT_VERSION)       # restored on exit

    def test_unknown_versions_refused(self):
        for bad in ("0.4.0-draft", "0.7.0-draft", "", "0.5.0"):
            with self.subTest(bad), self.assertRaises(ValueError):
                with contract_version(bad):
                    pass
        from sentinelai.collectors import build_snapshot
        from sentinelai.collectors.errors import CollectorError
        with self.assertRaisesRegex(CollectorError, "not measurement-identical"):     # refused before any input is read
            build_snapshot([], None, None, 1.0, None, False, contract_version="0.4.0-draft")

    def test_throttling_without_a_ratio_baseline(self):
        """The defect C7-11 removes: under v0.5.0 a quota-throttled window whose ratio has no baseline cannot be
        asserted; under v0.6.0 it is, and with a ratio baseline both versions assert it."""
        from sentinelai.diagnostic.rules.params import UncalibratedParameters
        with self.assertRaises(UncalibratedParameters):                   # v0.5.0 baselines the ratio: it needs a floor
            diagnose(snapshot(_throttled(False)).model_copy(update={"contract_version": V050}), params(),
                     code_commit=COMMIT)
        p = params(**{"floor[throttle.ratio]": FLOOR})
        new = diagnose(snapshot(_throttled(False)), p, code_commit=COMMIT)
        old = diagnose(snapshot(_throttled(False)).model_copy(update={"contract_version": V050}), p, code_commit=COMMIT)
        self.assertIs(status(new, L.cpu_throttling), S.ASSERTED)
        self.assertIsNot(status(old, L.cpu_throttling), S.ASSERTED)
        self.assertEqual((new.result.engine.contract_version, new.result.engine.rules_version),
                         ("0.6.0-draft", "m2-1.2.0"))
        self.assertEqual((old.result.engine.contract_version, old.result.engine.rules_version), (V050, "m2-1.1.0"))
        for ver in (CONTRACT_VERSION, V050):
            with self.subTest(ver):
                d = diagnose(snapshot(_throttled(True)).model_copy(update={"contract_version": ver}), p,
                             code_commit=COMMIT)
                self.assertIs(status(d, L.cpu_throttling), S.ASSERTED)


if __name__ == "__main__":
    unittest.main()
