"""Architectural boundary tests: ground truth, ML advisory, LLM text, M1 scope (no rule engine)."""

import ast
import json
import unittest
from pathlib import Path

from pydantic import ValidationError

from sentinelai.diagnostic import contract as C
from sentinelai.diagnostic.contract import EvidenceSnapshot, MLAdvisory, Label, canonical_bytes

from . import _builders as b

PKG = Path(C.__file__).resolve().parent


class TestGroundTruthBoundary(unittest.TestCase):
    def test_ground_truth_cannot_enter_a_snapshot(self):
        s = b.snapshot([b.meas("cpu.util.host", "host", 0.5)])
        d = json.loads(canonical_bytes(s))
        d["measurements"][0]["provenance"]["source"] = "FAULTLAB_GROUND_TRUTH"
        with self.assertRaises(ValidationError):
            EvidenceSnapshot.model_validate_json(json.dumps(d))
        d2 = json.loads(canonical_bytes(s))
        d2["ground_truth"] = {"label": "cpu_contention"}
        with self.assertRaises(ValidationError):
            EvidenceSnapshot.model_validate_json(json.dumps(d2))


class TestMLAdvisoryBoundary(unittest.TestCase):
    def test_result_decision_is_independent_of_ml(self):
        s = b.snapshot()
        ml = MLAdvisory(model_id="m", probabilities={Label.memory_pressure: 0.99, Label.cpu_contention: 0.01},
                        calibrated=True, agrees_with_rules=False)
        r = b.result(s, ml=ml)
        self.assertIs(r.decision, Label.INSUFFICIENT_EVIDENCE)
        self.assertNotIn("decision", MLAdvisory.model_fields)
        self.assertNotIn("label", MLAdvisory.model_fields)


class TestNoLLMAuthority(unittest.TestCase):
    def test_evidence_text_is_template_only(self):
        it = b.item("RT.R0", C.EvidenceKind.POSITIVE, [b.meas("tcp.out_segs_rate", "netns:A", 4000.0, base=None)],
                    supports=[Label.tcp_retransmissions])
        with self.assertRaises(ValidationError):
            b.rebuild(it, rationale="The assistant concluded that retransmissions are the cause.")


class TestM1Scope(unittest.TestCase):
    """M1 implements the contract only: no predicate evaluation, no diagnosis, no thresholds."""

    def test_no_decision_making_functions(self):
        forbidden = {"diagnose", "decide", "evaluate", "evaluate_predicate", "classify", "apply_precedence",
                     "calibrate", "train", "predict"}
        for f in PKG.glob("*.py"):
            tree = ast.parse(f.read_text())
            names = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
            self.assertFalse(names & forbidden, f"{f.name} defines {names & forbidden}")

    def test_no_numeric_thresholds_in_code(self):
        for name in C.load_contract().parameters.parameters:
            for f in PKG.glob("*.py"):
                self.assertNotRegex(f.read_text(), rf"\b{name}\s*=\s*[-0-9.]", f"{name} assigned a value in {f.name}")

    def test_no_heavy_or_network_dependencies(self):
        banned = {"torch", "tensorflow", "langchain", "langgraph", "transformers", "httpx", "requests", "sklearn",
                  "ollama", "docker", "subprocess", "socket"}
        for f in PKG.glob("*.py"):
            tree = ast.parse(f.read_text())
            mods = set()
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    mods |= {a.name.split(".")[0] for a in n.names}
                elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                    mods.add(n.module.split(".")[0])
            self.assertFalse(mods & banned, f"{f.name} imports {mods & banned}")


if __name__ == "__main__":
    unittest.main()
