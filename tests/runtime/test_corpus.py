"""Phase 2A.2 gate: replay every committed historical snapshot that the registered parameter set can evaluate.

Discovery is from the repository (results/**/snapshot.json, cross-checked against git when available); nothing is
hard-coded. Every snapshot gets exactly one classification:
  REPLAYABLE                    R2 FaultLab snapshot, registered parameter set, run.json with a recorded M2 result
  REPLAYABLE_NO_RECORD          registered parameter set but no recorded M2 result to compare against
  UNREGISTERED_PARAMETER_SET    parameter set not in the runtime registry (kept as a limitation, not registered here)
  NOT_FAULTLAB                  outside results/phase1c_r2*/ (M3A smoke snapshots; no run record)
For REPLAYABLE snapshots the recomputed M2 output, projected with the same functions the FaultLab drivers used
(m2_summary plus each driver's extra fields), must equal the recorded run.json "m2" exactly, the snapshot must
round-trip byte-identically, and a pure run built from it must replay as MATCH. Read-only on the corpus.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sentinelai.diagnostic.contract import EvidenceSnapshot
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.diagnostic.rules.engine import Diagnosis
from sentinelai.runtime import ArtifactStore, IncidentContext, TargetSpec, diagnose_snapshot, registry, run_pure
from sentinelai.runtime.replay import replay_run_dir

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from r2b_driver import m2_summary  # noqa: E402          (the projection every R2 driver recorded)
from r2c_driver import cc_items  # noqa: E402
from r2d_cpu import m2_record  # noqa: E402
from r2f_driver import clause_items  # noqa: E402

IN_GIT = (ROOT / ".git").exists()


def discover():
    found = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "results").rglob("*snapshot.json"))
    if IN_GIT:
        tracked = sorted(subprocess.run(["git", "-C", str(ROOT), "ls-files", "results/*snapshot.json"],
                                        capture_output=True, text=True, check=True).stdout.split())
        assert found == tracked, ("untracked or missing snapshots", sorted(set(found) ^ set(tracked)))
    return found


def classify(rel):
    raw = (ROOT / rel).read_bytes()
    snap = EvidenceSnapshot.model_validate_json(raw, strict=False)
    run_json = ROOT / Path(rel).parent / "run.json"
    if not rel.startswith("results/phase1c_r2"):
        return "NOT_FAULTLAB", snap, raw, None
    if snap.parameter_set_id not in registry.known():
        return "UNREGISTERED_PARAMETER_SET", snap, raw, None
    run = json.loads(run_json.read_text()) if run_json.exists() else None
    if not run or not run.get("m2"):
        return "REPLAYABLE_NO_RECORD", snap, raw, run
    return "REPLAYABLE", snap, raw, run


def projection(record, evaluated, recorded):
    d = Diagnosis(snapshot=evaluated, result=record.result)
    out = m2_summary(d)
    extras = {"cc_items": lambda: cc_items(d), "r2d": lambda: m2_record(d), "clauses": lambda: clause_items(d),
              "conflict_rules": lambda: sorted(c.rule for c in evaluated.conflicts)}
    for k in recorded:
        if k not in out:
            out[k] = extras[k]()          # an unknown recorded key raises KeyError: nothing is skipped silently
    return out


class TestCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = discover()
        cls.cls = {rel: classify(rel) for rel in cls.files}

    def test_every_snapshot_classified(self):
        self.assertTrue(self.files)
        kinds = {c for c, *_ in self.cls.values()}
        self.assertTrue(kinds <= {"REPLAYABLE", "REPLAYABLE_NO_RECORD", "UNREGISTERED_PARAMETER_SET", "NOT_FAULTLAB"})
        replayable = [r for r, (c, *_) in self.cls.items() if c == "REPLAYABLE"]
        for phase in ("phase1c_r2c", "phase1c_r2d", "phase1c_r2f"):
            self.assertTrue([r for r in replayable if f"/{phase}/" in f"/{r}"], phase)

    def test_exclusions_are_what_they_claim(self):
        for rel, (c, snap, raw, run) in self.cls.items():
            if c == "UNREGISTERED_PARAMETER_SET":
                with self.assertRaises(registry.UnknownParameterSet, msg=rel):
                    diagnose_snapshot(raw, code_commit="0bb1fc6")
            if c == "NOT_FAULTLAB":
                self.assertFalse((ROOT / Path(rel).parent / "run.json").exists(), rel)
                self.assertNotIn(snap.parameter_set_id, registry.known(), rel)

    def test_snapshots_round_trip_byte_identically(self):
        for rel, (c, snap, raw, run) in self.cls.items():
            self.assertEqual(canonical_bytes(snap), raw, rel)

    def test_replayable_snapshots_reproduce_recorded_m2(self):
        n = 0
        for rel, (c, snap, raw, run) in self.cls.items():
            if c not in ("REPLAYABLE", "REPLAYABLE_NO_RECORD"):
                continue
            with self.subTest(snapshot=rel):
                commit = run["commit"] if run else "0bb1fc6"
                record, s, b, evaluated, _ = diagnose_snapshot(raw, code_commit=commit)
                self.assertEqual(b, raw)                                         # input unchanged
                again = diagnose_snapshot(raw, code_commit=commit)[0]
                self.assertEqual(canonical_bytes(again), canonical_bytes(record))  # deterministic
                if c == "REPLAYABLE":
                    if "snapshot" in run and "id" in run["snapshot"]:
                        self.assertEqual(record.snapshot_id, run["snapshot"]["id"])
                    got = json.loads(json.dumps(projection(record, evaluated, run["m2"])))
                    self.assertEqual(got, run["m2"])
                    self.assertEqual(canonical_bytes(got), canonical_bytes(run["m2"]))
                    n += 1
        self.assertGreater(n, 0)

    def test_replayable_snapshots_replay_through_runs(self):
        with tempfile.TemporaryDirectory() as t:
            store = ArtifactStore(t)
            ctx = IncidentContext(incident_id="corpus", target=TargetSpec(name="r2", cgroup_path="/sentinel-r2"))
            for rel, (c, snap, raw, run) in self.cls.items():
                if c != "REPLAYABLE":
                    continue
                with self.subTest(snapshot=rel):
                    rec, _, path = run_pure(ctx, raw, store, code_commit=run["commit"])
                    r = replay_run_dir(path)
                    self.assertEqual((r.status, r.recomputed["diagnosis_id"]), ("MATCH", rec.diagnosis_id))
                    self.assertEqual(r.stored["decision"], run["m2"]["decision"])


if __name__ == "__main__":
    unittest.main()
