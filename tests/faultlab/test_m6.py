"""Tests of the M6 batch runner and dataset writer (experiments/faultlab/m6.py; FZ-M6-PLAN; AMD-29)."""
import gzip
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments" / "faultlab"))
import m6 as X  # noqa: E402
import pilot as P  # noqa: E402

MATRIX = X.M.generate(X.M.load())
CAMPAIGN = "20261013T080000Z"


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp))
        for name, value in (("STAGING", self.tmp / "staging"), ("RAW", self.tmp / "ds" / "raw"),
                            ("MANIFEST", self.tmp / "ds" / "manifest.json"), ("ROOT", self.tmp)):
            p = mock.patch.object(X, name, value)
            p.start()
            self.addCleanup(p.stop)

    def run_dir(self, name, extra=None):
        d = self.tmp / "staging" / CAMPAIGN / name
        for rel, data in {"evidence/run.json": b'{"ok": true}\n', "evidence/ticks.jsonl": b'{"t":1}\n{"t":2}\n',
                          "evidence/client.jsonl": b'{"k":0}\n', "evidence/ebpf.jsonl": b"", "ops.jsonl": b'{"op":1}\n',
                          "report.json": b'{"pipeline_ok": false}\n', "logs/workload.stderr": b"\xff\xfe binary\n",
                          "lg/client.jsonl": b'{"k":0}\n', **(extra or {})}.items():
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        return d


class TestDataset(Sandbox):
    def test_pack_unpack_round_trip_is_byte_identical(self):
        rid = MATRIX["runs"][10]["run_id"]
        src = self.run_dir(rid)
        rep = X.pack(CAMPAIGN, MATRIX)
        self.assertEqual(rep["added"], [rid])
        names = sorted(p.name for p in (self.tmp / "ds" / "raw" / rid).iterdir())
        self.assertEqual(names, ["client.jsonl.gz", "documents.jsonl.gz", "ebpf.jsonl.gz", "ops.jsonl.gz",
                                 "ticks.jsonl.gz"])
        man = json.loads((self.tmp / "ds" / "manifest.json").read_text())
        for rel, sha in man["files"].items():
            self.assertEqual(hashlib.sha256((self.tmp / rel).read_bytes()).hexdigest(), sha)
        out = self.tmp / "unpacked"
        X.unpack(self.tmp / "ds" / "raw" / rid, out)
        for p in src.rglob("*"):
            if p.is_file() and not p.relative_to(src).as_posix().startswith("lg/"):
                self.assertEqual((out / p.relative_to(src)).read_bytes(), p.read_bytes(), p)
        self.assertFalse((out / "lg").exists())                                     # transport copy left out

    def test_gzip_is_deterministic(self):
        self.assertEqual(X.gz(b"abc"), X.gz(b"abc"))
        self.assertEqual(X.gz(b"abc")[4:8], b"\0\0\0\0")                            # mtime 0
        self.assertEqual(gzip.decompress(X.gz(b"abc")), b"abc")

    def test_append_only_and_never_packs_smoke_or_unknown_runs(self):
        rid = MATRIX["runs"][3]["run_id"]
        self.run_dir(rid)
        self.run_dir("M6-s800001")                                                  # a smoke run
        (self.tmp / "staging" / CAMPAIGN / "PI0-1").mkdir()
        (self.tmp / "staging" / CAMPAIGN / "PI0-1" / "run.json").write_bytes(b'{"ok": true}\n')
        rep = X.pack(CAMPAIGN, MATRIX)
        self.assertEqual(sorted(rep["added"]), sorted([rid, f"PI0-{CAMPAIGN}-s1"]))
        self.assertIn("M6-s800001", rep["skipped"])
        before = (self.tmp / "ds" / "manifest.json").read_bytes()
        rep = X.pack(CAMPAIGN, MATRIX)                                               # again: nothing rewritten
        self.assertEqual(rep["added"], [])
        self.assertEqual((self.tmp / "ds" / "manifest.json").read_bytes(), before)
        self.assertTrue(X.P.L.RUN_ID.fullmatch(f"PI0-{CAMPAIGN}-s1"))               # the integrity policy's run id

    def test_a_differing_transport_copy_is_refused(self):
        self.run_dir(MATRIX["runs"][4]["run_id"], {"lg/client.jsonl": b'{"k":1}\n'})
        with self.assertRaises(SystemExit):
            X.pack(CAMPAIGN, MATRIX)

    def test_tampered_document_is_detected_on_unpack(self):
        rid = MATRIX["runs"][5]["run_id"]
        self.run_dir(rid)
        X.pack(CAMPAIGN, MATRIX)
        f = self.tmp / "ds" / "raw" / rid / "documents.jsonl.gz"
        f.write_bytes(X.gz(gzip.decompress(f.read_bytes()).replace(b"false", b"true ")))
        with self.assertRaises(SystemExit):
            X.unpack(f.parent, self.tmp / "u")


class TestGate(Sandbox):
    def args(self, cmd, **kw):
        return SimpleNamespace(cmd=cmd, campaign=CAMPAIGN, execute=True, **kw)

    def gate(self, a, pin_bad=(), matrix=MATRIX):
        calls = {}
        rep = {"overall": "READY", "checks": [{"id": "INT-HEAD", "observed": "c" * 40, "mandatory": True,
                                               "status": "PASS"}]}
        with mock.patch.object(P, "check_invocation"), mock.patch.object(P, "require_pi0") as pi0, \
                mock.patch.object(X, "committed_matrix", return_value=matrix), \
                mock.patch.object(X, "pin_violations", return_value=list(pin_bad)), \
                mock.patch.object(P, "hand_over"), \
                mock.patch.object(P, "ctrl", side_effect=lambda out, seed, commit, **kw: calls.update(
                    out=out, seed=seed, kw=kw) or 0), \
                mock.patch.object(P, "lifecycle", side_effect=lambda out, k, commit: calls.update(out=out, k=k) or 0):
            rc = X.run_stage(a, run_preflight=lambda: rep)
        return rc, calls, pi0

    def test_a_matrix_run_executes_its_committed_entry(self):
        e = MATRIX["runs"][20]
        rc, calls, pi0 = self.gate(self.args("run", run_id=e["run_id"]))
        self.assertEqual((rc, calls["seed"], calls["kw"]), (0, e["seed"], {"variant": "m6", "scenario": e}))
        self.assertEqual(calls["out"], self.tmp / "staging" / CAMPAIGN / e["run_id"])
        pi0.assert_called_once()

    def test_refusals(self):
        e = MATRIX["runs"][21]
        with self.assertRaises(P.Refused):
            self.gate(self.args("run", run_id=e["run_id"]), pin_bad=["experiments/faultlab/pilot.py"])
        with self.assertRaises(P.Refused):
            self.gate(self.args("run", run_id="M6-s123456"))                           # not in the matrix
        (self.tmp / "staging" / CAMPAIGN / e["run_id"]).mkdir(parents=True)
        with self.assertRaises(P.Refused):
            self.gate(self.args("run", run_id=e["run_id"]))                           # never reused
        with self.assertRaises(P.Refused):
            self.gate(SimpleNamespace(cmd="run", campaign="today", execute=True, run_id=e["run_id"]))
        with self.assertRaises(P.Refused):
            self.gate(self.args("lifecycle", cycle=6))

    def test_lifecycle_and_smoke(self):
        rc, calls, pi0 = self.gate(self.args("lifecycle", cycle=2))
        self.assertEqual((rc, calls["k"]), (0, 2))
        pi0.assert_not_called()
        rc, calls, pi0 = self.gate(self.args("smoke", family="OV-3"))
        sc = calls["kw"]["scenario"]
        self.assertEqual((sc["family"], sc["split"], sc["run_id"]), ("OV-3", "smoke", f"M6-s{sc['seed']}"))
        self.assertGreaterEqual(sc["seed"], X.SMOKE_SEED_BASE)
        self.assertNotIn(sc["seed"], {r["seed"] for r in MATRIX["runs"]})

    def test_smoke_seeds_are_distinct_per_family(self):
        fams = sorted({r["family"] for r in MATRIX["runs"]})
        seeds = {f: X.smoke_entry(MATRIX, f)["seed"] for f in fams}
        self.assertEqual(len(set(seeds.values())), len(fams))
        self.assertTrue(all(X.P.M6_SEED_MIN <= s <= X.P.M6_SEED_MAX for s in seeds.values()))
        with self.assertRaises(P.Refused):
            X.smoke_entry(MATRIX, "OV-11")


class TestPin(unittest.TestCase):
    def test_only_dataset_paths_and_m6_documents_may_change_after_the_matrix(self):
        out = {("log",): "abc\n", ("diff",): "datasets/faultlab/v1/raw/M6-s100001/ticks.jsonl.gz\n"
                                               "datasets/faultlab/v1/manifest.json\ndocs/PHASE_1C_M6_REPORT.md\n"}
        with mock.patch.object(X, "git", side_effect=lambda *a: out[(a[0],)]):
            self.assertEqual(X.pin_violations(), [])
        out[("diff",)] += "experiments/faultlab/pilot.py\ndatasets/faultlab/v1/matrix.json\n"
        with mock.patch.object(X, "git", side_effect=lambda *a: out[(a[0],)]):
            self.assertEqual(X.pin_violations(), ["experiments/faultlab/pilot.py", "datasets/faultlab/v1/matrix.json"])
        with mock.patch.object(X, "git", side_effect=lambda *a: "a\nb\n" if a[0] == "log" else ""), \
                self.assertRaises(P.Refused):
            X.pin_violations()                                                          # added twice

    def test_committed_matrix_must_regenerate(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "m.json"
            f.write_bytes(X.M.dump(MATRIX))
            ok = lambda *a: X.MATRIX_REL + "\n" if a[0] == "ls-files" else ""
            with mock.patch.object(X, "MATRIX", f), mock.patch.object(X, "git", side_effect=ok):
                self.assertEqual(X.committed_matrix(), json.loads(X.M.dump(MATRIX)))
                f.write_bytes(X.M.dump(MATRIX).replace(b'"OV-1"', b'"OV-X"', 1))
                with self.assertRaises(P.Refused):
                    X.committed_matrix()
            f.write_bytes(X.M.dump(MATRIX))
            with mock.patch.object(X, "MATRIX", f), mock.patch.object(X, "git", side_effect=lambda *a: ""), \
                    self.assertRaises(P.Refused):
                X.committed_matrix()                                                    # not tracked

    def test_cli(self):
        with mock.patch.object(X.os, "geteuid", return_value=0), self.assertRaises(P.Refused):
            X.main(["pack", "--campaign", CAMPAIGN])
        with self.assertRaises(P.Refused):
            X.main(["run", "--campaign", CAMPAIGN, "--run-id", "M6-s100001"])          # no --execute


if __name__ == "__main__":
    unittest.main()
