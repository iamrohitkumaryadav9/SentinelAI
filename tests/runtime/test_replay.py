"""Phase 2A.2: verify / replay of persisted pure runs, CLI exit codes, corruption handling and non-mutation."""

import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sentinelai.__main__ import main
from sentinelai.diagnostic.contract import EvidenceSnapshot
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.runtime import ArtifactStore, IncidentContext, TargetSpec, run_pure
from sentinelai.runtime import pipeline
from sentinelai.runtime.replay import ReplayRefused, replay_run_dir, verify_run_dir
from sentinelai.runtime.store import verify_run

ROOT = Path(__file__).resolve().parents[2]
R2F = ROOT / "results" / "phase1c_r2f" / "20261004T100422Z"
COMMIT = "0bb1fc6"
CTX = IncidentContext(incident_id="inc-r", target=TargetSpec(name="r2f", cgroup_path="/sentinel-r2f/target"))


def fingerprint(path):
    """Every entry under path: name, type, mode, size, mtime_ns, inode and content."""
    out = {}
    for d, dirs, files in os.walk(path):
        for n in sorted(dirs + files):
            p = os.path.join(d, n)
            st = os.lstat(p)
            body = None
            if stat.S_ISREG(st.st_mode):
                with open(p, "rb") as fh:
                    body = fh.read()
            out[os.path.relpath(p, path)] = (st.st_mode, st.st_size, st.st_mtime_ns, st.st_ino, body)
    return out


def forge(run_dir, name, data: bytes):
    """Replace an artifact AND re-hash it in the manifest (integrity then passes; the content check must fail)."""
    p = os.path.join(run_dir, name)
    if os.path.exists(p):
        os.chmod(p, 0o644)
    with open(p, "wb") as fh:
        fh.write(data)
    mp = os.path.join(run_dir, "manifest.json")
    m = json.loads(Path(mp).read_bytes())
    import hashlib
    m["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    Path(mp).write_bytes(canonical_bytes(m))


def cli(*argv):
    buf = io.StringIO()
    code = main(list(argv), out=buf)
    return code, json.loads(buf.getvalue())


class RunCase(unittest.TestCase):
    snapshot = "M1-1"

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = self._t.name
        self.rec, _, self.run = run_pure(CTX, (R2F / self.snapshot / "snapshot.json").read_bytes(),
                                         ArtifactStore(self.root), code_commit=COMMIT)

    def tearDown(self):
        self._t.cleanup()

    def assertRefused(self, category, exit_code):
        before = fingerprint(self.root)
        with self.assertRaises(ReplayRefused) as cm:
            replay_run_dir(self.run)
        self.assertEqual((cm.exception.category, cm.exception.exit_code), (category, exit_code), cm.exception.detail)
        code, out = cli("replay", "--run-dir", self.run)
        self.assertEqual((code, out.get("refused")), (exit_code, category))
        self.assertNotIn("status", out)                     # never a result, never an abstention
        self.assertEqual(fingerprint(self.root), before)
        return cm.exception


class TestValidRuns(RunCase):
    def test_verify_and_replay_match(self):
        before = fingerprint(self.root)
        v = verify_run_dir(self.run)
        self.assertEqual((v["ok"], v["complete"], v["first"]), (True, True, None))
        r = replay_run_dir(self.run)
        self.assertEqual(r.status, "MATCH")
        self.assertTrue(all(r.checks.values()), r.checks)
        self.assertEqual((r.stored, r.recomputed["diagnosis_id"]), (r.recomputed, self.rec.diagnosis_id))
        self.assertEqual(r.stored["decision"], "memory_pressure")
        self.assertIsNone(r.first_difference)
        self.assertEqual(cli("verify", "--run-dir", self.run)[0], 0)
        code, out = cli("replay", "--run-dir", self.run)
        self.assertEqual((code, out["status"]), (0, "MATCH"))
        self.assertEqual(fingerprint(self.root), before)

    def test_replay_is_deterministic(self):
        a, b = cli("replay", "--run-dir", self.run), cli("replay", "--run-dir", self.run)
        self.assertEqual(a, b)
        self.assertEqual(replay_run_dir(self.run), replay_run_dir(self.run))

    def test_read_only_run_replays(self):
        for n in os.listdir(self.run):
            os.chmod(os.path.join(self.run, n), 0o444)
        os.chmod(self.run, 0o555)
        try:
            before = fingerprint(self.run)
            self.assertEqual(replay_run_dir(self.run).status, "MATCH")
            self.assertTrue(verify_run_dir(self.run)["ok"])
            self.assertEqual(fingerprint(self.run), before)
        finally:
            os.chmod(self.run, 0o755)

    def test_python_dash_m_entry_point(self):
        env = {"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1", "PYTHONPATH": str(ROOT / "src")}
        p = subprocess.run([sys.executable, "-m", "sentinelai", "replay", "--run-dir", self.run], capture_output=True,
                           text=True, env=env, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["status"], "MATCH")
        p = subprocess.run([sys.executable, "-m", "sentinelai", "verify"], capture_output=True, text=True, env=env,
                           timeout=60)
        self.assertEqual(p.returncode, 2)


class TestAbstention(RunCase):
    snapshot = "E0-open"

    def test_valid_abstention_replays(self):
        code, out = cli("replay", "--run-dir", self.run)
        self.assertEqual((code, out["status"], out["stored"]["decision"]), (0, "MATCH", "INSUFFICIENT_EVIDENCE"))


class TestUsage(RunCase):
    def test_bad_run_dir_arguments(self):
        link = os.path.join(self.root, "link")
        os.symlink(self.run, link)
        for d in ("relative/run", os.path.join(self.root, "missing"), link,
                  os.path.join(self.run, "snapshot.json")):
            for cmd in ("verify", "replay"):
                code, out = cli(cmd, "--run-dir", d)
                self.assertEqual((code, out["refused"]), (2, "USAGE"), (cmd, d))


class TestGuards(RunCase):
    def test_existing_relative_run_dir_refused(self):
        rel = os.path.relpath(self.run, os.getcwd())
        self.assertTrue(os.path.isdir(rel) and not os.path.isabs(rel))
        for cmd in ("verify", "replay"):
            code, out = cli(cmd, "--run-dir", rel)
            self.assertEqual((code, out["refused"]), (2, "USAGE"), cmd)

    def test_artifact_changed_after_verification(self):
        """verify passes, then a file changes before it is read: the re-hash against the manifest must refuse."""
        from unittest import mock
        from sentinelai.runtime import replay as R
        real = R.verify_run_dir

        def verify_then_tamper(run_dir):
            v = real(run_dir)
            p = os.path.join(run_dir, "snapshot.json")
            os.chmod(p, 0o644)
            Path(p).write_bytes((R2F / "E0-open" / "snapshot.json").read_bytes())
            return v
        with mock.patch.object(R, "verify_run_dir", verify_then_tamper):
            with self.assertRaises(ReplayRefused) as cm:
                replay_run_dir(self.run)
        self.assertEqual(cm.exception.category, "RUN_INVALID")
        self.assertIn("changed after verification", cm.exception.detail)

    def test_read_artifact_registered_names_only(self):
        from sentinelai.runtime.store import StoreError, read_artifact
        Path(self.run, "notes.txt").write_bytes(b"x")
        for name in ("notes.txt", "../inc-r", "/etc/hostname", "", "manifest.json/.."):
            with self.assertRaises(StoreError, msg=name):
                read_artifact(self.run, name)
        self.assertEqual(read_artifact(self.run, "snapshot.json"), (R2F / "M1-1" / "snapshot.json").read_bytes())


class TestIntegrityFailures(RunCase):
    def test_missing_manifest_is_incomplete(self):
        os.remove(os.path.join(self.run, "manifest.json"))
        v = verify_run_dir(self.run)
        self.assertEqual((v["ok"], v["complete"]), (False, False))
        self.assertEqual(cli("verify", "--run-dir", self.run)[0], 7)
        self.assertRefused("RUN_INVALID", 7)

    def test_missing_required_artifacts(self):
        for name in ("snapshot.json", "diagnosis.json", "parameter_set.json", "context.json", "events.jsonl"):
            with self.subTest(name=name):
                self.tearDown()
                self.setUp()
                os.remove(os.path.join(self.run, name))
                v = verify_run_dir(self.run)
                self.assertFalse(v["ok"])
                self.assertIn(name, v["first"])
                self.assertRefused("RUN_INVALID", 7)

    def test_tampered_artifacts_without_manifest_update(self):
        for name in ("diagnosis.json", "snapshot.json", "parameter_set.json", "context.json"):
            with self.subTest(name=name):
                self.tearDown()
                self.setUp()
                p = os.path.join(self.run, name)
                os.chmod(p, 0o644)
                data = Path(p).read_bytes()
                Path(p).write_bytes(data[:-1] + (b"}" if data[-1:] != b"}" else b" "))
                v = verify_run_dir(self.run)
                self.assertEqual((v["ok"], v["mismatch"]), (False, [name]))
                self.assertRefused("RUN_INVALID", 7)

    def test_tampered_manifest(self):
        mp = os.path.join(self.run, "manifest.json")
        m = json.loads(Path(mp).read_bytes())
        m["files"]["snapshot.json"]["sha256"] = "0" * 64
        os.chmod(mp, 0o644)
        Path(mp).write_bytes(canonical_bytes(m))
        self.assertEqual(verify_run_dir(self.run)["mismatch"], ["snapshot.json"])
        self.assertRefused("RUN_INVALID", 7)
        for bad in (b"{not json", b"[]", b'{"format":"sentinelai.run.v1"}', b'{"format":"x","files":{}}'):
            Path(mp).write_bytes(bad)
            v = verify_run_dir(self.run)
            self.assertFalse(v["ok"])
            self.assertIn("manifest", v["first"])
            self.assertRefused("RUN_INVALID", 7)

    def test_manifest_listing_unregistered_name(self):
        Path(self.run, "evil.sh").write_bytes(b"x")
        mp = os.path.join(self.run, "manifest.json")
        m = json.loads(Path(mp).read_bytes())
        m["files"]["evil.sh"] = {"sha256": "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881", "bytes": 1}
        os.chmod(mp, 0o644)
        Path(mp).write_bytes(canonical_bytes(m))
        v = verify_run_dir(self.run)
        self.assertFalse(v["ok"])
        self.assertIn("evil.sh", v["mismatch"] + v["unregistered"])
        self.assertRefused("RUN_INVALID", 7)

    def test_unexpected_extra_files(self):
        for name in ("notes.txt", "acquisition.json"):
            with self.subTest(name=name):
                self.tearDown()
                self.setUp()
                Path(self.run, name).write_bytes(b"{}")
                v = verify_run_dir(self.run)
                self.assertFalse(v["ok"])
                self.assertIn(name, v["first"])
                self.assertRefused("RUN_INVALID", 7)
        self.tearDown()
        self.setUp()
        os.mkdir(os.path.join(self.run, "subdir"))
        self.assertFalse(verify_run_dir(self.run)["ok"])

    def test_required_artifact_absent_from_disk_and_manifest(self):
        mp = os.path.join(self.run, "manifest.json")
        m = json.loads(Path(mp).read_bytes())
        del m["files"]["events.jsonl"]
        os.chmod(mp, 0o644)
        Path(mp).write_bytes(canonical_bytes(m))
        os.remove(os.path.join(self.run, "events.jsonl"))
        self.assertTrue(verify_run(self.run)["ok"])                       # generic integrity alone passes ...
        v = verify_run_dir(self.run)
        self.assertEqual((v["ok"], v["required_missing"]), (False, ["events.jsonl"]))   # ... the pure-run rule does not
        self.assertRefused("RUN_INVALID", 7)

    def test_manifest_format_checked(self):
        mp = os.path.join(self.run, "manifest.json")
        m = json.loads(Path(mp).read_bytes())
        m["format"] = "sentinelai.run.v0"
        os.chmod(mp, 0o644)
        Path(mp).write_bytes(canonical_bytes(m))
        v = verify_run_dir(self.run)
        self.assertFalse(v["ok"])
        self.assertIn("format", v["first"])
        self.assertRefused("RUN_INVALID", 7)

    def test_symlinked_artifact_refused(self):
        p = os.path.join(self.run, "snapshot.json")
        keep = Path(p).read_bytes()
        os.chmod(p, 0o644)
        os.remove(p)
        target = os.path.join(self.root, "elsewhere.json")
        Path(target).write_bytes(keep)
        os.symlink(target, p)
        self.assertIn("snapshot.json", verify_run(self.run)["missing"])
        self.assertRefused("RUN_INVALID", 7)

    def test_incomplete_failed_run(self):
        from unittest import mock
        with mock.patch.object(pipeline.registry, "get", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                run_pure(IncidentContext(incident_id="inc-f", target=CTX.target),
                         (R2F / "M1-1" / "snapshot.json").read_bytes(), ArtifactStore(self.root), code_commit=COMMIT)
        (run,) = [os.path.join(self.root, "inc-f", d) for d in os.listdir(os.path.join(self.root, "inc-f"))]
        self.run = run
        self.assertFalse(verify_run_dir(run)["complete"])
        self.assertRefused("RUN_INVALID", 7)


class TestContentFailures(RunCase):
    """The manifest is forged to match, so integrity passes: the content checks must catch it."""

    def test_unknown_parameter_set(self):
        ctx = json.loads(Path(self.run, "context.json").read_bytes())
        for psid in ("r2b-validation-uncalibrated", "made-up", None):
            ctx["parameter_set_id"] = psid
            forge(self.run, "context.json", canonical_bytes(ctx))
            self.assertRefused("PARAMETERS_REFUSED", 5)

    def test_corrupted_parameter_set(self):
        ps = json.loads(Path(self.run, "parameter_set.json").read_bytes())
        ps["numbers"]["PSI_MEM_MIN"] = 0.0
        forge(self.run, "parameter_set.json", canonical_bytes(ps))
        self.assertRefused("PARAMETERS_REFUSED", 5)
        forge(self.run, "parameter_set.json", b"not json")
        self.assertRefused("PARAMETERS_REFUSED", 5)

    def test_invalid_snapshot(self):
        forge(self.run, "snapshot.json", b"{broken")
        self.assertRefused("SNAPSHOT_INVALID", 4)
        snap = json.loads((R2F / "M1-1" / "snapshot.json").read_bytes())
        snap["schema_version"] = "9.9.9"                                  # contract violation
        forge(self.run, "snapshot.json", canonical_bytes(snap))
        self.assertRefused("SNAPSHOT_INVALID", 4)
        forge(self.run, "snapshot.json", json.dumps(json.loads((R2F / "M1-1" / "snapshot.json").read_bytes()),
                                                    indent=1).encode())   # valid but not canonical
        self.assertRefused("SNAPSHOT_INVALID", 4)

    def test_other_valid_snapshot_is_a_mismatch(self):
        forge(self.run, "snapshot.json", (R2F / "E0-open" / "snapshot.json").read_bytes())
        before = fingerprint(self.root)
        r = replay_run_dir(self.run)
        self.assertEqual(r.status, "MISMATCH")
        self.assertFalse(r.checks["diagnosis_id_equal"])
        self.assertEqual((r.stored["decision"], r.recomputed["decision"]), ("memory_pressure", "INSUFFICIENT_EVIDENCE"))
        self.assertTrue(r.first_difference.startswith("$."))
        self.assertEqual(cli("replay", "--run-dir", self.run)[0], 6)
        self.assertEqual(fingerprint(self.root), before)

    def test_same_diagnosis_id_different_result_hash(self):
        d = json.loads(Path(self.run, "diagnosis.json").read_bytes())
        d["record"]["result_sha256"] = "f" * 64
        forge(self.run, "diagnosis.json", canonical_bytes(d))
        r = replay_run_dir(self.run)
        self.assertEqual(r.status, "MISMATCH")
        self.assertTrue(r.checks["diagnosis_id_equal"])
        self.assertFalse(r.checks["result_sha256_equal"])
        self.assertEqual(r.first_difference, "$.record.result_sha256")
        self.assertEqual(cli("replay", "--run-dir", self.run)[0], 6)

    def test_same_diagnosis_id_different_record_body(self):
        d = json.loads(Path(self.run, "diagnosis.json").read_bytes())
        d["record"]["validated_configuration"] = {"validated": False, "reasons": ["forged"]}
        forge(self.run, "diagnosis.json", canonical_bytes(d))
        r = replay_run_dir(self.run)
        self.assertEqual(r.status, "MISMATCH")
        self.assertTrue(r.checks["diagnosis_id_equal"] and r.checks["result_sha256_equal"])
        self.assertFalse(r.checks["record_equal"])
        self.assertTrue(r.first_difference.startswith("$.record.validated_configuration"))

    def test_same_record_different_evaluated_snapshot(self):
        d = json.loads(Path(self.run, "diagnosis.json").read_bytes())
        d["evaluated_snapshot"]["evidence_items"] = d["evaluated_snapshot"]["evidence_items"][1:]
        forge(self.run, "diagnosis.json", canonical_bytes(d))
        r = replay_run_dir(self.run)
        self.assertEqual(r.status, "MISMATCH")
        self.assertTrue(r.checks["record_equal"])
        self.assertFalse(r.checks["evaluated_snapshot_equal"])

    def test_invalid_stored_record_or_context(self):
        for name, data in (("diagnosis.json", b"not json"), ("diagnosis.json", b'{"record":{}}'),
                           ("diagnosis.json", b'{"evaluated_snapshot":{},"record":{}}')):
            with self.subTest(data=data):
                forge(self.run, name, data)
                self.assertRefused("RECORD_INVALID", 8)
        self.tearDown()
        self.setUp()
        ctx = json.loads(Path(self.run, "context.json").read_bytes())
        ctx["incident_id"] = "../escape"
        forge(self.run, "context.json", canonical_bytes(ctx))
        self.assertRefused("RECORD_INVALID", 8)

    def test_non_canonical_context_refused(self):
        ctx = json.loads(Path(self.run, "context.json").read_bytes())
        forge(self.run, "context.json", json.dumps(ctx, indent=2).encode())
        self.assertRefused("RECORD_INVALID", 8)

    def test_record_parameter_set_must_match_context(self):
        d = json.loads(Path(self.run, "diagnosis.json").read_bytes())
        d["record"]["parameter_set_id"] = "r2b-validation-uncalibrated"
        forge(self.run, "diagnosis.json", canonical_bytes(d))
        self.assertRefused("PARAMETERS_REFUSED", 5)

    def test_rules_or_contract_version_not_substituted(self):
        for field, value in (("rules_version", "m2-9.9.9"), ("contract_version", "0.6.0-draft")):
            with self.subTest(field=field):
                self.tearDown()
                self.setUp()
                d = json.loads(Path(self.run, "diagnosis.json").read_bytes())
                d["record"][field] = value
                forge(self.run, "diagnosis.json", canonical_bytes(d))
                self.assertRefused("PARAMETERS_REFUSED", 5)

    def test_snapshot_parameter_set_must_match_context(self):
        snap = EvidenceSnapshot.model_validate_json((R2F / "M1-1" / "snapshot.json").read_bytes(), strict=False)
        other = snap.model_copy(update={"parameter_set_id": "r2b-validation-uncalibrated"})
        forge(self.run, "snapshot.json", canonical_bytes(other))
        self.assertRefused("M2_REFUSED", 5)


if __name__ == "__main__":
    unittest.main()
