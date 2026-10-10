"""ArtifactStore: write-once, O_EXCL, no traversal or absolute paths, manifest last, incomplete runs, hashes."""

import hashlib
import json
import os
import tempfile
import unittest

from sentinelai.runtime.store import ARTIFACTS, ArtifactStore, StoreError, verify_run


def tree(path):
    out = {}
    for d, dirs, files in os.walk(path, followlinks=False):
        for n in dirs + files:
            p = os.path.join(d, n)
            if os.path.islink(p) or os.path.isdir(p):
                out[os.path.relpath(p, path)] = True
            else:
                with open(p, "rb") as fh:
                    out[os.path.relpath(p, path)] = fh.read()
    return out


class StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = self._tmp.name
        self.root = os.path.join(self.base, "root")
        self.outside = os.path.join(self.base, "outside")
        os.mkdir(self.root)
        os.mkdir(self.outside)
        with open(os.path.join(self.outside, "keep.txt"), "w") as fh:
            fh.write("untouched")
        self.store = ArtifactStore(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def assertOutsideUntouched(self):
        self.assertEqual(sorted(os.listdir(self.base)), ["outside", "root"])
        self.assertEqual(tree(self.outside), {"keep.txt": b"untouched"})


class TestLayout(StoreCase):
    def test_run_layout_and_names(self):
        run = self.store.create_run("inc-1", "20261010T000000Z-abc")
        self.assertEqual(run.path, os.path.join(os.path.realpath(self.root), "inc-1", "20261010T000000Z-abc"))
        for name in ARTIFACTS[:-2]:
            run.write_bytes(name, name.encode())
        run.append_event('{"seq":0}')
        run.seal({"k": "v"})
        self.assertEqual(sorted(os.listdir(run.path)), sorted(ARTIFACTS))
        self.assertOutsideUntouched()

    def test_root_must_be_absolute_existing_dir(self):
        for root in ("relative/dir", "", os.path.join(self.base, "missing"), os.path.join(self.outside, "keep.txt"), 5):
            with self.assertRaises(StoreError, msg=root):
                ArtifactStore(root)

    def test_path_traversal_and_absolute_segments_rejected(self):
        bad = ("..", ".", "../x", "a/b", "/abs", "/", "", "x\x00y", "a\\b", ".hidden", "-dash", "x" * 129, None)
        for seg in bad:
            with self.assertRaises(StoreError, msg=seg):
                self.store.create_run(seg, "run")
            with self.assertRaises(StoreError, msg=seg):
                self.store.create_run("inc", seg)
        self.assertOutsideUntouched()

    def test_artifact_names_restricted(self):
        run = self.store.create_run("inc", "run")
        for name in ("../outside/x.json", "/tmp/x.json", "sub/x.json", "other.json", "manifest.json", "events.jsonl",
                     ".", ""):
            with self.assertRaises(StoreError, msg=name):
                run.write_bytes(name, b"x")
        with self.assertRaises(StoreError):
            run.write_bytes("snapshot.json", "not bytes")
        self.assertEqual(os.listdir(run.path), [])
        self.assertOutsideUntouched()

    def test_symlinked_incident_dir_refused(self):
        os.symlink(self.outside, os.path.join(self.root, "inc"))
        with self.assertRaises((StoreError, OSError)):
            self.store.create_run("inc", "run")
        self.assertOutsideUntouched()

    def test_symlinked_root_resolved_and_contained(self):
        link = os.path.join(self.base, "link")
        os.symlink(self.root, link)
        run = ArtifactStore(link).create_run("inc", "run")
        self.assertTrue(run.path.startswith(os.path.realpath(self.root) + os.sep))


class TestWriteOnce(StoreCase):
    def test_run_directory_is_new(self):
        self.store.create_run("inc", "run")
        with self.assertRaises(StoreError):
            self.store.create_run("inc", "run")
        self.store.create_run("inc", "run2")                       # another run of the same incident is fine

    def test_overwrite_refused(self):
        run = self.store.create_run("inc", "run")
        run.write_bytes("snapshot.json", b"one")
        with self.assertRaises(StoreError):
            run.write_bytes("snapshot.json", b"two")
        with open(os.path.join(run.path, "snapshot.json"), "rb") as fh:
            self.assertEqual(fh.read(), b"one")

    def test_o_excl_refuses_preexisting_file(self):
        run = self.store.create_run("inc", "run")
        with open(os.path.join(run.path, "diagnosis.json"), "wb") as fh:
            fh.write(b"planted")
        with self.assertRaises(StoreError):
            run.write_bytes("diagnosis.json", b"mine")
        with open(os.path.join(run.path, "diagnosis.json"), "rb") as fh:
            self.assertEqual(fh.read(), b"planted")

    def test_o_nofollow_refuses_planted_symlink(self):
        run = self.store.create_run("inc", "run")
        os.symlink(os.path.join(self.outside, "keep.txt"), os.path.join(run.path, "snapshot.json"))
        with self.assertRaises((StoreError, OSError)):
            run.write_bytes("snapshot.json", b"x")
        self.assertOutsideUntouched()

    def test_write_json_is_canonical(self):
        run = self.store.create_run("inc", "run")
        run.write_json("context.json", {"b": [2, 1], "a": 1.0})
        with open(os.path.join(run.path, "context.json"), "rb") as fh:
            self.assertEqual(fh.read(), b'{"a":1.0,"b":[1,2]}')


class TestManifest(StoreCase):
    def test_manifest_last_seals_the_run(self):
        run = self.store.create_run("inc", "run")
        run.write_bytes("snapshot.json", b"s")
        run.append_event("e0")
        run.seal({})
        for act in (lambda: run.write_bytes("diagnosis.json", b"d"), lambda: run.append_event("e1"),
                    lambda: run.seal({})):
            with self.assertRaises(StoreError):
                act()
        self.assertEqual(sorted(os.listdir(run.path)), ["events.jsonl", "manifest.json", "snapshot.json"])

    def test_incomplete_without_manifest(self):
        run = self.store.create_run("inc", "run")
        run.write_bytes("snapshot.json", b"s")
        run.abandon()
        v = verify_run(run.path)
        self.assertEqual((v["complete"], v["ok"]), (False, False))
        with self.assertRaises(StoreError):
            run.write_bytes("diagnosis.json", b"d")

    def test_hashes_correct_and_tamper_detected(self):
        run = self.store.create_run("inc", "run")
        data = {"snapshot.json": b"snap", "diagnosis.json": b"diag"}
        for n, d in data.items():
            self.assertEqual(run.write_bytes(n, d), hashlib.sha256(d).hexdigest())
        run.append_event("a")
        run.append_event("b")
        run.seal({"meta": 1})
        with open(os.path.join(run.path, "manifest.json"), "rb") as fh:
            m = json.loads(fh.read())
        self.assertEqual(m["format"], "sentinelai.run.v1")
        self.assertEqual(m["files"]["snapshot.json"], {"sha256": hashlib.sha256(b"snap").hexdigest(), "bytes": 4})
        self.assertEqual(m["files"]["events.jsonl"]["sha256"], hashlib.sha256(b"a\nb\n").hexdigest())
        self.assertEqual(verify_run(run.path), {"complete": True, "ok": True, "mismatch": [], "missing": [],
                                                "extra": []})
        os.chmod(os.path.join(run.path, "snapshot.json"), 0o644)
        with open(os.path.join(run.path, "snapshot.json"), "wb") as fh:
            fh.write(b"SNAP")
        self.assertEqual(verify_run(run.path)["mismatch"], ["snapshot.json"])
        with open(os.path.join(run.path, "acquisition.json"), "wb") as fh:
            fh.write(b"{}")
        self.assertEqual(verify_run(run.path)["extra"], ["acquisition.json"])
        os.remove(os.path.join(run.path, "diagnosis.json"))
        v = verify_run(run.path)
        self.assertEqual((v["ok"], v["missing"]), (False, ["diagnosis.json"]))

    def test_events_append_only_one_line_each(self):
        run = self.store.create_run("inc", "run")
        for bad in ("two\nlines", 5):
            with self.assertRaises(StoreError):
                run.append_event(bad)
        run.append_event("x")
        run.append_event("y")
        with open(os.path.join(run.path, "events.jsonl"), "rb") as fh:
            self.assertEqual(fh.read(), b"x\ny\n")


if __name__ == "__main__":
    unittest.main()
