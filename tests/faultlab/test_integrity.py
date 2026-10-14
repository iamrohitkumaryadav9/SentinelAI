"""Phase 1C M4 integrity amendment (AMD-18) tests.

Live check: every code/data change after the approved anchor 606754c is an exact allowed path, an append-only raw
dataset file, the manifest, or a SHA-256-pinned file. Trust chain (no file embeds the hash of a file that embeds its
own): test_r2f pins test_r2e (existing); this module pins test_r2e and test_r2f; test_r2f accepts changes to this
module and _integrity.py only in commits on an approved parent. All other tests use disposable repositories.
"""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from faultlab import _integrity as I

ROOT = Path(__file__).resolve().parents[2]
IN_GIT = (ROOT / ".git").exists()
ANCHOR = "606754c5bdb24e7108b56be2720479a6c1123165"
CHECKER_FILES = frozenset({"tests/faultlab/_integrity.py", "tests/faultlab/test_integrity.py"})
# Candidate M4 paths, each needing owner approval: app collector (design §3 layout "collect/app.py"; pilot design §5.5),
# its tests, the baseline-placement builder change (proposed AMD-6/AMD-8), the contract text (proposed AMD-6/AMD-7)
# and the owner's FaultLab container files.
M4_PATHS = frozenset({
    "src/sentinelai/collectors/app.py",
    "src/sentinelai/collectors/normalize.py",
    "src/sentinelai/collectors/snapshot.py",
    "tests/collectors/test_app.py",
    "docs/EVIDENCE_CONTRACT.md",
    "experiments/faultlab/docker/Dockerfile",
    "experiments/faultlab/docker/workload.py",
    "tests/collectors/test_safety.py",       # AMD-19: the app-metrics read site (one exact new open)
    "tests/faultlab/test_workload.py",       # AMD-20: tests of the FaultLab workload
    "experiments/faultlab/docker/loadgen.py",  # AMD-21: the FaultLab load generator (design §3 layout)
    "tests/faultlab/test_loadgen.py",        # AMD-21: its tests
    "experiments/faultlab/rehearsal.py",     # AMD-22: unprivileged loopback end-to-end rehearsal driver
    "tests/faultlab/test_rehearsal.py",      # AMD-22: its tests
    "experiments/faultlab/preflight.py",     # AMD-24: read-only, fail-closed pilot preflight (Gate 1.2)
    "tests/faultlab/test_preflight.py",      # AMD-24: its tests
    "experiments/faultlab/lab.py",           # AMD-26: A–R–B lab plans, mutation guard, checks, cleanup
    "experiments/faultlab/pilot.py",         # AMD-26: PI-0 / CTRL pilot driver (Gate 2)
    "tests/faultlab/test_pilot.py",          # AMD-26: their tests (simulated host)
    "tests/runtime/test_corpus.py",          # AMD-27: committed pilot snapshots verified, never given to M2
    "tests/runtime/test_raw_replay.py",      # AMD-27: committed pilot ticks replayed byte-identically
    "experiments/faultlab/matrix.py",        # AMD-29: the M6 matrix generator (design §6.6, pilot design §5.3)
    "tests/faultlab/test_matrix.py",         # AMD-29: its tests
    "experiments/faultlab/m6.py",            # AMD-29: the M6 batch runner and dataset writer
    "tests/faultlab/test_m6.py",             # AMD-29: its tests
    "experiments/faultlab/m7.py",            # AMD-30: M7 windows, calibration, training and lock (FZ-M7-PLAN)
    "tests/faultlab/test_m7.py",             # AMD-30: its tests
})
M6_ADD_ONLY = frozenset({"datasets/faultlab/v1/matrix.json"})   # AMD-29: committed once, before any collection
M7_ADD_ONLY = frozenset(f"datasets/faultlab/v1/m7/{n}.json" for n in    # AMD-30: each artefact committed once
                        ("params.calibrated", "calibration_report", "model", "training_report", "lock"))
# AMD-27: recorded failed evaluations, pinned so that they can never be edited or relabelled as passing
FAILED_PILOT_PINS = {
    "results/phase1c_m5_pilot/20261011T175343Z/PI0-1/run.json":
        "5bf519a04fb5d2fa9c997f8dd7b4b1e8b1b851758319b3d7fbd5900c2bb1c9b2",       # ok false (forwarding, mounts)
    "results/phase1c_m5_pilot/20261012T030504Z/CTRL-900001/report.json":
        "dd79326c5951f87e6dd69c20ce039b4c23f938e49eef6073ae7221c94fc56519",       # pipeline_ok false (app_features)
}
PINS = {
    "tests/faultlab/test_r2e.py": "26cd086ebfa8fd1d9ce68e1a5f9bdc0e09d01b0ac7b7a7e01beab15ba949f415",
    "tests/faultlab/test_r2f.py": "27284e972c6006295d8b8e1e9d7b442088cc22102592e6889c64ec99f15787ed",
}
LIVE = I.Policy(anchor=ANCHOR, add_or_modify=M4_PATHS | CHECKER_FILES, add_only=M6_ADD_ONLY | M7_ADD_ONLY,
                pinned=PINS)                                                            # checker: see test_r2f


class TestLiveRepository(unittest.TestCase):
    @unittest.skipUnless(IN_GIT, "integrity checks need the git checkout")
    def test_policy_holds(self):
        self.assertEqual(I.check(ROOT, LIVE), [])

    @unittest.skipUnless(IN_GIT, "integrity checks need the git checkout")
    def test_pilot_evidence_policy_holds(self):
        self.assertEqual(I.check_pilot_evidence(ROOT, ANCHOR, FAILED_PILOT_PINS), [])

    @unittest.skipUnless(IN_GIT, "integrity checks need the git checkout")
    def test_recorded_failures_stay_failures(self):
        for path in FAILED_PILOT_PINS:
            doc = json.loads(I._blob(ROOT, "HEAD", path))
            self.assertFalse(doc.get("ok") or doc.get("pipeline_ok"), path)

    def test_policy_paths_are_exact(self):
        for p in M4_PATHS | CHECKER_FILES | set(PINS) | M6_ADD_ONLY | M7_ADD_ONLY:
            self.assertFalse(p.endswith("/") or any(c in p for c in "*?[ \t\n"), p)
        self.assertFalse(M4_PATHS & CHECKER_FILES or M4_PATHS & set(PINS) or CHECKER_FILES & set(PINS))
        self.assertFalse(M6_ADD_ONLY & (M4_PATHS | CHECKER_FILES | set(PINS)))
        self.assertFalse(M7_ADD_ONLY & (M4_PATHS | CHECKER_FILES | set(PINS) | M6_ADD_ONLY))


# ---------------------------------------------------------------------------------------------- disposable repos
APP = "src/sentinelai/collectors/app.py"
RAW = "datasets/faultlab/v1/raw/PL-QDISC-I2-s1013/ticks.jsonl.gz"
RAW2 = "datasets/faultlab/v1/raw/CTRL-s7/ticks.jsonl.gz"
MAN = "datasets/faultlab/v1/manifest.json"
CHECKER = "tests/faultlab/_integrity.py"
PINNED = "tests/faultlab/test_r2f.py"


class Repo:
    def __init__(self, d):
        self.d = d
        self.g("init", "-q", "-b", "main")
        self.g("config", "user.email", "t@t")
        self.g("config", "user.name", "t")
        for p in ("tests/faultlab/test_r2e.py", PINNED, "src/sentinelai/engine.py", "README.md"):
            self.write(p, f"# {p}\n")
        self.write(".gitignore", "*.bin\n__pycache__/\nebpf/build/\n")
        self.commit("anchor")
        self.anchor = self.g("rev-parse", "HEAD").stdout.decode().strip()
        self.write(PINNED, "# pinned v2\n")
        self.write(CHECKER, "# checker\n")
        self.commit("integrity amendment")

    def policy(self, anchor=None):
        return I.Policy(anchor=anchor or self.anchor, add_or_modify=frozenset({APP}), add_only=frozenset({CHECKER}),
                        pinned={PINNED: hashlib.sha256(b"# pinned v2\n").hexdigest()})

    def g(self, *a, check=True):
        return I.git(self.d, *a, check=check)

    def write(self, p, data, mode=0o644):
        f = Path(self.d, p)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data.encode() if isinstance(data, str) else data)
        os.chmod(f, mode)

    def commit(self, msg):
        self.g("add", "-A")
        self.g("commit", "-qm", msg)

    def manifest(self, entries):
        self.write(MAN, json.dumps({"files": entries}, sort_keys=True))

    def raw(self, p, data):
        self.write(p, data)
        return hashlib.sha256(data).hexdigest()

    def check(self, anchor=None):
        return I.check(self.d, self.policy(anchor))


class Disposable(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.r = Repo(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def rejected(self, needle):
        v = self.r.check()
        self.assertTrue(any(needle in x for x in v), v)


class TestPolicyAccepts(Disposable):
    def test_amendment_state(self):
        self.assertEqual(self.r.check(), [])

    def test_allowed_exact_path(self):
        self.r.write(APP, "x = 1\n")
        self.r.commit("app")
        self.assertEqual(self.r.check(), [])

    def test_raw_with_manifest_then_append(self):
        h = self.r.raw(RAW, b"\x1f\x8b raw1")
        self.r.manifest({RAW: h})
        self.r.commit("raw 1")
        self.assertEqual(self.r.check(), [])
        h2 = self.r.raw(RAW2, b"\x1f\x8b raw2")
        self.r.manifest({RAW: h, RAW2: h2})
        self.r.commit("raw 2")
        self.assertEqual(self.r.check(), [])

    def test_pycache_and_build_output_tolerated(self):
        self.r.write("tests/__pycache__/x.cpython-310.pyc", b"\0")
        self.r.write("ebpf/build/min_core.btf", b"\0")
        self.assertEqual(self.r.check(), [])

    def test_out_of_scope_untracked_and_changes_left_to_existing_checks(self):
        self.r.write("experiments/faultlab/docker/workload.py", "untracked owner file\n")
        self.r.write("docs/PHASE_1C_M4_M5_PILOT_DESIGN.md", "untracked owner draft\n")
        self.assertEqual(self.r.check(), [])
        self.r.write("docs/notes.md", "x\n")
        self.r.g("add", "docs/notes.md")
        self.r.g("commit", "-qm", "docs outside the governed scope")
        self.assertEqual(self.r.check(), [])


PILOT = "results/phase1c_m5_pilot/20261012T040045Z"


class TestPilotEvidence(Disposable):
    """AMD-27: names, modes, append-only history, run manifests and pins of committed pilot evidence."""

    def add_run(self, name="CTRL-900002", extra=()):
        ev = {f"evidence/{n}": f"{n}\n".encode() for n in ("run.json", "ticks.jsonl", "client.jsonl")}
        for rel, data in ev.items():
            self.r.write(f"{PILOT}/{name}/{rel}", data)
        self.r.write(f"{PILOT}/{name}/manifest.json",
                     json.dumps({"files": {k: hashlib.sha256(v).hexdigest() for k, v in ev.items()}}))
        for rel in ("report.json", "snapshot.json", "ops.jsonl", "preflight.json", "logs/workload.stderr") + extra:
            self.r.write(f"{PILOT}/{name}/{rel}", "x\n")

    def pv(self, pins=None):
        return I.check_pilot_evidence(self.r.d, self.r.anchor, pins)

    def committed(self, msg="pilot"):
        self.r.commit(msg)
        return self.pv()

    def test_intended_evidence_is_accepted(self):
        self.add_run()
        for name in ("PI1U-900008", "PI6OFF-900006", "INSTOFF-900006", "PI8-900020"):   # AMD-28: PI8
            self.add_run(name)
        for k in range(1, 6):
            for rel in ("run.json", "ops.jsonl", "host_before.json", "echo_server.stderr"):
                self.r.write(f"{PILOT}/PI0-{k}/{rel}", "x\n")
        self.assertEqual(self.committed(), [])
        self.add_run("CTRL-900003")                                         # later runs are added, never edited
        self.assertEqual(self.committed("more"), [])

    def test_unauthorised_paths_are_rejected(self):
        for bad in ("CTRL-900002/lg/client.jsonl", "CTRL-900002/collector/child_ticks.jsonl", "CTRL-900002/x.txt",
                    "CTRL-800002/run.json", "PI0-6/run.json", "FAULT-900002/run.json", "CTRL-900002/evidence/a/b.json",
                    "CTRL-900002/Run.json", "../CTRL-900002/run.json"):
            with self.subTest(bad):
                r = Repo(tempfile.mkdtemp(dir=self._t.name))
                r.write(f"{PILOT}/{bad}", "x\n")
                r.commit("bad")
                v = I.check_pilot_evidence(r.d, r.anchor)
                self.assertTrue(any("not allowed" in x for x in v), v)
        r = Repo(tempfile.mkdtemp(dir=self._t.name))
        r.write("results/phase1c_m5_pilot/2026-10-12/CTRL-900002/run.json", "x\n")
        r.commit("bad campaign")
        self.assertTrue(I.check_pilot_evidence(r.d, r.anchor))

    def test_modes_are_regular_files_only(self):
        self.add_run()
        os.chmod(Path(self.r.d, PILOT, "CTRL-900002/report.json"), 0o755)
        os.symlink("report.json", Path(self.r.d, PILOT, "CTRL-900002/snapshot_link.json"))
        v = self.committed()
        self.assertTrue(any("mode 100755" in x for x in v), v)
        self.assertTrue(any("mode 120000" in x for x in v), v)

    def test_history_is_append_only(self):
        self.add_run()
        self.assertEqual(self.committed(), [])
        self.r.write(f"{PILOT}/CTRL-900002/report.json", '{"pipeline_ok": true}\n')    # relabel after the fact
        self.assertTrue(any("not append-only: M" in x for x in self.committed("relabel")))
        r = Repo(tempfile.mkdtemp(dir=self._t.name))
        self.r = r
        self.add_run()
        r.commit("pilot")
        r.g("rm", "-q", f"{PILOT}/CTRL-900002/report.json")
        r.commit("drop a failed report")
        self.assertTrue(any("not append-only: D" in x for x in self.pv()))

    def test_manifest_must_cover_the_tracked_evidence(self):
        self.add_run()
        self.r.write(f"{PILOT}/CTRL-900002/evidence/extra.json", "x\n")
        self.assertTrue(any("not in its manifest" in x for x in self.committed()))
        r = Repo(tempfile.mkdtemp(dir=self._t.name))
        self.r = r
        self.add_run()
        r.write(f"{PILOT}/CTRL-900002/evidence/ticks.jsonl", "tampered before the commit\n")
        self.assertTrue(any("sha256 mismatch" in x for x in self.committed()))
        r = Repo(tempfile.mkdtemp(dir=self._t.name))
        self.r = r
        self.add_run()
        r.g("add", "-A")
        r.g("rm", "-q", "--cached", f"{PILOT}/CTRL-900002/evidence/client.jsonl")
        r.g("commit", "-qm", "partial")
        self.assertTrue(any("lists an untracked file" in x for x in self.pv()))
        r.write(f"{PILOT}/CTRL-900002/manifest.json", "{not json")
        self.assertTrue(any("malformed" in x for x in self.committed("bad manifest")))

    def test_pins_hold_the_recorded_content(self):
        self.add_run()
        path = f"{PILOT}/CTRL-900002/report.json"
        self.r.commit("pilot")
        pin = {path: hashlib.sha256(b"x\n").hexdigest()}
        self.assertEqual(self.pv(pin), [])
        self.assertTrue(self.pv({path: "0" * 64}))
        self.assertTrue(self.pv({f"{PILOT}/CTRL-900009/report.json": "0" * 64}))   # a pinned file must exist


class TestPolicyRejects(Disposable):
    def test_unrelated_source(self):
        self.r.write("scripts/evil.py", "x\n")
        self.r.commit("evil")
        self.rejected("path not allowed: A 'scripts/evil.py'")

    def test_existing_source_edit(self):
        self.r.write("src/sentinelai/engine.py", "# changed\n")
        self.r.commit("edit")
        self.rejected("path not allowed: M 'src/sentinelai/engine.py'")

    def test_sibling_of_allowed(self):
        self.r.write("src/sentinelai/collectors/other.py", "x\n")
        self.r.commit("other")
        self.rejected("path not allowed")

    def test_checker_modified_later(self):
        self.r.write(CHECKER, "# weakened checker\n")
        self.r.commit("weaken checker")
        self.rejected("history not append-only: M 'tests/faultlab/_integrity.py'")

    def test_checker_deleted(self):
        self.r.g("rm", "-q", CHECKER)
        self.r.commit("drop checker")
        self.rejected("history not append-only: D")

    def test_add_only_path_existing_at_anchor_modified(self):
        self.r.write("README.md", "changed\n")
        self.r.commit("edit a file that was present at the anchor")
        v = I.check(self.r.d, I.Policy(anchor=self.r.anchor, add_only=frozenset({"README.md"}),
                                       diff_scope=("README.md",)))
        self.assertIn("add-only path has status M: 'README.md'", v)

    def test_pinned_file_edited(self):
        self.r.write(PINNED, "# pin removed\n")
        self.r.commit("edit pinned")
        self.rejected("pinned content mismatch: 'tests/faultlab/test_r2f.py'")

    def test_pinned_file_deleted(self):
        self.r.g("rm", "-q", PINNED)
        self.r.commit("drop pinned")
        self.rejected("pinned path has status D")

    def test_rename_into_allowed_path(self):
        Path(self.r.d, "src/sentinelai/collectors").mkdir(parents=True)
        self.r.g("mv", "src/sentinelai/engine.py", APP)
        self.r.commit("rename")
        self.rejected("path not allowed: D 'src/sentinelai/engine.py'")

    def test_whitespace_path(self):
        self.r.write("src/sentinelai/collectors/app.py README.md", "x\n")
        self.r.commit("space")
        self.rejected("path not allowed: A 'src/sentinelai/collectors/app.py README.md'")

    def test_symlink_at_allowed_path(self):
        Path(self.r.d, APP).parent.mkdir(parents=True)
        os.symlink("../../../README.md", Path(self.r.d, APP))
        self.r.commit("link")
        self.rejected("mode 120000")

    def test_executable_at_allowed_path(self):
        self.r.write(APP, "x\n", mode=0o755)
        self.r.commit("exe")
        self.rejected("mode 100755")

    def test_raw_not_in_manifest(self):
        h = self.r.raw(RAW, b"a")
        self.r.raw(RAW2, b"b")
        self.r.manifest({RAW: h})
        self.r.commit("unlisted")
        self.rejected("raw file not in manifest")

    def test_sha_mismatch(self):
        self.r.raw(RAW, b"a")
        self.r.manifest({RAW: "0" * 64})
        self.r.commit("bad sha")
        self.rejected("sha256 mismatch")

    def test_raw_rewritten_with_manifest(self):
        h = self.r.raw(RAW, b"a")
        self.r.manifest({RAW: h})
        self.r.commit("raw")
        h = self.r.raw(RAW, b"edited")
        self.r.manifest({RAW: h})
        self.r.commit("edit raw and manifest together")
        self.rejected("history not append-only: M")

    def test_raw_deleted(self):
        h = self.r.raw(RAW, b"a")
        self.r.manifest({RAW: h})
        self.r.commit("raw")
        self.r.g("rm", "-q", RAW)
        self.r.manifest({})
        self.r.commit("delete")
        self.rejected("history not append-only: D")

    def test_manifest_entry_dropped(self):
        h = self.r.raw(RAW, b"a")
        self.r.manifest({RAW: h})
        self.r.commit("raw")
        self.r.manifest({})
        self.r.commit("drop entry")
        self.rejected("manifest entry rewritten or dropped")

    def test_malformed_manifest(self):
        self.r.write(MAN, "{not json")
        self.r.commit("bad")
        self.rejected("malformed")

    def test_wrong_dataset_version(self):
        self.r.write("datasets/faultlab/v2/raw/CTRL-s1/ticks.jsonl.gz", b"a")
        self.r.commit("v2")
        self.rejected("path not allowed")

    def test_malformed_run_id(self):
        self.r.write("datasets/faultlab/v1/raw/ctrl-s1/ticks.jsonl.gz", b"a")
        self.r.commit("lowercase")
        self.rejected("path not allowed")

    def test_uncommitted_tracked_edit(self):
        self.r.write("README.md", "changed\n")
        self.rejected("uncommitted tracked change: 'README.md'")

    def test_staged_tracked_edit(self):
        self.r.write("README.md", "changed\n")
        self.r.g("add", "README.md")
        self.rejected("uncommitted tracked change: 'README.md'")

    def test_untracked_in_src(self):
        self.r.write("src/sentinelai/sitecustomize.py", "x\n")
        self.rejected("untracked file in scope: 'src/sentinelai/sitecustomize.py'")

    def test_ignored_bin_in_datasets(self):
        self.r.write("datasets/faultlab/v1/raw/CTRL-s1/hidden.bin", b"a")
        self.rejected("ignored file in scope")

    def test_anchor_not_ancestor(self):
        self.r.g("checkout", "-q", "--orphan", "other")
        self.r.write("x.txt", "x\n")
        self.r.commit("orphan")
        self.rejected("is not an ancestor")

    def test_anchor_missing(self):
        v = self.r.check(anchor="f" * 40)
        self.assertTrue(v and "not present" in v[0], v)

    def test_shallow_clone(self):
        with tempfile.TemporaryDirectory() as t:
            I.git(t, "clone", "-q", "--depth", "1", f"file://{self.r.d}", "c")
            v = I.check(os.path.join(t, "c"), self.r.policy())
        self.assertTrue(v and "not present" in v[0], v)

    def test_hostile_global_config_ignored(self):
        """A global core.hooksPath with a failing hook must not influence the checks (config isolation)."""
        with tempfile.TemporaryDirectory() as home:
            hooks = Path(home, "hooks")
            hooks.mkdir()
            Path(hooks, "pre-commit").write_text("#!/bin/sh\nexit 1\n")
            os.chmod(Path(hooks, "pre-commit"), 0o755)
            Path(home, ".gitconfig").write_text(f"[core]\n\thooksPath = {hooks}\n")
            saved = {k: os.environ.get(k) for k in ("HOME", "GIT_CONFIG_GLOBAL")}
            os.environ["HOME"] = home                                   # independent of the caller's environment
            os.environ["GIT_CONFIG_GLOBAL"] = str(Path(home, ".gitconfig"))
            try:
                self.r.write(APP, "x\n")
                self.r.commit("commit with hostile global configuration")
                self.assertEqual(self.r.check(), [])
            finally:
                for k, val in saved.items():
                    if val is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = val


if __name__ == "__main__":
    unittest.main()
