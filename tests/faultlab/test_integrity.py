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
})
PINS = {
    "tests/faultlab/test_r2e.py": "daa4bfd7fed6bb66d0fed8eb026b7c3d2278224c2a66868940ee5a5c8ffa3250",
    "tests/faultlab/test_r2f.py": "1d085700a26cb3ddc6f74b19b6ec1a49354700366220377770008f769e635339",
}
LIVE = I.Policy(anchor=ANCHOR, add_or_modify=M4_PATHS | CHECKER_FILES, pinned=PINS)   # checker: see test_r2f


class TestLiveRepository(unittest.TestCase):
    @unittest.skipUnless(IN_GIT, "integrity checks need the git checkout")
    def test_policy_holds(self):
        self.assertEqual(I.check(ROOT, LIVE), [])

    def test_policy_paths_are_exact(self):
        for p in M4_PATHS | CHECKER_FILES | set(PINS):
            self.assertFalse(p.endswith("/") or any(c in p for c in "*?[ \t\n"), p)
        self.assertFalse(M4_PATHS & CHECKER_FILES or M4_PATHS & set(PINS) or CHECKER_FILES & set(PINS))


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
