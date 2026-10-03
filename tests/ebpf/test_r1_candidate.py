"""R1 tooling: the runtime validation only runs on the approved M3B candidate (or a descendant that adds only
R1 tooling), never on a modified implementation."""

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "m3b_r1_candidate.py"
_spec = importlib.util.spec_from_file_location("m3b_r1_candidate", _PATH)
cand_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cand_mod)


class TestCandidateCheck(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.repo = self.d.name
        self.git("init", "-q")
        self.write("ebpf/include/sentinel_core.h", "core v1\n")
        self.write("scripts/m3b_r1_validate.sh", "v1\n")
        self.candidate = self.commit("candidate")

    def tearDown(self):
        self.d.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", self.repo, "-c", "user.name=t", "-c", "user.email=t@t", *args],
                              capture_output=True, text=True, check=True).stdout.strip()

    def write(self, rel, text):
        p = Path(self.repo) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def test_candidate_itself_accepted(self):
        self.assertEqual(cand_mod.check(self.repo, self.candidate), (True, self.candidate))

    def test_tooling_only_descendant_accepted(self):
        self.write("scripts/m3b_r1_validate.sh", "v2\n")
        self.write("scripts/m3b_r1_compare.py", "x\n")
        self.write("tests/ebpf/test_r1_compare.py", "x\n")
        head = self.commit("tooling")
        self.assertEqual(cand_mod.check(self.repo, self.candidate), (True, head))

    def test_implementation_change_refused(self):
        self.write("scripts/m3b_r1_validate.sh", "v2\n")
        self.write("ebpf/include/sentinel_core.h", "core v2\n")
        self.commit("tooling + implementation")
        ok, reason = cand_mod.check(self.repo, self.candidate)
        self.assertFalse(ok)
        self.assertIn("ebpf/include/sentinel_core.h", reason)

    def test_other_script_or_test_refused(self):
        self.write("scripts/other.py", "x\n")
        self.commit("unrelated script")
        self.assertFalse(cand_mod.check(self.repo, self.candidate)[0])

    def test_non_descendant_refused(self):
        self.git("checkout", "-q", "--orphan", "other")
        self.write("x.txt", "x\n")
        self.commit("unrelated history")
        ok, reason = cand_mod.check(self.repo, self.candidate)
        self.assertFalse(ok)
        self.assertIn("does not descend", reason)

    def test_modified_tracked_file_refused(self):
        self.write("ebpf/include/sentinel_core.h", "edited, not committed\n")
        ok, reason = cand_mod.check(self.repo, self.candidate)
        self.assertFalse(ok)
        self.assertIn("tracked files modified", reason)

    def test_unknown_candidate_refused(self):
        self.assertFalse(cand_mod.check(self.repo, "0" * 40)[0])


if __name__ == "__main__":
    unittest.main()
