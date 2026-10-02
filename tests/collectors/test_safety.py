"""Static and behavioural safety audit of the collector layer: observation only."""

import re
import unittest
from pathlib import Path

from sentinelai.collectors import CollectorError, LiveReader
from sentinelai.collectors.reader import check_path

SRC = Path(__file__).resolve().parents[2] / "src" / "sentinelai" / "collectors"
CODE = {p.relative_to(SRC).as_posix(): p.read_text() for p in sorted(SRC.rglob("*.py"))}


class TestStatic(unittest.TestCase):
    def test_no_process_network_or_write_primitives(self):
        banned = (r"\bsubprocess\b", r"\bos\.system\b", r"\bos\.popen\b", r"\bos\.exec", r"\bos\.spawn",
                  r"\bimport\s+socket\b", r"\bsocket\.socket\b", r"\bctypes\b", r"\bos\.write\b", r"\bos\.remove\b", r"\bos\.unlink\b",
                  r"\bos\.rename\b", r"\bos\.chmod\b", r"\bos\.chown\b", r"\bshutil\b", r"\bsched_setaffinity\b",
                  r"\bos\.kill\b", r"\bsudo\b", r"\bnsenter\b", r"\bsetns\b", r"\.write_text\(", r"\.write_bytes\(")
        for name, code in CODE.items():
            for pat in banned:
                with self.subTest(file=name, pattern=pat):
                    self.assertIsNone(re.search(pat, code))

    def test_files_only_opened_read_only(self):
        opens = [(n, m.group(0)) for n, c in CODE.items() for m in re.finditer(r"\bopen\([^)]*\)", c)]
        self.assertEqual(opens, [("reader.py", 'open(path, "rb")')])

    def test_no_mutating_commands_referenced(self):
        for name, code in CODE.items():
            for pat in (r"\btc\s+(qdisc|class|filter)\s+(add|del|change|replace)", r"\bip\s+(link|route|addr)\b",
                        r"\bnetem\b", r"\bethtool\b", r"\biptables\b", r"\bnft\b", r"\bdocker\b", r"\bsystemctl\b",
                        r"\bbpftrace\b", r"\bbcc\b", r"\bollama\b", r"enp0s31f6"):
                with self.subTest(file=name, pattern=pat):
                    self.assertIsNone(re.search(pat, code))

    def test_imports_are_stdlib_or_project(self):
        allowed = {"collections", "dataclasses", "datetime", "enum", "errno", "math", "os", "re", "resource",
                   "statistics", "time", "typing"}
        for name, code in CODE.items():
            for mod in re.findall(r"^\s*(?:from|import)\s+([\w.]+)", code, re.M):
                with self.subTest(file=name, module=mod):
                    self.assertTrue(mod.startswith(".") or mod in allowed, mod)


class TestReaderAllowlist(unittest.TestCase):
    def test_rejects_paths_outside_proc_and_sys(self):
        for p in ("/etc/passwd", "/dev/mem", "proc/stat", "/proc/../etc/shadow", "/sys/../root", "/procfoo",
                  "/tmp/x", "/proc/stat\x00"):
            with self.subTest(p=p), self.assertRaises(CollectorError):
                check_path(p)
        r = LiveReader()
        for fn in (r.read, r.listdir, r.readlink):
            with self.assertRaises(CollectorError):
                fn("/etc/hostname")

    def test_live_reader_reports_absence_as_status(self):
        from sentinelai.collectors import Bad, Status
        v = LiveReader().read("/proc/sentinelai-does-not-exist")
        self.assertIsInstance(v, Bad)
        self.assertIs(v.status, Status.ABSENT)


if __name__ == "__main__":
    unittest.main()
