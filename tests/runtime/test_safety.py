"""Static safety of the 2A.1 runtime core (AST): no live reads, no host mutation, writes only through the store."""

import ast
import unittest
from pathlib import Path

RUNTIME = Path(__file__).resolve().parents[2] / "src" / "sentinelai" / "runtime"
CLI = RUNTIME.parent / "__main__.py"                      # 2A.2: the replay/verify command line, same rules
FILES = sorted(RUNTIME.glob("*.py")) + [CLI]
EXPECTED = {"__init__.py", "context.py", "registry.py", "ticks.py", "store.py", "events.py", "report.py", "pipeline.py",
            "replay.py", "__main__.py", "acquisition.py", "live.py"}
EBPF_ENTRY_POINTS = {"ProcessEbpfSource", "loader_argv", "resolve_ebpf_target", "replay_argv", "DEFAULT_LOADER"}
LIVE_ENTRY_POINTS = {"collect", "collect_snapshot", "LiveReader", "sample", "resolve_target", "FixtureReader",
                     "SystemClock"} | EBPF_ENTRY_POINTS
LIVE_ALLOWED = {"collect", "resolve_target", "LiveReader", "SystemClock"}     # 2A.4: runtime/live.py only

FORBIDDEN_MODULES = {"subprocess", "socket", "ctypes", "signal", "shutil", "multiprocessing", "pty", "fcntl",
                     "resource", "urllib", "http", "requests", "httpx"}
FORBIDDEN_SENTINEL = ("collectors.reader", "collectors.probes", "collectors.commands", "collectors.snapshot",
                      "sentinelai.ebpf", "..ebpf", "collectors.ebpf")
FORBIDDEN_OS = {"kill", "killpg", "system", "popen", "remove", "unlink", "rmdir", "removedirs", "rename", "replace",
                "renames", "chmod", "chown", "lchown", "symlink", "link", "truncate", "ftruncate", "sched_setaffinity",
                "setpriority", "nice", "setuid", "setgid", "chdir", "chroot", "makedirs", "mkfifo", "mknod", "fork",
                "forkpty", "putenv", "unsetenv"}
FORBIDDEN_OS_PREFIX = ("exec", "spawn", "posix_spawn", "set")
WRITE_OS = {"open", "mkdir", "write", "fsync", "close"}          # file creation: store.py only
FORBIDDEN_TEXT = ("/proc", "/sys", "sysctl", "swapon", "swapoff", "drop_caches", "cgroup.procs", "cgroup.kill",
                  "cpu.max", "memory.max", "memory.high", "memory.swap", "cpuset.cpus", "qdisc", "netem", "tc ",
                  "ip link", "ethtool", "bpftool", "sudo")
FORBIDDEN_NAMES = {"LiveReader", "collect", "collect_snapshot", "sample", "ProcessEbpfSource", "loader_argv",
                   "eval", "exec", "compile", "__import__"}


def trees():
    return {("cli:" if f == CLI else "") + f.name: ast.parse(f.read_text(), str(f)) for f in FILES}


def docstrings(tree):
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef)) and n.body and \
                isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant):
            out.add(id(n.body[0].value))
    return out


class TestStatic(unittest.TestCase):
    def test_exactly_the_approved_modules(self):
        self.assertEqual({f.name for f in FILES}, EXPECTED)
        self.assertEqual(len(FILES), len(EXPECTED))

    def test_no_forbidden_imports(self):
        for name, tree in trees().items():
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    mods = [a.name for a in n.names]
                elif isinstance(n, ast.ImportFrom):
                    mods = [("." * n.level) + (n.module or "")]
                else:
                    continue
                for m in mods:
                    self.assertNotIn(m.split(".")[0].lstrip("."), FORBIDDEN_MODULES, (name, m))
                    self.assertFalse([s for s in FORBIDDEN_SENTINEL if s in m], (name, m))

    def test_no_live_entry_points_imported(self):
        """2A.3: pipeline imports only the pure build_snapshot. 2A.4: runtime/live.py alone may import the M3A
        live entry points (collect, resolve_target, LiveReader, SystemClock); eBPF entry points stay forbidden
        everywhere; only live.py's caller, the CLI, may import runtime.live."""
        for name, tree in trees().items():
            for n in ast.walk(tree):
                if isinstance(n, ast.ImportFrom):
                    for a in n.names:
                        self.assertNotEqual(a.name, "*", (name, n.module))
                        self.assertNotIn(a.name, EBPF_ENTRY_POINTS, (name, n.module, a.name))
                        if a.name in LIVE_ENTRY_POINTS:
                            self.assertEqual(name, "live.py", (name, n.module, a.name))
                            self.assertIn(a.name, LIVE_ALLOWED, (name, a.name))
                    if (n.module or "").split(".")[-1] == "live":
                        self.assertIn(name, ("cli:__main__.py",), (name, n.module))
                if isinstance(n, ast.Import):
                    for a in n.names:
                        self.assertFalse(a.name.endswith(".live"), (name, a.name))
        live = trees()["live.py"]
        imported = {("." * n.level + (n.module or ""), a.name) for n in ast.walk(live) if isinstance(n, ast.ImportFrom)
                    for a in n.names}
        self.assertTrue({("..collectors", x) for x in LIVE_ALLOWED} <= imported, imported)

    def test_no_forbidden_os_calls(self):
        for name, tree in trees().items():
            for n in ast.walk(tree):
                if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "os":
                    self.assertNotIn(n.attr, FORBIDDEN_OS, (name, n.attr))
                    self.assertFalse(n.attr.startswith(FORBIDDEN_OS_PREFIX) and n.attr != "sep", (name, n.attr))
                    if n.attr in WRITE_OS:
                        self.assertEqual(name, "store.py", (name, n.attr))

    def test_no_shell_and_no_dynamic_code(self):
        for name, tree in trees().items():
            for n in ast.walk(tree):
                if isinstance(n, ast.keyword):
                    self.assertNotEqual(n.arg, "shell", name)
                if isinstance(n, ast.Name) and not (name == "live.py" and n.id in LIVE_ALLOWED):
                    self.assertNotIn(n.id, FORBIDDEN_NAMES, (name, n.id))
                if isinstance(n, ast.Attribute):
                    self.assertNotIn(n.attr, {"Popen", "check_output", "check_call", "getoutput", "getstatusoutput"},
                                     (name, n.attr))

    def test_builtin_open_is_read_only(self):
        for name, tree in trees().items():
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open":
                    mode = n.args[1] if len(n.args) > 1 else next((k.value for k in n.keywords if k.arg == "mode"), None)
                    self.assertTrue(isinstance(mode, ast.Constant) and mode.value == "rb", (name, ast.dump(n)))

    def test_no_host_paths_or_mutation_commands(self):
        from sentinelai.diagnostic.contract import load_contract
        reg = load_contract().registry
        reason = reg.get("net.drop.kfree_skb").dimension
        features = {f.id for f in reg.features}
        contract_name = lambda v: v in features or (v.isupper() and reason.accepts(v))
        for name, tree in trees().items():
            skip = docstrings(tree)
            for n in ast.walk(tree):
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in skip \
                        and not contract_name(n.value):          # registry literals name contract features
                    for word in FORBIDDEN_TEXT:
                        self.assertNotIn(word, n.value, (name, n.value[:80]))

    def test_store_creates_files_exclusively(self):
        tree = trees()["store.py"]
        flags = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
                {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertTrue({"O_EXCL", "O_NOFOLLOW", "O_CREAT"} <= flags)
        new_file = [n for n in ast.walk(tree) if isinstance(n, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "_NEW_FILE" for t in n.targets)]
        self.assertEqual(len(new_file), 1)
        names = {a.attr for a in ast.walk(new_file[0]) if isinstance(a, ast.Attribute)}
        self.assertEqual(names, {"O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW"})
        self.assertNotIn("O_TRUNC", flags)


if __name__ == "__main__":
    unittest.main()
