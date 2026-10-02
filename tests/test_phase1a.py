"""Phase 1A acceptance tests.

Every test executes a real command on this machine. Tests that need root run
live only when executed as root (``sudo .venv/bin/python -m unittest ...``);
otherwise they are skipped with an explicit reason, and a separate test checks
the evidence recorded by ``scripts/privileged_smoke.sh``.

Run:  PYTHONNOUSERSITE=1 .venv/bin/python -m unittest discover -s tests -v
"""

import grp
import shlex
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"
PRIV = ROOT / "results" / "phase1a" / "privileged"
IS_ROOT = os.geteuid() == 0
USER = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name


def run(cmd, timeout=60, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


class TestPython(unittest.TestCase):
    def test_interpreter_is_project_venv(self):
        self.assertEqual(Path(sys.prefix).resolve(), VENV.resolve())
        self.assertNotEqual(sys.prefix, sys.base_prefix)
        self.assertEqual(sys.version_info[:2], (3, 10))

    def test_user_site_disabled(self):
        import site

        self.assertFalse(site.ENABLE_USER_SITE)
        self.assertIn("include-system-site-packages = false", (VENV / "pyvenv.cfg").read_text())

    def test_sys_path_isolated(self):
        bad = [p for p in sys.path if "/.local/" in p or "dist-packages" in p]
        self.assertEqual(bad, [], f"contaminated sys.path entries: {bad}")

    def test_imports_resolve_from_venv(self):
        import httpx, numpy, pandas, prometheus_client, psutil, pydantic, scipy, sklearn

        for mod in (numpy, pandas, scipy, sklearn, psutil, pydantic, httpx, prometheus_client):
            self.assertTrue(
                Path(mod.__file__).resolve().is_relative_to(VENV.resolve()),
                f"{mod.__name__} loaded from {mod.__file__}",
            )

    def test_lock_matches_environment(self):
        frozen = run([str(VENV / "bin" / "pip"), "freeze", "--local"]).stdout.split()
        locked = [l for l in (ROOT / "requirements.lock").read_text().split() if "==" in l]
        self.assertEqual(sorted(frozen), sorted(locked))

    def test_pip_check(self):
        r = run([str(VENV / "bin" / "pip"), "check"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TestDocker(unittest.TestCase):
    def _docker(self, *args, timeout=120):
        """Run docker as this user. If the current process predates the
        `usermod -aG docker` (stale supplementary groups), use `sg docker`,
        which applies the group from /etc/group — no password, no sudo."""
        cmd = ["docker", *args]
        r = run(cmd, timeout=timeout)
        if r.returncode != 0 and "permission denied" in r.stderr and not IS_ROOT:
            r = run(["sg", "docker", "-c", shlex.join(cmd)], timeout=timeout)
        return r

    def test_user_in_docker_group(self):
        self.assertIn(USER, grp.getgrnam("docker").gr_mem)

    def test_docker_info(self):
        r = self._docker("info", "--format", "{{.ServerVersion}} {{.CgroupVersion}} {{.Driver}}")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(" 2 ", f" {r.stdout.strip()} ")  # cgroup v2

    def test_hello_world(self):
        r = self._docker("run", "--rm", "hello-world")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Hello from Docker!", r.stdout)


class TestEBPF(unittest.TestCase):
    def test_bpftool_runs(self):
        r = run(["bpftool", "version"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("libbpf", r.stdout)

    def test_btf_exists(self):
        btf = Path("/sys/kernel/btf/vmlinux")
        self.assertTrue(btf.exists())
        self.assertGreater(btf.stat().st_size, 1_000_000)

    def test_bpftrace_installed(self):
        r = run(["bpftrace", "--version"])
        self.assertEqual(r.returncode, 0)

    @unittest.skipUnless(IS_ROOT, "bpf() is root-only (unprivileged_bpf_disabled=2); run suite with sudo for the live attach")
    def test_bpftrace_sched_switch_live(self):
        prog = "tracepoint:sched:sched_switch { @n = count(); } interval:s:2 { exit(); }"
        r = run(["timeout", "10", "bpftrace", "-e", prog], timeout=15)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Attaching", r.stdout)
        n = int(r.stdout.split("@n:")[1].split()[0])
        self.assertGreater(n, 0)

    def test_privileged_smoke_evidence(self):
        """Validates the real output of scripts/privileged_smoke.sh (run under sudo)."""
        summary = PRIV / "summary.tsv"
        self.assertTrue(summary.exists(), "run: sudo bash scripts/privileged_smoke.sh")
        rows = {l.split("\t")[0]: l.split("\t") for l in summary.read_text().splitlines()}
        for ev in ("sched_switch", "sched_wakeup", "softirq_entry", "softirq_exit",
                   "tcp_retransmit_skb", "inet_sock_set_state", "kfree_skb"):
            row = rows[f"bpftrace:{ev}"]
            self.assertEqual(row[1], "PASS", row)
            self.assertIn("attached=yes", row[3])
        self.assertEqual(rows["bpf_leak_check"][1], "PASS")


class TestSystemTools(unittest.TestCase):
    def test_tool_versions(self):
        for cmd in (["perf", "--version"], ["ip", "-V"], ["tc", "-V"], ["ss", "-V"],
                    ["ethtool", "--version"], ["stress-ng", "--version"], ["iperf3", "--version"],
                    ["pidstat", "-V"], ["clang", "--version"], ["cmake", "--version"]):
            with self.subTest(cmd=cmd[0]):
                self.assertEqual(run(cmd).returncode, 0)

    def test_perf_restriction_documented(self):
        paranoid = int(Path("/proc/sys/kernel/perf_event_paranoid").read_text())
        r = run(["perf", "stat", "-e", "context-switches", "true"])
        if IS_ROOT:
            self.assertEqual(r.returncode, 0, r.stderr)
        elif paranoid >= 2:
            # Expected restriction: unprivileged perf is blocked; not changed in Phase 1A.
            self.assertNotEqual(r.returncode, 0)

    def test_stress_ng_functional(self):
        r = run(["stress-ng", "--cpu", "1", "--timeout", "1s", "--metrics-brief"], timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_iperf3_loopback(self):
        port = "5299"
        srv = subprocess.Popen(["iperf3", "-s", "-1", "-B", "127.0.0.1", "-p", port],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            r = None
            for _ in range(20):
                r = run(["iperf3", "-c", "127.0.0.1", "-p", port, "-t", "1", "-J"], timeout=20)
                if r.returncode == 0:
                    break
                subprocess.run(["sleep", "0.1"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("bits_per_second", r.stdout)
        finally:
            srv.kill()
            srv.wait()

    def test_physical_nic_untouched(self):
        r = run(["tc", "qdisc", "show", "dev", "enp0s31f6"])
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("netem", r.stdout)

    def test_safety_check_passes(self):
        if not os.environ.get("SSH_CONNECTION"):
            self.skipTest("no SSH_CONNECTION in this environment (e.g. under sudo); gate would correctly refuse")
        r = run([str(ROOT / "scripts" / "safety_check.sh"), "--quiet"])
        self.assertEqual(r.returncode, 0, "safety_check refused; see logs/")

    def test_safety_check_fails_closed(self):
        env = dict(os.environ, SENTINEL_PHYS_NIC="nonexistent0")
        r = run([str(ROOT / "scripts" / "safety_check.sh"), "--quiet"], env=env)
        self.assertEqual(r.returncode, 1)


class TestGit(unittest.TestCase):
    def test_repo_exists(self):
        r = run(["git", "-C", str(ROOT), "rev-parse", "--is-inside-work-tree"])
        self.assertEqual(r.stdout.strip(), "true")

    def test_initial_commit_present(self):
        r = run(["git", "-C", str(ROOT), "log", "--oneline", "-1"])
        self.assertEqual(r.returncode, 0, "no commit yet")
        files = run(["git", "-C", str(ROOT), "ls-files"]).stdout.split()
        for f in ("README.md", ".gitignore", "requirements.lock", "scripts/safety_check.sh"):
            self.assertIn(f, files)
        self.assertFalse(any(f.startswith(".venv/") for f in files), ".venv must not be committed")

    def test_clean_commit_can_be_created(self):
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                       GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
            self.assertEqual(run(["git", "clone", "-q", str(ROOT), d]).returncode, 0)
            Path(d, "probe.txt").write_text("x")
            run(["git", "-C", d, "add", "probe.txt"])
            r = run(["git", "-C", d, "commit", "-q", "-m", "probe"], env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(run(["git", "-C", d, "status", "--porcelain"]).stdout, "")


if __name__ == "__main__":
    unittest.main()
