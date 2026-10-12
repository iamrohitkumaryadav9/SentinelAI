"""FaultLab pilot preflight (experiments/faultlab/preflight.py): fail-closed status model, read-only enforcement.

Every case except TestLiveReadOnly runs against FakeHost (an in-memory host with no write path that also enforces the
preflight's command allowlist). TestLiveReadOnly runs the real ReadOnlyHost once under an audit hook and checks that
nothing was opened for writing, created, removed or chmod-ed, and that every subprocess was an allowlisted read-only
command. No privileged command is ever executed.
"""
import ast
import copy
import importlib.util
import json
import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("faultlab_preflight", ROOT / "experiments/faultlab/preflight.py")
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)
C = P.C

FAKE_ROOT = "/repo"
REC = "pilot/decisions.json"
STAGING = "/data/sentinel-raw"
RELEASE = "6.8.0-138-generic"
GIB = 1 << 30
DIR = stat.S_IFDIR | 0o750


def full_record():
    vals = {"FZ-WORKLOAD": {k: 1 for k in P.WORKLOAD_KEYS} | {"connection_model": "one request per connection"},
            "FZ-TTRANS": {"T_TRANS_rule": "rule", "T_cap": 1, "T_fb": 1},
            "FZ-DATA-QUALITY": {"U-2": "A", "COV_MIN": 1, "N_BASE_MIN": 1, "SEG_MIN": 1},
            "FZ-CB-B": {"c_B": 1, "b": 1}, "FZ-STAGING": {"path": STAGING}, "FZ-M4-BASELINE": {"commit": "a" * 40}}
    dec = {}
    for d, (_, _, keys) in P.DECISIONS.items():
        e = {"status": "approved", "approved_by": "Rohit Kumar", "date": "2026-10-12", "reference": "test fixture"}
        if keys is not None:
            e["value"] = vals.get(d, {k: 1 for k in keys} if keys else "fixture value")
        dec[d] = e
    return {"format": P.DECISIONS_FORMAT, "decisions": dec}


class FakeHost:
    """In-memory host. Only the read interface exists; run() refuses whatever the real allowlist refuses."""

    def __init__(self):
        self.root = FAKE_ROOT
        self.calls = []
        self.sysname, self.release, self.uid, self.sudo = "Linux", RELEASE, 0, "1000"
        self.snap = {"root": {}, "links": [], "addrs": [], "routes4": [], "routes6": [], "qdiscs": [], "netns": [],
                     "run_netns": [], "cgroup_dirs": [""], "bpf_available": True, "dynamic": {}}
        self.files = {
            "/proc/self/mounts": "cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n/dev/sda2 / ext4 rw 0 0\n"
                                 "/dev/sdb1 /data ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n",
            "/sys/fs/cgroup/cgroup.controllers": "cpuset cpu io memory pids\n",
            "/sys/fs/cgroup/cgroup.subtree_control": "cpuset cpu io memory pids\n",
            "/sys/fs/cgroup/cpuset.cpus.effective": "0-23\n",
            "/sys/devices/system/cpu/online": "0-23\n",
            "/sys/devices/system/cpu/cpu18/topology/thread_siblings_list": "18\n",
            f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list": "21\n",
            "/proc/sys/net/ipv4/ip_forward": "1\n",
            "/proc/meminfo": "MemTotal: 32000000 kB\nMemAvailable: 8388608 kB\n",
            "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\n',
            "/proc/1/cgroup": "0::/init.scope\n", "/proc/2/cgroup": "0::/user.slice\n",
        }
        self.present = {"/sys/kernel/btf/vmlinux", "/proc/self/ns/net", "/sys/module/veth", "/sys/module/sch_netem",
                        "/sys/class/net/enp0s31f6", "/sys/class/net/docker0"}
        self.dirs = {"/sys/class/net": ["docker0", "enp0s31f6", "lo"], "/run/netns": []}
        self.stats = {"/run/netns": (DIR, 0), "/data": (DIR, 0), STAGING: (DIR, 1000)}
        self.free = {FAKE_ROOT: 100 * GIB, STAGING: 100 * GIB}
        self.execs = {p for _, p in P.TOOLS}
        self.path_tools = {n: f"/usr/bin/{n}" for _, n in P.PATH_TOOLS}
        self.cgroups, self.pid_list = ["", "init.scope", "user.slice"], [1, 2]
        self.record = json.dumps(full_record()).encode()
        g = ("git", "-C", FAKE_ROOT)
        self.commands = {
            ("ip", "-j", "route", "show"): (0, '[{"dst": "default", "dev": "enp0s31f6"}, {"dst": "10.0.0.0/8"}]'),
            ("tc", "-j", "qdisc", "show"): (0, '[{"kind": "fq_codel", "dev": "enp0s31f6"}, '
                                               '{"kind": "noqueue", "dev": "docker0"}]'),
            (C.BPFTOOL, "-j", "prog", "show"): (0, '[{"name": "other"}]'),
            (C.BPFTOOL, "-j", "map", "show"): (0, "[]"),
            ("systemctl", "is-enabled", P.OPENVPN_UNIT): (1, "disabled\n"),
            g + ("rev-parse", "HEAD"): (0, "b" * 40 + "\n"),
            g + ("status", "--porcelain", "--untracked-files=no"): (0, ""),
            g + ("ls-files", "--error-unmatch", "--", REC): (0, REC + "\n"),
            g + ("diff", "--quiet", "HEAD", "--", REC): (0, ""),
            g + ("merge-base", "--is-ancestor", "a" * 40, "HEAD"): (0, ""),
        }
        for argv in P.VERSION_COMMANDS:
            self.commands[argv] = (0, "version 1")

    def _log(self, *a):
        self.calls.append(a)

    def uname(self):
        return self.sysname, self.release

    def euid(self):
        return self.uid

    def read(self, path):
        self._log("read", path)
        return self.files.get(path)

    def listdir(self, path):
        self._log("listdir", path)
        return self.dirs.get(path)

    def exists(self, path):
        return path in self.present

    def lstat(self, path):
        self._log("lstat", path)
        if path in self.stats:
            mode, uid = self.stats[path]
            return SimpleNamespace(st_mode=mode, st_uid=uid)
        return None

    def free_bytes(self, path):
        return self.free[path]

    def which(self, name):
        return self.path_tools.get(name)

    def executable(self, path):
        return path in self.execs

    def uid_exists(self, uid):
        return uid == 1000

    def cgroup_dirs(self):
        return self.cgroups

    def pids(self):
        return self.pid_list

    def run(self, argv):
        self._log("run", tuple(argv))
        if not P.command_allowed(argv, self.root):
            raise P.PreflightRefused(f"refused {argv}")
        return self.commands.get(tuple(argv))

    def read_repo_file(self, rel):
        self._log("read_repo_file", rel)
        return self.record if rel == REC else None

    def sudo_uid(self):
        return self.sudo

    def snapshot(self):
        return dict(self.snap)


def run(host=None, decisions=FAKE_ROOT + "/" + REC, integrity=lambda: [], stage="full",
        verifier=lambda path: ["manifest unreadable: No such file or directory"]):
    return P.Preflight(host or FakeHost(), decisions, integrity=integrity, clock=lambda: "T", stage=stage,
                       manifest_verifier=verifier).run()


def by_id(rep):
    return {c["id"]: c for c in rep["checks"]}


def not_pass(rep):
    return sorted(c["id"] for c in rep["checks"] if c["mandatory"] and c["status"] != "PASS")


class Base(unittest.TestCase):
    def assertStatus(self, rep, cid, status, ready=False):
        c = by_id(rep)[cid]
        self.assertEqual(c["status"], status, json.dumps(c, default=str))
        self.assertEqual(rep["overall"], "READY" if ready else "NOT_READY")
        if status != "PASS":
            self.assertTrue(c["next_action"], cid)
        return c

    def with_record(self, mutate):
        h = FakeHost()
        rec = full_record()
        mutate(rec)
        h.record = json.dumps(rec).encode()
        return h


class TestPositive(Base):
    def test_fully_satisfied_configuration_is_ready(self):
        rep = run()
        self.assertEqual(not_pass(rep), [])
        self.assertEqual(rep["overall"], "READY")
        self.assertFalse(rep["authorises_run"])                     # READY is never an authorisation
        self.assertIn("Gate 2", rep["note"])
        self.assertEqual(rep["blockers"], {"owner_approval": [], "environment": [], "technical": []})
        self.assertEqual({c["id"] for c in rep["checks"] if c["mandatory"]}, P.MANDATORY_IDS)

    def test_staging_path_free_space_and_memory_exactly_at_the_floors(self):
        h = FakeHost()
        h.files["/proc/meminfo"] = f"MemAvailable: {4 * GIB // 1024} kB\n"
        h.free[FAKE_ROOT] = h.free[STAGING] = 20 * GIB
        self.assertEqual(run(h)["overall"], "READY")

    def test_lab_uid_owned_or_invoking_uid_owned_staging(self):
        for uid, owner in ((0, 0), (1000, 1000), (0, 1000)):
            h = FakeHost()
            h.uid, h.stats[STAGING] = uid, (DIR, owner)
            rep = run(h)
            if uid == 1000:   # ENV-PRIVILEGE is UNVERIFIED for a non-root preflight; staging itself still passes
                self.assertEqual(by_id(rep)["STG-PERMISSIONS"]["status"], "PASS")
            else:
                self.assertEqual(rep["overall"], "READY")


class TestEnvironment(Base):
    def test_missing_tools_fail(self):
        for cid, path in P.TOOLS:
            with self.subTest(tool=path):
                h = FakeHost()
                h.execs.discard(path)
                c = self.assertStatus(run(h), cid, "FAIL")
                self.assertIn(cid, run(h)["blockers"]["environment"])
                self.assertIn(path, c["next_action"])
        for cid, name in P.PATH_TOOLS:
            with self.subTest(tool=name):
                h = FakeHost()
                del h.path_tools[name]
                self.assertStatus(run(h), cid, "FAIL")

    def test_unsupported_os_and_kernel(self):
        h = FakeHost()
        h.sysname = "Darwin"
        self.assertStatus(run(h), "ENV-KERNEL", "FAIL")
        h = FakeHost()
        h.release = "6.11.0-29-generic"
        self.assertStatus(run(h), "ENV-KERNEL-TOOLING", "FAIL")
        h = FakeHost()
        h.release = "6.8.0-1380-generic"                           # prefix trick: 6.8.0-138 must end at '-'
        self.assertStatus(run(h), "ENV-KERNEL-TOOLING", "FAIL")
        h = FakeHost()
        h.present.discard("/sys/kernel/btf/vmlinux")
        self.assertStatus(run(h), "ENV-BTF", "FAIL")
        h = FakeHost()
        h.files["/proc/self/mounts"] = "cgroup /sys/fs/cgroup cgroup rw 0 0\n"
        self.assertStatus(run(h), "ENV-CGROUP2", "FAIL")

    def test_missing_kernel_modules(self):
        for mod, cid in (("veth", "LAB-VETH-AVAILABLE"), ("sch_netem", "LAB-NETEM-AVAILABLE")):
            h = FakeHost()
            h.present.discard(f"/sys/module/{mod}")
            self.assertStatus(run(h), cid, "UNVERIFIED")              # /lib/modules unreadable in the fake
            h.files[f"/lib/modules/{RELEASE}/modules.builtin"] = "kernel/net/other.ko\n"
            self.assertStatus(run(h), cid, "FAIL")
            h.files[f"/lib/modules/{RELEASE}/modules.builtin"] = f"kernel/x/{mod}.ko\n"
            self.assertEqual(by_id(run(h))[cid]["status"], "PASS")

    def test_unprivileged_preflight_cannot_be_ready(self):
        h = FakeHost()
        h.uid = 1000
        c = self.assertStatus(run(h), "ENV-PRIVILEGE", "UNVERIFIED")
        self.assertIn("never invokes sudo", c["explanation"])

    def test_memory_and_disk_below_the_committed_floors(self):
        h = FakeHost()
        h.files["/proc/meminfo"] = f"MemAvailable: {4 * GIB // 1024 - 1} kB\n"
        self.assertStatus(run(h), "RES-MEM-AVAILABLE", "FAIL")
        h = FakeHost()
        h.files["/proc/meminfo"] = f"MemAvailable: {3 * GIB // 1024} kB\n"   # passes design §9's stale 2 GiB floor
        self.assertStatus(run(h), "RES-MEM-AVAILABLE", "FAIL")
        h = FakeHost()
        h.free[FAKE_ROOT] = 20 * GIB - 1
        self.assertStatus(run(h), "RES-DISK-REPO", "FAIL")
        h = FakeHost()
        del h.files["/proc/meminfo"]
        self.assertStatus(run(h), "RES-MEM-AVAILABLE", "UNVERIFIED")

    def test_conflicting_resources_fail(self):
        cases = {
            "LAB-NO-SENTINEL-NETNS": lambda h: h.dirs.__setitem__("/run/netns", ["sentinel-lab-a"]),
            "LAB-NO-LAB-INTERFACES": lambda h: h.dirs["/sys/class/net"].append("sentlab-a0"),
            "LAB-NO-SENTINEL-CGROUP": lambda h: h.cgroups.append("sentinel-fl/target"),
            "LAB-NO-LAB-PROCESS": lambda h: h.files.__setitem__("/proc/2/cgroup", "0::/sentinel-fl/target\n"),
            "LAB-RUN-DIR-ABSENT": lambda h: h.stats.__setitem__(P.RUN_LAB, (DIR, 1000)),
            "LAB-NO-NETEM": lambda h: h.commands.__setitem__(("tc", "-j", "qdisc", "show"),
                                                             (0, '[{"kind": "fq_codel", "dev": "enp0s31f6"}, '
                                                                 '{"kind": "netem", "dev": "veth9"}]')),
            "LAB-NO-SENTINEL-BPF": lambda h: h.commands.__setitem__((C.BPFTOOL, "-j", "prog", "show"),
                                                                    (0, '[{"name": "sn_wake"}]')),
            "LAB-OPENVPN-DISABLED": lambda h: h.commands.__setitem__(("systemctl", "is-enabled", P.OPENVPN_UNIT),
                                                                     (0, "enabled\n")),
            "LAB-PROTECTED-IFACES": lambda h: h.present.discard("/sys/class/net/docker0"),
            "LAB-DEFAULT-ROUTE": lambda h: h.commands.__setitem__(("ip", "-j", "route", "show"),
                                                                  (0, '[{"dst": "default", "dev": "wlan0"}]')),
            "LAB-ROOT-CPUSET": lambda h: h.files.__setitem__("/sys/fs/cgroup/cpuset.cpus.effective", "0-21\n"),
            "LAB-NIC-IRQ": lambda h: h.files.__setitem__(f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list", "18\n"),
            "LAB-CPU18-NO-SMT": lambda h: h.files.__setitem__(
                "/sys/devices/system/cpu/cpu18/topology/thread_siblings_list", "18-19\n"),
            "LAB-ROOT-SUBTREE": lambda h: h.files.__setitem__("/sys/fs/cgroup/cgroup.subtree_control", "cpu cpu\n"),
            "LAB-IP-FORWARD": lambda h: h.files.__setitem__("/proc/sys/net/ipv4/ip_forward", "0\n"),
            "LAB-LAB-UID": lambda h: setattr(h, "uid_exists", lambda uid: False),
        }
        for cid, mutate in cases.items():
            with self.subTest(cid):
                h = FakeHost()
                mutate(h)
                rep = run(h)
                self.assertStatus(rep, cid, "FAIL")
                self.assertEqual(not_pass(rep), [cid])
                self.assertIn(cid, rep["blockers"]["environment"])

    def test_unverifiable_prerequisites(self):
        cases = {
            "LAB-NO-SENTINEL-BPF": lambda h: h.commands.__setitem__((C.BPFTOOL, "-j", "map", "show"), None),
            "LAB-OPENVPN-DISABLED": lambda h: h.commands.pop(("systemctl", "is-enabled", P.OPENVPN_UNIT)),
            "LAB-DEFAULT-ROUTE": lambda h: h.commands.pop(("ip", "-j", "route", "show")),
            "LAB-NO-SENTINEL-NETNS": lambda h: h.dirs.pop("/run/netns"),
            "LAB-NIC-IRQ": lambda h: h.files.pop(f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list"),
            "LAB-ROOT-SUBTREE": lambda h: h.files.pop("/sys/fs/cgroup/cgroup.subtree_control"),
        }
        for cid, mutate in cases.items():
            with self.subTest(cid):
                h = FakeHost()
                mutate(h)
                self.assertStatus(run(h), cid, "UNVERIFIED")

    def test_absent_run_netns_directory_is_no_conflict(self):
        h = FakeHost()
        del h.stats["/run/netns"]
        del h.dirs["/run/netns"]
        self.assertEqual(run(h)["overall"], "READY")


class TestApprovals(Base):
    def test_no_record_blocks_every_decision_and_dependent_check(self):
        rep = run(decisions=None)
        c = by_id(rep)
        self.assertEqual(c["PROV-DECISIONS-RECORD"]["status"], "BLOCKED")
        for d in P.DECISIONS:
            self.assertEqual(c[f"APPR-{d}"]["status"], "BLOCKED", d)
        for cid in ("LAB-ROOT-SUBTREE", "LAB-CPUS-ONLINE", "LAB-NIC-IRQ", "LAB-IP-FORWARD", "STG-EXISTS",
                    "INT-M4-BASELINE"):
            self.assertEqual(c[cid]["status"], "BLOCKED", cid)
        self.assertEqual(c["LAB-NIC-IRQ"]["evaluation"], "PASS")    # host fine, requirement not approved
        self.assertEqual(rep["overall"], "NOT_READY")
        self.assertIn("APPR-FZ-PI7", rep["blockers"]["owner_approval"])
        self.assertIn("LAB-NIC-IRQ", rep["blockers"]["owner_approval"])

    def test_register_decisions_are_all_required(self):
        required = {"FZ-WORKLOAD", "FZ-INTENSITY", "FZ-PI5", "FZ-PI7", "FZ-PI8", "FZ-TTRANS", "FZ-DATA-QUALITY",
                    "FZ-CB-B", "FZ-STAGING", "FZ-MANIFEST", "FZ-ROOT-OF-TRUST", "FZ-EXCLUSIONS", "FZ-R2CD-ENV"}
        required |= {f"FZ-AMD-{n:02d}" for n in range(1, 18)}
        self.assertLessEqual(required, set(P.DECISIONS))
        self.assertLessEqual({f"APPR-{d}" for d in P.DECISIONS}, P.MANDATORY_IDS)
        self.assertEqual(P.DECISIONS["FZ-TTRANS"][2], ("T_TRANS_rule", "T_cap", "T_fb"))
        self.assertEqual(P.DECISIONS["FZ-DATA-QUALITY"][2], ("U-2", "COV_MIN", "N_BASE_MIN", "SEG_MIN"))
        self.assertEqual(P.DECISIONS["FZ-CB-B"][2], ("c_B", "b"))

    def test_each_unapproved_decision_prevents_ready(self):
        for d in P.DECISIONS:
            for status in ("proposed", "pending", "rejected"):
                with self.subTest(decision=d, status=status):
                    h = self.with_record(lambda r: r["decisions"][d].update(status=status))
                    rep = run(h)
                    self.assertStatus(rep, f"APPR-{d}", "BLOCKED")
                    self.assertIn(f"APPR-{d}", rep["blockers"]["owner_approval"])
            with self.subTest(decision=d, status="absent"):
                self.assertStatus(run(self.with_record(lambda r: r["decisions"].pop(d))), f"APPR-{d}", "BLOCKED")

    def test_dependent_check_blocked_even_when_host_fails(self):
        h = self.with_record(lambda r: r["decisions"]["FZ-LAB-SPEC"].update(status="pending"))
        h.files[f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list"] = "18\n"
        c = self.assertStatus(run(h), "LAB-NIC-IRQ", "BLOCKED")
        self.assertEqual((c["evaluation"], c["blocked_by"]), ("FAIL", ["FZ-LAB-SPEC"]))
        self.assertIn("LAB-NIC-IRQ", run(h)["blockers"]["environment"])   # both kinds of blocker are reported

    def test_missing_or_invalid_workload_parameters(self):
        for k in P.WORKLOAD_KEYS:
            with self.subTest(missing=k):
                c = self.assertStatus(run(self.with_record(lambda r: r["decisions"]["FZ-WORKLOAD"]["value"].pop(k))),
                                      "APPR-FZ-WORKLOAD", "BLOCKED")
                self.assertIn(k, c["explanation"])
        for k, v in (("pool", "16"), ("rate_per_s", True), ("cpu_us", None), ("connection_model", " "),
                     ("queue", [1])):
            with self.subTest(bad=k):
                self.assertStatus(run(self.with_record(lambda r: r["decisions"]["FZ-WORKLOAD"]["value"].update({k: v}))),
                                  "APPR-FZ-WORKLOAD", "BLOCKED")
        self.assertStatus(run(self.with_record(lambda r: r["decisions"]["FZ-WORKLOAD"]["value"].update(extra=1))),
                          "APPR-FZ-WORKLOAD", "BLOCKED")
        self.assertStatus(run(self.with_record(lambda r: r["decisions"]["FZ-WORKLOAD"].pop("value"))),
                          "APPR-FZ-WORKLOAD", "BLOCKED")

    def test_pi7_and_pi8_registration(self):
        for d in ("FZ-PI7", "FZ-PI8"):
            with self.subTest(d):
                self.assertStatus(run(self.with_record(lambda r: r["decisions"].pop(d))), f"APPR-{d}", "BLOCKED")
                self.assertStatus(run(self.with_record(lambda r: r["decisions"][d].update(value=None))),
                                  f"APPR-{d}", "BLOCKED")

    def test_value_keys_of_parameter_decisions(self):
        for d in ("FZ-TTRANS", "FZ-DATA-QUALITY", "FZ-CB-B", "FZ-STAGING", "FZ-M4-BASELINE"):
            for k in P.DECISIONS[d][2]:
                with self.subTest(decision=d, key=k):
                    self.assertStatus(run(self.with_record(lambda r: r["decisions"][d]["value"].pop(k))),
                                      f"APPR-{d}", "BLOCKED")
        self.assertStatus(run(self.with_record(lambda r: r["decisions"]["FZ-M4-BASELINE"]["value"].update(
            commit="abc123"))), "APPR-FZ-M4-BASELINE", "BLOCKED")

    def test_malformed_record_is_ignored_entirely(self):
        good = json.dumps(full_record())
        cases = {
            "invalid json": b"{",
            "duplicate key": good.replace('"decisions": {', '"decisions": {"FZ-PI5": {"status": "pending"}, ', 1)
            .encode(),
            "nan": good.replace('"T_cap": 1', '"T_cap": NaN').encode(),
            "oversize": b" " * (P.DECISIONS_MAX + 1),
            "not utf-8": b"\xff\xfe",
        }
        mutations = {
            "unknown id": lambda r: r["decisions"].update({"FZ-NEW": dict(r["decisions"]["FZ-PI5"])}),
            "wrong format": lambda r: r.update(format="other"),
            "extra top-level key": lambda r: r.update(signed=True),
            "wrong approver": lambda r: r["decisions"]["FZ-PI5"].update(approved_by="Claude"),
            "bad date": lambda r: r["decisions"]["FZ-PI5"].update(date="2026-13-40"),
            "no reference": lambda r: r["decisions"]["FZ-PI5"].update(reference=""),
            "unknown entry key": lambda r: r["decisions"]["FZ-PI5"].update(frozen=True),
            "bad status": lambda r: r["decisions"]["FZ-PI5"].update(status="APPROVED"),
            "decisions not object": lambda r: r.update(decisions=[]),
        }
        for name, m in mutations.items():
            rec = full_record()
            m(rec)
            cases[name] = json.dumps(rec).encode()
        for name, data in cases.items():
            with self.subTest(name):
                h = FakeHost()
                h.record = data
                rep = run(h)
                self.assertStatus(rep, "PROV-DECISIONS-RECORD", "FAIL")
                self.assertTrue(all(by_id(rep)[f"APPR-{d}"]["status"] == "BLOCKED" for d in P.DECISIONS))
                self.assertIn("PROV-DECISIONS-RECORD", rep["blockers"]["technical"])

    def test_record_provenance(self):
        g = ("git", "-C", FAKE_ROOT)
        cases = {
            "untracked": (lambda h: h.commands.__setitem__(g + ("ls-files", "--error-unmatch", "--", REC),
                                                           (1, "")), "FAIL"),
            "modified": (lambda h: h.commands.__setitem__(g + ("diff", "--quiet", "HEAD", "--", REC), (1, "")),
                         "FAIL"),
            "git unavailable": (lambda h: h.commands.pop(g + ("ls-files", "--error-unmatch", "--", REC)),
                                "UNVERIFIED"),
            "symlink or unreadable": (lambda h: setattr(h, "record", None), "FAIL"),
        }
        for name, (m, status) in cases.items():
            with self.subTest(name):
                h = FakeHost()
                m(h)
                self.assertStatus(run(h), "PROV-DECISIONS-RECORD", status)
        self.assertStatus(run(decisions="/elsewhere/decisions.json"), "PROV-DECISIONS-RECORD", "FAIL")


class TestStaging(Base):
    def stg(self, mutate, cid, status="FAIL"):
        h = FakeHost()
        mutate(h)
        return self.assertStatus(run(h), cid, status)

    def test_staging_undecided_is_blocked(self):
        h = self.with_record(lambda r: r["decisions"]["FZ-STAGING"].update(status="pending"))
        rep = run(h)
        for cid in ("STG-EXISTS", "STG-PERSISTENT", "STG-PERMISSIONS", "STG-FREE-SPACE"):
            self.assertStatus(rep, cid, "BLOCKED")
        self.assertFalse([c for c in h.calls if c[0] == "lstat" and c[1].startswith("/data")])   # nothing inspected

    def test_unsuitable_staging_location(self):
        self.stg(lambda h: h.stats.pop(STAGING), "STG-EXISTS")
        self.stg(lambda h: h.stats.pop("/data"), "STG-EXISTS")
        self.stg(lambda h: h.stats.__setitem__("/data", (stat.S_IFLNK | 0o777, 0)), "STG-EXISTS")
        self.stg(lambda h: h.stats.__setitem__(STAGING, (stat.S_IFREG | 0o640, 1000)), "STG-EXISTS")
        self.stg(lambda h: h.files.__setitem__("/proc/self/mounts", "tmpfs /data tmpfs rw 0 0\n"), "STG-PERSISTENT")
        self.stg(lambda h: h.stats.__setitem__(STAGING, (DIR | 0o002, 1000)), "STG-PERMISSIONS")
        self.stg(lambda h: h.stats.__setitem__(STAGING, (DIR, 1234)), "STG-PERMISSIONS")
        self.stg(lambda h: h.free.__setitem__(STAGING, 20 * GIB - 1), "STG-FREE-SPACE")
        for path in ("/data/../data/sentinel-raw", "/data/sentinel-raw/", "/"):
            with self.subTest(path=path):
                h = self.with_record(lambda r: r["decisions"]["FZ-STAGING"]["value"].update(path=path))
                self.assertStatus(run(h), "STG-EXISTS", "FAIL")
        h = self.with_record(lambda r: r["decisions"]["FZ-STAGING"]["value"].update(path="relative/dir"))
        self.assertStatus(run(h), "APPR-FZ-STAGING", "BLOCKED")

    def test_longest_mount_prefix_decides_the_filesystem(self):
        def m(h):
            h.files["/proc/self/mounts"] = "/dev/sda2 / ext4 rw 0 0\ntmpfs /data/sentinel-raw tmpfs rw 0 0\n" \
                                           "/dev/sdb1 /data ext4 rw 0 0\n"
        self.stg(m, "STG-PERSISTENT")
        h = FakeHost()
        h.files["/proc/self/mounts"] = "tmpfs /dat tmpfs rw 0 0\n/dev/sda2 / ext4 rw 0 0\n"   # /dat is not /data
        self.assertEqual(by_id(run(h))["STG-PERSISTENT"]["status"], "PASS")


class TestFailClosed(Base):
    def test_mandatory_fail_prevents_ready(self):
        rep = run(integrity=lambda: ["unexpected change: 'src/x.py'"])
        self.assertStatus(rep, "INT-INTEGRITY-POLICY", "FAIL")
        self.assertEqual(rep["blockers"]["technical"], ["INT-INTEGRITY-POLICY"])
        h = FakeHost()
        h.commands[("git", "-C", FAKE_ROOT, "status", "--porcelain", "--untracked-files=no")] = (0, " M src/a.py\n")
        self.assertStatus(run(h), "INT-REPO-CLEAN", "FAIL")
        h = FakeHost()
        h.commands[("git", "-C", FAKE_ROOT, "merge-base", "--is-ancestor", "a" * 40, "HEAD")] = (1, "")
        self.assertStatus(run(h), "INT-M4-BASELINE", "FAIL")

    def test_mandatory_unverified_prevents_ready(self):
        def boom():
            raise RuntimeError("git broke")
        c = self.assertStatus(run(integrity=boom), "INT-INTEGRITY-POLICY", "UNVERIFIED")
        self.assertIn("git broke", c["explanation"])
        self.assertStatus(run(integrity=lambda: None), "INT-INTEGRITY-POLICY", "UNVERIFIED")

    def test_exception_in_any_check_is_unverified_not_pass(self):
        h = FakeHost()
        h.free_bytes = mock.Mock(side_effect=OSError("statvfs failed"))
        rep = run(h)
        self.assertStatus(rep, "RES-DISK-REPO", "UNVERIFIED")
        self.assertEqual(by_id(rep)["STG-FREE-SPACE"]["status"], "UNVERIFIED")

    def test_unsafe_operation_is_intercepted_and_fails_the_check(self):
        h = FakeHost()
        real = h.run
        h.run = lambda argv: real(("ip", "netns", "add", "x")) if argv[:3] == ("ip", "-j", "route") else real(argv)
        c = self.assertStatus(run(h), "LAB-DEFAULT-ROUTE", "FAIL")
        self.assertIn("unsafe operation intercepted", c["explanation"])

    def test_skipped_or_tampered_mandatory_check_prevents_ready(self):
        pf = P.Preflight(FakeHost(), FAKE_ROOT + "/" + REC, integrity=lambda: [], clock=lambda: "T")
        with mock.patch.object(P.Preflight, "resource_checks", lambda self: None):
            rep = pf.run()
        self.assertStatus(rep, "PF-COMPLETENESS", "FAIL")
        self.assertIn("RES-MEM-AVAILABLE", by_id(rep)["PF-COMPLETENESS"]["explanation"])
        for tamper in ({"status": "WARN"}, {"mandatory": False}):
            checks = [P.Check(**c) for c in run()["checks"] if c["id"] != "PF-COMPLETENESS"]
            for k, v in tamper.items():
                setattr(checks[5], k, v)
            rep = P.report(checks, "T", {})
            self.assertEqual(rep["overall"], "NOT_READY", tamper)
            self.assertEqual(by_id(rep)["PF-COMPLETENESS"]["status"], "FAIL")
        checks = [P.Check(**c) for c in run()["checks"]]
        rep = P.report(checks + [checks[3]], "T", {})                 # duplicated id
        self.assertEqual(rep["overall"], "NOT_READY")

    def test_result_constructor_rejects_unknown_status(self):
        with self.assertRaises(AssertionError):
            P.Result("WARN")

    def test_report_is_json_and_actionable_with_provenance(self):
        rep = json.loads(json.dumps(run(decisions=None), default=str))
        for c in rep["checks"]:
            for k in ("id", "status", "required", "provenance", "category", "mandatory"):
                self.assertTrue(c[k] is not None and c[k] != "", (c["id"], k))
            if c["status"] != "PASS":
                self.assertTrue(c["next_action"], c["id"])
        c = by_id(rep)
        self.assertIn("scripts/safety_check.sh:17", c["RES-MEM-AVAILABLE"]["provenance"])
        self.assertIn("scripts/r2f_memory.py", c["LAB-ROOT-SUBTREE"]["provenance"])
        for d in P.DECISIONS:
            self.assertTrue(c[f"APPR-{d}"]["provenance"])
            self.assertIn(d, c[f"APPR-{d}"]["next_action"])
        self.assertIn("PHASE_1C_FREEZE1_DECISION_REGISTER", c["APPR-FZ-PI8"]["provenance"])
        self.assertIn("Not consumed by a host check", c["APPR-FZ-CB-B"]["explanation"])
        self.assertEqual(set(rep["invariants"]), {"preflight", "before_run", "after_run", "not_guaranteed"})
        self.assertIn("caveat", rep["host_state"])


class TestStagesAndPrivilege(Base):
    def test_ctrl_stage_does_not_require_fault_class_decisions(self):
        def pend(r):
            for d in P.FULL_ONLY:
                r["decisions"][d] = {"status": "pending", "reference": "unresolved"}
        h = self.with_record(pend)
        rep = run(h, stage="ctrl")
        self.assertEqual(rep["overall"], "READY", not_pass(rep))
        self.assertEqual(rep["stage"], "ctrl")
        for d in P.FULL_ONLY:
            c = by_id(rep)[f"APPR-{d}"]
            self.assertEqual((c["status"], c["mandatory"]), ("BLOCKED", False))
        rep = run(self.with_record(pend), stage="full")
        self.assertEqual(rep["overall"], "NOT_READY")
        self.assertEqual(sorted(not_pass(rep)), sorted(f"APPR-{d}" for d in P.FULL_ONLY))
        with self.assertRaises(ValueError):
            P.Preflight(FakeHost(), stage="partial")

    def test_ctrl_stage_still_requires_every_other_decision(self):
        for d in sorted(set(P.DECISIONS) - P.FULL_ONLY):
            with self.subTest(d):
                rep = run(self.with_record(lambda r: r["decisions"][d].update(status="proposed")), stage="ctrl")
                self.assertStatus(rep, f"APPR-{d}", "BLOCKED")
                self.assertTrue(by_id(rep)[f"APPR-{d}"]["mandatory"])

    def test_root_must_come_from_sudo_by_the_lab_uid(self):
        for sudo in (None, "0", "1001", ""):
            with self.subTest(sudo=sudo):
                h = FakeHost()
                h.sudo = sudo
                self.assertStatus(run(h), "ENV-PRIVILEGE", "FAIL")

    def test_host_baseline_needs_network_and_bpf_state(self):
        h = FakeHost()
        h.snap["bpf_available"] = False
        self.assertStatus(run(h), "LAB-HOST-BASELINE", "UNVERIFIED")
        h = FakeHost()
        h.snap["routes6"] = None
        self.assertStatus(run(h), "LAB-HOST-BASELINE", "UNVERIFIED")
        h = FakeHost()
        h.snapshot = mock.Mock(side_effect=OSError("bpftool"))
        self.assertStatus(run(h), "LAB-HOST-BASELINE", "UNVERIFIED")

    def test_manifest_verifier_must_fail_closed(self):
        self.assertStatus(run(verifier=lambda path: []), "INT-MANIFEST-VERIFIER", "FAIL")
        self.assertStatus(run(verifier=mock.Mock(side_effect=ImportError("x"))), "INT-MANIFEST-VERIFIER",
                          "UNVERIFIED")
        self.assertEqual(by_id(run(verifier=P.default_manifest_verifier))["INT-MANIFEST-VERIFIER"]["status"], "PASS")

    def test_root_git_runs_as_the_invoker(self):
        host = P.ReadOnlyHost()
        done = subprocess.CompletedProcess([], 0, "x\n", "")
        with mock.patch.object(P.os, "geteuid", return_value=0), \
                mock.patch.dict(P.os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}), \
                mock.patch.object(P.subprocess, "run", return_value=done) as sp:
            host.run(("git", "-C", str(ROOT), "rev-parse", "HEAD"))
            host.run(("ip", "-V"))
        self.assertEqual(sp.call_args_list[0].args[0][:5], ["setpriv", "--reuid=1000", "--regid=1000",
                                                            "--init-groups", "--"])
        self.assertEqual(sp.call_args_list[0].args[0][5:], ["git", "-C", str(ROOT), "rev-parse", "HEAD"])
        self.assertEqual(sp.call_args_list[1].args[0], ["ip", "-V"])
        for env in ({}, {"SUDO_UID": "0", "SUDO_GID": "0"}, {"SUDO_UID": "1000"}):
            with self.subTest(env=env), mock.patch.object(P.os, "geteuid", return_value=0), \
                    mock.patch.dict(P.os.environ, env, clear=True), \
                    mock.patch.object(P.subprocess, "run", side_effect=AssertionError("executed")) as sp:
                with self.assertRaises(P.PreflightRefused):
                    host.run(("git", "-C", str(ROOT), "rev-parse", "HEAD"))
                with self.assertRaises(P.PreflightRefused):
                    P.default_integrity()
                sp.assert_not_called()

    def test_root_integrity_policy_runs_as_the_invoker(self):
        done = subprocess.CompletedProcess([], 0, "[]\n", "")
        with mock.patch.object(P.os, "geteuid", return_value=0), \
                mock.patch.dict(P.os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}), \
                mock.patch.object(P.subprocess, "run", return_value=done) as sp:
            self.assertEqual(P.default_integrity(), [])
        argv = sp.call_args.args[0]
        self.assertEqual(argv[:5], ["setpriv", "--reuid=1000", "--regid=1000", "--init-groups", "--"])
        self.assertEqual(argv[-1], str(ROOT))
        bad = subprocess.CompletedProcess([], 1, "", "boom")
        with mock.patch.object(P.os, "geteuid", return_value=0), \
                mock.patch.dict(P.os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}), \
                mock.patch.object(P.subprocess, "run", return_value=bad):
            with self.assertRaises(RuntimeError):
                P.default_integrity()

    def test_committed_record_holds_the_decision_package_and_keeps_the_rest_pending(self):
        dec, errs = P.parse_decisions((ROOT / "docs/PHASE_1C_FREEZE1_DECISIONS.json").read_bytes())
        self.assertEqual(errs, [])
        for d in ("FZ-INTENSITY", "FZ-PI5"):
            self.assertEqual(P.decision_state(d, dec[d])[0], False, d)        # still unresolved parts
        package = {"FZ-INTENSITY-R2", "FZ-INTENSITY-APP", "FZ-INTENSITY-NET", "FZ-PI7-LOCK", "FZ-WORKSET", "FZ-OV",
                   "FZ-Q5", "FZ-Q2"}
        self.assertLessEqual(package, P.FULL_ONLY)                         # the ctrl stage does not depend on them
        for d in package:
            self.assertEqual(P.decision_state(d, dec[d]), (True, "approved"), d)
            self.assertEqual((dec[d]["approved_by"], dec[d]["date"]), ("Rohit Kumar", "2026-10-12"), d)
        v = lambda d: dec[d]["value"]
        self.assertEqual(v("FZ-INTENSITY-R2"), {"loss_a_egress_max_pct": 5.0, "cpu_quota_min_core": 0.075,
                                                "contender_weight_max": 400})
        self.assertEqual((v("FZ-PI7-LOCK")["ctrl_max_lock_wait_ms"], v("FZ-PI7-LOCK")["rep_lock_wait_p99_min_ms"]),
                         (0.0, 0.05))
        app = v("FZ-INTENSITY-APP")
        self.assertEqual((app["pool_min"], app["lock_hold_us_max"], app["dependency_delay_ms_max"]), (1, 5000, 15))
        self.assertTrue(max(app["lock_hold_us_candidates"]) <= app["lock_hold_us_max"] and
                        max(app["dependency_delay_ms_candidates"]) <= app["dependency_delay_ms_max"] and
                        min(app["pool_candidates"]) >= app["pool_min"])
        ws = v("FZ-WORKSET")["values"]                                     # D4 values, approved the same day
        self.assertEqual((ws["file_mib"], ws["pass_s"], ws["slices_per_pass"], ws["anon_mib"]), (1024, 1.0, 10, 16))
        self.assertEqual(v("FZ-Q2")["collector_mode_m6"], "driver-root")

    def test_committed_decisions_record_grants_only_what_it_states(self):
        data = (ROOT / "docs/PHASE_1C_FREEZE1_DECISIONS.json").read_bytes()
        dec, errs = P.parse_decisions(data)
        self.assertEqual(errs, [])
        self.assertEqual(set(dec), set(P.DECISIONS))
        h = FakeHost()
        h.record = data
        rep = run(h)
        for d, e in dec.items():
            approved = e["status"] == "approved" and P.decision_state(d, e)[0]
            self.assertEqual(by_id(rep)[f"APPR-{d}"]["status"], "PASS" if approved else "BLOCKED", d)
            if e["status"] == "approved":
                self.assertEqual(e["approved_by"], "Rohit Kumar")


class TestReadOnlyHost(unittest.TestCase):
    UNSAFE = (["sudo", "-n", "true"], ["ip", "netns", "add", "sentinel-lab-a"], ["ip", "link", "add", "x", "type",
              "veth"], ["tc", "qdisc", "add", "dev", "lo", "root", "netem"], [C.BPFTOOL, "prog", "load", "x", "/y"],
              ["systemctl", "disable", P.OPENVPN_UNIT], ["sh", "-c", "echo 1 > /sys/fs/cgroup/x"],
              ["git", "-C", str(ROOT), "checkout", "HEAD"], ["git", "-C", str(ROOT), "ls-files", "--error-unmatch",
              "--", "../etc/passwd"], ["git", "-C", "/elsewhere", "rev-parse", "HEAD"],
              ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", "HEAD~1", "HEAD"],
              ["git", "-C", str(ROOT), "diff", "--quiet", "HEAD", "--", "a;rm -rf /"], ["mkdir", P.RUN_LAB])

    def test_unsafe_commands_are_refused_before_execution(self):
        host = P.ReadOnlyHost()
        with mock.patch.object(P.subprocess, "run", side_effect=AssertionError("executed")) as sp:
            for argv in self.UNSAFE:
                with self.subTest(argv=argv), self.assertRaises(P.PreflightRefused):
                    host.run(argv)
            sp.assert_not_called()

    def test_reads_outside_the_allowlist_are_refused(self):
        host = P.ReadOnlyHost()
        for path in ("/etc/shadow", "/home/iiitd/.ssh/id_rsa", "/proc/../etc/shadow", "relative"):
            with self.subTest(path=path), self.assertRaises(P.PreflightRefused):
                host.read(path)
        for rel in ("../x", "/abs", "a/../b", "a b"):
            with self.subTest(rel=rel), self.assertRaises(P.PreflightRefused):
                host.read_repo_file(rel)
        with self.assertRaises(P.PreflightRefused):
            host.lstat("relative/path")

    def test_allowlist_is_exact(self):
        root = str(ROOT)
        self.assertTrue(P.command_allowed(("git", "-C", root, "merge-base", "--is-ancestor", "a" * 40, "HEAD"), root))
        self.assertFalse(P.command_allowed(("git", "-C", root, "merge-base", "--is-ancestor", "a" * 39, "HEAD"),
                                           root))
        self.assertFalse(P.command_allowed(("systemctl", "is-enabled", "ssh.service"), root))
        self.assertFalse(P.command_allowed(("tc", "-j", "qdisc", "show", "dev", "lo"), root))
        for argv in C.READ_ONLY_COMMANDS:
            self.assertTrue(P.command_allowed(argv, root), argv)

    def test_no_mutating_call_in_the_module(self):
        tree = ast.parse((ROOT / "experiments/faultlab/preflight.py").read_text())
        forbidden = {"mkdir", "makedirs", "remove", "unlink", "rmdir", "rename", "replace", "chmod", "chown",
                     "symlink", "link", "truncate", "write_text", "write_bytes", "rmtree", "copy", "copyfile",
                     "move", "utime", "mkfifo", "mknod", "setxattr", "kill", "Popen", "system", "check_call",
                     "check_output", "call", "execv", "execvp", "spawnv", "fork"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden, ast.dump(node.func))
                if node.func.attr == "open" and len(node.args) > 1:     # os.open: read-only flags only
                    flags = ast.unparse(node.args[1])
                    self.assertNotRegex(flags, r"O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                mode = ast.unparse(node.args[1]) if len(node.args) > 1 else "'r'"
                self.assertEqual(mode, "'rb'", "only binary read opens")
        runs = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "run" and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess"]
        self.assertEqual(len(runs), 2)                                  # ReadOnlyHost.run and the root integrity
        for n in runs:
            self.assertNotIn("shell", [k.arg for k in n.keywords if ast.unparse(k.value) == "True"])

    def test_real_git_queries_on_a_disposable_repository(self):
        import tempfile
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        with tempfile.TemporaryDirectory() as d:
            g = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, env=env)
            g("init", "-q")
            os.makedirs(os.path.join(d, "pilot"))
            Path(d, REC).write_text(json.dumps(full_record()))
            g("add", REC)
            g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "r")
            host = P.ReadOnlyHost(Path(d))
            pf = P.Preflight(host, os.path.join(d, REC), integrity=lambda: [], clock=lambda: "T")
            pf.load_decisions()
            self.assertEqual(pf.checks[-1].status, "PASS", pf.checks[-1])
            self.assertTrue(all(pf.approved[x][0] for x in P.DECISIONS))
            Path(d, REC).write_text(json.dumps(full_record()) + " ")       # uncommitted edit
            pf = P.Preflight(host, os.path.join(d, REC), integrity=lambda: [], clock=lambda: "T")
            pf.load_decisions()
            self.assertEqual(pf.checks[-1].status, "FAIL")
            self.assertFalse(any(pf.approved[x][0] for x in P.DECISIONS))
            os.symlink(os.path.join(d, REC), os.path.join(d, "link.json"))
            pf = P.Preflight(host, os.path.join(d, "link.json"), integrity=lambda: [], clock=lambda: "T")
            pf.load_decisions()
            self.assertEqual(pf.checks[-1].status, "FAIL")                  # untracked symlink


_AUDIT = {"on": False, "events": []}
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
_MUTATING = ("os.mkdir", "os.rmdir", "os.remove", "os.rename", "os.chmod", "os.chown", "os.symlink", "os.link",
             "os.truncate", "os.utime", "os.mkfifo", "os.mknod", "os.setxattr", "os.removexattr", "os.kill",
             "shutil.", "os.system", "os.exec", "os.posix_spawn", "os.fork")


def _hook(event, args):
    if _AUDIT["on"] and (event in ("open", "subprocess.Popen") or event.startswith(_MUTATING)):
        _AUDIT["events"].append((event, args))


class TestLiveReadOnly(unittest.TestCase):
    """The real preflight on this host: only reads and allowlisted read-only commands; host state unchanged."""

    @classmethod
    def setUpClass(cls):
        if not hasattr(sys, "_preflight_audit"):
            sys.addaudithook(_hook)
            sys._preflight_audit = True
        sys.path.insert(0, str(ROOT / "tests"))
        import shutil  # noqa: F401  (imported before auditing: imports open files)
        from faultlab import _integrity, test_integrity  # noqa: F401

    def state(self):
        s = C.Sys()
        snap = C.host_snapshot(s, require_bpf=False)
        return {"root": snap["root"], "top_cgroups": sorted(d for d in snap["cgroup_dirs"] if "/" not in d),
                "sentinel_cgroups": C.sentinel_cgroups(s), "netns": snap["netns"], "run_netns": snap["run_netns"],
                "mounts": snap["mounts"], "sysctls": snap["sysctls"], "links": sorted(l["ifname"] for l in
                                                                                      snap["links"] or []),
                "run_lab": os.path.lexists(P.RUN_LAB),
                "git": subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"], capture_output=True,
                                      text=True, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"}).stdout}

    def test_live_preflight_reads_only(self):
        before = self.state()
        _AUDIT["events"].clear()
        dont = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        _AUDIT["on"] = True
        try:
            rep = P.Preflight(P.ReadOnlyHost()).run()
        finally:
            _AUDIT["on"] = False
            sys.dont_write_bytecode = dont
        after = self.state()
        self.assertEqual(before, after)
        self.assertFalse(after["run_lab"])
        root = str(ROOT)
        git_ro = {"cat-file", "log", "rev-parse", "merge-base", "diff", "ls-tree", "rev-list", "ls-files", "status"}
        popens = 0
        for event, args in _AUDIT["events"]:
            if event == "open":
                path, mode, flags = args
                if path in (os.devnull, "/dev/null"):
                    continue                                          # subprocess stdin=DEVNULL
                writes = (isinstance(mode, str) and any(ch in mode for ch in "wax+")) or \
                    (isinstance(flags, int) and flags & _WRITE_FLAGS)
                self.assertFalse(writes, (event, args))
            elif event == "subprocess.Popen":
                popens += 1
                argv = [os.fsdecode(a) for a in args[1]]
                ok = P.command_allowed(argv, root) or (argv[:3] == ["git", "-C", root] and argv[3] in git_ro)
                self.assertTrue(ok, argv)
            else:
                self.fail((event, args))
        self.assertGreater(popens, 0)
        self.assertIn(rep["overall"], ("READY", "NOT_READY"))
        if os.geteuid() != 0:
            self.assertEqual(rep["overall"], "NOT_READY")
            self.assertEqual(by_id(rep)["ENV-PRIVILEGE"]["status"], "UNVERIFIED")
        self.assertEqual(by_id(rep)["PROV-DECISIONS-RECORD"]["status"], "BLOCKED")   # no record is committed


if __name__ == "__main__":
    unittest.main()
