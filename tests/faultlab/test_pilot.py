"""FaultLab A–R–B lab and pilot driver (experiments/faultlab/lab.py, pilot.py) against a simulated host.

No test executes a privileged operation: SimHost subclasses lab.Host and keeps its real plan check and op log, but its
_do only changes an in-memory model (FakeSys). Real subprocess, os.mkdir/rmdir/chown/kill are patched to fail if
reached. Covered: exact plans and the closed operation set, process placement, lab checks, setup and partial-setup
rollback, cleanup, PI-0 and CTRL orchestration, the privileged-preflight and PI-0-order gates, evidence integrity,
client/server and across-R reconciliation, and the PI evaluations.
"""
import ast
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments" / "faultlab"))
sys.path.insert(0, str(ROOT / "src"))
import lab as L  # noqa: E402
import pilot as P  # noqa: E402
import rehearsal as RH  # noqa: E402

_spec = importlib.util.spec_from_file_location("faultlab_workload_for_pilot",
                                               ROOT / "experiments/faultlab/docker/workload.py")
W = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(W)

COMMIT = "c" * 40
REAL_DO = L.Host._do                    # the real mutation dispatcher, for the one test that runs it on FakeSys
WORKLOAD = json.loads((ROOT / "docs/PHASE_1C_FREEZE1_DECISIONS.json").read_text())["decisions"]["FZ-WORKLOAD"]["value"]


# ------------------------------------------------------------------------------------------ simulated host
def _link(name, kind="veth", up=True, txq=1, rxq=1, stats=None):
    s = stats or {"rx": {"packets": 0, "dropped": 0, "errors": 0}, "tx": {"packets": 0, "dropped": 0, "errors": 0}}
    return {"ifname": name, "flags": ["UP"] if up else [], "operstate": "UP" if up else "DOWN",
            "linkinfo": {"info_kind": kind} if kind else {}, "num_tx_queues": txq, "num_rx_queues": rxq,
            "qdisc": "noqueue", "stats64": s}


def _mount(mid, parent, mnt, root="/", dev="0:26", fstype="tmpfs", optional=("shared:5",)):
    return {"id": mid, "parent": parent, "dev": dev, "root": root, "mnt": mnt, "optional": list(optional),
            "fstype": fstype}


BOOT_MOUNTS = [_mount(1, 0, "/", dev="259:2", fstype="ext4", optional=("shared:1",)), _mount(29, 1, "/run"),
               _mount(35, 1, "/sys/fs/cgroup", dev="0:27", fstype="cgroup2", optional=("shared:9",))]


class FakeSys(L.Sys):
    """In-memory host: cgroup files, namespaces, /run/sentinelai-lab, processes, the mount table. Lab inspection
    answers follow the model. Like the kernel observed in PI0-1, every new namespace inherits the host's ip_forward=1
    until the runner writes its own value, and the first `ip netns add` on a host where /run/netns is not a mount
    point bind-mounts it onto itself (iproute2), a mount `ip netns del` leaves in place."""

    def __init__(self):
        self.dirs, self.files, self.netns, self.applied = set(), {}, set(), set()
        self.fwd = {}                      # namespace -> ip_forward ("1" inherited from the host on creation)
        self.stuck = set()                 # namespaces whose ip_forward write silently does not take effect
        self.inherit = "1"                 # the host's ip_forward, copied into each new namespace
        self.run = {}                      # path under /run/sentinelai-lab -> ("dir"|"file", uid, bytes)
        self.procs = {}                    # pid -> cgroup path
        self.tweak = {}                    # probe key -> forced answer
        self.r_stats = {L.IF_RA: [0, 0, 0, 0], L.IF_RB: [0, 0, 0, 0]}   # rx, tx, rx_dropped, tx_dropped
        self.tcp = [0, 0, 0]              # OutSegs, InSegs, RetransSegs
        self.snmp_pid = None
        self.mounts = [dict(m) for m in BOOT_MOUNTS]   # /proc/self/mountinfo, in order
        self.next_mount_id = 1600
        self.mountinfo_ok = True
        self.on_umount = None              # called before the simulated umount2 (concurrent changes)

    def add_mount(self, mnt, parent, **kw):
        self.next_mount_id += 1
        self.mounts.append(_mount(self.next_mount_id, parent, mnt, **kw))
        return self.next_mount_id

    def top_mount(self, mnt):
        return next((m for m in reversed(self.mounts) if m["mnt"] == mnt), None)

    def umount(self, path):
        """umount2 without MNT_DETACH: the top mount at path; EBUSY with a child mount."""
        if self.on_umount:
            self.on_umount()
        m = self.top_mount(path)
        if m is None:
            raise OSError(22, f"umount2 {path}: Invalid argument")
        if any(c["parent"] == m["id"] for c in self.mounts):
            raise OSError(16, f"umount2 {path}: Device or resource busy")
        self.mounts.remove(m)

    def mountinfo(self):
        return "".join(" ".join([str(m["id"]), str(m["parent"]), m["dev"], m["root"], m["mnt"].replace(" ", "\\040"),
                                 "rw"] + m["optional"] + ["-", m["fstype"], m["fstype"], "rw"]) + "\n"
                       for m in self.mounts)

    # read-only interface
    def read(self, path):
        if path.endswith("/cgroup.procs"):
            d = path[: -len("/cgroup.procs")]
            if d not in self.dirs:
                return None
            return "".join(f"{p}\n" for p, cg in self.procs.items() if L.CG_ROOT + cg == d)
        if path.endswith("/cgroup.events"):
            d = path[: -len("/cgroup.events")]
            busy = any((L.CG_ROOT + cg).startswith(d) for cg in self.procs.values())
            return f"populated {int(busy)}\nfrozen 0\n" if d in self.dirs else None
        if path.startswith("/proc/") and path.endswith("/cgroup"):
            pid = int(path.split("/")[2])
            return f"0::{self.procs[pid]}\n" if pid in self.procs else None
        if path.endswith("/net/snmp"):
            o, i, r = self.tcp
            return ("Tcp: RtoAlgorithm OutSegs InSegs RetransSegs\nTcp: 1 %d %d %d\n" % (o, i, r))
        if path == f"{L.CG_ROOT}/cpuset.cpus.effective":
            return "0-23\n"
        if path == L.MOUNTINFO:
            return self.mountinfo() if self.mountinfo_ok else None
        return self.files.get(path)

    def exists(self, path):
        return path in self.dirs or path in self.files or (path.startswith("/run/netns/")
                                                          and path.rsplit("/", 1)[1] in self.netns)

    def listdir(self, path):
        if path == "/run/netns":
            return sorted(self.netns)
        if path == "/sys/class/net":
            return ["docker0", "enp0s31f6", "lo"]
        return []

    def cgroup_dirs(self):
        return [""] + sorted(d[len(L.CG_ROOT) + 1:] for d in self.dirs)

    def pids(self):
        return sorted(self.procs)

    def lstat_run(self, path):
        self._run_lab_path(path)
        e = self.run.get(str(path))
        if e is None:
            return None
        return SimpleNamespace(st_mode=(stat.S_IFDIR if e[0] == "dir" else stat.S_IFREG) | 0o700, st_uid=e[1])

    def listdir_run(self, path):
        self._run_lab_path(path)
        return sorted(p.rsplit("/", 1)[1] for p in self.run if p.rsplit("/", 1)[0] == path)

    def read_run(self, path, limit):
        e = self.run.get(str(self._run_lab_path(path)))
        if e is None or e[0] != "file":
            raise FileNotFoundError(path)
        return e[2]

    def netns_inode(self, ns):
        return 1000 + L.LAB_NETNS.index(ns) if ns in self.netns else None

    def pid_netns_inode(self, pid):
        return 1000 if pid in self.procs else None

    def lab_built(self):
        return {op[1] for op in L.lab_plan()} <= self.applied

    def probe(self, argv):
        argv = tuple(argv)
        if argv not in self.READ:
            raise L.LabRefused(f"not a lab read: {argv}")
        key = next((k for k, v in {**L.LAB_READS, **{f"route_get_{s}": a for s, a in L.ROUTE_GET.items()},
                                   **{f"forward_{s}": a for s, a in L.FORWARD_READS.items()},
                                   **{f"ping_{s}": a for s, a in L.PING.items()}}.items() if v == argv))
        if key in self.tweak:
            return self.tweak[key]
        if not self.lab_built():
            return (1, "", "Cannot open network namespace")
        side = key[0] if key[1] == "_" else None
        if key.startswith("route_get"):
            return (2, "", "RTNETLINK answers: Network is unreachable")
        if key.startswith("forward"):
            return (0, self.fwd[L.IFACES[key[-1]][0]] + "\n", "")
        if key.startswith("ping"):
            return (0, "3 packets transmitted, 3 received, 0% packet loss, time 400ms\n", "")
        ns, ifs = L.IFACES[side]
        what = key[2:]
        if what == "links":
            links = [_link("lo", kind=None)]
            for i in ifs:
                st = None
                if i in self.r_stats:
                    rx, tx, rd, td = self.r_stats[i]
                    st = {"rx": {"packets": rx, "dropped": rd, "errors": 0},
                          "tx": {"packets": tx, "dropped": td, "errors": 0}}
                links.append(_link(i, stats=st))
            return (0, json.dumps(links), "")
        if what == "addrs":
            doc = [{"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]}]
            doc += [{"ifname": i, "addr_info": [{"family": "inet", "local": ip, "prefixlen": p}]}
                    for i, v in L.EXPECTED_ADDRS[side].items() for ip, p in v]
            return (0, json.dumps(doc), "")
        if what == "routes":
            return (0, json.dumps([{"dst": d, "dev": dev} for d, dev in L.EXPECTED_ROUTES[side]]), "")
        return (0, "[]", "")                                  # routes6


class FakeProc:
    _next = 4242

    def __init__(self, rc=0, on_wait=None):
        self.pid, self.rc, self.on_wait = FakeProc._next, rc, on_wait
        FakeProc._next += 1

    def poll(self):
        return None

    def wait(self, timeout=None):
        if self.on_wait:
            self.on_wait()
        return self.rc


class SimHost(L.Host):
    """Real plan check and op log; the effect is simulated on FakeSys. fail(op) -> True raises OSError there."""

    def __init__(self, plan, oplog, sysr, fail=None, spawn=None, fail_after_mount=False, workload_files=None):
        super().__init__(plan, oplog, sysr)
        self.fail, self.spawn, self.ops = fail or (lambda op: False), spawn or {}, []
        self.workload_files = workload_files or {}   # what the workload publishes (config echo); default b"{}"
        self.fail_after_mount = fail_after_mount     # the first ip netns add fails after mounting /run/netns

    def _do(self, op, stdout, stderr):
        self.ops.append(op)
        s = self.sys
        if self.fail(op):
            raise OSError(f"simulated failure: {op[0]}")
        kind = op[0]
        if kind == "mkdir":
            if op[1].startswith(L.RUN_LAB):
                s.run[op[1]] = ("dir", 0, b"")
            else:
                assert op[1] not in s.dirs
                s.dirs.add(op[1])
        elif kind == "rmdir":
            if op[1].startswith(L.RUN_LAB):
                assert not s.listdir_run(op[1]), f"rmdir of non-empty {op[1]}"
                del s.run[op[1]]
            else:
                assert not [d for d in s.dirs if d.startswith(op[1] + "/")] and \
                    not [p for p, cg in s.procs.items() if L.CG_ROOT + cg == op[1]], f"rmdir busy {op[1]}"
                s.dirs.remove(op[1])
                s.files = {k: v for k, v in s.files.items() if not k.startswith(op[1] + "/")}
        elif kind == "write":
            if op[1].endswith("cgroup.kill"):
                s.procs = {p: cg for p, cg in s.procs.items() if not (L.CG_ROOT + cg).startswith(L.LAB_DIR)}
            elif op[1].endswith("cgroup.subtree_control"):
                s.files[op[1]] = op[2].replace("+", "")
            else:
                s.files[op[1]] = op[2]
                if op[1].endswith("cpuset.cpus"):
                    s.files[op[1] + ".effective"] = op[2]
                if op[1].endswith("pids.max") or op[1].endswith("cpuset.cpus"):
                    s.files.setdefault(op[1].rsplit("/", 1)[0] + "/cpu.max", L.C.CPU_MAX_UNLIMITED)
        elif kind == "cmd":
            argv = op[1]
            if argv[:3] == ("ip", "netns", "add"):
                if s.top_mount(L.NETNS_DIR) is None:          # iproute2: make /run/netns a (shared) mount point
                    run = s.top_mount("/run")
                    s.add_mount(L.NETNS_DIR, run["id"], root="/netns", dev=run["dev"], fstype=run["fstype"])
                    if self.fail_after_mount:
                        raise OSError("simulated failure after the /run/netns mount")
                s.add_mount(f"{L.NETNS_DIR}/{argv[3]}", s.top_mount(L.NETNS_DIR)["id"], dev="0:4", fstype="nsfs",
                            optional=())
                s.netns.add(argv[3])
                s.fwd[argv[3]] = s.inherit                    # inherited from the host (conf/all, conf/default)
            elif argv[:3] == ("ip", "netns", "del"):
                s.netns.discard(argv[3])
                s.mounts = [m for m in s.mounts if m["mnt"] != f"{L.NETNS_DIR}/{argv[3]}"]
                s.applied = {a for a in s.applied if argv[3] not in a}
            s.applied.add(argv)
        elif kind == "forward":
            argv = L.forward_argv(op[1], op[2])               # the real argv builder (refuses like the real host)
            if s.netns_inode(op[1]) != op[2]:
                raise OSError("forwarding helper failed (rc 3: namespace inode mismatch)")
            if op[1] not in s.stuck:
                s.fwd[op[1]] = argv[9]
        elif kind == "chown_lab":
            e = s.run[op[1]]
            s.run[op[1]] = (e[0], L.LAB_UID, e[2])
        elif kind == "write_new":
            s.run[op[1]] = ("file", 0, op[2])
        elif kind == "unlink_run":
            del s.run[op[1]]
        elif kind == "umount_netns_dir":
            L.umount_owned_netns_dir(s, op[1], s.umount)      # the real checks; only umount2 is simulated
        elif kind == "spawn":
            role = op[1]
            p = (self.spawn.get(role) or (lambda: FakeProc()))()
            leaf = {"echo_server": "support", "echo_client": "target", "workload": "target",
                    "dependency": "support", "loadgen": "support"}[role]
            if role in ("echo_server", "dependency", "loadgen", "workload"):
                s.procs[p.pid] = f"/{L.LAB}/{leaf}"
            if role == "dependency":
                s.run[f"{L.run_dir(self.plan.run_id)}/dependency_config.json"] = ("file", L.LAB_UID, b"{}")
            if role == "workload":
                for n in ("metrics.json", "config.json"):
                    s.run[f"{L.run_dir(self.plan.run_id)}/{n}"] = ("file", L.LAB_UID, self.workload_files.get(n, b"{}"))
            return p
        return None


def lab_mutations_blocked():
    """Every real mutation path patched to fail the test if reached."""
    boom = mock.Mock(side_effect=AssertionError("real host mutation reached"))
    return [mock.patch.object(L.subprocess, "run", boom), mock.patch.object(L.subprocess, "Popen", boom),
            mock.patch.object(L.Host, "_do", boom)]           # SimHost overrides _do; the real one must never run


class Sandboxed(unittest.TestCase):
    def setUp(self):
        for p in lab_mutations_blocked():
            p.start()
            self.addCleanup(p.stop)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp))
        snap = mock.patch.object(L, "host_snapshot", side_effect=lambda sysr, require_bpf=True: {
            "bpf_available": True, "lab": sorted(sysr.netns), "run": sorted(sysr.run),
            "mounts": sorted(f"{m['mnt']} {m['fstype']}" for m in sysr.mounts)})     # as findmnt TARGET,FSTYPE
        snap.start()
        self.addCleanup(snap.stop)

        def compare(a, b, require_bpf=True):
            failed = (["leftover"] if b["lab"] or b["run"] else []) + \
                (["mounts_identical"] if a.get("mounts") != b.get("mounts") else [])
            return {"ok": not failed, "failed": failed}
        cmp = mock.patch.object(L, "compare_host", side_effect=compare)
        cmp.start()
        self.addCleanup(cmp.stop)


def host_factory(store, **kw):
    def make(plan, oplog, sysr):
        h = SimHost(plan, oplog, sysr, **kw)
        store.append(h)
        return h
    return make


def empty(sysr):
    return not sysr.dirs and not sysr.netns and not sysr.run and not sysr.procs and sysr.mounts == BOOT_MOUNTS


# ------------------------------------------------------------------------------------------ plans and the guard
class TestPlans(unittest.TestCase):
    def test_cgroup_plan_stays_in_the_lab_cgroup(self):
        for op in L.cgroup_plan():
            self.assertTrue(op[1].startswith(L.LAB_DIR + "/") or op[1] == L.LAB_DIR, op)
            self.assertNotIn("cpu.max", op[1])                     # no quota: CTRL and PI-0 never throttle
        writes = {(op[1].rsplit("/", 1)[1], op[2]) for op in L.cgroup_plan() if op[0] == "write"}
        self.assertIn(("memory.max", str(2560 << 20)), writes)
        self.assertEqual(sum(1 for op in L.cgroup_plan() if op[0] == "write" and op[1].endswith("memory.swap.max")
                             and op[2] == "0"), 4)
        self.assertEqual({op[1] for op in L.cgroup_plan() if op[0] == "mkdir"}, set(L.LAB_DIRS))

    def test_topology_plan_is_exactly_the_approved_lab(self):
        cmds = [op[1] for op in L.lab_plan()]
        self.assertEqual(cmds[:3], [("ip", "netns", "add", n) for n in L.LAB_NETNS])
        for c in cmds:
            self.assertEqual(c[0], "ip")
            self.assertFalse(set(c) & {"enp0s31f6", "docker0", "default", "tc", "sysctl", "del"}, c)
            self.assertTrue(c[1:3] in (("netns", "add"), ("link", "add")) or c[1] == "-n", c)
            if c[1] == "-n":
                self.assertIn(c[2], L.LAB_NETNS)
        self.assertEqual(sum(1 for c in cmds if c[1:3] == ("link", "add")), 2)
        self.assertIn(("ip", "-n", L.NS_A, "route", "add", L.NET_B, "via", L.IP_RA, "dev", L.IF_A), cmds)
        self.assertIn(("ip", "-n", L.NS_B, "route", "add", L.NET_A, "via", L.IP_RB, "dev", L.IF_B), cmds)
        self.assertEqual([op[1] for op in L.netns_del_plan()], [("ip", "netns", "del", n)
                                                                for n in reversed(L.LAB_NETNS)])

    def test_forwarding_is_explicit_in_every_lab_namespace(self):
        self.assertEqual(L.FORWARD_VALUE, {L.NS_A: "0", L.NS_R: "1", L.NS_B: "0"})
        self.assertEqual(L.EXPECTED_FORWARD, {"a": "0", "r": "1", "b": "0"})
        for ns, ifs in ((L.NS_A, [L.IF_A]), (L.NS_R, [L.IF_RA, L.IF_RB]), (L.NS_B, [L.IF_B])):
            with self.subTest(ns):
                argv = L.forward_argv(ns, 77)
                self.assertEqual(argv[:4], ["ip", "netns", "exec", ns])
                self.assertEqual(argv[4:8], [L.PYTHON, "-I", "-c", L.FWD_HELPER])
                self.assertEqual(argv[8:], ["77", L.FORWARD_VALUE[ns]] + ifs)
        for bad in (("sentinel-lab-x", 7), ("", 7), (L.NS_A, 0), (L.NS_A, True), (L.NS_A, "7"), (L.NS_A, -1)):
            with self.subTest(bad=bad), self.assertRaises(L.LabRefused):
                L.forward_argv(*bad)
        self.assertNotIn("default/forwarding", L.FWD_HELPER)            # only the namespace's ip_forward

    def run_helper(self, argv_tail, ino=77, ifaces=("lo", "sentlab-a0"), readback=None):
        """Execute FWD_HELPER in-process with every OS access faked (nothing real is written)."""
        written = []
        st = SimpleNamespace(st_ino=ino)

        class Exit(Exception):
            pass

        def fake_exit(code=0):
            raise Exit(code)

        def fake_open(path, *a, **k):
            return SimpleNamespace(read=lambda: readback if readback is not None else written[-1].decode())
        fake_os = SimpleNamespace(stat=lambda p: st, listdir=lambda p: list(ifaces), O_WRONLY=1, O_NOFOLLOW=2,
                                  open=lambda p, f: (written.append(("open", p, f)) or 9),
                                  write=lambda fd, b: written.append(b), close=lambda fd: None)
        fake_sys = SimpleNamespace(argv=["-c"] + list(argv_tail), exit=fake_exit)
        g = {"__builtins__": dict(__builtins__ if isinstance(__builtins__, dict) else vars(__builtins__),
                                  open=fake_open,
                                  __import__=lambda n, *a, **k: {"os": fake_os, "sys": fake_sys}[n])}
        try:
            exec(compile(L.FWD_HELPER, "fwd", "exec"), g)
        except Exit as e:
            return e.args[0], written
        return None, written

    def test_forwarding_helper_logic(self):
        rc, w = self.run_helper(["77", "0", "sentlab-a0"])
        self.assertEqual(rc, 0)
        self.assertEqual(w[0], ("open", "/proc/sys/net/ipv4/ip_forward", 3))
        self.assertEqual(w[1], b"0")
        self.assertEqual(self.run_helper(["77", "2", "sentlab-a0"])[0], 2)                 # invalid value
        self.assertEqual(self.run_helper(["78", "0", "sentlab-a0"])[0], 3)                 # wrong namespace
        rc, w = self.run_helper(["77", "0", "sentlab-a0"], ifaces=("lo", "sentlab-a0", "eth0"))
        self.assertEqual((rc, w), (4, []))                                                 # unexpected interfaces
        self.assertEqual(self.run_helper(["77", "0", "sentlab-a0"], readback="1\n")[0], 5)  # read-back differs
        for rc, _ in (self.run_helper(["78", "0", "sentlab-a0"]), self.run_helper(["77", "x", "sentlab-a0"])):
            self.assertNotEqual(rc, 0)

    def test_processes_are_placed_in_leaf_namespace_and_lab_uid(self):
        run_id = "CTRL-s900001"
        cases = {"workload": (L.workload_argv(run_id, WORKLOAD), "target", L.NS_A),
                 "dependency": (L.dependency_argv(run_id, WORKLOAD), "support", L.NS_B),
                 "loadgen": (L.loadgen_argv(WORKLOAD, 170, 900001, "/x/client.jsonl"), "support", L.NS_B)}
        for role, (argv, leaf, ns) in cases.items():
            with self.subTest(role):
                self.assertEqual(argv[:4], ["timeout", "-s", "KILL", str(L.HARD_TIMEOUT_S)])
                self.assertEqual(argv[4:7], ["sh", "-c", f'echo $$ > {L.LEAVES[leaf]}/cgroup.procs && exec "$@"'])
                self.assertEqual(argv[8:12], ["ip", "netns", "exec", ns])
                self.assertEqual(argv[12:17], ["setpriv", "--reuid=1000", "--regid=1000", "--init-groups", "--"])
                self.assertEqual(argv[17], L.PYTHON)

    def test_argv_uses_the_approved_workload_values(self):
        argv = L.workload_argv("CTRL-s900001", WORKLOAD)
        pairs = dict(zip(argv, argv[1:]))
        for flag, key in (("--pool", "pool"), ("--queue", "queue"), ("--cpu-us", "cpu_us"),
                          ("--lock-hold-us", "lock_hold_us"), ("--publish-s", "publish_s"), ("--poll-s", "poll_s"),
                          ("--dependency-timeout-ms", "dependency_timeout_ms"),
                          ("--lock-wait-exceeded-ms", "lock_wait_exceeded_ms")):
            self.assertEqual(pairs[flag], str(WORKLOAD[key]), flag)
        lg = dict(zip(L.loadgen_argv(WORKLOAD, 170, 900001, "/o"), L.loadgen_argv(WORKLOAD, 170, 900001, "/o")[1:]))
        for flag, key in (("--rate", "rate_per_s"), ("--jitter", "jitter"), ("--timeout-s", "timeout_s"),
                          ("--max-inflight", "max_inflight")):
            self.assertEqual(lg[flag], str(WORKLOAD[key]), flag)
        self.assertEqual(lg["--target"], f"{L.IP_A}:{L.PORT_WORKLOAD}")

    def test_run_ids_and_paths(self):
        self.assertEqual(L.run_dir("CTRL-s900001"), "/run/sentinelai-lab/app/CTRL-s900001")
        for bad in ("../x", "ctrl-s1", "CTRL-s1/..", "CTRL"):
            with self.subTest(bad), self.assertRaises(L.LabRefused):
                L.run_dir(bad)


class TestGuard(unittest.TestCase):
    def setUp(self):
        self.plan = L.Plan("CTRL-s900001", spawns=[("workload", L.workload_argv("CTRL-s900001", WORKLOAD))])

    def test_every_planned_operation_is_accepted(self):
        for op in L.cgroup_plan() + L.lab_plan() + L.netns_del_plan() + L.app_plan("CTRL-s900001"):
            self.plan.check(op)
        rd = L.run_dir("CTRL-s900001")
        for op in (("forward", L.NS_A, 12), ("forward", L.NS_R, 12), ("forward", L.NS_B, 12),
                   ("write", f"{L.LAB_DIR}/cgroup.kill", "1"),
                   ("write_new", f"{rd}/control.json", b"{}"), ("unlink_run", f"{rd}/metrics.json"),
                   ("unlink_run", f"{rd}/.metrics.json.tmp.77"), ("kill", 4242),
                   ("spawn", "workload", L.workload_argv("CTRL-s900001", WORKLOAD))):
            self.plan.check(op)

    def test_operations_outside_the_lab_are_refused(self):
        rd = L.run_dir("CTRL-s900001")
        bad = [("mkdir", "/sys/fs/cgroup/user.slice/x"), ("rmdir", "/sys/fs/cgroup/system.slice"),
               ("mkdir", "/run/other"), ("write", f"{L.LAB_DIR}/cpu.max", "7500 100000"),
               ("write", f"{L.TARGET_DIR}/memory.max", "1"), ("write", "/proc/sys/net/ipv4/ip_forward", "1"),
               ("write", f"{L.LAB_DIR}/cgroup.kill", "0"),
               ("cmd", ("ip", "link", "del", "enp0s31f6")), ("cmd", ("tc", "qdisc", "add", "dev", "sentlab-ra")),
               ("cmd", ("ip", "netns", "del", "other")), ("cmd", ("ip", "route", "add", "default")),
               ("cmd", ("sysctl", "-w", "net.ipv4.ip_forward=1")), ("cmd", ["ip", "netns", "add", L.NS_A]),
               ("forward", True), ("forward", 0), ("forward", 12), ("forward", L.NS_A, True),
               ("forward", L.NS_A, 0), ("forward", "sentinel-lab-x", 12), ("forward", "init", 1),
               ("forward", L.NS_A, 12, "1"), ("chown_lab", "/run/sentinelai-lab"),
               ("chown_lab", "/etc"), ("write_new", f"{rd}/metrics.json", b"{}"), ("write_new", "/etc/x", b""),
               ("write_new", f"{rd}/control.json", "str"), ("unlink_run", f"{rd}/../x"),
               ("unlink_run", "/etc/passwd"), ("unlink_run", f"{rd}/evil"), ("unlink_run", f"{rd}/.evil.tmp.1"),
               ("spawn", "workload", ["sh", "-c", "id"]), ("spawn", "loadgen", L.workload_argv("CTRL-s900001",
                                                                                              WORKLOAD)),
               ("kill", 1), ("kill", True), ("kill", "4242"), ("exec", "anything"), (), "mkdir"]
        for op in bad:
            with self.subTest(op=op), self.assertRaises(L.LabRefused):
                self.plan.check(op)
        with self.assertRaises(L.LabRefused):
            L.Plan(None).check(("chown_lab", rd))                    # no run id: no run directory operation

    def test_defence_in_depth_behind_the_exact_plan(self):
        """Even a command wrongly present in the plan is refused if it names a protected interface or a forbidden
        tool."""
        for cmd in (("ip", "link", "del", "enp0s31f6"), ("ip", "link", "set", "docker0", "down"),
                    ("tc", "qdisc", "add", "dev", "sentlab-ra", "root", "netem"), ("sysctl", "-w", "x=1"),
                    ("modprobe", "sch_netem"), ("nft", "flush", "ruleset")):
            with self.subTest(cmd=cmd):
                self.plan.cmds.add(cmd)
                with self.assertRaises(L.LabRefused):
                    self.plan.check(("cmd", cmd))
        self.plan.dirs.add("/sys/fs/cgroup/enp0s31f6")
        with self.assertRaises(L.LabRefused):
            self.plan.check(("mkdir", "/sys/fs/cgroup/enp0s31f6"))

    def test_refused_operation_never_reaches_the_host(self):
        with tempfile.TemporaryDirectory() as d:
            h = L.Host(self.plan, os.path.join(d, "ops.jsonl"), sysr=FakeSys())
            with mock.patch.object(L.Host, "_do", side_effect=AssertionError("executed")) as do:
                with self.assertRaises(L.LabRefused):
                    h.apply(("cmd", ("ip", "link", "del", "enp0s31f6")))
                do.assert_not_called()
            self.assertFalse(os.path.exists(os.path.join(d, "ops.jsonl")))

    def test_operations_are_logged_intent_then_result(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "ops.jsonl")
            h = SimHost(self.plan, log, FakeSys(), fail=lambda op: op[0] == "rmdir")
            h.apply(("mkdir", L.LAB_DIR))
            with self.assertRaises(OSError):
                h.apply(("rmdir", L.LAB_DIR))
            e = L.read_oplog(log)
            self.assertEqual([(x["phase"], x.get("ok")) for x in e], [("intent", None), ("result", True),
                                                                      ("intent", None), ("result", False)])
            self.assertEqual(L.created(e)["dirs"], [L.LAB_DIR])

    def test_kill_only_signals_lab_processes(self):
        s = FakeSys()
        s.procs = {500: "/user.slice/x", 501: f"/{L.LAB}/target"}
        h = L.Host(self.plan, os.devnull, s)
        with mock.patch.object(L.os, "kill") as k:
            h._do(("kill", 500), None, None)
            k.assert_not_called()
            h._do(("kill", 501), None, None)
            k.assert_called_once()


# ------------------------------------------------------------------------------------------ inspection parsing
class TestInspection(unittest.TestCase):
    def built(self):
        s = FakeSys()
        s.applied = {op[1] for op in L.lab_plan()}
        s.netns = set(L.LAB_NETNS)
        s.fwd = dict(L.FORWARD_VALUE)
        return s

    def test_correct_lab_passes_every_check(self):
        c = L.lab_checks(L.lab_state(self.built()))
        self.assertEqual(L.failures(c), [])
        self.assertEqual(len(c), 3 * 7 + 2 * 4)                       # per side 7 + 2 per veth (4 veths)

    def test_each_deviation_fails(self):
        s = self.built()
        good = L.lab_state(s)
        mutations = {
            "a_only_lo_and_lab_veths": ("a_links", json.dumps([_link("lo", None), _link(L.IF_A), _link("eth9")])),
            "a_sentlab-a0_single_queue": ("a_links", json.dumps([_link("lo", None), _link(L.IF_A, txq=4)])),
            "b_sentlab-b0_veth_up": ("b_links", json.dumps([_link("lo", None), _link(L.IF_B, up=False)])),
            "a_routes": ("a_routes", json.dumps([{"dst": L.NET_A, "dev": L.IF_A}])),
            "r_no_default_route": ("r_routes", json.dumps([{"dst": d, "dev": v} for d, v in L.EXPECTED_ROUTES["r"]]
                                                          + [{"dst": "default", "dev": L.IF_RA}])),
            "b_addresses": ("b_addrs", json.dumps([{"ifname": L.IF_B, "addr_info": [
                {"family": "inet", "local": "10.199.2.3", "prefixlen": 24}]}])),
        }
        for check, (key, text) in mutations.items():
            with self.subTest(check):
                raw = dict(good, **{key: (0, text, "")})
                self.assertIn(check, L.failures(L.lab_checks(raw)))
        raw = dict(good, route_get_a=(0, "8.8.8.8 via 10.199.1.254 dev sentlab-a0", ""))
        self.assertIn("a_no_external_path", L.failures(L.lab_checks(raw)))
        raw = dict(good, forward_a=(0, "1\n", ""))
        self.assertIn("a_ip_forward", L.failures(L.lab_checks(raw)))
        raw = dict(good, forward_r=(0, "0\n", ""))
        self.assertIn("r_ip_forward", L.failures(L.lab_checks(raw)))
        raw = dict(good, b_links=None)
        self.assertEqual(L.failures(L.lab_checks(raw)), ["b_observable"])
        self.assertEqual(L.failures({}), ["unobservable"])

    def test_counters(self):
        s = self.built()
        s.r_stats[L.IF_RA] = [10, 20, 1, 0]
        r = L.r_counters(s)
        self.assertEqual(r[L.IF_RA]["rx_packets"], 10)
        self.assertEqual(r[L.IF_RA]["rx_dropped"], 1)
        self.assertIsNone(L.r_counters(FakeSys()))                   # no lab: unobservable, not zero
        self.assertEqual(L.tcp_counters("Tcp: OutSegs InSegs RetransSegs\nTcp: 5 6 7\n"),
                         {"OutSegs": 5, "InSegs": 6, "RetransSegs": 7})
        for bad in (None, "", "Tcp: OutSegs\nTcp: x\n", "Udp: 1\n"):
            self.assertIsNone(L.tcp_counters(bad))

    def test_ping_parse(self):
        self.assertTrue(L.ping_ok((0, "3 received, 0% packet loss", "")))
        for bad in ((1, "0% packet loss", ""), (0, "33% packet loss", ""), None, (0, "", "")):
            self.assertFalse(L.ping_ok(bad))

    def test_run_lab_reads_are_confined(self):
        s = L.Sys()
        for p in ("/run/other", "/run/sentinelai-lab/../shadow", "/etc/passwd", "/run/sentinelai-labx"):
            with self.subTest(p), self.assertRaises(L.LabRefused):
                s.lstat_run(p)
        with self.assertRaises(L.LabRefused):
            s.read_run("/etc/passwd", 10)


# ------------------------------------------------------------------------------------------ cleanup
class TestCleanup(Sandboxed):
    def setup(self, fail=None, upto=None):
        s = FakeSys()
        run_id = "PI0-s1"
        h = SimHost(L.Plan(run_id), str(self.tmp / "ops.jsonl"), s, fail=fail)
        ops = L.cgroup_plan() + L.lab_plan() + [("forward", ns, 1000 + i) for i, ns in enumerate(L.LAB_NETNS)] + \
            L.app_plan(run_id)
        for i, op in enumerate(ops[:upto]):
            h.apply(op)
        return s, h, run_id

    def test_full_cleanup_in_order(self):
        s, h, run_id = self.setup()
        s.procs[99] = f"/{L.LAB}/target"
        s.run[f"{L.run_dir(run_id)}/metrics.json"] = ("file", 1000, b"x")
        s.run[f"{L.run_dir(run_id)}/.metrics.json.tmp.12"] = ("file", 1000, b"x")
        order = []
        res = L.cleanup(h, s, L.read_oplog(h.oplog), run_id, after_procs=lambda: order.append("after"))
        self.assertTrue(res["ok"], res)
        self.assertTrue(empty(s))
        kinds = [op[0] if op[0] != "cmd" else op[1][1:3] for op in h.ops[len(L.cgroup_plan()) + 25:]]
        self.assertEqual(kinds[0], "write")                          # cgroup.kill first
        self.assertEqual(order, ["after"])
        rm = [op[1] for op in h.ops if op[0] == "rmdir"]
        self.assertEqual(rm, [L.run_dir(run_id), L.APP_ROOT.rstrip("/"), L.RUN_LAB, L.SUPPORT_DIR, L.CONTENDER_DIR,
                              L.TARGET_DIR, L.LAB_DIR])
        self.assertEqual([op[1][3] for op in h.ops if op[0] == "cmd" and op[1][:3] == ("ip", "netns", "del")],
                         list(reversed(L.LAB_NETNS)))

    def test_partial_setup_is_rolled_back_exactly(self):
        total = len(L.cgroup_plan() + L.lab_plan()) + 3 + len(L.app_plan("PI0-s1"))
        for upto in range(0, total + 1):
            with self.subTest(upto=upto):
                s, h, run_id = self.setup(upto=upto)
                foreign = "/sys/fs/cgroup/sentinel-other"
                res = L.cleanup(h, s, L.read_oplog(h.oplog), run_id)
                self.assertTrue(empty(s), (upto, s.dirs, s.netns, s.run))
                self.assertNotIn(foreign, [op[1] for op in h.ops if op[0] == "rmdir"])
                self.assertTrue(res["verify"]["ok"], res)
                self.tmp.joinpath("ops.jsonl").unlink(missing_ok=True)

    def test_cleanup_touches_only_what_this_invocation_created(self):
        s, h, run_id = self.setup(upto=len(L.cgroup_plan()))            # cgroups only
        s.netns.add(L.NS_A)                                           # pre-existing, not ours
        res = L.cleanup(h, s, L.read_oplog(h.oplog), run_id)
        self.assertIn(L.NS_A, s.netns)
        self.assertFalse(any(op[0] == "cmd" for op in h.ops[len(L.cgroup_plan()):]))
        self.assertFalse(res["ok"])                                   # verification still reports the leftover
        self.assertFalse(res["verify"]["checks"]["no_lab_netns"])

    def test_pre_existing_lab_state_is_never_removed(self):
        s = FakeSys()
        s.dirs |= set(L.LAB_DIRS)
        s.netns |= set(L.LAB_NETNS)
        s.run[L.RUN_LAB] = ("dir", 0, b"")
        h = SimHost(L.Plan("PI0-s1"), str(self.tmp / "ops.jsonl"), s)
        res = L.cleanup(h, s, [], "PI0-s1")
        self.assertEqual(h.ops, [])
        self.assertEqual(s.dirs, set(L.LAB_DIRS))
        self.assertFalse(res["ok"])

    def test_unexpected_file_is_kept_and_reported(self):
        s, h, run_id = self.setup()
        s.run[f"{L.run_dir(run_id)}/evil.sh"] = ("file", 1000, b"x")
        res = L.cleanup(h, s, L.read_oplog(h.oplog), run_id)
        self.assertFalse(res["ok"])
        self.assertTrue(any("unexpected file" in e for e in res["errors"]))
        self.assertIn(f"{L.run_dir(run_id)}/evil.sh", s.run)

    def test_cleanup_is_idempotent_and_continues_after_errors(self):
        s, h, run_id = self.setup()
        L.cleanup(h, s, L.read_oplog(h.oplog), run_id)
        n = len(h.ops)
        res = L.cleanup(h, s, L.read_oplog(h.oplog), run_id)
        self.assertTrue(res["ok"])
        self.assertEqual(len(h.ops), n + 0)                           # nothing left to do
        self.tmp.joinpath("ops.jsonl").unlink()
        s2, h2, rid2 = self.setup(fail=lambda op: op[0] == "rmdir" and op[1] == L.TARGET_DIR, upto=0)
        for op in L.cgroup_plan() + L.lab_plan():
            h2.apply(op)
        res = L.cleanup(h2, s2, L.read_oplog(h2.oplog), None)
        self.assertFalse(res["ok"])
        self.assertTrue(any(L.TARGET_DIR in e for e in res["errors"]))
        self.assertFalse(s2.netns)                                    # later steps still ran


# ------------------------------------------------------------------------------------------ PI-0 orchestration
class TestLifecycle(Sandboxed):
    def run_cycle(self, s=None, **kw):
        s = s or FakeSys()
        hosts = []
        out = self.tmp / f"PI0-{len(list(self.tmp.iterdir())) + 1}"
        rc = P.lifecycle(out, 1, COMMIT, sysr=s, host_cls=host_factory(hosts, **kw), sleep=lambda x: None)
        return rc, json.loads((out / "run.json").read_text()), s, hosts[0] if hosts else None

    def test_cycle_passes_and_leaves_nothing(self):
        rc, R, s, h = self.run_cycle()
        self.assertEqual(rc, 0, R["aborts"])
        self.assertTrue(R["ok"] and R["cleanup"]["ok"] and R["host_compare"]["ok"])
        self.assertTrue(empty(s))
        self.assertEqual(R["tcp_echo_rc"], {"client": 0, "server": 0})
        self.assertEqual(R["app_dir"], {"exists": True, "owner_uid": 1000})
        self.assertTrue(all(L.ping_ok(v) for v in R["ping"].values()))
        first = [op[0] for op in h.ops][:3]
        self.assertEqual(first, ["mkdir", "write", "write"])

    def test_failure_at_any_setup_step_aborts_and_rolls_back(self):
        steps = L.cgroup_plan() + L.lab_plan() + [("forward", ns) for ns in L.LAB_NETNS] + L.app_plan("PI0-s1")
        for i, target in enumerate(steps):
            with self.subTest(step=i, op=target[:2]):
                rc, R, s, h = self.run_cycle(fail=lambda op, t=target: op[:2] == t[:2])
                self.assertEqual(rc, 1)
                self.assertTrue(R["aborts"])
                self.assertTrue(empty(s), (i, s.dirs, s.netns, s.run))
                self.assertTrue(R["cleanup"]["verify"]["ok"])

    def test_inherited_forwarding_is_set_explicitly_and_verified(self):
        """Regression for PI0-1 (20261011T175343Z): A and B inherit ip_forward=1 from the host."""
        rc, R, s, h = self.run_cycle()
        self.assertEqual(rc, 0, R["aborts"])
        fw = [op for op in h.ops if op[0] == "forward"]
        self.assertEqual([op[1] for op in fw], list(L.LAB_NETNS))
        self.assertEqual([op[2] for op in fw], [1000, 1001, 1002])          # each namespace's own inode
        last = R["lab_settle"][-1]["raw"]
        self.assertEqual({k: last[k][1].strip() for k in ("forward_a", "forward_r", "forward_b")},
                         {"forward_a": "0", "forward_r": "1", "forward_b": "0"})
        last_setup = max(i for i, op in enumerate(h.ops) if op[0] == "cmd" and op[1][3:5] == ("route", "add"))
        self.assertTrue(all(h.ops.index(op) > last_setup for op in fw))       # after the topology exists

    def test_forwarding_write_failures_abort_and_roll_back(self):
        for ns in L.LAB_NETNS:
            with self.subTest(ns):
                rc, R, s, h = self.run_cycle(fail=lambda op, ns=ns: op[0] == "forward" and op[1] == ns)
                self.assertEqual(rc, 1)
                self.assertIn("simulated failure: forward", R["aborts"][0])
                self.assertTrue(empty(s))
                self.assertNotIn("lab_settle", R)                             # never reached the checks

    def test_forwarding_readback_failure_aborts(self):
        for ns, side, inherit in ((L.NS_A, "a", "1"), (L.NS_B, "b", "1"), (L.NS_R, "r", "0")):
            with self.subTest(ns):
                s = FakeSys()
                s.stuck, s.inherit = {ns}, inherit                            # the write does not take effect
                rc, R, s, h = self.run_cycle(s)
                self.assertEqual(rc, 1)
                self.assertIn(f"{side}_ip_forward", R["aborts"][0])
                self.assertTrue(empty(s))

    def test_host_without_forwarding_still_yields_the_specified_values(self):
        s = FakeSys()
        s.inherit = "0"
        rc, R, s, h = self.run_cycle(s)
        self.assertEqual(rc, 0, R["aborts"])
        self.assertTrue(empty(s))

    def test_unexpected_namespace_state_aborts(self):
        class Gone(FakeSys):                                                  # B vanishes before its write
            def netns_inode(self, ns):
                return None if ns == L.NS_B else super().netns_inode(ns)
        rc, R, s, h = self.run_cycle(Gone())
        self.assertEqual(rc, 1)
        self.assertIn(f"{L.NS_B} missing", R["aborts"][0])
        self.assertTrue(empty(s))

        class Swapped(FakeSys):                                               # inode no longer the one read
            def __init__(self):
                super().__init__()
                self.calls = 0

            def netns_inode(self, ns):
                self.calls += 1
                ino = super().netns_inode(ns)
                return ino + 50 if ns == L.NS_A and ino is not None and self.calls == 1 else ino
        rc, R, s, h = self.run_cycle(Swapped())
        self.assertEqual(rc, 1)
        self.assertIn("inode mismatch", R["aborts"][0])
        self.assertTrue(empty(s))

    def test_lab_check_ping_and_echo_failures_abort(self):
        for tweak in ({"r_routes": (0, "[]", "")}, {"ping_a_to_b": (1, "100% packet loss", "")},
                      {"route_get_b": (0, "8.8.8.8 dev x", "")}):
            with self.subTest(tweak):
                s = FakeSys()
                s.tweak = tweak
                rc, R, s, h = self.run_cycle(s)
                self.assertEqual(rc, 1)
                self.assertTrue(empty(s))
        rc, R, s, h = self.run_cycle(spawn={"echo_client": lambda: FakeProc(rc=1)})
        self.assertEqual(rc, 1)
        self.assertIn("TCP echo", R["aborts"][0])
        self.assertTrue(empty(s))

    def test_interrupt_during_setup_still_cleans_up(self):
        def interrupt(op):
            if op[0] == "cmd" and op[1][:3] == ("ip", "link", "add"):
                raise P.Interrupted("signal 15")
            return False
        rc, R, s, h = self.run_cycle(fail=interrupt)
        self.assertEqual(rc, 1)
        self.assertIn("Interrupted", R["aborts"][0])
        self.assertTrue(empty(s))

    def test_leftover_state_refuses_before_any_operation(self):
        s = FakeSys()
        s.netns.add(L.NS_B)
        hosts = []
        out = self.tmp / "PI0-1"
        with self.assertRaises(P.Refused):
            P.lifecycle(out, 1, COMMIT, sysr=s, host_cls=host_factory(hosts), sleep=lambda x: None)
        self.assertEqual(hosts[0].ops, [])
        self.assertFalse(json.loads((out / "run.json").read_text())["preflight"]["ok"])
        with mock.patch.object(L, "host_snapshot", return_value={"bpf_available": False}):
            hosts = []
            with self.assertRaises(P.Refused):
                P.lifecycle(self.tmp / "PI0-2", 1, COMMIT, sysr=FakeSys(), host_cls=host_factory(hosts))
            self.assertEqual(hosts[0].ops, [])

    def test_host_difference_alone_fails_the_cycle(self):
        with mock.patch.object(L, "compare_host", return_value={"ok": False, "failed": ["routes_identical"]}):
            rc, R, s, h = self.run_cycle()
        self.assertEqual(rc, 1)
        self.assertTrue(R["cleanup"]["ok"])
        self.assertFalse(R["ok"])

    def test_cleanup_or_host_difference_fails_the_cycle(self):
        rc, R, s, h = self.run_cycle(fail=lambda op: op[0] == "cmd" and op[1][:3] == ("ip", "netns", "del")
                                     and op[1][3] == L.NS_R)
        self.assertEqual(rc, 1)
        self.assertFalse(R["cleanup"]["ok"])
        self.assertFalse(R["host_compare"]["ok"])


# ------------------------------------------------------------------------------------------ /run/netns mount
PI0_1_MOUNT = "1609 29 0:26 /netns /run/netns rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,size=1605392k"


class TestNetnsDirMount(Sandboxed):
    """Regression for PI0-1 (20261011T175343Z): the first `ip netns add` bind-mounted /run/netns onto itself, `ip
    netns del` left it, cleanup reported success and the host comparison failed mounts_identical."""

    def run_cycle(self, s=None, **kw):
        return TestLifecycle.run_cycle(self, s, **kw)

    def pre_mounted(self):
        s = FakeSys()
        s.mounts.append(_mount(1609, 29, L.NETNS_DIR, root="/netns"))
        return s

    def umounts(self, h):
        return [op for op in h.ops if op[0] == "umount_netns_dir"]

    def test_mount_introduced_by_the_run_is_identified_and_removed(self):
        rc, R, s, h = self.run_cycle()
        self.assertEqual(rc, 0, R["aborts"])
        self.assertEqual(R["netns_dir_mount"], {"owned": [1601, 29, "0:26", "/netns"], "error": None,
                                                "pre_existing": []})
        self.assertEqual(s.mounts, BOOT_MOUNTS)
        self.assertTrue(R["host_compare"]["ok"] and R["cleanup"]["verify"]["checks"]["netns_dir_mounts_as_before"])
        last_del = max(i for i, op in enumerate(h.ops) if op[0] == "cmd" and op[1][:3] == ("ip", "netns", "del"))
        self.assertEqual([h.ops.index(op) for op in self.umounts(h)], [last_del + 1])   # after every namespace
        self.assertEqual(R["cleanup"]["steps"][-1], f"umount {L.NETNS_DIR}")

    def test_without_the_unmount_the_cycle_fails_like_pi0_1(self):
        """The old cleanup (no unmount step) leaves exactly the PI0-1 difference and must not pass."""
        with mock.patch.object(L, "netns_mount_owner", side_effect=lambda e: {
                "attempted": False, "before": None, "owned": None, "error": None}):
            rc, R, s, h = self.run_cycle()
        self.assertEqual(rc, 1)
        self.assertEqual(R["host_compare"]["failed"], ["mounts_identical"])
        self.assertEqual([m["mnt"] for m in s.mounts if m not in BOOT_MOUNTS], [L.NETNS_DIR])

    def test_pre_existing_mount_is_preserved(self):
        rc, R, s, h = self.run_cycle(self.pre_mounted())
        self.assertEqual(rc, 0, R["aborts"])
        self.assertEqual(R["netns_dir_mount"], {"owned": None, "error": None,
                                                "pre_existing": [[1609, 29, "0:26", "/netns"]]})
        self.assertEqual(self.umounts(h), [])
        self.assertEqual([m["id"] for m in s.mounts if m["mnt"] == L.NETNS_DIR], [1609])

    def test_concurrent_extra_mount_during_the_first_add_is_never_claimed(self):
        s = FakeSys()
        orig = s.add_mount

        def add(mnt, parent, **kw):
            mid = orig(mnt, parent, **kw)
            if mnt == L.NETNS_DIR:
                orig(L.NETNS_DIR, mid, root="/netns")                  # someone else stacks one at once
            return mid
        s.add_mount = add
        rc, R, s, h = self.run_cycle(s)
        self.assertEqual(rc, 1)
        self.assertIn("unexpected mounts", R["aborts"][0])
        self.assertEqual(self.umounts(h), [])
        self.assertEqual(len([m for m in s.mounts if m["mnt"] == L.NETNS_DIR]), 2)   # both kept
        self.assertFalse(R["cleanup"]["ok"])
        self.assertTrue(any("not owned" in e for e in R["cleanup"]["errors"]))
        self.assertEqual(s.netns, set())                               # namespaces still removed

    def test_concurrent_identical_self_bind_in_use_is_not_unmounted(self):
        """Another `ip netns add` racing the first one makes the same self-bind (indistinguishable by mount data);
        its namespace stays in /run/netns, so the unmount precondition (empty directory) refuses."""
        def race(op, s):
            if op[0] == "cmd" and op[1][:4] == ("ip", "netns", "add", L.NS_A):
                s.add_mount(L.NETNS_DIR, 29, root="/netns")
                s.netns.add("someone")
                s.add_mount(f"{L.NETNS_DIR}/someone", s.top_mount(L.NETNS_DIR)["id"], dev="0:4", fstype="nsfs",
                            optional=())
            return False
        s = FakeSys()
        rc, R, s, h = self.run_cycle(s, fail=lambda op: race(op, s))
        self.assertEqual(rc, 1)
        self.assertFalse(R["cleanup"]["ok"])
        self.assertTrue(any("differ" in e or "not empty" in e for e in R["cleanup"]["errors"]), R["cleanup"])
        self.assertIsNotNone(s.top_mount(L.NETNS_DIR))
        self.assertIn("someone", s.netns)

    def test_mount_of_unexpected_shape_is_never_claimed(self):
        for change in ({"root": "/"}, {"dev": "0:99"}, {"parent": 1}, {"fstype": "ramfs"}):
            with self.subTest(change):
                s = FakeSys()
                orig = s.add_mount

                def add(mnt, parent, _c=change, **kw):
                    if mnt == L.NETNS_DIR:
                        parent = _c.get("parent", parent)
                        kw.update({k: v for k, v in _c.items() if k != "parent"})
                    return orig(mnt, parent, **kw)
                s.add_mount = add
                rc, R, s, h = self.run_cycle(s)
                self.assertEqual(rc, 1)
                self.assertIn("not the self-bind", R["aborts"][0])
                self.assertEqual(self.umounts(h), [])
                self.assertTrue(any(m["mnt"] == L.NETNS_DIR for m in s.mounts))

    def test_mount_replaced_or_changed_before_cleanup_is_kept(self):
        def swap(s, how):
            m = s.top_mount(L.NETNS_DIR)
            if how == "stacked":
                s.add_mount(L.NETNS_DIR, m["id"], root="/netns")
            elif how == "replaced":
                s.mounts.remove(m)
                s.add_mount(L.NETNS_DIR, 29, root="/netns")
            elif how == "root":
                m["root"] = "/other"
            elif how == "foreign_netns":
                s.add_mount(f"{L.NETNS_DIR}/someone", m["id"], dev="0:4", fstype="nsfs", optional=())
        for how in ("stacked", "replaced", "root", "foreign_netns"):
            with self.subTest(how):
                s = FakeSys()
                hosts = []

                def fail(op, s=s, how=how):
                    if op[0] == "cmd" and op[1][:4] == ("ip", "netns", "del", L.NS_A):
                        swap(s, how)
                    return False
                out = self.tmp / f"x-{how}"
                rc = P.lifecycle(out, 1, COMMIT, sysr=s, host_cls=host_factory(hosts, fail=fail),
                                 sleep=lambda x: None)
                R = json.loads((out / "run.json").read_text())
                self.assertEqual(rc, 1)
                self.assertFalse(R["cleanup"]["ok"])
                self.assertTrue(any("umount" in e and "differ" in e for e in R["cleanup"]["errors"]),
                                R["cleanup"]["errors"])
                self.assertTrue(any(m["mnt"] == L.NETNS_DIR for m in s.mounts))   # nothing unmounted
                self.assertFalse(R["cleanup"]["verify"]["checks"]["netns_dir_mounts_as_before"])

    def test_non_empty_directory_is_not_unmounted(self):
        class Busy(FakeSys):
            def listdir(self, path):
                return ["stray"] if path == L.NETNS_DIR and not self.netns else super().listdir(path)
        rc, R, s, h = self.run_cycle(Busy())
        self.assertEqual(rc, 1)
        self.assertTrue(any("not empty" in e for e in R["cleanup"]["errors"]))
        self.assertTrue(any(m["mnt"] == L.NETNS_DIR for m in s.mounts))

    def test_unmount_failure_and_failed_restoration_fail_the_cycle(self):
        for name, effect in (("ebusy", OSError(16, "Device or resource busy")), ("no_effect", None)):
            with self.subTest(name):
                s = FakeSys()
                s.umount = (lambda p, e=effect: (_ for _ in ()).throw(e)) if effect else (lambda p: None)
                rc, R, s, h = self.run_cycle(s)
                self.assertEqual(rc, 1)
                self.assertFalse(R["cleanup"]["ok"])
                self.assertTrue(any(f"umount {L.NETNS_DIR}" in e for e in R["cleanup"]["errors"]))
                if effect is None:
                    self.assertTrue(any("not restored" in e for e in R["cleanup"]["errors"]))
                self.assertFalse(R["host_compare"]["ok"])

    def test_concurrent_mount_on_top_at_unmount_time_is_detected(self):
        """A mount stacked between the identity check and umount2 is the one umount2 removes: detected, reported."""
        s = FakeSys()
        s.on_umount = lambda: s.add_mount(L.NETNS_DIR, s.top_mount(L.NETNS_DIR)["id"], root="/netns")
        rc, R, s, h = self.run_cycle(s)
        self.assertEqual(rc, 1)
        self.assertTrue(any("not restored" in e for e in R["cleanup"]["errors"]), R["cleanup"]["errors"])

    def test_first_add_failing_after_the_mount_still_removes_it(self):
        rc, R, s, h = self.run_cycle(fail_after_mount=True)
        self.assertEqual(rc, 1)
        self.assertIn("after the /run/netns mount", R["aborts"][0])
        self.assertTrue(empty(s))
        self.assertTrue(R["cleanup"]["ok"] and R["host_compare"]["ok"])

    def test_unreadable_or_ambiguous_mount_state_refuses_before_any_namespace(self):
        s = FakeSys()
        s.mountinfo_ok = False
        out = self.tmp / "PI0-1"
        hosts = []
        with self.assertRaises(P.Refused):
            P.lifecycle(out, 1, COMMIT, sysr=s, host_cls=host_factory(hosts), sleep=lambda x: None)
        self.assertEqual(hosts[0].ops, [])
        self.assertFalse(json.loads((out / "run.json").read_text())["preflight"]["checks"][
            "netns_dir_mount_unambiguous"])
        for extra in ([_mount(1609, 29, L.NETNS_DIR, root="/netns"), _mount(1610, 1609, L.NETNS_DIR, root="/netns")],
                      [_mount(1609, 29, L.NETNS_DIR, root="/netns"),
                       _mount(1611, 1609, f"{L.NETNS_DIR}/other", dev="0:4", fstype="nsfs", optional=())]):
            with self.subTest(extra):
                s = FakeSys()
                s.mounts += extra
                self.assertFalse(L.preflight(s)["checks"]["netns_dir_mount_unambiguous"])
                h = SimHost(L.Plan("PI0-s1"), str(self.tmp / "g.jsonl"), s)
                with self.assertRaises(L.LabRefused):                  # the Host refuses on its own as well
                    h.apply(L.lab_plan()[0])
                self.assertEqual(h.ops, [])

    def test_mount_table_unreadable_after_the_first_add_is_not_claimed(self):
        class Flaky(FakeSys):
            def read(self, path):
                if path == L.MOUNTINFO and self.netns and not getattr(self, "seen", False):
                    self.seen = True
                    return None
                return super().read(path)
        rc, R, s, h = self.run_cycle(Flaky())
        self.assertEqual(rc, 1)
        self.assertIn("not recorded", R["aborts"][0])
        self.assertEqual(self.umounts(h), [])

    def test_cleanup_is_repeatable_and_the_wrapper_trap_removes_the_mount(self):
        s = FakeSys()
        h = SimHost(L.Plan("PI0-s1"), str(self.tmp / "ops.jsonl"), s)
        for op in L.cgroup_plan() + L.lab_plan():
            h.apply(op)                                                # interrupted here: no cleanup ran
        res = L.cleanup(SimHost(L.Plan("PI0-s1"), h.oplog, s), s, L.read_oplog(h.oplog), "PI0-s1")
        self.assertTrue(res["ok"], res)
        self.assertTrue(empty(s))
        h2 = SimHost(L.Plan("PI0-s1"), h.oplog, s)
        res = L.cleanup(h2, s, L.read_oplog(h.oplog), "PI0-s1")         # again: nothing to do, still ok
        self.assertTrue(res["ok"], res)
        self.assertEqual(h2.ops, [])

    def test_guard_and_real_unmount_call(self):
        plan = L.Plan("PI0-s1")
        plan.check(("umount_netns_dir", (1601, 29, "0:26", "/netns")))
        for bad in (("umount_netns_dir",), ("umount_netns_dir", [1601, 29, "0:26", "/netns"]),
                    ("umount_netns_dir", (0, 29, "0:26", "/netns")), ("umount_netns_dir", (True, 29, "0:26", "/n")),
                    ("umount_netns_dir", (1601, 29, "x", "/netns")), ("umount_netns_dir", (1601, 29, "0:26", "n")),
                    ("umount_netns_dir", (1601, 29, "0:26", "/netns"), "/etc"), ("umount", "/run/netns")):
            with self.subTest(bad=bad), self.assertRaises(L.LabRefused):
                plan.check(bad)
        s = FakeSys()
        mid = s.add_mount(L.NETNS_DIR, 29, root="/netns")
        calls = []
        host = L.Host(plan, str(self.tmp / "r.jsonl"), s)
        with mock.patch.object(L.Host, "_do", REAL_DO), \
                mock.patch.object(L, "_umount2", side_effect=lambda p: calls.append(p) or s.umount(p)):
            host.apply(("umount_netns_dir", (mid, 29, "0:26", "/netns")))
        self.assertEqual(calls, [L.NETNS_DIR])
        self.assertEqual(s.mounts, BOOT_MOUNTS)
        libc = mock.Mock()
        libc.umount2.return_value = 0
        with mock.patch("ctypes.CDLL", return_value=libc):
            L._umount2(L.NETNS_DIR)
        libc.umount2.assert_called_once_with(b"/run/netns", L.UMOUNT_NOFOLLOW)   # never MNT_DETACH (2)
        self.assertEqual(L.UMOUNT_NOFOLLOW & 2, 0)

    def test_parse_mountinfo_and_ownership_from_the_observed_pi0_1_line(self):
        run_line = "29 30 0:26 / /run rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,size=1605392k"
        root_line = "30 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw"
        before = {"phase": "observe", "what": L.NETNS_DIR, "label": "before",
                  "state": L.netns_dir_state(SimpleNamespace(read=lambda p: f"{root_line}\n{run_line}\n"))}
        after = {"phase": "observe", "what": L.NETNS_DIR, "label": "after_first_add",
                 "state": L.netns_dir_state(SimpleNamespace(read=lambda p: f"{root_line}\n{run_line}\n{PI0_1_MOUNT}\n"))}
        intent = {"phase": "intent", "op": ["cmd", ["ip", "netns", "add", L.NS_A]]}
        own = L.netns_mount_owner([before, intent, after])
        self.assertEqual((own["owned"], own["error"]), ((1609, 29, "0:26", "/netns"), None))
        self.assertEqual(L.parse_mountinfo("40 29 0:26 /a\\040b /run/a\\040b rw - tmpfs tmpfs rw")[0]["mnt"],
                         "/run/a b")
        self.assertIsNone(L.parse_mountinfo("garbage line"))
        self.assertIsNone(L.parse_mountinfo(""))


# ------------------------------------------------------------------------------------------ CTRL orchestration
def metrics_doc(completed=0, rejected=0, failed=0, busy=0, sha="0" * 64, lock_waits=0):
    m = W.Metrics()
    m.counters["requests_completed_total"] = completed
    m.counters["requests_rejected_total"] = rejected
    m.counters["requests_failed_total"] = failed
    for _ in range(lock_waits):
        m.observe("lock_wait", 1.0)
    return m.document(4, busy, sha)


def config_echo(workload, seq=1, control_error=None, **over):
    """config.json as the workload publishes it (Runner.echo_config, its own canonical encoding and hash)."""
    cfg = dict({k: workload[k] for k in P.SERVICE_CONFIG_KEYS}, **over)
    return W.canonical({"seq": seq, "mono_ns": 1, "config": cfg, "control_error": control_error,
                        "config_sha256": hashlib.sha256(W.canonical(cfg)).hexdigest()})


def app_snapshot(lock="MISSING", scope="app:faultlab-ctrl", quality=None, drop=(), unavailable=(), lock_scope=None):
    """A snapshot with every registry app.* measurement (OK, at scope) as the collector emits it; app.lock_wait_ms is
    MISSING without a value and listed as missing (lock="MISSING", as with lock_hold_us 0) or OK (lock="OK")."""
    from sentinelai.diagnostic.contract import load_contract
    ms, missing = [], []
    for f in load_contract().registry.features:
        if f.family != "application" or f.id in drop:
            continue
        for a in f.aggregations:
            for q in (sorted(f.dimension.values) if f.dimension else [None]):
                m = {"feature_id": f.id, "aggregation": str(getattr(a, "value", a)), "quality": "OK", "value": 1.0,
                     "coverage": 1.0, "scope": scope}
                if q is not None:
                    m["qualifier"] = {"dimension": f.dimension.name, "value": q}
                if f.id == P.LOCK_WAIT and lock == "MISSING":
                    m.update(quality="MISSING", value=None, scope=lock_scope or scope)
                    missing.append({"feature_id": f.id, "reason": "no requests in the window, or the rank is in "
                                    "the +Inf bucket", "scope": lock_scope or scope})
                m["quality"] = (quality or {}).get(f.id, m["quality"])
                ms.append(m)
    return (json.dumps({"target": {"name": "faultlab-ctrl"}, "measurements": ms, "missing_measurements": missing,
                        "data_quality": {"sources_unavailable": list(unavailable)}}, sort_keys=True) + "\n").encode()


class CtrlFixture(Sandboxed):
    """The simulated CTRL run (no tests here)."""

    def setUp(self):
        super().setUp()
        from sentinelai.diagnostic.contract import Target
        self.s = FakeSys()
        self.out = self.tmp / "CTRL-900001"
        self.n = P.scheduled_arrivals(WORKLOAD, P.WARMUP_S + P.B_S + P.W_S + P.COOLDOWN_S, 900001)
        self.docs = []
        self.workload = WORKLOAD                     # run.json workload (the approved FZ-WORKLOAD value)
        self.config = None                           # config.json bytes; None: the echo of self.workload
        self.doc_sha = None                          # config_sha256 in the metrics documents; None: the echo's
        self.lock_waits = 0                          # lock-wait observations in the end metrics document
        self.snap = app_snapshot()                   # the run's canonical snapshot (live and replay)
        target = Target(name="faultlab-ctrl", cgroup_path=L.TARGET_CGROUP_PATH, pids=(1,), cpuset="18",
                        netns_ref="pid:1", ifaces=())

        def resolve(reader, name, path):
            pid = [p for p, cg in self.s.procs.items() if cg == L.TARGET_CGROUP_PATH][0]
            return target.model_copy(update={"pids": (pid,), "netns_ref": f"pid:{pid}"})

        def read_metrics(run_id):
            try:
                sha = self.doc_sha or json.loads(self.config_bytes())["config_sha256"]
            except (ValueError, KeyError, TypeError):            # a deliberately malformed echo
                sha = "0" * 64
            if not self.docs:
                self.docs.append(metrics_doc(sha=sha))
                return self.docs[0]
            return metrics_doc(completed=self.n, sha=sha, lock_waits=self.lock_waits)

        def loadgen():
            def finish():
                base = json.loads(self.docs[0])["mono_ns"]
                recs = [{"k": k, "scheduled_ns": base + 1000 + k, "sent_ns": base + 1000 + k, "outcome": "200",
                         "latency_ms": 0.001} for k in range(self.n)]
                path = self.out / "lg" / "client.jsonl"
                path.write_text("".join(json.dumps(r) + "\n" for r in recs))
                self.s.tcp = [1000, 900, 0]
                self.s.r_stats = {L.IF_RA: [1010, 905, 0, 0], L.IF_RB: [905, 1010, 0, 0]}
            return FakeProc(on_wait=finish)
        self.spawn = {"loadgen": loadgen}

        class Loader:
            def __init__(self, *a, **k):
                self.raw, self.proc = ['{"meta": 1}'], SimpleNamespace(pid=9)

            def start(self):
                return None

            def sample(self):
                return {}

            def close(self):
                pass
        import m3b_r1_validate
        import sentinelai.collectors as COL
        import sentinelai.collectors.app as APP
        import sentinelai.ebpf as EB
        import sentinelai.diagnostic.contract as CON
        import sentinelai.runtime.pipeline as PIPE
        import sentinelai.runtime.ticks as TICKS
        stats = SimpleNamespace(ticks=136, wall_s=135.0, cpu_s=1.0, max_tick_read_s=0.01)
        for p in (mock.patch.object(COL, "resolve_target", side_effect=resolve),
                  mock.patch.object(COL, "collect", return_value=(["t"] * 136, stats)),
                  mock.patch.object(COL, "build_snapshot", return_value="snap"),
                  mock.patch.object(APP, "read_metrics", side_effect=read_metrics),
                  mock.patch.object(EB, "resolve_ebpf_target", return_value="ids"),
                  mock.patch.object(EB, "loader_argv", return_value=["loader"]),
                  mock.patch.object(m3b_r1_validate, "Recording", Loader),
                  mock.patch.object(CON, "canonical_bytes", return_value=b"snap"),
                  mock.patch.object(PIPE, "validate_snapshot", side_effect=lambda b: (None, self.snap)),
                  mock.patch.object(TICKS, "encode_ticks", return_value=b"TICKS\n"),
                  mock.patch.object(TICKS, "decode_ticks", return_value=[]),
                  mock.patch.object(P, "proc_cpu_s", return_value=0.5),
                  mock.patch.object(P.C, "wait_bpf_released", return_value={"released": True}),
                  mock.patch.object(P, "replay", side_effect=lambda out: self.snap),
                  mock.patch.object(P, "pi_checks", return_value={"PI-1": {"ok": True}})):
            p.start()
            self.addCleanup(p.stop)
        approved = mock.patch.object(P, "approved_value", side_effect=lambda name, rec=None: self.workload)
        approved.start()
        self.addCleanup(approved.stop)

    def config_bytes(self):
        return self.config if self.config is not None else config_echo(self.workload)

    def run_ctrl(self, **kw):
        hosts = []
        spawn = dict(self.spawn, **kw.pop("spawn", {}))
        kw.setdefault("workload_files", {"config.json": self.config_bytes()})
        with mock.patch.object(P.os, "chown"):
            rc = P.ctrl(self.out, 900001, COMMIT, sysr=self.s, host_cls=host_factory(hosts, spawn=spawn, **kw),
                        sleep=lambda x: None)
        return rc, hosts[0]


class TestCtrl(CtrlFixture):
    def test_ctrl_run_produces_verified_reconciled_evidence(self):
        rc, h = self.run_ctrl()
        rep = json.loads((self.out / "report.json").read_text())
        self.assertEqual(rc, 0, rep)
        self.assertTrue(rep["pipeline_ok"])
        self.assertEqual(set(rep["checks"]), P.PIPELINE_CHECKS)
        for k in P.PIPELINE_CHECKS:
            self.assertTrue(rep["checks"][k]["ok"], (k, rep["checks"][k]))
        self.assertEqual(rep["checks"]["client_server_reconciliation"]["client_outcomes"], {"200": self.n})
        self.assertEqual(RH.verify_manifest(self.out), [])
        roles = [op[1] for op in h.ops if op[0] == "spawn"]
        self.assertEqual(roles, ["dependency", "workload", "loadgen"])
        self.assertTrue(empty(self.s))
        run = json.loads((self.out / "evidence" / "run.json").read_text())
        self.assertEqual(run["workload"], WORKLOAD)
        self.assertEqual(run["load"]["arrivals"], self.n)

    def test_tampered_evidence_is_detected(self):
        self.run_ctrl()
        f = self.out / "evidence" / "client.jsonl"
        f.write_text(f.read_text().replace('"200"', '"503"', 1))
        rep = P.evaluate(self.out)
        self.assertFalse(rep["checks"]["manifest"]["ok"])
        self.assertFalse(rep["checks"]["client_server_reconciliation"]["ok"])
        self.assertFalse(rep["ok"])
        (self.out / "evidence" / "extra.txt").write_text("x")
        self.assertTrue(any("unexpected" in p for p in RH.verify_manifest(self.out)))

    def test_pipeline_needs_every_required_check_present(self):
        self.run_ctrl()
        self.assertTrue(P.evaluate(self.out)["pipeline_ok"])
        with mock.patch.object(P, "PIPELINE_CHECKS", P.PIPELINE_CHECKS | {"a_check_that_was_not_run"}):
            self.assertFalse(P.evaluate(self.out)["pipeline_ok"])

    def test_replay_mismatch_fails(self):
        self.run_ctrl()
        with mock.patch.object(P, "replay", return_value=self.snap + b" "):
            rep = P.evaluate(self.out)
        self.assertFalse(rep["checks"]["replay_byte_identical"]["ok"])
        self.assertFalse(rep["pipeline_ok"])

    def test_startup_failure_and_timeouts_abort_and_clean_up(self):
        for name, kw in (("loadgen exit 3", {"spawn": {"loadgen": lambda: FakeProc(rc=3)}}),
                         ("forward fails", {"fail": lambda op: op[0] == "forward"}),
                         ("spawn refused by host", {"fail": lambda op: op[0] == "spawn" and op[1] == "workload"})):
            with self.subTest(name):
                self.out = self.tmp / f"CTRL-90000{len(list(self.tmp.iterdir()))}"
                self.s = FakeSys()
                self.docs = []
                rc, h = self.run_ctrl(**kw)
                rep = json.loads((self.out / "report.json").read_text())
                self.assertEqual(rc, 1)
                self.assertFalse(rep["checks"]["run_completed"]["ok"])
                self.assertTrue(rep["checks"]["cleanup"]["ok"])
                self.assertTrue(empty(self.s))
                self.assertFalse((self.out / "manifest.json").exists())   # no manifest over incomplete evidence

    def test_workload_not_ready_times_out(self):
        class Silent(SimHost):
            def _do(self, op, stdout, stderr):
                r = super()._do(op, stdout, stderr)
                if op[0] == "spawn" and op[1] == "dependency":
                    self.sys.run.pop(f"{L.run_dir(self.plan.run_id)}/dependency_config.json")
                return r
        hosts = []

        def make(plan, oplog, sysr):
            h = Silent(plan, oplog, sysr, spawn=self.spawn)
            hosts.append(h)
            return h
        with mock.patch.object(P, "READY_TIMEOUT_S", 0.05), mock.patch.object(P.os, "chown"):
            rc = P.ctrl(self.out, 900001, COMMIT, sysr=self.s, host_cls=make, sleep=lambda x: None)
        self.assertEqual(rc, 1)
        self.assertIn("not ready", json.loads((self.out / "evidence" / "run.json").read_text())["aborts"][0])
        self.assertTrue(empty(self.s))

    def test_malformed_evidence_fails_without_crashing(self):
        self.run_ctrl()
        (self.out / "evidence" / "counters.json").write_text("{not json")
        rep = P.evaluate(self.out)
        self.assertFalse(rep["checks"]["evidence_readable"]["ok"])
        self.assertFalse(rep["ok"] or rep["pipeline_ok"])

    def test_r_drop_or_missing_traffic_fails_reconciliation(self):
        self.run_ctrl()
        c = json.loads((self.out / "evidence" / "counters.json").read_text())
        c["end"]["r"][L.IF_RA]["rx_dropped"] = 1
        _, failed = P.reconcile_r(c)
        self.assertIn(f"{L.IF_RA}_rx_dropped_0", failed)
        c = json.loads((self.out / "evidence" / "counters.json").read_text())
        c["end"]["r"][L.IF_RB]["tx_packets"] = c["start"]["r"][L.IF_RB]["tx_packets"]
        _, failed = P.reconcile_r(c)
        self.assertIn("a_out_left_r", failed)


class TestCtrlAppFeatures(CtrlFixture):
    """app_features through the real ctrl() -> evaluate() -> app_feature_report path (no mock of the checker).
    app.lock_wait_ms may be MISSING only when the run's manifest-verified evidence proves lock_hold_us == 0."""

    def app(self, rep=None):
        rep = rep or json.loads((self.out / "report.json").read_text())
        return rep["checks"]["app_features"]

    def assert_fails(self, needle, basis_needle=None):
        rc, _ = self.run_ctrl()
        rep = json.loads((self.out / "report.json").read_text())
        a = self.app(rep)
        self.assertEqual(rc, 1)
        self.assertFalse(a["ok"])
        self.assertFalse(rep["pipeline_ok"])
        self.assertTrue(any(needle in p for p in a["problems"]), a["problems"])
        if basis_needle is not None:
            self.assertFalse(a["structurally_unavailable"]["applied"])
            self.assertTrue(any(basis_needle in w for w in a["structurally_unavailable"]["not_applied_because"]),
                            a["structurally_unavailable"])
        return a

    def test_zero_lock_hold_accepts_only_the_missing_lock_wait(self):
        """The CTRL-900001 shape: everything measured except app.lock_wait_ms P99 (MISSING, listed as missing)."""
        rc, _ = self.run_ctrl()
        rep = json.loads((self.out / "report.json").read_text())
        a = self.app(rep)
        self.assertEqual(rc, 0, a)
        self.assertTrue(a["ok"] and rep["pipeline_ok"], a)
        self.assertEqual(a["problems"], [])
        basis = a["structurally_unavailable"]
        self.assertTrue(basis["applied"])
        self.assertEqual(basis["lock_hold_us"], {"config_json": 0, "run_json": 0})
        self.assertIn("lock_hold_us 0", basis["reason"])
        noted = [r for r in a["rows"] if "structurally_unavailable" in r]
        self.assertEqual([(r["feature"], r["aggregation"], r["quality"]) for r in noted],
                         [(P.LOCK_WAIT, "P99", "MISSING")])
        self.assertEqual(P.evaluate(self.out)["checks"]["app_features"], a)       # offline recomputation agrees

    def test_the_unpatched_checker_rejects_this_run(self):
        """Regression anchor: without the evidence-proven exemption the same evidence fails exactly as CTRL-900001."""
        self.run_ctrl()
        with mock.patch.object(P, "structural_app_gaps", return_value=({}, {"applied": False})):
            a = self.app(P.evaluate(self.out))
        self.assertFalse(a["ok"])
        self.assertEqual(sorted(a["problems"]), sorted([f"('{P.LOCK_WAIT}', 'P99', None): quality MISSING",
                         f"listed as missing: {P.LOCK_WAIT} (no requests in the window, or the rank is in the +Inf "
                         "bucket)"]))

    def test_zero_lock_hold_never_excuses_another_feature(self):
        for name, snap, needle in (
                ("unrelated feature not measured", app_snapshot(drop=("app.queue_wait_ms",)), "not measured"),
                ("unrelated feature MISSING", app_snapshot(quality={"app.throughput": "MISSING"}), "quality MISSING"),
                ("unrelated feature STALE", app_snapshot(quality={"app.latency_ms": "STALE"}), "quality STALE"),
                ("wrong scope everywhere", app_snapshot(scope="app:other"), "scope app:other"),
                ("lock wait at another scope", app_snapshot(lock_scope="app:other"), "scope app:other"),
                ("lock wait INVALID", app_snapshot(quality={P.LOCK_WAIT: "INVALID"}), "quality INVALID"),
                ("lock wait not measured at all", app_snapshot(drop=(P.LOCK_WAIT,)), "not measured"),
                ("app metrics unavailable", app_snapshot(unavailable=("APP_METRICS",)), "sources reported"),
                ("app events unavailable", app_snapshot(unavailable=("APP_EVENTS",)), "sources reported")):
            with self.subTest(name):
                self.out, self.s, self.docs, self.snap = self.tmp / f"CTRL-9{len(list(self.tmp.iterdir())):05d}", \
                    FakeSys(), [], snap
                a = self.assert_fails(needle)
                self.assertTrue(a["structurally_unavailable"]["applied"])      # the proof held; the snapshot did not

    def test_positive_lock_hold_requires_the_lock_wait(self):
        self.workload = dict(WORKLOAD, lock_hold_us=200)
        self.lock_waits = 5
        a = self.assert_fails("quality MISSING", "lock_hold_us is 200, not 0")
        self.assertIn(f"listed as missing: {P.LOCK_WAIT} (no requests in the window, or the rank is in the +Inf "
                      "bucket)", a["problems"])

    def test_positive_lock_hold_with_a_measured_lock_wait_passes(self):
        self.workload = dict(WORKLOAD, lock_hold_us=200)
        self.lock_waits = 5
        self.snap = app_snapshot(lock="OK")
        rc, _ = self.run_ctrl()
        a = self.app()
        self.assertEqual(rc, 0, a)
        self.assertTrue(a["ok"])
        self.assertFalse(a["structurally_unavailable"]["applied"])
        self.assertFalse([r for r in a["rows"] if "structurally_unavailable" in r])
        for bad in ("INVALID", "STALE", "MISSING"):                     # a present lock wait keeps its normal checks
            with self.subTest(bad):
                self.snap = app_snapshot(lock="OK", quality={P.LOCK_WAIT: bad})
                (self.out / "snapshot.json").write_bytes(self.snap)          # the live snapshot app_features reads
                a = self.app(P.evaluate(self.out))
                self.assertFalse(a["ok"])
                self.assertIn(f"('{P.LOCK_WAIT}', 'P99', None): quality {bad}", a["problems"])

    def test_recorded_configuration_must_prove_zero_lock_hold(self):
        echo = lambda **kw: config_echo(WORKLOAD, **kw)
        good = json.loads(echo())
        cases = (
            ("config.json not JSON", b"{not json", None, "evidence unreadable"),
            ("config.json not an echo", b'{"lock_hold_us": 0}', None, "not a workload configuration echo"),
            ("config.json missing config", W.canonical(dict(good, config=None)), None,
             "not a workload configuration echo"),
            ("config lock_hold_us 200", echo(lock_hold_us=200), None, "config.json lock_hold_us is 200"),
            ("config lock_hold_us false", echo(lock_hold_us=False), None, "config.json lock_hold_us is False"),
            ("config lock_hold_us '0'", echo(lock_hold_us="0"), None, "config.json lock_hold_us is '0'"),
            ("config lock_hold_us 0.0", echo(lock_hold_us=0.0), None, "config.json lock_hold_us is 0.0"),
            ("config lock_hold_us absent", W.canonical(dict(good, config={k: v for k, v in good["config"].items()
                                                                           if k != "lock_hold_us"})), None,
             "config.json lock_hold_us is None"),
            ("echo differs from run.json", echo(pool=8), None, "differs from run.json workload"),
            ("reconfigured during the run", echo(seq=2), None, "changed during the run"),
            ("control error recorded", echo(control_error="bad control"), None, "changed during the run"),
            ("hash does not match", W.canonical(dict(good, config_sha256="1" * 64)), None,
             "does not hash the recorded configuration"),
            ("metrics under another configuration", echo(), "2" * 64, "not produced under the recorded"))
        for name, config, doc_sha, why in cases:
            with self.subTest(name):
                self.out, self.s, self.docs = self.tmp / f"CTRL-9{len(list(self.tmp.iterdir())):05d}", FakeSys(), []
                self.config, self.doc_sha = config, doc_sha
                self.assert_fails("quality MISSING", why)

    def test_run_json_must_record_zero_lock_hold(self):
        for v in (200, None, True):
            with self.subTest(v):
                self.out, self.s, self.docs = self.tmp / f"CTRL-9{len(list(self.tmp.iterdir())):05d}", FakeSys(), []
                self.workload = dict(WORKLOAD, lock_hold_us=v)
                self.config = config_echo(WORKLOAD)
                self.assert_fails("quality MISSING", f"run.json workload lock_hold_us is {v!r}")

    def test_observed_lock_waits_contradict_zero_lock_hold(self):
        self.lock_waits = 1
        self.assert_fails("quality MISSING", "lock waits were observed")

    def test_provenance_requires_a_verified_manifest(self):
        self.run_ctrl()
        self.assertTrue(self.app()["ok"])
        f = self.out / "evidence" / "config.json"
        f.write_bytes(f.read_bytes() + b" ")                           # same content, changed bytes: not verified
        rep = P.evaluate(self.out)
        self.assertFalse(rep["checks"]["manifest"]["ok"])
        a = self.app(rep)
        self.assertFalse(a["ok"])
        self.assertEqual(a["structurally_unavailable"]["not_applied_because"], ["manifest not verified"])
        (self.out / "evidence" / "config.json").unlink()
        self.assertFalse(self.app(P.evaluate(self.out))["ok"])

    def test_missing_evidence_files_never_grant_the_exemption(self):
        self.run_ctrl()
        for n in ("run.json", "config.json", "app_start.json", "app_end.json"):
            with self.subTest(n):
                f = self.out / "evidence" / n
                data = f.read_bytes()
                f.unlink()
                gaps, basis = P.structural_app_gaps(self.out, True)
                f.write_bytes(data)
                self.assertEqual(gaps, {})
                self.assertFalse(basis["applied"])
                self.assertTrue(basis["not_applied_because"])
        self.assertEqual(P.structural_app_gaps(self.out, True)[0], {P.LOCK_WAIT: mock.ANY})


# ------------------------------------------------------------------------------------------ evaluation units
class TestReconciliation(unittest.TestCase):
    def test_client_server(self):
        a = {"mono_s": 1.0, "pool_util": 0.0, "requests_completed_total": 10, "requests_rejected_total": 0,
             "requests_failed_total": 0}
        b = dict(a, mono_s=9.0, requests_completed_total=12, requests_rejected_total=1)
        recs = [{"k": 0, "sent_ns": 2e9, "latency_ms": 1, "outcome": "200"},
                {"k": 1, "sent_ns": 3e9, "latency_ms": 1, "outcome": "200"},
                {"k": 2, "sent_ns": 4e9, "latency_ms": 1, "outcome": "503"},
                {"k": 3, "sent_ns": None, "latency_ms": None, "outcome": "client_saturated"}]
        run = {"load": {"arrivals": 4}}
        self.assertEqual(P.reconcile_clients(run, recs, a, b)[1], [])
        for name, (r2, a2, b2) in {
                "missing arrival": (recs[:3], a, b), "unexplained outcome": (recs[:3] + [dict(recs[3], outcome=
                                                                                        "ConnectionResetError")], a, b),
                "busy at end": (recs, a, dict(b, pool_util=0.25)), "late start doc": (recs, dict(a, mono_s=2.5), b),
                "early end doc": (recs, a, dict(b, mono_s=3.0)),
                "counter mismatch": (recs, a, dict(b, requests_completed_total=13))}.items():
            with self.subTest(name):
                self.assertTrue(P.reconcile_clients(run, r2, a2, b2)[1])

    def test_pi_checks(self):
        def m(f, cov=1.0, agg="RATE", q="OK"):
            return {"feature_id": f, "coverage": cov, "aggregation": agg, "quality": q}
        snap = {"measurements": [m("tcp.retrans_frac"), m("net.drop.qdisc"), m("app.latency_ms", agg="P99"),
                                 m("cpu.util.cpuset")], "missing_measurements": [{"feature_id": "net.drop.netfilter"}]}
        ticks = [SimpleNamespace(obs={"app": {}}) for _ in range(100)]
        run = {"collection": {"cpu_s": 1.0, "loader_cpu_s": 0.5, "wall_s": 100.0}}
        r = P.pi_checks(run, snap, ticks)
        self.assertTrue(r["PI-1"]["ok"] and r["PI-7_ctrl"]["ok"])
        self.assertTrue(r["PI-6"]["ok"])
        self.assertEqual(r["PI-6"]["not_collected"], ["net.drop.netfilter"])
        r = P.pi_checks({"collection": {"cpu_s": 2.0, "loader_cpu_s": 0.5, "wall_s": 100.0}}, snap, ticks)
        self.assertFalse(r["PI-6"]["ok"])                              # 0.025 core > 0.02
        low = dict(snap, measurements=snap["measurements"] + [m("tcp.out_segs_rate", cov=0.98)])
        r = P.pi_checks(run, low, ticks)
        self.assertFalse(r["PI-1"]["ok"] or r["PI-6"]["ok"])
        bad_ticks = ticks[:98] + [SimpleNamespace(obs={"app": "Bad"})] * 2
        self.assertFalse(P.pi_checks(run, snap, bad_ticks)["PI-7_ctrl"]["ok"])
        nop99 = dict(snap, measurements=[x for x in snap["measurements"] if x["aggregation"] != "P99"])
        self.assertFalse(P.pi_checks(run, nop99, ticks)["PI-7_ctrl"]["ok"])

    def test_aborted_run_is_never_ok(self):
        with tempfile.TemporaryDirectory() as d:
            rep = P.evaluate(Path(d), run_result={"aborts": ["x"], "cleanup": {"ok": True},
                                                  "host_compare": {"ok": True}, "bpf_release": {"released": True}})
        self.assertFalse(rep["ok"] or rep["pipeline_ok"])
        self.assertEqual(rep["pi"], {})


# ------------------------------------------------------------------------------------------ gates
class TestGates(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp))
        for p in (mock.patch.object(P, "check_invocation"), mock.patch.object(P, "hand_over"),
                  mock.patch.object(P, "staging_root", return_value=self.tmp)):
            p.start()
            self.addCleanup(p.stop)

    def report(self, overall="READY", head=COMMIT):
        return {"overall": overall, "checks": [{"id": "INT-HEAD", "mandatory": False, "status": "PASS",
                                                "observed": head},
                                               {"id": "ENV-PRIVILEGE", "mandatory": True,
                                                "status": "PASS" if overall == "READY" else "UNVERIFIED"}]}

    def args(self, cmd="lifecycle", **kw):
        return SimpleNamespace(cmd=cmd, campaign=kw.get("campaign", "20261012T000000Z"), cycle=kw.get("cycle", 1),
                               seed=kw.get("seed", 900001), execute=True)

    def test_not_ready_preflight_refuses_before_anything_is_created(self):
        with mock.patch.object(P, "lifecycle") as lc, self.assertRaises(P.Refused):
            P.run_stage(self.args(), run_preflight=lambda: self.report("NOT_READY"))
        lc.assert_not_called()
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_ready_preflight_runs_the_stage_with_the_preflight_head(self):
        with mock.patch.object(P, "lifecycle", return_value=0) as lc:
            rc = P.run_stage(self.args(), run_preflight=lambda: self.report())
        self.assertEqual(rc, 0)
        self.assertEqual(lc.call_args.args[2], COMMIT)

    def test_ctrl_needs_five_passing_pi0_cycles_at_the_same_commit(self):
        camp = self.tmp / "20261012T000000Z"
        with mock.patch.object(P, "ctrl") as ct, self.assertRaises(P.Refused):
            P.run_stage(self.args("ctrl"), run_preflight=lambda: self.report())
        ct.assert_not_called()
        for k in range(1, 6):
            (camp / f"PI0-{k}").mkdir(parents=True)
            (camp / f"PI0-{k}" / "run.json").write_text(json.dumps({"ok": k != 3, "commit": COMMIT}))
        with mock.patch.object(P, "ctrl") as ct, self.assertRaises(P.Refused):
            P.run_stage(self.args("ctrl"), run_preflight=lambda: self.report())
        ct.assert_not_called()
        (camp / "PI0-3" / "run.json").write_text(json.dumps({"ok": True, "commit": COMMIT}))
        with mock.patch.object(P, "ctrl") as ct, self.assertRaises(P.Refused):
            P.run_stage(self.args("ctrl"), run_preflight=lambda: self.report(head="d" * 40))
        ct.assert_not_called()
        with mock.patch.object(P, "ctrl", return_value=0) as ct:
            self.assertEqual(P.run_stage(self.args("ctrl"), run_preflight=lambda: self.report()), 0)
        ct.assert_called_once()

    def test_bad_arguments_and_reused_directories_are_refused(self):
        for a in (self.args(campaign="../x"), self.args(campaign="today"), self.args(cycle=6),
                  self.args("ctrl", seed=42)):
            with self.subTest(a=a), self.assertRaises(P.Refused):
                P.run_stage(a, run_preflight=lambda: self.report())
        (self.tmp / "20261012T000000Z" / "PI0-1").mkdir(parents=True)
        with self.assertRaises(P.Refused):
            P.run_stage(self.args(), run_preflight=lambda: self.report())

    def test_invocation_must_be_sudo_from_lab_uid_on_driver_cpus(self):
        mock.patch.stopall()                                          # the real check, not the setUp stub
        if os.geteuid() != 0:
            with self.assertRaises(P.Refused):
                P.check_invocation()
        with mock.patch.object(P.os, "geteuid", return_value=0), \
                mock.patch.dict(P.os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}), \
                mock.patch.object(P.os, "sched_getaffinity", return_value={0, 18}), self.assertRaises(P.Refused):
            P.check_invocation()
        with mock.patch.object(P.os, "geteuid", return_value=0), mock.patch.dict(P.os.environ, {"SUDO_UID": "0"}), \
                self.assertRaises(P.Refused):
            P.check_invocation()

    def test_unapproved_decisions_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            rec = json.loads((ROOT / "docs/PHASE_1C_FREEZE1_DECISIONS.json").read_text())
            f = Path(d) / "r.json"
            f.write_text(json.dumps(rec))
            for name in ("FZ-INTENSITY", "FZ-PI5"):
                with self.subTest(name), self.assertRaises(P.Refused):
                    P.approved_value(name, f)
            self.assertEqual(P.approved_value("FZ-WORKLOAD", f), WORKLOAD)
            rec["decisions"]["FZ-WORKLOAD"]["status"] = "proposed"
            f.write_text(json.dumps(rec))
            with self.assertRaises(P.Refused):
                P.approved_value("FZ-WORKLOAD", f)

    def test_lab_uid_files_are_never_read_through_a_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            secret = Path(d) / "secret"
            secret.write_text("x")
            link = Path(d) / "client.jsonl"
            link.symlink_to(secret)
            with self.assertRaises(OSError):
                P.read_regular(link)
            self.assertEqual(P.read_regular(secret), b"x")
            with self.assertRaises(L.LabAbort):
                P.read_regular(secret, limit=0)


class TestStatic(unittest.TestCase):
    def test_no_m2_and_no_fault_classes(self):
        for f in ("experiments/faultlab/pilot.py", "experiments/faultlab/lab.py"):
            src = (ROOT / f).read_text()
            tree = ast.parse(src)
            names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
                {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            self.assertFalse(names & {"diagnose", "Diagnosis"}, f)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module and "diagnostic.rules" in node.module:
                    self.assertEqual(node.module, "sentinelai.diagnostic.rules.params", f)
            self.assertNotIn('"FZ-INTENSITY"', src.replace("FZ-INTENSITY, FZ-PI5 pending", ""))
            self.assertNotIn('"FZ-PI5"', src)
            self.assertNotIn("netem", src)

    def test_no_protected_name_in_any_plan_or_argv(self):
        everything = repr(L.cgroup_plan() + L.lab_plan() + L.netns_del_plan() +
                          [L.forward_argv(ns, 1) for ns in L.LAB_NETNS] +
                          list(L.echo_argvs().values()) + [L.workload_argv("CTRL-s900001", WORKLOAD),
                                                           L.dependency_argv("CTRL-s900001", WORKLOAD),
                                                           L.loadgen_argv(WORKLOAD, 1, 900001, "/o")])
        for p in L.PROTECTED + ("'tc'", "sysctl", "iptables", "nft", "modprobe", "smp_affinity", "rps_cpus"):
            self.assertNotIn(p, everything)


if __name__ == "__main__":
    unittest.main()
