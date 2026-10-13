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
import subprocess
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
REAL_PI_CHECKS, REAL_REPLAY = P.pi_checks, P.replay      # the CTRL fixture mocks both
REAL_SNAPSHOT, REAL_COMPARE = L.host_snapshot, L.compare_host   # Sandboxed replaces both
REAL_APPROVED = P.approved_value                                 # the CTRL fixture replaces it
_RECORD = json.loads((ROOT / "docs/PHASE_1C_FREEZE1_DECISIONS.json").read_text())["decisions"]
WORKLOAD = _RECORD["FZ-WORKLOAD"]["value"]
WORKSET = _RECORD["FZ-WORKSET"]["value"]["values"]
ARRIVALS = _RECORD["FZ-ARRIVALS"]["value"]
LOAD_S = 15 + 45 + 90 + 20                                        # pilot WARMUP_S + B_S + W_S + COOLDOWN_S


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
        self.run = {}                      # path under a lab scratch root -> ("dir"|"file", uid, bytes)
        self.procs = {}                    # pid -> cgroup path
        self.tweak = {}                    # probe key -> forced answer
        self.r_stats = {L.IF_RA: [0, 0, 0, 0], L.IF_RB: [0, 0, 0, 0]}   # rx, tx, rx_dropped, tx_dropped
        self.tcp = [0, 0, 0]              # OutSegs, InSegs, RetransSegs
        self.snmp_pid = None
        self.mounts = [dict(m) for m in BOOT_MOUNTS]   # /proc/self/mountinfo, in order
        self.next_mount_id = 1600
        self.mountinfo_ok = True
        self.on_umount = None              # called before the simulated umount2 (concurrent changes)
        self.qd = {L.IF_A: [], L.IF_RB: []}  # tc state: qdiscs added by the run (veth default: noqueue)
        self.ppid = {}                       # pid -> parent pid (/proc/<pid>/stat)
        self.sizes = {}                      # scratch file -> size in bytes (the OV-5 file is never materialised)
        self.resident = lambda path, pages: pages   # page-cache residency of a scratch file (mincore)
        self.police_text = ""

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
        if path.startswith("/proc/") and path.endswith("/stat") and path.count("/") == 3:
            pid = int(path.split("/")[2])
            return f"{pid} (python3) S {self.ppid.get(pid, 1)} 0 0\n" if pid in self.procs else None
        if path.endswith("/net/snmp"):
            o, i, r = self.tcp
            return ("Ip: Forwarding InReceives OutRequests\nIp: 2 %d %d\n" % (i, o + r) +   # packets: segs + retrans
                    "Tcp: RtoAlgorithm OutSegs InSegs RetransSegs\nTcp: 1 %d %d %d\n" % (o, i, r))
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
        return SimpleNamespace(st_mode=(stat.S_IFDIR if e[0] == "dir" else stat.S_IFREG) | 0o700, st_uid=e[1],
                               st_size=self.sizes.get(str(path), len(e[2])))

    def residency(self, path):
        self._run_lab_path(path)
        if str(path) not in self.run:
            return None
        size = self.sizes.get(str(path), len(self.run[str(path)][2]))
        pages = (size + 4095) // 4096
        return {"size": size, "pages": pages, "resident": self.resident(str(path), pages)}

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
                                   **{f"ping_{s}": a for s, a in L.PING.items()},
                                   **{f"tc_{k}": a for k, a in L.TC_READS.items()}}.items() if v == argv))
        if key in self.tweak:
            return self.tweak[key]
        if not self.lab_built():
            return (1, "", "Cannot open network namespace")
        if key.startswith("tc_"):                              # tc as iproute2 renders it (text and -j)
            k = key[3:]
            if k == "a_ingress_filter":
                return (0, self.police_text, "")
            qs = self.qd[L.IF_A if k.startswith("a_") else L.IF_RB] or \
                [{"kind": "noqueue", "root": True, "drops": 0, "text": "qdisc noqueue 0: root refcnt 2"}]
            if k.endswith("_json"):
                return (0, json.dumps([{"kind": q["kind"], "root": q.get("root", False), "drops": q["drops"]}
                                       for q in qs]), "")
            return (0, "\n".join(q["text"] for q in qs) + "\n", "")
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
                    st = {"rx": {"packets": rx, "bytes": 100 * rx, "dropped": rd, "errors": 0},
                          "tx": {"packets": tx, "bytes": 100 * tx, "dropped": td, "errors": 0}}
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


def iperf_doc(sender=True, packets=80000 * 95, seconds=95.0, lost=0, error=None):
    """An iperf3 3.9 -J UDP report (client: sender True; one-off server: sender False)."""
    if error:
        return json.dumps({"start": {}, "intervals": [], "end": {}, "error": error}).encode()
    local, remote = (L.IP_A, L.IP_B) if sender else (L.IP_B, L.IP_A)
    s = {"start": 0, "end": seconds, "seconds": seconds, "bytes": packets * 64 if sender else 0, "jitter_ms": 0.01,
         "lost_packets": lost, "packets": packets, "lost_percent": 100.0 * lost / packets if packets else 0,
         "sender": sender}
    return json.dumps({"start": {"connected": [{"socket": 5, "local_host": local, "local_port": 40000,
                                                "remote_host": remote, "remote_port": L.FLOOD_PORT}]},
                       "intervals": [], "end": {"streams": [{"udp": s}], "sum": s}}).encode()


PI_CHECKS = P.pi_checks                                                  # the real one (fixtures replace it)


class FakeReadServer:
    """The real read_server loop on a thread over pipes; only entering A's netns view is simulated."""

    def __init__(self, view=None, enter=lambda ns: None):
        import threading
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        self.stdin, self.stdout = os.fdopen(w1, "w"), os.fdopen(r2, "r")
        self._r, self._w = os.fdopen(r1, "r"), os.fdopen(w2, "w")
        self.pid, self.rc = 4141, None
        self.view = view or {"ino": 7, "self_ino": 7, "ifs": ["lo", L.IF_A]}
        self.t = threading.Thread(target=self._serve, args=(enter,), daemon=True)
        self.t.start()

    def _serve(self, enter):
        try:
            self.rc = P.read_server(L.NS_A, self._r, self._w, enter=enter, view=self.view)
        finally:
            self._w.close()
            self._r.close()

    def wait(self, timeout=None):
        self.t.join(timeout)
        self.stdout.close()
        return self.rc

    def kill(self):
        pass


def fake_read_server(argv, stderr):
    assert argv == P.read_server_argv()
    return FakeReadServer()


class FakeProc:
    _next = 4242

    def __init__(self, rc=0, on_wait=None):
        self.pid, self.rc, self.on_wait, self.waited = FakeProc._next, rc, on_wait, False
        FakeProc._next += 1

    def poll(self):                                    # like Popen: the exit code once it has been reaped
        return self.rc if self.waited else None

    def wait(self, timeout=None):
        if self.on_wait:
            self.on_wait()
        self.waited = True
        return self.rc

    def kill(self):
        self.waited = True


class SimHost(L.Host):
    """Real plan check and op log; the effect is simulated on FakeSys. fail(op) -> True raises OSError there."""

    def __init__(self, plan, oplog, sysr, fail=None, spawn=None, fail_after_mount=False, workload_files=None,
                 on_control=None, flood=None, flood_cpus="22"):
        super().__init__(plan, oplog, sysr)
        self.on_control = on_control                   # the workload's reaction to a replaced control file
        self.flood = flood if flood is not None else {"flood_client": iperf_doc(), "flood_server": iperf_doc(False),
                                                      "bulk_client": iperf_doc()}
        self.flood_cpus = flood_cpus                   # the flood client's Cpus_allowed_list
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
            if op[1].startswith(L.SCRATCH_ROOTS):
                s.run[op[1]] = ("dir", 0, b"")
            else:
                assert op[1] not in s.dirs
                s.dirs.add(op[1])
        elif kind == "rmdir":
            if op[1].startswith(L.SCRATCH_ROOTS):
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
        elif kind == "tc":                                  # the kernel's view after the real tc command
            argv = op[1]
            dev = argv[argv.index("dev") + 1]
            if argv[3] == "qdisc" and "ingress" in argv:
                s.qd[dev].append({"kind": "ingress", "root": False, "drops": 0, "text": "qdisc ingress ffff: parent ffff:fff1"})
            elif argv[3] == "qdisc" and "netem" in argv:
                rest = list(argv[argv.index("netem") + 1:])
                if "rate" in rest:
                    rest[rest.index("rate") + 1] = rest[rest.index("rate") + 1].replace("kbit", "Kbit")
                s.qd[dev].append({"kind": "netem", "root": True, "drops": 0,
                                  "text": "qdisc netem 8001: root refcnt 2 limit 1000 " + " ".join(
                                      t for t in rest if t != "limit" and not (rest.index(t) > 0 and
                                                                             rest[rest.index(t) - 1] == "limit"))})
            elif argv[3] == "filter":
                k = argv[argv.index("rate") + 1].replace("kbit", "Kbit")
                s.police_text = (f"filter parent ffff: protocol all pref 49152 matchall chain 0\n  action order 1:  "
                                 f"police 0x1 rate {k} burst 3000b mtu 2Kb action drop overhead 0b\n")
        elif kind == "replace_control":
            s.run[f"{L.run_dir(self.plan.run_id)}/control.json"] = ("file", 0, op[1])
            if self.on_control:
                self.on_control(json.loads(op[1]), s, L.run_dir(self.plan.run_id))
        elif kind == "umount_netns_dir":
            L.umount_owned_netns_dir(s, op[1], s.umount)      # the real checks; only umount2 is simulated
        elif kind == "spawn":
            role = op[1]
            p = (self.spawn.get(role) or (lambda: FakeProc()))()
            leaf = {"echo_server": "support", "echo_client": "target", "workload": "target",
                    "dependency": "support", "loadgen": "support", "contender": "contender",
                    "flood_server": "support", "flood_client": "support", "ov5_writer": "target",
                    "bulk_client": "support", "stress": "support"}[role]
            if role in ("echo_server", "dependency", "loadgen", "workload", "contender", "flood_server", "flood_client",
                        "bulk_client", "stress"):
                s.procs[p.pid] = f"/{L.LAB}/{leaf}"
            if role == "ov5_writer":                          # written in full, fsynced, exited (never in the leaf)
                path, mib = op[2][-2], int(op[2][-1])
                s.run[path], s.sizes[path] = ("file", L.LAB_UID, b""), mib << 20
            if role == "stress":                              # taskset sets the CPU, then execs the busy loop
                i = op[2].index(L.TASKSET)
                s.files[f"/proc/{p.pid}/cmdline"] = "\0".join(op[2][i + 3:]) + "\0"
                s.files[f"/proc/{p.pid}/status"] = f"Name:\tpython3\nCpus_allowed_list:\t{op[2][i + 2]}\n"
            if role.startswith("flood_") or role == "bulk_client":   # iperf3: argv, affinity and JSON report
                prog = list(op[2][op[2].index(L.IPERF3):])
                s.files[f"/proc/{p.pid}/cmdline"] = "\0".join(prog) + "\0"
                s.files[f"/proc/{p.pid}/status"] = f"Name:\tiperf3\nCpus_allowed_list:\t" \
                    f"{self.flood_cpus if role == 'flood_client' else '23'}\n"
                if role in self.flood and stdout not in (None, subprocess.DEVNULL):
                    stdout.write(self.flood[role])
                    stdout.flush()
            if role == "dependency":
                s.run[f"{L.run_dir(self.plan.run_id)}/dependency_config.json"] = ("file", L.LAB_UID, b"{}")
            if role == "workload":                            # --metrics off: the workload publishes no metrics.json
                for n in ("config.json",) if "--metrics" in op[2] else ("metrics.json", "config.json"):
                    s.run[f"{L.run_dir(self.plan.run_id)}/{n}"] = ("file", L.LAB_UID, self.workload_files.get(n, b"{}"))
                if "--ws-file" in op[2]:                      # the workload creates its working-set file and
                    s.run[op[2][op[2].index("--ws-file") + 1]] = ("file", L.LAB_UID, b"")   # forks its scanner
                    child = p.pid + 500000
                    s.procs[child], s.ppid[child] = f"/{L.LAB}/target", p.pid
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

    def test_metrics_writer_off_only_appends_the_switch(self):
        on, off = L.workload_argv("INSTOFF-s900006", WORKLOAD), L.workload_argv("INSTOFF-s900006", WORKLOAD, False)
        self.assertEqual(on, L.workload_argv("INSTOFF-s900006", WORKLOAD, True))
        self.assertEqual(off, on + ["--metrics", "off"])
        self.assertNotIn("--metrics", on)

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
class TestWorkingSetScratch(Sandboxed):
    """FZ-WORKSET scratch: /var/tmp/sentinelai-lab/<run_id>/ws.bin, created, owned, removed and checked like the run
    directory, and nothing else under /var/tmp is ever touched."""

    def test_plan_and_guard(self):
        plan = L.app_plan("CTRL-s900010")
        w = L.ws_dir("CTRL-s900010")
        self.assertEqual(plan[-3:], [("mkdir", L.WS_ROOT), ("mkdir", w), ("chown_lab", w)])
        g = L.Plan("CTRL-s900010")
        for op in plan + [("unlink_run", f"{w}/{L.WS_FILE}"), ("rmdir", w), ("rmdir", L.WS_ROOT)]:
            self.assertEqual(g.check(op), op)
        for bad in (("mkdir", "/var/tmp/x"), ("mkdir", f"{L.WS_ROOT}/CTRL-s900011"), ("chown_lab", L.WS_ROOT),
                    ("chown_lab", "/var/tmp"), ("unlink_run", f"{w}/other.bin"), ("unlink_run", f"{L.WS_ROOT}/ws.bin"),
                    ("unlink_run", f"{L.ws_dir('CTRL-s900011')}/{L.WS_FILE}"), ("rmdir", "/var/tmp")):
            with self.subTest(bad), self.assertRaises(L.LabRefused):
                g.check(bad)
        for bad in ("/var/tmp/sentinelai-labX", "/var/tmp/sentinelai-lab/../x", "/var/tmp", "/etc/passwd"):
            with self.subTest(bad), self.assertRaises(L.LabRefused):
                L.Sys._run_lab_path(bad)
        self.assertEqual(L.Sys._run_lab_path(f"{w}/{L.WS_FILE}"), f"{w}/{L.WS_FILE}")

    def test_workload_argv_carries_the_approved_values(self):
        argv = L.workload_argv("CTRL-s900010", WORKLOAD, True, WORKSET)
        tail = argv[argv.index("--ws-file"):]
        self.assertEqual(tail, ["--ws-file", f"{L.WS_ROOT}/CTRL-s900010/ws.bin", "--ws-file-mib", "1024",
                                "--ws-anon-mib", "16", "--ws-pass-s", "1.0", "--ws-slices", "10"])
        self.assertNotIn("--ws-file", L.workload_argv("CTRL-s900010", WORKLOAD))

    def test_cleanup_removes_the_working_set_and_keeps_anything_else(self):
        s, hosts = FakeSys(), []
        h = SimHost(L.Plan("CTRL-s900010"), str(self.tmp / "ops.jsonl"), s)
        for op in L.app_plan("CTRL-s900010"):
            h.apply(op)
        w = L.ws_dir("CTRL-s900010")
        s.run[f"{w}/{L.WS_FILE}"] = ("file", L.LAB_UID, b"")
        res = L.cleanup(h, s, L.read_oplog(h.oplog), "CTRL-s900010")
        self.assertTrue(res["ok"], res)
        self.assertEqual(s.run, {})
        self.assertIn(("unlink_run", f"{w}/{L.WS_FILE}"), h.ops)
        s, h = FakeSys(), SimHost(L.Plan("CTRL-s900010"), str(self.tmp / "ops2.jsonl"), FakeSys())
        h.sys = s
        for op in L.app_plan("CTRL-s900010"):
            h.apply(op)
        s.run[f"{w}/evil.sh"] = ("file", L.LAB_UID, b"")
        res = L.cleanup(h, s, L.read_oplog(h.oplog), "CTRL-s900010")
        self.assertFalse(res["ok"])
        self.assertIn(f"{w}/evil.sh", s.run)
        self.assertFalse(res["verify"]["checks"]["ws_scratch_absent"])

    def test_leftover_scratch_refuses_and_fails_the_host_comparison(self):
        s = FakeSys()
        with mock.patch.object(L.E, "host_snapshot", side_effect=lambda *a, **k: {}), \
                mock.patch.object(L.E, "compare_host", lambda b, o, r=True: {"failed": [], "ok": True}):
            base = REAL_SNAPSHOT(s)
            s.run[L.WS_ROOT] = ("dir", 0, b"")                           # pre-existing: never ours
            after = REAL_SNAPSHOT(s)
            self.assertEqual((base["ws_scratch_present"], after["ws_scratch_present"]), (False, True))
            self.assertIn("ws_scratch_absent", REAL_COMPARE(base, after)["failed"])
            self.assertTrue(REAL_COMPARE(base, base)["ok"])
        self.assertFalse(L.preflight(s)["checks"]["ws_scratch_absent"])
        h = SimHost(L.Plan("CTRL-s900010"), str(self.tmp / "ops.jsonl"), s)
        L.cleanup(h, s, [], "CTRL-s900010")
        self.assertIn(L.WS_ROOT, s.run)                                  # not created by this invocation: kept


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
        order, before = [], len(h.ops)
        res = L.cleanup(h, s, L.read_oplog(h.oplog), run_id, after_procs=lambda: order.append("after"))
        self.assertTrue(res["ok"], res)
        self.assertTrue(empty(s))
        kinds = [op[0] if op[0] != "cmd" else op[1][1:3] for op in h.ops[before:]]
        self.assertEqual(kinds[0], "write")                          # cgroup.kill first
        self.assertEqual(order, ["after"])
        rm = [op[1] for op in h.ops if op[0] == "rmdir"]
        self.assertEqual(rm, [L.run_dir(run_id), L.APP_ROOT.rstrip("/"), L.RUN_LAB, L.ws_dir(run_id), L.WS_ROOT,
                              L.SUPPORT_DIR, L.CONTENDER_DIR, L.TARGET_DIR, L.LAB_DIR])
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
def metrics_doc(completed=0, rejected=0, failed=0, busy=0, sha="0" * 64, lock_waits=0, extra=()):
    m = W.Metrics()
    for hist, ms, count in extra:                      # W-window observations: (histogram, value ms, count)
        for _ in range(count):
            m.observe(hist, ms)
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
        self.n = P.scheduled_arrivals(WORKLOAD, LOAD_S, 900001, ARRIVALS)   # set per run from its seed
        self.docs = []
        self.workload = WORKLOAD                     # run.json workload (the approved FZ-WORKLOAD value)
        self.config = None                           # config.json bytes; None: the echo of self.workload
        self.doc_sha = None                          # config_sha256 in the metrics documents; None: the echo's
        self.lock_waits = 0                          # lock-wait observations in the end metrics document
        self.snap = app_snapshot()                   # the run's canonical snapshot (live and replay)
        self.reads, self.live_sha, self.w_extra = 0, None, ()   # metrics reads; hash after a fault; W observations
        self.echo = True                             # the simulated workload echoes a replaced control file
        self.effect = None                           # fn(FakeSys): the kernel-side effect of a fault during W
        target = Target(name="faultlab-ctrl", cgroup_path=L.TARGET_CGROUP_PATH, pids=(1,), cpuset="18",
                        netns_ref="pid:1", ifaces=())

        def resolve(reader, name, path, ifaces=()):        # like collectors.resolve_target: every pid, sorted
            pids = tuple(sorted(p for p, cg in self.s.procs.items() if cg == L.TARGET_CGROUP_PATH))
            return target.model_copy(update={"pids": pids, "netns_ref": f"pid:{pids[0]}", "ifaces": tuple(ifaces)})

        def read_metrics(run_id):
            try:
                sha = self.doc_sha or self.live_sha or json.loads(self.config_bytes())["config_sha256"]
            except (ValueError, KeyError, TypeError):            # a deliberately malformed echo
                sha = "0" * 64
            self.reads += 1
            if not self.docs:
                self.docs.append(metrics_doc(sha=sha))
                return self.docs[0]
            return metrics_doc(completed=self.n, sha=sha, lock_waits=self.lock_waits,
                               extra=self.w_extra if self.reads >= 3 else ())      # read 3 = the W-end document

        def loadgen():
            def finish():
                base = json.loads(self.docs[0])["mono_ns"] if self.docs else time.monotonic_ns()
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
        def collect(target, params, reader, clock, period, ebpf, app):   # drives the app source tick by tick
            self.reader = reader
            for k in range(P.B_S + P.W_S + 1):
                app.sample()
                if k == P.B_S and self.effect is not None:               # the fault acts during W
                    self.effect(self.s)
            return ["t"] * 136, stats

        class Quiet:                                                     # the per-tick app source reads nothing
            def __init__(self, run_id):
                pass

            def sample(self):
                return {}
        for p in (mock.patch.object(COL, "resolve_target", side_effect=resolve),
                  mock.patch.object(COL, "collect", side_effect=collect),
                  mock.patch.object(APP, "AppSource", Quiet),
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
        approved = mock.patch.object(P, "approved_value", side_effect=lambda name, rec=None:   # the committed record
                                     {"FZ-WORKLOAD": self.workload}.get(name, _RECORD[name]["value"]))
        approved.start()
        self.addCleanup(approved.stop)

    def config_bytes(self):
        return self.config if self.config is not None else config_echo(self.workload)

    def on_control(self, control, s, rdir):
        """The workload and dependency peer: echo the new control values like workload.Runner / dependency_loop."""
        if not self.echo:
            return
        if "dependency_delay_ms" in control:
            s.run[f"{rdir}/dependency_config.json"] = ("file", L.LAB_UID, W.canonical(
                {"seq": 2, "mono_ns": 2, "config": {"dependency_delay_ms": control["dependency_delay_ms"]},
                 "control_error": None}))
        service = {k: v for k, v in control.items() if k in W.SERVICE_CONTROL_KEYS}
        if service and any(self.workload.get(k, 0) != v for k, v in service.items()):   # distractor starts at 0
            cur = json.loads(s.run[f"{rdir}/config.json"][2])["config"]   # like Runner: the current config, changed
            cfg = dict(cur, **service)
            echo = W.canonical({"seq": 2, "mono_ns": 2, "config": cfg, "control_error": None,
                                "config_sha256": hashlib.sha256(W.canonical(cfg)).hexdigest()})
            s.run[f"{rdir}/config.json"] = ("file", L.LAB_UID, echo)
            self.live_sha = json.loads(echo)["config_sha256"]

    def run_ctrl(self, **kw):
        kw.setdefault("reader_spawn", fake_read_server)
        hosts = []
        spawn = dict(self.spawn, **kw.pop("spawn", {}))
        run = {k: kw.pop(k) for k in ("variant", "child_spawn", "fault", "reader_spawn", "scenario") if k in kw}
        kw.setdefault("workload_files", {"config.json": self.config_bytes()})
        kw.setdefault("on_control", self.on_control)
        with mock.patch.object(P.os, "chown"):
            seed = kw.pop("seed", 900001)
            self.n = P.scheduled_arrivals(WORKLOAD, LOAD_S, seed, ARRIVALS)  # Poisson: the count depends on the seed
            rc = P.ctrl(self.out, seed, COMMIT, sysr=self.s,
                        host_cls=host_factory(hosts, spawn=spawn, **kw), sleep=lambda x: None, **run)
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
        self.assertEqual(run["working_set"], WORKSET)
        tp = run["target_processes"]                                   # the workload and its scanner child (M-2)
        self.assertEqual(tp["scanner"] - tp["workload"], 500000)
        self.assertEqual((run["arrivals"], run["load"]["process"]), (ARRIVALS, "poisson"))
        lg = [op[2] for op in h.ops if op[0] == "spawn" and op[1] == "loadgen"][0]
        self.assertEqual(lg[lg.index("--arrivals") + 1:lg.index("--arrivals") + 4], ["poisson", "--rate", "100"])
        self.assertNotIn("--jitter", lg)
        self.assertEqual(run["load"]["arrivals"], self.n)
        w = L.ws_dir("CTRL-s900001")
        self.assertIn(("mkdir", w), h.ops)
        self.assertIn(("unlink_run", f"{w}/{L.WS_FILE}"), h.ops)          # created by the workload, removed
        self.assertTrue(run["cleanup"]["verify"]["checks"]["ws_scratch_absent"])
        r = json.loads((self.out / "evidence" / "counters.json").read_text())["end"]["r"]
        self.assertEqual((r[L.IF_RA]["rx_bytes"], r[L.IF_RB]["tx_bytes"]), (101000, 101000))   # D3 byte counters
        self.assertIn("rx_bytes", json.loads((self.out / "report.json").read_text())
                      ["checks"]["across_r_reconciliation"]["r"][L.IF_RA])

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


class HangingProc(FakeProc):
    """A collector child that never finishes until killed."""

    def __init__(self):
        super().__init__()
        self.killed = False

    def wait(self, timeout=None):
        if self.killed:
            return -9
        import subprocess
        raise subprocess.TimeoutExpired("collector", timeout)

    def kill(self):
        self.killed = True


class TestVariants(CtrlFixture):
    """PI-1 unprivileged (pi1u), PI-6 collectors off (pi6off) and instrumentation off (instoff) on the simulated host."""

    def go(self, variant, name=None, seed=900006, **kw):
        self.out = self.tmp / (name or f"{P.VARIANTS[variant]['prefix']}-{seed}")
        self.s, self.docs = FakeSys(), []
        rc, h = self.run_ctrl(variant=variant, seed=seed, **kw)
        return rc, h, json.loads((self.out / "report.json").read_text())

    def child(self, rc=0, write=True, link=None, target=None, proc=None):
        """A fake unprivileged collector child: writes what collect_child writes into its directory."""
        def spawn(argv, cwd, stderr):
            import sentinelai.collectors as COL
            self.child_call = (argv, cwd)
            t = COL.resolve_target(None, "faultlab-ctrl", L.TARGET_CGROUP_PATH)
            t = t.model_copy(update=target or {})
            if write:
                (cwd / P.CHILD_TICKS).write_bytes(b"CHILD-TICKS\n")
                (cwd / P.CHILD_STATS).write_bytes(P.dump({
                    "uid": 1000, "euid": 1000, "gid": 1000, "egid": 1000, "groups": [], "cap_eff": "0" * 16,
                    "netns_link": link or f"net:[{self.s.netns_inode(L.NS_A)}]", "target_doc": t.model_dump(mode="json"),
                    "ticks": 136, "wall_s": 135.0, "cpu_s": 0.3, "max_rss_kb": 1, "max_tick_read_s": 0.01}))
            return proc or FakeProc(rc=rc)
        return spawn

    def test_check_sets_are_exact_per_variant(self):
        self.assertEqual(P.pipeline_checks("ctrl"), P.PIPELINE_CHECKS)
        self.assertEqual(P.pipeline_checks("pi1u"), P.PIPELINE_CHECKS)
        base = {"run_completed", "cleanup", "host_compare", "bpf_released", "manifest", "across_r_reconciliation"}
        self.assertEqual(P.pipeline_checks("pi6off"), base | {"client_server_reconciliation"})
        self.assertEqual(P.pipeline_checks("instoff"), base | {"client_records"})
        self.assertEqual({v["prefix"] for v in P.VARIANTS.values()}, {"CTRL", "PI1U", "PI6OFF", "INSTOFF", "PI8", "M6"})
        self.assertEqual(P.pipeline_checks("pi8"), P.PIPELINE_CHECKS | {"injection_verified"})

    def test_collectors_off_runs_no_collector_and_no_loader(self):
        import m3b_r1_validate
        import sentinelai.collectors as COL
        with mock.patch.object(m3b_r1_validate, "Recording") as rec, mock.patch.object(COL, "collect") as col:
            rc, h, rep = self.go("pi6off")
        self.assertEqual(rc, 0, rep)
        rec.assert_not_called()
        col.assert_not_called()
        self.assertEqual(set(rep["checks"]), P.pipeline_checks("pi6off"))
        self.assertEqual(rep["pi"], {})
        self.assertEqual(rep["checks"]["client_server_reconciliation"]["client_outcomes"], {"200": self.n})
        for f in ("snapshot.json", "evidence/ticks.jsonl", "evidence/ebpf.jsonl"):
            self.assertFalse((self.out / f).exists(), f)
        self.assertEqual(RH.verify_manifest(self.out), [])
        run = json.loads((self.out / "evidence" / "run.json").read_text())
        self.assertEqual((run["run_id"], run["collector_mode"], run["ebpf"], run["metrics_writer"]),
                         ("PI6OFF-s900006", None, False, True))
        self.assertTrue(run["bpf_release"]["released"] and run["cleanup"]["ok"] and run["host_compare"]["ok"])
        self.assertTrue(empty(self.s))

    def test_instrumentation_off_runs_without_the_metrics_writer(self):
        import sentinelai.collectors.app as APP
        with mock.patch.object(APP, "read_metrics") as rm:
            rc, h, rep = self.go("instoff")
        self.assertEqual(rc, 0, rep)
        rm.assert_not_called()                                         # nothing reads a metrics document
        wl = [op[2] for op in h.ops if op[0] == "spawn" and op[1] == "workload"][0]
        self.assertEqual(wl[wl.index("--metrics") + 1], "off")
        self.assertEqual(wl[wl.index("--ws-file") + 1], f"{L.ws_dir('INSTOFF-s900006')}/{L.WS_FILE}")
        self.assertEqual(set(rep["checks"]), P.pipeline_checks("instoff"))
        self.assertEqual(rep["checks"]["client_records"]["client_outcomes"], {"200": self.n})
        self.assertFalse((self.out / "evidence" / "app_start.json").exists())
        self.assertTrue((self.out / "evidence" / "config.json").exists())
        self.assertIn("not observable", json.loads((self.out / "evidence" / "run.json").read_text())["drain"])
        self.assertTrue(empty(self.s))

    def test_client_records_alone_must_be_complete_and_answered(self):
        run = {"load": {"arrivals": 3}}
        rec = lambda k, o="200": {"k": k, "outcome": o, "sent_ns": 1, "latency_ms": 1.0}
        self.assertEqual(P.client_records(run, [rec(0), rec(1), rec(2, "503")])[1], [])
        for name, recs, needle in (("missing", [rec(0), rec(2)], "exactly once"),
                                   ("duplicate", [rec(0), rec(1), rec(1)], "exactly once"),
                                   ("client timeout", [rec(0), rec(1), rec(2, "client_timeout")], "without a server"),
                                   ("saturated", [rec(0), rec(1), rec(2, "client_saturated")], "without a server"),
                                   ("no latency", [rec(0), rec(1), dict(rec(2), latency_ms=None)], "no send time")):
            with self.subTest(name):
                self.assertTrue(any(needle in p for p in P.client_records(run, recs)[1]))

    def test_unprivileged_collector_child_does_the_collection(self):
        import m3b_r1_validate
        import sentinelai.collectors as COL
        with mock.patch.object(m3b_r1_validate, "Recording") as rec, mock.patch.object(COL, "collect") as col, \
                mock.patch.object(COL, "build_snapshot", return_value="snap") as bs:
            rc, h, rep = self.go("pi1u", child_spawn=self.child())
        self.assertEqual(rc, 0, rep)
        rec.assert_not_called()                                        # no eBPF loader in unprivileged mode
        col.assert_not_called()                                        # the root driver collects nothing itself
        self.assertIs(bs.call_args.args[4], False)                    # snapshot built without eBPF
        argv, cwd = self.child_call
        self.assertEqual(argv, P.collector_argv("PI1U-s900006", self.out / "collector"))
        self.assertEqual(cwd, self.out / "collector")
        self.assertEqual((self.out / "evidence" / "ticks.jsonl").read_bytes(), b"CHILD-TICKS\n")
        self.assertTrue((self.out / "evidence" / "collector_stats.json").exists())
        run = json.loads((self.out / "evidence" / "run.json").read_text())
        self.assertEqual(run["unprivileged"]["netns_verified"], True)
        self.assertEqual((run["unprivileged"]["uid"], run["unprivileged"]["cap_eff"]), (1000, "0" * 16))
        self.assertEqual((run["collection"]["cpu_s"], run["collection"]["loader_cpu_s"]), (0.3, 0.0))
        self.assertEqual(run["exit_codes"]["collector"], 0)
        self.assertEqual(set(rep["checks"]), P.PIPELINE_CHECKS)
        self.assertTrue(rep["pipeline_ok"], rep["checks"])
        self.assertTrue(empty(self.s))

    def test_unprivileged_child_failures_abort_and_clean_up(self):
        hang = HangingProc()
        for name, kw, needle in (("child exits 3", {"rc": 3}, "exited with 3"),
                                 ("child wrote nothing", {"write": False}, "FileNotFoundError"),
                                 ("another target", {"target": {"cpuset": "19"}}, "different target"),
                                 ("child hangs", {"proc": hang}, "did not finish")):
            with self.subTest(name):
                rc, h, rep = self.go("pi1u", name=f"PI1U-90{len(list(self.tmp.iterdir())):04d}",
                                     child_spawn=self.child(**kw))
                run = json.loads((self.out / "evidence" / "run.json").read_text())
                self.assertEqual(rc, 1)
                self.assertTrue(any(needle in a for a in run["aborts"]), run["aborts"])
                self.assertTrue(run["cleanup"]["ok"] and run["host_compare"]["ok"])
                self.assertFalse((self.out / "manifest.json").exists())
                self.assertTrue(empty(self.s))
        self.assertTrue(hang.killed)                                   # the hanging child was killed at release

    def test_pi1_unprivileged_needs_a_verified_netns(self):
        ms = [{"feature_id": "tcp.retrans_rate", "aggregation": "RATE", "coverage": 1.0, "quality": "OK"},
              {"feature_id": "app.latency_ms", "aggregation": "P99", "coverage": 1.0, "quality": "OK"}]
        snap = {"measurements": ms, "missing_measurements": []}
        ticks = [SimpleNamespace(obs={"app": {}})] * 10
        run = lambda ok: {"collection": {"cpu_s": 0.2, "loader_cpu_s": 0.0, "wall_s": 135.0},
                          "collector_mode": "unprivileged",
                          "unprivileged": {"netns_verified": ok, "netns_link": "net:[1]", "uid": 1000,
                                           "cap_eff": "0" * 16}}
        good, bad = REAL_PI_CHECKS(run(True), snap, ticks)["PI-1"], REAL_PI_CHECKS(run(False), snap, ticks)["PI-1"]
        self.assertEqual((good["mode"], good["ok"], good["netns_verified"]), ("unprivileged", True, True))
        self.assertEqual((bad["ok"], bad["netns_verified"]), (False, False))
        self.assertEqual(REAL_PI_CHECKS({"collection": run(True)["collection"]}, snap, ticks)["PI-1"]["mode"],
                         "driver-root")

    def test_collector_child_is_started_without_privileges(self):
        argv = P.collector_argv("PI1U-s900008", Path("/x/collector"))
        self.assertEqual(argv[1:4], ["-I", str(ROOT / "experiments/faultlab/pilot.py"), "collect-child"])
        with mock.patch.object(P.subprocess, "Popen") as po:
            P.spawn_collector(argv, Path("/x/collector"), None)
        kw = po.call_args.kwargs
        self.assertEqual((kw["user"], kw["group"], kw["extra_groups"], kw["shell"]), (1000, 1000, [], False))
        self.assertEqual(kw["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})

    def test_collect_child_refuses_any_privilege(self):
        import sentinelai.collectors as COL
        lab = "CapEff:\t0000000000000000\n"
        for name, ids, status in (("root", (0, 0, 0, 0), lab), ("setuid", (1000, 0, 1000, 1000), lab),
                                  ("capabilities", (1000, 1000, 1000, 1000), "CapEff:\t0000003fffffffff\n")):
            with self.subTest(name), mock.patch.object(P.os, "getuid", return_value=ids[0]), \
                    mock.patch.object(P.os, "geteuid", return_value=ids[1]), \
                    mock.patch.object(P.os, "getgid", return_value=ids[2]), \
                    mock.patch.object(P.os, "getegid", return_value=ids[3]), \
                    mock.patch.object(P.os, "getgroups", return_value=[]), \
                    mock.patch("pathlib.Path.read_text", return_value=status), \
                    mock.patch.object(COL, "collect") as col:
                self.assertEqual(P.collect_child("PI1U-s900008", self.tmp), 3)
                col.assert_not_called()
        self.assertFalse((self.tmp / P.CHILD_TICKS).exists())
        for bad in ("CTRL-s900008", "PI1U-x", "../PI1U-s1"):
            with self.subTest(bad), self.assertRaises(P.Refused):
                P.main(["collect-child", "--run-id", bad, "--out-dir", str(self.tmp)])

    def test_pairs_compare_on_and_off_runs_of_the_same_seed(self):
        for variant in ("ctrl", "pi6off", "instoff"):
            self.go(variant, seed=900006)
        rep = P.pairs(self.tmp)
        (p6,), (pi,) = rep["pi6_pairs"], rep["instrumentation_pairs"]
        self.assertEqual((p6["on"], p6["off"], p6["ok"]), ("CTRL-900006", "PI6OFF-900006", True), p6)
        self.assertEqual((pi["on"], pi["off"], pi["ok"]), ("PI6OFF-900006", "INSTOFF-900006", True), pi)
        self.assertEqual(p6["on_client"]["ok_200"], self.n)
        self.assertEqual(set(p6["diff"]), {"p50_ms", "p99_ms", "throughput_per_s"})
        self.go("pi6off", seed=900007)                                 # no CTRL partner
        f = self.tmp / "INSTOFF-900006" / "evidence" / "client.jsonl"   # a member that no longer verifies
        f.write_text(f.read_text().replace('"200"', '"503"', 1))
        rep = P.pairs(self.tmp)
        lone = [p for p in rep["pi6_pairs"] if p["seed"] == 900007][0]
        self.assertEqual((lone["ok"], lone["problems"]), (False, ["CTRL-900007 missing"]))
        self.assertIn("off run does not pass its own evaluation", rep["instrumentation_pairs"][0]["problems"])
        with mock.patch("builtins.print"):
            self.assertEqual(P.main(["pairs", str(self.tmp)]), 1)

    def test_replay_uses_the_recorded_ebpf_flag(self):
        import sentinelai.collectors as COL
        self.go("pi1u", child_spawn=self.child())
        with mock.patch.object(COL, "build_snapshot", return_value="snap") as bs:
            REAL_REPLAY(self.out)
        self.assertIs(bs.call_args.args[4], False)


APP = json.loads((ROOT / "docs/PHASE_1C_FREEZE1_DECISIONS.json").read_text())["decisions"]["FZ-INTENSITY-APP"]["value"]


class TestFaults(CtrlFixture):
    """PI-8 application faults (pi8) on the simulated host: AMD-10 timing, read-back, W-window effects, failures."""

    def go(self, fault=None, magnitude=None, seed=900020, variant="pi8", **kw):
        self.out = self.tmp / f"{P.VARIANTS[variant]['prefix']}-{seed}"
        self.s, self.docs, self.reads, self.live_sha = FakeSys(), [], 0, None
        rc, h = self.run_ctrl(variant=variant, seed=seed,
                              fault=(fault, magnitude) if fault else None, **kw)
        return rc, h, json.loads((self.out / "report.json").read_text())

    def test_pool_fault_is_issued_at_the_boundary_and_read_back(self):
        self.w_extra = (("queue_wait", 3.0, 200),)
        rc, h, rep = self.go("app_pool", 1)
        self.assertEqual(rc, 0, rep["checks"])
        run = json.loads((self.out / "evidence" / "run.json").read_text())
        inj = run["injection"]
        self.assertTrue(inj["issued"] and inj["verified"], inj)
        self.assertEqual(inj["issue_after_tick"], P.B_S)                    # after tick nB (run time 60 s)
        self.assertLessEqual(inj["readback_latency_s"], P.T_CAP_S)
        self.assertIn(("replace_control", b'{"dependency_delay_ms": 2, "pool": 1}'), h.ops)
        self.assertTrue(rep["checks"]["injection_verified"]["ok"])
        self.assertEqual(rep["w_effects"]["queue_wait"]["p99_ms"], 3.2)
        self.assertEqual(set(rep["checks"]), P.pipeline_checks("pi8"))
        basis = rep["checks"]["app_features"]["structurally_unavailable"]
        self.assertTrue(basis["applied"], basis)                            # pool fault leaves lock_hold at 0
        events = [e["event"] for e in run["events"]]
        self.assertLess(events.index("collect_start"), events.index("fault_issued"))
        self.assertTrue((self.out / "evidence" / "app_w_start.json").exists())
        self.assertTrue(empty(self.s))

    def test_dependency_delay_is_read_back_from_the_dependency_echo(self):
        self.w_extra = (("dependency_latency", 12.0, 200),)
        rc, h, rep = self.go("app_dependency_delay", 15)
        self.assertEqual(rc, 0, rep["checks"])
        self.assertEqual(rep["w_effects"]["dependency_latency"]["p99_ms"], 12.8)
        self.assertTrue(rep["checks"]["app_features"]["structurally_unavailable"]["applied"])   # seq stays 1

    def test_lock_fault_needs_the_lock_wait_measured(self):
        self.w_extra = (("lock_wait", 0.5, 200),)
        self.snap = app_snapshot(lock="OK")
        self.lock_waits = 5
        rc, h, rep = self.go("app_lock", 1000)
        self.assertEqual(rc, 0, rep["checks"])
        basis = rep["checks"]["app_features"]["structurally_unavailable"]
        self.assertFalse(basis["applied"])                                  # a lock fault never qualifies
        self.assertIn("the run's fault changes lock_hold_us", basis["not_applied_because"])
        self.snap = app_snapshot()                                          # lock wait MISSING in a lock fault rep
        rc, h, rep = self.go("app_lock", 1000, seed=900021)
        self.assertEqual(rc, 1)
        self.assertFalse(rep["checks"]["app_features"]["ok"])

    def test_missing_read_back_is_a_failed_injection(self):
        self.echo = False
        with mock.patch.object(P, "T_CAP_S", 0.2):
            rc, h, rep = self.go("app_pool", 2)
        self.assertEqual(rc, 1)
        c = rep["checks"]["injection_verified"]
        self.assertEqual((c["ok"], c["label"]), (False, "failed_injection"))
        self.assertTrue(rep["checks"]["cleanup"]["ok"] and rep["checks"]["host_compare"]["ok"])
        self.assertTrue(empty(self.s))

    def test_issue_error_is_a_failed_injection_and_the_run_still_cleans_up(self):
        rc, h, rep = self.go("app_pool", 2, fail=lambda op: op[0] == "replace_control")
        self.assertEqual(rc, 1)
        self.assertIn("not issued", rep["checks"]["injection_verified"]["problems"][0])
        self.assertTrue(rep["checks"]["cleanup"]["ok"])
        self.assertTrue(empty(self.s))

    def test_only_approved_faults_and_magnitudes(self):
        for fault, mag in (("app_pool", 4), ("app_pool", 0), ("app_lock", 6000), ("app_lock", 1500),
                           ("app_dependency_delay", 16), ("app_dependency_delay", 2), ("cpu_quota", 1),
                           ("netem_loss_a_egress", 3), ("cpu_contender", 800), ("netem_rate_r", 100),
                           ("memory_max", 300), ("memory_max", 128), ("app_lock", 1000.0), ("app_lock", True)):
            with self.subTest((fault, mag)), self.assertRaises(P.Refused):
                P.fault_spec(fault, mag, WORKLOAD)
        self.assertTrue(all(max(APP[k]) <= APP[c] for k, c in (("lock_hold_us_candidates", "lock_hold_us_max"),
                                                               ("dependency_delay_ms_candidates",
                                                                "dependency_delay_ms_max"))))
        for variant, fault in (("pi8", None), ("ctrl", ("app_pool", 1))):
            with self.subTest(variant), self.assertRaises(P.Refused):
                self.go(fault[0] if fault else None, fault[1] if fault else None, variant=variant)

    def test_ctrl_runs_record_w_window_effects_without_a_fault(self):
        self.w_extra = (("queue_wait", 0.04, 200),)
        rc, h, rep = self.go(variant="ctrl", seed=900030)
        self.assertEqual(rc, 0, rep["checks"])
        self.assertIsNone(rep["fault"])
        self.assertEqual(rep["w_effects"]["queue_wait"]["p99_ms"], 0.05)
        self.assertFalse(any(op[0] == "replace_control" for op in h.ops))

    def test_levels_apply_the_pi8_rule(self):
        self.w_extra = (("queue_wait", 0.04, 200),)
        self.go(variant="ctrl", seed=900030)
        self.go(variant="ctrl", seed=900031)
        seed = 900040
        for mag, eff in ((3, 0.04), (3, 0.04), (2, 3.0), (2, 3.0), (1, 6.0), (1, 6.0)):
            self.w_extra = (("queue_wait", eff, 200),)
            self.go("app_pool", mag, seed=seed)
            seed += 1
        rep = P.levels(self.tmp)
        self.assertEqual(rep["ctrl_max_ms"]["queue_wait"], 0.05)
        pool = rep["faults"]["app_pool"]
        self.assertEqual(pool["order_weakest_first"], [3, 2, 1])
        self.assertEqual(pool["established_2of2"], [2, 1])                  # P'=3 shows no wait above CTRL
        self.assertEqual((pool["I1"], pool["I3"], pool["I2"], pool["I0"]), (2, 1, 2, 3))
        self.assertIsNone(pool["stopped_after"])
        self.echo = False                                                   # two consecutive failed read-backs
        with mock.patch.object(P, "T_CAP_S", 0.1):
            for k in range(2):
                self.go("app_lock", 500, seed=900050 + k)
        self.assertEqual(P.levels(self.tmp)["faults"]["app_lock"]["stopped_after"], "PI8-900051")
        with mock.patch("builtins.print"):
            self.assertEqual(P.main(["levels", str(self.tmp)]), 0)


class TestFaultRules(CtrlFixture):
    """The decision rules on their own: AMD-10 issue tick, FZ-PI7-LOCK bar, PI-8 2/2."""

    def test_injection_check_requires_the_boundary_tick_and_a_read_back(self):
        good = {"injection": {"issued": True, "issue_after_tick": P.B_S, "verified": True, "readback_latency_s": 0.1}}
        self.assertTrue(P.injection_check(good)["ok"])
        for name, change in (("late tick", {"issue_after_tick": P.B_S + 1}), ("early tick", {"issue_after_tick": 0}),
                             ("not verified", {"verified": False}), ("slow read-back", {"readback_latency_s": 31.0}),
                             ("not issued", {"issued": False})):
            with self.subTest(name):
                c = P.injection_check({"injection": dict(good["injection"], **change)})
                self.assertEqual((c["ok"], c["label"]), (False, "failed_injection"))
        self.assertFalse(P.injection_check({})["ok"])

    def go(self, fault, mag, seed, eff_ms, hist):
        self.out = self.tmp / f"PI8-{seed}"
        self.s, self.docs, self.reads, self.live_sha = FakeSys(), [], 0, None
        self.w_extra = ((hist, eff_ms, 200),)
        self.run_ctrl(variant="pi8", seed=seed, fault=(fault, mag))

    def test_a_failed_rep_is_excluded_and_its_repeat_counts(self):
        self.w_extra = (("dependency_latency", 3.0, 200),)
        self.out, self.s, self.docs, self.reads = self.tmp / "CTRL-900075", FakeSys(), [], 0
        self.run_ctrl(variant="ctrl", seed=900075)
        self.go("app_dependency_delay", 15, 900076, 12.0, "dependency_latency")
        with mock.patch.object(L, "compare_host", return_value={"ok": False, "failed": ["cgroup_dirs_identical"]}):
            self.go("app_dependency_delay", 15, 900077, 12.0, "dependency_latency")        # fails its pipeline
        d = P.levels(self.tmp)["faults"]["app_dependency_delay"]
        self.assertEqual(d["established_2of2"], [])                                       # one valid rep only
        self.go("app_dependency_delay", 15, 900078, 12.0, "dependency_latency")           # the repeat
        d = P.levels(self.tmp)["faults"]["app_dependency_delay"]
        self.assertEqual((d["established_2of2"], len(d["reps"])), ([15], 3))
        self.assertFalse([x for x in d["reps"] if x["seed"] == 900077][0]["pipeline_ok"])  # kept, labelled

    def test_lock_reps_need_more_than_the_first_bucket(self):
        self.snap, self.lock_waits = app_snapshot(lock="OK"), 5
        self.go("app_lock", 500, 900060, 0.04, "lock_wait")              # P99 0.05 ms: an uncontended acquisition
        self.go("app_lock", 500, 900061, 0.08, "lock_wait")              # P99 0.1 ms: real waiting
        rule = _RECORD["FZ-PI7-LOCK"]["value"]
        a, b = (P.rep_effect(self.tmp / f"PI8-{s}", {"lock_wait": 0.0}, rule) for s in (900060, 900061))
        self.assertEqual((a["w_p99_ms"], a["ground_truth"]), (0.05, False))
        self.assertEqual((b["w_p99_ms"], b["ground_truth"]), (0.1, True))
        self.assertEqual(a["bar_ms"], 0.05)

    def test_a_level_needs_ground_truth_in_both_reps(self):
        self.w_extra = (("dependency_latency", 3.0, 200),)
        self.out, self.s, self.docs, self.reads = self.tmp / "CTRL-900070", FakeSys(), [], 0
        self.run_ctrl(variant="ctrl", seed=900070)
        for seed, mag, eff in ((900071, 7, 6.0), (900072, 7, 3.0), (900073, 15, 12.0), (900074, 15, 12.0)):
            self.go("app_dependency_delay", mag, seed, eff, "dependency_latency")
        d = P.levels(self.tmp)["faults"]["app_dependency_delay"]
        self.assertEqual(d["established_2of2"], [15])                    # 7 ms: 1 of 2 reps above the CTRL maximum
        self.assertEqual((d["I1"], d["I3"]), (15, 15))


CPUNET = _RECORD["FZ-INTENSITY-CPUNET"]["value"]


def proc_stat(busy, idle):
    return f"cpu  1 2 3 4 5 6 7 8 9 10\ncpu{L.TARGET_CPU} {busy} 0 0 {idle} 0 0 0 0 0 0\n"


def cpu_stat(periods, throttled, usage):
    return f"usage_usec {usage}\nuser_usec 0\nsystem_usec 0\nnr_periods {periods}\nnr_throttled {throttled}\n"


class OpFaultFixture(CtrlFixture):
    """A simulated host with CPU / network / memory kernel sources (no tests here)."""

    def setUp(self):
        super().setUp()
        self.base = lambda s: s.files.update({"/proc/stat": proc_stat(1000, 9000),
                                              f"{L.TARGET_DIR}/cpu.stat": cpu_stat(0, 0, 0)})

    def go(self, fault, mag, seed, effect=None, variant="pi8", tweak=None, **kw):
        self.out = self.tmp / f"{P.VARIANTS[variant]['prefix']}-{seed}"
        self.s, self.docs, self.reads, self.live_sha = FakeSys(), [], 0, None
        self.s.tweak.update(tweak or {})
        self.base(self.s)
        self.effect = effect
        rc, h = self.run_ctrl(variant=variant, seed=seed, fault=(fault, mag) if fault else None, **kw)
        return rc, h, json.loads((self.out / "report.json").read_text())

    def rep(self, seed, ctrl_retrans=0):
        return P.rep_effect(self.tmp / f"PI8-{seed}", {"retrans": ctrl_retrans, "mem_refaults": 0,
                                                       "mem_psi_some_us": 0}, _RECORD["FZ-PI7-LOCK"]["value"])


class TestOpFaults(OpFaultFixture):
    """CPU and network faults (pi8) on the simulated host: exact ops, kernel read-back, design §5.8 ground truth."""

    def test_each_fault_issues_its_exact_ops_and_reads_back(self):
        busy = lambda s: s.files.update({"/proc/stat": proc_stat(1000 + 9000, 9000 + 100)})      # idle 1 %
        throttled = lambda s: s.files.update({f"{L.TARGET_DIR}/cpu.stat": cpu_stat(900, 880, 900 * 9800)})
        a_drop = lambda s: s.qd[L.IF_A][0].update(drops=50)
        police = lambda s: s.qd[L.IF_A][0].update(drops=40)
        retrans = lambda s: s.__setattr__("tcp", [s.tcp[0], s.tcp[1], s.tcp[2] + 30])
        cases = (("cpu_contender", 200, busy, ("write", L.CONTENDER_WEIGHT_PATH, "200")),
                 ("cpu_quota", 10000, throttled, ("write", L.QUOTA_PATH, "10000 100000")),
                 ("netem_loss_a_egress", 2, a_drop, ("tc", L.netem_loss_ops("a", 2)[0][1])),
                 ("police_a_ingress", 350, police, ("tc", L.police_ops(350)[1][1])),
                 ("netem_loss_r_egress", 1, retrans, ("tc", L.netem_loss_ops("r", 1)[0][1])),
                 ("netem_rate_r", 400, retrans, ("tc", L.netem_rate_ops(400, 1000)[0][1])))
        for seed, (fault, mag, effect, op) in enumerate(cases, start=900100):
            with self.subTest(fault):
                rc, h, rep = self.go(fault, mag, seed, effect)
                self.assertEqual(rc, 0, (fault, rep["checks"]))
                self.assertIn(op, h.ops)
                self.assertTrue(rep["checks"]["injection_verified"]["ok"], rep["checks"]["injection_verified"])
                self.assertTrue(self.rep(seed)["ground_truth"], self.rep(seed))
                self.assertTrue(empty(self.s))
                if fault == "cpu_contender":
                    self.assertIn("contender", [o[1] for o in h.ops if o[0] == "spawn"])
                if fault == "cpu_quota":
                    self.assertIn(L.QUOTA_RESTORE, h.ops)                      # restored before the cgroup goes
                    self.assertLess(h.ops.index(L.QUOTA_RESTORE), h.ops.index(("rmdir", L.TARGET_DIR)))

    def test_local_loss_run_reconciles_through_the_declared_hop(self):
        def loadgen():                                                   # A sent 50 segments that never reached R
            def finish():
                base = json.loads(self.docs[0])["mono_ns"] if self.docs else time.monotonic_ns()
                recs = [{"k": k, "scheduled_ns": base + 1000 + k, "sent_ns": base + 1000 + k, "outcome": "200",
                         "latency_ms": 0.001} for k in range(self.n)]
                (self.out / "lg" / "client.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs))
                self.s.tcp = [1060, 900, 0]
                self.s.r_stats = {L.IF_RA: [1010, 905, 0, 0], L.IF_RB: [905, 1010, 0, 0]}
            return FakeProc(on_wait=finish)
        drops = lambda n: lambda s: s.qd[L.IF_A][0].update(drops=n)
        rc, h, rep = self.go("netem_loss_a_egress", 2, 900190, drops(60), spawn={"loadgen": loadgen})
        ar = rep["checks"]["across_r_reconciliation"]
        self.assertTrue(ar["ok"], ar)                                     # 50 short, 60 dropped at A's netem
        self.assertEqual((ar["declared_drop_hop"], ar["qdisc_drops"]["a_root"]), ("a_root", 60))
        rc, h, rep = self.go("netem_loss_a_egress", 2, 900191, drops(40), spawn={"loadgen": loadgen})
        self.assertFalse(rep["checks"]["across_r_reconciliation"]["ok"])  # 10 segments unexplained
        self.assertEqual(rc, 1)

    def test_ground_truth_fails_without_the_effect(self):
        for seed, (fault, mag) in enumerate((("cpu_contender", 200), ("cpu_quota", 10000), ("netem_loss_a_egress", 2),
                                             ("police_a_ingress", 350), ("netem_loss_r_egress", 1)), start=900120):
            with self.subTest(fault):
                rc, h, rep = self.go(fault, mag, seed)                          # injected, but no kernel effect
                self.assertEqual(rc, 0)
                self.assertFalse(self.rep(seed)["ground_truth"], self.rep(seed))

    def test_path_loss_must_stay_invisible_to_a_local_drops(self):
        def leak(s):
            s.tcp = [s.tcp[0], s.tcp[1], s.tcp[2] + 30]
            s.qd[L.IF_A].append({"kind": "pfifo", "root": True, "drops": 3, "text": "qdisc pfifo"})
        self.go("netem_loss_r_egress", 2, 900130, leak)
        g = self.rep(900130)
        self.assertEqual((g["measure"]["a_local_drops"], g["ground_truth"]), (3, False))
        self.assertFalse(self.rep(900130, ctrl_retrans=30)["ground_truth"])   # retransmissions must exceed CTRL

    def test_throttling_needs_both_ratio_and_usage_within_quota(self):
        for seed, (periods, throttled, usage, ok) in enumerate(((900, 880, 900 * 9800, True),
                                                               (900, 500, 900 * 9800, False),
                                                               (900, 880, 900 * 12000, False)), start=900140):
            self.go("cpu_quota", 10000, seed,
                    lambda s, a=(periods, throttled, usage): s.files.update({f"{L.TARGET_DIR}/cpu.stat": cpu_stat(*a)}))
            self.assertEqual(self.rep(seed)["ground_truth"], ok, (periods, throttled, usage))

    def test_failed_tc_and_wrong_read_back_are_failed_injections(self):
        rc, h, rep = self.go("netem_loss_a_egress", 1, 900150, fail=lambda op: op[0] == "tc")
        self.assertEqual((rc, rep["checks"]["injection_verified"]["label"]), (1, "failed_injection"))
        self.assertTrue(rep["checks"]["cleanup"]["ok"])
        with mock.patch.object(P, "T_CAP_S", 0.2):                          # the kernel shows 2 %, not 1 %
            rc, h, rep = self.go("netem_loss_a_egress", 1, 900151,
                                 tweak={"tc_a_qdisc_text": (0, "qdisc netem 8001: root refcnt 2 limit 1000 loss 2%\n", "")})
        self.assertEqual((rc, rep["checks"]["injection_verified"]["ok"]), (1, False))   # kernel shows 2 %, not 1 %
        self.assertTrue(empty(self.s))

    def test_levels_for_op_faults(self):
        self.go(None, None, 900160, variant="ctrl")
        a_drop = lambda s: s.qd[L.IF_A][0].update(drops=50)
        seed = 900161
        for mag, eff in ((0.5, None), (0.5, a_drop), (1, a_drop), (1, a_drop), (2, a_drop), (2, a_drop),
                         (5, a_drop), (5, a_drop)):
            self.go("netem_loss_a_egress", mag, seed, eff)
            seed += 1
        lv = P.levels(self.tmp)["faults"]["netem_loss_a_egress"]
        self.assertEqual(lv["established_2of2"], [1, 2, 5])                    # 0.5 %: 1 of 2 reps
        self.assertEqual((lv["I1"], lv["I3"], lv["I2"], lv["I0"]), (1, 5, 2, 0.5))

    def test_unapproved_candidates_are_refused_by_the_real_record(self):
        record = json.loads((ROOT / "docs/PHASE_1C_FREEZE1_DECISIONS.json").read_text())
        record["decisions"]["FZ-INTENSITY-CPUNET"] = {"status": "proposed", "reference": "test",
                                                      "value": CPUNET}         # as before the owner's approval
        rec = self.tmp / "proposed.json"
        rec.write_text(json.dumps(record))
        with mock.patch.object(P, "approved_value", REAL_APPROVED):          # the real decision check
            for fault, mag in (("cpu_quota", 10000), ("netem_loss_a_egress", 1), ("netem_rate_r", 400)):
                with self.subTest(fault), self.assertRaises(P.Refused):     # a proposed record never authorises
                    P.op_fault_spec(fault, mag, rec)
                self.assertEqual(P.op_fault_spec(fault, mag)["magnitude"], mag)   # the committed, approved record
            self.assertEqual(P.fault_spec("app_pool", 1, WORKLOAD)["magnitude"], 1)

    def test_ceilings_hold_even_if_a_candidate_list_exceeded_them(self):
        bad = dict(CPUNET, contender_weight_candidates=[400, 800], quota_us_candidates=[7500, 5000],
                   loss_a_pct_candidates=[5, 10], loss_r_pct_candidates=[5, 10], congestion_kbit_candidates=[320, 100],
                   police_kbit_candidates=[300, 100])
        approved = lambda name, rec=None: bad if name == "FZ-INTENSITY-CPUNET" else _RECORD[name]["value"]
        with mock.patch.object(P, "approved_value", side_effect=approved):
            for fault, ok, over in (("cpu_contender", 400, 800), ("cpu_quota", 7500, 5000),
                                    ("netem_loss_a_egress", 5, 10), ("netem_loss_r_egress", 5, 10),
                                    ("netem_rate_r", 320, 100), ("police_a_ingress", 300, 100)):
                with self.subTest(fault):
                    self.assertEqual(P.op_fault_spec(fault, ok)["magnitude"], ok)
                    with self.assertRaises(P.Refused):                       # in the list, beyond the ceiling
                        P.op_fault_spec(fault, over)

    def test_contender_read_back_needs_a_live_contender(self):
        s = FakeSys()
        s.dirs |= set(L.LAB_DIRS)
        s.files[L.CONTENDER_WEIGHT_PATH] = "200"
        spec = {"type": "cpu_contender", "magnitude": 200}
        self.assertFalse(P.op_readback(spec, s))                             # weight set, no process
        s.procs[777] = f"/{L.LAB}/contender"
        self.assertTrue(P.op_readback(spec, s))
        s.files[L.CONTENDER_WEIGHT_PATH] = "100"
        self.assertFalse(P.op_readback(spec, s))

    def test_contention_needs_cpu18_idle_at_most_5_percent(self):
        for seed, (idle, ok) in enumerate(((100, True), (500, True), (1000, False), (5000, False)), start=900180):
            busy = 10000 - idle                                              # W adds 10000 ticks on CPU 18
            self.go("cpu_contender", 100, seed,
                    lambda s, b=busy, i=idle: s.files.update({"/proc/stat": proc_stat(1000 + b, 9000 + i)}))
            g = self.rep(seed)
            self.assertEqual((round(g["measure"]["cpu18_idle_frac"], 3), g["ground_truth"]), (idle / 10000, ok))

    def test_tc_shape_refuses_protected_names_anywhere(self):
        self.assertTrue(L.tc_shape_ok(L.netem_loss_ops("a", 1)[0][1]))
        for p in L.PROTECTED:
            with self.subTest(p):
                argv = ("tc", "-n", L.NS_A, "filter", "add", "dev", L.IF_A, "parent", "ffff:", "matchall", "action",
                        "mirred", "egress", "redirect", "dev", p)
                self.assertFalse(L.tc_shape_ok(argv))
                with self.assertRaises(L.LabRefused):
                    L.Plan("PI8-s900170", fault_ops=[("tc", argv)])

    def test_guard_admits_only_the_declared_lab_tc(self):
        ops = L.netem_loss_ops("a", 1)
        g = L.Plan("PI8-s900170", fault_ops=ops)
        self.assertEqual(g.check(ops[0]), ops[0])
        for bad in (("tc", L.netem_loss_ops("a", 2)[0][1]), ("tc", L.netem_loss_ops("r", 1)[0][1]),
                    ("tc", ("tc", "-n", L.NS_A, "qdisc", "add", "dev", "enp0s31f6", "root", "netem", "loss", "1%")),
                    ("cmd", ops[0][1]), ("write", L.QUOTA_PATH, "5000 100000"),
                    ("write", L.CONTENDER_WEIGHT_PATH, "10000"), ("spawn", "contender", L.contender_argv())):
            with self.subTest(bad), self.assertRaises(L.LabRefused):
                g.check(bad)
        for bad_ops in ([("tc", ("tc", "-n", "other-ns", "qdisc", "add", "dev", L.IF_A, "root", "netem"))],
                        [("tc", ("tc", "-n", L.NS_A, "qdisc", "add", "dev", L.IF_RB, "root", "netem"))],
                        [("tc", ("tc", "-n", L.NS_A, "qdisc", "add", "dev", "docker0", "root", "netem"))],
                        [("mkdir", "/tmp/x")], [("write", "/etc/passwd", "x")]):
            with self.subTest(bad_ops), self.assertRaises(L.LabRefused):
                L.Plan("PI8-s900170", fault_ops=bad_ops)
        self.assertEqual(L.Plan("PI8-s900170").check(L.QUOTA_RESTORE), L.QUOTA_RESTORE)   # restore is always allowed
        q = L.Plan("PI8-s900170", fault_ops=L.contender_ops(100))
        self.assertEqual(q.check(("spawn", "contender", L.contender_argv()))[1], "contender")


class TestFaultAwareReconciliation(unittest.TestCase):
    """Across-R reconciliation under a declared network fault, on the PI8-900116 numbers (0.5 % loss on A egress):
    A sent 174,597 segments, R received 173,925 (672 short); R dropped nothing on its interfaces."""

    def counters(self, a_root=0, r_root=0, ra_rx=173925, rb_tx=173925, ra_drop=0):
        z = {"rx_packets": 0, "tx_packets": 0, "rx_dropped": 0, "tx_dropped": 0, "rx_errors": 0, "tx_errors": 0,
             "rx_bytes": 0, "tx_bytes": 0}
        start = {"r": {L.IF_RA: dict(z), L.IF_RB: dict(z)}, "tcp": {"OutSegs": 0, "InSegs": 0, "RetransSegs": 0},
                 "qdisc": {"a_root": 0, "a_ingress": 0, "r_root": 0}}
        end = {"r": {L.IF_RA: dict(z, rx_packets=ra_rx, tx_packets=171166, rx_dropped=ra_drop),
                     L.IF_RB: dict(z, rx_packets=171163, tx_packets=rb_tx)},
               "tcp": {"OutSegs": 174000, "InSegs": 171158, "RetransSegs": 597},
               "qdisc": {"a_root": a_root, "a_ingress": 0, "r_root": r_root}}
        return {"start": start, "end": end}

    def test_the_declared_hop_explains_exactly_its_drops(self):
        self.assertEqual(P.reconcile_r(self.counters(a_root=672), "netem_loss_a_egress")[1], [])
        self.assertEqual(P.reconcile_r(self.counters(a_root=700), "netem_loss_a_egress")[1], [])   # >= (ARP etc.)
        self.assertEqual(P.reconcile_r(self.counters(a_root=600), "netem_loss_a_egress")[1],     # 72 unexplained
                         ["a_out_entered_r", "a_out_left_r"])

    def test_drops_never_excuse_another_hop_or_ctrl(self):
        for fault in (None, "police_a_ingress", "cpu_quota", "app_pool"):            # no path allowance at all
            with self.subTest(fault):
                self.assertIn("a_out_entered_r", P.reconcile_r(self.counters(a_root=672), fault)[1])
        failed = P.reconcile_r(self.counters(r_root=672), "netem_loss_r_egress")[1]   # loss happened at A, not R
        self.assertIn("a_out_entered_r", failed)

    def test_r_side_faults_explain_only_the_r_to_b_hop(self):
        ok = self.counters(ra_rx=174597, rb_tx=174000, r_root=597)
        self.assertEqual(P.reconcile_r(ok, "netem_loss_r_egress")[1], [])
        self.assertEqual(P.reconcile_r(ok, "netem_rate_r")[1], [])
        self.assertEqual(P.reconcile_r(ok, None)[1], ["a_out_left_r"])
        self.assertEqual(P.reconcile_r(self.counters(ra_rx=174597, rb_tx=174000, r_root=500),
                                       "netem_loss_r_egress")[1], ["a_out_left_r"])

    def test_r_interface_drops_still_fail_and_old_records_get_no_allowance(self):
        failed = P.reconcile_r(self.counters(a_root=672, ra_drop=1), "netem_loss_a_egress")[1]
        self.assertEqual(failed, [f"{L.IF_RA}_rx_dropped_0"])
        old = self.counters(a_root=672)
        for k in ("start", "end"):
            del old[k]["qdisc"]                                          # counters.json before this change
        self.assertIn("a_out_entered_r", P.reconcile_r(old, "netem_loss_a_egress")[1])   # PI8-900116 stays failed
        summary = P.reconcile_r(self.counters(a_root=672), "netem_loss_a_egress")[0]
        self.assertEqual((summary["declared_drop_hop"], summary["allowance"]), ("a_root", {"a_root": 672, "r_root": 0}))


class TestPacketUnitReconciliation(unittest.TestCase):
    """PI8-900200 (0.5 % loss on A egress), W window, measured: A's IP sent 92,926 packets, its netem qdisc dropped
    471, A's interface (and so R's ingress) carried 92,456; TCP counted 92,737 segments plus 285 retransmissions."""

    def counters(self, ip_out, ra_rx, a_root, retrans=285, segs=92737, ip=True):
        z = {"rx_packets": 0, "tx_packets": 0, "rx_dropped": 0, "tx_dropped": 0, "rx_errors": 0, "tx_errors": 0}
        side = lambda tcp, ipc, ra, rb, qd: {"r": {L.IF_RA: dict(z, **ra), L.IF_RB: dict(z, **rb)}, "tcp": tcp,
                                             "qdisc": {"a_root": qd, "a_ingress": 0, "r_root": 0},
                                             **({"ip": ipc} if ip else {})}
        start = side({"OutSegs": 0, "InSegs": 0, "RetransSegs": 0}, {"OutRequests": 0, "InReceives": 0}, {}, {}, 0)
        end = side({"OutSegs": segs, "InSegs": 90000, "RetransSegs": retrans},
                   {"OutRequests": ip_out, "InReceives": 90000},
                   {"rx_packets": ra_rx, "tx_packets": 90001}, {"rx_packets": 90001, "tx_packets": ra_rx}, a_root)
        return {"start": start, "end": end}

    def test_packets_balance_where_segments_cannot(self):
        summary, failed = P.reconcile_r(self.counters(92926, 92456, 471), "netem_loss_a_egress")
        self.assertEqual((failed, summary["unit"]), ([], "ip_packets"))
        failed = P.reconcile_r(self.counters(92926, 92456, 471, ip=False), "netem_loss_a_egress")[1]
        self.assertEqual(failed, ["a_out_entered_r", "a_out_left_r"])          # 93,022 segments vs 92,927 packets
        self.assertEqual(P.reconcile_r(self.counters(92926, 92456, 400), "netem_loss_a_egress")[1],
                         ["a_out_entered_r", "a_out_left_r"])                   # 71 packets unexplained
        self.assertEqual(P.reconcile_r(self.counters(92926, 92456, 471), None)[1],
                         ["a_out_entered_r", "a_out_left_r"])                   # CTRL: no allowance

    def test_ctrl_numbers_balance_exactly(self):                              # CTRL-900150, W: 92,370 vs 92,371
        self.assertEqual(P.reconcile_r(self.counters(92370, 92371, 0, retrans=0, segs=92370), None)[1], [])

    def test_ip_counters_parser(self):
        text = "Ip: Forwarding DefaultTTL InReceives OutRequests\nIp: 2 64 90806 92371\nTcp: X\nTcp: 1\n"
        self.assertEqual(L.ip_counters(text), {"OutRequests": 92371, "InReceives": 90806})
        for bad in ("", None, "Ip: InReceives\nIp: x\n", "Tcp: OutSegs\nTcp: 1\n"):
            with self.subTest(bad):
                self.assertIsNone(L.ip_counters(bad))


class TestClientAccountingUnderNetworkFaults(unittest.TestCase):
    def check(self, fault, outcomes, server):
        recs, k = [], 0
        for o, c in outcomes.items():
            for _ in range(c):
                recs.append({"k": k, "outcome": o, "sent_ns": 2_000_000_000 + k,
                             "latency_ms": 1.0 if o in ("200", "400", "503", "504") else None})
                k += 1
        run = {"load": {"arrivals": k}, "fault": {"type": fault} if fault else None}
        a = {"mono_s": 1.0, "pool_util": 0.0, "requests_completed_total": 0, "requests_rejected_total": 0,
             "requests_failed_total": 0}
        b = dict(a, mono_s=1e6, **dict(zip(("requests_completed_total", "requests_rejected_total",
                                            "requests_failed_total"), server)))
        return P.reconcile_clients(run, recs, a, b)[1]

    def test_network_failures_are_accounted_not_excused(self):
        out = {"200": 100, "504": 2, "TimeoutError": 5, "ConnectionResetError": 1}
        for fault in sorted(P.NETWORK_FAULTS):
            with self.subTest(fault):
                self.assertEqual(self.check(fault, out, (100, 0, 2)), [])        # none reached the server
                self.assertEqual(self.check(fault, out, (106, 0, 2)), [])        # 6 answered, answers lost
                self.assertTrue(self.check(fault, out, (107, 0, 2)))             # 7 > 6 failures: unexplained
                self.assertTrue(self.check(fault, out, (99, 0, 2)))              # client got more than served
                self.assertTrue(self.check(fault, dict(out, malformed_response=1), (100, 0, 2)))

    def test_a_400_is_a_server_failure_exactly(self):
        """PI8-900617: a request the workload could not read within 2 s gets 400 and requests_failed_total (its
        documented accounting); the reconciliation counts it there, exactly, with or without a network fault."""
        out = {"200": 100, "504": 2, "400": 1}
        for fault in (None, "police_a_ingress", "app_lock"):
            with self.subTest(fault):
                self.assertEqual(self.check(fault, out, (100, 0, 3)), [])
                self.assertTrue(self.check(fault, out, (100, 0, 2)))             # the 400 not counted: wrong
                self.assertTrue(self.check(fault, {"200": 100, "504": 2}, (100, 0, 3)))  # unexplained server fail
        recs = [{"k": 0, "outcome": "400", "sent_ns": 1, "latency_ms": 5.0}]
        self.assertEqual(P.client_records({"load": {"arrivals": 1}}, recs)[1], [])
        self.assertTrue(P.client_records({"load": {"arrivals": 1}}, [dict(recs[0], latency_ms=None)])[1])

    def test_without_a_network_fault_everything_stays_exact(self):
        out = {"200": 100, "TimeoutError": 1}
        for fault in (None, "cpu_quota", "cpu_contender", "app_lock"):
            with self.subTest(fault):
                self.assertTrue(any("without a server counterpart" in p for p in self.check(fault, out, (100, 0, 0))))
                self.assertTrue(self.check(fault, {"200": 100}, (101, 0, 0)))
                self.assertEqual(self.check(fault, {"200": 100, "503": 3}, (100, 3, 0)), [])


def mem_files(max_events=0, oom=0, refaults=0, psi_us=0, swap=0, avail_kb=13 * 1024 * 1024, high=0, pgscan=0,
              current=1080 << 20):
    return {"/proc/meminfo": f"MemTotal: 16053920 kB\nMemAvailable: {avail_kb} kB\n",
            f"{L.TARGET_DIR}/memory.events": f"low 0\nhigh {high}\nmax {max_events}\noom 0\noom_kill {oom}\n",
            f"{L.TARGET_DIR}/memory.current": f"{current}\n",
            f"{L.TARGET_DIR}/memory.stat": f"anon 23000000\nfile 1073741824\nworkingset_refault_anon 0\n"
                                          f"workingset_refault_file {refaults}\npgscan {pgscan}\n",
            f"{L.TARGET_DIR}/memory.pressure": f"some avg10=0.00 avg60=0.00 avg300=0.00 total={psi_us}\n"
                                              f"full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
            "/proc/vmstat": f"pgfault 1\npswpin {swap}\npswpout 0\n"}


class TestMemoryFault(OpFaultFixture):
    """memory_max (FZ-INTENSITY-MEM, FZ-PI5) on the simulated host."""

    def setUp(self):
        super().setUp()
        cpu = self.base
        self.base = lambda s: (cpu(s), s.files.update(mem_files()))
        self.pressure = lambda s: s.files.update(mem_files(max_events=500, refaults=40000, psi_us=5_000_000))

    def test_memory_limit_is_written_read_back_and_restored(self):
        rc, h, rep = self.go("memory_max", 512, 900300, self.pressure)
        self.assertEqual(rc, 0, rep["checks"])
        self.assertIn(("write", L.MEMORY_PATH, str(512 * 1024 * 1024)), h.ops)
        self.assertTrue(rep["checks"]["injection_verified"]["ok"])
        self.assertIn(L.MEMORY_RESTORE, h.ops)                                 # restored before the cgroup goes
        self.assertLess(h.ops.index(L.MEMORY_RESTORE), h.ops.index(("rmdir", L.TARGET_DIR)))
        g = self.rep(900300)
        self.assertTrue(g["ground_truth"], g)
        self.assertTrue(g["measure"]["pi5"], g)
        self.assertTrue(empty(self.s))

    def test_no_pressure_no_ground_truth(self):
        self.go("memory_max", 960, 900301)
        g = self.rep(900301)
        self.assertEqual((g["ground_truth"], g["measure"]["pi5"]), (False, False))

    def test_swap_breaks_pi5_but_not_ground_truth(self):
        self.go("memory_max", 512, 900302,
                lambda s: s.files.update(mem_files(max_events=500, refaults=40000, psi_us=5_000_000, swap=10 ** 9)))
        g = self.rep(900302)
        self.assertEqual((g["ground_truth"], g["measure"]["pi5"]), (True, False))

    def test_oom_kill_or_low_host_memory_aborts_and_still_restores(self):
        for seed, effect, why in ((900303, lambda s: s.files.update(mem_files(max_events=5, oom=1)), "oom_kill"),
                                  (900304, lambda s: s.files.update(mem_files(avail_kb=3 * 1024 * 1024)),
                                   "MemAvailable")):
            with self.subTest(why):
                rc, h, rep = self.go("memory_max", 256, seed, effect)
                run = json.loads((self.out / "evidence" / "run.json").read_text())
                self.assertEqual(rc, 1)
                self.assertTrue(any(why in a for a in run["aborts"]), run["aborts"])
                self.assertIn(L.MEMORY_RESTORE, h.ops)
                self.assertTrue(run["cleanup"]["ok"] and run["host_compare"]["ok"])
                self.assertTrue(empty(self.s))

    def test_guard_only_in_memory_runs(self):
        rc, h, rep = self.go("cpu_quota", 10000, 900305, lambda s: s.files.update(mem_files(avail_kb=1)))
        self.assertNotIn("memory abort", " ".join(json.loads((self.out / "evidence" / "run.json").read_text())["aborts"]))

    def test_floor_and_candidates(self):
        self.assertEqual(P.op_fault_spec("memory_max", 256)["ops"], L.memory_ops(256))
        bad = dict(_RECORD["FZ-INTENSITY-MEM"]["value"], memory_max_mib_candidates=[256, 128])
        approved = lambda name, rec=None: bad if name == "FZ-INTENSITY-MEM" else _RECORD[name]["value"]
        with mock.patch.object(P, "approved_value", side_effect=approved), self.assertRaises(P.Refused):
            P.op_fault_spec("memory_max", 128)                                  # in a list, below the floor
        g = L.Plan("PI8-s900306", fault_ops=L.memory_ops(512))
        self.assertEqual(g.check(L.memory_ops(512)[0]), L.memory_ops(512)[0])
        for bad_op in (("write", L.MEMORY_PATH, str(128 * 1024 * 1024)), ("write", f"{L.LAB_DIR}/memory.max", "1")):
            with self.subTest(bad_op), self.assertRaises(L.LabRefused):
                g.check(bad_op)
        self.assertEqual(L.Plan("PI8-s900306").check(L.MEMORY_RESTORE), L.MEMORY_RESTORE)

    def test_each_ground_truth_ingredient_is_required(self):
        a = {"mono_ns": 0, "mem_max_events": 0, "oom_kill": 0, "mem_refaults": 0, "mem_psi_some_us": 0, "swap_pages": 0}
        b = dict(a, mono_ns=90 * 10 ** 9, mem_max_events=500, mem_refaults=40000, mem_psi_some_us=5_000_000)
        ctrl = {"mem_refaults": 0, "mem_psi_some_us": 0}
        g = P.fault_ground_truth("memory_max", 512, a, b, ctrl)
        self.assertEqual((g["established"], g["pi5"]), (True, True))
        for name, change, ctrl_change, gt, pi5 in (
                ("no max events", {"mem_max_events": 0}, {}, False, False),
                ("an OOM kill", {"oom_kill": 1}, {}, False, False),
                ("refaults not above CTRL", {}, {"mem_refaults": 40000}, False, False),
                ("PSI not above CTRL", {}, {"mem_psi_some_us": 5_000_000}, True, False),
                ("no CTRL reference", {}, {"mem_refaults": None}, False, False)):
            with self.subTest(name):
                g = P.fault_ground_truth("memory_max", 512, a, dict(b, **change), dict(ctrl, **ctrl_change))
                self.assertEqual((g["established"], g["pi5"]), (gt, pi5))

    def test_read_back_needs_the_exact_limit(self):
        s = FakeSys()
        spec = {"type": "memory_max", "magnitude": 512}
        s.files[L.MEMORY_PATH] = str(512 * 1024 * 1024)
        self.assertTrue(P.op_readback(spec, s))
        for other in ("max", str(768 * 1024 * 1024), ""):
            with self.subTest(other):
                s.files[L.MEMORY_PATH] = other
                self.assertFalse(P.op_readback(spec, s))

    def test_levels_for_memory(self):
        self.go(None, None, 900310, variant="ctrl")
        seed = 900311
        for mag, eff in ((960, None), (960, None), (768, self.pressure), (768, self.pressure),
                         (512, self.pressure), (512, self.pressure), (256, self.pressure), (256, self.pressure)):
            self.go("memory_max", mag, seed, eff)
            seed += 1
        lv = P.levels(self.tmp)["faults"]["memory_max"]
        self.assertEqual(lv["established_2of2"], [768, 512, 256])
        self.assertEqual((lv["I1"], lv["I3"], lv["I0"]), (768, 256, 960))


class TestOv4Flood(OpFaultFixture):
    """OV-4 feasibility (AMD-13, FZ-OV) as a PI-8 fault: a 64-byte UDP flood A -> B at the one approved level."""

    def test_only_the_preregistered_level_with_its_exact_ops(self):
        spec = P.fault_spec("ov4_udp_flood", 80000, WORKLOAD)
        self.assertEqual((spec["decision"], spec["candidates"], spec["ops"]),
                         ("FZ-OV", [80000], L.flood_ops(80000, P.W_S + 5)))
        argv = spec["ops"][0][2]
        prog = argv[argv.index(L.IPERF3):]
        self.assertEqual(prog, [L.IPERF3, "-c", L.IP_B, "-B", L.IP_A, "-p", "5301", "-u", "-l", "64",
                                "-b", str(80000 * 64 * 8), "-t", str(P.W_S + 5), "-A", "22", "-J"])
        self.assertEqual(argv[:len(L.placed("support", L.NS_A, []))], L.placed("support", L.NS_A, []))
        self.assertNotIn(L.FLOOD_CLIENT_CPU, (L.TARGET_CPU,))
        self.assertNotIn(L.FLOOD_SERVER_CPU, (L.TARGET_CPU,))
        for bad in (40000, 160000, 80000.0, True):
            with self.subTest(bad), self.assertRaises(P.Refused):
                P.fault_spec("ov4_udp_flood", bad, WORKLOAD)

    def test_guard_accepts_only_the_declared_flood(self):
        spec = P.fault_spec("ov4_udp_flood", 80000, WORKLOAD)
        plan = L.Plan("PI8-s900400", spawns=[("flood_server", L.flood_server_argv())], fault_ops=spec["ops"])
        plan.check(spec["ops"][0])
        plan.check(("spawn", "flood_server", L.flood_server_argv()))
        with self.assertRaises(L.LabRefused):
            plan.check(("spawn", "flood_client", L.flood_client_argv(160000, P.W_S + 5)))
        with self.assertRaises(L.LabRefused):
            L.Plan("PI8-s900400").check(spec["ops"][0])                       # undeclared: refused
        for role in ("workload", "loadgen", "flood_server", "dependency"):     # only fault roles are fault ops
            with self.subTest(role), self.assertRaises(L.LabRefused):
                L.Plan("PI8-s900400", fault_ops=[("spawn", role, L.flood_server_argv())])

    def test_feasible_run(self):
        rc, h, rep = self.go("ov4_udp_flood", 80000, 900400)
        self.assertEqual(rc, 0, rep["checks"])
        spawns = [o[1] for o in h.ops if o[0] == "spawn"]
        self.assertLess(spawns.index("flood_server"), spawns.index("loadgen"))   # listening before any flood
        self.assertLess(spawns.index("loadgen"), spawns.index("flood_client"))   # the client is the injection
        self.assertTrue(rep["checks"]["injection_verified"]["ok"])
        o = rep["ov4"]
        self.assertTrue(o["feasible"], o)
        self.assertEqual((o["c_ticks"], o["c_alive_ticks"], o["nW"]), (P.W_S, P.W_S, P.W_S))
        self.assertAlmostEqual(o["a_sender_pps"], 80000.0)
        man = json.loads((self.out / "manifest.json").read_text())
        self.assertTrue({"evidence/flood_client.json", "evidence/flood_server.json"} <= set(man["files"]))
        g = self.rep(900400)
        self.assertTrue(g["ground_truth"], g)
        self.assertTrue(empty(self.s))

    def test_infeasible_reps_are_reported_not_hidden(self):
        cases = (("sender rate off by more than tau", {"flood": {"flood_client": iperf_doc(packets=70000 * 95),
                                                                 "flood_server": iperf_doc(False, 70000 * 95)}}, "a"),
                 ("receiver loss", {"flood": {"flood_client": iperf_doc(),
                                              "flood_server": iperf_doc(False, lost=3)}}, "b"),
                 ("client on the target CPU", {"flood_cpus": "18,22"}, "d"),
                 ("client error", {"flood": {"flood_client": iperf_doc(error="unable to connect"),
                                             "flood_server": iperf_doc(False)}}, "a"))
        for seed, (name, kw, crit) in enumerate(cases, start=900401):
            with self.subTest(name):
                rc, h, rep = self.go("ov4_udp_flood", 80000, seed, **kw)
                o = rep["ov4"]
                self.assertFalse(o["feasible"])
                self.assertFalse(o["criteria"][crit], o)
                self.assertTrue(rep["pipeline_ok"], rep["checks"])               # a valid run, an infeasible rep
                self.assertFalse(self.rep(seed)["ground_truth"])

    def test_flood_dead_for_one_tick(self):
        obs = [{"k": k, "pid": 7, "alive": k != 100, "cpus": "22", "netns_a": True} for k in range(46, 136)]
        run = {"nW": 90, "flood": {"observations": obs, "target_cpus_effective": "18\n",
                                   "support_cpus_effective": "19-20,22-23\n"}}
        o = P.ov4_check(run, iperf_doc(), iperf_doc(False))
        self.assertEqual((o["criteria"]["c"], o["feasible"]), (False, False))
        run["flood"]["observations"] = [dict(x, alive=True) for x in obs]
        self.assertTrue(P.ov4_check(run, iperf_doc(), iperf_doc(False))["feasible"])
        for key, val in (("target_cpus_effective", "19\n"), ("support_cpus_effective", "")):
            with self.subTest(key):
                bad = dict(run, flood=dict(run["flood"], **{key: val}))
                self.assertFalse(P.ov4_check(bad, iperf_doc(), iperf_doc(False))["criteria"]["d"])
        wrong_ns = dict(run, flood=dict(run["flood"], observations=[dict(x, alive=True, netns_a=k > 0)
                                                                    for k, x in enumerate(obs)]))
        self.assertFalse(P.ov4_check(wrong_ns, iperf_doc(), iperf_doc(False))["criteria"]["d"])
        few = dict(run, flood=dict(run["flood"], observations=run["flood"]["observations"][:-1]))
        self.assertFalse(P.ov4_check(few, iperf_doc(), iperf_doc(False))["criteria"]["c"])
        swapped = json.loads(iperf_doc())
        swapped["start"]["connected"][0].update(local_host=L.IP_B, remote_host=L.IP_A)
        self.assertFalse(P.ov4_check(run, json.dumps(swapped).encode(), iperf_doc(False))["criteria"]["path"])
        edge = 80000 * 1.1                                                       # tau is inclusive
        self.assertTrue(P.ov4_check(run, iperf_doc(packets=round(edge * 95)), iperf_doc(False))["criteria"]["a"])
        self.assertFalse(P.ov4_check(run, iperf_doc(packets=round(edge * 95) + 100), iperf_doc(False))["criteria"]["a"])


class TestOv5Fill(OpFaultFixture):
    """OV-5 (AMD-15, FZ-OV O-1): M = 2,048 MiB for the whole run, a 768 MiB file written in A's cgroup at the boundary."""

    CTRL = {"retrans": 0, "mem_refaults": 0, "mem_psi_some_us": 0, "mem_pgscan": 0}

    def setUp(self):
        super().setUp()
        cpu = self.base
        self.base = lambda s: (cpu(s), s.files.update(mem_files()))
        self.filled = lambda s: s.files.update(mem_files(current=1848 << 20))

    def rep5(self, seed, ctrl=None):
        return P.rep_effect(self.tmp / f"PI8-{seed}", ctrl or self.CTRL, _RECORD["FZ-PI7-LOCK"]["value"])

    def test_spec_is_the_approved_sizes_only(self):
        spec = P.fault_spec("ov5_page_cache_fill", 768, WORKLOAD, run_id="PI8-s900420")
        self.assertEqual((spec["decision"], spec["candidates"], spec["memory_max_mib"], spec["r_star"]),
                         ("FZ-OV", [768], 2048, 0.9))
        self.assertEqual(spec["setup_ops"], [("write", L.MEMORY_PATH, str(2048 << 20))])
        self.assertEqual(spec["ops"], L.ov5_ops("PI8-s900420", 768))
        argv = spec["ops"][0][2]
        self.assertEqual(argv[-2:], [f"{L.WS_ROOT}/PI8-s900420/{L.OV5_FILE}", "768"])
        self.assertEqual(argv[:len(L.placed("target", L.NS_A, []))], L.placed("target", L.NS_A, []))
        for bad in (512, 1024, 768.0, True):
            with self.subTest(bad), self.assertRaises(P.Refused):
                P.fault_spec("ov5_page_cache_fill", bad, WORKLOAD, run_id="PI8-s900420")
        with self.assertRaises(P.Refused):
            P.fault_spec("ov5_page_cache_fill", 768, WORKLOAD)                    # the path needs the run id
        with mock.patch.object(L, "LAB_MEMORY_MAX", str(3072 << 20)), self.assertRaises(P.Refused):
            P.fault_spec("ov5_page_cache_fill", 768, WORKLOAD, run_id="PI8-s900420")   # lab cap differs

    def test_writer_writes_the_file_in_full_once(self):
        d = Path(tempfile.mkdtemp(dir=self.tmp))
        argv = L.ov5_writer_argv("PI8-s900420", 2)
        code = L.OV5_WRITER_CODE
        self.assertEqual(argv[argv.index(L.PYTHON):argv.index(L.PYTHON) + 3], [L.PYTHON, "-I", "-c"])
        self.assertEqual(argv[argv.index(L.PYTHON) + 3], code)
        with mock.patch.object(sys, "argv", ["-c", str(d / "f.bin"), "2"]):
            exec(compile(code, "ov5_writer", "exec"), {})
            self.assertEqual((d / "f.bin").read_bytes(), bytes([0xa5]) * (2 << 20))
            with self.assertRaises(FileExistsError):                             # O_EXCL: never overwrites
                exec(compile(code, "ov5_writer", "exec"), {})
        with mock.patch.object(sys, "argv", ["-c", str(d / "g.bin"), "1"]), mock.patch.object(os, "fsync") as fs:
            exec(compile(code, "ov5_writer", "exec"), {})
        fs.assert_called_once()                                                  # fsynced before it exits

    def test_real_residency_reader(self):
        with self.assertRaises(L.LabRefused):
            L.Sys().residency("/etc/passwd")                                    # only under the scratch roots
        d = Path(tempfile.mkdtemp(dir=self.tmp))
        (d / "r.bin").write_bytes(b"x" * (64 << 10))
        (d / "e.bin").write_bytes(b"")
        with mock.patch.object(L.Sys, "_run_lab_path", staticmethod(lambda p: str(p))):
            self.assertEqual(L.Sys().residency(d / "r.bin"), {"size": 64 << 10, "pages": 16, "resident": 16})
            self.assertEqual(L.Sys().residency(d / "e.bin"), {"size": 0, "pages": 0, "resident": 0})
            self.assertIsNone(L.Sys().residency(d / "absent.bin"))
            fd = os.open(d / "r.bin", os.O_RDONLY)
            try:
                os.fsync(fd)
                os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)               # clean pages: evicted
            finally:
                os.close(fd)
            self.assertEqual(L.Sys().residency(d / "r.bin")["resident"], 0)

    def test_readback_needs_the_full_file_and_the_writer_gone(self):
        spec = P.fault_spec("ov5_page_cache_fill", 768, WORKLOAD, run_id="PI8-s900420")
        s = FakeSys()
        s.dirs.add(L.TARGET_DIR)
        s.procs.update({10: f"/{L.LAB}/target", 11: f"/{L.LAB}/target"})
        self.assertFalse(P.op_readback(spec, s))                                 # not written yet
        s.run[spec["path"]], s.sizes[spec["path"]] = ("file", L.LAB_UID, b""), 767 << 20
        self.assertFalse(P.op_readback(spec, s))                                 # still being written
        s.sizes[spec["path"]] = 768 << 20
        s.procs[12] = f"/{L.LAB}/target"
        self.assertFalse(P.op_readback(spec, s))                                 # full size, writer not yet gone
        del s.procs[12]
        self.assertTrue(P.op_readback(spec, s))

    def test_setup_limit_must_read_back_and_the_memory_guard_applies(self):
        cpu = self.base

        def stuck(s):                                                            # memory.max write does not stick
            cpu(s)
            s.files.update(mem_files())
            real = s.read
            s.read = lambda path: "max\n" if path == L.MEMORY_PATH else real(path)
        self.base = stuck
        rc, h, rep = self.go("ov5_page_cache_fill", 768, 900428)
        self.assertNotEqual(rc, 0)
        self.assertTrue(any("setup write not read back" in a for a in rep["checks"]["run_completed"]["aborts"]))
        self.base = lambda s: (cpu(s), s.files.update(mem_files()))
        rc, h, rep = self.go("ov5_page_cache_fill", 768, 900429,
                             lambda s: s.files.update(mem_files(avail_kb=3 * 1024 * 1024)))
        self.assertNotEqual(rc, 0)
        self.assertTrue(any("MemAvailable" in a for a in rep["checks"]["run_completed"]["aborts"]), rep["checks"])
        self.assertIn(L.MEMORY_RESTORE, h.ops)                                   # restored after the abort

    def test_feasible_run(self):
        rc, h, rep = self.go("ov5_page_cache_fill", 768, 900420, self.filled)
        self.assertEqual(rc, 0, rep["checks"])
        mm = ("write", L.MEMORY_PATH, str(2048 << 20))
        self.assertLess(h.ops.index(mm), next(i for i, o in enumerate(h.ops)
                                              if o[0] == "spawn" and o[1] == "workload"))   # M before the workload
        self.assertIn(L.MEMORY_RESTORE, h.ops)
        self.assertLess(h.ops.index(L.MEMORY_RESTORE), h.ops.index(("rmdir", L.TARGET_DIR)))
        self.assertIn(("unlink_run", f"{L.WS_ROOT}/PI8-s900420/{L.OV5_FILE}"), h.ops)
        self.assertTrue(rep["checks"]["injection_verified"]["ok"])
        g = self.rep5(900420)
        self.assertTrue(g["ground_truth"], g)
        self.assertAlmostEqual(g["measure"]["utilisation_w_end"], 1848 / 2048)
        self.assertEqual(g["measure"]["residency_min"], 1.0)
        self.assertTrue(empty(self.s))

    def test_f1_failures_are_reported(self):
        cases = (("evicted below r*", 900421, lambda s: (self.filled(s), s.__setattr__(
                     "resident", lambda p, n: int(n * 0.85))), "residency"),
                 ("limit reached", 900422, lambda s: s.files.update(mem_files(max_events=3, current=2040 << 20)),
                  "events"),
                 ("high events", 900423, lambda s: s.files.update(mem_files(high=1)), "events"),
                 ("refaults above CTRL", 900424, lambda s: s.files.update(mem_files(refaults=10)), "ctrl_range"),
                 ("reclaim scans above CTRL", 900425, lambda s: s.files.update(mem_files(pgscan=5)), "ctrl_range"),
                 ("PSI above CTRL", 900426, lambda s: s.files.update(mem_files(psi_us=7)), "ctrl_range"))
        for name, seed, effect, crit in cases:
            with self.subTest(name):
                rc, h, rep = self.go("ov5_page_cache_fill", 768, seed, effect)
                self.assertTrue(rep["pipeline_ok"], rep["checks"])               # a valid run, an infeasible rep
                g = self.rep5(seed)
                self.assertFalse(g["ground_truth"])
                self.assertFalse(g["measure"]["criteria"][crit], g["measure"])

    def test_ctrl_range_is_inclusive_and_needs_ctrl(self):
        self.go("ov5_page_cache_fill", 768, 900427, lambda s: s.files.update(mem_files(refaults=10, pgscan=5,
                                                                                         psi_us=7)))
        self.assertTrue(self.rep5(900427, {"mem_refaults": 10, "mem_pgscan": 5, "mem_psi_some_us": 7})["ground_truth"])
        self.assertFalse(self.rep5(900427, {"mem_refaults": 10, "mem_pgscan": 5})["ground_truth"])   # no PSI max

    def test_writer_failure_or_missing_ticks_fail_f1(self):
        run = {"fault": {"magnitude": 768, "memory_max_mib": 2048, "r_star": 0.9}, "nW": 3,
               "injection": {"verified": True, "readback_latency_s": 4.0}, "exit_codes": {"ov5_writer": 0},
               "ov5": {"observations": [{"k": k, "size": 768 << 20, "pages": 196608, "resident": 196608}
                                        for k in (46, 47, 48)]}}
        a = {"mem_high_events": 0, "mem_max_events": 0, "oom_kill": 0, "mem_refaults": 0, "mem_pgscan": 0,
             "mem_psi_some_us": 0}
        b = dict(a, mem_current=1848 << 20)
        ok = P.ov5_check(run, a, b, self.CTRL)
        self.assertTrue(ok["established"], ok)
        for name, change, crit in (("writer failed", {"exit_codes": {"ov5_writer": 1}}, "fill"),
                                   ("fill slower than T_cap", {"injection": {"verified": True,
                                                                             "readback_latency_s": 31.0}}, "fill"),
                                   ("not read back", {"injection": {"verified": False}}, "fill"),
                                   ("a tick missing", {"nW": 4}, "residency"),
                                   ("never full size", {"ov5": {"observations": [
                                       {"k": 46, "size": 1 << 20, "pages": 256, "resident": 256}]}}, "residency"),
                                   ("residency unreadable", {"ov5": {"observations": [
                                       {"k": k, "size": 768 << 20, "pages": 196608, "resident": None}
                                       for k in (46, 47, 48)]}}, "residency")):
            with self.subTest(name):
                g = P.ov5_check(dict(run, **change), a, b, self.CTRL)
                self.assertFalse(g["criteria"][crit], g)
        partial = dict(run, ov5={"observations": [{"k": 46, "size": 1 << 20, "pages": 256, "resident": 10}] +
                                 run["ov5"]["observations"][1:]}, nW=3)
        self.assertTrue(P.ov5_check(partial, a, b, self.CTRL)["criteria"]["residency"])   # judged after the fill
        edge = dict(run, ov5={"observations": [dict(o, resident=int(196608 * 0.9) + 1) for o in
                                               run["ov5"]["observations"]]})
        self.assertTrue(P.ov5_check(edge, a, b, self.CTRL)["criteria"]["residency"])
        under = dict(run, ov5={"observations": [dict(o, resident=int(196608 * 0.9) - 1) for o in
                                                run["ov5"]["observations"]]})
        self.assertFalse(P.ov5_check(under, a, b, self.CTRL)["criteria"]["residency"])


class TestM5Review(OpFaultFixture):
    """FZ-M5-REVIEW (2026-10-13): frozen I2 runs and their AMD-13 confirmation (R-1); PI-6 under throttling (R-5)."""

    police = staticmethod(lambda s: s.qd[L.IF_A][0].update(drops=40))

    def test_only_the_frozen_i2_joins_the_candidates(self):
        w = P.approved_value("FZ-WORKLOAD", P.DECISIONS)
        for fault, i2 in (("app_lock", 1581), ("cpu_contender", 141), ("cpu_quota", 12248),
                          ("police_a_ingress", 407), ("netem_rate_r", 439)):
            with self.subTest(fault):
                self.assertEqual(P.frozen_i2(fault, P.DECISIONS), i2)
                self.assertEqual(P.fault_spec(fault, i2, w, P.DECISIONS)["magnitude"], i2)
                for bad in (i2 + 1, float(i2)):
                    with self.assertRaises(P.Refused):
                        P.fault_spec(fault, bad, w, P.DECISIONS)
        for fault in ("app_dependency_delay", "netem_loss_a_egress", "netem_loss_r_egress", "app_pool",
                      "memory_max", "ov4_udp_flood"):                         # tested candidates or single levels
            self.assertIsNone(P.frozen_i2(fault, P.DECISIONS), fault)
        with self.assertRaises(P.Refused):
            P.fault_spec("app_dependency_delay", 8, w, P.DECISIONS)

    def test_i2_confirmed_in_two_valid_reps(self):
        self.go(None, None, 900500, variant="ctrl")
        for seed in (900501, 900502):
            rc, h, rep = self.go("police_a_ingress", 407, seed, self.police)
            self.assertEqual(rc, 0, rep["checks"])
        c = P.levels(self.tmp)["faults"]["police_a_ingress"]["i2_confirmation"]
        self.assertEqual((c["I2"], c["confirmed"], c["valid_reps"], c["tie_break_next"]),
                         (407, True, ["PI8-900501", "PI8-900502"], None))

    def test_i2_not_confirmed_without_effect_or_with_one_rep(self):
        self.go(None, None, 900510, variant="ctrl")
        self.go("police_a_ingress", 407, 900511, self.police)
        self.assertIsNone(P.levels(self.tmp)["faults"]["police_a_ingress"]["i2_confirmation"]["confirmed"])
        self.go("police_a_ingress", 407, 900512)                                 # no drops: no ground truth
        self.assertFalse(P.levels(self.tmp)["faults"]["police_a_ingress"]["i2_confirmation"]["confirmed"])

    def test_failed_injection_names_the_tie_break_toward_i1(self):
        self.go(None, None, 900520, variant="ctrl")
        for seed in (900521, 900522):
            self.go("police_a_ingress", 407, seed, self.police)
        real = P.rep_effect

        def first_unverified(d, *a):
            r = real(d, *a)
            return dict(r, injection_verified=False, pipeline_ok=False) if d.name == "PI8-900521" else r
        with mock.patch.object(P, "rep_effect", side_effect=first_unverified):
            c = P.levels(self.tmp)["faults"]["police_a_ingress"]["i2_confirmation"]
        self.assertEqual((c["injection_failures"], c["tie_break_next"], c["confirmed"]), (1, 450, None))
        busy = lambda s: s.files.update({"/proc/stat": proc_stat(1000 + 9000, 9000 + 100)})
        for seed in (900523, 900524):                                           # higher is stronger: 141 -> 100
            self.go("cpu_contender", 141, seed, busy)

        def unverified(d, *a):
            r = real(d, *a)
            return dict(r, injection_verified=False, pipeline_ok=False) if d.name == "PI8-900523" else r
        with mock.patch.object(P, "rep_effect", side_effect=unverified):
            c = P.levels(self.tmp)["faults"]["cpu_contender"]["i2_confirmation"]
        self.assertEqual((c["I2"], c["tie_break_next"]), (141, 100))


class TestPi6UnderThrottling(unittest.TestCase):
    """FZ-M5-REVIEW R-5 on the real pi_checks."""

    def test_pi6_lists_quota_only_features_without_scoring_them(self):
        def snap(low):
            ms = [{"feature_id": f, "coverage": 0.5 if f in low else 1.0, "aggregation": "MEAN", "quality": "OK"}
                  for f in ("throttle.quota_cores", "throttle.quota_saturation", "cpu.util.cpuset", "tcp.retrans")]
            ms.append({"feature_id": "app.latency_ms", "coverage": 1.0, "aggregation": "P99", "quality": "OK"})
            return {"measurements": ms, "missing_measurements": []}
        ticks = [SimpleNamespace(obs={"app": {}})] * 136
        run = lambda t: {"fault": {"type": t} if t else None, "collection": {"cpu_s": 0.2, "wall_s": 135.0}}
        q = P.pi_checks(run("cpu_quota"), snap({"throttle.quota_cores", "throttle.quota_saturation"}), ticks)["PI-6"]
        self.assertTrue(q["ok"], q)
        self.assertEqual(q["post_fault_only"], {"throttle.quota_cores": 0.5, "throttle.quota_saturation": 0.5})
        for t in ("cpu_contender", None):                                       # only quota runs, only these two
            with self.subTest(t):
                self.assertFalse(P.pi_checks(run(t), snap({"throttle.quota_cores"}), ticks)["PI-6"]["ok"])
        self.assertFalse(P.pi_checks(run("cpu_quota"), snap({"throttle.quota_cores", "cpu.util.cpuset"}),
                                     ticks)["PI-6"]["ok"])


class TestReadsInTargetNetns(CtrlFixture):
    """P-7: the collector reads through the read server in A's netns; the target declares A's interface."""

    def test_proxy_returns_exactly_what_the_live_reader_returns(self):
        from sentinelai.collectors import LiveReader
        from sentinelai.collectors.errors import Bad, CollectorError, Status
        srv = FakeReadServer()
        px, lr = P.ProxyReader(srv), LiveReader()
        self.assertEqual(px.ready, {"ready": True, "netns": 7, "ifs": ["lo", L.IF_A]})
        self.assertEqual(px.read("/proc/sys/kernel/ostype"), lr.read("/proc/sys/kernel/ostype"))
        self.assertEqual(px.readlink("/proc/self/exe"), lr.readlink("/proc/self/exe"))
        self.assertEqual(px.listdir("/proc/sys/kernel/random"), lr.listdir("/proc/sys/kernel/random"))
        self.assertEqual(px.read("/proc/no-such-file"), Bad(Status.ABSENT, lr.read("/proc/no-such-file").detail))
        self.assertIsInstance(px.tc_qdisc("enp0s31f6"), Bad)                       # protected: refused, as live
        self.assertEqual(px.tc_qdisc("enp0s31f6").status, lr.tc_qdisc("enp0s31f6").status)
        with self.assertRaises(CollectorError):                                     # outside the allowlist
            px.read("/etc/passwd")
        px.close()
        self.assertEqual(srv.wait(5), 0)

    def test_a_wrong_view_is_refused(self):
        for view in ({"ino": 7, "self_ino": 8, "ifs": ["lo", L.IF_A]},                  # another netns
                     {"ino": 7, "self_ino": 7, "ifs": ["docker0", "enp0s31f6", "lo"]},   # the host's view
                     {"ino": 7, "self_ino": 7, "ifs": ["lo", L.IF_A, "x"]}):              # an extra interface
            with self.subTest(view), self.assertRaises(L.LabAbort):
                P.ProxyReader(FakeReadServer(view=view))
        with self.assertRaises(P.Refused):
            P.read_server(L.NS_B, None, None, enter=lambda ns: None, view={})

    def test_entering_the_view_order_and_flags(self):
        calls = []

        class Libc:
            def __getattr__(self, name):
                return lambda *a: calls.append((name,) + a) or 0
        with mock.patch("ctypes.CDLL", return_value=Libc()), mock.patch.object(P.os, "open", return_value=99), \
                mock.patch.object(P.os, "close"):
            P.enter_netns_view(L.NS_A)
        self.assertEqual([c[0] for c in calls], ["unshare", "mount", "setns", "mount", "mount"])
        self.assertEqual(calls[0][1], P.CLONE_NEWNS)
        self.assertEqual(calls[1][1:], (None, b"/", None, P.MS_REC | P.MS_SLAVE, None))   # nothing reaches the host
        self.assertEqual(calls[2][1:], (99, P.CLONE_NEWNET))
        self.assertEqual(calls[3][1:4], (b"sysfs", b"/sys", b"sysfs"))
        self.assertEqual(calls[4][1:4], (b"cgroup2", b"/sys/fs/cgroup", b"cgroup2"))

        tried = []

        class Failing:
            def __getattr__(self, name):
                return lambda *a: tried.append(name) or -1
        with mock.patch("ctypes.CDLL", return_value=Failing()), mock.patch.object(P.os, "open", return_value=99), \
                mock.patch.object(P.os, "close"), self.assertRaises(OSError):
            P.enter_netns_view(L.NS_A)
        self.assertEqual(tried, ["unshare"])                                        # fail closed at the first step

    def test_root_run_declares_a_interface_and_counts_the_server(self):
        rc, h = self.run_ctrl()
        self.assertEqual(rc, 0)
        run = json.loads((self.out / "evidence" / "run.json").read_text())
        self.assertEqual(run["target_doc"]["ifaces"], [L.IF_A])
        self.assertTrue(run["read_server"]["ready"]["ready"])
        self.assertEqual(run["exit_codes"]["read_server"], 0)
        self.assertEqual(run["collection"]["read_server_cpu_s"], 0.5)
        self.assertIsInstance(self.reader, P.ProxyReader)                           # every read in A's netns
        ticks = [SimpleNamespace(obs={"app": {}})] * 136
        snap = {"measurements": [{"feature_id": "app.latency_ms", "coverage": 1.0, "aggregation": "P99",
                                  "quality": "OK"}], "missing_measurements": []}
        pi6 = PI_CHECKS({"collection": {"cpu_s": 1.0, "loader_cpu_s": 0.5, "read_server_cpu_s": 1.2,
                                        "wall_s": 135.0}}, snap, ticks)["PI-6"]
        self.assertAlmostEqual(pi6["collector_cpu_core"], 2.7 / 135.0)                # the server's CPU counts

    def test_read_server_cli_needs_root(self):
        with mock.patch.object(P.os, "geteuid", return_value=1000), self.assertRaises(P.Refused):
            P.main(["read-server", "--netns", L.NS_A])


_MSPEC = importlib.util.spec_from_file_location("faultlab_matrix_for_pilot", ROOT / "experiments/faultlab/matrix.py")
MX = importlib.util.module_from_spec(_MSPEC)
_MSPEC.loader.exec_module(MX)
MATRIX = MX.generate(MX.load())


class TestM6Scenarios(OpFaultFixture):
    """Matrix entries (FZ-M6-PLAN) run through ctrl(variant="m6") on the simulated host."""

    def entry(self, family, **match):
        return next(r for r in MATRIX["runs"] if r["family"] == family and all(r[k] == v for k, v in match.items()))

    def m6(self, e, effect=None, **kw):
        self.out = self.tmp / f"M6-{e['seed']}"
        d = e.get("distractor")                                      # the workload's start config with a distractor
        self.config = config_echo(self.workload, distractor_kind=d["kind"], distractor_lines_per_s=0) if d else None
        self.live_sha = None
        self.s, self.docs, self.reads, self.live_sha = FakeSys(), [], 0, None
        self.base(self.s)
        self.effect = effect
        rc, h = self.run_ctrl(variant="m6", seed=e["seed"], scenario=e, **kw)
        return rc, h, json.loads((self.out / "report.json").read_text()), \
            json.loads((self.out / "evidence" / "run.json").read_text())

    def setUp(self):
        super().setUp()
        cpu = self.base
        self.base = lambda s: (cpu(s), s.files.update(mem_files()))

    def test_every_family_runs_with_its_exact_check_set(self):
        for fam in ["CTRL", "SF", "SENS"] + [f"OV-{k}" for k in range(1, 11)]:
            e = self.entry(fam)
            with self.subTest(fam):
                rc, h, rep, run = self.m6(e)
                self.assertEqual(rc, 0, (fam, rep["checks"]))
                self.assertEqual(set(rep["checks"]), P.pipeline_checks("m6", run))
                self.assertEqual(run["scenario"], e)
                self.assertEqual(run["run_id"], e["run_id"])
                self.assertTrue(empty(self.s))

    def test_two_faults_are_issued_in_order_and_both_read_back(self):
        rc, h, rep, run = self.m6(self.entry("OV-7"))
        parts = run["injection"]["parts"]
        self.assertEqual([p["type"] for p in parts], ["cpu_quota", "cpu_contender"])
        self.assertTrue(run["injection"]["verified"] and all(p["verified"] for p in parts))
        ops = [o for o in h.ops if o[0] in ("write", "spawn") and o[1] in (L.QUOTA_PATH, "contender",
                                                                           L.CONTENDER_WEIGHT_PATH)]
        self.assertEqual(ops[0][1], L.QUOTA_PATH)                                    # declared order
        self.assertTrue(rep["checks"]["injection_verified"]["ok"])

    def test_collector_switches(self):
        import m3b_r1_validate
        rc, h, rep, run = self.m6(self.entry("OV-8"))                                 # drop collectors disabled
        self.assertEqual((run["ebpf"], run["target_doc"]["ifaces"]), (False, []))
        self.assertEqual(run["collection"]["loader_cpu_s"], 0.0)
        rc, h, rep, run = self.m6(self.entry("OV-9"))                                 # app metrics disabled
        self.assertFalse(run["metrics_writer"])
        self.assertIn("client_records", rep["checks"])
        self.assertNotIn("app_features", rep["checks"])
        self.assertIn("--metrics", [o for o in h.ops if o[0] == "spawn" and o[1] == "workload"][0][2])
        rc, h, rep, run = self.m6(self.entry("SF"))
        self.assertEqual((run["ebpf"], run["target_doc"]["ifaces"]), (True, [L.IF_A]))

    def test_load_and_distractor_elements(self):
        rc, h, rep, run = self.m6(self.entry("OV-1"))
        self.assertEqual([p["type"] for p in run["injection"]["parts"]], ["cpu_contender", "bulk_flow"])
        self.assertIn(("spawn", "bulk_client", L.bulk_client_argv(40, P.FLOOD_S)), h.ops)
        self.assertTrue((self.out / "evidence" / "bulk_client.json").exists())
        rc, h, rep, run = self.m6(self.entry("OV-3"))
        stress = [o[2] for o in h.ops if o[0] == "spawn" and o[1] == "stress"]
        self.assertEqual(stress, [L.stress_argv(19), L.stress_argv(20)])
        self.assertTrue(rep["checks"]["injection_verified"]["ok"])
        self.assertEqual(sorted(P.stress_cpus(self.s)), [])                           # gone after cleanup

    def test_stress_readback_needs_the_loop_on_its_cpus(self):
        spec = {"type": "host_stress", "magnitude": [19, 20]}
        s = FakeSys()
        s.dirs.add(L.SUPPORT_DIR)
        loop = "\0".join([L.PYTHON, "-I", "-c", L.CONTENDER_CODE]) + "\0"
        for pid, cpus, cmd in ((10, "19", loop), (11, "20", loop), (12, "22", "/usr/bin/iperf3\0-s\0")):
            s.procs[pid] = f"/{L.LAB}/support"
            s.files[f"/proc/{pid}/cmdline"], s.files[f"/proc/{pid}/status"] = cmd, f"Cpus_allowed_list:\t{cpus}\n"
        self.assertTrue(P.op_readback(spec, s))
        s.files["/proc/11/status"] = "Cpus_allowed_list:\t18-20\n"                 # not pinned as declared
        self.assertFalse(P.op_readback(spec, s))
        s.files["/proc/11/status"] = "Cpus_allowed_list:\t20\n"
        del s.procs[10]                                                              # one loop missing
        self.assertFalse(P.op_readback(spec, s))
        rc, h, rep, run = self.m6(self.entry("OV-6"))
        wl = [o for o in h.ops if o[0] == "spawn" and o[1] == "workload"][0][2]
        self.assertEqual(wl[-4:], ["--distractor-kind", "slow_request", "--distractor-seed", str(run["seed"])])
        self.assertEqual([p["type"] for p in run["injection"]["parts"]], ["cpu_contender", "distractor"])
        rc, h, rep, run = self.m6(self.entry("OV-10"))
        self.assertEqual(run["injection"]["type"], "distractor")
        self.assertTrue(run["injection"]["verified"])

    def test_sens_magnitudes_only_through_the_matrix(self):
        e = self.entry("SENS", mechanism="cpu_quota")
        rc, h, rep, run = self.m6(e)
        self.assertEqual(rc, 0, rep["checks"])
        self.assertIn(("write", L.QUOTA_PATH, "40000 100000"), h.ops)
        with self.assertRaises(P.Refused):                                           # not via the pilot path
            P.fault_spec("cpu_quota", 40000, WORKLOAD)
        bad = dict(e, faults=[{"type": "cpu_quota", "magnitude": 5000}])            # below the approved floor
        with self.assertRaises(P.Refused):
            self.m6(bad)

    def test_distractor_rate_must_be_echoed_as_recorded(self):
        rc, h, rep, run = self.m6(self.entry("OV-10"))
        self.assertTrue(rep["checks"]["app_features"]["structurally_unavailable"]["applied"])
        ev = self.out / "evidence" / "run.json"
        run["faults"][0]["magnitude"] = 4                                           # recorded 4, echoed 5
        ev.write_text(json.dumps(run))
        gaps, basis = P.structural_app_gaps(self.out, True)
        self.assertEqual(gaps, {})
        self.assertEqual(basis["not_applied_because"], ["distractor rate not echoed as recorded"])

    def test_composite_injection_is_verified_only_when_every_part_is(self):
        part = lambda ok, t: SimpleNamespace(record={"type": t, "issued": True, "verified": ok, "issue_after_tick": 45,
                                                     "issue_mono_ns": 1, "readback_latency_s": 0.1 if ok else None,
                                                     **({} if ok else {"readback_error": "not read back"})},
                                             procs=[], join=lambda t: None)
        rec = P.MultiInjector([part(True, "cpu_quota"), part(False, "cpu_contender")]).record
        self.assertEqual((rec["issued"], rec["verified"], rec["readback_latency_s"]), (True, False, None))
        self.assertEqual(rec["readback_error"], "cpu_contender: not read back")
        self.assertFalse(P.injection_check({"injection": rec})["ok"])
        self.assertTrue(P.MultiInjector([part(True, "a"), part(True, "b")]).record["verified"])

    def test_every_element_counts_for_the_evaluation(self):
        run = {"fault": {"type": "cpu_contender"}, "faults": [{"type": "cpu_contender"}, {"type": "cpu_quota"}]}
        self.assertEqual(P.fault_types(run), ["cpu_contender", "cpu_quota"])
        ms = [{"feature_id": f, "coverage": 0.5, "aggregation": "MEAN", "quality": "OK"}
              for f in ("throttle.quota_cores", "throttle.quota_saturation")]
        ms.append({"feature_id": "app.latency_ms", "coverage": 1.0, "aggregation": "P99", "quality": "OK"})
        pi6 = PI_CHECKS(dict(run, collection={"cpu_s": 0.2, "wall_s": 135.0}),
                        {"measurements": ms, "missing_measurements": []},
                        [SimpleNamespace(obs={"app": {}})] * 136)["PI-6"]
        self.assertTrue(pi6["ok"], pi6)                                             # quota is the second element
        self.assertEqual(P.fault_types({"fault": {"type": "app_lock"}}), ["app_lock"])
        self.assertEqual(P.fault_types({"fault": None}), [])

    def test_m6_needs_its_scenario_and_its_seed_range(self):
        with self.assertRaises(P.Refused):
            self.run_ctrl(variant="m6", seed=100001)
        e = self.entry("CTRL")
        with self.assertRaises(P.Refused):
            self.run_ctrl(variant="m6", seed=e["seed"] + 1, scenario=e)               # another run's scenario
        with self.assertRaises(P.Refused):
            self.run_ctrl(variant="ctrl", seed=e["seed"])                             # M6 seed on a pilot variant
        self.assertNotIn("m6", P.main.__code__.co_consts)


class TestTargetProcesses(unittest.TestCase):
    """FZ-WORKSET M-2: the target leaf holds exactly the workload and the scanner it forked."""

    def sysr(self, procs, ppid):
        s = FakeSys()
        s.procs.update({p: f"/{L.LAB}/target" for p in procs})
        s.ppid.update(ppid)
        return s

    def test_workload_and_its_scanner_in_either_order(self):
        self.assertEqual(P.target_processes(self.sysr((10, 20), {20: 10, 10: 1}), [10, 20]), (10, 20))
        self.assertEqual(P.target_processes(self.sysr((10, 20), {10: 20, 20: 1}), [10, 20]), (20, 10))

    def test_anything_else_aborts(self):
        for name, pids, ppid in (("only the workload", [10], {10: 1}),
                                 ("three processes", [10, 20, 30], {20: 10, 30: 10}),
                                 ("unrelated pair", [10, 20], {10: 1, 20: 1}),
                                 ("scanner of another parent", [10, 20], {20: 99, 10: 1}),
                                 ("unreadable parent", [10, 20], {})):
            with self.subTest(name), self.assertRaises(L.LabAbort):
                s = self.sysr(pids, ppid)
                if name == "unreadable parent":
                    s.procs.pop(20)                                    # /proc/20/stat unreadable
                P.target_processes(s, pids)


class TestReplaceControl(unittest.TestCase):
    def test_guard(self):
        g = L.Plan("PI8-s900020")
        self.assertEqual(g.check(("replace_control", b'{"pool": 1}')), ("replace_control", b'{"pool": 1}'))
        for bad in (("replace_control", "text"), ("replace_control", b""), ("replace_control", b"x" * 5000),
                    ("replace_control", b"{}", "extra")):
            with self.subTest(bad), self.assertRaises(L.LabRefused):
                g.check(bad)
        with self.assertRaises(L.LabRefused):
            L.Plan(None).check(("replace_control", b"{}"))

    def test_real_replacement_is_atomic_and_never_follows_a_symlink(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(L, "APP_ROOT", d + "/"):
            run = Path(L.run_dir("PI8-s900020"))
            run.mkdir()
            (run / "control.json").write_text('{"dependency_delay_ms": 2}')
            h = L.Host(L.Plan("PI8-s900020"), str(Path(d) / "ops.jsonl"), FakeSys())
            REAL_DO(h, ("replace_control", b'{"dependency_delay_ms": 2, "pool": 1}'), None, None)
            self.assertEqual((run / "control.json").read_bytes(), b'{"dependency_delay_ms": 2, "pool": 1}')
            self.assertEqual(sorted(p.name for p in run.iterdir()), ["control.json"])     # no temporary left
            outside = Path(d) / "outside.txt"
            outside.write_text("keep")
            (run / "control.json").unlink()
            (run / "control.json").symlink_to(outside)
            REAL_DO(h, ("replace_control", b'{"pool": 2}'), None, None)
            self.assertEqual(outside.read_text(), "keep")                  # the link is replaced, not followed
            self.assertFalse((run / "control.json").is_symlink())
            (run / L.CONTROL_NEW).write_text("stale")
            with self.assertRaises(FileExistsError):                        # exclusive temp: never reused
                REAL_DO(h, ("replace_control", b'{"pool": 3}'), None, None)


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
                               seed=kw.get("seed", 900001), execute=True, fault=kw.get("fault"),
                               magnitude=kw.get("magnitude"))

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

    def test_new_stages_have_the_same_pi0_gate_and_run_their_variant(self):
        camp = self.tmp / "20261012T000000Z"
        for cmd, prefix in (("pi1u", "PI1U"), ("pi6off", "PI6OFF"), ("instoff", "INSTOFF")):
            with self.subTest(cmd), mock.patch.object(P, "ctrl") as ct, self.assertRaises(P.Refused):
                P.run_stage(self.args(cmd, seed=900006), run_preflight=lambda: self.report())
            ct.assert_not_called()
        for k in range(1, 6):
            (camp / f"PI0-{k}").mkdir(parents=True)
            (camp / f"PI0-{k}" / "run.json").write_text(json.dumps({"ok": True, "commit": COMMIT}))
        for cmd, prefix in (("pi1u", "PI1U"), ("pi6off", "PI6OFF"), ("instoff", "INSTOFF")):
            with self.subTest(cmd), mock.patch.object(P, "ctrl", return_value=0) as ct:
                with self.assertRaises(P.Refused):                       # another commit's PI-0 does not qualify
                    P.run_stage(self.args(cmd, seed=900006), run_preflight=lambda: self.report(head="d" * 40))
                ct.assert_not_called()
                self.assertEqual(P.run_stage(self.args(cmd, seed=900006), run_preflight=lambda: self.report()), 0)
                self.assertEqual((ct.call_args.args[0].name, ct.call_args.args[1:3], ct.call_args.kwargs),
                                 (f"{prefix}-900006", (900006, COMMIT), {"variant": cmd}))
            with self.subTest(f"{cmd} seed range"), mock.patch.object(P, "ctrl") as ct, self.assertRaises(P.Refused):
                P.run_stage(self.args(cmd, seed=800000), run_preflight=lambda: self.report())

    def test_pi8_refuses_unapproved_faults_first_and_needs_pi0(self):
        approved = lambda name, rec=None: _RECORD[name]["value"]
        with mock.patch.object(P, "approved_value", side_effect=approved):
            for fault, mag in (("app_pool", 4), ("cpu_quota", 1)):
                with self.subTest((fault, mag)), mock.patch.object(P, "ctrl") as ct, self.assertRaises(P.Refused):
                    P.run_stage(self.args("pi8", seed=900020, fault=fault, magnitude=mag),
                                run_preflight=lambda: self.report())
                ct.assert_not_called()
            self.assertEqual(list(self.tmp.iterdir()), [])                      # refused before anything exists
            with mock.patch.object(P, "ctrl") as ct, self.assertRaises(P.Refused):   # no PI-0 yet
                P.run_stage(self.args("pi8", seed=900020, fault="app_pool", magnitude=1),
                            run_preflight=lambda: self.report())
            camp = self.tmp / "20261012T000000Z"
            for k in range(1, 6):
                (camp / f"PI0-{k}").mkdir(parents=True, exist_ok=True)
                (camp / f"PI0-{k}" / "run.json").write_text(json.dumps({"ok": True, "commit": COMMIT}))
            with mock.patch.object(P, "ctrl", return_value=0) as ct:
                self.assertEqual(P.run_stage(self.args("pi8", seed=900020, fault="app_lock", magnitude=2000),
                                             run_preflight=lambda: self.report()), 0)
            self.assertEqual((ct.call_args.args[0].name, ct.call_args.kwargs),
                             ("PI8-900020", {"variant": "pi8", "fault": ("app_lock", 2000)}))

    def test_magnitude_argument(self):
        self.assertEqual((P.magnitude_arg("1000"), P.magnitude_arg("0.5"), P.magnitude_arg("5")), (1000, 0.5, 5))
        self.assertIsInstance(P.magnitude_arg("1000"), int)
        self.assertIsInstance(P.magnitude_arg("2.0"), float)                    # "2.0" stays a float: never a candidate int
        for bad in ("nan", "inf", "x"):
            with self.subTest(bad), self.assertRaises((ValueError, P.argparse.ArgumentTypeError)):
                P.magnitude_arg(bad)

    def test_run_names_are_exact(self):
        for ok in ("PI0-1", "CTRL-900001", "PI1U-909999", "PI6OFF-900006", "INSTOFF-900006", "PI8-900020"):
            self.assertRegex(ok, f"^(?:{P.RUN_NAME})$")
        for bad in ("PI0-6", "CTRL-800001", "PI1U-90000", "FAULT-900001", "pi1u-900001", "PI6OFF-900006/x"):
            with self.subTest(bad), self.assertRaises(P.Refused):
                P.run_path(self.tmp, "20261012T000000Z", bad)

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
            self.assertIn("levels", P.approved_value("FZ-INTENSITY", f))   # closed 2026-10-13 (R-8)
            rec["decisions"]["FZ-INTENSITY"]["status"] = "pending"
            f.write_text(json.dumps(rec))
            with self.assertRaises(P.Refused):                       # pending is refused
                P.approved_value("FZ-INTENSITY", f)
            self.assertIn("criterion", P.approved_value("FZ-PI5", f))  # approved 2026-10-12 (M-1)
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
    def test_scratch_roots_agree_with_the_privileged_preflight(self):
        import preflight as PF
        self.assertEqual((PF.RUN_LAB, PF.WS_ROOT), (L.RUN_LAB, L.WS_ROOT))
        self.assertTrue(L.WS_ROOT.startswith("/var/tmp/"))            # ext4 on this host, never tmpfs (/run, /tmp)

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
            self.assertNotIn('"FZ-INTENSITY"', src.replace("FZ-INTENSITY, FZ-PI5 pending", ""))   # the parts are read
            self.assertNotIn('"FZ-PI5"', src)
            for memory_fault in ("memory.high", "memory_high"):              # AMD-12b fallback: not implemented
                self.assertNotIn(memory_fault, src, f)

    def test_no_protected_name_in_any_plan_or_argv(self):
        everything = repr(L.cgroup_plan() + L.lab_plan() + L.netns_del_plan() +
                          [L.forward_argv(ns, 1) for ns in L.LAB_NETNS] +
                          list(L.echo_argvs().values()) + [L.workload_argv("CTRL-s900001", WORKLOAD),
                                                           L.workload_argv("INSTOFF-s900001", WORKLOAD, False),
                                                           P.collector_argv("PI1U-s900001", Path("/o")),
                                                           L.dependency_argv("CTRL-s900001", WORKLOAD),
                                                           L.loadgen_argv(WORKLOAD, 1, 900001, "/o")])
        for p in L.PROTECTED + ("'tc'", "sysctl", "iptables", "nft", "modprobe", "smp_affinity", "rps_cpus"):
            self.assertNotIn(p, everything)


if __name__ == "__main__":
    unittest.main()
