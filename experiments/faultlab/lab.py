#!/usr/bin/env python3
"""SentinelAI Phase 1C FaultLab A–R–B lab (Gate 2): exact plans, the single mutation site, lab checks and cleanup.

Specification: docs/PHASE_1C_FREEZE1_DECISION_REGISTER.md §3 FZ-LAB-SPEC (approved 2026-10-11, 4b6041c); the driver
(pilot.py) refuses to run unless the privileged preflight is READY.

  namespaces  sentinel-lab-a (workload), sentinel-lab-r (router, no process), sentinel-lab-b (dependency peer and
              load generator; Q-4 option A)
  links       veth sentlab-a0 (A, 10.199.1.1/24) <-> sentlab-ra (R, 10.199.1.254/24);
              veth sentlab-rb (R, 10.199.2.254/24) <-> sentlab-b0 (B, 10.199.2.2/24); single queue
  routes      A: 10.199.2.0/24 via 10.199.1.254; B: 10.199.1.0/24 via 10.199.2.254; no default route anywhere;
              net.ipv4.ip_forward=1 inside R only (written by FWD_HELPER after checking the namespace inode)
  cgroup      /sys/fs/cgroup/sentinel-fl {target 18, contender 18, support 19,20,22,23}; cpuset cpu memory pids;
              parent memory.max 2560 MiB; memory.swap.max 0 everywhere; cpu.max untouched (max)
  app root    /run/sentinelai-lab/app/<run_id>/ (tmpfs, volatile; owned by uid 1000; removed at cleanup)

Pure except Host (the only mutation site: every operation is re-validated by check_op immediately before it runs and
logged as intent, then result) and the read-only Sys inherited from R2-E. Nothing here touches enp0s31f6, docker0,
host routes, host sysctls, IRQ affinity, RPS, tc on the host, or any cgroup outside sentinel-fl.
"""
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import r2c_cpu as C  # noqa: E402  (cpu lists, read-only Sys, host snapshot, LAB_UID; unchanged)
import r2e_softirq as E  # noqa: E402  (link/route parsers, host snapshot with lab netns/iface checks; unchanged)
from r2a_lab import PROTECTED  # noqa: E402

# ------------------------------------------------------------------------------------------ specification
NS_A, NS_R, NS_B = "sentinel-lab-a", "sentinel-lab-r", "sentinel-lab-b"
LAB_NETNS = (NS_A, NS_R, NS_B)
IF_A, IF_RA, IF_RB, IF_B = "sentlab-a0", "sentlab-ra", "sentlab-rb", "sentlab-b0"
IP_A, IP_RA, IP_RB, IP_B = "10.199.1.1", "10.199.1.254", "10.199.2.254", "10.199.2.2"
NET_A, NET_B, PREFIX = "10.199.1.0/24", "10.199.2.0/24", 24
PORT_WORKLOAD, PORT_DEPENDENCY = 8080, 9000
IFACES = {"a": (NS_A, (IF_A,)), "r": (NS_R, (IF_RA, IF_RB)), "b": (NS_B, (IF_B,))}

CG_ROOT = C.CG_ROOT
LAB = "sentinel-fl"
LAB_DIR = f"{CG_ROOT}/{LAB}"
TARGET_DIR, CONTENDER_DIR, SUPPORT_DIR = f"{LAB_DIR}/target", f"{LAB_DIR}/contender", f"{LAB_DIR}/support"
LEAVES = {"target": TARGET_DIR, "contender": CONTENDER_DIR, "support": SUPPORT_DIR}
LAB_DIRS = (LAB_DIR, TARGET_DIR, CONTENDER_DIR, SUPPORT_DIR)
TARGET_CGROUP_PATH = f"/{LAB}/target"
TARGET_CPU = 18
SUPPORT_CPUS = (19, 20, 22, 23)
PARENT_CPUS = (TARGET_CPU,) + SUPPORT_CPUS
DRIVER_CPUS = C.SUPPORT_CPUS                 # 0-15: driver, collector, loader (taskset at invocation)
LAB_MEMORY_MAX = str(2560 * 1024 * 1024)     # design §9: lab <= 2.5 GiB total
PIDS_MAX = {"target": "64", "contender": "4", "support": "256"}
LEAF_CPUS = {"target": (TARGET_CPU,), "contender": (TARGET_CPU,), "support": SUPPORT_CPUS}

RUN_LAB = "/run/sentinelai-lab"
APP_ROOT = f"{RUN_LAB}/app/"
LAB_UID = LAB_GID = C.LAB_UID                 # 1000
PYTHON = C.PYTHON                             # /usr/bin/python3 (workload and load generator: standard library)
WORKLOAD = str(ROOT / "experiments/faultlab/docker/workload.py")
LOADGEN = str(ROOT / "experiments/faultlab/docker/loadgen.py")
HARD_TIMEOUT_S = 900
RUN_ID = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*-s[0-9]+")
RUN_FILES = ("metrics.json", "config.json", "control.json", "dependency_config.json", "distractor.log")
TMP_FILE = re.compile(r"\.(metrics|config|dependency_config)\.json\.tmp\.[0-9]+")   # workload publish() temporaries

_LAUNCH = ("import importlib.util, sys; s = importlib.util.spec_from_file_location('faultlab_workload', sys.argv[1]); "
           "w = importlib.util.module_from_spec(s); s.loader.exec_module(w); w.APP_ROOT = sys.argv[2]; "
           "sys.exit(w.main(sys.argv[3:]))")
# Runs inside sentinel-lab-r via `ip netns exec`; refuses unless it is in the namespace whose inode the driver read,
# that namespace holds exactly lo + the two R veths, and the value read back is the one written.
FWD_HELPER = (
    "import os,sys\n"
    "ino=int(sys.argv[1])\n"
    "if os.stat('/proc/self/ns/net').st_ino!=ino:sys.exit(3)\n"
    "if sorted(os.listdir('/sys/class/net'))!=['lo','sentlab-ra','sentlab-rb']:sys.exit(4)\n"
    "p='/proc/sys/net/ipv4/ip_forward'\n"
    "fd=os.open(p,os.O_WRONLY|os.O_NOFOLLOW)\n"
    "os.write(fd,b'1');os.close(fd)\n"
    "sys.exit(0 if open(p).read().strip()=='1' else 5)\n")


class LabRefused(ValueError):
    """An operation outside the run's closed set was requested. Nothing was executed."""


class LabAbort(RuntimeError):
    """A run condition failed: stop, clean up, report."""


# ------------------------------------------------------------------------------------------ plans
def cgroup_plan() -> List[tuple]:
    ops = [("mkdir", LAB_DIR),
           ("write", f"{LAB_DIR}/cpuset.mems", C.MEMS),
           ("write", f"{LAB_DIR}/cpuset.cpus", C.cpus_text(PARENT_CPUS)),
           ("write", f"{LAB_DIR}/cgroup.subtree_control", " ".join(f"+{c}" for c in C.CONTROLLERS)),
           ("write", f"{LAB_DIR}/memory.max", LAB_MEMORY_MAX),
           ("write", f"{LAB_DIR}/memory.swap.max", "0")]
    for name in ("target", "contender", "support"):
        d = LEAVES[name]
        ops += [("mkdir", d),
                ("write", f"{d}/cpuset.cpus", C.cpus_text(LEAF_CPUS[name])),
                ("write", f"{d}/cpuset.mems", C.MEMS),
                ("write", f"{d}/memory.swap.max", "0"),
                ("write", f"{d}/pids.max", PIDS_MAX[name])]
    return ops


def _veth(a, ns_a, b, ns_b) -> tuple:
    return ("ip", "link", "add", a, "numtxqueues", "1", "numrxqueues", "1", "netns", ns_a, "type", "veth",
            "peer", "name", b, "numtxqueues", "1", "numrxqueues", "1", "netns", ns_b)


def lab_plan() -> List[tuple]:
    """The A–R–B topology as exact ip commands, in order (forwarding in R is a separate, checked op)."""
    cmds = [("ip", "netns", "add", n) for n in LAB_NETNS]
    cmds += [_veth(IF_A, NS_A, IF_RA, NS_R), _veth(IF_RB, NS_R, IF_B, NS_B)]
    cmds += [("ip", "-n", NS_A, "addr", "add", f"{IP_A}/{PREFIX}", "dev", IF_A),
             ("ip", "-n", NS_R, "addr", "add", f"{IP_RA}/{PREFIX}", "dev", IF_RA),
             ("ip", "-n", NS_R, "addr", "add", f"{IP_RB}/{PREFIX}", "dev", IF_RB),
             ("ip", "-n", NS_B, "addr", "add", f"{IP_B}/{PREFIX}", "dev", IF_B)]
    cmds += [("ip", "-n", n, "link", "set", "lo", "up") for n in LAB_NETNS]
    cmds += [("ip", "-n", NS_A, "link", "set", IF_A, "up"), ("ip", "-n", NS_R, "link", "set", IF_RA, "up"),
             ("ip", "-n", NS_R, "link", "set", IF_RB, "up"), ("ip", "-n", NS_B, "link", "set", IF_B, "up")]
    cmds += [("ip", "-n", NS_A, "route", "add", NET_B, "via", IP_RA, "dev", IF_A),
             ("ip", "-n", NS_B, "route", "add", NET_A, "via", IP_RB, "dev", IF_B)]
    return [("cmd", c) for c in cmds]


def netns_del_plan() -> List[tuple]:
    return [("cmd", ("ip", "netns", "del", n)) for n in reversed(LAB_NETNS)]


def forward_argv(ino: int) -> List[str]:
    return ["ip", "netns", "exec", NS_R, PYTHON, "-I", "-c", FWD_HELPER, str(int(ino))]


def run_dir(run_id: str) -> str:
    if not RUN_ID.fullmatch(run_id):
        raise LabRefused(f"malformed run id {run_id!r}")
    return f"{APP_ROOT}{run_id}"


def app_plan(run_id: str) -> List[tuple]:
    d = run_dir(run_id)
    return [("mkdir", RUN_LAB), ("mkdir", APP_ROOT.rstrip("/")), ("mkdir", d), ("chown_lab", d)]


# ------------------------------------------------------------------------------------------ process argv
WRAPPER = ["timeout", "-s", "KILL", str(HARD_TIMEOUT_S)]
DROP = ["setpriv", f"--reuid={LAB_UID}", f"--regid={LAB_GID}", "--init-groups", "--"]


def placed(leaf: str, ns: str, argv: List[str]) -> List[str]:
    """timeout (outside the lab) -> sh joins the leaf -> exec ip netns exec -> exec setpriv -> exec the program: one
    pid in the leaf, in the namespace, as the lab uid."""
    return WRAPPER + ["sh", "-c", f'echo $$ > {LEAVES[leaf]}/cgroup.procs && exec "$@"', "sh",
                      "ip", "netns", "exec", ns] + DROP + list(argv)


def workload_argv(run_id: str, w: dict) -> List[str]:
    return placed("target", NS_A, [PYTHON, "-I", "-c", _LAUNCH, WORKLOAD, APP_ROOT, "serve", "--run-id", run_id,
                                   "--listen", f"{IP_A}:{PORT_WORKLOAD}", "--pool", str(w["pool"]),
                                   "--queue", str(w["queue"]), "--cpu-us", str(w["cpu_us"]),
                                   "--lock-hold-us", str(w["lock_hold_us"]),
                                   "--lock-wait-exceeded-ms", str(w["lock_wait_exceeded_ms"]),
                                   "--dependency", f"{IP_B}:{PORT_DEPENDENCY}",
                                   "--dependency-timeout-ms", str(w["dependency_timeout_ms"]),
                                   "--publish-s", str(w["publish_s"]), "--poll-s", str(w["poll_s"])])


def dependency_argv(run_id: str, w: dict) -> List[str]:
    return placed("support", NS_B, [PYTHON, "-I", "-c", _LAUNCH, WORKLOAD, APP_ROOT, "dependency", "--run-id", run_id,
                                    "--listen", f"{IP_B}:{PORT_DEPENDENCY}", "--poll-s", str(w["poll_s"])])


def loadgen_argv(w: dict, duration_s: float, seed: int, out: str) -> List[str]:
    return placed("support", NS_B, [PYTHON, "-I", LOADGEN, "--target", f"{IP_A}:{PORT_WORKLOAD}",
                                    "--rate", str(w["rate_per_s"]), "--duration-s", str(duration_s),
                                    "--jitter", str(w["jitter"]), "--seed", str(seed),
                                    "--timeout-s", str(w["timeout_s"]), "--max-inflight", str(w["max_inflight"]),
                                    "--out", out])


ECHO_SERVER = ("import socket,sys\n"
               "s=socket.create_server((sys.argv[1],int(sys.argv[2])));s.settimeout(10)\n"
               "c,_=s.accept();c.settimeout(5);c.sendall(c.recv(64));c.close()\n")
ECHO_CLIENT = ("import socket,sys\n"
               "c=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=5);c.sendall(b'ECHO-OK')\n"
               "sys.exit(0 if c.recv(64)==b'ECHO-OK' else 1)\n")


def echo_argvs() -> Dict[str, List[str]]:
    return {"echo_server": placed("support", NS_B, [PYTHON, "-I", "-c", ECHO_SERVER, IP_B, str(PORT_DEPENDENCY)]),
            "echo_client": placed("target", NS_A, [PYTHON, "-I", "-c", ECHO_CLIENT, IP_B, str(PORT_DEPENDENCY)])}


# ------------------------------------------------------------------------------------------ read-only inspection
LAB_READS = {f"{side}_{what}": ("ip", "-n", ns) + args
             for side, (ns, _) in IFACES.items()
             for what, args in (("links", ("-s", "-j", "-d", "link", "show")), ("addrs", ("-j", "addr", "show")),
                                ("routes", ("-j", "route", "show")), ("routes6", ("-j", "-6", "route", "show")))}
ROUTE_GET = {side: ("ip", "-n", ns, "route", "get", "8.8.8.8") for side, (ns, _) in IFACES.items()}
PING = {"a_to_b": ("ip", "netns", "exec", NS_A, "ping", "-c", "3", "-i", "0.2", "-W", "1", IP_B),
        "b_to_a": ("ip", "netns", "exec", NS_B, "ping", "-c", "3", "-i", "0.2", "-W", "1", IP_A)}
FORWARD_READS = {side: ("ip", "netns", "exec", ns, "cat", "/proc/sys/net/ipv4/ip_forward")
                 for side, (ns, _) in IFACES.items()}


class Sys(C.Sys):
    """Read-only host view (R2-C) plus the exact lab inspection commands. `probe` returns (rc, stdout, stderr)."""

    READ = set(LAB_READS.values()) | set(ROUTE_GET.values()) | set(PING.values()) | set(FORWARD_READS.values())

    def probe(self, argv) -> Optional[tuple]:
        if tuple(argv) not in self.READ:
            raise LabRefused(f"not a lab read: {argv}")
        try:
            p = subprocess.run(list(argv), capture_output=True, text=True, timeout=15, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return p.returncode, p.stdout, p.stderr

    def run(self, argv):
        if tuple(argv) in self.READ:
            r = self.probe(argv)
            return r[1] if r and r[0] == 0 else None
        return super().run(argv)

    @staticmethod
    def _run_lab_path(path) -> str:
        p = str(path)
        if not (p == RUN_LAB or p.startswith(RUN_LAB + "/")) or "/../" in p or p.endswith("/..") or "\x00" in p:
            raise LabRefused(f"not under {RUN_LAB}: {p!r}")
        return p

    def lstat_run(self, path):
        """os.lstat of a path under /run/sentinelai-lab, None if absent (read-only)."""
        try:
            return os.lstat(self._run_lab_path(path))
        except FileNotFoundError:
            return None

    def listdir_run(self, path) -> List[str]:
        try:
            return sorted(os.listdir(self._run_lab_path(path)))
        except FileNotFoundError:
            return []

    def read_run(self, path, limit: int) -> bytes:
        """A regular file under /run/sentinelai-lab (written by the lab uid), never via a symlink, <= limit bytes."""
        fd = os.open(self._run_lab_path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
                raise LabAbort(f"{path}: not a regular file of at most {limit} bytes")
            data = os.read(fd, limit + 1)
            if len(data) > limit:
                raise LabAbort(f"{path}: larger than {limit} bytes")
            return data
        finally:
            os.close(fd)

    @staticmethod
    def pid_netns_inode(pid: int) -> Optional[int]:
        try:
            return os.stat(f"/proc/{int(pid)}/ns/net").st_ino
        except OSError:
            return None

    def netns_inode(self, ns) -> Optional[int]:
        if ns not in LAB_NETNS:
            raise LabRefused(f"not a lab namespace: {ns!r}")
        try:
            return os.stat(f"/run/netns/{ns}").st_ino
        except OSError:
            return None


def lab_state(sysr) -> dict:
    """Raw inspection texts of one lab check (saved before evaluation)."""
    raw = {k: sysr.probe(argv) for k, argv in LAB_READS.items()}
    raw.update({f"route_get_{s}": sysr.probe(argv) for s, argv in ROUTE_GET.items()})
    raw.update({f"forward_{s}": sysr.probe(argv) for s, argv in FORWARD_READS.items()})
    return raw


def _out(raw, key) -> Optional[str]:
    r = raw.get(key)
    return r[1] if isinstance(r, (list, tuple)) and len(r) == 3 and r[0] == 0 else None


def _addrs(text) -> Optional[Dict[str, List[tuple]]]:
    try:
        doc = json.loads(text)
        return {a["ifname"]: sorted((i["local"], i["prefixlen"]) for i in a.get("addr_info", [])
                                    if i.get("family") == "inet") for a in doc}
    except (TypeError, ValueError, KeyError):
        return None


EXPECTED_ADDRS = {"a": {IF_A: [(IP_A, PREFIX)]}, "r": {IF_RA: [(IP_RA, PREFIX)], IF_RB: [(IP_RB, PREFIX)]},
                  "b": {IF_B: [(IP_B, PREFIX)]}}
EXPECTED_ROUTES = {"a": sorted([(NET_A, IF_A), (NET_B, IF_A)]), "r": sorted([(NET_A, IF_RA), (NET_B, IF_RB)]),
                   "b": sorted([(NET_B, IF_B), (NET_A, IF_B)])}
EXPECTED_FORWARD = {"a": "0", "r": "1", "b": "0"}


def lab_checks(raw: dict, after_forward: bool = True) -> Dict[str, bool]:
    """Structure of the lab from one raw inspection: interfaces, addresses, routes, no default route, no external path,
    forwarding only in R. An unobservable item is a failure, never a pass."""
    c = {}
    for side, (ns, ifs) in IFACES.items():
        links = E.links(_out(raw, f"{side}_links"))
        addrs = _addrs(_out(raw, f"{side}_addrs"))
        rt, rt6 = E.routes(_out(raw, f"{side}_routes")), E.routes(_out(raw, f"{side}_routes6"))
        if links is None or addrs is None or rt is None or rt6 is None:
            c[f"{side}_observable"] = False
            continue
        c[f"{side}_only_lo_and_lab_veths"] = sorted(links) == sorted(("lo",) + ifs)
        for i in ifs:
            v = links.get(i) or {}
            c[f"{side}_{i}_veth_up"] = v.get("kind") == "veth" and v.get("up") is True
            c[f"{side}_{i}_single_queue"] = v.get("txq") == 1 and v.get("rxq") == 1
        c[f"{side}_lo_up"] = (links.get("lo") or {}).get("up") is True
        c[f"{side}_addresses"] = {k: v for k, v in addrs.items() if k != "lo"} == EXPECTED_ADDRS[side]
        c[f"{side}_routes"] = sorted((d, dev) for d, dev in rt) == EXPECTED_ROUTES[side]
        c[f"{side}_no_default_route"] = not any(d == "default" for d, _ in rt + rt6)
        g = raw.get(f"route_get_{side}")
        c[f"{side}_no_external_path"] = isinstance(g, (list, tuple)) and len(g) == 3 and g[0] != 0 and \
            "unreachable" in (g[2] or "").lower()
        if after_forward:
            f = _out(raw, f"forward_{side}")
            c[f"{side}_ip_forward"] = f is not None and f.strip() == EXPECTED_FORWARD[side]
    return c


def failures(checks: Dict[str, bool]) -> List[str]:
    return ["unobservable"] if not checks else sorted(k for k, v in checks.items() if v is not True)


def ping_ok(r) -> bool:
    return isinstance(r, (list, tuple)) and len(r) == 3 and r[0] == 0 and " 0% packet loss" in (r[1] or "")


def r_counters(sysr) -> Optional[Dict[str, dict]]:
    """Packet and drop counters of R's two interfaces (ip -s -j link in R)."""
    out = _out({"x": sysr.probe(LAB_READS["r_links"])}, "x")
    try:
        doc = json.loads(out)
        res = {}
        for l in doc:
            if l["ifname"] in (IF_RA, IF_RB):
                s = l["stats64"]
                res[l["ifname"]] = {"rx_packets": s["rx"]["packets"], "tx_packets": s["tx"]["packets"],
                                    "rx_dropped": s["rx"]["dropped"], "tx_dropped": s["tx"]["dropped"],
                                    "rx_errors": s["rx"]["errors"], "tx_errors": s["tx"]["errors"]}
        return res if set(res) == {IF_RA, IF_RB} else None
    except (TypeError, ValueError, KeyError):
        return None


def tcp_counters(snmp_text) -> Optional[Dict[str, int]]:
    """OutSegs, InSegs and RetransSegs from a /proc/<pid>/net/snmp text."""
    lines = [l.split() for l in (snmp_text or "").splitlines() if l.startswith("Tcp:")]
    if len(lines) != 2:
        return None
    try:
        d = dict(zip(lines[0][1:], (int(x) for x in lines[1][1:])))
        return {k: d[k] for k in ("OutSegs", "InSegs", "RetransSegs")}
    except (ValueError, KeyError):
        return None


def verify_cgroups(sysr) -> Dict[str, bool]:
    r = lambda d, f: (sysr.read(f"{d}/{f}") or "").strip()
    c = {"parent_subtree_control": set(r(LAB_DIR, "cgroup.subtree_control").split()) == set(C.CONTROLLERS),
         "parent_cpus": C.parse_cpulist(r(LAB_DIR, "cpuset.cpus.effective")) == set(PARENT_CPUS),
         "parent_memory_max": r(LAB_DIR, "memory.max") == LAB_MEMORY_MAX,
         "parent_swap_0": r(LAB_DIR, "memory.swap.max") == "0"}
    for name, d in LEAVES.items():
        c[f"{name}_cpus"] = C.parse_cpulist(r(d, "cpuset.cpus.effective")) == set(LEAF_CPUS[name])
        c[f"{name}_swap_0"] = r(d, "memory.swap.max") == "0"
        c[f"{name}_pids_max"] = r(d, "pids.max") == PIDS_MAX[name]
        c[f"{name}_no_quota"] = r(d, "cpu.max") == C.CPU_MAX_UNLIMITED
        c[f"{name}_empty"] = sysr.read(f"{d}/cgroup.procs") is not None and r(d, "cgroup.procs") == ""
    return c


# ------------------------------------------------------------------------------------------ mutation guard
FORBIDDEN = ("enp0s31f6", "docker0", "tc", "sysctl", "modprobe", "iptables", "nft", "smp_affinity", "rps_cpus",
             "cpu.max")


class Plan:
    """The closed set of operations one invocation may perform."""

    def __init__(self, run_id: Optional[str] = None, spawns: Iterable[tuple] = ()):
        self.writes = {(op[1], op[2]) for op in cgroup_plan() if op[0] == "write"} | \
            {(f"{LAB_DIR}/cgroup.kill", "1")}
        self.cmds = {op[1] for op in lab_plan() + netns_del_plan()}
        self.dirs = set(LAB_DIRS)
        self.run_dirs = set()
        if run_id is not None:
            self.run_dirs = {op[1] for op in app_plan(run_id) if op[0] == "mkdir"}
        self.spawns = {(role, tuple(argv)) for role, argv in spawns}
        self.run_id = run_id

    def check(self, op) -> tuple:
        if not isinstance(op, tuple) or not op or not isinstance(op[0], str):
            raise LabRefused(f"malformed operation {op!r}")
        text = repr(op)
        for p in PROTECTED:
            if p in text:
                raise LabRefused(f"protected interface {p} in operation")
        kind = op[0]
        if kind in ("mkdir", "rmdir"):
            if len(op) != 2 or (op[1] not in self.dirs and op[1] not in self.run_dirs):
                raise LabRefused(f"{kind} outside the lab: {op!r}")
        elif kind == "write":
            if len(op) != 3 or (op[1], op[2]) not in self.writes:
                raise LabRefused(f"write not allowed: {op!r}")
        elif kind == "cmd":
            if len(op) != 2 or not isinstance(op[1], tuple) or op[1] not in self.cmds or \
                    any(t in op[1] for t in FORBIDDEN):
                raise LabRefused(f"command not allowed: {op!r}")
        elif kind == "forward":
            if len(op) != 2 or isinstance(op[1], bool) or not isinstance(op[1], int) or op[1] <= 0:
                raise LabRefused(f"malformed forward {op!r}")
        elif kind == "chown_lab":
            if len(op) != 2 or self.run_id is None or op[1] != run_dir(self.run_id):
                raise LabRefused(f"chown outside the run directory: {op!r}")
        elif kind == "write_new":
            if len(op) != 3 or self.run_id is None or op[1] != f"{run_dir(self.run_id)}/control.json" or \
                    not isinstance(op[2], bytes):
                raise LabRefused(f"file write not allowed: {op!r}")
        elif kind == "unlink_run":
            name = os.path.basename(op[1]) if len(op) == 2 and isinstance(op[1], str) else ""
            if len(op) != 2 or self.run_id is None or os.path.dirname(op[1]) != run_dir(self.run_id) or \
                    not (name in RUN_FILES or TMP_FILE.fullmatch(name)):
                raise LabRefused(f"unlink outside the run files: {op!r}")
        elif kind == "spawn":
            if len(op) != 3 or (op[1], tuple(op[2])) not in self.spawns:
                raise LabRefused(f"spawn not in the plan: {op[1]!r}")
        elif kind == "kill":
            if len(op) != 2 or isinstance(op[1], bool) or not isinstance(op[1], int) or op[1] <= 1:
                raise LabRefused(f"malformed kill {op!r}")
        else:
            raise LabRefused(f"operation {kind!r} is not authorised")
        return op


class Host:
    """The single mutation site. Every operation is re-validated by plan.check and logged (intent, result)."""

    def __init__(self, plan: Plan, oplog: str, sysr=None):
        self.plan, self.oplog, self.sys = plan, oplog, sysr or Sys()

    def _log(self, **kw):
        with open(self.oplog, "a") as fh:
            fh.write(json.dumps({"t": time.monotonic(), **kw}, sort_keys=True, default=str) + "\n")

    @staticmethod
    def _desc(op):
        return [op[0], list(op[1]) if op[0] == "cmd" else op[1]] + ([len(op[2])] if op[0] == "write_new" else [])

    def apply(self, op, stdout=None, stderr=None):
        self.plan.check(op)
        self._log(phase="intent", op=self._desc(op))
        try:
            res = self._do(op, stdout, stderr)
        except OSError as exc:
            self._log(phase="result", op=self._desc(op), ok=False, err=str(exc))
            raise
        self._log(phase="result", op=self._desc(op), ok=True, pid=getattr(res, "pid", None))
        return res

    def _do(self, op, stdout, stderr):
        kind = op[0]
        if kind == "mkdir":
            os.mkdir(op[1], 0o755 if not op[1].startswith(APP_ROOT) else 0o700)
        elif kind == "rmdir":
            os.rmdir(op[1])
        elif kind == "write":
            with open(op[1], "w") as fh:
                fh.write(op[2])
        elif kind == "cmd":
            p = subprocess.run(list(op[1]), capture_output=True, text=True, timeout=15, shell=False)
            if p.returncode != 0:
                raise OSError(f"{' '.join(op[1][:5])} failed (rc {p.returncode}): {p.stderr.strip()[:200]}")
        elif kind == "forward":
            p = subprocess.run(forward_argv(op[1]), capture_output=True, text=True, timeout=15, shell=False)
            if p.returncode != 0:
                raise OSError(f"forwarding helper refused or failed (rc {p.returncode})")
        elif kind == "chown_lab":
            fd = os.open(op[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchown(fd, LAB_UID, LAB_GID)
            finally:
                os.close(fd)
        elif kind == "write_new":
            fd = os.open(op[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
            try:
                os.write(fd, op[2])
            finally:
                os.close(fd)
        elif kind == "unlink_run":
            st = os.lstat(op[1])
            if not stat.S_ISREG(st.st_mode):
                raise OSError(f"not a regular file: {op[1]}")
            os.unlink(op[1])
        elif kind == "spawn":
            return subprocess.Popen(list(op[2]), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    shell=False, start_new_session=True)
        elif kind == "kill":
            if f"::/{LAB}/" not in (self.sys.read(f"/proc/{op[1]}/cgroup") or ""):
                return None                   # gone, or not a lab process: never signalled
            os.kill(op[1], signal.SIGKILL)
        return None


# ------------------------------------------------------------------------------------------ cleanup
def read_oplog(path) -> List[dict]:
    return C.read_oplog(path)


def created(entries: List[dict]) -> dict:
    """What this invocation created, from successful results in its op log."""
    ok = [e["op"] for e in entries if e.get("phase") == "result" and e.get("ok")]
    return {"dirs": [o[1] for o in ok if o[0] == "mkdir"],
            "netns": [o[1][3] for o in ok if o[0] == "cmd" and o[1][:3] == ["ip", "netns", "add"]],
            "pids": [e.get("pid") for e in entries if e.get("phase") == "result" and e.get("ok")
                     and e["op"][0] == "spawn" and e.get("pid")]}


def lab_pids(sysr) -> List[int]:
    return [p for p in sysr.pids() if f"::/{LAB}/" in (sysr.read(f"/proc/{p}/cgroup") or "")]


def cleanup(host: Host, sysr, entries: List[dict], run_id: Optional[str], wait_s: float = 5.0,
            sleep=time.sleep, after_procs=None) -> dict:
    """Idempotent cleanup of what this invocation created, in order: lab processes (cgroup.kill) -> after_procs (the
    eBPF loader release) -> run files and app directories -> lab cgroups (leaves first) -> lab namespaces. Never
    touches anything the op log does not show as created by this invocation."""
    st = created(entries)
    steps, errors = [], []

    def step(name, fn):
        try:
            fn()
            steps.append(name)
        except Exception as exc:                       # noqa: BLE001 -- recorded; cleanup continues
            errors.append(f"{name}: {exc!r}")

    ours = LAB_DIR in st["dirs"]
    deadline = time.monotonic() + wait_s
    while ours and sysr.exists(LAB_DIR):
        populated = "populated 1" in (sysr.read(f"{LAB_DIR}/cgroup.events") or "")
        if populated or "cgroup.kill" not in steps:
            step("cgroup.kill", lambda: host.apply(("write", f"{LAB_DIR}/cgroup.kill", "1")))
        if not populated or time.monotonic() >= deadline:
            break
        sleep(0.05)
    if after_procs is not None:
        step("after_procs", after_procs)
    if run_id is not None and run_dir(run_id) in st["dirs"]:
        for name in sysr.listdir_run(run_dir(run_id)):   # only run files and publish temporaries; anything else stays
            path = f"{run_dir(run_id)}/{name}"
            if name in RUN_FILES or TMP_FILE.fullmatch(name):
                step(f"unlink {name}", lambda path=path: host.apply(("unlink_run", path)))
            else:
                errors.append(f"unexpected file in the run directory (kept): {name!r}")
    for d in ((run_dir(run_id),) if run_id is not None else ()) + (APP_ROOT.rstrip("/"), RUN_LAB):
        if d in st["dirs"] and sysr.lstat_run(d) is not None:     # each one only if this invocation created it
            step(f"rmdir {d}", lambda d=d: host.apply(("rmdir", d)))
    for d in (SUPPORT_DIR, CONTENDER_DIR, TARGET_DIR, LAB_DIR):
        if d in st["dirs"] and sysr.exists(d):
            step(f"rmdir {d}", lambda d=d: host.apply(("rmdir", d)))
    for op in netns_del_plan():
        if op[1][3] in st["netns"] and sysr.exists(f"/run/netns/{op[1][3]}"):
            step(f"netns del {op[1][3]}", lambda op=op: host.apply(op))
    v = cleanup_state(sysr, st["pids"], run_id)
    return {"ok": not errors and v["ok"], "steps": steps, "errors": errors, "verify": v}


def cleanup_state(sysr, pids=(), run_id: Optional[str] = None) -> dict:
    c = {"lab_cgroup_absent": not sysr.exists(LAB_DIR), "no_sentinel_cgroup": not C.sentinel_cgroups(sysr),
         "no_lab_process": not lab_pids(sysr),
         "no_logged_pid_alive_in_lab": not [p for p in pids
                                            if f"::/{LAB}/" in (sysr.read(f"/proc/{p}/cgroup") or "")],
         "no_lab_netns": not E.lab_netns_present(sysr), "no_lab_interface_in_host": not E.host_lab_ifaces(sysr),
         "run_lab_absent": sysr.lstat_run(RUN_LAB) is None}
    return {"ok": all(c.values()), "checks": c}


def host_snapshot(sysr, require_bpf=True) -> dict:
    snap = E.host_snapshot(sysr, require_bpf)
    snap["run_lab_present"] = sysr.lstat_run(RUN_LAB) is not None
    return snap


def compare_host(base: dict, other: dict, require_bpf=True) -> dict:
    """R2-E's comparison (R2-C must-list, host RPS, no lab netns, no lab interface) plus /run/sentinelai-lab absent."""
    r = E.compare_host(base, other, require_bpf)
    r["run_lab_absent"] = not other.get("run_lab_present", False)
    if not r["run_lab_absent"]:
        r["failed"].append("run_lab_absent")
    r["ok"] = not r["failed"]
    return r


def preflight(sysr) -> dict:
    """Read-only refusal conditions immediately before setup (the privileged preflight ran just before)."""
    c = {"no_sentinel_cgroup": not C.sentinel_cgroups(sysr), "no_lab_process": not lab_pids(sysr),
         "no_lab_netns": not E.lab_netns_present(sysr), "no_lab_interface_in_host": not E.host_lab_ifaces(sysr),
         "run_lab_absent": sysr.lstat_run(RUN_LAB) is None,
         "root_cpuset_0_23": C.parse_cpulist(sysr.read(f"{CG_ROOT}/cpuset.cpus.effective")) == C.HOST_CPUS}
    return {"ok": all(c.values()), "checks": c}
