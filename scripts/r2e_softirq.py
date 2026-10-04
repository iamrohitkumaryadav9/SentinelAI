#!/usr/bin/env python3
"""SentinelAI R2-E: controlled softirq overload (RPS-steered veth NET_RX onto CPU 18): guards, ground truth, cleanup.

The approved design (R2-E SOFTIRQ OVERLOAD DESIGN: READY; decisions D1-D6 approved; single-queue lab veth approved):
  lab        R2-A topology (sentinel-lab-a 10.199.0.1 sentlab-a0 <-> sentinel-lab-b 10.199.0.2 sentlab-b0, no default
             route), created per run by this tooling with numtxqueues 1 numrxqueues 1 on both veth ends so every
             packet uses rx-0 of sentlab-b0
  RPS        the ONLY new mutation: sentinel-lab-b:/sys/class/net/sentlab-b0/queues/rx-0/rps_cpus, values 40000 (CPU 18),
             80000 (CPU 19, N2), 0; read-before -> validate -> write -> read-after -> log; reset to 0 and verified BEFORE
             the lab namespaces are deleted (deleting a veth with an RPS map leaks the kernel's rps_needed key)
  cgroups    /sys/fs/cgroup/sentinel-r2c {target (18), contender (18, N1 only), traffic (20,22,23)}; cpu.max never written
  target     R2-C r2c_target.py (unchanged) on CPU 18, private interface-less netns, uid 1000
  traffic    iperf3 3.9 UDP, 64-byte payload: clients in sentinel-lab-a on CPUs 20 and 22, servers in sentinel-lab-b on
             CPU 23, uid 1000; never on CPU 18
  truth      GP GN GS GV GI G0 G6' GL GC G7 GR, computed by evaluate() / restore_record() from saved raw inputs only

Sys only reads. Host is the single mutation site; every operation is re-validated by check_op() right before it runs.
"""

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import r2c_cpu as C  # noqa: E402  (R2-C boundary, parsers, host snapshot, BPF release; unchanged)
from r2a_lab import LAB as R2A_LAB, PROTECTED  # noqa: E402  (the R2-A topology names and addresses)

REPO = C.REPO
sys.path.insert(0, str(REPO / "src"))
from r2b_driver import NUMBERS  # noqa: E402  (validation parameter values, unchanged)

# ------------------------------------------------------------------------------------------ design constants
NS_A, NS_B, IF_A, IF_B = R2A_LAB["ns_a"], R2A_LAB["ns_b"], R2A_LAB["if_a"], R2A_LAB["if_b"]
IP_A, IP_B, PREFIX, SUBNET = R2A_LAB["ip_a"], R2A_LAB["ip_b"], R2A_LAB["prefix"], R2A_LAB["subnet"]
LAB_NETNS = (NS_A, NS_B)

LAB_DIR, TARGET_DIR, CONTENDER_DIR = C.LAB_DIR, C.TARGET_DIR, C.CONTENDER_DIR
TRAFFIC_DIR = f"{C.LAB_DIR}/traffic"
LAB_DIRS = (LAB_DIR, TARGET_DIR, CONTENDER_DIR, TRAFFIC_DIR)
LEAVES = (("target", TARGET_DIR), ("contender", CONTENDER_DIR), ("traffic", TRAFFIC_DIR))

TARGET_CPU = C.TARGET_CPU                    # 18
SENDER_CPUS = (20, 22)
RECEIVER_CPU = 23
N2_RPS_CPU = 19
PARENT_CPUS = (TARGET_CPU,) + SENDER_CPUS + (RECEIVER_CPU,)
TRAFFIC_CPUS = SENDER_CPUS + (RECEIVER_CPU,)
EXPERIMENT_CPUS = frozenset(PARENT_CPUS) | {N2_RPS_CPU}   # the NIC IRQ may never be on these
SUPPORT_CPUS = C.SUPPORT_CPUS                # 0-15: driver, collector, loader
TRAFFIC_PIDS_MAX = "8"
CONTENDER_WEIGHT_N1 = 400                    # the R2-C E2 contender (contention established in R2-C)

RPS_REL = f"/sys/class/net/{IF_B}/queues/rx-0/rps_cpus"
RPS_REAL = f"/sys/devices/virtual/net/{IF_B}/queues/rx-0/rps_cpus"
RPS_VALUES = {"40000": TARGET_CPU, "80000": N2_RPS_CPU, "0": None}
RPS_READBACK = {"40000": "040000", "80000": "080000", "0": "000000"}
RPS_ZERO = RPS_READBACK["0"]

IPERF3 = "/usr/bin/iperf3"
PORTS = (5201, 5202)
UDP_LEN = 64
CLIENT_T = C.NW + 1                          # starts in the window callback, outlives the last W tick by ~1 s
LADDER_START_PPS = 10_000
LADDER_STEPS_MAX = 8                         # 10k .. 1.28M packets/s in total (doubling)
LADDER_PPS = tuple(LADDER_START_PPS * 2 ** k for k in range(LADDER_STEPS_MAX))
LADDER_STEP_S = 5
LADDER_SETTLE_S, LADDER_MEASURE_S = 0.5, 4.0

# Validation parameters (r2b NUMBERS, uncalibrated) and existing safety limits -- referenced, never changed.
SI_ABS_MIN = NUMBERS["SI_ABS_MIN"]           # 0.5
SI_RATIO_MIN = NUMBERS["SI_RATIO_MIN"]       # 3.0
SI_SHARE_MIN = NUMBERS["SI_SHARE_MIN"]       # 0.5
RDX_MIN = NUMBERS["RDX_MIN"]                 # 0.05
FLOOR = 1e-3                                 # the validation parameter set's floor (r2c_driver.params)
G6_MAX = C.G6_FOREIGN_MAX_CORES              # 0.05
PF_KTHREAD = 0x00200000
KTHREAD_CPU18 = re.compile(r"^[a-z_]+/18(:\S*)?$")

TOOLING = ("scripts/r2e_softirq.py", "scripts/r2e_driver.py", "scripts/r2e_validate.sh", "tests/faultlab/test_r2e.py")
BASE_COMMIT = "d11e755"
CRITERIA = {
    "GS": {"value": f"S2/S3: eBPF NET_RX(18) in W >= SI_ABS_MIN {SI_ABS_MIN} and >= SI_RATIO_MIN {SI_RATIO_MIN} x "
                    f"max(B, floor {FLOOR}); S1: rise >= SI_RATIO_MIN x max(B, floor) and < SI_ABS_MIN - delta; "
                    "E0/N1/N2: NET_RX(18) in W < SI_RATIO_MIN x max(B, floor); processed(rps cpu) >= sentlab-b0 rx - "
                    "netdev_max_backlog; NET_RX(18) <= precise non-idle(18) + 2 jiffies", "type": "DESIGN (approved)"},
    "GV": {"value": f"NET_RX >= SI_SHARE_MIN {SI_SHARE_MIN} of all softirq time on CPU 18 in W (S1-S3)",
           "type": "DESIGN (approved)"},
    "GI": {"value": f"target run_delay rate W - B >= RDX_MIN {RDX_MIN} and target cpu.pressure some W > B (S2/S3)",
           "type": "DESIGN (approved)"},
    "G6p": {"value": f"(rq_cpu_time(18) - target - N1 contender - per-CPU-18 kthreads) / s <= {G6_MAX} in B and W",
            "type": "R2-C limit, reused"},
    "LADDER": {"value": f"{LADDER_PPS[0]}..{LADDER_PPS[-1]} pps doubling, {LADDER_STEP_S} s per step, stop at first "
                        "loss; delta = max|frac - eBPF|; S1 = highest below SI_ABS_MIN - delta (both measures); S2 = "
                        "lowest eBPF NET_RX >= SI_ABS_MIN + delta; S3 = highest loss-free above S2",
               "type": "DESIGN (approved); provenance only"},
}


@dataclass(frozen=True)
class Experiment:
    kind: str
    lab: bool                   # lab namespaces + veth + RPS
    rps: Optional[str]          # RPS value written for the run
    traffic: Optional[str]      # level of the W traffic (S1 | S2 | S3), "LADDER", or None
    contender: bool             # R2-C E2 contender on CPU 18 during W
    contender_weight: int = 100


EXPERIMENTS = {
    "CAL": Experiment("CAL", False, None, None, False),
    "LADDER": Experiment("LADDER", True, "40000", "LADDER", False),
    "E0": Experiment("E0", True, "40000", None, False),
    "S1": Experiment("S1", True, "40000", "S1", False),
    "S2": Experiment("S2", True, "40000", "S2", False),
    "S3": Experiment("S3", True, "40000", "S3", False),
    "N1": Experiment("N1", True, "40000", None, True, CONTENDER_WEIGHT_N1),
    "N2": Experiment("N2", True, "80000", "S3", False),
}
MATRIX = ("E0-open", "S1-1", "S1-2", "S2-1", "S2-2", "S2-3", "S3-1", "S3-2", "S3-3", "N1-1", "N1-2", "N2-1", "N2-2",
          "E0-close")


class R2ERefused(C.R2CRefused):
    """An operation outside the R2-E authorisation."""


class RpsAbort(C.LabAbort):
    """An RPS read-back, previous-value or restoration check failed: hard abort."""


def experiment_of(label: str) -> Experiment:
    if label not in MATRIX:
        raise R2ERefused(f"run {label!r} is not in the approved R2-E matrix")
    return EXPERIMENTS[label.split("-")[0]]


def allocation_checks() -> Dict[str, bool]:
    """The approved CPU allocation (D6), checked as data."""
    return {
        "generators_off_target": TARGET_CPU not in TRAFFIC_CPUS,
        "senders_20_22": SENDER_CPUS == (20, 22), "receiver_23": RECEIVER_CPU == 23,
        "nic_cpu_excluded": C.NIC_CPU not in EXPERIMENT_CPUS,
        "support_cpus_disjoint": not set(SUPPORT_CPUS) & EXPERIMENT_CPUS,
        "n2_cpu_19_no_process": N2_RPS_CPU not in PARENT_CPUS,
        "rps_values": set(RPS_VALUES) == {"40000", "80000", "0"} and RPS_VALUES["40000"] == 18
        and RPS_VALUES["80000"] == 19 and int("40000", 16) == 1 << 18 and int("80000", 16) == 1 << 19,
        "matrix_14": len(MATRIX) == 14 and len(set(MATRIX)) == 14,
    }


# ------------------------------------------------------------------------------------------ parsers (pure)
def softnet(text) -> Optional[Dict[int, Dict[str, int]]]:
    """/proc/net/softnet_stat -> {cpu: {processed, dropped, time_squeeze, received_rps}} (cpu id = column 13)."""
    if not text:
        return None
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) < 13 or not all(re.fullmatch(r"[0-9a-f]{8}", x) for x in f):
            return None
        cpu = int(f[12], 16)
        if cpu in out:
            return None
        out[cpu] = {"processed": int(f[0], 16), "dropped": int(f[1], 16), "time_squeeze": int(f[2], 16),
                    "received_rps": int(f[9], 16)}
    return out or None


def softirqs(text) -> Optional[Dict[str, List[int]]]:
    """/proc/softirqs -> {vector: [count per CPU column]}."""
    if not text:
        return None
    lines = text.splitlines()
    ncpu = len(lines[0].split()) if lines else 0
    out = {}
    for line in lines[1:]:
        name, _, rest = line.partition(":")
        vals = rest.split()[:ncpu]
        if len(vals) != ncpu or not all(v.isdigit() for v in vals):
            return None
        out[name.strip()] = [int(v) for v in vals]
    return out or None


def task_stat(text) -> Optional[dict]:
    """/proc/<pid>/stat -> {comm, state, flags, processor} (comm may contain spaces and parentheses)."""
    if not text or "(" not in text or ")" not in text:
        return None
    comm = text[text.index("(") + 1:text.rindex(")")]
    rest = text.rsplit(")", 1)[1].split()
    if len(rest) <= 36:
        return None
    return {"comm": comm, "state": rest[0], "flags": int(rest[6]), "processor": int(rest[36])}


def task_schedstat(text) -> Optional[dict]:
    """/proc/<pid>/schedstat -> {exec_ns, run_delay_ns, slices}."""
    p = (text or "").split()
    if len(p) != 3 or not all(x.isdigit() for x in p):
        return None
    return {"exec_ns": int(p[0]), "run_delay_ns": int(p[1]), "slices": int(p[2])}


def links(json_text) -> Optional[Dict[str, dict]]:
    """`ip -s -j -d link show` -> {ifname: {kind, qdisc, txq, rxq, up, rx_packets, tx_packets, rx_dropped, tx_dropped}}."""
    try:
        data = json.loads(json_text) if json_text else None
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    out = {}
    for l in data:
        s = l.get("stats64") or {}
        rx, tx = s.get("rx") or {}, s.get("tx") or {}
        out[l.get("ifname")] = {"kind": (l.get("linkinfo") or {}).get("info_kind"), "qdisc": l.get("qdisc"),
                                "txq": l.get("num_tx_queues"), "rxq": l.get("num_rx_queues"),
                                "up": "UP" in (l.get("flags") or []) and l.get("operstate") in ("UP", "UNKNOWN"),
                                "rx_packets": rx.get("packets"), "tx_packets": tx.get("packets"),
                                "rx_dropped": rx.get("dropped"), "tx_dropped": tx.get("dropped")}
    return out


def routes(json_text) -> Optional[List[tuple]]:
    try:
        data = json.loads(json_text) if json_text else None
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    return [(r.get("dst"), r.get("dev")) for r in data]


def snmp_udp(text) -> Optional[Dict[str, int]]:
    """/proc/<pid>/net/snmp Udp: row by header name."""
    rows = [l.split() for l in (text or "").splitlines()]
    hdr = [r for r in rows if r and r[0] == "Udp:"]
    if len(hdr) < 2:
        return None
    m = dict(zip(hdr[0][1:], hdr[1][1:]))
    try:
        return {k: int(m[k]) for k in ("InDatagrams", "NoPorts", "InErrors", "OutDatagrams", "RcvbufErrors",
                                       "SndbufErrors")}
    except (KeyError, ValueError):
        return None


def ethtool_gro(text) -> Optional[str]:
    m = re.search(r"^generic-receive-offload:\s+(on|off)", text or "", re.M)
    return m.group(1) if m else None


def iperf_client(json_text) -> Optional[dict]:
    """iperf3 -J client output -> {packets, lost_packets, remote_host, local_host, error}."""
    try:
        d = json.loads(json_text) if json_text else None
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    if d.get("error"):
        return {"error": d["error"]}
    try:
        s = d["end"]["sum"]
        con = d["start"]["connected"][0]
        return {"packets": int(s["packets"]), "lost_packets": int(s["lost_packets"]),
                "remote_host": con["remote_host"], "local_host": con["local_host"], "error": None}
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def ebpf_softirq(meta_line, line) -> Optional[Dict[tuple, int]]:
    """Raw loader lines -> {(cpu, vector name): cumulative ns}, through the production protocol parser."""
    from sentinelai.collectors.ebpf import VECTORS, ProtocolError, parse_meta, parse_sample
    if not meta_line or not line:
        return None
    try:
        s = parse_sample(line, parse_meta(meta_line))
    except ProtocolError:
        return None
    return {(c, VECTORS[v]): ns for (c, v), (ns, _) in s.softirq.items()}


# ------------------------------------------------------------------------------------------ read-only host access
LAB_READS = {
    "a_links": ("ip", "-n", NS_A, "-s", "-j", "-d", "link", "show"),
    "b_links": ("ip", "-n", NS_B, "-s", "-j", "-d", "link", "show"),
    "a_routes": ("ip", "-n", NS_A, "-j", "route", "show"), "b_routes": ("ip", "-n", NS_B, "-j", "route", "show"),
    "a_routes6": ("ip", "-n", NS_A, "-j", "-6", "route", "show"),
    "b_routes6": ("ip", "-n", NS_B, "-j", "-6", "route", "show"),
}
ETHTOOL_READS = {"ethtool_a": ("ip", "netns", "exec", NS_A, "ethtool", "-k", IF_A),
                 "ethtool_b": ("ip", "netns", "exec", NS_B, "ethtool", "-k", IF_B)}
R2E_READ_ONLY = tuple(LAB_READS.values()) + tuple(ETHTOOL_READS.values()) + ((IPERF3, "--version"),)


class Sys(C.Sys):
    """R2-C's read-only host view plus the R2-E read-only lab inspection commands. No write, no mutation path."""

    def run(self, argv) -> Optional[str]:
        if tuple(argv) in R2E_READ_ONLY:
            try:
                p = subprocess.run(list(argv), capture_output=True, text=True, timeout=15, shell=False)
            except (OSError, subprocess.TimeoutExpired):
                return None
            return p.stdout if p.returncode == 0 else None
        return super().run(argv)

    def ip_link_help(self) -> str:
        """`ip link help` (read-only; prints its usage on stderr)."""
        p = subprocess.run(["ip", "link", "help"], capture_output=True, text=True, timeout=15, shell=False)
        return p.stdout + p.stderr

    def netns_inode(self, ns) -> Optional[int]:
        if ns not in LAB_NETNS:
            raise R2ERefused(f"not a lab namespace: {ns!r}")
        try:
            return os.stat(f"/run/netns/{ns}").st_ino
        except OSError:
            return None


def host_rps(sysr) -> Dict[str, str]:
    """rps_cpus of every rx queue of every host interface (read-only)."""
    out = {}
    for ifn in sysr.listdir("/sys/class/net") or []:
        for q in sysr.listdir(f"/sys/class/net/{ifn}/queues") or []:
            if q.startswith("rx-"):
                out[f"{ifn}/{q}"] = (sysr.read(f"/sys/class/net/{ifn}/queues/{q}/rps_cpus") or "").strip()
    return out


def lab_netns_present(sysr) -> List[str]:
    return sorted(n for n in (sysr.listdir("/run/netns") or []) if n.startswith("sentinel-lab"))


def host_lab_ifaces(sysr) -> List[str]:
    return sorted(n for n in (sysr.listdir("/sys/class/net") or []) if n.startswith("sentlab"))


def host_snapshot(sysr, require_bpf=True) -> dict:
    snap = C.host_snapshot(sysr, require_bpf)
    snap["rps"] = host_rps(sysr)
    snap["lab_netns"] = lab_netns_present(sysr)
    return snap


def compare_host(base: dict, other: dict, require_bpf=True) -> dict:
    """R2-C's exact comparison plus: host RPS maps identical, no lab namespace, no lab interface in the host."""
    r = C.compare_host(base, other, require_bpf)
    r["host_rps_identical"] = base.get("rps") == other.get("rps") and base.get("rps") is not None
    r["no_lab_netns"] = not other.get("lab_netns")
    r["no_lab_interface_in_host"] = not [l.get("ifname") for l in (other.get("links") or [])
                                         if str(l.get("ifname", "")).startswith("sentlab")]
    for k in ("host_rps_identical", "no_lab_netns", "no_lab_interface_in_host"):
        if not r[k]:
            r["failed"].append(k)
    r["ok"] = not r["failed"]
    return r


# ------------------------------------------------------------------------------------------ mutation guard
def cgroup_plan(exp: Experiment) -> List[tuple]:
    ops = [("mkdir", LAB_DIR),
           ("write", f"{LAB_DIR}/cpuset.mems", C.MEMS),
           ("write", f"{LAB_DIR}/cpuset.cpus", C.cpus_text(PARENT_CPUS)),
           ("write", f"{LAB_DIR}/cgroup.subtree_control", " ".join(f"+{c}" for c in C.CONTROLLERS)),
           ("mkdir", TARGET_DIR), ("mkdir", CONTENDER_DIR), ("mkdir", TRAFFIC_DIR),
           ("write", f"{TARGET_DIR}/cpuset.cpus", str(TARGET_CPU)),
           ("write", f"{TARGET_DIR}/cpuset.mems", C.MEMS),
           ("write", f"{TARGET_DIR}/cpu.weight", str(C.TARGET_WEIGHT)),
           ("write", f"{TARGET_DIR}/pids.max", C.PIDS_MAX),
           ("write", f"{CONTENDER_DIR}/cpuset.cpus", str(TARGET_CPU)),
           ("write", f"{CONTENDER_DIR}/cpuset.mems", C.MEMS),
           ("write", f"{CONTENDER_DIR}/cpu.weight", str(exp.contender_weight)),
           ("write", f"{CONTENDER_DIR}/pids.max", C.PIDS_MAX),
           ("write", f"{TRAFFIC_DIR}/cpuset.cpus", C.cpus_text(TRAFFIC_CPUS)),
           ("write", f"{TRAFFIC_DIR}/cpuset.mems", C.MEMS),
           ("write", f"{TRAFFIC_DIR}/pids.max", TRAFFIC_PIDS_MAX)]
    return ops


def lab_plan() -> List[tuple]:
    """The R2-A topology with single-queue veth ends (approved), as exact ip commands, in order."""
    return [("cmd", ("ip", "netns", "add", NS_A)), ("cmd", ("ip", "netns", "add", NS_B)),
            ("cmd", ("ip", "link", "add", IF_A, "numtxqueues", "1", "numrxqueues", "1", "netns", NS_A, "type", "veth",
                     "peer", "name", IF_B, "numtxqueues", "1", "numrxqueues", "1", "netns", NS_B)),
            ("cmd", ("ip", "-n", NS_A, "addr", "add", f"{IP_A}/{PREFIX}", "dev", IF_A)),
            ("cmd", ("ip", "-n", NS_B, "addr", "add", f"{IP_B}/{PREFIX}", "dev", IF_B)),
            ("cmd", ("ip", "-n", NS_A, "link", "set", "lo", "up")), ("cmd", ("ip", "-n", NS_B, "link", "set", "lo", "up")),
            ("cmd", ("ip", "-n", NS_A, "link", "set", IF_A, "up")), ("cmd", ("ip", "-n", NS_B, "link", "set", IF_B, "up"))]


def setup_plan(exp: Experiment) -> List[tuple]:
    return cgroup_plan(exp) + (lab_plan() if exp.lab else [])


def netns_del(ns) -> tuple:
    return ("cmd", ("ip", "netns", "del", ns))


def allowed_writes(exp: Experiment) -> set:
    return {(op[1], op[2]) for op in cgroup_plan(exp) if op[0] == "write"} | \
        {(f"{LAB_DIR}/cgroup.kill", "1"), (f"{TRAFFIC_DIR}/cgroup.kill", "1")}


def allowed_cmds(exp: Experiment) -> set:
    return {op[1] for op in lab_plan()} | {netns_del(n)[1] for n in LAB_NETNS} if exp.lab else set()


TRAFFIC_JOIN = C.WRAPPER + ["sh", "-c", f'echo $$ > {TRAFFIC_DIR}/cgroup.procs && exec "$@"', "sh"]
DROP_PRIV = ["setpriv", f"--reuid={C.LAB_UID}", f"--regid={C.LAB_GID}", "--init-groups", "--"]


def server_argv(i: int) -> List[str]:
    if i not in (0, 1):
        raise R2ERefused(f"server index {i!r}")
    return TRAFFIC_JOIN + ["ip", "netns", "exec", NS_B] + DROP_PRIV + \
        [IPERF3, "-s", "-B", IP_B, "-p", str(PORTS[i]), "-A", str(RECEIVER_CPU), "-J"]


def client_bps(pps_total: int) -> int:
    if isinstance(pps_total, bool) or pps_total not in LADDER_PPS:
        raise R2ERefused(f"packet rate {pps_total!r} is not a ladder rate {LADDER_PPS}")
    return pps_total // 2 * UDP_LEN * 8


def client_argv(i: int, pps_total: int, seconds: int = CLIENT_T) -> List[str]:
    if i not in (0, 1) or seconds not in (CLIENT_T, LADDER_STEP_S):
        raise R2ERefused(f"client {i!r} / duration {seconds!r} not approved")
    return TRAFFIC_JOIN + ["ip", "netns", "exec", NS_A] + DROP_PRIV + \
        [IPERF3, "-c", IP_B, "-B", IP_A, "-p", str(PORTS[i]), "-u", "-l", str(UDP_LEN), "-b", str(client_bps(pps_total)),
         "-t", str(seconds), "-A", str(SENDER_CPUS[i]), "-J"]


def traffic_structure(argv) -> dict:
    """One-pid invariant of a traffic spawn: timeout wrapper outside, sh joins the traffic leaf and execs (no fork)
    through ip netns exec and setpriv into iperf3."""
    n, j = len(C.WRAPPER), len(TRAFFIC_JOIN)
    after = argv[j:]
    c = {"wrapper_first": argv[:n] == C.WRAPPER, "join_follows_wrapper": argv[:j] == TRAFFIC_JOIN,
         "single_wrapper": argv.count("timeout") == 1,
         "no_fork_after_join": not {"timeout", "sh", "nohup", "setsid", "bash"} & set(after),
         "iperf3_last_exec": IPERF3 in after and after.index(IPERF3) > after.index("--")}
    return {"ok": all(c.values()), "checks": c}


def _results_path(p) -> bool:
    s = str(p)
    return s.startswith(str(REPO / "results" / "phase1c_r2e") + "/") and "/../" not in s and "\x00" not in s


def check_spawn(op, exp: Experiment, iters: Optional[int], pps: Optional[int]):
    if len(op) != 3 or op[1] not in ("target", "contender", "calibration", "server", "client"):
        raise R2ERefused(f"malformed spawn {op!r}")
    role, argv = op[1], list(op[2])
    if role in ("server", "client"):
        if not exp.traffic and not exp.lab:
            raise R2ERefused(f"{role} spawn without a lab in {exp.kind}")
        if not traffic_structure(argv)["ok"]:
            raise R2ERefused(f"{role} argv breaks the one-pid structure: {argv}")
        if role == "server" and argv not in (server_argv(0), server_argv(1)):
            raise R2ERefused(f"server argv not approved: {argv}")
        if role == "client":
            if exp.traffic is None:
                raise R2ERefused(f"client spawn in {exp.kind} (no traffic)")
            secs = LADDER_STEP_S if exp.traffic == "LADDER" else CLIENT_T
            rates = LADDER_PPS if exp.traffic == "LADDER" else (pps,)
            if argv not in [client_argv(i, r, secs) for i in (0, 1) for r in rates if r in LADDER_PPS]:
                raise R2ERefused(f"client argv not approved for {exp.kind} at {pps}: {argv}")
        return op
    if not argv or not _results_path(argv[-1]):
        raise R2ERefused(f"{role} output outside results/phase1c_r2e: {argv[-1:]}")
    if not C.spawn_structure(argv, CONTENDER_DIR if role == "contender" else TARGET_DIR)["ok"]:
        raise R2ERefused(f"{role} argv breaks the one-pid structure: {argv}")
    if role == "contender":
        if not exp.contender or argv != C.contender_argv(argv[-1]):
            raise R2ERefused(f"contender argv not approved for {exp.kind}: {argv}")
    elif role == "target":
        if exp.kind in ("CAL", "LADDER") or argv != C.target_argv(iters, argv[-1]):
            raise R2ERefused(f"target argv not approved: {argv}")
    elif exp.kind != "CAL" or argv != C.calibration_argv(argv[-1]):
        raise R2ERefused(f"calibration argv not approved: {argv}")
    return op


FORBIDDEN_TOKENS = ("tc", "sysctl", "modprobe", "insmod", "rmmod", "-K", "--features", "--offload", "iptables", "nft",
                    "cpu.max", "smp_affinity", "rps_sock_flow_entries", "xps_cpus")


def check_op(op, exp: Experiment, iters: Optional[int] = None, pps: Optional[int] = None):
    """The closed set of host operations of one R2-E run. Anything else raises R2ERefused. RPS is never an op here:
    it is written only through rps_write / rps_restore (exact helper argv, check_rps_argv)."""
    if not isinstance(op, tuple) or not op:
        raise R2ERefused(f"malformed operation {op!r}")
    text = repr(op)
    for p in PROTECTED:
        if p in text:
            raise R2ERefused(f"protected interface {p} in operation")
    kind = op[0]
    if kind in ("mkdir", "rmdir"):
        if len(op) != 2 or op[1] not in LAB_DIRS:
            raise R2ERefused(f"{kind} outside the lab cgroup: {op!r}")
    elif kind == "write":
        if len(op) != 3 or (op[1], op[2]) not in allowed_writes(exp):
            raise R2ERefused(f"write not in the {exp.kind} allowlist: {op!r}")
    elif kind == "cmd":
        if len(op) != 2 or not isinstance(op[1], tuple) or any(t in op[1] for t in FORBIDDEN_TOKENS) or \
                op[1] not in allowed_cmds(exp):
            raise R2ERefused(f"command not in the {exp.kind} allowlist: {op!r}")
    elif kind == "spawn":
        check_spawn(op, exp, iters, pps)
    elif kind == "kill":
        if len(op) != 2 or isinstance(op[1], bool) or not isinstance(op[1], int) or op[1] <= 1:
            raise R2ERefused(f"malformed kill {op!r}")
    else:
        raise R2ERefused(f"operation {kind!r} is not authorised in R2-E")
    return op


# ------------------------------------------------------------------------------------------ RPS (the D1 mutation)
# Runs inside sentinel-lab-b via `ip netns exec` (private sysfs view of that namespace). Defence in depth: it refuses
# unless it is in the expected namespace (inode), that namespace holds exactly lo + sentlab-b0, the path resolves to
# the virtual veth's rx-0 (no symlink substitution, no physical device), the device has exactly rx-0/tx-0, and the
# value is approved. It writes with O_NOFOLLOW and nothing else.
RPS_HELPER = (
    "import os,sys\n"
    "m,ino=sys.argv[1],int(sys.argv[2])\n"
    "if os.stat('/proc/self/ns/net').st_ino!=ino:sys.exit(3)\n"
    f"if sorted(os.listdir('/sys/class/net'))!=['lo','{IF_B}']:sys.exit(4)\n"
    f"p='{RPS_REL}'\n"
    f"if os.path.realpath(p)!='{RPS_REAL}':sys.exit(5)\n"
    f"if sorted(os.listdir('/sys/class/net/{IF_B}/queues'))!=['rx-0','tx-0']:sys.exit(6)\n"
    "if m=='write':\n"
    " v=sys.argv[3]\n"
    " if len(sys.argv)!=4 or v not in ('40000','80000','0'):sys.exit(7)\n"
    " fd=os.open(p,os.O_WRONLY|os.O_NOFOLLOW)\n"
    " os.write(fd,v.encode())\n"
    " os.close(fd)\n"
    "elif m!='read' or len(sys.argv)!=3:sys.exit(8)\n"
    "else:print(open(p).read().strip())\n")
RPS_PREFIX = ["ip", "netns", "exec", NS_B, C.PYTHON, "-I", "-c", RPS_HELPER]


def rps_argv(mode: str, ino: int, value: Optional[str] = None) -> List[str]:
    argv = RPS_PREFIX + [mode, str(ino)] + ([value] if value is not None else [])
    return check_rps_argv(argv)


def check_rps_argv(argv) -> List[str]:
    if not isinstance(argv, list) or argv[:len(RPS_PREFIX)] != RPS_PREFIX:
        raise R2ERefused("RPS command is not the approved helper in sentinel-lab-b")
    rest = argv[len(RPS_PREFIX):]
    if len(rest) not in (2, 3) or rest[0] not in ("read", "write") or not re.fullmatch(r"[1-9]\d{0,11}", rest[1]):
        raise R2ERefused(f"malformed RPS helper arguments {rest!r}")
    if rest[0] == "read" and len(rest) != 2:
        raise R2ERefused("RPS read takes no value")
    if rest[0] == "write" and (len(rest) != 3 or rest[2] not in RPS_VALUES):
        raise R2ERefused(f"RPS value {rest[2:]!r} not in {sorted(RPS_VALUES)}")
    return argv


def rps_read(run) -> str:
    rc, out = run("read", None)
    v = (out or "").strip()
    if rc != 0 or not re.fullmatch(r"[0-9a-f]{6}", v):
        raise RpsAbort(f"RPS read failed (rc {rc}, output {v!r})")
    return v


def rps_write(value, expected_prev, run, log, clock=time.monotonic) -> dict:
    """The single RPS write path: validate, read-before, log intent, write, read-after, log result."""
    if value not in RPS_VALUES:
        raise R2ERefused(f"RPS value {value!r} not in {sorted(RPS_VALUES)}")
    prev = rps_read(run)
    if prev != expected_prev:
        log(phase="refused", op=["rps", RPS_REL], value=value, prev=prev, expected_prev=expected_prev)
        raise RpsAbort(f"rps_cpus before write is {prev!r}, expected {expected_prev!r}")
    log(phase="intent", op=["rps", RPS_REL], value=value, prev=prev)
    t0 = clock()
    rc, _ = run("write", value)
    t1 = clock()
    if rc != 0:
        log(phase="result", op=["rps", RPS_REL], value=value, prev=prev, post=None, ok=False, rc=rc)
        raise RpsAbort(f"RPS write of {value!r} failed (rc {rc})")
    post = rps_read(run)
    ok = post == RPS_READBACK[value]
    log(phase="result", op=["rps", RPS_REL], value=value, prev=prev, post=post, ok=ok, t0=t0, t1=t1)
    if not ok:
        raise RpsAbort(f"rps_cpus after write is {post!r}, expected {RPS_READBACK[value]!r}")
    return {"value": value, "prev": prev, "post": post, "t0": t0, "t1": t1}


def rps_restore(run, log, clock=time.monotonic) -> dict:
    """Restore 0 (verified). A value no approved write produces is restored and reported as an anomaly."""
    cur = rps_read(run)
    if cur == RPS_ZERO:
        log(phase="result", op=["rps_restore", RPS_REL], value="0", prev=cur, post=cur, ok=True, noop=True)
        return {"ok": True, "restored": True, "noop": True, "prev": cur, "post": cur}
    anomaly = cur not in (RPS_READBACK["40000"], RPS_READBACK["80000"])
    rec = rps_write("0", cur, run, log, clock)
    return {"ok": not anomaly, "restored": rec["post"] == RPS_ZERO, "noop": False, "prev": cur, "post": rec["post"],
            "anomaly": f"value {cur!r} was not written by an approved operation" if anomaly else None}


class Host:
    """The single R2-E mutation site. Every operation is re-validated by check_op and logged (intent, result)."""

    _log = C.Host._log

    def __init__(self, exp: Experiment, oplog: str, iters: Optional[int] = None, pps: Optional[int] = None,
                 sysr=None):
        self.exp, self.oplog, self.iters, self.pps, self.sys = exp, oplog, iters, pps, sysr or Sys()

    def apply(self, op, stdout=None, stderr=None):
        check_op(op, self.exp, self.iters, self.pps)
        self._log(phase="intent", op=[op[0], list(op[1]) if op[0] == "cmd" else op[1]])
        try:
            res = self._do(op, stdout, stderr)
        except OSError as exc:
            self._log(phase="result", op=[op[0], list(op[1]) if op[0] == "cmd" else op[1]], ok=False, err=str(exc))
            raise
        self._log(phase="result", op=[op[0], list(op[1]) if op[0] == "cmd" else op[1]], ok=True,
                  pid=getattr(res, "pid", None))
        return res

    def _do(self, op, stdout, stderr):
        if op[0] == "cmd":
            p = subprocess.run(list(op[1]), capture_output=True, text=True, timeout=15, shell=False)
            if p.returncode != 0:
                raise OSError(f"{' '.join(op[1][:4])} failed (rc {p.returncode}): {p.stderr.strip()[:200]}")
            return None
        return C.Host._do(self, op, stdout, stderr)

    def _rps_run(self, mode, value):
        ino = self.sys.netns_inode(NS_B)
        if ino is None:
            raise RpsAbort(f"{NS_B} does not exist")
        p = subprocess.run(rps_argv(mode, ino, value), capture_output=True, text=True, timeout=15, shell=False)
        return p.returncode, p.stdout

    def rps_write(self, value, expected_prev):
        return rps_write(value, expected_prev, self._rps_run, self._log)

    def rps_restore(self):
        return rps_restore(self._rps_run, self._log)

    def rps_read(self):
        return rps_read(self._rps_run)


# ------------------------------------------------------------------------------------------ preflight / verification
def preflight(sysr) -> dict:
    """Read-only prerequisites before anything is created; refuses on any pre-existing lab or RPS state (D2)."""
    c = {}
    c["root_cpuset_0_23"] = C.parse_cpulist(sysr.read(f"{C.CG_ROOT}/cpuset.cpus.effective")) == C.HOST_CPUS
    c["root_subtree_control"] = set((sysr.read(f"{C.CG_ROOT}/cgroup.subtree_control") or "").split()) == C.ROOT_SUBTREE
    c["no_sentinel_cgroup"] = not C.sentinel_cgroups(sysr)
    c["no_lab_process"] = not C.lab_pids(sysr)
    c["no_lab_netns"] = not lab_netns_present(sysr)
    c["no_lab_interface_in_host"] = not host_lab_ifaces(sysr)
    rps = host_rps(sysr)
    c["host_rps_all_zero"] = bool(rps) and all(re.fullmatch(r"0+(,0+)*", v or "") for v in rps.values())
    online = C.parse_cpulist(sysr.read("/sys/devices/system/cpu/online"))
    c["experiment_cpus_online"] = EXPERIMENT_CPUS | set(SUPPORT_CPUS) <= online
    c["experiment_cpus_no_smt"] = all(C.parse_cpulist(sysr.read(f"/sys/devices/system/cpu/cpu{n}/topology/"
                                                                "thread_siblings_list")) == {n} for n in EXPERIMENT_CPUS)
    irq_line = [l for l in (sysr.read("/proc/interrupts") or "").splitlines() if l.strip().startswith(f"{C.NIC_IRQ}:")]
    c["nic_irq_is_enp0s31f6"] = bool(irq_line) and irq_line[0].split()[-1] == C.NIC_IRQ_NAME
    eff = sysr.read(f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list")
    c["nic_irq_off_experiment_cpus"] = eff is not None and not C.parse_cpulist(eff) & EXPERIMENT_CPUS
    c["protected_interfaces_present"] = all(sysr.exists(f"/sys/class/net/{p}") for p in PROTECTED)
    c["cgroup_kill_supported"] = sysr.exists(f"{C.CG_ROOT}/init.scope/cgroup.kill")
    c["psi_available"] = sysr.read("/proc/pressure/cpu") is not None
    c["lab_uid_exists"] = sysr.uid_name(C.LAB_UID) is not None
    c["netdev_max_backlog_readable"] = (sysr.read("/proc/sys/net/core/netdev_max_backlog") or "").strip().isdigit()
    for t in ("/usr/bin/unshare", "/usr/bin/setpriv", "/usr/bin/timeout", "/usr/bin/taskset", C.PYTHON, C.LOADER,
              C.BPFTOOL, IPERF3, "/usr/sbin/ethtool", "/usr/sbin/ip"):
        c[f"tool:{t}"] = sysr.tool(t)
    return {"ok": all(c.values()), "checks": c}


def verify_cgroups(sysr, exp: Experiment) -> dict:
    r = lambda d, f: sysr.read(f"{d}/{f}")
    c = {"parent_subtree_control": set((r(LAB_DIR, "cgroup.subtree_control") or "").split()) == set(C.CONTROLLERS),
         "parent_cpus": C.parse_cpulist(r(LAB_DIR, "cpuset.cpus.effective")) == set(PARENT_CPUS)}
    want = {"target": {TARGET_CPU}, "contender": {TARGET_CPU}, "traffic": set(TRAFFIC_CPUS)}
    for name, d in (("parent", LAB_DIR),) + LEAVES:
        c[f"{name}_no_quota"] = (r(d, "cpu.max") or "").strip() == C.CPU_MAX_UNLIMITED
        procs = r(d, "cgroup.procs")
        c[f"{name}_empty"] = procs is not None and procs.strip() == ""
        if name != "parent":
            c[f"{name}_cpus"] = C.parse_cpulist(r(d, "cpuset.cpus.effective")) == want[name]
            c[f"{name}_controllers"] = set(C.CONTROLLERS) <= set((r(d, "cgroup.controllers") or "").split())
            c[f"{name}_memory_max_unlimited"] = (r(d, "memory.max") or "").strip() == "max"
    c["contender_weight"] = (r(CONTENDER_DIR, "cpu.weight") or "").strip() == str(exp.contender_weight)
    c["traffic_pids_max"] = (r(TRAFFIC_DIR, "pids.max") or "").strip() == TRAFFIC_PIDS_MAX
    return {"ok": all(c.values()), "checks": c}


def lab_state(sysr) -> dict:
    """Raw lab inspection texts (read-only), saved for offline recomputation."""
    return {k: sysr.run(argv) for k, argv in LAB_READS.items()}


def lab_checks(raw: dict) -> dict:
    """GN for one lab inspection: only lo + the veth per side, veth single-queue, noqueue, up; lab routes only."""
    c = {}
    for side, ifn in (("a", IF_A), ("b", IF_B)):
        ls = links(raw.get(f"{side}_links"))
        rt, rt6 = routes(raw.get(f"{side}_routes")), routes(raw.get(f"{side}_routes6"))
        if ls is None or rt is None or rt6 is None:
            c[f"{side}_observable"] = False
            continue
        v = ls.get(ifn) or {}
        c[f"{side}_only_lo_and_veth"] = sorted(ls) == sorted(["lo", ifn])
        c[f"{side}_veth"] = v.get("kind") == "veth" and v.get("up") is True
        c[f"{side}_single_queue"] = v.get("txq") == 1 and v.get("rxq") == 1
        c[f"{side}_noqueue"] = v.get("qdisc") == "noqueue"
        c[f"{side}_routes_lab_only"] = rt == [(SUBNET, ifn)]
        c[f"{side}_no_default_route"] = not any(d == "default" for d, _ in rt + rt6)
    return c


LAB_SETTLE_POLL_S = 0.1                      # approved: read-only re-inspection every 0.1 s ...
LAB_SETTLE_MAX_S = 3.0                       # ... for at most 3 s after the last `ip link set ... up`


def lab_parsed(raw: dict) -> dict:
    """What each inspection reported, per side: interfaces (type, flags-derived up, queues, qdisc) and routes."""
    return {side: {"links": links(raw.get(f"{side}_links")), "routes": routes(raw.get(f"{side}_routes")),
                   "routes6": routes(raw.get(f"{side}_routes6"))} for side in ("a", "b")}


def lab_failures(checks: dict) -> List[str]:
    """Failed lab checks of one inspection (an empty or partial check set is a failure, never a pass)."""
    if not checks:
        return ["unobservable"]
    return sorted(k for k, v in checks.items() if v is not True)


def settle_lab(read, attempts: list, persist, clock=time.monotonic, sleep=time.sleep, wall=time.time) -> dict:
    """Bounded read-only settle of the lab after creation (timing only; lab_checks is unchanged):
    read -> append the raw observation to `attempts` and persist it -> evaluate -> record the verdict and persist.
    PASS ends the loop at once; otherwise sleep LAB_SETTLE_POLL_S and re-read, until LAB_SETTLE_MAX_S has elapsed
    since the first read. Every observation, failed or not, stays in `attempts` (never overwritten)."""
    t0 = clock()
    k = 0
    while True:
        rec = {"attempt": k, "mono": clock(), "wall": wall(), "raw": read()}
        attempts.append(rec)
        persist()                                                        # raw observation saved before evaluation
        checks = lab_checks(rec["raw"])
        fails = lab_failures(checks)
        rec.update(parsed=lab_parsed(rec["raw"]), checks=checks, ok=not fails, failures=fails)
        persist()                                                        # verdict saved with its observation
        if not fails:
            return {"settled": True, "settled_attempt": k, "n_attempts": len(attempts), "elapsed_s": rec["mono"] - t0,
                    "final_reason": None}
        if clock() - t0 >= LAB_SETTLE_MAX_S:
            return {"settled": False, "settled_attempt": None, "n_attempts": len(attempts),
                    "elapsed_s": clock() - t0, "final_reason": f"lab not settled within {LAB_SETTLE_MAX_S} s: {fails}"}
        sleep(LAB_SETTLE_POLL_S)
        k += 1


def replay_lab_settle(setup: Optional[dict]) -> dict:
    """Offline: re-evaluate every saved lab inspection from its raw text; which attempt settled the lab and why each
    attempt passed or failed. Runs recorded before the settle fix (no `settle`) are reported as not replayable."""
    settle = (setup or {}).get("settle")
    if not settle:
        return {"replayable": False, "identical": None}
    rows, same = [], True
    for rec in settle["attempts"]:
        checks = lab_checks(rec["raw"])
        fails = lab_failures(checks)
        rows.append({"attempt": rec["attempt"], "ok": not fails, "failures": fails})
        same &= rec.get("checks") == checks and rec.get("ok") == (not fails) and rec.get("failures") == fails
    first_ok = next((r["attempt"] for r in rows if r["ok"]), None)
    same &= settle.get("settled") == (first_ok is not None) and settle.get("settled_attempt") == first_ok and \
        all(not r["ok"] for r in rows[:-1]) and settle.get("n_attempts") == len(rows)
    return {"replayable": True, "identical": same, "attempts": rows, "settled_attempt": first_ok}


# ------------------------------------------------------------------------------------------ ground-truth sampling
def cpu18_kthread_pids(sysr) -> List[int]:
    """Per-CPU kernel threads of CPU 18 (ksoftirqd/18, migration/18, cpuhp/18, kworker/18:*), by comm and PF_KTHREAD."""
    out = []
    for pid in sysr.pids():
        st = task_stat(sysr.read(f"/proc/{pid}/stat"))
        if st and st["flags"] & PF_KTHREAD and KTHREAD_CPU18.match(st["comm"]):
            out.append(pid)
    return out


def gt_sample(sysr, mono: float, tag: str, target_pid: Optional[int], server_pids, ebpf_line=None,
              with_lab=True) -> dict:
    """One raw ground-truth observation: every file text the predicates need, nothing derived."""
    rd = sysr.read
    leaves = {}
    for name, d in (("parent", LAB_DIR),) + LEAVES:
        leaves[name] = {f: rd(f"{d}/{f}") for f in ("cpu.max", "cpuset.cpus.effective", "cpu.stat", "cpu.pressure",
                                                    "memory.events", "cgroup.procs")}
    pids = set()
    for name, _ in LEAVES:
        pids |= {int(p) for p in (leaves[name]["cgroup.procs"] or "").split()}
    pids |= set(cpu18_kthread_pids(sysr))
    tasks = {str(p): {"stat": rd(f"/proc/{p}/stat"), "schedstat": rd(f"/proc/{p}/schedstat")} for p in sorted(pids)}
    srv = [p for p in server_pids if rd(f"/proc/{p}/net/snmp") is not None]
    return {
        "mono": mono, "tag": tag,
        "raw": {"stat": rd("/proc/stat"), "schedstat": rd("/proc/schedstat"), "softirqs": rd("/proc/softirqs"),
                "softnet": rd("/proc/net/softnet_stat"), "vmstat": rd("/proc/vmstat"),
                "psi_cpu": rd("/proc/pressure/cpu"), "psi_memory": rd("/proc/pressure/memory"),
                "nic_irq_eff": rd(f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list")},
        "slices": {s: rd(f"{C.CG_ROOT}/{s}/cpu.pressure") for s in C.SLICES},
        "leaves": leaves, "tasks": tasks,
        "target_netns": None if target_pid is None else {"dev": rd(f"/proc/{target_pid}/net/dev"),
                                                         "snmp": rd(f"/proc/{target_pid}/net/snmp")},
        "lab_b_snmp": rd(f"/proc/{srv[0]}/net/snmp") if srv else None,
        "lab": lab_state(sysr) if with_lab else None,
        "ebpf_line": ebpf_line,
    }


def parse_obs(t: dict) -> dict:
    """A raw observation -> the R2-C-shaped parsed view (pure), so R2-C's host-level checks apply unchanged."""
    raw, lv = t["raw"], t["leaves"]
    leaves = {}
    for name in ("parent",) + tuple(n for n, _ in LEAVES):
        x = lv[name]
        procs = x["cgroup.procs"]
        leaves[name] = {"cpu_max": (x["cpu.max"] or "").strip() or None,
                        "cpus_eff": (x["cpuset.cpus.effective"] or "").strip() if name != "parent" else None,
                        "cpu_stat": C.kv(x["cpu.stat"]) or None,
                        "cpu_pressure": (C.psi(x["cpu.pressure"]) or None) if name != "parent" else None,
                        "mem_events": (C.kv(x["memory.events"]) or None) if name != "parent" else None,
                        "procs": None if procs is None else sorted(int(p) for p in procs.split())}
    tasks = {int(p): {"stat": task_stat(v["stat"]), "schedstat": task_schedstat(v["schedstat"])}
             for p, v in t["tasks"].items()}
    vm = C.kv(raw["vmstat"])
    tn = t.get("target_netns")
    return {"mono": t["mono"], "tag": t["tag"], "stat": C.proc_stat_cpus(raw["stat"]),
            "rq_cpu_time": C.schedstat_rq_cpu_time(raw["schedstat"]), "softirqs": softirqs(raw["softirqs"]),
            "softnet": softnet(raw["softnet"]), "leaves": leaves, "tasks": tasks,
            "nic_irq_eff": raw["nic_irq_eff"].strip() if raw["nic_irq_eff"] is not None else None,
            "psi_cpu": C.psi(raw["psi_cpu"]) or None, "psi_memory": C.psi(raw["psi_memory"]) or None,
            "slices": {s: C.psi(v) or None for s, v in t["slices"].items()},
            "vmstat": {k: v for k, v in vm.items() if k in ("pswpin", "pswpout")} or None,
            "netns": None if tn is None else C.netns_counters(tn["dev"], tn["snmp"]),
            "lab_b_udp": snmp_udp(t.get("lab_b_snmp")),
            "lab": t.get("lab"), "ebpf_line": t.get("ebpf_line")}


# ------------------------------------------------------------------------------------------ predicates (pure)
def _d(obs, a, b, get):
    return C._d(obs, a, b, get)


def _secs(obs, a, b):
    return obs[b]["mono"] - obs[a]["mono"]


def _task(o, pid, part, key):
    t = o["tasks"].get(pid) or {}
    return (t.get(part) or {}).get(key)


def _lab_link(o, side, ifn, key):
    ls = links((o.get("lab") or {}).get(f"{side}_links"))
    return None if ls is None or ifn not in ls else ls[ifn].get(key)


def evaluate_gp(obs, expected, in_w) -> dict:
    """GP placement, every observation: leaves' cpusets, exact pids per leaf, each pid on its approved CPU."""
    viol, unknown = [], 0
    for k, (o, want) in enumerate(zip(obs, expected)):
        lv = o["leaves"]
        for name, cpus in (("target", {TARGET_CPU}), ("contender", {TARGET_CPU}), ("traffic", set(TRAFFIC_CPUS))):
            if lv[name]["cpus_eff"] is None or lv[name]["procs"] is None:
                unknown += 1
                continue
            if C.parse_cpulist(lv[name]["cpus_eff"]) != cpus:
                viol.append(f"obs {k}: {name} cpuset {lv[name]['cpus_eff']!r} != {C.cpus_text(cpus)}")
        if lv["parent"]["procs"] != []:
            viol.append(f"obs {k}: process in the lab parent: {lv['parent']['procs']}")
        cpu_of = {int(p): c for p, c in want.get("cpu", {}).items()}
        for name in ("target", "contender", "traffic"):
            exp_pids = sorted(want.get(name, []))
            if lv[name]["procs"] is not None and lv[name]["procs"] != exp_pids:
                viol.append(f"obs {k}: {name} procs {lv[name]['procs']} != expected {exp_pids}")
            for pid in lv[name]["procs"] or []:
                st = (o["tasks"].get(pid) or {}).get("stat")
                if st is None:
                    unknown += 1
                    continue
                if st["processor"] != cpu_of.get(pid):
                    viol.append(f"obs {k}: {name} pid {pid} on CPU {st['processor']} (allowed {cpu_of.get(pid)})")
        if not in_w[k] and lv["contender"]["procs"]:
            viol.append(f"obs {k}: contender running outside W")
    ok = False if viol else (None if unknown else True)
    return {"ok": ok, "violations": viol[:20], "n_violations": len(viol), "unknown": unknown, "observations": len(obs)}


def evaluate_gn(obs, setup: dict, iperf: dict, exp: Experiment) -> dict:
    """GN network isolation: lab topology at every observation (single-queue veths, lab routes only, no default);
    GRO off on sentlab-b0 (no veth NAPI); iperf3 connected only between the lab addresses."""
    viol, unknown = [], 0
    if exp.lab:
        for k, o in enumerate(obs):
            c = lab_checks(o.get("lab") or {})
            if not c or any(v is False and n.endswith("_observable") for n, v in c.items()):
                unknown += 1
                continue
            viol += [f"obs {k}: {n}" for n, v in c.items() if v is False]
        gro = ethtool_gro(setup.get("ethtool_b"))
        if gro is None:
            unknown += 1
        elif gro != "off":
            viol.append(f"GRO {gro} on {IF_B} (veth NAPI would move work off the RPS CPU)")
    for name, cl in sorted((iperf or {}).items()):
        if cl is None or cl.get("error"):
            viol.append(f"iperf3 {name}: {cl and cl.get('error') or 'no result'}")
        elif cl["remote_host"] != IP_B or cl["local_host"] != IP_A:
            viol.append(f"iperf3 {name} connected {cl['local_host']} -> {cl['remote_host']}")
    ok = False if viol else (None if unknown else True)
    return {"ok": ok, "violations": viol[:20], "n_violations": len(viol), "unknown": unknown}


def _sirq(obs, k, meta, cpu, vec=None):
    s = ebpf_softirq(meta, obs[k].get("ebpf_line"))
    if s is None:
        return None
    return sum(ns for (c, v), ns in s.items() if c == cpu and (vec is None or v == vec))


def softirq_rates(obs, i_b0, i_w0, i_w1, meta, cpu) -> dict:
    """eBPF softirq execution time on `cpu` (cores) in B and W: NET_RX and all vectors."""
    out = {}
    for name, (a, b) in (("b", (i_b0, i_w0)), ("w", (i_w0, i_w1))):
        secs = _secs(obs, a, b)
        for vec, key in (("NET_RX", "netrx"), (None, "all")):
            x, y = _sirq(obs, a, meta, cpu, vec), _sirq(obs, b, meta, cpu, vec)
            out[f"{key}_{name}"] = None if x is None or y is None or y < x or secs <= 0 else (y - x) / 1e9 / secs
    return out


def evaluate_gs(obs, i_b0, i_w0, i_w1, exp: Experiment, meta, delta: Optional[float], max_backlog: Optional[int],
                hz: int) -> dict:
    """GS: softirq time on CPU 18 (precise eBPF) as the experiment requires; packets processed where RPS sends them;
    the eBPF time bounded by CPU 18's precise non-idle time."""
    r18 = softirq_rates(obs, i_b0, i_w0, i_w1, meta, TARGET_CPU)
    r = {"cpu18": r18, "delta": delta}
    nb, nw = r18["netrx_b"], r18["netrx_w"]
    if nb is None or nw is None or (exp.traffic in ("S1",) and delta is None):
        r.update(ok=None, status="UNAVAILABLE")
        return r
    rise = SI_RATIO_MIN * max(nb, FLOOR)
    c = {}
    if exp.traffic in ("S2", "S3") and exp.rps == "40000":
        c["netrx18_w_at_least_si_abs_min"] = nw >= SI_ABS_MIN
        c["netrx18_w_rise"] = nw >= rise
    elif exp.traffic == "S1":
        c["netrx18_w_rise"] = nw >= rise
        c["netrx18_w_below_si_abs_min_minus_delta"] = nw < SI_ABS_MIN - delta
    else:                                                       # E0, N1, N2: no softirq rise on the target CPU
        c["netrx18_w_no_rise"] = nw < rise
    # bound: NET_RX time on 18 <= precise non-idle time of 18 (idle is precise under NO_HZ; 2 jiffies of granularity)
    di = _d(obs, i_w0, i_w1, lambda o: o["stat"]["cpu18"]["idle"])
    secs = _secs(obs, i_w0, i_w1)
    if di is None or secs <= 0:
        r.update(ok=None, status="UNAVAILABLE")
        return r
    nonidle_s = secs - di / hz
    r["nonidle18_s_w"] = nonidle_s
    c["netrx18_within_nonidle"] = nw * secs <= nonidle_s + 2 / hz
    if exp.traffic is not None:                                 # steering: every lab packet processed on the RPS CPU
        cpu = RPS_VALUES[exp.rps]
        pr = _d(obs, i_w0, i_w1, lambda o: o["softnet"][cpu]["processed"])
        rx = _d(obs, i_w0, i_w1, lambda o: _lab_link(o, "b", IF_B, "rx_packets"))
        r.update(processed_rps_cpu_w=pr, b0_rx_packets_w=rx, max_backlog=max_backlog)
        if pr is None or rx is None or max_backlog is None:
            r.update(ok=None, status="UNAVAILABLE", checks=c)
            return r
        c["processed_on_rps_cpu"] = rx > 0 and pr >= rx - max_backlog
        if exp.kind == "N2":                                    # the load exists, on CPU 19
            r19 = softirq_rates(obs, i_b0, i_w0, i_w1, meta, N2_RPS_CPU)
            r["cpu19"] = r19
            if r19["netrx_b"] is None or r19["netrx_w"] is None:
                r.update(ok=None, status="UNAVAILABLE", checks=c)
                return r
            c["netrx19_w_rise"] = r19["netrx_w"] >= SI_RATIO_MIN * max(r19["netrx_b"], FLOOR)
    r.update(checks=c, ok=all(c.values()), status="EVALUATED")
    return r


def evaluate_gv(gs: dict, exp: Experiment) -> dict:
    """GV: NET_RX is at least SI_SHARE_MIN of all softirq time on CPU 18 in W (S1-S3)."""
    if exp.traffic not in ("S1", "S2", "S3") or exp.rps != "40000":
        return {"applies": False, "ok": True}
    nw, aw = gs["cpu18"].get("netrx_w"), gs["cpu18"].get("all_w")
    if nw is None or aw is None or aw <= 0:
        return {"applies": True, "ok": None, "status": "UNAVAILABLE"}
    share = nw / aw
    return {"applies": True, "ok": share >= SI_SHARE_MIN, "netrx_share_w": share, "threshold": SI_SHARE_MIN}


def evaluate_gi(obs, i_b0, i_w0, i_w1, target_pid) -> dict:
    """GI: target run_delay rate (schedstat, waiting cores) W - B and target cgroup cpu.pressure some W vs B."""
    sb, sw = _secs(obs, i_b0, i_w0), _secs(obs, i_w0, i_w1)
    rd = lambda o: _task(o, target_pid, "schedstat", "run_delay_ns")
    db, dw = _d(obs, i_b0, i_w0, rd), _d(obs, i_w0, i_w1, rd)
    ps = lambda o: (o["leaves"]["target"]["cpu_pressure"] or {}).get("some_total")
    pb, pw = _d(obs, i_b0, i_w0, ps), _d(obs, i_w0, i_w1, ps)
    if None in (db, dw, pb, pw) or sb <= 0 or sw <= 0:
        return {"ok": None, "status": "UNAVAILABLE"}
    rb, rw = db / 1e9 / sb, dw / 1e9 / sw
    return {"ok": rw - rb >= RDX_MIN and pw > pb, "run_delay_rate_b": rb, "run_delay_rate_w": rw,
            "psi_some_us_b": pb, "psi_some_us_w": pw, "threshold": RDX_MIN, "status": "EVALUATED"}


def evaluate_g0(obs) -> dict:
    """G0: cpu.max 'max 100000' on every lab cgroup at every observation; no throttled period anywhere."""
    quota = all(o["leaves"][n]["cpu_max"] == C.CPU_MAX_UNLIMITED for o in obs for n in ("parent", "target",
                                                                                       "contender", "traffic"))
    thr = {f"{n}.{k}": _d(obs, 0, len(obs) - 1, lambda o, n=n, k=k: (o["leaves"][n]["cpu_stat"] or {}).get(k))
           for n in ("target", "contender", "traffic") for k in ("nr_throttled", "throttled_usec")}
    if any(v is None for v in thr.values()):
        return {"ok": None if quota else False, "cpu_max_unlimited": quota, "deltas": thr, "status": "UNAVAILABLE"}
    return {"ok": quota and all(v == 0 for v in thr.values()), "cpu_max_unlimited": quota, "deltas": thr}


def _kthread_runtime(obs, a, b) -> Optional[int]:
    """Sum of exec time of the per-CPU-18 kernel threads between observations a and b (threads appearing later count
    from 0, which only enlarges what is subtracted from nothing -- they did not exist before)."""
    tot = 0
    for pid, t in obs[b]["tasks"].items():
        st = t.get("stat")
        if not st or not st["flags"] & PF_KTHREAD or not KTHREAD_CPU18.match(st["comm"]):
            continue
        y = (t.get("schedstat") or {}).get("exec_ns")
        x = _task(obs[a], pid, "schedstat", "exec_ns") if pid in obs[a]["tasks"] else 0
        if y is None or x is None or y < x:
            return None
        tot += y - x
    return tot


def evaluate_g6p(obs, i_b0, i_w0, i_w1, exp: Experiment) -> dict:
    """G6': foreign busy time on CPU 18 = rq_cpu_time(18) - target usage - (N1) contender usage - per-CPU-18 kernel
    threads (ksoftirqd/18 runs softirq work: it is the fault, not a foreign task), per second."""
    def foreign(a, z):
        rq = C._rq(obs, a, z)
        tu = _d(obs, a, z, lambda o: (o["leaves"]["target"]["cpu_stat"] or {}).get("usage_usec"))
        cu = _d(obs, a, z, lambda o: (o["leaves"]["contender"]["cpu_stat"] or {}).get("usage_usec")) \
            if exp.contender else 0
        kt = _kthread_runtime(obs, a, z)
        secs = _secs(obs, a, z)
        if None in (rq, tu, cu, kt) or secs <= 0:
            return None, None
        return (rq / 1e9 - tu / 1e6 - cu / 1e6 - kt / 1e9) / secs, kt / 1e9 / secs
    fb, kb = foreign(i_b0, i_w0)
    fw, kw = foreign(i_w0, i_w1)
    return {"ok": None if fb is None or fw is None else fb <= G6_MAX and fw <= G6_MAX, "foreign_cores_b": fb,
            "foreign_cores_w": fw, "kthread18_cores_b": kb, "kthread18_cores_w": kw, "threshold": G6_MAX,
            "contender_subtracted": exp.contender}


def evaluate_gl(obs, iperf: dict, exp: Experiment) -> dict:
    """GL: no packet loss anywhere over the run. S3 only: softnet drops on CPU 18 (backlog full, the PR-2 form) are
    allowed when nothing else dropped and the sender's veth drops are exactly those backlog drops."""
    a, z = 0, len(obs) - 1
    sn_drop = {}
    first, last = obs[a]["softnet"], obs[z]["softnet"]
    if first is None or last is None or set(first) != set(last):
        return {"ok": None, "status": "UNAVAILABLE"}
    for cpu in last:
        sn_drop[cpu] = last[cpu]["dropped"] - first[cpu]["dropped"]
    c = {"softnet_drops_off_rps_cpu": {k: v for k, v in sn_drop.items() if v}}
    if exp.lab:
        ad = _d(obs, a, z, lambda o: _lab_link(o, "a", IF_A, "tx_dropped"))
        bd = _d(obs, a, z, lambda o: _lab_link(o, "b", IF_B, "rx_dropped"))
        udp = [o["lab_b_udp"] for o in obs if o.get("lab_b_udp")]
        ue = None if len(udp) < 2 else {k: udp[-1][k] - udp[0][k] for k in ("InErrors", "RcvbufErrors", "NoPorts")}
        if ad is None or bd is None or (exp.traffic and ue is None):
            return {"ok": None, "status": "UNAVAILABLE", "softnet_drops": sn_drop}
        c.update(a_tx_dropped=ad, b_rx_dropped=bd, lab_b_udp_errors=ue)
    lost = {n: (cl or {}).get("lost_packets") for n, cl in (iperf or {}).items()}
    c["iperf3_lost"] = lost
    if any(v is None for v in lost.values()):
        return {"ok": None, "status": "UNAVAILABLE", **c}
    other = sum(v for k, v in sn_drop.items() if k != TARGET_CPU)
    s18 = sn_drop.get(TARGET_CPU, 0)
    errs = sum((c.get("lab_b_udp_errors") or {}).values())
    if exp.kind == "S3" and s18 > 0:
        ok = other == 0 and errs == 0 and c.get("b_rx_dropped") == 0 and c.get("a_tx_dropped") == s18 and \
            sum(lost.values()) <= s18
        c["pr2_form"] = True
    else:
        ok = other == 0 and s18 == 0 and errs == 0 and not c.get("a_tx_dropped") and not c.get("b_rx_dropped") and \
            sum(lost.values()) == 0
    return {"ok": ok, **c, "softnet_drops": sn_drop}


def evaluate_gc(obs, i_w0, i_w1, exp: Experiment) -> dict:
    """GC: N1 contender ran on CPU 18 and saturated it (R2-C G2/G3 criteria); elsewhere the contender did nothing."""
    cu = lambda o: (o["leaves"]["contender"]["cpu_stat"] or {}).get("usage_usec")
    if not exp.contender:
        d = _d(obs, 0, len(obs) - 1, cu)
        return {"applies": False, "ok": None if d is None else d == 0, "contender_usage_us": d}
    du, sw, rq = _d(obs, i_w0, i_w1, cu), _secs(obs, i_w0, i_w1), C._rq(obs, i_w0, i_w1)
    if du is None or rq is None or sw <= 0:
        return {"applies": True, "ok": None, "status": "UNAVAILABLE"}
    cores, idle = du / 1e6 / sw, 1 - rq / (sw * 1e9)
    return {"applies": True, "ok": cores >= C.G2_CONTENDER_MIN_CORES and idle <= C.G3_IDLE_MAX,
            "contender_cores_w": cores, "cpu18_idle_frac_w": idle, "thresholds": [C.G2_CONTENDER_MIN_CORES,
                                                                                  C.G3_IDLE_MAX]}


def evaluate_g7(obs, i_w0, i_w1) -> dict:
    """G7 (R2-C, unchanged criteria) minus its CPU-18 softirq part, which is the fault here (GS judges it): NIC IRQ off
    the experiment CPUs, no memory events, no host memory PSI stall and no swap I/O in W, target netns quiet."""
    g = {"nic_irq_ok": all(o["nic_irq_eff"] is not None and not C.parse_cpulist(o["nic_irq_eff"]) & EXPERIMENT_CPUS
                           for o in obs)}
    ev = {}
    for n in ("target", "contender", "traffic"):
        for k in ("high", "max", "oom", "oom_kill"):
            ev[f"{n}.{k}"] = _d(obs, 0, len(obs) - 1, lambda o, n=n, k=k: (o["leaves"][n]["mem_events"] or {}).get(k))
    g["memory_events"] = ev
    g["memory_events_ok"] = None if any(v is None for v in ev.values()) else all(v == 0 for v in ev.values())
    pm = _d(obs, i_w0, i_w1, lambda o: (o["psi_memory"] or {}).get("some_total"))
    sw = _secs(obs, i_w0, i_w1)

    def swap(o):
        v = o["vmstat"] or {}
        return v["pswpin"] + v["pswpout"] if "pswpin" in v and "pswpout" in v else None
    si = _d(obs, i_w0, i_w1, swap)
    g["swap_pages_per_s_w"] = None if si is None or sw <= 0 else si / sw
    g["memory_psi_ok"] = None if pm is None else pm <= C.MEM_PSI_W_MAX_US
    g["swap_ok"] = None if g["swap_pages_per_s_w"] is None else g["swap_pages_per_s_w"] <= C.SWAP_MAX_PAGES_PER_S
    nets = [o["netns"] for o in obs if o["netns"] is not None]
    g["netns_quiet"] = (all(n == nets[0] for n in nets)) if len(nets) == len(obs) else None
    parts = ("nic_irq_ok", "memory_events_ok", "memory_psi_ok", "swap_ok", "netns_quiet")
    g["ok"] = all(g[p] is True for p in parts)
    g["undecided"] = [p for p in parts if g[p] is None]
    return g


def ground_truth_inputs(R: dict, target_out: Optional[dict]) -> dict:
    """Exactly the saved inputs evaluate() reads (a pure function of the run directory)."""
    return {"label": R["label"], "obs": R["observations"], "expected": R["expected"], "in_w": R["in_w"],
            "window": R["window"]["obs_index"], "ebpf_meta": R["ebpf_meta_line"], "setup": R["lab_setup"],
            "iperf": R.get("iperf_raw", {}), "delta": R["ladder"]["delta"], "hz": R["hz"],
            "target_pid": R["target"]["pids"][0], "target_out": target_out}


def evaluate(inp: dict) -> dict:
    """R2-E ground truth GP GN GS GV GI G0 G6' GL GC G7 (+ R2-C host-level conditions), from saved raw inputs."""
    exp = experiment_of(inp["label"])
    obs = [parse_obs(t) for t in inp["obs"]]
    i_b0, i_w0, i_w1 = inp["window"]
    iperf = {n: iperf_client(t) for n, t in sorted(inp["iperf"].items())}
    setup = inp["setup"]
    mb = setup.get("netdev_max_backlog")
    G = {"GP": evaluate_gp(obs, inp["expected"], inp["in_w"]),
         "GN": evaluate_gn(obs, setup, iperf, exp),
         "GS": evaluate_gs(obs, i_b0, i_w0, i_w1, exp, inp["ebpf_meta"], inp["delta"],
                           int(mb) if str(mb).isdigit() else None, inp["hz"])}
    G["GV"] = evaluate_gv(G["GS"], exp)
    G["GI"] = evaluate_gi(obs, i_b0, i_w0, i_w1, int(inp["target_pid"]))
    G["G0"] = evaluate_g0(obs)
    G["G6p"] = evaluate_g6p(obs, i_b0, i_w0, i_w1, exp)
    G["GL"] = evaluate_gl(obs, iperf, exp)
    G["GC"] = evaluate_gc(obs, i_w0, i_w1, exp)
    G["G7"] = evaluate_g7(obs, i_w0, i_w1)
    G["host_level_aborts"] = C.host_level_aborts(obs, i_b0, i_w0, i_w1)
    G["setup_checks"] = {"rps_readback": setup.get("rps_readback") == RPS_READBACK[exp.rps] if exp.lab else True,
                         "lab_verified": bool(setup.get("lab_verified")) if exp.lab else True}
    lw = C.lateness_stats(inp.get("target_out"), int(obs[i_w0]["mono"] * 1e9), int(obs[i_w1]["mono"] * 1e9))
    lb = C.lateness_stats(inp.get("target_out"), int(obs[i_b0]["mono"] * 1e9), int(obs[i_w0]["mono"] * 1e9))
    G["lateness"] = {"b": lb, "w": lw}                         # recorded only
    safety = ("GP", "GN", "G0", "G6p", "GL", "G7")
    fault = {"S2": ("GS", "GV", "GI"), "S3": ("GS", "GV", "GI"), "S1": ("GS", "GV")}.get(exp.kind, ("GS",)) + ("GC",)
    G["computable"] = all(G[g]["ok"] is not None for g in safety + fault)
    ok = G["computable"] and all(G[g]["ok"] for g in safety + fault) and all(G["setup_checks"].values()) and \
        not G["host_level_aborts"]
    G["established"] = {"softirq_overload": ok if exp.kind in ("S2", "S3") else None,
                        "softirq_sub_threshold": ok if exp.kind == "S1" else None,
                        "softirq_absent_on_target": ok if exp.kind in ("E0", "N1", "N2") else None,
                        "contention_present": (G["GC"]["ok"] if exp.contender else None)}
    G["ok"] = ok
    return G


def ground_truth_aborts(G: dict, exp: Experiment) -> List[str]:
    a = []
    names = {"GP": "experiment escaped its placement", "GN": "lab isolation violated",
             "GS": "softirq ground truth contradicts the experiment", "GV": "NET_RX does not dominate softirq on 18",
             "GI": "no target scheduling impact", "G0": "CPU quota or throttling", "G6p": "foreign busy time on CPU 18",
             "GL": "packet loss", "GC": "contender contradicts the experiment", "G7": "host safety (G7)"}
    req = ("GP", "GN", "G0", "G6p", "GL", "G7", "GS", "GC") + \
        {"S2": ("GV", "GI"), "S3": ("GV", "GI"), "S1": ("GV",)}.get(exp.kind, ())
    for g in req:
        if G[g]["ok"] is None:
            a.append(f"ground truth unavailable: {g} ({G[g].get('status', G[g].get('undecided', 'not computable'))})")
        elif G[g]["ok"] is False:
            detail = G[g].get("violations") or G[g].get("checks") or {k: v for k, v in G[g].items() if k != "ok"}
            a.append(f"{names[g]} ({g}): {str(detail)[:300]}")
    for k, v in G["setup_checks"].items():
        if not v:
            a.append(f"setup check failed: {k}")
    return a + G["host_level_aborts"]


def restore_record(entries: List[dict], cleanup_rec: dict, host_compare: dict) -> dict:
    """GR from the op log and records (pure): RPS restored to 0 and verified after the last approved write and BEFORE
    any lab namespace deletion; cleanup complete; host identical. Records explicitly whether RPS restoration succeeded."""
    st = oplog_state(entries)
    zero = [k for k, e in enumerate(entries) if e.get("phase") == "result" and e["op"][0] in ("rps", "rps_restore")
            and e.get("value") == "0" and e.get("post") == RPS_ZERO]
    last_write = max([k for k, e in enumerate(entries) if e.get("phase") == "intent" and e["op"][0] == "rps"
                      and e.get("value") != "0"], default=-1)
    dels = [k for k, e in enumerate(entries) if e.get("phase") == "intent" and e["op"][0] == "cmd"
            and list(e["op"][1][:3]) == ["ip", "netns", "del"]]
    good_zero = [k for k in zero if k > last_write]
    restored = not st["rps_written"] or bool(good_zero)
    order_ok = not dels or not st["rps_written"] or (bool(good_zero) and min(good_zero) < min(dels))
    c = {"rps_restored": restored, "rps_reset_before_netns_deletion": order_ok,
         "cleanup_ok": bool(cleanup_rec.get("ok")), "host_identical": bool(host_compare.get("ok"))}
    return {"ok": all(c.values()), "checks": c, "rps_written": st["rps_written"],
            "unsafe_incomplete": st["rps_written"] and not (restored and order_ok)}


# ------------------------------------------------------------------------------------------ calibration ladder (pure)
def ladder_step_record(obs0: dict, obs1: dict, meta, hz: int, iperf: dict) -> dict:
    """One ladder step from two raw observations (steady-state interval): eBPF NET_RX / all softirq on 18, tick
    softirq fraction on 18, achieved rate, steering, and every loss counter."""
    a, b = parse_obs(obs0), parse_obs(obs1)
    obs = [a, b]
    secs = b["mono"] - a["mono"]
    rec = {"secs": secs}
    nr = [_sirq(obs, k, meta, TARGET_CPU, "NET_RX") for k in (0, 1)]
    al = [_sirq(obs, k, meta, TARGET_CPU) for k in (0, 1)]
    st = [(o["stat"] or {}).get("cpu18") for o in obs]
    sn = [o["softnet"] for o in obs]
    rx = [_lab_link(o, "b", IF_B, "rx_packets") for o in obs]
    ad = [_lab_link(o, "a", IF_A, "tx_dropped") for o in obs]
    bd = [_lab_link(o, "b", IF_B, "rx_dropped") for o in obs]
    ue = [o["lab_b_udp"] for o in obs]
    cl = {n: iperf_client(t) for n, t in sorted((iperf or {}).items())}
    vals = nr + al + st + sn + rx + ad + bd + ue + list(cl.values())
    if secs <= 0 or any(v is None for v in vals) or any(c.get("error") for c in cl.values()) or \
            nr[1] < nr[0] or al[1] < al[0]:
        rec["malformed"] = True
        return rec
    dt = st[1]["total"] - st[0]["total"]
    rec.update(malformed=False,
               netrx18=(nr[1] - nr[0]) / 1e9 / secs, all18=(al[1] - al[0]) / 1e9 / secs,
               frac18=None if dt <= 0 else (st[1]["softirq"] - st[0]["softirq"]) / dt,
               achieved_pps=(rx[1] - rx[0]) / secs,
               processed18=sn[1][TARGET_CPU]["processed"] - sn[0][TARGET_CPU]["processed"],
               b0_rx=rx[1] - rx[0],
               loss={"softnet": sum(sn[1][c]["dropped"] - sn[0][c]["dropped"] for c in sn[1]),
                     "a_tx_dropped": ad[1] - ad[0], "b_rx_dropped": bd[1] - bd[0],
                     "udp": sum(ue[1][k] - ue[0][k] for k in ("InErrors", "RcvbufErrors", "NoPorts")),
                     "iperf3_lost": sum(c["lost_packets"] for c in cl.values())})
    if rec["frac18"] is None:
        rec["malformed"] = True
    return rec


def select_levels(steps: List[dict], max_backlog: int) -> dict:
    """Fixed before any evidence run (D5): delta, S1, S2, S3 from the ladder; NOT FEASIBLE otherwise. Thresholds are
    the unchanged validation parameters; nothing is tuned."""
    res = {"steps": steps, "feasible": False, "delta": None, "S1": None, "S2": None, "S3": None, "reason": None}
    usable = []
    for s in steps:
        if s.get("malformed"):
            res["reason"] = f"malformed observation at {s.get('pps')} pps"
            return res
        if any(v for v in s["loss"].values()):
            break
        if not s["processed18"] >= s["b0_rx"] - max_backlog or s["b0_rx"] <= 0:
            res["reason"] = f"RPS steering to CPU 18 not demonstrated at {s['pps']} pps"
            return res
        usable.append(s)
    if not usable:
        res["reason"] = "no loss-free ladder step"
        return res
    delta = max(abs(s["frac18"] - s["all18"]) for s in usable)
    res["delta"] = delta
    s1 = [s["pps"] for s in usable if s["netrx18"] < SI_ABS_MIN - delta and s["frac18"] < SI_ABS_MIN - delta]
    s2 = [s["pps"] for s in usable if s["netrx18"] >= SI_ABS_MIN + delta]
    res["S1"] = max(s1) if s1 else None
    res["S2"] = min(s2) if s2 else None
    s3 = [s["pps"] for s in usable if res["S2"] is not None and s["pps"] > res["S2"]]
    res["S3"] = max(s3) if s3 else None
    if res["S2"] is None:
        res["reason"] = "S2 not reachable without loss: R2-E NOT FEASIBLE"
    elif res["S3"] is None:
        res["reason"] = "no loss-free rate above S2: R2-E NOT FEASIBLE"
    elif res["S1"] is None or res["S1"] >= res["S2"]:
        res["reason"] = "no sub-threshold S1 below S2: R2-E NOT FEASIBLE"
    else:
        res["feasible"] = True
    return res


def level_pps(ladder: dict, exp: Experiment) -> Optional[int]:
    if exp.traffic in ("S1", "S2", "S3"):
        return ladder[exp.traffic]
    return None


def check_ladder(ladder: dict) -> dict:
    """The wrapper passes the calibration result to every run; the driver re-validates it."""
    if not isinstance(ladder, dict) or ladder.get("feasible") is not True:
        raise R2ERefused("calibration ladder missing or NOT FEASIBLE")
    if not all(ladder.get(k) in LADDER_PPS for k in ("S1", "S2", "S3")) or \
            not ladder["S1"] < ladder["S2"] < ladder["S3"]:
        raise R2ERefused(f"ladder levels invalid: {[ladder.get(k) for k in ('S1', 'S2', 'S3')]}")
    if not isinstance(ladder.get("delta"), (int, float)) or isinstance(ladder["delta"], bool) or \
            not 0 <= ladder["delta"] < SI_ABS_MIN:
        raise R2ERefused(f"ladder delta invalid: {ladder.get('delta')!r}")
    return ladder


# ------------------------------------------------------------------------------------------ metric gate
REQUIRED = (
    ("sched.run_delay_excess.target", "cg", "RATE", True), ("psi.cpu.some.target", "cg", "RATE", True),
    ("cpu.util.cpuset", "cpuset", "MEAN", True), ("cpu.steal.cpuset", "cpuset", "MEAN", True),
    ("softirq.frac.percpu", f"cpu:{TARGET_CPU}", "RATIO", True),
    ("softirq.relevant_cpu_max", "cpuset", "MAX", True),
    ("sched.latency_hist.target", "cg", "P50", True), ("sched.latency_hist.target", "cg", "P99", True),
    ("throttle.quota_limited", "cg", "GAUGE", False),
)
RECORDED = ("softirq.net_rx_rate.percpu", "softnet.time_squeeze.percpu", "softirq.imbalance",
            "softirq.exec_time.percpu", "net.drop.softnet")


def metric_gate(snapshot, cov_min: float, n_base_min: float) -> dict:
    """The measurements SI.R1 / SI.R2 / CC.* need are usable (baseline where the clause uses one); no quota; the
    target netns quiet (net.drop.softnet is CPU-scoped and judged by GL / PR-2, not here)."""
    cg = f"cgroup:{C.TARGET_CGROUP_PATH}"
    ms = snapshot.measurements
    find = lambda f, sc, agg=None: [m for m in ms if m.feature_id == f and m.scope == (cg if sc == "cg" else sc)
                                    and (agg is None or m.aggregation.value == agg)]
    c, aborts = {}, []
    c["target"] = snapshot.target.cgroup_path == C.TARGET_CGROUP_PATH and snapshot.target.cpuset == str(TARGET_CPU)
    if not c["target"]:
        aborts.append("snapshot target is not the R2-E target")
    for f, sc, agg, needs_baseline in REQUIRED:
        found = find(f, sc, agg)
        key = f"{f}[{agg}]"
        bad = []
        if len(found) != 1:
            bad.append("not present exactly once")
        else:
            m = found[0]
            if m.quality.value not in ("OK", "PARTIAL") or m.value is None:
                bad.append(f"quality {m.quality.value}")
            elif m.quality.value == "PARTIAL" and m.coverage < cov_min:
                bad.append(f"coverage {m.coverage}")
            if needs_baseline and (m.baseline is None or not m.baseline.adequate or m.baseline.n < n_base_min):
                bad.append("baseline inadequate")
            if f == "throttle.quota_limited" and m.value != 0.0:
                bad.append(f"value {m.value} != 0.0 (no quota)")
        c[key] = not bad
        if bad:
            aborts.append(f"required metric {key} unusable: {', '.join(bad)}")
    tr = find("throttle.ratio", "cg")
    c["throttle_ratio_missing"] = len(tr) == 1 and tr[0].value is None and tr[0].quality.value == "MISSING"
    if not c["throttle_ratio_missing"]:
        aborts.append("throttle.ratio is not MISSING (CFS bandwidth periods advanced)")
    net = [(m.feature_id, m.scope, m.value) for m in ms if m.feature_id.startswith(("net.", "tcp."))
           and m.feature_id != "net.drop.softnet" and m.value]
    c["target_netns_quiet"] = not net
    if net:
        aborts.append(f"network activity in the target netns: {net}")
    c["gate_passed"] = snapshot.data_quality.gate_passed
    if not c["gate_passed"]:
        aborts.append("snapshot data-quality gate failed")
    rec = {f: [{"scope": m.scope, "qualifier": m.qualifier.value if m.qualifier else None, "value": m.value,
                "quality": m.quality.value} for m in ms if m.feature_id == f and m.scope == f"cpu:{TARGET_CPU}"]
           for f in RECORDED}
    rec["softirq.imbalance"] = [{"scope": m.scope, "value": m.value, "quality": m.quality.value} for m in ms
                                if m.feature_id == "softirq.imbalance"]
    return {"ok": not aborts, "checks": c, "aborts": aborts, "recorded": rec}


# ------------------------------------------------------------------------------------------ cleanup
def oplog_state(entries) -> dict:
    intents = [e for e in entries if e.get("phase") == "intent"]
    dirs = [e["op"][1] for e in intents if e["op"][0] == "mkdir"]
    netns = [e["op"][1][3] for e in intents if e["op"][0] == "cmd" and list(e["op"][1][:3]) == ["ip", "netns", "add"]]
    pids = [e["pid"] for e in entries if e.get("phase") == "result" and e["op"][0] == "spawn" and e.get("pid")]
    written = any(e["op"][0] == "rps" and e.get("value") != "0" for e in intents)
    verified_zero = [k for k, e in enumerate(entries) if e.get("phase") == "result" and
                     e["op"][0] in ("rps", "rps_restore") and e.get("value") == "0" and e.get("post") == RPS_ZERO]
    last_write = max([k for k, e in enumerate(entries) if e.get("phase") == "intent" and e["op"][0] == "rps"
                      and e.get("value") != "0"], default=-1)
    return {"dirs": [d for d in LAB_DIRS if d in dirs], "netns": [n for n in LAB_NETNS if n in netns], "pids": pids,
            "rps_written": written, "rps_verified_zero_after_last_write": any(k > last_write for k in verified_zero)}


def cleanup(host, sysr, entries, wait_s: float = 5.0, sleep=time.sleep, after_rps=None) -> dict:
    """Idempotent, from the op log, in the approved order: (1) kill the traffic leaf; (2) RPS -> 0, verified; then
    after_rps() (the driver stops its eBPF loader here); (3) kill the remaining lab processes, remove the cgroups;
    (4) delete the lab namespaces ONLY if RPS is verified 0; (5) verify.
    Never touches what the run did not create; never signals a process outside the lab cgroup."""
    st = oplog_state(entries)
    steps, errors = [], []
    rps_rec = {"attempted": False}

    def step(name, fn):
        try:
            fn()
            steps.append(name)
            return True
        except Exception as exc:                       # noqa: BLE001 -- recorded; cleanup continues
            errors.append(f"{name}: {exc!r}")
            return False

    def populated(d):
        return sysr.exists(d) and "populated 1" in (sysr.read(f"{d}/cgroup.events") or "")

    # (1) traffic first: no packet is in flight while RPS is reset
    if TRAFFIC_DIR in st["dirs"] and sysr.exists(TRAFFIC_DIR):
        step("traffic cgroup.kill", lambda: host.apply(("write", f"{TRAFFIC_DIR}/cgroup.kill", "1")))
        deadline = time.monotonic() + wait_s
        while populated(TRAFFIC_DIR) and time.monotonic() < deadline:
            sleep(0.05)
        if populated(TRAFFIC_DIR):
            errors.append("traffic cgroup still populated")
    # (2) RPS back to 0, read back
    if NS_B in st["netns"] and sysr.exists(f"/run/netns/{NS_B}"):
        rps_rec["attempted"] = True
        try:
            rps_rec.update(host.rps_restore())
            if not rps_rec.get("ok"):
                errors.append(f"RPS restore anomaly: {rps_rec.get('anomaly')}")
        except Exception as exc:                       # noqa: BLE001
            if st["rps_written"]:                      # unsafe/incomplete: no namespace deletion below
                rps_rec.update(ok=False, restored=False)
                errors.append(f"RPS restore failed: {exc!r}")
            else:                                      # this run never wrote RPS (e.g. the veth was never created)
                rps_rec.update(ok=True, restored=True, verified=False, unreadable=repr(exc))
    else:                                              # lab-b gone: restored only if a verified reset is logged
        restored = not st["rps_written"] or st["rps_verified_zero_after_last_write"]
        rps_rec.update(ok=restored, restored=restored, lab_b_absent=True)
        if not restored:
            errors.append("RPS was written and lab-b is gone without a verified reset (unsafe/incomplete)")
    if after_rps is not None:
        step("stop eBPF loader", after_rps)
    # (3) remaining lab processes, then the cgroups (leaves first)
    for pid in st["pids"]:
        step(f"kill {pid}", lambda pid=pid: host.apply(("kill", pid)))
    ours = LAB_DIR in st["dirs"]
    deadline = time.monotonic() + wait_s
    killed = False
    while True:
        if ours and sysr.exists(LAB_DIR) and (populated(LAB_DIR) or not killed):
            killed = step("cgroup.kill", lambda: host.apply(("write", f"{LAB_DIR}/cgroup.kill", "1"))) or killed
        wrappers = [p for p in st["pids"] if C.wrapper_alive(sysr, p)]
        if (not (ours and populated(LAB_DIR)) and not wrappers) or time.monotonic() >= deadline:
            break
        sleep(0.05)
    if C.lab_pids(sysr):
        errors.append(f"lab processes remain: {C.lab_pids(sysr)}")
    if wrappers:
        errors.append(f"timeout wrappers still running: {wrappers}")
    for d in (CONTENDER_DIR, TARGET_DIR, TRAFFIC_DIR, LAB_DIR):
        if d in st["dirs"] and sysr.exists(d):
            step(f"rmdir {d}", lambda d=d: host.apply(("rmdir", d)))
    # (4) lab namespaces (this destroys the veth pair) -- only after a verified RPS reset
    if rps_rec.get("restored"):
        for ns in st["netns"]:
            if sysr.exists(f"/run/netns/{ns}"):
                step(f"netns del {ns}", lambda ns=ns: host.apply(netns_del(ns)))
    elif st["netns"]:
        errors.append("lab namespaces NOT deleted: RPS not verified 0 (unsafe/incomplete cleanup; manual cleanup "
                      "and verification required before any further run)")
    v = cleanup_state(sysr, st["pids"])                # (5)
    v["checks"]["rps_restored"] = bool(rps_rec.get("restored"))
    v["ok"] = all(v["checks"].values())
    return {"ok": not errors and v["ok"], "rps_restore": rps_rec, "steps": steps, "errors": errors, "verify": v,
            "unsafe_incomplete": st["rps_written"] and not rps_rec.get("restored")}


def cleanup_state(sysr, pids=()) -> dict:
    c = {"lab_cgroup_absent": not sysr.exists(LAB_DIR), "no_sentinel_cgroup": not C.sentinel_cgroups(sysr),
         "no_lab_process": not C.lab_pids(sysr),
         "no_logged_pid_alive_in_lab": not [p for p in pids if f"::/{C.LAB}" in (sysr.read(f"/proc/{p}/cgroup") or "")],
         "no_wrapper_alive": not [p for p in pids if C.wrapper_alive(sysr, p)],
         "no_lab_netns": not lab_netns_present(sysr), "no_lab_interface_in_host": not host_lab_ifaces(sysr)}
    return {"ok": all(c.values()), "checks": c}


# ------------------------------------------------------------------------------------------ simulated host (dry-run)
class SimHost:
    """In-memory Host + Sys for the dry-run and tests: cgroupfs rules (no rmdir while populated / with children),
    lab namespaces, the veth pair, the rx-0 RPS map (through the same rps_write/rps_restore) and the rps_needed
    leak a namespace deletion with a non-zero map would cause."""

    def __init__(self, exp, iters=1000, pps=None, fail_at=None, fail_rps=None):
        self.exp, self.iters, self.pps, self.fail_at, self.fail_rps = exp, iters, pps, fail_at, fail_rps
        self.dirs, self.procs, self.alive, self.wrappers = set(), {d: [] for d in LAB_DIRS}, set(), {}
        self.netns, self.veth, self.rps = set(), False, RPS_ZERO
        self.leaked, self.events, self.entries, self.n, self.next_pid = False, [], [], 0, 50000
        self.files = {}

    def _log(self, **kw):
        self.entries.append(kw)

    # Host
    def apply(self, op, stdout=None, stderr=None):
        check_op(op, self.exp, self.iters, self.pps)
        logged = [op[0], list(op[1]) if op[0] == "cmd" else op[1]]
        self._log(phase="intent", op=logged)
        self.n += 1
        if self.fail_at == self.n:
            self._log(phase="result", op=logged, ok=False, err="injected")
            raise OSError(f"injected failure at operation {self.n}: {op[0]}")
        res = self._do(op)
        self._log(phase="result", op=logged, ok=True, pid=getattr(res, "pid", None))
        return res

    def _do(self, op):
        kind = op[0]
        if kind == "mkdir":
            parent = op[1].rsplit("/", 1)[0]
            if op[1] in self.dirs or (parent != C.CG_ROOT and parent not in self.dirs):
                raise OSError("mkdir")
            self.dirs.add(op[1])
        elif kind == "rmdir":
            if self.procs.get(op[1]) or any(d.startswith(op[1] + "/") for d in self.dirs):
                raise OSError("busy")
            self.dirs.discard(op[1])
        elif kind == "write":
            d = op[1].rsplit("/", 1)[0]
            if d not in self.dirs:
                raise OSError("no such cgroup")
            if op[1].endswith("cgroup.kill"):
                for k in list(self.procs):
                    if k.startswith(d):
                        for p in self.procs[k]:
                            self._die(p)
                        self.procs[k] = []
                self.events.append(("cgroup.kill", d))
            self.files[op[1]] = op[2]
        elif kind == "cmd":
            a = op[1]
            if a[:3] == ("ip", "netns", "add"):
                if a[3] in self.netns:
                    raise OSError("exists")
                self.netns.add(a[3])
            elif a[:3] == ("ip", "netns", "del"):
                if a[3] not in self.netns:
                    raise OSError("absent")
                self.netns.discard(a[3])
                if self.veth:
                    if self.rps != RPS_ZERO:
                        self.leaked = True          # rx_queue_release frees the map without static_branch_dec
                    self.veth, self.rps = False, RPS_ZERO
                self.events.append(("netns del", a[3]))
            elif a[:3] == ("ip", "link", "add"):
                if not {NS_A, NS_B} <= self.netns or self.veth:
                    raise OSError("link add")
                self.veth = True
            elif not self.veth:
                raise OSError("no veth")
        elif kind == "spawn":
            leaf = {"contender": CONTENDER_DIR, "server": TRAFFIC_DIR, "client": TRAFFIC_DIR}.get(op[1], TARGET_DIR)
            if leaf not in self.dirs:
                raise OSError("leaf missing")
            pid, self.next_pid = self.next_pid, self.next_pid + 2
            self.procs[leaf] = self.procs.get(leaf, []) + [pid + 1]
            self.wrappers[pid] = pid + 1
            self.alive |= {pid, pid + 1}
            return type("P", (), {"pid": pid})()
        elif kind == "kill":
            for k in self.procs:
                if op[1] in self.procs[k]:
                    self.procs[k] = [p for p in self.procs[k] if p != op[1]]
                    self._die(op[1])
        return None

    def _die(self, pid):
        self.alive.discard(pid)
        for w, c in self.wrappers.items():
            if c == pid:
                self.alive.discard(w)

    def _rps_run(self, mode, value):
        if NS_B not in self.netns or not self.veth:
            return 1, ""
        if mode == "read":
            return 0, self.rps + "\n"
        self.n += 1
        if self.fail_at == self.n or self.fail_rps == "write" or (self.fail_rps == "restore" and value == "0"):
            return 1, ""
        bad = self.fail_rps == "readback" and value != "0"
        self.rps = "0c0000" if bad else RPS_READBACK[value]   # 0c0000 = CPUs 18+19: no approved write produces it
        self.events.append(("rps", value))
        return 0, ""

    def rps_write(self, value, expected_prev):
        return rps_write(value, expected_prev, self._rps_run, self._log)

    def rps_restore(self):
        return rps_restore(self._rps_run, self._log)

    # Sys
    def exists(self, path):
        if path.startswith("/run/netns/"):
            return path.rsplit("/", 1)[1] in self.netns
        return path in self.dirs

    def read(self, path):
        if path.endswith("/cgroup.events"):
            d = path.rsplit("/", 1)[0]
            return f"populated {int(any(self.procs.get(x) for x in LAB_DIRS if x.startswith(d)))}\\n"
        if path.startswith("/proc/") and path.endswith("/cgroup"):
            pid = int(path.split("/")[2])
            if pid not in self.alive:
                return None
            return "0::/user.slice/driver\n" if pid in self.wrappers else f"0::/{C.LAB}/x\n"
        if path.startswith("/proc/") and path.endswith("/cmdline"):
            pid = int(path.split("/")[2])
            return "\0".join(C.WRAPPER + ["sh"]) + "\0" if pid in self.wrappers and pid in self.alive else None
        return None

    def listdir(self, path):
        if path == "/run/netns":
            return sorted(self.netns)
        if path == "/sys/class/net":
            return ["docker0", "enp0s31f6", "lo"]
        return None

    def cgroup_dirs(self):
        return sorted(d[len(C.CG_ROOT) + 1:] for d in self.dirs)

    def pids(self):
        return sorted(self.alive)


def simulate(exp: Experiment, fail_at=None, crash_after=None, fail_rps=None, fail_cleanup_at=None) -> dict:
    """The driver's order (setup, RPS, target, servers, contender, clients) with a failure injected at operation
    fail_at, a crash after crash_after steps, or an RPS failure; then cleanup from the op log. Safe outcomes only:
    either everything is gone with RPS reset before the namespace deletion, or (RPS not restorable) the namespaces are
    kept, the cleanup reports unsafe/incomplete, and no leak happened."""
    pps = LADDER_PPS[3] if exp.traffic else None
    sim = SimHost(exp, pps=pps, fail_at=fail_at, fail_rps=fail_rps)
    out = str(REPO / "results" / "phase1c_r2e" / "sim" / "x.json")
    steps = [("op", op) for op in setup_plan(exp)]
    if exp.lab:
        steps.append(("rps", exp.rps))
    if exp.kind == "CAL":
        steps.append(("op", ("spawn", "calibration", C.calibration_argv(out))))
    elif exp.kind != "LADDER":
        steps.append(("op", ("spawn", "target", C.target_argv(1000, out))))
    if exp.lab:
        steps += [("op", ("spawn", "server", server_argv(i))) for i in (0, 1)]
    if exp.contender:
        steps.append(("op", ("spawn", "contender", C.contender_argv(out))))
    if exp.traffic:
        secs = LADDER_STEP_S if exp.traffic == "LADDER" else CLIENT_T
        steps += [("op", ("spawn", "client", client_argv(i, pps, secs))) for i in (0, 1)]
    failed = None
    try:
        for k, (kind, x) in enumerate(steps):
            if crash_after is not None and k >= crash_after:
                break
            if kind == "rps":
                sim.rps_write(x, RPS_ZERO)
            else:
                sim.apply(x)
    except (OSError, RpsAbort, R2ERefused) as exc:
        failed = str(exc)
    sim.fail_at = None if fail_cleanup_at is None else sim.n + fail_cleanup_at   # injection inside the cleanup only
    res = cleanup(sim, sim, list(sim.entries), wait_s=0.0, sleep=lambda s: None)
    gr = restore_record(sim.entries, res, {"ok": True})
    ev = sim.events
    dels = [k for k, e in enumerate(ev) if e[0] == "netns del"]
    zero = [k for k, e in enumerate(ev) if e == ("rps", "0")]
    rps_set = any(e[0] == "rps" and e[1] != "0" for e in ev)
    order = not dels or not rps_set or (zero and min(zero) < min(dels))
    clean = not sim.dirs and not sim.alive and not sim.netns and not sim.veth
    safe_abort = fail_rps == "restore" and rps_set and not res["ok"] and res["unsafe_incomplete"] and \
        NS_B in sim.netns and not sim.leaked and not gr["ok"]
    if fail_rps == "restore":
        ok = safe_abort
    elif fail_rps == "readback":                       # anomaly reported (never silently OK), restored, nothing leaked
        ok = clean and order and not sim.leaked and not res["ok"] and bool(res["rps_restore"].get("anomaly")) and \
            res["rps_restore"].get("restored") and not gr["ok"]
    elif fail_cleanup_at is not None:                  # a failing cleanup step is reported; never a leak
        ok = not sim.leaked and (not res["ok"] or res["ok"] and clean) and (res["ok"] == gr["ok"])
    else:
        ok = res["ok"] and clean and order and not sim.leaked and gr["ok"]
    return {"failed_at": failed, "cleanup_ok": res["ok"], "host_clean": clean, "rps_reset_before_netns_del": order,
            "leaked": sim.leaked, "safe_abort": safe_abort, "gr_ok": gr["ok"], "ok": bool(ok)}


def simulation_cases() -> dict:
    cases = []
    for kind, exp in EXPERIMENTS.items():
        n = len(setup_plan(exp)) + (1 if exp.lab else 0) + (0 if exp.kind == "LADDER" else 1) + \
            (2 if exp.lab else 0) + int(exp.contender) + (2 if exp.traffic else 0)
        cases += [(kind, simulate(exp, f)) for f in [None] + list(range(1, n + 1))]
        cases += [(kind, simulate(exp, crash_after=c)) for c in range(1, n + 1)]
        if exp.lab:
            cases += [(kind, simulate(exp, fail_rps=m)) for m in ("write", "readback", "restore")]
        cases += [(kind, simulate(exp, fail_cleanup_at=c)) for c in range(1, 16)]
    bad = [(k, r) for k, r in cases if not r["ok"]]
    return {"cases": len(cases), "ok": not bad, "failures": bad[:5],
            "safe_aborts": sum(1 for _, r in cases if r["safe_abort"])}


def _sim_lab_raw(b_operstate="UP", b_kind="veth", q=1, extra=False, malformed=False, b_flags=("UP", "LOWER_UP")):
    """Synthetic `ip -j` texts of a lab inspection (dry-run / tests only)."""
    def side(ifn, oper, kind, flags):
        lo = {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "operstate": "UNKNOWN", "qdisc": "noqueue",
              "num_tx_queues": 1, "num_rx_queues": 1}
        v = {"ifname": ifn, "flags": ["BROADCAST", "MULTICAST"] + list(flags), "operstate": oper, "qdisc": "noqueue",
             "num_tx_queues": q, "num_rx_queues": q, "linkinfo": {"info_kind": kind}}
        return json.dumps([lo, v] + ([{"ifname": "tun0"}] if extra else []))
    raw = {"a_links": side(IF_A, "UP", "veth", ("UP", "LOWER_UP")), "b_links": side(IF_B, b_operstate, b_kind, b_flags),
           "a_routes": json.dumps([{"dst": SUBNET, "dev": IF_A}]), "b_routes": json.dumps([{"dst": SUBNET, "dev": IF_B}]),
           "a_routes6": "[]", "b_routes6": "[]"}
    if malformed:
        raw["b_links"] = "{not json"
    return raw


def settle_simulation() -> dict:
    """settle_lab against scripted inspections on a fake clock: the verdicts the approved semantics require."""
    good = _sim_lab_raw()
    scripts = {
        "immediate_success": ([good], True, 1),
        "transient_operstate": ([_sim_lab_raw("LOWERLAYERDOWN"), good], True, 2),
        "eventual_success": ([_sim_lab_raw("DOWN")] * 5 + [_sim_lab_raw("LOWERLAYERDOWN")] * 5 + [good], True, 11),
        "persistent_down": ([_sim_lab_raw("DOWN")], False, 31),
        "malformed_inspection": ([_sim_lab_raw(malformed=True)], False, 31),
        "wrong_interface_type": ([_sim_lab_raw(b_kind="dummy")], False, 31),
        "wrong_queue_count": ([_sim_lab_raw(q=24)], False, 31),
        "unexpected_device": ([_sim_lab_raw(extra=True)], False, 31),
        "admin_down_flags": ([_sim_lab_raw("UNKNOWN", b_flags=())], False, 31),
    }
    res = {}
    for name, (seq, want, n) in scripts.items():
        t = {"now": 0.0}
        it = iter(seq)
        last = {"raw": seq[-1]}
        read = lambda: last.update(raw=next(it, last["raw"])) or last["raw"]
        attempts, saves = [], []
        r = settle_lab(read, attempts, lambda: saves.append(len(attempts)), clock=lambda: t["now"],
                       sleep=lambda s: t.__setitem__("now", round(t["now"] + s, 6)), wall=lambda: 0.0)
        res[name] = bool(r["settled"] is want and r["n_attempts"] == n == len(attempts) and len(saves) == 2 * n and
                         all(a["attempt"] == i for i, a in enumerate(attempts)) and (want or r["final_reason"]))
    return {"ok": all(res.values()), "cases": res}


# ------------------------------------------------------------------------------------------ dry run
def dry_run(sysr) -> dict:
    """Read-only: prerequisites, allocation, intended mutations, guards, RPS helper, cleanup simulation, metric and
    ground-truth sources. Never instantiates Host; creates no cgroup, namespace, veth, process, RPS map or traffic."""
    from sentinelai.collectors.ebpf import ebpf_calcs
    from sentinelai.collectors.features import build as feature_table
    from sentinelai.diagnostic.contract import Target

    rep = {"mode": "r2e dry-run", "criteria": CRITERIA, "matrix": MATRIX, "rps_path": f"{NS_B}:{RPS_REL}"}
    before = host_snapshot(sysr, require_bpf=False)
    rep["preflight"] = preflight(sysr)
    rep["allocation"] = allocation_checks()
    out = REPO / "results" / "phase1c_r2e" / "<TS>"
    plan = {"calibration": {"runtime_step": "0a", "setup": setup_plan(EXPERIMENTS["CAL"]),
                            "spawn": [("calibration", C.calibration_argv(str(out / "calibration" / "c.json")))]},
            "ladder": {"runtime_step": "0b", "setup": setup_plan(EXPERIMENTS["LADDER"]), "rps": "40000",
                       "rates_pps": LADDER_PPS, "step_s": LADDER_STEP_S, "evidence": "provenance only"}}
    for label in MATRIX:
        exp = experiment_of(label)
        plan[label] = {"experiment": exp.__dict__, "setup": setup_plan(exp), "rps": exp.rps,
                       "spawn": ["target", "server x2 (CPU 23)"] + (["contender (W)"] if exp.contender else []) +
                       ([f"client x2 (CPUs 20, 22) at the {exp.traffic} ladder rate (W)"] if exp.traffic else []),
                       "teardown": ["traffic cgroup.kill", "RPS -> 0 (read back)", "cgroup.kill", "rmdir leaves",
                                    f"ip netns del {NS_A}", f"ip netns del {NS_B}"]}
    rep["intended_mutations"] = plan
    g = {}
    for label in MATRIX:
        exp = experiment_of(label)
        pps = LADDER_PPS[3] if exp.traffic else None
        try:
            for op in setup_plan(exp) + [("write", f"{TRAFFIC_DIR}/cgroup.kill", "1"), netns_del(NS_A),
                                         netns_del(NS_B), ("rmdir", TRAFFIC_DIR)]:
                check_op(op, exp, 1000, pps)
            for i in (0, 1):
                check_op(("spawn", "server", server_argv(i)), exp, 1000, pps)
                if exp.traffic:
                    check_op(("spawn", "client", client_argv(i, pps)), exp, 1000, pps)
            check_rps_argv(rps_argv("write", 4026531840, exp.rps))
            g[label] = True
        except R2ERefused as exc:
            g[label] = str(exc)
    s3 = EXPERIMENTS["S3"]
    pps = LADDER_PPS[3]
    bad_client = client_argv(0, pps)
    bad_client[bad_client.index("-A") + 1] = str(TARGET_CPU)
    forbidden = [("write", f"{TARGET_DIR}/cpu.max", "50000 100000"), ("write", f"{C.CG_ROOT}/cpuset.cpus", "0-23"),
                 ("write", f"{TRAFFIC_DIR}/cpuset.cpus", "18"), ("mkdir", f"{C.CG_ROOT}/system.slice/x"),
                 ("cmd", ("ip", "link", "set", "enp0s31f6", "down")), ("cmd", ("ip", "link", "set", "docker0", "down")),
                 ("cmd", ("tc", "qdisc", "add", "dev", IF_A, "root", "netem")),
                 ("cmd", ("sysctl", "-w", "net.core.netdev_max_backlog=10000")),
                 ("cmd", ("ethtool", "-K", IF_B, "gro", "on")), ("cmd", ("modprobe", "pktgen")),
                 ("cmd", ("ip", "netns", "del", "other")), ("cmd", ("ip", "route", "add", "default", "via", IP_B)),
                 ("cmd", ("ip", "link", "add", IF_A, "netns", NS_A, "type", "veth", "peer", "name", IF_B, "netns",
                          NS_B)),
                 ("spawn", "client", bad_client), ("spawn", "client", client_argv(0, LADDER_PPS[4])),
                 ("spawn", "server", server_argv(0)[:-6] + ["-A", "18"]),
                 ("write", "/sys/class/net/enp0s31f6/queues/rx-0/rps_cpus", "40000"), ("exec", "rps")]
    refused = []
    for op in forbidden:
        try:
            check_op(op, s3, 1000, pps)
            refused.append(False)
        except (R2ERefused, ValueError, IndexError):
            refused.append(True)
    rps_bad = [RPS_PREFIX + ["write", "1", "ff"], RPS_PREFIX + ["write", "1"], RPS_PREFIX + ["read", "1", "0"],
               ["ip", "netns", "exec", NS_A] + RPS_PREFIX[4:] + ["write", "1", "40000"],
               RPS_PREFIX[:-1] + [RPS_HELPER.replace("rx-0", "rx-1"), "write", "1", "0"], RPS_PREFIX + ["erase", "1"]]
    for argv in rps_bad:
        try:
            check_rps_argv(argv)
            refused.append(False)
        except R2ERefused:
            refused.append(True)
    rep["guards"] = {"planned_ops_accepted": g, "forbidden_refused": all(refused), "n_forbidden": len(refused)}
    rep["rps_helper"] = {"no_follow": "O_NOFOLLOW" in RPS_HELPER, "netns_inode_check": "/proc/self/ns/net" in RPS_HELPER,
                         "only_lab_device": f"['lo','{IF_B}']" in RPS_HELPER, "realpath_virtual": RPS_REAL in RPS_HELPER,
                         "single_queue": "['rx-0','tx-0']" in RPS_HELPER,
                         "values": "('40000','80000','0')" in RPS_HELPER}
    rep["cleanup_simulation"] = simulation_cases()
    rep["lab_settle_simulation"] = settle_simulation()
    t = Target(name="r2e", cgroup_path=C.TARGET_CGROUP_PATH, pids=(1,), cpuset=str(TARGET_CPU), netns_ref="pid:1",
               ifaces=())
    calcs = feature_table(t, tuple(sorted(C.HOST_CPUS)), (TARGET_CPU,), (TARGET_CPU,), False) + \
        ebpf_calcs(t, tuple(sorted(C.HOST_CPUS)), ())
    have = {(c.feature, c.scope) for c in calcs}
    cg = f"cgroup:{C.TARGET_CGROUP_PATH}"
    rep["metric_table"] = {f"{f}[{a}]": (f, cg if sc == "cg" else sc) in have for f, sc, a, _ in REQUIRED}
    rep["metric_table"]["softirq.exec_time.percpu[cpu:18]"] = ("softirq.exec_time.percpu", "cpu:18") in have
    me = os.getpid()
    rep["gt_sources"] = {
        "proc_stat_cpu18": bool(C.proc_stat_cpus(sysr.read("/proc/stat")).get("cpu18")),
        "schedstat_v15": C.schedstat_rq_cpu_time(sysr.read("/proc/schedstat")) is not None,
        "softirqs_net_rx": len((softirqs(sysr.read("/proc/softirqs")) or {}).get("NET_RX", [])) == 24,
        "softnet_cpu_ids": sorted(softnet(sysr.read("/proc/net/softnet_stat")) or {}) == list(range(24)),
        "task_stat": task_stat(sysr.read(f"/proc/{me}/stat")) is not None,
        "task_schedstat": task_schedstat(sysr.read(f"/proc/{me}/schedstat")) is not None,
        "ksoftirqd18_visible": any((task_stat(sysr.read(f"/proc/{p}/stat")) or {}).get("comm") == "ksoftirqd/18"
                                   for p in cpu18_kthread_pids(sysr)),
        "snmp_udp": snmp_udp(sysr.read(f"/proc/{me}/net/snmp")) is not None,
        "netdev_max_backlog": (sysr.read("/proc/sys/net/core/netdev_max_backlog") or "").strip().isdigit(),
        "ip_link_numrxqueues": all(k in sysr.ip_link_help() for k in ("numtxqueues", "numrxqueues")),
        "iperf3_3x": (sysr.run((IPERF3, "--version")) or "").startswith("iperf 3."),
        "loader_libbpf_1_4": '"libbpf_linked":"1.4"' in (sysr.run((C.LOADER, "--version")) or ""),
    }
    rep["bpf_release_simulation"] = C.simulate_bpf_release()
    after = host_snapshot(sysr, require_bpf=False)
    rep["zero_mutation"] = compare_host(before, after, require_bpf=False)
    rep["structural_ok"] = (rep["preflight"]["ok"] and all(rep["allocation"].values())
                            and all(v is True for v in g.values()) and rep["guards"]["forbidden_refused"]
                            and all(rep["rps_helper"].values()) and rep["cleanup_simulation"]["ok"]
                            and rep["lab_settle_simulation"]["ok"]
                            and all(rep["metric_table"].values()) and all(rep["gt_sources"].values())
                            and rep["bpf_release_simulation"]["ok"] and rep["zero_mutation"]["ok"])
    return rep


# ------------------------------------------------------------------------------------------ candidate / offline
def candidate(repo, base=BASE_COMMIT):
    """HEAD descends from d11e755 and differs from it only by R2-E tooling; no tracked file modified."""
    g = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)
    head, b = g("rev-parse", "HEAD"), g("rev-parse", "--verify", f"{base}^{{commit}}")
    if head.returncode or b.returncode:
        return {"ok": False, "reason": "HEAD or base not resolvable"}
    head, b = head.stdout.strip(), b.stdout.strip()
    if g("merge-base", "--is-ancestor", b, head).returncode:
        return {"ok": False, "reason": f"HEAD {head} does not descend from {b}"}
    changed = [p for p in g("diff", "--name-only", b, head).stdout.split() if p not in TOOLING]
    if changed:
        return {"ok": False, "reason": f"changed since {b[:7]} beyond R2-E tooling: {sorted(changed)}"}
    if g("status", "--porcelain", "--untracked-files=no").stdout.strip():
        return {"ok": False, "reason": "tracked files modified"}
    return {"ok": True, "head": head, "base": b}


def offline_ladder(run_dir) -> dict:
    """Closeout of step 0b: every ladder step and the selected levels recomputed from the saved observations."""
    R = json.loads((Path(run_dir) / "run.json").read_text())
    steps = []
    for s in R["ladder"]["steps"]:
        a, b = s["obs_index"]
        rec = ladder_step_record(R["observations"][a], R["observations"][b], R["ebpf_meta_line"], R["hz"],
                                 s["iperf_raw"])
        rec.update(pps=s["pps"], iperf_raw=s["iperf_raw"], obs_index=s["obs_index"])
        steps.append(rec)
    sel = select_levels(steps, int(R["lab_setup"]["netdev_max_backlog"]))
    sel["hz"] = R["hz"]
    norm = lambda x: json.loads(json.dumps(x, sort_keys=True, default=str))
    ls = replay_lab_settle(R.get("lab_setup"))
    return {"ok": norm(sel) == norm(R["ladder"]) and ls["identical"] is not False, "feasible": sel["feasible"],
            "lab_settle": ls}


def offline_evaluate(run_dir) -> dict:
    """Closeout: recompute every predicate from the saved run directory and compare with what the run recorded."""
    d = Path(run_dir)
    R = json.loads((d / "run.json").read_text())
    tj = d / "target.json"
    target_out = json.loads(tj.read_text()) if tj.exists() else None
    G = evaluate(ground_truth_inputs(R, target_out))
    gr = restore_record(C.read_oplog(d / "ops.jsonl") + C.read_oplog(d / "ops.jsonl.cleanup"), R["cleanup"],
                        R["host_compare"])
    norm = lambda x: json.loads(json.dumps(x, sort_keys=True, default=str))
    ls = replay_lab_settle(R.get("lab_setup"))
    return {"ground_truth_identical": norm(G) == norm(R["ground_truth"]), "GR_identical": norm(gr) == norm(R["GR"]),
            "lab_settle": ls,
            "ok": norm(G) == norm(R["ground_truth"]) and norm(gr) == norm(R["GR"]) and ls["identical"] is not False}


# ------------------------------------------------------------------------------------------ CLI
def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "dry-run":
        rep = dry_run(Sys())
        print(json.dumps(rep, indent=1, sort_keys=True, default=str))
        return 0 if rep["structural_ok"] else 3
    if cmd == "criteria":
        print(json.dumps({"criteria": CRITERIA, "rps": {"path": f"{NS_B}:{RPS_REL}", "values": RPS_VALUES},
                          "ladder_pps": LADDER_PPS, "matrix": MATRIX}, indent=1, sort_keys=True))
        return 0
    if cmd == "preflight":
        r = preflight(Sys())
        print(json.dumps(r, indent=1, sort_keys=True))
        return 0 if r["ok"] else 3
    if cmd == "host-snapshot":
        d = Path(argv[2])
        d.mkdir(parents=True, exist_ok=True)
        (d / "host.json").write_text(json.dumps(host_snapshot(Sys()), indent=1, sort_keys=True))
        return 0
    if cmd == "compare":
        r = compare_host(json.loads((Path(argv[2]) / "host.json").read_text()),
                         json.loads((Path(argv[3]) / "host.json").read_text()))
        print(json.dumps(r, indent=1, sort_keys=True))
        return 0 if r["ok"] else 3
    if cmd == "cleanup":                         # wrapper trap / manual recovery: every op log under OUT
        res = {}
        for log in sorted(Path(argv[2]).rglob("ops.jsonl")):
            label = log.parent.name
            exp = experiment_of(label) if label in MATRIX else EXPERIMENTS["LADDER" if label == "ladder" else "CAL"]
            res[str(log)] = cleanup(Host(exp, str(log) + ".cleanup"), Sys(), C.read_oplog(log))
        v = cleanup_state(Sys())
        unsafe = [k for k, r in res.items() if r["unsafe_incomplete"]]
        print(json.dumps({"runs": res, "final": v, "unsafe_incomplete": unsafe}, indent=1, sort_keys=True,
                         default=str))
        return 0 if v["ok"] and not unsafe and all(r["ok"] for r in res.values()) else 3
    if cmd == "candidate":
        r = candidate(argv[2], argv[3] if len(argv) > 3 else BASE_COMMIT)
        print(r["head"] if r["ok"] else r["reason"])
        return 0 if r["ok"] else 3
    if cmd == "evaluate":
        r = offline_ladder(argv[2]) if Path(argv[2]).name == "ladder" else offline_evaluate(argv[2])
        print(json.dumps(r, indent=1, sort_keys=True))
        return 0 if r["ok"] else 3
    raise SystemExit("usage: r2e_softirq.py dry-run | criteria | preflight | host-snapshot DIR | compare A B | "
                     "cleanup OUT | candidate REPO [BASE] | evaluate RUN_DIR")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
