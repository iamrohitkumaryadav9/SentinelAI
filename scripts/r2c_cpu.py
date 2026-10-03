#!/usr/bin/env python3
"""SentinelAI R2-C: controlled CPU contention, guards, ground truth and cleanup (pure except Sys/Host).

The approved design (R2-C DESIGN REVIEW: READY), implemented without reinterpretation:
  boundary   /sys/fs/cgroup/sentinel-r2c {target, contender}; controllers cpuset cpu memory pids; no process in
             the parent; cpu.max stays 'max' everywhere (no quota, no throttling)
  CPUs       target 18; contender 18 (E1, E2), 23 (N1), 19 (N2); lab support processes 0-15; 21 (NIC IRQ) excluded
  contender  one SCHED_OTHER nice-0 python3 -c busy loop; level knob = contender cpu.weight (100 | 400)
  target     one periodic process (2 ms period, fixed iterations), private interface-less netns (unshare --net)
  timeline   warm-up 10 s, B 10 s, W 10 s (contender only in W), recovery 10 s; hard timeout 60 s

Two classes touch the host. Sys only reads (/proc, /sys, /run/netns, an exact list of read-only commands). Host is the
single mutation site: every operation is re-validated by check_op() immediately before it runs, against the closed
set of operations the design allows for the experiment being run.

The five criteria the design named without a value were approved separately (R2-C parameter approval) as
engineering/safety criteria, NOT as calibrated thresholds; see CRITERIA for each value and its approved type label.
Unavailable data for any of them aborts the run (fail closed).
"""

import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import m3b_r1_compare as hostcmp  # noqa: E402  (bridge-timer-aware interface comparison, committed in c2ac7e5)
from r2a_lab import PROTECTED, SYSCTLS as R2A_SYSCTLS  # noqa: E402

REPO = Path(__file__).resolve().parents[1]

# ------------------------------------------------------------------------------------------ design constants
CG_ROOT = "/sys/fs/cgroup"
LAB = "sentinel-r2c"
LAB_DIR = f"{CG_ROOT}/{LAB}"
TARGET_DIR, CONTENDER_DIR = f"{LAB_DIR}/target", f"{LAB_DIR}/contender"
TARGET_CGROUP_PATH = f"/{LAB}/target"
LAB_DIRS = (LAB_DIR, TARGET_DIR, CONTENDER_DIR)

HOST_CPUS = frozenset(range(24))
ROOT_SUBTREE = frozenset("cpuset cpu io memory hugetlb pids rdma misc".split())
CONTROLLERS = ("cpuset", "cpu", "memory", "pids")
PARENT_CPUS = (18, 19, 23)
TARGET_CPU = 18
SUPPORT_CPUS = tuple(range(16))            # driver, collector, eBPF loader (taskset by the wrapper)
NIC_IRQ, NIC_IRQ_NAME, NIC_CPU = 134, "enp0s31f6", 21
EXPERIMENT_CPUS = frozenset(PARENT_CPUS)   # the NIC IRQ may never be on these
MEMS = "0"
TARGET_WEIGHT = 100
PIDS_MAX = "4"
CPU_MAX_UNLIMITED = "max 100000"
LAB_UID = LAB_GID = 1000
PYTHON = "/usr/bin/python3"
TARGET_SCRIPT = str(REPO / "scripts" / "r2c_target.py")
LOADER = str(REPO / "ebpf" / "build" / "sentinel_loader")
BPFTOOL = "/usr/lib/linux-hwe-6.8-tools-6.8.0-138/bpftool"

PERIOD_S, NB, NW = 1.0, 10, 10              # validation parameters W = B = 10 s (r2b_driver NUMBERS)
WARMUP_S, RECOVERY_S, HARD_TIMEOUT_S = 10, 10, 60
TARGET_DURATION_S = WARMUP_S + NB + NW + RECOVERY_S          # 40 s
TARGET_PERIOD_NS = 2_000_000
TARGET_CYCLES = TARGET_DURATION_S * 1_000_000_000 // TARGET_PERIOD_NS   # 20000
TARGET_WORK_NS = 500_000                    # calibration target: ~0.5 ms of work per cycle on an idle E-core


@dataclass(frozen=True)
class Experiment:
    kind: str
    contender_cpu: Optional[int]            # None: no contender is started (E0)
    contender_weight: int


EXPERIMENTS = {
    "E0": Experiment("E0", None, 100),
    "E1": Experiment("E1", 18, 100),
    "E2": Experiment("E2", 18, 400),
    "N1": Experiment("N1", 23, 400),
    "N2": Experiment("N2", 19, 400),
}
# Design §4: reps E0 2 (opening and closing), N1 2, N2 2, E1 3, E2 3; order E0, N1, N2, E1, E2, E0.
MATRIX = ("E0-open", "N1-rep1", "N1-rep2", "N2-rep1", "N2-rep2", "E1-rep1", "E1-rep2", "E1-rep3",
          "E2-rep1", "E2-rep2", "E2-rep3", "E0-close")

# Ground-truth and abort thresholds stated by the design (§7, §12)
G2_CONTENDER_MIN_CORES = 0.4
G3_IDLE_MAX = 0.05
G6_FOREIGN_MAX_CORES = 0.05
HOST_UTIL_B_MAX = 0.10
HOST_PSI_AVG10_MAX = 5.0

# Approved R2-C criteria (parameter approval): engineering/safety criteria, not calibrated thresholds.
G4_N_MIN = 4000                 # cycles per window = COV_MIN 0.8 x 5000 expected cycles in 10 s
G4_RATIO_MIN = 1.5              # med_W >= 1.5 * med_B (the R_MODERATE validation convention)
G4_ABS_MIN_NS = 50_000          # med_W - med_B >= 50 us (this host's default timerslack_ns)
G7_SOFTIRQ_MAX_DELTA = 0.01     # |f_W - f_B| <= 0.01 of CPU 18 time
MEM_PSI_W_MAX_US = 0            # host memory PSI some: any stall in W aborts
SWAP_MAX_PAGES_PER_S = 25.0     # (pswpin + pswpout) / W_s
SLICE_AVG10_MAX = 5.0           # non-lab slice cpu.pressure some avg10, inspected when host avg10 > 5 %
SLICE_PSI_RISE_MAX = 0.01       # r_W - r_B, r = delta some_total_us / (seconds * 1e6)
CRITERIA = {
    "G4": {"value": f"n_B,n_W >= {G4_N_MIN}; med_W >= {G4_RATIO_MIN}*med_B; med_W - med_B >= {G4_ABS_MIN_NS} ns; "
                    "psi_w > psi_b", "type": "EXPERIMENTAL HEURISTIC"},
    "G7": {"value": f"|f_W - f_B| <= {G7_SOFTIRQ_MAX_DELTA}", "type": "SAFETY THRESHOLD, repository-informed"},
    "MEMORY_PSI": {"value": f"abort if delta some_total_us(W) > {MEM_PSI_W_MAX_US}", "type": "REPOSITORY-SUPPORTED"},
    "MEMORY_SWAP": {"value": f"abort if (pswpin + pswpout) / W_s > {SWAP_MAX_PAGES_PER_S} pages/s",
                    "type": "SAFETY THRESHOLD, repository-informed"},
    "HOST_PSI": {"value": f"host avg10 > {HOST_PSI_AVG10_MAX}: abort if any of system.slice, user.slice, "
                          f"init.scope cpu.pressure some avg10 > {SLICE_AVG10_MAX} or unreadable",
                 "type": "SAFETY THRESHOLD"},
    "SLICE_PSI": {"value": f"abort if r_W - r_B > {SLICE_PSI_RISE_MAX}", "type": "SAFETY THRESHOLD"},
}

# eBPF objects owned by an R2-C run (the loader's skeleton maps + libbpf's internal maps of object "sentinel")
LOADER_BPF_MAPS = ("sn_wake", "sn_hist", "sn_stats", "sn_sirq_start", "sn_sirq_acc", "sn_retrans", "sn_kfree")
LOADER_BPF_MAP_PREFIX = "sentinel."
LOADER_BPF_PROG_PREFIX = "sn_"
BPF_RELEASE_POLL_S = 0.1
BPF_RELEASE_MAX_S = 5.0

TOOLING = ("scripts/r2c_cpu.py", "scripts/r2c_driver.py", "scripts/r2c_target.py", "scripts/r2c_validate.sh",
           "tests/faultlab/test_r2c.py")
SYSCTLS = R2A_SYSCTLS + ("kernel/sched_schedstats", "kernel/sched_autogroup_enabled", "kernel/sched_rt_runtime_us",
                         "kernel/sched_rt_period_us")
CGROUP_ATTRS = ("cpu.max", "cpu.weight", "cpuset.cpus", "cpuset.cpus.partition", "cgroup.subtree_control")
SLICES = ("system.slice", "user.slice", "init.scope")


class R2CRefused(ValueError):
    """An operation outside the R2-C authorisation."""


class LabAbort(RuntimeError):
    """An abort condition fired: stop, clean up, NO-GO."""


# ------------------------------------------------------------------------------------------ cpu lists
def parse_cpulist(text) -> frozenset:
    """Kernel cpu list ('18-19,23', '', '0-23') -> set. Malformed -> ValueError."""
    text = (text or "").strip()
    out = set()
    if not text:
        return frozenset()
    for part in text.split(","):
        if not re.fullmatch(r"\d+(-\d+)?", part):
            raise ValueError(f"malformed cpu list {text!r}")
        a, _, b = part.partition("-")
        lo, hi = int(a), int(b or a)
        if hi < lo:
            raise ValueError(f"malformed cpu list {text!r}")
        out.update(range(lo, hi + 1))
    return frozenset(out)


def cpus_text(cpus) -> str:
    return ",".join(str(c) for c in sorted(cpus))


def allocation_checks() -> Dict[str, bool]:
    """The design's CPU allocation, checked as data."""
    nc = {e.contender_cpu for e in EXPERIMENTS.values() if e.kind.startswith("N")}
    ec = {e.contender_cpu for e in EXPERIMENTS.values() if e.kind in ("E1", "E2")}
    return {
        "parent_is_union": set(PARENT_CPUS) == {TARGET_CPU} | nc | ec,
        "contention_on_target_cpu": ec == {TARGET_CPU},
        "negative_controls_off_target_cpu": TARGET_CPU not in nc,
        "nic_cpu_excluded": NIC_CPU not in PARENT_CPUS,
        "support_cpus_disjoint": not set(SUPPORT_CPUS) & set(PARENT_CPUS),
        "all_on_host": set(PARENT_CPUS) | set(SUPPORT_CPUS) <= HOST_CPUS,
        "e0_has_no_contender": EXPERIMENTS["E0"].contender_cpu is None,
        "weights": {e.contender_weight for e in EXPERIMENTS.values()} == {100, 400},
    }


def experiment_of(label: str) -> Experiment:
    if label not in MATRIX:
        raise R2CRefused(f"run {label!r} is not in the approved matrix")
    return EXPERIMENTS[label.split("-")[0]]


# ------------------------------------------------------------------------------------------ parsers
def proc_stat_cpus(text) -> Dict[str, Dict[str, int]]:
    """/proc/stat -> {'all'|'cpuN': {busy, total, idle, softirq}} with the collector's busy/total definitions."""
    out = {}
    for line in (text or "").splitlines():
        f = line.split()
        if not f or not f[0].startswith("cpu"):
            continue
        v = [int(x) for x in f[1:9]]
        user, nice, system, idle, iowait, irq, softirq, steal = v
        busy = user + nice + system + irq + softirq + steal
        out["all" if f[0] == "cpu" else f[0]] = {"busy": busy, "total": busy + idle + iowait, "idle": idle + iowait,
                                                 "softirq": softirq}
    return out


def kv(text) -> Dict[str, int]:
    """'key value' lines (cpu.stat, memory.events, vmstat) -> {key: int}."""
    out = {}
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) == 2 and re.fullmatch(r"-?\d+", p[1]):
            out[p[0]] = int(p[1])
    return out


def psi(text) -> Dict[str, float]:
    """PSI file -> {'some_avg10', 'some_total', 'full_total'} (missing lines absent)."""
    out = {}
    for line in (text or "").splitlines():
        kind, *fields = line.split()
        d = dict(x.split("=", 1) for x in fields)
        out[f"{kind}_avg10"], out[f"{kind}_total"] = float(d["avg10"]), int(d["total"])
    return out


def schedstat_rq_cpu_time(text) -> Optional[Dict[int, int]]:
    """R2-C's own strict /proc/schedstat (version 15) parser: {cpu: rq_cpu_time ns} (cpu line field 7: time tasks
    other than idle ran on the CPU). None, never a partial result, when the text is absent, not version 15, has a
    malformed cpu line, or has no cpu18 line (fail closed)."""
    if not text:
        return None
    lines = text.splitlines()
    if not lines or lines[0].split() != ["version", "15"]:
        return None
    out = {}
    for line in lines[1:]:
        p = line.split()
        if not p or not re.fullmatch(r"cpu\d+", p[0]):
            continue
        if len(p) != 10 or not all(re.fullmatch(r"\d+", x) for x in p[1:]):
            return None
        cpu = int(p[0][3:])
        if cpu in out:
            return None
        out[cpu] = int(p[7])
    return out if TARGET_CPU in out else None


def task_processor(stat_text) -> Optional[int]:
    """/proc/<pid>/stat field 39 (processor). The comm field may contain spaces and parentheses."""
    if not stat_text or ")" not in stat_text:
        return None
    rest = stat_text.rsplit(")", 1)[1].split()
    return int(rest[36]) if len(rest) > 36 else None        # rest[0] is field 3 (state); field 39 -> index 36


def netns_counters(dev_text, snmp_text) -> Optional[Dict[str, int]]:
    """Private-netns activity: all interfaces' packets/bytes (net/dev) and TCP/UDP segment counters (net/snmp)."""
    if dev_text is None or snmp_text is None:
        return None
    rx = tx = rxp = txp = 0
    for line in dev_text.splitlines()[2:]:
        if ":" not in line:
            continue
        v = line.split(":", 1)[1].split()
        rx, rxp, tx, txp = rx + int(v[0]), rxp + int(v[1]), tx + int(v[8]), txp + int(v[9])
    out = {"rx_bytes": rx, "rx_packets": rxp, "tx_bytes": tx, "tx_packets": txp}
    rows = [l.split() for l in snmp_text.splitlines()]
    for proto, keys in (("Tcp:", ("InSegs", "OutSegs", "RetransSegs")), ("Udp:", ("InDatagrams", "OutDatagrams"))):
        hdr = [r for r in rows if r and r[0] == proto]
        if len(hdr) >= 2:
            m = dict(zip(hdr[0][1:], hdr[1][1:]))
            for k in keys:
                out[f"{proto[:-1].lower()}_{k}"] = int(m[k])
    return out


# ------------------------------------------------------------------------------------------ read-only host access
READ_ONLY_COMMANDS = (
    ("ip", "-j", "-d", "link", "show"), ("ip", "-j", "addr", "show"), ("ip", "-j", "route", "show"),
    ("ip", "-j", "-6", "route", "show"), ("tc", "-j", "qdisc", "show"), ("ip", "-j", "netns", "list"),
    ("findmnt", "-rn", "-o", "TARGET,FSTYPE"), (BPFTOOL, "-j", "prog", "show"), (BPFTOOL, "-j", "link", "show"),
    (BPFTOOL, "-j", "map", "show"), (LOADER, "--version"),
)
READ_PREFIXES = ("/proc/", "/sys/", "/run/netns")


class Sys:
    """Read-only view of the running host. No write, no mutation path."""

    def _check(self, path):
        if not str(path).startswith(READ_PREFIXES) or "/../" in str(path) or "\x00" in str(path):
            raise R2CRefused(f"read outside the allowlist: {path!r}")

    def read(self, path) -> Optional[str]:
        self._check(path)
        try:
            with open(path, "rb") as fh:
                return fh.read(1 << 20).decode("ascii", "replace")
        except OSError:
            return None

    def listdir(self, path) -> Optional[List[str]]:
        self._check(path)
        try:
            return sorted(os.listdir(path))
        except OSError:
            return None

    def exists(self, path) -> bool:
        self._check(path)
        return os.path.exists(path)

    def cgroup_dirs(self) -> List[str]:
        """Every cgroup directory, relative to /sys/fs/cgroup ('' is the root)."""
        out = []
        for d, subdirs, _ in os.walk(CG_ROOT):
            rel = os.path.relpath(d, CG_ROOT)
            out.append("" if rel == "." else rel)
        return sorted(out)

    def run(self, argv) -> Optional[str]:
        if tuple(argv) not in READ_ONLY_COMMANDS:
            raise R2CRefused(f"command not in the read-only allowlist: {argv}")
        try:
            p = subprocess.run(list(argv), capture_output=True, text=True, timeout=15, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return p.stdout if p.returncode == 0 else None

    def tool(self, path) -> bool:
        return os.path.isfile(path) and os.access(path, os.X_OK)

    def uid_name(self, uid) -> Optional[str]:
        import pwd
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return None

    def pids(self) -> List[int]:
        return sorted(int(p) for p in os.listdir("/proc") if p.isdigit())


def lab_pids(sysr) -> List[int]:
    """Every process whose cgroup lies in the lab subtree."""
    out = []
    for pid in sysr.pids():
        cg = sysr.read(f"/proc/{pid}/cgroup") or ""
        if f"::/{LAB}" in cg:
            out.append(pid)
    return out


def sentinel_cgroups(sysr) -> List[str]:
    return [d for d in sysr.cgroup_dirs() if any(p.startswith("sentinel") for p in d.split("/"))]


# ------------------------------------------------------------------------------------------ mutation guard
# The hard-timeout wrapper stays OUTSIDE the lab cgroup: timeout forks sh, sh joins the leaf before any workload code
# and execs (same pid) into the workload. Each leaf therefore holds exactly one pid: the workload.
WRAPPER = ["timeout", "-s", "KILL", str(HARD_TIMEOUT_S)]
TARGET_PREFIX = WRAPPER + ["sh", "-c", f'echo $$ > {TARGET_DIR}/cgroup.procs && exec "$@"', "sh",
                           "unshare", "--net", "--",
                           "setpriv", f"--reuid={LAB_UID}", f"--regid={LAB_GID}", "--init-groups", "--",
                           PYTHON, "-I", TARGET_SCRIPT]
CONTENDER_PREFIX = WRAPPER + ["sh", "-c", f'echo $$ > {CONTENDER_DIR}/cgroup.procs && exec "$@"', "sh",
                              "setpriv", f"--reuid={LAB_UID}", f"--regid={LAB_GID}", "--init-groups", "--",
                              PYTHON, "-I", "-c"]
# One SCHED_OTHER thread, pure integer loop; no sleep, no I/O, no syscall in the loop. Its iteration count is
# published through a shared mapping (memory stores only), so it survives the SIGKILL that stops the contender.
CONTENDER_CODE = ("import mmap,sys\n"
                  "f=open(sys.argv[1],'r+b')\n"
                  "m=mmap.mmap(f.fileno(),8)\n"
                  "i=0\n"
                  "while True:\n"
                  " i+=1\n"
                  " if not i&65535:\n"
                  "  m[0:8]=i.to_bytes(8,'little')\n")


def target_argv(iters: int, out_path: str) -> List[str]:
    if isinstance(iters, bool) or not isinstance(iters, int) or not 1 <= iters <= 10_000_000:
        raise R2CRefused(f"target iterations {iters!r} out of range")
    return TARGET_PREFIX + ["--period-ns", str(TARGET_PERIOD_NS), "--cycles", str(TARGET_CYCLES),
                            "--iters", str(iters), "--out", str(out_path)]


def calibration_argv(out_path: str) -> List[str]:
    return TARGET_PREFIX + ["--calibrate", "--work-ns", str(TARGET_WORK_NS), "--out", str(out_path)]


def contender_argv(counter_path: str) -> List[str]:
    return CONTENDER_PREFIX + [CONTENDER_CODE, str(counter_path)]


def spawn_structure(argv, leaf) -> dict:
    """One-pid invariant of a spawn argv: the timeout wrapper first (outside the cgroup), then sh joins `leaf` and
    exec's the workload; no second timeout or other forking wrapper after the join."""
    join = ["sh", "-c", f'echo $$ > {leaf}/cgroup.procs && exec "$@"', "sh"]
    n = len(WRAPPER)
    after = argv[n + len(join):]
    c = {"wrapper_first": argv[:n] == WRAPPER, "join_follows_wrapper": argv[n:n + len(join)] == join,
         "single_wrapper": argv.count("timeout") == 1,
         "no_fork_after_join": not {"timeout", "sh", "nohup", "setsid", "bash"} & set(after[:-1] if after else []),
         "workload_last": PYTHON in after and after.index(PYTHON) > (after.index("--") if "--" in after else -1)}
    return {"ok": all(c.values()), "checks": c}


def _results_path(p) -> bool:
    s = str(p)
    return s.startswith(str(REPO / "results" / "phase1c_r2c") + "/") and "/../" not in s and "\x00" not in s


def setup_plan(exp: Experiment) -> List[tuple]:
    """The creation sequence of the design (§1), in order."""
    ops = [("mkdir", LAB_DIR),
           ("write", f"{LAB_DIR}/cpuset.mems", MEMS),
           ("write", f"{LAB_DIR}/cpuset.cpus", cpus_text(PARENT_CPUS)),
           ("write", f"{LAB_DIR}/cgroup.subtree_control", " ".join(f"+{c}" for c in CONTROLLERS)),
           ("mkdir", TARGET_DIR), ("mkdir", CONTENDER_DIR),
           ("write", f"{TARGET_DIR}/cpuset.cpus", str(TARGET_CPU)),
           ("write", f"{TARGET_DIR}/cpuset.mems", MEMS),
           ("write", f"{TARGET_DIR}/cpu.weight", str(TARGET_WEIGHT)),
           ("write", f"{TARGET_DIR}/pids.max", PIDS_MAX)]
    if exp.contender_cpu is not None:
        ops.append(("write", f"{CONTENDER_DIR}/cpuset.cpus", str(exp.contender_cpu)))
    ops += [("write", f"{CONTENDER_DIR}/cpuset.mems", MEMS),
            ("write", f"{CONTENDER_DIR}/cpu.weight", str(exp.contender_weight)),
            ("write", f"{CONTENDER_DIR}/pids.max", PIDS_MAX)]
    return ops


def allowed_writes(exp: Experiment) -> set:
    return {(op[1], op[2]) for op in setup_plan(exp) if op[0] == "write"} | {(f"{LAB_DIR}/cgroup.kill", "1")}


def check_op(op, exp: Experiment, iters: Optional[int] = None):
    """The closed set of host operations of one R2-C run. Anything else raises R2CRefused."""
    if not isinstance(op, tuple) or not op:
        raise R2CRefused(f"malformed operation {op!r}")
    kind = op[0]
    text = repr(op)
    for p in PROTECTED:
        if p in text:
            raise R2CRefused(f"protected interface {p} in operation")
    if kind in ("mkdir", "rmdir"):
        if len(op) != 2 or op[1] not in LAB_DIRS:
            raise R2CRefused(f"{kind} outside the lab cgroup: {op!r}")
    elif kind == "write":
        if len(op) != 3 or (op[1], op[2]) not in allowed_writes(exp):
            raise R2CRefused(f"write not in the {exp.kind} allowlist: {op!r}")
    elif kind == "spawn":
        if len(op) != 3 or op[1] not in ("target", "contender", "calibration"):
            raise R2CRefused(f"malformed spawn {op!r}")
        role, argv = op[1], list(op[2])
        if not spawn_structure(argv, CONTENDER_DIR if role == "contender" else TARGET_DIR)["ok"]:
            raise R2CRefused(f"{role} argv breaks the one-pid structure: {argv}")
        if role == "contender":
            if exp.contender_cpu is None or len(argv) != len(CONTENDER_PREFIX) + 2 or \
                    argv[:-1] != CONTENDER_PREFIX + [CONTENDER_CODE] or not _results_path(argv[-1]):
                raise R2CRefused(f"contender argv not approved for {exp.kind}: {argv}")
        elif role == "target":
            if not argv[-2:-1] == ["--out"] or argv != target_argv(iters, argv[-1]) or not _results_path(argv[-1]):
                raise R2CRefused(f"target argv not approved: {argv}")
        else:
            if argv != calibration_argv(argv[-1]) or not _results_path(argv[-1]):
                raise R2CRefused(f"calibration argv not approved: {argv}")
    elif kind == "kill":
        if len(op) != 2 or isinstance(op[1], bool) or not isinstance(op[1], int) or op[1] <= 1:
            raise R2CRefused(f"malformed kill {op!r}")
    else:
        raise R2CRefused(f"operation {kind!r} is not authorised in R2-C")
    return op


class Host:
    """The single R2-C mutation site. Every operation is logged (intent, then result) and re-validated first."""

    def __init__(self, exp: Experiment, oplog: str, iters: Optional[int] = None, sysr: Optional[Sys] = None):
        self.exp, self.oplog, self.iters, self.sys = exp, oplog, iters, sysr or Sys()

    def _log(self, **kw):
        with open(self.oplog, "a") as fh:
            fh.write(json.dumps({"t": time.monotonic(), **kw}, sort_keys=True) + "\n")

    def apply(self, op, stdout=None, stderr=None):
        check_op(op, self.exp, self.iters)
        self._log(phase="intent", op=list(op[:2]))
        try:
            res = self._do(op, stdout, stderr)
        except OSError as exc:
            self._log(phase="result", op=list(op[:2]), ok=False, err=str(exc))
            raise
        self._log(phase="result", op=list(op[:2]), ok=True, pid=getattr(res, "pid", None))
        return res

    def _do(self, op, stdout, stderr):
        kind = op[0]
        if kind == "mkdir":
            os.mkdir(op[1])
        elif kind == "rmdir":
            os.rmdir(op[1])
        elif kind == "write":
            with open(op[1], "w") as fh:
                fh.write(op[2])
        elif kind == "spawn":
            return subprocess.Popen(list(op[2]), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    shell=False, start_new_session=True)
        elif kind == "kill":
            if f"::/{LAB}" not in (self.sys.read(f"/proc/{op[1]}/cgroup") or ""):
                return None                   # gone, or not (any longer) a lab process: never signalled
            os.kill(op[1], signal.SIGKILL)
        return None


# ------------------------------------------------------------------------------------------ preflight / verification
def preflight(sysr) -> dict:
    """Read-only prerequisites before anything is created (design §1, §2, §10, §12)."""
    c = {}
    c["root_cpuset_0_23"] = parse_cpulist(sysr.read(f"{CG_ROOT}/cpuset.cpus.effective")) == HOST_CPUS
    c["root_subtree_control"] = set((sysr.read(f"{CG_ROOT}/cgroup.subtree_control") or "").split()) == ROOT_SUBTREE
    c["no_sentinel_cgroup"] = not sentinel_cgroups(sysr)
    c["no_lab_process"] = not lab_pids(sysr)
    online = parse_cpulist(sysr.read("/sys/devices/system/cpu/online"))
    c["experiment_cpus_online"] = set(PARENT_CPUS) | set(SUPPORT_CPUS) <= online
    c["experiment_cpus_no_smt"] = all(parse_cpulist(sysr.read(f"/sys/devices/system/cpu/cpu{n}/topology/"
                                                              "thread_siblings_list")) == {n} for n in PARENT_CPUS)
    cl = lambda n: parse_cpulist(sysr.read(f"/sys/devices/system/cpu/cpu{n}/topology/cluster_cpus_list"))
    c["n1_other_l2_cluster"] = TARGET_CPU in cl(TARGET_CPU) and 23 not in cl(TARGET_CPU)
    c["n2_same_l2_cluster"] = 19 in cl(TARGET_CPU)
    irq_line = [l for l in (sysr.read("/proc/interrupts") or "").splitlines() if l.strip().startswith(f"{NIC_IRQ}:")]
    c["nic_irq_is_enp0s31f6"] = bool(irq_line) and irq_line[0].split()[-1] == NIC_IRQ_NAME
    eff = sysr.read(f"/proc/irq/{NIC_IRQ}/effective_affinity_list")
    c["nic_irq_off_experiment_cpus"] = eff is not None and not parse_cpulist(eff) & EXPERIMENT_CPUS
    c["protected_interfaces_present"] = all(sysr.exists(f"/sys/class/net/{p}") for p in PROTECTED)
    c["cgroup_kill_supported"] = sysr.exists(f"{CG_ROOT}/init.scope/cgroup.kill")
    c["psi_available"] = sysr.read("/proc/pressure/cpu") is not None
    c["lab_uid_exists"] = sysr.uid_name(LAB_UID) is not None
    for t in ("/usr/bin/unshare", "/usr/bin/setpriv", "/usr/bin/timeout", "/usr/bin/taskset", PYTHON, LOADER, BPFTOOL):
        c[f"tool:{t}"] = sysr.tool(t)
    return {"ok": all(c.values()), "checks": c}


def verify_lab(sysr, exp: Experiment) -> dict:
    """After creation, before any process joins (design §1)."""
    r = lambda d, f: sysr.read(f"{d}/{f}")
    c = {}
    c["parent_subtree_control"] = set((r(LAB_DIR, "cgroup.subtree_control") or "").split()) == set(CONTROLLERS)
    for name, d in (("target", TARGET_DIR), ("contender", CONTENDER_DIR)):
        c[f"{name}_controllers"] = set(CONTROLLERS) <= set((r(d, "cgroup.controllers") or "").split())
        c[f"{name}_pids_max"] = (r(d, "pids.max") or "").strip() == PIDS_MAX
        c[f"{name}_memory_max_unlimited"] = (r(d, "memory.max") or "").strip() == "max"
        c[f"{name}_mems"] = (r(d, "cpuset.mems.effective") or "").strip() == MEMS
    c["parent_cpus"] = parse_cpulist(r(LAB_DIR, "cpuset.cpus.effective")) == set(PARENT_CPUS)
    c["target_cpus"] = parse_cpulist(r(TARGET_DIR, "cpuset.cpus.effective")) == {TARGET_CPU}
    want = {exp.contender_cpu} if exp.contender_cpu is not None else set(PARENT_CPUS)
    c["contender_cpus"] = parse_cpulist(r(CONTENDER_DIR, "cpuset.cpus.effective")) == want
    for name, d in (("parent", LAB_DIR), ("target", TARGET_DIR), ("contender", CONTENDER_DIR)):
        c[f"{name}_no_quota"] = (r(d, "cpu.max") or "").strip() == CPU_MAX_UNLIMITED
        procs = r(d, "cgroup.procs")
        c[f"{name}_empty"] = procs is not None and procs.strip() == ""
    c["target_weight"] = (r(TARGET_DIR, "cpu.weight") or "").strip() == str(TARGET_WEIGHT)
    c["contender_weight"] = (r(CONTENDER_DIR, "cpu.weight") or "").strip() == str(exp.contender_weight)
    c["target_cpu_stat_has_throttle_fields"] = {"nr_periods", "nr_throttled", "throttled_usec"} <= \
        set(kv(r(TARGET_DIR, "cpu.stat")))
    return {"ok": all(c.values()), "checks": c}


# ------------------------------------------------------------------------------------------ host snapshot
def host_snapshot(sysr, require_bpf=True) -> dict:
    """Read-only, comparable host state (design §10, §11): equality part + recorded dynamic part."""
    j = lambda argv: json.loads(sysr.run(argv) or "null")
    dirs = sysr.cgroup_dirs()
    cg = {d: {a: (sysr.read(f"{CG_ROOT}/{d}/{a}" if d else f"{CG_ROOT}/{a}") or "").strip() for a in CGROUP_ATTRS}
          for d in dirs}
    irqs = {}
    for n in sysr.listdir("/proc/irq") or []:
        if n.isdigit():
            irqs[n] = [(sysr.read(f"/proc/irq/{n}/{f}") or "").strip()
                       for f in ("smp_affinity_list", "effective_affinity_list")]
    bpf = {k: j((BPFTOOL, "-j", k, "show")) for k in ("prog", "link", "map")}
    snap = {
        "root": {f: (sysr.read(f"{CG_ROOT}/{f}") or "").strip()
                 for f in ("cpuset.cpus.effective", "cgroup.subtree_control", "cpuset.mems.effective")},
        "cgroup_dirs": dirs, "cgroups": cg, "irq": irqs,
        "links": j(("ip", "-j", "-d", "link", "show")), "addrs": j(("ip", "-j", "addr", "show")),
        "routes4": j(("ip", "-j", "route", "show")), "routes6": j(("ip", "-j", "-6", "route", "show")),
        "qdiscs": j(("tc", "-j", "qdisc", "show")),
        "netns": sorted(n["name"] for n in (j(("ip", "-j", "netns", "list")) or [])),
        "run_netns": sysr.listdir("/run/netns") or [],
        "sysctls": "\n".join(f"{s}={(sysr.read(f'/proc/sys/{s}') or '').strip()}" for s in SYSCTLS),
        "mounts": sorted((sysr.run(("findmnt", "-rn", "-o", "TARGET,FSTYPE")) or "").splitlines()),
        "bpf": bpf, "bpf_available": all(v is not None for v in bpf.values()),
        "dynamic": {"psi_cpu": psi(sysr.read("/proc/pressure/cpu")), "psi_memory": psi(sysr.read("/proc/pressure/memory")),
                    "slices_cpu_pressure": {s: psi(sysr.read(f"{CG_ROOT}/{s}/cpu.pressure")) for s in SLICES},
                    "lab_pids": lab_pids(sysr), "stat": proc_stat_cpus(sysr.read("/proc/stat"))},
    }
    return snap


def compare_host(base: dict, other: dict, require_bpf=True) -> dict:
    """Equality of everything the design protects; dynamic counters are not compared."""
    net = lambda s: {"links": s["links"] or [], "addrs": s["addrs"] or [], "routes4": s["routes4"],
                     "routes6": s["routes6"], "netns": "", "sysctls": s["sysctls"],
                     "bpf_progs": s["bpf"]["prog"] or [], "bpf_links": s["bpf"]["link"] or [],
                     "bpf_maps": s["bpf"]["map"] or []}
    r = hostcmp.compare(net(base), net(other))
    r.pop("netns_identical")
    r.pop("ignored_volatile_fields")
    q = lambda s: {(x.get("dev"), x.get("handle"), x.get("parent", "root")): x for x in (s["qdiscs"] or [])}
    qb, qo = q(base), q(other)
    r["qdiscs_identical"] = qb == qo
    r["protected_qdiscs_identical"] = all({k: v for k, v in qb.items() if k[0] == p} ==
                                          {k: v for k, v in qo.items() if k[0] == p} for p in PROTECTED)
    r["network_state_captured"] = all(s[k] is not None for s in (base, other)
                                      for k in ("links", "addrs", "routes4", "routes6", "qdiscs"))
    r["netns_identical"] = base["netns"] == other["netns"] and base["run_netns"] == other["run_netns"]
    r["root_identical"] = base["root"] == other["root"]
    r["root_cpuset_0_23"] = parse_cpulist(other["root"]["cpuset.cpus.effective"]) == HOST_CPUS
    r["cgroup_dirs_identical"] = base["cgroup_dirs"] == other["cgroup_dirs"]
    r["cgroups_added"] = sorted(set(other["cgroup_dirs"]) - set(base["cgroup_dirs"]))
    r["cgroups_removed"] = sorted(set(base["cgroup_dirs"]) - set(other["cgroup_dirs"]))
    common = set(base["cgroups"]) & set(other["cgroups"])
    r["cgroups_differing"] = sorted(d for d in common if base["cgroups"][d] != other["cgroups"][d])
    r["cgroup_attrs_identical"] = not r["cgroups_differing"]
    r["no_lab_cgroup"] = not [d for d in other["cgroup_dirs"] if any(p.startswith("sentinel") for p in d.split("/"))]
    r["no_lab_process"] = not other["dynamic"]["lab_pids"]
    r["irq_affinity_identical"] = base["irq"] == other["irq"]
    r["irqs_differing"] = sorted(n for n in set(base["irq"]) | set(other["irq"])
                                 if base["irq"].get(n) != other["irq"].get(n))
    r["nic_irq_identical"] = base["irq"].get(str(NIC_IRQ)) == other["irq"].get(str(NIC_IRQ))
    r["mounts_identical"] = base["mounts"] == other["mounts"]
    r["bpf_compared"] = base["bpf_available"] and other["bpf_available"]
    must = ("interfaces_identical", "enp0s31f6_identical", "docker0_identical", "addresses_identical",
            "routes_identical", "sysctls_identical", "qdiscs_identical", "protected_qdiscs_identical",
            "network_state_captured", "netns_identical", "root_identical", "root_cpuset_0_23", "cgroup_dirs_identical",
            "cgroup_attrs_identical", "no_lab_cgroup", "no_lab_process", "irq_affinity_identical", "nic_irq_identical",
            "mounts_identical")
    if require_bpf:
        must += ("bpf_compared", "bpf_progs_identical", "bpf_links_identical", "bpf_maps_identical")
    r["failed"] = [k for k in must if not r[k]] + (["sn_programs_left"] if r["sn_programs_left"] else [])
    r["ok"] = not r["failed"]
    return r


# ------------------------------------------------------------------------------------------ ground-truth sampling
def gt_sample(sysr, mono: float, target_pid: Optional[int]) -> dict:
    """One independent ground-truth observation (read directly from kernel files, never through the collector)."""
    rd = sysr.read
    leaves = {}
    for name, d in (("parent", LAB_DIR), ("target", TARGET_DIR), ("contender", CONTENDER_DIR)):
        procs = rd(f"{d}/cgroup.procs")
        leaves[name] = {
            "cpu_max": (rd(f"{d}/cpu.max") or "").strip() or None,
            "cpus_eff": (rd(f"{d}/cpuset.cpus.effective") or "").strip() if name != "parent" else None,
            "cpu_stat": kv(rd(f"{d}/cpu.stat")) or None,
            "cpu_pressure": (psi(rd(f"{d}/cpu.pressure")) or None) if name != "parent" else None,
            "mem_events": (kv(rd(f"{d}/memory.events")) or None) if name != "parent" else None,
            "procs": None if procs is None else sorted(int(p) for p in procs.split()),
        }
    proc = {}
    for name in ("target", "contender"):
        for pid in leaves[name]["procs"] or []:
            proc[str(pid)] = task_processor(rd(f"/proc/{pid}/stat"))
    netns = None
    if target_pid is not None:
        netns = netns_counters(rd(f"/proc/{target_pid}/net/dev"), rd(f"/proc/{target_pid}/net/snmp"))
    irq = rd(f"/proc/irq/{NIC_IRQ}/effective_affinity_list")
    return {"mono": mono, "stat": proc_stat_cpus(rd("/proc/stat")), "rq_cpu_time": schedstat_rq_cpu_time(rd("/proc/schedstat")),
            "leaves": leaves, "proc": proc,
            "nic_irq_eff": irq.strip() if irq is not None else None,
            "psi_cpu": psi(rd("/proc/pressure/cpu")) or None, "psi_memory": psi(rd("/proc/pressure/memory")) or None,
            "slices": {s: psi(rd(f"{CG_ROOT}/{s}/cpu.pressure")) or None for s in SLICES},
            "vmstat": {k: v for k, v in kv(rd("/proc/vmstat")).items() if k in ("pswpin", "pswpout")} or None,
            "netns": netns}


def placement_violations(t: dict, exp: Experiment, expected: Dict[str, List[int]], in_window: bool) -> List[str]:
    """G1 for one observation. expected: pids each leaf must contain now (target always; contender only in W)."""
    v = []
    lv = t["leaves"]
    if parse_cpulist(lv["target"]["cpus_eff"] or "") != {TARGET_CPU}:
        v.append(f"target cpuset.cpus.effective {lv['target']['cpus_eff']!r} != {TARGET_CPU}")
    cwant = {exp.contender_cpu} if exp.contender_cpu is not None else set(PARENT_CPUS)
    if parse_cpulist(lv["contender"]["cpus_eff"] or "") != cwant:
        v.append(f"contender cpuset.cpus.effective {lv['contender']['cpus_eff']!r} != {cpus_text(cwant)}")
    if lv["parent"]["procs"] != []:
        v.append(f"process in the lab parent cgroup: {lv['parent']['procs']}")
    for name in ("target", "contender"):
        want = sorted(expected.get(name, []))
        if lv[name]["procs"] != want:
            v.append(f"{name} cgroup.procs {lv[name]['procs']} != expected {want}")
    if exp.contender_cpu is None and lv["contender"]["procs"]:
        v.append("contender process present in E0")
    for pid in lv["target"]["procs"] or []:
        if t["proc"].get(str(pid)) != TARGET_CPU:
            v.append(f"target pid {pid} on CPU {t['proc'].get(str(pid))} (allowed {TARGET_CPU})")
    for pid in lv["contender"]["procs"] or []:
        if t["proc"].get(str(pid)) != exp.contender_cpu:
            v.append(f"contender pid {pid} on CPU {t['proc'].get(str(pid))} (allowed {exp.contender_cpu})")
    if not in_window and lv["contender"]["procs"]:
        v.append("contender running outside W")
    return v


def immediate_aborts(t: dict) -> List[str]:
    """Conditions checked at every observation, besides placement: quota, throttling, NIC IRQ, cleanup-relevant."""
    a = []
    for name in ("parent", "target", "contender"):
        if t["leaves"][name]["cpu_max"] != CPU_MAX_UNLIMITED:
            a.append(f"CPU quota: {name} cpu.max = {t['leaves'][name]['cpu_max']!r}")
    if t["nic_irq_eff"] is None or parse_cpulist(t["nic_irq_eff"]) & EXPERIMENT_CPUS:
        a.append(f"NIC IRQ {NIC_IRQ} effective affinity {t['nic_irq_eff']!r} on an experiment CPU")
    return a


# ------------------------------------------------------------------------------------------ G1-G7
def _d(ticks, a, b, get):
    """Delta of get(tick) between ticks a and b; None if either is unavailable."""
    try:
        x, y = get(ticks[a]), get(ticks[b])
    except (KeyError, TypeError, IndexError):
        return None
    if x is None or y is None:
        return None
    return y - x


def _rq(ticks, a, b, cpu=TARGET_CPU):
    """Delta of rq_cpu_time (ns) of `cpu` between observations a and b; None if unavailable or backwards."""
    x, y = ticks[a].get("rq_cpu_time"), ticks[b].get("rq_cpu_time")
    if not x or not y or cpu not in x or cpu not in y or y[cpu] < x[cpu]:
        return None
    return y[cpu] - x[cpu]


def _secs(ticks, a, b):
    return ticks[b]["mono"] - ticks[a]["mono"]


def _cs(name, key):
    return lambda t: (t["leaves"][name]["cpu_stat"] or {}).get(key)


def _cpu(n, key):
    return lambda t: t["stat"][f"cpu{n}"][key]


def lateness_stats(target_out: Optional[dict], lo_ns: int, hi_ns: int) -> Optional[dict]:
    """Target self-reported wake lateness / cycle time for cycles whose deadline lies in [lo, hi)."""
    if not target_out:
        return None
    t0, per = target_out["t0_ns"], target_out["period_ns"]
    late, cyc, missed = [], [], 0
    for k, (w, e) in enumerate(zip(target_out["wake_ns"], target_out["done_ns"])):
        dl = t0 + k * per
        if lo_ns <= dl < hi_ns:
            late.append(w - dl)
            cyc.append(e - w)
            missed += e > dl + per
    if not late:
        return None
    s = sorted(late)
    p99 = s[max(0, -(-99 * len(s) // 100) - 1)]
    return {"n": len(late), "lateness_median_ns": median(late), "lateness_p99_ns": p99,
            "cycle_median_ns": median(cyc), "missed": missed}


def evaluate_ground_truth(obs: List[dict], i_b0: int, i_w0: int, i_w1: int, exp: Experiment,
                          expected: List[Dict[str, List[int]]], in_w: List[bool], target_out: Optional[dict],
                          hz: int) -> dict:
    """G1-G7. obs: every GT observation of the run in time order (warm-up, B, W, recovery).
    i_b0, i_w0, i_w1: indices of the observations taken at collector ticks 0, NB and NB+NW."""
    G = {}
    b, w = (i_b0, i_w0), (i_w0, i_w1)
    sb, sw = _secs(obs, *b), _secs(obs, *w)

    # G1 placement, every observation
    viol = []
    for k, t in enumerate(obs):
        viol += [f"obs {k}: {x}" for x in placement_violations(t, exp, expected[k], in_w[k])]
    G["G1"] = {"ok": not viol, "violations": viol[:20], "n_violations": len(viol), "observations": len(obs)}

    # G2 contender ran (cgroup usage over W); E0: the contender leaf consumed nothing
    du = _d(obs, *w, _cs("contender", "usage_usec"))
    cores = None if du is None else du / 1e6 / sw
    if exp.contender_cpu is None:
        dall = _d(obs, 0, len(obs) - 1, _cs("contender", "usage_usec"))
        ok = dall == 0
    else:
        ok = cores is not None and cores >= G2_CONTENDER_MIN_CORES
    G["G2"] = {"ok": ok, "contender_cores_w": cores, "threshold": G2_CONTENDER_MIN_CORES}

    # G3 CPU 18 saturated (E1/E2): idle_W = 1 - delta rq_cpu_time / W (precise; /proc/stat value diagnostic only)
    drq_w = _rq(obs, *w)
    idle = None if drq_w is None or sw <= 0 else 1 - drq_w / (sw * 1e9)
    di, dt = _d(obs, *w, _cpu(TARGET_CPU, "idle")), _d(obs, *w, _cpu(TARGET_CPU, "total"))
    applies = exp.kind in ("E1", "E2")
    G["G3"] = {"ok": (idle is not None and idle <= G3_IDLE_MAX) if applies else idle is not None,
               "applies": applies, "cpu18_idle_frac_w": idle, "threshold": G3_IDLE_MAX,
               "source": "/proc/schedstat v15 cpu18 field 7 (rq_cpu_time)",
               "diagnostic_tick_idle_frac_w": None if di is None or not dt else di / dt}

    # G4 target harmed: self-reported lateness B vs W; target cgroup PSI some delta W vs B
    lb = lateness_stats(target_out, int(obs[i_b0]["mono"] * 1e9), int(obs[i_w0]["mono"] * 1e9))
    lw = lateness_stats(target_out, int(obs[i_w0]["mono"] * 1e9), int(obs[i_w1]["mono"] * 1e9))
    psi_t = lambda t: (t["leaves"]["target"]["cpu_pressure"] or {}).get("some_total")
    pb, pw = _d(obs, *b, psi_t), _d(obs, *w, psi_t)
    measured = (lb is not None and lw is not None and pb is not None and pw is not None
                and lb["n"] >= G4_N_MIN and lw["n"] >= G4_N_MIN)
    g4 = {"lateness_b": lb, "lateness_w": lw, "psi_some_us_b": pb, "psi_some_us_w": pw, "measured": measured,
          "criterion": CRITERIA["G4"]}
    if not measured:                              # missing output or too few samples: ground truth unavailable
        g4.update(ok=None, status="UNAVAILABLE")
    else:
        mb, mw = lb["lateness_median_ns"], lw["lateness_median_ns"]
        g4["shift"] = mw >= G4_RATIO_MIN * mb and mw - mb >= G4_ABS_MIN_NS
        g4["psi_w_above_b"] = pw > pb
        g4.update(ok=g4["shift"] and g4["psi_w_above_b"], status="EVALUATED")   # FALSE is not a safety abort
    G["G4"] = g4

    # G5 no quota, no throttling (every observation; whole run)
    quota_ok = all(t["leaves"][n]["cpu_max"] == CPU_MAX_UNLIMITED for t in obs for n in ("parent", "target", "contender"))
    thr = {f"{n}.{k}": _d(obs, 0, len(obs) - 1, _cs(n, k)) for n in ("target", "contender")
           for k in ("nr_periods", "nr_throttled", "throttled_usec")}
    G["G5"] = {"ok": quota_ok and all(v == 0 for v in thr.values()), "cpu_max_unlimited": quota_ok, "deltas": thr}

    # G6 foreign busy time on CPU 18 (B and W): precise rq_cpu_time minus lab usage. The contender is subtracted
    # only when it shares CPU 18 (E1/E2); E0 has none, N1/N2 run it elsewhere.
    subtract = exp.contender_cpu == TARGET_CPU

    def foreign(a, z, busy_s):
        tu = _d(obs, a, z, _cs("target", "usage_usec"))
        cu = _d(obs, a, z, _cs("contender", "usage_usec")) if subtract else 0
        secs = _secs(obs, a, z)
        if busy_s is None or tu is None or cu is None or secs <= 0:
            return None
        return (busy_s - tu / 1e6 - cu / 1e6) / secs

    def rq_s(a, z):
        v = _rq(obs, a, z)
        return None if v is None else v / 1e9

    def tick_s(a, z):
        v = _d(obs, a, z, _cpu(TARGET_CPU, "busy"))
        return None if v is None else v / hz
    fb, fw = foreign(*b, rq_s(*b)), foreign(*w, rq_s(*w))
    G["G6"] = {"ok": None if fb is None or fw is None else fb <= G6_FOREIGN_MAX_CORES and fw <= G6_FOREIGN_MAX_CORES,
               "foreign_cores_b": fb, "foreign_cores_w": fw, "threshold": G6_FOREIGN_MAX_CORES,
               "contender_subtracted": subtract, "source": "/proc/schedstat v15 cpu18 field 7 (rq_cpu_time)",
               "diagnostic_tick_foreign_cores_b": foreign(*b, tick_s(*b)),
               "diagnostic_tick_foreign_cores_w": foreign(*w, tick_s(*w))}

    # G7 no softirq / memory / network fault
    g7 = {}
    sib, sit = _d(obs, *b, _cpu(TARGET_CPU, "softirq")), _d(obs, *b, _cpu(TARGET_CPU, "total"))
    siw, siwt = _d(obs, *w, _cpu(TARGET_CPU, "softirq")), _d(obs, *w, _cpu(TARGET_CPU, "total"))
    g7["softirq_frac_b"] = None if sib is None or not sit else sib / sit
    g7["softirq_frac_w"] = None if siw is None or not siwt else siw / siwt
    if g7["softirq_frac_b"] is None or g7["softirq_frac_w"] is None:
        g7["softirq_ok"] = None
    else:
        g7["softirq_ok"] = abs(g7["softirq_frac_w"] - g7["softirq_frac_b"]) <= G7_SOFTIRQ_MAX_DELTA
    g7["nic_irq_ok"] = all(t["nic_irq_eff"] is not None and not parse_cpulist(t["nic_irq_eff"]) & EXPERIMENT_CPUS
                           for t in obs)
    ev = {}
    for n in ("target", "contender"):
        for k in ("high", "max", "oom", "oom_kill"):
            ev[f"{n}.{k}"] = _d(obs, 0, len(obs) - 1, lambda t, n=n, k=k: (t["leaves"][n]["mem_events"] or {}).get(k))
    g7["memory_events"] = ev
    g7["memory_events_ok"] = all(v == 0 for v in ev.values())
    pm = _d(obs, *w, lambda t: (t["psi_memory"] or {}).get("some_total"))

    def swap(t):
        v = t["vmstat"] or {}
        return v["pswpin"] + v["pswpout"] if "pswpin" in v and "pswpout" in v else None
    sw_io = _d(obs, *w, swap)
    g7["psi_mem_some_us_w"], g7["swap_io_pages_w"], g7["w_seconds"] = pm, sw_io, sw
    g7["swap_pages_per_s_w"] = None if sw_io is None or sw <= 0 else sw_io / sw
    g7["memory_psi_ok"] = None if pm is None else pm <= MEM_PSI_W_MAX_US
    g7["swap_ok"] = None if g7["swap_pages_per_s_w"] is None else g7["swap_pages_per_s_w"] <= SWAP_MAX_PAGES_PER_S
    nets = [t["netns"] for t in obs if t["netns"] is not None]
    g7["netns_observed"] = len(nets) == len(obs)
    g7["netns_quiet"] = g7["netns_observed"] and all(n == nets[0] for n in nets)
    parts = ("softirq_ok", "nic_irq_ok", "memory_events_ok", "memory_psi_ok", "swap_ok", "netns_quiet")
    g7["ok"] = all(g7[p] is True for p in parts)
    g7["undecided"] = [p for p in parts if g7[p] is None]
    G["G7"] = g7

    # contention established (E1/E2) / no shared runqueue (N1/N2) / no contender (E0), from G1-G6
    computable = all(G[g]["ok"] is not None for g in ("G1", "G2", "G3", "G4", "G5", "G6")) and not g7["undecided"]
    G["computable"] = computable
    G["established"] = all(G[g]["ok"] for g in ("G1", "G2", "G3", "G4", "G5", "G6")) if computable else None
    return G


def host_level_aborts(obs, i_b0, i_w0, i_w1) -> List[str]:
    """§12 host-wide conditions over the run (approved host-PSI and slice-PSI criteria)."""
    a = []
    du = _d(obs, i_b0, i_w0, lambda t: t["stat"]["all"]["busy"])
    dt = _d(obs, i_b0, i_w0, lambda t: t["stat"]["all"]["total"])
    util_b = None if du is None or not dt else du / dt
    if util_b is None:
        a.append("host CPU utilisation in B unavailable")
    elif util_b > HOST_UTIL_B_MAX:
        a.append(f"cpu.util.host in B {util_b:.3f} > {HOST_UTIL_B_MAX}")
    avg = [t["psi_cpu"]["some_avg10"] for t in obs if t["psi_cpu"]]
    if len(avg) != len(obs):
        a.append("/proc/pressure/cpu unavailable")
    elif max(avg) > HOST_PSI_AVG10_MAX:          # inspect the non-lab top-level cgroups (no attribution formula)
        for s in SLICES:
            vals = [(t["slices"][s] or {}).get("some_avg10") for t in obs]
            if any(v is None for v in vals):
                a.append(f"host cpu PSI avg10 {max(avg):.2f} > {HOST_PSI_AVG10_MAX} and {s} cpu.pressure unreadable")
            elif max(vals) > SLICE_AVG10_MAX:
                a.append(f"host cpu PSI avg10 {max(avg):.2f} > {HOST_PSI_AVG10_MAX} and {s} cpu.pressure some avg10 "
                         f"{max(vals):.2f} > {SLICE_AVG10_MAX}")
    sb, sw = _secs(obs, i_b0, i_w0), _secs(obs, i_w0, i_w1)
    for s in SLICES:
        dsb = _d(obs, i_b0, i_w0, lambda t, s=s: (t["slices"][s] or {}).get("some_total"))
        dsw = _d(obs, i_w0, i_w1, lambda t, s=s: (t["slices"][s] or {}).get("some_total"))
        if dsb is None or dsw is None or sb <= 0 or sw <= 0:
            a.append(f"{s} cpu.pressure unavailable in B or W")
            continue
        rb, rw = dsb / (sb * 1e6), dsw / (sw * 1e6)
        if rw - rb > SLICE_PSI_RISE_MAX:
            a.append(f"{s} cpu.pressure some rose in W: r_W {rw:.4f} - r_B {rb:.4f} > {SLICE_PSI_RISE_MAX}")
    return a


def ground_truth_aborts(G: dict, exp: Experiment) -> List[str]:
    a = []
    if not G["computable"]:
        a.append("independent ground truth unavailable: " + ", ".join(
            [f"{g}: {G[g].get('status', 'not computable')}" for g in ("G1", "G2", "G3", "G4", "G5", "G6")
             if G[g]["ok"] is None] + [f"G7.{p}" for p in G["G7"]["undecided"]]))
    if G["G1"]["ok"] is False:
        a.append(f"experiment escaped its boundary (G1): {G['G1']['violations'][:3]}")
    if G["G2"]["ok"] is False:
        a.append(f"contender consumption contradicts the fault model (G2): {G['G2']['contender_cores_w']}")
    if G["G3"]["ok"] is False:
        a.append(f"CPU {TARGET_CPU} idle {G['G3']['cpu18_idle_frac_w']} > {G3_IDLE_MAX} in W (G3)")
    if G["G5"]["ok"] is False:
        a.append(f"CPU quota or throttling detected (G5): {G['G5']['deltas']}")
    if G["G6"]["ok"] is False:
        a.append(f"foreign busy time on CPU {TARGET_CPU} (G6): B {G['G6']['foreign_cores_b']} "
                 f"W {G['G6']['foreign_cores_w']}")
    g7 = G["G7"]
    if g7["nic_irq_ok"] is False:
        a.append(f"NIC IRQ {NIC_IRQ} moved onto an experiment CPU")
    if g7["memory_events_ok"] is False:
        a.append(f"memory events in the lab cgroups: {g7['memory_events']}")
    if g7["memory_psi_ok"] is False:
        a.append(f"host memory PSI stall in W: {g7['psi_mem_some_us_w']} us > {MEM_PSI_W_MAX_US}")
    if g7["swap_ok"] is False:
        a.append(f"swap I/O in W {g7['swap_pages_per_s_w']:.2f} pages/s > {SWAP_MAX_PAGES_PER_S}")
    if g7["netns_quiet"] is False:
        a.append("network activity in the target's private netns (or netns not observable)")
    if g7["softirq_ok"] is False:
        a.append(f"CPU 18 softirq changed: |{g7['softirq_frac_w']} - {g7['softirq_frac_b']}| > {G7_SOFTIRQ_MAX_DELTA}")
    return a


# ------------------------------------------------------------------------------------------ metric gate
REQUIRED_METRICS = (("sched.run_delay_excess.target", "cg", "RATE"), ("cpu.util.cpuset", "cpuset", "MEAN"),
                    ("cpu.steal.cpuset", "cpuset", "MEAN"), ("sched.latency_hist.target", "cg", "P50"),
                    ("sched.latency_hist.target", "cg", "P99"))


def metric_gate(snapshot, cov_min: float, n_base_min: float) -> dict:
    """The required SentinelAI measurements are usable; the exclusions behave as the design states (§8, §12, §13)."""
    cg = f"cgroup:{TARGET_CGROUP_PATH}"
    ms = snapshot.measurements
    find = lambda f, sc, agg=None: [m for m in ms if m.feature_id == f and m.scope == sc
                                    and (agg is None or m.aggregation.value == agg)]
    c, aborts = {}, []
    c["target_cpuset_is_18"] = snapshot.target.cpuset == str(TARGET_CPU)
    c["target_cgroup"] = snapshot.target.cgroup_path == TARGET_CGROUP_PATH
    if not (c["target_cpuset_is_18"] and c["target_cgroup"]):
        aborts.append(f"snapshot target {snapshot.target.cgroup_path} cpuset {snapshot.target.cpuset!r} is not the "
                      f"R2-C target ({TARGET_CGROUP_PATH}, {TARGET_CPU})")
    for f, sc, agg in REQUIRED_METRICS:
        key = f"{f}[{agg}]"
        found = find(f, cg if sc == "cg" else sc, agg)
        m = found[0] if len(found) == 1 else None
        if m is None:
            c[key] = False
            aborts.append(f"required metric {key} not present exactly once")
            continue
        q = m.quality.value
        bad = []
        if q not in ("OK", "PARTIAL") or m.value is None:
            bad.append(f"quality {q}")
        elif q == "PARTIAL" and m.coverage < cov_min:
            bad.append(f"coverage {m.coverage}")
        if m.baseline is None or not m.baseline.adequate or m.baseline.n < n_base_min:
            bad.append("baseline inadequate")
        c[key] = not bad
        if bad:
            aborts.append(f"required metric {key} unusable: {', '.join(bad)}")
    tr = find("throttle.ratio", cg)
    c["throttle.ratio_missing_by_design"] = len(tr) == 1 and tr[0].value is None and tr[0].quality.value == "MISSING"
    if len(tr) == 1 and tr[0].value is not None:
        aborts.append(f"throttle.ratio has a value ({tr[0].value}): CFS bandwidth periods advanced")
    ql = find("throttle.quota_limited", cg)
    c["quota_limited_is_0"] = len(ql) == 1 and ql[0].value == 0.0
    if not c["quota_limited_is_0"]:
        aborts.append(f"throttle.quota_limited is not 0.0: {[m.value for m in ql]}")
    tt = find("throttle.time_rate", cg)
    c["throttle_time_rate_is_0"] = len(tt) == 1 and tt[0].value == 0.0
    if not c["throttle_time_rate_is_0"]:
        aborts.append(f"throttle.time_rate is not 0: {[m.value for m in tt]}")
    si = find("softirq.frac.percpu", f"cpu:{TARGET_CPU}")
    c["softirq_frac_cpu18_usable"] = len(si) == 1 and si[0].value is not None and si[0].quality.value in ("OK", "PARTIAL")
    if not c["softirq_frac_cpu18_usable"]:
        aborts.append("softirq.frac.percpu cpu:18 unusable (CC.X2 not evaluable)")
    net = [(m.feature_id, m.value) for m in ms if m.feature_id.startswith(("net.", "tcp.")) and m.value]
    c["no_network_activity"] = not net
    if net:
        aborts.append(f"network activity in the target netns: {net}")
    c["gate_passed"] = snapshot.data_quality.gate_passed
    if not c["gate_passed"]:
        aborts.append("snapshot data-quality gate failed")
    return {"ok": not aborts, "checks": c, "aborts": aborts}


# ------------------------------------------------------------------------------------------ BPF teardown
def run_owned_bpf(base: dict, maps, progs) -> dict:
    """Run-owned eBPF objects still present: maps absent from the pre-run snapshot named like the loader's maps, and
    any sn_* program. Unrelated objects are not listed here (the exact host comparison judges them)."""
    before = {m.get("id") for m in (base["bpf"]["map"] or [])}
    own = [m for m in maps if m.get("id") not in before and
           (m.get("name") in LOADER_BPF_MAPS or str(m.get("name", "")).startswith(LOADER_BPF_MAP_PREFIX))]
    sn = [p for p in progs if str(p.get("name", "")).startswith(LOADER_BPF_PROG_PREFIX)]
    return {"maps": sorted((m.get("id"), m.get("name")) for m in own),
            "progs": sorted((p.get("id"), p.get("name")) for p in sn)}


def wait_bpf_released(sysr, base: dict, timeout_s: float = BPF_RELEASE_MAX_S, poll_s: float = BPF_RELEASE_POLL_S,
                      sleep=time.sleep, clock=time.monotonic) -> dict:
    """Poll the current BPF state (read-only bpftool) until no run-owned map or program remains, at most timeout_s.
    Unreadable state never counts as released (fail closed)."""
    t0, polls, left = clock(), 0, None
    while True:
        polls += 1
        maps = sysr.run((BPFTOOL, "-j", "map", "show"))
        progs = sysr.run((BPFTOOL, "-j", "prog", "show"))
        try:
            m, p = json.loads(maps) if maps is not None else None, json.loads(progs) if progs is not None else None
        except ValueError:
            m = p = None
        if isinstance(m, list) and isinstance(p, list):
            left = run_owned_bpf(base, m, p)
            if not left["maps"] and not left["progs"]:
                return {"released": True, "timed_out": False, "elapsed_s": clock() - t0, "polls": polls,
                        "remaining": left}
        else:
            left = {"unreadable": True}
        if clock() - t0 >= timeout_s:
            return {"released": False, "timed_out": True, "elapsed_s": clock() - t0, "polls": polls,
                    "remaining": left}
        sleep(poll_s)


# ------------------------------------------------------------------------------------------ cleanup
def read_oplog(path) -> List[dict]:
    try:
        return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    except OSError:
        return []


def oplog_state(entries) -> dict:
    """What this run created or started, from intents (a crash between intent and result still counts)."""
    dirs = [e["op"][1] for e in entries if e["phase"] == "intent" and e["op"][0] == "mkdir"]
    pids = [e["pid"] for e in entries if e["phase"] == "result" and e["op"][0] == "spawn" and e.get("pid")]
    return {"dirs": [d for d in LAB_DIRS if d in dirs], "pids": pids}


def wrapper_alive(sysr, pid) -> bool:
    """A logged hard-timeout wrapper (outside the lab cgroup) is still running. A reaped, zombie or reused pid has a
    different (or empty) command line and does not count."""
    cmd = sysr.read(f"/proc/{pid}/cmdline")
    return bool(cmd) and cmd.split("\0")[:len(WRAPPER)] == WRAPPER


def cleanup(host, sysr, entries, wait_s: float = 5.0, sleep=time.sleep) -> dict:
    """Idempotent cleanup of one run (design §11). Never touches a path the run did not create and never signals a
    process outside the lab cgroup: the workloads die by cgroup.kill, their timeout wrappers then exit by themselves."""
    st = oplog_state(entries)
    steps, errors = [], []

    def step(name, fn):
        try:
            fn()
            steps.append(name)
        except Exception as exc:                       # noqa: BLE001 -- recorded; cleanup continues
            errors.append(f"{name}: {exc!r}")

    for pid in st["pids"]:                            # 1-2: stop target, contender (Host signals lab processes only)
        step(f"kill {pid}", lambda pid=pid: host.apply(("kill", pid)))
    ours = LAB_DIR in st["dirs"]
    deadline = time.monotonic() + wait_s
    while True:                                       # a wrapper's sh may still be joining: kill until both settle
        populated = ours and sysr.exists(LAB_DIR) and "populated 1" in (sysr.read(f"{LAB_DIR}/cgroup.events") or "")
        if populated or (ours and sysr.exists(LAB_DIR) and "cgroup.kill" not in steps):
            step("cgroup.kill", lambda: host.apply(("write", f"{LAB_DIR}/cgroup.kill", "1")))
        wrappers = [p for p in st["pids"] if wrapper_alive(sysr, p)]
        if (not populated and not wrappers) or time.monotonic() >= deadline:
            break
        sleep(0.05)
    left = lab_pids(sysr)                             # 3: no lab PID (and no wrapper) remains
    if left:
        errors.append(f"lab processes remain: {left}")
    if wrappers:
        errors.append(f"timeout wrappers still running: {wrappers}")
    for d in (CONTENDER_DIR, TARGET_DIR, LAB_DIR):    # 4: remove the experiment cgroup (leaves first)
        if d in st["dirs"] and sysr.exists(d):
            step(f"rmdir {d}", lambda d=d: host.apply(("rmdir", d)))
    v = cleanup_state(sysr, st["pids"])               # 5: verify
    return {"ok": not errors and v["ok"], "steps": steps, "errors": errors, "verify": v}


def cleanup_state(sysr, pids=()) -> dict:
    c = {"lab_cgroup_absent": not sysr.exists(LAB_DIR), "no_sentinel_cgroup": not sentinel_cgroups(sysr),
         "no_lab_process": not lab_pids(sysr),
         "no_logged_pid_alive_in_lab": not [p for p in pids if f"::/{LAB}" in (sysr.read(f"/proc/{p}/cgroup") or "")],
         "no_wrapper_alive": not [p for p in pids if wrapper_alive(sysr, p)]}
    return {"ok": all(c.values()), "checks": c}


# ------------------------------------------------------------------------------------------ simulated host (dry-run)
class SimHost:
    """In-memory stand-in for Host + Sys used by the dry-run to validate setup/cleanup structurally.
    It applies check_op() exactly like Host and models cgroupfs rules (no rmdir while populated or with children)."""

    def __init__(self, exp, iters=1000, fail_at=None):
        self.exp, self.iters, self.fail_at = exp, iters, fail_at
        self.dirs, self.files, self.procs, self.alive = set(), {}, {d: [] for d in LAB_DIRS}, set()
        self.wrappers = {}                 # wrapper pid (outside the lab) -> its workload pid (in a leaf)
        self.applied, self.n = [], 0
        self.next_pid = 40000

    # Host
    def apply(self, op, stdout=None, stderr=None):
        check_op(op, self.exp, self.iters)
        self.n += 1
        if self.fail_at == self.n:
            raise OSError(f"injected failure at operation {self.n}: {op[0]}")
        kind = op[0]
        self.applied.append(op)
        if kind == "mkdir":
            if op[1] in self.dirs:
                raise OSError("exists")
            parent = op[1].rsplit("/", 1)[0]
            if parent != CG_ROOT and parent not in self.dirs:
                raise OSError("no parent")
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
                    if k.startswith(LAB_DIR):
                        for p in self.procs[k]:
                            self._die(p)
                        self.procs[k] = []
            self.files[op[1]] = op[2]
        elif kind == "spawn":
            leaf = TARGET_DIR if op[1] in ("target", "calibration") else CONTENDER_DIR
            if leaf not in self.dirs:
                raise OSError("leaf missing")
            pid, self.next_pid = self.next_pid, self.next_pid + 2
            self.procs[leaf] = self.procs.get(leaf, []) + [pid + 1]      # one pid per leaf: the workload
            self.wrappers[pid] = pid + 1
            self.alive |= {pid, pid + 1}
            return type("P", (), {"pid": pid})()
        elif kind == "kill":                                             # like Host: lab processes only
            for k in self.procs:
                if op[1] in self.procs[k]:
                    self.procs[k] = [p for p in self.procs[k] if p != op[1]]
                    self._die(op[1])

    def _die(self, pid):
        self.alive.discard(pid)
        for w, c in self.wrappers.items():
            if c == pid:
                self.alive.discard(w)          # timeout exits when its child dies

    # Sys (subset used by cleanup)
    def exists(self, path):
        return path in self.dirs

    def read(self, path):
        if path == f"{LAB_DIR}/cgroup.events":
            return f"populated {int(any(self.procs[d] for d in LAB_DIRS if d in self.procs))}\nfrozen 0\n"
        if path.startswith("/proc/") and path.endswith("/cgroup"):
            pid = int(path.split("/")[2])
            if pid not in self.alive:
                return None
            return "0::/user.slice/driver\n" if pid in self.wrappers else f"0::/{LAB}/x\n"
        if path.startswith("/proc/") and path.endswith("/cmdline"):
            pid = int(path.split("/")[2])
            return "\0".join(WRAPPER + ["sh"]) + "\0" if pid in self.wrappers and pid in self.alive else None
        return None

    def cgroup_dirs(self):
        return sorted(d[len(CG_ROOT) + 1:] for d in self.dirs)

    def pids(self):
        return sorted(self.alive)


def simulate(exp: Experiment, fail_at=None) -> dict:
    """Setup (optionally failing at operation fail_at), spawn, then cleanup from the op log; result must be clean."""
    sim = SimHost(exp, fail_at=fail_at)
    entries = []

    class Logged:
        def apply(self, op, stdout=None, stderr=None):
            entries.append({"phase": "intent", "op": list(op[:2])})
            res = sim.apply(op)
            entries.append({"phase": "result", "op": list(op[:2]), "ok": True, "pid": getattr(res, "pid", None)})
            return res

    h = Logged()
    failed = None
    out = str(REPO / "results" / "phase1c_r2c" / "sim" / "x.json")
    try:
        for op in setup_plan(exp):
            h.apply(op)
        h.apply(("spawn", "target", target_argv(1000, out)))
        if exp.contender_cpu is not None:
            h.apply(("spawn", "contender", contender_argv(out)))
    except OSError as exc:
        failed = str(exc)
    res = cleanup(h, sim, entries, wait_s=0.0, sleep=lambda s: None)
    clean = not sim.dirs and not sim.alive
    return {"failed_at": failed, "cleanup_ok": res["ok"], "host_clean": clean, "ops_applied": len(sim.applied)}


def simulate_bpf_release() -> dict:
    """wait_bpf_released against scripted BPF states (fake clock): released at once, late, never, unrelated object."""
    base = {"bpf": {"map": [{"id": 1, "name": "other"}], "prog": []}}
    own = [{"id": 10, "name": "sn_hist"}, {"id": 11, "name": "sentinel.rodata"}]

    class Script:
        def __init__(self, states):
            self.states, self.i = states, 0

        def run(self, argv):
            st = self.states[min(self.i // 2, len(self.states) - 1)]
            self.i += 1
            return json.dumps(st[0] if argv[2] == "map" else st[1])
    clock = {"t": 0.0}
    res = {}
    for name, states, want in (("immediate", [([{"id": 1, "name": "other"}], [])], True),
                               ("late", [(own, [{"id": 5, "name": "sn_sched_switch"}]), (own, []), ([], [])], True),
                               ("never", [(own, [])], False),
                               ("unrelated_remains", [([{"id": 1, "name": "other"}, {"id": 12, "name": "x"}], [])], True)):
        clock["t"] = 0.0
        r = wait_bpf_released(Script(states), base, sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
                              clock=lambda: clock.__setitem__("t", clock["t"] + 1e-4) or clock["t"])
        res[name] = r["released"] == want and (r["timed_out"] is not want)
    return {"ok": all(res.values()), "cases": res}


# ------------------------------------------------------------------------------------------ dry run
def dry_run(sysr) -> dict:
    """Read-only: prerequisites, allocation, guards, intended mutations, metric sources, cleanup structure.
    Never instantiates Host; never creates a cgroup, process, namespace, qdisc or affinity change."""
    from sentinelai.collectors.ebpf import ebpf_calcs
    from sentinelai.collectors.features import build as feature_table
    from sentinelai.collectors.probes import sample as probe_sample
    from sentinelai.collectors.reader import LiveReader
    from sentinelai.diagnostic.contract import Target

    rep = {"mode": "dry-run", "criteria": CRITERIA}
    before = host_snapshot(sysr, require_bpf=False)
    rep["preflight"] = preflight(sysr)
    rep["allocation"] = allocation_checks()
    # intended mutations, per run (ITERS is fixed by the calibration step at runtime)
    out = REPO / "results" / "phase1c_r2c" / "<TS>"
    cal_argv = calibration_argv(str(out / "calibration" / "calibration.json"))
    plan = {"calibration": {"runtime_step": 0, "requires_runtime_authorisation": True, "executed": False,
                            "cpu": TARGET_CPU, "cgroup": TARGET_DIR, "contender": None, "before": MATRIX[0],
                            "evidence": "provenance only: excluded from experiment evidence and baselines; its "
                                        "iteration count is fixed for every run",
                            "setup": setup_plan(EXPERIMENTS["E0"]), "spawn": [("calibration", cal_argv)]}}
    for label in MATRIX:
        exp = experiment_of(label)
        targv = target_argv(1, str(out / label / "target.json"))
        targv[targv.index("--iters") + 1] = "<ITERS>"
        spawns = [("target", targv)]
        if exp.contender_cpu is not None:
            spawns.append(("contender (at W start, SIGKILL at W end)", contender_argv(str(out / label / "contender.cnt"))))
        plan[label] = {"experiment": exp.__dict__, "setup": setup_plan(exp), "spawn": spawns,
                       "teardown": [("kill", "<logged pids>"), ("write", f"{LAB_DIR}/cgroup.kill", "1"),
                                    ("rmdir", CONTENDER_DIR), ("rmdir", TARGET_DIR), ("rmdir", LAB_DIR)]}
    rep["intended_mutations"] = plan
    one = {"calibration": spawn_structure(cal_argv, TARGET_DIR),
           "target": spawn_structure(target_argv(1, str(out / "x" / "target.json")), TARGET_DIR),
           "contender": spawn_structure(contender_argv(str(out / "x" / "contender.cnt")), CONTENDER_DIR)}
    rep["one_pid_spawn_structure"] = {k: v["ok"] for k, v in one.items()}
    rep["criteria_resolved"] = all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (
        G4_N_MIN, G4_RATIO_MIN, G4_ABS_MIN_NS, G7_SOFTIRQ_MAX_DELTA, MEM_PSI_W_MAX_US, SWAP_MAX_PAGES_PER_S,
        HOST_PSI_AVG10_MAX, SLICE_AVG10_MAX, SLICE_PSI_RISE_MAX))
    # guards accept every planned operation and refuse a set of forbidden ones
    g = {}
    for label in MATRIX:
        exp = experiment_of(label)
        try:
            for op in setup_plan(exp) + [("write", f"{LAB_DIR}/cgroup.kill", "1"), ("rmdir", LAB_DIR)]:
                check_op(op, exp)
            g[label] = True
        except R2CRefused as exc:
            g[label] = str(exc)
    forbidden = [("write", f"{TARGET_DIR}/cpu.max", "50000 100000"), ("write", f"{CG_ROOT}/cpuset.cpus", "0-23"),
                 ("write", f"{CG_ROOT}/system.slice/cpu.weight", "100"), ("write", f"{TARGET_DIR}/cpuset.cpus", "21"),
                 ("mkdir", f"{CG_ROOT}/system.slice/x"), ("rmdir", f"{CG_ROOT}/user.slice"),
                 ("spawn", "contender", ["stress-ng", "--cpu", "0"]), ("exec", "sysctl", "-w")]
    refused = []
    for op in forbidden:
        try:
            check_op(op, EXPERIMENTS["E2"], 1000)
        except R2CRefused:
            refused.append(True)
        else:
            refused.append(False)
    rep["guards"] = {"planned_ops_accepted": g, "forbidden_ops_refused": all(refused), "n_forbidden": len(forbidden)}
    # cleanup structure: failure injected at every setup step, for every experiment
    sims = {}
    for k, exp in EXPERIMENTS.items():
        n = len(setup_plan(exp)) + (2 if exp.contender_cpu is not None else 1)
        sims[k] = [simulate(exp, f) for f in [None] + list(range(1, n + 1))]
    rep["cleanup_simulation"] = {"ok": all(s["cleanup_ok"] and s["host_clean"] for v in sims.values() for s in v),
                                 "cases": sum(len(v) for v in sims.values())}
    # metric availability: the collector's own feature table for the R2-C target shape, and live source parsing
    t = Target(name="r2c", cgroup_path=TARGET_CGROUP_PATH, pids=(1,), cpuset=str(TARGET_CPU), netns_ref="pid:1", ifaces=())
    calcs = feature_table(t, tuple(sorted(HOST_CPUS)), (TARGET_CPU,), (TARGET_CPU,), False) + \
        ebpf_calcs(t, tuple(sorted(HOST_CPUS)), ())
    have = {(c.feature, c.scope, (c.aggregation.value if c.aggregation else None)) for c in calcs}
    cg = f"cgroup:{TARGET_CGROUP_PATH}"
    rep["metric_table"] = {f"{f}[{a}]": (f, cg if sc == "cg" else sc, a if f == "sched.latency_hist.target" else None)
                           in have for f, sc, a in REQUIRED_METRICS}
    rep["metric_table"].update({f"exclusion:{f}": (f, s, None) in have for f, s in
                                (("throttle.ratio", cg), ("softirq.frac.percpu", f"cpu:{TARGET_CPU}"),
                                 ("throttle.time_rate", cg), ("throttle.quota_limited", cg))})
    stand_in = Target(name="r2c-dry", cgroup_path="/system.slice", pids=(os.getpid(),), cpuset=str(TARGET_CPU),
                      netns_ref=f"pid:{os.getpid()}", ifaces=())
    obs = probe_sample(LiveReader(), stand_in)
    stat, sched, cst, task = obs["proc.stat"], obs["proc.schedstat"], obs["cg.cpu.stat"], obs["task"]
    rep["live_sources"] = {
        "proc_stat_cpu18_busy_total_steal": isinstance(stat, dict) and all(f"cpu18.{k}" in stat
                                                                          for k in ("busy", "total", "steal")),
        "proc_stat_cpu18_softirq": isinstance(stat, dict) and "cpu18.softirq" in stat,
        "proc_schedstat_cpu18": isinstance(sched, dict) and "cpu18.run_delay" in sched,
        "task_schedstat_run_delay": isinstance(task, dict) and isinstance(task.get("run_delay"), dict)
        and bool(task["run_delay"]),
        "cpu_stat_throttle_fields_on_cpu_controller_cgroup": isinstance(cst, dict) and all(
            isinstance(cst.get(k), float) for k in ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec")),
        "psi_cpu_host": sysr.read("/proc/pressure/cpu") is not None,
        "btf_vmlinux": sysr.exists("/sys/kernel/btf/vmlinux"),
        "loader_libbpf_1_4": '"libbpf_linked":"1.4"' in (sysr.run((LOADER, "--version")) or ""),
    }
    # G1-G7 sources readable on this host (the lab files themselves exist only at runtime)
    rep["gt_sources"] = {
        "proc_stat": bool(proc_stat_cpus(sysr.read("/proc/stat")).get(f"cpu{TARGET_CPU}")),
        "schedstat_v15_cpu18_rq_cpu_time": schedstat_rq_cpu_time(sysr.read("/proc/schedstat")) is not None,
        "task_stat_processor": task_processor(sysr.read(f"/proc/{os.getpid()}/stat")) is not None,
        "irq_effective_affinity": sysr.read(f"/proc/irq/{NIC_IRQ}/effective_affinity_list") is not None,
        "psi_cpu_memory": bool(psi(sysr.read("/proc/pressure/cpu"))) and bool(psi(sysr.read("/proc/pressure/memory"))),
        "slice_cpu_pressure": all(psi(sysr.read(f"{CG_ROOT}/{s}/cpu.pressure")) for s in SLICES),
        "vmstat_swap": {"pswpin", "pswpout"} <= set(kv(sysr.read("/proc/vmstat"))),
        "netns_counters_parse": netns_counters(sysr.read(f"/proc/{os.getpid()}/net/dev"),
                                               sysr.read(f"/proc/{os.getpid()}/net/snmp")) is not None,
        "cgroup_cpu_stat_memory_events_parse": bool(kv(sysr.read(f"{CG_ROOT}/system.slice/cpu.stat"))) and
        bool(kv(sysr.read(f"{CG_ROOT}/system.slice/memory.events"))),
    }
    rep["bpf_release_simulation"] = simulate_bpf_release()
    after = host_snapshot(sysr, require_bpf=False)
    rep["zero_mutation"] = compare_host(before, after, require_bpf=False)
    rep["structural_ok"] = (rep["preflight"]["ok"] and all(rep["allocation"].values())
                            and all(v is True for v in g.values()) and rep["guards"]["forbidden_ops_refused"]
                            and rep["cleanup_simulation"]["ok"] and all(rep["metric_table"].values())
                            and all(rep["live_sources"].values()) and all(rep["gt_sources"].values())
                            and all(rep["one_pid_spawn_structure"].values()) and rep["criteria_resolved"]
                            and rep["bpf_release_simulation"]["ok"]
                            and rep["zero_mutation"]["ok"])
    return rep


# ------------------------------------------------------------------------------------------ candidate
def candidate(repo, base):
    g = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)
    head, b = g("rev-parse", "HEAD"), g("rev-parse", "--verify", f"{base}^{{commit}}")
    if head.returncode or b.returncode:
        return {"ok": False, "reason": "HEAD or base not resolvable"}
    head, b = head.stdout.strip(), b.stdout.strip()
    if g("merge-base", "--is-ancestor", b, head).returncode:
        return {"ok": False, "reason": f"HEAD {head} does not descend from {b}"}
    changed = [p for p in g("diff", "--name-only", b, head).stdout.split() if p not in TOOLING]
    if changed:
        return {"ok": False, "reason": f"changed since {b[:7]} beyond R2-C tooling: {sorted(changed)}"}
    if g("status", "--porcelain", "--untracked-files=no").stdout.strip():
        return {"ok": False, "reason": "tracked files modified"}
    return {"ok": True, "head": head, "base": b}


# ------------------------------------------------------------------------------------------ CLI
def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    sys.path.insert(0, str(REPO / "src"))
    if cmd == "dry-run":
        rep = dry_run(Sys())
        print(json.dumps(rep, indent=1, sort_keys=True, default=str))
        return 0 if rep["structural_ok"] else 3
    if cmd == "criteria":
        print(json.dumps(CRITERIA, indent=1, sort_keys=True))
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
    if cmd == "cleanup":                         # wrapper trap: every op log under OUT, idempotent
        res = {}
        for log in sorted(Path(argv[2]).rglob("ops.jsonl")):
            entries = read_oplog(log)
            res[str(log)] = cleanup(Host(EXPERIMENTS["E2"], str(log) + ".cleanup"), Sys(), entries)
        v = cleanup_state(Sys())
        print(json.dumps({"runs": res, "final": v}, indent=1, sort_keys=True))
        return 0 if v["ok"] and all(r["ok"] for r in res.values()) else 3
    if cmd == "candidate":
        r = candidate(argv[2], argv[3])
        print(r["head"] if r["ok"] else r["reason"])
        return 0 if r["ok"] else 3
    raise SystemExit("usage: r2c_cpu.py dry-run | criteria | preflight | host-snapshot DIR | compare A B | "
                     "cleanup OUT | candidate REPO BASE")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
