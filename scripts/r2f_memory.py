#!/usr/bin/env python3
"""SentinelAI R2-F: controlled memory pressure in an isolated lab cgroup: guards, ground truth, cleanup.

The approved design (R2-F DESIGN REVIEW: APPROVED WITH CONDITIONS 1-12), implemented without reinterpretation:
  lab        /sys/fs/cgroup/sentinel-r2f {target, contender}; controllers cpuset cpu memory pids; CPU 18 only
  memory     memory.swap.max = 0 on parent, target, contender (the lab never uses swap); target memory.high = H and
             memory.max = H + 128 MiB; parent memory.max = 1792 MiB; contender memory.max = 64 MiB. Every memory control
             is written (read-before 'max', read-after exact bytes, logged) during setup, verified, and only then may
             the target start; no memory control is written after any spawn (no reclaim ever runs in the driver)
  workload   scripts/r2f_target.py (uid 1000, private netns, CPU 18): creates a 1 GiB file in its own cgroup on the
             ext4 /var/tmp scratch path, MADV_RANDOM, one byte per page, 256 MiB scan range; one SIGUSR1 in the
             window callback expands it to 1 GiB exactly once (M1, M2, N1)
  matrix     calibration (provenance), E0-open, M1 x3 (H 768 MiB), M2 x3 (H 512 MiB), N1 x2 (H 1536 MiB, expansion
             without pressure), N2 x2 (R2-C E2 contender on CPU 18), E0-close
  truth      GP GC GD GM GI GL GCPU GT GN GH GR from saved raw inputs (evaluate() is pure); never "MP.R1 became TRUE"
  OOM        target or contender oom / oom_kill > 0: ABORT; host /proc/vmstat oom_kill delta > 0: ABORT + stop campaign

Sys only reads. Host is the single mutation site; every operation is re-validated by check_op() right before it runs.
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
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import r2c_cpu as C  # noqa: E402  (R2-C parsers, host snapshot, BPF release; unchanged)
import r2e_softirq as E  # noqa: E402  (R2-E task/softirq parsers, host snapshot with RPS/lab checks; unchanged)
from r2a_lab import PROTECTED  # noqa: E402

REPO = C.REPO
from r2b_driver import NUMBERS  # noqa: E402  (validation parameter values, unchanged)

# ------------------------------------------------------------------------------------------ design constants
CG_ROOT = C.CG_ROOT
LAB = "sentinel-r2f"
LAB_DIR = f"{CG_ROOT}/{LAB}"
TARGET_DIR, CONTENDER_DIR = f"{LAB_DIR}/target", f"{LAB_DIR}/contender"
TARGET_CGROUP_PATH = f"/{LAB}/target"
LAB_DIRS = (LAB_DIR, TARGET_DIR, CONTENDER_DIR)
LEAVES = (("target", TARGET_DIR), ("contender", CONTENDER_DIR))
TARGET_CPU = C.TARGET_CPU                    # 18
SUPPORT_CPUS = C.SUPPORT_CPUS                # 0-15
EXPERIMENT_CPUS = frozenset({TARGET_CPU})
CONTROLLERS = ("cpuset", "cpu", "memory", "pids")
# R2-F-local root requirement: the root must delegate every controller the lab enables; other root controllers
# (io, hugetlb, rdma, misc, ...) are irrelevant to R2-F. Deliberately NOT R2-C's exact ROOT_SUBTREE set.
REQUIRED_ROOT_CONTROLLERS = frozenset({"cpuset", "cpu", "memory", "pids"})
CONTROLLER_NAME = re.compile(r"[a-z][a-z0-9_]*")

MIB = 1 << 20
PAGE = 4096
FILE_BYTES = 1024 * MIB                      # DESIGN CONSTANT
SCAN_B = 256 * MIB                           # DESIGN CONSTANT
SCAN_W = 1024 * MIB                          # DESIGN CONSTANT (the expansion)
TARGET_MAX_HEADROOM = 128 * MIB              # memory.max = H + 128 MiB
PARENT_MAX = 1792 * MIB
CONTENDER_MAX = 64 * MIB
PERIOD_NS = 10_000_000
PAGES_PER_CYCLE = 524                        # 2 full 1 GiB passes in 10 s at 100 cycles/s
WARMUP_S, NB, NW, RECOVERY_S = C.WARMUP_S, C.NB, C.NW, C.RECOVERY_S
CYCLES = (WARMUP_S + NB + NW + RECOVERY_S) * 1_000_000_000 // PERIOD_NS     # 4000
READY_TIMEOUT_S = 30
HARD_TIMEOUT_S = 90
TARGET_SCRIPT = str(REPO / "scripts" / "r2f_target.py")
RESULTS = REPO / "results" / "phase1c_r2f"
SCRATCH_PARENT = "/var/tmp"
SCRATCH_BASE = f"{SCRATCH_PARENT}/{LAB}"
SCRATCH_RUN = re.compile(rf"^{re.escape(SCRATCH_BASE)}/\d{{8}}T\d{{6}}Z-(calibration|E0-open|E0-close|M[12]-[123]|"
                         r"N[12]-[12])$")
WS_NAME = "ws.bin"

# Safety thresholds (Condition 1: frozen, provenance in SAFETY_THRESHOLDS)
MEM_AVAILABLE_MIN_BYTES = 4 << 30
SLICE_MEM_PSI_RISE_MAX = C.SLICE_PSI_RISE_MAX        # 0.01
SLICE_IO_PSI_RISE_MAX = C.SLICE_PSI_RISE_MAX         # 0.01
SWAP_MAX_PAGES_PER_S = C.SWAP_MAX_PAGES_PER_S        # 25.0
SAFETY_THRESHOLDS = {
    "host_MemAvailable_min": {
        "value": "4 GiB at every observation", "class": "design-derived safety threshold",
        "rationale": "the lab is hard-capped at 1792 MiB (parent memory.max) and never swaps; 4 GiB keeps >= 2.2 GiB "
                     "above that cap (~25 % of the 16 GiB host), far above the kernel watermarks (min_free_kbytes "
                     "67584 KiB); the host had 13.0-13.9 GiB available at the R2-E gates; global reclaim is detected "
                     "independently (host pgscan_kswapd delta = 0)"},
    "slice_memory_psi_rise": {
        "value": f"system.slice / user.slice / init.scope memory.pressure some: r_W - r_B <= {SLICE_MEM_PSI_RISE_MAX}",
        "class": "design-derived safety threshold (repository analogue)",
        "rationale": "same value and formula as the R2-C SLICE_PSI_RISE_MAX (cpu.pressure), approved in the R2-C "
                     "parameter approval and passed in R2-C/R2-D runtime; applied to memory.pressure of the same "
                     "non-lab top-level cgroups"},
    "slice_io_psi_rise": {
        "value": f"system.slice / user.slice / init.scope io.pressure some: r_W - r_B <= {SLICE_IO_PSI_RISE_MAX}",
        "class": "design-derived safety threshold (repository analogue)",
        "rationale": "as above, for io.pressure: refault reads hit the shared NVMe"},
    "host_swap_io": {
        "value": f"(pswpin + pswpout) / W_s <= {SWAP_MAX_PAGES_PER_S} pages/s", "class": "previously validated safety "
        "threshold", "rationale": "R2-C MEMORY_SWAP criterion (SAFETY THRESHOLD, repository-informed), enforced in "
                                  "every R2-C and R2-D evidence run; the lab itself cannot swap (memory.swap.max = 0)"},
}

REFAULT_MIN = NUMBERS["REFAULT_MIN"]         # 100 pages/s (existing validation number)
R_STRONG = NUMBERS["R_STRONG"]               # 3.0
RDX_MIN = NUMBERS["RDX_MIN"]                 # 0.05
SI_RATIO_MIN = NUMBERS["SI_RATIO_MIN"]       # 3.0
FLOOR = 1e-3
G6_MAX = C.G6_FOREIGN_MAX_CORES              # 0.05
G3_IDLE_MAX = C.G3_IDLE_MAX                  # 0.05
G4_RATIO_MIN = C.G4_RATIO_MIN                # 1.5
VM_SYSCTLS = ("vm/swappiness", "vm/overcommit_memory", "vm/min_free_kbytes", "vm/watermark_scale_factor",
              "vm/vfs_cache_pressure", "vm/dirty_ratio", "vm/dirty_background_ratio")
TOOLING = ("scripts/r2f_memory.py", "scripts/r2f_driver.py", "scripts/r2f_target.py", "scripts/r2f_validate.sh",
           "tests/faultlab/test_r2f.py")
BASE_COMMIT = "4aa23b8"


@dataclass(frozen=True)
class Experiment:
    kind: str
    high: int                 # target memory.high (bytes)
    expand: bool              # one SIGUSR1 in the window callback (scan 256 MiB -> 1 GiB)
    contender: bool           # R2-C E2 contender on CPU 18 during W
    contender_weight: int = 400


EXPERIMENTS = {
    "CAL": Experiment("CAL", 1536 * MIB, False, False),
    "E0": Experiment("E0", 1536 * MIB, False, False),
    "M1": Experiment("M1", 768 * MIB, True, False),
    "M2": Experiment("M2", 512 * MIB, True, False),
    "N1": Experiment("N1", 1536 * MIB, True, False),
    "N2": Experiment("N2", 1536 * MIB, False, True),
}
MATRIX = ("E0-open", "M1-1", "M1-2", "M1-3", "M2-1", "M2-2", "M2-3", "N1-1", "N1-2", "N2-1", "N2-2", "E0-close")
PRESSURE = ("M1", "M2")


class R2FRefused(C.R2CRefused):
    """An operation outside the R2-F authorisation."""


class MemAbort(C.LabAbort):
    """A memory-control read-back / previous-value / ordering check failed: hard abort."""


def experiment_of(label: str) -> Experiment:
    if label not in MATRIX:
        raise R2FRefused(f"run {label!r} is not in the approved R2-F matrix")
    return EXPERIMENTS[label.split("-")[0]]


def scan_w(exp: Experiment) -> int:
    return SCAN_W if exp.expand else SCAN_B


def allocation_checks() -> Dict[str, bool]:
    return {
        "pressure_by_geometry": all(SCAN_W > EXPERIMENTS[k].high for k in PRESSURE),
        "controls_without_pressure": all(scan_w(EXPERIMENTS[k]) + 64 * MIB < EXPERIMENTS[k].high
                                         for k in ("CAL", "E0", "N1", "N2")),
        "m2_stronger_than_m1": EXPERIMENTS["M2"].high < EXPERIMENTS["M1"].high,
        "parent_cap_holds_leaves": all(e.high + TARGET_MAX_HEADROOM + CONTENDER_MAX <= PARENT_MAX
                                       for e in EXPERIMENTS.values()),
        "page_aligned": all(v % PAGE == 0 for v in (FILE_BYTES, SCAN_B, SCAN_W, PARENT_MAX, CONTENDER_MAX)
                            ) and all(e.high % PAGE == 0 for e in EXPERIMENTS.values()),
        "nic_cpu_excluded": C.NIC_CPU not in EXPERIMENT_CPUS,
        "support_cpus_disjoint": not set(SUPPORT_CPUS) & EXPERIMENT_CPUS,
        "matrix_12_plus_calibration": len(MATRIX) == 12 and len(set(MATRIX)) == 12,
    }


# ------------------------------------------------------------------------------------------ mutation guard
def memory_plan(exp: Experiment) -> List[tuple]:
    """The memory controls, in order (all before any process exists)."""
    return [("mem", f"{LAB_DIR}/memory.max", str(PARENT_MAX)), ("mem", f"{LAB_DIR}/memory.swap.max", "0"),
            ("mem", f"{TARGET_DIR}/memory.swap.max", "0"),
            ("mem", f"{TARGET_DIR}/memory.max", str(exp.high + TARGET_MAX_HEADROOM)),
            ("mem", f"{TARGET_DIR}/memory.high", str(exp.high)),
            ("mem", f"{CONTENDER_DIR}/memory.swap.max", "0"),
            ("mem", f"{CONTENDER_DIR}/memory.max", str(CONTENDER_MAX))]


def cgroup_plan(exp: Experiment) -> List[tuple]:
    return [("mkdir", LAB_DIR),
            ("write", f"{LAB_DIR}/cpuset.mems", C.MEMS), ("write", f"{LAB_DIR}/cpuset.cpus", str(TARGET_CPU)),
            ("write", f"{LAB_DIR}/cgroup.subtree_control", " ".join(f"+{c}" for c in CONTROLLERS)),
            ("mkdir", TARGET_DIR), ("mkdir", CONTENDER_DIR),
            ("write", f"{TARGET_DIR}/cpuset.cpus", str(TARGET_CPU)), ("write", f"{TARGET_DIR}/cpuset.mems", C.MEMS),
            ("write", f"{TARGET_DIR}/cpu.weight", str(C.TARGET_WEIGHT)), ("write", f"{TARGET_DIR}/pids.max", C.PIDS_MAX),
            ("write", f"{CONTENDER_DIR}/cpuset.cpus", str(TARGET_CPU)), ("write", f"{CONTENDER_DIR}/cpuset.mems", C.MEMS),
            ("write", f"{CONTENDER_DIR}/cpu.weight", str(exp.contender_weight)),
            ("write", f"{CONTENDER_DIR}/pids.max", C.PIDS_MAX)]


def allowed_writes(exp: Experiment) -> set:
    return {(op[1], op[2]) for op in cgroup_plan(exp) if op[0] == "write"} | \
        {(f"{d}/cgroup.kill", "1") for d in LAB_DIRS}


def allowed_mem(exp: Experiment) -> set:
    return {(op[1], op[2]) for op in memory_plan(exp)}


WRAPPER = ["timeout", "-s", "KILL", str(HARD_TIMEOUT_S)]
DROP_PRIV = ["setpriv", f"--reuid={C.LAB_UID}", f"--regid={C.LAB_GID}", "--init-groups", "--"]


def join(leaf):
    return WRAPPER + ["sh", "-c", f'echo $$ > {leaf}/cgroup.procs && exec "$@"', "sh"]


def scratch_dir(ts: str, label: str) -> str:
    d = f"{SCRATCH_BASE}/{ts}-{label}"
    if not SCRATCH_RUN.fullmatch(d):
        raise R2FRefused(f"scratch directory {d!r} not approved")
    return d


def target_argv(exp: Experiment, run_dir: str, out_path: str) -> List[str]:
    if not SCRATCH_RUN.fullmatch(run_dir):
        raise R2FRefused(f"scratch directory {run_dir!r} not approved")
    return join(TARGET_DIR) + ["unshare", "--net", "--"] + DROP_PRIV + [
        C.PYTHON, "-I", TARGET_SCRIPT, "--file", f"{run_dir}/{WS_NAME}", "--file-bytes", str(FILE_BYTES),
        "--scan-b", str(SCAN_B), "--scan-w", str(scan_w(exp)), "--period-ns", str(PERIOD_NS),
        "--pages-per-cycle", str(PAGES_PER_CYCLE), "--cycles", str(CYCLES), "--out", str(out_path)]


def contender_argv(counter_path: str) -> List[str]:
    return join(CONTENDER_DIR) + DROP_PRIV + [C.PYTHON, "-I", "-c", C.CONTENDER_CODE, str(counter_path)]


def _results_path(p) -> bool:
    s = str(p)
    return s.startswith(str(RESULTS) + "/") and "/../" not in s and "\x00" not in s


def spawn_structure(argv, leaf) -> dict:
    j = join(leaf)
    after = argv[len(j):]
    c = {"wrapper_first": argv[:len(WRAPPER)] == WRAPPER, "join_follows_wrapper": argv[:len(j)] == j,
         "single_wrapper": argv.count("timeout") == 1,
         "no_fork_after_join": not {"timeout", "sh", "nohup", "setsid", "bash"} & set(after),
         "python_last_exec": C.PYTHON in after and after.index(C.PYTHON) > after.index("--")}
    return {"ok": all(c.values()), "checks": c}


def check_op(op, exp: Experiment, state: Optional[dict] = None):
    """The closed set of host operations of one R2-F run. state: {'controls_verified', 'spawned', 'run_dir',
    'target_pid'} of the Host (ordering is part of the guard). Anything else raises R2FRefused."""
    st = state or {}
    if not isinstance(op, tuple) or not op:
        raise R2FRefused(f"malformed operation {op!r}")
    text = repr(op)
    for p in PROTECTED:
        if p in text:
            raise R2FRefused(f"protected interface {p} in operation")
    kind = op[0]
    if kind in ("mkdir", "rmdir"):
        if len(op) != 2 or op[1] not in LAB_DIRS:
            raise R2FRefused(f"{kind} outside the lab cgroup: {op!r}")
    elif kind == "write":
        if len(op) != 3 or (op[1], op[2]) not in allowed_writes(exp) or "memory." in str(op[1]):
            raise R2FRefused(f"write not in the {exp.kind} allowlist: {op!r}")
    elif kind == "mem":
        if len(op) != 3 or (op[1], op[2]) not in allowed_mem(exp):
            raise R2FRefused(f"memory write not in the {exp.kind} allowlist: {op!r}")
        if st.get("spawned"):
            raise R2FRefused("memory controls may not change after a process was started (reclaim in the driver)")
    elif kind == "scratch":
        if len(op) != 3 or op[1] not in ("mkdir_base", "mkdir", "unlink", "rmdir", "rmdir_base"):
            raise R2FRefused(f"malformed scratch operation {op!r}")
        path = op[2]
        if op[1] in ("mkdir_base", "rmdir_base"):
            if path != SCRATCH_BASE:
                raise R2FRefused(f"scratch base {path!r} not approved")
        elif op[1] in ("mkdir", "rmdir"):
            if not SCRATCH_RUN.fullmatch(path) or path != st.get("run_dir", path):
                raise R2FRefused(f"scratch directory {path!r} not approved")
        elif not (path.endswith("/" + WS_NAME) and SCRATCH_RUN.fullmatch(path.rsplit("/", 1)[0])):
            raise R2FRefused(f"scratch file {path!r} not approved")
    elif kind == "spawn":
        if not st.get("controls_verified"):
            raise R2FRefused("no process may start before every memory control is written and verified")
        if len(op) != 3 or op[1] not in ("target", "contender"):
            raise R2FRefused(f"malformed spawn {op!r}")
        role, argv = op[1], list(op[2])
        if not _results_path(argv[-1]):
            raise R2FRefused(f"{role} output outside results/phase1c_r2f: {argv[-1:]}")
        if not spawn_structure(argv, CONTENDER_DIR if role == "contender" else TARGET_DIR)["ok"]:
            raise R2FRefused(f"{role} argv breaks the one-pid structure: {argv}")
        if role == "contender":
            if not exp.contender or argv != contender_argv(argv[-1]):
                raise R2FRefused(f"contender argv not approved for {exp.kind}: {argv}")
        elif st.get("target_spawned"):
            raise R2FRefused("the target was already started in this run")
        elif not st.get("run_dir") or argv != target_argv(exp, st["run_dir"], argv[-1]):
            raise R2FRefused(f"target argv not approved: {argv}")
    elif kind == "signal":
        if len(op) != 2 or not exp.expand or op[1] != st.get("target_pid") or st.get("signalled"):
            raise R2FRefused(f"SIGUSR1 not approved: {op!r} (expand {exp.expand}, signalled {st.get('signalled')})")
    elif kind == "kill":
        if len(op) != 2 or isinstance(op[1], bool) or not isinstance(op[1], int) or op[1] <= 1:
            raise R2FRefused(f"malformed kill {op!r}")
    else:
        raise R2FRefused(f"operation {kind!r} is not authorised in R2-F")
    return op


def lab_member(sysr, pid) -> bool:
    return f"::/{LAB}/" in (sysr.read(f"/proc/{pid}/cgroup") or "")


def lab_pids(sysr) -> List[int]:
    return [p for p in sysr.pids() if f"::/{LAB}" in (sysr.read(f"/proc/{p}/cgroup") or "")]


def wrapper_alive(sysr, pid) -> bool:
    cmd = sysr.read(f"/proc/{pid}/cmdline")
    return bool(cmd) and cmd.split("\0")[:len(WRAPPER)] == WRAPPER


def mem_write(path, value, read, write, log, clock=time.monotonic) -> dict:
    """The single memory-control write path: read-before ('max'), log intent, write, read-after (exact), log result."""
    prev = (read(path) or "").strip()
    if prev != "max":
        log(phase="refused", op=["mem", path], value=value, prev=prev, expected_prev="max")
        raise MemAbort(f"{path} before write is {prev!r}, expected 'max'")
    log(phase="intent", op=["mem", path], value=value, prev=prev)
    t0 = clock()
    write(path, value)
    post = (read(path) or "").strip()
    ok = post == value
    log(phase="result", op=["mem", path], value=value, prev=prev, post=post, ok=ok, t0=t0, t1=clock())
    if not ok:
        raise MemAbort(f"{path} after write is {post!r}, expected {value!r}")
    return {"path": path, "value": value, "prev": prev, "post": post}


def verify_controls(read, exp: Experiment) -> dict:
    """Every memory control holds its approved value, and every cpu.max is unlimited (read-only)."""
    c = {f"{p}={v}": (read(p) or "").strip() == v for _, p, v in memory_plan(exp)}
    for d in LAB_DIRS:
        c[f"{d}/cpu.max=max"] = (read(f"{d}/cpu.max") or "").strip() == C.CPU_MAX_UNLIMITED
    return {"ok": all(c.values()), "checks": c}


class Host:
    """The single R2-F mutation site. Ordering is part of the guard: memory controls only before any spawn; spawns only
    after verify(); one SIGUSR1 to the logged target pid only while it is in the target leaf."""

    _log = C.Host._log

    def __init__(self, exp: Experiment, oplog: str, sysr=None, run_dir: Optional[str] = None):
        self.exp, self.oplog, self.sys = exp, oplog, sysr or Sys()
        self.state = {"controls_verified": False, "spawned": False, "target_spawned": False, "run_dir": run_dir,
                      "target_pid": None, "signalled": False}

    def _lop(self, op):
        return [op[0], op[1]] if op[0] != "scratch" else [op[0], op[1], op[2]]

    def apply(self, op, stdout=None, stderr=None):
        if op[0] == "mem":
            raise R2FRefused("memory controls are written only through mem_write (read-before, read-after)")
        check_op(op, self.exp, self.state)
        self._log(phase="intent", op=self._lop(op))
        try:
            res = self._do(op, stdout, stderr)
        except OSError as exc:
            self._log(phase="result", op=self._lop(op), ok=False, err=str(exc))
            raise
        self._log(phase="result", op=self._lop(op), ok=True, pid=getattr(res, "pid", None))
        if op[0] == "spawn":
            self.state["spawned"] = True
            self.state["target_spawned"] |= op[1] == "target"
        if op[0] == "signal":
            self.state["signalled"] = True
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
        elif kind == "scratch":
            scratch_do(op[1], op[2])
        elif kind == "spawn":
            return subprocess.Popen(list(op[2]), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, shell=False,
                                    start_new_session=True)
        elif kind == "signal":
            if f"{op[1]}" not in (self.sys.read(f"{TARGET_DIR}/cgroup.procs") or "").split():
                raise OSError(f"pid {op[1]} is not in the target leaf")
            os.kill(op[1], signal.SIGUSR1)
        elif kind == "kill":
            if lab_member(self.sys, op[1]):
                os.kill(op[1], signal.SIGKILL)
        return None

    def mem_write(self, path, value):
        check_op(("mem", path, value), self.exp, self.state)

        def write(p, v):
            with open(p, "w") as fh:
                fh.write(v)
        return mem_write(path, value, self.sys.read, write, self._log)

    def verify(self):
        v = verify_controls(self.sys.read, self.exp)
        self.state["controls_verified"] = v["ok"]
        self._log(phase="result", op=["verify_controls", LAB_DIR], ok=v["ok"])
        return v


def _no_symlink_chain(path: str) -> bool:
    """Every component from /var/tmp down is a real directory/file, never a symlink, and resolves to itself."""
    p = Path(path)
    for q in [p] + [x for x in p.parents if str(x).startswith(SCRATCH_PARENT)]:
        if q.is_symlink():
            return False
    return os.path.realpath(path) == path


def scratch_do(action: str, path: str) -> None:
    if action in ("mkdir_base", "mkdir"):
        os.mkdir(path, 0o755)
        if not _no_symlink_chain(path):
            raise OSError(f"{path} is not a plain directory")
        if action == "mkdir":
            os.chown(path, C.LAB_UID, C.LAB_GID)
    elif action == "unlink":
        if not _no_symlink_chain(path) or not os.path.isfile(path):
            raise OSError(f"{path} is not a plain file")
        os.unlink(path)
    else:
        if not _no_symlink_chain(path):
            raise OSError(f"{path} is not a plain directory")
        os.rmdir(path)


# ------------------------------------------------------------------------------------------ read-only host
class Sys(E.Sys):
    """R2-E's read-only view (R2-C reads + lab inspection) plus a filesystem-type read. No write path."""

    def _check(self, path):
        s = str(path)
        if (s == SCRATCH_BASE or s.startswith(SCRATCH_BASE + "/")) and "/../" not in s and "\x00" not in s:
            return                                                   # read-only view of the R2-F scratch path only
        super()._check(path)

    def fstype(self, path) -> Optional[str]:
        if path not in (SCRATCH_PARENT, "/"):
            raise R2FRefused(f"fstype read not approved: {path!r}")
        best, fs = "", None
        for line in (self.read("/proc/self/mounts") or "").splitlines():
            p = line.split()
            if len(p) >= 3 and (path == p[1] or path.startswith(p[1].rstrip("/") + "/")) and len(p[1]) > len(best):
                best, fs = p[1], p[2]
        return fs


def host_snapshot(sysr, require_bpf=True) -> dict:
    snap = E.host_snapshot(sysr, require_bpf)
    snap["vm"] = {s: (sysr.read(f"/proc/sys/{s}") or "").strip() for s in VM_SYSCTLS}
    snap["scratch_present"] = sysr.exists(SCRATCH_BASE)
    snap["r2f_lab_present"] = sysr.exists(LAB_DIR)
    return snap


def compare_host(base: dict, other: dict, require_bpf=True) -> dict:
    """R2-E's comparison (R2-C exact equality + host RPS + no lab netns/interface) plus vm.* identical, no R2-F
    scratch directory and no R2-F lab cgroup."""
    r = E.compare_host(base, other, require_bpf)
    r["vm_sysctls_identical"] = base.get("vm") == other.get("vm") and bool(base.get("vm"))
    r["no_scratch"] = other.get("scratch_present") is False
    r["no_r2f_lab"] = other.get("r2f_lab_present") is False
    for k in ("vm_sysctls_identical", "no_scratch", "no_r2f_lab"):
        if not r[k]:
            r["failed"].append(k)
    r["ok"] = not r["failed"]
    return r


def meminfo(text) -> Dict[str, int]:
    out = {}
    for line in (text or "").splitlines():
        p = line.replace(":", " ").split()
        if len(p) >= 2 and p[1].isdigit():
            out[p[0]] = int(p[1]) * (1024 if len(p) > 2 and p[2] == "kB" else 1)
    return out


def root_controllers_ok(text) -> bool:
    """REQUIRED_ROOT_CONTROLLERS is a subset of the root's cgroup.subtree_control (pure; reads nothing itself).
    Unreadable (None / not a string), empty, multi-line, malformed or duplicated controller names fail."""
    if not isinstance(text, str) or "\n" in text.strip():
        return False
    names = text.split()
    if not names or len(set(names)) != len(names) or not all(CONTROLLER_NAME.fullmatch(n) for n in names):
        return False
    return REQUIRED_ROOT_CONTROLLERS <= set(names)


def preflight(sysr) -> dict:
    c = {}
    c["root_cpuset_0_23"] = C.parse_cpulist(sysr.read(f"{CG_ROOT}/cpuset.cpus.effective")) == C.HOST_CPUS
    c["root_subtree_has_r2f_controllers"] = root_controllers_ok(sysr.read(f"{CG_ROOT}/cgroup.subtree_control"))
    c["no_sentinel_cgroup"] = not C.sentinel_cgroups(sysr)
    c["no_lab_process"] = not lab_pids(sysr) and not C.lab_pids(sysr)
    c["no_scratch_leftover"] = not sysr.exists(SCRATCH_BASE)
    c["scratch_parent_ext4"] = sysr.fstype(SCRATCH_PARENT) == "ext4"
    c["scratch_parent_not_symlink"] = os.path.realpath(SCRATCH_PARENT) == SCRATCH_PARENT
    mi = meminfo(sysr.read("/proc/meminfo"))
    c["mem_available_ge_4GiB"] = mi.get("MemAvailable", 0) >= MEM_AVAILABLE_MIN_BYTES
    c["page_size_4096"] = os.sysconf("SC_PAGE_SIZE") == PAGE
    c["memory_swap_accounting"] = sysr.exists(f"{CG_ROOT}/user.slice/memory.swap.max")
    c["memory_psi_per_cgroup"] = sysr.exists(f"{CG_ROOT}/user.slice/memory.pressure")
    c["vmstat_oom_kill_readable"] = "oom_kill" in C.kv(sysr.read("/proc/vmstat"))
    online = C.parse_cpulist(sysr.read("/sys/devices/system/cpu/online"))
    c["cpus_online"] = EXPERIMENT_CPUS | set(SUPPORT_CPUS) <= online
    c["cpu18_no_smt"] = C.parse_cpulist(sysr.read(f"/sys/devices/system/cpu/cpu{TARGET_CPU}/topology/"
                                                  "thread_siblings_list")) == {TARGET_CPU}
    eff = sysr.read(f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list")
    c["nic_irq_off_cpu18"] = eff is not None and not C.parse_cpulist(eff) & EXPERIMENT_CPUS
    c["protected_interfaces_present"] = all(sysr.exists(f"/sys/class/net/{p}") for p in PROTECTED)
    c["cgroup_kill_supported"] = sysr.exists(f"{CG_ROOT}/init.scope/cgroup.kill")
    c["lab_uid_exists"] = sysr.uid_name(C.LAB_UID) is not None
    for t in ("/usr/bin/unshare", "/usr/bin/setpriv", "/usr/bin/timeout", "/usr/bin/taskset", C.PYTHON, C.LOADER,
              C.BPFTOOL, TARGET_SCRIPT):
        c[f"tool:{t}"] = sysr.tool(t) or (t == TARGET_SCRIPT and os.path.isfile(t))
    return {"ok": all(c.values()), "checks": c}


def verify_cgroups(sysr, exp: Experiment) -> dict:
    r = lambda d, f: sysr.read(f"{d}/{f}")
    c = {"parent_subtree_control": set((r(LAB_DIR, "cgroup.subtree_control") or "").split()) == set(CONTROLLERS),
         "parent_cpus": C.parse_cpulist(r(LAB_DIR, "cpuset.cpus.effective")) == {TARGET_CPU}}
    for name, d in (("parent", LAB_DIR),) + LEAVES:
        procs = r(d, "cgroup.procs")
        c[f"{name}_empty"] = procs is not None and procs.strip() == ""
        if name != "parent":
            c[f"{name}_cpus"] = C.parse_cpulist(r(d, "cpuset.cpus.effective")) == {TARGET_CPU}
            c[f"{name}_controllers"] = set(CONTROLLERS) <= set((r(d, "cgroup.controllers") or "").split())
    c["contender_weight"] = (r(CONTENDER_DIR, "cpu.weight") or "").strip() == str(exp.contender_weight)
    return {"ok": all(c.values()), "checks": c}


# ------------------------------------------------------------------------------------------ ground-truth sampling
LEAF_FILES = ("cpu.max", "cpuset.cpus.effective", "cpu.stat", "cpu.pressure", "memory.current", "memory.high",
              "memory.max", "memory.swap.max", "memory.swap.current", "memory.events", "memory.events.local",
              "memory.stat", "memory.pressure", "cgroup.procs")


def gt_sample(sysr, mono: float, tag: str, target_pid: Optional[int], ebpf_line=None) -> dict:
    """One raw ground-truth observation: every file text the predicates need, nothing derived."""
    rd = sysr.read
    leaves = {name: {f: rd(f"{d}/{f}") for f in LEAF_FILES} for name, d in (("parent", LAB_DIR),) + LEAVES}
    pids = set()
    for name, _ in LEAVES:
        pids |= {int(p) for p in (leaves[name]["cgroup.procs"] or "").split()}
    pids |= set(E.cpu18_kthread_pids(sysr))
    tasks = {str(p): {"stat": rd(f"/proc/{p}/stat"), "schedstat": rd(f"/proc/{p}/schedstat")} for p in sorted(pids)}
    return {
        "mono": mono, "tag": tag,
        "raw": {"stat": rd("/proc/stat"), "schedstat": rd("/proc/schedstat"), "softirqs": rd("/proc/softirqs"),
                "meminfo": rd("/proc/meminfo"), "vmstat": rd("/proc/vmstat"), "psi_cpu": rd("/proc/pressure/cpu"),
                "psi_memory": rd("/proc/pressure/memory"), "psi_io": rd("/proc/pressure/io"),
                "nic_irq_eff": rd(f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list")},
        "slices": {s: {k: rd(f"{CG_ROOT}/{s}/{k}.pressure") for k in ("cpu", "memory", "io")} for s in C.SLICES},
        "leaves": leaves, "tasks": tasks,
        "target_netns": None if target_pid is None else {"dev": rd(f"/proc/{target_pid}/net/dev"),
                                                         "snmp": rd(f"/proc/{target_pid}/net/snmp")},
        "ebpf_line": ebpf_line,
    }


def task_majflt(stat_text) -> Optional[int]:
    """/proc/<pid>/stat field 12 (majflt)."""
    if not stat_text or ")" not in stat_text:
        return None
    rest = stat_text.rsplit(")", 1)[1].split()
    return int(rest[9]) if len(rest) > 9 else None


def parse_obs(t: dict) -> dict:
    """Raw observation -> parsed view (pure); the R2-C-shaped keys let R2-C host-level checks apply unchanged."""
    raw, lv = t["raw"], t["leaves"]
    leaves = {}
    for name, x in lv.items():
        procs = x["cgroup.procs"]
        num = lambda f: (lambda s: int(s) if s.isdigit() else s)((x[f] or "").strip()) if x[f] is not None else None
        leaves[name] = {"cpu_max": (x["cpu.max"] or "").strip() or None,
                        "cpus_eff": (x["cpuset.cpus.effective"] or "").strip(),
                        "cpu_stat": C.kv(x["cpu.stat"]) or None, "cpu_pressure": C.psi(x["cpu.pressure"]) or None,
                        "mem_current": num("memory.current"), "mem_high": (x["memory.high"] or "").strip() or None,
                        "mem_max": (x["memory.max"] or "").strip() or None,
                        "swap_max": (x["memory.swap.max"] or "").strip() or None, "swap_current": num("memory.swap.current"),
                        "mem_events": C.kv(x["memory.events"]) or None, "mem_stat": C.kv(x["memory.stat"]) or None,
                        "mem_pressure": C.psi(x["memory.pressure"]) or None,
                        "procs": None if procs is None else sorted(int(p) for p in procs.split())}
    tasks = {int(p): {"stat": E.task_stat(v["stat"]), "schedstat": E.task_schedstat(v["schedstat"]),
                      "majflt": task_majflt(v["stat"])} for p, v in t["tasks"].items()}
    vm = C.kv(raw["vmstat"])
    tn = t.get("target_netns")
    sl = t["slices"]
    return {"mono": t["mono"], "tag": t["tag"], "stat": C.proc_stat_cpus(raw["stat"]),
            "rq_cpu_time": C.schedstat_rq_cpu_time(raw["schedstat"]), "meminfo": meminfo(raw["meminfo"]),
            "vm": vm, "vmstat": {k: v for k, v in vm.items() if k in ("pswpin", "pswpout")} or None,
            "leaves": leaves, "tasks": tasks,
            "nic_irq_eff": raw["nic_irq_eff"].strip() if raw["nic_irq_eff"] is not None else None,
            "psi_cpu": C.psi(raw["psi_cpu"]) or None, "psi_memory": C.psi(raw["psi_memory"]) or None,
            "psi_io": C.psi(raw["psi_io"]) or None,
            "slices": {s: C.psi(v["cpu"]) or None for s, v in sl.items()},
            "slices_mem": {s: C.psi(v["memory"]) or None for s, v in sl.items()},
            "slices_io": {s: C.psi(v["io"]) or None for s, v in sl.items()},
            "netns": None if tn is None else C.netns_counters(tn["dev"], tn["snmp"]),
            "ebpf_line": t.get("ebpf_line")}


# ------------------------------------------------------------------------------------------ predicates (pure)
def _d(obs, a, b, get):
    return C._d(obs, a, b, get)


def _secs(obs, a, b):
    return obs[b]["mono"] - obs[a]["mono"]


def _leaf(o, name, key):
    return o["leaves"][name][key]


def _mstat(name, key):
    return lambda o: (o["leaves"][name]["mem_stat"] or {}).get(key)


def evaluate_gp(obs, expected, in_w) -> dict:
    """GP: target (and N2 contender in W) in its leaf, on CPU 18, at every observation; nothing in the parent."""
    viol, unknown = [], 0
    for k, (o, want) in enumerate(zip(obs, expected)):
        lv = o["leaves"]
        for name, _ in LEAVES:
            if lv[name]["procs"] is None:
                unknown += 1
                continue
            if C.parse_cpulist(lv[name]["cpus_eff"]) != {TARGET_CPU}:
                viol.append(f"obs {k}: {name} cpuset {lv[name]['cpus_eff']!r}")
            if lv[name]["procs"] != sorted(want.get(name, [])):
                viol.append(f"obs {k}: {name} procs {lv[name]['procs']} != expected {sorted(want.get(name, []))}")
            for pid in lv[name]["procs"]:
                st = (o["tasks"].get(pid) or {}).get("stat")
                if st is None:
                    unknown += 1
                elif st["processor"] != TARGET_CPU:
                    viol.append(f"obs {k}: {name} pid {pid} on CPU {st['processor']}")
        if lv["parent"]["procs"] != []:
            viol.append(f"obs {k}: process in the lab parent")
        if not in_w[k] and lv["contender"]["procs"]:
            viol.append(f"obs {k}: contender outside W")
    return {"ok": False if viol else (None if unknown else True), "violations": viol[:20], "n_violations": len(viol),
            "unknown": unknown}


def evaluate_gc(obs, exp: Experiment, i_w0: int, signal_rec: Optional[dict], target_out: Optional[dict]) -> dict:
    """GC: approved memory controls and unlimited cpu.max at every observation; exactly one SIGUSR1 between
    observations i_w0 and i_w0+1 for expanding experiments, none otherwise; the target expanded exactly once."""
    want = {("parent", "mem_max"): str(PARENT_MAX), ("parent", "swap_max"): "0", ("target", "swap_max"): "0",
            ("target", "mem_max"): str(exp.high + TARGET_MAX_HEADROOM), ("target", "mem_high"): str(exp.high),
            ("contender", "swap_max"): "0", ("contender", "mem_max"): str(CONTENDER_MAX)}
    viol = []
    for k, o in enumerate(obs):
        for (name, key), v in want.items():
            if o["leaves"][name][key] != v:
                viol.append(f"obs {k}: {name} {key} {o['leaves'][name][key]!r} != {v}")
        for name in ("parent", "target", "contender"):
            if o["leaves"][name]["cpu_max"] != C.CPU_MAX_UNLIMITED:
                viol.append(f"obs {k}: {name} cpu.max {o['leaves'][name]['cpu_max']!r}")
    if exp.expand:
        if not signal_rec or not (obs[i_w0]["mono"] < signal_rec["t0"] and signal_rec["t1"] < obs[i_w0 + 1]["mono"]):
            viol.append(f"SIGUSR1 {signal_rec} not between observations {i_w0} and {i_w0 + 1}")
    elif signal_rec:
        viol.append("SIGUSR1 sent in a non-expanding experiment")
    if target_out is None:
        return {"ok": None if not viol else False, "violations": viol[:20], "status": "target output missing"}
    want_n = 1 if exp.expand else 0
    if target_out.get("sigusr1_count") != want_n or (target_out.get("expanded_at_cycle") is None) == exp.expand:
        viol.append(f"target expanded {target_out.get('sigusr1_count')} times (cycle "
                    f"{target_out.get('expanded_at_cycle')}), expected {want_n}")
    return {"ok": not viol, "violations": viol[:20], "n_violations": len(viol)}


def evaluate_gd(obs, exp: Experiment, i_w0: int, target_out: Optional[dict]) -> dict:
    """GD: demand vs capacity from the target's own record and the page cache it was charged with."""
    if target_out is None or obs[i_w0]["leaves"]["target"]["mem_stat"] is None:
        return {"ok": None, "status": "UNAVAILABLE"}
    anon = obs[i_w0]["leaves"]["target"]["mem_stat"].get("anon", 0)
    cur_b = obs[i_w0]["leaves"]["target"]["mem_current"]
    sw = target_out.get("scan_w")
    c = {"file_is_1GiB": target_out.get("file_size") == FILE_BYTES == target_out.get("file_bytes"),
         "scan_ranges_as_registered": target_out.get("scan_b") == SCAN_B and sw == scan_w(exp),
         "b_range_charged_to_target": isinstance(cur_b, int) and cur_b >= SCAN_B}
    if exp.kind in PRESSURE:
        c["demand_exceeds_high"] = sw > exp.high
    else:
        c["demand_fits_under_high"] = sw + anon < exp.high
    return {"ok": all(c.values()), "checks": c, "anon_bytes_b": anon, "memory_current_end_b": cur_b}


def _rate(obs, a, b, get):
    d, s = _d(obs, a, b, get), _secs(obs, a, b)
    return None if d is None or s <= 0 or d < 0 else d / s


def evaluate_gm(obs, exp: Experiment, i_b0, i_w0, i_w1, target_pid) -> dict:
    """GM: reclaim / refault in the target cgroup (raw memory.stat) and the target's own major faults (task stat)."""
    rf = _mstat("target", "workingset_refault_file")
    rb, rw = _rate(obs, i_b0, i_w0, rf), _rate(obs, i_w0, i_w1, rf)
    scan = _d(obs, i_w0, i_w1, _mstat("target", "pgscan"))
    mj = lambda o: (o["tasks"].get(target_pid) or {}).get("majflt")
    mw = _rate(obs, i_w0, i_w1, mj)
    r = {"refault_rate_b": rb, "refault_rate_w": rw, "pgscan_w": scan, "majflt_rate_w": mw}
    if None in (rb, rw, scan, mw):
        r.update(ok=None, status="UNAVAILABLE")
        return r
    if exp.kind in PRESSURE:
        c = {"refault_w_ge_REFAULT_MIN": rw >= REFAULT_MIN, "refault_w_rise": rw >= R_STRONG * max(rb, FLOOR),
             "reclaim_w": scan > 0, "majflt_w_ge_REFAULT_MIN": mw >= REFAULT_MIN}
    else:
        c = {"refault_w_below_REFAULT_MIN": rw < REFAULT_MIN}
    r.update(checks=c, ok=all(c.values()), status="EVALUATED")
    return r


def evaluate_gi(target_out, obs, i_b0, i_w0, i_w1, exp: Experiment) -> dict:
    """GI (EXPERIMENTAL HEURISTIC; required for M2, recorded otherwise): cycle median W >= 1.5 x B and more missed
    deadlines in W than in B (the target's own record)."""
    lb = C.lateness_stats(target_out, int(obs[i_b0]["mono"] * 1e9), int(obs[i_w0]["mono"] * 1e9))
    lw = C.lateness_stats(target_out, int(obs[i_w0]["mono"] * 1e9), int(obs[i_w1]["mono"] * 1e9))
    if lb is None or lw is None:
        return {"applies": exp.kind == "M2", "ok": None, "status": "UNAVAILABLE"}
    ok = lw["cycle_median_ns"] >= G4_RATIO_MIN * lb["cycle_median_ns"] and lw["missed"] > lb["missed"]
    return {"applies": exp.kind == "M2", "ok": ok, "b": lb, "w": lw, "threshold": G4_RATIO_MIN}


def evaluate_gl(obs) -> dict:
    """GL: pressure stays local: no global reclaim (kswapd), no host OOM, no lab OOM, the lab never swaps."""
    ks = _d(obs, 0, len(obs) - 1, lambda o: o["vm"].get("pgscan_kswapd"))
    hoom = _d(obs, 0, len(obs) - 1, lambda o: o["vm"].get("oom_kill"))
    lab = {}
    for name in ("parent", "target", "contender"):
        for k in ("oom", "oom_kill"):
            lab[f"{name}.{k}"] = _d(obs, 0, len(obs) - 1, lambda o, n=name, k=k: (o["leaves"][n]["mem_events"] or {}).get(k))
    swaps = [o["leaves"][n]["swap_current"] for o in obs for n in ("parent", "target", "contender")]
    if ks is None or hoom is None or any(v is None for v in lab.values()) or any(not isinstance(v, int) for v in swaps):
        return {"ok": None, "status": "UNAVAILABLE"}
    c = {"no_kswapd_reclaim": ks == 0, "no_host_oom": hoom == 0, "no_lab_oom": all(v == 0 for v in lab.values()),
         "lab_never_swaps": all(v == 0 for v in swaps)}
    return {"ok": all(c.values()), "checks": c, "pgscan_kswapd_delta": ks, "host_oom_kill_delta": hoom,
            "lab_oom": lab, "host_oom": hoom > 0}


def evaluate_gcpu(obs, exp: Experiment, i_b0, i_w0, i_w1, target_pid) -> dict:
    """GCPU: no CPU contention (E0/M/N1): foreign busy on CPU 18 <= 0.05 core, target run-delay rate W - B < RDX_MIN,
    CPU 18 idle in W >= G3_IDLE_MAX. N2: the contender ran on CPU 18 and saturated it (R2-C G2/G3)."""
    def foreign(a, z):
        rq = C._rq(obs, a, z)
        tu = _d(obs, a, z, lambda o: (o["leaves"]["target"]["cpu_stat"] or {}).get("usage_usec"))
        cu = _d(obs, a, z, lambda o: (o["leaves"]["contender"]["cpu_stat"] or {}).get("usage_usec")) if exp.contender \
            else 0
        kt = E._kthread_runtime(obs, a, z)
        s = _secs(obs, a, z)
        if None in (rq, tu, cu, kt) or s <= 0:
            return None
        return (rq / 1e9 - tu / 1e6 - cu / 1e6 - kt / 1e9) / s
    fb, fw = foreign(i_b0, i_w0), foreign(i_w0, i_w1)
    rd = lambda o: ((o["tasks"].get(target_pid) or {}).get("schedstat") or {}).get("run_delay_ns")
    rb, rw = _rate(obs, i_b0, i_w0, rd), _rate(obs, i_w0, i_w1, rd)
    rq_w, sw = C._rq(obs, i_w0, i_w1), _secs(obs, i_w0, i_w1)
    idle = None if rq_w is None or sw <= 0 else 1 - rq_w / (sw * 1e9)
    r = {"foreign_cores_b": fb, "foreign_cores_w": fw, "run_delay_rate_b": None if rb is None else rb / 1e9,
         "run_delay_rate_w": None if rw is None else rw / 1e9, "cpu18_idle_w": idle}
    if None in (fb, fw, rb, rw, idle):
        r.update(ok=None, status="UNAVAILABLE")
        return r
    c = {"foreign_b": fb <= G6_MAX, "foreign_w": fw <= G6_MAX}
    if exp.contender:
        cu = _rate(obs, i_w0, i_w1, lambda o: (o["leaves"]["contender"]["cpu_stat"] or {}).get("usage_usec"))
        c.update(contender_ran=cu is not None and cu / 1e6 >= C.G2_CONTENDER_MIN_CORES, cpu18_saturated=idle <= G3_IDLE_MAX)
    else:
        c.update(no_run_delay_rise=(rw - rb) / 1e9 < RDX_MIN, cpu18_not_saturated=idle >= G3_IDLE_MAX)
    r.update(checks=c, ok=all(c.values()), status="EVALUATED")
    return r


def evaluate_gt(obs) -> dict:
    quota = all(o["leaves"][n]["cpu_max"] == C.CPU_MAX_UNLIMITED for o in obs for n in ("parent", "target", "contender"))
    thr = {f"{n}.{k}": _d(obs, 0, len(obs) - 1, lambda o, n=n, k=k: (o["leaves"][n]["cpu_stat"] or {}).get(k))
           for n in ("target", "contender") for k in ("nr_throttled", "throttled_usec")}
    if any(v is None for v in thr.values()):
        return {"ok": None if quota else False, "status": "UNAVAILABLE", "deltas": thr}
    return {"ok": quota and all(v == 0 for v in thr.values()), "cpu_max_unlimited": quota, "deltas": thr}


def evaluate_gn(obs, i_b0, i_w0, i_w1, meta) -> dict:
    """GN: target private netns quiet; NET_RX on CPU 18 does not rise (R2-E rule); BLOCK softirq recorded."""
    nets = [o["netns"] for o in obs]
    quiet = None if any(n is None for n in nets) else all(n == nets[0] for n in nets)
    r = E.softirq_rates(obs, i_b0, i_w0, i_w1, meta, TARGET_CPU)
    blk = [E._sirq(obs, k, meta, TARGET_CPU, "BLOCK") for k in (i_w0, i_w1)]
    res = {"netns_quiet": quiet, "netrx18": r, "block18_ns_w": None if None in blk else blk[1] - blk[0]}
    if quiet is None or r["netrx_b"] is None or r["netrx_w"] is None:
        res.update(ok=None, status="UNAVAILABLE")
        return res
    res["ok"] = quiet and r["netrx_w"] < SI_RATIO_MIN * max(r["netrx_b"], FLOOR)
    return res


def evaluate_gh(obs, i_b0, i_w0, i_w1) -> dict:
    """GH host safety (Condition 1 thresholds) + R2-C host-level checks (host util in B, host/slice cpu PSI)."""
    avail = [o["meminfo"].get("MemAvailable") for o in obs]
    sw, sb = _secs(obs, i_w0, i_w1), _secs(obs, i_b0, i_w0)

    def swap(o):
        v = o["vmstat"] or {}
        return v["pswpin"] + v["pswpout"] if "pswpin" in v and "pswpout" in v else None
    si = _d(obs, i_w0, i_w1, swap)
    rises = {}
    for kind, key in (("memory", "slices_mem"), ("io", "slices_io")):
        for s in C.SLICES:
            db = _d(obs, i_b0, i_w0, lambda o, s=s, key=key: (o[key][s] or {}).get("some_total"))
            dw = _d(obs, i_w0, i_w1, lambda o, s=s, key=key: (o[key][s] or {}).get("some_total"))
            rises[f"{s}.{kind}"] = None if db is None or dw is None or sb <= 0 or sw <= 0 else \
                dw / (sw * 1e6) - db / (sb * 1e6)
    c = {"mem_available": None if any(a is None for a in avail) else min(avail) >= MEM_AVAILABLE_MIN_BYTES,
         "swap_io": None if si is None or sw <= 0 else si / sw <= SWAP_MAX_PAGES_PER_S,
         "slice_psi": None if any(v is None for v in rises.values()) else all(
             v <= (SLICE_MEM_PSI_RISE_MAX if k.endswith("memory") else SLICE_IO_PSI_RISE_MAX) for k, v in rises.items())}
    host_level = C.host_level_aborts(obs, i_b0, i_w0, i_w1)
    ok = None if any(v is None for v in c.values()) else all(c.values()) and not host_level
    return {"ok": ok, "checks": c, "mem_available_min": None if None in avail else min(avail),
            "swap_pages_per_s_w": None if si is None or sw <= 0 else si / sw, "slice_rises": rises,
            "host_level_aborts": host_level}


def ground_truth_inputs(R: dict, target_out: Optional[dict]) -> dict:
    return {"label": R["label"], "obs": R["observations"], "expected": R["expected"], "in_w": R["in_w"],
            "window": R["window"]["obs_index"], "ebpf_meta": R["ebpf_meta_line"], "signal": R.get("signal"),
            "target_pid": R["target"]["pids"][0], "target_out": target_out}


SAFETY = ("GP", "GC", "GT", "GL", "GH", "GN")


def evaluate(inp: dict) -> dict:
    """R2-F ground truth from saved raw inputs only (pure). Never derived from MP.R1 or any M2 output."""
    exp = experiment_of(inp["label"])
    obs = [parse_obs(t) for t in inp["obs"]]
    i_b0, i_w0, i_w1 = inp["window"]
    tp, to = int(inp["target_pid"]), inp.get("target_out")
    G = {"GP": evaluate_gp(obs, inp["expected"], inp["in_w"]), "GC": evaluate_gc(obs, exp, i_w0, inp.get("signal"), to),
         "GD": evaluate_gd(obs, exp, i_w0, to), "GM": evaluate_gm(obs, exp, i_b0, i_w0, i_w1, tp),
         "GI": evaluate_gi(to, obs, i_b0, i_w0, i_w1, exp), "GL": evaluate_gl(obs),
         "GCPU": evaluate_gcpu(obs, exp, i_b0, i_w0, i_w1, tp), "GT": evaluate_gt(obs),
         "GN": evaluate_gn(obs, i_b0, i_w0, i_w1, inp["ebpf_meta"]), "GH": evaluate_gh(obs, i_b0, i_w0, i_w1)}
    req = SAFETY + ("GD", "GM", "GCPU") + (("GI",) if exp.kind == "M2" else ())
    G["required"] = list(req)
    G["computable"] = all(G[g]["ok"] is not None for g in req)
    ok = G["computable"] and all(G[g]["ok"] for g in req)
    G["established"] = {"memory_pressure": ok if exp.kind in PRESSURE else None,
                        "memory_pressure_absent": ok if exp.kind in ("E0", "N1", "N2") else None,
                        "cpu_contention_present": (G["GCPU"]["ok"] if exp.contender else None)}
    G["ok"] = ok
    G["host_oom"] = bool(G["GL"].get("host_oom"))
    return G


def ground_truth_aborts(G: dict) -> List[str]:
    names = {"GP": "placement", "GC": "memory/cpu controls", "GD": "demand vs capacity", "GM": "reclaim/refault",
             "GI": "application impact", "GL": "OOM / swap / global reclaim", "GCPU": "CPU contention exclusion",
             "GT": "throttling exclusion", "GN": "network/softirq exclusion", "GH": "host safety"}
    a = []
    for g in G["required"]:
        if G[g]["ok"] is None:
            a.append(f"ground truth unavailable: {g} ({G[g].get('status')})")
        elif G[g]["ok"] is False:
            detail = G[g].get("violations") or G[g].get("checks") or {k: v for k, v in G[g].items() if k != "ok"}
            a.append(f"{names[g]} ({g}): {str(detail)[:300]}")
    if G.get("host_oom"):
        a.append("HOST OOM: stop the campaign")
    return a


# ------------------------------------------------------------------------------------------ metric gate
REQUIRED = (("psi.mem.some.target", "cg", "RATE", True), ("mem.reclaim.target", "cg", "RATE", True),
            ("mem.refault.target", "cg", "RATE", True), ("mem.majfault.target", "cg", "RATE", True),
            ("mem.events.oom_kill", "cg", "DELTA", False), ("cpu.util.cpuset", "cpuset", "MEAN", True),
            ("cpu.steal.cpuset", "cpuset", "MEAN", True), ("sched.run_delay_excess.target", "cg", "RATE", True),
            ("throttle.quota_limited", "cg", "GAUGE", False))
RECORDED = ("mem.events.high", "psi.mem.full.target", "mem.util.target", "mem.swap.target", "mem.swap_io.host",
            "mem.available.host", "psi.mem.some.host", "mem.reclaim_direct.host", "sched.latency_hist.target")


def metric_gate(snapshot, cov_min: float, n_base_min: float) -> dict:
    cg = f"cgroup:{TARGET_CGROUP_PATH}"
    ms = snapshot.measurements
    find = lambda f, sc, agg=None: [m for m in ms if m.feature_id == f and m.scope == (cg if sc == "cg" else sc)
                                    and (agg is None or m.aggregation.value == agg)]
    c, aborts = {}, []
    c["target"] = snapshot.target.cgroup_path == TARGET_CGROUP_PATH and snapshot.target.cpuset == str(TARGET_CPU)
    if not c["target"]:
        aborts.append("snapshot target is not the R2-F target")
    for f, sc, agg, base in REQUIRED:
        found = find(f, sc, agg)
        key, bad = f"{f}[{agg}]", []
        if len(found) != 1:
            bad.append("not present exactly once")
        else:
            m = found[0]
            if m.quality.value not in ("OK", "PARTIAL") or m.value is None:
                bad.append(f"quality {m.quality.value}")
            elif m.quality.value == "PARTIAL" and m.coverage < cov_min:
                bad.append(f"coverage {m.coverage}")
            if base and (m.baseline is None or not m.baseline.adequate or m.baseline.n < n_base_min):
                bad.append("baseline inadequate")
            if f == "throttle.quota_limited" and m.value != 0.0:
                bad.append(f"value {m.value} != 0.0")
        c[key] = not bad
        if bad:
            aborts.append(f"required metric {key} unusable: {', '.join(bad)}")
    tr = find("throttle.ratio", "cg")
    c["throttle_ratio_missing"] = len(tr) == 1 and tr[0].value is None and tr[0].quality.value == "MISSING"
    if not c["throttle_ratio_missing"]:
        aborts.append("throttle.ratio is not MISSING")
    net = [(m.feature_id, m.scope, m.value) for m in ms if m.feature_id.startswith(("net.", "tcp.")) and m.value]
    c["target_netns_quiet"] = not net
    if net:
        aborts.append(f"network activity in the target netns: {net}")
    c["gate_passed"] = snapshot.data_quality.gate_passed
    if not c["gate_passed"]:
        aborts.append("snapshot data-quality gate failed")
    rec = {f: [{"scope": m.scope, "aggregation": m.aggregation.value, "value": m.value, "quality": m.quality.value}
               for m in ms if m.feature_id == f] for f in RECORDED}
    return {"ok": not aborts, "checks": c, "aborts": aborts, "recorded": rec}


# ------------------------------------------------------------------------------------------ cleanup
def oplog_state(entries) -> dict:
    intents = [e for e in entries if e.get("phase") == "intent"]
    dirs = [e["op"][1] for e in intents if e["op"][0] == "mkdir"]
    pids = [e["pid"] for e in entries if e.get("phase") == "result" and e["op"][0] == "spawn" and e.get("pid")]
    sc = [(e["op"][1], e["op"][2]) for e in intents if e["op"][0] == "scratch"]
    run_dirs = [p for a, p in sc if a == "mkdir"]
    return {"dirs": [d for d in LAB_DIRS if d in dirs], "pids": pids, "run_dirs": run_dirs,
            "base_created": any(a == "mkdir_base" for a, _ in sc)}


def cleanup(host, sysr, entries, exp: Experiment, wait_s: float = 5.0, sleep=time.sleep, after_kill=None) -> dict:
    """Idempotent, from the op log, in the approved order (Condition 9):
    (1) kill target/contender; (2) verify termination; (3) verify memory controls (read-only); (4)+(5) after_kill():
    the driver closes its eBPF loader and waits for BPF release; (6) delete the scratch file and directories;
    (7) remove the cgroups; (8) the caller compares the host. Never touches what the run did not create."""
    st = oplog_state(entries)
    steps, errors, events = [], [], []

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

    for pid in st["pids"]:                                                              # (1)
        step(f"kill {pid}", lambda pid=pid: host.apply(("kill", pid)))
    ours = LAB_DIR in st["dirs"]
    deadline, killed = time.monotonic() + wait_s, False
    while True:
        if ours and sysr.exists(LAB_DIR) and (populated(LAB_DIR) or not killed):
            killed = step("cgroup.kill", lambda: host.apply(("write", f"{LAB_DIR}/cgroup.kill", "1"))) or killed
        wrappers = [p for p in st["pids"] if wrapper_alive(sysr, p)]
        if (not (ours and populated(LAB_DIR)) and not wrappers) or time.monotonic() >= deadline:
            break
        sleep(0.05)
    term = {"no_lab_process": not lab_pids(sysr), "no_wrapper": not wrappers}                # (2)
    events.append("terminated")
    if not all(term.values()):
        errors.append(f"termination not verified: {term}")
    ctl = verify_written(sysr.read, entries) if sysr.exists(LAB_DIR) else {"ok": None, "lab_absent": True}  # (3)
    events.append("controls_verified")
    if ctl["ok"] is False:
        errors.append(f"memory controls changed during the run: {[k for k, v in ctl['checks'].items() if not v]}")
    if after_kill is not None:                                                          # (4)+(5)
        step("stop eBPF loader + wait BPF release", after_kill)
    events.append("bpf_released")
    for d in st["run_dirs"]:                                                            # (6)
        f = f"{d}/{WS_NAME}"
        if sysr.exists(f):
            step(f"unlink {f}", lambda f=f: host.apply(("scratch", "unlink", f)))
        if sysr.exists(d):
            step(f"rmdir {d}", lambda d=d: host.apply(("scratch", "rmdir", d)))
    if st["base_created"] and sysr.exists(SCRATCH_BASE) and not (sysr.listdir(SCRATCH_BASE) or []):
        step(f"rmdir {SCRATCH_BASE}", lambda: host.apply(("scratch", "rmdir_base", SCRATCH_BASE)))
    events.append("scratch_deleted")
    for d in (CONTENDER_DIR, TARGET_DIR, LAB_DIR):                                      # (7)
        if d in st["dirs"] and sysr.exists(d):
            step(f"rmdir {d}", lambda d=d: host.apply(("rmdir", d)))
    events.append("cgroups_removed")
    v = cleanup_state(sysr, st["pids"])
    return {"ok": not errors and v["ok"], "steps": steps, "errors": errors, "verify": v, "termination": term,
            "controls_at_cleanup": ctl, "order": events}


def verify_written(read, entries) -> dict:
    """Cleanup step (3), read-only: every memory control this run wrote (logged result ok) still holds its value."""
    done = {e["op"][1]: e["value"] for e in entries if e.get("phase") == "result" and e["op"][0] == "mem" and e.get("ok")}
    c = {f"{p}={v}": (read(p) or "").strip() == v for p, v in done.items()}
    return {"ok": all(c.values()), "checks": c, "n_written": len(done)}


def cleanup_state(sysr, pids=()) -> dict:
    c = {"lab_cgroup_absent": not sysr.exists(LAB_DIR), "no_sentinel_cgroup": not C.sentinel_cgroups(sysr),
         "no_lab_process": not lab_pids(sysr), "no_wrapper_alive": not [p for p in pids if wrapper_alive(sysr, p)],
         "no_scratch": not sysr.exists(SCRATCH_BASE)}
    return {"ok": all(c.values()), "checks": c}


def restore_record(cleanup_rec: dict, host_compare: dict, bpf_release: dict) -> dict:
    """GR (pure): cleanup complete in the approved order, BPF released, scratch gone, host identical."""
    c = {"cleanup_ok": bool(cleanup_rec.get("ok")),
         "order": cleanup_rec.get("order") == ["terminated", "controls_verified", "bpf_released", "scratch_deleted",
                                               "cgroups_removed"],
         "bpf_released": bool((bpf_release or {}).get("released")), "host_identical": bool(host_compare.get("ok"))}
    return {"ok": all(c.values()), "checks": c}


# ------------------------------------------------------------------------------------------ simulated host
class SimHost:
    """In-memory Host + Sys for the dry-run and tests: cgroupfs rules, memory-control files (default 'max'), scratch
    files, processes, the ordering state, and an event trace (memory writes, spawns, signals, cleanup steps)."""

    def __init__(self, exp, fail_at=None, fail_mem=None, run_dir=None):
        self.exp, self.fail_at, self.fail_mem = exp, fail_at, fail_mem
        self.dirs, self.files, self.procs, self.alive, self.wrappers = set(), {}, {d: [] for d in LAB_DIRS}, set(), {}
        self.scratch, self.events, self.entries, self.n, self.next_pid = set(), [], [], 0, 60000
        self.state = {"controls_verified": False, "spawned": False, "target_spawned": False, "run_dir": run_dir,
                      "target_pid": None, "signalled": False}

    def _log(self, **kw):
        self.entries.append(kw)

    def _lop(self, op):
        return [op[0], op[1]] if op[0] != "scratch" else [op[0], op[1], op[2]]

    def apply(self, op, stdout=None, stderr=None):
        if op[0] == "mem":
            raise R2FRefused("memory controls are written only through mem_write (read-before, read-after)")
        check_op(op, self.exp, self.state)
        self._log(phase="intent", op=self._lop(op))
        self.n += 1
        if self.fail_at == self.n:
            self._log(phase="result", op=self._lop(op), ok=False, err="injected")
            raise OSError(f"injected failure at operation {self.n}: {op[0]}")
        res = self._do(op)
        self._log(phase="result", op=self._lop(op), ok=True, pid=getattr(res, "pid", None))
        if op[0] == "spawn":
            self.state["spawned"] = True
            self.state["target_spawned"] |= op[1] == "target"
        if op[0] == "signal":
            self.state["signalled"] = True
        return res

    def _do(self, op):
        kind = op[0]
        if kind == "mkdir":
            parent = op[1].rsplit("/", 1)[0]
            if op[1] in self.dirs or (parent != CG_ROOT and parent not in self.dirs):
                raise OSError("mkdir")
            self.dirs.add(op[1])
            for f in ("memory.max", "memory.high", "memory.swap.max"):
                self.files[f"{op[1]}/{f}"] = "max"
            self.files[f"{op[1]}/cpu.max"] = C.CPU_MAX_UNLIMITED
        elif kind == "rmdir":
            if self.procs.get(op[1]) or any(d.startswith(op[1] + "/") for d in self.dirs):
                raise OSError("busy")
            self.dirs.discard(op[1])
            self.events.append(("rmdir", op[1]))
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
        elif kind == "scratch":
            a, p = op[1], op[2]
            if a in ("mkdir_base", "mkdir"):
                if p in self.scratch:
                    raise OSError("exists")
                self.scratch.add(p)
            elif a == "unlink":
                self.scratch.discard(p)
                self.events.append(("unlink", p))
            else:
                if any(x.startswith(p + "/") for x in self.scratch):
                    raise OSError("not empty")
                self.scratch.discard(p)
                self.events.append(("scratch_rmdir", p))
        elif kind == "spawn":
            leaf = CONTENDER_DIR if op[1] == "contender" else TARGET_DIR
            if leaf not in self.dirs:
                raise OSError("leaf missing")
            pid, self.next_pid = self.next_pid, self.next_pid + 2
            self.procs[leaf] = self.procs.get(leaf, []) + [pid + 1]
            self.wrappers[pid] = pid + 1
            self.alive |= {pid, pid + 1}
            if op[1] == "target":
                self.state["target_pid"] = pid + 1
                self.scratch.add(f"{self.state['run_dir']}/{WS_NAME}")       # the target creates its file
            self.events.append(("spawn", op[1]))
            return type("P", (), {"pid": pid})()
        elif kind == "signal":
            if op[1] not in self.procs[TARGET_DIR]:
                raise OSError("not in target leaf")
            self.events.append(("signal", op[1]))
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

    def _mwrite(self, p, v):
        self.n += 1
        if self.fail_at == self.n or self.fail_mem == "write":
            raise OSError(f"injected memory write failure {p}")
        self.files[p] = "123" if self.fail_mem == "readback" else v
        self.events.append(("mem", p, v))

    def mem_write(self, path, value):
        check_op(("mem", path, value), self.exp, self.state)
        return mem_write(path, value, lambda p: self.files.get(p), self._mwrite, self._log)

    def verify(self):
        v = verify_controls(lambda p: self.files.get(p), self.exp)
        self.state["controls_verified"] = v["ok"]
        self.events.append(("verify", v["ok"]))
        return v

    # Sys
    def exists(self, path):
        return path in self.dirs or path in self.scratch

    def read(self, path):
        if path.endswith("/cgroup.events"):
            d = path.rsplit("/", 1)[0]
            return f"populated {int(any(self.procs.get(x) for x in LAB_DIRS if x.startswith(d)))}\n"
        if path.startswith("/proc/") and path.endswith("/cgroup"):
            pid = int(path.split("/")[2])
            if pid not in self.alive:
                return None
            return "0::/user.slice/driver\n" if pid in self.wrappers else f"0::/{LAB}/target\n"
        if path.startswith("/proc/") and path.endswith("/cmdline"):
            pid = int(path.split("/")[2])
            return "\0".join(WRAPPER + ["sh"]) + "\0" if pid in self.wrappers and pid in self.alive else None
        return self.files.get(path)

    def listdir(self, path):
        return sorted(x.rsplit("/", 1)[1] for x in self.scratch if x.rsplit("/", 1)[0] == path)

    def cgroup_dirs(self):
        return sorted(d[len(CG_ROOT) + 1:] for d in self.dirs)

    def pids(self):
        return sorted(self.alive)


SIM_TS = "20260101T000000Z"


def driver_steps(exp: Experiment, label: str) -> List[tuple]:
    """The driver's order: cgroups -> memory controls (verified writes) -> verify -> scratch -> target -> (signal |
    contender). Shared by the dry-run simulation and the tests."""
    run_dir = scratch_dir(SIM_TS, label)
    out = str(RESULTS / SIM_TS / label / "x.json")
    s = [("op", op) for op in cgroup_plan(exp)] + [("mem", op) for op in memory_plan(exp)] + [("verify", None)]
    s += [("op", ("scratch", "mkdir_base", SCRATCH_BASE)), ("op", ("scratch", "mkdir", run_dir)),
          ("op", ("spawn", "target", target_argv(exp, run_dir, out)))]
    if exp.expand:
        s.append(("signal", None))
    if exp.contender:
        s.append(("op", ("spawn", "contender", contender_argv(out))))
    return s


def simulate(exp: Experiment, label: str, fail_at=None, crash_after=None, fail_mem=None, fail_cleanup_at=None) -> dict:
    sim = SimHost(exp, fail_at=fail_at, fail_mem=fail_mem, run_dir=scratch_dir(SIM_TS, label))
    failed = None
    try:
        for k, (kind, x) in enumerate(driver_steps(exp, label)):
            if crash_after is not None and k >= crash_after:
                break
            if kind == "op":
                sim.apply(x)
            elif kind == "mem":
                sim.mem_write(x[1], x[2])
            elif kind == "verify":
                if not sim.verify()["ok"]:
                    raise MemAbort("controls not verified")
            else:
                sim.apply(("signal", sim.state["target_pid"]))
    except (OSError, MemAbort, R2FRefused) as exc:
        failed = str(exc)
    sim.fail_at = None if fail_cleanup_at is None else sim.n + fail_cleanup_at
    trace = []
    res = cleanup(sim, sim, list(sim.entries), exp, wait_s=0.0, sleep=lambda s: None,
                  after_kill=lambda: trace.append(len(sim.events)))
    ev = sim.events
    first = lambda pred: next((i for i, e in enumerate(ev) if pred(e)), None)
    mems = [i for i, e in enumerate(ev) if e[0] == "mem"]
    spawn = first(lambda e: e[0] == "spawn")
    ordering = spawn is None or (bool(mems) and max(mems) < spawn and any(e == ("verify", True) for e in ev[:spawn]))
    clean = not sim.dirs and not sim.alive and not sim.scratch
    ok = (res["ok"] and clean and ordering) if fail_cleanup_at is None else (ordering and (res["ok"] == clean or
                                                                                          not res["ok"]))
    return {"failed_at": failed, "cleanup_ok": res["ok"], "host_clean": clean, "ordering": ordering, "ok": bool(ok),
            "order": res["order"]}


def simulation_cases() -> dict:
    cases = []
    for kind, exp in EXPERIMENTS.items():
        label = "calibration" if kind == "CAL" else next(l for l in MATRIX if l.startswith(kind))
        n = len(driver_steps(exp, label))
        cases += [(kind, simulate(exp, label, fail_at=f)) for f in [None] + list(range(1, n + 3))]
        cases += [(kind, simulate(exp, label, crash_after=c)) for c in range(1, n + 1)]
        cases += [(kind, simulate(exp, label, fail_mem=m)) for m in ("write", "readback")]
        cases += [(kind, simulate(exp, label, fail_cleanup_at=c)) for c in range(1, 10)]
    bad = [(k, r) for k, r in cases if not r["ok"]]
    return {"cases": len(cases), "ok": not bad, "failures": bad[:5]}


# ------------------------------------------------------------------------------------------ dry run
def dry_run(sysr) -> dict:
    """Read-only: prerequisites, allocation, guards, ordering, cleanup simulation, metric and ground-truth sources.
    Never instantiates Host; creates no cgroup, file, process, signal or memory pressure."""
    from sentinelai.collectors.features import build as feature_table
    from sentinelai.diagnostic.contract import Target

    rep = {"mode": "r2f dry-run", "matrix": MATRIX, "safety_thresholds": SAFETY_THRESHOLDS}
    before = host_snapshot(sysr, require_bpf=False)
    rep["preflight"] = preflight(sysr)
    rep["allocation"] = allocation_checks()
    rep["intended_mutations"] = {label: {"experiment": experiment_of(label).__dict__,
                                         "steps": [(k, x if k != "op" else x[:2]) for k, x in
                                                   driver_steps(experiment_of(label), label)]} for label in MATRIX}
    g = {}
    for label in MATRIX:
        exp = experiment_of(label)
        st = {"controls_verified": False, "spawned": False, "run_dir": scratch_dir(SIM_TS, label), "target_pid": 7,
              "signalled": False}
        try:
            for kind, x in driver_steps(exp, label):
                if kind == "verify":
                    st["controls_verified"] = True
                elif kind == "signal":
                    check_op(("signal", 7), exp, st)
                else:
                    check_op(x, exp, st)
            g[label] = True
        except R2FRefused as exc:
            g[label] = str(exc)
    m2 = EXPERIMENTS["M2"]
    rd = scratch_dir(SIM_TS, "M2-1")
    out = str(RESULTS / SIM_TS / "M2-1" / "x.json")
    pre = {"controls_verified": False, "spawned": False, "run_dir": rd, "target_pid": 7, "signalled": False}
    post = {**pre, "controls_verified": True, "spawned": True}
    forbidden = [
        (("mem", f"{TARGET_DIR}/memory.high", "1"), pre), (("mem", f"{TARGET_DIR}/../memory.high", str(m2.high)), pre),
        (("mem", f"{CG_ROOT}/user.slice/memory.max", str(PARENT_MAX)), pre),
        (("mem", f"{CG_ROOT}/memory.swap.max", "0"), pre), (("mem", f"{TARGET_DIR}/memory.swap.max", "max"), pre),
        (("mem", f"{TARGET_DIR}/memory.high", str(m2.high)), post),
        (("write", f"{TARGET_DIR}/memory.high", str(m2.high)), pre), (("write", f"{TARGET_DIR}/cpu.max", "1 100000"), pre),
        (("write", f"{CG_ROOT}/system.slice/memory.high", "1"), pre), (("write", "/proc/sys/vm/swappiness", "0"), pre),
        (("write", "/proc/sys/vm/drop_caches", "3"), pre), (("spawn", "target", target_argv(m2, rd, out)), pre),
        (("spawn", "target", target_argv(EXPERIMENTS["E0"], rd, out)), post),
        (("spawn", "target", target_argv(m2, rd, out)), {**post, "target_spawned": True}),
        (("spawn", "contender", contender_argv(out)), post), (("signal", 7), {**post, "signalled": True}),
        (("signal", 8), post), (("scratch", "unlink", "/var/tmp/x/ws.bin"), pre),
        (("scratch", "mkdir", "/tmp/sentinel-r2f/20260101T000000Z-M2-1"), pre),
        (("scratch", "rmdir_base", "/var/tmp"), pre), (("exec", "swapoff", "-a"), pre),
        (("write", "/sys/class/net/enp0s31f6/mtu", "1500"), pre), (("mkdir", f"{CG_ROOT}/system.slice/x"), pre)]
    refused = []
    for op, st in forbidden:
        try:
            check_op(op, m2, st)
            refused.append(False)
        except (R2FRefused, ValueError):
            refused.append(True)
    rep["guards"] = {"planned_ops_accepted": g, "forbidden_refused": all(refused), "n_forbidden": len(refused)}
    rep["cleanup_simulation"] = simulation_cases()
    t = Target(name="r2f", cgroup_path=TARGET_CGROUP_PATH, pids=(1,), cpuset=str(TARGET_CPU), netns_ref="pid:1",
               ifaces=())
    have = {(c.feature, c.scope) for c in feature_table(t, tuple(sorted(C.HOST_CPUS)), (TARGET_CPU,), (TARGET_CPU,),
                                                        False)}
    cg = f"cgroup:{TARGET_CGROUP_PATH}"
    rep["metric_table"] = {f"{f}[{a}]": (f, cg if sc == "cg" else sc) in have for f, sc, a, _ in REQUIRED}
    me = os.getpid()
    us = f"{CG_ROOT}/user.slice"
    rep["gt_sources"] = {
        "cgroup_memory_files": all(sysr.read(f"{us}/{f}") is not None for f in LEAF_FILES if f.startswith("memory.")),
        "memory_stat_keys": {"anon", "pgscan", "workingset_refault_file", "pgmajfault"} <= set(C.kv(sysr.read(
            f"{us}/memory.stat"))),
        "memory_events_keys": {"oom", "oom_kill", "high", "max"} <= set(C.kv(sysr.read(f"{us}/memory.events"))),
        "vmstat_keys": {"pgscan_kswapd", "oom_kill", "pswpin", "pswpout"} <= set(C.kv(sysr.read("/proc/vmstat"))),
        "meminfo_available": "MemAvailable" in meminfo(sysr.read("/proc/meminfo")),
        "slice_pressure_files": all(sysr.read(f"{CG_ROOT}/{s}/{k}.pressure") is not None for s in C.SLICES
                                    for k in ("cpu", "memory", "io")),
        "task_majflt": task_majflt(sysr.read(f"/proc/{me}/stat")) is not None,
        "schedstat_v15": C.schedstat_rq_cpu_time(sysr.read("/proc/schedstat")) is not None,
        "scratch_parent_ext4": sysr.fstype(SCRATCH_PARENT) == "ext4",
        "target_script_present": os.path.isfile(TARGET_SCRIPT),
    }
    rep["bpf_release_simulation"] = C.simulate_bpf_release()
    after = host_snapshot(sysr, require_bpf=False)
    rep["zero_mutation"] = compare_host(before, after, require_bpf=False)
    rep["structural_ok"] = (rep["preflight"]["ok"] and all(rep["allocation"].values())
                            and all(v is True for v in g.values()) and rep["guards"]["forbidden_refused"]
                            and rep["cleanup_simulation"]["ok"] and all(rep["metric_table"].values())
                            and all(rep["gt_sources"].values()) and rep["bpf_release_simulation"]["ok"]
                            and rep["zero_mutation"]["ok"])
    return rep


# ------------------------------------------------------------------------------------------ candidate / offline / CLI
def candidate(repo, base=BASE_COMMIT):
    g = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)
    head, b = g("rev-parse", "HEAD"), g("rev-parse", "--verify", f"{base}^{{commit}}")
    if head.returncode or b.returncode:
        return {"ok": False, "reason": "HEAD or base not resolvable"}
    head, b = head.stdout.strip(), b.stdout.strip()
    if g("merge-base", "--is-ancestor", b, head).returncode:
        return {"ok": False, "reason": f"HEAD {head} does not descend from {b}"}
    changed = [p for p in g("diff", "--name-only", b, head).stdout.split() if p not in TOOLING]
    if changed:
        return {"ok": False, "reason": f"changed since {b[:7]} beyond R2-F tooling: {sorted(changed)}"}
    if g("status", "--porcelain", "--untracked-files=no").stdout.strip():
        return {"ok": False, "reason": "tracked files modified"}
    return {"ok": True, "head": head, "base": b}


def offline_evaluate(run_dir) -> dict:
    d = Path(run_dir)
    R = json.loads((d / "run.json").read_text())
    tj = d / "target.json"
    G = evaluate(ground_truth_inputs(R, json.loads(tj.read_text()) if tj.exists() else None))
    gr = restore_record(R["cleanup"], R["host_compare"], R["bpf_release"])
    norm = lambda x: json.loads(json.dumps(x, sort_keys=True, default=str))
    return {"ground_truth_identical": norm(G) == norm(R["ground_truth"]), "GR_identical": norm(gr) == norm(R["GR"]),
            "ok": norm(G) == norm(R["ground_truth"]) and norm(gr) == norm(R["GR"])}


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "dry-run":
        rep = dry_run(Sys())
        print(json.dumps(rep, indent=1, sort_keys=True, default=str))
        return 0 if rep["structural_ok"] else 3
    if cmd == "criteria":
        print(json.dumps({"safety_thresholds": SAFETY_THRESHOLDS, "matrix": MATRIX,
                          "experiments": {k: e.__dict__ for k, e in EXPERIMENTS.items()}}, indent=1, sort_keys=True))
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
            exp = experiment_of(label) if label in MATRIX else EXPERIMENTS["CAL"]
            host = Host(exp, str(log) + ".cleanup")
            res[str(log)] = cleanup(host, Sys(), C.read_oplog(log), exp)
        v = cleanup_state(Sys())
        print(json.dumps({"runs": res, "final": v}, indent=1, sort_keys=True, default=str))
        return 0 if v["ok"] and all(r["ok"] for r in res.values()) else 3
    if cmd == "candidate":
        r = candidate(argv[2], argv[3] if len(argv) > 3 else BASE_COMMIT)
        print(r["head"] if r["ok"] else r["reason"])
        return 0 if r["ok"] else 3
    if cmd == "evaluate":
        r = offline_evaluate(argv[2])
        print(json.dumps(r, indent=1, sort_keys=True))
        return 0 if r["ok"] else 3
    raise SystemExit("usage: r2f_memory.py dry-run | criteria | preflight | host-snapshot DIR | compare A B | "
                     "cleanup OUT | candidate REPO [BASE] | evaluate RUN_DIR")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
