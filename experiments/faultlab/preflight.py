#!/usr/bin/env python3
"""SentinelAI Phase 1C FaultLab pilot preflight (Gate 1.2): read-only, fail-closed readiness report.

    .venv/bin/python experiments/faultlab/preflight.py [--decisions PATH] [--stage ctrl|full] [--summary]
    sudo .venv/bin/python experiments/faultlab/preflight.py ...     (Gate 2 privileged mode, from uid 1000)

Prints one JSON report (FORMAT) on stdout; --summary also prints one line per check on stderr.
Exit status: 0 READY, 1 NOT_READY, 2 usage error.

READY means only that every mandatory prerequisite is PASS and every required Freeze-1 decision is formally approved
in a committed decisions record. It never authorises a run: the privileged pilot needs a separate owner authorisation
(Gate 2), and the report says so (`authorises_run: false`).

Statuses: PASS (verified, meets an approved requirement), FAIL (verified, violates it), UNVERIFIED (cannot be
established by a permitted read-only check), BLOCKED (a required approval, frozen value or prerequisite is missing).
A check whose requirement comes from a decision that is not approved is BLOCKED whatever the host shows; its
`evaluation` field still records the result against the proposed requirement. An exception inside a check makes it
UNVERIFIED, an attempted unsafe operation makes it FAIL, and a missing or duplicated mandatory check adds a FAIL
(PF-COMPLETENESS): nothing defaults to PASS.

Read-only by construction: every host access goes through ReadOnlyHost, which reads files under an exact prefix list,
takes metadata (lstat, statvfs) and runs only an exact list of read-only commands (R2-C's list plus version queries,
`systemctl is-enabled` of one unit and five fixed git queries). It has no write, create, chmod or delete path and
never invokes sudo. It never creates /run/sentinelai-lab or the staging path, never starts the workload, the load
generator or the loader, and never runs scripts/safety_check.sh (which writes logs/).

Stages: `full` (default) requires every Freeze-1 decision; `ctrl` (lab lifecycle PI-0 and CTRL runs only) does not
require the fault-class decisions in FULL_ONLY, which are then reported as non-mandatory.

Privileged mode (euid 0): only through sudo from uid 1000 (ENV-PRIVILEGE fails otherwise). Root makes the BPF inventory
and the full host baseline readable; every other access is the same read-only allowlist. Git and the integrity policy
run as the invoking user (setpriv), never as root, so the repository is never accessed with root's identity.

Decisions record (format DECISIONS_FORMAT, PROPOSED by this preflight, not approved): a JSON file committed in this
repository, passed with --decisions. Without it every Freeze-1 decision is BLOCKED. The record is trusted only if it is
tracked by Git and unmodified against HEAD; whether that is an adequate root of trust is itself decision
FZ-ROOT-OF-TRUST.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import r2c_cpu as C  # noqa: E402  (read-only Sys, host snapshot, cpu lists; unchanged)
import r2f_memory as F  # noqa: E402  (required-subset root controller rule; unchanged)
from r2a_lab import PROTECTED  # noqa: E402

FORMAT = "sentinelai.faultlab.preflight.v1"
DECISIONS_FORMAT = "sentinelai.faultlab.freeze1-decisions.v0"
OWNER = "Rohit Kumar"
REGISTER = "docs/PHASE_1C_FREEZE1_DECISION_REGISTER.md"
DRAFT = "docs/PHASE_1C_M4_M5_PILOT_DESIGN.md (owner draft, untracked)"
STATUSES = ("PASS", "FAIL", "UNVERIFIED", "BLOCKED")
GIB = 1 << 30
DECISIONS_MAX = 256 * 1024

# Floors from committed code (existing safety gate defaults; R2-F uses the same memory floor). Design §9's
# "MemAvailable < 2 GiB" is the stale, weaker value (register §2 item 1); the stricter committed floor is used.
MEM_AVAILABLE_MIN = 4 * GIB                     # scripts/safety_check.sh:17, scripts/r2f_memory.py
DISK_FREE_MIN = 20 * GIB                        # scripts/safety_check.sh:16 (df on the repository)
SAFE_QDISCS = frozenset({"fq_codel", "mq", "fq", "pfifo_fast", "noqueue"})   # scripts/safety_check.sh:20
PHYS_NIC = PROTECTED[0]                         # enp0s31f6
RUN_LAB = "/run/sentinelai-lab"
WS_ROOT = "/var/tmp/sentinelai-lab"          # FZ-WORKSET working-set scratch (experiments/faultlab/lab.py WS_ROOT)
OPENVPN_UNIT = "openvpn-server@server.service"
# Lab placement proposed in the draft §5.1 (FZ-LAB-SPEC): target 18; contender 18 or 19, 23; support 19, 20, 22, 23.
LAB_CPUS = frozenset({18, 19, 20, 22, 23})
DRIVER_CPUS = frozenset(range(16))
TOOLS = (("TOOL-UNSHARE", "/usr/bin/unshare"), ("TOOL-SETPRIV", "/usr/bin/setpriv"),
         ("TOOL-TIMEOUT", "/usr/bin/timeout"), ("TOOL-TASKSET", "/usr/bin/taskset"), ("TOOL-PYTHON3", C.PYTHON),
         ("TOOL-BPFTOOL", C.BPFTOOL), ("TOOL-LOADER", C.LOADER))
PATH_TOOLS = (("TOOL-IP", "ip"), ("TOOL-TC", "tc"), ("TOOL-FINDMNT", "findmnt"), ("TOOL-GIT", "git"),
              ("TOOL-SYSTEMCTL", "systemctl"))
VERSION_COMMANDS = (("ip", "-V"), ("tc", "-V"), (C.BPFTOOL, "version"), (C.LOADER, "--version"))
REL_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
SHA40 = re.compile(r"[0-9a-f]{40}")

# ------------------------------------------------------------------------------------------ Freeze-1 decisions
# id -> (title, provenance, required value keys: None = approval of text only, () = any non-null value)
WORKLOAD_KEYS = ("rate_per_s", "jitter", "pool", "pool_shrink", "queue", "cpu_us", "lock_hold_us",
                 "lock_wait_exceeded_ms", "dependency_delay_ms", "dependency_timeout_ms", "poll_s", "publish_s",
                 "timeout_s", "max_inflight", "connection_model")
DECISIONS: Dict[str, Tuple[str, str, Optional[Tuple[str, ...]]]] = {
    "FZ-WORKLOAD": ("Workload and load-generator parameters", f"{REGISTER} §1 item 1; draft §5.4", WORKLOAD_KEYS),
    "FZ-INTENSITY": ("I1-I3 levels, I3 ceilings and the selection rule", f"{REGISTER} §1 item 2; draft §6.9", ()),
    "FZ-PI5": ("PI-5 quantified acceptance criterion and mechanism", f"{REGISTER} §1 item 3; design §10; draft §6.6",
               ()),
    "FZ-PI7": ("PI-7 registration and acceptance criterion", f"{REGISTER} §1 item 3b, §2 item 4; draft §6.8", ()),
    "FZ-PI8": ("PI-8 registration and acceptance criterion", f"{REGISTER} §1 item 3b, §2 item 4; draft §6.9", ()),
    "FZ-TTRANS": ("T_TRANS rule, T_cap and T_fb", f"{REGISTER} §1 item 4; draft §6.11; AMD-9/AMD-10 (not in repo)",
                  ("T_TRANS_rule", "T_cap", "T_fb", "K_c_s", "R_hat_max_s", "T_TRANS_s", "W_s", "basis")),   # R-2
    "FZ-DATA-QUALITY": ("U-2 and COV_MIN, N_BASE_MIN, SEG_MIN", f"{REGISTER} §1 item 5; contract §6; draft §6.10",
                        ("U-2", "COV_MIN", "N_BASE_MIN", "SEG_MIN")),
    "FZ-CB-B": ("c_B and b", f"{REGISTER} §1 item 6; draft §6.10, §6.11", ("c_B", "b")),
    "FZ-STAGING": ("Persistent raw-data staging path (U-6)", f"{REGISTER} §1 item 7; design §8; draft U-6",
                   ("path", "m6_raw_retention")),                                                       # R-7
    **{f"FZ-AMD-{n:02d}": (f"AMD-{n} design text", f"{REGISTER} §1 item 8 (Stage 3H reports; not in repo)", None)
       for n in range(1, 18)},
    "FZ-MANIFEST": ("Manifest format for pilot/M6 raw data", f"{REGISTER} §1 item 9; tests/faultlab/_integrity.py:61",
                    None),
    "FZ-ROOT-OF-TRUST": ("Root of trust (unsigned Git commit + SHA-256 manifests, or other)",
                         f"{REGISTER} §1 item 10; design §8", None),
    "FZ-EXCLUSIONS": ("failed_injection, exclusion list and host-state equivalence set",
                      f"{REGISTER} §1 item 11; design §6.5; draft §9", None),
    "FZ-R2CD-ENV": ("Disposition of the two accepted R2-C/R2-D environment failures for pilot validity",
                    f"{REGISTER} §1 item 12", None),
    "FZ-LAB-SPEC": ("Lab specification: names, lab cgroup, CPU placement, host ip_forward",
                    "draft §5.1 (preflight prerequisite; not a register item)", None),
    "FZ-SAFETY-CHECKLIST": ("Pilot safety checklist (preflight, protected state, abort conditions)",
                            "draft §9 (preflight prerequisite; not a register item)", None),
    "FZ-M4-BASELINE": ("Approved M4 baseline commit", "draft §9 preflight item 1 (not a register item)", ("commit",)),
    # decision package of 2026-10-12 (register §5): the parts of FZ-INTENSITY, FZ-PI7, FZ-PI5, AMD-13/15, Q-2 and Q-5
    # that the owner settled; FZ-INTENSITY and FZ-PI5 stay pending for what is still unresolved
    "FZ-INTENSITY-R2": ("I3 ceilings with R2 evidence (D0)", f"{REGISTER} §5 D0",
                        ("loss_a_egress_max_pct", "cpu_quota_min_core", "contender_weight_max")),
    "FZ-INTENSITY-APP": ("Application I3 ceilings and PI-8 candidates (D2)", f"{REGISTER} §5 D2",
                         ("utilisation_max", "pool_min", "pool_candidates", "lock_hold_us_max",
                          "lock_hold_us_candidates", "dependency_delay_ms_max", "dependency_delay_ms_candidates")),
    "FZ-INTENSITY-NET": ("Path-loss ceiling and the congestion / police rate rule (D3)", f"{REGISTER} §5 D3",
                         ("loss_r_egress_max_pct", "rate_floor_fraction", "rate_floor_basis",
                          "netem_limit_max_packets", "byte_counters_required")),
    "FZ-PI7-LOCK": ("PI-7 fault criterion for lock-hold reps (D1)", f"{REGISTER} §5 D1",
                    ("ctrl_max_lock_wait_ms", "rep_lock_wait_p99_min_ms", "rep_quality")),
    "FZ-WORKSET": ("Workload memory working set: approach (D4)", f"{REGISTER} §5 D4",
                   ("approach", "values", "ctrl_rebaseline")),
    "FZ-OV": ("OV-4 (AMD-13) and OV-5 (AMD-15) parameters (D5)", f"{REGISTER} §5 D5",
              ("ov4_n_r", "ov4_tau", "ov4_level_pps", "ov5_r_star", "ov5_sizes")),
    "FZ-Q5": ("Test-seed provisioning, CTRL test runs (Q-5)", f"{REGISTER} §5 D5", ("ctrl_test_runs",)),
    "FZ-Q2": ("Collector privilege mode for M6 (Q-2)", f"{REGISTER} §5 Q-2", ("collector_mode_m6",)),
    "FZ-ARRIVALS": ("Load arrival process (amends FZ-WORKLOAD jitter)", f"{REGISTER} §5 A-1",
                    ("process", "rate_per_s", "replaces")),
    "FZ-INTENSITY-CPUNET": ("PI-8 candidates of the CPU and network faults", f"{REGISTER} §5 C-1",
                            ("contender_weight_candidates", "quota_us_candidates", "loss_a_pct_candidates",
                             "loss_r_pct_candidates", "congestion_kbit_candidates", "police_kbit_candidates",
                             "congestion_floor_kbit", "police_floor_kbit", "netem_limit_packets", "basis")),
    "FZ-INTENSITY-MEM": ("Memory floor and PI-8 candidates (memory.max)", f"{REGISTER} §5 M-1",
                         ("memory_max_mib_candidates", "floor_mib", "basis", "aborts", "grading",
                          "mem_util_overshoot")),                                                       # M-3, M-4
    "FZ-M5-REVIEW": ("M5 review: frozen PI-8 levels, single levels, PI-6 under throttling, U-1/U-1b/U-7",
                     f"{REGISTER} §5 R-1..R-7", ("levels", "single_levels", "congestion", "pi6_post_fault_only",
                                                 "memory", "U-1", "U-1b", "U-7")),
}
# Decisions needed only by the fault classes (PI-2/3/5/8, OV-4/5) or by M6: not mandatory for the `ctrl` stage.
FULL_ONLY = frozenset({"FZ-INTENSITY", "FZ-PI5", "FZ-PI8", "FZ-TTRANS", "FZ-INTENSITY-R2", "FZ-INTENSITY-APP",
                       "FZ-INTENSITY-NET", "FZ-PI7-LOCK", "FZ-WORKSET", "FZ-OV", "FZ-Q5", "FZ-Q2",
                       "FZ-INTENSITY-CPUNET", "FZ-INTENSITY-MEM", "FZ-M5-REVIEW"})
STAGES = ("ctrl", "full")
# Why each decision is mandatory although no host check consumes its value.
NOT_CONSUMED = ("Not consumed by a host check; mandatory because the pilot's registered procedure cannot be executed "
                "without it (register §4: Freeze-1 requires it).")
ENTRY_KEYS = frozenset({"status", "approved_by", "date", "reference", "value"})
DECISION_STATUSES = ("approved", "proposed", "pending", "rejected")


class PreflightRefused(ValueError):
    """An operation outside the read-only allowlist was requested. Nothing was executed."""


def _no_constants(name):
    raise ValueError(f"non-finite number {name}")


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def parse_decisions(data: bytes) -> Tuple[Optional[dict], List[str]]:
    """Strict parse of a decisions record. Any error -> (None, errors): the whole record is then untrusted."""
    if len(data) > DECISIONS_MAX:
        return None, [f"record larger than {DECISIONS_MAX} bytes"]
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_no_constants)
    except (ValueError, UnicodeDecodeError) as exc:
        return None, [f"not valid JSON: {exc}"]
    errs = []
    if not isinstance(doc, dict) or set(doc) != {"format", "decisions"}:
        return None, ["top level must be an object with exactly 'format' and 'decisions'"]
    if doc["format"] != DECISIONS_FORMAT:
        errs.append(f"format must be {DECISIONS_FORMAT!r}")
    dec = doc["decisions"]
    if not isinstance(dec, dict):
        return None, errs + ["'decisions' must be an object"]
    for k, e in dec.items():
        if k not in DECISIONS:
            errs.append(f"unknown decision id {k!r}")
            continue
        if not isinstance(e, dict) or "status" not in e or not set(e) <= ENTRY_KEYS:
            errs.append(f"{k}: entry must be an object with 'status' and only {sorted(ENTRY_KEYS)}")
            continue
        if e["status"] not in DECISION_STATUSES:
            errs.append(f"{k}: status must be one of {DECISION_STATUSES}")
            continue
        if e["status"] == "approved":
            if e.get("approved_by") != OWNER:
                errs.append(f"{k}: approved_by must be {OWNER!r}")
            try:
                ok_date = (isinstance(e.get("date"), str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", e["date"])
                           and datetime.date.fromisoformat(e["date"]))
            except ValueError:
                ok_date = False
            if not ok_date:
                errs.append(f"{k}: date must be YYYY-MM-DD")
            if not isinstance(e.get("reference"), str) or not e["reference"].strip():
                errs.append(f"{k}: reference (where the approval is recorded) must be a non-empty string")
    return (None, errs) if errs else (dec, [])


def decision_state(did: str, entry: Optional[dict]) -> Tuple[bool, str]:
    """(approved and complete, reason). Anything short of an approved, complete entry is not approved."""
    if entry is None:
        return False, "no entry in the decisions record"
    if entry["status"] != "approved":
        return False, f"status is {entry['status']!r}"
    keys = DECISIONS[did][2]
    if keys is None:
        return True, "approved"
    v = entry.get("value")
    if v is None:
        return False, "approved but no frozen value"
    if not keys:
        return True, "approved"
    if not isinstance(v, dict):
        return False, f"value must be an object with keys {list(keys)}"
    missing = [k for k in keys if v.get(k) is None]
    extra = sorted(set(v) - set(keys))
    if missing or extra:
        return False, f"value incomplete: missing {missing}" + (f", unexpected {extra}" if extra else "")
    if did == "FZ-WORKLOAD":
        bad = [k for k in keys if k != "connection_model" and not _is_number(v[k])]
        if not (isinstance(v["connection_model"], str) and v["connection_model"].strip()):
            bad.append("connection_model")
        if bad:
            return False, f"value has non-numeric or empty fields {bad}"
    if did == "FZ-STAGING" and not (isinstance(v["path"], str) and v["path"].startswith("/")):
        return False, "path must be an absolute path string"
    if did == "FZ-M4-BASELINE" and not (isinstance(v["commit"], str) and SHA40.fullmatch(v["commit"])):
        return False, "commit must be a full 40-hex SHA-1"
    return True, "approved"


# ------------------------------------------------------------------------------------------ read-only host
READ_PREFIXES = C.READ_PREFIXES + ("/etc/os-release", "/lib/modules/")
FIXED_COMMANDS = frozenset(C.READ_ONLY_COMMANDS) | frozenset(VERSION_COMMANDS) | {
    ("systemctl", "is-enabled", OPENVPN_UNIT)}


def command_allowed(argv, root: str) -> bool:
    """Exact read-only commands only (no sudo, no namespace, link, tc, cgroup or BPF mutation is expressible)."""
    a = tuple(argv)
    if a in FIXED_COMMANDS:
        return True
    if len(a) < 4 or a[:3] != ("git", "-C", root):
        return False
    t = a[3:]
    rel_ok = lambda p: REL_PATH.fullmatch(p) is not None and ".." not in p.split("/")
    return (t in (("rev-parse", "HEAD"), ("status", "--porcelain", "--untracked-files=no"))
            or (len(t) == 4 and t[:3] == ("ls-files", "--error-unmatch", "--") and rel_ok(t[3]))
            or (len(t) == 5 and t[:4] == ("diff", "--quiet", "HEAD", "--") and rel_ok(t[4]))
            or (len(t) == 4 and t[:2] == ("merge-base", "--is-ancestor") and SHA40.fullmatch(t[2]) is not None
                and t[3] == "HEAD"))


def invoker_prefix() -> List[str]:
    """setpriv prefix that drops root back to the sudo invoker (uid 1000) for repository access. Refuses otherwise."""
    uid, gid = os.environ.get("SUDO_UID", ""), os.environ.get("SUDO_GID", "")
    if uid != str(C.LAB_UID) or not gid.isdigit():
        raise PreflightRefused(f"root without sudo from uid {C.LAB_UID}: repository access refused")
    return ["setpriv", f"--reuid={uid}", f"--regid={gid}", "--init-groups", "--"]


class ReadOnlyHost:
    """The only host access of the preflight. Reads, metadata and allowlisted read-only commands; nothing else."""

    def __init__(self, root: Path = ROOT):
        self.root = str(root)
        self.sys = C.Sys()

    def _check(self, path):
        p = str(path)
        if not p.startswith(READ_PREFIXES) or "/../" in p or "\x00" in p:
            raise PreflightRefused(f"read outside the allowlist: {p!r}")

    def uname(self) -> Tuple[str, str]:
        u = os.uname()
        return u.sysname, u.release

    def euid(self) -> int:
        return os.geteuid()

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
        return os.path.lexists(path)

    def lstat(self, path):
        """os.lstat result, None if the path does not exist; any other error propagates (-> UNVERIFIED)."""
        p = str(path)
        if not p.startswith("/") or "\x00" in p:
            raise PreflightRefused(f"lstat of a non-absolute path: {p!r}")
        try:
            return os.lstat(p)
        except FileNotFoundError:
            return None

    def free_bytes(self, path) -> int:
        s = os.statvfs(str(path))
        return s.f_bavail * s.f_frsize

    def which(self, name) -> Optional[str]:
        import shutil
        return shutil.which(name)

    def executable(self, path) -> bool:
        return os.path.isfile(path) and os.access(path, os.X_OK)

    def uid_exists(self, uid) -> bool:
        return self.sys.uid_name(uid) is not None

    def cgroup_dirs(self) -> List[str]:
        return self.sys.cgroup_dirs()

    def pids(self) -> List[int]:
        return self.sys.pids()

    def run(self, argv) -> Optional[Tuple[int, str]]:
        if not command_allowed(argv, self.root):
            raise PreflightRefused(f"command not in the read-only allowlist: {list(argv)}")
        env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"}
        exe = list(argv)
        if exe[0] == "git" and os.geteuid() == 0:
            exe = invoker_prefix() + exe                     # the repository is read as its owner, never as root
        try:
            p = subprocess.run(exe, capture_output=True, text=True, timeout=15, shell=False, env=env,
                               stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return p.returncode, p.stdout + p.stderr if argv[1:] in (("-V",), ("version",)) else p.stdout

    def read_repo_file(self, rel: str) -> Optional[bytes]:
        """A regular file inside the repository, opened without following a final symlink, at most 256 KiB + 1."""
        if REL_PATH.fullmatch(rel) is None or ".." in rel.split("/"):
            raise PreflightRefused(f"not a plain repository-relative path: {rel!r}")
        path = os.path.join(self.root, rel)
        if os.path.realpath(path) != path:
            return None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            return os.read(fd, DECISIONS_MAX + 1)
        finally:
            os.close(fd)

    def sudo_uid(self) -> Optional[str]:
        return os.environ.get("SUDO_UID")

    def snapshot(self) -> dict:
        """R2-C's read-only host snapshot (BPF parts need root and are None when unprivileged)."""
        return C.host_snapshot(self.sys, require_bpf=False)


_INTEGRITY_CODE = ("import json, sys; sys.path.insert(0, sys.argv[1] + '/tests'); "
                   "from faultlab import _integrity as I, test_integrity as T; "
                   "print(json.dumps(I.check(sys.argv[1], T.LIVE)))")


def default_manifest_verifier(path: Path) -> List[str]:
    """experiments/faultlab/rehearsal.py verify_manifest (the approved verifier candidate; read-only)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("faultlab_rehearsal_for_preflight",
                                                  ROOT / "experiments/faultlab/rehearsal.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.verify_manifest(path)


def default_integrity() -> List[str]:
    """The live integrity policy (tests/faultlab/test_integrity.py LIVE), read-only Git queries only. As root it runs
    in a child process with the invoker's identity."""
    if os.geteuid() == 0:
        p = subprocess.run(invoker_prefix() + [sys.executable, "-I", "-c", _INTEGRITY_CODE, str(ROOT)],
                           capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        if p.returncode != 0:
            raise RuntimeError(f"integrity check as the invoker failed (rc {p.returncode}): {p.stderr[-300:]}")
        return json.loads(p.stdout)
    sys.path.insert(0, str(ROOT / "tests"))
    from faultlab import _integrity as I, test_integrity as T
    return I.check(ROOT, T.LIVE)


# ------------------------------------------------------------------------------------------ checks
@dataclass
class Check:
    id: str
    title: str
    category: str                  # approval | provenance | integrity | environment | lab | resources | staging
    mandatory: bool
    status: str
    observed: object
    required: str
    provenance: str
    explanation: str
    next_action: Optional[str]
    depends_on: List[str] = field(default_factory=list)
    evaluation: Optional[str] = None   # result against the (possibly unapproved) requirement
    blocked_by: List[str] = field(default_factory=list)


class Result:
    """Outcome of one host evaluation, before decision dependencies are applied."""

    def __init__(self, status, observed=None, explanation="", next_action=None):
        assert status in ("PASS", "FAIL", "UNVERIFIED", "BLOCKED"), status
        self.status, self.observed, self.explanation, self.next_action = status, observed, explanation, next_action


def ok(observed, explanation="") -> Result:
    return Result("PASS", observed, explanation)


def bad(observed, explanation, action) -> Result:
    return Result("FAIL", observed, explanation, action)


def unverified(observed, explanation, action) -> Result:
    return Result("UNVERIFIED", observed, explanation, action)


@dataclass(frozen=True)
class Spec:
    id: str
    title: str
    category: str
    required: str
    provenance: str
    depends_on: Tuple[str, ...] = ()
    mandatory: bool = True


class Preflight:
    def __init__(self, host, decisions_path: Optional[str] = None,
                 integrity: Callable[[], List[str]] = default_integrity, clock=None, stage: str = "full",
                 manifest_verifier: Callable[[Path], List[str]] = default_manifest_verifier):
        if stage not in STAGES:
            raise ValueError(f"stage must be one of {STAGES}")
        self.host, self.decisions_path, self.integrity, self.stage = host, decisions_path, integrity, stage
        self.manifest_verifier = manifest_verifier
        self.clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.checks: List[Check] = []
        self.approved: Dict[str, Tuple[bool, str]] = {d: (False, "no decisions record") for d in DECISIONS}
        self.decisions: Dict[str, dict] = {}

    # -- plumbing
    def add(self, spec: Spec, fn: Callable[[], Result]):
        try:
            r = fn()
            if not isinstance(r, Result):
                r = unverified(None, f"check returned {type(r).__name__}, not a Result", "fix the preflight check")
        except PreflightRefused as exc:
            r = bad(None, f"unsafe operation intercepted (nothing executed): {exc}", "fix the preflight check")
        except Exception as exc:   # noqa: BLE001  (fail closed: any error is UNVERIFIED, never PASS)
            r = unverified(None, f"check raised {type(exc).__name__}: {exc}", "investigate the error and re-run")
        missing = [d for d in spec.depends_on if not self.approved[d][0]]
        status, evaluation, action = r.status, None, r.next_action
        expl = r.explanation
        if missing:
            evaluation = r.status
            status = "BLOCKED"
            expl = (f"Requirement depends on decision(s) not approved: {missing}. Evaluated against the proposed "
                    f"requirement: {r.status}. " + expl).strip()
            action = f"Owner decision needed on {missing}" + (
                f"; also: {r.next_action}" if r.next_action and r.status != "BLOCKED" else "")
        elif r.status != "PASS" and not action:
            action = "investigate and re-run the preflight"
        self.checks.append(Check(spec.id, spec.title, spec.category, spec.mandatory, status, r.observed, spec.required,
                                 spec.provenance, expl, None if status == "PASS" else action, list(spec.depends_on),
                                 evaluation, missing))

    def git(self, *args) -> Optional[Tuple[int, str]]:
        return self.host.run(("git", "-C", self.host.root) + args)

    # -- decisions
    def load_decisions(self):
        spec = Spec("PROV-DECISIONS-RECORD", "Freeze-1 decisions record is committed, unmodified and well-formed",
                    "provenance", "--decisions names a repository file that is tracked by Git, identical to HEAD, "
                    f"and valid {DECISIONS_FORMAT} (strict)", f"{REGISTER} §4; design §8 (Git + SHA-256 provenance)")

        def fn():
            if not self.decisions_path:
                return Result("BLOCKED", None, "No decisions record supplied: no Freeze-1 decision can be shown to be "
                              "approved.", "Owner records approvals in a committed decisions record and passes it "
                              "with --decisions")
            p = os.path.abspath(self.decisions_path)
            rel = os.path.relpath(p, self.host.root)
            if rel.startswith("..") or os.path.isabs(rel):
                return bad(p, "decisions record is outside the repository", "commit the record inside the repository")
            tracked = self.git("ls-files", "--error-unmatch", "--", rel)
            if tracked is None:
                return unverified(rel, "git ls-files could not run", "make git available and re-run")
            if tracked[0] != 0:
                return bad(rel, "decisions record is not tracked by Git", "commit the record (owner approval)")
            clean = self.git("diff", "--quiet", "HEAD", "--", rel)
            if clean is None or clean[0] not in (0, 1):
                return unverified(rel, "git diff could not run", "make git available and re-run")
            if clean[0] != 0:
                return bad(rel, "decisions record differs from HEAD (uncommitted edits)", "commit or revert the edits")
            data = self.host.read_repo_file(rel)
            if data is None:
                return bad(rel, "decisions record is not a readable regular file (symlink or special file?)",
                           "store the record as a regular file")
            dec, errs = parse_decisions(data)
            if dec is None:
                return bad({"path": rel, "errors": errs}, "decisions record is malformed; it is ignored entirely",
                           "correct the record")
            self.decisions = dec
            for d in DECISIONS:
                self.approved[d] = decision_state(d, dec.get(d))
            return ok({"path": rel, "sha256": hashlib.sha256(data).hexdigest(), "entries": len(dec)})
        self.add(spec, fn)

    def approval_checks(self):
        for d, (title, prov, keys) in DECISIONS.items():
            consumed = {"FZ-STAGING": "Consumed by the STG-* checks.",
                        "FZ-LAB-SPEC": "Consumed by the LAB-* placement and ip_forward checks.",
                        "FZ-SAFETY-CHECKLIST": "Consumed by STG-FREE-SPACE.",
                        "FZ-R2CD-ENV": "Consumed by LAB-ROOT-SUBTREE.",
                        "FZ-M4-BASELINE": "Consumed by INT-M4-BASELINE."}.get(d, NOT_CONSUMED)
            req = ("status 'approved' by Rohit Kumar with date and reference"
                   + ("" if keys is None else " and a frozen value" + (f" with keys {list(keys)}" if keys else "")))

            def fn(d=d, consumed=consumed):
                approved, reason = self.approved[d]
                entry = self.decisions.get(d)
                obs = None if entry is None else {k: entry.get(k) for k in ("status", "date", "reference")}
                if approved:
                    return ok(obs, consumed)
                return Result("BLOCKED", obs, f"Not approved: {reason}. {consumed}",
                              f"Owner decision on {d} ({title}); record it in the committed decisions record")
            self.add(Spec(f"APPR-{d}", title, "approval", req, prov,
                          mandatory=self.stage == "full" or d not in FULL_ONLY), fn)

    # -- environment
    def environment_checks(self):
        h = self.host

        def kernel():
            sysname, release = h.uname()
            return ok({"sysname": sysname, "release": release}) if sysname == "Linux" else \
                bad(sysname, "not Linux", "run on the lab host")
        self.add(Spec("ENV-KERNEL", "Operating system kernel", "environment", "Linux",
                      "design §3 (Linux host, cgroup v2, eBPF)"), kernel)

        def kernel_tooling():
            m = re.search(r"tools-(\d+\.\d+\.\d+-\d+)/", C.BPFTOOL)
            release = h.uname()[1]
            if m is None:
                return unverified(C.BPFTOOL, "kernel version not derivable from the bpftool path", "review R2 tooling")
            return ok(release) if release.startswith(m.group(1) + "-") else \
                bad(release, f"kernel differs from the release the committed BPF tooling targets ({m.group(1)})",
                    "rebuild/re-validate M3B tooling for this kernel (separate approval)")
        self.add(Spec("ENV-KERNEL-TOOLING", "Kernel matches the committed bpftool/loader build", "environment",
                      "kernel release prefix equal to the version in scripts/r2c_cpu.py BPFTOOL",
                      "scripts/r2c_cpu.py:63 (BPFTOOL); M3B loader built against it"), kernel_tooling)

        self.add(Spec("ENV-BTF", "Kernel BTF for the CO-RE eBPF loader", "environment",
                      "/sys/kernel/btf/vmlinux exists", "ebpf/bpf/sentinel.bpf.c (CO-RE), ebpf/Makefile"),
                 lambda: ok(True) if h.exists("/sys/kernel/btf/vmlinux") else
                 bad(False, "no kernel BTF", "use a kernel with CONFIG_DEBUG_INFO_BTF"))

        def cgroup2():
            mounts = h.read("/proc/self/mounts")
            if mounts is None:
                return unverified(None, "/proc/self/mounts unreadable", "re-run on the lab host")
            v2 = any(l.split()[1:3] == ["/sys/fs/cgroup", "cgroup2"] for l in mounts.splitlines() if len(l.split()) > 2)
            ctl = h.read(f"{C.CG_ROOT}/cgroup.controllers")
            return ok(ctl.strip()) if v2 and ctl else bad({"cgroup2_mounted": v2, "controllers": ctl},
                                                           "cgroup v2 not mounted at /sys/fs/cgroup",
                                                           "boot with the unified cgroup hierarchy")
        self.add(Spec("ENV-CGROUP2", "Unified cgroup v2 hierarchy", "environment",
                      "cgroup2 mounted at /sys/fs/cgroup with a readable cgroup.controllers",
                      "design §13 decision 2 (dedicated lab cgroup); scripts/r2c_cpu.py:40"), cgroup2)

        def os_release():
            t = h.read("/etc/os-release") or ""
            m = re.search(r'^PRETTY_NAME="?([^"\n]*)"?', t, re.M)
            return ok(m.group(1) if m else None, "Recorded only: no approved distribution requirement exists.")
        self.add(Spec("ENV-OS-RELEASE", "Distribution (recorded)", "environment", "none (record only)",
                      "no registered requirement", mandatory=False), os_release)

        for cid, path in TOOLS:
            self.add(Spec(cid, f"Tool {path}", "environment", f"{path} is an executable file",
                          "scripts/r2f_memory.py preflight tool list (verified, R2-F); draft §9 tool list"),
                     lambda p=path: ok(p) if h.executable(p) else bad(p, "missing or not executable",
                                                                       f"install or build {p}"))
        for cid, name in PATH_TOOLS:
            self.add(Spec(cid, f"Tool {name} on PATH", "environment", f"{name} resolves on PATH",
                          "scripts/r2c_cpu.py READ_ONLY_COMMANDS / host snapshot; draft §9 tool list"),
                     lambda n=name: (lambda w: ok(w) if w else bad(None, f"{n} not found", f"install {n}"))(
                         h.which(n)))

        def versions():
            out = {}
            for argv in VERSION_COMMANDS:
                r = h.run(argv) if (argv[0] in ("ip", "tc") and h.which(argv[0])) or h.executable(argv[0]) else None
                out[" ".join(os.path.basename(a) for a in argv)] = None if r is None else r[1].strip()[:200]
            return ok(out, "Recorded only: no approved version requirement exists beyond the kernel/tooling match.")
        self.add(Spec("ENV-TOOL-VERSIONS", "Tool versions (recorded)", "environment", "none (record only)",
                      "no registered requirement", mandatory=False), versions)

        def privilege():
            e = h.euid()
            if e == 0:
                su = h.sudo_uid()
                return ok({"euid": 0, "sudo_uid": su}) if su == str(C.LAB_UID) else \
                    bad({"euid": 0, "sudo_uid": su}, f"root, but not through sudo from uid {C.LAB_UID}",
                        f"run as: sudo .venv/bin/python experiments/faultlab/preflight.py ... from uid {C.LAB_UID}")
            return unverified(e, "The future run needs root for netns/veth, lab cgroup, tc in lab netns and the "
                              "M3B loader (draft §5.1 Privileges). The preflight never invokes sudo, so whether "
                              "those privileges will be available cannot be established, and BPF state "
                              "(LAB-NO-SENTINEL-BPF) cannot be read.",
                              "At Gate 2 (separately authorised) re-run the preflight with the approved privileges")
        self.add(Spec("ENV-PRIVILEGE", "Privileges required by the future run", "environment",
                      f"effective uid 0 through sudo from uid {C.LAB_UID}",
                      "draft §5.1 Privileges; scripts/r2c_cpu.py Host; scripts/r2e_validate.sh (sudo from uid 1000)"),
                 privilege)

    # -- lab prerequisites (read-only inspection only)
    def lab_checks(self):
        h = self.host

        def module(name, subdir):
            def fn():
                release = h.uname()[1]
                if h.exists(f"/sys/module/{name}"):
                    return ok("loaded")
                files = h.listdir(f"/lib/modules/{release}/kernel/{subdir}")
                builtin = h.read(f"/lib/modules/{release}/modules.builtin") or ""
                if files is None and not builtin:
                    return unverified(None, f"/lib/modules/{release} unreadable", "re-run on the lab host")
                if any(f.startswith(f"{name}.ko") for f in files or []) or f"/{name}.ko" in builtin:
                    return ok("available, not loaded",
                              "Loading it at run time changes kernel module state (see invariants).")
                return bad(None, f"{name} neither loaded, built in nor installed", f"install the {name} module")
            return fn
        self.add(Spec("LAB-NETNS-SUPPORT", "Network namespace support", "lab", "/proc/self/ns/net exists",
                      "design §13 decision 2 (three network namespaces)"),
                 lambda: ok(True) if h.exists("/proc/self/ns/net") else bad(False, "no netns support",
                                                                             "use a kernel with CONFIG_NET_NS"))
        self.add(Spec("LAB-VETH-AVAILABLE", "veth driver available", "lab", "veth loaded, built in or installed",
                      "design §13 decision 2; draft §5.1 Links"), module("veth", "drivers/net"))
        self.add(Spec("LAB-NETEM-AVAILABLE", "netem qdisc available", "lab", "sch_netem loaded, built in or installed",
                      "design §6.3 network faults; draft §5.2 fault types"), module("sch_netem", "net/sched"))

        def subtree():
            t = h.read(f"{C.CG_ROOT}/cgroup.subtree_control")
            if t is None:
                return unverified(None, "root cgroup.subtree_control unreadable", "re-run on the lab host")
            return ok(t.strip()) if F.root_controllers_ok(t) else bad(t.strip(), "required controllers missing "
                                                                     "or malformed list", "owner decision (root write)")
        self.add(Spec("LAB-ROOT-SUBTREE", "Root delegates cpuset cpu memory pids", "lab",
                      "required subset {cpuset,cpu,memory,pids} of root cgroup.subtree_control (strict parse)",
                      "scripts/r2f_memory.py:54,501-508; draft §9", ("FZ-R2CD-ENV",)), subtree)

        def subtree_exact():
            t = h.read(f"{C.CG_ROOT}/cgroup.subtree_control")
            names = set((t or "").split())
            return ok({"observed": sorted(names), "missing_vs_r2c": sorted(C.ROOT_SUBTREE - names)},
                      "Recorded only: R2-C's exact set; a difference explains the two accepted R2-C/R2-D "
                      "test_dry_run_mutates_nothing failures (register item 12).")
        self.add(Spec("LAB-ROOT-SUBTREE-R2C", "Root controllers vs R2-C exact set (recorded)", "lab",
                      "none (record only)", "scripts/r2c_cpu.py:48 ROOT_SUBTREE", mandatory=False), subtree_exact)

        def cpulist(path):
            t = h.read(path)
            return None if t is None else C.parse_cpulist(t)

        def root_cpuset():
            s = cpulist(f"{C.CG_ROOT}/cpuset.cpus.effective")
            if s is None:
                return unverified(None, "root cpuset.cpus.effective unreadable", "re-run on the lab host")
            return ok(C.cpus_text(s)) if s == C.HOST_CPUS else bad(C.cpus_text(s), "root cpuset is not 0-23",
                                                                    "investigate CPU hotplug/isolation")
        self.add(Spec("LAB-ROOT-CPUSET", "Root cpuset.cpus.effective is 0-23", "lab", "0-23",
                      "scripts/r2c_cpu.py:47 HOST_CPUS; compare_host root_cpuset_0_23"), root_cpuset)

        def online():
            s = cpulist("/sys/devices/system/cpu/online")
            if s is None:
                return unverified(None, "cpu online list unreadable", "re-run on the lab host")
            need = LAB_CPUS | DRIVER_CPUS
            return ok(C.cpus_text(s)) if need <= s else bad(C.cpus_text(s), f"offline: {C.cpus_text(need - s)}",
                                                            "bring the CPUs online")
        self.add(Spec("LAB-CPUS-ONLINE", "Lab and driver CPUs online", "lab", "CPUs 0-15, 18, 19, 20, 22, 23 online",
                      "draft §5.1 CPU placement", ("FZ-LAB-SPEC",)), online)

        def smt():
            s = cpulist(f"/sys/devices/system/cpu/cpu{C.TARGET_CPU}/topology/thread_siblings_list")
            if s is None:
                return unverified(None, "CPU 18 topology unreadable", "re-run on the lab host")
            return ok(C.cpus_text(s)) if s == {C.TARGET_CPU} else bad(C.cpus_text(s), "CPU 18 has an SMT sibling",
                                                                       "owner decision on placement")
        self.add(Spec("LAB-CPU18-NO-SMT", "Target CPU 18 has no SMT sibling", "lab", "thread_siblings_list = 18",
                      "draft §9; scripts/r2f_memory.py preflight cpu18_no_smt", ("FZ-LAB-SPEC",)), smt)

        def irq():
            t = h.read(f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list")
            if t is None:
                return unverified(None, f"IRQ {C.NIC_IRQ} affinity unreadable", "re-run on the lab host")
            s = C.parse_cpulist(t)
            return ok(C.cpus_text(s)) if not s & LAB_CPUS else bad(C.cpus_text(s), "NIC IRQ on a lab CPU",
                                                                   "owner decision (IRQ affinity is protected state)")
        self.add(Spec("LAB-NIC-IRQ", f"NIC IRQ {C.NIC_IRQ} not on lab CPUs", "lab",
                      "effective affinity disjoint from {18,19,20,22,23}",
                      "draft §5.1, §9; scripts/r2c_cpu.py:53 NIC_IRQ", ("FZ-LAB-SPEC",)), irq)

        def protected():
            have = {p: h.exists(f"/sys/class/net/{p}") for p in PROTECTED}
            return ok(have) if all(have.values()) else bad(have, "protected interface missing",
                                                           "restore the host network before any run")
        self.add(Spec("LAB-PROTECTED-IFACES", "Protected interfaces present", "lab", f"{list(PROTECTED)} exist",
                      "scripts/r2a_lab.py:25 PROTECTED; draft §9 protected state"), protected)

        def default_route():
            r = h.run(("ip", "-j", "route", "show"))
            if r is None or r[0] != 0:
                return unverified(None, "ip route unreadable", "re-run on the lab host")
            devs = [x.get("dev") for x in json.loads(r[1] or "[]") if x.get("dst") == "default"]
            return ok(devs) if devs and devs[0] == PHYS_NIC else bad(devs, f"default route not via {PHYS_NIC}",
                                                                      "restore the host network")
        self.add(Spec("LAB-DEFAULT-ROUTE", "Default route via the protected NIC", "lab", f"default dev {PHYS_NIC}",
                      "scripts/safety_check.sh §4 default_route"), default_route)

        def qdiscs():
            r = h.run(("tc", "-j", "qdisc", "show"))
            if r is None or r[0] != 0:
                return unverified(None, "tc qdisc unreadable", "re-run on the lab host")
            q = json.loads(r[1] or "[]")
            netem = [x.get("dev") for x in q if x.get("kind") == "netem"]
            nic = sorted({x.get("kind") for x in q if x.get("dev") == PHYS_NIC})
            if netem or not nic or not set(nic) <= SAFE_QDISCS:
                return bad({"netem_on": netem, "nic_kinds": nic}, "netem present or non-default qdisc on the NIC",
                           "remove leftover qdiscs (owner action) before any run")
            return ok({"netem_on": [], "nic_kinds": nic})
        self.add(Spec("LAB-NO-NETEM", "No netem anywhere; default qdiscs on the NIC", "lab",
                      f"no netem qdisc; {PHYS_NIC} kinds within {sorted(SAFE_QDISCS)}",
                      "scripts/safety_check.sh §4 nic_qdisc, netem_global"), qdiscs)

        def ip_forward():
            t = h.read("/proc/sys/net/ipv4/ip_forward")
            if t is None:
                return unverified(None, "ip_forward unreadable", "re-run on the lab host")
            return ok(t.strip()) if t.strip() == "1" else bad(t.strip(), "host ip_forward differs from the value the "
                                                              "lab specification assumes", "owner decision")
        self.add(Spec("LAB-IP-FORWARD", "Host ip_forward as the lab spec assumes", "lab", "net.ipv4.ip_forward = 1, "
                      "to stay identical", "draft §5.1 Routing (R2-A report §3)", ("FZ-LAB-SPEC",)), ip_forward)

        def netns():
            if h.lstat("/run/netns") is None:
                return ok([], "/run/netns absent: no named network namespace exists")
            names = h.listdir("/run/netns")
            if names is None:
                return unverified(None, "/run/netns unreadable", "re-run on the lab host")
            hits = [n for n in names if n.startswith("sentinel")]
            return bad(hits, "sentinel network namespace exists", "owner cleanup") if hits else ok(names)
        self.add(Spec("LAB-NO-SENTINEL-NETNS", "No sentinel* named network namespace", "lab", "none in /run/netns",
                      "draft §9 preflight; draft §5.1 names sentinel-lab-{a,r,b}"), netns)

        def links():
            names = h.listdir("/sys/class/net")
            if names is None:
                return unverified(None, "/sys/class/net unreadable", "re-run on the lab host")
            hits = [n for n in names if n.startswith(("sentlab", "sentinel"))]
            return bad(hits, "lab interface in the host namespace", "owner cleanup") if hits else ok(len(names))
        self.add(Spec("LAB-NO-LAB-INTERFACES", "No lab interface in the host namespace", "lab",
                      "no sentlab*/sentinel* interface", "draft §5.1 Links, Lab checks"), links)

        def cgroups():
            hits = C.sentinel_cgroups(h)
            return bad(hits, "sentinel cgroup exists", "owner cleanup") if hits else ok([])
        self.add(Spec("LAB-NO-SENTINEL-CGROUP", "No sentinel* cgroup", "lab", "no cgroup path component sentinel*",
                      "draft §9; scripts/r2c_cpu.py sentinel_cgroups"), cgroups)

        def procs():
            hits = [p for p in h.pids() if "::/sentinel" in (h.read(f"/proc/{p}/cgroup") or "")]
            return bad(hits, "process in a sentinel cgroup", "owner cleanup") if hits else ok([])
        self.add(Spec("LAB-NO-LAB-PROCESS", "No process in a sentinel* cgroup", "lab", "none",
                      "draft §9; scripts/r2c_cpu.py lab_pids"), procs)

        def run_lab():
            st = h.lstat(RUN_LAB)
            return ok("absent") if st is None else bad(stat.filemode(st.st_mode), f"{RUN_LAB} exists (leftover)",
                                                       "owner cleanup; the preflight never removes it")
        self.add(Spec("LAB-RUN-DIR-ABSENT", f"No {RUN_LAB} leftover", "lab", "absent",
                      "draft §9 preflight; app metrics root (src/sentinelai/collectors/app.py APP_ROOT)"), run_lab)

        def ws_scratch():
            st = h.lstat(WS_ROOT)
            return ok("absent") if st is None else bad(stat.filemode(st.st_mode), f"{WS_ROOT} exists (leftover)",
                                                       "owner cleanup; the preflight never removes it")
        self.add(Spec("LAB-WS-SCRATCH-ABSENT", f"No {WS_ROOT} leftover", "lab", "absent",
                      "draft §9 preflight; FZ-WORKSET working-set scratch (register §5 D4)"), ws_scratch)

        def bpf():
            got = {k: h.run((C.BPFTOOL, "-j", k, "show")) for k in ("prog", "map")}
            if any(v is None or v[0] != 0 for v in got.values()):
                return unverified(None, "bpftool prog/map listing needs privileges the preflight does not use",
                                  "At Gate 2 re-run with the approved privileges")
            progs = [p.get("name") for p in json.loads(got["prog"][1] or "[]")
                     if str(p.get("name", "")).startswith(C.LOADER_BPF_PROG_PREFIX)]
            maps = [m.get("name") for m in json.loads(got["map"][1] or "[]")
                    if str(m.get("name", "")).startswith(C.LOADER_BPF_MAP_PREFIX)]
            return bad({"progs": progs, "maps": maps}, "SentinelAI BPF objects present", "owner cleanup") \
                if progs or maps else ok({"progs": [], "maps": []})
        self.add(Spec("LAB-NO-SENTINEL-BPF", "No SentinelAI BPF program or map", "lab",
                      f"no prog {C.LOADER_BPF_PROG_PREFIX}*, no map {C.LOADER_BPF_MAP_PREFIX}*",
                      "draft §9; scripts/r2c_cpu.py:121-123"), bpf)

        self.add(Spec("LAB-LAB-UID", f"Lab uid {C.LAB_UID} exists", "lab", f"uid {C.LAB_UID} resolves",
                      "scripts/r2c_cpu.py:59 LAB_UID; app metrics owner check"),
                 lambda: ok(C.LAB_UID) if h.uid_exists(C.LAB_UID) else bad(C.LAB_UID, "uid missing", "owner action"))

        def openvpn():
            r = h.run(("systemctl", "is-enabled", OPENVPN_UNIT))
            if r is None or not r[1].strip():
                return unverified(None, "systemctl is-enabled gave no answer", "re-run on the lab host")
            v = r[1].strip()
            return ok(v) if v in ("disabled", "masked") else bad(v, f"{OPENVPN_UNIT} is not disabled",
                                                                 "owner disables the unit")
        self.add(Spec("LAB-OPENVPN-DISABLED", f"{OPENVPN_UNIT} disabled", "lab", "disabled or masked",
                      "docs/PROJECT_STATUS.json:234 known limitation; draft §9"), openvpn)

    # -- resources
    def resource_checks(self):
        h = self.host

        def mem():
            t = h.read("/proc/meminfo")
            avail = F.meminfo(t).get("MemAvailable") if t else None
            if avail is None:
                return unverified(None, "MemAvailable unreadable", "re-run on the lab host")
            return ok(avail) if avail >= MEM_AVAILABLE_MIN else bad(avail, "below the 4 GiB floor",
                                                                    "free memory before the run")
        self.add(Spec("RES-MEM-AVAILABLE", "MemAvailable floor", "resources", f">= {MEM_AVAILABLE_MIN} bytes (4 GiB)",
                      "scripts/safety_check.sh:17 (SENTINEL_MIN_MEM_GB default 4); scripts/r2f_memory.py "
                      "MEM_AVAILABLE_MIN_BYTES; design §9 says 2 GiB (stale, register §2 item 1)"), mem)

        def disk():
            free = h.free_bytes(h.root)
            return ok(free) if free >= DISK_FREE_MIN else bad(free, "below the 20 GiB floor", "free disk space")
        self.add(Spec("RES-DISK-REPO", "Free disk on the repository filesystem", "resources",
                      f">= {DISK_FREE_MIN} bytes (20 GiB)", "scripts/safety_check.sh:16 (SENTINEL_MIN_DISK_GB "
                      "default 20, df on the repository)"), disk)

    # -- staging (never created or changed)
    def staging_checks(self):
        h = self.host
        approved = self.approved["FZ-STAGING"][0]
        path = self.decisions.get("FZ-STAGING", {}).get("value", {}).get("path") if approved else None
        dep = ("FZ-STAGING",)
        undecided = lambda: Result("BLOCKED", None, "staging path not decided (U-6); nothing to inspect",
                                   "Owner decision on FZ-STAGING")

        def components():
            if path is None:
                return undecided()
            norm = os.path.normpath(path)
            if norm != path or not path.startswith("/") or path == "/":
                return bad(path, "path is not absolute and normalised", "record a normalised absolute path")
            cur = ""
            for part in path.strip("/").split("/"):
                cur += "/" + part
                st = h.lstat(cur)
                if st is None:
                    return bad(cur, "does not exist; the preflight never creates it",
                               "owner creates the staging directory")
                if stat.S_ISLNK(st.st_mode):
                    return bad(cur, "symlink in the staging path", "use a path without symlinks")
            st = h.lstat(path)
            return ok(path) if stat.S_ISDIR(st.st_mode) else bad(path, "not a directory", "use a directory")
        self.add(Spec("STG-EXISTS", "Staging path exists as a directory without symlinks", "staging",
                      "approved absolute path; every component exists; no symlink; final is a directory",
                      "register item 7; design §8 append-only raw data", dep), components)

        def persistent():
            if path is None:
                return undecided()
            mounts = h.read("/proc/self/mounts")
            if mounts is None:
                return unverified(None, "/proc/self/mounts unreadable", "re-run on the lab host")
            best = ("", None)
            for l in mounts.splitlines():
                f = l.split()
                covers = len(f) > 2 and (path == f[1] or path.startswith(f[1].rstrip("/") + "/"))
                if covers and len(f[1]) >= len(best[0]):
                    best = (f[1], f[2])
            if best[1] is None:
                return unverified(None, "no mount covers the path", "re-run on the lab host")
            return bad(best, "volatile filesystem", "choose a persistent filesystem") \
                if best[1] in ("tmpfs", "ramfs", "devtmpfs") else ok({"mount": best[0], "fstype": best[1]})
        self.add(Spec("STG-PERSISTENT", "Staging path is on a persistent filesystem", "staging",
                      "filesystem type not tmpfs/ramfs/devtmpfs", "register item 7 ('persistent' staging path)", dep),
                 persistent)

        def perms():
            if path is None:
                return undecided()
            st = h.lstat(path)
            if st is None:
                return bad(path, "does not exist", "owner creates the staging directory")
            owner_ok = st.st_uid in (h.euid(), C.LAB_UID)
            ww = bool(st.st_mode & stat.S_IWOTH)
            obs = {"uid": st.st_uid, "mode": oct(stat.S_IMODE(st.st_mode))}
            return ok(obs) if owner_ok and not ww else bad(obs, "world-writable or foreign owner",
                                                           "owner fixes ownership/mode (the preflight never does)")
        self.add(Spec("STG-PERMISSIONS", "Staging directory ownership and mode", "staging",
                      f"owned by the invoking uid or uid {C.LAB_UID}; not world-writable",
                      "register item 7; LAB_UID convention (scripts/r2c_cpu.py:59)", dep), perms)

        def space():
            if path is None:
                return undecided()
            if h.lstat(path) is None:
                return bad(path, "does not exist", "owner creates the staging directory")
            free = h.free_bytes(path)
            return ok(free) if free >= DISK_FREE_MIN else bad(free, "below 20 GiB", "free space on the staging fs")
        self.add(Spec("STG-FREE-SPACE", "Free space on the staging filesystem", "staging",
                      f">= {DISK_FREE_MIN} bytes (20 GiB)", "draft §9 (disk >= 20 GiB free); register U-6 estimate "
                      "1.5-2.1 GB raw data", dep + ("FZ-SAFETY-CHECKLIST",)), space)

    # -- integrity and provenance
    def integrity_checks(self):
        def head():
            r = self.git("rev-parse", "HEAD")
            return ok(r[1].strip()) if r and r[0] == 0 else unverified(None, "git rev-parse failed", "re-run")
        self.add(Spec("INT-HEAD", "Repository HEAD (recorded)", "integrity", "none (record only)", "git",
                      mandatory=False), head)

        def clean():
            r = self.git("status", "--porcelain", "--untracked-files=no")
            if r is None or r[0] != 0:
                return unverified(None, "git status failed", "re-run")
            return ok("clean") if not r[1].strip() else bad(r[1].splitlines()[:20], "tracked files modified",
                                                            "commit or revert tracked changes")
        self.add(Spec("INT-REPO-CLEAN", "No uncommitted tracked change", "integrity", "git status (tracked) empty",
                      "tests/faultlab/test_r2e.py (untracked-files=no must be empty); draft §9"), clean)

        def checker():
            v = self.integrity()
            if not isinstance(v, list):
                return unverified(v, "integrity checker returned no violation list", "investigate")
            return ok([]) if not v else bad(v[:20], "integrity policy violated", "resolve before any run")
        self.add(Spec("INT-INTEGRITY-POLICY", "Live integrity policy holds", "integrity", "no violation",
                      "tests/faultlab/_integrity.py check(); tests/faultlab/test_integrity.py LIVE (AMD-18..)"),
                 checker)

        def baseline():
            v = self.decisions.get("FZ-M4-BASELINE", {}).get("value")
            if not self.approved["FZ-M4-BASELINE"][0]:
                return Result("BLOCKED", None, "no approved M4 baseline commit", "Owner decision on FZ-M4-BASELINE")
            r = self.git("merge-base", "--is-ancestor", v["commit"], "HEAD")
            if r is None or r[0] not in (0, 1):
                return unverified(v["commit"], "ancestry could not be determined (unknown commit?)", "check the SHA")
            return ok(v["commit"]) if r[0] == 0 else bad(v["commit"], "HEAD does not descend from the approved "
                                                         "M4 commit", "check out an approved descendant")
        self.add(Spec("INT-M4-BASELINE", "HEAD descends from the approved M4 commit", "integrity",
                      "git merge-base --is-ancestor <approved commit> HEAD", "draft §9 preflight item 1",
                      ("FZ-M4-BASELINE",)), baseline)

    def baseline_checks(self):
        h = self.host

        def baseline():
            snap = h.snapshot()
            net = {k: snap.get(k) is not None for k in ("links", "addrs", "routes4", "routes6", "qdiscs")}
            obs = {"network_captured": net, "bpf_captured": bool(snap.get("bpf_available")),
                   "cgroup_dirs": len(snap.get("cgroup_dirs") or [])}
            if not all(net.values()):
                return unverified(obs, "network state not fully captured", "re-run on the lab host")
            if not snap.get("bpf_available"):
                return unverified(obs, "BPF programs, links and maps not readable (needs root)",
                                  "Gate 2: re-run through sudo from uid 1000")
            return ok(obs)
        self.add(Spec("LAB-HOST-BASELINE", "Host-state baseline capturable (incl. BPF)", "lab",
                      "R2-C host_snapshot with network state and BPF inventory captured",
                      "scripts/r2c_cpu.py host_snapshot/compare_host; register FZ-EXCLUSIONS"), baseline)

        def verifier():
            probe = Path("/nonexistent/sentinelai-preflight-manifest-probe")
            problems = self.manifest_verifier(probe)
            if not isinstance(problems, list) or not problems:
                return bad(problems, "the manifest verifier accepted a run directory that does not exist",
                           "fix the manifest verifier")
            return ok(problems[:3])
        self.add(Spec("INT-MANIFEST-VERIFIER", "Manifest verifier present and fail-closed", "integrity",
                      "rehearsal.verify_manifest importable; it reports problems for a missing run (read-only probe)",
                      "experiments/faultlab/rehearsal.py verify_manifest; register FZ-MANIFEST"), verifier)

    # -- report
    def run(self) -> dict:
        self.checks = []
        self.load_decisions()
        self.approval_checks()
        self.environment_checks()
        self.lab_checks()
        self.resource_checks()
        self.staging_checks()
        self.integrity_checks()
        self.baseline_checks()
        try:
            snap = self.host.snapshot()
            observed = {"digest_sha256": hashlib.sha256(json.dumps({k: v for k, v in snap.items() if k != "dynamic"},
                                                                   sort_keys=True).encode()).hexdigest(),
                        "network_captured": all(snap.get(k) is not None for k in ("links", "addrs", "routes4",
                                                                                   "routes6", "qdiscs")),
                        "bpf_captured": bool(snap.get("bpf_available")),
                        "root": snap.get("root"), "netns": snap.get("netns"), "run_netns": snap.get("run_netns"),
                        "cgroup_dirs": len(snap.get("cgroup_dirs") or [])}
        except Exception as exc:   # noqa: BLE001  (recorded state is informational; failure is reported, not hidden)
            observed = {"error": f"{type(exc).__name__}: {exc}"}
        return report(self.checks, self.clock(), observed, self.stage)


def expected_ids(stage: str = "full") -> List[str]:
    ids = ["PROV-DECISIONS-RECORD"] + [f"APPR-{d}" for d in DECISIONS if stage == "full" or d not in FULL_ONLY]
    ids += ["ENV-KERNEL", "ENV-KERNEL-TOOLING", "ENV-BTF", "ENV-CGROUP2"] + [t for t, _ in TOOLS + PATH_TOOLS]
    ids += ["ENV-PRIVILEGE", "LAB-NETNS-SUPPORT", "LAB-VETH-AVAILABLE", "LAB-NETEM-AVAILABLE", "LAB-ROOT-SUBTREE",
            "LAB-ROOT-CPUSET", "LAB-CPUS-ONLINE", "LAB-CPU18-NO-SMT", "LAB-NIC-IRQ", "LAB-PROTECTED-IFACES",
            "LAB-DEFAULT-ROUTE", "LAB-NO-NETEM", "LAB-IP-FORWARD", "LAB-NO-SENTINEL-NETNS", "LAB-NO-LAB-INTERFACES",
            "LAB-NO-SENTINEL-CGROUP", "LAB-NO-LAB-PROCESS", "LAB-RUN-DIR-ABSENT", "LAB-WS-SCRATCH-ABSENT",
            "LAB-NO-SENTINEL-BPF",
            "LAB-LAB-UID", "LAB-OPENVPN-DISABLED", "RES-MEM-AVAILABLE", "RES-DISK-REPO", "STG-EXISTS",
            "STG-PERSISTENT", "STG-PERMISSIONS", "STG-FREE-SPACE", "INT-REPO-CLEAN", "INT-INTEGRITY-POLICY",
            "INT-M4-BASELINE", "LAB-HOST-BASELINE", "INT-MANIFEST-VERIFIER"]
    return ids


MANDATORY_IDS = frozenset(expected_ids("full"))

# Host-state invariants of the future run (documentation of what must be captured and compared; nothing here is
# collected by the preflight except the 'preflight' category, which is observed now and guarantees nothing later).
INVARIANTS = {
    "preflight": ["root cgroup files (cpuset.cpus.effective, cgroup.subtree_control, cpuset.mems.effective)",
                  "cgroup directory list", "named network namespaces (/run/netns, ip netns)",
                  "interfaces, addresses, IPv4/IPv6 routes (ip -j)", "qdiscs (tc -j)", "R2 sysctl set",
                  "IRQ affinities", "mounts (findmnt)", f"{RUN_LAB} absence", "MemAvailable", "free disk"],
    "before_run": ["full scripts/r2c_cpu.py host_snapshot with BPF programs, links and maps (needs root)",
                   "scripts/safety_check.sh (not read-only: writes logs/; also covers the SSH recovery path)",
                   "re-run of every LAB-* check immediately before setup", "host /proc/vmstat oom_kill baseline"],
    "after_run": ["compare_host(base, after, require_bpf=True): every key in its 'must' list",
                  "cleanup verification (draft §5.9): no sentinel cgroup, netns, interface, process or BPF object; "
                  f"{RUN_LAB} removed", "oom_kill delta 0; swap I/O and PSI abort criteria (R2-C run.json criteria)"],
    "not_guaranteed": ["kernel module state: veth and sch_netem are loaded on first use and stay loaded "
                       "(not in compare_host)", "dynamic counters (PSI, /proc/stat, /proc/vmstat, interface "
                       "statistics)", "page cache, slab and memory fragmentation", "kernel log and journal entries",
                       "BPF JIT memory after unload", "CPU frequency and thermal state"],
}


def report(checks: List[Check], generated: str, observed: dict, stage: str = "full") -> dict:
    mandatory_ids = frozenset(expected_ids(stage))
    ids = [c.id for c in checks]
    problems = []
    dup = sorted({i for i in ids if ids.count(i) > 1})
    missing = sorted(mandatory_ids - set(ids))
    if dup or missing:
        problems.append(f"duplicated {dup}, missing {missing}")
    for c in checks:
        if c.status not in STATUSES:
            problems.append(f"{c.id}: invalid status {c.status!r}")
        if c.id in mandatory_ids and not c.mandatory:
            problems.append(f"{c.id}: mandatory check marked optional")
    if problems:
        checks = checks + [Check("PF-COMPLETENESS", "Every mandatory check present exactly once", "integrity", True,
                                 "FAIL", problems, "each mandatory id exactly once, valid status",
                                 "experiments/faultlab/preflight.py MANDATORY_IDS", "; ".join(problems),
                                 "fix the preflight")]
    mand = [c for c in checks if c.mandatory]
    ready = all(c.status == "PASS" for c in mand) and not problems
    owner = sorted(c.id for c in mand if c.status == "BLOCKED" and (c.category == "approval" or c.blocked_by
                                                                      or c.id == "PROV-DECISIONS-RECORD"))
    env = sorted(c.id for c in mand if c.category in ("environment", "lab", "resources", "staging")
                 and (c.status in ("FAIL", "UNVERIFIED") or c.evaluation in ("FAIL", "UNVERIFIED")))
    tech = sorted(c.id for c in mand if c.category in ("integrity", "provenance")
                  and c.status in ("FAIL", "UNVERIFIED"))
    counts = {s: sum(1 for c in mand if c.status == s) for s in STATUSES}
    return {
        "format": FORMAT, "generated_utc": generated, "stage": stage,
        "overall": "READY" if ready else "NOT_READY",
        "authorises_run": False,
        "note": "READY is not authorisation: the privileged pilot needs a separate owner authorisation (Gate 2).",
        "mandatory_counts": counts,
        "blockers": {"owner_approval": owner, "environment": env, "technical": tech},
        "checks": [asdict(c) for c in checks],
        "host_state": {"observed_now": observed,
                       "caveat": "Observed current state only. It says nothing about the state during or after a "
                                 "future run; the preflight is read-only, the future run is not."},
        "invariants": INVARIANTS,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--decisions", help="committed Freeze-1 decisions record (repository file)")
    ap.add_argument("--stage", choices=STAGES, default="full",
                    help="ctrl: lab lifecycle and CTRL runs only; full: every pilot class (default)")
    ap.add_argument("--summary", action="store_true", help="one line per check on stderr")
    a = ap.parse_args(argv)
    rep = Preflight(ReadOnlyHost(), a.decisions, stage=a.stage).run()
    sys.stdout.write(json.dumps(rep, indent=1, sort_keys=True, default=str) + "\n")
    if a.summary:
        for c in rep["checks"]:
            print(f"{c['status']:<10} {'M' if c['mandatory'] else '-'} {c['id']}", file=sys.stderr)
        print(f"overall {rep['overall']} {rep['mandatory_counts']}", file=sys.stderr)
    return 0 if rep["overall"] == "READY" else 1


if __name__ == "__main__":
    sys.exit(main())
