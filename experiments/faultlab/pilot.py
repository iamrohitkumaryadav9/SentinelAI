#!/usr/bin/env python3
"""SentinelAI Phase 1C FaultLab pilot driver (Gate 2): PI-0 lab lifecycle and CTRL runs in the A–R–B lab, as root.

    sudo taskset -c 0-15 .venv/bin/python experiments/faultlab/pilot.py lifecycle --campaign <UTC> --cycle K --execute
    sudo taskset -c 0-15 .venv/bin/python experiments/faultlab/pilot.py ctrl --campaign <UTC> --seed N --execute
    sudo taskset -c 0-15 .venv/bin/python experiments/faultlab/pilot.py {pi1u|pi6off|instoff} --campaign <UTC> --seed N --execute
    .venv/bin/python experiments/faultlab/pilot.py evaluate <campaign dir>/<run>
    .venv/bin/python experiments/faultlab/pilot.py pairs <campaign dir>
    sudo .venv/bin/python experiments/faultlab/pilot.py cleanup <campaign dir>

Before any host mutation every privileged invocation refuses unless: root via sudo from uid 1000, confined to CPUs
0-15, and a fresh in-process privileged preflight (experiments/faultlab/preflight.py, --stage ctrl, the committed
decisions record) is READY; the commit recorded is the preflight's HEAD. `ctrl` also refuses unless the same campaign
holds PI-0 cycles 1-5, all ok, at the same commit (draft §6.1: nothing else runs until PI-0 passes); so do pi1u,
pi6off and instoff. Output goes to <FZ-STAGING path>/<campaign>/{PI0-K | CTRL-N | PI1U-N | PI6OFF-N | INSTOFF-N} and
is handed to the invoking user at the end.

  lifecycle --cycle K   PI-0: lab cgroup + A–R–B lab + app directory created, checked (structure, forwarding only in R,
                        no external path, ping both ways, TCP echo A->B), removed; cleanup verified; host compared with
                        the pre-cycle snapshot, BPF included
  ctrl --seed N         one CTRL run: dependency peer and load generator in B, workload in A (target leaf, CPU 18),
                        M3A + M3B + app collection over B 45 s + W 90 s after a 15 s warm-up, 20 s cool-down; evidence,
                        manifest, replay, client/server and across-R reconciliation, PI-1 / PI-6 / PI-7 (CTRL part)
  pi1u --seed N         PI-1 unprivileged mode: as ctrl, but M3A + app are collected by a child running as the lab uid
                        with no capabilities (no eBPF: the loader needs root); netns verified from that child
  pi6off --seed N       PI-6 collectors off: as ctrl with no collector and no loader (pair it with ctrl at the same seed)
  instoff --seed N      instrumentation off: as pi6off with the workload's metrics writer off (pair with pi6off)
  pairs DIR             offline: PI-6 and instrumentation pairs of a campaign, client-side differences, report-only
  evaluate DIR          offline (no root): every check recomputed from the saved evidence of a ctrl run
  cleanup DIR           idempotent cleanup from every op log under a campaign (after an interrupted invocation)

Values come only from approved decisions (docs/PHASE_1C_FREEZE1_DECISIONS.json); the driver refuses otherwise. M2 is
never invoked on pilot data (design §13 decision 7). Lab operations go through lab.Host only. The fault classes
(FZ-INTENSITY, FZ-PI5 pending) are not implemented here.
"""
import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab as L  # noqa: E402
from lab import C  # noqa: E402

FORMAT = "sentinelai.faultlab.pilot.ctrl.v1"
DECISIONS = ROOT / "docs/PHASE_1C_FREEZE1_DECISIONS.json"
CAMPAIGN = re.compile(r"[0-9]{8}T[0-9]{6}Z")
RUN_NAME = r"PI0-[1-5]|(?:CTRL|PI1U|PI6OFF|INSTOFF|PI8)-9[0-9]{5}"   # one directory per run (AMD-27/28 evidence names)
EVIDENCE_MAX = 64 << 20                                           # bytes read back from a lab-uid file
PERIOD_S = 1.0
WARMUP_S, B_S, W_S, COOLDOWN_S = 15, 45, 90, 20                   # design §6.2 timeline
SEED_MIN, SEED_MAX = 900000, 909999                               # pilot seed range (draft §7)
EVIDENCE, MANIFEST = "evidence", "manifest.json"
READY_TIMEOUT_S, LAB_SETTLE_MAX_S, DRAIN_MAX_S = 10.0, 3.0, 15.0
WORKLOAD_READY_TIMEOUT_S = 60.0                                   # writes and fsyncs its 1 GiB working set first
COVERAGE_MIN = 0.99                                               # PI-1, PI-6, PI-7 (registered / proposed)
CPU_BUDGET_CORE = 0.02                                            # PI-6 (registered "<= 2 % CPU")
PARAMS_ID = "pilot-ctrl-uncalibrated"
PIPELINE_CHECKS = frozenset({"run_completed", "cleanup", "host_compare", "bpf_released", "manifest",
                             "replay_byte_identical", "app_features", "client_server_reconciliation",
                             "across_r_reconciliation"})            # every one present and ok, nothing else


def pipeline_checks(variant: str) -> frozenset:
    """The exact check set of a variant: collected runs as CTRL; collectors off: no snapshot, so no replay and no app
    features; metrics writer off: no server documents, so the client records are checked on their own."""
    if variant == "pi8":
        return PIPELINE_CHECKS | {"injection_verified"}
    if variant in ("ctrl", "pi1u"):
        return PIPELINE_CHECKS
    off = PIPELINE_CHECKS - {"replay_byte_identical", "app_features"}
    return off if variant == "pi6off" else off - {"client_server_reconciliation"} | {"client_records"}


class Refused(SystemExit):
    pass


def refuse(msg):
    print(json.dumps({"refused": msg}), file=sys.stderr)
    raise Refused(2)


class Interrupted(BaseException):
    """SIGINT / SIGTERM: unwinds to the finally block (cleanup)."""


def on_signal(signum, frame):
    raise Interrupted(f"signal {signum}")


# ------------------------------------------------------------------------------------------ decisions
def approved_value(name, record=DECISIONS):
    """The value of an approved decision, through the preflight's strict parser; refuses otherwise."""
    import preflight as P
    dec, errs = P.parse_decisions(Path(record).read_bytes())
    if dec is None:
        refuse(f"decisions record malformed: {errs[:3]}")
    ok, why = P.decision_state(name, dec.get(name))
    if not ok:
        refuse(f"{name} is not approved ({why}); nothing was changed")
    return (dec[name] or {}).get("value")


def check_seed(seed: int):
    if not SEED_MIN <= seed <= SEED_MAX:
        refuse(f"pilot seed {seed} outside {SEED_MIN}..{SEED_MAX}")


def staging_root(record=DECISIONS) -> Path:
    v = approved_value("FZ-STAGING", record)
    p = Path(v["path"])
    if not p.is_absolute() or p.is_symlink() or not p.is_dir():
        refuse(f"staging path {p} is not an existing real directory")
    return p


def run_path(staging: Path, campaign: str, name: str) -> Path:
    """<staging>/<campaign>/<name>: the campaign is created if absent (never a symlink); the run must be new."""
    if not CAMPAIGN.fullmatch(campaign or ""):
        refuse(f"campaign {campaign!r} is not a UTC stamp YYYYMMDDTHHMMSSZ")
    if not re.fullmatch(RUN_NAME, name):
        refuse(f"run name {name!r} not allowed")
    c = staging / campaign
    if c.is_symlink() or (c.exists() and not c.is_dir()):
        refuse(f"campaign path {c} is not a real directory")
    out = c / name
    if os.path.lexists(out):
        refuse(f"{out} already exists; a run directory is never reused")
    return out


def read_regular(path, limit=EVIDENCE_MAX) -> bytes:
    """A regular file written by the lab uid, read without following a symlink, at most `limit` bytes."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise L.LabAbort(f"{path}: not a regular file of at most {limit} bytes")
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise L.LabAbort(f"{path}: larger than {limit} bytes")
        return data
    finally:
        os.close(fd)


def require_preflight(run_preflight=None) -> dict:
    """A fresh privileged preflight (--stage ctrl, committed decisions record) must be READY; returns its report."""
    import preflight as P
    rep = (run_preflight or (lambda: P.Preflight(P.ReadOnlyHost(), str(DECISIONS), stage="ctrl").run()))()
    if rep.get("overall") != "READY":
        bad = [f"{c['id']}={c['status']}" for c in rep.get("checks", []) if c.get("mandatory") and
               c.get("status") != "PASS"]
        refuse(f"privileged preflight is not READY: {bad[:12]}")
    head = next((c.get("observed") for c in rep["checks"] if c["id"] == "INT-HEAD"), None)
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        refuse("preflight did not record HEAD")
    return rep


def require_pi0(campaign_dir: Path, commit: str):
    """CTRL only after PI-0 cycles 1-5 all ok in the same campaign at the same commit."""
    for k in range(1, 6):
        f = campaign_dir / f"PI0-{k}" / "run.json"
        try:
            r = json.loads(read_regular(f, 16 << 20))
        except (OSError, ValueError, L.LabAbort) as exc:
            refuse(f"PI-0 cycle {k} has no readable result ({exc}); CTRL needs 5/5 PI-0 cycles first")
        if r.get("ok") is not True or r.get("commit") != commit:
            refuse(f"PI-0 cycle {k} not ok at commit {commit[:12]}; CTRL needs 5/5 PI-0 cycles first")


def hand_over(path: Path):
    """Give the run directory (created by this root process) to the invoking user; symlinks are never followed."""
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    for d, dirs, files in os.walk(path, followlinks=False):
        os.lchown(d, uid, gid)
        for n in dirs + files:
            os.lchown(os.path.join(d, n), uid, gid)


def check_invocation():
    if os.geteuid() != 0 or os.environ.get("SUDO_UID") != str(C.LAB_UID) or \
            not (os.environ.get("SUDO_GID") or "").isdigit():
        refuse(f"must run as root via sudo from uid {C.LAB_UID}")
    if not set(os.sched_getaffinity(0)) <= set(L.DRIVER_CPUS):
        refuse("driver must be confined to CPUs 0-15 (taskset)")


# ------------------------------------------------------------------------------------------ parameters
def pilot_params():
    """Uncalibrated validation numbers (registry) with the design timeline B = 45 s, W = 90 s and positive floors for
    every collected feature. Snapshots are built for coverage and quality only; M2 never runs on them."""
    from sentinelai.collectors.snapshot import collected_features
    from sentinelai.diagnostic.rules.params import ParameterSet
    from sentinelai.runtime import registry
    base = registry.get("r2c-validation-uncalibrated")
    nums = dict(base.numbers)
    for f in collected_features(True, True):
        nums.setdefault(f"floor[{f}]", 0.001)
    nums.update(B=float(B_S), W=float(W_S))
    return ParameterSet(parameter_set_id=PARAMS_ID, numbers=nums, reason_sets=dict(base.reason_sets))


# ------------------------------------------------------------------------------------------ small helpers
def write_new(path: Path, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def dump(obj) -> bytes:
    return (json.dumps(obj, indent=1, sort_keys=True, default=str) + "\n").encode()


def wait_for(pred, timeout_s, procs=(), sleep=time.sleep):
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        for name, p in procs:
            if p.poll() is not None:
                raise L.LabAbort(f"{name} exited during startup (rc {p.returncode})")
        if pred():
            return True
        sleep(0.05)
    return False


def leaf_pids(sysr, leaf):
    t = sysr.read(f"{L.LEAVES[leaf]}/cgroup.procs")
    return sorted(int(x) for x in (t or "").split())


def settle(sysr, attempts, after_forward=True, clock=time.monotonic, sleep=time.sleep):
    """Bounded read-only re-inspection (R2-E pattern): every raw inspection is kept; PASS ends the loop."""
    t0 = clock()
    while True:
        raw = L.lab_state(sysr)
        checks = L.lab_checks(raw, after_forward)
        fails = L.failures(checks)
        attempts.append({"mono": clock(), "raw": raw, "checks": checks, "failures": fails})
        if not fails:
            return True
        if clock() - t0 >= LAB_SETTLE_MAX_S:
            return False
        sleep(0.1)


def setup_lab(host, sysr, R, run_id=None):
    for op in L.cgroup_plan():
        host.apply(op)
    R["verify_cgroups"] = L.verify_cgroups(sysr)
    if not all(R["verify_cgroups"].values()):
        raise L.LabAbort(f"cgroup verification failed: {L.failures(R['verify_cgroups'])}")
    plan = L.lab_plan()
    host.apply(plan[0])                                     # first ip netns add: Host records /run/netns around it
    own = L.netns_mount_owner(L.read_oplog(host.oplog))
    R["netns_dir_mount"] = {"owned": own["owned"], "error": own["error"],
                            "pre_existing": [L._identity(m) for m in (own["before"] or {}).get("at", [])]}
    if own["error"]:
        raise L.LabAbort(own["error"])
    for op in plan[1:]:
        host.apply(op)
    for ns in L.LAB_NETNS:                                  # A 0, R 1, B 0: never inherited from the host
        ino = sysr.netns_inode(ns)
        if ino is None:
            raise L.LabAbort(f"{ns} missing after creation")
        host.apply(("forward", ns, ino))
    R["lab_settle"] = []
    if not settle(sysr, R["lab_settle"]):
        raise L.LabAbort(f"lab checks failed: {R['lab_settle'][-1]['failures']}")
    R["ping"] = {k: sysr.probe(argv) for k, argv in L.PING.items()}
    if not all(L.ping_ok(v) for v in R["ping"].values()):
        raise L.LabAbort(f"ping across R failed: {R['ping']}")
    if run_id is not None:
        for op in L.app_plan(run_id):
            host.apply(op)


def finish(host, sysr, base, R, run_id, after_procs=None):
    """Cleanup (always), cleanup verification and the host comparison with the pre-run snapshot."""
    R["cleanup"] = L.cleanup(host, sysr, L.read_oplog(host.oplog), run_id, after_procs=after_procs)
    after = L.host_snapshot(sysr)
    R["host_compare"] = L.compare_host(base, after)
    return after


# ------------------------------------------------------------------------------------------ PI-0
def lifecycle(out: Path, cycle: int, commit: str, sysr=None, host_cls=None, sleep=time.sleep) -> int:
    sysr = sysr or L.Sys()
    run_id = f"PI0-s{cycle}"
    echo = L.echo_argvs()
    plan = L.Plan(run_id, spawns=[("echo_server", echo["echo_server"]), ("echo_client", echo["echo_client"])])
    out.mkdir(mode=0o755)
    host = (host_cls or L.Host)(plan, str(out / "ops.jsonl"), sysr)
    R = {"stage": "PI-0", "cycle": cycle, "commit": commit, "aborts": [], "events": []}
    base = L.host_snapshot(sysr)
    write_new(out / "host_before.json", dump(base))
    R["preflight"] = L.preflight(sysr)
    if not R["preflight"]["ok"] or not base["bpf_available"]:
        write_new(out / "run.json", dump(R))
        refuse(f"pre-setup checks failed: {R['preflight']}; bpf_available={base['bpf_available']}")
    old = {s: signal.signal(s, on_signal) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        setup_lab(host, sysr, R, run_id)
        logs = {}
        for role in ("echo_server", "echo_client"):
            logs[role] = (out / f"{role}.stderr").open("wb")
        srv = host.apply(("spawn", "echo_server", echo["echo_server"]), stderr=logs["echo_server"])
        sleep(0.3)
        cli = host.apply(("spawn", "echo_client", echo["echo_client"]), stderr=logs["echo_client"])
        R["tcp_echo_rc"] = {"client": cli.wait(15), "server": srv.wait(15)}
        if R["tcp_echo_rc"] != {"client": 0, "server": 0}:
            raise L.LabAbort(f"TCP echo A->B failed: {R['tcp_echo_rc']}")
        st = sysr.lstat_run(L.run_dir(run_id))
        R["app_dir"] = {"exists": st is not None and stat.S_ISDIR(st.st_mode),
                        "owner_uid": None if st is None else st.st_uid}
        if R["app_dir"] != {"exists": True, "owner_uid": C.LAB_UID}:
            raise L.LabAbort(f"app directory not as specified: {R['app_dir']}")
    except (L.LabAbort, L.LabRefused, Interrupted, Exception) as exc:     # noqa: BLE001 -- abort, then cleanup
        R["aborts"].append(f"{type(exc).__name__}: {exc}")
    finally:
        for s in old:
            signal.signal(s, signal.SIG_IGN)
        after = finish(host, sysr, base, R, run_id)
        write_new(out / "host_after.json", dump(after))
        for s, h in old.items():
            signal.signal(s, h)
    R["ok"] = not R["aborts"] and R["cleanup"]["ok"] and R["host_compare"]["ok"]
    write_new(out / "run.json", dump(R))
    print(json.dumps({"stage": "PI-0", "cycle": cycle, "ok": R["ok"], "aborts": R["aborts"][:3],
                      "cleanup_ok": R["cleanup"]["ok"], "host_ok": R["host_compare"]["ok"]}))
    return 0 if R["ok"] else 1


# ------------------------------------------------------------------------------------------ faults (PI-8)
# fault type -> (control key, FZ-INTENSITY-APP candidate list, workload histogram of its wait metric, echo file,
#                stronger magnitude is: "lower" (pool) or "higher")
APP_FAULTS = {"app_pool": ("pool", "pool_candidates", "queue_wait", "config.json", "lower"),
              "app_lock": ("lock_hold_us", "lock_hold_us_candidates", "lock_wait", "config.json", "higher"),
              "app_dependency_delay": ("dependency_delay_ms", "dependency_delay_ms_candidates", "dependency_latency",
                                       "dependency_config.json", "higher")}
T_CAP_S = 30.0                                                    # FZ-TTRANS T_cap: read-back after it = failed


def fault_spec(fault: str, magnitude: int, w: dict, decisions=DECISIONS) -> dict:
    """An application fault at an approved PI-8 candidate magnitude (FZ-INTENSITY-APP); refuses anything else."""
    if fault not in APP_FAULTS:
        refuse(f"fault {fault!r} is not implemented (application faults only: {sorted(APP_FAULTS)})")
    key, cands, hist, echo, stronger = APP_FAULTS[fault]
    app = approved_value("FZ-INTENSITY-APP", decisions)
    if type(magnitude) is not int or magnitude not in app[cands]:
        refuse(f"{fault} magnitude {magnitude!r} is not an approved candidate {app[cands]}")
    control = {"dependency_delay_ms": int(w["dependency_delay_ms"]), key: magnitude}
    return {"type": fault, "key": key, "magnitude": magnitude, "candidates": app[cands], "metric_histogram": hist,
            "echo_file": echo, "stronger": stronger, "control": control, "decision": "FZ-INTENSITY-APP"}


class WindowHook:
    """Wraps the app source of collect(). After tick nB is collected (the B/W boundary, run time 60 s; AMD-10) it
    reads the raw metrics document and then issues the fault, if any; after tick nB + nW it reads the raw document
    again. Effect ground truth for application faults is computed from these documents, never from features."""

    def __init__(self, app, nB: int, nW: int, read_raw, inject=None):
        self.app, self.nB, self.nW, self.read_raw, self.inject = app, nB, nW, read_raw, inject
        self.k, self.docs = 0, {}

    def sample(self):
        obs = self.app.sample()
        if self.k in (self.nB, self.nB + self.nW):
            self.docs["w_start" if self.k == self.nB else "w_end"] = (time.monotonic_ns(), self.read_raw())
        if self.k == self.nB and self.inject is not None:
            self.inject(self.k)
        self.k += 1
        return obs


class Injector:
    """Issues one application fault through replace_control and watches its echo (read-back) on a thread."""

    def __init__(self, host, sysr, run_id: str, spec: dict, clock_ns=time.monotonic_ns, poll_s: float = 0.01):
        self.host, self.sysr, self.run_id, self.spec, self.clock_ns, self.poll_s = \
            host, sysr, run_id, spec, clock_ns, poll_s
        self.record = {"type": spec["type"], "magnitude": spec["magnitude"], "issued": False, "verified": False}
        self.thread = None

    def __call__(self, tick: int):
        r = self.record
        r["issue_mono_ns"], r["issue_after_tick"] = self.clock_ns(), tick
        try:
            self.host.apply(("replace_control", json.dumps(self.spec["control"], sort_keys=True).encode()))
            r["issued"] = True
        except Exception as exc:                                       # noqa: BLE001 -- failed_injection
            r["issue_error"] = f"{type(exc).__name__}: {exc}"
            return
        self.thread = threading.Thread(target=self.watch, daemon=True)
        self.thread.start()

    def echo_value(self):
        try:
            doc = json.loads(self.sysr.read_run(f"{L.run_dir(self.run_id)}/{self.spec['echo_file']}", 1 << 20))
            return doc["config"].get(self.spec["key"]), doc.get("control_error")
        except Exception:                                              # noqa: BLE001 -- mid-publish: retry
            return None, None

    def watch(self):
        r, end = self.record, self.record["issue_mono_ns"] + int(T_CAP_S * 1e9)
        while self.clock_ns() < end:
            value, err = self.echo_value()
            if value == self.spec["magnitude"] and err is None:
                r["readback_mono_ns"] = self.clock_ns()
                r["readback_latency_s"] = (r["readback_mono_ns"] - r["issue_mono_ns"]) / 1e9
                r["verified"] = True
                return
            time.sleep(self.poll_s)
        r["readback_error"] = f"no echo of {self.spec['key']} = {self.spec['magnitude']} within {T_CAP_S} s"

    def join(self, timeout: float):
        if self.thread is not None:
            self.thread.join(timeout)


# ------------------------------------------------------------------------------------------ CTRL
class LoaderTicks:
    """The eBPF source for collect(); keeps every raw loader line."""

    def __init__(self, loader):
        self.loader = loader

    def sample(self):
        return self.loader.sample()


def proc_cpu_s(pid) -> float:
    f = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")


# variant -> run-name prefix, collector mode (root driver, unprivileged child, none), eBPF loader, workload metrics writer
VARIANTS = {
    "ctrl": {"prefix": "CTRL", "collector": "root", "ebpf": True, "metrics_writer": True},             # design §6.2
    "pi1u": {"prefix": "PI1U", "collector": "unprivileged", "ebpf": False, "metrics_writer": True},     # PI-1 §6.2
    "pi6off": {"prefix": "PI6OFF", "collector": None, "ebpf": False, "metrics_writer": True},           # PI-6 §6.7
    "instoff": {"prefix": "INSTOFF", "collector": None, "ebpf": False, "metrics_writer": False},        # §5.5
    "pi8": {"prefix": "PI8", "collector": "root", "ebpf": True, "metrics_writer": True},                 # §6.9
}
COLLECTOR_DIR, CHILD_TICKS, CHILD_STATS = "collector", "child_ticks.jsonl", "child_stats.json"
CHILD_TIMEOUT_S = B_S + W_S + 60                                  # collection (B + W + 1 ticks) plus start-up margin


def collector_argv(run_id: str, out_dir: Path) -> list:
    """The unprivileged collector child (PI-1): this file, isolated interpreter, run as the lab uid (no capabilities)."""
    return [sys.executable, "-I", str(Path(__file__).resolve()), "collect-child", "--run-id", run_id,
            "--out-dir", str(out_dir)]


def spawn_collector(argv, cwd: Path, stderr):
    """The driver's own child (like the eBPF loader, it is not a lab role): uid/gid = the lab uid, no supplementary
    groups, a minimal environment, inheriting the driver's CPUs 0-15."""
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr,
                            user=C.LAB_UID, group=C.LAB_GID, extra_groups=[], env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                            cwd=str(cwd), close_fds=True, start_new_session=True, shell=False)


def collect_child(run_id: str, out_dir: Path) -> int:
    """Runs as the lab uid: resolve the target, read its netns link, collect M3A + app over B + W (no eBPF: the loader
    needs root), and write child_ticks.jsonl and child_stats.json into out_dir. Refuses with any privilege."""
    from sentinelai.collectors import LiveReader, SystemClock, collect, resolve_target
    from sentinelai.collectors import app as appmod
    from sentinelai.runtime.ticks import encode_ticks
    status = Path("/proc/self/status").read_text()
    ident = {"uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(), "egid": os.getegid(),
             "groups": sorted(os.getgroups()),
             "cap_eff": next((l.split()[1] for l in status.splitlines() if l.startswith("CapEff:")), None)}
    if (ident["uid"], ident["euid"], ident["gid"], ident["egid"]) != (C.LAB_UID,) * 4 or \
            ident["cap_eff"] != "0" * 16 or ident["groups"] not in ([], [C.LAB_GID]):
        print(json.dumps({"refused": "collector child is not the unprivileged lab uid", **ident}), file=sys.stderr)
        return 3
    target = resolve_target(LiveReader(), "faultlab-ctrl", L.TARGET_CGROUP_PATH)
    try:
        link = os.readlink(f"/proc/{target.pids[0]}/ns/net")
    except OSError as exc:
        link = f"unreadable: {exc.strerror}"
    ticks, stats = collect(target, pilot_params(), LiveReader(), SystemClock(), PERIOD_S, None, appmod.AppSource(run_id))
    write_new(out_dir / CHILD_TICKS, encode_ticks(ticks))
    write_new(out_dir / CHILD_STATS, dump({**ident, "netns_link": link, "target_doc": target.model_dump(mode="json"),
                                           "ticks": stats.ticks, "wall_s": stats.wall_s, "cpu_s": stats.cpu_s,
                                           "max_rss_kb": stats.max_rss_kb, "max_tick_read_s": stats.max_tick_read_s}))
    return 0


def ctrl(out: Path, seed: int, commit: str, decisions=DECISIONS, sysr=None, host_cls=None,
         sleep=time.sleep, variant: str = "ctrl", child_spawn=None, fault=None) -> int:
    from sentinelai.collectors import LiveReader, SystemClock, build_snapshot, collect, resolve_target
    from sentinelai.collectors import app as appmod
    from sentinelai.diagnostic.contract import Target, canonical_bytes
    from sentinelai.ebpf import loader_argv, resolve_ebpf_target
    from sentinelai.runtime.pipeline import validate_snapshot
    from sentinelai.runtime.ticks import decode_ticks, encode_ticks
    from m3b_r1_validate import Recording

    v = VARIANTS[variant]
    check_seed(seed)
    w = approved_value("FZ-WORKLOAD", decisions)
    ws = approved_value("FZ-WORKSET", decisions)["values"]           # D4: always present (approved 2026-10-12)
    arr = approved_value("FZ-ARRIVALS", decisions)                   # Poisson arrivals (approved 2026-10-12)
    if (variant == "pi8") != (fault is not None):
        refuse("a pi8 run needs exactly one fault; other variants take none")
    spec = fault_spec(fault[0], fault[1], w, decisions) if fault is not None else None
    run_id = f"{v['prefix']}-s{seed}"
    load_s = WARMUP_S + B_S + W_S + COOLDOWN_S
    unpriv, writer = v["collector"] == "unprivileged", v["metrics_writer"]
    out.mkdir(mode=0o755)
    for d in (EVIDENCE, "logs", "lg") + ((COLLECTOR_DIR,) if unpriv else ()):
        (out / d).mkdir(mode=0o755)
    os.chown(out / "lg", C.LAB_UID, C.LAB_GID)                        # the load generator (uid 1000) writes here
    if unpriv:
        os.chown(out / COLLECTOR_DIR, C.LAB_UID, C.LAB_GID)           # the unprivileged collector writes here
    client_tmp = out / "lg" / "client.jsonl"
    argv = {"dependency": L.dependency_argv(run_id, w), "workload": L.workload_argv(run_id, w, writer, ws),
            "loadgen": L.loadgen_argv(w, load_s, seed, str(client_tmp), arr)}
    sysr = sysr or L.Sys()
    host = (host_cls or L.Host)(L.Plan(run_id, spawns=argv.items()), str(out / "ops.jsonl"), sysr)
    ev = out / EVIDENCE
    R = {"format": FORMAT, "stage": "CTRL" if variant == "ctrl" else variant.upper(), "variant": variant,
         "collector_mode": v["collector"], "ebpf": v["ebpf"], "metrics_writer": writer, "working_set": ws,
         "fault": spec, "arrivals": arr,
         "run_id": run_id, "seed": seed, "commit": commit, "workload": w,
         "timeline": {"warmup_s": WARMUP_S, "B_s": B_S, "W_s": W_S, "cooldown_s": COOLDOWN_S, "load_s": load_s,
                      "period_s": PERIOD_S},
         "lab": {"netns": L.LAB_NETNS, "cgroup": L.LAB_DIR, "target_cpu": L.TARGET_CPU,
                 "support_cpus": L.SUPPORT_CPUS}, "aborts": [], "events": [], "exit_codes": {}}
    evt = lambda name, **kw: R["events"].append({"t_mono": time.monotonic(), "event": name, **kw})
    base = L.host_snapshot(sysr)
    write_new(ev / "host_before.json", dump(base))
    R["preflight"] = L.preflight(sysr)
    if not R["preflight"]["ok"] or not base["bpf_available"]:
        write_new(ev / "run.json", dump(R))
        refuse(f"pre-setup checks failed: {R['preflight']}; bpf_available={base['bpf_available']}")
    procs, loader, child, state, injector, hook = {}, None, None, {}, None, None
    read_app = (lambda: appmod.read_metrics(run_id)) if writer else (lambda: None)
    old = {s: signal.signal(s, on_signal) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        setup_lab(host, sysr, R, run_id)
        rdir = L.run_dir(run_id)
        host.apply(("write_new", f"{rdir}/control.json",
                    json.dumps({"dependency_delay_ms": int(w["dependency_delay_ms"])}).encode()))
        for role in ("dependency", "workload"):
            procs[role] = host.apply(("spawn", role, argv[role]), stderr=(out / "logs" / f"{role}.stderr").open("wb"))
            ready = f"{rdir}/" + ("dependency_config.json" if role == "dependency" else
                                  "metrics.json" if writer else "config.json")
            limit = WORKLOAD_READY_TIMEOUT_S if role == "workload" else READY_TIMEOUT_S
            if not wait_for(lambda: sysr.lstat_run(ready) is not None, limit, procs.items()):
                raise L.LabAbort(f"{role} not ready within {limit} s")
            evt(f"{role}_ready")
        tpids = leaf_pids(sysr, "target")
        if len(tpids) != 1:
            raise L.LabAbort(f"target leaf holds {tpids}: one-pid invariant broken")
        target = resolve_target(LiveReader(), "faultlab-ctrl", L.TARGET_CGROUP_PATH)
        ns_a = sysr.netns_inode(L.NS_A)
        R["target"] = {"pids": list(target.pids), "cpuset": target.cpuset,
                       "netns_inode": sysr.pid_netns_inode(tpids[0]), "lab_a_inode": ns_a}
        if list(target.pids) != tpids or ns_a is None or R["target"]["netns_inode"] != ns_a or \
                target.cpuset != str(L.TARGET_CPU):
            raise L.LabAbort(f"target not in {L.NS_A} on CPU {L.TARGET_CPU}: {R['target']}")
        if v["ebpf"]:
            ids = resolve_ebpf_target(target)
            loader = Recording(loader_argv(ids, load_s + 120), ids, 5.0)
            err = loader.start()
            if err:
                raise L.LabAbort(f"eBPF loader unavailable: {err}")
            evt("loader_started", pid=loader.proc.pid)
        read_snmp = lambda: L.tcp_counters(sysr.read(f"/proc/{tpids[0]}/net/snmp"))
        state["start"] = {"app": read_app(), "r": L.r_counters(sysr), "tcp": read_snmp(),
                          "mono_ns": time.monotonic_ns()}
        if (writer and not isinstance(state["start"]["app"], bytes)) or None in (state["start"]["r"],
                                                                                  state["start"]["tcp"]):
            raise L.LabAbort("start counters unavailable")
        procs["loadgen"] = host.apply(("spawn", "loadgen", argv["loadgen"]),
                                      stderr=(out / "logs" / "loadgen.stderr").open("wb"))
        evt("loadgen_started")
        sleep(WARMUP_S)
        params = pilot_params()
        ticks = None
        if v["collector"] == "root":
            if spec is not None:
                injector = Injector(host, sysr, run_id, spec)
            hook = WindowHook(appmod.AppSource(run_id), round(B_S / PERIOD_S), round(W_S / PERIOD_S), read_app,
                              injector)
            evt("collect_start")
            ticks, stats = collect(target, params, LiveReader(), SystemClock(), PERIOD_S, LoaderTicks(loader), hook)
            evt("collect_end")
            if injector is not None:
                injector.join(T_CAP_S + 1)
                R["injection"] = dict(injector.record)
                if R["injection"]["issued"]:
                    evt("fault_issued", mono_ns=R["injection"]["issue_mono_ns"])
            R["w_docs"] = {k: {"mono_ns": t, "valid": isinstance(b, bytes)} for k, (t, b) in hook.docs.items()}
            R["collection"] = {"ticks": stats.ticks, "wall_s": stats.wall_s, "cpu_s": stats.cpu_s,
                               "max_tick_read_s": stats.max_tick_read_s, "loader_cpu_s": proc_cpu_s(loader.proc.pid)}
        elif unpriv:
            evt("collect_start")
            child = (child_spawn or spawn_collector)(collector_argv(run_id, out / COLLECTOR_DIR), out / COLLECTOR_DIR,
                                                     (out / "logs" / "collector.stderr").open("wb"))
            try:
                R["exit_codes"]["collector"] = child.wait(CHILD_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                raise L.LabAbort("unprivileged collector did not finish") from None
            evt("collect_end")
            if R["exit_codes"]["collector"] != 0:
                raise L.LabAbort(f"unprivileged collector exited with {R['exit_codes']['collector']}")
            raw_ticks = read_regular(out / COLLECTOR_DIR / CHILD_TICKS)
            cs = json.loads(read_regular(out / COLLECTOR_DIR / CHILD_STATS, 1 << 20))
            ticks = decode_ticks(raw_ticks)
            if Target.model_validate_json(json.dumps(cs["target_doc"]), strict=False) != target:
                raise L.LabAbort("the unprivileged collector resolved a different target")
            R["collection"] = {"ticks": cs["ticks"], "wall_s": cs["wall_s"], "cpu_s": cs["cpu_s"],
                               "max_tick_read_s": cs["max_tick_read_s"], "loader_cpu_s": 0.0}
            R["unprivileged"] = {k: cs[k] for k in ("uid", "euid", "gid", "egid", "groups", "cap_eff", "netns_link")}
            R["unprivileged"]["netns_verified"] = cs["netns_link"] == f"net:[{ns_a}]"
        try:
            R["exit_codes"]["loadgen"] = procs["loadgen"].wait(load_s + 60)
        except subprocess.TimeoutExpired:
            raise L.LabAbort("load generator did not finish") from None
        if R["exit_codes"]["loadgen"] != 0:
            raise L.LabAbort(f"load generator exited with {R['exit_codes']['loadgen']}")
        evt("loadgen_finished")

        def drained():
            d = appmod.parse(appmod.read_metrics(run_id))
            return isinstance(d, appmod.AppSample) and d.pool_busy == 0
        if writer:
            if not wait_for(drained, DRAIN_MAX_S):
                raise L.LabAbort(f"workload not drained within {DRAIN_MAX_S} s")
        else:                                                     # no server document: the client records decide
            R["drain"] = "not observable (metrics writer off); client records checked in client_records"
        sleep(2 * float(w["publish_s"]))                          # one more document after the last completion
        state["end"] = {"app": read_app(), "r": L.r_counters(sysr), "tcp": read_snmp(),
                        "mono_ns": time.monotonic_ns()}
        if (writer and not isinstance(state["end"]["app"], bytes)) or None in (state["end"]["r"], state["end"]["tcp"]):
            raise L.LabAbort("end counters unavailable")
        for name in ("config.json", "dependency_config.json", "control.json"):
            write_new(ev / name, sysr.read_run(f"{rdir}/{name}", 1 << 20))
        if writer:
            write_new(ev / "app_start.json", state["start"]["app"])
            write_new(ev / "app_end.json", state["end"]["app"])
        for k, (t, b) in (hook.docs.items() if hook is not None else ()):
            if isinstance(b, bytes):                                  # W-window documents (effect ground truth)
                write_new(ev / f"app_{k}.json", b)
        write_new(ev / "counters.json", dump({k: {"r": state[k]["r"], "tcp": state[k]["tcp"],
                                                  "mono_ns": state[k]["mono_ns"]} for k in ("start", "end")}))
        write_new(ev / "client.jsonl", read_regular(client_tmp))
        R["load"] = {"arrivals": scheduled_arrivals(w, load_s, seed, arr), "duration_s": load_s, "seed": seed,
                     "process": arr["process"]}
        if ticks is not None:
            write_new(ev / "ticks.jsonl", raw_ticks if unpriv else encode_ticks(ticks))
            if unpriv:
                write_new(ev / "collector_stats.json", read_regular(out / COLLECTOR_DIR / CHILD_STATS, 1 << 20))
            R["target_doc"], R["parameter_set"] = target.model_dump(mode="json"), params.model_dump(mode="json")
            R["nB"], R["nW"] = round(B_S / PERIOD_S), round(W_S / PERIOD_S)
            snap = build_snapshot(ticks, target, params, PERIOD_S, v["ebpf"], True)
            write_new(out / "snapshot.json", validate_snapshot(canonical_bytes(snap))[1])
    except (L.LabAbort, L.LabRefused, Interrupted, Exception) as exc:     # noqa: BLE001 -- abort, then cleanup
        R["aborts"].append(f"{type(exc).__name__}: {exc}")
    finally:
        for s in old:
            signal.signal(s, signal.SIG_IGN)

        def release():
            if child is not None and child.poll() is None:            # the driver's own child, never a host process
                child.kill()
                R["exit_codes"]["collector"] = child.wait(5)
            if loader is not None:
                R["raw_ebpf_lines"] = len(loader.raw)
                write_new(ev / "ebpf.jsonl", "\n".join(l or "" for l in loader.raw).encode())
                loader.close()
            R["bpf_release"] = C.wait_bpf_released(sysr, base)
        after = finish(host, sysr, base, R, run_id, after_procs=release)
        for name, p in procs.items():
            try:
                R["exit_codes"].setdefault(name, p.wait(5))
            except Exception:                                           # noqa: BLE001
                R["exit_codes"].setdefault(name, None)
        write_new(ev / "host_after.json", dump(after))
        for s, h in old.items():
            signal.signal(s, h)
    write_new(ev / "run.json", dump(R))
    if not R["aborts"]:
        from rehearsal import write_manifest
        write_manifest(out)
    rep = evaluate(out, live=True, run_result=R)
    print(json.dumps({"stage": R["stage"], "run_id": run_id, "ok": rep["ok"], "aborts": R["aborts"][:3],
                      "failed": [k for k, c in rep["checks"].items() if not c.get("ok")]}))
    return 0 if rep["ok"] else 1


def scheduled_arrivals(w, load_s, seed, arr=None) -> int:
    """Arrivals the load generator schedules, from its own arrivals() (independent of the records it writes)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("faultlab_loadgen_for_pilot", L.LOADGEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if arr is not None:
        return len(mod.arrivals("poisson", float(arr["rate_per_s"]), float(load_s), None, seed))
    return len(mod.schedule(float(w["rate_per_s"]), float(load_s), float(w["jitter"]), seed))


# ------------------------------------------------------------------------------------------ evaluation (offline)
def replay(out: Path) -> bytes:
    from sentinelai.collectors import build_snapshot
    from sentinelai.diagnostic.contract import Target, canonical_bytes
    from sentinelai.diagnostic.rules.params import ParameterSet
    from sentinelai.runtime.pipeline import validate_snapshot
    from sentinelai.runtime.ticks import decode_ticks
    run = json.loads((out / EVIDENCE / "run.json").read_bytes())
    if run.get("format") != FORMAT:
        raise ValueError(f"run.json format {run.get('format')!r}")
    ticks = decode_ticks((out / EVIDENCE / "ticks.jsonl").read_bytes())
    target = Target.model_validate_json(json.dumps(run["target_doc"]), strict=False)
    params = ParameterSet.model_validate_json(json.dumps(run["parameter_set"]), strict=False)
    snap = build_snapshot(ticks, target, params, run["timeline"]["period_s"], run.get("ebpf", True), True)
    return validate_snapshot(canonical_bytes(snap))[1]


def app_flat(data: bytes) -> dict:
    """A saved metrics document through the collector's own parser (mono_s, pool_util, counters)."""
    from sentinelai.collectors import app as appmod
    s = appmod.parse(data)
    if not isinstance(s, appmod.AppSample):
        raise ValueError(f"saved metrics document invalid: {s}")
    return appmod._flatten(s)


def reconcile_clients(run, recs, a, b):
    """Exact client/server reconciliation over [app_start, app_end] (load wholly inside, end document drained)."""
    problems, outcomes = [], {}
    n = run["load"]["arrivals"]
    if [r["k"] for r in recs] != list(range(n)):
        problems.append(f"client records do not cover the {n} scheduled arrivals exactly once")
    for r in recs:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    unexplained = set(outcomes) - {"200", "503", "504", "client_saturated"}
    if unexplained:
        problems.append(f"client outcomes without a server counterpart: { {k: outcomes[k] for k in unexplained} }")
    sent = [r["sent_ns"] for r in recs if r["sent_ns"] is not None]
    done = [r["sent_ns"] + r["latency_ms"] * 1e6 for r in recs if r["sent_ns"] is not None
            and r["latency_ms"] is not None]
    if not sent:
        problems.append("no request was sent")
    if b.get("pool_util") != 0.0:
        problems.append("end document not drained (a worker was busy)")
    if sent and not a["mono_s"] * 1e9 < min(sent):
        problems.append("start document does not predate the first send")
    if done and not max(done) < b["mono_s"] * 1e9:
        problems.append("end document does not postdate the last completion")
    keys = ("requests_completed_total", "requests_rejected_total", "requests_failed_total")
    delta = {k: b[k] - a[k] for k in keys}
    expect = dict(zip(keys, (outcomes.get("200", 0), outcomes.get("503", 0), outcomes.get("504", 0))))
    problems += [f"{k}: server delta {delta[k]:g} != client {expect[k]}" for k in keys if delta[k] != expect[k]]
    return {"client_outcomes": dict(sorted(outcomes.items())), "server_delta": delta, "scheduled": n}, problems


def client_records(run, recs):
    """Metrics writer off: the client side alone. Every scheduled arrival recorded exactly once, sent, and answered
    with a server outcome (200 / 503 / 504); a client timeout or saturation is a problem here, because no server
    document can explain it."""
    problems, outcomes = [], {}
    n = run["load"]["arrivals"]
    if [r["k"] for r in recs] != list(range(n)):
        problems.append(f"client records do not cover the {n} scheduled arrivals exactly once")
    for r in recs:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    other = set(outcomes) - {"200", "503", "504"}
    if other:
        problems.append(f"client outcomes without a server answer: { {k: outcomes[k] for k in other} }")
    if any(r["sent_ns"] is None or r["latency_ms"] is None for r in recs if r["outcome"] in ("200", "503", "504")):
        problems.append("an answered request has no send time or latency")
    return {"client_outcomes": dict(sorted(outcomes.items())), "scheduled": n}, problems


def reconcile_r(counters):
    """Across R: every TCP segment A sent entered R on sentlab-ra and left R on sentlab-rb; every segment A received
    entered R on sentlab-rb and left it on sentlab-ra (packet counts include ARP, so >=); R dropped nothing."""
    s, e = counters["start"], counters["end"]
    d = lambda ifn, k: e["r"][ifn][k] - s["r"][ifn][k]
    out_a = e["tcp"]["OutSegs"] - s["tcp"]["OutSegs"] + e["tcp"]["RetransSegs"] - s["tcp"]["RetransSegs"]
    in_a = e["tcp"]["InSegs"] - s["tcp"]["InSegs"]
    c = {"a_out_entered_r": d(L.IF_RA, "rx_packets") >= out_a, "a_out_left_r": d(L.IF_RB, "tx_packets") >= out_a,
         "a_in_entered_r": d(L.IF_RB, "rx_packets") >= in_a, "a_in_left_r": d(L.IF_RA, "tx_packets") >= in_a,
         "traffic_present": out_a > 0 and in_a > 0}
    for ifn in (L.IF_RA, L.IF_RB):
        for k in ("rx_dropped", "tx_dropped", "rx_errors", "tx_errors"):
            c[f"{ifn}_{k}_0"] = d(ifn, k) == 0
    summary = {"a_tcp_out_incl_retrans": out_a, "a_tcp_in": in_a,
               "r": {ifn: {k: d(ifn, k) for k in s["r"][ifn]} for ifn in (L.IF_RA, L.IF_RB)}}
    return summary, sorted(k for k, v in c.items() if not v)


LOCK_WAIT = "app.lock_wait_ms"
CONFIG_DOC_KEYS = {"seq", "mono_ns", "config", "config_sha256", "control_error"}
SERVICE_CONFIG_KEYS = ("cpu_us", "dependency_timeout_ms", "lock_hold_us", "lock_wait_exceeded_ms", "pool", "queue")


def structural_app_gaps(out: Path, manifest_ok: bool):
    """({feature: reason}, basis): the app.* features this run's own configuration cannot produce, for
    app_feature_report. Only app.lock_wait_ms, and only if the manifest-verified evidence proves lock_hold_us == 0: the
    workload observes lock waits only while it holds the lock (workload.py), and FZ-WORKLOAD approves 0 for CTRL
    (register: "no lock contention in CTRL"). Proof: run.json and the workload's own config echo agree on 0, the echo
    is the only configuration of the run (seq 1, no control error) and hashes to its config_sha256, both bracketing
    metrics documents carry that hash, and the end document holds no lock-wait observation at all. A pi8 run whose one
    recorded fault changes another service key (app_pool) has exactly one more echo (seq 2): its start document then
    carries the hash of the pre-fault configuration. A fault on lock_hold_us never qualifies. Anything else leaves the
    feature required (basis.not_applied_because says why)."""
    from sentinelai.collectors import app as appmod
    failed = []
    basis = {"feature": LOCK_WAIT, "applied": False, "not_applied_because": failed}

    def need(cond, why):
        if not cond:
            failed.append(why)
        return cond
    try:
        if not need(manifest_ok, "manifest not verified"):
            return {}, basis
        run = json.loads((out / EVIDENCE / "run.json").read_bytes())
        doc = json.loads((out / EVIDENCE / "config.json").read_bytes())
        if not need(isinstance(doc, dict) and set(doc) == CONFIG_DOC_KEYS and isinstance(doc["config"], dict),
                    "config.json is not a workload configuration echo"):
            return {}, basis
        cfg, w = doc["config"], run.get("workload") if isinstance(run.get("workload"), dict) else {}
        f = run.get("fault") if isinstance(run.get("fault"), dict) else None      # a pi8 run's one recorded fault
        basis["lock_hold_us"] = {"config_json": cfg.get("lock_hold_us"), "run_json": w.get("lock_hold_us")}
        for name, v in (("config.json", cfg.get("lock_hold_us")), ("run.json workload", w.get("lock_hold_us"))):
            need(type(v) is int and v == 0, f"{name} lock_hold_us is {v!r}, not 0")
        expect = dict(w)
        if f is not None and f.get("key") in SERVICE_CONFIG_KEYS:       # the fault's own key echoes its new value
            expect[f["key"]] = f.get("magnitude")
        need(all(k in cfg and k in expect and type(cfg[k]) is type(expect[k]) and cfg[k] == expect[k]
                 for k in SERVICE_CONFIG_KEYS),
             "workload configuration echo differs from run.json workload (and its recorded fault)")
        changes = 1 if f is not None and f.get("key") in SERVICE_CONFIG_KEYS else 0     # one re-echo per change
        need(f is None or f.get("key") != "lock_hold_us", "the run's fault changes lock_hold_us")
        need(doc["seq"] == 1 + changes and doc["control_error"] is None,
             "workload configuration changed during the run other than by its recorded fault, or a control error was "
             "recorded")
        digest = lambda c: hashlib.sha256(json.dumps(c, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        sha = digest(cfg)
        need(doc["config_sha256"] == sha, "config_sha256 does not hash the recorded configuration")
        before = dict(cfg, **({f["key"]: w.get(f["key"])} if changes else {}))   # configuration before the fault
        docs = [appmod.parse((out / EVIDENCE / n).read_bytes()) for n in ("app_start.json", "app_end.json")]
        if need(all(isinstance(d, appmod.AppSample) for d in docs), "saved metrics documents invalid"):
            need(docs[0].config_sha256 == digest(before) and docs[1].config_sha256 == sha,
                 "metrics documents were not produced under the recorded configuration (and its recorded fault)")
            need(not any(docs[1].histograms["lock_wait"]) and docs[1].events.get("LOCK_WAIT_EXCEEDED") == 0,
                 "lock waits were observed")
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        failed.append(f"evidence unreadable: {type(exc).__name__}: {exc}")
    if failed:
        return {}, basis
    reason = ("structurally unavailable: the approved CTRL workload (FZ-WORKLOAD) has lock_hold_us 0, and the workload "
              "records lock waits only while holding the lock; zero lock-wait observations confirmed in the evidence")
    basis.update(applied=True, reason=reason)
    return {LOCK_WAIT: reason}, basis


def w_effects(out: Path) -> dict:
    """W-window wait metrics from the raw metrics documents captured at ticks nB and nB + nW (histogram delta,
    nearest-rank P99 as bucket upper bound, the collector's own percentile); never from snapshot features."""
    from sentinelai.collectors import app as appmod
    a, b = (appmod.parse((out / EVIDENCE / f"app_{k}.json").read_bytes()) for k in ("w_start", "w_end"))
    if not (isinstance(a, appmod.AppSample) and isinstance(b, appmod.AppSample)):
        raise ValueError("W-window metrics documents invalid")
    res = {}
    for hist in ("queue_wait", "lock_wait", "dependency_latency", "latency"):
        delta = [y - x for x, y in zip(a.histograms[hist], b.histograms[hist])]
        if any(d < 0 for d in delta):
            raise ValueError(f"{hist} histogram decreased in W")
        p99, why = appmod.percentile(delta, 0.99)
        res[hist] = {"count": sum(delta), "p99_ms": p99, "missing": why}
    return res


def injection_check(run) -> dict:
    """AMD-10: issued after tick nB (the B/W boundary), no issue error, read back within T_cap (FZ-TTRANS)."""
    inj = run.get("injection") or {}
    problems = []
    if not inj.get("issued"):
        problems.append(f"not issued: {inj.get('issue_error', 'no injection record')}")
    if inj.get("issue_after_tick") != round(B_S / PERIOD_S):
        problems.append("not issued at the B/W boundary")
    if not inj.get("verified") or not (inj.get("readback_latency_s") or T_CAP_S + 1) <= T_CAP_S:
        problems.append(inj.get("readback_error", "read-back not verified within T_cap"))
    return {"ok": not problems, "problems": problems, "readback_latency_s": inj.get("readback_latency_s"),
            "label": None if not problems else "failed_injection"}


def pi_checks(run, snap, ticks):
    ms = snap["measurements"]
    net = [m for m in ms if m["feature_id"].startswith(("tcp.", "net."))]
    pi1 = {"ok": bool(net) and all(m["coverage"] >= COVERAGE_MIN for m in net), "measurements": len(net),
           "min_coverage": min((m["coverage"] for m in net), default=None), "mode": "driver-root"}
    if run.get("collector_mode") == "unprivileged":                # the netns must also be verified as the lab uid
        u = run.get("unprivileged") or {}
        pi1.update(mode="unprivileged", netns_verified=u.get("netns_verified") is True, netns_link=u.get("netns_link"),
                   uid=u.get("uid"), cap_eff=u.get("cap_eff"))
        pi1["ok"] = pi1["ok"] and pi1["netns_verified"]
    col = run.get("collection") or {}
    cpu = (col.get("cpu_s", 0) + col.get("loader_cpu_s", 0)) / col["wall_s"] if col.get("wall_s") else None
    low = sorted({m["feature_id"] for m in ms if m["coverage"] < COVERAGE_MIN})
    pi6 = {"ok": cpu is not None and cpu <= CPU_BUDGET_CORE and not low, "collector_cpu_core": cpu,
           "budget_core": CPU_BUDGET_CORE, "features_below_coverage": low,
           "not_collected": sorted({m["feature_id"] for m in snap["missing_measurements"]}),
           "note": "coverage over collected measurements; structurally unavailable sources listed, not scored"}
    valid = sum(1 for t in ticks if isinstance(t.obs.get("app"), dict))
    p99 = [m for m in ms if m["feature_id"] == "app.latency_ms" and m["aggregation"] == "P99"]
    p99_ok = bool(p99) and all(m["quality"] in ("OK", "PARTIAL") for m in p99)
    pi7 = {"ok": bool(ticks) and valid / len(ticks) >= COVERAGE_MIN and p99_ok,
           "valid_app_ticks": valid, "ticks": len(ticks), "latency_p99_measured": p99_ok}
    return {"PI-1": pi1, "PI-6": pi6, "PI-7_ctrl": pi7}


def evaluate(out: Path, live: bool = False, run_result=None) -> dict:
    """Every CTRL check recomputed from the saved evidence. Pipeline checks and PI verdicts are kept apart."""
    from rehearsal import app_feature_report, verify_manifest
    from sentinelai.runtime.ticks import decode_ticks
    checks = {}
    run = run_result or json.loads((out / EVIDENCE / "run.json").read_bytes())
    checks["run_completed"] = {"ok": not run.get("aborts"), "aborts": run.get("aborts")}
    checks["cleanup"] = {"ok": bool((run.get("cleanup") or {}).get("ok")), "detail": run.get("cleanup")}
    checks["host_compare"] = {"ok": bool((run.get("host_compare") or {}).get("ok")),
                              "failed": (run.get("host_compare") or {}).get("failed")}
    checks["bpf_released"] = {"ok": bool((run.get("bpf_release") or {}).get("released"))}
    pis, effects = {}, None
    variant = run.get("variant", "ctrl")
    collected = VARIANTS.get(variant, VARIANTS["ctrl"])["collector"] is not None
    if not run.get("aborts"):
        m = verify_manifest(out)
        checks["manifest"] = {"ok": not m, "problems": m}
        if collected:
            live_bytes = (out / "snapshot.json").read_bytes()
            try:
                rep = replay(out)
                checks["replay_byte_identical"] = {"ok": rep == live_bytes,
                                                   "sha256": hashlib.sha256(live_bytes).hexdigest()}
            except Exception as exc:                                    # noqa: BLE001 -- recorded, never hidden
                checks["replay_byte_identical"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        try:                                                            # malformed evidence fails, never crashes
            if collected:
                gaps, basis = structural_app_gaps(out, checks["manifest"]["ok"])
                rows, problems = app_feature_report(live_bytes, gaps)
                checks["app_features"] = {"ok": not problems, "problems": problems,
                                          "structurally_unavailable": basis, "rows": rows}
            recs = [json.loads(x) for x in (out / EVIDENCE / "client.jsonl").read_text().splitlines()]
            if run.get("metrics_writer", True):
                a, b = (app_flat((out / EVIDENCE / n).read_bytes()) for n in ("app_start.json", "app_end.json"))
                summary, problems = reconcile_clients(run, recs, a, b)
                checks["client_server_reconciliation"] = dict(summary, ok=not problems, problems=problems)
            else:
                summary, problems = client_records(run, recs)
                checks["client_records"] = dict(summary, ok=not problems, problems=problems)
            counters = json.loads((out / EVIDENCE / "counters.json").read_bytes())
            summary, failed = reconcile_r(counters)
            checks["across_r_reconciliation"] = dict(summary, ok=not failed, failed=failed)
            if collected:
                ticks = decode_ticks((out / EVIDENCE / "ticks.jsonl").read_bytes())
                pis = pi_checks(run, json.loads(live_bytes), ticks)
            if variant == "pi8":
                checks["injection_verified"] = injection_check(run)
            if run.get("w_docs"):                                       # root-collected runs: W-window effects
                effects = w_effects(out)
        except Exception as exc:                                        # noqa: BLE001 -- recorded, never hidden
            checks["evidence_readable"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            pis = {}
    ok = set(checks) == pipeline_checks(variant) and all(c["ok"] for c in checks.values())
    report = {"format": FORMAT + ".report", "variant": variant, "pipeline_ok": ok,
              "ok": ok and all(p["ok"] for p in pis.values()), "checks": checks, "pi": pis,
              "w_effects": effects, "fault": run.get("fault"),
              "note": "PI verdicts are measurements against the proposed criteria; a pipeline pass is not a "
                      "scientific validation."}
    if live:
        write_new(out / "report.json", dump(report))
    return report


# ------------------------------------------------------------------------------------------ pairs (offline, report-only)
def client_summary(out: Path) -> dict:
    """Client-side load and latency of one run (nearest-rank percentiles over answered 200 requests)."""
    import math
    run = json.loads((out / EVIDENCE / "run.json").read_bytes())
    recs = [json.loads(x) for x in (out / EVIDENCE / "client.jsonl").read_text().splitlines()]
    lat = sorted(r["latency_ms"] for r in recs if r["outcome"] == "200" and r["latency_ms"] is not None)
    rank = lambda q: lat[max(0, math.ceil(q * len(lat)) - 1)] if lat else None
    sent = sorted(r["sent_ns"] for r in recs if r["sent_ns"] is not None)
    span_s = (sent[-1] - sent[0]) / 1e9 if len(sent) > 1 else None
    return {"run_id": run["run_id"], "commit": run["commit"], "seed": run["seed"], "requests": len(recs),
            "ok_200": len(lat), "p50_ms": rank(0.50), "p99_ms": rank(0.99),
            "throughput_per_s": len(lat) / span_s if span_s else None}


def pairs(campaign: Path) -> dict:
    """PI-6 (collectors on vs off: CTRL-s / PI6OFF-s) and workload instrumentation (metrics writer on vs off:
    PI6OFF-s / INSTOFF-s) pairs of one campaign, recomputed offline from the saved evidence. A pair counts only if
    both members pass their own evaluation at the same commit and seed with the same scheduled arrivals. Differences
    are reported (off minus on); design §5.5 / §6.7 set no pass threshold on them."""
    runs = {d.name: d for d in sorted(campaign.iterdir()) if d.is_dir() and not d.is_symlink()}
    out = {"campaign": campaign.name, "pi6_pairs": [], "instrumentation_pairs": [],
           "note": "report-only: client-side differences (off minus on); no threshold (design §5.5, §6.7)"}
    for kind, on_p, off_p in (("pi6_pairs", "CTRL", "PI6OFF"), ("instrumentation_pairs", "PI6OFF", "INSTOFF")):
        for name in sorted(n for n in runs if n.startswith(off_p + "-")):
            seed = name.split("-", 1)[1]
            on, off = runs.get(f"{on_p}-{seed}"), runs[name]
            pair = {"seed": int(seed), "on": f"{on_p}-{seed}", "off": name, "problems": []}
            if on is None:
                pair["problems"].append(f"{on_p}-{seed} missing")
                pair["ok"] = False
                out[kind].append(pair)
                continue
            reps = {k: evaluate(d) for k, d in (("on", on), ("off", off))}
            ra, rb = (json.loads((d / EVIDENCE / "run.json").read_bytes()) for d in (on, off))
            pair["problems"] += [f"{k} run does not pass its own evaluation" for k, r in reps.items()
                                 if not r["pipeline_ok"]]
            if (ra["commit"], ra["seed"], ra["load"]["arrivals"]) != (rb["commit"], rb["seed"], rb["load"]["arrivals"]):
                pair["problems"].append("members differ in commit, seed or scheduled arrivals")
            a, b = client_summary(on), client_summary(off)
            pair.update(on_client=a, off_client=b, ok=not pair["problems"],
                        diff={k: (b[k] - a[k]) if None not in (a[k], b[k]) else None
                              for k in ("p50_ms", "p99_ms", "throughput_per_s")})
            out[kind].append(pair)
    return out


# ------------------------------------------------------------------------------------------ PI-8 levels (offline)
def rep_effect(run_dir: Path, ctrl_max: dict, lock_rule: dict) -> dict:
    """One pi8 rep: injection verified (AMD-10) and the injected mechanism's wait metric in W above the CTRL maximum
    (FZ-PI7); for app_lock the approved FZ-PI7-LOCK rule (CTRL maximum 0 ms, P99 measured and > 0.05 ms)."""
    rep = evaluate(run_dir)
    run = json.loads((run_dir / EVIDENCE / "run.json").read_bytes())
    f = run["fault"]
    eff = (rep.get("w_effects") or {}).get(f["metric_histogram"]) or {}
    value = eff.get("p99_ms")
    if f["type"] == "app_lock":
        bar, basis = float(lock_rule["rep_lock_wait_p99_min_ms"]), "FZ-PI7-LOCK: > 0.05 ms (CTRL maximum 0 ms)"
    else:
        bar, basis = ctrl_max.get(f["metric_histogram"]), "FZ-PI7: above the CTRL maximum"
    gt = bool(rep["pipeline_ok"] and value is not None and bar is not None and value > bar)
    return {"run": run_dir.name, "seed": run["seed"], "magnitude": f["magnitude"], "pipeline_ok": rep["pipeline_ok"],
            "injection_verified": (rep["checks"].get("injection_verified") or {}).get("ok", False),
            "w_p99_ms": value, "w_count": eff.get("count"), "bar_ms": bar, "basis": basis, "ground_truth": gt}


def levels(campaign: Path, decisions=DECISIONS) -> dict:
    """PI-8 (FZ-PI8) for the application faults of one campaign, offline and report-only: CTRL maxima from the
    campaign's passing CTRL runs; per fault, I1 = weakest candidate with effect ground truth in 2/2 reps, I3 = strongest
    candidate with ground truth in 2/2 (within the approved ceiling by construction), I2 = geometric mean of I1 and I3
    in injection units rounded toward I1, I0 = the candidate just weaker than I1; two consecutive verification
    failures stop the fault. Nothing is frozen here: freezing is the M5 review's (owner)."""
    import math
    lock_rule = approved_value("FZ-PI7-LOCK", decisions)
    runs = sorted((d for d in campaign.iterdir() if d.is_dir() and not d.is_symlink()), key=lambda d: d.name)
    ctrl_max, ctrl_runs = {}, []
    for d in runs:
        if d.name.startswith("CTRL-"):
            rep = evaluate(d)
            if rep["pipeline_ok"] and rep.get("w_effects"):
                ctrl_runs.append(d.name)
                for h, e in rep["w_effects"].items():
                    if e["p99_ms"] is not None:
                        ctrl_max[h] = max(ctrl_max.get(h, 0.0), e["p99_ms"])
    out = {"campaign": campaign.name, "ctrl_runs": ctrl_runs, "ctrl_max_ms": ctrl_max, "faults": {},
           "note": "report-only; levels are frozen only by the M5 review; the CTRL maximum of lock_wait is 0 ms by "
                   "FZ-PI7-LOCK"}
    pi8 = [(d, json.loads((d / EVIDENCE / "run.json").read_bytes())) for d in runs if d.name.startswith("PI8-")]
    for fault in sorted({r["fault"]["type"] for _, r in pi8}):
        reps = sorted((rep_effect(d, ctrl_max, lock_rule) for d, r in pi8 if r["fault"]["type"] == fault),
                      key=lambda x: x["seed"])
        spec = next(r["fault"] for _, r in pi8 if r["fault"]["type"] == fault)
        order = sorted(spec["candidates"], reverse=spec["stronger"] == "lower")       # weakest -> strongest
        streak, stopped = 0, None
        for x in reps:                                                              # in run (seed) order
            streak = 0 if x["injection_verified"] else streak + 1
            if streak >= 2 and stopped is None:
                stopped = x["run"]
        by = {m: [x for x in reps if x["magnitude"] == m] for m in order}
        established = [m for m in order if len(by[m]) >= 2 and all(x["ground_truth"] for x in by[m][:2])]
        res = {"reps": reps, "order_weakest_first": order, "established_2of2": established,
               "stopped_after": stopped, "I1": None, "I2": None, "I3": None, "I0": None}
        if established and stopped is None:
            i1, i3 = established[0], established[-1]
            g = math.sqrt(i1 * i3)
            i2 = math.ceil(g) if spec["stronger"] == "lower" else math.floor(g)   # rounded toward I1 (weaker)
            i2 = max(min(i2, max(i1, i3)), min(i1, i3))
            weaker = order[:order.index(i1)]
            res.update(I1=i1, I3=i3, I2=i2, I0=weaker[-1] if weaker else None,
                       i2_needs_confirmation=i2 not in (i1, i3))
        out["faults"][fault] = res
    return out


# ------------------------------------------------------------------------------------------ cleanup (wrapper trap)
def cleanup_all(top: Path) -> int:
    sysr = L.Sys()
    res = {}
    for oplog in sorted(top.glob("*/ops.jsonl")):
        m = re.fullmatch(RUN_NAME, oplog.parent.name)
        run_id = None
        entries = L.read_oplog(str(oplog))
        made = L.created(entries)
        for d in made["dirs"]:
            if d.startswith(L.APP_ROOT) and L.RUN_ID.fullmatch(d[len(L.APP_ROOT):]):
                run_id = d[len(L.APP_ROOT):]
        host = L.Host(L.Plan(run_id), str(oplog), sysr)
        res[oplog.parent.name] = L.cleanup(host, sysr, entries, run_id) if m else {"ok": False, "skipped": True}
    state = L.cleanup_state(sysr)
    print(json.dumps({"runs": res, "state": state}, indent=1, default=str))
    return 0 if state["ok"] and all(r.get("ok") for r in res.values()) else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("lifecycle",) + tuple(VARIANTS):
        p = sub.add_parser(name)
        p.add_argument("--campaign", required=True, help="UTC stamp YYYYMMDDTHHMMSSZ (one directory per campaign)")
        p.add_argument("--execute", action="store_true", help="required: this mutates the host")
        if name == "lifecycle":
            p.add_argument("--cycle", type=int, required=True)
        else:
            p.add_argument("--seed", type=int, required=True)
        if name == "pi8":
            p.add_argument("--fault", required=True, choices=sorted(APP_FAULTS))
            p.add_argument("--magnitude", type=int, required=True, help="an approved FZ-INTENSITY-APP candidate")
    sub.add_parser("evaluate").add_argument("dir")
    sub.add_parser("pairs").add_argument("campaign_dir")
    sub.add_parser("levels").add_argument("campaign_dir")
    sub.add_parser("cleanup").add_argument("dir")
    child = sub.add_parser("collect-child")                       # internal: started by pi1u as the lab uid
    child.add_argument("--run-id", required=True)
    child.add_argument("--out-dir", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "collect-child":
        if not L.RUN_ID.fullmatch(a.run_id) or not a.run_id.startswith("PI1U-"):
            refuse(f"collector child run id {a.run_id!r} not allowed")
        return collect_child(a.run_id, Path(a.out_dir))
    if a.cmd == "levels":
        rep = levels(Path(a.campaign_dir))
        print(json.dumps(rep, indent=1, sort_keys=True, default=str))
        return 0
    if a.cmd == "pairs":
        rep = pairs(Path(a.campaign_dir))
        print(json.dumps(rep, indent=1, sort_keys=True, default=str))
        return 0 if all(p["ok"] for k in ("pi6_pairs", "instrumentation_pairs") for p in rep[k]) else 1
    if a.cmd == "evaluate":
        rep = evaluate(Path(a.dir))
        print(json.dumps(rep, indent=1, sort_keys=True, default=str))
        return 0 if rep["ok"] else 1
    if a.cmd == "cleanup":
        if os.geteuid() != 0:
            refuse("cleanup needs root (wrapper trap)")
        return cleanup_all(Path(a.dir))
    if not a.execute:
        refuse("--execute not given")
    return run_stage(a)


def run_stage(a, run_preflight=None) -> int:
    """The gate in front of every host mutation: invocation, staging, run path, privileged preflight, PI-0 order."""
    check_invocation()
    if a.cmd == "lifecycle" and not 1 <= a.cycle <= 5:
        refuse("PI-0 has cycles 1..5")
    if a.cmd != "lifecycle":
        check_seed(a.seed)
    if a.cmd == "pi8":                                    # refuse an unapproved fault before anything is created
        fault_spec(a.fault, a.magnitude, approved_value("FZ-WORKLOAD"))
    staging = staging_root()
    out = run_path(staging, a.campaign, f"PI0-{a.cycle}" if a.cmd == "lifecycle" else
                   f"{VARIANTS[a.cmd]['prefix']}-{a.seed}")
    rep = require_preflight(run_preflight)
    commit = next(c["observed"] for c in rep["checks"] if c["id"] == "INT-HEAD")
    if a.cmd != "lifecycle":
        require_pi0(out.parent, commit)
    if not out.parent.exists():
        out.parent.mkdir(mode=0o755)
        hand_over(out.parent)
    try:
        if a.cmd == "lifecycle":
            rc = lifecycle(out, a.cycle, commit)
        elif a.cmd == "pi8":
            rc = ctrl(out, a.seed, commit, variant="pi8", fault=(a.fault, a.magnitude))
        else:
            rc = ctrl(out, a.seed, commit, variant=a.cmd)
    finally:
        if out.is_dir() and not out.is_symlink():
            write_new(out / "preflight.json", dump(rep))
            hand_over(out)
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refused as r:
        sys.exit(r.code)
