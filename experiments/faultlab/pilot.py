#!/usr/bin/env python3
"""SentinelAI Phase 1C FaultLab pilot driver (Gate 2): PI-0 lab lifecycle and CTRL runs in the A–R–B lab, as root.

    sudo taskset -c 0-15 .venv/bin/python experiments/faultlab/pilot.py lifecycle --campaign <UTC> --cycle K --execute
    sudo taskset -c 0-15 .venv/bin/python experiments/faultlab/pilot.py ctrl --campaign <UTC> --seed N --execute
    .venv/bin/python experiments/faultlab/pilot.py evaluate <campaign dir>/CTRL-<N>
    sudo .venv/bin/python experiments/faultlab/pilot.py cleanup <campaign dir>

Before any host mutation every privileged invocation refuses unless: root via sudo from uid 1000, confined to CPUs
0-15, and a fresh in-process privileged preflight (experiments/faultlab/preflight.py, --stage ctrl, the committed
decisions record) is READY; the commit recorded is the preflight's HEAD. `ctrl` also refuses unless the same campaign
holds PI-0 cycles 1-5, all ok, at the same commit (draft §6.1: nothing else runs until PI-0 passes). Output goes to
<FZ-STAGING path>/<campaign>/{PI0-K | CTRL-N} and is handed to the invoking user at the end.

  lifecycle --cycle K   PI-0: lab cgroup + A–R–B lab + app directory created, checked (structure, forwarding only in R,
                        no external path, ping both ways, TCP echo A->B), removed; cleanup verified; host compared with
                        the pre-cycle snapshot, BPF included
  ctrl --seed N         one CTRL run: dependency peer and load generator in B, workload in A (target leaf, CPU 18),
                        M3A + M3B + app collection over B 45 s + W 90 s after a 15 s warm-up, 20 s cool-down; evidence,
                        manifest, replay, client/server and across-R reconciliation, PI-1 / PI-6 / PI-7 (CTRL part)
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
EVIDENCE_MAX = 64 << 20                                           # bytes read back from a lab-uid file
PERIOD_S = 1.0
WARMUP_S, B_S, W_S, COOLDOWN_S = 15, 45, 90, 20                   # design §6.2 timeline
SEED_MIN, SEED_MAX = 900000, 909999                               # pilot seed range (draft §7)
EVIDENCE, MANIFEST = "evidence", "manifest.json"
READY_TIMEOUT_S, LAB_SETTLE_MAX_S, DRAIN_MAX_S = 10.0, 3.0, 15.0
COVERAGE_MIN = 0.99                                               # PI-1, PI-6, PI-7 (registered / proposed)
CPU_BUDGET_CORE = 0.02                                            # PI-6 (registered "<= 2 % CPU")
PARAMS_ID = "pilot-ctrl-uncalibrated"
PIPELINE_CHECKS = frozenset({"run_completed", "cleanup", "host_compare", "bpf_released", "manifest",
                             "replay_byte_identical", "app_features", "client_server_reconciliation",
                             "across_r_reconciliation"})            # every one present and ok, nothing else


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
    if not re.fullmatch(r"PI0-[1-5]|CTRL-9[0-9]{5}", name):
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


def ctrl(out: Path, seed: int, commit: str, decisions=DECISIONS, sysr=None, host_cls=None,
         sleep=time.sleep) -> int:
    from sentinelai.collectors import LiveReader, SystemClock, build_snapshot, collect, resolve_target
    from sentinelai.collectors import app as appmod
    from sentinelai.diagnostic.contract import canonical_bytes
    from sentinelai.ebpf import loader_argv, resolve_ebpf_target
    from sentinelai.runtime.pipeline import validate_snapshot
    from sentinelai.runtime.ticks import encode_ticks
    from m3b_r1_validate import Recording

    check_seed(seed)
    w = approved_value("FZ-WORKLOAD", decisions)
    run_id = f"CTRL-s{seed}"
    load_s = WARMUP_S + B_S + W_S + COOLDOWN_S
    out.mkdir(mode=0o755)
    for d in (EVIDENCE, "logs", "lg"):
        (out / d).mkdir(mode=0o755)
    os.chown(out / "lg", C.LAB_UID, C.LAB_GID)                        # the load generator (uid 1000) writes here
    client_tmp = out / "lg" / "client.jsonl"
    argv = {"dependency": L.dependency_argv(run_id, w), "workload": L.workload_argv(run_id, w),
            "loadgen": L.loadgen_argv(w, load_s, seed, str(client_tmp))}
    sysr = sysr or L.Sys()
    host = (host_cls or L.Host)(L.Plan(run_id, spawns=argv.items()), str(out / "ops.jsonl"), sysr)
    ev = out / EVIDENCE
    R = {"format": FORMAT, "stage": "CTRL", "run_id": run_id, "seed": seed, "commit": commit, "workload": w,
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
    procs, loader, state = {}, None, {}
    old = {s: signal.signal(s, on_signal) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        setup_lab(host, sysr, R, run_id)
        rdir = L.run_dir(run_id)
        host.apply(("write_new", f"{rdir}/control.json",
                    json.dumps({"dependency_delay_ms": int(w["dependency_delay_ms"])}).encode()))
        for role in ("dependency", "workload"):
            procs[role] = host.apply(("spawn", role, argv[role]), stderr=(out / "logs" / f"{role}.stderr").open("wb"))
            ready = f"{rdir}/{'dependency_config.json' if role == 'dependency' else 'metrics.json'}"
            if not wait_for(lambda: sysr.lstat_run(ready) is not None, READY_TIMEOUT_S, procs.items()):
                raise L.LabAbort(f"{role} not ready within {READY_TIMEOUT_S} s")
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
        ids = resolve_ebpf_target(target)
        loader = Recording(loader_argv(ids, load_s + 120), ids, 5.0)
        err = loader.start()
        if err:
            raise L.LabAbort(f"eBPF loader unavailable: {err}")
        evt("loader_started", pid=loader.proc.pid)
        read_snmp = lambda: L.tcp_counters(sysr.read(f"/proc/{tpids[0]}/net/snmp"))
        state["start"] = {"app": appmod.read_metrics(run_id), "r": L.r_counters(sysr), "tcp": read_snmp(),
                          "mono_ns": time.monotonic_ns()}
        if not isinstance(state["start"]["app"], bytes) or None in (state["start"]["r"], state["start"]["tcp"]):
            raise L.LabAbort("start counters unavailable")
        procs["loadgen"] = host.apply(("spawn", "loadgen", argv["loadgen"]),
                                      stderr=(out / "logs" / "loadgen.stderr").open("wb"))
        evt("loadgen_started")
        sleep(WARMUP_S)
        evt("collect_start")
        params = pilot_params()
        ticks, stats = collect(target, params, LiveReader(), SystemClock(), PERIOD_S, LoaderTicks(loader),
                               appmod.AppSource(run_id))
        evt("collect_end")
        R["collection"] = {"ticks": stats.ticks, "wall_s": stats.wall_s, "cpu_s": stats.cpu_s,
                           "max_tick_read_s": stats.max_tick_read_s, "loader_cpu_s": proc_cpu_s(loader.proc.pid)}
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
        if not wait_for(drained, DRAIN_MAX_S):
            raise L.LabAbort(f"workload not drained within {DRAIN_MAX_S} s")
        sleep(2 * float(w["publish_s"]))                          # one more document after the last completion
        state["end"] = {"app": appmod.read_metrics(run_id), "r": L.r_counters(sysr), "tcp": read_snmp(),
                        "mono_ns": time.monotonic_ns()}
        if not isinstance(state["end"]["app"], bytes) or None in (state["end"]["r"], state["end"]["tcp"]):
            raise L.LabAbort("end counters unavailable")
        for name in ("config.json", "dependency_config.json", "control.json"):
            write_new(ev / name, sysr.read_run(f"{rdir}/{name}", 1 << 20))
        write_new(ev / "app_start.json", state["start"]["app"])
        write_new(ev / "app_end.json", state["end"]["app"])
        write_new(ev / "counters.json", dump({k: {"r": state[k]["r"], "tcp": state[k]["tcp"],
                                                  "mono_ns": state[k]["mono_ns"]} for k in ("start", "end")}))
        write_new(ev / "client.jsonl", read_regular(client_tmp))
        write_new(ev / "ticks.jsonl", encode_ticks(ticks))
        target_doc = target.model_dump(mode="json")
        R["target_doc"], R["parameter_set"] = target_doc, params.model_dump(mode="json")
        R["nB"], R["nW"] = round(B_S / PERIOD_S), round(W_S / PERIOD_S)
        R["load"] = {"arrivals": scheduled_arrivals(w, load_s, seed), "duration_s": load_s, "seed": seed}
        snap = build_snapshot(ticks, target, params, PERIOD_S, True, True)
        write_new(out / "snapshot.json", validate_snapshot(canonical_bytes(snap))[1])
    except (L.LabAbort, L.LabRefused, Interrupted, Exception) as exc:     # noqa: BLE001 -- abort, then cleanup
        R["aborts"].append(f"{type(exc).__name__}: {exc}")
    finally:
        for s in old:
            signal.signal(s, signal.SIG_IGN)

        def release():
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
    print(json.dumps({"stage": "CTRL", "run_id": run_id, "ok": rep["ok"], "aborts": R["aborts"][:3],
                      "failed": [k for k, v in rep["checks"].items() if not v.get("ok")]}))
    return 0 if rep["ok"] else 1


def scheduled_arrivals(w, load_s, seed) -> int:
    import importlib.util
    spec = importlib.util.spec_from_file_location("faultlab_loadgen_for_pilot", L.LOADGEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
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
    snap = build_snapshot(ticks, target, params, run["timeline"]["period_s"], True, True)
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
    metrics documents carry that hash, and the end document holds no lock-wait observation at all. Anything else
    leaves the feature required (basis.not_applied_because says why)."""
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
        basis["lock_hold_us"] = {"config_json": cfg.get("lock_hold_us"), "run_json": w.get("lock_hold_us")}
        for name, v in (("config.json", cfg.get("lock_hold_us")), ("run.json workload", w.get("lock_hold_us"))):
            need(type(v) is int and v == 0, f"{name} lock_hold_us is {v!r}, not 0")
        need(all(k in cfg and k in w and type(cfg[k]) is type(w[k]) and cfg[k] == w[k] for k in SERVICE_CONFIG_KEYS),
             "workload configuration echo differs from run.json workload")
        need(doc["seq"] == 1 and doc["control_error"] is None,
             "workload configuration changed during the run or a control error was recorded")
        sha = hashlib.sha256(json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        need(doc["config_sha256"] == sha, "config_sha256 does not hash the recorded configuration")
        docs = [appmod.parse((out / EVIDENCE / n).read_bytes()) for n in ("app_start.json", "app_end.json")]
        if need(all(isinstance(d, appmod.AppSample) for d in docs), "saved metrics documents invalid"):
            need(all(d.config_sha256 == doc["config_sha256"] for d in docs),
                 "metrics documents were not produced under the recorded configuration")
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


def pi_checks(run, snap, ticks):
    ms = snap["measurements"]
    net = [m for m in ms if m["feature_id"].startswith(("tcp.", "net."))]
    pi1 = {"ok": bool(net) and all(m["coverage"] >= COVERAGE_MIN for m in net), "measurements": len(net),
           "min_coverage": min((m["coverage"] for m in net), default=None), "mode": "driver-root"}
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
    pis = {}
    if not run.get("aborts"):
        m = verify_manifest(out)
        checks["manifest"] = {"ok": not m, "problems": m}
        live_bytes = (out / "snapshot.json").read_bytes()
        try:
            rep = replay(out)
            checks["replay_byte_identical"] = {"ok": rep == live_bytes,
                                               "sha256": hashlib.sha256(live_bytes).hexdigest()}
        except Exception as exc:                                        # noqa: BLE001 -- recorded, never hidden
            checks["replay_byte_identical"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        try:                                                            # malformed evidence fails, never crashes
            gaps, basis = structural_app_gaps(out, checks["manifest"]["ok"])
            rows, problems = app_feature_report(live_bytes, gaps)
            checks["app_features"] = {"ok": not problems, "problems": problems, "structurally_unavailable": basis,
                                      "rows": rows}
            recs = [json.loads(x) for x in (out / EVIDENCE / "client.jsonl").read_text().splitlines()]
            a, b = (app_flat((out / EVIDENCE / n).read_bytes()) for n in ("app_start.json", "app_end.json"))
            summary, problems = reconcile_clients(run, recs, a, b)
            checks["client_server_reconciliation"] = dict(summary, ok=not problems, problems=problems)
            counters = json.loads((out / EVIDENCE / "counters.json").read_bytes())
            summary, failed = reconcile_r(counters)
            checks["across_r_reconciliation"] = dict(summary, ok=not failed, failed=failed)
            ticks = decode_ticks((out / EVIDENCE / "ticks.jsonl").read_bytes())
            pis = pi_checks(run, json.loads(live_bytes), ticks)
        except Exception as exc:                                        # noqa: BLE001 -- recorded, never hidden
            checks["evidence_readable"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            pis = {}
    ok = set(checks) == PIPELINE_CHECKS and all(c["ok"] for c in checks.values())
    report = {"format": FORMAT + ".report", "pipeline_ok": ok, "ok": ok and all(p["ok"] for p in pis.values()),
              "checks": checks, "pi": pis,
              "note": "PI verdicts are measurements against the proposed criteria; a pipeline pass is not a "
                      "scientific validation."}
    if live:
        write_new(out / "report.json", dump(report))
    return report


# ------------------------------------------------------------------------------------------ cleanup (wrapper trap)
def cleanup_all(top: Path) -> int:
    sysr = L.Sys()
    res = {}
    for oplog in sorted(top.glob("*/ops.jsonl")):
        m = re.fullmatch(r"PI0-[1-5]|CTRL-9[0-9]{5}", oplog.parent.name)
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
    for name in ("lifecycle", "ctrl"):
        p = sub.add_parser(name)
        p.add_argument("--campaign", required=True, help="UTC stamp YYYYMMDDTHHMMSSZ (one directory per campaign)")
        p.add_argument("--execute", action="store_true", help="required: this mutates the host")
        if name == "lifecycle":
            p.add_argument("--cycle", type=int, required=True)
        else:
            p.add_argument("--seed", type=int, required=True)
    sub.add_parser("evaluate").add_argument("dir")
    sub.add_parser("cleanup").add_argument("dir")
    a = ap.parse_args(argv)
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
    if a.cmd == "ctrl":
        check_seed(a.seed)
    staging = staging_root()
    out = run_path(staging, a.campaign, f"PI0-{a.cycle}" if a.cmd == "lifecycle" else f"CTRL-{a.seed}")
    rep = require_preflight(run_preflight)
    commit = next(c["observed"] for c in rep["checks"] if c["id"] == "INT-HEAD")
    if a.cmd == "ctrl":
        require_pi0(out.parent, commit)
    if not out.parent.exists():
        out.parent.mkdir(mode=0o755)
        hand_over(out.parent)
    try:
        rc = lifecycle(out, a.cycle, commit) if a.cmd == "lifecycle" else ctrl(out, a.seed, commit)
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
