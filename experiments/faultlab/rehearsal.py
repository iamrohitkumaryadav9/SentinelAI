#!/usr/bin/env python3
"""SentinelAI M4 rehearsal: unprivileged, loopback-only end-to-end run with evidence, manifest and replay.

    .venv/bin/python experiments/faultlab/rehearsal.py run [--out DIR] [--seed N]
    .venv/bin/python experiments/faultlab/rehearsal.py verify DIR

`run` starts the dependency peer, the workload (experiments/faultlab/docker/workload.py) and, inside the measured
window, the load generator, all on 127.0.0.1 ephemeral ports and as the invoking user; collects B + W ticks with the
existing collector (collectors.collect with app.AppSource); builds the live EvidenceSnapshot; persists the raw evidence;
writes a SHA-256 manifest; and checks: replay byte identity, the nine app.* measurements, and client/counter
reconciliation. `verify` repeats the manifest and replay checks on a finished run without starting anything.
Exit status: 0 all checks pass, 1 a check failed, 2 setup or startup failure.

It never uses root, namespaces, cgroup writes, eBPF, interface reads (which need a subprocess) or /run/sentinelai-lab:
the workload's application root is a directory inside DIR (the module constant APP_ROOT of the workload and of the
reader are set to it for this process tree only). The target is the workload's existing cgroup, read-only; in this
unprivileged rehearsal that cgroup is the invoking user's session cgroup, so cgroup-scoped M3A measurements include
other session processes. The parameter set is the uncalibrated validation set plus app.* floors (rehearsal only).

Timeline (period 1 s): ticks 0..B idle (baseline), load from tick B + LOAD_OFFSET_S for LOAD_S seconds, then idle
until tick B + W, so the whole load lies inside the measured window and the window's counter deltas can be
reconciled exactly with the client records.

DIR layout: evidence/ (raw evidence, all covered by manifest.json): ticks.jsonl (runtime.ticks lossless format),
client.jsonl (load generator records), config.json and dependency_config.json (ground-truth echoes), control.json
(the driver's control input), run.json (parameters, target, parameter set, timeline, exit codes); manifest.json;
snapshot.json (live snapshot, canonical bytes); report.json (checks); logs/ (process stderr); app/ (workload files).
"""
import argparse
import hashlib
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from sentinelai.collectors import LiveReader, SystemClock, build_snapshot, collect, resolve_target  # noqa: E402
from sentinelai.collectors import app as appmod  # noqa: E402
from sentinelai.diagnostic.contract import Target, canonical_bytes  # noqa: E402
from sentinelai.diagnostic.rules import ParameterSet  # noqa: E402
from sentinelai.runtime import registry  # noqa: E402
from sentinelai.runtime.pipeline import validate_snapshot  # noqa: E402
from sentinelai.runtime.ticks import decode_ticks, encode_ticks  # noqa: E402

FORMAT = "sentinelai.m4.rehearsal.v1"
WORKLOAD = ROOT / "experiments" / "faultlab" / "docker" / "workload.py"
LOADGEN = ROOT / "experiments" / "faultlab" / "docker" / "loadgen.py"
PY = sys.executable
BASE_PARAMS = "r2c-validation-uncalibrated"
PARAMS_ID = "m4-rehearsal-uncalibrated"
EVIDENCE, MANIFEST = "evidence", "manifest.json"
MANIFEST_MAX = 1 << 20
PERIOD_S = 1.0
# Rehearsal profiles (engineering choices for loopback smoke runs, not experiment parameters). publish_s < PERIOD_S,
# so every collector tick sees a fresh document. "overload" saturates pool and queue so that 503s are reconciled too.
PROFILES = {
    "smoke": {"workload": {"pool": 4, "queue": 32, "cpu_us": 500, "lock_hold_us": 200, "lock_wait_exceeded_ms": 5.0,
                           "dependency_timeout_ms": 1000.0, "publish_s": 0.25, "poll_s": 0.05},
              "dependency_delay_ms": 2, "load": {"rate": 40.0, "jitter": 0.5, "timeout_s": 5.0, "max_inflight": 64}},
    "overload": {"workload": {"pool": 1, "queue": 2, "cpu_us": 500, "lock_hold_us": 200, "lock_wait_exceeded_ms": 5.0,
                              "dependency_timeout_ms": 1000.0, "publish_s": 0.25, "poll_s": 0.05},
                 "dependency_delay_ms": 30, "load": {"rate": 60.0, "jitter": 0.5, "timeout_s": 5.0,
                                                     "max_inflight": 64}},
}
LOAD_OFFSET_S, LOAD_TAIL_S = 0.5, 3.0          # load starts 0.5 s after tick B and ends 3 s before tick B + W
READY_TIMEOUT_S, STOP_TIMEOUT_S = 10.0, 10.0
_LAUNCH = ("import importlib.util, sys; s = importlib.util.spec_from_file_location('faultlab_workload', sys.argv[1]); "
           "w = importlib.util.module_from_spec(s); s.loader.exec_module(w); w.APP_ROOT = sys.argv[2]; "
           "sys.exit(w.main(sys.argv[3:]))")


class RehearsalError(RuntimeError):
    """Setup or startup failure (exit status 2)."""


def _loadgen_module():
    spec = importlib.util.spec_from_file_location("faultlab_loadgen", LOADGEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def scheduled_arrivals(rate: float, duration_s: float, jitter: float, seed: int) -> int:
    """Arrivals the load generator schedules, from its own schedule() (independent of the records it writes)."""
    return len(_loadgen_module().schedule(rate, duration_s, jitter, seed))


# ------------------------------------------------------------------------------------------ processes
class Proc:
    """A child process this driver started; only these are ever signalled."""
    started = []

    def __init__(self, name: str, argv, log_dir: Path):
        self.name = name
        self.log = log_dir / f"{name}.stderr"
        self.fh = open(self.log, "wb")
        self.p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self.fh,
                                  cwd=str(log_dir))
        Proc.started.append(self)

    def alive(self) -> bool:
        return self.p.poll() is None

    def stderr_tail(self) -> str:
        self.fh.flush()
        return self.log.read_bytes()[-2000:].decode(errors="replace")

    def wait_ready(self, ready, timeout_s: float) -> None:
        end = time.monotonic() + timeout_s
        while time.monotonic() < end:
            if not self.alive():
                raise RehearsalError(f"{self.name} exited during startup with status {self.p.returncode}: "
                                     f"{self.stderr_tail()}")
            if ready():
                return
            time.sleep(0.02)
        raise RehearsalError(f"{self.name} not ready within {timeout_s} s")

    def stop(self, timeout_s: float = STOP_TIMEOUT_S):
        if self.alive():
            self.p.send_signal(signal.SIGTERM)
            try:
                self.p.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(timeout=timeout_s)
        self.fh.close()
        return self.p.returncode


def stop_all():
    codes = {}
    for proc in reversed(Proc.started):
        codes[proc.name] = proc.stop()
    Proc.started.clear()
    return codes


def free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def port_open(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()   # a connect with no bytes: not a request
        return True
    except OSError:
        return False


def cgroup_of(pid: int) -> str:
    for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            return line[3:]
    raise RehearsalError(f"no cgroup v2 path for pid {pid}")


def rehearsal_params() -> ParameterSet:
    base = registry.get(BASE_PARAMS)
    numbers = dict(base.numbers)
    numbers.update({f"floor[{f}]": 0.001 for f in appmod.APP_FEATURES})
    return ParameterSet(parameter_set_id=PARAMS_ID, numbers=numbers, reason_sets=dict(base.reason_sets))


# ------------------------------------------------------------------------------------------ manifest
def _safe_rel(p) -> bool:
    return (isinstance(p, str) and p.startswith(EVIDENCE + "/") and "\\" not in p and "\0" not in p
            and os.path.normpath(p) == p and ".." not in p.split("/") and not os.path.isabs(p))


def _scan(out: Path):
    """(files, problems): every regular file below DIR/evidence, run-relative; symlinks and other types refused."""
    files, problems = [], []
    top = out / EVIDENCE
    if top.is_symlink() or not top.is_dir():
        return [], [f"{EVIDENCE}/ is missing or not a real directory"]

    def walk(d: Path, rel: str):
        for e in sorted(os.scandir(d), key=lambda e: e.name):
            r = f"{rel}/{e.name}"
            if e.is_symlink():
                problems.append(f"symbolic link in evidence: {r}")
            elif e.is_dir(follow_symlinks=False):
                walk(Path(e.path), r)
            elif e.is_file(follow_symlinks=False):
                files.append(r)
            else:
                problems.append(f"not a regular file: {r}")
    walk(top, EVIDENCE)
    return files, problems


def _sha256(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                return h.hexdigest()
            h.update(chunk)
    finally:
        os.close(fd)


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def write_manifest(out: Path) -> dict:
    files, problems = _scan(out)
    if problems:
        raise RehearsalError("; ".join(problems))
    doc = {"files": {f: _sha256(out / f) for f in files}}
    _write_new(out / MANIFEST, (json.dumps(doc, sort_keys=True, indent=1) + "\n").encode())
    return doc


def verify_manifest(out: Path):
    """Problems ([] = verified): manifest format and paths, missing, changed and unexpected evidence files."""
    try:
        fd = os.open(out / MANIFEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        return [f"manifest unreadable: {exc.strerror}"]
    try:
        raw = os.read(fd, MANIFEST_MAX + 1)
    finally:
        os.close(fd)
    try:
        doc = json.loads(raw)
        listed = doc["files"]
        if len(raw) > MANIFEST_MAX or set(doc) != {"files"} or not isinstance(listed, dict):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        return ["manifest malformed"]
    problems = [f"unsafe manifest path: {p!r}" for p in listed if not _safe_rel(p)]
    problems += [f"malformed digest for {p!r}" for p, h in listed.items()
                 if not (isinstance(h, str) and len(h) == 64 and set(h) <= set("0123456789abcdef"))]
    files, scan_problems = _scan(out)
    problems += scan_problems
    actual = set(files)
    safe = {p for p in listed if _safe_rel(p)}
    problems += [f"missing listed file: {p}" for p in sorted(safe - actual)]
    problems += [f"unexpected evidence file: {p}" for p in sorted(actual - set(listed))]
    problems += [f"digest mismatch: {p}" for p in sorted(safe & actual) if _sha256(out / p) != listed[p]]
    return problems


# ------------------------------------------------------------------------------------------ replay and checks
def load_run(out: Path):
    run = json.loads((out / EVIDENCE / "run.json").read_bytes())
    if run.get("format") != FORMAT:
        raise RehearsalError(f"run.json format {run.get('format')!r}")
    return run


def replay(out: Path) -> bytes:
    """Canonical snapshot bytes rebuilt from the saved evidence only (no service, no live read)."""
    run = load_run(out)
    ticks = decode_ticks((out / EVIDENCE / "ticks.jsonl").read_bytes())
    target = Target.model_validate_json(json.dumps(run["target"]), strict=False)       # JSON mode: arrays -> tuples
    params = ParameterSet.model_validate_json(json.dumps(run["parameter_set"]), strict=False)
    snap = build_snapshot(ticks, target, params, run["period_s"], run["ebpf"], run["app"])
    return validate_snapshot(canonical_bytes(snap))[1]


def app_feature_report(snap_bytes: bytes, structural=None):
    """(rows, problems): every registry app.* measurement with quality OK or PARTIAL, at app:<target>.

    structural {feature_id: reason}: features the caller has proven, from the run's verified evidence, that its
    configuration cannot produce (pilot CTRL: app.lock_wait_ms with lock_hold_us 0). For those only, a MISSING
    measurement without a value at the right scope, and their missing entry at the right scope, are accepted and noted
    on the row; never measured, any other quality or another scope still fail. Default: nothing is exempt."""
    from sentinelai.diagnostic.contract import load_contract
    structural = dict(structural or {})
    snap = json.loads(snap_bytes)
    scope = f"app:{snap['target']['name']}"
    want = set()
    for f in load_contract().registry.features:
        if f.family == "application":
            for a in f.aggregations:
                for q in (sorted(f.dimension.values) if f.dimension else [None]):
                    want.add((f.id, str(getattr(a, "value", a)), q))
    rows, problems, seen = [], [], set()
    for m in snap["measurements"]:
        if not m["feature_id"].startswith("app."):
            continue
        key = (m["feature_id"], m["aggregation"], (m.get("qualifier") or {}).get("value"))
        seen.add(key)
        rows.append({"feature": key[0], "aggregation": key[1], "qualifier": key[2], "quality": m["quality"],
                     "value": m["value"], "coverage": m["coverage"], "scope": m["scope"]})
        if key[0] in structural and m["quality"] == "MISSING" and m["value"] is None and m["scope"] == scope:
            rows[-1]["structurally_unavailable"] = structural[key[0]]
        elif m["quality"] not in ("OK", "PARTIAL"):
            problems.append(f"{key}: quality {m['quality']}")
        if m["scope"] != scope:
            problems.append(f"{key}: scope {m['scope']}")
    problems += [f"not measured: {k}" for k in sorted(want - seen, key=str)]
    missing = [mm for mm in snap["missing_measurements"] if mm["feature_id"].startswith("app.")
               and not (mm["feature_id"] in structural and mm.get("scope") == scope)]
    problems += [f"listed as missing: {mm['feature_id']} ({mm['reason']})" for mm in missing]
    if {"APP_METRICS", "APP_EVENTS"} & set(snap["data_quality"]["sources_unavailable"]):
        problems.append("application sources reported unavailable")
    return sorted(rows, key=lambda r: (r["feature"], r["aggregation"], r["qualifier"] or "")), problems


def reconcile(out: Path):
    """(summary, problems): the window's counter deltas (documents at ticks B and B + W) against the client records.
    Exact equality is required, and is valid only if the load lies wholly inside the window: the start document
    predates every send, the end document postdates every completion and shows no busy worker (busy is decremented
    after a request is counted, so 0 means every admitted request has been counted)."""
    run = load_run(out)
    ticks = decode_ticks((out / EVIDENCE / "ticks.jsonl").read_bytes())
    recs = [json.loads(x) for x in (out / EVIDENCE / "client.jsonl").read_text().splitlines()]
    nb, nw = run["nB"], run["nW"]
    a, b = ticks[nb].obs.get("app"), ticks[nb + nw].obs.get("app")
    problems = []
    if not isinstance(a, dict) or not isinstance(b, dict):
        return {}, [f"window boundary document not valid: start={a!r} end={b!r}"]
    n_sched = run["load"]["arrivals"]
    if [r["k"] for r in recs] != list(range(n_sched)):
        problems.append(f"client records do not cover the {n_sched} scheduled arrivals exactly once")
    outcomes = {}
    for r in recs:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    unexplained = set(outcomes) - {"200", "503", "504", "client_saturated"}    # saturated: never sent
    if unexplained:
        problems.append(f"client outcomes without a server counterpart: { {k: outcomes[k] for k in unexplained} }")
    sent = [r["sent_ns"] for r in recs if r["sent_ns"] is not None]
    done = [r["sent_ns"] + r["latency_ms"] * 1e6 for r in recs
            if r["sent_ns"] is not None and r["latency_ms"] is not None]
    if not sent:
        problems.append("no request was sent")
    else:
        if not a["mono_s"] * 1e9 < min(sent):
            problems.append("window start document does not predate the first send")
        if not max(done) < b["mono_s"] * 1e9:
            problems.append("window end document does not postdate the last completion")
    if b["pool_util"] != 0.0:
        problems.append("a worker was still busy at the window end document")
    delta = {k: b[k] - a[k] for k in ("requests_completed_total", "requests_rejected_total", "requests_failed_total")}
    expect = {"requests_completed_total": outcomes.get("200", 0), "requests_rejected_total": outcomes.get("503", 0),
              "requests_failed_total": outcomes.get("504", 0)}
    for k in delta:
        if delta[k] != expect[k]:
            problems.append(f"{k}: server delta {delta[k]:g} != client {expect[k]}")
    summary = {"client_outcomes": dict(sorted(outcomes.items())), "server_window_delta": delta,
               "client_saturated": outcomes.get("client_saturated", 0), "scheduled_arrivals": n_sched}
    return summary, problems


# ------------------------------------------------------------------------------------------ run
def run(out: Path, seed: int, profile: str = "smoke") -> int:
    if profile not in PROFILES:
        raise RehearsalError(f"unknown profile {profile!r}")
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    for d in ("logs", "app", EVIDENCE):
        (out / d).mkdir(mode=0o700)
    run_id = f"REHEARSAL-s{seed}"
    app_root = str(out / "app") + "/"
    run_dir = out / "app" / run_id
    run_dir.mkdir(mode=0o700)
    saved_root, appmod.APP_ROOT = appmod.APP_ROOT, app_root   # this process's reader looks where the workload writes
    try:
        return _run(out, seed, profile, run_id, app_root, run_dir)
    finally:
        appmod.APP_ROOT = saved_root


def _run(out: Path, seed: int, profile: str, run_id: str, app_root: str, run_dir: Path) -> int:
    prof = PROFILES[profile]
    w, load_cfg, delay_ms = prof["workload"], prof["load"], prof["dependency_delay_ms"]
    params = rehearsal_params()
    nb, nw = round(params.num("B") / PERIOD_S), round(params.num("W") / PERIOD_S)
    load_s = nw * PERIOD_S - LOAD_OFFSET_S - LOAD_TAIL_S
    report = {"format": FORMAT, "run_id": run_id, "checks": {}}
    codes, timeline = {}, {}
    try:
        control = json.dumps({"dependency_delay_ms": delay_ms}).encode()
        _write_new(run_dir / "control.json", control)
        dport, sport = free_port(), free_port()
        dep = Proc("dependency", [PY, "-I", "-c", _LAUNCH, str(WORKLOAD), app_root, "dependency", "--run-id", run_id,
                                  "--listen", f"127.0.0.1:{dport}", "--poll-s", str(w["poll_s"])],
                   out / "logs")
        dep.wait_ready(lambda: (run_dir / "dependency_config.json").exists() and port_open(dport), READY_TIMEOUT_S)
        srv = Proc("workload", [PY, "-I", "-c", _LAUNCH, str(WORKLOAD), app_root, "serve", "--run-id", run_id,
                                "--listen", f"127.0.0.1:{sport}", "--pool", str(w["pool"]), "--queue", str(w["queue"]),
                                "--cpu-us", str(w["cpu_us"]), "--lock-hold-us", str(w["lock_hold_us"]),
                                "--lock-wait-exceeded-ms", str(w["lock_wait_exceeded_ms"]),
                                "--dependency", f"127.0.0.1:{dport}",
                                "--dependency-timeout-ms", str(w["dependency_timeout_ms"]),
                                "--publish-s", str(w["publish_s"]), "--poll-s", str(w["poll_s"])], out / "logs")
        srv.wait_ready(lambda: (run_dir / "metrics.json").exists() and port_open(sport), READY_TIMEOUT_S)
        target = resolve_target(LiveReader(), "faultlab-rehearsal", cgroup_of(srv.p.pid), ())
        client = out / EVIDENCE / "client.jsonl"
        load_argv = [PY, "-I", str(LOADGEN), "--target", f"127.0.0.1:{sport}", "--rate", str(load_cfg["rate"]),
                     "--duration-s", str(load_s), "--jitter", str(load_cfg["jitter"]), "--seed", str(seed),
                     "--timeout-s", str(load_cfg["timeout_s"]), "--max-inflight", str(load_cfg["max_inflight"]),
                     "--out", str(client)]
        holder = {}

        def start_load():
            timeline["load_start_mono_ns"] = time.monotonic_ns()
            holder["proc"] = Proc("loadgen", load_argv, out / "logs")
        t0 = time.monotonic()
        timeline["collect_start_mono_ns"] = time.monotonic_ns()
        timer = threading.Timer(nb * PERIOD_S + LOAD_OFFSET_S, start_load)
        timer.start()
        try:
            ticks, stats = collect(target, params, LiveReader(), SystemClock(), PERIOD_S, None,
                                   appmod.AppSource(run_id))
        finally:
            timer.cancel()
        timeline["collect_end_mono_ns"] = time.monotonic_ns()
        lg = holder.get("proc")
        if lg is None:
            raise RehearsalError("the load generator was never started")
        try:
            lg.p.wait(timeout=STOP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            raise RehearsalError("the load generator did not finish") from None
        codes["loadgen"] = lg.p.returncode
        if lg.p.returncode != 0:
            raise RehearsalError(f"load generator exited with {lg.p.returncode}: {lg.stderr_tail()}")
        for name in ("config.json", "dependency_config.json", "control.json"):
            _write_new(out / EVIDENCE / name, (run_dir / name).read_bytes())
        _write_new(out / EVIDENCE / "ticks.jsonl", encode_ticks(ticks))
        snap = build_snapshot(ticks, target, params, PERIOD_S, False, True)
        live = validate_snapshot(canonical_bytes(snap))[1]
        _write_new(out / "snapshot.json", live)
        codes.update(stop_all())
        arrivals = scheduled_arrivals(load_cfg["rate"], load_s, load_cfg["jitter"], seed)
        run_doc = {"format": FORMAT, "run_id": run_id, "seed": seed, "period_s": PERIOD_S, "ebpf": False, "app": True,
                   "nB": nb, "nW": nw, "target": target.model_dump(mode="json"),
                   "parameter_set": params.model_dump(mode="json"),
                   "profile": profile, "workload": dict(w, dependency_delay_ms=delay_ms),
                   "load": dict(load_cfg, duration_s=load_s, offset_s=LOAD_OFFSET_S, seed=seed, arrivals=arrivals),
                   "timeline": timeline, "collection": {"ticks": stats.ticks, "wall_s": stats.wall_s,
                                                        "cpu_s": stats.cpu_s},
                   "exit_codes": codes, "collect_t0_monotonic_s": t0}
        _write_new(out / EVIDENCE / "run.json", (json.dumps(run_doc, sort_keys=True, indent=1) + "\n").encode())
        write_manifest(out)
    except BaseException as exc:
        codes.update(stop_all())
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["exit_codes"] = codes
        (out / "report.json").write_text(json.dumps(report, sort_keys=True, indent=1) + "\n")
        if isinstance(exc, (RehearsalError, OSError)):
            print(f"rehearsal: setup/startup failure: {exc}", file=sys.stderr)
            return 2
        raise
    rc = check(out, live, report, codes)
    return rc


def check(out: Path, live: bytes, report: dict, codes: dict) -> int:
    checks = report["checks"]
    m = verify_manifest(out)
    checks["manifest"] = {"ok": not m, "problems": m}
    try:
        rep = replay(out)
        checks["replay_byte_identical"] = {"ok": rep == live, "live_sha256": hashlib.sha256(live).hexdigest(),
                                           "replay_sha256": hashlib.sha256(rep).hexdigest()}
    except Exception as exc:                          # recorded, never hidden
        checks["replay_byte_identical"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    rows, problems = app_feature_report(live)
    checks["app_features"] = {"ok": not problems, "problems": problems, "measurements": rows}
    summary, problems = reconcile(out)
    checks["reconciliation"] = dict(summary, ok=not problems, problems=problems)
    bad_codes = {k: v for k, v in codes.items() if v != 0}
    checks["exit_codes"] = {"ok": not bad_codes, "codes": codes}
    ticks = decode_ticks((out / EVIDENCE / "ticks.jsonl").read_bytes())
    report["app_tick_problems"] = [{"tick": t.index, "status": t.obs["app"].status.value, "detail": t.obs["app"].detail}
                                   for t in ticks if not isinstance(t.obs.get("app"), dict)]
    report["ok"] = all(c["ok"] for c in checks.values())
    (out / "report.json").write_text(json.dumps(report, sort_keys=True, indent=1) + "\n")
    return 0 if report["ok"] else 1


def verify(out: Path) -> int:
    """Manifest and replay checks on a finished run (nothing is started)."""
    problems = verify_manifest(out)
    try:
        rep = replay(out)
        same = rep == (out / "snapshot.json").read_bytes()
    except Exception as exc:
        problems.append(f"replay failed: {type(exc).__name__}: {exc}")
        same = False
    if not same:
        problems.append("replayed snapshot differs from snapshot.json")
    print(json.dumps({"ok": not problems, "problems": problems}, indent=1))
    return 0 if not problems else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--out", default=None, help="new directory for the run (default: a fresh temporary directory)")
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--profile", choices=sorted(PROFILES), default="smoke")
    v = sub.add_parser("verify")
    v.add_argument("dir")
    a = ap.parse_args(argv)
    if a.cmd == "verify":
        return verify(Path(a.dir))
    out = Path(a.out) if a.out else Path(tempfile.mkdtemp(prefix="sentinelai-rehearsal-")) / "run"
    if out.exists() or out.is_symlink():
        print(f"rehearsal: {out} already exists; refusing to reuse it", file=sys.stderr)
        return 2

    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")      # unwinds through run(), which stops its children
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        rc = run(out, a.seed, a.profile)
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps({"dir": str(out), "exit": rc}))
    return rc


if __name__ == "__main__":
    sys.exit(main())
