#!/usr/bin/env python3
"""SentinelAI R2-C: one controlled CPU-contention run (or the calibration step), as root, on the host.

Run only through scripts/r2c_validate.sh (taskset -c 0-15; the wrapper's trap repeats the cleanup).

  boundary  create /sys/fs/cgroup/sentinel-r2c {target, contender} (r2c_cpu.setup_plan), verify it (verify_lab)
  target    r2c_target.py in the target leaf (CPU 18), private interface-less netns, uid 1000
  collect   M3A + M3B for the target cgroup: B without contender, W with the contender (E1/E2/N1/N2)
  contender python3 -c busy loop in the contender leaf, started right after the last baseline tick, SIGKILLed right
            after the last window tick
  truth     an independent ground-truth observation (r2c_cpu.gt_sample) at every collector tick and every second of
            warm-up and recovery; placement, quota and NIC-IRQ checks abort immediately
  M2        the unchanged engine diagnoses the snapshot; its output is recorded, never predicted
  cleanup   always (finally), from the op log; then the host is compared with the snapshot taken before the run
Writes OUT/run.json, OUT/snapshot.json, OUT/raw_ebpf.jsonl, OUT/target.json, OUT/ops.jsonl, OUT/host_{before,after}.
"""

import argparse
import json
import os
import re
import signal
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

import r2c_cpu as C  # noqa: E402
from m3b_r1_validate import Recording  # noqa: E402  (production ProcessEbpfSource + raw-line recording)
from r2b_driver import KFREE_REASONS_LOSS, NUMBERS, m2_summary  # noqa: E402  (the validation-only parameter values)
from sentinelai.collectors import LiveReader, SystemClock, build_snapshot, collect, collected_features  # noqa: E402
from sentinelai.collectors import resolve_target  # noqa: E402
from sentinelai.diagnostic.contract import EvidenceSnapshot, SourceType  # noqa: E402
from sentinelai.diagnostic.contract.serialize import canonical_bytes  # noqa: E402
from sentinelai.diagnostic.rules import ParameterSet, diagnose  # noqa: E402
from sentinelai.diagnostic.rules.engine import DEV_FEATURES  # noqa: E402
from sentinelai.ebpf import loader_argv, resolve_ebpf_target  # noqa: E402

PARAMETER_SET_ID = "r2c-validation-uncalibrated"
CC_CLAUSES = ("CC.R1", "CC.R2", "CC.X1", "CC.X2")
REPORTED = ("sched.run_delay_excess.target", "sched.run_delay.target", "cpu.util.cpuset", "cpu.steal.cpuset",
            "sched.latency_hist.target", "throttle.ratio", "throttle.time_rate", "throttle.quota_limited",
            "softirq.frac.percpu", "psi.cpu.some.target", "sched.involuntary_cs.target", "sched.run_delay.cpuset",
            "cpu.usage.target", "cpu.util.host", "psi.cpu.some.host")


def params():
    """The R2-B validation numbers, unchanged (contract §6: uncalibrated); all floors 1e-3."""
    nums = dict(NUMBERS)
    nums.update({f"floor[{f}]": 1e-3 for f in set(DEV_FEATURES) | set(collected_features(True))})
    return ParameterSet(parameter_set_id=PARAMETER_SET_ID, numbers=nums,
                        reason_sets={"KFREE_REASONS_LOSS": KFREE_REASONS_LOSS})


class Interrupted(BaseException):
    """SIGINT / SIGTERM: unwinds to the finally block (cleanup)."""


class Done(Exception):
    """The calibration step finished: skip the run body, still clean up in finally."""


def on_signal(signum, frame):
    raise Interrupted(signal.Signals(signum).name)


class WindowClock(SystemClock):
    """Calls on_window() once, right after the last baseline tick (before sleeping to tick NB+1)."""

    def __init__(self, on_window):
        self.on_window, self.calls = on_window, 0

    def sleep_until(self, mono):
        if self.calls == C.NB + 1:
            self.on_window()
        self.calls += 1
        super().sleep_until(mono)


class GTSource:
    """Feeds the snapshot from the eBPF loader and takes the ground-truth observation at the same tick."""

    def __init__(self, loader, observe):
        self.loader, self.observe = loader, observe

    def sample(self):
        out = self.loader.sample()
        self.observe("tick")
        return out


def _stat(sysr, pid):
    """(comm, ppid) of a pid, or None."""
    text = sysr.read(f"/proc/{pid}/stat")
    if not text or ")" not in text:
        return None
    comm = text[text.index("(") + 1:text.rindex(")")]
    return comm, int(text.rsplit(")", 1)[1].split()[1])


def precreate(path, size=0):
    """An output file the unprivileged lab process may write (owned by uid 1000)."""
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    try:
        if size:
            os.write(fd, b"\0" * size)
        os.fchown(fd, C.LAB_UID, C.LAB_GID)
    finally:
        os.close(fd)


class Run:
    def __init__(self, exp, sysr, host, out):
        self.exp, self.sys, self.host, self.out = exp, sysr, host, out
        self.obs, self.expected, self.in_w = [], [], []
        self.want = {"target": [], "contender": []}
        self.window = False
        self.target_pid = None
        self.procs = []

    def observe(self, tag):
        t = C.gt_sample(self.sys, time.monotonic(), self.target_pid)
        t["tag"] = tag
        self.obs.append(t)
        self.expected.append({k: list(v) for k, v in self.want.items()})
        self.in_w.append(self.window)
        bad = C.placement_violations(t, self.exp, self.want, self.window) + C.immediate_aborts(t)
        if bad:
            raise C.LabAbort(f"{tag} observation {len(self.obs) - 1}: {bad}")

    def observe_until_exit(self, proc, tag):
        """Observation while the workload behind wrapper `proc` may be finishing normally. The only violation it may
        excuse is an observation that raced that normal exit: the target leaf empty, nothing else wrong, and the
        wrapper gone within 0.5 s with rc 0. That observation is discarded; any other violation still aborts."""
        try:
            self.observe(tag)
        except C.LabAbort:
            t, want = self.obs[-1], self.expected[-1]
            others = [v for v in C.placement_violations(t, self.exp, {**want, "target": []}, self.in_w[-1])]
            if t["leaves"]["target"]["procs"] != [] or others or C.immediate_aborts(t):
                raise
            try:
                rc = proc.wait(0.5)
            except Exception:                                        # noqa: BLE001 -- still running: genuine
                raise C.LabAbort(f"{tag}: target cgroup empty while its wrapper still runs")
            if rc != 0:
                raise
            del self.obs[-1], self.expected[-1], self.in_w[-1]
            return False
        return True

    def spawn(self, role, argv):
        leaf = C.CONTENDER_DIR if role == "contender" else C.TARGET_DIR
        so, se = open(self.out / f"{role}.stdout", "w"), open(self.out / f"{role}.stderr", "w")
        p = self.host.apply(("spawn", role, argv), stdout=so, stderr=se)
        self.procs.append(p)
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:          # wrapper outside the leaf; exactly one pid (the workload) inside
            procs = sorted(int(x) for x in (self.sys.read(f"{leaf}/cgroup.procs") or "").split())
            w = _stat(self.sys, p.pid)
            k = _stat(self.sys, procs[0]) if len(procs) == 1 else None
            if p.pid not in procs and w and w[0] == "timeout" and k and k[0] == "python3" and k[1] == p.pid:
                return p, procs[0]
            if len(procs) > 1 or p.pid in procs:
                raise C.LabAbort(f"{role} cgroup holds {procs}: one-pid invariant broken")
            if p.poll() is not None:
                raise C.LabAbort(f"{role} exited during start (rc {p.returncode})")
            time.sleep(0.01)
        raise C.LabAbort(f"{role} did not reach the one-pid structure (timeout outside -> python3 inside) in 3 s")

    def wait_empty(self, leaf, seconds=2.0):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            procs = self.sys.read(f"{leaf}/cgroup.procs")
            if procs is not None and not procs.strip():
                return True
            time.sleep(0.01)
        return False


def cc_items(d):
    return sorted(({"clause": i.predicate_id, "kind": i.kind.value, "strength": i.strength.value if i.strength else None,
                    "observed": i.observed, "missing_reason": i.missing_reason,
                    "supports": [l.value for l in i.supports], "contradicts": [l.value for l in i.contradicts]}
                   for i in d.snapshot.evidence_items if i.predicate_id in CC_CLAUSES), key=lambda x: x["clause"])


def measurement_rows(snap):
    return [{"feature": m.feature_id, "scope": m.scope, "aggregation": m.aggregation.value, "unit": m.unit.value,
             "value": m.value, "quality": m.quality.value, "coverage": m.coverage,
             "baseline_median": m.baseline.median if m.baseline else None,
             "baseline_adequate": m.baseline.adequate if m.baseline else None,
             "ratio": m.deviation.ratio if m.deviation else None, "robust_z": m.deviation.robust_z if m.deviation else None}
            for m in snap.measurements if m.feature_id in REPORTED
            and (m.feature_id != "softirq.frac.percpu" or m.scope == f"cpu:{C.TARGET_CPU}")]


def refuse(msg):
    raise SystemExit(f"REFUSING: {msg}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--run", help="a label of r2c_cpu.MATRIX")
    ap.add_argument("--calibrate", action="store_true")
    ap.add_argument("--iters", type=int)
    ap.add_argument("--commit", required=True, help="git HEAD of the checkout (M2 EngineInfo requires a git hash)")
    ap.add_argument("--execute", action="store_true", help="required: this run mutates the host")
    a = ap.parse_args()
    # ---- refusals: nothing has been touched yet
    if not a.execute:
        refuse("--execute not given (use scripts/r2c_cpu.py dry-run for a read-only check)")
    if os.geteuid() != 0 or os.environ.get("SUDO_UID") != str(C.LAB_UID):
        refuse(f"must run as root via sudo from uid {C.LAB_UID}")
    if not re.fullmatch(r"[0-9a-f]{7,40}", a.commit):
        refuse(f"--commit {a.commit!r} is not a git hash")
    if not set(os.sched_getaffinity(0)) <= set(C.SUPPORT_CPUS):
        refuse(f"driver must be confined to CPUs {C.SUPPORT_CPUS[0]}-{C.SUPPORT_CPUS[-1]} (taskset)")
    if a.calibrate == bool(a.run):
        refuse("exactly one of --calibrate / --run")
    exp = C.EXPERIMENTS["E0"] if a.calibrate else C.experiment_of(a.run)
    if not a.calibrate:
        C.target_argv(a.iters, "/x")                    # range check before anything runs
    out = Path(a.out)
    if not C._results_path(out / "x"):
        refuse(f"output {out} outside results/phase1c_r2c")
    out.mkdir(parents=True, exist_ok=False)
    sysr = C.Sys()
    R = {"label": "calibration" if a.calibrate else a.run, "experiment": exp.__dict__, "commit": a.commit,
         "criteria": C.CRITERIA,
         "events": [], "aborts": [], "design": {"target_cpu": C.TARGET_CPU, "parent_cpus": C.PARENT_CPUS,
                                                "warmup_s": C.WARMUP_S, "nb": C.NB, "nw": C.NW,
                                                "recovery_s": C.RECOVERY_S, "hard_timeout_s": C.HARD_TIMEOUT_S}}
    ev = lambda name, **kw: R["events"].append({"t_mono": time.monotonic(), "event": name, **kw})

    def save():
        (out / "run.json").write_text(json.dumps(R, indent=1, sort_keys=True, default=str))

    (out / "host_before").mkdir()
    base = C.host_snapshot(sysr)
    (out / "host_before" / "host.json").write_text(json.dumps(base, indent=1, sort_keys=True))
    R["preflight"] = C.preflight(sysr)
    if not R["preflight"]["ok"] or not base["bpf_available"]:
        save()
        refuse(f"preflight failed: {[k for k, v in R['preflight']['checks'].items() if not v]}")

    oplog = str(out / "ops.jsonl")
    host = C.Host(exp, oplog, a.iters, sysr)
    run = Run(exp, sysr, host, out)
    loader = None
    old = {s: signal.signal(s, on_signal) for s in (signal.SIGINT, signal.SIGTERM)}   # cleanup is registered first
    try:
        ev("setup_start")
        for op in C.setup_plan(exp):
            host.apply(op)
        R["verify_lab"] = C.verify_lab(sysr, exp)
        if not R["verify_lab"]["ok"]:
            raise C.LabAbort(f"lab verification failed: {[k for k, v in R['verify_lab']['checks'].items() if not v]}")
        ev("lab_verified")
        if a.calibrate:
            precreate(out / "calibration.json")
            p, py = run.spawn("calibration", C.calibration_argv(str(out / "calibration.json")))
            run.want["target"] = [py]
            t_end = time.monotonic() + C.HARD_TIMEOUT_S
            while p.poll() is None and time.monotonic() < t_end:
                run.observe_until_exit(p, "calibration")
                time.sleep(1.0)
            if p.poll() is None or p.returncode != 0:
                raise C.LabAbort(f"calibration did not complete (rc {p.poll()})")
            R["calibration"] = json.loads((out / "calibration.json").read_text())
            R["iters"] = R["calibration"]["iters"]
            R["role"] = ("runtime step 0: provenance only, excluded from experiment evidence and baselines; "
                         "no collection, no snapshot, no M2")
            R["driver_ok"] = True
            raise Done()
        precreate(out / "target.json")
        if exp.contender_cpu is not None:
            precreate(out / "contender.cnt", size=8)
        tp, tpy = run.spawn("target", C.target_argv(a.iters, str(out / "target.json")))
        t_spawn = time.monotonic()
        run.want["target"] = [tpy]
        run.target_pid = tpy
        ev("target_started", wrapper=tp.pid, pid=tpy)
        target = resolve_target(LiveReader(), "r2c", C.TARGET_CGROUP_PATH)
        if sorted(target.pids) != run.want["target"] or target.cpuset != str(C.TARGET_CPU):
            raise C.LabAbort(f"resolved target {target} differs from the started target")
        ids = resolve_ebpf_target(target)
        R["target"] = {"cgroup_path": target.cgroup_path, "pids": list(target.pids), "cpuset": target.cpuset,
                       "netns_ref": target.netns_ref, "ifaces": list(target.ifaces), "ebpf": ids.__dict__,
                       "netns_inode": os.stat(f"/proc/{tpy}/ns/net").st_ino,
                       "host_netns_inode": os.stat("/proc/1/ns/net").st_ino}
        if R["target"]["netns_inode"] == R["target"]["host_netns_inode"]:
            raise C.LabAbort("target is not in a private network namespace")
        loader = Recording(loader_argv(ids, 300), ids, 5.0)
        R["loader_start"] = loader.start()
        if R["loader_start"]:
            raise C.LabAbort(f"eBPF loader unavailable: {R['loader_start']}")
        while time.monotonic() < t_spawn + C.WARMUP_S:     # warm-up, observed every second
            run.observe("warmup")
            time.sleep(1.0)
        contender = {}

        def on_window():
            run.window = True
            if exp.contender_cpu is not None:
                cp, cpy = run.spawn("contender", C.contender_argv(str(out / "contender.cnt")))
                contender.update(wrapper=cp, pid=cpy)
                run.want["contender"] = [cpy]
                ev("contender_started", wrapper=cp.pid, pid=cpy)
            else:
                ev("no_contender_window")

        i_b0 = len(run.obs)
        ev("collect_start")
        ticks, cstats = collect(target, params(), LiveReader(), WindowClock(on_window), C.PERIOD_S,
                                GTSource(loader, run.observe))
        ev("collect_end")
        if contender:
            host.apply(("kill", contender["pid"]))
            ev("contender_killed", pid=contender["pid"])
            if not run.wait_empty(C.CONTENDER_DIR):
                raise C.LabAbort("contender cgroup not empty 2 s after SIGKILL")
            contender["wrapper"].wait(2)
            R["contender_iterations"] = int.from_bytes((out / "contender.cnt").read_bytes()[:8], "little")
        run.want["contender"], run.window = [], False
        i_w0, i_w1 = i_b0 + C.NB, i_b0 + C.NB + C.NW
        R["window"] = {"start_mono": ticks[C.NB].mono, "end_mono": ticks[C.NB + C.NW].mono,
                       "start_wall": str(ticks[C.NB].wall), "end_wall": str(ticks[C.NB + C.NW].wall),
                       "obs_index": [i_b0, i_w0, i_w1]}
        while tp.poll() is None and time.monotonic() < t_spawn + C.HARD_TIMEOUT_S:   # recovery
            run.observe_until_exit(tp, "recovery")
            time.sleep(1.0)
        if tp.poll() is None or tp.returncode != 0:
            raise C.LabAbort(f"target did not complete (rc {tp.poll()})")
        target_out = json.loads((out / "target.json").read_text())
        R["target_result"] = {"pid": target_out["pid"], "cycles": target_out["cycles"], "iters": target_out["iters"],
                              "checksum": target_out["checksum"]}
        if target_out["pid"] != tpy or target_out["cycles"] != C.TARGET_CYCLES:
            raise C.LabAbort("target output does not belong to the started target or is incomplete")

        snap = build_snapshot(ticks, target, params(), C.PERIOD_S, ebpf=True)
        (out / "snapshot.json").write_bytes(canonical_bytes(snap))
        again = EvidenceSnapshot.model_validate_json(canonical_bytes(snap), strict=False)
        R["snapshot"] = {"id": snap.snapshot_id, "measurements": len(snap.measurements),
                         "ebpf_measurements": sum(m.provenance.source is SourceType.EBPF for m in snap.measurements),
                         "round_trip_identical": canonical_bytes(again) == canonical_bytes(snap),
                         "rebuild_identical": canonical_bytes(build_snapshot(ticks, target, params(), C.PERIOD_S,
                                                                             ebpf=True)) == canonical_bytes(snap),
                         "gate_passed": snap.data_quality.gate_passed, "max_tick_read_s": cstats.max_tick_read_s}
        R["measurements"] = measurement_rows(snap)
        R["metric_gate"] = C.metric_gate(snap, NUMBERS["COV_MIN"], NUMBERS["N_BASE_MIN"])
        R["aborts"] += R["metric_gate"]["aborts"]
        hz = os.sysconf("SC_CLK_TCK")
        R["ground_truth"] = C.evaluate_ground_truth(run.obs, i_b0, i_w0, i_w1, exp, run.expected, run.in_w,
                                                    target_out, hz)
        R["aborts"] += C.ground_truth_aborts(R["ground_truth"], exp) + C.host_level_aborts(run.obs, i_b0, i_w0, i_w1)
        save()
        d = diagnose(snap, params(), code_commit=a.commit)        # recorded, never predicted
        R["m2"] = m2_summary(d)
        R["m2"]["cc_items"] = cc_items(d)
        R["snapshot_unchanged_by_m2"] = canonical_bytes(snap) == (out / "snapshot.json").read_bytes()
        (out / "raw_ebpf.jsonl").write_text("\n".join(l or "" for l in loader.raw))
    except Done:
        pass
    except (C.LabAbort, Interrupted, Exception) as exc:              # noqa: BLE001 -- every failure: abort + cleanup
        R["aborts"].append(f"{type(exc).__name__}: {exc}")
        ev("abort", reason=repr(exc))
    finally:
        for s in old:                                                # a second signal must not interrupt cleanup
            signal.signal(s, signal.SIG_IGN)
        if loader is not None:
            loader.close()
        R["cleanup"] = C.cleanup(host, sysr, C.read_oplog(oplog))
        for p in run.procs:
            try:
                p.wait(2)
            except Exception:                                       # noqa: BLE001
                pass
        R["bpf_release"] = C.wait_bpf_released(sysr, base)          # run-owned eBPF objects freed (read-only poll)
        if R["bpf_release"]["released"]:                           # the authoritative post-run snapshot, only now
            (out / "host_after").mkdir()
            after = C.host_snapshot(sysr)
            (out / "host_after" / "host.json").write_text(json.dumps(after, indent=1, sort_keys=True))
            R["host_compare"] = C.compare_host(base, after)
        else:                                                      # evidence only; never compared as authoritative
            (out / "host_after_unreleased").mkdir()
            (out / "host_after_unreleased" / "host.json").write_text(
                json.dumps(C.host_snapshot(sysr), indent=1, sort_keys=True))
            R["host_compare"] = {"ok": False, "failed": ["bpf_objects_not_released"]}
            R["aborts"].append(f"ABORT: BPF objects not released within {C.BPF_RELEASE_MAX_S} s: "
                               f"{R['bpf_release']['remaining']}")
        R["observations"] = run.obs
        if not R["cleanup"]["ok"]:
            R["aborts"].append(f"cleanup failure: {R['cleanup']['errors'] or R['cleanup']['verify']}")
        if not R["host_compare"]["ok"]:
            R["aborts"].append(f"host state differs from the pre-run snapshot: {R['host_compare']['failed']}")
        R.setdefault("driver_ok", False)
        R["driver_ok"] = bool(not R["aborts"] and (a.calibrate and R["driver_ok"] or R.get("snapshot_unchanged_by_m2")))
        R["verdict"] = "OK" if R["driver_ok"] else "ABORT"
        save()
        for s, h in old.items():
            signal.signal(s, h)
    print(json.dumps({"label": R["label"], "verdict": R["verdict"], "aborts": R["aborts"][:5],
                      "m2": R.get("m2", {}).get("decision"), "iters": R.get("iters")}))
    return 0 if R["driver_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
