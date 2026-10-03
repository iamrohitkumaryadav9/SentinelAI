#!/usr/bin/env python3
"""SentinelAI R2-D: one controlled CPU-throttling run (or the calibration step), as root, on the host.

Run only through scripts/r2d_validate.sh (taskset -c 0-15; the wrapper's trap repeats the cleanup and the quota restore).

  boundary  the R2-C cgroup (r2c_cpu.setup_plan / verify_lab, unchanged)
  quota     /sys/fs/cgroup/sentinel-r2c/target/cpu.max only, via r2d_cpu.Host.write_quota (read-before, read-after):
            Q_B before tick 0 -> Q_W in the window callback (after tick NB is collected, before tick NB+1 is sampled)
            -> MAX after tick NB+NW is collected -> MAX re-verified in cleanup before cgroup.kill / rmdir
  target    r2c_target.py (unchanged) in the target leaf on CPU 18, private netns, uid 1000
  contender C1/TC: the R2-C E1 contender (CPU 18, weight 100) during W
  truth     r2d_cpu.evaluate: R2-C G1 G2 G3 G4 G6 G7 + GQ GT GD; GR from the cleanup read-backs and host comparison
  M2        the unchanged engine; CT/CC clause items and PR-3 consistency are recorded, never predicted
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
import r2d_cpu as Q  # noqa: E402
from m3b_r1_validate import Recording  # noqa: E402
from r2b_driver import NUMBERS, m2_summary  # noqa: E402
from r2c_driver import (Done, GTSource, Interrupted, Run, measurement_rows, on_signal, params, precreate,  # noqa: E402
                        refuse)
from sentinelai.collectors import LiveReader, SystemClock, build_snapshot, collect, resolve_target  # noqa: E402
from sentinelai.diagnostic.contract import EvidenceSnapshot, SourceType  # noqa: E402
from sentinelai.diagnostic.contract.serialize import canonical_bytes  # noqa: E402
from sentinelai.diagnostic.rules import diagnose  # noqa: E402
from sentinelai.ebpf import loader_argv, resolve_ebpf_target  # noqa: E402

REPORTED_EXTRA = ("throttle.quota_cores", "throttle.quota_saturation")


class WindowClock(SystemClock):
    """Calls on_window() once: inside the sleep_until call for tick NB+1, i.e. after tick NB has been collected
    (collector read + eBPF sample + ground-truth observation) and before tick NB+1 is sampled."""

    def __init__(self, on_window):
        self.on_window, self.calls = on_window, 0

    def sleep_until(self, mono):
        if self.calls == Q.NB + 1:
            self.on_window()
        self.calls += 1
        super().sleep_until(mono)


class R2DRun(Run):
    """R2-C's Run with the R2-D per-observation checks: the target quota must be the one currently in force."""

    def __init__(self, exp, sysr, host, out):
        super().__init__(exp, sysr, host, out)
        self.quota_now = Q.MAX

    def observe(self, tag):
        t = C.gt_sample(self.sys, time.monotonic(), self.target_pid)
        t["tag"] = tag
        self.obs.append(t)
        self.expected.append({k: list(v) for k, v in self.want.items()})
        self.in_w.append(self.window)
        bad = C.placement_violations(t, self.exp, self.want, self.window) + Q.immediate_aborts(t, self.quota_now)
        if bad:
            raise C.LabAbort(f"{tag} observation {len(self.obs) - 1}: {bad}")


def set_quota(host, run, writes, value, ev, moment):
    rec = host.write_quota(value, run.quota_now)
    rec["moment"] = moment
    writes.append(rec)
    run.quota_now = value
    ev("quota_written", moment=moment, value=value, t0=rec["t0"], t1=rec["t1"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--run", help="a label of r2d_cpu.MATRIX")
    ap.add_argument("--calibrate", action="store_true")
    ap.add_argument("--iters", type=int)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--execute", action="store_true", help="required: this run mutates the host")
    a = ap.parse_args()
    if not a.execute:
        refuse("--execute not given (use scripts/r2d_cpu.py dry-run for a read-only check)")
    if os.geteuid() != 0 or os.environ.get("SUDO_UID") != str(C.LAB_UID):
        refuse(f"must run as root via sudo from uid {C.LAB_UID}")
    if not re.fullmatch(r"[0-9a-f]{7,40}", a.commit):
        refuse(f"--commit {a.commit!r} is not a git hash")
    if not set(os.sched_getaffinity(0)) <= set(C.SUPPORT_CPUS):
        refuse(f"driver must be confined to CPUs {C.SUPPORT_CPUS[0]}-{C.SUPPORT_CPUS[-1]} (taskset)")
    if a.calibrate == bool(a.run):
        refuse("exactly one of --calibrate / --run")
    exp = Q.EXPERIMENTS["E0"] if a.calibrate else Q.experiment_of(a.run)
    if not a.calibrate:
        C.target_argv(a.iters, "/x")
    out = Path(a.out)
    if not str(out / "x").startswith(str(Q.RESULTS) + "/") or "/../" in str(out):
        refuse(f"output {out} outside {Q.RESULTS}")
    out.mkdir(parents=True, exist_ok=False)
    sysr = C.Sys()
    R = {"label": "calibration" if a.calibrate else a.run, "experiment": exp.__dict__, "commit": a.commit,
         "criteria": C.CRITERIA, "quota_schedule": Q.schedule(exp), "events": [], "aborts": [], "quota_writes": []}
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
    host = Q.Host(exp, oplog, a.iters, sysr)
    run = R2DRun(exp, sysr, host, out)
    writes = R["quota_writes"]
    loader = None
    old = {s: signal.signal(s, on_signal) for s in (signal.SIGINT, signal.SIGTERM)}   # cleanup registered first
    try:
        for op in C.setup_plan(exp):
            host.apply(op)
        R["verify_lab"] = C.verify_lab(sysr, exp)                 # all three cpu.max read 'max 100000' here
        if not R["verify_lab"]["ok"]:
            raise C.LabAbort(f"lab verification failed: {[k for k, v in R['verify_lab']['checks'].items() if not v]}")
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
            R["role"] = "runtime step 0: provenance only, excluded from experiment evidence and baselines"
            R["driver_ok"] = True
            raise Done()
        precreate(out / "target.json")
        if exp.contender_cpu is not None:
            precreate(out / "contender.cnt", size=8)
        tp, tpy = run.spawn("target", C.target_argv(a.iters, str(out / "target.json")))
        t_spawn = time.monotonic()
        run.want["target"], run.target_pid = [tpy], tpy
        target = resolve_target(LiveReader(), "r2d", C.TARGET_CGROUP_PATH)
        if sorted(target.pids) != run.want["target"] or target.cpuset != str(C.TARGET_CPU):
            raise C.LabAbort(f"resolved target {target} differs from the started target")
        sched = {m: (v, p) for m, v, p in Q.schedule(exp)}
        if "before_tick0" in sched:                                  # Q_B before any observation and tick 0
            set_quota(host, run, writes, sched["before_tick0"][0], ev, "before_tick0")
        ids = resolve_ebpf_target(target)
        R["target"] = {"cgroup_path": target.cgroup_path, "pids": list(target.pids), "cpuset": target.cpuset,
                       "netns_ref": target.netns_ref, "ebpf": ids.__dict__,
                       "netns_inode": os.stat(f"/proc/{tpy}/ns/net").st_ino,
                       "host_netns_inode": os.stat("/proc/1/ns/net").st_ino}
        if R["target"]["netns_inode"] == R["target"]["host_netns_inode"]:
            raise C.LabAbort("target is not in a private network namespace")
        loader = Recording(loader_argv(ids, 300), ids, 5.0)
        R["loader_start"] = loader.start()
        if R["loader_start"]:
            raise C.LabAbort(f"eBPF loader unavailable: {R['loader_start']}")
        while time.monotonic() < t_spawn + C.WARMUP_S:
            run.observe("warmup")
            time.sleep(1.0)
        contender = {}

        def on_window():
            run.window = True
            if "window_callback" in sched:                           # timing-critical: first
                set_quota(host, run, writes, sched["window_callback"][0], ev, "window_callback")
            if exp.contender_cpu is not None:
                cp, cpy = run.spawn("contender", C.contender_argv(str(out / "contender.cnt")))
                contender.update(wrapper=cp, pid=cpy)
                run.want["contender"] = [cpy]
                ev("contender_started", wrapper=cp.pid, pid=cpy)

        i_b0 = len(run.obs)
        ev("collect_start")
        ticks, cstats = collect(target, params(), LiveReader(), WindowClock(on_window), C.PERIOD_S,
                                GTSource(loader, run.observe))
        ev("collect_end")
        if "after_last_w_tick" in sched:                             # only after tick NB+NW has been collected
            set_quota(host, run, writes, sched["after_last_w_tick"][0], ev, "after_last_w_tick")
        if contender:
            host.apply(("kill", contender["pid"]))
            if not run.wait_empty(C.CONTENDER_DIR):
                raise C.LabAbort("contender cgroup not empty 2 s after SIGKILL")
            contender["wrapper"].wait(2)
            R["contender_iterations"] = int.from_bytes((out / "contender.cnt").read_bytes()[:8], "little")
        run.want["contender"], run.window = [], False
        i_w0, i_w1 = i_b0 + C.NB, i_b0 + C.NB + C.NW
        R["window"] = {"start_mono": ticks[C.NB].mono, "end_mono": ticks[C.NB + C.NW].mono,
                       "obs_index": [i_b0, i_w0, i_w1]}
        while tp.poll() is None and time.monotonic() < t_spawn + C.HARD_TIMEOUT_S:
            run.observe_until_exit(tp, "recovery")
            time.sleep(1.0)
        if tp.poll() is None or tp.returncode != 0:
            raise C.LabAbort(f"target did not complete (rc {tp.poll()})")
        target_out = json.loads((out / "target.json").read_text())
        if target_out["pid"] != tpy or target_out["cycles"] != C.TARGET_CYCLES:
            raise C.LabAbort("target output does not belong to the started target or is incomplete")
        R["target_result"] = {k: target_out[k] for k in ("pid", "cycles", "iters", "checksum")}

        snap = build_snapshot(ticks, target, params(), C.PERIOD_S, ebpf=True)
        (out / "snapshot.json").write_bytes(canonical_bytes(snap))
        again = EvidenceSnapshot.model_validate_json(canonical_bytes(snap), strict=False)
        R["snapshot"] = {"id": snap.snapshot_id, "measurements": len(snap.measurements),
                         "ebpf_measurements": sum(m.provenance.source is SourceType.EBPF for m in snap.measurements),
                         "round_trip_identical": canonical_bytes(again) == canonical_bytes(snap),
                         "rebuild_identical": canonical_bytes(build_snapshot(ticks, target, params(), C.PERIOD_S,
                                                                             ebpf=True)) == canonical_bytes(snap),
                         "gate_passed": snap.data_quality.gate_passed}
        R["measurements"] = measurement_rows(snap) + [
            {"feature": m.feature_id, "value": m.value, "quality": m.quality.value,
             "baseline_median": m.baseline.median if m.baseline else None}
            for m in snap.measurements if m.feature_id in REPORTED_EXTRA]
        R["metric_gate"] = Q.metric_gate(snap, exp, NUMBERS["COV_MIN"], NUMBERS["N_BASE_MIN"])
        R["aborts"] += R["metric_gate"]["aborts"]
        R["ground_truth"] = Q.evaluate(run.obs, i_b0, i_w0, i_w1, exp, run.expected, run.in_w, target_out,
                                       os.sysconf("SC_CLK_TCK"), writes)
        R["aborts"] += Q.ground_truth_aborts(R["ground_truth"], exp) + C.host_level_aborts(run.obs, i_b0, i_w0, i_w1)
        save()
        d = diagnose(snap, params(), code_commit=a.commit)          # recorded, never predicted
        R["m2"] = m2_summary(d)
        R["m2"]["r2d"] = Q.m2_record(d)
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
        R["cleanup"] = Q.cleanup(host, sysr, C.read_oplog(oplog))   # quota MAX first, then R2-C kill / rmdir
        for p in run.procs:
            try:
                p.wait(2)
            except Exception:                                       # noqa: BLE001
                pass
        R["bpf_release"] = C.wait_bpf_released(sysr, base)
        if R["bpf_release"]["released"]:
            (out / "host_after").mkdir()
            after = C.host_snapshot(sysr)
            (out / "host_after" / "host.json").write_text(json.dumps(after, indent=1, sort_keys=True))
            R["host_compare"] = C.compare_host(base, after)          # includes every cgroup's cpu.max (GR)
        else:
            (out / "host_after_unreleased").mkdir()
            (out / "host_after_unreleased" / "host.json").write_text(
                json.dumps(C.host_snapshot(sysr), indent=1, sort_keys=True))
            R["host_compare"] = {"ok": False, "failed": ["bpf_objects_not_released"]}
            R["aborts"].append(f"ABORT: BPF objects not released within {C.BPF_RELEASE_MAX_S} s")
        R["GR"] = {"restore": R["cleanup"]["quota_restore"], "host_cpu_max_identical": R["host_compare"].get(
            "cgroup_attrs_identical"), "ok": bool(R["cleanup"]["quota_restore"].get("ok"))
            and bool(R["host_compare"].get("ok"))}
        R["observations"] = run.obs
        if not R["cleanup"]["ok"]:
            R["aborts"].append(f"cleanup failure (NO-GO): {R['cleanup']['errors'] or R['cleanup']['verify']}")
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
