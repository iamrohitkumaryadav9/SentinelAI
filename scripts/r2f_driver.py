#!/usr/bin/env python3
"""SentinelAI R2-F: one controlled memory-pressure run, or the calibration step, as root.

Run only through scripts/r2f_validate.sh (taskset -c 0-15; the wrapper's trap repeats the cleanup).

  order     cgroups -> memory controls (r2f_memory.mem_write: read-before 'max', read-after exact) -> verify every
            control -> scratch directory -> only then the target (Host refuses a spawn before verification and any
            memory write after a spawn)
  target    r2f_target.py on CPU 18, private netns, uid 1000: creates its 1 GiB file, prints READY, scans 256 MiB;
            M1/M2/N1: one SIGUSR1 in the window callback (after tick NB) expands the scan to 1 GiB
  N2        the R2-C E2 contender (CPU 18, weight 400) during W, no expansion
  truth     a raw ground-truth observation every second of creation/warm-up/recovery and at every collector tick
            (with its raw eBPF line); immediate aborts: placement, cpu.max, NIC IRQ, any lab or host OOM
  M2        the unchanged engine; MP/CC/CT clause items recorded, never predicted
  cleanup   always (finally), from the op log: kill -> verify termination -> verify memory controls -> loader close ->
            BPF release -> scratch file -> cgroups; then the host comparison
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
import r2e_softirq as E  # noqa: E402
import r2f_memory as F  # noqa: E402
from m3b_r1_validate import Recording  # noqa: E402
from r2b_driver import NUMBERS, m2_summary  # noqa: E402
from r2c_driver import Done, Interrupted, WindowClock, measurement_rows, on_signal, params, precreate, refuse  # noqa: E402
from sentinelai.collectors import LiveReader, build_snapshot, collect, resolve_target  # noqa: E402
from sentinelai.diagnostic.contract import EvidenceSnapshot, SourceType  # noqa: E402
from sentinelai.diagnostic.contract.serialize import canonical_bytes  # noqa: E402
from sentinelai.diagnostic.rules import diagnose  # noqa: E402
from sentinelai.ebpf import loader_argv, resolve_ebpf_target  # noqa: E402

CLAUSES = ("MP.R1", "CC.R1", "CC.R2", "CC.X1", "CC.X2", "CT.R1", "CT.R2", "SI.R1", "SI.R2")
LEAF = {"target": F.TARGET_DIR, "contender": F.CONTENDER_DIR}


class GTSource:
    def __init__(self, loader, observe):
        self.loader, self.observe = loader, observe

    def sample(self):
        out = self.loader.sample()
        self.observe("tick", ebpf_line=self.loader.raw[-1])
        return out


def _stat(sysr, pid):
    text = sysr.read(f"/proc/{pid}/stat")
    st = E.task_stat(text)
    return None if not st else (st["comm"], int(text.rsplit(")", 1)[1].split()[1]))


def immediate_violations(t, want, in_w, first) -> list:
    """Checked at every observation: placement (GP), memory controls and cpu.max (GC), NIC IRQ, lab OOM, host OOM."""
    o, f = F.parse_obs(t), F.parse_obs(first) if first is not None else None
    v = F.evaluate_gp([o], [want], [in_w])["violations"]
    for name in ("parent", "target", "contender"):
        if o["leaves"][name]["cpu_max"] != C.CPU_MAX_UNLIMITED:
            v.append(f"cpu.max {name} = {o['leaves'][name]['cpu_max']!r}")
        ev = o["leaves"][name]["mem_events"] or {}
        if ev.get("oom", 0) or ev.get("oom_kill", 0):
            v.append(f"OOM in {name}: {ev}")
        if o["leaves"][name]["swap_current"] not in (0, None):
            v.append(f"{name} uses swap: {o['leaves'][name]['swap_current']}")
    if f is not None and o["vm"].get("oom_kill", 0) > f["vm"].get("oom_kill", 0):
        v.append("HOST OOM (vmstat oom_kill increased): stop the campaign")
    if o["nic_irq_eff"] is None or C.parse_cpulist(o["nic_irq_eff"]) & F.EXPERIMENT_CPUS:
        v.append(f"NIC IRQ on CPU 18: {o['nic_irq_eff']!r}")
    return v


class Run:
    def __init__(self, exp, sysr, host, out):
        self.exp, self.sys, self.host, self.out = exp, sysr, host, out
        self.obs, self.expected, self.in_w = [], [], []
        self.want = {"target": [], "contender": []}
        self.window, self.target_pid, self.procs = False, None, []

    def observe(self, tag, ebpf_line=None):
        t = F.gt_sample(self.sys, time.monotonic(), tag, self.target_pid, ebpf_line)
        self.obs.append(t)
        self.expected.append({k: list(v) for k, v in self.want.items()})
        self.in_w.append(self.window)
        bad = immediate_violations(t, self.expected[-1], self.window, self.obs[0])
        if bad:
            raise C.LabAbort(f"{tag} observation {len(self.obs) - 1}: {bad}")

    def observe_until_exit(self, proc, tag):
        try:
            self.observe(tag)
        except C.LabAbort:
            t, want = self.obs[-1], self.expected[-1]
            o = F.parse_obs(t)
            others = immediate_violations(t, {**want, "target": []}, self.in_w[-1], self.obs[0])
            if o["leaves"]["target"]["procs"] != [] or others:
                raise
            try:
                rc = proc.wait(0.5)
            except Exception:                                        # noqa: BLE001
                raise C.LabAbort(f"{tag}: target cgroup empty while its wrapper still runs")
            if rc != 0:
                raise
            del self.obs[-1], self.expected[-1], self.in_w[-1]
            return False
        return True

    def spawn(self, role, argv):
        leaf = LEAF[role]
        so, se = open(self.out / f"{role}.stdout", "w"), open(self.out / f"{role}.stderr", "w")
        p = self.host.apply(("spawn", role, argv), stdout=so, stderr=se)
        self.procs.append(p)
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
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
        raise C.LabAbort(f"{role} did not reach the one-pid structure in 3 s")

    def wait_empty(self, leaf, seconds=2.0):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            procs = self.sys.read(f"{leaf}/cgroup.procs")
            if procs is not None and not procs.strip():
                return True
            time.sleep(0.01)
        return False


def wait_ready(run, proc, stdout_path, timeout_s=F.READY_TIMEOUT_S):
    """The target prints READY after creating, fsyncing and warming its file; observed every second meanwhile."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        text = Path(stdout_path).read_text() if Path(stdout_path).exists() else ""
        m = re.search(r"^READY (\d+)$", text, re.M)
        if m:
            return int(m.group(1))
        if proc.poll() is not None:
            raise C.LabAbort(f"target exited before READY (rc {proc.returncode})")
        run.observe("create")
        time.sleep(1.0)
    raise C.LabAbort(f"target not READY within {timeout_s} s")


def make_after_kill(state, sysr, base, R):
    """Cleanup steps (4)+(5): close the loader, then wait (read-only bpftool polls) for BPF release. The wait runs even
    when the close fails; an unconfirmed release is recorded, never assumed."""
    def after_kill():
        try:
            loader = state.get("loader")
            if loader is not None:
                loader.close()
        finally:
            R["bpf_release"] = C.wait_bpf_released(sysr, base)
    return after_kill


def clause_items(d):
    return sorted(({"clause": i.predicate_id, "kind": i.kind.value, "strength": i.strength.value if i.strength else None,
                    "observed": i.observed, "missing_reason": i.missing_reason,
                    "supports": [l.value for l in i.supports], "contradicts": [l.value for l in i.contradicts]}
                   for i in d.snapshot.evidence_items if i.predicate_id in CLAUSES), key=lambda x: x["clause"])


def calibration_record(run, target_out, t_ready_mono):
    """Step 0 (provenance only): file creation/readiness, cached cycle cost, B-like pressure-free steady state,
    host safety. Sets no parameter."""
    obs = [F.parse_obs(t) for t in run.obs]
    after = [k for k, o in enumerate(obs) if o["mono"] >= t_ready_mono]
    rec = {"ready": True, "observations_after_ready": len(after)}
    if len(after) < 12 or target_out is None:
        return {**rec, "feasible": False, "reason": "too few observations or no target output"}
    a, z = after[1], after[-1]
    rf = F._rate(obs, a, z, F._mstat("target", "workingset_refault_file"))
    lat = C.lateness_stats(target_out, int(obs[a]["mono"] * 1e9), int(obs[z]["mono"] * 1e9))
    avail = min(o["meminfo"].get("MemAvailable", 0) for o in obs)
    rec.update(refault_rate_steady=rf, cycle=lat, mem_available_min=avail,
               create_to_ready_s=(target_out["ready_ns"] - target_out["create_start_ns"]) / 1e9)
    rec["feasible"] = rf is not None and rf < F.REFAULT_MIN and avail >= F.MEM_AVAILABLE_MIN_BYTES and lat is not None
    rec["reason"] = None if rec["feasible"] else "baseline not pressure-free, host memory below the gate, or no cycles"
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--run", help="a label of r2f_memory.MATRIX")
    ap.add_argument("--calibrate", action="store_true")
    ap.add_argument("--ts", required=True, help="the wrapper's UTC timestamp (scratch directory name)")
    ap.add_argument("--commit", required=True)
    ap.add_argument("--execute", action="store_true", help="required: this run mutates the host")
    a = ap.parse_args()
    if not a.execute:
        refuse("--execute not given (use scripts/r2f_memory.py dry-run for a read-only check)")
    if os.geteuid() != 0 or os.environ.get("SUDO_UID") != str(C.LAB_UID):
        refuse(f"must run as root via sudo from uid {C.LAB_UID}")
    if not re.fullmatch(r"[0-9a-f]{7,40}", a.commit) or not re.fullmatch(r"\d{8}T\d{6}Z", a.ts):
        refuse("--commit / --ts malformed")
    if not set(os.sched_getaffinity(0)) <= set(F.SUPPORT_CPUS):
        refuse("driver must be confined to CPUs 0-15 (taskset)")
    if a.calibrate == bool(a.run):
        refuse("exactly one of --calibrate / --run")
    exp = F.EXPERIMENTS["CAL"] if a.calibrate else F.experiment_of(a.run)
    label = "calibration" if a.calibrate else a.run
    out = Path(a.out)
    if not F._results_path(out / "x"):
        refuse(f"output {out} outside results/phase1c_r2f")
    out.mkdir(parents=True, exist_ok=False)
    sysr = F.Sys()
    run_dir = F.scratch_dir(a.ts, label)
    R = {"label": label, "experiment": exp.__dict__, "commit": a.commit, "safety_thresholds": F.SAFETY_THRESHOLDS,
         "scratch": run_dir, "events": [], "aborts": [], "memory_writes": [], "signal": None,
         "design": {"file_bytes": F.FILE_BYTES, "scan_b": F.SCAN_B, "scan_w": F.scan_w(exp), "high": exp.high,
                    "target_max": exp.high + F.TARGET_MAX_HEADROOM, "parent_max": F.PARENT_MAX,
                    "period_ns": F.PERIOD_NS, "pages_per_cycle": F.PAGES_PER_CYCLE, "cycles": F.CYCLES, "nb": F.NB,
                    "nw": F.NW}}
    ev = lambda name, **kw: R["events"].append({"t_mono": time.monotonic(), "event": name, **kw})

    def save():
        (out / "run.json").write_text(json.dumps(R, indent=1, sort_keys=True, default=str))

    (out / "host_before").mkdir()
    base = F.host_snapshot(sysr)
    (out / "host_before" / "host.json").write_text(json.dumps(base, indent=1, sort_keys=True))
    R["preflight"] = F.preflight(sysr)
    if not R["preflight"]["ok"] or not base["bpf_available"]:
        save()
        refuse(f"preflight failed: {[k for k, v in R['preflight']['checks'].items() if not v]}")
    oplog = str(out / "ops.jsonl")
    host = F.Host(exp, oplog, sysr, run_dir)
    run = Run(exp, sysr, host, out)
    R["observations"], R["expected"], R["in_w"] = run.obs, run.expected, run.in_w
    state = {"loader": None}
    old = {s: signal.signal(s, on_signal) for s in (signal.SIGINT, signal.SIGTERM)}   # cleanup registered first
    try:
        ev("setup_start")
        for op in F.cgroup_plan(exp):
            host.apply(op)
        R["verify_cgroups"] = F.verify_cgroups(sysr, exp)
        if not R["verify_cgroups"]["ok"]:
            raise C.LabAbort(f"cgroup verification failed: {[k for k, v in R['verify_cgroups']['checks'].items() if not v]}")
        for _, path, value in F.memory_plan(exp):                    # before any process exists
            R["memory_writes"].append(host.mem_write(path, value))
        R["controls"] = host.verify()
        if not R["controls"]["ok"]:
            raise F.MemAbort(f"memory controls not verified: {[k for k, v in R['controls']['checks'].items() if not v]}")
        ev("controls_verified")
        if not sysr.exists(F.SCRATCH_BASE):
            host.apply(("scratch", "mkdir_base", F.SCRATCH_BASE))
        host.apply(("scratch", "mkdir", run_dir))
        precreate(out / "target.json")
        if exp.contender:
            precreate(out / "contender.cnt", size=8)
        tp, tpy = run.spawn("target", F.target_argv(exp, run_dir, str(out / "target.json")))
        t_spawn = time.monotonic()
        run.want["target"], run.target_pid, host.state["target_pid"] = [tpy], tpy, tpy
        ev("target_started", wrapper=tp.pid, pid=tpy)
        t_ready_ns = wait_ready(run, tp, out / "target.stdout")
        t_ready = time.monotonic()
        ev("target_ready", ready_ns=t_ready_ns, after_s=t_ready - t_spawn)
        target = resolve_target(LiveReader(), "r2f", F.TARGET_CGROUP_PATH)
        if sorted(target.pids) != [tpy] or target.cpuset != str(F.TARGET_CPU):
            raise C.LabAbort(f"resolved target {target} differs from the started target")
        ids = resolve_ebpf_target(target)
        R["target"] = {"cgroup_path": target.cgroup_path, "pids": list(target.pids), "cpuset": target.cpuset,
                       "netns_ref": target.netns_ref, "ebpf": ids.__dict__,
                       "netns_inode": os.stat(f"/proc/{tpy}/ns/net").st_ino,
                       "host_netns_inode": os.stat("/proc/1/ns/net").st_ino}
        if R["target"]["netns_inode"] == R["target"]["host_netns_inode"]:
            raise C.LabAbort("target is not in a private network namespace")
        loader = Recording(loader_argv(ids, 300), ids, 5.0)
        state["loader"] = loader
        R["loader_start"] = loader.start()
        if R["loader_start"]:
            raise C.LabAbort(f"eBPF loader unavailable: {R['loader_start']}")
        R["ebpf_meta_line"] = loader.raw[0]
        if a.calibrate:
            while tp.poll() is None and time.monotonic() < t_spawn + F.HARD_TIMEOUT_S:
                run.observe_until_exit(tp, "calibration")
                time.sleep(1.0)
            if tp.poll() is None or tp.returncode != 0:
                raise C.LabAbort(f"calibration target did not complete (rc {tp.poll()})")
            target_out = json.loads((out / "target.json").read_text())
            R["calibration"] = calibration_record(run, target_out, t_ready)
            R["role"] = "runtime step 0: provenance only, excluded from evidence; sets no parameter"
            R["driver_ok"] = True
            raise Done()
        while time.monotonic() < t_ready + F.WARMUP_S:
            run.observe("warmup")
            time.sleep(1.0)
        contender = {}

        def on_window():
            run.window = True
            if exp.expand:                                            # timing-critical: first
                t0 = time.monotonic()
                host.apply(("signal", tpy))
                R["signal"] = {"pid": tpy, "t0": t0, "t1": time.monotonic()}
                ev("sigusr1", **R["signal"])
            if exp.contender:
                cp, cpy = run.spawn("contender", F.contender_argv(str(out / "contender.cnt")))
                contender.update(wrapper=cp, pid=cpy)
                run.want["contender"] = [cpy]
                ev("contender_started", wrapper=cp.pid, pid=cpy)

        i_b0 = len(run.obs)
        ev("collect_start")
        ticks, cstats = collect(target, params(), LiveReader(), WindowClock(on_window), C.PERIOD_S,
                                GTSource(loader, run.observe))
        ev("collect_end")
        if contender:
            host.apply(("kill", contender["pid"]))
            if not run.wait_empty(F.CONTENDER_DIR):
                raise C.LabAbort("contender cgroup not empty 2 s after SIGKILL")
            contender["wrapper"].wait(2)
            R["contender_iterations"] = int.from_bytes((out / "contender.cnt").read_bytes()[:8], "little")
        run.want["contender"], run.window = [], False
        i_w0, i_w1 = i_b0 + F.NB, i_b0 + F.NB + F.NW
        R["window"] = {"start_mono": ticks[F.NB].mono, "end_mono": ticks[F.NB + F.NW].mono,
                       "obs_index": [i_b0, i_w0, i_w1]}
        while tp.poll() is None and time.monotonic() < t_spawn + F.HARD_TIMEOUT_S:
            run.observe_until_exit(tp, "recovery")
            time.sleep(1.0)
        if tp.poll() is None or tp.returncode != 0:
            raise C.LabAbort(f"target did not complete (rc {tp.poll()})")
        target_out = json.loads((out / "target.json").read_text())
        if target_out["pid"] != tpy or target_out["cycles"] != F.CYCLES:
            raise C.LabAbort("target output does not belong to the started target or is incomplete")
        R["target_result"] = {k: target_out[k] for k in ("pid", "cycles", "file_size", "scan_b", "scan_w",
                                                         "sigusr1_count", "expanded_at_cycle", "majflt_end")}
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
        R["metric_gate"] = F.metric_gate(snap, NUMBERS["COV_MIN"], NUMBERS["N_BASE_MIN"])
        R["aborts"] += R["metric_gate"]["aborts"]
        R["ground_truth"] = F.evaluate(F.ground_truth_inputs(R, target_out))    # independent of M2
        R["aborts"] += F.ground_truth_aborts(R["ground_truth"])
        save()
        d = diagnose(snap, params(), code_commit=a.commit)            # recorded, never predicted
        R["m2"] = m2_summary(d)
        R["m2"]["clauses"] = clause_items(d)
        R["m2"]["conflict_rules"] = sorted(c.rule for c in d.snapshot.conflicts)
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
        R["cleanup"] = F.cleanup(host, sysr, C.read_oplog(oplog), exp,
                                 after_kill=make_after_kill(state, sysr, base, R))
        for p in run.procs:
            try:
                p.wait(2)
            except Exception:                                       # noqa: BLE001
                pass
        R.setdefault("bpf_release", {"released": False, "timed_out": False,
                                     "remaining": f"BPF release wait not completed: {R['cleanup']['errors']}"})
        if R["bpf_release"]["released"]:
            (out / "host_after").mkdir()
            after = F.host_snapshot(sysr)
            (out / "host_after" / "host.json").write_text(json.dumps(after, indent=1, sort_keys=True))
            R["host_compare"] = F.compare_host(base, after)
        else:
            (out / "host_after_unreleased").mkdir()
            (out / "host_after_unreleased" / "host.json").write_text(
                json.dumps(F.host_snapshot(sysr), indent=1, sort_keys=True))
            R["host_compare"] = {"ok": False, "failed": ["bpf_objects_not_released"]}
            R["aborts"].append(f"ABORT: BPF objects not released within {C.BPF_RELEASE_MAX_S} s")
        R["GR"] = F.restore_record(R["cleanup"], R["host_compare"], R["bpf_release"])
        if not R["cleanup"]["ok"]:
            R["aborts"].append(f"cleanup failure: {R['cleanup']['errors'] or R['cleanup']['verify']}")
        if not R["host_compare"]["ok"]:
            R["aborts"].append(f"host state differs from the pre-run snapshot: {R['host_compare']['failed']}")
        if not R["GR"]["ok"]:
            R["aborts"].append(f"GR failed: {R['GR']['checks']}")
        R["host_oom"] = any("HOST OOM" in a for a in R["aborts"])
        R.setdefault("driver_ok", False)
        R["driver_ok"] = bool(not R["aborts"] and (a.calibrate and R["driver_ok"] or R.get("snapshot_unchanged_by_m2")))
        R["verdict"] = "OK" if R["driver_ok"] else "ABORT"
        save()
        for s, h in old.items():
            signal.signal(s, h)
    print(json.dumps({"label": R["label"], "verdict": R["verdict"], "aborts": R["aborts"][:5],
                      "m2": R.get("m2", {}).get("decision"), "host_oom": R["host_oom"],
                      "calibration": {k: (R.get("calibration") or {}).get(k) for k in ("feasible", "reason")}
                      if a.calibrate else None}))
    return 0 if R["driver_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
