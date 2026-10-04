#!/usr/bin/env python3
"""SentinelAI R2-E: one controlled softirq-overload run, the target calibration, or the UDP rate ladder, as root.

Run only through scripts/r2e_validate.sh (taskset -c 0-15; the wrapper's trap repeats the cleanup, RPS reset first).

  boundary  /sys/fs/cgroup/sentinel-r2c {target 18, contender 18, traffic 20,22,23} (r2e_softirq.cgroup_plan)
  lab       sentinel-lab-a <-> sentinel-lab-b, single-queue veth (r2e_softirq.lab_plan); RPS on sentlab-b0 rx-0 through
            r2e_softirq.Host.rps_write only (read-before, read-after, logged)
  target    r2c_target.py (unchanged) in the target leaf on CPU 18, private interface-less netns, uid 1000
  traffic   iperf3 servers in sentinel-lab-b on CPU 23 for the whole run; clients in sentinel-lab-a on CPUs 20 and 22
            started in the window callback (after tick NB is collected) at the run's calibrated rate, for NW + 1 s
  N1        the R2-C E2 contender (CPU 18, weight 400) during W, no traffic
  truth     one raw ground-truth observation (r2e_softirq.gt_sample) every second of warm-up and recovery and at every
            collector tick (with that tick's raw eBPF line); r2e_softirq.evaluate() computes GP..G7 from them
  M2        the unchanged engine; SI/CC/PL clause items recorded, never predicted
  cleanup   always (finally), from the op log: traffic -> RPS 0 (verified) -> loader -> cgroups -> lab namespaces
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
from m3b_r1_validate import Recording  # noqa: E402
from r2b_driver import NUMBERS, m2_summary  # noqa: E402
from r2c_driver import Done, Interrupted, WindowClock, measurement_rows, on_signal, params, precreate, refuse  # noqa: E402
from sentinelai.collectors import LiveReader, build_snapshot, collect, resolve_target  # noqa: E402
from sentinelai.diagnostic.contract import EvidenceSnapshot, SourceType, Target  # noqa: E402
from sentinelai.diagnostic.contract.serialize import canonical_bytes  # noqa: E402
from sentinelai.diagnostic.rules import diagnose  # noqa: E402
from sentinelai.ebpf import loader_argv, resolve_ebpf_target  # noqa: E402

CLAUSES = ("SI.R1", "SI.R2", "CC.R1", "CC.R2", "CC.X1", "CC.X2", "PL.R1")
COMM = {"target": "python3", "contender": "python3", "calibration": "python3", "server": "iperf3", "client": "iperf3"}
LEAF = {"target": C.TARGET_DIR, "calibration": C.TARGET_DIR, "contender": C.CONTENDER_DIR, "server": E.TRAFFIC_DIR,
        "client": E.TRAFFIC_DIR}


class GTSource:
    """Feeds the snapshot from the eBPF loader and takes the raw ground-truth observation at the same tick, carrying
    that tick's raw loader line."""

    def __init__(self, loader, observe):
        self.loader, self.observe = loader, observe

    def sample(self):
        out = self.loader.sample()
        self.observe("tick", ebpf_line=self.loader.raw[-1])
        return out


def _stat(sysr, pid):
    st = E.task_stat(sysr.read(f"/proc/{pid}/stat"))
    if not st:
        return None
    text = sysr.read(f"/proc/{pid}/stat")
    return st["comm"], int(text.rsplit(")", 1)[1].split()[1])


class Run:
    def __init__(self, exp, sysr, host, out):
        self.exp, self.sys, self.host, self.out = exp, sysr, host, out
        self.obs, self.expected, self.in_w = [], [], []
        self.want = {"target": [], "contender": [], "traffic": []}
        self.cpu = {}
        self.window = False
        self.target_pid = None
        self.servers = []
        self.procs = []

    def _want(self):
        return {**{k: list(v) for k, v in self.want.items()}, "cpu": {str(p): c for p, c in self.cpu.items()}}

    def observe(self, tag, ebpf_line=None):
        t = E.gt_sample(self.sys, time.monotonic(), tag, self.target_pid, self.servers, ebpf_line, self.exp.lab)
        self.obs.append(t)
        self.expected.append(self._want())
        self.in_w.append(self.window)
        bad = self.violations(t, self.expected[-1], self.window)
        if bad:
            raise C.LabAbort(f"{tag} observation {len(self.obs) - 1}: {bad}")

    @staticmethod
    def violations(t, want, in_w):
        o = E.parse_obs(t)
        v = E.evaluate_gp([o], [want], [in_w])["violations"]
        for n in ("parent", "target", "contender", "traffic"):
            if o["leaves"][n]["cpu_max"] != C.CPU_MAX_UNLIMITED:
                v.append(f"CPU quota: {n} cpu.max = {o['leaves'][n]['cpu_max']!r}")
        if o["nic_irq_eff"] is None or C.parse_cpulist(o["nic_irq_eff"]) & E.EXPERIMENT_CPUS:
            v.append(f"NIC IRQ {C.NIC_IRQ} effective affinity {o['nic_irq_eff']!r} on an experiment CPU")
        return v

    def observe_until_exit(self, proc, tag):
        """As R2-C: the one excusable violation is an observation racing the target's normal exit."""
        try:
            self.observe(tag)
        except C.LabAbort:
            t, want = self.obs[-1], self.expected[-1]
            o = E.parse_obs(t)
            others = self.violations(t, {**want, "target": []}, self.in_w[-1])
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

    def spawn(self, role, argv, cpu=None):
        """One new pid in the role's leaf: the workload (comm as expected), child of the wrapper outside the leaf."""
        leaf = LEAF[role]
        before = set(int(x) for x in (self.sys.read(f"{leaf}/cgroup.procs") or "").split())
        so, se = open(self.out / f"{role}{len(self.procs)}.stdout", "w"), open(self.out / f"{role}{len(self.procs)}"
                                                                                ".stderr", "w")
        p = self.host.apply(("spawn", role, argv), stdout=so, stderr=se)
        self.procs.append(p)
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            now = set(int(x) for x in (self.sys.read(f"{leaf}/cgroup.procs") or "").split())
            new = sorted(now - before)
            w = _stat(self.sys, p.pid)
            k = _stat(self.sys, new[0]) if len(new) == 1 else None
            if p.pid not in now and w and w[0] == "timeout" and k and k[0] == COMM[role] and k[1] == p.pid:
                if cpu is not None:
                    self.cpu[new[0]] = cpu
                return p, new[0], so.name
            if len(new) > 1 or p.pid in now or before - now:
                raise C.LabAbort(f"{role}: {leaf} holds {sorted(now)} (before {sorted(before)}): one-pid invariant broken")
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


def make_after_rps(state, sysr, base, R):
    """Cleanup step between the verified RPS reset and the cgroup / namespace removal (approved order): close the
    loader, then wait (read-only bpftool polls) until no run-owned BPF object remains. The wait runs even when the
    close fails; its result is recorded as before (an unconfirmed release aborts the run)."""
    def after_rps():
        try:
            loader = state.get("loader")
            if loader is not None:
                if "raw_ebpf" not in R:
                    R["raw_ebpf_lines"] = len(loader.raw)
                loader.close()
        finally:
            R["bpf_release"] = C.wait_bpf_released(sysr, base)
    return after_rps


def clause_items(d):
    return sorted(({"clause": i.predicate_id, "kind": i.kind.value, "strength": i.strength.value if i.strength else None,
                    "observed": i.observed, "missing_reason": i.missing_reason,
                    "supports": [l.value for l in i.supports], "contradicts": [l.value for l in i.contradicts]}
                   for i in d.snapshot.evidence_items if i.predicate_id in CLAUSES), key=lambda x: x["clause"])


def start_clients(run, pps, seconds, R, ev):
    clients = []
    for i in (0, 1):
        cp, cpy, path = run.spawn("client", E.client_argv(i, pps, seconds), cpu=E.SENDER_CPUS[i])
        run.want["traffic"].append(cpy)
        clients.append((cp, cpy, path))
        ev("client_started", index=i, wrapper=cp.pid, pid=cpy, pps=pps)
    return clients


def finish_clients(run, clients, timeout_s):
    """Wait for the clients' normal end; their JSON is the raw iperf3 record. No observation is taken meanwhile."""
    raw = {}
    for i, (cp, cpy, path) in enumerate(clients):
        try:
            rc = cp.wait(timeout_s)
        except Exception:                                            # noqa: BLE001
            raise C.LabAbort(f"iperf3 client {i} did not finish in {timeout_s} s")
        if rc != 0:
            raise C.LabAbort(f"iperf3 client {i} exited with rc {rc}")
        run.want["traffic"].remove(cpy)
        run.cpu.pop(cpy, None)
        raw[f"client{i}"] = Path(path).read_text()
    left = set(int(x) for x in (run.sys.read(f"{E.TRAFFIC_DIR}/cgroup.procs") or "").split())
    if left & {cpy for _, cpy, _ in clients}:
        raise C.LabAbort(f"client pids still in the traffic leaf: {sorted(left)}")
    return raw


def lab_setup(sysr, host, exp, R, ev, save):
    """After the lab exists: settle and verify it (bounded read-only re-inspection; every raw inspection is saved to
    run.json before it is evaluated), record ethtool / backlog, refuse GRO on sentlab-b0, then the one RPS write."""
    setup = {"settle": {"poll_s": E.LAB_SETTLE_POLL_S, "max_s": E.LAB_SETTLE_MAX_S, "attempts": []}}
    R["lab_setup"] = setup
    res = E.settle_lab(lambda: E.lab_state(sysr), setup["settle"]["attempts"], save)
    setup["settle"].update(res)
    save()
    ev("lab_settle", settled=res["settled"], attempts=res["n_attempts"], elapsed_s=res["elapsed_s"])
    if not res["settled"]:
        raise C.LabAbort(f"lab verification failed: {res['final_reason']}")
    final = setup["settle"]["attempts"][-1]
    setup.update(lab=final["raw"], lab_checks=final["checks"], ethtool_a=sysr.run(E.ETHTOOL_READS["ethtool_a"]),
                 ethtool_b=sysr.run(E.ETHTOOL_READS["ethtool_b"]),
                 netdev_max_backlog=(sysr.read("/proc/sys/net/core/netdev_max_backlog") or "").strip())
    save()
    if E.ethtool_gro(setup["ethtool_b"]) != "off":
        raise C.LabAbort(f"GRO on {E.IF_B} is {E.ethtool_gro(setup['ethtool_b'])!r} (veth NAPI): refusing RPS")
    rec = host.rps_write(exp.rps, E.RPS_ZERO)
    setup.update(rps_write=rec, rps_readback=rec["post"], lab_verified=True)
    ev("rps_written", value=exp.rps, post=rec["post"])


def ladder(run, sysr, host, R, ev, out):
    """Runtime step 0b (provenance only): the UDP rate ladder; levels fixed by r2e_softirq.select_levels."""
    t = Target(name="r2e-ladder", cgroup_path=C.TARGET_CGROUP_PATH, pids=(os.getpid(),), cpuset=str(E.TARGET_CPU),
               netns_ref=f"pid:{os.getpid()}", ifaces=())
    ids = resolve_ebpf_target(t)
    loader = Recording(loader_argv(ids, 300), ids, 5.0)
    R["loader_start"] = loader.start()
    if R["loader_start"]:
        raise C.LabAbort(f"eBPF loader unavailable: {R['loader_start']}")
    R["ebpf_meta_line"] = loader.raw[0]
    hz = os.sysconf("SC_CLK_TCK")
    try:
        for i in (0, 1):
            _, spy, _ = run.spawn("server", E.server_argv(i), cpu=E.RECEIVER_CPU)
            run.want["traffic"].append(spy)
            run.servers.append(spy)
        time.sleep(0.5)
        steps = []
        for pps in E.LADDER_PPS:
            clients = start_clients(run, pps, E.LADDER_STEP_S, R, ev)
            time.sleep(E.LADDER_SETTLE_S)
            loader.sample()
            run.observe("ladder", ebpf_line=loader.raw[-1])
            o0 = run.obs[-1]
            time.sleep(E.LADDER_MEASURE_S)
            loader.sample()
            run.observe("ladder", ebpf_line=loader.raw[-1])
            o1 = run.obs[-1]
            raw = finish_clients(run, clients, E.LADDER_STEP_S + 5)
            rec = E.ladder_step_record(o0, o1, R["ebpf_meta_line"], hz, raw)
            rec["pps"] = pps
            rec["iperf_raw"] = raw
            rec["obs_index"] = [len(run.obs) - 2, len(run.obs) - 1]
            steps.append(rec)
            ev("ladder_step", pps=pps, malformed=rec.get("malformed"), loss=rec.get("loss"))
            if rec.get("malformed") or any((rec.get("loss") or {}).values()):
                break
        mb = R["lab_setup"]["netdev_max_backlog"]
        R["ladder"] = E.select_levels(steps, int(mb))
        R["ladder"]["hz"] = hz
        (out / "ladder.json").write_text(json.dumps(R["ladder"], indent=1, sort_keys=True, default=str))
    finally:
        R["raw_ebpf"] = list(loader.raw)
        loader.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--run", help="a label of r2e_softirq.MATRIX")
    ap.add_argument("--calibrate", action="store_true", help="runtime step 0a: R2-C target calibration")
    ap.add_argument("--ladder", action="store_true", help="runtime step 0b: UDP rate ladder")
    ap.add_argument("--iters", type=int)
    ap.add_argument("--ladder-file", help="ladder.json of this invocation's step 0b (runs only)")
    ap.add_argument("--commit", required=True)
    ap.add_argument("--execute", action="store_true", help="required: this run mutates the host")
    a = ap.parse_args()
    if not a.execute:
        refuse("--execute not given (use scripts/r2e_softirq.py dry-run for a read-only check)")
    if os.geteuid() != 0 or os.environ.get("SUDO_UID") != str(C.LAB_UID):
        refuse(f"must run as root via sudo from uid {C.LAB_UID}")
    if not re.fullmatch(r"[0-9a-f]{7,40}", a.commit):
        refuse(f"--commit {a.commit!r} is not a git hash")
    if not set(os.sched_getaffinity(0)) <= set(E.SUPPORT_CPUS):
        refuse("driver must be confined to CPUs 0-15 (taskset)")
    if sum([a.calibrate, a.ladder, bool(a.run)]) != 1:
        refuse("exactly one of --calibrate / --ladder / --run")
    exp = E.EXPERIMENTS["CAL"] if a.calibrate else E.EXPERIMENTS["LADDER"] if a.ladder else E.experiment_of(a.run)
    lad, pps = None, None
    if a.run:
        C.target_argv(a.iters, "/x")
        try:
            lad = E.check_ladder(json.loads(Path(a.ladder_file).read_text()))
        except (OSError, TypeError, ValueError) as exc:
            refuse(f"ladder file: {exc}")
        pps = E.level_pps(lad, exp)
    out = Path(a.out)
    if not E._results_path(out / "x"):
        refuse(f"output {out} outside results/phase1c_r2e")
    out.mkdir(parents=True, exist_ok=False)
    sysr = E.Sys()
    label = "calibration" if a.calibrate else "ladder" if a.ladder else a.run
    R = {"label": label, "experiment": exp.__dict__, "commit": a.commit, "criteria": E.CRITERIA, "pps": pps,
         "ladder": lad, "events": [], "aborts": [], "hz": os.sysconf("SC_CLK_TCK"),
         "design": {"target_cpu": E.TARGET_CPU, "sender_cpus": E.SENDER_CPUS, "receiver_cpu": E.RECEIVER_CPU,
                    "parent_cpus": E.PARENT_CPUS, "rps": exp.rps, "nb": C.NB, "nw": C.NW, "warmup_s": C.WARMUP_S,
                    "client_t": E.CLIENT_T}}
    ev = lambda name, **kw: R["events"].append({"t_mono": time.monotonic(), "event": name, **kw})

    def save():
        (out / "run.json").write_text(json.dumps(R, indent=1, sort_keys=True, default=str))

    (out / "host_before").mkdir()
    base = E.host_snapshot(sysr)
    (out / "host_before" / "host.json").write_text(json.dumps(base, indent=1, sort_keys=True))
    R["preflight"] = E.preflight(sysr)
    if not R["preflight"]["ok"] or not base["bpf_available"]:
        save()
        refuse(f"preflight failed: {[k for k, v in R['preflight']['checks'].items() if not v]}")

    oplog = str(out / "ops.jsonl")
    host = E.Host(exp, oplog, a.iters, pps, sysr)
    run = Run(exp, sysr, host, out)
    R["observations"], R["expected"], R["in_w"] = run.obs, run.expected, run.in_w
    loader = None
    old = {s: signal.signal(s, on_signal) for s in (signal.SIGINT, signal.SIGTERM)}   # cleanup registered first
    try:
        ev("setup_start")
        for op in E.setup_plan(exp):
            host.apply(op)
        R["verify_cgroups"] = E.verify_cgroups(sysr, exp)
        if not R["verify_cgroups"]["ok"]:
            raise C.LabAbort(f"cgroup verification failed: {[k for k, v in R['verify_cgroups']['checks'].items() if not v]}")
        if exp.lab:
            lab_setup(sysr, host, exp, R, ev, save)
        if a.calibrate:
            precreate(out / "calibration.json")
            p, py, _ = run.spawn("calibration", C.calibration_argv(str(out / "calibration.json")), cpu=E.TARGET_CPU)
            run.want["target"] = [py]
            t_end = time.monotonic() + C.HARD_TIMEOUT_S
            while p.poll() is None and time.monotonic() < t_end:
                run.observe_until_exit(p, "calibration")
                time.sleep(1.0)
            if p.poll() is None or p.returncode != 0:
                raise C.LabAbort(f"calibration did not complete (rc {p.poll()})")
            R["calibration"] = json.loads((out / "calibration.json").read_text())
            R["iters"] = R["calibration"]["iters"]
            R["role"] = "runtime step 0a: provenance only, excluded from evidence"
            R["driver_ok"] = True
            raise Done()
        if a.ladder:
            ladder(run, sysr, host, R, ev, out)
            R["role"] = "runtime step 0b: provenance only, excluded from evidence; fixes S1/S2/S3 and delta"
            R["driver_ok"] = True
            raise Done()
        precreate(out / "target.json")
        if exp.contender:
            precreate(out / "contender.cnt", size=8)
        tp, tpy, _ = run.spawn("target", C.target_argv(a.iters, str(out / "target.json")), cpu=E.TARGET_CPU)
        t_spawn = time.monotonic()
        run.want["target"], run.target_pid = [tpy], tpy
        ev("target_started", wrapper=tp.pid, pid=tpy)
        target = resolve_target(LiveReader(), "r2e", C.TARGET_CGROUP_PATH)
        if sorted(target.pids) != run.want["target"] or target.cpuset != str(E.TARGET_CPU):
            raise C.LabAbort(f"resolved target {target} differs from the started target")
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
        R["ebpf_meta_line"] = loader.raw[0]
        for i in (0, 1):                                              # receivers for the whole run (idle outside W)
            _, spy, _ = run.spawn("server", E.server_argv(i), cpu=E.RECEIVER_CPU)
            run.want["traffic"].append(spy)
            run.servers.append(spy)
        while time.monotonic() < t_spawn + C.WARMUP_S:
            run.observe("warmup")
            time.sleep(1.0)
        state = {"clients": [], "contender": {}}

        def on_window():
            run.window = True
            if exp.traffic:                                           # timing-critical: first
                state["clients"] = start_clients(run, pps, E.CLIENT_T, R, ev)
            if exp.contender:
                cp, cpy, _ = run.spawn("contender", C.contender_argv(str(out / "contender.cnt")), cpu=E.TARGET_CPU)
                state["contender"].update(wrapper=cp, pid=cpy)
                run.want["contender"] = [cpy]
                ev("contender_started", wrapper=cp.pid, pid=cpy)

        i_b0 = len(run.obs)
        ev("collect_start")
        ticks, cstats = collect(target, params(), LiveReader(), WindowClock(on_window), C.PERIOD_S,
                                GTSource(loader, run.observe))
        ev("collect_end")
        R["iperf_raw"] = {}
        if state["clients"]:
            R["iperf_raw"] = finish_clients(run, state["clients"], E.CLIENT_T + 5)
            ev("clients_finished")
        if state["contender"]:
            host.apply(("kill", state["contender"]["pid"]))
            if not run.wait_empty(C.CONTENDER_DIR):
                raise C.LabAbort("contender cgroup not empty 2 s after SIGKILL")
            state["contender"]["wrapper"].wait(2)
            run.cpu.pop(state["contender"]["pid"], None)
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
                         "gate_passed": snap.data_quality.gate_passed, "max_tick_read_s": cstats.max_tick_read_s}
        R["measurements"] = measurement_rows(snap)
        R["metric_gate"] = E.metric_gate(snap, NUMBERS["COV_MIN"], NUMBERS["N_BASE_MIN"])
        R["aborts"] += R["metric_gate"]["aborts"]
        R["ground_truth"] = E.evaluate(E.ground_truth_inputs(R, target_out))
        R["aborts"] += E.ground_truth_aborts(R["ground_truth"], exp)
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

        R["cleanup"] = E.cleanup(host, sysr, C.read_oplog(oplog),
                                 after_rps=make_after_rps({"loader": loader}, sysr, base, R))
        for p in run.procs:
            try:
                p.wait(2)
            except Exception:                                       # noqa: BLE001
                pass
        R.setdefault("bpf_release", {"released": False, "timed_out": False,          # the wait did not complete
                                     "remaining": f"BPF release wait not completed: {R['cleanup']['errors']}"})
        if R["bpf_release"]["released"]:
            (out / "host_after").mkdir()
            after = E.host_snapshot(sysr)
            (out / "host_after" / "host.json").write_text(json.dumps(after, indent=1, sort_keys=True))
            R["host_compare"] = E.compare_host(base, after)
        else:
            (out / "host_after_unreleased").mkdir()
            (out / "host_after_unreleased" / "host.json").write_text(
                json.dumps(E.host_snapshot(sysr), indent=1, sort_keys=True))
            R["host_compare"] = {"ok": False, "failed": ["bpf_objects_not_released"]}
            R["aborts"].append(f"ABORT: BPF objects not released within {C.BPF_RELEASE_MAX_S} s")
        R["GR"] = E.restore_record(C.read_oplog(oplog), R["cleanup"], R["host_compare"])
        R["rps_restored"] = R["GR"]["checks"]["rps_restored"]
        R["unsafe_incomplete"] = R["GR"]["unsafe_incomplete"] or R["cleanup"]["unsafe_incomplete"]
        if R["unsafe_incomplete"]:
            R["aborts"].append("UNSAFE/INCOMPLETE CLEANUP: RPS on sentlab-b0 not verified 0; lab namespaces kept; "
                               "no further run may start until manual cleanup and verification")
        if not R["cleanup"]["ok"]:
            R["aborts"].append(f"cleanup failure: {R['cleanup']['errors'] or R['cleanup']['verify']}")
        if not R["host_compare"]["ok"]:
            R["aborts"].append(f"host state differs from the pre-run snapshot: {R['host_compare']['failed']}")
        if not R["GR"]["ok"]:
            R["aborts"].append(f"GR failed: {R['GR']['checks']}")
        R.setdefault("driver_ok", False)
        R["driver_ok"] = bool(not R["aborts"] and ((a.calibrate or a.ladder) and R["driver_ok"]
                                                   or R.get("snapshot_unchanged_by_m2")))
        R["verdict"] = "OK" if R["driver_ok"] else "ABORT"
        save()
        for s, h in old.items():
            signal.signal(s, h)
    print(json.dumps({"label": R["label"], "verdict": R["verdict"], "aborts": R["aborts"][:5],
                      "m2": R.get("m2", {}).get("decision"), "iters": R.get("iters"),
                      "ladder": {k: (R.get("ladder") or {}).get(k) for k in ("feasible", "S1", "S2", "S3", "delta",
                                                                             "reason")} if a.ladder else None,
                      "rps_restored": R["rps_restored"], "unsafe_incomplete": R["unsafe_incomplete"]}))
    return 0 if R["driver_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
