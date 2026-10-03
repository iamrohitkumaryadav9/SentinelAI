#!/usr/bin/env python3
"""SentinelAI M3B R1: privileged runtime validation driver.

Run ONLY through scripts/m3b_r1_validate.sh (as root, via sudo). Observation only:
  * loads/attaches the committed M3B loader (no rebuild), reads bpftool state, collects snapshots;
  * baseline activity is harmless and local: short sleep/wake threads, /bin/true process creation and a
    rate-limited TCP stream on 127.0.0.1 (lo) -- no faults, no contention, no external interface;
  * never runs tc/netem/ip changes, never creates namespaces/veth, never writes a sysctl or a cgroup.

Every result goes to OUT/r1.json; raw loader lines, snapshots and bpftool JSON next to it.
Dry run without privileges: --replay SCRIPT uses the replay harness in place of the loader (no bpf()).
"""

import argparse
import json
import math
import os
import resource
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from sentinelai.collectors import LiveReader, SystemClock, build_snapshot, collect, resolve_target  # noqa: E402
from sentinelai.collectors import collected_features  # noqa: E402
from sentinelai.collectors.ebpf import (EBPF_FEATURES, EBPF_SOURCES, EbpfTarget, parse_meta, parse_sample,  # noqa: E402
                                        quantile_ns)
from sentinelai.diagnostic.contract import (EvidenceSnapshot, SourceType, Target, load_contract,  # noqa: E402
                                            measurement_id, scope_kind)
from sentinelai.diagnostic.contract.serialize import canonical_bytes  # noqa: E402
from sentinelai.diagnostic.rules import ParameterSet, diagnose  # noqa: E402
from sentinelai.diagnostic.rules.engine import DEV_FEATURES  # noqa: E402
from sentinelai.ebpf import ProcessEbpfSource, loader_argv, replay_argv, resolve_ebpf_target  # noqa: E402
from sentinelai.ebpf.loader import DEFAULT_LOADER  # noqa: E402

BPFTOOL = "/usr/lib/linux-hwe-6.8-tools-6.8.0-138/bpftool"
REG = load_contract().registry
PROGRAMS = ("sn_sched_wakeup", "sn_sched_wakeup_new", "sn_sched_switch", "sn_softirq_entry", "sn_softirq_exit",
            "sn_tcp_retransmit_skb", "sn_kfree_skb")
MAPS = ("sn_wake", "sn_hist", "sn_stats", "sn_sirq_start", "sn_sirq_acc", "sn_retrans", "sn_kfree")
# validation-only values (contract §6: uncalibrated); used to run collection and confirm M2 accepts the snapshot
NUMBERS = {"W": 10.0, "B": 10.0, "N_BASE_MIN": 5.0, "COV_MIN": 0.8, "Z_STRONG": 3.0, "Z_MODERATE": 2.0,
           "R_STRONG": 3.0, "R_MODERATE": 1.5, "DROP_ABS_MIN": 10.0, "DROP_FRAC_MIN": 0.001, "RT_FRAC_MIN": 0.01,
           "RT_RATE_MIN": 1.0, "SEG_MIN": 100.0, "THR_RATIO_MIN": 0.3, "THR_TIME_MIN": 0.05, "RDX_MIN": 0.05,
           "SAT_MIN": 0.9, "SI_ABS_MIN": 0.5, "SI_RATIO_MIN": 3.0, "SI_SHARE_MIN": 0.5, "PSI_MEM_MIN": 0.2,
           "RECLAIM_MIN": 1000.0, "REFAULT_MIN": 100.0, "APP_WAIT_MIN": 50.0, "APP_SHARE_MIN": 0.5,
           "IMPACT_MIN": 2.0, "DOM_RATIO": 2.0, "τ_DISAGREE": 0.9}
NB = NW = 10
N_TICKS = NB + NW + 1


# ------------------------------------------------------------------------------------------ helpers
def bpftool(*args):
    p = subprocess.run([BPFTOOL, "-j", *args], capture_output=True, text=True, timeout=60)
    try:
        return json.loads(p.stdout) if p.returncode == 0 else {"error": p.stderr.strip()}
    except ValueError:
        return {"error": "unparseable bpftool output"}


def sn_state():
    """Programs, links and maps of the M3B loader, from the kernel. Kernel object names are truncated to 15
    characters (sn_sched_wakeup_new -> sn_sched_wakeup), so objects are selected by the sn_ / sentinel prefix,
    which no pre-existing host object uses; which tracepoint a link is on comes from attach_targets()."""
    progs = bpftool("prog", "show")
    links = bpftool("link", "show")
    maps = bpftool("map", "show")
    if any(isinstance(x, dict) for x in (progs, links, maps)):
        return {"error": [x for x in (progs, links, maps) if isinstance(x, dict)]}
    mine = [p for p in progs if str(p.get("name", "")).startswith("sn_")]
    ids = {p["id"] for p in mine}
    return {"progs": mine, "links": [l for l in links if l.get("prog_id") in ids],
            "maps": [m for m in maps if str(m.get("name", "")).startswith(("sn_", "sentinel"))],
            "all_prog_ids": sorted(p["id"] for p in progs), "all_map_ids": sorted(m["id"] for m in maps),
            "all_link_ids": sorted(l["id"] for l in links)}


_BTF_TRACE = {}


def btf_trace_names():
    """vmlinux BTF type id -> 'btf_trace_<tracepoint>' typedef name (tp_btf attach targets)."""
    if not _BTF_TRACE:
        p = subprocess.run([BPFTOOL, "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "raw"],
                           capture_output=True, text=True, timeout=120)
        for line in p.stdout.splitlines():
            if line.startswith("[") and "TYPEDEF 'btf_trace_" in line:
                _BTF_TRACE[int(line[1:line.index("]")])] = line.split("'")[1]
    return _BTF_TRACE


def attach_targets(pid):
    """From the loader's own fds (kernel fdinfo): every BPF link -> program id and attach target tracepoint."""
    links, progs = [], {}
    for fd in sorted(os.listdir(f"/proc/{pid}/fdinfo"), key=int):
        try:
            kv = dict(l.split(":", 1) for l in open(f"/proc/{pid}/fdinfo/{fd}").read().splitlines() if ":" in l)
        except OSError:
            continue
        kv = {k.strip(): v.strip() for k, v in kv.items()}
        if "link_type" in kv:
            btf_id = int(kv.get("target_btf_id", "-1"))
            links.append({"fd": int(fd), "link_id": int(kv.get("link_id", -1)), "link_type": kv["link_type"],
                          "attach_type": kv.get("attach_type"), "prog_id": int(kv.get("prog_id", -1)),
                          "target_btf_id": btf_id, "tp_name": kv.get("tp_name"),
                          "target": kv.get("tp_name") or btf_trace_names().get(btf_id)})
        elif "prog_type" in kv:
            progs[int(kv.get("prog_id", -1))] = {"fd": int(fd), "prog_type": kv["prog_type"], "tag": kv.get("prog_tag")}
    return {"links": links, "prog_fds": progs}


def proc_stat_busy():
    f = open("/proc/stat").readline().split()
    v = [int(x) for x in f[1:9]]
    user, nice, system, idle, iowait, irq, softirq, steal = v
    return user + nice + system + irq + softirq + steal, sum(v)


def proc_softirqs():
    lines = open("/proc/softirqs").read().splitlines()
    ncpu = len(lines[0].split())
    out = {}
    for l in lines[1:]:
        name, _, rest = l.partition(":")
        out[name.strip()] = [int(x) for x in rest.split()[:ncpu]]
    return out


def proc_task_cpu(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        status = open(f"/proc/{pid}/status").read()
    except OSError:
        return None
    rss = int(next(l.split()[1] for l in status.splitlines() if l.startswith("VmRSS:")))
    hwm = int(next(l.split()[1] for l in status.splitlines() if l.startswith("VmHWM:")))
    return {"cpu_s": (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK"), "rss_kb": rss, "hwm_kb": hwm}


def snmp_retrans():
    lines = [l.split() for l in open("/proc/net/snmp") if l.startswith("Tcp:")]
    return int(lines[1][lines[0].index("RetransSegs")])


class Recording(ProcessEbpfSource):
    """The production process source, recording each raw line, its request latency and /proc/softirqs."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.raw, self.softirqs, self.latency_s = [], [], []

    def _readline(self):
        line = super()._readline()
        self.raw.append(line)
        self.softirqs.append(proc_softirqs())
        return line

    def sample(self):
        t = time.perf_counter()
        out = super().sample()
        self.latency_s.append(time.perf_counter() - t)
        return out


# ------------------------------------------------------------------------------------------ workload
class Workload:
    """Harmless baseline activity in the target cgroup (children and threads inherit it)."""

    def __init__(self, sleepers=2, tcp_chunk=65536, tcp_pause=0.008, spawn_every=1.0):
        self.stop = threading.Event()
        self.counts = {"wake_loops": 0, "tcp_bytes": 0, "spawned": 0}
        self.sleepers, self.chunk, self.pause, self.spawn_every = sleepers, tcp_chunk, tcp_pause, spawn_every
        self.threads = []

    def _sleeper(self):
        n = 0
        while not self.stop.is_set():
            time.sleep(0.001)
            n += 1
        self.counts["wake_loops"] += n

    def _tcp(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))            # loopback only
        srv.listen(1)
        port = srv.getsockname()[1]
        cli = socket.create_connection(("127.0.0.1", port))
        conn, _ = srv.accept()
        conn.settimeout(1.0)
        buf = b"\0" * self.chunk

        def reader():
            while not self.stop.is_set():
                try:
                    if not conn.recv(1 << 20):
                        break
                except OSError:
                    break
        r = threading.Thread(target=reader, daemon=True)
        r.start()
        sent = 0
        while not self.stop.is_set():
            cli.sendall(buf)
            sent += len(buf)
            time.sleep(self.pause)
        self.counts["tcp_bytes"] += sent
        cli.close()
        r.join(2)
        conn.close()
        srv.close()

    def _spawner(self):
        while not self.stop.wait(self.spawn_every):
            subprocess.run(["/bin/true"], check=False)
            self.counts["spawned"] += 1

    def __enter__(self):
        targets = [self._sleeper] * self.sleepers + [self._tcp, self._spawner]
        self.threads = [threading.Thread(target=t, daemon=True) for t in targets]
        for t in self.threads:
            t.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        for t in self.threads:
            t.join(5)


# ------------------------------------------------------------------------------------------ checks
def params():
    nums = dict(NUMBERS)
    nums.update({f"floor[{f}]": 1e-3 for f in set(DEV_FEATURES) | set(collected_features(True))})
    return ParameterSet(parameter_set_id="r1-validation-uncalibrated", numbers=nums,
                        reason_sets={"KFREE_REASONS_LOSS": ("QDISC_DROP",)})


def check_measurements(snap):
    """Data-quality checks on every EBPF measurement of a runtime snapshot."""
    problems, ebpf = [], [m for m in snap.measurements if m.provenance.source is SourceType.EBPF]
    for m in ebpf:
        spec = REG.get(m.feature_id)
        mid = measurement_id(m.feature_id, m.scope, m.window, m.qualifier, m.aggregation)
        checks = {
            "feature": m.feature_id in EBPF_FEATURES, "unit": m.unit is spec.unit,
            "aggregation": m.aggregation in spec.aggregations, "scope": scope_kind(m.scope) in spec.scope_kinds,
            "qualifier": (m.qualifier is None) == (spec.dimension is None)
            and (m.qualifier is None or m.qualifier.dimension == spec.dimension.name),
            "collector_version": m.provenance.collector_version == "m3b-1.0.0",
            "privileged": m.provenance.privileged is True, "id": m.measurement_id == mid,
            "finite_nonneg": m.value is None or (math.isfinite(m.value) and m.value >= 0),
            "window": m.window == snap.window,
            "provenance": bool(m.provenance.locator) and m.provenance.first_sample_at <= m.provenance.last_sample_at,
        }
        bad = [k for k, ok in checks.items() if not ok]
        if bad:
            problems.append({"measurement": f"{m.feature_id}@{m.scope}", "failed": bad})
    ids = [m.measurement_id for m in snap.measurements]
    again = EvidenceSnapshot.model_validate_json(canonical_bytes(snap), strict=False)
    return {"ebpf_measurements": len(ebpf), "problems": problems, "duplicate_ids": len(ids) - len(set(ids)),
            "round_trip_identical": canonical_bytes(again) == canonical_bytes(snap)}


def window_crosscheck(src, offset, ticks, snap):
    """Independent recomputation of the snapshot's W values from the raw loader lines, and softirq
    execution counts against /proc/softirqs over the same interval."""
    meta = src.stream.meta
    a_i, b_i = 1 + offset + NB, 1 + offset + NB + NW
    if src.raw[a_i] is None or src.raw[b_i] is None:
        return {"error": "W boundary sample missing"}
    a, b = parse_sample(src.raw[a_i], meta), parse_sample(src.raw[b_i], meta)
    dt = ticks[NB + NW].mono - ticks[NB].mono
    by = {}
    for m in snap.measurements:
        if m.provenance.source is SourceType.EBPF:
            by[(m.feature_id, m.scope, m.qualifier.value if m.qualifier else None, m.aggregation.value)] = m.value
    out = {"dt_s": dt, "mismatches": []}

    def cmp(key, expect):
        got = by.get(key)
        ok = (got is None and expect is None) or (got is not None and expect is not None
                                                  and math.isclose(got, expect, rel_tol=1e-9, abs_tol=1e-12))
        if not ok:
            out["mismatches"].append({"key": list(key), "snapshot": got, "recomputed": expect})

    hist = {i: b.hist.get(i, 0) - a.hist.get(i, 0) for i in set(a.hist) | set(b.hist)}
    hist = {i: c for i, c in hist.items() if c > 0}
    cg = f"cgroup:{snap.target.cgroup_path}"
    for q, agg in ((0.50, "P50"), (0.99, "P99")):
        v = quantile_ns(hist, q)
        cmp(("sched.latency_hist.target", cg, None, agg), None if v is None else v / 1e6)
    out["latency_samples_in_W"] = sum(hist.values())
    cmp(("tcp.retrans_skb_rate", f"netns:{snap.target.name}", None, "RATE"), (b.retrans - a.retrans) / dt)
    for (cpu, vec), (ns, cnt) in b.softirq.items():
        name = ("HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU")[vec]
        cmp(("softirq.exec_time.percpu", f"cpu:{cpu}", name, "RATE"), (ns - a.softirq[(cpu, vec)][0]) * 1e-9 / dt)
    for slot in set(a.kfree) | set(b.kfree):
        d = b.kfree.get(slot, 0) - a.kfree.get(slot, 0)
        if d > 0:
            cmp(("net.drop.kfree_skb", f"netns:{snap.target.name}", meta.reasons[slot], "RATE"), d / dt)
    pa, pb = src.softirqs[a_i], src.softirqs[b_i]
    sirq = {}
    for vec_i, name in ((2, "NET_TX"), (3, "NET_RX"), (1, "TIMER"), (9, "RCU")):
        ebpf = sum(b.softirq[(c, vec_i)][1] - a.softirq[(c, vec_i)][1] for c in range(meta.ncpu))
        procd = sum(y - x for x, y in zip(pa.get(name, []), pb.get(name, [])))
        sirq[name] = {"ebpf_count": ebpf, "proc_softirqs_count": procd,
                      "rel_diff": abs(ebpf - procd) / procd if procd else None}
    out["softirq_count_vs_proc"] = sirq
    out["stats_delta_W"] = {k: b.stats[k] - a.stats[k] for k in b.stats}
    return out


def run_snapshot(src, target):
    ticks, stats = collect(target, params(), LiveReader(), SystemClock(), 1.0, src)
    snap = build_snapshot(ticks, target, params(), 1.0, ebpf=True)
    again = build_snapshot(ticks, target, params(), 1.0, ebpf=True)
    return ticks, snap, canonical_bytes(snap) == canonical_bytes(again), stats


def summarize_snapshot(snap):
    rows = []
    for m in sorted(snap.measurements, key=lambda m: (m.feature_id, m.scope)):
        if m.provenance.source is SourceType.EBPF and (m.value or m.feature_id != "softirq.exec_time.percpu"):
            rows.append({"feature": m.feature_id, "scope": m.scope, "qualifier": m.qualifier.value if m.qualifier else None,
                         "aggregation": m.aggregation.value, "unit": m.unit.value, "value": m.value,
                         "quality": m.quality.value, "coverage": m.coverage, "id": m.measurement_id})
    return rows


# ------------------------------------------------------------------------------------------ phases
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--replay", help="dry run: replay-harness script instead of the loader (no bpf())")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--trial-seconds", type=float, default=15.0)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    real = a.replay is None
    R = {"real": real, "phases": {}}

    def save():
        (out / "r1.json").write_text(json.dumps(R, indent=1, sort_keys=True, default=str))

    cg_path = open("/proc/self/cgroup").read().strip().split("::", 1)[1]
    t = resolve_target(LiveReader(), "r1", cg_path)
    target = Target(name="r1", cgroup_path=t.cgroup_path, pids=t.pids, cpuset=t.cpuset, netns_ref=f"pid:{os.getpid()}",
                    ifaces=())          # no interfaces: the M3A qdisc read (tc) is never run
    ids = resolve_ebpf_target(target) if real else EbpfTarget(777, 2, 4026531840)
    R["target"] = {"cgroup_path": target.cgroup_path, "pids": len(target.pids), "ebpf": ids.__dict__}

    def source(max_seconds=900):
        argv = loader_argv(ids, max_seconds) if real else replay_argv(str(Path(a.replay).resolve()), ncpu=os.cpu_count())
        return Recording(argv, ids, timeout_s=5.0)

    # -------- phase A: direct load/attach with full stdout/stderr capture
    print("[A] load/attach", flush=True)
    A = {"before": sn_state() if real else None}
    if real:
        p = subprocess.Popen(loader_argv(ids, 120), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        first = p.stdout.readline()
        A["first_line"] = first.strip()
        try:
            parse_meta(first)
            A["meta_ok"] = True
            time.sleep(0.5)
            A["during"] = sn_state()
            A["attach_targets"] = attach_targets(p.pid)
            s0 = p.stdout  # request two samples 3 s apart under baseline activity
            with Workload():
                p.stdin.write("s")
                p.stdin.flush()
                l1 = s0.readline()
                time.sleep(3)
                p.stdin.write("s")
                p.stdin.flush()
                l2 = s0.readline()
            meta = parse_meta(first)
            x, y = parse_sample(l1, meta), parse_sample(l2, meta)
            A["firing_stats_delta_3s"] = {k: y.stats[k] - x.stats[k] for k in y.stats}
            A["firing_counts_delta_3s"] = {
                "latency_samples": sum(y.hist.values()) - sum(x.hist.values()),
                "softirq_pairs": sum(c for _, c in y.softirq.values()) - sum(c for _, c in x.softirq.values()),
                "kfree_target": sum(y.kfree.values()) - sum(x.kfree.values()), "retrans_target": y.retrans - x.retrans}
        except Exception as exc:                      # noqa: BLE001 -- record any failure verbatim
            A["meta_ok"] = False
            A["exception"] = repr(exc)
        try:
            so, se = p.communicate("q", timeout=20)
        except subprocess.TimeoutExpired:
            p.kill()
            so, se = p.communicate()
        A["rest_stdout"], A["stderr"], A["returncode"] = so, se, p.returncode
        time.sleep(1.0)
        A["after"] = sn_state()
    R["phases"]["A_load_attach"] = A
    save()
    if real and not A.get("meta_ok"):
        print("load/attach FAILED; stopping before collection", flush=True)
        return 1

    # -------- phase B: end-to-end, three consecutive windows on one loader
    print("[B] end-to-end windows", flush=True)
    B = {"windows": []}
    src = source()
    B["start"] = src.start()
    if B["start"] is None:
        with Workload() as w:
            for j in range(3):
                ticks, snap, det, cstats = run_snapshot(src, target)
                (out / f"snapshot_B{j}.json").write_bytes(canonical_bytes(snap))
                d = diagnose(snap, params(), code_commit="f18e9fc")
                B["windows"].append({"checks": check_measurements(snap), "deterministic_rebuild": det,
                                     "crosscheck": window_crosscheck(src, j * N_TICKS, ticks, snap),
                                     "measurements": summarize_snapshot(snap),
                                     "privileged_sources_unavailable": list(snap.data_quality.privileged_sources_unavailable),
                                     "m2": {"decision": d.result.decision.value, "accepted": True},
                                     "proc_retrans_segs_rate": next((m.value for m in snap.measurements
                                                                     if m.feature_id == "tcp.retrans_rate"), None),
                                     "collect_max_tick_read_s": cstats.max_tick_read_s})
                save()
        B["workload"] = dict(w.counts)
        B["sample_latency_s"] = {"n": len(src.latency_s), "median": statistics.median(src.latency_s),
                                 "max": max(src.latency_s)}
        B["seq_strictly_increasing"] = all(
            parse_sample(x, src.stream.meta).seq < parse_sample(y, src.stream.meta).seq
            for x, y in zip(src.raw[1:-1], src.raw[2:]) if x and y)
        B["counters_monotonic"] = _monotonic(src)
        (out / "raw_B.jsonl").write_text("\n".join(l or "" for l in src.raw))
        B["loader_pid"] = src.proc.pid
        src.close()
        B["loader_returncode"] = src.proc.returncode
    B["after_close"] = sn_state() if real else None
    R["phases"]["B_end_to_end"] = B
    save()

    # -------- phase C: restart (new loader: counters start from zero, new stream)
    print("[C] restart", flush=True)
    C = {}
    src = source()
    C["start"] = src.start()
    if C["start"] is None:
        with Workload():
            ticks, snap, det, _ = run_snapshot(src, target)
        first = parse_sample(src.raw[1], src.stream.meta)
        C["first_sample"] = {"seq": first.seq, "latency_samples": sum(first.hist.values()),
                             "stats_total": sum(first.stats.values())}
        C["checks"] = check_measurements(snap)
        C["crosscheck"] = window_crosscheck(src, 0, ticks, snap)
        (out / "snapshot_C.json").write_bytes(canonical_bytes(snap))
        src.close()
        C["loader_returncode"] = src.proc.returncode
    C["after_close"] = sn_state() if real else None
    R["phases"]["C_restart"] = C
    save()

    # -------- phase D: loader killed mid-window (fail closed; kernel detaches on process exit)
    print("[D] kill mid-window", flush=True)
    D = {}
    src = source()
    D["start"] = src.start()
    if D["start"] is None:
        killer = threading.Timer(NB + 5, src.proc.kill)
        killer.start()
        with Workload():
            ticks, snap, det, _ = run_snapshot(src, target)
        killer.cancel()
        ebpf = [m for m in snap.measurements if m.provenance.source is SourceType.EBPF]
        D["qualities"] = sorted({m.quality.value for m in ebpf})
        D["max_coverage"] = max((m.coverage for m in ebpf), default=None)
        D["checks"] = check_measurements(snap)
        D["privileged_sources_unavailable"] = list(snap.data_quality.privileged_sources_unavailable)
        src.close()
        D["loader_returncode"] = src.proc.returncode
        time.sleep(1.0)
    D["after_kill"] = sn_state() if real else None
    R["phases"]["D_kill"] = D
    save()

    # -------- phase E: overhead (alternating baseline / enabled trials, same light workload)
    print("[E] overhead", flush=True)
    E = {"trials": []}
    for i in range(a.trials):
        for mode in ("baseline", "enabled"):
            tr = {"trial": i, "mode": mode}
            src = None
            if mode == "enabled":
                src = source(int(a.trial_seconds) + 60)
                tr["start"] = src.start()
                if tr["start"] is not None:
                    E["trials"].append(tr)
                    continue
                c0 = proc_task_cpu(src.proc.pid)
            b0, t0 = proc_stat_busy()
            self0 = resource.getrusage(resource.RUSAGE_SELF)
            w0 = time.monotonic()
            with Workload() as w:
                stop = time.monotonic() + a.trial_seconds
                while time.monotonic() < stop:
                    if src is not None:
                        src.sample()
                    time.sleep(1.0)
            el = time.monotonic() - w0
            b1, t1 = proc_stat_busy()
            self1 = resource.getrusage(resource.RUSAGE_SELF)
            tr.update({"seconds": el, "host_busy_cores": (b1 - b0) / (t1 - t0) * os.cpu_count(),
                       "driver_cpu_s": (self1.ru_utime + self1.ru_stime) - (self0.ru_utime + self0.ru_stime),
                       "wake_loops_per_s": w.counts["wake_loops"] / el, "tcp_MBps": w.counts["tcp_bytes"] / el / 1e6})
            if src is not None:
                c1 = proc_task_cpu(src.proc.pid)
                tr.update({"loader_cpu_s": c1["cpu_s"] - c0["cpu_s"], "loader_rss_kb": c1["rss_kb"],
                           "loader_hwm_kb": c1["hwm_kb"], "sample_latency_ms_median":
                           statistics.median(src.latency_s) * 1e3 if src.latency_s else None})
                if real:
                    tr["maps_memlock_bytes"] = sum(int(m.get("bytes_memlock", 0)) for m in sn_state().get("maps", []))
                src.close()
            E["trials"].append(tr)
            save()
    base = [t["host_busy_cores"] for t in E["trials"] if t["mode"] == "baseline"]
    en = [t["host_busy_cores"] for t in E["trials"] if t["mode"] == "enabled" and "host_busy_cores" in t]
    if base and en:
        E["host_busy_cores"] = {"baseline_mean": statistics.mean(base), "enabled_mean": statistics.mean(en),
                                "baseline_stdev": statistics.pstdev(base), "enabled_stdev": statistics.pstdev(en),
                                "paired_diffs": [e - b for b, e in zip(base, en)]}
    E["after"] = sn_state() if real else None
    R["phases"]["E_overhead"] = E
    save()
    print("done", flush=True)
    return 0


def _monotonic(src):
    """Every cumulative counter in consecutive samples of one stream never decreases."""
    prev = None
    for line in src.raw[1:]:
        if not line:
            continue
        try:
            s = parse_sample(line, src.stream.meta)
        except Exception:                             # noqa: BLE001 -- terminal lines end the stream
            continue
        if prev is not None:
            if s.retrans < prev.retrans or any(s.hist.get(i, 0) < c for i, c in prev.hist.items()) or \
               any(s.softirq[k][0] < v[0] or s.softirq[k][1] < v[1] for k, v in prev.softirq.items()) or \
               any(s.kfree.get(i, 0) < c for i, c in prev.kfree.items()) or \
               any(s.stats[k] < v for k, v in prev.stats.items()):
                return False
        prev = s
    return True


if __name__ == "__main__":
    sys.exit(main())
