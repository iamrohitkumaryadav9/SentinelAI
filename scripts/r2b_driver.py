#!/usr/bin/env python3
"""SentinelAI R2-B: one controlled packet-loss run, executed as root INSIDE netns sentinel-lab-a.

Run only through scripts/r2b_validate.sh (which creates and destroys the R2-A lab around every run).

  workload  paced TCP stream sentinel-lab-a (10.199.0.1) -> sentinel-lab-b (10.199.0.2:5201), fixed rate
  collect   M3A + M3B collection for the sender (target netns A, iface sentlab-a0): B clean, W faulted
  fault     netem loss <p>% on sentlab-a0 root, applied right after the last baseline tick, removed right
            after the last window tick (p = 0: no fault; the baseline run)
  attribute a second eBPF loader targets netns B (receiver) over the same ticks
  M2        the unchanged engine diagnoses the snapshot; the prediction is written before the call
Writes OUT/run.json, OUT/snapshot.json, OUT/raw_a.jsonl, OUT/raw_b.jsonl.
"""

import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

import r2b_fault as F  # noqa: E402
from m3b_r1_validate import Recording  # noqa: E402  (production ProcessEbpfSource + raw-line recording)
from sentinelai.collectors import LiveReader, SystemClock, build_snapshot, collect, collected_features  # noqa: E402
from sentinelai.collectors.ebpf import EbpfTarget, parse_sample  # noqa: E402
from sentinelai.diagnostic.contract import EvidenceSnapshot, SourceType, Target  # noqa: E402
from sentinelai.diagnostic.contract.serialize import canonical_bytes  # noqa: E402
from sentinelai.diagnostic.rules import ParameterSet, diagnose  # noqa: E402
from sentinelai.diagnostic.rules.engine import DEV_FEATURES  # noqa: E402
from sentinelai.ebpf import loader_argv, resolve_ebpf_target  # noqa: E402

# validation-only parameter values (contract §6: uncalibrated), the same numbers as the M3B R1 validation
NUMBERS = {"W": 10.0, "B": 10.0, "N_BASE_MIN": 5.0, "COV_MIN": 0.8, "Z_STRONG": 3.0, "Z_MODERATE": 2.0,
           "R_STRONG": 3.0, "R_MODERATE": 1.5, "DROP_ABS_MIN": 10.0, "DROP_FRAC_MIN": 0.001, "RT_FRAC_MIN": 0.01,
           "RT_RATE_MIN": 1.0, "SEG_MIN": 100.0, "THR_RATIO_MIN": 0.3, "THR_TIME_MIN": 0.05, "RDX_MIN": 0.05,
           "SAT_MIN": 0.9, "SI_ABS_MIN": 0.5, "SI_RATIO_MIN": 3.0, "SI_SHARE_MIN": 0.5, "PSI_MEM_MIN": 0.2,
           "RECLAIM_MIN": 1000.0, "REFAULT_MIN": 100.0, "APP_WAIT_MIN": 50.0, "APP_SHARE_MIN": 0.5,
           "IMPACT_MIN": 2.0, "DOM_RATIO": 2.0, "τ_DISAGREE": 0.9}
KFREE_REASONS_LOSS = ("QDISC_DROP", "CPU_BACKLOG", "NETFILTER_DROP")
NB = NW = 10
PORT, CHUNK, RATE = 5201, 1448, 4000            # one MSS-sized write every 1/4000 s, TCP_NODELAY
RECEIVER = (f"import socket\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            f"s.bind(('{F.LAB['ip_b']}',{PORT}));s.listen(1);s.settimeout(30)\nc,_=s.accept();c.settimeout(5);n=0\n"
            "while True:\n try:\n  d=c.recv(1<<20)\n except OSError:\n  break\n if not d:\n  break\n n+=len(d)\n"
            "print(n,flush=True)")


def params():
    nums = dict(NUMBERS)
    nums.update({f"floor[{f}]": 1e-3 for f in set(DEV_FEATURES) | set(collected_features(True))})
    return ParameterSet(parameter_set_id="r2b-validation-uncalibrated", numbers=nums,
                        reason_sets={"KFREE_REASONS_LOSS": KFREE_REASONS_LOSS})


def tcp_total_retrans(sock):
    """struct tcp_info.tcpi_total_retrans (u32 at offset 100): retransmitted SEGMENTS of this connection."""
    info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
    return struct.unpack_from("I", info, 100)[0]


def snmp():
    lines = [l.split() for l in open("/proc/net/snmp") if l.startswith("Tcp:")]
    return {k: int(v) for k, v in zip(lines[0][1:], lines[1][1:]) if k in ("OutSegs", "RetransSegs", "InSegs")}


class Sender:
    def __init__(self):
        self.stop, self.sent, self.sock, self.error = threading.Event(), 0, None, None
        self.t = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            for _ in range(50):
                try:
                    self.sock = socket.create_connection((F.LAB["ip_b"], PORT), timeout=2)
                    break
                except OSError:
                    time.sleep(0.1)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            buf, t0, i = b"\x5a" * CHUNK, time.monotonic(), 0
            while not self.stop.is_set():
                i += 1
                delay = t0 + i / RATE - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                self.sock.sendall(buf)
                self.sent += CHUNK
        except Exception as exc:                                     # noqa: BLE001 -- recorded, run fails
            self.error = repr(exc)


class FaultClock(SystemClock):
    """SystemClock that calls on_window() once, right after the last baseline tick (before sleeping to tick nB+1)
    and on_end() right after the last window tick is sampled (first call after collection finishes)."""

    def __init__(self, on_window):
        self.on_window, self.calls = on_window, 0

    def sleep_until(self, mono):
        if self.calls == NB + 1:
            self.on_window()
        self.calls += 1
        super().sleep_until(mono)


class Both:
    """Feeds the snapshot from loader A (target) and samples loader B at the same tick."""

    def __init__(self, a, b):
        self.a, self.b = a, b

    def sample(self):
        out = self.a.sample()
        self.b.sample()
        return out


def m2_summary(d):
    r = d.result
    items = {i.item_id: i for i in d.snapshot.evidence_items}
    cands = [{"label": c.label.value, "status": c.status.value, "required_met": list(c.required_met),
              "required_missing": list(c.required_missing),
              "supporting": sorted(items[i].predicate_id for i in c.supporting),
              "contradicting": sorted(items[i].predicate_id for i in c.contradicting)} for c in r.candidates]
    return {"decision": r.decision.value, "contributing": [l.value for l in r.contributing],
            "abstained": r.abstained, "abstention_reasons": [x.value for x in r.abstention_reasons],
            "confidence": r.confidence_level.value, "flags": [f.value for f in r.flags], "candidates": cands,
            "network_items": sorted({(i.predicate_id, i.kind.value, i.observed) for i in d.snapshot.evidence_items
                                     if i.predicate_id.startswith(("PL.", "RT.", "DEV[net.drop", "DEV[tcp"))},
                                    key=str)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--loss", type=float, required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--commit", required=True, help="git HEAD of the checkout (M2 EngineInfo requires a git hash)")
    a = ap.parse_args()
    if not re.fullmatch(r"[0-9a-f]{7,40}", a.commit):
        raise SystemExit(f"REFUSING: --commit {a.commit!r} is not a git hash")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if a.loss != 0:
        F._loss_token(a.loss)                                   # refuse unapproved levels before anything runs
    if os.stat("/proc/self/ns/net").st_ino != os.stat(f"/run/netns/{F.NS_A}").st_ino:
        raise SystemExit(f"REFUSING: driver must run inside netns {F.NS_A}")
    R = {"label": a.label, "loss_pct": a.loss, "workload": {"port": PORT, "chunk_bytes": CHUNK, "rate_per_s": RATE},
         "numbers": {k: NUMBERS[k] for k in ("W", "B", "DROP_ABS_MIN", "DROP_FRAC_MIN", "RT_FRAC_MIN", "SEG_MIN")},
         "kfree_reasons_loss": KFREE_REASONS_LOSS, "events": []}
    ev = lambda name, **kw: R["events"].append({"t_mono": time.monotonic(), "event": name, **kw})

    def save():
        (out / "run.json").write_text(json.dumps(R, indent=1, sort_keys=True, default=str))

    q0 = F.parse_qdiscs(F.execute(F.qdisc_show())[1])
    R["qdisc_before"] = q0
    if not F.is_clean(q0):
        raise SystemExit(f"REFUSING: lab qdisc not clean before the run: {q0}")

    recv = subprocess.Popen(["ip", "netns", "exec", F.NS_B, "python3", "-c", RECEIVER], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    sender = Sender()
    fault = {"installed": False}
    srcs = []
    try:
        time.sleep(0.5)
        sender.t.start()
        cg = open("/proc/self/cgroup").read().strip().split("::", 1)[1]
        target = Target(name="laba", cgroup_path=cg, pids=(os.getpid(),), cpuset=None, netns_ref=f"pid:{os.getpid()}",
                        ifaces=(F.IF_A,))
        ids_a = resolve_ebpf_target(target)
        ids_b = EbpfTarget(ids_a.cgroup_id, ids_a.cgroup_level, os.stat(f"/run/netns/{F.NS_B}").st_ino)
        R["target"] = {"cgroup_path": cg, "pid": os.getpid(), "iface": F.IF_A, "ebpf_a": ids_a.__dict__,
                       "ebpf_b": ids_b.__dict__}
        src_a, src_b = Recording(loader_argv(ids_a, 300), ids_a, 5.0), Recording(loader_argv(ids_b, 300), ids_b, 5.0)
        srcs = [src_a, src_b]
        R["loader_start"] = {"a": src_a.start(), "b": src_b.start()}
        if any(R["loader_start"].values()):
            raise RuntimeError(f"loader unavailable: {R['loader_start']}")
        time.sleep(2.0)                                          # workload warm-up before tick 0

        def on_window():
            R["tcp_info_retrans_at_window_start"] = tcp_total_retrans(sender.sock)
            R["snmp_a_at_window_start"] = snmp()
            if a.loss > 0:
                rc, _, err = F.execute(F.netem_add(a.loss))
                ev("fault_added", rc=rc, err=err.strip())
                if rc != 0:
                    raise RuntimeError(f"netem add failed: {err}")
                fault["installed"] = True
                qs = F.parse_qdiscs(F.execute(F.qdisc_show())[1])
                R["fault_ground_truth_start"] = F.netem_ground_truth(qs, F.execute(F.qdisc_show_text())[1], a.loss)
            else:
                ev("no_fault_baseline_window")

        ev("collect_start")
        ticks, cstats = collect(target, params(), LiveReader(), FaultClock(on_window), 1.0, Both(src_a, src_b))
        ev("collect_end")
        R["tcp_info_retrans_at_window_end"] = tcp_total_retrans(sender.sock)
        R["snmp_a_at_window_end"] = snmp()
        if fault["installed"]:
            qs = F.parse_qdiscs(F.execute(F.qdisc_show())[1])
            R["fault_ground_truth_end"] = F.netem_ground_truth(qs, F.execute(F.qdisc_show_text())[1], a.loss)
            rc, _, err = F.execute(F.netem_del())
            ev("fault_removed", rc=rc, err=err.strip())
            fault["installed"] = rc != 0
        R["window"] = {"start_mono": ticks[NB].mono, "end_mono": ticks[NB + NW].mono,
                       "start_wall": str(ticks[NB].wall), "end_wall": str(ticks[NB + NW].wall)}
        snap = build_snapshot(ticks, target, params(), 1.0, ebpf=True)
        (out / "snapshot.json").write_bytes(canonical_bytes(snap))
        again = EvidenceSnapshot.model_validate_json(canonical_bytes(snap), strict=False)
        R["snapshot"] = {"id": snap.snapshot_id, "measurements": len(snap.measurements),
                         "ebpf_measurements": sum(m.provenance.source is SourceType.EBPF for m in snap.measurements),
                         "round_trip_identical": canonical_bytes(again) == canonical_bytes(snap),
                         "rebuild_identical": canonical_bytes(build_snapshot(ticks, target, params(), 1.0, ebpf=True))
                         == canonical_bytes(snap), "gate_passed": snap.data_quality.gate_passed,
                         "privileged_sources_unavailable": list(snap.data_quality.privileged_sources_unavailable),
                         "max_tick_read_s": cstats.max_tick_read_s}
        R["measurements"] = [{"feature": m.feature_id, "scope": m.scope, "qualifier": m.qualifier.value if m.qualifier
                              else None, "aggregation": m.aggregation.value, "unit": m.unit.value, "value": m.value,
                              "quality": m.quality.value, "coverage": m.coverage, "source": m.provenance.source.value,
                              "baseline_median": m.baseline.median if m.baseline else None}
                             for m in snap.measurements if m.feature_id in (
                                 "net.drop.qdisc", "net.pkts.iface", "net.drop.kfree_skb", "tcp.retrans_skb_rate",
                                 "tcp.retrans_rate", "tcp.retrans_frac", "tcp.out_segs_rate", "net.drop.iface_tx",
                                 "net.drop.iface_rx", "net.drop.socket")]
        # window deltas from both loaders at the same ticks (raw[0] is the meta line; raw[1 + k] is tick k)
        meta_a, meta_b = src_a.stream.meta, src_b.stream.meta
        da = F.w_delta(parse_sample(src_a.raw[1 + NB], meta_a), parse_sample(src_a.raw[1 + NB + NW], meta_a))
        db = F.w_delta(parse_sample(src_b.raw[1 + NB], meta_b), parse_sample(src_b.raw[1 + NB + NW], meta_b))
        qslot = meta_a.reasons.index("QDISC_DROP")
        qd = lambda t: t.obs[f"tc.{F.IF_A}"]["drops"] if isinstance(t.obs.get(f"tc.{F.IF_A}"), dict) else None
        qdw = (qd(ticks[NB + NW]) or 0) - (qd(ticks[NB]) or 0)
        R["ebpf_window"] = {"a": da, "b": db, "qdisc_drop_slot": qslot,
                            "reason_names": {str(s): meta_a.reasons[s] for s in set(da["kfree"]) | set(db["kfree"])}}
        R["attribution"] = F.attribution_checks(a.loss, qdw, da, db, qslot)
        dt = ticks[NB + NW].mono - ticks[NB].mono
        pk = next((m for m in snap.measurements if m.feature_id == "net.pkts.iface"), None)
        R["prediction"] = F.predict_m2(a.loss, qdw / dt, pk.value if pk and pk.value else 0.0, NUMBERS)
        save()
        d = diagnose(snap, params(), code_commit=a.commit)
        R["m2"] = m2_summary(d)
        R["m2_matches_prediction"] = R["m2"]["decision"] == R["prediction"]["decision"]
        R["snapshot_unchanged_by_m2"] = canonical_bytes(snap) == (out / "snapshot.json").read_bytes()
        for name, s in (("a", src_a), ("b", src_b)):
            (out / f"raw_{name}.jsonl").write_text("\n".join(l or "" for l in s.raw))
    finally:
        if fault["installed"]:                                  # failure path: never leave the fault behind
            rc, _, err = F.execute(F.netem_del())
            ev("fault_removed_on_failure_path", rc=rc, err=err.strip())
        sender.stop.set()
        sender.t.join(5)
        for s in srcs:
            s.close()
        try:
            rout, rerr = recv.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            recv.kill()
            rout, rerr = recv.communicate()
        q1 = F.parse_qdiscs(F.execute(F.qdisc_show())[1])
        R["qdisc_after"], R["qdisc_restored_clean"] = q1, F.is_clean(q1)
        R["workload_result"] = {"sent_bytes": sender.sent, "received_bytes": int(rout.strip() or -1)
                                if rout.strip().isdigit() else None, "sender_error": sender.error,
                                "receiver_stderr": rerr.strip()[-500:]}
        save()
    ok = (R.get("qdisc_restored_clean") and R["attribution"]["ok"] and R["snapshot"]["round_trip_identical"]
          and R["snapshot"]["rebuild_identical"] and R.get("snapshot_unchanged_by_m2") and not sender.error)
    R["driver_ok"] = bool(ok)
    save()
    print(json.dumps({"label": a.label, "driver_ok": R["driver_ok"], "m2": R["m2"]["decision"],
                      "prediction": R["prediction"]["decision"], "qdisc_drops_w": R["attribution"]["qdisc_drops"]}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
