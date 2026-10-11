"""R2-E tooling: RPS-steered veth NET_RX onto CPU 18. The only new host mutation is rps_cpus of sentlab-b0 rx-0 inside
sentinel-lab-b (40000 | 80000 | 0) through one read-before / read-after path, reset and verified before the lab
namespaces are deleted. Ground truth (GP GN GS GV GI G0 G6' GL GC G7 GR) is exercised on synthetic RAW observations
(kernel file texts, loader lines, iperf3 JSON) through the same pure evaluate() the run uses, and recomputed offline.
No test creates a cgroup, namespace, veth, RPS map, process in a lab, or traffic; no test changes the host."""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import r2c_cpu as C  # noqa: E402
import r2e_softirq as E  # noqa: E402

MODULE = (ROOT / "scripts" / "r2e_softirq.py").read_text()
DRIVER = (ROOT / "scripts" / "r2e_driver.py").read_text()
WRAPPER = (ROOT / "scripts" / "r2e_validate.sh").read_text()
EBPF_FIXTURE = ROOT / "results" / "phase1c_r2d" / "20261003T191737Z" / "T1-1" / "raw_ebpf.jsonl"
SNAP_E2 = ROOT / "results" / "phase1c_r2c" / "20261003T175532Z" / "E2-rep1" / "snapshot.json"
SNAP_E0 = ROOT / "results" / "phase1c_r2c" / "20261003T175532Z" / "E0-open" / "snapshot.json"
IN_GIT = (ROOT / ".git").exists()

HZ, NB, NW = 100, C.NB, C.NW
I_B0, I_W0, I_W1 = 2, 2 + NB, 2 + NB + NW
N_OBS = I_W1 + 3
TPID, CPID, S0, S1P, C0, C1P, KSOFT = 4101, 4103, 4201, 4203, 4301, 4303, 78
OUT = str(E.REPO / "results" / "phase1c_r2e" / "T" / "x.json")


def opt(argv, flag):
    """Index of the value of an iperf3 option (searched after the iperf3 binary, not in the sh -c join)."""
    k = argv.index(E.IPERF3)
    return k + argv[k:].index(flag) + 1


def code_lines(text):
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


# ------------------------------------------------------------------------------------------ synthetic raw evidence
_lines = EBPF_FIXTURE.read_text().splitlines()
META = _lines[0]
_TEMPLATE = json.loads(_lines[1])


def ebpf_line(seq, mono_s, ns):
    """A protocol-valid loader sample: cumulative softirq ns per (cpu, vector index) from `ns`, everything else 0."""
    d = copy.deepcopy(_TEMPLATE)
    d.update(seq=seq, mono_ns=int(mono_s * 1e9))
    d["softirq"] = [[c, v, int(ns.get((c, v), 0)), 0] for c in range(24) for v in range(10)]
    return json.dumps(d, separators=(",", ":"))


def psi_text(total):
    return f"some avg10=0.00 avg60=0.00 avg300=0.00 total={int(total)}\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"


def stat_text(name, comm, flags, cpu, state="S"):
    rest = [state] + ["0"] * 50
    rest[6], rest[36] = str(flags), str(cpu)
    return f"{name} ({comm}) " + " ".join(rest) + "\n"


def links_json(side, ifn, rx, tx, rxd=0, txd=0, q=1, extra=None, qdisc="noqueue", kind="veth"):
    lo = {"ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"], "operstate": "UNKNOWN", "qdisc": "noqueue",
          "num_tx_queues": 1, "num_rx_queues": 1, "stats64": {"rx": {"packets": 0, "dropped": 0},
                                                              "tx": {"packets": 0, "dropped": 0}}}
    v = {"ifname": ifn, "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP", "qdisc": qdisc,
         "num_tx_queues": q, "num_rx_queues": q, "linkinfo": {"info_kind": kind}, "link_netnsid": 0,
         "stats64": {"rx": {"packets": rx, "dropped": rxd}, "tx": {"packets": tx, "dropped": txd}}}
    return json.dumps([lo, v] + (extra or []))


def iperf_json(packets=100000, lost=0, remote=E.IP_B, local=E.IP_A, error=None):
    if error:
        return json.dumps({"error": error})
    return json.dumps({"start": {"connected": [{"remote_host": remote, "local_host": local}]},
                       "end": {"sum": {"packets": packets, "lost_packets": lost}}})


DEFAULTS = {
    "E0": dict(nw=0.0001, kw=0.0, rd_w=0.002, psi_w=1000, pps=0),
    "S1": dict(nw=0.2, kw=0.0, rd_w=0.01, psi_w=5000, pps=40000),
    "S2": dict(nw=0.6, kw=0.15, rd_w=0.12, psi_w=60000, pps=160000),
    "S3": dict(nw=0.75, kw=0.25, rd_w=0.2, psi_w=120000, pps=320000),
    "N1": dict(nw=0.0001, kw=0.0, rd_w=0.5, psi_w=400000, pps=0, cont_w=0.78),
    "N2": dict(nw=0.0001, kw=0.0, rd_w=0.002, psi_w=1000, pps=320000, n19=0.7),
}


def synth(label="S2-1", **kw):
    """Raw observations of one run, as gt_sample would record them, plus every other saved input of evaluate()."""
    exp = E.experiment_of(label)
    p = {"nb": 0.0001, "other18": 0.001, "target": 0.21, "foreign": 0.0, "rd_b": 0.001, "psi_b": 1000.0,
         "cont_w": 0.0, "n19": 0.0, "delta": 0.05, "drop": {}, "udp_err": 0, "a_txd": 0, "b_rxd": 0, "lost": 0,
         "processed_ratio": 1.0, "frac": None}
    p.update(DEFAULTS[exp.kind])
    p.update(kw)
    rps_cpu = E.RPS_VALUES[exp.rps]
    cum = {k: 0.0 for k in ("nr18", "ot18", "nr19", "tgt", "cont", "kth", "for", "idle18", "si18", "busy18", "rd",
                            "psi", "rx", "proc", "snd", "udp", "cpu_all_busy")}
    drops = {c: 0 for c in range(24)}
    obs, expected, in_w = [], [], []
    traffic = exp.traffic is not None
    for k in range(N_OBS):
        w = I_W0 < k <= I_W1
        if k > 0:
            nr = p["nw"] if w else p["nb"]
            cum["nr18"] += nr * 1e9
            cum["ot18"] += p["other18"] * 1e9
            cum["nr19"] += (p["n19"] if w else 0.0001) * 1e9
            cum["tgt"] += p["target"] * 1e6
            cum["cont"] += (p["cont_w"] if w else 0.0) * 1e6
            kth = (p["kw"] if w else 0.0)
            cum["kth"] += kth * 1e9
            cum["for"] += p["foreign"] * 1e9
            busy = min(1.0, p["target"] + (p["cont_w"] if w else 0) + kth + p["foreign"] + nr)
            cum["idle18"] += HZ * (1 - busy)
            frac = p["frac"] if p["frac"] is not None else nr
            cum["si18"] += HZ * frac
            cum["busy18"] += HZ * (busy - frac) if busy > frac else 0
            cum["rd"] += (p["rd_w"] if w else p["rd_b"]) * 1e9
            cum["psi"] += p["psi_w"] if w else p["psi_b"]
            pk = p["pps"] if w and traffic else 0
            cum["rx"] += pk
            cum["proc"] += pk * p["processed_ratio"]
            cum["udp"] += pk
            cum["cpu_all_busy"] += 0.02 * 24 * HZ
            if k == I_W0 + 1:
                for c, n in p["drop"].items():
                    drops[c] += n
        mono = 100.0 + k
        rq = {n: 0 for n in range(24)}
        rq[18] = int(cum["tgt"] * 1e3 + cum["cont"] * 1e3 + cum["kth"] + cum["for"])
        sched = "version 15\ntimestamp 1\n" + "".join(f"cpu{n} 0 0 0 0 0 0 {rq[n]} 0 0\n" for n in range(24))
        lines = [f"cpu {int(cum['cpu_all_busy'])} 0 0 {int(24 * HZ * k - cum['cpu_all_busy'])} 0 0 0 0 0 0"]
        for n in range(24):
            if n == 18:
                lines.append(f"cpu18 {int(cum['busy18'])} 0 0 {int(cum['idle18'])} 0 0 {int(cum['si18'])} 0 0 0")
            else:
                lines.append(f"cpu{n} 1 0 0 {HZ * k} 0 0 0 0 0 0")
        softnet = "".join(" ".join(f"{x:08x}" for x in (
            int(cum["proc"]) if n == rps_cpu else 0, drops[n], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, n, 0, 0)) + "\n"
            for n in range(24))
        sirqs = "    " + " ".join(f"CPU{n}" for n in range(24)) + "\n" + "".join(
            f"{v}: " + " ".join("0" for _ in range(24)) + "\n" for v in ("HI", "TIMER", "NET_TX", "NET_RX"))
        traffic_pids = [S0, S1P] + ([C0, C1P] if traffic and w else [])
        cont_pids = [CPID] if exp.contender and w else []
        cpu = {str(TPID): 18, str(S0): 23, str(S1P): 23}
        if traffic and w:
            cpu.update({str(C0): 20, str(C1P): 22})
        if cont_pids:
            cpu[str(CPID)] = 18
        want = {"target": [TPID], "contender": cont_pids, "traffic": traffic_pids, "cpu": cpu}
        leaf = lambda procs, cpus, usage: {
            "cpu.max": "max 100000\n", "cpuset.cpus.effective": cpus + "\n",
            "cpu.stat": f"usage_usec {int(usage)}\nuser_usec 0\nsystem_usec 0\nnr_periods 0\nnr_throttled 0\n"
                        "throttled_usec 0\n",
            "cpu.pressure": psi_text(cum["psi"]), "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
            "cgroup.procs": "".join(f"{x}\n" for x in procs)}
        tasks = {str(TPID): {"stat": stat_text(TPID, "python3", 0, 18),
                             "schedstat": f"{int(cum['tgt'] * 1e3)} {int(cum['rd'])} 10\n"},
                 str(KSOFT): {"stat": stat_text(KSOFT, "ksoftirqd/18", E.PF_KTHREAD, 18),
                              "schedstat": f"{int(cum['kth'])} 0 1\n"}}
        for pid in traffic_pids:
            tasks[str(pid)] = {"stat": stat_text(pid, "iperf3", 0, cpu[str(pid)]), "schedstat": "1 0 1\n"}
        for pid in cont_pids:
            tasks[str(pid)] = {"stat": stat_text(pid, "python3", 0, 18), "schedstat": f"{int(cum['cont'] * 1e3)} 0 1\n"}
        ns = {(18, 3): cum["nr18"], (18, 1): cum["ot18"], (19, 3): cum["nr19"]}
        is_tick = I_B0 <= k <= I_W1
        o = {"mono": mono, "tag": "tick" if is_tick else "warmup" if k < I_B0 else "recovery",
             "raw": {"stat": "\n".join(lines) + "\n", "schedstat": sched, "softirqs": sirqs, "softnet": softnet,
                     "vmstat": "pswpin 10\npswpout 20\n", "psi_cpu": psi_text(5), "psi_memory": psi_text(7),
                     "nic_irq_eff": "21\n"},
             "slices": {s: psi_text(100) for s in C.SLICES},
             "leaves": {"parent": leaf([], "18,20,22-23", 0), "target": leaf([TPID], "18", cum["tgt"]),
                        "contender": leaf(cont_pids, "18", cum["cont"]),
                        "traffic": leaf(traffic_pids, "20,22-23", 1000)},
             "tasks": tasks,
             "target_netns": {"dev": "Inter-|\n face |\n    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                              "snmp": "Tcp: InSegs OutSegs RetransSegs\nTcp: 0 0 0\nUdp: InDatagrams OutDatagrams\n"
                                      "Udp: 0 0\n"},
             "lab_b_snmp": "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n"
                           f"Udp: {int(cum['udp'])} 0 {p['udp_err'] if k > I_W0 else 0} 0 "
                           f"{p['udp_err'] if k > I_W0 else 0} 0\n",
             "lab": {"a_links": links_json("a", E.IF_A, 0, int(cum["rx"]), txd=p["a_txd"] if k > I_W0 else 0),
                     "b_links": links_json("b", E.IF_B, int(cum["rx"]), 0, rxd=p["b_rxd"] if k > I_W0 else 0),
                     "a_routes": json.dumps([{"dst": E.SUBNET, "dev": E.IF_A}]),
                     "b_routes": json.dumps([{"dst": E.SUBNET, "dev": E.IF_B}]), "a_routes6": "[]", "b_routes6": "[]"},
             "ebpf_line": ebpf_line(k + 1, mono, ns) if is_tick else None}
        obs.append(o)
        expected.append(want)
        in_w.append(w)
    iperf = {"client0": iperf_json(lost=p["lost"]), "client1": iperf_json()} if traffic else {}
    setup = {"ethtool_b": "Features for sentlab-b0:\ngeneric-receive-offload: off\n", "netdev_max_backlog": "1000",
             "rps_readback": E.RPS_READBACK[exp.rps], "lab_verified": True}
    return {"label": label, "obs": obs, "expected": expected, "in_w": in_w, "window": [I_B0, I_W0, I_W1],
            "ebpf_meta": META, "setup": setup, "iperf": iperf, "delta": p["delta"], "hz": HZ, "target_pid": TPID,
            "target_out": None}


def gt(label="S2-1", edit=None, **kw):
    inp = synth(label, **kw)
    if edit:
        edit(inp)
    return E.evaluate(inp)


# ------------------------------------------------------------------------------------------ allowlist
class TestAllowlist(unittest.TestCase):
    def test_every_planned_operation_accepted(self):
        for label in E.MATRIX:
            exp = E.experiment_of(label)
            pps = E.LADDER_PPS[3] if exp.traffic else None
            for op in E.setup_plan(exp) + [E.netns_del(E.NS_A), E.netns_del(E.NS_B),
                                           ("write", f"{E.TRAFFIC_DIR}/cgroup.kill", "1"), ("rmdir", E.TRAFFIC_DIR)]:
                E.check_op(op, exp, 1000, pps)
            for i in (0, 1):
                E.check_op(("spawn", "server", E.server_argv(i)), exp, 1000, pps)
                if exp.traffic:
                    E.check_op(("spawn", "client", E.client_argv(i, pps)), exp, 1000, pps)

    def test_lab_is_r2a_topology_with_single_queue_veth(self):
        cmds = [op[1] for op in E.lab_plan()]
        add = [c for c in cmds if c[:3] == ("ip", "link", "add")]
        self.assertEqual(len(add), 1)
        self.assertEqual(add[0].count("numtxqueues"), 2)
        self.assertEqual(add[0].count("numrxqueues"), 2)
        self.assertEqual([add[0][i + 1] for i, t in enumerate(add[0]) if t in ("numtxqueues", "numrxqueues")],
                         ["1"] * 4)
        self.assertEqual((E.NS_A, E.NS_B, E.IF_A, E.IF_B, E.IP_A, E.IP_B), ("sentinel-lab-a", "sentinel-lab-b",
                                                                             "sentlab-a0", "sentlab-b0", "10.199.0.1",
                                                                             "10.199.0.2"))
        self.assertFalse([c for c in cmds if "route" in c or "default" in c])

    def test_forbidden_operations_refused(self):
        s3, pps = E.EXPERIMENTS["S3"], E.LADDER_PPS[3]
        c18 = E.client_argv(0, pps)
        c18[opt(c18, "-A")] = "18"
        other_ip = E.client_argv(0, pps)
        other_ip[opt(other_ip, "-c")] = "8.8.8.8"
        srv_a = E.server_argv(0)
        srv_a[srv_a.index("exec") + 1] = E.NS_A
        bad = [("write", f"{E.TARGET_DIR}/cpu.max", "50000 100000"), ("write", f"{E.LAB_DIR}/cpu.max", "max 100000"),
               ("write", f"{C.CG_ROOT}/cpuset.cpus", "0-23"), ("write", f"{E.TRAFFIC_DIR}/cpuset.cpus", "18"),
               ("write", f"{E.TARGET_DIR}/../cpu.max", "1 1"), ("mkdir", f"{C.CG_ROOT}/system.slice/x"),
               ("rmdir", f"{C.CG_ROOT}/user.slice"),
               ("write", "/sys/class/net/enp0s31f6/queues/rx-0/rps_cpus", "40000"),
               ("write", "/sys/class/net/docker0/queues/rx-0/rps_cpus", "0"),
               ("cmd", ("ip", "link", "set", "enp0s31f6", "down")), ("cmd", ("ip", "addr", "flush", "docker0")),
               ("cmd", ("tc", "qdisc", "add", "dev", E.IF_A, "root", "netem")),
               ("cmd", ("sysctl", "-w", "net.core.rps_sock_flow_entries=1")),
               ("cmd", ("ethtool", "-K", E.IF_B, "gro", "on")), ("cmd", ("modprobe", "pktgen")),
               ("cmd", ("ip", "netns", "del", "other")), ("cmd", ("ip", "route", "add", "default", "via", E.IP_B)),
               ("cmd", ("ip", "link", "add", E.IF_A, "netns", E.NS_A, "type", "veth", "peer", "name", E.IF_B,
                        "netns", E.NS_B)),
               ("cmd", ["ip", "netns", "add", E.NS_A]),
               ("spawn", "client", c18), ("spawn", "client", other_ip), ("spawn", "server", srv_a),
               ("spawn", "client", E.client_argv(0, E.LADDER_PPS[2])), ("spawn", "contender", C.contender_argv(OUT)),
               ("spawn", "calibration", C.calibration_argv(OUT)), ("spawn", "x", ["true"]), ("exec", "rps"),
               ("kill", 1), ("kill", True)]
        for op in bad:
            with self.subTest(op=op), self.assertRaises((E.R2ERefused, ValueError)):
                E.check_op(op, s3, 1000, pps)

    def test_clients_only_with_traffic_and_never_on_cpu18(self):
        for kind in ("E0", "N1"):
            with self.assertRaises(E.R2ERefused):
                E.check_op(("spawn", "client", E.client_argv(0, E.LADDER_PPS[3])), E.EXPERIMENTS[kind], 1000, None)
        self.assertNotIn(18, E.TRAFFIC_CPUS)
        for i in (0, 1):
            a = E.client_argv(i, E.LADDER_PPS[0])
            self.assertEqual(a[opt(a, "-A")], str(E.SENDER_CPUS[i]))
            self.assertEqual(a[opt(a, "-c")], E.IP_B)
            self.assertEqual(a[opt(a, "-B")], E.IP_A)
            self.assertEqual(a[a.index("exec") + 1], E.NS_A)
            s = E.server_argv(i)
            self.assertEqual((s[opt(s, "-A")], s[opt(s, "-B")], s[s.index("exec") + 1]), ("23", E.IP_B, E.NS_B))
        with self.assertRaises(E.R2ERefused):
            E.client_argv(0, 12345)
        with self.assertRaises(E.R2ERefused):
            E.client_argv(2, E.LADDER_PPS[0])

    def test_inner_layers_hold_even_if_an_allowlist_were_wrong(self):
        """Defence in depth: forbidden tokens and protected interfaces are refused independently of the allowlists;
        clients need traffic even with a rate; a traffic spawn must keep the one-pid exec chain."""
        s2, pps = E.EXPERIMENTS["S2"], E.LADDER_PPS[3]
        for cmd in (("tc", "qdisc", "show"), ("sysctl", "-w", "x=1"), ("ethtool", "-K", E.IF_B, "gro", "on"),
                    ("modprobe", "pktgen"), ("ip", "netns", "exec", E.NS_B, "cat", "cpu.max")):
            with mock.patch.object(E, "allowed_cmds", lambda exp, cmd=cmd: {cmd}), self.assertRaises(E.R2ERefused):
                E.check_op(("cmd", cmd), s2, 1000, pps)
        for w in (("/sys/class/net/enp0s31f6/queues/rx-0/rps_cpus", "0"), ("/sys/class/net/docker0/mtu", "1500")):
            with mock.patch.object(E, "allowed_writes", lambda exp, w=w: {w}), self.assertRaises(E.R2ERefused):
                E.check_op(("write",) + w, s2, 1000, pps)
        for kind in ("E0", "N1"):
            with self.assertRaises(E.R2ERefused):
                E.check_spawn(("spawn", "client", E.client_argv(0, pps)), E.EXPERIMENTS[kind], 1000, pps)
        forked = E.server_argv(0)
        forked = forked[:len(E.TRAFFIC_JOIN)] + ["sh", "-c", "x"] + forked[len(E.TRAFFIC_JOIN):]
        self.assertFalse(E.traffic_structure(forked)["ok"])
        with mock.patch.object(E, "server_argv", lambda i: forked), self.assertRaises(E.R2ERefused):
            E.check_spawn(("spawn", "server", forked), s2, 1000, pps)

    def test_cgroup_plan_values(self):
        plan = {op[1]: op[2] for op in E.cgroup_plan(E.EXPERIMENTS["S2"]) if op[0] == "write"}
        self.assertEqual(plan[f"{E.TRAFFIC_DIR}/cpuset.cpus"], "20,22,23")
        self.assertEqual(plan[f"{E.TARGET_DIR}/cpuset.cpus"], "18")
        self.assertEqual(plan[f"{E.CONTENDER_DIR}/cpuset.cpus"], "18")
        self.assertEqual(plan[f"{E.LAB_DIR}/cpuset.cpus"], "18,20,22,23")
        self.assertFalse([k for k in plan if k.endswith("cpu.max")])
        for v in ("18,20,22,23", "18-23", "19"):
            with self.assertRaises(E.R2ERefused):
                E.check_op(("write", f"{E.TRAFFIC_DIR}/cpuset.cpus", v), E.EXPERIMENTS["S2"], 1000, E.LADDER_PPS[3])

    def test_outputs_under_r2e_results_only(self):
        e0 = E.EXPERIMENTS["E0"]
        for path in ("/tmp/x.json", str(C.REPO / "results" / "phase1c_r2c" / "x.json"),
                     str(E.REPO / "results" / "phase1c_r2e" / ".." / "x.json")):
            with self.assertRaises(E.R2ERefused):
                E.check_op(("spawn", "target", C.target_argv(1000, path)), e0, 1000)

    def test_rps_is_never_an_ordinary_operation(self):
        for op in (("rps", "40000"), ("write", E.RPS_REL, "40000"), ("cmd", tuple(E.rps_argv("write", 5, "40000")))):
            with self.assertRaises((E.R2ERefused, ValueError)):
                E.check_op(op, E.EXPERIMENTS["S2"], 1000, E.LADDER_PPS[3])

    def test_rps_helper_argv_guard(self):
        E.check_rps_argv(E.rps_argv("read", 4026531840))
        for v in E.RPS_VALUES:
            E.check_rps_argv(E.rps_argv("write", 4026531840, v))
        bad = [E.RPS_PREFIX + ["write", "1", "ff"], E.RPS_PREFIX + ["write", "1", "c0000"],
               E.RPS_PREFIX + ["write", "1"], E.RPS_PREFIX + ["read", "1", "0"], E.RPS_PREFIX + ["erase", "1"],
               E.RPS_PREFIX + ["read", "x1"], E.RPS_PREFIX + ["read", "0"],
               ["ip", "netns", "exec", E.NS_A] + E.RPS_PREFIX[4:] + ["write", "1", "40000"],
               E.RPS_PREFIX[:-1] + [E.RPS_HELPER.replace("rx-0", "rx-1"), "write", "1", "0"],
               E.RPS_PREFIX[:-1] + [E.RPS_HELPER.replace(E.IF_B, "enp0s31f6"), "write", "1", "0"],
               ["sh", "-c", "echo 40000 > /sys/class/net/sentlab-b0/queues/rx-0/rps_cpus"], ("tuple",)]
        for argv in bad:
            with self.subTest(argv=argv[-3:]), self.assertRaises(E.R2ERefused):
                E.check_rps_argv(argv)


class TestRpsHelper(unittest.TestCase):
    """The helper runs inside sentinel-lab-b; here it runs against a sandbox copy of its paths (no sysfs is touched)."""

    def sandbox(self, extra_iface=False, extra_queue=False, symlink_sub=False):
        """A temporary tree mirroring the helper's paths (rps_cpus starts empty: a regular file is not truncated by
        the helper's single write, sysfs replaces the whole value)."""
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        nsfile = d / "ns_net"
        nsfile.write_text("")
        real = d / "sys/devices/virtual/net" / E.IF_B / "queues"
        (real / "rx-0").mkdir(parents=True)
        (real / "tx-0").mkdir()
        if extra_queue:
            (real / "rx-1").mkdir()
        (real / "rx-0" / "rps_cpus").write_text("")
        cls = d / "sys/class/net"
        cls.mkdir(parents=True)
        (cls / "lo").mkdir()
        os.symlink(d / "sys/devices/virtual/net" / E.IF_B, cls / E.IF_B)
        if extra_iface:
            (cls / "enp0s31f6").mkdir()
        if symlink_sub:
            elsewhere = d / "elsewhere"
            elsewhere.write_text("000000\n")
            (real / "rx-0" / "rps_cpus").unlink()
            os.symlink(elsewhere, real / "rx-0" / "rps_cpus")
        code = E.RPS_HELPER.replace("/proc/self/ns/net", str(nsfile)).replace("'/sys/", f"'{d}/sys/")
        return d, code, os.stat(nsfile).st_ino

    def run_helper(self, code, *args):
        return subprocess.run([sys.executable, "-I", "-c", code, *map(str, args)], capture_output=True, text=True)

    def test_read_write_in_sandbox(self):
        d, code, ino = self.sandbox()
        self.assertEqual(self.run_helper(code, "read", ino).returncode, 0)
        self.assertEqual(self.run_helper(code, "write", ino, "40000").returncode, 0)
        self.assertEqual(self.run_helper(code, "read", ino).stdout.strip(), "40000")
        self.assertEqual((d / "sys/devices/virtual/net" / E.IF_B / "queues/rx-0/rps_cpus").read_text(), "40000")

    def test_namespace_mismatch(self):
        _, code, ino = self.sandbox()
        self.assertEqual(self.run_helper(code, "read", ino + 1).returncode, 3)

    def test_unexpected_device(self):
        _, code, ino = self.sandbox(extra_iface=True)
        self.assertEqual(self.run_helper(code, "write", ino, "40000").returncode, 4)

    def test_symlink_substitution(self):
        d, code, ino = self.sandbox(symlink_sub=True)
        self.assertEqual(self.run_helper(code, "write", ino, "40000").returncode, 5)
        self.assertEqual((d / "elsewhere").read_text(), "000000\n")

    def test_unexpected_queue(self):
        _, code, ino = self.sandbox(extra_queue=True)
        self.assertEqual(self.run_helper(code, "write", ino, "40000").returncode, 6)

    def test_unexpected_value_and_mode(self):
        d, code, ino = self.sandbox()
        for v in ("ff", "c0000", "40000 "):
            self.assertEqual(self.run_helper(code, "write", ino, v).returncode, 7)
        self.assertEqual(self.run_helper(code, "erase", ino).returncode, 8)
        self.assertEqual((d / "sys/devices/virtual/net" / E.IF_B / "queues/rx-0/rps_cpus").read_text(), "")

    def test_real_helper_refuses_host_namespace(self):
        """The unmodified helper in the host netns: wrong inode -> 3; right inode -> refuses the host's devices (4).
        Both exit before any write (read mode)."""
        me = os.stat("/proc/self/ns/net").st_ino
        self.assertEqual(self.run_helper(E.RPS_HELPER, "read", me + 1).returncode, 3)
        self.assertEqual(self.run_helper(E.RPS_HELPER, "read", me).returncode, 4)


# ------------------------------------------------------------------------------------------ RPS write path
class FakeRps:
    def __init__(self, value="000000", write_rc=0, readback=None, read_rc=0):
        self.value, self.write_rc, self.readback, self.read_rc, self.calls, self.log = \
            value, write_rc, readback, read_rc, [], []

    def run(self, mode, value):
        self.calls.append((mode, value))
        if mode == "read":
            return self.read_rc, self.value + "\n"
        if self.write_rc:
            return self.write_rc, ""
        self.value = self.readback or E.RPS_READBACK[value]
        return 0, ""

    def logf(self, **kw):
        self.log.append(kw)


class TestRpsWrite(unittest.TestCase):
    def test_success_logged(self):
        f = FakeRps()
        rec = E.rps_write("40000", "000000", f.run, f.logf)
        self.assertEqual((rec["prev"], rec["post"]), ("000000", "040000"))
        self.assertEqual([c[0] for c in f.calls], ["read", "write", "read"])
        self.assertEqual([e["phase"] for e in f.log], ["intent", "result"])
        self.assertTrue(f.log[1]["ok"])

    def test_read_before_mismatch_never_writes(self):
        f = FakeRps(value="040000")
        with self.assertRaises(E.RpsAbort):
            E.rps_write("40000", "000000", f.run, f.logf)
        self.assertNotIn("write", [c[0] for c in f.calls])
        self.assertEqual(f.log[0]["phase"], "refused")

    def test_read_after_mismatch(self):
        f = FakeRps(readback="0c0000")
        with self.assertRaises(E.RpsAbort):
            E.rps_write("40000", "000000", f.run, f.logf)
        self.assertFalse(f.log[-1]["ok"])

    def test_write_failure(self):
        f = FakeRps(write_rc=1)
        with self.assertRaises(E.RpsAbort):
            E.rps_write("80000", "000000", f.run, f.logf)
        self.assertEqual(f.log[-1]["ok"], False)

    def test_unapproved_value_refused_before_any_read(self):
        for v in ("ff", "40000\n", "c0000", 40000, None):
            f = FakeRps()
            with self.assertRaises(E.R2ERefused):
                E.rps_write(v, "000000", f.run, f.logf)
            self.assertEqual(f.calls, [])

    def test_malformed_or_failed_read(self):
        for f in (FakeRps(value="40000"), FakeRps(value="xyzxyz"), FakeRps(read_rc=4)):
            with self.assertRaises(E.RpsAbort):
                E.rps_read(f.run)

    def test_restore(self):
        f = FakeRps(value="000000")
        self.assertTrue(E.rps_restore(f.run, f.logf)["noop"])
        for v in ("040000", "080000"):
            f = FakeRps(value=v)
            r = E.rps_restore(f.run, f.logf)
            self.assertEqual((r["ok"], r["restored"], f.value), (True, True, "000000"))

    def test_restore_anomaly_reported_not_silent(self):
        f = FakeRps(value="0c0000")
        r = E.rps_restore(f.run, f.logf)
        self.assertEqual((r["ok"], r["restored"], f.value), (False, True, "000000"))
        self.assertIn("not written by an approved operation", r["anomaly"])

    def test_restore_failure_raises(self):
        f = FakeRps(value="040000", write_rc=1)
        with self.assertRaises(E.RpsAbort):
            E.rps_restore(f.run, f.logf)

    def test_host_rps_uses_lab_b_inode_and_exact_helper(self):
        h = E.Host(E.EXPERIMENTS["S2"], os.devnull, 1000, E.LADDER_PPS[3], sysr=SimpleNamespace(
            netns_inode=lambda ns: 4026532999 if ns == E.NS_B else None))
        seen = []

        def fake_run(argv, **kw):
            seen.append(argv)
            return SimpleNamespace(returncode=0, stdout="000000\n" if argv[-2] == "read" or argv[-1] == "read"
                                   else "")
        with mock.patch.object(E.subprocess, "run", fake_run), mock.patch.object(E.Host, "_log", lambda s, **k: None):
            self.assertEqual(h.rps_read(), "000000")
        self.assertEqual(seen[0], E.RPS_PREFIX + ["read", "4026532999"])
        h2 = E.Host(E.EXPERIMENTS["S2"], os.devnull, sysr=SimpleNamespace(netns_inode=lambda ns: None))
        with self.assertRaises(E.RpsAbort):
            h2.rps_read()

    def test_rps_values_and_bits(self):
        self.assertEqual(E.RPS_VALUES, {"40000": 18, "80000": 19, "0": None})
        self.assertEqual(int(E.RPS_READBACK["40000"], 16), 1 << 18)
        self.assertEqual(int(E.RPS_READBACK["80000"], 16), 1 << 19)
        self.assertEqual(E.RPS_REL, "/sys/class/net/sentlab-b0/queues/rx-0/rps_cpus")


# ------------------------------------------------------------------------------------------ cleanup
class TestCleanup(unittest.TestCase):
    def test_every_failure_point_crash_and_cleanup_failure(self):
        r = E.simulation_cases()
        self.assertTrue(r["ok"], r["failures"])
        self.assertGreater(r["cases"], 600)
        self.assertEqual(r["safe_aborts"], 7)          # RPS restoration failure, one per lab experiment

    def test_normal_exit_resets_rps_before_namespace_deletion(self):
        for kind in ("E0", "S2", "N1", "N2", "LADDER"):
            exp = E.EXPERIMENTS[kind]
            r = E.simulate(exp)
            self.assertTrue(r["ok"] and r["host_clean"] and r["rps_reset_before_netns_del"] and not r["leaked"], kind)

    def run_until(self, exp, k):
        sim = E.SimHost(exp, pps=E.LADDER_PPS[3] if exp.traffic else None)
        for op in E.setup_plan(exp):
            sim.apply(op)
        sim.rps_write(exp.rps, E.RPS_ZERO)
        sim.apply(("spawn", "target", C.target_argv(1000, OUT)))
        for i in range(k):
            sim.apply(("spawn", "server", E.server_argv(i)))
        return sim

    def test_wrapper_sigkill_path_cleans_from_op_log(self):
        """The driver is SIGKILLed after the RPS write: the wrapper trap cleans from the op log alone."""
        exp = E.EXPERIMENTS["S2"]
        sim = self.run_until(exp, 2)
        res = E.cleanup(sim, sim, list(sim.entries), wait_s=0.0, sleep=lambda s: None)
        self.assertTrue(res["ok"], res)
        self.assertFalse(sim.netns or sim.dirs or sim.alive or sim.leaked)
        order = [e for e in sim.events[1:] if e[0] in ("rps", "netns del", "cgroup.kill")]   # after the setup write
        self.assertEqual(order[0], ("cgroup.kill", E.TRAFFIC_DIR))          # traffic leaf first
        self.assertEqual(order[1], ("rps", "0"))
        self.assertLess(sim.events.index(("rps", "0")), sim.events.index(("netns del", E.NS_A)))

    def test_restoration_failure_keeps_namespaces_and_is_unsafe(self):
        exp = E.EXPERIMENTS["S2"]
        sim = self.run_until(exp, 1)
        sim.fail_rps = "restore"
        res = E.cleanup(sim, sim, list(sim.entries), wait_s=0.0, sleep=lambda s: None)
        self.assertFalse(res["ok"])
        self.assertTrue(res["unsafe_incomplete"])
        self.assertIn(E.NS_B, sim.netns)
        self.assertFalse(sim.leaked)
        self.assertTrue(any("NOT deleted" in e for e in res["errors"]))
        self.assertFalse(res["verify"]["checks"]["no_lab_netns"])
        self.assertFalse(res["verify"]["checks"]["rps_restored"])
        gr = E.restore_record(sim.entries, res, {"ok": True})
        self.assertFalse(gr["ok"])
        self.assertTrue(gr["unsafe_incomplete"])

    def test_lab_b_gone_without_verified_reset_is_unsafe(self):
        exp = E.EXPERIMENTS["S2"]
        sim = self.run_until(exp, 0)
        sim.netns.discard(E.NS_B)                                            # deleted outside the tooling
        res = E.cleanup(sim, sim, list(sim.entries), wait_s=0.0, sleep=lambda s: None)
        self.assertFalse(res["ok"])
        self.assertTrue(res["unsafe_incomplete"])

    def test_never_written_unreadable_rps_is_not_unsafe(self):
        exp = E.EXPERIMENTS["S2"]
        sim = E.SimHost(exp)
        for op in E.setup_plan(exp)[:-7]:                                    # namespaces exist, veth never created
            sim.apply(op)
        res = E.cleanup(sim, sim, list(sim.entries), wait_s=0.0, sleep=lambda s: None)
        self.assertTrue(res["ok"], res)
        self.assertFalse(res["unsafe_incomplete"])
        self.assertFalse(sim.netns)

    def test_verified_zero_must_follow_the_last_write(self):
        w = {"phase": "intent", "op": ["rps", E.RPS_REL], "value": "40000"}
        z = {"phase": "result", "op": ["rps", E.RPS_REL], "value": "0", "post": "000000"}
        self.assertTrue(E.oplog_state([w, z])["rps_verified_zero_after_last_write"])
        self.assertFalse(E.oplog_state([w, z, dict(w, value="80000")])["rps_verified_zero_after_last_write"])
        self.assertFalse(E.oplog_state([z, w])["rps_verified_zero_after_last_write"])

    def test_restore_record(self):
        w = {"phase": "intent", "op": ["rps", E.RPS_REL], "value": "40000"}
        z = {"phase": "result", "op": ["rps", E.RPS_REL], "value": "0", "post": "000000"}
        d = {"phase": "intent", "op": ["cmd", ["ip", "netns", "del", E.NS_B]]}
        ok = {"ok": True}
        self.assertTrue(E.restore_record([w, z, d], ok, ok)["ok"])
        self.assertTrue(E.restore_record([d], ok, ok)["ok"])                  # no RPS written (calibration)
        r = E.restore_record([w, d, z], ok, ok)
        self.assertFalse(r["checks"]["rps_reset_before_netns_deletion"])
        self.assertTrue(r["unsafe_incomplete"])
        r = E.restore_record([w, d], ok, ok)
        self.assertFalse(r["checks"]["rps_restored"])
        r = E.restore_record([z, w, d], ok, ok)                               # zero before the write does not count
        self.assertFalse(r["checks"]["rps_restored"])
        self.assertFalse(E.restore_record([w, z, d], {"ok": False}, ok)["ok"])
        self.assertFalse(E.restore_record([w, z, d], ok, {"ok": False})["ok"])

    def test_driver_and_wrapper_failure_paths(self):
        lines = code_lines(DRIVER)
        i_sig = next(i for i, l in enumerate(lines) if l.startswith("old = {s: signal.signal(s, on_signal)"))
        i_setup = next(i for i, l in enumerate(lines) if l.startswith("for op in E.setup_plan(exp):"))
        self.assertLess(i_sig, i_setup)                                     # SIGTERM/SIGINT -> finally -> cleanup
        self.assertIn("except (C.LabAbort, Interrupted, Exception) as exc:", DRIVER)   # workload/collector failure
        self.assertIn('R["cleanup"] = E.cleanup(host, sysr, C.read_oplog(oplog),\n'
                      '                                 after_rps=make_after_rps({"loader": loader}, sysr, base, R))',
                      DRIVER)
        self.assertIn("signal.signal(s, signal.SIG_IGN)", DRIVER)
        self.assertIn("C.wait_bpf_released(sysr, base)", DRIVER)             # BPF failure -> abort
        self.assertIn("bpf_objects_not_released", DRIVER)
        self.assertIn("UNSAFE/INCOMPLETE CLEANUP", DRIVER)
        self.assertIn('if R["unsafe_incomplete"]:', DRIVER)
        self.assertIn('R["unsafe_incomplete"] = R["GR"]["unsafe_incomplete"] or R["cleanup"]["unsafe_incomplete"]', DRIVER)
        self.assertIn("trap finish EXIT", WRAPPER)
        self.assertIn("trap 'finish; exit 130' INT TERM", WRAPPER)            # wrapper interruption
        self.assertIn('"$PY" "$R2E" cleanup "$OUT"', WRAPPER)
        self.assertIn("timeout 300", WRAPPER)                                # hard timeout of every driver run
        self.assertIn("no further run may start", WRAPPER)

    def test_cleanup_order_in_module(self):
        src = MODULE[MODULE.index("def cleanup(host"):MODULE.index("def cleanup_state")]
        i_traffic = src.index("traffic cgroup.kill")
        i_rps = src.index("host.rps_restore()")
        i_loader = src.index("stop eBPF loader")
        i_cg = src.index('("write", f"{LAB_DIR}/cgroup.kill", "1")')
        i_ns = src.index("host.apply(netns_del(ns))")
        self.assertLess(i_traffic, i_rps)
        self.assertLess(i_rps, i_loader)
        self.assertLess(i_loader, i_cg)
        self.assertLess(i_cg, i_ns)
        self.assertIn('if rps_rec.get("restored"):', src)


class OrderSim(E.SimHost):
    """SimHost that also records cgroup removals, so the full cleanup sequence is observable as events."""

    def _do(self, op):
        res = super()._do(op)
        if op[0] == "rmdir":
            self.events.append(("rmdir", op[1]))
        return res


class FakeLoader:
    def __init__(self, events, fail=False):
        self.events, self.fail, self.raw = events, fail, []

    def close(self):
        self.events.append(("loader close",))
        if self.fail:
            raise OSError("loader close failed")


def driver_module():
    import importlib
    return importlib.import_module("r2e_driver")


class TestBpfReleaseOrder(unittest.TestCase):
    """Approved order: traffic kill -> RPS 0 (read back) -> loader close -> BPF release wait -> cgroup removal ->
    namespace/veth deletion. Exercised with the driver's real after-RPS callback and the module's real cleanup."""

    def scenario(self, kind="S2", fail_at=None, crash_after=None, fail_rps=None, fail_cleanup_at=None,
                 loader=True, loader_fails=False, released=True, wait_raises=False):
        D = driver_module()
        exp = E.EXPERIMENTS[kind]
        pps = E.LADDER_PPS[3] if exp.traffic else None
        sim = OrderSim(exp, pps=pps, fail_at=fail_at, fail_rps=fail_rps)
        steps = [("op", op) for op in E.setup_plan(exp)] + [("rps", exp.rps)] + \
            [("op", ("spawn", "target", C.target_argv(1000, OUT)))] + \
            [("op", ("spawn", "server", E.server_argv(i))) for i in (0, 1)] + \
            ([("op", ("spawn", "contender", C.contender_argv(OUT)))] if exp.contender else []) + \
            ([("op", ("spawn", "client", E.client_argv(i, pps))) for i in (0, 1)] if exp.traffic else [])
        try:
            for k, (kind_, x) in enumerate(steps):
                if crash_after is not None and k >= crash_after:
                    break
                sim.rps_write(x, E.RPS_ZERO) if kind_ == "rps" else sim.apply(x)
        except (OSError, E.RpsAbort):
            pass
        sim.fail_at = None if fail_cleanup_at is None else sim.n + fail_cleanup_at

        def fake_wait(sysr, base, **kw):
            sim.events.append(("bpf wait",))
            if wait_raises:
                raise RuntimeError("bpftool unreadable")
            return {"released": released, "timed_out": not released, "remaining": {}}
        R = {}
        state = {"loader": FakeLoader(sim.events, loader_fails) if loader else None}
        with mock.patch.object(D.C, "wait_bpf_released", fake_wait):
            res = E.cleanup(sim, sim, list(sim.entries), wait_s=0.0, sleep=lambda s: None,
                            after_rps=D.make_after_rps(state, sim, {}, R))
        return sim, res, R

    def assert_order(self, sim, loader=True):
        ev = sim.events
        idx = lambda pred: [k for k, e in enumerate(ev) if pred(e)]
        wait = idx(lambda e: e == ("bpf wait",))
        self.assertEqual(len(wait), 1, ev)
        w = wait[0]
        if loader:
            self.assertEqual(idx(lambda e: e == ("loader close",)), [w - 1], ev)          # immediately before
        removal = idx(lambda e: e[0] == "rmdir" or e == ("cgroup.kill", E.LAB_DIR))
        dels = idx(lambda e: e[0] == "netns del")
        self.assertTrue(all(w < k for k in removal), ev)                               # before cgroup removal
        self.assertTrue(all(w < k for k in dels), ev)                                  # before namespace deletion
        self.assertTrue(all(r < d for r in idx(lambda e: e[0] == "rmdir") for d in dels), ev)
        zero = idx(lambda e: e == ("rps", "0"))
        if zero:
            self.assertLess(max(zero), w - (1 if loader else 0), ev)                   # RPS reset before the loader
        traffic = idx(lambda e: e == ("cgroup.kill", E.TRAFFIC_DIR))
        self.assertTrue(all(t < w for t in traffic), ev)
        return w

    def test_normal_cleanup_exact_sequence(self):
        sim, res, R = self.scenario()
        self.assertTrue(res["ok"], res)
        names = [e[0] if e[0] != "rmdir" else "rmdir" for e in sim.events[1:]]
        seq = []
        for n in names:
            if not seq or seq[-1] != n:
                seq.append(n)
        self.assertEqual(seq, ["cgroup.kill", "rps", "loader close", "bpf wait", "cgroup.kill", "rmdir", "netns del"])
        self.assertEqual(sim.events[1], ("cgroup.kill", E.TRAFFIC_DIR))
        self.assertEqual(sim.events[2], ("rps", "0"))
        self.assertEqual(sim.events[5], ("cgroup.kill", E.LAB_DIR))
        self.assert_order(sim)
        self.assertTrue(R["bpf_release"]["released"])

    def test_every_experiment(self):
        for kind in ("E0", "S1", "S2", "S3", "N1", "N2"):
            sim, res, R = self.scenario(kind)
            self.assertTrue(res["ok"], (kind, res))
            self.assert_order(sim)

    def test_workload_failure(self):
        n_setup = len(E.setup_plan(E.EXPERIMENTS["S2"]))
        for f in (n_setup + 2, n_setup + 3, n_setup + 4):                 # target / server spawn fails
            sim, res, R = self.scenario(fail_at=f)
            self.assert_order(sim)
            self.assertIn("bpf_release", R)

    def test_collector_failure_timeout_and_sigterm(self):
        """The driver unwinds (collector exception, hard timeout, SIGTERM -> Interrupted) at any point: the finally
        cleanup sees only the op log; the wait still precedes every removal."""
        n = len(E.setup_plan(E.EXPERIMENTS["S2"])) + 6
        for k in range(1, n + 1):
            sim, res, R = self.scenario(crash_after=k)
            self.assert_order(sim)
            self.assertIn("bpf_release", R)

    def test_loader_absent_or_failing(self):
        sim, res, R = self.scenario(loader=False)                          # failure before the loader started
        self.assert_order(sim, loader=False)
        sim, res, R = self.scenario(loader_fails=True)                     # close raises: the wait still runs
        self.assert_order(sim)
        self.assertFalse(res["ok"])
        self.assertTrue(any("stop eBPF loader" in e for e in res["errors"]))
        self.assertIn("bpf_release", R)

    def test_cleanup_failure(self):
        for c in range(1, 12):
            sim, res, R = self.scenario(fail_cleanup_at=c)
            self.assert_order(sim)

    def test_rps_restoration_failure(self):
        sim, res, R = self.scenario(fail_rps="restore")
        self.assert_order(sim)
        self.assertTrue(res["unsafe_incomplete"])
        self.assertIn(E.NS_B, sim.netns)                                   # kept for manual cleanup
        self.assertFalse([e for e in sim.events if e[0] == "netns del"])

    def test_unconfirmed_release_is_recorded_not_assumed(self):
        sim, res, R = self.scenario(released=False)
        self.assert_order(sim)
        self.assertFalse(R["bpf_release"]["released"])
        sim, res, R = self.scenario(wait_raises=True)                      # the wait itself fails
        self.assert_order(sim)
        self.assertNotIn("bpf_release", R)
        self.assertFalse(res["ok"])
        lines = code_lines(DRIVER)
        self.assertIn('R.setdefault("bpf_release", {"released": False, "timed_out": False,          # the wait did not '
                      'complete', lines)
        self.assertIn("ABORT: BPF objects not released", DRIVER)

    def test_driver_waits_only_inside_the_callback(self):
        self.assertEqual(DRIVER.count("C.wait_bpf_released("), 1)
        cb = DRIVER[DRIVER.index("def make_after_rps"):DRIVER.index("def clause_items")]
        self.assertIn("C.wait_bpf_released(sysr, base)", cb)
        self.assertLess(cb.index("loader.close()"), cb.index("C.wait_bpf_released"))
        self.assertIn("finally:", cb)
        fin = DRIVER[DRIVER.index("    finally:\n        for s in old:"):]
        self.assertIn("after_rps=make_after_rps(", fin)
        self.assertLess(fin.index("E.cleanup("), fin.index('if R["bpf_release"]["released"]:'))
        self.assertLess(fin.index('if R["bpf_release"]["released"]:'), fin.index("E.host_snapshot(sysr)"))


class FakeClock:
    def __init__(self):
        self.now, self.sleeps = 0.0, []

    def clock(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now = round(self.now + s, 6)


def settle_run(seq, events=None):
    """settle_lab over a scripted inspection sequence (the last one repeats) on a fake clock."""
    fc, it = FakeClock(), iter(seq)
    last = {"raw": seq[-1]}
    log = events if events is not None else []

    def read():
        last["raw"] = next(it, last["raw"])
        log.append(("read", len(attempts)))
        return last["raw"]

    def persist():
        log.append(("persist", len(attempts), "checks" in attempts[-1]))
    attempts = []
    with mock.patch.object(E, "lab_checks", side_effect=lambda raw, f=E.lab_checks: (log.append(("evaluate",
                                                                                                 len(attempts))),
                                                                                     f(raw))[1]):
        r = E.settle_lab(read, attempts, persist, clock=fc.clock, sleep=fc.sleep, wall=lambda: 1.5)
    return r, attempts, fc, log


GOOD = E._sim_lab_raw()


class TestLabSettle(unittest.TestCase):
    """The lab-setup fix: bounded read-only settle (0.1 s, 3 s) with every raw inspection persisted before it is
    evaluated; the lab checks themselves are unchanged."""

    def test_A_immediate_success(self):
        r, att, fc, _ = settle_run([GOOD])
        self.assertTrue(r["settled"])
        self.assertEqual((r["n_attempts"], r["settled_attempt"], len(att), fc.sleeps), (1, 0, 1, []))
        self.assertTrue(att[0]["ok"])

    def test_B_one_transient_failure(self):
        r, att, fc, _ = settle_run([E._sim_lab_raw("LOWERLAYERDOWN"), GOOD])
        self.assertTrue(r["settled"])
        self.assertEqual((r["n_attempts"], r["settled_attempt"]), (2, 1))
        self.assertEqual([a["ok"] for a in att], [False, True])
        self.assertEqual(att[0]["failures"], ["b_veth"])
        self.assertEqual(att[0]["parsed"]["b"]["links"][E.IF_B]["up"], False)
        self.assertIn('"operstate": "LOWERLAYERDOWN"', att[0]["raw"]["b_links"])        # the raw kernel report kept

    def test_C_multiple_transient_failures(self):
        seq = [E._sim_lab_raw("DOWN")] * 4 + [E._sim_lab_raw("LOWERLAYERDOWN")] * 7 + [GOOD]
        r, att, fc, _ = settle_run(seq)
        self.assertTrue(r["settled"])
        self.assertEqual(len(att), 12)
        self.assertEqual([a["attempt"] for a in att], list(range(12)))
        self.assertEqual([a["ok"] for a in att], [False] * 11 + [True])
        self.assertEqual([a["raw"] for a in att], seq)                                    # nothing overwritten
        self.assertAlmostEqual(r["elapsed_s"], 1.1, places=6)

    def test_D_persistent_failure_aborts_with_every_observation(self):
        r, att, fc, _ = settle_run([E._sim_lab_raw("DOWN")])
        self.assertFalse(r["settled"])
        self.assertIsNone(r["settled_attempt"])
        self.assertEqual(len(att), 31)                                                     # t = 0.0, 0.1, ..., 3.0
        self.assertTrue(all(not a["ok"] and a["failures"] == ["b_veth"] for a in att))
        self.assertIn("lab not settled within 3.0 s", r["final_reason"])
        self.assertAlmostEqual(r["elapsed_s"], 3.0, places=6)

    def test_E_invalid_states_never_become_valid(self):
        for raw, fail in ((E._sim_lab_raw("DOWN"), "b_veth"), (E._sim_lab_raw("LOWERLAYERDOWN"), "b_veth"),
                          (E._sim_lab_raw(b_kind="dummy"), "b_veth"), (E._sim_lab_raw(q=24), "b_single_queue"),
                          (E._sim_lab_raw(extra=True), "b_only_lo_and_veth"),
                          (E._sim_lab_raw("UNKNOWN", b_flags=()), "b_veth"),
                          (E._sim_lab_raw(malformed=True), "b_observable")):
            r, att, _, _ = settle_run([raw])
            self.assertFalse(r["settled"], fail)
            self.assertIn(fail, att[-1]["failures"])
        self.assertEqual(E.lab_failures({}), ["unobservable"])
        self.assertEqual(E.lab_failures({"a_veth": None}), ["a_veth"])                    # missing is a failure
        self.assertTrue(E.links(E._sim_lab_raw("UNKNOWN")["b_links"])[E.IF_B]["up"])     # predicate unchanged
        for oper in ("DOWN", "LOWERLAYERDOWN", "DORMANT", "NOTPRESENT", "TESTING"):
            self.assertFalse(E.links(E._sim_lab_raw(oper)["b_links"])[E.IF_B]["up"], oper)

    def test_F_timing_bound(self):
        self.assertEqual((E.LAB_SETTLE_POLL_S, E.LAB_SETTLE_MAX_S), (0.1, 3.0))
        r, att, fc, _ = settle_run([E._sim_lab_raw("DOWN")])
        self.assertEqual(set(fc.sleeps), {0.1})
        self.assertEqual(len(fc.sleeps), 30)
        self.assertEqual([round(a["mono"], 6) for a in att], [round(0.1 * k, 6) for k in range(31)])
        r, att, fc, _ = settle_run([E._sim_lab_raw("DOWN")] * 30 + [GOOD])                  # passes at exactly 3.0 s
        self.assertTrue(r["settled"])

    def test_G_read_persist_evaluate_order(self):
        events = []
        settle_run([E._sim_lab_raw("DOWN"), GOOD], events)
        self.assertEqual(events, [("read", 0), ("persist", 1, False), ("evaluate", 1), ("persist", 1, True),
                                  ("read", 1), ("persist", 2, False), ("evaluate", 2), ("persist", 2, True)])

    def test_H_final_successful_observation_persisted(self):
        r, att, _, log = settle_run([E._sim_lab_raw("DOWN")] * 3 + [GOOD])
        self.assertEqual(att[-1]["raw"], GOOD)
        self.assertTrue(att[-1]["ok"])
        self.assertEqual(log[-1], ("persist", 4, True))

    def test_replay_answers_each_attempt(self):
        r, att, _, _ = settle_run([E._sim_lab_raw("DOWN"), E._sim_lab_raw("LOWERLAYERDOWN"), GOOD])
        setup = {"settle": {"attempts": json.loads(json.dumps(att)), **r}}
        rp = E.replay_lab_settle(setup)
        self.assertTrue(rp["replayable"] and rp["identical"])
        self.assertEqual(rp["settled_attempt"], 2)
        self.assertEqual([x["failures"] for x in rp["attempts"]], [["b_veth"], ["b_veth"], []])
        setup["settle"]["attempts"][0]["raw"] = GOOD                                         # tampered observation
        self.assertFalse(E.replay_lab_settle(setup)["identical"])
        setup = {"settle": {"attempts": json.loads(json.dumps(att)), **r}}
        setup["settle"]["attempts"][1]["failures"] = ["b_single_queue"]                       # tampered verdict only
        self.assertFalse(E.replay_lab_settle(setup)["identical"])
        setup = {"settle": {"attempts": json.loads(json.dumps(att)), **r}}
        setup["settle"]["attempts"][0]["checks"]["a_veth"] = False                            # tampered check only
        self.assertFalse(E.replay_lab_settle(setup)["identical"])
        self.assertFalse(E.replay_lab_settle(None)["replayable"])                             # attempt 1: not saved

    def test_settle_simulation_in_dry_run(self):
        sim = E.settle_simulation()
        self.assertTrue(sim["ok"], sim)
        self.assertEqual(set(sim["cases"]), {"immediate_success", "transient_operstate", "eventual_success",
                                             "persistent_down", "malformed_inspection", "wrong_interface_type",
                                             "wrong_queue_count", "unexpected_device", "admin_down_flags"})

    def test_dry_run_requires_the_settle_simulation(self):
        src = MODULE[MODULE.index("def dry_run"):MODULE.index("def candidate")]
        self.assertIn('rep["lab_settle_simulation"] = settle_simulation()', src)
        ok_expr = src[src.index('rep["structural_ok"] = ('):src.index("return rep")]
        self.assertIn('rep["lab_settle_simulation"]["ok"]', ok_expr)

    def test_driver_uses_settle_and_saves_every_attempt(self):
        body = DRIVER[DRIVER.index("def lab_setup"):DRIVER.index("def ladder")]
        self.assertIn('E.settle_lab(lambda: E.lab_state(sysr), setup["settle"]["attempts"], save)', body)
        self.assertLess(body.index('R["lab_setup"] = setup'), body.index("E.settle_lab("))      # persisted container first
        self.assertLess(body.index("E.settle_lab("), body.index("raise C.LabAbort"))
        self.assertLess(body.index("raise C.LabAbort"), body.index("host.rps_write("))          # no RPS unless settled
        self.assertNotIn("E.lab_checks(", body)                                                 # no unsaved evaluation
        self.assertIn("lab_setup(sysr, host, exp, R, ev, save)", DRIVER)

    def test_driver_lab_setup_with_fakes(self):
        D = driver_module()
        seq = iter([E._sim_lab_raw("DOWN"), GOOD])
        fs = SimpleNamespace(run=lambda argv: "generic-receive-offload: off\n",
                             read=lambda p: "1000\n")
        host = SimpleNamespace(rps_write=lambda v, prev: {"value": v, "prev": prev, "post": E.RPS_READBACK[v]})
        R, saved = {}, []
        with mock.patch.object(E, "lab_state", lambda sysr: next(seq)):              # real 0.1 s settle sleep
            D.lab_setup(fs, host, E.EXPERIMENTS["S2"], R, lambda *a, **k: None,
                        lambda: saved.append(json.dumps(R["lab_setup"], sort_keys=True, default=str)))
        st = R["lab_setup"]["settle"]
        self.assertTrue(st["settled"])
        self.assertEqual(len(st["attempts"]), 2)
        self.assertIn('"operstate": "DOWN"', json.loads(saved[0])["settle"]["attempts"][0]["raw"]["b_links"])
        self.assertEqual(R["lab_setup"]["lab"], GOOD)
        self.assertEqual(R["lab_setup"]["rps_readback"], "040000")
        R2 = {}
        with mock.patch.object(E, "lab_state", lambda sysr: E._sim_lab_raw("DOWN")), \
                self.assertRaises(C.LabAbort):                                     # the real 3 s bound expires
            D.lab_setup(fs, SimpleNamespace(rps_write=lambda *a: self.fail("RPS written")), E.EXPERIMENTS["S2"],
                        R2, lambda *a, **k: None, lambda: None)
        self.assertFalse(R2["lab_setup"]["settle"]["settled"])
        self.assertGreater(len(R2["lab_setup"]["settle"]["attempts"]), 1)


# ------------------------------------------------------------------------------------------ ground truth
class TestGroundTruth(unittest.TestCase):
    def test_established_per_experiment(self):
        for label, key in (("S2-1", "softirq_overload"), ("S3-1", "softirq_overload"), ("S1-1", "softirq_sub_threshold"),
                           ("E0-open", "softirq_absent_on_target"), ("N1-1", "softirq_absent_on_target"),
                           ("N2-1", "softirq_absent_on_target"), ("E0-close", "softirq_absent_on_target")):
            G = gt(label)
            self.assertTrue(G["ok"], (label, E.ground_truth_aborts(G, E.experiment_of(label))))
            self.assertTrue(G["established"][key], label)
            self.assertEqual(E.ground_truth_aborts(G, E.experiment_of(label)), [], label)
        self.assertTrue(gt("N1-1")["established"]["contention_present"])

    def assert_pred(self, G, name, want):
        self.assertIs(G[name]["ok"], want, (name, G[name]))
        if want is not True:
            self.assertFalse(G["ok"])

    # GP
    def test_gp(self):
        self.assert_pred(gt(), "GP", True)

        def target_on_17(inp):
            inp["obs"][15]["tasks"][str(TPID)]["stat"] = stat_text(TPID, "python3", 0, 17)
        self.assert_pred(gt(edit=target_on_17), "GP", False)

        def client_on_18(inp):
            inp["obs"][15]["tasks"][str(C0)]["stat"] = stat_text(C0, "iperf3", 0, 18)
        self.assert_pred(gt(edit=client_on_18), "GP", False)

        def stray_pid(inp):
            inp["obs"][5]["leaves"]["traffic"]["cgroup.procs"] += "999\n"
        self.assert_pred(gt(edit=stray_pid), "GP", False)

        def parent_proc(inp):
            inp["obs"][3]["leaves"]["parent"]["cgroup.procs"] = "777\n"
        self.assert_pred(gt(edit=parent_proc), "GP", False)

        def traffic_cpuset(inp):
            inp["obs"][3]["leaves"]["traffic"]["cpuset.cpus.effective"] = "18,20,22-23\n"
        self.assert_pred(gt(edit=traffic_cpuset), "GP", False)

        def unreadable(inp):
            inp["obs"][3]["tasks"][str(TPID)]["stat"] = None
        self.assert_pred(gt(edit=unreadable), "GP", None)

        def contender_outside_w(inp):
            inp["obs"][3]["leaves"]["contender"]["cgroup.procs"] = f"{CPID}\n"
            inp["expected"][3]["contender"] = [CPID]
            inp["expected"][3]["cpu"][str(CPID)] = 18
            inp["obs"][3]["tasks"][str(CPID)] = {"stat": stat_text(CPID, "python3", 0, 18), "schedstat": "1 0 1\n"}
        self.assert_pred(gt("N1-1", edit=contender_outside_w), "GP", False)

    # GN
    def test_gn(self):
        self.assert_pred(gt(), "GN", True)

        def queues(inp):
            inp["obs"][7]["lab"]["b_links"] = links_json("b", E.IF_B, 0, 0, q=24)
        self.assert_pred(gt(edit=queues), "GN", False)

        def default_route(inp):
            inp["obs"][7]["lab"]["a_routes"] = json.dumps([{"dst": "default", "dev": E.IF_A},
                                                           {"dst": E.SUBNET, "dev": E.IF_A}])
        self.assert_pred(gt(edit=default_route), "GN", False)

        def extra_iface(inp):
            inp["obs"][7]["lab"]["a_links"] = links_json("a", E.IF_A, 0, 0, extra=[{"ifname": "tun0"}])
        self.assert_pred(gt(edit=extra_iface), "GN", False)

        def qdisc(inp):
            inp["obs"][7]["lab"]["a_links"] = links_json("a", E.IF_A, 0, 0, qdisc="netem")
        self.assert_pred(gt(edit=qdisc), "GN", False)

        def gro(inp):
            inp["setup"]["ethtool_b"] = "generic-receive-offload: on\n"
        self.assert_pred(gt(edit=gro), "GN", False)

        def gro_missing(inp):
            inp["setup"]["ethtool_b"] = None
        self.assert_pred(gt(edit=gro_missing), "GN", None)

        def remote(inp):
            inp["iperf"]["client0"] = iperf_json(remote="8.8.8.8")
        self.assert_pred(gt(edit=remote), "GN", False)

        def iperf_err(inp):
            inp["iperf"]["client1"] = iperf_json(error="unable to connect")
        self.assert_pred(gt(edit=iperf_err), "GN", False)

        def default_route6(inp):
            inp["obs"][7]["lab"]["b_routes6"] = json.dumps([{"dst": "default", "dev": E.IF_B}])
        self.assert_pred(gt(edit=default_route6), "GN", False)

        def unobservable(inp):
            inp["obs"][7]["lab"]["b_links"] = None
        self.assert_pred(gt(edit=unobservable), "GN", None)

    # GS / GV
    def test_gs(self):
        self.assert_pred(gt("S2-1", nw=0.45), "GS", False)                   # below SI_ABS_MIN
        self.assert_pred(gt("S2-1", nb=0.3), "GS", False)                    # no 3x rise over B
        self.assert_pred(gt("S1-1", nw=0.47), "GS", False)                   # S1 above SI_ABS_MIN - delta
        self.assert_pred(gt("S1-1", nw=0.001), "GS", False)                  # S1 not measurable
        self.assert_pred(gt("S1-1", delta=None), "GS", None)
        self.assert_pred(gt("E0-open", nw=0.2), "GS", False)                 # softirq rise in a control
        self.assert_pred(gt("N1-1", nw=0.2), "GS", False)
        self.assert_pred(gt("N2-1", n19=0.0001), "GS", False)                # N2 load not on 19
        self.assert_pred(gt("N2-1", nw=0.6), "GS", False)                    # N2 load on 18
        self.assert_pred(gt("S2-1", processed_ratio=0.5), "GS", False)       # not steered to 18
        self.assertIs(gt("S2-1", processed_ratio=0.9995)["GS"]["ok"], True)  # 800 short: within netdev_max_backlog
        self.assert_pred(gt("S2-1", processed_ratio=0.999), "GS", False)     # 1600 short: beyond it

        def eb_missing(inp):
            inp["obs"][I_W1]["ebpf_line"] = None
        self.assert_pred(gt(edit=eb_missing), "GS", None)

        def bound(inp):
            for k in range(I_W0 + 1, N_OBS):
                o = inp["obs"][k]
                lines = o["raw"]["stat"].splitlines()
                f = lines[19].split()
                f[4] = str(int(f[4]) + 95 * (min(k, I_W1) - I_W0))           # CPU 18 almost all idle in W
                lines[19] = " ".join(f)
                o["raw"]["stat"] = "\n".join(lines) + "\n"
        self.assert_pred(gt(edit=bound), "GS", False)

    def test_gv(self):
        self.assert_pred(gt("S2-1"), "GV", True)
        self.assert_pred(gt("S2-1", other18=0.8), "GV", False)               # NET_RX not dominant on 18
        self.assertFalse(gt("S1-1", nw=0.2, other18=0.3)["ok"])
        self.assertIs(gt("E0-open")["GV"]["applies"], False)

    # GI
    def test_gi(self):
        self.assert_pred(gt("S2-1"), "GI", True)
        self.assert_pred(gt("S2-1", rd_w=0.03), "GI", False)                 # rise < RDX_MIN
        self.assert_pred(gt("S2-1", psi_w=500), "GI", False)                 # PSI not above B

        def missing(inp):
            inp["obs"][I_W1]["tasks"][str(TPID)]["schedstat"] = None
        self.assert_pred(gt(edit=missing), "GI", None)
        self.assertTrue(gt("S1-1", rd_w=0.001)["ok"])                       # GI recorded, not required, in S1

    # G0
    def test_g0(self):
        self.assert_pred(gt(), "G0", True)

        def quota(inp):
            inp["obs"][9]["leaves"]["traffic"]["cpu.max"] = "50000 100000\n"
        self.assert_pred(gt(edit=quota), "G0", False)

        def throttled(inp):
            for o in inp["obs"][10:]:
                o["leaves"]["target"]["cpu.stat"] = o["leaves"]["target"]["cpu.stat"].replace("nr_throttled 0",
                                                                                               "nr_throttled 3")
        self.assert_pred(gt(edit=throttled), "G0", False)

        def unreadable(inp):
            inp["obs"][-1]["leaves"]["contender"]["cpu.stat"] = None
        self.assert_pred(gt(edit=unreadable), "G0", None)

    # G6'
    def test_g6p(self):
        G = gt("S3-1")
        self.assertIs(G["G6p"]["ok"], True)
        self.assertAlmostEqual(G["G6p"]["kthread18_cores_w"], 0.25, places=3)   # ksoftirqd/18 subtracted
        self.assert_pred(gt("S2-1", foreign=0.1), "G6p", False)              # foreign userspace on 18
        self.assertIs(gt("S2-1", foreign=0.04)["G6p"]["ok"], True)
        self.assertIs(gt("N1-1")["G6p"]["ok"], True)                         # contender subtracted in N1

        def no_rq(inp):
            inp["obs"][I_W1]["raw"]["schedstat"] = "version 14\n"
        self.assert_pred(gt(edit=no_rq), "G6p", None)

        def kthread_not_counted(inp):                                        # a userspace task named like a kthread
            for o in inp["obs"]:
                o["tasks"][str(KSOFT)]["stat"] = stat_text(KSOFT, "ksoftirqd/18", 0, 18)
        self.assert_pred(gt("S3-1", edit=kthread_not_counted), "G6p", False)

    # GL
    def test_gl(self):
        self.assert_pred(gt(), "GL", True)
        self.assert_pred(gt("S2-1", drop={3: 5}), "GL", False)               # softnet drop on another CPU
        self.assert_pred(gt("S2-1", drop={18: 5}, a_txd=5), "GL", False)     # S2: no drop allowed at all
        self.assert_pred(gt("S2-1", udp_err=2), "GL", False)
        self.assert_pred(gt("S2-1", lost=4), "GL", False)
        self.assert_pred(gt("S2-1", b_rxd=1), "GL", False)
        G = gt("S3-1", drop={18: 50}, a_txd=50, lost=50)                    # S3: the PR-2 form only
        self.assertIs(G["GL"]["ok"], True)
        self.assertTrue(G["GL"]["pr2_form"])
        self.assert_pred(gt("S3-1", drop={18: 50, 2: 1}, a_txd=50), "GL", False)
        self.assert_pred(gt("S3-1", drop={18: 50}, a_txd=50, udp_err=1), "GL", False)
        self.assert_pred(gt("S3-1", drop={18: 50}, a_txd=49), "GL", False)

        def missing(inp):
            inp["obs"][-1]["raw"]["softnet"] = None
        self.assert_pred(gt(edit=missing), "GL", None)

    # GC
    def test_gc(self):
        self.assert_pred(gt("N1-1"), "GC", True)
        self.assert_pred(gt("N1-1", cont_w=0.2), "GC", False)
        G = gt("N1-1", cont_w=0.3, foreign=0.5)                             # CPU 18 saturated, but not by the contender
        self.assertLessEqual(G["GC"]["cpu18_idle_frac_w"], C.G3_IDLE_MAX)
        self.assertIs(G["GC"]["ok"], False)

        def contender_ran_in_e0(inp):
            for o in inp["obs"][10:]:
                o["leaves"]["contender"]["cpu.stat"] = o["leaves"]["contender"]["cpu.stat"].replace(
                    "usage_usec 0", "usage_usec 500")
        self.assert_pred(gt("E0-open", edit=contender_ran_in_e0), "GC", False)

    # G7
    def test_g7(self):
        self.assert_pred(gt(), "G7", True)

        def irq(inp):
            inp["obs"][5]["raw"]["nic_irq_eff"] = "20\n"
        self.assert_pred(gt(edit=irq), "G7", False)

        def mem(inp):
            for o in inp["obs"][15:]:
                o["leaves"]["traffic"]["memory.events"] = "low 0\nhigh 0\nmax 0\noom 1\noom_kill 0\n"
        self.assert_pred(gt(edit=mem), "G7", False)

        def swap(inp):
            for k, o in enumerate(inp["obs"]):
                o["raw"]["vmstat"] = f"pswpin {10 + 100 * k}\npswpout 20\n"
        self.assert_pred(gt(edit=swap), "G7", False)

        def netns(inp):
            inp["obs"][-1]["target_netns"]["snmp"] = inp["obs"][-1]["target_netns"]["snmp"].replace(
                "Udp: 0 0", "Udp: 1 0")
        self.assert_pred(gt(edit=netns), "G7", False)

    def test_setup_checks_and_host_level(self):
        def rps(inp):
            inp["setup"]["rps_readback"] = "080000"
        G = gt(edit=rps)
        self.assertFalse(G["ok"])
        self.assertIn("setup check failed: rps_readback", E.ground_truth_aborts(G, E.experiment_of("S2-1")))

        def busy_host(inp):
            for k, o in enumerate(inp["obs"]):
                f = o["raw"]["stat"].splitlines()
                a = f[0].split()
                a[1] = str(int(0.5 * 24 * HZ * k))
                f[0] = " ".join(a)
                o["raw"]["stat"] = "\n".join(f) + "\n"
        G = gt(edit=busy_host)
        self.assertTrue(G["host_level_aborts"])
        self.assertFalse(G["ok"])

    def test_unavailable_is_an_abort(self):
        def eb_missing(inp):
            inp["obs"][I_W1]["ebpf_line"] = None
        G = gt(edit=eb_missing)
        a = E.ground_truth_aborts(G, E.experiment_of("S2-1"))
        self.assertTrue(any(x.startswith("ground truth unavailable: GS") for x in a))


# ------------------------------------------------------------------------------------------ calibration ladder
def step(pps, netrx, frac, all18=None, loss=0, rx=100000, processed=None, malformed=False):
    if malformed:
        return {"pps": pps, "malformed": True}
    return {"pps": pps, "malformed": False, "netrx18": netrx, "all18": netrx + 0.002 if all18 is None else all18,
            "frac18": frac, "achieved_pps": rx / 4, "processed18": rx if processed is None else processed, "b0_rx": rx,
            "loss": {"softnet": loss, "a_tx_dropped": 0, "b_rx_dropped": 0, "udp": 0, "iperf3_lost": 0}}


LADDER_OK = [step(10000, 0.02, 0.02), step(20000, 0.05, 0.05), step(40000, 0.1, 0.11), step(80000, 0.25, 0.24),
             step(160000, 0.55, 0.56), step(320000, 0.8, 0.8), step(640000, 0.9, 0.9, loss=3)]


class TestCalibration(unittest.TestCase):
    def test_valid_ladder(self):
        r = E.select_levels(LADDER_OK, 1000)
        self.assertTrue(r["feasible"], r["reason"])
        self.assertAlmostEqual(r["delta"], 0.012, places=6)
        self.assertEqual((r["S1"], r["S2"], r["S3"]), (80000, 160000, 320000))
        E.check_ladder(r)

    def test_disagreement_moves_the_levels(self):
        steps = [dict(s) for s in LADDER_OK]
        steps[3] = step(80000, 0.25, 0.43)                                   # delta 0.18
        r = E.select_levels(steps, 1000)
        self.assertAlmostEqual(r["delta"], 0.178, places=6)                 # |0.43 - (0.25 + 0.002)|
        self.assertEqual(r["S1"], 40000)                                     # 80000: frac 0.43 >= 0.5 - 0.178
        self.assertEqual(r["S2"], 320000)                                    # 160000: 0.55 < 0.5 + 0.178
        self.assertFalse(r["feasible"])                                       # nothing loss-free above 320000
        self.assertIn("no loss-free rate above S2", r["reason"])

    def test_no_s2(self):
        r = E.select_levels([step(10000, 0.1, 0.1), step(20000, 0.3, 0.3), step(40000, 0.45, 0.45, loss=1)], 1000)
        self.assertFalse(r["feasible"])
        self.assertIn("S2 not reachable", r["reason"])
        with self.assertRaises(E.R2ERefused):
            E.check_ladder(r)

    def test_no_loss_free_s3(self):
        r = E.select_levels(LADDER_OK[:5] + [step(320000, 0.8, 0.8, loss=2)], 1000)
        self.assertEqual(r["S2"], 160000)
        self.assertIsNone(r["S3"])
        self.assertFalse(r["feasible"])

    def test_loss_truncates(self):
        r = E.select_levels([step(10000, 0.02, 0.02, loss=1)] + LADDER_OK[1:], 1000)
        self.assertFalse(r["feasible"])
        self.assertEqual(r["reason"], "no loss-free ladder step")

    def test_malformed_and_steering(self):
        r = E.select_levels(LADDER_OK[:2] + [step(40000, 0, 0, malformed=True)] + LADDER_OK[3:], 1000)
        self.assertFalse(r["feasible"])
        self.assertIn("malformed", r["reason"])
        bad = [dict(s) for s in LADDER_OK]
        bad[2] = step(40000, 0.1, 0.11, processed=50000)
        r = E.select_levels(bad, 1000)
        self.assertFalse(r["feasible"])
        self.assertIn("steering", r["reason"])

    def test_check_ladder_refusals(self):
        good = E.select_levels(LADDER_OK, 1000)
        for mutate in (lambda d: d.update(feasible=False), lambda d: d.update(S2=12345),
                       lambda d: d.update(S1=d["S3"]), lambda d: d.update(delta=0.6), lambda d: d.update(delta=True),
                       lambda d: d.update(delta=None)):
            d = dict(good)
            mutate(d)
            with self.assertRaises(E.R2ERefused):
                E.check_ladder(d)
        self.assertEqual(E.level_pps(good, E.EXPERIMENTS["N2"]), good["S3"])
        self.assertIsNone(E.level_pps(good, E.EXPERIMENTS["N1"]))

    def test_step_record_from_raw_observations(self):
        inp = synth("S2-1")
        rec = E.ladder_step_record(inp["obs"][I_W0], inp["obs"][I_W1], META, HZ, inp["iperf"])
        self.assertFalse(rec["malformed"])
        self.assertAlmostEqual(rec["netrx18"], 0.6, places=6)
        self.assertAlmostEqual(rec["frac18"], 0.6, places=2)
        self.assertEqual(rec["b0_rx"], 10 * 160000)
        self.assertEqual(sum(rec["loss"].values()), 0)
        broken = copy.deepcopy(inp["obs"][I_W1])
        broken["ebpf_line"] = None
        self.assertTrue(E.ladder_step_record(inp["obs"][I_W0], broken, META, HZ, inp["iperf"])["malformed"])
        self.assertTrue(E.ladder_step_record(inp["obs"][I_W0], inp["obs"][I_W1], META, HZ,
                                             {"client0": iperf_json(error="x")})["malformed"])
        self.assertTrue(E.ladder_step_record(inp["obs"][I_W0], inp["obs"][I_W1], META, HZ,
                                             {"client0": "not json"})["malformed"])

    def test_ladder_rates_and_thresholds_unchanged(self):
        self.assertEqual(E.LADDER_PPS, tuple(10000 * 2 ** k for k in range(8)))
        self.assertEqual((E.SI_ABS_MIN, E.SI_RATIO_MIN, E.SI_SHARE_MIN, E.RDX_MIN, E.G6_MAX),
                         (0.5, 3.0, 0.5, 0.05, 0.05))


# ------------------------------------------------------------------------------------------ reproducibility
class TestReproducibility(unittest.TestCase):
    def test_json_round_trip(self):
        for label in ("S2-1", "S3-2", "N1-1", "N2-1", "E0-open", "S1-1"):
            inp = synth(label)
            self.assertEqual(E.evaluate(inp), E.evaluate(json.loads(json.dumps(inp))), label)

    def write_run(self, d, label="S2-1"):
        inp = synth(label)
        ops = [{"phase": "intent", "op": ["rps", E.RPS_REL], "value": "40000"},
               {"phase": "result", "op": ["rps", E.RPS_REL], "value": "40000", "prev": "000000", "post": "040000",
                "ok": True}]
        cops = [{"phase": "result", "op": ["rps", E.RPS_REL], "value": "0", "prev": "040000", "post": "000000"},
                {"phase": "intent", "op": ["cmd", ["ip", "netns", "del", E.NS_A]]}]
        R = {"label": label, "observations": inp["obs"], "expected": inp["expected"], "in_w": inp["in_w"],
             "window": {"obs_index": inp["window"]}, "ebpf_meta_line": META, "lab_setup": inp["setup"],
             "iperf_raw": inp["iperf"], "ladder": {"delta": inp["delta"]}, "hz": HZ, "target": {"pids": [TPID]},
             "cleanup": {"ok": True}, "host_compare": {"ok": True}}
        R["ground_truth"] = E.evaluate(E.ground_truth_inputs(R, None))
        R["GR"] = E.restore_record(ops + cops, R["cleanup"], R["host_compare"])
        (d / "run.json").write_text(json.dumps(R, sort_keys=True, default=str))
        (d / "ops.jsonl").write_text("\n".join(json.dumps(x) for x in ops) + "\n")
        (d / "ops.jsonl.cleanup").write_text("\n".join(json.dumps(x) for x in cops) + "\n")
        return R

    def test_offline_equals_runtime(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            R = self.write_run(d)
            self.assertTrue(R["ground_truth"]["ok"])
            r = E.offline_evaluate(d)
            self.assertTrue(r["ok"], r)
            R["observations"][15]["tasks"][str(TPID)]["stat"] = stat_text(TPID, "python3", 0, 17)   # tampered
            (d / "run.json").write_text(json.dumps(R, sort_keys=True, default=str))
            self.assertFalse(E.offline_evaluate(d)["ground_truth_identical"])

    def test_offline_ladder(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "ladder"
            d.mkdir()
            inp = synth("S2-1")
            obs = inp["obs"]
            raw = inp["iperf"]
            steps = []
            for pps, (a, b) in zip(E.LADDER_PPS[:3], ((I_B0, I_W0), (I_W0, I_W1), (I_W0, I_W1))):
                rec = E.ladder_step_record(obs[a], obs[b], META, HZ, raw)
                rec.update(pps=pps, iperf_raw=raw, obs_index=[a, b])
                steps.append(rec)
            R = {"observations": obs, "ebpf_meta_line": META, "hz": HZ, "lab_setup": {"netdev_max_backlog": "1000"}}
            R["ladder"] = E.select_levels(steps, 1000)
            R["ladder"]["hz"] = HZ
            (d / "run.json").write_text(json.dumps(R, sort_keys=True, default=str))
            self.assertTrue(E.offline_ladder(d)["ok"])
            R["ladder"]["S2"] = 40000
            (d / "run.json").write_text(json.dumps(R, sort_keys=True, default=str))
            self.assertFalse(E.offline_ladder(d)["ok"])

    def test_every_input_of_evaluate_is_saved_by_the_driver(self):
        for key in ('R["observations"], R["expected"], R["in_w"] = run.obs, run.expected, run.in_w',
                    'R["ebpf_meta_line"] = loader.raw[0]', 'R["lab_setup"] = setup', 'R["iperf_raw"] = {}',
                    '"obs_index": [i_b0, i_w0, i_w1]', '"hz": os.sysconf("SC_CLK_TCK")', '"ladder": lad',
                    'R["ground_truth"] = E.evaluate(E.ground_truth_inputs(R, target_out))',
                    'self.observe("tick", ebpf_line=self.loader.raw[-1])', 'rec["obs_index"] ='):
            self.assertIn(key, DRIVER)
        sample = MODULE[MODULE.index("def gt_sample"):MODULE.index("def parse_obs")]
        for raw in ('"/proc/stat"', '"/proc/schedstat"', '"/proc/softirqs"', '"/proc/net/softnet_stat"',
                    '"/proc/vmstat"', "/stat\")", "/schedstat\")", '"cpu.stat"', '"cpu.pressure"', "/net/snmp",
                    "lab_state(sysr)", "ebpf_line"):
            self.assertIn(raw, sample)


# ------------------------------------------------------------------------------------------ M2 (unchanged engine)
def whatif(path, values, max_value=None):
    """A real committed snapshot with CPU softirq fractions replaced in memory (consistent deviation + id)."""
    from sentinelai.diagnostic.contract import EvidenceSnapshot
    from sentinelai.diagnostic.contract.ids import snapshot_id
    snap = EvidenceSnapshot.model_validate_json(path.read_bytes(), strict=False)
    ms = []
    for m in snap.measurements:
        v = None
        if m.feature_id == "softirq.frac.percpu" and m.scope in values:
            v = values[m.scope]
        elif m.feature_id == "softirq.relevant_cpu_max" and max_value is not None:
            v = max_value
        if v is not None:
            upd = {"value": v}
            if m.deviation is not None:
                b, f = m.baseline, m.deviation.floor_used
                upd["deviation"] = m.deviation.model_copy(update={
                    "delta": v - b.median, "ratio": v / max(b.median, f), "robust_z": (v - b.median) / max(1.4826 * b.mad, f)})
            m = m.model_copy(update=upd)
        ms.append(m)
    ms = tuple(ms)
    return snap.model_copy(update={"measurements": ms, "snapshot_id": snapshot_id(snap.target, snap.window, ms)})


def m2(snap):
    from r2c_driver import params
    from sentinelai.diagnostic.rules import diagnose
    d = diagnose(snap, params(), code_commit="d11e755")
    items = {i.predicate_id: i for i in d.snapshot.evidence_items}
    return d, items


class TestM2(unittest.TestCase):
    def test_softirq_overload_through_pr5(self):
        d, it = m2(whatif(SNAP_E2, {"cpu:18": 0.7}, 0.7))
        self.assertEqual(d.result.decision.value, "softirq_overload")
        self.assertEqual((it["SI.R1"].kind.value, it["SI.R2"].kind.value), ("POSITIVE", "POSITIVE"))
        self.assertEqual(it["CC.X2"].kind.value, "POSITIVE")
        self.assertIn("cpu_contention", [l.value for l in it["CC.X2"].contradicts])

    def test_ordinary_contention_not_softirq(self):
        d, it = m2(whatif(SNAP_E2, {}))
        self.assertEqual(d.result.decision.value, "cpu_contention")
        self.assertEqual((it["SI.R1"].kind.value, it["CC.X2"].kind.value), ("NEGATIVE", "NEGATIVE"))

    def test_n2_softirq_on_cpu19_does_not_bind(self):
        d, it = m2(whatif(SNAP_E0, {"cpu:19": 0.9}))
        self.assertEqual(d.result.decision.value, "INSUFFICIENT_EVIDENCE")
        self.assertEqual(it["SI.R1"].kind.value, "NEGATIVE")
        snap = whatif(SNAP_E0, {"cpu:19": 0.9})
        cpu19 = [m.measurement_id for m in snap.measurements if m.feature_id == "softirq.frac.percpu"
                 and m.scope == "cpu:19"]
        self.assertFalse(set(cpu19) & set(it["SI.R1"].measurement_ids))

    def test_s1_sub_threshold_insufficient(self):
        d, it = m2(whatif(SNAP_E0, {"cpu:18": 0.3}, 0.3))
        self.assertEqual(d.result.decision.value, "INSUFFICIENT_EVIDENCE")
        self.assertEqual(it["SI.R1"].kind.value, "NEGATIVE")

    def test_packet_loss_precedence_unchanged(self):
        from sentinelai.diagnostic.contract import Label as L
        from sentinelai.diagnostic.rules import engine
        cl = lambda qual: {"SI.R1": SimpleNamespace(data={"saturated_cpus": [18]}),
                           "PL.R1": SimpleNamespace(data={"qualifying": qual})}
        self.assertEqual(engine._resolve(None, L.softirq_overload, L.network_packet_loss,
                                         cl([("net.drop.softnet", 18, None)])), (L.softirq_overload, "PR-2"))
        self.assertEqual(engine._resolve(None, L.softirq_overload, L.network_packet_loss,
                                         cl([("net.drop.kfree_skb", None, "CPU_BACKLOG")])), (L.softirq_overload, "PR-2"))
        self.assertEqual(engine._resolve(None, L.softirq_overload, L.network_packet_loss,
                                         cl([("net.drop.qdisc", None, None)])), (None, "PR-2b"))
        self.assertEqual(engine._resolve(None, L.softirq_overload, L.network_packet_loss,
                                         cl([("net.drop.softnet", 19, None)])), (None, "PR-2b"))


# ------------------------------------------------------------------------------------------ metric gate
class TestMetricGate(unittest.TestCase):
    def snap(self):
        from sentinelai.diagnostic.contract import EvidenceSnapshot
        return EvidenceSnapshot.model_validate_json(SNAP_E2.read_bytes(), strict=False)

    def test_r2c_shaped_snapshot_passes(self):
        g = E.metric_gate(self.snap(), 0.8, 5)
        self.assertTrue(g["ok"], g["aborts"])
        self.assertTrue(g["recorded"]["softirq.exec_time.percpu"])

    def test_required_metric_missing_aborts(self):
        s = self.snap()
        s2 = s.model_copy(update={"measurements": tuple(m for m in s.measurements
                                                        if not (m.feature_id == "softirq.frac.percpu"
                                                                and m.scope == "cpu:18"))})
        self.assertFalse(E.metric_gate(s2, 0.8, 5)["ok"])
        s3 = s.model_copy(update={"measurements": tuple(m for m in s.measurements
                                                        if m.feature_id != "psi.cpu.some.target")})
        self.assertFalse(E.metric_gate(s3, 0.8, 5)["ok"])

    def test_inadequate_baseline_aborts(self):
        s = self.snap()
        m = [m for m in s.measurements if m.feature_id == "psi.cpu.some.target"][0]
        bad = m.model_copy(update={"baseline": m.baseline.model_copy(update={"adequate": False})})
        s2 = s.model_copy(update={"measurements": tuple(bad if x is m else x for x in s.measurements)})
        g = E.metric_gate(s2, 0.8, 5)
        self.assertFalse(g["ok"])
        self.assertTrue(any("baseline inadequate" in a for a in g["aborts"]))
        self.assertFalse(E.metric_gate(s, 0.8, 10 ** 6)["ok"])               # n below N_BASE_MIN

    def test_network_activity_but_softnet_is_gl(self):
        s = self.snap()
        sn = [m for m in s.measurements if m.feature_id == "net.drop.softnet" and m.scope == "cpu:18"][0]
        s2 = s.model_copy(update={"measurements": tuple(m.model_copy(update={"value": 5.0}) if m is sn else m
                                                        for m in s.measurements)})
        self.assertTrue(E.metric_gate(s2, 0.8, 5)["ok"])
        rt = [m for m in s.measurements if m.feature_id.startswith("tcp.") and m.value is not None][0]
        s3 = s.model_copy(update={"measurements": tuple(m.model_copy(update={"value": 3.0}) if m is rt else m
                                                        for m in s.measurements)})
        self.assertFalse(E.metric_gate(s3, 0.8, 5)["ok"])


# ------------------------------------------------------------------------------------------ static / integrity
class TestStaticAndIntegrity(unittest.TestCase):
    def test_matrix_and_allocation(self):
        self.assertEqual(E.MATRIX, ("E0-open", "S1-1", "S1-2", "S2-1", "S2-2", "S2-3", "S3-1", "S3-2", "S3-3", "N1-1",
                                    "N1-2", "N2-1", "N2-2", "E0-close"))
        self.assertTrue(all(E.allocation_checks().values()))
        self.assertEqual((E.SENDER_CPUS, E.RECEIVER_CPU, E.N2_RPS_CPU, E.TARGET_CPU), ((20, 22), 23, 19, 18))
        self.assertEqual(E.EXPERIMENTS["N2"].rps, "80000")
        self.assertTrue(all(E.EXPERIMENTS[k].rps == "40000" for k in ("E0", "S1", "S2", "S3", "N1", "LADDER")))
        self.assertEqual(E.EXPERIMENTS["N1"].contender_weight, 400)
        self.assertNotIn(C.NIC_CPU, E.EXPERIMENT_CPUS)
        self.assertEqual(open(ROOT / "scripts" / "r2e_validate.sh").read().count("--ladder-file"), 1)
        self.assertEqual(code_lines(WRAPPER).count("BASE=d11e755"), 1)

    def test_single_mutation_sites(self):
        """subprocess only in Sys (read-only allowlist), Host (validated) and the RPS helper runner; no direct
        file write to /sys or /proc outside Host; the driver never calls subprocess."""
        self.assertNotIn("subprocess", DRIVER)
        self.assertNotIn("os.system", MODULE + DRIVER)
        self.assertNotIn("shell=True", MODULE + DRIVER)
        self.assertEqual(MODULE.count("subprocess.run("), 5)      # Sys.run, ip_link_help, Host cmd, Host RPS, candidate
        self.assertEqual(MODULE.count("subprocess.Popen("), 0)    # spawns go through R2-C's Host._do
        self.assertNotIn('open(p, "w")', MODULE)

    def test_no_forbidden_mechanism_in_executable_shapes(self):
        shapes = [c for _, c in E.lab_plan()] + [E.netns_del(n)[1] for n in E.LAB_NETNS] + \
            [tuple(E.server_argv(i)) for i in (0, 1)] + [tuple(E.client_argv(i, p)) for i in (0, 1) for p in E.LADDER_PPS]
        for s in shapes:
            for tok in ("tc", "sysctl", "ethtool", "modprobe", "cpu.max", "enp0s31f6", "docker0", "iptables", "nft",
                        "smp_affinity", "default"):
                self.assertNotIn(tok, s)
        for tok in ("tc ", "sysctl", "ethtool -K", "modprobe", "cpu.max", "enp0s31f6 ", "smp_affinity",
                    "git commit", "systemctl"):
            self.assertFalse([l for l in code_lines(WRAPPER) if tok in l and not l.startswith(("#", "echo"))], tok)

    def test_window_and_traffic_order_in_driver(self):
        cb = DRIVER[DRIVER.index("def on_window():"):DRIVER.index("i_b0 = len(run.obs)")]
        self.assertLess(cb.index("run.window = True"), cb.index("start_clients"))
        self.assertIn("WindowClock(on_window)", DRIVER)
        body = DRIVER[DRIVER.index('ev("collect_end")'):DRIVER.index("while tp.poll() is None")]
        self.assertIn("finish_clients", body)                     # no recovery observation while clients still run
        self.assertIn("E.CLIENT_T", DRIVER)
        self.assertEqual(E.CLIENT_T, C.NW + 1)

    def test_preflight_refuses_existing_lab_and_rps_state(self):
        src = MODULE[MODULE.index("def preflight"):MODULE.index("def verify_cgroups")]
        for k in ('"no_lab_netns"', '"no_lab_interface_in_host"', '"host_rps_all_zero"', '"no_sentinel_cgroup"',
                  '"nic_irq_off_experiment_cpus"'):
            self.assertIn(k, src)
        fake = SimpleNamespace(listdir=lambda p: ["sentinel-lab-b"] if p == "/run/netns" else None)
        self.assertEqual(E.lab_netns_present(fake), ["sentinel-lab-b"])
        rps = SimpleNamespace(listdir=lambda p: {"/sys/class/net": ["enp0s31f6"],
                                                 "/sys/class/net/enp0s31f6/queues": ["rx-0", "tx-0"]}.get(p),
                              read=lambda p: "040000\n")
        self.assertEqual(E.host_rps(rps), {"enp0s31f6/rx-0": "040000"})

    def test_host_compare_includes_rps_and_lab(self):
        base = {"rps": {"enp0s31f6/rx-0": "000000"}, "lab_netns": [], "links": []}
        with mock.patch.object(E.C, "compare_host", lambda b, o, r=True: {"failed": [], "ok": True}):
            self.assertTrue(E.compare_host(base, dict(base))["ok"])
            r = E.compare_host(base, {**base, "rps": {"enp0s31f6/rx-0": "040000"}})
            self.assertIn("host_rps_identical", r["failed"])
            r = E.compare_host(base, {**base, "lab_netns": ["sentinel-lab-b"]})
            self.assertIn("no_lab_netns", r["failed"])
            r = E.compare_host(base, {**base, "links": [{"ifname": "sentlab-a0"}]})
            self.assertIn("no_lab_interface_in_host", r["failed"])

    @unittest.skipUnless(IN_GIT, "integrity checks need the git checkout")
    def test_r2c_r2d_m2_m3a_m3b_contract_unchanged(self):
        git = lambda *a: subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True)
        for p in ("scripts/r2c_cpu.py", "scripts/r2c_driver.py", "scripts/r2c_target.py", "scripts/r2c_validate.sh",
                  "tests/faultlab/test_r2c.py", "scripts/r2d_cpu.py", "scripts/r2d_driver.py", "scripts/r2d_validate.sh",
                  "tests/faultlab/test_r2d.py", "scripts/r2a_lab.py", "scripts/r2b_driver.py"):
            self.assertEqual((ROOT / p).read_bytes(), git("show", f"d11e755:{p}").stdout.encode(), p)
        # Phase 2A.6: src/ may gain exactly the authorised flat runtime modules and the CLI; nothing else in src,
        # ebpf or contract may differ from d11e755
        changed = git("diff", "--name-only", "d11e755", "--", "src", "ebpf", "contract").stdout.split()
        runtime = lambda p: (p == "src/sentinelai/__main__.py"
                             or re.fullmatch(r"src/sentinelai/runtime/[a-z_]+\.py", p) is not None)
        self.assertEqual([p for p in changed if not runtime(p)], [])
        self.assertEqual(git("status", "--porcelain", "--untracked-files=no").stdout, "")

    @unittest.skipUnless(IN_GIT, "candidate check needs git")
    def test_candidate(self):
        """Live repository: at d11e755 (pre-runtime state) candidate() accepts. After the authorised R2-E closeout
        commit it must refuse, and the refusal may name only the closeout artifacts on top of d11e755 (plus, after the
        authorised R2-F closeout commit, exactly the R2-F tooling, report and evidence paths)."""
        git = lambda *a: subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True)
        base = git("rev-parse", "d11e755^{commit}").stdout.strip()
        res = E.candidate(str(ROOT))
        if git("rev-parse", "HEAD").stdout.strip() == base:
            self.assertTrue(res["ok"], res)
        else:                                                    # the authorised R2-E closeout state, exactly
            self.assertEqual(git("merge-base", "--is-ancestor", base, "HEAD").returncode, 0)
            closeout = lambda p: (re.fullmatch(r"docs/PHASE_1C_R2E_[A-Z0-9_]+\.md", p) is not None
                                  or p == "docs/PROJECT_STATUS.json" or p.startswith("results/phase1c_r2e/"))
            # the authorised R2-F closeout (a later phase) adds exactly these paths; nothing else is accepted
            r2f = lambda p: (re.fullmatch(r"scripts/r2f_[a-z_]+\.(py|sh)", p) is not None
                             or p == "tests/faultlab/test_r2f.py"
                             or re.fullmatch(r"docs/PHASE_1C_R2F_[A-Z0-9_]+\.md", p) is not None
                             or p.startswith("results/phase1c_r2f/"))
            # the authorised Phase 2A.6 closeout adds exactly these paths; nothing else is accepted
            p2a6 = lambda p: (p in ("README.md", "src/sentinelai/__main__.py")
                              or re.fullmatch(r"src/sentinelai/runtime/[a-z_]+\.py", p) is not None
                              or re.fullmatch(r"tests/runtime/[a-z_]+\.py", p) is not None
                              or re.fullmatch(r"docs/PHASE_2A_[A-Z0-9_]+\.md", p) is not None
                              or p.startswith("results/phase2a_live/"))
            # the authorised Phase 1C M4/M5 design revision and G-R2 evidence add exactly these paths; nothing
            # else is accepted
            p1c = lambda p: p in ("docs/PHASE_1C_DESIGN.md", "docs/PHASE_1C_M4_M5_PILOT_DESIGN.md",
                                  "tests/rules/test_design_adv.py", "docs/PHASE_1C_G_R2_EVIDENCE.md")
            changed = git("diff", "--name-only", base, "HEAD").stdout.split()
            others = sorted(p for p in changed if p not in E.TOOLING)
            self.assertTrue(others and all(closeout(p) or r2f(p) or p2a6(p) or p1c(p) for p in others), others)
            self.assertFalse(res["ok"])
            self.assertEqual(res["reason"], f"changed since {base[:7]} beyond R2-E tooling: {others}")
        with tempfile.TemporaryDirectory() as t:
            g = lambda *a: subprocess.run(["git", "-C", t, *a], capture_output=True, text=True, check=True)
            g("init", "-q")
            g("config", "user.email", "t@t")
            g("config", "user.name", "t")
            Path(t, "a.txt").write_text("a")
            g("add", ".")
            g("commit", "-qm", "base")
            base = g("rev-parse", "HEAD").stdout.strip()
            Path(t, "scripts").mkdir()
            Path(t, "scripts", "r2e_softirq.py").write_text("x")
            g("add", ".")
            g("commit", "-qm", "tooling")
            self.assertTrue(E.candidate(t, base)["ok"])
            Path(t, "a.txt").write_text("b")
            self.assertFalse(E.candidate(t, base)["ok"])                     # modified tracked file
            g("commit", "-qam", "other")
            self.assertIn("beyond R2-E tooling", E.candidate(t, base)["reason"])


class FakeSys:
    """A read-only host as preflight sees it (dict files), healthy unless edited."""

    def __init__(self, **edit):
        self.files = {f"{C.CG_ROOT}/cpuset.cpus.effective": "0-23\n",
                      f"{C.CG_ROOT}/cgroup.subtree_control": "cpuset cpu io memory hugetlb pids rdma misc\n",
                      "/sys/devices/system/cpu/online": "0-23\n", "/proc/pressure/cpu": psi_text(1),
                      "/proc/interrupts": " 134:  0  IR-PCI-MSI  enp0s31f6\n",
                      f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list": "21\n",
                      "/proc/sys/net/core/netdev_max_backlog": "1000\n"}
        self.files.update({f"/sys/devices/system/cpu/cpu{n}/topology/thread_siblings_list": f"{n}\n" for n in range(24)})
        self.dirs = {"/run/netns": [], "/sys/class/net": ["docker0", "enp0s31f6", "lo"]}
        self.dirs.update({f"/sys/class/net/{i}/queues": ["rx-0", "tx-0"] for i in ("docker0", "enp0s31f6", "lo")})
        self.files.update({f"/sys/class/net/{i}/queues/rx-0/rps_cpus": "000000\n" for i in ("docker0", "enp0s31f6",
                                                                                           "lo")})
        self.cgdirs = [""]
        for k, v in edit.items():
            getattr(self, k).update(v) if isinstance(v, dict) else setattr(self, k, v)

    def read(self, path):
        return self.files.get(path)

    def listdir(self, path):
        return self.dirs.get(path)

    def exists(self, path):
        return path in self.files or path in self.dirs or path.startswith(("/sys/class/net/", f"{C.CG_ROOT}/init"))

    def cgroup_dirs(self):
        return self.cgdirs

    def pids(self):
        return []

    def uid_name(self, uid):
        return "iiitd"

    def tool(self, path):
        return True


class TestPreflight(unittest.TestCase):
    def test_healthy(self):
        r = E.preflight(FakeSys())
        self.assertTrue(r["ok"], [k for k, v in r["checks"].items() if not v])

    def test_refusals(self):
        cases = {"no_lab_netns": FakeSys(dirs={"/run/netns": ["sentinel-lab-b"]}),
                 "no_lab_interface_in_host": FakeSys(dirs={"/sys/class/net": ["enp0s31f6", "lo", "sentlab-a0"]}),
                 "host_rps_all_zero": FakeSys(files={"/sys/class/net/enp0s31f6/queues/rx-0/rps_cpus": "040000\n"}),
                 "no_sentinel_cgroup": FakeSys(cgdirs=["", "sentinel-r2c"]),
                 "nic_irq_off_experiment_cpus": FakeSys(files={f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list": "20\n"}),
                 "experiment_cpus_no_smt": FakeSys(files={"/sys/devices/system/cpu/cpu22/topology/thread_siblings_list":
                                                          "6,22\n"}),
                 "root_cpuset_0_23": FakeSys(files={f"{C.CG_ROOT}/cpuset.cpus.effective": "0-21\n"})}
        for key, fs in cases.items():
            r = E.preflight(fs)
            self.assertFalse(r["ok"], key)
            self.assertFalse(r["checks"][key], key)


class TestDryRun(unittest.TestCase):
    def test_dry_run_mutates_nothing_and_guards_hold(self):
        rep = E.dry_run(E.Sys())
        self.assertTrue(rep["zero_mutation"]["ok"], rep["zero_mutation"]["failed"])
        self.assertTrue(all(v is True for v in rep["guards"]["planned_ops_accepted"].values()))
        self.assertTrue(rep["guards"]["forbidden_refused"])
        self.assertTrue(all(rep["rps_helper"].values()))
        self.assertTrue(rep["cleanup_simulation"]["ok"])
        self.assertTrue(all(rep["metric_table"].values()))
        self.assertTrue(all(rep["allocation"].values()))

    def test_dry_run_never_instantiates_host(self):
        src = MODULE[MODULE.index("def dry_run"):MODULE.index("def candidate")]
        self.assertNotIn("Host(", src)
        self.assertNotIn("rps_write(", src)
        self.assertNotIn(".apply(", src)


if __name__ == "__main__":
    unittest.main()
