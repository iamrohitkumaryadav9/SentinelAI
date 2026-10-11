"""R2-F tooling: controlled memory pressure in sentinel-r2f. The only new mutations are lab memory controls (written
read-before / read-after, all before any process starts, memory.swap.max 0 everywhere), a lab scratch file under
/var/tmp/sentinel-r2f, and one SIGUSR1 to the target. Ground truth (GP GC GD GM GI GL GCPU GT GN GH GR) is exercised
on synthetic RAW observations through the same pure evaluate() the run uses, and recomputed offline.
No test creates a cgroup, applies memory pressure, touches swap, or changes the host. The workload test runs
r2f_target.py unprivileged on a 4 MiB file in a temporary directory."""

import copy
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import r2c_cpu as C  # noqa: E402
import r2f_memory as F  # noqa: E402

MODULE = (ROOT / "scripts" / "r2f_memory.py").read_text()
DRIVER = (ROOT / "scripts" / "r2f_driver.py").read_text()
WRAPPER = (ROOT / "scripts" / "r2f_validate.sh").read_text()
TARGET = (ROOT / "scripts" / "r2f_target.py").read_text()
EBPF_FIXTURE = ROOT / "results" / "phase1c_r2d" / "20261003T191737Z" / "T1-1" / "raw_ebpf.jsonl"
SNAP_E0 = ROOT / "results" / "phase1c_r2c" / "20261003T175532Z" / "E0-open" / "snapshot.json"
IN_GIT = (ROOT / ".git").exists()
MIB = F.MIB
I_B0, I_W0, I_W1 = 2, 2 + F.NB, 2 + F.NB + F.NW
N_OBS = I_W1 + 3
TPID, CPID = 5101, 5103
RD = F.scratch_dir(F.SIM_TS, "M2-1")
OUT = str(F.RESULTS / F.SIM_TS / "M2-1" / "target.json")


def code_lines(text):
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


# ------------------------------------------------------------------------------------------ synthetic raw evidence
_lines = EBPF_FIXTURE.read_text().splitlines()
META, _TEMPLATE = _lines[0], json.loads(_lines[1])


def ebpf_line(seq, mono_s, netrx18_ns):
    d = copy.deepcopy(_TEMPLATE)
    d.update(seq=seq, mono_ns=int(mono_s * 1e9))
    d["softirq"] = [[c, v, int(netrx18_ns) if (c, v) == (18, 3) else 0, 0] for c in range(24) for v in range(10)]
    return json.dumps(d, separators=(",", ":"))


def psi_text(total, avg10=0.0):
    return f"some avg10={avg10:.2f} avg60=0.00 avg300=0.00 total={int(total)}\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"


def stat_text(pid, comm, cpu, majflt=0, flags=0):
    rest = ["S"] + ["0"] * 50
    rest[6], rest[9], rest[36] = str(flags), str(majflt), str(cpu)
    return f"{pid} ({comm}) " + " ".join(rest) + "\n"


KIND_DEFAULTS = {
    "E0": dict(refault_w=0, majflt_w=0, scan_w=0, cur_w=300 * MIB, cost_w=50_000),
    "M1": dict(refault_w=8_000, majflt_w=8_000, scan_w=20_000, cur_w=760 * MIB, cost_w=3_000_000),
    "M2": dict(refault_w=20_000, majflt_w=20_000, scan_w=40_000, cur_w=510 * MIB, cost_w=15_000_000),
    "N1": dict(refault_w=0, majflt_w=0, scan_w=0, cur_w=1100 * MIB, cost_w=60_000),
    "N2": dict(refault_w=0, majflt_w=0, scan_w=0, cur_w=300 * MIB, cost_w=50_000, cont_w=0.97),
}


def synth(label="M2-1", **kw):
    """Raw observations of one run, as gt_sample records them, plus every other saved input of evaluate()."""
    exp = F.experiment_of(label)
    p = {"refault_b": 0, "target_cores": 0.01, "cont_w": 0.0, "foreign": 0.0, "rd_b": 0.001, "rd_w": 0.002,
         "avail": 13 << 30, "swap_pages": 0, "kswapd": 0, "host_oom": 0, "lab_oom": 0, "slice_mem": 0.0,
         "slice_io": 0.0, "netrx18": 0.0001, "cost_b": 50_000, "anon": 30 * MIB, "swap_cur": 0, "cpu_max": None,
         "high": None, "cpu18": F.TARGET_CPU}
    p.update(KIND_DEFAULTS[exp.kind])
    if exp.kind == "N2":
        p.update(rd_w=0.5)
    p.update(kw)
    cum = {k: 0.0 for k in ("refault", "majflt", "scan", "tgt", "cont", "foreign", "rd", "psi", "smem", "sio",
                            "swap", "kswapd", "netrx", "hoom", "busy_all")}
    obs, expected, in_w = [], [], []
    for k in range(N_OBS):
        w = I_W0 < k <= I_W1
        if k > 0:
            cum["refault"] += p["refault_w"] if w else p["refault_b"]
            cum["majflt"] += p["majflt_w"] if w else 0
            cum["scan"] += p["scan_w"] if w else 0
            cum["tgt"] += p["target_cores"] * 1e6
            cum["cont"] += (p["cont_w"] if w else 0) * 1e6
            cum["foreign"] += p["foreign"] * 1e9
            cum["rd"] += (p["rd_w"] if w else p["rd_b"]) * 1e9
            cum["psi"] += 5000 if w else 100
            cum["smem"] += 1000 + (p["slice_mem"] * 1e6 if w else 0)
            cum["sio"] += 1000 + (p["slice_io"] * 1e6 if w else 0)
            cum["swap"] += p["swap_pages"] if w else 0
            cum["kswapd"] += p["kswapd"] if w else 0
            cum["netrx"] += p["netrx18"] * 1e9
            cum["busy_all"] += 0.02 * 24 * 100
        mono = 100.0 + k
        rq18 = int(cum["tgt"] * 1e3 + cum["cont"] * 1e3 + cum["foreign"])
        sched = "version 15\ntimestamp 1\n" + "".join(f"cpu{n} 0 0 0 0 0 0 {rq18 if n == 18 else 0} 0 0\n"
                                                       for n in range(24))
        stat = [f"cpu {int(cum['busy_all'])} 0 0 {int(24 * 100 * k - cum['busy_all'])} 0 0 0 0 0 0"] + \
            [f"cpu{n} 1 0 0 {100 * k} 0 0 0 0 0 0" for n in range(24)]
        cont = [CPID] if exp.contender and w else []
        cur = p["cur_w"] if w else 300 * MIB
        high = p["high"] if p["high"] is not None else exp.high
        hoom = p["host_oom"] if k == N_OBS - 1 else 0
        loom = p["lab_oom"] if k == N_OBS - 1 else 0

        def leaf(procs, mem_high, mem_max, usage, current, mstat=""):
            return {"cpu.max": (p["cpu_max"] or "max 100000") + "\n", "cpuset.cpus.effective": "18\n",
                    "cpu.stat": f"usage_usec {int(usage)}\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n",
                    "cpu.pressure": psi_text(cum["rd"] / 1e3), "memory.current": f"{current}\n",
                    "memory.high": f"{mem_high}\n", "memory.max": f"{mem_max}\n", "memory.swap.max": "0\n",
                    "memory.swap.current": f"{p['swap_cur']}\n",
                    "memory.events": f"low 0\nhigh 0\nmax 0\noom {loom}\noom_kill {loom}\noom_group_kill 0\n",
                    "memory.events.local": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n", "memory.stat": mstat,
                    "memory.pressure": psi_text(cum["psi"]), "cgroup.procs": "".join(f"{x}\n" for x in procs)}
        tstat = (f"anon {p['anon']}\nfile {cur - p['anon']}\npgscan {int(cum['scan'])}\n"
                 f"workingset_refault_anon 0\nworkingset_refault_file {int(cum['refault'])}\n"
                 f"pgmajfault {int(cum['majflt'])}\n")
        tasks = {str(TPID): {"stat": stat_text(TPID, "python3", p["cpu18"], int(cum["majflt"])),
                             "schedstat": f"{int(cum['tgt'] * 1e3)} {int(cum['rd'])} 10\n"}}
        for c in cont:
            tasks[str(c)] = {"stat": stat_text(c, "python3", 18), "schedstat": f"{int(cum['cont'] * 1e3)} 0 1\n"}
        tick = I_B0 <= k <= I_W1
        o = {"mono": mono, "tag": "tick" if tick else "warmup",
             "raw": {"stat": "\n".join(stat) + "\n", "schedstat": sched, "softirqs": "CPU0\nNET_RX: 0\n",
                     "meminfo": f"MemTotal: 16054116 kB\nMemAvailable: {p['avail'] // 1024} kB\n",
                     "vmstat": f"pswpin {int(cum['swap'])}\npswpout 0\npgscan_kswapd {int(cum['kswapd'])}\n"
                               f"oom_kill {hoom}\n",
                     "psi_cpu": psi_text(1000), "psi_memory": psi_text(cum["psi"]), "psi_io": psi_text(cum["sio"]),
                     "nic_irq_eff": "21\n"},
             "slices": {s: {"cpu": psi_text(100 * k), "memory": psi_text(cum["smem"]), "io": psi_text(cum["sio"])}
                        for s in C.SLICES},
             "leaves": {"parent": leaf([], "max", F.PARENT_MAX, 0, cur),
                        "target": leaf([TPID], high, exp.high + F.TARGET_MAX_HEADROOM, cum["tgt"], cur, tstat),
                        "contender": leaf(cont, "max", F.CONTENDER_MAX, cum["cont"], 0)},
             "tasks": tasks,
             "target_netns": {"dev": "Inter-|\n face |\n    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                              "snmp": "Tcp: InSegs OutSegs RetransSegs\nTcp: 0 0 0\nUdp: InDatagrams OutDatagrams\n"
                                      "Udp: 0 0\n"},
             "ebpf_line": ebpf_line(k + 1, mono, cum["netrx"]) if tick else None}
        obs.append(o)
        expected.append({"target": [TPID], "contender": cont})
        in_w.append(w)
    per, t0 = F.PERIOD_NS, int(99.0 * 1e9)
    n = int((N_OBS + 1) * 1e9 // per)
    wake, done = [], []
    for c in range(n):
        dl = t0 + c * per
        cost = p["cost_w"] if obs[I_W0]["mono"] * 1e9 <= dl < obs[I_W1]["mono"] * 1e9 else p["cost_b"]
        wake.append(dl + 1000)
        done.append(dl + 1000 + cost)
    target_out = {"pid": TPID, "period_ns": per, "cycles": n, "t0_ns": t0, "wake_ns": wake, "done_ns": done,
                  "file_bytes": F.FILE_BYTES, "file_size": F.FILE_BYTES, "scan_b": F.SCAN_B, "scan_w": F.scan_w(exp),
                  "sigusr1_count": 1 if exp.expand else 0, "expanded_at_cycle": 1200 if exp.expand else None}
    sig = {"pid": TPID, "t0": obs[I_W0]["mono"] + 0.01, "t1": obs[I_W0]["mono"] + 0.02} if exp.expand else None
    return {"label": label, "obs": obs, "expected": expected, "in_w": in_w, "window": [I_B0, I_W0, I_W1],
            "ebpf_meta": META, "signal": sig, "target_pid": TPID, "target_out": target_out}


def gt(label="M2-1", edit=None, **kw):
    inp = synth(label, **kw)
    if edit:
        edit(inp)
    return F.evaluate(inp)


# ------------------------------------------------------------------------------------------ allowlist / ordering
def state(**kw):
    s = {"controls_verified": False, "spawned": False, "target_spawned": False, "run_dir": RD, "target_pid": 7,
         "signalled": False}
    s.update(kw)
    return s


class TestAllowlist(unittest.TestCase):
    def test_planned_operations_accepted_in_order(self):
        for label in F.MATRIX:
            exp = F.experiment_of(label)
            st = state(run_dir=F.scratch_dir(F.SIM_TS, label))
            for kind, x in F.driver_steps(exp, label):
                if kind == "verify":
                    st["controls_verified"] = True
                elif kind == "signal":
                    F.check_op(("signal", 7), exp, st)
                else:
                    F.check_op(x, exp, st)
                    if x[0] == "spawn":
                        st["spawned"] = True
                        st["target_spawned"] |= x[1] == "target"

    def test_memory_plan_values(self):
        m2 = F.EXPERIMENTS["M2"]
        plan = {p: v for _, p, v in F.memory_plan(m2)}
        self.assertEqual(plan, {f"{F.LAB_DIR}/memory.max": str(1792 * MIB), f"{F.LAB_DIR}/memory.swap.max": "0",
                                f"{F.TARGET_DIR}/memory.swap.max": "0", f"{F.TARGET_DIR}/memory.max": str(640 * MIB),
                                f"{F.TARGET_DIR}/memory.high": str(512 * MIB), f"{F.CONTENDER_DIR}/memory.swap.max": "0",
                                f"{F.CONTENDER_DIR}/memory.max": str(64 * MIB)})
        self.assertEqual({k: e.high // MIB for k, e in F.EXPERIMENTS.items()},
                         {"CAL": 1536, "E0": 1536, "M1": 768, "M2": 512, "N1": 1536, "N2": 1536})
        self.assertTrue(all(F.allocation_checks().values()))
        self.assertEqual((F.FILE_BYTES, F.SCAN_B, F.SCAN_W), (1024 * MIB, 256 * MIB, 1024 * MIB))

    def test_memory_path_escapes_and_invalid_values(self):
        m2, st = F.EXPERIMENTS["M2"], state()
        bad = [(f"{F.TARGET_DIR}/../memory.high", str(512 * MIB)), (f"{F.CG_ROOT}/memory.max", str(F.PARENT_MAX)),
               (f"{F.CG_ROOT}/user.slice/memory.high", str(512 * MIB)), (f"{F.CG_ROOT}/system.slice/memory.max", "1"),
               (f"{F.TARGET_DIR}/memory.high", "1"), (f"{F.TARGET_DIR}/memory.high", "512M"),
               (f"{F.TARGET_DIR}/memory.high", str(768 * MIB)), (f"{F.TARGET_DIR}/memory.max", "max"),
               (f"{F.TARGET_DIR}/memory.swap.max", "max"), (f"{F.LAB_DIR}/memory.swap.max", "1048576"),
               (f"{F.CONTENDER_DIR}/memory.high", "1"), (f"{F.TARGET_DIR}/memory.low", "0"),
               (f"{F.TARGET_DIR}/memory.reclaim", "1G"), ("/sys/fs/cgroup/sentinel-r2c/target/memory.high", "1")]
        for path, value in bad:
            with self.subTest(path=path, value=value), self.assertRaises(F.R2FRefused):
                F.check_op(("mem", path, value), m2, st)

    def test_forbidden_operations(self):
        m2, pre, post = F.EXPERIMENTS["M2"], state(), state(controls_verified=True, spawned=True, target_spawned=True)
        bad = [(("write", f"{F.TARGET_DIR}/memory.high", str(512 * MIB)), pre),
               (("write", f"{F.TARGET_DIR}/cpu.max", "1 100000"), pre), (("write", "/proc/sys/vm/swappiness", "0"), pre),
               (("write", "/proc/sys/vm/drop_caches", "3"), pre), (("write", f"{F.CG_ROOT}/cpuset.cpus", "0-23"), pre),
               (("write", "/sys/class/net/enp0s31f6/mtu", "1"), pre), (("mkdir", f"{F.CG_ROOT}/system.slice/x"), pre),
               (("exec", "swapoff", "-a"), pre), (("exec", "swapon", "-a"), pre),
               (("scratch", "mkdir", "/tmp/sentinel-r2f/20260101T000000Z-M2-1"), pre),
               (("scratch", "mkdir", "/var/tmp/sentinel-r2f/../etc"), pre),
               (("scratch", "unlink", "/var/tmp/sentinel-r2f/20260101T000000Z-M2-1/other.bin"), pre),
               (("scratch", "rmdir_base", "/var/tmp"), pre), (("scratch", "rm", RD), pre),
               (("spawn", "contender", F.contender_argv(OUT)), post), (("kill", 1), pre), (("kill", True), pre)]
        for op, st in bad:
            with self.subTest(op=op[:2]), self.assertRaises(F.R2FRefused):
                F.check_op(op, m2, st)

    def test_ordering_is_enforced_by_the_guard(self):
        """Condition 2: no spawn before verified controls; no memory write after a spawn; one target only."""
        m2 = F.EXPERIMENTS["M2"]
        targ = ("spawn", "target", F.target_argv(m2, RD, OUT))
        with self.assertRaises(F.R2FRefused):
            F.check_op(targ, m2, state(controls_verified=False))
        F.check_op(targ, m2, state(controls_verified=True))
        with self.assertRaises(F.R2FRefused):
            F.check_op(targ, m2, state(controls_verified=True, target_spawned=True))
        for _, p, v in F.memory_plan(m2):
            F.check_op(("mem", p, v), m2, state())
            with self.assertRaises(F.R2FRefused):
                F.check_op(("mem", p, v), m2, state(controls_verified=True, spawned=True))

    def test_reversed_ordering_fails_in_simulation(self):
        """Running the plan with the target spawn moved before the memory controls must be refused."""
        exp = F.EXPERIMENTS["M2"]
        steps = F.driver_steps(exp, "M2-1")
        spawn = next(s for s in steps if s[0] == "op" and s[1][0] == "spawn")
        reordered = [s for s in steps if s is not spawn]
        reordered.insert(next(i for i, s in enumerate(reordered) if s[0] == "mem"), spawn)
        sim = F.SimHost(exp, run_dir=RD)
        with self.assertRaises(F.R2FRefused):
            for kind, x in reordered:
                if kind == "op":
                    sim.apply(x)
                elif kind == "mem":
                    sim.mem_write(x[1], x[2])
        self.assertFalse([e for e in sim.events if e[0] == "spawn"])

    def test_scratch_regex_independent_of_run_dir(self):
        m2 = F.EXPERIMENTS["M2"]
        for path in ("/tmp/sentinel-r2f/20260101T000000Z-M2-1", "/var/tmp/sentinel-r2f/x", "/var/tmp/other",
                     "/var/tmp/sentinel-r2f/20260101T000000Z-M2-1/../../x"):
            for action in ("mkdir", "rmdir"):
                with self.subTest(path=path, action=action), self.assertRaises(F.R2FRefused):
                    F.check_op(("scratch", action, path), m2, {})
        F.check_op(("scratch", "mkdir", RD), m2, {})

    def test_signal_guard(self):
        m2, e0 = F.EXPERIMENTS["M2"], F.EXPERIMENTS["E0"]
        F.check_op(("signal", 7), m2, state(target_pid=7))
        for exp, st, pid in ((e0, state(), 7), (F.EXPERIMENTS["N2"], state(), 7), (m2, state(signalled=True), 7),
                             (m2, state(), 8), (m2, state(target_pid=None), 7)):
            with self.assertRaises(F.R2FRefused):
                F.check_op(("signal", pid), exp, st)
        for k in ("M1", "M2", "N1"):
            self.assertTrue(F.EXPERIMENTS[k].expand)
        self.assertFalse(F.EXPERIMENTS["E0"].expand or F.EXPERIMENTS["N2"].expand)

    def test_spawn_shapes(self):
        m2 = F.EXPERIMENTS["M2"]
        a = F.target_argv(m2, RD, OUT)
        k = a.index(C.PYTHON)
        self.assertEqual(a[:len(F.WRAPPER)], ["timeout", "-s", "KILL", "90"])
        self.assertIn("unshare", a)
        self.assertEqual(a[a.index("setpriv") + 1], "--reuid=1000")
        self.assertEqual(a[k + 1:k + 3], ["-I", F.TARGET_SCRIPT])
        self.assertEqual(a[a.index("--file") + 1], f"{RD}/ws.bin")
        self.assertEqual(a[a.index("--scan-w") + 1], str(1024 * MIB))
        self.assertEqual(F.target_argv(F.EXPERIMENTS["E0"], RD, OUT)[a.index("--scan-w") + 1], str(256 * MIB))
        for bad in ("/tmp/x", "/var/tmp/sentinel-r2f/x", "/var/tmp/sentinel-r2f/20260101T000000Z-M3-1"):
            with self.assertRaises(F.R2FRefused):
                F.target_argv(m2, bad, OUT)
        with self.assertRaises(F.R2FRefused):
            F.check_op(("spawn", "target", F.target_argv(m2, RD, "/tmp/x.json")), m2, state(controls_verified=True))


class TestMemWrite(unittest.TestCase):
    def fake(self, prev="max", readback=None):
        files, log = {"p": prev}, []

        def write(p, v):
            files[p] = readback if readback is not None else v
        return files, log, (lambda p: files.get(p)), write, (lambda **kw: log.append(kw))

    def test_success(self):
        files, log, read, write, lg = self.fake()
        rec = F.mem_write("p", "536870912", read, write, lg)
        self.assertEqual((rec["prev"], rec["post"]), ("max", "536870912"))
        self.assertEqual([e["phase"] for e in log], ["intent", "result"])

    def test_read_before_mismatch_never_writes(self):
        files, log, read, write, lg = self.fake(prev="1073741824")
        with self.assertRaises(F.MemAbort):
            F.mem_write("p", "536870912", read, write, lg)
        self.assertEqual(files["p"], "1073741824")
        self.assertEqual(log[0]["phase"], "refused")

    def test_missing_or_wrong_readback(self):
        for rb in ("", "max", "536866816"):
            files, log, read, write, lg = self.fake(readback=rb)
            with self.assertRaises(F.MemAbort):
                F.mem_write("p", "536870912", read, write, lg)
            self.assertFalse(log[-1]["ok"])

    def test_host_routes_memory_only_through_mem_write(self):
        h = F.Host(F.EXPERIMENTS["M2"], os.devnull, sysr=SimpleNamespace(read=lambda p: None))
        with self.assertRaises(F.R2FRefused):
            h.apply(("mem", f"{F.TARGET_DIR}/memory.high", str(512 * MIB)))

    def test_verify_controls(self):
        exp = F.EXPERIMENTS["M1"]
        files = {p: v for _, p, v in F.memory_plan(exp)}
        files.update({f"{d}/cpu.max": "max 100000" for d in F.LAB_DIRS})
        self.assertTrue(F.verify_controls(files.get, exp)["ok"])
        for p in list(files):
            bad = dict(files, **{p: "max" if "memory" in p else "50000 100000"})
            self.assertFalse(F.verify_controls(bad.get, exp)["ok"], p)


# ------------------------------------------------------------------------------------------ cleanup
class TestCleanup(unittest.TestCase):
    def test_simulation_cases(self):
        r = F.simulation_cases()
        self.assertTrue(r["ok"], r["failures"])
        self.assertGreater(r["cases"], 350)

    def test_exact_cleanup_order(self):
        for kind, label in (("M2", "M2-1"), ("N2", "N2-1"), ("E0", "E0-open"), ("CAL", "calibration")):
            r = F.simulate(F.EXPERIMENTS[kind], label)
            self.assertTrue(r["ok"], (kind, r))
            self.assertEqual(r["order"], ["terminated", "controls_verified", "bpf_released", "scratch_deleted",
                                          "cgroups_removed"])

    def test_trace_kill_before_bpf_before_scratch_before_rmdir(self):
        exp = F.EXPERIMENTS["M2"]
        sim = F.SimHost(exp, run_dir=RD)
        for kind, x in F.driver_steps(exp, "M2-1"):
            if kind == "op":
                sim.apply(x)
            elif kind == "mem":
                sim.mem_write(x[1], x[2])
            elif kind == "verify":
                sim.verify()
            else:
                sim.apply(("signal", sim.state["target_pid"]))
        marks = []
        res = F.cleanup(sim, sim, list(sim.entries), exp, wait_s=0, sleep=lambda s: None,
                        after_kill=lambda: marks.append(len(sim.events)))
        self.assertTrue(res["ok"], res)
        ev = sim.events
        kill = max(i for i, e in enumerate(ev) if e[0] == "cgroup.kill")
        unlink = next(i for i, e in enumerate(ev) if e[0] == "unlink")
        rmdirs = [i for i, e in enumerate(ev) if e[0] == "rmdir"]
        self.assertLess(kill, marks[0])                                  # kill before loader/BPF release
        self.assertLessEqual(marks[0], unlink)                           # BPF release before the scratch file
        self.assertLess(unlink, min(rmdirs))                             # scratch file before the cgroups
        self.assertFalse(sim.scratch or sim.dirs or sim.alive)

    def test_crash_paths_and_cleanup_failures(self):
        exp = F.EXPERIMENTS["M1"]
        n = len(F.driver_steps(exp, "M1-1"))
        for c in range(1, n + 1):                                        # driver SIGKILL / timeout / SIGTERM point
            self.assertTrue(F.simulate(exp, "M1-1", crash_after=c)["ok"], c)
        for c in range(1, 10):
            r = F.simulate(exp, "M1-1", fail_cleanup_at=c)
            self.assertTrue(r["ok"], c)

    def test_controls_changed_during_run_is_reported(self):
        exp = F.EXPERIMENTS["M2"]
        sim = F.SimHost(exp, run_dir=RD)
        for kind, x in F.driver_steps(exp, "M2-1"):
            if kind == "op":
                sim.apply(x)
            elif kind == "mem":
                sim.mem_write(x[1], x[2])
            elif kind == "verify":
                sim.verify()
        sim.files[f"{F.TARGET_DIR}/memory.high"] = "max"                  # changed by someone else
        res = F.cleanup(sim, sim, list(sim.entries), exp, wait_s=0, sleep=lambda s: None)
        self.assertFalse(res["ok"])
        self.assertTrue(any("memory controls changed" in e for e in res["errors"]))

    def test_restore_record(self):
        ok = {"ok": True, "order": ["terminated", "controls_verified", "bpf_released", "scratch_deleted",
                                    "cgroups_removed"]}
        self.assertTrue(F.restore_record(ok, {"ok": True}, {"released": True})["ok"])
        self.assertFalse(F.restore_record(dict(ok, order=ok["order"][::-1]), {"ok": True}, {"released": True})["ok"])
        self.assertFalse(F.restore_record(ok, {"ok": True}, {"released": False})["ok"])
        self.assertFalse(F.restore_record(ok, {"ok": False}, {"released": True})["ok"])

    def test_driver_and_wrapper_failure_paths(self):
        lines = code_lines(DRIVER)
        i_sig = next(i for i, l in enumerate(lines) if l.startswith("old = {s: signal.signal(s, on_signal)"))
        i_setup = next(i for i, l in enumerate(lines) if l.startswith("for op in F.cgroup_plan(exp):"))
        self.assertLess(i_sig, i_setup)
        self.assertIn("except (C.LabAbort, Interrupted, Exception) as exc:", DRIVER)
        self.assertIn("after_kill=make_after_kill(state, sysr, base, R))", DRIVER)
        cb = DRIVER[DRIVER.index("def make_after_kill"):DRIVER.index("def clause_items")]
        self.assertLess(cb.index("loader.close()"), cb.index("C.wait_bpf_released"))
        self.assertIn("finally:", cb)
        self.assertEqual(DRIVER.count("C.wait_bpf_released("), 1)
        self.assertIn('R.setdefault("bpf_release", {"released": False', DRIVER)
        self.assertIn("trap finish EXIT", WRAPPER)
        self.assertIn("trap 'finish; exit 130' INT TERM", WRAPPER)
        self.assertIn('"$PY" "$R2F" cleanup "$OUT"', WRAPPER)

    def test_driver_setup_order(self):
        """Condition 2 in the driver: cgroups -> memory writes -> verify -> scratch -> target spawn."""
        body = DRIVER[DRIVER.index('ev("setup_start")'):DRIVER.index("t_ready_ns = wait_ready")]
        order = [body.index(s) for s in ("for op in F.cgroup_plan(exp):", "host.mem_write(path, value)",
                                         "R[\"controls\"] = host.verify()", 'host.apply(("scratch", "mkdir", run_dir))',
                                         'run.spawn("target"')]
        self.assertEqual(order, sorted(order))
        self.assertNotIn("mem_write", DRIVER[DRIVER.index('run.spawn("target"'):])


# ------------------------------------------------------------------------------------------ ground truth
class TestGroundTruth(unittest.TestCase):
    def assert_pred(self, G, name, want):
        self.assertIs(G[name]["ok"], want, (name, G[name]))
        if want is not True and name in G["required"]:
            self.assertFalse(G["ok"])

    def test_established(self):
        for label, key in (("M1-1", "memory_pressure"), ("M2-1", "memory_pressure"), ("E0-open", "memory_pressure_absent"),
                           ("N1-1", "memory_pressure_absent"), ("N2-1", "memory_pressure_absent")):
            G = gt(label)
            self.assertTrue(G["ok"], (label, F.ground_truth_aborts(G)))
            self.assertTrue(G["established"][key], label)
        self.assertTrue(gt("N2-1")["established"]["cpu_contention_present"])

    def test_gp(self):
        self.assert_pred(gt(cpu18=17), "GP", False)

        def outside(inp):
            inp["obs"][5]["leaves"]["target"]["cgroup.procs"] = ""
        self.assert_pred(gt(edit=outside), "GP", False)

        def parent(inp):
            inp["obs"][5]["leaves"]["parent"]["cgroup.procs"] = "9\n"
        self.assert_pred(gt(edit=parent), "GP", False)

    def test_gc(self):
        self.assert_pred(gt(high=str(768 * MIB)), "GC", False)                     # wrong memory.high

        def swapmax(inp):
            inp["obs"][9]["leaves"]["target"]["memory.swap.max"] = "max\n"
        self.assert_pred(gt(edit=swapmax), "GC", False)
        self.assert_pred(gt(cpu_max="50000 100000"), "GC", False)

        def late_signal(inp):
            inp["signal"] = {"pid": TPID, "t0": inp["obs"][I_W0 + 1]["mono"] + 0.1, "t1": inp["obs"][I_W0 + 1]["mono"] + 0.2}
        self.assert_pred(gt(edit=late_signal), "GC", False)

        def no_signal(inp):
            inp["signal"] = None
        self.assert_pred(gt(edit=no_signal), "GC", False)

        def signal_in_e0(inp):
            inp["signal"] = {"pid": TPID, "t0": 112.01, "t1": 112.02}
        self.assert_pred(gt("E0-open", edit=signal_in_e0), "GC", False)

        def double_expand(inp):
            inp["target_out"]["sigusr1_count"] = 2
        self.assert_pred(gt(edit=double_expand), "GC", False)

    def test_gd(self):
        def small(inp):
            inp["target_out"]["scan_w"] = 256 * MIB
        self.assert_pred(gt(edit=small), "GD", False)
        self.assert_pred(gt("N1-1", anon=600 * MIB), "GD", False)                 # N1 would pressure

        def file(inp):
            inp["target_out"]["file_size"] = 512 * MIB
        self.assert_pred(gt(edit=file), "GD", False)

        def not_charged(inp):
            inp["obs"][I_W0]["leaves"]["target"]["memory.current"] = f"{10 * MIB}\n"
        self.assert_pred(gt(edit=not_charged), "GD", False)

        def no_out(inp):
            inp["target_out"] = None
        self.assert_pred(gt(edit=no_out), "GD", None)

    def test_gd_demand_and_fit_isolated(self):
        inp = synth("M1-1")
        obs = [F.parse_obs(t) for t in inp["obs"]]
        big_h = F.Experiment("M1", 2048 * MIB, True, False)            # registered scan, but H above the demand
        r = F.evaluate_gd(obs, big_h, I_W0, inp["target_out"])
        self.assertFalse(r["checks"]["demand_exceeds_high"])
        self.assertIs(r["ok"], False)
        small_h = F.Experiment("N1", 900 * MIB, True, False)           # control whose demand would not fit
        r = F.evaluate_gd([F.parse_obs(t) for t in synth("N1-1")["obs"]], small_h, I_W0, synth("N1-1")["target_out"])
        self.assertFalse(r["checks"]["demand_fits_under_high"])

    def test_unavailable_is_an_abort_and_gi_required_for_m2(self):
        G = gt(edit=lambda i: i["obs"][I_W1]["leaves"]["target"].update({"memory.stat": None}))
        self.assertTrue(any(a.startswith("ground truth unavailable: GM") for a in F.ground_truth_aborts(G)))
        self.assertIn("GI", gt("M2-1")["required"])
        self.assertNotIn("GI", gt("M1-1")["required"])
        G = gt("M2-1", cost_w=60_000)
        self.assertFalse(G["ok"])
        self.assertTrue(any("(GI)" in a for a in F.ground_truth_aborts(G)))

    def test_n2_contention_must_saturate(self):
        G = gt("N2-1", cont_w=0.5)                                      # contender ran, but CPU 18 not saturated
        self.assertTrue(G["GCPU"]["checks"]["contender_ran"])
        self.assertFalse(G["GCPU"]["checks"]["cpu18_saturated"])
        self.assertFalse(G["ok"])

    def test_gm(self):
        self.assert_pred(gt("M2-1", refault_w=50), "GM", False)                  # below REFAULT_MIN
        self.assert_pred(gt("M2-1", refault_b=19_000), "GM", False)              # no rise over B
        self.assert_pred(gt("M2-1", scan_w=0), "GM", False)                      # no reclaim
        self.assert_pred(gt("M2-1", majflt_w=10), "GM", False)                   # target never re-read
        self.assert_pred(gt("N1-1", refault_w=500), "GM", False)                 # control under pressure
        self.assert_pred(gt("E0-open", refault_w=500), "GM", False)

        def no_stat(inp):
            inp["obs"][I_W1]["leaves"]["target"]["memory.stat"] = None
        self.assert_pred(gt(edit=no_stat), "GM", None)

    def test_gi(self):
        self.assert_pred(gt("M2-1", cost_w=60_000), "GI", False)                 # no impact
        G = gt("M1-1", cost_w=60_000)                                           # recorded only for M1
        self.assertFalse(G["GI"]["ok"])
        self.assertTrue(G["ok"])

    def test_gl_oom_and_swap(self):
        self.assert_pred(gt(lab_oom=1), "GL", False)
        G = gt(host_oom=1)
        self.assert_pred(G, "GL", False)
        self.assertTrue(G["host_oom"])
        self.assertIn("HOST OOM: stop the campaign", F.ground_truth_aborts(G))
        self.assert_pred(gt(kswapd=500), "GL", False)
        self.assert_pred(gt(swap_cur=4096), "GL", False)
        self.assertFalse(gt(lab_oom=1)["established"]["memory_pressure"])       # OOM never satisfies ground truth

    def test_gcpu(self):
        self.assert_pred(gt("M2-1", foreign=0.2), "GCPU", False)
        self.assert_pred(gt("M2-1", rd_w=0.2), "GCPU", False)
        self.assert_pred(gt("M2-1", target_cores=0.97), "GCPU", False)           # CPU 18 saturated
        self.assert_pred(gt("N2-1", cont_w=0.1), "GCPU", False)                  # contender did not contend

    def test_gt_gn_gh(self):
        def throttled(inp):
            for o in inp["obs"][10:]:
                o["leaves"]["target"]["cpu.stat"] = o["leaves"]["target"]["cpu.stat"].replace("nr_throttled 0",
                                                                                               "nr_throttled 4")
        self.assert_pred(gt(edit=throttled), "GT", False)
        self.assert_pred(gt(netrx18=0.0001, edit=lambda i: [o.update(ebpf_line=ebpf_line(1, o["mono"], 9e9))
                                                             for o in i["obs"][I_W1:I_W1 + 1]]), "GN", False)

        def netns(inp):
            inp["obs"][-1]["target_netns"]["snmp"] = inp["obs"][-1]["target_netns"]["snmp"].replace("Udp: 0 0", "Udp: 2 0")
        self.assert_pred(gt(edit=netns), "GN", False)
        self.assert_pred(gt(avail=3 << 30), "GH", False)
        self.assert_pred(gt(swap_pages=400), "GH", False)                        # 40 pages/s > 25
        self.assert_pred(gt(slice_mem=0.05), "GH", False)
        self.assert_pred(gt(slice_io=0.05), "GH", False)
        self.assertIs(gt(slice_mem=0.005)["GH"]["ok"], True)

    def test_ground_truth_is_independent_of_m2(self):
        src = "\n".join(l for l in MODULE[MODULE.index("def evaluate(inp"):MODULE.index("def ground_truth_aborts")]
                        .splitlines() if '"""' not in l)                 # code only, not the docstring
        for tok in ("diagnose", "MP.R1", "mp_r1", "snapshot", "psi.mem"):
            self.assertNotIn(tok, src)
        self.assertIn('F.evaluate(F.ground_truth_inputs(R, target_out))', DRIVER)

    def test_immediate_violations(self):
        import importlib
        D = importlib.import_module("r2f_driver")
        inp = synth("M2-1")
        first = inp["obs"][0]
        self.assertEqual(D.immediate_violations(inp["obs"][5], inp["expected"][5], False, first), [])
        bad = copy.deepcopy(inp["obs"][5])
        bad["leaves"]["target"]["memory.events"] = "oom 1\noom_kill 1\n"
        self.assertTrue(any("OOM" in v for v in D.immediate_violations(bad, inp["expected"][5], False, first)))
        bad = copy.deepcopy(inp["obs"][5])
        bad["raw"]["vmstat"] = bad["raw"]["vmstat"].replace("oom_kill 0", "oom_kill 1")
        self.assertTrue(any("HOST OOM" in v for v in D.immediate_violations(bad, inp["expected"][5], False, first)))
        bad = copy.deepcopy(inp["obs"][5])
        bad["tasks"][str(TPID)]["stat"] = stat_text(TPID, "python3", 3)
        self.assertTrue(D.immediate_violations(bad, inp["expected"][5], False, first))
        bad = copy.deepcopy(inp["obs"][5])
        bad["leaves"]["target"]["memory.swap.current"] = "8192\n"
        self.assertTrue(any("swap" in v for v in D.immediate_violations(bad, inp["expected"][5], False, first)))


# ------------------------------------------------------------------------------------------ reproducibility
class TestReproducibility(unittest.TestCase):
    def test_json_round_trip(self):
        for label in ("M1-1", "M2-2", "N1-1", "N2-1", "E0-open"):
            inp = synth(label)
            self.assertEqual(F.evaluate(inp), F.evaluate(json.loads(json.dumps(inp))), label)

    def test_offline_equals_runtime(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            inp = synth("M2-1")
            R = {"label": "M2-1", "observations": inp["obs"], "expected": inp["expected"], "in_w": inp["in_w"],
                 "window": {"obs_index": inp["window"]}, "ebpf_meta_line": META, "signal": inp["signal"],
                 "target": {"pids": [TPID]},
                 "cleanup": {"ok": True, "order": ["terminated", "controls_verified", "bpf_released",
                                                   "scratch_deleted", "cgroups_removed"]},
                 "host_compare": {"ok": True}, "bpf_release": {"released": True}}
            R["ground_truth"] = F.evaluate(F.ground_truth_inputs(R, inp["target_out"]))
            R["GR"] = F.restore_record(R["cleanup"], R["host_compare"], R["bpf_release"])
            (d / "run.json").write_text(json.dumps(R, default=str))
            (d / "target.json").write_text(json.dumps(inp["target_out"]))
            self.assertTrue(F.offline_evaluate(d)["ok"])
            R["observations"][9]["leaves"]["target"]["memory.high"] = "1\n"
            (d / "run.json").write_text(json.dumps(R, default=str))
            self.assertFalse(F.offline_evaluate(d)["ok"])

    def test_every_input_is_persisted_by_the_driver(self):
        for key in ('R["observations"], R["expected"], R["in_w"] = run.obs, run.expected, run.in_w',
                    'R["ebpf_meta_line"] = loader.raw[0]', 'R["signal"] = {"pid": tpy, "t0": t0, "t1": time.monotonic()}',
                    '"obs_index": [i_b0, i_w0, i_w1]', 'self.observe("tick", ebpf_line=self.loader.raw[-1])',
                    'R["memory_writes"].append(host.mem_write(path, value))', 'R["controls"] = host.verify()',
                    "(out / \"raw_ebpf.jsonl\").write_text"):
            self.assertIn(key, DRIVER)
        src = MODULE[MODULE.index("def gt_sample"):MODULE.index("def task_majflt")]
        for raw in ('"/proc/meminfo"', '"/proc/vmstat"', '"/proc/pressure/memory"', '"/proc/pressure/io"',
                    '"/proc/schedstat"', '"/proc/stat"', "LEAF_FILES", '("cpu", "memory", "io")', "/schedstat\")",
                    "ebpf_line"):
            self.assertIn(raw, src)
        for f in ("memory.current", "memory.high", "memory.max", "memory.swap.max", "memory.swap.current",
                  "memory.events", "memory.events.local", "memory.stat", "memory.pressure", "cgroup.procs"):
            self.assertIn(f, F.LEAF_FILES)


# ------------------------------------------------------------------------------------------ workload
class TestTargetWorkload(unittest.TestCase):
    def test_static_constraints(self):
        import ast
        tree = ast.parse(TARGET)
        imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                    for a in (n.names if isinstance(n, ast.Import) else [ast.alias(n.module or "")])}
        self.assertEqual(imported, {"argparse", "ctypes", "errno", "json", "mmap", "os", "resource", "signal", "sys",
                                    "time", "array"})                    # no socket/threading/queue/subprocess
        calls = {n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
                 for n in ast.walk(tree) if isinstance(n, ast.Call)}
        for bad in ("fork", "Thread", "Lock", "Queue", "socket", "system", "popen", "spawnv", "execv"):
            self.assertNotIn(bad, calls, bad)
        self.assertIn("MADV_RANDOM", TARGET)
        self.assertIn("O_EXCL", TARGET)
        self.assertIn("os.fsync", TARGET)
        self.assertIn('state["n"] >= 1 and expanded_at is None', TARGET)

    def test_runs_small_and_expands_exactly_once(self):
        with tempfile.TemporaryDirectory() as t:
            f, out = Path(t) / "ws.bin", Path(t) / "out.json"
            p = subprocess.Popen([sys.executable, "-I", str(ROOT / "scripts" / "r2f_target.py"), "--file", str(f),
                                  "--file-bytes", str(4 * MIB), "--scan-b", str(1 * MIB), "--scan-w", str(4 * MIB),
                                  "--period-ns", "2000000", "--pages-per-cycle", "64", "--cycles", "150",
                                  "--out", str(out)], stdout=subprocess.PIPE, text=True)
            line = p.stdout.readline()
            self.assertTrue(re.fullmatch(r"READY \d+\n", line), line)
            time.sleep(0.05)
            p.send_signal(signal.SIGUSR1)
            time.sleep(0.05)
            p.send_signal(signal.SIGUSR1)
            self.assertEqual(p.wait(10), 0)
            r = json.loads(out.read_text())
            self.assertEqual((r["file_size"], r["scan_b"], r["scan_w"], r["cycles"]), (4 * MIB, MIB, 4 * MIB, 150))
            self.assertEqual(r["sigusr1_count"], 2)
            self.assertIsNotNone(r["expanded_at_cycle"])
            self.assertEqual(len(r["wake_ns"]), 150)
            self.assertEqual(os.stat(f).st_size, 4 * MIB)

    def test_no_expansion_without_signal_and_refuses_existing_file(self):
        with tempfile.TemporaryDirectory() as t:
            f, out = Path(t) / "ws.bin", Path(t) / "out.json"
            args = [sys.executable, "-I", str(ROOT / "scripts" / "r2f_target.py"), "--file", str(f), "--file-bytes",
                    str(2 * MIB), "--scan-b", str(MIB), "--scan-w", str(2 * MIB), "--period-ns", "1000000",
                    "--pages-per-cycle", "16", "--cycles", "20", "--out", str(out)]
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
            r = json.loads(out.read_text())
            self.assertIsNone(r["expanded_at_cycle"])
            self.assertEqual(r["sigusr1_count"], 0)
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)       # O_EXCL
            bad = list(args)
            bad[bad.index("--scan-w") + 1] = str(4 * MIB)
            bad[bad.index("--file") + 1] = str(Path(t) / "other.bin")                    # a fresh file
            r = subprocess.run(bad, capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)                                         # bounded scan range
            self.assertIn("invalid workload geometry", r.stderr)
            self.assertFalse((Path(t) / "other.bin").exists())                         # refused before creating


# ------------------------------------------------------------------------------------------ M2 (unchanged engine)
def whatif(values):
    from sentinelai.diagnostic.contract import EvidenceSnapshot
    from sentinelai.diagnostic.contract.ids import snapshot_id
    snap = EvidenceSnapshot.model_validate_json(SNAP_E0.read_bytes(), strict=False)
    ms = []
    for m in snap.measurements:
        if m.feature_id in values and m.deviation is not None:
            v = values[m.feature_id]
            b, f = m.baseline, m.deviation.floor_used
            m = m.model_copy(update={"value": v, "deviation": m.deviation.model_copy(update={
                "delta": v - b.median, "ratio": v / max(b.median, f), "robust_z": (v - b.median) / max(1.4826 * b.mad, f)})})
        ms.append(m)
    ms = tuple(ms)
    return snap.model_copy(update={"measurements": ms, "snapshot_id": snapshot_id(snap.target, snap.window, ms)})


def m2(snap):
    from r2c_driver import params
    from sentinelai.diagnostic.rules import diagnose
    d = diagnose(snap, params(), code_commit="4aa23b8")
    return d, {i.predicate_id: i for i in d.snapshot.evidence_items}


class TestM2Compatibility(unittest.TestCase):
    def test_mp_r1_psi_path(self):
        d, it = m2(whatif({"psi.mem.some.target": 0.4}))
        self.assertEqual(d.result.decision.value, "memory_pressure")
        self.assertEqual(it["MP.R1"].kind.value, "POSITIVE")

    def test_mp_r1_reclaim_refault_path(self):
        d, it = m2(whatif({"mem.reclaim.target": 30000.0, "mem.refault.target": 20000.0}))
        self.assertEqual(d.result.decision.value, "memory_pressure")

    def test_reclaim_without_refault_is_not_enough(self):
        d, it = m2(whatif({"mem.reclaim.target": 30000.0}))
        self.assertEqual(it["MP.R1"].kind.value, "NEGATIVE")
        self.assertEqual(d.result.decision.value, "INSUFFICIENT_EVIDENCE")

    def test_n1_high_usage_without_pressure(self):
        d, it = m2(whatif({"mem.util.target": 0.95}))
        self.assertEqual(it["MP.R1"].kind.value, "NEGATIVE")
        self.assertEqual(d.result.decision.value, "INSUFFICIENT_EVIDENCE")

    def test_application_bottleneck_never_assertable(self):
        from sentinelai.collectors.snapshot import NOT_COLLECTED_SOURCES
        self.assertIn("APP_METRICS", NOT_COLLECTED_SOURCES)
        d, it = m2(whatif({"psi.mem.some.target": 0.4}))
        self.assertNotEqual(d.result.decision.value, "application_bottleneck")


# ------------------------------------------------------------------------------------------ static / integrity
class TestStaticAndIntegrity(unittest.TestCase):
    def test_safety_threshold_provenance(self):
        T = F.SAFETY_THRESHOLDS
        self.assertEqual(set(T), {"host_MemAvailable_min", "slice_memory_psi_rise", "slice_io_psi_rise", "host_swap_io"})
        for v in T.values():
            self.assertIn(v["class"].split(" (")[0], ("design-derived safety threshold", "previously validated safety "
                                                                                          "threshold"))
            self.assertTrue(v["rationale"])
        self.assertEqual((F.MEM_AVAILABLE_MIN_BYTES, F.SLICE_MEM_PSI_RISE_MAX, F.SLICE_IO_PSI_RISE_MAX,
                          F.SWAP_MAX_PAGES_PER_S), (4 << 30, 0.01, 0.01, 25.0))
        self.assertEqual((F.SLICE_MEM_PSI_RISE_MAX, F.SWAP_MAX_PAGES_PER_S),
                         (C.SLICE_PSI_RISE_MAX, C.SWAP_MAX_PAGES_PER_S))

    def test_matrix(self):
        self.assertEqual(F.MATRIX, ("E0-open", "M1-1", "M1-2", "M1-3", "M2-1", "M2-2", "M2-3", "N1-1", "N1-2",
                                    "N2-1", "N2-2", "E0-close"))
        self.assertEqual(code_lines(WRAPPER).count("BASE=4aa23b8"), 1)

    def test_no_forbidden_mechanism(self):
        for tok in ("swapoff", "swapon", "drop_caches", "/proc/sys/vm", "sysctl -w", "cpu.max\", \"", "tc qdisc",
                    "ethtool -K", "systemctl"):
            self.assertFalse([l for l in code_lines(DRIVER) if tok in l], tok)
            self.assertFalse([l for l in code_lines(WRAPPER) if tok in l and not l.startswith("#")], tok)
        self.assertNotIn("subprocess", DRIVER)
        self.assertNotIn("shell=True", MODULE + DRIVER)
        self.assertEqual(MODULE.count("subprocess.Popen("), 1)                # Host._do spawn only
        self.assertEqual(MODULE.count("os.kill("), 2)                         # SIGUSR1 + SIGKILL, lab-checked
        writes = [l for l in code_lines(MODULE) if 'open(' in l and '"w"' in l]
        self.assertEqual(len(writes), 2)                                      # Host write + mem write, both guarded

    def test_preflight_refusals(self):
        src = MODULE[MODULE.index("def preflight"):MODULE.index("def verify_cgroups")]
        for k in ('"no_sentinel_cgroup"', '"no_scratch_leftover"', '"scratch_parent_ext4"', '"mem_available_ge_4GiB"',
                  '"memory_swap_accounting"', '"nic_irq_off_cpu18"'):
            self.assertIn(k, src)

    def test_compare_host_adds_vm_and_scratch(self):
        base = {"vm": {"vm/swappiness": "60"}, "scratch_present": False, "r2f_lab_present": False}
        with mock.patch.object(F.E, "compare_host", lambda b, o, r=True: {"failed": [], "ok": True}):
            self.assertTrue(F.compare_host(base, dict(base))["ok"])
            self.assertIn("vm_sysctls_identical", F.compare_host(base, {**base, "vm": {"vm/swappiness": "0"}})["failed"])
            self.assertIn("no_scratch", F.compare_host(base, {**base, "scratch_present": True})["failed"])
            self.assertIn("no_r2f_lab", F.compare_host(base, {**base, "r2f_lab_present": True})["failed"])

    @unittest.skipUnless(IN_GIT, "integrity checks need the git checkout")
    def test_protected_files_unchanged(self):
        import hashlib
        git = lambda *a: subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True)
        for p in ("scripts/r2a_lab.py", "scripts/r2b_driver.py", "scripts/r2c_cpu.py", "scripts/r2c_driver.py",
                  "scripts/r2c_target.py", "scripts/r2d_cpu.py", "scripts/r2d_driver.py", "scripts/r2e_softirq.py",
                  "scripts/r2e_driver.py", "scripts/r2e_validate.sh"):
            self.assertEqual((ROOT / p).read_bytes(), git("show", f"4aa23b8:{p}").stdout.encode(), p)
        # test_r2e.py: byte-identical to 4aa23b8, or 4aa23b8 plus exactly the authorised maintenance patch (three
        # hunks below, nothing else): R2-F closeout + Phase 2A.6 test_candidate paths, Phase 2A.6 runtime src exception.
        # The patched file is also pinned by its sha256.
        base_e = git("show", "4aa23b8:tests/faultlab/test_r2e.py").stdout
        hunks = (('        commit it must refuse, and the refusal may name only the closeout artifacts on top of d11e755."""\n',
                  '        commit it must refuse, and the refusal may name only the closeout artifacts on top of d11e755 (plus, after the\n        authorised R2-F closeout commit, exactly the R2-F tooling, report and evidence paths)."""\n'),
                 ('            changed = git("diff", "--name-only", base, "HEAD").stdout.split()\n            others = sorted(p for p in changed if p not in E.TOOLING)\n            self.assertTrue(others and all(closeout(p) for p in others), others)\n',
                  '            # the authorised R2-F closeout (a later phase) adds exactly these paths; nothing else is accepted\n            r2f = lambda p: (re.fullmatch(r"scripts/r2f_[a-z_]+\\.(py|sh)", p) is not None\n                             or p == "tests/faultlab/test_r2f.py"\n                             or re.fullmatch(r"docs/PHASE_1C_R2F_[A-Z0-9_]+\\.md", p) is not None\n                             or p.startswith("results/phase1c_r2f/"))\n            # the authorised Phase 2A.6 closeout adds exactly these paths; nothing else is accepted\n            p2a6 = lambda p: (p in ("README.md", "src/sentinelai/__main__.py")\n                              or re.fullmatch(r"src/sentinelai/runtime/[a-z_]+\\.py", p) is not None\n                              or re.fullmatch(r"tests/runtime/[a-z_]+\\.py", p) is not None\n                              or re.fullmatch(r"docs/PHASE_2A_[A-Z0-9_]+\\.md", p) is not None\n                              or p.startswith("results/phase2a_live/"))\n            # the authorised Phase 1C M4/M5 design revision and G-R2 evidence add exactly these paths; nothing\n            # else is accepted\n            p1c = lambda p: p in ("docs/PHASE_1C_DESIGN.md", "docs/PHASE_1C_M4_M5_PILOT_DESIGN.md",\n                                  "tests/rules/test_design_adv.py", "docs/PHASE_1C_G_R2_EVIDENCE.md")\n            changed = git("diff", "--name-only", base, "HEAD").stdout.split()\n            others = sorted(p for p in changed if p not in E.TOOLING)\n            self.assertTrue(others and all(closeout(p) or r2f(p) or p2a6(p) or p1c(p) for p in others), others)\n'),
                 ('        self.assertEqual(git("diff", "--name-only", "d11e755", "--", "src", "ebpf", "contract").stdout, "")\n',
                  '        # Phase 2A.6: src/ may gain exactly the authorised flat runtime modules and the CLI; nothing else in src,\n        # ebpf or contract may differ from d11e755\n        changed = git("diff", "--name-only", "d11e755", "--", "src", "ebpf", "contract").stdout.split()\n        runtime = lambda p: (p == "src/sentinelai/__main__.py"\n                             or re.fullmatch(r"src/sentinelai/runtime/[a-z_]+\\.py", p) is not None)\n        self.assertEqual([p for p in changed if not runtime(p)], [])\n'))
        patched = base_e
        for old, new in hunks:
            self.assertEqual(patched.count(old), 1, old)
            patched = patched.replace(old, new)
        self.assertEqual(hashlib.sha256(patched.encode()).hexdigest(),
                         '3ab31610a4daaa7a04c94566e41c55d34e8524cbd47e0a609382451bc060f003')
        self.assertIn((ROOT / "tests/faultlab/test_r2e.py").read_text(), (base_e, patched))
        # Phase 2A.6: src/ may gain exactly the authorised flat runtime modules and the CLI; nothing else in src,
        # ebpf or contract may differ from 4aa23b8
        changed = git("diff", "--name-only", "4aa23b8", "--", "src", "ebpf", "contract").stdout.split()
        runtime = lambda p: (p == "src/sentinelai/__main__.py"
                             or re.fullmatch(r"src/sentinelai/runtime/[a-z_]+\.py", p) is not None)
        self.assertEqual([p for p in changed if not runtime(p)], [])
        hist = ("results/phase1c_r2b", "results/phase1c_r2c", "results/phase1c_r2d", "results/phase1c_r2e")
        self.assertEqual(git("diff", "--name-only", "4aa23b8", "--", *hist).stdout, "")      # historical evidence
        self.assertEqual(git("status", "--porcelain", "--", *hist).stdout, "")

    @unittest.skipUnless(IN_GIT, "candidate check needs git")
    def test_candidate_logic(self):
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
            Path(t, "scripts", "r2f_memory.py").write_text("x")
            g("add", ".")
            g("commit", "-qm", "tooling")
            self.assertTrue(F.candidate(t, base)["ok"])
            Path(t, "a.txt").write_text("b")
            self.assertFalse(F.candidate(t, base)["ok"])
            g("commit", "-qam", "other")
            self.assertIn("beyond R2-F tooling", F.candidate(t, base)["reason"])


class ReadOnlySys:
    """Real read-only F.Sys behind a method allowlist (any other attribute is a test failure); the root
    cgroup.subtree_control text is substituted. Records every call."""
    READ_METHODS = ("read", "exists", "listdir", "cgroup_dirs", "tool", "uid_name", "pids", "fstype")

    def __init__(self, root_text):
        self._real, self._root_text, self.calls = F.Sys(), root_text, []

    def __getattr__(self, name):
        if name not in self.READ_METHODS:
            raise AssertionError(f"preflight used non-read method {name}")
        fn = getattr(self._real, name)

        def call(*a):
            self.calls.append((name,) + a)
            if name == "read" and a == (f"{F.CG_ROOT}/cgroup.subtree_control",):
                return self._root_text
            return fn(*a)
        return call


class TestRootControllers(unittest.TestCase):
    """R2-F requires only the controllers its lab enables at the root (subset), never R2-C's exact ROOT_SUBTREE."""
    KEY = "root_subtree_has_r2f_controllers"
    PASS = {"exact R2-F set": "cpuset cpu memory pids",
            "post-reboot host set": "cpuset cpu io memory pids",
            "pre-reboot host set": "cpuset cpu io memory hugetlb pids rdma misc",
            "other order, trailing newline": "pids memory cpu cpuset\n"}
    FAIL = {"missing memory": "cpuset cpu io pids", "missing cpu": "cpuset io memory pids",
            "missing cpuset": "cpu io memory pids", "missing pids": "cpuset cpu io memory",
            "empty": "", "whitespace only": " \n", "unreadable": None, "not a string": 123,
            "bytes": b"cpuset cpu memory pids", "comma separated": "cpuset,cpu,memory,pids",
            "+ prefixes": "+cpuset +cpu +memory +pids", "malformed extra token": "cpuset cpu memory pids io,misc",
            "nul byte": "cpuset cpu memory pids \x00", "two lines": "cpuset cpu\nmemory pids",
            "duplicate": "cpuset cpu memory pids pids", "upper case": "CPUSET CPU MEMORY PIDS"}

    def test_required_set_is_r2f_local(self):
        self.assertEqual(F.REQUIRED_ROOT_CONTROLLERS, frozenset({"cpuset", "cpu", "memory", "pids"}))
        self.assertEqual(F.REQUIRED_ROOT_CONTROLLERS, frozenset(F.CONTROLLERS))       # what the lab enables
        self.assertNotEqual(F.REQUIRED_ROOT_CONTROLLERS, C.ROOT_SUBTREE)
        self.assertEqual(C.ROOT_SUBTREE, frozenset("cpuset cpu io memory hugetlb pids rdma misc".split()))  # R2-C unchanged

    def test_validator(self):
        for name, text in self.PASS.items():
            self.assertIs(F.root_controllers_ok(text), True, name)
        for name, text in self.FAIL.items():
            self.assertIs(F.root_controllers_ok(text), False, name)

    def test_preflight_uses_subset(self):
        for name, text in self.PASS.items():
            self.assertIs(F.preflight(ReadOnlySys(text))["checks"][self.KEY], True, name)
        for name, text in self.FAIL.items():
            pf = F.preflight(ReadOnlySys(text))
            self.assertIs(pf["checks"][self.KEY], False, name)
            self.assertFalse(pf["ok"], name)                                          # missing controller = hard fail

    def test_preflight_ok_depends_on_root_controllers(self):
        """Canned host on which every other preflight check passes: ok flips exactly with the root controller text."""
        reads = {f"{F.CG_ROOT}/cpuset.cpus.effective": "0-23\n", "/proc/meminfo": "MemAvailable: 8388608 kB\n",
                 "/proc/vmstat": "oom_kill 0\n", "/sys/devices/system/cpu/online": "0-23\n",
                 f"/sys/devices/system/cpu/cpu{F.TARGET_CPU}/topology/thread_siblings_list": f"{F.TARGET_CPU}\n",
                 f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list": "21\n"}

        def host(root_text):
            return SimpleNamespace(read=lambda p: root_text if p == f"{F.CG_ROOT}/cgroup.subtree_control" else reads[p],
                                   exists=lambda p: p != F.SCRATCH_BASE, cgroup_dirs=lambda: [], pids=lambda: [],
                                   fstype=lambda p: "ext4", uid_name=lambda u: "lab", tool=lambda t: True)
        for name, text in self.PASS.items():
            pf = F.preflight(host(text))
            self.assertEqual([k for k, v in pf["checks"].items() if v is not True], [], name)
            self.assertIs(pf["ok"], True, name)
        for name, text in self.FAIL.items():
            pf = F.preflight(host(text))
            self.assertEqual([k for k, v in pf["checks"].items() if v is not True], [self.KEY], name)
            self.assertIs(pf["ok"], False, name)

    def test_preflight_read_only_and_other_checks_kept(self):
        s = ReadOnlySys("cpuset cpu io memory pids")
        checks = F.preflight(s)["checks"]
        self.assertIn(("read", f"{F.CG_ROOT}/cgroup.subtree_control"), s.calls)
        self.assertTrue({c[0] for c in s.calls} <= set(ReadOnlySys.READ_METHODS))
        for k in ("root_cpuset_0_23", "no_sentinel_cgroup", "no_lab_process", "no_scratch_leftover",
                  "scratch_parent_ext4", "scratch_parent_not_symlink", "mem_available_ge_4GiB", "page_size_4096",
                  "memory_swap_accounting", "memory_psi_per_cgroup", "vmstat_oom_kill_readable", "cpus_online",
                  "cpu18_no_smt", "nic_irq_off_cpu18", "protected_interfaces_present", "cgroup_kill_supported",
                  "lab_uid_exists", self.KEY):
            self.assertIn(k, checks)
        self.assertNotIn("root_subtree_control_has_memory", checks)

    def test_r2c_exact_set_not_used(self):
        import ast
        tree = ast.parse(MODULE)
        self.assertFalse([n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr == "ROOT_SUBTREE"])
        self.assertFalse([n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "ROOT_SUBTREE"])
        src = MODULE[MODULE.index("def preflight"):MODULE.index("def verify_cgroups")]
        self.assertIn("root_controllers_ok(sysr.read(f\"{CG_ROOT}/cgroup.subtree_control\"))", src)

    @unittest.skipUnless(IN_GIT, "integrity checks need the git checkout")
    def test_r2c_file_unmodified(self):
        out = subprocess.run(["git", "-C", str(ROOT), "show", "4aa23b8:scripts/r2c_cpu.py"], capture_output=True)
        self.assertEqual((ROOT / "scripts" / "r2c_cpu.py").read_bytes(), out.stdout)


class TestDryRun(unittest.TestCase):
    def test_dry_run_guards_and_zero_mutation(self):
        rep = F.dry_run(F.Sys())
        self.assertTrue(rep["zero_mutation"]["ok"], rep["zero_mutation"]["failed"])
        self.assertTrue(all(v is True for v in rep["guards"]["planned_ops_accepted"].values()))
        self.assertTrue(rep["guards"]["forbidden_refused"])
        self.assertTrue(rep["cleanup_simulation"]["ok"])
        self.assertTrue(all(rep["metric_table"].values()))
        self.assertTrue(all(rep["allocation"].values()))

    def test_dry_run_never_instantiates_host(self):
        src = MODULE[MODULE.index("def dry_run"):MODULE.index("def candidate")]
        self.assertNotIn("Host(", src.replace("SimHost(", ""))
        self.assertNotIn(".mem_write(", src)


if __name__ == "__main__":
    unittest.main()
