"""R2-C tooling: the only possible mutations are the design's sentinel-r2c cgroup, its target and contender processes and
their removal; every invalid state ABORTs; ground truth, metric gate, host comparison and cleanup are exercised on
fakes (no test mutates the host, creates a cgroup, starts the target or the contender, or changes affinity)."""

import builtins
import copy
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
_spec = importlib.util.spec_from_file_location("r2c_cpu", ROOT / "scripts" / "r2c_cpu.py")
C = importlib.util.module_from_spec(_spec)
sys.modules["r2c_cpu"] = C
_spec.loader.exec_module(C)
WRAPPER = (ROOT / "scripts" / "r2c_validate.sh").read_text()
DRIVER = (ROOT / "scripts" / "r2c_driver.py").read_text()
TARGET = (ROOT / "scripts" / "r2c_target.py").read_text()
MODULE = (ROOT / "scripts" / "r2c_cpu.py").read_text()
OUT = str(ROOT / "results" / "phase1c_r2c" / "T" / "E2-rep1")


def code_lines(text):
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


# ------------------------------------------------------------------------------------------ fake read-only host
LINKS = [{"ifname": "lo", "flags": ["LOOPBACK", "UP"], "mtu": 65536, "operstate": "UNKNOWN"},
         {"ifname": "enp0s31f6", "flags": ["UP"], "mtu": 1500, "operstate": "UP", "address": "aa:bb:cc:dd:ee:ff",
          "stats64": {"rx": {"packets": 1}}},
         {"ifname": "docker0", "flags": ["UP"], "mtu": 1500, "operstate": "DOWN",
          "linkinfo": {"info_kind": "bridge", "info_data": {"stp_state": 0, "gc_timer": 12.3}}}]
QDISCS = [{"kind": "fq_codel", "dev": "enp0s31f6", "handle": "0:", "root": True, "packets": 5},
          {"kind": "noqueue", "dev": "docker0", "handle": "0:", "root": True}]


class FakeSys:
    """Read-only fake of Sys: files, directory listings, command outputs, cgroup dirs, pids, tools."""

    def __init__(self, files=None, dirs=None, cmds=None, cgroups=None, pids=(), tools=None, uid=True):
        self.files, self.dirs = dict(files or {}), dict(dirs or {})
        self.cmds = cmds if cmds is not None else {
            ("ip", "-j", "-d", "link", "show"): json.dumps(LINKS),
            ("ip", "-j", "addr", "show"): json.dumps([{"ifname": "enp0s31f6", "addr_info": [
                {"family": "inet", "local": "192.168.1.5", "prefixlen": 24}]}]),
            ("ip", "-j", "route", "show"): json.dumps([{"dst": "default", "gateway": "192.168.1.1"}]),
            ("ip", "-j", "-6", "route", "show"): "[]", ("tc", "-j", "qdisc", "show"): json.dumps(QDISCS),
            ("ip", "-j", "netns", "list"): "[]", ("findmnt", "-rn", "-o", "TARGET,FSTYPE"): "/ ext4\n/sys/fs/cgroup cgroup2\n",
            (C.BPFTOOL, "-j", "prog", "show"): "[]", (C.BPFTOOL, "-j", "link", "show"): "[]",
            (C.BPFTOOL, "-j", "map", "show"): "[]", (C.LOADER, "--version"): '{"libbpf_linked":"1.4"}'}
        self.cgroups = list(cgroups if cgroups is not None else ["", "init.scope", "system.slice", "user.slice"])
        self._pids, self.tools, self.uid = list(pids), tools, uid

    def read(self, path):
        return self.files.get(path)

    def listdir(self, path):
        return self.dirs.get(path)

    def exists(self, path):
        return path in self.files or path in self.dirs or path in {f"{C.CG_ROOT}/{d}" for d in self.cgroups}

    def cgroup_dirs(self):
        return sorted(self.cgroups)

    def run(self, argv):
        if tuple(argv) not in C.READ_ONLY_COMMANDS:
            raise C.R2CRefused(argv)
        return self.cmds.get(tuple(argv))

    def tool(self, path):
        return True if self.tools is None else path in self.tools

    def uid_name(self, uid):
        return "iiitd" if self.uid else None

    def pids(self):
        return list(self._pids)


def preflight_files():
    f = {f"{C.CG_ROOT}/cpuset.cpus.effective": "0-23\n",
         f"{C.CG_ROOT}/cgroup.subtree_control": "cpuset cpu io memory hugetlb pids rdma misc\n",
         "/sys/devices/system/cpu/online": "0-23\n",
         "/proc/interrupts": "           CPU0\n 134:   1   IR-PCI-MSI 520192-edge      enp0s31f6\n",
         "/proc/irq/134/effective_affinity_list": "21\n", "/sys/class/net/enp0s31f6": "", "/sys/class/net/docker0": "",
         f"{C.CG_ROOT}/init.scope/cgroup.kill": "", "/proc/pressure/cpu": "some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n"}
    for n in C.PARENT_CPUS:
        f[f"/sys/devices/system/cpu/cpu{n}/topology/thread_siblings_list"] = f"{n}\n"
        f[f"/sys/devices/system/cpu/cpu{n}/topology/cluster_cpus_list"] = "16-19\n" if n < 20 else "20-23\n"
    return f


def lab_files(exp, **over):
    """sysfs of a correctly created lab (before any process joins)."""
    f = {f"{C.LAB_DIR}/cgroup.subtree_control": "cpuset cpu memory pids\n",
         f"{C.LAB_DIR}/cpuset.cpus.effective": "18-19,23\n", f"{C.LAB_DIR}/cpu.max": "max 100000\n",
         f"{C.LAB_DIR}/cgroup.procs": ""}
    cc = str(exp.contender_cpu) if exp.contender_cpu is not None else "18-19,23"
    for d, cpus, w in ((C.TARGET_DIR, "18", "100"), (C.CONTENDER_DIR, cc, str(exp.contender_weight))):
        f.update({f"{d}/cgroup.controllers": "cpuset cpu memory pids\n", f"{d}/pids.max": "4\n", f"{d}/memory.max": "max\n",
                  f"{d}/cpuset.mems.effective": "0\n", f"{d}/cpuset.cpus.effective": cpus + "\n",
                  f"{d}/cpu.max": "max 100000\n", f"{d}/cgroup.procs": "", f"{d}/cpu.weight": w + "\n",
                  f"{d}/cpu.stat": "usage_usec 0\nuser_usec 0\nsystem_usec 0\nnr_periods 0\nnr_throttled 0\n"
                                   "throttled_usec 0\nnr_bursts 0\nburst_usec 0\n"})
    f.update(over)
    return f


class TestDesignConstants(unittest.TestCase):
    def test_cpu_allocation(self):
        self.assertEqual(C.TARGET_CPU, 18)
        self.assertEqual(C.PARENT_CPUS, (18, 19, 23))
        self.assertEqual({k: (e.contender_cpu, e.contender_weight) for k, e in C.EXPERIMENTS.items()},
                         {"E0": (None, 100), "E1": (18, 100), "E2": (18, 400), "N1": (23, 400), "N2": (19, 400)})
        self.assertEqual(C.SUPPORT_CPUS, tuple(range(16)))
        self.assertNotIn(21, C.PARENT_CPUS)
        self.assertTrue(all(C.allocation_checks().values()), C.allocation_checks())

    def test_cgroup_structure_and_timeline(self):
        self.assertEqual(C.LAB_DIR, "/sys/fs/cgroup/sentinel-r2c")
        self.assertEqual(C.TARGET_CGROUP_PATH, "/sentinel-r2c/target")
        self.assertEqual(C.CONTROLLERS, ("cpuset", "cpu", "memory", "pids"))
        self.assertEqual((C.WARMUP_S, C.NB, C.NW, C.RECOVERY_S, C.HARD_TIMEOUT_S), (10, 10, 10, 10, 60))
        self.assertEqual((C.TARGET_PERIOD_NS, C.TARGET_CYCLES, C.TARGET_WORK_NS), (2_000_000, 20_000, 500_000))

    def test_matrix_and_reps(self):
        reps = {k: sum(l.startswith(k) for l in C.MATRIX) for k in C.EXPERIMENTS}
        self.assertEqual(reps, {"E0": 2, "E1": 3, "E2": 3, "N1": 2, "N2": 2})
        self.assertEqual([l[:2] for l in C.MATRIX], ["E0", "N1", "N1", "N2", "N2", "E1", "E1", "E1", "E2", "E2", "E2",
                                                     "E0"])
        self.assertIn("MATRIX=(" + " ".join(C.MATRIX) + ")", WRAPPER)
        with self.assertRaises(C.R2CRefused):
            C.experiment_of("E3-rep1")

    def test_design_thresholds_unchanged(self):
        self.assertEqual((C.G2_CONTENDER_MIN_CORES, C.G3_IDLE_MAX, C.G6_FOREIGN_MAX_CORES, C.HOST_UTIL_B_MAX,
                          C.HOST_PSI_AVG10_MAX), (0.4, 0.05, 0.05, 0.10, 5.0))

    def test_approved_criteria_and_labels(self):
        self.assertEqual((C.G4_N_MIN, C.G4_RATIO_MIN, C.G4_ABS_MIN_NS), (4000, 1.5, 50_000))
        self.assertEqual(C.G7_SOFTIRQ_MAX_DELTA, 0.01)
        self.assertEqual((C.MEM_PSI_W_MAX_US, C.SWAP_MAX_PAGES_PER_S), (0, 25.0))
        self.assertEqual((C.HOST_PSI_AVG10_MAX, C.SLICE_AVG10_MAX, C.SLICE_PSI_RISE_MAX), (5.0, 5.0, 0.01))
        self.assertEqual(C.SLICES, ("system.slice", "user.slice", "init.scope"))
        self.assertEqual({k: v["type"] for k, v in C.CRITERIA.items()},
                         {"G4": "EXPERIMENTAL HEURISTIC", "G7": "SAFETY THRESHOLD, repository-informed",
                          "MEMORY_PSI": "REPOSITORY-SUPPORTED", "MEMORY_SWAP": "SAFETY THRESHOLD, repository-informed",
                          "HOST_PSI": "SAFETY THRESHOLD", "SLICE_PSI": "SAFETY THRESHOLD"})
        self.assertNotRegex(json.dumps(C.CRITERIA).lower(), r"calibrat")


class TestParameterIntegrity(unittest.TestCase):
    def test_validation_numbers_reused_unchanged(self):
        import r2b_driver as B
        import r2c_driver as D
        p, q = D.params(), B.params()
        self.assertEqual(p.numbers, q.numbers)
        self.assertEqual(p.reasons("KFREE_REASONS_LOSS"), q.reasons("KFREE_REASONS_LOSS"))
        self.assertEqual(p.num("SAT_MIN"), 0.9)
        self.assertEqual(p.num("RT_FRAC_MIN"), 0.01)
        self.assertEqual(json.loads((ROOT / "src/sentinelai/diagnostic/contract/data/parameters.json").read_text())
                         ["status"], "UNCALIBRATED")
        self.assertNotRegex(DRIVER, r"NUMBERS\[[^\]]+\]\s*=")          # never reassigned


class TestCpuSets(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(C.parse_cpulist("18-19,23\n"), {18, 19, 23})
        self.assertEqual(C.parse_cpulist("0-23"), set(range(24)))
        self.assertEqual(C.parse_cpulist(""), set())
        for bad in ("18-", "a", "19-18", "1,,2"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                C.parse_cpulist(bad)
        self.assertEqual(C.cpus_text({23, 18, 19}), "18,19,23")

    def test_task_processor(self):
        rest = ["S"] + ["0"] * 35 + ["18"] + ["0"] * 13
        self.assertEqual(C.task_processor("42 (we ird) comm) " + " ".join(rest)), 18)
        self.assertIsNone(C.task_processor(None))


# ------------------------------------------------------------------------------------------ guards
class TestMutationGuard(unittest.TestCase):
    def test_every_planned_operation_is_allowed(self):
        for label in C.MATRIX:
            exp = C.experiment_of(label)
            for op in C.setup_plan(exp):
                C.check_op(op, exp)
            for op in (("write", f"{C.LAB_DIR}/cgroup.kill", "1"), ("rmdir", C.CONTENDER_DIR), ("rmdir", C.LAB_DIR),
                       ("kill", 1234)):
                C.check_op(op, exp)

    def test_setup_order(self):
        ops = C.setup_plan(C.EXPERIMENTS["E2"])
        self.assertEqual(ops[:4], [("mkdir", C.LAB_DIR), ("write", f"{C.LAB_DIR}/cpuset.mems", "0"),
                                   ("write", f"{C.LAB_DIR}/cpuset.cpus", "18,19,23"),
                                   ("write", f"{C.LAB_DIR}/cgroup.subtree_control", "+cpuset +cpu +memory +pids")])
        self.assertNotIn(("write", f"{C.CONTENDER_DIR}/cpuset.cpus", "18"), C.setup_plan(C.EXPERIMENTS["E0"]))
        self.assertFalse([op for op in ops if "cpu.max" in op[1]])

    def test_forbidden_operations_refused(self):
        e2, e0 = C.EXPERIMENTS["E2"], C.EXPERIMENTS["E0"]
        bad = [
            ("write", f"{C.TARGET_DIR}/cpu.max", "50000 100000"),          # CPU quota
            ("write", f"{C.CONTENDER_DIR}/cpu.max", "max 100000"),         # even the default value
            ("write", f"{C.LAB_DIR}/cpu.max", "max 100000"),
            ("write", f"{C.CG_ROOT}/cpuset.cpus", "0-23"),                 # root cpuset
            ("write", f"{C.CG_ROOT}/cgroup.subtree_control", "-cpu"),
            ("write", f"{C.CG_ROOT}/system.slice/cpu.weight", "100"),      # an existing cgroup
            ("write", f"{C.TARGET_DIR}/cpuset.cpus", "21"),                # NIC IRQ CPU
            ("write", f"{C.TARGET_DIR}/cpuset.cpus", "0-23"),
            ("write", f"{C.CONTENDER_DIR}/cpuset.cpus", "23"),             # N1 placement in an E2 run
            ("write", f"{C.CONTENDER_DIR}/cpu.weight", "10000"),
            ("write", f"{C.TARGET_DIR}/memory.max", "100M"),               # memory fault
            ("write", f"{C.TARGET_DIR}/cgroup.procs", "1"),                # moving a foreign process in
            ("write", "/proc/sys/kernel/sched_schedstats", "1"),           # sysctl
            ("write", "/proc/irq/134/smp_affinity_list", "18"),            # IRQ affinity
            ("write", f"{C.LAB_DIR}/../system.slice/cpu.max", "1 100000"),
            ("mkdir", f"{C.CG_ROOT}/system.slice/sentinel-r2c"), ("mkdir", f"{C.CG_ROOT}/sentinel-r2c-2"),
            ("rmdir", f"{C.CG_ROOT}/user.slice"), ("kill", 1), ("kill", 0), ("kill", True),
            ("exec", "sysctl", "-w"), ("taskset", 18, 1234), ("tc", "qdisc", "add", "dev", "enp0s31f6"),
            ("spawn", "contender", ["stress-ng", "--cpu", "0"]),
            ("spawn", "contender", C.contender_argv(OUT + "/c") + ["--x"]),
            ("spawn", "contender", C.CONTENDER_PREFIX + ["while 1: pass", OUT + "/c"]),
            ("spawn", "contender", ["chrt", "-f", "99"] + C.contender_argv(OUT + "/c")),
            ("spawn", "contender", C.contender_argv("/tmp/c")),           # output outside results
            ("spawn", "target", [x for x in C.target_argv(1000, OUT + "/t") if x not in ("unshare", "--net")]),
            ("spawn", "target", C.target_argv(1000, OUT + "/t")[4:]),         # no timeout wrapper
            ("spawn", "target", C.target_argv(1000, OUT + "/t")[4:8] + C.WRAPPER       # timeout inside the cgroup
             + C.target_argv(1000, OUT + "/t")[8:]),
            ("spawn", "contender", C.contender_argv(OUT + "/c")[4:8] + C.WRAPPER + C.contender_argv(OUT + "/c")[8:]),
            ("spawn", "target", C.target_argv(999, OUT + "/t")),           # iterations differ from the run's
            ("spawn", "target", [x.replace("target/cgroup.procs", "contender/cgroup.procs")
                                 for x in C.target_argv(1000, OUT + "/t")]),
            ("spawn", "calibration", C.target_argv(1000, OUT + "/t")),
            ("write", f"{C.TARGET_DIR}/cpuset.cpus", "18 enp0s31f6"),
        ]
        for op in bad:
            with self.subTest(op=op), self.assertRaises(C.R2CRefused):
                C.check_op(op, e2, 1000)
        with self.assertRaises(C.R2CRefused):                              # no contender in E0
            C.check_op(("spawn", "contender", C.contender_argv(OUT + "/c")), e0, 1000)
        with self.assertRaises(C.R2CRefused):                              # target without fixed iterations
            C.check_op(("spawn", "target", C.target_argv(1000, OUT + "/t")), e2, None)
        C.check_op(("spawn", "target", C.target_argv(1000, OUT + "/t")), e2, 1000)
        C.check_op(("spawn", "contender", C.contender_argv(OUT + "/c")), e2, 1000)
        C.check_op(("spawn", "calibration", C.calibration_argv(OUT + "/cal.json")), e0, None)

    def test_protected_interfaces_refused_by_their_own_check(self):
        for p in C.PROTECTED:
            with self.subTest(p=p), self.assertRaisesRegex(C.R2CRefused, "protected interface"):
                C.check_op(("write", f"{C.TARGET_DIR}/cpu.weight", p), C.EXPERIMENTS["E1"])

    def test_spawn_shapes(self):
        t = C.target_argv(1234, OUT + "/target.json")
        self.assertEqual(t[:4], ["timeout", "-s", "KILL", "60"])                      # wrapper outside the cgroup
        self.assertEqual(t[4:8], ["sh", "-c", 'echo $$ > /sys/fs/cgroup/sentinel-r2c/target/cgroup.procs && exec "$@"',
                                  "sh"])                                              # join before workload code
        i = t.index
        self.assertTrue(i("timeout") < i("sh") < i("unshare") < i("setpriv") < i(C.PYTHON))   # netns before uid drop
        self.assertEqual(t.count("timeout"), 1)
        self.assertEqual(t[i("unshare"):i("unshare") + 3], ["unshare", "--net", "--"])
        self.assertIn("--reuid=1000", t)
        c = C.contender_argv(OUT + "/c")
        self.assertNotIn("unshare", c)
        self.assertEqual(c[:4], ["timeout", "-s", "KILL", "60"])
        self.assertEqual(c.count("timeout"), 1)
        for argv, leaf in ((t, C.TARGET_DIR), (c, C.CONTENDER_DIR),
                           (C.calibration_argv(OUT + "/cal.json"), C.TARGET_DIR)):
            self.assertTrue(C.spawn_structure(argv, leaf)["ok"], C.spawn_structure(argv, leaf))
        self.assertFalse(C.spawn_structure(t, C.CONTENDER_DIR)["ok"])
        for argv in (t, c):
            for word in ("chrt", "nice", "taskset", "stress", "cpu.max", "sysctl", "tc"):
                self.assertNotIn(word, argv)
        with self.assertRaises(C.R2CRefused):
            C.target_argv(0, OUT)
        with self.assertRaises(C.R2CRefused):
            C.target_argv(True, OUT)

    def test_host_validates_before_executing_and_logs(self):
        with tempfile.TemporaryDirectory() as d, mock.patch("os.mkdir") as mk, mock.patch("os.kill") as kill, \
                mock.patch("subprocess.Popen") as popen:
            log = os.path.join(d, "ops.jsonl")
            popen.return_value.pid = 999
            h = C.Host(C.EXPERIMENTS["E1"], log, 1000, FakeSys())
            for op in (("mkdir", f"{C.CG_ROOT}/system.slice/x"), ("write", f"{C.TARGET_DIR}/cpu.max", "1 2"),
                       ("spawn", "contender", ["stress-ng"])):
                with self.assertRaises(C.R2CRefused):
                    h.apply(op)
            mk.assert_not_called()
            popen.assert_not_called()
            self.assertFalse(os.path.exists(log))                         # refused: not even an intent
            h.apply(("mkdir", C.LAB_DIR))
            mk.assert_called_once_with(C.LAB_DIR)
            h.apply(("kill", 4242))                                       # not a lab process: never signalled
            kill.assert_not_called()
            h.sys.files["/proc/4243/cgroup"] = "0::/sentinel-r2c/target\n"
            h.apply(("kill", 4243))
            kill.assert_called_once()
            h.apply(("spawn", "contender", C.contender_argv(OUT + "/c")))
            self.assertIs(popen.call_args.kwargs["shell"], False)
            with open(log) as fh:
                phases = [json.loads(l)["phase"] for l in fh]
            self.assertEqual(phases, ["intent", "result"] * 4)


# ------------------------------------------------------------------------------------------ preflight / lab
class TestPreflight(unittest.TestCase):
    def test_ok(self):
        r = C.preflight(FakeSys(preflight_files()))
        self.assertTrue(r["ok"], [k for k, v in r["checks"].items() if not v])

    def test_refusals(self):
        cases = {
            "existing sentinel cgroup": dict(cgroups=["", "system.slice", "sentinel-r2c"]),
            "nested sentinel cgroup": dict(cgroups=["", "system.slice", "system.slice/sentinel-x"]),
            "root cpuset changed": dict(files={f"{C.CG_ROOT}/cpuset.cpus.effective": "0-15"}),
            "root controllers changed": dict(files={f"{C.CG_ROOT}/cgroup.subtree_control": "memory pids"}),
            "NIC IRQ on CPU 18": dict(files={"/proc/irq/134/effective_affinity_list": "18"}),
            "NIC IRQ on CPU 23": dict(files={"/proc/irq/134/effective_affinity_list": "22-23"}),
            "IRQ 134 is not the NIC": dict(files={"/proc/interrupts": " 134:   1   IR-PCI-MSI   nvme0q1\n"}),
            "SMT sibling": dict(files={"/sys/devices/system/cpu/cpu18/topology/thread_siblings_list": "18-19"}),
            "CPU offline": dict(files={"/sys/devices/system/cpu/online": "0-17"}),
            "docker0 missing": dict(drop="/sys/class/net/docker0"),
            "no PSI": dict(drop="/proc/pressure/cpu"),
            "tool missing": dict(tools={"/usr/bin/python3"}),
            "uid missing": dict(uid=False),
            "lab process exists": dict(pids=[77], files={"/proc/77/cgroup": "0::/sentinel-r2c/target\n"}),
        }
        for name, case in cases.items():
            with self.subTest(name):
                f = preflight_files()
                f.update(case.get("files", {}))
                f.pop(case.get("drop", ""), None)
                s = FakeSys(f, cgroups=case.get("cgroups"), tools=case.get("tools"), uid=case.get("uid", True),
                            pids=case.get("pids", ()))
                self.assertFalse(C.preflight(s)["ok"])


class TestLabVerification(unittest.TestCase):
    def test_ok_for_every_experiment(self):
        for k, exp in C.EXPERIMENTS.items():
            with self.subTest(k):
                r = C.verify_lab(FakeSys(lab_files(exp)), exp)
                self.assertTrue(r["ok"], [x for x, v in r["checks"].items() if not v])

    def test_invalid_lab_aborts(self):
        e2 = C.EXPERIMENTS["E2"]
        cases = {
            "missing cpu controller in parent": {f"{C.LAB_DIR}/cgroup.subtree_control": "cpuset memory pids"},
            "missing cpu controller in target": {f"{C.TARGET_DIR}/cgroup.controllers": "cpuset memory pids"},
            "extra controller": {f"{C.LAB_DIR}/cgroup.subtree_control": "cpuset cpu io memory pids"},
            "incorrect target cpuset": {f"{C.TARGET_DIR}/cpuset.cpus.effective": "18-19"},
            "incorrect contender cpuset": {f"{C.CONTENDER_DIR}/cpuset.cpus.effective": "23"},
            "incorrect parent cpuset": {f"{C.LAB_DIR}/cpuset.cpus.effective": "18-23"},
            "CPU quota on target": {f"{C.TARGET_DIR}/cpu.max": "50000 100000"},
            "CPU quota on contender": {f"{C.CONTENDER_DIR}/cpu.max": "90000 100000"},
            "CPU quota on parent": {f"{C.LAB_DIR}/cpu.max": "100000 100000"},
            "memory limit": {f"{C.TARGET_DIR}/memory.max": "1073741824"},
            "weight": {f"{C.CONTENDER_DIR}/cpu.weight": "100"},
            "pids.max": {f"{C.TARGET_DIR}/pids.max": "max"},
            "process already inside": {f"{C.TARGET_DIR}/cgroup.procs": "123\n"},
            "throttle fields absent (no cpu controller)": {f"{C.TARGET_DIR}/cpu.stat": "usage_usec 0\n"},
        }
        for name, over in cases.items():
            with self.subTest(name):
                self.assertFalse(C.verify_lab(FakeSys(lab_files(e2, **over)), e2)["ok"])


# ------------------------------------------------------------------------------------------ ground truth
HZ = 100
WARM, REC = 2, 2
I_B0, I_W0, I_W1 = WARM, WARM + C.NB, WARM + C.NB + C.NW
N_OBS = I_W1 + 1 + REC
TPIDS, CPIDS = [501], [601]                # one pid per leaf: the workload (its timeout wrapper is outside)


class LabWorld:
    """Kernel files of one run, per observation index (1 s apart), rendered from per-second rates."""

    def __init__(self, exp, **over):
        self.exp = exp
        e = exp.contender_cpu is not None
        on18 = exp.contender_cpu == 18
        self.r = {   # (B rate, W rate) per second
            "cpu18.busy": (27, 100 if on18 else 27), "cpu18.idle": (73, 0 if on18 else 73), "cpu18.softirq": (1, 1),
            # precise task run time on CPU 18 (ns/s): target 0.25 + foreign 0.02 (+ contender 0.73 when on CPU 18)
            "cpu18.rq": (270_000_000, 1_000_000_000 if on18 else 270_000_000),
            "cpuc.busy": (2, 100), "all.busy": (100, 175 if e else 100), "all.total": (2400, 2400),
            "t.usage": (250_000, 250_000), "c.usage": (0, 730_000 if on18 else (980_000 if e else 0)),
            "t.periods": (0, 0), "t.throttled": (0, 0), "t.throttled_usec": (0, 0), "c.periods": (0, 0),
            "c.throttled": (0, 0), "c.throttled_usec": (0, 0), "t.psi": (100, 50_000 if on18 else 100),
            "host.psi": (10, 500), "mem.psi": (0, 0), "swap": (0, 0), "slice": (0, 0), "net": (0, 0),
            "mem.high": (0, 0), "mem.oom_kill": (0, 0),
        }
        self.avg10, self.slice_avg10, self.irq, self.cpu_max = 0.5, 0.0, "21", "max 100000"
        self.tproc, self.cproc = 18, exp.contender_cpu
        self.r.update(over)
        self.overrides = {}          # obs index -> {path: text}

    def in_w(self, k):
        return I_W0 < k <= I_W1

    def c(self, key, k):
        b, w = self.r[key]
        return 1_000_000 + sum(w if self.in_w(j) else b for j in range(1, k + 1))

    def files(self, k):
        cc = self.exp.contender_cpu
        cpu = lambda n, busy, idle, si: f"cpu{n} {busy - si} 0 0 {idle} 0 0 {si} 0 0 0"
        stat = [f"cpu  {self.c('all.busy', k)} 0 0 {self.c('all.total', k) - self.c('all.busy', k)} 0 0 0 0 0 0",
                cpu(18, self.c("cpu18.busy", k), self.c("cpu18.idle", k), self.c("cpu18.softirq", k))]
        for n in (19, 23):
            stat.append(cpu(n, self.c("cpuc.busy", k) if n == cc else 1000, 5000, 3))
        f = {"/proc/stat": "\n".join(stat) + "\n",
             "/proc/schedstat": ("version 15\ntimestamp 4660604175\n"
                                 f"cpu18 0 0 0 0 0 0 {self.c('cpu18.rq', k)} 24876201087 27352777\n"
                                 "domain0 00000 0 0 0 0 0 0 0 0\n"
                                 "cpu19 0 0 0 0 0 0 1000 2000 3\ncpu23 0 0 0 0 0 0 1000 2000 3\n"),
             f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list": self.irq + "\n",
             "/proc/pressure/cpu": f"some avg10={self.avg10:.2f} avg60=0.00 avg300=0.00 total={self.c('host.psi', k)}\n"
                                   "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
             "/proc/pressure/memory": f"some avg10=0.00 avg60=0.00 avg300=0.00 total={self.c('mem.psi', k)}\n"
                                      "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
             "/proc/vmstat": f"nr_free_pages 1\npswpin {self.c('swap', k)}\npswpout 7\n"}
        for s in C.SLICES:
            f[f"{C.CG_ROOT}/{s}/cpu.pressure"] = (f"some avg10={self.slice_avg10:.2f} avg60=0.00 avg300=0.00 "
                                                  f"total={self.c('slice', k)}\n")
        contender_present = cc is not None and I_W0 < k <= I_W1
        for name, d, pids, pre in (("parent", C.LAB_DIR, [], None), ("target", C.TARGET_DIR, TPIDS, "t"),
                                   ("contender", C.CONTENDER_DIR, CPIDS if contender_present else [], "c")):
            f[f"{d}/cpu.max"] = self.cpu_max + "\n"
            f[f"{d}/cgroup.procs"] = "".join(f"{p}\n" for p in pids)
            if pre:
                f[f"{d}/cpuset.cpus.effective"] = ("18" if pre == "t" else (str(cc) if cc else "18-19,23")) + "\n"
                f[f"{d}/cpu.stat"] = (f"usage_usec {self.c(pre + '.usage', k)}\nnr_periods {self.c(pre + '.periods', k)}\n"
                                      f"nr_throttled {self.c(pre + '.throttled', k)}\n"
                                      f"throttled_usec {self.c(pre + '.throttled_usec', k)}\n")
                f[f"{d}/cpu.pressure"] = f"some avg10=0.00 avg60=0.00 avg300=0.00 total={self.c(pre + '.psi', k)}\n" \
                    if pre == "t" else "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
                f[f"{d}/memory.events"] = (f"low 0\nhigh {self.c('mem.high', k)}\nmax 0\noom 0\n"
                                           f"oom_kill {self.c('mem.oom_kill', k)}\n")
            else:
                f[f"{d}/cpu.stat"] = "usage_usec 0\n"
            for p in pids:
                proc = self.tproc if pre == "t" else self.cproc
                f[f"/proc/{p}/stat"] = f"{p} (python3) " + " ".join(["S"] + ["0"] * 35 + [str(proc)] + ["0"] * 13)
        f[f"/proc/{TPIDS[0]}/net/dev"] = ("Inter-|\n face |\n    lo:" + f" {self.c('net', k)} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
        f[f"/proc/{TPIDS[0]}/net/snmp"] = ("Tcp: InSegs OutSegs RetransSegs\nTcp: 0 0 0\n"
                                           "Udp: InDatagrams OutDatagrams\nUdp: 0 0\n")
        f.update(self.overrides.get(k, {}))
        return f

    def observations(self):
        obs, expected, in_w = [], [], []
        for k in range(N_OBS):
            t = C.gt_sample(FakeSys(self.files(k)), float(k), TPIDS[0])
            obs.append(t)
            win = I_W0 < k <= I_W1
            expected.append({"target": TPIDS, "contender": CPIDS if win and self.exp.contender_cpu is not None else []})
            in_w.append(win)
        return obs, expected, in_w

    def target_out(self, late_b=10_000, late_w=400_000):
        per, t0 = C.TARGET_PERIOD_NS, 0
        n = int(N_OBS * 1e9 / per)
        wake = [t0 + k * per + (late_w if I_W0 * 1e9 <= t0 + k * per < I_W1 * 1e9 else late_b) for k in range(n)]
        return {"t0_ns": t0, "period_ns": per, "wake_ns": wake, "done_ns": [w + 500_000 for w in wake]}


def evaluate(world, target_out=None):
    obs, expected, in_w = world.observations()
    G = C.evaluate_ground_truth(obs, I_B0, I_W0, I_W1, world.exp, expected, in_w,
                                target_out if target_out is not None else world.target_out(), HZ)
    return G, C.ground_truth_aborts(G, world.exp) + C.host_level_aborts(obs, I_B0, I_W0, I_W1), obs


class TestGroundTruth(unittest.TestCase):
    def test_contention_established_e1_e2(self):
        for k in ("E1", "E2"):
            with self.subTest(k):
                G, aborts, _ = evaluate(LabWorld(C.EXPERIMENTS[k]))
                self.assertEqual(aborts, [])
                self.assertTrue(G["established"], G)
                self.assertAlmostEqual(G["G2"]["contender_cores_w"], 0.73)
                self.assertAlmostEqual(G["G3"]["cpu18_idle_frac_w"], 0.0)
                self.assertAlmostEqual(G["G6"]["foreign_cores_b"], 0.02)
                self.assertAlmostEqual(G["G6"]["foreign_cores_w"], 0.02)
                self.assertEqual(G["G4"]["lateness_b"]["lateness_median_ns"], 10_000)
                self.assertEqual(G["G4"]["lateness_w"]["lateness_median_ns"], 400_000)
                self.assertTrue(G["G4"]["psi_w_above_b"])

    def test_negative_controls_and_baseline(self):
        for k in ("N1", "N2", "E0"):
            with self.subTest(k):
                G, aborts, _ = evaluate(LabWorld(C.EXPERIMENTS[k]), target_out=LabWorld(C.EXPERIMENTS[k]).target_out(
                    late_w=10_000))
                self.assertTrue(G["G1"]["ok"] and G["G5"]["ok"] and G["G6"]["ok"] and G["G7"]["ok"], G)
                self.assertFalse(G["G3"]["applies"])
                self.assertEqual(G["G2"]["ok"], True)
                self.assertNotIn("G3", " ".join(aborts))

    def test_g4_approved_criterion(self):
        e1 = C.EXPERIMENTS["E1"]
        w = LabWorld(e1)
        cases = {   # (late_b, late_w) ns -> shift
            "clear shift": (10_000, 400_000, True),
            "exact boundary (1.5x and +50 us)": (100_000, 150_000, True),
            "ratio met, margin 49 us": (10_000, 59_000, False),
            "margin met, ratio 1.49": (200_000, 298_000, False),
            "no change": (60_000, 60_000, False),
            "W below B": (60_000, 20_000, False),
        }
        for name, (lb, lw, shift) in cases.items():
            with self.subTest(name):
                G, aborts, _ = evaluate(w, target_out=w.target_out(late_b=lb, late_w=lw))
                self.assertEqual(G["G4"]["status"], "EVALUATED")
                self.assertEqual(G["G4"]["shift"], shift)
                self.assertEqual(G["G4"]["ok"], shift)                # psi_w > psi_b holds in this world
                self.assertTrue(G["computable"])
                self.assertEqual(aborts, [])                         # G4 FALSE is not a safety abort
                self.assertEqual(G["established"], shift)
        G, aborts, _ = evaluate(LabWorld(e1, **{"t.psi": (100, 100)}))   # shift but no PSI rise
        self.assertTrue(G["G4"]["shift"])
        self.assertFalse(G["G4"]["ok"])
        self.assertEqual(aborts, [])

    def test_g4_insufficient_samples_is_unavailable_and_aborts(self):
        w = LabWorld(C.EXPERIMENTS["E1"])
        out = w.target_out()
        per = out["period_ns"]
        lw = C.lateness_stats(out, int(I_W0 * 1e9), int(I_W1 * 1e9))
        self.assertEqual(lw["n"], 5000)
        cut = int((I_W0 * 1e9 + 3999 * per) / per)               # the target stopped after 3999 W cycles
        trimmed = dict(out, wake_ns=out["wake_ns"][:cut], done_ns=out["done_ns"][:cut])
        G, aborts, _ = evaluate(w, target_out=trimmed)
        self.assertEqual(G["G4"]["lateness_w"]["n"], 3999)
        self.assertEqual(G["G4"]["status"], "UNAVAILABLE")
        self.assertIsNone(G["G4"]["ok"])
        self.assertTrue(any(a.startswith("independent ground truth unavailable") for a in aborts), aborts)

    def test_invalid_states_abort(self):
        e1 = C.EXPERIMENTS["E1"]

        def world(**kw):
            w = LabWorld(kw.pop("exp", e1), **kw.pop("rates", {}))
            for k, v in kw.items():
                setattr(w, k, v)
            return w

        def moved(path, text, ks):
            w = LabWorld(e1)
            for k in ks:
                w.overrides[k] = {path: text}
            return w
        cases = {
            "target outside CPU set": world(tproc=17),
            "contender outside CPU set": world(cproc=19),
            "negative control shares the target CPU": world(exp=C.EXPERIMENTS["N1"], cproc=18),
            "target cpuset changed": moved(f"{C.TARGET_DIR}/cpuset.cpus.effective", "18-19\n", [5]),
            "contender cpuset changed": moved(f"{C.CONTENDER_DIR}/cpuset.cpus.effective", "19\n", [15]),
            "foreign process in target cgroup": moved(f"{C.TARGET_DIR}/cgroup.procs", "501\n999\n", [3]),
            "timeout wrapper inside target cgroup": moved(f"{C.TARGET_DIR}/cgroup.procs", "500\n501\n", [6]),
            "process in the lab parent": moved(f"{C.LAB_DIR}/cgroup.procs", "77\n", [4]),
            "contender before W": moved(f"{C.CONTENDER_DIR}/cgroup.procs", "601\n", [5]),
            "CPU quota present": world(cpu_max="50000 100000"),
            "throttling detected": world(rates={"t.throttled": (1, 1), "t.periods": (10, 10),
                                                "t.throttled_usec": (100, 100)}),
            "contender throttled": world(rates={"c.throttled_usec": (0, 5)}),
            "contender too weak": world(rates={"c.usage": (0, 300_000)}),
            "CPU 18 idle in W": world(rates={"cpu18.rq": (270_000_000, 800_000_000)}),
            "foreign busy on CPU 18 in B": world(rates={"cpu18.rq": (400_000_000, 1_000_000_000)}),
            "foreign busy on CPU 18 in W": world(rates={"c.usage": (0, 600_000)}),
            "IRQ affinity change onto lab CPU": world(irq="18"),
            "IRQ moved to 23 once": moved(f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list", "23\n", [20]),
            "unexpected network activity": world(rates={"net": (0, 64)}),
            "memory pressure (events)": world(rates={"mem.high": (0, 1)}),
            "memory pressure (oom kill)": world(rates={"mem.oom_kill": (0, 1)}),
            "memory pressure (psi rising)": world(rates={"mem.psi": (0, 1000)}),
            "memory pressure (1 us psi)": world(rates={"mem.psi": (0, 1)}),
            "swap I/O above 25 pages/s": world(rates={"swap": (0, 26)}),
            "host busy in B": world(rates={"all.busy": (300, 300)}),
            "host psi above 5% and slice avg10 above 5": world(avg10=7.5, slice_avg10=5.5),
            "non-lab slice pressure rising": world(rates={"slice": (0, 10_500)}),
            "softirq changed": world(rates={"cpu18.softirq": (1, 30)}),
            "metric source unreadable": moved("/proc/stat", None, [12]),
        }
        for name, w in cases.items():
            with self.subTest(name):
                G, aborts, _ = evaluate(w)
                self.assertTrue(aborts, f"{name}: no abort; G={G}")

    def test_approved_boundaries_tolerate_noise(self):
        e1 = C.EXPERIMENTS["E1"]
        quiet = {
            "softirq delta exactly 0.01": LabWorld(e1, **{"cpu18.softirq": (1, 2)}),
            "softirq decrease within 0.01": LabWorld(e1, **{"cpu18.softirq": (2, 1)}),
            "swap noise 3 pages/s (historical)": LabWorld(e1, swap=(0, 3)),
            "swap exactly 25 pages/s": LabWorld(e1, swap=(0, 25)),
            "slice rise 0.009": LabWorld(e1, slice=(0, 9_000)),
            "slice decrease": LabWorld(e1, slice=(20_000, 0)),
            "slice rise from a non-zero B within 0.01": LabWorld(e1, slice=(5_000, 14_000)),
        }
        w = LabWorld(e1)
        w.avg10 = 9.0                              # host above 5 % but every non-lab slice at or below 5.0
        w.slice_avg10 = 5.0
        quiet["host avg10 9 %, slices 5.0"] = w
        for name, w in quiet.items():
            with self.subTest(name):
                G, aborts, _ = evaluate(w)
                self.assertEqual(aborts, [])
                self.assertTrue(G["established"])

    def test_approved_boundaries_abort(self):
        e1 = C.EXPERIMENTS["E1"]
        w = LabWorld(e1)
        w.avg10 = 9.0
        w.overrides[14] = {f"{C.CG_ROOT}/user.slice/cpu.pressure": None}
        cases = {
            "softirq delta 0.02": (LabWorld(e1, **{"cpu18.softirq": (1, 3)}), "softirq"),
            "swap 26 pages/s": (LabWorld(e1, swap=(0, 26)), "swap I/O"),
            "memory psi 1 us": (LabWorld(e1, **{"mem.psi": (0, 1)}), "memory PSI"),
            "slice rise 0.0105": (LabWorld(e1, slice=(0, 10_500)), "rose in W"),
            "host > 5 % and a slice unreadable": (w, "unreadable"),
        }
        for name, (w, needle) in cases.items():
            with self.subTest(name):
                _, aborts, _ = evaluate(w)
                self.assertTrue(any(needle in a for a in aborts), aborts)
        w = LabWorld(e1)
        w.overrides[I_W1] = {"/proc/vmstat": "nr_free_pages 1\n"}        # swap counters unreadable at the end of W
        G, aborts, _ = evaluate(w)
        self.assertIsNone(G["G7"]["swap_ok"])
        self.assertTrue(any("ground truth unavailable" in a for a in aborts), aborts)

    def test_target_output_missing_is_unavailable(self):
        G, aborts, _ = evaluate(LabWorld(C.EXPERIMENTS["E1"]), target_out={})
        self.assertEqual(G["G4"]["status"], "UNAVAILABLE")
        self.assertTrue(aborts)

    def test_immediate_checks(self):
        w = LabWorld(C.EXPERIMENTS["E2"])
        obs, expected, in_w = w.observations()
        for k, t in enumerate(obs):
            self.assertEqual(C.placement_violations(t, w.exp, expected[k], in_w[k]) + C.immediate_aborts(t), [], k)
        t = copy.deepcopy(obs[15])
        t["leaves"]["contender"]["cpu_max"] = "1000 100000"
        self.assertTrue(C.immediate_aborts(t))
        t = copy.deepcopy(obs[15])
        t["nic_irq_eff"] = "19"
        self.assertTrue(C.immediate_aborts(t))
        t = copy.deepcopy(obs[15])
        t["proc"]["601"] = 3
        self.assertTrue(C.placement_violations(t, w.exp, expected[15], True))

    def test_lateness_stats(self):
        out = {"t0_ns": 0, "period_ns": 10, "wake_ns": [1, 12, 25, 31, 45], "done_ns": [5, 16, 33, 35, 46]}
        s = C.lateness_stats(out, 0, 30)
        self.assertEqual((s["n"], s["lateness_median_ns"], s["missed"]), (3, 2, 1))
        self.assertIsNone(C.lateness_stats(out, 100, 200))


V15 = "version 15\ntimestamp 1\n"


class TestSchedstatParser(unittest.TestCase):
    def test_strict_parse(self):
        ok = V15 + "cpu0 1 0 2 3 4 5 777 8 9\ndomain0 0003 1 2 3\ncpu18 0 0 0 0 0 0 123456789 5 6\n"
        self.assertEqual(C.schedstat_rq_cpu_time(ok), {0: 777, 18: 123456789})       # field 7, not run_delay (8)
        bad = {
            "missing": None, "empty": "",
            "wrong version": ok.replace("version 15", "version 16"),
            "no version line": ok.split("\n", 1)[1],
            "missing cpu18": V15 + "cpu0 1 0 2 3 4 5 777 8 9\n",
            "non-integer": V15 + "cpu18 0 0 0 0 0 0 12.5 5 6\n",
            "negative": V15 + "cpu18 0 0 0 0 0 0 -1 5 6\n",
            "too few fields": V15 + "cpu18 0 0 0 0 0 0 1 5\n",
            "too many fields": V15 + "cpu18 0 0 0 0 0 0 1 5 6 7\n",
            "duplicate cpu18": V15 + "cpu18 0 0 0 0 0 0 1 5 6\ncpu18 0 0 0 0 0 0 2 5 6\n",
            "malformed other cpu": V15 + "cpu18 0 0 0 0 0 0 1 5 6\ncpu3 0 0 x 0 0 0 1 5 6\n",
        }
        for name, text in bad.items():
            with self.subTest(name):
                self.assertIsNone(C.schedstat_rq_cpu_time(text))

    def test_live_source(self):
        live = C.Sys().read("/proc/schedstat")
        if live is None or "cpu18 " not in live:
            self.skipTest("needs the R2-C host")
        self.assertIsInstance(C.schedstat_rq_cpu_time(live)[18], int)


class TestPreciseCpuTime(unittest.TestCase):
    """G6 and G3 from /proc/schedstat rq_cpu_time (approved measurement fix after runtime attempt 1)."""

    def test_tick_inflated_proc_stat_with_precise_schedstat_passes(self):
        # runtime attempt 1, E0-open: /proc/stat busy 50 + idle 74.6 jiffies/s on CPU 18 for 0.25 core of real work
        w = LabWorld(C.EXPERIMENTS["E0"], **{"cpu18.busy": (50, 50), "cpu18.idle": (75, 75)})
        G, aborts, _ = evaluate(w, target_out=w.target_out(late_w=10_000))
        self.assertAlmostEqual(G["G6"]["diagnostic_tick_foreign_cores_b"], 0.25)   # the artifact, recorded only
        self.assertAlmostEqual(G["G6"]["foreign_cores_b"], 0.02)
        self.assertAlmostEqual(G["G6"]["foreign_cores_w"], 0.02)
        self.assertTrue(G["G6"]["ok"])
        self.assertFalse([a for a in aborts if "G6" in a])

    def test_genuine_foreign_load_fails(self):
        for k, rq in (("E0", (500_000_000, 270_000_000)), ("E0", (270_000_000, 330_000_000)),
                      ("E1", (270_000_000, 1_000_000_000 + 60_000_000)), ("N1", (270_000_000, 400_000_000))):
            with self.subTest(k=k, rq=rq):
                G, aborts, _ = evaluate(LabWorld(C.EXPERIMENTS[k], **{"cpu18.rq": rq}))
                self.assertFalse(G["G6"]["ok"])
                self.assertTrue(any("(G6)" in a for a in aborts), aborts)

    def test_threshold_boundary(self):
        G, aborts, _ = evaluate(LabWorld(C.EXPERIMENTS["E1"], **{"cpu18.rq": (300_000_000, 1_000_000_000)}))
        self.assertAlmostEqual(G["G6"]["foreign_cores_b"], 0.05)                # exactly 0.05 passes
        self.assertTrue(G["G6"]["ok"])
        G, _, _ = evaluate(LabWorld(C.EXPERIMENTS["E1"], **{"cpu18.rq": (300_000_001 + 10, 1_000_000_000)}))
        self.assertFalse(G["G6"]["ok"])

    def test_contender_term(self):
        for k, sub in (("E0", False), ("N1", False), ("N2", False), ("E1", True), ("E2", True)):
            with self.subTest(k):
                G, _, _ = evaluate(LabWorld(C.EXPERIMENTS[k]))
                self.assertEqual(G["G6"]["contender_subtracted"], sub)
                self.assertAlmostEqual(G["G6"]["foreign_cores_w"], 0.02)       # N: contender usage 0.98 not removed
                self.assertTrue(G["G6"]["ok"])

    def test_unavailable_schedstat_aborts(self):
        e1 = C.EXPERIMENTS["E1"]
        cases = {
            "missing": None,
            "malformed": V15 + "cpu18 0 0 0 0 0 0 x 1 2\n",
            "wrong version": "version 16\ncpu18 0 0 0 0 0 0 1 1 2\n",
            "missing cpu18": V15 + "cpu19 0 0 0 0 0 0 1 1 2\n",
            "backwards": V15 + "cpu18 0 0 0 0 0 0 1 1 2\n",                    # far below the running counter
        }
        for name, text in cases.items():
            # a backwards counter is only visible at the END of a window (a low start value is a jump forward)
            for idx, g in (((I_W0 if name == "backwards" else I_B0), "G6"), (I_W1, "G3")):
                with self.subTest(name=name, at=idx):
                    w = LabWorld(e1)
                    w.overrides[idx] = {"/proc/schedstat": text}
                    G, aborts, _ = evaluate(w)
                    self.assertIsNone(G[g]["ok"] if g == "G6" else G["G3"]["cpu18_idle_frac_w"])
                    self.assertFalse(G["computable"])
                    self.assertTrue(any(a.startswith("independent ground truth unavailable") for a in aborts), aborts)

    def test_g3_precise_idle(self):
        e1 = C.EXPERIMENTS["E1"]
        cases = {"fully busy": (1_000_000_000, 0.0, True), "partial idle 10 %": (900_000_000, 0.1, False),
                 "idle 4.9 %": (951_000_000, 0.049, True), "boundary overshoot": (1_002_000_000, -0.002, True)}
        for name, (rq, idle, ok) in cases.items():
            with self.subTest(name):
                w = LabWorld(e1, **{"cpu18.rq": (270_000_000, rq), "c.usage": (0, rq // 1000 - 270_000)})
                G, aborts, _ = evaluate(w)
                self.assertAlmostEqual(G["G3"]["cpu18_idle_frac_w"], idle)
                self.assertEqual(G["G3"]["ok"], ok)
                self.assertEqual(any("idle" in a for a in aborts), not ok)
        w = LabWorld(e1, **{"cpu18.busy": (27, 50), "cpu18.idle": (73, 75)})   # tick view: 0.6 idle, recorded only
        G, _, _ = evaluate(w)
        self.assertAlmostEqual(G["G3"]["diagnostic_tick_idle_frac_w"], 0.6)
        self.assertTrue(G["G3"]["ok"])
        G, _, _ = evaluate(LabWorld(C.EXPERIMENTS["N1"], **{"cpu18.rq": (270_000_000, 270_000_000)}))
        self.assertFalse(G["G3"]["applies"])
        self.assertTrue(G["G3"]["ok"])                                       # measured, not applied


class TestBpfRelease(unittest.TestCase):
    BASE = {"bpf": {"map": [{"id": 1, "name": "other"}, {"id": 2, "name": "sn_hist"}], "prog": []}}
    OWN = [{"id": 10, "name": n} for n in C.LOADER_BPF_MAPS] + [{"id": 30, "name": "sentinel.rodata"}]

    def run_states(self, states, timeout=5.0):
        clock, sleeps = {"t": 0.0}, []

        class S:
            def __init__(self):
                self.i = 0

            def run(self, argv):
                assert tuple(argv) in C.READ_ONLY_COMMANDS
                st = states[min(self.i // 2, len(states) - 1)]
                self.i += 1
                v = st[0] if argv[2] == "map" else st[1]
                return v if v is None else json.dumps(v)

        def sleep(x):
            sleeps.append(x)
            clock["t"] += x
        def now():                    # advances a little on every read, so a loop that never sleeps still ends
            clock["t"] += 1e-4
            return clock["t"]
        r = C.wait_bpf_released(S(), self.BASE, timeout_s=timeout, sleep=sleep, clock=now)
        return r, sleeps

    def test_released_immediately(self):
        r, sleeps = self.run_states([(self.BASE["bpf"]["map"], [])])
        self.assertEqual((r["released"], r["timed_out"], r["polls"], sleeps), (True, False, 1, []))

    def test_released_late(self):
        r, sleeps = self.run_states([(self.OWN, [{"id": 7, "name": "sn_sched_switch"}]), (self.OWN, []),
                                     (self.OWN[:2], []), (self.BASE["bpf"]["map"], [])])
        self.assertTrue(r["released"])
        self.assertEqual(r["polls"], 4)
        self.assertEqual(sleeps, [C.BPF_RELEASE_POLL_S] * 3)
        self.assertAlmostEqual(r["elapsed_s"], 0.3, delta=0.01)

    def test_never_released_times_out(self):
        for name, st in (("map", (self.OWN, [])), ("libbpf map", ([{"id": 30, "name": "sentinel.bss"}], [])),
                         ("program", ([], [{"id": 7, "name": "sn_softirq_entry"}])), ("unreadable", (None, []))):
            with self.subTest(name):
                r, sleeps = self.run_states([st])
                self.assertFalse(r["released"])
                self.assertTrue(r["timed_out"])
                self.assertEqual(set(sleeps), {C.BPF_RELEASE_POLL_S})
                self.assertGreaterEqual(r["elapsed_s"], C.BPF_RELEASE_MAX_S)
                self.assertLessEqual(r["polls"], int(C.BPF_RELEASE_MAX_S / C.BPF_RELEASE_POLL_S) + 2)

    def test_constants(self):
        self.assertEqual((C.BPF_RELEASE_POLL_S, C.BPF_RELEASE_MAX_S), (0.1, 5.0))
        self.assertEqual(C.LOADER_BPF_MAPS, ("sn_wake", "sn_hist", "sn_stats", "sn_sirq_start", "sn_sirq_acc",
                                             "sn_retrans", "sn_kfree"))
        src = (ROOT / "ebpf" / "bpf" / "sentinel.bpf.c").read_text()
        self.assertEqual(tuple(re.findall(r"\}\s*(sn_\w+)\s+SEC\(\"\.maps\"\)", src)), C.LOADER_BPF_MAPS)

    def test_unrelated_objects_are_not_waited_for_but_still_fail_exact_comparison(self):
        unrelated = self.BASE["bpf"]["map"] + [{"id": 99, "name": "someone_else"}]
        r, sleeps = self.run_states([(unrelated, [])])
        self.assertTrue(r["released"])                                       # not run-owned: no wait
        self.assertEqual(sleeps, [])
        own_named_preexisting = C.run_owned_bpf(self.BASE, self.BASE["bpf"]["map"], [])
        self.assertEqual(own_named_preexisting["maps"], [])                  # id 2 existed before the run
        base = C.host_snapshot(snapshot_sys())
        after = C.host_snapshot(snapshot_sys(cmds={(C.BPFTOOL, "-j", "map", "show"):
                                                   json.dumps([{"id": 99, "name": "someone_else"}])}))
        r = C.compare_host(base, after)
        self.assertFalse(r["ok"])
        self.assertIn("bpf_maps_identical", r["failed"])

    def test_dry_run_simulation(self):
        self.assertEqual(C.simulate_bpf_release(), {"ok": True, "cases": {"immediate": True, "late": True,
                                                                          "never": True, "unrelated_remains": True}})


# ------------------------------------------------------------------------------------------ metric gate (real collector)
def r2c_snapshot(window_rates=None, tcp=0, latency=True, stale_ebpf=False, cpu_max="max 100000", periods=0):
    """A snapshot built by the real M3A/M3B collector code for the R2-C target shape (FixtureReader host)."""
    from collectors._world import CG as WCG, World
    from sentinelai.collectors import build_snapshot
    from sentinelai.collectors.ebpf import (EBPF_COLLECTOR_VERSION, KFREE_SLOTS, EbpfTarget, Meta, Sample,
                                            bucket_index, sample_obs)
    from sentinelai.collectors.normalize import Tick
    from sentinelai.collectors.probes import sample
    from sentinelai.diagnostic.contract import Target
    import r2c_driver as D

    class R2CWorld(World):
        def files(self, k):
            return {p.replace(WCG, C.TARGET_DIR): v for p, v in super().files(k).items()}

    w = R2CWorld(cpus=(18, 23))
    w.gauges["cg.cpu.max"] = cpu_max
    w.gauges["task.processor"] = 18
    w.rates.update({"cg.nr_periods": periods, "Tcp.OutSegs": tcp, "Tcp.RetransSegs": 0, "TcpExt.TCPTimeouts": 0,
                    "TcpExt.TCPFastRetrans": 0})
    w.window_rates.update(window_rates or {})
    t = Target(name="r2c", cgroup_path=C.TARGET_CGROUP_PATH, pids=(100,), cpuset="18", netns_ref="pid:100", ifaces=())
    meta = Meta(producer="sentinel_loader", version=EBPF_COLLECTOR_VERSION, libbpf="1.4", ncpu=24,
                target=EbpfTarget(1, 2, 3), lat_stale_ns=1, sirq_stale_ns=1,
                reasons=tuple(f"R{i}" for i in range(KFREE_SLOTS)) + ("UNKNOWN_OVERFLOW",))
    ticks = []
    for k in range(C.NB + C.NW + 1):
        obs = sample(w.reader(k), t)
        hist = {bucket_index(10_000): 100 * k, bucket_index(60_000): 2 * k} if latency else {}
        if stale_ebpf and k > C.NB:
            hist = {bucket_index(10_000): 100 * C.NB, bucket_index(60_000): 2 * C.NB}
        obs.update(sample_obs(meta, Sample(seq=k + 1, mono_ns=k + 1, hist=hist,
                                           softirq={(18, v): (1000 * k, k) for v in range(10)}, retrans=0, kfree={},
                                           stats={})))
        from datetime import timedelta
        from collectors._world import T0
        ticks.append(Tick(k, float(k), T0 + timedelta(seconds=k), obs))
    return build_snapshot(ticks, t, D.params(), 1.0, ebpf=True)


def with_measurement(snap, feature, aggregation=None, **update):
    ms = [m.model_copy(update=update) if m.feature_id == feature and
          (aggregation is None or m.aggregation.value == aggregation) else m for m in snap.measurements]
    return SimpleNamespace(measurements=ms, target=snap.target, data_quality=snap.data_quality)


class TestMetricGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snap = r2c_snapshot()

    def gate(self, s):
        return C.metric_gate(s, 0.8, 5.0)

    def test_required_metrics_present_and_usable(self):
        r = self.gate(self.snap)
        self.assertTrue(r["ok"], r)
        cg = f"cgroup:{C.TARGET_CGROUP_PATH}"
        ids = {(m.feature_id, m.scope, m.aggregation.value) for m in self.snap.measurements}
        for f, sc, agg in C.REQUIRED_METRICS:
            self.assertIn((f, cg if sc == "cg" else sc, agg), ids)
        tr = [m for m in self.snap.measurements if m.feature_id == "throttle.ratio"][0]
        self.assertEqual((tr.quality.value, tr.value), ("MISSING", None))       # MISSING by design
        steal = [m for m in self.snap.measurements if m.feature_id == "cpu.steal.cpuset"][0]
        self.assertEqual(steal.value, 0.0)

    def test_m2_consumes_the_snapshot_unchanged(self):
        import r2c_driver as D
        from sentinelai.diagnostic.contract.serialize import canonical_bytes
        from sentinelai.diagnostic.rules import diagnose
        before = canonical_bytes(self.snap)
        d = diagnose(self.snap, D.params(), code_commit="7354f40")
        self.assertEqual(canonical_bytes(self.snap), before)
        cc = {i["clause"]: i for i in D.cc_items(d)}
        self.assertEqual(set(cc), {"CC.R1", "CC.R2", "CC.X1", "CC.X2"})
        self.assertNotEqual(cc["CC.R1"]["kind"], "MISSING")                 # run_delay_excess evaluable
        self.assertNotEqual(cc["CC.R2"]["kind"], "MISSING")
        self.assertEqual(cc["CC.X1"]["kind"], "MISSING")                    # throttle.ratio undefined by design
        self.assertNotEqual(cc["CC.X2"]["kind"], "MISSING")

    def test_invalid_metric_states_abort(self):
        from sentinelai.diagnostic.contract import Quality
        s = self.snap
        rd = "sched.run_delay_excess.target"
        cases = {
            "missing metric": SimpleNamespace(measurements=[m for m in s.measurements if m.feature_id != rd],
                                              target=s.target, data_quality=s.data_quality),
            "stale metric": with_measurement(s, "cpu.util.cpuset", quality=Quality.STALE),
            "invalid metric": with_measurement(s, rd, quality=Quality.INVALID, value=None),
            "missing value": with_measurement(s, "cpu.steal.cpuset", quality=Quality.MISSING, value=None),
            "low coverage": with_measurement(s, rd, quality=Quality.PARTIAL, coverage=0.5),
            "missing baseline": with_measurement(s, "sched.latency_hist.target", "P99", baseline=None),
            "inadequate baseline": with_measurement(
                s, "sched.latency_hist.target", "P50",
                baseline=[m for m in s.measurements if m.feature_id == rd][0].baseline.model_copy(update={"adequate": False})),
            "duplicate metric": SimpleNamespace(measurements=list(s.measurements) +
                                                [m for m in s.measurements if m.feature_id == rd],
                                                target=s.target, data_quality=s.data_quality),
            "wrong target cpuset": SimpleNamespace(measurements=s.measurements, target=s.target.model_copy(
                update={"cpuset": "18-19"}), data_quality=s.data_quality),
            "throttle.ratio has a value": with_measurement(s, "throttle.ratio", quality=Quality.OK, value=0.5),
            "quota limited": with_measurement(s, "throttle.quota_limited", value=1.0),
            "throttle time": with_measurement(s, "throttle.time_rate", value=0.2),
            "unexpected network activity": with_measurement(s, "tcp.out_segs_rate", value=12.0),
            "data quality gate": SimpleNamespace(measurements=s.measurements, target=s.target,
                                                 data_quality=s.data_quality.model_copy(update={"gate_passed": False})),
        }
        for name, snap in cases.items():
            with self.subTest(name):
                r = self.gate(snap)
                self.assertFalse(r["ok"])
                self.assertTrue(r["aborts"])

    def test_real_collector_states(self):
        self.assertFalse(self.gate(r2c_snapshot(latency=False))["ok"])          # no wakeups: latency MISSING
        self.assertFalse(self.gate(r2c_snapshot(stale_ebpf=True))["ok"])        # no latency sample in W
        self.assertFalse(self.gate(r2c_snapshot(tcp=50))["ok"])                 # traffic in the private netns
        self.assertFalse(self.gate(r2c_snapshot(cpu_max="50000 100000", periods=10))["ok"])   # quota


# ------------------------------------------------------------------------------------------ host comparison
def snapshot_sys(**over):
    files = {f"{C.CG_ROOT}/cpuset.cpus.effective": "0-23", f"{C.CG_ROOT}/cgroup.subtree_control":
             "cpuset cpu io memory hugetlb pids rdma misc", f"{C.CG_ROOT}/cpuset.mems.effective": "0",
             f"{C.CG_ROOT}/system.slice/cpu.max": "max 100000", f"{C.CG_ROOT}/system.slice/cpu.weight": "100",
             "/proc/irq/134/smp_affinity_list": "21", "/proc/irq/134/effective_affinity_list": "21",
             "/proc/irq/9/smp_affinity_list": "0-23", "/proc/irq/9/effective_affinity_list": "3",
             "/proc/pressure/cpu": "some avg10=0.00 avg60=0.00 avg300=0.00 total=5\n",
             "/proc/stat": "cpu  1 0 0 9 0 0 0 0 0 0\ncpu18 1 0 0 9 0 0 0 0 0 0\n"}
    files.update({f"/proc/sys/{s}": "0" for s in C.SYSCTLS})
    s = FakeSys(files, dirs={"/proc/irq": ["134", "9", "default_smp_affinity"], "/run/netns": []})
    for k, v in over.items():
        if k == "cmds":
            s.cmds.update(v)
        elif k == "cgroups":
            s.cgroups = v
        elif k == "pids":
            s._pids = v
        else:
            s.files.update(v)
    return s


class TestHostCompare(unittest.TestCase):
    def setUp(self):
        self.base = C.host_snapshot(snapshot_sys())

    def cmp(self, **over):
        return C.compare_host(self.base, C.host_snapshot(snapshot_sys(**over)))

    def test_identical_and_volatile_only(self):
        self.assertTrue(C.compare_host(self.base, C.host_snapshot(snapshot_sys()))["ok"])
        links = copy.deepcopy(LINKS)
        links[1]["stats64"] = {"rx": {"packets": 999}}
        links[2]["linkinfo"]["info_data"]["gc_timer"] = 1.0
        r = self.cmp(cmds={("ip", "-j", "-d", "link", "show"): json.dumps(links)},
                     files={"/proc/pressure/cpu": "some avg10=3.00 avg60=0.00 avg300=0.00 total=999\n"})
        self.assertTrue(r["ok"], r["failed"])

    def test_changes_detected(self):
        nic = copy.deepcopy(LINKS)
        nic[1]["mtu"] = 1400
        br = copy.deepcopy(LINKS)
        br[2]["operstate"] = "UP"
        br2 = copy.deepcopy(LINKS)
        br2[2]["linkinfo"]["info_data"]["stp_state"] = 1
        q = copy.deepcopy(QDISCS)
        q[0]["kind"] = "netem"
        cases = {
            "protected NIC change": dict(cmds={("ip", "-j", "-d", "link", "show"): json.dumps(nic)}),
            "protected Docker bridge change": dict(cmds={("ip", "-j", "-d", "link", "show"): json.dumps(br)}),
            "Docker bridge configuration": dict(cmds={("ip", "-j", "-d", "link", "show"): json.dumps(br2)}),
            "NIC qdisc change": dict(cmds={("tc", "-j", "qdisc", "show"): json.dumps(q)}),
            "route added": dict(cmds={("ip", "-j", "route", "show"): "[]"}),
            "netns added": dict(cmds={("ip", "-j", "netns", "list"): '[{"name": "x"}]'}),
            "network state unreadable": dict(cmds={("ip", "-j", "addr", "show"): None}),
            "root cpuset changed": dict(files={f"{C.CG_ROOT}/cpuset.cpus.effective": "0-15"}),
            "root controllers changed": dict(files={f"{C.CG_ROOT}/cgroup.subtree_control": "memory pids"}),
            "existing cgroup modified": dict(files={f"{C.CG_ROOT}/system.slice/cpu.weight": "200"}),
            "existing cgroup quota": dict(files={f"{C.CG_ROOT}/system.slice/cpu.max": "50000 100000"}),
            "cgroup added": dict(cgroups=["", "init.scope", "system.slice", "user.slice", "user.slice/x"]),
            "persistent cgroup": dict(cgroups=["", "init.scope", "system.slice", "user.slice", "sentinel-r2c"]),
            "persistent process": dict(pids=[88], files={"/proc/88/cgroup": "0::/sentinel-r2c/contender\n"}),
            "IRQ affinity change": dict(files={"/proc/irq/9/effective_affinity_list": "18"}),
            "NIC IRQ change": dict(files={"/proc/irq/134/effective_affinity_list": "20"}),
            "sysctl change": dict(files={"/proc/sys/kernel/sched_schedstats": "1"}),
            "mount added": dict(cmds={("findmnt", "-rn", "-o", "TARGET,FSTYPE"): "/ ext4\n/x tmpfs\n"}),
            "BPF program left": dict(cmds={(C.BPFTOOL, "-j", "prog", "show"): '[{"id": 7, "name": "sn_sched_switch"}]'}),
            "BPF state unreadable": dict(cmds={(C.BPFTOOL, "-j", "map", "show"): None}),
        }
        for name, over in cases.items():
            with self.subTest(name):
                self.assertFalse(self.cmp(**over)["ok"])


# ------------------------------------------------------------------------------------------ cleanup
class TestCleanup(unittest.TestCase):
    def test_every_partial_setup_is_cleaned(self):
        for k, exp in C.EXPERIMENTS.items():
            n = len(C.setup_plan(exp)) + (2 if exp.contender_cpu is not None else 1)
            for fail_at in [None] + list(range(1, n + 1)):
                with self.subTest(exp=k, fail_at=fail_at):
                    r = C.simulate(exp, fail_at)
                    self.assertTrue(r["cleanup_ok"] and r["host_clean"], r)

    def run_cleanup(self, sim, entries):
        return C.cleanup(sim, sim, entries, wait_s=0.0, sleep=lambda s: None)

    def setup_sim(self, exp, cls=C.SimHost):
        sim = cls(exp)
        entries = []
        for op in C.setup_plan(exp) + [("spawn", "target", C.target_argv(1000, OUT + "/t"))]:
            entries.append({"phase": "intent", "op": list(op[:2])})
            res = sim.apply(op)
            entries.append({"phase": "result", "op": list(op[:2]), "ok": True, "pid": getattr(res, "pid", None)})
        return sim, entries

    def test_cleanup_failure_is_reported(self):
        class StuckRmdir(C.SimHost):
            def apply(self, op, stdout=None, stderr=None):
                if op[0] == "rmdir":
                    C.check_op(op, self.exp, self.iters)
                    raise OSError("EBUSY")
                return super().apply(op)

        class Unkillable(C.SimHost):
            def apply(self, op, stdout=None, stderr=None):
                if op[0] == "kill" or op[1].endswith("cgroup.kill"):
                    C.check_op(op, self.exp, self.iters)
                    return None
                return super().apply(op)
        for cls in (StuckRmdir, Unkillable):
            with self.subTest(cls.__name__):
                sim, entries = self.setup_sim(C.EXPERIMENTS["E1"], cls)
                r = self.run_cleanup(sim, entries)
                self.assertFalse(r["ok"], r)
                self.assertFalse(r["verify"]["ok"])

    def test_only_created_paths_are_removed(self):
        sim, entries = self.setup_sim(C.EXPERIMENTS["E1"])
        r = self.run_cleanup(sim, [e for e in entries if e["op"][0] != "mkdir"])   # nothing logged as created
        self.assertFalse([op for op in sim.applied if op[0] == "rmdir"])
        self.assertFalse(r["ok"])                                                   # the lab is still there: NO-GO

    def test_cleanup_is_idempotent(self):
        sim, entries = self.setup_sim(C.EXPERIMENTS["E2"])
        self.assertTrue(self.run_cleanup(sim, entries)["ok"])
        n = len(sim.applied)
        self.assertTrue(self.run_cleanup(sim, entries)["ok"])
        self.assertEqual([op[0] for op in sim.applied[n:]], ["kill"])               # only a no-op kill of the logged pid

    def test_wrappers_are_waited_for_never_signalled(self):
        sim, entries = self.setup_sim(C.EXPERIMENTS["E1"])
        wrapper = C.oplog_state(entries)["pids"][0]
        self.assertTrue(C.wrapper_alive(sim, wrapper))
        self.assertNotIn(wrapper, sim.procs[C.TARGET_DIR])                         # outside the lab cgroup
        self.assertEqual(len(sim.procs[C.TARGET_DIR]), 1)
        r = self.run_cleanup(sim, entries)
        self.assertTrue(r["ok"], r)
        self.assertFalse(C.wrapper_alive(sim, wrapper))
        self.assertTrue(r["verify"]["checks"]["no_wrapper_alive"])

    def test_wrapper_that_survives_is_a_cleanup_failure(self):
        class StuckWrapper(C.SimHost):
            def _die(self, pid):
                self.alive.discard(pid)                                            # wrapper never exits
        sim, entries = self.setup_sim(C.EXPERIMENTS["E1"], StuckWrapper)
        r = self.run_cleanup(sim, entries)
        self.assertFalse(r["ok"])
        self.assertTrue(any("timeout wrappers still running" in e for e in r["errors"]), r["errors"])

    def test_oplog_counts_intent_without_result(self):
        st = C.oplog_state([{"phase": "intent", "op": ["mkdir", C.LAB_DIR]}])
        self.assertEqual(st["dirs"], [C.LAB_DIR])


# ------------------------------------------------------------------------------------------ dry run
class TestDryRun(unittest.TestCase):
    @unittest.skipUnless(os.path.exists("/proc/stat") and os.path.exists("/sys/devices/system/cpu/cpu23"),
                         "needs the R2-C host topology")
    def test_dry_run_mutates_nothing(self):
        real_open = builtins.open

        def ro_open(path, mode="r", *a, **kw):
            if any(c in mode for c in "wax+"):
                raise AssertionError(f"dry-run opened {path} for writing")
            return real_open(path, mode, *a, **kw)

        def forbidden(*a, **kw):
            raise AssertionError(f"dry-run mutation: {a}")
        with mock.patch("builtins.open", ro_open), mock.patch.object(C, "Host", forbidden), \
                mock.patch("os.mkdir", forbidden), mock.patch("os.rmdir", forbidden), mock.patch("os.kill", forbidden), \
                mock.patch("os.sched_setaffinity", forbidden), mock.patch("os.unshare", forbidden, create=True):
            rep = C.dry_run(C.Sys())
        self.assertTrue(rep["zero_mutation"]["ok"], rep["zero_mutation"]["failed"])
        self.assertTrue(rep["guards"]["forbidden_ops_refused"])
        self.assertTrue(rep["cleanup_simulation"]["ok"])
        self.assertTrue(all(rep["metric_table"].values()), rep["metric_table"])
        self.assertTrue(rep["structural_ok"], {k: v for k, v in rep.items() if k != "intended_mutations"})
        self.assertTrue(rep["criteria_resolved"])
        self.assertEqual(rep["one_pid_spawn_structure"], {"calibration": True, "target": True, "contender": True})
        self.assertEqual(set(rep["intended_mutations"]), set(C.MATRIX) | {"calibration"})
        cal = rep["intended_mutations"]["calibration"]
        self.assertEqual((cal["runtime_step"], cal["executed"], cal["contender"], cal["cpu"], cal["before"]),
                         (0, False, None, 18, "E0-open"))
        self.assertTrue(cal["requires_runtime_authorisation"])
        self.assertNotIn("pending_criteria", rep)


# ------------------------------------------------------------------------------------------ target and contender
class TestTarget(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("r2c_target", ROOT / "scripts" / "r2c_target.py")
        self.T = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.T)

    def test_work_is_deterministic(self):
        self.assertEqual(self.T.work(1000, 1), self.T.work(1000, 1))
        self.assertNotEqual(self.T.work(1000, 1), self.T.work(1001, 1))

    def test_run_schedule_with_fake_clock(self):
        clock = {"t": 1_000}
        slept = []

        def sleep_until(d):
            slept.append(d)
            clock["t"] = max(clock["t"], d) + 7

        def now():
            clock["t"] += 1
            return clock["t"]
        r = self.T.run(5, 2_000_000, 10, now=now, sleep_until=sleep_until)
        self.assertEqual(slept, [r["t0_ns"] + k * 2_000_000 for k in range(5)])   # absolute deadlines, fixed grid
        self.assertEqual(len(r["wake_ns"]), 5)
        self.assertEqual(r["pid"], os.getpid())
        self.assertTrue(all(w >= d for w, d in zip(r["wake_ns"], slept)))

    def test_calibration_formula(self):
        ticks = iter(range(0, 10**9, 1000))
        with mock.patch.object(self.T, "CAL_REPS", 3), mock.patch.object(self.T, "CAL_PROBE", 10):
            r = self.T.calibrate(500_000, now=lambda: next(ticks))
        self.assertEqual(r["median_ns"], 1000)
        self.assertEqual(r["iters"], 10 * 500_000 // 1000)

    def test_one_process_no_fork(self):
        code = "\n".join(code_lines(TARGET.split('"""', 2)[2]))           # without the module docstring
        for pat in (r"\bfork\b", r"\bsubprocess\b", r"\bthreading\b", r"\bmultiprocessing\b", r"os\.system", r"\bexec[lv]",
                    r"sched_setaffinity", r"\bunshare\b", r"\bsetuid\b", r"cgroup", r"\bsignal\b", r"\bsocket\b"):
            self.assertIsNone(re.search(pat, code), pat)
        self.assertIn("TIMER_ABSTIME", code)
        self.assertIn("for k in range(cycles):", code)


class TestContender(unittest.TestCase):
    def test_code_is_a_pure_loop(self):
        import ast
        tree = ast.parse(C.CONTENDER_CODE)
        imports = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertEqual(imports, {"mmap", "sys"})
        loop = [n for n in ast.walk(tree) if isinstance(n, ast.While)]
        self.assertEqual(len(loop), 1)
        calls = {getattr(n.func, "attr", getattr(n.func, "id", None)) for n in ast.walk(loop[0]) if isinstance(n, ast.Call)}
        self.assertEqual(calls, {"to_bytes"})                    # no syscall, no sleep, no I/O inside the loop
        for word in ("sleep", "os", "fork", "thread", "nice", "sched"):
            self.assertNotRegex(C.CONTENDER_CODE, rf"\b{word}\b")

    def test_iteration_count_is_published(self):
        class Stop(Exception):
            pass

        class Mapping:
            def __init__(self, *a):
                self.v = None

            def __setitem__(self, k, v):
                self.v = v
                raise Stop()
        m = Mapping()
        fake_mmap = SimpleNamespace(mmap=lambda *a: m)
        with tempfile.NamedTemporaryFile() as f, mock.patch.dict(sys.modules, {"mmap": fake_mmap}), \
                mock.patch.object(sys, "argv", ["-c", f.name]):
            ns = {}
            with self.assertRaises(Stop):
                exec(compile(C.CONTENDER_CODE, "<contender>", "exec"), ns)
            ns["f"].close()
        self.assertEqual(int.from_bytes(m.v, "little"), 65536)


# ------------------------------------------------------------------------------------------ script safety
class TestScriptSafety(unittest.TestCase):
    def test_module_mutates_only_through_host(self):
        body = MODULE.split("class Host:")[1].split("# ----")[0]
        outside = MODULE.replace(body, "")
        for pat, n in ((r"os\.mkdir\(", 1), (r"os\.rmdir\(", 1), (r"os\.kill\(", 1), (r"subprocess\.Popen\(", 1),
                       (r"open\([^)]*['\"][wa]", 2)):                  # the cgroupfs write and the op log
            self.assertEqual(len(re.findall(pat, body)), n, pat)
            self.assertEqual(re.findall(pat, outside), [], pat)
        self.assertIn("check_op(op, self.exp, self.iters)\n        self._log(phase=\"intent\"", body)
        self.assertNotRegex(MODULE, r"shell\s*=\s*True|os\.system")
        self.assertNotRegex(MODULE, r"sched_setaffinity|\"chrt\"")

    def test_driver(self):
        code = "\n".join(code_lines(DRIVER))
        self.assertNotRegex(code, r"subprocess\.|os\.system|shell\s*=\s*True|os\.mkdir|os\.rmdir|os\.kill")
        self.assertNotRegex(code, r"\.write_text\([^)]*cgroup|open\([^)]*/sys/fs/cgroup")
        self.assertNotRegex(code, r"cpu\.max\"|sched_setaffinity|chrt|stress")
        self.assertEqual(re.findall(r"host\.apply\(\(\"(\w+)\"", code), ["spawn", "kill"])   # setup: setup_plan
        self.assertIn("for op in C.setup_plan(exp):\nhost.apply(op)", code)
        self.assertIn('refuse("--execute not given', code)
        self.assertNotIn("pending", code)
        self.assertIn('run.want["target"] = [tpy]', code)
        self.assertIn('run.want["target"] = [py]', code)
        self.assertIn('run.want["contender"] = [cpy]', code)
        self.assertIn('raise C.LabAbort(f"{role} cgroup holds {procs}: one-pid invariant broken")', code)
        self.assertIn("provenance only, excluded from experiment evidence and baselines", code)
        self.assertIn("if not set(os.sched_getaffinity(0)) <= set(C.SUPPORT_CPUS):", code)
        i_pf = code.index('R["preflight"] = C.preflight(sysr)')
        i_sig = code.index("signal.signal(s, on_signal)")
        i_setup = code.index("for op in C.setup_plan(exp):")
        i_fin = code.rindex("finally:")
        i_clean = code.index('R["cleanup"] = C.cleanup(host, sysr, C.read_oplog(oplog))')
        i_cmp = code.index('R["host_compare"] = C.compare_host(base, after)')
        self.assertTrue(i_pf < i_sig < i_setup < i_fin < i_clean < i_cmp)
        self.assertIn("signal.signal(s, signal.SIG_IGN)", code[i_fin:i_clean])
        i_close = code.index("loader.close()", i_fin)
        i_wait = code.index('R["bpf_release"] = C.wait_bpf_released(sysr, base)')
        i_gate = code.index('if R["bpf_release"]["released"]:')
        i_after = code.index("after = C.host_snapshot(sysr)")
        i_cmp2 = code.index('R["host_compare"] = C.compare_host(base, after)')
        self.assertTrue(i_fin < i_close < i_clean < i_wait < i_gate < i_after < i_cmp2)
        self.assertEqual(code.count("after = C.host_snapshot(sysr)"), 1)    # the only authoritative snapshot
        self.assertIn('R["host_compare"] = {"ok": False, "failed": ["bpf_objects_not_released"]}', code)
        self.assertIn('R["aborts"].append(f"ABORT: BPF objects not released within', code)
        self.assertIn('host.apply(("kill", contender["pid"]))', code[code.index("collect_end"):])
        self.assertIn("d = diagnose(snap, params(), code_commit=a.commit)", code)
        self.assertNotRegex(code, r"predict\w*\(")

    def test_normal_target_exit_is_not_a_violation(self):
        import subprocess as sp
        import r2c_driver as D
        e0 = C.EXPERIMENTS["E0"]
        k = I_W1 + 1                                                  # a recovery observation

        class Proc:
            def __init__(self, rc, running=False):
                self.rc, self.running = rc, running

            def wait(self, timeout=None):
                if self.running:
                    raise sp.TimeoutExpired("timeout", timeout)
                return self.rc

        def run(files, proc):
            r = D.Run(e0, FakeSys(files), None, Path("."))
            r.want = {"target": [TPIDS[0]], "contender": []}
            r.target_pid = TPIDS[0]
            return r, r.observe_until_exit(proc, "recovery")

        alive = LabWorld(e0).files(k)
        r, kept = run(alive, Proc(None, running=True))
        self.assertTrue(kept)
        self.assertEqual(len(r.obs), 1)
        gone = dict(alive, **{f"{C.TARGET_DIR}/cgroup.procs": ""})
        r, kept = run(gone, Proc(0))                                  # raced the normal exit: discarded
        self.assertFalse(kept)
        self.assertEqual((r.obs, r.expected, r.in_w), ([], [], []))
        for name, files, proc in (
                ("wrapper still running", gone, Proc(None, running=True)),
                ("workload failed", gone, Proc(3)),
                ("exit plus NIC IRQ on CPU 18", dict(gone, **{f"/proc/irq/{C.NIC_IRQ}/effective_affinity_list": "18"}),
                 Proc(0)),
                ("exit plus quota", dict(gone, **{f"{C.TARGET_DIR}/cpu.max": "1000 100000"}), Proc(0)),
                ("foreign pid instead of target", dict(alive, **{f"{C.TARGET_DIR}/cgroup.procs": "999\n"}), Proc(0))):
            with self.subTest(name), self.assertRaises(C.LabAbort):
                run(files, proc)

    def test_driver_contender_timing(self):
        import r2c_driver as D
        from sentinelai.collectors.clock import SystemClock
        fired = []
        with mock.patch.object(SystemClock, "sleep_until", lambda self, mono: None):
            clk = D.WindowClock(lambda: fired.append(clk.calls))
            for k in range(C.NB + C.NW + 1):
                clk.sleep_until(float(k))
        self.assertEqual(fired, [C.NB + 1])

    def test_wrapper(self):
        code = "\n".join(code_lines(WRAPPER))
        self.assertIn("trap finish EXIT", code)
        self.assertIn("trap 'finish; exit 130' INT TERM", code)
        self.assertNotIn("pending", code)
        i_pend = code.index('"$R2C" candidate "$REPO" "$BASE"')
        i_pf = code.index('"$PY" "$R2C" preflight')
        i_trap = code.index("trap finish EXIT")
        i_base = code.index('host-snapshot "$OUT/host_baseline"')
        i_drv = code.index('"$DRIVER" --calibrate')
        self.assertTrue(i_pend < i_pf < i_trap < i_base < i_drv)
        self.assertEqual(len(re.findall(r"taskset -c 0-15 timeout 180 \"\$PY\" \"\$DRIVER\"", code)), 2)
        self.assertNotRegex(code, r"taskset -c (?!0-15 )")
        for pat in (r"\bsysctl\b", r">\s*/proc/sys", r"cpu\.max", r"\bstress", r"\bchrt\b", r"\btc\b", r"\bip (link|addr|route)",
                    r"\bethtool\b", r"\bdocker\b", r"enp0s31f6", r"docker0", r"/sys/fs/cgroup", r"\bmkdir /sys",
                    r"smp_affinity", r"\bnetem\b", r"\bunshare\b", r"\bkill\b"):
            with self.subTest(pattern=pat):
                self.assertIsNone(re.search(pat, code))
        self.assertIn('if (( STATUS )); then echo "[$label] a check failed: stopping"', code)
        i_cal = code.index('"$DRIVER" --calibrate')
        i_calcmp = code.index('compare "$OUT/host_baseline" "$OUT/calibration/host_wrapper_after"')
        i_loop = code.index('for label in "${MATRIX[@]}"')
        self.assertTrue(i_cal < i_calcmp < i_loop)                 # calibration: step 0, host compared, before E0
        self.assertIn('"$PY" "$R2C" criteria', code)


if __name__ == "__main__":
    unittest.main()
