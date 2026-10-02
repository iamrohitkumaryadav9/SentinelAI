"""A deterministic synthetic host: every source file rendered from counters with known rates.

Counter c at tick k = base + sum of per-tick increments (default constant), so every expected
measurement value is known exactly. Per-tick overrides inject faults: a file absent / denied /
malformed / reset at chosen ticks.
"""

import copy
from datetime import datetime, timedelta, timezone

from sentinelai.collectors import Bad, FixtureReader, Status
from sentinelai.collectors.normalize import Tick
from sentinelai.collectors.probes import sample
from sentinelai.diagnostic.contract import Target
from sentinelai.diagnostic.rules import ParameterSet
from sentinelai.diagnostic.rules.engine import DEV_FEATURES
from sentinelai.collectors import collected_features

T0 = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
TARGET = Target(name="lab", cgroup_path="/lab/A", pids=(100,), cpuset="0-1", netns_ref="pid:100", ifaces=("eth0",))
CG = "/sys/fs/cgroup/lab/A"
NB, NW = 10, 10
PSID = "test-params-m3a"

NUMBERS = {
    "W": 10.0, "B": 10.0, "N_BASE_MIN": 5.0, "COV_MIN": 0.8, "Z_STRONG": 3.0, "Z_MODERATE": 2.0,
    "R_STRONG": 3.0, "R_MODERATE": 1.5, "DROP_ABS_MIN": 10.0, "DROP_FRAC_MIN": 0.001, "RT_FRAC_MIN": 0.01,
    "RT_RATE_MIN": 1.0, "SEG_MIN": 100.0, "THR_RATIO_MIN": 0.3, "THR_TIME_MIN": 0.05, "RDX_MIN": 0.05,
    "SAT_MIN": 0.9, "SI_ABS_MIN": 0.5, "SI_RATIO_MIN": 3.0, "SI_SHARE_MIN": 0.5, "PSI_MEM_MIN": 0.2,
    "RECLAIM_MIN": 1000.0, "REFAULT_MIN": 100.0, "APP_WAIT_MIN": 50.0, "APP_SHARE_MIN": 0.5, "IMPACT_MIN": 2.0,
    "DOM_RATIO": 2.0, "τ_DISAGREE": 0.9,
}


def params(**over):
    """Test-only values (contract §6: unit tests supply explicit test values). Never calibrated."""
    nums = dict(NUMBERS)
    nums.update({f"floor[{f}]": 1e-3 for f in set(DEV_FEATURES) | set(collected_features())})
    nums.update(over)
    return ParameterSet(parameter_set_id=PSID, numbers=nums, reason_sets={"KFREE_REASONS_LOSS": ("QDISC_DROP",)})


# per-tick increments (jiffies, ns, counts); every CPU gets 100 jiffies per tick
RATES = {
    "cpu.user": 50, "cpu.nice": 0, "cpu.system": 20, "cpu.idle": 25, "cpu.iowait": 0, "cpu.irq": 0,
    "cpu.softirq": 5, "cpu.steal": 0,
    "ctxt": 4000, "sched.run_delay": 100_000_000,            # 0.1 waiting-cores per CPU
    "softirq.NET_RX": 300, "softirq.NET_TX": 30,
    "softnet.processed": 500, "softnet.dropped": 0, "softnet.time_squeeze": 0,
    "Tcp.OutSegs": 1000, "Tcp.RetransSegs": 10,
    "TcpExt.TCPBacklogDrop": 0, "TcpExt.TCPRcvQDrop": 0, "TcpExt.TCPTimeouts": 1, "TcpExt.TCPFastRetrans": 2,
    "TcpExt.TCPSynRetrans": 0,
    "vm.pgscan_direct": 0, "vm.pswpin": 0, "vm.pswpout": 0,
    "psi.cpu": 10_000, "psi.memory": 0,                       # us per tick (1 s): 0.01 / 0.0
    "cg.usage_usec": 400_000, "cg.nr_periods": 10, "cg.nr_throttled": 0, "cg.throttled_usec": 0,
    "cg.cpu.some": 20_000, "cg.mem.some": 0, "cg.mem.full": 0,
    "cg.pgscan": 0, "cg.refault_anon": 0, "cg.refault_file": 0, "cg.pgmajfault": 0,
    "cg.events.high": 0, "cg.events.oom_kill": 0,
    "if.rx_packets": 9000, "if.tx_packets": 1000, "if.rx_bytes": 9_000_000, "if.tx_bytes": 1_000_000,
    "if.rx_dropped": 0, "if.rx_missed_errors": 0, "if.rx_fifo_errors": 0, "if.tx_dropped": 0,
    "if.tx_fifo_errors": 0, "if.rx_errors": 0, "if.tx_errors": 0,
    "task.run_delay": 50_000_000, "task.nr_migrations": 1, "task.nonvol": 3,
}
GAUGES = {"procs_running": 3, "MemTotal": 16_000_000, "MemAvailable": 8_000_000, "cg.memory.current": 1_000_000_000,
          "cg.memory.max": "4000000000", "cg.swap": 0, "cg.cpu.max": "50000 100000", "task.processor": 0}
CPUS = (0, 1)
TIDS = (100, 101)


class World:
    def __init__(self, cpus=CPUS, tids=TIDS):
        self.cpus, self.tids = cpus, tids
        self.rates = dict(RATES)
        self.window_rates = {}          # key -> per-tick increment during W only (ticks > NB)
        self.gauges = dict(GAUGES)
        self.window_gauges = {}
        self.overrides = {}             # (path, tick) -> text | Bad
        self.cpu_ticks = {}             # cpu -> set of ticks where the CPU is absent

    # counter value of key at tick k
    def c(self, key, k, cpu=None):
        base = 1_000_000 + 1000 * (hash(key) % 7) if False else 1_000_000
        total = 0
        for j in range(1, k + 1):
            total += self.window_rates.get(key, self.rates[key]) if j > NB else self.rates[key]
        return base + total

    def gv(self, key, k):
        return self.window_gauges.get(key, self.gauges[key]) if k >= NB else self.gauges[key]

    def files(self, k):
        f = {}
        cpus = [n for n in self.cpus if k not in self.cpu_ticks.get(n, ())]
        fields = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
        per = {n: [self.c(f"cpu.{x}", k) for x in fields] for n in cpus}
        agg = [sum(per[n][i] for n in cpus) for i in range(8)]
        lines = ["cpu  " + " ".join(map(str, agg)) + " 0 0"]
        lines += [f"cpu{n} " + " ".join(map(str, per[n])) + " 0 0" for n in cpus]
        lines += ["intr 12345 0 0", f"ctxt {self.c('ctxt', k)}", "btime 1700000000", "processes 999",
                  f"procs_running {self.gv('procs_running', k)}", "procs_blocked 0", "softirq 1 2 3"]
        f["/proc/stat"] = "\n".join(lines) + "\n"
        f["/proc/schedstat"] = "version 15\ntimestamp 4600883468\n" + "".join(
            f"cpu{n} 0 0 0 0 0 0 {self.c('cpu.user', k)} {self.c('sched.run_delay', k)} 5\n"
            f"domain0 000003 0 0 0 0 0 0 0 0\n" for n in cpus)
        hdr = "".join(f"       CPU{n}" for n in cpus)
        f["/proc/softirqs"] = (f"     {hdr}\n          HI:" + "".join("          0" for _ in cpus) +
                               "\n      NET_TX:" + "".join(f" {self.c('softirq.NET_TX', k):10d}" for _ in cpus) +
                               "\n      NET_RX:" + "".join(f" {self.c('softirq.NET_RX', k):10d}" for _ in cpus) + "\n")
        f["/proc/net/softnet_stat"] = "".join(
            " ".join([f"{self.c('softnet.processed', k):08x}", f"{self.c('softnet.dropped', k):08x}",
                      f"{self.c('softnet.time_squeeze', k):08x}"] + ["00000000"] * 9 + [f"{n:08x}", "00000000", "00000000"])
            + "\n" for n in cpus)
        snmp_n = ["RtoAlgorithm", "RtoMin", "MaxConn", "OutSegs", "RetransSegs", "InErrs"]
        snmp_v = ["1", "200", "-1", str(self.c("Tcp.OutSegs", k)), str(self.c("Tcp.RetransSegs", k)), "0"]
        f["/proc/100/net/snmp"] = ("Ip: Forwarding DefaultTTL\nIp: 1 64\nTcp: " + " ".join(snmp_n) + "\nTcp: " +
                                   " ".join(snmp_v) + "\nUdp: InDatagrams\nUdp: 5\n")
        ext = ["SyncookiesSent", "TCPBacklogDrop", "TCPRcvQDrop", "TCPTimeouts", "TCPFastRetrans", "TCPSynRetrans"]
        f["/proc/100/net/netstat"] = ("TcpExt: " + " ".join(ext) + "\nTcpExt: 0 " +
                                      " ".join(str(self.c(f"TcpExt.{e}", k)) for e in ext[1:]) +
                                      "\nIpExt: InOctets\nIpExt: 77\n")
        f["/proc/meminfo"] = (f"MemTotal:       {self.gv('MemTotal', k)} kB\nMemFree:        1000 kB\n"
                              f"MemAvailable:   {self.gv('MemAvailable', k)} kB\n")
        f["/proc/vmstat"] = (f"nr_free_pages 1\npgscan_direct {self.c('vm.pgscan_direct', k)}\n"
                             f"pswpin {self.c('vm.pswpin', k)}\npswpout {self.c('vm.pswpout', k)}\n")
        f["/proc/pressure/cpu"] = (f"some avg10=0.00 avg60=0.00 avg300=0.00 total={self.c('psi.cpu', k)}\n"
                                   "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
        f["/proc/pressure/memory"] = (f"some avg10=0.00 avg60=0.00 avg300=0.00 total={self.c('psi.memory', k)}\n"
                                      "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
        f[f"{CG}/cpu.stat"] = (f"usage_usec {self.c('cg.usage_usec', k)}\nuser_usec 1\nsystem_usec 1\n"
                               f"nr_periods {self.c('cg.nr_periods', k)}\nnr_throttled {self.c('cg.nr_throttled', k)}\n"
                               f"throttled_usec {self.c('cg.throttled_usec', k)}\nnr_bursts 0\nburst_usec 0\n")
        f[f"{CG}/cpu.max"] = self.gv("cg.cpu.max", k) + "\n"
        f[f"{CG}/cpu.pressure"] = f"some avg10=0.00 avg60=0.00 avg300=0.00 total={self.c('cg.cpu.some', k)}\n" \
                                  "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
        f[f"{CG}/memory.pressure"] = (f"some avg10=0.00 avg60=0.00 avg300=0.00 total={self.c('cg.mem.some', k)}\n"
                                      f"full avg10=0.00 avg60=0.00 avg300=0.00 total={self.c('cg.mem.full', k)}\n")
        f[f"{CG}/memory.stat"] = (f"anon 1\nfile 2\npgscan {self.c('cg.pgscan', k)}\npgsteal 0\n"
                                  f"workingset_refault_anon {self.c('cg.refault_anon', k)}\n"
                                  f"workingset_refault_file {self.c('cg.refault_file', k)}\n"
                                  f"pgmajfault {self.c('cg.pgmajfault', k)}\n")
        f[f"{CG}/memory.events"] = (f"low 0\nhigh {self.c('cg.events.high', k)}\nmax 0\noom 0\n"
                                    f"oom_kill {self.c('cg.events.oom_kill', k)}\noom_group_kill 0\n")
        f[f"{CG}/memory.current"] = f"{self.gv('cg.memory.current', k)}\n"
        f[f"{CG}/memory.max"] = f"{self.gv('cg.memory.max', k)}\n"
        f[f"{CG}/memory.swap.current"] = f"{self.gv('cg.swap', k)}\n"
        for name in ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_dropped", "rx_missed_errors",
                     "rx_fifo_errors", "tx_dropped", "tx_fifo_errors", "rx_errors", "tx_errors"):
            f[f"/sys/class/net/eth0/statistics/{name}"] = f"{self.c('if.' + name, k)}\n"
        for tid in self.tids:
            base = f"/proc/100/task/{tid}"
            f[f"{base}/schedstat"] = f"123456 {self.c('task.run_delay', k)} 42\n"
            f[f"{base}/sched"] = (f"lab ({tid}, #threads: {len(self.tids)})\n-----\nse.exec_start : 1.0\n"
                                  f"se.nr_migrations                             :   {self.c('task.nr_migrations', k)}\n")
            f[f"{base}/status"] = f"Name:\tlab\nvoluntary_ctxt_switches:\t5\nnonvoluntary_ctxt_switches:\t{self.c('task.nonvol', k)}\n"
            rest = ["S"] + ["0"] * 35 + [str(self.gv("task.processor", k))] + ["0"] * 13
            f[f"{base}/stat"] = f"{tid} (lab worker) " + " ".join(rest) + "\n"
        for (path, tick), v in self.overrides.items():
            if tick == k:
                if v is None:
                    f.pop(path, None)
                else:
                    f[path] = v
        return f

    def reader(self, k):
        return FixtureReader(self.files(k), dirs={"/proc/100/task": [str(t) for t in self.tids]},
                             links={"/proc/100/ns/net": "net:[4026531840]", "/proc/self/ns/net": "net:[4026531840]"})

    def ticks(self, target=TARGET, n=NB + NW + 1):
        return [Tick(k, float(k), T0 + timedelta(seconds=k), sample(self.reader(k), target)) for k in range(n)]

    def override(self, path, ticks, value):
        for k in ticks:
            self.overrides[(path, k)] = value
        return self


def build(world=None, target=TARGET, **param_over):
    from sentinelai.collectors import build_snapshot
    w = world or World()
    return build_snapshot(w.ticks(target), target, params(**param_over))


def meas(snap, feature, scope):
    found = [m for m in snap.measurements if m.feature_id == feature and m.scope == scope]
    assert len(found) == 1, (feature, scope, len(found))
    return found[0]


W_TICKS = range(NB + 1, NB + NW + 1)        # counter intervals in W end at these ticks
DENIED = Bad(Status.DENIED, "Permission denied")
