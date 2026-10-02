"""Contract feature -> computation table (EVIDENCE_CONTRACT.md §4).

Every entry names exactly one registered feature, its scope, its source fields and the formula the
contract gives. Nothing here judges a value: there are no thresholds and no labels.

Parts of a computation:
  C  counter: sum of (source, field) cumulative counters; contributes its delta per interval
  T  per-thread counter of the target (summed over threads present at both ends of an interval)
  G  gauge: a function of one tick's observations, sampled at the start of each interval
``combine(d, dt)`` turns the parts' values for an interval (or for the whole window) into the
feature value; it returns None when the value is undefined (e.g. a ratio whose denominator did
not advance), which is never turned into a number.
"""

from dataclasses import dataclass, field
from statistics import median
from typing import Callable, Optional, Tuple

from ..diagnostic.contract import SourceType, Target
from .errors import Bad, Status
from .probes import IFACE_FIELDS, cgroup_dir, get, netns_pid

COLLECTOR_VERSION = "m3a-1.1.0"


@dataclass(frozen=True)
class C:
    terms: Tuple[Tuple[str, str], ...]


@dataclass(frozen=True)
class T:
    field: str


@dataclass(frozen=True)
class G:
    fn: Callable
    name: str = ""


@dataclass(frozen=True)
class Calc:
    feature: str
    scope: str
    parts: Tuple[Tuple[str, object], ...]
    combine: Callable[[dict, float], Optional[float]]
    source: SourceType
    locator: str
    collector: str
    gauge_agg: str = "mean"                      # pure-gauge window aggregate: mean | last | bool
    derived_from: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)
    undefined: str = "undefined over the window: the denominator did not advance"

    @property
    def gauge_only(self) -> bool:
        return all(isinstance(p, G) for _, p in self.parts)


def rate(scale=1.0):
    return lambda d, dt: d["x"] * scale / dt


def ratio(d, dt):
    return d["n"] / d["d"] if d["d"] > 0 else None


def delta(d, dt):
    return d["x"]


def ident(d, dt):
    return d["g"]


def g(src, fld):
    return G(lambda obs: get(obs, src, fld), f"{src}:{fld}")


def _div(a, b):
    if isinstance(a, Bad):
        return a
    if isinstance(b, Bad):
        return b
    return a / b if b > 0 else Bad(Status.MALFORMED, "zero denominator")


def _mem_util(obs):
    cur, unl = get(obs, "cg.memory", "current"), get(obs, "cg.memory", "unlimited")
    if isinstance(unl, Bad):
        return unl
    if unl == 1.0:                                   # memory.max = 'max' -> host MemTotal (contract §4.6)
        tot = get(obs, "proc.meminfo", "MemTotal")
        return _div(cur, tot if isinstance(tot, Bad) else tot * 1024.0)
    return _div(cur, get(obs, "cg.memory", "max"))


def _iface_guard(obs):
    """sysfs shows the collector's netns: attributable to the target only if it is the same netns."""
    same = get(obs, "netns", "same")
    if isinstance(same, Bad):
        return same
    return 1.0 if same == 1.0 else Bad(Status.UNVERIFIED, "target netns differs from the collector's netns")


def _max_frac(cpus):
    def f(d, dt):
        if any(d[f"t{n}"] <= 0 for n in cpus):
            return None
        return max(d[f"s{n}"] / d[f"t{n}"] for n in cpus)
    return f


def _imbalance(cpus):
    def f(d, dt):
        if any(d[f"t{n}"] <= 0 for n in cpus):
            return None
        fr = [d[f"s{n}"] / d[f"t{n}"] for n in cpus]
        med = median(fr)
        return max(fr) / med if med > 0 else None
    return f


def _excess(d, dt):
    """sched.run_delay_excess.target = max(0, run_delay.target - throttle.time_rate) (contract §4.1)."""
    return max(0.0, d["rd"] * 1e-9 / dt - d["tt"] * 1e-6 / dt)


def _saturation(d, dt):
    return (d["u"] * 1e-6 / dt) / d["q"] if d["q"] > 0 else None


def build(target: Target, cpus: Tuple[int, ...], cpuset: Tuple[int, ...], relevant: Tuple[int, ...],
          emit_quota: bool) -> Tuple[Calc, ...]:
    """All attempted measurements for this target. cpus: every CPU observed on the host."""
    P, D, CG_, SY, TC = SourceType.PROC, SourceType.DERIVED, SourceType.CGROUPFS, SourceType.SYSFS, SourceType.TC
    cg = cgroup_dir(target)
    CG, NS = f"cgroup:{target.cgroup_path}", f"netns:{target.name}"
    pid = netns_pid(target)
    net = f"/proc/{pid}/net" if pid else "/proc/<no-netns-pid>/net"
    at = f"@netns(pid={pid})"
    pids = ",".join(str(p) for p in target.pids)
    cs = ",".join(str(n) for n in cpuset)
    st = lambda n, f: ("proc.stat", f"cpu{n}.{f}")
    out = [
        # ---- CPU / scheduler (§4.1)
        Calc("cpu.util.host", "host", (("n", C((("proc.stat", "all.busy"),))), ("d", C((("proc.stat", "all.total"),)))),
             ratio, P, "/proc/stat:cpu (user+nice+system+irq+softirq+steal)/total", "m3a.proc.stat"),
        Calc("cpu.util.cpuset", "cpuset", (("n", C(tuple(st(n, "busy") for n in cpuset))),
                                           ("d", C(tuple(st(n, "total") for n in cpuset)))),
             ratio, P, f"/proc/stat:cpu{{{cs}}} busy/total", "m3a.proc.stat"),
        Calc("cpu.steal.cpuset", "cpuset", (("n", C(tuple(st(n, "steal") for n in cpuset))),
                                            ("d", C(tuple(st(n, "total") for n in cpuset)))),
             ratio, P, f"/proc/stat:cpu{{{cs}}} steal/total", "m3a.proc.stat"),
        Calc("cpu.usage.target", CG, (("x", C((("cg.cpu.stat", "usage_usec"),))),), rate(1e-6), CG_,
             f"{cg}/cpu.stat:usage_usec", "m3a.cgroup.cpu"),
        Calc("sched.run_delay.target", CG, (("x", T("run_delay")),), rate(1e-9), P,
             f"/proc/{{{pids}}}/task/<tid>/schedstat:field2 summed over target threads", "m3a.proc.task"),
        Calc("sched.run_delay.cpuset", "cpuset", (("x", C(tuple(("proc.schedstat", f"cpu{n}.run_delay") for n in cpuset))),),
             rate(1e-9), P, f"/proc/schedstat:cpu{{{cs}}} field8 summed", "m3a.proc.schedstat"),
        Calc("sched.run_delay_excess.target", CG, (("rd", T("run_delay")), ("tt", C((("cg.cpu.stat", "throttled_usec"),)))),
             _excess, D, "max(0, sched.run_delay.target - throttle.time_rate)", "m3a.derived",
             derived_from=(("sched.run_delay.target", CG), ("throttle.time_rate", CG))),
        Calc("sched.nr_migrations.target", CG, (("x", T("nr_migrations")),), rate(), P,
             f"/proc/{{{pids}}}/task/<tid>/sched:se.nr_migrations summed", "m3a.proc.task"),
        Calc("sched.involuntary_cs.target", CG, (("x", T("nonvol")),), rate(), P,
             f"/proc/{{{pids}}}/task/<tid>/status:nonvoluntary_ctxt_switches summed", "m3a.proc.task"),
        Calc("sched.ctxt.host", "host", (("x", C((("proc.stat", "ctxt"),))),), rate(), P, "/proc/stat:ctxt", "m3a.proc.stat"),
        Calc("sched.procs_running.host", "host", (("g", g("proc.stat", "procs_running")),), ident, P,
             "/proc/stat:procs_running", "m3a.proc.stat"),
        Calc("psi.cpu.some.target", CG, (("x", C((("cg.cpu.pressure", "some"),))),), rate(1e-6), CG_,
             f"{cg}/cpu.pressure:some total", "m3a.cgroup.cpu"),
        Calc("psi.cpu.some.host", "host", (("x", C((("proc.psi.cpu", "some"),))),), rate(1e-6), P,
             "/proc/pressure/cpu:some total", "m3a.proc.psi"),
        # ---- throttling (§4.2)
        Calc("throttle.quota_limited", CG, (("g", g("cg.cpu.max", "limited")),), ident, CG_,
             f"{cg}/cpu.max: max->0.0, <quota> <period>->1.0", "m3a.cgroup.cpu", gauge_agg="bool"),
        Calc("throttle.ratio", CG, (("n", C((("cg.cpu.stat", "nr_throttled"),))), ("d", C((("cg.cpu.stat", "nr_periods"),)))),
             ratio, CG_, f"{cg}/cpu.stat:d(nr_throttled)/d(nr_periods)", "m3a.cgroup.cpu"),
        Calc("throttle.time_rate", CG, (("x", C((("cg.cpu.stat", "throttled_usec"),))),), rate(1e-6), CG_,
             f"{cg}/cpu.stat:d(throttled_usec)/dt", "m3a.cgroup.cpu"),
        # ---- TCP and socket drops in the target netns (§4.3, §4.4)
        Calc("net.drop.socket", NS, (("x", C((("net.netstat", "TCPBacklogDrop"), ("net.netstat", "TCPRcvQDrop")))),),
             rate(), P, f"{net}/netstat:TcpExt.TCPBacklogDrop+TCPRcvQDrop{at}", "m3a.proc.net"),
        Calc("tcp.retrans_rate", NS, (("x", C((("net.snmp", "RetransSegs"),))),), rate(), P,
             f"{net}/snmp:Tcp.RetransSegs{at}", "m3a.proc.net"),
        Calc("tcp.out_segs_rate", NS, (("x", C((("net.snmp", "OutSegs"),))),), rate(), P,
             f"{net}/snmp:Tcp.OutSegs{at}", "m3a.proc.net"),
        Calc("tcp.retrans_frac", NS, (("n", C((("net.snmp", "RetransSegs"),))), ("d", C((("net.snmp", "OutSegs"),)))),
             ratio, P, f"{net}/snmp:d(Tcp.RetransSegs)/d(Tcp.OutSegs){at}", "m3a.proc.net"),
        Calc("tcp.timeouts_rate", NS, (("x", C((("net.netstat", "TCPTimeouts"),))),), rate(), P,
             f"{net}/netstat:TcpExt.TCPTimeouts{at}", "m3a.proc.net"),
        Calc("tcp.fast_retrans_rate", NS, (("x", C((("net.netstat", "TCPFastRetrans"),))),), rate(), P,
             f"{net}/netstat:TcpExt.TCPFastRetrans{at}", "m3a.proc.net"),
        Calc("tcp.syn_retrans_rate", NS, (("x", C((("net.netstat", "TCPSynRetrans"),))),), rate(), P,
             f"{net}/netstat:TcpExt.TCPSynRetrans{at}", "m3a.proc.net"),
        # ---- memory (§4.6)
        Calc("mem.util.target", CG, (("g", G(_mem_util, "memory.current/memory.max")),), ident, CG_,
             f"{cg}/memory.current / memory.max ('max' -> /proc/meminfo MemTotal)", "m3a.cgroup.memory"),
        Calc("mem.available.host", "host", (("g", G(lambda o: _div(get(o, "proc.meminfo", "MemAvailable"),
                                                                    get(o, "proc.meminfo", "MemTotal")), "meminfo")),),
             ident, P, "/proc/meminfo:MemAvailable/MemTotal", "m3a.proc.meminfo"),
        Calc("psi.mem.some.target", CG, (("x", C((("cg.memory.pressure", "some"),))),), rate(1e-6), CG_,
             f"{cg}/memory.pressure:some total", "m3a.cgroup.memory"),
        Calc("psi.mem.full.target", CG, (("x", C((("cg.memory.pressure", "full"),))),), rate(1e-6), CG_,
             f"{cg}/memory.pressure:full total", "m3a.cgroup.memory"),
        Calc("psi.mem.some.host", "host", (("x", C((("proc.psi.memory", "some"),))),), rate(1e-6), P,
             "/proc/pressure/memory:some total", "m3a.proc.psi"),
        Calc("mem.reclaim.target", CG, (("x", C((("cg.memory.stat", "pgscan"),))),), rate(), CG_,
             f"{cg}/memory.stat:d(pgscan)", "m3a.cgroup.memory"),
        Calc("mem.reclaim_direct.host", "host", (("x", C((("proc.vmstat", "pgscan_direct"),))),), rate(), P,
             "/proc/vmstat:pgscan_direct", "m3a.proc.vmstat"),
        Calc("mem.refault.target", CG, (("x", C((("cg.memory.stat", "workingset_refault_anon"),
                                                  ("cg.memory.stat", "workingset_refault_file")))),), rate(), CG_,
             f"{cg}/memory.stat:workingset_refault_anon+workingset_refault_file", "m3a.cgroup.memory"),
        Calc("mem.majfault.target", CG, (("x", C((("cg.memory.stat", "pgmajfault"),))),), rate(), CG_,
             f"{cg}/memory.stat:pgmajfault", "m3a.cgroup.memory"),
        Calc("mem.events.high", CG, (("x", C((("cg.memory.events", "high"),))),), rate(), CG_,
             f"{cg}/memory.events:high", "m3a.cgroup.memory"),
        Calc("mem.events.oom_kill", CG, (("x", C((("cg.memory.events", "oom_kill"),))),), delta, CG_,
             f"{cg}/memory.events:oom_kill (count in W)", "m3a.cgroup.memory"),
        Calc("mem.swap.target", CG, (("g", g("cg.memory", "swap")),), ident, CG_,
             f"{cg}/memory.swap.current", "m3a.cgroup.memory", gauge_agg="last"),
        Calc("mem.swap_io.host", "host", (("x", C((("proc.vmstat", "pswpin"), ("proc.vmstat", "pswpout")))),), rate(), P,
             "/proc/vmstat:pswpin+pswpout", "m3a.proc.vmstat"),
    ]
    if emit_quota:   # contract §4.2: only when a finite quota exists
        out += [
            Calc("throttle.quota_cores", CG, (("g", g("cg.cpu.max", "quota_cores")),), ident, CG_,
                 f"{cg}/cpu.max:quota/period", "m3a.cgroup.cpu", gauge_agg="last"),
            Calc("throttle.quota_saturation", CG, (("u", C((("cg.cpu.stat", "usage_usec"),))),
                                                   ("q", g("cg.cpu.max", "quota_cores"))),
                 _saturation, D, "cpu.usage.target / throttle.quota_cores", "m3a.derived",
                 derived_from=(("cpu.usage.target", CG), ("throttle.quota_cores", CG)),
                 undefined="undefined over the window: no finite quota"),
        ]
    # ---- per-CPU (§4.1, §4.3, §4.5)
    for n in cpus:
        sc = f"cpu:{n}"
        out += [
            Calc("cpu.util.percpu", sc, (("n", C((st(n, "busy"),))), ("d", C((st(n, "total"),)))), ratio, P,
                 f"/proc/stat:cpu{n} busy/total", "m3a.proc.stat"),
            Calc("softirq.frac.percpu", sc, (("n", C((st(n, "softirq"),))), ("d", C((st(n, "total"),)))), ratio, P,
                 f"/proc/stat:cpu{n} softirq/total", "m3a.proc.stat"),
            Calc("softirq.net_rx_rate.percpu", sc, (("x", C((("proc.softirqs", f"NET_RX.cpu{n}"),))),), rate(), P,
                 f"/proc/softirqs:NET_RX CPU{n}", "m3a.proc.softirqs"),
            Calc("softirq.net_tx_rate.percpu", sc, (("x", C((("proc.softirqs", f"NET_TX.cpu{n}"),))),), rate(), P,
                 f"/proc/softirqs:NET_TX CPU{n}", "m3a.proc.softirqs"),
            Calc("net.drop.softnet", sc, (("x", C((("proc.softnet", f"cpu{n}.dropped"),))),), rate(), P,
                 f"/proc/net/softnet_stat:cpu{n} column 2 (dropped)", "m3a.proc.softnet"),
            Calc("softnet.time_squeeze.percpu", sc, (("x", C((("proc.softnet", f"cpu{n}.time_squeeze"),))),), rate(), P,
                 f"/proc/net/softnet_stat:cpu{n} column 3 (time_squeeze)", "m3a.proc.softnet"),
            Calc("softnet.processed.percpu", sc, (("x", C((("proc.softnet", f"cpu{n}.processed"),))),), rate(), P,
                 f"/proc/net/softnet_stat:cpu{n} column 1 (processed)", "m3a.proc.softnet"),
        ]
    if relevant:
        parts = tuple(p for n in relevant for p in ((f"s{n}", C((st(n, "softirq"),))), (f"t{n}", C((st(n, "total"),)))))
        src = tuple(("softirq.frac.percpu", f"cpu:{n}") for n in relevant)
        rel = ",".join(str(n) for n in relevant)
        out += [
            Calc("softirq.relevant_cpu_max", "cpuset", parts, _max_frac(relevant), D,
                 f"max softirq.frac.percpu over cpu{{{rel}}}", "m3a.derived", derived_from=src),
            Calc("softirq.imbalance", "cpuset", parts, _imbalance(relevant), D,
                 f"max/median softirq.frac.percpu over cpu{{{rel}}}", "m3a.derived", derived_from=src,
                 undefined="undefined over the window: median softirq fraction is 0 or a CPU total did not advance"),
        ]
    # ---- interfaces in the target netns (§4.3): sysfs is only attributable in the collector's netns
    for ifname in target.ifaces:
        sc, s = f"iface:{target.name}/{ifname}", f"sys.net.{ifname}"
        guard = ("ns", G(_iface_guard, "netns"))
        base = f"/sys/class/net/{ifname}/statistics"
        for feat, fields in (("net.drop.iface_rx", ("rx_dropped", "rx_missed_errors", "rx_fifo_errors")),
                             ("net.drop.iface_tx", ("tx_dropped", "tx_fifo_errors")),
                             ("net.err.iface", ("rx_errors", "tx_errors")),
                             ("net.pkts.iface", ("rx_packets", "tx_packets")),
                             ("net.bytes.iface", ("rx_bytes", "tx_bytes"))):
            assert set(fields) <= set(IFACE_FIELDS)
            out.append(Calc(feat, sc, (("x", C(tuple((s, f) for f in fields))), guard), rate(), SY,
                            f"{base}/{'+'.join(fields)}", "m3a.sysfs.net"))
        # tc runs in the collector's netns, so the same netns guard applies (M3A-C1)
        out.append(Calc("net.drop.qdisc", sc, (("x", C(((f"tc.{ifname}", "drops"),))), guard), rate(), TC,
                        f"tc -s -j qdisc show dev {ifname} -> drops (single root qdisc)", "m3a.tc.qdisc"))
    return tuple(out)


# Registered features M3A does not collect, with the reason (reported, never silently dropped).
NOT_COLLECTED = {
    "sched.latency_hist.target": "privileged eBPF source (P) not available in M3A",
    "net.drop.netfilter": "FaultLab-only source (L) not available",
    "tcp.srtt_ms": "ss collector not implemented in M3A (A*: unverified read path; target-socket attribution "
                   "needs privileges)",
    "tcp.cwnd": "ss collector not implemented in M3A (A*: unverified read path; target-socket attribution "
                "needs privileges)",
}
APP_REASON = "application instrumentation (L) not available"
