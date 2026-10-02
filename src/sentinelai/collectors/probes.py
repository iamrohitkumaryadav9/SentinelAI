"""Acquisition: one read of every source for a target at one tick.

Each source becomes either a Bad(status) or a dict of named numeric fields (a field may itself be
Bad). Nothing is defaulted: an unreadable file is Bad(ABSENT/DENIED), unparseable text is
Bad(MALFORMED). Parsing is delegated to the pure functions in ``parsers``.
"""

from typing import Dict, Optional, Union

from ..diagnostic.contract import Target
from .errors import Bad, ParseError, Status
from .parsers import cgroup as pc
from .parsers import proc as pp
from .parsers import sysfs as ps

IFACE_FIELDS = ("rx_dropped", "rx_missed_errors", "rx_fifo_errors", "tx_dropped", "tx_fifo_errors",
                "rx_errors", "tx_errors", "rx_packets", "tx_packets", "rx_bytes", "tx_bytes")
VMSTAT_FIELDS = ("pgscan_direct", "pswpin", "pswpout")
NETSTAT_FIELDS = ("TCPBacklogDrop", "TCPRcvQDrop", "TCPTimeouts", "TCPFastRetrans", "TCPSynRetrans")
MEMSTAT_FIELDS = ("pgscan", "workingset_refault_anon", "workingset_refault_file", "pgmajfault")

Obs = Dict[str, Union[Bad, Dict]]


def cgroup_dir(target: Target) -> str:
    return "/sys/fs/cgroup" + target.cgroup_path.rstrip("/")


def netns_pid(target: Target) -> Optional[int]:
    ref = target.netns_ref or ""
    if ref.startswith("pid:") and ref[4:].isdigit() and int(ref[4:]) > 0:
        return int(ref[4:])
    return None


def _parse(reader, path, fn, *args):
    text = reader.read(path)
    if isinstance(text, Bad):
        return text
    try:
        return fn(text, *args)
    except ParseError as exc:
        return Bad(Status.MALFORMED, str(exc))


def _pick(parsed, fields):
    if isinstance(parsed, Bad):
        return parsed
    return {f: float(parsed[f]) for f in fields if f in parsed}


def _proc_stat(reader):
    p = _parse(reader, "/proc/stat", pp.proc_stat)
    if isinstance(p, Bad):
        return p
    out = {}
    for cpu, f in p["cpus"].items():
        name = "all" if cpu == "all" else f"cpu{cpu}"
        busy = f["user"] + f["nice"] + f["system"] + f["irq"] + f["softirq"] + f["steal"]
        out[f"{name}.busy"] = float(busy)
        out[f"{name}.total"] = float(busy + f["idle"] + f["iowait"])
        out[f"{name}.steal"] = float(f["steal"])
        out[f"{name}.softirq"] = float(f["softirq"])
    for k in ("ctxt", "procs_running"):
        if k in p:
            out[k] = float(p[k])
    return out


def _schedstat(reader):
    p = _parse(reader, "/proc/schedstat", pp.schedstat)
    return p if isinstance(p, Bad) else {f"cpu{c}.run_delay": float(v) for c, v in p.items()}


def _softirqs(reader):
    p = _parse(reader, "/proc/softirqs", pp.softirqs)
    return p if isinstance(p, Bad) else {f"{n}.cpu{c}": float(v) for n, row in p.items() for c, v in row.items()}


def _softnet(reader):
    p = _parse(reader, "/proc/net/softnet_stat", pp.softnet_stat)
    return p if isinstance(p, Bad) else {f"cpu{c}.{k}": float(v) for c, row in p.items() for k, v in row.items()}


def _cpu_max(reader, cg):
    p = _parse(reader, f"{cg}/cpu.max", pc.cpu_max)
    if isinstance(p, Bad):
        return p
    if p is None:
        return {"limited": 0.0, "quota_cores": Bad(Status.ABSENT, "unlimited quota: quota_cores not emitted")}
    return {"limited": 1.0, "quota_cores": p[0] / p[1]}


def _netns(reader, pid):
    if pid is None:
        return Bad(Status.UNVERIFIED, "target has no pid-based netns_ref")
    a, b = reader.readlink(f"/proc/{pid}/ns/net"), reader.readlink("/proc/self/ns/net")
    if isinstance(a, Bad) or isinstance(b, Bad):
        return Bad(Status.UNVERIFIED, "target netns cannot be compared with the collector's netns "
                                      f"({(a if isinstance(a, Bad) else b).detail})")
    return {"same": 1.0 if a == b else 0.0}


def _iface(reader, ifname):
    base = f"/sys/class/net/{ifname}/statistics"
    out = {}
    for f in IFACE_FIELDS:
        v = _parse(reader, f"{base}/{f}", ps.counter, f"{ifname}/{f}")
        out[f] = v if isinstance(v, Bad) else float(v)
    return out


def _tasks(reader, pids):
    """Per-thread counters of the target: {'run_delay'|'nr_migrations'|'nonvol'|'processor': {tid: v}}."""
    files = (("run_delay", "schedstat", pp.task_schedstat), ("nr_migrations", "sched", pp.task_sched_migrations),
             ("nonvol", "status", pp.task_status_nonvol), ("processor", "stat", pp.task_stat_processor))
    maps = {k: {} for k, _, _ in files}
    bad = {}
    listed = False
    for pid in pids:
        tids = reader.listdir(f"/proc/{pid}/task")
        if isinstance(tids, Bad):
            if tids.status is Status.DENIED:
                bad.setdefault("all", tids)
            continue
        listed = True
        for tid in tids:
            if not tid.isdigit():
                continue
            for key, name, fn in files:
                v = _parse(reader, f"/proc/{pid}/task/{tid}/{name}", fn)
                if isinstance(v, Bad):
                    if v.status is not Status.ABSENT:   # an exited thread is not an error
                        bad.setdefault(key, v)
                    continue
                maps[key][int(tid)] = float(v)
    if not listed:
        return bad.get("all", Bad(Status.ABSENT, "no target thread could be listed"))
    return {k: bad[k] if k in bad else (maps[k] if maps[k] else Bad(Status.ABSENT, "no target thread readable"))
            for k in maps}


def sample(reader, target: Target) -> Obs:
    """Read every source once. Pure function of what the reader returns."""
    cg, nspid = cgroup_dir(target), netns_pid(target)
    net = f"/proc/{nspid}/net" if nspid else None
    no_ns = Bad(Status.ABSENT, "target has no pid-based netns_ref")
    obs: Obs = {
        "proc.stat": _proc_stat(reader),
        "proc.schedstat": _schedstat(reader),
        "proc.softirqs": _softirqs(reader),
        "proc.softnet": _softnet(reader),
        "proc.meminfo": _pick(_parse(reader, "/proc/meminfo", pp.meminfo), ("MemTotal", "MemAvailable")),
        "proc.vmstat": _pick(_parse(reader, "/proc/vmstat", pp.vmstat), VMSTAT_FIELDS),
        "proc.psi.cpu": _pick(_parse(reader, "/proc/pressure/cpu", pp.psi, "/proc/pressure/cpu"), ("some",)),
        "proc.psi.memory": _pick(_parse(reader, "/proc/pressure/memory", pp.psi, "/proc/pressure/memory"), ("some",)),
        "net.snmp": (_pick(_parse(reader, f"{net}/snmp", pp.snmp_table, "Tcp", "snmp"), ("OutSegs", "RetransSegs"))
                     if net else no_ns),
        "net.netstat": (_pick(_parse(reader, f"{net}/netstat", pp.snmp_table, "TcpExt", "netstat"), NETSTAT_FIELDS)
                        if net else no_ns),
        "netns": _netns(reader, nspid),
        "cg.cpu.stat": _pick(_parse(reader, f"{cg}/cpu.stat", pc.cpu_stat),
                             ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec")),
        "cg.cpu.max": _cpu_max(reader, cg),
        "cg.cpu.pressure": _pick(_parse(reader, f"{cg}/cpu.pressure", pp.psi, "cpu.pressure"), ("some",)),
        "cg.memory.pressure": _pick(_parse(reader, f"{cg}/memory.pressure", pp.psi, "memory.pressure"),
                                    ("some", "full")),
        "cg.memory.stat": _pick(_parse(reader, f"{cg}/memory.stat", pc.memory_stat), MEMSTAT_FIELDS),
        "cg.memory.events": _pick(_parse(reader, f"{cg}/memory.events", pc.memory_events), ("high", "oom_kill")),
        "task": _tasks(reader, target.pids),
    }
    cur = _parse(reader, f"{cg}/memory.current", pc.single, "memory.current")
    mx = _parse(reader, f"{cg}/memory.max", pc.memory_max)
    swap = _parse(reader, f"{cg}/memory.swap.current", pc.single, "memory.swap.current")
    obs["cg.memory"] = {"current": cur if isinstance(cur, Bad) else float(cur),
                        "max": mx if isinstance(mx, Bad) else (Bad(Status.ABSENT, "max") if mx is None else float(mx)),
                        "unlimited": mx if isinstance(mx, Bad) else (1.0 if mx is None else 0.0),
                        "swap": swap if isinstance(swap, Bad) else float(swap)}
    for ifname in target.ifaces:
        obs[f"sys.net.{ifname}"] = _iface(reader, ifname)
    return obs


def get(obs: Obs, src: str, field: str):
    s = obs.get(src)
    if s is None:
        return Bad(Status.ABSENT, f"{src} not sampled")
    if isinstance(s, Bad):
        return s
    if field not in s:
        return Bad(Status.ABSENT, f"{src}:{field} not present")
    return s[field]
