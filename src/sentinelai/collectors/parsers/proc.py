"""Parsers for /proc sources (contract §4)."""

import re
from typing import Dict

from ..errors import ParseError
from ._common import hexint, keyed, sint, uint

STAT_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
_CPU = re.compile(r"^cpu(\d*)$")


def proc_stat(text: str) -> Dict:
    """/proc/stat -> {'cpus': {'all'|N: {field: jiffies}}, 'ctxt': int, 'procs_running': int}.
    guest/guest_nice are already included in user/nice and are not used."""
    cpus, out = {}, {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        m = _CPU.match(parts[0])
        if m:
            if len(parts) < 1 + len(STAT_FIELDS):
                raise ParseError(f"/proc/stat {parts[0]}: {len(parts) - 1} fields, need {len(STAT_FIELDS)}")
            key = "all" if m.group(1) == "" else int(m.group(1))
            if key in cpus:
                raise ParseError(f"/proc/stat: duplicate line {parts[0]}")
            cpus[key] = {f: uint(v, f"/proc/stat {parts[0]}.{f}") for f, v in zip(STAT_FIELDS, parts[1:])}
            for v in parts[1 + len(STAT_FIELDS):]:      # guest fields: validated, not used
                uint(v, f"/proc/stat {parts[0]}")
        elif parts[0] in ("ctxt", "procs_running"):
            if len(parts) != 2 or parts[0] in out:
                raise ParseError(f"/proc/stat: malformed {parts[0]} line")
            out[parts[0]] = uint(parts[1], f"/proc/stat {parts[0]}")
    if "all" not in cpus:
        raise ParseError("/proc/stat: no aggregate 'cpu' line")
    out["cpus"] = cpus
    return out


def schedstat(text: str) -> Dict[int, int]:
    """/proc/schedstat (version 15) -> {cpu: run_delay_ns} (cpu line field 8)."""
    lines = text.splitlines()
    if not lines or lines[0].split() != ["version", "15"]:
        raise ParseError(f"/proc/schedstat: unsupported version line {lines[0] if lines else ''!r} (need 15)")
    out = {}
    for line in lines[1:]:
        parts = line.split()
        if parts and re.match(r"^cpu\d+$", parts[0]):
            if len(parts) < 10:
                raise ParseError(f"/proc/schedstat {parts[0]}: {len(parts) - 1} fields, need 9")
            cpu = int(parts[0][3:])
            if cpu in out:
                raise ParseError(f"/proc/schedstat: duplicate {parts[0]}")
            out[cpu] = uint(parts[8], f"/proc/schedstat {parts[0]} run_delay")
    if not out:
        raise ParseError("/proc/schedstat: no cpu lines")
    return out


def softirqs(text: str) -> Dict[str, Dict[int, int]]:
    """/proc/softirqs -> {'NET_RX': {cpu: count}, 'NET_TX': {...}} (columns named by header)."""
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        raise ParseError("/proc/softirqs: empty")
    header = lines[0].split()
    if not header or not all(re.match(r"^CPU\d+$", h) for h in header):
        raise ParseError("/proc/softirqs: malformed header")
    cpus = [int(h[3:]) for h in header]
    if len(set(cpus)) != len(cpus):
        raise ParseError("/proc/softirqs: duplicate CPU column")
    out = {}
    for line in lines[1:]:
        name, _, rest = line.partition(":")
        name, vals = name.strip(), rest.split()
        if name in ("NET_RX", "NET_TX"):
            if len(vals) != len(cpus):
                raise ParseError(f"/proc/softirqs {name}: {len(vals)} values for {len(cpus)} CPUs")
            out[name] = {c: uint(v, f"/proc/softirqs {name}") for c, v in zip(cpus, vals)}
    for name in ("NET_RX", "NET_TX"):
        if name not in out:
            raise ParseError(f"/proc/softirqs: no {name} row")
    return out


SOFTNET_CPU_COL = 12   # kernel >= 5.10 appends the CPU id; rows are NOT indexed by CPU otherwise


def softnet_stat(text: str) -> Dict[int, Dict[str, int]]:
    """/proc/net/softnet_stat (hex) -> {cpu: {'processed', 'dropped', 'time_squeeze'}}.
    CPU identity comes from the cpu-id column; without it (old kernels) the file is rejected,
    because rows skip offline CPUs and cannot be attributed safely."""
    out = {}
    for n, line in enumerate(text.splitlines(), 1):
        cols = line.split()
        if not cols:
            continue
        if len(cols) <= SOFTNET_CPU_COL:
            raise ParseError(f"softnet_stat row {n}: {len(cols)} columns; no cpu-id column")
        vals = [hexint(c, f"softnet_stat row {n}") for c in cols]
        cpu = vals[SOFTNET_CPU_COL]
        if cpu in out:
            raise ParseError(f"softnet_stat: duplicate cpu id {cpu}")
        out[cpu] = {"processed": vals[0], "dropped": vals[1], "time_squeeze": vals[2]}
    if not out:
        raise ParseError("softnet_stat: empty")
    return out


def snmp_table(text: str, section: str, what: str) -> Dict[str, int]:
    """/proc/net/snmp or /proc/net/netstat: header/value line pairs, parsed BY NAME (contract §4.4)."""
    rows = [l.split() for l in text.splitlines() if l.startswith(section + ":")]
    if not rows:
        raise ParseError(f"{what}: no {section} section")
    if len(rows) != 2:
        raise ParseError(f"{what}: {section} must have exactly one header and one value line")
    names, values = rows[0][1:], rows[1][1:]
    if len(names) != len(values) or len(set(names)) != len(names):
        raise ParseError(f"{what}: {section} header/value mismatch")
    return {k: sint(v, f"{what} {section}.{k}") for k, v in zip(names, values)}


def meminfo(text: str) -> Dict[str, int]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(\w+):\s+(\d+)(?:\s+kB)?$", line.strip())
        if m:
            if m.group(1) in out:
                raise ParseError(f"/proc/meminfo: duplicate {m.group(1)}")
            out[m.group(1)] = int(m.group(2))
    for k in ("MemTotal", "MemAvailable"):
        if k not in out:
            raise ParseError(f"/proc/meminfo: no {k}")
    if out["MemTotal"] <= 0:
        raise ParseError("/proc/meminfo: MemTotal must be positive")
    return out


def vmstat(text: str) -> Dict[str, int]:
    return keyed(text, "/proc/vmstat")


def psi(text: str, what: str) -> Dict[str, int]:
    """PSI file -> {'some': total_us, 'full'?: total_us}."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] not in ("some", "full"):
            raise ParseError(f"{what}: unexpected line {line!r}")
        fields = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
        if "total" not in fields or parts[0] in out:
            raise ParseError(f"{what}: malformed {parts[0]} line")
        out[parts[0]] = uint(fields["total"], f"{what} {parts[0]}.total")
    if "some" not in out:
        raise ParseError(f"{what}: no 'some' line")
    return out


# -- per-task files ------------------------------------------------------------------------
def task_schedstat(text: str) -> int:
    """/proc/<pid>/task/<tid>/schedstat -> run_delay_ns (field 2)."""
    parts = text.split()
    if len(parts) != 3:
        raise ParseError(f"task schedstat: expected 3 fields, got {len(parts)}")
    return uint(parts[1], "task schedstat run_delay")


def task_sched_migrations(text: str) -> int:
    for line in text.splitlines():
        key, sep, val = line.partition(":")
        if sep and key.strip() == "se.nr_migrations":
            return uint(val.strip(), "se.nr_migrations")
    raise ParseError("task sched: no se.nr_migrations")


def task_status_nonvol(text: str) -> int:
    for line in text.splitlines():
        key, sep, val = line.partition(":")
        if sep and key == "nonvoluntary_ctxt_switches":
            return uint(val.strip(), "nonvoluntary_ctxt_switches")
    raise ParseError("task status: no nonvoluntary_ctxt_switches")


def task_stat_processor(text: str) -> int:
    """/proc/<pid>/task/<tid>/stat field 39 (CPU last run on). comm may contain spaces/parens."""
    i = text.rfind(")")
    if i < 0:
        raise ParseError("task stat: no comm terminator")
    rest = text[i + 1:].split()          # rest[0] is field 3
    if len(rest) < 37:
        raise ParseError(f"task stat: {len(rest) + 2} fields, need 39")
    return uint(rest[36], "task stat processor")
