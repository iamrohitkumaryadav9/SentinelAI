"""Resolve a Target from a cgroup path (read-only)."""

from typing import Iterable, Optional

from ..diagnostic.contract import Target
from .errors import Bad, CollectorError, ParseError
from .parsers.cgroup import cpuset_list


def _cpuset(reader, cgroup_path: str) -> Optional[str]:
    """Nearest cpuset.cpus.effective from the target cgroup up to the root."""
    parts = [p for p in cgroup_path.strip("/").split("/") if p]
    for i in range(len(parts), -1, -1):
        d = "/sys/fs/cgroup" + "".join("/" + p for p in parts[:i])
        text = reader.read(f"{d}/cpuset.cpus.effective")
        if isinstance(text, Bad):
            continue
        try:
            cpus = cpuset_list(text)
        except ParseError as exc:
            raise CollectorError(f"{d}/cpuset.cpus.effective: {exc}")
        return ",".join(str(c) for c in cpus)
    return None


def resolve_target(reader, name: str, cgroup_path: str, ifaces: Iterable[str] = ()) -> Target:
    procs = reader.read(f"/sys/fs/cgroup{cgroup_path.rstrip('/')}/cgroup.procs")
    if isinstance(procs, Bad):
        raise CollectorError(f"cannot read cgroup.procs of {cgroup_path}: {procs.status.value} {procs.detail}")
    try:
        pids = tuple(sorted({int(l) for l in procs.split() if l.strip()}))
    except ValueError:
        raise CollectorError(f"malformed cgroup.procs of {cgroup_path}")
    if not pids:
        raise CollectorError(f"cgroup {cgroup_path} has no processes")
    return Target(name=name, cgroup_path=cgroup_path, pids=pids, cpuset=_cpuset(reader, cgroup_path),
                  netns_ref=f"pid:{pids[0]}", ifaces=tuple(ifaces))
