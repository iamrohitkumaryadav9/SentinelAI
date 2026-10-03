"""Run the eBPF loader (or the replay harness) as a child process and serve its samples per tick.

Safety:
  * one execution site (ProcessEbpfSource.start), list argv, shell=False, no environment inheritance
    beyond PATH, stdin/stdout pipes only, stderr discarded;
  * argv is built only by loader_argv / replay_argv: an absolute path to one of the two known binaries
    plus fixed flags with integer values; anything else is refused before execution;
  * nothing here elevates privileges: the loader only works when the caller already has them, and
    otherwise answers "unavailable", which becomes Bad observations (never zeros);
  * bounded: one outstanding request, one line per request, line length capped, read timeout, and
    the loader itself exits at --max-seconds.
"""

import os
import re
import select
import subprocess
from pathlib import Path
from typing import List, Optional

from ..collectors.ebpf import MAX_LINE, EbpfStream, EbpfTarget, bad_obs
from ..collectors.errors import Status
from ..collectors.probes import netns_pid
from ..diagnostic.contract import Target

BUILD = Path(__file__).resolve().parents[3] / "ebpf" / "build"
DEFAULT_LOADER = BUILD / "sentinel_loader"
DEFAULT_REPLAY = BUILD / "sentinel_replay"
BINARIES = ("sentinel_loader", "sentinel_replay")
MAX_SECONDS = 86400
_NETNS = re.compile(r"^net:\[(\d+)\]$")


class LoaderRefused(ValueError):
    """An argv or target that the process boundary does not allow."""


def resolve_ebpf_target(target: Target) -> EbpfTarget:
    """Read-only: kernfs id (inode) and depth of the target cgroup, and the target netns inode."""
    parts = [p for p in target.cgroup_path.split("/") if p]
    path = "/sys/fs/cgroup" + "".join("/" + p for p in parts)
    if any(p in (".", "..") for p in parts):
        raise LoaderRefused(f"cgroup path {target.cgroup_path!r} is not canonical")
    pid = netns_pid(target)
    if pid is None:
        raise LoaderRefused("target has no pid-based netns_ref")
    m = _NETNS.match(os.readlink(f"/proc/{pid}/ns/net"))
    if not m:
        raise LoaderRefused("unexpected netns link format")
    return EbpfTarget(cgroup_id=os.stat(path).st_ino, cgroup_level=len(parts), netns_inum=int(m.group(1)))


def _binary(path, name: str) -> str:
    p = Path(path)
    if not p.is_absolute() or p.name != name or name not in BINARIES:
        raise LoaderRefused(f"{path!s} is not an absolute path to {name}")
    return str(p)


def _int(v, lo: int, hi: int, what: str) -> str:
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise LoaderRefused(f"{what} {v!r} outside [{lo}, {hi}]")
    return str(v)


def loader_argv(ids: EbpfTarget, max_seconds: int, binary=DEFAULT_LOADER) -> List[str]:
    return [_binary(binary, "sentinel_loader"),
            "--cgroup-id", _int(ids.cgroup_id, 1, (1 << 64) - 1, "cgroup id"),
            "--cgroup-level", _int(ids.cgroup_level, 0, 64, "cgroup level"),
            "--netns-inum", _int(ids.netns_inum, 1, (1 << 32) - 1, "netns inode"),
            "--max-seconds", _int(max_seconds, 1, MAX_SECONDS, "max seconds")]


def replay_argv(script, ncpu: int = 4, binary=DEFAULT_REPLAY) -> List[str]:
    """The replay harness in loader-protocol mode (--serve): for tests of this process boundary."""
    s = Path(script)
    if not s.is_absolute():
        raise LoaderRefused("replay script must be an absolute path")
    return [_binary(binary, "sentinel_replay"), "--ncpu", _int(ncpu, 1, 64, "ncpu"), "--serve", str(s)]


def _check_argv(argv) -> List[str]:
    if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
        raise LoaderRefused("argv must be a non-empty list of strings")
    name = Path(argv[0]).name
    if name not in BINARIES or not Path(argv[0]).is_absolute():
        raise LoaderRefused(f"refusing to execute {argv[0]!r}")
    flags = {"sentinel_loader": {"--cgroup-id", "--cgroup-level", "--netns-inum", "--max-seconds"},
             "sentinel_replay": {"--ncpu", "--serve"}}[name]
    for a in argv[1:]:
        if a.startswith("-") and a not in flags:
            raise LoaderRefused(f"flag {a!r} not allowed for {name}")
    return list(argv)


class ProcessEbpfSource:
    """Collector-facing eBPF source backed by a child process speaking the loader line protocol."""

    def __init__(self, argv: List[str], expect: EbpfTarget, timeout_s: float = 2.0, runner=subprocess.Popen):
        self.argv = _check_argv(argv)
        self.stream = EbpfStream(expect)
        self.timeout_s, self._runner = timeout_s, runner
        self.proc, self._buf = None, bytearray()

    def start(self) -> Optional[str]:
        """Start the process and read its first line. Returns None when usable, else the reason."""
        try:
            self.proc = self._runner(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                                     env={"PATH": "/usr/bin:/bin"})
        except OSError as exc:
            self.stream.failed = f"loader could not start: {exc.strerror or exc}"
            return self.stream.failed
        line = self._readline()
        if line is None:
            self.stream.failed = "loader produced no meta line"
            self.close()
            return self.stream.failed
        reason = self.stream.start(line)
        if reason is not None:
            self.close()
        return reason

    def _readline(self) -> Optional[str]:
        fd = self.proc.stdout.fileno()
        while b"\n" not in self._buf:
            ready, _, _ = select.select([fd], [], [], self.timeout_s)
            if not ready:
                return None
            chunk = os.read(fd, 65536)
            if not chunk:
                return None
            self._buf += chunk
            if len(self._buf) > MAX_LINE:
                self._buf.clear()
                return None
        line, _, rest = bytes(self._buf).partition(b"\n")
        self._buf = bytearray(rest)
        try:
            return line.decode("ascii")
        except UnicodeDecodeError:
            return ""

    def sample(self) -> dict:
        if self.proc is None or self.stream.meta is None:
            return bad_obs(self.stream.fail_status, self.stream.failed or "eBPF loader not started")
        try:
            self.proc.stdin.write(b"s")
            self.proc.stdin.flush()
        except OSError:
            return bad_obs(Status.ABSENT, "eBPF loader is no longer running")
        return self.stream.observe(self._readline())

    def close(self) -> None:
        if self.proc is None:
            return
        try:
            self.proc.stdin.write(b"q")
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc.stdout.close()
