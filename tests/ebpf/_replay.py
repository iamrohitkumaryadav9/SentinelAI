"""Helpers: build the eBPF tree once, write synthetic event scripts, run them through the replay harness
(the BPF program's own event-handling code, sentinel_core.h, compiled for userspace)."""

import json
import subprocess
import tempfile
from pathlib import Path

from sentinelai.collectors.ebpf import VECTORS, EbpfTarget

REPO = Path(__file__).resolve().parents[2]
EBPF = REPO / "ebpf"
BUILD = EBPF / "build"
REPLAY = BUILD / "sentinel_replay"
LOADER = BUILD / "sentinel_loader"
BPF_OBJ = BUILD / "sentinel.bpf.o"
SKEL = BUILD / "sentinel.skel.h"
BPFTOOL = "/usr/lib/linux-hwe-6.8-tools-6.8.0-138/bpftool"

NETNS, OTHER_NS, CGID, LEVEL = 4026531840, 4026532999, 777, 2
TGT = EbpfTarget(CGID, LEVEL, NETNS)
MS, US, S = 1_000_000, 1_000, 1_000_000_000

_make = None


def ensure_built():
    """make -C ebpf all (once per test process). Failure is a test failure, never a skip."""
    global _make
    if _make is None:
        _make = subprocess.run(["make", "-C", str(EBPF), "all"], capture_output=True, text=True, timeout=900)
    if _make.returncode != 0:
        raise AssertionError(f"eBPF build failed:\n{_make.stdout[-3000:]}\n{_make.stderr[-3000:]}")
    return _make


class Script:
    def __init__(self, cgid=CGID, level=LEVEL, netns=NETNS, lat_stale=10 * S, sirq_stale=1 * S):
        self.lines = [f"cfg {cgid} {level} {netns} {lat_stale} {sirq_stale}"]

    def __getattr__(self, cmd):
        def add(*args):
            self.lines.append(" ".join([cmd] + [str(a) for a in args]))
            return self
        return add

    def at(self, ns):
        return getattr(self, "t")(ns)

    def entry(self, vec):
        return getattr(self, "sirq_entry")(VECTORS.index(vec))

    def exit(self, vec):
        return getattr(self, "sirq_exit")(VECTORS.index(vec))

    def text(self):
        return "\n".join(self.lines) + "\n"


def replay(script: Script, ncpu=2, capacity=None, check=True):
    with tempfile.NamedTemporaryFile("w", suffix=".sn", delete=False) as fh:
        fh.write(script.text())
        path = fh.name
    argv = [str(REPLAY), "--ncpu", str(ncpu)] + (["--wake-capacity", str(capacity)] if capacity else []) + [path]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    Path(path).unlink()
    if check and p.returncode != 0:
        raise AssertionError(f"replay failed ({p.returncode}): {p.stderr}")
    return p


def lines(script: Script, **kw):
    return [l for l in replay(script, **kw).stdout.splitlines() if l.strip()]


def last(script: Script, **kw):
    """The last sample of a script, decoded."""
    out = [json.loads(l) for l in lines(script, **kw)]
    return [d for d in out if d["type"] == "sample"][-1]


def meta(script: Script, **kw):
    return json.loads(lines(script, **kw)[0])
