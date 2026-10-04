#!/usr/bin/env python3
"""SentinelAI R2-F target workload: one process, one thread, never forks, no network, no locks, no queues.

1. Creates --file (exactly --file-bytes, deterministic content, O_EXCL) inside its own cgroup and fsyncs it, so the
   page cache it reads is charged to that cgroup.
2. Maps it read-only with MADV_RANDOM (no readahead) and touches one byte per page of the first --scan-b bytes once.
3. Prints "READY <monotonic ns>" on stdout.
4. Runs exactly --cycles cycles: every --period-ns it sleeps to an absolute CLOCK_MONOTONIC deadline, then touches
   --pages-per-cycle consecutive pages (one byte each, wrapping) inside the current scan range.
   The scan range is --scan-b until the first SIGUSR1, then --scan-w; it expands exactly once (later signals are
   counted, never acted on).
5. Writes wake / done times per cycle (deadline k = t0 + k * period), the expansion cycle and the major-fault counts
   to --out and exits.

Placement (cgroup, CPU, private netns, uid) is set entirely by the process that starts it; this program changes none.
"""

import argparse
import ctypes
import errno
import json
import mmap
import os
import resource
import signal
import sys
import time
from array import array

CLOCK_MONOTONIC, TIMER_ABSTIME = 1, 1
PAGE = 4096
CHUNK = 1 << 20


class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


def make_sleep_until():
    libc = ctypes.CDLL(None, use_errno=True)
    fn = libc.clock_nanosleep
    fn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(Timespec), ctypes.POINTER(Timespec)]
    fn.restype = ctypes.c_int

    def sleep_until(deadline_ns: int) -> None:
        ts = Timespec(deadline_ns // 1_000_000_000, deadline_ns % 1_000_000_000)
        while True:
            rc = fn(CLOCK_MONOTONIC, TIMER_ABSTIME, ctypes.byref(ts), None)
            if rc == 0:
                return
            if rc != errno.EINTR:                      # SIGUSR1 interrupts the sleep: resume the same deadline
                raise OSError(rc, os.strerror(rc))
    return sleep_until


def check_args(file_bytes, scan_b, scan_w, pages_per_cycle, cycles, period_ns):
    if file_bytes <= 0 or file_bytes % CHUNK or not 0 < scan_b <= scan_w <= file_bytes or scan_b % PAGE or \
            scan_w % PAGE or pages_per_cycle <= 0 or cycles <= 0 or period_ns <= 0:
        raise SystemExit("invalid workload geometry")


def create_file(path: str, file_bytes: int) -> None:
    """Deterministic content (each 1 MiB chunk stamped with its index), written once, fsynced."""
    base = bytes((i * 131 + 7) & 0xFF for i in range(CHUNK))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        for k in range(file_bytes // CHUNK):
            os.write(fd, k.to_bytes(8, "little") + base[8:])
        os.fsync(fd)
    finally:
        os.close(fd)


def majflt() -> int:
    return resource.getrusage(resource.RUSAGE_SELF).ru_majflt


def run(m, scan_b: int, scan_w: int, pages_per_cycle: int, cycles: int, period_ns: int, state: dict,
        now=time.monotonic_ns, sleep_until=None) -> dict:
    sleep_until = sleep_until or make_sleep_until()
    wake, done = array("q", bytes(8 * cycles)), array("q", bytes(8 * cycles))
    t0 = now() + period_ns
    cursor, checksum, expanded_at, majflt_at_expand = 0, 0, None, None
    for k in range(cycles):
        sleep_until(t0 + k * period_ns)
        wake[k] = now()
        if state["n"] >= 1 and expanded_at is None:
            expanded_at, majflt_at_expand = k, majflt()
        pages = (scan_w if expanded_at is not None else scan_b) // PAGE
        for _ in range(pages_per_cycle):
            cursor %= pages
            checksum = (checksum + m[cursor * PAGE]) & 0xFFFFFFFF
            cursor += 1
        done[k] = now()
    return {"period_ns": period_ns, "cycles": cycles, "t0_ns": t0, "wake_ns": wake.tolist(), "done_ns": done.tolist(),
            "expanded_at_cycle": expanded_at, "majflt_at_expand": majflt_at_expand, "checksum": checksum}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    for name in ("--file", "--out"):
        ap.add_argument(name, required=True)
    for name in ("--file-bytes", "--scan-b", "--scan-w", "--period-ns", "--pages-per-cycle", "--cycles"):
        ap.add_argument(name, type=int, required=True)
    a = ap.parse_args(argv)
    check_args(a.file_bytes, a.scan_b, a.scan_w, a.pages_per_cycle, a.cycles, a.period_ns)
    state = {"n": 0}

    def on_usr1(signum, frame):
        state["n"] += 1
    signal.signal(signal.SIGUSR1, on_usr1)
    t_create = time.monotonic_ns()
    create_file(a.file, a.file_bytes)
    fd = os.open(a.file, os.O_RDONLY)
    m = mmap.mmap(fd, a.file_bytes, mmap.MAP_SHARED, mmap.PROT_READ)
    os.close(fd)
    m.madvise(mmap.MADV_RANDOM)
    warm = 0
    for p in range(a.scan_b // PAGE):
        warm = (warm + m[p * PAGE]) & 0xFFFFFFFF
    majflt_ready, t_ready = majflt(), time.monotonic_ns()
    print(f"READY {t_ready}", flush=True)
    res = run(m, a.scan_b, a.scan_w, a.pages_per_cycle, a.cycles, a.period_ns, state)
    res.update(pid=os.getpid(), file_bytes=a.file_bytes, file_size=os.stat(a.file).st_size, scan_b=a.scan_b,
               scan_w=a.scan_w, pages_per_cycle=a.pages_per_cycle, sigusr1_count=state["n"],
               create_start_ns=t_create, ready_ns=t_ready, majflt_ready=majflt_ready, majflt_end=majflt(),
               warm_checksum=warm)
    with open(a.out, "w") as fh:
        json.dump(res, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
