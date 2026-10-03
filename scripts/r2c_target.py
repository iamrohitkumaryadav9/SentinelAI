#!/usr/bin/env python3
"""SentinelAI R2-C target workload: one process, one thread, never forks (design §5).

Every --period-ns it sleeps to an absolute CLOCK_MONOTONIC deadline (clock_nanosleep, TIMER_ABSTIME), then runs a
fixed number of integer iterations. It runs exactly --cycles cycles, then writes, per cycle, the wake time and the
work-done time (CLOCK_MONOTONIC ns; deadline k = t0 + k * period) to --out and exits.

--calibrate measures the iteration count that takes --work-ns on the CPU it runs on (the runtime calibration step,
run once in the target cgroup on CPU 18 before the matrix) and writes it to --out.

Placement (cgroup, CPU, private netns, uid) is set entirely by the process that starts it; this program changes none.
"""

import argparse
import ctypes
import errno
import json
import os
import time
from array import array
from statistics import median

CLOCK_MONOTONIC, TIMER_ABSTIME = 1, 1
LCG_A, LCG_C, LCG_M = 1103515245, 12345, 0x7FFFFFFF
CAL_PROBE, CAL_REPS = 20_000, 200


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
            if rc != errno.EINTR:
                raise OSError(rc, os.strerror(rc))
    return sleep_until


def work(iters: int, x: int) -> int:
    """Fixed integer work: iters steps of a linear congruential generator."""
    for _ in range(iters):
        x = (x * LCG_A + LCG_C) & LCG_M
    return x


def run(cycles: int, period_ns: int, iters: int, now=time.monotonic_ns, sleep_until=None) -> dict:
    sleep_until = sleep_until or make_sleep_until()
    wake, done = array("q", bytes(8 * cycles)), array("q", bytes(8 * cycles))
    t0 = now() + period_ns
    x = 1
    for k in range(cycles):
        sleep_until(t0 + k * period_ns)
        wake[k] = now()
        x = work(iters, x)
        done[k] = now()
    return {"pid": os.getpid(), "period_ns": period_ns, "cycles": cycles, "iters": iters, "t0_ns": t0,
            "wake_ns": wake.tolist(), "done_ns": done.tolist(), "checksum": x}


def calibrate(work_ns: int, now=time.monotonic_ns) -> dict:
    durations = []
    x = 1
    for _ in range(CAL_REPS):
        a = now()
        x = work(CAL_PROBE, x)
        durations.append(now() - a)
    med = median(durations)
    return {"pid": os.getpid(), "probe_iters": CAL_PROBE, "reps": CAL_REPS, "median_ns": med,
            "durations_ns": durations, "work_ns": work_ns, "iters": max(1, round(CAL_PROBE * work_ns / med)),
            "checksum": x}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--calibrate", action="store_true")
    ap.add_argument("--work-ns", type=int)
    ap.add_argument("--period-ns", type=int)
    ap.add_argument("--cycles", type=int)
    ap.add_argument("--iters", type=int)
    a = ap.parse_args(argv)
    if a.calibrate:
        res = calibrate(a.work_ns)
    else:
        res = run(a.cycles, a.period_ns, a.iters)
    with open(a.out, "w") as fh:
        json.dump(res, fh)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
