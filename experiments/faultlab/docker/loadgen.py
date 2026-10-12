#!/usr/bin/env python3
"""SentinelAI Phase 1C FaultLab load generator (M4): fixed-rate open-loop HTTP client. Standard library only.

Two arrival processes, both reproducible from random.Random(seed):
- bounded (--arrivals bounded --jitter j): arrival k at start + (k + u_k) / rate, u_k uniform in [-j/2, +j/2]; the
  jitter is bounded, so consecutive arrivals are never closer than (1 - j) / rate (FZ-WORKLOAD, campaigns up to
  20261012T074028Z);
- poisson (--arrivals poisson): independent exponential gaps with mean 1 / rate (FZ-ARRIVALS, approved 2026-10-12),
  so requests can overlap and queue the way real traffic does. Open loop: a request is sent at its scheduled time whatever happened to earlier ones; at most max_inflight
requests are outstanding, and a scheduled arrival that finds the client saturated is recorded as "client_saturated"
(not sent), so every scheduled arrival is accounted for. One request per connection (Connection: close).

Client-side latency is recorded for ground-truth sanity checks only; it is never a diagnostic feature (design §6.1).
Records are written once, at the end, atomically (temporary file, fsync, rename) as JSON lines:
  {"k", "scheduled_ns", "sent_ns", "outcome", "latency_ms"}   (times on CLOCK_MONOTONIC; outcome is the HTTP status
code as a string, an exception class name, or "client_saturated"; latency_ms is null when nothing was received).
"""
import argparse
import json
import os
import random
import socket
import sys
import threading
import time

RESPONSE_MAX = 65536


def poisson_schedule(rate: float, duration_s: float, seed: int):
    """Offsets (ns from start) of a Poisson arrival process of the given rate over [0, duration_s), in order."""
    if rate <= 0 or duration_s <= 0:
        raise ValueError("rate and duration must be > 0")
    rng, out, t = random.Random(seed), [], 0.0
    while True:
        t += rng.expovariate(rate)
        if t >= duration_s:
            return out
        out.append(int(t * 1e9))


def arrivals(process: str, rate: float, duration_s: float, jitter, seed: int):
    """The schedule of either arrival process (the single entry point the drivers use)."""
    if process == "poisson":
        if jitter is not None:
            raise ValueError("poisson arrivals take no jitter")
        return poisson_schedule(rate, duration_s, seed)
    if process == "bounded":
        if jitter is None:
            raise ValueError("bounded arrivals need a jitter")
        return schedule(rate, duration_s, jitter, seed)
    raise ValueError(f"unknown arrival process {process!r}")


def schedule(rate: float, duration_s: float, jitter: float, seed: int):
    """Offsets (ns from start) of every arrival in [0, duration_s), in order."""
    if rate <= 0 or duration_s <= 0 or not 0 <= jitter < 1:
        raise ValueError("rate and duration must be > 0 and jitter in [0, 1)")
    rng, out, k = random.Random(seed), [], 0
    while k / rate < duration_s:
        t = (k + rng.uniform(-jitter / 2, jitter / 2)) / rate
        out.append(max(0, int(t * 1e9)))
        k += 1
    return out


def tcp_connector(host: str, port: int, timeout_s: float):
    return lambda: socket.create_connection((host, port), timeout=timeout_s)


def request_once(connect, path: str, timeout_s: float):
    """(outcome, latency_ms): the HTTP status code as a string, or the exception class name."""
    t0 = time.monotonic_ns()
    try:
        with connect() as c:
            c.settimeout(timeout_s)
            c.sendall(b"GET %s HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n" % path.encode())
            data = b""
            while len(data) <= RESPONSE_MAX:
                chunk = c.recv(4096)
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        return type(exc).__name__, None
    line = data.split(b"\r\n", 1)[0].split()
    if len(line) < 2 or not line[0].startswith(b"HTTP/1.") or not line[1].isdigit():
        return "malformed_response", (time.monotonic_ns() - t0) / 1e6
    return line[1].decode(), (time.monotonic_ns() - t0) / 1e6


def run(connect, offsets, path: str, timeout_s: float, max_inflight: int, sleep=time.sleep):
    """Send every scheduled arrival open-loop; return one record per arrival, ordered by k."""
    records, lock = [None] * len(offsets), threading.Lock()
    slots = threading.BoundedSemaphore(max_inflight)
    threads = []
    start = time.monotonic_ns()

    def one(k, scheduled, sent):
        try:
            outcome, latency = request_once(connect, path, timeout_s)
        finally:
            slots.release()
        with lock:
            records[k] = {"k": k, "scheduled_ns": scheduled, "sent_ns": sent, "outcome": outcome,
                          "latency_ms": latency}

    for k, off in enumerate(offsets):
        scheduled = start + off
        delay = (scheduled - time.monotonic_ns()) / 1e9
        if delay > 0:
            sleep(delay)
        if not slots.acquire(blocking=False):
            records[k] = {"k": k, "scheduled_ns": scheduled, "sent_ns": None, "outcome": "client_saturated",
                          "latency_ms": None}
            continue
        t = threading.Thread(target=one, args=(k, scheduled, time.monotonic_ns()), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    missing = [k for k, r in enumerate(records) if r is None]
    if missing:
        raise RuntimeError(f"arrivals without a record: {missing[:10]}")
    return records


def write_records(path: str, records) -> None:
    data = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records).encode()
    d, name = os.path.split(os.path.abspath(path))
    tmp = os.path.join(d, f".{name}.tmp.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--target", required=True, help="host:port")
    ap.add_argument("--path", default="/work")
    ap.add_argument("--rate", type=float, required=True, help="requests per second")
    ap.add_argument("--duration-s", type=float, required=True)
    ap.add_argument("--arrivals", choices=("bounded", "poisson"), default="bounded")
    ap.add_argument("--jitter", type=float, default=None, help="bounded arrivals: uniform jitter, fraction of 1/rate")
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--timeout-s", type=float, required=True)
    ap.add_argument("--max-inflight", type=int, required=True)
    ap.add_argument("--out", required=True, help="JSON-lines records (sanity checks only)")
    a = ap.parse_args(argv)
    if a.max_inflight < 1 or a.timeout_s <= 0:
        print("loadgen: max-inflight must be >= 1 and timeout-s > 0", file=sys.stderr)
        return 2
    try:
        offsets = arrivals(a.arrivals, a.rate, a.duration_s, a.jitter, a.seed)
    except ValueError as exc:
        print(f"loadgen: {exc}", file=sys.stderr)
        return 2
    host, port = a.target.rsplit(":", 1)
    records = run(tcp_connector(host, int(port), a.timeout_s), offsets, a.path, a.timeout_s, a.max_inflight)
    write_records(a.out, records)
    return 0


if __name__ == "__main__":
    sys.exit(main())
