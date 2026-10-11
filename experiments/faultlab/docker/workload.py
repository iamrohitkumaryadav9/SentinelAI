#!/usr/bin/env python3
"""SentinelAI Phase 1C FaultLab workload (M4): target HTTP service and dependency peer. Standard library only.

serve       HTTP/1.1 service (one request per connection) with a bounded worker pool (P) and a bounded admission queue
            (Q). Each request: optional instrumented lock held for lock_hold_us (wall time), cpu_us of CPU work measured
            on the thread CPU clock, optional call to the dependency peer with a timeout. Every publish interval it
            atomically replaces APP_ROOT/<run_id>/metrics.json (schema sentinelai-app-metrics/1, the contract of
            src/sentinelai/collectors/app.py). Run-time reconfiguration only through APP_ROOT/<run_id>/control.json;
            every applied configuration is echoed atomically to config.json (ground truth).
dependency  TCP peer: answers each line after dependency_delay_ms (from the same control file); echo in
            dependency_config.json.
distractor  (serve --distractor-kind) free-text log lines for OV-6 ("slow request") and OV-10 (generic) appended to
            <run dir>/distractor.log at distractor_lines_per_s (control file; 0 until switched on). They are never
            metrics and never closed-set events: no counter changes and the collector does not read the file
            (contract §4.7, §8.7 "free-text logs ... never sufficient").

Ownership: the workload must run as the lab uid/gid (LAB_UID/LAB_GID, as scripts/r2c_cpu.py), so the files it writes
are owned by the identity the collector accepts; it refuses to start otherwise. The run directory must already exist,
be a real directory (no symbolic link on the path) and be owned by the lab uid.

Accounting: a request rejected because the queue is full is counted in requests_rejected_total (QUEUE_FULL); an
admitted request is either completed (200) or failed (400 bad request, 504 dependency timeout/error, or a lost
client); latency (admission to response) is recorded for every admitted request. A connection closed without sending
a single byte (for example a readiness probe) is not a request: it is closed and counted nowhere. POOL_EXHAUSTED
counts admissions that found no idle worker. Python threads share one interpreter lock, so CPU work from different
workers does not run in parallel: the service's CPU capacity is about one core.
"""
import argparse
import hashlib
import json
import math
import os
import queue
import random
import re
import signal
import socket
import sys
import threading
import time

SCHEMA = "sentinelai-app-metrics/1"
APP_ROOT = "/run/sentinelai-lab/app/"
METRICS_FILE, CONFIG_FILE, CONTROL_FILE, DEP_CONFIG_FILE = "metrics.json", "config.json", "control.json", \
    "dependency_config.json"
MAX_BYTES = 256 * 1024
CONTROL_MAX_BYTES = 4096
LAB_UID = LAB_GID = 1000
RUN_ID = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*-s[0-9]+")
BUCKETS_MS = tuple(0.05 * 2 ** k for k in range(18)) + (math.inf,)
HISTOGRAMS = ("dependency_latency", "latency", "lock_wait", "queue_wait")
COUNTERS = ("requests_completed_total", "requests_failed_total", "requests_rejected_total")
EVENT_CODES = ("DEPENDENCY_TIMEOUT", "LOCK_WAIT_EXCEEDED", "POOL_EXHAUSTED", "QUEUE_FULL")
CONTROL_KEYS = {"pool": 1, "cpu_us": 0, "lock_hold_us": 0, "dependency_delay_ms": 0,  # key -> minimum value
                "distractor_lines_per_s": 0}
SERVICE_CONTROL_KEYS = ("pool", "cpu_us", "lock_hold_us", "distractor_lines_per_s")
DISTRACTOR_FILE = "distractor.log"
DISTRACTOR_KINDS = ("generic", "slow_request")
_GENERIC = ("INFO cache refresh completed", "INFO background job finished", "INFO configuration reloaded",
            "DEBUG connection pool statistics collected", "INFO session cleanup ran", "INFO health check passed")
REQUEST_MAX = 8192
REJECT_BACKLOG = 64          # rejected connections awaiting their 503 (beyond this, an immediate 503 and close)
REJECT_WAIT_S = 0.5          # bounded wait for a rejected request's bytes, and for the client's end of stream
_S_IFMT, _S_IFDIR, _S_IFREG = 0o170000, 0o040000, 0o100000


class WorkloadError(RuntimeError):
    pass


# ------------------------------------------------------------------------------------------------ run directory
def open_run_dir(run_id: str, root: str = None) -> int:
    """Directory fd of <root>/<run_id>: every component opened with O_NOFOLLOW; must be owned by this process."""
    root = APP_ROOT if root is None else root
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise WorkloadError(f"invalid run_id {run_id!r}")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in [p for p in root.split("/") if p] + [run_id]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except OSError as exc:
        os.close(fd)
        raise WorkloadError(f"run directory unusable: {exc}") from None
    st = os.fstat(fd)
    if st.st_uid != os.geteuid():
        os.close(fd)
        raise WorkloadError(f"run directory owned by uid {st.st_uid}, not this process ({os.geteuid()})")
    return fd


def check_identity() -> None:
    if (os.geteuid(), os.getegid()) != (LAB_UID, LAB_GID):
        raise WorkloadError(f"must run as the lab uid/gid {LAB_UID}/{LAB_GID}, not {os.geteuid()}/{os.getegid()}")


def publish(dir_fd: int, name: str, data: bytes) -> None:
    """Atomically replace <dir>/<name>: write a private temporary file, fsync, rename over the target, fsync the
    directory. A reader sees either the previous complete document or the new one, never a partial one."""
    if len(data) > MAX_BYTES:
        raise WorkloadError(f"{name}: document of {len(data)} bytes exceeds {MAX_BYTES}")
    tmp = f".{name}.tmp.{os.getpid()}"
    try:
        os.unlink(tmp, dir_fd=dir_fd)                       # leftover from a crashed predecessor with this pid
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dir_fd)
    try:
        os.fchmod(fd, 0o644)                                # independent of the umask
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    os.fsync(dir_fd)


def read_control(dir_fd: int):
    """(changes, error): validated changes from control.json, ({}, None) when absent, ({}, reason) when invalid."""
    try:
        fd = os.open(CONTROL_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except FileNotFoundError:
        return {}, None
    except OSError as exc:
        return {}, f"control file unreadable: {exc.strerror}"
    try:
        st = os.fstat(fd)
        if st.st_mode & _S_IFMT != _S_IFREG:
            return {}, "control file is not a regular file"
        data = os.read(fd, CONTROL_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > CONTROL_MAX_BYTES:
        return {}, "control file too large"
    try:
        doc = json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        return {}, f"control file is not valid JSON: {exc}"
    if not isinstance(doc, dict) or set(doc) - set(CONTROL_KEYS):
        return {}, f"control file keys must be a subset of {sorted(CONTROL_KEYS)}"
    for k, v in doc.items():
        if type(v) is not int or v < CONTROL_KEYS[k]:
            return {}, f"control value {k} must be an integer >= {CONTROL_KEYS[k]}"
    return doc, None


def _reject_constant(name):
    raise ValueError(f"non-finite number {name}")


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ------------------------------------------------------------------------------------------------ metrics
def bucket(ms: float) -> int:
    for i, bound in enumerate(BUCKETS_MS):
        if ms <= bound:
            return i
    return len(BUCKETS_MS) - 1


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.counters = {k: 0 for k in COUNTERS}
        self.events = {k: 0 for k in EVENT_CODES}
        self.hist = {h: [0] * len(BUCKETS_MS) for h in HISTOGRAMS}
        self.seq = 0

    def count(self, counter=None, event=None):
        with self.lock:
            if counter:
                self.counters[counter] += 1
            if event:
                self.events[event] += 1

    def observe(self, hist: str, ms: float):
        with self.lock:
            self.hist[hist][bucket(ms)] += 1

    def document(self, pool_size: int, pool_busy: int, config_sha256: str) -> bytes:
        """The next metrics document; seq strictly increasing, mono_ns taken when the document is built."""
        with self.lock:
            self.seq += 1
            doc = {"schema": SCHEMA, "seq": self.seq, "mono_ns": time.monotonic_ns(), "pid": os.getpid(),
                   "config_sha256": config_sha256, "counters": dict(self.counters), "events_total": dict(self.events),
                   "pool_size": pool_size, "pool_busy": pool_busy,
                   "histograms": {h: list(c) for h, c in self.hist.items()}}
        return json.dumps(doc, sort_keys=True).encode()


# ------------------------------------------------------------------------------------------------ service
def tcp_dependency(host: str, port: int):
    def call(timeout_s: float) -> None:
        with socket.create_connection((host, port), timeout=timeout_s) as s:
            s.settimeout(timeout_s)
            s.sendall(b"req\n")
            if not s.recv(16):
                raise OSError("dependency closed the connection")
    return call


class Service:
    """Admission, worker pool and request handling. Connections are socket-like (recv, sendall, settimeout, close)."""

    def __init__(self, config: dict, dependency=None):
        self.cfg = dict(config)          # pool, queue, cpu_us, lock_hold_us, lock_wait_exceeded_ms, dependency_timeout_ms
        self.metrics = Metrics()
        self.dependency = dependency
        self.q = queue.Queue(maxsize=self.cfg["queue"])
        self.state = threading.Lock()
        self.app_lock = threading.Lock()
        self.live = self.busy = 0
        self.stop = threading.Event()
        self.threads = []
        self.rejects = queue.Queue(maxsize=REJECT_BACKLOG)
        threading.Thread(target=self._rejector, daemon=True).start()
        self.resize(self.cfg["pool"])

    # pool ------------------------------------------------------------------------------------------------------
    def resize(self, pool: int) -> None:
        with self.state:
            self.cfg["pool"] = pool
            start = max(0, pool - self.live)
            self.live += start
        for _ in range(start):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self.threads.append(t)

    def pool_state(self):
        """(pool_size, pool_busy): live workers (draining workers included, so busy <= size) and busy workers."""
        with self.state:
            return self.live, self.busy

    def _worker(self):
        while True:
            with self.state:
                if self.live > self.cfg["pool"] or (self.stop.is_set() and self.q.empty()):
                    self.live -= 1
                    return
            try:
                conn, t_admit = self.q.get(timeout=0.1)
            except queue.Empty:
                continue
            with self.state:
                self.busy += 1
            try:
                self._handle(conn, t_admit)
            finally:
                with self.state:
                    self.busy -= 1

    # admission -------------------------------------------------------------------------------------------------
    def submit(self, conn) -> bool:
        t_admit = time.monotonic_ns()
        with self.state:
            no_idle = self.busy >= self.live
        try:
            self.q.put_nowait((conn, t_admit))
        except queue.Full:
            self.metrics.count("requests_rejected_total", "QUEUE_FULL")
            try:
                self.rejects.put_nowait(conn)               # answered off the acceptor thread (see _reject)
            except queue.Full:
                self._drain(conn)                           # rejector saturated: immediate 503, a reset is possible
                self._reply(conn, 503, "Service Unavailable")
            return False
        if no_idle:
            self.metrics.count(event="POOL_EXHAUSTED")
        return True

    # request ---------------------------------------------------------------------------------------------------
    @staticmethod
    def _reply(conn, code: int, reason: str) -> bool:
        body = reason.encode()
        try:
            conn.sendall(b"HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                         % (code, reason.encode(), len(body), body))
            return True
        except OSError:
            return False
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _rejector(self) -> None:
        while True:
            self._reject(self.rejects.get())

    @staticmethod
    def _reject(conn) -> None:
        """503 for a rejected connection without a reset: wait (bounded) for its request bytes, answer, half-close,
        then wait (bounded) for the client's end of stream before closing. Closing with unread or still-arriving
        request bytes would make the kernel reset the connection and discard the 503 before the client reads it."""
        try:
            conn.settimeout(REJECT_WAIT_S)
            data = b""
            try:
                while b"\r\n\r\n" not in data and len(data) <= REQUEST_MAX:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            body = b"Service Unavailable"
            conn.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                         % (len(body), body))
            conn.shutdown(socket.SHUT_WR)
            end = time.monotonic() + REJECT_WAIT_S
            while time.monotonic() < end:
                if not conn.recv(4096):
                    break
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _drain(conn) -> None:
        """Consume request bytes that have already arrived, without blocking the acceptor (bounded)."""
        try:
            conn.setblocking(False)
            n = 0
            while n <= REQUEST_MAX:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                n += len(chunk)
        except OSError:                                     # BlockingIOError: nothing more has arrived
            pass
        finally:
            try:
                conn.setblocking(True)
            except OSError:
                pass

    @staticmethod
    def _read_request(conn):
        """True: a well-formed request; False: malformed or incomplete; None: closed before sending any byte."""
        conn.settimeout(2.0)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(1024)
                if not chunk:
                    return None if not data else False
                data += chunk
                if len(data) > REQUEST_MAX:
                    return False
        except OSError:
            return False
        return data.split(b"\r\n", 1)[0].startswith((b"GET ", b"POST ")) and b" HTTP/1." in data.split(b"\r\n", 1)[0]

    def _handle(self, conn, t_admit: int) -> None:
        m, cfg = self.metrics, self.cfg
        t_start = time.monotonic_ns()
        ok, code, reason = self._read_request(conn), 200, "OK"
        if ok is None:                                      # not a request: nothing to answer or count
            try:
                conn.close()
            except OSError:
                pass
            return
        m.observe("queue_wait", (t_start - t_admit) / 1e6)
        if not ok:
            code, reason = 400, "Bad Request"
        else:
            if cfg["lock_hold_us"] > 0:
                t0 = time.monotonic_ns()
                with self.app_lock:
                    wait_ms = (time.monotonic_ns() - t0) / 1e6
                    m.observe("lock_wait", wait_ms)
                    if wait_ms > cfg["lock_wait_exceeded_ms"]:
                        m.count(event="LOCK_WAIT_EXCEEDED")
                    time.sleep(cfg["lock_hold_us"] / 1e6)    # enforced occupancy of the critical section
            end = time.thread_time_ns() + cfg["cpu_us"] * 1000
            while time.thread_time_ns() < end:               # CPU work on the thread CPU clock
                pass
            if self.dependency is not None:
                t0 = time.monotonic_ns()
                try:
                    self.dependency(cfg["dependency_timeout_ms"] / 1000)
                    m.observe("dependency_latency", (time.monotonic_ns() - t0) / 1e6)
                except socket.timeout:
                    m.count(event="DEPENDENCY_TIMEOUT")
                    code, reason = 504, "Gateway Timeout"
                except OSError:
                    code, reason = 504, "Gateway Timeout"
        sent = self._reply(conn, code, reason)
        m.observe("latency", (time.monotonic_ns() - t_admit) / 1e6)
        m.count("requests_completed_total" if (code == 200 and sent) else "requests_failed_total")

    def document(self, config_sha256: str) -> bytes:
        size, busy = self.pool_state()
        return self.metrics.document(size, busy, config_sha256)


# ------------------------------------------------------------------------------------------------ distractor
class Distractor:
    """Free-text log lines in <run dir>/distractor.log (O_APPEND, no symlink). Never metrics or closed-set events."""

    def __init__(self, dir_fd: int, kind: str, seed: int):
        if kind not in DISTRACTOR_KINDS:
            raise WorkloadError(f"distractor kind must be one of {DISTRACTOR_KINDS}")
        try:
            self.fd = os.open(DISTRACTOR_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o644, dir_fd=dir_fd)
        except OSError as exc:
            raise WorkloadError(f"distractor log unusable: {exc}") from None
        os.fchmod(self.fd, 0o644)
        self.kind, self.rng, self.n = kind, random.Random(seed), 0

    def line(self) -> bytes:
        self.n += 1
        t = time.monotonic()
        if self.kind == "slow_request":
            return f"{t:.3f} WARN slow request {self.n}: took {self.rng.randint(200, 5000)} ms\n".encode()
        return f"{t:.3f} {self.rng.choice(_GENERIC)}\n".encode()

    def write(self) -> None:
        os.write(self.fd, self.line())                      # one small O_APPEND write per line

    def loop(self, svc: "Service", stop: threading.Event, poll_s: float) -> None:
        while not stop.is_set():
            rate = svc.cfg.get("distractor_lines_per_s", 0)
            if rate > 0:
                self.write()
                stop.wait(1.0 / rate)
            else:
                stop.wait(poll_s)


# ------------------------------------------------------------------------------------------------ runtime loops
class Runner:
    """Control polling, config echo and metrics publication for one run directory."""

    def __init__(self, service: Service, dir_fd: int, publish_s: float, poll_s: float):
        self.svc, self.dir_fd, self.publish_s, self.poll_s = service, dir_fd, publish_s, poll_s
        self.config_seq, self.control_error, self.config_sha256 = 0, None, ""
        self.echo_config()

    def applied(self) -> dict:
        return {k: self.svc.cfg[k] for k in sorted(self.svc.cfg)}

    def echo_config(self) -> None:
        self.config_sha256 = hashlib.sha256(canonical(self.applied())).hexdigest()
        self.config_seq += 1
        publish(self.dir_fd, CONFIG_FILE, canonical({"seq": self.config_seq, "mono_ns": time.monotonic_ns(),
                                                     "config": self.applied(), "config_sha256": self.config_sha256,
                                                     "control_error": self.control_error}))

    def poll_control(self) -> None:
        changes, err = read_control(self.dir_fd)
        changes = {k: v for k, v in changes.items() if k in SERVICE_CONTROL_KEYS}
        if "distractor_lines_per_s" in changes and "distractor_kind" not in self.svc.cfg:
            changes, err = {}, "distractor_lines_per_s set but the service runs without --distractor-kind"
        new = {k: v for k, v in changes.items() if self.svc.cfg.get(k) != v}
        if err != self.control_error or new:
            self.control_error = err
            if "pool" in new:
                self.svc.resize(new.pop("pool"))
            self.svc.cfg.update(new)
            self.echo_config()

    def publish_metrics(self) -> None:
        publish(self.dir_fd, METRICS_FILE, self.svc.document(self.config_sha256))

    def loop(self, stop: threading.Event) -> None:
        next_pub = next_poll = time.monotonic()
        while not stop.is_set():
            now = time.monotonic()
            if now >= next_poll:
                self.poll_control()
                next_poll += self.poll_s
            if now >= next_pub:
                self.publish_metrics()
                next_pub += self.publish_s
            stop.wait(max(0.0, min(next_pub, next_poll) - time.monotonic()))
        self.publish_metrics()


def accept_loop(listener, service: Service, stop: threading.Event) -> None:
    listener.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            if stop.is_set():
                return
            raise
        service.submit(conn)


def dependency_loop(listener, dir_fd: int, stop: threading.Event, poll_s: float) -> None:
    state = {"dependency_delay_ms": 0}
    seq = [0]

    def echo(err):
        seq[0] += 1
        publish(dir_fd, DEP_CONFIG_FILE, canonical({"seq": seq[0], "mono_ns": time.monotonic_ns(), "config": state,
                                                    "control_error": err}))

    def poll():
        last = (None, None)
        while not stop.is_set():
            changes, err = read_control(dir_fd)
            if "dependency_delay_ms" in changes:
                state["dependency_delay_ms"] = changes["dependency_delay_ms"]
            if (state["dependency_delay_ms"], err) != last:
                last = (state["dependency_delay_ms"], err)
                echo(err)
            stop.wait(poll_s)

    def answer(conn):
        with conn:
            conn.settimeout(10.0)
            try:
                if conn.recv(64):
                    time.sleep(state["dependency_delay_ms"] / 1000)
                    conn.sendall(b"ok\n")
            except OSError:
                pass

    threading.Thread(target=poll, daemon=True).start()
    listener.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        threading.Thread(target=answer, args=(conn,), daemon=True).start()


# ------------------------------------------------------------------------------------------------ CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--run-id", required=True)
    s.add_argument("--listen", required=True, help="host:port")
    s.add_argument("--pool", type=int, required=True)
    s.add_argument("--queue", type=int, required=True)
    s.add_argument("--cpu-us", type=int, required=True)
    s.add_argument("--lock-hold-us", type=int, default=0)
    s.add_argument("--lock-wait-exceeded-ms", type=float, required=True)
    s.add_argument("--dependency", default=None, help="host:port of the dependency peer")
    s.add_argument("--dependency-timeout-ms", type=float, required=True)
    s.add_argument("--publish-s", type=float, default=1.0)
    s.add_argument("--poll-s", type=float, required=True)
    s.add_argument("--distractor-kind", choices=DISTRACTOR_KINDS, default=None, help="OV-6 slow_request, OV-10 generic")
    s.add_argument("--distractor-seed", type=int, default=None)
    d = sub.add_parser("dependency")
    d.add_argument("--run-id", required=True)
    d.add_argument("--listen", required=True, help="host:port")
    d.add_argument("--poll-s", type=float, required=True)
    a = ap.parse_args(argv)
    try:
        check_identity()
        dir_fd = open_run_dir(a.run_id)
        host, port = a.listen.rsplit(":", 1)
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())
        listener = socket.create_server((host, int(port)), backlog=128)
        if a.cmd == "dependency":
            dependency_loop(listener, dir_fd, stop, a.poll_s)
            return 0
        if min(a.pool, a.queue) < 1 or a.cpu_us < 0 or a.lock_hold_us < 0:
            raise WorkloadError("pool and queue must be >= 1; cpu_us and lock_hold_us >= 0")
        dep = None
        if a.dependency:
            dh, dp = a.dependency.rsplit(":", 1)
            dep = tcp_dependency(dh, int(dp))
        cfg = {"pool": a.pool, "queue": a.queue, "cpu_us": a.cpu_us, "lock_hold_us": a.lock_hold_us,
               "lock_wait_exceeded_ms": a.lock_wait_exceeded_ms, "dependency_timeout_ms": a.dependency_timeout_ms}
        distractor = None
        if a.distractor_kind is not None:
            if a.distractor_seed is None:
                raise WorkloadError("--distractor-kind needs --distractor-seed")
            distractor = Distractor(dir_fd, a.distractor_kind, a.distractor_seed)
            cfg.update(distractor_kind=a.distractor_kind, distractor_lines_per_s=0)
        svc = Service(cfg, dependency=dep)
        runner = Runner(svc, dir_fd, a.publish_s, a.poll_s)
        if distractor is not None:
            threading.Thread(target=distractor.loop, args=(svc, stop, a.poll_s), daemon=True).start()
        threading.Thread(target=accept_loop, args=(listener, svc, stop), daemon=True).start()
        runner.loop(stop)
        return 0
    except WorkloadError as exc:
        print(f"workload: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
