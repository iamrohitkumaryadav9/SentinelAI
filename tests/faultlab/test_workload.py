"""FaultLab M4 workload (experiments/faultlab/docker/workload.py) against the committed app.* parser and reader.

No network: connections are AF_UNIX socket pairs, the accept loop runs on an AF_UNIX listener in a temporary
directory, and every file lives in a temporary run directory.
"""
import hashlib
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from sentinelai.collectors import app as A  # noqa: E402
from sentinelai.collectors.errors import Bad, Status  # noqa: E402

_spec = importlib.util.spec_from_file_location("faultlab_workload", ROOT / "experiments/faultlab/docker/workload.py")
W = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(W)

RUN = "PL-QDISC-I2-s1013"
CFG = {"pool": 2, "queue": 2, "cpu_us": 0, "lock_hold_us": 0, "lock_wait_exceeded_ms": 5.0,
       "dependency_timeout_ms": 200.0}
AS_LAB = os.geteuid() == A.LAB_UID and os.getegid() == W.LAB_GID


def request(svc, payload=b"GET /work HTTP/1.1\r\nHost: a\r\n\r\n"):
    """Submit one request on a socket pair; return the client end (the response arrives there)."""
    client, server = socket.socketpair()
    client.sendall(payload)
    svc.submit(server)
    return client


def response(client, timeout=5.0):
    client.settimeout(timeout)
    data = b""
    while True:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    client.close()
    return data.split(b"\r\n", 1)[0]


def wait_until(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.01)
    return False


class RunDir(unittest.TestCase):
    """A temporary APP_ROOT with one run directory owned by this process; the reader looks there too."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.join(self._t.name, "run", "sentinelai-lab", "app") + "/"
        os.makedirs(self.root + RUN)
        self.dir_fd = W.open_run_dir(RUN, self.root)
        self._patches = [mock.patch.object(A, "APP_ROOT", self.root)]
        if not AS_LAB:                                      # the reader's owner check follows the test identity
            self._patches.append(mock.patch.object(A, "LAB_UID", os.geteuid()))
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        os.close(self.dir_fd)
        self._t.cleanup()

    def path(self, name):
        return os.path.join(self.root, RUN, name)


class TestContract(unittest.TestCase):
    def test_constants_match_the_committed_parser_and_reader(self):
        self.assertEqual((W.SCHEMA, W.APP_ROOT, W.METRICS_FILE, W.MAX_BYTES, W.LAB_UID),
                         (A.SCHEMA, A.APP_ROOT, A.METRICS_FILE, A.MAX_BYTES, A.LAB_UID))
        self.assertEqual((W.BUCKETS_MS, W.HISTOGRAMS, W.COUNTERS, W.EVENT_CODES),
                         (A.BUCKETS_MS, A.HISTOGRAMS, A.COUNTERS, A.EVENT_CODES))
        self.assertEqual(W.RUN_ID.pattern, A.RUN_ID.pattern)

    def test_bucket_assignment(self):
        self.assertEqual(W.bucket(0.0), 0)
        self.assertEqual(W.bucket(0.05), 0)
        self.assertEqual(W.bucket(0.0500001), 1)
        self.assertEqual(W.bucket(6553.6), 17)
        self.assertEqual(W.bucket(1e9), 18)

    def test_identity_check(self):
        with mock.patch.object(W, "LAB_UID", os.geteuid() + 1):
            with self.assertRaises(W.WorkloadError):
                W.check_identity()
        with mock.patch.object(W, "LAB_UID", os.geteuid()), mock.patch.object(W, "LAB_GID", os.getegid()):
            W.check_identity()

    def test_main_refuses_wrong_identity_before_touching_anything(self):
        with mock.patch.object(W, "LAB_UID", os.geteuid() + 1), mock.patch.object(W, "open_run_dir") as opener:
            self.assertEqual(W.main(["serve", "--run-id", RUN, "--listen", "127.0.0.1:1", "--pool", "1", "--queue",
                                     "1", "--cpu-us", "0", "--lock-wait-exceeded-ms", "1", "--dependency-timeout-ms",
                                     "1", "--poll-s", "1"]), 2)
            opener.assert_not_called()


class TestRunDirectory(RunDir):
    def test_invalid_run_id(self):
        for rid in ("", "../x", "ctrl-s1", "CTRL", "CTRL-s1/.."):
            with self.subTest(rid=rid), self.assertRaises(W.WorkloadError):
                W.open_run_dir(rid, self.root)

    def test_symlinked_run_directory_refused(self):
        real = os.path.join(self._t.name, "elsewhere")
        os.makedirs(real)
        os.symlink(real, self.root + "CTRL-s3")
        with self.assertRaises(W.WorkloadError):
            W.open_run_dir("CTRL-s3", self.root)

    def test_absent_run_directory_refused(self):
        with self.assertRaises(W.WorkloadError):
            W.open_run_dir("CTRL-s9", self.root)

    def test_foreign_owner_refused(self):
        with mock.patch.object(W.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(W.WorkloadError):
                W.open_run_dir(RUN, self.root)


class TestPublication(RunDir):
    def runner(self, cfg=CFG, dependency=None):
        return W.Runner(W.Service(cfg, dependency=dependency), self.dir_fd, publish_s=1.0, poll_s=1.0)

    def test_end_to_end_valid_document(self):
        r = self.runner()
        r.publish_metrics()
        data = A.read_metrics(RUN)
        self.assertIsInstance(data, bytes, data)
        s = A.observe(data, None, time.monotonic_ns())
        self.assertIsInstance(s, A.AppSample, s)
        self.assertEqual((s.pool_size, s.pool_busy, s.pid, s.config_sha256), (2, 0, os.getpid(), r.config_sha256))

    def test_published_file_owner_mode_size(self):
        self.runner().publish_metrics()
        st = os.stat(self.path("metrics.json"))
        self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o777), (os.geteuid(), os.getegid(), 0o644))
        self.assertLessEqual(st.st_size, A.MAX_BYTES)
        self.assertEqual(sorted(os.listdir(self.root + RUN)), ["config.json", "metrics.json"])   # no temp left

    @unittest.skipUnless(AS_LAB, "the unpatched reader owner check needs the lab uid")
    def test_reader_accepts_as_the_real_lab_uid(self):
        self.runner().publish_metrics()
        self.assertEqual(A.LAB_UID, os.geteuid())
        self.assertIsInstance(A.observe(A.read_metrics(RUN), None, time.monotonic_ns()), A.AppSample)

    def test_sequence_of_documents_is_valid_under_load(self):
        svc = W.Service(dict(CFG, pool=2, queue=8, cpu_us=200))
        r = W.Runner(svc, self.dir_fd, 1.0, 1.0)
        prev, samples = None, []
        for i in range(5):
            clients = [request(svc) for _ in range(3)]
            for c in clients:
                self.assertEqual(response(c), b"HTTP/1.1 200 OK")
            r.publish_metrics()
            s = A.observe(A.read_metrics(RUN), prev, time.monotonic_ns())
            self.assertIsInstance(s, A.AppSample, s)
            prev = s
            samples.append(s)
        self.assertEqual(samples[-1].counters["requests_completed_total"], 15)
        v = A.window_values(samples)
        self.assertGreater(v[("app.throughput", "RATE")][0], 0)
        self.assertIsNotNone(v[("app.latency_ms", "P99")][0])
        self.assertIsNotNone(v[("app.queue_wait_ms", "P99")][0])

    def test_atomic_replace_never_exposes_a_partial_document(self):
        r = self.runner()
        r.publish_metrics()
        first = Path(self.path("metrics.json")).read_bytes()
        seen = []
        real_replace = os.replace

        def inspect_then_replace(src, dst, **kw):
            seen.append(A.read_metrics(RUN))                # temp file fully written, target not yet replaced
            seen.append(sorted(os.listdir(self.root + RUN)))
            return real_replace(src, dst, **kw)
        with mock.patch.object(W.os, "replace", side_effect=inspect_then_replace):
            r.publish_metrics()
        self.assertEqual(seen[0], first)
        self.assertIn(f".metrics.json.tmp.{os.getpid()}", seen[1])
        self.assertIsInstance(A.parse(Path(self.path("metrics.json")).read_bytes()), A.AppSample)

    def test_concurrent_reader_never_sees_a_partial_document(self):
        svc = W.Service(dict(CFG, queue=64))
        r = W.Runner(svc, self.dir_fd, 1.0, 1.0)
        r.publish_metrics()
        stop, bad, reads = threading.Event(), [], [0]

        def reader():
            while not stop.is_set():
                data = A.read_metrics(RUN)
                reads[0] += 1
                if not isinstance(data, bytes) or isinstance(A.parse(data), Bad):
                    bad.append(data if isinstance(data, Bad) else A.parse(data))
        t = threading.Thread(target=reader)
        t.start()
        for _ in range(300):
            r.publish_metrics()
        stop.set()
        t.join()
        self.assertGreater(reads[0], 0)
        self.assertEqual(bad, [])

    def test_partial_document_is_rejected_by_the_reader(self):
        """Control for the two atomicity tests: a non-atomic, half-written file is caught as MALFORMED."""
        data = self.runner().svc.document("ab" * 32)
        Path(self.path("metrics.json")).write_bytes(data[: len(data) // 2])
        self.assertIs(A.observe(A.read_metrics(RUN), None, time.monotonic_ns()).status, Status.MALFORMED)

    def test_oversized_document_is_never_published(self):
        r = self.runner()
        r.publish_metrics()
        before = Path(self.path("metrics.json")).read_bytes()
        with self.assertRaises(W.WorkloadError):
            W.publish(self.dir_fd, "metrics.json", b" " * (W.MAX_BYTES + 1))
        self.assertEqual(Path(self.path("metrics.json")).read_bytes(), before)

    def test_leftover_temporary_file_is_replaced(self):
        tmp = self.path(f".metrics.json.tmp.{os.getpid()}")
        Path(tmp).write_bytes(b"stale")
        self.runner().publish_metrics()
        self.assertFalse(os.path.exists(tmp))


class TestService(unittest.TestCase):
    def test_request_completed(self):
        svc = W.Service(CFG)
        self.assertEqual(response(request(svc)), b"HTTP/1.1 200 OK")
        self.assertTrue(wait_until(lambda: svc.metrics.counters["requests_completed_total"] == 1))
        self.assertEqual(sum(svc.metrics.hist["latency"]), 1)
        self.assertEqual(sum(svc.metrics.hist["queue_wait"]), 1)

    def test_bad_request_failed(self):
        svc = W.Service(CFG)
        self.assertEqual(response(request(svc, b"garbage\r\n\r\n")), b"HTTP/1.1 400 Bad Request")
        self.assertTrue(wait_until(lambda: svc.metrics.counters["requests_failed_total"] == 1))

    def test_empty_connection_is_not_a_request(self):
        svc = W.Service(CFG)
        client, server = socket.socketpair()
        client.close()                                      # readiness probe: connect, send nothing, close
        svc.submit(server)
        self.assertEqual(response(request(svc)), b"HTTP/1.1 200 OK")   # a real request after it
        self.assertTrue(wait_until(lambda: svc.metrics.counters["requests_completed_total"] == 1))
        m = svc.metrics
        self.assertEqual(m.counters["requests_failed_total"], 0)
        self.assertEqual((sum(m.hist["latency"]), sum(m.hist["queue_wait"])), (1, 1))

    def test_partial_request_still_failed(self):
        svc = W.Service(CFG)
        client, server = socket.socketpair()
        client.sendall(b"GET /work HT")                     # half a request line, then end of stream
        client.shutdown(socket.SHUT_WR)
        svc.submit(server)
        self.assertEqual(response(client), b"HTTP/1.1 400 Bad Request")
        self.assertTrue(wait_until(lambda: svc.metrics.counters["requests_failed_total"] == 1))

    def test_queue_full_rejected_and_pool_exhausted(self):
        gate = threading.Event()
        svc = W.Service(dict(CFG, pool=1, queue=1), dependency=lambda timeout: gate.wait(5))
        c1 = request(svc)                                   # occupies the only worker (blocked in the dependency)
        self.assertTrue(wait_until(lambda: svc.pool_state()[1] == 1))
        c2 = request(svc)                                   # queued: no idle worker
        c3 = request(svc)                                   # queue full: rejected
        self.assertEqual(response(c3), b"HTTP/1.1 503 Service Unavailable")
        gate.set()
        self.assertEqual((response(c1), response(c2)), (b"HTTP/1.1 200 OK", b"HTTP/1.1 200 OK"))
        m = svc.metrics
        self.assertTrue(wait_until(lambda: m.counters["requests_completed_total"] == 2))
        self.assertEqual((m.counters["requests_rejected_total"], m.events["QUEUE_FULL"]), (1, 1))
        self.assertGreaterEqual(m.events["POOL_EXHAUSTED"], 1)

    def test_cpu_work_uses_the_thread_cpu_clock(self):
        svc = W.Service(dict(CFG, cpu_us=20000))
        t0 = time.monotonic()
        self.assertEqual(response(request(svc)), b"HTTP/1.1 200 OK")
        self.assertGreaterEqual(time.monotonic() - t0, 0.02)

    def test_lock_wait_recorded_and_exceeded(self):
        svc = W.Service(dict(CFG, pool=2, lock_hold_us=30000, lock_wait_exceeded_ms=5.0))
        a, b = request(svc), request(svc)
        self.assertEqual((response(a), response(b)), (b"HTTP/1.1 200 OK", b"HTTP/1.1 200 OK"))
        self.assertTrue(wait_until(lambda: sum(svc.metrics.hist["lock_wait"]) == 2))
        self.assertGreaterEqual(svc.metrics.events["LOCK_WAIT_EXCEEDED"], 1)

    def test_dependency_success_and_timeout(self):
        svc = W.Service(CFG, dependency=lambda timeout: None)
        self.assertEqual(response(request(svc)), b"HTTP/1.1 200 OK")
        self.assertTrue(wait_until(lambda: sum(svc.metrics.hist["dependency_latency"]) == 1))

        def slow(timeout):
            raise socket.timeout("timed out")
        svc = W.Service(CFG, dependency=slow)
        self.assertEqual(response(request(svc)), b"HTTP/1.1 504 Gateway Timeout")
        m = svc.metrics
        self.assertTrue(wait_until(lambda: m.counters["requests_failed_total"] == 1))
        self.assertEqual((m.events["DEPENDENCY_TIMEOUT"], sum(m.hist["dependency_latency"])), (1, 0))

    def test_tcp_dependency_client_over_a_socket_pair(self):
        a, b = socket.socketpair()

        def peer():
            with b:
                if b.recv(16):
                    b.sendall(b"ok\n")
        threading.Thread(target=peer).start()
        with mock.patch.object(W.socket, "create_connection", return_value=a):
            W.tcp_dependency("10.199.2.2", 9000)(1.0)

    def test_pool_shrink_keeps_busy_within_size(self):
        gate = threading.Event()
        svc = W.Service(dict(CFG, pool=3, queue=8), dependency=lambda timeout: gate.wait(5))
        clients = [request(svc) for _ in range(3)]
        self.assertTrue(wait_until(lambda: svc.pool_state()[1] == 3))
        svc.resize(1)
        size, busy = svc.pool_state()
        self.assertLessEqual(busy, size)                  # draining workers still counted as live
        self.assertIsInstance(A.parse(svc.document("ab" * 32)), A.AppSample)
        gate.set()
        for c in clients:
            response(c)
        self.assertTrue(wait_until(lambda: svc.pool_state() == (1, 0)))

    def test_accept_loop_on_a_unix_listener(self):
        with tempfile.TemporaryDirectory() as t:
            path = os.path.join(t, "s")
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(path)
            listener.listen()
            svc, stop = W.Service(CFG), threading.Event()
            th = threading.Thread(target=W.accept_loop, args=(listener, svc, stop))
            th.start()
            try:
                c = socket.socket(socket.AF_UNIX)
                c.connect(path)
                c.sendall(b"GET / HTTP/1.1\r\n\r\n")
                self.assertEqual(response(c), b"HTTP/1.1 200 OK")
            finally:
                stop.set()
                th.join()
                listener.close()


class TestControl(RunDir):
    def write_control(self, obj):
        Path(self.path("control.json")).write_bytes(obj if isinstance(obj, bytes) else json.dumps(obj).encode())

    def echo(self):
        return json.loads(Path(self.path("config.json")).read_bytes())

    def test_initial_echo_matches_metrics_hash(self):
        r = W.Runner(W.Service(CFG), self.dir_fd, 1.0, 1.0)
        e = self.echo()
        self.assertEqual(e["config"], dict(sorted(CFG.items())))
        self.assertEqual(e["config_sha256"], hashlib.sha256(W.canonical(e["config"])).hexdigest())
        r.publish_metrics()
        self.assertEqual(A.parse(A.read_metrics(RUN)).config_sha256, e["config_sha256"])

    def test_valid_control_applied_and_echoed(self):
        r = W.Runner(W.Service(dict(CFG, pool=3)), self.dir_fd, 1.0, 1.0)
        before = self.echo()
        self.write_control({"pool": 1, "lock_hold_us": 2000, "dependency_delay_ms": 50})
        r.poll_control()
        after = self.echo()
        self.assertEqual((after["config"]["pool"], after["config"]["lock_hold_us"]), (1, 2000))
        self.assertNotIn("dependency_delay_ms", after["config"])            # the peer's key, not the service's
        self.assertEqual(after["seq"], before["seq"] + 1)
        self.assertNotEqual(after["config_sha256"], before["config_sha256"])
        self.assertIsNone(after["control_error"])

    def test_invalid_control_not_applied(self):
        cases = {"not json": b"{pool", "unknown key": {"threads": 4}, "negative": {"cpu_us": -1},
                 "zero pool": {"pool": 0}, "bool": {"pool": True}, "float": {"pool": 2.0},
                 "too large": b" " * (W.CONTROL_MAX_BYTES + 1), "NaN": b'{"cpu_us": NaN}'}
        for name, obj in cases.items():
            with self.subTest(name):
                r = W.Runner(W.Service(CFG), self.dir_fd, 1.0, 1.0)
                self.write_control(obj)
                r.poll_control()
                e = self.echo()
                self.assertEqual(e["config"], dict(sorted(CFG.items())))
                self.assertIsNotNone(e["control_error"])

    def test_symlinked_control_refused(self):
        target = os.path.join(self._t.name, "evil.json")
        Path(target).write_text(json.dumps({"pool": 9}))
        os.symlink(target, self.path("control.json"))
        r = W.Runner(W.Service(CFG), self.dir_fd, 1.0, 1.0)
        r.poll_control()
        self.assertEqual(self.echo()["config"]["pool"], CFG["pool"])
        self.assertIsNotNone(self.echo()["control_error"])


class TestDependencyPeer(RunDir):
    def test_answers_after_the_controlled_delay_and_echoes_it(self):
        path = os.path.join(self._t.name, "dep.sock")
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(path)
        listener.listen()
        stop = threading.Event()
        th = threading.Thread(target=W.dependency_loop, args=(listener, self.dir_fd, stop, 0.02))
        th.start()

        def call():
            c = socket.socket(socket.AF_UNIX)
            c.settimeout(5)
            c.connect(path)
            t0 = time.monotonic()
            c.sendall(b"req\n")
            data = c.recv(16)
            c.close()
            return data, time.monotonic() - t0
        try:
            self.assertTrue(wait_until(lambda: os.path.exists(self.path("dependency_config.json"))))
            self.assertEqual(call()[0], b"ok\n")
            Path(self.path("control.json")).write_text(json.dumps({"dependency_delay_ms": 150, "pool": 4}))
            self.assertTrue(wait_until(lambda: json.loads(Path(self.path("dependency_config.json")).read_bytes())
                                       ["config"]["dependency_delay_ms"] == 150))
            data, dt = call()
            self.assertEqual(data, b"ok\n")
            self.assertGreaterEqual(dt, 0.15)
        finally:
            stop.set()
            th.join()
            listener.close()


if __name__ == "__main__":
    unittest.main()
