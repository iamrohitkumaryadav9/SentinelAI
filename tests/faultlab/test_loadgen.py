"""FaultLab M4 load generator (experiments/faultlab/docker/loadgen.py), alone and against the committed workload.

No network: connections are AF_UNIX socket pairs whose server end is handed to the workload's Service.
"""
import importlib.util
import json
import os
import socket
import statistics
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


L = _load("faultlab_loadgen", "experiments/faultlab/docker/loadgen.py")
W = _load("faultlab_workload_for_loadgen", "experiments/faultlab/docker/workload.py")
CFG = {"pool": 2, "queue": 4, "cpu_us": 0, "lock_hold_us": 0, "lock_wait_exceeded_ms": 5.0,
       "dependency_timeout_ms": 1000.0}


def into(svc):
    """Connector whose connections are served by the workload Service (socket pair, no network)."""
    def connect():
        client, server = socket.socketpair()
        svc.submit(server)
        return client
    return connect


def outcomes(records):
    out = {}
    for r in records:
        out[r["outcome"]] = out.get(r["outcome"], 0) + 1
    return out


class TestSchedule(unittest.TestCase):
    def test_deterministic_per_seed(self):
        self.assertEqual(L.schedule(200, 1.0, 0.5, 7), L.schedule(200, 1.0, 0.5, 7))
        self.assertNotEqual(L.schedule(200, 1.0, 0.5, 7), L.schedule(200, 1.0, 0.5, 8))

    def test_count_bounds_and_order(self):
        rate, jitter = 250.0, 0.6
        offs = L.schedule(rate, 2.0, jitter, 1)
        self.assertEqual(len(offs), 500)
        for k, off in enumerate(offs):
            self.assertLessEqual(abs(off / 1e9 - k / rate), jitter / (2 * rate) + 1e-9)
        self.assertTrue(all(b > a for a, b in zip(offs, offs[1:])))

    def test_zero_jitter_is_the_exact_grid(self):
        self.assertEqual(L.schedule(4, 1.0, 0.0, 3), [0, 250_000_000, 500_000_000, 750_000_000])

    def test_invalid_parameters(self):
        for args in ((0, 1, 0.1), (10, 0, 0.1), (10, 1, 1.0), (10, 1, -0.1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                L.schedule(*args, seed=1)


class TestPoisson(unittest.TestCase):
    """FZ-ARRIVALS (2026-10-12): Poisson arrivals, reproducible from the seed."""

    def test_deterministic_ordered_and_inside_the_run(self):
        a = L.poisson_schedule(100, 170.0, 900010)
        self.assertEqual(a, L.poisson_schedule(100, 170.0, 900010))
        self.assertNotEqual(a, L.poisson_schedule(100, 170.0, 900011))
        self.assertEqual(a, sorted(a))
        self.assertTrue(0 < a[0] and a[-1] < 170 * 10 ** 9)

    def test_rate_and_overlapping_arrivals(self):
        a = L.poisson_schedule(100, 1000.0, 1)
        gaps = [(y - x) / 1e9 for x, y in zip(a, a[1:])]
        self.assertAlmostEqual(len(a) / 1000.0, 100, delta=3)             # ~100,000 arrivals, sd ~316
        self.assertAlmostEqual(statistics.mean(gaps), 0.01, delta=0.0003)
        self.assertGreater(sum(g < 0.005 for g in gaps) / len(gaps), 0.35)  # exp: P(gap < 5 ms) = 1 - e^-0.5 = 0.39
        self.assertLess(min(gaps), 0.0005)                                  # bounded jitter never went below 5 ms

    def test_entry_point_and_refusals(self):
        self.assertEqual(L.arrivals("poisson", 100, 2.0, None, 3), L.poisson_schedule(100, 2.0, 3))
        self.assertEqual(L.arrivals("bounded", 100, 2.0, 0.5, 3), L.schedule(100, 2.0, 0.5, 3))
        for args in (("poisson", 100, 2.0, 0.5, 3), ("bounded", 100, 2.0, None, 3), ("burst", 100, 2.0, None, 3),
                     ("poisson", 0, 2.0, None, 3), ("poisson", 100, 0, None, 3)):
            with self.subTest(args), self.assertRaises(ValueError):
                L.arrivals(*args)

    def test_cli_selects_the_process(self):
        seen = {}

        def run(connect, offsets, path, timeout_s, max_inflight):
            seen["offsets"] = offsets
            return []
        with mock.patch.object(L, "run", run), mock.patch.object(L, "write_records"):
            base = ["--target", "127.0.0.1:1", "--rate", "100", "--duration-s", "2", "--seed", "3", "--timeout-s", "1",
                    "--max-inflight", "4", "--out", "/dev/null"]
            self.assertEqual(L.main(base + ["--arrivals", "poisson"]), 0)
            self.assertEqual(seen["offsets"], L.poisson_schedule(100, 2.0, 3))
            self.assertEqual(L.main(base + ["--jitter", "0.5"]), 0)                  # default: bounded
            self.assertEqual(seen["offsets"], L.schedule(100, 2.0, 0.5, 3))
            with mock.patch("sys.stderr"):
                self.assertEqual(L.main(base + ["--arrivals", "poisson", "--jitter", "0.5"]), 2)
                self.assertEqual(L.main(base), 2)                                     # bounded needs a jitter


class TestRequest(unittest.TestCase):
    def serve_once(self, reply):
        client, server = socket.socketpair()

        def peer():
            with server:
                server.recv(4096)
                if reply is not None:
                    server.sendall(reply)
        threading.Thread(target=peer).start()
        return lambda: client

    def test_status_parsed(self):
        out, lat = L.request_once(self.serve_once(b"HTTP/1.1 503 Service Unavailable\r\n\r\n"), "/work", 2)
        self.assertEqual(out, "503")
        self.assertIsNotNone(lat)

    def test_malformed_response(self):
        self.assertEqual(L.request_once(self.serve_once(b"garbage"), "/w", 2)[0], "malformed_response")
        self.assertEqual(L.request_once(self.serve_once(None), "/w", 2)[0], "malformed_response")   # empty

    def test_connection_error_recorded_by_class_name(self):
        def refuse():
            raise ConnectionRefusedError("refused")
        self.assertEqual(L.request_once(refuse, "/w", 1), ("ConnectionRefusedError", None))

    def test_timeout_recorded(self):
        client, server = socket.socketpair()                # the peer never answers
        try:
            out, lat = L.request_once(lambda: client, "/w", 0.2)
            self.assertEqual((out, lat), ("TimeoutError", None))
        finally:
            server.close()


class TestOpenLoop(unittest.TestCase):
    def test_sends_on_schedule_and_accounts_for_saturation(self):
        gate, accepted = threading.Event(), []

        def stuck():
            client, server = socket.socketpair()
            accepted.append(server)                         # nobody answers until the gate opens
            threading.Thread(target=lambda s=server: (gate.wait(5), s.close())).start()
            return client
        offs = L.schedule(100, 0.3, 0.0, 1)                 # 30 arrivals over 0.3 s
        t0 = time.monotonic()
        rec = []
        th = threading.Thread(target=lambda: rec.extend(L.run(stuck, offs, "/w", 5.0, max_inflight=5)))
        th.start()
        self.assertTrue(th.is_alive())
        time.sleep(0.5)
        self.assertEqual(len(accepted), 5)                  # open loop: never waits for answers beyond max_inflight
        gate.set()
        th.join()
        self.assertLess(time.monotonic() - t0, 3.0)
        o = outcomes(rec)
        self.assertEqual(o.get("client_saturated"), 25)
        self.assertEqual(sum(o.values()), 30)               # every scheduled arrival accounted for
        self.assertEqual([r["k"] for r in rec], list(range(30)))
        self.assertTrue(all(r["sent_ns"] is None for r in rec if r["outcome"] == "client_saturated"))

    def test_send_times_follow_the_schedule(self):
        svc = W.Service(CFG)
        offs = L.schedule(50, 0.4, 0.5, 3)
        rec = L.run(into(svc), offs, "/work", 2.0, max_inflight=10)
        lateness = [(r["sent_ns"] - r["scheduled_ns"]) / 1e6 for r in rec]
        self.assertTrue(all(x >= -0.001 for x in lateness))  # never early
        self.assertLess(sorted(lateness)[len(lateness) // 2], 5.0)   # median lateness of a few ms at most


class TestAgainstTheWorkload(unittest.TestCase):
    def test_every_response_matches_the_workload_counters(self):
        svc = W.Service(dict(CFG, cpu_us=200))
        rec = L.run(into(svc), L.schedule(200, 0.5, 0.5, 11), "/work", 2.0, max_inflight=50)
        o = outcomes(rec)
        self.assertEqual(o, {"200": 100})
        m = svc.metrics
        self.assertTrue(W_wait(lambda: m.counters["requests_completed_total"] == 100))
        self.assertEqual((m.counters["requests_failed_total"], m.counters["requests_rejected_total"]), (0, 0))
        self.assertTrue(all(r["latency_ms"] is not None and r["latency_ms"] >= 0 for r in rec))

    def test_overload_outcomes_match_the_workload_counters(self):
        gate = threading.Event()
        svc = W.Service(dict(CFG, pool=1, queue=1), dependency=lambda timeout: gate.wait(0.05))
        rec = L.run(into(svc), L.schedule(200, 0.3, 0.0, 5), "/work", 3.0, max_inflight=60)
        o = outcomes(rec)
        m = svc.metrics
        self.assertTrue(W_wait(lambda: m.counters["requests_completed_total"] == o.get("200", 0)))
        self.assertGreater(o.get("503", 0), 0)
        self.assertEqual(o.get("503", 0), m.counters["requests_rejected_total"])
        self.assertEqual(sum(o.values()), 60)
        self.assertEqual(set(o) - {"200", "503"}, set(), o)  # no resets, timeouts or malformed answers


def W_wait(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.01)
    return False


class TestOutputAndCli(unittest.TestCase):
    def test_records_written_atomically_as_json_lines(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "client.jsonl")
            recs = [{"k": 0, "scheduled_ns": 1, "sent_ns": 2, "outcome": "200", "latency_ms": 1.5}]
            L.write_records(out, recs)
            self.assertEqual([json.loads(x) for x in Path(out).read_text().splitlines()], recs)
            self.assertEqual(sorted(os.listdir(t)), ["client.jsonl"])
            self.assertEqual(os.stat(out).st_mode & 0o777, 0o644)

    def test_symlinked_temporary_name_is_not_followed(self):
        with tempfile.TemporaryDirectory() as t:
            target = os.path.join(t, "elsewhere")
            os.symlink(target, os.path.join(t, f".client.jsonl.tmp.{os.getpid()}"))
            with self.assertRaises(OSError):
                L.write_records(os.path.join(t, "client.jsonl"), [])
            self.assertFalse(os.path.exists(target))

    def test_cli_rejects_invalid_parameters(self):
        base = ["--target", "127.0.0.1:1", "--rate", "10", "--duration-s", "1", "--jitter", "0.1", "--seed", "1",
                "--timeout-s", "1", "--out", os.devnull]
        self.assertEqual(L.main(base + ["--max-inflight", "0"]), 2)
        self.assertEqual(L.main([a if a != "0.1" else "1.5" for a in base] + ["--max-inflight", "1"]), 2)


if __name__ == "__main__":
    unittest.main()
