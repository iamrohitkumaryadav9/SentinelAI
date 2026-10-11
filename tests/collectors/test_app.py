"""app.* metrics document: parsing, per-tick validation and window aggregation (no files, no network)."""

import json
import math
import os
import tempfile
import time
import unittest
from unittest import mock

from sentinelai.collectors import app as A
from sentinelai.collectors.errors import Bad, CollectorError, Status

NB = len(A.BUCKETS_MS)


def doc(seq=1, mono_ns=10_000_000_000, completed=0, failed=0, rejected=0, busy=1, size=4, events=None, hist=None,
        pid=4242, **override):
    d = {"schema": A.SCHEMA, "seq": seq, "mono_ns": mono_ns, "pid": pid, "config_sha256": "ab" * 32,
         "counters": {"requests_completed_total": completed, "requests_failed_total": failed,
                      "requests_rejected_total": rejected},
         "events_total": {c: (events or {}).get(c, 0) for c in A.EVENT_CODES},
         "pool_size": size, "pool_busy": busy,
         "histograms": {h: list((hist or {}).get(h, [0] * NB)) for h in A.HISTOGRAMS}}
    d.update(override)
    return d


def raw(d):
    return json.dumps(d).encode()


def buckets(**at):
    """Per-bucket counts from {bucket_index: count}."""
    c = [0] * NB
    for i, n in at.items():
        c[int(i[1:])] = n
    return c


class TestParse(unittest.TestCase):
    def test_valid_document(self):
        s = A.parse(raw(doc(completed=5, events={"QUEUE_FULL": 2})))
        self.assertIsInstance(s, A.AppSample)
        self.assertEqual((s.seq, s.counters["requests_completed_total"], s.events["QUEUE_FULL"]), (1, 5, 2))

    def test_bucket_bounds(self):
        self.assertEqual(NB, 19)
        self.assertAlmostEqual(A.BUCKETS_MS[0], 0.05)
        self.assertAlmostEqual(A.BUCKETS_MS[17], 6553.6)
        self.assertTrue(math.isinf(A.BUCKETS_MS[18]))

    def assertMalformed(self, data, needle=""):
        r = A.parse(data)
        self.assertIsInstance(r, Bad, r)
        self.assertIs(r.status, Status.MALFORMED)
        self.assertIn(needle, r.detail)

    def test_rejects_malformed_documents(self):
        cases = {
            "truncated (partial write)": raw(doc())[:-7],
            "not json": b"metrics",
            "not utf-8": b"\xff\xfe{}",
            "empty": b"",
            "array": b"[]",
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.assertMalformed(data)

    def test_oversized(self):
        self.assertMalformed(b" " * (A.MAX_BYTES + 1), "larger than")

    def test_schema_violations(self):
        d = doc()
        cases = {
            "wrong schema": dict(d, schema="sentinelai-app-metrics/2"),
            "missing key": {k: v for k, v in d.items() if k != "pool_busy"},
            "unknown key": dict(d, extra=1),
            "negative counter": dict(d, counters=dict(d["counters"], requests_failed_total=-1)),
            "float counter": dict(d, counters=dict(d["counters"], requests_failed_total=1.0)),
            "bool counter": dict(d, counters=dict(d["counters"], requests_failed_total=True)),
            "string seq": dict(d, seq="1"),
            "missing counter": dict(d, counters={"requests_completed_total": 0, "requests_failed_total": 0}),
            "unknown event code": dict(d, events_total=dict(d["events_total"], OOM=1)),
            "short histogram": dict(d, histograms=dict(d["histograms"], latency=[0] * (NB - 1))),
            "missing histogram": dict(d, histograms={h: [0] * NB for h in A.HISTOGRAMS[:3]}),
            "pool_busy > pool_size": dict(d, pool_busy=5),
            "pool_size 0": dict(d, pool_size=0, pool_busy=0),
            "pid 0": dict(d, pid=0),
            "bad config hash": dict(d, config_sha256="AB" * 32),
        }
        for name, bad in cases.items():
            with self.subTest(name):
                self.assertMalformed(raw(bad))

    def test_non_finite_and_duplicate_keys(self):
        self.assertMalformed(raw(doc()).replace(b'"seq": 1', b'"seq": NaN'), "non-finite")
        self.assertMalformed(raw(doc()).replace(b'"seq": 1', b'"seq": Infinity'), "non-finite")
        self.assertMalformed(raw(doc()).replace(b'"seq": 1', b'"seq": 1, "seq": 2'), "duplicate")

    def test_deep_nesting_rejected_not_raised(self):
        self.assertMalformed(b"[" * 100000 + b"]" * 100000)

    def test_not_bytes(self):
        self.assertMalformed("{}", "not bytes")


class TestObserve(unittest.TestCase):
    NOW = 10_500_000_000

    def test_first_valid(self):
        self.assertIsInstance(A.observe(raw(doc()), None, self.NOW), A.AppSample)

    def test_reader_bad_passes_through(self):
        for st in (Status.ABSENT, Status.DENIED):
            b = Bad(st, "x")
            self.assertIs(A.observe(b, None, self.NOW), b)

    def test_seq_not_advanced_is_stale(self):
        prev = A.parse(raw(doc(seq=3)))
        r = A.observe(raw(doc(seq=3, mono_ns=10_100_000_000)), prev, self.NOW)
        self.assertEqual((r.status, r.detail), (Status.ABSENT, "stale: seq did not advance"))

    def test_old_document_is_stale(self):
        r = A.observe(raw(doc(mono_ns=self.NOW - A.STALE_NS - 1)), None, self.NOW)
        self.assertEqual((r.status, r.detail), (Status.ABSENT, "stale: document older than 2 s"))

    def test_future_timestamp_invalid(self):
        self.assertIs(A.observe(raw(doc(mono_ns=self.NOW + 1)), None, self.NOW).status, Status.MALFORMED)

    def test_seq_advanced_time_not(self):
        prev = A.parse(raw(doc(seq=1)))
        self.assertIs(A.observe(raw(doc(seq=2)), prev, self.NOW).status, Status.MALFORMED)

    def test_counter_decrease_is_reset(self):
        prev = A.parse(raw(doc(seq=1, completed=10)))
        for name, cur in {"counter": doc(seq=2, mono_ns=10_100_000_000, completed=9),
                          "event": doc(seq=2, mono_ns=10_100_000_000, completed=10, events={"QUEUE_FULL": 0}),
                          "histogram": doc(seq=2, mono_ns=10_100_000_000, completed=10)}.items():
            with self.subTest(name):
                p = prev
                if name == "event":
                    p = A.parse(raw(doc(seq=1, completed=10, events={"QUEUE_FULL": 1})))
                if name == "histogram":
                    p = A.parse(raw(doc(seq=1, completed=10, hist={"latency": buckets(b3=2)})))
                r = A.observe(raw(cur), p, self.NOW)
                self.assertIs(r.status, Status.MALFORMED)
                self.assertIn("decreased", r.detail)

    def test_pid_change_invalid(self):
        prev = A.parse(raw(doc(seq=1)))
        r = A.observe(raw(doc(seq=2, mono_ns=10_100_000_000, pid=99)), prev, self.NOW)
        self.assertIs(r.status, Status.MALFORMED)


class TestPercentile(unittest.TestCase):
    def test_upper_bound_of_rank_bucket(self):
        c = buckets(b2=98, b10=2)                           # 100 requests
        self.assertEqual(A.percentile(c, 0.50), (A.BUCKETS_MS[2], None))
        self.assertEqual(A.percentile(c, 0.98), (A.BUCKETS_MS[2], None))
        self.assertEqual(A.percentile(c, 0.99), (A.BUCKETS_MS[10], None))

    def test_nearest_rank_rounds_up(self):
        c = buckets(b1=1, b2=1, b3=1)                       # n = 3: rank ceil(0.5 * 3) = 2, not floor = 1
        self.assertEqual(A.percentile(c, 0.50), (A.BUCKETS_MS[2], None))
        self.assertEqual(A.percentile(c, 0.99), (A.BUCKETS_MS[3], None))

    def test_single_request(self):
        self.assertEqual(A.percentile(buckets(b5=1), 0.99), (A.BUCKETS_MS[5], None))

    def test_no_requests_is_missing_not_zero(self):
        self.assertEqual(A.percentile([0] * NB, 0.99), (None, "no requests in the window"))

    def test_rank_in_inf_bucket_is_missing(self):
        self.assertEqual(A.percentile(buckets(b1=1, b18=99), 0.99), (None, "rank in the +Inf bucket"))

    def test_bad_quantile(self):
        for q in (0.0, 1.5, -0.1):
            with self.assertRaises(ValueError):
                A.percentile([1] + [0] * (NB - 1), q)


class TestWindowValues(unittest.TestCase):
    def sample(self, t_s, completed, failed=0, rejected=0, busy=1, lat=None, events=None):
        return A.parse(raw(doc(seq=t_s + 1, mono_ns=int(t_s * 1e9) + 1, completed=completed, failed=failed,
                               rejected=rejected, busy=busy, events=events, hist={"latency": lat or [0] * NB})))

    def test_values_from_first_and_last_valid(self):
        s0 = self.sample(0, 0, lat=[0] * NB)
        s1 = Bad(Status.ABSENT, "stale")
        s2 = self.sample(10, 200, failed=5, rejected=20, busy=3, lat=buckets(b4=190, b9=10),
                         events={"QUEUE_FULL": 20})
        v = A.window_values([s0, s1, s2])
        self.assertAlmostEqual(v[("app.throughput", "RATE")][0], 20.0)
        self.assertAlmostEqual(v[("app.pool_rejections", "RATE")][0], 2.0)
        self.assertAlmostEqual(v[("app.error_rate", "RATIO")][0], 5 / 205)
        self.assertAlmostEqual(v[("app.events", "QUEUE_FULL")][0], 2.0)
        self.assertEqual(v[("app.events", "POOL_EXHAUSTED")], (0.0, None))
        self.assertEqual(v[("app.latency_ms", "P50")], (A.BUCKETS_MS[4], None))
        self.assertEqual(v[("app.latency_ms", "P99")], (A.BUCKETS_MS[9], None))
        self.assertAlmostEqual(v[("app.pool_utilization", "MEAN")][0], (1 / 4 + 3 / 4) / 2)

    def test_deltas_span_first_to_last_of_many_valid_samples(self):
        v = A.window_values([self.sample(0, 0), self.sample(1, 10), self.sample(2, 20, lat=buckets(b6=5)),
                             self.sample(4, 100, lat=buckets(b6=5, b8=95))])
        self.assertAlmostEqual(v[("app.throughput", "RATE")][0], 25.0)
        self.assertEqual(v[("app.latency_ms", "P99")], (A.BUCKETS_MS[8], None))

    def test_idle_window_has_no_percentile_or_error_rate(self):
        v = A.window_values([self.sample(0, 7), self.sample(10, 7)])
        self.assertEqual(v[("app.latency_ms", "P99")], (None, "no requests in the window"))
        self.assertEqual(v[("app.error_rate", "RATIO")], (None, "no completed or failed requests"))
        self.assertEqual(v[("app.throughput", "RATE")], (0.0, None))        # a measured zero, not a missing value

    def test_fewer_than_two_valid_samples(self):
        v = A.window_values([Bad(Status.ABSENT, "x"), self.sample(0, 1), Bad(Status.MALFORMED, "y")])
        self.assertEqual(v[("app.throughput", "RATE")], (None, "fewer than two valid samples"))
        self.assertEqual(v[("app.latency_ms", "P99")], (None, "fewer than two valid samples"))
        self.assertAlmostEqual(v[("app.pool_utilization", "MEAN")][0], 0.25)

    def test_no_valid_samples(self):
        v = A.window_values([Bad(Status.ABSENT, "x")])
        self.assertTrue(all(val is None and why for val, why in v.values()))

    def test_non_positive_span_or_mixed_process(self):
        s = self.sample(0, 1)
        v = A.window_values([s, s])
        self.assertIsNone(v[("app.throughput", "RATE")][0])
        other = A.parse(raw(doc(seq=9, mono_ns=5_000_000_001, pid=7)))
        self.assertIsNone(A.window_values([s, other])[("app.throughput", "RATE")][0])

    def test_matches_registry_features_and_aggregations(self):
        from sentinelai.diagnostic.contract import load_contract
        specs = {f.id: f for f in load_contract().registry.features if f.id.startswith("app.")}
        v = A.window_values([self.sample(0, 0), self.sample(1, 1, lat=buckets(b0=1))])
        self.assertEqual({k[0] for k in v}, set(specs))
        for fid, spec in specs.items():
            got = {k[1] for k in v if k[0] == fid}
            want = set(A.EVENT_CODES) if fid == "app.events" else {str(getattr(a, "value", a)) for a in spec.aggregations}
            self.assertEqual(got, want, fid)


class TestReadMetrics(unittest.TestCase):
    """read_metrics against a temporary APP_ROOT (real files; nothing outside the temporary directory is touched)."""
    RUN = "PL-QDISC-I2-s1013"

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.join(self._t.name, "run", "sentinelai-lab", "app")
        os.makedirs(os.path.join(self.root, self.RUN))
        self.file = os.path.join(self.root, self.RUN, "metrics.json")
        self._patch = mock.patch.object(A, "APP_ROOT", self.root + "/")
        self._patch.start()
        self._uid = mock.patch.object(A, "LAB_UID", os.geteuid())      # files below are created by this process
        self._uid.start()

    def tearDown(self):
        self._uid.stop()
        self._patch.stop()
        for dirpath, dirnames, _ in os.walk(self._t.name):
            for d in dirnames:
                os.chmod(os.path.join(dirpath, d), 0o755)
        self._t.cleanup()

    def put(self, data: bytes, path=None):
        with open(path or self.file, "wb") as fh:
            fh.write(data)

    def bad(self, status, needle=""):
        r = A.read_metrics(self.RUN)
        self.assertIsInstance(r, Bad, r)
        self.assertIs(r.status, status, r)
        self.assertIn(needle, r.detail)

    def test_reads_document_bytes(self):
        self.put(raw(doc()))
        self.assertEqual(A.read_metrics(self.RUN), raw(doc()))

    def test_end_to_end_valid_sample(self):
        self.put(raw(doc(mono_ns=time.monotonic_ns() - 1)))
        self.assertIsInstance(A.observe(A.read_metrics(self.RUN), None, time.monotonic_ns()), A.AppSample)

    def test_partial_write_is_read_then_rejected(self):
        self.put(raw(doc())[:-9])
        r = A.observe(A.read_metrics(self.RUN), None, time.monotonic_ns())
        self.assertIs(r.status, Status.MALFORMED)

    def test_absent_file_and_run_directory(self):
        self.bad(Status.ABSENT)
        self.assertIs(A.read_metrics("CTRL-s9").status, Status.ABSENT)

    def test_symlinked_file_refused(self):
        target = os.path.join(self._t.name, "elsewhere.json")
        self.put(raw(doc()), target)
        os.symlink(target, self.file)
        self.bad(Status.REFUSED, "symbolic link")

    def test_symlinked_run_directory_refused(self):
        real = os.path.join(self._t.name, "real-run")
        os.makedirs(real)
        self.put(raw(doc()), os.path.join(real, "metrics.json"))
        os.symlink(real, os.path.join(self.root, "CTRL-s3"))
        self.assertIs(A.read_metrics("CTRL-s3").status, Status.REFUSED)

    def test_symlink_in_root_component_refused(self):
        lab = os.path.join(self._t.name, "run", "sentinelai-lab")
        os.rename(lab, lab + "-real")
        os.symlink(lab + "-real", lab)
        self.put(raw(doc()))
        self.bad(Status.REFUSED)

    def test_fifo_rejected_without_blocking(self):
        os.mkfifo(self.file)
        t0 = time.monotonic()
        self.bad(Status.MALFORMED, "not a regular file")
        self.assertLess(time.monotonic() - t0, 1.0)

    def test_directory_rejected(self):
        os.mkdir(self.file)
        self.bad(Status.MALFORMED, "not a regular file")

    def test_non_directory_component_refused(self):
        os.rmdir(os.path.join(self.root, self.RUN))
        self.put(b"x", os.path.join(self.root, self.RUN))
        self.bad(Status.REFUSED)

    def test_size_limit(self):
        self.put(b" " * A.MAX_BYTES)
        self.assertEqual(len(A.read_metrics(self.RUN)), A.MAX_BYTES)
        self.put(b" " * (A.MAX_BYTES + 1))
        self.bad(Status.MALFORMED, "larger than")

    def test_oversized_rejected_before_any_read(self):
        self.put(b" " * (A.MAX_BYTES + 1))
        with mock.patch.object(A.os, "read", side_effect=AssertionError("read attempted")):
            self.bad(Status.MALFORMED, "larger than")

    def test_growth_after_fstat_still_bounded(self):
        """fstat reports a small size (the file grew afterwards); the bounded read must still refuse it."""
        self.put(b" " * (A.MAX_BYTES + 10))
        real = os.fstat

        def small(fd):
            st = real(fd)
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, st.st_gid, 10,
                                   st.st_atime, st.st_mtime, st.st_ctime))
        with mock.patch.object(A.os, "fstat", side_effect=small):
            self.bad(Status.MALFORMED, "larger than")

    @unittest.skipIf(os.geteuid() == 0, "root bypasses file permissions")
    def test_permission_denied(self):
        self.put(raw(doc()))
        os.chmod(self.file, 0)
        self.bad(Status.DENIED)
        os.chmod(self.file, 0o644)
        os.chmod(os.path.join(self.root, self.RUN), 0)
        self.bad(Status.DENIED)

    def test_invalid_run_ids_are_usage_errors(self):
        for rid in ("", "..", "../CTRL-s1", "CTRL-s1/..", "CTRL", "ctrl-s1", "CTRL-s1/x", "CTRL-s1\x00", None, 7):
            with self.subTest(rid=rid), self.assertRaises(CollectorError):
                A.read_metrics(rid)

    def test_no_descriptor_leaks(self):
        before = len(os.listdir("/proc/self/fd"))
        self.put(raw(doc()))
        for _ in range(50):
            A.read_metrics(self.RUN)
            A.read_metrics("CTRL-s9")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_owned_by_lab_uid_accepted(self):
        self.put(raw(doc()))
        self.assertEqual(os.stat(self.file).st_uid, A.LAB_UID)
        self.assertEqual(A.read_metrics(self.RUN), raw(doc()))

    def test_other_owner_refused(self):
        self.put(raw(doc()))
        with mock.patch.object(A, "LAB_UID", os.geteuid() + 1):
            self.bad(Status.REFUSED, "not the lab uid")

    def test_owner_checked_before_any_read(self):
        self.put(raw(doc()))
        with mock.patch.object(A, "LAB_UID", os.geteuid() + 1), \
                mock.patch.object(A.os, "read", side_effect=AssertionError("read attempted")):
            self.bad(Status.REFUSED)

    def test_lab_uid_matches_the_lab_tooling(self):
        import re as _re
        from pathlib import Path
        text = (Path(__file__).resolve().parents[2] / "scripts" / "r2c_cpu.py").read_text()
        self._uid.stop()
        try:
            self.assertEqual(A.LAB_UID, int(_re.search(r"^LAB_UID = LAB_GID = (\d+)$", text, _re.M).group(1)))
        finally:
            self._uid.start()

    def test_production_root_is_fixed(self):
        self._patch.stop()
        try:
            self.assertEqual(A.APP_ROOT, "/run/sentinelai-lab/app/")
        finally:
            self._patch.start()


if __name__ == "__main__":
    unittest.main()
