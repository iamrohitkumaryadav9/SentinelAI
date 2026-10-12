"""M4 rehearsal (experiments/faultlab/rehearsal.py): real loopback runs, evidence manifest, replay, reconciliation.

The real runs are unprivileged: 127.0.0.1 ephemeral ports, temporary directories, no namespaces, cgroup writes or eBPF.
Tamper tests work on copies of a finished real run; the remaining negative cases use small synthetic evidence.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("faultlab_rehearsal", ROOT / "experiments/faultlab/rehearsal.py")
R = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R)

from sentinelai.collectors import Bad, Status  # noqa: E402
from sentinelai.collectors.normalize import Tick  # noqa: E402
from sentinelai.runtime.ticks import encode_ticks  # noqa: E402

AS_LAB = os.geteuid() == 1000 and os.getegid() == 1000           # the workload's lab-identity check
APP_FEATURES = {"app.dependency_latency_ms", "app.error_rate", "app.events", "app.latency_ms", "app.lock_wait_ms",
                "app.pool_rejections", "app.pool_utilization", "app.queue_wait_ms", "app.throughput"}


def real_run(profile: str, seed: int):
    t = tempfile.TemporaryDirectory()
    out = Path(t.name) / "run"
    rc = R.main(["run", "--out", str(out), "--seed", str(seed), "--profile", profile])
    return t, out, rc


@unittest.skipUnless(AS_LAB, "the workload runs only as the lab uid/gid 1000")
class TestRealRehearsal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._t, cls.out, cls.rc = real_run("smoke", 11)
        cls.report = json.loads((cls.out / "report.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls._t.cleanup()

    def copy(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        dst = Path(t.name) / "run"
        shutil.copytree(self.out, dst, symlinks=True)
        return dst

    def test_run_passes_every_check(self):
        self.assertEqual(self.rc, 0, json.dumps(self.report, indent=1)[:3000])
        self.assertTrue(all(c["ok"] for c in self.report["checks"].values()))

    def test_nine_app_features_ok_or_partial_at_app_scope(self):
        rows = self.report["checks"]["app_features"]["measurements"]
        self.assertEqual({r["feature"] for r in rows}, APP_FEATURES)
        self.assertTrue(all(r["quality"] in ("OK", "PARTIAL") and r["scope"] == "app:faultlab-rehearsal"
                            for r in rows))
        self.assertTrue(all(r["value"] is not None for r in rows))
        snap = json.loads((self.out / "snapshot.json").read_bytes())
        self.assertFalse({"APP_METRICS", "APP_EVENTS"} & set(snap["data_quality"]["sources_unavailable"]))

    def test_replay_is_byte_identical_and_verify_passes(self):
        self.assertEqual(R.replay(self.out), (self.out / "snapshot.json").read_bytes())
        self.assertEqual(R.verify(self.out), 0)

    def test_reconciliation_exact(self):
        rec = self.report["checks"]["reconciliation"]
        self.assertEqual(rec["problems"], [])
        self.assertEqual(sum(v for k, v in rec["client_outcomes"].items()), rec["scheduled_arrivals"])
        self.assertEqual(rec["server_window_delta"]["requests_completed_total"], rec["client_outcomes"]["200"])

    def test_recorded_arrivals_match_the_load_generators_schedule(self):
        run = json.loads((self.out / "evidence" / "run.json").read_text())
        spec = importlib.util.spec_from_file_location("lg_check", ROOT / "experiments/faultlab/docker/loadgen.py")
        lg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lg)
        load = run["load"]
        self.assertEqual(load["arrivals"], len(lg.schedule(load["rate"], load["duration_s"], load["jitter"],
                                                           load["seed"])))
        self.assertEqual(len((self.out / "evidence" / "client.jsonl").read_text().splitlines()), load["arrivals"])

    def test_manifest_covers_exactly_the_evidence(self):
        listed = json.loads((self.out / "manifest.json").read_text())["files"]
        actual = {f"evidence/{p.name}" for p in (self.out / "evidence").iterdir()}
        self.assertEqual(set(listed), actual)
        self.assertEqual(actual, {f"evidence/{n}" for n in ("client.jsonl", "config.json", "control.json",
                                                            "dependency_config.json", "run.json", "ticks.jsonl")})
        self.assertNotIn("manifest.json", listed)

    def test_corrupted_ticks_detected_by_manifest_and_replay(self):
        out = self.copy()
        p = out / "evidence" / "ticks.jsonl"
        data = bytearray(p.read_bytes())
        i = data.index(b'"index":3')
        data[i + 8:i + 9] = b"4"                             # tick 3 now claims index 4
        p.write_bytes(bytes(data))
        self.assertIn("digest mismatch: evidence/ticks.jsonl", R.verify_manifest(out))
        self.assertEqual(R.verify(out), 1)

    def test_missing_extra_and_symlinked_evidence_detected(self):
        out = self.copy()
        (out / "evidence" / "client.jsonl").unlink()
        (out / "evidence" / "notes.txt").write_text("x")
        os.symlink("/etc/hostname", out / "evidence" / "link")
        problems = R.verify_manifest(out)
        self.assertIn("missing listed file: evidence/client.jsonl", problems)
        self.assertIn("unexpected evidence file: evidence/notes.txt", problems)
        self.assertIn("symbolic link in evidence: evidence/link", problems)

    def test_snapshot_tampering_detected_by_verify(self):
        out = self.copy()
        p = out / "snapshot.json"
        p.write_bytes(p.read_bytes().replace(b'"faultlab-rehearsal"', b'"faultlab-rehearsel"', 1))
        self.assertEqual(R.verify(out), 1)

    def test_existing_directory_is_refused(self):
        self.assertEqual(R.main(["run", "--out", str(self.out)]), 2)


@unittest.skipUnless(AS_LAB, "the workload runs only as the lab uid/gid 1000")
class TestRealOverload(unittest.TestCase):
    def test_rejections_reconcile_exactly(self):
        t, out, rc = real_run("overload", 12)
        self.addCleanup(t.cleanup)
        report = json.loads((out / "report.json").read_text())
        self.assertEqual(rc, 0, json.dumps(report["checks"], indent=1)[:3000])
        rec = report["checks"]["reconciliation"]
        self.assertGreater(rec["client_outcomes"].get("503", 0), 0)
        self.assertEqual(rec["server_window_delta"]["requests_rejected_total"], rec["client_outcomes"]["503"])


# ---------------------------------------------------------------------------------------------- synthetic evidence
def evidence(tmp: Path, docs, records, nb=2, nw=4, arrivals=None):
    """A minimal run directory: ticks whose app observations are docs (dict or Bad), plus client records."""
    out = tmp / "run"
    (out / "evidence").mkdir(parents=True)
    ticks = [Tick(i, float(i), datetime(2026, 10, 11, tzinfo=timezone.utc), {"app": d}) for i, d in enumerate(docs)]
    (out / "evidence" / "ticks.jsonl").write_bytes(encode_ticks(ticks))
    (out / "evidence" / "client.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
    run = {"format": R.FORMAT, "nB": nb, "nW": nw, "load": {"arrivals": len(records) if arrivals is None else arrivals}}
    (out / "evidence" / "run.json").write_text(json.dumps(run))
    return out


def doc(t_s, completed=0, rejected=0, failed=0, busy=0.0):
    return {"mono_s": t_s, "requests_completed_total": float(completed), "requests_rejected_total": float(rejected),
            "requests_failed_total": float(failed), "pool_util": busy}


def rec(k, outcome="200", sent_s=2.5, lat_ms=10.0):
    return {"k": k, "scheduled_ns": int(sent_s * 1e9), "sent_ns": None if outcome == "client_saturated" else
            int(sent_s * 1e9), "outcome": outcome, "latency_ms": None if outcome == "client_saturated" else lat_ms}


class Synthetic(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()


class TestReconcile(Synthetic):
    def window(self, end, records, start=None, busy=0.0, **kw):
        docs = [doc(0.0), doc(1.0), start or doc(2.0), doc(3.0), doc(4.0), doc(5.0), {**end, "pool_util": busy}]
        return R.reconcile(evidence(Path(tempfile.mkdtemp(dir=self.tmp)), docs, records, **kw))

    def test_exact_match_passes(self):
        summary, problems = self.window(doc(6.0, completed=2, rejected=1),
                                        [rec(0), rec(1), rec(2, "503"), rec(3, "client_saturated")])
        self.assertEqual(problems, [])
        self.assertEqual(summary["client_saturated"], 1)

    def test_count_mismatch_fails(self):
        _, problems = self.window(doc(6.0, completed=3), [rec(0), rec(1)])
        self.assertIn("requests_completed_total: server delta 3 != client 2", problems)

    def test_missing_client_record_fails(self):
        _, problems = self.window(doc(6.0, completed=2), [rec(0), rec(2)], arrivals=3)
        self.assertTrue(any("scheduled arrivals" in p for p in problems), problems)

    def test_unexplained_client_outcome_fails(self):
        _, problems = self.window(doc(6.0, completed=1), [rec(0), rec(1, "ConnectionResetError")])
        self.assertTrue(any("without a server counterpart" in p for p in problems), problems)

    def test_load_outside_the_window_fails(self):
        _, problems = self.window(doc(6.0, completed=1), [rec(0, sent_s=1.5)])       # sent before the start doc
        self.assertIn("window start document does not predate the first send", problems)
        _, problems = self.window(doc(6.0, completed=1), [rec(0, sent_s=5.9, lat_ms=500.0)])
        self.assertIn("window end document does not postdate the last completion", problems)

    def test_busy_worker_at_the_end_fails(self):
        _, problems = self.window(doc(6.0, completed=1), [rec(0)], busy=0.25)
        self.assertIn("a worker was still busy at the window end document", problems)

    def test_stale_boundary_document_fails(self):
        out = evidence(self.tmp, [doc(0.0), doc(1.0), Bad(Status.ABSENT, "stale: seq did not advance"), doc(3.0),
                                  doc(4.0), doc(5.0), doc(6.0, completed=1)], [rec(0)])
        _, problems = R.reconcile(out)
        self.assertTrue(problems and "window boundary document not valid" in problems[0], problems)


class TestManifest(Synthetic):
    def run_dir(self):
        out = self.tmp / "run"
        (out / "evidence" / "sub").mkdir(parents=True)
        (out / "evidence" / "a.jsonl").write_text("a\n")
        (out / "evidence" / "sub" / "b.json").write_text("{}")
        R.write_manifest(out)
        return out

    def test_round_trip_and_scope(self):
        out = self.run_dir()
        self.assertEqual(R.verify_manifest(out), [])
        self.assertEqual(set(json.loads((out / "manifest.json").read_text())["files"]),
                         {"evidence/a.jsonl", "evidence/sub/b.json"})

    def test_manifest_never_overwritten(self):
        out = self.run_dir()
        with self.assertRaises(FileExistsError):
            R.write_manifest(out)

    def test_missing_corrupted_extra(self):
        out = self.run_dir()
        (out / "evidence" / "a.jsonl").write_text("A\n")
        (out / "evidence" / "sub" / "b.json").unlink()
        (out / "evidence" / "sub" / "c.json").write_text("x")
        self.assertEqual(sorted(R.verify_manifest(out)), sorted([
            "digest mismatch: evidence/a.jsonl", "missing listed file: evidence/sub/b.json",
            "unexpected evidence file: evidence/sub/c.json"]))

    def test_escaping_and_malformed_entries_rejected(self):
        out = self.run_dir()
        digest = json.loads((out / "manifest.json").read_text())["files"]["evidence/a.jsonl"]
        for bad in ("../evidence/a.jsonl", "/etc/passwd", "evidence/../manifest.json", "evidence/./a.jsonl",
                    "evidence\\a.jsonl", "other/a.jsonl", "evidence/a.jsonl\x00"):
            with self.subTest(path=bad):
                m = {"files": {"evidence/a.jsonl": digest, "evidence/sub/b.json": json.loads(
                    (out / "manifest.json").read_text())["files"]["evidence/sub/b.json"], bad: digest}}
                p = self.tmp / "m.json"
                p.write_text(json.dumps(m))
                os.replace(p, out / "manifest.json")
                self.assertTrue(any(x.startswith("unsafe manifest path") for x in R.verify_manifest(out)))
        for doc_ in ({"files": [], }, {"files": {}, "extra": 1}, {"files": {"evidence/a.jsonl": "zz"}}, "nope"):
            with self.subTest(doc=doc_):
                (out / "manifest.json").write_text(json.dumps(doc_))
                self.assertTrue(R.verify_manifest(out))

    def test_symlinked_manifest_or_evidence_dir_refused(self):
        out = self.run_dir()
        real = self.tmp / "real-manifest.json"
        os.replace(out / "manifest.json", real)
        os.symlink(real, out / "manifest.json")
        self.assertTrue(R.verify_manifest(out)[0].startswith("manifest unreadable"))
        out2 = self.tmp / "run2"
        out2.mkdir()
        os.symlink(out / "evidence", out2 / "evidence")
        os.replace(real, out2 / "manifest.json")
        self.assertIn("evidence/ is missing or not a real directory", R.verify_manifest(out2))

    def test_manifest_generation_refuses_symlinks_in_evidence(self):
        out = self.tmp / "run"
        (out / "evidence").mkdir(parents=True)
        os.symlink("/etc/hostname", out / "evidence" / "x")
        with self.assertRaises(R.RehearsalError):
            R.write_manifest(out)
        self.assertFalse((out / "manifest.json").exists())


class TestFeatureReport(unittest.TestCase):
    def snapshot(self, quality="OK"):
        ms = [{"feature_id": f, "aggregation": "RATE", "qualifier": None, "quality": quality, "value": 1.0,
               "coverage": 1.0, "scope": "app:t"} for f in sorted(APP_FEATURES)]
        return json.dumps({"target": {"name": "t"}, "measurements": ms, "missing_measurements": [],
                           "data_quality": {"sources_unavailable": []}}).encode()

    def test_stale_or_insufficient_metrics_fail(self):
        _, problems = R.app_feature_report(self.snapshot("MISSING"))
        self.assertTrue(any("quality MISSING" in p for p in problems))

    def test_unmeasured_features_fail(self):
        _, problems = R.app_feature_report(self.snapshot())   # wrong aggregations and no event codes: not measured
        self.assertTrue(any(p.startswith("not measured") for p in problems))

    def test_structural_exemption_covers_only_a_valueless_missing_measurement_of_that_feature(self):
        def snap(quality="MISSING", value=None, scope="app:t", listed_scope="app:t"):
            ms = [{"feature_id": "app.lock_wait_ms", "aggregation": "P99", "qualifier": None, "quality": quality,
                   "value": value, "coverage": 1.0, "scope": scope},
                  {"feature_id": "app.throughput", "aggregation": "RATE", "qualifier": None, "quality": "MISSING",
                   "value": None, "coverage": 1.0, "scope": "app:t"}]
            return json.dumps({"target": {"name": "t"}, "measurements": ms, "data_quality": {"sources_unavailable": []},
                               "missing_measurements": [{"feature_id": f, "reason": "r", "scope": listed_scope}
                                                        for f in ("app.lock_wait_ms", "app.throughput")]}).encode()
        lock = ("app.lock_wait_ms", "P99", None)
        ex = {"app.lock_wait_ms": "why"}
        rows, problems = R.app_feature_report(snap(), ex)
        self.assertNotIn(f"{lock}: quality MISSING", problems)
        self.assertNotIn("listed as missing: app.lock_wait_ms (r)", problems)
        self.assertEqual([r["feature"] for r in rows if r.get("structurally_unavailable") == "why"],
                         ["app.lock_wait_ms"])
        self.assertIn("('app.throughput', 'RATE', None): quality MISSING", problems)   # never another feature
        self.assertIn("listed as missing: app.throughput (r)", problems)
        _, default = R.app_feature_report(snap())                                       # default: nothing exempt
        self.assertIn(f"{lock}: quality MISSING", default)
        self.assertIn("listed as missing: app.lock_wait_ms (r)", default)
        for name, kw, needle in (("INVALID", {"quality": "INVALID"}, f"{lock}: quality INVALID"),
                                 ("STALE", {"quality": "STALE"}, f"{lock}: quality STALE"),
                                 ("MISSING with a value", {"value": 0.0}, f"{lock}: quality MISSING"),
                                 ("other scope", {"scope": "app:x", "listed_scope": "app:x"}, f"{lock}: scope app:x"),
                                 ("listed at another scope", {"listed_scope": "app:x"},
                                  "listed as missing: app.lock_wait_ms (r)")):
            with self.subTest(name):
                self.assertIn(needle, R.app_feature_report(snap(**kw), ex)[1])
        absent = json.loads(snap())
        absent["measurements"] = absent["measurements"][1:]
        self.assertIn(f"not measured: {lock}", R.app_feature_report(json.dumps(absent).encode(), ex)[1])


class TestProcesses(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.logs = Path(self._t.name)

    def tearDown(self):
        R.stop_all()
        self._t.cleanup()

    def test_startup_failure_reported_with_stderr(self):
        p = R.Proc("broken", [sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"], self.logs)
        with self.assertRaises(R.RehearsalError) as cm:
            p.wait_ready(lambda: False, 5)
        self.assertIn("status 3", str(cm.exception))
        self.assertIn("boom", str(cm.exception))

    def test_readiness_timeout_is_bounded_and_cleanup_kills(self):
        p = R.Proc("sleeper", [sys.executable, "-c", "import time; time.sleep(60)"], self.logs)
        t0 = time.monotonic()
        with self.assertRaises(R.RehearsalError):
            p.wait_ready(lambda: False, 0.5)
        self.assertLess(time.monotonic() - t0, 3)
        self.assertTrue(p.alive())
        codes = R.stop_all()
        self.assertFalse(p.alive())
        self.assertIn("sleeper", codes)
        self.assertEqual(R.Proc.started, [])

    def test_failed_run_stops_its_children_and_reports(self):
        broken = self.logs / "broken_workload.py"
        broken.write_text("import sys\nsys.exit(4)\n")
        out = self.logs / "run"
        orig = R.WORKLOAD
        R.WORKLOAD = broken
        try:
            rc = R.run(out, 1)
        finally:
            R.WORKLOAD = orig
        self.assertEqual(rc, 2)
        report = json.loads((out / "report.json").read_text())
        self.assertIn("dependency exited during startup", report["error"])
        self.assertEqual(R.Proc.started, [])
        self.assertFalse((out / "manifest.json").exists())
        from sentinelai.collectors import app as appmod
        self.assertEqual(appmod.APP_ROOT, "/run/sentinelai-lab/app/")      # restored after the run


class TestContract(unittest.TestCase):
    def test_workload_publishes_faster_than_the_collector_samples(self):
        for name, prof in R.PROFILES.items():
            self.assertLess(prof["workload"]["publish_s"], R.PERIOD_S, name)

    def test_load_lies_inside_the_window(self):
        self.assertGreater(R.LOAD_OFFSET_S, 0)
        self.assertGreater(R.LOAD_TAIL_S, 1.0)

    def test_only_loopback_and_no_privileged_tools(self):
        text = (ROOT / "experiments/faultlab/rehearsal.py").read_text()
        for tok in ("sudo", "unshare", "nsenter", "ip netns", "bpftool", "0.0.0.0", "shell=True", "setns",
                    "/run/sentinelai-lab"):
            self.assertNotIn(tok, text.replace("or /run/sentinelai-lab:", ""))
        listens = [l for l in text.splitlines() if '"--listen"' in l]
        self.assertTrue(listens and all('f"127.0.0.1:' in l for l in listens), listens)

    def test_run_restores_the_reader_root(self):
        from sentinelai.collectors import app as appmod
        self.assertEqual(appmod.APP_ROOT, "/run/sentinelai-lab/app/")


if __name__ == "__main__":
    unittest.main()
