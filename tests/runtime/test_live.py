"""Phase 2A.4: live read-only M3A acquisition through the runtime, with injected readers only (no host reads here).

The reader steps through the deterministic synthetic World one tick per clock step (the collectors' own test
pattern), answers the cgroup files target resolution needs, and fails the test if the tc command is ever used.
These tests validate the integration logic; they do not validate a live host run (that needs the separately
authorised first live acquisition).
"""

import io
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from collectors._world import NB, NW, T0, TARGET, World
from sentinelai.__main__ import main
from sentinelai.collectors import ManualClock
from sentinelai.collectors.errors import Bad, CollectorError, Status
from sentinelai.diagnostic.contract import EvidenceSnapshot, Quality
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.runtime import ArtifactStore, IncidentContext, TargetSpec, registry
from sentinelai.runtime.acquisition import AcquisitionFailed
from sentinelai.runtime.live import LiveRefused, NoCommandReader, acquire, run_live
from sentinelai.runtime.pipeline import snapshot_from_ticks
from sentinelai.runtime.replay import replay_run_dir, verify_run_dir
from sentinelai.runtime.store import verify_run

from runtime.test_replay import fingerprint

COMMIT = "0bb1fc6"
CG = f"/sys/fs/cgroup{TARGET.cgroup_path}"
MEMORY = {"cg.pgscan": 50_000, "cg.refault_file": 40_000, "cg.pgmajfault": 40_000, "cg.mem.some": 300_000,
          "cg.mem.full": 200_000, "cg.events.high": 500}
N = NB + NW + 1


class StepReader:
    """World.reader(k) for the clock's current tick k; cgroup files for target resolution; tc forbidden."""

    def __init__(self, world, clock, procs="100\n", cpuset="0-1\n", raise_at=None):
        self.w, self.clock, self.procs, self.cpuset, self.raise_at = world, clock, procs, cpuset, raise_at
        self.calls = 0

    def read(self, p):
        self.calls += 1
        if self.raise_at is not None and self.clock._i == self.raise_at:
            raise CollectorError("injected reader failure")
        if p == f"{CG}/cgroup.procs":
            return self.procs
        if p == f"{CG}/cpuset.cpus.effective":
            return self.cpuset
        return self.w.reader(self.clock._i).read(p)

    def listdir(self, p):
        return self.w.reader(self.clock._i).listdir(p)

    def readlink(self, p):
        return self.w.reader(self.clock._i).readlink(p)

    def tc_qdisc(self, ifname):
        raise AssertionError("the tc command must never be reached in Phase 2A.4")


def clock():
    return ManualClock([(float(k), T0 + timedelta(seconds=k)) for k in range(N)])


def event_clock(start=datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)):
    st = {"t": start}

    def tick():
        st["t"] += timedelta(milliseconds=3)
        return st["t"], 1.0
    return tick


def ctx(incident="live-1", ebpf="disabled", ifaces=(), cgroup=TARGET.cgroup_path):
    return IncidentContext(incident_id=incident, ebpf=ebpf,
                           target=TargetSpec(name=TARGET.name, cgroup_path=cgroup, ifaces=ifaces))


def world(rates=None, **overrides):
    w = World()
    w.window_rates.update(rates or {})
    for path, (ticks, value) in overrides.items():
        w.override(path, ticks, value)
    return w


def live(store, w=None, incident="live-1", **kw):
    c = clock()
    return run_live(ctx(incident), store, code_commit=COMMIT, reader=StepReader(w or World(), c, **kw), clock=c,
                    event_clock=event_clock())


class StoreCase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = self._t.name
        self.store = ArtifactStore(self.root)

    def tearDown(self):
        self._t.cleanup()


class TestCompleteAndPartial(StoreCase):
    def test_complete_acquisition_end_to_end(self):
        rec, rep, run, status = live(self.store, world(MEMORY))
        self.assertEqual((status, rep.decision), ("COMPLETE", "memory_pressure"))
        self.assertEqual(sorted(os.listdir(run)), ["acquisition.json", "context.json", "diagnosis.json",
                                                   "events.jsonl", "manifest.json", "parameter_set.json",
                                                   "snapshot.json", "ticks.jsonl"])
        acq = json.loads(Path(run, "acquisition.json").read_bytes())
        self.assertEqual((acq["status"], acq["ebpf"], acq["bad_counts"], acq["ticks"]["count"]), ("COMPLETE", False, {}, N))
        self.assertEqual(acq["collection"]["mode"], "live-m3a")
        self.assertEqual(acq["collection"]["reader"], "StepReader")
        self.assertEqual(acq["collection"]["ticks"], N)
        self.assertEqual(acq["target"]["pids"], [100])
        self.assertEqual(acq["target"]["ifaces"], [])
        self.assertEqual(acq["collector_versions"], ["m3a-1.1.0"])
        kinds = [json.loads(l)["kind"] for l in Path(run, "events.jsonl").read_text().splitlines()]
        self.assertEqual(kinds[:3], ["acquisition_started", "acquisition_completed", "snapshot_created"])
        self.assertEqual(kinds[-1], "diagnosis_completed")
        self.assertFalse(rec.validated_configuration.validated)          # M3A only: outside the validated config
        self.assertTrue(any("eBPF" in r for r in rec.validated_configuration.reasons))
        self.assertTrue(verify_run_dir(run)["ok"])
        for source in ("ticks", "snapshot"):
            self.assertEqual(replay_run_dir(run, source).status, "MATCH", source)

    def test_snapshot_equals_the_collectors_own_build(self):
        rec, rep, run, _ = live(self.store, world(MEMORY))
        acq = json.loads(Path(run, "acquisition.json").read_bytes())
        from sentinelai.runtime.ticks import decode_ticks
        from sentinelai.diagnostic.contract import Target
        ticks = decode_ticks(Path(run, "ticks.jsonl").read_bytes())
        target = Target.model_validate_json(json.dumps(acq["target"]), strict=False)
        snap = snapshot_from_ticks(ticks, target, registry.get(registry.DEFAULT_PARAMETER_SET_ID), 1.0, False)
        self.assertEqual(Path(run, "snapshot.json").read_bytes(), canonical_bytes(snap))
        self.assertIsNone(json.loads(Path(run, "snapshot.json").read_bytes()).get("incident_id"))

    def test_partial_acquisition_keeps_every_bad_state(self):
        w = world(MEMORY)
        w.override(f"{CG}/memory.pressure", range(3, 6), Bad(Status.DENIED, "denied"))     # denied
        w.override("/proc/vmstat", [12], "garbage")                                          # malformed
        w.override("/proc/meminfo", [14], Bad(Status.ABSENT, "gone"))                        # missing
        w.override(f"{CG}/memory.current", [8, 9], Bad(Status.DENIED, "nested"))             # nested in cg.memory
        w.override(f"{CG}/memory.max", range(NB, N), Bad(Status.ABSENT, "gone in W"))        # gauge -> stale (W gauges: ticks NB..N-2)
        rec, rep, run, status = live(self.store, w)
        self.assertEqual(status, "PARTIAL")
        acq = json.loads(Path(run, "acquisition.json").read_bytes())
        self.assertEqual(acq["status"], "PARTIAL")
        self.assertEqual(acq["bad_counts"]["cg.memory.pressure"], {"denied": 3})
        self.assertIn("malformed", acq["bad_counts"]["proc.vmstat"])
        self.assertIn("absent", acq["bad_counts"]["proc.meminfo"])
        self.assertEqual(acq["bad_counts"]["cg.memory"]["denied"], 2)
        snap = EvidenceSnapshot.model_validate_json(Path(run, "snapshot.json").read_bytes(), strict=False)
        qualities = {m.quality for m in snap.measurements}
        self.assertIn(Quality.STALE, qualities)
        self.assertTrue(qualities & {Quality.PARTIAL, Quality.MISSING, Quality.INVALID})
        for m in snap.measurements:                                    # never a fabricated zero
            if m.quality in (Quality.MISSING, Quality.INVALID):
                self.assertIsNone(m.value, m.feature_id)
        self.assertEqual(replay_run_dir(run, "ticks").status, "MATCH")

    def test_abstention_is_a_diagnosis_not_a_failure(self):
        rec, rep, run, status = live(self.store, World())
        self.assertEqual((status, rep.decision, rep.abstained), ("COMPLETE", "INSUFFICIENT_EVIDENCE", True))
        self.assertTrue(verify_run(run)["complete"])

    def test_deterministic_given_identical_inputs(self):
        a = live(self.store, world(MEMORY), incident="det-a")
        b = live(self.store, world(MEMORY), incident="det-b")
        self.assertEqual(a[0].diagnosis_id, b[0].diagnosis_id)
        for f in ("ticks.jsonl", "snapshot.json", "diagnosis.json", "parameter_set.json"):
            self.assertEqual(Path(a[2], f).read_bytes(), Path(b[2], f).read_bytes(), f)
        acq_a, acq_b = (json.loads(Path(r[2], "acquisition.json").read_bytes()) for r in (a, b))
        for k in ("collection",):
            acq_a.pop(k), acq_b.pop(k)                                 # observational timing/rusage only
        self.assertEqual(acq_a, acq_b)


class TestFailed(StoreCase):
    def assertFailed(self, stage, **kw):
        with self.assertRaises(AcquisitionFailed) as cm:
            live(self.store, kw.pop("w", None), **kw)
        e = cm.exception
        self.assertEqual(e.stage, stage, e.reason)
        run = e.run_dir
        self.assertTrue(run.startswith(os.path.realpath(self.root) + os.sep))
        self.assertEqual(sorted(os.listdir(run)), ["acquisition.json", "context.json", "events.jsonl"])
        v = verify_run(run)
        self.assertEqual((v["complete"], v["ok"]), (False, False))       # incomplete: no manifest
        acq = json.loads(Path(run, "acquisition.json").read_bytes())
        self.assertEqual((acq["status"], acq["stage"], acq["format"]),
                         ("FAILED", stage, "sentinelai.acquisition-failure.v1"))
        kinds = [json.loads(l)["kind"] for l in Path(run, "events.jsonl").read_text().splitlines()]
        self.assertEqual(kinds, ["acquisition_started", "acquisition_failed"])
        for f in ("snapshot.json", "diagnosis.json", "ticks.jsonl"):
            self.assertFalse(os.path.exists(os.path.join(run, f)), f)   # no snapshot, no diagnosis
        return acq

    def test_missing_cgroup(self):
        acq = self.assertFailed("target", procs=Bad(Status.ABSENT, "no such cgroup"))
        self.assertIsNone(acq["target"])

    def test_denied_cgroup(self):
        self.assertFailed("target", procs=Bad(Status.DENIED, "permission denied"))

    def test_empty_or_malformed_cgroup(self):
        self.assertFailed("target", procs="")
        self.assertFailed("target", procs="12x\n", incident="live-2")      # same event clock: new incident

    def test_reader_failure_during_collection(self):
        acq = self.assertFailed("collect", raise_at=5)
        self.assertEqual(acq["target"]["pids"], [100])

    def test_no_usable_evidence(self):
        class Dead(StepReader):
            def read(self, p):
                if p in (f"{CG}/cgroup.procs", f"{CG}/cpuset.cpus.effective"):
                    return super().read(p)
                return Bad(Status.DENIED, "everything denied")

            def listdir(self, p):
                return Bad(Status.DENIED, "denied")

            def readlink(self, p):
                return Bad(Status.DENIED, "denied")
        c = clock()
        with self.assertRaises(AcquisitionFailed) as cm:
            run_live(ctx(), self.store, code_commit=COMMIT, reader=Dead(World(), c), clock=c, event_clock=event_clock())
        self.assertEqual(cm.exception.stage, "evidence")
        acq = json.loads(Path(cm.exception.run_dir, "acquisition.json").read_bytes())
        self.assertEqual(acq["ticks"], N)
        self.assertGreater(sum(sum(v.values()) for v in acq["bad_counts"].values()), 0)

    def test_snapshot_build_failure(self):
        from sentinelai.runtime import live as L
        with mock.patch.object(L, "snapshot_from_ticks", side_effect=CollectorError("injected build failure")):
            acq = self.assertFailed("snapshot")
        self.assertEqual(acq["ticks"], N)
        self.assertIn("injected build failure", acq["reason"])

    def test_failed_run_is_not_replayable(self):
        with self.assertRaises(AcquisitionFailed) as cm:
            live(self.store, procs=Bad(Status.ABSENT, "x"))
        from sentinelai.runtime.replay import ReplayRefused
        for source in ("snapshot", "ticks"):
            with self.assertRaises(ReplayRefused) as r:
                replay_run_dir(cm.exception.run_dir, source)
            self.assertEqual(r.exception.exit_code, 7)


class TestRefusedBeforeReading(StoreCase):
    def test_ebpf_required_and_interfaces_refused(self):
        for c in (ctx(ebpf="required"), ctx(ifaces=("eth0",))):
            reader = StepReader(World(), clock())
            with self.assertRaises(LiveRefused):
                run_live(c, self.store, code_commit=COMMIT, reader=reader, clock=clock())
            self.assertEqual(reader.calls, 0)
        self.assertEqual(os.listdir(self.root), [])

    def test_unsafe_targets_rejected_by_contract(self):
        from pydantic import ValidationError
        for bad in ("relative", "/a/../b", "/a/./b", "/a\x00b"):
            with self.assertRaises(ValidationError, msg=bad):
                ctx(cgroup=bad)

    def test_no_command_reader_refuses_tc(self):
        r = NoCommandReader(StepReader(World(), clock()))
        self.assertEqual(r.tc_qdisc("eth0").status, Status.REFUSED)
        self.assertEqual(r.refused_commands, 1)

    def test_acquire_uses_no_command_reader(self):
        c = clock()
        got = acquire(ctx(), registry.get(registry.DEFAULT_PARAMETER_SET_ID), reader=StepReader(World(), c), clock=c)
        self.assertEqual(len(got.ticks), N)
        self.assertNotIn("tc.eth0", got.ticks[0].obs)


class TestNoHostSideEffects(StoreCase):
    def test_no_subprocess_signal_or_writes_outside_root(self):
        sibling = tempfile.mkdtemp()
        try:
            before = fingerprint(sibling)
            forbid = lambda *a, **k: (_ for _ in ()).throw(AssertionError(f"forbidden call {a[:1]}"))
            with mock.patch.object(subprocess, "Popen", forbid), mock.patch.object(subprocess, "run", forbid), \
                    mock.patch.object(os, "kill", forbid), mock.patch.object(os, "system", forbid):
                rec, rep, run, status = live(self.store, world(MEMORY))
            self.assertEqual(status, "COMPLETE")
            self.assertEqual(fingerprint(sibling), before)
            self.assertEqual(os.listdir(self.root), ["live-1"])
        finally:
            os.rmdir(sibling)

    def test_existing_run_never_overwritten(self):
        c1 = clock()
        args = dict(code_commit=COMMIT, event_clock=lambda: (datetime(2026, 1, 1, tzinfo=timezone.utc), 1.0))
        rec, rep, run, _ = run_live(ctx(), self.store, reader=StepReader(World(), c1), clock=c1, **args)
        before = fingerprint(run)
        c2 = clock()
        from sentinelai.runtime.store import StoreError
        with self.assertRaises(StoreError):
            run_live(ctx(), self.store, reader=StepReader(World(), c2), clock=c2, **args)
        self.assertEqual(fingerprint(run), before)

    def test_collection_block_must_agree_with_stream(self):
        from runtime.test_replay import forge
        from sentinelai.runtime.replay import ReplayRefused
        rec, rep, run, _ = live(self.store, world(MEMORY))
        acq = json.loads(Path(run, "acquisition.json").read_bytes())
        acq["collection"]["ticks"] = N - 1
        forge(run, "acquisition.json", canonical_bytes(acq))
        with self.assertRaises(ReplayRefused) as cm:
            replay_run_dir(run, "ticks")
        self.assertEqual((cm.exception.category, cm.exception.exit_code), ("RECORD_INVALID", 8))

    def test_replay_does_not_mutate_live_run(self):
        rec, rep, run, _ = live(self.store, world(MEMORY))
        before = fingerprint(self.root)
        for source in ("ticks", "snapshot"):
            replay_run_dir(run, source)
        verify_run_dir(run)
        self.assertEqual(fingerprint(self.root), before)


class TestCli(StoreCase):
    def run_cli(self, *extra, w=None, base=True, **reader_kw):
        c = clock()
        args = ["diagnose", "--incident-id", "cli-1", "--target-name", TARGET.name, "--cgroup", TARGET.cgroup_path,
                "--out", self.root, "--code-commit", COMMIT] if base else []
        out, err = io.StringIO(), io.StringIO()
        code = main(args + list(extra), out=out, err=err, reader=StepReader(w or World(), c, **reader_kw), clock=c,
                    event_clock=event_clock())
        return code, json.loads(out.getvalue()), err.getvalue()

    def test_complete_partial_and_failed_exit_codes(self):
        code, out, err = self.run_cli("--ebpf", "disabled", w=world(MEMORY))
        self.assertEqual((code, out["acquisition"]["status"], out["decision"]), (0, "COMPLETE", "memory_pressure"))
        self.assertIn("live read-only M3A acquisition", err)
        self.assertNotIn("live read-only", json.dumps(out))                     # diagnostics only on stderr
        self.assertFalse(out["validated_configuration"]["validated"])
        w = world(MEMORY)
        w.override(f"{CG}/memory.pressure", range(3, 6), Bad(Status.DENIED, "x"))
        code, out, _ = self.run_cli("--ebpf", "disabled", w=w)
        self.assertEqual((code, out["acquisition"]["status"]), (11, "PARTIAL"))
        code, out, _ = self.run_cli("--ebpf", "disabled", procs=Bad(Status.ABSENT, "x"))
        self.assertEqual((code, out["acquisition"]["status"], out["acquisition"]["stage"]), (3, "FAILED", "target"))
        self.assertNotIn("decision", out)

    def test_abstention_exit_zero(self):
        code, out, _ = self.run_cli("--ebpf", "disabled")
        self.assertEqual((code, out["decision"], out["abstained"]), (0, "INSUFFICIENT_EVIDENCE", True))

    def test_refusals_before_any_read(self):
        cases = [
            (["--ebpf", "required"], "eBPF"),
            ([], "eBPF"),                                                         # Q1 default: required -> refused
            (["--ebpf", "disabled", "--iface", "eth0"], "command-backed"),
            (["--ebpf", "disabled", "--parameter-set", "r2b-validation-uncalibrated"], "context"),
        ]
        for extra, word in cases:
            with self.subTest(extra=extra):
                code, out, _ = self.run_cli(*extra)
                self.assertEqual((code, out["refused"]), (2, "USAGE"))
                self.assertIn(word, out["detail"])
        for flag, value in (("--incident-id", "../escape"), ("--cgroup", "relative/cg"), ("--cgroup", "/a/../b"),
                            ("--out", "relative/out"), ("--out", "/nonexistent/sentinel-out"),
                            ("--code-commit", "HEAD"), ("--target-name", "")):
            with self.subTest(flag=flag, value=value):
                c = clock()
                reader = StepReader(World(), c)
                args = {"--incident-id": "cli-1", "--target-name": TARGET.name, "--cgroup": TARGET.cgroup_path,
                        "--out": self.root, "--code-commit": COMMIT, flag: value}
                argv = ["diagnose", "--ebpf", "disabled"] + [x for kv in args.items() for x in kv]
                out = io.StringIO()
                code = main(argv, out=out, err=io.StringIO(), reader=reader, clock=c)
                got = json.loads(out.getvalue())
                self.assertEqual((code, got["refused"]), (2, "USAGE"))
                if flag == "--out" and value.startswith("relative"):
                    self.assertEqual(got["detail"], "--out must be an absolute path: 'relative/out'")
                self.assertEqual(reader.calls, 0)
        self.assertEqual(os.listdir(self.root), [])

    def test_existing_run_exit_12(self):
        fixed = lambda: (datetime(2026, 1, 1, tzinfo=timezone.utc), 1.0)
        for expected in (0, 12):
            c = clock()
            out = io.StringIO()
            code = main(["diagnose", "--incident-id", "cli-1", "--target-name", TARGET.name, "--cgroup",
                         TARGET.cgroup_path, "--out", self.root, "--code-commit", COMMIT, "--ebpf", "disabled"],
                        out=out, err=io.StringIO(), reader=StepReader(world(MEMORY), c), clock=c, event_clock=fixed)
            self.assertEqual(code, expected)
        self.assertEqual(json.loads(out.getvalue())["refused"], "OUTPUT_REFUSED")

    def test_cli_runs_replay(self):
        code, out, _ = self.run_cli("--ebpf", "disabled", w=world(MEMORY))
        buf = io.StringIO()
        self.assertEqual(main(["replay", "--run-dir", out["run_dir"], "--source", "ticks"], out=buf), 0)
        self.assertEqual(json.loads(buf.getvalue())["status"], "MATCH")


if __name__ == "__main__":
    unittest.main()
