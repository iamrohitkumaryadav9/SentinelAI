"""Phase 2A.3: raw-tick replay (ticks.jsonl + acquisition.json -> build_snapshot == snapshot.json -> M2 == diagnosis.json).

Corpus: no committed run contains ticks.jsonl (the FaultLab drivers never persisted M3A ticks), so historical tick
coverage is NOT claimed; any committed tick run that appears later is replayed by test_committed_tick_runs.
Coverage instead: (1) synthetic M3A-only runs (fault-free, injected faults, and worlds that M2 diagnoses as
memory_pressure / network_packet_loss / tcp_retransmissions); (2) hybrid runs: the synthetic M3A world plus every
committed eBPF loader stream (raw_*.jsonl) whose sample count matches the registered window — real M3B data
through the full encode -> persist -> decode -> rebuild path. No make, no replay binary, no live collection.
"""

import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from collectors._world import TARGET, World
from sentinelai.collectors.ebpf import EbpfTarget, FixtureEbpfSource
from sentinelai.collectors.errors import Bad, Status
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.runtime import ArtifactStore, IncidentContext, TargetSpec, registry
from sentinelai.runtime.acquisition import AcquisitionInvalid, bad_counts
from sentinelai.runtime.pipeline import run_from_ticks, run_pure, snapshot_from_ticks
from sentinelai.runtime.replay import ReplayRefused, replay_run_dir, verify_run_dir
from sentinelai.runtime.ticks import decode_ticks, encode_ticks

from runtime.test_replay import cli, fingerprint, forge

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "0bb1fc6"
IN_GIT = (ROOT / ".git").exists()
SCENARIOS = {
    "baseline": ({}, "INSUFFICIENT_EVIDENCE"),
    "memory": ({"cg.pgscan": 50_000, "cg.refault_file": 40_000, "cg.pgmajfault": 40_000, "cg.mem.some": 300_000,
                "cg.mem.full": 200_000, "cg.events.high": 500}, "memory_pressure"),
    "loss": ({"tc.drops": 500}, "network_packet_loss"),
    "retrans": ({"Tcp.RetransSegs": 100}, "tcp_retransmissions"),
}


def ctx_for(ebpf: bool, incident="raw"):
    return IncidentContext(incident_id=incident, ebpf="required" if ebpf else "disabled",
                           target=TargetSpec(name=TARGET.name, cgroup_path=TARGET.cgroup_path, ifaces=TARGET.ifaces))


def world_ticks(rates=None, faults=False):
    w = World()
    w.window_rates.update(rates or {})
    if faults:
        w.override(f"/sys/fs/cgroup{TARGET.cgroup_path}/memory.pressure", range(3, 6), Bad(Status.DENIED, "x"))
        w.override("/proc/vmstat", [12], "garbage")
        w.override("/proc/meminfo", [14], Bad(Status.ABSENT, "gone"))
        w.cpu_ticks[1] = {7, 15}
        w.override(f"/sys/fs/cgroup{TARGET.cgroup_path}/memory.current", [8, 9], Bad(Status.DENIED, "nested"))
    return w.ticks(TARGET)


def ebpf_streams():
    """Committed eBPF loader streams: (path, lines) usable with the 21-tick window, and exclusions with reasons."""
    use, excluded = [], []
    n_ticks = 21
    for p in sorted((ROOT / "results").rglob("raw_*.jsonl")):
        lines = [l for l in p.read_text().splitlines() if l.strip()]
        samples = sum(json.loads(l).get("type") == "sample" for l in lines)
        meta = json.loads(lines[0])
        if meta.get("type") != "meta" or meta.get("producer") != "sentinel_loader":
            excluded.append((p, "not a sentinel_loader stream"))
        elif samples != n_ticks:
            excluded.append((p, f"{samples} samples != {n_ticks} ticks of the registered window"))
        else:
            use.append((p, lines))
    return use, excluded


def hybrid_ticks(lines):
    cfg = json.loads(lines[0])["cfg"]
    src = FixtureEbpfSource(lines, EbpfTarget(cfg["cgroup_id"], cfg["cgroup_level"], cfg["netns_inum"]))
    ticks = World().ticks(TARGET)
    for t in ticks:
        t.obs.update(src.sample())
    return ticks


def retick(run, mutate):
    """Decode ticks.jsonl, apply mutate(ticks), re-encode, and forge ticks.jsonl + acquisition.json + manifest so that
    integrity and the acquisition binding pass: only reconstruction can notice."""
    ticks = decode_ticks(Path(run, "ticks.jsonl").read_bytes())
    ticks = mutate(ticks) or ticks
    data = encode_ticks(ticks)
    acq = json.loads(Path(run, "acquisition.json").read_bytes())
    import hashlib
    counts = bad_counts(ticks)
    acq["ticks"].update(sha256=hashlib.sha256(data).hexdigest(), count=len(ticks))
    acq["bad_counts"], acq["status"] = counts, ("PARTIAL" if counts else "COMPLETE")
    forge(run, "ticks.jsonl", data)
    forge(run, "acquisition.json", canonical_bytes(acq))


def forge_lines(run, text: bytes, count=None):
    import hashlib
    acq = json.loads(Path(run, "acquisition.json").read_bytes())
    acq["ticks"]["sha256"] = hashlib.sha256(text).hexdigest()
    if count is not None:
        acq["ticks"]["count"] = count
    forge(run, "ticks.jsonl", text)
    forge(run, "acquisition.json", canonical_bytes(acq))


class TickRun(unittest.TestCase):
    rates, faults, ebpf_lines = {}, False, None

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = self._t.name
        ebpf = self.ebpf_lines is not None
        self.ticks = hybrid_ticks(self.ebpf_lines) if ebpf else world_ticks(self.rates, self.faults)
        self.rec, self.report, self.run = run_from_ticks(ctx_for(ebpf), self.ticks, TARGET, ArtifactStore(self.root),
                                                         ebpf=ebpf, code_commit=COMMIT)

    def tearDown(self):
        self._t.cleanup()

    def assertRefused(self, category, exit_code, source="ticks"):
        before = fingerprint(self.root)
        with self.assertRaises(ReplayRefused) as cm:
            replay_run_dir(self.run, source)
        self.assertEqual((cm.exception.category, cm.exception.exit_code), (category, exit_code), cm.exception.detail)
        code, out = cli("replay", "--run-dir", self.run, "--source", source)
        self.assertEqual((code, out.get("refused")), (exit_code, category))
        self.assertNotIn("status", out)
        self.assertEqual(fingerprint(self.root), before)
        return cm.exception


class TestSyntheticReconstruction(unittest.TestCase):
    def test_scenarios_rebuild_byte_identically(self):
        p = registry.get(registry.DEFAULT_PARAMETER_SET_ID)
        for name, (rates, decision) in SCENARIOS.items():
            for faults in (False, True):
                with self.subTest(scenario=name, faults=faults), tempfile.TemporaryDirectory() as t:
                    ticks = world_ticks(rates, faults)
                    rec, rep, run = run_from_ticks(ctx_for(False), ticks, TARGET, ArtifactStore(t), ebpf=False,
                                                   code_commit=COMMIT)
                    self.assertEqual(sorted(os.listdir(run)), ["acquisition.json", "context.json", "diagnosis.json",
                                                               "events.jsonl", "manifest.json", "parameter_set.json",
                                                               "snapshot.json", "ticks.jsonl"])
                    self.assertEqual(Path(run, "snapshot.json").read_bytes(),
                                     canonical_bytes(snapshot_from_ticks(ticks, TARGET, p, 1.0, False)))
                    acq = json.loads(Path(run, "acquisition.json").read_bytes())
                    self.assertEqual(acq["status"], "PARTIAL" if faults else "COMPLETE")
                    if faults:
                        self.assertEqual(acq["bad_counts"]["cg.memory.pressure"], {"denied": 3})
                        self.assertIn("malformed", acq["bad_counts"]["proc.vmstat"])
                        self.assertIn("absent", acq["bad_counts"]["proc.meminfo"])
                        self.assertEqual(acq["bad_counts"]["cg.memory"], {"denied": 2})     # nested inside a source
                    else:
                        self.assertEqual(rep.decision, decision)
                    before = fingerprint(t)
                    r = replay_run_dir(run, "ticks")
                    self.assertEqual((r.status, r.source, r.mismatch_stage), ("MATCH", "ticks", None))
                    self.assertTrue(r.checks["snapshot_byte_identical"] and all(r.checks.values()))
                    self.assertEqual(r.recomputed["decision"], rec.result.decision.value)
                    self.assertEqual(replay_run_dir(run, "snapshot").status, "MATCH")
                    self.assertTrue(verify_run_dir(run)["ok"])
                    self.assertEqual(fingerprint(t), before)

    def test_tick_runs_are_deterministic(self):
        outs = []
        for incident, start in (("a", datetime(2026, 1, 1, tzinfo=timezone.utc)),
                                ("b", datetime(2030, 7, 7, tzinfo=timezone.utc))):
            clock = (lambda s: (lambda: (s, 1.0)))(start)
            with tempfile.TemporaryDirectory() as t:
                rec, _, run = run_from_ticks(ctx_for(False, incident), world_ticks(SCENARIOS["memory"][0]), TARGET,
                                             ArtifactStore(t), ebpf=False, code_commit=COMMIT, clock=clock)
                outs.append({f: Path(run, f).read_bytes() for f in ("ticks.jsonl", "acquisition.json",
                                                                     "snapshot.json", "diagnosis.json",
                                                                     "parameter_set.json")})
                a = cli("replay", "--run-dir", run, "--source", "ticks")
                b = cli("replay", "--run-dir", run, "--source", "ticks")
                self.assertEqual(a, b)
                self.assertEqual(a[0], 0)
        self.assertEqual(outs[0], outs[1])


class TestHybridEbpfStreams(unittest.TestCase):
    def test_every_matching_committed_ebpf_stream(self):
        use, excluded = ebpf_streams()
        self.assertTrue(use)
        for p, why in excluded:
            self.assertIn("samples", why, p)
        with tempfile.TemporaryDirectory() as t:
            store = ArtifactStore(t)
            for i, (p, lines) in enumerate(use):
                with self.subTest(stream=str(p.relative_to(ROOT))):
                    rec, rep, run = run_from_ticks(ctx_for(True, f"h{i}"), hybrid_ticks(lines), TARGET, store,
                                                   ebpf=True, code_commit=COMMIT)
                    acq = json.loads(Path(run, "acquisition.json").read_bytes())
                    self.assertEqual((acq["ebpf"], acq["collector_versions"]), (True, ["m3a-1.1.0", "m3b-1.0.0"]))
                    self.assertTrue(rec.validated_configuration.validated)
                    r = replay_run_dir(run, "ticks")
                    self.assertEqual(r.status, "MATCH")
                    self.assertTrue(all(r.checks.values()))


class TestCommittedTickRuns(unittest.TestCase):
    def test_committed_tick_runs(self):
        """Replays every committed run that carries ticks.jsonl (there are none at 2A.3; nothing is claimed)."""
        found = sorted(p.parent for p in (ROOT / "results").rglob("ticks.jsonl"))
        if IN_GIT:
            tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "*ticks.jsonl"], capture_output=True,
                                     text=True, check=True).stdout.split()
            self.assertEqual(sorted(ROOT / Path(t).parent for t in tracked), found)
        for run in found:
            self.assertEqual(replay_run_dir(str(run), "ticks").status, "MATCH", run)


class TestValidRun(TickRun):
    def test_abstention_is_a_valid_diagnosis(self):
        code, out = cli("replay", "--run-dir", self.run, "--source", "ticks")
        self.assertEqual((code, out["status"], out["stored"]["decision"]), (0, "MATCH", "INSUFFICIENT_EVIDENCE"))

    def test_default_source_is_snapshot(self):
        code, out = cli("replay", "--run-dir", self.run)
        self.assertEqual((code, out["source"]), (0, "snapshot"))
        self.assertNotIn("snapshot_byte_identical", out["checks"])

    def test_bad_source(self):
        import contextlib, io
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
            cli("replay", "--run-dir", self.run, "--source", "raw")
        self.assertEqual(cm.exception.code, 2)
        with self.assertRaises(ReplayRefused) as cm:
            replay_run_dir(self.run, "raw")
        self.assertEqual(cm.exception.exit_code, 2)

    def test_snapshot_only_run_has_no_tick_source(self):
        with tempfile.TemporaryDirectory() as t:
            p = registry.get(registry.DEFAULT_PARAMETER_SET_ID)
            _, _, run = run_pure(ctx_for(False), snapshot_from_ticks(self.ticks, TARGET, p, 1.0, False),
                                 ArtifactStore(t), code_commit=COMMIT)
            with self.assertRaises(ReplayRefused) as cm:
                replay_run_dir(run, "ticks")
            self.assertEqual((cm.exception.category, cm.exception.exit_code), ("RUN_INVALID", 7))
            self.assertRegex(cm.exception.detail, r"^(acquisition\.json|ticks\.jsonl) absent: required for --source ticks")


class TestMissingAndTamperedArtifacts(TickRun):
    def test_missing_tick_artifacts(self):
        for name in ("ticks.jsonl", "acquisition.json"):
            with self.subTest(name=name):
                self.tearDown()
                self.setUp()
                os.remove(os.path.join(self.run, name))
                self.assertFalse(verify_run_dir(self.run)["ok"])
                self.assertRefused("RUN_INVALID", 7)

    def test_corrupted_ticks_without_manifest_update(self):
        p = os.path.join(self.run, "ticks.jsonl")
        os.chmod(p, 0o644)
        Path(p).write_bytes(Path(p).read_bytes().replace(b'"index":3', b'"index":4', 1))
        self.assertRefused("RUN_INVALID", 7)

    def test_ticks_not_the_stream_acquisition_describes(self):
        data = Path(self.run, "ticks.jsonl").read_bytes()
        forge(self.run, "ticks.jsonl", data.replace(b'"index":3', b'"index":4', 1))     # manifest only
        self.assertTrue(verify_run_dir(self.run)["ok"])
        self.assertRefused("RUN_INVALID", 7)

    def test_acquisition_record_invalid(self):
        acq = json.loads(Path(self.run, "acquisition.json").read_bytes())
        cases = [("not json", b"{"), ("non-canonical", json.dumps(acq, indent=1).encode()),
                 ("extra field", canonical_bytes({**acq, "note": "x"})),
                 ("ebpf contradicts context", canonical_bytes({**acq, "ebpf": True})),
                 ("target mismatch", canonical_bytes({**acq, "target": {**acq["target"], "name": "other"}})),
                 ("period mismatch", canonical_bytes({**acq, "period_s": 2.0})),
                 ("unknown status", canonical_bytes({**acq, "status": "FAILED"}))]
        for name, data in cases:
            with self.subTest(case=name):
                forge(self.run, "acquisition.json", data)
                self.assertRefused("RECORD_INVALID", 8)

    def test_collector_version_not_substituted(self):
        acq = json.loads(Path(self.run, "acquisition.json").read_bytes())
        forge(self.run, "acquisition.json", canonical_bytes({**acq, "collector_versions": ["m3a-0.9.0"]}))
        self.assertRefused("PARAMETERS_REFUSED", 5)

    def test_persisted_snapshot_invalid(self):
        forge(self.run, "snapshot.json", b"{broken")
        self.assertRefused("SNAPSHOT_INVALID", 4)


class TestMalformedTickStream(TickRun):
    def lines(self):
        return Path(self.run, "ticks.jsonl").read_bytes().decode().splitlines()

    def test_malformed_streams(self):
        ls = self.lines()
        n = len(ls)
        obj = json.loads(ls[3])
        cases = {
            "not json": ("\n".join(ls[:3] + ["{nope"] + ls[4:]) + "\n", n),
            "truncated (no newline)": ("\n".join(ls), n),
            "missing field": ("\n".join(ls[:3] + [json.dumps({k: v for k, v in obj.items() if k != "mono"},
                                                             sort_keys=True, separators=(",", ":"))] + ls[4:]) + "\n", n),
            "duplicate field": ("\n".join(ls[:3] + [ls[3].replace('"index":3', '"index":3,"index":3', 1)] + ls[4:]) + "\n", n),
            "unknown tag": ("\n".join(ls[:3] + [ls[3].replace('{"f":', '{"zz":', 1)] + ls[4:]) + "\n", n),
            "out of sequence": ("\n".join(ls[:3] + [ls[4], ls[3]] + ls[5:]) + "\n", n),
            "wrong format tag": ("\n".join(ls[:3] + [ls[3].replace("sentinelai.ticks.v1", "sentinelai.ticks.v0")] + ls[4:]) + "\n", n),
            "count disagrees": ("\n".join(ls) + "\n", n + 1),
            "not utf-8": (None, n),
        }
        for name, (text, count) in cases.items():
            with self.subTest(case=name):
                self.tearDown()
                self.setUp()
                data = b"\xff\xfe" + Path(self.run, "ticks.jsonl").read_bytes() if text is None else text.encode()
                forge_lines(self.run, data, count)
                self.assertRefused("TICKS_INVALID", 9)

    def test_bad_counts_must_match_stream(self):
        ticks = decode_ticks(Path(self.run, "ticks.jsonl").read_bytes())
        ticks[5].obs["proc.meminfo"] = Bad(Status.DENIED, "injected")
        forge_lines(self.run, encode_ticks(ticks))
        self.assertRefused("TICKS_INVALID", 9)

    def test_invalid_tick_values_fail_reconstruction(self):
        def bad_value(ticks):
            ticks[4].obs["proc.stat"]["all.busy"] = "not a number"
        retick(self.run, bad_value)
        self.assertRefused("RECONSTRUCTION_INVALID", 10)

    def test_wrong_tick_count_fails_reconstruction(self):
        retick(self.run, lambda ticks: ticks[:-1])
        self.assertRefused("RECONSTRUCTION_INVALID", 10)


class TestEvidenceTampering(TickRun):
    rates = SCENARIOS["memory"][0]

    def test_valid_json_tampering_changes_evidence(self):
        self.assertEqual(self.report.decision, "memory_pressure")

        def no_pressure(ticks):                    # flatten W: every pressure counter frozen at its tick-10 value
            src = ticks[10].obs
            for t in ticks[11:]:
                for key in ("cg.memory.stat", "cg.memory.pressure", "cg.memory.events"):
                    t.obs[key] = json.loads(json.dumps(src[key])) if not isinstance(src[key], Bad) else src[key]
        retick(self.run, no_pressure)
        self.assertTrue(verify_run_dir(self.run)["ok"])
        before = fingerprint(self.root)
        r = replay_run_dir(self.run, "ticks")
        self.assertEqual((r.status, r.mismatch_stage), ("MISMATCH", "snapshot"))
        self.assertFalse(r.checks["snapshot_byte_identical"])
        self.assertTrue(r.first_difference.startswith("$."), r.first_difference)
        self.assertEqual((r.stored["decision"], r.recomputed["decision"]), ("memory_pressure", "INSUFFICIENT_EVIDENCE"))
        self.assertEqual(cli("replay", "--run-dir", self.run, "--source", "ticks")[0], 6)
        self.assertEqual(replay_run_dir(self.run, "snapshot").status, "MATCH")     # snapshot path cannot see it
        self.assertEqual(fingerprint(self.root), before)

    def test_single_counter_change_located(self):
        def bump(ticks):          # last tick: the W total changes (an interior bump cancels between two intervals)
            ticks[-1].obs["cg.memory.stat"]["pgscan"] += 1.0
        retick(self.run, bump)
        r = replay_run_dir(self.run, "ticks")
        self.assertEqual((r.status, r.mismatch_stage), ("MISMATCH", "snapshot"))
        self.assertTrue(r.first_difference.startswith("$.measurements") or r.first_difference.startswith("$.snapshot_id"),
                        r.first_difference)

    def test_interior_bump_that_cancels_is_not_a_difference(self):
        def bump(ticks):
            ticks[15].obs["cg.memory.stat"]["pgscan"] += 1.0
        retick(self.run, bump)
        self.assertEqual(replay_run_dir(self.run, "ticks").status, "MATCH")   # same evidence, honestly reported

    def test_persisted_snapshot_replaced(self):
        other = snapshot_from_ticks(world_ticks(), TARGET, registry.get(registry.DEFAULT_PARAMETER_SET_ID), 1.0, False)
        forge(self.run, "snapshot.json", canonical_bytes(other))
        r = replay_run_dir(self.run, "ticks")
        self.assertEqual((r.status, r.mismatch_stage), ("MISMATCH", "snapshot"))
        s = replay_run_dir(self.run, "snapshot")
        self.assertEqual((s.status, s.mismatch_stage), ("MISMATCH", "diagnosis"))


class TestRunFromTicksGuards(unittest.TestCase):
    def test_refusals_write_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            store, ticks = ArtifactStore(t), world_ticks()
            other = TARGET.model_copy(update={"name": "other"})
            for kw in (dict(target=other, ebpf=False), dict(target=TARGET, ebpf=True), dict(target=TARGET, ebpf=1),
                       dict(target={"name": "lab"}, ebpf=False)):
                with self.assertRaises(AcquisitionInvalid, msg=kw):
                    run_from_ticks(ctx_for(False), ticks, kw["target"], store, ebpf=kw["ebpf"], code_commit=COMMIT)
            with self.assertRaises(Exception):
                run_from_ticks(ctx_for(False), ticks[:-1], TARGET, store, ebpf=False, code_commit=COMMIT)
            self.assertEqual(os.listdir(t), [])

    def test_unreplayable_stream_is_never_persisted(self):
        """Write-time self-check: if the encoded stream would not rebuild the identical snapshot, nothing is written."""
        from unittest import mock
        from sentinelai.runtime import pipeline

        def lossy(data):
            ticks = decode_ticks(data)
            ticks[-1].obs["cg.memory.stat"]["pgscan"] += 1.0
            return ticks
        with tempfile.TemporaryDirectory() as t, mock.patch.object(pipeline, "decode_ticks", lossy):
            with self.assertRaises(AcquisitionInvalid):
                run_from_ticks(ctx_for(False), world_ticks(), TARGET, ArtifactStore(t), ebpf=False, code_commit=COMMIT)
            self.assertEqual(os.listdir(t), [])


if __name__ == "__main__":
    unittest.main()
