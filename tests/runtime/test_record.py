"""Diagnosis identity, DiagnosisRecord, report, runtime events and the pure pipeline (R2-F snapshots as fixtures)."""

import inspect
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from pydantic import ValidationError

from collectors._world import World, TARGET, params as world_params
from sentinelai.collectors import build_snapshot
from sentinelai.diagnostic.contract import EvidenceKind, EvidenceSnapshot
from sentinelai.diagnostic.contract.serialize import canonical_bytes, canonical_json
from sentinelai.diagnostic.contract.version import CONTRACT_VERSION
from sentinelai.diagnostic.rules import RULES_VERSION, diagnose
from sentinelai.runtime import (ArtifactStore, EventLog, IncidentContext, SnapshotInvalid, SnapshotMutated,
                                TargetSpec, UnknownParameterSet, build_report, diagnose_snapshot, diagnosis_id,
                                registry, run_pure, verify_run)
from sentinelai.runtime import pipeline
from sentinelai.runtime.report import Report, sha256_bytes, validated_configuration

ROOT = Path(__file__).resolve().parents[2]
R2F = ROOT / "results" / "phase1c_r2f" / "20261004T100422Z"
COMMIT = "0bb1fc6"
PIN = "880d9af62f6e120c227cbc1abc50a8521d8cc62ff059c3bbd8f316dbd56807cb"


def raw(run):
    return (R2F / run / "snapshot.json").read_bytes()


def recorded_m2(run):
    return json.loads((R2F / run / "run.json").read_text())["m2"]


def clock_at(start):
    state = {"t": start, "m": 100.0}

    def tick():
        state["t"] += timedelta(milliseconds=7)
        state["m"] += 0.007
        return state["t"], state["m"]
    return tick


CTX = IncidentContext(incident_id="inc-a", target=TargetSpec(name="r2f", cgroup_path="/sentinel-r2f/target"))
KW = dict(input_snapshot_sha256="a" * 64, parameter_set_sha256="b" * 64, rules_version="m2-1.1.0",
          contract_version="0.5.0-draft")


class TestDiagnosisId(unittest.TestCase):
    def test_deterministic_hex16(self):
        a, b = diagnosis_id(**KW), diagnosis_id(**KW)
        self.assertEqual(a, b)
        self.assertRegex(a, r"^[0-9a-f]{16}$")

    def test_order_independent(self):
        rev = dict(reversed(list(KW.items())))
        self.assertEqual(diagnosis_id(**rev), diagnosis_id(**KW))
        import hashlib
        named = {"contract_version": KW["contract_version"], "kind": "diagnosis", **KW}
        self.assertEqual(diagnosis_id(**KW), hashlib.sha1(canonical_json(named).encode()).hexdigest()[:16])

    def test_every_field_matters(self):
        base = diagnosis_id(**KW)
        for k, v in (("input_snapshot_sha256", "c" * 64), ("parameter_set_sha256", "d" * 64),
                     ("rules_version", "m2-1.2.0"), ("contract_version", "0.6.0-draft")):
            self.assertNotEqual(diagnosis_id(**{**KW, k: v}), base, k)

    def test_identity_inputs_are_exactly_four(self):
        self.assertEqual(sorted(inspect.signature(diagnosis_id).parameters), sorted(KW))

    def test_clock_incident_and_commit_excluded(self):
        with tempfile.TemporaryDirectory() as t:
            store = ArtifactStore(t)
            r1, _, p1 = run_pure(CTX, raw("M1-1"), store, code_commit=COMMIT,
                                 clock=clock_at(datetime(2026, 1, 1, tzinfo=timezone.utc)))
            ctx2 = IncidentContext(incident_id="inc-b", target=CTX.target)
            r2, _, p2 = run_pure(ctx2, raw("M1-1"), store, code_commit="4aa23b8",
                                 clock=clock_at(datetime(2030, 6, 6, tzinfo=timezone.utc)))
            self.assertEqual(r1.diagnosis_id, r2.diagnosis_id)
            self.assertNotEqual(r1.result_sha256, r2.result_sha256)        # code_commit is in EngineInfo
            self.assertEqual((r1.code_commit, r2.code_commit), (COMMIT, "4aa23b8"))
            r3, _, p3 = run_pure(CTX, raw("M1-1"), store, code_commit=COMMIT,
                                 clock=clock_at(datetime(2031, 1, 1, tzinfo=timezone.utc)))
            for f in ("diagnosis.json", "snapshot.json", "parameter_set.json", "context.json"):
                self.assertEqual(Path(p1, f).read_bytes(), Path(p3, f).read_bytes(), f)
            self.assertNotEqual(Path(p1, "events.jsonl").read_bytes(), Path(p3, "events.jsonl").read_bytes())

    def test_different_snapshot_different_id(self):
        a, b = diagnose_snapshot(raw("M1-1"), code_commit=COMMIT)[0], diagnose_snapshot(raw("E0-open"), code_commit=COMMIT)[0]
        self.assertNotEqual(a.diagnosis_id, b.diagnosis_id)


class TestRecord(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = raw("M1-1")
        cls.rec, cls.snap, cls.bytes, cls.evaluated, cls.params = diagnose_snapshot(cls.raw, code_commit=COMMIT)

    def test_matches_direct_m2_and_recorded_r2f(self):
        direct = diagnose(EvidenceSnapshot.model_validate_json(self.raw, strict=False), registry.get(
            "r2c-validation-uncalibrated"), code_commit=COMMIT)
        self.assertEqual(canonical_bytes(self.rec.result), canonical_bytes(direct.result))
        self.assertEqual(canonical_bytes(self.evaluated), canonical_bytes(direct.snapshot))
        for run in ("M1-1", "E0-open"):
            r = diagnose_snapshot(raw(run), code_commit=COMMIT)[0].result
            m = recorded_m2(run)
            self.assertEqual((r.decision.value, r.confidence_level.value, [f.value for f in r.flags]),
                             (m["decision"], m["confidence"], m["flags"]), run)

    def test_identity_and_provenance_fields(self):
        r = self.rec
        self.assertEqual(r.snapshot_id, self.snap.snapshot_id)
        self.assertEqual(r.input_snapshot_sha256, sha256_bytes(self.raw))
        self.assertEqual((r.parameter_set_id, r.parameter_set_sha256), ("r2c-validation-uncalibrated", PIN))
        self.assertEqual((r.rules_version, r.contract_version, r.code_commit), (RULES_VERSION, CONTRACT_VERSION, COMMIT))
        self.assertEqual(r.result_sha256, sha256_bytes(canonical_bytes(r.result)))
        self.assertEqual(r.diagnosis_id, diagnosis_id(input_snapshot_sha256=r.input_snapshot_sha256,
                                                      parameter_set_sha256=PIN, rules_version=RULES_VERSION,
                                                      contract_version=CONTRACT_VERSION))
        self.assertEqual(self.evaluated.measurements, self.snap.measurements)    # provenance untouched

    def test_input_unchanged(self):
        self.assertEqual(self.bytes, self.raw)
        self.assertEqual(canonical_bytes(self.snap), self.raw)
        self.assertEqual(self.snap.evidence_items, ())

    def test_deterministic(self):
        again = diagnose_snapshot(self.raw, code_commit=COMMIT)[0]
        self.assertEqual(canonical_bytes(again), canonical_bytes(self.rec))

    def test_evidence_breakdown_partitions_m2_items(self):
        e = self.rec.evidence
        kinds = {"supporting": EvidenceKind.POSITIVE, "negative": EvidenceKind.NEGATIVE,
                 "missing": EvidenceKind.MISSING, "conflicting": EvidenceKind.CONFLICTING}
        total = 0
        for part, kind in kinds.items():
            refs = getattr(e, part)
            self.assertTrue(all(x.kind is kind for x in refs), part)
            total += len(refs)
        self.assertEqual(total, len(self.evaluated.evidence_items))
        self.assertEqual(e.missing_measurements, self.evaluated.missing_measurements)
        self.assertEqual(e.conflicts, self.evaluated.conflicts)
        self.assertIn("MP.R1", [x.predicate_id for x in e.supporting])
        self.assertEqual(self.rec.predicate_ids, tuple(sorted({i.predicate_id for i in self.evaluated.evidence_items})))

    def test_validated_configuration(self):
        self.assertTrue(self.rec.validated_configuration.validated)
        self.assertEqual(self.rec.validated_configuration.reasons, ())
        ws = build_snapshot(World().ticks(TARGET), TARGET, world_params())          # M3A only, test parameters
        v = validated_configuration(ws, ws.parameter_set_id)
        self.assertFalse(v.validated)
        self.assertTrue(any("eBPF" in x for x in v.reasons) and any("parameter set" in x for x in v.reasons))
        v = validated_configuration(self.snap, "r2c-validation-uncalibrated", rules_version="m2-9.9.9")
        self.assertFalse(v.validated)

    def test_record_is_strict_and_frozen(self):
        with self.assertRaises(ValidationError):
            self.rec.diagnosis_id = "0" * 16


class TestReport(unittest.TestCase):
    def test_report_exposes_record_only(self):
        rec = diagnose_snapshot(raw("M1-1"), code_commit=COMMIT)[0]
        rep = build_report(rec, "inc-a")
        self.assertEqual((rep.incident_id, rep.snapshot_id, rep.diagnosis_id), ("inc-a", rec.snapshot_id, rec.diagnosis_id))
        self.assertEqual((rep.decision, rep.confidence), (rec.result.decision.value, rec.result.confidence_level.value))
        self.assertEqual(rep.rules_fired, rec.result.rules_fired)
        self.assertEqual(rep.supporting, tuple(x.predicate_id for x in rec.evidence.supporting))
        self.assertEqual(rep.validated_configuration, rec.validated_configuration)
        self.assertEqual(rep.versions["code_commit"], COMMIT)
        self.assertEqual(canonical_bytes(rep), canonical_bytes(build_report(rec, "inc-a")))
        for word in ("explanation", "recommend", "remediat", "summary", "llm"):
            self.assertFalse([f for f in Report.model_fields if word in f], word)

    def test_abstention_reported(self):
        rep = build_report(diagnose_snapshot(raw("E0-open"), code_commit=COMMIT)[0], "inc-a")
        self.assertEqual((rep.decision, rep.abstained), ("INSUFFICIENT_EVIDENCE", True))
        self.assertIn("REQUIRED_EVIDENCE_MISSING", rep.abstention_reasons)


class TestEvents(unittest.TestCase):
    def test_append_only_and_sink(self):
        lines = []
        log = EventLog(clock_at(datetime(2026, 1, 1, tzinfo=timezone.utc)), sink=lines.append)
        a = log.emit("acquisition_started", incident_id="x")
        b = log.emit("snapshot_created", snapshot_id="s")
        self.assertEqual([e.seq for e in log.events], [0, 1])
        self.assertIsInstance(log.events, tuple)
        self.assertFalse([n for n in dir(log) if n in ("remove", "clear", "pop", "insert", "update", "replace")])
        with self.assertRaises(ValidationError):
            a.kind = "runtime_failure"
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])["kind"], b.kind)
        with self.assertRaises(ValidationError):
            log.emit("not_an_event")

    def test_events_do_not_affect_results(self):
        quiet = diagnose_snapshot(raw("M1-1"), code_commit=COMMIT)[0]
        noisy_log = EventLog(clock_at(datetime(2040, 1, 1, tzinfo=timezone.utc)))
        noisy = diagnose_snapshot(raw("M1-1"), code_commit=COMMIT, events=noisy_log, refs={"incident_id": "zz"})[0]
        self.assertEqual(canonical_bytes(quiet), canonical_bytes(noisy))
        self.assertEqual([e.kind for e in noisy_log.events],
                         ["snapshot_validated", "diagnosis_started", "diagnosis_completed"])


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.store = ArtifactStore(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def test_run_pure_artifacts(self):
        rec, rep, path = run_pure(CTX, raw("M1-1"), self.store, code_commit=COMMIT)
        self.assertEqual(sorted(os.listdir(path)), ["context.json", "diagnosis.json", "events.jsonl",
                                                    "manifest.json", "parameter_set.json", "snapshot.json"])
        self.assertEqual(verify_run(path)["ok"], True)
        self.assertEqual(Path(path, "snapshot.json").read_bytes(), raw("M1-1"))
        self.assertEqual(Path(path, "parameter_set.json").read_bytes(), canonical_bytes(registry.get(
            "r2c-validation-uncalibrated")))
        stored = json.loads(Path(path, "diagnosis.json").read_text())
        self.assertEqual(stored["record"]["diagnosis_id"], rec.diagnosis_id)
        self.assertEqual(rep.decision, "memory_pressure")
        self.assertIsNone(json.loads(Path(path, "snapshot.json").read_text()).get("incident_id"))
        kinds = [json.loads(l)["kind"] for l in Path(path, "events.jsonl").read_text().splitlines()]
        self.assertEqual(kinds, ["snapshot_validated", "diagnosis_started", "diagnosis_completed"])
        self.assertTrue(path.startswith(os.path.realpath(self._t.name) + os.sep + "inc-a" + os.sep))

    def test_invalid_inputs_refused(self):
        good = EvidenceSnapshot.model_validate_json(raw("M1-1"), strict=False)
        evaluated = diagnose_snapshot(raw("M1-1"), code_commit=COMMIT)[3]
        cases = {
            "garbage": b"{not json",
            "pretty": json.dumps(json.loads(raw("M1-1")), indent=1).encode(),
            "incident_id": canonical_bytes(good.model_copy(update={"incident_id": "inc-a"})),
            "evaluated": canonical_bytes(evaluated),
            "constructed": EvidenceSnapshot.model_construct(**{**dict(good), "schema_version": "9.9.9"}),
            "wrong type": "a string",
        }
        for name, bad in cases.items():
            with self.assertRaises(SnapshotInvalid, msg=name):
                pipeline.validate_snapshot(bad)
            with self.assertRaises(SnapshotInvalid, msg=name):
                diagnose_snapshot(bad, code_commit=COMMIT)

    def test_unknown_parameter_set_is_an_error_and_run_incomplete(self):
        ws = build_snapshot(World().ticks(TARGET), TARGET, world_params())
        with self.assertRaises(UnknownParameterSet):
            diagnose_snapshot(ws, code_commit=COMMIT)
        with self.assertRaises(SnapshotInvalid):                     # context/snapshot mismatch: before any write
            run_pure(CTX, ws, self.store, code_commit=COMMIT)
        self.assertEqual(os.listdir(self._t.name), [])
        with mock.patch.object(pipeline.registry, "get", side_effect=UnknownParameterSet("x")):
            with self.assertRaises(UnknownParameterSet):
                run_pure(CTX, raw("M1-1"), self.store, code_commit=COMMIT)
        (run_dir,) = [os.path.join(self._t.name, "inc-a", d) for d in os.listdir(os.path.join(self._t.name, "inc-a"))]
        self.assertFalse(verify_run(run_dir)["complete"])
        kinds = [json.loads(l)["kind"] for l in Path(run_dir, "events.jsonl").read_text().splitlines()]
        self.assertEqual(kinds[-1], "runtime_failure")

    def test_snapshot_mutation_detected(self):
        real = pipeline.diagnose

        def mutating(snap, params, *, code_commit):
            d = real(snap, params, code_commit=code_commit)
            object.__setattr__(snap, "snapshot_id", "0" * 16)
            return d
        with mock.patch.object(pipeline, "diagnose", mutating):
            with self.assertRaises(SnapshotMutated):
                diagnose_snapshot(raw("M1-1"), code_commit=COMMIT)

    def test_bad_commit_refused_by_m2(self):
        with self.assertRaises(Exception):
            diagnose_snapshot(raw("M1-1"), code_commit="not-a-hash")


if __name__ == "__main__":
    unittest.main()
