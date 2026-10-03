"""Feature registry and contract catalogs (contract §4, §6, §8, §9). Expected IDs typed from the contract."""

import json
import unittest
from pathlib import Path

from pydantic import ValidationError

from sentinelai.diagnostic.contract import ContractViolation, FeatureRegistry, FeatureSpec, Label, load_contract
from sentinelai.diagnostic.contract.catalog import DATA

C = load_contract()

# Every feature ID written in EVIDENCE_CONTRACT.md §4 (independent transcription for this test).
CONTRACT_FEATURES = """
cpu.util.host cpu.util.cpuset cpu.util.percpu cpu.steal.cpuset cpu.usage.target sched.run_delay.target
sched.run_delay.cpuset sched.run_delay_excess.target sched.nr_migrations.target sched.involuntary_cs.target
sched.ctxt.host sched.procs_running.host psi.cpu.some.target psi.cpu.some.host sched.latency_hist.target
throttle.quota_limited throttle.quota_cores throttle.ratio throttle.time_rate throttle.quota_saturation
net.drop.qdisc net.drop.iface_rx net.drop.iface_tx net.err.iface net.drop.softnet net.drop.socket
net.drop.netfilter net.drop.kfree_skb net.pkts.iface net.bytes.iface
tcp.retrans_rate tcp.retrans_frac tcp.out_segs_rate tcp.timeouts_rate tcp.fast_retrans_rate tcp.syn_retrans_rate
tcp.srtt_ms tcp.cwnd tcp.retrans_skb_rate
softirq.frac.percpu softirq.net_rx_rate.percpu softirq.net_tx_rate.percpu softirq.exec_time.percpu softnet.time_squeeze.percpu
softnet.processed.percpu softirq.imbalance softirq.relevant_cpu_max
mem.util.target mem.available.host psi.mem.some.target psi.mem.full.target psi.mem.some.host mem.reclaim.target
mem.reclaim_direct.host mem.refault.target mem.majfault.target mem.events.high mem.events.oom_kill mem.swap.target
mem.swap_io.host
app.latency_ms app.throughput app.error_rate app.queue_wait_ms app.pool_utilization app.pool_rejections
app.lock_wait_ms app.dependency_latency_ms app.events
""".split()

REQUIRED_CLAUSES = {  # contract §8 Required clauses
    Label.cpu_contention: {"CC.R1", "CC.R2"}, Label.cpu_throttling: {"CT.R1", "CT.R2"},
    Label.softirq_overload: {"SI.R1", "SI.R2"}, Label.network_packet_loss: {"PL.R1"},  # unchanged by v0.2.0
    Label.tcp_retransmissions: {"RT.R0", "RT.R1", "RT.R2"}, Label.memory_pressure: {"MP.R1"},
    Label.application_bottleneck: {"AB.R1", "AB.R2", "AB.R3"},
}


class TestRegistry(unittest.TestCase):
    def test_exactly_the_contract_features(self):
        self.assertEqual(sorted(f.id for f in C.registry.features), sorted(CONTRACT_FEATURES))

    def test_ids_unique_and_versioned(self):
        ids = [f.id for f in C.registry.features]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(C.registry.contract_version, "0.4.0-draft")

    def test_unknown_feature_rejected(self):
        with self.assertRaises(ContractViolation):
            C.registry.get("cpu.made_up")

    def test_no_feature_sourced_from_ground_truth(self):
        for f in C.registry.features:
            self.assertNotIn("FAULTLAB_GROUND_TRUTH", [s.value for s in f.sources], f.id)

    def test_privileged_only_for_ebpf_availability(self):
        priv = sorted(f.id for f in C.registry.features if f.privileged)
        self.assertEqual(priv, ["net.drop.kfree_skb", "sched.latency_hist.target", "softirq.exec_time.percpu",
                                "tcp.retrans_skb_rate"])                      # v0.4.0: the two EBPF additions

    def test_application_features_marked_lab_only(self):
        for f in C.registry.features:
            if f.id.startswith("app."):
                self.assertEqual(f.availability.value, "L", f.id)

    def test_derived_features_declare_inputs(self):
        derived = {f.id: f.derived_from for f in C.registry.features if f.kind == "derived"}
        self.assertEqual(set(derived), {"sched.run_delay_excess.target", "throttle.quota_saturation",
                                        "softirq.imbalance", "softirq.relevant_cpu_max"})
        self.assertEqual(set(derived["sched.run_delay_excess.target"]), {"sched.run_delay.target", "throttle.time_rate"})

    def _raw(self):
        return json.loads((DATA / "registry.json").read_text())

    def test_duplicate_id_rejected(self):
        raw = self._raw()
        raw["features"].append(dict(raw["features"][0]))
        with self.assertRaises(ValidationError):
            FeatureRegistry.model_validate_json(json.dumps(raw))

    def test_invalid_unit_aggregation_source_rejected(self):
        base = self._raw()["features"][0]
        for k, v in (("unit", "furlongs"), ("aggregations", ["MEDIAN"]), ("sources", ["SYSLOG"]),
                     ("sources", ["FAULTLAB_GROUND_TRUTH"]), ("scope_kinds", ["galaxy"]), ("id", "Bad-ID")):
            with self.subTest(field=k, value=v), self.assertRaises(ValidationError):
                FeatureSpec.model_validate_json(json.dumps({**base, k: v}))

    def test_privileged_availability_mismatch_rejected(self):
        base = self._raw()["features"][0]
        with self.assertRaises(ValidationError):
            FeatureSpec.model_validate_json(json.dumps({**base, "privileged": True}))


class TestCatalogs(unittest.TestCase):
    def test_required_clauses_match_contract(self):
        for lab, exp in REQUIRED_CLAUSES.items():
            with self.subTest(label=lab.value):
                self.assertEqual({c.clause_id for c in C.labels.required_clauses(lab)}, exp)

    def test_insufficient_evidence_has_no_clauses(self):
        self.assertFalse([c for c in C.labels.clauses if c.label is Label.INSUFFICIENT_EVIDENCE])
        self.assertNotIn(Label.INSUFFICIENT_EVIDENCE, C.labels.labels)

    def test_precedence_rule_ids(self):
        self.assertEqual([p.rule_id for p in C.labels.precedence], ["PR-1", "PR-2", "PR-2b", "PR-3", "PR-4", "PR-5"])

    def test_application_clause_cannot_use_impact_features(self):
        ab1 = C.labels.clause("AB.R1")
        self.assertNotIn("app.latency_ms", ab1.features)
        self.assertNotIn("app.error_rate", ab1.features)
        info = C.labels.labels[Label.application_bottleneck]
        self.assertEqual(set(info.never_sufficient_features), {"app.latency_ms", "app.error_rate"})

    def test_no_threshold_values_anywhere(self):
        """Contract §6: all thresholds are uncalibrated parameters; M1 defines none."""
        params = json.loads((DATA / "parameters.json").read_text())
        self.assertEqual(params["status"], "UNCALIBRATED")
        for p in params["parameters"] + params["per_feature_parameters"]:   # v0.2.0 R-4: name + type only
            self.assertEqual(set(p), {"name", "type"})
            self.assertIn(p["type"], ("number", "reason_set"))
        for name in ("labels.json", "predicates.json", "parameters.json"):
            def walk(o, path=name):
                if isinstance(o, bool):
                    return
                self.assertNotIsInstance(o, (int, float), f"numeric value in {path}")
                if isinstance(o, dict):
                    for k, v in o.items():
                        walk(v, f"{path}.{k}")
                elif isinstance(o, list):
                    for i, v in enumerate(o):
                        walk(v, f"{path}[{i}]")
            walk(json.loads((DATA / name).read_text()))


if __name__ == "__main__":
    unittest.main()
