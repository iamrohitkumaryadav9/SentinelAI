"""M3B-C1 (contract v0.5.0-draft): multi-aggregation measurements coexist in one snapshot, and M2, which
selects app.latency_ms by aggregation, keeps reading P99 only. Rules are unchanged (m2-1.1.0)."""

import unittest

from sentinelai.diagnostic.contract import Label as L

from ._fixtures import APP, Aggregation, contention, m, reasons, run, scenario


def lat(value, agg, median=100.0):
    return m("app.latency_ms", APP, value, median, 10.0, agg=agg)


def fingerprint(d):
    r = d.result
    return (r.decision, r.flags, r.confidence_level, tuple((c.label, c.status) for c in r.candidates), reasons(d),
            sorted((i.predicate_id, i.kind, i.measurement_ids) for i in d.snapshot.evidence_items))


class TestLatencyAggregationsCoexist(unittest.TestCase):
    def test_extra_p50_changes_no_decision(self):
        for p99 in (100.0, 900.0):                               # no impact / impact
            with self.subTest(p99=p99):
                only = run(scenario(contention(), {"app.latency_ms": lat(p99, Aggregation.P99)}))
                both = run(scenario(contention(), {"app.latency_ms": lat(p99, Aggregation.P99),
                                                   "app.latency_ms@P50": lat(5000.0, Aggregation.P50)}))
                self.assertEqual(len(both.snapshot.measurements), len(only.snapshot.measurements) + 1)
                self.assertEqual(fingerprint(both), fingerprint(only))

    def test_impact_gate_reads_p99_not_p50(self):
        d = run(scenario(contention(), {"app.latency_ms": lat(100.0, Aggregation.P99),
                                        "app.latency_ms@P50": lat(5000.0, Aggregation.P50)}))
        self.assertEqual(reasons(d), ["NO_IMPACT_OBSERVED"])     # a huge P50 is not impact
        d = run(scenario(contention(), {"app.latency_ms": lat(900.0, Aggregation.P99),
                                        "app.latency_ms@P50": lat(100.0, Aggregation.P50)}))
        self.assertIs(d.result.decision, L.cpu_contention)


if __name__ == "__main__":
    unittest.main()
