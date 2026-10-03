"""Independent fixtures for the rule engine: a complete, normal target plus per-test overrides.

All parameter VALUES below are test-only (contract §6: unit tests supply explicit test values).
They are not calibrated contract thresholds and never appear in engine code.
"""

from datetime import datetime, timedelta, timezone

from sentinelai.diagnostic.contract import (Aggregation, BaselineMethod, BaselineStat, DataQuality, Deviation,
                                            EvidenceSnapshot, Measurement, MissingMeasurement, Provenance, Qualifier,
                                            Quality, SourceType, Target, Window, load_contract, measurement_id,
                                            snapshot_id)
from sentinelai.diagnostic.rules import ParameterSet, diagnose
from sentinelai.diagnostic.rules.engine import DEV_FEATURES

C = load_contract()
T0 = datetime(2026, 10, 3, 9, 0, 0, tzinfo=timezone.utc)
BASE = Window(start=T0, end=T0 + timedelta(seconds=45), duration_s=45.0, sample_period_s=1.0)
INC = Window(start=T0 + timedelta(seconds=60), end=T0 + timedelta(seconds=70), duration_s=10.0, sample_period_s=1.0)
TARGET = Target(name="A", cgroup_path="/lab/A", pids=(100,), cpuset="2-3", netns_ref="pid:100", ifaces=("eth0",))
CG, NS, IF, APP = "cgroup:/lab/A", "netns:A", "iface:A/eth0", "app:A"
PSID = "test-params-m2"
FLOOR = 0.01
COMMIT = "d98daac"

TEST_NUMBERS = {
    "W": 10.0, "B": 45.0, "N_BASE_MIN": 10.0, "COV_MIN": 0.8, "Z_STRONG": 3.0, "Z_MODERATE": 2.0,
    "R_STRONG": 3.0, "R_MODERATE": 1.5, "DROP_ABS_MIN": 10.0, "DROP_FRAC_MIN": 0.001, "RT_FRAC_MIN": 0.01,
    "RT_RATE_MIN": 1.0, "SEG_MIN": 100.0, "THR_RATIO_MIN": 0.3, "THR_TIME_MIN": 0.05, "RDX_MIN": 0.05,
    "SAT_MIN": 0.9, "SI_ABS_MIN": 0.5, "SI_RATIO_MIN": 3.0, "SI_SHARE_MIN": 0.5, "PSI_MEM_MIN": 0.2,
    "RECLAIM_MIN": 1000.0, "REFAULT_MIN": 100.0, "APP_WAIT_MIN": 50.0, "APP_SHARE_MIN": 0.5, "IMPACT_MIN": 2.0,
    "DOM_RATIO": 2.0, "τ_DISAGREE": 0.9,
}


def params(**override):
    nums = dict(TEST_NUMBERS)
    nums.update({f"floor[{f}]": FLOOR for f in DEV_FEATURES})
    nums.update({k: v for k, v in override.items() if k != "KFREE_REASONS_LOSS"})
    reasons = override.get("KFREE_REASONS_LOSS", ("QDISC_DROP", "CPU_BACKLOG", "NETFILTER_DROP"))
    return ParameterSet(parameter_set_id=PSID, numbers=nums, reason_sets={"KFREE_REASONS_LOSS": tuple(reasons)})


def m(feature, scope, value, median=None, mad=0.1, *, quality=Quality.OK, coverage=1.0, agg=None, base=True,
      adequate=True, qualifier=None, derived_from=(), last=None):
    """One measurement. median=None means 'value is at baseline' (median = value)."""
    spec = C.registry.get(feature)
    b = d = None
    if base and quality not in (Quality.MISSING, Quality.INVALID):
        med = value if median is None else median
        b = BaselineStat(method=BaselineMethod.within_run, window=BASE, median=float(med), mad=float(mad),
                         p99=float(max(med, med + 3 * mad)), n=45, adequate=adequate)
        if value is not None:
            dr, dz = max(med, FLOOR), max(1.4826 * mad, FLOOR)
            d = Deviation(ratio=value / dr, delta=value - med, robust_z=(value - med) / dz, floor_used=FLOOR)
    src = spec.sources[0]
    if quality is Quality.STALE and last is None:
        last = INC.start - timedelta(seconds=5)   # M1: STALE means the last sample predates the window
    prov = Provenance(source=src, locator=spec.locator, collector="fixture", collector_version="0",
                      privileged=spec.privileged, first_sample_at=min(INC.start, last or INC.end) - timedelta(seconds=1),
                      last_sample_at=last or INC.end, samples=0 if value is None else 10,
                      derived_from=tuple(derived_from))
    agg = agg or spec.aggregations[0]
    return Measurement(measurement_id=measurement_id(feature, scope, INC, qualifier, agg), feature_id=feature,
                       scope=scope, window=INC, aggregation=agg, unit=spec.unit,
                       value=None if quality in (Quality.MISSING, Quality.INVALID) else value, quality=quality,
                       coverage=coverage, baseline=b, deviation=d, provenance=prov, qualifier=qualifier)


def kfree(reason, value, median=None):
    return m("net.drop.kfree_skb", NS, value, median, qualifier=Qualifier(dimension="reason", value=reason))


def derived(feature, scope, value, sources, median=None, mad=0.1):
    return m(feature, scope, value, median, mad, derived_from=tuple(x.measurement_id for x in sources))


def world(**ov):
    """A complete, NORMAL target. ov: feature-key -> replacement measurement (or None to drop it)."""
    rd = ov.pop("sched.run_delay.target", None) or m("sched.run_delay.target", CG, 0.05)
    tt = ov.pop("throttle.time_rate", None) or m("throttle.time_rate", CG, 0.0, mad=0.0)
    sc2 = ov.pop("softirq.frac.percpu@2", None) or m("softirq.frac.percpu", "cpu:2", 0.02, mad=0.01)
    sc3 = ov.pop("softirq.frac.percpu@3", None) or m("softirq.frac.percpu", "cpu:3", 0.02, mad=0.01)
    base = {
        "sched.run_delay.target": rd, "throttle.time_rate": tt,
        "sched.run_delay_excess.target": derived("sched.run_delay_excess.target", CG, 0.05, [rd, tt]),
        "cpu.util.cpuset": m("cpu.util.cpuset", "cpuset", 0.30, mad=0.05),
        "cpu.steal.cpuset": m("cpu.steal.cpuset", "cpuset", 0.0, mad=0.0),
        "throttle.quota_limited": m("throttle.quota_limited", CG, 0.0, base=False),
        "throttle.ratio": m("throttle.ratio", CG, 0.0, mad=0.0),
        "softirq.frac.percpu@2": sc2, "softirq.frac.percpu@3": sc3,
        "softirq.relevant_cpu_max": derived("softirq.relevant_cpu_max", "cpuset", max(sc2.value, sc3.value), [sc2, sc3],
                                            mad=0.01),
        "psi.cpu.some.target": m("psi.cpu.some.target", CG, 0.01, mad=0.01),
        "psi.mem.some.target": m("psi.mem.some.target", CG, 0.0, mad=0.0),
        "mem.events.oom_kill": m("mem.events.oom_kill", CG, 0.0, mad=0.0),
        "mem.reclaim.target": m("mem.reclaim.target", CG, 0.0, mad=0.0),
        "mem.refault.target": m("mem.refault.target", CG, 0.0, mad=0.0),
        "mem.majfault.target": m("mem.majfault.target", CG, 0.0, mad=0.0),
        "net.drop.qdisc": m("net.drop.qdisc", IF, 0.0, mad=0.0),
        "net.drop.iface_rx": m("net.drop.iface_rx", IF, 0.0, mad=0.0),
        "net.drop.iface_tx": m("net.drop.iface_tx", IF, 0.0, mad=0.0),
        "net.pkts.iface": m("net.pkts.iface", IF, 20000.0, mad=500.0),
        "tcp.out_segs_rate": m("tcp.out_segs_rate", NS, 5000.0, mad=100.0),
        "tcp.retrans_frac": m("tcp.retrans_frac", NS, 0.001, mad=0.0005),
        "app.latency_ms": m("app.latency_ms", APP, 900.0, 100.0, 10.0, agg=Aggregation.P99),
        "app.queue_wait_ms": m("app.queue_wait_ms", APP, 5.0, mad=1.0),
    }
    for k, v in ov.items():
        if v is None:
            base.pop(k, None)
        else:
            base[k] = v
    return [x for x in base.values() if x is not None]


def snapshot(measurements, gate=True):
    ms = tuple(measurements)
    missing = tuple(MissingMeasurement(feature_id=x.feature_id, scope=x.scope, reason="unavailable", qualifier=x.qualifier)
                    for x in ms if x.quality is Quality.MISSING)
    return EvidenceSnapshot(schema_version="0.2.0", contract_version="0.5.0-draft", parameter_set_id=PSID,
                            snapshot_id=snapshot_id(TARGET, INC, ms), target=TARGET, window=INC, baseline_window=BASE,
                            measurements=ms, evidence_items=(), missing_measurements=missing, conflicts=(),
                            data_quality=DataQuality(overall_coverage=1.0, sources_unavailable=(),
                                                     privileged_sources_unavailable=("EBPF",), baseline_adequate=True,
                                                     counter_resets=0, gate_passed=gate))


def run(measurements, gate=True, **param_override):
    return diagnose(snapshot(measurements, gate), params(**param_override), code_commit=COMMIT)


def status(diag, label):
    return next(c for c in diag.result.candidates if c.label is label).status


# ---------------------------------------------------------------------------- scenario fragments
def rdx(value, median=0.02, mad=0.005):
    srcs = (m("sched.run_delay.target", CG, 0.0), m("throttle.time_rate", CG, 0.0))   # ids are value-independent
    return {"sched.run_delay_excess.target": derived("sched.run_delay_excess.target", CG, value, srcs, median, mad)}


def contention(rd_excess=0.8):
    return {**rdx(rd_excess), "cpu.util.cpuset": m("cpu.util.cpuset", "cpuset", 0.95, 0.30, 0.05)}


def throttling(time_rate=0.5, ratio=0.6):
    return {"throttle.quota_limited": m("throttle.quota_limited", CG, 1.0, base=False),
            "throttle.ratio": m("throttle.ratio", CG, ratio, 0.0, 0.0),
            "throttle.time_rate": m("throttle.time_rate", CG, time_rate, 0.0, 0.0)}


def softirq(frac=0.7, both=True):
    s2 = m("softirq.frac.percpu", "cpu:2", frac, 0.05, 0.01)
    s3 = m("softirq.frac.percpu", "cpu:3", frac if both else 0.02, 0.05 if both else None, 0.01)
    return {"softirq.frac.percpu@2": s2, "softirq.frac.percpu@3": s3,
            "softirq.relevant_cpu_max": derived("softirq.relevant_cpu_max", "cpuset", frac, [s2, s3], 0.05, 0.01),
            "psi.cpu.some.target": m("psi.cpu.some.target", CG, 0.3, 0.01, 0.01)}


def retrans(frac=0.05):
    return {"tcp.retrans_frac": m("tcp.retrans_frac", NS, frac, 0.001, 0.0005)}


def qdisc_drops(value=500.0):
    return {"net.drop.qdisc": m("net.drop.qdisc", IF, value, 0.0, 0.0)}


def kfree_drops(reason, value, median=0.0, key=None):
    return {key or f"kfree:{reason}": m("net.drop.kfree_skb", NS, value, median, 0.0,
                                         qualifier=Qualifier(dimension="reason", value=reason))}


def app_wait(value=600.0):
    return {"app.queue_wait_ms": m("app.queue_wait_ms", APP, value, 5.0, 1.0)}


def memory(psi=0.5):
    return {"psi.mem.some.target": m("psi.mem.some.target", CG, psi, 0.0, 0.0)}


def no_drop_counters():
    return {"net.drop.qdisc": None, "net.drop.iface_rx": None, "net.drop.iface_tx": None}


def scenario(*parts, **extra):
    ov = {}
    for p in parts:
        ov.update(p)
    ov.update(extra)
    return world(**ov)


def items(diag, predicate_prefix):
    return [i for i in diag.snapshot.evidence_items if i.predicate_id.startswith(predicate_prefix)]


def reasons(diag):
    return [r.value for r in diag.result.abstention_reasons]
