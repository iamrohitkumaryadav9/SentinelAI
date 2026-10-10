"""Runtime-owned parameter-set registry (Phase 2A.1).

M2 refuses to run without the exact ParameterSet whose id matches the snapshot. The runtime holds the
validated sets as literals, never recomputed: each is rebuilt from its literal and checked against a pinned
SHA-256 of its canonical bytes on every load, so a drifted value fails loudly instead of diagnosing.

r2c-validation-uncalibrated: the set used by R2-C, R2-D and R2-F (scripts/r2c_driver.params(); numbers =
scripts/r2b_driver.NUMBERS, floor 1e-3 for every DEV/collected feature). Uncalibrated (contract §6).
"""

import hashlib
from types import MappingProxyType

from ..diagnostic.contract.serialize import canonical_bytes
from ..diagnostic.rules.params import ParameterSet

DEFAULT_PARAMETER_SET_ID = "r2c-validation-uncalibrated"


class UnknownParameterSet(KeyError):
    """The requested parameter-set id is not in the registry (never substituted)."""


class RegistryIntegrityError(RuntimeError):
    """A registry literal no longer hashes to its pinned value."""


_FLOOR_FEATURES = (
    "app.dependency_latency_ms", "app.events", "app.latency_ms", "app.lock_wait_ms", "app.pool_rejections",
    "app.queue_wait_ms", "cpu.steal.cpuset", "cpu.usage.target", "cpu.util.cpuset", "cpu.util.host",
    "cpu.util.percpu", "mem.available.host", "mem.events.high", "mem.events.oom_kill", "mem.majfault.target",
    "mem.reclaim.target", "mem.reclaim_direct.host", "mem.refault.target", "mem.swap.target", "mem.swap_io.host",
    "mem.util.target", "net.bytes.iface", "net.drop.iface_rx", "net.drop.iface_tx", "net.drop.kfree_skb",
    "net.drop.netfilter", "net.drop.qdisc", "net.drop.socket", "net.drop.softnet", "net.err.iface",
    "net.pkts.iface", "psi.cpu.some.host", "psi.cpu.some.target", "psi.mem.full.target", "psi.mem.some.host",
    "psi.mem.some.target", "sched.ctxt.host", "sched.involuntary_cs.target", "sched.latency_hist.target",
    "sched.nr_migrations.target", "sched.procs_running.host", "sched.run_delay.cpuset", "sched.run_delay.target",
    "sched.run_delay_excess.target", "softirq.exec_time.percpu", "softirq.frac.percpu", "softirq.imbalance",
    "softirq.net_rx_rate.percpu", "softirq.net_tx_rate.percpu", "softirq.relevant_cpu_max",
    "softnet.processed.percpu", "softnet.time_squeeze.percpu", "tcp.fast_retrans_rate", "tcp.out_segs_rate",
    "tcp.retrans_frac", "tcp.retrans_rate", "tcp.retrans_skb_rate", "tcp.srtt_ms", "tcp.syn_retrans_rate",
    "tcp.timeouts_rate", "throttle.quota_cores", "throttle.quota_limited", "throttle.quota_saturation",
    "throttle.ratio", "throttle.time_rate",
)

_R2C_NUMBERS = {
    "W": 10.0, "B": 10.0, "N_BASE_MIN": 5.0, "COV_MIN": 0.8, "Z_STRONG": 3.0, "Z_MODERATE": 2.0,
    "R_STRONG": 3.0, "R_MODERATE": 1.5, "DROP_ABS_MIN": 10.0, "DROP_FRAC_MIN": 0.001, "RT_FRAC_MIN": 0.01,
    "RT_RATE_MIN": 1.0, "SEG_MIN": 100.0, "THR_RATIO_MIN": 0.3, "THR_TIME_MIN": 0.05, "RDX_MIN": 0.05,
    "SAT_MIN": 0.9, "SI_ABS_MIN": 0.5, "SI_RATIO_MIN": 3.0, "SI_SHARE_MIN": 0.5, "PSI_MEM_MIN": 0.2,
    "RECLAIM_MIN": 1000.0, "REFAULT_MIN": 100.0, "APP_WAIT_MIN": 50.0, "APP_SHARE_MIN": 0.5,
    "IMPACT_MIN": 2.0, "DOM_RATIO": 2.0, "τ_DISAGREE": 0.9,
    **{f"floor[{f}]": 0.001 for f in _FLOOR_FEATURES},
}

# id -> (numbers, reason_sets, pinned sha256 of canonical_bytes(ParameterSet))
_SETS = MappingProxyType({
    "r2c-validation-uncalibrated": (
        MappingProxyType(_R2C_NUMBERS),
        MappingProxyType({"KFREE_REASONS_LOSS": ("QDISC_DROP", "CPU_BACKLOG", "NETFILTER_DROP")}),
        "880d9af62f6e120c227cbc1abc50a8521d8cc62ff059c3bbd8f316dbd56807cb",
    ),
})

# parameter sets the R2 FaultLab campaigns validated M2 with (the validated-configuration check uses this)
VALIDATED_PARAMETER_SETS = frozenset({"r2c-validation-uncalibrated"})


def known() -> tuple:
    return tuple(sorted(_SETS))


def parameter_set_sha256(ps: ParameterSet) -> str:
    return hashlib.sha256(canonical_bytes(ps)).hexdigest()


def get(parameter_set_id: str) -> ParameterSet:
    """The exact registered ParameterSet. Unknown ids raise; a literal that drifted from its pin raises."""
    if not isinstance(parameter_set_id, str) or parameter_set_id not in _SETS:
        raise UnknownParameterSet(parameter_set_id)
    numbers, reasons, pinned = _SETS[parameter_set_id]
    ps = ParameterSet(parameter_set_id=parameter_set_id, numbers=dict(numbers), reason_sets=dict(reasons))
    if parameter_set_sha256(ps) != pinned:
        raise RegistryIntegrityError(f"{parameter_set_id}: canonical sha256 differs from the pinned value")
    return ps
