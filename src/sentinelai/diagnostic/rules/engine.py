"""Deterministic evidence rule engine (Phase 1C M2).

    diagnose(snapshot, params, code_commit=...) -> Diagnosis(snapshot, result)

Pure function of (EvidenceSnapshot measurements, ParameterSet, contract version): no I/O, no
clock, no randomness, no ML, no LLM. It produces the EvidenceItems (the snapshot it receives
must contain measurements only) and the DiagnosticResult, then checks every contract invariant
with ``validate_against_snapshot`` before returning.

Contract semantics implemented here are cited by section. Points the contract leaves open are
resolved by the interpretations I-1 … I-n listed in docs/PHASE_1C_M2_REPORT.md; contradictions
are not resolved (they are reported, and the contract text is followed literally).
"""

import re
from dataclasses import dataclass, field
from itertools import combinations
from typing import Dict, List, Optional, Tuple

from ..contract import (FAULT_LABELS, AbstentionReason, Candidate, CandidateStatus, ConfidenceLevel, Conflict, DiagnosticFlag,
                        DiagnosticResult, EngineInfo, EvidenceItem, EvidenceKind, EvidenceSnapshot, Label,
                        ScopeKind, Strength, Threshold, evidence_item_id, load_contract, scope_kind,
                        validate_against_snapshot)
from ..contract.enums import Aggregation
from ..contract.version import CONTRACT_VERSION
from .logic import Eval, Tri, absolute, absolute_b, baseline_gate, dev, k_and, k_not, k_or, strongest, usable
from .params import ParameterSet, UncalibratedParameters

RULES_VERSION = "m2-1.0.0"
L = Label
INFRA = (L.cpu_contention, L.cpu_throttling, L.softirq_overload, L.network_packet_loss, L.tcp_retransmissions,
         L.memory_pressure)
IFACE_DROP_SOURCES = ("net.drop.qdisc", "net.drop.iface_rx", "net.drop.iface_tx", "net.err.iface")
OTHER_DROP_SOURCES = ("net.drop.softnet", "net.drop.socket", "net.drop.netfilter")


class EngineError(RuntimeError):
    """The engine refused its input (not a diagnosis)."""


# ============================================================================ snapshot view
class View:
    """Target-bound, deterministic access to a snapshot's measurements (interpretation I-2)."""

    def __init__(self, snapshot: EvidenceSnapshot, params: ParameterSet):
        self.s, self.p, t = snapshot, params, snapshot.target
        self.cgroup, self.netns, self.app = f"cgroup:{t.cgroup_path}", f"netns:{t.name}", f"app:{t.name}"
        self.cpus = _parse_cpuset(t.cpuset)
        self.ms = sorted(snapshot.measurements, key=lambda m: m.measurement_id)
        self.by_id = {m.measurement_id: m for m in self.ms}

    def binds(self, m) -> bool:
        k = scope_kind(m.scope)
        if k in (ScopeKind.host, ScopeKind.cpuset):
            return True
        if k is ScopeKind.cgroup:
            return m.scope == self.cgroup
        if k is ScopeKind.netns:
            return m.scope == self.netns
        if k is ScopeKind.app:
            return m.scope == self.app
        if k is ScopeKind.iface:
            ns, _, ifn = m.scope[len("iface:"):].partition("/")
            return ns == self.s.target.name and ifn in self.s.target.ifaces
        if k is ScopeKind.socket:
            return m.scope.startswith(f"socket:{self.s.target.name}/")
        if k is ScopeKind.cpu:
            return self.cpus is None or int(m.scope[4:]) in self.cpus
        return False

    def all(self, feature: str, aggregation: Optional[Aggregation] = None) -> List:
        return [m for m in self.ms if m.feature_id == feature and self.binds(m)
                and (aggregation is None or m.aggregation is aggregation)]

    def one(self, feature: str, aggregation: Optional[Aggregation] = None):
        """The single target-bound measurement of a feature, or None (several -> engine refuses)."""
        found = self.all(feature, aggregation)
        if len(found) > 1:
            raise EngineError(f"ambiguous input: {len(found)} target-bound measurements of {feature}")
        return found[0] if found else None


def _parse_cpuset(cs):
    if cs is None:
        return None
    out = set()
    for part in cs.split(","):
        a, _, b = part.partition("-")
        out |= set(range(int(a), int(b or a) + 1))
    return frozenset(out)


# ============================================================================ clause evaluation
@dataclass
class Clause:
    clause_id: str
    ev: Eval
    items: List[EvidenceItem] = field(default_factory=list)
    data: Dict = field(default_factory=dict)


@dataclass
class Ctx:
    v: View
    p: ParameterSet
    items: Dict[str, EvidenceItem] = field(default_factory=dict)

    def emit(self, predicate_id, ev: Eval, *, supports=(), contradicts=(), threshold=None, observed=None):
        """Create (or merge) an EvidenceItem for an evaluation. Absent inputs produce no item."""
        if not ev.used:
            return None
        kind = {Tri.TRUE: EvidenceKind.POSITIVE, Tri.FALSE: EvidenceKind.NEGATIVE, Tri.MISSING: EvidenceKind.MISSING}[ev.tri]
        sup = tuple(sorted(supports, key=_lab)) if kind is EvidenceKind.POSITIVE else ()
        con = tuple(sorted(contradicts, key=_lab))
        strength = None if kind is EvidenceKind.MISSING else ev.strength
        thr = Threshold(parameter=threshold, value=self.p.num(threshold)) if threshold else None
        iid = evidence_item_id(predicate_id, ev.used)
        if iid in self.items:   # same predicate over the same measurements: merge label lists
            old = self.items[iid]
            sup = tuple(sorted(set(old.supports) | set(sup), key=_lab))
            con = tuple(sorted(set(old.contradicts) | set(con), key=_lab))
        it = EvidenceItem(item_id=iid, predicate_id=predicate_id, kind=kind, strength=strength,
                          measurement_ids=tuple(sorted(ev.used)), observed=observed, threshold=thr,
                          supports=sup, contradicts=con,
                          missing_reason=(ev.reason or "unavailable") if kind is EvidenceKind.MISSING else None,
                          rationale=load_contract().render_rationale(predicate_id, kind, strength, observed, thr))
        self.items[iid] = it
        return it


def _lab(l):
    return FAULT_LABELS.index(l)


def _required_item(ctx, cid, label, ev, threshold=None, observed=None):
    """Clause-level item: TRUE supports the label, FALSE contradicts it, MISSING records absence."""
    return ctx.emit(cid, ev, supports=(label,), contradicts=(label,) if ev.tri is Tri.FALSE else (),
                    threshold=threshold, observed=observed)


# -- cpu_contention (§8.1) ----------------------------------------------------------------
def cc_r1(ctx):
    ev = k_or(*[dev(m, ctx.p) for m in ctx.v.all("sched.run_delay_excess.target")])
    _required_item(ctx, "CC.R1", L.cpu_contention, ev)
    return Clause("CC.R1", ev)


def cc_r2(ctx):
    p = ctx.p
    ev = k_or(absolute_b(ctx.v.one("cpu.util.cpuset"), p.num("SAT_MIN"), p), dev(ctx.v.one("cpu.steal.cpuset"), p))
    _required_item(ctx, "CC.R2", L.cpu_contention, ev, threshold="SAT_MIN")
    return Clause("CC.R2", ev)


def cc_x1(ctx):
    ev = absolute(ctx.v.one("throttle.ratio"), ctx.p.num("THR_RATIO_MIN"), ctx.p)
    ctx.emit("CC.X1", ev, supports=(L.cpu_throttling,),
             contradicts=(L.cpu_contention,) if ev.tri is Tri.TRUE else (), threshold="THR_RATIO_MIN")
    return Clause("CC.X1", ev)


def softirq_share(ctx):
    """Softirq share of busy time on the relevant CPUs (interpretation I-5): mean per-CPU softirq
    fraction over relevant CPUs / cpu.util.cpuset. Uses only the CC.X2 clause features."""
    v, p = ctx.v, ctx.p
    util = v.one("cpu.util.cpuset")
    per = v.all("softirq.frac.percpu")
    used = tuple(sorted([m.measurement_id for m in per] + ([util.measurement_id] if util else [])))
    if util is None or not per or usable(util, p.num("COV_MIN")) or any(usable(m, p.num("COV_MIN")) for m in per):
        return None, Eval(Tri.MISSING, reason="softirq share not measurable", used=used)
    if util.value == 0:
        return 0.0, Eval(Tri.FALSE, Strength.STRONG, used=used)
    share = (sum(m.value for m in per) / len(per)) / util.value
    return share, Eval(Tri.TRUE if share >= p.num("SI_SHARE_MIN") else Tri.FALSE, Strength.STRONG, used=used)


def cc_x2(ctx):
    share, ev = softirq_share(ctx)
    ctx.emit("CC.X2", ev, supports=(L.softirq_overload,),
             contradicts=(L.cpu_contention,) if ev.tri is Tri.TRUE else (), threshold="SI_SHARE_MIN", observed=share)
    return Clause("CC.X2", ev, data={"share": share})


# -- cpu_throttling (§8.2) ----------------------------------------------------------------
def ct_r1(ctx):
    m = ctx.v.one("throttle.quota_limited")
    if m is None:
        ev = Eval(Tri.MISSING, reason="measurement not present")
    elif usable(m, ctx.p.num("COV_MIN")):
        ev = Eval(Tri.MISSING, reason=usable(m, ctx.p.num("COV_MIN")), used=(m.measurement_id,))
    else:   # v0.2.0 R-1: 1.0 = finite quota (TRUE), 0.0 = unlimited (a real FALSE, never MISSING)
        ev = Eval(Tri.TRUE if m.value == 1.0 else Tri.FALSE, Strength.STRONG, used=(m.measurement_id,))
    _required_item(ctx, "CT.R1", L.cpu_throttling, ev, observed=m.value if m is not None else None)
    return Clause("CT.R1", ev)


def ct_r2(ctx):
    p = ctx.p
    ev = k_and(absolute_b(ctx.v.one("throttle.ratio"), p.num("THR_RATIO_MIN"), p), dev(ctx.v.one("throttle.time_rate"), p))
    _required_item(ctx, "CT.R2", L.cpu_throttling, ev, threshold="THR_RATIO_MIN")
    return Clause("CT.R2", ev)


# -- softirq_overload (§8.3) --------------------------------------------------------------
def _cpu_si(ctx, m):
    """Per-CPU part of SI.R1 on one CPU: x ≥ SI_ABS_MIN ∧ DEV TRUE ∧ ratio ≥ SI_RATIO_MIN."""
    p = ctx.p
    d = dev(m, p)
    if d.tri is not Tri.TRUE:
        return d
    if m.value >= p.num("SI_ABS_MIN") and m.deviation.ratio >= p.num("SI_RATIO_MIN"):
        return d
    return Eval(Tri.FALSE, Strength.STRONG, used=d.used)


def si_r1(ctx):
    p, v = ctx.p, ctx.v
    per = {m.measurement_id: (_cpu_si(ctx, m), m) for m in v.all("softirq.frac.percpu")}
    saturated = sorted(int(m.scope[4:]) for e, m in per.values() if e.tri is Tri.TRUE)
    same_cpu = k_or(*[e for e, _ in per.values()])
    ev = k_and(absolute_b(v.one("softirq.relevant_cpu_max"), p.num("SI_ABS_MIN"), p), same_cpu)
    _required_item(ctx, "SI.R1", L.softirq_overload, ev, threshold="SI_ABS_MIN")
    return Clause("SI.R1", ev, data={"saturated_cpus": saturated})


def si_r2(ctx):
    ev = k_or(dev(ctx.v.one("sched.run_delay_excess.target"), ctx.p), dev(ctx.v.one("psi.cpu.some.target"), ctx.p))
    _required_item(ctx, "SI.R2", L.softirq_overload, ev)
    return Clause("SI.R2", ev)


# -- network_packet_loss (§8.4): LOSS.LOCAL ----------------------------------------------
def _drop_source(ctx, m, pkts=None):
    """One drop source: x ≥ DROP_ABS_MIN ∧ (DEV ∨ baseline median = 0) [∧ drop fraction]."""
    p = ctx.p
    bad = usable(m, p.num("COV_MIN"))
    if bad:
        return Eval(Tri.MISSING, reason=bad, used=(m.measurement_id,))
    gate = baseline_gate(m, p)
    if gate:
        return gate
    used = (m.measurement_id,)
    if m.feature_id in IFACE_DROP_SOURCES:
        if pkts is None or usable(pkts, p.num("COV_MIN")) or baseline_gate(pkts, p):
            return Eval(Tri.MISSING, reason="net.pkts.iface unavailable for drop fraction",
                        used=used + ((pkts.measurement_id,) if pkts is not None else ()))
        used = used + (pkts.measurement_id,)
    if m.value < p.num("DROP_ABS_MIN"):
        return Eval(Tri.FALSE, Strength.STRONG, used=used)
    d = dev(m, p)
    if d.tri is Tri.MISSING:
        return Eval(Tri.MISSING, reason=d.reason, used=used)
    if d.tri is Tri.FALSE:
        if m.baseline.median != 0:
            return Eval(Tri.FALSE, d.strength, used=used)
        d = Eval(Tri.TRUE, Strength.MODERATE, used=used)   # baseline-zero branch (interpretation I-6)
    if m.feature_id in IFACE_DROP_SOURCES:
        if m.value / (pkts.value + m.value) < p.num("DROP_FRAC_MIN"):
            return Eval(Tri.FALSE, Strength.STRONG, used=used)
    return Eval(Tri.TRUE, d.strength, used=used)


def loss_local(ctx):
    """Evaluate LOSS.LOCAL once (memoised): per-source evaluations, the min-set completeness and
    the aggregate (contract §8.4). Absent sources are never treated as 'no drops'."""
    if "loss" in ctx.__dict__:
        return ctx.__dict__["loss"]
    v, p = ctx.v, ctx.p
    sources = []   # (feature, measurement, eval, softnet_cpu, kfree_reason)
    for f in IFACE_DROP_SOURCES:
        for m in v.all(f):
            pk = next((x for x in v.all("net.pkts.iface") if x.scope == m.scope), None)
            sources.append((f, m, _drop_source(ctx, m, pk), None, None))
    for f in OTHER_DROP_SOURCES:
        for m in v.all(f):
            cpu = int(m.scope[4:]) if f == "net.drop.softnet" else None
            sources.append((f, m, _drop_source(ctx, m), cpu, None))
    loss_reasons = set(p.reasons("KFREE_REASONS_LOSS"))
    for m in v.all("net.drop.kfree_skb"):
        if m.qualifier is not None and m.qualifier.value in loss_reasons:   # only qualifying reasons (§8.4)
            sources.append(("net.drop.kfree_skb", m, _drop_source(ctx, m), None, m.qualifier.value))
    # completeness of the minimum local drop set over every target interface
    min_set = load_contract().registry.named_sets["min_local_drop_set"]
    ifaces = ctx.v.s.target.ifaces
    min_ok = bool(ifaces) and all(
        any(m.scope == f"iface:{v.s.target.name}/{i}" and not usable(m, p.num("COV_MIN")) for m in v.all(f))
        for f in min_set for i in ifaces)
    min_used = tuple(sorted(m.measurement_id for f in min_set for m in v.all(f)))
    evaluated = Eval(Tri.TRUE, Strength.STRONG, used=min_used) if min_ok else \
        Eval(Tri.MISSING, reason="minimum local drop set not evaluated", used=min_used)
    true = [s for s in sources if s[2].tri is Tri.TRUE]
    usable_sources = [s for s in sources if not usable(s[1], p.num("COV_MIN"))]
    all_used = tuple(sorted({u for s in sources for u in s[2].used}))
    if true:
        agg = Eval(Tri.TRUE, strongest(*(s[2].strength for s in true)),
                   used=tuple(sorted({u for s in true for u in s[2].used})))
    elif min_ok and usable_sources and all(s[2].tri is Tri.FALSE for s in usable_sources):
        agg = Eval(Tri.FALSE, Strength.STRONG, used=all_used)
    else:
        agg = Eval(Tri.MISSING, reason="local drops not determinable", used=all_used)
    ctx.__dict__["loss"] = (sources, evaluated, agg)
    return ctx.__dict__["loss"]


def pl_r1(ctx):
    sources, _, agg = loss_local(ctx)
    for f, m, ev, _, _ in sources:
        ctx.emit(f"PL.R1/LOSS.LOCAL[{f}]", ev, supports=(L.network_packet_loss,), threshold="DROP_ABS_MIN",
                 observed=m.value)
    true = [(f, cpu, reason) for f, m, ev, cpu, reason in sources if ev.tri is Tri.TRUE]
    return Clause("PL.R1", agg, data={"qualifying": true})


# -- tcp_retransmissions (§8.5) -----------------------------------------------------------
def rt_r0(ctx):
    ev = absolute(ctx.v.one("tcp.out_segs_rate"), ctx.p.num("SEG_MIN"), ctx.p)
    _required_item(ctx, "RT.R0", L.tcp_retransmissions, ev, threshold="SEG_MIN")
    return Clause("RT.R0", ev)


def rt_r1(ctx):
    m = ctx.v.one("tcp.retrans_frac")
    # The optional DEV(tcp.timeouts_rate) substitution is not applied (interpretation I-7).
    ev = k_and(absolute_b(m, ctx.p.num("RT_FRAC_MIN"), ctx.p), dev(m, ctx.p))
    _required_item(ctx, "RT.R1", L.tcp_retransmissions, ev, threshold="RT_FRAC_MIN")
    return Clause("RT.R1", ev)


def rt_r2(ctx):
    _, evaluated, loss = loss_local(ctx)
    ctx.emit("RT.R2/EVALUATED[min_local_drop_set]", evaluated, supports=(L.tcp_retransmissions,))
    if loss.tri is Tri.FALSE:
        ctx.emit("RT.R2/LOSS.LOCAL", loss, contradicts=(L.network_packet_loss,))
    elif loss.tri is Tri.MISSING:
        ctx.emit("RT.R2/LOSS.LOCAL", loss)
    else:   # proven local loss: RT.R2 is FALSE (recorded under a distinct predicate id)
        ctx.emit("RT.R2", Eval(Tri.FALSE, loss.strength, used=loss.used), contradicts=(L.tcp_retransmissions,))
    ev = k_and(evaluated, k_not(loss))
    return Clause("RT.R2", ev, data={"evaluated": evaluated.tri, "loss": loss.tri})


# -- memory_pressure (§8.6) ---------------------------------------------------------------
def mp_r1(ctx):
    v, p = ctx.v, ctx.p
    psi = v.one("psi.mem.some.target")
    a1 = k_and(absolute_b(psi, p.num("PSI_MEM_MIN"), p), dev(psi, p))
    oom = v.one("mem.events.oom_kill")
    if oom is None:
        a2 = Eval(Tri.MISSING, reason="measurement not present")
    elif usable(oom, p.num("COV_MIN")):
        a2 = Eval(Tri.MISSING, reason=usable(oom, p.num("COV_MIN")), used=(oom.measurement_id,))
    elif baseline_gate(oom, p):
        a2 = baseline_gate(oom, p)
    else:
        a2 = Eval(Tri.TRUE if oom.value > 0 else Tri.FALSE, Strength.STRONG, used=(oom.measurement_id,))
    rec = v.one("mem.reclaim.target")
    a3 = k_and(dev(rec, p), absolute_b(rec, p.num("RECLAIM_MIN"), p),
               k_or(dev(v.one("mem.refault.target"), p), dev(v.one("mem.majfault.target"), p)))
    ev = k_or(a1, a2, a3)
    _required_item(ctx, "MP.R1", L.memory_pressure, ev)
    return Clause("MP.R1", ev)


# -- application_bottleneck (§8.7) --------------------------------------------------------
WAITS = ("app.queue_wait_ms", "app.lock_wait_ms", "app.dependency_latency_ms")


def ab_r1(ctx):
    v, p = ctx.v, ctx.p
    alts = [k_and(dev(m, p), absolute_b(m, p.num("APP_WAIT_MIN"), p)) for f in WAITS for m in v.all(f)]
    alts += [dev(m, p) for m in v.all("app.pool_rejections")]
    alts += [dev(m, p) for m in v.all("app.events")]           # qualified by closed-set code (v0.2.0)
    ev = k_or(*alts)
    _required_item(ctx, "AB.R1", L.application_bottleneck, ev, threshold="APP_WAIT_MIN")
    return Clause("AB.R1", ev)


def ab_r2(ctx):
    """Share of the p99 latency increase explained by app-level wait (interpretation I-8)."""
    v, p = ctx.v, ctx.p
    lat = v.one("app.latency_ms", Aggregation.P99)
    waits = [m for f in WAITS for m in v.all(f)]
    used = tuple(sorted([m.measurement_id for m in waits] + ([lat.measurement_id] if lat else [])))
    ok = [m for m in waits if not usable(m, p.num("COV_MIN")) and m.baseline is not None and m.baseline.adequate]
    if lat is None or usable(lat, p.num("COV_MIN")) or lat.baseline is None or not lat.baseline.adequate or not ok:
        ev, share = Eval(Tri.MISSING, reason="latency or wait components unavailable", used=used), None
    else:
        used = tuple(sorted([m.measurement_id for m in ok] + [lat.measurement_id]))
        d_lat = lat.value - lat.baseline.median
        share = (max(m.value - m.baseline.median for m in ok) / d_lat) if d_lat > 0 else None
        ev = Eval(Tri.TRUE if share is not None and share >= p.num("APP_SHARE_MIN") else Tri.FALSE,
                  Strength.STRONG, used=used)
    _required_item(ctx, "AB.R2", L.application_bottleneck, ev, threshold="APP_SHARE_MIN", observed=share)
    return Clause("AB.R2", ev)


EVALUATORS = {"CC.R1": cc_r1, "CC.R2": cc_r2, "CC.X1": cc_x1, "CC.X2": cc_x2, "CT.R1": ct_r1, "CT.R2": ct_r2,
              "SI.R1": si_r1, "SI.R2": si_r2, "PL.R1": pl_r1, "RT.R0": rt_r0, "RT.R1": rt_r1, "RT.R2": rt_r2,
              "MP.R1": mp_r1, "AB.R1": ab_r1, "AB.R2": ab_r2}
# AB.R3 depends on the infrastructure candidates and is evaluated after them (see _ab_r3).

# Supporting predicates (contract §8 "Supporting"); only those expressible with registered features
# and the defined DEV/ABS primitives (interpretation I-9).
SUPPORTING = {
    L.cpu_contention: (("DEV", "sched.involuntary_cs.target", None), ("DEV", "psi.cpu.some.target", None),
                       ("DEV", "sched.run_delay.cpuset", None)),
    L.cpu_throttling: (("ABS", "throttle.quota_saturation", "SAT_MIN"),),
    L.softirq_overload: (("DEV", "softirq.net_rx_rate.percpu", None), ("DEV", "softnet.time_squeeze.percpu", None),
                         ("DEV", "softirq.imbalance", None)),
    L.network_packet_loss: (("DEV", "tcp.retrans_frac", None),),
    L.tcp_retransmissions: (("DEV", "tcp.srtt_ms", None), ("DEV", "tcp.timeouts_rate", None)),
    L.memory_pressure: (("DEV", "mem.events.high", None), ("DEV", "psi.mem.full.target", None),
                        ("DEV", "mem.swap_io.host", None), ("ABS", "mem.util.target", "SAT_MIN")),
    L.application_bottleneck: (("ABS", "app.pool_utilization", "SAT_MIN"),),
}
DEV_FEATURES = tuple(sorted(set().union(
    *[load_contract().labels.clause(c).features for c in EVALUATORS if load_contract().labels.clause(c).uses_baseline],
    {f for preds in SUPPORTING.values() for prim, f, _ in preds if prim == "DEV"},
    {"app.latency_ms", "net.drop.kfree_skb"})))


def _self_check():
    """The evaluator table must cover the contract's clauses exactly (no hidden or missing rules)."""
    c = load_contract()
    have = set(EVALUATORS) | {"AB.R3"}
    want = {cl.clause_id for cl in c.labels.clauses}
    if have != want:
        raise ImportError(f"rule table does not match contract clauses: {sorted(have ^ want)}")


_self_check()


def _supporting(ctx):
    """Evaluate supporting predicates. Returns {label: [missing supporting feature, ...]}."""
    missing = {l: [] for l in FAULT_LABELS}
    for label, preds in SUPPORTING.items():
        for prim, f, param in preds:
            ms = ctx.v.all(f)
            if not ms:
                missing[label].append(f)
            for m in ms:
                ev = dev(m, ctx.p) if prim == "DEV" else absolute(m, ctx.p.num(param), ctx.p)
                if ev.tri is Tri.MISSING:
                    missing[label].append(f)
                ctx.emit(f"{prim}[{f}]", ev, supports=(label,), threshold=param)
    # kfree_skb reasons outside KFREE_REASONS_LOSS: at most a WEAK supporting item (contract §8.4)
    loss_reasons = set(ctx.p.reasons("KFREE_REASONS_LOSS"))
    for m in ctx.v.all("net.drop.kfree_skb"):
        if m.qualifier is not None and m.qualifier.value not in loss_reasons:
            ev = dev(m, ctx.p)
            if ev.tri is Tri.TRUE:
                ev = Eval(Tri.TRUE, Strength.WEAK, used=ev.used)
            ctx.emit("DEV[net.drop.kfree_skb]", ev, supports=(L.network_packet_loss,))
    return missing


def _impact(ctx):
    """IMPACT gate (§7). No EvidenceItem is emitted: an impact item supports no fault label, which
    the schema forbids for POSITIVE items (contradiction C-2 in the M2 report)."""
    lat = ctx.v.one("app.latency_ms", Aggregation.P99)
    d = dev(lat, ctx.p)
    if d.tri is Tri.TRUE and lat.deviation.ratio < ctx.p.num("IMPACT_MIN"):
        return Tri.FALSE
    return d.tri


def _ab_r3(ctx, clauses, infra_assertable):
    """AB.R3: infrastructure families EVALUATED (interpretation I-10) and none assertable."""
    fam_label = (("cpu_sched", L.cpu_contention), ("cpu_throttling", L.cpu_throttling), ("memory", L.memory_pressure),
                 ("softirq", L.softirq_overload))
    if clauses["RT.R0"].ev.tri is Tri.TRUE:
        fam_label += (("network_drops", L.network_packet_loss), ("network_tcp", L.tcp_retransmissions))
    c = load_contract()
    # Items may cite only AB.R3's declared features. The contract's AB.R3 list omits throttle.quota_limited
    # (contradiction C-3, M2 report): that measurement still drives evaluation but cannot be cited here.
    allowed = set(c.labels.clause("AB.R3").features)
    cite = lambda ids: tuple(sorted(u for u in ids if ctx.v.by_id[u].feature_id in allowed))
    evs = []
    for fam, label in fam_label:
        req = [clauses[cl.clause_id].ev for cl in c.labels.required_clauses(label)]
        conj = k_and(*req)
        used = cite(conj.used)   # a decided family cites only the clauses that decided it
        ev = Eval(Tri.TRUE, Strength.STRONG, used=used) if conj.tri is not Tri.MISSING else \
            Eval(Tri.MISSING, reason=f"{fam} not evaluated", used=used)
        ctx.emit(f"AB.R3/EVALUATED[family:{fam}]", ev, supports=(L.application_bottleneck,))
        evs.append(ev)
    evaluated = k_and(*evs)
    if infra_assertable:
        used = cite({u for l in infra_assertable for cl in c.labels.required_clauses(l)
                     for u in clauses[cl.clause_id].ev.used})
        ctx.emit("AB.R3", Eval(Tri.FALSE, Strength.STRONG, used=used), contradicts=(L.application_bottleneck,))
        return Clause("AB.R3", Eval(Tri.FALSE, Strength.STRONG, used=used), data={"evaluated": evaluated.tri})
    return Clause("AB.R3", evaluated, data={"evaluated": evaluated.tri})


# ============================================================================ precedence (§9)
def _value(ctx, feature):
    m = ctx.v.one(feature)
    return None if m is None or usable(m, ctx.p.num("COV_MIN")) else m.value


def _resolve(ctx, a, b, clauses) -> Tuple[Optional[Label], Optional[str]]:
    """Resolve one co-assertable pair. Returns (winner or None for conflict, rule id or None)."""
    pair = {a, b}
    if pair == {L.network_packet_loss, L.tcp_retransmissions}:                     # PR-1
        return L.network_packet_loss, "PR-1"
    if pair == {L.softirq_overload, L.network_packet_loss}:                         # PR-2 / PR-2b
        sat = set(clauses["SI.R1"].data["saturated_cpus"])
        qual = clauses["PL.R1"].data["qualifying"]
        softirq_caused = qual and all((f == "net.drop.softnet" and cpu in sat) or
                                      (f == "net.drop.kfree_skb" and reason == "CPU_BACKLOG") for f, cpu, reason in qual)
        return (L.softirq_overload, "PR-2") if softirq_caused else (None, "PR-2b")
    if pair == {L.cpu_throttling, L.cpu_contention}:                                 # PR-3
        tt, rd = _value(ctx, "throttle.time_rate"), _value(ctx, "sched.run_delay_excess.target")
        if tt is None or rd is None:
            return None, "PR-3"
        dom = ctx.p.num("DOM_RATIO")
        if tt >= dom * rd and tt > rd:
            return L.cpu_throttling, "PR-3"
        if rd >= dom * tt and rd > tt:
            return L.cpu_contention, "PR-3"
        return None, "PR-3"
    if L.application_bottleneck in pair and pair - {L.application_bottleneck} <= set(INFRA):   # PR-4
        return next(iter(pair - {L.application_bottleneck})), "PR-4"
    if pair == {L.softirq_overload, L.cpu_contention}:                               # PR-5
        share = clauses["CC.X2"].data["share"]
        if share is not None and share >= ctx.p.num("SI_SHARE_MIN"):
            return L.softirq_overload, "PR-5"
        # "cpu_contention if CC.R1 holds without the softirq CPUs" is not evaluable with the
        # registered features (run_delay_excess is per cgroup, not per CPU): conflict (I-11).
        return None, "PR-5"
    return None, None                                                                # not in §9: conflict


# ============================================================================ diagnose
@dataclass(frozen=True)
class Diagnosis:
    snapshot: EvidenceSnapshot
    result: DiagnosticResult


def diagnose(snapshot: EvidenceSnapshot, params: ParameterSet, *, code_commit: str) -> Diagnosis:
    """Evaluate the contract on a measurements-only snapshot. Pure and deterministic."""
    if snapshot.evidence_items or snapshot.conflicts:
        raise EngineError("input snapshot must contain measurements only; the engine produces the evidence")
    if params.parameter_set_id != snapshot.parameter_set_id:
        raise EngineError("parameter set does not match snapshot.parameter_set_id")
    missing = params.missing(DEV_FEATURES)
    if missing:
        raise UncalibratedParameters(missing)

    c = load_contract()
    ctx = Ctx(View(snapshot, params), params)
    clauses = {cid: fn(ctx) for cid, fn in EVALUATORS.items()}
    support_missing = _supporting(ctx)
    impact = _impact(ctx)

    def req_evs(label):
        return [clauses[cl.clause_id].ev for cl in c.labels.required_clauses(label)]

    infra_assertable = [l for l in INFRA if all(e.tri is Tri.TRUE for e in req_evs(l))]
    clauses["AB.R3"] = _ab_r3(ctx, clauses, infra_assertable)
    assertable = [l for l in FAULT_LABELS if all(e.tri is Tri.TRUE for e in req_evs(l))]

    # ---- precedence among assertable labels (closed table; anything else is a conflict)
    primary, conflicts = None, []
    if len(assertable) == 1:
        primary = assertable[0]
    elif len(assertable) > 1:
        wins = {l: 0 for l in assertable}
        for a, b in combinations(assertable, 2):
            winner, rule = _resolve(ctx, a, b, clauses)
            if winner is None:
                conflicts.append((a, b, rule))
            else:
                wins[winner] += 1
        top = [l for l in assertable if wins[l] == len(assertable) - 1]
        if not conflicts and len(top) == 1:
            primary = top[0]
        elif not conflicts:
            conflicts.append((assertable[0], assertable[1], None))

    # ---- abstention (§8.8, design §5.1)
    reasons = []
    if not snapshot.data_quality.gate_passed:
        reasons = [AbstentionReason.DATA_QUALITY]
    elif impact is Tri.FALSE:
        reasons = [AbstentionReason.NO_IMPACT_OBSERVED]
    elif conflicts:
        reasons = [AbstentionReason.CONFLICT_UNRESOLVED]
    elif primary is None:
        undecided = [l for l in FAULT_LABELS
                     if not any(e.tri is Tri.FALSE for e in req_evs(l)) and any(e.tri is Tri.MISSING for e in req_evs(l))]
        covered = set()
        if (L.tcp_retransmissions in undecided and clauses["RT.R1"].ev.tri is Tri.TRUE
                and clauses["RT.R2"].ev.tri is Tri.MISSING):
            reasons.append(AbstentionReason.LOSS_VS_RETRANS_UNDECIDABLE)
            covered.add(L.tcp_retransmissions)
            if clauses["PL.R1"].ev.tri is Tri.MISSING:   # the same undetermined local-drop question
                covered.add(L.network_packet_loss)
        if (L.application_bottleneck in undecided and clauses["AB.R1"].ev.tri is Tri.TRUE
                and clauses["AB.R2"].ev.tri is Tri.TRUE and clauses["AB.R3"].ev.tri is Tri.MISSING):
            reasons.append(AbstentionReason.CONFOUNDER_NOT_EVALUATED)
            covered.add(L.application_bottleneck)
        if set(undecided) - covered:
            reasons.append(AbstentionReason.REQUIRED_EVIDENCE_MISSING)
        if not reasons:
            reasons.append(AbstentionReason.NO_CANDIDATE)
    decision = L.INSUFFICIENT_EVIDENCE if reasons else primary

    # ---- candidates
    items = ctx.items
    cands = []
    for label in FAULT_LABELS:
        rq = c.labels.required_clauses(label)
        evs = {cl.clause_id: clauses[cl.clause_id].ev for cl in rq}
        met = tuple(cid for cid, e in evs.items() if e.tri is Tri.TRUE)
        supporting = tuple(sorted(i.item_id for i in items.values()
                                  if i.kind is EvidenceKind.POSITIVE and label in i.supports))
        contradicting = tuple(sorted(i.item_id for i in items.values() if label in i.contradicts))
        fired = tuple(sorted(cl.clause_id for cl in c.labels.clauses
                             if cl.label is label and clauses[cl.clause_id].ev.tri is Tri.TRUE))
        if label in assertable:
            status = CandidateStatus.CONTRIBUTING if (decision not in (L.INSUFFICIENT_EVIDENCE, label)
                                                      and not conflicts) else CandidateStatus.ASSERTED
        elif any(e.tri is Tri.FALSE for e in evs.values()):
            status = CandidateStatus.NOT_SUPPORTED
        elif supporting:
            status = CandidateStatus.SUPPORTED_NOT_SUFFICIENT
        else:
            status = CandidateStatus.NOT_EVALUABLE
        cands.append((label, status, met, supporting, contradicting, fired))

    # ---- confidence (§10.9) and flags
    flags = (DiagnosticFlag.IMPACT_NOT_MEASURED,) if impact is Tri.MISSING else ()
    if decision is L.INSUFFICIENT_EVIDENCE:
        confidence = ConfidenceLevel.LOW
    else:
        strong = all(clauses[cl.clause_id].ev.strength is Strength.STRONG for cl in c.labels.required_clauses(decision))
        contradicted = any(decision in i.contradicts for i in items.values())
        high = strong and not contradicted and impact is Tri.TRUE and not support_missing[decision]
        confidence = ConfidenceLevel.HIGH if high else ConfidenceLevel.MEDIUM

    # ---- conflicts as contract objects
    conflict_objs = []
    for a, b, rule in conflicts:
        ids = tuple(sorted(i.item_id for i in items.values() if i.kind is EvidenceKind.POSITIVE
                           and (a in i.supports or b in i.supports)
                           and load_contract().parse_predicate(i.predicate_id).clause_id is not None))
        conflict_objs.append(Conflict(labels=tuple(sorted((a, b), key=_lab)), rule=rule, item_ids=ids))

    out_snapshot = EvidenceSnapshot(**{**{k: getattr(snapshot, k) for k in type(snapshot).model_fields},
                                       "evidence_items": tuple(sorted(items.values(), key=lambda i: i.item_id)),
                                       "conflicts": tuple(conflict_objs)})
    result = DiagnosticResult(
        snapshot_id=snapshot.snapshot_id, decision=decision,
        contributing=tuple(l for l, st, *_ in cands if st is CandidateStatus.CONTRIBUTING),
        abstained=decision is L.INSUFFICIENT_EVIDENCE, abstention_reasons=tuple(reasons),
        confidence_level=confidence,
        candidates=tuple(Candidate(label=l, status=st, required_met=met,
                                   required_missing=tuple(cl.clause_id for cl in c.labels.required_clauses(l)
                                                          if cl.clause_id not in met),
                                   supporting=sup, contradicting=con, rules_fired=fired)
                         for l, st, met, sup, con, fired in cands),
        rules_fired=tuple(sorted({r for *_, fired in cands for r in fired})),
        ml=None, flags=flags,
        engine=EngineInfo(contract_version=CONTRACT_VERSION, rules_version=RULES_VERSION,
                          parameter_set_id=params.parameter_set_id, code_commit=code_commit))
    validate_against_snapshot(result, out_snapshot)   # every contract invariant, or raise
    return Diagnosis(out_snapshot, result)
