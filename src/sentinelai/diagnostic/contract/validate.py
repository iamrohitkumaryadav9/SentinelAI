"""Cross-object invariant checks between a DiagnosticResult and its EvidenceSnapshot.

Single-object invariants are enforced by the models themselves. These checks need both
objects (contract §10.7: I2, I3, I4, I5, I6). They evaluate nothing about telemetry: they only
check that what a result CLAIMS is backed by the snapshot's evidence items.
"""

from .catalog import ContractViolation, ItemComponent, LabelsNotAssertedComponent, load_contract
from .enums import CandidateStatus, EvidenceKind, Label
from .models import DiagnosticResult, EvidenceSnapshot
from .version import parse_semver

ASSERTIVE = (CandidateStatus.ASSERTED, CandidateStatus.CONTRIBUTING)


def _clause_satisfied(clause, items, result) -> bool:
    for comp in clause.components:
        if isinstance(comp, LabelsNotAssertedComponent):
            status = {cd.label: cd.status for cd in result.candidates}
            if any(status[l] in ASSERTIVE for l in comp.labels):
                return False
            continue
        ok = False
        for it in items:
            p = load_contract().parse_predicate(it.predicate_id)
            if p.clause_id != clause.clause_id or (comp.sub is not None and p.primitive != comp.sub):
                continue
            if it.kind.value != comp.kind:
                continue
            if comp.kind == "POSITIVE" and clause.label not in it.supports:
                continue
            ok = True
            break
        if not ok:
            return False
    return True


def validate_against_snapshot(result: DiagnosticResult, snapshot: EvidenceSnapshot) -> None:
    """Raise ContractViolation if the result is not backed by the snapshot."""
    c = load_contract()
    if result.snapshot_id != snapshot.snapshot_id:
        raise ContractViolation("I5", "result.snapshot_id does not match the snapshot")
    if parse_semver(result.engine.contract_version)[0] != parse_semver(snapshot.contract_version)[0]:
        raise ContractViolation("I5", "engine and snapshot contract versions are incompatible")
    if result.engine.parameter_set_id != snapshot.parameter_set_id:
        raise ContractViolation("I7", "result and snapshot were produced with different parameter sets")
    items = {i.item_id: i for i in snapshot.evidence_items}
    ms = {m.measurement_id: m for m in snapshot.measurements}
    for cd in result.candidates:
        for iid in cd.supporting + cd.contradicting:
            if iid not in items:
                raise ContractViolation("I5", f"{cd.label}: evidence item {iid} not in snapshot")
        for iid in cd.supporting:
            it = items[iid]
            if it.kind is EvidenceKind.MISSING:
                raise ContractViolation("I3", f"{cd.label}: MISSING item {it.predicate_id} listed as supporting")
            if cd.label not in it.supports:
                raise ContractViolation("I3", f"{cd.label}: supporting item {it.predicate_id} does not support it")
        for iid in cd.contradicting:
            if cd.label not in items[iid].contradicts:
                raise ContractViolation("I3", f"{cd.label}: contradicting item does not contradict it")
        if cd.status in ASSERTIVE:
            for clause in c.labels.required_clauses(cd.label):
                if not _clause_satisfied(clause, snapshot.evidence_items, result):
                    raise ContractViolation("I4" if cd.label is not result.decision else "I2",
                                            f"{cd.label} {cd.status}: required clause {clause.clause_id} "
                                            "is not satisfied by the snapshot's evidence items")
        if cd.label is Label.application_bottleneck and cd.status in ASSERTIVE:
            info = c.labels.labels[Label.application_bottleneck]
            positive_app = [it for it in snapshot.evidence_items
                            if it.kind is EvidenceKind.POSITIVE and Label.application_bottleneck in it.supports
                            and any(ms[mid].feature_id in info.positive_evidence_features for mid in it.measurement_ids)]
            if not positive_app:
                raise ContractViolation("I6", "application_bottleneck asserted without positive application-level "
                                        "evidence (app.* other than app.latency_ms / app.error_rate)")
