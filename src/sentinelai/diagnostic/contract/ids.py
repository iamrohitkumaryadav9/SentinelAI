"""Deterministic identifiers (contract §10.3–10.5).

Encoding (fixed here because the contract names the inputs but not the byte encoding):
  id = sha1( canonical_json({"kind": <tag>, <named inputs>}) ).hexdigest()[:16]
Inputs are NAMED (an object), never positional: the canonical form treats arrays as sets, so a
positional array would lose the meaning of each slot. No randomness or clocks are used.
"""

import hashlib

from .catalog import load_contract
from .enums import Aggregation
from .serialize import canonical_json

ID_LEN = 16


def _h(kind: str, **inputs) -> str:
    return hashlib.sha1(canonical_json({"kind": kind, **inputs}).encode("utf-8")).hexdigest()[:ID_LEN]


def _identity_aggregation(feature_id: str, aggregation):
    """v0.5.0 (M3B-C1): the aggregation value to hash, or None when it is not part of identity.

    It is part of identity iff the registry declares more than one aggregation for the feature.
    The registry is the only authority; no feature is special-cased. Whether the aggregation is
    allowed for the feature is checked by Measurement (registry agreement), not here; an
    unregistered feature keeps the pre-v0.5.0 identity (Measurement rejects it as I5).
    """
    reg = load_contract().registry
    if not reg.has(feature_id) or len(reg.get(feature_id).aggregations) == 1:
        return None
    if aggregation is None:
        raise ValueError(f"{feature_id} registers several aggregations; its measurement id requires one")
    return Aggregation(aggregation).value


def measurement_id(feature_id: str, scope: str, window, qualifier=None, aggregation=None) -> str:
    """sha1(feature_id, scope, window[, qualifier][, aggregation]) truncated to 16 hex (contract §10.3).

    v0.2.0 (R-3): the qualifier is part of identity when present. When absent the key is
    omitted, so every unqualified id is byte-identical to v0.1.0.
    v0.5.0 (M3B-C1): the aggregation is part of identity only when the feature registers more than
    one aggregation. Otherwise the key is omitted and the id is byte-identical to v0.4.0.
    """
    inputs = dict(feature_id=feature_id, scope=scope, window=window)
    if qualifier is not None:
        inputs["qualifier"] = qualifier
    agg = _identity_aggregation(feature_id, aggregation)
    if agg is not None:
        inputs["aggregation"] = agg
    return _h("measurement", **inputs)


def evidence_item_id(predicate_id: str, measurement_ids) -> str:
    """Deterministic from predicate_id + measurement_ids (order-independent)."""
    return _h("evidence_item", predicate_id=predicate_id, measurement_ids=sorted(measurement_ids))


def inputs_hash(measurements) -> str:
    """SHA-256 of the canonical encoding of the snapshot's measurements (order-independent)."""
    return hashlib.sha256(canonical_json(list(measurements)).encode("utf-8")).hexdigest()


def snapshot_id(target, window, measurements) -> str:
    """Deterministic from target + window + inputs hash (contract §10.5)."""
    return _h("snapshot", target=target, window=window, inputs_sha256=inputs_hash(measurements))
