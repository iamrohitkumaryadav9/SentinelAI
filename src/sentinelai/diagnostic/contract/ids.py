"""Deterministic identifiers (contract §10.3–10.5).

Encoding (fixed here because the contract names the inputs but not the byte encoding):
  id = sha1( canonical_json({"kind": <tag>, <named inputs>}) ).hexdigest()[:16]
Inputs are NAMED (an object), never positional: the canonical form treats arrays as sets, so a
positional array would lose the meaning of each slot. No randomness or clocks are used.
"""

import hashlib

from .serialize import canonical_json

ID_LEN = 16


def _h(kind: str, **inputs) -> str:
    return hashlib.sha1(canonical_json({"kind": kind, **inputs}).encode("utf-8")).hexdigest()[:ID_LEN]


def measurement_id(feature_id: str, scope: str, window, qualifier=None) -> str:
    """sha1(feature_id, scope, window[, qualifier]) truncated to 16 hex (contract §10.3).

    v0.2.0 (R-3): the qualifier is part of identity when present. When absent the key is
    omitted, so every unqualified id is byte-identical to v0.1.0.
    """
    if qualifier is None:
        return _h("measurement", feature_id=feature_id, scope=scope, window=window)
    return _h("measurement", feature_id=feature_id, scope=scope, window=window, qualifier=qualifier)


def evidence_item_id(predicate_id: str, measurement_ids) -> str:
    """Deterministic from predicate_id + measurement_ids (order-independent)."""
    return _h("evidence_item", predicate_id=predicate_id, measurement_ids=sorted(measurement_ids))


def inputs_hash(measurements) -> str:
    """SHA-256 of the canonical encoding of the snapshot's measurements (order-independent)."""
    return hashlib.sha256(canonical_json(list(measurements)).encode("utf-8")).hexdigest()


def snapshot_id(target, window, measurements) -> str:
    """Deterministic from target + window + inputs hash (contract §10.5)."""
    return _h("snapshot", target=target, window=window, inputs_sha256=inputs_hash(measurements))
