"""Contract and schema version metadata (EVIDENCE_CONTRACT.md §12)."""

import re

CONTRACT_ID = "sentinelai.evidence-contract"
CONTRACT_VERSION = "0.4.0-draft"
SCHEMA_VERSION = "0.2.0"

_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$")


def parse_semver(v: str) -> tuple:
    m = _SEMVER.match(v)
    if not m:
        raise ValueError(f"not a semantic version: {v!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)


def require_compatible(v: str) -> str:
    """Contract §12: an engine MUST reject snapshots of a different major version."""
    if parse_semver(v)[0] != parse_semver(CONTRACT_VERSION)[0]:
        raise ValueError(f"contract_version {v} incompatible with {CONTRACT_VERSION} (major differs)")
    return v
