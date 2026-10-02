"""Deterministic evidence rule engine (Phase 1C M2). The authoritative decision-maker.

No collection, no ML, no LLM: it consumes an EvidenceSnapshot and a ParameterSet.
"""

from .engine import RULES_VERSION, Diagnosis, EngineError, diagnose
from .params import ParameterSet, UncalibratedParameters

__all__ = ["diagnose", "Diagnosis", "EngineError", "ParameterSet", "UncalibratedParameters", "RULES_VERSION"]
