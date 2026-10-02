"""Parameter sets consumed by the rule engine (EVIDENCE_CONTRACT.md §6).

The engine never contains threshold values. A ParameterSet supplies them; the engine refuses to
run unless every contract parameter (and every per-feature floor it needs) is present
(contract §6: "An engine MUST refuse to run with any UNCALIBRATED parameter").
"""

import re
from typing import Annotated, Dict, Iterable, Tuple

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..contract.catalog import load_contract

STRICT = ConfigDict(extra="forbid", frozen=True, strict=True)
FiniteFloat = Annotated[float, Field(allow_inf_nan=False)]


class UncalibratedParameters(RuntimeError):
    """Raised when a rule needs a parameter the ParameterSet does not provide."""

    def __init__(self, missing):
        self.missing = tuple(sorted(missing))
        super().__init__(f"refusing to run: uncalibrated/missing parameters {list(self.missing)}")


class ParameterSet(BaseModel):
    model_config = STRICT
    parameter_set_id: Annotated[str, Field(min_length=1)]
    numbers: Dict[str, FiniteFloat]
    reason_sets: Dict[str, Tuple[str, ...]]

    @model_validator(mode="after")
    def _check(self):
        c = load_contract()
        for name in self.numbers:
            if c.parameter_type(name) != "number":
                raise ValueError(f"{name!r} is not a number parameter of the contract")
        reason = c.registry.get("net.drop.kfree_skb").dimension
        for name, values in self.reason_sets.items():
            if c.parameter_type(name) != "reason_set":
                raise ValueError(f"{name!r} is not a reason_set parameter of the contract")
            if len(set(values)) != len(values) or not all(reason.accepts(v) for v in values):
                raise ValueError(f"{name!r}: values must be unique, valid kfree_skb reason names")
        return self

    def num(self, name: str) -> float:
        if name not in self.numbers:
            raise UncalibratedParameters([name])
        return self.numbers[name]

    def reasons(self, name: str) -> Tuple[str, ...]:
        if name not in self.reason_sets:
            raise UncalibratedParameters([name])
        return self.reason_sets[name]

    def floor(self, feature_id: str) -> float:
        return self.num(f"floor[{feature_id}]")

    def missing(self, floor_features: Iterable[str]):
        c = load_contract()
        need = {p.name for p in c.parameters.parameters}
        need |= {f"floor[{f}]" for f in floor_features}
        have = set(self.numbers) | set(self.reason_sets)
        return need - have
