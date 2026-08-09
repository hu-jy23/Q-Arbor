"""Frozen C9 task-plugin adapters."""

from __future__ import annotations

from .formula_alpha import (
    FormulaAlphaPlugin,
    FormulaAlphaSplitData,
    FormulaMockOutcome,
    PublicFormulaSchema,
)
from .hm1 import HM1EngineOutput, HM1FuturesPlugin, HM1SplitData
from .synthetic import (
    SyntheticSignalPlugin,
    SyntheticSplitData,
    canonical_synthetic_candidate,
    synthetic_contract_draft,
    synthetic_fixture_identities,
)

__all__ = [
    "FormulaAlphaPlugin",
    "FormulaAlphaSplitData",
    "FormulaMockOutcome",
    "HM1EngineOutput",
    "HM1FuturesPlugin",
    "HM1SplitData",
    "PublicFormulaSchema",
    "SyntheticSignalPlugin",
    "SyntheticSplitData",
    "canonical_synthetic_candidate",
    "synthetic_contract_draft",
    "synthetic_fixture_identities",
]
