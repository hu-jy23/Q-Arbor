"""Immutable quantitative research contracts."""

from __future__ import annotations

from .core import (
    QuantResearchContract,
    canonical_contract_bytes,
    compute_contract_hash,
    freeze_contract,
    load_contract,
    validate_contract,
)
from .errors import (
    ContractDecodeError,
    ContractError,
    ContractHashMismatch,
    ContractInvariantError,
    ContractSchemaError,
)

__all__ = [
    "ContractError",
    "ContractDecodeError",
    "ContractSchemaError",
    "ContractInvariantError",
    "ContractHashMismatch",
    "QuantResearchContract",
    "load_contract",
    "freeze_contract",
    "validate_contract",
    "canonical_contract_bytes",
    "compute_contract_hash",
]
