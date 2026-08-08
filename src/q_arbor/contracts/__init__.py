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
    "ContractDecodeError",
    "ContractError",
    "ContractHashMismatch",
    "ContractInvariantError",
    "ContractSchemaError",
    "QuantResearchContract",
    "canonical_contract_bytes",
    "compute_contract_hash",
    "freeze_contract",
    "load_contract",
    "validate_contract",
]
