"""Public errors raised while loading and freezing research contracts."""

from __future__ import annotations


class ContractError(ValueError):
    """Base class for fail-closed contract errors."""


class ContractDecodeError(ContractError):
    """The input is not an unambiguous finite JSON document."""


class ContractSchemaError(ContractError):
    """The normalized document does not satisfy the frozen C6 schema."""


class ContractInvariantError(ContractError):
    """The document violates a cross-field runtime invariant."""


class ContractHashMismatch(ContractInvariantError):
    """The declared contract hash differs from the canonical digest."""
