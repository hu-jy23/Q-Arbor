"""Typed failures for quantitative hypothesis trees."""

from __future__ import annotations


class HypothesisError(Exception):
    """Base class for fail-closed hypothesis-tree errors."""


class HypothesisDecodeError(HypothesisError):
    """The input is not an unambiguous finite JSON value."""


class HypothesisSchemaError(HypothesisError):
    """The normalized artifact does not satisfy the frozen C6 schema."""


class HypothesisInvariantError(HypothesisError):
    """A schema-valid node or tree violates a cross-field invariant."""


class TreeConflictError(HypothesisError):
    """A requested mutation conflicts with the current tree state."""


class TreeIntegrityError(HypothesisError):
    """A declared hash or materialized state cannot be trusted."""


class TreeCompatibilityError(HypothesisError):
    """Compatibility-quarantined state cannot perform the requested action."""


class TreePersistenceError(HypothesisError):
    """A tree filesystem, locking, or atomic-write operation failed."""
