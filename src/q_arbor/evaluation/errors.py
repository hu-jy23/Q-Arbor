"""Typed failures for the evaluation boundary."""

from __future__ import annotations


class EvaluationError(Exception):
    """Base class for fail-closed evaluation errors."""


class EvaluationDecodeError(EvaluationError):
    """Input is not an unambiguous finite JSON value."""


class EvaluationSchemaError(EvaluationError):
    """A normalized value does not satisfy its frozen or closed schema."""


class EvaluationInvariantError(EvaluationError):
    """A schema-valid value violates a cross-field invariant."""


class EvaluationIntegrityError(EvaluationError):
    """A declared identity, digest, or provenance relation does not hold."""


class EvaluationPersistenceError(EvaluationError):
    """A filesystem operation failed at a known atomic-write phase."""

    def __init__(self, message: str, *, committed: bool = False) -> None:
        super().__init__(message)
        self.committed = committed


class EvaluationBoundaryError(EvaluationError):
    """A resource, path, or artifact operation crossed its trusted boundary."""


class EvaluationPluginError(EvaluationError):
    """Plugin construction or programming failed before a terminal result."""
