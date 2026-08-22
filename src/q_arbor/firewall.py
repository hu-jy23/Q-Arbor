"""Minimal C10 split-resource authorization boundary."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from q_arbor.evaluation import EvaluationBoundaryError, EvaluationRequest


@dataclass(frozen=True, slots=True)
class SplitGrant:
    """Trusted binding from one split identity to an opaque resource."""

    split_role: str
    split_manifest_hash: str
    resource: object


@dataclass(frozen=True, slots=True, init=False)
class SplitGrantRegistry:
    """Immutable grant lookup that releases only an exactly bound resource."""

    _grants: Mapping[str, SplitGrant]

    def __init__(self, grants: Mapping[str, SplitGrant]) -> None:
        object.__setattr__(self, "_grants", MappingProxyType(dict(grants)))

    def resolve(self, request: EvaluationRequest) -> object:
        grant = self._grants.get(request.capability_grant_id)
        if grant is None:
            raise EvaluationBoundaryError("split grant is unavailable")
        if grant.split_role != request.split_role:
            raise EvaluationBoundaryError("split role differs from trusted grant")
        if grant.split_manifest_hash != request.split_manifest_hash:
            raise EvaluationBoundaryError("split manifest differs from trusted grant")
        return grant.resource


__all__ = ["SplitGrant", "SplitGrantRegistry"]
