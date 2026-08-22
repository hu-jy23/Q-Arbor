"""Minimal C10 split-resource authorization boundary."""

from __future__ import annotations

import hmac
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from threading import Lock
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


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    """Frozen C6 capability identity without its raw bearer token."""

    grant_id: str
    run_id: str
    contract_hash: str
    role: str
    principal: str
    query_limit: int
    query_count: int
    state: str
    token_digest: str = field(repr=False)
    issued_event_id: str


class FinalCapabilityState(str, Enum):
    """Closed C6 final-capability states for the synthetic mechanism test."""

    LOCKED = "locked"
    UNLOCKED = "unlocked"
    CONSUMED = "consumed"


class FinalResearchAction(str, Enum):
    """Research actions forbidden after final-capability consumption."""

    PROPOSE = "propose"
    DISPATCH = "dispatch"
    EVALUATE = "evaluate"
    MERGE = "merge"


@dataclass(frozen=True, slots=True)
class FinalCapabilityTerminal:
    """Mechanism-only final-capability state; it grants no sealed-final access."""

    state: FinalCapabilityState = FinalCapabilityState.LOCKED

    def __post_init__(self) -> None:
        self._validated_state()

    def unlock(self) -> FinalCapabilityTerminal:
        """Return the sole valid successor of a locked capability."""

        if self._validated_state() is not FinalCapabilityState.LOCKED:
            raise EvaluationBoundaryError(
                "final capability unlock transition is invalid"
            )
        return FinalCapabilityTerminal(FinalCapabilityState.UNLOCKED)

    def consume(self) -> FinalCapabilityTerminal:
        """Return the terminal successor of an unlocked capability."""

        if self._validated_state() is not FinalCapabilityState.UNLOCKED:
            raise EvaluationBoundaryError(
                "final capability consume transition is invalid"
            )
        return FinalCapabilityTerminal(FinalCapabilityState.CONSUMED)

    def allow_research_action(
        self,
        action: FinalResearchAction,
    ) -> FinalResearchAction:
        """Fail closed for untyped actions and every action after final unlock."""

        state = self._validated_state()
        if type(action) is not FinalResearchAction:
            raise EvaluationBoundaryError("final research action is invalid")
        if state is not FinalCapabilityState.LOCKED:
            raise EvaluationBoundaryError(
                "research is frozen after final capability unlock"
            )
        return action

    def _validated_state(self) -> FinalCapabilityState:
        if type(self.state) is not FinalCapabilityState:
            raise EvaluationBoundaryError("final capability state is invalid")
        return self.state


_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}")
_SHA256_RE = re.compile(r"[a-f0-9]{64}")
_PRINCIPAL_ROLES = {
    "executor": frozenset({"development"}),
    "coordinator": frozenset({"development", "gate"}),
    "finalizer": frozenset({"final"}),
}


class EvaluationBroker:
    """In-memory fail-closed authorization and query-budget boundary."""

    __slots__ = ("_grants", "_query_counts", "_resources", "_state_lock")

    def __init__(
        self,
        grants: Mapping[str, CapabilityGrant],
        resources: SplitGrantRegistry,
    ) -> None:
        if not isinstance(grants, Mapping):
            raise EvaluationBoundaryError("capability grant registry is invalid")
        if not isinstance(resources, SplitGrantRegistry):
            raise EvaluationBoundaryError("split resource registry is invalid")
        copied = dict(grants)
        counts = {
            grant_id: (
                grant.query_count
                if type(grant) is CapabilityGrant
                and type(grant.query_count) is int
                and grant.query_count >= 0
                else 0
            )
            for grant_id, grant in copied.items()
        }
        self._grants = MappingProxyType(copied)
        self._query_counts = counts
        self._resources = resources
        self._state_lock = Lock()

    def __repr__(self) -> str:
        return f"EvaluationBroker(grants={len(self._grants)})"

    def query_count(self, grant_id: str) -> int:
        """Return broker-owned execution-query consumption for one grant."""

        with self._state_lock:
            if grant_id not in self._query_counts:
                raise EvaluationBoundaryError("capability grant is unavailable")
            return self._query_counts[grant_id]

    def authorize(
        self,
        request: EvaluationRequest,
        *,
        principal: str,
        token: bytes,
    ) -> object:
        """Consume one query and return only the exactly authorized opaque handle."""

        if type(request) is not EvaluationRequest:
            raise EvaluationBoundaryError("evaluation request is invalid")
        with self._state_lock:
            grant = self._grants.get(request.capability_grant_id)
            if grant is None:
                raise EvaluationBoundaryError("capability grant is unavailable")
            self._validate_grant(grant)
            if grant.grant_id != request.capability_grant_id:
                raise EvaluationBoundaryError("capability grant identity differs")
            if request.split_role == "final":
                raise EvaluationBoundaryError("final split remains sealed")
            if grant.run_id != request.run_id:
                raise EvaluationBoundaryError("run differs from capability grant")
            if grant.contract_hash != request.contract_hash:
                raise EvaluationBoundaryError("contract differs from capability grant")
            if grant.role != request.split_role:
                raise EvaluationBoundaryError("split role differs from capability grant")
            allowed_roles = _PRINCIPAL_ROLES.get(principal)
            if (
                grant.principal != principal
                or allowed_roles is None
                or request.split_role not in allowed_roles
            ):
                raise EvaluationBoundaryError("principal differs from capability grant")
            if type(token) is not bytes or not token:
                raise EvaluationBoundaryError("capability token is invalid")
            supplied_digest = sha256(token).hexdigest()
            if not hmac.compare_digest(grant.token_digest, supplied_digest):
                raise EvaluationBoundaryError("capability token is invalid")
            if grant.state != "active":
                raise EvaluationBoundaryError("capability grant is inactive")

            count = self._query_counts[request.capability_grant_id]
            if count >= grant.query_limit:
                raise EvaluationBoundaryError("capability query budget is exhausted")
            resource = self._resources.resolve(request)
            if isinstance(
                resource,
                (str, bytes, bytearray, memoryview, os.PathLike),
            ):
                raise EvaluationBoundaryError("split resource must be opaque")

            self._query_counts[request.capability_grant_id] = count + 1
            return resource

    @staticmethod
    def _validate_grant(grant: object) -> None:
        if type(grant) is not CapabilityGrant:
            raise EvaluationBoundaryError("capability grant is invalid")
        identifier_values = (grant.grant_id, grant.run_id, grant.issued_event_id)
        if any(
            not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None
            for value in identifier_values
        ):
            raise EvaluationBoundaryError("capability grant is invalid")
        if (
            not isinstance(grant.contract_hash, str)
            or _SHA256_RE.fullmatch(grant.contract_hash) is None
            or grant.role not in {"development", "gate", "final"}
            or grant.principal not in _PRINCIPAL_ROLES
            or type(grant.query_limit) is not int
            or grant.query_limit < 1
            or type(grant.query_count) is not int
            or grant.query_count < 0
            or grant.query_count > grant.query_limit
            or grant.state not in {"active", "consumed", "revoked", "expired"}
            or not isinstance(grant.token_digest, str)
            or _SHA256_RE.fullmatch(grant.token_digest) is None
        ):
            raise EvaluationBoundaryError("capability grant is invalid")


__all__ = [
    "CapabilityGrant",
    "EvaluationBroker",
    "FinalCapabilityState",
    "FinalCapabilityTerminal",
    "FinalResearchAction",
    "SplitGrant",
    "SplitGrantRegistry",
]
