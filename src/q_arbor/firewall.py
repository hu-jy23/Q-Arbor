"""Minimal split-resource authorization boundary."""

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

from q_arbor.evaluation import (
    EvaluationBoundaryError,
    EvaluationRequest,
    VerifiedRuntimeLock,
)


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
    """Frozen capability identity without its raw bearer token."""

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
    """Closed final-capability states for deterministic tests."""

    LOCKED = "locked"
    UNLOCKED = "unlocked"
    CONSUMED = "consumed"


class FinalResearchAction(str, Enum):
    """Research actions forbidden after final-capability consumption."""

    PROPOSE = "propose"
    DISPATCH = "dispatch"
    EVALUATE = "evaluate"
    MERGE = "merge"


class CapabilityAuthority:
    """Shared in-process authority for capability state and runtime identity."""

    __slots__ = ("_final_state", "_query_counts", "_runtime_locks", "_state_lock")

    def __init__(self) -> None:
        self._final_state: FinalCapabilityState | None = None
        self._query_counts: dict[str, int] = {}
        self._runtime_locks: dict[str, str] = {}
        self._state_lock = Lock()

    def _register_grants(self, grants: Mapping[str, CapabilityGrant]) -> None:
        with self._state_lock:
            for grant_id, grant in grants.items():
                initial_count = (
                    grant.query_count
                    if type(grant) is CapabilityGrant
                    and type(grant.query_count) is int
                    and grant.query_count >= 0
                    else 0
                )
                self._query_counts.setdefault(grant_id, initial_count)

    def _register_runtime_locks(
        self,
        runtime_locks: Mapping[str, VerifiedRuntimeLock],
    ) -> None:
        with self._state_lock:
            for grant_id, runtime_lock in runtime_locks.items():
                runtime_identity = runtime_lock.sha256
                bound = self._runtime_locks.get(grant_id)
                if bound is not None and bound != runtime_identity:
                    raise EvaluationBoundaryError(
                        "runtime lock differs from authoritative binding"
                    )
                self._runtime_locks[grant_id] = runtime_identity

    def _require_runtime_lock(
        self,
        grant_id: str,
        runtime_lock: VerifiedRuntimeLock,
    ) -> None:
        with self._state_lock:
            if self._runtime_locks.get(grant_id) != runtime_lock.sha256:
                raise EvaluationBoundaryError(
                    "runtime lock differs from authoritative binding"
                )

    def _bind_final_state(self, state: FinalCapabilityState) -> None:
        with self._state_lock:
            if self._final_state is None:
                self._final_state = state
            elif self._final_state is not state:
                raise EvaluationBoundaryError(
                    "final capability differs from authoritative state"
                )

    def _transition_final(
        self,
        expected: FinalCapabilityState,
        successor: FinalCapabilityState,
        *,
        message: str,
    ) -> None:
        with self._state_lock:
            if self._final_state is not expected:
                raise EvaluationBoundaryError(message)
            self._final_state = successor

    def _get_final_state(self) -> FinalCapabilityState:
        with self._state_lock:
            if self._final_state is None:
                raise EvaluationBoundaryError("final capability state is unavailable")
            return self._final_state


@dataclass(frozen=True, slots=True)
class FinalCapabilityTerminal:
    """Mechanism-only final-capability state; it grants no sealed-final access."""

    state: FinalCapabilityState = FinalCapabilityState.LOCKED
    _authority: CapabilityAuthority = field(
        default_factory=CapabilityAuthority,
        repr=False,
        compare=False,
        kw_only=True,
    )

    def __post_init__(self) -> None:
        state = self._validated_state()
        if type(self._authority) is not CapabilityAuthority:
            raise EvaluationBoundaryError("final capability authority is invalid")
        self._authority._bind_final_state(state)

    def unlock(self) -> FinalCapabilityTerminal:
        """Return the sole valid successor of a locked capability."""

        if self._validated_state() is not FinalCapabilityState.LOCKED:
            raise EvaluationBoundaryError(
                "final capability unlock transition is invalid"
            )
        self._authority._transition_final(
            FinalCapabilityState.LOCKED,
            FinalCapabilityState.UNLOCKED,
            message="final capability unlock transition is invalid",
        )
        return FinalCapabilityTerminal(
            FinalCapabilityState.UNLOCKED,
            _authority=self._authority,
        )

    def consume(self) -> FinalCapabilityTerminal:
        """Return the terminal successor of an unlocked capability."""

        if self._validated_state() is not FinalCapabilityState.UNLOCKED:
            raise EvaluationBoundaryError(
                "final capability consume transition is invalid"
            )
        self._authority._transition_final(
            FinalCapabilityState.UNLOCKED,
            FinalCapabilityState.CONSUMED,
            message="final capability consume transition is invalid",
        )
        return FinalCapabilityTerminal(
            FinalCapabilityState.CONSUMED,
            _authority=self._authority,
        )

    def allow_research_action(
        self,
        action: FinalResearchAction,
    ) -> FinalResearchAction:
        """Fail closed for untyped actions and every action after final unlock."""

        state = self._validated_state()
        if type(action) is not FinalResearchAction:
            raise EvaluationBoundaryError("final research action is invalid")
        if self._authority._get_final_state() is not FinalCapabilityState.LOCKED:
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

    __slots__ = ("_authority", "_grants", "_resources")

    def __init__(
        self,
        grants: Mapping[str, CapabilityGrant],
        resources: SplitGrantRegistry,
        *,
        authority: CapabilityAuthority | None = None,
        runtime_locks: Mapping[str, VerifiedRuntimeLock] | None = None,
    ) -> None:
        if not isinstance(grants, Mapping):
            raise EvaluationBoundaryError("capability grant registry is invalid")
        if not isinstance(resources, SplitGrantRegistry):
            raise EvaluationBoundaryError("split resource registry is invalid")
        copied = dict(grants)
        if authority is not None and type(authority) is not CapabilityAuthority:
            raise EvaluationBoundaryError("capability authority is invalid")
        if runtime_locks is not None and not isinstance(runtime_locks, Mapping):
            raise EvaluationBoundaryError("runtime lock registry is invalid")
        copied_runtime_locks = dict(runtime_locks or {})
        if any(
            grant_id not in copied or type(runtime_lock) is not VerifiedRuntimeLock
            for grant_id, runtime_lock in copied_runtime_locks.items()
        ):
            raise EvaluationBoundaryError("runtime lock registry is invalid")
        shared_authority = authority or CapabilityAuthority()
        shared_authority._register_grants(copied)
        shared_authority._register_runtime_locks(copied_runtime_locks)
        self._authority = shared_authority
        self._grants = MappingProxyType(copied)
        self._resources = resources

    def __repr__(self) -> str:
        return f"EvaluationBroker(grants={len(self._grants)})"

    @property
    def authority(self) -> CapabilityAuthority:
        """Return the shareable in-process authority used by this broker."""

        return self._authority

    def query_count(self, grant_id: str) -> int:
        """Return broker-owned execution-query consumption for one grant."""

        with self._authority._state_lock:
            if grant_id not in self._grants:
                raise EvaluationBoundaryError("capability grant is unavailable")
            return self._authority._query_counts[grant_id]

    def authorize_runtime(
        self,
        request: EvaluationRequest,
        *,
        runtime_lock: VerifiedRuntimeLock,
        principal: str,
        token: bytes,
    ) -> object:
        """Verify the live runtime before consuming launch authorization."""

        if type(runtime_lock) is not VerifiedRuntimeLock:
            raise EvaluationBoundaryError("runtime lock is invalid")
        if type(request) is not EvaluationRequest:
            raise EvaluationBoundaryError("evaluation request is invalid")
        if request.capability_grant_id not in self._grants:
            raise EvaluationBoundaryError("capability grant is unavailable")
        self._authority._require_runtime_lock(
            request.capability_grant_id,
            runtime_lock,
        )
        runtime_lock.verify()
        return self.authorize(request, principal=principal, token=token)

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
        with self._authority._state_lock:
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

            count = self._authority._query_counts[request.capability_grant_id]
            if count >= grant.query_limit:
                raise EvaluationBoundaryError("capability query budget is exhausted")
            resource = self._resources.resolve(request)
            if isinstance(
                resource,
                (str, bytes, bytearray, memoryview, os.PathLike),
            ):
                raise EvaluationBoundaryError("split resource must be opaque")

            self._authority._query_counts[request.capability_grant_id] = count + 1
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
    "CapabilityAuthority",
    "CapabilityGrant",
    "EvaluationBroker",
    "FinalCapabilityState",
    "FinalCapabilityTerminal",
    "FinalResearchAction",
    "SplitGrant",
    "SplitGrantRegistry",
]
