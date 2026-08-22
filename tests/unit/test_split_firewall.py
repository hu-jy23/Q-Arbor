from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
from pathlib import Path

import pytest

from q_arbor.evaluation import EvaluationBoundaryError, EvaluationRequest
from q_arbor.firewall import (
    CapabilityGrant,
    EvaluationBroker,
    FinalCapabilityState,
    FinalCapabilityTerminal,
    FinalResearchAction,
    SplitGrant,
    SplitGrantRegistry,
)
from tests.evaluation_helpers import make_request, validated_synthetic_components


_CAPABILITY_TOKEN = b"qualification capability token"


def _development_request_and_manifest(tmp_path: Path) -> tuple[EvaluationRequest, str]:
    _, _, contract, _, receipt = validated_synthetic_components(tmp_path / "case")
    request = make_request(contract, receipt)
    manifest = contract.to_dict()["data"]["splits"]["development"][
        "manifest_sha256"
    ]
    return request, manifest


def test_development_request_cannot_resolve_gate_grant(tmp_path: Path) -> None:
    _, _, contract, _, receipt = validated_synthetic_components(tmp_path / "case")
    request = make_request(
        contract,
        receipt,
        capability_grant_id="grant.gate.qualification",
    )
    gate_manifest = contract.to_dict()["data"]["splits"]["gate"][
        "manifest_sha256"
    ]
    gate_handle = object()
    registry = SplitGrantRegistry(
        {
            "grant.gate.qualification": SplitGrant(
                split_role="gate",
                split_manifest_hash=gate_manifest,
                resource=gate_handle,
            )
        }
    )

    with pytest.raises(EvaluationBoundaryError, match="split role"):
        registry.resolve(request)


def test_matching_split_grant_returns_bound_resource(tmp_path: Path) -> None:
    request, manifest = _development_request_and_manifest(tmp_path)
    handle = object()
    registry = SplitGrantRegistry(
        {
            request.capability_grant_id: SplitGrant(
                split_role="development",
                split_manifest_hash=manifest,
                resource=handle,
            )
        }
    )

    assert registry.resolve(request) is handle


def test_split_grant_resolution_rejects_unknown_grant(tmp_path: Path) -> None:
    request, manifest = _development_request_and_manifest(tmp_path)
    registry = SplitGrantRegistry(
        {
            "grant.other.qualification": SplitGrant(
                split_role="development",
                split_manifest_hash=manifest,
                resource=object(),
            )
        }
    )

    with pytest.raises(EvaluationBoundaryError, match="unavailable"):
        registry.resolve(request)


def test_split_grant_resolution_rejects_manifest_mismatch(tmp_path: Path) -> None:
    request, _ = _development_request_and_manifest(tmp_path)
    registry = SplitGrantRegistry(
        {
            request.capability_grant_id: SplitGrant(
                split_role="development",
                split_manifest_hash="0" * 64,
                resource=object(),
            )
        }
    )

    with pytest.raises(EvaluationBoundaryError, match="split manifest"):
        registry.resolve(request)


def _capability_grant(
    request: EvaluationRequest,
    *,
    query_limit: int = 2,
) -> CapabilityGrant:
    return CapabilityGrant(
        grant_id=request.capability_grant_id,
        run_id=request.run_id,
        contract_hash=request.contract_hash,
        role=request.split_role,
        principal="executor",
        query_limit=query_limit,
        query_count=0,
        state="active",
        token_digest=sha256(_CAPABILITY_TOKEN).hexdigest(),
        issued_event_id="event.grant.qualification",
    )


def _broker(
    request: EvaluationRequest,
    manifest: str,
    resource: object,
    *,
    capability: CapabilityGrant | None = None,
) -> EvaluationBroker:
    grant = capability or _capability_grant(request)
    return EvaluationBroker(
        {request.capability_grant_id: grant},
        SplitGrantRegistry(
            {
                request.capability_grant_id: SplitGrant(
                    split_role=request.split_role,
                    split_manifest_hash=manifest,
                    resource=resource,
                )
            }
        ),
    )


def test_broker_rejects_forged_grant_without_spending_budget(
    tmp_path: Path,
) -> None:
    request, manifest = _development_request_and_manifest(tmp_path)
    forged = replace(
        _capability_grant(request),
        grant_id="grant.forged.qualification",
    )
    broker = _broker(request, manifest, object(), capability=forged)

    with pytest.raises(EvaluationBoundaryError, match="grant identity"):
        broker.authorize(
            request,
            principal="executor",
            token=_CAPABILITY_TOKEN,
        )

    assert broker.query_count(request.capability_grant_id) == 0


def test_broker_rejects_forged_token_without_spending_budget(
    tmp_path: Path,
) -> None:
    request, manifest = _development_request_and_manifest(tmp_path)
    broker = _broker(request, manifest, object())

    with pytest.raises(EvaluationBoundaryError, match="capability"):
        broker.authorize(
            request,
            principal="executor",
            token=b"forged capability token",
        )

    assert broker.query_count(request.capability_grant_id) == 0


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("run_id", "run.other", "run"),
        ("contract_hash", "0" * 64, "contract"),
        ("role", "gate", "split role"),
    ],
)
def test_broker_rejects_grant_identity_mismatch_without_spending_budget(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    request, manifest = _development_request_and_manifest(tmp_path)
    capability = replace(_capability_grant(request), **{field: value})
    broker = _broker(request, manifest, object(), capability=capability)

    with pytest.raises(EvaluationBoundaryError, match=message):
        broker.authorize(
            request,
            principal="executor",
            token=_CAPABILITY_TOKEN,
        )

    assert broker.query_count(request.capability_grant_id) == 0


def test_broker_rejects_principal_mismatch_without_spending_budget(
    tmp_path: Path,
) -> None:
    request, manifest = _development_request_and_manifest(tmp_path)
    broker = _broker(request, manifest, object())

    with pytest.raises(EvaluationBoundaryError, match="principal"):
        broker.authorize(
            request,
            principal="coordinator",
            token=_CAPABILITY_TOKEN,
        )

    assert broker.query_count(request.capability_grant_id) == 0


def test_broker_rejects_manifest_mismatch_without_spending_budget(
    tmp_path: Path,
) -> None:
    request, _ = _development_request_and_manifest(tmp_path)
    broker = _broker(request, "0" * 64, object())

    with pytest.raises(EvaluationBoundaryError, match="split manifest"):
        broker.authorize(
            request,
            principal="executor",
            token=_CAPABILITY_TOKEN,
        )

    assert broker.query_count(request.capability_grant_id) == 0


def test_broker_rejects_direct_path_resource_without_spending_budget(
    tmp_path: Path,
) -> None:
    request, manifest = _development_request_and_manifest(tmp_path)
    raw_path = tmp_path / "restricted" / "development.json"
    broker = _broker(request, manifest, raw_path)

    with pytest.raises(EvaluationBoundaryError, match="opaque") as error:
        broker.authorize(
            request,
            principal="executor",
            token=_CAPABILITY_TOKEN,
        )

    assert str(raw_path) not in str(error.value)
    assert str(raw_path) not in repr(broker)
    assert broker.query_count(request.capability_grant_id) == 0


def test_broker_rejects_path_escape_resource_without_spending_budget(
    tmp_path: Path,
) -> None:
    request, manifest = _development_request_and_manifest(tmp_path)
    escaped_path = "allowed/../final/hidden.json"
    broker = _broker(request, manifest, escaped_path)

    with pytest.raises(EvaluationBoundaryError, match="opaque") as error:
        broker.authorize(
            request,
            principal="executor",
            token=_CAPABILITY_TOKEN,
        )

    assert escaped_path not in str(error.value)
    assert escaped_path not in repr(broker)
    assert broker.query_count(request.capability_grant_id) == 0


def test_broker_allow_returns_opaque_resource_and_consumes_one_query(
    tmp_path: Path,
) -> None:
    request, manifest = _development_request_and_manifest(tmp_path)
    handle = object()
    broker = _broker(request, manifest, handle)

    assert broker.query_count(request.capability_grant_id) == 0
    assert (
        broker.authorize(
            request,
            principal="executor",
            token=_CAPABILITY_TOKEN,
        )
        is handle
    )
    assert broker.query_count(request.capability_grant_id) == 1


def test_broker_deny_after_allow_does_not_consume_another_query(
    tmp_path: Path,
) -> None:
    request, manifest = _development_request_and_manifest(tmp_path)
    broker = _broker(request, manifest, object())
    broker.authorize(
        request,
        principal="executor",
        token=_CAPABILITY_TOKEN,
    )

    with pytest.raises(EvaluationBoundaryError, match="principal"):
        broker.authorize(
            request,
            principal="coordinator",
            token=_CAPABILITY_TOKEN,
        )

    assert broker.query_count(request.capability_grant_id) == 1


def test_broker_rejects_query_budget_exhaustion(tmp_path: Path) -> None:
    request, manifest = _development_request_and_manifest(tmp_path)
    capability = _capability_grant(request, query_limit=1)
    broker = _broker(request, manifest, object(), capability=capability)
    broker.authorize(
        request,
        principal="executor",
        token=_CAPABILITY_TOKEN,
    )

    with pytest.raises(EvaluationBoundaryError, match="query budget"):
        broker.authorize(
            request,
            principal="executor",
            token=_CAPABILITY_TOKEN,
        )

    assert broker.query_count(request.capability_grant_id) == 1


def test_broker_keeps_final_sealed(tmp_path: Path) -> None:
    _, _, contract, _, receipt = validated_synthetic_components(tmp_path / "case")
    request = make_request(contract, receipt, split_role="final")
    manifest = contract.to_dict()["data"]["splits"]["final"]["manifest_sha256"]
    capability = replace(
        _capability_grant(request, query_limit=1),
        principal="finalizer",
    )
    broker = _broker(request, manifest, object(), capability=capability)

    with pytest.raises(EvaluationBoundaryError, match="final.*sealed"):
        broker.authorize(
            request,
            principal="finalizer",
            token=_CAPABILITY_TOKEN,
        )

    assert broker.query_count(request.capability_grant_id) == 0


def test_e4_final_capability_transitions_are_monotonic_immutable_values() -> None:
    locked = FinalCapabilityTerminal()

    unlocked = locked.unlock()
    consumed = unlocked.consume()

    assert locked.state is FinalCapabilityState.LOCKED
    assert unlocked.state is FinalCapabilityState.UNLOCKED
    assert consumed.state is FinalCapabilityState.CONSUMED
    assert locked is not unlocked
    assert unlocked is not consumed
    with pytest.raises(FrozenInstanceError):
        consumed.state = FinalCapabilityState.LOCKED  # type: ignore[misc]


@pytest.mark.parametrize(
    "state",
    [FinalCapabilityState.UNLOCKED, FinalCapabilityState.CONSUMED],
)
def test_e4_final_capability_rejects_duplicate_unlock(
    state: FinalCapabilityState,
) -> None:
    capability = FinalCapabilityTerminal(state=state)

    with pytest.raises(EvaluationBoundaryError, match="unlock transition"):
        capability.unlock()

    assert capability.state is state


def test_e4_final_capability_rejects_consume_before_unlock() -> None:
    locked = FinalCapabilityTerminal()

    with pytest.raises(EvaluationBoundaryError, match="consume transition"):
        locked.consume()

    assert locked.state is FinalCapabilityState.LOCKED


def test_e4_final_capability_rejects_duplicate_consume() -> None:
    consumed = FinalCapabilityTerminal(FinalCapabilityState.CONSUMED)

    with pytest.raises(EvaluationBoundaryError, match="consume transition"):
        consumed.consume()

    assert consumed.state is FinalCapabilityState.CONSUMED


@pytest.mark.parametrize("invalid_state", ["locked", None, object()])
def test_e4_final_capability_rejects_untyped_states(
    invalid_state: object,
) -> None:
    with pytest.raises(EvaluationBoundaryError, match="state is invalid"):
        FinalCapabilityTerminal(invalid_state)  # type: ignore[arg-type]


@pytest.mark.parametrize("state", list(FinalCapabilityState))
def test_e5_final_capability_rejects_untyped_research_actions(
    state: FinalCapabilityState,
) -> None:
    capability = FinalCapabilityTerminal(state)

    with pytest.raises(EvaluationBoundaryError, match="research action is invalid"):
        capability.allow_research_action("propose")  # type: ignore[arg-type]


@pytest.mark.parametrize("action", list(FinalResearchAction))
@pytest.mark.parametrize(
    "state",
    [FinalCapabilityState.UNLOCKED, FinalCapabilityState.CONSUMED],
)
def test_e5_final_unlock_freezes_research_actions(
    state: FinalCapabilityState,
    action: FinalResearchAction,
) -> None:
    capability = FinalCapabilityTerminal(state)

    with pytest.raises(EvaluationBoundaryError, match="research is frozen"):
        capability.allow_research_action(action)


@pytest.mark.parametrize("action", list(FinalResearchAction))
def test_e5_research_actions_remain_open_while_final_is_locked(
    action: FinalResearchAction,
) -> None:
    capability = FinalCapabilityTerminal(FinalCapabilityState.LOCKED)

    assert capability.allow_research_action(action) is action
