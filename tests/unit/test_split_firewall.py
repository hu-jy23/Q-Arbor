from __future__ import annotations

from pathlib import Path

import pytest

from q_arbor.evaluation import EvaluationBoundaryError, EvaluationRequest
from q_arbor.firewall import SplitGrant, SplitGrantRegistry
from tests.evaluation_helpers import make_request, validated_synthetic_components


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
