from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from q_arbor.evaluation import (
    EvaluationIntegrityError,
    ReasonCode,
    freeze_evaluation_result,
    make_access_denied_result,
    validate_evaluation_evidence,
)
from q_arbor.hypotheses import QuantHypothesisNode, freeze_node
from tests.evaluation_helpers import synthetic_case
from tests.hypothesis_helpers import valid_node_mapping, valid_tree_draft_mapping


def _running_node(case: Any, **updates: Any) -> QuantHypothesisNode:
    mapping = valid_node_mapping()
    mapping.update(
        id=case.request.node_id,
        status="running",
        lifecycle="running",
        admissibility="unevaluated",
        score=None,
        candidate_id="candidate.qualification",
        candidate_artifact=case.request.candidate.to_dict(),
        attempt_ids=[case.request.attempt_id],
        evidence_refs=[],
        insights=[],
    )
    mapping["scope"]["data_snapshot_sha256"] = case.result.provenance[
        "data_snapshot_sha256"
    ]
    mapping["scope"]["cost_model_sha256"] = case.result.costs["cost_model_sha256"]
    mapping.update(updates)
    return freeze_node(mapping)


def _scored_node(case: Any, score: float) -> QuantHypothesisNode:
    mapping = copy.deepcopy(valid_tree_draft_mapping()["nodes"][1])
    mapping["id"] = case.request.node_id
    mapping["candidate_id"] = "candidate.qualification"
    mapping["candidate_artifact"] = case.request.candidate.to_dict()
    mapping["attempt_ids"] = [case.request.attempt_id]
    mapping["score"] = score
    mapping["scope"]["data_snapshot_sha256"] = case.result.provenance[
        "data_snapshot_sha256"
    ]
    mapping["scope"]["cost_model_sha256"] = case.result.costs["cost_model_sha256"]
    for insight in mapping["insights"]:
        insight["scope"] = copy.deepcopy(mapping["scope"])
    mapping["evidence_refs"][0]["attempt_id"] = case.request.attempt_id
    mapping["evidence_refs"][0]["result_id"] = "result.preexisting.support"
    mapping["evidence_refs"][0]["artifact_refs"] = []
    return freeze_node(mapping)


def _evidence(case: Any, **updates: Any) -> dict[str, Any]:
    mapping = {
        "evidence_id": "evidence.qualification",
        "attempt_id": case.request.attempt_id,
        "result_id": case.result.result_id,
        "split_role": case.result.split_role,
        "level": "observed",
        "claim": "The frozen development result supports this exact candidate.",
        "conditions": ["frozen snapshot", "frozen cost model"],
        "status": "valid",
        "artifact_refs": [item.to_dict() for item in case.result.artifacts],
    }
    mapping.update(updates)
    return mapping


def test_c8_evidence_binding_succeeds_without_mutating_node_or_result(
    tmp_path: Path,
) -> None:
    case = synthetic_case(tmp_path / "case")
    node = _running_node(case)
    evidence = _evidence(case)
    node_before = node.to_json()
    result_before = case.result.to_json()

    assert (
        validate_evaluation_evidence(
            case.result,
            request=case.request,
            node=node,
            evidence=evidence,
        )
        is None
    )

    assert node.to_json() == node_before
    assert case.result.to_json() == result_before
    assert node.status == "running"
    assert node.score is None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(result_id="result.wrong"),
        lambda value: value.update(attempt_id="attempt.wrong"),
        lambda value: value.update(split_role="gate"),
        lambda value: value.update(level="inferred"),
        lambda value: value.update(status="invalidated"),
    ],
)
def test_c8_evidence_identity_level_and_status_mismatch_fail_closed(
    tmp_path: Path, mutation: Callable[[dict[str, Any]], None]
) -> None:
    case = synthetic_case(tmp_path / "case")
    node = _running_node(case)
    evidence = _evidence(case)
    mutation(evidence)
    before = node.to_json()

    with pytest.raises(EvaluationIntegrityError):
        validate_evaluation_evidence(
            case.result,
            request=case.request,
            node=node,
            evidence=evidence,
        )

    assert node.to_json() == before
    assert node.score is None


def test_c8_evidence_artifact_set_must_be_byte_identical(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    node = _running_node(case)
    evidence = _evidence(case)
    if evidence["artifact_refs"]:
        evidence["artifact_refs"][0]["sha256"] = "f" * 64
    else:
        evidence["artifact_refs"].append(
            {
                "artifact_id": "artifact.forged",
                "kind": "q-arbor.aggregate-metrics.v1",
                "relative_path": "artifacts/evaluations/forged.json",
                "sha256": "f" * 64,
                "media_type": "application/json",
            }
        )

    with pytest.raises(EvaluationIntegrityError):
        validate_evaluation_evidence(
            case.result,
            request=case.request,
            node=node,
            evidence=evidence,
        )


@pytest.mark.parametrize("mismatch", ["node_id", "attempt_id", "candidate"])
def test_c8_node_request_attempt_and_candidate_binding_are_exact(
    tmp_path: Path, mismatch: str
) -> None:
    case = synthetic_case(tmp_path / "case")
    updates: dict[str, Any]
    if mismatch == "node_id":
        updates = {"id": "node.wrong"}
    elif mismatch == "attempt_id":
        updates = {"attempt_ids": ["attempt.wrong"]}
    else:
        candidate_artifact = case.request.candidate.to_dict()
        candidate_artifact["sha256"] = "f" * 64
        updates = {"candidate_artifact": candidate_artifact}
    node = _running_node(case, **updates)

    with pytest.raises(EvaluationIntegrityError):
        validate_evaluation_evidence(
            case.result,
            request=case.request,
            node=node,
            evidence=_evidence(case),
        )


@pytest.mark.parametrize("scope_field", ["data_snapshot_sha256", "cost_model_sha256"])
def test_c8_node_scope_hashes_bind_result_provenance_and_costs(
    tmp_path: Path, scope_field: str
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = _running_node(case).to_dict()
    mapping["scope"][scope_field] = "f" * 64
    node = freeze_node(mapping)

    with pytest.raises(EvaluationIntegrityError):
        validate_evaluation_evidence(
            case.result,
            request=case.request,
            node=node,
            evidence=_evidence(case),
        )


def test_existing_node_score_must_equal_result_primary_exactly(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    matching = _scored_node(case, case.result.primary_metric.value)
    mismatched = _scored_node(case, case.result.primary_metric.value + 0.001)

    validate_evaluation_evidence(
        case.result,
        request=case.request,
        node=matching,
        evidence=_evidence(case),
    )
    with pytest.raises(EvaluationIntegrityError):
        validate_evaluation_evidence(
            case.result,
            request=case.request,
            node=mismatched,
            evidence=_evidence(case),
        )


@pytest.mark.parametrize("score", [-0.00075, 0.0])
def test_c8_evidence_accepts_finite_negative_and_zero_scores(
    tmp_path: Path, score: float
) -> None:
    case = synthetic_case(tmp_path / "case", signal_column="null_signal")
    if score == 0.0:
        mapping = case.result.to_dict()
        mapping["primary_metric"]["value"] = 0.0
        for diagnostic in mapping["diagnostics"]:
            diagnostic["value"] = 0.0
        for fold in mapping["fold_metrics"]:
            for metric in fold["metrics"]:
                metric["value"] = 0.0
        mapping["costs"].update(
            gross=0.0,
            transaction_cost=0.0,
            net=0.0,
            turnover=0.0,
        )
        case = replace(
            case,
            result=freeze_evaluation_result(mapping, binding=case.binding),
        )
    node = _scored_node(case, score)

    validate_evaluation_evidence(
        case.result,
        request=case.request,
        node=node,
        evidence=_evidence(case),
    )
    assert node.score == score


@pytest.mark.parametrize(
    ("status", "failure_type"),
    [
        ("invalid_candidate", "constraint_violation"),
        ("implementation_failure", "implementation_failure"),
        ("access_denied", "access_denied"),
        ("evaluation_failure", "evaluation_failure"),
        ("incomparable", "incomparable"),
        ("contaminated", "contamination"),
    ],
)
def test_no_non_success_result_can_become_valid_observed_c8_evidence(
    tmp_path: Path, status: str, failure_type: str
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = make_access_denied_result(
        binding=case.binding,
        reason_code=ReasonCode.parse("qualification.non_success"),
    ).to_dict()
    mapping["status"] = status
    mapping["failure"]["failure_type"] = failure_type
    if failure_type == "constraint_violation":
        mapping["constraints"][0].update(
            status="fail",
            evidence="constraint.failed",
        )
    result = freeze_evaluation_result(mapping, binding=case.binding)
    case = replace(case, result=result)
    node = _running_node(case)

    with pytest.raises(EvaluationIntegrityError):
        validate_evaluation_evidence(
            result,
            request=case.request,
            node=node,
            evidence=_evidence(case),
        )
    assert node.score is None
