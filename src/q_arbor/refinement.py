"""Small callback seam for one C11 development refinement cycle."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from q_arbor.evaluation import EvaluationRequest, EvaluationResult
from q_arbor.evaluation.codec import (
    FrozenJSON,
    JSONValue,
    canonical_normalized_bytes,
    deep_freeze,
    normalize_mapping,
    require_identifier,
    require_sha256,
    validate_definition,
)
from q_arbor.evaluation.values import _ImmutableJSON
from q_arbor.generality import ControlPathOutcome
from q_arbor.hypotheses.models import QuantHypothesisNode


class PromptSnapshot(_ImmutableJSON):
    """Immutable value validated by the frozen C6 definition."""

    @classmethod
    def _freeze(cls, mapping: Mapping[str, Any]) -> PromptSnapshot:
        normalized = normalize_mapping(mapping)
        validate_definition(normalized, "PromptSnapshot")
        if normalized["phase"] != "dispatch":
            raise ValueError("only dispatch snapshots are supported")
        descriptor = normalized["development_evaluator_descriptor"]
        if descriptor.get("split_role") != "development":
            raise ValueError("snapshot must describe development evaluation")
        require_identifier(normalized["prompt_snapshot_id"], "prompt_snapshot_id")
        require_sha256(normalized["snapshot_hash"], "snapshot_hash")
        body = dict(normalized)
        declared = body.pop("snapshot_hash")
        digest = hashlib.sha256(canonical_normalized_bytes(body)).hexdigest()
        if declared != digest:
            raise ValueError("snapshot hash does not match canonical content")
        # Keep this explicit: the stored value is detached and deeply immutable.
        frozen = deep_freeze(normalized)
        return cls._from_normalized(normalized)

    @property
    def prompt_snapshot_id(self) -> str:
        return str(self._get("prompt_snapshot_id"))


def freeze_prompt_snapshot(mapping: Mapping[str, Any]) -> PromptSnapshot:
    return PromptSnapshot._freeze(mapping)


def refinement_signature(snapshot: PromptSnapshot) -> str:
    """Return the canonical identity of one frozen refinement context."""

    body = snapshot.to_dict()
    family_id = require_identifier(body["family_id"], "snapshot family_id")
    scope = body["scope"]
    if scope is None:
        raise ValueError("snapshot scope is required for refinement signature")
    user_prompt_sha256 = require_sha256(
        body["user_prompt_sha256"], "snapshot user_prompt_sha256"
    )
    return hashlib.sha256(canonical_normalized_bytes({
        "family_id": family_id,
        "scope": scope,
        "user_prompt_sha256": user_prompt_sha256,
    })).hexdigest()


def _proposal_set(proposal: Mapping[str, Any], field: str) -> list[str]:
    values = proposal.get(field, [])
    if not isinstance(values, list):
        raise ValueError(f"proposal {field} must be a list")
    return sorted({require_identifier(value, f"proposal {field} item") for value in values})


def _proposal_hash_set(proposal: Mapping[str, Any], field: str) -> list[str]:
    values = proposal.get(field, [])
    if not isinstance(values, list):
        raise ValueError(f"proposal {field} must be a list")
    return sorted({require_sha256(value, f"proposal {field} item") for value in values})


def _snapshot_set(snapshot: PromptSnapshot, field: str) -> set[str]:
    return {
        require_identifier(value, f"snapshot {field} item")
        for value in snapshot.to_dict()[field]
    }


@dataclass(frozen=True, slots=True)
class DevelopmentCycleTrace:
    snapshot: PromptSnapshot
    request: EvaluationRequest
    result: EvaluationResult
    node: QuantHypothesisNode


@dataclass(frozen=True, slots=True)
class ProductIntegrationTrace:
    """Existing development trace plus one B1 general-surface identity bridge."""

    cycle: DevelopmentCycleTrace
    general: ControlPathOutcome
    budget_query_count_before: int
    budget_query_count_after: int
    report: Mapping[str, FrozenJSON]
    report_sha256: str


def run_development_cycle(
    proposal: Mapping[str, Any],
    snapshot_mapping: Mapping[str, Any],
    dispatch_cb: Callable[[PromptSnapshot], EvaluationRequest],
    evaluate_cb: Callable[[EvaluationRequest], EvaluationResult],
    decide_cb: Callable[[EvaluationRequest, EvaluationResult], QuantHypothesisNode],
) -> DevelopmentCycleTrace:
    """Freeze and consume one development snapshot through typed callbacks."""

    snapshot = freeze_prompt_snapshot(snapshot_mapping)
    ancestors = _proposal_set(proposal, "ancestor_insight_ids")
    refuted = _proposal_set(proposal, "refuted_insight_ids")
    selected = _snapshot_set(snapshot, "selected_insight_ids")
    if selected & set(refuted):
        raise ValueError("selected and refuted insights overlap")
    if not set(ancestors).issubset(selected | set(refuted)):
        raise ValueError("proposal does not account for every ancestor insight")
    known_failed = _proposal_hash_set(proposal, "known_failed_signatures")
    if refinement_signature(snapshot) in known_failed:
        raise ValueError("proposal repeats a known failed refinement signature")
    node_id = require_identifier(proposal["node_id"], "proposal node_id")
    attempt_id = require_identifier(proposal["attempt_id"], "proposal attempt_id")
    expected_request_id = require_identifier(proposal["request_id"], "proposal request_id")
    expected_result_id = require_identifier(proposal["result_id"], "proposal result_id")
    request = dispatch_cb(snapshot)
    if request.node_id != node_id or request.attempt_id != attempt_id:
        raise ValueError("dispatch changed node or attempt identity")
    if request.request_id != expected_request_id or request.split_role != "development":
        raise ValueError("dispatch returned an incompatible request")
    result = evaluate_cb(request)
    if result.request_id != request.request_id or result.result_id != expected_result_id:
        raise ValueError("evaluation changed request or result identity")
    node = decide_cb(request, result)
    if node.id != node_id or attempt_id not in node.attempt_ids:
        raise ValueError("decision changed node or attempt identity")
    if not any(ref.get("result_id") == result.result_id for ref in node.evidence_refs):
        raise ValueError("decision did not retain the evaluated result identity")
    return DevelopmentCycleTrace(snapshot, request, result, node)


def run_product_integration_cycle(
    proposal: Mapping[str, Any],
    snapshot_mapping: Mapping[str, Any],
    dispatch_cb: Callable[[PromptSnapshot], EvaluationRequest],
    general_evaluate_cb: Callable[[EvaluationRequest], ControlPathOutcome],
    project_result_cb: Callable[
        [EvaluationRequest, ControlPathOutcome], EvaluationResult
    ],
    decide_cb: Callable[[EvaluationRequest, EvaluationResult], QuantHypothesisNode],
    *,
    query_count_cb: Callable[[], int],
) -> ProductIntegrationTrace:
    """Bridge the existing refinement cycle to B1 surfaces without new states.

    The existing callbacks retain ownership of capability authorization, Idea Tree
    mutations, evidence ledger events, and C6-compatible result projection.  This
    seam verifies that exactly one existing query budget unit is consumed and that
    the general result/provenance/artifacts remain bound to those product identities.
    """

    budget_before = query_count_cb()
    if type(budget_before) is not int or budget_before < 0:
        raise ValueError("query budget counter is invalid")
    holder: dict[str, object] = {}

    def evaluate(request: EvaluationRequest) -> EvaluationResult:
        outcome = general_evaluate_cb(request)
        if not isinstance(outcome, ControlPathOutcome):
            raise ValueError("general evaluation did not return a control-path outcome")
        if outcome.result.invocation_id != request.request_id:
            raise ValueError("general evaluation changed request identity")
        if outcome.result.provenance.candidate_sha256 != request.candidate_hash:
            raise ValueError("general provenance changed candidate identity")
        if outcome.decision.get("selection_eligible") is not True:
            raise ValueError("general result is not eligible for development decision")
        projected = project_result_cb(request, outcome)
        if not isinstance(projected, EvaluationResult):
            raise ValueError("general result projection is not a C6 EvaluationResult")
        general_refs = [ref.to_dict() for ref in outcome.result.output_artifact_refs]
        projected_refs = [ref.to_dict() for ref in projected.artifacts]
        if canonical_normalized_bytes(general_refs) != canonical_normalized_bytes(
            projected_refs
        ):
            raise ValueError("general and projected result artifacts differ")
        result_mapping = outcome.result.to_dict()
        decision_objective_id = result_mapping["decision_objective_id"]
        objectives = cast(list[dict[str, JSONValue]], result_mapping["objective_vector"])
        primary = next(
            (
                item
                for item in objectives
                if item["objective_id"] == decision_objective_id
            ),
            None,
        )
        if primary is None or (
            primary["value"] != projected.primary_metric.value
            or primary["direction"] != projected.primary_metric.direction
        ):
            raise ValueError("general and projected decision objectives differ")
        holder["outcome"] = outcome
        return projected

    cycle = run_development_cycle(
        proposal,
        snapshot_mapping,
        dispatch_cb,
        evaluate,
        decide_cb,
    )
    budget_after = query_count_cb()
    if type(budget_after) is not int or budget_after != budget_before + 1:
        raise ValueError("development cycle must consume exactly one query budget unit")
    outcome = holder.get("outcome")
    if not isinstance(outcome, ControlPathOutcome):
        raise ValueError("development cycle did not retain the general outcome")
    snapshot = cycle.snapshot.to_dict()
    capability_grant_id = snapshot["capability_grant_id"]
    if capability_grant_id != cycle.request.capability_grant_id:
        raise ValueError("snapshot and request capability identities differ")
    evidence = next(
        (
            ref
            for ref in cycle.node.evidence_refs
            if ref.get("result_id") == cycle.result.result_id
        ),
        None,
    )
    if evidence is None:
        raise ValueError("product decision lost its result evidence")
    report_mapping: dict[str, JSONValue] = {
        "node_id": cycle.node.id,
        "attempt_id": cycle.request.attempt_id,
        "request_id": cycle.request.request_id,
        "result_id": cycle.result.result_id,
        "general_result_id": outcome.result.result_id,
        "general_result_sha256": outcome.result.sha256,
        "runner_receipt_sha256": outcome.receipt.sha256,
        "provenance_sha256": outcome.result.provenance.sha256,
        "general_transcript_sha256": outcome.transcript_sha256,
        "evidence_id": cast(str, evidence["evidence_id"]),
        "capability_grant_id": cast(str, capability_grant_id),
        "budget_query_count_before": budget_before,
        "budget_query_count_after": budget_after,
        "code_ref": cast(str | None, snapshot["branch"]),
        "artifact_refs": [ref.to_dict() for ref in cycle.result.artifacts],
    }
    report_sha256 = hashlib.sha256(
        canonical_normalized_bytes(report_mapping)
    ).hexdigest()
    return ProductIntegrationTrace(
        cycle=cycle,
        general=outcome,
        budget_query_count_before=budget_before,
        budget_query_count_after=budget_after,
        report=cast(Mapping[str, FrozenJSON], deep_freeze(report_mapping)),
        report_sha256=report_sha256,
    )


__all__ = [
    "DevelopmentCycleTrace", "ProductIntegrationTrace", "PromptSnapshot",
    "freeze_prompt_snapshot", "refinement_signature", "run_development_cycle",
    "run_product_integration_cycle",
]
