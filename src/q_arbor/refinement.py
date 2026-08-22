"""Small callback seam for one C11 development refinement cycle."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from q_arbor.evaluation import EvaluationRequest, EvaluationResult
from q_arbor.evaluation.codec import (
    JSONValue,
    canonical_normalized_bytes,
    deep_freeze,
    normalize_mapping,
    require_identifier,
    require_sha256,
    validate_definition,
)
from q_arbor.evaluation.values import _ImmutableJSON
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


@dataclass(frozen=True, slots=True)
class DevelopmentCycleTrace:
    snapshot: PromptSnapshot
    request: EvaluationRequest
    result: EvaluationResult
    node: QuantHypothesisNode


def run_development_cycle(
    proposal: Mapping[str, Any],
    snapshot_mapping: Mapping[str, Any],
    dispatch_cb: Callable[[PromptSnapshot], EvaluationRequest],
    evaluate_cb: Callable[[EvaluationRequest], EvaluationResult],
    decide_cb: Callable[[EvaluationRequest, EvaluationResult], QuantHypothesisNode],
) -> DevelopmentCycleTrace:
    """Freeze and consume one development snapshot through typed callbacks."""

    snapshot = freeze_prompt_snapshot(snapshot_mapping)
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


__all__ = ["DevelopmentCycleTrace", "PromptSnapshot", "freeze_prompt_snapshot", "run_development_cycle"]
