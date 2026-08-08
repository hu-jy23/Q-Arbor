"""Exact upward, scope-aware insight propagation."""

from __future__ import annotations

from typing import Final, cast

from .codec import JSONValue, canonical_normalized_bytes
from .errors import (
    TreeCompatibilityError,
    TreeConflictError,
)
from .invariants import compatibility_quarantined, require_identifier
from .models import QHypothesisTree, QuantHypothesisNode, validate_node

_SCOPE_MATCH_FIELDS: Final = (
    "market",
    "universe",
    "frequency",
    "horizon",
    "data_snapshot_sha256",
    "cost_model_sha256",
)


def _same_json(left: dict[str, JSONValue], right: dict[str, JSONValue]) -> bool:
    return canonical_normalized_bytes(left) == canonical_normalized_bytes(right)


def _require_ancestor(
    tree: QHypothesisTree, source_node_id: str, target_node_id: str
) -> None:
    current = tree.get_node(source_node_id).parent_id
    while current is not None:
        if current == target_node_id:
            return
        current = tree.get_node(current).parent_id
    raise TreeConflictError("insight propagation target must be a strict ancestor")


def prepare_insight_propagation(
    tree: QHypothesisTree,
    source_node_id: str,
    target_node_id: str,
    insight_id: str,
    *,
    event_id: str,
) -> QuantHypothesisNode | None:
    """Return the complete changed target node, or ``None`` for an exact replay."""

    require_identifier(source_node_id, "propagation source_node_id")
    require_identifier(target_node_id, "propagation target_node_id")
    require_identifier(insight_id, "propagation insight_id")
    require_identifier(event_id, "propagation event_id")
    if compatibility_quarantined(tree.to_dict()):
        raise TreeCompatibilityError(
            "compatibility-quarantined state cannot propagate insights"
        )
    try:
        source = tree.get_node(source_node_id)
        target = tree.get_node(target_node_id)
    except KeyError as exc:
        raise TreeConflictError("propagation node does not exist") from exc
    if source_node_id == target_node_id:
        raise TreeConflictError("an insight cannot propagate to its source node")
    _require_ancestor(tree, source_node_id, target_node_id)

    # C5 G09 / C6 J04: identity-critical market, data, and cost scope must match;
    # optional time/field/regime conditions stay attached to the original record.
    source_scope = source.scope
    target_scope = target.scope
    if any(source_scope[field] != target_scope[field] for field in _SCOPE_MATCH_FIELDS):
        raise TreeConflictError("insight propagation scope does not match")

    source_mapping = source.to_dict()
    target_mapping = target.to_dict()
    source_insights = cast(list[dict[str, JSONValue]], source_mapping["insights"])
    matching = [item for item in source_insights if item["insight_id"] == insight_id]
    if len(matching) != 1:
        raise TreeConflictError("source insight does not exist")
    insight = matching[0]
    if insight["validity"] != "active" or insight["grade"] == "contradicted":
        raise TreeConflictError("only an active non-contradicted insight may propagate")
    if source.admissibility == "contaminated":
        raise TreeConflictError("contaminated source state cannot propagate insights")

    source_evidence = {
        cast(str, evidence["evidence_id"]): evidence
        for evidence in cast(
            list[dict[str, JSONValue]], source_mapping["evidence_refs"]
        )
    }
    evidence_ids = cast(list[str], insight["evidence_ids"])
    if any(
        evidence_id not in source_evidence
        or source_evidence[evidence_id]["status"] != "valid"
        for evidence_id in evidence_ids
    ):
        # C5 G05/G09 and C6 J05: invalidated or contaminated evidence remains
        # recorded but cannot become active upstream research memory.
        raise TreeConflictError("insight evidence is not valid for propagation")

    target_insights = cast(list[dict[str, JSONValue]], target_mapping["insights"])
    existing_insight = next(
        (item for item in target_insights if item["insight_id"] == insight_id), None
    )
    if existing_insight is not None:
        if not _same_json(existing_insight, insight):
            raise TreeConflictError("insight ID already identifies different content")
        return None

    target_evidence = cast(list[dict[str, JSONValue]], target_mapping["evidence_refs"])
    target_evidence_by_id = {
        cast(str, evidence["evidence_id"]): evidence for evidence in target_evidence
    }
    for evidence_id in evidence_ids:
        evidence = source_evidence[evidence_id]
        existing = target_evidence_by_id.get(evidence_id)
        if existing is not None and not _same_json(existing, evidence):
            raise TreeConflictError(
                "evidence ID already identifies different target content"
            )
        if existing is None:
            target_evidence.append(evidence)
            target_evidence_by_id[evidence_id] = evidence
    target_insights.append(insight)
    target_mapping["last_event_id"] = event_id
    return validate_node(target_mapping)
