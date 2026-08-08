"""Cross-field invariants for C8 hypothesis nodes and trees."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any, Final, cast

from .codec import JSONValue, canonical_normalized_bytes
from .errors import HypothesisInvariantError

_IDENTIFIER_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}")
_SHA256_RE: Final = re.compile(r"[a-f0-9]{64}")
_GLOB_META: Final = frozenset("*?[")
_STATUS_COMPONENTS: Final = {
    "pending": ("pending", "unevaluated"),
    "running": ("running", "unevaluated"),
    "needs_retry": ("needs_retry", "unevaluated"),
    "done": ("done", "admissible"),
    "merged": ("merged", "admissible"),
    "invalid": ("done", "invalid"),
    "contaminated": ("done", "contaminated"),
    "incomparable": ("done", "incomparable"),
}
_SCOPE_MATCH_FIELDS: Final = (
    "market",
    "universe",
    "frequency",
    "horizon",
    "data_snapshot_sha256",
    "cost_model_sha256",
)
_COMPATIBILITY_KEYS: Final = frozenset(
    {
        "source",
        "source_version",
        "quarantined",
        "missing_fields_by_node",
        "legacy_scores_by_node",
        "legacy_status_by_node",
        "safe_meta",
        "dropped_meta_keys",
    }
)
_LEGACY_SCORE_KEYS: Final = frozenset(
    {"score", "score_source", "score_split", "test_score"}
)
_LEGACY_STATUS_KEYS: Final = frozenset(
    {
        "status",
        "eval_status",
        "stop_reason",
        "attempt",
        "result_sha256",
        "insight_sha256",
        "code_ref_sha256",
        "related_work_sha256",
        "grounding_sha256",
    }
)
_LEGACY_STATUS_OPTIONAL_KEYS: Final = frozenset({"source_parent_id", "source_depth"})
_COMPATIBILITY_MISSING_LABELS: Final = frozenset(
    {
        "hypothesis.mechanism",
        "hypothesis.falsifiable_prediction",
        "hypothesis.observable",
        "hypothesis.single_change",
        "hypothesis.conflicts",
        "scope.market",
        "scope.universe",
        "scope.frequency",
        "scope.horizon",
        "scope.time_range",
        "scope.fields",
        "scope.regime_labels",
        "scope.data_snapshot_sha256",
        "scope.cost_model_sha256",
        "family",
        "candidate_id",
        "candidate_artifact",
        "attempt_ids",
        "evidence_refs",
        "test_family_refs",
        "lineage_refs",
        "prompt_snapshot_sha256",
        "score.evidence_binding",
        "test_score.evidence_binding",
        "insights.evidence_binding",
        "code_ref.trust_binding",
        "source.id",
        "source.parent_id",
        "source.children_ids",
        "source.depth",
        "source.parent_id_normalized",
        "source.depth_normalized",
        "synthetic_compatibility_root",
    }
)
_KNOWN_DROPPED_META_KEYS: Final = frozenset(
    {
        "metric_direction",
        "max_depth",
        "baseline_score",
        "trunk_score",
        "test_baseline_score",
        "test_trunk_score",
        "eval_cmd",
        "eval_cmd_test",
        "eval_timeout",
        "eval_retries",
        "eval_retry_base_delay",
        "eval_retry_max_delay",
        "dataset_info",
        "submission_path",
        "sample_submission_path",
    }
)
_UNKNOWN_DROPPED_META_RE: Final = re.compile(r"unknown-sha256:[a-f0-9]{64}")


def require_identifier(value: Any, field: str) -> str:
    """Return a strict C6 identifier, closing the schema ``$`` newline seam."""

    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise HypothesisInvariantError(f"{field} is not a strict identifier")
    return value


def require_sha256(value: Any, field: str) -> str:
    """Return a strict lowercase SHA-256 digest."""

    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise HypothesisInvariantError(f"{field} is not a strict SHA-256 digest")
    return value


def _require_optional_identifier(value: Any, field: str) -> None:
    if value is not None:
        require_identifier(value, field)


def _require_optional_sha256(value: Any, field: str) -> None:
    if value is not None:
        require_sha256(value, field)


def _validate_relative_artifact_path(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise HypothesisInvariantError(f"{field} must be a repository-relative path")
    if value != value.strip() or value.endswith("/"):
        raise HypothesisInvariantError(f"{field} is not a canonical path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise HypothesisInvariantError(f"{field} contains a control character")
    if value.startswith(("/", "~", "./", "../")) or "://" in value:
        raise HypothesisInvariantError(f"{field} is not a safe relative path")
    if "\\" in value or re.match(r"^[A-Za-z]:", value):
        raise HypothesisInvariantError(f"{field} is not a safe relative path")
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise HypothesisInvariantError(f"{field} is not a canonical path")
    if any(character in value for character in _GLOB_META):
        raise HypothesisInvariantError(f"{field} must identify one literal artifact")
    if len(value.encode("utf-8")) > 4095 or any(
        len(segment.encode("utf-8")) > 255 for segment in segments
    ):
        raise HypothesisInvariantError(f"{field} exceeds repository path limits")


def _validate_artifact_ref(value: Mapping[str, JSONValue], field: str) -> None:
    require_identifier(value["artifact_id"], f"{field}.artifact_id")
    require_sha256(value["sha256"], f"{field}.sha256")
    _validate_relative_artifact_path(value["relative_path"], f"{field}.relative_path")
    _require_optional_identifier(
        value.get("produced_by_event_id"), f"{field}.produced_by_event_id"
    )


def _validate_scope(scope: Mapping[str, JSONValue], field: str) -> None:
    # C5 G02/G09 and C6 J04: PIT data and cost identities remain part of the
    # exact scope carried by every node and insight.
    require_sha256(scope["data_snapshot_sha256"], f"{field}.data_snapshot_sha256")
    require_sha256(scope["cost_model_sha256"], f"{field}.cost_model_sha256")


def _same_json(left: Mapping[str, JSONValue], right: Mapping[str, JSONValue]) -> bool:
    return canonical_normalized_bytes(left) == canonical_normalized_bytes(right)


def _validate_status(node: Mapping[str, JSONValue]) -> None:
    status = cast(str, node["status"])
    lifecycle = node["lifecycle"]
    admissibility = node["admissibility"]
    if status == "pruned":
        if lifecycle != "pruned":
            raise HypothesisInvariantError("pruned status requires pruned lifecycle")
    elif (lifecycle, admissibility) != _STATUS_COMPONENTS[status]:
        raise HypothesisInvariantError(
            "status, lifecycle, and admissibility are inconsistent"
        )

    score = node["score"]
    if score is None:
        return
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise HypothesisInvariantError("node score must be a finite number or null")
    if isinstance(score, float) and not math.isfinite(score):
        raise HypothesisInvariantError("node score must be finite")
    if status not in {"done", "merged", "pruned"} or admissibility != "admissible":
        raise HypothesisInvariantError(
            "only admissible done, merged, or pruned nodes may expose a score"
        )


def validate_node_invariants(node: Mapping[str, JSONValue]) -> None:
    """Validate one normalized C6 QuantHypothesisNode payload."""

    require_identifier(node["id"], "node.id")
    _require_optional_identifier(node["parent_id"], "node.parent_id")
    for index, child_id in enumerate(cast(list[JSONValue], node["children_ids"])):
        require_identifier(child_id, f"node.children_ids[{index}]")
    if cast(list[str], node["children_ids"]) != sorted(
        cast(list[str], node["children_ids"])
    ):
        raise HypothesisInvariantError(
            "node children_ids must be lexicographically ordered"
        )

    _validate_status(node)
    scope = cast(dict[str, JSONValue], node["scope"])
    _validate_scope(scope, "node.scope")

    family = cast(dict[str, JSONValue], node["family"])
    require_identifier(family["family_id"], "node.family.family_id")
    _require_optional_identifier(
        family.get("parent_family_id"), "node.family.parent_family_id"
    )
    _require_optional_sha256(family.get("canonical_hash"), "node.family.canonical_hash")
    for index, similarity in enumerate(
        cast(list[dict[str, JSONValue]], family["similarity_refs"])
    ):
        require_identifier(
            similarity["candidate_id"],
            f"node.family.similarity_refs[{index}].candidate_id",
        )

    _require_optional_identifier(node["candidate_id"], "node.candidate_id")
    candidate_artifact = node["candidate_artifact"]
    artifacts_by_id: dict[str, Mapping[str, JSONValue]] = {}
    if isinstance(candidate_artifact, dict):
        _validate_artifact_ref(candidate_artifact, "node.candidate_artifact")
        artifacts_by_id[cast(str, candidate_artifact["artifact_id"])] = (
            candidate_artifact
        )
        if node["candidate_id"] is None:
            raise HypothesisInvariantError(
                "candidate_artifact requires a non-null candidate_id"
            )

    attempt_ids = cast(list[str], node["attempt_ids"])
    for index, attempt_id in enumerate(attempt_ids):
        require_identifier(attempt_id, f"node.attempt_ids[{index}]")

    evidence_by_id: dict[str, Mapping[str, JSONValue]] = {}
    evidence_refs = cast(list[dict[str, JSONValue]], node["evidence_refs"])
    for index, evidence in enumerate(evidence_refs):
        evidence_id = require_identifier(
            evidence["evidence_id"], f"node.evidence_refs[{index}].evidence_id"
        )
        if evidence_id in evidence_by_id:
            raise HypothesisInvariantError("node evidence IDs must be unique")
        evidence_by_id[evidence_id] = evidence
        _require_optional_identifier(
            evidence.get("attempt_id"),
            f"node.evidence_refs[{index}].attempt_id",
        )
        _require_optional_identifier(
            evidence.get("result_id"), f"node.evidence_refs[{index}].result_id"
        )
        for artifact_index, artifact in enumerate(
            cast(list[dict[str, JSONValue]], evidence["artifact_refs"])
        ):
            artifact_field = (
                f"node.evidence_refs[{index}].artifact_refs[{artifact_index}]"
            )
            _validate_artifact_ref(artifact, artifact_field)
            artifact_id = cast(str, artifact["artifact_id"])
            previous = artifacts_by_id.get(artifact_id)
            if previous is not None and not _same_json(previous, artifact):
                raise HypothesisInvariantError(
                    "one artifact ID cannot identify different records"
                )
            artifacts_by_id[artifact_id] = artifact

    if node["score"] is not None and not any(
        evidence["status"] == "valid"
        and evidence["level"] == "observed"
        and evidence.get("result_id") is not None
        for evidence in evidence_refs
    ):
        raise HypothesisInvariantError(
            "a non-null score requires valid observed result evidence"
        )
    if node["admissibility"] == "admissible" and not any(
        evidence["status"] == "valid" and evidence["level"] == "observed"
        for evidence in evidence_refs
    ):
        # C5 G01/G08 and C6 J02/J04: an admissible state is an evidence
        # projection; a scoreless result may exist, but an evidence-free one may not.
        raise HypothesisInvariantError(
            "an admissible node requires valid observed evidence"
        )

    for field in ("test_family_refs", "lineage_refs"):
        for index, identifier in enumerate(cast(list[str], node[field])):
            require_identifier(identifier, f"node.{field}[{index}]")

    insights_by_id: dict[str, Mapping[str, JSONValue]] = {}
    for index, insight in enumerate(cast(list[dict[str, JSONValue]], node["insights"])):
        insight_id = require_identifier(
            insight["insight_id"], f"node.insights[{index}].insight_id"
        )
        if insight_id in insights_by_id:
            raise HypothesisInvariantError("node insight IDs must be unique")
        insights_by_id[insight_id] = insight
        insight_scope = cast(dict[str, JSONValue], insight["scope"])
        _validate_scope(insight_scope, f"node.insights[{index}].scope")
        if any(insight_scope[field] != scope[field] for field in _SCOPE_MATCH_FIELDS):
            raise HypothesisInvariantError(
                "insight scope identity must match its containing node"
            )
        evidence_ids = cast(list[str], insight["evidence_ids"])
        for evidence_index, evidence_id in enumerate(evidence_ids):
            require_identifier(
                evidence_id,
                f"node.insights[{index}].evidence_ids[{evidence_index}]",
            )
            if evidence_id not in evidence_by_id:
                raise HypothesisInvariantError(
                    "insight evidence_ids must resolve in the containing node"
                )
        if insight["validity"] == "active" and any(
            evidence_by_id[evidence_id]["status"] != "valid"
            for evidence_id in evidence_ids
        ):
            raise HypothesisInvariantError(
                "active insight cannot rely on non-valid evidence"
            )
        supporting = [evidence_by_id[evidence_id] for evidence_id in evidence_ids]
        if (
            insight["validity"] == "active"
            and insight["grade"] == "development_supported"
            and not any(
                evidence["status"] == "valid"
                and evidence["level"] == "observed"
                and evidence.get("split_role") in {"development", "gate"}
                for evidence in supporting
            )
        ):
            raise HypothesisInvariantError(
                "development-supported insight lacks observed development evidence"
            )
        if (
            insight["validity"] == "active"
            and insight["grade"] == "gate_supported"
            and not any(
                evidence["status"] == "valid"
                and evidence["level"] == "observed"
                and evidence.get("split_role") == "gate"
                for evidence in supporting
            )
        ):
            raise HypothesisInvariantError(
                "gate-supported insight lacks observed gate evidence"
            )
        reason = insight.get("invalidation_reason")
        if insight["validity"] == "invalidated" and not reason:
            raise HypothesisInvariantError(
                "invalidated insight requires an invalidation reason"
            )
        if insight["validity"] != "invalidated" and reason is not None:
            raise HypothesisInvariantError(
                "only invalidated insight may carry an invalidation reason"
            )

    failure = cast(dict[str, JSONValue], node["failure"])
    failure_evidence_ids = cast(list[str], failure["evidence_ids"])
    for index, evidence_id in enumerate(failure_evidence_ids):
        require_identifier(evidence_id, f"node.failure.evidence_ids[{index}]")
        if evidence_id not in evidence_by_id:
            raise HypothesisInvariantError(
                "failure evidence_ids must resolve in the containing node"
            )
    failure_type = failure["failure_type"]
    if failure_type == "none" and (failure["summary"] or failure_evidence_ids):
        raise HypothesisInvariantError(
            "failure type none cannot carry a summary or evidence"
        )
    if failure_type != "none" and not failure["summary"]:
        raise HypothesisInvariantError("a recorded failure requires a summary")
    if (
        node["status"] in {"pending", "running", "done", "merged"}
        and failure_type != "none"
    ):
        raise HypothesisInvariantError(
            "the node composite status is inconsistent with its failure"
        )
    if node["status"] in {"needs_retry", "invalid"} and failure_type == "none":
        raise HypothesisInvariantError(
            f"{node['status']} status requires a recorded failure"
        )
    if node["status"] == "contaminated" and failure_type != "contamination":
        raise HypothesisInvariantError(
            "contaminated status requires contamination failure"
        )
    if node["status"] == "incomparable" and failure_type != "incomparable":
        raise HypothesisInvariantError(
            "incomparable status requires incomparable failure"
        )
    if failure_type == "contamination" and node["status"] not in {
        "contaminated",
        "pruned",
    }:
        raise HypothesisInvariantError(
            "contamination failure requires contaminated or pruned status"
        )
    if failure_type == "incomparable" and node["status"] not in {
        "incomparable",
        "pruned",
    }:
        raise HypothesisInvariantError(
            "incomparable failure requires incomparable or pruned status"
        )

    _require_optional_sha256(
        node["prompt_snapshot_sha256"], "node.prompt_snapshot_sha256"
    )
    require_identifier(node["created_event_id"], "node.created_event_id")
    require_identifier(node["last_event_id"], "node.last_event_id")


def _validate_compatibility(
    compatibility: Mapping[str, JSONValue], node_ids: set[str]
) -> bool:
    if set(compatibility) != _COMPATIBILITY_KEYS:
        raise HypothesisInvariantError(
            "compatibility metadata does not use the frozen C8 shape"
        )
    if compatibility["source"] not in {"arbor.idea_tree", "arbor.node"}:
        raise HypothesisInvariantError(
            "compatibility source is not a pinned Arbor form"
        )
    if compatibility["source_version"] != "3":
        raise HypothesisInvariantError("compatibility source_version must equal 3")
    quarantined = compatibility["quarantined"]
    if not isinstance(quarantined, bool):
        raise HypothesisInvariantError("compatibility quarantined must be boolean")

    missing = compatibility["missing_fields_by_node"]
    legacy_scores = compatibility["legacy_scores_by_node"]
    legacy_status = compatibility["legacy_status_by_node"]
    safe_meta = compatibility["safe_meta"]
    dropped = compatibility["dropped_meta_keys"]
    if not all(
        isinstance(item, dict)
        for item in (missing, legacy_scores, legacy_status, safe_meta)
    ):
        raise HypothesisInvariantError("compatibility map fields must be objects")
    if not isinstance(dropped, list) or any(
        not isinstance(item, str) for item in dropped
    ):
        raise HypothesisInvariantError(
            "compatibility dropped_meta_keys must be strings"
        )
    if len(dropped) != len(set(cast(list[str], dropped))):
        raise HypothesisInvariantError("compatibility dropped_meta_keys must be unique")
    if cast(list[str], dropped) != sorted(cast(list[str], dropped)):
        raise HypothesisInvariantError("compatibility dropped_meta_keys must be sorted")
    if any(
        item not in _KNOWN_DROPPED_META_KEYS
        and _UNKNOWN_DROPPED_META_RE.fullmatch(item) is None
        for item in cast(list[str], dropped)
    ):
        raise HypothesisInvariantError(
            "compatibility dropped_meta_keys contains an unsafe label"
        )

    safe_meta_mapping = cast(dict[str, JSONValue], safe_meta)
    if not set(safe_meta_mapping) <= {"metric_direction", "max_depth"}:
        raise HypothesisInvariantError("compatibility safe_meta contains an unsafe key")
    metric_direction = safe_meta_mapping.get("metric_direction")
    if "metric_direction" in safe_meta_mapping and metric_direction not in {
        "maximize",
        "minimize",
    }:
        raise HypothesisInvariantError(
            "compatibility metric_direction must be maximize or minimize"
        )
    max_depth = safe_meta_mapping.get("max_depth")
    if max_depth is not None and (
        isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1
    ):
        raise HypothesisInvariantError(
            "compatibility max_depth must be a positive integer or null"
        )

    for node_id, fields in cast(dict[str, JSONValue], missing).items():
        require_identifier(node_id, "compatibility missing-fields node ID")
        if node_id not in node_ids or not isinstance(fields, list):
            raise HypothesisInvariantError(
                "compatibility missing fields must reference existing nodes"
            )
        if any(not isinstance(field, str) or not field for field in fields):
            raise HypothesisInvariantError(
                "compatibility missing-field names must be non-empty strings"
            )
        if any(field not in _COMPATIBILITY_MISSING_LABELS for field in fields):
            raise HypothesisInvariantError(
                "compatibility missing fields contain an unsafe label"
            )
        if len(fields) != len(set(cast(list[str], fields))):
            raise HypothesisInvariantError(
                "compatibility missing-field names must be unique"
            )
        if cast(list[str], fields) != sorted(cast(list[str], fields)):
            raise HypothesisInvariantError(
                "compatibility missing-field names must be sorted"
            )

    for node_id, score_record in cast(dict[str, JSONValue], legacy_scores).items():
        require_identifier(node_id, "compatibility legacy-score node ID")
        if node_id not in node_ids:
            raise HypothesisInvariantError(
                "compatibility legacy scores must reference existing nodes"
            )
        if not isinstance(score_record, dict):
            raise HypothesisInvariantError(
                "compatibility legacy-score records must be objects"
            )
        if set(score_record) != _LEGACY_SCORE_KEYS:
            raise HypothesisInvariantError(
                "compatibility legacy-score record has unexpected fields"
            )
        for score_field in ("score", "test_score"):
            score = score_record[score_field]
            if score is not None and (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
                or (isinstance(score, float) and not math.isfinite(score))
            ):
                raise HypothesisInvariantError(
                    "compatibility legacy scores must be finite or null"
                )
        if score_record["score_source"] not in {"score", "score_delta", None}:
            raise HypothesisInvariantError(
                "compatibility score_source is not a pinned Arbor value"
            )
        if score_record["score_split"] not in {"dev", "test", None}:
            raise HypothesisInvariantError(
                "compatibility score_split is not a pinned Arbor value"
            )

    for node_id, status_record in cast(dict[str, JSONValue], legacy_status).items():
        require_identifier(node_id, "compatibility legacy-status node ID")
        if node_id not in node_ids or not isinstance(status_record, dict):
            raise HypothesisInvariantError(
                "compatibility legacy-status records must reference existing nodes"
            )
        keys = set(status_record)
        if not _LEGACY_STATUS_KEYS <= keys or not keys <= (
            _LEGACY_STATUS_KEYS | _LEGACY_STATUS_OPTIONAL_KEYS
        ):
            raise HypothesisInvariantError(
                "compatibility legacy-status record has unexpected fields"
            )
        if status_record["status"] not in {
            "pending",
            "running",
            "done",
            "needs_retry",
            "merged",
            "pruned",
            None,
        }:
            raise HypothesisInvariantError(
                "compatibility status is not a pinned Arbor value"
            )
        if status_record["eval_status"] not in {
            "scored",
            "skipped",
            "failed_to_run",
            None,
        }:
            raise HypothesisInvariantError(
                "compatibility eval_status is not a pinned Arbor value"
            )
        if status_record["stop_reason"] not in {"finished", "max_turns", None}:
            raise HypothesisInvariantError(
                "compatibility stop_reason is not a pinned Arbor value"
            )
        attempt = status_record["attempt"]
        if attempt is not None and (
            isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1
        ):
            raise HypothesisInvariantError(
                "compatibility attempt must be a positive integer or null"
            )
        for hash_field in (
            "result_sha256",
            "insight_sha256",
            "code_ref_sha256",
            "related_work_sha256",
            "grounding_sha256",
        ):
            _require_optional_sha256(
                status_record[hash_field], f"compatibility {hash_field}"
            )
        has_source_parent = "source_parent_id" in status_record
        has_source_depth = "source_depth" in status_record
        if has_source_parent != has_source_depth:
            raise HypothesisInvariantError(
                "compatibility source parent and depth must be recorded together"
            )
        if has_source_parent:
            source_parent_id = status_record["source_parent_id"]
            _require_optional_identifier(
                source_parent_id, "compatibility source_parent_id"
            )
            source_depth = status_record["source_depth"]
            if (
                isinstance(source_depth, bool)
                or not isinstance(source_depth, int)
                or source_depth < 0
            ):
                raise HypothesisInvariantError(
                    "compatibility source_depth must be a non-negative integer"
                )

    if set(cast(dict[str, JSONValue], legacy_scores)) != node_ids:
        raise HypothesisInvariantError(
            "compatibility legacy scores must cover every imported node"
        )
    if set(cast(dict[str, JSONValue], legacy_status)) != node_ids:
        raise HypothesisInvariantError(
            "compatibility legacy statuses must cover every imported node"
        )
    if set(cast(dict[str, JSONValue], missing)) != node_ids:
        raise HypothesisInvariantError(
            "compatibility missing fields must cover every imported node"
        )

    has_quarantined_facts = bool(missing or legacy_scores or legacy_status)
    if has_quarantined_facts and quarantined is not True:
        raise HypothesisInvariantError(
            "legacy incomplete facts require compatibility quarantine"
        )
    return quarantined


def project_counts(
    nodes: list[Mapping[str, JSONValue]], root_node_id: str
) -> dict[str, JSONValue]:
    """Compute the one frozen C8 count projection."""

    non_root = [node for node in nodes if node["id"] != root_node_id]
    candidates = {
        cast(str, node["candidate_id"])
        for node in non_root
        if node["candidate_id"] is not None
    }
    families = {
        cast(str, cast(dict[str, JSONValue], node["family"])["family_id"])
        for node in non_root
    }
    attempt_ids: set[str] = set()
    result_ids: set[str] = set()
    admissible_evidence: set[str] = set()
    for node in nodes:
        attempt_ids.update(cast(list[str], node["attempt_ids"]))
        is_admissible = node["admissibility"] == "admissible"
        for evidence in cast(list[dict[str, JSONValue]], node["evidence_refs"]):
            result_id = evidence.get("result_id")
            if isinstance(result_id, str):
                result_ids.add(result_id)
            if is_admissible and evidence["status"] == "valid":
                admissible_evidence.add(cast(str, evidence["evidence_id"]))
    return {
        "proposals": len(non_root),
        "unique_candidates": len(candidates),
        "candidate_families": len(families),
        "attempts": len(attempt_ids),
        "evaluation_queries": len(result_ids),
        "admissible_evidence": len(admissible_evidence),
    }


def compatibility_quarantined(tree: Mapping[str, JSONValue]) -> bool:
    """Return whether frozen compatibility metadata quarantines this tree."""

    compatibility = tree.get("compatibility")
    return isinstance(compatibility, dict) and compatibility.get("quarantined") is True


def validate_tree_invariants(tree: Mapping[str, JSONValue]) -> None:
    """Validate a normalized C6 QHypothesisTree payload."""

    require_identifier(tree["run_id"], "tree.run_id")
    require_sha256(tree["contract_hash"], "tree.contract_hash")
    root_node_id = require_identifier(tree["root_node_id"], "tree.root_node_id")
    ledger_head = cast(dict[str, JSONValue], tree["ledger_head"])
    require_sha256(ledger_head["last_event_hash"], "tree.ledger_head.last_event_hash")
    if ledger_head["last_sequence"] != cast(int, tree["revision"]) + 1:
        raise HypothesisInvariantError(
            "ledger sequence must equal tree revision plus one"
        )
    require_sha256(tree["tree_hash"], "tree.tree_hash")

    nodes = cast(list[dict[str, JSONValue]], tree["nodes"])
    node_by_id: dict[str, dict[str, JSONValue]] = {}
    for node in nodes:
        validate_node_invariants(node)
        node_id = cast(str, node["id"])
        if node_id in node_by_id:
            raise HypothesisInvariantError("tree node IDs must be unique")
        node_by_id[node_id] = node
    if root_node_id not in node_by_id:
        raise HypothesisInvariantError("root_node_id does not resolve")

    roots = [node for node in nodes if node["parent_id"] is None]
    if len(roots) != 1 or roots[0]["id"] != root_node_id:
        raise HypothesisInvariantError("tree must contain exactly its declared root")
    root = node_by_id[root_node_id]
    if root["depth"] != 0:
        raise HypothesisInvariantError("tree root depth must be zero")

    for node in nodes:
        node_id = cast(str, node["id"])
        parent_id = node["parent_id"]
        if parent_id is not None:
            parent = node_by_id.get(cast(str, parent_id))
            if parent is None:
                raise HypothesisInvariantError("node parent_id does not resolve")
            if node["depth"] != cast(int, parent["depth"]) + 1:
                raise HypothesisInvariantError("node depth does not follow its parent")
            if node_id not in cast(list[str], parent["children_ids"]):
                raise HypothesisInvariantError("parent/child links are not reciprocal")
        for child_id in cast(list[str], node["children_ids"]):
            child = node_by_id.get(child_id)
            if child is None or child["parent_id"] != node_id:
                raise HypothesisInvariantError("child/parent links are not reciprocal")

    preorder: list[str] = []
    seen: set[str] = set()
    stack = [root_node_id]
    while stack:
        node_id = stack.pop()
        if node_id in seen:
            raise HypothesisInvariantError("tree graph contains a cycle")
        seen.add(node_id)
        preorder.append(node_id)
        children = cast(list[str], node_by_id[node_id]["children_ids"])
        stack.extend(reversed(children))
    if seen != set(node_by_id):
        raise HypothesisInvariantError("tree contains nodes unreachable from the root")
    if [cast(str, node["id"]) for node in nodes] != preorder:
        raise HypothesisInvariantError("tree nodes must use deterministic DFS preorder")

    global_attempt_ids: set[str] = set()
    evidence_by_id: dict[str, Mapping[str, JSONValue]] = {}
    insights_by_id: dict[str, Mapping[str, JSONValue]] = {}
    artifacts_by_id: dict[str, Mapping[str, JSONValue]] = {}
    candidate_artifacts: dict[str, Mapping[str, JSONValue]] = {}
    for node in nodes:
        for attempt_id in cast(list[str], node["attempt_ids"]):
            if attempt_id in global_attempt_ids:
                raise HypothesisInvariantError(
                    "an attempt_id cannot be reused by another node"
                )
            global_attempt_ids.add(attempt_id)
    for node in nodes:
        for evidence in cast(list[dict[str, JSONValue]], node["evidence_refs"]):
            attempt_id = evidence.get("attempt_id")
            if attempt_id is not None and attempt_id not in global_attempt_ids:
                raise HypothesisInvariantError(
                    "evidence attempt_id must resolve in the tree attempt index"
                )
    for node in nodes:
        candidate_id = node["candidate_id"]
        candidate_artifact = node["candidate_artifact"]
        if isinstance(candidate_id, str) and isinstance(candidate_artifact, dict):
            previous_candidate_artifact = candidate_artifacts.get(candidate_id)
            if previous_candidate_artifact is not None and not _same_json(
                previous_candidate_artifact, candidate_artifact
            ):
                raise HypothesisInvariantError(
                    "one candidate ID cannot identify different artifacts"
                )
            candidate_artifacts[candidate_id] = candidate_artifact
            artifact_id = cast(str, candidate_artifact["artifact_id"])
            previous_artifact = artifacts_by_id.get(artifact_id)
            if previous_artifact is not None and not _same_json(
                previous_artifact, candidate_artifact
            ):
                raise HypothesisInvariantError(
                    "one artifact ID cannot identify different records"
                )
            artifacts_by_id[artifact_id] = candidate_artifact
        for evidence in cast(list[dict[str, JSONValue]], node["evidence_refs"]):
            evidence_id = cast(str, evidence["evidence_id"])
            previous = evidence_by_id.get(evidence_id)
            if previous is not None and not _same_json(previous, evidence):
                raise HypothesisInvariantError(
                    "one evidence ID cannot identify different records"
                )
            evidence_by_id[evidence_id] = evidence
            for artifact in cast(list[dict[str, JSONValue]], evidence["artifact_refs"]):
                artifact_id = cast(str, artifact["artifact_id"])
                previous_artifact = artifacts_by_id.get(artifact_id)
                if previous_artifact is not None and not _same_json(
                    previous_artifact, artifact
                ):
                    raise HypothesisInvariantError(
                        "one artifact ID cannot identify different records"
                    )
                artifacts_by_id[artifact_id] = artifact
        for insight in cast(list[dict[str, JSONValue]], node["insights"]):
            insight_id = cast(str, insight["insight_id"])
            previous = insights_by_id.get(insight_id)
            if previous is not None and not _same_json(previous, insight):
                raise HypothesisInvariantError(
                    "one insight ID cannot identify different records"
                )
            insights_by_id[insight_id] = insight

    projected = project_counts(cast(list[Mapping[str, JSONValue]], nodes), root_node_id)
    if tree["counts"] != projected:
        raise HypothesisInvariantError("tree counts do not match the C8 projection")

    compatibility = tree.get("compatibility")
    quarantined = False
    if compatibility is not None:
        if not isinstance(compatibility, dict):
            raise HypothesisInvariantError("tree compatibility must be an object")
        quarantined = _validate_compatibility(compatibility, set(node_by_id))
    if quarantined and any(node["score"] is not None for node in nodes):
        raise HypothesisInvariantError(
            "compatibility-quarantined trees cannot expose Q-node scores"
        )
