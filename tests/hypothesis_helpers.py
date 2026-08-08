from __future__ import annotations

import copy
import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HYPOTHESIS_FIXTURES = REPOSITORY_ROOT / "tests" / "fixtures" / "hypotheses"

CONTRACT_HASH = "f" * 64
DATA_HASH = "a" * 64
COST_HASH = "b" * 64
PROMPT_HASH = "d" * 64


def hypothesis_fixture(name: str) -> Path:
    return HYPOTHESIS_FIXTURES / name


def _fixture_mapping(name: str) -> dict[str, Any]:
    with hypothesis_fixture(name).open(encoding="utf-8") as stream:
        value = json.load(stream)
    assert isinstance(value, dict)
    return value


def valid_node_mapping() -> dict[str, Any]:
    return _fixture_mapping("valid_node.json")


def valid_tree_draft_mapping() -> dict[str, Any]:
    return _fixture_mapping("valid_tree_draft.json")


def arbor_v3_mapping() -> dict[str, Any]:
    return _fixture_mapping("arbor_v3_tree.json")


def normalized_copy(value: Any) -> Any:
    """Independent normalization oracle for C6 canonical JSON."""

    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite number")
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (list, tuple)):
        return [normalized_copy(item) for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise TypeError("JSON object keys must be strings")
            key = unicodedata.normalize("NFC", raw_key)
            if key in normalized:
                raise ValueError("NFC-normalized key collision")
            normalized[key] = normalized_copy(item)
        return normalized
    raise TypeError(f"not a JSON value: {type(value).__name__}")


def canonical_json(mapping: Mapping[str, Any]) -> str:
    return json.dumps(
        normalized_copy(mapping),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def expected_tree_hash(mapping: Mapping[str, Any]) -> str:
    payload = normalized_copy(mapping)
    assert isinstance(payload, dict)
    payload.pop("tree_hash", None)
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def scope_mapping(**updates: Any) -> dict[str, Any]:
    scope: dict[str, Any] = {
        "market": "synthetic-equities",
        "universe": "liquid-large-cap",
        "frequency": "daily",
        "horizon": "one-day",
        "time_range": "2020-01-01/2020-12-31",
        "fields": ["close", "volume"],
        "regime_labels": ["all"],
        "data_snapshot_sha256": DATA_HASH,
        "cost_model_sha256": COST_HASH,
    }
    scope.update(updates)
    return scope


def hypothesis_mapping(label: str) -> dict[str, Any]:
    return {
        "mechanism": f"Mechanism for {label}.",
        "falsifiable_prediction": f"Prediction for {label} is falsifiable.",
        "observable": f"Frozen observable for {label}.",
        "single_change": f"Apply only the {label} change.",
        "conflicts": [],
    }


def family_mapping(node_id: str, proposal_order: int) -> dict[str, Any]:
    return {
        "family_id": f"family.{node_id}",
        "parent_family_id": None if node_id == "root" else "family.root",
        "proposal_order": proposal_order,
        "canonical_status": "unique",
        "canonical_hash": hashlib.sha256(node_id.encode("utf-8")).hexdigest(),
        "similarity_refs": [],
    }


def node_draft_kwargs(
    node_id: str,
    *,
    parent_id: str | None,
    proposal_order: int,
    scope: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": node_id,
        "parent_id": parent_id,
        "hypothesis": hypothesis_mapping(node_id),
        "scope": copy.deepcopy(dict(scope or scope_mapping())),
        "family": family_mapping(node_id, proposal_order),
        "prompt_snapshot_sha256": PROMPT_HASH,
        "candidate_id": f"candidate.{node_id}" if parent_id is not None else None,
        "candidate_artifact": None,
        "test_family_refs": (),
        "lineage_refs": () if parent_id is None else (parent_id,),
        "code_ref": None,
    }


def valid_observed_evidence(
    node_id: str,
    *,
    status: str = "valid",
    result_id: str | None = None,
) -> dict[str, Any]:
    return {
        "evidence_id": f"evidence.{node_id}",
        "attempt_id": f"attempt.{node_id}",
        "result_id": result_id,
        "split_role": "development",
        "level": "observed",
        "claim": f"Observed evidence for {node_id}.",
        "conditions": ["frozen development snapshot"],
        "status": status,
        "artifact_refs": [],
    }


def active_insight(
    node_id: str,
    *,
    scope: Mapping[str, Any] | None = None,
    grade: str = "development_supported",
    validity: str = "active",
) -> dict[str, Any]:
    return {
        "insight_id": f"insight.{node_id}",
        "text": f"Reusable insight from {node_id}.",
        "scope": copy.deepcopy(dict(scope or scope_mapping())),
        "evidence_ids": [f"evidence.{node_id}"],
        "grade": grade,
        "validity": validity,
        "invalidation_reason": None,
    }


def deterministic_clock() -> datetime:
    return datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


def deterministic_event_id(next_sequence: int) -> str:
    return f"event.{next_sequence:04d}"


def node_record(tree: object, node_id: str) -> dict[str, Any]:
    mapping = tree.to_dict()  # type: ignore[attr-defined]
    return next(node for node in mapping["nodes"] if node["id"] == node_id)
