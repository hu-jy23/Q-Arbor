from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, cast

import pytest

from q_arbor.hypotheses import (
    LEGACY_UNKNOWN_HASH,
    LEGACY_UNKNOWN_TEXT,
    TreeCompatibilityError,
    apply_tree_event,
    import_arbor_tree,
)

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "hypotheses"
    / "arbor_v3_tree.json"
)
CONTRACT_HASH = "f" * 64


def _legacy_tree() -> dict[str, Any]:
    with FIXTURE.open(encoding="utf-8") as stream:
        value = json.load(stream)
    assert isinstance(value, dict)
    return value


def _compatibility(tree: object) -> dict[str, Any]:
    mapping = tree.to_dict()  # type: ignore[attr-defined]
    value = mapping["compatibility"]
    assert isinstance(value, dict)
    return value


def test_arbor_v3_import_is_deterministic_replayable_and_quarantined() -> None:
    legacy = _legacy_tree()
    before = copy.deepcopy(legacy)

    first = import_arbor_tree(legacy, run_id="run.compat", contract_hash=CONTRACT_HASH)
    second = import_arbor_tree(
        copy.deepcopy(legacy), run_id="run.compat", contract_hash=CONTRACT_HASH
    )

    assert legacy == before
    assert first.tree == second.tree
    assert first.events == second.events
    assert first.warnings == second.warnings
    assert len(first.events) == 1
    assert apply_tree_event(None, first.events[0]) == first.tree

    tree = first.tree.to_dict()
    assert tree["revision"] == 0
    assert tree["ledger_head"]["last_sequence"] == 1
    assert tree["ledger_head"]["last_event_hash"] == first.events[0]["event_hash"]
    assert all(node["score"] is None for node in tree["nodes"])
    assert all(node["status"] == "pending" for node in tree["nodes"])
    assert all(node["admissibility"] == "unevaluated" for node in tree["nodes"])

    event_payload = first.events[0]["payload"]
    assert isinstance(event_payload, Mapping)
    assert set(event_payload) == {
        "schema_version",
        "kind",
        "idempotency_key",
        "request_hash",
        "expected_revision",
        "result_revision",
        "tree",
    }
    assert event_payload["kind"] == "initialize_tree"
    assert event_payload["result_revision"] == 0
    with pytest.raises(TypeError):
        first.events[0]["event_hash"] = "0" * 64  # type: ignore[index]
    with pytest.raises(TypeError):
        cast(dict[str, Any], event_payload)["kind"] = "changed"


def test_score_delta_and_test_score_are_preserved_only_in_exact_compat_records() -> (
    None
):
    result = import_arbor_tree(
        _legacy_tree(), run_id="run.compat", contract_hash=CONTRACT_HASH
    )
    compatibility = _compatibility(result.tree)
    assert set(compatibility) == {
        "source",
        "source_version",
        "quarantined",
        "missing_fields_by_node",
        "legacy_scores_by_node",
        "legacy_status_by_node",
        "safe_meta",
        "dropped_meta_keys",
    }
    assert compatibility["source"] == "arbor.idea_tree"
    assert compatibility["source_version"] == "3"
    assert compatibility["quarantined"] is True

    scores = compatibility["legacy_scores_by_node"]
    assert scores["ROOT"] == {
        "score": 0.1,
        "score_source": "score",
        "score_split": "dev",
        "test_score": None,
    }
    assert scores["1"] == {
        "score": 0.16,
        "score_source": "score",
        "score_split": "dev",
        "test_score": 0.13,
    }
    assert scores["2"] == {
        "score": -0.02,
        "score_source": "score_delta",
        "score_split": "dev",
        "test_score": None,
    }
    assert all(
        set(record) == {"score", "score_source", "score_split", "test_score"}
        for record in scores.values()
    )

    missing = compatibility["missing_fields_by_node"]
    for node_id in ("ROOT", "1", "2"):
        assert "hypothesis.falsifiable_prediction" in missing[node_id]
        assert "scope.data_snapshot_sha256" in missing[node_id]
        assert "evidence_refs" in missing[node_id]
    assert "score.evidence_binding" in missing["2"]
    assert "test_score.evidence_binding" in missing["1"]


def test_status_free_text_is_hashed_and_unsafe_meta_values_never_cross() -> None:
    legacy = _legacy_tree()
    result = import_arbor_tree(legacy, run_id="run.compat", contract_hash=CONTRACT_HASH)
    compatibility = _compatibility(result.tree)

    statuses = compatibility["legacy_status_by_node"]
    assert set(statuses["1"]) == {
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
    assert statuses["1"]["status"] == "merged"
    assert statuses["1"]["eval_status"] == "scored"
    assert statuses["1"]["stop_reason"] == "finished"
    assert statuses["1"]["attempt"] == 2
    assert (
        statuses["1"]["insight_sha256"]
        == hashlib.sha256(
            "Tail clipping helped & needs confirmation".encode()
        ).hexdigest()
    )
    assert (
        statuses["1"]["code_ref_sha256"]
        == hashlib.sha256("refs/heads/idea-1".encode()).hexdigest()
    )

    assert compatibility["safe_meta"] == {
        "max_depth": 3,
        "metric_direction": "maximize",
    }
    unknown_label = (
        "unknown-sha256:" + hashlib.sha256("plugin_payload".encode()).hexdigest()
    )
    dropped = compatibility["dropped_meta_keys"]
    assert dropped == sorted(dropped)
    assert "eval_cmd" in dropped
    assert "eval_cmd_test" in dropped
    assert "dataset_info" in dropped
    assert "submission_path" in dropped
    assert "baseline_score" in dropped
    assert unknown_label in dropped
    assert "plugin_payload" not in dropped

    serialized = "\n".join(
        (
            result.tree.to_json(),
            json.dumps(result.events, ensure_ascii=False, sort_keys=True),
            "\n".join(result.warnings),
        )
    )
    for forbidden in (
        "SYNTHETIC_SECRET",
        "python evaluator.py",
        "python hidden_evaluator.py",
        "private rows at /srv/hidden/final.csv",
        "/srv/private/submission.csv",
        "../hidden/sample.csv",
        "plugin_payload",
        "Legacy development improvement",
        "Tail clipping helped & needs confirmation",
        "refs/heads/idea-1",
        "citation <unsafe>",
    ):
        assert forbidden not in serialized


def test_standalone_nonroot_node_is_normalized_to_its_own_root() -> None:
    node = {
        "id": "1.2",
        "parent_id": "1",
        "children_ids": [],
        "depth": 2,
        "hypothesis": "Standalone legacy node",
        "status": "done",
        "score_delta": 0.25,
    }
    result = import_arbor_tree(node, run_id="run.single", contract_hash=CONTRACT_HASH)
    tree = result.tree.to_dict()
    assert tree["root_node_id"] == "1.2"
    assert len(tree["nodes"]) == 1
    assert tree["nodes"][0]["id"] == "1.2"
    assert tree["nodes"][0]["parent_id"] is None
    assert tree["nodes"][0]["depth"] == 0
    assert tree["counts"]["proposals"] == 0
    assert tree["counts"]["candidate_families"] == 0

    compatibility = tree["compatibility"]
    status = compatibility["legacy_status_by_node"]["1.2"]
    assert status["source_parent_id"] == "1"
    assert status["source_depth"] == 2
    assert compatibility["legacy_scores_by_node"]["1.2"]["score"] == 0.25
    assert apply_tree_event(None, result.events[0]) == result.tree


def test_default_scope_replaces_only_scope_sentinels() -> None:
    scope = {
        "market": "synthetic-equities",
        "universe": "large-cap",
        "frequency": "daily",
        "horizon": "one-day",
        "time_range": "2020-01-01/2020-12-31",
        "fields": ["close"],
        "regime_labels": ["all"],
        "data_snapshot_sha256": "a" * 64,
        "cost_model_sha256": "b" * 64,
    }
    result = import_arbor_tree(
        _legacy_tree(),
        run_id="run.scope",
        contract_hash=CONTRACT_HASH,
        default_scope=scope,
    )
    mapping = result.tree.to_dict()
    assert all(node["scope"] == scope for node in mapping["nodes"])
    missing = mapping["compatibility"]["missing_fields_by_node"]
    assert all(
        not any(field.startswith("scope.") for field in fields)
        for fields in missing.values()
    )
    assert mapping["nodes"][0]["family"]["family_id"] == LEGACY_UNKNOWN_TEXT
    assert mapping["nodes"][0]["score"] is None
    assert LEGACY_UNKNOWN_HASH not in json.dumps(mapping["nodes"][0]["scope"])


@pytest.mark.parametrize(
    "mutation",
    [
        lambda tree: tree["nodes"]["1"].update(parent_id="missing"),
        lambda tree: tree["nodes"]["ROOT"].update(children_ids=["1"]),
        lambda tree: tree["nodes"]["1"].update(depth=3),
        lambda tree: tree.update(version=2),
    ],
)
def test_incompatible_arbor_graph_fails_closed(mutation: object) -> None:
    legacy = _legacy_tree()
    cast(Any, mutation)(legacy)
    with pytest.raises(TreeCompatibilityError):
        import_arbor_tree(legacy, run_id="run.bad", contract_hash=CONTRACT_HASH)
