from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest

from q_arbor.hypotheses import (
    HypothesisDecodeError,
    HypothesisInvariantError,
    HypothesisSchemaError,
    NodeDraft,
    QHypothesisTree,
    TreeConflictError,
    TreeIntegrityError,
    TreeMutation,
    TreePersistenceError,
    apply_tree_event,
    compute_ledger_event_hash,
    freeze_node,
    freeze_tree,
    load_tree,
    materialize_node_draft,
    prepare_mutation,
    prepare_run_started,
    validate_tree,
)
from q_arbor.hypotheses.invariants import project_counts

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def scope(*, market: str = "synthetic") -> dict[str, Any]:
    return {
        "market": market,
        "universe": "all-assets",
        "frequency": "daily",
        "horizon": "one-day",
        "time_range": "2020/2021",
        "fields": ["close"],
        "regime_labels": ["all"],
        "data_snapshot_sha256": HASH_A,
        "cost_model_sha256": HASH_B,
    }


def hypothesis(mechanism: str = "Signal persistence") -> dict[str, Any]:
    return {
        "mechanism": mechanism,
        "falsifiable_prediction": "Rank correlation is positive",
        "observable": "daily rank IC",
        "single_change": "add lagged signal",
        "conflicts": [],
    }


def family(family_id: str, proposal_order: int) -> dict[str, Any]:
    return {
        "family_id": family_id,
        "parent_family_id": None,
        "proposal_order": proposal_order,
        "canonical_status": "unique",
        "canonical_hash": HASH_C,
        "similarity_refs": [],
    }


def draft(
    node_id: str,
    parent_id: str | None,
    *,
    node_scope: dict[str, Any] | None = None,
) -> NodeDraft:
    return NodeDraft(
        node_id,
        parent_id,
        hypothesis(),
        node_scope or scope(),
        family(f"family:{node_id}", 1 if parent_id is None else 2),
        None,
    )


def ledger_event(
    *,
    tree: QHypothesisTree | None,
    event_id: str,
    event_type: str,
    node_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    event = {
        "schema_version": "1.0",
        "run_id": "run:unit" if tree is None else tree.run_id,
        "sequence": 1 if tree is None else tree.revision + 2,
        "event_id": event_id,
        "timestamp": "2026-08-09T00:00:00Z",
        "event_type": event_type,
        "actor": "system" if tree is None else "coordinator",
        "contract_hash": HASH_C if tree is None else tree.contract_hash,
        "node_id": node_id,
        "attempt_id": None,
        "split_role": "none",
        "payload": payload,
        "prev_event_hash": (
            None if tree is None else tree.ledger_head["last_event_hash"]
        ),
        "event_hash": "0" * 64,
    }
    event["event_hash"] = compute_ledger_event_hash(event)
    return event


def initial_tree() -> QHypothesisTree:
    node_id, payload = prepare_run_started(
        run_id="run:unit",
        contract_hash=HASH_C,
        root=draft("root", None),
        event_id="event:start",
    )
    return apply_tree_event(
        None,
        ledger_event(
            tree=None,
            event_id="event:start",
            event_type="run.started",
            node_id=node_id,
            payload=payload,
        ),
    )


def apply_mutation(
    tree: QHypothesisTree,
    mutation: TreeMutation,
    event_id: str,
    *,
    idempotency_key: str,
) -> QHypothesisTree:
    event_type, node_id, payload = prepare_mutation(
        tree,
        mutation,
        event_id=event_id,
        idempotency_key=idempotency_key,
    )
    return apply_tree_event(
        tree,
        ledger_event(
            tree=tree,
            event_id=event_id,
            event_type=event_type,
            node_id=node_id,
            payload=payload,
        ),
    )


def test_initial_round_trip_hash_immutability_and_atomic_write(tmp_path: Path) -> None:
    tree = initial_tree()
    assert tree.revision == 0
    assert tree.tree_hash == tree.to_dict()["tree_hash"]
    assert tree.counts["proposals"] == 0
    assert tree.nodes[0].hypothesis["mechanism"] == "Signal persistence"

    source = tree.to_dict()
    source["nodes"][0]["hypothesis"]["mechanism"] = "mutated"
    assert tree.nodes[0].hypothesis["mechanism"] == "Signal persistence"
    with pytest.raises(TypeError):
        tree.nodes[0].scope["market"] = "other"  # type: ignore[index]
    with pytest.raises(AttributeError):
        tree.revision = 10  # type: ignore[misc]
    assert copy.copy(tree) is tree
    assert copy.deepcopy(tree) is tree

    path = tmp_path / "tree.json"
    tree.write(path)
    assert path.read_text(encoding="utf-8") == tree.to_json()
    assert load_tree(path) == tree


def test_atomic_write_failure_preserves_target_and_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = initial_tree()
    path = tmp_path / "tree.json"
    path.write_text("sentinel", encoding="utf-8")

    def fail_replace(source: object, destination: object) -> None:
        raise OSError("replace failed")

    def fail_cleanup(path_value: object) -> None:
        raise OSError("cleanup failed")

    monkeypatch.setattr(os, "replace", fail_replace)
    monkeypatch.setattr(os, "unlink", fail_cleanup)
    with pytest.raises(TreePersistenceError):
        tree.write(path)
    assert path.read_text(encoding="utf-8") == "sentinel"


def test_unicode_normalization_and_strict_tree_hash() -> None:
    root = materialize_node_draft(
        draft("root", None), depth=0, event_id="event:start"
    ).to_dict()
    root["hypothesis"]["mechanism"] = "Cafe\u0301"
    mapping = {
        "schema_version": "1.0",
        "run_id": "run:unit",
        "revision": 0,
        "contract_hash": HASH_C,
        "root_node_id": "root",
        "run_state": "setup",
        "ledger_head": {"last_sequence": 1, "last_event_hash": HASH_A},
        "nodes": [root],
        "counts": {
            "proposals": 0,
            "unique_candidates": 0,
            "candidate_families": 0,
            "attempts": 0,
            "evaluation_queries": 0,
            "admissible_evidence": 0,
        },
    }
    frozen = freeze_tree(mapping)
    assert frozen.nodes[0].hypothesis["mechanism"] == "Caf\u00e9"
    wrong = frozen.to_dict()
    wrong["tree_hash"] = HASH_B
    with pytest.raises(TreeIntegrityError):
        validate_tree(wrong)


def test_freeze_canonicalizes_dfs_order_but_validate_is_strict() -> None:
    root = materialize_node_draft(
        draft("root", None), depth=0, event_id="event:start"
    ).to_dict()
    child_a = materialize_node_draft(
        draft("a", "root"), depth=1, event_id="event:start"
    ).to_dict()
    child_b = materialize_node_draft(
        draft("b", "root"), depth=1, event_id="event:start"
    ).to_dict()
    root["children_ids"] = ["b", "a"]
    nodes = [child_b, root, child_a]
    mapping = {
        "schema_version": "1.0",
        "run_id": "run:unit",
        "revision": 0,
        "contract_hash": HASH_C,
        "root_node_id": "root",
        "run_state": "setup",
        "ledger_head": {"last_sequence": 1, "last_event_hash": HASH_A},
        "nodes": nodes,
        "counts": project_counts(nodes, "root"),
    }
    frozen = freeze_tree(mapping)
    assert [node.id for node in frozen.nodes] == ["root", "a", "b"]
    assert frozen.nodes[0].children_ids == ("a", "b")

    noncanonical = frozen.to_dict()
    noncanonical["nodes"] = list(reversed(noncanonical["nodes"]))
    with pytest.raises(HypothesisInvariantError):
        validate_tree(noncanonical, verify_hash=False)


def test_schema_decode_identifier_count_and_status_rejections(tmp_path: Path) -> None:
    tree = initial_tree()
    missing = tree.to_dict()
    del missing["run_id"]
    with pytest.raises(HypothesisSchemaError):
        freeze_tree(missing)

    newline_id = tree.to_dict()
    newline_id["run_id"] = "run:unit\n"
    with pytest.raises(HypothesisInvariantError):
        freeze_tree(newline_id)

    bad_count = tree.to_dict()
    bad_count["counts"]["proposals"] = 9
    with pytest.raises(HypothesisInvariantError):
        freeze_tree(bad_count)

    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text('{"run_id":"a","run_id":"b"}', encoding="utf-8")
    with pytest.raises(HypothesisDecodeError):
        load_tree(duplicate_path)

    root = tree.nodes[0].to_dict()
    root.update(
        {
            "status": "done",
            "lifecycle": "done",
            "admissibility": "invalid",
        }
    )
    with pytest.raises(HypothesisInvariantError):
        freeze_node(root)


def test_score_requires_admissible_observed_result_evidence() -> None:
    node = materialize_node_draft(
        draft("root", None), depth=0, event_id="event:start"
    ).to_dict()
    node.update(
        {
            "status": "done",
            "lifecycle": "done",
            "admissibility": "admissible",
            "score": 1.5,
            "attempt_ids": ["attempt:1"],
            "evidence_refs": [
                {
                    "evidence_id": "evidence:1",
                    "attempt_id": "attempt:1",
                    "result_id": "result:1",
                    "split_role": "development",
                    "level": "observed",
                    "claim": "positive score",
                    "conditions": [],
                    "status": "valid",
                    "artifact_refs": [],
                }
            ],
        }
    )
    assert freeze_node(node).score == 1.5
    node["evidence_refs"][0]["result_id"] = None
    with pytest.raises(HypothesisInvariantError):
        freeze_node(node)


def test_pure_add_update_failure_insight_propagation_and_idempotence() -> None:
    tree = apply_mutation(
        initial_tree(),
        TreeMutation.add_node(draft("child", "root")),
        "event:add",
        idempotency_key="key:add",
    )
    assert [node.id for node in tree.nodes] == ["root", "child"]
    assert tree.counts["proposals"] == 1

    tree = apply_mutation(
        tree,
        TreeMutation.update_node(
            "child",
            {
                "status": "running",
                "lifecycle": "running",
                "admissibility": "unevaluated",
            },
        ),
        "event:running",
        idempotency_key="key:running",
    )
    evidence = {
        "evidence_id": "evidence:failure",
        "attempt_id": "attempt:1",
        "result_id": None,
        "split_role": "development",
        "level": "observed",
        "claim": "implementation cannot satisfy the interface",
        "conditions": [],
        "status": "valid",
        "artifact_refs": [],
    }
    insight = {
        "insight_id": "insight:failure",
        "text": "Avoid this incompatible interface",
        "scope": scope(),
        "evidence_ids": ["evidence:failure"],
        "grade": "development_supported",
        "validity": "active",
        "invalidation_reason": None,
    }
    tree = apply_mutation(
        tree,
        TreeMutation.update_node(
            "child",
            {
                "status": "invalid",
                "lifecycle": "done",
                "admissibility": "invalid",
                "attempt_ids": ["attempt:1"],
                "evidence_refs": [evidence],
                "insights": [insight],
                "failure": {
                    "failure_type": "invalid_candidate",
                    "summary": "interface mismatch",
                    "evidence_ids": ["evidence:failure"],
                },
            },
        ),
        "event:invalid",
        idempotency_key="key:invalid",
    )
    propagated = apply_mutation(
        tree,
        TreeMutation.propagate_insight("child", "root", "insight:failure"),
        "event:propagate",
        idempotency_key="key:propagate",
    )
    assert propagated.get_node("root").insights[0]["scope"]["time_range"] == "2020/2021"
    assert propagated.get_node("root").evidence_refs[0]["attempt_id"] == "attempt:1"

    mutation = TreeMutation.propagate_insight("child", "root", "insight:failure")
    _, _, replay_payload = prepare_mutation(
        propagated,
        mutation,
        event_id="event:propagate-again",
        idempotency_key="key:propagate-again",
    )
    assert replay_payload["changed_nodes"] == []


def test_mutation_conflicts_for_immutable_scope_and_wrong_ancestry() -> None:
    tree = apply_mutation(
        initial_tree(),
        TreeMutation.add_node(draft("child", "root")),
        "event:add",
        idempotency_key="key:add",
    )
    with pytest.raises(TreeConflictError):
        prepare_mutation(
            tree,
            TreeMutation.update_node("child", {"scope": scope(market="other")}),
            event_id="event:bad",
        )

    sibling_tree = apply_mutation(
        tree,
        TreeMutation.add_node(draft("sibling", "root")),
        "event:sibling",
        idempotency_key="key:sibling",
    )
    with pytest.raises(TreeConflictError):
        prepare_mutation(
            sibling_tree,
            TreeMutation.propagate_insight("child", "sibling", "missing"),
            event_id="event:bad-propagate",
        )


def test_event_tamper_is_integrity_failure() -> None:
    tree = initial_tree()
    mutation = TreeMutation.add_node(draft("child", "root"))
    event_type, node_id, payload = prepare_mutation(
        tree,
        mutation,
        event_id="event:add",
        idempotency_key="key:add",
    )
    event = ledger_event(
        tree=tree,
        event_id="event:add",
        event_type=event_type,
        node_id=node_id,
        payload=payload,
    )
    event["payload"]["changed_nodes"][0]["last_event_id"] = "event:tampered"
    event["event_hash"] = compute_ledger_event_hash(event)
    with pytest.raises(TreeIntegrityError):
        apply_tree_event(tree, event)


def test_mutation_request_hash_binds_revision_and_key() -> None:
    mutation = TreeMutation.prune_subtree("child", "stop branch")
    assert mutation.request_hash(1, "key:a") != mutation.request_hash(2, "key:a")
    assert mutation.request_hash(1, "key:a") != mutation.request_hash(1, "key:b")
    assert json.loads(mutation.to_json()) == mutation.to_dict()


def test_admissible_grade_and_huge_integer_score_boundaries() -> None:
    node = materialize_node_draft(
        draft("root", None), depth=0, event_id="event:start"
    ).to_dict()
    evidence = {
        "evidence_id": "evidence:dev",
        "attempt_id": None,
        "result_id": None,
        "split_role": "development",
        "level": "observed",
        "claim": "bounded development observation",
        "conditions": [],
        "status": "valid",
        "artifact_refs": [],
    }
    node.update(
        {
            "status": "done",
            "lifecycle": "done",
            "admissibility": "admissible",
            "evidence_refs": [evidence],
        }
    )
    assert freeze_node(node).score is None
    evidence["result_id"] = "result:dev"
    node["score"] = 10**1000
    assert freeze_node(node).score == 10**1000

    node["score"] = None
    node["insights"] = [
        {
            "insight_id": "insight:gate",
            "text": "claimed gate result",
            "scope": scope(),
            "evidence_ids": ["evidence:dev"],
            "grade": "gate_supported",
            "validity": "active",
            "invalidation_reason": None,
        }
    ]
    with pytest.raises(HypothesisInvariantError):
        freeze_node(node)
    node["insights"] = []
    node["evidence_refs"] = []
    with pytest.raises(HypothesisInvariantError):
        freeze_node(node)


def test_existing_evidence_and_insight_records_cannot_be_erased() -> None:
    tree = apply_mutation(
        initial_tree(),
        TreeMutation.add_node(draft("child", "root")),
        "event:add",
        idempotency_key="key:add",
    )
    evidence = {
        "evidence_id": "evidence:failure",
        "attempt_id": None,
        "result_id": None,
        "split_role": "development",
        "level": "observed",
        "claim": "candidate is invalid",
        "conditions": [],
        "status": "valid",
        "artifact_refs": [],
    }
    insight = {
        "insight_id": "insight:failure",
        "text": "avoid this candidate shape",
        "scope": scope(),
        "evidence_ids": ["evidence:failure"],
        "grade": "development_supported",
        "validity": "active",
        "invalidation_reason": None,
    }
    tree = apply_mutation(
        tree,
        TreeMutation.update_node(
            "child",
            {
                "status": "invalid",
                "lifecycle": "done",
                "admissibility": "invalid",
                "evidence_refs": [evidence],
                "insights": [insight],
                "failure": {
                    "failure_type": "invalid_candidate",
                    "summary": "pre-dispatch validation failed",
                    "evidence_ids": ["evidence:failure"],
                },
            },
        ),
        "event:invalid",
        idempotency_key="key:invalid",
    )
    with pytest.raises(TreeConflictError):
        prepare_mutation(
            tree,
            TreeMutation.update_node("child", {"evidence_refs": []}),
            event_id="event:erase-evidence",
        )
    with pytest.raises(TreeConflictError):
        prepare_mutation(
            tree,
            TreeMutation.update_node("child", {"insights": []}),
            event_id="event:erase-insight",
        )
    conflicting_insight = dict(insight)
    conflicting_insight["text"] = "different content under the same ID"
    with pytest.raises(TreeConflictError):
        prepare_mutation(
            tree,
            TreeMutation.update_node(
                "root",
                {
                    "evidence_refs": [evidence],
                    "insights": [conflicting_insight],
                },
            ),
            event_id="event:identity-conflict",
        )
    with pytest.raises(TreeConflictError):
        prepare_mutation(
            tree,
            TreeMutation.update_node(
                "child",
                {
                    "failure": {
                        "failure_type": "invalid_candidate",
                        "summary": "rewritten terminal history",
                        "evidence_ids": ["evidence:failure"],
                    }
                },
            ),
            event_id="event:rewrite-failure",
        )

    invalidated_evidence = dict(evidence)
    invalidated_evidence["status"] = "invalidated"
    invalidated_insight = dict(insight)
    invalidated_insight.update(
        {"validity": "invalidated", "invalidation_reason": "new contrary evidence"}
    )
    _, _, payload = prepare_mutation(
        tree,
        TreeMutation.update_node(
            "child",
            {
                "evidence_refs": [invalidated_evidence],
                "insights": [invalidated_insight],
            },
        ),
        event_id="event:invalidate",
    )
    assert payload["changed_nodes"][0]["insights"][0]["grade"] == (
        "development_supported"
    )


def test_insight_evidence_and_grade_can_upgrade_monotonically() -> None:
    tree = apply_mutation(
        initial_tree(),
        TreeMutation.add_node(draft("child", "root")),
        "event:add",
        idempotency_key="key:add",
    )
    dev = {
        "evidence_id": "evidence:dev",
        "attempt_id": None,
        "result_id": None,
        "split_role": "development",
        "level": "observed",
        "claim": "development support",
        "conditions": [],
        "status": "valid",
        "artifact_refs": [],
    }
    initial_insight = {
        "insight_id": "insight:upgrade",
        "text": "bounded finding",
        "scope": scope(),
        "evidence_ids": ["evidence:dev"],
        "grade": "unverified",
        "validity": "uncertain",
        "invalidation_reason": None,
    }
    tree = apply_mutation(
        tree,
        TreeMutation.update_node(
            "child",
            {
                "status": "invalid",
                "lifecycle": "done",
                "admissibility": "invalid",
                "evidence_refs": [dev],
                "insights": [initial_insight],
                "failure": {
                    "failure_type": "invalid_candidate",
                    "summary": "bounded failure",
                    "evidence_ids": ["evidence:dev"],
                },
            },
        ),
        "event:record",
        idempotency_key="key:record",
    )
    development_insight = dict(initial_insight)
    development_insight.update({"grade": "development_supported", "validity": "active"})
    tree = apply_mutation(
        tree,
        TreeMutation.update_node("child", {"insights": [development_insight]}),
        "event:dev-grade",
        idempotency_key="key:dev-grade",
    )
    gate = dict(dev)
    gate.update(
        {
            "evidence_id": "evidence:gate",
            "split_role": "gate",
            "claim": "gate support",
        }
    )
    gate_insight = dict(development_insight)
    gate_insight.update(
        {
            "evidence_ids": ["evidence:dev", "evidence:gate"],
            "grade": "gate_supported",
        }
    )
    _, _, payload = prepare_mutation(
        tree,
        TreeMutation.update_node(
            "child",
            {"evidence_refs": [dev, gate], "insights": [gate_insight]},
        ),
        event_id="event:gate-grade",
    )
    assert payload["changed_nodes"][0]["insights"][0]["grade"] == "gate_supported"


def test_run_started_request_and_semantic_scope_are_bound() -> None:
    node_id, payload_a = prepare_run_started(
        run_id="run:unit",
        contract_hash=HASH_C,
        root=draft("root", None),
        event_id="event:start",
        idempotency_key="key:a",
    )
    _, payload_b = prepare_run_started(
        run_id="run:unit",
        contract_hash=HASH_C,
        root=draft("root", None),
        event_id="event:start",
        idempotency_key="key:b",
    )
    assert payload_a["request_hash"] != payload_b["request_hash"]
    event = ledger_event(
        tree=None,
        event_id="event:start",
        event_type="run.started",
        node_id=node_id,
        payload=payload_a,
    )
    event["actor"] = "user"
    event["event_hash"] = compute_ledger_event_hash(event)
    with pytest.raises(TreeConflictError):
        apply_tree_event(None, event)
    event["split_role"] = "none"
    event["timestamp"] = "definitely-not-date-time"
    event["event_hash"] = compute_ledger_event_hash(event)
    with pytest.raises(HypothesisSchemaError):
        apply_tree_event(None, event)
    event["actor"] = "system"
    event["timestamp"] = "2026-08-09T00:00:00Z"
    event["split_role"] = "final"
    event["event_hash"] = compute_ledger_event_hash(event)
    with pytest.raises(TreeConflictError):
        apply_tree_event(None, event)


def test_compatibility_labels_are_closed_and_non_locating() -> None:
    root = materialize_node_draft(
        draft("root", None), depth=0, event_id="event:start"
    ).to_dict()
    compatibility = {
        "source": "arbor.idea_tree",
        "source_version": "3",
        "quarantined": True,
        "missing_fields_by_node": {"root": ["scope.market"]},
        "legacy_scores_by_node": {
            "root": {
                "score": None,
                "score_source": None,
                "score_split": None,
                "test_score": None,
            }
        },
        "legacy_status_by_node": {
            "root": {
                "status": "pending",
                "eval_status": None,
                "stop_reason": None,
                "attempt": 1,
                "result_sha256": None,
                "insight_sha256": None,
                "code_ref_sha256": None,
                "related_work_sha256": None,
                "grounding_sha256": None,
            }
        },
        "safe_meta": {"metric_direction": "maximize", "max_depth": None},
        "dropped_meta_keys": ["eval_cmd"],
    }
    mapping = {
        "schema_version": "1.0",
        "run_id": "run:unit",
        "revision": 0,
        "contract_hash": HASH_C,
        "root_node_id": "root",
        "run_state": "development",
        "ledger_head": {"last_sequence": 1, "last_event_hash": HASH_A},
        "nodes": [root],
        "counts": project_counts([root], "root"),
        "compatibility": compatibility,
    }
    assert freeze_tree(mapping).compatibility is not None
    bad = copy.deepcopy(mapping)
    bad["compatibility"]["missing_fields_by_node"]["root"] = [
        "../../restricted/final.csv"
    ]
    with pytest.raises(HypothesisInvariantError):
        freeze_tree(bad)
    bad = copy.deepcopy(mapping)
    bad["compatibility"]["dropped_meta_keys"] = ["token=secret"]
    with pytest.raises(HypothesisInvariantError):
        freeze_tree(bad)
