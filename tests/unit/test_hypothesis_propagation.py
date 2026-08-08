from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable

import pytest

from q_arbor.hypotheses import (
    HypothesisTreeStore,
    NodeDraft,
    TreeConflictError,
    TreeMutation,
)
from tests.hypothesis_helpers import (
    CONTRACT_HASH,
    active_insight,
    deterministic_clock,
    deterministic_event_id,
    node_draft_kwargs,
    node_record,
    scope_mapping,
    valid_observed_evidence,
)


def _new_store(tmp_path: Path) -> HypothesisTreeStore:
    root = NodeDraft(**node_draft_kwargs("root", parent_id=None, proposal_order=1))
    return HypothesisTreeStore.create(
        tmp_path / "state",
        run_id="run.propagation",
        contract_hash=CONTRACT_HASH,
        root=root,
        clock=deterministic_clock,
        event_id_factory=deterministic_event_id,
    )


def _apply(
    store: HypothesisTreeStore,
    mutation: TreeMutation,
    key: str,
) -> object:
    current = store.load()
    return store.apply(
        mutation,
        expected_revision=current.revision,
        idempotency_key=key,
    )


def _add_node(
    store: HypothesisTreeStore,
    node_id: str,
    parent_id: str,
    proposal_order: int,
    *,
    scope: dict[str, Any] | None = None,
) -> object:
    draft = NodeDraft(
        **node_draft_kwargs(
            node_id,
            parent_id=parent_id,
            proposal_order=proposal_order,
            scope=scope,
        )
    )
    return _apply(store, TreeMutation.add_node(draft), f"add.{node_id}")


def _failure_insight_updates(
    node_id: str,
    *,
    scope: dict[str, Any] | None = None,
    evidence_status: str = "valid",
    grade: str = "development_supported",
    validity: str = "active",
    failure_type: str = "constraint_violation",
) -> dict[str, Any]:
    evidence = valid_observed_evidence(node_id, status=evidence_status)
    insight = active_insight(
        node_id,
        scope=scope,
        grade=grade,
        validity=validity,
    )
    admissibility = {
        "contamination": "contaminated",
        "incomparable": "incomparable",
    }.get(failure_type, "invalid")
    status = {
        "contamination": "contaminated",
        "incomparable": "incomparable",
    }.get(failure_type, "invalid")
    if validity != "active":
        insight["invalidation_reason"] = "qualification fixture"
    return {
        "status": status,
        "lifecycle": "done",
        "admissibility": admissibility,
        "attempt_ids": [f"attempt.{node_id}"],
        "evidence_refs": [evidence],
        "insights": [insight],
        "failure": {
            "failure_type": failure_type,
            "summary": f"Bounded failure for {node_id}.",
            "evidence_ids": [f"evidence.{node_id}"],
        },
    }


def _attach_failure_insight(
    store: HypothesisTreeStore,
    node_id: str,
    **updates: Any,
) -> object:
    _apply(
        store,
        TreeMutation.update_node(
            node_id,
            {
                "status": "running",
                "lifecycle": "running",
                "admissibility": "unevaluated",
            },
        ),
        f"start.{node_id}",
    )
    content = _failure_insight_updates(node_id, **updates)
    return _apply(
        store,
        TreeMutation.update_node(node_id, content),
        f"finish.{node_id}",
    )


def test_failed_child_insight_propagates_upward_without_scope_generalization(
    tmp_path: Path,
) -> None:
    store = _new_store(tmp_path)
    source_scope = scope_mapping(
        time_range="2020-03-01/2020-06-30",
        fields=["close"],
        regime_labels=["high-volatility"],
    )
    _add_node(store, "child", "root", 2)
    _add_node(store, "grandchild", "child", 3, scope=source_scope)
    source_tree = _attach_failure_insight(
        store, "grandchild", scope=source_scope
    )
    source_before = node_record(source_tree, "grandchild")

    propagated = _apply(
        store,
        TreeMutation.propagate_insight(
            "grandchild", "root", "insight.grandchild"
        ),
        "propagate.grandchild.root",
    )
    root = node_record(propagated, "root")
    source_after = node_record(propagated, "grandchild")

    assert root["insights"] == source_before["insights"]
    assert root["evidence_refs"] == source_before["evidence_refs"]
    assert root["insights"][0]["scope"] == source_scope
    assert root["failure"]["failure_type"] == "none"
    assert source_after == source_before


def test_duplicate_identical_propagation_is_semantically_idempotent(
    tmp_path: Path,
) -> None:
    store = _new_store(tmp_path)
    _add_node(store, "child", "root", 2)
    _attach_failure_insight(store, "child")
    mutation = TreeMutation.propagate_insight(
        "child", "root", "insight.child"
    )
    first = _apply(store, mutation, "propagate.first")
    second = _apply(store, mutation, "propagate.second")

    first_root = node_record(first, "root")
    second_root = node_record(second, "root")
    assert len(second_root["insights"]) == 1
    assert len(second_root["evidence_refs"]) == 1
    assert second_root["insights"] == first_root["insights"]
    assert second_root["evidence_refs"] == first_root["evidence_refs"]


def test_same_insight_id_with_different_content_is_conflict(tmp_path: Path) -> None:
    store = _new_store(tmp_path)
    _add_node(store, "child", "root", 2)
    _attach_failure_insight(store, "child")
    source = node_record(store.load(), "child")
    conflicting = copy.deepcopy(source["insights"][0])
    conflicting["text"] = "Different canonical content under one insight ID."
    root_updates = {
        "evidence_refs": copy.deepcopy(source["evidence_refs"]),
        "insights": [conflicting],
    }
    _apply(
        store,
        TreeMutation.update_node("root", root_updates),
        "seed.conflicting.insight",
    )
    before = store.load().to_dict()

    with pytest.raises(TreeConflictError):
        _apply(
            store,
            TreeMutation.propagate_insight(
                "child", "root", "insight.child"
            ),
            "propagate.conflicting",
        )

    assert store.load().to_dict() == before


@pytest.mark.parametrize(
    ("field", "different"),
    [
        ("market", "other-market"),
        ("universe", "other-universe"),
        ("frequency", "hourly"),
        ("horizon", "five-day"),
        ("data_snapshot_sha256", "1" * 64),
        ("cost_model_sha256", "2" * 64),
    ],
)
def test_propagation_rejects_every_required_scope_mismatch(
    tmp_path: Path, field: str, different: str
) -> None:
    store = _new_store(tmp_path)
    source_scope = scope_mapping(**{field: different})
    _add_node(store, "child", "root", 2, scope=source_scope)
    _attach_failure_insight(store, "child", scope=source_scope)
    before = store.load().to_dict()

    with pytest.raises(TreeConflictError):
        _apply(
            store,
            TreeMutation.propagate_insight(
                "child", "root", "insight.child"
            ),
            f"propagate.scope.{field}",
        )

    assert store.load().to_dict() == before


def test_propagation_rejects_sibling_transfer(tmp_path: Path) -> None:
    store = _new_store(tmp_path)
    _add_node(store, "left", "root", 2)
    _add_node(store, "right", "root", 3)
    _attach_failure_insight(store, "left")
    before = store.load().to_dict()

    with pytest.raises(TreeConflictError):
        _apply(
            store,
            TreeMutation.propagate_insight(
                "left", "right", "insight.left"
            ),
            "propagate.sibling",
        )

    assert store.load().to_dict() == before


@pytest.mark.parametrize(
    "update",
    [
        pytest.param(
            lambda: {
                "evidence_status": "invalidated",
                "validity": "invalidated",
            },
            id="invalidated-evidence",
        ),
        pytest.param(
            lambda: {
                "evidence_status": "contaminated",
                "validity": "invalidated",
                "failure_type": "contamination",
            },
            id="contaminated-evidence",
        ),
        pytest.param(
            lambda: {"validity": "uncertain"}, id="uncertain-insight"
        ),
        pytest.param(
            lambda: {"grade": "contradicted"}, id="contradicted-insight"
        ),
    ],
)
def test_propagation_rejects_nonactive_or_tainted_insight(
    tmp_path: Path,
    update: Callable[[], dict[str, Any]],
) -> None:
    store = _new_store(tmp_path)
    _add_node(store, "child", "root", 2)
    _attach_failure_insight(store, "child", **update())
    before = store.load().to_dict()

    with pytest.raises(TreeConflictError):
        _apply(
            store,
            TreeMutation.propagate_insight(
                "child", "root", "insight.child"
            ),
            "propagate.rejected",
        )

    assert store.load().to_dict() == before


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("id", "changed"),
        ("parent_id", "changed"),
        ("depth", 99),
        ("hypothesis", {"mechanism": "changed"}),
        ("scope", {"market": "changed"}),
        ("family", {"family_id": "changed"}),
        ("prompt_snapshot_sha256", "9" * 64),
        ("created_event_id", "event.changed"),
        ("children_ids", ["forged-child"]),
    ],
)
def test_update_rejects_immutable_or_derived_node_fields(
    tmp_path: Path, field: str, replacement: object
) -> None:
    store = _new_store(tmp_path)
    _add_node(store, "child", "root", 2)
    before = store.load().to_dict()

    with pytest.raises(TreeConflictError):
        _apply(
            store,
            TreeMutation.update_node("child", {field: replacement}),
            f"immutable.{field}",
        )

    assert store.load().to_dict() == before


def test_prune_subtree_preserves_prior_admissibility(tmp_path: Path) -> None:
    store = _new_store(tmp_path)
    _add_node(store, "child", "root", 2)
    _add_node(store, "grandchild", "child", 3)
    pruned = _apply(
        store,
        TreeMutation.prune_subtree("child", "No remaining bounded path"),
        "prune.child",
    )

    for node_id in ("child", "grandchild"):
        node = node_record(pruned, node_id)
        assert node["status"] == "pruned"
        assert node["lifecycle"] == "pruned"
        assert node["admissibility"] == "unevaluated"
    assert node_record(pruned, "root")["status"] == "pending"
