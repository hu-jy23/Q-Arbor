from __future__ import annotations

import copy
import hashlib
import os
import unicodedata
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from q_arbor.hypotheses import (
    HypothesisDecodeError,
    HypothesisError,
    HypothesisInvariantError,
    HypothesisSchemaError,
    NodeDraft,
    QHypothesisTree,
    QuantHypothesisNode,
    TreeCompatibilityError,
    TreeConflictError,
    TreeIntegrityError,
    TreeMutation,
    TreePersistenceError,
    freeze_node,
    freeze_tree,
    load_tree,
    validate_node,
    validate_tree,
)
from tests.hypothesis_helpers import (
    canonical_json,
    expected_tree_hash,
    node_draft_kwargs,
    valid_node_mapping,
    valid_observed_evidence,
    valid_tree_draft_mapping,
)


def _frozen_tree_mapping() -> dict[str, Any]:
    return freeze_tree(valid_tree_draft_mapping()).to_dict()


def _child(mapping: dict[str, Any]) -> dict[str, Any]:
    return next(node for node in mapping["nodes"] if node["id"] == "node.child")


@pytest.mark.parametrize(
    "error_type",
    [
        HypothesisDecodeError,
        HypothesisSchemaError,
        HypothesisInvariantError,
        TreeConflictError,
        TreeIntegrityError,
        TreeCompatibilityError,
        TreePersistenceError,
    ],
)
def test_public_errors_share_one_hypothesis_error_base(
    error_type: type[Exception],
) -> None:
    assert issubclass(error_type, HypothesisError)


def test_node_freeze_round_trip_is_canonical_normalized_and_detached() -> None:
    draft = valid_node_mapping()
    draft["hypothesis"]["mechanism"] += " Café"
    decomposed = copy.deepcopy(draft)
    mechanism = decomposed["hypothesis"]["mechanism"]
    decomposed["hypothesis"]["mechanism"] = unicodedata.normalize("NFD", mechanism)
    assert decomposed["hypothesis"]["mechanism"] != mechanism

    node = freeze_node(decomposed)
    validated = validate_node(node.to_dict())

    assert isinstance(node, QuantHypothesisNode)
    assert node.to_dict() == draft
    assert validated.to_dict() == draft
    assert node.to_json() == canonical_json(draft)
    assert node.sha256 == hashlib.sha256(node.to_json().encode("utf-8")).hexdigest()
    detached = node.to_dict()
    detached["scope"]["market"] = "caller-mutated"
    detached["hypothesis"]["conflicts"].append("caller-mutated")
    assert node.to_dict() == draft


def test_node_is_deeply_immutable() -> None:
    node = freeze_node(valid_node_mapping())

    with pytest.raises((FrozenInstanceError, AttributeError)):
        node.status = "running"  # type: ignore[misc]
    with pytest.raises(TypeError):
        node.scope["market"] = "mutated"  # type: ignore[index]
    with pytest.raises((AttributeError, TypeError)):
        node.hypothesis["conflicts"].append("mutated")  # type: ignore[union-attr]


def test_node_missing_required_field_is_schema_error() -> None:
    mapping = valid_node_mapping()
    del mapping["hypothesis"]["observable"]

    with pytest.raises(HypothesisSchemaError):
        validate_node(mapping)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_node_nonfinite_values_are_decode_errors(value: float) -> None:
    mapping = valid_node_mapping()
    mapping["score"] = value

    with pytest.raises(HypothesisDecodeError):
        freeze_node(mapping)


def test_recursive_mapping_is_a_typed_decode_error() -> None:
    mapping = valid_node_mapping()
    recursive: dict[str, Any] = {}
    recursive["self"] = recursive
    mapping["hypothesis"]["conflicts"] = recursive

    with pytest.raises(HypothesisDecodeError):
        freeze_node(mapping)


@pytest.mark.parametrize(
    ("status", "lifecycle", "admissibility"),
    [
        ("pending", "running", "unevaluated"),
        ("running", "running", "admissible"),
        ("needs_retry", "pending", "unevaluated"),
        ("done", "done", "invalid"),
        ("merged", "done", "admissible"),
        ("invalid", "done", "unevaluated"),
        ("contaminated", "done", "invalid"),
        ("incomparable", "done", "contaminated"),
        ("pruned", "done", "unevaluated"),
    ],
)
def test_composite_status_table_is_enforced(
    status: str, lifecycle: str, admissibility: str
) -> None:
    mapping = valid_node_mapping()
    mapping.update(
        status=status,
        lifecycle=lifecycle,
        admissibility=admissibility,
    )

    with pytest.raises(HypothesisInvariantError):
        validate_node(mapping)


@pytest.mark.parametrize(
    ("status", "lifecycle", "admissibility", "failure_type"),
    [
        ("pending", "pending", "unevaluated", "none"),
        ("running", "running", "unevaluated", "none"),
        ("needs_retry", "needs_retry", "unevaluated", "timeout"),
        ("done", "done", "admissible", "none"),
        ("merged", "merged", "admissible", "none"),
        ("invalid", "done", "invalid", "invalid_candidate"),
        ("contaminated", "done", "contaminated", "contamination"),
        ("incomparable", "done", "incomparable", "incomparable"),
        ("pruned", "pruned", "unevaluated", "none"),
        ("pruned", "pruned", "admissible", "none"),
        ("pruned", "pruned", "invalid", "invalid_candidate"),
        ("pruned", "pruned", "contaminated", "contamination"),
        ("pruned", "pruned", "incomparable", "incomparable"),
    ],
)
def test_every_documented_composite_status_is_accepted(
    status: str,
    lifecycle: str,
    admissibility: str,
    failure_type: str,
) -> None:
    mapping = valid_node_mapping()
    mapping.update(
        status=status,
        lifecycle=lifecycle,
        admissibility=admissibility,
    )
    mapping["failure"] = {
        "failure_type": failure_type,
        "summary": "" if failure_type == "none" else "Typed outcome.",
        "evidence_ids": [],
    }
    if admissibility == "admissible":
        mapping["attempt_ids"] = ["attempt.accepted"]
        mapping["evidence_refs"] = [valid_observed_evidence("accepted")]

    validate_node(mapping)


@pytest.mark.parametrize("status", ["pending", "running", "needs_retry"])
def test_unevaluated_nodes_cannot_expose_score(status: str) -> None:
    mapping = valid_node_mapping()
    mapping.update(status=status, lifecycle=status, score=0.1)

    with pytest.raises(HypothesisInvariantError):
        validate_node(mapping)


@pytest.mark.parametrize(
    ("evidence_level", "evidence_status", "result_id"),
    [
        ("inferred", "valid", "result.child.1"),
        ("observed", "invalidated", "result.child.1"),
        ("observed", "contaminated", "result.child.1"),
        ("observed", "valid", None),
    ],
)
def test_score_requires_valid_observed_result_evidence(
    evidence_level: str, evidence_status: str, result_id: str | None
) -> None:
    mapping = valid_node_mapping()
    evidence = valid_observed_evidence(
        "score", status=evidence_status, result_id=result_id
    )
    evidence["level"] = evidence_level
    mapping.update(
        status="done",
        lifecycle="done",
        admissibility="admissible",
        score=0.25,
        attempt_ids=["attempt.score"],
        evidence_refs=[evidence],
    )

    with pytest.raises(HypothesisInvariantError):
        validate_node(mapping)


def test_valid_scored_node_is_accepted() -> None:
    mapping = valid_tree_draft_mapping()
    child = _child(mapping)

    assert validate_node(child).score == pytest.approx(0.125)


@pytest.mark.parametrize(
    ("status", "lifecycle"),
    [("done", "done"), ("merged", "merged"), ("pruned", "pruned")],
)
def test_all_admissible_terminal_statuses_may_expose_supported_score(
    status: str, lifecycle: str
) -> None:
    child = _child(valid_tree_draft_mapping())
    child.update(status=status, lifecycle=lifecycle)

    assert validate_node(child).score == pytest.approx(0.125)


@pytest.mark.parametrize("evidence_status", ["invalidated", "contaminated"])
def test_active_insight_cannot_rely_on_tainted_evidence(
    evidence_status: str,
) -> None:
    mapping = valid_tree_draft_mapping()
    child = _child(mapping)
    child["score"] = None
    child["evidence_refs"][0]["status"] = evidence_status

    with pytest.raises(HypothesisInvariantError):
        validate_node(child)


def test_insight_must_reference_local_unique_evidence() -> None:
    missing = valid_tree_draft_mapping()
    _child(missing)["insights"][0]["evidence_ids"] = ["evidence.missing"]
    duplicate = valid_tree_draft_mapping()
    duplicate_child = _child(duplicate)
    duplicate_child["score"] = None
    duplicate_child["evidence_refs"].append(
        copy.deepcopy(duplicate_child["evidence_refs"][0])
    )

    with pytest.raises(HypothesisInvariantError):
        validate_node(_child(missing))
    with pytest.raises(HypothesisInvariantError):
        validate_node(duplicate_child)


def test_tree_freeze_hash_write_load_round_trip(tmp_path: Path) -> None:
    draft = valid_tree_draft_mapping()
    expected_hash = expected_tree_hash(draft)

    frozen = freeze_tree(draft)
    mapping = frozen.to_dict()

    assert isinstance(frozen, QHypothesisTree)
    assert "tree_hash" not in draft
    assert frozen.sha256 == expected_hash
    assert mapping["tree_hash"] == expected_hash
    assert frozen.to_json() == canonical_json(mapping)
    assert validate_tree(mapping).to_dict() == mapping

    snapshot = tmp_path / "tree.json"
    frozen.write(snapshot)
    loaded = load_tree(snapshot)

    assert snapshot.read_text(encoding="utf-8") == frozen.to_json()
    assert loaded.to_dict() == mapping
    assert loaded.sha256 == expected_hash


def test_tree_write_failure_is_atomic_and_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = freeze_tree(valid_tree_draft_mapping())
    snapshot = tmp_path / "tree.json"
    sentinel = b"existing-snapshot-must-survive"
    snapshot.write_bytes(sentinel)

    def fail_replace(source: os.PathLike[str], destination: os.PathLike[str]) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(TreePersistenceError):
        tree.write(snapshot)

    assert snapshot.read_bytes() == sentinel
    assert tuple(tmp_path.iterdir()) == (snapshot,)


def test_tree_hash_is_stable_across_mapping_and_node_order() -> None:
    draft = valid_tree_draft_mapping()
    reordered = dict(reversed(tuple(draft.items())))
    reordered["nodes"] = list(reversed(reordered["nodes"]))

    first = freeze_tree(draft)
    second = freeze_tree(reordered)

    assert second.to_dict() == first.to_dict()
    assert second.sha256 == first.sha256


def test_tree_wrong_hash_is_integrity_error() -> None:
    mapping = _frozen_tree_mapping()
    mapping["tree_hash"] = "0" * 64

    with pytest.raises(TreeIntegrityError):
        validate_tree(mapping)
    assert validate_tree(mapping, verify_hash=False).to_dict() == mapping
    refrozen = freeze_tree(mapping)
    assert refrozen.sha256 == expected_tree_hash(mapping)
    assert refrozen.to_dict()["tree_hash"] != "0" * 64


def test_load_tree_uses_strict_json_decode_and_typed_schema_errors(
    tmp_path: Path,
) -> None:
    canonical = freeze_tree(valid_tree_draft_mapping()).to_json()
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        canonical.replace(
            '"run_id":"run.qualification"',
            '"run_id":"run.qualification","run_id":"run.shadow"',
            1,
        ),
        encoding="utf-8",
    )
    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text(
        canonical.replace('"score":0.125', '"score":NaN'),
        encoding="utf-8",
    )
    missing = tmp_path / "missing.json"
    missing.write_text("{}", encoding="utf-8")

    with pytest.raises(HypothesisDecodeError):
        load_tree(duplicate)
    with pytest.raises(HypothesisDecodeError):
        load_tree(nonfinite)
    with pytest.raises(HypothesisSchemaError):
        load_tree(missing)


def test_nfc_normalized_mapping_key_collision_is_decode_error() -> None:
    mapping = valid_tree_draft_mapping()
    mapping["compatibility"] = {
        "\N{LATIN SMALL LETTER E WITH ACUTE}": 1,
        "e\N{COMBINING ACUTE ACCENT}": 2,
    }

    with pytest.raises(HypothesisDecodeError):
        freeze_tree(mapping)


def test_tree_output_and_nested_state_are_detached_and_immutable() -> None:
    tree = freeze_tree(valid_tree_draft_mapping())
    detached = tree.to_dict()
    detached["nodes"][0]["scope"]["fields"].append("caller-mutated")

    assert "caller-mutated" not in tree.to_json()
    with pytest.raises((FrozenInstanceError, AttributeError)):
        tree.revision = 10  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        tree.nodes.append("mutated")  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda tree: tree.update(root_node_id="node.missing"), id="root-id"
        ),
        pytest.param(
            lambda tree: _child(tree).update(parent_id="node.missing"),
            id="missing-parent",
        ),
        pytest.param(lambda tree: _child(tree).update(depth=2), id="wrong-depth"),
        pytest.param(
            lambda tree: tree["nodes"][0].update(children_ids=[]),
            id="nonreciprocal-child",
        ),
        pytest.param(
            lambda tree: tree["nodes"].append(copy.deepcopy(tree["nodes"][0])),
            id="duplicate-id",
        ),
        pytest.param(
            lambda tree: tree["ledger_head"].update(last_sequence=99),
            id="ledger-revision",
        ),
    ],
)
def test_tree_topology_and_ledger_invariants(
    mutate: Any,
) -> None:
    mapping = _frozen_tree_mapping()
    mutate(mapping)
    mapping["tree_hash"] = expected_tree_hash(mapping)

    with pytest.raises(HypothesisInvariantError):
        validate_tree(mapping)


def test_tree_rejects_unreachable_cycle() -> None:
    mapping = _frozen_tree_mapping()
    child = _child(mapping)
    grandchild = copy.deepcopy(child)
    grandchild.update(
        id="node.grandchild",
        parent_id="node.child",
        children_ids=["node.child"],
        depth=2,
        score=None,
        status="pending",
        lifecycle="pending",
        admissibility="unevaluated",
        candidate_id="candidate.grandchild",
        attempt_ids=[],
        evidence_refs=[],
        insights=[],
        test_family_refs=[],
        lineage_refs=["node.child"],
    )
    grandchild["family"] = copy.deepcopy(child["family"])
    grandchild["family"].update(family_id="family.grandchild", proposal_order=3)
    grandchild["failure"] = {
        "failure_type": "none",
        "summary": "",
        "evidence_ids": [],
    }
    child.update(parent_id="node.grandchild", children_ids=["node.grandchild"], depth=3)
    mapping["nodes"][0]["children_ids"] = []
    mapping["nodes"].append(grandchild)
    mapping["tree_hash"] = expected_tree_hash(mapping)

    with pytest.raises(HypothesisInvariantError):
        validate_tree(mapping)


@pytest.mark.parametrize(
    "count_name",
    [
        "proposals",
        "unique_candidates",
        "candidate_families",
        "attempts",
        "evaluation_queries",
        "admissible_evidence",
    ],
)
def test_every_materialized_count_is_verified(count_name: str) -> None:
    mapping = _frozen_tree_mapping()
    mapping["counts"][count_name] += 1
    mapping["tree_hash"] = expected_tree_hash(mapping)

    with pytest.raises(HypothesisInvariantError):
        validate_tree(mapping)


def test_node_draft_and_mutation_are_immutable_and_canonically_hashed() -> None:
    draft = NodeDraft(**node_draft_kwargs("child", parent_id="root", proposal_order=2))
    mutation = TreeMutation.add_node(draft)
    expected = {
        "schema_version": "1.0",
        "kind": "add_node",
        "payload": {"draft": draft.to_dict()},
    }

    assert mutation.to_dict() == expected
    assert (
        mutation.sha256
        == hashlib.sha256(canonical_json(expected).encode("utf-8")).hexdigest()
    )
    detached = mutation.to_dict()
    detached["payload"]["draft"]["hypothesis"]["mechanism"] = "mutated"
    assert mutation.to_dict() == expected

    with pytest.raises((FrozenInstanceError, AttributeError)):
        draft.id = "mutated"  # type: ignore[misc]
    with pytest.raises(TypeError):
        draft.scope["market"] = "mutated"  # type: ignore[index]
    with pytest.raises((FrozenInstanceError, AttributeError)):
        mutation.kind = "mutated"  # type: ignore[misc]


def test_all_mutation_builders_have_exact_payload_shapes() -> None:
    update = TreeMutation.update_node("node.1", {"status": "running"})
    prune = TreeMutation.prune_subtree("node.1", "bounded failure")
    propagate = TreeMutation.propagate_insight(
        "node.1.1", "node.root", "insight.node.1.1"
    )

    assert update.to_dict()["payload"] == {
        "node_id": "node.1",
        "updates": {"status": "running"},
    }
    assert prune.to_dict()["payload"] == {
        "node_id": "node.1",
        "reason": "bounded failure",
    }
    assert propagate.to_dict()["payload"] == {
        "source_node_id": "node.1.1",
        "target_node_id": "node.root",
        "insight_id": "insight.node.1.1",
    }
