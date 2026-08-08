from __future__ import annotations

import copy
import hashlib
import json
import os
import unicodedata
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, Callable

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from q_arbor.hypotheses import (
    LEGACY_UNKNOWN_HASH,
    LEGACY_UNKNOWN_TEXT,
    ArborImportResult,
    HypothesisInvariantError,
    HypothesisTreeStore,
    TreeCompatibilityError,
    TreeMutation,
    TreePersistenceError,
    apply_tree_event,
    export_tree_json,
    freeze_tree,
    import_arbor_tree,
    render_tree_html,
    write_tree_html,
)
from q_arbor.spec import load_schema
from tests.hypothesis_helpers import (
    CONTRACT_HASH,
    arbor_v3_mapping,
    canonical_json,
    scope_mapping,
)


def _text_sha256(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def _import() -> ArborImportResult:
    return import_arbor_tree(
        arbor_v3_mapping(),
        run_id="run.compatibility",
        contract_hash=CONTRACT_HASH,
    )


def _compatibility(result: ArborImportResult) -> dict[str, Any]:
    value = result.tree.to_dict()["compatibility"]
    assert isinstance(value, dict)
    return value


def test_pinned_arbor_v3_import_is_deterministic_immutable_and_replayable() -> None:
    first = _import()
    second = _import()

    assert isinstance(first, ArborImportResult)
    assert isinstance(first.events, tuple)
    assert isinstance(first.warnings, tuple)
    assert first.tree.to_dict() == second.tree.to_dict()
    assert [canonical_json(event) for event in first.events] == [
        canonical_json(event) for event in second.events
    ]
    assert first.warnings == second.warnings
    with pytest.raises((FrozenInstanceError, AttributeError)):
        first.tree = second.tree  # type: ignore[misc]
    with pytest.raises(TypeError):
        first.tree.compatibility["quarantined"] = False  # type: ignore[index]

    events = [json.loads(canonical_json(event)) for event in first.events]
    assert [event["sequence"] for event in events] == list(
        range(1, len(events) + 1)
    )
    assert events[0]["event_type"] == "run.started"
    assert all(event["timestamp"] == "1970-01-01T00:00:00Z" for event in events)
    assert first.tree.revision == len(events) - 1
    assert first.tree.ledger_head["last_sequence"] == len(events)
    assert first.tree.ledger_head["last_event_hash"] == events[-1]["event_hash"]

    validator = Draft202012Validator(load_schema(), format_checker=FormatChecker())
    replayed = None
    for event in events:
        validator.validate({"artifact_type": "ledger_event", "payload": event})
        content = copy.deepcopy(event)
        event_hash = content.pop("event_hash")
        assert event_hash == hashlib.sha256(
            canonical_json(content).encode("utf-8")
        ).hexdigest()
        replayed = apply_tree_event(replayed, event)
    assert replayed is not None
    assert replayed.to_dict() == first.tree.to_dict()


def test_import_never_promotes_legacy_scores_or_invents_c9_c10_evidence() -> None:
    result = _import()
    tree = result.tree.to_dict()

    assert tree["counts"] == {
        "proposals": 2,
        "unique_candidates": 0,
        "candidate_families": 1,
        "attempts": 0,
        "evaluation_queries": 0,
        "admissible_evidence": 0,
    }
    for node in tree["nodes"]:
        assert node["status"] == "pending"
        assert node["lifecycle"] == "pending"
        assert node["admissibility"] == "unevaluated"
        assert node["score"] is None
        assert node["candidate_id"] is None
        assert node["attempt_ids"] == []
        assert node["evidence_refs"] == []
        assert node["insights"] == []
        assert node["failure"]["failure_type"] == "none"

    compatibility = tree["compatibility"]
    assert compatibility["quarantined"] is True
    assert compatibility["legacy_scores_by_node"] == {
        "ROOT": {
            "score": 0.1,
            "score_source": "score",
            "score_split": "dev",
            "test_score": None,
        },
        "1": {
            "score": 0.16,
            "score_source": "score",
            "score_split": "dev",
            "test_score": 0.13,
        },
        "2": {
            "score": -0.02,
            "score_source": "score_delta",
            "score_split": "dev",
            "test_score": None,
        },
    }


def test_legacy_status_projection_hashes_free_text_and_has_exact_shape() -> None:
    source = arbor_v3_mapping()["nodes"]
    status_by_node = _compatibility(_import())["legacy_status_by_node"]
    expected_keys = {
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

    assert set(status_by_node) == {"ROOT", "1", "2"}
    for node_id, projection in status_by_node.items():
        assert set(projection) == expected_keys
        legacy = source[node_id]
        assert projection["status"] == legacy["status"]
        assert projection["eval_status"] == legacy.get("eval_status")
        assert projection["stop_reason"] == legacy.get("stop_reason")
        assert projection["attempt"] == legacy.get("attempt", 1)
        for field in ("result", "insight", "code_ref", "related_work", "grounding"):
            expected = (
                _text_sha256(legacy[field]) if legacy.get(field) else None
            )
            assert projection[f"{field}_sha256"] == expected


def test_missing_flags_and_compatibility_sentinels_are_explicit() -> None:
    result = _import()
    tree = result.tree.to_dict()
    compatibility = tree["compatibility"]

    assert LEGACY_UNKNOWN_HASH == "0" * 64
    assert LEGACY_UNKNOWN_TEXT == "legacy:unspecified"
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
    missing = compatibility["missing_fields_by_node"]
    assert set(missing) == {"ROOT", "1", "2"}
    for fields in missing.values():
        assert fields
        assert fields == sorted(set(fields))
        assert any("scope" in field for field in fields)
        assert any("prediction" in field for field in fields)

    family_ids = {node["family"]["family_id"] for node in tree["nodes"]}
    assert family_ids == {LEGACY_UNKNOWN_TEXT}
    for node in tree["nodes"]:
        assert node["scope"]["data_snapshot_sha256"] == LEGACY_UNKNOWN_HASH
        assert node["scope"]["cost_model_sha256"] == LEGACY_UNKNOWN_HASH
        assert node["hypothesis"]["mechanism"] == arbor_v3_mapping()["nodes"][
            node["id"]
        ]["hypothesis"]


def test_safe_meta_allowlist_and_dropped_values_do_not_leak() -> None:
    result = _import()
    compatibility = _compatibility(result)
    unknown_label = f"unknown-sha256:{_text_sha256('plugin_payload')}"
    known_dropped = {
        "baseline_score",
        "trunk_score",
        "test_baseline_score",
        "test_trunk_score",
        "eval_timeout",
        "eval_retries",
        "eval_cmd",
        "eval_cmd_test",
        "dataset_info",
        "submission_path",
        "sample_submission_path",
    }

    assert compatibility["safe_meta"] == {
        "metric_direction": "maximize",
        "max_depth": 3,
    }
    assert set(compatibility["dropped_meta_keys"]) == known_dropped | {
        unknown_label
    }
    assert compatibility["dropped_meta_keys"] == sorted(
        compatibility["dropped_meta_keys"]
    )

    serialized = "\n".join(
        [
            export_tree_json(result.tree),
            *(canonical_json(event) for event in result.events),
            *result.warnings,
        ]
    )
    for forbidden in (
        "SYNTHETIC_SECRET",
        "/srv/hidden/final.csv",
        "/srv/private/submission.csv",
        "../hidden/sample.csv",
        "python evaluator.py",
        "python hidden_evaluator.py",
        "plugin_payload",
    ):
        assert forbidden not in serialized


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda compatibility: compatibility["safe_meta"].update(
                baseline_score=0.1
            ),
            id="safe-meta-not-allowlisted",
        ),
        pytest.param(
            lambda compatibility: compatibility["dropped_meta_keys"].append(
                "api_token=SYNTHETIC_SECRET"
            ),
            id="dropped-secret-value",
        ),
        pytest.param(
            lambda compatibility: compatibility["legacy_scores_by_node"][
                "ROOT"
            ].update(score_source="guessed"),
            id="score-source",
        ),
        pytest.param(
            lambda compatibility: compatibility["legacy_status_by_node"][
                "ROOT"
            ].update(result="raw result must not survive"),
            id="raw-status-extra-field",
        ),
        pytest.param(
            lambda compatibility: compatibility["missing_fields_by_node"][
                "ROOT"
            ].append(
                compatibility["missing_fields_by_node"]["ROOT"][0]
            ),
            id="duplicate-missing-flag",
        ),
    ],
)
def test_crafted_compatibility_metadata_invariants_fail_closed(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    mapping = _import().tree.to_dict()
    mutate(mapping["compatibility"])

    with pytest.raises(HypothesisInvariantError):
        freeze_tree(mapping)


def test_invalid_legacy_meta_is_dropped_and_never_echoed() -> None:
    legacy = arbor_v3_mapping()
    legacy["meta"]["metric_direction"] = "sideways:SYNTHETIC_META_SECRET"
    legacy["max_depth"] = 0
    legacy["meta"]["unknown_secret_key"] = "SYNTHETIC_UNKNOWN_VALUE"

    result = import_arbor_tree(
        legacy,
        run_id="run.invalid-meta",
        contract_hash=CONTRACT_HASH,
    )
    serialized = "\n".join(
        [
            export_tree_json(result.tree),
            *(canonical_json(event) for event in result.events),
            *result.warnings,
        ]
    )

    assert result.tree.compatibility["quarantined"] is True
    assert "sideways:SYNTHETIC_META_SECRET" not in serialized
    assert "SYNTHETIC_UNKNOWN_VALUE" not in serialized
    assert "unknown_secret_key" not in serialized


def test_individual_arbor_node_is_normalized_without_guessing_parentage() -> None:
    legacy_node = arbor_v3_mapping()["nodes"]["2"]
    result = import_arbor_tree(
        legacy_node,
        run_id="run.single-node",
        contract_hash=CONTRACT_HASH,
        default_scope=scope_mapping(),
    )
    tree = result.tree.to_dict()
    node = tree["nodes"][0]
    status = tree["compatibility"]["legacy_status_by_node"]["2"]

    assert tree["root_node_id"] == "2"
    assert len(tree["nodes"]) == 1
    assert node["parent_id"] is None
    assert node["depth"] == 0
    assert node["scope"] == scope_mapping()
    assert status["source_parent_id"] == "ROOT"
    assert status["source_depth"] == 1
    assert status["result_sha256"] == _text_sha256("Pre-v3 score field")
    assert tree["compatibility"]["legacy_scores_by_node"]["2"][
        "score_source"
    ] == "score_delta"


def test_structurally_invalid_legacy_topology_is_compatibility_error() -> None:
    legacy = arbor_v3_mapping()
    legacy["nodes"]["1"]["parent_id"] = "missing"

    with pytest.raises(TreeCompatibilityError):
        import_arbor_tree(
            legacy,
            run_id="run.bad-topology",
            contract_hash=CONTRACT_HASH,
        )


def test_canonical_json_and_escaped_self_contained_html_exports(
    tmp_path: Path,
) -> None:
    result = _import()
    exported = export_tree_json(result.tree)
    injected_title = "Tree </title><script>alert('title')</script>"
    first_html = render_tree_html(result.tree, title=injected_title)
    second_html = render_tree_html(result.tree, title=injected_title)

    assert exported == result.tree.to_json()
    assert exported == canonical_json(result.tree.to_dict())
    assert first_html == second_html
    assert "Baseline" in first_html
    assert "robust reversal" in first_html
    for required_section in (
        "admissibility",
        "scope",
        "evidence",
        "failure",
        "insight",
        "compatibility",
    ):
        assert required_section in first_html.casefold()
    assert "http://" not in first_html
    assert "https://" not in first_html
    assert "<link" not in first_html.lower()
    assert "<script src=" not in first_html.lower()
    for injection in (
        "</title><script>alert('title')</script>",
        "<script>alert('root')</script>",
        "</script><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
    ):
        assert injection not in first_html

    target = tmp_path / "tree.html"
    write_tree_html(result.tree, target, title=injected_title)
    assert target.read_text(encoding="utf-8") == first_html


def test_html_write_failure_does_not_replace_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _import()
    target = tmp_path / "tree.html"
    target.write_text("sentinel", encoding="utf-8")

    def fail_replace(source: os.PathLike[str], destination: os.PathLike[str]) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(TreePersistenceError):
        write_tree_html(result.tree, target)

    assert target.read_text(encoding="utf-8") == "sentinel"
    assert tuple(tmp_path.iterdir()) == (target,)


def test_quarantined_import_cannot_propagate_through_store(tmp_path: Path) -> None:
    result = _import()
    directory = tmp_path / "state"
    directory.mkdir()
    result.tree.write(directory / "tree.json")
    event_text = "".join(
        f"{canonical_json(event)}\n" for event in result.events
    )
    (directory / "tree.events.jsonl").write_text(event_text, encoding="utf-8")
    store = HypothesisTreeStore.open(directory)
    assert store.recover().to_dict() == result.tree.to_dict()

    with pytest.raises(TreeCompatibilityError):
        store.apply(
            TreeMutation.propagate_insight("1", "ROOT", "insight.legacy"),
            expected_revision=result.tree.revision,
            idempotency_key="compat.propagation",
        )
