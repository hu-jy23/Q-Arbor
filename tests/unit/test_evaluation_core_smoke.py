from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from q_arbor.evaluation import (
    ArtifactRef,
    EvaluationDecodeError,
    EvaluationFailure,
    EvaluationInvariantError,
    MetricValue,
    PluginIdentity,
    ReasonCode,
)
from q_arbor.evaluation.codec import decode_json_bytes, normalize_mapping


def _artifact_mapping(**updates: object) -> dict[str, object]:
    mapping: dict[str, object] = {
        "artifact_id": "candidate.one",
        "kind": "q-arbor.synthetic-signal.v1",
        "relative_path": "strategies/candidate.json",
        "sha256": "a" * 64,
    }
    mapping.update(updates)
    return mapping


def test_primitive_values_are_canonical_detached_and_immutable(tmp_path: Path) -> None:
    source = _artifact_mapping()
    artifact = ArtifactRef.from_mapping(source)
    source["artifact_id"] = "mutated"

    assert artifact.artifact_id == "candidate.one"
    assert artifact.sha256 == hashlib.sha256(
        artifact.to_json().encode("utf-8")
    ).hexdigest()
    assert artifact.to_json() == json.dumps(
        artifact.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    )
    detached = artifact.to_dict()
    detached["artifact_id"] = "also-mutated"
    assert artifact.artifact_id == "candidate.one"
    with pytest.raises(AttributeError):
        artifact.artifact_id = "blocked"  # type: ignore[misc]

    destination = tmp_path / "artifact.json"
    artifact.write(destination)
    assert destination.read_text(encoding="utf-8") == artifact.to_json()


def test_strict_json_and_mapping_normalization_reject_ambiguity() -> None:
    with pytest.raises(EvaluationDecodeError):
        decode_json_bytes(b'{"x":1,"x":2}')
    with pytest.raises(EvaluationDecodeError):
        decode_json_bytes(b'{"x":NaN}')
    with pytest.raises(EvaluationDecodeError):
        decode_json_bytes(b"\xef\xbb\xbf{}")
    with pytest.raises(EvaluationDecodeError):
        normalize_mapping({"\N{LATIN SMALL LETTER E WITH ACUTE}": 1, "e\u0301": 2})


def test_primitive_schema_and_lexical_guards() -> None:
    PluginIdentity.from_mapping(
        {
            "name": "synthetic.signal",
            "version": "1",
            "code_sha256": "b" * 64,
            "artifact_type": "q-arbor.synthetic-signal.v1",
        }
    )
    assert MetricValue.from_mapping(
        {"name": "score", "value": 0, "direction": "maximize", "unit": "ratio"}
    ).value == 0
    assert EvaluationFailure.from_mapping(
        {
            "failure_type": "timeout",
            "summary": "evaluation.timeout",
            "evidence_ids": [],
        }
    ).summary == "evaluation.timeout"
    assert ReasonCode.parse("evaluation.timeout") == "evaluation.timeout"

    with pytest.raises(EvaluationInvariantError):
        ArtifactRef.from_mapping(
            _artifact_mapping(relative_path="strategies/*.json")
        )
    with pytest.raises(EvaluationInvariantError):
        ReasonCode.parse("contains/slash")


def test_copying_an_immutable_value_returns_same_snapshot() -> None:
    artifact = ArtifactRef.from_mapping(_artifact_mapping())
    assert copy.copy(artifact) is artifact
    assert copy.deepcopy(artifact) is artifact
