from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from q_arbor.evaluation import (
    ArtifactRef,
    CheckResult,
    EvaluationBoundaryError,
    EvaluationDecodeError,
    EvaluationError,
    EvaluationFailure,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationPersistenceError,
    EvaluationPluginError,
    EvaluationSchemaError,
    EvaluationSummary,
    FamilyEvidence,
    MetricValue,
    PluginIdentity,
    ReasonCode,
    canonical_evaluation_result_bytes,
    compute_evaluation_result_hash,
    freeze_evaluation_result,
    load_evaluation_result,
    validate_evaluation_result,
)
from tests.evaluation_helpers import (
    evaluation_fixture,
    plugin_identity_mapping,
    synthetic_case,
)
from tests.hypothesis_helpers import canonical_json


@pytest.mark.parametrize(
    "error_type",
    [
        EvaluationDecodeError,
        EvaluationSchemaError,
        EvaluationInvariantError,
        EvaluationIntegrityError,
        EvaluationPersistenceError,
        EvaluationBoundaryError,
        EvaluationPluginError,
    ],
)
def test_public_errors_share_one_evaluation_error_base(
    error_type: type[Exception],
) -> None:
    assert issubclass(error_type, EvaluationError)


def test_reason_code_is_closed_ascii_and_hashable() -> None:
    reason = ReasonCode.parse("synthetic.evaluation_ok")

    assert reason == ReasonCode.parse("synthetic.evaluation_ok")
    assert hash(reason) == hash(ReasonCode.parse("synthetic.evaluation_ok"))
    for invalid in (
        "",
        "Uppercase",
        "contains space",
        "contains/path",
        "café",
        "x" * 129,
        "secret=value",
    ):
        with pytest.raises(EvaluationSchemaError):
            ReasonCode.parse(invalid)


def test_mapping_value_constructors_are_canonical_detached_and_hashable() -> None:
    artifact_mapping = {
        "sha256": "1" * 64,
        "relative_path": "artifacts/café.json",
        "kind": "q-arbor.synthetic.v1",
        "artifact_id": "artifact.cafe",
        "media_type": "application/json",
    }
    decomposed = copy.deepcopy(artifact_mapping)
    decomposed["relative_path"] = unicodedata.normalize(
        "NFD", decomposed["relative_path"]
    )
    artifact = ArtifactRef.from_mapping(decomposed)
    plugin = PluginIdentity.from_mapping(plugin_identity_mapping())
    check = CheckResult.from_mapping(
        {"evidence": "check.passed", "status": "pass", "name": "check.one"}
    )
    metric = MetricValue.from_mapping(
        {"unit": "ratio", "direction": "maximize", "value": -0.0, "name": "m"}
    )
    failure = EvaluationFailure.from_mapping(
        {
            "summary": "synthetic.failed",
            "failure_type": "evaluation_failure",
            "evidence_ids": [],
        }
    )
    family = FamilyEvidence.from_mapping(
        {
            "method": "exact-ast-v1",
            "family_hint": None,
            "evidence_sha256": "2" * 64,
        }
    )

    assert artifact.relative_path == artifact_mapping["relative_path"]
    assert artifact.sha256 == artifact_mapping["sha256"]
    assert artifact.canonical_sha256 == hashlib.sha256(
        artifact.to_json().encode()
    ).hexdigest()
    for value in (plugin, check, metric, failure, family):
        snapshot = value.to_dict()
        assert value.to_json() == canonical_json(snapshot)
        assert value.sha256 == hashlib.sha256(value.to_json().encode()).hexdigest()
        assert hash(value) == hash(value)
        snapshot[next(iter(snapshot))] = "caller mutation"
        assert value.to_json() != canonical_json(snapshot)


def test_result_round_trip_canonical_hash_and_frozen_c6_shape(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    path = tmp_path / "result.json"
    case.result.write(path)
    loaded = load_evaluation_result(
        path,
        binding=case.binding,
        expected_sha256=case.result.sha256,
    )

    assert loaded == case.result
    assert loaded.to_dict() == case.result.to_dict()
    assert loaded.to_json() == canonical_json(case.result.to_dict())
    assert canonical_evaluation_result_bytes(loaded) == loaded.to_json().encode("utf-8")
    assert compute_evaluation_result_hash(loaded) == loaded.sha256
    assert loaded.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert "result_hash" not in loaded.to_dict()


def test_result_freeze_normalizes_input_without_mutating_it(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    source = case.result.to_dict()
    source["warnings"] = ["warning.z", "warning.a"]
    source["checks"].append(
        {"name": "optional.z", "status": "pass", "evidence": "optional.z.ok"}
    )
    source["checks"].append(
        {"name": "optional.a", "status": "pass", "evidence": "optional.a.ok"}
    )
    original = copy.deepcopy(source)

    frozen = freeze_evaluation_result(source, binding=case.binding)

    assert source == original
    assert frozen.warnings == ("warning.a", "warning.z")
    required = list(case.runtime.lock.policy["required_check_names"])
    assert [item.name for item in frozen.checks] == [
        *required,
        "optional.a",
        "optional.z",
    ]


def test_validate_rejects_noncanonical_signed_array_order(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = case.result.to_dict()
    mapping["warnings"] = ["warning.z", "warning.a"]

    with pytest.raises(EvaluationInvariantError):
        validate_evaluation_result(mapping, binding=case.binding)


@pytest.mark.parametrize(
    "fixture_name",
    [
        "raw_duplicate_key.json",
        "raw_nested_duplicate_key.json",
        "raw_nonfinite.json",
        "raw_nfc_key_collision.json",
    ],
)
def test_raw_ambiguous_or_nonfinite_json_is_decode_error(
    tmp_path: Path, fixture_name: str
) -> None:
    case = synthetic_case(tmp_path / "case")

    with pytest.raises(EvaluationDecodeError):
        load_evaluation_result(
            evaluation_fixture(fixture_name),
            binding=case.binding,
        )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
@pytest.mark.parametrize(
    "location",
    ["primary", "diagnostic", "fold", "cost", "statistical"],
)
def test_mapping_nonfinite_values_are_typed_decode_errors(
    tmp_path: Path, value: float, location: str
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = case.result.to_dict()
    if location == "primary":
        mapping["primary_metric"]["value"] = value
    elif location == "diagnostic":
        mapping["diagnostics"][0]["value"] = value
    elif location == "fold":
        mapping["fold_metrics"][0]["metrics"][0]["value"] = value
    elif location == "cost":
        mapping["costs"]["gross"] = value
    else:
        mapping["statistical_diagnostics"] = [{"result": {"value": value}}]

    with pytest.raises(EvaluationDecodeError):
        freeze_evaluation_result(mapping, binding=case.binding)


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        (lambda value: value.pop("provenance"), EvaluationSchemaError),
        (lambda value: value.update(extra="forbidden"), EvaluationSchemaError),
        (lambda value: value.update(status="unknown"), EvaluationSchemaError),
        (
            lambda value: value["provenance"].update(seed=True),
            EvaluationSchemaError,
        ),
        (
            lambda value: value["costs"].update(turnover=False),
            EvaluationSchemaError,
        ),
    ],
)
def test_result_schema_failures_are_not_reclassified(
    tmp_path: Path,
    mutation: Any,
    expected_error: type[Exception],
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = case.result.to_dict()
    mutation(mapping)

    with pytest.raises(expected_error):
        freeze_evaluation_result(mapping, binding=case.binding)


def test_result_is_deeply_immutable_and_to_dict_is_detached(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    before = case.result.to_json()
    detached = case.result.to_dict()
    detached["provenance"]["seed"] = 19
    detached["fold_metrics"][0]["metrics"][0]["value"] = 999

    with pytest.raises(AttributeError):
        case.result.status = "contaminated"  # type: ignore[misc]
    with pytest.raises(TypeError):
        case.result.provenance["seed"] = 19  # type: ignore[index]
    with pytest.raises((AttributeError, TypeError)):
        case.result.fold_metrics[0]["metrics"].append({})  # type: ignore[union-attr]

    assert case.result.to_json() == before


def test_summary_is_one_closed_deterministic_redacted_projection(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    via_plugin = case.plugin.summarize(case.result)
    via_public_factory = EvaluationSummary.from_result(case.result)
    expected_keys = {
        "schema_version",
        "result_id",
        "request_id",
        "status",
        "split_role",
        "primary_metric",
        "constraints",
        "diagnostics",
        "fold_metrics",
        "costs",
        "checks",
        "failure_type",
        "failure_code",
        "warning_codes",
    }

    assert via_plugin == via_public_factory
    assert set(via_plugin.to_dict()) == expected_keys
    assert via_plugin.to_json() == canonical_json(via_plugin.to_dict())
    assert via_plugin.sha256 == EvaluationSummary.from_result(case.result).sha256
    text = via_plugin.to_json()
    for forbidden in (
        "relative_path",
        "artifact_id",
        "provenance",
        "sha256",
        "evidence",
        "time_range",
    ):
        assert forbidden not in text


def test_result_atomic_write_precommit_failure_preserves_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = synthetic_case(tmp_path / "case")
    target = tmp_path / "result.json"
    target.write_bytes(b"sentinel")

    def fail_replace(source: object, destination: object) -> None:
        raise OSError("replace fault")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(EvaluationPersistenceError) as caught:
        case.result.write(target)

    assert caught.value.committed is False
    assert target.read_bytes() == b"sentinel"
    assert list(tmp_path.glob(".result.json.*.tmp")) == []


def test_result_atomic_write_postcommit_fsync_reports_committed_new_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = synthetic_case(tmp_path / "case")
    target = tmp_path / "result.json"
    target.write_bytes(b"sentinel")
    real_fsync = os.fsync

    def fail_directory_fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory fsync fault")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(EvaluationPersistenceError) as caught:
        case.result.write(target)

    assert caught.value.committed is True
    assert target.read_bytes() == case.result.to_json().encode("utf-8")


def test_load_io_utf8_and_expected_hash_failures_are_distinct(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    missing = tmp_path / "missing.json"
    invalid_utf8 = tmp_path / "invalid.json"
    invalid_utf8.write_bytes(b"\xff\xfe")
    valid = tmp_path / "valid.json"
    case.result.write(valid)

    with pytest.raises(EvaluationPersistenceError):
        load_evaluation_result(missing, binding=case.binding)
    with pytest.raises(EvaluationDecodeError):
        load_evaluation_result(invalid_utf8, binding=case.binding)
    with pytest.raises(EvaluationIntegrityError):
        load_evaluation_result(
            valid,
            binding=case.binding,
            expected_sha256="f" * 64,
        )


def test_decode_error_does_not_echo_untrusted_content(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    canary = "TOKEN_CANARY_SHOULD_NOT_LEAK"
    path = tmp_path / "malformed.json"
    path.write_text('{"broken":"' + canary, encoding="utf-8")

    with pytest.raises(EvaluationDecodeError) as caught:
        load_evaluation_result(path, binding=case.binding)

    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)
