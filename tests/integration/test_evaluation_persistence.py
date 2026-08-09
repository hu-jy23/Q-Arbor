from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest
from q_arbor.evaluation import (
    ArtifactRef,
    CheckResult,
    EvaluationFailure,
    EvaluationPersistenceError,
    EvaluationSummary,
    FamilyEvidence,
    FoldPolicy,
    MetricValue,
    PluginIdentity,
)

from tests.evaluation_helpers import (
    plugin_identity_mapping,
    synthetic_case,
)


def _json_backed_values(tmp_path: Path) -> tuple[Any, ...]:
    case = synthetic_case(tmp_path / "case")
    return (
        ArtifactRef.from_mapping(
            {
                "artifact_id": "artifact.persistence",
                "kind": "q-arbor.test.v1",
                "relative_path": "artifacts/test.json",
                "sha256": "a" * 64,
                "media_type": "application/json",
            }
        ),
        PluginIdentity.from_mapping(plugin_identity_mapping()),
        CheckResult.from_mapping(
            {"name": "check.persistence", "status": "pass", "evidence": "check.ok"}
        ),
        MetricValue.from_mapping(
            {
                "name": "metric.persistence",
                "value": 0,
                "direction": "maximize",
                "unit": "ratio",
            }
        ),
        EvaluationFailure.from_mapping(
            {
                "failure_type": "evaluation_failure",
                "summary": "evaluation.persistence",
                "evidence_ids": [],
            }
        ),
        FamilyEvidence.from_mapping(
            {
                "family_hint": None,
                "method": "exact-ast-v1",
                "evidence_sha256": "b" * 64,
            }
        ),
        case.candidate.materialization,
        FoldPolicy.from_mapping(case.runtime.lock.policy["fold_policy"]),
        case.runtime.lock,
        case.receipt.validation,
        case.request,
        case.result,
        EvaluationSummary.from_result(case.result),
    )


def test_every_json_backed_public_value_writes_exact_canonical_bytes(
    tmp_path: Path,
) -> None:
    for index, value in enumerate(_json_backed_values(tmp_path)):
        path = tmp_path / f"value-{index}.json"
        value.write(path)
        assert path.read_bytes() == value.to_json().encode("utf-8")


@pytest.mark.parametrize("target_exists", [False, True])
def test_precommit_replace_failure_preserves_absent_or_existing_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_exists: bool,
) -> None:
    case = synthetic_case(tmp_path / "case")
    target = tmp_path / "result.json"
    if target_exists:
        target.write_bytes(b"sentinel")

    def fail_replace(source: object, destination: object) -> None:
        del source, destination
        raise OSError("replace fault")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(EvaluationPersistenceError) as caught:
        case.result.write(target)

    assert caught.value.committed is False
    if target_exists:
        assert target.read_bytes() == b"sentinel"
    else:
        assert not target.exists()
    assert list(tmp_path.glob(".result.json.*.tmp")) == []


def test_precommit_file_fsync_failure_is_uncommitted_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = synthetic_case(tmp_path / "case")
    target = tmp_path / "result.json"
    target.write_bytes(b"sentinel")

    def fail_fsync(fd: int) -> None:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("file fsync fault")

    monkeypatch.setattr(os, "fsync", fail_fsync)
    with pytest.raises(EvaluationPersistenceError) as caught:
        case.result.write(target)

    assert caught.value.committed is False
    assert target.read_bytes() == b"sentinel"
    assert list(tmp_path.glob(".result.json.*.tmp")) == []


def test_postcommit_directory_fsync_failure_has_complete_new_file(
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


def test_cleanup_failure_never_masks_primary_uncommitted_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = synthetic_case(tmp_path / "case")
    target = tmp_path / "result.json"

    def fail_replace(source: object, destination: object) -> None:
        del source, destination
        raise OSError("PRIMARY_REPLACE_FAULT")

    def fail_unlink(path: object) -> None:
        del path
        raise OSError("SECONDARY_CLEANUP_FAULT")

    monkeypatch.setattr(os, "replace", fail_replace)
    monkeypatch.setattr(os, "unlink", fail_unlink)
    with pytest.raises(EvaluationPersistenceError) as caught:
        case.result.write(target)

    assert caught.value.committed is False
    assert "SECONDARY_CLEANUP_FAULT" not in str(caught.value)
    assert not target.exists()


def test_write_open_failure_is_typed_uncommitted_and_creates_no_target(
    tmp_path: Path,
) -> None:
    case = synthetic_case(tmp_path / "case")
    non_directory = tmp_path / "not-a-directory"
    non_directory.write_bytes(b"sentinel")
    target = non_directory / "result.json"

    with pytest.raises(EvaluationPersistenceError) as caught:
        case.result.write(target)

    assert caught.value.committed is False
    assert non_directory.read_bytes() == b"sentinel"


def test_runtime_value_write_is_atomic_under_same_fault_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = synthetic_case(tmp_path / "case")
    target = tmp_path / "runtime-lock.json"
    target.write_bytes(b"sentinel")

    def fail_replace(source: object, destination: object) -> None:
        del source, destination
        raise OSError("replace fault")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(EvaluationPersistenceError) as caught:
        case.runtime.lock.write(target)

    assert caught.value.committed is False
    assert target.read_bytes() == b"sentinel"
