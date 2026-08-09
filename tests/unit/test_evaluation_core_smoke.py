from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from q_arbor.contracts import freeze_contract
from q_arbor.evaluation import (
    ArtifactRef,
    CandidateArtifact,
    CandidateReceipt,
    ContentAddressedArtifactStore,
    EvaluationBoundaryError,
    EvaluationDecodeError,
    EvaluationFailure,
    EvaluationInvariantError,
    MaterializationReceipt,
    MetricValue,
    PluginIdentity,
    ReasonCode,
    ValidatedCandidate,
    VerifiedRuntimeLock,
    freeze_candidate_validation,
    freeze_evaluation_request,
)
from q_arbor.evaluation.codec import decode_json_bytes, normalize_mapping
from tests.helpers import valid_contract_mapping


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
    assert artifact.sha256 == "a" * 64
    assert artifact.canonical_sha256 == hashlib.sha256(
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


def _candidate_fixture(tmp_path: Path):
    contract = freeze_contract(valid_contract_mapping())
    plugin = PluginIdentity.from_mapping(contract.to_dict()["plugin"])
    candidate_path = tmp_path / "strategies" / "candidate.json"
    candidate_path.parent.mkdir()
    payload = b'{"candidate":"one"}'
    candidate_path.write_bytes(payload)
    artifact = ArtifactRef.from_mapping(
        {
            "artifact_id": "candidate.one",
            "kind": "python_strategy",
            "relative_path": "strategies/candidate.json",
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    )
    materialization = MaterializationReceipt.scan(
        tmp_path, ["strategies/candidate.json"]
    )
    candidate = CandidateArtifact.from_bytes(
        artifact,
        payload,
        code_commit="1" * 40,
        changed_paths=["strategies/candidate.json"],
        materialization=materialization,
    )
    validation = freeze_candidate_validation(
        {
            "schema_version": "1.0",
            "status": "valid",
            "contract_hash": contract.sha256,
            "plugin": plugin.to_dict(),
            "candidate": artifact.to_dict(),
            "candidate_hash": candidate.candidate_hash,
            "canonical_form_sha256": "c" * 64,
            "family_evidence": {
                "family_hint": None,
                "method": "exact-ast-v1",
                "evidence_sha256": "d" * 64,
            },
            "changed_paths": list(candidate.changed_paths),
            "checks": [
                {
                    "name": "candidate.syntax",
                    "status": "pass",
                    "evidence": "candidate.syntax.ok",
                }
            ],
            "failure": None,
        },
        candidate=candidate,
        contract=contract,
        plugin_identity=plugin,
    )
    receipt_ref = ArtifactRef.from_mapping(
        {
            "artifact_id": "validation.one",
            "kind": "q-arbor.validation-receipt.v1",
            "relative_path": "artifacts/validations/validation.one.json",
            "sha256": validation.sha256,
        }
    )
    receipt = ValidatedCandidate.bind(
        candidate,
        validation,
        receipt_ref,
        contract=contract,
        plugin_identity=plugin,
    )
    return contract, plugin, candidate, receipt


def test_materialization_candidate_validation_and_request_round_trip(
    tmp_path: Path,
) -> None:
    contract, plugin, candidate, receipt = _candidate_fixture(tmp_path)
    split = contract.to_dict()["data"]["splits"]["development"]
    request = freeze_evaluation_request(
        {
            "request_id": "request.one",
            "run_id": "run.one",
            "node_id": "node.one",
            "attempt_id": "attempt.one",
            "idempotency_key": "request.one",
            "contract_hash": contract.sha256,
            "candidate": candidate.artifact.to_dict(),
            "candidate_hash": candidate.candidate_hash,
            "validation_receipt": receipt.receipt_ref.to_dict(),
            "plugin": plugin.to_dict(),
            "split_role": "development",
            "split_manifest_hash": split["manifest_sha256"],
            "capability_grant_id": "grant.one",
            "requested_metrics": ["turnover", "net_sharpe"],
            "created_event_id": "event.one",
        },
        contract=contract,
        candidate_receipt=receipt,
    )

    assert request.requested_metrics == ("net_sharpe", "turnover")
    assert request.candidate.sha256 == candidate.artifact.sha256
    assert isinstance(receipt, CandidateReceipt)


def test_materialization_rejects_symlinks_and_hardlinks(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"secret")
    symlink = tmp_path / "link"
    symlink.symlink_to(target)
    with pytest.raises(Exception) as symlink_error:
        MaterializationReceipt.scan(tmp_path, ["link"])
    assert type(symlink_error.value).__name__ == "EvaluationBoundaryError"

    hardlink = tmp_path / "hardlink"
    os.link(target, hardlink)
    with pytest.raises(Exception) as hardlink_error:
        MaterializationReceipt.scan(tmp_path, ["target"])
    assert type(hardlink_error.value).__name__ == "EvaluationBoundaryError"


def test_runtime_lock_and_store_bind_issued_artifacts(tmp_path: Path) -> None:
    store_root = tmp_path / "store"
    runtime_dir = store_root / "runtime"
    runtime_dir.mkdir(parents=True)
    evaluator_bytes = b"fixed evaluator"
    config_mapping = {
        "schema_version": "1.0",
        "plugin_config": {},
        "policy": {
            "required_check_names": [
                "candidate.identity",
                "cost.reconciled",
                "split.identity",
            ],
            "fold_policy": {
                "mode": "required",
                "expected_fold_ids": ["fold.a", "fold.b"],
                "required_metric_names": ["net_sharpe", "turnover"],
            },
            "allowed_artifacts": [
                {
                    "kind": "q-arbor.aggregate-metrics.v1",
                    "media_type": "application/json",
                }
            ],
        },
    }
    config_bytes = json.dumps(
        config_mapping, sort_keys=True, separators=(",", ":")
    ).encode()
    (runtime_dir / "evaluator.bin").write_bytes(evaluator_bytes)
    (runtime_dir / "config.json").write_bytes(config_bytes)
    store = ContentAddressedArtifactStore.create(store_root)
    evaluator_ref = ArtifactRef.from_mapping(
        {
            "artifact_id": "runtime.evaluator",
            "kind": "q-arbor.evaluator.v1",
            "relative_path": "runtime/evaluator.bin",
            "sha256": hashlib.sha256(evaluator_bytes).hexdigest(),
        }
    )
    config_ref = ArtifactRef.from_mapping(
        {
            "artifact_id": "runtime.config",
            "kind": "q-arbor.evaluator-config.v1",
            "relative_path": "runtime/config.json",
            "sha256": hashlib.sha256(config_bytes).hexdigest(),
        }
    )
    runtime_lock = VerifiedRuntimeLock.from_artifacts(
        evaluator_ref,
        config_ref,
        resolver=store,
    )

    outside = tmp_path / "outside"
    outside.mkdir()
    (store_root / "artifacts").symlink_to(outside, target_is_directory=True)
    with pytest.raises(EvaluationBoundaryError):
        store.scope(
            request_id="request.one",
            produced_by_event_id="event.one",
            runtime_lock=runtime_lock,
        )
    assert list(outside.iterdir()) == []
    (store_root / "artifacts").unlink()

    sink = store.scope(
        request_id="request.one",
        produced_by_event_id="event.one",
        runtime_lock=runtime_lock,
    )
    artifact = sink.put(
        kind="q-arbor.aggregate-metrics.v1",
        media_type="application/json",
        content=b"{}",
    )

    store.verify_issued(
        artifact,
        request_id="request.one",
        runtime_lock_sha256=runtime_lock.sha256,
    )
    assert sink.issued_refs == (artifact,)
