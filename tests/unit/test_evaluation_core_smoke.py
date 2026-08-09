from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from q_arbor.contracts import QuantResearchContract, freeze_contract
from q_arbor.evaluation import (
    ArtifactRef,
    CandidateArtifact,
    CandidateReceipt,
    ContentAddressedArtifactStore,
    EvaluationBinding,
    EvaluationBoundaryError,
    EvaluationDecodeError,
    EvaluationFailure,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationPersistenceError,
    EvaluationSchemaError,
    EvaluationSummary,
    MaterializationReceipt,
    MetricValue,
    PluginIdentity,
    ReasonCode,
    ValidatedCandidate,
    VerifiedRuntimeLock,
    freeze_candidate_validation,
    freeze_evaluation_request,
    freeze_evaluation_result,
    load_evaluation_result,
    make_access_denied_result,
    validate_evaluation_evidence,
)
from q_arbor.evaluation import runtime as evaluation_runtime
from q_arbor.evaluation.candidate import _classify_candidate_surface
from q_arbor.evaluation.codec import decode_json_bytes, normalize_mapping
from q_arbor.evaluation.results import _freeze_controlled_evaluation_result
from q_arbor.hypotheses import freeze_node
from tests.evaluation_helpers import synthetic_case
from tests.helpers import valid_contract_mapping
from tests.hypothesis_helpers import valid_node_mapping


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
    assert (
        artifact.canonical_sha256
        == hashlib.sha256(artifact.to_json().encode("utf-8")).hexdigest()
    )
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
    assert (
        MetricValue.from_mapping(
            {"name": "score", "value": 0, "direction": "maximize", "unit": "ratio"}
        ).value
        == 0
    )
    assert (
        EvaluationFailure.from_mapping(
            {
                "failure_type": "timeout",
                "summary": "evaluation.timeout",
                "evidence_ids": [],
            }
        ).summary
        == "evaluation.timeout"
    )
    assert ReasonCode.parse("evaluation.timeout") == "evaluation.timeout"

    with pytest.raises(EvaluationInvariantError):
        ArtifactRef.from_mapping(_artifact_mapping(relative_path="strategies/*.json"))
    with pytest.raises(EvaluationSchemaError):
        ReasonCode.parse("contains/slash")


def test_copying_an_immutable_value_returns_same_snapshot() -> None:
    artifact = ArtifactRef.from_mapping(_artifact_mapping())
    assert copy.copy(artifact) is artifact
    assert copy.deepcopy(artifact) is artifact


def _candidate_fixture(tmp_path: Path):
    contract = freeze_contract(valid_contract_mapping())
    plugin = PluginIdentity.from_mapping(contract.to_dict()["plugin"])
    candidate_path = tmp_path / "strategies" / "candidate.json"
    candidate_path.parent.mkdir(parents=True)
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


def _surface_candidate(
    root: Path,
    *,
    artifact_path: str,
    changed_paths: tuple[str, ...],
    materialized_paths: tuple[str, ...],
) -> tuple[QuantResearchContract, CandidateArtifact]:
    contract = freeze_contract(valid_contract_mapping())
    payload = b'{"candidate":"surface"}'
    for path in materialized_paths:
        destination = root.joinpath(*path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload if path == artifact_path else b"{}")
    materialization = MaterializationReceipt.scan(root, materialized_paths)
    artifact = ArtifactRef.from_mapping(
        {
            "artifact_id": "candidate.surface",
            "kind": "python_strategy",
            "relative_path": artifact_path,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    )
    candidate = CandidateArtifact.from_bytes(
        artifact,
        payload,
        code_commit="1" * 40,
        changed_paths=changed_paths,
        materialization=materialization,
    )
    return contract, candidate


@pytest.mark.parametrize(
    ("artifact_path", "changed_paths", "materialized_paths", "expected"),
    [
        (
            "strategies/candidate.json",
            ("evaluator/config.json", "strategies/candidate.json"),
            ("evaluator/config.json", "strategies/candidate.json"),
            "candidate.surface.protected",
        ),
        (
            "strategies/candidate.json",
            ("reports/result.json", "strategies/candidate.json"),
            ("reports/result.json", "strategies/candidate.json"),
            "candidate.surface.outside_editable",
        ),
        (
            "strategies/other.json",
            ("strategies/other.json",),
            ("strategies/other.json",),
            "candidate.surface.missing_output",
        ),
    ],
)
def test_candidate_surface_classifier_returns_bounded_reason_codes(
    tmp_path: Path,
    artifact_path: str,
    changed_paths: tuple[str, ...],
    materialized_paths: tuple[str, ...],
    expected: str,
) -> None:
    contract, candidate = _surface_candidate(
        tmp_path,
        artifact_path=artifact_path,
        changed_paths=changed_paths,
        materialized_paths=materialized_paths,
    )

    assert _classify_candidate_surface(candidate, contract) == expected


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
                f"diagnostic.{hashlib.sha256(b'turnover').hexdigest()[:16]}.observed",
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
    preplanted = b"preplanted"
    preplanted_digest = hashlib.sha256(preplanted).hexdigest()
    preplanted_identity = hashlib.sha256(
        json.dumps(
            {
                "kind": "q-arbor.aggregate-metrics.v1",
                "media_type": "application/json",
                "sha256": preplanted_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    request_digest = hashlib.sha256(b"request.one").hexdigest()
    preplanted_path = (
        store_root / "artifacts" / "evaluations" / request_digest / preplanted_identity
    )
    preplanted_path.write_bytes(preplanted)
    with pytest.raises(EvaluationBoundaryError):
        sink.put(
            kind="q-arbor.aggregate-metrics.v1",
            media_type="application/json",
            content=preplanted,
        )

    artifact = sink.put(
        kind="q-arbor.aggregate-metrics.v1",
        media_type="application/json",
        content=b"{}",
    )

    store.verify_issued(
        artifact,
        request_id="request.one",
        runtime_lock=runtime_lock,
    )
    assert sink.issued_refs == (artifact,)


def test_artifact_retry_requires_same_sink_pending_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding, _ = _binding_fixture(tmp_path)
    store = binding.artifact_resolver
    sink = store.scope(
        request_id=binding.request.request_id,
        produced_by_event_id="event.retry",
        runtime_lock=binding.runtime_lock,
    )
    content = b'{"retry":true}'
    original_fsync = evaluation_runtime.os.fsync
    failed = False

    def fail_first_directory_sync(fd: int) -> None:
        nonlocal failed
        if not failed and stat.S_ISDIR(os.fstat(fd).st_mode):
            failed = True
            raise OSError("injected directory fsync failure")
        original_fsync(fd)

    monkeypatch.setattr(evaluation_runtime.os, "fsync", fail_first_directory_sync)
    with pytest.raises(EvaluationPersistenceError) as fault:
        sink.put(
            kind="q-arbor.aggregate-metrics.v1",
            media_type="application/json",
            content=content,
        )
    assert fault.value.committed is True
    monkeypatch.setattr(evaluation_runtime.os, "fsync", original_fsync)

    unrelated_sink = store.scope(
        request_id=binding.request.request_id,
        produced_by_event_id="event.retry",
        runtime_lock=binding.runtime_lock,
    )
    with pytest.raises(EvaluationBoundaryError):
        unrelated_sink.put(
            kind="q-arbor.aggregate-metrics.v1",
            media_type="application/json",
            content=content,
        )

    recovered = sink.put(
        kind="q-arbor.aggregate-metrics.v1",
        media_type="application/json",
        content=content,
    )
    store.verify_issued(
        recovered,
        request_id=binding.request.request_id,
        runtime_lock=binding.runtime_lock,
    )


def _binding_fixture(tmp_path: Path):
    contract, plugin, candidate, receipt = _candidate_fixture(tmp_path / "candidate")
    split = contract.to_dict()["data"]["splits"]["development"]
    request = freeze_evaluation_request(
        {
            "request_id": "request.result",
            "run_id": "run.one",
            "node_id": "node.one",
            "attempt_id": "attempt.one",
            "idempotency_key": "request.result",
            "contract_hash": contract.sha256,
            "candidate": candidate.artifact.to_dict(),
            "candidate_hash": candidate.candidate_hash,
            "validation_receipt": receipt.receipt_ref.to_dict(),
            "plugin": plugin.to_dict(),
            "split_role": "development",
            "split_manifest_hash": split["manifest_sha256"],
            "capability_grant_id": "grant.one",
            "requested_metrics": ["net_sharpe", "turnover"],
            "created_event_id": "event.one",
        },
        contract=contract,
        candidate_receipt=receipt,
    )
    store_root = tmp_path / "store"
    runtime_dir = store_root / "runtime"
    runtime_dir.mkdir(parents=True)
    evaluator_bytes = b"result evaluator"
    diagnostic_check = (
        f"diagnostic.{hashlib.sha256(b'turnover').hexdigest()[:16]}.observed"
    )
    config = {
        "schema_version": "1.0",
        "plugin_config": {},
        "policy": {
            "required_check_names": [
                "candidate.identity",
                "cost.reconciled",
                diagnostic_check,
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
    config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
    (runtime_dir / "evaluator.bin").write_bytes(evaluator_bytes)
    (runtime_dir / "config.json").write_bytes(config_bytes)
    store = ContentAddressedArtifactStore.create(store_root)
    runtime_lock = VerifiedRuntimeLock.from_artifacts(
        ArtifactRef.from_mapping(
            {
                "artifact_id": "runtime.evaluator.result",
                "kind": "q-arbor.evaluator.v1",
                "relative_path": "runtime/evaluator.bin",
                "sha256": hashlib.sha256(evaluator_bytes).hexdigest(),
            }
        ),
        ArtifactRef.from_mapping(
            {
                "artifact_id": "runtime.config.result",
                "kind": "q-arbor.evaluator-config.v1",
                "relative_path": "runtime/config.json",
                "sha256": hashlib.sha256(config_bytes).hexdigest(),
            }
        ),
        resolver=store,
    )
    binding = EvaluationBinding.create(
        request,
        contract,
        receipt,
        plugin,
        runtime_lock,
        result_id="result.one",
        seed=7,
        artifact_resolver=store,
    )
    return binding, diagnostic_check


def _issued_fixture(tmp_path: Path):
    binding, _ = _binding_fixture(tmp_path)
    store = binding.artifact_resolver
    sink = store.scope(
        request_id=binding.request.request_id,
        produced_by_event_id="event.issued.fixture",
        runtime_lock=binding.runtime_lock,
    )
    content = b'{"aggregate":1}'
    artifact = sink.put(
        kind="q-arbor.aggregate-metrics.v1",
        media_type="application/json",
        content=content,
    )
    request_digest = hashlib.sha256(binding.request.request_id.encode()).hexdigest()
    scope_directory = tmp_path / "store" / "artifacts" / "evaluations" / request_digest
    record_name = hashlib.sha256(artifact.artifact_id.encode()).hexdigest() + ".json"
    return (
        binding,
        store,
        sink,
        artifact,
        content,
        scope_directory,
        scope_directory / ".issued" / record_name,
    )


@pytest.mark.parametrize(
    "tamper",
    ["schema", "config", "allowed", "extra", "missing", "noncanonical"],
)
def test_verify_issued_rejects_untrusted_scope_sidecars(
    tmp_path: Path,
    tamper: str,
) -> None:
    binding, store, _sink, artifact, _content, scope_directory, _record = (
        _issued_fixture(tmp_path)
    )
    scope_path = scope_directory / ".scope.json"
    scope = json.loads(scope_path.read_bytes())
    if tamper == "schema":
        scope["schema_version"] = "2.0"
    elif tamper == "config":
        scope["config_sha256"] = "f" * 64
    elif tamper == "allowed":
        scope["allowed_artifacts"].append(
            {"kind": "q-arbor.forged.v1", "media_type": "application/json"}
        )
    elif tamper == "extra":
        scope["unexpected"] = True
    elif tamper == "missing":
        del scope["config_sha256"]
    if tamper == "noncanonical":
        encoded = json.dumps(scope, indent=2).encode()
    else:
        encoded = json.dumps(scope, sort_keys=True, separators=(",", ":")).encode()
    scope_path.write_bytes(encoded)

    with pytest.raises(EvaluationIntegrityError):
        store.verify_issued(
            artifact,
            request_id=binding.request.request_id,
            runtime_lock=binding.runtime_lock,
        )


def test_verify_issued_requires_canonical_issuance_bytes(tmp_path: Path) -> None:
    binding, store, _sink, artifact, _content, _scope, record_path = _issued_fixture(
        tmp_path
    )
    record_path.write_text(json.dumps(artifact.to_dict(), indent=2), encoding="utf-8")

    with pytest.raises(EvaluationIntegrityError):
        store.verify_issued(
            artifact,
            request_id=binding.request.request_id,
            runtime_lock=binding.runtime_lock,
        )


@pytest.mark.parametrize("tamper", ["artifact_id", "relative_path"])
def test_verify_issued_recomputes_content_addressed_identity(
    tmp_path: Path,
    tamper: str,
) -> None:
    binding, store, _sink, artifact, content, scope_directory, record_path = (
        _issued_fixture(tmp_path)
    )
    forged = artifact.to_dict()
    if tamper == "artifact_id":
        forged["artifact_id"] = "artifact.forged"
        record_path = (
            scope_directory
            / ".issued"
            / (hashlib.sha256(b"artifact.forged").hexdigest() + ".json")
        )
    else:
        forged["relative_path"] = (
            f"artifacts/evaluations/{scope_directory.name}/alternate"
        )
        (scope_directory / "alternate").write_bytes(content)
    forged_ref = ArtifactRef.from_mapping(forged)
    record_path.write_bytes(
        json.dumps(forged_ref.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    )

    with pytest.raises(EvaluationIntegrityError):
        store.verify_issued(
            forged_ref,
            request_id=binding.request.request_id,
            runtime_lock=binding.runtime_lock,
        )


def test_pending_issuance_recovery_revalidates_raw_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding, _ = _binding_fixture(tmp_path)
    store = binding.artifact_resolver
    sink = store.scope(
        request_id=binding.request.request_id,
        produced_by_event_id="event.pending.record",
        runtime_lock=binding.runtime_lock,
    )
    content = b'{"pending":true}'
    original_fsync = evaluation_runtime.os.fsync
    directory_syncs = 0

    def fail_issuance_record_sync(fd: int) -> None:
        nonlocal directory_syncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_syncs += 1
            if directory_syncs == 2:
                raise OSError("injected issuance-record directory sync failure")
        original_fsync(fd)

    monkeypatch.setattr(
        evaluation_runtime.os,
        "fsync",
        fail_issuance_record_sync,
    )
    with pytest.raises(EvaluationPersistenceError) as fault:
        sink.put(
            kind="q-arbor.aggregate-metrics.v1",
            media_type="application/json",
            content=content,
        )
    assert fault.value.committed is True
    monkeypatch.setattr(evaluation_runtime.os, "fsync", original_fsync)

    content_sha256 = hashlib.sha256(content).hexdigest()
    identity_digest = hashlib.sha256(
        json.dumps(
            {
                "kind": "q-arbor.aggregate-metrics.v1",
                "media_type": "application/json",
                "sha256": content_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    artifact_id = f"artifact.{identity_digest}"
    request_digest = hashlib.sha256(binding.request.request_id.encode()).hexdigest()
    record_path = (
        tmp_path
        / "store"
        / "artifacts"
        / "evaluations"
        / request_digest
        / ".issued"
        / (hashlib.sha256(artifact_id.encode()).hexdigest() + ".json")
    )
    record_path.write_text(
        json.dumps(json.loads(record_path.read_bytes()), indent=2),
        encoding="utf-8",
    )

    with pytest.raises(EvaluationIntegrityError):
        sink.put(
            kind="q-arbor.aggregate-metrics.v1",
            media_type="application/json",
            content=content,
        )


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "mkfifo"),
    reason="FIFO boundary is a POSIX contract",
)
@pytest.mark.parametrize(
    "probe",
    ["candidate", "artifact", "sidecar", "exists", "immutable", "recovery"],
)
def test_fifo_reads_fail_before_blocking(tmp_path: Path, probe: str) -> None:
    root = tmp_path / probe
    source_root = Path(__file__).resolve().parents[2] / "src"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        filter(None, (str(source_root), environment.get("PYTHONPATH", "")))
    )
    script = r"""
import os
import sys
from pathlib import Path

from q_arbor.evaluation import (
    ArtifactRef,
    ContentAddressedArtifactStore,
    EvaluationBoundaryError,
    MaterializationReceipt,
)
from q_arbor.evaluation.runtime import (
    _create_exclusive_file_at,
    _create_or_verify_immutable_file_at,
    _read_json_object_at,
    _record_exists_at,
)

root = Path(sys.argv[1])
probe = sys.argv[2]
root.mkdir()
try:
    if probe == "candidate":
        os.mkfifo(root / "pipe")
        MaterializationReceipt.scan(root, ["pipe"])
    elif probe == "artifact":
        store = ContentAddressedArtifactStore.create(root / "store")
        os.mkfifo(root / "store" / "pipe")
        ref = ArtifactRef.from_mapping(
            {
                "artifact_id": "artifact.pipe",
                "kind": "q-arbor.probe.v1",
                "relative_path": "pipe",
                "sha256": "0" * 64,
            }
        )
        store.read_bytes(ref)
    else:
        os.mkfifo(root / "pipe")
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            if probe == "sidecar":
                _read_json_object_at(directory_fd, "pipe")
            elif probe == "exists":
                _record_exists_at(directory_fd, "pipe")
            elif probe == "immutable":
                _create_or_verify_immutable_file_at(directory_fd, "pipe", b"{}")
            elif probe == "recovery":
                _create_exclusive_file_at(
                    directory_fd,
                    "pipe",
                    b"payload",
                    recover_existing=True,
                )
            else:
                raise AssertionError(probe)
        finally:
            os.close(directory_fd)
except EvaluationBoundaryError:
    raise SystemExit(0)
raise SystemExit("FIFO was accepted")
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(root), probe],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
        timeout=5,
    )
    assert completed.returncode == 0, completed.stderr


def _success_result_mapping(binding, diagnostic_check: str) -> dict[str, object]:
    candidate = binding.candidate_receipt.candidate
    contract = binding.contract.to_dict()
    return {
        "result_id": binding.result_id,
        "request_id": binding.request.request_id,
        "status": "success",
        "split_role": "development",
        "primary_metric": {
            "name": "net_sharpe",
            "value": 0,
            "direction": "maximize",
            "unit": "ratio",
        },
        "constraints": [
            {
                "name": "max_drawdown",
                "status": "pass",
                "evidence": "constraint.ok",
            }
        ],
        "diagnostics": [
            {
                "name": "turnover",
                "value": 0.75,
                "direction": "minimize",
                "unit": "fraction_per_day",
            }
        ],
        "fold_metrics": [
            {
                "fold_id": fold_id,
                "time_range": f"{fold_id}.range",
                "metrics": [
                    {
                        "name": "net_sharpe",
                        "value": 0,
                        "direction": "maximize",
                        "unit": "ratio",
                    },
                    {
                        "name": "turnover",
                        "value": 0.75,
                        "direction": "minimize",
                        "unit": "fraction_per_day",
                    },
                ],
            }
            for fold_id in ("fold.a", "fold.b")
        ],
        "costs": {
            "gross": 0.9,
            "transaction_cost": 0.1,
            "net": 0.8,
            "turnover": 0.75,
            "cost_model_sha256": contract["cost_model"]["sha256"],
        },
        "checks": [
            {"name": name, "status": "pass", "evidence": "evaluation.check.ok"}
            for name in binding.runtime_lock.required_check_names
        ],
        "artifacts": [],
        "provenance": {
            "candidate_sha256": candidate.candidate_hash,
            "code_commit": candidate.code_commit,
            "data_snapshot_sha256": contract["data"]["snapshot_sha256"],
            "split_manifest_hash": binding.request.split_manifest_hash,
            "contract_hash": binding.contract.sha256,
            "plugin_code_sha256": binding.plugin_identity.code_sha256,
            "evaluator_sha256": binding.runtime_lock.evaluator_sha256,
            "config_sha256": binding.runtime_lock.config_sha256,
            "seed": binding.seed,
        },
        "failure": None,
        "statistical_diagnostics": [],
        "warnings": ["warning.z", "warning.a"],
    }


def test_result_round_trip_summary_and_hash_binding(tmp_path: Path) -> None:
    binding, diagnostic_check = _binding_fixture(tmp_path)
    mapping = _success_result_mapping(binding, diagnostic_check)
    result = freeze_evaluation_result(mapping, binding=binding)

    assert result.primary_metric.value == 0
    assert tuple(result.warnings) == ("warning.a", "warning.z")
    assert result.checks[2].name == diagnostic_check
    summary = EvaluationSummary.from_result(result)
    assert "provenance" not in summary.to_dict()
    assert "artifacts" not in summary.to_dict()
    assert "time_range" not in summary.to_dict()["fold_metrics"][0]

    destination = tmp_path / "result.json"
    result.write(destination)
    loaded = load_evaluation_result(
        destination,
        binding=binding,
        expected_sha256=result.sha256,
    )
    assert loaded == result

    tampered = result.to_dict()
    tampered["provenance"]["seed"] = 19
    with pytest.raises(EvaluationIntegrityError):
        freeze_evaluation_result(tampered, binding=binding)


def test_evidence_binding_rejects_a_different_candidate_request(
    tmp_path: Path,
) -> None:
    result_case = synthetic_case(
        tmp_path / "result",
        signal_column="planted_signal",
    )
    request_case = synthetic_case(
        tmp_path / "request",
        signal_column="null_signal",
        request_id=result_case.request.request_id,
    )
    assert result_case.result.provenance["candidate_sha256"] != (
        request_case.request.candidate_hash
    )

    node_mapping = valid_node_mapping()
    node_mapping.update(
        id=result_case.request.node_id,
        status="running",
        lifecycle="running",
        admissibility="unevaluated",
        score=None,
        candidate_id=None,
        candidate_artifact=None,
        attempt_ids=[result_case.request.attempt_id],
        evidence_refs=[],
        insights=[],
    )
    node_mapping["scope"]["data_snapshot_sha256"] = result_case.result.provenance[
        "data_snapshot_sha256"
    ]
    node_mapping["scope"]["cost_model_sha256"] = result_case.result.costs[
        "cost_model_sha256"
    ]
    node = freeze_node(node_mapping)
    evidence = {
        "evidence_id": "evidence.cross_candidate",
        "attempt_id": result_case.request.attempt_id,
        "result_id": result_case.result.result_id,
        "split_role": result_case.result.split_role,
        "level": "observed",
        "claim": "The result supports only its exact candidate request.",
        "conditions": [],
        "status": "valid",
        "artifact_refs": [item.to_dict() for item in result_case.result.artifacts],
    }
    result_before = result_case.result.to_json()
    request_before = request_case.request.to_json()
    node_before = node.to_json()

    with pytest.raises(EvaluationIntegrityError, match="result provenance"):
        validate_evaluation_evidence(
            result_case.result,
            request=request_case.request,
            node=node,
            evidence=evidence,
        )

    assert result_case.result.to_json() == result_before
    assert request_case.request.to_json() == request_before
    assert node.to_json() == node_before


def test_access_denied_factory_is_exact_null_projection(tmp_path: Path) -> None:
    binding, _ = _binding_fixture(tmp_path)
    denied = make_access_denied_result(
        binding=binding,
        reason_code="authorization.denied",
    )

    assert denied.status == "access_denied"
    assert denied.primary_metric.value is None
    assert denied.failure is not None
    assert denied.failure.failure_type == "access_denied"
    assert denied.fold_metrics == ()
    assert denied.artifacts == ()

    smuggled = denied.to_dict()
    smuggled["checks"][0] = {
        "name": smuggled["checks"][0]["name"],
        "status": "pass",
        "evidence": "evaluation.check.ok",
    }
    with pytest.raises(EvaluationInvariantError):
        freeze_evaluation_result(smuggled, binding=binding)


def test_controlled_runtime_drift_accepts_only_exact_null_template(
    tmp_path: Path,
) -> None:
    binding, _ = _binding_fixture(tmp_path)
    payload = make_access_denied_result(
        binding=binding,
        reason_code="authorization.denied",
    ).to_dict()
    payload["status"] = "contaminated"
    payload["failure"] = {
        "failure_type": "contamination",
        "summary": "runtime.contamination",
        "evidence_ids": [],
    }

    result = _freeze_controlled_evaluation_result(payload, binding=binding)
    assert result.status == "contaminated"

    smuggled = copy.deepcopy(payload)
    smuggled["diagnostics"][0]["value"] = 1
    with pytest.raises(EvaluationInvariantError):
        _freeze_controlled_evaluation_result(smuggled, binding=binding)

    (tmp_path / "store" / "runtime" / "evaluator.bin").write_bytes(b"drifted")
    destination = tmp_path / "controlled-contamination.json"
    result.write(destination)
    assert destination.read_text(encoding="utf-8") == result.to_json()


def test_result_write_reverifies_runtime_before_touching_target(
    tmp_path: Path,
) -> None:
    binding, diagnostic_check = _binding_fixture(tmp_path)
    result = freeze_evaluation_result(
        _success_result_mapping(binding, diagnostic_check),
        binding=binding,
    )
    (tmp_path / "store" / "runtime" / "evaluator.bin").write_bytes(b"drifted")

    destination = tmp_path / "must-not-exist.json"
    with pytest.raises(EvaluationIntegrityError):
        result.write(destination)
    assert not destination.exists()
