from __future__ import annotations

import copy
import hashlib
import inspect
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from q_arbor import evaluation
from q_arbor.evaluation import (
    ArtifactRef,
    CandidateArtifact,
    CandidateReceipt,
    ContentAddressedArtifactStore,
    EvaluationBoundaryError,
    EvaluationDecodeError,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationSchemaError,
    EvaluationSummary,
    FoldPolicy,
    MaterializationReceipt,
    QuantTaskPlugin,
    ValidatedCandidate,
    VerifiedRuntimeLock,
    freeze_evaluation_request,
    load_candidate_validation,
    load_evaluation_request,
    validate_candidate_validation,
    validate_evaluation_request,
)
from q_arbor.plugins.formula_alpha import FormulaMockOutcome
from q_arbor.plugins.synthetic import SyntheticSignalPlugin
from tests.evaluation_helpers import (
    artifact_ref_mapping,
    formula_case,
    hm1_case,
    invalid_synthetic_case,
    make_request,
    plugin_identity_mapping,
    runtime_fixture,
    synthetic_case,
    synthetic_contract,
    validated_synthetic_components,
)
from tests.hypothesis_helpers import canonical_json


def test_evaluation_package_all_is_the_exact_frozen_public_surface() -> None:
    expected = {
        "EvaluationError",
        "EvaluationDecodeError",
        "EvaluationSchemaError",
        "EvaluationInvariantError",
        "EvaluationIntegrityError",
        "EvaluationPersistenceError",
        "EvaluationBoundaryError",
        "EvaluationPluginError",
        "ReasonCode",
        "ArtifactRef",
        "PluginIdentity",
        "CheckResult",
        "MetricValue",
        "EvaluationFailure",
        "FamilyEvidence",
        "MaterializationReceipt",
        "CandidateArtifact",
        "CandidateValidation",
        "CandidateReceipt",
        "ValidatedCandidate",
        "EvaluationRequest",
        "FoldPolicy",
        "VerifiedRuntimeLock",
        "EvaluationBinding",
        "EvaluationResult",
        "EvaluationSummary",
        "SplitDataView",
        "ArtifactResolver",
        "ArtifactSink",
        "AuthorizedSplit",
        "QuantTaskPlugin",
        "ContentAddressedArtifactStore",
        "freeze_candidate_validation",
        "validate_candidate_validation",
        "load_candidate_validation",
        "freeze_evaluation_request",
        "validate_evaluation_request",
        "load_evaluation_request",
        "freeze_evaluation_result",
        "validate_evaluation_result",
        "load_evaluation_result",
        "make_candidate_failure_result",
        "make_access_denied_result",
        "validate_evaluation_evidence",
        "canonical_evaluation_result_bytes",
        "compute_evaluation_result_hash",
    }

    assert set(evaluation.__all__) == expected
    assert not hasattr(evaluation, "_freeze_controlled_evaluation_result")


def test_frozen_public_function_parameter_names_and_keyword_boundaries() -> None:
    expected = {
        evaluation.freeze_candidate_validation: (
            ("mapping", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            ("candidate", inspect.Parameter.KEYWORD_ONLY),
            ("contract", inspect.Parameter.KEYWORD_ONLY),
            ("plugin_identity", inspect.Parameter.KEYWORD_ONLY),
        ),
        evaluation.validate_candidate_validation: (
            ("mapping", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            ("candidate", inspect.Parameter.KEYWORD_ONLY),
            ("contract", inspect.Parameter.KEYWORD_ONLY),
            ("plugin_identity", inspect.Parameter.KEYWORD_ONLY),
        ),
        evaluation.load_candidate_validation: (
            ("path", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            ("candidate", inspect.Parameter.KEYWORD_ONLY),
            ("contract", inspect.Parameter.KEYWORD_ONLY),
            ("plugin_identity", inspect.Parameter.KEYWORD_ONLY),
        ),
        evaluation.freeze_evaluation_request: (
            ("mapping", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            ("contract", inspect.Parameter.KEYWORD_ONLY),
            ("candidate_receipt", inspect.Parameter.KEYWORD_ONLY),
        ),
        evaluation.freeze_evaluation_result: (
            ("mapping", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            ("binding", inspect.Parameter.KEYWORD_ONLY),
        ),
        evaluation.load_evaluation_result: (
            ("path", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            ("binding", inspect.Parameter.KEYWORD_ONLY),
            ("expected_sha256", inspect.Parameter.KEYWORD_ONLY),
        ),
    }

    for function, parameter_spec in expected.items():
        parameters = inspect.signature(function).parameters
        assert tuple((name, value.kind) for name, value in parameters.items()) == (
            parameter_spec
        )


@pytest.mark.parametrize(
    "case_factory",
    [
        synthetic_case,
        hm1_case,
        lambda path: formula_case(
            path,
            outcome=FormulaMockOutcome.BACKEND_UNAVAILABLE,
        ),
    ],
    ids=["synthetic", "hm1", "formula-alpha"],
)
def test_one_controller_protocol_handles_all_three_adapters_without_branching(
    tmp_path: Path,
    case_factory: Callable[[Path], Any],
) -> None:
    case = case_factory(tmp_path / "case")

    def controller(plugin: QuantTaskPlugin, case_value: Any) -> tuple[Any, Any]:
        validation = plugin.validate(case_value.candidate, case_value.contract)
        assert validation.status == "valid"
        result = plugin.evaluate(case_value.receipt, case_value.split)
        summary = plugin.summarize(result)
        return result, summary

    result, summary = controller(case.plugin, case)

    assert isinstance(case.plugin, QuantTaskPlugin)
    assert result.request_id == case.request.request_id
    assert summary == EvaluationSummary.from_result(result)
    for method, expected_names in (
        (case.plugin.validate, ("candidate", "contract")),
        (case.plugin.evaluate, ("candidate", "split")),
        (case.plugin.summarize, ("result",)),
    ):
        assert tuple(inspect.signature(method).parameters) == expected_names


def test_candidate_validation_round_trip_hash_order_and_immutability(
    tmp_path: Path,
) -> None:
    _, identity, contract, candidate, receipt = validated_synthetic_components(
        tmp_path / "case"
    )
    validation = receipt.validation
    path = tmp_path / "validation.json"
    validation.write(path)
    loaded = load_candidate_validation(
        path,
        candidate=candidate,
        contract=contract,
        plugin_identity=identity,
    )
    validated = validate_candidate_validation(
        validation.to_dict(),
        candidate=candidate,
        contract=contract,
        plugin_identity=identity,
    )

    assert loaded == validated == validation
    assert path.read_text(encoding="utf-8") == validation.to_json()
    assert validation.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert validation.to_json() == canonical_json(validation.to_dict())
    detached = validation.to_dict()
    detached["checks"][0]["status"] = "fail"
    assert validation.checks[0].status == "pass"
    with pytest.raises(AttributeError):
        validation.status = "invalid_candidate"  # type: ignore[misc]
    with pytest.raises(TypeError):
        validation.plugin["name"] = "mutated"  # type: ignore[index]


def test_candidate_validation_binds_artifact_candidate_canonical_and_receipt_hashes(
    tmp_path: Path,
) -> None:
    _, identity, contract, candidate, receipt = validated_synthetic_components(
        tmp_path / "case"
    )
    mapping = receipt.validation.to_dict()
    mutations = []
    wrong_artifact = copy.deepcopy(mapping)
    wrong_artifact["candidate"]["sha256"] = "f" * 64
    mutations.append(wrong_artifact)
    wrong_candidate = copy.deepcopy(mapping)
    wrong_candidate["candidate_hash"] = "f" * 64
    mutations.append(wrong_candidate)
    wrong_contract = copy.deepcopy(mapping)
    wrong_contract["contract_hash"] = "f" * 64
    mutations.append(wrong_contract)
    wrong_plugin = copy.deepcopy(mapping)
    wrong_plugin["plugin"]["code_sha256"] = "f" * 64
    mutations.append(wrong_plugin)

    for forged in mutations:
        with pytest.raises(EvaluationIntegrityError):
            validate_candidate_validation(
                forged,
                candidate=candidate,
                contract=contract,
                plugin_identity=identity,
            )

    wrong_ref_mapping = receipt.receipt_ref.to_dict()
    wrong_ref_mapping["sha256"] = "f" * 64
    wrong_ref = ArtifactRef.from_mapping(wrong_ref_mapping)
    with pytest.raises(EvaluationIntegrityError):
        CandidateReceipt.bind(
            candidate,
            receipt.validation,
            wrong_ref,
            contract=contract,
            plugin_identity=identity,
        )

    changed_canonical = receipt.validation.to_dict()
    changed_canonical["canonical_form_sha256"] = "e" * 64
    changed_validation = evaluation.freeze_candidate_validation(
        changed_canonical,
        candidate=candidate,
        contract=contract,
        plugin_identity=identity,
    )
    with pytest.raises(EvaluationIntegrityError):
        CandidateReceipt.bind(
            candidate,
            changed_validation,
            receipt.receipt_ref,
            contract=contract,
            plugin_identity=identity,
        )


def test_validated_candidate_is_a_positive_witness_only(tmp_path: Path) -> None:
    _, identity, contract, candidate, invalid_receipt = invalid_synthetic_case(
        tmp_path / "case"
    )

    with pytest.raises(EvaluationInvariantError):
        ValidatedCandidate.bind(
            candidate,
            invalid_receipt.validation,
            invalid_receipt.receipt_ref,
            contract=contract,
            plugin_identity=identity,
        )


def test_evaluation_request_round_trip_canonical_order_and_binding(
    tmp_path: Path,
) -> None:
    _, _, contract, _, receipt = validated_synthetic_components(tmp_path / "case")
    request = make_request(contract, receipt)
    path = tmp_path / "request.json"
    request.write(path)
    loaded = load_evaluation_request(
        path,
        contract=contract,
        candidate_receipt=receipt,
    )
    validated = validate_evaluation_request(
        request.to_dict(),
        contract=contract,
        candidate_receipt=receipt,
    )

    expected_metric_names = [
        contract.to_dict()["metrics"]["primary"]["name"],
        *(item["name"] for item in contract.to_dict()["metrics"]["diagnostics"]),
    ]
    assert loaded == validated == request
    assert request.requested_metrics == tuple(expected_metric_names)
    assert request.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert path.read_text(encoding="utf-8") == request.to_json()


def test_request_freeze_sorts_metrics_but_validate_rejects_signed_reordering(
    tmp_path: Path,
) -> None:
    _, _, contract, _, receipt = validated_synthetic_components(tmp_path / "case")
    request = make_request(contract, receipt)
    mapping = request.to_dict()
    mapping["requested_metrics"] = list(reversed(mapping["requested_metrics"]))

    frozen = freeze_evaluation_request(
        mapping,
        contract=contract,
        candidate_receipt=receipt,
    )
    assert frozen.requested_metrics == request.requested_metrics
    with pytest.raises(EvaluationInvariantError):
        validate_evaluation_request(
            mapping,
            contract=contract,
            candidate_receipt=receipt,
        )


def test_request_raw_duplicate_nonfinite_and_nfc_collision_are_decode_errors(
    tmp_path: Path,
) -> None:
    _, _, contract, _, receipt = validated_synthetic_components(tmp_path / "case")
    for name, raw in (
        ("duplicate.json", b'{"request_id":"a","request_id":"b"}'),
        ("nonfinite.json", b'{"requested_metrics":[NaN]}'),
        ("nfc.json", '{"caf\u00e9":1,"cafe\u0301":2}'.encode()),
    ):
        path = tmp_path / name
        path.write_bytes(raw)
        with pytest.raises(EvaluationDecodeError):
            load_evaluation_request(
                path,
                contract=contract,
                candidate_receipt=receipt,
            )


def test_runtime_lock_is_canonical_complete_and_reverified(tmp_path: Path) -> None:
    contract = synthetic_contract()
    runtime = runtime_fixture(tmp_path, contract)
    mapping = runtime.lock.to_dict()

    assert set(mapping) == {"schema_version", "evaluator", "config", "policy"}
    assert mapping["policy"] == runtime.config["policy"]
    assert runtime.lock.evaluator_sha256 == runtime.evaluator_ref.sha256
    assert runtime.lock.config_sha256 == runtime.config_ref.sha256
    assert (
        runtime.lock.sha256
        == hashlib.sha256(runtime.lock.to_json().encode("utf-8")).hexdigest()
    )
    runtime.lock.verify()


@pytest.mark.parametrize(
    "mapping",
    [
        {
            "mode": "required",
            "expected_fold_ids": [],
            "required_metric_names": ["mean_net_return"],
        },
        {
            "mode": "aggregate_only",
            "expected_fold_ids": ["fold.a"],
            "required_metric_names": [],
        },
        {
            "mode": "required",
            "expected_fold_ids": ["fold.a", "fold.a"],
            "required_metric_names": ["mean_net_return"],
        },
        {
            "mode": "required",
            "expected_fold_ids": ["fold.a"],
            "required_metric_names": ["mean_net_return", "mean_net_return"],
        },
    ],
)
def test_fold_policy_modes_and_names_are_closed(mapping: dict[str, Any]) -> None:
    with pytest.raises(EvaluationInvariantError):
        FoldPolicy.from_mapping(mapping)


def test_materialization_identity_is_relocation_safe_and_root_free(
    tmp_path: Path,
) -> None:
    relative_paths = ("formulas/a.json", "formulas/b.json")
    receipts = []
    for root_name in ("first-root", "second-root"):
        root = tmp_path / root_name
        for index, relative_path in enumerate(relative_paths):
            path = root.joinpath(*relative_path.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"payload-{index}".encode())
        receipts.append(MaterializationReceipt.scan(root, reversed(relative_paths)))

    assert receipts[0] == receipts[1]
    assert receipts[0].sha256 == receipts[1].sha256
    assert [entry["path"] for entry in receipts[0].entries] == list(relative_paths)
    serialized = receipts[0].to_json()
    assert "first-root" not in serialized
    assert "second-root" not in serialized
    assert str(tmp_path) not in serialized


@pytest.mark.parametrize(
    "changed_paths",
    [
        ("strategies/candidate.json", "strategies/candidate.json"),
        ("strategies/z.json", "strategies/a.json"),
    ],
)
def test_candidate_changed_paths_must_be_sorted_unique(
    tmp_path: Path, changed_paths: tuple[str, ...]
) -> None:
    contract = synthetic_contract()
    root = tmp_path / "candidate"
    for relative_path in set(changed_paths) | {"strategies/candidate.json"}:
        path = root.joinpath(*relative_path.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{}")
    receipt = MaterializationReceipt.scan(root, sorted(set(changed_paths)))
    artifact = ArtifactRef.from_mapping(
        artifact_ref_mapping(
            artifact_id="candidate.changed_paths",
            kind=contract.to_dict()["objective"]["candidate_artifact_type"],
            relative_path="strategies/candidate.json",
            payload=b"{}",
            media_type="application/json",
        )
    )

    with pytest.raises(EvaluationInvariantError):
        CandidateArtifact.from_bytes(
            artifact,
            b"{}",
            code_commit="0123456789abcdef0123456789abcdef01234567",
            changed_paths=changed_paths,
            materialization=receipt,
        )


@pytest.mark.parametrize("kind_target", ["evaluator", "config"])
def test_runtime_lock_rejects_wrong_ref_kind(tmp_path: Path, kind_target: str) -> None:
    contract = synthetic_contract()
    runtime = runtime_fixture(tmp_path, contract)
    evaluator_mapping = runtime.evaluator_ref.to_dict()
    config_mapping = runtime.config_ref.to_dict()
    target = evaluator_mapping if kind_target == "evaluator" else config_mapping
    target["kind"] = "q-arbor.wrong-runtime-kind.v1"
    evaluator = ArtifactRef.from_mapping(evaluator_mapping)
    config = ArtifactRef.from_mapping(config_mapping)

    with pytest.raises(EvaluationInvariantError):
        VerifiedRuntimeLock.from_artifacts(
            evaluator,
            config,
            resolver=runtime.resolver,
        )


def test_runtime_config_requires_strict_canonical_json(tmp_path: Path) -> None:
    contract = synthetic_contract()
    runtime = runtime_fixture(tmp_path, contract)
    mapping = json.loads(runtime.config_path.read_text(encoding="utf-8"))
    runtime.config_path.write_text(
        json.dumps(mapping, indent=2, sort_keys=False),
        encoding="utf-8",
    )
    changed_ref = ArtifactRef.from_mapping(
        artifact_ref_mapping(
            artifact_id=runtime.config_ref.artifact_id,
            kind=runtime.config_ref.kind,
            relative_path=runtime.config_ref.relative_path,
            payload=runtime.config_path.read_bytes(),
            media_type="application/json",
        )
    )

    with pytest.raises(EvaluationIntegrityError):
        VerifiedRuntimeLock.from_artifacts(
            runtime.evaluator_ref,
            changed_ref,
            resolver=runtime.resolver,
        )


@pytest.mark.parametrize(
    ("mutate", "expected_error"),
    [
        (
            lambda value: value.update(plugin_config={"api_token": "SECRET"}),
            EvaluationBoundaryError,
        ),
        (
            lambda value: value["policy"].update(
                required_check_names=["split.identity", "candidate.identity"]
            ),
            EvaluationInvariantError,
        ),
        (
            lambda value: value["policy"].update(
                required_check_names=["candidate.identity", "candidate.identity"]
            ),
            EvaluationInvariantError,
        ),
        (
            lambda value: value["policy"].update(
                allowed_artifacts=[
                    {
                        "kind": "q-arbor.aggregate-metrics.v1",
                        "media_type": "TEXT/PLAIN",
                    }
                ]
            ),
            EvaluationSchemaError,
        ),
        (
            lambda value: value["policy"].update(
                allowed_artifacts=[
                    {
                        "kind": "q-arbor.aggregate-metrics.v1",
                        "media_type": "application/json",
                    },
                    {
                        "kind": "q-arbor.aggregate-metrics.v1",
                        "media_type": "application/json",
                    },
                ]
            ),
            EvaluationInvariantError,
        ),
    ],
)
def test_runtime_config_policy_is_closed_sorted_unique_and_secret_free(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    expected_error: type[Exception],
) -> None:
    contract = synthetic_contract()
    runtime = runtime_fixture(tmp_path, contract)
    mapping = copy.deepcopy(runtime.config)
    mutate(mapping)
    payload = canonical_json(mapping).encode("utf-8")
    runtime.config_path.write_bytes(payload)
    changed_ref = ArtifactRef.from_mapping(
        artifact_ref_mapping(
            artifact_id=runtime.config_ref.artifact_id,
            kind=runtime.config_ref.kind,
            relative_path=runtime.config_ref.relative_path,
            payload=payload,
            media_type="application/json",
        )
    )

    with pytest.raises(expected_error):
        VerifiedRuntimeLock.from_artifacts(
            runtime.evaluator_ref,
            changed_ref,
            resolver=runtime.resolver,
        )


def test_artifact_store_is_create_only_scoped_and_uses_hashed_request_namespace(
    tmp_path: Path,
) -> None:
    contract = synthetic_contract()
    runtime = runtime_fixture(tmp_path / "runtime", contract)
    root = tmp_path / "store"
    store = ContentAddressedArtifactStore.create(root)
    request_id = "request.visible-name"
    sink = store.scope(
        request_id=request_id,
        produced_by_event_id="event.artifact",
        runtime_lock=runtime.lock,
    )
    ref = sink.put(
        kind="q-arbor.aggregate-metrics.v1",
        media_type="application/json",
        content=b'{"metric":1}',
    )
    namespace = hashlib.sha256(request_id.encode()).hexdigest()

    assert request_id not in ref.relative_path
    assert namespace in ref.relative_path
    assert ref.produced_by_event_id == "event.artifact"
    assert sink.issued_refs == (ref,)
    store.verify(ref)
    store.verify_issued(
        ref,
        request_id=request_id,
        runtime_lock_sha256=runtime.lock.sha256,
    )
    assert store.read_bytes(ref) == b'{"metric":1}'


@pytest.mark.parametrize(
    ("kind", "media_type"),
    [
        ("q-arbor.unlisted.v1", "application/json"),
        ("q-arbor.aggregate-metrics.v1", "text/plain"),
    ],
)
def test_artifact_sink_rejects_unallowlisted_kind_media_pairs(
    tmp_path: Path, kind: str, media_type: str
) -> None:
    contract = synthetic_contract()
    runtime = runtime_fixture(tmp_path / "runtime", contract)
    store = ContentAddressedArtifactStore.create(tmp_path / "store")
    sink = store.scope(
        request_id="request.artifact",
        produced_by_event_id="event.artifact",
        runtime_lock=runtime.lock,
    )

    with pytest.raises(EvaluationBoundaryError):
        sink.put(kind=kind, media_type=media_type, content=b"safe")
    assert sink.issued_refs == ()


def test_artifact_store_rejects_duplicate_tamper_and_unissued_preexisting_file(
    tmp_path: Path,
) -> None:
    contract = synthetic_contract()
    runtime = runtime_fixture(tmp_path / "runtime", contract)
    root = tmp_path / "store"
    store = ContentAddressedArtifactStore.create(root)
    sink = store.scope(
        request_id="request.artifact",
        produced_by_event_id="event.artifact",
        runtime_lock=runtime.lock,
    )
    ref = sink.put(
        kind="q-arbor.aggregate-metrics.v1",
        media_type="application/json",
        content=b"safe",
    )
    with pytest.raises(EvaluationBoundaryError):
        sink.put(
            kind="q-arbor.aggregate-metrics.v1",
            media_type="application/json",
            content=b"safe",
        )

    issued_path = root.joinpath(*ref.relative_path.split("/"))
    issued_path.write_bytes(b"tampered")
    with pytest.raises(EvaluationIntegrityError):
        store.verify_issued(
            ref,
            request_id="request.artifact",
            runtime_lock_sha256=runtime.lock.sha256,
        )

    preexisting_path = root / "artifacts" / "evaluations" / "preexisting.json"
    preexisting_path.parent.mkdir(parents=True, exist_ok=True)
    preexisting_path.write_bytes(b"preexisting")
    preexisting = ArtifactRef.from_mapping(
        artifact_ref_mapping(
            artifact_id="artifact.preexisting",
            kind="q-arbor.aggregate-metrics.v1",
            relative_path="artifacts/evaluations/preexisting.json",
            payload=b"preexisting",
            media_type="application/json",
        )
    )
    with pytest.raises(EvaluationIntegrityError):
        store.verify_issued(
            preexisting,
            request_id="request.artifact",
            runtime_lock_sha256=runtime.lock.sha256,
        )


def test_artifact_store_rejects_post_issuance_symlink_swap(tmp_path: Path) -> None:
    contract = synthetic_contract()
    runtime = runtime_fixture(tmp_path / "runtime", contract)
    root = tmp_path / "store"
    store = ContentAddressedArtifactStore.create(root)
    sink = store.scope(
        request_id="request.artifact",
        produced_by_event_id="event.artifact",
        runtime_lock=runtime.lock,
    )
    ref = sink.put(
        kind="q-arbor.aggregate-metrics.v1",
        media_type="application/json",
        content=b"safe",
    )
    issued_path = root.joinpath(*ref.relative_path.split("/"))
    outside = tmp_path / "outside"
    outside.write_bytes(b"safe")
    issued_path.unlink()
    issued_path.symlink_to(outside)

    with pytest.raises(EvaluationBoundaryError):
        store.verify_issued(
            ref,
            request_id="request.artifact",
            runtime_lock_sha256=runtime.lock.sha256,
        )


def test_artifact_store_rejects_symlinked_artifacts_parent_before_external_write(
    tmp_path: Path,
) -> None:
    contract = synthetic_contract()
    runtime = runtime_fixture(tmp_path / "runtime", contract)
    root = tmp_path / "store"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "artifacts").symlink_to(outside, target_is_directory=True)
    store = ContentAddressedArtifactStore.create(root)

    with pytest.raises(EvaluationBoundaryError):
        store.scope(
            request_id="request.artifact",
            produced_by_event_id="event.artifact",
            runtime_lock=runtime.lock,
        )

    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("sidecar_name", [".issued", ".scope.json"])
def test_artifact_store_rejects_preexisting_sidecar_symlink(
    tmp_path: Path, sidecar_name: str
) -> None:
    contract = synthetic_contract()
    runtime = runtime_fixture(tmp_path / "runtime", contract)
    root = tmp_path / "store"
    outside = tmp_path / "outside"
    namespace = hashlib.sha256(b"request.artifact").hexdigest()
    sidecar = root / "artifacts" / "evaluations" / namespace / sidecar_name
    sidecar.parent.mkdir(parents=True)
    outside.mkdir()
    if sidecar_name == ".issued":
        sidecar.symlink_to(outside, target_is_directory=True)
    else:
        outside_file = outside / "scope.json"
        outside_file.write_text('{"forged":true}', encoding="utf-8")
        sidecar.symlink_to(outside_file)
    with pytest.raises(EvaluationBoundaryError):
        store = ContentAddressedArtifactStore.create(root)
        store.scope(
            request_id="request.artifact",
            produced_by_event_id="event.artifact",
            runtime_lock=runtime.lock,
        )

    expected = [] if sidecar_name == ".issued" else [outside / "scope.json"]
    assert list(outside.iterdir()) == expected


def test_artifact_store_never_follows_a_swapped_issuance_record(
    tmp_path: Path,
) -> None:
    contract = synthetic_contract()
    runtime = runtime_fixture(tmp_path / "runtime", contract)
    root = tmp_path / "store"
    store = ContentAddressedArtifactStore.create(root)
    sink = store.scope(
        request_id="request.artifact",
        produced_by_event_id="event.artifact",
        runtime_lock=runtime.lock,
    )
    ref = sink.put(
        kind="q-arbor.aggregate-metrics.v1",
        media_type="application/json",
        content=b"safe",
    )
    issuance_records = [
        path for path in root.rglob("*") if path.is_file() and ".issued" in path.parts
    ]
    assert len(issuance_records) == 1
    record = issuance_records[0]
    outside = tmp_path / "outside-record.json"
    outside.write_text('{"forged":true}', encoding="utf-8")
    record.unlink()
    record.symlink_to(outside)

    with pytest.raises(EvaluationBoundaryError):
        store.verify_issued(
            ref,
            request_id="request.artifact",
            runtime_lock_sha256=runtime.lock.sha256,
        )

    assert outside.read_text(encoding="utf-8") == '{"forged":true}'


@pytest.mark.parametrize(
    ("identifier", "expected_error"),
    [
        ("identifier\n", EvaluationSchemaError),
        ("a" * 161, EvaluationSchemaError),
        ("contains space", EvaluationSchemaError),
        ("/absolute", EvaluationSchemaError),
        ("café", EvaluationSchemaError),
    ],
)
def test_identifiers_are_runtime_fullmatched(
    identifier: str, expected_error: type[Exception]
) -> None:
    mapping = artifact_ref_mapping(
        artifact_id=identifier,
        kind="q-arbor.aggregate-metrics.v1",
        relative_path="artifacts/result.json",
        payload=b"{}",
        media_type="application/json",
    )

    with pytest.raises(expected_error):
        ArtifactRef.from_mapping(mapping)


def test_plugin_identity_fullmatches_hashes_and_identifier(tmp_path: Path) -> None:
    from q_arbor.evaluation import PluginIdentity

    for field, value, expected_error in (
        ("name", "plugin\n", EvaluationSchemaError),
        ("code_sha256", "a" * 64 + "\n", EvaluationSchemaError),
        ("code_sha256", "A" * 64, EvaluationSchemaError),
    ):
        mapping = plugin_identity_mapping()
        mapping[field] = value
        with pytest.raises(expected_error):
            PluginIdentity.from_mapping(mapping)
    assert tmp_path.exists()


def test_candidate_artifact_kind_mismatch_is_invalid_before_split(
    tmp_path: Path,
) -> None:
    plugin, _, contract, candidate, _ = validated_synthetic_components(
        tmp_path / "case"
    )
    mapping = candidate.artifact.to_dict()
    mapping["kind"] = "q-arbor.wrong-candidate-kind.v1"
    wrong_ref = ArtifactRef.from_mapping(mapping)
    wrong_candidate = CandidateArtifact.from_bytes(
        wrong_ref,
        candidate.payload,
        code_commit=candidate.code_commit,
        changed_paths=candidate.changed_paths,
        materialization=candidate.materialization,
    )

    validation = plugin.validate(wrong_candidate, contract)

    assert validation.status == "invalid_candidate"
    assert validation.failure.failure_type == "invalid_candidate"


def test_live_plugin_identity_drift_is_integrity_error_before_validation(
    tmp_path: Path,
) -> None:
    _, _, contract, candidate, _ = validated_synthetic_components(tmp_path / "case")
    wrong_identity_mapping = plugin_identity_mapping(code_sha256="f" * 64)
    from q_arbor.evaluation import PluginIdentity

    wrong_plugin = SyntheticSignalPlugin.create(
        PluginIdentity.from_mapping(wrong_identity_mapping)
    )

    with pytest.raises(EvaluationIntegrityError):
        wrong_plugin.validate(candidate, contract)


def test_contract_task_kind_mismatch_is_integrity_error_before_validation(
    tmp_path: Path,
) -> None:
    plugin, _, contract, candidate, _ = validated_synthetic_components(
        tmp_path / "case"
    )
    mapping = contract.to_dict()
    mapping.pop("contract_hash")
    mapping["task_kind"] = "formula_alpha"
    from q_arbor.contracts import freeze_contract

    wrong_contract = freeze_contract(mapping)

    with pytest.raises(EvaluationIntegrityError):
        plugin.validate(candidate, wrong_contract)
