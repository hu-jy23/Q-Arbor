from __future__ import annotations

import copy
import hashlib
import inspect
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from q_arbor.evaluation import (
    ArtifactRef,
    CandidateArtifact,
    EvaluationBoundaryError,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationSchemaError,
    ReasonCode,
    ValidatedCandidate,
    freeze_candidate_validation,
    freeze_evaluation_request,
    freeze_evaluation_result,
    make_access_denied_result,
    make_candidate_failure_result,
    validate_evaluation_result,
)
from q_arbor.plugins.synthetic import make_synthetic_development_split

from tests.evaluation_helpers import (
    CODE_COMMIT,
    artifact_ref_mapping,
    bind_validation,
    corrupt_bytes,
    directory_entries,
    fixture_bytes,
    invalid_synthetic_case,
    make_binding,
    make_request,
    materialize_candidate,
    runtime_fixture,
    synthetic_case,
    validated_synthetic_components,
)


def _terminal_binding(
    root: Path,
    *,
    split_role: str = "development",
) -> tuple[Any, Any, Any, ValidatedCandidate, Any, Any, Any]:
    plugin, identity, contract, _, receipt = validated_synthetic_components(root)
    request = make_request(
        contract,
        receipt,
        split_role=split_role,
        request_id=f"request.terminal.{split_role}",
    )
    runtime = runtime_fixture(root, contract)
    from q_arbor.evaluation import ContentAddressedArtifactStore

    store = ContentAddressedArtifactStore.create(root / "artifact-store")
    binding = make_binding(
        request=request,
        contract=contract,
        receipt=receipt,
        plugin_identity=identity,
        runtime_lock=runtime.lock,
        artifact_resolver=store,
        result_id=f"result.terminal.{split_role}",
    )
    return plugin, identity, contract, receipt, request, runtime, binding


def _assert_exact_null_terminal(
    result: Any,
    *,
    contract: Any,
    runtime: Any,
    status: str,
    failure_type: str,
    reason_code: str,
) -> None:
    mapping = result.to_dict()
    contract_mapping = contract.to_dict()
    primary = contract_mapping["metrics"]["primary"]
    assert mapping["status"] == status
    assert mapping["primary_metric"] == {
        "name": primary["name"],
        "value": None,
        "direction": primary["direction"],
        "unit": primary["unit"],
    }
    assert mapping["constraints"] == [
        {
            "name": item["name"],
            "status": "not_observed",
            "evidence": "evaluation.not_observed",
        }
        for item in contract_mapping["metrics"]["hard_constraints"]
    ]
    assert mapping["diagnostics"] == [
        {
            "name": item["name"],
            "value": None,
            "direction": item["direction"],
            "unit": item["unit"],
        }
        for item in contract_mapping["metrics"]["diagnostics"]
    ]
    assert mapping["fold_metrics"] == []
    assert mapping["artifacts"] == []
    assert mapping["statistical_diagnostics"] == []
    assert mapping["warnings"] == []
    assert mapping["costs"] == {
        "gross": None,
        "transaction_cost": None,
        "net": None,
        "turnover": None,
        "cost_model_sha256": contract_mapping["cost_model"]["sha256"],
    }
    assert mapping["checks"] == [
        {
            "name": name,
            "status": "not_observed",
            "evidence": "evaluation.not_observed",
        }
        for name in runtime.lock.policy["required_check_names"]
    ]
    assert mapping["failure"] == {
        "failure_type": failure_type,
        "summary": reason_code,
        "evidence_ids": [],
    }


@pytest.mark.parametrize(
    ("fixture_name", "reason"),
    [
        ("synthetic_unknown_field_candidate.json", "candidate.unknown_signal"),
        ("synthetic_label_leak_candidate.json", "candidate.label_leak"),
    ],
)
def test_invalid_candidate_terminal_is_exact_and_never_constructs_a_split(
    tmp_path: Path, fixture_name: str, reason: str
) -> None:
    root = tmp_path / "case"
    plugin, identity, contract, _, receipt = invalid_synthetic_case(
        root,
        fixture_name=fixture_name,
    )
    assert receipt.status == "invalid_candidate"
    request = make_request(contract, receipt, request_id="request.invalid")
    runtime = runtime_fixture(root, contract)
    from q_arbor.evaluation import ContentAddressedArtifactStore

    store_root = root / "artifact-store"
    store = ContentAddressedArtifactStore.create(store_root)
    binding = make_binding(
        request=request,
        contract=contract,
        receipt=receipt,
        plugin_identity=identity,
        runtime_lock=runtime.lock,
        artifact_resolver=store,
        result_id="result.invalid",
    )
    before = directory_entries(store_root)

    result = make_candidate_failure_result(
        binding=binding,
        reason_code=ReasonCode.parse(reason),
    )

    assert directory_entries(store_root) == before
    _assert_exact_null_terminal(
        result,
        contract=contract,
        runtime=runtime,
        status="invalid_candidate",
        failure_type="invalid_candidate",
        reason_code=reason,
    )
    assert "split" not in inspect.signature(make_candidate_failure_result).parameters
    assert "plugin" not in inspect.signature(make_candidate_failure_result).parameters
    assert plugin.identity == identity


def test_validation_implementation_failure_maps_to_exact_terminal(
    tmp_path: Path,
) -> None:
    root = tmp_path / "case"
    plugin, identity, contract, candidate, invalid_receipt = invalid_synthetic_case(
        root
    )
    mapping = invalid_receipt.validation.to_dict()
    mapping["status"] = "implementation_failure"
    mapping["failure"] = {
        "failure_type": "implementation_failure",
        "summary": "candidate.validator_unavailable",
        "evidence_ids": [],
    }
    validation = freeze_candidate_validation(
        mapping,
        candidate=candidate,
        contract=contract,
        plugin_identity=identity,
    )
    receipt = bind_validation(
        root / "implementation",
        candidate=candidate,
        validation=validation,
        contract=contract,
        plugin_identity=identity,
        require_valid=False,
    )
    request = make_request(contract, receipt, request_id="request.validation.failure")
    runtime = runtime_fixture(root / "implementation", contract)
    from q_arbor.evaluation import ContentAddressedArtifactStore

    store = ContentAddressedArtifactStore.create(root / "implementation/store")
    binding = make_binding(
        request=request,
        contract=contract,
        receipt=receipt,
        plugin_identity=identity,
        runtime_lock=runtime.lock,
        artifact_resolver=store,
        result_id="result.validation.failure",
    )

    result = make_candidate_failure_result(
        binding=binding,
        reason_code=ReasonCode.parse("candidate.validator_unavailable"),
    )

    _assert_exact_null_terminal(
        result,
        contract=contract,
        runtime=runtime,
        status="implementation_failure",
        failure_type="implementation_failure",
        reason_code="candidate.validator_unavailable",
    )
    assert plugin.identity == identity


@pytest.mark.parametrize("role", ["gate", "final"])
def test_access_denied_factory_is_zero_call_and_opens_no_split_or_artifact(
    tmp_path: Path, role: str
) -> None:
    root = tmp_path / role
    _, _, contract, _, _, runtime, binding = _terminal_binding(
        root,
        split_role=role,
    )
    store_root = root / "artifact-store"
    before = directory_entries(store_root)

    result = make_access_denied_result(
        binding=binding,
        reason_code=ReasonCode.parse("authorization.access_denied"),
    )

    assert directory_entries(store_root) == before
    _assert_exact_null_terminal(
        result,
        contract=contract,
        runtime=runtime,
        status="access_denied",
        failure_type="access_denied",
        reason_code="authorization.access_denied",
    )
    assert "plugin" not in inspect.signature(make_access_denied_result).parameters
    assert "split" not in inspect.signature(make_access_denied_result).parameters


def test_terminal_factories_reject_inapplicable_candidate_status(
    tmp_path: Path,
) -> None:
    _, _, _, _, _, _, valid_binding = _terminal_binding(tmp_path / "valid")
    _, identity, contract, _, invalid_receipt = invalid_synthetic_case(
        tmp_path / "invalid"
    )
    request = make_request(contract, invalid_receipt, request_id="request.invalid")
    runtime = runtime_fixture(tmp_path / "invalid", contract)
    from q_arbor.evaluation import ContentAddressedArtifactStore

    store = ContentAddressedArtifactStore.create(tmp_path / "invalid/store")
    invalid_binding = make_binding(
        request=request,
        contract=contract,
        receipt=invalid_receipt,
        plugin_identity=identity,
        runtime_lock=runtime.lock,
        artifact_resolver=store,
        result_id="result.invalid",
    )

    with pytest.raises(EvaluationInvariantError):
        make_candidate_failure_result(
            binding=valid_binding,
            reason_code=ReasonCode.parse("candidate.invalid"),
        )
    with pytest.raises(EvaluationInvariantError):
        make_access_denied_result(
            binding=invalid_binding,
            reason_code=ReasonCode.parse("authorization.denied"),
        )


@pytest.mark.parametrize(
    ("status", "failure_type"),
    [
        ("access_denied", "access_denied"),
        ("implementation_failure", "implementation_failure"),
        ("evaluation_failure", "evaluation_failure"),
        ("evaluation_failure", "timeout"),
        ("evaluation_failure", "interruption"),
        ("incomparable", "incomparable"),
        ("contaminated", "contamination"),
    ],
)
def test_every_non_success_status_failure_pair_is_accepted_with_null_shape(
    tmp_path: Path, status: str, failure_type: str
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = make_access_denied_result(
        binding=case.binding,
        reason_code=ReasonCode.parse("qualification.terminal"),
    ).to_dict()
    mapping["status"] = status
    mapping["failure"]["failure_type"] = failure_type

    frozen = freeze_evaluation_result(mapping, binding=case.binding)

    assert frozen.status == status
    assert frozen.failure.failure_type == failure_type


def test_hard_constraint_failure_is_invalid_candidate_without_score(
    tmp_path: Path,
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = make_access_denied_result(
        binding=case.binding,
        reason_code=ReasonCode.parse("constraint.max_turnover"),
    ).to_dict()
    mapping["status"] = "invalid_candidate"
    mapping["failure"]["failure_type"] = "constraint_violation"
    mapping["constraints"][0] = {
        "name": mapping["constraints"][0]["name"],
        "status": "fail",
        "evidence": "constraint.max_turnover.failed",
    }

    frozen = freeze_evaluation_result(mapping, binding=case.binding)

    assert frozen.status == "invalid_candidate"
    assert frozen.failure.failure_type == "constraint_violation"
    assert frozen.primary_metric.value is None


@pytest.mark.parametrize(
    ("status", "failure_type"),
    [
        ("success", "evaluation_failure"),
        ("access_denied", "timeout"),
        ("implementation_failure", "incomparable"),
        ("evaluation_failure", "contamination"),
        ("incomparable", "access_denied"),
        ("contaminated", "evaluation_failure"),
    ],
)
def test_status_failure_mismatches_are_invariant_errors(
    tmp_path: Path, status: str, failure_type: str
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = make_access_denied_result(
        binding=case.binding,
        reason_code=ReasonCode.parse("qualification.terminal"),
    ).to_dict()
    mapping["status"] = status
    mapping["failure"]["failure_type"] = failure_type

    with pytest.raises(EvaluationInvariantError):
        freeze_evaluation_result(mapping, binding=case.binding)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["primary_metric"].update(value=0.1),
        lambda value: value.update(failure=None),
        lambda value: value["fold_metrics"].append(
            {
                "fold_id": "fold.a",
                "time_range": "2020-01-01/2020-01-31",
                "metrics": [
                    {
                        "name": "mean_net_return",
                        "value": 0.1,
                        "direction": "maximize",
                        "unit": "ratio",
                    }
                ],
            }
        ),
        lambda value: value["checks"][0].update(
            status="pass", evidence="candidate.identity.ok"
        ),
    ],
)
def test_non_success_cannot_smuggle_score_fold_or_success_evidence(
    tmp_path: Path, mutation: Callable[[dict[str, Any]], None]
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = make_access_denied_result(
        binding=case.binding,
        reason_code=ReasonCode.parse("authorization.denied"),
    ).to_dict()
    mutation(mapping)

    with pytest.raises(EvaluationInvariantError):
        freeze_evaluation_result(mapping, binding=case.binding)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["primary_metric"].update(value=0.1),
        lambda value: value["fold_metrics"].append(
            {
                "fold_id": "fold.a",
                "time_range": "2020-01-01/2020-01-31",
                "metrics": [],
            }
        ),
        lambda value: value["artifacts"].append(
            {
                "artifact_id": "artifact.suspect",
                "kind": "q-arbor.aggregate-metrics.v1",
                "relative_path": "artifacts/evaluations/suspect.json",
                "sha256": "a" * 64,
                "media_type": "application/json",
            }
        ),
        lambda value: value.update(warnings=["warning.suspect"]),
        lambda value: value["failure"].update(failure_type="evaluation_failure"),
    ],
)
def test_contaminated_terminal_cannot_retain_any_suspect_observation(
    tmp_path: Path, mutation: Callable[[dict[str, Any]], None]
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = make_access_denied_result(
        binding=case.binding,
        reason_code=ReasonCode.parse("runtime.drift"),
    ).to_dict()
    mapping["status"] = "contaminated"
    mapping["failure"]["failure_type"] = "contamination"
    mutation(mapping)

    with pytest.raises(EvaluationInvariantError):
        freeze_evaluation_result(mapping, binding=case.binding)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["primary_metric"].update(value=None),
        lambda value: value.update(
            failure={
                "failure_type": "evaluation_failure",
                "summary": "evaluation.failed",
                "evidence_ids": [],
            }
        ),
        lambda value: value["constraints"][0].update(status="fail"),
        lambda value: value["checks"][0].update(status="not_observed"),
        lambda value: value["diagnostics"].clear(),
    ],
)
def test_success_requires_complete_finite_passing_observations(
    tmp_path: Path, mutation: Callable[[dict[str, Any]], None]
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = case.result.to_dict()
    mutation(mapping)

    with pytest.raises(EvaluationInvariantError):
        freeze_evaluation_result(mapping, binding=case.binding)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("result_id", "result.forged"),
        ("request_id", "request.forged"),
        ("split_role", "gate"),
    ],
)
def test_result_header_identity_is_bound(
    tmp_path: Path, field: str, replacement: str
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = case.result.to_dict()
    mapping[field] = replacement

    with pytest.raises(EvaluationIntegrityError):
        freeze_evaluation_result(mapping, binding=case.binding)


@pytest.mark.parametrize(
    "field",
    [
        "candidate_sha256",
        "code_commit",
        "data_snapshot_sha256",
        "split_manifest_hash",
        "contract_hash",
        "plugin_code_sha256",
        "evaluator_sha256",
        "config_sha256",
        "seed",
    ],
)
def test_every_provenance_field_is_bound_to_trusted_inputs(
    tmp_path: Path, field: str
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = case.result.to_dict()
    mapping["provenance"][field] = 19 if field == "seed" else "f" * 64

    with pytest.raises(EvaluationIntegrityError):
        freeze_evaluation_result(mapping, binding=case.binding)


def test_missing_provenance_is_schema_error_for_failure_too(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = make_access_denied_result(
        binding=case.binding,
        reason_code=ReasonCode.parse("authorization.denied"),
    ).to_dict()
    del mapping["provenance"]["config_sha256"]

    with pytest.raises(EvaluationSchemaError):
        freeze_evaluation_result(mapping, binding=case.binding)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["primary_metric"].update(name="wrong"),
        lambda value: value["primary_metric"].update(direction="minimize"),
        lambda value: value["primary_metric"].update(unit="wrong"),
        lambda value: value["diagnostics"].clear(),
        lambda value: value["diagnostics"].append(
            copy.deepcopy(value["diagnostics"][0])
        ),
        lambda value: value["constraints"].clear(),
        lambda value: value["constraints"].append(
            copy.deepcopy(value["constraints"][0])
        ),
    ],
)
def test_metric_and_constraint_declarations_are_exact(
    tmp_path: Path, mutation: Callable[[dict[str, Any]], None]
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = case.result.to_dict()
    mutation(mapping)

    with pytest.raises(EvaluationInvariantError):
        freeze_evaluation_result(mapping, binding=case.binding)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["fold_metrics"].append(
            copy.deepcopy(value["fold_metrics"][0])
        ),
        lambda value: value["fold_metrics"][0].update(
            time_range="2020-12-31/2020-01-01"
        ),
        lambda value: value["fold_metrics"][0]["metrics"].clear(),
        lambda value: value["fold_metrics"][0]["metrics"].append(
            copy.deepcopy(value["fold_metrics"][0]["metrics"][0])
        ),
    ],
)
def test_fold_identity_order_range_and_metrics_are_exact(
    tmp_path: Path, mutation: Callable[[dict[str, Any]], None]
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = case.result.to_dict()
    mutation(mapping)

    with pytest.raises(EvaluationInvariantError):
        freeze_evaluation_result(mapping, binding=case.binding)


def test_fold_freeze_normalizes_order_while_validate_rejects_it(
    tmp_path: Path,
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = case.result.to_dict()
    mapping["fold_metrics"] = list(reversed(mapping["fold_metrics"]))

    frozen = freeze_evaluation_result(mapping, binding=case.binding)

    assert [fold["fold_id"] for fold in frozen.fold_metrics] == list(
        case.runtime.lock.policy["fold_policy"]["expected_fold_ids"]
    )
    with pytest.raises(EvaluationInvariantError):
        validate_evaluation_result(mapping, binding=case.binding)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["costs"].update(transaction_cost=-0.1),
        lambda value: value["costs"].update(turnover=-0.1),
        lambda value: value["costs"].update(net=value["costs"]["net"] + 0.000001),
        lambda value: value["costs"].update(cost_model_sha256="f" * 64),
    ],
)
def test_costs_are_exact_finite_and_reconciled(
    tmp_path: Path, mutation: Callable[[dict[str, Any]], None]
) -> None:
    case = synthetic_case(tmp_path / "case")
    mapping = case.result.to_dict()
    mutation(mapping)

    expected_error = (
        EvaluationIntegrityError
        if mapping["costs"]["cost_model_sha256"] == "f" * 64
        else EvaluationInvariantError
    )
    with pytest.raises(expected_error):
        freeze_evaluation_result(mapping, binding=case.binding)


def test_c9_rejects_statistical_diagnostics_and_duplicate_warnings(
    tmp_path: Path,
) -> None:
    case = synthetic_case(tmp_path / "case")
    statistical = case.result.to_dict()
    statistical["statistical_diagnostics"] = [
        {
            "method": "psr",
            "method_plan_hash": "a" * 64,
            "control_object": "selection_bias",
            "status": "diagnostic",
            "claim_level": "diagnostic",
            "family_unit": "candidate",
            "duplicate_policy": "count_each_query",
            "family_snapshot_hash": "b" * 64,
            "trial_count": 1,
            "assumptions": [],
            "inputs_sha256": "c" * 64,
            "result": {},
        }
    ]
    duplicate = case.result.to_dict()
    duplicate["warnings"] = ["warning.same", "warning.same"]

    with pytest.raises(EvaluationInvariantError):
        freeze_evaluation_result(statistical, binding=case.binding)
    with pytest.raises(EvaluationInvariantError):
        freeze_evaluation_result(duplicate, binding=case.binding)


def test_request_rejects_manifest_candidate_receipt_and_plugin_identity_drift(
    tmp_path: Path,
) -> None:
    _, identity, contract, _, receipt = validated_synthetic_components(
        tmp_path / "case"
    )
    valid = make_request(contract, receipt).to_dict()
    mutations = []
    wrong_contract = copy.deepcopy(valid)
    wrong_contract["contract_hash"] = "f" * 64
    mutations.append(wrong_contract)
    wrong_manifest = copy.deepcopy(valid)
    wrong_manifest["split_manifest_hash"] = "f" * 64
    mutations.append(wrong_manifest)
    wrong_candidate = copy.deepcopy(valid)
    wrong_candidate["candidate_hash"] = "f" * 64
    mutations.append(wrong_candidate)
    wrong_receipt = copy.deepcopy(valid)
    wrong_receipt["validation_receipt"]["sha256"] = "f" * 64
    mutations.append(wrong_receipt)
    wrong_plugin = copy.deepcopy(valid)
    wrong_plugin["plugin"]["code_sha256"] = "f" * 64
    mutations.append(wrong_plugin)

    for mapping in mutations:
        with pytest.raises(EvaluationIntegrityError):
            freeze_evaluation_request(
                mapping,
                contract=contract,
                candidate_receipt=receipt,
            )
    assert identity == receipt.plugin_identity


def test_candidate_hash_has_independent_exact_three_identity_oracle(
    tmp_path: Path,
) -> None:
    _, _, _, candidate, _ = validated_synthetic_components(tmp_path / "case")
    expected_payload = {
        "schema_version": "1.0",
        "artifact_kind": candidate.artifact.kind,
        "artifact_sha256": candidate.artifact.sha256,
        "code_commit": candidate.code_commit,
        "changed_paths": list(candidate.changed_paths),
        "materialization_sha256": candidate.materialization.sha256,
    }
    expected = hashlib.sha256(
        __import__("json")
        .dumps(
            expected_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        .encode("utf-8")
    ).hexdigest()

    assert candidate.candidate_hash == expected
    assert candidate.candidate_hash != candidate.artifact.sha256


def test_candidate_payload_digest_mismatch_is_integrity_error(tmp_path: Path) -> None:
    _, _, contract, candidate, _ = validated_synthetic_components(tmp_path / "case")

    with pytest.raises(EvaluationIntegrityError):
        CandidateArtifact.from_bytes(
            candidate.artifact,
            b"different payload",
            code_commit=CODE_COMMIT,
            changed_paths=candidate.changed_paths,
            materialization=candidate.materialization,
        )
    assert contract.sha256


@pytest.mark.parametrize("attack", ["symlink", "hardlink"])
def test_candidate_materialization_denies_symlink_and_hardlink(
    tmp_path: Path, attack: str
) -> None:
    from q_arbor.evaluation import MaterializationReceipt

    root = tmp_path / "candidate"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"{}")
    target = root / "candidate.json"
    if attack == "symlink":
        target.symlink_to(outside)
    else:
        os.link(outside, target)

    with pytest.raises(EvaluationBoundaryError):
        MaterializationReceipt.scan(root, ("candidate.json",))


@pytest.mark.parametrize(
    ("path", "expected_error"),
    [
        ("/absolute.json", EvaluationSchemaError),
        ("C:/drive.json", EvaluationSchemaError),
        ("../escape.json", EvaluationSchemaError),
        ("./dot.json", EvaluationSchemaError),
        ("double//separator.json", EvaluationSchemaError),
        ("back\\slash.json", EvaluationSchemaError),
        ("glob/*.json", EvaluationInvariantError),
        ("nul\x00byte.json", EvaluationInvariantError),
    ],
)
def test_artifact_paths_are_literal_and_bounded(
    path: str, expected_error: type[Exception]
) -> None:
    mapping = artifact_ref_mapping(
        artifact_id="artifact.path",
        kind="q-arbor.aggregate-metrics.v1",
        relative_path=path,
        payload=b"{}",
        media_type="application/json",
    )

    with pytest.raises(expected_error):
        ArtifactRef.from_mapping(mapping)


@pytest.mark.parametrize(
    "path",
    [
        "segment-" + "x" * 248 + ".json",
        "/".join(["segment"] * 600) + ".json",
    ],
)
def test_artifact_path_segment_and_total_utf8_limits_are_enforced(path: str) -> None:
    mapping = artifact_ref_mapping(
        artifact_id="artifact.long_path",
        kind="q-arbor.aggregate-metrics.v1",
        relative_path=path,
        payload=b"{}",
        media_type="application/json",
    )

    with pytest.raises(EvaluationInvariantError):
        ArtifactRef.from_mapping(mapping)


def test_changed_protected_path_is_invalid_before_evaluation(tmp_path: Path) -> None:
    root = tmp_path / "case"
    plugin, identity, contract, _, _ = validated_synthetic_components(root / "valid")
    candidate_root = root / "protected"
    protected = candidate_root / "evaluator" / "config.json"
    protected.parent.mkdir(parents=True)
    protected.write_bytes(b"{}")
    candidate = materialize_candidate(
        candidate_root,
        contract,
        fixture_bytes("synthetic_planted_candidate.json"),
        changed_paths=("evaluator/config.json", "strategies/candidate.json"),
    )

    validation = plugin.validate(candidate, contract)

    assert validation.status == "invalid_candidate"
    assert validation.failure.failure_type == "invalid_candidate"
    assert identity == plugin.identity


@pytest.mark.parametrize("runtime_part", ["evaluator", "config"])
def test_runtime_lock_rejects_pre_execution_byte_drift(
    tmp_path: Path, runtime_part: str
) -> None:
    case = synthetic_case(tmp_path / "case")
    path = (
        case.runtime.evaluator_path
        if runtime_part == "evaluator"
        else case.runtime.config_path
    )
    corrupt_bytes(path)

    with pytest.raises(EvaluationIntegrityError):
        validate_evaluation_result(case.result.to_dict(), binding=case.binding)


@pytest.mark.parametrize("runtime_part", ["evaluator", "config"])
def test_first_post_execution_runtime_drift_returns_contaminated(
    tmp_path: Path, runtime_part: str
) -> None:
    root = tmp_path / "case"
    plugin, identity, contract, _, receipt = validated_synthetic_components(root)
    request = make_request(contract, receipt, request_id="request.post.tamper")
    runtime = runtime_fixture(root, contract)
    from q_arbor.evaluation import ContentAddressedArtifactStore

    store = ContentAddressedArtifactStore.create(root / "store")
    split = make_synthetic_development_split(
        request,
        contract,
        receipt,
        plugin,
        runtime.lock,
        result_id="result.post.tamper",
        evaluation_seed=7,
        artifact_store=store,
        produced_by_event_id="event.post.tamper",
    )
    original_verify = runtime.resolver.verify
    target_ref = (
        runtime.evaluator_ref if runtime_part == "evaluator" else runtime.config_ref
    )
    target_path = (
        runtime.evaluator_path if runtime_part == "evaluator" else runtime.config_path
    )
    flipped = False

    def verify_then_flip(ref: ArtifactRef) -> None:
        nonlocal flipped
        original_verify(ref)
        if not flipped and ref == target_ref:
            flipped = True
            corrupt_bytes(target_path)

    runtime.resolver.verify = verify_then_flip  # type: ignore[method-assign]

    result = plugin.evaluate(receipt, split)
    target = root / f"controlled-{runtime_part}.json"
    target.write_bytes(b"sentinel")
    result.write(target)

    assert result.status == "contaminated"
    assert result.failure.failure_type == "contamination"
    assert result.primary_metric.value is None
    assert result.fold_metrics == ()
    assert result.artifacts == ()
    assert target.read_bytes() == result.to_json().encode("utf-8")
    assert identity == plugin.identity


def test_issued_artifact_is_bound_to_complete_runtime_lock(tmp_path: Path) -> None:
    root = tmp_path / "case"
    _, identity, contract, _, receipt = validated_synthetic_components(root)
    request = make_request(contract, receipt, request_id="request.issued")
    runtime_a = runtime_fixture(root / "runtime-a", contract)
    runtime_b = runtime_fixture(
        root / "runtime-b",
        contract,
        evaluator_payload=b"different evaluator bytes\n",
    )
    from q_arbor.evaluation import ContentAddressedArtifactStore

    store = ContentAddressedArtifactStore.create(root / "store")
    sink = store.scope(
        request_id=request.request_id,
        produced_by_event_id="event.issued",
        runtime_lock=runtime_a.lock,
    )
    ref = sink.put(
        kind="q-arbor.aggregate-metrics.v1",
        media_type="application/json",
        content=b'{"safe":true}',
    )

    store.verify_issued(
        ref,
        request_id=request.request_id,
        runtime_lock_sha256=runtime_a.lock.sha256,
    )
    with pytest.raises(EvaluationIntegrityError):
        store.verify_issued(
            ref,
            request_id=request.request_id,
            runtime_lock_sha256=runtime_b.lock.sha256,
        )
    assert runtime_a.lock.config_sha256 == runtime_b.lock.config_sha256
    assert runtime_a.lock.sha256 != runtime_b.lock.sha256
    assert identity == receipt.plugin_identity


def test_put_rejects_same_bytes_preplanted_during_exclusive_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "case"
    _, _, contract, _, receipt = validated_synthetic_components(root)
    request = make_request(contract, receipt, request_id="request.preplanted")
    runtime = runtime_fixture(root, contract)
    from q_arbor.evaluation import ContentAddressedArtifactStore

    store_root = root / "store"
    store = ContentAddressedArtifactStore.create(store_root)
    sink = store.scope(
        request_id=request.request_id,
        produced_by_event_id="event.preplanted",
        runtime_lock=runtime.lock,
    )
    content = b'{"safe":true}'
    real_open = os.open
    injected = False

    def inject_same_bytes_before_exclusive_create(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal injected
        if not injected and flags & os.O_CREAT and flags & os.O_EXCL:
            injected = True
            planted_fd = real_open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=dir_fd,
            )
            try:
                offset = 0
                while offset < len(content):
                    offset += os.write(planted_fd, content[offset:])
            finally:
                os.close(planted_fd)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", inject_same_bytes_before_exclusive_create)

    with pytest.raises(EvaluationBoundaryError):
        sink.put(
            kind="q-arbor.aggregate-metrics.v1",
            media_type="application/json",
            content=content,
        )

    scope_name = hashlib.sha256(request.request_id.encode("utf-8")).hexdigest()
    issued_directory = store_root / "artifacts" / "evaluations" / scope_name / ".issued"
    assert injected is True
    assert sink.issued_refs == ()
    assert list(issued_directory.iterdir()) == []


def test_result_cannot_replay_an_artifact_issued_under_another_runtime_lock(
    tmp_path: Path,
) -> None:
    case = synthetic_case(tmp_path / "case")
    if case.result.artifacts:
        issued_ref = case.result.artifacts[0]
    else:
        sink = case.store.scope(
            request_id=case.request.request_id,
            produced_by_event_id="event.evaluation.synthetic",
            runtime_lock=case.runtime.lock,
        )
        issued_ref = sink.put(
            kind="q-arbor.aggregate-metrics.v1",
            media_type="application/json",
            content=b'{"cross_lock":true}',
        )
    runtime_b = runtime_fixture(
        tmp_path / "runtime-b",
        case.contract,
        evaluator_payload=b"replacement runtime\n",
    )
    binding_b = make_binding(
        request=case.request,
        contract=case.contract,
        receipt=case.receipt,
        plugin_identity=case.identity,
        runtime_lock=runtime_b.lock,
        artifact_resolver=case.store,
        result_id=case.result.result_id,
    )
    mapping = case.result.to_dict()
    mapping["artifacts"] = [issued_ref.to_dict()]
    mapping["provenance"]["evaluator_sha256"] = runtime_b.lock.evaluator_sha256
    mapping["provenance"]["config_sha256"] = runtime_b.lock.config_sha256

    with pytest.raises(EvaluationIntegrityError):
        freeze_evaluation_result(mapping, binding=binding_b)


def test_result_artifacts_are_unique_and_canonically_ordered(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    sink = case.store.scope(
        request_id=case.request.request_id,
        produced_by_event_id="event.evaluation.synthetic",
        runtime_lock=case.runtime.lock,
    )
    refs = [
        sink.put(
            kind="q-arbor.aggregate-metrics.v1",
            media_type="application/json",
            content=content,
        )
        for content in (b'{"value":1}', b'{"value":2}')
    ]
    reverse = sorted(
        (ref.to_dict() for ref in refs),
        key=lambda item: (item["artifact_id"], item["relative_path"]),
        reverse=True,
    )
    mapping = case.result.to_dict()
    mapping["artifacts"] = reverse

    frozen = freeze_evaluation_result(mapping, binding=case.binding)
    assert [(ref.artifact_id, ref.relative_path) for ref in frozen.artifacts] == sorted(
        (ref.artifact_id, ref.relative_path) for ref in refs
    )
    with pytest.raises(EvaluationInvariantError):
        validate_evaluation_result(mapping, binding=case.binding)

    duplicate = case.result.to_dict()
    duplicate["artifacts"] = [refs[0].to_dict(), refs[0].to_dict()]
    with pytest.raises(EvaluationInvariantError):
        freeze_evaluation_result(duplicate, binding=case.binding)
