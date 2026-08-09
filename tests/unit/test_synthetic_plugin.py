from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from q_arbor.contracts import freeze_contract
from q_arbor.evaluation import (
    ContentAddressedArtifactStore,
    EvaluationBoundaryError,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    QuantTaskPlugin,
    ValidatedCandidate,
    freeze_evaluation_result,
)
from q_arbor.plugins.synthetic import (
    SyntheticSignalPlugin,
    canonical_synthetic_candidate,
    make_synthetic_development_split,
    synthetic_contract_draft,
    synthetic_fixture_identities,
)
from tests.evaluation_helpers import (
    REPOSITORY_ROOT,
    bind_validation,
    directory_entries,
    fixture_bytes,
    invalid_synthetic_case,
    make_request,
    materialize_candidate,
    runtime_fixture,
    synthetic_case,
    synthetic_contract,
    synthetic_identity,
    validated_synthetic_components,
)


def _metric_values(fold: object) -> dict[str, float | int | None]:
    return {metric.name: metric.value for metric in fold["metrics"]}  # type: ignore[index,union-attr]


def test_synthetic_public_fixture_identities_are_exact_closed_opaque_hashes() -> None:
    identities = synthetic_fixture_identities()
    expected_keys = {
        "data_snapshot_sha256",
        "data_schema_sha256",
        "development_manifest_sha256",
        "gate_manifest_sha256",
        "final_manifest_sha256",
        "cost_model_sha256",
    }

    assert set(identities) == expected_keys
    assert all(
        len(value) == 64 and value == value.lower() and int(value, 16) >= 0
        for value in identities.values()
    )
    assert (
        len(
            {
                identities["development_manifest_sha256"],
                identities["gate_manifest_sha256"],
                identities["final_manifest_sha256"],
            }
        )
        == 3
    )
    assert all("/" not in value and "\\" not in value for value in identities.values())


def test_synthetic_contract_helper_is_c7_valid_and_keeps_final_sealed() -> None:
    identity = synthetic_identity()
    draft = synthetic_contract_draft(
        plugin_identity=identity,
        baseline_ref="baseline/main@0123456789abcdef",
    )
    contract = synthetic_contract(identity)
    mapping = contract.to_dict()
    identities = synthetic_fixture_identities()

    assert "contract_hash" not in draft
    assert mapping["task_kind"] == "synthetic_factor"
    assert mapping["plugin"] == identity.to_dict()
    assert mapping["data"]["snapshot_sha256"] == identities["data_snapshot_sha256"]
    assert mapping["data"]["schema_sha256"] == identities["data_schema_sha256"]
    for role in ("development", "gate", "final"):
        assert (
            mapping["data"]["splits"][role]["manifest_sha256"]
            == identities[f"{role}_manifest_sha256"]
        )
    assert mapping["data"]["splits"]["final"]["sealed"] is True
    assert mapping["data"]["splits"]["final"]["query_budget"] == 1


@pytest.mark.parametrize("column", ["null_signal", "planted_signal"])
def test_canonical_synthetic_candidate_has_exact_closed_shape(column: str) -> None:
    payload = canonical_synthetic_candidate(signal_column=column)

    assert payload == fixture_bytes(
        f"synthetic_{column.removesuffix('_signal')}_candidate.json"
    ).rstrip(b"\n")
    assert json.loads(payload) == {
        "schema_version": "1.0",
        "kind": "signal",
        "signal_column": column,
    }


@pytest.mark.parametrize(
    "column",
    ["forward_return", "unknown_signal", "development", "gate", "final", "../x"],
)
def test_synthetic_candidate_factory_rejects_every_nonfixture_column(
    column: str,
) -> None:
    with pytest.raises(EvaluationInvariantError):
        canonical_synthetic_candidate(signal_column=column)


@pytest.mark.parametrize(
    "fixture_name",
    ["synthetic_unknown_field_candidate.json", "synthetic_label_leak_candidate.json"],
)
def test_unknown_and_future_label_candidates_are_invalid_before_split(
    tmp_path: Path, fixture_name: str
) -> None:
    plugin, _, _, candidate, receipt = invalid_synthetic_case(
        tmp_path / "case",
        fixture_name=fixture_name,
    )

    assert receipt.status == "invalid_candidate"
    assert receipt.validation.canonical_form_sha256 is None
    assert receipt.validation.failure.failure_type == "invalid_candidate"
    assert candidate.artifact.sha256 == hashlib.sha256(candidate.payload).hexdigest()
    assert isinstance(plugin, QuantTaskPlugin)


def test_semantically_equal_candidate_encodings_share_only_canonical_form(
    tmp_path: Path,
) -> None:
    identity = synthetic_identity()
    plugin = SyntheticSignalPlugin.create(identity)
    contract = synthetic_contract(identity)
    canonical = canonical_synthetic_candidate(signal_column="planted_signal")
    shuffled = (
        b'{"signal_column":"planted_signal","kind":"signal","schema_version":"1.0"}'
    )
    first = materialize_candidate(tmp_path / "first", contract, canonical)
    second = materialize_candidate(tmp_path / "second", contract, shuffled)
    first_validation = plugin.validate(first, contract)
    second_validation = plugin.validate(second, contract)

    assert first_validation.status == second_validation.status == "valid"
    assert [item.name for item in first_validation.checks] == [
        "candidate.kind",
        "candidate.surface",
        "synthetic.payload",
    ]
    assert first.artifact.sha256 != second.artifact.sha256
    assert first.candidate_hash != second.candidate_hash
    assert (
        first_validation.canonical_form_sha256
        == second_validation.canonical_form_sha256
    )
    assert first_validation.canonical_form_sha256 not in {
        first.artifact.sha256,
        first.candidate_hash,
    }
    assert first_validation.family_evidence.evidence_sha256 == (
        second_validation.family_evidence.evidence_sha256
    )


@pytest.mark.parametrize(
    (
        "column",
        "primary",
        "fold_primary",
        "gross",
        "turnover",
        "transaction_cost",
    ),
    [
        ("null_signal", -0.00075, [-0.00075, -0.00075], 0.0, 0.75, 0.00075),
        ("planted_signal", 0.02075, [0.01825, 0.02325], 0.0225, 1.75, 0.00175),
    ],
)
def test_synthetic_known_truth_is_exact_and_complete(
    tmp_path: Path,
    column: str,
    primary: float,
    fold_primary: list[float],
    gross: float,
    turnover: float,
    transaction_cost: float,
) -> None:
    case = synthetic_case(tmp_path / "case", signal_column=column)
    result = case.result

    assert isinstance(case.plugin, QuantTaskPlugin)
    assert isinstance(case.receipt, ValidatedCandidate)
    assert result.status == "success"
    assert result.primary_metric.value == primary
    assert [fold["fold_id"] for fold in result.fold_metrics] == ["fold.a", "fold.b"]
    assert [
        _metric_values(fold)[result.primary_metric.name] for fold in result.fold_metrics
    ] == fold_primary
    assert result.costs["gross"] == gross
    assert result.costs["turnover"] == turnover
    assert result.costs["transaction_cost"] == transaction_cost
    assert result.costs["net"] == primary
    assert result.diagnostics[0].value == turnover
    assert all(item.status == "pass" for item in result.constraints)
    assert all(item.status == "pass" for item in result.checks)
    assert result.failure is None
    assert result.statistical_diagnostics == ()


def test_zero_and_negative_success_are_preserved_without_truthiness_fallback(
    tmp_path: Path,
) -> None:
    negative = synthetic_case(tmp_path / "negative", signal_column="null_signal")
    assert negative.result.primary_metric.value == -0.00075
    assert negative.result.status == "success"

    zero_source = synthetic_case(tmp_path / "zero", signal_column="planted_signal")
    mapping = zero_source.result.to_dict()
    mapping["primary_metric"]["value"] = 0.0
    for fold in mapping["fold_metrics"]:
        for metric in fold["metrics"]:
            metric["value"] = 0.0
    for diagnostic in mapping["diagnostics"]:
        diagnostic["value"] = 0.0
    mapping["costs"].update(
        gross=0.0,
        transaction_cost=0.0,
        net=0.0,
        turnover=0.0,
    )
    zero = freeze_evaluation_result(mapping, binding=zero_source.binding)

    assert zero.status == "success"
    assert zero.primary_metric.value == 0.0


def test_synthetic_same_seed_and_id_are_byte_deterministic_across_roots(
    tmp_path: Path,
) -> None:
    first = synthetic_case(tmp_path / "first")
    second = synthetic_case(tmp_path / "second")

    assert first.result.to_json() == second.result.to_json()
    assert first.result.sha256 == second.result.sha256
    assert first.plugin.summarize(first.result) == second.plugin.summarize(
        second.result
    )


def test_seed_changes_only_provenance_identity_not_deterministic_score(
    tmp_path: Path,
) -> None:
    first = synthetic_case(tmp_path / "first", seed=7)
    second = synthetic_case(tmp_path / "second", seed=19)

    assert first.result.primary_metric == second.result.primary_metric
    assert first.result.provenance["seed"] == 7
    assert second.result.provenance["seed"] == 19
    assert first.result.sha256 != second.result.sha256


def test_synthetic_result_is_stable_across_bounded_process_environments(
    tmp_path: Path,
) -> None:
    script = """
from pathlib import Path
from tempfile import TemporaryDirectory
from tests.evaluation_helpers import synthetic_case
with TemporaryDirectory() as directory:
    print(synthetic_case(Path(directory)).result.to_json())
"""
    outputs: list[str] = []
    for hash_seed, timezone, locale in (
        ("1", "UTC", "C"),
        ("9187", "GMT-8", "C.UTF-8"),
    ):
        env = os.environ.copy()
        env.update(PYTHONHASHSEED=hash_seed, TZ=timezone, LC_ALL=locale)
        env["PYTHONPATH"] = os.pathsep.join(
            [str(REPOSITORY_ROOT / "src"), str(REPOSITORY_ROOT)]
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=REPOSITORY_ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert completed.returncode == 0, completed.stderr
        outputs.append(completed.stdout.strip())

    assert outputs[0] == outputs[1]


def test_plugin_inputs_and_frozen_result_do_not_share_mutable_state(
    tmp_path: Path,
) -> None:
    case = synthetic_case(tmp_path / "case")
    contract_mapping = case.contract.to_dict()
    result_before = case.result.to_json()
    contract_mapping["metrics"]["primary"]["name"] = "caller_changed"
    payload_copy = bytearray(case.candidate.payload)
    payload_copy[:] = b"{}"

    assert case.result.to_json() == result_before
    assert case.result.primary_metric.name != "caller_changed"
    assert case.candidate.payload != bytes(payload_copy)


@pytest.mark.parametrize("role", ["gate", "final"])
def test_synthetic_split_factory_rejects_gate_and_final_before_store_issuance(
    tmp_path: Path, role: str
) -> None:
    root = tmp_path / role
    plugin, _, contract, _, receipt = validated_synthetic_components(root)
    request = make_request(contract, receipt, split_role=role)
    runtime = runtime_fixture(root, contract)
    store_root = root / "store"
    store = ContentAddressedArtifactStore.create(store_root)
    before = directory_entries(store_root)

    with pytest.raises(EvaluationBoundaryError):
        make_synthetic_development_split(
            request,
            contract,
            receipt,
            plugin,
            runtime.lock,
            result_id=f"result.synthetic.{role}",
            evaluation_seed=7,
            artifact_store=store,
            produced_by_event_id=f"event.synthetic.{role}",
        )

    assert directory_entries(store_root) == before


@pytest.mark.parametrize(
    "variant",
    [
        "constraint_operator",
        "constraint_threshold",
        "development_time_range",
        "cost_rule",
        "primary_aggregation",
    ],
)
def test_synthetic_factory_rejects_computation_contract_variants_before_issuance(
    tmp_path: Path,
    variant: str,
) -> None:
    root = tmp_path / variant
    identity = synthetic_identity()
    plugin = SyntheticSignalPlugin.create(identity)
    draft = cast(
        dict[str, Any],
        synthetic_contract_draft(
            plugin_identity=identity,
            baseline_ref="baseline/main@0123456789abcdef",
        ),
    )
    if variant == "constraint_operator":
        draft["metrics"]["hard_constraints"][0]["operator"] = "ge"
    elif variant == "constraint_threshold":
        draft["metrics"]["hard_constraints"][0]["threshold"] = 0.3
    elif variant == "development_time_range":
        draft["data"]["splits"]["development"]["time_range"]["start"] = (
            "2019-01-01T00:00:00Z"
        )
    elif variant == "cost_rule":
        draft["cost_model"]["components"][0]["rule"] = "0.002 per unit turnover"
    elif variant == "primary_aggregation":
        draft["metrics"]["primary"]["aggregation"] = "mean_across_folds"
    else:  # pragma: no cover - parametrization is closed above
        raise AssertionError("unknown synthetic contract variant")

    contract = freeze_contract(draft)
    candidate = materialize_candidate(
        root / "candidate",
        contract,
        fixture_bytes("synthetic_planted_candidate.json"),
    )
    validation = plugin.validate(candidate, contract)
    receipt = bind_validation(
        root,
        candidate=candidate,
        validation=validation,
        contract=contract,
        plugin_identity=identity,
    )
    assert isinstance(receipt, ValidatedCandidate)
    request = make_request(contract, receipt, split_role="development")
    runtime = runtime_fixture(root, contract)
    store_root = root / "store"
    store = ContentAddressedArtifactStore.create(store_root)
    before = directory_entries(store_root)

    with pytest.raises(
        EvaluationIntegrityError,
        match="synthetic computation contract mismatch",
    ):
        make_synthetic_development_split(
            request,
            contract,
            receipt,
            plugin,
            runtime.lock,
            result_id=f"result.synthetic.variant.{variant}",
            evaluation_seed=7,
            artifact_store=store,
            produced_by_event_id=f"event.synthetic.variant.{variant}",
        )

    assert directory_entries(store_root) == before


def test_synthetic_factory_does_not_pin_noncomputation_contract_fields(
    tmp_path: Path,
) -> None:
    root = tmp_path / "noncomputation"
    identity = synthetic_identity()
    plugin = SyntheticSignalPlugin.create(identity)
    draft = cast(
        dict[str, Any],
        synthetic_contract_draft(
            plugin_identity=identity,
            baseline_ref="baseline/main@0123456789abcdef",
        ),
    )
    draft["objective"]["baseline_ref"] = "baseline/alternate@fedcba9876543210"
    draft["objective"]["research_question"] = "Alternate public smoke question"
    draft["budgets"]["max_nodes"] = 9
    contract = freeze_contract(draft)
    candidate = materialize_candidate(
        root / "candidate",
        contract,
        fixture_bytes("synthetic_planted_candidate.json"),
    )
    validation = plugin.validate(candidate, contract)
    receipt = bind_validation(
        root,
        candidate=candidate,
        validation=validation,
        contract=contract,
        plugin_identity=identity,
    )
    assert isinstance(receipt, ValidatedCandidate)
    request = make_request(contract, receipt, split_role="development")
    runtime = runtime_fixture(root, contract)
    store = ContentAddressedArtifactStore.create(root / "store")

    split = make_synthetic_development_split(
        request,
        contract,
        receipt,
        plugin,
        runtime.lock,
        result_id="result.synthetic.noncomputation",
        evaluation_seed=7,
        artifact_store=store,
        produced_by_event_id="event.synthetic.noncomputation",
    )

    assert plugin.evaluate(receipt, split).status == "success"
