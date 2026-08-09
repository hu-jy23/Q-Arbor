from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from q_arbor.evaluation import (
    ContentAddressedArtifactStore,
    EvaluationBoundaryError,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationSchemaError,
    QuantTaskPlugin,
)
from q_arbor.plugins.formula_alpha import (
    FormulaAlphaPlugin,
    FormulaMockOutcome,
    PublicFormulaSchema,
)
from q_arbor.plugins.formula_alpha.testing import (
    make_formula_alpha_mock_development_split,
)

from q_arbor.contracts import freeze_contract
from tests.evaluation_helpers import (
    bind_validation,
    diagnostic_check_name,
    directory_entries,
    fixture_bytes,
    formula_case,
    formula_contract,
    formula_identity,
    make_request,
    materialize_candidate,
    public_formula_schema,
    runtime_fixture,
)
from tests.hypothesis_helpers import canonical_json


def _formula_payload(expression: dict[str, Any]) -> bytes:
    return canonical_json({"schema_version": "1.0", "expression": expression}).encode(
        "utf-8"
    )


def _validate_formula(tmp_path: Path, expression: dict[str, Any]) -> Any:
    identity = formula_identity()
    schema = public_formula_schema()
    plugin = FormulaAlphaPlugin.create(identity, schema)
    contract = formula_contract(identity, schema)
    candidate = materialize_candidate(
        tmp_path,
        contract,
        _formula_payload(expression),
    )
    return plugin.validate(candidate, contract)


def _unary_expression(nodes: int) -> dict[str, Any]:
    expression: dict[str, Any] = {"op": "field", "name": "close"}
    for _ in range(nodes - 1):
        expression = {"op": "neg", "arg": expression}
    return expression


def _full_binary_expression(depth: int) -> dict[str, Any]:
    if depth == 1:
        return {"op": "field", "name": "close"}
    child = _full_binary_expression(depth - 1)
    return {"op": "add", "left": child, "right": json.loads(json.dumps(child))}


def test_public_formula_schema_is_closed_sorted_immutable_and_hashable() -> None:
    mapping = {
        "schema_version": "1.0",
        "fields": [
            {"name": "close", "dtype": "float64"},
            {"name": "volume", "dtype": "float64"},
        ],
    }
    schema = PublicFormulaSchema.from_mapping(mapping)
    mapping["fields"][0]["name"] = "mutated"

    assert schema.to_dict()["fields"][0]["name"] == "close"
    assert schema.to_json() == canonical_json(schema.to_dict())
    assert len(schema.sha256) == 64
    with pytest.raises(TypeError):
        schema.fields[0]["name"] = "mutated"  # type: ignore[index]


@pytest.mark.parametrize(
    ("mapping", "expected_error"),
    [
        (
            {
                "schema_version": "1.0",
                "fields": [
                    {"name": "volume", "dtype": "float64"},
                    {"name": "close", "dtype": "float64"},
                ],
            },
            EvaluationInvariantError,
        ),
        (
            {
                "schema_version": "1.0",
                "fields": [
                    {"name": "close", "dtype": "float64"},
                    {"name": "close", "dtype": "float32"},
                ],
            },
            EvaluationInvariantError,
        ),
        (
            {
                "schema_version": "1.0",
                "fields": [{"name": "close", "dtype": "float64", "extra": 1}],
            },
            EvaluationSchemaError,
        ),
        (
            {"schema_version": "2.0", "fields": []},
            EvaluationSchemaError,
        ),
    ],
)
def test_public_formula_schema_rejects_ambiguity(
    mapping: dict[str, Any], expected_error: type[Exception]
) -> None:
    with pytest.raises(expected_error):
        PublicFormulaSchema.from_mapping(mapping)


@pytest.mark.parametrize(
    "expression",
    [
        {"op": "field", "name": "close"},
        {"op": "constant", "value": -1.25},
        {"op": "lag", "periods": 1, "arg": {"op": "field", "name": "volume"}},
        {"op": "lag", "periods": 252, "arg": {"op": "field", "name": "close"}},
        {"op": "neg", "arg": {"op": "field", "name": "close"}},
        {
            "op": "add",
            "left": {"op": "field", "name": "close"},
            "right": {"op": "constant", "value": 1},
        },
        {
            "op": "sub",
            "left": {"op": "field", "name": "close"},
            "right": {"op": "field", "name": "volume"},
        },
        {
            "op": "mul",
            "left": {"op": "constant", "value": 2},
            "right": {"op": "field", "name": "close"},
        },
        {
            "op": "div",
            "left": {"op": "field", "name": "close"},
            "right": {"op": "constant", "value": 2},
        },
        _unary_expression(16),
        _full_binary_expression(8),
        {"op": "neg", "arg": _full_binary_expression(8)},
    ],
)
def test_formula_closed_grammar_accepts_only_declared_public_expressions(
    tmp_path: Path, expression: dict[str, Any]
) -> None:
    validation = _validate_formula(tmp_path, expression)

    assert validation.status == "valid"
    assert validation.canonical_form_sha256 is not None
    assert [item.name for item in validation.checks] == [
        "candidate.kind",
        "formula.expression",
        "formula.public_schema",
    ]


@pytest.mark.parametrize(
    "expression",
    [
        {"op": "field", "name": "future_return"},
        {"op": "constant", "value": True},
        {"op": "lag", "periods": 0, "arg": {"op": "field", "name": "close"}},
        {"op": "lag", "periods": 253, "arg": {"op": "field", "name": "close"}},
        {"op": "mean", "arg": {"op": "field", "name": "close"}},
        {"op": "field", "name": "close", "extra": "forbidden"},
        {"op": "add", "left": {"op": "field", "name": "close"}},
        _unary_expression(17),
        {"op": "neg", "arg": {"op": "neg", "arg": _full_binary_expression(8)}},
    ],
)
def test_formula_closed_grammar_rejects_unknown_fields_operators_and_bounds(
    tmp_path: Path, expression: dict[str, Any]
) -> None:
    validation = _validate_formula(tmp_path, expression)

    assert validation.status == "invalid_candidate"
    assert validation.failure.failure_type == "invalid_candidate"
    assert validation.canonical_form_sha256 is None


@pytest.mark.parametrize("literal", [b"NaN", b"Infinity", b"-Infinity"])
def test_formula_candidate_nonfinite_literal_is_invalid_not_parsed_as_a_score(
    tmp_path: Path, literal: bytes
) -> None:
    identity = formula_identity()
    schema = public_formula_schema()
    plugin = FormulaAlphaPlugin.create(identity, schema)
    contract = formula_contract(identity, schema)
    payload = (
        b'{"expression":{"op":"constant","value":'
        + literal
        + b'},"schema_version":"1.0"}'
    )
    candidate = materialize_candidate(tmp_path, contract, payload)

    validation = plugin.validate(candidate, contract)

    assert validation.status == "invalid_candidate"
    assert validation.canonical_form_sha256 is None


def test_formula_key_order_changes_bytes_but_not_canonical_form(tmp_path: Path) -> None:
    identity = formula_identity()
    schema = public_formula_schema()
    plugin = FormulaAlphaPlugin.create(identity, schema)
    contract = formula_contract(identity, schema)
    canonical = fixture_bytes("formula_minimal_candidate.json").rstrip(b"\n")
    shuffled = b'{"schema_version":"1.0","expression":{"op":"field","name":"close"}}'
    first = materialize_candidate(tmp_path / "first", contract, canonical)
    second = materialize_candidate(tmp_path / "second", contract, shuffled)
    first_validation = plugin.validate(first, contract)
    second_validation = plugin.validate(second, contract)

    assert first.artifact.sha256 != second.artifact.sha256
    assert first.candidate_hash != second.candidate_hash
    assert first_validation.canonical_form_sha256 == (
        second_validation.canonical_form_sha256
    )


def test_formula_public_schema_hash_is_bound_before_validation(tmp_path: Path) -> None:
    identity = formula_identity()
    schema = public_formula_schema()
    plugin = FormulaAlphaPlugin.create(identity, schema)
    contract_mapping = formula_contract(identity, schema).to_dict()
    contract_mapping.pop("contract_hash")
    contract_mapping["data"]["schema_sha256"] = "f" * 64
    mismatched_contract = freeze_contract(contract_mapping)
    candidate = materialize_candidate(
        tmp_path,
        mismatched_contract,
        fixture_bytes("formula_minimal_candidate.json"),
    )

    with pytest.raises(EvaluationIntegrityError):
        plugin.validate(candidate, mismatched_contract)


@pytest.mark.parametrize(
    ("outcome", "status", "failure_type", "failure_code"),
    [
        (
            FormulaMockOutcome.BACKEND_UNAVAILABLE,
            "implementation_failure",
            "implementation_failure",
            "formula.backend_unavailable",
        ),
        (
            FormulaMockOutcome.SCHEMA_INCOMPATIBLE,
            "incomparable",
            "incomparable",
            "formula.schema_incompatible",
        ),
    ],
)
def test_formula_mock_has_only_two_closed_scoreless_outcomes(
    tmp_path: Path,
    outcome: FormulaMockOutcome,
    status: str,
    failure_type: str,
    failure_code: str,
) -> None:
    case = formula_case(tmp_path / "case", outcome=outcome)

    assert isinstance(case.plugin, QuantTaskPlugin)
    assert case.result.status == status
    assert case.result.failure.failure_type == failure_type
    assert case.result.failure.summary == failure_code
    assert case.result.primary_metric.value is None
    assert case.result.fold_metrics == ()
    assert case.result.artifacts == ()
    assert case.result.statistical_diagnostics == ()
    assert {item.value for item in case.result.diagnostics} == {None}
    checks = {item.name: item.status for item in case.result.checks}
    assert all(
        checks[diagnostic_check_name(item.name)] == "not_observed"
        for item in case.result.diagnostics
    )
    assert case.plugin.summarize(case.result).primary_metric.value is None
    assert set(FormulaMockOutcome) == {
        FormulaMockOutcome.BACKEND_UNAVAILABLE,
        FormulaMockOutcome.SCHEMA_INCOMPATIBLE,
    }


@pytest.mark.parametrize("role", ["gate", "final"])
def test_formula_mock_factory_rejects_gate_and_final_before_store_issuance(
    tmp_path: Path, role: str
) -> None:
    root = tmp_path / role
    identity = formula_identity()
    schema = public_formula_schema()
    plugin = FormulaAlphaPlugin.create(identity, schema)
    contract = formula_contract(identity, schema)
    candidate = materialize_candidate(
        root / "candidate",
        contract,
        fixture_bytes("formula_minimal_candidate.json"),
    )
    validation = plugin.validate(candidate, contract)
    receipt = bind_validation(
        root,
        candidate=candidate,
        validation=validation,
        contract=contract,
        plugin_identity=identity,
    )
    request = make_request(contract, receipt, split_role=role)
    runtime = runtime_fixture(root, contract, aggregate_only=True)
    store_root = root / "store"
    store = ContentAddressedArtifactStore.create(store_root)
    before = directory_entries(store_root)

    with pytest.raises(EvaluationBoundaryError):
        make_formula_alpha_mock_development_split(
            request,
            contract,
            receipt,
            plugin,
            runtime.lock,
            result_id=f"result.formula.{role}",
            evaluation_seed=7,
            artifact_store=store,
            produced_by_event_id=f"event.formula.{role}",
            outcome=FormulaMockOutcome.BACKEND_UNAVAILABLE,
        )

    assert directory_entries(store_root) == before
