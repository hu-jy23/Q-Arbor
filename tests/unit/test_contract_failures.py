from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from q_arbor.contracts import (
    ContractError,
    ContractDecodeError,
    ContractHashMismatch,
    ContractInvariantError,
    ContractSchemaError,
    QuantResearchContract,
    canonical_contract_bytes,
    compute_contract_hash,
    freeze_contract,
    load_contract,
    validate_contract,
)
from tests.helpers import (
    contract_fixture,
    expected_contract_hash,
    valid_contract_mapping,
)


def _frozen_contract_mapping() -> dict[str, Any]:
    return freeze_contract(valid_contract_mapping()).to_dict()


@pytest.mark.parametrize(
    "error_type",
    [
        ContractDecodeError,
        ContractSchemaError,
        ContractInvariantError,
        ContractHashMismatch,
    ],
)
def test_public_errors_share_the_contract_error_base(
    error_type: type[Exception],
) -> None:
    assert issubclass(error_type, ContractError)


def test_complete_contract_freeze_load_and_hash_round_trip(tmp_path: Path) -> None:
    draft = valid_contract_mapping()
    expected_hash = expected_contract_hash(draft)

    frozen = freeze_contract(draft)
    frozen_mapping = frozen.to_dict()
    reordered = dict(reversed(tuple(frozen_mapping.items())))

    assert isinstance(frozen, QuantResearchContract)
    assert "contract_hash" not in draft
    assert frozen.sha256 == expected_hash
    assert frozen_mapping["contract_hash"] == expected_hash
    assert compute_contract_hash(draft) == expected_hash
    assert compute_contract_hash(reordered) == expected_hash
    assert canonical_contract_bytes(reordered) == canonical_contract_bytes(frozen_mapping)
    assert json.loads(frozen.to_json()) == frozen_mapping
    assert frozen.to_json().encode("utf-8") == canonical_contract_bytes(frozen_mapping)

    snapshot = tmp_path / "frozen-contract.json"
    frozen.write(snapshot)
    loaded = load_contract(snapshot)

    assert snapshot.read_bytes() == canonical_contract_bytes(frozen_mapping)
    assert loaded.sha256 == frozen.sha256
    assert loaded.to_dict() == frozen.to_dict()
    assert canonical_contract_bytes(loaded.to_dict()) == canonical_contract_bytes(frozen_mapping)


def test_missing_required_field_is_rejected_before_hash_check() -> None:
    mapping = _frozen_contract_mapping()
    del mapping["metrics"]

    with pytest.raises(ContractSchemaError):
        validate_contract(mapping)


@pytest.mark.parametrize(
    "fixture_name",
    ["duplicate_key.json", "nonfinite_nan.json", "nonfinite_infinity.json"],
)
def test_strict_json_rejects_ambiguous_or_nonfinite_input(fixture_name: str) -> None:
    with pytest.raises(ContractDecodeError):
        load_contract(contract_fixture(fixture_name))


def test_nfc_equivalent_value_freezes_to_the_same_snapshot_and_hash() -> None:
    composed = valid_contract_mapping()
    decomposed = valid_contract_mapping()
    question = decomposed["objective"]["research_question"]
    decomposed["objective"]["research_question"] = unicodedata.normalize("NFD", question)
    assert decomposed["objective"]["research_question"] != question

    normalized = freeze_contract(decomposed)
    frozen_composed = freeze_contract(composed)

    assert normalized.sha256 == frozen_composed.sha256
    assert normalized.to_dict() == frozen_composed.to_dict()
    assert canonical_contract_bytes(decomposed) == canonical_contract_bytes(composed)


def test_nfc_normalization_induced_key_collision_is_rejected() -> None:
    with pytest.raises(ContractDecodeError):
        load_contract(contract_fixture("nfc_key_collision.json"))


def test_mapping_nfc_key_collision_is_rejected_before_schema_validation() -> None:
    mapping = valid_contract_mapping()
    mapping["metrics"]["hard_constraints"][0]["threshold"] = {
        "\N{LATIN SMALL LETTER E WITH ACUTE}": 1,
        "e\N{COMBINING ACUTE ACCENT}": 2,
    }

    with pytest.raises(ContractDecodeError):
        freeze_contract(mapping)


def test_wrong_embedded_hash_is_rejected(tmp_path: Path) -> None:
    mapping = freeze_contract(valid_contract_mapping()).to_dict()
    mapping["contract_hash"] = "f" * 64

    with pytest.raises(ContractHashMismatch):
        validate_contract(mapping)

    snapshot = tmp_path / "wrong-hash.json"
    snapshot.write_text(json.dumps(mapping), encoding="utf-8")
    with pytest.raises(ContractHashMismatch):
        load_contract(snapshot)


@pytest.mark.parametrize(
    ("split_name", "start", "end"),
    [
        ("development", "2020-12-31T00:00:00Z", "2020-01-01T00:00:00Z"),
        ("gate", "2021-12-31T00:00:00Z", "2021-01-01T00:00:00Z"),
        ("final", "2022-12-31T00:00:00Z", "2022-01-01T00:00:00Z"),
    ],
)
def test_split_time_range_must_be_forward(
    split_name: str, start: str, end: str
) -> None:
    mapping = _frozen_contract_mapping()
    time_range = mapping["data"]["splits"][split_name]["time_range"]
    time_range.update(start=start, end=end)

    with pytest.raises(ContractInvariantError):
        validate_contract(mapping)


@pytest.mark.parametrize(
    ("earlier", "later"),
    [("development", "gate"), ("gate", "final")],
)
def test_adjacent_splits_must_not_overlap(earlier: str, later: str) -> None:
    mapping = _frozen_contract_mapping()
    earlier_range = mapping["data"]["splits"][earlier]["time_range"]
    later_range = mapping["data"]["splits"][later]["time_range"]
    later_range["start"] = earlier_range["end"]

    with pytest.raises(ContractInvariantError):
        validate_contract(mapping)


def test_every_split_requires_an_explicit_time_range() -> None:
    mapping = _frozen_contract_mapping()
    del mapping["data"]["splits"]["gate"]["time_range"]

    with pytest.raises(ContractInvariantError):
        validate_contract(mapping)


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "/absolute/candidate.py",
        "strategies/../data/candidate.py",
        "strategies\\candidate.py",
    ],
)
def test_unsafe_paths_are_rejected_by_the_frozen_schema(unsafe_path: str) -> None:
    mapping = _frozen_contract_mapping()
    mapping["editable_surface"] = [unsafe_path]

    with pytest.raises(ContractSchemaError):
        validate_contract(mapping)


@pytest.mark.parametrize("protected", ["strategies/**", "strategies/private/**"])
def test_editable_and_protected_globs_must_be_disjoint(protected: str) -> None:
    mapping = _frozen_contract_mapping()
    mapping["protected_paths"].append(protected)

    with pytest.raises(ContractInvariantError):
        validate_contract(mapping)


@pytest.mark.parametrize(
    ("role_field", "roles"),
    [
        ("executor_roles", ["gate"]),
        ("coordinator_roles", ["development"]),
        ("finalizer_roles", ["development"]),
    ],
)
def test_capability_role_sets_are_exact(role_field: str, roles: list[str]) -> None:
    mapping = _frozen_contract_mapping()
    mapping["capabilities"][role_field] = roles

    with pytest.raises(ContractSchemaError):
        validate_contract(mapping)


def test_split_role_must_match_its_named_slot() -> None:
    mapping = _frozen_contract_mapping()
    mapping["data"]["splits"]["gate"]["role"] = "development"

    with pytest.raises(ContractInvariantError):
        validate_contract(mapping)


@pytest.mark.parametrize(("field", "value"), [("sealed", False), ("query_budget", 2)])
def test_final_split_is_sealed_and_single_query(field: str, value: object) -> None:
    mapping = _frozen_contract_mapping()
    mapping["data"]["splits"]["final"][field] = value

    with pytest.raises(ContractInvariantError):
        validate_contract(mapping)


def test_global_final_budget_is_exactly_one() -> None:
    mapping = _frozen_contract_mapping()
    mapping["budgets"]["max_final_queries"] = 2

    with pytest.raises(ContractSchemaError):
        validate_contract(mapping)


def test_secret_like_field_is_rejected_inside_schema_open_content() -> None:
    mapping = _frozen_contract_mapping()
    mapping["metrics"]["hard_constraints"][0]["threshold"] = {
        "api_token": "synthetic-placeholder"
    }

    with pytest.raises(ContractInvariantError):
        validate_contract(mapping)


def test_invalid_metric_direction_is_rejected() -> None:
    mapping = _frozen_contract_mapping()
    mapping["metrics"]["primary"]["direction"] = "sideways"

    with pytest.raises(ContractSchemaError):
        validate_contract(mapping)


@pytest.mark.parametrize(
    ("section", "field"),
    [
        (None, "contract_id"),
        (None, "task_id"),
        ("development", "dataset_id"),
    ],
)
def test_identity_fields_reject_non_identifiers(section: str | None, field: str) -> None:
    mapping = _frozen_contract_mapping()
    target = mapping if section is None else mapping["data"]["splits"][section]
    target[field] = "contains spaces"

    with pytest.raises(ContractSchemaError):
        validate_contract(mapping)


def test_primary_and_diagnostic_metric_names_must_be_distinct() -> None:
    mapping = _frozen_contract_mapping()
    mapping["metrics"]["diagnostics"][0]["name"] = mapping["metrics"]["primary"]["name"]

    with pytest.raises(ContractInvariantError):
        validate_contract(mapping)


def test_frozen_snapshot_is_deeply_isolated_from_mutable_mappings() -> None:
    source = valid_contract_mapping()
    frozen = freeze_contract(source)
    original_json = frozen.to_json()

    source["objective"]["research_question"] = "mutated source"
    source["editable_surface"].append("outside/**")
    exported = frozen.to_dict()
    exported["objective"]["research_question"] = "mutated export"
    exported["data"]["splits"]["final"]["sealed"] = False
    exported["statistical_plan"][0]["required_assumptions"].clear()

    assert frozen.to_json() == original_json
    assert frozen.to_dict() == freeze_contract(valid_contract_mapping()).to_dict()
    assert frozen.to_dict() is not frozen.to_dict()
    assert frozen.to_dict()["data"] is not frozen.to_dict()["data"]
    with pytest.raises((AttributeError, TypeError)):
        frozen.sha256 = "0" * 64  # type: ignore[misc]
