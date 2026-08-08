from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from q_arbor.contracts import (
    ContractDecodeError,
    ContractError,
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


def _replace_at_path(
    mapping: dict[str, Any], path: tuple[str, ...], value: object
) -> None:
    target: dict[str, Any] = mapping
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value


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
    assert canonical_contract_bytes(reordered) == canonical_contract_bytes(
        frozen_mapping
    )
    assert json.loads(frozen.to_json()) == frozen_mapping
    assert frozen.to_json().encode("utf-8") == canonical_contract_bytes(frozen_mapping)

    snapshot = tmp_path / "frozen-contract.json"
    frozen.write(snapshot)
    loaded = load_contract(snapshot)

    assert snapshot.read_bytes() == canonical_contract_bytes(frozen_mapping)
    assert loaded.sha256 == frozen.sha256
    assert loaded.to_dict() == frozen.to_dict()
    assert canonical_contract_bytes(loaded.to_dict()) == canonical_contract_bytes(
        frozen_mapping
    )


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
    decomposed["objective"]["research_question"] = unicodedata.normalize(
        "NFD", question
    )
    assert decomposed["objective"]["research_question"] != question

    normalized = freeze_contract(decomposed)
    frozen_composed = freeze_contract(composed)

    assert normalized.sha256 == frozen_composed.sha256
    assert normalized.to_dict() == frozen_composed.to_dict()
    assert canonical_contract_bytes(decomposed) == canonical_contract_bytes(composed)


def test_nfc_normalization_induced_key_collision_is_rejected() -> None:
    with pytest.raises(ContractDecodeError):
        load_contract(contract_fixture("nfc_key_collision.json"))


def test_deep_raw_json_is_rejected_as_a_decode_error(tmp_path: Path) -> None:
    text = json.dumps(valid_contract_mapping(), ensure_ascii=False)
    needle = '"threshold": 0.2'
    assert needle in text
    source = tmp_path / "deep.json"
    source.write_text(
        text.replace(needle, f'"threshold": {"[" * 2000}0{"]" * 2000}', 1),
        encoding="utf-8",
    )

    with pytest.raises(ContractDecodeError):
        load_contract(source)


def test_deep_mapping_is_rejected_at_normalization_boundaries() -> None:
    nested: Any = 0
    for _ in range(2000):
        nested = [nested]
    mapping = valid_contract_mapping()
    mapping["metrics"]["hard_constraints"][0]["threshold"] = nested

    with pytest.raises(ContractDecodeError):
        freeze_contract(mapping)
    with pytest.raises(ContractDecodeError):
        canonical_contract_bytes({"nested": nested})


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
    "boundary",
    ["0001-01-01T00:00:00+23:59", "9999-12-31T23:59:59-23:59"],
)
def test_timezone_normalization_overflow_stays_inside_typed_boundary(
    boundary: str,
) -> None:
    mapping = valid_contract_mapping()
    mapping["data"]["splits"]["development"]["time_range"]["start"] = boundary

    with pytest.raises(ContractInvariantError):
        freeze_contract(mapping)


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


@pytest.mark.parametrize(
    "oversized_path",
    [
        "a" * 256,
        "界" * 86,
        "/".join("a" for _ in range(2050)),
    ],
)
def test_paths_respect_git_and_filesystem_byte_limits(oversized_path: str) -> None:
    mapping = valid_contract_mapping()
    mapping["editable_surface"] = [oversized_path]

    with pytest.raises(ContractInvariantError):
        freeze_contract(mapping)


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


@pytest.mark.parametrize(
    "threshold",
    [
        {"final_path": "/restricted/final.csv"},
        {"extension": {"data_uri": "s3://restricted/gate.parquet"}},
        {"nested": [{"dataset": {"location": "file:///sealed/final.arrow"}}]},
    ],
)
def test_threshold_cannot_smuggle_nested_split_locators(threshold: object) -> None:
    mapping = valid_contract_mapping()
    mapping["metrics"]["hard_constraints"][0]["threshold"] = threshold

    with pytest.raises(ContractInvariantError):
        freeze_contract(mapping)


@pytest.mark.parametrize(
    ("operator", "threshold"),
    [
        ("eq", "/restricted/final.csv"),
        ("eq", "restricted/final"),
        ("eq", "s3://restricted/gate.parquet"),
        ("in", ["development", "file:///sealed/final.arrow"]),
    ],
)
def test_threshold_scalar_values_cannot_be_data_locators(
    operator: str, threshold: object
) -> None:
    mapping = valid_contract_mapping()
    constraint = mapping["metrics"]["hard_constraints"][0]
    constraint.update(operator=operator, threshold=threshold)

    with pytest.raises(ContractInvariantError):
        freeze_contract(mapping)


@pytest.mark.parametrize(
    ("operator", "threshold"),
    [
        ("le", 0.2),
        ("eq", "risk_off"),
        ("in", ["low", "medium", "high"]),
    ],
)
def test_threshold_keeps_scalar_statistical_semantics(
    operator: str, threshold: object
) -> None:
    mapping = valid_contract_mapping()
    constraint = mapping["metrics"]["hard_constraints"][0]
    constraint.update(operator=operator, threshold=threshold)

    assert (
        freeze_contract(mapping).to_dict()["metrics"]["hard_constraints"][0][
            "threshold"
        ]
        == threshold
    )


@pytest.mark.parametrize(
    "required_output",
    ["strategies/*.json", "strategies/candidate?.json", "strategies/[ab].json"],
)
def test_required_outputs_must_be_literal_git_paths(required_output: str) -> None:
    mapping = valid_contract_mapping()
    mapping["required_outputs"] = [required_output]

    with pytest.raises(ContractInvariantError):
        freeze_contract(mapping)


def test_required_output_must_be_inside_candidate_editable_surface() -> None:
    mapping = valid_contract_mapping()
    mapping["editable_surface"] = ["strategies/**"]
    # A pre-existing uneditable file would satisfy Arbor's existence-only guard.
    mapping["required_outputs"] = ["reports/result.json"]

    with pytest.raises(ContractInvariantError):
        freeze_contract(mapping)


def test_path_overlap_uses_arbor_full_path_fnmatch_semantics() -> None:
    mapping = valid_contract_mapping()
    mapping["editable_surface"] = ["models/*.py"]
    mapping["protected_paths"] = ["models/private/*.py"]
    mapping["required_outputs"] = []

    # Python/Arbor fnmatch lets '*' consume '/', so the patterns share a witness.
    with pytest.raises(ContractInvariantError):
        freeze_contract(mapping)


@pytest.mark.parametrize("split_name", ["development", "gate", "final"])
@pytest.mark.parametrize(
    "dataset_id",
    [
        "restricted/final.csv",
        "file:final.csv",
        "C:/restricted/final.csv",
        "C:restricted.csv",
    ],
)
def test_split_dataset_ids_are_opaque_non_locating_identifiers(
    split_name: str, dataset_id: str
) -> None:
    mapping = valid_contract_mapping()
    mapping["data"]["splits"][split_name]["dataset_id"] = dataset_id

    with pytest.raises(ContractInvariantError):
        freeze_contract(mapping)


@pytest.mark.parametrize(
    "snapshot_id",
    [
        "restricted/final.csv",
        "file:/restricted/final.csv",
        "C:restricted.csv",
    ],
)
def test_snapshot_id_is_an_opaque_non_locating_identifier(snapshot_id: str) -> None:
    mapping = valid_contract_mapping()
    mapping["data"]["snapshot_id"] = snapshot_id

    with pytest.raises(ContractInvariantError):
        freeze_contract(mapping)


def test_data_identifiers_keep_dotted_and_hyphenated_labels() -> None:
    mapping = valid_contract_mapping()
    mapping["data"]["snapshot_id"] = "vendor.snapshot-2026.08"
    for split_name, split in mapping["data"]["splits"].items():
        split["dataset_id"] = f"vendor-{split_name}.v1"

    frozen = freeze_contract(mapping).to_dict()

    assert frozen["data"]["snapshot_id"] == "vendor.snapshot-2026.08"


def test_data_identifiers_accept_nonlocating_urn_labels() -> None:
    mapping = valid_contract_mapping()
    mapping["data"]["snapshot_id"] = "urn:vendor:snapshot:v1"
    for split_name, split in mapping["data"]["splits"].items():
        split["dataset_id"] = f"urn:vendor:{split_name}:v1"

    frozen = freeze_contract(mapping).to_dict()

    assert frozen["data"]["snapshot_id"] == "urn:vendor:snapshot:v1"


@pytest.mark.parametrize(
    ("left_split", "right_split"),
    [
        ("development", "gate"),
        ("development", "final"),
        ("gate", "final"),
    ],
)
def test_split_manifest_hashes_are_pairwise_distinct(
    left_split: str, right_split: str
) -> None:
    mapping = valid_contract_mapping()
    splits = mapping["data"]["splits"]
    splits[right_split]["manifest_sha256"] = splits[left_split]["manifest_sha256"]

    with pytest.raises(ContractInvariantError):
        freeze_contract(mapping)


@pytest.mark.parametrize(
    "source_version",
    ["/restricted/source", "file:restricted.csv", "s3://restricted/snapshot"],
)
def test_source_version_is_a_label_not_a_data_locator(source_version: str) -> None:
    mapping = valid_contract_mapping()
    mapping["data"]["source_version"] = source_version

    with pytest.raises(ContractInvariantError):
        freeze_contract(mapping)


def test_source_version_accepts_non_locating_provenance_label() -> None:
    mapping = valid_contract_mapping()
    mapping["data"]["source_version"] = "vendor-release-2026.08"

    assert freeze_contract(mapping).to_dict()["data"]["source_version"] == (
        "vendor-release-2026.08"
    )


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
def test_identity_fields_reject_non_identifiers(
    section: str | None, field: str
) -> None:
    mapping = _frozen_contract_mapping()
    target = mapping if section is None else mapping["data"]["splits"][section]
    target[field] = "contains spaces"

    with pytest.raises(ContractSchemaError):
        validate_contract(mapping)


@pytest.mark.parametrize(
    "path",
    [
        ("contract_id",),
        ("task_id",),
        ("plugin", "name"),
        ("data", "snapshot_id"),
        ("data", "splits", "development", "dataset_id"),
        ("data", "splits", "gate", "dataset_id"),
        ("data", "splits", "final", "dataset_id"),
        ("cost_model", "model_id"),
    ],
)
def test_identifier_fullmatch_rejects_trailing_newline(
    path: tuple[str, ...],
) -> None:
    mapping = _frozen_contract_mapping()
    target: Any = mapping
    for part in path:
        target = target[part]
    _replace_at_path(mapping, path, f"{target}\n")

    with pytest.raises(ContractInvariantError):
        validate_contract(mapping)


@pytest.mark.parametrize(
    "path",
    [
        ("contract_hash",),
        ("plugin", "code_sha256"),
        ("data", "snapshot_sha256"),
        ("data", "schema_sha256"),
        ("data", "splits", "development", "manifest_sha256"),
        ("data", "splits", "gate", "manifest_sha256"),
        ("data", "splits", "final", "manifest_sha256"),
        ("cost_model", "sha256"),
    ],
)
def test_hash_fullmatch_rejects_trailing_newline(path: tuple[str, ...]) -> None:
    mapping = _frozen_contract_mapping()
    target: Any = mapping
    for part in path:
        target = target[part]
    _replace_at_path(mapping, path, f"{target}\n")

    with pytest.raises(ContractInvariantError):
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
