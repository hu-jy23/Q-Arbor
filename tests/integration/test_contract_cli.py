from __future__ import annotations

import json
from pathlib import Path

import pytest

from q_arbor.contracts import canonical_contract_bytes, freeze_contract, load_contract
from tests.helpers import (
    contract_fixture,
    expected_contract_hash,
    run_contract_cli,
    valid_contract_mapping,
)


def _write_json(path: Path, mapping: object) -> None:
    path.write_text(
        json.dumps(mapping, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_cli_validate_and_show_hash_are_read_only(tmp_path: Path) -> None:
    source = tmp_path / "frozen.json"
    freeze_contract(valid_contract_mapping()).write(source)
    before = source.read_bytes()

    validation = run_contract_cli("validate", source)
    shown_hash = run_contract_cli("show-hash", source)

    assert validation.returncode == 0, validation.stderr
    assert shown_hash.returncode == 0, shown_hash.stderr
    assert shown_hash.stdout.strip() == expected_contract_hash(valid_contract_mapping())
    assert source.read_bytes() == before


def test_cli_freeze_atomically_replaces_destination_with_canonical_snapshot(
    tmp_path: Path,
) -> None:
    draft = valid_contract_mapping()
    source = tmp_path / "draft.json"
    destination = tmp_path / "frozen.json"
    _write_json(source, draft)
    destination.write_bytes(b"sentinel: previous complete snapshot\n")

    completed = run_contract_cli("freeze", source, "--output", destination)

    assert completed.returncode == 0, completed.stderr
    frozen = load_contract(destination)
    assert frozen.sha256 == expected_contract_hash(draft)
    assert destination.read_bytes() == canonical_contract_bytes(frozen.to_dict())
    assert set(tmp_path.iterdir()) == {source, destination}


@pytest.mark.parametrize("preexisting_output", [False, True])
@pytest.mark.parametrize("failure_stage", ["decode", "invariant"])
def test_cli_freeze_failure_leaves_no_partial_output(
    tmp_path: Path, preexisting_output: bool, failure_stage: str
) -> None:
    destination = tmp_path / "frozen.json"
    sentinel = b"sentinel: previous complete snapshot\n"
    if preexisting_output:
        destination.write_bytes(sentinel)

    if failure_stage == "decode":
        source = contract_fixture("duplicate_key.json")
    else:
        mapping = valid_contract_mapping()
        mapping["data"]["splits"]["final"]["sealed"] = False
        source = tmp_path / "invalid-contract.json"
        _write_json(source, mapping)

    before_entries = set(tmp_path.iterdir())
    completed = run_contract_cli("freeze", source, "--output", destination)

    assert completed.returncode != 0
    assert completed.stderr.strip()
    assert completed.stdout == ""
    assert "No module named" not in completed.stderr
    assert "Traceback" not in completed.stderr
    if preexisting_output:
        assert destination.read_bytes() == sentinel
    else:
        assert not destination.exists()
    assert set(tmp_path.iterdir()) == before_entries
