from __future__ import annotations

import copy
import json
import shlex
from dataclasses import FrozenInstanceError, dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest

from q_arbor.contracts import QuantResearchContract, freeze_contract
from q_arbor.integrations import ArborRunProjection, project_to_arbor
from tests.helpers import valid_contract_mapping

BASE_KEYS = {
    "projection_version",
    "eval_cmd",
    "metric_direction",
    "trunk_branch",
    "protected_paths",
    "required_outputs",
    "q_contract_path",
    "q_contract_hash",
    "q_baseline_ref",
}


@dataclass(frozen=True)
class StubContract:
    snapshot: dict[str, Any]
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self.snapshot)


@pytest.fixture
def contract() -> QuantResearchContract:
    return freeze_contract(valid_contract_mapping())


@pytest.fixture
def contract_path(tmp_path: Path, contract: QuantResearchContract) -> Path:
    path = tmp_path / "contract 'safe copy'.json"
    contract.write(path)
    return path


def test_real_contract_projection_is_exact_stable_and_detached(
    contract: QuantResearchContract, contract_path: Path
) -> None:
    before = contract.to_dict()
    assert "payload" not in before  # QuantResearchContract exposes the direct payload.

    first = project_to_arbor(
        contract,
        contract_path=contract_path,
        trunk_branch="q-arbor/trunk",
        baseline_score=1.25,
    )
    second = project_to_arbor(
        contract,
        contract_path=contract_path,
        trunk_branch="q-arbor/trunk",
        baseline_score=1.25,
    )

    assert isinstance(first, ArborRunProjection)
    assert first is not second
    assert dict(first) == dict(second)
    assert set(first) == BASE_KEYS | {"baseline_score"}
    assert first["q_contract_hash"] == contract.sha256
    assert contract.to_dict() == before

    detached = first.to_dict()
    detached_again = first.to_dict()
    assert detached is not detached_again
    assert detached["protected_paths"] is not detached_again["protected_paths"]
    assert isinstance(detached["protected_paths"], list)
    detached["protected_paths"].append("injected/**")  # type: ignore[union-attr]
    assert first["protected_paths"] == tuple(before["protected_paths"])


def test_eval_command_quotes_static_path_and_arbor_templates(
    contract: QuantResearchContract, contract_path: Path
) -> None:
    projection = project_to_arbor(
        contract, contract_path=contract_path, trunk_branch="q-arbor/trunk"
    )
    command = projection["eval_cmd"]
    assert isinstance(command, str)
    assert "'{cwd}'" in command
    assert "'{node_id}'" in command

    assert shlex.split(command) == [
        "python",
        "-m",
        "q_arbor.evaluation",
        "--contract",
        str(contract_path.resolve()),
        "--split",
        "development",
        "--candidate-root",
        "{cwd}",
        "--node-id",
        "{node_id}",
    ]

    rendered = command.replace("{cwd}", "/tmp/work tree").replace(
        "{node_id}", 'node "1.2"'
    )
    rendered_tokens = shlex.split(rendered)
    assert rendered_tokens[8] == "/tmp/work tree"
    assert rendered_tokens[10] == 'node "1.2"'


def test_projection_has_minimal_fields_and_no_restricted_data(
    contract: QuantResearchContract, contract_path: Path
) -> None:
    projection = project_to_arbor(
        contract, contract_path=contract_path, trunk_branch="q-arbor/trunk"
    )
    assert set(projection) == BASE_KEYS
    assert "eval_cmd_test" not in projection
    serialized = json.dumps(projection.to_dict(), sort_keys=True)
    for forbidden in (
        "synthetic.gate.v1",
        "synthetic.final.v1",
        "5555555555555555",
        "6666666666666666",
        '"seeds"',
        '"max_tokens"',
        '"provider"',
        '"credential"',
        '"token"',
        "eval_cmd_test",
    ):
        assert forbidden not in serialized


def test_source_specific_views_do_not_mix_arbor_or_audit_seams(
    contract: QuantResearchContract, contract_path: Path
) -> None:
    projection = project_to_arbor(
        contract,
        contract_path=contract_path,
        trunk_branch="q-arbor/trunk",
        baseline_score=0.0,
    )

    assert set(projection.tree_meta()) == {
        "eval_cmd",
        "metric_direction",
        "baseline_score",
    }
    assert projection.tree_meta()["baseline_score"] == 0.0
    assert set(projection.config_overrides()) == {"trunk_branch", "protected_paths"}
    assert set(projection.plugin_overrides()) == {
        "protected_paths",
        "required_outputs",
    }
    assert set(projection.audit_metadata()) == {
        "projection_version",
        "q_contract_path",
        "q_contract_hash",
        "q_baseline_ref",
    }
    for runtime_view in (
        projection.tree_meta(),
        projection.config_overrides(),
        projection.plugin_overrides(),
    ):
        assert not any(key.startswith("q_") for key in runtime_view)
        assert "eval_cmd_test" not in runtime_view

    config = projection.config_overrides()
    config["protected_paths"].append("injected/**")  # type: ignore[union-attr]
    assert "injected/**" not in projection.protected_paths


def test_projection_is_immutable(
    contract: QuantResearchContract, contract_path: Path
) -> None:
    projection = project_to_arbor(
        contract, contract_path=contract_path, trunk_branch="q-arbor/trunk"
    )
    with pytest.raises(FrozenInstanceError):
        projection.trunk_branch = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        projection["protected_paths"][0] = "changed"  # type: ignore[index]


@pytest.mark.parametrize(
    "branch",
    [
        "",
        " main",
        "main",
        "master",
        "HEAD",
        "-trunk",
        "/trunk",
        "trunk/",
        ".trunk",
        "bad..name",
        "bad@{name",
        "bad name",
        "bad?name",
        "x.lock",
        "@",
        "refs/heads/main",
        "refs/remotes/origin/main",
        "heads/main",
        "tags/release",
        "remotes/origin/trunk",
    ],
)
def test_invalid_trunk_branch_fails_closed(
    contract: QuantResearchContract, contract_path: Path, branch: str
) -> None:
    with pytest.raises(ValueError):
        project_to_arbor(contract, contract_path=contract_path, trunk_branch=branch)


@pytest.mark.parametrize("score", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_baseline_fails_closed(
    contract: QuantResearchContract, contract_path: Path, score: float
) -> None:
    with pytest.raises(ValueError):
        project_to_arbor(
            contract,
            contract_path=contract_path,
            trunk_branch="q-arbor/trunk",
            baseline_score=score,
        )


@pytest.mark.parametrize(
    "score",
    [
        pytest.param(10**10000, id="huge-integer"),
        pytest.param(Fraction(10**10000, 1), id="huge-fraction"),
    ],
)
def test_overflowing_baseline_has_stable_finite_error(
    contract: QuantResearchContract,
    contract_path: Path,
    score: int | Fraction,
) -> None:
    with pytest.raises(ValueError, match="^baseline_score must be finite$"):
        project_to_arbor(
            contract,
            contract_path=contract_path,
            trunk_branch="q-arbor/trunk",
            baseline_score=score,
        )


@pytest.mark.parametrize("score", [True, "1.0"])
def test_non_numeric_baseline_fails_closed(
    contract: QuantResearchContract, contract_path: Path, score: object
) -> None:
    with pytest.raises(TypeError):
        project_to_arbor(
            contract,
            contract_path=contract_path,
            trunk_branch="q-arbor/trunk",
            baseline_score=score,  # type: ignore[arg-type]
        )


def test_invalid_contract_path_fails_closed(
    contract: QuantResearchContract, tmp_path: Path
) -> None:
    with pytest.raises(ValueError):
        project_to_arbor(
            contract,
            contract_path=tmp_path / "missing.json",
            trunk_branch="q-arbor/trunk",
        )
    with pytest.raises(ValueError):
        project_to_arbor(contract, contract_path=tmp_path, trunk_branch="q-arbor/trunk")
    with pytest.raises(ValueError):
        project_to_arbor(
            contract,
            contract_path="{cwd}/contract.json",
            trunk_branch="q-arbor/trunk",
        )
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        project_to_arbor(contract, contract_path=invalid, trunk_branch="q-arbor/trunk")


def test_contract_path_hash_drift_fails_closed(
    contract: QuantResearchContract, tmp_path: Path
) -> None:
    other_mapping = valid_contract_mapping()
    other_mapping["contract_id"] = "synthetic.contract.other"
    other_contract = freeze_contract(other_mapping)
    other_path = tmp_path / "other-contract.json"
    other_contract.write(other_path)
    assert other_contract.sha256 != contract.sha256

    with pytest.raises(ValueError, match="projected contract snapshot"):
        project_to_arbor(
            contract,
            contract_path=other_path,
            trunk_branch="q-arbor/trunk",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            lambda value: value["metrics"]["primary"].update(direction="minimize"),
            id="direction",
        ),
        pytest.param(
            lambda value: value["objective"].update(
                baseline_ref="baseline/legally-substituted"
            ),
            id="baseline-ref",
        ),
        pytest.param(
            lambda value: value.update(protected_paths=["contracts/**", "data/**"]),
            id="protected-paths",
        ),
        pytest.param(
            lambda value: value.update(
                required_outputs=["strategies/substituted.json"]
            ),
            id="required-outputs",
        ),
    ],
)
def test_duck_contract_cannot_substitute_legal_projected_fields(
    contract: QuantResearchContract,
    contract_path: Path,
    mutation: Any,
) -> None:
    forged_snapshot = contract.to_dict()
    mutation(forged_snapshot)

    # The forged object retains an authentic digest and payload hash while its
    # projected facts differ from the persisted snapshot.
    forged = StubContract(forged_snapshot, contract.sha256)
    with pytest.raises(TypeError, match="QuantResearchContract"):
        project_to_arbor(  # type: ignore[arg-type]
            forged,
            contract_path=contract_path,
            trunk_branch="q-arbor/trunk",
        )


def test_replaced_contract_path_is_revalidated_as_stale(
    contract: QuantResearchContract, contract_path: Path
) -> None:
    project_to_arbor(
        contract,
        contract_path=contract_path,
        trunk_branch="q-arbor/trunk",
    )

    replacement_mapping = valid_contract_mapping()
    replacement_mapping["contract_id"] = "synthetic.contract.replacement"
    replacement = freeze_contract(replacement_mapping)
    replacement.write(contract_path)

    with pytest.raises(ValueError, match="projected contract snapshot"):
        project_to_arbor(
            contract,
            contract_path=contract_path,
            trunk_branch="q-arbor/trunk",
        )


def test_canonically_identical_pretty_snapshot_is_accepted(
    contract: QuantResearchContract, contract_path: Path
) -> None:
    contract_path.write_text(
        json.dumps(contract.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    projection = project_to_arbor(
        contract,
        contract_path=contract_path,
        trunk_branch="q-arbor/trunk",
    )
    assert projection["q_contract_hash"] == contract.sha256


def test_corrupted_contract_object_canonical_fails_closed(
    contract: QuantResearchContract, contract_path: Path
) -> None:
    corrupted = freeze_contract(contract.to_dict())
    object.__setattr__(corrupted, "_canonical", b"{}")

    with pytest.raises(ValueError, match="canonical snapshot"):
        project_to_arbor(
            corrupted,
            contract_path=contract_path,
            trunk_branch="q-arbor/trunk",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schema_version="2.0"),
        lambda value: value.update(contract_hash="b" * 64),
        lambda value: value["metrics"]["primary"].update(direction="sideways"),
        lambda value: value.update(protected_paths=["../secret"]),
    ],
)
def test_malformed_duck_contract_projection_fails_closed(
    contract: QuantResearchContract,
    contract_path: Path,
    mutation: Any,
) -> None:
    malformed = contract.to_dict()
    mutation(malformed)
    with pytest.raises(TypeError, match="QuantResearchContract"):
        project_to_arbor(  # type: ignore[arg-type]
            StubContract(malformed, contract.sha256),
            contract_path=contract_path,
            trunk_branch="q-arbor/trunk",
        )
