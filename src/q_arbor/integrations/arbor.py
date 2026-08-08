"""Pure metadata projection into Arbor's development-time seams.

This adapter constructs metadata only.  It neither imports nor invokes Arbor.
The projected evaluator module is a forward contract owned by C9 and is not an
executable evaluator in the C7 partial prototype.
"""

from __future__ import annotations

import math
import os
import re
import shlex
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from numbers import Real
from pathlib import Path
from typing import Any

from q_arbor.contracts import QuantResearchContract, load_contract

_PROJECTION_VERSION = "q-arbor.arbor-metadata.v1"
_HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_ALWAYS_KEYS = (
    "projection_version",
    "eval_cmd",
    "metric_direction",
    "trunk_branch",
    "protected_paths",
    "required_outputs",
    "q_contract_path",
    "q_contract_hash",
    "q_baseline_ref",
)


@dataclass(frozen=True, slots=True)
class ArborRunProjection(Mapping[str, object]):
    """Immutable, whitelisted Arbor metadata for one Q-Arbor run."""

    projection_version: str
    eval_cmd: str
    metric_direction: str
    trunk_branch: str
    protected_paths: tuple[str, ...]
    required_outputs: tuple[str, ...]
    q_contract_path: str
    q_contract_hash: str
    q_baseline_ref: str
    baseline_score: float | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "protected_paths", tuple(self.protected_paths))
        object.__setattr__(self, "required_outputs", tuple(self.required_outputs))

    def __iter__(self) -> Iterator[str]:
        yield from _ALWAYS_KEYS
        if self.baseline_score is not None:
            yield "baseline_score"

    def __len__(self) -> int:
        return len(_ALWAYS_KEYS) + (self.baseline_score is not None)

    def __getitem__(self, key: str) -> object:
        if key not in _ALWAYS_KEYS and not (
            key == "baseline_score" and self.baseline_score is not None
        ):
            raise KeyError(key)
        return getattr(self, key)

    def to_dict(self) -> dict[str, object]:
        """Return the detached flat audit view; do not inject it into TreeSetMeta."""

        result = {key: self[key] for key in _ALWAYS_KEYS}
        result["protected_paths"] = list(self.protected_paths)
        result["required_outputs"] = list(self.required_outputs)
        if self.baseline_score is not None:
            result["baseline_score"] = self.baseline_score
        return result

    def tree_meta(self) -> dict[str, object]:
        """Return fields accepted by Arbor ``TreeSetMeta``."""

        result: dict[str, object] = {
            "eval_cmd": self.eval_cmd,
            "metric_direction": self.metric_direction,
        }
        if self.baseline_score is not None:
            result["baseline_score"] = self.baseline_score
        return result

    def config_overrides(self) -> dict[str, object]:
        """Return fields accepted by Arbor ``CoordinatorConfig``."""

        return {
            "trunk_branch": self.trunk_branch,
            "protected_paths": list(self.protected_paths),
        }

    def plugin_overrides(self) -> dict[str, object]:
        """Return development-safe fields represented by Arbor ``Plugin``."""

        return {
            "protected_paths": list(self.protected_paths),
            "required_outputs": list(self.required_outputs),
        }

    def audit_metadata(self) -> dict[str, object]:
        """Return Q-Arbor-only identity fields for an external session artifact."""

        return {
            "projection_version": self.projection_version,
            "q_contract_path": self.q_contract_path,
            "q_contract_hash": self.q_contract_hash,
            "q_baseline_ref": self.q_baseline_ref,
        }


def project_to_arbor(
    contract: QuantResearchContract,
    *,
    contract_path: str | os.PathLike[str],
    trunk_branch: str,
    baseline_score: Real | None = None,
) -> ArborRunProjection:
    """Project validated contract facts into Arbor's development-only metadata."""

    payload, contract_hash = _read_contract(contract)
    objective = _mapping_at(payload, "objective")
    metrics = _mapping_at(payload, "metrics")
    primary = _mapping_at(metrics, "primary")

    direction = _string_at(primary, "direction")
    if direction not in {"maximize", "minimize"}:
        raise ValueError(
            "contract primary metric direction must be maximize or minimize"
        )

    payload_hash = _string_at(payload, "contract_hash")
    if payload_hash != contract_hash:
        raise ValueError("contract hash property does not match the frozen payload")

    baseline_ref = _string_at(objective, "baseline_ref")
    protected_paths = _path_list_at(payload, "protected_paths", allow_empty=False)
    required_outputs = _path_list_at(payload, "required_outputs", allow_empty=True)
    resolved_contract_path = _contract_path(contract_path, contract_hash)
    checked_branch = _branch_name(trunk_branch)
    checked_baseline = _baseline_score(baseline_score)

    # shlex.join quotes both placeholders as complete shell arguments.  Arbor's
    # textual replacement therefore preserves spaces in its cwd/node values.
    eval_cmd = shlex.join(
        (
            "python",
            "-m",
            "q_arbor.evaluation",
            "--contract",
            resolved_contract_path,
            "--split",
            "development",
            "--candidate-root",
            "{cwd}",
            "--node-id",
            "{node_id}",
        )
    )

    return ArborRunProjection(
        projection_version=_PROJECTION_VERSION,
        eval_cmd=eval_cmd,
        metric_direction=direction,
        trunk_branch=checked_branch,
        protected_paths=protected_paths,
        required_outputs=required_outputs,
        q_contract_path=resolved_contract_path,
        q_contract_hash=contract_hash,
        q_baseline_ref=baseline_ref,
        baseline_score=checked_baseline,
    )


def _read_contract(contract: object) -> tuple[Mapping[str, Any], str]:
    to_dict = getattr(contract, "to_dict", None)
    if not callable(to_dict):
        raise TypeError("contract must provide the QuantResearchContract to_dict API")
    snapshot = to_dict()
    if not isinstance(snapshot, Mapping):
        raise TypeError("contract.to_dict() must return a mapping")
    if snapshot.get("schema_version") != "1.0":
        raise ValueError("contract must use the frozen QuantResearchContract schema")

    contract_hash = getattr(contract, "sha256", None)
    if not isinstance(contract_hash, str) or not _HASH_PATTERN.fullmatch(contract_hash):
        raise ValueError("contract.sha256 must be a lowercase SHA-256 digest")
    return snapshot, contract_hash


def _mapping_at(mapping: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = mapping.get(key)
    if not isinstance(value, Mapping):
        raise TypeError(f"contract field {key!r} must be an object")
    return value


def _string_at(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"contract field {key!r} must be a non-empty string")
    if _has_control(value):
        raise ValueError(f"contract field {key!r} contains control characters")
    return value


def _path_list_at(
    mapping: Mapping[str, Any], key: str, *, allow_empty: bool
) -> tuple[str, ...]:
    value = mapping.get(key)
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ValueError(f"contract field {key!r} must be a valid path list")
    paths = tuple(_relative_contract_path(item, key) for item in value)
    if len(paths) != len(set(paths)):
        raise ValueError(f"contract field {key!r} contains duplicate paths")
    return paths


def _relative_contract_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"contract field {field!r} contains an invalid path")
    if (
        value.startswith("/")
        or "\\" in value
        or "//" in value
        or _has_control(value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError(f"contract field {field!r} contains an unsafe path")
    return value


def _contract_path(value: str | os.PathLike[str], expected_hash: str) -> str:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise TypeError("contract_path must be a filesystem path") from exc
    if not isinstance(raw, str):
        raise TypeError("contract_path must resolve to text, not bytes")
    if not raw or raw != raw.strip() or _has_control(raw):
        raise ValueError("contract_path must be a non-empty path without controls")
    if "{cwd}" in raw or "{node_id}" in raw:
        raise ValueError("contract_path may not contain Arbor template variables")
    try:
        resolved = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("contract_path must resolve to an existing file") from exc
    if not resolved.is_file():
        raise ValueError("contract_path must resolve to a regular file")
    persisted = load_contract(resolved)
    if persisted.sha256 != expected_hash:
        raise ValueError(
            "contract_path does not contain the projected contract snapshot"
        )
    return str(resolved)


def _branch_name(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("trunk_branch must be a non-empty branch name")
    if len(value.encode("utf-8")) > 255 or _has_control(value):
        raise ValueError("trunk_branch is not a safe branch name")
    if value.casefold() in {"head", "main", "master"}:
        raise ValueError("trunk_branch must be an independent non-default branch")
    if (
        value.startswith(("-", "/", "."))
        or value.endswith(("/", "."))
        or "//" in value
        or ".." in value
        or "@{" in value
        or any(character in value for character in " ~^:?*[\\")
        or any(
            part.endswith(".lock") or part.startswith(".") for part in value.split("/")
        )
    ):
        raise ValueError("trunk_branch is not a safe branch name")
    return value


def _baseline_score(value: Real | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError("baseline_score must be a real number")
    projected = float(value)
    if not math.isfinite(projected):
        raise ValueError("baseline_score must be finite")
    return projected


def _has_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)
