"""Strict, immutable QuantResearchContract implementation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime, timezone
from functools import lru_cache
from hashlib import sha256
from importlib import resources
import fnmatch
import json
import math
import os
from pathlib import Path
import re
import tempfile
from types import MappingProxyType
from typing import Any, Final, TypeAlias, cast
import unicodedata

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .errors import (
    ContractDecodeError,
    ContractHashMismatch,
    ContractInvariantError,
    ContractSchemaError,
)


JSONScalar: TypeAlias = type(None) | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
FrozenJSON: TypeAlias = JSONScalar | tuple["FrozenJSON", ...] | Mapping[str, "FrozenJSON"]

_SCHEMA_NAME: Final = "C6_INTERFACE_SCHEMA.json"
_SCHEMA_SHA256: Final = "89d39ebb0c9d8c06839f6d72951ccc8abd9ad36d753de79a06fa1890d6e420a0"
_HASH_PLACEHOLDER: Final = "0" * 64
_SPLIT_ORDER: Final = ("development", "gate", "final")
_EXPECTED_SPLITS: Final = {
    "development": ("development", False),
    "gate": ("gate", True),
    "final": ("final", True),
}
_DATE_RE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME_RE: Final = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_GLOB_META: Final = frozenset("*?[")
_SECRET_PARTS: Final = frozenset(
    {
        "apikey",
        "authorization",
        "bearer",
        "clientsecret",
        "credential",
        "credentials",
        "password",
        "passwd",
        "privatekey",
        "secret",
        "token",
    }
)


def _reject_constant(_: str) -> None:
    raise ContractDecodeError("JSON contains a non-finite numeric literal")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractDecodeError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _decode_json_bytes(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ContractDecodeError("contract is not valid UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except ContractDecodeError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        line = getattr(exc, "lineno", None)
        column = getattr(exc, "colno", None)
        location = f" at line {line}, column {column}" if line and column else ""
        raise ContractDecodeError(f"invalid contract JSON{location}") from exc


def _normalized_string(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    try:
        normalized.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ContractDecodeError("JSON contains a string that cannot be encoded as UTF-8") from exc
    return normalized


def _normalize_json(value: Any, active: set[int]) -> JSONValue:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _normalized_string(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractDecodeError("JSON contains a non-finite numeric value")
        return value

    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise ContractDecodeError("contract contains a recursive object")
        active.add(identity)
        try:
            result: dict[str, JSONValue] = {}
            for raw_key, raw_value in value.items():
                if not isinstance(raw_key, str):
                    raise ContractDecodeError("JSON object keys must be strings")
                key = _normalized_string(raw_key)
                if key in result:
                    raise ContractDecodeError(
                        "Unicode normalization causes an object-key collision"
                    )
                result[key] = _normalize_json(raw_value, active)
            return result
        finally:
            active.remove(identity)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        identity = id(value)
        if identity in active:
            raise ContractDecodeError("contract contains a recursive array")
        active.add(identity)
        try:
            return [_normalize_json(item, active) for item in value]
        finally:
            active.remove(identity)

    raise ContractDecodeError("contract contains a value that JSON cannot represent")


def _normalize_mapping(mapping: Mapping[str, Any]) -> dict[str, JSONValue]:
    if not isinstance(mapping, Mapping):
        raise ContractDecodeError("contract must be a JSON object")
    normalized = _normalize_json(mapping, set())
    if not isinstance(normalized, dict):  # Kept explicit for type-checkers and custom mappings.
        raise ContractDecodeError("contract must be a JSON object")
    return normalized


def _canonical_normalized_bytes(mapping: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            mapping,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContractDecodeError("contract cannot be encoded as canonical JSON") from exc


def canonical_contract_bytes(mapping: Mapping[str, Any]) -> bytes:
    """Return normalized, sorted, compact UTF-8 JSON including ``contract_hash``."""

    return _canonical_normalized_bytes(_normalize_mapping(mapping))


def _compute_normalized_hash(mapping: Mapping[str, JSONValue]) -> str:
    hash_input = dict(mapping)
    hash_input.pop("contract_hash", None)
    return sha256(_canonical_normalized_bytes(hash_input)).hexdigest()


def compute_contract_hash(mapping: Mapping[str, Any]) -> str:
    """Compute the canonical SHA-256 digest, excluding only the top-level hash field."""

    return _compute_normalized_hash(_normalize_mapping(mapping))


@lru_cache(maxsize=1)
def _schema_validator() -> Draft202012Validator:
    try:
        raw = resources.files("q_arbor.spec").joinpath(_SCHEMA_NAME).read_bytes()
    except (OSError, ModuleNotFoundError) as exc:
        raise ContractSchemaError("frozen contract schema is unavailable") from exc
    if sha256(raw).hexdigest() != _SCHEMA_SHA256:
        raise ContractSchemaError("frozen contract schema hash does not match C6")
    try:
        decoded = _decode_json_bytes(raw)
        if not isinstance(decoded, dict):
            raise ContractSchemaError("frozen contract schema is not a JSON object")
        Draft202012Validator.check_schema(decoded)
        return Draft202012Validator(decoded)
    except ContractSchemaError:
        raise
    except (ContractDecodeError, SchemaError) as exc:
        raise ContractSchemaError("frozen contract schema is invalid") from exc


def _display_schema_path(parts: Sequence[Any]) -> str:
    clean = list(parts)
    if clean and clean[0] == "payload":
        clean.pop(0)
    path = "$"
    for part in clean:
        if isinstance(part, int):
            path += f"[{part}]"
        elif isinstance(part, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part):
            path += f".{part}"
        else:
            path += "[?]"
    return path


def _validate_schema(mapping: Mapping[str, JSONValue]) -> None:
    # C6 C01: exercise the frozen artifact discriminator, not a copied subschema.
    envelope = {"artifact_type": "quant_research_contract", "payload": mapping}
    try:
        errors = sorted(
            _schema_validator().iter_errors(envelope),
            key=lambda item: (
                tuple(f"{type(part).__name__}:{part}" for part in item.absolute_path),
                str(item.validator or "schema"),
            ),
        )
        error = errors[0] if errors else None
    except ContractSchemaError:
        raise
    except Exception as exc:  # jsonschema reference failures must remain fail-closed.
        raise ContractSchemaError("unable to evaluate the frozen contract schema") from exc
    if error is not None:
        location = _display_schema_path(list(error.absolute_path))
        rule = str(error.validator or "schema")
        raise ContractSchemaError(
            f"contract failed frozen schema validation at {location} ({rule})"
        )


def _parse_boundary(value: str, path: str) -> tuple[str, date | datetime]:
    try:
        if _DATE_RE.fullmatch(value):
            return "date", date.fromisoformat(value)
        if _DATETIME_RE.fullmatch(value):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError
            return "datetime", parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise ContractInvariantError(f"{path} is not a valid time boundary") from exc
    raise ContractInvariantError(f"{path} must be an ISO date or timezone-aware datetime")


def _validate_time_invariants(contract: Mapping[str, JSONValue]) -> None:
    data = cast(dict[str, Any], contract["data"])
    splits = cast(dict[str, dict[str, Any]], data["splits"])
    present = [name for name in _SPLIT_ORDER if "time_range" in splits[name]]
    if present and len(present) != len(_SPLIT_ORDER):
        raise ContractInvariantError("split time ranges must be configured together")
    if not present:
        return

    parsed_ranges: dict[str, tuple[str, date | datetime, date | datetime]] = {}
    common_kind: str | None = None
    for name in _SPLIT_ORDER:
        time_range = cast(dict[str, str], splits[name]["time_range"])
        start_kind, start = _parse_boundary(
            time_range["start"], f"data.splits.{name}.time_range.start"
        )
        end_kind, end = _parse_boundary(
            time_range["end"], f"data.splits.{name}.time_range.end"
        )
        if start_kind != end_kind:
            raise ContractInvariantError(f"{name} split mixes date and datetime boundaries")
        if start >= end:
            raise ContractInvariantError(f"{name} split must start before it ends")
        if common_kind is None:
            common_kind = start_kind
        elif common_kind != start_kind:
            raise ContractInvariantError("split time ranges must use one boundary format")
        parsed_ranges[name] = (start_kind, start, end)

    for left_name, right_name in zip(_SPLIT_ORDER, _SPLIT_ORDER[1:]):
        left_end = parsed_ranges[left_name][2]
        right_start = parsed_ranges[right_name][1]
        if left_end >= right_start:
            raise ContractInvariantError(
                f"{left_name} and {right_name} split time ranges overlap or are out of order"
            )


def _validate_path_syntax(path: str, field: str) -> list[str]:
    if path != path.strip() or path.endswith("/"):
        raise ContractInvariantError(f"{field} contains a non-canonical path")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise ContractInvariantError(f"{field} contains a control character")
    if path.startswith("~") or "://" in path:
        raise ContractInvariantError(f"{field} contains an unsafe path")
    segments = path.split("/")
    if any("**" in segment and segment != "**" for segment in segments):
        raise ContractInvariantError(f"{field} contains an ambiguous recursive glob")
    return segments


def _fixed_prefix(pattern: str) -> str:
    index = min((pattern.find(char) for char in _GLOB_META if char in pattern), default=len(pattern))
    return pattern[:index]


def _fixed_suffix(pattern: str) -> str:
    last = max((pattern.rfind(char) for char in _GLOB_META), default=-1)
    if last < 0:
        return pattern
    if "[" in pattern and "]" in pattern[last:]:
        last = max(last, pattern.find("]", last))
    return pattern[last + 1 :]


def _literal_prefixes_compatible(left: str, right: str) -> bool:
    common = min(len(left), len(right))
    return left[:common] == right[:common]


def _literal_suffixes_compatible(left: str, right: str) -> bool:
    common = min(len(left), len(right))
    if common == 0:
        return True
    return left[-common:] == right[-common:]


def _segment_patterns_overlap(left: str, right: str) -> bool:
    left_glob = any(char in left for char in _GLOB_META)
    right_glob = any(char in right for char in _GLOB_META)
    if not left_glob and not right_glob:
        return left == right
    if not left_glob:
        return fnmatch.fnmatchcase(left, right)
    if not right_glob:
        return fnmatch.fnmatchcase(right, left)
    if not _literal_prefixes_compatible(_fixed_prefix(left), _fixed_prefix(right)):
        return False
    if not _literal_suffixes_compatible(_fixed_suffix(left), _fixed_suffix(right)):
        return False
    # Remaining wildcard-language intersections are conservatively considered possible.
    return True


def _glob_patterns_overlap(left: list[str], right: list[str]) -> bool:
    @lru_cache(maxsize=None)
    def visit(left_index: int, right_index: int) -> bool:
        if left_index == len(left) and right_index == len(right):
            return True
        if left_index == len(left):
            return all(segment == "**" for segment in right[right_index:])
        if right_index == len(right):
            return all(segment == "**" for segment in left[left_index:])

        left_segment = left[left_index]
        right_segment = right[right_index]
        if left_segment == "**":
            if visit(left_index + 1, right_index):
                return True
            return visit(left_index, right_index + 1)
        if right_segment == "**":
            if visit(left_index, right_index + 1):
                return True
            return visit(left_index + 1, right_index)
        return _segment_patterns_overlap(left_segment, right_segment) and visit(
            left_index + 1, right_index + 1
        )

    return visit(0, 0)


def _validate_path_invariants(contract: Mapping[str, JSONValue]) -> None:
    editable = [
        (path, _validate_path_syntax(path, "editable_surface"))
        for path in cast(list[str], contract["editable_surface"])
    ]
    protected = [
        (path, _validate_path_syntax(path, "protected_paths"))
        for path in cast(list[str], contract["protected_paths"])
    ]
    required = [
        (path, _validate_path_syntax(path, "required_outputs"))
        for path in cast(list[str], contract["required_outputs"])
    ]

    for _, editable_segments in editable:
        for _, protected_segments in protected:
            if _glob_patterns_overlap(editable_segments, protected_segments):
                raise ContractInvariantError("editable and protected path surfaces overlap")
    for _, output_segments in required:
        for _, protected_segments in protected:
            if _glob_patterns_overlap(output_segments, protected_segments):
                raise ContractInvariantError("required output and protected path surfaces overlap")


def _validate_role_and_split_invariants(contract: Mapping[str, JSONValue]) -> None:
    capabilities = cast(dict[str, Any], contract["capabilities"])
    if capabilities["executor_roles"] != ["development"]:
        raise ContractInvariantError("executor capability must be development-only")
    if set(capabilities["coordinator_roles"]) != {"development", "gate"}:
        raise ContractInvariantError("coordinator capability must cover development and gate")
    if capabilities["finalizer_roles"] != ["final"]:
        raise ContractInvariantError("finalizer capability must be final-only")

    data = cast(dict[str, Any], contract["data"])
    splits = cast(dict[str, dict[str, Any]], data["splits"])
    for name, (expected_role, expected_sealed) in _EXPECTED_SPLITS.items():
        split = splits[name]
        if split["role"] != expected_role or split["sealed"] is not expected_sealed:
            raise ContractInvariantError(f"{name} split role or sealed state is inconsistent")
    if splits["final"]["query_budget"] != 1:
        raise ContractInvariantError("final split query budget must equal one")

    budgets = cast(dict[str, int], contract["budgets"])
    if splits["development"]["query_budget"] > budgets["max_dev_queries"]:
        raise ContractInvariantError("development split query budget exceeds the run budget")
    if splits["gate"]["query_budget"] > budgets["max_gate_queries"]:
        raise ContractInvariantError("gate split query budget exceeds the run budget")
    if budgets["max_final_queries"] != 1:
        raise ContractInvariantError("final run query budget must equal one")


def _validate_metric_invariants(contract: Mapping[str, JSONValue]) -> None:
    metrics = cast(dict[str, Any], contract["metrics"])
    primary_name = cast(dict[str, str], metrics["primary"])["name"]
    diagnostic_names = [item["name"] for item in metrics["diagnostics"]]
    if primary_name in diagnostic_names or len(diagnostic_names) != len(set(diagnostic_names)):
        raise ContractInvariantError("metric names must be unique")
    constraint_names = [item["name"] for item in metrics["hard_constraints"]]
    if len(constraint_names) != len(set(constraint_names)):
        raise ContractInvariantError("hard-constraint names must be unique")


def _key_is_secret_like(key: str) -> bool:
    words = [part for part in re.split(r"[^a-z0-9]+", key.casefold()) if part]
    compact = "".join(words)
    if compact in _SECRET_PARTS:
        return True
    if any(part in _SECRET_PARTS for part in words):
        return True
    return any(
        marker in compact
        for marker in ("apikey", "clientsecret", "privatekey", "authtoken", "accesstoken")
    )


def _scan_secret_keys(value: JSONValue, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _key_is_secret_like(key):
                raise ContractInvariantError(f"secret-like field is forbidden at {path}")
            _scan_secret_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_secret_keys(item, f"{path}[{index}]")


def _validate_invariants(contract: Mapping[str, JSONValue]) -> None:
    # C5 G01-G05 / C6 C01: reject inconsistent task facts before any Arbor call.
    _validate_time_invariants(contract)
    _validate_path_invariants(contract)
    _validate_role_and_split_invariants(contract)
    _validate_metric_invariants(contract)
    _scan_secret_keys(cast(JSONValue, contract))


def _validate_normalized(
    normalized: dict[str, JSONValue], *, verify_hash: bool
) -> str:
    _validate_schema(normalized)
    _validate_invariants(normalized)
    computed = _compute_normalized_hash(normalized)
    if verify_hash and normalized["contract_hash"] != computed:
        raise ContractHashMismatch("contract_hash does not match canonical contract content")
    return computed


def _deep_freeze(value: JSONValue) -> FrozenJSON:
    if isinstance(value, dict):
        frozen = {key: _deep_freeze(item) for key, item in value.items()}
        return MappingProxyType(frozen)
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _deep_thaw(value: FrozenJSON) -> JSONValue:
    if isinstance(value, Mapping):
        return {key: _deep_thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_deep_thaw(item) for item in value]
    return cast(JSONScalar, value)


class QuantResearchContract:
    """An immutable, normalized snapshot of a validated research contract."""

    __slots__ = ("_canonical", "_sha256", "_snapshot", "_initialized")

    def __init__(self, mapping: Mapping[str, Any], *, verify_hash: bool = True) -> None:
        normalized = _normalize_mapping(mapping)
        digest = _validate_normalized(normalized, verify_hash=verify_hash)
        self._initialize(normalized, digest)

    @classmethod
    def _from_normalized(
        cls, normalized: dict[str, JSONValue], digest: str
    ) -> "QuantResearchContract":
        instance = cls.__new__(cls)
        instance._initialize(normalized, digest)
        return instance

    def _initialize(self, normalized: dict[str, JSONValue], digest: str) -> None:
        object.__setattr__(self, "_snapshot", _deep_freeze(normalized))
        object.__setattr__(self, "_canonical", _canonical_normalized_bytes(normalized))
        object.__setattr__(self, "_sha256", digest)
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("QuantResearchContract is immutable")
        object.__setattr__(self, name, value)

    @property
    def sha256(self) -> str:
        """The canonical digest of the contract content excluding ``contract_hash``."""

        return self._sha256

    def to_dict(self) -> dict[str, JSONValue]:
        """Return a detached mutable copy of the normalized contract."""

        thawed = _deep_thaw(self._snapshot)
        return cast(dict[str, JSONValue], thawed)

    def to_json(self) -> str:
        """Return canonical compact JSON for the complete frozen contract."""

        return self._canonical.decode("utf-8")

    def write(self, path: str | os.PathLike[str]) -> None:
        """Atomically write canonical UTF-8 JSON without mutating an existing file on failure."""

        destination = Path(path)
        temporary_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = temporary.name
                temporary.write(self._canonical)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, destination)
            temporary_path = None
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass

    def __copy__(self) -> "QuantResearchContract":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "QuantResearchContract":
        memo[id(self)] = self
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, QuantResearchContract):
            return NotImplemented
        return self._canonical == other._canonical

    def __hash__(self) -> int:
        return hash(self._canonical)

    def __repr__(self) -> str:
        return f"QuantResearchContract(sha256={self._sha256!r})"


def validate_contract(
    mapping: Mapping[str, Any], *, verify_hash: bool = True
) -> QuantResearchContract:
    """Normalize, schema-check, invariant-check, and optionally verify a contract hash."""

    normalized = _normalize_mapping(mapping)
    digest = _validate_normalized(normalized, verify_hash=verify_hash)
    return QuantResearchContract._from_normalized(normalized, digest)


def freeze_contract(mapping: Mapping[str, Any]) -> QuantResearchContract:
    """Validate a draft, replace its hash, and return an immutable frozen contract."""

    normalized = _normalize_mapping(mapping)
    normalized["contract_hash"] = _HASH_PLACEHOLDER
    _validate_normalized(normalized, verify_hash=False)
    digest = _compute_normalized_hash(normalized)
    normalized["contract_hash"] = digest
    _validate_normalized(normalized, verify_hash=True)
    return QuantResearchContract._from_normalized(normalized, digest)


def _load_contract_mapping(path: str | os.PathLike[str]) -> dict[str, JSONValue]:
    try:
        raw = Path(path).read_bytes()
    except (OSError, TypeError, ValueError) as exc:
        raise ContractDecodeError("unable to read contract JSON") from exc
    decoded = _decode_json_bytes(raw)
    if not isinstance(decoded, Mapping):
        raise ContractDecodeError("contract must be a JSON object")
    return _normalize_mapping(decoded)


def load_contract(path: str | os.PathLike[str]) -> QuantResearchContract:
    """Strictly decode and fully validate a contract file."""

    return validate_contract(_load_contract_mapping(path))
