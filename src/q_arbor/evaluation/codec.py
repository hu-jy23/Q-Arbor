"""Strict JSON, frozen-C6 schema, and atomic persistence helpers for C9."""

from __future__ import annotations

import json
import math
import os
import re
import tempfile
import unicodedata
from collections.abc import Mapping, Sequence
from functools import lru_cache
from hashlib import sha256
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, TypeAlias, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from .errors import (
    EvaluationDecodeError,
    EvaluationPersistenceError,
    EvaluationSchemaError,
)

JSONScalar: TypeAlias = type(None) | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
FrozenJSON: TypeAlias = (
    JSONScalar | tuple["FrozenJSON", ...] | Mapping[str, "FrozenJSON"]
)

SCHEMA_SHA256: Final = (
    "89d39ebb0c9d8c06839f6d72951ccc8abd9ad36d753de79a06fa1890d6e420a0"
)
IDENTIFIER_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}")
SHA256_RE: Final = re.compile(r"[a-f0-9]{64}")
GIT_COMMIT_RE: Final = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")
REASON_CODE_RE: Final = re.compile(r"[a-z][a-z0-9_.-]{0,127}")
MEDIA_TYPE_RE: Final = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/"
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}"
)
_GLOB_META: Final = frozenset("*?[")
_WINDOWS_DRIVE_RE: Final = re.compile(r"[A-Za-z]:")


def _reject_constant(_: str) -> None:
    raise EvaluationDecodeError("JSON contains a non-finite numeric literal")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationDecodeError("JSON contains a duplicate object key")
        result[key] = value
    return result


def decode_json_bytes(raw: bytes) -> Any:
    """Decode strict UTF-8 JSON without duplicate keys or non-finite values."""

    if raw.startswith(b"\xef\xbb\xbf"):
        raise EvaluationDecodeError("evaluation JSON must not contain a BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise EvaluationDecodeError("evaluation artifact is not valid UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except EvaluationDecodeError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        line = getattr(exc, "lineno", None)
        column = getattr(exc, "colno", None)
        location = f" at line {line}, column {column}" if line and column else ""
        raise EvaluationDecodeError(f"invalid evaluation JSON{location}") from exc


def _normalize_string(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    try:
        normalized.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise EvaluationDecodeError("JSON string cannot be encoded as UTF-8") from exc
    return normalized


def _normalize_json(value: Any, active: set[int]) -> JSONValue:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _normalize_string(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EvaluationDecodeError("JSON contains a non-finite numeric value")
        return value
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise EvaluationDecodeError("evaluation artifact contains a cycle")
        active.add(identity)
        try:
            normalized: dict[str, JSONValue] = {}
            for raw_key, raw_item in value.items():
                if not isinstance(raw_key, str):
                    raise EvaluationDecodeError("JSON object keys must be strings")
                key = _normalize_string(raw_key)
                if key in normalized:
                    raise EvaluationDecodeError(
                        "Unicode normalization causes an object-key collision"
                    )
                normalized[key] = _normalize_json(raw_item, active)
            return normalized
        finally:
            active.remove(identity)
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        identity = id(value)
        if identity in active:
            raise EvaluationDecodeError("evaluation artifact contains a cycle")
        active.add(identity)
        try:
            return [_normalize_json(item, active) for item in value]
        finally:
            active.remove(identity)
    raise EvaluationDecodeError("evaluation artifact contains a non-JSON value")


def normalize_json(value: Any) -> JSONValue:
    """Return a detached NFC-normalized finite JSON value."""

    try:
        return _normalize_json(value, set())
    except EvaluationDecodeError:
        raise
    except RecursionError as exc:
        raise EvaluationDecodeError("evaluation JSON nesting is too deep") from exc


def normalize_mapping(mapping: Mapping[str, Any]) -> dict[str, JSONValue]:
    """Return a detached normalized JSON object."""

    if not isinstance(mapping, Mapping):
        raise EvaluationDecodeError("evaluation value must be a JSON object")
    normalized = normalize_json(mapping)
    if not isinstance(normalized, dict):
        raise EvaluationDecodeError("evaluation value must be a JSON object")
    return normalized


def canonical_normalized_bytes(value: JSONValue | Mapping[str, Any]) -> bytes:
    """Encode normalized JSON as compact sorted UTF-8 bytes."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError) as exc:
        raise EvaluationDecodeError(
            "evaluation value cannot be encoded as canonical JSON"
        ) from exc


def canonical_json_bytes(value: Any) -> bytes:
    """Normalize and canonically encode a finite JSON value."""

    return canonical_normalized_bytes(normalize_json(value))


def deep_freeze(value: JSONValue) -> FrozenJSON:
    """Create a deeply immutable JSON snapshot."""

    try:
        if isinstance(value, dict):
            return MappingProxyType({key: deep_freeze(item) for key, item in value.items()})
        if isinstance(value, list):
            return tuple(deep_freeze(item) for item in value)
        return value
    except RecursionError as exc:
        raise EvaluationDecodeError("evaluation JSON nesting is too deep") from exc


def deep_thaw(value: FrozenJSON) -> JSONValue:
    """Return a detached mutable JSON value from a frozen snapshot."""

    if isinstance(value, Mapping):
        return {key: deep_thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [deep_thaw(item) for item in value]
    return cast(JSONScalar, value)


@lru_cache(maxsize=1)
def _schema_mapping() -> dict[str, Any]:
    try:
        raw = resources.files("q_arbor.spec").joinpath(
            "C6_INTERFACE_SCHEMA.json"
        ).read_bytes()
    except (OSError, ModuleNotFoundError) as exc:
        raise EvaluationSchemaError("frozen C6 schema is unavailable") from exc
    if sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise EvaluationSchemaError("frozen C6 schema hash does not match")
    try:
        decoded = decode_json_bytes(raw)
        if not isinstance(decoded, dict):
            raise EvaluationSchemaError("frozen C6 schema is not an object")
        Draft202012Validator.check_schema(decoded)
        return decoded
    except EvaluationSchemaError:
        raise
    except (EvaluationDecodeError, SchemaError) as exc:
        raise EvaluationSchemaError("frozen C6 schema is invalid") from exc


@lru_cache(maxsize=16)
def _definition_validator(name: str) -> Draft202012Validator:
    schema = _schema_mapping()
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict) or name not in definitions:
        raise EvaluationSchemaError("requested frozen C6 definition is unavailable")
    wrapper = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": f"#/$defs/{name}",
        "$defs": definitions,
    }
    return Draft202012Validator(wrapper, format_checker=FormatChecker())


@lru_cache(maxsize=1)
def _discriminator_validator() -> Draft202012Validator:
    return Draft202012Validator(
        _schema_mapping(),
        format_checker=FormatChecker(),
    )


def _display_path(parts: Sequence[Any]) -> str:
    clean = list(parts)
    if clean and clean[0] == "payload":
        clean.pop(0)
    path = "$"
    for part in clean:
        if isinstance(part, int):
            path += f"[{part}]"
        elif isinstance(part, str) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", part
        ):
            path += f".{part}"
        else:
            path += "[?]"
    return path


def _run_schema_validation(
    validator: Draft202012Validator,
    value: Mapping[str, JSONValue],
    *,
    label: str,
) -> None:
    try:
        errors = sorted(
            validator.iter_errors(value),
            key=lambda error: (
                tuple(
                    f"{type(part).__name__}:{part}"
                    for part in error.absolute_path
                ),
                str(error.validator or "schema"),
            ),
        )
    except EvaluationSchemaError:
        raise
    except Exception as exc:
        raise EvaluationSchemaError("unable to evaluate frozen C6 schema") from exc
    if errors:
        error = errors[0]
        raise EvaluationSchemaError(
            f"{label} failed schema validation at "
            f"{_display_path(list(error.absolute_path))} "
            f"({error.validator or 'schema'})"
        )


def validate_definition(mapping: Mapping[str, JSONValue], name: str) -> None:
    """Validate one value against a hash-checked C6 ``$defs`` definition."""

    _run_schema_validation(_definition_validator(name), mapping, label=name)


def validate_discriminator(
    mapping: Mapping[str, JSONValue], artifact_type: str
) -> None:
    """Validate through the complete frozen C6 artifact discriminator."""

    envelope: dict[str, JSONValue] = {
        "artifact_type": artifact_type,
        "payload": cast(dict[str, JSONValue], dict(mapping)),
    }
    _run_schema_validation(
        _discriminator_validator(),
        envelope,
        label=artifact_type,
    )


def require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        from .errors import EvaluationInvariantError

        raise EvaluationInvariantError(f"{field} is not a strict identifier")
    return value


def require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        from .errors import EvaluationInvariantError

        raise EvaluationInvariantError(f"{field} is not a strict SHA-256 digest")
    return value


def require_reason_code(value: Any, field: str) -> str:
    if not isinstance(value, str) or REASON_CODE_RE.fullmatch(value) is None:
        from .errors import EvaluationInvariantError

        raise EvaluationInvariantError(f"{field} is not a safe ReasonCode")
    return value


def require_git_commit(value: Any, field: str) -> str:
    if not isinstance(value, str) or GIT_COMMIT_RE.fullmatch(value) is None:
        from .errors import EvaluationInvariantError

        raise EvaluationInvariantError(f"{field} is not a full Git object ID")
    return value


def require_media_type(value: Any, field: str) -> str:
    if not isinstance(value, str) or MEDIA_TYPE_RE.fullmatch(value) is None:
        from .errors import EvaluationInvariantError

        raise EvaluationInvariantError(f"{field} is not a canonical media type")
    return value


def require_literal_path(value: Any, field: str) -> str:
    """Apply the C7 literal path and Git/filesystem byte limits."""

    from .errors import EvaluationInvariantError

    if not isinstance(value, str) or not value:
        raise EvaluationInvariantError(f"{field} must be a relative path")
    if value != value.strip() or value.endswith("/"):
        raise EvaluationInvariantError(f"{field} is not a canonical path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise EvaluationInvariantError(f"{field} contains a control character")
    if value.startswith(("/", "~", "./", "../")) or "://" in value:
        raise EvaluationInvariantError(f"{field} is not repository-relative")
    if "\\" in value or _WINDOWS_DRIVE_RE.match(value):
        raise EvaluationInvariantError(f"{field} is not repository-relative")
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise EvaluationInvariantError(f"{field} is not canonical")
    if any(character in value for character in _GLOB_META):
        raise EvaluationInvariantError(f"{field} must identify one literal path")
    if len(value.encode("utf-8")) > 4095 or any(
        len(segment.encode("utf-8")) > 255 for segment in segments
    ):
        raise EvaluationInvariantError(f"{field} exceeds repository path limits")
    return value


def atomic_write(path: str | os.PathLike[str], content: bytes) -> None:
    """Durably replace one file and report whether replacement committed."""

    destination = Path(path)
    temporary_path: str | None = None
    committed = False
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = temporary.name
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, destination)
        committed = True
        temporary_path = None
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_fd = os.open(destination.parent, flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except EvaluationPersistenceError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise EvaluationPersistenceError(
            "unable to atomically write evaluation artifact",
            committed=committed,
        ) from exc
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


def read_bytes(path: str | os.PathLike[str]) -> bytes:
    """Read a file while keeping I/O errors distinct from decode errors."""

    try:
        return Path(path).read_bytes()
    except (OSError, TypeError, ValueError) as exc:
        raise EvaluationPersistenceError(
            "unable to read evaluation artifact",
            committed=False,
        ) from exc


def read_json_object(path: str | os.PathLike[str]) -> dict[str, Any]:
    decoded = decode_json_bytes(read_bytes(path))
    if not isinstance(decoded, dict):
        raise EvaluationDecodeError("evaluation artifact root must be an object")
    return decoded
