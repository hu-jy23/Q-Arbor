"""Strict JSON, interface-schema, and canonical hashing helpers."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from functools import lru_cache
from hashlib import sha256
from importlib import resources
from typing import Any, Final, TypeAlias, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from .errors import HypothesisDecodeError, HypothesisSchemaError

JSONScalar: TypeAlias = type(None) | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]

_SCHEMA_NAME: Final = "INTERFACE_SCHEMA.json"
_SCHEMA_SHA256: Final = (
    "adcfe46321a6908cf1fc20a5dcfc9e363a1aeddca4e7f4fd93f0c2e6a9fd56c4"
)


def _reject_constant(_: str) -> None:
    raise HypothesisDecodeError("JSON contains a non-finite numeric literal")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HypothesisDecodeError("JSON contains a duplicate object key")
        result[key] = value
    return result


def decode_json_bytes(raw: bytes) -> Any:
    """Decode strict UTF-8 JSON, rejecting duplicate keys and non-finite values."""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HypothesisDecodeError("hypothesis artifact is not valid UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except HypothesisDecodeError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        line = getattr(exc, "lineno", None)
        column = getattr(exc, "colno", None)
        location = f" at line {line}, column {column}" if line and column else ""
        raise HypothesisDecodeError(f"invalid hypothesis JSON{location}") from exc


def _normalized_string(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    try:
        normalized.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise HypothesisDecodeError(
            "JSON contains a string that cannot be encoded as UTF-8"
        ) from exc
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
            raise HypothesisDecodeError("JSON contains a non-finite numeric value")
        return value

    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise HypothesisDecodeError(
                "hypothesis artifact contains a recursive object"
            )
        active.add(identity)
        try:
            result: dict[str, JSONValue] = {}
            for raw_key, raw_value in value.items():
                if not isinstance(raw_key, str):
                    raise HypothesisDecodeError("JSON object keys must be strings")
                key = _normalized_string(raw_key)
                if key in result:
                    raise HypothesisDecodeError(
                        "Unicode normalization causes an object-key collision"
                    )
                result[key] = _normalize_json(raw_value, active)
            return result
        finally:
            active.remove(identity)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        identity = id(value)
        if identity in active:
            raise HypothesisDecodeError(
                "hypothesis artifact contains a recursive array"
            )
        active.add(identity)
        try:
            return [_normalize_json(item, active) for item in value]
        finally:
            active.remove(identity)

    raise HypothesisDecodeError("hypothesis artifact contains a non-JSON value")


def normalize_json(value: Any) -> JSONValue:
    """Return a detached NFC-normalized JSON value."""

    try:
        return _normalize_json(value, set())
    except HypothesisDecodeError:
        raise
    except RecursionError as exc:
        raise HypothesisDecodeError("hypothesis JSON nesting is too deep") from exc


def normalize_mapping(mapping: Mapping[str, Any]) -> dict[str, JSONValue]:
    """Return a detached normalized JSON object."""

    if not isinstance(mapping, Mapping):
        raise HypothesisDecodeError("hypothesis artifact must be a JSON object")
    normalized = normalize_json(mapping)
    if not isinstance(normalized, dict):
        raise HypothesisDecodeError("hypothesis artifact must be a JSON object")
    return normalized


def canonical_normalized_bytes(value: JSONValue | Mapping[str, Any]) -> bytes:
    """Encode an already-normalized JSON value as canonical UTF-8 JSON."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError) as exc:
        raise HypothesisDecodeError(
            "hypothesis artifact cannot be encoded as canonical JSON"
        ) from exc


def canonical_json_bytes(value: Any) -> bytes:
    """Normalize and encode a finite JSON value deterministically."""

    return canonical_normalized_bytes(normalize_json(value))


def canonical_mapping_hash(
    mapping: Mapping[str, Any], *, omit_top_level: str | None = None
) -> str:
    """Hash a normalized mapping, optionally omitting one top-level key."""

    normalized = normalize_mapping(mapping)
    if omit_top_level is not None:
        normalized.pop(omit_top_level, None)
    return sha256(canonical_normalized_bytes(normalized)).hexdigest()


@lru_cache(maxsize=1)
def schema_validator() -> Draft202012Validator:
    """Load and hash-check the interface discriminator schema."""

    try:
        raw = resources.files("q_arbor.spec").joinpath(_SCHEMA_NAME).read_bytes()
    except (OSError, ModuleNotFoundError) as exc:
        raise HypothesisSchemaError("interface schema is unavailable") from exc
    if sha256(raw).hexdigest() != _SCHEMA_SHA256:
        raise HypothesisSchemaError("interface schema hash does not match")
    try:
        decoded = decode_json_bytes(raw)
        if not isinstance(decoded, dict):
            raise HypothesisSchemaError("interface schema is not a JSON object")
        Draft202012Validator.check_schema(decoded)
        return Draft202012Validator(decoded, format_checker=FormatChecker())
    except HypothesisSchemaError:
        raise
    except (HypothesisDecodeError, SchemaError) as exc:
        raise HypothesisSchemaError("interface schema is invalid") from exc


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


def validate_discriminator(
    mapping: Mapping[str, JSONValue], artifact_type: str
) -> None:
    """Validate a normalized payload through the complete discriminator."""

    envelope = {"artifact_type": artifact_type, "payload": mapping}
    try:
        errors = sorted(
            schema_validator().iter_errors(envelope),
            key=lambda item: (
                tuple(f"{type(part).__name__}:{part}" for part in item.absolute_path),
                str(item.validator or "schema"),
            ),
        )
        error = errors[0] if errors else None
    except HypothesisSchemaError:
        raise
    except Exception as exc:
        raise HypothesisSchemaError("unable to evaluate the interface schema") from exc
    if error is not None:
        location = _display_schema_path(list(error.absolute_path))
        rule = str(error.validator or "schema")
        raise HypothesisSchemaError(
            f"artifact failed frozen schema validation at {location} ({rule})"
        )


def normalized_object(value: JSONValue, path: str) -> dict[str, JSONValue]:
    """Narrow a normalized JSON value to an object for internal validators."""

    if not isinstance(value, dict):
        raise HypothesisDecodeError(f"{path} must be a JSON object")
    return cast(dict[str, JSONValue], value)
