"""Frozen design schemas packaged with Q-Arbor."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Any

FROZEN_SCHEMA_SHA256 = (
    "89d39ebb0c9d8c06839f6d72951ccc8abd9ad36d753de79a06fa1890d6e420a0"
)


class FrozenSchemaDrift(RuntimeError):
    """Raised when the packaged C6 design input has changed."""


def schema_bytes() -> bytes:
    """Return the packaged C6 schema bytes after checking their identity."""

    raw = files(__package__).joinpath("C6_INTERFACE_SCHEMA.json").read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != FROZEN_SCHEMA_SHA256:
        raise FrozenSchemaDrift(
            f"frozen C6 schema hash mismatch: expected {FROZEN_SCHEMA_SHA256}, got {actual}"
        )
    return raw


def load_schema() -> dict[str, Any]:
    """Load a fresh mapping of the hash-verified C6 schema."""

    return json.loads(schema_bytes())


__all__ = ["FROZEN_SCHEMA_SHA256", "FrozenSchemaDrift", "load_schema", "schema_bytes"]
