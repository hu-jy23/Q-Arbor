"""Stable product schemas packaged with Q-Arbor."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Any

INTERFACE_SCHEMA_SHA256 = (
    "adcfe46321a6908cf1fc20a5dcfc9e363a1aeddca4e7f4fd93f0c2e6a9fd56c4"
)


class InterfaceSchemaDrift(RuntimeError):
    """Raised when the packaged interface schema has changed unexpectedly."""


def schema_bytes() -> bytes:
    """Return the packaged interface schema bytes after checking identity."""

    raw = files(__package__).joinpath("INTERFACE_SCHEMA.json").read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != INTERFACE_SCHEMA_SHA256:
        raise InterfaceSchemaDrift(
            "interface schema hash mismatch: "
            f"expected {INTERFACE_SCHEMA_SHA256}, got {actual}"
        )
    return raw


def load_schema() -> dict[str, Any]:
    """Load a fresh mapping of the hash-verified interface schema."""

    return json.loads(schema_bytes())


__all__ = [
    "INTERFACE_SCHEMA_SHA256",
    "InterfaceSchemaDrift",
    "load_schema",
    "schema_bytes",
]
