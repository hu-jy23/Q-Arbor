from __future__ import annotations

import hashlib
from importlib.resources import files

from q_arbor.spec import INTERFACE_SCHEMA_SHA256, load_schema, schema_bytes


def test_packaged_interface_schema_has_stable_product_identity() -> None:
    raw = schema_bytes()
    schema = load_schema()

    assert hashlib.sha256(raw).hexdigest() == INTERFACE_SCHEMA_SHA256
    assert schema["$id"] == "urn:q-arbor:interface-schema:1.0"
    assert schema["title"] == "Q-Arbor Interface Schema"
    assert schema["$defs"]["QuantResearchContract"]["properties"]["task_kind"] == {
        "$ref": "#/$defs/Identifier"
    }
    assert files("q_arbor.spec").joinpath("INTERFACE_SCHEMA.json").is_file()
