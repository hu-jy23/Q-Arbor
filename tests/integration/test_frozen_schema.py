from __future__ import annotations

import hashlib

from q_arbor.spec import FROZEN_SCHEMA_SHA256, load_schema, schema_bytes


def test_packaged_schema_matches_c6_identity() -> None:
    raw = schema_bytes()
    schema = load_schema()

    assert hashlib.sha256(raw).hexdigest() == FROZEN_SCHEMA_SHA256
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert len(schema["properties"]["artifact_type"]["enum"]) == 12
    assert set(schema["x-q-arbor-interfaces"]) == {
        "QuantTaskPlugin",
        "EvaluationBroker",
        "Ledger",
        "RecoveryReporter",
    }
    assert "score" in schema["$defs"]["QuantHypothesisNode"]["required"]


def test_schema_loader_returns_independent_mapping() -> None:
    first = load_schema()
    second = load_schema()

    first["title"] = "mutated caller copy"
    assert second["title"] != first["title"]
