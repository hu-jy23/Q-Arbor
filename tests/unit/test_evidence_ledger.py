from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from q_arbor.evaluation import EvaluationIntegrityError, EvaluationPersistenceError
from q_arbor.evaluation.codec import canonical_json_bytes, decode_json_bytes
from q_arbor.ledger import EvidenceLedger


CONTRACT_HASH = "a" * 64
RUN_ID = "run.ledger.fixture"


def _event(event_type: str, **overrides: Any) -> dict[str, Any]:
    event = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "event_id": f"event.{event_type}",
        "timestamp": "2026-08-22T00:00:00Z",
        "event_type": event_type,
        "actor": "coordinator",
        "contract_hash": CONTRACT_HASH,
        "node_id": None,
        "attempt_id": None,
        "split_role": "none",
        "payload": {},
    }
    event.update(overrides)
    return event


def _append_trace(ledger: EvidenceLedger) -> list[Path]:
    drafts = [
        _event("run.started", actor="system", payload={"phase": "development"}),
        _event(
            "hypothesis.proposed",
            node_id="node.alpha",
            payload={"candidate_id": "candidate.alpha"},
        ),
        _event(
            "candidate.validated",
            actor="evaluator",
            node_id="node.alpha",
            payload={"candidate_id": "candidate.alpha"},
        ),
        _event(
            "evaluation.requested",
            node_id="node.alpha",
            attempt_id="attempt.alpha.1",
            split_role="development",
            payload={"request_id": "request.alpha.1"},
        ),
        _event(
            "evaluation.allowed",
            actor="evaluator",
            split_role="development",
            payload={"request_id": "request.alpha.1"},
        ),
        _event(
            "evaluation.denied",
            actor="evaluator",
            split_role="gate",
            payload={"request_id": "request.alpha.2"},
        ),
    ]
    return [ledger.append(draft) for draft in drafts]


def _decoded(path: Path) -> dict[str, Any]:
    value = decode_json_bytes(path.read_bytes())
    assert isinstance(value, dict)
    return value


def test_evidence_ledger_replays_candidate_and_split_access_trace_from_zero(
    tmp_path: Path,
) -> None:
    ledger = EvidenceLedger.create(tmp_path / "ledger")
    paths = _append_trace(ledger)
    events = [_decoded(path) for path in paths]

    verified = ledger.verify()
    replay = ledger.replay(verified)

    assert [event["sequence"] for event in events] == list(range(1, 7))
    assert events[0]["prev_event_hash"] is None
    assert [event["prev_event_hash"] for event in events[1:]] == [
        event["event_hash"] for event in events[:-1]
    ]
    assert all(
        path.read_bytes() == canonical_json_bytes(event)
        for path, event in zip(paths, events)
    )
    assert (verified.last_sequence, verified.last_event_hash) == (
        6,
        events[-1]["event_hash"],
    )
    assert (replay.run_id, replay.contract_hash) == (RUN_ID, CONTRACT_HASH)
    assert [event["event_type"] for event in replay.candidate_trace] == [
        "hypothesis.proposed",
        "candidate.validated",
    ]
    assert [event["event_type"] for event in replay.split_access_trace] == [
        "evaluation.requested",
        "evaluation.allowed",
        "evaluation.denied",
    ]
    assert [event["split_role"] for event in replay.split_access_trace] == [
        "development",
        "development",
        "gate",
    ]


def test_evidence_ledger_rejects_overwrite_and_preserves_original_bytes(
    tmp_path: Path,
) -> None:
    ledger = EvidenceLedger.create(tmp_path / "ledger")
    original = _event(
        "evaluation.allowed",
        actor="evaluator",
        split_role="development",
        payload={"decision": "allow"},
    )
    replacement = {**original, "payload": {"decision": "deny"}}
    event_path = ledger.append(original)
    original_bytes = event_path.read_bytes()

    with pytest.raises(EvaluationPersistenceError, match="already exists") as caught:
        ledger.append(replacement)

    assert caught.value.committed is False
    assert event_path.read_bytes() == original_bytes


@pytest.mark.parametrize(
    ("challenge", "message"),
    [("delete", "head"), ("reorder", "order"), ("tamper", "hash")],
)
def test_evidence_ledger_verify_rejects_deletion_reorder_or_tamper(
    tmp_path: Path,
    challenge: str,
    message: str,
) -> None:
    ledger = EvidenceLedger.create(tmp_path / "ledger")
    paths = _append_trace(ledger)
    if challenge == "delete":
        paths[-1].unlink()
    elif challenge == "reorder":
        temporary = tmp_path / "reordered-event"
        paths[1].replace(temporary)
        paths[2].replace(paths[1])
        temporary.replace(paths[2])
    else:
        event = _decoded(paths[1])
        event["payload"]["candidate_id"] = "candidate.tampered"
        paths[1].write_bytes(canonical_json_bytes(event))

    with pytest.raises(EvaluationIntegrityError, match=message):
        ledger.verify()


@pytest.mark.parametrize("field", ["sequence", "prev_event_hash"])
def test_evidence_ledger_verify_rejects_sequence_or_prev_hash_break(
    tmp_path: Path,
    field: str,
) -> None:
    ledger = EvidenceLedger.create(tmp_path / "ledger")
    paths = _append_trace(ledger)
    event = _decoded(paths[1])
    event[field] = 99 if field == "sequence" else "f" * 64
    paths[1].write_bytes(canonical_json_bytes(event))

    with pytest.raises(EvaluationIntegrityError, match="sequence|previous hash"):
        ledger.verify()


def test_evidence_ledger_verify_rejects_duplicate_event_ids(tmp_path: Path) -> None:
    ledger = EvidenceLedger.create(tmp_path / "ledger")
    paths = _append_trace(ledger)
    first, second = _decoded(paths[0]), _decoded(paths[1])
    second["event_id"] = first["event_id"]
    duplicate_path = paths[1].with_name(
        f"{second['sequence']:020d}-"
        f"{sha256(first['event_id'].encode('utf-8')).hexdigest()}.json"
    )
    paths[1].replace(duplicate_path)
    duplicate_path.write_bytes(canonical_json_bytes(second))

    with pytest.raises(EvaluationIntegrityError, match="duplicate event_id"):
        ledger.verify()


@pytest.mark.parametrize("challenge", ["forged", "stale"])
def test_evidence_ledger_replay_requires_current_verified_snapshot(
    tmp_path: Path,
    challenge: str,
) -> None:
    ledger = EvidenceLedger.create(tmp_path / "ledger")
    _append_trace(ledger)
    verified = ledger.verify()
    if challenge == "forged":
        verified = replace(verified, last_sequence=99)
    else:
        ledger.append(_event("node.updated", payload={"status": "done"}))

    with pytest.raises(EvaluationIntegrityError, match="current verified"):
        ledger.replay(verified)
