from __future__ import annotations

from pathlib import Path

import pytest

from q_arbor.evaluation import EvaluationPersistenceError
from q_arbor.ledger import EvidenceLedger


def test_evidence_ledger_rejects_overwrite_and_preserves_original_bytes(
    tmp_path: Path,
) -> None:
    ledger = EvidenceLedger.create(tmp_path / "ledger")
    original = b'{"event_id":"event.evaluate.0001","kind":"evaluate"}\n'
    replacement = b'{"event_id":"event.evaluate.0001","kind":"deny"}\n'
    event_path = ledger.append(
        event_id="event.evaluate.0001",
        event_bytes=original,
    )

    with pytest.raises(EvaluationPersistenceError, match="already exists") as caught:
        ledger.append(
            event_id="event.evaluate.0001",
            event_bytes=replacement,
        )

    assert caught.value.committed is False
    assert event_path.read_bytes() == original
