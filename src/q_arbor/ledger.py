"""Minimal append-only evidence storage for C10."""

from __future__ import annotations

import os
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from q_arbor.evaluation import EvaluationPersistenceError
from q_arbor.evaluation.codec import require_identifier


@dataclass(frozen=True, slots=True)
class EvidenceLedger:
    """Store opaque event bytes once under a trusted event identity."""

    _root: Path

    @classmethod
    def create(cls, root: str | os.PathLike[str]) -> EvidenceLedger:
        path = Path(root).absolute()
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise EvaluationPersistenceError(
                "unable to create evidence ledger",
                committed=False,
            ) from exc
        if not path.is_dir():
            raise EvaluationPersistenceError(
                "evidence ledger root is not a directory",
                committed=False,
            )
        return cls(path)

    def append(self, *, event_id: str, event_bytes: bytes) -> Path:
        identifier = require_identifier(event_id, "ledger event_id")
        digest = sha256(identifier.encode("utf-8")).hexdigest()
        destination = self._root / f"{digest}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            descriptor = os.open(destination, flags, 0o600)
        except FileExistsError as exc:
            raise EvaluationPersistenceError(
                "evidence ledger event already exists",
                committed=False,
            ) from exc
        except OSError as exc:
            raise EvaluationPersistenceError(
                "unable to create evidence ledger event",
                committed=False,
            ) from exc
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(event_bytes)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception as exc:
            raise EvaluationPersistenceError(
                "unable to append evidence ledger event",
                committed=True,
            ) from exc
        return destination


__all__ = ["EvidenceLedger"]
