"""Canonical hash-chained evidence storage and minimal replay for C10."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Final, cast

from q_arbor.evaluation import (
    EvaluationDecodeError,
    EvaluationIntegrityError,
    EvaluationPersistenceError,
    EvaluationSchemaError,
)
from q_arbor.evaluation.codec import (
    FrozenJSON,
    JSONValue,
    atomic_write,
    canonical_json_bytes,
    decode_json_bytes,
    deep_freeze,
    normalize_mapping,
    require_identifier,
    validate_discriminator,
)
from q_arbor.hypotheses.mutations import compute_ledger_event_hash


_HEAD_NAME: Final = "ledger.head"
_EVENT_NAME_RE: Final = re.compile(
    r"(?P<sequence>[0-9]{20})-(?P<event_id_hash>[a-f0-9]{64})\.json"
)
_CHAIN_FIELDS: Final = frozenset({"sequence", "prev_event_hash", "event_hash"})
_CANDIDATE_EVENTS: Final = frozenset(
    {
        "hypothesis.proposed",
        "candidate.validated",
        "candidate.rejected",
        "candidate.duplicate",
    }
)
_SPLIT_ACCESS_EVENTS: Final = frozenset(
    {
        "evaluation.requested",
        "evaluation.allowed",
        "evaluation.denied",
        "evaluation.response_replayed",
        "evaluation.completed",
    }
)


@dataclass(frozen=True, slots=True)
class VerifiedLedger:
    """Immutable events accepted by a complete on-disk integrity check."""

    events: tuple[Mapping[str, FrozenJSON], ...]
    run_id: str | None
    contract_hash: str | None
    last_sequence: int
    last_event_hash: str | None


@dataclass(frozen=True, slots=True)
class LedgerReplay:
    """Minimal run identity, candidate history, and split-access history."""

    run_id: str
    contract_hash: str
    last_sequence: int
    last_event_hash: str
    candidate_trace: tuple[Mapping[str, FrozenJSON], ...]
    split_access_trace: tuple[Mapping[str, FrozenJSON], ...]


def _canonical_object(raw: bytes, label: str) -> dict[str, JSONValue]:
    try:
        decoded = decode_json_bytes(raw)
        if not isinstance(decoded, Mapping):
            raise EvaluationIntegrityError(f"evidence ledger {label} is not an object")
        normalized = normalize_mapping(decoded)
    except EvaluationIntegrityError:
        raise
    except (EvaluationDecodeError, EvaluationSchemaError) as exc:
        raise EvaluationIntegrityError(
            f"evidence ledger {label} is invalid"
        ) from exc
    if canonical_json_bytes(normalized) != raw:
        raise EvaluationIntegrityError(
            f"evidence ledger {label} is not canonical"
        )
    return normalized


def _read_event(path: Path) -> dict[str, JSONValue]:
    try:
        event = _canonical_object(path.read_bytes(), "event")
        validate_discriminator(event, "ledger_event")
        return event
    except EvaluationIntegrityError:
        raise
    except (EvaluationDecodeError, EvaluationSchemaError) as exc:
        raise EvaluationIntegrityError(
            "evidence ledger event is not a valid C6 LedgerEvent"
        ) from exc
    except OSError as exc:
        raise EvaluationPersistenceError(
            "unable to read evidence ledger event",
            committed=False,
        ) from exc


@dataclass(frozen=True, slots=True)
class EvidenceLedger:
    """Store canonical C6 events once and verify their ordered hash chain."""

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

    def _paths(self) -> tuple[Path, ...]:
        try:
            return tuple(sorted(self._root.glob("*.json")))
        except OSError as exc:
            raise EvaluationPersistenceError(
                "unable to list evidence ledger events",
                committed=False,
            ) from exc

    def _head(self) -> dict[str, JSONValue] | None:
        try:
            return _canonical_object(
                (self._root / _HEAD_NAME).read_bytes(),
                "head",
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise EvaluationPersistenceError(
                "unable to read evidence ledger head",
                committed=False,
            ) from exc

    def append(self, event: Mapping[str, Any]) -> Path:
        draft = normalize_mapping(event)
        if _CHAIN_FIELDS.intersection(draft):
            raise EvaluationSchemaError(
                "ledger append requires an event without chain fields"
            )
        event_id = require_identifier(draft.get("event_id"), "ledger event_id")
        verified = self.verify()
        if any(item["event_id"] == event_id for item in verified.events):
            raise EvaluationPersistenceError(
                "evidence ledger event already exists",
                committed=False,
            )

        draft["sequence"] = verified.last_sequence + 1
        draft["prev_event_hash"] = verified.last_event_hash
        draft["event_hash"] = compute_ledger_event_hash(draft)
        validate_discriminator(draft, "ledger_event")
        if verified.events and (
            draft["run_id"] != verified.run_id
            or draft["contract_hash"] != verified.contract_hash
        ):
            raise EvaluationIntegrityError(
                "evidence ledger run or contract identity changed"
            )

        sequence = cast(int, draft["sequence"])
        event_id_hash = sha256(event_id.encode("utf-8")).hexdigest()
        destination = self._root / f"{sequence:020d}-{event_id_hash}.json"
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
                stream.write(canonical_json_bytes(draft))
                stream.flush()
                os.fsync(stream.fileno())
        except (OSError, TypeError, ValueError) as exc:
            raise EvaluationPersistenceError(
                "unable to append evidence ledger event",
                committed=True,
            ) from exc

        head = {
            "run_id": draft["run_id"],
            "contract_hash": draft["contract_hash"],
            "last_sequence": draft["sequence"],
            "last_event_hash": draft["event_hash"],
        }
        try:
            atomic_write(self._root / _HEAD_NAME, canonical_json_bytes(head))
        except EvaluationPersistenceError as exc:
            raise EvaluationPersistenceError(
                "unable to commit evidence ledger head",
                committed=True,
            ) from exc
        return destination

    def verify(self) -> VerifiedLedger:
        paths = self._paths()
        head = self._head()
        if not paths:
            if head is not None:
                raise EvaluationIntegrityError(
                    "evidence ledger head does not match its events"
                )
            return VerifiedLedger((), None, None, 0, None)
        if head is None:
            raise EvaluationIntegrityError("evidence ledger head is missing")

        events: list[Mapping[str, FrozenJSON]] = []
        event_ids: set[str] = set()
        previous_hash: str | None = None
        run_id: str | None = None
        contract_hash: str | None = None
        for sequence, path in enumerate(paths, start=1):
            match = _EVENT_NAME_RE.fullmatch(path.name)
            if match is None or path.is_symlink() or not path.is_file():
                raise EvaluationIntegrityError(
                    "evidence ledger event order path is invalid"
                )
            event = _read_event(path)
            if (
                int(match.group("sequence")) != sequence
                or event["sequence"] != sequence
            ):
                raise EvaluationIntegrityError(
                    "evidence ledger event sequence/order is broken"
                )

            event_id = cast(str, event["event_id"])
            if match.group("event_id_hash") != sha256(
                event_id.encode("utf-8")
            ).hexdigest():
                raise EvaluationIntegrityError(
                    "evidence ledger event_id does not match its path"
                )
            if event_id in event_ids:
                raise EvaluationIntegrityError(
                    "evidence ledger contains a duplicate event_id"
                )
            event_ids.add(event_id)
            if event["prev_event_hash"] != previous_hash:
                raise EvaluationIntegrityError(
                    "evidence ledger previous hash link is broken"
                )
            if event["event_hash"] != compute_ledger_event_hash(event):
                raise EvaluationIntegrityError(
                    "evidence ledger event hash does not match its content"
                )

            if sequence == 1:
                run_id = cast(str, event["run_id"])
                contract_hash = cast(str, event["contract_hash"])
            elif event["run_id"] != run_id or event["contract_hash"] != contract_hash:
                raise EvaluationIntegrityError(
                    "evidence ledger run or contract identity changed"
                )
            previous_hash = cast(str, event["event_hash"])
            events.append(
                cast(Mapping[str, FrozenJSON], deep_freeze(event))
            )

        assert run_id is not None and contract_hash is not None
        assert previous_hash is not None
        expected_head: dict[str, JSONValue] = {
            "run_id": run_id,
            "contract_hash": contract_hash,
            "last_sequence": len(events),
            "last_event_hash": previous_hash,
        }
        if head != expected_head:
            raise EvaluationIntegrityError(
                "evidence ledger head does not match its events"
            )
        return VerifiedLedger(
            tuple(events), run_id, contract_hash, len(events), previous_hash
        )

    def replay(self, verified: VerifiedLedger) -> LedgerReplay:
        if not isinstance(verified, VerifiedLedger):
            raise EvaluationIntegrityError("ledger replay requires verified events")
        if (
            verified.run_id is None
            or verified.contract_hash is None
            or verified.last_event_hash is None
        ):
            raise EvaluationIntegrityError("an empty evidence ledger cannot replay")
        return LedgerReplay(
            run_id=verified.run_id,
            contract_hash=verified.contract_hash,
            last_sequence=verified.last_sequence,
            last_event_hash=verified.last_event_hash,
            candidate_trace=tuple(
                event
                for event in verified.events
                if event["event_type"] in _CANDIDATE_EVENTS
            ),
            split_access_trace=tuple(
                event
                for event in verified.events
                if event["event_type"] in _SPLIT_ACCESS_EVENTS
            ),
        )


__all__ = ["EvidenceLedger", "LedgerReplay", "VerifiedLedger"]
