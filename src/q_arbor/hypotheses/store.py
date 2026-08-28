"""Event-first persistence for the quantitative hypothesis tree.

The append-only journal is authoritative and ``tree.json`` is a materialized
view. Tree mutations remain append-only; the evaluation ledger and session
recovery are handled by their dedicated product modules.
"""

from __future__ import annotations

import fcntl
import os
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

from .codec import (
    JSONValue,
    canonical_normalized_bytes,
    decode_json_bytes,
    normalize_mapping,
    validate_discriminator,
)
from .errors import (
    HypothesisError,
    TreeConflictError,
    TreeIntegrityError,
    TreePersistenceError,
)
from .invariants import require_identifier, require_sha256
from .models import NodeDraft, QHypothesisTree, load_tree
from .mutations import (
    TreeMutation,
    apply_tree_event,
    prepare_mutation,
    prepare_run_started,
)

Clock = Callable[[], datetime]
EventIdFactory = Callable[[int], str]
FaultHook = Callable[[str], None]

_ZERO_HASH = "0" * 64
_ACTORS = frozenset(
    {"coordinator", "executor", "evaluator", "finalizer", "system", "user"}
)


@dataclass(frozen=True, slots=True)
class TreeVerification:
    """Verified correspondence between one journal and its snapshot."""

    event_count: int
    last_sequence: int
    last_event_hash: str
    tree_revision: int
    tree_hash: str


@dataclass(frozen=True, slots=True)
class _Replay:
    events: tuple[dict[str, JSONValue], ...]
    states: tuple[QHypothesisTree, ...]
    idempotency: Mapping[str, tuple[str, int | None, QHypothesisTree]]

    @property
    def tree(self) -> QHypothesisTree:
        return self.states[-1]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _default_event_id(sequence: int) -> str:
    return f"event.{sequence}.{uuid.uuid4().hex}"


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TreePersistenceError("clock must return a timezone-aware datetime")
    try:
        offset = value.utcoffset()
        if offset is None:
            raise ValueError("missing UTC offset")
        rendered = value.astimezone(UTC).isoformat()
    except (OverflowError, ValueError) as exc:
        raise TreePersistenceError("clock returned an invalid datetime") from exc
    if rendered.endswith("+00:00"):
        rendered = rendered[:-6] + "Z"
    return rendered


def _event_hash(event: Mapping[str, Any]) -> str:
    content = normalize_mapping(event)
    content.pop("event_hash", None)
    return sha256(canonical_normalized_bytes(content)).hexdigest()


def _checked_actor(value: str) -> str:
    try:
        actor = require_identifier(value, "actor")
    except HypothesisError as exc:
        raise TreeConflictError("actor is invalid") from exc
    if actor not in _ACTORS:
        raise TreeConflictError("actor is invalid")
    return actor


def _idempotency_request_hash(request_hash: str, actor: str) -> str:
    """Bind a public write request to the audit principal that issued it."""

    require_sha256(request_hash, "request_hash")
    checked_actor = _checked_actor(actor)
    return sha256(
        canonical_normalized_bytes(
            {"request_hash": request_hash, "actor": checked_actor}
        )
    ).hexdigest()


def _build_event(
    *,
    run_id: str,
    contract_hash: str,
    sequence: int,
    event_id: str,
    timestamp: str,
    event_type: str,
    actor: str,
    node_id: str | None,
    payload: Mapping[str, Any],
    prev_event_hash: str | None,
) -> dict[str, JSONValue]:
    event: dict[str, JSONValue] = {
        "schema_version": "1.0",
        "run_id": run_id,
        "sequence": sequence,
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "actor": actor,
        "contract_hash": contract_hash,
        "node_id": node_id,
        "attempt_id": None,
        "split_role": "none",
        "payload": normalize_mapping(payload),
        "prev_event_hash": prev_event_hash,
        "event_hash": _ZERO_HASH,
    }
    event["event_hash"] = _event_hash(event)
    validate_discriminator(event, "ledger_event")
    return event


def _fsync_directory(directory: Path) -> None:
    descriptor: int | None = None
    synchronized = False
    try:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        os.fsync(descriptor)
        synchronized = True
    except OSError as exc:
        raise TreePersistenceError(
            "unable to synchronize tree state directory"
        ) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as exc:
                if synchronized:
                    raise TreePersistenceError(
                        "unable to close tree state directory"
                    ) from exc


class HypothesisTreeStore:
    """Serialize, journal, replay, and recover Q-Hypothesis Tree mutations."""

    __slots__ = (
        "_clock",
        "_directory",
        "_event_id_factory",
        "_events_path",
        "_fault_hook",
        "_lock_path",
        "_tree_path",
    )

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        clock: Clock | None = None,
        event_id_factory: EventIdFactory | None = None,
        fault_hook: FaultHook | None = None,
    ) -> None:
        try:
            root = Path(directory)
        except (TypeError, ValueError) as exc:
            raise TreePersistenceError("invalid tree state directory") from exc
        self._directory = root
        self._tree_path = root / "tree.json"
        self._events_path = root / "tree.events.jsonl"
        self._lock_path = root / "tree.lock"
        self._clock = clock or _utc_now
        self._event_id_factory = event_id_factory or _default_event_id
        self._fault_hook = fault_hook

    @classmethod
    def create(
        cls,
        directory: str | os.PathLike[str],
        *,
        run_id: str,
        contract_hash: str,
        root: NodeDraft,
        clock: Clock | None = None,
        event_id_factory: EventIdFactory | None = None,
        fault_hook: FaultHook | None = None,
    ) -> HypothesisTreeStore:
        """Create a new store with one durable ``run.started`` event."""

        if not isinstance(root, NodeDraft):
            raise TypeError("root must be a NodeDraft")
        if root.parent_id is not None:
            raise TreeConflictError("the initial root draft must have parent_id null")
        checked_run_id = require_identifier(run_id, "run_id")
        checked_contract_hash = require_sha256(contract_hash, "contract_hash")
        store = cls(
            directory,
            clock=clock,
            event_id_factory=event_id_factory,
            fault_hook=fault_hook,
        )
        try:
            store._directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TreePersistenceError("unable to create tree state directory") from exc
        if not store._directory.is_dir():
            raise TreePersistenceError("tree state path is not a directory")

        with store._exclusive_lock():
            if store._tree_path.exists() or store._events_path.exists():
                raise TreeConflictError("tree state directory is already initialized")
            try:
                unexpected = [
                    path.name
                    for path in store._directory.iterdir()
                    if path != store._lock_path
                ]
            except OSError as exc:
                raise TreePersistenceError(
                    "unable to inspect tree state directory"
                ) from exc
            if unexpected:
                raise TreeConflictError("tree state directory is not empty")
            sequence = 1
            event_id = store._new_event_id(sequence)
            node_id, payload = prepare_run_started(
                run_id=checked_run_id,
                contract_hash=checked_contract_hash,
                root=root,
                event_id=event_id,
            )
            event = _build_event(
                run_id=checked_run_id,
                contract_hash=checked_contract_hash,
                sequence=sequence,
                event_id=event_id,
                timestamp=store._new_timestamp(),
                event_type="run.started",
                actor="system",
                node_id=node_id,
                payload=payload,
                prev_event_hash=None,
            )
            initial = store._reduce(None, event)
            store._append_event(event)
            if store._fault_hook is not None:
                store._fault_hook("after_event_fsync")
            initial.write(store._tree_path)
            _fsync_directory(store._directory)
        return store

    @classmethod
    def open(
        cls,
        directory: str | os.PathLike[str],
        *,
        clock: Clock | None = None,
        event_id_factory: EventIdFactory | None = None,
        fault_hook: FaultHook | None = None,
    ) -> HypothesisTreeStore:
        """Open an existing state directory without mutating it."""

        store = cls(
            directory,
            clock=clock,
            event_id_factory=event_id_factory,
            fault_hook=fault_hook,
        )
        try:
            if not store._directory.is_dir():
                raise TreePersistenceError("tree state directory does not exist")
        except OSError as exc:
            raise TreePersistenceError(
                "unable to inspect tree state directory"
            ) from exc
        return store

    @property
    def directory(self) -> Path:
        return self._directory

    def load(self) -> QHypothesisTree:
        """Load a snapshot only after proving it equals journal replay."""

        with self._exclusive_lock():
            replay = self._replay_journal()
            return self._check_snapshot(replay, repair=False)

    def apply(
        self,
        mutation: TreeMutation,
        *,
        expected_revision: int,
        idempotency_key: str,
        actor: str = "coordinator",
    ) -> QHypothesisTree:
        """Durably apply one mutation under revision and idempotency guards."""

        if not isinstance(mutation, TreeMutation):
            raise TypeError("mutation must be a TreeMutation")
        if isinstance(expected_revision, bool) or not isinstance(
            expected_revision, int
        ):
            raise TreeConflictError("expected_revision must be an integer")
        if expected_revision < 0:
            raise TreeConflictError("expected_revision cannot be negative")
        checked_key = require_identifier(idempotency_key, "idempotency_key")
        checked_actor = _checked_actor(actor)
        with self._exclusive_lock():
            replay = self._replay_journal()
            current = self._check_snapshot(replay, repair=True)
            request_hash = _idempotency_request_hash(
                mutation.request_hash(
                    expected_revision=expected_revision,
                    idempotency_key=checked_key,
                ),
                checked_actor,
            )
            previous = replay.idempotency.get(checked_key)
            if previous is not None:
                prior_hash, _prior_revision, prior_tree = previous
                if prior_hash != request_hash:
                    raise TreeConflictError(
                        "idempotency key was already used for a different request"
                    )
                return prior_tree
            if expected_revision != current.revision:
                raise TreeConflictError("expected_revision is stale")

            sequence = current.revision + 2
            event_id = self._new_event_id(sequence)
            if any(event["event_id"] == event_id for event in replay.events):
                raise TreePersistenceError(
                    "event_id_factory produced an existing event_id"
                )
            event_type, node_id, payload = prepare_mutation(
                current,
                mutation,
                event_id=event_id,
                idempotency_key=checked_key,
            )
            event = _build_event(
                run_id=current.run_id,
                contract_hash=current.contract_hash,
                sequence=sequence,
                event_id=event_id,
                timestamp=self._new_timestamp(),
                event_type=event_type,
                actor=checked_actor,
                node_id=node_id,
                payload=payload,
                prev_event_hash=current.ledger_head["last_event_hash"],
            )
            result = self._reduce(current, event)
            self._append_event(event)
            if self._fault_hook is not None:
                self._fault_hook("after_event_fsync")
            result.write(self._tree_path)
            _fsync_directory(self._directory)
            return result

    def recover(self) -> QHypothesisTree:
        """Rebuild a missing or exact-prefix snapshot from verified history."""

        with self._exclusive_lock():
            replay = self._replay_journal()
            return self._check_snapshot(replay, repair=True)

    def verify(self) -> TreeVerification:
        """Verify the journal, deterministic replay, and exact snapshot."""

        with self._exclusive_lock():
            replay = self._replay_journal()
            tree = self._check_snapshot(replay, repair=False)
            return TreeVerification(
                event_count=len(replay.events),
                last_sequence=cast(int, tree.ledger_head["last_sequence"]),
                last_event_hash=cast(str, tree.ledger_head["last_event_hash"]),
                tree_revision=tree.revision,
                tree_hash=tree.tree_hash,
            )

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        descriptor: int | None = None
        try:
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._lock_path, flags, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise TreePersistenceError("unable to lock tree state") from exc
        body_succeeded = False
        try:
            yield
            body_succeeded = True
        finally:
            release_error: OSError | None = None
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError as exc:
                    release_error = exc
                try:
                    os.close(descriptor)
                except OSError as exc:
                    if release_error is None:
                        release_error = exc
            if release_error is not None and body_succeeded:
                raise TreePersistenceError(
                    "unable to release tree state lock"
                ) from release_error

    def _new_event_id(self, sequence: int) -> str:
        try:
            value = self._event_id_factory(sequence)
            return require_identifier(value, "event_id")
        except Exception as exc:
            raise TreePersistenceError("event_id_factory failed") from exc

    def _new_timestamp(self) -> str:
        try:
            value = self._clock()
            return _timestamp(value)
        except TreePersistenceError:
            raise
        except Exception as exc:
            raise TreePersistenceError("clock failed") from exc

    def _append_event(self, event: Mapping[str, Any]) -> None:
        content = canonical_normalized_bytes(event) + b"\n"
        descriptor: int | None = None
        appended = False
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._events_path, flags, 0o600)
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short journal write")
                view = view[written:]
            os.fsync(descriptor)
            _fsync_directory(self._directory)
            appended = True
        except OSError as exc:
            raise TreePersistenceError("unable to append hypothesis event") from exc
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    if appended:
                        raise TreePersistenceError(
                            "unable to close hypothesis journal"
                        ) from exc

    def _read_journal_lines(self) -> tuple[bytes, ...]:
        try:
            raw = self._events_path.read_bytes()
        except FileNotFoundError as exc:
            raise TreeIntegrityError("authoritative tree journal is missing") from exc
        except OSError as exc:
            raise TreePersistenceError("unable to read hypothesis journal") from exc
        if not raw:
            raise TreeIntegrityError("authoritative tree journal is empty")
        if not raw.endswith(b"\n"):
            raise TreeIntegrityError("hypothesis journal has a partial final event")
        lines = tuple(raw[:-1].split(b"\n"))
        if not lines or any(not line for line in lines):
            raise TreeIntegrityError("hypothesis journal contains an empty event")
        return lines

    def _replay_journal(self) -> _Replay:
        events: list[dict[str, JSONValue]] = []
        states: list[QHypothesisTree] = []
        idempotency: dict[str, tuple[str, int | None, QHypothesisTree]] = {}
        seen_event_ids: set[str] = set()
        previous_hash: str | None = None
        run_id: str | None = None
        contract_hash: str | None = None
        current: QHypothesisTree | None = None

        for sequence, raw_line in enumerate(self._read_journal_lines(), start=1):
            try:
                decoded = decode_json_bytes(raw_line)
                if not isinstance(decoded, Mapping):
                    raise TreeIntegrityError("journal event must be a JSON object")
                event = normalize_mapping(decoded)
                validate_discriminator(event, "ledger_event")
            except TreeIntegrityError:
                raise
            except HypothesisError as exc:
                raise TreeIntegrityError("hypothesis journal event is invalid") from exc
            if canonical_normalized_bytes(event) != raw_line:
                raise TreeIntegrityError("hypothesis journal event is not canonical")
            if event["sequence"] != sequence:
                raise TreeIntegrityError(
                    "hypothesis journal sequence is not contiguous"
                )
            if event["prev_event_hash"] != previous_hash:
                raise TreeIntegrityError("hypothesis journal hash chain is broken")
            if event["event_hash"] != _event_hash(event):
                raise TreeIntegrityError("hypothesis journal event hash is invalid")
            event_id = cast(str, event["event_id"])
            if event_id in seen_event_ids:
                raise TreeIntegrityError("hypothesis journal reuses an event_id")
            seen_event_ids.add(event_id)
            if sequence == 1:
                if event["event_type"] != "run.started":
                    raise TreeIntegrityError(
                        "first hypothesis event must be run.started"
                    )
                run_id = cast(str, event["run_id"])
                contract_hash = cast(str, event["contract_hash"])
            elif event["event_type"] == "run.started":
                raise TreeIntegrityError("run.started may occur only once")
            if event["run_id"] != run_id or event["contract_hash"] != contract_hash:
                raise TreeIntegrityError("journal run or contract identity changed")

            current = self._reduce(current, event)
            if current.revision != sequence - 1:
                raise TreeIntegrityError("journal event produced the wrong revision")
            events.append(event)
            states.append(current)
            previous_hash = cast(str, event["event_hash"])

            payload = cast(dict[str, JSONValue], event["payload"])
            key = payload.get("idempotency_key")
            request_hash = payload.get("request_hash")
            expected = payload.get("expected_revision")
            result_revision = payload.get("result_revision")
            valid_expected = (
                expected is None
                if sequence == 1
                else not isinstance(expected, bool)
                and isinstance(expected, int)
                and expected == sequence - 2
            )
            if (
                not isinstance(key, str)
                or not isinstance(request_hash, str)
                or not valid_expected
                or result_revision != sequence - 1
            ):
                raise TreeIntegrityError("journal mutation receipt is incomplete")
            try:
                require_identifier(key, "journal idempotency_key")
                require_sha256(request_hash, "journal request_hash")
            except HypothesisError as exc:
                raise TreeIntegrityError(
                    "journal mutation identity is invalid"
                ) from exc
            previous = idempotency.get(key)
            if previous is not None:
                raise TreeIntegrityError("journal contains a reused idempotency key")
            bound_request_hash = _idempotency_request_hash(
                request_hash, cast(str, event["actor"])
            )
            idempotency[key] = (
                bound_request_hash,
                cast(int | None, expected),
                current,
            )

        if current is None:
            raise TreeIntegrityError("hypothesis journal did not produce a tree")
        return _Replay(tuple(events), tuple(states), idempotency)

    def _reduce(
        self,
        tree: QHypothesisTree | None,
        event: Mapping[str, Any],
    ) -> QHypothesisTree:
        try:
            return apply_tree_event(tree, event)
        except TreeIntegrityError:
            raise
        except (HypothesisError, KeyError, TypeError, ValueError, IndexError) as exc:
            raise TreeIntegrityError("hypothesis event cannot be replayed") from exc

    def _read_snapshot(self) -> QHypothesisTree | None:
        try:
            self._tree_path.stat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise TreePersistenceError("unable to inspect tree snapshot") from exc
        try:
            return load_tree(self._tree_path)
        except TreePersistenceError:
            raise
        except HypothesisError as exc:
            raise TreeIntegrityError("tree snapshot is invalid") from exc

    def _check_snapshot(self, replay: _Replay, *, repair: bool) -> QHypothesisTree:
        snapshot = self._read_snapshot()
        authoritative = replay.tree
        if snapshot is None:
            if not repair:
                raise TreeIntegrityError("tree snapshot is missing")
            authoritative.write(self._tree_path)
            _fsync_directory(self._directory)
            return authoritative
        if (
            snapshot.run_id != authoritative.run_id
            or snapshot.contract_hash != authoritative.contract_hash
        ):
            raise TreeIntegrityError(
                "snapshot run or contract identity differs from journal"
            )
        if snapshot.revision > authoritative.revision:
            raise TreeIntegrityError("tree snapshot is ahead of its journal")
        expected = replay.states[snapshot.revision]
        if snapshot.to_dict() != expected.to_dict():
            raise TreeIntegrityError(
                "tree snapshot does not match deterministic replay"
            )
        if snapshot.revision < authoritative.revision:
            if not repair:
                raise TreeIntegrityError("tree snapshot is behind its journal")
            authoritative.write(self._tree_path)
            _fsync_directory(self._directory)
            return authoritative
        return snapshot


__all__ = ["HypothesisTreeStore", "TreeVerification"]
