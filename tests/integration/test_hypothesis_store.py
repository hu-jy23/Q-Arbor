from __future__ import annotations

import copy
import fcntl
import json
import multiprocessing
import queue
import time
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from q_arbor.hypotheses import (
    HypothesisTreeStore,
    NodeDraft,
    TreeConflictError,
    TreeIntegrityError,
    TreeMutation,
    TreePersistenceError,
    TreeVerification,
    apply_tree_event,
    freeze_tree,
)
from q_arbor.spec import load_schema
from tests.hypothesis_helpers import (
    CONTRACT_HASH,
    canonical_json,
    deterministic_clock,
    deterministic_event_id,
    node_draft_kwargs,
    node_record,
)


def _root_draft() -> NodeDraft:
    return NodeDraft(**node_draft_kwargs("root", parent_id=None, proposal_order=1))


def _child_draft(node_id: str, proposal_order: int) -> NodeDraft:
    return NodeDraft(
        **node_draft_kwargs(
            node_id,
            parent_id="root",
            proposal_order=proposal_order,
        )
    )


def _create_store(directory: Path) -> HypothesisTreeStore:
    return HypothesisTreeStore.create(
        directory,
        run_id="run.store",
        contract_hash=CONTRACT_HASH,
        root=_root_draft(),
        clock=deterministic_clock,
        event_id_factory=deterministic_event_id,
    )


def _events(directory: Path) -> list[dict[str, Any]]:
    lines = (directory / "tree.events.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def _event_hash(event: dict[str, Any]) -> str:
    import hashlib

    content = copy.deepcopy(event)
    content.pop("event_hash", None)
    return hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest()


def _rewrite_events(directory: Path, events: list[dict[str, Any]]) -> None:
    text = "".join(f"{canonical_json(event)}\n" for event in events)
    (directory / "tree.events.jsonl").write_text(text, encoding="utf-8")


def _replace_nested_key(value: Any, key: str, replacement: Any) -> int:
    replacements = 0
    if isinstance(value, dict):
        for child_key, child in value.items():
            if child_key == key:
                value[child_key] = replacement
                replacements += 1
            else:
                replacements += _replace_nested_key(child, key, replacement)
    elif isinstance(value, list):
        for child in value:
            replacements += _replace_nested_key(child, key, replacement)
    return replacements


def _multiprocess_add_worker(
    directory: str,
    worker_index: int,
    start_gate: Any,
    result_queue: Any,
) -> None:
    try:
        store = HypothesisTreeStore.open(
            directory,
            clock=deterministic_clock,
            event_id_factory=deterministic_event_id,
        )
        mutation = TreeMutation.add_node(
            _child_draft(f"worker.{worker_index}", worker_index + 2)
        )
        if not start_gate.wait(timeout=10):
            raise TimeoutError("multiprocess start gate")
        for _ in range(20):
            current = store.load()
            try:
                result = store.apply(
                    mutation,
                    expected_revision=current.revision,
                    idempotency_key=f"multiprocess.{worker_index}",
                    actor="coordinator",
                )
            except TreeConflictError:
                continue
            result_queue.put(("ok", worker_index, result.revision))
            return
        raise TimeoutError("mutation did not serialize within 20 retries")
    except BaseException as error:  # pragma: no cover - reported in parent
        result_queue.put(
            ("error", worker_index, type(error).__name__, str(error))
        )


def test_store_serial_mutations_emit_canonical_c6_events_and_replay(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    initial = store.load()
    added = store.apply(
        TreeMutation.add_node(_child_draft("child", 2)),
        expected_revision=0,
        idempotency_key="add.child",
    )
    running = store.apply(
        TreeMutation.update_node(
            "child",
            {
                "status": "running",
                "lifecycle": "running",
                "admissibility": "unevaluated",
            },
        ),
        expected_revision=1,
        idempotency_key="run.child",
    )
    pruned = store.apply(
        TreeMutation.prune_subtree("child", "bounded stop"),
        expected_revision=2,
        idempotency_key="prune.child",
        actor="coordinator",
    )

    assert [initial.revision, added.revision, running.revision, pruned.revision] == [
        0,
        1,
        2,
        3,
    ]
    assert initial.run_state == "development"
    assert pruned.ledger_head["last_sequence"] == pruned.revision + 1
    assert node_record(pruned, "child")["status"] == "pruned"
    assert (directory / "tree.json").is_file()
    assert (directory / "tree.events.jsonl").is_file()

    events = _events(directory)
    assert [event["sequence"] for event in events] == [1, 2, 3, 4]
    assert [event["event_type"] for event in events] == [
        "run.started",
        "hypothesis.proposed",
        "node.updated",
        "prune.completed",
    ]
    assert events[0]["prev_event_hash"] is None
    assert [event["prev_event_hash"] for event in events[1:]] == [
        event["event_hash"] for event in events[:-1]
    ]
    validator = Draft202012Validator(load_schema(), format_checker=FormatChecker())
    raw_lines = (directory / "tree.events.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    for raw_line, event in zip(raw_lines, events, strict=True):
        assert raw_line == canonical_json(event)
        assert event["event_hash"] == _event_hash(event)
        validator.validate({"artifact_type": "ledger_event", "payload": event})

    required_node_fields = set(node_record(initial, "root"))
    assert [
        {node["id"] for node in event["payload"]["changed_nodes"]}
        for event in events[1:]
    ] == [{"root", "child"}, {"child"}, {"child"}]
    for event in events[1:]:
        for changed_node in event["payload"]["changed_nodes"]:
            assert set(changed_node) == required_node_fields

    replayed = apply_tree_event(None, events[0])
    assert replayed.to_dict() == initial.to_dict()
    for event, expected in zip(
        events[1:], (added, running, pruned), strict=True
    ):
        replayed = apply_tree_event(replayed, event)
        assert replayed.to_dict() == expected.to_dict()
    assert isinstance(store.verify(), TreeVerification)


def test_store_idempotent_retry_stale_revision_and_key_conflict(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    mutation = TreeMutation.add_node(_child_draft("child", 2))
    accepted = store.apply(
        mutation,
        expected_revision=0,
        idempotency_key="request.same",
    )
    event_bytes = (directory / "tree.events.jsonl").read_bytes()

    retried = store.apply(
        mutation,
        expected_revision=0,
        idempotency_key="request.same",
    )

    assert retried.to_dict() == accepted.to_dict()
    assert (directory / "tree.events.jsonl").read_bytes() == event_bytes

    with pytest.raises(TreeConflictError):
        store.apply(
            TreeMutation.update_node(
                "root",
                {
                    "status": "running",
                    "lifecycle": "running",
                    "admissibility": "unevaluated",
                },
            ),
            expected_revision=0,
            idempotency_key="request.same",
        )
    with pytest.raises(TreeConflictError):
        store.apply(
            TreeMutation.add_node(_child_draft("other", 3)),
            expected_revision=0,
            idempotency_key="request.stale",
        )

    assert store.load().to_dict() == accepted.to_dict()
    assert (directory / "tree.events.jsonl").read_bytes() == event_bytes


def test_idempotency_key_cannot_hide_a_different_actor(tmp_path: Path) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    mutation = TreeMutation.add_node(_child_draft("child", 2))
    accepted = store.apply(
        mutation,
        expected_revision=0,
        idempotency_key="request.actor-bound",
        actor="coordinator",
    )
    event_bytes = (directory / "tree.events.jsonl").read_bytes()

    with pytest.raises(TreeConflictError):
        store.apply(
            mutation,
            expected_revision=0,
            idempotency_key="request.actor-bound",
            actor="user",
        )

    assert store.load().to_dict() == accepted.to_dict()
    assert (directory / "tree.events.jsonl").read_bytes() == event_bytes


def test_event_id_factory_collision_is_rejected_before_append(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "state"
    store = HypothesisTreeStore.create(
        directory,
        run_id="run.event-id-collision",
        contract_hash=CONTRACT_HASH,
        root=_root_draft(),
        clock=deterministic_clock,
        event_id_factory=lambda _sequence: "event.reused",
    )
    journal_before = (directory / "tree.events.jsonl").read_bytes()
    snapshot_before = store.load().to_dict()

    with pytest.raises(TreePersistenceError):
        store.apply(
            TreeMutation.add_node(_child_draft("child", 2)),
            expected_revision=0,
            idempotency_key="add.child",
        )

    assert (directory / "tree.events.jsonl").read_bytes() == journal_before
    assert store.load().to_dict() == snapshot_before
    store.verify()


class InjectedEventFsyncCrash(RuntimeError):
    pass


def test_event_fsync_precedes_snapshot_and_exact_retry_recovers(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "state"
    _create_store(directory)
    snapshot_before = (directory / "tree.json").read_bytes()
    observed_stages: list[str] = []

    def fault_hook(stage: str) -> None:
        observed_stages.append(stage)
        if stage == "after_event_fsync":
            raise InjectedEventFsyncCrash(stage)

    faulty = HypothesisTreeStore.open(
        directory,
        clock=deterministic_clock,
        event_id_factory=deterministic_event_id,
        fault_hook=fault_hook,
    )
    mutation = TreeMutation.add_node(_child_draft("child", 2))

    with pytest.raises(InjectedEventFsyncCrash):
        faulty.apply(
            mutation,
            expected_revision=0,
            idempotency_key="crash.once",
        )

    assert observed_stages == ["after_event_fsync"]
    assert (directory / "tree.json").read_bytes() == snapshot_before
    assert len(_events(directory)) == 2

    reopened = HypothesisTreeStore.open(
        directory,
        clock=deterministic_clock,
        event_id_factory=deterministic_event_id,
    )
    recovered = reopened.recover()
    event_bytes = (directory / "tree.events.jsonl").read_bytes()
    retried = reopened.apply(
        mutation,
        expected_revision=0,
        idempotency_key="crash.once",
    )

    assert recovered.revision == 1
    assert node_record(recovered, "child")["id"] == "child"
    assert retried.to_dict() == recovered.to_dict()
    assert (directory / "tree.events.jsonl").read_bytes() == event_bytes


def test_missing_snapshot_is_rebuilt_from_authoritative_journal(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    expected = store.apply(
        TreeMutation.add_node(_child_draft("child", 2)),
        expected_revision=0,
        idempotency_key="add.child",
    )
    (directory / "tree.json").unlink()

    recovered = HypothesisTreeStore.open(directory).recover()

    assert recovered.to_dict() == expected.to_dict()
    assert (directory / "tree.json").read_text(
        encoding="utf-8"
    ) == expected.to_json()


def test_event_behind_snapshot_is_rebuilt_from_journal(tmp_path: Path) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    stale_snapshot = (directory / "tree.json").read_bytes()
    expected = store.apply(
        TreeMutation.add_node(_child_draft("child", 2)),
        expected_revision=0,
        idempotency_key="add.child",
    )
    (directory / "tree.json").write_bytes(stale_snapshot)

    recovered = HypothesisTreeStore.open(directory).recover()

    assert recovered.to_dict() == expected.to_dict()
    assert (directory / "tree.json").read_text(
        encoding="utf-8"
    ) == expected.to_json()


def test_snapshot_tamper_with_wrong_hash_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    snapshot = store.load().to_dict()
    snapshot["nodes"][0]["hypothesis"]["mechanism"] = "tampered"
    (directory / "tree.json").write_text(json.dumps(snapshot), encoding="utf-8")

    with pytest.raises(TreeIntegrityError):
        HypothesisTreeStore.open(directory).recover()


def test_chain_consistent_hash_valid_snapshot_tamper_is_rejected(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    snapshot = store.load().to_dict()
    snapshot["nodes"][0]["hypothesis"]["mechanism"] = "hash-valid tamper"
    tampered = freeze_tree(snapshot)
    (directory / "tree.json").write_text(tampered.to_json(), encoding="utf-8")

    with pytest.raises(TreeIntegrityError):
        HypothesisTreeStore.open(directory).recover()


def test_snapshot_ahead_of_journal_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    snapshot = store.load().to_dict()
    snapshot["revision"] += 1
    snapshot["ledger_head"]["last_sequence"] += 1
    ahead = freeze_tree(snapshot)
    (directory / "tree.json").write_text(ahead.to_json(), encoding="utf-8")

    with pytest.raises(TreeIntegrityError):
        HypothesisTreeStore.open(directory).recover()


@pytest.mark.parametrize("tamper", ["hash", "sequence", "partial-json"])
def test_journal_hash_sequence_and_partial_event_tamper_fail_closed(
    tmp_path: Path, tamper: str
) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    store.apply(
        TreeMutation.add_node(_child_draft("child", 2)),
        expected_revision=0,
        idempotency_key="add.child",
    )
    events = _events(directory)

    if tamper == "hash":
        events[1]["payload"]["expected_revision"] = 99
        _rewrite_events(directory, events)
    elif tamper == "sequence":
        events[1]["sequence"] = 3
        events[1]["event_hash"] = _event_hash(events[1])
        _rewrite_events(directory, events)
    else:
        with (directory / "tree.events.jsonl").open(
            "a", encoding="utf-8"
        ) as stream:
            stream.write('{"schema_version":')

    with pytest.raises(TreeIntegrityError):
        HypothesisTreeStore.open(directory).recover()


def test_chain_valid_conflicting_idempotency_history_is_rejected(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    first = store.apply(
        TreeMutation.add_node(_child_draft("one", 2)),
        expected_revision=0,
        idempotency_key="key.shared",
    )
    store.apply(
        TreeMutation.add_node(_child_draft("two", 3)),
        expected_revision=first.revision,
        idempotency_key="key.other",
    )
    events = _events(directory)
    replacements = _replace_nested_key(
        events[-1]["payload"], "idempotency_key", "key.shared"
    )
    assert replacements == 1
    events[-1]["event_hash"] = _event_hash(events[-1])
    _rewrite_events(directory, events)
    (directory / "tree.json").unlink()

    with pytest.raises(TreeIntegrityError):
        HypothesisTreeStore.open(directory).recover()


@pytest.mark.parametrize(
    "tamper",
    ["duplicate-event-id", "contract-hash", "run-id", "event-kind"],
)
def test_rehashed_semantic_event_tamper_is_rejected(
    tmp_path: Path, tamper: str
) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    store.apply(
        TreeMutation.add_node(_child_draft("child", 2)),
        expected_revision=0,
        idempotency_key="add.child",
    )
    events = _events(directory)
    if tamper == "duplicate-event-id":
        events[1]["event_id"] = events[0]["event_id"]
    elif tamper == "contract-hash":
        events[1]["contract_hash"] = "0" * 64
    elif tamper == "run-id":
        events[1]["run_id"] = "run.other"
    else:
        events[1]["event_type"] = "node.updated"
    events[1]["event_hash"] = _event_hash(events[1])
    _rewrite_events(directory, events)
    (directory / "tree.json").unlink()

    with pytest.raises(TreeIntegrityError):
        HypothesisTreeStore.open(directory).recover()


def test_rehashed_non_datetime_event_timestamp_is_rejected(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "state"
    store = _create_store(directory)
    store.apply(
        TreeMutation.add_node(_child_draft("child", 2)),
        expected_revision=0,
        idempotency_key="add.child",
    )
    events = _events(directory)
    events[-1]["timestamp"] = "definitely-not-a-date-time"
    events[-1]["event_hash"] = _event_hash(events[-1])
    _rewrite_events(directory, events)
    (directory / "tree.json").unlink()

    with pytest.raises(TreeIntegrityError):
        HypothesisTreeStore.open(directory).recover()


def test_missing_journal_is_an_integrity_failure(tmp_path: Path) -> None:
    directory = tmp_path / "state"
    _create_store(directory)
    (directory / "tree.events.jsonl").unlink()

    with pytest.raises(TreeIntegrityError):
        HypothesisTreeStore.open(directory).recover()


@pytest.mark.parametrize("state_kind", ["missing", "regular-file"])
def test_open_state_directory_io_failures_are_typed(
    tmp_path: Path, state_kind: str
) -> None:
    path = tmp_path / "unusable-state"
    if state_kind == "regular-file":
        path.write_text("not a directory", encoding="utf-8")

    with pytest.raises(TreePersistenceError):
        HypothesisTreeStore.open(path).recover()


def test_lock_release_io_failure_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _create_store(tmp_path / "state")
    original_flock = fcntl.flock

    def fail_unlock(descriptor: int, operation: int) -> None:
        if operation == fcntl.LOCK_UN:
            raise OSError("injected unlock failure")
        original_flock(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", fail_unlock)
    with pytest.raises(TreePersistenceError):
        store.load()


def test_multiprocess_mutations_are_serialized_without_lost_updates(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "state"
    _create_store(directory)
    context = multiprocessing.get_context("spawn")
    start_gate = context.Event()
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_multiprocess_add_worker,
            args=(str(directory), index, start_gate, result_queue),
        )
        for index in range(4)
    ]
    for process in processes:
        process.start()
    start_gate.set()

    deadline = time.monotonic() + 30
    for process in processes:
        process.join(timeout=max(0.0, deadline - time.monotonic()))
    hung = [process for process in processes if process.is_alive()]
    for process in hung:
        process.terminate()
        process.join(timeout=5)
    assert not hung, "multiprocess store mutation exceeded 30 seconds"
    assert [process.exitcode for process in processes] == [0, 0, 0, 0]

    results = []
    try:
        for _ in processes:
            results.append(result_queue.get(timeout=5))
    except queue.Empty:
        pytest.fail(f"worker did not report a result: {results!r}")
    finally:
        result_queue.close()
        result_queue.join_thread()

    assert [result[0] for result in results] == ["ok"] * 4, results
    final = HypothesisTreeStore.open(directory).recover()
    node_ids = {node["id"] for node in final.to_dict()["nodes"]}
    assert node_ids == {"root", "worker.0", "worker.1", "worker.2", "worker.3"}
    assert final.revision == 4
    assert final.ledger_head["last_sequence"] == 5
    assert final.counts["proposals"] == 4
    assert len(_events(directory)) == 5
    HypothesisTreeStore.open(directory).verify()
