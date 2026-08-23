from __future__ import annotations
import os
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, cast
from q_arbor.evaluation.codec import (
    atomic_write,
    canonical_json_bytes,
    decode_json_bytes,
    normalize_mapping,
    validate_definition,
)
from q_arbor.evaluation.errors import EvaluationIntegrityError
from q_arbor.hypotheses import HypothesisTreeStore, TreeMutation
from q_arbor.ledger import EvidenceLedger, VerifiedLedger
def _file_ref(path: Path, root: Path, kind: str) -> dict[str, Any]:
    path = path.absolute()
    root = root.absolute()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise EvaluationIntegrityError(f"{kind} artifact is outside the session") from exc
    if path.is_symlink() or not path.is_file():
        raise EvaluationIntegrityError(f"{kind} artifact is not a regular file")
    digest = sha256(path.read_bytes()).hexdigest()
    return {"artifact_id": f"{kind}.checkpoint", "kind": kind, "relative_path": relative.as_posix(),
            "sha256": digest, "media_type": "application/json", "produced_by_event_id": None}
def _verify_ref(ref: Mapping[str, Any], root: Path, kind: str) -> Path:
    if ref.get("kind") != kind:
        raise EvaluationIntegrityError(f"checkpoint {kind} reference kind is invalid")
    relative = ref.get("relative_path")
    if not isinstance(relative, str):
        raise EvaluationIntegrityError(f"checkpoint {kind} path is invalid")
    path = (root / relative).absolute()
    try: path.relative_to(root.absolute())
    except ValueError as exc:
        raise EvaluationIntegrityError(f"checkpoint {kind} path escapes session") from exc
    if path.is_symlink() or not path.is_file():
        raise EvaluationIntegrityError(f"checkpoint {kind} artifact is missing")
    digest = sha256(path.read_bytes()).hexdigest()
    if digest != ref.get("sha256"):
        raise EvaluationIntegrityError(f"checkpoint {kind} artifact digest differs")
    return path
class QCheckpoint:
    __slots__ = ("_canonical", "_mapping")
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        normalized = normalize_mapping(mapping)
        validate_definition(normalized, "QCheckpoint")
        self._mapping = normalized
        self._canonical = canonical_json_bytes(normalized)
    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical
    @property
    def ledger_head(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], self._mapping["ledger_head"])
    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], normalize_mapping(self._mapping))
def _read_checkpoint(path: Path) -> QCheckpoint:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EvaluationIntegrityError("checkpoint cannot be read") from exc
    try:
        decoded = decode_json_bytes(raw)
        if not isinstance(decoded, Mapping):
            raise EvaluationIntegrityError("checkpoint is not an object")
        mapping = normalize_mapping(decoded)
        if canonical_json_bytes(mapping) != raw:
            raise EvaluationIntegrityError("checkpoint is not canonical")
        return QCheckpoint(mapping)
    except EvaluationIntegrityError:
        raise
    except Exception as exc:
        raise EvaluationIntegrityError("checkpoint is invalid") from exc
def save_checkpoint(
    path: str | os.PathLike[str], *, ledger: EvidenceLedger, tree: HypothesisTreeStore,
    messages_path: str | os.PathLike[str], phase: str, cycle: int, git: Mapping[str, Any],
    inflight_attempts: list[Mapping[str, Any]], budget_state: Mapping[str, Any],
    capability_state: Mapping[str, Any], created_at: str, pending_user: Mapping[str, Any] | None = None,
) -> QCheckpoint:
    verified: VerifiedLedger = ledger.verify()
    tree.verify()
    if verified.run_id is None or verified.contract_hash is None or verified.last_event_hash is None:
        raise EvaluationIntegrityError("cannot checkpoint an empty ledger")
    current_tree = tree.load()
    if current_tree.run_id != verified.run_id or current_tree.contract_hash != verified.contract_hash:
        raise EvaluationIntegrityError("ledger and tree identities differ")
    destination = Path(path).absolute()
    root = destination.parent
    root.mkdir(parents=True, exist_ok=True)
    tree_snapshot = root / f"{destination.name}.tree.json"
    atomic_write(tree_snapshot, (tree.directory / "tree.json").read_bytes())
    mapping = {
        "schema_version": "1.0", "run_id": verified.run_id,
        "contract_hash": verified.contract_hash, "phase": phase, "cycle": cycle,
        "ledger_head": {"last_sequence": verified.last_sequence, "last_event_hash": verified.last_event_hash},
        "tree": _file_ref(tree_snapshot, root, "tree"),
        "messages": _file_ref(Path(messages_path), root, "messages"),
        "git": dict(git), "inflight_attempts": [dict(item) for item in inflight_attempts],
        "budget_state": dict(budget_state), "capability_state": dict(capability_state),
        "pending_user": None if pending_user is None else dict(pending_user),
        "created_at": created_at,
    }
    checkpoint = QCheckpoint(mapping)
    atomic_write(destination, checkpoint.canonical_bytes)
    written = _read_checkpoint(destination)
    if written.canonical_bytes != checkpoint.canonical_bytes:
        raise EvaluationIntegrityError("checkpoint changed after atomic write")
    return written
@dataclass(frozen=True)
class ResumeResult:
    node_status: str
    changed: bool
def _ledger_event(
    *, run_id: str, contract_hash: str, event_id: str, event_type: str,
    node_id: str, attempt_id: str, payload: Mapping[str, Any], actor: str = "system",
) -> dict[str, Any]:
    return {"schema_version": "1.0", "run_id": run_id, "event_id": event_id,
            "timestamp": "2026-08-23T00:00:00Z", "event_type": event_type, "actor": actor,
            "contract_hash": contract_hash, "node_id": node_id, "attempt_id": attempt_id,
            "split_role": "none", "payload": dict(payload)}
def resume_session(
    path: str | os.PathLike[str], *, ledger: EvidenceLedger, tree: HypothesisTreeStore,
) -> ResumeResult:
    checkpoint_path = Path(path).absolute()
    checkpoint = _read_checkpoint(checkpoint_path)
    mapping = checkpoint.to_dict()
    root = checkpoint_path.parent
    _verify_ref(cast(Mapping[str, Any], mapping["tree"]), root, "tree")
    _verify_ref(cast(Mapping[str, Any], mapping["messages"]), root, "messages")
    verified = ledger.verify()
    tree.verify()
    if verified.run_id != mapping["run_id"] or verified.contract_hash != mapping["contract_hash"]:
        raise EvaluationIntegrityError("checkpoint identity differs from ledger")
    current_tree = tree.load()
    if current_tree.run_id != verified.run_id or current_tree.contract_hash != verified.contract_hash:
        raise EvaluationIntegrityError("checkpoint identity differs from tree")
    anchor = cast(Mapping[str, Any], mapping["ledger_head"])
    sequence = cast(int, anchor["last_sequence"])
    if sequence > verified.last_sequence or verified.events[sequence - 1]["event_hash"] != anchor["last_event_hash"]:
        raise EvaluationIntegrityError("checkpoint ledger head is not a verified prefix")
    checkpoint_hash = sha256(checkpoint.canonical_bytes).hexdigest()
    changed = False
    for raw_attempt in mapping["inflight_attempts"]:
        attempt = cast(Mapping[str, Any], raw_attempt)
        node_id, attempt_id = cast(str, attempt["node_id"]), cast(str, attempt["attempt_id"])
        started_id = cast(str, attempt["started_event_id"])
        started = [event for event in verified.events if event["event_id"] == started_id]
        if len(started) != 1 or started[0]["event_type"] != "attempt.started" or any(
            started[0][field] != expected for field, expected in (
                ("run_id", mapping["run_id"]), ("contract_hash", mapping["contract_hash"]),
                ("node_id", node_id), ("attempt_id", attempt_id))):
            raise EvaluationIntegrityError("inflight attempt.started identity is invalid")
        interrupted_id = f"attempt.interrupted.{attempt_id}"
        reconciled_id = f"resume.reconciled.{attempt_id}"
        interrupted = [event for event in verified.events if event["event_id"] == interrupted_id]
        reconciled = [event for event in verified.events if event["event_id"] == reconciled_id]
        node = tree.load().get_node(node_id)
        if len(reconciled) > 1 or len(interrupted) > 1 or (reconciled and not interrupted):
            raise EvaluationIntegrityError("resume events are inconsistent")
        if reconciled:
            if node.status != "needs_retry":
                raise EvaluationIntegrityError("reconciled attempt has a non-retry node")
            continue
        if not interrupted:
            ledger.append(_ledger_event(
                run_id=cast(str, mapping["run_id"]), contract_hash=cast(str, mapping["contract_hash"]),
                event_id=interrupted_id, event_type="attempt.interrupted", node_id=node_id,
                attempt_id=attempt_id, payload={"checkpoint_sha256": checkpoint_hash, "reason": "resume"},
            ))
            changed = True
            verified = ledger.verify()
        if node.status == "running":
            failure = {"failure_type": "interruption", "summary": "executor interrupted before completion", "evidence_ids": []}
            tree.apply(TreeMutation.update_node(node_id, {
                "status": "needs_retry", "lifecycle": "needs_retry", "failure": failure,
            }), expected_revision=tree.load().revision,
                idempotency_key=f"resume.needs_retry.{attempt_id}")
            changed = True
        elif node.status != "needs_retry":
            raise EvaluationIntegrityError("inflight attempt is neither running nor reconciled")
        ledger.append(_ledger_event(
            run_id=cast(str, mapping["run_id"]), contract_hash=cast(str, mapping["contract_hash"]),
            event_id=reconciled_id, event_type="resume.reconciled", node_id=node_id,
            attempt_id=attempt_id, payload={"checkpoint_sha256": checkpoint_hash, "interrupted_event_id": interrupted_id},
        ))
        changed = True
        verified = ledger.verify()
    node_status = "none"
    if mapping["inflight_attempts"]:
        first_attempt = cast(Mapping[str, Any], mapping["inflight_attempts"][0])
        node_status = tree.load().get_node(cast(str, first_attempt["node_id"])).status
    return ResumeResult(node_status=node_status, changed=changed)
__all__ = ["QCheckpoint", "ResumeResult", "resume_session", "save_checkpoint"]
