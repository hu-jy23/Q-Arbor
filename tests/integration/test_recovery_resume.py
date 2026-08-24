from pathlib import Path
import pytest
from q_arbor.hypotheses import HypothesisTreeStore, NodeDraft, TreeMutation
from q_arbor.ledger import EvidenceLedger
from q_arbor.evaluation import EvaluationIntegrityError
from q_arbor.recovery import resume_session, save_checkpoint
from tests.evaluation_helpers import synthetic_case
from tests.hypothesis_helpers import CONTRACT_HASH, node_draft_kwargs
def _event(run_id: str, contract_hash: str, event_id: str, event_type: str, *, node_id=None, attempt_id=None, payload=None):
    return {"schema_version": "1.0", "run_id": run_id, "event_id": event_id,
            "timestamp": "2026-08-23T00:00:00Z", "event_type": event_type,
            "actor": "coordinator", "contract_hash": contract_hash, "node_id": node_id,
            "attempt_id": attempt_id, "split_role": "none", "payload": payload or {}}


def test_resume_predecide_reuses_persisted_result_without_evaluation(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    run_id, attempt_id, node_id = case.request.run_id, "attempt.predecide", "node.predecide"
    session = tmp_path / "session"
    ledger_path, tree_path = session / "ledger", session / "tree"
    messages = session / "messages.json"
    result_path = session / "results" / "result.json"
    messages.parent.mkdir(parents=True)
    messages.write_text('{"messages":[]}', encoding="utf-8")
    result_path.parent.mkdir(parents=True)
    case.result.write(result_path)
    ledger = EvidenceLedger.create(ledger_path)
    for event_id, event_type in (("run.started", "run.started"),
                                 ("attempt.dispatched", "attempt.dispatched"),
                                 ("attempt.started", "attempt.started")):
        ledger.append(_event(run_id, case.request.contract_hash, event_id, event_type,
                             node_id=node_id if event_type != "run.started" else None,
                             attempt_id=attempt_id if event_type != "run.started" else None))
    ledger.append(_event(
        run_id, case.request.contract_hash, "evaluation.completed.predecide", "evaluation.completed",
        node_id=node_id, attempt_id=attempt_id,
        payload={"request_id": case.request.request_id, "result_id": case.result.result_id,
                 "result_path": str(result_path.relative_to(session)),
                 "result_sha256": case.result.sha256},
    ))
    tree = HypothesisTreeStore.create(
        tree_path, run_id=run_id, contract_hash=case.request.contract_hash,
        root=NodeDraft(**node_draft_kwargs("root", parent_id=None, proposal_order=1)),
    )
    tree.apply(TreeMutation.add_node(NodeDraft(**node_draft_kwargs(
        node_id, parent_id="root", proposal_order=2))), expected_revision=0,
        idempotency_key="add.predecide")
    tree.apply(TreeMutation.update_node(node_id, {
        "status": "running", "lifecycle": "running", "attempt_ids": [attempt_id],
    }), expected_revision=1, idempotency_key="start.predecide")
    checkpoint_path = session / "checkpoint.json"
    save_checkpoint(
        checkpoint_path, ledger=ledger, tree=tree, messages_path=messages,
        phase="development", cycle=1,
        git={"trunk_branch": "main", "trunk_commit": "a" * 40,
             "active_branches": [], "worktrees": []},
        inflight_attempts=[{"attempt_id": attempt_id, "node_id": node_id,
                            "branch": "exec/predecide", "started_event_id": "attempt.started", "pid": None}],
        budget_state={}, capability_state={}, created_at="2026-08-23T00:00:00Z",
    )
    decisions = []
    evaluate_calls = query_calls = 0

    def decide(result):
        decisions.append(result.result_id)
        return {"status": "done", "lifecycle": "done", "admissibility": "admissible",
                "evidence_refs": [{"evidence_id": "evidence.predecide", "attempt_id": attempt_id,
                                   "result_id": result.result_id, "split_role": "development",
                                   "level": "observed", "claim": "persisted result",
                                   "conditions": ["development"], "status": "valid", "artifact_refs": []}]}

    with pytest.raises(EvaluationIntegrityError):
        resume_session(checkpoint_path, ledger=EvidenceLedger.create(ledger_path),
                       tree=HypothesisTreeStore.open(tree_path))
    first = resume_session(
        checkpoint_path, ledger=EvidenceLedger.create(ledger_path),
        tree=HypothesisTreeStore.open(tree_path), binding=case.binding, decision_cb=decide,
    )
    assert first.node_status == "done"
    assert decisions == [case.result.result_id]
    events = EvidenceLedger.create(ledger_path).verify().events
    assert sum(event["event_type"] == "decision.recorded" for event in events) == 1
    assert sum(event["event_type"] == "resume.reconciled" for event in events) == 1
    revision = HypothesisTreeStore.open(tree_path).verify().tree_revision
    second = resume_session(
        checkpoint_path, ledger=EvidenceLedger.create(ledger_path),
        tree=HypothesisTreeStore.open(tree_path), binding=case.binding, decision_cb=decide,
    )
    repeated = EvidenceLedger.create(ledger_path).verify()
    assert second.changed is False and decisions == [case.result.result_id]
    assert evaluate_calls == query_calls == 0
    assert len(repeated.events) == len(events)
    assert HypothesisTreeStore.open(tree_path).verify().tree_revision == revision


def test_resume_predecide_replays_durable_decision_before_tree_write(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    run_id, attempt_id, node_id = case.request.run_id, "attempt.crash", "node.crash"
    session = tmp_path / "session"
    ledger_path, tree_path = session / "ledger", session / "tree"
    messages, result_path = session / "messages.json", session / "results" / "result.json"
    messages.parent.mkdir(parents=True); messages.write_text('{"messages":[]}', encoding="utf-8")
    result_path.parent.mkdir(parents=True); case.result.write(result_path)
    ledger = EvidenceLedger.create(ledger_path)
    for event_id, event_type in (("run.started", "run.started"), ("attempt.dispatched", "attempt.dispatched"), ("attempt.started", "attempt.started")):
        ledger.append(_event(run_id, case.request.contract_hash, event_id, event_type,
                             node_id=None if event_type == "run.started" else node_id,
                             attempt_id=None if event_type == "run.started" else attempt_id))
    ledger.append(_event(run_id, case.request.contract_hash, "evaluation.completed.crash",
                         "evaluation.completed", node_id=node_id, attempt_id=attempt_id,
                         payload={"request_id": case.request.request_id, "result_id": case.result.result_id,
                                  "result_path": str(result_path.relative_to(session)),
                                  "result_sha256": case.result.sha256}))
    updates = {"status": "done", "lifecycle": "done", "admissibility": "admissible",
               "evidence_refs": [{"evidence_id": "evidence.crash", "attempt_id": attempt_id,
                                  "result_id": case.result.result_id, "split_role": "development",
                                  "level": "observed", "claim": "persisted result", "conditions": ["development"],
                                  "status": "valid", "artifact_refs": []}]}
    tree = HypothesisTreeStore.create(tree_path, run_id=run_id,
                                      contract_hash=case.request.contract_hash,
                                      root=NodeDraft(**node_draft_kwargs("root", parent_id=None, proposal_order=1)))
    tree.apply(TreeMutation.add_node(NodeDraft(**node_draft_kwargs(node_id, parent_id="root", proposal_order=2))),
               expected_revision=0, idempotency_key="add.crash")
    tree.apply(TreeMutation.update_node(node_id, {"status": "running", "lifecycle": "running", "attempt_ids": [attempt_id]}),
               expected_revision=1, idempotency_key="start.crash")
    checkpoint_path = session / "checkpoint.json"
    save_checkpoint(checkpoint_path, ledger=ledger, tree=tree, messages_path=messages,
                    phase="development", cycle=1,
                    git={"trunk_branch": "main", "trunk_commit": "a" * 40, "active_branches": [], "worktrees": []},
                    inflight_attempts=[{"attempt_id": attempt_id, "node_id": node_id, "branch": "exec/crash",
                                        "started_event_id": "attempt.started", "pid": None}], budget_state={},
                    capability_state={}, created_at="2026-08-23T00:00:00Z")
    ledger.append(_event(run_id, case.request.contract_hash, "decision.recorded." + attempt_id,
                         "decision.recorded", node_id=node_id, attempt_id=attempt_id,
                         payload={"request_id": case.request.request_id, "result_id": case.result.result_id,
                                  "node_updates": updates}))
    callback_calls = []

    def forbidden(result):
        callback_calls.append(result.result_id)
        raise AssertionError("durable decision must be replayed")

    before = EvidenceLedger.create(ledger_path).verify()
    resumed = resume_session(checkpoint_path, ledger=EvidenceLedger.create(ledger_path),
                             tree=HypothesisTreeStore.open(tree_path), binding=case.binding,
                             decision_cb=forbidden)
    after = EvidenceLedger.create(ledger_path).verify()
    assert resumed.node_status == "done" and callback_calls == []
    assert [event["event_type"] for event in after.events[-2:]] == ["attempt.interrupted", "resume.reconciled"]
    assert sum(event["event_type"] == "decision.recorded" for event in after.events) == 1
    assert len(after.events) == len(before.events) + 2
def test_running_resume_is_checkpointed_reconciled_and_idempotent(tmp_path: Path) -> None:
    run_id, attempt_id, node_id = "run.recovery", "attempt.1", "node.1"
    session = tmp_path / "session"
    ledger_path, tree_path = session / "ledger", session / "tree"
    messages = session / "messages.json"
    messages.parent.mkdir(parents=True)
    messages.write_text('{"messages":[]}', encoding="utf-8")
    ledger = EvidenceLedger.create(ledger_path)
    for event_id, event_type in (("run.started", "run.started"),
                                 ("attempt.dispatched", "attempt.dispatched"),
                                 ("attempt.started", "attempt.started")):
        ledger.append(_event(run_id, CONTRACT_HASH, event_id, event_type,
                             node_id=node_id if event_type != "run.started" else None,
                             attempt_id=attempt_id if event_type != "run.started" else None))
    tree = HypothesisTreeStore.create(
        tree_path, run_id=run_id, contract_hash=CONTRACT_HASH,
        root=NodeDraft(**node_draft_kwargs("root", parent_id=None, proposal_order=1)),
    )
    tree.apply(TreeMutation.add_node(NodeDraft(**node_draft_kwargs(
        node_id, parent_id="root", proposal_order=2))), expected_revision=0,
        idempotency_key="add.node")
    tree.apply(TreeMutation.update_node(node_id, {
        "status": "running", "lifecycle": "running", "attempt_ids": [attempt_id],
    }), expected_revision=1, idempotency_key="start.node")
    checkpoint_path = session / "checkpoint.json"
    save_checkpoint(
        checkpoint_path, ledger=ledger, tree=tree, messages_path=messages,
        phase="development", cycle=1,
        git={"trunk_branch": "main", "trunk_commit": "a" * 40,
             "active_branches": [], "worktrees": []},
        inflight_attempts=[{"attempt_id": attempt_id, "node_id": node_id,
                            "branch": "exec/node.1", "started_event_id": "attempt.started", "pid": None}],
        budget_state={}, capability_state={}, created_at="2026-08-23T00:00:00Z",
    )
    before = ledger.verify()
    first = resume_session(checkpoint_path, ledger=EvidenceLedger.create(ledger_path),
                           tree=HypothesisTreeStore.open(tree_path))
    assert first.node_status == "needs_retry"
    events = ledger.verify().events
    assert [event["event_type"] for event in events[-2:]] == [
        "attempt.interrupted", "resume.reconciled"
    ]
    assert len(events) == len(before.events) + 2
    after = EvidenceLedger.create(ledger_path).verify()
    tree_after = HypothesisTreeStore.open(tree_path).verify()
    second = resume_session(checkpoint_path, ledger=EvidenceLedger.create(ledger_path),
                            tree=HypothesisTreeStore.open(tree_path))
    repeated = EvidenceLedger.create(ledger_path).verify()
    assert second.node_status == "needs_retry"
    assert len(repeated.events) == len(after.events)
    assert tuple(event["event_hash"] for event in repeated.events) == tuple(event["event_hash"] for event in after.events)
    assert HypothesisTreeStore.open(tree_path).verify().tree_revision == tree_after.tree_revision
    assert sum(event["event_type"] == "attempt.interrupted" for event in repeated.events) == 1
    assert sum(event["event_type"] == "resume.reconciled" for event in repeated.events) == 1
