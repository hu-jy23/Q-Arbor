from pathlib import Path
from q_arbor.hypotheses import HypothesisTreeStore, NodeDraft, TreeMutation
from q_arbor.ledger import EvidenceLedger
from q_arbor.recovery import resume_session, save_checkpoint
from tests.hypothesis_helpers import CONTRACT_HASH, node_draft_kwargs
def _event(run_id: str, contract_hash: str, event_id: str, event_type: str, *, node_id=None, attempt_id=None):
    return {"schema_version": "1.0", "run_id": run_id, "event_id": event_id,
            "timestamp": "2026-08-23T00:00:00Z", "event_type": event_type,
            "actor": "coordinator", "contract_hash": contract_hash, "node_id": node_id,
            "attempt_id": attempt_id, "split_role": "none", "payload": {}}
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
