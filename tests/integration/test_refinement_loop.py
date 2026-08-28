from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from q_arbor.evaluation import validate_evaluation_evidence
from q_arbor.firewall import CapabilityGrant, EvaluationBroker, SplitGrant, SplitGrantRegistry
from q_arbor.hypotheses import HypothesisTreeStore, NodeDraft, TreeMutation
from q_arbor.ledger import EvidenceLedger
from q_arbor.refinement import (
    freeze_prompt_snapshot,
    refinement_signature,
    run_development_cycle,
)
from tests.evaluation_helpers import synthetic_case
from tests.hypothesis_helpers import canonical_json, node_draft_kwargs, scope_mapping, hypothesis_mapping, family_mapping


def _snapshot(
    case, request, scope, *, selected_insight_ids=(), evidence_hashes=(),
    failure_summary=None, user="refine:synthetic",
    branch: str = "exec/node.fixture",
    worktree: str = "worktrees/node.fixture",
):
    system = "dispatch:development"
    snapshot = {
        "schema_version": "1.0", "prompt_snapshot_id": "prompt.node.fixture",
        "run_id": request.run_id, "phase": "dispatch", "cycle": 0,
        "attempt_id": request.attempt_id, "tree_revision": 0, "ledger_sequence": 1,
        "contract_hash": request.contract_hash, "candidate_id": "candidate.fixture",
        "family_id": "family.node.fixture", "scope": scope,
        "base_commit": None, "branch": branch, "worktree": worktree,
        "system_template_id": "q-arbor.synthetic.v1",
        "system_prompt_sha256": hashlib.sha256(system.encode()).hexdigest(),
        "user_prompt_sha256": hashlib.sha256(user.encode()).hexdigest(),
        "system_prompt_redacted": system, "user_prompt_redacted": user,
        "plugin": case.identity.to_dict(), "selected_insight_ids": list(selected_insight_ids),
        "evidence_hashes": list(evidence_hashes), "editable_surface": case.contract.to_dict()["editable_surface"],
        "protected_paths": case.contract.to_dict()["protected_paths"],
        "required_outputs": case.contract.to_dict()["required_outputs"],
        "development_evaluator_descriptor": {
            "split_role": "development", "split_manifest_hash": request.split_manifest_hash,
            **({"failure_summary": failure_summary} if failure_summary is not None else {}),
        },
        "capability_grant_id": request.capability_grant_id,
        "redaction_manifest": ["development_only"],
    }
    snapshot["snapshot_hash"] = hashlib.sha256(canonical_json(snapshot).encode()).hexdigest()
    return snapshot


def test_development_cycle_consumes_snapshot_and_keeps_identity(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    request, result_id = case.request, case.binding.result_id
    token = b"development-token"
    grant = CapabilityGrant(
        grant_id=request.capability_grant_id, run_id=request.run_id,
        contract_hash=request.contract_hash, role="development", principal="executor",
        query_limit=1, query_count=0, state="active",
        token_digest=hashlib.sha256(token).hexdigest(), issued_event_id="event.grant.1",
    )
    broker = EvaluationBroker(
        {grant.grant_id: grant},
        SplitGrantRegistry({grant.grant_id: SplitGrant(
            "development", request.split_manifest_hash, object())}),
        runtime_locks={grant.grant_id: case.runtime.lock},
    )
    ledger = EvidenceLedger.create(tmp_path / "ledger")
    root = NodeDraft(**node_draft_kwargs("root", parent_id=None, proposal_order=1))
    tree = HypothesisTreeStore.create(
        tmp_path / "tree", run_id=request.run_id,
        contract_hash=request.contract_hash, root=root,
    )
    scope = scope_mapping(
        data_snapshot_sha256=result_id and case.result.provenance["data_snapshot_sha256"],
        cost_model_sha256=case.result.costs["cost_model_sha256"],
    )
    snapshot = _snapshot(
        case, request, scope,
        selected_insight_ids=["insight.parent.failed"],
        evidence_hashes=[hashlib.sha256(b"insight.parent.failed:evidence").hexdigest()],
        failure_summary={
            "category": "constraint_violation",
            "summary": "ancestor failed under development evaluation",
        },
    )
    proposal = {
        "node_id": request.node_id, "attempt_id": request.attempt_id,
        "request_id": request.request_id, "result_id": result_id,
        "ancestor_insight_ids": ["insight.parent.failed", "insight.grandparent.failed"],
        "refuted_insight_ids": ["insight.grandparent.failed"],
    }
    consumed = []

    def event(event_id: str, event_type: str, actor: str, payload: dict[str, object]) -> None:
        ledger.append({
            "schema_version": "1.0", "run_id": request.run_id, "event_id": event_id,
            "timestamp": "2026-08-22T00:00:00Z", "event_type": event_type,
            "actor": actor, "contract_hash": request.contract_hash,
            "node_id": request.node_id, "attempt_id": request.attempt_id,
            "split_role": "development", "payload": payload,
        })

    def dispatch(snap):
        consumed.append(freeze_prompt_snapshot(snap.to_dict()))
        broker.authorize_runtime(request, runtime_lock=case.runtime.lock,
                                 principal="executor", token=token)
        draft = node_draft_kwargs(request.node_id, parent_id="root", proposal_order=1, scope=scope)
        draft.update(prompt_snapshot_sha256=snap.sha256,
                     candidate_id="candidate.fixture",
                     candidate_artifact=request.candidate.to_dict())
        proposed = tree.apply(TreeMutation.add_node(NodeDraft(**draft)),
                              expected_revision=tree.load().revision,
                              idempotency_key="propose.fixture")
        event(proposed.get_node(request.node_id).created_event_id, "hypothesis.proposed",
              "coordinator", {"request_id": request.request_id, "result_id": result_id,
                               "artifact_ref": request.candidate.to_dict()})
        tree.apply(TreeMutation.update_node(
            request.node_id, {"status": "running", "lifecycle": "running",
                              "attempt_ids": [request.attempt_id]}),
            expected_revision=tree.load().revision, idempotency_key="dispatch.fixture")
        event("event.dispatch.fixture", "attempt.dispatched", "coordinator",
              {"request_id": request.request_id, "result_id": result_id,
               "prompt_snapshot_sha256": snap.sha256})
        return request

    def evaluate(req):
        event("event.request.fixture", "evaluation.requested", "coordinator",
              {"request_id": req.request_id, "result_id": result_id})
        value = case.plugin.evaluate(case.receipt, case.split)
        event("event.complete.fixture", "evaluation.completed", "evaluator",
              {"request_id": req.request_id, "result_id": value.result_id,
               "artifact_refs": [ref.to_dict() for ref in value.artifacts]})
        return value

    def decide(req, value):
        node = tree.load().get_node(req.node_id)
        evidence = {
            "evidence_id": "evidence.fixture", "attempt_id": req.attempt_id,
            "result_id": value.result_id, "split_role": "development", "level": "observed",
            "claim": "development result supports candidate", "conditions": ["development"],
            "status": "valid", "artifact_refs": [ref.to_dict() for ref in value.artifacts],
        }
        validate_evaluation_evidence(value, request=req, node=node, evidence=evidence)
        event("event.decision.fixture", "decision.recorded", "coordinator",
              {"request_id": req.request_id, "result_id": value.result_id,
               "evidence_id": evidence["evidence_id"]})
        return tree.apply(TreeMutation.update_node(
            req.node_id, {"status": "done", "lifecycle": "done",
                          "admissibility": "admissible", "evidence_refs": [evidence]}),
            expected_revision=tree.load().revision, idempotency_key="decide.fixture").get_node(req.node_id)

    trace = run_development_cycle(proposal, snapshot, dispatch, evaluate, decide)
    assert consumed and consumed[0].sha256 == trace.snapshot.sha256
    consumed_snapshot = consumed[0].to_dict()
    result_artifact_refs = [ref.to_dict() for ref in trace.result.artifacts]
    report = {
        "node_id": trace.node.id,
        "code_ref": consumed_snapshot["branch"],
        "result_id": trace.result.result_id,
        "artifact_refs": result_artifact_refs,
    }
    ancestor_evidence_hash = hashlib.sha256(
        b"insight.parent.failed:evidence"
    ).hexdigest()
    sensitive_source = {
        "raw_gate_locator": "raw_gate_locator",
        "raw_final_locator": "raw_final_locator",
        "raw_path": "protected/evaluator.json",
        "raw_data": "secret-data-sentinel",
        "seed": "seed-sentinel",
        "capability_token": "capability-token-sentinel",
        "protected_evaluator_surface": "evaluator/internal.py",
    }
    assert "insight.parent.failed" in consumed_snapshot["selected_insight_ids"]
    assert ancestor_evidence_hash in consumed_snapshot["evidence_hashes"]
    descriptor = consumed_snapshot["development_evaluator_descriptor"]
    assert descriptor["failure_summary"] == {
        "category": "constraint_violation",
        "summary": "ancestor failed under development evaluation",
    }
    assert consumed_snapshot["family_id"] == "family.node.fixture"
    assert consumed_snapshot["scope"] is not None
    assert descriptor["split_role"] == "development"
    assert descriptor["split_manifest_hash"] == request.split_manifest_hash
    assert not set(consumed_snapshot["editable_surface"]) & set(
        consumed_snapshot["protected_paths"]
    )
    serialized = consumed[0].to_json()
    for sensitive in sensitive_source:
        assert sensitive not in serialized
    for sensitive in sensitive_source.values():
        assert sensitive not in serialized
    assert trace.node.id == request.node_id and trace.request.attempt_id in trace.node.attempt_ids
    assert trace.result.request_id == request.request_id and trace.result.result_id == result_id
    assert trace.node.evidence_refs[0]["result_id"] == trace.result.result_id
    assert consumed_snapshot["branch"] == "exec/node.fixture"
    assert consumed_snapshot["worktree"] == "worktrees/node.fixture"
    assert report["node_id"] == request.node_id
    assert report["code_ref"] == consumed_snapshot["branch"]
    assert report["result_id"] == trace.result.result_id
    assert report["artifact_refs"] == result_artifact_refs
    events = ledger.verify().events
    assert all(item["node_id"] == request.node_id for item in events)
    evidence = trace.node.evidence_refs[0]
    completed = next(item for item in events if item["event_type"] == "evaluation.completed")
    assert evidence["result_id"] == completed["payload"]["result_id"] == report["result_id"]
    assert list(evidence["artifact_refs"]) == list(completed["payload"]["artifact_refs"]) == report["artifact_refs"]
    assert broker.query_count(request.capability_grant_id) == 1
    assert [item["event_type"] for item in ledger.verify().events] == [
        "hypothesis.proposed", "attempt.dispatched", "evaluation.requested",
        "evaluation.completed", "decision.recorded",
    ]


def test_known_failed_signature_rejected_before_dispatch_side_effect(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    request, result_id = case.request, case.binding.result_id
    scope = scope_mapping(
        data_snapshot_sha256=case.result.provenance["data_snapshot_sha256"],
        cost_model_sha256=case.result.costs["cost_model_sha256"],
    )
    snapshot = _snapshot(case, request, scope, selected_insight_ids=["insight.failed"])
    signature = refinement_signature(freeze_prompt_snapshot(snapshot))
    proposal = {
        "node_id": request.node_id, "attempt_id": request.attempt_id,
        "request_id": request.request_id, "result_id": result_id,
        "ancestor_insight_ids": ["insight.failed"],
        "known_failed_signatures": [signature],
    }
    side_effects = []
    with pytest.raises(ValueError, match="known failed"):
        run_development_cycle(
            proposal, snapshot,
            lambda _: side_effects.append("dispatch"),
            lambda _: side_effects.append("evaluate"),
            lambda _, __: side_effects.append("decide"),
        )
    assert side_effects == []
