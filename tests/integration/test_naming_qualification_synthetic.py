from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from q_arbor.evaluation import validate_evaluation_evidence
from q_arbor.evaluation.codec import canonical_json_bytes
from q_arbor.hypotheses import HypothesisTreeStore, NodeDraft, TreeMutation
from q_arbor.ledger import EvidenceLedger
from q_arbor.recovery import resume_session, save_checkpoint
from q_arbor.refinement import freeze_prompt_snapshot, refinement_signature, run_development_cycle
from q_arbor.reporting import audit_research_package, render_research_report, write_research_report
from tests.evaluation_helpers import synthetic_case
from tests.hypothesis_helpers import node_draft_kwargs, scope_mapping
from tests.integration.test_refinement_loop import _snapshot


def _event(ledger, case, event_id, event_type, *, node_id=None, attempt_id=None, payload=None):
    ledger.append({
        "schema_version": "1.0", "run_id": case.request.run_id, "event_id": event_id,
        "timestamp": "2026-08-23T00:00:00Z", "event_type": event_type, "actor": "coordinator",
        "contract_hash": case.request.contract_hash, "node_id": node_id, "attempt_id": attempt_id,
        "split_role": "development", "payload": payload or {},
    })


def _ref(root: Path, artifact_id: str, relative_path: str, payload: bytes, *, media_type="application/json"):
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {"artifact_id": artifact_id, "kind": "q-arbor.synthetic.v1", "relative_path": relative_path,
            "sha256": hashlib.sha256(payload).hexdigest(), "media_type": media_type}


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, text=True,
                          capture_output=True).stdout.strip()


def test_synthetic_development_trace_is_durable_and_auditable(tmp_path: Path) -> None:
    case = synthetic_case(tmp_path / "case")
    branch = "exec/synthetic-success"
    repo, worktree = tmp_path / "executor-repo", tmp_path / "executor-worktree"
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.email", "q-arbor@example.invalid")
    _git(repo, "config", "user.name", "Q-Arbor test")
    (repo / "README.md").write_text("synthetic executor fixture\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "seed")
    trunk_commit = _git(repo, "rev-parse", "HEAD")
    _git(repo, "worktree", "add", "-b", branch, str(worktree))
    (worktree / "solution.py").write_text("CANDIDATE = 'synthetic-success'\n", encoding="utf-8")
    _git(worktree, "add", "solution.py")
    _git(worktree, "commit", "-m", "implement synthetic candidate")
    executor_commit = _git(worktree, "rev-parse", "HEAD")
    assert Path(_git(worktree, "rev-parse", "--show-toplevel")) == worktree
    root = tmp_path / "session"
    ledger = EvidenceLedger.create(root / "ledger")
    tree = HypothesisTreeStore.create(
        root / "tree", run_id=case.request.run_id, contract_hash=case.request.contract_hash,
        root=NodeDraft(**node_draft_kwargs("root", parent_id=None, proposal_order=1)),
    )
    messages = root / "messages.json"
    messages.parent.mkdir(parents=True, exist_ok=True)
    messages.write_text('{"messages":[]}', encoding="utf-8")
    _event(ledger, case, "run.started", "run.started")

    scope = scope_mapping(data_snapshot_sha256=case.result.provenance["data_snapshot_sha256"],
                          cost_model_sha256=case.result.costs["cost_model_sha256"])
    snapshot = _snapshot(case, case.request, scope)
    proposal = {"node_id": case.request.node_id, "attempt_id": case.request.attempt_id,
                "request_id": case.request.request_id, "result_id": case.result.result_id,
                "ancestor_insight_ids": [], "known_failed_signatures": []}
    def dispatch(snap):
        draft = node_draft_kwargs(case.request.node_id, parent_id="root", proposal_order=2, scope=scope)
        draft.update(candidate_id="candidate.synthetic.success",
                     candidate_artifact=case.request.candidate.to_dict(), code_ref=branch,
                     prompt_snapshot_sha256=snap.sha256)
        tree.apply(TreeMutation.add_node(NodeDraft(**draft)), expected_revision=tree.load().revision,
                   idempotency_key="trace.propose")
        _event(ledger, case, "hypothesis.proposed.success", "hypothesis.proposed",
               node_id=case.request.node_id, attempt_id=case.request.attempt_id,
               payload={"branch": branch, "request_id": case.request.request_id})
        tree.apply(TreeMutation.update_node(case.request.node_id,
                   {"status": "running", "lifecycle": "running", "attempt_ids": [case.request.attempt_id]}),
                   expected_revision=tree.load().revision, idempotency_key="trace.dispatch")
        _event(ledger, case, "attempt.dispatched.success", "attempt.dispatched",
               node_id=case.request.node_id, attempt_id=case.request.attempt_id,
               payload={"branch": branch})
        _event(ledger, case, "attempt.started.success", "attempt.started",
               node_id=case.request.node_id, attempt_id=case.request.attempt_id, payload={"branch": branch})
        return case.request

    def evaluate(request):
        _event(ledger, case, "evaluation.requested.success", "evaluation.requested",
               node_id=request.node_id, attempt_id=request.attempt_id,
               payload={"request_id": request.request_id, "result_id": case.result.result_id})
        _event(ledger, case, "evaluation.completed.success", "evaluation.completed",
               node_id=request.node_id, attempt_id=request.attempt_id,
               payload={"request_id": request.request_id, "result_id": case.result.result_id,
                        "artifact_refs": [ref.to_dict() for ref in case.result.artifacts]})
        return case.result

    def decide(request, result):
        evidence = {"evidence_id": "evidence.synthetic.success", "attempt_id": request.attempt_id,
                    "result_id": result.result_id, "split_role": "development", "level": "observed",
                    "claim": "synthetic development result", "conditions": ["development"],
                    "status": "valid", "artifact_refs": [ref.to_dict() for ref in result.artifacts]}
        validate_evaluation_evidence(result, request=request, node=tree.load().get_node(request.node_id), evidence=evidence)
        _event(ledger, case, "decision.recorded.success", "decision.recorded", node_id=request.node_id,
               attempt_id=request.attempt_id, payload={"result_id": result.result_id, "evidence_id": evidence["evidence_id"]})
        return tree.apply(TreeMutation.update_node(request.node_id,
                           {"status": "done", "lifecycle": "done", "admissibility": "admissible",
                            "evidence_refs": [evidence]}), expected_revision=tree.load().revision,
                          idempotency_key="trace.decide").get_node(request.node_id)

    trace = run_development_cycle(proposal, snapshot, dispatch, evaluate, decide)
    assert trace.result.result_id == case.result.result_id and trace.node.code_ref == branch

    failed_id, failed_attempt = "node.synthetic.failure", "attempt.synthetic.failure"
    failure_draft = node_draft_kwargs(failed_id, parent_id="root", proposal_order=3, scope=scope)
    failure_draft["family"].update(
        canonical_status="near_duplicate",
        similarity_refs=[{"candidate_id": "candidate.synthetic.success", "method": "synthetic_similarity", "value": 0.99}],
    )
    side_effects = []
    failed_snapshot = _snapshot(case, case.request, scope)
    failed_signature = refinement_signature(freeze_prompt_snapshot(failed_snapshot))
    with pytest.raises(ValueError, match="known failed"):
        run_development_cycle({**proposal, "known_failed_signatures": [failed_signature]}, failed_snapshot,
                              lambda _: side_effects.append("dispatch"), lambda _: side_effects.append("evaluate"),
                              lambda *_: side_effects.append("decide"))
    _event(ledger, case, "candidate.duplicate.approximate", "candidate.duplicate", node_id=failed_id,
           attempt_id=failed_attempt, payload={"duplicate_kind": "approximate", "family": failure_draft["family"],
                                               "side_effects": side_effects})
    _event(ledger, case, "candidate.rejected.known_failed", "candidate.rejected", node_id=failed_id,
           attempt_id=failed_attempt, payload={"reason": "known_failed_signature", "side_effects": side_effects})
    _event(ledger, case, "attempt.failed.failure", "attempt.failed", node_id=failed_id, attempt_id=failed_attempt,
           payload={"failure_type": "invalid_candidate", "summary": "duplicate rejected before dispatch"})
    assert side_effects == []
    tree.apply(TreeMutation.add_node(NodeDraft(**failure_draft)), expected_revision=tree.load().revision,
               idempotency_key="trace.failure.propose")
    duplicate_node = tree.load().get_node(failed_id)
    assert duplicate_node.family["canonical_status"] == "near_duplicate"
    assert duplicate_node.family["similarity_refs"][0]["candidate_id"] == "candidate.synthetic.success"
    failure_evidence = {"evidence_id": "evidence.synthetic.failure", "attempt_id": failed_attempt,
                        "result_id": None, "split_role": "development", "level": "observed",
                        "claim": "controlled implementation failure", "conditions": ["development"],
                        "status": "valid", "artifact_refs": []}
    tree.apply(TreeMutation.update_node(failed_id, {"status": "invalid", "lifecycle": "done", "admissibility": "invalid",
                                                     "attempt_ids": [failed_attempt],
                                                     "evidence_refs": [failure_evidence],
                                                     "failure": {"failure_type": "invalid_candidate",
                                                                 "summary": "controlled failure", "evidence_ids": [failure_evidence["evidence_id"]]}}),
               expected_revision=tree.load().revision, idempotency_key="trace.failure.complete")

    resume_id, resume_attempt = "node.synthetic.resume", "attempt.synthetic.resume"
    resume_draft = node_draft_kwargs(resume_id, parent_id="root", proposal_order=4, scope=scope)
    tree.apply(TreeMutation.add_node(NodeDraft(**resume_draft)), expected_revision=tree.load().revision,
               idempotency_key="trace.resume.propose")
    tree.apply(TreeMutation.update_node(resume_id, {"status": "running", "lifecycle": "running",
                                                     "attempt_ids": [resume_attempt]}),
               expected_revision=tree.load().revision, idempotency_key="trace.resume.start")
    _event(ledger, case, "attempt.started.resume", "attempt.started", node_id=resume_id, attempt_id=resume_attempt)
    checkpoint = root / "checkpoint.json"
    save_checkpoint(checkpoint, ledger=ledger, tree=tree, messages_path=messages, phase="development", cycle=1,
                    git={"trunk_branch": "main", "trunk_commit": trunk_commit,
                         "active_branches": [branch], "worktrees": [str(worktree)]},
                    inflight_attempts=[{"attempt_id": resume_attempt, "node_id": resume_id, "branch": branch,
                                        "started_event_id": "attempt.started.resume", "pid": None}],
                    budget_state={}, capability_state={}, created_at="2026-08-23T00:00:00Z")
    resumed = resume_session(checkpoint, ledger=EvidenceLedger.create(root / "ledger"),
                             tree=HypothesisTreeStore.open(root / "tree"))
    assert resumed.node_status == "needs_retry"
    resume_evidence = {"evidence_id": "evidence.synthetic.interruption", "attempt_id": resume_attempt,
                       "result_id": None, "split_role": "development", "level": "observed",
                       "claim": "controlled interruption and reconciliation", "conditions": ["development"],
                       "status": "valid", "artifact_refs": []}
    tree.apply(TreeMutation.update_node(resume_id, {"evidence_refs": [resume_evidence],
                                                     "failure": {"failure_type": "interruption",
                                                                 "summary": "executor interrupted before completion",
                                                                 "evidence_ids": [resume_evidence["evidence_id"]]}}),
               expected_revision=tree.load().revision, idempotency_key="trace.resume.evidence")
    tree.apply(TreeMutation.prune_subtree(resume_id, "controlled interruption exhausted"),
               expected_revision=tree.load().revision, idempotency_key="trace.prune.resume")
    _event(ledger, case, "prune.completed.resume", "prune.completed", node_id=resume_id,
           attempt_id=resume_attempt, payload={"reason": "controlled interruption exhausted"})
    tree.apply(TreeMutation.update_node(case.request.node_id, {"status": "merged", "lifecycle": "merged"}),
               expected_revision=tree.load().revision, idempotency_key="trace.merge.success")
    _event(ledger, case, "merge.requested.success", "merge.requested", node_id=case.request.node_id,
           attempt_id=case.request.attempt_id, payload={"branch": branch})
    _git(repo, "merge", "--no-ff", branch, "-m", "merge synthetic candidate")
    merge_commit = _git(repo, "rev-parse", "HEAD")
    _event(ledger, case, "merge.completed.success", "merge.completed", node_id=case.request.node_id,
           attempt_id=case.request.attempt_id, payload={"branch": branch, "commit": merge_commit})

    contract_ref = _ref(root, "contract", "contract.json", case.contract.to_json().encode())
    tree_path = root / "tree.json"
    tree.load().write(tree_path)
    tree_ref = _ref(root, "tree", "tree.json", tree_path.read_bytes())
    ledger_head = ledger.verify()
    head_ref = _ref(root, "ledger.head", "ledger_head.json", canonical_json_bytes({
        "run_id": ledger_head.run_id, "contract_hash": ledger_head.contract_hash,
        "last_sequence": ledger_head.last_sequence, "last_event_hash": ledger_head.last_event_hash,
    }))
    candidate_ref = _ref(root, "candidate.synthetic", "candidate.json", b"synthetic-candidate")
    summary_ref = _ref(root, "summary.synthetic", "reports/summary.json", b'{"claim_scope":"development_only"}')
    package = {"schema_version": "1.0", "run_id": case.request.run_id, "contract": contract_ref,
               "selected_candidate": candidate_ref, "selected_commit": executor_commit, "tree": tree_ref,
               "research_head": dict(tree.load().ledger_head),
               "ledger": {"artifact": head_ref, "last_sequence": ledger_head.last_sequence,
                          "last_event_hash": ledger_head.last_event_hash},
               "family_snapshot_hash": "b" * 64, "reports": [summary_ref, _ref(root, "report.synthetic", "reports/research.html", b"placeholder", media_type="text/html")],
               "stop_reason": "frontier_exhausted", "final_state": "sealed_unopened",
               "integrity_status": "pass", "claim_scope": "development_only", "missing_artifacts": []}
    rendered = render_research_report(package, root)
    package["reports"][1] = _ref(root, "report.synthetic", "reports/research.html", rendered.encode(), media_type="text/html")
    write_research_report(package, root, root / "reports/research.html")
    _event(ledger, case, "report.generated", "report.generated", payload={"artifact_id": "report.synthetic"})
    ledger_head = ledger.verify()
    head_ref = _ref(root, "ledger.head", "ledger_head.json", canonical_json_bytes({
        "run_id": ledger_head.run_id, "contract_hash": ledger_head.contract_hash,
        "last_sequence": ledger_head.last_sequence, "last_event_hash": ledger_head.last_event_hash,
    }))
    package["ledger"] = {"artifact": head_ref, "last_sequence": ledger_head.last_sequence,
                          "last_event_hash": ledger_head.last_event_hash}
    package_path = root / "research_package.json"
    package_path.write_bytes(canonical_json_bytes(package))
    assert audit_research_package(package, root).integrity_status == "pass"
    assert package_path.is_file() and (root / "reports/research.html").is_file()
    event_types = [event["event_type"] for event in ledger.verify().events]
    for expected in ("hypothesis.proposed", "evaluation.completed", "attempt.failed", "candidate.duplicate",
                     "candidate.rejected", "attempt.interrupted", "resume.reconciled", "prune.completed",
                     "merge.completed", "report.generated"):
        assert expected in event_types
