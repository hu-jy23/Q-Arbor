from __future__ import annotations

import hashlib
from pathlib import Path

from q_arbor.evaluation import EvaluationBinding
from q_arbor.evaluation.codec import canonical_json_bytes
from q_arbor.firewall import CapabilityGrant, EvaluationBroker, SplitGrant, SplitGrantRegistry
from q_arbor.hypotheses import HypothesisTreeStore, NodeDraft, TreeMutation
from q_arbor.ledger import EvidenceLedger
from q_arbor.plugins.hm1 import HM1EngineOutput
from q_arbor.plugins.hm1.pilot import evaluate_authorized_aggregate, run_hm1_pilot
from q_arbor.reporting import audit_research_package, render_research_report, write_research_report
from tests.evaluation_helpers import hm1_case, hm1_engine_mapping, make_request
from tests.hypothesis_helpers import node_draft_kwargs, scope_mapping


def _ref(root: Path, artifact_id: str, relative_path: str, payload: bytes, media_type="application/json"):
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {"artifact_id": artifact_id, "kind": "q-arbor.synthetic.v1", "relative_path": relative_path,
            "sha256": hashlib.sha256(payload).hexdigest(), "media_type": media_type}


def _event(ledger, case, event_id, event_type, *, node_id=None, attempt_id=None, payload=None, split_role="development"):
    ledger.append({"schema_version": "1.0", "run_id": case.request.run_id, "event_id": event_id,
                   "timestamp": "2026-08-23T00:00:00Z", "event_type": event_type, "actor": "coordinator",
                   "contract_hash": case.request.contract_hash, "node_id": node_id, "attempt_id": attempt_id,
                   "split_role": split_role, "payload": payload or {}})


def test_hm1_pilot_fake_opaque_control_plane(tmp_path: Path) -> None:
    case = hm1_case(tmp_path / "case", engine_status="complete")
    gate_request = make_request(case.contract, case.receipt, split_role="gate",
                                request_id="request.hm1.gate", node_id=case.request.node_id,
                                attempt_id="attempt.hm1.gate")
    gate_binding = EvaluationBinding.create(
        gate_request, case.contract, case.receipt, case.identity, case.runtime.lock,
        result_id="result.hm1.gate", seed=7, artifact_resolver=case.store,
    )
    dev_token, gate_token = b"hm1-development-token", b"hm1-gate-token"
    dev_grant = CapabilityGrant(
        grant_id=case.request.capability_grant_id, run_id=case.request.run_id,
        contract_hash=case.request.contract_hash, role="development", principal="executor",
        query_limit=1, query_count=0, state="active", token_digest=hashlib.sha256(dev_token).hexdigest(),
        issued_event_id="grant.issued.development",
    )
    gate_grant = CapabilityGrant(
        grant_id=gate_request.capability_grant_id, run_id=case.request.run_id,
        contract_hash=case.request.contract_hash, role="gate", principal="coordinator",
        query_limit=1, query_count=0, state="active", token_digest=hashlib.sha256(gate_token).hexdigest(),
        issued_event_id="grant.issued.gate",
    )
    broker = EvaluationBroker(
        {dev_grant.grant_id: dev_grant, gate_grant.grant_id: gate_grant},
        SplitGrantRegistry({
            dev_grant.grant_id: SplitGrant("development", case.request.split_manifest_hash, object()),
            gate_grant.grant_id: SplitGrant("gate", gate_request.split_manifest_hash, object()),
        }),
        runtime_locks={dev_grant.grant_id: case.runtime.lock, gate_grant.grant_id: case.runtime.lock},
    )
    seen_resources = []

    def fake_evaluator(request, resource):
        assert not isinstance(resource, (str, bytes, bytearray, Path))
        seen_resources.append((request.split_role, type(resource).__name__))
        artifacts = case.store.scope(request_id=request.request_id,
                                     produced_by_event_id=f"event.{request.split_role}.aggregate",
                                     runtime_lock=case.runtime.lock)
        return evaluate_authorized_aggregate(
            plugin=case.plugin, candidate=case.receipt, request=request, contract=case.contract,
            binding=case.binding if request.split_role == "development" else gate_binding,
            engine_output=HM1EngineOutput.from_mapping(hm1_engine_mapping("complete")),
            artifacts=artifacts,
        )

    trace = run_hm1_pilot(
        broker=broker, development_request=case.request, gate_request=gate_request,
        bindings={case.request.capability_grant_id: case.binding, gate_request.capability_grant_id: gate_binding},
        runtime_locks={case.request.capability_grant_id: case.runtime.lock, gate_request.capability_grant_id: case.runtime.lock},
        tokens={case.request.capability_grant_id: dev_token, gate_request.capability_grant_id: gate_token},
        evaluator=fake_evaluator,
    )
    assert seen_resources == [("development", "object"), ("gate", "object")]
    assert trace.development.status == "incomparable" and trace.gate.status == "incomparable"
    assert trace.development.costs["transaction_cost"] is None
    assert trace.gate.costs["transaction_cost"] is None
    assert trace.query_counts == {
        case.request.capability_grant_id: 1, gate_request.capability_grant_id: 1,
    }
    assert trace.final_query_count == 0
    assert not any(key.startswith("grant.final") for key in trace.query_counts)

    root = tmp_path / "session"
    ledger = EvidenceLedger.create(root / "ledger")
    tree = HypothesisTreeStore.create(
        root / "tree", run_id=case.request.run_id, contract_hash=case.request.contract_hash,
        root=NodeDraft(**node_draft_kwargs("root", parent_id=None, proposal_order=1)),
    )
    node_id = "node.hm1.pilot"
    scope = scope_mapping(data_snapshot_sha256=case.result.provenance["data_snapshot_sha256"],
                          cost_model_sha256=case.result.costs["cost_model_sha256"])
    draft = node_draft_kwargs(node_id, parent_id="root", proposal_order=2, scope=scope)
    draft.update(candidate_id="candidate.hm1.pilot", candidate_artifact=case.request.candidate.to_dict(),
                 code_ref="refs/heads/exec/hm1-pilot")
    _event(ledger, case, "run.started", "run.started")
    tree.apply(TreeMutation.add_node(NodeDraft(**draft)), expected_revision=tree.load().revision,
               idempotency_key="hm1.pilot.propose")
    _event(ledger, case, "hypothesis.proposed.hm1", "hypothesis.proposed", node_id=node_id,
           attempt_id=case.request.attempt_id, payload={"code_ref": "refs/heads/exec/hm1-pilot"})
    tree.apply(TreeMutation.update_node(node_id, {"status": "running", "lifecycle": "running",
                                                   "attempt_ids": [case.request.attempt_id]}),
               expected_revision=tree.load().revision, idempotency_key="hm1.pilot.dispatch")
    _event(ledger, case, "evaluation.completed.dev", "evaluation.completed", node_id=node_id,
           attempt_id=case.request.attempt_id, payload={"request_id": case.request.request_id,
                                                        "result_id": trace.development.result_id}, split_role="development")
    _event(ledger, case, "evaluation.completed.gate", "evaluation.completed", node_id=node_id,
           attempt_id=gate_request.attempt_id, payload={"request_id": gate_request.request_id,
                                                        "result_id": trace.gate.result_id}, split_role="gate")
    evidence = {"evidence_id": "evidence.hm1.incomparable", "attempt_id": case.request.attempt_id,
                "result_id": trace.development.result_id, "split_role": "development", "level": "observed",
                "claim": "HM1 pilot output is incomparable while costs are unavailable",
                "conditions": ["development_only", "cost_semantics_unavailable"], "status": "valid", "artifact_refs": []}
    tree.apply(TreeMutation.update_node(node_id, {"status": "incomparable", "lifecycle": "done",
                                                   "admissibility": "incomparable", "evidence_refs": [evidence],
                                                   "failure": {"failure_type": "incomparable",
                                                               "summary": "hm1.cost_semantics_unavailable",
                                                               "evidence_ids": [evidence["evidence_id"]]}}),
               expected_revision=tree.load().revision, idempotency_key="hm1.pilot.incomparable")
    _event(ledger, case, "decision.recorded.hm1", "decision.recorded", node_id=node_id,
           attempt_id=case.request.attempt_id, payload={"result_id": trace.development.result_id,
                                                        "claim": evidence["claim"]})

    messages = root / "messages.json"
    messages.parent.mkdir(parents=True, exist_ok=True)
    messages.write_text('{"messages":[]}', encoding="utf-8")
    contract_ref = _ref(root, "contract.hm1", "contract.json", case.contract.to_json().encode())
    tree_path = root / "tree.json"
    tree.load().write(tree_path)
    tree_ref = _ref(root, "tree.hm1", "tree.json", tree_path.read_bytes())
    head = ledger.verify()
    head_ref = _ref(root, "ledger.head.hm1", "ledger_head.json", canonical_json_bytes({
        "run_id": head.run_id, "contract_hash": head.contract_hash,
        "last_sequence": head.last_sequence, "last_event_hash": head.last_event_hash,
    }))
    candidate_ref = _ref(root, "candidate.hm1", "candidate.json", b"opaque-hm1-candidate")
    summary_ref = _ref(root, "summary.hm1", "reports/summary.json", b'{"claim_scope":"development_only"}')
    package = {"schema_version": "1.0", "run_id": case.request.run_id, "contract": contract_ref,
               "selected_candidate": candidate_ref, "selected_commit": "a" * 40, "tree": tree_ref,
               "research_head": dict(tree.load().ledger_head),
               "ledger": {"artifact": head_ref, "last_sequence": head.last_sequence, "last_event_hash": head.last_event_hash},
               "family_snapshot_hash": "b" * 64,
               "reports": [summary_ref, _ref(root, "report.hm1", "reports/research.html", b"placeholder", "text/html")],
               "stop_reason": "frontier_exhausted", "final_state": "sealed_unopened",
               "integrity_status": "pass", "claim_scope": "development_only", "missing_artifacts": []}
    rendered = render_research_report(package, root)
    package["reports"][1] = _ref(root, "report.hm1", "reports/research.html", rendered.encode(), "text/html")
    write_research_report(package, root, root / "reports/research.html")
    _event(ledger, case, "report.generated.hm1", "report.generated", payload={"artifact_id": "report.hm1"})
    head = ledger.verify()
    head_ref = _ref(root, "ledger.head.hm1", "ledger_head.json", canonical_json_bytes({
        "run_id": head.run_id, "contract_hash": head.contract_hash,
        "last_sequence": head.last_sequence, "last_event_hash": head.last_event_hash,
    }))
    package["ledger"] = {"artifact": head_ref, "last_sequence": head.last_sequence, "last_event_hash": head.last_event_hash}
    package_path = root / "research_package.json"
    package_path.write_bytes(canonical_json_bytes(package))
    assert audit_research_package(package, root).integrity_status == "pass"
    assert package_path.is_file() and (root / "reports/research.html").is_file()
    assert "http://" not in rendered and "https://" not in rendered
