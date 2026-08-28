from __future__ import annotations

import hashlib
from pathlib import Path

from q_arbor.evaluation import validate_evaluation_evidence
from q_arbor.evaluation.codec import canonical_json_bytes
from q_arbor.firewall import CapabilityGrant, EvaluationBroker, SplitGrant, SplitGrantRegistry
from q_arbor.generality import (
    AdapterDescriptor,
    ControlPath,
    EvaluationStagePolicy,
    ProvenanceSeed,
    RunnerReceipt,
    RunnerRequest,
)
from q_arbor.hypotheses import HypothesisTreeStore, NodeDraft, TreeMutation
from q_arbor.ledger import EvidenceLedger
from q_arbor.refinement import run_product_integration_cycle
from q_arbor.reporting import audit_research_package, render_research_report
from tests.evaluation_helpers import CODE_COMMIT, synthetic_case
from tests.hypothesis_helpers import node_draft_kwargs, scope_mapping
from tests.integration.test_refinement_loop import _snapshot
from tests.integration.test_research_package import _ref


H = "a" * 64


def test_refinement_product_path_calls_general_surface_and_retains_chains(
    tmp_path: Path,
) -> None:
    case = synthetic_case(tmp_path / "case")
    request = case.request
    result_id = case.binding.result_id
    token = b"development-token"
    grant = CapabilityGrant(
        grant_id=request.capability_grant_id,
        run_id=request.run_id,
        contract_hash=request.contract_hash,
        role="development",
        principal="executor",
        query_limit=1,
        query_count=0,
        state="active",
        token_digest=hashlib.sha256(token).hexdigest(),
        issued_event_id="event.grant.bridge",
    )
    broker = EvaluationBroker(
        {grant.grant_id: grant},
        SplitGrantRegistry(
            {
                grant.grant_id: SplitGrant(
                    "development", request.split_manifest_hash, object()
                )
            }
        ),
        runtime_locks={grant.grant_id: case.runtime.lock},
    )
    ledger = EvidenceLedger.create(tmp_path / "ledger")
    tree = HypothesisTreeStore.create(
        tmp_path / "tree",
        run_id=request.run_id,
        contract_hash=request.contract_hash,
        root=NodeDraft(**node_draft_kwargs("root", parent_id=None, proposal_order=1)),
    )
    scope = scope_mapping(
        data_snapshot_sha256=case.result.provenance["data_snapshot_sha256"],
        cost_model_sha256=case.result.costs["cost_model_sha256"],
    )
    snapshot = _snapshot(case, request, scope)
    proposal = {
        "node_id": request.node_id,
        "attempt_id": request.attempt_id,
        "request_id": request.request_id,
        "result_id": result_id,
        "ancestor_insight_ids": [],
    }
    adapter = AdapterDescriptor.from_mapping(
        {
            "adapter_id": "adapter.synthetic-bridge/v1",
            "adapter_version": "1.0",
            "adapter_code_sha256": H,
            "candidate_codec_id": "codec.candidate/interface-compat-v1",
            "invocation_codec_id": "codec.invocation/interface-compat-v1",
            "result_codec_id": "codec.result/interface-compat-v1",
            "runner_id": "runner.synthetic-bridge/v1",
            "required_output_descriptors": ["evaluation.artifacts"],
            "objective_descriptors": ["objective.primary"],
            "diagnostic_descriptors": ["diagnostic.open"],
            "failure_mapping_id": "failure.interface-compat/v1",
            "provenance_requirements": ["contract", "evaluator", "split"],
        }
    )
    stage = EvaluationStagePolicy.from_mapping(
        {
            "stage_id": "q-arbor.synthetic/development-bridge-v1",
            "data_visibility": "capability-scoped",
            "selection_use_allowed": True,
            "query_budget": 1,
            "feedback_availability_rule": "on-completion",
            "feedback_granularity_descriptor": "objective-and-diagnostics",
            "target_maturity_predicate": "evaluation-complete",
            "contamination_transition_policy": "development-labelled",
            "claim_boundary": "synthetic-development-only",
            "principal_capabilities": ["evaluate.development"],
        }
    )
    general_request = RunnerRequest.from_mapping(
        {
            "invocation_id": request.request_id,
            "adapter_ref": adapter.sha256,
            "stage_policy_ref": stage.sha256,
            "candidate_artifact_ref": request.candidate_hash,
            "cell_root_capability": "cell.synthetic.bridge",
            "environment_lock_ref": case.runtime.lock.sha256,
            "immutable_argv": ["synthetic-evaluator"],
            "environment_allowlist": {},
            "timeout_seconds": 30,
            "required_outputs": [],
        }
    )
    provenance_seed = ProvenanceSeed.from_mapping(
        {
            "cell_id": "cell.synthetic.bridge",
            "cell_contract_sha256": request.contract_hash,
            "data_manifest_sha256": request.split_manifest_hash,
            "baseline_manifest_sha256": H,
            "evaluator_sha256": case.runtime.lock.evaluator_sha256,
            "code_commit": CODE_COMMIT,
            "artifact_manifest_sha256": request.candidate_hash,
        }
    )

    def event(
        event_id: str,
        event_type: str,
        actor: str,
        payload: dict[str, object],
    ) -> None:
        ledger.append(
            {
                "schema_version": "1.0",
                "run_id": request.run_id,
                "event_id": event_id,
                "timestamp": "2026-08-25T00:00:00Z",
                "event_type": event_type,
                "actor": actor,
                "contract_hash": request.contract_hash,
                "node_id": request.node_id,
                "attempt_id": request.attempt_id,
                "split_role": "development",
                "payload": payload,
            }
        )

    def dispatch(snap):
        broker.authorize_runtime(
            request,
            runtime_lock=case.runtime.lock,
            principal="executor",
            token=token,
        )
        draft = node_draft_kwargs(
            request.node_id, parent_id="root", proposal_order=1, scope=scope
        )
        draft.update(
            prompt_snapshot_sha256=snap.sha256,
            candidate_id="candidate.bridge",
            candidate_artifact=request.candidate.to_dict(),
        )
        proposed = tree.apply(
            TreeMutation.add_node(NodeDraft(**draft)),
            expected_revision=tree.load().revision,
            idempotency_key="propose.bridge",
        )
        event(
            proposed.get_node(request.node_id).created_event_id,
            "hypothesis.proposed",
            "coordinator",
            {"request_id": request.request_id, "result_id": result_id},
        )
        tree.apply(
            TreeMutation.update_node(
                request.node_id,
                {
                    "status": "running",
                    "lifecycle": "running",
                    "attempt_ids": [request.attempt_id],
                },
            ),
            expected_revision=tree.load().revision,
            idempotency_key="dispatch.bridge",
        )
        event(
            "event.dispatch.bridge",
            "attempt.dispatched",
            "coordinator",
            {"request_id": request.request_id, "result_id": result_id},
        )
        return request

    class SyntheticRunner:
        legacy_result = None

        def run(self, invocation: RunnerRequest) -> RunnerReceipt:
            assert invocation.invocation_id == request.request_id
            self.legacy_result = case.plugin.evaluate(case.receipt, case.split)
            return RunnerReceipt.from_mapping(
                {
                    "runner_id": adapter.runner_id,
                    "runner_code_sha256": H,
                    "request_sha256": invocation.sha256,
                    "started_event_id": "event.general.started.bridge",
                    "completed_event_id": "event.general.completed.bridge",
                    "termination": "succeeded",
                    "exit_code": 0,
                    "stdout_ref": None,
                    "stderr_ref": None,
                    "output_artifact_refs": [
                        ref.to_dict() for ref in self.legacy_result.artifacts
                    ],
                    "resource_usage": {"wall_seconds": 0.01},
                }
            )

    runner = SyntheticRunner()

    def general_evaluate(req):
        assert req.request_id == general_request.invocation_id
        event(
            "event.request.bridge",
            "evaluation.requested",
            "coordinator",
            {"request_id": req.request_id, "result_id": result_id},
        )

        def decode(_):
            value = runner.legacy_result
            assert value is not None
            primary = value.primary_metric
            return {
                "availability": "available",
                "mature": True,
                "status": "success",
                "objective_vector": [
                    {
                        "objective_id": "objective.primary",
                        "value": primary.value,
                        "direction": primary.direction,
                    }
                ],
                "decision_objective_id": "objective.primary",
                "constraints": [item.to_dict() for item in value.constraints],
                "diagnostic_records": [item.to_dict() for item in value.diagnostics],
                "output_artifact_refs": [ref.to_dict() for ref in value.artifacts],
                "failure": None,
                "warnings": [str(item) for item in value.warnings],
            }

        outcome = ControlPath().execute(
            proposal_id="proposal.synthetic.bridge",
            adapter=adapter,
            stage=stage,
            request=general_request,
            provenance_seed=provenance_seed,
            runner=runner,
            decoder=decode,
        )
        event(
            "event.complete.bridge",
            "evaluation.completed",
            "evaluator",
            {
                "request_id": req.request_id,
                "result_id": result_id,
                "general_result_id": outcome.result.result_id,
                "general_result_sha256": outcome.result.sha256,
                "runner_receipt_sha256": outcome.receipt.sha256,
                "provenance_sha256": outcome.result.provenance.sha256,
                "artifact_refs": [ref.to_dict() for ref in runner.legacy_result.artifacts],
            },
        )
        return outcome

    def project(req, outcome):
        assert req.request_id == outcome.result.invocation_id
        assert runner.legacy_result is not None
        return runner.legacy_result

    def decide(req, value):
        node = tree.load().get_node(req.node_id)
        evidence = {
            "evidence_id": "evidence.bridge",
            "attempt_id": req.attempt_id,
            "result_id": value.result_id,
            "split_role": "development",
            "level": "observed",
            "claim": "synthetic development bridge result supports candidate",
            "conditions": ["development"],
            "status": "valid",
            "artifact_refs": [ref.to_dict() for ref in value.artifacts],
        }
        validate_evaluation_evidence(value, request=req, node=node, evidence=evidence)
        event(
            "event.decision.bridge",
            "decision.recorded",
            "coordinator",
            {
                "request_id": req.request_id,
                "result_id": value.result_id,
                "evidence_id": evidence["evidence_id"],
            },
        )
        return tree.apply(
            TreeMutation.update_node(
                req.node_id,
                {
                    "status": "done",
                    "lifecycle": "done",
                    "admissibility": "admissible",
                    "evidence_refs": [evidence],
                },
            ),
            expected_revision=tree.load().revision,
            idempotency_key="decide.bridge",
        ).get_node(req.node_id)

    trace = run_product_integration_cycle(
        proposal,
        snapshot,
        dispatch,
        general_evaluate,
        project,
        decide,
        query_count_cb=lambda: broker.query_count(request.capability_grant_id),
    )

    assert trace.budget_query_count_before == 0
    assert trace.budget_query_count_after == 1
    assert trace.cycle.node.id == request.node_id
    assert trace.cycle.result.result_id == result_id
    assert trace.cycle.node.evidence_refs[0]["result_id"] == result_id
    assert trace.general.result.invocation_id == request.request_id
    assert trace.general.result.provenance.candidate_sha256 == request.candidate_hash
    completed = next(
        item for item in ledger.verify().events if item["event_type"] == "evaluation.completed"
    )
    assert trace.report["result_id"] == completed["payload"]["result_id"] == result_id
    assert trace.report["general_result_id"] == completed["payload"]["general_result_id"]
    assert trace.report["provenance_sha256"] == completed["payload"]["provenance_sha256"]
    assert trace.report["runner_receipt_sha256"] == completed["payload"]["runner_receipt_sha256"]
    assert trace.report["evidence_id"] == trace.cycle.node.evidence_refs[0]["evidence_id"]
    assert trace.report["artifact_refs"] == completed["payload"]["artifact_refs"]
    assert trace.report_sha256
    assert [item["event_type"] for item in ledger.verify().events] == [
        "hypothesis.proposed",
        "attempt.dispatched",
        "evaluation.requested",
        "evaluation.completed",
        "decision.recorded",
    ]

    package_root = tmp_path / "package"
    verified = ledger.verify()
    contract_ref = _ref(
        package_root,
        "contract.bridge",
        "contract.json",
        case.contract.to_json().encode("utf-8"),
    )
    tree_ref = _ref(
        package_root,
        "tree.bridge",
        "tree.json",
        (tree.directory / "tree.json").read_bytes(),
    )
    ledger_ref = _ref(
        package_root,
        "ledger.head.bridge",
        "ledger/head.json",
        canonical_json_bytes(
            {
                "run_id": verified.run_id,
                "contract_hash": verified.contract_hash,
                "last_sequence": verified.last_sequence,
                "last_event_hash": verified.last_event_hash,
            }
        ),
    )
    candidate_ref = _ref(
        package_root,
        "candidate.bridge",
        "candidate.json",
        canonical_json_bytes(case.candidate.artifact.to_dict()),
    )
    report_ref = _ref(
        package_root,
        "report.bridge",
        "reports/bridge.json",
        canonical_json_bytes(trace.report),
    )
    provenance_report_ref = _ref(
        package_root,
        "report.provenance.bridge",
        "reports/provenance.json",
        canonical_json_bytes(trace.general.result.provenance.to_dict()),
    )
    package = {
        "schema_version": "1.0",
        "run_id": request.run_id,
        "contract": contract_ref,
        "selected_candidate": candidate_ref,
        "selected_commit": CODE_COMMIT,
        "tree": tree_ref,
        "research_head": dict(tree.load().ledger_head),
        "ledger": {
            "artifact": ledger_ref,
            "last_sequence": verified.last_sequence,
            "last_event_hash": verified.last_event_hash,
        },
        "family_snapshot_hash": H,
        "reports": [report_ref, provenance_report_ref],
        "stop_reason": "frontier_exhausted",
        "final_state": "sealed_unopened",
        "integrity_status": "pass",
        "claim_scope": "development_only",
        "missing_artifacts": [],
    }
    assert audit_research_package(package, package_root).integrity_status == "pass"
    rendered = render_research_report(package, package_root)
    assert "Q-Arbor research report" in rendered
    assert "evidence.bridge" in rendered
