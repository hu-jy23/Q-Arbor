from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
from q_arbor.contracts import freeze_contract
from q_arbor.evaluation import ContentAddressedArtifactStore, EvaluationBinding
from q_arbor.evaluation.codec import canonical_json_bytes
from q_arbor.firewall import CapabilityGrant, EvaluationBroker, SplitGrant, SplitGrantRegistry
from q_arbor.hypotheses import HypothesisTreeStore, NodeDraft, TreeMutation
from q_arbor.ledger import EvidenceLedger
from q_arbor.plugins.hm1 import HM1EngineOutput
from q_arbor.plugins.hm1.pilot import HM1PilotBudget, evaluate_authorized_aggregate, run_hm1_pilot
from q_arbor.reporting import audit_research_package, render_research_report, write_research_report
from tests.evaluation_helpers import (
    bind_validation, fixture_bytes, hm1_case, hm1_contract, hm1_engine_mapping,
    hm1_identity, make_request, materialize_candidate, runtime_fixture,
)
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


def _status_fingerprint(project: Path) -> str:
    status = subprocess.run(
        ["git", "-C", str(project), "status", "--porcelain=v1"],
        check=True, capture_output=True, text=True,
    ).stdout.encode()
    return hashlib.sha256(status).hexdigest()


def _git_identity(project: Path) -> tuple[str, str]:
    head = subprocess.run(["git", "-C", str(project), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()
    tree = subprocess.run(["git", "-C", str(project), "rev-parse", "HEAD^{tree}"],
                          check=True, capture_output=True, text=True).stdout.strip()
    return head, tree


def _real_hm1_contract(evaluator_sha256: str, config_sha256: str):
    contract = hm1_contract(hm1_identity()).to_dict()
    public = {
        "evaluator_code_sha256": evaluator_sha256,
        "config_sha256": config_sha256,
        "schema_categories": ["ohlcv", "trade_price_mode", "daily_nav"],
        "content_hash_status": "not_computed_policy",
    }
    contract["data"]["snapshot_sha256"] = hashlib.sha256(
        canonical_json_bytes({**public, "snapshot": "protected-public-access"})
    ).hexdigest()
    dates = {"development": ("2022-01-04", "2023-03-31"),
             "gate": ("2023-04-01", "2023-12-29")}
    for role, (start, end) in dates.items():
        manifest = {**public, "role": role, "start": start, "end": end, "interval": "1D", "symbols": ["CU"]}
        contract["data"]["splits"][role]["manifest_sha256"] = hashlib.sha256(
            canonical_json_bytes(manifest)
        ).hexdigest()
        contract["data"]["splits"][role]["time_range"] = {
            "start": f"{start}T00:00:00Z", "end": f"{end}T23:59:59Z"
        }
    contract["data"]["splits"]["final"]["time_range"] = {
        "start": "2024-01-01T00:00:00Z", "end": "2024-12-31T23:59:59Z"
    }
    return freeze_contract(contract)


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
        budget=HM1PilotBudget.open(
            tmp_path / "budget.json", run_id=case.request.run_id,
            contract_hash=case.request.contract_hash,
            limits={"development": 1, "gate": 1, "final": 0},
        ),
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
    recreated_budget = HM1PilotBudget.open(
        tmp_path / "budget.json", run_id=case.request.run_id,
        contract_hash=case.request.contract_hash,
        limits={"development": 1, "gate": 1, "final": 0},
    )
    with pytest.raises(RuntimeError, match="exhausted"):
        recreated_budget.reserve(run_id=case.request.run_id,
                                 contract_hash=case.request.contract_hash,
                                 role="development")

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


def test_hm1_pilot_budget_survives_interrupted_recreated_runner(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    budget = HM1PilotBudget.open(
        path, run_id="run.budget", contract_hash="a" * 64,
        limits={"development": 1, "gate": 3, "final": 0},
    )
    budget.reserve(run_id="run.budget", contract_hash="a" * 64, role="development")
    try:
        raise KeyboardInterrupt
    except KeyboardInterrupt:
        pass
    for _ in range(3):
        budget.reserve(run_id="run.budget", contract_hash="a" * 64, role="gate")
    recreated = HM1PilotBudget.open(
        path, run_id="run.budget", contract_hash="a" * 64,
        limits={"development": 1, "gate": 3, "final": 0},
    )
    with pytest.raises(RuntimeError, match="exhausted"):
        recreated.reserve(run_id="run.budget", contract_hash="a" * 64, role="development")
    with pytest.raises(RuntimeError, match="binding"):
        HM1PilotBudget.open(path, run_id="run.other", contract_hash="a" * 64,
                            limits={"development": 1, "gate": 3, "final": 0})
    with pytest.raises(RuntimeError, match="exhausted"):
        recreated.reserve(run_id="run.budget", contract_hash="a" * 64, role="gate")
    with pytest.raises(RuntimeError, match="exhausted"):
        recreated.reserve(run_id="run.budget", contract_hash="a" * 64, role="final")


def test_hm1_protected_real_engineering_pilot() -> None:
    project_value = os.environ.get("Q_ARBOR_HM1_PROJECT")
    session_value = os.environ.get("Q_ARBOR_HM1_PILOT_SESSION")
    if not project_value or not session_value:
        pytest.skip("protected HM1 pilot environment is not configured")
    sys.dont_write_bytecode = True
    project = Path(project_value).resolve()
    root = Path(session_value).resolve()
    if not project.is_dir():
        pytest.fail("protected HM1 project is unavailable")
    root.mkdir(parents=True, exist_ok=True)
    before_status = _status_fingerprint(project)
    protected_head, protected_tree = _git_identity(project)
    evaluate_path = project / "evaluate.py"
    evaluator_sha256 = hashlib.sha256(evaluate_path.read_bytes()).hexdigest()
    config = {"interval": "1D", "strategy": "CandidateStrategy", "symbols": ["CU"],
              "quick": True, "content_hash_status": "not_computed_policy"}
    config_sha256 = hashlib.sha256(canonical_json_bytes(config)).hexdigest()
    contract = _real_hm1_contract(evaluator_sha256, config_sha256)
    identity = hm1_identity()
    plugin = __import__("q_arbor.plugins.hm1", fromlist=["HM1FuturesPlugin"]).HM1FuturesPlugin.create(identity)
    candidate = materialize_candidate(root / "candidate", contract, fixture_bytes("hm1_valid_strategy.py"))
    receipt = bind_validation(root / "candidate", candidate=candidate, validation=plugin.validate(candidate, contract),
                              contract=contract, plugin_identity=identity)
    runtime = runtime_fixture(root / "runtime", contract, aggregate_only=True,
                              evaluator_payload=evaluator_sha256.encode())
    store = ContentAddressedArtifactStore.create(root / "artifact-store")
    run_id, node_id = "run.hm1.engineering.pilot", "node.hm1.engineering"
    dev_request = make_request(contract, receipt, run_id=run_id, split_role="development",
                               request_id="request.hm1.engineering.dev", node_id=node_id,
                               attempt_id="attempt.hm1.engineering.dev")
    gate_request = make_request(contract, receipt, run_id=run_id, split_role="gate",
                                request_id="request.hm1.engineering.gate", node_id=node_id,
                                attempt_id="attempt.hm1.engineering.gate")
    dev_binding = EvaluationBinding.create(dev_request, contract, receipt, identity, runtime.lock,
                                           result_id="result.hm1.engineering.dev", seed=7,
                                           artifact_resolver=store)
    gate_binding = EvaluationBinding.create(gate_request, contract, receipt, identity, runtime.lock,
                                             result_id="result.hm1.engineering.gate", seed=7,
                                             artifact_resolver=store)
    dev_token, gate_token = b"real-pilot-development", b"real-pilot-gate"
    grants = {
        dev_request.capability_grant_id: CapabilityGrant(
            dev_request.capability_grant_id, run_id, contract.sha256, "development", "executor",
            contract.to_dict()["data"]["splits"]["development"]["query_budget"], 0, "active",
            hashlib.sha256(dev_token).hexdigest(), "grant.issued.real.dev"),
        gate_request.capability_grant_id: CapabilityGrant(
            gate_request.capability_grant_id, run_id, contract.sha256, "gate", "coordinator",
            contract.to_dict()["data"]["splits"]["gate"]["query_budget"], 0, "active",
            hashlib.sha256(gate_token).hexdigest(), "grant.issued.real.gate"),
    }
    broker = EvaluationBroker(
        grants,
        SplitGrantRegistry({
            dev_request.capability_grant_id: SplitGrant("development", dev_request.split_manifest_hash, object()),
            gate_request.capability_grant_id: SplitGrant("gate", gate_request.split_manifest_hash, object()),
        }),
        runtime_locks={dev_request.capability_grant_id: runtime.lock, gate_request.capability_grant_id: runtime.lock},
    )
    spec = importlib.util.spec_from_file_location("q_arbor_protected_hm1_evaluate", evaluate_path)
    if spec is None or spec.loader is None:
        pytest.fail("protected evaluator cannot be loaded")
    evaluate_module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = evaluate_module
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        spec.loader.exec_module(evaluate_module)
    sys.path.insert(0, str(project))
    candidate_path = root / "candidate" / "strategies" / "candidate.py"
    assert hashlib.sha256(candidate_path.read_bytes()).hexdigest() == receipt.candidate.artifact.sha256
    candidate_spec = importlib.util.spec_from_file_location("q_arbor_materialized_candidate", candidate_path)
    if candidate_spec is None or candidate_spec.loader is None:
        pytest.fail("materialized candidate cannot be loaded")
    candidate_module = importlib.util.module_from_spec(candidate_spec)
    sys.modules[candidate_spec.name] = candidate_module
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        candidate_spec.loader.exec_module(candidate_module)
    strategy_class = getattr(candidate_module, "CandidateStrategy")

    def engine_mapping_for(request):
        split = "dev" if request.split_role == "development" else "test"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            raw = evaluate_module.evaluate_strategy(strategy_class, split=split, symbols=["CU"], interval="1D")
        metrics = raw.portfolio_metrics
        aggregate = {
            "schema_version": "1.0", "status": "complete",
            "portfolio_daily_sharpe": metrics["portfolio_daily_sharpe"],
            "annualized_return": metrics["portfolio_annualized_return"],
            "max_drawdown": metrics["portfolio_max_drawdown"],
            "calmar": metrics["portfolio_calmar_ratio"],
            "win_rate": metrics["portfolio_daily_win_rate"],
            "trade_count": int(metrics.get("total_trades", 0)),
            "coverage_count": int(metrics["num_symbols"]), "expected_coverage_count": 1,
            "cost_semantics": "unavailable", "warning_codes": [],
        }
        del raw
        return aggregate

    def real_evaluator(request, resource):
        assert type(resource) is object
        output = HM1EngineOutput.from_mapping(engine_mapping_for(request))
        artifacts = store.scope(request_id=request.request_id, produced_by_event_id=f"event.{request.split_role}.real",
                                runtime_lock=runtime.lock)
        return evaluate_authorized_aggregate(
            plugin=plugin, candidate=receipt, request=request, contract=contract,
            binding=dev_binding if request.split_role == "development" else gate_binding,
            engine_output=output, artifacts=artifacts,
        )

    trace = run_hm1_pilot(
        broker=broker, development_request=dev_request, gate_request=gate_request,
        bindings={dev_request.capability_grant_id: dev_binding, gate_request.capability_grant_id: gate_binding},
        runtime_locks={dev_request.capability_grant_id: runtime.lock, gate_request.capability_grant_id: runtime.lock},
        tokens={dev_request.capability_grant_id: dev_token, gate_request.capability_grant_id: gate_token},
        evaluator=real_evaluator,
        budget=HM1PilotBudget.open(
            root / "budget.json", run_id=run_id, contract_hash=contract.sha256,
            limits={"development": 1, "gate": 1, "final": 0},
        ),
    )
    after_status = _status_fingerprint(project)
    assert (protected_head, protected_tree) == _git_identity(project)
    assert before_status == after_status
    assert trace.development.status == trace.gate.status == "incomparable"
    assert trace.query_counts == {dev_request.capability_grant_id: 1, gate_request.capability_grant_id: 1}
    assert trace.final_query_count == 0
    results = root / "results"
    results.mkdir(parents=True, exist_ok=True)
    trace.development.write(results / "development.json")
    trace.gate.write(results / "gate.json")
    receipt_payload = {"claim_scope": "engineering_only", "status": "incomparable",
                       "evaluator_code_sha256": evaluator_sha256, "config_sha256": config_sha256,
                       "input_identity_sha256": contract.to_dict()["data"]["snapshot_sha256"],
                       "candidate_sha256": receipt.candidate.artifact.sha256, "contract_sha256": contract.sha256,
                       "protected_head": protected_head, "protected_tree": protected_tree,
                       "git_status_fingerprint_before": before_status, "git_status_fingerprint_after": after_status,
                       "development_query_count": 1, "gate_query_count": 1, "final_query_count": 0,
                       "result_ids": [trace.development.result_id, trace.gate.result_id]}
    (root / "receipt.json").write_bytes(canonical_json_bytes(receipt_payload))
    ledger = EvidenceLedger.create(root / "ledger")
    tree = HypothesisTreeStore.create(root / "tree", run_id=run_id, contract_hash=contract.sha256,
                                      root=NodeDraft(**node_draft_kwargs("root", parent_id=None, proposal_order=1)))
    event = lambda event_id, event_type, **kwargs: ledger.append({
        "schema_version": "1.0", "run_id": run_id, "event_id": event_id,
        "timestamp": "2026-08-23T00:00:00Z", "event_type": event_type, "actor": "coordinator",
        "contract_hash": contract.sha256, "node_id": kwargs.get("node_id"), "attempt_id": kwargs.get("attempt_id"),
        "split_role": kwargs.get("split_role", "development"), "payload": kwargs.get("payload", {})})
    event("run.started", "run.started")
    draft = node_draft_kwargs(node_id, parent_id="root", proposal_order=2,
                              scope={**scope_mapping(data_snapshot_sha256=contract.to_dict()["data"]["snapshot_sha256"],
                                                     cost_model_sha256=contract.to_dict()["cost_model"]["sha256"])})
    draft.update(candidate_id="candidate.hm1.engineering", candidate_artifact=receipt.candidate.artifact.to_dict(),
                 code_ref="refs/heads/exec/hm1-engineering")
    tree.apply(TreeMutation.add_node(NodeDraft(**draft)), expected_revision=tree.load().revision,
               idempotency_key="real.hm1.propose")
    event("hypothesis.proposed", "hypothesis.proposed", node_id=node_id, attempt_id=dev_request.attempt_id)
    tree.apply(TreeMutation.update_node(node_id, {"status": "incomparable", "lifecycle": "done",
                                                   "admissibility": "incomparable", "attempt_ids": [dev_request.attempt_id, gate_request.attempt_id],
                                                   "evidence_refs": [{"evidence_id": "evidence.hm1.engineering", "attempt_id": dev_request.attempt_id,
                                                                      "result_id": trace.development.result_id, "split_role": "development", "level": "observed",
                                                                      "claim": "engineering-only aggregate; cost semantics unavailable", "conditions": ["development_only"],
                                                                      "status": "valid", "artifact_refs": []}],
                                                   "failure": {"failure_type": "incomparable", "summary": "hm1.cost_semantics_unavailable",
                                                               "evidence_ids": ["evidence.hm1.engineering"]}}),
               expected_revision=tree.load().revision, idempotency_key="real.hm1.result")
    event("evaluation.completed.dev", "evaluation.completed", node_id=node_id, attempt_id=dev_request.attempt_id,
          split_role="development", payload={"request_id": dev_request.request_id, "result_id": trace.development.result_id})
    event("evaluation.completed.gate", "evaluation.completed", node_id=node_id, attempt_id=gate_request.attempt_id,
          split_role="gate", payload={"request_id": gate_request.request_id, "result_id": trace.gate.result_id})
    event("decision.recorded", "decision.recorded", node_id=node_id, attempt_id=dev_request.attempt_id,
          payload={"claim_scope": "engineering_only", "status": "incomparable"})

    contract_ref = _ref(root, "contract.hm1.engineering", "contract.json", contract.to_json().encode())
    tree_path = root / "tree.json"
    tree.load().write(tree_path)
    tree_ref = _ref(root, "tree.hm1.engineering", "tree.json", tree_path.read_bytes())
    summary = {"claim_scope": "development_only", "status": "incomparable",
               "development_query_count": 1, "gate_query_count": 1, "final_query_count": 0,
               "result_ids": [trace.development.result_id, trace.gate.result_id]}
    summary_ref = _ref(root, "summary.hm1.engineering", "reports/summary.json",
                       canonical_json_bytes(summary))
    report_placeholder = _ref(root, "report.hm1.engineering", "reports/research.html",
                              b"placeholder", "text/html")
    head = ledger.verify()
    head_payload = {"run_id": head.run_id, "contract_hash": head.contract_hash,
                    "last_sequence": head.last_sequence, "last_event_hash": head.last_event_hash}
    head_ref = _ref(root, "ledger.head.hm1.engineering", "ledger_head.json",
                    canonical_json_bytes(head_payload))
    package = {"schema_version": "1.0", "run_id": run_id, "contract": contract_ref,
               "selected_candidate": _ref(root, "candidate.hm1.engineering",
                                           "candidate/strategies/candidate.py", candidate_path.read_bytes(),
                                           "text/x-python"),
               "selected_commit": "a" * 40, "tree": tree_ref, "research_head": dict(tree.load().ledger_head),
               "ledger": {"artifact": head_ref, "last_sequence": head.last_sequence,
                          "last_event_hash": head.last_event_hash},
               "family_snapshot_hash": "b" * 64, "reports": [summary_ref, report_placeholder],
               "stop_reason": "frontier_exhausted", "final_state": "sealed_unopened",
               "integrity_status": "pass", "claim_scope": "development_only", "missing_artifacts": []}
    rendered = render_research_report(package, root)
    package["reports"][1] = _ref(root, "report.hm1.engineering", "reports/research.html",
                                 rendered.encode(), "text/html")
    write_research_report(package, root, root / "reports/research.html")
    event("report.generated", "report.generated", payload={"artifact_id": "report.hm1.engineering"})
    head = ledger.verify()
    head_payload = {"run_id": head.run_id, "contract_hash": head.contract_hash,
                    "last_sequence": head.last_sequence, "last_event_hash": head.last_event_hash}
    head_ref = _ref(root, "ledger.head.hm1.engineering", "ledger_head.json",
                    canonical_json_bytes(head_payload))
    package["ledger"] = {"artifact": head_ref, "last_sequence": head.last_sequence,
                          "last_event_hash": head.last_event_hash}
    package_path = root / "research_package.json"
    package_path.write_bytes(canonical_json_bytes(package))
    assert audit_research_package(package, root).integrity_status == "pass"
    assert package_path.is_file() and (root / "reports/research.html").is_file()
    assert str(project) not in rendered
