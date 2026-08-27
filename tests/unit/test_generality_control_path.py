from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import sys

import pytest

from q_arbor.evaluation import EvaluationSchemaError
from q_arbor.generality import (
    AdapterDescriptor,
    ControlPath,
    EvaluationStagePolicy,
    ProvenanceSeed,
    RunnerReceipt,
    RunnerRequest,
    SubprocessRunner,
)


H = "a" * 64
G = "b" * 40


def _adapter(adapter_id: str = "adapter.unknown-shape/v7") -> AdapterDescriptor:
    return AdapterDescriptor.from_mapping(
        {
            "adapter_id": adapter_id,
            "adapter_version": "7.0",
            "adapter_code_sha256": H,
            "candidate_codec_id": "codec.candidate/open-v1",
            "invocation_codec_id": "codec.invocation/open-v1",
            "result_codec_id": "codec.result/open-v1",
            "runner_id": "runner.fixture/v1",
            "required_output_descriptors": ["predictions", "metrics"],
            "objective_descriptors": ["objective.primary"],
            "diagnostic_descriptors": ["diagnostic.any"],
            "failure_mapping_id": "failure.generic/v1",
            "provenance_requirements": ["data_manifest", "evaluator"],
        }
    )


def _stage(
    stage_id: str = "lab.example/arbitrary-stage-v9",
    *,
    selectable: bool = True,
) -> EvaluationStagePolicy:
    return EvaluationStagePolicy.from_mapping(
        {
            "stage_id": stage_id,
            "data_visibility": "capability-scoped",
            "selection_use_allowed": selectable,
            "query_budget": 8,
            "feedback_availability_rule": "on-completion",
            "feedback_granularity_descriptor": "objective-vector",
            "target_maturity_predicate": "receipt-complete",
            "contamination_transition_policy": "feedback-use-is-recorded",
            "claim_boundary": "fixture-only",
            "principal_capabilities": ["evaluate.development"],
        }
    )


def _request(adapter: AdapterDescriptor, stage: EvaluationStagePolicy) -> RunnerRequest:
    return RunnerRequest.from_mapping(
        {
            "invocation_id": "invocation.fixture-001",
            "adapter_ref": adapter.sha256,
            "stage_policy_ref": stage.sha256,
            "candidate_artifact_ref": H,
            "cell_root_capability": "cell.fixture",
            "environment_lock_ref": H,
            "immutable_argv": [sys.executable, "-c", "pass"],
            "environment_allowlist": {},
            "timeout_seconds": 30,
            "required_outputs": [],
        }
    )


def _seed() -> ProvenanceSeed:
    return ProvenanceSeed.from_mapping(
        {
            "cell_id": "cell.fixture",
            "cell_contract_sha256": H,
            "data_manifest_sha256": H,
            "baseline_manifest_sha256": H,
            "evaluator_sha256": H,
            "code_commit": G,
            "artifact_manifest_sha256": H,
        }
    )


class _Runner:
    def __init__(self, termination: str = "succeeded") -> None:
        self.termination = termination

    def run(self, request: RunnerRequest) -> RunnerReceipt:
        return RunnerReceipt.from_mapping(
            {
                "runner_id": "runner.fixture/v1",
                "runner_code_sha256": H,
                "request_sha256": request.sha256,
                "started_event_id": "event.started",
                "completed_event_id": "event.completed",
                "termination": self.termination,
                "exit_code": 0 if self.termination == "succeeded" else 1,
                "stdout_ref": None,
                "stderr_ref": None,
                "output_artifact_refs": [],
                "resource_usage": {"wall_seconds": 0.01},
            }
        )


def _decode(_: RunnerReceipt, *, availability: str = "available", mature: bool = True) -> Mapping[str, object]:
    return {
        "availability": availability,
        "mature": mature,
        "status": "success" if availability == "available" else "deferred",
        "objective_vector": [
            {"objective_id": "objective.primary", "value": 1.25, "direction": "maximize"}
        ],
        "decision_objective_id": "objective.primary" if availability == "available" else None,
        "constraints": [],
        "diagnostic_records": [],
        "output_artifact_refs": [],
        "failure": None,
        "warnings": [],
    }


@pytest.mark.parametrize(
    "shape",
    ["tabular-regression", "multi-target-ranking", "hierarchical-forecast"],
)
def test_open_adapter_and_stage_share_one_control_path(shape: str) -> None:
    adapter = _adapter(f"adapter.{shape}/v99")
    stage = _stage(f"org.unseen/{shape}-stage")
    outcome = ControlPath().execute(
        proposal_id=f"proposal.{shape}",
        adapter=adapter,
        stage=stage,
        request=_request(adapter, stage),
        provenance_seed=_seed(),
        runner=_Runner(),
        decoder=_decode,
    )

    assert outcome.decision["selection_eligible"] is True
    assert [record["phase"] for record in outcome.transcript] == [
        "propose",
        "dispatch",
        "evaluate",
        "decide",
        "recover",
        "report",
    ]
    assert outcome.result.stage_id == stage.stage_id
    assert outcome.report["adapter_id"] == adapter.adapter_id


@pytest.mark.parametrize(
    ("selectable", "availability", "mature", "reason"),
    [
        (False, "available", True, "stage_forbids_selection"),
        (True, "deferred", False, "result_not_available"),
        (True, "available", False, "result_not_mature"),
    ],
)
def test_nonselectable_or_immature_result_is_preserved_without_selection(
    selectable: bool, availability: str, mature: bool, reason: str
) -> None:
    adapter = _adapter()
    stage = _stage(selectable=selectable)
    outcome = ControlPath().execute(
        proposal_id="proposal.fixture",
        adapter=adapter,
        stage=stage,
        request=_request(adapter, stage),
        provenance_seed=_seed(),
        runner=_Runner(),
        decoder=lambda receipt: _decode(receipt, availability=availability, mature=mature),
    )

    assert outcome.decision == {"selection_eligible": False, "reason": reason}
    assert outcome.receipt.sha256 == outcome.result.provenance.runner_receipt_sha256
    assert outcome.transcript_sha256


@pytest.mark.parametrize(
    ("termination", "failure_code"),
    [
        ("timeout", "runner_timeout"),
        ("nonzero_exit", "runner_nonzero_exit"),
        ("missing_output", "runner_missing_output"),
    ],
)
def test_runner_failures_become_bounded_task_neutral_results(
    termination: str, failure_code: str
) -> None:
    adapter = _adapter()
    stage = _stage()
    outcome = ControlPath().execute(
        proposal_id="proposal.failure",
        adapter=adapter,
        stage=stage,
        request=_request(adapter, stage),
        provenance_seed=_seed(),
        runner=_Runner(termination),
        decoder=lambda _: pytest.fail("decoder must not run"),
    )

    assert outcome.result.status == "failure"
    assert outcome.result.failure == {"code": failure_code}
    assert outcome.decision["selection_eligible"] is False


def test_malformed_decoder_result_becomes_bounded_failure() -> None:
    adapter = _adapter()
    stage = _stage()
    outcome = ControlPath().execute(
        proposal_id="proposal.malformed",
        adapter=adapter,
        stage=stage,
        request=_request(adapter, stage),
        provenance_seed=_seed(),
        runner=_Runner(),
        decoder=lambda _: {"status": "success"},
    )
    assert outcome.result.failure == {"code": "malformed_result_envelope"}


def test_descriptor_rejects_task_or_platform_semantics() -> None:
    raw = _adapter().to_dict()
    raw["platform_name"] = "forbidden"
    with pytest.raises(EvaluationSchemaError):
        AdapterDescriptor.from_mapping(raw)


def test_subprocess_runner_uses_capability_and_no_shell(tmp_path: Path) -> None:
    cell = tmp_path / "cell"
    cell.mkdir()
    adapter = _adapter()
    stage = _stage()
    request = RunnerRequest.from_mapping(
        {
            **_request(adapter, stage).to_dict(),
            "immutable_argv": [sys.executable, "-c", "from pathlib import Path; Path('metrics.json').write_text('{}')"],
            "required_outputs": ["metrics.json"],
        }
    )
    runner = SubprocessRunner(
        artifact_root=tmp_path / "artifacts",
        capabilities={"cell.fixture": cell},
        runner_id="runner.fixture/v1",
        runner_code_sha256=H,
    )
    receipt = runner.run(request)
    assert receipt.termination == "succeeded"
    assert len(receipt.output_artifact_refs) == 1


@pytest.mark.parametrize(
    ("argv", "required_outputs", "termination"),
    [
        ([sys.executable, "-c", "raise SystemExit(3)"], [], "nonzero_exit"),
        ([sys.executable, "-c", "pass"], ["missing.json"], "missing_output"),
    ],
)
def test_subprocess_runner_maps_process_failures(
    tmp_path: Path,
    argv: list[str],
    required_outputs: list[str],
    termination: str,
) -> None:
    cell = tmp_path / "cell"
    cell.mkdir()
    adapter = _adapter()
    stage = _stage()
    request = RunnerRequest.from_mapping(
        {
            **_request(adapter, stage).to_dict(),
            "immutable_argv": argv,
            "required_outputs": required_outputs,
        }
    )
    receipt = SubprocessRunner(
        artifact_root=tmp_path / "artifacts",
        capabilities={"cell.fixture": cell},
        runner_id="runner.fixture/v1",
        runner_code_sha256=H,
    ).run(request)
    assert receipt.termination == termination
