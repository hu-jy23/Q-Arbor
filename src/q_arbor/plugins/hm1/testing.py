"""Closed fabricated HM1 development capability for C9 qualification."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from q_arbor.contracts import QuantResearchContract
from q_arbor.evaluation import (
    ArtifactRef,
    ArtifactSink,
    AuthorizedSplit,
    CheckResult,
    ContentAddressedArtifactStore,
    EvaluationBinding,
    EvaluationBoundaryError,
    EvaluationFailure,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationRequest,
    EvaluationResult,
    EvaluationSchemaError,
    MetricValue,
    ReasonCode,
    ValidatedCandidate,
    VerifiedRuntimeLock,
    freeze_evaluation_result,
)
from q_arbor.evaluation.results import _freeze_controlled_evaluation_result

from . import (
    HM1EngineOutput,
    HM1FuturesPlugin,
    HM1SplitData,
    _require_hm1_mock_contract,
)


def _typed_values(
    values: Sequence[Any], expected_type: type[Any], field: str
) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise EvaluationSchemaError(f"{field} must be a sequence")
    detached = tuple(values)
    if not all(isinstance(item, expected_type) for item in detached):
        raise EvaluationSchemaError(f"{field} contains an unsupported value")
    return detached


def _fold_payloads(
    fold_metrics: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    if isinstance(fold_metrics, (str, bytes, bytearray)) or not isinstance(
        fold_metrics, Sequence
    ):
        raise EvaluationSchemaError("fold_metrics must be a sequence")
    payloads: list[dict[str, object]] = []
    for fold in fold_metrics:
        if not isinstance(fold, Mapping) or set(fold) != {
            "fold_id",
            "time_range",
            "metrics",
        }:
            raise EvaluationSchemaError("fold metric fields do not match C6")
        metrics = _typed_values(fold["metrics"], MetricValue, "fold metrics")  # type: ignore[arg-type]
        payloads.append(
            {
                "fold_id": fold["fold_id"],
                "time_range": fold["time_range"],
                "metrics": [item.to_dict() for item in metrics],
            }
        )
    return payloads


class _HM1MockDevelopmentSplit:
    __slots__ = (
        "_artifacts",
        "_binding",
        "_contract",
        "_data",
        "_initialized",
        "_request",
    )

    def __init__(self) -> None:  # pragma: no cover - construction is closed
        raise TypeError("use make_hm1_mock_development_split")

    @classmethod
    def _create(
        cls,
        *,
        request: EvaluationRequest,
        contract: QuantResearchContract,
        binding: EvaluationBinding,
        data: HM1SplitData,
        artifacts: ArtifactSink,
    ) -> _HM1MockDevelopmentSplit:
        instance = cls.__new__(cls)
        object.__setattr__(instance, "_request", request)
        object.__setattr__(instance, "_contract", contract)
        object.__setattr__(instance, "_binding", binding)
        object.__setattr__(instance, "_data", data)
        object.__setattr__(instance, "_artifacts", artifacts)
        object.__setattr__(instance, "_initialized", True)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("authorized HM1 split is immutable")
        object.__setattr__(self, name, value)

    @property
    def request(self) -> EvaluationRequest:
        return self._request

    @property
    def contract(self) -> QuantResearchContract:
        return self._contract

    @property
    def binding(self) -> EvaluationBinding:
        return self._binding

    @property
    def data(self) -> HM1SplitData:
        return self._data

    @property
    def artifacts(self) -> ArtifactSink:
        return self._artifacts

    def _provenance(self) -> dict[str, object]:
        candidate = self.binding.candidate_receipt.candidate
        contract = self.contract.to_dict()
        return {
            "candidate_sha256": candidate.candidate_hash,
            "code_commit": candidate.code_commit,
            "data_snapshot_sha256": contract["data"]["snapshot_sha256"],
            "split_manifest_hash": self.request.split_manifest_hash,
            "contract_hash": self.contract.sha256,
            "plugin_code_sha256": self.binding.plugin_identity.code_sha256,
            "evaluator_sha256": self.binding.runtime_lock.evaluator_sha256,
            "config_sha256": self.binding.runtime_lock.config_sha256,
            "seed": self.binding.seed,
        }

    def _contaminated_payload(self) -> dict[str, object]:
        contract = self.contract.to_dict()
        metrics = contract["metrics"]
        primary = metrics["primary"]
        return {
            "result_id": self.binding.result_id,
            "request_id": self.request.request_id,
            "status": "contaminated",
            "split_role": self.request.split_role,
            "primary_metric": {
                "name": primary["name"],
                "value": None,
                "direction": primary["direction"],
                "unit": primary["unit"],
            },
            "constraints": [
                {
                    "name": item["name"],
                    "status": "not_observed",
                    "evidence": "evaluation.not_observed",
                }
                for item in metrics["hard_constraints"]
            ],
            "diagnostics": [
                {
                    "name": item["name"],
                    "value": None,
                    "direction": item["direction"],
                    "unit": item["unit"],
                }
                for item in metrics["diagnostics"]
            ],
            "fold_metrics": [],
            "costs": {
                "gross": None,
                "transaction_cost": None,
                "net": None,
                "turnover": None,
                "cost_model_sha256": contract["cost_model"]["sha256"],
            },
            "checks": [
                {
                    "name": name,
                    "status": "not_observed",
                    "evidence": "evaluation.not_observed",
                }
                for name in self.binding.runtime_lock.required_check_names
            ],
            "artifacts": [],
            "provenance": self._provenance(),
            "failure": {
                "failure_type": "contamination",
                "summary": "runtime.contamination",
                "evidence_ids": [],
            },
            "statistical_diagnostics": [],
            "warnings": [],
        }

    def _contaminated_result(self) -> EvaluationResult:
        # C5 G01/G02/G05 and C6 J01/J04: discard all suspect HM1 aggregates.
        return _freeze_controlled_evaluation_result(
            self._contaminated_payload(),
            binding=self.binding,
            runtime_drift_observed=True,
        )

    def make_result(
        self,
        *,
        status: str,
        primary_metric: MetricValue,
        constraints: Sequence[CheckResult],
        diagnostics: Sequence[MetricValue],
        fold_metrics: Sequence[Mapping[str, object]],
        costs: Mapping[str, object],
        checks: Sequence[CheckResult],
        artifacts: Sequence[ArtifactRef] = (),
        failure: EvaluationFailure | None = None,
        warnings: Sequence[ReasonCode] = (),
    ) -> EvaluationResult:
        if not isinstance(status, str) or not isinstance(primary_metric, MetricValue):
            raise EvaluationSchemaError("result status/primary wrapper is invalid")
        if status not in {
            "implementation_failure",
            "evaluation_failure",
            "incomparable",
        }:
            raise EvaluationInvariantError("HM1 mock result status is unsupported")
        constraint_values = _typed_values(constraints, CheckResult, "constraints")
        diagnostic_values = _typed_values(diagnostics, MetricValue, "diagnostics")
        check_values = _typed_values(checks, CheckResult, "checks")
        artifact_values = _typed_values(artifacts, ArtifactRef, "artifacts")
        warning_values = _typed_values(warnings, ReasonCode, "warnings")
        if not isinstance(costs, Mapping):
            raise EvaluationSchemaError("costs must be a mapping")
        if failure is not None and not isinstance(failure, EvaluationFailure):
            raise EvaluationSchemaError("failure must use the common wrapper")
        payload = {
            "result_id": self.binding.result_id,
            "request_id": self.request.request_id,
            "status": status,
            "split_role": self.request.split_role,
            "primary_metric": primary_metric.to_dict(),
            "constraints": [item.to_dict() for item in constraint_values],
            "diagnostics": [item.to_dict() for item in diagnostic_values],
            "fold_metrics": _fold_payloads(fold_metrics),
            "costs": dict(costs),
            "checks": [item.to_dict() for item in check_values],
            "artifacts": [item.to_dict() for item in artifact_values],
            "provenance": self._provenance(),
            "failure": None if failure is None else failure.to_dict(),
            "statistical_diagnostics": [],
            "warnings": [str(item) for item in warning_values],
        }
        try:
            self.binding.runtime_lock.verify()
        except EvaluationIntegrityError:
            return self._contaminated_result()
        try:
            result = freeze_evaluation_result(payload, binding=self.binding)
        except EvaluationIntegrityError:
            try:
                self.binding.runtime_lock.verify()
            except EvaluationIntegrityError:
                return self._contaminated_result()
            raise
        try:
            self.binding.runtime_lock.verify()
        except EvaluationIntegrityError:
            return self._contaminated_result()
        return result


def make_hm1_mock_development_split(
    request: EvaluationRequest,
    contract: QuantResearchContract,
    candidate: ValidatedCandidate,
    plugin: HM1FuturesPlugin,
    runtime_lock: VerifiedRuntimeLock,
    *,
    result_id: str,
    evaluation_seed: int,
    artifact_store: ContentAddressedArtifactStore,
    produced_by_event_id: str,
    engine_output: HM1EngineOutput,
    untrusted_failure_detail: str | None = None,
) -> AuthorizedSplit:
    """Mint a fabricated aggregate-only HM1 development view."""

    if not isinstance(request, EvaluationRequest):
        raise EvaluationSchemaError("HM1 request type mismatch")
    if request.split_role != "development":
        raise EvaluationBoundaryError("HM1 mock factory is development-only")
    if (
        not isinstance(contract, QuantResearchContract)
        or not isinstance(candidate, ValidatedCandidate)
        or not isinstance(plugin, HM1FuturesPlugin)
        or not isinstance(runtime_lock, VerifiedRuntimeLock)
        or not isinstance(artifact_store, ContentAddressedArtifactStore)
        or not isinstance(engine_output, HM1EngineOutput)
        or (
            untrusted_failure_detail is not None
            and not isinstance(untrusted_failure_detail, str)
        )
    ):
        raise EvaluationSchemaError("HM1 mock factory input type mismatch")
    mapping = contract.to_dict()
    if mapping["task_kind"] != "futures_strategy":
        raise EvaluationIntegrityError("HM1 contract task kind mismatch")
    _require_hm1_mock_contract(mapping)
    development = mapping["data"]["splits"]["development"]
    fold_policy = runtime_lock.fold_policy
    if (
        fold_policy.mode != "aggregate_only"
        or fold_policy.expected_fold_ids
        or fold_policy.required_metric_names != (mapping["metrics"]["primary"]["name"],)
    ):
        raise EvaluationIntegrityError("HM1 fold policy mismatch")
    binding = EvaluationBinding.create(
        request,
        contract,
        candidate,
        plugin.identity,
        runtime_lock,
        result_id=result_id,
        seed=evaluation_seed,
        artifact_resolver=artifact_store,
    )
    data = HM1SplitData(
        data_snapshot_sha256=mapping["data"]["snapshot_sha256"],
        split_manifest_sha256=development["manifest_sha256"],
        engine_output=engine_output,
        untrusted_failure_detail=untrusted_failure_detail,
    )
    artifacts = artifact_store.scope(
        request_id=request.request_id,
        produced_by_event_id=produced_by_event_id,
        runtime_lock=runtime_lock,
    )
    return _HM1MockDevelopmentSplit._create(
        request=request,
        contract=contract,
        binding=binding,
        data=data,
        artifacts=artifacts,
    )


__all__ = ["make_hm1_mock_development_split"]
