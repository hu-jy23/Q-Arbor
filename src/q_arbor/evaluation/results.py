"""EvaluationResult invariants, terminal factories, summaries, and C8 binding."""

from __future__ import annotations

import math
import os
import re
from collections.abc import Mapping
from datetime import date
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Final, cast

from q_arbor.hypotheses import QuantHypothesisNode

from .candidate import ValidatedCandidate, _contract_snapshot
from .codec import (
    FrozenJSON,
    JSONValue,
    atomic_write,
    canonical_normalized_bytes,
    normalize_mapping,
    read_json_object,
    require_git_commit,
    require_identifier,
    require_reason_code,
    require_sha256,
    validate_definition,
    validate_discriminator,
)
from .errors import (
    EvaluationError,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationSchemaError,
)
from .runtime import EvaluationBinding, EvaluationRequest
from .values import (
    ArtifactRef,
    CheckResult,
    EvaluationFailure,
    MetricValue,
    ReasonCode,
    _ImmutableJSON,
)

_STATUS_FAILURES: Final = {
    "success": {None},
    "invalid_candidate": {"invalid_candidate", "constraint_violation"},
    "implementation_failure": {"implementation_failure"},
    "access_denied": {"access_denied"},
    "evaluation_failure": {"evaluation_failure", "timeout", "interruption"},
    "incomparable": {"incomparable"},
    "contaminated": {"contamination"},
}
_SUMMARY_KEYS: Final = {
    "schema_version",
    "result_id",
    "request_id",
    "status",
    "split_role",
    "primary_metric",
    "constraints",
    "diagnostics",
    "fold_metrics",
    "costs",
    "checks",
    "failure_type",
    "failure_code",
    "warning_codes",
}
_ISO_DATE_RANGE_RE: Final = re.compile(
    r"(?P<start>\d{4}-\d{2}-\d{2})/(?P<end>\d{4}-\d{2}-\d{2})\Z"
)


def _metric_specs(
    contract_mapping: Mapping[str, JSONValue],
) -> tuple[dict[str, JSONValue], list[dict[str, JSONValue]]]:
    metrics = cast(dict[str, JSONValue], contract_mapping["metrics"])
    return (
        cast(dict[str, JSONValue], metrics["primary"]),
        cast(list[dict[str, JSONValue]], metrics["diagnostics"]),
    )


def _metric_order(contract_mapping: Mapping[str, JSONValue]) -> list[str]:
    primary, diagnostics = _metric_specs(contract_mapping)
    return [
        cast(str, primary["name"]),
        *[cast(str, item["name"]) for item in diagnostics],
    ]


def _canonicalize_result(
    result: dict[str, JSONValue],
    *,
    binding: EvaluationBinding,
) -> None:
    contract_mapping = _contract_snapshot(binding.contract)
    metrics = cast(dict[str, JSONValue], contract_mapping["metrics"])
    constraint_order = [
        cast(str, item["name"])
        for item in cast(list[dict[str, JSONValue]], metrics["hard_constraints"])
    ]
    diagnostic_order = [
        cast(str, item["name"])
        for item in cast(list[dict[str, JSONValue]], metrics["diagnostics"])
    ]
    metric_order = _metric_order(contract_mapping)
    required_checks = list(binding.runtime_lock.required_check_names)

    def sort_named(field: str, order: list[str]) -> None:
        values = result.get(field)
        if isinstance(values, list) and all(isinstance(item, dict) for item in values):
            rank = {name: index for index, name in enumerate(order)}
            values.sort(
                key=lambda item: (
                    rank.get(
                        cast(str, cast(dict[str, Any], item).get("name")), len(rank)
                    ),
                    cast(str, cast(dict[str, Any], item).get("name", "")),
                )
            )

    sort_named("constraints", constraint_order)
    sort_named("diagnostics", diagnostic_order)
    folds = result.get("fold_metrics")
    if isinstance(folds, list) and all(isinstance(item, dict) for item in folds):
        fold_rank = {
            fold_id: index
            for index, fold_id in enumerate(
                binding.runtime_lock.fold_policy.expected_fold_ids
            )
        }
        folds.sort(
            key=lambda item: (
                fold_rank.get(
                    cast(str, cast(dict[str, Any], item).get("fold_id")), len(fold_rank)
                ),
                cast(str, cast(dict[str, Any], item).get("fold_id", "")),
            )
        )
        for raw_fold in folds:
            fold = cast(dict[str, JSONValue], raw_fold)
            fold_values = fold.get("metrics")
            if isinstance(fold_values, list) and all(
                isinstance(item, dict) for item in fold_values
            ):
                rank = {name: index for index, name in enumerate(metric_order)}
                fold_values.sort(
                    key=lambda item: (
                        rank.get(
                            cast(str, cast(dict[str, Any], item).get("name")),
                            len(rank),
                        ),
                        cast(str, cast(dict[str, Any], item).get("name", "")),
                    )
                )
    checks = result.get("checks")
    if isinstance(checks, list) and all(isinstance(item, dict) for item in checks):
        rank = {name: index for index, name in enumerate(required_checks)}
        checks.sort(
            key=lambda item: (
                rank.get(cast(str, cast(dict[str, Any], item).get("name")), len(rank)),
                cast(str, cast(dict[str, Any], item).get("name", "")),
            )
        )
    artifacts = result.get("artifacts")
    if isinstance(artifacts, list) and all(
        isinstance(item, dict) for item in artifacts
    ):
        artifacts.sort(
            key=lambda item: (
                cast(str, cast(dict[str, Any], item).get("artifact_id", "")),
                cast(str, cast(dict[str, Any], item).get("relative_path", "")),
            )
        )
    warnings = result.get("warnings")
    if isinstance(warnings, list) and all(isinstance(item, str) for item in warnings):
        warnings.sort()


def _require_exact_names(values: list[Any], expected: list[str], field: str) -> None:
    names = [cast(str, value.name) for value in values]
    if names != expected:
        raise EvaluationInvariantError(f"{field} names/order differ from contract")
    if len(names) != len(set(names)):
        raise EvaluationInvariantError(f"{field} names must be unique")


def _require_metric_matches(
    metric: MetricValue,
    spec: Mapping[str, JSONValue],
    field: str,
) -> None:
    if (
        metric.name != spec["name"]
        or metric.direction != spec["direction"]
        or metric.unit != spec["unit"]
    ):
        raise EvaluationInvariantError(f"{field} differs from its contract metric")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _require_finite(value: Any, field: str, *, nullable: bool) -> int | float | None:
    if value is None and nullable:
        return None
    if not _is_number(value) or (isinstance(value, float) and not math.isfinite(value)):
        raise EvaluationInvariantError(f"{field} must be finite")
    return cast(int | float, value)


def _diagnostic_check_name(metric_name: str) -> str:
    digest = sha256(metric_name.encode("utf-8")).hexdigest()[:16]
    return f"diagnostic.{digest}.observed"


def _validate_costs(
    costs: Mapping[str, JSONValue],
    *,
    contract_mapping: Mapping[str, JSONValue],
    success: bool,
) -> None:
    expected_keys = {
        "gross",
        "transaction_cost",
        "net",
        "turnover",
        "cost_model_sha256",
    }
    if set(costs) != expected_keys:
        raise EvaluationSchemaError("result costs fields do not match C6")
    contract_cost = cast(dict[str, JSONValue], contract_mapping["cost_model"])
    require_sha256(costs["cost_model_sha256"], "result cost_model_sha256")
    if costs["cost_model_sha256"] != contract_cost["sha256"]:
        raise EvaluationIntegrityError("result cost model differs from contract")
    gross = _require_finite(costs["gross"], "cost gross", nullable=not success)
    transaction_cost = _require_finite(
        costs["transaction_cost"],
        "transaction cost",
        nullable=not success,
    )
    net = _require_finite(costs["net"], "cost net", nullable=not success)
    turnover = _require_finite(costs["turnover"], "cost turnover", nullable=not success)
    if transaction_cost is not None and transaction_cost < 0:
        raise EvaluationInvariantError("transaction cost must be non-negative")
    if turnover is not None and turnover < 0:
        raise EvaluationInvariantError("turnover must be non-negative")
    nonnull_reconciliation = (gross, transaction_cost, net)
    if all(item is not None for item in nonnull_reconciliation):
        try:
            if Decimal(str(gross)) - Decimal(str(transaction_cost)) != Decimal(
                str(net)
            ):
                raise EvaluationInvariantError("gross-cost does not equal net exactly")
        except (InvalidOperation, ValueError) as exc:
            raise EvaluationInvariantError("cost values cannot be reconciled") from exc
    elif success:
        raise EvaluationInvariantError("success requires complete cost values")


def _require_null_projection(
    *,
    constraints: list[CheckResult],
    diagnostics: list[MetricValue],
    folds: list[dict[str, JSONValue]],
    checks: list[CheckResult],
    artifacts: list[ArtifactRef],
    costs: Mapping[str, JSONValue],
    failure: EvaluationFailure,
    warnings: list[str],
    required_checks: list[str],
) -> None:
    if any(
        item.status != "not_observed" or item.evidence != "evaluation.not_observed"
        for item in constraints
    ):
        raise EvaluationInvariantError(
            "terminal null result cannot retain constraint observations"
        )
    if any(metric.value is not None for metric in diagnostics):
        raise EvaluationInvariantError("terminal null result cannot retain diagnostics")
    if [item.name for item in checks] != required_checks or any(
        item.status != "not_observed" or item.evidence != "evaluation.not_observed"
        for item in checks
    ):
        raise EvaluationInvariantError(
            "terminal null result must contain exact not-observed checks"
        )
    if folds or artifacts:
        raise EvaluationInvariantError(
            "terminal null result cannot retain folds/artifacts"
        )
    if any(
        costs[field] is not None
        for field in ("gross", "transaction_cost", "net", "turnover")
    ):
        raise EvaluationInvariantError("terminal null result cannot retain cost values")
    if failure.evidence_ids:
        raise EvaluationInvariantError(
            "terminal null result cannot retain failure evidence"
        )
    if warnings:
        raise EvaluationInvariantError("terminal null result cannot retain warnings")


class EvaluationResult(_ImmutableJSON):
    """Deeply immutable, fully bound C6 EvaluationResult."""

    __slots__ = (
        "_controlled_runtime_drift",
        "_required_check_names",
        "_runtime_lock",
    )

    @classmethod
    def _from_binding(
        cls,
        normalized: dict[str, JSONValue],
        binding: EvaluationBinding,
        *,
        controlled_runtime_drift: bool = False,
    ) -> EvaluationResult:
        instance = super()._from_normalized(normalized)
        object.__setattr__(
            instance,
            "_required_check_names",
            binding.runtime_lock.required_check_names,
        )
        object.__setattr__(instance, "_runtime_lock", binding.runtime_lock)
        object.__setattr__(
            instance,
            "_controlled_runtime_drift",
            controlled_runtime_drift,
        )
        return instance

    def write(self, path: str | os.PathLike[str]) -> None:
        """Persist only while the evaluator/config identity is still live."""

        if not self._controlled_runtime_drift:
            self._runtime_lock.verify()
        atomic_write(path, self.to_json().encode("utf-8"))

    @property
    def result_id(self) -> str:
        return cast(str, self._get("result_id"))

    @property
    def request_id(self) -> str:
        return cast(str, self._get("request_id"))

    @property
    def status(self) -> str:
        return cast(str, self._get("status"))

    @property
    def split_role(self) -> str:
        return cast(str, self._get("split_role"))

    @property
    def primary_metric(self) -> MetricValue:
        return MetricValue.from_mapping(
            cast(Mapping[str, Any], self._get("primary_metric"))
        )

    @property
    def constraints(self) -> tuple[CheckResult, ...]:
        return tuple(
            CheckResult.from_mapping(cast(Mapping[str, Any], item))
            for item in cast(
                tuple[Mapping[str, FrozenJSON], ...], self._get("constraints")
            )
        )

    @property
    def diagnostics(self) -> tuple[MetricValue, ...]:
        return tuple(
            MetricValue.from_mapping(cast(Mapping[str, Any], item))
            for item in cast(
                tuple[Mapping[str, FrozenJSON], ...], self._get("diagnostics")
            )
        )

    @property
    def fold_metrics(self) -> tuple[Mapping[str, object], ...]:
        return tuple(
            MappingProxyType(
                {
                    "fold_id": fold["fold_id"],
                    "time_range": fold["time_range"],
                    "metrics": tuple(
                        MetricValue.from_mapping(cast(Mapping[str, Any], metric))
                        for metric in cast(
                            tuple[Mapping[str, FrozenJSON], ...], fold["metrics"]
                        )
                    ),
                }
            )
            for fold in cast(
                tuple[Mapping[str, FrozenJSON], ...], self._get("fold_metrics")
            )
        )

    @property
    def costs(self) -> Mapping[str, FrozenJSON]:
        return cast(Mapping[str, FrozenJSON], self._get("costs"))

    @property
    def checks(self) -> tuple[CheckResult, ...]:
        return tuple(
            CheckResult.from_mapping(cast(Mapping[str, Any], item))
            for item in cast(tuple[Mapping[str, FrozenJSON], ...], self._get("checks"))
        )

    @property
    def artifacts(self) -> tuple[ArtifactRef, ...]:
        return tuple(
            ArtifactRef.from_mapping(cast(Mapping[str, Any], item))
            for item in cast(
                tuple[Mapping[str, FrozenJSON], ...], self._get("artifacts")
            )
        )

    @property
    def provenance(self) -> Mapping[str, FrozenJSON]:
        return cast(Mapping[str, FrozenJSON], self._get("provenance"))

    @property
    def failure(self) -> EvaluationFailure | None:
        value = self._get("failure")
        if value is None:
            return None
        return EvaluationFailure.from_mapping(cast(Mapping[str, Any], value))

    @property
    def statistical_diagnostics(self) -> tuple[Mapping[str, FrozenJSON], ...]:
        return cast(
            tuple[Mapping[str, FrozenJSON], ...],
            self._get("statistical_diagnostics"),
        )

    @property
    def warnings(self) -> tuple[ReasonCode, ...]:
        return tuple(
            ReasonCode.parse(value)
            for value in cast(tuple[str, ...], self._get("warnings"))
        )


def _validate_result_mapping(
    mapping: Mapping[str, Any],
    *,
    binding: EvaluationBinding,
    canonicalize: bool,
    verify_artifacts: bool,
) -> dict[str, JSONValue]:
    if not isinstance(binding, EvaluationBinding):
        raise EvaluationSchemaError("binding must be an EvaluationBinding")
    normalized = normalize_mapping(mapping)
    validate_discriminator(normalized, "evaluation_result")
    if canonicalize:
        _canonicalize_result(normalized, binding=binding)

    require_identifier(normalized["result_id"], "result_id")
    require_identifier(normalized["request_id"], "result request_id")
    if normalized["result_id"] != binding.result_id:
        raise EvaluationIntegrityError("result_id differs from binding")
    if normalized["request_id"] != binding.request.request_id:
        raise EvaluationIntegrityError("result request_id differs from request")
    if normalized["split_role"] != binding.request.split_role:
        raise EvaluationIntegrityError("result split role differs from request")
    status = cast(str, normalized["status"])

    failure_mapping = normalized["failure"]
    failure = None
    if failure_mapping is not None:
        failure = EvaluationFailure.from_mapping(cast(dict[str, Any], failure_mapping))
        if failure.failure_type == "none":
            raise EvaluationInvariantError("result failure_type=none is forbidden")
    failure_type = None if failure is None else failure.failure_type
    if status not in _STATUS_FAILURES or failure_type not in _STATUS_FAILURES[status]:
        raise EvaluationInvariantError("result status/failure combination is invalid")

    warnings = cast(list[JSONValue], normalized["warnings"])
    if not all(isinstance(item, str) for item in warnings):
        raise EvaluationSchemaError("result warnings must be strings")
    for warning in warnings:
        require_reason_code(warning, "result warning")
    warning_values = cast(list[str], warnings)
    if warning_values != sorted(warning_values) or len(warning_values) != len(
        set(warning_values)
    ):
        raise EvaluationInvariantError("result warnings must be sorted and unique")
    strict_null = status in {
        "implementation_failure",
        "access_denied",
        "evaluation_failure",
        "contaminated",
    } or (status == "invalid_candidate" and failure_type == "invalid_candidate")

    contract_mapping = _contract_snapshot(binding.contract)
    primary_spec, diagnostic_specs = _metric_specs(contract_mapping)
    primary = MetricValue.from_mapping(
        cast(dict[str, Any], normalized["primary_metric"])
    )
    _require_metric_matches(primary, primary_spec, "primary metric")

    raw_constraints = cast(list[dict[str, Any]], normalized["constraints"])
    constraints = [CheckResult.from_mapping(item) for item in raw_constraints]
    constraint_specs = cast(
        list[dict[str, JSONValue]],
        cast(dict[str, JSONValue], contract_mapping["metrics"])["hard_constraints"],
    )
    _require_exact_names(
        constraints,
        [cast(str, item["name"]) for item in constraint_specs],
        "constraints",
    )

    raw_diagnostics = cast(list[dict[str, Any]], normalized["diagnostics"])
    diagnostics = [MetricValue.from_mapping(item) for item in raw_diagnostics]
    _require_exact_names(
        diagnostics,
        [cast(str, item["name"]) for item in diagnostic_specs],
        "diagnostics",
    )
    for index, metric in enumerate(diagnostics):
        _require_metric_matches(metric, diagnostic_specs[index], "diagnostic")

    raw_checks = cast(list[dict[str, Any]], normalized["checks"])
    checks = [CheckResult.from_mapping(item) for item in raw_checks]
    for check in checks:
        require_reason_code(check.name, "result check name")
    check_names = [check.name for check in checks]
    if len(check_names) != len(set(check_names)):
        raise EvaluationInvariantError("result check names must be unique")
    required_checks = list(binding.runtime_lock.required_check_names)
    if not set(required_checks) <= set(check_names):
        raise EvaluationInvariantError("result is missing runtime-required checks")
    expected_check_order = [
        *required_checks,
        *sorted(name for name in check_names if name not in set(required_checks)),
    ]
    if check_names != expected_check_order:
        raise EvaluationInvariantError("result checks are not in canonical order")

    check_by_name = {check.name: check for check in checks}
    for diagnostic in diagnostics:
        observation_name = _diagnostic_check_name(diagnostic.name)
        if observation_name not in required_checks:
            raise EvaluationInvariantError(
                "runtime lock is missing a diagnostic observation check"
            )
        observed = check_by_name[observation_name]
        if diagnostic.value is None and observed.status == "pass":
            raise EvaluationInvariantError("null diagnostic cannot claim observation")
        if diagnostic.value is not None and observed.status != "pass":
            raise EvaluationInvariantError(
                "observed diagnostic requires a passing check"
            )

    fold_policy = binding.runtime_lock.fold_policy
    folds = cast(list[dict[str, JSONValue]], normalized["fold_metrics"])
    fold_ids: list[str] = []
    contract_metric_specs = {
        cast(str, primary_spec["name"]): primary_spec,
        **{cast(str, spec["name"]): spec for spec in diagnostic_specs},
    }
    required_fold_metrics = list(fold_policy.required_metric_names)
    if not set(required_fold_metrics) <= set(contract_metric_specs):
        raise EvaluationInvariantError("fold policy names non-contract metrics")
    expected_fold_metric_order = [
        name
        for name in _metric_order(contract_mapping)
        if name in required_fold_metrics
    ]
    if status != "success":
        expected_fold_metric_order = [
            name
            for name in expected_fold_metric_order
            if name != cast(str, primary_spec["name"])
        ]
    for fold in folds:
        if set(fold) != {"fold_id", "time_range", "metrics"}:
            raise EvaluationSchemaError("fold metric fields do not match C6")
        fold_id = require_identifier(fold["fold_id"], "fold ID")
        fold_ids.append(fold_id)
        time_range = fold["time_range"]
        if (
            not isinstance(time_range, str)
            or not time_range
            or any(
                ord(character) < 32 or ord(character) == 127 for character in time_range
            )
        ):
            raise EvaluationInvariantError("fold time_range is invalid")
        date_range = _ISO_DATE_RANGE_RE.fullmatch(time_range)
        if date_range is not None:
            try:
                start = date.fromisoformat(date_range.group("start"))
                end = date.fromisoformat(date_range.group("end"))
            except ValueError as exc:
                raise EvaluationInvariantError("fold time_range is invalid") from exc
            if start >= end:
                raise EvaluationInvariantError("fold time_range must be non-empty")
        raw_metrics = fold["metrics"]
        if not isinstance(raw_metrics, list):
            raise EvaluationSchemaError("fold metrics must be an array")
        fold_values = [
            MetricValue.from_mapping(cast(dict[str, Any], item)) for item in raw_metrics
        ]
        _require_exact_names(
            fold_values,
            expected_fold_metric_order,
            "fold metrics",
        )
        for metric in fold_values:
            _require_metric_matches(
                metric,
                contract_metric_specs[metric.name],
                "fold metric",
            )
            if metric.value is None:
                raise EvaluationInvariantError("required fold metric is null")
    if len(fold_ids) != len(set(fold_ids)):
        raise EvaluationInvariantError("fold IDs must be unique")
    if fold_policy.mode == "required" and status == "success":
        if fold_ids != list(fold_policy.expected_fold_ids):
            raise EvaluationInvariantError("result folds differ from runtime policy")
    elif fold_policy.mode == "required":
        canonical_subset = [
            fold_id
            for fold_id in fold_policy.expected_fold_ids
            if fold_id in set(fold_ids)
        ]
        if fold_ids != canonical_subset:
            raise EvaluationInvariantError("result folds are not a canonical subset")
    elif folds:
        raise EvaluationInvariantError("aggregate-only policy forbids fold metrics")

    raw_artifacts = cast(list[dict[str, Any]], normalized["artifacts"])
    artifacts = [ArtifactRef.from_mapping(item) for item in raw_artifacts]
    costs = cast(dict[str, JSONValue], normalized["costs"])
    if strict_null:
        if failure is None:
            raise EvaluationInvariantError("terminal null result requires a failure")
        _require_null_projection(
            constraints=constraints,
            diagnostics=diagnostics,
            folds=folds,
            checks=checks,
            artifacts=artifacts,
            costs=costs,
            failure=failure,
            warnings=warning_values,
            required_checks=required_checks,
        )
    artifact_order = [(item.artifact_id, item.relative_path) for item in artifacts]
    if artifact_order != sorted(artifact_order) or len(artifact_order) != len(
        set(artifact_order)
    ):
        raise EvaluationInvariantError("result artifacts must be sorted and unique")
    artifact_ids = [item.artifact_id for item in artifacts]
    artifact_paths = [item.relative_path for item in artifacts]
    if len(artifact_ids) != len(set(artifact_ids)) or len(artifact_paths) != len(
        set(artifact_paths)
    ):
        raise EvaluationInvariantError("artifact IDs and paths must each be unique")
    for artifact in artifacts:
        if artifact.media_type is None or (
            artifact.kind,
            artifact.media_type,
        ) not in set(binding.runtime_lock.allowed_artifacts):
            raise EvaluationInvariantError("result artifact kind/media is not allowed")
        if verify_artifacts:
            binding.artifact_resolver.verify_issued(
                artifact,
                request_id=binding.request.request_id,
                runtime_lock_sha256=binding.runtime_lock.sha256,
            )

    provenance = cast(dict[str, JSONValue], normalized["provenance"])
    for field in (
        "candidate_sha256",
        "data_snapshot_sha256",
        "split_manifest_hash",
        "contract_hash",
        "plugin_code_sha256",
        "evaluator_sha256",
        "config_sha256",
    ):
        require_sha256(provenance[field], f"result provenance {field}")
    require_git_commit(provenance["code_commit"], "result provenance code_commit")
    expected_provenance: dict[str, JSONValue] = {
        "candidate_sha256": binding.candidate_receipt.candidate.candidate_hash,
        "code_commit": binding.candidate_receipt.candidate.code_commit,
        "data_snapshot_sha256": cast(dict[str, JSONValue], contract_mapping["data"])[
            "snapshot_sha256"
        ],
        "split_manifest_hash": binding.request.split_manifest_hash,
        "contract_hash": binding.contract.sha256,
        "plugin_code_sha256": binding.plugin_identity.code_sha256,
        "evaluator_sha256": binding.runtime_lock.evaluator_sha256,
        "config_sha256": binding.runtime_lock.config_sha256,
        "seed": binding.seed,
    }
    if provenance != expected_provenance:
        raise EvaluationIntegrityError("result provenance differs from binding")

    _validate_costs(
        costs,
        contract_mapping=contract_mapping,
        success=status == "success",
    )
    if normalized["statistical_diagnostics"] != []:
        raise EvaluationInvariantError(
            "C9 results cannot claim statistical diagnostics"
        )

    if status == "success":
        if primary.value is None:
            raise EvaluationInvariantError("success requires a finite primary metric")
        if any(constraint.status != "pass" for constraint in constraints):
            raise EvaluationInvariantError("success requires all constraints to pass")
        if any(check_by_name[name].status != "pass" for name in required_checks):
            raise EvaluationInvariantError("success requires required checks to pass")
        if any(metric.value is None for metric in diagnostics):
            raise EvaluationInvariantError("success requires complete diagnostics")
    else:
        if primary.value is not None:
            raise EvaluationInvariantError("non-success result cannot expose a primary")
        primary_name = cast(str, primary_spec["name"])
        if any(
            cast(dict[str, Any], metric)["name"] == primary_name
            for fold in folds
            for metric in cast(list[dict[str, Any]], fold["metrics"])
        ):
            raise EvaluationInvariantError(
                "non-success result cannot expose fold primary metrics"
            )
    return normalized


def freeze_evaluation_result(
    mapping: Mapping[str, Any],
    *,
    binding: EvaluationBinding,
) -> EvaluationResult:
    binding.runtime_lock.verify()
    normalized = _validate_result_mapping(
        mapping,
        binding=binding,
        canonicalize=True,
        verify_artifacts=True,
    )
    return EvaluationResult._from_binding(normalized, binding)


def validate_evaluation_result(
    mapping: Mapping[str, Any],
    *,
    binding: EvaluationBinding,
) -> EvaluationResult:
    binding.runtime_lock.verify()
    normalized = _validate_result_mapping(
        mapping,
        binding=binding,
        canonicalize=False,
        verify_artifacts=True,
    )
    return EvaluationResult._from_binding(normalized, binding)


def _freeze_controlled_evaluation_result(
    mapping: Mapping[str, Any],
    *,
    binding: EvaluationBinding,
    runtime_drift_observed: bool = True,
) -> EvaluationResult:
    """Close a post-computation runtime drift without re-reading drifted bytes.

    This package-private C10 seam accepts exactly one host-generated null
    projection. C5 G01/G02/G05 and C6 J04 require that no observation or
    artifact from the contaminated computation can cross this boundary.
    """

    if runtime_drift_observed is not True:
        raise EvaluationInvariantError("controlled freeze requires observed drift")
    normalized = _validate_result_mapping(
        mapping,
        binding=binding,
        canonicalize=False,
        verify_artifacts=False,
    )
    expected = _null_result_payload(
        binding,
        status="contaminated",
        failure_type="contamination",
        reason_code=ReasonCode.parse("runtime.contamination"),
    )
    if normalized != expected:
        raise EvaluationInvariantError(
            "controlled freeze requires the exact contaminated null template"
        )
    return EvaluationResult._from_binding(
        normalized,
        binding,
        controlled_runtime_drift=True,
    )


def load_evaluation_result(
    path: str | os.PathLike[str],
    *,
    binding: EvaluationBinding,
    expected_sha256: str | None = None,
) -> EvaluationResult:
    binding.runtime_lock.verify()
    mapping = read_json_object(path)
    normalized = _validate_result_mapping(
        mapping,
        binding=binding,
        canonicalize=False,
        verify_artifacts=True,
    )
    result = EvaluationResult._from_binding(normalized, binding)
    if expected_sha256 is not None:
        require_sha256(expected_sha256, "expected result sha256")
        if result.sha256 != expected_sha256:
            raise EvaluationIntegrityError("evaluation result hash does not match")
    return result


def canonical_evaluation_result_bytes(
    result: EvaluationResult | Mapping[str, Any],
) -> bytes:
    if isinstance(result, EvaluationResult):
        return result.to_json().encode("utf-8")
    normalized = normalize_mapping(result)
    validate_discriminator(normalized, "evaluation_result")
    return canonical_normalized_bytes(normalized)


def compute_evaluation_result_hash(
    result: EvaluationResult | Mapping[str, Any],
) -> str:
    return sha256(canonical_evaluation_result_bytes(result)).hexdigest()


def _null_result_payload(
    binding: EvaluationBinding,
    *,
    status: str,
    failure_type: str,
    reason_code: ReasonCode,
) -> dict[str, JSONValue]:
    contract_mapping = _contract_snapshot(binding.contract)
    primary, diagnostics = _metric_specs(contract_mapping)
    constraints = cast(
        list[dict[str, JSONValue]],
        cast(dict[str, JSONValue], contract_mapping["metrics"])["hard_constraints"],
    )
    required_checks = list(binding.runtime_lock.required_check_names)
    for diagnostic in diagnostics:
        required_name = _diagnostic_check_name(cast(str, diagnostic["name"]))
        if required_name not in required_checks:
            raise EvaluationInvariantError(
                "runtime lock lacks a diagnostic observation check"
            )
    candidate = binding.candidate_receipt.candidate
    data = cast(dict[str, JSONValue], contract_mapping["data"])
    cost_model = cast(dict[str, JSONValue], contract_mapping["cost_model"])
    return {
        "result_id": binding.result_id,
        "request_id": binding.request.request_id,
        "status": status,
        "split_role": binding.request.split_role,
        "primary_metric": {
            "name": primary["name"],
            "value": None,
            "direction": primary["direction"],
            "unit": primary["unit"],
        },
        "constraints": [
            {
                "name": constraint["name"],
                "status": "not_observed",
                "evidence": "evaluation.not_observed",
            }
            for constraint in constraints
        ],
        "diagnostics": [
            {
                "name": diagnostic["name"],
                "value": None,
                "direction": diagnostic["direction"],
                "unit": diagnostic["unit"],
            }
            for diagnostic in diagnostics
        ],
        "fold_metrics": [],
        "costs": {
            "gross": None,
            "transaction_cost": None,
            "net": None,
            "turnover": None,
            "cost_model_sha256": cost_model["sha256"],
        },
        "checks": [
            {
                "name": name,
                "status": "not_observed",
                "evidence": "evaluation.not_observed",
            }
            for name in required_checks
        ],
        "artifacts": [],
        "provenance": {
            "candidate_sha256": candidate.candidate_hash,
            "code_commit": candidate.code_commit,
            "data_snapshot_sha256": data["snapshot_sha256"],
            "split_manifest_hash": binding.request.split_manifest_hash,
            "contract_hash": binding.contract.sha256,
            "plugin_code_sha256": binding.plugin_identity.code_sha256,
            "evaluator_sha256": binding.runtime_lock.evaluator_sha256,
            "config_sha256": binding.runtime_lock.config_sha256,
            "seed": binding.seed,
        },
        "failure": {
            "failure_type": failure_type,
            "summary": str(reason_code),
            "evidence_ids": [],
        },
        "statistical_diagnostics": [],
        "warnings": [],
    }


def _trusted_terminal_result(
    binding: EvaluationBinding,
    payload: dict[str, JSONValue],
) -> EvaluationResult:
    normalized = _validate_result_mapping(
        payload,
        binding=binding,
        canonicalize=False,
        verify_artifacts=False,
    )
    return EvaluationResult._from_binding(normalized, binding)


def make_candidate_failure_result(
    *,
    binding: EvaluationBinding,
    reason_code: str | ReasonCode,
) -> EvaluationResult:
    if not isinstance(binding, EvaluationBinding):
        raise EvaluationSchemaError("binding must be an EvaluationBinding")
    receipt = binding.candidate_receipt
    if receipt.status == "valid":
        raise EvaluationInvariantError("candidate failure requires a non-valid receipt")
    reason = ReasonCode.parse(str(reason_code))
    if receipt.status == "invalid_candidate":
        status = failure_type = "invalid_candidate"
    elif receipt.status == "implementation_failure":
        status = failure_type = "implementation_failure"
    else:
        raise EvaluationInvariantError("candidate receipt status is unsupported")
    return _trusted_terminal_result(
        binding,
        _null_result_payload(
            binding,
            status=status,
            failure_type=failure_type,
            reason_code=reason,
        ),
    )


def make_access_denied_result(
    *,
    binding: EvaluationBinding,
    reason_code: str | ReasonCode,
) -> EvaluationResult:
    if not isinstance(binding, EvaluationBinding):
        raise EvaluationSchemaError("binding must be an EvaluationBinding")
    if not isinstance(binding.candidate_receipt, ValidatedCandidate):
        raise EvaluationInvariantError("access denial requires a validated candidate")
    reason = ReasonCode.parse(str(reason_code))
    return _trusted_terminal_result(
        binding,
        _null_result_payload(
            binding,
            status="access_denied",
            failure_type="access_denied",
            reason_code=reason,
        ),
    )


class EvaluationSummary(_ImmutableJSON):
    """Deterministic view that excludes artifact and provenance identities."""

    @classmethod
    def from_result(cls, result: EvaluationResult) -> EvaluationSummary:
        if not isinstance(result, EvaluationResult):
            raise EvaluationSchemaError("summary source must be an EvaluationResult")
        failure = result.failure
        result_mapping = result.to_dict()
        summary: dict[str, JSONValue] = {
            "schema_version": "1.0",
            "result_id": result.result_id,
            "request_id": result.request_id,
            "status": result.status,
            "split_role": result.split_role,
            "primary_metric": result.primary_metric.to_dict(),
            "constraints": [
                {"name": item.name, "status": item.status}
                for item in result.constraints
            ],
            "diagnostics": [item.to_dict() for item in result.diagnostics],
            "fold_metrics": [
                {
                    "fold_id": fold["fold_id"],
                    "metrics": fold["metrics"],
                }
                for fold in cast(
                    list[dict[str, JSONValue]], result_mapping["fold_metrics"]
                )
            ],
            "costs": {
                field: cast(JSONValue, result.costs[field])
                for field in ("gross", "transaction_cost", "net", "turnover")
            },
            "checks": [
                {"name": item.name, "status": item.status} for item in result.checks
            ],
            "failure_type": None if failure is None else failure.failure_type,
            "failure_code": None if failure is None else failure.summary,
            "warning_codes": [str(item) for item in result.warnings],
        }
        if set(summary) != _SUMMARY_KEYS:
            raise EvaluationInvariantError("summary projection keys drifted")
        return cls._from_normalized(summary)

    @property
    def schema_version(self) -> str:
        return cast(str, self._get("schema_version"))

    @property
    def result_id(self) -> str:
        return cast(str, self._get("result_id"))

    @property
    def request_id(self) -> str:
        return cast(str, self._get("request_id"))

    @property
    def status(self) -> str:
        return cast(str, self._get("status"))

    @property
    def split_role(self) -> str:
        return cast(str, self._get("split_role"))

    @property
    def primary_metric(self) -> MetricValue:
        return MetricValue.from_mapping(
            cast(Mapping[str, Any], self._get("primary_metric"))
        )

    @property
    def constraints(self) -> tuple[Mapping[str, FrozenJSON], ...]:
        return cast(tuple[Mapping[str, FrozenJSON], ...], self._get("constraints"))

    @property
    def diagnostics(self) -> tuple[Mapping[str, FrozenJSON], ...]:
        return cast(tuple[Mapping[str, FrozenJSON], ...], self._get("diagnostics"))

    @property
    def fold_metrics(self) -> tuple[Mapping[str, FrozenJSON], ...]:
        return cast(tuple[Mapping[str, FrozenJSON], ...], self._get("fold_metrics"))

    @property
    def costs(self) -> Mapping[str, FrozenJSON]:
        return cast(Mapping[str, FrozenJSON], self._get("costs"))

    @property
    def checks(self) -> tuple[Mapping[str, FrozenJSON], ...]:
        return cast(tuple[Mapping[str, FrozenJSON], ...], self._get("checks"))

    @property
    def failure_type(self) -> str | None:
        return cast(str | None, self._get("failure_type"))

    @property
    def failure_code(self) -> str | None:
        return cast(str | None, self._get("failure_code"))

    @property
    def warning_codes(self) -> tuple[str, ...]:
        return cast(tuple[str, ...], self._get("warning_codes"))


def validate_evaluation_evidence(
    result: EvaluationResult,
    *,
    request: EvaluationRequest,
    node: QuantHypothesisNode,
    evidence: Mapping[str, Any],
) -> None:
    if (
        not isinstance(result, EvaluationResult)
        or not isinstance(request, EvaluationRequest)
        or not isinstance(node, QuantHypothesisNode)
    ):
        raise EvaluationSchemaError("evidence binding requires typed C8/C9 values")
    try:
        normalized = normalize_mapping(evidence)
        validate_definition(normalized, "EvidenceRef")
        require_identifier(normalized["evidence_id"], "evidence_id")
        require_identifier(normalized.get("attempt_id"), "evidence attempt_id")
        require_identifier(normalized.get("result_id"), "evidence result_id")
        artifacts = [
            ArtifactRef.from_mapping(cast(dict[str, Any], item))
            for item in cast(list[dict[str, Any]], normalized["artifact_refs"])
        ]
    except EvaluationError as exc:
        raise EvaluationIntegrityError("evidence mapping cannot be trusted") from exc

    if (
        result.request_id != request.request_id
        or result.split_role != request.split_role
    ):
        raise EvaluationIntegrityError("result/request binding differs")
    provenance = result.provenance
    # C6 J04 and C9 §7 require observed evidence to bind the complete
    # result/request identity, even while a node has no candidate projection.
    if (
        provenance["candidate_sha256"] != request.candidate_hash
        or provenance["contract_hash"] != request.contract_hash
        or provenance["plugin_code_sha256"] != request.plugin.code_sha256
        or provenance["split_manifest_hash"] != request.split_manifest_hash
    ):
        raise EvaluationIntegrityError("result provenance differs from request")
    if request.node_id != node.id or request.attempt_id not in node.attempt_ids:
        raise EvaluationIntegrityError("request does not bind the target node attempt")
    if (
        normalized["level"] != "observed"
        or normalized["status"] != "valid"
        or normalized.get("attempt_id") != request.attempt_id
        or normalized.get("result_id") != result.result_id
        or normalized.get("split_role") != result.split_role
    ):
        raise EvaluationIntegrityError("evidence identity/status differs")
    result_artifacts = {item.to_json() for item in result.artifacts}
    if any(item.to_json() not in result_artifacts for item in artifacts):
        raise EvaluationIntegrityError("evidence references a non-result artifact")
    if result.status != "success" or result.failure is not None:
        raise EvaluationIntegrityError("non-success result cannot support evidence")
    primary = result.primary_metric.value
    if primary is None or (isinstance(primary, float) and not math.isfinite(primary)):
        raise EvaluationIntegrityError("evidence result has no finite primary")
    if any(item.status != "pass" for item in result.constraints):
        raise EvaluationIntegrityError("evidence result failed a hard constraint")
    checks = {item.name: item for item in result.checks}
    if any(
        name not in checks or checks[name].status != "pass"
        for name in result._required_check_names
    ):
        raise EvaluationIntegrityError("evidence result failed a required check")

    scope = node.scope
    if (
        scope["data_snapshot_sha256"] != result.provenance["data_snapshot_sha256"]
        or scope["cost_model_sha256"] != result.costs["cost_model_sha256"]
    ):
        raise EvaluationIntegrityError("node scope differs from result provenance")
    candidate_artifact = node.candidate_artifact
    if (
        candidate_artifact is not None
        and candidate_artifact != request.candidate.to_dict()
    ):
        raise EvaluationIntegrityError("node candidate artifact differs from request")
    if node.score is not None and node.score != primary:
        raise EvaluationIntegrityError("node score differs from result primary")
