"""Mock-only HM1 futures adapter with static Python validation."""

from __future__ import annotations

import ast
import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any, Final

from q_arbor.contracts import QuantResearchContract
from q_arbor.evaluation import (
    AuthorizedSplit,
    CandidateArtifact,
    CandidateValidation,
    CheckResult,
    EvaluationDecodeError,
    EvaluationFailure,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationPluginError,
    EvaluationResult,
    EvaluationSchemaError,
    EvaluationSummary,
    MetricValue,
    PluginIdentity,
    ReasonCode,
    ValidatedCandidate,
    freeze_candidate_validation,
)
from q_arbor.evaluation.candidate import _classify_candidate_surface

_ARTIFACT_TYPE: Final = "q-arbor.hm1-strategy-python.v1"
_ENGINE_KEYS: Final = {
    "schema_version",
    "status",
    "portfolio_daily_sharpe",
    "annualized_return",
    "max_drawdown",
    "calmar",
    "win_rate",
    "trade_count",
    "coverage_count",
    "expected_coverage_count",
    "cost_semantics",
    "warning_codes",
}
_METRIC_FIELDS: Final = (
    "portfolio_daily_sharpe",
    "annualized_return",
    "max_drawdown",
    "calmar",
    "win_rate",
)
_COUNT_FIELDS: Final = (
    "trade_count",
    "coverage_count",
    "expected_coverage_count",
)
_ENGINE_STATUSES: Final = {
    "complete",
    "implementation_failure",
    "evaluation_failure",
    "timeout",
    "incomparable",
}
_ALLOWED_IMPORTS: Final = {
    "math",
    "typing",
    "dataclasses",
    "research_env.backtest.strategy",
    "research_env.backtest.models",
}
_FORBIDDEN_ROOTS: Final = {
    "os",
    "sys",
    "subprocess",
    "socket",
    "pathlib",
    "shutil",
    "requests",
    "httpx",
    "urllib",
    "importlib",
}
_FORBIDDEN_CALLS: Final = {
    "open",
    "eval",
    "exec",
    "compile",
    "__import__",
    "input",
}


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


_HM1_COST_SEMANTICS_SHA256: Final = hashlib.sha256(
    _canonical_json(
        {
            "kind": "hm1_cost_semantics",
            "schema_version": "1.0",
            "status": "unavailable",
        }
    )
).hexdigest()
_HM1_SUPPORTED_DOMAIN_BYTES: Final = _canonical_json(
    {
        "metrics": {
            "primary": {
                "name": "portfolio_daily_sharpe",
                "direction": "maximize",
                "unit": "ratio",
                "aggregation": "aggregate_only",
            },
            "hard_constraints": [],
            "diagnostics": [
                {
                    "name": name,
                    "direction": direction,
                    "unit": unit,
                    "aggregation": "aggregate_only",
                }
                for name, direction, unit in (
                    ("annualized_return", "maximize", "fraction"),
                    ("max_drawdown", "minimize", "fraction"),
                    ("calmar", "maximize", "ratio"),
                    ("win_rate", "maximize", "fraction"),
                    ("trade_count", "minimize", "count"),
                    ("coverage_count", "maximize", "count"),
                    ("expected_coverage_count", "maximize", "count"),
                )
            ],
            "admission_rule": (
                "C9 HM1 results are incomparable until cost semantics exist"
            ),
        },
        "cost_model": {
            "model_id": "hm1.cost.unavailable.v1",
            "sha256": _HM1_COST_SEMANTICS_SHA256,
            "components": [
                {
                    "name": "transaction_cost",
                    "rule": "unavailable in C9 HM1 mock",
                }
            ],
            "currency": "not_applicable",
        },
    }
)


def _require_hm1_mock_contract(mapping: Mapping[str, object]) -> None:
    """Keep C5 G05 / C6 J01/J04 mock aggregates under fixed semantics."""

    try:
        live_domain = {
            "metrics": mapping["metrics"],
            "cost_model": mapping["cost_model"],
        }
        matches = _canonical_json(live_domain) == _HM1_SUPPORTED_DOMAIN_BYTES
    except (KeyError, TypeError, ValueError) as exc:
        raise EvaluationIntegrityError("HM1 mock contract mismatch") from exc
    if not matches:
        raise EvaluationIntegrityError("HM1 mock contract mismatch")


def _finite_or_none(value: object, field: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvaluationSchemaError(f"{field} must be a finite number or null")
    try:
        converted = float(value)
    except (OverflowError, ValueError) as exc:
        raise EvaluationDecodeError(f"{field} must be finite") from exc
    if not math.isfinite(converted):
        raise EvaluationDecodeError(f"{field} must be finite")
    return converted


def _count_or_none(value: object, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvaluationSchemaError(f"{field} must be a nonnegative integer or null")
    return value


class HM1EngineOutput:
    """Closed aggregate output; no command, path, row, or free-form detail exists."""

    __slots__ = ("_canonical", "_initialized", "_mapping", "_sha256")

    def __init__(self) -> None:  # pragma: no cover - construction is closed
        raise TypeError("use HM1EngineOutput.from_mapping")

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, object]) -> HM1EngineOutput:
        if set(mapping) != _ENGINE_KEYS:
            raise EvaluationSchemaError("HM1 engine output has unexpected keys")
        if mapping["schema_version"] != "1.0":
            raise EvaluationSchemaError("unsupported HM1 engine-output version")
        status = mapping["status"]
        if not isinstance(status, str) or status not in _ENGINE_STATUSES:
            raise EvaluationSchemaError("unsupported HM1 engine status")
        if mapping["cost_semantics"] != "unavailable":
            raise EvaluationSchemaError(
                "HM1 cost semantics must remain unavailable in C9"
            )
        normalized: dict[str, object] = {
            "schema_version": "1.0",
            "status": status,
            "cost_semantics": "unavailable",
        }
        for field in _METRIC_FIELDS:
            normalized[field] = _finite_or_none(mapping[field], field)
        for field in _COUNT_FIELDS:
            normalized[field] = _count_or_none(mapping[field], field)
        warnings = mapping["warning_codes"]
        if not isinstance(warnings, Sequence) or isinstance(
            warnings, (str, bytes, bytearray)
        ):
            raise EvaluationSchemaError("warning_codes must be an array")
        parsed_warnings = [str(ReasonCode.parse(item)) for item in warnings]
        if parsed_warnings != sorted(set(parsed_warnings)):
            raise EvaluationInvariantError("warning_codes must be sorted and unique")
        normalized["warning_codes"] = parsed_warnings

        expected = normalized["expected_coverage_count"]
        if not isinstance(expected, int) or expected < 1:
            raise EvaluationInvariantError("expected_coverage_count must be positive")
        if status == "complete":
            if any(
                normalized[field] is None for field in _METRIC_FIELDS + _COUNT_FIELDS
            ):
                raise EvaluationInvariantError(
                    "complete HM1 output requires every aggregate"
                )
        else:
            if any(normalized[field] is not None for field in _METRIC_FIELDS):
                raise EvaluationInvariantError(
                    "failed HM1 output may not retain metrics"
                )
            if (
                normalized["trade_count"] is not None
                or normalized["coverage_count"] is not None
            ):
                raise EvaluationInvariantError(
                    "failed HM1 output may not retain observed counts"
                )

        canonical = _canonical_json(normalized)
        instance = cls.__new__(cls)
        object.__setattr__(instance, "_canonical", canonical)
        object.__setattr__(instance, "_mapping", normalized)
        object.__setattr__(instance, "_sha256", hashlib.sha256(canonical).hexdigest())
        object.__setattr__(instance, "_initialized", True)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("HM1EngineOutput is immutable")
        object.__setattr__(self, name, value)

    @property
    def sha256(self) -> str:
        return self._sha256

    @property
    def status(self) -> str:
        return str(self._mapping["status"])

    @property
    def warning_codes(self) -> tuple[ReasonCode, ...]:
        return tuple(ReasonCode.parse(item) for item in self._mapping["warning_codes"])

    def value(self, name: str) -> float | int | None:
        if name not in _METRIC_FIELDS + _COUNT_FIELDS:
            raise KeyError(name)
        value = self._mapping[name]
        if value is None or isinstance(value, (int, float)):
            return value
        raise AssertionError("closed HM1 output contains an invalid value")

    def to_dict(self) -> dict[str, object]:
        return json.loads(self._canonical)

    def to_json(self) -> str:
        return self._canonical.decode("utf-8")

    def __hash__(self) -> int:
        return hash(self._canonical)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, HM1EngineOutput) and self._canonical == other._canonical
        )


class HM1SplitData:
    """Closed C9 view over fabricated aggregate output only."""

    __slots__ = (
        "_data_snapshot_sha256",
        "_engine_output",
        "_initialized",
        "_split_manifest_sha256",
        "_untrusted_failure_detail",
    )

    def __init__(
        self,
        *,
        data_snapshot_sha256: str,
        split_manifest_sha256: str,
        engine_output: HM1EngineOutput,
        untrusted_failure_detail: str | None = None,
    ) -> None:
        object.__setattr__(self, "_data_snapshot_sha256", data_snapshot_sha256)
        object.__setattr__(self, "_split_manifest_sha256", split_manifest_sha256)
        object.__setattr__(self, "_engine_output", engine_output)
        object.__setattr__(self, "_untrusted_failure_detail", untrusted_failure_detail)
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("HM1SplitData is immutable")
        object.__setattr__(self, name, value)

    @property
    def role(self) -> str:
        return "development"

    @property
    def data_snapshot_sha256(self) -> str:
        return self._data_snapshot_sha256

    @property
    def split_manifest_sha256(self) -> str:
        return self._split_manifest_sha256

    def read_engine_output(self) -> HM1EngineOutput:
        if self._untrusted_failure_detail is not None:
            raise RuntimeError(self._untrusted_failure_detail)
        return self._engine_output


def _is_docstring(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _is_json_scalar_assignment(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Assign):
        if len(statement.targets) != 1 or not isinstance(
            statement.targets[0], ast.Name
        ):
            return False
        value = statement.value
    elif isinstance(statement, ast.AnnAssign):
        if not isinstance(statement.target, ast.Name) or not statement.simple:
            return False
        value = statement.value
    else:
        return False
    if not isinstance(value, ast.Constant):
        return False
    scalar = value.value
    if scalar is None or isinstance(scalar, (str, bool, int)):
        return True
    return isinstance(scalar, float) and math.isfinite(scalar)


def _validate_import(statement: ast.Import | ast.ImportFrom) -> None:
    if isinstance(statement, ast.Import):
        if any(alias.name not in _ALLOWED_IMPORTS for alias in statement.names):
            raise ValueError("HM1 candidate imports a non-allowlisted module")
        return
    if statement.level != 0 or statement.module not in _ALLOWED_IMPORTS:
        raise ValueError("HM1 candidate imports a non-allowlisted module")
    if any(alias.name == "*" for alias in statement.names):
        raise ValueError("HM1 candidate may not use star imports")


def _validate_method(node: ast.FunctionDef, expected_args: tuple[str, ...]) -> None:
    if node.decorator_list or node.returns is not None:
        raise ValueError("HM1 lifecycle methods must be undecorated")
    arguments = node.args
    if (
        arguments.posonlyargs
        or arguments.kwonlyargs
        or arguments.vararg is not None
        or arguments.kwarg is not None
        or arguments.defaults
        or arguments.kw_defaults
        or tuple(item.arg for item in arguments.args) != expected_args
    ):
        raise ValueError("HM1 lifecycle method signature mismatch")


def _attribute_root(node: ast.Attribute) -> str | None:
    value: ast.expr = node
    while isinstance(value, ast.Attribute):
        value = value.value
    return value.id if isinstance(value, ast.Name) else None


def _validate_hm1_ast(tree: ast.Module) -> bytes:
    body = list(tree.body)
    if body and _is_docstring(body[0]):
        body.pop(0)
    candidate_classes: list[ast.ClassDef] = []
    for statement in body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            _validate_import(statement)
        elif _is_json_scalar_assignment(statement):
            continue
        elif isinstance(statement, ast.ClassDef):
            candidate_classes.append(statement)
        else:
            raise ValueError("HM1 candidate contains top-level execution")
    if len(candidate_classes) != 1:
        raise ValueError("HM1 candidate must declare exactly one strategy class")
    candidate_class = candidate_classes[0]
    if (
        candidate_class.name != "CandidateStrategy"
        or candidate_class.keywords
        or candidate_class.decorator_list
        or len(candidate_class.bases) != 1
        or not isinstance(candidate_class.bases[0], ast.Name)
        or candidate_class.bases[0].id != "BaseStrategy"
    ):
        raise ValueError("HM1 candidate strategy class declaration is invalid")
    class_body = list(candidate_class.body)
    if class_body and _is_docstring(class_body[0]):
        class_body.pop(0)
    methods: dict[str, ast.FunctionDef] = {}
    expected = {
        "on_bar": ("self", "context"),
        "on_start": ("self", "bars"),
        "on_finish": ("self", "result"),
    }
    for statement in class_body:
        if not isinstance(statement, ast.FunctionDef) or statement.name not in expected:
            raise ValueError("HM1 candidate class contains an unsupported member")
        if statement.name in methods:
            raise ValueError("HM1 candidate repeats a lifecycle method")
        _validate_method(statement, expected[statement.name])
        methods[statement.name] = statement
    if "on_bar" not in methods:
        raise ValueError("HM1 candidate must define on_bar")

    for node in ast.walk(candidate_class):
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)):
            raise ValueError(  # noqa: TRY004
                "HM1 candidate contains a nested escape form"
            )
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("__") or node.attr.endswith("__"):
                raise ValueError("HM1 candidate uses a dunder attribute")
            if _attribute_root(node) in _FORBIDDEN_ROOTS:
                raise ValueError("HM1 candidate uses a forbidden attribute root")
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_ROOTS:
            raise ValueError("HM1 candidate uses a forbidden name")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _FORBIDDEN_CALLS
        ):
            raise ValueError("HM1 candidate calls a forbidden builtin")
    canonical = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return canonical.encode("utf-8")


def _validation_mapping(
    *,
    candidate: CandidateArtifact,
    contract: QuantResearchContract,
    identity: PluginIdentity,
    status: str,
    canonical_sha256: str | None,
    checks: list[dict[str, str]],
    failure_summary: str,
) -> dict[str, object]:
    failure = None
    method = "exact-ast-v1" if canonical_sha256 is not None else "exact-bytes-v1"
    evidence_basis = canonical_sha256 or candidate.artifact.sha256
    family = {
        "family_hint": None,
        "method": method,
        "evidence_sha256": hashlib.sha256(
            f"hm1:{method}:{evidence_basis}".encode()
        ).hexdigest(),
    }
    if status != "valid":
        failure = {
            "failure_type": "invalid_candidate",
            "summary": failure_summary,
            "evidence_ids": [],
        }
    return {
        "schema_version": "1.0",
        "status": status,
        "contract_hash": contract.sha256,
        "plugin": identity.to_dict(),
        "candidate": candidate.artifact.to_dict(),
        "candidate_hash": candidate.candidate_hash,
        "canonical_form_sha256": canonical_sha256,
        "family_evidence": family,
        "changed_paths": list(candidate.changed_paths),
        "checks": checks,
        "failure": failure,
    }


def _mark_check_failed(
    checks: list[dict[str, str]], *, name: str, evidence: str
) -> None:
    for check in checks:
        if check["name"] == name:
            check["status"] = "fail"
            check["evidence"] = evidence
            return
    raise EvaluationInvariantError("internal validation check is missing")


def _diagnostic_check_name(metric_name: str) -> str:
    digest = hashlib.sha256(metric_name.encode("utf-8")).hexdigest()
    return f"diagnostic.{digest[:16]}.observed"


class HM1FuturesPlugin:
    """C9 HM1 adapter; real imports and evaluation remain behind C10."""

    __slots__ = ("_identity", "_initialized")

    def __init__(self) -> None:  # pragma: no cover - construction is closed
        raise TypeError("use HM1FuturesPlugin.create")

    @classmethod
    def create(cls, identity: PluginIdentity) -> HM1FuturesPlugin:
        if identity.to_dict()["artifact_type"] != _ARTIFACT_TYPE:
            raise EvaluationPluginError("HM1 plugin artifact type mismatch")
        instance = cls.__new__(cls)
        object.__setattr__(instance, "_identity", identity)
        object.__setattr__(instance, "_initialized", True)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("HM1FuturesPlugin is immutable")
        object.__setattr__(self, name, value)

    @property
    def identity(self) -> PluginIdentity:
        return self._identity

    def validate(
        self, candidate: CandidateArtifact, contract: QuantResearchContract
    ) -> CandidateValidation:
        if (
            not isinstance(contract, QuantResearchContract)
            or contract.to_dict()["task_kind"] != "futures_strategy"
        ):
            raise EvaluationIntegrityError("HM1 contract task kind mismatch")
        surface_failure = _classify_candidate_surface(candidate, contract)
        checks = [
            {
                "name": "candidate.kind",
                "status": "pass",
                "evidence": "candidate.kind.ok",
            },
            {
                "name": "candidate.surface",
                "status": "pass" if surface_failure is None else "fail",
                "evidence": (
                    "candidate.surface.ok"
                    if surface_failure is None
                    else str(surface_failure)
                ),
            },
            {"name": "hm1.ast", "status": "pass", "evidence": "hm1.ast.ok"},
        ]
        status = "valid" if surface_failure is None else "invalid_candidate"
        failure_summary = (
            "hm1.invalid_candidate" if surface_failure is None else str(surface_failure)
        )
        canonical_sha256: str | None = None
        kind_valid = True
        try:
            if candidate.artifact.to_dict()["kind"] != _ARTIFACT_TYPE:
                kind_valid = False
                _mark_check_failed(
                    checks,
                    name="candidate.kind",
                    evidence="candidate.kind.invalid",
                )
                raise ValueError("candidate kind mismatch")
            try:
                source = candidate.payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("HM1 candidate is not UTF-8") from exc
            if source.startswith("\ufeff"):
                raise ValueError("HM1 candidate may not contain a BOM")
            try:
                tree = ast.parse(source, mode="exec", type_comments=True)
            except (SyntaxError, ValueError) as exc:
                raise ValueError("HM1 candidate is not valid Python") from exc
            canonical_sha256 = hashlib.sha256(
                b"q-arbor.hm1.canonical-form.v1\0" + _validate_hm1_ast(tree)
            ).hexdigest()
        except (RecursionError, ValueError):
            status = "invalid_candidate"
            if kind_valid:
                _mark_check_failed(
                    checks,
                    name="hm1.ast",
                    evidence="hm1.ast.invalid",
                )
        mapping = _validation_mapping(
            candidate=candidate,
            contract=contract,
            identity=self.identity,
            status=status,
            canonical_sha256=canonical_sha256,
            checks=sorted(checks, key=lambda item: item["name"]),
            failure_summary=failure_summary,
        )
        return freeze_candidate_validation(
            mapping,
            candidate=candidate,
            contract=contract,
            plugin_identity=self.identity,
        )

    def evaluate(
        self, candidate: ValidatedCandidate, split: AuthorizedSplit
    ) -> EvaluationResult:
        contract = split.contract.to_dict()
        _require_hm1_mock_contract(contract)
        if not isinstance(split.data, HM1SplitData):
            raise EvaluationIntegrityError("HM1 split data type mismatch")
        binding = split.binding
        if candidate != binding.candidate_receipt:
            raise EvaluationIntegrityError("HM1 candidate binding mismatch")
        if (
            split.request != binding.request
            or split.contract.sha256 != binding.contract.sha256
            or binding.plugin_identity != self.identity
        ):
            raise EvaluationIntegrityError("HM1 split binding mismatch")
        development = contract["data"]["splits"]["development"]
        if (
            split.data.role != "development"
            or split.request.split_role != "development"
            or split.data.data_snapshot_sha256 != contract["data"]["snapshot_sha256"]
            or split.data.split_manifest_sha256 != development["manifest_sha256"]
            or split.request.split_manifest_hash != split.data.split_manifest_sha256
        ):
            raise EvaluationIntegrityError("HM1 development identity mismatch")
        binding.runtime_lock.verify()
        try:
            output = split.data.read_engine_output()
        # C5 G05 / C6 J04: never serialize an untrusted adapter exception.
        except Exception:  # noqa: BLE001
            return self._failure_result(
                split,
                status="implementation_failure",
                failure_type="implementation_failure",
                code="hm1.implementation_failure",
            )

        status = output.status
        if status == "implementation_failure":
            result = self._failure_result(
                split,
                status="implementation_failure",
                failure_type="implementation_failure",
                code="hm1.implementation_failure",
            )
        elif status == "evaluation_failure":
            result = self._failure_result(
                split,
                status="evaluation_failure",
                failure_type="evaluation_failure",
                code="hm1.evaluation_failure",
            )
        elif status == "timeout":
            result = self._failure_result(
                split,
                status="evaluation_failure",
                failure_type="timeout",
                code="hm1.timeout",
            )
        elif status == "incomparable":
            result = self._failure_result(
                split,
                status="incomparable",
                failure_type="incomparable",
                code="hm1.incomparable",
                warnings=output.warning_codes,
            )
        else:
            coverage = output.value("coverage_count")
            expected = output.value("expected_coverage_count")
            code = (
                "hm1.coverage_mismatch"
                if coverage != expected
                else "hm1.cost_semantics_unavailable"
            )
            result = self._failure_result(
                split,
                status="incomparable",
                failure_type="incomparable",
                code=code,
                output=output,
                warnings=output.warning_codes,
            )
        return result

    def _failure_result(
        self,
        split: Any,
        *,
        status: str,
        failure_type: str,
        code: str,
        output: HM1EngineOutput | None = None,
        warnings: tuple[ReasonCode, ...] = (),
    ) -> EvaluationResult:
        contract = split.contract.to_dict()
        metrics = contract["metrics"]
        primary_spec = metrics["primary"]
        primary = MetricValue.from_mapping(
            {
                "name": primary_spec["name"],
                "value": None,
                "direction": primary_spec["direction"],
                "unit": primary_spec["unit"],
            }
        )
        constraints = tuple(
            CheckResult.from_mapping(
                {
                    "name": item["name"],
                    "status": "not_observed",
                    "evidence": "evaluation.not_observed",
                }
            )
            for item in metrics["hard_constraints"]
        )
        diagnostics = tuple(
            MetricValue.from_mapping(
                {
                    "name": item["name"],
                    "value": None if output is None else output.value(item["name"]),
                    "direction": item["direction"],
                    "unit": item["unit"],
                }
            )
            for item in metrics["diagnostics"]
        )
        observed_check_names = (
            set()
            if output is None
            else {
                _diagnostic_check_name(item["name"]) for item in metrics["diagnostics"]
            }
        )
        checks = []
        for name in split.binding.runtime_lock.required_check_names:
            observed = name in observed_check_names
            checks.append(
                CheckResult.from_mapping(
                    {
                        "name": name,
                        "status": "pass" if observed else "not_observed",
                        "evidence": (
                            "diagnostic.observed"
                            if observed
                            else "evaluation.not_observed"
                        ),
                    }
                )
            )
        if output is not None:
            coverage_status = (
                "pass"
                if output.value("coverage_count")
                == output.value("expected_coverage_count")
                else "fail"
            )
            checks.append(
                CheckResult.from_mapping(
                    {
                        "name": "hm1.coverage",
                        "status": coverage_status,
                        "evidence": f"hm1.coverage.{coverage_status}",
                    }
                )
            )
        failure = EvaluationFailure.from_mapping(
            {"failure_type": failure_type, "summary": code, "evidence_ids": []}
        )
        costs = {
            "gross": None,
            "transaction_cost": None,
            "net": None,
            "turnover": None,
            "cost_model_sha256": contract["cost_model"]["sha256"],
        }
        return split.make_result(
            status=status,
            primary_metric=primary,
            constraints=constraints,
            diagnostics=diagnostics,
            fold_metrics=(),
            costs=costs,
            checks=tuple(checks),
            artifacts=(),
            failure=failure,
            warnings=warnings,
        )

    def summarize(self, result: EvaluationResult) -> EvaluationSummary:
        return EvaluationSummary.from_result(result)


__all__ = ["HM1EngineOutput", "HM1FuturesPlugin", "HM1SplitData"]
