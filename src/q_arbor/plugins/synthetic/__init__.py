"""Development-only known-truth synthetic evaluation plugin."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Mapping, Sequence
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Final

from q_arbor.contracts import QuantResearchContract
from q_arbor.evaluation import (
    ArtifactRef,
    ArtifactSink,
    AuthorizedSplit,
    CandidateArtifact,
    CandidateValidation,
    CheckResult,
    ContentAddressedArtifactStore,
    EvaluationBinding,
    EvaluationBoundaryError,
    EvaluationFailure,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationPluginError,
    EvaluationRequest,
    EvaluationResult,
    EvaluationSchemaError,
    EvaluationSummary,
    MetricValue,
    PluginIdentity,
    ReasonCode,
    ValidatedCandidate,
    VerifiedRuntimeLock,
    freeze_candidate_validation,
    freeze_evaluation_result,
)
from q_arbor.evaluation.candidate import _classify_candidate_surface
from q_arbor.evaluation.results import _freeze_controlled_evaluation_result

_ARTIFACT_TYPE: Final = "q-arbor.synthetic-signal.v1"
_SIGNALS: Final = ("null_signal", "planted_signal")
_ROWS: Final = (
    ("fold.a", "a.1", 0.0, 1.0, 0.04),
    ("fold.a", "a.2", 1.0, -1.0, 0.01),
    ("fold.a", "a.3", 0.0, 1.0, 0.04),
    ("fold.a", "a.4", 1.0, -1.0, -0.01),
    ("fold.b", "b.1", 0.0, 1.0, 0.05),
    ("fold.b", "b.2", 1.0, -1.0, 0.012),
    ("fold.b", "b.3", 0.0, 1.0, 0.05),
    ("fold.b", "b.4", 1.0, -1.0, -0.012),
)
_FOLD_RANGES: Final = {
    "fold.a": "fixture-window-a",
    "fold.b": "fixture-window-b",
}


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _hash_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


_SCHEMA_DOCUMENT: Final = {
    "schema_version": "1.0",
    "fields": [
        {"name": "fold_id", "dtype": "identifier"},
        {"name": "row_id", "dtype": "identifier"},
        {"name": "null_signal", "dtype": "float64"},
        {"name": "planted_signal", "dtype": "float64"},
        {"name": "forward_return", "dtype": "float64"},
    ],
}
_SNAPSHOT_DOCUMENT: Final = {
    "schema_version": "1.0",
    "kind": "q-arbor.synthetic-known-truth.v1",
    "rows": [list(row) for row in _ROWS],
}
_DEVELOPMENT_MANIFEST: Final = {
    "schema_version": "1.0",
    "role": "development",
    "snapshot_sha256": _hash_json(_SNAPSHOT_DOCUMENT),
    "fold_ids": ["fold.a", "fold.b"],
}
_GATE_MANIFEST: Final = {
    "schema_version": "1.0",
    "role": "gate",
    "opaque_placeholder": "sealed",
}
_FINAL_MANIFEST: Final = {
    "schema_version": "1.0",
    "role": "final",
    "opaque_placeholder": "sealed",
}
_COST_DOCUMENT: Final = {
    "schema_version": "1.0",
    "transaction_cost_per_turnover": 0.001,
}
_FIXTURE_IDENTITIES: Final = MappingProxyType(
    {
        "data_snapshot_sha256": _hash_json(_SNAPSHOT_DOCUMENT),
        "data_schema_sha256": _hash_json(_SCHEMA_DOCUMENT),
        "development_manifest_sha256": _hash_json(_DEVELOPMENT_MANIFEST),
        "gate_manifest_sha256": _hash_json(_GATE_MANIFEST),
        "final_manifest_sha256": _hash_json(_FINAL_MANIFEST),
        "cost_model_sha256": _hash_json(_COST_DOCUMENT),
    }
)


def synthetic_fixture_identities() -> Mapping[str, str]:
    """Return detached public identities without exposing fixture rows."""

    return MappingProxyType(dict(_FIXTURE_IDENTITIES))


def canonical_synthetic_candidate(*, signal_column: str) -> bytes:
    if signal_column not in _SIGNALS:
        raise EvaluationInvariantError("unsupported synthetic signal column")
    return _canonical_json(
        {"schema_version": "1.0", "kind": "signal", "signal_column": signal_column}
    )


def synthetic_contract_draft(
    *, plugin_identity: PluginIdentity, baseline_ref: str
) -> dict[str, object]:
    """Build the complete public fixture contract draft; final stays sealed."""

    if plugin_identity.to_dict()["artifact_type"] != _ARTIFACT_TYPE:
        raise EvaluationPluginError("synthetic plugin artifact type mismatch")
    if not isinstance(baseline_ref, str) or not baseline_ref:
        raise EvaluationInvariantError("baseline_ref must be non-empty")
    identity = synthetic_fixture_identities()
    return {
        "schema_version": "1.0",
        "contract_id": "synthetic.contract.v1",
        "task_id": "synthetic.signal.v1",
        "task_kind": "synthetic_factor",
        "objective": {
            "research_question": "Can the known signal survive fixed costs?",
            "baseline_ref": baseline_ref,
            "candidate_artifact_type": _ARTIFACT_TYPE,
        },
        "plugin": plugin_identity.to_dict(),
        "editable_surface": ["candidates/**"],
        "protected_paths": ["contracts/**", "data/**", "evaluator/**"],
        "required_outputs": ["candidates/candidate.json"],
        "data": {
            "snapshot_id": "synthetic.snapshot.v1",
            "snapshot_sha256": identity["data_snapshot_sha256"],
            "schema_sha256": identity["data_schema_sha256"],
            "source_version": "synthetic-v1",
            "point_in_time": {
                "enabled": True,
                "asof_rule": "signals precede fixed forward returns",
                "availability_lag": "P1D",
                "universe_rule": "fixture membership is frozen",
                "adjustment_rule": "not applicable to synthetic rows",
                "label_horizon": "P1D",
                "known_limitations": ["mechanism smoke only"],
            },
            "splits": {
                "development": {
                    "dataset_id": "synthetic.development.v1",
                    "manifest_sha256": identity["development_manifest_sha256"],
                    "role": "development",
                    "query_budget": 20,
                    "sealed": False,
                    "time_range": {
                        "start": "2020-01-01T00:00:00Z",
                        "end": "2020-12-31T23:59:59Z",
                    },
                },
                "gate": {
                    "dataset_id": "synthetic.gate.v1",
                    "manifest_sha256": identity["gate_manifest_sha256"],
                    "role": "gate",
                    "query_budget": 2,
                    "sealed": True,
                    "time_range": {
                        "start": "2021-01-01T00:00:00Z",
                        "end": "2021-12-31T23:59:59Z",
                    },
                },
                "final": {
                    "dataset_id": "synthetic.final.v1",
                    "manifest_sha256": identity["final_manifest_sha256"],
                    "role": "final",
                    "query_budget": 1,
                    "sealed": True,
                    "time_range": {
                        "start": "2022-01-01T00:00:00Z",
                        "end": "2022-12-31T23:59:59Z",
                    },
                },
            },
        },
        "metrics": {
            "primary": {
                "name": "mean_net_return",
                "direction": "maximize",
                "unit": "fraction",
                "aggregation": "median_across_folds",
            },
            "hard_constraints": [
                {
                    "name": "max_drawdown",
                    "operator": "le",
                    "threshold": 0.2,
                    "unit": "fraction",
                }
            ],
            "diagnostics": [
                {
                    "name": "turnover",
                    "direction": "minimize",
                    "unit": "fraction_per_fold",
                    "aggregation": "mean_across_folds",
                }
            ],
            "admission_rule": "primary improves and every hard constraint passes",
        },
        "cost_model": {
            "model_id": "synthetic.cost.v1",
            "sha256": identity["cost_model_sha256"],
            "components": [
                {
                    "name": "transaction_cost",
                    "rule": "0.001 per unit turnover",
                }
            ],
            "currency": "unitless",
            "execution_delay": "P1D",
        },
        "budgets": {
            "max_nodes": 8,
            "max_executor_runs": 6,
            "max_dev_queries": 20,
            "max_gate_queries": 2,
            "max_final_queries": 1,
            "max_tokens": None,
            "max_wall_seconds": 3600,
        },
        "capabilities": {
            "executor_roles": ["development"],
            "coordinator_roles": ["development", "gate"],
            "finalizer_roles": ["final"],
            "network_policy": "deny",
        },
        "model_provenance": {
            "provider": "fixture",
            "model": "deterministic",
            "version": "1.0",
            "knowledge_cutoff_status": "not_applicable",
            "knowledge_cutoff": None,
            "contamination_risk": "not_applicable",
        },
        "statistical_plan": [],
        "seeds": [7, 19],
    }


def _strict_candidate(payload: bytes) -> tuple[str, bytes]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("synthetic candidate is not UTF-8") from exc
    if text.startswith("\ufeff"):
        raise ValueError("synthetic candidate may not contain a BOM")

    def reject_constant(value: str) -> None:
        raise ValueError(f"unsupported JSON constant {value!r}")

    def object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        normalized: set[str] = set()
        for key, value in pairs:
            normalized_key = unicodedata.normalize("NFC", key)
            if key in result or normalized_key in normalized:
                raise ValueError("ambiguous synthetic candidate key")
            normalized.add(normalized_key)
            result[normalized_key] = value
        return result

    try:
        value = json.loads(
            text,
            object_pairs_hook=object_hook,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError("synthetic candidate is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "kind",
        "signal_column",
    }:
        raise ValueError("synthetic candidate has an invalid shape")
    if value["schema_version"] != "1.0" or value["kind"] != "signal":
        raise ValueError("synthetic candidate has an invalid discriminator")
    signal = value["signal_column"]
    if not isinstance(signal, str) or signal not in _SIGNALS:
        raise ValueError("synthetic candidate selects an unsupported signal")
    return signal, _canonical_json(value)


class SyntheticSplitData:
    """Fixed internal data view; rows are intentionally not serializable."""

    __slots__ = ("_data_snapshot_sha256", "_initialized", "_split_manifest_sha256")

    def __init__(self) -> None:
        object.__setattr__(
            self, "_data_snapshot_sha256", _FIXTURE_IDENTITIES["data_snapshot_sha256"]
        )
        object.__setattr__(
            self,
            "_split_manifest_sha256",
            _FIXTURE_IDENTITIES["development_manifest_sha256"],
        )
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("SyntheticSplitData is immutable")
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
    method = "exact-json-v1" if canonical_sha256 is not None else "exact-bytes-v1"
    evidence_basis = canonical_sha256 or candidate.artifact.sha256
    family = {
        "family_hint": None,
        "method": method,
        "evidence_sha256": hashlib.sha256(
            f"synthetic:{method}:{evidence_basis}".encode()
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


def _fold_observations(signal: str) -> list[dict[str, float | str]]:
    observations: list[dict[str, float | str]] = []
    for fold_id in ("fold.a", "fold.b"):
        rows = [row for row in _ROWS if row[0] == fold_id]
        positions = [
            float(row[2] if signal == "null_signal" else row[3]) for row in rows
        ]
        returns = [float(row[4]) for row in rows]
        gross = sum(
            position * value for position, value in zip(positions, returns)
        ) / len(rows)
        previous = 0.0
        changes: list[float] = []
        for position in positions:
            changes.append(abs(position - previous))
            previous = position
        turnover = sum(changes) / len(changes)
        cost = float(Decimal("0.001") * Decimal(str(turnover)))
        net = float(Decimal(str(gross)) - Decimal(str(cost)))
        observations.append(
            {
                "fold_id": fold_id,
                "gross": gross,
                "turnover": turnover,
                "cost": cost,
                "net": net,
            }
        )
    return observations


def _max_drawdown(signal: str) -> float:
    wealth = Decimal(1)
    peak = wealth
    drawdown = Decimal(0)
    previous_by_fold: dict[str, float] = {}
    for fold_id, _row_id, null_signal, planted_signal, forward_return in _ROWS:
        previous = previous_by_fold.get(fold_id, 0.0)
        position = null_signal if signal == "null_signal" else planted_signal
        cost = Decimal("0.001") * Decimal(str(abs(position - previous)))
        row_return = Decimal(str(position * forward_return)) - cost
        wealth += row_return
        peak = max(peak, wealth)
        if peak > 0:
            drawdown = max(drawdown, (peak - wealth) / peak)
        previous_by_fold[fold_id] = position
    return float(drawdown)


class SyntheticSignalPlugin:
    """Known-truth plugin whose only executable inputs are closed JSON signals."""

    __slots__ = ("_identity", "_initialized")

    def __init__(self) -> None:  # pragma: no cover - construction is closed
        raise TypeError("use SyntheticSignalPlugin.create")

    @classmethod
    def create(cls, identity: PluginIdentity) -> SyntheticSignalPlugin:
        if identity.to_dict()["artifact_type"] != _ARTIFACT_TYPE:
            raise EvaluationPluginError("synthetic plugin artifact type mismatch")
        instance = cls.__new__(cls)
        object.__setattr__(instance, "_identity", identity)
        object.__setattr__(instance, "_initialized", True)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("SyntheticSignalPlugin is immutable")
        object.__setattr__(self, name, value)

    @property
    def identity(self) -> PluginIdentity:
        return self._identity

    def validate(
        self, candidate: CandidateArtifact, contract: QuantResearchContract
    ) -> CandidateValidation:
        if (
            not isinstance(contract, QuantResearchContract)
            or contract.to_dict()["task_kind"] != "synthetic_factor"
        ):
            raise EvaluationIntegrityError("synthetic contract task kind mismatch")
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
            {
                "name": "synthetic.payload",
                "status": "pass",
                "evidence": "synthetic.payload.ok",
            },
        ]
        status = "valid" if surface_failure is None else "invalid_candidate"
        failure_summary = (
            "synthetic.invalid_candidate"
            if surface_failure is None
            else str(surface_failure)
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
            _signal, canonical = _strict_candidate(candidate.payload)
            canonical_sha256 = hashlib.sha256(
                b"q-arbor.synthetic.canonical-form.v1\0" + canonical
            ).hexdigest()
        except ValueError:
            status = "invalid_candidate"
            if kind_valid:
                _mark_check_failed(
                    checks,
                    name="synthetic.payload",
                    evidence="synthetic.payload.invalid",
                )
        return freeze_candidate_validation(
            _validation_mapping(
                candidate=candidate,
                contract=contract,
                identity=self.identity,
                status=status,
                canonical_sha256=canonical_sha256,
                checks=sorted(checks, key=lambda item: item["name"]),
                failure_summary=failure_summary,
            ),
            candidate=candidate,
            contract=contract,
            plugin_identity=self.identity,
        )

    def evaluate(
        self, candidate: ValidatedCandidate, split: AuthorizedSplit
    ) -> EvaluationResult:
        if not isinstance(split.data, SyntheticSplitData):
            raise EvaluationIntegrityError("synthetic split data type mismatch")
        binding = split.binding
        if candidate != binding.candidate_receipt:
            raise EvaluationIntegrityError("synthetic candidate binding mismatch")
        if (
            split.request != binding.request
            or split.contract.sha256 != binding.contract.sha256
            or binding.plugin_identity != self.identity
        ):
            raise EvaluationIntegrityError("synthetic split binding mismatch")
        contract = split.contract.to_dict()
        development = contract["data"]["splits"]["development"]
        if (
            split.data.role != "development"
            or split.request.split_role != "development"
            or split.data.data_snapshot_sha256 != contract["data"]["snapshot_sha256"]
            or split.data.split_manifest_sha256 != development["manifest_sha256"]
            or split.request.split_manifest_hash != split.data.split_manifest_sha256
        ):
            raise EvaluationIntegrityError("synthetic development identity mismatch")
        binding.runtime_lock.verify()
        signal, _canonical = _strict_candidate(candidate.candidate.payload)
        observations = _fold_observations(signal)
        metrics = contract["metrics"]
        primary_spec = metrics["primary"]
        diagnostics_spec = metrics["diagnostics"]
        if primary_spec["name"] != "mean_net_return" or [
            item["name"] for item in diagnostics_spec
        ] != ["turnover"]:
            raise EvaluationIntegrityError("synthetic metric contract mismatch")
        fold_nets = [Decimal(str(item["net"])) for item in observations]
        primary_value = float(sum(fold_nets) / Decimal(len(fold_nets)))
        turnover_value = sum(float(item["turnover"]) for item in observations) / len(
            observations
        )
        gross = sum(Decimal(str(item["gross"])) for item in observations) / Decimal(
            len(observations)
        )
        transaction_cost = sum(
            Decimal(str(item["cost"])) for item in observations
        ) / Decimal(len(observations))
        net = gross - transaction_cost
        drawdown = _max_drawdown(signal)
        threshold = float(metrics["hard_constraints"][0]["threshold"])
        constraint_status = "pass" if drawdown <= threshold else "fail"
        primary = MetricValue.from_mapping(
            {
                "name": primary_spec["name"],
                "value": primary_value,
                "direction": primary_spec["direction"],
                "unit": primary_spec["unit"],
            }
        )
        constraints = (
            CheckResult.from_mapping(
                {
                    "name": "max_drawdown",
                    "status": constraint_status,
                    "evidence": f"constraint.max_drawdown.{constraint_status}",
                }
            ),
        )
        diagnostics = (
            MetricValue.from_mapping(
                {
                    "name": "turnover",
                    "value": turnover_value,
                    "direction": diagnostics_spec[0]["direction"],
                    "unit": diagnostics_spec[0]["unit"],
                }
            ),
        )
        fold_metrics = tuple(
            {
                "fold_id": item["fold_id"],
                "time_range": _FOLD_RANGES[str(item["fold_id"])],
                "metrics": (
                    MetricValue.from_mapping(
                        {
                            "name": primary_spec["name"],
                            "value": item["net"],
                            "direction": primary_spec["direction"],
                            "unit": primary_spec["unit"],
                        }
                    ),
                ),
            }
            for item in observations
        )
        checks = tuple(
            CheckResult.from_mapping(
                {"name": name, "status": "pass", "evidence": f"{name}.pass"}
            )
            for name in split.binding.runtime_lock.required_check_names
        )
        costs = {
            "gross": float(gross),
            "transaction_cost": float(transaction_cost),
            "net": float(net),
            "turnover": turnover_value,
            "cost_model_sha256": contract["cost_model"]["sha256"],
        }
        if constraint_status != "pass":
            failure = EvaluationFailure.from_mapping(
                {
                    "failure_type": "constraint_violation",
                    "summary": "synthetic.constraint_violation",
                    "evidence_ids": [],
                }
            )
            status = "invalid_candidate"
            primary = MetricValue.from_mapping(
                {
                    "name": primary_spec["name"],
                    "value": None,
                    "direction": primary_spec["direction"],
                    "unit": primary_spec["unit"],
                }
            )
            fold_metrics = ()
        else:
            failure = None
            status = "success"
        return split.make_result(
            status=status,
            primary_metric=primary,
            constraints=constraints,
            diagnostics=diagnostics,
            fold_metrics=fold_metrics,
            costs=costs,
            checks=checks,
            artifacts=(),
            failure=failure,
            warnings=(),
        )

    def summarize(self, result: EvaluationResult) -> EvaluationSummary:
        return EvaluationSummary.from_result(result)


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
    result: list[dict[str, object]] = []
    for fold in fold_metrics:
        if not isinstance(fold, Mapping) or set(fold) != {
            "fold_id",
            "time_range",
            "metrics",
        }:
            raise EvaluationSchemaError("fold metric fields do not match C6")
        metrics = _typed_values(fold["metrics"], MetricValue, "fold metrics")  # type: ignore[arg-type]
        result.append(
            {
                "fold_id": fold["fold_id"],
                "time_range": fold["time_range"],
                "metrics": [item.to_dict() for item in metrics],
            }
        )
    return result


class _SyntheticDevelopmentSplit:
    """Concrete C9 capability carrier; C10 owns every production constructor."""

    __slots__ = (
        "_artifacts",
        "_binding",
        "_contract",
        "_data",
        "_initialized",
        "_request",
    )

    def __init__(self) -> None:  # pragma: no cover - construction is closed
        raise TypeError("use make_synthetic_development_split")

    @classmethod
    def _create(
        cls,
        *,
        request: EvaluationRequest,
        contract: QuantResearchContract,
        binding: EvaluationBinding,
        data: SyntheticSplitData,
        artifacts: ArtifactSink,
    ) -> _SyntheticDevelopmentSplit:
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
            raise AttributeError("authorized synthetic split is immutable")
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
    def data(self) -> SyntheticSplitData:
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
        # C5 G01/G02/G05 and C6 J01/J04: suspect values/artifacts cannot cross.
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
        if status not in {"success", "invalid_candidate"}:
            raise EvaluationInvariantError("synthetic result status is unsupported")
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


def make_synthetic_development_split(
    request: EvaluationRequest,
    contract: QuantResearchContract,
    candidate: ValidatedCandidate,
    plugin: SyntheticSignalPlugin,
    runtime_lock: VerifiedRuntimeLock,
    *,
    result_id: str,
    evaluation_seed: int,
    artifact_store: ContentAddressedArtifactStore,
    produced_by_event_id: str,
) -> AuthorizedSplit:
    """Mint the fixed in-memory development fixture; gate/final stay closed."""

    if not isinstance(request, EvaluationRequest):
        raise EvaluationSchemaError("synthetic request type mismatch")
    if request.split_role != "development":
        raise EvaluationBoundaryError("synthetic factory is development-only")
    if (
        not isinstance(contract, QuantResearchContract)
        or not isinstance(candidate, ValidatedCandidate)
        or not isinstance(plugin, SyntheticSignalPlugin)
        or not isinstance(runtime_lock, VerifiedRuntimeLock)
        or not isinstance(artifact_store, ContentAddressedArtifactStore)
    ):
        raise EvaluationSchemaError("synthetic factory input type mismatch")
    mapping = contract.to_dict()
    identities = synthetic_fixture_identities()
    splits = mapping["data"]["splits"]
    expected = {
        "data_snapshot_sha256": mapping["data"]["snapshot_sha256"],
        "data_schema_sha256": mapping["data"]["schema_sha256"],
        "development_manifest_sha256": splits["development"]["manifest_sha256"],
        "gate_manifest_sha256": splits["gate"]["manifest_sha256"],
        "final_manifest_sha256": splits["final"]["manifest_sha256"],
        "cost_model_sha256": mapping["cost_model"]["sha256"],
    }
    if mapping["task_kind"] != "synthetic_factor" or expected != dict(identities):
        raise EvaluationIntegrityError("synthetic fixture identity mismatch")
    fold_policy = runtime_lock.fold_policy
    if (
        fold_policy.mode != "required"
        or fold_policy.expected_fold_ids != ("fold.a", "fold.b")
        or fold_policy.required_metric_names != ("mean_net_return",)
    ):
        raise EvaluationIntegrityError("synthetic fold policy mismatch")
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
    data = SyntheticSplitData()
    artifacts = artifact_store.scope(
        request_id=request.request_id,
        produced_by_event_id=produced_by_event_id,
        runtime_lock=runtime_lock,
    )
    return _SyntheticDevelopmentSplit._create(
        request=request,
        contract=contract,
        binding=binding,
        data=data,
        artifacts=artifacts,
    )


__all__ = [
    "SyntheticSignalPlugin",
    "SyntheticSplitData",
    "canonical_synthetic_candidate",
    "make_synthetic_development_split",
    "synthetic_contract_draft",
    "synthetic_fixture_identities",
]
