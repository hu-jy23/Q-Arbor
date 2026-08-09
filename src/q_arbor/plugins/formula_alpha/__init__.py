"""Validation-only formula-alpha adapter for the C9 control seam."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from enum import Enum
from types import MappingProxyType
from typing import Any, Final

from q_arbor.contracts import QuantResearchContract
from q_arbor.evaluation import (
    CandidateArtifact,
    CandidateValidation,
    CheckResult,
    EvaluationFailure,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationPluginError,
    EvaluationResult,
    EvaluationSchemaError,
    EvaluationSummary,
    MetricValue,
    PluginIdentity,
    ValidatedCandidate,
    freeze_candidate_validation,
)

_ARTIFACT_TYPE: Final = "q-arbor.formula-alpha.v1"
_IDENTIFIER_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_MAX_DEPTH: Final = 16
_MAX_NODES: Final = 256


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _strict_json_object(payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("candidate is not UTF-8 JSON") from exc
    if text.startswith("\ufeff"):
        raise ValueError("candidate JSON may not contain a BOM")

    def reject_constant(value: str) -> None:
        raise ValueError(f"unsupported JSON constant {value!r}")

    def object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        normalized: set[str] = set()
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("normalized JSON key collision")
            normalized.add(normalized_key)
            result[normalized_key] = value
        return result

    try:
        value = json.loads(
            text,
            parse_constant=reject_constant,
            object_pairs_hook=object_hook,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError("candidate is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("candidate root must be an object")  # noqa: TRY004
    return value


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be an Identifier")
    return unicodedata.normalize("NFC", value)


class PublicFormulaSchema:
    """Immutable, public field allowlist bound to ``contract.data.schema_sha256``."""

    __slots__ = ("_canonical", "_fields", "_initialized", "_mapping", "_sha256")

    def __init__(self) -> None:  # pragma: no cover - construction is closed
        raise TypeError("use PublicFormulaSchema.from_mapping")

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, object]) -> PublicFormulaSchema:
        if set(mapping) != {"schema_version", "fields"}:
            raise EvaluationSchemaError("public formula schema has unexpected keys")
        if mapping["schema_version"] != "1.0":
            raise EvaluationSchemaError("unsupported public formula schema version")
        raw_fields = mapping["fields"]
        if not isinstance(raw_fields, Sequence) or isinstance(
            raw_fields, (str, bytes, bytearray)
        ):
            raise EvaluationSchemaError("public formula fields must be an array")
        fields: list[dict[str, str]] = []
        names: set[str] = set()
        for item in raw_fields:
            if not isinstance(item, Mapping) or set(item) != {"name", "dtype"}:
                raise EvaluationSchemaError("public formula field has an invalid shape")
            try:
                name = _identifier(item["name"], "field.name")
                dtype = _identifier(item["dtype"], "field.dtype")
            except ValueError as exc:
                raise EvaluationInvariantError(str(exc)) from exc
            if name in names:
                raise EvaluationInvariantError(
                    "public formula field names must be unique"
                )
            names.add(name)
            fields.append({"name": name, "dtype": dtype})
        if fields != sorted(fields, key=lambda item: item["name"]):
            raise EvaluationInvariantError(
                "public formula fields must be sorted by name"
            )
        payload = {"schema_version": "1.0", "fields": fields}
        canonical = _canonical_json(payload)
        instance = cls.__new__(cls)
        object.__setattr__(instance, "_canonical", canonical)
        object.__setattr__(instance, "_fields", frozenset(names))
        object.__setattr__(instance, "_mapping", MappingProxyType(payload))
        object.__setattr__(instance, "_sha256", hashlib.sha256(canonical).hexdigest())
        object.__setattr__(instance, "_initialized", True)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("PublicFormulaSchema is immutable")
        object.__setattr__(self, name, value)

    @property
    def fields(self) -> tuple[str, ...]:
        return tuple(sorted(self._fields))

    @property
    def sha256(self) -> str:
        return self._sha256

    def to_dict(self) -> dict[str, object]:
        return json.loads(self._canonical)

    def to_json(self) -> str:
        return self._canonical.decode("utf-8")

    def __hash__(self) -> int:
        return hash(self._canonical)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, PublicFormulaSchema)
            and self._canonical == other._canonical
        )


class FormulaMockOutcome(str, Enum):
    BACKEND_UNAVAILABLE = "backend_unavailable"
    SCHEMA_INCOMPATIBLE = "schema_incompatible"


class FormulaAlphaSplitData:
    """Closed formula mock view; it never exposes a backend or locator."""

    __slots__ = (
        "_data_snapshot_sha256",
        "_initialized",
        "_outcome",
        "_split_manifest_sha256",
    )

    def __init__(
        self,
        *,
        data_snapshot_sha256: str,
        split_manifest_sha256: str,
        outcome: FormulaMockOutcome,
    ) -> None:
        object.__setattr__(self, "_data_snapshot_sha256", data_snapshot_sha256)
        object.__setattr__(self, "_split_manifest_sha256", split_manifest_sha256)
        object.__setattr__(self, "_outcome", FormulaMockOutcome(outcome))
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("FormulaAlphaSplitData is immutable")
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

    @property
    def outcome(self) -> FormulaMockOutcome:
        return self._outcome


def _validate_expression(document: dict[str, Any], fields: frozenset[str]) -> bytes:
    if set(document) != {"schema_version", "expression"}:
        raise ValueError("formula document has unexpected keys")
    if document["schema_version"] != "1.0":
        raise ValueError("unsupported formula document version")
    expression = document["expression"]
    stack: list[tuple[object, int]] = [(expression, 1)]
    node_count = 0
    while stack:
        node, depth = stack.pop()
        node_count += 1
        if depth > _MAX_DEPTH or node_count > _MAX_NODES:
            raise ValueError("formula expression exceeds structural limits")
        if not isinstance(node, dict):
            raise ValueError(  # noqa: TRY004
                "formula expression nodes must be objects"
            )
        operator = node.get("op")
        if operator == "field":
            if set(node) != {"op", "name"}:
                raise ValueError("field expression has unexpected keys")
            name = _identifier(node["name"], "expression.name")
            if name not in fields:
                raise ValueError("formula references a field outside the public schema")
        elif operator == "constant":
            if set(node) != {"op", "value"}:
                raise ValueError("constant expression has unexpected keys")
            value = node["value"]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("formula constant must be numeric")
            if not math.isfinite(float(value)):
                raise ValueError("formula constant must be finite")
        elif operator == "lag":
            if set(node) != {"op", "periods", "arg"}:
                raise ValueError("lag expression has unexpected keys")
            periods = node["periods"]
            if isinstance(periods, bool) or not isinstance(periods, int):
                raise ValueError("lag periods must be an integer")
            if not 1 <= periods <= 252:
                raise ValueError("lag periods are out of range")
            stack.append((node["arg"], depth + 1))
        elif operator == "neg":
            if set(node) != {"op", "arg"}:
                raise ValueError("neg expression has unexpected keys")
            stack.append((node["arg"], depth + 1))
        elif operator in {"add", "sub", "mul", "div"}:
            if set(node) != {"op", "left", "right"}:
                raise ValueError("binary expression has unexpected keys")
            stack.append((node["right"], depth + 1))
            stack.append((node["left"], depth + 1))
        else:
            raise ValueError("unsupported formula operator")
    return _canonical_json(document)


def _candidate_validation_mapping(
    *,
    candidate: CandidateArtifact,
    contract: QuantResearchContract,
    identity: PluginIdentity,
    status: str,
    canonical_sha256: str | None,
    checks: list[dict[str, str]],
) -> dict[str, object]:
    failure = None
    method = "exact-json-ast-v1" if canonical_sha256 is not None else "exact-bytes-v1"
    evidence_basis = canonical_sha256 or candidate.artifact.sha256
    family = {
        "family_hint": None,
        "method": method,
        "evidence_sha256": hashlib.sha256(
            f"formula:{method}:{evidence_basis}".encode()
        ).hexdigest(),
    }
    if status != "valid":
        failure = {
            "failure_type": "invalid_candidate",
            "summary": "formula.invalid_candidate",
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


class FormulaAlphaPlugin:
    """Formula candidate validator with no real backend or data access."""

    __slots__ = ("_identity", "_initialized", "_public_schema")

    def __init__(self) -> None:  # pragma: no cover - construction is closed
        raise TypeError("use FormulaAlphaPlugin.create")

    @classmethod
    def create(
        cls, identity: PluginIdentity, public_schema: PublicFormulaSchema
    ) -> FormulaAlphaPlugin:
        if identity.to_dict()["artifact_type"] != _ARTIFACT_TYPE:
            raise EvaluationPluginError("formula plugin artifact type mismatch")
        if not isinstance(public_schema, PublicFormulaSchema):
            raise EvaluationPluginError("formula public schema is invalid")
        instance = cls.__new__(cls)
        object.__setattr__(instance, "_identity", identity)
        object.__setattr__(instance, "_public_schema", public_schema)
        object.__setattr__(instance, "_initialized", True)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("FormulaAlphaPlugin is immutable")
        object.__setattr__(self, name, value)

    @property
    def identity(self) -> PluginIdentity:
        return self._identity

    @property
    def public_schema(self) -> PublicFormulaSchema:
        return self._public_schema

    def validate(
        self, candidate: CandidateArtifact, contract: QuantResearchContract
    ) -> CandidateValidation:
        if (
            not isinstance(contract, QuantResearchContract)
            or contract.to_dict()["task_kind"] != "formula_alpha"
        ):
            raise EvaluationIntegrityError("formula contract task kind mismatch")
        contract_data = contract.to_dict()["data"]
        if not isinstance(contract_data, dict):  # frozen contract invariant
            raise EvaluationIntegrityError("contract data is unavailable")
        if contract_data["schema_sha256"] != self._public_schema.sha256:
            raise EvaluationIntegrityError("formula public schema hash mismatch")
        checks = [
            {
                "name": "candidate.kind",
                "status": "pass",
                "evidence": "candidate.kind.ok",
            },
            {
                "name": "formula.expression",
                "status": "pass",
                "evidence": "formula.expression.ok",
            },
            {
                "name": "formula.public_schema",
                "status": "pass",
                "evidence": "formula.public_schema.ok",
            },
        ]
        canonical_sha256: str | None = None
        status = "valid"
        try:
            if candidate.artifact.to_dict()["kind"] != _ARTIFACT_TYPE:
                checks[0] = {
                    "name": "candidate.kind",
                    "status": "fail",
                    "evidence": "candidate.kind.invalid",
                }
                raise ValueError("candidate kind mismatch")
            document = _strict_json_object(candidate.payload)
            canonical = _validate_expression(document, self._public_schema._fields)
            canonical_sha256 = hashlib.sha256(canonical).hexdigest()
        except (OverflowError, ValueError):
            status = "invalid_candidate"
            if checks[0]["status"] == "pass":
                checks[1] = {
                    "name": "formula.expression",
                    "status": "fail",
                    "evidence": "formula.expression.invalid",
                }
        mapping = _candidate_validation_mapping(
            candidate=candidate,
            contract=contract,
            identity=self.identity,
            status=status,
            canonical_sha256=canonical_sha256,
            checks=sorted(checks, key=lambda item: item["name"]),
        )
        return freeze_candidate_validation(
            mapping,
            candidate=candidate,
            contract=contract,
            plugin_identity=self.identity,
        )

    def evaluate(self, candidate: ValidatedCandidate, split: Any) -> EvaluationResult:
        data = split.data
        if not isinstance(data, FormulaAlphaSplitData):
            raise EvaluationIntegrityError("formula split data type mismatch")
        binding = split.binding
        if candidate != binding.candidate_receipt:
            raise EvaluationIntegrityError("formula candidate binding mismatch")
        if (
            split.request != binding.request
            or split.contract.sha256 != binding.contract.sha256
            or binding.plugin_identity != self.identity
        ):
            raise EvaluationIntegrityError("formula split binding mismatch")
        contract = split.contract.to_dict()
        development = contract["data"]["splits"]["development"]
        if (
            contract["data"]["schema_sha256"] != self.public_schema.sha256
            or data.role != "development"
            or split.request.split_role != "development"
            or data.data_snapshot_sha256 != contract["data"]["snapshot_sha256"]
            or data.split_manifest_sha256 != development["manifest_sha256"]
            or split.request.split_manifest_hash != data.split_manifest_sha256
        ):
            raise EvaluationIntegrityError("formula development identity mismatch")
        binding.runtime_lock.verify()
        primary_spec = contract["metrics"]["primary"]
        diagnostics = contract["metrics"]["diagnostics"]
        constraints = contract["metrics"]["hard_constraints"]
        runtime_checks = split.binding.runtime_lock.required_check_names
        primary = MetricValue.from_mapping(
            {
                "name": primary_spec["name"],
                "value": None,
                "direction": primary_spec["direction"],
                "unit": primary_spec["unit"],
            }
        )
        constraint_values = tuple(
            CheckResult.from_mapping(
                {
                    "name": item["name"],
                    "status": "not_observed",
                    "evidence": "evaluation.not_observed",
                }
            )
            for item in constraints
        )
        diagnostic_values = tuple(
            MetricValue.from_mapping(
                {
                    "name": item["name"],
                    "value": None,
                    "direction": item["direction"],
                    "unit": item["unit"],
                }
            )
            for item in diagnostics
        )
        check_values = tuple(
            CheckResult.from_mapping(
                {
                    "name": name,
                    "status": "not_observed",
                    "evidence": "evaluation.not_observed",
                }
            )
            for name in runtime_checks
        )
        if data.outcome is FormulaMockOutcome.BACKEND_UNAVAILABLE:
            status = "implementation_failure"
            failure_type = "implementation_failure"
            code = "formula.backend_unavailable"
        else:
            status = "incomparable"
            failure_type = "incomparable"
            code = "formula.schema_incompatible"
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
            constraints=constraint_values,
            diagnostics=diagnostic_values,
            fold_metrics=(),
            costs=costs,
            checks=check_values,
            artifacts=(),
            failure=failure,
            warnings=(),
        )

    def summarize(self, result: EvaluationResult) -> EvaluationSummary:
        return EvaluationSummary.from_result(result)


__all__ = [
    "FormulaAlphaPlugin",
    "FormulaAlphaSplitData",
    "FormulaMockOutcome",
    "PublicFormulaSchema",
]
