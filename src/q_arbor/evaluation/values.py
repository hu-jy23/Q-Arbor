"""Deeply immutable primitive C9 value objects."""

from __future__ import annotations

import os
from collections.abc import Mapping
from hashlib import sha256
from typing import Any, Self, cast

from .codec import (
    FrozenJSON,
    JSONValue,
    atomic_write,
    canonical_normalized_bytes,
    deep_freeze,
    deep_thaw,
    normalize_mapping,
    require_identifier,
    require_reason_code,
    require_sha256,
    validate_definition,
    validate_discriminator,
)
from .errors import (
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationSchemaError,
)


class ReasonCode(str):
    """A bounded ASCII machine-readable explanation code."""

    __slots__ = ()

    @classmethod
    def parse(cls, value: str) -> ReasonCode:
        require_reason_code(value, "reason code")
        return cls(value)


class _ImmutableJSON:
    __slots__ = ("_canonical", "_initialized", "_sha256", "_snapshot")

    def __init__(self) -> None:
        raise TypeError(f"use a public {type(self).__name__} factory")

    @classmethod
    def _from_normalized(cls, normalized: dict[str, JSONValue]) -> Self:
        instance = cls.__new__(cls)
        canonical = canonical_normalized_bytes(normalized)
        object.__setattr__(instance, "_snapshot", deep_freeze(normalized))
        object.__setattr__(instance, "_canonical", canonical)
        object.__setattr__(instance, "_sha256", sha256(canonical).hexdigest())
        object.__setattr__(instance, "_initialized", True)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError(f"{type(self).__name__} is immutable")
        object.__setattr__(self, name, value)

    @property
    def sha256(self) -> str:
        return cast(str, self._sha256)

    def to_dict(self) -> dict[str, JSONValue]:
        return cast(dict[str, JSONValue], deep_thaw(self._snapshot))

    def to_json(self) -> str:
        return cast(bytes, self._canonical).decode("utf-8")

    def write(self, path: str | os.PathLike[str]) -> None:
        atomic_write(path, cast(bytes, self._canonical))

    def _get(self, key: str) -> FrozenJSON:
        return cast(Mapping[str, FrozenJSON], self._snapshot)[key]

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> Self:
        memo[id(self)] = self
        return self

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return NotImplemented
        return self._canonical == cast(_ImmutableJSON, other)._canonical

    def __hash__(self) -> int:
        return hash((type(self), self._canonical))

    def __repr__(self) -> str:
        return f"{type(self).__name__}(sha256={self.sha256!r})"


def _normalized_definition(
    mapping: Mapping[str, Any], name: str
) -> dict[str, JSONValue]:
    normalized = normalize_mapping(mapping)
    validate_definition(normalized, name)
    return normalized


class ArtifactRef(_ImmutableJSON):
    """Frozen C6 ArtifactRef with strict identity and literal path checks."""

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> ArtifactRef:
        normalized = _normalized_definition(mapping, "ArtifactRef")
        require_identifier(normalized["artifact_id"], "artifact_id")
        require_sha256(normalized["sha256"], "artifact sha256")
        from .codec import require_literal_path

        require_literal_path(normalized["relative_path"], "artifact relative_path")
        event_id = normalized.get("produced_by_event_id")
        if event_id is not None:
            require_identifier(event_id, "artifact produced_by_event_id")
        return cls._from_normalized(normalized)

    @property
    def artifact_id(self) -> str:
        return cast(str, self._get("artifact_id"))

    @property
    def sha256(self) -> str:
        """Return the digest of the referenced payload bytes."""

        return cast(str, self._get("sha256"))

    @property
    def canonical_sha256(self) -> str:
        """Return the digest of this complete canonical ArtifactRef."""

        return cast(str, self._sha256)

    @property
    def kind(self) -> str:
        return cast(str, self._get("kind"))

    @property
    def relative_path(self) -> str:
        return cast(str, self._get("relative_path"))

    @property
    def media_type(self) -> str | None:
        return cast(str | None, self.to_dict().get("media_type"))

    @property
    def produced_by_event_id(self) -> str | None:
        return cast(str | None, self.to_dict().get("produced_by_event_id"))


def compute_test_family_snapshot_hash(mapping: Mapping[str, Any]) -> str:
    """Hash canonical snapshot content, excluding only its declared hash."""

    normalized = normalize_mapping(mapping)
    normalized.pop("snapshot_hash", None)
    return sha256(canonical_normalized_bytes(normalized)).hexdigest()


class TestFamilySnapshot(_ImmutableJSON):
    """Canonical frozen C6 test-family membership and method assumptions."""

    __test__ = False

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> TestFamilySnapshot:
        normalized = normalize_mapping(mapping)
        validate_discriminator(normalized, "test_family_snapshot")

        for field in (
            "test_family_id",
            "run_id",
            "decision_point_id",
            "frozen_event_id",
        ):
            require_identifier(normalized[field], field)
        for field in ("member_candidate_ids", "evaluation_request_ids"):
            for identifier in cast(list[JSONValue], normalized[field]):
                require_identifier(identifier, field)
        for field in (
            "benchmark_ref",
            "selection_rule_ref",
            "dependence_description_ref",
        ):
            ArtifactRef.from_mapping(cast(Mapping[str, Any], normalized[field]))
        require_sha256(normalized["method_plan_hash"], "method_plan_hash")
        declared_hash = require_sha256(
            normalized["snapshot_hash"], "snapshot_hash"
        )
        if declared_hash != compute_test_family_snapshot_hash(normalized):
            raise EvaluationIntegrityError("test family snapshot hash does not match")
        return cls._from_normalized(normalized)

    @property
    def schema_version(self) -> str:
        return cast(str, self._get("schema_version"))

    @property
    def test_family_id(self) -> str:
        return cast(str, self._get("test_family_id"))

    @property
    def run_id(self) -> str:
        return cast(str, self._get("run_id"))

    @property
    def decision_point_id(self) -> str:
        return cast(str, self._get("decision_point_id"))

    @property
    def family_unit(self) -> str:
        return cast(str, self._get("family_unit"))

    @property
    def duplicate_policy(self) -> str:
        return cast(str, self._get("duplicate_policy"))

    @property
    def member_candidate_ids(self) -> tuple[str, ...]:
        return cast(tuple[str, ...], self._get("member_candidate_ids"))

    @property
    def evaluation_request_ids(self) -> tuple[str, ...]:
        return cast(tuple[str, ...], self._get("evaluation_request_ids"))

    @property
    def benchmark_ref(self) -> ArtifactRef:
        return ArtifactRef.from_mapping(
            cast(Mapping[str, Any], self._get("benchmark_ref"))
        )

    @property
    def selection_rule_ref(self) -> ArtifactRef:
        return ArtifactRef.from_mapping(
            cast(Mapping[str, Any], self._get("selection_rule_ref"))
        )

    @property
    def dependence_description_ref(self) -> ArtifactRef:
        return ArtifactRef.from_mapping(
            cast(Mapping[str, Any], self._get("dependence_description_ref"))
        )

    @property
    def method_plan_hash(self) -> str:
        return cast(str, self._get("method_plan_hash"))

    @property
    def frozen_event_id(self) -> str:
        return cast(str, self._get("frozen_event_id"))

    @property
    def snapshot_hash(self) -> str:
        return cast(str, self._get("snapshot_hash"))


def freeze_test_family_snapshot(mapping: Mapping[str, Any]) -> TestFamilySnapshot:
    """Create a canonical snapshot and fill its content-bound hash."""

    normalized = normalize_mapping(mapping)
    normalized["snapshot_hash"] = compute_test_family_snapshot_hash(normalized)
    return TestFamilySnapshot.from_mapping(normalized)


class PluginIdentity(_ImmutableJSON):
    """Frozen C6 plugin identity."""

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> PluginIdentity:
        normalized = _normalized_definition(mapping, "PluginIdentity")
        require_identifier(normalized["name"], "plugin name")
        require_sha256(normalized["code_sha256"], "plugin code_sha256")
        for field in ("version", "artifact_type"):
            value = normalized[field]
            if not isinstance(value, str) or not value:
                raise EvaluationInvariantError(f"plugin {field} must be non-empty")
        return cls._from_normalized(normalized)

    @property
    def name(self) -> str:
        return cast(str, self._get("name"))

    @property
    def version(self) -> str:
        return cast(str, self._get("version"))

    @property
    def code_sha256(self) -> str:
        return cast(str, self._get("code_sha256"))

    @property
    def artifact_type(self) -> str:
        return cast(str, self._get("artifact_type"))


class CheckResult(_ImmutableJSON):
    """Frozen C6 check outcome with sanitized evidence."""

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> CheckResult:
        normalized = _normalized_definition(mapping, "CheckResult")
        name = normalized["name"]
        if not isinstance(name, str) or not name:
            raise EvaluationInvariantError("check name must be non-empty")
        require_reason_code(normalized["evidence"], "check evidence")
        return cls._from_normalized(normalized)

    @property
    def name(self) -> str:
        return cast(str, self._get("name"))

    @property
    def status(self) -> str:
        return cast(str, self._get("status"))

    @property
    def evidence(self) -> ReasonCode:
        return ReasonCode.parse(cast(str, self._get("evidence")))


class MetricValue(_ImmutableJSON):
    """Frozen C6 finite-or-null metric value."""

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> MetricValue:
        normalized = _normalized_definition(mapping, "MetricValue")
        value = normalized["value"]
        if isinstance(value, bool):
            raise EvaluationSchemaError("metric value must not be boolean")
        if not isinstance(normalized["name"], str) or not normalized["name"]:
            raise EvaluationInvariantError("metric name must be non-empty")
        return cls._from_normalized(normalized)

    @property
    def name(self) -> str:
        return cast(str, self._get("name"))

    @property
    def value(self) -> int | float | None:
        return cast(int | float | None, self._get("value"))

    @property
    def direction(self) -> str:
        return cast(str, self._get("direction"))

    @property
    def unit(self) -> str:
        return cast(str, self._get("unit"))


class EvaluationFailure(_ImmutableJSON):
    """Frozen C6 failure record with bounded machine-readable summary."""

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> EvaluationFailure:
        normalized = _normalized_definition(mapping, "FailureRecord")
        failure_type = normalized["failure_type"]
        summary = normalized["summary"]
        if failure_type == "none":
            if summary != "":
                raise EvaluationInvariantError(
                    "failure_type=none requires empty summary"
                )
        else:
            require_reason_code(summary, "failure summary")
        evidence_ids = cast(list[JSONValue], normalized["evidence_ids"])
        for evidence_id in evidence_ids:
            require_identifier(evidence_id, "failure evidence ID")
        if len(evidence_ids) != len(set(cast(list[str], evidence_ids))):
            raise EvaluationInvariantError("failure evidence IDs must be unique")
        return cls._from_normalized(normalized)

    @property
    def failure_type(self) -> str:
        return cast(str, self._get("failure_type"))

    @property
    def summary(self) -> str:
        return cast(str, self._get("summary"))

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return cast(tuple[str, ...], self._get("evidence_ids"))


class FamilyEvidence(_ImmutableJSON):
    """Non-authoritative exact-family evidence emitted by validation."""

    _KEYS = frozenset({"family_hint", "method", "evidence_sha256"})

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> FamilyEvidence:
        normalized = normalize_mapping(mapping)
        if set(normalized) != cls._KEYS:
            raise EvaluationSchemaError("FamilyEvidence fields do not match C9")
        family_hint = normalized["family_hint"]
        if family_hint is not None:
            require_identifier(family_hint, "family hint")
        require_reason_code(normalized["method"], "family evidence method")
        require_sha256(normalized["evidence_sha256"], "family evidence sha256")
        return cls._from_normalized(normalized)

    @property
    def family_hint(self) -> str | None:
        return cast(str | None, self._get("family_hint"))

    @property
    def method(self) -> ReasonCode:
        return ReasonCode.parse(cast(str, self._get("method")))

    @property
    def evidence_sha256(self) -> str:
        return cast(str, self._get("evidence_sha256"))


class FoldPolicy(_ImmutableJSON):
    """Closed runtime fold policy decoded from evaluator configuration."""

    _KEYS = frozenset({"mode", "expected_fold_ids", "required_metric_names"})

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> FoldPolicy:
        normalized = normalize_mapping(mapping)
        if set(normalized) != cls._KEYS:
            raise EvaluationSchemaError("FoldPolicy fields do not match C9")
        mode = normalized["mode"]
        if mode not in {"required", "aggregate_only"}:
            raise EvaluationSchemaError("FoldPolicy mode is invalid")
        fold_ids = normalized["expected_fold_ids"]
        metric_names = normalized["required_metric_names"]
        if not isinstance(fold_ids, list) or not isinstance(metric_names, list):
            raise EvaluationSchemaError("FoldPolicy arrays are required")
        for fold_id in fold_ids:
            require_reason_code(fold_id, "fold ID")
        for metric_name in metric_names:
            require_reason_code(metric_name, "fold metric name")
        for values, label in (
            (cast(list[str], fold_ids), "fold IDs"),
            (cast(list[str], metric_names), "fold metric names"),
        ):
            if values != sorted(values) or len(values) != len(set(values)):
                raise EvaluationInvariantError(f"{label} must be sorted and unique")
        if mode == "required" and not fold_ids:
            raise EvaluationInvariantError("required fold policy needs fold IDs")
        if mode == "aggregate_only" and fold_ids:
            raise EvaluationInvariantError("aggregate-only policy forbids fold IDs")
        if not metric_names:
            raise EvaluationInvariantError("fold policy needs metric names")
        return cls._from_normalized(normalized)

    @property
    def mode(self) -> str:
        return cast(str, self._get("mode"))

    @property
    def expected_fold_ids(self) -> tuple[str, ...]:
        return cast(tuple[str, ...], self._get("expected_fold_ids"))

    @property
    def required_metric_names(self) -> tuple[str, ...]:
        return cast(tuple[str, ...], self._get("required_metric_names"))
