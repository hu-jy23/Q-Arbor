"""Task-neutral adapter, runner, stage, result, and provenance control path."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol, cast

from .evaluation.codec import (
    JSONValue,
    atomic_write,
    canonical_normalized_bytes,
    normalize_mapping,
    require_git_commit,
    require_identifier,
    require_literal_path,
    require_reason_code,
    require_sha256,
)
from .evaluation.errors import (
    EvaluationBoundaryError,
    EvaluationError,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationSchemaError,
)
from .evaluation.values import ArtifactRef, _ImmutableJSON


_ENVIRONMENT_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,127}")
_SECRET_ENVIRONMENT_PARTS = ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY")
_RUNNER_TERMINATIONS = frozenset(
    {"succeeded", "timeout", "nonzero_exit", "missing_output", "runner_error"}
)


def _exact_mapping(
    mapping: Mapping[str, Any], *, fields: frozenset[str], label: str
) -> dict[str, JSONValue]:
    normalized = normalize_mapping(mapping)
    actual = frozenset(normalized)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        raise EvaluationSchemaError(
            f"{label} fields differ; missing={missing!r}, extra={extra!r}"
        )
    return normalized


def _canonical_identifiers(value: JSONValue, field: str) -> list[str]:
    if not isinstance(value, list):
        raise EvaluationSchemaError(f"{field} must be an array")
    parsed = [require_identifier(item, field) for item in value]
    if len(parsed) != len(set(parsed)):
        raise EvaluationInvariantError(f"{field} contains duplicates")
    return sorted(parsed)


def _artifact_refs(value: JSONValue, field: str) -> list[dict[str, JSONValue]]:
    if not isinstance(value, list):
        raise EvaluationSchemaError(f"{field} must be an array")
    refs = [ArtifactRef.from_mapping(cast(Mapping[str, Any], item)) for item in value]
    if len({ref.artifact_id for ref in refs}) != len(refs):
        raise EvaluationInvariantError(f"{field} contains duplicate artifact IDs")
    return [ref.to_dict() for ref in sorted(refs, key=lambda item: item.artifact_id)]


class AdapterDescriptor(_ImmutableJSON):
    """Open, task-opaque description of one replaceable experiment adapter."""

    _FIELDS = frozenset(
        {
            "adapter_id",
            "adapter_version",
            "adapter_code_sha256",
            "candidate_codec_id",
            "invocation_codec_id",
            "result_codec_id",
            "runner_id",
            "required_output_descriptors",
            "objective_descriptors",
            "diagnostic_descriptors",
            "failure_mapping_id",
            "provenance_requirements",
        }
    )

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> AdapterDescriptor:
        raw = _exact_mapping(mapping, fields=cls._FIELDS, label="adapter descriptor")
        for field in (
            "adapter_id",
            "adapter_version",
            "candidate_codec_id",
            "invocation_codec_id",
            "result_codec_id",
            "runner_id",
            "failure_mapping_id",
        ):
            require_identifier(raw[field], field)
        require_sha256(raw["adapter_code_sha256"], "adapter code SHA-256")
        for field in (
            "required_output_descriptors",
            "objective_descriptors",
            "diagnostic_descriptors",
            "provenance_requirements",
        ):
            raw[field] = _canonical_identifiers(raw[field], field)
        return cls._from_normalized(raw)

    @property
    def adapter_id(self) -> str:
        return cast(str, self._get("adapter_id"))

    @property
    def runner_id(self) -> str:
        return cast(str, self._get("runner_id"))


class EvaluationStagePolicy(_ImmutableJSON):
    """Open namespaced evaluation policy whose identifiers are never enumerated."""

    _FIELDS = frozenset(
        {
            "stage_id",
            "data_visibility",
            "selection_use_allowed",
            "query_budget",
            "feedback_availability_rule",
            "feedback_granularity_descriptor",
            "target_maturity_predicate",
            "contamination_transition_policy",
            "claim_boundary",
            "principal_capabilities",
        }
    )

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> EvaluationStagePolicy:
        raw = _exact_mapping(mapping, fields=cls._FIELDS, label="stage policy")
        for field in (
            "stage_id",
            "data_visibility",
            "feedback_availability_rule",
            "feedback_granularity_descriptor",
            "target_maturity_predicate",
            "contamination_transition_policy",
            "claim_boundary",
        ):
            require_identifier(raw[field], field)
        if not isinstance(raw["selection_use_allowed"], bool):
            raise EvaluationSchemaError("selection_use_allowed must be boolean")
        if type(raw["query_budget"]) is not int or not 0 <= raw["query_budget"] <= 1_000_000:
            raise EvaluationSchemaError("query_budget must be a bounded nonnegative integer")
        raw["principal_capabilities"] = _canonical_identifiers(
            raw["principal_capabilities"], "principal_capabilities"
        )
        return cls._from_normalized(raw)

    @property
    def stage_id(self) -> str:
        return cast(str, self._get("stage_id"))

    @property
    def selection_use_allowed(self) -> bool:
        return cast(bool, self._get("selection_use_allowed"))


class RunnerRequest(_ImmutableJSON):
    """Immutable request addressed to a capability-bound task-local runner."""

    _FIELDS = frozenset(
        {
            "invocation_id",
            "adapter_ref",
            "stage_policy_ref",
            "candidate_artifact_ref",
            "cell_root_capability",
            "environment_lock_ref",
            "immutable_argv",
            "environment_allowlist",
            "timeout_seconds",
            "required_outputs",
        }
    )

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> RunnerRequest:
        raw = _exact_mapping(mapping, fields=cls._FIELDS, label="runner request")
        require_identifier(raw["invocation_id"], "invocation_id")
        require_identifier(raw["cell_root_capability"], "cell_root_capability")
        for field in (
            "adapter_ref",
            "stage_policy_ref",
            "candidate_artifact_ref",
            "environment_lock_ref",
        ):
            require_sha256(raw[field], field)
        argv = raw["immutable_argv"]
        if not isinstance(argv, list) or not argv:
            raise EvaluationSchemaError("immutable_argv must be a nonempty array")
        if any(not isinstance(item, str) or not item or "\0" in item for item in argv):
            raise EvaluationSchemaError("immutable_argv contains an invalid argument")
        environment = raw["environment_allowlist"]
        if not isinstance(environment, dict):
            raise EvaluationSchemaError("environment_allowlist must be an object")
        for name, value in environment.items():
            if _ENVIRONMENT_NAME.fullmatch(name) is None or not isinstance(value, str):
                raise EvaluationSchemaError("environment_allowlist contains an invalid entry")
            if any(part in name for part in _SECRET_ENVIRONMENT_PARTS):
                raise EvaluationBoundaryError("secret-like environment names are forbidden")
        timeout = raw["timeout_seconds"]
        if type(timeout) is not int or not 1 <= timeout <= 86_400:
            raise EvaluationSchemaError("timeout_seconds must be between 1 and 86400")
        outputs = raw["required_outputs"]
        if not isinstance(outputs, list):
            raise EvaluationSchemaError("required_outputs must be an array")
        parsed_outputs = [require_literal_path(item, "required output") for item in outputs]
        if len(parsed_outputs) != len(set(parsed_outputs)):
            raise EvaluationInvariantError("required_outputs contains duplicates")
        raw["required_outputs"] = sorted(parsed_outputs)
        return cls._from_normalized(raw)

    @property
    def invocation_id(self) -> str:
        return cast(str, self._get("invocation_id"))

    @property
    def adapter_ref(self) -> str:
        return cast(str, self._get("adapter_ref"))

    @property
    def stage_policy_ref(self) -> str:
        return cast(str, self._get("stage_policy_ref"))

    @property
    def cell_root_capability(self) -> str:
        return cast(str, self._get("cell_root_capability"))

    @property
    def environment_lock_ref(self) -> str:
        return cast(str, self._get("environment_lock_ref"))

    @property
    def immutable_argv(self) -> tuple[str, ...]:
        return tuple(cast(Sequence[str], self._get("immutable_argv")))

    @property
    def environment_allowlist(self) -> dict[str, str]:
        return cast(dict[str, str], self.to_dict()["environment_allowlist"])

    @property
    def timeout_seconds(self) -> int:
        return cast(int, self._get("timeout_seconds"))

    @property
    def required_outputs(self) -> tuple[str, ...]:
        return tuple(cast(Sequence[str], self._get("required_outputs")))


class RunnerReceipt(_ImmutableJSON):
    """Integrity-bound, transport-neutral runner completion record."""

    _FIELDS = frozenset(
        {
            "runner_id",
            "runner_code_sha256",
            "request_sha256",
            "started_event_id",
            "completed_event_id",
            "termination",
            "exit_code",
            "stdout_ref",
            "stderr_ref",
            "output_artifact_refs",
            "resource_usage",
        }
    )

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> RunnerReceipt:
        raw = _exact_mapping(mapping, fields=cls._FIELDS, label="runner receipt")
        for field in ("runner_id", "started_event_id", "completed_event_id"):
            require_identifier(raw[field], field)
        for field in ("runner_code_sha256", "request_sha256"):
            require_sha256(raw[field], field)
        termination = raw["termination"]
        if termination not in _RUNNER_TERMINATIONS:
            raise EvaluationSchemaError("runner termination is invalid")
        exit_code = raw["exit_code"]
        if exit_code is not None and type(exit_code) is not int:
            raise EvaluationSchemaError("runner exit_code must be integer or null")
        for field in ("stdout_ref", "stderr_ref"):
            value = raw[field]
            if value is not None:
                raw[field] = ArtifactRef.from_mapping(cast(Mapping[str, Any], value)).to_dict()
        raw["output_artifact_refs"] = _artifact_refs(
            raw["output_artifact_refs"], "output_artifact_refs"
        )
        if not isinstance(raw["resource_usage"], dict):
            raise EvaluationSchemaError("resource_usage must be an object")
        return cls._from_normalized(raw)

    @property
    def runner_id(self) -> str:
        return cast(str, self._get("runner_id"))

    @property
    def request_sha256(self) -> str:
        return cast(str, self._get("request_sha256"))

    @property
    def termination(self) -> str:
        return cast(str, self._get("termination"))

    @property
    def output_artifact_refs(self) -> tuple[ArtifactRef, ...]:
        return tuple(
            ArtifactRef.from_mapping(item)
            for item in cast(list[dict[str, Any]], self.to_dict()["output_artifact_refs"])
        )


class ProvenanceSeed(_ImmutableJSON):
    """Cell-local identities known before one runner receipt exists."""

    _FIELDS = frozenset(
        {
            "cell_id",
            "cell_contract_sha256",
            "data_manifest_sha256",
            "baseline_manifest_sha256",
            "evaluator_sha256",
            "code_commit",
            "artifact_manifest_sha256",
        }
    )

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> ProvenanceSeed:
        raw = _exact_mapping(mapping, fields=cls._FIELDS, label="provenance seed")
        require_identifier(raw["cell_id"], "cell_id")
        for field in cls._FIELDS - {"cell_id", "code_commit"}:
            require_sha256(raw[field], field)
        require_git_commit(raw["code_commit"], "code_commit")
        return cls._from_normalized(raw)


class ProvenanceEnvelope(_ImmutableJSON):
    """Complete cell/adapter/runner/stage identity binding for one result."""

    _FIELDS = frozenset(
        {
            "cell_id",
            "cell_contract_sha256",
            "adapter_descriptor_sha256",
            "runner_receipt_sha256",
            "environment_lock_sha256",
            "data_manifest_sha256",
            "baseline_manifest_sha256",
            "evaluator_sha256",
            "stage_policy_sha256",
            "candidate_sha256",
            "code_commit",
            "artifact_manifest_sha256",
        }
    )

    @classmethod
    def bind(
        cls,
        *,
        seed: ProvenanceSeed,
        adapter: AdapterDescriptor,
        request: RunnerRequest,
        receipt: RunnerReceipt,
        stage: EvaluationStagePolicy,
    ) -> ProvenanceEnvelope:
        raw = seed.to_dict()
        raw.update(
            {
                "adapter_descriptor_sha256": adapter.sha256,
                "runner_receipt_sha256": receipt.sha256,
                "environment_lock_sha256": request.environment_lock_ref,
                "stage_policy_sha256": stage.sha256,
                "candidate_sha256": request.to_dict()["candidate_artifact_ref"],
            }
        )
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> ProvenanceEnvelope:
        raw = _exact_mapping(mapping, fields=cls._FIELDS, label="provenance envelope")
        require_identifier(raw["cell_id"], "cell_id")
        for field in cls._FIELDS - {"cell_id", "code_commit"}:
            require_sha256(raw[field], field)
        require_git_commit(raw["code_commit"], "code_commit")
        return cls._from_normalized(raw)

    @property
    def runner_receipt_sha256(self) -> str:
        return cast(str, self._get("runner_receipt_sha256"))


class ResultEnvelope(_ImmutableJSON):
    """Metric-neutral decision envelope with task payloads held as artifacts."""

    _FIELDS = frozenset(
        {
            "result_id",
            "invocation_id",
            "stage_id",
            "availability",
            "mature",
            "status",
            "objective_vector",
            "decision_objective_id",
            "constraints",
            "diagnostic_records",
            "output_artifact_refs",
            "failure",
            "warnings",
            "provenance",
        }
    )

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> ResultEnvelope:
        raw = _exact_mapping(mapping, fields=cls._FIELDS, label="result envelope")
        for field in ("result_id", "invocation_id", "stage_id"):
            require_identifier(raw[field], field)
        if raw["availability"] not in {"available", "deferred"}:
            raise EvaluationSchemaError("result availability is invalid")
        if not isinstance(raw["mature"], bool):
            raise EvaluationSchemaError("result mature must be boolean")
        if raw["status"] not in {"success", "failure", "deferred"}:
            raise EvaluationSchemaError("result status is invalid")
        objectives = raw["objective_vector"]
        if not isinstance(objectives, list):
            raise EvaluationSchemaError("objective_vector must be an array")
        parsed: list[dict[str, JSONValue]] = []
        for item in objectives:
            objective = _exact_mapping(
                cast(Mapping[str, Any], item),
                fields=frozenset({"objective_id", "value", "direction"}),
                label="objective",
            )
            require_identifier(objective["objective_id"], "objective_id")
            if type(objective["value"]) not in {int, float}:
                raise EvaluationSchemaError("objective value must be numeric")
            if objective["direction"] not in {"maximize", "minimize"}:
                raise EvaluationSchemaError("objective direction is invalid")
            parsed.append(objective)
        if len({item["objective_id"] for item in parsed}) != len(parsed):
            raise EvaluationInvariantError("objective IDs must be unique")
        raw["objective_vector"] = sorted(parsed, key=lambda item: cast(str, item["objective_id"]))
        decision_id = raw["decision_objective_id"]
        if decision_id is not None:
            require_identifier(decision_id, "decision_objective_id")
        status = raw["status"]
        objective_ids = {item["objective_id"] for item in parsed}
        if status == "success" and (not parsed or decision_id not in objective_ids):
            raise EvaluationInvariantError("successful result must select an objective")
        if status != "success" and decision_id is not None:
            raise EvaluationInvariantError("non-success result cannot select an objective")
        for field in ("constraints", "diagnostic_records"):
            if not isinstance(raw[field], list) or any(
                not isinstance(item, dict) for item in raw[field]
            ):
                raise EvaluationSchemaError(f"{field} must contain objects")
        raw["output_artifact_refs"] = _artifact_refs(
            raw["output_artifact_refs"], "result output_artifact_refs"
        )
        failure = raw["failure"]
        if status == "failure":
            if not isinstance(failure, dict) or set(failure) != {"code"}:
                raise EvaluationSchemaError("failed result requires one failure code")
            require_reason_code(failure["code"], "failure code")
        elif failure is not None:
            raise EvaluationInvariantError("non-failure result cannot carry failure")
        warnings = raw["warnings"]
        if not isinstance(warnings, list):
            raise EvaluationSchemaError("warnings must be an array")
        raw["warnings"] = sorted(require_reason_code(item, "warning") for item in warnings)
        raw["provenance"] = ProvenanceEnvelope.from_mapping(
            cast(Mapping[str, Any], raw["provenance"])
        ).to_dict()
        return cls._from_normalized(raw)

    @property
    def stage_id(self) -> str:
        return cast(str, self._get("stage_id"))

    @property
    def availability(self) -> str:
        return cast(str, self._get("availability"))

    @property
    def mature(self) -> bool:
        return cast(bool, self._get("mature"))

    @property
    def status(self) -> str:
        return cast(str, self._get("status"))

    @property
    def failure(self) -> dict[str, str] | None:
        return cast(dict[str, str] | None, self.to_dict()["failure"])

    @property
    def provenance(self) -> ProvenanceEnvelope:
        return ProvenanceEnvelope.from_mapping(
            cast(Mapping[str, Any], self.to_dict()["provenance"])
        )


class Runner(Protocol):
    def run(self, request: RunnerRequest) -> RunnerReceipt: ...


ResultDecoder = Callable[[RunnerReceipt], Mapping[str, Any]]


def _artifact_ref(
    *, root: Path, kind: str, label: str, event_id: str, content: bytes
) -> ArtifactRef:
    digest = sha256(content).hexdigest()
    identity = sha256(
        canonical_normalized_bytes({"kind": kind, "label": label, "sha256": digest})
    ).hexdigest()
    relative = f"runner/{digest}"
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.is_symlink() or not target.is_file() or target.read_bytes() != content:
            raise EvaluationIntegrityError("runner artifact identity conflicts")
    else:
        atomic_write(target, content)
    return ArtifactRef.from_mapping(
        {
            "artifact_id": f"artifact.runner.{identity}",
            "kind": kind,
            "relative_path": relative,
            "sha256": digest,
            "media_type": "application/octet-stream",
            "produced_by_event_id": event_id,
        }
    )


class SubprocessRunner:
    """First transport adapter: argv-only subprocess behind root capabilities."""

    def __init__(
        self,
        *,
        artifact_root: str | os.PathLike[str],
        capabilities: Mapping[str, str | os.PathLike[str]],
        runner_id: str,
        runner_code_sha256: str,
    ) -> None:
        self._artifact_root = Path(artifact_root).absolute()
        self._artifact_root.mkdir(parents=True, exist_ok=True)
        self._capabilities = {
            require_identifier(key, "capability ID"): Path(value).absolute()
            for key, value in capabilities.items()
        }
        require_identifier(runner_id, "runner_id")
        require_sha256(runner_code_sha256, "runner_code_sha256")
        self._runner_id = runner_id
        self._runner_code_sha256 = runner_code_sha256

    def run(self, request: RunnerRequest) -> RunnerReceipt:
        started = time.monotonic()
        event_digest = sha256(request.sha256.encode("ascii")).hexdigest()[:24]
        started_event = f"runner.started.{event_digest}"
        completed_event = f"runner.completed.{event_digest}"
        root = self._capabilities.get(request.cell_root_capability)
        if root is None or root.is_symlink() or not root.is_dir():
            raise EvaluationBoundaryError("cell root capability is unavailable")
        stdout = b""
        stderr = b""
        exit_code: int | None = None
        termination = "runner_error"
        try:
            completed = subprocess.run(
                request.immutable_argv,
                cwd=root,
                env=request.environment_allowlist,
                capture_output=True,
                timeout=request.timeout_seconds,
                check=False,
                shell=False,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            exit_code = completed.returncode
            termination = "succeeded" if completed.returncode == 0 else "nonzero_exit"
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            termination = "timeout"
        except OSError as exc:
            stderr = str(exc).encode("utf-8", errors="replace")
            termination = "runner_error"
        output_refs: list[ArtifactRef] = []
        if termination == "succeeded":
            for relative in request.required_outputs:
                path = (root / relative).absolute()
                try:
                    path.relative_to(root)
                except ValueError as exc:
                    raise EvaluationBoundaryError("runner output escapes capability") from exc
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    termination = "missing_output"
                    break
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    termination = "missing_output"
                    break
                output_refs.append(
                    _artifact_ref(
                        root=self._artifact_root,
                        kind="runner.output",
                        label=relative,
                        event_id=completed_event,
                        content=path.read_bytes(),
                    )
                )
        stdout_ref = _artifact_ref(
            root=self._artifact_root,
            kind="runner.stdout",
            label="stdout",
            event_id=completed_event,
            content=stdout,
        )
        stderr_ref = _artifact_ref(
            root=self._artifact_root,
            kind="runner.stderr",
            label="stderr",
            event_id=completed_event,
            content=stderr,
        )
        return RunnerReceipt.from_mapping(
            {
                "runner_id": self._runner_id,
                "runner_code_sha256": self._runner_code_sha256,
                "request_sha256": request.sha256,
                "started_event_id": started_event,
                "completed_event_id": completed_event,
                "termination": termination,
                "exit_code": exit_code,
                "stdout_ref": stdout_ref.to_dict(),
                "stderr_ref": stderr_ref.to_dict(),
                "output_artifact_refs": [ref.to_dict() for ref in output_refs],
                "resource_usage": {"wall_seconds": time.monotonic() - started},
            }
        )


@dataclass(frozen=True, slots=True)
class ControlPathOutcome:
    receipt: RunnerReceipt
    result: ResultEnvelope
    decision: Mapping[str, JSONValue]
    transcript: tuple[Mapping[str, JSONValue], ...]
    transcript_sha256: str
    report: Mapping[str, JSONValue]


def _failure_code(termination: str) -> str:
    return {
        "timeout": "runner_timeout",
        "nonzero_exit": "runner_nonzero_exit",
        "missing_output": "runner_missing_output",
        "runner_error": "runner_error",
    }[termination]


def _synthetic_receipt(
    *, request: RunnerRequest, adapter: AdapterDescriptor
) -> RunnerReceipt:
    return RunnerReceipt.from_mapping(
        {
            "runner_id": adapter.runner_id,
            "runner_code_sha256": cast(str, adapter.to_dict()["adapter_code_sha256"]),
            "request_sha256": request.sha256,
            "started_event_id": "runner.started.synthetic-error",
            "completed_event_id": "runner.completed.synthetic-error",
            "termination": "runner_error",
            "exit_code": None,
            "stdout_ref": None,
            "stderr_ref": None,
            "output_artifact_refs": [],
            "resource_usage": {},
        }
    )


class ControlPath:
    """One shared propose→dispatch→evaluate→decide→recover→report path."""

    def execute(
        self,
        *,
        proposal_id: str,
        adapter: AdapterDescriptor,
        stage: EvaluationStagePolicy,
        request: RunnerRequest,
        provenance_seed: ProvenanceSeed,
        runner: Runner,
        decoder: ResultDecoder,
    ) -> ControlPathOutcome:
        require_identifier(proposal_id, "proposal_id")
        if request.adapter_ref != adapter.sha256:
            raise EvaluationIntegrityError("request adapter identity differs")
        if request.stage_policy_ref != stage.sha256:
            raise EvaluationIntegrityError("request stage policy identity differs")
        transcript: list[dict[str, JSONValue]] = [
            {"phase": "propose", "proposal_id": proposal_id, "adapter_ref": adapter.sha256},
            {"phase": "dispatch", "request_sha256": request.sha256, "stage_policy_ref": stage.sha256},
        ]
        try:
            receipt = runner.run(request)
        except Exception:
            receipt = _synthetic_receipt(request=request, adapter=adapter)
        if receipt.request_sha256 != request.sha256:
            raise EvaluationIntegrityError("runner receipt request identity differs")
        if receipt.runner_id != adapter.runner_id:
            raise EvaluationIntegrityError("runner receipt adapter identity differs")
        provenance = ProvenanceEnvelope.bind(
            seed=provenance_seed,
            adapter=adapter,
            request=request,
            receipt=receipt,
            stage=stage,
        )
        result_id = "result." + sha256(
            canonical_normalized_bytes(
                {
                    "invocation_id": request.invocation_id,
                    "receipt_sha256": receipt.sha256,
                    "stage_policy_sha256": stage.sha256,
                }
            )
        ).hexdigest()[:24]
        if receipt.termination != "succeeded":
            decoded: Mapping[str, Any] = {
                "availability": "available",
                "mature": True,
                "status": "failure",
                "objective_vector": [],
                "decision_objective_id": None,
                "constraints": [],
                "diagnostic_records": [],
                "output_artifact_refs": [],
                "failure": {"code": _failure_code(receipt.termination)},
                "warnings": [],
            }
        else:
            try:
                decoded = decoder(receipt)
                if not isinstance(decoded, Mapping):
                    raise EvaluationSchemaError("decoder result must be an object")
                candidate_result = dict(decoded)
                candidate_result.update(
                    {
                        "result_id": result_id,
                        "invocation_id": request.invocation_id,
                        "stage_id": stage.stage_id,
                        "provenance": provenance.to_dict(),
                    }
                )
                result = ResultEnvelope.from_mapping(candidate_result)
            except Exception:
                decoded = {
                    "availability": "available",
                    "mature": True,
                    "status": "failure",
                    "objective_vector": [],
                    "decision_objective_id": None,
                    "constraints": [],
                    "diagnostic_records": [],
                    "output_artifact_refs": [],
                    "failure": {"code": "malformed_result_envelope"},
                    "warnings": [],
                }
            else:
                decoded = {}
        if not decoded:
            pass
        else:
            result_mapping = dict(decoded)
            result_mapping.update(
                {
                    "result_id": result_id,
                    "invocation_id": request.invocation_id,
                    "stage_id": stage.stage_id,
                    "provenance": provenance.to_dict(),
                }
            )
            result = ResultEnvelope.from_mapping(result_mapping)
        transcript.append(
            {"phase": "evaluate", "receipt_sha256": receipt.sha256, "result_sha256": result.sha256}
        )
        if not stage.selection_use_allowed:
            decision: dict[str, JSONValue] = {
                "selection_eligible": False,
                "reason": "stage_forbids_selection",
            }
        elif result.availability != "available":
            decision = {"selection_eligible": False, "reason": "result_not_available"}
        elif not result.mature:
            decision = {"selection_eligible": False, "reason": "result_not_mature"}
        elif result.status != "success":
            decision = {"selection_eligible": False, "reason": "result_not_successful"}
        else:
            decision = {"selection_eligible": True, "reason": "eligible"}
        transcript.extend(
            [
                {"phase": "decide", **decision},
                {
                    "phase": "recover",
                    "action": "receipt_and_result_preserved",
                    "receipt_sha256": receipt.sha256,
                    "result_sha256": result.sha256,
                },
            ]
        )
        report: dict[str, JSONValue] = {
            "adapter_id": adapter.adapter_id,
            "stage_id": stage.stage_id,
            "result_status": result.status,
            "selection_eligible": cast(bool, decision["selection_eligible"]),
            "receipt_sha256": receipt.sha256,
            "result_sha256": result.sha256,
            "provenance_sha256": provenance.sha256,
        }
        transcript.append({"phase": "report", "report": report})
        frozen_transcript = tuple(cast(Mapping[str, JSONValue], item) for item in transcript)
        transcript_sha256 = sha256(
            canonical_normalized_bytes(cast(Any, list(frozen_transcript)))
        ).hexdigest()
        return ControlPathOutcome(
            receipt=receipt,
            result=result,
            decision=decision,
            transcript=frozen_transcript,
            transcript_sha256=transcript_sha256,
            report=report,
        )


__all__ = [
    "AdapterDescriptor",
    "ControlPath",
    "ControlPathOutcome",
    "EvaluationStagePolicy",
    "ProvenanceEnvelope",
    "ProvenanceSeed",
    "ResultEnvelope",
    "Runner",
    "RunnerReceipt",
    "RunnerRequest",
    "SubprocessRunner",
]
