from __future__ import annotations

import copy
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from q_arbor.contracts import QuantResearchContract, freeze_contract
from q_arbor.evaluation import (
    ArtifactRef,
    CandidateArtifact,
    CandidateReceipt,
    ContentAddressedArtifactStore,
    EvaluationBinding,
    EvaluationIntegrityError,
    EvaluationRequest,
    EvaluationResult,
    MaterializationReceipt,
    PluginIdentity,
    ValidatedCandidate,
    VerifiedRuntimeLock,
    freeze_evaluation_request,
)
from tests.synthetic_plugin import (
    SyntheticSignalPlugin,
    make_synthetic_development_split,
    synthetic_contract_draft,
)
from tests.hypothesis_helpers import canonical_json

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EVALUATION_FIXTURES = REPOSITORY_ROOT / "tests" / "fixtures" / "evaluation"

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
CODE_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def evaluation_fixture(name: str) -> Path:
    return EVALUATION_FIXTURES / name


def fixture_bytes(name: str) -> bytes:
    return evaluation_fixture(name).read_bytes()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def diagnostic_check_name(name: str) -> str:
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
    return f"diagnostic.{digest[:16]}.observed"


def plugin_identity_mapping(
    *,
    name: str = "synthetic.signal",
    artifact_type: str = "q-arbor.synthetic-signal.v1",
    code_sha256: str = HASH_A,
) -> dict[str, str]:
    return {
        "name": name,
        "version": "1.0.0",
        "code_sha256": code_sha256,
        "artifact_type": artifact_type,
    }


def synthetic_identity() -> PluginIdentity:
    return PluginIdentity.from_mapping(plugin_identity_mapping())


def synthetic_contract(identity: PluginIdentity | None = None) -> QuantResearchContract:
    identity = identity or synthetic_identity()
    return freeze_contract(
        synthetic_contract_draft(
            plugin_identity=identity,
            baseline_ref="baseline/main@0123456789abcdef",
        )
    )


class FileArtifactResolver:
    """A minimal test implementation of the public ArtifactResolver protocol."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def _path(self, ref: ArtifactRef) -> Path:
        path = self.root.joinpath(*ref.relative_path.split("/"))
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise EvaluationIntegrityError("artifact escaped test resolver") from exc
        return path

    def read_bytes(self, ref: ArtifactRef) -> bytes:
        self.verify(ref)
        try:
            return self._path(ref).read_bytes()
        except OSError as exc:
            raise EvaluationIntegrityError("artifact became unreadable") from exc

    def verify(self, ref: ArtifactRef) -> None:
        path = self._path(ref)
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink():
                raise EvaluationIntegrityError("artifact is not a regular file")
            payload = path.read_bytes()
        except OSError as exc:
            raise EvaluationIntegrityError("artifact is unavailable") from exc
        if sha256_bytes(payload) != ref.sha256:
            raise EvaluationIntegrityError("artifact digest drift")

    def verify_issued(
        self,
        ref: ArtifactRef,
        *,
        request_id: str,
        runtime_lock: VerifiedRuntimeLock,
    ) -> None:
        del request_id, runtime_lock
        self.verify(ref)


@dataclass(frozen=True)
class RuntimeFixture:
    lock: VerifiedRuntimeLock
    resolver: FileArtifactResolver
    evaluator_ref: ArtifactRef
    config_ref: ArtifactRef
    evaluator_path: Path
    config_path: Path
    config: dict[str, Any]


def runtime_fixture(
    root: Path,
    contract: QuantResearchContract,
    *,
    aggregate_only: bool = False,
    evaluator_payload: bytes = b"q-arbor deterministic evaluator v1\n",
) -> RuntimeFixture:
    contract_mapping = contract.to_dict()
    primary_name = contract_mapping["metrics"]["primary"]["name"]
    diagnostics = contract_mapping["metrics"]["diagnostics"]
    required_checks = sorted(
        {
            "candidate.identity",
            "cost.reconciled",
            "split.identity",
            *(diagnostic_check_name(item["name"]) for item in diagnostics),
        }
    )
    fold_policy = {
        "mode": "aggregate_only" if aggregate_only else "required",
        "expected_fold_ids": [] if aggregate_only else ["fold.a", "fold.b"],
        "required_metric_names": [primary_name],
    }
    config: dict[str, Any] = {
        "schema_version": "1.0",
        "plugin_config": {},
        "policy": {
            "required_check_names": required_checks,
            "fold_policy": fold_policy,
            "allowed_artifacts": [
                {
                    "kind": "q-arbor.aggregate-metrics.v1",
                    "media_type": "application/json",
                }
            ],
        },
    }
    runtime_root = root / "runtime"
    runtime_root.mkdir(parents=True, exist_ok=True)
    evaluator_path = runtime_root / "evaluator.bin"
    config_path = runtime_root / "config.json"
    evaluator_path.write_bytes(evaluator_payload)
    config_payload = canonical_json(config).encode("utf-8")
    config_path.write_bytes(config_payload)
    evaluator_ref = ArtifactRef.from_mapping(
        {
            "artifact_id": "runtime.evaluator",
            "kind": "q-arbor.evaluator.v1",
            "relative_path": "runtime/evaluator.bin",
            "sha256": sha256_bytes(evaluator_payload),
            "media_type": "application/octet-stream",
        }
    )
    config_ref = ArtifactRef.from_mapping(
        {
            "artifact_id": "runtime.config",
            "kind": "q-arbor.evaluator-config.v1",
            "relative_path": "runtime/config.json",
            "sha256": sha256_bytes(config_payload),
            "media_type": "application/json",
        }
    )
    resolver = FileArtifactResolver(root)
    lock = VerifiedRuntimeLock.from_artifacts(
        evaluator_ref,
        config_ref,
        resolver=resolver,
    )
    return RuntimeFixture(
        lock=lock,
        resolver=resolver,
        evaluator_ref=evaluator_ref,
        config_ref=config_ref,
        evaluator_path=evaluator_path,
        config_path=config_path,
        config=config,
    )


def artifact_ref_mapping(
    *,
    artifact_id: str,
    kind: str,
    relative_path: str,
    payload: bytes,
    media_type: str,
    produced_by_event_id: str | None = None,
) -> dict[str, Any]:
    mapping: dict[str, Any] = {
        "artifact_id": artifact_id,
        "kind": kind,
        "relative_path": relative_path,
        "sha256": sha256_bytes(payload),
        "media_type": media_type,
    }
    if produced_by_event_id is not None:
        mapping["produced_by_event_id"] = produced_by_event_id
    return mapping


def materialize_candidate(
    root: Path,
    contract: QuantResearchContract,
    payload: bytes,
    *,
    relative_path: str | None = None,
    changed_paths: tuple[str, ...] | None = None,
) -> CandidateArtifact:
    contract_mapping = contract.to_dict()
    relative_path = relative_path or contract_mapping["required_outputs"][0]
    path = root.joinpath(*relative_path.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    artifact = ArtifactRef.from_mapping(
        artifact_ref_mapping(
            artifact_id="candidate.primary",
            kind=contract_mapping["objective"]["candidate_artifact_type"],
            relative_path=relative_path,
            payload=payload,
            media_type=(
                "text/x-python" if relative_path.endswith(".py") else "application/json"
            ),
        )
    )
    paths = changed_paths or (relative_path,)
    receipt = MaterializationReceipt.scan(root, paths)
    return CandidateArtifact.from_bytes(
        artifact,
        payload,
        code_commit=CODE_COMMIT,
        changed_paths=paths,
        materialization=receipt,
    )


def bind_validation(
    root: Path,
    *,
    candidate: CandidateArtifact,
    validation: Any,
    contract: QuantResearchContract,
    plugin_identity: PluginIdentity,
    require_valid: bool = True,
) -> CandidateReceipt:
    relative_path = f"artifacts/validations/{validation.sha256}.json"
    receipt_path = root.joinpath(*relative_path.split("/"))
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    validation.write(receipt_path)
    receipt_ref = ArtifactRef.from_mapping(
        artifact_ref_mapping(
            artifact_id=f"validation.{validation.sha256[:16]}",
            kind="q-arbor.validation-receipt.v1",
            relative_path=relative_path,
            payload=validation.to_json().encode("utf-8"),
            media_type="application/json",
        )
    )
    binder = ValidatedCandidate.bind if require_valid else CandidateReceipt.bind
    return binder(
        candidate,
        validation,
        receipt_ref,
        contract=contract,
        plugin_identity=plugin_identity,
    )


def evaluation_request_mapping(
    contract: QuantResearchContract,
    receipt: CandidateReceipt,
    *,
    split_role: str = "development",
    request_id: str = "request.fixture.1",
    node_id: str = "node.fixture",
    attempt_id: str = "attempt.fixture.1",
) -> dict[str, Any]:
    contract_mapping = contract.to_dict()
    split = contract_mapping["data"]["splits"][split_role]
    metrics = contract_mapping["metrics"]
    return {
        "request_id": request_id,
        "run_id": "run.fixture",
        "node_id": node_id,
        "attempt_id": attempt_id,
        "idempotency_key": f"idempotency.{request_id}",
        "contract_hash": contract.sha256,
        "candidate": receipt.candidate.artifact.to_dict(),
        "candidate_hash": receipt.candidate.candidate_hash,
        "validation_receipt": receipt.receipt_ref.to_dict(),
        "plugin": receipt.plugin_identity.to_dict(),
        "split_role": split_role,
        "split_manifest_hash": split["manifest_sha256"],
        "capability_grant_id": f"grant.{split_role}.fixture",
        "requested_metrics": [
            metrics["primary"]["name"],
            *(item["name"] for item in metrics["diagnostics"]),
        ],
        "created_event_id": "event.request.fixture",
    }


def make_request(
    contract: QuantResearchContract,
    receipt: CandidateReceipt,
    **updates: Any,
) -> EvaluationRequest:
    mapping = evaluation_request_mapping(
        contract,
        receipt,
        split_role=updates.pop("split_role", "development"),
        request_id=updates.pop("request_id", "request.fixture.1"),
        node_id=updates.pop("node_id", "node.fixture"),
        attempt_id=updates.pop("attempt_id", "attempt.fixture.1"),
    )
    mapping.update(updates)
    return freeze_evaluation_request(
        mapping,
        contract=contract,
        candidate_receipt=receipt,
    )


def make_binding(
    *,
    request: EvaluationRequest,
    contract: QuantResearchContract,
    receipt: CandidateReceipt,
    plugin_identity: PluginIdentity,
    runtime_lock: VerifiedRuntimeLock,
    artifact_resolver: Any,
    result_id: str = "result.fixture.1",
    seed: int = 7,
) -> EvaluationBinding:
    return EvaluationBinding.create(
        request,
        contract,
        receipt,
        plugin_identity,
        runtime_lock,
        result_id=result_id,
        seed=seed,
        artifact_resolver=artifact_resolver,
    )


@dataclass(frozen=True)
class EvaluationCase:
    plugin: Any
    identity: PluginIdentity
    contract: QuantResearchContract
    candidate: CandidateArtifact
    receipt: CandidateReceipt
    request: EvaluationRequest
    runtime: RuntimeFixture
    store: ContentAddressedArtifactStore
    binding: EvaluationBinding
    result: EvaluationResult
    split: Any | None


def validated_synthetic_components(
    root: Path,
    *,
    signal_column: str = "planted_signal",
) -> tuple[
    SyntheticSignalPlugin,
    PluginIdentity,
    QuantResearchContract,
    CandidateArtifact,
    ValidatedCandidate,
]:
    identity = synthetic_identity()
    plugin = SyntheticSignalPlugin.create(identity)
    contract = synthetic_contract(identity)
    fixture_stem = signal_column.removesuffix("_signal")
    payload = fixture_bytes(f"synthetic_{fixture_stem}_candidate.json")
    candidate = materialize_candidate(root / "candidate", contract, payload)
    validation = plugin.validate(candidate, contract)
    receipt = bind_validation(
        root,
        candidate=candidate,
        validation=validation,
        contract=contract,
        plugin_identity=identity,
    )
    assert isinstance(receipt, ValidatedCandidate)
    return plugin, identity, contract, candidate, receipt


def synthetic_case(
    root: Path,
    *,
    signal_column: str = "planted_signal",
    result_id: str = "result.synthetic.1",
    request_id: str = "request.synthetic.1",
    seed: int = 7,
) -> EvaluationCase:
    plugin, identity, contract, candidate, receipt = validated_synthetic_components(
        root,
        signal_column=signal_column,
    )
    request = make_request(
        contract,
        receipt,
        split_role="development",
        request_id=request_id,
    )
    runtime = runtime_fixture(root, contract)
    store = ContentAddressedArtifactStore.create(root / "artifact-store")
    split = make_synthetic_development_split(
        request,
        contract,
        receipt,
        plugin,
        runtime.lock,
        result_id=result_id,
        evaluation_seed=seed,
        artifact_store=store,
        produced_by_event_id="event.evaluation.synthetic",
    )
    result = plugin.evaluate(receipt, split)
    return EvaluationCase(
        plugin=plugin,
        identity=identity,
        contract=contract,
        candidate=candidate,
        receipt=receipt,
        request=request,
        runtime=runtime,
        store=store,
        binding=split.binding,
        result=result,
        split=split,
    )


def invalid_synthetic_case(
    root: Path,
    *,
    fixture_name: str = "synthetic_unknown_field_candidate.json",
) -> tuple[
    Any, PluginIdentity, QuantResearchContract, CandidateArtifact, CandidateReceipt
]:
    identity = synthetic_identity()
    plugin = SyntheticSignalPlugin.create(identity)
    contract = synthetic_contract(identity)
    candidate = materialize_candidate(
        root / "candidate",
        contract,
        fixture_bytes(fixture_name),
    )
    validation = plugin.validate(candidate, contract)
    receipt = bind_validation(
        root,
        candidate=candidate,
        validation=validation,
        contract=contract,
        plugin_identity=identity,
        require_valid=False,
    )
    return plugin, identity, contract, candidate, receipt


def detached_copy(value: Any) -> dict[str, Any]:
    return copy.deepcopy(value.to_dict())


def directory_entries(root: Path) -> tuple[str, ...]:
    if not root.exists():
        return ()
    return tuple(
        sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if not path.is_dir()
        )
    )


def corrupt_bytes(path: Path, replacement: bytes = b"tampered\n") -> None:
    os.replace(path, path.with_suffix(path.suffix + ".old"))
    path.write_bytes(replacement)
