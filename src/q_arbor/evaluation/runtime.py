"""Evaluation requests, runtime identity locks, bindings, and artifact storage."""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any, Final, cast

from q_arbor.contracts import QuantResearchContract

from .candidate import CandidateReceipt, _contract_snapshot, _plugin_matches_contract
from .codec import (
    FrozenJSON,
    JSONValue,
    canonical_normalized_bytes,
    decode_json_bytes,
    normalize_mapping,
    read_json_object,
    require_identifier,
    require_literal_path,
    require_media_type,
    require_reason_code,
    require_sha256,
    validate_discriminator,
)
from .errors import (
    EvaluationBoundaryError,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationPersistenceError,
    EvaluationSchemaError,
)
from .values import ArtifactRef, FoldPolicy, PluginIdentity, _ImmutableJSON

_REQUEST_ID_FIELDS: Final = (
    "request_id",
    "run_id",
    "node_id",
    "attempt_id",
    "idempotency_key",
    "capability_grant_id",
    "created_event_id",
)
_CONFIG_KEYS: Final = {"schema_version", "plugin_config", "policy"}
_POLICY_KEYS: Final = {
    "required_check_names",
    "fold_policy",
    "allowed_artifacts",
}
_SECRET_KEY_PARTS: Final = frozenset(
    {
        "apikey",
        "authorization",
        "bearer",
        "clientsecret",
        "credential",
        "credentials",
        "password",
        "passwd",
        "privatekey",
        "secret",
        "token",
    }
)


def _canonicalize_requested_metrics(
    mapping: dict[str, JSONValue],
    contract_mapping: Mapping[str, JSONValue],
) -> None:
    if "requested_metrics" not in mapping:
        return
    requested = mapping["requested_metrics"]
    if not isinstance(requested, list):
        return
    metrics = cast(dict[str, JSONValue], contract_mapping["metrics"])
    primary = cast(dict[str, JSONValue], metrics["primary"])["name"]
    diagnostics = [
        cast(dict[str, JSONValue], item)["name"]
        for item in cast(list[dict[str, JSONValue]], metrics["diagnostics"])
    ]
    order = [primary, *diagnostics]
    requested_set = set(cast(list[str], requested))
    mapping["requested_metrics"] = [name for name in order if name in requested_set]


class EvaluationRequest(_ImmutableJSON):
    """Exact frozen C6 EvaluationRequest bound to a candidate receipt."""

    @property
    def request_id(self) -> str:
        return cast(str, self._get("request_id"))

    @property
    def run_id(self) -> str:
        return cast(str, self._get("run_id"))

    @property
    def node_id(self) -> str:
        return cast(str, self._get("node_id"))

    @property
    def attempt_id(self) -> str:
        return cast(str, self._get("attempt_id"))

    @property
    def idempotency_key(self) -> str:
        return cast(str, self._get("idempotency_key"))

    @property
    def contract_hash(self) -> str:
        return cast(str, self._get("contract_hash"))

    @property
    def candidate(self) -> ArtifactRef:
        return ArtifactRef.from_mapping(cast(Mapping[str, Any], self._get("candidate")))

    @property
    def candidate_hash(self) -> str:
        return cast(str, self._get("candidate_hash"))

    @property
    def validation_receipt(self) -> ArtifactRef:
        return ArtifactRef.from_mapping(
            cast(Mapping[str, Any], self._get("validation_receipt"))
        )

    @property
    def plugin(self) -> PluginIdentity:
        return PluginIdentity.from_mapping(cast(Mapping[str, Any], self._get("plugin")))

    @property
    def split_role(self) -> str:
        return cast(str, self._get("split_role"))

    @property
    def split_manifest_hash(self) -> str:
        return cast(str, self._get("split_manifest_hash"))

    @property
    def capability_grant_id(self) -> str:
        return cast(str, self._get("capability_grant_id"))

    @property
    def requested_metrics(self) -> tuple[str, ...] | None:
        value = self.to_dict().get("requested_metrics")
        if value is None:
            return None
        return tuple(cast(list[str], value))

    @property
    def created_event_id(self) -> str:
        return cast(str, self._get("created_event_id"))


def _validate_request_mapping(
    mapping: Mapping[str, Any],
    *,
    contract: QuantResearchContract,
    candidate_receipt: CandidateReceipt,
    canonicalize: bool,
) -> dict[str, JSONValue]:
    if not isinstance(candidate_receipt, CandidateReceipt):
        raise EvaluationSchemaError("candidate_receipt must be a CandidateReceipt")
    contract_mapping = _contract_snapshot(contract)
    normalized = normalize_mapping(mapping)
    validate_discriminator(normalized, "evaluation_request")
    for field in _REQUEST_ID_FIELDS:
        require_identifier(normalized[field], f"request {field}")
    require_sha256(normalized["contract_hash"], "request contract_hash")
    require_sha256(normalized["candidate_hash"], "request candidate_hash")
    require_sha256(normalized["split_manifest_hash"], "request split manifest")
    candidate = ArtifactRef.from_mapping(cast(dict[str, Any], normalized["candidate"]))
    validation_ref = ArtifactRef.from_mapping(
        cast(dict[str, Any], normalized["validation_receipt"])
    )
    plugin = PluginIdentity.from_mapping(cast(dict[str, Any], normalized["plugin"]))
    if candidate_receipt.contract_hash != contract.sha256:
        raise EvaluationIntegrityError(
            "candidate receipt contract differs from request"
        )
    if candidate_receipt.plugin_identity.to_dict() != contract_mapping["plugin"]:
        raise EvaluationIntegrityError("candidate receipt plugin differs from contract")
    if normalized["contract_hash"] != contract.sha256:
        raise EvaluationIntegrityError("request contract hash differs from contract")
    if candidate != candidate_receipt.candidate.artifact:
        raise EvaluationIntegrityError("request candidate differs from receipt")
    if normalized["candidate_hash"] != candidate_receipt.candidate.candidate_hash:
        raise EvaluationIntegrityError("request candidate hash differs from receipt")
    if validation_ref != candidate_receipt.receipt_ref:
        raise EvaluationIntegrityError("request validation receipt differs")
    if plugin != candidate_receipt.plugin_identity:
        raise EvaluationIntegrityError("request plugin differs from receipt")

    split_role = cast(str, normalized["split_role"])
    split = cast(
        dict[str, JSONValue],
        cast(dict[str, JSONValue], contract_mapping["data"])["splits"],
    )[split_role]
    split_mapping = cast(dict[str, JSONValue], split)
    if normalized["split_manifest_hash"] != split_mapping["manifest_sha256"]:
        raise EvaluationIntegrityError("request split manifest differs from contract")

    requested = normalized.get("requested_metrics")
    if requested is not None:
        if not isinstance(requested, list) or not all(
            isinstance(name, str) for name in requested
        ):
            raise EvaluationSchemaError("requested_metrics must be strings")
        metrics = cast(dict[str, JSONValue], contract_mapping["metrics"])
        allowed = [
            cast(str, cast(dict[str, JSONValue], metrics["primary"])["name"]),
            *[
                cast(str, item["name"])
                for item in cast(list[dict[str, JSONValue]], metrics["diagnostics"])
            ],
        ]
        requested_names = cast(list[str], requested)
        if len(requested_names) != len(set(requested_names)) or not set(
            requested_names
        ) <= set(allowed):
            raise EvaluationInvariantError(
                "requested_metrics must be unique contract metrics"
            )
        if canonicalize:
            _canonicalize_requested_metrics(normalized, contract_mapping)
            requested_names = cast(list[str], normalized["requested_metrics"])
        if requested_names != [name for name in allowed if name in requested_names]:
            raise EvaluationInvariantError("requested_metrics are not canonical")
    return normalized


def freeze_evaluation_request(
    mapping: Mapping[str, Any],
    *,
    contract: QuantResearchContract,
    candidate_receipt: CandidateReceipt,
) -> EvaluationRequest:
    normalized = _validate_request_mapping(
        mapping,
        contract=contract,
        candidate_receipt=candidate_receipt,
        canonicalize=True,
    )
    return EvaluationRequest._from_normalized(normalized)


def validate_evaluation_request(
    mapping: Mapping[str, Any],
    *,
    contract: QuantResearchContract,
    candidate_receipt: CandidateReceipt,
) -> EvaluationRequest:
    normalized = _validate_request_mapping(
        mapping,
        contract=contract,
        candidate_receipt=candidate_receipt,
        canonicalize=False,
    )
    return EvaluationRequest._from_normalized(normalized)


def load_evaluation_request(
    path: str | os.PathLike[str],
    *,
    contract: QuantResearchContract,
    candidate_receipt: CandidateReceipt,
) -> EvaluationRequest:
    return validate_evaluation_request(
        read_json_object(path),
        contract=contract,
        candidate_receipt=candidate_receipt,
    )


def _scan_config_keys(value: JSONValue, path: str = "config") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = "".join(
                character for character in key.lower() if character.isalnum()
            )
            if any(part in normalized for part in _SECRET_KEY_PARTS):
                raise EvaluationBoundaryError(
                    "runtime config contains a secret-like key"
                )
            if any(
                marker in key.lower() for marker in ("path", "uri", "url", "locator")
            ):
                raise EvaluationBoundaryError(
                    "runtime config contains a locator-like key"
                )
            _scan_config_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_config_keys(item, f"{path}[{index}]")


def _validate_runtime_config(
    mapping: Mapping[str, Any],
) -> tuple[dict[str, JSONValue], FoldPolicy]:
    normalized = normalize_mapping(mapping)
    if set(normalized) != _CONFIG_KEYS or normalized["schema_version"] != "1.0":
        raise EvaluationSchemaError("runtime config fields do not match C9")
    plugin_config = normalized["plugin_config"]
    policy = normalized["policy"]
    if not isinstance(plugin_config, dict) or not isinstance(policy, dict):
        raise EvaluationSchemaError("runtime config objects are required")
    _scan_config_keys(cast(JSONValue, plugin_config))
    if set(policy) != _POLICY_KEYS:
        raise EvaluationSchemaError("runtime policy fields do not match C9")
    required_checks = policy["required_check_names"]
    allowed_artifacts = policy["allowed_artifacts"]
    fold_policy_mapping = policy["fold_policy"]
    if not isinstance(required_checks, list) or not all(
        isinstance(name, str) for name in required_checks
    ):
        raise EvaluationSchemaError("required_check_names must be strings")
    for name in cast(list[str], required_checks):
        require_reason_code(name, "required check name")
    if cast(list[str], required_checks) != sorted(
        cast(list[str], required_checks)
    ) or len(required_checks) != len(set(cast(list[str], required_checks))):
        raise EvaluationInvariantError("required check names must be sorted and unique")
    if not required_checks:
        raise EvaluationInvariantError("runtime policy needs required checks")
    if not isinstance(fold_policy_mapping, dict):
        raise EvaluationSchemaError("fold_policy must be an object")
    fold_policy = FoldPolicy.from_mapping(cast(dict[str, Any], fold_policy_mapping))
    if not isinstance(allowed_artifacts, list):
        raise EvaluationSchemaError("allowed_artifacts must be an array")
    pairs: list[tuple[str, str]] = []
    for item in allowed_artifacts:
        if not isinstance(item, dict) or set(item) != {"kind", "media_type"}:
            raise EvaluationSchemaError("allowed artifact entry fields do not match C9")
        kind = require_reason_code(item["kind"], "allowed artifact kind")
        media_type = require_media_type(
            item["media_type"], "allowed artifact media type"
        )
        pairs.append((kind, media_type))
    if pairs != sorted(pairs) or len(pairs) != len(set(pairs)):
        raise EvaluationInvariantError(
            "allowed artifact pairs must be sorted and unique"
        )
    return normalized, fold_policy


class VerifiedRuntimeLock(_ImmutableJSON):
    """Hash-bound evaluator/config snapshot with a live re-verification handle."""

    __slots__ = (*_ImmutableJSON.__slots__, "_config_bytes", "_resolver")

    @classmethod
    def from_artifacts(
        cls,
        evaluator_ref: ArtifactRef,
        config_ref: ArtifactRef,
        *,
        resolver: Any,
    ) -> VerifiedRuntimeLock:
        if not isinstance(evaluator_ref, ArtifactRef) or not isinstance(
            config_ref, ArtifactRef
        ):
            raise EvaluationSchemaError("runtime refs must be ArtifactRef values")
        if evaluator_ref.kind != "q-arbor.evaluator.v1":
            raise EvaluationInvariantError("runtime evaluator kind is invalid")
        if config_ref.kind != "q-arbor.evaluator-config.v1":
            raise EvaluationInvariantError("runtime config kind is invalid")
        for method in ("read_bytes", "verify"):
            if not callable(getattr(resolver, method, None)):
                raise EvaluationSchemaError("resolver does not implement runtime reads")
        try:
            resolver.verify(evaluator_ref)
            config_bytes = resolver.read_bytes(config_ref)
        except Exception as exc:
            raise EvaluationIntegrityError(
                "runtime artifacts failed verification"
            ) from exc
        if not isinstance(config_bytes, bytes):
            raise EvaluationIntegrityError("runtime resolver returned non-bytes")
        if sha256(config_bytes).hexdigest() != config_ref.sha256:
            raise EvaluationIntegrityError("runtime config bytes changed")
        decoded = decode_json_bytes(config_bytes)
        if not isinstance(decoded, dict):
            raise EvaluationSchemaError("runtime config root must be an object")
        config, _ = _validate_runtime_config(decoded)
        if canonical_normalized_bytes(config) != config_bytes:
            raise EvaluationIntegrityError("runtime config bytes are not canonical")
        try:
            resolver.verify(config_ref)
        except Exception as exc:
            raise EvaluationIntegrityError(
                "runtime config changed during verification"
            ) from exc
        normalized: dict[str, JSONValue] = {
            "schema_version": "1.0",
            "evaluator": evaluator_ref.to_dict(),
            "config": config_ref.to_dict(),
            "policy": cast(dict[str, JSONValue], config["policy"]),
        }
        instance = cls._from_normalized(normalized)
        object.__setattr__(instance, "_resolver", resolver)
        object.__setattr__(instance, "_config_bytes", config_bytes)
        return instance

    @property
    def evaluator_ref(self) -> ArtifactRef:
        return ArtifactRef.from_mapping(cast(Mapping[str, Any], self._get("evaluator")))

    @property
    def config_ref(self) -> ArtifactRef:
        return ArtifactRef.from_mapping(cast(Mapping[str, Any], self._get("config")))

    @property
    def policy(self) -> Mapping[str, FrozenJSON]:
        return cast(Mapping[str, FrozenJSON], self._get("policy"))

    @property
    def evaluator_sha256(self) -> str:
        return self.evaluator_ref.sha256

    @property
    def config_sha256(self) -> str:
        return self.config_ref.sha256

    @property
    def fold_policy(self) -> FoldPolicy:
        return FoldPolicy.from_mapping(
            cast(Mapping[str, Any], self.policy["fold_policy"])
        )

    @property
    def required_check_names(self) -> tuple[str, ...]:
        return cast(tuple[str, ...], self.policy["required_check_names"])

    @property
    def allowed_artifacts(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (cast(str, item["kind"]), cast(str, item["media_type"]))
            for item in cast(
                tuple[Mapping[str, FrozenJSON], ...], self.policy["allowed_artifacts"]
            )
        )

    def verify(self) -> None:
        try:
            # The final config identity check is the verification boundary.
            # C5 G02/G05 and C6 J04 require all bytes/policy to be closed first.
            self._resolver.verify(self.evaluator_ref)
            current = self._resolver.read_bytes(self.config_ref)
        except Exception as exc:
            raise EvaluationIntegrityError("runtime artifacts drifted") from exc
        if not isinstance(current, bytes) or current != self._config_bytes:
            raise EvaluationIntegrityError("runtime config bytes drifted")
        decoded = decode_json_bytes(current)
        if not isinstance(decoded, dict):
            raise EvaluationIntegrityError("runtime config is no longer an object")
        try:
            config, _ = _validate_runtime_config(decoded)
        except Exception as exc:
            raise EvaluationIntegrityError("runtime config semantics drifted") from exc
        if cast(dict[str, JSONValue], config["policy"]) != self.to_dict()["policy"]:
            raise EvaluationIntegrityError("runtime policy drifted")
        try:
            self._resolver.verify(self.config_ref)
        except Exception as exc:
            raise EvaluationIntegrityError("runtime config drifted") from exc


class EvaluationBinding:
    """Immutable identity bundle; deliberately carries no authorization."""

    __slots__ = (
        "_artifact_resolver",
        "_candidate_receipt",
        "_contract",
        "_initialized",
        "_plugin_identity",
        "_request",
        "_result_id",
        "_runtime_lock",
        "_seed",
    )

    def __init__(self) -> None:
        raise TypeError("use EvaluationBinding.create")

    @classmethod
    def create(
        cls,
        request: EvaluationRequest,
        contract: QuantResearchContract,
        candidate_receipt: CandidateReceipt,
        plugin_identity: PluginIdentity,
        runtime_lock: VerifiedRuntimeLock,
        *,
        result_id: str,
        seed: int,
        artifact_resolver: Any,
    ) -> EvaluationBinding:
        if not isinstance(request, EvaluationRequest):
            raise EvaluationSchemaError("request must be an EvaluationRequest")
        if not isinstance(runtime_lock, VerifiedRuntimeLock):
            raise EvaluationSchemaError("runtime_lock must be verified")
        _plugin_matches_contract(plugin_identity, contract)
        validate_evaluation_request(
            request.to_dict(),
            contract=contract,
            candidate_receipt=candidate_receipt,
        )
        require_identifier(result_id, "result_id")
        contract_mapping = _contract_snapshot(contract)
        seeds = cast(list[int], contract_mapping["seeds"])
        if isinstance(seed, bool) or not isinstance(seed, int) or seed not in seeds:
            raise EvaluationInvariantError("binding seed is not allowed by contract")
        for method in ("read_bytes", "verify", "verify_issued"):
            if not callable(getattr(artifact_resolver, method, None)):
                raise EvaluationSchemaError(
                    "artifact_resolver does not implement the required protocol"
                )
        runtime_lock.verify()
        instance = cls.__new__(cls)
        object.__setattr__(instance, "_request", request)
        object.__setattr__(instance, "_contract", contract)
        object.__setattr__(instance, "_candidate_receipt", candidate_receipt)
        object.__setattr__(instance, "_plugin_identity", plugin_identity)
        object.__setattr__(instance, "_runtime_lock", runtime_lock)
        object.__setattr__(instance, "_result_id", result_id)
        object.__setattr__(instance, "_seed", seed)
        object.__setattr__(instance, "_artifact_resolver", artifact_resolver)
        object.__setattr__(instance, "_initialized", True)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("EvaluationBinding is immutable")
        object.__setattr__(self, name, value)

    @property
    def request(self) -> EvaluationRequest:
        return self._request

    @property
    def contract(self) -> QuantResearchContract:
        return self._contract

    @property
    def candidate_receipt(self) -> CandidateReceipt:
        return self._candidate_receipt

    @property
    def plugin_identity(self) -> PluginIdentity:
        return self._plugin_identity

    @property
    def runtime_lock(self) -> VerifiedRuntimeLock:
        return self._runtime_lock

    @property
    def result_id(self) -> str:
        return self._result_id

    @property
    def seed(self) -> int:
        return self._seed

    @property
    def artifact_resolver(self) -> Any:
        return self._artifact_resolver


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise EvaluationBoundaryError("platform lacks no-follow store support")
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0)


def _open_or_create_store_root(root: str | os.PathLike[str]) -> int:
    """Walk the absolute root component-by-component without following links."""

    try:
        absolute = Path(root).absolute()
    except (TypeError, ValueError) as exc:
        raise EvaluationPersistenceError(
            "artifact store root is invalid",
            committed=False,
        ) from exc
    components = absolute.parts
    if not components or components[0] != os.sep:
        raise EvaluationBoundaryError("artifact store root must resolve absolutely")
    current_fd = os.open(os.sep, _directory_flags())
    try:
        for index, component in enumerate(components[1:], start=1):
            final = index == len(components) - 1
            try:
                next_fd = os.open(component, _directory_flags(), dir_fd=current_fd)
            except FileNotFoundError as exc:
                if not final:
                    raise EvaluationPersistenceError(
                        "artifact store parent does not exist",
                        committed=False,
                    ) from exc
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                    next_fd = os.open(
                        component,
                        _directory_flags(),
                        dir_fd=current_fd,
                    )
                except OSError as create_exc:
                    raise EvaluationPersistenceError(
                        "unable to create artifact store",
                        committed=False,
                    ) from create_exc
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise EvaluationBoundaryError(
                        "artifact store path traverses a symlink"
                    ) from exc
                raise EvaluationPersistenceError(
                    "unable to open artifact store",
                    committed=False,
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        try:
            os.close(current_fd)
        except OSError:
            pass
        raise


def _open_beneath(root_fd: int, relative_path: str) -> int:
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise EvaluationBoundaryError("platform lacks no-follow artifact reads")
    current_fd = os.dup(root_fd)
    try:
        components = relative_path.split("/")
        for component in components[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0),
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        result = os.open(
            components[-1],
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=current_fd,
        )
        os.close(current_fd)
        return result
    except OSError as exc:
        try:
            os.close(current_fd)
        except OSError:
            pass
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise EvaluationBoundaryError("artifact path traverses a symlink") from exc
        raise EvaluationPersistenceError(
            "unable to open artifact",
            committed=False,
        ) from exc


def _read_regular_fd(fd: int) -> bytes:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise EvaluationBoundaryError("artifact must be one singly-linked regular file")
    chunks: list[bytes] = []
    try:
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(fd)
    except OSError as exc:
        raise EvaluationPersistenceError(
            "unable to read artifact",
            committed=False,
        ) from exc
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if identity(before) != identity(after):
        raise EvaluationBoundaryError("artifact changed while it was read")
    return b"".join(chunks)


class ContentAddressedArtifactStore:
    """Symlink-safe create-only artifact sink and resolver."""

    __slots__ = ("_initialized", "_root_fd")

    def __init__(self) -> None:
        raise TypeError("use ContentAddressedArtifactStore.create")

    @classmethod
    def create(cls, root: str | os.PathLike[str]) -> ContentAddressedArtifactStore:
        root_fd = _open_or_create_store_root(root)
        try:
            root_stat = os.fstat(root_fd)
            if not stat.S_ISDIR(root_stat.st_mode):
                raise EvaluationBoundaryError("artifact store root is not a directory")
        except Exception:
            os.close(root_fd)
            raise
        instance = cls.__new__(cls)
        object.__setattr__(instance, "_root_fd", root_fd)
        object.__setattr__(instance, "_initialized", True)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("ContentAddressedArtifactStore is immutable")
        object.__setattr__(self, name, value)

    def read_bytes(self, ref: ArtifactRef) -> bytes:
        if not isinstance(ref, ArtifactRef):
            raise EvaluationSchemaError("artifact resolver requires ArtifactRef")
        require_literal_path(ref.relative_path, "artifact relative_path")
        root_fd = os.dup(self._root_fd)
        try:
            artifact_fd = _open_beneath(root_fd, ref.relative_path)
            try:
                content = _read_regular_fd(artifact_fd)
            finally:
                os.close(artifact_fd)
        finally:
            os.close(root_fd)
        if sha256(content).hexdigest() != ref.sha256:
            raise EvaluationIntegrityError("artifact digest does not match its ref")
        return content

    def verify(self, ref: ArtifactRef) -> None:
        self.read_bytes(ref)

    def scope(
        self,
        *,
        request_id: str,
        produced_by_event_id: str,
        runtime_lock: VerifiedRuntimeLock,
    ) -> _ScopedArtifactSink:
        require_identifier(request_id, "artifact scope request_id")
        require_identifier(produced_by_event_id, "artifact scope event_id")
        if not isinstance(runtime_lock, VerifiedRuntimeLock):
            raise EvaluationSchemaError("artifact scope needs a runtime lock")
        runtime_lock.verify()
        request_digest = sha256(request_id.encode("utf-8")).hexdigest()
        relative_directory = f"artifacts/evaluations/{request_digest}"
        directory_fd = _ensure_beneath_directory(
            self._root_fd,
            relative_directory,
        )

        record: dict[str, JSONValue] = {
            "schema_version": "1.0",
            "request_id": request_id,
            "runtime_lock_sha256": runtime_lock.sha256,
            "config_sha256": runtime_lock.config_sha256,
            "allowed_artifacts": [
                {"kind": kind, "media_type": media_type}
                for kind, media_type in runtime_lock.allowed_artifacts
            ],
        }
        expected = canonical_normalized_bytes(record)
        try:
            _create_or_verify_immutable_file_at(
                directory_fd,
                ".scope.json",
                expected,
            )
            issued_fd = _ensure_beneath_directory(directory_fd, ".issued")
            os.close(issued_fd)
        finally:
            os.close(directory_fd)
        return _ScopedArtifactSink(
            store=self,
            request_id=request_id,
            produced_by_event_id=produced_by_event_id,
            runtime_lock=runtime_lock,
            relative_directory=relative_directory,
        )

    def verify_issued(
        self,
        ref: ArtifactRef,
        *,
        request_id: str,
        runtime_lock_sha256: str,
    ) -> None:
        require_identifier(request_id, "issued artifact request_id")
        require_sha256(runtime_lock_sha256, "issued artifact runtime lock hash")
        if not isinstance(ref, ArtifactRef):
            raise EvaluationSchemaError("issued artifact must be an ArtifactRef")
        request_digest = sha256(request_id.encode("utf-8")).hexdigest()
        prefix = f"artifacts/evaluations/{request_digest}/"
        if not ref.relative_path.startswith(prefix):
            raise EvaluationIntegrityError("artifact request namespace differs")
        directory_fd = _open_beneath_directory(self._root_fd, prefix.rstrip("/"))
        try:
            scope_mapping = _read_json_object_at(directory_fd, ".scope.json")
            issued_fd = _open_beneath_directory(directory_fd, ".issued")
            try:
                record_name = (
                    sha256(ref.artifact_id.encode("utf-8")).hexdigest() + ".json"
                )
                record = _read_json_object_at(issued_fd, record_name)
            finally:
                os.close(issued_fd)
        finally:
            os.close(directory_fd)
        if scope_mapping.get("request_id") != request_id:
            raise EvaluationIntegrityError("artifact scope request identity differs")
        if scope_mapping.get("runtime_lock_sha256") != runtime_lock_sha256:
            raise EvaluationIntegrityError("artifact scope runtime lock differs")
        try:
            allowed = {
                (item["kind"], item["media_type"])
                for item in cast(
                    list[dict[str, Any]], scope_mapping["allowed_artifacts"]
                )
            }
        except (KeyError, TypeError) as exc:
            raise EvaluationIntegrityError(
                "artifact scope record is malformed"
            ) from exc
        if (ref.kind, ref.media_type) not in allowed:
            raise EvaluationBoundaryError("artifact kind/media pair is not allowed")
        if record != ref.to_dict():
            raise EvaluationIntegrityError("artifact issuance record differs from ref")
        self.verify(ref)

    def __del__(self) -> None:
        root_fd = getattr(self, "_root_fd", None)
        if isinstance(root_fd, int):
            try:
                os.close(root_fd)
            except OSError:
                pass


def _open_beneath_directory(root_fd: int, relative_path: str) -> int:
    current_fd = os.dup(root_fd)
    try:
        for component in relative_path.split("/"):
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0),
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError as exc:
        try:
            os.close(current_fd)
        except OSError:
            pass
        raise EvaluationBoundaryError("artifact directory traversal is unsafe") from exc


def _ensure_beneath_directory(root_fd: int, relative_path: str) -> int:
    """Create missing directories from one held root descriptor."""

    current_fd = os.dup(root_fd)
    try:
        for component in relative_path.split("/"):
            try:
                next_fd = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=current_fd,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                    next_fd = os.open(
                        component,
                        _directory_flags(),
                        dir_fd=current_fd,
                    )
                except OSError as exc:
                    raise EvaluationPersistenceError(
                        "unable to create artifact directory",
                        committed=False,
                    ) from exc
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise EvaluationBoundaryError(
                        "artifact directory traverses a symlink"
                    ) from exc
                raise EvaluationPersistenceError(
                    "unable to open artifact directory",
                    committed=False,
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        try:
            os.close(current_fd)
        except OSError:
            pass
        raise


def _read_json_object_at(directory_fd: int, name: str) -> dict[str, Any]:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise EvaluationBoundaryError("store record is a symlink") from exc
        raise EvaluationPersistenceError(
            "unable to open store record",
            committed=False,
        ) from exc
    try:
        decoded = decode_json_bytes(_read_regular_fd(fd))
    finally:
        os.close(fd)
    if not isinstance(decoded, dict):
        raise EvaluationIntegrityError("store record root is not an object")
    return decoded


def _create_or_verify_immutable_file_at(
    directory_fd: int,
    name: str,
    content: bytes,
    *,
    allow_existing: bool = True,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except FileExistsError:
        if not allow_existing:
            raise EvaluationBoundaryError("artifact issuance record already exists")
        try:
            existing_fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                existing = _read_regular_fd(existing_fd)
            finally:
                os.close(existing_fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise EvaluationBoundaryError(
                    "immutable store record is a symlink"
                ) from exc
            raise EvaluationPersistenceError(
                "unable to read immutable store record",
                committed=False,
            ) from exc
        if existing != content:
            raise EvaluationIntegrityError("immutable store record conflicts")
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            raise EvaluationPersistenceError(
                "immutable store record directory sync failed",
                committed=True,
            ) from exc
        return
    except OSError as exc:
        raise EvaluationPersistenceError(
            "unable to create immutable store record",
            committed=False,
        ) from exc
    try:
        offset = 0
        while offset < len(content):
            written = os.write(fd, content[offset:])
            if written <= 0:
                raise OSError("short immutable-record write")
            offset += written
        os.fsync(fd)
    except OSError as exc:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except OSError:
            pass
        raise EvaluationPersistenceError(
            "unable to persist immutable store record",
            committed=False,
        ) from exc
    finally:
        os.close(fd)
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        raise EvaluationPersistenceError(
            "immutable store record directory sync failed",
            committed=True,
        ) from exc


def _create_exclusive_file_at(
    directory_fd: int,
    name: str,
    content: bytes,
    *,
    recover_existing: bool = False,
) -> bool:
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
    except FileExistsError:
        if not recover_existing:
            raise EvaluationBoundaryError("pre-existing artifact content is not issued")
        try:
            existing_fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                existing = _read_regular_fd(existing_fd)
            finally:
                os.close(existing_fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise EvaluationBoundaryError("existing artifact is a symlink") from exc
            raise EvaluationPersistenceError(
                "unable to recover existing evaluation artifact",
                committed=False,
            ) from exc
        if existing != content:
            raise EvaluationIntegrityError("existing artifact content conflicts")
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            raise EvaluationPersistenceError(
                "recovered artifact directory sync failed",
                committed=True,
            ) from exc
        return False
    except OSError as exc:
        raise EvaluationPersistenceError(
            "unable to create evaluation artifact",
            committed=False,
        ) from exc
    try:
        offset = 0
        while offset < len(content):
            written = os.write(fd, content[offset:])
            if written <= 0:
                raise OSError("short evaluation-artifact write")
            offset += written
        os.fsync(fd)
    except OSError as exc:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except OSError:
            pass
        raise EvaluationPersistenceError(
            "unable to persist evaluation artifact",
            committed=False,
        ) from exc
    finally:
        os.close(fd)
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        raise EvaluationPersistenceError(
            "evaluation artifact directory sync failed",
            committed=True,
        ) from exc
    return True


def _record_exists_at(directory_fd: int, name: str) -> bool:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    except FileNotFoundError:
        return False
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise EvaluationBoundaryError("issuance record is a symlink") from exc
        raise EvaluationPersistenceError(
            "unable to inspect issuance record",
            committed=False,
        ) from exc
    try:
        result = os.fstat(fd)
        if not stat.S_ISREG(result.st_mode) or result.st_nlink != 1:
            raise EvaluationBoundaryError("issuance record is not a regular file")
    finally:
        os.close(fd)
    return True


class _ScopedArtifactSink:
    __slots__ = (
        "_initialized",
        "_issued_refs",
        "_pending_states",
        "_produced_by_event_id",
        "_relative_directory",
        "_request_id",
        "_runtime_lock",
        "_store",
    )

    def __init__(
        self,
        *,
        store: ContentAddressedArtifactStore,
        request_id: str,
        produced_by_event_id: str,
        runtime_lock: VerifiedRuntimeLock,
        relative_directory: str,
    ) -> None:
        object.__setattr__(self, "_store", store)
        object.__setattr__(self, "_request_id", request_id)
        object.__setattr__(self, "_produced_by_event_id", produced_by_event_id)
        object.__setattr__(self, "_runtime_lock", runtime_lock)
        object.__setattr__(self, "_relative_directory", relative_directory)
        object.__setattr__(self, "_issued_refs", [])
        object.__setattr__(self, "_pending_states", {})
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("ArtifactSink is immutable")
        object.__setattr__(self, name, value)

    @property
    def issued_refs(self) -> tuple[ArtifactRef, ...]:
        return tuple(self._issued_refs)

    def put(self, *, kind: str, media_type: str, content: bytes) -> ArtifactRef:
        require_reason_code(kind, "artifact kind")
        require_media_type(media_type, "artifact media_type")
        if not isinstance(content, bytes):
            raise EvaluationSchemaError("artifact content must be immutable bytes")
        if (kind, media_type) not in set(self._runtime_lock.allowed_artifacts):
            raise EvaluationBoundaryError("artifact kind/media pair is not allowed")
        self._runtime_lock.verify()
        digest = sha256(content).hexdigest()
        identity_digest = sha256(
            canonical_normalized_bytes(
                {"kind": kind, "media_type": media_type, "sha256": digest}
            )
        ).hexdigest()
        artifact_id = f"artifact.{identity_digest}"
        relative_path = f"{self._relative_directory}/{identity_digest}"
        ref = ArtifactRef.from_mapping(
            {
                "artifact_id": artifact_id,
                "kind": kind,
                "relative_path": relative_path,
                "sha256": digest,
                "media_type": media_type,
                "produced_by_event_id": self._produced_by_event_id,
            }
        )
        directory_fd = _open_beneath_directory(
            self._store._root_fd,
            self._relative_directory,
        )
        try:
            issued_fd = _open_beneath_directory(directory_fd, ".issued")
            try:
                record_name = sha256(artifact_id.encode("utf-8")).hexdigest() + ".json"
                pending_state = self._pending_states.get(identity_digest)
                record_exists = _record_exists_at(issued_fd, record_name)
                if record_exists:
                    if pending_state != "issued":
                        raise EvaluationBoundaryError("artifact ID/path already issued")
                    record = _read_json_object_at(issued_fd, record_name)
                    if record != ref.to_dict():
                        raise EvaluationIntegrityError(
                            "pending issuance record differs from artifact"
                        )
                    _create_exclusive_file_at(
                        directory_fd,
                        identity_digest,
                        content,
                        recover_existing=True,
                    )
                else:
                    if pending_state == "issued":
                        raise EvaluationIntegrityError(
                            "committed issuance record disappeared"
                        )
                    try:
                        _create_exclusive_file_at(
                            directory_fd,
                            identity_digest,
                            content,
                            recover_existing=pending_state == "content",
                        )
                    except EvaluationPersistenceError as exc:
                        if exc.committed:
                            self._pending_states[identity_digest] = "content"
                        raise
                    try:
                        _create_or_verify_immutable_file_at(
                            issued_fd,
                            record_name,
                            canonical_normalized_bytes(ref.to_dict()),
                            allow_existing=False,
                        )
                    except EvaluationPersistenceError as exc:
                        self._pending_states[identity_digest] = (
                            "issued" if exc.committed else "content"
                        )
                        raise
            finally:
                os.close(issued_fd)
        finally:
            os.close(directory_fd)
        self._pending_states.pop(identity_digest, None)
        self._issued_refs.append(ref)
        return ref
