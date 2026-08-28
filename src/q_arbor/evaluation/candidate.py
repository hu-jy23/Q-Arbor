"""Candidate materialization, validation receipts, and immutable bindings."""

from __future__ import annotations

import errno
import fnmatch
import os
import stat
from collections.abc import Iterable, Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from typing import Any, Final, Self, cast

from q_arbor.contracts import QuantResearchContract, validate_contract

from .codec import (
    FrozenJSON,
    JSONValue,
    canonical_normalized_bytes,
    normalize_json,
    normalize_mapping,
    read_json_object,
    require_git_commit,
    require_literal_path,
    require_reason_code,
    require_sha256,
)
from .errors import (
    EvaluationBoundaryError,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationPersistenceError,
    EvaluationSchemaError,
)
from .values import (
    ArtifactRef,
    CheckResult,
    EvaluationFailure,
    FamilyEvidence,
    PluginIdentity,
    ReasonCode,
    _ImmutableJSON,
)

_VALIDATION_KEYS: Final = {
    "schema_version",
    "status",
    "contract_hash",
    "plugin",
    "candidate",
    "candidate_hash",
    "canonical_form_sha256",
    "family_evidence",
    "changed_paths",
    "checks",
    "failure",
}
_VALIDATION_STATUSES: Final = {
    "valid",
    "invalid_candidate",
    "implementation_failure",
}
_OPEN_SUPPORTS_DIR_FD: Final = os.open in os.supports_dir_fd


def _contract_snapshot(contract: QuantResearchContract) -> dict[str, JSONValue]:
    if not isinstance(contract, QuantResearchContract):
        raise EvaluationSchemaError("contract must be a QuantResearchContract")
    try:
        validated = validate_contract(contract.to_dict())
    except Exception as exc:
        raise EvaluationIntegrityError("contract snapshot cannot be trusted") from exc
    if validated.sha256 != contract.sha256 or validated.to_json() != contract.to_json():
        raise EvaluationIntegrityError("contract snapshot identity changed")
    return cast(dict[str, JSONValue], validated.to_dict())


def _plugin_matches_contract(
    plugin_identity: PluginIdentity,
    contract: QuantResearchContract,
) -> dict[str, JSONValue]:
    if not isinstance(plugin_identity, PluginIdentity):
        raise EvaluationSchemaError("plugin_identity must be a PluginIdentity")
    contract_mapping = _contract_snapshot(contract)
    if plugin_identity.to_dict() != contract_mapping["plugin"]:
        raise EvaluationIntegrityError("live plugin identity differs from contract")
    return contract_mapping


def _safe_literal_path(value: Any, field: str) -> str:
    try:
        return require_literal_path(value, field)
    except (EvaluationSchemaError, EvaluationInvariantError) as exc:
        raise EvaluationBoundaryError(
            f"{field} escapes the materialization root"
        ) from exc


def _identity_tuple(result: os.stat_result) -> tuple[int, ...]:
    return (
        result.st_dev,
        result.st_ino,
        result.st_mode,
        result.st_nlink,
        result.st_size,
        result.st_mtime_ns,
        result.st_ctime_ns,
    )


def _readonly_nofollow_flags(*, directory: bool = False) -> int:
    """Return the fail-fast flags required for an anchored read."""

    required = ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")
    if not _OPEN_SUPPORTS_DIR_FD or any(not hasattr(os, name) for name in required):
        raise EvaluationBoundaryError("platform lacks fail-fast file primitives")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    if directory:
        if not hasattr(os, "O_DIRECTORY"):
            raise EvaluationBoundaryError("platform lacks directory-open protection")
        flags |= os.O_DIRECTORY
    return flags


def _open_regular_beneath(root_fd: int, relative_path: str) -> int:
    directory_flags = _readonly_nofollow_flags(directory=True)
    final_flags = _readonly_nofollow_flags()
    current_fd = os.dup(root_fd)
    try:
        components = relative_path.split("/")
        for component in components[:-1]:
            next_fd = os.open(
                component,
                directory_flags,
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        final_fd = os.open(
            components[-1],
            final_flags,
            dir_fd=current_fd,
        )
        os.close(current_fd)
        return final_fd
    except OSError as exc:
        try:
            os.close(current_fd)
        except OSError:
            pass
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise EvaluationBoundaryError(
                "materialized entry traverses a symlink or non-directory"
            ) from exc
        raise EvaluationPersistenceError(
            "unable to open materialized entry",
            committed=False,
        ) from exc


class MaterializationReceipt(_ImmutableJSON):
    """Relocation-stable inventory hashed from no-follow file descriptors."""

    @classmethod
    def scan(
        cls,
        root: str | os.PathLike[str],
        relative_paths: Iterable[str],
    ) -> MaterializationReceipt:
        if isinstance(relative_paths, (str, bytes, bytearray)):
            raise EvaluationSchemaError("materialization paths must be an iterable")
        try:
            supplied_paths = list(relative_paths)
        except TypeError as exc:
            raise EvaluationSchemaError(
                "materialization paths must be an iterable"
            ) from exc
        normalized_paths = normalize_json(supplied_paths)
        if not isinstance(normalized_paths, list) or not all(
            isinstance(path, str) for path in normalized_paths
        ):
            raise EvaluationSchemaError("materialization paths must be strings")
        paths = cast(list[str], normalized_paths)
        if len(paths) != len(set(paths)):
            raise EvaluationInvariantError("materialization paths must be unique")
        paths.sort()
        safe_paths = [
            _safe_literal_path(path, "materialization path") for path in paths
        ]

        root_path = Path(root)
        try:
            root_fd = os.open(root_path, _readonly_nofollow_flags(directory=True))
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise EvaluationBoundaryError(
                    "materialization root must be a real directory"
                ) from exc
            raise EvaluationPersistenceError(
                "unable to open materialization root",
                committed=False,
            ) from exc

        entries: list[JSONValue] = []
        try:
            root_stat = os.fstat(root_fd)
            if not stat.S_ISDIR(root_stat.st_mode):
                raise EvaluationBoundaryError("materialization root is not a directory")
            for relative_path in safe_paths:
                entry_fd = _open_regular_beneath(root_fd, relative_path)
                try:
                    before = os.fstat(entry_fd)
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                        raise EvaluationBoundaryError(
                            "materialized entry must be one singly-linked regular file"
                        )
                    digest = sha256()
                    while chunk := os.read(entry_fd, 1024 * 1024):
                        digest.update(chunk)
                    after = os.fstat(entry_fd)
                    if _identity_tuple(before) != _identity_tuple(after):
                        raise EvaluationBoundaryError(
                            "materialized entry changed while it was hashed"
                        )
                    entries.append(
                        {
                            "path": relative_path,
                            "kind": "regular_file",
                            "sha256": digest.hexdigest(),
                        }
                    )
                except OSError as exc:
                    raise EvaluationPersistenceError(
                        "unable to read materialized entry",
                        committed=False,
                    ) from exc
                finally:
                    try:
                        os.close(entry_fd)
                    except OSError:
                        pass
        finally:
            try:
                os.close(root_fd)
            except OSError:
                pass

        normalized = cast(
            dict[str, JSONValue],
            {
                "schema_version": "1.0",
                "symlink_policy": "deny",
                "entries": entries,
            },
        )
        return cls._from_normalized(normalized)

    @property
    def schema_version(self) -> str:
        return cast(str, self._get("schema_version"))

    @property
    def symlink_policy(self) -> str:
        return cast(str, self._get("symlink_policy"))

    @property
    def entries(self) -> tuple[Mapping[str, FrozenJSON], ...]:
        return cast(tuple[Mapping[str, FrozenJSON], ...], self._get("entries"))


class CandidateArtifact:
    """Host-observed immutable candidate bytes and repository identity."""

    __slots__ = (
        "_artifact",
        "_candidate_hash",
        "_changed_paths",
        "_code_commit",
        "_initialized",
        "_materialization",
        "_payload",
    )

    def __init__(self) -> None:
        raise TypeError("use CandidateArtifact.from_bytes")

    @classmethod
    def from_bytes(
        cls,
        artifact: ArtifactRef,
        payload: bytes,
        *,
        code_commit: str,
        changed_paths: Sequence[str],
        materialization: MaterializationReceipt,
    ) -> CandidateArtifact:
        if not isinstance(artifact, ArtifactRef):
            raise EvaluationSchemaError("candidate artifact must be an ArtifactRef")
        if not isinstance(payload, bytes):
            raise EvaluationSchemaError("candidate payload must be immutable bytes")
        if not isinstance(materialization, MaterializationReceipt):
            raise EvaluationSchemaError(
                "candidate materialization must be a MaterializationReceipt"
            )
        require_git_commit(code_commit, "candidate code_commit")
        if sha256(payload).hexdigest() != artifact.sha256:
            raise EvaluationIntegrityError("candidate payload digest does not match")

        normalized_paths = normalize_json(changed_paths)
        if not isinstance(normalized_paths, list) or not all(
            isinstance(path, str) for path in normalized_paths
        ):
            raise EvaluationSchemaError("changed_paths must be an array of strings")
        paths = cast(list[str], normalized_paths)
        for path in paths:
            require_literal_path(path, "candidate changed path")
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise EvaluationInvariantError(
                "candidate changed_paths must be sorted and unique"
            )

        matching_entries = [
            entry
            for entry in materialization.to_dict()["entries"]
            if entry["path"] == artifact.relative_path
        ]
        if (
            len(matching_entries) != 1
            or matching_entries[0]["sha256"] != artifact.sha256
        ):
            raise EvaluationIntegrityError(
                "candidate artifact is not bound to its materialization receipt"
            )
        manifest: dict[str, JSONValue] = {
            "schema_version": "1.0",
            "artifact_kind": artifact.kind,
            "artifact_sha256": artifact.sha256,
            "code_commit": code_commit,
            "changed_paths": paths,
            "materialization_sha256": materialization.sha256,
        }
        candidate_hash = sha256(canonical_normalized_bytes(manifest)).hexdigest()
        instance = cls.__new__(cls)
        object.__setattr__(instance, "_artifact", artifact)
        object.__setattr__(instance, "_payload", payload)
        object.__setattr__(instance, "_code_commit", code_commit)
        object.__setattr__(instance, "_changed_paths", tuple(paths))
        object.__setattr__(instance, "_materialization", materialization)
        object.__setattr__(instance, "_candidate_hash", candidate_hash)
        object.__setattr__(instance, "_initialized", True)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("CandidateArtifact is immutable")
        object.__setattr__(self, name, value)

    @property
    def artifact(self) -> ArtifactRef:
        return self._artifact

    @property
    def payload(self) -> bytes:
        return self._payload

    @property
    def code_commit(self) -> str:
        return self._code_commit

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return self._changed_paths

    @property
    def materialization(self) -> MaterializationReceipt:
        return self._materialization

    @property
    def candidate_hash(self) -> str:
        return self._candidate_hash

    def __copy__(self) -> CandidateArtifact:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> CandidateArtifact:
        memo[id(self)] = self
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CandidateArtifact):
            return NotImplemented
        return self.candidate_hash == other.candidate_hash

    def __hash__(self) -> int:
        return hash(self.candidate_hash)


def _classify_candidate_surface_mapping(
    candidate: CandidateArtifact,
    contract_mapping: Mapping[str, JSONValue],
) -> ReasonCode | None:
    editable = cast(list[str], contract_mapping["editable_surface"])
    protected = cast(list[str], contract_mapping["protected_paths"])
    for path in candidate.changed_paths:
        if any(fnmatch.fnmatch(path, pattern) for pattern in protected):
            return ReasonCode.parse("candidate.surface.protected")
        if not any(fnmatch.fnmatch(path, pattern) for pattern in editable):
            return ReasonCode.parse("candidate.surface.outside_editable")
    materialized = {
        cast(str, entry["path"])
        for entry in cast(
            list[dict[str, JSONValue]], candidate.materialization.to_dict()["entries"]
        )
    }
    if not set(cast(list[str], contract_mapping["required_outputs"])) <= materialized:
        return ReasonCode.parse("candidate.surface.missing_output")
    return None


def _classify_candidate_surface(
    candidate: CandidateArtifact,
    contract: QuantResearchContract,
) -> ReasonCode | None:
    """Return a bounded pre-split surface failure for trusted plugin adapters."""

    if not isinstance(candidate, CandidateArtifact):
        raise EvaluationSchemaError("candidate must be a CandidateArtifact")
    return _classify_candidate_surface_mapping(candidate, _contract_snapshot(contract))


def _validate_candidate_surface(
    candidate: CandidateArtifact,
    contract_mapping: Mapping[str, JSONValue],
) -> None:
    objective = cast(dict[str, JSONValue], contract_mapping["objective"])
    plugin = cast(dict[str, JSONValue], contract_mapping["plugin"])
    if not (
        candidate.artifact.kind
        == objective["candidate_artifact_type"]
        == plugin["artifact_type"]
    ):
        raise EvaluationInvariantError("candidate artifact kind differs from contract")
    failure = _classify_candidate_surface_mapping(candidate, contract_mapping)
    if failure is not None:
        raise EvaluationInvariantError(f"candidate surface failed: {failure}")


class CandidateValidation(_ImmutableJSON):
    """Canonical validation receipt content, excluding its own ArtifactRef."""

    @property
    def schema_version(self) -> str:
        return cast(str, self._get("schema_version"))

    @property
    def status(self) -> str:
        return cast(str, self._get("status"))

    @property
    def contract_hash(self) -> str:
        return cast(str, self._get("contract_hash"))

    @property
    def plugin(self) -> PluginIdentity:
        return PluginIdentity.from_mapping(cast(Mapping[str, Any], self._get("plugin")))

    @property
    def candidate(self) -> ArtifactRef:
        return ArtifactRef.from_mapping(cast(Mapping[str, Any], self._get("candidate")))

    @property
    def candidate_hash(self) -> str:
        return cast(str, self._get("candidate_hash"))

    @property
    def canonical_form_sha256(self) -> str | None:
        return cast(str | None, self._get("canonical_form_sha256"))

    @property
    def family_evidence(self) -> FamilyEvidence:
        return FamilyEvidence.from_mapping(
            cast(Mapping[str, Any], self._get("family_evidence"))
        )

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return cast(tuple[str, ...], self._get("changed_paths"))

    @property
    def checks(self) -> tuple[CheckResult, ...]:
        return tuple(
            CheckResult.from_mapping(cast(Mapping[str, Any], item))
            for item in cast(tuple[Mapping[str, FrozenJSON], ...], self._get("checks"))
        )

    @property
    def failure(self) -> EvaluationFailure | None:
        value = self._get("failure")
        if value is None:
            return None
        return EvaluationFailure.from_mapping(cast(Mapping[str, Any], value))


def _canonicalize_candidate_validation(mapping: dict[str, JSONValue]) -> None:
    checks = mapping.get("checks")
    if isinstance(checks, list) and all(isinstance(item, dict) for item in checks):
        checks.sort(
            key=lambda item: cast(str, cast(dict[str, JSONValue], item).get("name", ""))
        )


def _validate_candidate_validation_mapping(
    mapping: Mapping[str, Any],
    *,
    candidate: CandidateArtifact,
    contract: QuantResearchContract,
    plugin_identity: PluginIdentity,
    canonicalize: bool,
) -> dict[str, JSONValue]:
    if not isinstance(candidate, CandidateArtifact):
        raise EvaluationSchemaError("candidate must be a CandidateArtifact")
    contract_mapping = _plugin_matches_contract(plugin_identity, contract)
    normalized = normalize_mapping(mapping)
    if set(normalized) != _VALIDATION_KEYS:
        raise EvaluationSchemaError("CandidateValidation fields do not match the interface schema")
    if normalized["schema_version"] != "1.0":
        raise EvaluationSchemaError("CandidateValidation schema_version is invalid")
    if normalized["status"] not in _VALIDATION_STATUSES:
        raise EvaluationSchemaError("CandidateValidation status is invalid")
    require_sha256(normalized["contract_hash"], "validation contract_hash")
    require_sha256(normalized["candidate_hash"], "validation candidate_hash")
    canonical_form = normalized["canonical_form_sha256"]
    if canonical_form is not None:
        require_sha256(canonical_form, "validation canonical_form_sha256")
    if not isinstance(normalized["plugin"], dict):
        raise EvaluationSchemaError("validation plugin must be an object")
    plugin = PluginIdentity.from_mapping(cast(dict[str, Any], normalized["plugin"]))
    if not isinstance(normalized["candidate"], dict):
        raise EvaluationSchemaError("validation candidate must be an object")
    artifact = ArtifactRef.from_mapping(cast(dict[str, Any], normalized["candidate"]))
    if not isinstance(normalized["family_evidence"], dict):
        raise EvaluationSchemaError("validation family_evidence must be an object")
    FamilyEvidence.from_mapping(cast(dict[str, Any], normalized["family_evidence"]))

    changed_paths = normalized["changed_paths"]
    checks = normalized["checks"]
    if not isinstance(changed_paths, list) or not all(
        isinstance(path, str) for path in changed_paths
    ):
        raise EvaluationSchemaError("validation changed_paths must be strings")
    for path in cast(list[str], changed_paths):
        require_literal_path(path, "validation changed path")
    if cast(list[str], changed_paths) != sorted(cast(list[str], changed_paths)) or len(
        changed_paths
    ) != len(set(cast(list[str], changed_paths))):
        raise EvaluationInvariantError(
            "validation changed_paths must be sorted and unique"
        )
    if not isinstance(checks, list) or not checks:
        raise EvaluationSchemaError("validation checks must be a non-empty array")
    for item in checks:
        if not isinstance(item, dict):
            raise EvaluationSchemaError("validation checks must be objects")
        check = CheckResult.from_mapping(cast(dict[str, Any], item))
        require_reason_code(check.name, "validation check name")
    if canonicalize:
        _canonicalize_candidate_validation(normalized)
        checks = cast(list[JSONValue], normalized["checks"])
    names = [cast(str, cast(dict[str, JSONValue], item)["name"]) for item in checks]
    if names != sorted(names) or len(names) != len(set(names)):
        raise EvaluationInvariantError("validation checks must be sorted and unique")

    failure_value = normalized["failure"]
    failure = None
    if failure_value is not None:
        if not isinstance(failure_value, dict):
            raise EvaluationSchemaError("validation failure must be an object or null")
        failure = EvaluationFailure.from_mapping(cast(dict[str, Any], failure_value))

    if normalized["contract_hash"] != contract.sha256:
        raise EvaluationIntegrityError("validation contract hash differs from contract")
    if plugin != plugin_identity:
        raise EvaluationIntegrityError(
            "validation plugin identity differs from live plugin"
        )
    if artifact != candidate.artifact:
        raise EvaluationIntegrityError(
            "validation candidate artifact differs from input"
        )
    if normalized["candidate_hash"] != candidate.candidate_hash:
        raise EvaluationIntegrityError("validation candidate hash differs from input")
    if tuple(cast(list[str], changed_paths)) != candidate.changed_paths:
        raise EvaluationIntegrityError("validation changed_paths differ from candidate")

    status = cast(str, normalized["status"])
    check_values = [
        CheckResult.from_mapping(cast(dict[str, Any], item)) for item in checks
    ]
    if status == "valid":
        _validate_candidate_surface(candidate, contract_mapping)
        if candidate.artifact.kind != plugin_identity.artifact_type:
            raise EvaluationInvariantError("candidate kind differs from live plugin")
        if canonical_form is None or any(
            check.status != "pass" for check in check_values
        ):
            raise EvaluationInvariantError(
                "valid candidate requires canonical passing checks"
            )
        if failure is not None:
            raise EvaluationInvariantError("valid candidate cannot contain a failure")
    elif status == "invalid_candidate":
        if not any(check.status == "fail" for check in check_values):
            raise EvaluationInvariantError("invalid candidate requires a failed check")
        if failure is None or failure.failure_type != "invalid_candidate":
            raise EvaluationInvariantError(
                "invalid candidate failure type is inconsistent"
            )
    elif failure is None or failure.failure_type != "implementation_failure":
        raise EvaluationInvariantError(
            "validation implementation failure type is inconsistent"
        )
    return normalized


def freeze_candidate_validation(
    mapping: Mapping[str, Any],
    *,
    candidate: CandidateArtifact,
    contract: QuantResearchContract,
    plugin_identity: PluginIdentity,
) -> CandidateValidation:
    normalized = _validate_candidate_validation_mapping(
        mapping,
        candidate=candidate,
        contract=contract,
        plugin_identity=plugin_identity,
        canonicalize=True,
    )
    return CandidateValidation._from_normalized(normalized)


def validate_candidate_validation(
    mapping: Mapping[str, Any],
    *,
    candidate: CandidateArtifact,
    contract: QuantResearchContract,
    plugin_identity: PluginIdentity,
) -> CandidateValidation:
    normalized = _validate_candidate_validation_mapping(
        mapping,
        candidate=candidate,
        contract=contract,
        plugin_identity=plugin_identity,
        canonicalize=False,
    )
    return CandidateValidation._from_normalized(normalized)


def load_candidate_validation(
    path: str | os.PathLike[str],
    *,
    candidate: CandidateArtifact,
    contract: QuantResearchContract,
    plugin_identity: PluginIdentity,
) -> CandidateValidation:
    return validate_candidate_validation(
        read_json_object(path),
        candidate=candidate,
        contract=contract,
        plugin_identity=plugin_identity,
    )


class CandidateReceipt:
    """Runtime binding between candidate bytes and a persisted validation."""

    __slots__ = (
        "_candidate",
        "_contract_hash",
        "_initialized",
        "_plugin_identity",
        "_receipt_ref",
        "_validation",
    )

    def __init__(self) -> None:
        raise TypeError("use CandidateReceipt.bind")

    @classmethod
    def bind(
        cls,
        candidate: CandidateArtifact,
        validation: CandidateValidation,
        receipt_ref: ArtifactRef,
        *,
        contract: QuantResearchContract,
        plugin_identity: PluginIdentity,
    ) -> Self:
        if not isinstance(candidate, CandidateArtifact):
            raise EvaluationSchemaError("candidate must be a CandidateArtifact")
        if not isinstance(validation, CandidateValidation):
            raise EvaluationSchemaError("validation must be a CandidateValidation")
        if not isinstance(receipt_ref, ArtifactRef):
            raise EvaluationSchemaError("receipt_ref must be an ArtifactRef")
        _plugin_matches_contract(plugin_identity, contract)
        verified = validate_candidate_validation(
            validation.to_dict(),
            candidate=candidate,
            contract=contract,
            plugin_identity=plugin_identity,
        )
        if receipt_ref.kind != "q-arbor.validation-receipt.v1":
            raise EvaluationIntegrityError("validation receipt kind is invalid")
        if not receipt_ref.relative_path.startswith("artifacts/validations/"):
            raise EvaluationBoundaryError("validation receipt is outside its namespace")
        if receipt_ref.sha256 != verified.sha256:
            raise EvaluationIntegrityError("validation receipt digest does not match")
        instance = cls.__new__(cls)
        object.__setattr__(instance, "_candidate", candidate)
        object.__setattr__(instance, "_validation", verified)
        object.__setattr__(instance, "_receipt_ref", receipt_ref)
        object.__setattr__(instance, "_contract_hash", contract.sha256)
        object.__setattr__(instance, "_plugin_identity", plugin_identity)
        object.__setattr__(instance, "_initialized", True)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError(f"{type(self).__name__} is immutable")
        object.__setattr__(self, name, value)

    @property
    def candidate(self) -> CandidateArtifact:
        return self._candidate

    @property
    def validation(self) -> CandidateValidation:
        return self._validation

    @property
    def receipt_ref(self) -> ArtifactRef:
        return self._receipt_ref

    @property
    def contract_hash(self) -> str:
        return self._contract_hash

    @property
    def plugin_identity(self) -> PluginIdentity:
        return self._plugin_identity

    @property
    def status(self) -> str:
        return self.validation.status

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> Self:
        memo[id(self)] = self
        return self

    def __hash__(self) -> int:
        return hash((self.candidate.candidate_hash, self.receipt_ref.sha256))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CandidateReceipt):
            return NotImplemented
        return (
            self.candidate == other.candidate
            and self.validation == other.validation
            and self.receipt_ref == other.receipt_ref
            and self.contract_hash == other.contract_hash
            and self.plugin_identity == other.plugin_identity
        )


class ValidatedCandidate(CandidateReceipt):
    """Positive runtime witness that candidate validation succeeded."""

    @classmethod
    def bind(
        cls,
        candidate: CandidateArtifact,
        validation: CandidateValidation,
        receipt_ref: ArtifactRef,
        *,
        contract: QuantResearchContract,
        plugin_identity: PluginIdentity,
    ) -> ValidatedCandidate:
        if validation.status != "valid":
            raise EvaluationInvariantError("ValidatedCandidate requires valid status")
        return cast(
            ValidatedCandidate,
            super().bind(
                candidate,
                validation,
                receipt_ref,
                contract=contract,
                plugin_identity=plugin_identity,
            ),
        )
