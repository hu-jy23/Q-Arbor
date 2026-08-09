"""Runtime-checkable task, resource, and artifact protocols for C9."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, runtime_checkable

from q_arbor.contracts import QuantResearchContract

from .candidate import CandidateArtifact, CandidateValidation, ValidatedCandidate
from .results import EvaluationResult, EvaluationSummary
from .runtime import EvaluationBinding, EvaluationRequest
from .values import (
    ArtifactRef,
    CheckResult,
    EvaluationFailure,
    MetricValue,
    PluginIdentity,
    ReasonCode,
)


@runtime_checkable
class SplitDataView(Protocol):
    @property
    def role(self) -> str: ...

    @property
    def data_snapshot_sha256(self) -> str: ...

    @property
    def split_manifest_sha256(self) -> str: ...


@runtime_checkable
class ArtifactResolver(Protocol):
    def read_bytes(self, ref: ArtifactRef) -> bytes: ...

    def verify(self, ref: ArtifactRef) -> None: ...

    def verify_issued(
        self,
        ref: ArtifactRef,
        *,
        request_id: str,
        runtime_lock_sha256: str,
    ) -> None: ...


@runtime_checkable
class ArtifactSink(Protocol):
    @property
    def issued_refs(self) -> tuple[ArtifactRef, ...]: ...

    def put(self, *, kind: str, media_type: str, content: bytes) -> ArtifactRef: ...


@runtime_checkable
class AuthorizedSplit(Protocol):
    @property
    def request(self) -> EvaluationRequest: ...

    @property
    def contract(self) -> QuantResearchContract: ...

    @property
    def binding(self) -> EvaluationBinding: ...

    @property
    def data(self) -> SplitDataView: ...

    @property
    def artifacts(self) -> ArtifactSink: ...

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
    ) -> EvaluationResult: ...


@runtime_checkable
class QuantTaskPlugin(Protocol):
    @property
    def identity(self) -> PluginIdentity: ...

    def validate(
        self,
        candidate: CandidateArtifact,
        contract: QuantResearchContract,
    ) -> CandidateValidation: ...

    def evaluate(
        self,
        candidate: ValidatedCandidate,
        split: AuthorizedSplit,
    ) -> EvaluationResult: ...

    def summarize(self, result: EvaluationResult) -> EvaluationSummary: ...
