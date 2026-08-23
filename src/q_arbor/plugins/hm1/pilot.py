"""Small HM1 control-plane pilot over opaque development/gate resources."""

from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from q_arbor.evaluation import EvaluationBinding, EvaluationRequest, EvaluationResult, VerifiedRuntimeLock
from q_arbor.firewall import EvaluationBroker
from . import HM1EngineOutput, HM1FuturesPlugin, make_hm1_authorized_aggregate


@dataclass(frozen=True, slots=True)
class HM1PilotTrace:
    development: EvaluationResult
    gate: EvaluationResult
    query_counts: Mapping[str, int]
    final_query_count: int = 0


@dataclass(frozen=True, slots=True)
class HM1PilotBudget:
    """Durable run/contract-bound reservations consumed before evaluator calls."""

    path: Path
    run_id: str
    contract_hash: str
    limits: Mapping[str, int]

    @classmethod
    def open(cls, path, *, run_id: str, contract_hash: str,
             limits: Mapping[str, int]) -> "HM1PilotBudget":
        budget = cls(Path(path), run_id, contract_hash, dict(limits))
        budget._update(None)
        return budget

    def reserve(self, *, run_id: str, contract_hash: str, role: str) -> None:
        if run_id != self.run_id or contract_hash != self.contract_hash:
            raise RuntimeError("HM1 pilot budget identity mismatch")
        if role not in self.limits or role not in {"development", "gate", "final"}:
            raise RuntimeError("HM1 pilot budget role is invalid")
        self._update(role)

    def _update(self, role: str | None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(self.path.name + ".lock")
        with lock_path.open("a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if self.path.exists():
                state = json.loads(self.path.read_text(encoding="utf-8"))
                expected = {"run_id": self.run_id, "contract_hash": self.contract_hash,
                            "limits": dict(self.limits)}
                if any(state.get(key) != value for key, value in expected.items()):
                    raise RuntimeError("HM1 pilot budget binding mismatch")
                consumed = state.get("consumed")
                if not isinstance(consumed, dict):
                    raise RuntimeError("HM1 pilot budget is corrupt")
            else:
                consumed = {key: 0 for key in self.limits}
            if role is not None:
                if consumed.get(role, 0) >= self.limits[role]:
                    raise RuntimeError("HM1 pilot budget exhausted")
                consumed[role] = consumed.get(role, 0) + 1
            state = {"schema_version": "hm1-pilot-budget.v1", "run_id": self.run_id,
                     "contract_hash": self.contract_hash, "limits": dict(self.limits),
                     "consumed": consumed}
            temporary = self.path.with_name(self.path.name + ".tmp")
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(state, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)


def evaluate_authorized_aggregate(
    *, plugin: HM1FuturesPlugin, candidate, request: EvaluationRequest,
    contract, binding: EvaluationBinding, engine_output: HM1EngineOutput, artifacts,
) -> EvaluationResult:
    """Turn one already-authorized opaque aggregate into a typed HM1 result."""
    split = make_hm1_authorized_aggregate(
        plugin=plugin, request=request, contract=contract, binding=binding,
        engine_output=engine_output, artifacts=artifacts,
    )
    return plugin.evaluate(candidate, split)


def run_hm1_pilot(
    *,
    broker: EvaluationBroker,
    development_request: EvaluationRequest,
    gate_request: EvaluationRequest,
    bindings: Mapping[str, EvaluationBinding],
    runtime_locks: Mapping[str, VerifiedRuntimeLock],
    tokens: Mapping[str, bytes],
    evaluator: Callable[[EvaluationRequest, object], EvaluationResult],
    budget: HM1PilotBudget,
) -> HM1PilotTrace:
    """Authorize exactly one opaque resource per development/gate request."""
    requests = ((development_request, "executor"), (gate_request, "coordinator"))
    results: list[EvaluationResult] = []
    for request, principal in requests:
        if request.split_role not in {"development", "gate"}:
            raise ValueError("HM1 pilot accepts development and gate only")
        binding = bindings.get(request.capability_grant_id)
        runtime_lock = runtime_locks.get(request.capability_grant_id)
        token = tokens.get(request.capability_grant_id)
        if binding is None or runtime_lock is None or token is None:
            raise ValueError("HM1 pilot authorization inputs are incomplete")
        budget.reserve(run_id=request.run_id, contract_hash=request.contract_hash,
                       role=request.split_role)
        resource = broker.authorize_runtime(
            request, runtime_lock=runtime_lock, principal=principal, token=token
        )
        result = evaluator(request, resource)
        if not isinstance(result, EvaluationResult):
            raise TypeError("HM1 evaluator must return EvaluationResult")
        if result.request_id != request.request_id or result.split_role != request.split_role:
            raise ValueError("HM1 evaluator result identity differs")
        if result.result_id != binding.result_id:
            raise ValueError("HM1 evaluator result_id differs from binding")
        results.append(result)
    counts = {
        development_request.capability_grant_id: broker.query_count(
            development_request.capability_grant_id
        ),
        gate_request.capability_grant_id: broker.query_count(gate_request.capability_grant_id),
    }
    return HM1PilotTrace(results[0], results[1], counts, final_query_count=0)


__all__ = ["HM1PilotBudget", "HM1PilotTrace", "evaluate_authorized_aggregate", "run_hm1_pilot"]
