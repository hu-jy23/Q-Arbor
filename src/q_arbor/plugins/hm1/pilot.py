"""Small HM1 control-plane pilot over opaque development/gate resources."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from q_arbor.evaluation import EvaluationBinding, EvaluationRequest, EvaluationResult, VerifiedRuntimeLock
from q_arbor.firewall import EvaluationBroker
from . import HM1EngineOutput, HM1FuturesPlugin, make_hm1_authorized_aggregate


@dataclass(frozen=True, slots=True)
class HM1PilotTrace:
    development: EvaluationResult
    gate: EvaluationResult
    query_counts: Mapping[str, int]
    final_query_count: int = 0


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


__all__ = ["HM1PilotTrace", "evaluate_authorized_aggregate", "run_hm1_pilot"]
