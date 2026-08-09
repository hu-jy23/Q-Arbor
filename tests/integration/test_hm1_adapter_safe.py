from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest

from q_arbor.contracts import freeze_contract
from q_arbor.evaluation import (
    ContentAddressedArtifactStore,
    EvaluationBoundaryError,
    EvaluationDecodeError,
    EvaluationIntegrityError,
    EvaluationInvariantError,
    EvaluationSchemaError,
    QuantTaskPlugin,
)
from q_arbor.plugins.hm1 import HM1EngineOutput, HM1FuturesPlugin, HM1SplitData
from q_arbor.plugins.hm1.testing import make_hm1_mock_development_split
from tests.evaluation_helpers import (
    bind_validation,
    diagnostic_check_name,
    directory_entries,
    fixture_bytes,
    hm1_case,
    hm1_contract,
    hm1_engine_mapping,
    hm1_identity,
    make_request,
    materialize_candidate,
    runtime_fixture,
)

SECRET_CANARY = "RESTRICTED_SOURCE_TOKEN_CANARY_9F3B"


@pytest.mark.parametrize(
    (
        "engine_status",
        "coverage_count",
        "result_status",
        "failure_type",
        "failure_code",
    ),
    [
        (
            "complete",
            251,
            "incomparable",
            "incomparable",
            "hm1.coverage_mismatch",
        ),
        (
            "complete",
            252,
            "incomparable",
            "incomparable",
            "hm1.cost_semantics_unavailable",
        ),
        (
            "implementation_failure",
            None,
            "implementation_failure",
            "implementation_failure",
            "hm1.implementation_failure",
        ),
        (
            "evaluation_failure",
            None,
            "evaluation_failure",
            "evaluation_failure",
            "hm1.evaluation_failure",
        ),
        ("timeout", None, "evaluation_failure", "timeout", "hm1.timeout"),
        (
            "incomparable",
            None,
            "incomparable",
            "incomparable",
            "hm1.incomparable",
        ),
    ],
)
def test_hm1_five_engine_states_and_complete_precedence_are_exact(
    tmp_path: Path,
    engine_status: str,
    coverage_count: int | None,
    result_status: str,
    failure_type: str,
    failure_code: str,
) -> None:
    case = hm1_case(
        tmp_path / "case",
        engine_status=engine_status,
        coverage_count=coverage_count,
    )

    assert isinstance(case.plugin, QuantTaskPlugin)
    assert case.result.status == result_status
    assert case.result.failure.failure_type == failure_type
    assert case.result.failure.summary == failure_code
    assert case.result.primary_metric.value is None
    assert case.result.fold_metrics == ()
    assert case.result.statistical_diagnostics == ()
    if engine_status == "complete":
        diagnostics = {item.name: item.value for item in case.result.diagnostics}
        assert diagnostics == {
            "annualized_return": 0.12,
            "max_drawdown": 0.08,
            "calmar": 1.5,
            "win_rate": 0.55,
            "trade_count": 42,
            "coverage_count": coverage_count,
            "expected_coverage_count": 252,
        }
        checks = {item.name: item.status for item in case.result.checks}
        assert all(
            checks[diagnostic_check_name(name)] == "pass" for name in diagnostics
        )
    else:
        assert all(item.value is None for item in case.result.diagnostics)
        checks = {item.name: item.status for item in case.result.checks}
        assert all(
            checks[diagnostic_check_name(item.name)] == "not_observed"
            for item in case.result.diagnostics
        )


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        (
            lambda value: value.update(portfolio_daily_sharpe=None),
            EvaluationInvariantError,
        ),
        (lambda value: value.update(trade_count=None), EvaluationInvariantError),
        (
            lambda value: value.update(expected_coverage_count=0),
            EvaluationInvariantError,
        ),
        (lambda value: value.update(cost_semantics="guessed"), EvaluationSchemaError),
        (lambda value: value.update(extra="forbidden"), EvaluationSchemaError),
        (
            lambda value: value.update(warning_codes=["warning.z", "warning.a"]),
            EvaluationInvariantError,
        ),
        (
            lambda value: value.update(warning_codes=["warning.same", "warning.same"]),
            EvaluationInvariantError,
        ),
        (lambda value: value.update(trade_count=True), EvaluationSchemaError),
    ],
)
def test_hm1_complete_output_rejects_missing_ambiguous_or_noncanonical_fields(
    mutation: Any, expected_error: type[Exception]
) -> None:
    mapping = hm1_engine_mapping("complete")
    mutation(mapping)

    with pytest.raises(expected_error):
        HM1EngineOutput.from_mapping(mapping)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_hm1_engine_output_rejects_nonfinite_numeric_values(value: float) -> None:
    mapping = hm1_engine_mapping("complete")
    mapping["portfolio_daily_sharpe"] = value

    with pytest.raises(EvaluationDecodeError):
        HM1EngineOutput.from_mapping(mapping)


@pytest.mark.parametrize(
    "status",
    ["implementation_failure", "evaluation_failure", "timeout", "incomparable"],
)
def test_hm1_noncomplete_output_cannot_smuggle_metrics_or_observed_counts(
    status: str,
) -> None:
    mapping = hm1_engine_mapping(status)
    mapping["portfolio_daily_sharpe"] = 1.0
    mapping["coverage_count"] = 252

    with pytest.raises(EvaluationInvariantError):
        HM1EngineOutput.from_mapping(mapping)


def _hm1_validation(tmp_path: Path, payload: bytes) -> Any:
    identity = hm1_identity()
    plugin = HM1FuturesPlugin.create(identity)
    contract = hm1_contract(identity)
    candidate = materialize_candidate(tmp_path, contract, payload)
    return plugin.validate(candidate, contract)


def test_hm1_valid_strategy_is_ast_checked_without_import_or_execution(
    tmp_path: Path,
) -> None:
    validation = _hm1_validation(tmp_path, fixture_bytes("hm1_valid_strategy.py"))

    assert validation.status == "valid"
    assert validation.canonical_form_sha256 is not None
    assert [item.name for item in validation.checks] == [
        "candidate.kind",
        "candidate.surface",
        "hm1.ast",
    ]
    assert all(item.status == "pass" for item in validation.checks)


@pytest.mark.parametrize(
    "payload",
    [
        fixture_bytes("hm1_forbidden_strategy.py"),
        (
            b"from research_env.backtest.strategy import BaseStrategy\n"
            b"class CandidateStrategy(BaseStrategy):\n"
            b"    def on_bar(self, context):\n"
            b"        import socket\n"
        ),
        (
            b"from research_env.backtest.strategy import BaseStrategy\n"
            b"class CandidateStrategy(BaseStrategy):\n"
            b"    def on_bar(self, context):\n"
            b"        return open('forbidden')\n"
        ),
        (
            b"from research_env.backtest.strategy import BaseStrategy\n"
            b"class CandidateStrategy(BaseStrategy):\n"
            b"    def on_bar(self, context):\n"
            b"        return context.__dict__\n"
        ),
        (
            b"from research_env.backtest.strategy import BaseStrategy\n"
            b"class CandidateStrategy(BaseStrategy):\n"
            b"    def on_start(self):\n"
            b"        return None\n"
            b"    def on_bar(self, context):\n"
            b"        return None\n"
        ),
        (
            b"from research_env.backtest.strategy import BaseStrategy\n"
            b"class CandidateStrategy(BaseStrategy):\n"
            b"    def on_bar(self, context):\n"
            b"        global leaked\n"
        ),
    ],
)
def test_hm1_static_guard_rejects_forbidden_constructs_before_mock_split(
    tmp_path: Path, payload: bytes
) -> None:
    validation = _hm1_validation(tmp_path, payload)

    assert validation.status == "invalid_candidate"
    assert validation.failure.failure_type == "invalid_candidate"
    assert validation.canonical_form_sha256 is None


@pytest.mark.parametrize("role", ["gate", "final"])
def test_hm1_mock_factory_rejects_gate_and_final_before_store_issuance(
    tmp_path: Path, role: str
) -> None:
    root = tmp_path / role
    identity = hm1_identity()
    plugin = HM1FuturesPlugin.create(identity)
    contract = hm1_contract(identity)
    candidate = materialize_candidate(
        root / "candidate",
        contract,
        fixture_bytes("hm1_valid_strategy.py"),
    )
    validation = plugin.validate(candidate, contract)
    receipt = bind_validation(
        root,
        candidate=candidate,
        validation=validation,
        contract=contract,
        plugin_identity=identity,
    )
    request = make_request(contract, receipt, split_role=role)
    runtime = runtime_fixture(root, contract, aggregate_only=True)
    store_root = root / "store"
    store = ContentAddressedArtifactStore.create(store_root)
    output = HM1EngineOutput.from_mapping(hm1_engine_mapping("incomparable"))
    before = directory_entries(store_root)

    with pytest.raises(EvaluationBoundaryError):
        make_hm1_mock_development_split(
            request,
            contract,
            receipt,
            plugin,
            runtime.lock,
            result_id=f"result.hm1.{role}",
            evaluation_seed=7,
            artifact_store=store,
            produced_by_event_id=f"event.hm1.{role}",
            engine_output=output,
        )

    assert directory_entries(store_root) == before


@pytest.mark.parametrize(
    "variant",
    [
        "primary_direction",
        "diagnostic_unit",
        "diagnostic_aggregation",
        "hard_constraint",
        "cost_rule",
    ],
)
def test_hm1_mock_factory_rejects_contract_relabelling_before_issuance(
    tmp_path: Path,
    variant: str,
) -> None:
    root = tmp_path / variant
    identity = hm1_identity()
    plugin = HM1FuturesPlugin.create(identity)
    mapping = hm1_contract(identity).to_dict()
    if variant == "primary_direction":
        mapping["metrics"]["primary"]["direction"] = "minimize"
    elif variant == "diagnostic_unit":
        mapping["metrics"]["diagnostics"][0]["unit"] = "ratio"
    elif variant == "diagnostic_aggregation":
        mapping["metrics"]["diagnostics"][0]["aggregation"] = "mean_across_folds"
    elif variant == "hard_constraint":
        mapping["metrics"]["hard_constraints"] = [
            {
                "name": "max_drawdown",
                "operator": "le",
                "threshold": 0.2,
                "unit": "fraction",
            }
        ]
    elif variant == "cost_rule":
        mapping["cost_model"]["components"][0]["rule"] = "estimated elsewhere"
    else:  # pragma: no cover - parametrization is closed above
        raise AssertionError("unknown HM1 contract variant")
    contract = freeze_contract(mapping)
    candidate = materialize_candidate(
        root / "candidate",
        contract,
        fixture_bytes("hm1_valid_strategy.py"),
    )
    validation = plugin.validate(candidate, contract)
    receipt = bind_validation(
        root,
        candidate=candidate,
        validation=validation,
        contract=contract,
        plugin_identity=identity,
    )
    request = make_request(contract, receipt)
    runtime = runtime_fixture(root, contract, aggregate_only=True)
    store_root = root / "store"
    store = ContentAddressedArtifactStore.create(store_root)
    output = HM1EngineOutput.from_mapping(hm1_engine_mapping("complete"))
    before = directory_entries(store_root)

    with pytest.raises(EvaluationIntegrityError, match="HM1 mock contract mismatch"):
        make_hm1_mock_development_split(
            request,
            contract,
            receipt,
            plugin,
            runtime.lock,
            result_id=f"result.hm1.variant.{variant}",
            evaluation_seed=7,
            artifact_store=store,
            produced_by_event_id=f"event.hm1.variant.{variant}",
            engine_output=output,
        )

    assert directory_entries(store_root) == before


def test_hm1_evaluator_rechecks_exact_contract_before_output_access(
    tmp_path: Path,
) -> None:
    root = tmp_path / "evaluator-domain"
    identity = hm1_identity()
    plugin = HM1FuturesPlugin.create(identity)
    contract = hm1_contract(identity)
    candidate = materialize_candidate(
        root / "candidate",
        contract,
        fixture_bytes("hm1_valid_strategy.py"),
    )
    validation = plugin.validate(candidate, contract)
    receipt = bind_validation(
        root,
        candidate=candidate,
        validation=validation,
        contract=contract,
        plugin_identity=identity,
    )
    request = make_request(contract, receipt)
    runtime = runtime_fixture(root, contract, aggregate_only=True)
    store = ContentAddressedArtifactStore.create(root / "store")
    output = HM1EngineOutput.from_mapping(hm1_engine_mapping("complete"))
    split = make_hm1_mock_development_split(
        request,
        contract,
        receipt,
        plugin,
        runtime.lock,
        result_id="result.hm1.evaluator-domain",
        evaluation_seed=7,
        artifact_store=store,
        produced_by_event_id="event.hm1.evaluator-domain",
        engine_output=output,
        untrusted_failure_detail=SECRET_CANARY,
    )
    changed_mapping = contract.to_dict()
    changed_mapping["metrics"]["primary"]["unit"] = "fraction"
    object.__setattr__(split, "_contract", freeze_contract(changed_mapping))

    with pytest.raises(EvaluationIntegrityError, match="HM1 mock contract mismatch"):
        plugin.evaluate(receipt, split)


def test_hm1_untrusted_failure_detail_is_sanitized_everywhere(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "case"
    case = hm1_case(
        root,
        engine_status="implementation_failure",
        untrusted_failure_detail=(
            f"traceback /restricted/source/raw token={SECRET_CANARY} stdout secret"
        ),
    )
    captured = capsys.readouterr()
    observable = "\n".join(
        [
            case.result.to_json(),
            case.plugin.summarize(case.result).to_json(),
            str(case.result.failure.summary),
            captured.out,
            captured.err,
        ]
    )
    tree_bytes = b"".join(
        path.read_bytes() for path in root.rglob("*") if path.is_file()
    ).decode("utf-8", errors="ignore")

    assert case.result.status == "implementation_failure"
    assert case.result.failure.summary == "hm1.implementation_failure"
    assert SECRET_CANARY not in observable
    assert SECRET_CANARY not in tree_bytes
    assert "/restricted/source/raw" not in observable
    assert "/restricted/source/raw" not in tree_bytes


@pytest.mark.parametrize("fatal_error", [KeyboardInterrupt, SystemExit])
def test_hm1_fatal_base_exceptions_are_never_converted_to_a_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fatal_error: type[BaseException],
) -> None:
    root = tmp_path / fatal_error.__name__
    identity = hm1_identity()
    plugin = HM1FuturesPlugin.create(identity)
    contract = hm1_contract(identity)
    candidate = materialize_candidate(
        root / "candidate",
        contract,
        fixture_bytes("hm1_valid_strategy.py"),
    )
    validation = plugin.validate(candidate, contract)
    receipt = bind_validation(
        root,
        candidate=candidate,
        validation=validation,
        contract=contract,
        plugin_identity=identity,
    )
    request = make_request(contract, receipt)
    runtime = runtime_fixture(root, contract, aggregate_only=True)
    store = ContentAddressedArtifactStore.create(root / "store")
    output = HM1EngineOutput.from_mapping(hm1_engine_mapping("incomparable"))
    split = make_hm1_mock_development_split(
        request,
        contract,
        receipt,
        plugin,
        runtime.lock,
        result_id=f"result.hm1.{fatal_error.__name__.lower()}",
        evaluation_seed=7,
        artifact_store=store,
        produced_by_event_id=f"event.hm1.{fatal_error.__name__.lower()}",
        engine_output=output,
    )

    def raise_fatal(_self: HM1SplitData) -> HM1EngineOutput:
        raise fatal_error("qualification fatal control signal")

    monkeypatch.setattr(HM1SplitData, "read_engine_output", raise_fatal)

    with pytest.raises(fatal_error):
        plugin.evaluate(receipt, split)


def test_hm1_mock_evaluation_uses_no_environment_network_or_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "case"
    identity = hm1_identity()
    plugin = HM1FuturesPlugin.create(identity)
    contract = hm1_contract(identity)
    candidate = materialize_candidate(
        root / "candidate",
        contract,
        fixture_bytes("hm1_valid_strategy.py"),
    )
    validation = plugin.validate(candidate, contract)
    receipt = bind_validation(
        root,
        candidate=candidate,
        validation=validation,
        contract=contract,
        plugin_identity=identity,
    )
    request = make_request(contract, receipt)
    runtime = runtime_fixture(root, contract, aggregate_only=True)
    store = ContentAddressedArtifactStore.create(root / "store")
    output = HM1EngineOutput.from_mapping(hm1_engine_mapping("incomparable"))
    split = make_hm1_mock_development_split(
        request,
        contract,
        receipt,
        plugin,
        runtime.lock,
        result_id="result.hm1.no_io",
        evaluation_seed=7,
        artifact_store=store,
        produced_by_event_id="event.hm1.no_io",
        engine_output=output,
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("forbidden discovery call")

    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    result = plugin.evaluate(receipt, split)

    assert result.status == "incomparable"
    for forbidden_attribute in (
        "path",
        "uri",
        "token",
        "credential",
        "rows",
        "open",
        "subprocess",
        "network",
    ):
        assert not hasattr(split.data, forbidden_attribute)
