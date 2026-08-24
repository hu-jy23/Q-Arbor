from __future__ import annotations

from pathlib import Path

import pytest

from q_arbor.evaluation import EvaluationInvariantError, freeze_evaluation_result
from tests.evaluation_helpers import synthetic_case


def test_c10_synthetic_smokes_cannot_cross_the_statistical_claim_boundary(
    tmp_path: Path,
) -> None:
    cases = {
        signal_column: synthetic_case(
            tmp_path / signal_column,
            signal_column=signal_column,
        )
        for signal_column in ("null_signal", "planted_signal")
    }

    for case in cases.values():
        contract = case.contract.to_dict()
        assert case.request.split_role == "development"
        assert case.result.split_role == "development"
        assert contract["data"]["point_in_time"]["known_limitations"] == [
            "mechanism smoke only"
        ]
        assert contract["data"]["splits"]["final"]["sealed"] is True
        assert case.result.statistical_diagnostics == ()

        for claim_level, status in (
            ("diagnostic", "diagnostic"),
            ("controlled", "calibrated"),
        ):
            injected = case.result.to_dict()
            injected["statistical_diagnostics"] = [
                {
                    "method": "psr",
                    "method_plan_hash": "a" * 64,
                    "control_object": "selection_bias",
                    "status": status,
                    "claim_level": claim_level,
                    "family_unit": "candidate",
                    "duplicate_policy": "count_each_query",
                    "family_snapshot_hash": "b" * 64,
                    "trial_count": 1,
                    "assumptions": [],
                    "inputs_sha256": "c" * 64,
                    "result": {},
                }
            ]

            with pytest.raises(
                EvaluationInvariantError,
                match="C9 results cannot claim statistical diagnostics",
            ):
                freeze_evaluation_result(injected, binding=case.binding)
