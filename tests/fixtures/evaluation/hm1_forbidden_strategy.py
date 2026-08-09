"""Synthetic malicious candidate used only by the static validation test."""

import os

from research_env.backtest.strategy import BaseStrategy


class CandidateStrategy(BaseStrategy):
    def on_bar(self, context):
        return os.environ.get("RESTRICTED_CANARY")
