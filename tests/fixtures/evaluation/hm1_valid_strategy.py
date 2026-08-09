"""Synthetic-only qualification candidate; never imported or executed by C9."""

from research_env.backtest.strategy import BaseStrategy


class CandidateStrategy(BaseStrategy):
    def on_start(self, bars):
        self.ready = True

    def on_bar(self, context):
        return None

    def on_finish(self, result):
        return None
