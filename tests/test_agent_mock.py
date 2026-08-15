"""End-to-end tests: mock adapter + ReAct loop + scoreboard."""
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.agent import run_benchmark, solve_challenge
from core.types import Budget
from adapters.mock import MockAdapter, TOOL_NAMES
from llm.local_policy import LocalPolicyLLM
from bench.scoreboard import Scoreboard


def _budget():
    return Budget(max_steps=10, max_elapsed=30.0, max_tokens=100000)


class AgentMockTest(unittest.TestCase):
    def setUp(self):
        self.adapter = MockAdapter()
        self.llm = LocalPolicyLLM()

    def test_mock_adapter_has_all_tool_names(self):
        registry = self.adapter.tool_registry()
        for name in TOOL_NAMES:
            self.assertIsNotNone(registry.get(name), f"missing mock tool {name}")

    def test_single_solvable_challenge(self):
        ch = next(c for c in self.adapter.list_challenges() if c.id == "web-sqli-01")
        result = solve_challenge(ch, self.adapter, self.llm, _budget())
        self.assertTrue(result.passed)
        self.assertEqual(result.submitted_flag, ch.ground_truth_flag)
        self.assertGreater(result.steps_used, 0)

    def test_unsolvable_challenge_gives_up(self):
        ch = next(c for c in self.adapter.list_challenges() if c.id == "web-ssrf-01")
        result = solve_challenge(ch, self.adapter, self.llm, _budget())
        self.assertFalse(result.passed)
        self.assertIsNone(result.submitted_flag)

    def test_full_benchmark_solves_majority(self):
        results = run_benchmark(self.adapter.list_challenges(), self.adapter,
                                self.llm, _budget())
        scoreboard = Scoreboard(results)
        self.assertGreaterEqual(scoreboard.pass_count, 5)
        self.assertGreater(scoreboard.score_pct, 60.0)
        self.assertEqual(scoreboard.total_possible, 80)


if __name__ == "__main__":
    unittest.main()
