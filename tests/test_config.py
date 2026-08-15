"""Tests for config loading."""
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from config import AppConfig, load_config


class ConfigTest(unittest.TestCase):
    def test_load_defaults(self):
        cfg = load_config()
        self.assertIsInstance(cfg, AppConfig)
        self.assertIn(cfg.adapter.mode, ("mock", "tsecbench", "http"))
        self.assertGreater(cfg.budget.max_steps, 0)

    def test_env_override(self):
        os.environ["AV_ADAPTER"] = "tsecbench"
        os.environ["AV_MAX_STEPS"] = "7"
        cfg = load_config()
        self.assertEqual(cfg.adapter.mode, "tsecbench")
        self.assertEqual(cfg.budget.max_steps, 7)
        os.environ.pop("AV_ADAPTER", None)
        os.environ.pop("AV_MAX_STEPS", None)

    def test_benchmark_env_vars_resolve(self):
        os.environ["BENCHMARK_BASE_URL"] = "https://tsecbench.example"
        os.environ["BENCHMARK_TOKEN"] = "tok-abc"
        cfg = load_config()
        self.assertEqual(cfg.adapter.base_url, "https://tsecbench.example")
        self.assertEqual(cfg.adapter.token, "tok-abc")
        os.environ.pop("BENCHMARK_BASE_URL", None)
        os.environ.pop("BENCHMARK_TOKEN", None)

    def test_configured_token_env_takes_precedence(self):
        os.environ["AV_SUBMIT_TOKEN"] = "av"
        os.environ["BENCHMARK_TOKEN"] = "bench"
        cfg = load_config()
        self.assertEqual(cfg.adapter.token, "av")
        os.environ.pop("AV_SUBMIT_TOKEN", None)
        os.environ.pop("BENCHMARK_TOKEN", None)


if __name__ == "__main__":
    unittest.main()
