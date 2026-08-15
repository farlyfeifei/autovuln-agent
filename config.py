"""Configuration loading: config.yaml + environment variable overrides.

All values can be overridden by env vars so real API keys never live in the
repo:

    LLM_PROVIDER / LLM_MODEL / LLM_API_KEY / LLM_BASE_URL / AV_LLM_TIMEOUT
    AV_ADAPTER / AV_CHALLENGES_FILE / AV_BASE_URL / AV_SUBMIT_TOKEN
    BENCHMARK_BASE_URL / BENCHMARK_TOKEN   (TSecBench platform-standard names)
    AV_MAX_STEPS / AV_MAX_ELAPSED / AV_MAX_TOKENS
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

DEFAULT_CONFIG = {
    "llm": {
        "provider": "local",
        "model": "",
        "api_key_env": "LLM_API_KEY",
        "base_url": "",
        "temperature": 0.2,
        "max_output_tokens": 1024,
        "timeout": 120.0,
    },
    "budget": {"max_steps": 15, "max_elapsed": 300.0, "max_tokens": 200000,
               "run_max_elapsed": 19800.0},
    "net": {"timeout": 12, "verify_ssl": False,
            "user_agent": "AutoVulnAgent/0.1 (BSRC Agent+)"},
    "adapter": {"mode": "mock", "challenges_file": "", "base_url": "", "token_env": "AV_SUBMIT_TOKEN"},
    "report": {"out_dir": "reports", "trace_dir": "traces"},
}


@dataclass
class LLMConfig:
    provider: str = "local"
    model: str = ""
    api_key_env: str = "LLM_API_KEY"
    base_url: str = ""
    temperature: float = 0.2
    max_output_tokens: int = 1024
    timeout: float = 120.0

    @property
    def api_key(self) -> str:
        return os.environ.get(self.api_key_env, "").strip()


@dataclass
class BudgetConfig:
    max_steps: int = 15
    max_elapsed: float = 300.0
    max_tokens: int = 200000
    # Whole-run wall-clock cap (seconds) so the agent stops starting new
    # challenges before the platform's total timeout (6h) is reached.
    run_max_elapsed: float = 19800.0  # 5.5h — leaves a safety margin


@dataclass
class NetConfig:
    timeout: float = 12.0
    verify_ssl: bool = False
    user_agent: str = "AutoVulnAgent/0.1 (BSRC Agent+)"
    proxies: Optional[dict] = None


@dataclass
class AdapterConfig:
    mode: str = "mock"
    challenges_file: str = ""
    base_url: str = ""
    token_env: str = "AV_SUBMIT_TOKEN"

    @property
    def token(self) -> str:
        # BENCHMARK_TOKEN is the platform-standard name TSecBench auto-distributes;
        # the configured token_env (AV_SUBMIT_TOKEN) stays the primary alias.
        for name in (self.token_env, "BENCHMARK_TOKEN"):
            value = os.environ.get(name, "").strip()
            if value:
                return value
        return ""


@dataclass
class ReportConfig:
    out_dir: str = "reports"
    trace_dir: str = "traces"


@dataclass
class AppConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    net: NetConfig = field(default_factory=NetConfig)
    adapter: AdapterConfig = field(default_factory=AdapterConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


def _as_bool(s: str) -> bool:
    return s.strip().lower() in ("1", "true", "yes", "on")


def load_config(path: Optional[str] = None) -> AppConfig:
    raw = dict(DEFAULT_CONFIG)
    cfg_path = path or os.environ.get("AV_CONFIG", "config.yaml")
    if os.path.exists(cfg_path):
        if yaml is None:
            print(f"[config] warning: config file '{cfg_path}' exists but PyYAML is "
                  "not installed; using built-in defaults.  `pip install PyYAML` "
                  "to honour the file.", file=sys.stderr)
        else:
            with open(cfg_path, encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            for section, values in loaded.items():
                if isinstance(values, dict) and isinstance(raw.get(section), dict):
                    raw[section].update(values)
                else:
                    raw[section] = values

    cfg = AppConfig(
        llm=LLMConfig(**raw["llm"]),
        budget=BudgetConfig(**raw["budget"]),
        net=NetConfig(**raw["net"]),
        adapter=AdapterConfig(**raw["adapter"]),
        report=ReportConfig(**raw["report"]),
    )
    # --- environment overrides ---
    env = os.environ
    cfg.llm.provider = env.get("LLM_PROVIDER", cfg.llm.provider)
    cfg.llm.model = env.get("LLM_MODEL", cfg.llm.model)
    cfg.llm.base_url = env.get("LLM_BASE_URL", cfg.llm.base_url)
    cfg.adapter.mode = env.get("AV_ADAPTER", cfg.adapter.mode)
    cfg.adapter.challenges_file = env.get("AV_CHALLENGES_FILE", cfg.adapter.challenges_file)
    cfg.adapter.base_url = env.get("BENCHMARK_BASE_URL",
                                   env.get("AV_BASE_URL", cfg.adapter.base_url))
    if env.get("AV_MAX_STEPS"):
        try:
            cfg.budget.max_steps = int(env["AV_MAX_STEPS"])
        except ValueError:
            print(f"[config] warning: AV_MAX_STEPS={env['AV_MAX_STEPS']!r} is not an "
                  "integer; ignoring override", file=sys.stderr)
    if env.get("AV_MAX_ELAPSED"):
        try:
            cfg.budget.max_elapsed = float(env["AV_MAX_ELAPSED"])
        except ValueError:
            print(f"[config] warning: AV_MAX_ELAPSED={env['AV_MAX_ELAPSED']!r} is not "
                  "a number; ignoring override", file=sys.stderr)
    if env.get("AV_MAX_TOKENS"):
        try:
            cfg.budget.max_tokens = int(env["AV_MAX_TOKENS"])
        except ValueError:
            print(f"[config] warning: AV_MAX_TOKENS={env['AV_MAX_TOKENS']!r} is not an "
                  "integer; ignoring override", file=sys.stderr)
    if env.get("AV_RUN_MAX_ELAPSED"):
        try:
            cfg.budget.run_max_elapsed = float(env["AV_RUN_MAX_ELAPSED"])
        except ValueError:
            print(f"[config] warning: AV_RUN_MAX_ELAPSED={env['AV_RUN_MAX_ELAPSED']!r} "
                  "is not a number; ignoring override", file=sys.stderr)
    if env.get("AV_LLM_TIMEOUT"):
        try:
            cfg.llm.timeout = float(env["AV_LLM_TIMEOUT"])
        except ValueError:
            print(f"[config] warning: AV_LLM_TIMEOUT={env['AV_LLM_TIMEOUT']!r} is "
                  "not a number; ignoring override", file=sys.stderr)
    if env.get("AV_VERIFY_SSL"):
        cfg.net.verify_ssl = _as_bool(env["AV_VERIFY_SSL"])
    return cfg
