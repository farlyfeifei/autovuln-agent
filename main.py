#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AutoVulnAgent CLI entry point.

Wires together config -> adapter -> LLM -> ReAct benchmark loop -> scoreboard,
then writes a JSONL trace, optionally a markdown report and a machine-readable
JSON summary.

Examples:
    python main.py                          # mock benchmark, local-policy LLM
    python main.py --trace --json --report  # verbose local run with all outputs
    python main.py --mode http --challenges-file manifest.json --llm glm
    python main.py --mode tsecbench --llm deepseek --max-steps 30 --no-sweep

Exit codes:
    0  at least one challenge solved
    1  fatal error / nothing solved
    2  a live mode (http/tsecbench) produced no challenges to run
"""
from __future__ import annotations

import sys, os  # noqa: E401 -- must run before any package import below
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import json
from datetime import datetime
from typing import List, Optional

from config import AppConfig, load_config
from core import __version__
from core.agent import run_benchmark
from core.net import configure as net_configure
from core.trace import write_trace_jsonl
from core.types import Budget, ChallengeResult
from adapters.mock import MockAdapter

# Rough public-API pricing used ONLY for the ``cost_usd`` report field, in USD
# per 1M tokens. These are generic mid-range estimates; exact per-vendor rates
# depend on the configured provider. They are pricing facts, not secrets.
_INPUT_USD_PER_1M = 0.5
_OUTPUT_USD_PER_1M = 1.5

MODES = ("mock", "tsecbench", "http")
LLM_PROVIDERS = ("local", "openai", "glm", "deepseek", "comate", "opencode")

# When --json is active every human-readable line must go to stderr so stdout
# carries nothing but the machine-readable JSON document.
_JSON_MODE = False


def _emit(*args, **kwargs) -> None:
    """Print a human-readable line; routed to stderr under --json."""
    if _JSON_MODE:
        print(*args, file=sys.stderr, **kwargs)
    else:
        print(*args, **kwargs)


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="autovuln",
        description="AutoVulnAgent — autonomous vulnerability-discovery "
                    "benchmark CLI (BSRC Agent+).",
    )
    parser.add_argument("--config", default="config.yaml",
                        help="path to YAML config (default: config.yaml)")
    parser.add_argument("--mode", choices=MODES, default=None,
                        help="adapter mode (default: from config)")
    parser.add_argument("--llm", dest="llm_provider", choices=LLM_PROVIDERS,
                        default=None,
                        help="LLM provider (default: from config)")
    parser.add_argument("--trace", action="store_true",
                        help="print live progress rows and per-step ReAct traces")
    parser.add_argument("--report", action="store_true",
                        help="write a markdown report via reports.gen_report")
    parser.add_argument("--json", action="store_true",
                        help="emit a machine-readable JSON summary on stdout")
    parser.add_argument("--challenges-file", default=None,
                        help="challenge manifest path (JSON) for http/tsecbench "
                             "modes")
    parser.add_argument("--max-steps", type=int, default=None,
                        help="per-challenge step budget (overrides config)")
    parser.add_argument("--timeout", type=float, default=None,
                        help="per-request HTTP timeout in seconds "
                             "(overrides config)")
    parser.add_argument("--no-sweep", action="store_true",
                        help="disable the final whole-transcript flag sweep")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def _apply_overrides(args: argparse.Namespace, cfg: AppConfig) -> None:
    """Fold CLI-provided values into the loaded config object."""
    if args.mode:
        cfg.adapter.mode = args.mode
    if args.llm_provider:
        cfg.llm.provider = args.llm_provider
    if args.challenges_file:
        cfg.adapter.challenges_file = args.challenges_file
    if args.max_steps is not None:
        cfg.budget.max_steps = args.max_steps
    if args.timeout is not None:
        cfg.net.timeout = args.timeout


def _load_manifest(cfg: AppConfig) -> Optional[List]:
    """Load a challenge manifest for http/tsecbench modes; None when absent."""
    path = (cfg.adapter.challenges_file or "").strip()
    if not path:
        return None
    from adapters.http import load_challenges_manifest
    try:
        manifest = load_challenges_manifest(path)
    except Exception as exc:
        _emit(f"[main] warning: could not load challenges manifest '{path}': "
              f"{type(exc).__name__}: {exc}")
        return None
    if manifest:
        _emit(f"[main] loaded {len(manifest)} challenges from '{path}'")
    else:
        _emit(f"[main] warning: manifest '{path}' contained no challenges")
    return manifest


def _build_adapter(cfg: AppConfig, manifest: Optional[List]):
    """Construct the adapter for the configured mode; never raises.

    A missing submit token in a live mode is only a warning (listing may still
    be anonymous); if construction itself fails we fall back to the offline
    mock adapter so the run can still complete.
    """
    mode = cfg.adapter.mode
    if mode == "mock":
        if manifest:
            _emit(f"[main] mock adapter: using {len(manifest)} challenges from "
                  f"'{cfg.adapter.challenges_file}'")
            return MockAdapter(challenges=manifest)
        return MockAdapter()

    token = cfg.adapter.token
    if not token:
        _emit(f"[main] warning: mode '{mode}' has no submit token configured; "
              f"set the environment variable {cfg.adapter.token_env} for real "
              "submissions (listing may still work anonymously).")
    try:
        if mode == "http":
            from adapters.http import HttpAdapter
            return HttpAdapter(challenges=manifest,
                               submit_endpoint=cfg.adapter.base_url, token=token)
        if mode == "tsecbench":
            from adapters.tsecbench import TsecBenchAdapter
            return TsecBenchAdapter(challenges=manifest,
                                    base_url=cfg.adapter.base_url, token=token)
    except Exception as exc:
        _emit(f"[main] warning: failed to build '{mode}' adapter "
              f"({type(exc).__name__}: {exc}); falling back to the local mock "
              "adapter so the run can still complete.")
        return MockAdapter()

    _emit(f"[main] warning: unknown adapter mode '{mode}'; falling back to mock.")
    return MockAdapter()


def _build_llm(cfg: AppConfig):
    from llm.providers import build_llm
    return build_llm(cfg.llm)


def _apply_no_sweep(enabled: bool) -> None:
    """Disable the core loop's final whole-transcript flag sweep (--no-sweep)."""
    if not enabled:
        return
    try:
        import core.agent as agent_mod
        agent_mod.sweep_flags = lambda history: []  # type: ignore[assignment]
        _emit("[main] --no-sweep: final transcript flag sweep disabled")
    except Exception as exc:
        _emit(f"[main] warning: could not disable final sweep "
              f"({type(exc).__name__}: {exc})")


def _on_done(result: ChallengeResult) -> None:
    """Live per-challenge progress row printed when --trace is set."""
    status = "PASS" if result.passed else "FAIL"
    _emit(f"  [{result.challenge_id}] {result.name} -> {status}  "
          f"steps={result.steps_used}  {result.elapsed_sec:.1f}s  "
          f"points={result.points_awarded}/{result.points_possible}")


def _print_scoreboard(results: List[ChallengeResult]) -> None:
    """Print the aggregated scoreboard table + summary lines."""
    try:
        from bench.scoreboard import Scoreboard
        board = Scoreboard(results)

        table_attr = getattr(board, "table", None)
        if table_attr is not None:
            table = table_attr() if callable(table_attr) else table_attr
            if table:
                _emit(table)

        summary_attr = getattr(board, "summary_lines", None)
        if summary_attr is not None:
            summary = summary_attr() if callable(summary_attr) else summary_attr
            if isinstance(summary, str):
                _emit(summary)
            else:
                for line in summary:
                    _emit(line)
    except Exception as exc:
        # Never crash the CLI because the scoreboard rendering broke.
        _emit(f"[main] warning: scoreboard unavailable "
              f"({type(exc).__name__}: {exc})")
        solved = sum(1 for r in results if r.passed)
        total = len(results)
        score = sum(r.points_awarded for r in results)
        max_score = sum(r.points_possible for r in results)
        pct = (score / max_score * 100.0) if max_score else 0.0
        _emit(f"[main] summary: solved {solved}/{total}, "
              f"score {score}/{max_score} ({pct:.1f}%)")


def _print_react_trace(results: List[ChallengeResult]) -> None:
    """Print each challenge's ReAct steps: index, action, trimmed observation."""
    for r in results:
        _emit(f"\n--- {r.challenge_id} | {r.name} | "
              f"{'PASS' if r.passed else 'FAIL'} | "
              f"steps={r.steps_used} | {r.elapsed_sec:.2f}s ---")
        for step in r.trace:
            obs = step.observation or ""
            if len(obs) > 220:
                obs = obs[:220] + "..."
            _emit(f"  #{step.index} {step.action}")
            if step.thought:
                _emit(f"     thought: {step.thought}")
            _emit(f"     obs: {obs}")


def _summary_data(results: List[ChallengeResult], llm, mode: str) -> dict:
    """Machine-readable aggregate summary for the --json output."""
    solved = sum(1 for r in results if r.passed)
    total = len(results)
    score = sum(r.points_awarded for r in results)
    max_score = sum(r.points_possible for r in results)
    usage = llm.usage
    cost_usd = (usage.prompt_tokens * _INPUT_USD_PER_1M
                + usage.completion_tokens * _OUTPUT_USD_PER_1M) / 1_000_000
    return {
        "mode": mode,
        "solved": solved,
        "total": total,
        "score": score,
        "max_score": max_score,
        "score_pct": round((score / max_score * 100.0) if max_score else 0.0, 2),
        "avg_steps": round((sum(r.steps_used for r in results) / total)
                           if total else 0.0, 2),
        "total_time": round(sum(r.elapsed_sec for r in results), 3),
        "tokens": usage.total_tokens,
        "cost_usd": round(cost_usd, 6),
    }


def _write_trace(cfg: AppConfig, results: List[ChallengeResult]) -> str:
    """Persist the full ReAct trajectories as JSONL; returns the file path.

    Appends a counter when a same-second collision exists so concurrent runs
    never clobber each other's traces.
    """
    trace_dir = os.path.join(cfg.report.out_dir, cfg.report.trace_dir)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    path = os.path.join(trace_dir, f"run_{stamp}.jsonl")
    n = 1
    while os.path.exists(path):
        path = os.path.join(trace_dir, f"run_{stamp}_{n}.jsonl")
        n += 1
    write_trace_jsonl(path, results)
    return path


def main(argv: Optional[List[str]] = None) -> int:
    global _JSON_MODE
    try:
        args = _parse_args(argv)
        if args.json:
            _JSON_MODE = True
        cfg = load_config(args.config)
        _apply_overrides(args, cfg)

        # Push the resolved network settings into the shared HTTP helper so
        # every tool/adapter uses the configured timeout/SSL policy.
        net_configure(timeout=cfg.net.timeout, verify_ssl=cfg.net.verify_ssl,
                      user_agent=cfg.net.user_agent)
        _apply_no_sweep(args.no_sweep)

        manifest = _load_manifest(cfg)
        adapter = _build_adapter(cfg, manifest)
        challenges = adapter.list_challenges()
        if not challenges:
            _emit(f"[main] error: no challenges available in mode "
                  f"'{cfg.adapter.mode}'.")
            _emit("[main] pass --challenges-file <manifest.json> or configure "
                  "the platform URL/token in config.yaml.")
            return 2

        llm = _build_llm(cfg)
        budget = Budget(cfg.budget.max_steps, cfg.budget.max_elapsed,
                        cfg.budget.max_tokens)

        _emit(f"[main] mode={cfg.adapter.mode} llm={llm.name} "
              f"challenges={len(challenges)} budget_steps={budget.max_steps}")

        on_done = _on_done if args.trace else None
        try:
            results = run_benchmark(challenges, adapter, llm, budget,
                                    on_done=on_done,
                                    run_max_elapsed=cfg.budget.run_max_elapsed)
        finally:
            try:
                adapter.close()
            except Exception:
                pass

        _print_scoreboard(results)

        if args.trace:
            _print_react_trace(results)

        trace_path = _write_trace(cfg, results)
        _emit(f"[main] trace JSONL: {trace_path}")

        if args.report:
            try:
                from reports.gen_report import generate_report
                title = (f"AutoVulnAgent Report — {cfg.adapter.mode} mode, "
                         f"{len(results)} challenges")
                report_path = generate_report(results, out_dir=cfg.report.out_dir,
                                              title=title)
                if report_path:
                    _emit(f"[main] markdown report: {report_path}")
                else:
                    _emit("[main] markdown report written")
            except Exception as exc:
                _emit(f"[main] warning: report generation failed "
                      f"({type(exc).__name__}: {exc})")

        if args.json:
            sys.stdout.write(json.dumps(_summary_data(results, llm, cfg.adapter.mode),
                                        ensure_ascii=False) + "\n")

        solved = sum(1 for r in results if r.passed)
        return 0 if solved > 0 else 1
    except Exception as exc:
        _emit(f"[main] error: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
