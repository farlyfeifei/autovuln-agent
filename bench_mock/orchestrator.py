"""ReAct orchestration for a single challenge.

Runs the loop ``LLM decides -> tool executes -> observe -> extract flag`` until
the agent submits a flag or the per-challenge step budget is exhausted. Records
a full trace and delegates final judging to :mod:`bench_mock.scorer`.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .challenges import Challenge
from .mock_llm import Action, MockLLM
from .mock_tools import ToolRegistry
from .scorer import score_submission


@dataclass
class Step:
    """One recorded ReAct step (thought / action / observation)."""

    index: int
    thought: str
    action: str
    observation: str


@dataclass
class ChallengeResult:
    """Outcome of attempting a single challenge."""

    challenge_id: str
    name: str
    category: str
    passed: bool
    submitted_flag: Optional[str]
    ground_truth_flag: str
    points_awarded: int
    points_possible: int
    steps_used: int
    elapsed_sec: float
    trace: List[Step] = field(default_factory=list)


def _fmt_params(params: Dict[str, Any]) -> str:
    if not params:
        return ""
    return ", ".join(f"{k}={v!r}" for k, v in params.items())


def solve_challenge(
    challenge: Challenge,
    tools: ToolRegistry,
    llm: MockLLM,
    max_steps: int = 6,
) -> ChallengeResult:
    """Attempt a single challenge with a bounded ReAct loop."""
    history: List[Step] = []
    submitted_flag: Optional[str] = None
    steps_used = 0
    start = time.perf_counter()

    # max_steps caps tool executions; +1 allows the final "submit" turn.
    for _ in range(max_steps + 1):
        action = llm.decide(challenge, history)

        if action.is_submit:
            submitted_flag = action.flag
            history.append(
                Step(
                    index=len(history) + 1,
                    thought=action.thought,
                    action=f"submit(flag={action.flag!r})",
                    observation="[platform] flag received, queued for judging",
                )
            )
            break

        if action.tool in ("give_up", "noop"):
            history.append(
                Step(
                    index=len(history) + 1,
                    thought=action.thought,
                    action=action.tool,
                    observation="[agent] halting: no further actions",
                )
            )
            break

        if steps_used >= max_steps:
            history.append(
                Step(
                    index=len(history) + 1,
                    thought="Out of step budget before a flag was submitted.",
                    action="budget_exhausted",
                    observation="[agent] step limit reached",
                )
            )
            break

        observation = tools.run(action.tool, challenge, action.params)
        steps_used += 1
        history.append(
            Step(
                index=len(history) + 1,
                thought=action.thought,
                action=f"{action.tool}({_fmt_params(action.params)})",
                observation=observation,
            )
        )

    elapsed = time.perf_counter() - start
    passed, awarded = score_submission(challenge, submitted_flag)

    return ChallengeResult(
        challenge_id=challenge.id,
        name=challenge.name,
        category=challenge.category,
        passed=passed,
        submitted_flag=submitted_flag,
        ground_truth_flag=challenge.ground_truth_flag,
        points_awarded=awarded,
        points_possible=challenge.points,
        steps_used=steps_used,
        elapsed_sec=elapsed,
        trace=history,
    )
