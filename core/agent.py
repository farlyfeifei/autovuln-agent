"""ReAct orchestration: the bounded decision loop for a single challenge.

``LLM decides -> tool executes -> observe -> extract flag -> (submit | loop)``
until the agent submits a flag or the budget (steps / elapsed / tokens) runs out.
A final whole-history flag sweep is done before giving up, so a flag observed by
a real LLM but never explicitly submitted is still recovered.

Adapters that provision targets (e.g. TSecBench containers) implement the
optional ``start`` / ``close_challenge`` lifecycle hooks; ``start`` runs before
the decision loop and ``close_challenge`` is guaranteed to run in a ``finally``
block so container resources are always released.
"""
from __future__ import annotations

import time
from typing import Callable, List, Optional

from core.context import sweep_flags
from core.types import Budget, Challenge, ChallengeResult, Step
from adapters.base import Adapter
from llm.base import BaseLLM


def solve_challenge(
    challenge: Challenge,
    adapter: Adapter,
    llm: BaseLLM,
    budget: Budget,
) -> ChallengeResult:
    """Attempt one challenge with a bounded ReAct loop."""
    registry = adapter.tool_registry()
    history: List[Step] = []
    submitted: Optional[str] = None
    error: Optional[str] = None
    steps_used = 0
    start = time.perf_counter()
    prompt_before = llm.usage.prompt_tokens
    comp_before = llm.usage.completion_tokens
    tokens_before = llm.usage.total_tokens
    # ``accepted`` is the ground truth for scoring: a flag the platform (or the
    # mock's ground truth) actually confirmed. Merely *producing* a flag string
    # does not solve the challenge — a rejected submit must not count as solved.
    accepted = False
    progress: Optional[dict] = None
    flag_progress = getattr(adapter, "flag_progress", None)

    challenge = adapter.start(challenge)
    try:
        while True:
            if time.perf_counter() - start > budget.max_elapsed:
                error = "budget: max_elapsed exceeded"
                break
            if steps_used >= budget.max_steps:
                error = "budget: max_steps exhausted"
                break
            if (budget.max_tokens > 0
                    and llm.usage.total_tokens - tokens_before >= budget.max_tokens):
                error = "budget: max_tokens exceeded"
                break

            remaining = max(0.0, budget.max_elapsed - (time.perf_counter() - start))
            loop_budget = Budget(budget.max_steps, remaining, budget.max_tokens)
            action = llm.decide(challenge, history, loop_budget)

            if action.is_submit:
                submitted = (action.flag or "").strip()
                ok = adapter.submit(challenge, submitted)
                if ok:
                    accepted = True
                progress = flag_progress(challenge) if flag_progress else None
                # A multi-flag challenge keeps going: the platform accepted this
                # flag but more remain, so feed that back and continue hunting
                # instead of treating the challenge as finished.
                if ok and isinstance(progress, dict):
                    correct = int(progress.get("correct") or 0)
                    total = int(progress.get("total") or 1)
                    challenge.extra["correct_flag_count"] = correct
                    challenge.extra["total_flag_count"] = total
                    if correct < total:
                        history.append(Step(
                            index=len(history) + 1,
                            thought=action.thought,
                            action=f"submit(flag={submitted!r})",
                            observation=(f"[platform] flag accepted "
                                         f"({correct}/{total}) — "
                                         f"{total - correct} more flag(s) "
                                         "remain; keep hunting."),
                            flags=[submitted] if submitted else [],
                        ))
                        steps_used += 1
                        continue
                history.append(Step(
                    index=len(history) + 1,
                    thought=action.thought,
                    action=f"submit(flag={submitted!r})",
                    observation="[platform] flag received, queued for judging"
                                if ok else "[platform] submission rejected",
                    flags=[submitted] if submitted else [],
                ))
                break

            if action.is_give_up or action.tool in ("noop", "", "give_up"):
                history.append(Step(
                    index=len(history) + 1,
                    thought=action.thought,
                    action="give_up" if action.is_give_up else "noop",
                    observation="[agent] halting: no further actions",
                ))
                break

            res = registry.run(action.tool, challenge, action.params)
            steps_used += 1
            history.append(Step(
                index=len(history) + 1,
                thought=action.thought,
                action=f"{res.tool}({action.params!r})",
                observation=res.observation,
                flags=res.flags,
                tool=res.tool,
                params=action.params,
                elapsed=time.perf_counter() - start,
                tokens={},
            ))

        # Final sweep: a flag may have appeared in observations without an explicit
        # submit decision, or the LLM may have submitted a wrong/empty flag while the
        # real one was already observed. Only run it when nothing was accepted yet.
        if not accepted:
            sweep = sweep_flags(history)
            if sweep:
                submitted = sweep[0]
                ok = adapter.submit(challenge, submitted)
                if ok:
                    accepted = True
                progress = flag_progress(challenge) if flag_progress else None
                history.append(Step(
                    index=len(history) + 1,
                    thought="Final sweep recovered a flag from the transcript.",
                    action=f"submit(flag={submitted!r})",
                    observation="[platform] flag received (via final sweep)" if ok
                                else "[platform] submission rejected (final sweep)",
                    flags=[submitted],
                ))
                steps_used += 1
                error = "recovered via final sweep" if error is None else error
    finally:
        try:
            adapter.close_challenge(challenge)
        except Exception:  # a broken lifecycle hook must not mask the result
            pass

    elapsed = time.perf_counter() - start
    # Points come from the platform when it reports per-flag progress (a
    # multi-flag challenge pays per accepted flag); otherwise a solved challenge
    # is worth its full point value.
    if isinstance(progress, dict) and progress.get("awarded") is not None:
        points_awarded = int(progress.get("awarded") or 0)
    else:
        points_awarded = challenge.points if accepted else 0

    tokens = {
        "prompt": llm.usage.prompt_tokens - prompt_before,
        "completion": llm.usage.completion_tokens - comp_before,
    }
    return ChallengeResult(
        challenge_id=challenge.id,
        name=challenge.name,
        category=challenge.category,
        passed=accepted,
        submitted_flag=submitted,
        ground_truth_flag=challenge.ground_truth_flag,
        points_awarded=points_awarded,
        points_possible=challenge.points,
        steps_used=steps_used,
        elapsed_sec=elapsed,
        trace=history,
        tokens=tokens,
        error=error,
    )


def run_benchmark(
    challenges: List[Challenge],
    adapter: Adapter,
    llm: BaseLLM,
    budget: Budget,
    on_start: Optional[Callable[[Challenge], None]] = None,
    on_done: Optional[Callable[[ChallengeResult], None]] = None,
    run_max_elapsed: Optional[float] = None,
) -> List[ChallengeResult]:
    """Run every challenge sequentially, reporting per-challenge progress.

    ``run_max_elapsed`` (optional, seconds) caps the whole run so a long
    challenge list can never outlive the platform's total timeout: once the
    wall clock passes it, no new challenge is started. The in-flight challenge
    still finishes under its own per-challenge budget.
    """
    results: List[ChallengeResult] = []
    wall_start = time.perf_counter()
    for ch in challenges:
        if (run_max_elapsed is not None
                and time.perf_counter() - wall_start >= run_max_elapsed):
            break
        if on_start:
            on_start(ch)
        result = solve_challenge(ch, adapter, llm, budget)
        results.append(result)
        if on_done:
            on_done(result)
    return results
