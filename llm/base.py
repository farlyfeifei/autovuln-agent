"""LLM interface contract.

Any decision brain (deterministic policy or a real model) implements
``decide(challenge, history, budget) -> Action``. That is the only method the
ReAct loop calls, which is what makes the model layer pluggable.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List

from core.types import Action, Budget, Challenge, Step


@dataclass
class LLMUsage:
    """Token/call accounting so the report can price every run."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def add(self, prompt: int = 0, completion: int = 0, calls: int = 1) -> None:
        self.prompt_tokens += int(prompt)
        self.completion_tokens += int(completion)
        self.calls += int(calls)

    def merge(self, other: "LLMUsage") -> None:
        self.add(other.prompt_tokens, other.completion_tokens, other.calls)


class BaseLLM(ABC):
    name: str = "base"

    def __init__(self) -> None:
        self.usage = LLMUsage()

    @abstractmethod
    def decide(self, challenge: Challenge, history: List[Step], budget: Budget) -> Action:
        """Produce the next action given the challenge and ReAct history."""

    def usage_summary(self) -> str:
        return (f"{self.name}: {self.usage.calls} calls, "
                f"{self.usage.total_tokens} tokens "
                f"({self.usage.prompt_tokens} prompt / {self.usage.completion_tokens} completion)")
