"""Shared data model for the whole agent pipeline.

These dataclasses are the single source of truth for the interfaces every
module depends on. Keep them frozen/stable — parallel tool/llm/adapter modules
import from here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class Challenge:
    """One benchmark target. ``ground_truth_flag`` is only known in mock/local
    scoring; in live mode it is ``None`` and correctness comes from the adapter's
    ``submit()`` return value."""

    id: str
    name: str
    category: str
    description: str
    target: str
    points: int = 0
    ground_truth_flag: Optional[str] = None
    # mock-only metadata (used by the mock adapter to leak the flag on the
    # "winning" tool call; ignored in live mode)
    win_tool: Optional[str] = None
    win_params: dict = field(default_factory=dict)
    solvable: bool = True
    extra: dict = field(default_factory=dict)


@dataclass
class Budget:
    """Per-challenge execution budget for the ReAct loop."""

    max_steps: int = 15
    max_elapsed: float = 300.0  # seconds
    max_tokens: int = 200_000   # LLM prompt+completion token budget


@dataclass
class Action:
    """A single decision produced by the LLM / policy in the ReAct loop."""

    tool: str = "noop"
    params: dict = field(default_factory=dict)
    thought: str = ""
    flag: Optional[str] = None     # set only when is_submit=True
    is_submit: bool = False
    is_give_up: bool = False

    def __repr__(self) -> str:  # keep trace log lines compact
        if self.is_submit:
            return f"submit(flag={self.flag!r})"
        if self.is_give_up:
            return "give_up"
        return f"{self.tool}({self.params!r})"


@dataclass
class ToolResult:
    """Output of a tool execution fed back into the agent as an observation."""

    tool: str
    observation: str
    params: dict = field(default_factory=dict)
    flags: List[str] = field(default_factory=list)
    ok: bool = True
    exit_code: Optional[int] = None
    raw: str = ""


@dataclass
class Step:
    """One recorded ReAct step."""

    index: int
    thought: str
    action: str
    observation: str
    flags: List[str] = field(default_factory=list)
    tool: str = ""
    params: dict = field(default_factory=dict)
    elapsed: float = 0.0
    tokens: dict = field(default_factory=dict)  # {"prompt": n, "completion": m}


@dataclass
class ChallengeResult:
    """Outcome of attempting one challenge."""

    challenge_id: str
    name: str
    category: str
    passed: bool
    submitted_flag: Optional[str]
    ground_truth_flag: Optional[str]
    points_awarded: int
    points_possible: int
    steps_used: int
    elapsed_sec: float
    trace: List[Step] = field(default_factory=list)
    tokens: dict = field(default_factory=dict)
    error: Optional[str] = None
