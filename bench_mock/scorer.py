"""Scoring: compare submitted flags with ground truth and aggregate results."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:  # avoid a runtime import cycle with orchestrator
    from .challenges import Challenge
    from .orchestrator import ChallengeResult


def normalize_flag(flag: Optional[str]) -> str:
    """Trim surrounding whitespace; ``None`` becomes the empty string."""
    return (flag or "").strip()


def score_submission(challenge: "Challenge", submitted_flag: Optional[str]) -> Tuple[bool, int]:
    """Return ``(passed, points_awarded)`` for a single submission."""
    passed = normalize_flag(submitted_flag) == normalize_flag(challenge.ground_truth_flag)
    return passed, (challenge.points if passed else 0)


@dataclass
class Scoreboard:
    """Aggregate view over a list of :class:`ChallengeResult`."""

    results: List["ChallengeResult"]

    @property
    def total_count(self) -> int:
        return len(self.results)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def total_score(self) -> int:
        return sum(r.points_awarded for r in self.results)

    @property
    def total_possible(self) -> int:
        return sum(r.points_possible for r in self.results)

    @property
    def pass_rate(self) -> float:
        return (self.pass_count / self.total_count * 100.0) if self.total_count else 0.0

    @property
    def score_pct(self) -> float:
        return (self.total_score / self.total_possible * 100.0) if self.total_possible else 0.0

    @property
    def avg_steps(self) -> float:
        return (sum(r.steps_used for r in self.results) / self.total_count) if self.total_count else 0.0

    @property
    def total_time(self) -> float:
        return sum(r.elapsed_sec for r in self.results)
