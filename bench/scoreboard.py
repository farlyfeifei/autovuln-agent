"""Run-level scoring: aggregate :class:`ChallengeResult` objects into a table.

Pure computation over the results produced by the ReAct loop — no network, no
filesystem. ``Scoreboard`` computes pass/solve/score aggregates, a per-category
breakdown and token/time summaries; ``reports.gen_report`` renders those into a
human-readable Markdown report.
"""
from __future__ import annotations

from typing import Dict, List

from core.types import ChallengeResult

# Fixed-width column widths for :meth:`Scoreboard.table` (keep in sync with the
# header + the separator row below).
_COLUMNS = (
    ("ID", 10),
    ("CATEGORY", 12),
    ("RESULT", 7),
    ("STEPS", 5),
    ("TIME(s)", 9),
    ("POINTS", 8),
    ("FLAG", 40),
)


def _fmt_flag(value: object) -> str:
    """Render a submitted flag compactly; never exceed the column width."""
    if value is None:
        return "(none)"
    text = str(value).strip()
    if not text:
        return "(none)"
    return text if len(text) <= 40 else text[:36] + "..."


class Scoreboard:
    """Aggregate statistics over a benchmark run."""

    def __init__(self, results: List[ChallengeResult]) -> None:
        self.results: List[ChallengeResult] = list(results)

    # ------------------------------------------------------------------ totals
    @property
    def total_count(self) -> int:
        return len(self.results)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def total_score(self) -> int:
        return sum(int(r.points_awarded) for r in self.results)

    @property
    def total_possible(self) -> int:
        return sum(int(r.points_possible) for r in self.results)

    @property
    def pass_rate(self) -> float:
        """Percentage of challenges solved (0.0 .. 100.0)."""
        n = self.total_count
        return (self.pass_count * 100.0 / n) if n else 0.0

    @property
    def score_pct(self) -> float:
        """Points won as a percentage of the maximum available (0.0 .. 100.0)."""
        total = self.total_possible
        return (self.total_score * 100.0 / total) if total else 0.0

    @property
    def avg_steps(self) -> float:
        """Mean number of steps across all challenges (including failures)."""
        n = self.total_count
        return (sum(r.steps_used for r in self.results) / n) if n else 0.0

    @property
    def total_time(self) -> float:
        """Total wall-clock time (seconds) spent on every challenge."""
        return sum(r.elapsed_sec for r in self.results)

    # ------------------------------------------------------------------ tokens
    @property
    def total_prompt_tokens(self) -> int:
        return sum(_tokens(r, "prompt") for r in self.results)

    @property
    def total_completion_tokens(self) -> int:
        return sum(_tokens(r, "completion") for r in self.results)

    @property
    def total_tokens(self) -> int:
        return self.total_prompt_tokens + self.total_completion_tokens

    # ------------------------------------------------------------- breakdowns
    def by_category(self) -> Dict[str, Dict[str, int]]:
        """Per-category ``{"solved", "total", "points"}``, sorted by name.

        ``points`` is the sum of *possible* points per category, so the report
        can show how much of each category was claimed.
        """
        cats: Dict[str, Dict[str, int]] = {}
        for r in self.results:
            entry = cats.setdefault(
                r.category or "unknown", {"solved": 0, "total": 0, "points": 0}
            )
            entry["total"] += 1
            entry["points"] += int(r.points_possible)
            if r.passed:
                entry["solved"] += 1
        return {name: cats[name] for name in sorted(cats)}

    # ------------------------------------------------------------- rendering
    def table(self) -> str:
        """A clean fixed-width text table: ID / CATEGORY / RESULT / STEPS /
        TIME / POINTS / FLAG."""
        header = "  ".join(label.ljust(width) for label, width in _COLUMNS)
        sep = "-" * len(header)
        lines = [header, sep]
        for r in self.results:
            status = "PASS" if r.passed else "FAIL"
            points = str(r.points_awarded) if r.passed else (
                f"0/{r.points_possible}"
            )
            lines.append(
                "  ".join(
                    (
                        (r.challenge_id or "?").ljust(10),
                        (r.category or "?").ljust(12),
                        status.ljust(7),
                        str(r.steps_used).ljust(5),
                        f"{r.elapsed_sec:.2f}".ljust(9),
                        points.ljust(8),
                        _fmt_flag(r.submitted_flag),
                    )
                )
            )
        lines.append(sep)
        return "\n".join(lines)

    def summary_lines(self) -> List[str]:
        """One-line-per-metric summary: solve count, score, percentages, steps,
        time and token usage."""
        return [
            f"solved: {self.pass_count}/{self.total_count}",
            f"score: {self.total_score}/{self.total_possible}",
            f"pass rate: {self.pass_rate:.1f}%   score pct: {self.score_pct:.1f}%",
            f"avg steps: {self.avg_steps:.1f}",
            f"total time: {self.total_time:.2f}s",
            f"tokens: {self.total_tokens} "
            f"({self.total_prompt_tokens} prompt / {self.total_completion_tokens} completion)",
        ]


def _tokens(result: ChallengeResult, key: str) -> int:
    """Read a token bucket from a result, tolerating missing/odd shapes.

    ``result.tokens`` is a plain ``dict`` (e.g. ``{"prompt": n, "completion": m}``)
    so defensive parsing keeps the scoreboard robust to sloppy producers.
    """
    raw = result.tokens or {}
    try:
        value = int(raw.get(key, 0))
    except (TypeError, ValueError):
        value = 0
    return max(value, 0)
