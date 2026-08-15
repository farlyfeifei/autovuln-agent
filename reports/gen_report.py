"""Markdown run-report generation from :class:`ChallengeResult` objects.

Pure computation + local file output; never touches the network and never
raises. ``generate_report`` writes a timestamped ``run_YYYYmmdd_HHMMSS.md``
(plus an optional category-bar chart PNG when matplotlib is available) and
returns the absolute path of the report file.
"""
from __future__ import annotations

import datetime as _dt
import os
from typing import List

from bench.scoreboard import Scoreboard
from core.types import ChallengeResult

# Default price assumptions for an OpenAI-class API (USD per 1M tokens).
_PRICE_PROMPT = 2.0
_PRICE_COMPLETION = 8.0

_TRACE_CHARS = 200  # per-line trace trimming limit


def estimate_cost(
    prompt_tokens: int,
    completion_tokens: int,
    price_per_1m_prompt: float = _PRICE_PROMPT,
    price_per_1m_completion: float = _PRICE_COMPLETION,
) -> float:
    """Estimate LLM cost in USD for a token mix, rounded to 2 decimals."""
    try:
        prompt = max(float(prompt_tokens), 0.0)
        completion = max(float(completion_tokens), 0.0)
        prompt_price = max(float(price_per_1m_prompt), 0.0)
        completion_price = max(float(price_per_1m_completion), 0.0)
    except (TypeError, ValueError):
        return 0.0
    cost = prompt * prompt_price / 1_000_000.0 + completion * completion_price / 1_000_000.0
    return round(cost, 2)


def _discovery_rate(board: Scoreboard) -> float:
    """Fraction of challenges that were at least attempted (a scoreable run)."""
    return (board.pass_count * 100.0 / board.total_count) if board.total_count else 0.0


def _false_positives(results: List[ChallengeResult]) -> int:
    """Count wrong submissions: solved-looking attempts that judged incorrect.

    A result counts when a flag was submitted (or one was recovered from the
    trace) but the challenge was not passed — i.e. the submission was rejected.
    """
    count = 0
    for r in results:
        submitted = bool((r.submitted_flag or "").strip())
        if not submitted:
            # nothing submitted but a flag surfaced in the trace => rejected
            submitted = any(st.flags for st in getattr(r, "trace", []) or [])
        if submitted and not r.passed:
            count += 1
    return count


def _avg_solved_time(board: Scoreboard) -> float:
    """Mean wall-clock time of the challenges that were actually solved."""
    solved = [r for r in board.results if r.passed]
    if not solved:
        return 0.0
    return sum(r.elapsed_sec for r in solved) / len(solved)


def _ascii_bars(categories: List[str], solved: List[int], width: int = 40) -> str:
    """Render a simple horizontal bar chart of solved counts as text."""
    if not categories:
        return "(no categories)"
    max_value = max(solved) or 1
    lines: List[str] = []
    for name, value in zip(categories, solved):
        bar = "#" * max(1, int(round(value / max_value * width))) if value else ""
        lines.append(f"{name:<14} {value:>3} |{bar}")
    return "\n".join(lines)


def _render_chart(board: Scoreboard, out_dir: str) -> str:
    """Best-effort chart: matplotlib PNG if available, ASCII fallback otherwise.

    Returns the PNG filename (for the report to reference) or ``""`` when the
    chart could only be rendered as ASCII text.
    """
    breakdown = board.by_category()
    categories = list(breakdown)
    solved = [breakdown[c]["solved"] for c in categories]

    try:  # optional dependency: degrade silently to ASCII bars if unavailable
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return ""

    try:
        fig, ax = plt.subplots(figsize=(6, max(2.5, 0.4 * len(categories))))
        ax.barh(categories, solved, color="#4c78a8")
        ax.set_xlabel("solved challenges")
        ax.set_title("Solved per category")
        fig.tight_layout()
        png_name = "category_solved.png"
        fig.savefig(os.path.join(out_dir, png_name), dpi=120)
        plt.close(fig)
        return png_name
    except Exception:
        return ""


def _trace_section(results: List[ChallengeResult]) -> str:
    """Markdown appendix listing each solved challenge's ReAct trace."""
    lines: List[str] = ["## Trace", ""]
    found = False
    for r in results:
        steps = [st for st in getattr(r, "trace", []) or [] if (st.action or "").strip()]
        if not steps:
            continue
        found = True
        lines.append(f"### {r.challenge_id} — {r.name}  ({'PASS' if r.passed else 'FAIL'})")
        lines.append("")
        for st in steps:
            action = _trim_line(st.action)
            observation = _trim_line(st.observation)
            lines.append(f"- **step {st.index}** `{action}`")
            if observation:
                lines.append(f"  {observation}")
            if st.flags:
                lines.append(
                    "  **flags:** " + ", ".join(str(f) for f in st.flags)
                )
        lines.append("")
    if not found:
        lines.append("_No step traces recorded for any challenge._")
        lines.append("")
    return "\n".join(lines)


def _trim_line(text: str, max_chars: int = _TRACE_CHARS) -> str:
    """Flatten whitespace and truncate a single trace line."""
    if not text:
        return ""
    line = " ".join(text.split())
    if len(line) <= max_chars:
        return line
    return line[: max_chars - 1] + "…"


def generate_report(
    results: List[ChallengeResult],
    *,
    out_dir: str = "reports",
    title: str = "AutoVulnAgent Run Report",
    note: str = "",
) -> str:
    """Write a Markdown run report and return its absolute path.

    Never raises: missing directories are created, chart rendering degrades to
    ASCII, and every individual step is best-effort.
    """
    board = Scoreboard(results)
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError:
        out_dir = os.getcwd()

    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"run_{stamp}.md"
    path = os.path.abspath(os.path.join(out_dir, filename))
    n = 1
    while os.path.exists(path):
        path = os.path.abspath(os.path.join(out_dir, f"run_{stamp}_{n}.md"))
        n += 1

    png_name = _render_chart(board, out_dir)

    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"_Generated {_dt.datetime.now().isoformat(timespec='seconds')}_")
    if note:
        lines.append("")
        lines.append(f"> {note}")
    lines.append("")

    # summary table (from the Scoreboard)
    lines.append("## Summary")
    lines.append("")
    lines.append("```text")
    lines.append(board.table())
    lines.append("```")
    lines.append("")
    lines.extend(f"{line}  " for line in board.summary_lines())
    lines.append("")

    # quant metrics block
    lines.append("## Quantitative Metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Discovery rate | {_discovery_rate(board):.1f}% |")
    lines.append(f"| False positives (rejected submissions) | {_false_positives(results)} |")
    lines.append(f"| Avg time per solved challenge | {_avg_solved_time(board):.2f}s |")
    lines.append(f"| Total prompt tokens | {board.total_prompt_tokens} |")
    lines.append(f"| Total completion tokens | {board.total_completion_tokens} |")
    lines.append(f"| Total tokens | {board.total_tokens} |")
    lines.append(
        f"| Estimated cost | ${estimate_cost(board.total_prompt_tokens, board.total_completion_tokens):.2f} |"
    )
    lines.append("")

    # per-category breakdown
    lines.append("## Per-Category Breakdown")
    lines.append("")
    breakdown = board.by_category()
    if breakdown:
        lines.append("| Category | Solved | Total | Points (possible) |")
        lines.append("|---|---|---|---|")
        for name, info in breakdown.items():
            lines.append(
                f"| {name} | {info['solved']} | {info['total']} | {info['points']} |"
            )
    else:
        lines.append("_(no challenges in this run)_")
    lines.append("")

    # chart (PNG reference when one was rendered, ASCII fallback otherwise)
    lines.append("### Solved per category")
    lines.append("")
    if png_name:
        lines.append(f"![solved per category]({png_name})")
    else:
        lines.append("```text")
        lines.append(_ascii_bars(list(breakdown), [breakdown[c]["solved"] for c in breakdown]))
        lines.append("```")
    lines.append("")

    lines.append(_trace_section(results))

    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines).rstrip() + "\n")
    except OSError:
        path = os.path.abspath(filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines).rstrip() + "\n")
    return path
