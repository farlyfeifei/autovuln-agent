"""Context helpers: observation compression + history summaries for the LLM prompt."""
from __future__ import annotations

from typing import List

from .flags import extract_flags, extract_hex_tokens
from .types import Step


def trim_observation(obs: str, max_chars: int = 2000) -> str:
    """Truncate a long observation while keeping the head (and a tail hint)."""
    if obs is None:
        return ""
    if len(obs) <= max_chars:
        return obs
    keep = max(max_chars - 40, 0)
    return obs[:keep] + f"\n... [truncated, total {len(obs)} chars]"


def summarize_history(history: List[Step], max_chars: int = 4000) -> str:
    """Render the ReAct history compactly for the LLM, keeping recent steps."""
    if not history:
        return "(no prior steps)"
    lines: List[str] = []
    for st in history[-12:]:  # keep the most relevant recent window
        lines.append(f"Step {st.index} · thought: {st.thought}")
        lines.append(f"  action: {st.action}")
        obs = trim_observation(st.observation, 400)
        lines.append(f"  observation: {obs}")
    text = "\n".join(lines)
    if len(text) > max_chars:
        # keep the tail (most recent) when still too big; clamp so tiny
        # max_chars values can never produce a slice longer than the limit
        tail = max(max_chars - 60, 0)
        if tail <= 0:
            return "(history too large to summarize)"[:max_chars]
        return "... (older steps dropped)\n" + text[-tail:]
    return text


def last_observation(history: List[Step]) -> str:
    return history[-1].observation if history else ""


def seen_flags(history: List[Step]) -> List[str]:
    """Every distinct flag observed so far, in first-seen order."""
    seen: List[str] = []
    for st in history:
        for f in st.flags:
            if f not in seen:
                seen.append(f)
    return seen


def combined_observations(history: List[Step]) -> str:
    """Concatenate all observations (used for final flag sweep before giving up)."""
    return "\n".join(st.observation for st in history if st.observation)


def sweep_flags(history: List[Step]) -> List[str]:
    """Extract flags from the whole history — used as a last resort.

    Brace-style flags first; long hex tokens (e.g. md5/sha hashes used as
    flags) are a secondary signal so they are still recoverable.
    """
    text = combined_observations(history)
    flags = extract_flags(text)
    return flags if flags else extract_hex_tokens(text)
