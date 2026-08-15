"""Adapter interface contract.

An adapter provides the three things the ReAct loop needs, regardless of the
underlying platform:

* ``list_challenges()``      — the challenge set to attempt
* ``tool_registry()``        — the tools to execute (mock tools in offline mode,
                               real tools in live mode)
* ``submit(challenge, flag)``— push a recovered flag to the scoring platform

Targets that must be provisioned before solving (e.g. a container started per
challenge) implement the two optional lifecycle hooks ``start`` /
``close_challenge``. The ReAct loop calls ``start`` before the decision loop
and guarantees ``close_challenge`` runs in a ``finally`` block, so adapters
can hold resources (containers, sessions) per challenge safely.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from core.types import Challenge
from tools.registry import ToolRegistry


class Adapter(ABC):
    name: str = "base"

    @abstractmethod
    def list_challenges(self) -> List[Challenge]:
        ...

    @abstractmethod
    def tool_registry(self) -> ToolRegistry:
        ...

    def submit(self, challenge: Challenge, flag: str) -> bool:
        """Default: submission is meaningless unless an adapter implements it."""
        return False

    def flag_progress(self, challenge: Challenge) -> Optional[dict]:
        """Post-submit per-flag progress ``{"correct": int, "total": int,
        "awarded": int}`` for challenges that can hold several flags.

        ``None`` (default) signals a single-flag challenge with no platform-level
        tracking — the ReAct loop treats one successful submit as terminal.
        """
        return None

    def start(self, challenge: Challenge) -> Challenge:
        """Provision ``challenge``'s target before solving. Default: no-op."""
        return challenge

    def close_challenge(self, challenge: Challenge) -> None:
        """Release ``challenge``'s resources after solving. Default: no-op."""
        pass

    def close(self) -> None:
        pass
