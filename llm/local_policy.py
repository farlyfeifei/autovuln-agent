"""Deterministic ReAct policy — the zero-dependency fallback "brain".

Used when no LLM API key is configured, for local mock runs, or as a baseline
for A/B comparison. Follows a category-specific action chain; submits as soon
as a flag appears in the latest observation; gives up when the plan is spent.
"""
from __future__ import annotations

from typing import Dict, List

from core.flags import extract_flag
from core.types import Action, Budget, Challenge, Step
from llm.base import BaseLLM


# Category -> ordered list of tool actions the policy will attempt, in order.
# These names and params MUST exist in the tool registry and in the mock
# challenge bank's win paths so a mock run passes end-to-end.
CATEGORY_PLANS: Dict[str, List[Dict]] = {
    "web-sqli": [
        {"tool": "http_probe", "params": {"path": "/login"},
         "thought": "Map the login endpoint before attacking the auth form."},
        {"tool": "sqli", "params": {"param": "user", "technique": "union"},
         "thought": "Login form looks injectable; try a UNION-based dump of the users table."},
    ],
    "web-xss": [
        {"tool": "http_probe", "params": {"path": "/search", "params": {"q": "test"}},
         "thought": "Probe the search page to see how the 'q' parameter is reflected."},
        {"tool": "xss", "params": {"param": "q"},
         "thought": "Reflection is unescaped; inject a script payload to steal the cookie."},
    ],
    "recon-info": [
        {"tool": "http_probe", "params": {"path": "/"},
         "thought": "Grab the root page and headers to understand the target."},
        {"tool": "dir_enum", "params": {"depth": 2},
         "thought": "Deep-enumerate directories to find exposed backup/config files."},
    ],
    "web-lfi": [
        {"tool": "http_probe", "params": {"path": "/view?file=index.html"},
         "thought": "Check the viewer's normal behaviour with a benign file first."},
        {"tool": "lfi", "params": {"path": "/view", "param": "file",
                                   "traversal": "../../../../etc/passwd"},
         "thought": "No sanitisation seen; try classic path traversal on the file param to read /etc/passwd."},
    ],
    "crypto-weak": [
        {"tool": "http_probe", "params": {"path": "/token"},
         "thought": "Grab the service banner and the captured token from the oracle."},
        {"tool": "decode", "params": {"scheme": "xor"},
         "thought": "The token is weakly 'protected'; brute the single-byte XOR key."},
    ],
    "web-idor": [
        {"tool": "http_probe", "params": {"path": "/api/user/1"},
         "thought": "Inspect our own user object to learn the response shape."},
        {"tool": "idor", "params": {"id": 1, "count": 6},
         "thought": "No authz check observed; enumerate from our own low-privilege id to read another user."},
    ],
    "web-ssrf": [
        {"tool": "http_probe", "params": {"path": "/fetch", "params": {"u": "http://127.0.0.1/"}},
         "thought": "Find a parameter that performs server-side requests."},
        {"tool": "ssrf", "params": {"param": "u", "target": "http://169.254.169.254/"},
         "thought": "Try the cloud metadata endpoint through the fetch parameter."},
    ],
}


class LocalPolicyLLM(BaseLLM):
    """Deterministic decision policy standing in for a real LLM."""

    name: str = "local-policy"

    def decide(self, challenge: Challenge, history: List[Step], budget: Budget) -> Action:
        # 1) If the last observation revealed a flag, submit it.
        if history:
            flag = extract_flag(history[-1].observation)
            if flag:
                return Action(
                    tool="submit", flag=flag, is_submit=True,
                    thought=f"The last observation contains '{flag}'; submitting it.",
                )
        # 2) Otherwise follow the category plan by number of tool calls taken.
        plan = CATEGORY_PLANS.get(challenge.category, [])
        idx = len(history)
        if idx < len(plan):
            step = plan[idx]
            return Action(tool=step["tool"], params=dict(step["params"]), thought=step["thought"])
        # 3) Plan exhausted without a flag.
        return Action(tool="give_up", is_give_up=True,
                      thought="Exhausted my plan without recovering a flag for this challenge.")
