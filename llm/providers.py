"""OpenAI-compatible chat-completions decision brain + provider factory.

``OpenAILikeProvider`` talks to any ``POST {base_url}/chat/completions``
endpoint (OpenAI, Zhipu GLM, DeepSeek, Baidu Comate, or any compatible
gateway) and turns the model's JSON reply into an :class:`Action` for the
ReAct loop. ``build_llm`` is the single entry point the orchestrator uses:
it falls back to the deterministic :class:`LocalPolicyLLM` whenever no API
key is configured so the agent stays fully usable offline.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Dict, List, Optional, Tuple

from core.context import summarize_history
from core.flags import extract_flag
from core.net import join, post
from core.types import Action, Budget, Challenge, Step
from llm.base import BaseLLM, LLMUsage
from tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Provider defaults (contract).  ``comate`` has NO baked-in default: it must
# come from config/env, which is exactly why those two entries are empty.
# ---------------------------------------------------------------------------
_DEFAULT_BASE_URLS: Dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "glm": "https://open.bigmodel.cn/api/paas/v4",
    "deepseek": "https://api.deepseek.com/v1",
    "comate": "",  # must come from config/env
    "opencode": "https://opencode.ai/zen/go/v1",  # OpenCode Go (OpenAI-compatible)
}
_DEFAULT_MODELS: Dict[str, str] = {
    "openai": "gpt-4o-mini",
    "glm": "glm-4-flash",
    "deepseek": "deepseek-chat",
    "comate": "",  # must come from config/env
    "opencode": "deepseek-v4-flash",  # OpenCode Go default (DeepSeek V4 flash)
}

# HTTP statuses worth retrying with a short backoff (429 rate-limit, 5xx,
# and status 0 which is what core.net returns for transport/timeout errors).
_RETRYABLE_STATUSES = frozenset([429, 500, 502, 503, 504, 0])

_MAX_ATTEMPTS = 3

_OUTPUT_SCHEMA = (
    '{"thought": "...", "action": "submit | give_up | <tool_name>", '
    '"params": {...}, "flag": "..."}'
)

# Category -> brief tactical guidance injected next to the challenge block so
# the model does not waste steps re-discovering an obvious attack chain.
CATEGORY_GUIDANCE: Dict[str, str] = {
    "web-sqli": ("Look for an injectable SQL parameter (auth bypass via OR 1=1 / "
                 "UNION-based dump), then extract credentials or the flag row."),
    "web-xss": ("Find a parameter reflected without output-encoding; try to read "
                "a cookie/session or the admin secret and submit it as the flag."),
    "web-lfi": ("A file-parameter likely performs a server-side file read; try path "
                "traversal to read configs, source or /etc/passwd."),
    "web-idor": ("Object endpoints usually trust client-supplied ids; increment them "
                 "to read another user's data containing the flag."),
    "web-ssrf": ("A fetch/url parameter performs server-side requests; pivot to "
                 "127.0.0.1 or the cloud metadata endpoint."),
    "recon-info": ("Enumerate the surface (directories, backups, .git, debug "
                   "endpoints) to find exposed configs that leak the flag."),
    "crypto-weak": ("The token/banner is likely weakly encoded (base64, hex, XOR) "
                    "or a crackable hash; decode it to recover the flag."),
}
_GENERIC_GUIDANCE = ("Probe the endpoint, confirm the vulnerability with a benign "
                     "request first, then attempt the exploit that yields the flag.")


def _extract_json_object(text: str) -> Optional[dict]:
    """Pull the first balanced ``{ ... }`` JSON object out of model text.

    Tolerant of markdown fences and of prose wrapped around the JSON: locate
    the first ``{``, then scan forward tracking string literals and brace
    depth until the matching ``}``, and ``json.loads`` that slice. Returns
    ``None`` when no parseable object can be found.
    """
    if not text:
        return None
    # Remove markdown code fences so the brace scanner sees the bare JSON.
    cleaned = re.sub(r"```(?:json)?\s*", "", text)
    start = cleaned.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(cleaned)):
        ch = cleaned[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(cleaned[start:i + 1])
                except Exception:
                    return None
    return None


class OpenAILikeProvider(BaseLLM):
    """Decision brain backed by an OpenAI-compatible chat-completions API."""

    name: str = "openai-like"

    def __init__(
        self,
        *,
        provider: str = "openai",
        model: str = "",
        base_url: str = "",
        api_key: str = "",
        temperature: float = 0.2,
        max_output_tokens: int = 1024,
        timeout: float = 120,
        registry: Optional[ToolRegistry] = None,
    ) -> None:
        super().__init__()
        self.provider = (provider or "openai").strip().lower()
        # Empty value -> provider default; comate intentionally has none and
        # must be supplied through config/env or decide() gives up cleanly.
        self.base_url = (base_url or _DEFAULT_BASE_URLS.get(self.provider, "")).rstrip("/")
        self.model = model or _DEFAULT_MODELS.get(self.provider, "")
        self.api_key = (api_key or "").strip()
        self.temperature = float(temperature)
        self.max_output_tokens = int(max_output_tokens)
        self.timeout = float(timeout)
        self._registry = registry
        self.name = f"openai-like({self.provider})"

    # ------------------------------------------------------------- public API

    def decide(self, challenge: Challenge, history: List[Step], budget: Budget) -> Action:
        """Build the prompt, call the model (with retries) and map to an Action.

        Never raises: every failure path degrades to ``Action(is_give_up=True,
        thought="LLM error: ...")``.
        """
        deadline = time.perf_counter() + max(0.0, budget.max_elapsed)
        try:
            if not self.model or not self.base_url:
                return self._give_up(
                    f"LLM error: provider {self.provider!r} needs a model and base_url "
                    "(set via config or LLM_MODEL/LLM_BASE_URL env)."
                )
            messages = self._build_messages(challenge, history, budget)
            content = self._request_with_retry(messages, deadline)
            if content is None:
                return self._give_up("LLM error: no usable response after retries")
            parsed = _extract_json_object(content)
            if parsed is None:
                # One corrective retry asking for strict JSON.
                corrected = self._request_with_retry(
                    self._append_correction(messages, content), deadline
                )
                if corrected is None:
                    return self._give_up("LLM error: correction call failed")
                parsed = _extract_json_object(corrected)
                if parsed is None:
                    return self._give_up(
                        "LLM error: model returned unparseable JSON after correction"
                    )
                content = corrected
            return self._to_action(parsed, content)
        except Exception as exc:  # final safety net — decide never raises
            return self._give_up(f"LLM error: {type(exc).__name__}: {exc}")

    def usage_summary(self) -> str:
        """Usage line including the concrete provider name."""
        return (f"{self.name}: {self.usage.calls} calls, "
                f"{self.usage.total_tokens} tokens "
                f"({self.usage.prompt_tokens} prompt / {self.usage.completion_tokens} completion)")

    # ------------------------------------------------------------- prompt box

    def _build_messages(self, challenge: Challenge, history: List[Step],
                        budget: Budget) -> List[Dict[str, str]]:
        system = (
            "You are an autonomous security researcher operating on an authorized "
            "CTF / vulnerability-discovery benchmark. You only ever test targets you "
            "are explicitly allowed to attack. Your job is to recover the challenge "
            "flag by choosing tools from the manifest and reading their observations.\n"
            "If any observation already contains a flag (flag{...}, CTF{...}, or a "
            "long hex token), submit it IMMEDIATELY with action \"submit\" — do not "
            "keep exploring.\n"
            "Some challenges contain MULTIPLE flags. If the platform accepts a flag "
            "but the observation says more flags remain, keep working until every "
            "flag is submitted — stopping early forfeits the rest of the score.\n"
            "You reply with ONLY a single JSON object — no markdown fences, no "
            "explanation, no prose. The object must match exactly this schema:\n"
            + _OUTPUT_SCHEMA
        )
        guidance = CATEGORY_GUIDANCE.get(challenge.category, _GENERIC_GUIDANCE)
        steps_remaining = max(0, budget.max_steps)
        secs_remaining = max(0.0, budget.max_elapsed)
        user = (
            "# Challenge\n"
            f"- id: {challenge.id}\n"
            f"- name: {challenge.name or '(untitled)'}\n"
            f"- category: {challenge.category}\n"
            f"- description: {challenge.description}\n"
            f"- target: {challenge.target}\n"
            f"- points: {challenge.points}\n"
            f"- flags recovered: {(challenge.extra or {}).get('correct_flag_count', 0)}/"
            f"{(challenge.extra or {}).get('total_flag_count', 1)}\n"
            "\n# Category guidance\n"
            f"{guidance}\n"
            "\n# Tools\n"
            f"{self._manifest()}\n"
            "\n# ReAct history (prior steps)\n"
            f"{summarize_history(history, 4000)}\n"
            "\n# Budget remaining\n"
            f"- actions left: {steps_remaining}\n"
            f"- seconds left: {secs_remaining:.0f}\n"
            "\nDecide the next action. Output ONLY the JSON object now."
        )
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

    def _append_correction(self, messages: List[Dict[str, str]], bad_content: str) -> List[Dict[str, str]]:
        """Return a new message list with a repair instruction appended."""
        repair = (
            "Your previous response was not a valid JSON object:\n"
            f"---\n{bad_content}\n---\n"
            "Please respond again with ONLY a single JSON object matching the schema, "
            "with no markdown and no extra text."
        )
        return messages + [{"role": "user", "content": repair}]

    def _manifest(self) -> str:
        """Render the tool manifest, building the real registry on first use."""
        if self._registry is None:
            try:
                from tools.registry import build_real_registry
                self._registry = build_real_registry()
            except Exception:
                return (
                    "(tool registry unavailable — expected tools: http_probe, port_scan, "
                    "dir_enum, fingerprint, param_probe, fuzz, sqli, xss, lfi, ssrf, "
                    "idor, decode, hash_crack)"
                )
        try:
            return self._registry.manifest_text()
        except Exception:
            return "(tool manifest unavailable)"

    # --------------------------------------------------------------- transport

    def _request_with_retry(self, messages: List[Dict[str, str]], deadline: float) -> Optional[str]:
        """Call the model, retrying transient failures, until content is returned."""
        attempt = 0
        while attempt < _MAX_ATTEMPTS:
            if time.perf_counter() >= deadline:
                return None
            content, status = self._chat(messages)
            if content is not None:
                return content
            if status not in _RETRYABLE_STATUSES:
                return None  # permanent error (e.g. 400/401) — do not retry
            attempt += 1
            if attempt >= _MAX_ATTEMPTS:
                return None
            backoff = min(2.0, 0.5 * attempt)
            if time.perf_counter() + backoff >= deadline:
                return None
            time.sleep(backoff)
        return None

    def _chat(self, messages: List[Dict[str, str]]) -> Tuple[Optional[str], int]:
        """One chat-completions round-trip. Returns ``(content, http_status)``.

        ``content`` is ``None`` on any transport/HTTP/parse failure. On a
        successful response, token usage (if reported) is added to ``usage``.
        """
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        resp = post(
            join(self.base_url, "chat/completions"),
            json={
                "model": self.model,
                "temperature": self.temperature,
                "max_tokens": self.max_output_tokens,
                "messages": messages,
            },
            headers=headers,
            timeout=self.timeout,
        )
        if resp.status == 0 or resp.status >= 400:
            return None, resp.status
        try:
            body = json.loads(resp.text)
            if not isinstance(body, dict):
                return None, resp.status
        except Exception:
            return None, resp.status
        usage = body.get("usage")
        prompt_tokens = 0
        completion_tokens = 0
        if isinstance(usage, dict):
            try:
                prompt_tokens = int(usage.get("prompt_tokens") or 0)
                completion_tokens = int(usage.get("completion_tokens") or 0)
            except (TypeError, ValueError):
                prompt_tokens = completion_tokens = 0
        self.usage.add(prompt_tokens, completion_tokens, 1)
        try:
            content = body["choices"][0]["message"]["content"]
        except Exception:
            return None, resp.status
        if not isinstance(content, str) or not content.strip():
            # Empty assistant content (e.g. a reasoning model exhausted its output
            # budget on thinking) is transient — let the retry loop try again.
            return None, 0
        return content, resp.status

    # ----------------------------------------------------------------- mapping

    def _to_action(self, parsed: dict, raw_text: str) -> Action:
        thought = str(parsed.get("thought") or "").strip()
        action = str(parsed.get("action") or "").strip().lower()
        params = parsed.get("params")
        if not isinstance(params, dict):
            params = {}
        if action == "submit":
            flag = parsed.get("flag")
            if not isinstance(flag, str) or not flag.strip():
                flag = extract_flag(raw_text) or ""
            return Action(tool="submit", flag=flag, is_submit=True,
                          thought=thought or "Submitting the recovered flag.")
        if action == "give_up":
            return Action(tool="give_up", is_give_up=True,
                          thought=thought or "No further progress possible; giving up.")
        if not re.fullmatch(r"[a-z0-9_]+", action):
            return Action(tool="noop", params=params,
                          thought=thought or "Model produced an invalid action; doing nothing.")
        return Action(tool=action, params=params,
                      thought=thought or f"Running {action}.")

    @staticmethod
    def _give_up(reason: str) -> Action:
        return Action(tool="give_up", is_give_up=True, thought=reason)


def _opencode_api_key() -> str:
    """Resolve the OpenCode Go API key without requiring an env var.

    The key lives in opencode's own auth store (``~/.local/share/opencode/
    auth.json`` under ``opencode-go.api.key``) — the user already "plugged it
    in" there, so ``LLM_API_KEY`` stays optional. Falls back to the env var.
    """
    env_key = os.environ.get("LLM_API_KEY", "").strip()
    if env_key:
        return env_key
    try:
        auth_path = os.path.join(os.path.expanduser("~"),
                                 ".local", "share", "opencode", "auth.json")
        with open(auth_path, "r", encoding="utf-8") as fh:
            auth = json.load(fh)
        provider = auth.get("opencode-go") or {}
        if isinstance(provider, dict):
            api = provider.get("api")
            if isinstance(api, dict):
                return str(api.get("key") or "").strip()
            # flat shape: {"type": "api", "key": "sk-..."}
            return str(provider.get("key") or "").strip()
    except Exception:
        pass
    return ""


def build_llm(llm_cfg) -> BaseLLM:
    """Construct the decision brain from an :class:`LLMConfig`.

    Falls back to :class:`LocalPolicyLLM` (imported from ``llm.local_policy``)
    when the provider is ``local`` or no API key is available, so the whole
    agent runs offline with zero credentials.
    """
    from llm.local_policy import LocalPolicyLLM  # local import: sibling leaf module

    provider = (llm_cfg.provider or "local").strip().lower()
    api_key = llm_cfg.api_key  # LLMConfig.api_key reads the env var
    max_output_tokens = int(llm_cfg.max_output_tokens)
    if provider == "opencode":
        # OpenCode Go is a plain OpenAI-compatible gateway; its API key already
        # lives in opencode's auth store, so it needs no LLM_API_KEY env var.
        # Reasoning models (glm-5.x) can burn the default 1024 output budget on
        # thinking and return empty content, so give them headroom.
        api_key = api_key or _opencode_api_key()
        max_output_tokens = max(max_output_tokens, 4096)
    if provider == "local" or not api_key:
        print(f"[llm] no API key for provider {provider!r}; falling back to local policy",
              file=sys.stderr)
        return LocalPolicyLLM()
    return OpenAILikeProvider(
        provider=provider,
        model=llm_cfg.model,
        base_url=llm_cfg.base_url,
        api_key=api_key,
        temperature=llm_cfg.temperature,
        max_output_tokens=max_output_tokens,
        timeout=llm_cfg.timeout,
    )
