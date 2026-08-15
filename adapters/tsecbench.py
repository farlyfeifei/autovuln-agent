"""TsecBench adapter — official TSecBench Challenges API (BENCHMARK_BASE_URL).

Implements the documented per-run lifecycle against the agent-facing answering
API (see docs/CHALLENGES_API.md):

    GET  <base>/openapi/v1/challenges                       list + progress
    POST <base>/openapi/v1/challenges/start?unique_code=..  provision container
    ...   real tools attack the returned ``container_addr`` (reachable via VPN)
    POST <base>/openapi/v1/challenges/submit  {unique_code, flag}
    POST <base>/openapi/v1/challenges/close?unique_code=..  release resources

Every request authenticates with the header ``BENCHMARK_TOKEN``. Credentials
are read from the platform-standard env vars ``BENCHMARK_BASE_URL`` /
``BENCHMARK_TOKEN`` (the names TSecBench auto-distributes), with ``AV_BASE_URL``
/ ``AV_SUBMIT_TOKEN`` as fallback aliases.

The container lifecycle is threaded through the base :class:`Adapter` hooks:
``start(challenge)`` is called by the ReAct loop before solving and stamps the
returned ``container_addr`` onto ``challenge.target``; ``close_challenge``
releases the container afterwards. The adapter never raises: list degrades to
empty, start returns the challenge unchanged, submit reports False, close is
best-effort.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Dict, List, Optional

from core.net import get, post
from core.types import Challenge
from adapters.base import Adapter

_API_PREFIX = "/openapi/v1/challenges"
_TOKEN_HEADER = "BENCHMARK_TOKEN"

# Best-effort category hints for the LLM prompt guidance; a wrong category only
# weakens the hint, it never blocks solving.
_CATEGORY_KEYWORDS = (
    ("web-sqli", ("sql", "sqli", "injection")),
    ("web-xss", ("xss",)),
    ("web-lfi", ("lfi", "file", "include")),
    ("web-ssrf", ("ssrf",)),
    ("web-idor", ("idor",)),
    ("crypto-weak", ("crypto", "rsa", "aes", "des", "hash", "xor")),
    ("recon-info", ("recon", "leak", "info", "directory", "backup", "env")),
    ("binary", ("binary", "pwn", "buffer", "lru", "tls", "heartbeat", "writer",
                "stack", "heap", "use-after-free", "license", "serial")),
    ("cloud", ("aws", "azure", "s3", "lambda", "ec2", "cloud", "storage", "sas")),
)
_SERIES_CATEGORY = {"a": "web", "b": "pentest", "c": "exploit",
                    "d": "cloud", "e": "exploit", "f": "binary"}


def _log(message: str) -> None:
    print(f"[tsecbench] {message}", file=sys.stderr)


def _env(name: str, fallback: str = "") -> str:
    return os.environ.get(name, "").strip() or fallback


def _trim(text: str, limit: int = 200) -> str:
    text = (text or "").strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def _json_body(text: str) -> Optional[dict]:
    try:
        value = json.loads((text or "").strip() or "null")
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _category_from_code(code: str) -> str:
    low = (code or "").lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(keyword in low for keyword in keywords):
            return category
    prefix = low.split("-", 1)[0] if "-" in low else low[:1]
    return _SERIES_CATEGORY.get(prefix, "")


def _container_target(addrs: object) -> str:
    """Turn a ``container_addr`` entry (IP:port) into a tool-attackable URL."""
    if not isinstance(addrs, (list, tuple)):
        return ""
    for addr in addrs:
        addr = str(addr or "").strip()
        if not addr:
            continue
        if addr.startswith(("http://", "https://")):
            return addr
        return "http://" + addr
    return ""


class TsecBenchAdapter(Adapter):
    """Adapter for the official TSecBench Challenges API."""

    name: str = "tsecbench"

    def __init__(self, challenges: Optional[List[Challenge]] = None,
                 base_url: str = "", token: str = "") -> None:
        self.base_url = (base_url or _env("BENCHMARK_BASE_URL",
                                          _env("AV_BASE_URL"))).rstrip("/")
        self.token = token or _env("BENCHMARK_TOKEN", _env("AV_SUBMIT_TOKEN"))
        try:
            self.timeout = float(os.environ.get("AV_NET_TIMEOUT", "") or 12.0)
        except (TypeError, ValueError):
            self.timeout = 12.0
        # ``challenges`` is only a seed (e.g. an offline manifest). The live
        # list is authoritative whenever the API is reachable; the seed is
        # merely a fallback so a run still has something to attempt offline.
        self._seed = challenges
        self._challenges: Optional[List[Challenge]] = None
        if challenges is None:
            self._challenges = self._fetch_challenges() or []
        self._started: Dict[str, bool] = {}
        # Per-challenge flag progress carried across the run so the ReAct loop
        # knows when a multi-flag challenge still has flags left to recover.
        self._progress: Dict[str, dict] = {}

    # --------------------------------------------------------- Adapter API

    def list_challenges(self) -> List[Challenge]:
        if self._challenges is None:
            live = self._fetch_challenges()
            self._challenges = live if live is not None else (self._seed or [])
        return self._challenges

    def tool_registry(self):
        from tools.registry import build_real_registry
        return build_real_registry()

    def start(self, challenge: Challenge) -> Challenge:
        """Provision the challenge container and stamp its address as target."""
        code = challenge.id
        # A container already provisioned earlier in the run (list showed
        # ``container_status: available``) is reused without a new API call.
        raw_addrs = challenge.extra.get("container_addr")
        already = _container_target(raw_addrs)
        if already:
            if not challenge.target:
                challenge.target = already
            self._started[code] = True
            return challenge
        if not self.base_url:
            _log(f"start disabled: no base_url (challenge={code!r})")
            return challenge
        resp = post(self.base_url + _API_PREFIX + "/start",
                    params={"unique_code": code},
                    headers=self._auth_headers(), timeout=self.timeout)
        if not (200 <= resp.status < 300):
            _log(f"start {code!r} -> status={resp.status} body={_trim(resp.text)}")
            return challenge
        data = _json_body(resp.text)
        addrs = (data or {}).get("container_addr")
        if isinstance(addrs, list) and addrs:
            challenge.extra["container_addr"] = list(addrs)
            target = _container_target(addrs)
            if target:
                challenge.target = target
                self._started[code] = True
            else:
                _log(f"start {code!r}: response addresses not usable: {addrs!r}")
        else:
            _log(f"start {code!r}: response had no usable container_addr")
        return challenge

    def submit(self, challenge: Challenge, flag: str) -> bool:
        flag = (flag or "").strip()
        if not flag or not self.base_url:
            return False
        resp = post(self.base_url + _API_PREFIX + "/submit",
                    json={"unique_code": challenge.id, "flag": flag},
                    headers=self._auth_headers(), timeout=self.timeout)
        if resp.status == 409:
            # duplicate = that flag index was already correctly submitted.
            code = _json_body(resp.text)
            if isinstance(code, dict) and code.get("code") == "duplicate":
                _log(f"submit {challenge.id}: duplicate (already scored)")
                return True
            return False
        if not (200 <= resp.status < 300):
            _log(f"submit {challenge.id} -> status={resp.status} "
                 f"body={_trim(resp.text)}")
            return False
        data = _json_body(resp.text)
        if not isinstance(data, dict) or data.get("correct") is None:
            _log(f"submit {challenge.id}: response lacks 'correct' field")
            return False
        _log(f"submit {challenge.id}: correct={data.get('correct')} "
             f"awarded={data.get('awarded')} "
             f"cumulative={data.get('cumulative_score')}")
        self._record_progress(challenge, data)
        return bool(data.get("correct"))

    def flag_progress(self, challenge: Challenge) -> Optional[dict]:
        """Platform-confirmed per-flag progress after the latest submit."""
        return self._progress.get(challenge.id)

    def close_challenge(self, challenge: Challenge) -> None:
        if not self._started.pop(challenge.id, False) or not self.base_url:
            return
        try:
            resp = post(self.base_url + _API_PREFIX + "/close",
                        params={"unique_code": challenge.id},
                        headers=self._auth_headers(), timeout=self.timeout)
            if resp.status != 200:
                _log(f"close {challenge.id} -> status={resp.status}")
        except Exception as exc:  # never raise from a lifecycle hook
            _log(f"close {challenge.id}: {type(exc).__name__}: {exc}")

    def close(self) -> None:
        """Safety net: release every container still marked started."""
        for code in list(self._started):
            if not self.base_url:
                break
            try:
                resp = post(self.base_url + _API_PREFIX + "/close",
                            params={"unique_code": code},
                            headers=self._auth_headers(), timeout=self.timeout)
                _log(f"close {code} -> status={resp.status}")
            except Exception as exc:
                _log(f"close {code}: {type(exc).__name__}: {exc}")
        self._started.clear()

    # ------------------------------------------------------------ internals

    def _auth_headers(self) -> Dict[str, str]:
        return {_TOKEN_HEADER: self.token}

    def _record_progress(self, challenge: Challenge, data: dict) -> None:
        """Store the platform's per-flag progress for this challenge.

        The list API calls the field ``flag_count`` while the submit API calls
        it ``total_flag_count``; normalise both into the same ``extra`` keys so
        the LLM prompt and the ReAct loop read one consistent shape.
        """
        total = data.get("total_flag_count")
        try:
            total = int(total) if total is not None else int(
                challenge.extra.get("total_flag_count") or challenge.extra.get(
                    "flag_count") or 1)
        except (TypeError, ValueError):
            total = 1
        correct = data.get("correct_flag_count")
        try:
            correct = int(correct) if correct is not None else 0
        except (TypeError, ValueError):
            correct = 0
        awarded = data.get("awarded")
        try:
            awarded = int(awarded) if awarded is not None else 0
        except (TypeError, ValueError):
            awarded = 0
        progress = {"correct": correct, "total": total, "awarded": awarded}
        self._progress[challenge.id] = progress
        challenge.extra["correct_flag_count"] = correct
        challenge.extra["total_flag_count"] = total

    def _fetch_challenges(self) -> Optional[List[Challenge]]:
        """Fetch the live challenge list. Returns ``None`` on API failure so the
        caller can distinguish "platform unreachable" from "no challenges"."""
        if not self.base_url:
            _log("list disabled: no base_url (set BENCHMARK_BASE_URL)")
            return None
        resp = get(self.base_url + _API_PREFIX, headers=self._auth_headers(),
                   timeout=self.timeout)
        if not (200 <= resp.status < 300):
            _log(f"list -> status={resp.status} body={_trim(resp.text)}")
            return None
        try:
            data = json.loads((resp.text or "").strip() or "[]")
        except (ValueError, TypeError):
            _log("list -> response is not valid JSON")
            return None
        if not isinstance(data, list):
            _log(f"list -> expected JSON array, got {type(data).__name__}")
            return None
        challenges: List[Challenge] = []
        skipped = 0
        for index, entry in enumerate(data):
            if not isinstance(entry, dict):
                continue
            code = str(entry.get("unique_code") or "").strip()
            if not code:
                continue
            # Already fully solved earlier in the run — do not burn time again.
            if entry.get("is_completed") is True:
                skipped += 1
                continue
            try:
                points = int(entry.get("total_score") or 0)
            except (TypeError, ValueError):
                points = 0
            extra = dict(entry)
            extra["unique_code"] = code
            # normalise list flag_count -> total_flag_count (submit-API naming)
            try:
                total = int(entry.get("flag_count") or 1)
            except (TypeError, ValueError):
                total = 1
            try:
                correct = int(entry.get("correct_flag_count") or 0)
            except (TypeError, ValueError):
                correct = 0
            extra["total_flag_count"] = total
            extra["correct_flag_count"] = correct
            challenges.append(Challenge(
                id=code,
                name=code,
                category=_category_from_code(code),
                description=str(entry.get("description") or ""),
                target="",
                points=points,
                extra=extra,
            ))
        if skipped:
            _log(f"list -> {len(challenges)} challenges ({skipped} already completed skipped)")
        else:
            _log(f"list -> {len(challenges)} challenges")
        return challenges
