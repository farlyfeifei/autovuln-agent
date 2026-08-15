"""Probing tools: parameter reflection scanning and generic payload fuzzing.

Both tools are pure "discovery" stages of the agent loop — they send real HTTP
requests through ``core.net`` (which never raises) and return a compact text
observation the ReAct loop feeds back to the LLM. Every interesting finding is
a (parameter, payload, signal) line so the model can then choose an exploit
tool. Any flag-shaped token in the response bodies is surfaced immediately.

Neither tool ever raises: every exception path is caught and converted into a
``ToolResult(ok=False, ...)``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.flags import extract_flags
from core.net import get, join, request
from core.types import Challenge, ToolResult
from tools.registry import Tool

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

#: Default injection payloads used by :class:`ParamProbeTool` when the caller
#: does not supply its own list.
DEFAULT_PAYLOADS: List[str] = [
    "'",
    '"',
    "<script>alert(1)</script>",
    "{{7*7}}",
    "../../",
    "1' OR '1'='1",
    "%0a",
    "\\",
]

#: Signatures that hint at SQL / template / generic backend errors. Matching is
#: case-insensitive.
ERROR_SIGNATURES: List[str] = [
    "sql", "syntax error", "mysql", "postgres", "oracle", "odbc",
    "traceback", "exception", "internal server error",
    "stack trace", "warning", "500",
]

#: Response bodies longer than this (vs. a baseline request) are flagged as a
#: size anomaly.
SIZE_ANOMALY_FACTOR: float = 1.5

#: Elapsed time beyond this many seconds (vs. baseline) is flagged as a timing
#: anomaly (e.g. ``sleep``-driven SQLi).
TIME_ANOMALY_SEC: float = 2.0


def _escape(text: Any) -> str:
    """Render a value safely for a table cell (no newlines)."""
    s = str(text)
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    return s if len(s) <= 80 else s[:77] + "..."


def _normalize_payloads(raw: Any) -> List[str]:
    """Accept a list of strings or numbers and return them as strings."""
    if isinstance(raw, (list, tuple)) and raw:
        return [str(p) for p in raw]
    return list(DEFAULT_PAYLOADS)


def _build_url(challenge: Challenge, path: Any) -> str:
    """Build the absolute URL for a challenge target + path."""
    base = challenge.target if challenge.target else "http://localhost/"
    p = str(path or "/")
    if "://" in p:  # already absolute — use as-is
        return p
    return join(base, p)


def _send(method: str, url: str, params: Optional[Dict[str, Any]] = None,
          data: Any = None) -> tuple:
    """Send one request and return (status, body, elapsed) or a sentinel."""
    if method.upper() == "GET":
        resp = get(url, params=params)
    else:
        resp = request(method.upper(), url, params=params, data=data)
    if not resp.ok:
        return 0, resp.text, resp.elapsed
    return resp.status, resp.text, resp.elapsed


class ParamProbeTool(Tool):
    """Scan a path with injection payloads against every GET parameter.

    Finds which parameters reflect input back (XSS candidates), trigger
    backend errors (SQLi / SSTI candidates) or produce size/timing anomalies.
    Sends one request per (param, payload) combination and emits a compact
    table of interesting findings.
    """

    name: str = "param_probe"
    description: str = (
        "Scan one endpoint for parameters that reflect input or trigger errors. "
        "params: {path, params?=[names to scan (default: id, name, q, search, "
        "user, url, file, page, msg, cmd, x, key, action)], payloads?=[custom "
        "injection strings], method?=GET|POST}. Returns which parameters "
        "reflect input or error."
    )

    def run(self, challenge: Challenge, params: dict) -> ToolResult:
        try:
            obs = self._probe(challenge, params or {})
            return ToolResult(
                tool=self.name,
                observation=obs,
                params=params or {},
                flags=extract_flags(obs),
                ok=True,
            )
        except Exception as exc:  # absolute guard — never raise
            return ToolResult(
                tool=self.name,
                observation=f"[param_probe] error: {type(exc).__name__}: {exc}",
                params=params or {},
                flags=[],
                ok=False,
            )

    def _probe(self, challenge: Challenge, params: dict) -> str:
        path = params.get("path", "/")
        payloads = _normalize_payloads(params.get("payloads"))
        method = str(params.get("method", "GET")).upper()
        if method not in ("GET", "POST"):
            method = "GET"
        names = params.get("params")
        if not isinstance(names, (list, tuple)) or not names:
            names = ["id", "name", "q", "search", "user", "url",
                     "file", "page", "msg", "cmd", "x", "key", "action"]
        names = [str(n) for n in names]

        url = _build_url(challenge, path)
        if not url:
            return "[param_probe] no target configured on challenge"

        # baseline: one empty-parameter request per method
        base_status, base_body, base_el = _send(method, url, params={} if method == "GET" else None)
        base_len = len(base_body)

        rows: List[str] = []
        found_flags: List[str] = []
        for name in names:
            for payload in payloads:
                if method == "POST":
                    status, body, elapsed = _send(method, url, params=None,
                                                  data={name: payload})
                else:
                    status, body, elapsed = _send(method, url, params={name: payload})
                if status == 0 and not body:
                    continue  # request error, already swallowed
                signals: List[str] = []
                if payload in body:
                    signals.append("REFLECT")
                low = body.lower()
                for sig in ERROR_SIGNATURES:
                    if sig in low:
                        signals.append("ERR:" + sig)
                if status and base_status and status >= 500:
                    signals.append("STATUS:%d" % status)
                if status == 0:
                    signals.append("CONNECT-ERR")
                if base_len and len(body) >= base_len * SIZE_ANOMALY_FACTOR:
                    signals.append("SIZE+")
                if elapsed >= base_el + TIME_ANOMALY_SEC:
                    signals.append("SLOW:%.1fs" % elapsed)
                body_flags = extract_flags(body)
                for f in body_flags:
                    if f not in found_flags:
                        found_flags.append(f)
                    signals.append("FLAG:" + f)
                if not signals:
                    continue
                rows.append(
                    "  %-12s %-30s status=%-4s len=%-6s %.2fs  %s"
                    % (name, _escape(payload), status or "-",
                       len(body), elapsed, ", ".join(signals))
                )

        # trim the payload tail down to keep the observation readable
        def _short(p: str) -> str:
            p2 = p.replace("\\r", "").replace("\\n", "")
            return p2 if len(p2) <= 40 else p2[:37] + "..."

        header = (
            "param_probe %s %s | %d params x %d payloads | baseline status=%s "
            "len=%d %.2fs | %d interesting hit(s)"
            % (method, url, len(names), len(payloads),
               base_status or "-", base_len, base_el, len(rows))
        )
        lines = [header]
        if rows:
            lines.append("param         payload                        signal(s)")
            lines.extend(rows)
        else:
            lines.append("  no reflection / error / anomaly signals observed")
        if found_flags:
            lines.append("flags: %s" % ", ".join(found_flags))
        if payloads != list(DEFAULT_PAYLOADS):
            lines.append("payloads: %s" % " | ".join(_short(p) for p in payloads[:12]))
        lines.append("params scanned: %s" % ", ".join(names[:16]))
        return "\n".join(lines)


class FuzzTool(Tool):
    """Generic payload fuzz: fire a list of payloads at one endpoint.

    Sends GET requests (or POSTs with a ``data`` body), buckets responses by
    status code and collects reflections and sensitive markers. Useful for
    brute-forcing parameter names, probing hidden values, testing auth
    tokens, or discovering 4xx/5xx behaviour differences.
    """

    name: str = "fuzz"
    description: str = (
        "Fuzz one endpoint with a list of payloads (paths or '?key=val' query "
        "fragments appended to the endpoint). params: {path, payloads?=[paths], "
        "method?=GET|POST, data?=raw POST body}. Returns status-code buckets "
        "and reflection/sensitive-marker hits."
    )

    def run(self, challenge: Challenge, params: dict) -> ToolResult:
        try:
            obs = self._fuzz(challenge, params or {})
            return ToolResult(
                tool=self.name,
                observation=obs,
                params=params or {},
                flags=extract_flags(obs),
                ok=True,
            )
        except Exception as exc:  # absolute guard — never raise
            return ToolResult(
                tool=self.name,
                observation=f"[fuzz] error: {type(exc).__name__}: {exc}",
                params=params or {},
                flags=[],
                ok=False,
            )

    def _fuzz(self, challenge: Challenge, params: dict) -> str:
        path = params.get("path", "/")
        method = str(params.get("method", "GET")).upper()
        if method not in ("GET", "POST", "PUT", "DELETE", "OPTIONS"):
            method = "GET"
        data = params.get("data")

        raw_payloads = params.get("payloads")
        if isinstance(raw_payloads, (list, tuple)) and raw_payloads:
            payloads = [str(p) for p in raw_payloads]
        elif isinstance(raw_payloads, str) and raw_payloads.strip():
            # allow "a\nb\nc" multiline strings (e.g. wordlist pastes)
            payloads = [ln.strip() for ln in raw_payloads.splitlines() if ln.strip()]
        else:
            payloads = [
                "admin", "admin.php", "flag", "flag.txt", "robots.txt",
                "config.php", "index.php", "debug", "test", "users",
                "password", "..", "source", "bak", "admin/",
            ]

        url = _build_url(challenge, path)
        if not url:
            return "[fuzz] no target configured on challenge"

        # interesting substrings looked up in every response body (flag shapes
        # are already surfaced via the FLAG: signal from extract_flags)
        markers = ["admin", "password", "secret", "token", "internal",
                   "traceback", "debug", "root", "user", "config"]
        seen_status: Dict[int, int] = {}
        hits: List[str] = []
        found_flags: List[str] = []
        for payload in payloads:
            # payloads are treated as paths (or raw query fragments when they
            # start with '?') appended to the base endpoint — this is what
            # reveals hidden resources / different status codes / reflections.
            if payload.startswith("?"):
                sep = "&" if "?" in url else "?"
                target = url.rstrip("&") + sep + payload[1:]
            elif payload.startswith("/"):
                target = join(url, payload.lstrip("/"))
            else:
                target = join(url, payload)
            if method == "GET" and data is None:
                resp = get(target)
            else:
                resp = request(method, target, data=data)
            if not resp.ok and not resp.text:
                seen_status[0] = seen_status.get(0, 0) + 1
                continue
            seen_status[resp.status] = seen_status.get(resp.status, 0) + 1
            signals: List[str] = []
            if payload and payload in resp.text:
                signals.append("REFLECT")
            low = resp.text.lower()
            for marker in markers:
                if marker in low:
                    signals.append("MARK:" + marker)
            if resp.status >= 500:
                signals.append("STATUS:%d" % resp.status)
            for f in extract_flags(resp.text):
                if f not in found_flags:
                    found_flags.append(f)
                signals.append("FLAG:" + f)
            if not signals:
                continue
            snippet = resp.text[max(0, resp.text.find(payload) - 40):resp.text.find(payload) + 40] \
                if payload in resp.text else resp.text[:80]
            hits.append(
                "  %-28s status=%-4s len=%-6s %.2fs  %s  body=[..]%s[..]"
                % (_escape(payload), resp.status, len(resp.text),
                   resp.elapsed, ", ".join(signals), _escape(snippet))
            )

        bucket_str = ", ".join(
            "%d x %s" % (count, code) for code, count in sorted(seen_status.items())
        )
        header = (
            "fuzz %s %s | %d payload(s) | statuses: %s | %d interesting hit(s)"
            % (method, url, len(payloads), bucket_str or "(none)", len(hits))
        )
        lines = [header]
        if hits:
            lines.extend(hits)
        else:
            lines.append("  no reflections or sensitive markers observed")
        if found_flags:
            lines.append("flags: %s" % ", ".join(found_flags))
        if len(payloads) <= 24:
            lines.append("payloads: %s" % " | ".join(_short_payload(p) for p in payloads))
        return "\n".join(lines)


def _short_payload(p: str) -> str:
    s = p.replace("\r", "").replace("\n", "")
    return s if len(s) <= 48 else s[:45] + "..."
