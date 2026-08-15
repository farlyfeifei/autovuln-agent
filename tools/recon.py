"""Reconnaissance tools: HTTP probing, port scanning, dir enumeration, fingerprinting.

Every tool is a subclass of :class:`tools.registry.Tool` and is wired into the
real registry by ``tools/registry.build_real_registry``.  All HTTP goes through
``core.net`` helpers (which never raise); socket scanning uses the standard
``socket`` module with short timeouts.  Tools must never raise — every error is
surfaced inside ``ToolResult.observation``.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from core.flags import extract_flags
from core.net import get, normalize_url, request
from core.types import Challenge, ToolResult
from tools.registry import Tool

# --------------------------------------------------------------------------- #
# shared URL + host helpers
# --------------------------------------------------------------------------- #


def _join_url(target: str, path: str) -> str:
    """Return ``normalize_url(target)`` + ``path``, joined robustly.

    ``path`` may be empty, start with or omit a leading slash, and may already
    carry a query string.  ``http://h/login`` + ``?debug=1`` stays on the same
    page rather than being urljoin-rewritten to ``/``.
    """
    base = normalize_url(target or "")
    path = str(path or "").strip()
    if not path or not base:
        return base or path
    if path.startswith(("http://", "https://")):
        return path
    if path.startswith(("//", "?")):
        return base + path
    query = ""
    if "?" in path:
        path, query = path.split("?", 1)
        query = "?" + query
    joined = base.rstrip("/") + "/" + path.lstrip("/")
    return joined + query


def _host_from_target(target: str) -> str:
    """Extract the bare hostname from a target URL (defaults to ``localhost``)."""
    t = normalize_url(target or "")
    try:
        host = urlparse(t).hostname
    except ValueError:
        host = ""
    if host:
        return host
    # last-resort fallback: strip scheme and any leading port
    return t.split("://", 1)[-1].split(":", 1)[0] or "localhost"


def _truncate(text: str, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f" ... [truncated {len(text) - limit} chars]"


def _fmt_headers(headers: Dict[str, str], keys: Sequence[str]) -> List[str]:
    """Render selected headers (case-insensitive) as ``Key: value`` lines."""
    lines: List[str] = []
    for key in keys:
        value = next((v for k, v in headers.items() if k.lower() == key.lower()), None)
        if value:
            lines.append(f"{key}: {_truncate(str(value), 120)}")
        else:
            lines.append(f"{key}: (absent)")
    return lines


def _set_cookie_line(headers: Dict[str, str]) -> str:
    value = next((v for k, v in headers.items() if k.lower() == "set-cookie"), None)
    if value is None:
        return "Set-Cookie: (absent)"
    # log the presence plus the bare cookie name(s), never full values
    name = value.split("=", 1)[0] if value else "?"
    return f"Set-Cookie: present ({name}=...)"


def _flags_line(text: str) -> str:
    flags = extract_flags(text)
    return f"flags: {flags}" if flags else "flags: (none)"


def _tool_error(name: str, exc: BaseException) -> ToolResult:
    return ToolResult(
        tool=name, ok=False,
        observation=f"[{name}] error: {type(exc).__name__}: {exc}",
    )


def _result(name: str, observation: str, params: dict,
            raw: str = "", ok: bool = True) -> ToolResult:
    return ToolResult(
        tool=name, observation=observation, params=params,
        flags=extract_flags(observation), ok=ok, raw=raw,
    )


# --------------------------------------------------------------------------- #
# 1) HttpProbeTool
# --------------------------------------------------------------------------- #


class HttpProbeTool(Tool):
    """Send a single raw HTTP request to the target and report the response."""

    name = "http_probe"
    description = ("Send a raw HTTP request to the target URL (GET by default) and report "
                   "status, key headers, truncated body and any flags. "
                   "params: {path: str, method: 'GET'|'POST'|..., headers: dict, "
                   "data: str|dict, params: dict (appended as query string), "
                   "allow_redirects: bool}")

    _HEADERS_OF_INTEREST = ("Server", "Content-Type", "X-Powered-By", "Location")
    _BODY_LIMIT = 1500

    def run(self, challenge: Challenge, params: dict) -> ToolResult:
        try:
            path = str(params.get("path") or "")
            method = str(params.get("method") or "GET").upper().strip()
            headers = params.get("headers") or {}
            if not isinstance(headers, dict):
                headers = {}
            data = params.get("data")
            query = params.get("params") or {}
            if not isinstance(query, dict):
                query = {}
            allow_redirects = bool(params.get("allow_redirects", True))

            url = _join_url(challenge.target, path)
            resp = request(method, url, params=query, headers=headers, data=data,
                           allow_redirects=allow_redirects)

            if not resp.ok:
                lines = [
                    f"[http_probe] {method} {url}",
                    f"  request failed: {resp.error}  (elapsed: {resp.elapsed:.3f}s)",
                ]
                obs = "\n".join(lines)
                return _result(self.name, obs, params, ok=False)

            lines = [
                f"[http_probe] {method} {url}",
                f"  status: {resp.status}  (elapsed: {resp.elapsed:.3f}s)",
            ]
            lines.extend(f"  {line}" for line in _fmt_headers(
                resp.headers, self._HEADERS_OF_INTEREST))
            lines.append(f"  {_set_cookie_line(resp.headers)}")
            body = resp.text or ""
            lines.append(f"  --- body ({len(body)} chars, first {self._BODY_LIMIT}) ---")
            lines.append(_truncate(body, self._BODY_LIMIT))
            lines.append(f"  {_flags_line(body)}")
            obs = "\n".join(lines)
            return _result(self.name, obs, params, raw=body)
        except Exception as exc:  # defensive: never raise
            return _tool_error(self.name, exc)


# --------------------------------------------------------------------------- #
# 2) PortScanTool
# --------------------------------------------------------------------------- #

DEFAULT_PORTS: List[int] = [22, 80, 443, 8080, 8443, 1337, 3000, 5000, 6379, 9000]
_MAX_SCAN_PORTS = 1024


def _parse_ports(value: Any) -> List[int]:
    """Normalise *value* into a de-duplicated list of ints in range 1..65535."""
    if value is None:
        return list(DEFAULT_PORTS)
    if isinstance(value, bool):  # bool is an int subclass; exclude it
        return [int(value)] if value else []
    if isinstance(value, int):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        ports: List[int] = []
        for item in value:
            ports.extend(_parse_ports(item))
        return _sanitize_ports(ports)
    raw = str(value).strip()
    if not raw:
        return list(DEFAULT_PORTS)
    parts: List[int] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                lo, hi = (int(x) for x in chunk.split("-", 1))
                if hi < lo:
                    lo, hi = hi, lo
                # cap a huge range so we never materialize a giant list
                if hi - lo + 1 > _MAX_SCAN_PORTS:
                    hi = lo + _MAX_SCAN_PORTS - 1
                parts.extend(range(lo, hi + 1))
            except ValueError:
                continue
        else:
            try:
                parts.append(int(chunk))
            except ValueError:
                continue
        if len(parts) > _MAX_SCAN_PORTS:
            parts = parts[:_MAX_SCAN_PORTS]
            break
    return _sanitize_ports(parts)


def _sanitize_ports(ports: Iterable[int]) -> List[int]:
    seen: set = set()
    out: List[int] = []
    for p in ports:
        if 1 <= int(p) <= 65535 and int(p) not in seen:
            seen.add(int(p))
            out.append(int(p))
    return out


def _check_port(host: str, port: int, timeout: float) -> Tuple[int, str]:
    """Non-blocking TCP connect.  Returns (errno, label); errno 0 == open.

    ``socket.connect_ex`` returns 0 on success and a platform errno otherwise,
    so it needs no exception for the common refused/filtered case.  A gaierror
    in one address family (e.g. an IPv6-only host under AF_INET) falls through
    to the next family instead of giving up immediately.
    """
    if not host:
        return -1, "empty-host"
    resolved_errno: Optional[int] = None
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
        except OSError:
            continue
        sock.settimeout(timeout)
        try:
            rc = sock.connect_ex((host, port))
            if rc == 0:
                return 0, "open"
            if resolved_errno is None:
                resolved_errno = rc  # a real connect result (e.g. refused)
        except socket.gaierror:
            continue  # hostname has no address in this family; try the next
        except (socket.timeout, TimeoutError):
            return -1, "timeout"
        except OSError as exc:
            return getattr(exc, "errno", -1), f"error:{exc}"
        finally:
            sock.close()
    if resolved_errno is None:
        return -1, "dns-fail"
    return resolved_errno, "closed"


class PortScanTool(Tool):
    """TCP connect scan of the target host across a set of ports."""

    name = "port_scan"
    description = ("TCP-connect port scan of the target host. "
                   "params: {host: str (default: derived from challenge.target), "
                   "ports: int | '22,80,443' | '8000-8010' | list (default common "
                   "web ports), timeout: float (default 1.0s)}")

    _DEFAULT_TIMEOUT = 1.0

    def run(self, challenge: Challenge, params: dict) -> ToolResult:
        try:
            host = str(params.get("host") or "").strip() or _host_from_target(challenge.target)
            try:
                timeout = float(params.get("timeout") or self._DEFAULT_TIMEOUT)
            except (TypeError, ValueError):
                timeout = self._DEFAULT_TIMEOUT
            timeout = min(max(timeout, 0.05), 10.0)

            ports = _parse_ports(params.get("ports"))
            if not ports:
                ports = list(DEFAULT_PORTS)
            truncated = len(ports) > _MAX_SCAN_PORTS
            if truncated:
                ports = ports[:_MAX_SCAN_PORTS]

            open_ports: List[int] = []
            closed: List[int] = []
            failed: List[str] = []
            start = __import__("time").perf_counter()

            with ThreadPoolExecutor(max_workers=min(64, len(ports))) as pool:
                futures = {pool.submit(_check_port, host, p, timeout): p for p in ports}
                for fut in as_completed(futures):
                    rc, label = fut.result()
                    port = futures[fut]
                    if rc == 0:
                        open_ports.append(port)
                    elif label.startswith("dns-fail"):
                        failed.append(f"dns-fail:{port}")
                    elif label.startswith("timeout"):
                        closed.append(port)
                    else:
                        closed.append(port)

            open_ports.sort()
            closed.sort()
            elapsed = __import__("time").perf_counter() - start

            lines = [
                f"[port_scan] host={host}  ports_scanned={len(ports)}  "
                f"timeout={timeout:.2f}s  elapsed={elapsed:.2f}s",
            ]
            if truncated:
                lines.append(f"  [!] port list capped at {_MAX_SCAN_PORTS} entries")
            if open_ports:
                lines.append(f"  OPEN: {', '.join(str(p) for p in open_ports)}")
            else:
                lines.append("  OPEN: (none)")
            if closed:
                lines.append(f"  closed: {len(closed)} ports ({', '.join(str(p) for p in closed[:25])}"
                             f"{' ...' if len(closed) > 25 else ''})")
            if failed:
                lines.append(f"  unresolved: {', '.join(failed[:10])}")
            obs = "\n".join(lines)
            return _result(self.name, obs, params)
        except Exception as exc:  # defensive: never raise
            return _tool_error(self.name, exc)


# --------------------------------------------------------------------------- #
# 3) DirEnumTool
# --------------------------------------------------------------------------- #

DIR_WORDLIST: List[str] = [
    "admin", "admin/", "login", "api", "api/", "backup", "backup.zip",
    "backup.tar.gz", "index.php.bak", "index.html.bak", "db.sql", "db.sqlite",
    "database.sql", "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php",
    ".git/config", ".git/HEAD", ".env", ".env.local", ".env.bak",
    "config", "config.php", "config.json", "config.yaml", "settings.py",
    "swagger", "swagger-ui", "swagger/index.html", "api/swagger", "openapi.json",
    "robots.txt", "sitemap.xml", ".DS_Store", "upload", "debug", "health",
    "healthz", "web.config", "application.properties", "server-status",
    "wp-login.php", "wp-admin", "wp-content", "wp-config.php", "adminer.php",
    "phpmyadmin/", ".well-known/security.txt", "vendor/", "composer.json",
    "package.json", "static/", "js/", "css/", "logs", "access.log", "error.log",
    "old", "bak", "temp", "tmp", "test", "dev", "console", "panel", "dashboard",
    "manager", "flag", "flag.txt", "key", "secret", "users", "data",
]

# appended when depth >= 2 (deeper / nested paths)
DEEP_WORDLIST: List[str] = [
    "api/v1/", "api/v2/", "api/users", "api/admin", "api/config", "api/health",
    "admin/config.php", "admin/login", "admin/dashboard", "admin/users",
    ".git/logs/HEAD", ".git/refs/heads/master", ".git/packed-refs",
    "backup/backup.zip", "backup/site.tar.gz", "backup/db.sql", "backup/.env",
    "config/config.php", "config/database.php", "config/secrets.json",
    "static/js/app.js", "static/css/style.css", "static/uploads/", "uploads/",
    "files/", "docs/", "tests/", "src/", "lib/", "tmp/", "debug/", "internal/",
    "management/", "console/", "panel/login", "openapi.yaml", "api-docs",
    "vendor/autoload.php", "node_modules/.package-lock.json",
    "wp-content/uploads/", "wp-includes/", "env.js", "config.js", "settings.js",
    ".well-known/", "security.txt", "server-info", "git/", "web/", "www/",
]

SENSITIVE_MARKERS: Tuple[str, ...] = (
    ".git", ".env", ".DS_Store", "backup", "config", "swagger", ".bak",
    "db.sql", "database.sql", "secret", "key", "flag", "wp-config",
    "upload", "debug", "admin", "credentials", "passwd",
)


def _is_sensitive(path: str) -> bool:
    low = path.lower()
    return any(marker in low for marker in SENSITIVE_MARKERS)


def _interesting(status: int) -> bool:
    """Statuses worth surfacing in the report."""
    return status in (200, 201, 202, 204, 206, 301, 302, 307, 308, 401, 403,
                      405, 500, 502, 503, 504) or 200 <= status < 300


class DirEnumTool(Tool):
    """HTTP directory / file enumeration against the target."""

    name = "dir_enum"
    description = ("Brute-force interesting HTTP paths against the target. "
                   "params: {wordlist: list (optional, overrides built-in), "
                   "depth: int (default 1; >= 2 probes deeper paths), "
                   "max_results: int (default 60), timeout: float (default 5s)}. "
                   "Sensitive hits (.git/.env/backup/config/*.bak/swagger) are marked [!].")

    _DEFAULT_TIMEOUT = 5.0
    _MAX_RESULTS = 60
    _MAX_PROBE_PATHS = 400   # hard work cap: a huge wordlist can't fire unbounded requests

    def _probe(self, base: str, path: str, timeout: float) -> Tuple[str, int, str]:
        """GET one path.  Returns (path, status, body). Never raises."""
        try:
            resp = get(base + "/" + path, timeout=timeout)
        except Exception as exc:
            return path, 0, f"error:{type(exc).__name__}:{exc}"
        if not resp.ok:
            return path, 0, f"request-failed:{resp.error}"
        return path, resp.status, (resp.text or "")

    def run(self, challenge: Challenge, params: dict) -> ToolResult:
        try:
            base = normalize_url(challenge.target).rstrip("/")
            depth = 1
            try:
                depth = int(params.get("depth") or 1)
            except (TypeError, ValueError):
                depth = 1
            try:
                timeout = float(params.get("timeout") or self._DEFAULT_TIMEOUT)
            except (TypeError, ValueError):
                timeout = self._DEFAULT_TIMEOUT
            timeout = min(max(timeout, 0.1), 15.0)
            try:
                max_results = int(params.get("max_results") or self._MAX_RESULTS)
            except (TypeError, ValueError):
                max_results = self._MAX_RESULTS
            max_results = max(max_results, 1)

            supplied = params.get("wordlist")
            if supplied:
                if not isinstance(supplied, (list, tuple, set)):
                    supplied = [str(supplied)]
                paths = [str(p) for p in supplied]
            else:
                paths = list(DIR_WORDLIST)
            if depth >= 2:
                paths = list(dict.fromkeys(paths + DEEP_WORDLIST))
            else:
                paths = list(dict.fromkeys(paths))
            if not paths:
                return _result(self.name, f"[dir_enum] empty wordlist for {base}", params)

            capped = len(paths) > self._MAX_PROBE_PATHS
            if capped:
                paths = paths[:self._MAX_PROBE_PATHS]

            hits: List[Tuple[str, int, str]] = []
            with ThreadPoolExecutor(max_workers=min(12, len(paths))) as pool:
                futures = [pool.submit(self._probe, base, p, timeout) for p in paths]
                for fut in as_completed(futures):
                    hits.append(fut.result())

            hits.sort(key=lambda t: (t[1] != 0, _is_sensitive(t[0]), t[0]))
            flagged = [h for h in hits if _interesting(h[1])]
            if len(flagged) > max_results:
                flagged = flagged[:max_results]

            if not flagged:
                obs = (f"[dir_enum] {base}  depth={depth}  probed={len(paths)} "
                       f"paths in ~{timeout:.0f}s each — no interesting hits "
                       f"(all 404 / unreachable)")
                if capped:
                    obs += f"  (wordlist capped at {self._MAX_PROBE_PATHS})"
                return _result(self.name, obs, params)

            lines = [f"[dir_enum] {base}  depth={depth}  hits={len(flagged)}/{len(paths)}"]
            if capped:
                lines.append(f"  [!] wordlist capped at {self._MAX_PROBE_PATHS} paths")
            body_flags: List[str] = []
            for path, status, body in flagged:
                mark = "  [!] sensitive" if _is_sensitive(path) else ""
                body_flags.extend(extract_flags(body))
                if mark:
                    lines.append(f"  /{path}  ({status}){mark}")
                    if body:
                        lines.append(f"    body: {_truncate(body, 220)}")
                else:
                    lines.append(f"  /{path}  ({status})")
            for flag in dict.fromkeys(body_flags):
                lines.append(f"  FLAG FOUND: {flag}")
            lines.append(f"  {_flags_line(' '.join(body_flags))}")
            obs = "\n".join(lines)
            return _result(self.name, obs, params)
        except Exception as exc:  # defensive: never raise
            return _tool_error(self.name, exc)


# --------------------------------------------------------------------------- #
# 4) FingerprintTool
# --------------------------------------------------------------------------- #

# tech -> list of lowercase substrings to look for in headers + body
TECH_HINTS: Dict[str, Tuple[str, ...]] = {
    "nginx": ("server: nginx", "nginx/"),
    "apache": ("server: apache", "apache/"),
    "iis": ("server: microsoft-iis",),
    "openresty": ("server: openresty",),
    "gunicorn": ("gunicorn", "server: gunicorn"),
    "uvicorn": ("uvicorn",),
    "werkzeug": ("werkzeug",),
    "flask": ("flask",),
    "django": ("django", "csrftoken"),
    "php": ("x-powered-by: php", "php/", ".php"),
    "nodejs": ("node.js", "x-powered-by: express", "express", "connect.sid"),
    "express": ("express",),
    "nextjs": ("__next", "next.js"),
    "java": ("javax.servlet", "java", "jsessionid"),
    "spring": ("springframework", "spring", "whitelabel"),
    "tomcat": ("apache-tomcat", "tomcat", "catalina"),
    "shiro": ("shiro",),
    "golang": ("go-http-server", "golang"),
    "ruby": ("x-powered-by: phusion", "ruby", "rails"),
    "wordpress": ("wordpress", "wp-content", "wp-includes", "wp-login", "wp-json"),
    "drupal": ("drupal",),
    "jquery": ("jquery", "jquery-"),
    "bootstrap": ("bootstrap",),
    "vue": ("vue.js", "vue", "__vue__"),
    "react": ("react",),
    "angular": ("ng-", "angular"),
    "jenkins": ("jenkins", "x-jenkins"),
    "grafana": ("grafana",),
    "phpmyadmin": ("phpmyadmin",),
    "discuz": ("discuz",),
    "thinkphp": ("thinkphp", "tp_"),
}


def _tech_hits(headers: Dict[str, str], body: str) -> List[str]:
    """Return a de-duplicated list of detected tech names, in dict order."""
    hdr_text = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
    body_low = (body or "").lower()
    detected: List[str] = []
    for tech, markers in TECH_HINTS.items():
        if any(marker in hdr_text or marker in body_low for marker in markers):
            detected.append(tech)
    return detected


class FingerprintTool(Tool):
    """Detect the server / framework / frontend stack of the target."""

    name = "fingerprint"
    description = ("Fingerprint the target's technology stack by GETting a path "
                   "(default '/') and analysing Server / X-Powered-By / Set-Cookie "
                   "headers plus the HTML body. params: {path: str (default '/')}")

    _HEADERS_OF_INTEREST = ("Server", "Content-Type", "X-Powered-By", "Location")
    _BODY_LIMIT = 3000

    def run(self, challenge: Challenge, params: dict) -> ToolResult:
        try:
            path = str(params.get("path") or "/")
            url = _join_url(challenge.target, path)
            resp = get(url, timeout=10.0)

            if not resp.ok:
                obs = (f"[fingerprint] GET {url} — request failed: {resp.error} "
                       f"(elapsed: {resp.elapsed:.3f}s)")
                return _result(self.name, obs, params, ok=False)

            body = resp.text or ""
            tech = _tech_hits(resp.headers, body)
            lines = [
                f"[fingerprint] GET {url} -> {resp.status}  (elapsed: {resp.elapsed:.3f}s)",
            ]
            lines.extend(f"  {line}" for line in _fmt_headers(
                resp.headers, self._HEADERS_OF_INTEREST))
            lines.append(f"  {_set_cookie_line(resp.headers)}")
            if tech:
                lines.append("  tech hints: " + ", ".join(tech))
            else:
                lines.append("  tech hints: (none identified)")
            if body:
                lines.append(f"  --- body sample ({len(body)} chars) ---")
                lines.append(_truncate(body, self._BODY_LIMIT))
            lines.append(f"  {_flags_line(body)}")
            obs = "\n".join(lines)
            return _result(self.name, obs, params, raw=body)
        except Exception as exc:  # defensive: never raise
            return _tool_error(self.name, exc)
