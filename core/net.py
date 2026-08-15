"""Thin HTTP helper used by every tool and adapter.

Robust to CTF-target quirks: bad TLS certs, redirects, timeouts, encodings.
Uses ``requests`` when available and falls back to ``urllib`` otherwise so the
package still runs in a truly dependency-free environment.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urljoin as _urljoin

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

_DEFAULTS: Dict[str, Any] = {
    "timeout": 12.0,
    "verify_ssl": False,
    "user_agent": "AutoVulnAgent/0.1 (BSRC Agent+)",
    "proxies": None,
}


@dataclass
class NetResponse:
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    url: str = ""
    elapsed: float = 0.0
    ok: bool = False
    error: str = ""


def configure(*, timeout=None, verify_ssl=None, user_agent=None, proxies=None) -> None:
    if timeout is not None:
        _DEFAULTS["timeout"] = float(timeout)
    if verify_ssl is not None:
        _DEFAULTS["verify_ssl"] = bool(verify_ssl)
    if user_agent is not None:
        _DEFAULTS["user_agent"] = user_agent
    if proxies is not None:
        _DEFAULTS["proxies"] = proxies


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target:
        return target
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target


def join(base: str, path: str) -> str:
    return _urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _headers(base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    h = {"User-Agent": _DEFAULTS["user_agent"]}
    if base:
        h.update({k: str(v) for k, v in base.items()})
    return h


def request(
    method: str,
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json: Any = None,
    timeout: Optional[float] = None,
    allow_redirects: bool = True,
) -> NetResponse:
    """Send one HTTP request and return a ``NetResponse`` (never raises)."""
    url = normalize_url(url)
    start = time.perf_counter()
    to = timeout if timeout is not None else _DEFAULTS["timeout"]

    if requests is not None:
        try:
            if not _DEFAULTS["verify_ssl"]:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            resp = requests.request(
                method, url, params=params, headers=_headers(headers),
                data=data, json=json, timeout=to,
                allow_redirects=allow_redirects,
                verify=_DEFAULTS["verify_ssl"],
                proxies=_DEFAULTS["proxies"] or None,
            )
            text = resp.text
            return NetResponse(
                status=resp.status_code, headers=dict(resp.headers), text=text,
                url=str(resp.url), elapsed=time.perf_counter() - start,
                ok=True,
            )
        except Exception as exc:  # network errors, bad TLS, etc.
            return NetResponse(
                status=0, text="", url=url,
                elapsed=time.perf_counter() - start, ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )
    return _urllib_request(method, url, params=params, headers=headers,
                           data=data, json=json, timeout=to,
                           allow_redirects=allow_redirects)


def _urllib_request(method, url, *, params, headers, data, json=None, timeout,
                    allow_redirects=True):  # pragma: no cover
    import urllib.request
    import urllib.parse
    import urllib.error
    import ssl

    if params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method=method, headers=_headers(headers))
    if json is not None:
        payload = json.dumps(json) if not isinstance(json, str) else json
        req.data = payload.encode("utf-8")
    elif isinstance(data, str):
        req.data = data.encode("utf-8")
    elif isinstance(data, dict):
        req.data = urllib.parse.urlencode(data).encode("utf-8")

    ctx = ssl._create_unverified_context() if not _DEFAULTS["verify_ssl"] \
        else ssl.create_default_context()

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not allow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read()
            try:
                text = body.decode("utf-8", "replace")
            except Exception:
                text = body.decode("latin-1", "replace")
            return NetResponse(status=resp.status, headers=dict(resp.headers),
                               text=text, url=url, ok=True)
    except Exception as exc:
        # urllib raises HTTPError for every non-2xx status (and for 3xx when
        # redirects are disabled); surface the real status instead of treating
        # it like a transport failure.
        if isinstance(exc, urllib.error.HTTPError):
            body = exc.read()
            try:
                text = body.decode("utf-8", "replace")
            except Exception:
                text = body.decode("latin-1", "replace")
            return NetResponse(status=exc.code, headers=dict(exc.headers),
                               text=text, url=url, ok=True)
        return NetResponse(status=0, text="", url=url, ok=False,
                           error=f"{type(exc).__name__}: {exc}")


def get(url: str, **kw) -> NetResponse:
    return request("GET", url, **kw)


def post(url: str, **kw) -> NetResponse:
    return request("POST", url, **kw)
