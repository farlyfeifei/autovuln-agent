"""Probe the Tsecbench per-run answering API (BENCHMARK_BASE_URL).

Once a run is created on the platform, the running page shows BENCHMARK_TOKEN
and BENCHMARK_BASE_URL. That base URL is the *agent-facing* answering API (the
SPA at tsecbench.zc.tencent.com never calls it; the Agent does). Its exact
surface is unknown until a live run exists, so this script tries a battery of
plausible endpoints with the token in several auth positions and reports what
responds — one shot, read-only, no state changes.

Usage:
    python scripts/tsecbench_probe.py --base-url <BENCHMARK_BASE_URL> --token <BENCHMARK_TOKEN>
"""
from __future__ import annotations

import argparse
import json
import os
import sys

try:
    from core.net import get
except ImportError:
    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, _ROOT)
    from core.net import get

CANDIDATES = [
    "/",
    "/health",
    "/challenges",
    "/api/challenges",
    "/v1/challenges",
    "/api/v1/challenges",
    "/benchmark/challenges",
    "/runs",
    "/runs/me",
    "/run",
    "/env",
    "/info",
    "/manifest",
    "/challenge",
    "/openapi.json",
    "/docs",
]

AUTH_STYLES = ["bearer", "header", "query", "bare"]


def _request(base_url: str, path: str, token: str, style: str):
    headers = {}
    params = {}
    if style == "bearer":
        headers["Authorization"] = f"Bearer {token}"
    elif style == "header":
        headers["X-Token"] = token
        headers["Authorization"] = token
    elif style == "query":
        params["token"] = token
    elif style == "bare":
        headers["Authorization"] = token
    resp = get(base_url + path, headers=headers, params=params, timeout=8)
    return resp.status, (resp.text or "")[:300]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--token", required=True)
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    print(f"# probing {base}  (token len={len(args.token)})\n", file=sys.stderr)
    hits = []
    for style in AUTH_STYLES:
        for path in CANDIDATES:
            try:
                status, body = _request(base, path, args.token, style)
            except Exception as exc:
                print(f"[{style:>6}] {path:24s} ERR {type(exc).__name__}: {exc}", file=sys.stderr)
                continue
            tag = ""
            if status == 200:
                tag = "  <-- interesting"
                hits.append((style, path, status, body))
            print(f"[{style:>6}] {path:24s} -> {status}{tag}")
        print(file=sys.stderr)

    print("\n# 200 OK responses:", file=sys.stderr)
    for style, path, status, body in hits:
        print(f"[{style:>6}] {path}: {body}\n", file=sys.stdout)
    print(file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
