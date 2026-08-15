"""HTTP adapter: manifest-loaded challenges + HTTP flag submission.

This adapter talks to any scoring platform exposing a plain REST contract:

* challenge list  -> a local JSON manifest (see :func:`load_challenges_manifest`)
* tool registry   -> the real, network-capable tool set (built lazily on the
                     first ``tool_registry()`` call so importing this module
                     never touches the tool modules)
* flag submission -> ``POST {challenge_id, flag}`` with an optional
                     ``Authorization: Bearer <token>`` header; success is an
                     HTTP 2xx whose JSON body carries ``retcode`` 0/"0" or the
                     word "success".

The class never raises: every network or parsing failure inside ``submit()``
is swallowed and reported as ``False``.
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

from core.net import post
from core.types import Challenge
from tools.registry import ToolRegistry
from adapters.base import Adapter

# Fields that map onto real Challenge attributes; anything else in a manifest
# entry is folded into ``extra`` so manifests may carry mock metadata too.
_CHALLENGE_FIELDS = {
    "id", "name", "category", "description", "target", "points",
    "ground_truth_flag", "win_tool", "win_params", "solvable", "extra",
}


def _as_str(value: Any, field: str) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    return text


def _as_bool(value: Any, default: bool = True) -> bool:
    """Tolerate JSON strings for boolean fields ("false"/"0" are False)."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in ("", "0", "false", "no", "off")


def challenge_from_dict(entry: Dict[str, Any], index: int = 0) -> Challenge:
    """Build one :class:`Challenge` from a manifest dict.

    ``id``/``name``/``target`` are required and must be non-empty strings;
    everything else falls back to safe defaults. Unknown keys are preserved in
    ``extra`` so round-tripping mock-style manifests keeps ``win_tool`` etc.
    """
    if not isinstance(entry, dict):
        raise ValueError(
            f"challenge manifest entry #{index} is not an object: {entry!r}")

    cid = _as_str(entry.get("id"), "id")
    name = _as_str(entry.get("name"), "name")
    target = _as_str(entry.get("target"), "target")
    if not cid:
        raise ValueError(f"challenge manifest entry #{index} is missing 'id'")
    if not name:
        raise ValueError(f"challenge manifest entry #{index} is missing 'name'")
    if not target:
        raise ValueError(f"challenge manifest entry #{index} is missing 'target'")

    points = entry.get("points", 0)
    try:
        points = int(points)
    except (TypeError, ValueError):
        points = 0

    win_params = entry.get("win_params") or {}
    if not isinstance(win_params, dict):
        win_params = {}

    extra = dict(entry.get("extra") or {})
    for key, value in entry.items():
        if key not in _CHALLENGE_FIELDS:
            extra[key] = value

    return Challenge(
        id=cid,
        name=name,
        category=_as_str(entry.get("category"), "category"),
        description=_as_str(entry.get("description"), "description"),
        target=target,
        points=points,
        ground_truth_flag=_as_str(entry.get("ground_truth_flag"), "ground_truth_flag") or None,
        win_tool=_as_str(entry.get("win_tool"), "win_tool") or None,
        win_params=win_params,
        solvable=_as_bool(entry.get("solvable"), default=True),
        extra=extra,
    )


def load_challenges_manifest(path: str) -> List[Challenge]:
    """Read a JSON challenge manifest file into ``Challenge`` objects.

    The file must contain a JSON array of objects with ``id``/``name``/``target``
    (``category``/``description``/``points`` optional, ``ground_truth_flag``
    optional). A top-level ``{"challenges": [...]}`` wrapper is also accepted.

    Raises ``FileNotFoundError``/``ValueError`` with a clear message when the
    file is missing, unparseable, or does not look like a manifest.
    """
    if not path:
        raise ValueError("challenge manifest path is empty")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"challenge manifest not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read challenge manifest {path!r}: {exc}") from exc

    if isinstance(data, dict) and isinstance(data.get("challenges"), list):
        data = data["challenges"]
    if not isinstance(data, list):
        raise ValueError(
            f"challenge manifest {path!r} must be a JSON array of objects, "
            f"got {type(data).__name__}")

    challenges: List[Challenge] = []
    for index, entry in enumerate(data):
        try:
            challenges.append(challenge_from_dict(entry, index))
        except ValueError as exc:
            raise ValueError(f"invalid challenge manifest {path!r}: {exc}") from exc
    return challenges


_SUCCESS_WORD_RE = re.compile(r"\b(?:success|ok|accepted)\b", re.IGNORECASE)


def _retcode_ok(data: Any) -> bool:
    """True only when the submission envelope reports ``retcode`` 0/"0".

    Checks the top-level object first, then the common wrapping shapes
    (``{"data": {"retcode": 0}}`` etc). Deliberately does NOT recurse with
    "any" semantics: a nested `retcode` inside an error object must never be
    mistaken for submission success.
    """
    if isinstance(data, dict):
        if "retcode" in data:
            return data["retcode"] in (0, "0")
        for key in ("data", "result", "body", "payload"):
            value = data.get(key)
            if isinstance(value, dict) and "retcode" in value:
                return value["retcode"] in (0, "0")
    return False


def _body_indicates_success(text: str) -> bool:
    """True if the response body means "submission accepted"."""
    body = (text or "").strip()
    if not body:
        return False
    # A structured body decides by retcode alone; the word fallback only
    # applies to plain-text bodies and must match a whole word (so
    # "unsuccessful" / "failed" never read as success).
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return bool(_SUCCESS_WORD_RE.search(body))
    return _retcode_ok(data)


class HttpAdapter(Adapter):
    """Adapter for a generic HTTP-scoring backend.

    :param challenges: challenge set; defaults to ``[]`` (load one via
        :func:`load_challenges_manifest`).
    :param submit_endpoint: full URL that accepts ``POST {challenge_id, flag}``.
    :param token: bearer token for the ``Authorization`` header (may be empty).
    """

    name: str = "http"

    def __init__(
        self,
        challenges: Optional[List[Challenge]] = None,
        submit_endpoint: str = "",
        token: str = "",
    ) -> None:
        self.challenges: List[Challenge] = list(challenges) if challenges is not None else []
        self.submit_endpoint: str = (submit_endpoint or "").strip()
        self.token: str = token or ""
        self._registry: Optional[ToolRegistry] = None

    def list_challenges(self) -> List[Challenge]:
        return self.challenges

    def tool_registry(self) -> ToolRegistry:
        """Return the real tool registry, built once and lazily.

        The registry (and with it every tool module) is only constructed on the
        first call, so importing this module has no side effects on the tools
        package — useful for dry runs that never execute tools.
        """
        if self._registry is None:
            from tools.registry import build_real_registry  # deferred on purpose
            self._registry = build_real_registry()
        return self._registry

    def submit(self, challenge: Challenge, flag: str) -> bool:
        """POST ``{challenge_id, flag}`` to the scoring endpoint.

        Returns ``True`` only for HTTP 2xx responses whose body carries a JSON
        ``retcode`` of 0/"0" or the word "success". Every failure — missing
        endpoint, network error, non-2xx, bad body — returns ``False`` and never
        raises.
        """
        if not self.submit_endpoint:
            print(f"[http] submit disabled: no submit_endpoint configured "
                  f"(challenge={challenge.id!r}, flag={'<set>' if (flag or '').strip() else '<empty>'})",
                  file=sys.stderr)
            return False

        flag = (flag or "").strip()
        if not flag:
            return False

        headers: Dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            resp = post(
                self.submit_endpoint,
                json={"challenge_id": challenge.id, "flag": flag},
                headers=headers,
            )
        except Exception as exc:  # never raise from an adapter
            print(f"[http] submit request error: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            return False

        if not (200 <= resp.status < 300):
            return False
        return _body_indicates_success(resp.text)
