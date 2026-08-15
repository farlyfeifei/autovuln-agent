"""Flag extraction helpers.

Recognises the common CTF flag shapes (``flag{...}``, ``FLAG{...}``, ``CTF{...}``,
``key{...}``) plus long hex tokens (md5/sha style). The ReAct policy uses
:func:`extract_flag` to decide when it has "seen" a flag in a tool observation.
"""
from __future__ import annotations

import re
from typing import List, Optional

# Brace-style flags, case-insensitive prefix. Kept greedy-safe with [^}].
_BRACE_PATTERNS = [
    re.compile(r"(?:flag|ctf|key)\{[^}\r\n]{1,256}\}", re.IGNORECASE),
]

# Long hex tokens (e.g. md5=32, sha1=40, sha256=64). Secondary signal only.
_HEX_PATTERN = re.compile(r"\b[0-9a-fA-F]{32,64}\b")


def extract_flags(text: str) -> List[str]:
    """Return every brace-style flag found in *text*, in order, de-duplicated."""
    if not text:
        return []
    seen: set[str] = set()
    found: List[str] = []
    for pattern in _BRACE_PATTERNS:
        for match in pattern.finditer(text):
            token = match.group(0)
            if token not in seen:
                seen.add(token)
                found.append(token)
    return found


def extract_hex_tokens(text: str) -> List[str]:
    """Return long hex tokens found in *text* (secondary flag heuristic)."""
    if not text:
        return []
    return list(dict.fromkeys(_HEX_PATTERN.findall(text)))


def extract_flag(text: str) -> Optional[str]:
    """Return the first brace-style flag in *text*, or ``None`` if absent."""
    flags = extract_flags(text)
    return flags[0] if flags else None
