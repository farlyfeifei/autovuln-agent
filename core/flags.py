"""Flag extraction helpers.

Recognises the common CTF flag shapes (``flag{...}``, ``FLAG{...}``, ``CTF{...}``,
``key{...}``) plus long hex tokens (md5/sha style) as a secondary signal.
"""
from __future__ import annotations

import re
from typing import List, Optional

BRACE_PATTERNS = [
    re.compile(r"(?<![A-Za-z0-9_])flag\{[^}\r\n]{1,256}\}", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z0-9_])ctf\{[^}\r\n]{1,256}\}", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z0-9_])key\{[^}\r\n]{1,256}\}", re.IGNORECASE),
]

HEX_PATTERN = re.compile(r"\b[0-9a-fA-F]{32,64}\b")


def extract_flags(text: str) -> List[str]:
    """Return every brace-style flag found in *text*, in order, de-duplicated."""
    if not text:
        return []
    seen: set = set()
    found: List[str] = []
    for pattern in BRACE_PATTERNS:
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
    return list(dict.fromkeys(HEX_PATTERN.findall(text)))


def extract_flag(text: str) -> Optional[str]:
    """Return the first brace-style flag in *text*, or a hex token, or None."""
    flags = extract_flags(text)
    if flags:
        return flags[0]
    hexes = extract_hex_tokens(text)
    return hexes[0] if hexes else None
