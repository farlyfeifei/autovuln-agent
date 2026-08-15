"""Parsing / offline-analysis tools: encoding decode + hash identification & crack.

Both tools are subclasses of :class:`tools.registry.Tool` and are wired into the
real registry by ``tools/registry.build_real_registry``.  They are fully
offline, pure-Python (no network, no third-party deps):

* ``DecodeTool`` ("decode") — decode common CTF encodings: base64 / hex /
  url-encoding / single-byte XOR / rot13, or auto-detect among them.  Falls
  back to ``challenge.extra["cipher"]`` / ``challenge.extra["token"]`` when no
  ``text`` param is supplied.
* ``HashCrackTool`` ("hash_crack") — identify a hash type by its length/format
  (md5 / sha1 / sha256 / sha512 / md5-crypt) and attempt a bounded offline
  wordlist + numeric lookup so weak values crack instantly.

Tools must never raise — every error is surfaced inside
``ToolResult.observation``.

Contract (do not rename):
    DecodeTool    -> "decode"
    HashCrackTool -> "hash_crack"
"""
from __future__ import annotations

import base64
import codecs
import hashlib
from typing import Any, Iterable, List, Optional, Tuple
from urllib.parse import unquote, unquote_plus

from core.flags import extract_flags
from core.types import Challenge, ToolResult
from tools.registry import Tool

# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #


def _coerce_str(value: Any) -> str:
    """Turn a param / ``extra`` value into a ``str`` (handles ``bytes``)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        for enc in ("utf-8", "latin-1"):
            try:
                return value.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
        return value.decode("latin-1", "replace")
    return str(value)


def _clip(text: str, limit: int = 300) -> str:
    """Truncate a value for the observation while hinting at the real length."""
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f" ...[+{len(text) - limit} chars]"


def _as_bytes(text: str) -> bytes:
    """Interpret a string as raw bytes (latin-1 preserves arbitrary bytes)."""
    try:
        return text.encode("latin-1")
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace")


def _to_text(data: bytes) -> str:
    """Decode bytes preferring UTF-8, falling back to a lossless 1:1 mapping."""
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
    return data.decode("latin-1", "replace")


def _printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII (or whitespace/controls)."""
    if not data:
        return 0.0
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(data)


def _is_texty(data: bytes) -> bool:
    """Heuristic for 'this bytes buffer is actually readable text'."""
    return len(data) > 0 and _printable_ratio(data) >= 0.8


def _result(tool: str, obs_lines: List[str], params: dict, ok: bool = True) -> ToolResult:
    """Build a ``ToolResult`` and surface any brace-style flags as trailing lines."""
    observation = "\n".join(obs_lines)
    flags = extract_flags(observation)
    if flags:
        obs_lines = list(obs_lines) + [f"  [flag] {f}" for f in flags]
        observation = "\n".join(obs_lines)
    return ToolResult(
        tool=tool, observation=observation, params=dict(params or {}),
        flags=extract_flags(observation), ok=ok,
    )


# --------------------------------------------------------------------------- #
# DecodeTool
# --------------------------------------------------------------------------- #

_MAX_XOR_BRUTEFORCE = 4096  # keep the 256-key scan instant even on long inputs

_COMMON_PRINT = b" etaoinshrdlucmfwypvbgkjqxzETAOINSHRDLUCMFWYPVBGKJQXZ.,!?;:'\"-()[]{}_/0123456789\n\r\t"


def _b64_variants(text: str) -> List[str]:
    """Normalised base64 candidates: whitespace stripped, padded, url-safe."""
    s = "".join(text.split())
    variants = [s]
    pad = len(s) % 4
    if pad:
        variants.append(s + "=" * (4 - pad))
    if "-" in s or "_" in s:
        alt = s.replace("-", "+").replace("_", "/")
        if alt not in variants:
            variants.append(alt)
        if pad:
            alt_padded = alt + "=" * (4 - pad)
            if alt_padded not in variants:
                variants.append(alt_padded)
    return variants


def _try_b64(text: str) -> Optional[bytes]:
    """Best-effort base64 decode; returns ``None`` when every variant fails."""
    for variant in _b64_variants(text):
        if not variant:
            continue
        try:
            return base64.b64decode(variant, validate=False)
        except Exception:
            continue
    return None


def _try_hex(text: str) -> Optional[bytes]:
    """Best-effort hex decode (tolerates ``0x``, colons, dashes, whitespace)."""
    s = (text.strip().replace("0x", "").replace("0X", "")
         .replace(":", "").replace("-", "")
         .replace(" ", "").replace("\t", "").replace("\n", "").replace("\r", ""))
    if not s or len(s) % 2:
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


def _caesar(text: str, shift: int) -> str:
    """Shift every ASCII letter by *shift* mod 26 (non-letters pass through)."""
    shift %= 26
    if not shift:
        return text
    out: List[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def _score_bytes(data: bytes) -> float:
    """Rate how 'plaintext-like' a buffer is (printable + common-char bonus).

    A brace-style flag pattern (``flag{``/``ctf{``/``key{``) and word spaces
    are strong extra signals, so a real decoded flag beats a random printable
    string that happens to score the same character-wise.
    """
    if not data:
        return 0.0
    total = 0.0
    for b in data:
        if 32 <= b < 127 or b in (9, 10, 13):
            total += 1.0
            if b in _COMMON_PRINT:
                total += 1.5
    lower = data.lower()
    if b"flag{" in lower or b"ctf{" in lower or b"key{" in lower:
        total += 20.0
    total += 0.5 * data.count(b" ")
    return total


def _xor_bruteforce(data: bytes, key: Optional[int] = None) -> Tuple[Optional[int], bytes, float]:
    """Single-byte XOR: fixed *key* if given (0..255), else brute-force all keys.

    Returns ``(best_key, plaintext, score)``.  ``best_key`` is ``None`` for
    empty input.
    """
    if not data:
        return None, b"", 0.0
    if key is not None:
        if 0 <= key <= 255:
            out = bytes(b ^ key for b in data)
            return key, out, _score_bytes(out)
        key = None  # out-of-range key -> fall back to brute force
    best_key, best_out, best_score = 0, b"", -1.0
    for k in range(256):
        out = bytes(b ^ k for b in data)
        score = _score_bytes(out)
        if score > best_score:
            best_key, best_out, best_score = k, out, score
    return best_key, best_out, best_score


def _xor_data(text: str) -> bytes:
    """Bytes to feed the XOR brute-forcer.

    A ciphertext is usually transmitted as hex, so hex-decode it first; only
    fall back to the raw string bytes when it is not valid hex.
    """
    raw = _try_hex(text)
    if raw is not None:
        return raw
    return _as_bytes(text)[:_MAX_XOR_BRUTEFORCE]


def _auto_decode(text: str) -> List[Tuple[str, str]]:
    """Try b64, hex, url, xor-best in order; return every texty decoding.

    XOR is a fallback: it is only reported when no b64/hex/url match exists or
    its output itself contains a flag, so a normal hex/base64/url ciphertext
    does not also produce a spurious xor line.
    """
    results: List[Tuple[str, str]] = []

    raw = _try_b64(text)
    if raw is not None and _is_texty(raw):
        results.append(("b64", _to_text(raw)))

    raw = _try_hex(text)
    if raw is not None and _is_texty(raw):
        results.append(("hex", _to_text(raw)))

    plain = unquote_plus(text)
    if plain != text and _is_texty(plain.encode("latin-1", "replace")):
        results.append(("url", plain))

    data = _xor_data(text)
    best_key, out, _ = _xor_bruteforce(data)
    # key 0 is the identity transform (plaintext came through untouched) —
    # not a real decoding, so skip it
    if best_key is not None and best_key != 0 and _is_texty(out):
        decoded = _to_text(out)
        if not results or extract_flags(decoded):
            results.append((f"xor(0x{best_key:02x})", decoded))

    return results


class DecodeTool(Tool):
    """Decode common CTF encodings (base64 / hex / url / xor / rot13 / auto)."""

    name = "decode"
    description = ("Decode common CTF encodings offline. "
                   "params: {scheme: 'b64'|'base64'|'hex'|'url'|'xor'|'rot13'|'auto' "
                   "(default 'auto'), text: str (optional - falls back to "
                   "challenge.extra['cipher'] / ['token']), key: int (optional). "
                   "For xor: the single byte used to encode (0-255; brute-forced "
                   "when omitted). For rot13: the caesar shift used to encode "
                   "(default 13; the inverse shift is applied to decode). "
                   "Reports each decoding result and any flags found.")

    def run(self, challenge: Challenge, params: dict) -> ToolResult:
        try:
            return self._run(challenge, params or {})
        except Exception as exc:  # defensive: never raise
            return ToolResult(
                tool=self.name, ok=False, params=dict(params or {}),
                observation=f"[decode] error: {type(exc).__name__}: {exc}",
            )

    def _run(self, challenge: Challenge, params: dict) -> ToolResult:
        scheme = str(params.get("scheme") or "auto").strip().lower()
        if scheme == "base64":
            scheme = "b64"
        if scheme not in ("b64", "hex", "url", "xor", "rot13", "auto"):
            scheme = "auto"

        text = params.get("text")
        if text is None:
            text = challenge.extra.get("cipher")
        if text is None:
            text = challenge.extra.get("token")
        if text is None:
            return ToolResult(
                tool=self.name, ok=False, params=dict(params or {}),
                observation="[decode] error: no input text "
                            "(pass params['text'] or set challenge.extra 'cipher'/'token')",
            )
        text = _coerce_str(text)

        key_raw = params.get("key")
        try:
            key: Optional[int] = int(str(key_raw), 10) if key_raw is not None else None
        except (TypeError, ValueError):
            key = None

        lines = [
            f"[decode] scheme={scheme}, input={_clip(text, 160)!r} (len={len(text)})",
        ]

        if scheme == "b64":
            raw = _try_b64(text)
            if raw is None:
                lines.append("  b64: decode failed (invalid base64 input)")
            else:
                lines.append(f"  b64 -> {_clip(_to_text(raw), 300)!r}")
        elif scheme == "hex":
            raw = _try_hex(text)
            if raw is None:
                lines.append("  hex: decode failed (not valid hex / odd length)")
            else:
                lines.append(f"  hex -> {_clip(_to_text(raw), 300)!r}")
        elif scheme == "url":
            plain = unquote(text)
            lines.append(f"  url(unquote) -> {_clip(plain, 300)!r}")
            plus = unquote_plus(text)
            if plus != plain:
                lines.append(f"  url(unquote_plus) -> {_clip(plus, 300)!r}")
        elif scheme == "rot13":
            if key is not None and key % 26 != 13:
                # generalised caesar: the key is the shift used to ENCODE, so a
                # decoder applies the inverse shift (mirrors xor's semantics)
                encode_shift = key % 26
                applied = (-encode_shift) % 26
                lines.append(f"  caesar(encode shift={encode_shift}, decode inverse={applied}) "
                             f"-> {_clip(_caesar(text, applied), 300)!r}")
            else:
                lines.append(f"  rot13 -> {_clip(codecs.encode(text, 'rot13'), 300)!r}")
        elif scheme == "xor":
            data = _xor_data(text)
            truncated = len(data) > _MAX_XOR_BRUTEFORCE
            data = data[:_MAX_XOR_BRUTEFORCE]
            best_key, out, _ = _xor_bruteforce(data, key=key)
            if best_key is None:
                lines.append("  xor: empty input")
            else:
                lines.append(f"  xor(key=0x{best_key:02x}) -> {_clip(_to_text(out), 300)!r}"
                             + ("  (note: input truncated to first %d bytes)" % _MAX_XOR_BRUTEFORCE if truncated else ""))
                if not _is_texty(out):
                    lines.append("  (output not clearly printable — try another scheme or a different key)")
        else:  # auto
            results = _auto_decode(text)
            if not results:
                lines.append("  auto: no encoding matched — input may already be plaintext")
                lines.append(f"  input as-is: {_clip(text, 300)!r}")
            else:
                lines.append("  auto matched:")
                for found_scheme, decoded in results:
                    lines.append(f"    {found_scheme} -> {_clip(decoded, 300)!r}")

        return _result(self.name, lines, params)


# --------------------------------------------------------------------------- #
# HashCrackTool
# --------------------------------------------------------------------------- #

_HEXCHARS = frozenset("0123456789abcdefABCDEF")

_BASE_WORDS = (
    "flag", "ctf", "key", "admin", "administrator", "root", "toor", "user",
    "guest", "username", "name", "login", "password", "pass", "passwd", "pwd",
    "test", "test1", "test123", "test1234", "testing", "secret", "secret123",
    "letmein", "letmein123", "qwerty", "qwerty123", "qwertyuiop", "welcome",
    "welcome1", "iloveyou", "dragon", "monkey", "sunshine", "princess",
    "football", "baseball", "master", "shadow", "michael", "abc123", "ninja",
    "mustang", "password1", "password123", "123456", "123456789", "12345",
    "12345678", "1234567", "654321", "111111", "112233", "000000", "012345",
    "987654", "121212", "123123", "123321", "passw0rd", "p@ssw0rd", "p@ssword",
    "pa55w0rd", "adm1n", "4dm1n", "letme1n", "l3tm31n", "monkey123", "qwerty1",
    "abc12345", "football123", "admin123", "root123", "toor123", "guest123",
    "user123", "changeme", "changeit", "default", "default1", "system",
    "system123", "temp", "temp123", "dev", "developer", "testpass",
    "testpass123", "oracle", "mysql", "postgres", "redis", "ubuntu", "centos",
    "vagrant", "docker", "pass123", "1q2w3e4r", "1qaz2wsx", "qazwsx",
    "zaq12wsx", "asdf", "asdfgh", "zxcvbn", "trustno1", "dragon1", "monkey1",
    "sunshine1", "princess1", "freedom", "whatever", "hello", "hello123",
    "letmein1", "welcome123", "access", "access1", "opensesame", "iloveu",
    "computer", "internet", "software", "monday", "tuesday", "wednesday",
    "thursday", "friday", "saturday", "sunday", "january", "february", "march",
    "april", "may", "june", "july", "august", "september", "october",
    "november", "december", "summer", "winter", "spring", "autumn",
    "hunter", "harley", "batman", "superman", "soccer", "basketball", "hockey",
    "panthers", "tigers", "liverpool", "arsenal", "chelsea", "pepper",
    "pepper1", "ginger", "cookie", "cookie1", "banana", "orange", "mango",
    "apple", "pineapple", "strawberry", "chocolate", "pizza", "cheese",
    "hamburger", "coffee", "coffee1", "starwars", "pokemon", "naruto",
    "adminadmin", "testing123", "debug", "backup", "rootroot", "mysecret",
    "supersecret", "topsecret", "gandalf", "linux", "windows", "android",
    "google", "facebook", "amazon", "microsoft", "hacker", "hacker123",
    "rootme", "terminal", "shell", "nmap", "burp", "kali", "metasploit",
    "sqlmap", "hydra", "john", "pentester", "ctf123", "flag1", "flag123",
    "flagflag", "pwned", "pwnd", "pwn", "exploit", "exploit1", "challenge",
    "challenge1", "solution", "answer", "answer1", "passwordpassword",
    "passpass", "passpass123", "defaultpassword", "adminpass", "adminpass1",
    "123qwe", "qwe123", "zxc123", "asd123", "qweasd", "qweasdzxc",
    "pass1234", "pass12345", "liverpool1", "arsenal1", "chelsea1",
    "superman1", "batman1", "starwars1", "pokemon1", "naruto1",
)

_LEET_MAP = {
    "a": ("@", "4"), "e": ("3",), "i": ("1", "!"), "o": ("0",),
    "s": ("$", "5"), "t": ("7",), "l": ("1",), "g": ("9",), "b": ("8",),
}


def _leet_variants(word: str, max_variants: int = 6) -> List[str]:
    """A small bounded set of leetspeak variants for a single base word."""
    lower = word.lower()
    out: List[str] = []
    for idx, ch in enumerate(lower):
        for rep in _LEET_MAP.get(ch, ()):
            cand = word[:idx] + rep + word[idx + 1:]
            if cand not in out:
                out.append(cand)
    # a couple of double-substitution variants for extra coverage
    singles = [(idx, rep) for idx, ch in enumerate(lower) for rep in _LEET_MAP.get(ch, ())]
    added = 0
    for i in range(len(singles)):
        for j in range(i + 1, len(singles)):
            i1, r1 = singles[i]
            i2, r2 = singles[j]
            if i1 == i2:
                continue
            cand = list(word)
            cand[i1] = r1
            cand[i2] = r2
            combo = "".join(cand)
            if combo not in out:
                out.append(combo)
                added += 1
                if added >= 3:
                    break
        if added >= 3:
            break
    return out[:max_variants]


def _build_common_words() -> Tuple[str, ...]:
    """Base words + leetspeak variants -> a few-hundred-entry dictionary."""
    words: List[str] = []
    for w in _BASE_WORDS:
        if w not in words:
            words.append(w)
    for w in _BASE_WORDS[:80]:  # leet variants only for the most common bases
        for v in _leet_variants(w):
            if v not in words:
                words.append(v)
    return tuple(words)


COMMON_WORDS: Tuple[str, ...] = _build_common_words()


def _iter_candidates(htype: str) -> Iterable[str]:
    """Dictionary words then a bounded numeric range (kept instant)."""
    for w in COMMON_WORDS:
        yield w
    if htype == "md5crypt":
        # md5-crypt runs 1000 hash rounds per candidate — keep the range small
        for n in range(1000):
            yield str(n)
    else:
        for n in range(10_000):  # 0..9999 plain + zero-padded 4-digit PINs
            yield str(n)
            yield f"{n:04d}"


def _is_hex(value: str, length: int) -> bool:
    return len(value) == length and all(c in _HEXCHARS for c in value)


def detect_hash_type(value: str) -> str:
    """Guess md5 / sha1 / sha256 / sha512 / md5crypt from length and format."""
    v = value.strip()
    if v.startswith("$1$") and "$" in v[len("$1$"):]:
        return "md5crypt"
    if _is_hex(v, 32):
        return "md5"
    if _is_hex(v, 40):
        return "sha1"
    if _is_hex(v, 64):
        return "sha256"
    if _is_hex(v, 128):
        return "sha512"
    return "unknown"


def _split_md5crypt(value: str) -> Tuple[Optional[str], str]:
    """Return ``(salt, encoded_digest)`` from a ``$1$salt$digest`` string."""
    if not value.startswith("$1$"):
        return None, value
    rest = value[len("$1$"):]
    if "$" not in rest:
        return None, value
    salt, encoded = rest.split("$", 1)
    return salt, encoded


_MD5_CRYPT_64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _to64(value: int, count: int) -> str:
    """Emit *count* crypt-base64 chars, least-significant group first."""
    out: List[str] = []
    for _ in range(count):
        out.append(_MD5_CRYPT_64[value & 0x3F])
        value >>= 6
    return "".join(out)


def _md5_crypt_encode(digest: bytes) -> str:
    """Encode the 16-byte MD5-crypt digest into its 22-char alphabet."""
    if len(digest) != 16:
        raise ValueError("md5-crypt expects a 16-byte digest")
    return (
        _to64((digest[0] << 16) | (digest[6] << 8) | digest[12], 4)
        + _to64((digest[1] << 16) | (digest[7] << 8) | digest[13], 4)
        + _to64((digest[2] << 16) | (digest[8] << 8) | digest[14], 4)
        + _to64((digest[3] << 16) | (digest[9] << 8) | digest[15], 4)
        + _to64((digest[4] << 16) | (digest[10] << 8) | digest[5], 4)
        + _to64(digest[11], 2)
    )


def _md5_crypt(password: bytes, salt: bytes) -> str:
    """Pure-Python MD5-crypt (the ``$1$`` scheme) — no ``crypt`` module needed.

    Follows the OpenSSL / glibc reference algorithm (apps/passwd.c) so the
    result is identical to ``openssl passwd -1`` and to Linux ``crypt(3)`` on
    Windows (where the ``crypt`` module is unavailable).  Verified against the
    reference outputs for ("test","salt"), ("password","1234") and
    ("a_long_random_secret_xyz","s0m3s4lt").
    """
    salt = salt[:8]
    md = hashlib.md5(password + b"$1$" + salt)
    buf = hashlib.md5(password + salt + password).digest()

    # mix the alternate digest in as many whole blocks as the password is long
    remaining = len(password)
    while remaining > 16:
        md.update(buf)
        remaining -= 16
    md.update(buf[:remaining])

    # append one byte per bit of the password length (NUL if the bit is set,
    # otherwise the password's first byte) — the step most naive ports miss
    n = len(password)
    while n:
        md.update(b"\x00" if n & 1 else password[:1])
        n >>= 1
    buf = md.digest()

    # 1000 "weird" rounds, alternating password / previous digest
    for i in range(1000):
        ctx2 = hashlib.md5()
        if i & 1:
            ctx2.update(password)
        else:
            ctx2.update(buf)
        if i % 3:
            ctx2.update(salt)
        if i % 7:
            ctx2.update(password)
        if i & 1:
            ctx2.update(buf)
        else:
            ctx2.update(password)
        buf = ctx2.digest()
    return "$1$" + salt.decode("latin-1") + "$" + _md5_crypt_encode(buf)


def _hash_hex(value: str, htype: str) -> str:
    """Hash one plaintext candidate for the given (non-crypt) hash type."""
    data = value.encode("utf-8")
    if htype == "md5":
        return hashlib.md5(data).hexdigest()
    if htype == "sha1":
        return hashlib.sha1(data).hexdigest()
    if htype == "sha256":
        return hashlib.sha256(data).hexdigest()
    if htype == "sha512":
        return hashlib.sha512(data).hexdigest()
    return ""


def _matches(value: str, htype: str, salt: Optional[str], candidate: str) -> bool:
    """Compare one candidate against the target hash (never raises)."""
    if htype == "md5crypt":
        if not salt:
            return False
        try:
            return _md5_crypt(candidate.encode("latin-1"), salt.encode("latin-1")) == value
        except Exception:
            return False
    return _hash_hex(candidate, htype) == value.lower()


class HashCrackTool(Tool):
    """Identify a hash type and attempt a bounded offline wordlist + numeric lookup."""

    name = "hash_crack"
    description = ("Identify a hash (md5/sha1/sha256/sha512/md5-crypt) by length/format "
                   "and try a bounded offline dictionary + numeric lookup for weak values. "
                   "params: {hash: str, type: 'auto'|'md5'|'sha1'|'sha256'|'sha512'|'md5crypt' "
                   "(default 'auto')}. Only small/weak secrets crack; larger ones are "
                   "reported as needing a bigger cracker (hashcat/john).")

    def run(self, challenge: Challenge, params: dict) -> ToolResult:
        try:
            return self._run(challenge, params or {})
        except Exception as exc:  # defensive: never raise
            return ToolResult(
                tool=self.name, ok=False, params=dict(params or {}),
                observation=f"[hash_crack] error: {type(exc).__name__}: {exc}",
            )

    def _run(self, challenge: Challenge, params: dict) -> ToolResult:
        value = params.get("hash")
        if value is None:
            value = challenge.extra.get("hash")
        if value is None:
            value = challenge.extra.get("hash_value")
        if value is None:
            return ToolResult(
                tool=self.name, ok=False, params=dict(params or {}),
                observation="[hash_crack] error: no hash value (pass params['hash'])",
            )
        value = _coerce_str(value).strip()
        if not value:
            return ToolResult(
                tool=self.name, ok=False, params=dict(params or {}),
                observation="[hash_crack] error: empty hash value",
            )

        htype = str(params.get("type") or "auto").strip().lower()
        if htype not in ("auto", *("md5", "sha1", "sha256", "sha512", "md5crypt")):
            return ToolResult(
                tool=self.name, ok=False, params=dict(params or {}),
                observation=f"[hash_crack] error: unknown type {htype!r} "
                            "(valid: auto, md5, sha1, sha256, sha512, md5crypt)",
            )
        if htype == "auto":
            htype = detect_hash_type(value)

        lines = [
            f"[hash_crack] type={htype}, hash={_clip(value, 90)!r}",
        ]

        salt: Optional[str] = None
        if htype == "md5crypt":
            salt, encoded = _split_md5crypt(value)
            lines.append(f"  md5crypt: salt={salt!r} digest={_clip(encoded, 60)!r}")
        elif htype == "unknown":
            lines.append("  format: not recognised (md5=32 hex, sha1=40, sha256=64, "
                         "sha512=128, md5crypt=$1$...)")
            lines.append("  not in small wordlist (may need larger cracking)")
            lines.append("  hint: pass params['type'] to force a scheme, or crack "
                         "offline with hashcat/john")
            return _result(self.name, lines, params)

        found: Optional[str] = None
        count = 0
        for candidate in _iter_candidates(htype):
            count += 1
            if _matches(value, htype, salt, candidate):
                found = candidate
                break

        lines.append(f"  candidates tried: {count} ({len(COMMON_WORDS)} words + numeric range)")
        if found is not None:
            lines.append(f"  cracked: {found!r}")
            lines.append("  note: plaintext value found matches the given hash")
        else:
            lines.append("  not in small wordlist (may need larger cracking)")
            lines.append("  hint: try a larger dictionary, hybrid masks, or hashcat/john")
        return _result(self.name, lines, params)
