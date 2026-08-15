"""tsecbench-mock: a self-contained, stdlib-only CTF auto-solve scoring loop.

This package simulates an "AI agent that autonomously solves CTF challenges and
submits flags to a scoring platform" (in the spirit of tsecbench), fully offline:
no network, no API keys, no Docker, no real targets. Everything is deterministic
mock behaviour so the scoring loop can be demonstrated end-to-end.
"""
from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
