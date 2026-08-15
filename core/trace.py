"""Trace recording: dump/read ReAct trajectories as JSONL."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict
from typing import List

from .types import ChallengeResult, Step


def _atomic_write(path: str, lines: List[str]) -> None:
    """Write JSONL lines atomically: temp file + rename, so a crash mid-write
    never leaves a truncated trace that later readers choke on."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=os.path.dirname(path) or ".", prefix=os.path.basename(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_trace_jsonl(path: str, results: List[ChallengeResult]) -> None:
    _atomic_write(path, [json.dumps(asdict(r), ensure_ascii=False) for r in results])


def read_trace_jsonl(path: str) -> List[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write_steps(path: str, steps: List[Step]) -> None:
    _atomic_write(path, [json.dumps(asdict(s), ensure_ascii=False) for s in steps])
