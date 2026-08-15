"""Zero-dependency live web demo for AutoVulnAgent.

Serves a dark "agent console" page over stdlib ``http.server`` only (no
FastAPI/Flask) and broadcasts benchmark progress to every connected browser as
Server-Sent Events: one SSE event per ReAct step and per challenge, fanned out
to a per-client bounded queue so each open tab gets the full stream and one
slow tab can never stall the benchmark worker.

Run:
    python webdemo/app.py --port 8080

Endpoints:
    GET /          -> index.html (the agent console)
    GET /start     -> launch a MockAdapter + LocalPolicyLLM benchmark run once
    GET /events    -> SSE stream (initial ``ready`` + live step/challenge events)
    GET /stop      -> signal the running benchmark to stop at the next boundary
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

# Repo root goes on sys.path so this module works no matter which cwd it is
# launched from.  Top-level packages (core / llm / tools / adapters / ...) are
# sibling packages — never relative imports across packages.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Make the banner / request log readable on Windows consoles (cp936 vs UTF-8).
try:  # pragma: no cover (best-effort, no-op elsewhere)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

# Contract imports only (these are always present); the leaf siblings
# (adapters.mock / llm.local_policy) are imported lazily inside the benchmark
# worker so the demo page still serves even if one is momentarily unavailable.
from core.agent import run_benchmark  # noqa: E402
from core.types import Action, Budget  # noqa: E402
from config import load_config  # noqa: E402

_INDEX_PATH = os.path.join(_ROOT, "webdemo", "index.html")


class _StopRun(Exception):
    """Internal signal: stop the benchmark run at the next challenge boundary."""


# ---------------------------------------------------------------------------
# Shared module-level state (handlers share the flags; SSE clients each get a
# dedicated bounded queue registered in _CLIENTS).
# ---------------------------------------------------------------------------
_LOCK = threading.Lock()           # guards _STATE["running"] in the handlers
_CLIENTS_LOCK = threading.Lock()   # guards the per-client SSE queue registry
_CLIENTS: "set[queue.Queue]" = set()
_MAX_CLIENT_QUEUE = 2000           # per-client bound; a lagging tab drops events
_STATE: dict = {
    "running": False,           # True while a benchmark worker thread is alive
    "stop": threading.Event(),  # set by GET /stop, cleared by GET /start
    "current": None,            # Challenge currently being solved
    "steps_emitted": 0,         # per-challenge count of steps already emitted
    "results": [],              # completed ChallengeResults (summary helpers)
    "total_challenges": 0,
}


def _emit(payload: dict) -> None:
    """Broadcast one SSE payload to every connected client's queue.

    Each client has its own bounded queue with drop-oldest: a slow/lagged tab
    drops stale events instead of stalling the benchmark worker, and events are
    never consumed by one client at another's expense.
    """
    with _CLIENTS_LOCK:
        clients = list(_CLIENTS)
    for q in clients:
        try:
            q.put_nowait(payload)
        except queue.Full:
            try:
                q.get_nowait()      # drop this client's oldest event
                q.put_nowait(payload)
            except Exception:
                pass


def _send_event(wfile, evt_type: str, payload: dict) -> None:
    """Write one SSE frame (``event:`` + ``data:``) and flush it immediately."""
    data = json.dumps(payload, ensure_ascii=False)
    wfile.write(f"event: {evt_type}\ndata: {data}\n\n".encode("utf-8"))
    wfile.flush()


# ---------------------------------------------------------------------------
# Benchmark worker: run_benchmark callbacks + a real-time per-step probe.
# core/agent.py exposes only on_start/on_done, so the step stream is produced by
# wrapping the LLM's ``decide`` — that fires once per ReAct step, letting us
# emit each completed step the moment the next decision is made.
# ---------------------------------------------------------------------------
def _install_step_probe(llm) -> None:
    """Wrap ``llm.decide`` so every completed ReAct step is streamed in real
    time.  Assigning a plain function as an *instance* attribute (not a bound
    method) keeps the exact signature ``(challenge, history, budget)`` that
    ``solve_challenge`` calls with."""
    original = llm.decide

    def probe(challenge, history, budget):
        if _STATE["stop"].is_set():  # stop at the next step boundary
            return Action(tool="give_up", is_give_up=True,
                          thought="[webdemo] run stopped by user at step boundary")
        action = original(challenge, history, budget)
        emitted = _STATE["steps_emitted"]
        while emitted < len(history):  # history grew by one since last call
            step = history[emitted]
            _emit({
                "type": "step",
                "challenge_id": challenge.id,
                "index": step.index,
                "thought": step.thought,
                "action": step.action,
                "observation": step.observation,
                "flags": list(step.flags),
                "elapsed": round(step.elapsed, 3),
            })
            emitted += 1
        _STATE["steps_emitted"] = emitted
        return action

    llm.decide = probe  # type: ignore[method-assign]


def _on_start(challenge) -> None:
    """run_benchmark on_start: track the current challenge; abort if stopped."""
    if _STATE["stop"].is_set():  # stop at the next challenge boundary
        raise _StopRun()
    _STATE["current"] = challenge
    _STATE["steps_emitted"] = 0
    _emit({
        "type": "challenge_start",
        "id": challenge.id,
        "name": challenge.name,
        "category": challenge.category,
        "target": challenge.target,
    })


def _on_done(result) -> None:
    """run_benchmark on_done: emit trailing trace steps (e.g. the final submit)
    that were never seen by the step probe, then the challenge result."""
    start = _STATE["steps_emitted"]
    for step in result.trace[start:]:
        _emit({
            "type": "step",
            "challenge_id": result.challenge_id,
            "index": step.index,
            "thought": step.thought,
            "action": step.action,
            "observation": step.observation,
            "flags": list(step.flags),
            "elapsed": round(step.elapsed, 3),
        })
    _STATE["steps_emitted"] = len(result.trace)
    _STATE["results"].append(result)
    _emit({
        "type": "challenge_done",
        "id": result.challenge_id,
        "name": result.name,
        "category": result.category,
        "passed": bool(result.passed),
        "flag": result.submitted_flag or "",
        "ground_truth": result.ground_truth_flag or "",
        "steps": result.steps_used,
        "points": result.points_awarded,
        "elapsed": round(result.elapsed_sec, 3),
        "error": result.error or "",
    })


def _summary(reason: str) -> dict:
    results = _STATE["results"]
    return {
        "type": "done",
        "reason": reason,
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "points": sum(r.points_awarded for r in results),
    }


def _run_benchmark() -> None:
    """Background entry point: mock adapter + deterministic policy, streamed.

    Everything is wrapped so a failure inside a worker thread can never take
    the HTTP server down; the error is reported to the client as an SSE event.
    """
    adapter = None
    try:
        # Lazy imports: these leaf modules must not block serving the page.
        from adapters.mock import MockAdapter
        from llm.providers import build_llm

        cfg = load_config()
        budget = Budget(max_steps=cfg.budget.max_steps,
                        max_elapsed=cfg.budget.max_elapsed,
                        max_tokens=cfg.budget.max_tokens)
        adapter = MockAdapter()
        challenges = adapter.list_challenges()
        # Respect the configured provider: with an API key this drives a real
        # LLM (GLM/DeepSeek/...); without one build_llm falls back to the
        # deterministic local policy, keeping the demo fully offline.
        llm = build_llm(cfg.llm)
        _install_step_probe(llm)
        _STATE["total_challenges"] = len(challenges)

        _emit({
            "type": "run_start",
            "mode": adapter.name,
            "llm": getattr(llm, "name", "local-policy"),
            "challenges": len(challenges),
            "budget": {"max_steps": budget.max_steps,
                       "max_elapsed": budget.max_elapsed,
                       "max_tokens": budget.max_tokens},
        })
        run_benchmark(challenges, adapter, llm, budget,
                      on_start=_on_start, on_done=_on_done)
        # A user stop can also land mid-challenge: the step probe turns every
        # remaining decision into an immediate give-up, so run_benchmark still
        # returns normally — report the true reason instead of "completed".
        reason = "stopped" if _STATE["stop"].is_set() else "completed"
        _emit(_summary(reason))
    except _StopRun:
        _emit(_summary("stopped"))
    except Exception as exc:  # never crash the server from a worker thread
        _emit({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
        _emit(_summary("error"))
    finally:
        _STATE["running"] = False
        if adapter is not None:
            try:
                adapter.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# HTTP layer: stdlib ThreadingHTTPServer + BaseHTTPRequestHandler.
# ---------------------------------------------------------------------------
def _load_index() -> bytes:
    """Read index.html fresh on every request (live-editable page); empty bytes
    when missing, which the route turns into a clean 500 text response."""
    try:
        with open(_INDEX_PATH, "rb") as fh:
            return fh.read()
    except OSError:
        return b""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AutoVulnAgentDemo/0.2"

    # -- helpers -----------------------------------------------------------
    def _plain(self, code: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _safe_500(self, msg: str) -> None:
        try:
            self._plain(500, f"500 Internal Server Error\n{msg}\n")
        except OSError:
            pass

    # -- routes ------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        try:
            path = urllib.parse.urlparse(self.path).path
            if path in ("/", "/index.html"):
                self._serve_index()
            elif path == "/start":
                self._serve_start()
            elif path == "/stop":
                self._serve_stop()
            elif path == "/events":
                self._serve_events()
            elif path == "/favicon.ico":
                self._plain(404, "no favicon")
            else:
                self._plain(404, f"404 Not Found: {path}")
        except (BrokenPipeError, ConnectionResetError):
            pass  # client hung up mid-response — nothing to send
        except Exception as exc:
            self._safe_500(f"{type(exc).__name__}: {exc}")

    def _serve_index(self) -> None:
        data = _load_index()
        if not data:
            self._safe_500("webdemo/index.html is missing or empty")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _serve_start(self) -> None:
        with _LOCK:
            if _STATE["running"]:
                self._plain(409, "benchmark already running\n")
                return
            _STATE["running"] = True
        _STATE["stop"].clear()
        _STATE["results"] = []
        _STATE["steps_emitted"] = 0
        threading.Thread(target=_run_benchmark, daemon=True,
                         name="webdemo-benchmark").start()
        self._plain(200, "benchmark started\n")

    def _serve_stop(self) -> None:
        _STATE["stop"].set()
        self._plain(200, "stop signal sent\n")

    def _serve_events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        client_q = queue.Queue(maxsize=_MAX_CLIENT_QUEUE)
        with _CLIENTS_LOCK:
            _CLIENTS.add(client_q)
        try:
            _send_event(self.wfile, "ready", {
                "type": "ready",
                "running": bool(_STATE["running"]),
                "total_challenges": _STATE["total_challenges"],
                "completed": len(_STATE["results"]),
                "ts": time.time(),
            })
            self._stream_queue(client_q)
        finally:
            with _CLIENTS_LOCK:
                _CLIENTS.discard(client_q)

    def _stream_queue(self, client_q) -> None:
        """Drain this client's private queue until it disconnects."""
        try:
            while True:
                try:
                    payload = client_q.get(timeout=1.0)
                except queue.Empty:
                    try:
                        self.wfile.write(b": keep-alive\n\n")
                        self.wfile.flush()
                    except OSError:
                        return
                    continue
                evt_type = payload.get("type", "message")
                _send_event(self.wfile, evt_type, payload)
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            return
        finally:
            self.close_connection = True

    def log_message(self, fmt: str, *args) -> None:  # noqa: N802
        sys.stderr.write("[webdemo] " + (fmt % args) + "\n")


# ---------------------------------------------------------------------------
# CLI entry point.
# ---------------------------------------------------------------------------
def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="AutoVulnAgent 实时演示: 零依赖 SSE 控制台 (stdlib only)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="绑定地址 (默认 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080,
                        help="监听端口 (默认 8080)")
    args = parser.parse_args(argv)

    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        print(f"[webdemo] 无法绑定 {args.host}:{args.port}: {exc}",
              file=sys.stderr, flush=True)
        return 1

    print(f"[webdemo] AutoVulnAgent 实时演示 → http://{args.host}:{args.port}/"
          "  (Ctrl+C 停止)", flush=True)
    if not os.path.exists(_INDEX_PATH):
        print("[webdemo] 警告: webdemo/index.html 缺失, '/' 将返回 500",
              file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[webdemo] 已停止", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
