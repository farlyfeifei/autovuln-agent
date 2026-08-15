"""End-to-end: a real-model provider (OpenAILikeProvider against a local mock
OpenAI service that acts like a reasoning LLM) drives the real toolchain
against a real local target and recovers + submits the flag. No mocks on the
target side; the only fake is the LLM HTTP service.

This closes the loop for the "live" path:  challenge -> LLM decide -> real tool
-> observation -> LLM sees flag -> submit -> passed.
"""
import sys
import os
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, ".."))  # project root for core/llm/tools
sys.path.insert(0, _HERE)                      # tests dir for test_live_target

from core.types import Challenge, Budget
from core.agent import solve_challenge
from llm.providers import OpenAILikeProvider
from tools.registry import build_real_registry
from test_live_target import _TargetHandler, FLAG


class MockReasoningLLM(BaseHTTPRequestHandler):
    """A scripted stand-in for a real chat model.

    Replays a fixed action plan until the transcript contains a flag, then
    emits a submit action — mirroring what an actual LLM would do.
    """

    plan = []           # class-level scripted actions (popped per call)
    calls = 0
    received_messages = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        body = json.loads(raw)
        type(self).received_messages.append(body["messages"])
        type(self).calls += 1
        user_content = body["messages"][-1]["content"]
        if FLAG in user_content:
            content = {"thought": "flag in transcript",
                       "action": "submit", "flag": FLAG}
        elif type(self).plan:
            content = type(self).plan[0]
            type(self).plan = type(self).plan[1:]
        else:
            content = {"thought": "plan spent", "action": "give_up", "params": {}}
        payload = {"choices": [{"message": {"content": json.dumps(content)}}],
                   "usage": {"prompt_tokens": 10, "completion_tokens": 4}}
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class LiveAdapter:
    name = "live-e2e"

    def __init__(self):
        self.registry = build_real_registry()

    def list_challenges(self):
        return []

    def tool_registry(self):
        return self.registry

    def submit(self, challenge, flag):
        return flag == challenge.ground_truth_flag

    def start(self, challenge):
        return challenge

    def close_challenge(self, challenge):
        pass

    def close(self):
        pass


class E2ELlmTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import ThreadingHTTPServer as THT
        cls.target_srv = THT(("127.0.0.1", 0), _TargetHandler)
        cls.target_port = cls.target_srv.server_address[1]
        threading.Thread(target=cls.target_srv.serve_forever, daemon=True).start()

        cls.llm_srv = THT(("127.0.0.1", 0), MockReasoningLLM)
        cls.llm_port = cls.llm_srv.server_address[1]
        threading.Thread(target=cls.llm_srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.target_srv.shutdown()
        cls.target_srv.server_close()
        cls.llm_srv.shutdown()
        cls.llm_srv.server_close()

    def setUp(self):
        MockReasoningLLM.plan = [
            {"thought": "map login", "action": "http_probe",
             "params": {"path": "/login"}},
            {"thought": "union dump", "action": "sqli",
             "params": {"param": "user", "technique": "union", "path": "/login"}},
        ]
        MockReasoningLLM.calls = 0
        MockReasoningLLM.received_messages = []

    def test_llm_driven_live_solve(self):
        challenge = Challenge(
            id="e2e-1", name="", category="web-sqli", description="",
            target=f"http://127.0.0.1:{self.target_port}", points=10,
            ground_truth_flag=FLAG, extra={},
        )
        provider = OpenAILikeProvider(
            provider="e2e", model="e2e-model",
            base_url=f"http://127.0.0.1:{self.llm_port}/v1",
            api_key="sk-e2e", max_output_tokens=64,
        )
        result = solve_challenge(challenge, LiveAdapter(), provider,
                                 Budget(max_steps=6, max_elapsed=30.0,
                                        max_tokens=50000))
        self.assertTrue(result.passed, f"trace:\n{result.trace}")
        self.assertEqual(result.submitted_flag, FLAG)
        self.assertEqual(result.points_awarded, 10)
        # the real toolchain was exercised: the LLM's first decide ran a real
        # http_probe against the live target, whose observation leaked the flag
        actions = [s.action for s in result.trace]
        self.assertTrue(any(a.startswith("http_probe") for a in actions))
        # flag leaked on the very first probe -> the model submits immediately
        # instead of burning steps on more tools (correct, non-wasteful behavior)
        self.assertTrue(any(a.startswith("submit") for a in actions))

    def test_tokens_attributed_per_challenge(self):
        challenge = Challenge(
            id="e2e-2", name="", category="web-sqli", description="",
            target=f"http://127.0.0.1:{self.target_port}", points=10,
            ground_truth_flag=FLAG, extra={},
        )
        provider = OpenAILikeProvider(
            provider="e2e", model="e2e-model",
            base_url=f"http://127.0.0.1:{self.llm_port}/v1",
            api_key="sk-e2e", max_output_tokens=64,
        )
        result = solve_challenge(challenge, LiveAdapter(), provider,
                                 Budget(max_steps=6, max_elapsed=30.0,
                                        max_tokens=50000))
        self.assertTrue(result.passed)
        self.assertGreaterEqual(result.tokens["prompt"], 0)
        self.assertGreaterEqual(result.tokens["completion"], 0)


if __name__ == "__main__":
    unittest.main()
