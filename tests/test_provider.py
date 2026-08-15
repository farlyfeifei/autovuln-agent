"""Provider chain integration tests: OpenAILikeProvider against a local mock
OpenAI server. Validates the real-model path (URL, payload, JSON parsing with
markdown fences, usage accounting, 429 retry, correction call, permanent-error
degrade) with zero network egress and no real API key.
"""
import sys
import os
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.types import Challenge, Budget
from llm.providers import OpenAILikeProvider

FAST_JSON = {
    "thought": "probe the login page",
    "action": "http_probe",
    "params": {"path": "/login"},
}
SUBMIT_JSON = {
    "thought": "found it",
    "action": "submit",
    "flag": "flag{provider_test_2026}",
}


def _ok(content, usage=None):
    body = {"choices": [{"message": {"content": content}}]}
    if usage is not None:
        body["usage"] = usage
    return body


class MockOpenAI(BaseHTTPRequestHandler):
    """Stateful fake: returns scripted responses per request number."""

    responses = []            # list of (status, dict_body)
    received = []             # list of parsed request bodies
    requests = 0
    headers_received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw)
        except Exception:
            body = {"raw": raw.decode("utf-8", "replace")}
        type(self).received.append(body)
        type(self).headers_received.append(dict(self.headers))
        type(self).requests += 1

        if not type(self).responses:
            status, payload = 200, _ok(json.dumps(FAST_JSON))
        else:
            status, payload = type(self).responses[0]
            if len(type(self).responses) > 1:
                type(self).responses = type(self).responses[1:]
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class ProviderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MockOpenAI)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}/v1"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        MockOpenAI.responses = []
        MockOpenAI.received = []
        MockOpenAI.requests = 0
        MockOpenAI.headers_received = []

    def _provider(self, **kw):
        kw.setdefault("provider", "test")
        kw.setdefault("model", "test-model")
        kw.setdefault("base_url", self.base)
        kw.setdefault("api_key", "sk-test")
        kw.setdefault("max_output_tokens", 64)
        return OpenAILikeProvider(**kw)

    def _challenge(self, category="web-sqli"):
        return Challenge(
            id="p1", name="n", category=category, description="d",
            target="http://mock.local", points=10,
            ground_truth_flag="flag{x}", extra={},
        )

    def _budget(self):
        return Budget(max_steps=5, max_elapsed=30.0, max_tokens=50000)

    def test_normal_http_probe_action(self):
        prov = self._provider()
        action = prov.decide(self._challenge(), [], self._budget())
        self.assertEqual(action.tool, "http_probe")
        self.assertEqual(action.params, {"path": "/login"})

    def test_request_payload_structure(self):
        self._provider().decide(self._challenge(), [], self._budget())
        req = MockOpenAI.received[0]
        self.assertEqual(req["model"], "test-model")
        self.assertEqual(req["temperature"], 0.2)
        self.assertEqual(req["max_tokens"], 64)
        self.assertEqual(req["messages"][0]["role"], "system")
        self.assertIn("Challenge", req["messages"][1]["content"])
        self.assertIn("web-sqli", req["messages"][1]["content"])
        self.assertIn("UNION", req["messages"][1]["content"])  # category guidance
        self.assertIn("http_probe", req["messages"][1]["content"])  # tool manifest
        self.assertIn("http_probe", req["messages"][1]["content"])  # manifest
        # authorization header attached
        self.assertIn("Authorization", MockOpenAI.headers_received[0])
        self.assertEqual(MockOpenAI.headers_received[0]["Authorization"],
                         "Bearer sk-test")

    def test_markdown_fenced_json(self):
        MockOpenAI.responses = [
            (200, _ok("```json\n" + json.dumps(FAST_JSON) + "\n```")),
        ]
        action = self._provider().decide(self._challenge(), [], self._budget())
        self.assertEqual(action.tool, "http_probe")

    def test_submit_action_maps_flag(self):
        MockOpenAI.responses = [(200, _ok(json.dumps(SUBMIT_JSON)))]
        action = self._provider().decide(self._challenge(), [], self._budget())
        self.assertTrue(action.is_submit)
        self.assertEqual(action.flag, "flag{provider_test_2026}")

    def test_retry_on_429(self):
        # two rate-limits, then success — provider must retry transparently
        MockOpenAI.responses = [
            (429, {"error": {"message": "rate limited"}}),
            (429, {"error": {"message": "rate limited"}}),
            (200, _ok(json.dumps(FAST_JSON))),
        ]
        prov = self._provider()
        action = prov.decide(self._challenge(), [], self._budget())
        self.assertEqual(action.tool, "http_probe")
        self.assertEqual(MockOpenAI.requests, 3)
        self.assertEqual(prov.usage.calls, 1)  # only the successful call counts

    def test_corrupt_then_correction(self):
        MockOpenAI.responses = [
            (200, _ok("sorry, here is some prose with no json at all")),
            (200, _ok(json.dumps(FAST_JSON))),  # reply to the correction prompt
        ]
        prov = self._provider()
        action = prov.decide(self._challenge(), [], self._budget())
        self.assertEqual(action.tool, "http_probe")
        self.assertEqual(MockOpenAI.requests, 2)
        # the correction prompt was appended to the message list
        joined = " ".join(m["content"] for m in MockOpenAI.received[1]["messages"])
        self.assertIn("previous response", joined)

    def test_permanent_error_degrades_to_give_up(self):
        MockOpenAI.responses = [(400, {"error": {"message": "bad key"}})]
        prov = self._provider()
        action = prov.decide(self._challenge(), [], self._budget())
        self.assertTrue(action.is_give_up)
        self.assertIn("LLM error", action.thought)
        self.assertEqual(MockOpenAI.requests, 1)  # no retry on permanent error

    def test_usage_tracking(self):
        MockOpenAI.responses = [(
            200, _ok(json.dumps(FAST_JSON), {"prompt_tokens": 120, "completion_tokens": 18}),
        )]
        prov = self._provider()
        prov.decide(self._challenge(), [], self._budget())
        self.assertEqual(prov.usage.prompt_tokens, 120)
        self.assertEqual(prov.usage.completion_tokens, 18)
        self.assertEqual(prov.usage.total_tokens, 138)
        self.assertIn("138 tokens", prov.usage_summary())

    def test_no_api_key_still_connects(self):
        prov = self._provider(api_key="")
        action = prov.decide(self._challenge(), [], self._budget())
        self.assertEqual(action.tool, "http_probe")
        self.assertNotIn("Authorization", MockOpenAI.headers_received[0])

    def test_invalid_action_becomes_noop(self):
        MockOpenAI.responses = [(
            200, _ok(json.dumps({"thought": "x", "action": "bad action!", "params": {}})),
        )]
        action = self._provider().decide(self._challenge(), [], self._budget())
        self.assertEqual(action.tool, "noop")


if __name__ == "__main__":
    unittest.main()
