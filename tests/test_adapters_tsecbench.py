"""Contract tests for adapters/tsecbench.py against the official TSecBench
Challenges API (see docs/CHALLENGES_API.md):

    GET  /openapi/v1/challenges?token=        list + progress
    POST /openapi/v1/challenges/start         provision container
    POST /openapi/v1/challenges/submit        judge a flag
    POST /openapi/v1/challenges/close         release container

Every request authenticates with the ``BENCHMARK_TOKEN`` header. A local
ThreadingHTTPServer stands in for both the platform (``/openapi/v1/*``) and the
challenge container (everything else), recording every request so tests can
assert wire-level behaviour and the per-challenge start/close lifecycle.
"""
import json
import os
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.agent import solve_challenge
from core.types import Action, Budget, Challenge
from adapters.tsecbench import TsecBenchAdapter
from llm.base import LLMUsage
from llm.local_policy import LocalPolicyLLM

API_LIST = [
    {
        "unique_code": "web_sql_injection_01",
        "description": "通过 SQL 注入获取管理员凭证并读取 flag",
        "difficulty": "easy",
        "level": 1,
        "total_score": 100,
        "flag_count": 2,
        "correct_flag_count": 0,
        "is_completed": False,
        "container_status": "stopped",
        "container_addr": [],
    },
    {
        "unique_code": "crypto_rsa_02",
        "description": "RSA 参数不当导致私钥可恢复",
        "difficulty": "hard",
        "level": 3,
        "total_score": 200,
        "flag_count": 1,
        "correct_flag_count": 0,
        "is_completed": False,
        "container_status": "available",
        "container_addr": ["10.0.1.5:8080"],
    },
]

CONTAINER_FLAG = "flag{tsecbench_contract_2026}"
TOKEN = "11111111-2222-3333-4444-555555555555"


class _TsecBenchHandler(BaseHTTPRequestHandler):
    """Fake platform + fake challenge container in one server.

    Class-level state (a new handler instance serves each request):
    * ``requests``        — every request as (method, path, body, headers)
    * ``api_list``        — the challenge list returned by GET /challenges
    * ``container_addr``  — the addr returned by POST /start
    * ``flag_totals``     — per unique_code total flag count (default 1)
    * ``accepted_count``  — per unique_code correctly-submitted flag count
    * ``submit_correct``  — whether the next submit is judged correct
    * ``submit_error``    — optional (status, {"code": ...}) forced submit reply
    """

    requests = []
    api_list = API_LIST
    container_addr = "127.0.0.1:9"
    flag_totals = {}
    accepted_count = {}
    submit_correct = True
    submit_error = None

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {"__raw__": raw.decode("utf-8", "replace")}

    def _reply(self, status, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _record(self, body):
        type(self).requests.append((self.command, self.path, body, dict(self.headers)))

    def _unique_code(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        values = query.get("unique_code", [])
        return values[0] if values else ""

    def do_GET(self):
        body = self._read_body()
        self._record(body)
        if urlparse(self.path).path == "/openapi/v1/challenges":
            self._reply(200, type(self).api_list)
        else:
            self._reply(200, {
                "title": "Internal Portal",
                "body": f"Welcome. Admin console session: {CONTAINER_FLAG}",
            })

    def do_POST(self):
        body = self._read_body()
        self._record(body)
        path = urlparse(self.path).path
        if path == "/openapi/v1/challenges/start":
            self._reply(200, {"unique_code": self._unique_code(),
                              "container_addr": [type(self).container_addr]})
        elif path == "/openapi/v1/challenges/submit":
            if type(self).submit_error is not None:
                status, payload = type(self).submit_error
                self._reply(status, payload)
                return
            body = body if isinstance(body, dict) else {}
            flag = body.get("flag")
            code = body.get("unique_code") or ""
            correct = type(self).submit_correct and bool(flag)
            total = int(type(self).flag_totals.get(code, 1))
            if correct:
                type(self).accepted_count[code] = \
                    type(self).accepted_count.get(code, 0) + 1
            cc = type(self).accepted_count.get(code, 0)
            awarded = 100 * cc
            self._reply(200, {
                "correct": correct,
                "awarded": awarded,
                "cumulative_score": awarded,
                "correct_flag_count": cc,
                "total_flag_count": total,
                "matched_flag_index": (cc - 1) if correct else None,
            })
        elif path == "/openapi/v1/challenges/close":
            self._reply(200, {"unique_code": self._unique_code(), "closed": True})
        else:
            self._reply(404, {"code": "challenge_not_found",
                              "message": "no such endpoint"})

    def log_message(self, *args):
        pass


class _ServerTestCase(unittest.TestCase):
    server = None
    base = ""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _TsecBenchHandler)
        port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{port}"
        _TsecBenchHandler.container_addr = f"127.0.0.1:{port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _TsecBenchHandler.requests = []
        _TsecBenchHandler.api_list = API_LIST
        _TsecBenchHandler.flag_totals = {}
        _TsecBenchHandler.accepted_count = {}
        _TsecBenchHandler.submit_correct = True
        _TsecBenchHandler.submit_error = None


def _challenge(**overrides):
    fields = dict(
        id="web_sql_injection_01", name="web_sql_injection_01", category="web-sqli",
        description="d", target="", points=100,
    )
    fields.update(overrides)
    return Challenge(**fields)


def _budget():
    return Budget(max_steps=10, max_elapsed=30.0, max_tokens=100000)


class TsecBenchListTest(_ServerTestCase):
    def test_list_fetches_and_maps_api_entries(self):
        adapter = TsecBenchAdapter(challenges=None, base_url=self.base, token=TOKEN)
        chs = adapter.list_challenges()
        self.assertEqual([c.id for c in chs], ["web_sql_injection_01", "crypto_rsa_02"])
        self.assertEqual(chs[0].points, 100)
        self.assertEqual(chs[1].points, 200)
        self.assertEqual(chs[0].category, "web-sqli")
        self.assertEqual(chs[1].category, "crypto-weak")
        self.assertEqual(chs[0].target, "")  # targets come from start, not list
        self.assertEqual(chs[0].extra.get("container_status"), "stopped")
        self.assertEqual(chs[1].extra.get("container_addr"), ["10.0.1.5:8080"])

    def test_list_sends_benchmark_token_header(self):
        TsecBenchAdapter(challenges=None, base_url=self.base, token=TOKEN)
        method, path, _, headers = _TsecBenchHandler.requests[-1]
        self.assertEqual((method, path), ("GET", "/openapi/v1/challenges"))
        self.assertEqual(headers.get("BENCHMARK_TOKEN"), TOKEN)

    def test_list_server_error_degrades_to_empty(self):
        adapter = TsecBenchAdapter(challenges=None, base_url="http://127.0.0.1:9",
                                   token=TOKEN)
        self.assertEqual(adapter.list_challenges(), [])

    def test_no_base_url_list_disabled(self):
        adapter = TsecBenchAdapter(challenges=None, base_url="", token="")
        self.assertEqual(adapter.list_challenges(), [])

    def test_live_list_preferred_over_seed_manifest(self):
        # A seed manifest (placeholder ids like "ts4-01") must never shadow the
        # authoritative live list when the API is reachable.
        seed = [_challenge(id="seed_only", name="seed_only")]
        adapter = TsecBenchAdapter(challenges=seed, base_url=self.base, token=TOKEN)
        chs = adapter.list_challenges()
        self.assertEqual([c.id for c in chs],
                         ["web_sql_injection_01", "crypto_rsa_02"])

    def test_seed_fallback_when_live_unreachable(self):
        seed = [_challenge(id="seed_only", name="seed_only")]
        adapter = TsecBenchAdapter(challenges=seed,
                                   base_url="http://127.0.0.1:9", token=TOKEN)
        chs = adapter.list_challenges()
        self.assertEqual([c.id for c in chs], ["seed_only"])

    def test_list_skips_already_completed_challenges(self):
        completed = dict(API_LIST[0], unique_code="done_01", is_completed=True)
        _TsecBenchHandler.api_list = [completed, API_LIST[1]]
        adapter = TsecBenchAdapter(challenges=None, base_url=self.base, token=TOKEN)
        chs = adapter.list_challenges()
        self.assertEqual([c.id for c in chs], ["crypto_rsa_02"])

    def test_list_normalises_flag_counts(self):
        adapter = TsecBenchAdapter(challenges=None, base_url=self.base, token=TOKEN)
        chs = adapter.list_challenges()
        self.assertEqual(chs[0].extra.get("total_flag_count"), 2)  # flag_count
        self.assertEqual(chs[0].extra.get("correct_flag_count"), 0)


class TsecBenchStartTest(_ServerTestCase):
    def test_start_posts_unique_code_and_stamps_target(self):
        ch = _challenge()
        adapter = TsecBenchAdapter(challenges=[ch], base_url=self.base, token=TOKEN)
        out = adapter.start(ch)
        self.assertEqual(out.target, f"http://{_TsecBenchHandler.container_addr}")
        method, path, body, headers = _TsecBenchHandler.requests[-1]
        self.assertEqual(method, "POST")
        self.assertTrue(path.startswith("/openapi/v1/challenges/start"))
        self.assertIn("unique_code=web_sql_injection_01", path)
        self.assertEqual(headers.get("BENCHMARK_TOKEN"), TOKEN)

    def test_start_reuses_already_available_addr_without_api_call(self):
        ch = _challenge(extra={"container_status": "available",
                               "container_addr": ["10.0.1.5:8080"]})
        adapter = TsecBenchAdapter(challenges=[ch], base_url=self.base, token=TOKEN)
        out = adapter.start(ch)
        self.assertEqual(out.target, "http://10.0.1.5:8080")
        self.assertEqual(_TsecBenchHandler.requests, [])  # no API call at all

    def test_start_no_base_url_returns_unchanged(self):
        ch = _challenge()
        adapter = TsecBenchAdapter(challenges=[ch], base_url="", token="")
        self.assertIs(adapter.start(ch), ch)
        self.assertEqual(ch.target, "")

    def test_start_failure_leaves_target_empty(self):
        ch = _challenge()
        adapter = TsecBenchAdapter(challenges=[ch],
                                   base_url="http://127.0.0.1:9", token=TOKEN)
        out = adapter.start(ch)
        self.assertEqual(out.target, "")


class TsecBenchSubmitTest(_ServerTestCase):
    def _adapter(self):
        return TsecBenchAdapter(challenges=[_challenge()], base_url=self.base,
                                token=TOKEN)

    def test_submit_posts_unique_code_and_flag_true(self):
        self.assertTrue(self._adapter().submit(_challenge(), "flag{x}"))
        method, path, body, headers = _TsecBenchHandler.requests[-1]
        self.assertEqual((method, path), ("POST", "/openapi/v1/challenges/submit"))
        self.assertEqual(body, {"unique_code": "web_sql_injection_01", "flag": "flag{x}"})
        self.assertEqual(headers.get("BENCHMARK_TOKEN"), TOKEN)

    def test_submit_wrong_flag_false(self):
        _TsecBenchHandler.submit_correct = False
        self.assertFalse(self._adapter().submit(_challenge(), "flag{wrong}"))

    def test_submit_duplicate_409_true(self):
        _TsecBenchHandler.submit_error = (409, {"code": "duplicate",
                                                "message": "already scored"})
        self.assertTrue(self._adapter().submit(_challenge(), "flag{x}"))

    def test_submit_invalid_state_409_false(self):
        _TsecBenchHandler.submit_error = (409, {"code": "invalid_state",
                                                "message": "task ended"})
        self.assertFalse(self._adapter().submit(_challenge(), "flag{x}"))

    def test_submit_resource_unavailable_503_false(self):
        _TsecBenchHandler.submit_error = (503, {"code": "resource_unavailable",
                                                "message": "no instances"})
        self.assertFalse(self._adapter().submit(_challenge(), "flag{x}"))

    def test_submit_missing_correct_field_false(self):
        _TsecBenchHandler.submit_error = (200, {"awarded": 0})
        self.assertFalse(self._adapter().submit(_challenge(), "flag{x}"))

    def test_flag_progress_reported_after_submit(self):
        _TsecBenchHandler.flag_totals["web_sql_injection_01"] = 2
        ch = _challenge()
        adapter = self._adapter()
        self.assertTrue(adapter.submit(ch, "flag{first}"))
        self.assertEqual(adapter.flag_progress(ch),
                         {"correct": 1, "total": 2, "awarded": 100})
        # list-vs-submit API naming is normalised into extra
        self.assertEqual(ch.extra.get("total_flag_count"), 2)
        self.assertEqual(ch.extra.get("correct_flag_count"), 1)

    def test_submit_empty_flag_or_no_base_url_false(self):
        adapter = self._adapter()
        self.assertFalse(adapter.submit(_challenge(), ""))
        self.assertFalse(adapter.submit(_challenge(), "   "))
        adapter_no_base = TsecBenchAdapter(challenges=[_challenge()], base_url="",
                                           token="")
        self.assertFalse(adapter_no_base.submit(_challenge(), "flag{x}"))


class TsecBenchCloseTest(_ServerTestCase):
    def test_close_posts_once_per_started_challenge(self):
        ch = _challenge()
        adapter = TsecBenchAdapter(challenges=[ch], base_url=self.base, token=TOKEN)
        adapter.start(ch)
        adapter.close_challenge(ch)
        adapter.close_challenge(ch)  # second call: already released, no-op
        close_requests = [r for r in _TsecBenchHandler.requests
                          if urlparse(r[1]).path == "/openapi/v1/challenges/close"]
        self.assertEqual(len(close_requests), 1)
        method, path, body, headers = close_requests[0]
        self.assertEqual(method, "POST")
        self.assertIn("unique_code=web_sql_injection_01", path)
        self.assertEqual(headers.get("BENCHMARK_TOKEN"), TOKEN)

    def test_close_untouched_challenge_is_noop(self):
        ch = _challenge()
        adapter = TsecBenchAdapter(challenges=[ch], base_url=self.base, token=TOKEN)
        adapter.close_challenge(ch)  # never started
        self.assertEqual(_TsecBenchHandler.requests, [])

    def test_close_safety_net_releases_all_started(self):
        ch1, ch2 = _challenge(id="a-01"), _challenge(id="b-02")
        adapter = TsecBenchAdapter(challenges=[ch1, ch2], base_url=self.base,
                                   token=TOKEN)
        adapter.start(ch1)
        adapter.start(ch2)
        adapter.close()
        paths = [urlparse(r[1]).path for r in _TsecBenchHandler.requests]
        self.assertEqual(paths.count("/openapi/v1/challenges/close"), 2)


class TsecBenchLifecycleTest(_ServerTestCase):
    def test_full_lifecycle_through_solve_challenge(self):
        ch = _challenge(category="recon-info", points=250,
                        extra={"container_status": "stopped", "container_addr": []})
        adapter = TsecBenchAdapter(challenges=[ch], base_url=self.base, token=TOKEN)
        llm = LocalPolicyLLM()
        result = solve_challenge(ch, adapter, llm, _budget())

        self.assertTrue(result.passed)
        self.assertEqual(result.submitted_flag, CONTAINER_FLAG)

        paths = [urlparse(r[1]).path for r in _TsecBenchHandler.requests]
        # ordering: start -> container probe(s) -> submit -> close
        self.assertIn("/openapi/v1/challenges/start", paths)
        self.assertEqual(paths[-1], "/openapi/v1/challenges/close")
        submit_idx = next(i for i, p in enumerate(paths)
                          if p == "/openapi/v1/challenges/submit")
        self.assertLess(submit_idx, len(paths) - 1)
        _, _, body, _ = _TsecBenchHandler.requests[submit_idx]
        self.assertEqual(body["flag"], CONTAINER_FLAG)


class _TwoFlagLLM:
    """Submits one flag per call until the challenge reports all flags accepted."""

    name = "two-flag"

    def __init__(self):
        self.usage = LLMUsage()

    def decide(self, challenge, history, budget):
        correct = challenge.extra.get("correct_flag_count", 0)
        total = challenge.extra.get("total_flag_count", 1)
        if correct < total:
            return Action(tool="submit", flag=f"flag{{n{correct}}}",
                          is_submit=True,
                          thought=f"submitting recovered flag #{correct + 1}")
        return Action(tool="give_up", is_give_up=True,
                      thought="all flags submitted")


class TsecBenchMultiFlagTest(_ServerTestCase):
    """A multi-flag challenge keeps the ReAct loop going after each accepted
    flag and pays out per accepted flag."""

    def test_loop_continues_until_all_flags_accepted(self):
        _TsecBenchHandler.flag_totals["web_sql_injection_01"] = 2
        ch = _challenge(extra={"total_flag_count": 2, "correct_flag_count": 0,
                               "container_status": "available",
                               "container_addr": ["10.0.1.5:8080"]})
        adapter = TsecBenchAdapter(challenges=[ch], base_url=self.base, token=TOKEN)
        result = solve_challenge(ch, adapter, _TwoFlagLLM(), _budget())

        self.assertTrue(result.passed)
        self.assertEqual(result.submitted_flag, "flag{n1}")  # last accepted flag
        self.assertEqual(result.points_awarded, 200)         # 100 per flag
        submit_requests = [r for r in _TsecBenchHandler.requests
                           if urlparse(r[1]).path == "/openapi/v1/challenges/submit"]
        self.assertEqual(len(submit_requests), 2)
        # the agent saw the "keep hunting" cue between the two submissions
        self.assertTrue(any("more flag(s) remain" in s.observation
                            for s in result.trace))

    def test_single_flag_challenge_stops_after_one_submit(self):
        ch = _challenge(extra={"total_flag_count": 1, "correct_flag_count": 0,
                               "container_status": "available",
                               "container_addr": ["10.0.1.5:8080"]})
        adapter = TsecBenchAdapter(challenges=[ch], base_url=self.base, token=TOKEN)
        result = solve_challenge(ch, adapter, _TwoFlagLLM(), _budget())

        self.assertTrue(result.passed)
        self.assertEqual(result.points_awarded, 100)
        submit_requests = [r for r in _TsecBenchHandler.requests
                           if urlparse(r[1]).path == "/openapi/v1/challenges/submit"]
        self.assertEqual(len(submit_requests), 1)


if __name__ == "__main__":
    unittest.main()
