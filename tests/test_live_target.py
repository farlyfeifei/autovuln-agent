"""Live-target integration smoke tests: ALL real tools + the ReAct loop against
a real local HTTP target (stdlib http.server). No mocks anywhere in this path.

Proves the "live" capability end-to-end:
  * http_probe reads a real response body
  * sqli performs real injected requests and detects a UNION injection
  * xss / lfi / ssrf / idor detect their vulnerability class on real responses
  * port_scan / dir_enum / fingerprint / param_probe / fuzz work against live
    HTTP
  * the ReAct loop recovers + submits a flag that only appears in the real
    response
"""
import sys
import os
import re
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.types import Challenge, Budget, Step
from core.agent import solve_challenge
from core.context import summarize_history
from llm.local_policy import LocalPolicyLLM
from tools.registry import build_real_registry
from tools.recon import (HttpProbeTool, PortScanTool, DirEnumTool,
                         FingerprintTool, _check_port)
from tools.probe import ParamProbeTool, FuzzTool
from tools.exploit import (SqliTool, XssTool, LfiTool, SsrfTool, IdorTool)

FLAG = "flag{real_http_sqli_2026}"
MARKER = "ZzVuL1nUq1"
BASE = "http://127.0.0.1"
_ORDER_BY_RE = re.compile(r"ORDER BY\s+(\d+)")


class _TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            self._plain(200, "<html><head><meta name='debug-flag' content='%s'>"
                        "</head><body>Mock Target App</body></html>" % FLAG)
        elif path == "/login":
            self._serve_login(query)
        elif path == "/search":
            self._plain(200, "<p>results for: %s</p>" % (query.get("q") or [""])[0])
        elif path == "/view":
            self._serve_view(query)
        elif path == "/fetch":
            self._serve_fetch(query)
        elif path.startswith("/api/user/"):
            self._serve_user(path)
        elif path == "/admin":
            self._plain(200, "<h1>admin panel</h1><p>internal</p>")
        else:
            self._plain(404, "not found")

    def _serve_login(self, query):
        user = (query.get("user") or [""])[0]
        if "ORDER BY" in user:
            m = _ORDER_BY_RE.search(user)
            n = int(m.group(1)) if m else 0
            if n >= 3:
                self._plain(500, "SQL error: near 'ORDER BY'")
                return
            self._plain(200, "Hello user #%d" % n)
            return
        if "UNION SELECT" in user:
            if MARKER in user:
                self._plain(200, "<html><body><table><tr><td>%s</td><td>2</td></tr>"
                            "</table><meta name='debug-flag' content='%s'>"
                            "</body></html>" % (MARKER, FLAG))
                return
            self._plain(500, "SQL error: column mismatch")
            return
        self._plain(200, "<html><head><meta name='debug-flag' content='%s'>"
                    "</head><body>Login form: <input name='user'></body></html>" % FLAG)

    def _serve_view(self, query):
        file_param = (query.get("file") or [""])[0]
        if "etc/passwd" in file_param or "etc%2fpasswd" in file_param.lower():
            body = ("root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            self._plain(200, body)
            return
        self._plain(200, "<p>rendered: index.html</p>")

    def _serve_fetch(self, query):
        u = (query.get("u") or [""])[0]
        if "169.254.169.254" in u or "metadata" in u.lower():
            body = ("ami-id: ami-0c55b159cbfafe1f0\n"
                    "instance-id: i-0123456789abcdef0\n"
                    "local-ipv4: 10.0.0.42\n")
            self._plain(200, body)
            return
        self._plain(200, "fetched ok")

    def _serve_user(self, path):
        cid = re.sub(r"[^0-9]", "", path.split("/api/user/")[-1]) or "0"
        # id 1 is the baseline caller; any other id returns a different object
        self._plain(200, '{"id": %s, "name": "user-%s", "secret": "s%s"}' % (cid, cid, cid))

    def _plain(self, status, body, ctype="text/html; charset=utf-8"):
        self.send_response(int(status))
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body.encode("utf-8"))))
        self.send_header("Server", "AutoVuln-Test/1.0")
        self.send_header("X-Powered-By", "PHP/7.4")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, *args):
        pass


class LiveTargetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.target = f"{BASE}:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _challenge(self, category="web-sqli"):
        return Challenge(
            id="live-01", name="", category=category, description="",
            target=self.target, points=10,
            ground_truth_flag=FLAG,
            extra={},
        )

    def _budget(self):
        return Budget(max_steps=8, max_elapsed=30.0, max_tokens=50000)

    # ---- recon tools ----------------------------------------------------
    def test_http_probe_reads_real_body(self):
        res = HttpProbeTool().run(self._challenge(), {"path": "/"})
        self.assertTrue(res.ok)
        self.assertIn("200", res.observation)
        self.assertIn("AutoVuln-Test", res.observation)

    def test_port_scan_finds_open_port(self):
        res = PortScanTool().run(self._challenge(), {"ports": [self.port]})
        self.assertTrue(res.ok)
        self.assertIn("OPEN:", res.observation)
        self.assertIn(str(self.port), res.observation)

    def test_dir_enum_finds_admin(self):
        res = DirEnumTool().run(self._challenge(), {"wordlist": ["admin"]})
        self.assertTrue(res.ok)
        self.assertIn("/admin", res.observation)

    def test_fingerprint_detects_tech(self):
        res = FingerprintTool().run(self._challenge(), {"path": "/"})
        self.assertTrue(res.ok)
        self.assertIn("php", res.observation.lower())

    def test_param_probe_finds_reflection(self):
        res = ParamProbeTool().run(self._challenge(), {"path": "/search"})
        self.assertTrue(res.ok)
        self.assertIn("REFLECT", res.observation)

    def test_fuzz_finds_200_and_marker(self):
        res = FuzzTool().run(self._challenge(),
                             {"path": "/", "payloads": ["?q=abc"]})
        self.assertTrue(res.ok)
        self.assertIn("200", res.observation)
        self.assertIn("MARK:", res.observation)

    # ---- exploit tools ---------------------------------------------------
    def test_sqli_union_detection_on_real_target(self):
        res = SqliTool().run(self._challenge(),
                             {"param": "user", "technique": "union",
                              "path": "/login"})
        self.assertTrue(res.ok)
        self.assertIn("UNION-BASED", res.observation)
        self.assertIn("column count=2", res.observation)

    def test_xss_unescaped_reflection(self):
        res = XssTool().run(self._challenge(), {"param": "q", "path": "/search"})
        self.assertTrue(res.ok)
        self.assertIn("UNESCAPED", res.observation)

    def test_lfi_reads_passwd(self):
        res = LfiTool().run(self._challenge(), {"param": "file", "path": "/view"})
        self.assertTrue(res.ok)
        self.assertIn("etc/passwd", res.observation)

    def test_ssrf_metadata_leak(self):
        res = SsrfTool().run(self._challenge(),
                             {"param": "u", "path": "/fetch",
                              "target": "http://169.254.169.254/latest/meta-data/"})
        self.assertTrue(res.ok)
        self.assertIn("SSRF", res.observation)

    def test_idor_detects_differing_objects(self):
        res = IdorTool().run(self._challenge(),
                             {"path": "/api/user/1", "count": 3})
        self.assertTrue(res.ok)
        self.assertIn("DIFFERS", res.observation)

    # ---- full ReAct loop -------------------------------------------------
    def test_react_loop_recovers_flag_from_real_target(self):
        result = solve_challenge(self._challenge(), _LiveAdapter(), LocalPolicyLLM(),
                                 self._budget())
        self.assertTrue(result.passed)
        self.assertEqual(result.submitted_flag, FLAG)


class _LiveAdapter:
    """Minimal adapter: real tools + a pass-through submit that checks ground truth."""

    name = "live-test"

    def __init__(self):
        self.registry = build_real_registry()
        self.challenges = []

    def list_challenges(self):
        return self.challenges

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


class ReviewFixRegressionTest(unittest.TestCase):
    """Regression tests for specific code-review findings (Medium/Low)."""

    # ---- summarize_history tail-slice clamp (Low, core/context.py) --------
    def test_summarize_history_never_exceeds_max_chars(self):
        steps = [
            Step(index=i, thought="t" * 80, action="act",
                 observation="o" * 500, flags=[])
            for i in range(1, 15)
        ]
        for limit in (10, 30, 59, 60, 61, 4000):
            out = summarize_history(steps, max_chars=limit)
            self.assertLessEqual(len(out), limit,
                                 f"max_chars={limit} produced {len(out)} chars")

    def test_summarize_history_tiny_limit_returns_bounded_text(self):
        out = summarize_history([Step(index=1, thought="x", action="a",
                                      observation="y" * 200, flags=[])], max_chars=10)
        self.assertLessEqual(len(out), 10)

    # ---- _check_port IPv6 fall-through (Low, tools/recon.py) --------------
    def test_port_check_tries_next_family_on_gaierror(self):
        class _FakeSock:
            def __init__(self, family):
                self.family = family

            def settimeout(self, _t):
                pass

            def connect_ex(self, _addr):
                if self.family == socket.AF_INET:
                    raise socket.gaierror(-2, "no A record")
                return 0  # AF_INET6 connects fine

            def close(self):
                pass

        orig = socket.socket
        socket.socket = lambda family, socktype: _FakeSock(family)
        try:
            rc, label = _check_port("ipv6-only.example", 80, 0.5)
        finally:
            socket.socket = orig
        self.assertEqual((rc, label), (0, "open"))

    def test_port_check_dns_fail_only_when_all_families_fail(self):
        class _FakeSock:
            def __init__(self, family):
                self.family = family

            def settimeout(self, _t):
                pass

            def connect_ex(self, _addr):
                raise socket.gaierror(-2, "nope")

            def close(self):
                pass

        orig = socket.socket
        socket.socket = lambda family, socktype: _FakeSock(family)
        try:
            rc, label = _check_port("nowhere.example", 80, 0.5)
        finally:
            socket.socket = orig
        self.assertEqual((rc, label), (-1, "dns-fail"))

    # ---- dir_enum work cap (Low, tools/recon.py) --------------------------
    def test_dir_enum_caps_giant_wordlist(self):
        class _CountingDirEnum(DirEnumTool):
            def __init__(self):
                super().__init__()
                self.probed = 0

            def _probe(self, base, path, timeout):
                self.probed += 1
                return path, 404, ""

        tool = _CountingDirEnum()
        res = tool.run(
            Challenge(id="c", name="c", category="web", description="",
                      target="http://127.0.0.1:1/"),
            {"wordlist": ["p%d" % i for i in range(2000)]},
        )
        self.assertLessEqual(tool.probed, tool._MAX_PROBE_PATHS)
        self.assertIn("capped", res.observation)


if __name__ == "__main__":
    unittest.main()
