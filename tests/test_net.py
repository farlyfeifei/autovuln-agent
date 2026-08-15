"""Behavioral contract tests for core.net.

Backend-agnostic: every assertion targets observable behavior (URL
normalization, join semantics, HTTP status/body/headers, params/json/form
encoding, redirect handling, timeout/refused errors) and never the choice of
HTTP library. Requests run against a real stdlib ThreadingHTTPServer on
127.0.0.1 (ephemeral port). One test forces the urllib fallback (net.requests
= None) to lock in identical behavior on that path.
"""
import copy
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core import net

ECHO_MARKER = "zNq71bW8"


def _header(headers, name):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


class _EchoHandler(BaseHTTPRequestHandler):
    """Echo server.

    GET  /echo    -> 200, echoes q=<value of query param 'q'> + marker
    GET  /redirect -> 302, Location: /echo
    GET  /hdr     -> 200, echoes "ua=<User-Agent header>"
    POST /echo    -> 200, echoes the raw request body
    anything else -> 404
    """

    records = []  # class-level; BaseHTTPRequestHandler is per-request

    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        type(self).records.append({
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": raw.decode("utf-8", "replace"),
        })

    def _finish(self, status=200, body="", ctype="text/plain; charset=utf-8",
                extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(int(status))
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, str(v))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._record()
        path = urlparse(self.path).path
        if path == "/echo":
            q = parse_qs(urlparse(self.path).query)
            self._finish(200, "q=%s marker=%s" % (q.get("q", [""])[0], ECHO_MARKER),
                         ctype="text/html; charset=utf-8")
        elif path == "/redirect":
            self._finish(302, "", extra={"Location": "/echo"})
        elif path == "/hdr":
            self._finish(200, "ua=%s" % self.headers.get("User-Agent", ""))
        else:
            self._finish(404, "not found")

    def do_POST(self):
        self._record()
        path = urlparse(self.path).path
        if path == "/echo":
            self._finish(200, self.records[-1]["body"])
        else:
            self._finish(404, "not found")

    def log_message(self, *args):
        pass


class NetContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self._saved_defaults = copy.deepcopy(net._DEFAULTS)
        _EchoHandler.records = []

    def tearDown(self):
        net._DEFAULTS.clear()
        net._DEFAULTS.update(self._saved_defaults)

    # ---------------- normalize_url ----------------
    def test_normalize_url_adds_scheme_when_missing(self):
        self.assertEqual(net.normalize_url("example.com:8080/x"),
                         "http://example.com:8080/x")

    def test_normalize_url_keeps_existing_scheme(self):
        self.assertEqual(net.normalize_url("https://example.com/x"),
                         "https://example.com/x")

    def test_normalize_url_strips_whitespace(self):
        self.assertEqual(net.normalize_url("  example.com/a  "),
                         "http://example.com/a")

    def test_normalize_url_empty_string(self):
        self.assertEqual(net.normalize_url(""), "")
        self.assertEqual(net.normalize_url("   "), "")

    # ---------------- join ----------------
    def test_join_clean_single_slashes(self):
        self.assertEqual(net.join("http://a.com/base", "sub"),
                         "http://a.com/base/sub")
        # a leading slash on the path appends cleanly (no double slash) and
        # does not discard the base path -- tools rely on this (e.g. joining
        # the target base with "/login").
        self.assertEqual(net.join("http://a.com/base/", "/sub"),
                         "http://a.com/base/sub")
        self.assertEqual(net.join("http://a.com/", "/"), "http://a.com/")
        self.assertEqual(net.join("http://a.com", "b/c"), "http://a.com/b/c")

    def test_join_query_string_survives(self):
        self.assertEqual(net.join("http://a.com/x", "y?a=1&b=2"),
                         "http://a.com/x/y?a=1&b=2")

    def test_join_absolute_url_replaces_base(self):
        self.assertEqual(net.join("http://a.com/x", "http://b.com/z"),
                         "http://b.com/z")
        self.assertEqual(net.join("http://a.com/x", "http://b.com/z?a=1"),
                         "http://b.com/z?a=1")

    # ---------------- configure ----------------
    def test_configure_mutates_defaults(self):
        net.configure(timeout=1.5, verify_ssl=True, user_agent="UA-X",
                      proxies={"http": "http://p:1"})
        self.assertEqual(net._DEFAULTS["timeout"], 1.5)
        self.assertIs(net._DEFAULTS["verify_ssl"], True)
        self.assertEqual(net._DEFAULTS["user_agent"], "UA-X")
        self.assertEqual(net._DEFAULTS["proxies"], {"http": "http://p:1"})

    # ---------------- request behavior, live server ----------------
    def test_get_status_body_and_content_type(self):
        res = net.get(self.base + "/echo", timeout=5)
        self.assertEqual(res.status, 200)
        self.assertTrue(res.ok)
        self.assertIn(ECHO_MARKER, res.text)
        ct = _header(res.headers, "Content-Type")
        self.assertIsNotNone(ct)
        self.assertIn("text/html", ct)

    def test_user_agent_header_is_sent(self):
        res = net.get(self.base + "/hdr", timeout=5)
        self.assertTrue(res.ok)
        expected = net._DEFAULTS["user_agent"]
        self.assertEqual(res.text, "ua=" + expected)
        self.assertEqual(_header(_EchoHandler.records[-1]["headers"], "User-Agent"),
                         expected)

    def test_params_urlencoded_and_roundtrip(self):
        res = net.get(self.base + "/echo",
                      params={"q": "hello world", "n": 42}, timeout=5)
        self.assertEqual(res.status, 200)
        self.assertTrue(res.ok)
        self.assertEqual(res.text, "q=hello world marker=%s" % ECHO_MARKER)
        # the wire query string was URL-encoded; parse_qs decodes it back
        q = parse_qs(urlparse(_EchoHandler.records[-1]["path"]).query)
        self.assertEqual(q["q"], ["hello world"])
        self.assertEqual(q["n"], ["42"])

    def test_post_json_roundtrips(self):
        payload = {"name": "ctf", "n": 3, "note": "x y"}
        res = net.post(self.base + "/echo", json=payload, timeout=5)
        self.assertEqual(res.status, 200)
        self.assertTrue(res.ok)
        self.assertEqual(json.loads(res.text), payload)
        self.assertEqual(json.loads(_EchoHandler.records[-1]["body"]), payload)

    def test_post_data_dict_is_form_urlencoded(self):
        res = net.post(self.base + "/echo", data={"a": "x y", "b": 2}, timeout=5)
        self.assertEqual(res.status, 200)
        self.assertTrue(res.ok)
        q = parse_qs(_EchoHandler.records[-1]["body"])
        self.assertEqual(q["a"], ["x y"])
        self.assertEqual(q["b"], ["2"])
        self.assertNotIn('"a"', res.text)  # body is form-encoded, not JSON

    def test_post_data_str_sent_raw(self):
        raw = "raw-payload-42"
        res = net.post(self.base + "/echo", data=raw, timeout=5)
        self.assertEqual(res.status, 200)
        self.assertTrue(res.ok)
        self.assertEqual(_EchoHandler.records[-1]["body"], raw)
        self.assertEqual(res.text, raw)

    def test_redirects_followed_by_default(self):
        res = net.get(self.base + "/redirect", timeout=5)
        self.assertEqual(res.status, 200)
        self.assertTrue(res.ok)
        self.assertEqual(len(_EchoHandler.records), 2)  # /redirect + /echo

    def test_redirect_not_followed_when_disabled(self):
        res = net.get(self.base + "/redirect", allow_redirects=False, timeout=5)
        self.assertEqual(res.status, 302)
        self.assertTrue(res.ok)
        self.assertEqual(len(_EchoHandler.records), 1)

    # ---------------- failure modes ----------------
    def test_timeout_becomes_error_response(self):
        saved = net._DEFAULTS["proxies"]
        net._DEFAULTS["proxies"] = {"http": None, "https": None}  # direct, no proxy
        try:
            res = net.request("GET", "http://203.0.113.1/", timeout=0.1)
        finally:
            net._DEFAULTS["proxies"] = saved
        self.assertEqual(res.status, 0)
        self.assertFalse(res.ok)
        self.assertTrue(res.error)

    def test_connection_refused_becomes_error_response(self):
        res = net.get("http://127.0.0.1:1/", timeout=5)
        self.assertEqual(res.status, 0)
        self.assertFalse(res.ok)
        self.assertTrue(res.error)

    def test_get_post_wrappers_work(self):
        g = net.get(self.base + "/echo", timeout=5)
        self.assertEqual(g.status, 200)
        p = net.post(self.base + "/echo", json={"k": 1}, timeout=5)
        self.assertEqual(p.status, 200)
        self.assertEqual(json.loads(p.text), {"k": 1})

    # ---------------- urllib fallback parity ----------------
    def test_urllib_fallback_surfaces_http_statuses(self):
        """HTTP error statuses (302-not-followed, 404) must surface their real
        code on the urllib fallback too, never be collapsed to status=0."""
        saved = net.requests
        net.requests = None  # force the urllib fallback
        try:
            r = net.get(self.base + "/redirect", allow_redirects=False, timeout=5)
            self.assertEqual(r.status, 302)
            self.assertTrue(r.ok)
            self.assertEqual(len(_EchoHandler.records), 1)

            r = net.get(self.base + "/echo", timeout=5)
            self.assertEqual(r.status, 200)
            self.assertTrue(r.ok)
            self.assertIn(ECHO_MARKER, r.text)

            r = net.get(self.base + "/nope", timeout=5)
            self.assertEqual(r.status, 404)
            self.assertTrue(r.ok)

            r = net.get("http://127.0.0.1:1/", timeout=5)
            self.assertEqual(r.status, 0)
            self.assertFalse(r.ok)
            self.assertTrue(r.error)
        finally:
            net.requests = saved


if __name__ == "__main__":
    unittest.main()
