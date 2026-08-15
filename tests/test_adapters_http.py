"""Contract tests for adapters/http.py.

Covers:
* challenge_from_dict  — required fields, points coercion, win_params
  normalization, unknown-key folding into ``extra``, solvable variants.
* load_challenges_manifest — temp-file cases (empty path, missing file, bad
  JSON, plain object, ``{"challenges": [...]}`` wrapper, missing id).
* the importable helpers ``_retcode_ok`` / ``_body_indicates_success``.
* HttpAdapter.submit against a real local stdlib HTTP server that inspects the
  incoming request and returns configurable bodies.
"""
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from adapters.http import (
    _body_indicates_success,
    _retcode_ok,
    challenge_from_dict,
    load_challenges_manifest,
    HttpAdapter,
)
from core.types import Challenge

FLAG = "flag{adapter_http_2026}"


def _challenge(**overrides):
    fields = dict(
        id="ch-1", name="challenge one", category="web", description="d",
        target="http://127.0.0.1:9", points=100,
    )
    fields.update(overrides)
    return Challenge(**fields)


def _closed_port():
    """Return a port number that (at the moment of the call) has no listener."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _ScoringHandler(BaseHTTPRequestHandler):
    """Stateful fake scoring platform. Class-level state because the handler
    is instantiated fresh per request (BaseHTTPRequestHandler)."""

    post_responses = []    # list of (status, text), consumed per POST
    get_responses = []     # list of (status, text), consumed per GET
    received = []          # list of (method, path, parsed_body_or_None)
    headers_received = []  # list of header dicts, one per request

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {"__raw__": raw.decode("utf-8", "replace")}

    def _reply(self, status, text):
        data = str(text).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        body = self._read_body()
        type(self).received.append(("POST", self.path, body))
        type(self).headers_received.append(dict(self.headers))
        status, text = (type(self).post_responses.pop(0)
                        if type(self).post_responses else (500, '{"error":"unexpected"}'))
        self._reply(status, text)

    def do_GET(self):
        body = self._read_body()
        type(self).received.append(("GET", self.path, body))
        type(self).headers_received.append(dict(self.headers))
        status, text = (type(self).get_responses.pop(0)
                        if type(self).get_responses else (500, '{"error":"unexpected"}'))
        self._reply(status, text)

    def log_message(self, *args):
        pass


class _ServerTestCase(unittest.TestCase):
    server = None
    base = ""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _ScoringHandler)
        port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _ScoringHandler.post_responses = []
        _ScoringHandler.get_responses = []
        _ScoringHandler.received = []
        _ScoringHandler.headers_received = []


class ChallengeFromDictTest(unittest.TestCase):
    def test_valid_entry_round_trips_fields(self):
        entry = {
            "id": "c1", "name": "SQLi 01", "category": "web",
            "description": "desc", "target": "http://127.0.0.1:9",
            "points": "10", "ground_truth_flag": "flag{x}",
            "win_tool": "sqli", "win_params": {"param": "id"},
            "solvable": "true", "foo": 1, "extra": {"bar": 2},
        }
        ch = challenge_from_dict(entry)
        self.assertEqual(ch.id, "c1")
        self.assertEqual(ch.name, "SQLi 01")
        self.assertEqual(ch.category, "web")
        self.assertEqual(ch.description, "desc")
        self.assertEqual(ch.target, "http://127.0.0.1:9")
        self.assertEqual(ch.points, 10)
        self.assertEqual(ch.ground_truth_flag, "flag{x}")
        self.assertEqual(ch.win_tool, "sqli")
        self.assertEqual(ch.win_params, {"param": "id"})
        self.assertIs(ch.solvable, True)
        self.assertEqual(ch.extra, {"foo": 1, "bar": 2})

    def test_missing_required_fields_raise(self):
        for missing in ("id", "name", "target"):
            entry = {"id": "x", "name": "y", "target": "z"}
            entry.pop(missing)
            with self.assertRaises(ValueError, msg=f"missing {missing}"):
                challenge_from_dict(entry)

    def test_empty_required_field_raises(self):
        with self.assertRaises(ValueError):
            challenge_from_dict({"id": " ", "name": "n", "target": "t"})

    def test_non_dict_entry_raises(self):
        for bad in ("nope", ["a"], 42, None):
            with self.assertRaises(ValueError):
                challenge_from_dict(bad)

    def test_points_coercion(self):
        self.assertEqual(challenge_from_dict(
            {"id": "c", "name": "n", "target": "t", "points": "10"}).points, 10)
        self.assertEqual(challenge_from_dict(
            {"id": "c", "name": "n", "target": "t", "points": "abc"}).points, 0)
        self.assertEqual(challenge_from_dict(
            {"id": "c", "name": "n", "target": "t", "points": " 7 "}).points, 7)

    def test_win_params_non_dict_becomes_empty(self):
        ch = challenge_from_dict({"id": "c", "name": "n", "target": "t",
                                  "win_params": "oops"})
        self.assertEqual(ch.win_params, {})

    def test_unknown_key_lands_in_extra_known_keys_do_not(self):
        ch = challenge_from_dict({"id": "c", "name": "n", "target": "t",
                                  "points": 5, "foo": 1})
        self.assertEqual(ch.extra, {"foo": 1})
        self.assertNotIn("id", ch.extra)
        self.assertNotIn("points", ch.extra)
        self.assertNotIn("solvable", ch.extra)

    def test_solvable_variants(self):
        for raw, expected in (("false", False), ("true", True), ("no", False),
                              ("FALSE", False), ("yes", True)):
            ch = challenge_from_dict({"id": "c", "name": "n", "target": "t",
                                      "solvable": raw})
            self.assertIs(ch.solvable, expected, msg=repr(raw))
        missing = challenge_from_dict({"id": "c", "name": "n", "target": "t"})
        self.assertIs(missing.solvable, True)
        false_bool = challenge_from_dict({"id": "c", "name": "n", "target": "t",
                                          "solvable": False})
        self.assertIs(false_bool.solvable, False)


class LoadManifestTest(unittest.TestCase):
    def _write(self, text_or_obj):
        raw = text_or_obj if isinstance(text_or_obj, str) else json.dumps(text_or_obj)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json",
                                         delete=False) as fh:
            fh.write(raw)
            path = fh.name
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_empty_path_raises_value_error(self):
        with self.assertRaises(ValueError):
            load_challenges_manifest("")

    def test_missing_file_raises_filenotfound(self):
        path = os.path.join(tempfile.gettempdir(), "no-such-manifest-2026.json")
        with self.assertRaises(FileNotFoundError):
            load_challenges_manifest(path)

    def test_bad_json_raises_value_error(self):
        path = self._write("this is not json {")
        with self.assertRaises(ValueError):
            load_challenges_manifest(path)

    def test_plain_object_without_challenges_raises(self):
        path = self._write({"foo": 1})
        with self.assertRaises(ValueError):
            load_challenges_manifest(path)

    def test_challenges_wrapper_accepted(self):
        path = self._write({"challenges": [
            {"id": "a", "name": "A", "target": "http://a"},
            {"id": "b", "name": "B", "target": "http://b", "points": "20"},
        ]})
        loaded = load_challenges_manifest(path)
        self.assertEqual(len(loaded), 2)
        self.assertEqual([c.id for c in loaded], ["a", "b"])
        self.assertEqual(loaded[1].points, 20)

    def test_entry_with_missing_id_raises(self):
        path = self._write([{"name": "n", "target": "http://t"}])
        with self.assertRaises(ValueError):
            load_challenges_manifest(path)


class SuccessHelperTest(unittest.TestCase):
    def test_retcode_ok_shapes(self):
        self.assertTrue(_retcode_ok({"retcode": 0}))
        self.assertTrue(_retcode_ok({"retcode": "0"}))
        self.assertFalse(_retcode_ok({"retcode": 1}))
        self.assertFalse(_retcode_ok({"retcode": "1"}))
        self.assertTrue(_retcode_ok({"data": {"retcode": 0}}))
        self.assertTrue(_retcode_ok({"result": {"retcode": "0"}}))
        self.assertTrue(_retcode_ok({"body": {"retcode": 0}}))
        self.assertTrue(_retcode_ok({"payload": {"retcode": 0}}))
        self.assertFalse(_retcode_ok({"error": {"retcode": 0}}))
        self.assertFalse(_retcode_ok({}))
        self.assertFalse(_retcode_ok("success"))
        self.assertFalse(_retcode_ok([{"retcode": 0}]))

    def test_body_indicates_success(self):
        for text in ("success", "Success", "SUCCESS", "all ok", "Ok",
                     "the submission was accepted", "ok"):
            self.assertTrue(_body_indicates_success(text), msg=text)
        for text in ("unsuccessful", "failed", "submission failed",
                     "broken", "okay", "", "  ", "not json at all", "<html>500</html>"):
            self.assertFalse(_body_indicates_success(text), msg=text)
        self.assertTrue(_body_indicates_success('{"retcode": 0}'))
        self.assertTrue(_body_indicates_success('{"data": {"retcode": 0}}'))
        self.assertFalse(_body_indicates_success('{"retcode": 1}'))
        self.assertFalse(_body_indicates_success('{"message": "success"}'))


class HttpAdapterSubmitTest(_ServerTestCase):
    def _adapter(self, token=""):
        return HttpAdapter(challenges=[], submit_endpoint=f"{self.base}/submit",
                           token=token)

    def test_submit_retcode_0_true(self):
        _ScoringHandler.post_responses = [(200, '{"retcode": 0}')]
        self.assertTrue(self._adapter().submit(_challenge(), FLAG))
        method, path, body = _ScoringHandler.received[-1]
        self.assertEqual((method, path), ("POST", "/submit"))
        self.assertEqual(body, {"challenge_id": "ch-1", "flag": FLAG})

    def test_submit_retcode_string_zero_true(self):
        _ScoringHandler.post_responses = [(200, '{"retcode": "0"}')]
        self.assertTrue(self._adapter().submit(_challenge(), FLAG))

    def test_submit_retcode_one_false(self):
        _ScoringHandler.post_responses = [(200, '{"retcode": 1}')]
        self.assertFalse(self._adapter().submit(_challenge(), FLAG))

    def test_submit_wrapped_data_retcode_true(self):
        _ScoringHandler.post_responses = [(200, '{"data": {"retcode": 0}}')]
        self.assertTrue(self._adapter().submit(_challenge(), FLAG))

    def test_submit_plain_success_true(self):
        _ScoringHandler.post_responses = [(200, "success")]
        self.assertTrue(self._adapter().submit(_challenge(), FLAG))

    def test_submit_plain_unsuccessful_false(self):
        _ScoringHandler.post_responses = [(200, "unsuccessful")]
        self.assertFalse(self._adapter().submit(_challenge(), FLAG))

    def test_submit_garbage_body_false(self):
        _ScoringHandler.post_responses = [(200, "not json at all")]
        self.assertFalse(self._adapter().submit(_challenge(), FLAG))

    def test_submit_http_500_false(self):
        _ScoringHandler.post_responses = [(500, '{"retcode": 0}')]
        self.assertFalse(self._adapter().submit(_challenge(), FLAG))

    def test_submit_no_endpoint_false(self):
        adapter = HttpAdapter(challenges=[], submit_endpoint="", token="")
        self.assertFalse(adapter.submit(_challenge(), FLAG))
        self.assertEqual(_ScoringHandler.received, [])

    def test_submit_empty_flag_false(self):
        _ScoringHandler.post_responses = [(200, '{"retcode": 0}')]
        adapter = self._adapter()
        self.assertFalse(adapter.submit(_challenge(), ""))
        self.assertFalse(adapter.submit(_challenge(), "   "))
        self.assertEqual(_ScoringHandler.received, [])

    def test_submit_no_token_no_auth_header(self):
        _ScoringHandler.post_responses = [(200, '{"retcode": 0}')]
        self.assertTrue(self._adapter().submit(_challenge(), FLAG))
        self.assertNotIn("Authorization", _ScoringHandler.headers_received[-1])

    def test_submit_with_token_sends_bearer_header(self):
        _ScoringHandler.post_responses = [(200, '{"retcode": 0}')]
        self.assertTrue(self._adapter(token="tok-abc").submit(_challenge(), FLAG))
        self.assertEqual(_ScoringHandler.headers_received[-1]["Authorization"],
                         "Bearer tok-abc")

    def test_submit_server_down_false_without_raising(self):
        port = _closed_port()
        adapter = HttpAdapter(challenges=[],
                              submit_endpoint=f"http://127.0.0.1:{port}/submit",
                              token="")
        self.assertFalse(adapter.submit(_challenge(), FLAG))


if __name__ == "__main__":
    unittest.main()
