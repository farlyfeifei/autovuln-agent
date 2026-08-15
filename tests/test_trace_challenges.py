"""Contract tests for core/trace.py (atomic JSONL trace persistence) and
bench/challenges.py (the mock challenge bank).

Run from the project root:
    PYTHONIOENCODING=utf-8 python -m unittest tests.test_trace_challenges -v
"""
import glob
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.trace import read_trace_jsonl, write_steps, write_trace_jsonl
from core.types import ChallengeResult, Step
from bench.challenges import get_challenges

EXPECTED_CATEGORIES = {
    "web-sqli", "web-xss", "web-lfi", "web-idor",
    "web-ssrf", "recon-info", "crypto-weak",
}

ALLOWED_CATEGORIES = EXPECTED_CATEGORIES


def _step(index=1, **overrides):
    fields = dict(
        index=index,
        thought="probe target",
        action='{"tool": "http_probe", "params": {"path": "/"}}',
        observation="200 OK",
        flags=[],
        tool="http_probe",
        params={"path": "/"},
        elapsed=0.42,
        tokens={"prompt": 100, "completion": 25},
    )
    fields.update(overrides)
    return Step(**fields)


def _result(challenge_id="web-sqli-01", **overrides):
    fields = dict(
        challenge_id=challenge_id,
        name="登录接口 UNION SQL 注入",
        category="web-sqli",
        passed=True,
        submitted_flag="flag{sql1_un10n_dump_2026}",
        ground_truth_flag="flag{sql1_un10n_dump_2026}",
        points_awarded=10,
        points_possible=10,
        steps_used=2,
        elapsed_sec=3.14,
        trace=[_step(1), _step(2, thought="submit the flag", action="submit")],
        tokens={"prompt": 200, "completion": 50},
        error=None,
    )
    fields.update(overrides)
    return ChallengeResult(**fields)


class TraceWriteTest(unittest.TestCase):
    """Contract for core/trace.py write/read helpers."""

    def setUp(self):
        self._dirs = []

    def tearDown(self):
        for d in self._dirs:
            try:
                import shutil
                shutil.rmtree(d)
            except OSError:
                pass

    def _tmpdir(self):
        d = tempfile.mkdtemp(prefix="trace_test_")
        self._dirs.append(d)
        return d

    def _assert_no_tmp_left(self, directory):
        self.assertEqual(
            glob.glob(os.path.join(directory, "*.tmp")),
            [],
            "atomic write must not leave a *.tmp file behind",
        )

    def test_write_trace_jsonl_creates_one_line_per_result(self):
        d = self._tmpdir()
        path = os.path.join(d, "trace.jsonl")
        results = [_result("web-sqli-01"), _result("recon-leak-01")]
        write_trace_jsonl(path, results)
        with open(path, encoding="utf-8") as fh:
            lines = [l for l in fh if l.strip()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["challenge_id"], "web-sqli-01")
        self.assertEqual(json.loads(lines[1])["challenge_id"], "recon-leak-01")

    def test_read_trace_jsonl_roundtrips_write(self):
        d = self._tmpdir()
        path = os.path.join(d, "trace.jsonl")
        results = [_result(), _result("web-xss-01", passed=False,
                                      submitted_flag="flag{wrong}",
                                      points_awarded=0, steps_used=3,
                                      elapsed_sec=9.9, error="timeout")]
        write_trace_jsonl(path, results)
        from dataclasses import asdict
        self.assertEqual(read_trace_jsonl(path), [asdict(r) for r in results])

    def test_read_trace_jsonl_roundtrip_nested_steps_and_unicode(self):
        d = self._tmpdir()
        path = os.path.join(d, "nested", "trace.jsonl")
        step = _step(1, thought="用 UNION 注入 dump 密钥",
                     params={"param": "user", "technique": "union"})
        r = _result("web-sqli-01", trace=[step], tokens={"prompt": 5, "completion": 2})
        write_trace_jsonl(path, [r])
        from dataclasses import asdict
        got = read_trace_jsonl(path)
        self.assertEqual(got, [asdict(r)])
        self.assertEqual(got[0]["trace"][0]["params"],
                         {"param": "user", "technique": "union"})
        self.assertEqual(got[0]["trace"][0]["thought"], "用 UNION 注入 dump 密钥")

    def test_write_trace_jsonl_creates_parent_directories(self):
        d = self._tmpdir()
        path = os.path.join(d, "a", "b", "c", "trace.jsonl")
        write_trace_jsonl(path, [_result()])
        self.assertTrue(os.path.isfile(path))

    def test_write_trace_jsonl_atomic_leaves_no_tmp(self):
        d = self._tmpdir()
        path = os.path.join(d, "trace.jsonl")
        write_trace_jsonl(path, [_result()])
        self.assertTrue(os.path.isfile(path))
        self._assert_no_tmp_left(d)

    def test_write_trace_jsonl_overwrites_existing_file(self):
        d = self._tmpdir()
        path = os.path.join(d, "trace.jsonl")
        write_trace_jsonl(path, [_result("web-sqli-01")])
        write_trace_jsonl(path, [_result("web-xss-01"), _result("web-idor-01")])
        ids = [d["challenge_id"] for d in read_trace_jsonl(path)]
        self.assertEqual(ids, ["web-xss-01", "web-idor-01"])
        self._assert_no_tmp_left(d)

    def test_read_trace_jsonl_skips_empty_lines(self):
        d = self._tmpdir()
        path = os.path.join(d, "trace.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('\n')
            fh.write('{"challenge_id": "web-xss-01"}\n')
            fh.write('\n')
            fh.write('{"challenge_id": "web-idor-01"}\n')
            fh.write('\n')
        got = read_trace_jsonl(path)
        self.assertEqual([d["challenge_id"] for d in got],
                         ["web-xss-01", "web-idor-01"])

    def test_write_steps_creates_parent_dir_and_parsable_lines(self):
        d = self._tmpdir()
        path = os.path.join(d, "deep", "steps.jsonl")
        steps = [_step(1), _step(2, tool="submit", action="submit",
                                 observation="flag accepted")]
        write_steps(path, steps)
        self.assertTrue(os.path.isfile(path))
        with open(path, encoding="utf-8") as fh:
            lines = [l for l in fh if l.strip()]
        self.assertEqual(len(lines), 2)
        parsed = [json.loads(l) for l in lines]
        self.assertEqual([s["index"] for s in parsed], [1, 2])
        self.assertEqual(parsed[0]["tool"], "http_probe")
        self._assert_no_tmp_left(os.path.join(d, "deep"))

    def test_write_steps_atomic_leaves_no_tmp(self):
        d = self._tmpdir()
        path = os.path.join(d, "steps.jsonl")
        write_steps(path, [_step(1)])
        self.assertTrue(os.path.isfile(path))
        self._assert_no_tmp_left(d)


class ChallengesContractTest(unittest.TestCase):
    """Contract for bench/challenges.py get_challenges()."""

    def setUp(self):
        self.challenges = get_challenges()

    def test_exactly_seven_challenges(self):
        self.assertEqual(len(self.challenges), 7)

    def test_ids_unique_and_nonempty(self):
        ids = [c.id for c in self.challenges]
        self.assertTrue(all(ids), "every challenge id must be non-empty")
        self.assertEqual(len(ids), len(set(ids)), "challenge ids must be unique")

    def test_every_entry_has_required_text_fields(self):
        for c in self.challenges:
            self.assertTrue(c.name.strip(), f"{c.id} has empty name")
            self.assertTrue(c.category.strip(), f"{c.id} has empty category")
            self.assertTrue(c.target.strip(), f"{c.id} has empty target")

    def test_points_positive(self):
        for c in self.challenges:
            self.assertGreater(c.points, 0, f"{c.id} points must be > 0")

    def test_ground_truth_flag_present_on_every_entry(self):
        for c in self.challenges:
            self.assertTrue(c.ground_truth_flag, f"{c.id} missing ground_truth_flag")

    def test_win_tool_set_on_every_entry(self):
        for c in self.challenges:
            self.assertTrue(c.win_tool, f"{c.id} missing win_tool")

    def test_exactly_one_unsolvable_is_the_ssrf(self):
        unsolvable = [c for c in self.challenges if not c.solvable]
        self.assertEqual(len(unsolvable), 1,
                         "exactly one challenge must have solvable=False")
        self.assertTrue(unsolvable[0].id.startswith("web-ssrf"),
                        "the unsolvable challenge must be the SSRF one")

    def test_points_sum_to_80(self):
        self.assertEqual(sum(c.points for c in self.challenges), 80)

    def test_categories_cover_expected_set(self):
        seen = {c.category for c in self.challenges}
        self.assertTrue(EXPECTED_CATEGORIES.issubset(seen),
                        f"missing categories: {EXPECTED_CATEGORIES - seen}")
        # sanity: no category outside the expected taxonomy
        self.assertTrue(seen.issubset(ALLOWED_CATEGORIES),
                        f"unexpected categories: {seen - ALLOWED_CATEGORIES}")


if __name__ == "__main__":
    unittest.main()
