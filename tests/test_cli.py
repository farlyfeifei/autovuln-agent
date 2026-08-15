"""CLI subprocess tests: --json stdout purity, exit codes, custom manifest."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "main.py")
ENV = dict(os.environ, PYTHONIOENCODING="utf-8")


def _run(*args, timeout=120):
    return subprocess.run(
        [sys.executable, MAIN, *args],
        capture_output=True, text=True, env=ENV, timeout=timeout, cwd=ROOT,
    )


_SQLI_CHALLENGE = {
    "id": "c1", "name": "C1", "category": "web-sqli",
    "target": "http://localhost/", "points": 10,
    "ground_truth_flag": "flag{manifest_cli_2026}",
    "win_tool": "sqli", "win_params": {"param": "user", "technique": "union"},
    "solvable": True,
}


def _write_manifest(challenges):
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                     encoding="utf-8")
    with fh:
        json.dump(challenges, fh, ensure_ascii=False)
    return fh.name


class CliTest(unittest.TestCase):
    def test_json_stdout_is_pure_json(self):
        proc = _run("--mode", "mock", "--json")
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)  # raises if any human line leaked
        self.assertEqual(data["mode"], "mock")
        self.assertEqual(data["solved"], 6)
        self.assertEqual(data["total"], 7)
        self.assertEqual(data["score"], 60)
        self.assertIn("score_pct", data)
        # the scoreboard/summary must live on stderr, never stdout
        self.assertNotIn("CATEGORY", proc.stdout)
        self.assertNotIn("solved:", proc.stdout)
        self.assertNotIn("[main]", proc.stdout)
        self.assertIn("CATEGORY", proc.stderr)
        self.assertIn("solved:", proc.stderr)

    def test_default_run_is_human_readable_on_stdout(self):
        proc = _run("--mode", "mock")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("CATEGORY", proc.stdout)
        self.assertIn("solved: 6/7", proc.stdout)

    def test_custom_manifest_in_mock_mode(self):
        path = _write_manifest([_SQLI_CHALLENGE])
        try:
            proc = _run("--mode", "mock", "--challenges-file", path, "--json")
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["solved"], 1)

    def test_exit_code_1_when_nothing_solved(self):
        unsolvable = dict(_SQLI_CHALLENGE, id="c2", solvable=False)
        path = _write_manifest([unsolvable])
        try:
            proc = _run("--mode", "mock", "--challenges-file", path)
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 1)

    def test_live_mode_with_no_challenges_exits_2(self):
        proc = _run("--mode", "http", "--challenges-file", "/nonexistent.json")
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
