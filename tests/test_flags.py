"""Tests for core.flags extraction."""
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.flags import extract_flag, extract_flags, extract_hex_tokens


class FlagsTest(unittest.TestCase):
    def test_brace_flags(self):
        text = "got flag{abc_123} and CTF{xyz} and key{k1}"
        self.assertEqual(extract_flags(text),
                         ["flag{abc_123}", "CTF{xyz}", "key{k1}"])

    def test_case_insensitive(self):
        self.assertEqual(extract_flags("FLAG{uppercase}"),
                         ["FLAG{uppercase}"])

    def test_dedup(self):
        self.assertEqual(extract_flags("flag{a} flag{a} flag{b}"),
                         ["flag{a}", "flag{b}"])

    def test_first_flag(self):
        self.assertEqual(extract_flag("noise flag{first} tail flag{second}"),
                         "flag{first}")

    def test_no_flag(self):
        self.assertIsNone(extract_flag("nothing here"))
        self.assertEqual(extract_flags(""), [])

    def test_hex_tokens(self):
        h = "a" * 32
        self.assertEqual(extract_hex_tokens(f"token={h}"), [h])


if __name__ == "__main__":
    unittest.main()
