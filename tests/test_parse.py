"""Tests for the parse tools (decode / hash_crack)."""
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.types import Challenge
from tools.parse import DecodeTool, HashCrackTool


def _challenge(extra=None):
    return Challenge(id="t1", name="", category="crypto-weak", description="",
                     target="http://mock.local/token", points=10,
                     ground_truth_flag="flag{test_flag_1}", extra=extra or {})


class DecodeToolTest(unittest.TestCase):
    def setUp(self):
        self.tool = DecodeTool()

    def test_base64(self):
        import base64
        enc = base64.b64encode(b"flag{decode_me}").decode()
        res = self.tool.run(_challenge(), {"scheme": "b64", "text": enc})
        self.assertTrue(res.ok)
        self.assertIn("flag{decode_me}", res.observation)

    def test_hex(self):
        res = self.tool.run(_challenge(), {"scheme": "hex", "text": "666c61677b6865787d"})
        self.assertTrue(res.ok)
        self.assertIn("flag{hex}", res.observation)

    def test_xor_brute(self):
        data = b"secret:flag{xor_test}"
        key = 0x5a
        cipher = bytes(b ^ key for b in data).hex()
        res = self.tool.run(_challenge(), {"scheme": "xor", "text": cipher})
        self.assertTrue(res.ok)
        self.assertIn("flag{xor_test}", res.observation)

    def test_rot13(self):
        import codecs
        rot = codecs.encode("flag{rot_test}", "rot_13")
        res = self.tool.run(_challenge(), {"scheme": "rot13", "text": rot})
        self.assertTrue(res.ok)
        self.assertIn("flag{rot_test}", res.observation)

    def test_no_text_falls_back_to_extra(self):
        res = self.tool.run(_challenge({"cipher": "ZmxhZ3tleHRyYX9ufQ=="}),
                            {"scheme": "b64"})
        self.assertTrue(res.ok)


class HashCrackTest(unittest.TestCase):
    def setUp(self):
        self.tool = HashCrackTool()

    def test_crack_known_word(self):
        import hashlib
        h = hashlib.md5(b"admin").hexdigest()
        res = self.tool.run(_challenge(), {"hash": h, "type": "auto"})
        self.assertTrue(res.ok)
        self.assertIn("admin", res.observation)

    def test_identify_unknown(self):
        h = "f" * 64
        res = self.tool.run(_challenge(), {"hash": h, "type": "auto"})
        self.assertTrue(res.ok)
        self.assertIn("sha256", res.observation)


if __name__ == "__main__":
    unittest.main()
