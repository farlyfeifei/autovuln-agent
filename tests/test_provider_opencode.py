"""OpenCode Go provider wiring: API-key resolution + build_llm routing.

The OpenCode Go integration reuses :class:`OpenAILikeProvider` against
``https://opencode.ai/zen/go/v1``; the only opencode-specific logic is (a)
resolving the API key from opencode's own auth store (``~/.local/share/
opencode/auth.json``) when ``LLM_API_KEY`` is absent, and (b) routing the
``opencode`` provider through ``build_llm`` without treating it as key-less.

These tests patch ``os.path.expanduser`` to point at a scratch home, so no real
credentials are touched and nothing hits the network.
"""
import sys
import os
import json
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from config import LLMConfig
from llm.local_policy import LocalPolicyLLM
from llm.providers import OpenAILikeProvider, _opencode_api_key, build_llm


def _scratch_auth(key: str) -> str:
    """Write a fake opencode auth.json into a scratch home; return the home."""
    tmp = tempfile.mkdtemp()
    auth_dir = os.path.join(tmp, ".local", "share", "opencode")
    os.makedirs(auth_dir)
    with open(os.path.join(auth_dir, "auth.json"), "w", encoding="utf-8") as fh:
        json.dump({"opencode-go": {"type": "api", "key": key}}, fh)
    return tmp


class OpenCodeKeyTest(unittest.TestCase):
    def test_env_var_takes_precedence(self):
        with patch.dict(os.environ, {"LLM_API_KEY": "sk-env-123"}, clear=True):
            self.assertEqual(_opencode_api_key(), "sk-env-123")

    def test_reads_key_from_opencode_auth_json(self):
        home = _scratch_auth("sk-auth-456")
        with patch.dict(os.environ, {}, clear=True):
            with patch("llm.providers.os.path.expanduser", return_value=home):
                self.assertEqual(_opencode_api_key(), "sk-auth-456")

    def test_missing_auth_store_returns_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("llm.providers.os.path.expanduser",
                       return_value=tempfile.mkdtemp()):
                self.assertEqual(_opencode_api_key(), "")


class BuildLlmOpenCodeTest(unittest.TestCase):
    def test_opencode_returns_http_provider_with_resolved_key(self):
        home = _scratch_auth("sk-auth-789")
        with patch.dict(os.environ, {}, clear=True):
            with patch("llm.providers.os.path.expanduser", return_value=home):
                llm = build_llm(LLMConfig(provider="opencode", model="glm-5.2",
                                          base_url="http://127.0.0.1:1/v1",
                                          timeout=5))
        self.assertIsInstance(llm, OpenAILikeProvider)
        self.assertEqual(llm.api_key, "sk-auth-789")
        self.assertEqual(llm.model, "glm-5.2")
        self.assertEqual(llm.provider, "opencode")

    def test_opencode_defaults_to_zen_go_endpoint(self):
        home = _scratch_auth("sk-auth-111")
        with patch.dict(os.environ, {}, clear=True):
            with patch("llm.providers.os.path.expanduser", return_value=home):
                llm = build_llm(LLMConfig(provider="opencode", model="glm-5.2"))
        self.assertEqual(llm.base_url, "https://opencode.ai/zen/go/v1")

    def test_opencode_without_key_falls_back_to_local(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("llm.providers.os.path.expanduser",
                       return_value=tempfile.mkdtemp()):
                llm = build_llm(LLMConfig(provider="opencode", model="glm-5.2"))
        self.assertIsInstance(llm, LocalPolicyLLM)


if __name__ == "__main__":
    unittest.main()
