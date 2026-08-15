"""Tool layer: unified Tool interface + registry + the default real registry.

Every concrete tool (in tools/recon.py, probe.py, exploit.py, parse.py) is a
subclass of :class:`Tool` exposing ``name``, ``description`` and
``run(challenge, params) -> ToolResult``. The registry is the single entry
point the ReAct loop uses to execute an action.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from core.types import Challenge, ToolResult


class Tool(ABC):
    name: str = "tool"
    description: str = ""

    @abstractmethod
    def run(self, challenge: Challenge, params: dict) -> ToolResult:
        """Execute the tool against the challenge target. Must never raise:
        catch exceptions and return them in the observation instead."""

    def __repr__(self) -> str:
        return f"<Tool {self.name}>"


class ToolRegistry:
    """Name -> Tool dispatcher. Also renders a manifest for the LLM prompt."""

    def __init__(self, tools: Optional[List[Tool]] = None) -> None:
        self._tools: Dict[str, Tool] = {}
        if tools:
            for tool in tools:
                self.register(tool)

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def names(self) -> List[str]:
        return sorted(self._tools)

    def run(self, name: str, challenge: Challenge, params: dict) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(
                tool=name, ok=False,
                observation=f"[tool-error] unknown tool '{name}'. available: {', '.join(self.names())}",
                params=params or {},
            )
        try:
            result = tool.run(challenge, params or {})
            if result.tool != name:
                result.tool = name
            return result
        except Exception as exc:  # never let a tool crash the loop
            return ToolResult(
                tool=name, ok=False, params=params or {},
                observation=f"[tool-error] {type(exc).__name__}: {exc}",
            )

    def manifest_text(self) -> str:
        """Short tool reference injected into the LLM system prompt."""
        lines = ["Available tools (name: description):"]
        for name in self.names():
            tool = self._tools[name]
            lines.append(f"- {name}: {tool.description}")
        return "\n".join(lines)


def build_real_registry() -> ToolRegistry:
    """Instantiate every real tool module into a single registry.

    Tool classes and their required ``name`` values (contract — do not rename):
      tools.recon   -> HttpProbeTool(http_probe), PortScanTool(port_scan),
                       DirEnumTool(dir_enum), FingerprintTool(fingerprint)
      tools.probe   -> ParamProbeTool(param_probe), FuzzTool(fuzz)
      tools.exploit -> SqliTool(sqli), XssTool(xss), LfiTool(lfi),
                       SsrfTool(ssrf), IdorTool(idor)
      tools.parse   -> DecodeTool(decode), HashCrackTool(hash_crack)
    """
    from . import exploit, parse, probe, recon

    tools = [
        recon.HttpProbeTool(),
        recon.PortScanTool(),
        recon.DirEnumTool(),
        recon.FingerprintTool(),
        probe.ParamProbeTool(),
        probe.FuzzTool(),
        exploit.SqliTool(),
        exploit.XssTool(),
        exploit.LfiTool(),
        exploit.SsrfTool(),
        exploit.IdorTool(),
        parse.DecodeTool(),
        parse.HashCrackTool(),
    ]
    return ToolRegistry(tools)
