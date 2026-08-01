"""UPSTREAM DEFECT SHIM — fast-agent-mcp 0.9.22 strips `_meta` from every tool result.

Finding (reproduce with apt/test_meta_stripping.py):

    fast_agent/mcp/ui_mixin.py::McpUIMixin._extract_ui_from_tool_results runs on EVERY
    tool result, and rebuilds each one as

        CallToolResult(content=split_blocks.other_blocks, isError=result.isError)

    Only `content` and `isError` are carried over. `_meta` and `structuredContent` are
    silently dropped — before ToolRunnerHooks.after_tool_call is awaited.

Impact well beyond this harness: MCP's `_meta` is the designated channel for
out-of-band per-result metadata, and it is where any provenance, signature, labelling
or attestation scheme has to ride. An agent framework that discards it mid-loop makes
in-agent verification of tool-result provenance impossible — the verifier sees
`no_envelope` for results that were correctly signed on the wire (proven independently
by apt/test_meta_stripping.py, which reads the same result straight off a real MCP
session and finds the envelope intact).

This shim restores `_meta`/`structuredContent` onto the rebuilt results by correlating
on the tool-call id. It does NOT edit the installed package — it patches the method at
runtime, from our own code, and is applied only by the APT scenario.

HONEST SCOPE: with this shim the APT test demonstrates what in-agent enforcement does
ONCE THE FRAMEWORK PRESERVES `_meta`. On stock fast-agent 0.9.22 it does not, and no
amount of consumer-side work fixes that — it needs an upstream change. Any writeup must
say so; claiming a deployable in-agent control today would be false.
"""
from __future__ import annotations


def apply() -> str:
    """Patch McpUIMixin._extract_ui_from_tool_results to preserve _meta. Idempotent.
    Returns a human-readable status string for the run log."""
    from fast_agent.mcp.ui_mixin import McpUIMixin

    original = McpUIMixin._extract_ui_from_tool_results
    if getattr(original, "_envelope_shim", False):
        return "already applied"

    def patched(self, tool_results):
        extraction = original(self, tool_results)
        if not tool_results or not extraction.tool_results:
            return extraction
        for key, rebuilt in extraction.tool_results.items():
            src = tool_results.get(key)
            if src is None or rebuilt is src:
                continue  # untouched pass-through path already keeps everything
            if getattr(rebuilt, "meta", None) is None:
                rebuilt.meta = getattr(src, "meta", None)
            if getattr(rebuilt, "structuredContent", None) is None:
                rebuilt.structuredContent = getattr(src, "structuredContent", None)
        return extraction

    patched._envelope_shim = True
    McpUIMixin._extract_ui_from_tool_results = patched
    return "applied to McpUIMixin._extract_ui_from_tool_results"
