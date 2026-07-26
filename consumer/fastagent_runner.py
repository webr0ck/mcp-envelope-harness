"""Drive one tool result through the REAL fast-agent ToolRunner so our conformant
ToolRunnerHooks.after_tool_call fires exactly as in a live agent turn — minus the LLM.

No faked pass: `ToolRunner.generate_tool_call_response()` (fast_agent's own code) awaits
our async hook and uses the mutated `message` for the (stubbed) next turn. The LLM is the
only thing stubbed — a `_FakeToolAgent.run_tools` returns the wire-fetched CallToolResult;
everything about the hook-firing path (before_tool_call → run_tools → await after_tool_call)
is the real fast-agent code. This is the conformance evidence for the article: our hook
runs inside real fast-agent, and redaction happens BEFORE the model would see the result.

Requires fast-agent-mcp installed (see docs/ROADMAP.md WI-2). Import lazily so the rest of
the harness still works without it.
"""
from __future__ import annotations

import asyncio

from consumer import hooks as _hooks


class _FakeToolAgent:
    """Minimal fast-agent tool-loop agent: returns a pre-built tool-result message.
    Only `run_tools` + `name` are touched by ToolRunner.generate_tool_call_response;
    the status-message deferral checks `isinstance(agent, LlmAgent)` and no-ops for us."""

    name = "fake-tool-agent"

    def __init__(self, tool_message):
        self._tool_message = tool_message

    async def run_tools(self, request, request_params=None):
        return self._tool_message


def dict_to_call_tool_result(result: dict):
    from mcp.types import CallToolResult, TextContent

    content = [
        TextContent(type="text", text=i.get("text", ""))
        for i in (result.get("content") or [])
        if isinstance(i, dict)
    ] or [TextContent(type="text", text="")]
    ctr = CallToolResult(content=content)
    ctr.meta = result.get("_meta") or None
    return ctr


def _mk_request(tool_name: str, call_id: str):
    from fast_agent.types import PromptMessageExtended
    from mcp.types import CallToolRequest, CallToolRequestParams

    call = CallToolRequest(
        method="tools/call", params=CallToolRequestParams(name=tool_name, arguments={})
    )
    return PromptMessageExtended(role="assistant", tool_calls={call_id: call})


async def _run(result: dict, *, tool_name: str, result_id: str, hooks_obj):
    from fast_agent.agents.tool_runner import ToolRunner, ToolRunnerHooks
    from fast_agent.types import PromptMessageExtended

    ctr = dict_to_call_tool_result(result)
    tool_message = PromptMessageExtended(role="user", tool_results={result_id: ctr})
    hk = hooks_obj or ToolRunnerHooks(
        before_tool_call=_hooks.before_tool_call, after_tool_call=_hooks.after_tool_call
    )
    runner = ToolRunner(agent=_FakeToolAgent(tool_message), messages=[], hooks=hk)
    # The tool REQUEST the model "made" — carries the tool name under the same call id so
    # the hook resolves tool_name from the runner (the real seam), AND lets before_tool_call
    # fire on the Biba floor first (fail-closed) exactly as in a live turn.
    runner._pending_tool_request = _mk_request(tool_name, result_id)
    out = await runner.generate_tool_call_response()
    verdicts = getattr(runner, "trust_verdicts", [])
    return out, verdicts


def run_through_fastagent(result: dict, *, tool_name: str, result_id: str, hooks_obj=None):
    """Run one wire result through the REAL fast-agent ToolRunner. Returns
    (contained_message, verdicts). The returned message's tool_results[result_id] is the
    (possibly redacted) CallToolResult the model turn would consume."""
    return asyncio.run(_run(result, tool_name=tool_name, result_id=result_id, hooks_obj=hooks_obj))


def contained_text(message, result_id: str) -> str:
    """Concatenated text of the contained CallToolResult — what the LLM turn would see."""
    ctr = (message.tool_results or {}).get(result_id)
    if ctr is None:
        return ""
    return " ".join(getattr(c, "text", "") for c in (ctr.content or []))
