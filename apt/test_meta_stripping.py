"""Evidence for the upstream `_meta` stripping defect that apt/fastagent_meta_shim.py works
around. Deterministic and LLM-free — these must hold regardless of model behaviour.

Run: .venv/bin/python -m pytest apt/test_meta_stripping.py -v
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("fast_agent", reason="fast-agent-mcp not installed")

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult, TextContent
from mcp_trust_verifier import TRUST_ENVELOPE_KEY, TrustVerifier

from apt import scenario
from producer.signer import Pki

pytestmark = pytest.mark.skipif(
    not scenario.ANCHOR.exists(), reason="run `.venv/bin/python -m apt.setup` first"
)


def _signed_result() -> CallToolResult:
    from producer.signer import build_result

    signed = build_result(
        Pki.load(scenario.PKI_DIR),
        [{"type": "text", "text": "hello"}],
        tool_name=scenario.TOOL_FETCH,
        server_id=scenario.SERVER_ISSUES,
        result_id="rid-meta-test",
        trust_tier=0,
    )
    ctr = CallToolResult(content=[TextContent(type="text", text="hello")])
    ctr.meta = signed["_meta"]
    return ctr


def _host():
    """A real McpUIMixin subclass — NOT a duck-typed stand-in.

    Copying the two methods onto a bare class instead makes `_split_ui_blocks` raise,
    which lands in the mixin's `except Exception: pass through untouched` branch and
    silently hides the defect (the result comes back WITH its meta). That false-negative
    is exactly what a lazy test host buys you, so the host has to be the real class.
    The strip point itself was localised on a live run: aggregator.call_tool -> meta True,
    _extract_ui_from_tool_results IN True / OUT False, hook False.
    """
    from fast_agent.mcp.ui_mixin import McpUIMixin

    class _H(McpUIMixin):
        def __init__(self):
            pass

    return _H()


def test_stock_fastagent_strips_meta_from_tool_results():
    """THE DEFECT: the UI-extraction pass rebuilds every result and drops _meta."""
    import apt.fastagent_meta_shim as shim
    from fast_agent.mcp.ui_mixin import McpUIMixin

    if getattr(McpUIMixin._extract_ui_from_tool_results, "_envelope_shim", False):
        pytest.skip("shim already applied in this process; run this test first/in isolation")

    src = _signed_result()
    assert src.meta and TRUST_ENVELOPE_KEY in src.meta, "precondition: envelope attached"

    out = _host()._extract_ui_from_tool_results({"call-1": src})
    rebuilt = out.tool_results["call-1"]

    assert getattr(rebuilt, "meta", None) is None, (
        "fast-agent no longer strips _meta — re-verify whether the shim is still needed "
        "and drop it if upstream fixed this"
    )
    assert rebuilt.content[0].text == "hello"  # content itself survives
    del shim


def test_shim_restores_meta():
    from apt.fastagent_meta_shim import apply

    apply()
    src = _signed_result()
    out = _host()._extract_ui_from_tool_results({"call-1": src})
    rebuilt = out.tool_results["call-1"]

    assert rebuilt.meta is not None and TRUST_ENVELOPE_KEY in rebuilt.meta
    assert rebuilt.meta == src.meta


def test_envelope_is_intact_on_the_real_mcp_wire():
    """Independent of fast-agent entirely: a real MCP client session over stdio receives
    the envelope correctly and it VERIFIES. This is what localises the fault to
    fast-agent rather than to our server, the SDK, or the signing."""

    async def go():
        params = StdioServerParameters(
            command=str(scenario.ROOT / ".venv" / "bin" / "python"),
            args=["-m", "apt.mcp_servers", "--role", "issues"],
            cwd=str(scenario.ROOT),
        )
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                return await s.call_tool(scenario.TOOL_FETCH, {"number": 42})

    res = asyncio.run(go())
    env = (res.meta or {}).get(TRUST_ENVELOPE_KEY)
    assert env is not None, "envelope missing on the real MCP wire"
    assert env["label"]["integrity_rank"] == 0

    verifier = TrustVerifier.from_pem(str(scenario.ANCHOR))
    dumped = res.model_dump(by_alias=True, exclude_none=True)
    verdict = verifier.verify(
        {"content": dumped.get("content", []), "_meta": res.meta},
        tool_name=scenario.TOOL_FETCH,
        result_id=env["call_context"]["result_id"],
    )
    assert verdict.accepted, f"wire envelope failed to verify: {verdict.reason}"
    assert verdict.integrity_rank == 0
