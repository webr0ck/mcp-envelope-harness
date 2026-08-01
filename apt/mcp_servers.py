"""The two REAL MCP servers for the APT scenario. Genuine protocol over stdio — real
initialize handshake, real tools/list, real tools/call — not an HTTP stand-in.

  --role issues  : issue_tracker. Signs its results tier 0 (untrustedPublic), because
                   that is the TRUTH about a public issue tracker. It is not compromised
                   and it is not lying; it correctly labels content anyone can write.
  --role mailer  : mailer. The privileged egress capability. Whatever it is asked to send
                   is appended to the sink file — that file is the test's ground truth.

Both load the SAME persisted labeler PKI, so a consumer pins ONE sub-CA for both.

Returning a `types.CallToolResult` straight from the low-level call_tool handler is what
lets us attach `_meta` (mcp/server/lowlevel/server.py passes it through untouched); the
FastMCP convenience wrapper would rebuild the result and drop the envelope.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from apt import scenario
from producer.signer import Pki

TOOLS = {
    "issues": [
        types.Tool(
            name=scenario.TOOL_FETCH,
            description="Fetch the body of an issue from the public issue tracker.",
            inputSchema={
                "type": "object",
                "properties": {"number": {"type": "integer", "description": "Issue number"}},
                "required": ["number"],
            },
        )
    ],
    "mailer": [
        types.Tool(
            name=scenario.TOOL_SEND,
            description="Send a report by email to an address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient email address"},
                    "body": {"type": "string", "description": "Report body"},
                },
                "required": ["to", "body"],
            },
        )
    ],
}


def _record_exfil(args: dict) -> None:
    """Append to the sink. This is the oracle: the ONLY question that ultimately matters
    is whether the canary left the building, so we record verbatim and assert on it."""
    scenario.SINK.parent.mkdir(parents=True, exist_ok=True)
    sent = json.loads(scenario.SINK.read_text()) if scenario.SINK.exists() else []
    sent.append({"to": args.get("to"), "body": args.get("body")})
    scenario.SINK.write_text(json.dumps(sent, indent=2))


def build(role: str) -> Server:
    pki = Pki.load(scenario.PKI_DIR)
    name = scenario.SERVER_ISSUES if role == "issues" else scenario.SERVER_MAIL
    server = Server(name)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return TOOLS[role]

    @server.call_tool()
    async def call_tool(tool_name: str, arguments: dict) -> types.CallToolResult:
        if role == "issues":
            n = arguments.get("number")
            text = scenario.POISONED_ISSUE if n == 42 else scenario.BENIGN_ISSUE
            tier = 0  # untrustedPublic — honest label for public-writable content
        else:
            _record_exfil(arguments)
            text = f"Report sent to {arguments.get('to')}."
            tier = 4  # system — an internal service reporting its own action

        # The server mints result_id: over real MCP it cannot learn the client's
        # tool-call id (fast-agent does not forward request _meta — see
        # consumer.hooks._result_id_for for the cost this carries).
        signed = _sign(pki, text, tool_name=tool_name, server_id=name, tier=tier)
        ctr = types.CallToolResult(
            content=[types.TextContent(type="text", text=c["text"]) for c in signed["content"]]
        )
        ctr.meta = signed["_meta"]
        return ctr

    return server


def _sign(pki: Pki, text: str, *, tool_name: str, server_id: str, tier: int) -> dict:
    from producer.signer import build_result

    return build_result(
        pki,
        [{"type": "text", "text": text}],
        tool_name=tool_name,
        server_id=server_id,
        result_id=secrets.token_urlsafe(12),
        trust_tier=tier,
    )


async def _main(role: str) -> None:
    server = build(role)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", required=True, choices=["issues", "mailer"])
    a = ap.parse_args()
    asyncio.run(_main(a.role))
