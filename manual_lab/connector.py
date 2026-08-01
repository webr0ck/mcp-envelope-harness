"""MCP connector exposing the manual lab to Claude, Codex, and test harnesses."""
from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from manual_lab.constants import LAB_DECISION_META_KEY
from manual_lab.core import ManualEnvelopeLab


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = Path(
    os.environ.get("MANUAL_LAB_EVIDENCE_DIR", ROOT / ".run" / "manual_lab")
)

SAFE_TOOL_CONTENT = {
    "read_news": "Security teams are reviewing the latest vendor advisories.",
    "list_pull_requests": "PR #184 — Update dependency verification checks — open.",
    "get_last_jira_ticket": "SEC-241 — Review MCP connector policy — In Progress.",
}


def _inspection_state(config: dict[str, Any]) -> dict[str, Any]:
    targets = set(config.get("target_tools", []))
    effective_tools: dict[str, dict[str, Any]] = {}
    for tool_name in SAFE_TOOL_CONTENT:
        targeted = tool_name in targets
        effective_tools[tool_name] = {
            "content_source": "configured_payload" if targeted else "safe_fixture",
            "trust_tier": config["trust_tier"] if targeted else 2,
            "required_integrity": config["required_integrity"] if targeted else 1,
            "envelope": (
                "missing"
                if tool_name == "read_news"
                else "valid"
                if tool_name == "list_pull_requests"
                else config["envelope"] if targeted else "valid"
            ),
            "protection": "enforce" if tool_name == "get_last_jira_ticket" else "off",
        }
    return {**config, "effective_tools": effective_tools}

TOOLS = [
    types.Tool(
        name="read_news",
        description="Read the latest news available to this connector.",
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
    ),
    types.Tool(
        name="list_pull_requests",
        description="List the most recent pull requests available to this connector.",
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
    ),
    types.Tool(
        name="get_last_jira_ticket",
        description="Get the most recently updated Jira ticket available to this connector.",
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
    ),
    types.Tool(
        name="inspect_envelope_lab_state",
        description=(
            "Read-only diagnostic: show the response and policy currently published "
            "from the web lab for the connector tools."
        ),
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
    ),
]


def _decision_meta(run: dict[str, Any]) -> dict[str, Any]:
    consumer = run["consumer"]
    return {
        "run_id": run["run_id"],
        "payload": run["submission"]["payload"],
        **run["decision"],
        "delivered_payload": consumer["delivered_payload"],
    }


def _call_tool_result(
    result: dict[str, Any],
    decision: dict[str, Any] | None = None,
) -> types.CallToolResult:
    call_result = types.CallToolResult(
        content=[
            types.TextContent(type="text", text=str(item.get("text", "")))
            for item in result.get("content") or []
            if item.get("type") == "text"
        ]
    )
    meta = dict(result.get("_meta") or {})
    if decision:
        meta[LAB_DECISION_META_KEY] = decision
    call_result.meta = meta or None
    return call_result


def build_server(lab: ManualEnvelopeLab | None = None) -> Server:
    active_lab = lab or ManualEnvelopeLab(EVIDENCE)
    server = Server(
        "mcp-envelope-manual-lab",
        instructions=(
            "Use these tools to read current news, list recent pull requests, retrieve "
            "the latest Jira ticket, or inspect the connector's published state."
        ),
    )

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return TOOLS

    @server.call_tool()
    async def call_tool(tool_name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        del arguments
        config = active_lab.connector_config()

        if tool_name == "inspect_envelope_lab_state":
            import json

            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=json.dumps(_inspection_state(config), ensure_ascii=False, indent=2),
                    )
                ]
            )

        target_tools = set(config.pop("target_tools", []))
        if tool_name not in target_tools:
            config.update(
                content=SAFE_TOOL_CONTENT[tool_name],
                trust_tier=2,
                required_integrity=1,
                envelope="valid",
                protection="enforce",
            )

        if tool_name == "read_news":
            config.update(
                envelope="missing",
                protection="off",
                tool_name=tool_name,
            )
            run = active_lab.run(config, origin="mcp")
            return _call_tool_result(
                run["raw"]["wire_result"],
                _decision_meta(run),
            )

        if tool_name == "list_pull_requests":
            config.update(
                envelope="valid",
                protection="off",
                tool_name=tool_name,
            )
            run = active_lab.run(config, origin="mcp")
            return _call_tool_result(
                run["raw"]["wire_result"],
                _decision_meta(run),
            )

        if tool_name == "get_last_jira_ticket":
            config.update(
                protection="enforce",
                tool_name=tool_name,
            )
            run = active_lab.run(config, origin="mcp")
            protected_result = {
                "content": [{"type": "text", "text": run["consumer"]["delivered_text"]}]
            }
            return _call_tool_result(protected_result, _decision_meta(run))

        raise ValueError(f"Unknown tool: {tool_name}")

    return server


async def run_stdio() -> None:
    server = build_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdio", action="store_true", help="Run the MCP stdio transport")
    args = parser.parse_args()
    if not args.stdio:
        parser.error("use --stdio, or start manual_lab.app for Streamable HTTP")
    asyncio.run(run_stdio())


if __name__ == "__main__":
    main()
