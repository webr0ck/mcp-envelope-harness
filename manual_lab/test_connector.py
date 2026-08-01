from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp_trust_verifier import TRUST_ENVELOPE_KEY

from manual_lab.connector import SAFE_TOOL_CONTENT, TOOLS
from manual_lab.core import ManualEnvelopeLab, POISON_MARKERS


ROOT = Path(__file__).resolve().parent.parent


async def _exercise_connector(evidence_dir: Path):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "manual_lab.connector", "--stdio"],
        cwd=str(ROOT),
        env={
            **os.environ,
            "MANUAL_LAB_EVIDENCE_DIR": str(evidence_dir),
        },
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            news = await session.call_tool("read_news", {})
            pull_requests = await session.call_tool("list_pull_requests", {})
            jira_ticket = await session.call_tool("get_last_jira_ticket", {})
            state = await session.call_tool("inspect_envelope_lab_state", {})
            return tools, news, pull_requests, jira_ticket, state


def test_stdio_connector_proves_unsigned_signed_and_protected_paths(tmp_path):
    lab = ManualEnvelopeLab(tmp_path)
    lab.publish_connector_config(lab.scenario("malicious_blocked"))

    tools, news, pull_requests, jira_ticket, state = asyncio.run(
        _exercise_connector(tmp_path)
    )
    names = {tool.name for tool in tools.tools}
    assert names == {
        "read_news",
        "list_pull_requests",
        "get_last_jira_ticket",
        "inspect_envelope_lab_state",
    } <= names

    news_text = news.content[0].text
    assert news.meta is None
    assert all(marker in news_text for marker in POISON_MARKERS)

    pull_requests_text = pull_requests.content[0].text
    assert (pull_requests.meta or {}).get(TRUST_ENVELOPE_KEY)
    assert all(marker in pull_requests_text for marker in POISON_MARKERS)

    jira_ticket_text = jira_ticket.content[0].text
    assert jira_ticket_text.startswith("[trust-gate REFUSED")
    assert not any(marker in jira_ticket_text for marker in POISON_MARKERS)
    inspected = json.loads(state.content[0].text)
    assert inspected["effective_tools"]["read_news"]["protection"] == "off"
    assert inspected["effective_tools"]["list_pull_requests"]["envelope"] == "valid"
    assert inspected["effective_tools"]["get_last_jira_ticket"]["protection"] == "enforce"
    assert {record["origin"] for record in lab.recent_logs()["consumer"]} == {"mcp"}


def test_connector_sends_configured_payload_only_to_selected_tools(tmp_path):
    lab = ManualEnvelopeLab(tmp_path)
    config = lab.scenario("malicious_blocked")
    config["target_tools"] = ["list_pull_requests"]
    lab.publish_connector_config(config)

    _, news, pull_requests, jira_ticket, state = asyncio.run(_exercise_connector(tmp_path))

    assert news.content[0].text == SAFE_TOOL_CONTENT["read_news"]
    assert not any(marker in news.content[0].text for marker in POISON_MARKERS)
    assert all(marker in pull_requests.content[0].text for marker in POISON_MARKERS)
    assert jira_ticket.content[0].text == SAFE_TOOL_CONTENT["get_last_jira_ticket"]
    assert not any(marker in jira_ticket.content[0].text for marker in POISON_MARKERS)
    inspected = json.loads(state.content[0].text)
    assert inspected["effective_tools"]["read_news"]["content_source"] == "safe_fixture"
    assert inspected["effective_tools"]["list_pull_requests"]["content_source"] == (
        "configured_payload"
    )


def test_business_tool_descriptions_do_not_signal_security_posture():
    descriptions = {tool.name: tool.description for tool in TOOLS}
    assert descriptions["read_news"] == "Read the latest news available to this connector."
    assert descriptions["list_pull_requests"] == (
        "List the most recent pull requests available to this connector."
    )
    assert descriptions["get_last_jira_ticket"] == (
        "Get the most recently updated Jira ticket available to this connector."
    )
    business_descriptions = " ".join(
        descriptions[name]
        for name in ("read_news", "list_pull_requests", "get_last_jira_ticket")
    ).lower()
    assert not {"vulnerable", "protected", "unsigned", "unenforced"} & set(
        business_descriptions.split()
    )
