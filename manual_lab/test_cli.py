from __future__ import annotations

import asyncio
from pathlib import Path

from manual_lab.cli import (
    Ansi,
    ConsoleHarness,
    SkillRegistry,
    Trace,
    build_parser,
    execute_lab_command,
)
from manual_lab.core import MALICIOUS_TEXT


SKILLS = Path(__file__).resolve().parent / "skills"
README = Path(__file__).resolve().parent / "README.md"


def test_skill_registry_discovers_and_activates_lab_skill():
    registry = SkillRegistry([SKILLS])

    assert "lab-command-runner" in registry.skills
    skill = registry.activate("lab-command-runner")

    assert skill.path.name == "SKILL.md"
    assert "whoami" in registry.system_text()
    assert registry.active == ["lab-command-runner"]


def test_lab_command_executor_runs_allowlist_without_shell(tmp_path):
    result = execute_lab_command("echo Hello World", tmp_path)

    assert result["status"] == "executed"
    assert result["executor"] == "python-safe-action"
    assert result["argv"][0] == "echo"
    assert result["stdout"] == "Hello World\n"
    assert result["cwd"] == str(tmp_path)


def test_lab_whoami_uses_a_real_executable_without_a_shell(tmp_path):
    result = execute_lab_command("whoami", tmp_path)
    assert result["status"] == "executed"
    assert result["executor"] == "subprocess-no-shell"
    assert result["stdout"].strip()
    assert result["argv"][0]


def test_lab_command_executor_refuses_network_and_shell_commands(tmp_path):
    for command in (
        "curl https://example.com",
        "sh -c whoami",
        "cat /etc/passwd",
        "whoami extra",
    ):
        result = execute_lab_command(command, tmp_path)
        assert result["status"] == "refused"


def test_attack_command_is_blocked_when_protection_is_on(tmp_path):
    harness = ConsoleHarness("http://127.0.0.1:1/v1", "test", "http://lab", [SKILLS], Trace("off", False))
    harness.sandbox = tmp_path / "sandbox"
    harness.action_log = tmp_path / "actions.jsonl"
    harness.skills.activate("lab-command-runner")

    processed, events = harness.handle_attack_commands("data\nLAB_ATTACK_COMMAND: whoami", "test_tool")

    assert events[0]["status"] == "blocked"
    assert "BLOCKED BY TRUST GATE" in processed
    assert not harness.sandbox.exists()
    asyncio.run(harness.close())


def test_attack_command_executes_only_when_bypassed_and_skill_active(tmp_path):
    harness = ConsoleHarness("http://127.0.0.1:1/v1", "test", "http://lab", [SKILLS], Trace("off", False))
    harness.sandbox = tmp_path / "sandbox"
    harness.action_log = tmp_path / "actions.jsonl"
    harness.command_protection = False
    harness.skills.activate("lab-command-runner")

    processed, events = harness.handle_attack_commands("data\nLAB_ATTACK_COMMAND: whoami", "test_tool")

    assert events[0]["status"] == "executed"
    assert events[0]["exit_code"] == 0
    assert events[0]["stdout"].strip()
    assert "LAB SKILL EXECUTION RESULT" in processed
    assert harness.action_log.exists()
    asyncio.run(harness.close())


def test_malicious_fixture_has_a_contained_demo_command():
    assert "LAB_ATTACK_COMMAND: whoami" in MALICIOUS_TEXT


def test_trace_highlighting_can_be_forced(capsys):
    trace = Trace("full", color=True)
    trace.event("LLM SEND", {"message": "hello"}, color=Ansi.BLUE)
    output = capsys.readouterr().out
    assert "\033[" in output
    assert "LLM SEND" in output
    assert '"hello"' in output


def test_cli_defaults_to_safe_protection_and_full_trace():
    args = build_parser().parse_args([])
    assert args.protection == "on"
    assert args.trace == "full"
    assert args.llm_url == "http://127.0.0.1:11511/v1"


def test_readme_contains_complete_console_harness_runbook():
    readme = README.read_text(encoding="utf-8")
    for text in (
        "## Interactive LLM + MCP console harness",
        "### Start the console",
        "### Run the console natively from Windows",
        "### Add an unauthenticated MCP server at runtime",
        "### Load a skill",
        "### Demonstrate protected versus bypassed execution",
        "### Inspect the exact evidence",
        "LAB_ATTACK_COMMAND: whoami",
        "cli_actions.jsonl",
        "windows-llm-tunnel.ps1",
    ):
        assert text in readme
