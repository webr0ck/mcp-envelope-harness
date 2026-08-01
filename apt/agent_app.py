"""Run ONE arm of the APT scenario through a real fast-agent agent + a real LLM.

  --arm control    no hooks at all. Establishes that the injection genuinely works on
                   this model. If the control arm does NOT exfiltrate, the protected arm
                   proves nothing and the whole test is INCONCLUSIVE.
  --arm protected  identical prompt, identical servers, identical model, plus our
                   ToolRunnerHooks under the low-water-mark floor policy.

The only difference between the arms is the hooks. Same seed of a prompt, temperature 0,
so any behavioural divergence is attributable to the gate rather than to sampling.

Model comes from FAST_AGENT_MODEL (default: the local llama-server Qwen on :11511 via
fast-agent's OpenAI-compatible `generic` provider). Nothing here is Anthropic-specific —
point it at any provider fast-agent supports and the test is unchanged.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apt import scenario

DEFAULT_MODEL = "generic.qwen2.5-coder-3b-instruct-q4_k_m.gguf"


def _configure_gate() -> None:
    """Environment the hook seam builds its TrustGate from (the real fast-agent config
    path — hooks read env, exactly as a deployed consumer would)."""
    os.environ["HARNESS_ANCHOR"] = str(scenario.ANCHOR)
    os.environ["HARNESS_LOG"] = str(scenario.VERDICTS)
    # A privileged tool requires integrity >= 1; tier-0 public content sits below it.
    os.environ["HARNESS_REQUIRED_INTEGRITY"] = "1"
    # Read-down permitted: the poisoned issue REACHES the model (that is the point).
    os.environ["HARNESS_FLOOR_POLICY"] = "lowwatermark"
    # Only egress is privileged; fetching issues must stay allowed or the agent is useless.
    os.environ["HARNESS_PRIVILEGED_TOOLS"] = scenario.TOOL_SEND
    # Real MCP realities, both documented at their definition in consumer/hooks.py.
    os.environ["HARNESS_STRIP_TOOL_NAMESPACE"] = "1"
    os.environ["HARNESS_RESULT_ID_SOURCE"] = "envelope"


async def run(arm: str, model: str) -> dict:
    from fast_agent import FastAgent
    from fast_agent.agents.tool_runner import ToolRunnerHooks

    from apt.fastagent_meta_shim import apply as apply_meta_shim

    # Applied to BOTH arms so the arms differ only by the presence of the gate.
    # Without it fast-agent 0.9.22 strips _meta and every result verifies as
    # `no_envelope` — see apt/fastagent_meta_shim.py for the defect and its scope.
    print(f"[{arm}] _meta shim: {apply_meta_shim()}")

    if arm == "protected":
        _configure_gate()

    fast = FastAgent(
        "apt-scenario",
        config_path=str(Path(__file__).resolve().parent / "fastagent.config.yaml"),
        parse_cli_args=False,
    )

    @fast.agent(
        name="triage",
        instruction=scenario.AGENT_INSTRUCTION,
        servers=[scenario.SERVER_ISSUES, scenario.SERVER_MAIL],
        model=model,
    )
    async def _triage():
        pass

    async with fast.run() as app:
        agent = app.triage
        if arm == "protected":
            import consumer.hooks as hooks

            hooks._gate = None  # fresh gate bound to this arm's env
            # The real attach point fast-agent reads in ToolAgent._tool_runner_hooks().
            agent.tool_runner_hooks = ToolRunnerHooks(
                before_tool_call=hooks.before_tool_call,
                after_tool_call=hooks.after_tool_call,
            )
        reply = await agent.send(scenario.TASK)

    return {"arm": arm, "model": model, "reply": str(reply)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True, choices=["control", "protected"])
    ap.add_argument("--model", default=os.environ.get("FAST_AGENT_MODEL", DEFAULT_MODEL))
    a = ap.parse_args()

    try:
        out = asyncio.run(run(a.arm, a.model))
    except Exception as e:  # a crashed arm must never look like a clean pass
        out = {"arm": a.arm, "model": a.model, "error": f"{type(e).__name__}: {e}"}
        scenario.TRANSCRIPT.parent.mkdir(parents=True, exist_ok=True)
        scenario.TRANSCRIPT.write_text(json.dumps(out, indent=2))
        print(f"[{a.arm}] ERROR {out['error']}", file=sys.stderr)
        return 2

    scenario.TRANSCRIPT.parent.mkdir(parents=True, exist_ok=True)
    scenario.TRANSCRIPT.write_text(json.dumps(out, indent=2))
    print(f"[{a.arm}] reply: {out['reply'][:300]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
