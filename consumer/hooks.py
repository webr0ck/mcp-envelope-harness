"""fast-agent ToolRunnerHooks wiring for the trust gate.

Configured, NOT forked. In fast-agent's config, point the tool_runner hooks at:
    tool_runner:
      hooks:
        before_tool_call: "consumer/hooks.py:before_tool_call"
        after_tool_call:  "consumer/hooks.py:after_tool_call"
(seam: fast_agent/agents/tool_runner.py ~596-647). The tool result is an MCP
CallToolResult whose `.meta` carries the wire `_meta` envelope.

CAVEAT (documented, not worked around): fast-agent truncates large tool results
BEFORE after_tool_call and nulls structuredContent (mcp_agent.py:1907). Truncation
changes the bytes → content_hash would mismatch. So demo payloads MUST be small
(our fixture is one short text item) and MUST NOT rely on structuredContent. If you
enable large results, verification will (correctly, fail-closed) reject them.

fast-agent is not cloned in this environment; consumer/driver.py exercises these
SAME gate calls without the LLM loop. The security logic is identical; only the LLM
turn is stubbed.

Config via env: HARNESS_ANCHOR (pinned sub-CA PEM path, required),
HARNESS_LOG (verdict JSONL), HARNESS_REQUIRED_INTEGRITY (default 1),
HARNESS_REPLAY_STORE (durable sqlite replay-cache path; default per-instance in-memory).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from consumer.harness import TrustGate

_gate: TrustGate | None = None


def _get_gate() -> TrustGate:
    global _gate
    if _gate is None:
        anchor = os.environ["HARNESS_ANCHOR"]
        _gate = TrustGate(
            anchor,
            required_integrity=int(os.environ.get("HARNESS_REQUIRED_INTEGRITY", "1")),
            log_path=os.environ.get("HARNESS_LOG"),
            replay_store=os.environ.get("HARNESS_REPLAY_STORE") or None,
        )
    return _gate


def _result_to_dict(tool_result) -> dict:
    """Coerce an MCP CallToolResult (pydantic) OR a plain dict to {content, _meta}."""
    if isinstance(tool_result, dict):
        return tool_result
    # pydantic model_dump gives content list + meta; fast-agent puts wire _meta on .meta
    dumped = tool_result.model_dump(by_alias=True, exclude_none=False) if hasattr(tool_result, "model_dump") else {}
    meta = getattr(tool_result, "meta", None) or dumped.get("_meta") or dumped.get("meta") or {}
    return {"content": dumped.get("content", []), "_meta": meta}


REFUSE_ACTIONS = {"refuse", "refuse_privileged"}


def _redact_result(context, reason: str) -> None:
    """Replace the tool result's content with a fixed refusal stub so the poisoned
    bytes NEVER enter the LLM turn. Retains the verdict on the context for audit.

    Handles the dict shape the harness uses fully; a pydantic CallToolResult (real
    fast-agent) is redacted best-effort in place (content overwritten, structuredContent
    and _meta nulled). Fail-closed: if we can't rewrite content, blank it entirely.
    """
    stub = f"[trust-gate REFUSED ({reason or 'unverified'}): tool output withheld from the model]"
    res = getattr(context, "result", None)
    if isinstance(res, dict):
        res["content"] = [{"type": "text", "text": stub}]
        res.pop("structuredContent", None)
        res["_meta"] = {}
        return
    # pydantic-ish object (real fast-agent CallToolResult, not cloned here)
    try:
        item = res.content[0]
        if hasattr(item, "model_copy"):
            res.content = [item.model_copy(update={"text": stub})]
        elif hasattr(item, "text"):
            item.text = stub
            res.content = [item]
        else:
            res.content = []
    except Exception:
        try:
            res.content = []  # fail-closed: no content is safer than poisoned content
        except Exception:
            pass
    for attr in ("structuredContent", "meta"):
        if hasattr(res, attr):
            setattr(res, attr, None)


def after_tool_call(context):
    """Verify the returned envelope, update the Biba floor, and CONTAIN the result.

    On a refuse verdict (no/invalid envelope, content_hash_mismatch, rogue chain,
    replay, stale, or a Biba-floor drop below the required integrity) the untrusted
    content is REDACTED in place — replaced with a fixed stub — so the poisoned bytes
    never reach the LLM this turn. The verdict is stashed on the context for audit and
    so before_tool_call can also block any follow-on privileged tool via the floor.
    Returns the (contained) context so fast-agent continues its loop with a safe result.
    """
    gate = _get_gate()
    tool_name = getattr(context, "tool_name", None) or getattr(context, "tool", "unknown")
    result_id = getattr(context, "request_id", None) or getattr(context, "result_id", "unknown")
    result = _result_to_dict(getattr(context, "result", context))
    rec = gate.evaluate(result, case="fast-agent", tool_name=tool_name, result_id=result_id)
    setattr(context, "trust_verdict", rec)
    if rec["action"] in REFUSE_ACTIONS:
        _redact_result(context, rec.get("reason"))
    return context


def before_tool_call(context):
    """Biba floor enforcement: refuse a privileged tool if session_floor < required.

    Raises to abort the tool call — fail-closed. A tool's required integrity is read
    from context.required_integrity (default = gate.required_integrity).
    """
    gate = _get_gate()
    required = getattr(context, "required_integrity", gate.required_integrity)
    if gate.session_floor < required:
        raise PermissionError(
            f"Biba floor: session_floor={gate.session_floor} < required_integrity={required}; "
            f"refusing privileged tool {getattr(context, 'tool_name', '?')}"
        )
    return context
