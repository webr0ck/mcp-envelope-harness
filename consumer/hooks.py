"""fast-agent ToolRunnerHooks wiring for the trust gate — REAL contract.

These are conformant `fast_agent.agents.tool_runner.ToolRunnerHooks` callbacks:
both are **async** and **two-arg** `(runner: ToolRunner, message: PromptMessageExtended)`
and are `await`ed by fast-agent (tool_runner.py `generate_tool_call_response`,
~596-647). The tool result is an `mcp.types.CallToolResult` in
`message.tool_results` (dict keyed by tool-call id); the wire `_meta` envelope
rides on each result's `.meta`. Register with:

    from fast_agent.agents.tool_runner import ToolRunnerHooks
    from consumer import hooks
    ToolRunnerHooks(before_tool_call=hooks.before_tool_call,
                    after_tool_call=hooks.after_tool_call)

CONTAINMENT PROPERTY: on a refuse verdict (no/invalid envelope, content_hash_mismatch,
rogue chain, replay, stale, or a Biba-floor drop below required integrity) the
untrusted `CallToolResult` is REDACTED IN PLACE — content replaced with a fixed
stub, structuredContent + _meta nulled — so the poisoned bytes never reach the next
LLM turn. fast-agent uses the SAME mutated `message` object for the model turn, so
mutating in place is the redaction. The verdicts are stashed on the runner
(`runner.trust_verdicts`) for audit; every verdict is also one JSONL line via the gate.

Why async and why mutate-in-place (not raise): fast-agent CATCHES any exception from
after_tool_call and continues with the ORIGINAL result (tool_runner.py ~639) = fail-OPEN.
A conformant hook must therefore NOT rely on raising to contain — it neuters the result
in place and returns normally. before_tool_call raising IS fail-closed there: fast-agent
turns it into a tool error response, so the privileged tool never runs.

CAVEAT (documented, not worked around): fast-agent truncates large tool results and
nulls structuredContent before after_tool_call in some paths. Truncation changes the
bytes → content_hash would mismatch. Demo payloads MUST be small (our fixture is one
short text item) and MUST NOT rely on structuredContent.

Config via env: HARNESS_ANCHOR (pinned sub-CA PEM path, required),
HARNESS_LOG (verdict JSONL), HARNESS_REQUIRED_INTEGRITY (default 1),
HARNESS_REPLAY_STORE (durable sqlite replay-cache path; default per-instance in-memory).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_trust_verifier import TRUST_ENVELOPE_KEY

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


REFUSE_ACTIONS = {"refuse", "refuse_privileged"}

# Which Biba variant the consumer enforces. Both are real policies; they differ only in
# what happens to content that VERIFIED FINE but sits below the session's required
# integrity (`refuse_privileged`).
#
#   strict (default)  — no read-down. Low-integrity content is redacted too: the model
#                       never sees it. Safest, but an agent under it can never read a
#                       public web page / issue / inbox at all.
#   lowwatermark      — read-down allowed; absorbing the source lowers session_floor
#                       (Biba low-water-mark), and before_tool_call then denies the
#                       privileged tool. The injection reaches the model; the CAPABILITY
#                       to act on it is gone. This is the APT scenario (apt/README.md).
#
# Unverified content (`refuse` — tampered, rogue chain, replayed, stale, no envelope) is
# redacted under BOTH policies. A typo degrades to strict, never to silently permissive.
_FLOOR_POLICIES = {"strict": REFUSE_ACTIONS, "lowwatermark": {"refuse"}}


def _redact_actions() -> set:
    return _FLOOR_POLICIES.get(os.environ.get("HARNESS_FLOOR_POLICY", "strict"), REFUSE_ACTIONS)


def _result_to_dict(tool_result) -> dict:
    """Coerce an MCP CallToolResult (pydantic) OR a plain dict to {content, _meta}."""
    if isinstance(tool_result, dict):
        return tool_result
    # exclude_none: pydantic re-adds `annotations:None, _meta:None` to each content item;
    # those absent-in-source keys would change the JCS canonical bytes and break the
    # content_hash for an otherwise-valid result. Drop them to match what the signer signed.
    dumped = (
        tool_result.model_dump(by_alias=True, exclude_none=True)
        if hasattr(tool_result, "model_dump")
        else {}
    )
    meta = getattr(tool_result, "meta", None) or dumped.get("_meta") or dumped.get("meta") or {}
    out = {"content": dumped.get("content", []), "_meta": meta}
    if dumped.get("structuredContent") is not None:
        out["structuredContent"] = dumped["structuredContent"]
    return out


def _redact_call_tool_result(ctr, reason: str) -> None:
    """Replace a CallToolResult's content with a fixed refusal stub, in place, so the
    poisoned bytes NEVER enter the LLM turn. structuredContent + _meta nulled. Fail-closed:
    if we can't rewrite content, blank it entirely (no content is safer than poison)."""
    stub = f"[trust-gate REFUSED ({reason or 'unverified'}): tool output withheld from the model]"
    if isinstance(ctr, dict):  # tolerate a raw dict (legacy path / defensive)
        ctr["content"] = [{"type": "text", "text": stub}]
        ctr.pop("structuredContent", None)
        ctr["_meta"] = {}
        return
    try:
        from mcp.types import TextContent

        ctr.content = [TextContent(type="text", text=stub)]
    except Exception:
        try:
            ctr.content = []
        except Exception:
            pass
    for attr in ("structuredContent", "meta"):
        if hasattr(ctr, attr):
            try:
                setattr(ctr, attr, None)
            except Exception:
                pass


def _contain(ctr, *, tool_name: str, result_id: str) -> dict:
    """Verify one CallToolResult, update the Biba floor, and REDACT it in place on a
    refuse verdict. Returns the gate record. This is the shared core both hooks and
    any driver route through — the single seam where poison is contained."""
    gate = _get_gate()
    rec = gate.evaluate(
        _result_to_dict(ctr), case="fast-agent", tool_name=tool_name, result_id=result_id
    )
    if rec["action"] in _redact_actions():
        _redact_call_tool_result(ctr, rec.get("reason"))
    return rec


def _local_tool_name(name: str) -> str:
    """Strip fast-agent's `server__tool` namespacing (fast_agent.mcp.common.SEP).

    Over REAL MCP the model calls `issue_tracker__fetch_issue`, but the server signed
    the envelope over its own local tool name (`fetch_issue`) — it has no idea what the
    client namespaced it to. The signature binds the local name, so we must verify
    against that or every real-MCP result would fail signature_invalid.
    Only active under HARNESS_STRIP_TOOL_NAMESPACE=1 so the 8-case demo is untouched."""
    if os.environ.get("HARNESS_STRIP_TOOL_NAMESPACE") != "1":
        return name
    return name.split("__", 1)[1] if "__" in name else name


def _result_id_for(ctr, call_id: str) -> str:
    """Which result_id to verify against.

    consumer (default) — the consumer's own id. Strongest: a valid envelope lifted onto
        a different call fails signature. Requires the producer to KNOW the id.
    envelope — take the id from the signed call_context hint.

    Why `envelope` has to exist: over real MCP the server cannot learn the client's
    tool-call id. The transport channel for it (CallToolRequestParams._meta) exists in
    the MCP SDK, but fast-agent's aggregator does NOT forward a per-call `meta` to
    session.call_tool (mcp_aggregator.call_tool, 0.9.22), so there is no stock way to
    hand the producer a consumer-minted nonce.

    COST, stated plainly: under `envelope` the result_id is server-supplied, so it no
    longer pins the envelope to THIS call. Tamper is still caught (content_hash) and
    verbatim replay is still caught (the nonce seen-cache), but cross-call envelope
    lifting is not. Closing it needs an upstream fast-agent change, not a workaround here.
    """
    if os.environ.get("HARNESS_RESULT_ID_SOURCE", "consumer") != "envelope":
        return call_id
    meta = getattr(ctr, "meta", None) or {}
    if isinstance(ctr, dict):
        meta = ctr.get("_meta") or {}
    env = (meta or {}).get(TRUST_ENVELOPE_KEY) or {}
    return (env.get("call_context") or {}).get("result_id") or call_id


def _tool_name_for(runner, call_id: str) -> str:
    """Resolve the tool name for a result from the originating request the runner holds
    (the authoritative source; the signature binds it, so a spoofed name fails verify)."""
    req = getattr(runner, "_pending_tool_request", None)
    calls = getattr(req, "tool_calls", None) or {}
    call = calls.get(call_id)
    params = getattr(call, "params", None)
    return getattr(params, "name", None) or "unknown"


async def after_tool_call(runner, message) -> None:
    """REAL fast-agent hook: verify every tool result, CONTAIN on refuse before the model turn.

    Async two-arg, awaited by fast-agent. Mutates each poisoned CallToolResult in
    `message.tool_results` in place (fail-open safe — never raises). Verdicts are stashed
    on `runner.trust_verdicts` for audit."""
    verdicts = []
    for call_id, ctr in (getattr(message, "tool_results", None) or {}).items():
        verdicts.append(
            _contain(
                ctr,
                tool_name=_local_tool_name(_tool_name_for(runner, call_id)),
                result_id=_result_id_for(ctr, call_id),
            )
        )
    try:
        runner.trust_verdicts = verdicts
    except Exception:
        pass


def _requested_tool_names(request) -> list[str]:
    """Tool names the model is asking to call this turn."""
    out = []
    for call in (getattr(request, "tool_calls", None) or {}).values():
        name = getattr(getattr(call, "params", None), "name", None)
        if name:
            # Namespaced over real MCP (`mailer__send_report`); the privileged-tool list
            # is written in local names, so normalise here too or nothing ever matches.
            out.append(_local_tool_name(name))
    return out


def _is_privileged(tool_name: str) -> bool:
    """HARNESS_PRIVILEGED_TOOLS is a comma-list of the tools that require integrity.
    UNSET = every tool is privileged (fail-closed default, and what the 8-case demo
    assumes). An empty-but-set value also means 'all' — never 'none'."""
    spec = os.environ.get("HARNESS_PRIVILEGED_TOOLS", "").strip()
    if not spec:
        return True
    return tool_name in {t.strip() for t in spec.split(",") if t.strip()}


async def before_tool_call(runner, request) -> None:
    """REAL fast-agent hook: refuse a privileged tool if the Biba session floor dropped
    below required integrity. Raising here is fail-closed — fast-agent turns it into a
    tool error response, so the privileged tool never runs.

    Note the asymmetry that makes the APT scenario work: reading an untrusted source is
    permitted (it only lowers the floor), but the privileged call that the injected text
    is trying to provoke is denied. The model can be persuaded; it cannot act."""
    gate = _get_gate()
    if gate.session_floor >= gate.required_integrity:
        return
    names = _requested_tool_names(request)
    blocked = [n for n in names if _is_privileged(n)] or ([] if names else ["<unknown>"])
    if not blocked:
        return  # only unprivileged tools this turn — reading down is allowed
    # Durable evidence that the model ATTEMPTED the privileged call and was denied.
    # Without this line a blocked run and a run where the model never took the bait
    # look identical from the outside — which would make the APT test vacuous.
    if gate.log_path:
        import json

        with open(gate.log_path, "a") as f:
            f.write(
                json.dumps({
                    "ts": time.time(), "event": "privileged_denied",
                    "tools": blocked, "session_floor": gate.session_floor,
                    "required_integrity": gate.required_integrity,
                }) + "\n"
            )
    raise PermissionError(
        f"Biba floor: session_floor={gate.session_floor} < "
        f"required_integrity={gate.required_integrity}; refusing privileged tool(s) "
        f"{','.join(blocked)}"
    )
