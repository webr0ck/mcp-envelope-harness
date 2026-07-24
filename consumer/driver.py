"""No-LLM consumer driver: fetch a tool result over the wire, run it through the
SAME fast-agent hook functions (consumer.hooks.before_tool_call / after_tool_call)
the real agent would, and assert the security OUTCOME on the wire result.

fast-agent is NOT cloned into this environment, so the full LLM loop cannot run
offline. This driver wraps the wire-fetched result in a minimal `Ctx` (same dict
shape tests/test_hooks.py uses) and calls the identical hook entrypoints, so the
containment path under test is real: on a refuse verdict, after_tool_call REDACTS
ctx.result in place — the poisoned bytes are gone before any LLM turn. The driver
proves that on the wire, not just the verdict fields. Only the LLM turn is stubbed;
no faked pass.

Usage: python -m consumer.driver --case valid --url http://127.0.0.1:8899/tool \
         --anchor .run/sub_ca.pem --tool import_conversation --result-id rid-1 --log logs/verdicts.jsonl
Exit 0 iff the observed action matches the case's EXPECTED action AND (on refuse)
the poisoned content was actually redacted out of the wire result.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Markers of the injection payload in fixtures/poisoned_conversation.json. If ANY of
# these survives into ctx.result on a refuse verdict, containment failed.
POISON_MARKERS = ("SYSTEM OVERRIDE", "id_rsa", "evil.example")

# case -> (expected action, expected reason substring or None, required_integrity, producer query extras)
EXPECTED = {
    "valid":       ("proceed",  None,                      1, {"tier": "1"}),
    "mitm_tamper": ("refuse",   "content_hash_mismatch",   1, {"tier": "1"}),
    "rogue_cert":  ("refuse",   "chain_validation_failed", 1, {"tier": "1"}),
    "no_envelope": ("refuse",   "no_envelope",             1, {"tier": "1"}),
    "replay":      ("refuse",   "signature_invalid",       1, {"tier": "1"}),
    # verbatim replay: the SAME validly-signed envelope re-served on the wire (replay_cache
    # MITM) is accepted once, then refused by the consumer's per-session seen-cache.
    "replay_seen": ("refuse",   "replayed_envelope",       1, {"tier": "1"}),
    "stale":       ("refuse",   "envelope_too_old",        1, {"tier": "1", "stale": "1"}),
    # tier-0 advisory content: with no privileged action pending (required=0) it is
    # accepted and proceeds; the Layer B boundary rides in-band. (A required>=1 tool
    # would be refused by the Biba floor — see the biba test.)
    "layer_b":     ("proceed",  None,                      0, {"tier": "0", "layer_b": "1"}),
}


class Ctx:
    """Minimal stand-in for the fast-agent ToolRunnerHooks context. `.result` is the
    same dict shape the wire carries; after_tool_call mutates it in place on refuse."""

    def __init__(self, result, tool_name, result_id):
        self.result = result
        self.tool_name = tool_name
        self.request_id = result_id


def fetch(url, tool, result_id, extras):
    q = {"tool": tool, "result_id": result_id, "server_id": "anticlaw-producer", **extras}
    with urllib.request.urlopen(f"{url}?{urlencode(q)}", timeout=10) as r:
        return json.loads(r.read())["result"]


def _content_text(result) -> str:
    return " ".join(item.get("text", "") for item in (result.get("content") or []) if isinstance(item, dict))


def _run_hook(hooks, result, tool, result_id):
    """Drive one result through the real before/after hook seam; return (rec, ctx)."""
    ctx = Ctx(result, tool, result_id)
    # before_tool_call: Biba-floor entry guard (fail-closed if the session is already
    # tainted below the required integrity). At session start the floor is BIBA_TOP so
    # this passes; it is the same guard that blocks a privileged follow-on after a poisoned
    # read — exercising it here proves the seam the agent uses, not a stub.
    hooks.before_tool_call(ctx)
    hooks.after_tool_call(ctx)  # verify + taint + REDACT on refuse (in place on ctx.result)
    return ctx.trust_verdict, ctx


def _redaction_ok(action, ctx) -> tuple[bool, str]:
    """On a refuse action the poisoned bytes MUST be gone and the stub present.
    On proceed the original content passes through untouched."""
    txt = _content_text(ctx.result)
    if action in ("refuse", "refuse_privileged"):
        leaked = [m for m in POISON_MARKERS if m in txt]
        if leaked:
            return False, f"CONTAINMENT FAILED: poisoned marker(s) {leaked} survived redaction"
        if "REFUSED" not in txt:
            return False, "redaction stub missing (expected '[trust-gate REFUSED ...]')"
    return True, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True, choices=list(EXPECTED))
    ap.add_argument("--url", required=True)
    ap.add_argument("--anchor", required=True)
    ap.add_argument("--tool", default="import_conversation")
    ap.add_argument("--result-id", default="rid-1")
    ap.add_argument("--required-integrity", type=int, default=None,
                    help="override the case's default required integrity")
    ap.add_argument("--log", default=str(Path(__file__).resolve().parent.parent / "logs" / "verdicts.jsonl"))
    ap.add_argument("--replay-store", default=str(Path(__file__).resolve().parent.parent / ".run" / "replay_cache.db"),
                    help="durable sqlite replay cache shared across consumer processes; "
                         "run_demo.sh clears it once at start so reruns stay green")
    args = ap.parse_args()

    exp_action, exp_reason, req_int, extras = EXPECTED[args.case]
    if args.required_integrity is not None:
        req_int = args.required_integrity

    # The hook seam builds its gate from env (matching the real fast-agent config path).
    # Set env BEFORE importing/using hooks so _get_gate() picks up this case's settings.
    os.environ["HARNESS_ANCHOR"] = str(args.anchor)
    os.environ["HARNESS_LOG"] = str(args.log)
    os.environ["HARNESS_REQUIRED_INTEGRITY"] = str(req_int)
    os.environ["HARNESS_REPLAY_STORE"] = str(args.replay_store)
    import consumer.hooks as hooks
    hooks._gate = None  # fresh gate bound to this case's env

    if args.case == "replay_seen":
        # Two real round-trips through the replay_cache MITM (identical envelope on the
        # wire), one consumer session (one gate, shared across both hook calls): 1st must
        # proceed with content intact, 2nd must be refused as a replay AND redacted.
        r1 = fetch(args.url, args.tool, args.result_id, extras)
        first, ctx1 = _run_hook(hooks, r1, args.tool, args.result_id)
        r2 = fetch(args.url, args.tool, args.result_id, extras)
        rec, ctx2 = _run_hook(hooks, r2, args.tool, args.result_id)
        red_ok, red_msg = _redaction_ok(rec["action"], ctx2)
        # 1st must have passed poisoned-but-signed content through untouched (accepted)
        first_intact = "SYSTEM OVERRIDE" in _content_text(ctx1.result)
        ok = (first["action"] == "proceed" and first_intact
              and rec["action"] == exp_action
              and (rec["reason"] or "").startswith(exp_reason)
              and red_ok)
        print(f"[replay_seen] 1st: action={first['action']} intact={first_intact} | "
              f"2nd: action={rec['action']} reason={rec['reason']} redacted={red_ok} "
              f"-> {'PASS' if ok else 'FAIL ' + red_msg}")
        sys.exit(0 if ok else 1)

    result = fetch(args.url, args.tool, args.result_id, extras)
    rec, ctx = _run_hook(hooks, result, args.tool, args.result_id)

    ok = rec["action"] == exp_action and (exp_reason is None or (rec["reason"] or "").startswith(exp_reason))
    red_ok, red_msg = _redaction_ok(rec["action"], ctx)
    ok = ok and red_ok
    # layer_b (proceed): the advisory boundary must ride in the passed-through content
    if args.case == "layer_b" and "LAYER-B-UNTRUSTED" not in _content_text(ctx.result):
        ok = False
        red_msg = "advisory boundary missing from content"
    print(f"[{args.case}] action={rec['action']} reason={rec['reason']} rank={rec['integrity_rank']} "
          f"floor={rec['session_floor']} redacted_ok={red_ok} -> "
          f"{'PASS' if ok else 'FAIL ' + (red_msg or 'want %s/%s' % (exp_action, exp_reason))}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
