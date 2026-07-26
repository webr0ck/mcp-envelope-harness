"""No-LLM consumer driver: fetch a tool result over the wire, run it through the REAL
fast-agent ToolRunner (consumer.fastagent_runner) with our conformant hooks, and assert
the security OUTCOME on the wire result.

fast-agent-mcp IS installed now, so `fast_agent.agents.tool_runner.ToolRunner` itself
awaits our async two-arg after_tool_call; only the LLM is stubbed (a fake agent returns
the wire-fetched result). On a refuse verdict, after_tool_call REDACTS the CallToolResult
in place — the poisoned bytes are gone before any model turn. The driver proves that on
the wire, not just the verdict fields. No faked pass.

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


def fetch(url, tool, result_id, extras):
    q = {"tool": tool, "result_id": result_id, "server_id": "anticlaw-producer", **extras}
    with urllib.request.urlopen(f"{url}?{urlencode(q)}", timeout=10) as r:
        return json.loads(r.read())["result"]


def _run_hook(result, tool, result_id):
    """Drive one wire result through the REAL fast-agent ToolRunner (before_tool_call →
    run_tools → await after_tool_call); return (rec, contained_text). The gate is the
    module singleton, so session_floor + replay cache persist across calls in this process."""
    from consumer.fastagent_runner import contained_text, run_through_fastagent

    msg, verdicts = run_through_fastagent(result, tool_name=tool, result_id=result_id)
    return verdicts[0], contained_text(msg, result_id)


def _redaction_ok(action, txt) -> tuple[bool, str]:
    """On a refuse action the poisoned bytes MUST be gone and the stub present.
    On proceed the original content passes through untouched."""
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
        first, txt1 = _run_hook(r1, args.tool, args.result_id)
        r2 = fetch(args.url, args.tool, args.result_id, extras)
        rec, txt2 = _run_hook(r2, args.tool, args.result_id)
        red_ok, red_msg = _redaction_ok(rec["action"], txt2)
        # 1st must have passed poisoned-but-signed content through untouched (accepted)
        first_intact = "SYSTEM OVERRIDE" in txt1
        ok = (first["action"] == "proceed" and first_intact
              and rec["action"] == exp_action
              and (rec["reason"] or "").startswith(exp_reason)
              and red_ok)
        print(f"[replay_seen] 1st: action={first['action']} intact={first_intact} | "
              f"2nd: action={rec['action']} reason={rec['reason']} redacted={red_ok} "
              f"-> {'PASS' if ok else 'FAIL ' + red_msg}")
        sys.exit(0 if ok else 1)

    result = fetch(args.url, args.tool, args.result_id, extras)
    rec, txt = _run_hook(result, args.tool, args.result_id)

    ok = rec["action"] == exp_action and (exp_reason is None or (rec["reason"] or "").startswith(exp_reason))
    red_ok, red_msg = _redaction_ok(rec["action"], txt)
    ok = ok and red_ok
    # layer_b (proceed): the advisory boundary must ride in the passed-through content
    if args.case == "layer_b" and "LAYER-B-UNTRUSTED" not in txt:
        ok = False
        red_msg = "advisory boundary missing from content"
    print(f"[{args.case}] action={rec['action']} reason={rec['reason']} rank={rec['integrity_rank']} "
          f"floor={rec['session_floor']} redacted_ok={red_ok} -> "
          f"{'PASS' if ok else 'FAIL ' + (red_msg or 'want %s/%s' % (exp_action, exp_reason))}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
