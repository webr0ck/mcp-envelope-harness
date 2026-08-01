"""Org B consumer and the comparative cross-boundary acceptance oracle."""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from consumer.harness import TrustGate
from federation.protocol import TOOL_NAME

CANARY = "FEDERATION-CANARY"
REQUIRED_INTEGRITY = 1


def fetch(base_url: str, **query) -> dict:
    url = f"{base_url.rstrip('/')}/result?{urlencode(query)}"
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read())["result"]


def unsigned_decision(result: dict, *, default_rank: int) -> dict:
    """Model the two possible static policies for results with no envelope.

    The server identity is the same in both cases, so a static receiver can either
    trust every result or distrust every result. It cannot distinguish Org A-authored
    internal data from public-writable data returned by that server.
    """
    floor = min(4, default_rank)
    return {
        "verdict": "unverified",
        "reason": f"unsigned_default_rank_{default_rank}",
        "integrity_rank": default_rank,
        "session_floor": floor,
        "action": "proceed" if floor >= REQUIRED_INTEGRITY else "refuse_privileged",
        "has_meta": False,
    }


def signed_decision(result: dict, *, anchor: Path, result_id: str, case: str) -> dict:
    gate = TrustGate(anchor, required_integrity=REQUIRED_INTEGRITY)
    return gate.evaluate(result, case=case, tool_name=TOOL_NAME, result_id=result_id)


def _attempt_report(sink: list[dict], decision: dict, *, purpose: str, body: str) -> bool:
    if decision["action"] != "proceed":
        return False
    sink.append({"purpose": purpose, "body": body})
    return True


def run(relay_url: str, anchor: Path) -> dict:
    sink: list[dict] = []
    cases: list[dict] = []

    unsigned_public = fetch(
        relay_url,
        kind="public",
        signed="0",
        result_id="unsigned-public",
        relay_mode="passthrough",
    )
    decision = unsigned_decision(unsigned_public, default_rank=2)
    executed = _attempt_report(sink, decision, purpose="attack", body=CANARY)
    cases.append({
        "case": "unsigned_default_trusted_public",
        "expected": "unsafe",
        "decision": decision,
        "report_executed": executed,
        "pass": executed and any(item["body"] == CANARY for item in sink),
    })

    unsigned_internal = fetch(
        relay_url,
        kind="internal",
        signed="0",
        result_id="unsigned-internal",
        relay_mode="passthrough",
    )
    decision = unsigned_decision(unsigned_internal, default_rank=0)
    executed = _attempt_report(
        sink, decision, purpose="legitimate", body="Org A status delivered"
    )
    cases.append({
        "case": "unsigned_default_untrusted_internal",
        "expected": "unusable",
        "decision": decision,
        "report_executed": executed,
        "pass": not executed,
    })

    signed_internal = fetch(
        relay_url,
        kind="internal",
        signed="1",
        result_id="signed-internal",
        relay_mode="passthrough",
    )
    decision = signed_decision(
        signed_internal,
        anchor=anchor,
        result_id="signed-internal",
        case="federation_signed_internal",
    )
    executed = _attempt_report(
        sink, decision, purpose="legitimate", body="Org A status delivered"
    )
    cases.append({
        "case": "signed_internal",
        "expected": "legitimate_action_allowed",
        "decision": decision,
        "report_executed": executed,
        "pass": executed and decision["integrity_rank"] == 2,
    })

    signed_public = fetch(
        relay_url,
        kind="public",
        signed="1",
        result_id="signed-public",
        relay_mode="passthrough",
    )
    decision = signed_decision(
        signed_public,
        anchor=anchor,
        result_id="signed-public",
        case="federation_signed_public",
    )
    executed = _attempt_report(sink, decision, purpose="attack", body=CANARY)
    cases.append({
        "case": "signed_public",
        "expected": "poison_ingested_but_action_blocked",
        "decision": decision,
        "report_executed": executed,
        "pass": (
            not executed
            and decision["verdict"] == "accepted"
            and decision["integrity_rank"] == 0
            and decision["action"] == "refuse_privileged"
        ),
    })

    raised_public = fetch(
        relay_url,
        kind="public",
        signed="1",
        result_id="raised-public",
        relay_mode="raise_rank",
    )
    decision = signed_decision(
        raised_public,
        anchor=anchor,
        result_id="raised-public",
        case="federation_relay_rank_raise",
    )
    executed = _attempt_report(sink, decision, purpose="attack", body=CANARY)
    cases.append({
        "case": "relay_raises_rank",
        "expected": "tampering_rejected",
        "decision": decision,
        "report_executed": executed,
        "pass": (
            not executed
            and decision["verdict"] == "rejected"
            and decision["action"] == "refuse"
        ),
    })

    return {
        "claim": (
            "A static server-level default cannot both allow Org A internal results "
            "and contain public-writable results from the same server; an authenticated "
            "per-result label can."
        ),
        "cases": cases,
        "sink": sink,
        "all_passed": all(case["pass"] for case in cases),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Org B comparative consumer")
    parser.add_argument("--relay-url", required=True)
    parser.add_argument("--anchor", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()

    evidence = run(args.relay_url, Path(args.anchor))
    path = Path(args.evidence)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    for case in evidence["cases"]:
        decision = case["decision"]
        status = "PASS" if case["pass"] else "FAIL"
        print(
            f"[{status}] {case['case']}: {case['expected']} | "
            f"verdict={decision['verdict']} action={decision['action']} "
            f"reason={decision.get('reason')}"
        )
    print(f"evidence: {path}")
    return 0 if evidence["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
