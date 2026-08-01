"""Core scenario engine for the interactive trust-envelope manual lab.

This module deliberately reuses the harness producer and consumer:

* ``producer.signer.build_result`` creates the signed MCP-ish result.
* ``consumer.harness.TrustGate`` verifies it and applies the Biba floor.

The only special case is ``protection=off``. That is the vulnerable control arm:
the verifier is intentionally bypassed and the wire content is delivered unchanged.
It must never be confused with envelope enforcement.
"""
from __future__ import annotations

import copy
import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from consumer.harness import TrustGate
from mcp_trust_verifier import TRUST_ENVELOPE_KEY
from mcp_trust_verifier.jcs import jcs_signed_input, jcs_tool_result
from producer.signer import Pki, build_result

from manual_lab.constants import LAB_DECISION_META_KEY, MALICIOUS_TEXT


BENIGN_TEXT = (
    "Patch window approved for Saturday 02:00–04:00 UTC. "
    "No emergency actions are required."
)

REFUSAL_PREFIX = "[trust-gate REFUSED"
POISON_MARKERS = ("UNTRUSTED TOOL INSTRUCTION", "id_rsa", "evil.example")
ALLOWED_ENVELOPES = {"valid", "missing", "tampered", "rogue"}
ALLOWED_PROTECTION = {"enforce", "off"}
ALLOWED_ORIGINS = {"ui", "mcp"}
CONNECTOR_TOOL_NAMES = (
    "read_news",
    "list_pull_requests",
    "get_last_jira_ticket",
)


def payload_identity(content: str) -> dict[str, Any]:
    """Return a stable, human-checkable identity for one exact UTF-8 payload."""
    encoded = content.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    return {
        "id": f"sha256:{digest[:12]}",
        "sha256": digest,
        "utf8_bytes": len(encoded),
        "preview": content[:160],
    }


def config_identity(config: dict[str, Any]) -> dict[str, Any]:
    """Bind a UI result to the exact normalized configuration that produced it."""
    canonical = json.dumps(
        config,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return {
        "id": f"sha256:{digest[:12]}",
        "sha256": digest,
        "utf8_bytes": len(canonical),
        "payload": payload_identity(str(config.get("content", ""))),
    }


def decision_summary(consumer: dict[str, Any]) -> dict[str, Any]:
    """Translate verifier internals into a stable, explicit operator outcome."""
    action = str(consumer.get("action", "unknown"))
    reason = str(consumer.get("reason") or "integrity_floor_below_required")
    if action == "proceed":
        outcome = "allowed"
        headline = "ALLOWED — verified content met the integrity policy"
        explanation = (
            f"Verified integrity {consumer.get('integrity_rank')} met required integrity "
            f"{consumer.get('required_integrity')}."
        )
    elif action == "proceed_unverified":
        outcome = "bypassed"
        headline = "BYPASSED — payload delivered without verification"
        explanation = "Protection was disabled, so the trust envelope was not checked."
    else:
        outcome = "blocked"
        headline = "BLOCKED — payload withheld from the model"
        explanations = {
            "no_envelope": "Protection was enabled, but the MCP result had no trust envelope.",
            "chain_validation_failed": "Protection was enabled, but the signer did not chain to the pinned authority.",
            "signature_invalid": "Protection was enabled, but signature verification failed.",
            "replayed_envelope": "Protection was enabled, and this envelope identity had already been consumed.",
            "integrity_floor_below_required": (
                f"The accepted integrity flag was {consumer.get('session_floor')}; policy requires "
                f"at least {consumer.get('required_integrity')}."
            ),
        }
        explanation = explanations.get(
            reason,
            "Protection was enabled and the verifier rejected the result. " + reason,
        )
        if reason.startswith("content_hash_mismatch"):
            explanation = "Protection was enabled, but the received bytes did not match the signed content hash."
        elif reason.startswith("envelope_too_old"):
            explanation = "Protection was enabled, but the envelope was outside the accepted freshness window."
    return {
        "outcome": outcome,
        "headline": headline,
        "reason_code": reason,
        "explanation": explanation,
        "protection": consumer.get("protection"),
        "verdict": consumer.get("verdict"),
        "action": action,
        "integrity_rank": consumer.get("integrity_rank"),
        "session_floor": consumer.get("session_floor"),
        "required_integrity": consumer.get("required_integrity"),
        "content_withheld": bool(consumer.get("content_withheld")),
    }


SCENARIOS: dict[str, dict[str, Any]] = {
    "valid": {
        "title": "Valid signed result",
        "description": "Trusted content, valid envelope, protection enabled.",
        "content": BENIGN_TEXT,
        "trust_tier": 2,
        "required_integrity": 1,
        "envelope": "valid",
        "protection": "enforce",
        "expected_action": "proceed",
    },
    "malicious_blocked": {
        "title": "Malicious content blocked",
        "description": (
            "The envelope is cryptographically valid but authenticates rank 0. "
            "The privileged consumer requires rank 1, so the Biba floor refuses it."
        ),
        "content": MALICIOUS_TEXT,
        "trust_tier": 0,
        "required_integrity": 1,
        "envelope": "valid",
        "protection": "enforce",
        "expected_action": "refuse_privileged",
    },
    "malicious_no_envelope_unprotected": {
        "title": "Vulnerable control: poison passes",
        "description": (
            "No envelope and protection is OFF. Verification is bypassed, "
            "so the malicious bytes reach the model-side consumer."
        ),
        "content": MALICIOUS_TEXT,
        "trust_tier": 0,
        "required_integrity": 1,
        "envelope": "missing",
        "protection": "off",
        "expected_action": "proceed_unverified",
    },
    "malicious_no_envelope_protected": {
        "title": "Missing envelope blocked",
        "description": (
            "The same envelope-free malicious result with protection ON. "
            "Fail-closed verification returns no_envelope and redacts the content."
        ),
        "content": MALICIOUS_TEXT,
        "trust_tier": 0,
        "required_integrity": 1,
        "envelope": "missing",
        "protection": "enforce",
        "expected_action": "refuse",
    },
    "tampered_blocked": {
        "title": "Post-signing tamper blocked",
        "description": (
            "The producer signs a rank-2 result; the wire changes its content "
            "without changing the envelope. The consumer detects a hash mismatch."
        ),
        "content": BENIGN_TEXT,
        "trust_tier": 2,
        "required_integrity": 1,
        "envelope": "tampered",
        "protection": "enforce",
        "expected_action": "refuse",
    },
}


@dataclass(frozen=True)
class RunConfig:
    content: str
    trust_tier: int
    required_integrity: int
    envelope: str
    protection: str
    tool_name: str = "manual_response"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RunConfig":
        content = str(value.get("content", ""))
        if not content or len(content) > 20_000:
            raise ValueError("content must contain 1–20,000 characters")

        try:
            trust_tier = int(value.get("trust_tier", 0))
            required = int(value.get("required_integrity", 1))
        except (TypeError, ValueError) as exc:
            raise ValueError("trust_tier and required_integrity must be integers") from exc
        if not 0 <= trust_tier <= 4:
            raise ValueError("trust_tier must be between 0 and 4")
        if not 0 <= required <= 4:
            raise ValueError("required_integrity must be between 0 and 4")

        envelope = str(value.get("envelope", "valid"))
        protection = str(value.get("protection", "enforce"))
        if envelope not in ALLOWED_ENVELOPES:
            raise ValueError(f"envelope must be one of {sorted(ALLOWED_ENVELOPES)}")
        if protection not in ALLOWED_PROTECTION:
            raise ValueError(f"protection must be one of {sorted(ALLOWED_PROTECTION)}")

        tool_name = str(value.get("tool_name", "manual_response")).strip()
        if not tool_name or len(tool_name) > 100:
            raise ValueError("tool_name must contain 1–100 characters")
        return cls(content, trust_tier, required, envelope, protection, tool_name)


class ManualEnvelopeLab:
    """Generate, manipulate, verify, and record one response at a time."""

    def __init__(self, evidence_dir: str | Path):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        # The harness Pki intentionally gives leaf certificates a short 15-minute
        # lifetime. A long-running manual service must therefore NOT retain one signer
        # forever: after 15 minutes every "valid" result would correctly fail certificate
        # time validation. Each run mints a fresh lab PKI and records its exact anchor.
        self.anchor_path = self.evidence_dir / "latest_trusted_sub_ca.pem"
        self.producer_log = self.evidence_dir / "producer.jsonl"
        self.wire_log = self.evidence_dir / "wire.jsonl"
        self.consumer_log = self.evidence_dir / "consumer.jsonl"
        self.connector_config_path = self.evidence_dir / "connector_config.json"

    @staticmethod
    def scenario(name: str) -> dict[str, Any]:
        if name not in SCENARIOS:
            raise KeyError(name)
        return copy.deepcopy(SCENARIOS[name])

    @staticmethod
    def scenarios() -> dict[str, dict[str, Any]]:
        return copy.deepcopy(SCENARIOS)

    def connector_config(self) -> dict[str, Any]:
        if not self.connector_config_path.exists():
            raw_config = self.scenario("valid")
        else:
            raw_config = json.loads(self.connector_config_path.read_text(encoding="utf-8"))
        config = asdict(RunConfig.from_dict(raw_config))
        config["target_tools"] = self._target_tools(raw_config)
        return config

    def publish_connector_config(self, raw_config: dict[str, Any]) -> dict[str, Any]:
        config = asdict(RunConfig.from_dict(raw_config))
        config["target_tools"] = self._target_tools(raw_config)
        temporary = self.connector_config_path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(config, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(self.connector_config_path)
        return config

    @staticmethod
    def _target_tools(raw_config: dict[str, Any]) -> list[str]:
        requested = raw_config.get("target_tools", list(CONNECTOR_TOOL_NAMES))
        if not isinstance(requested, list) or not all(
            isinstance(tool_name, str) for tool_name in requested
        ):
            raise ValueError("target_tools must be a list of connector tool names")
        unknown = sorted(set(requested) - set(CONNECTOR_TOOL_NAMES))
        if unknown:
            raise ValueError(f"unknown target_tools: {unknown}")
        return [tool_name for tool_name in CONNECTOR_TOOL_NAMES if tool_name in requested]

    def _append(self, path: Path, value: dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, ensure_ascii=False) + "\n")

    @staticmethod
    def _first_text(result: dict[str, Any]) -> str:
        for item in result.get("content") or []:
            if item.get("type") == "text":
                return str(item.get("text", ""))
        return ""

    @staticmethod
    def _redacted(reason: str | None) -> str:
        return f"{REFUSAL_PREFIX} ({reason or 'integrity_floor'}): tool output withheld]"

    @staticmethod
    def _envelope_summary(result: dict[str, Any]) -> dict[str, Any]:
        meta = result.get("_meta") or {}
        if not meta:
            return {"present": False}
        envelope = next(iter(meta.values()), {})
        label = envelope.get("label") or {}
        binding = envelope.get("binding") or {}
        context = envelope.get("call_context") or {}
        sig = envelope.get("sig") or {}
        return {
            "present": True,
            "source": label.get("source"),
            "integrity_rank": label.get("integrity_rank"),
            "content_hash": binding.get("content_hash"),
            "nonce": binding.get("nonce"),
            "signed_at": binding.get("signed_at"),
            "tool_name": context.get("tool_name"),
            "result_id": context.get("result_id"),
            "server_id": context.get("server_id"),
            "algorithm": sig.get("alg"),
            "certificate_count": len(sig.get("x5c") or []),
        }

    @staticmethod
    def _crypto_evidence(result: dict[str, Any]) -> dict[str, Any]:
        """Return the exact deterministic bytes covered by the signature."""
        envelope = (result.get("_meta") or {}).get(TRUST_ENVELOPE_KEY)
        content_bytes = jcs_tool_result(
            content=result.get("content") or [],
            structured_content=result.get("structuredContent"),
        )
        evidence: dict[str, Any] = {
            "content_canonical_utf8": content_bytes.decode("utf-8"),
            "content_canonical_hex": content_bytes.hex(),
        }
        if not envelope:
            return {**evidence, "signed_input_utf8": None, "signature": None}
        binding = envelope["binding"]
        context = envelope["call_context"]
        signed_bytes = jcs_signed_input(
            label=envelope["label"],
            content_hash=binding["content_hash"],
            nonce=binding["nonce"],
            signed_at=binding["signed_at"],
            result_id=context["result_id"],
            tool_name=context["tool_name"],
            server_id=context["server_id"],
        )
        return {
            **evidence,
            "signed_input_utf8": signed_bytes.decode("utf-8"),
            "signed_input_hex": signed_bytes.hex(),
            "algorithm": envelope["sig"]["alg"],
            "signature": envelope["sig"]["value"],
            "certificate_chain_x5c": envelope["sig"]["x5c"],
        }

    def run(self, raw_config: dict[str, Any], *, origin: str = "ui") -> dict[str, Any]:
        if origin not in ALLOWED_ORIGINS:
            raise ValueError(f"origin must be one of {sorted(ALLOWED_ORIGINS)}")
        config = RunConfig.from_dict(raw_config)
        run_id = f"{origin}-{int(time.time())}-{secrets.token_hex(4)}"
        result_id = f"rid-{secrets.token_urlsafe(12)}"
        server_id = "manual-response-generator"
        content = [{"type": "text", "text": config.content}]

        trusted_pki = Pki(cn="Manual Lab Trusted")
        rogue_pki = Pki(cn="Manual Lab Rogue")
        run_anchor_path = self.evidence_dir / f"{run_id}-trusted-sub-ca.pem"
        run_anchor_path.write_bytes(trusted_pki.sub_ca_pem)
        # Convenience pointer for a human inspecting the most recent run. Verification
        # below uses the in-memory anchor from THIS run, so concurrent runs cannot cross.
        self.anchor_path.write_bytes(trusted_pki.sub_ca_pem)

        signer = rogue_pki if config.envelope == "rogue" else trusted_pki
        producer_result = build_result(
            signer,
            content,
            tool_name=config.tool_name,
            server_id=server_id,
            result_id=result_id,
            trust_tier=config.trust_tier,
        )
        if config.envelope == "missing":
            producer_result.pop("_meta", None)

        wire_result = copy.deepcopy(producer_result)
        manipulation = "none"
        if config.envelope == "tampered":
            manipulation = "content_changed_after_signing"
            wire_result["content"][0]["text"] = (
                "TAMPERED AFTER SIGNING\n" + wire_result["content"][0]["text"]
            )
        elif config.envelope == "missing":
            manipulation = "legacy_response_without_envelope"
        elif config.envelope == "rogue":
            manipulation = "signed_by_unpinned_rogue_ca"

        common = {
            "ts": time.time(),
            "run_id": run_id,
            "origin": origin,
            "result_id": result_id,
            "tool_name": config.tool_name,
            "anchor_path": str(run_anchor_path),
            "submitted_payload": payload_identity(config.content),
        }
        producer_record = {
            **common,
            "side": "producer",
            "trust_tier": config.trust_tier,
            "envelope_mode": config.envelope,
            "content": self._first_text(producer_result),
            "envelope": self._envelope_summary(producer_result),
            "exact_result": producer_result,
            "crypto": self._crypto_evidence(producer_result),
        }
        wire_record = {
            **common,
            "side": "wire",
            "manipulation": manipulation,
            "content": self._first_text(wire_result),
            "envelope": self._envelope_summary(wire_result),
            "exact_result": wire_result,
            "crypto": self._crypto_evidence(wire_result),
        }

        if config.protection == "off":
            consumer_record = {
                **common,
                "side": "consumer",
                "protection": "off",
                "verdict": "not_run",
                "reason": "verification_bypassed",
                "integrity_rank": None,
                "required_integrity": config.required_integrity,
                "session_floor": None,
                "action": "proceed_unverified",
                "delivered_text": self._first_text(wire_result),
            }
        else:
            gate = TrustGate(
                trusted_pki.sub_ca_pem,
                required_integrity=config.required_integrity,
            )
            verdict = gate.evaluate(
                wire_result,
                case="manual",
                tool_name=config.tool_name,
                result_id=result_id,
            )
            action = verdict["action"]
            reason = verdict.get("reason")
            if action == "refuse_privileged" and not reason:
                reason = "integrity_floor_below_required"
            delivered = (
                self._first_text(wire_result)
                if action == "proceed"
                else self._redacted(reason)
            )
            consumer_record = {
                **common,
                "side": "consumer",
                "protection": "enforce",
                **{k: v for k, v in verdict.items() if k not in {"ts", "case", "tool", "result_id"}},
                "reason": reason,
                "delivered_text": delivered,
            }

        poison_delivered = any(
            marker in consumer_record["delivered_text"] for marker in POISON_MARKERS
        )
        consumer_record["poison_delivered"] = poison_delivered
        consumer_record["content_withheld"] = consumer_record["delivered_text"].startswith(
            REFUSAL_PREFIX
        )
        consumer_record["delivered_payload"] = payload_identity(consumer_record["delivered_text"])
        decision = decision_summary(consumer_record)

        self._append(self.producer_log, producer_record)
        self._append(self.wire_log, wire_record)
        self._append(self.consumer_log, consumer_record)

        return {
            "run_id": run_id,
            "anchor_path": str(run_anchor_path),
            "config": asdict(config),
            "submission": config_identity(asdict(config)),
            "decision": decision,
            "producer": producer_record,
            "wire": wire_record,
            "consumer": consumer_record,
            "raw": {
                "producer_result": producer_result,
                "wire_result": wire_result,
            },
        }

    def recent_logs(self, limit: int = 25) -> dict[str, list[dict[str, Any]]]:
        safe_limit = max(1, min(int(limit), 200))

        def read(path: Path) -> list[dict[str, Any]]:
            if not path.exists():
                return []
            lines = path.read_text(encoding="utf-8").splitlines()[-safe_limit:]
            return [json.loads(line) for line in lines if line.strip()]

        return {
            "producer": read(self.producer_log),
            "wire": read(self.wire_log),
            "consumer": read(self.consumer_log),
        }
