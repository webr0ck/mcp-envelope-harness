"""Consumer trust gate: verify (shipped wheel) + Biba integrity floor + decide.

This is the seam the fast-agent ToolRunnerHooks plug into. It does NOT reimplement
crypto — it calls mcp_trust_verifier.TrustVerifier. It maintains a Biba session
floor: a consumer is only as trusted as its lowest-integrity accepted source, and
refuses a privileged tool when session_floor < required_integrity. Fail-closed:
no/!accepted envelope → rank 0, floor untouched, privileged action refused.

Every decision is one JSONL line: {case, tool, verdict, reason, integrity_rank, action, session_floor}.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path

from mcp_trust_verifier import TRUST_ENVELOPE_KEY, TrustVerifier
from mcp_trust_verifier.verifier import MAX_ENVELOPE_AGE_SECONDS

BIBA_TOP = 4  # system — fully trusted starting floor


class _MemStore:
    """Single-use envelope cache, in-process. Isolated per gate instance — the right
    default for tests and a single short-lived consumer. Does NOT survive restart or
    span instances; pass a `replay_store` path for that (_SqliteStore)."""

    def __init__(self):
        self._d: dict[tuple, float] = {}

    def check_and_add(self, key: tuple, expiry: float, now: float) -> bool:
        self._d = {k: e for k, e in self._d.items() if e > now}
        if key in self._d:
            return True
        self._d[key] = expiry
        return False


class _SqliteStore:
    """Durable, cross-instance single-use envelope cache (sqlite file).

    Survives consumer restart and is SHARED by any consumer pointed at the same file - closing the replay window across a gateway/agent fleet, not just within one process.
    `BEGIN IMMEDIATE` takes the write lock before the read so two instances racing the
    same new envelope can't both accept it (one blocks, then sees it already recorded).
    TTL-pruned each call; the verifier age-rejects anything older before it reaches here.
    """

    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._con() as c:
            c.execute("CREATE TABLE IF NOT EXISTS seen (k TEXT PRIMARY KEY, exp REAL)")
            c.execute("PRAGMA journal_mode=WAL")

    def _con(self):
        return sqlite3.connect(self.path, timeout=5)

    def check_and_add(self, key: tuple, expiry: float, now: float) -> bool:
        k = "\x00".join(map(str, key))
        with self._con() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("DELETE FROM seen WHERE exp <= ?", (now,))
            if c.execute("SELECT 1 FROM seen WHERE k = ?", (k,)).fetchone():
                return True
            c.execute("INSERT INTO seen (k, exp) VALUES (?, ?)", (k, expiry))
            return False


class TrustGate:
    def __init__(self, anchor_pem_path, *, required_integrity=1, log_path=None, replay_store=None):
        # accept a Path/str filepath or raw PEM (bytes/str with -----BEGIN)
        self.verifier = TrustVerifier.from_pem(
            anchor_pem_path if isinstance(anchor_pem_path, bytes) else str(anchor_pem_path)
        )
        self.required_integrity = required_integrity
        self.session_floor = BIBA_TOP
        # Anti-replay: a validly-signed envelope is single-use per call identity. The
        # signer stamps a fresh binding.nonce per signing, so (tool_name, result_id, nonce)
        # uniquely names one envelope; re-presenting it (verbatim replay by a MITM) must be
        # refused even though the crypto still verifies. TTL-bounded by the same freshness
        # window the verifier enforces — outside it the envelope is age-rejected anyway.
        #
        # SCOPE / result_id contract: this defence is only as strong as result_id's
        # uniqueness. In production the consumer MUST mint result_id as a fresh
        # cryptographically-random nonce per call (never reuse, never accept a
        # server-supplied one) — the signature binds it, so a replayed envelope carrying
        # an OLD result_id fails signature (the `replay` case) and the seen-cache only has
        # to catch exact same-result_id re-serves (the `replay_seen` case). Pass a
        # `replay_store` PATH to persist the cache across restarts and share it across
        # consumer instances (sqlite); default is per-instance in-memory (tests / a single
        # short-lived consumer). The demo uses fixed result_ids only for reproducibility.
        self._store = _SqliteStore(replay_store) if replay_store else _MemStore()
        self.log_path = Path(log_path) if log_path else None
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def evaluate(self, result: dict, *, case: str, tool_name: str, result_id: str) -> dict:
        """Verify one tool result, update the Biba floor, decide proceed/refuse.

        The consumer passes its OWN tool_name + result_id (the anti-replay property):
        a valid envelope lifted onto a different call fails signature verification.
        server_id is left to the A6 hint — a downstream consumer legitimately does not
        know the upstream id, and the signature covers the real value so a forged hint fails.
        """
        verdict = self.verifier.verify(result, tool_name=tool_name, result_id=result_id)
        reason = verdict.reason

        if not verdict.accepted:
            action = "refuse"  # fail-closed: do not ingest, floor unchanged
        else:
            envelope = (result.get("_meta") or {}).get(TRUST_ENVELOPE_KEY) or {}
            nonce = (envelope.get("binding") or {}).get("nonce", "")
            key = (tool_name, result_id, nonce)
            now = time.time()
            if self._store.check_and_add(key, now + MAX_ENVELOPE_AGE_SECONDS, now):
                # Verbatim replay of an already-consumed envelope. Crypto still passes; the
                # gate refuses on identity. Floor is NOT lowered again (already absorbed once).
                action = "refuse"
                reason = "replayed_envelope"
            else:
                # Biba: absorbing this source can only LOWER our integrity.
                self.session_floor = min(self.session_floor, verdict.integrity_rank)
                action = "proceed" if self.session_floor >= self.required_integrity else "refuse_privileged"

        rec = {
            "ts": time.time(), "case": case, "tool": tool_name, "result_id": result_id,
            "verdict": "accepted" if verdict.accepted else "rejected",
            "reason": reason, "integrity_rank": verdict.integrity_rank,
            "required_integrity": self.required_integrity,
            "session_floor": self.session_floor, "action": action,
            "has_meta": bool((result.get("_meta") or {}).get(TRUST_ENVELOPE_KEY)),
        }
        if self.log_path:
            try:
                with open(self.log_path, "a") as f:
                    f.write(json.dumps(rec) + "\n")
            except Exception as exc:  # noqa: BLE001
                # AUDIT MUST NEVER GATE CONTAINMENT. This write happens after the verdict
                # is computed but BEFORE the caller redacts, and fast-agent swallows any
                # exception out of after_tool_call and forwards the ORIGINAL result
                # (tool_runner.py ~635). So an unwritable log used to be a silent bypass:
                # full disk, read-only mount, or a typo'd HARNESS_LOG disabled containment.
                # Degrade to stderr and keep going - a lost log line is not a lost refusal.
                print(f"[trust-gate] verdict log write failed ({exc}); rec={rec}", file=sys.stderr)
        return rec
