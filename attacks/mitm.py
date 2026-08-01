"""MITM localhost proxy between producer and consumer.

Sits on a real socket, forwards to the producer, and (per --mode) manipulates the
body IN FLIGHT. Every request/response frame — including the full `_meta` envelope
JSON — is appended to an app-level wire capture (captures/*.jsonl). This is the
PRIMARY on-the-wire artifact (loopback tcpdump needs sudo; see captures/HOWTO-tcpdump.md).

Modes:
  passthrough : forward unchanged (valid + stale cases)
  tamper      : flip a char in content text, keep the original signature → content_hash_mismatch
  strip_meta  : delete result._meta → no_envelope
  rogue_cert  : re-sign content under an UNPINNED rogue PKI → chain_validation_failed
  replay      : forward with a DIFFERENT result_id than the consumer asked → a
                validly-signed envelope for another call, presented for this one → signature_invalid
  replay_cache: cache the FIRST upstream response and re-serve it verbatim on every
                later request (same nonce + result_id) → a captured accepted envelope
                replayed on the wire → consumer's seen-cache refuses the 2nd → replayed_envelope

Run: python -m attacks.mitm --port 8899 --producer-port 8811 --mode tamper --capture captures/mitm.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_trust_verifier import TRUST_ENVELOPE_KEY
from producer.signer import Pki

ROGUE_PKI = Pki(cn="ROGUE Attacker")  # not chained to the pinned anchor


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _capture(self, direction, case_mode, path, obj):
        rec = {"ts": time.time(), "direction": direction, "mode": case_mode, "path": path, "body": obj}
        with open(self.server.capture_path, "a") as f:
            f.write(json.dumps(rec) + "\n")

    def do_GET(self):
        mode = self.server.mode
        q = parse_qs(urlparse(self.path).query)
        self._capture("consumer->mitm", mode, self.path, {k: v[0] for k, v in q.items()})

        # replay_cache: re-serve the first captured upstream payload verbatim (nonce + id
        # identical) so a validly-signed envelope is replayed on the wire.
        if mode == "replay_cache" and self.server.cached_payload is not None:
            payload = self.server.cached_payload
            self._capture("mitm->consumer", mode, self.path, payload)
            self._send_json(payload)
            return

        # Forward to producer (replay rewrites result_id in flight)
        fwd_q = {k: v[0] for k, v in q.items()}
        if mode == "replay":
            fwd_q["result_id"] = (fwd_q.get("result_id", "rid") + "-REPLAYED")
        up = f"http://127.0.0.1:{self.server.producer_port}/tool?{urlencode(fwd_q)}"
        with urllib.request.urlopen(up, timeout=10) as r:
            payload = json.loads(r.read())
        self._capture("producer->mitm", mode, up, payload)

        if mode == "replay_cache":
            self.server.cached_payload = payload  # freeze the first accepted envelope

        result = payload["result"]
        result = self._manipulate(mode, result)
        payload["result"] = result

        self._capture("mitm->consumer", mode, self.path, payload)
        self._send_json(payload)

    def _send_json(self, payload):
        out = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def _manipulate(self, mode, result):
        if mode in ("passthrough", "replay", "replay_cache"):
            return result
        if mode == "strip_meta":
            result.pop("_meta", None)
            return result
        if mode == "tamper":
            c = result.get("content") or []
            if c and c[0].get("type") == "text":
                t = c[0]["text"]
                c[0]["text"] = ("X" + t[1:]) if t else "TAMPERED"  # flip first char, keep _meta
            return result
        if mode == "rogue_cert":
            # re-sign the (unchanged) content with a rogue PKI the consumer never pinned
            env = result.get("_meta", {}).get(TRUST_ENVELOPE_KEY, {})
            cc = env.get("call_context", {})
            label = env.get("label", {})
            rogue = ROGUE_PKI.sign_envelope(
                content=result.get("content", []),
                tool_name=cc.get("tool_name", ""), server_id=cc.get("server_id", ""),
                result_id=cc.get("result_id", ""),
                trust_tier=int(label.get("integrity_rank", 0) or 0),
            )
            result["_meta"] = {TRUST_ENVELOPE_KEY: rogue}
            return result
        raise ValueError(f"unknown mode {mode}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--producer-port", type=int, default=8811)
    ap.add_argument("--mode", default="passthrough")
    ap.add_argument("--capture", default=str(Path(__file__).resolve().parent.parent / "captures" / "mitm.jsonl"))
    args = ap.parse_args()
    Path(args.capture).parent.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    srv.mode = args.mode
    srv.producer_port = args.producer_port
    srv.capture_path = args.capture
    srv.cached_payload = None  # replay_cache: first accepted envelope, frozen for re-serve
    print(f"mitm[{args.mode}]: http://127.0.0.1:{args.port} -> producer:{args.producer_port} cap={args.capture}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
