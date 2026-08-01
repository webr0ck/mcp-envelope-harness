"""Untrusted relay between Org A and Org B.

``relay_mode=raise_rank`` changes a signed public rank from 0 to 2 without access
to Org A's signing key. Org B must reject the result rather than trusting the raised
rank. The relay records every upstream and downstream body as evidence.
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

from federation.protocol import TRUST_ENVELOPE_KEY


def build_handler(upstream: str, capture_path: Path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _capture(self, direction: str, mode: str, body: dict) -> None:
            record = {
                "ts": time.time(),
                "direction": direction,
                "mode": mode,
                "body": body,
            }
            with capture_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record) + "\n")

        def do_GET(self):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            mode = query.pop("relay_mode", ["passthrough"])[0]
            forwarded = urlencode({key: values[0] for key, values in query.items()})
            url = f"{upstream.rstrip('/')}{parsed.path}"
            if forwarded:
                url = f"{url}?{forwarded}"

            with urllib.request.urlopen(url, timeout=10) as response:
                payload = json.loads(response.read())
            self._capture("org-a->relay", mode, payload)

            if mode == "raise_rank":
                envelope = (
                    payload.get("result", {})
                    .get("_meta", {})
                    .get(TRUST_ENVELOPE_KEY, {})
                )
                label = envelope.get("label") or {}
                label["integrity_rank"] = 2
                label["source"] = "internal"
            elif mode != "passthrough":
                self.send_error(400, "relay_mode must be passthrough or raise_rank")
                return

            self._capture("relay->org-b", mode, payload)
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the untrusted federation relay")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8912)
    parser.add_argument("--upstream", required=True, help="Org A base URL")
    parser.add_argument("--capture", required=True)
    args = parser.parse_args()

    capture = Path(args.capture)
    capture.parent.mkdir(parents=True, exist_ok=True)
    capture.write_text("", encoding="utf-8")
    server = ThreadingHTTPServer(
        (args.host, args.port), build_handler(args.upstream, capture)
    )
    print(f"untrusted relay: http://{args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
