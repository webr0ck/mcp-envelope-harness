"""AnticLaw-style untrusted MCP-ish producer over real localhost HTTP.

Serves the poisoned imported-conversation fixture and SIGNS the result with an
ephemeral labeler PKI → Layer A `_meta` envelope. On startup it writes its
sub-CA anchor PEM to disk so the consumer can PIN it (the consumer's only trust
input). Query params let the harness drive edge cases without a second server:

    GET /tool?tool=NAME&result_id=RID&server_id=SID&tier=N&stale=1&layer_b=1

Responds: {"result": <CallToolResult dict with content + _meta>}
Everything is a real socket; no in-process shortcuts.

Run:  python -m producer.server --port 8811 --anchor .run/sub_ca.pem
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from producer.signer import Pki, build_result

_ROOT = Path(__file__).resolve().parent.parent
_FIXTURE = json.loads((_ROOT / "fixtures" / "poisoned_conversation.json").read_text())

PKI = Pki()  # one ephemeral PKI for the process lifetime


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet; the MITM/consumer own the audit trail
        pass

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        g = lambda k, d="": q.get(k, [d])[0]
        try:
            tier = int(g("tier", "0"))
        except ValueError:
            tier = 0
        stale = g("stale", "0") == "1"
        result = build_result(
            PKI, _FIXTURE["content"],
            tool_name=g("tool", "import_conversation"),
            server_id=g("server_id", "anticlaw-producer"),
            result_id=g("result_id", "rid-0"),
            trust_tier=tier,
            signed_at_skew_seconds=-1200 if stale else 0,  # 20 min in the past
            layer_b=g("layer_b", "0") == "1",
        )
        body = json.dumps({"result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8811)
    ap.add_argument("--anchor", default=str(_ROOT / ".run" / "sub_ca.pem"))
    args = ap.parse_args()
    anchor = Path(args.anchor)
    anchor.parent.mkdir(parents=True, exist_ok=True)
    anchor.write_bytes(PKI.sub_ca_pem)  # consumer pins THIS
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"producer: http://127.0.0.1:{args.port}/tool  anchor={anchor}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
