# Cross-boundary envelope demonstration

This scenario carries the missing **why**. It does not merely show that a signature
detects changed bytes. It compares what Org B can safely do when one Org A server returns
both trusted internal material and attacker-writable public material through an untrusted
relay.

The result is deliberately asymmetric:

| Receiver policy | Public result | Internal result |
|---|---|---|
| No envelope, default trusted | attacker-requested report executes | works |
| No envelope, default untrusted | contained | legitimate report is blocked |
| Signed per-result envelope + floor | contained | works |

There is no single static trust value for the server that achieves both safety and
utility. The envelope transports an authenticated **per-result** rank; the Biba floor
uses that rank to contain the follow-on privileged action. A relay rank-raising case
also proves that the intermediary cannot turn public rank 0 into internal rank 2.

## Run locally on macOS, Linux, or Windows

The verifier wheel declares Python 3.12 or newer. Use a Python 3.12+ environment with
the repository dependencies and the private `mcp_trust_verifier` wheel installed:

```bash
python -m federation.run_demo
```

Expected output contains five `PASS` lines. Generated evidence is written under
`.run/federation/`:

- `evidence.json` — decisions, side effects, and acceptance results;
- `relay.jsonl` — Org A→relay and relay→Org B wire bodies;
- `org_a/public/labeler_ca.pem` — the public trust anchor Org A publishes;
- `org_b/trust/org_a_labeler_ca.pem` — Org B's out-of-band pinned copy.

The local command uses three separate processes and real HTTP sockets for a reproducible
test. No producer key or shared database enters Org B. Only the public CA anchor crosses
the trust-bootstrap boundary.

The interactive Windows CLI under `manual_lab/` has a different dependency boundary: it
can run on Python 3.11 because verification occurs in the remote lab service. This
federation demo performs signing and verification locally, so it needs the verifier
wheel and its Python 3.12+ runtime on every host running Org A or Org B components.

## Run on separate hosts

The addresses below are placeholders. Choose reachable addresses for your environment;
do not commit them.

On the Org A host:

```bash
python -m federation.producer \
  --host 0.0.0.0 --port 8911 \
  --anchor-out .run/federation/org_a_labeler_ca.pem
```

Transfer only the generated public `org_a_labeler_ca.pem` to Org B through the trust
bootstrap channel you are testing.

On the relay host:

```bash
python -m federation.relay \
  --host 0.0.0.0 --port 8912 \
  --upstream http://ORG_A_HOST:8911 \
  --capture .run/federation/relay.jsonl
```

On the Org B host:

```bash
python -m federation.consumer \
  --relay-url http://RELAY_HOST:8912 \
  --anchor /path/to/org_a_labeler_ca.pem \
  --evidence .run/federation/evidence.json
```

Restrict these unauthenticated lab listeners with host firewall or private networking.

## What “RFC federation” means here

The earlier review's “RFC §6 federation” is **not an IETF RFC citation**. It refers to
the platform project's internal RFC-0002 draft. In the current executable specification,
federation and trust-scope are §5; §6 is AI provenance. An older generated status table
uses §6 for federation, so the section reference has drifted and should not be quoted as
an external standard.

This demonstration proves the RFC's motivating substrate: an authenticated label can
survive an administrative boundary and an untrusted relay. It is **not** a complete
RFC-0002 federation implementation. Signed trust-list governance, issuer scope ceilings,
transparency, revocation, and rollback protection remain separate work.
