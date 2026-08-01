# Capturing the `_meta` envelope on the wire

## Primary artifact (no sudo): `captures/mitm.jsonl`
The MITM proxy logs every frame it sees — `consumer->mitm`, `producer->mitm`,
`mitm->consumer` — including the **full `_meta` trust envelope JSON** (label,
binding.content_hash, signed_at, sig.x5c cert chain, sig.value). This is an
application-level wire dump and needs no privileges. It is written by
`attacks/mitm.py` and rebuilt on every `run_demo.sh`.

Inspect one envelope frame:
```bash
grep '"direction": "producer->mitm"' captures/mitm.jsonl | head -1 | \
  .venv/bin/python -m json.tool
```

## Packet-level capture (needs sudo — BPF on loopback)
Loopback capture on macOS needs root (BPF device perms). `run_demo.sh` first tries
it **non-interactively** (`sudo -n`) and, if that prompts for a password, skips it
and notes so in `captures/tcpdump.txt` — the run never blocks on a password.

To capture packets yourself, run this in a second terminal, then run the demo:
```bash
# macOS loopback is lo0; envelope traffic is plaintext HTTP on the MITM port
sudo tcpdump -i lo0 -s0 -A "tcp port 8899" -w captures/loopback.pcap
# then, elsewhere:  ./run_demo.sh
# read it back:
tcpdump -A -r captures/loopback.pcap | less   # the JSON envelope is visible in-band
```
The envelope is HTTP (not TLS) between producer/MITM/consumer on purpose, so the
signed `_meta` is directly readable on the wire — the security property is the
signature, not transport secrecy.
