# MCP Envelope Harness — Roadmap

**Goal:** demonstrate, end-to-end over a real localhost transport, that the mcp-security-platform
MIME-like protection (Layer A signed trust envelope + Layer B advisory wrap + Biba integrity floor)
actually protects an AI agent harness, across attack cases including MITM — with the decisions and the
on-the-wire envelope captured in **log files** and **network traffic**.

The consumer verifies using the **shipped** `mcp-trust-verifier` wheel (same code the proxy runs).

## Capability checklist (definition of "full capability")

- [x] Producer (AnticLaw-style, serves a poisoned imported-conversation fixture) signs results → `_meta` envelope over real localhost HTTP — `producer/server.py` + `producer/signer.py`
- [x] Consumer harness verifies via the wheel, applies a Biba integrity floor, decides proceed/refuse — `consumer/harness.py`
- [x] **REAL fast-agent hook integration (Loop 5, WI-2).** `fast-agent-mcp` 0.9.22 is now installed in `.venv`; `consumer/hooks.py` is rewritten to the REAL async two-arg `ToolRunnerHooks` contract (`after_tool_call(runner, message)` awaited by fast-agent, operating on `message.tool_results[*]` as `mcp.types.CallToolResult`). `consumer/fastagent_runner.py` drives the actual `fast_agent.agents.tool_runner.ToolRunner.generate_tool_call_response()` — fast-agent's OWN code awaits our hook and uses the mutated message for the (stubbed) next turn. Redaction happens BEFORE the model turn; proven NON-VACUOUSLY (a neuter hook leaks the poison — `tests/test_fastagent_conformance.py`). Only the LLM is stubbed (a fake agent returns the wire result); the hook-firing path is 100% real fast-agent.
- [x] Attack: **valid** → accept, integrity_rank honored → **proceed**
- [x] Attack: **MITM body tamper** (proxy flips content in flight) → `content_hash_mismatch` → **refuse**
- [x] Attack: **rogue cert** (unpinned CA) → `chain_validation_failed` → **refuse**
- [x] Attack: **no envelope / stripped `_meta`** → fail-closed rank 0 → **refuse**
- [x] Attack: **replay** (valid envelope lifted onto a different call) → `signature_invalid` → **refuse**
- [x] Attack: **verbatim replay** (byte-identical accepted envelope re-served on the wire, same call identity) → consumer seen-cache → `replayed_envelope` → **refuse** — `consumer/harness.py` `_seen`, MITM `replay_cache` mode
- [x] Attack: **stale** envelope (age > window) → `envelope_too_old` → **refuse**
- [x] Layer B advisory wrapper present on low-trust content (MIME-style boundary) — `producer/layer_b.py`, signed-over
- [x] **Network capture** of the `_meta` envelope on the wire (app-level frame dump `captures/mitm.jsonl`; sudo-tcpdump path documented in `captures/HOWTO-tcpdump.md`)
- [x] **Structured logs** (JSONL) of every verdict + action, per case — `logs/verdicts.jsonl`
- [x] One `run_demo.sh` orchestrates start→exercise→teardown, reproducible, exits non-zero on any miss (verified: exit 1 when a case regresses)
- [x] Acceptance test passes ALL cases — `tests/test_harness.py` + `tests/test_hooks.py` (14 passed) + `run_demo.sh` (8/8 over sockets)
- [x] **Cross-boundary motivation demo.** `federation/` compares the same Org A server under unsigned/default-trusted, unsigned/default-untrusted, and signed per-result policies through an untrusted relay. It proves that static server trust cannot provide both safety and utility, while signed rank permits internal work, contains public poison, and rejects an in-flight rank raise. The components can run locally as three processes or on separate hosts.
- [x] Security review: no unresolved HIGH/CRITICAL findings — **MET (Loop 4).** `consumer/driver.py` now routes every wire result through the REAL hook seam (`consumer.hooks.before_tool_call` + `after_tool_call`) instead of `TrustGate.evaluate()` directly, and asserts on the wire result that on any refuse verdict the poisoned markers (`SYSTEM OVERRIDE` / `id_rsa` / `evil.example`) are GONE and the `[trust-gate REFUSED …]` stub is present. `run_demo.sh` gates on the driver exit code, so all 6 refuse cases (mitm_tamper, rogue_cert, no_envelope, replay, replay_seen, stale) now prove containment against real MITM-tampered wire bytes — not a synthetic context object. Non-vacuous: neutering `_redact_result` makes the wire check fail (verified). Remaining items are MEDIUM/documented (global monotonic Biba floor; stubbed LLM loop; app-level vs packet capture). **Unresolved HIGH: 0. No CRITICAL.**

## Loop log

_(updated by the roadmap agent after each loop)_

### Loop 0 — scaffold (done by hand, 2026-07-23)
- Created `~/Code/mcp-envelope-harness/` (separate from mcp-security-platform), git init, `.venv` (system-site).
- Installed `mcp-trust-verifier` wheel; import verified.
- tcpdump present but loopback capture needs sudo → app-level wire capture is the primary artifact.

### Loop 1 — full scaffold + all attack cases (2026-07-23)
- Built producer→(MITM)→consumer over real localhost sockets (`http.server` + `urllib`).
- Producer signs `_meta` envelope with an ephemeral labeler PKI (`producer/signer.py`, faithful port of `trust_labeler._sign`, reusing the wheel's own JCS so signer/verifier agree byte-for-byte). Writes its sub-CA anchor to `.run/sub_ca.pem` for the consumer to pin.
- Consumer verifies with the shipped wheel (`TrustVerifier`), maintains a Biba `session_floor`, decides proceed / refuse / refuse_privileged (`consumer/harness.py`).
- MITM (`attacks/mitm.py`) manipulates in flight: passthrough / tamper / strip_meta / rogue_cert (re-sign under unpinned PKI) / replay (rewrite result_id). Every frame incl. the full envelope JSON is dumped to `captures/mitm.jsonl` (21 frames/run) — the primary on-wire artifact.
- ALL 7 cases green over sockets (`run_demo.sh`, exit 0) + 8 in-process acceptance tests (`tests/test_harness.py`). Verified the demo exits **1** when a case regresses (ran `valid` through a tamper MITM).
- stale = producer backdates `signed_at` −20 min (real signature, age-rejected first); replay = MITM presents a validly-signed-for-another-call envelope, consumer verifies with its own result_id → `signature_invalid`.
- fast-agent hooks written (`consumer/hooks.py`) but fast-agent is NOT cloned in this env; the no-LLM `consumer/driver.py` calls the identical gate. LLM loop honestly stubbed. Truncation caveat (mcp_agent.py:1907) documented in the hook module.
- tcpdump: `sudo -n` unavailable here (no password prompt hit) → skipped, noted in `captures/tcpdump.txt`; packet-capture command documented in `captures/HOWTO-tcpdump.md`.

**Acceptance case table** (from `logs/verdicts.jsonl`, 7 lines, 1 run):

| Case | Expected | Verdict / reason | rank | floor | Pass |
|---|---|---|---|---|---|
| valid | proceed (accepted) | accepted / — | 1 | 1 | ✅ |
| mitm_tamper | refuse | rejected / `content_hash_mismatch` | 0 | 4 | ✅ |
| rogue_cert | refuse | rejected / `chain_validation_failed` | 0 | 4 | ✅ |
| no_envelope | refuse (fail-closed) | rejected / `no_envelope` (has_meta=false) | 0 | 4 | ✅ |
| replay (cross-call) | refuse | rejected / `signature_invalid` | 0 | 4 | ✅ |
| stale | refuse | rejected / `envelope_too_old_age=1200s` | 0 | 4 | ✅ |
| layer_b | proceed (rank 0, floor 0) | accepted / — | 0 | 0 | ✅ |

7/7 over sockets (`run_demo.sh` exit 0) + 8 in-process (`tests/test_harness.py`). Log/capture values cross-checked byte-for-byte against the acceptance report — not vacuous.

**Security findings:**
- 🔴 **HIGH — same-call envelope replay is not blocked (unresolved).** The `replay` case only proves *cross-call* replay fails (envelope signed over a different `result_id`). A byte-identical, validly-signed envelope re-presented for the SAME `result_id` verifies again — `consumer/harness.py` keeps no seen-id/nonce cache, so nothing marks an envelope as already consumed. Confirmed by inspection (no `seen`/`nonce`/replay-cache state in `consumer/`). Fix next loop: a bounded seen-`result_id` (or envelope-digest) set on the consumer, evicting past the freshness window; treat a repeat within the window as `replay_seen` → refuse.
- ✅ Chain validation pins the out-of-band anchor (`.run/sub_ca.pem`), ignoring the on-wire `x5c` — rogue_cert is non-bypassable.
- ✅ Tamper/strip/rogue/stale all fail-closed: `label`, `content_hash`, `signed_at`, `tool_name`, `result_id`, `server_id` are all inside the JCS-signed payload (RFC 8785 via the wheel's own `jcs`), so signer/verifier agree byte-for-byte.

**Unresolved HIGH/CRITICAL: 1** (same-call replay). No CRITICAL.

**Top remaining gaps for next loop:**
1. Same-call replay cache (the HIGH above) + an 8th acceptance case (`replay_seen`) that reproduces double-accept then proves the fix refuses it.
2. Real fast-agent LLM loop — needs the clone; today's `driver.py` calls the identical gate without the LLM (honestly stubbed).
3. Packet-level (tcpdump) capture — needs interactive sudo; app-level wire dump is the standing artifact.

- **Not done:** the HIGH replay fix; real fast-agent LLM loop (needs the clone); packet capture.

### Loop 2 — close the HIGH: verbatim replay defense (2026-07-23)
- **Fixed the 1 unresolved HIGH.** `consumer/harness.py` `TrustGate` now holds a TTL-bounded `_seen` dict keyed on `(tool_name, result_id, binding.nonce)`. The signer already stamps a fresh `binding.nonce` per signing, so that tuple uniquely names one envelope. After an envelope verifies, if the tuple is already seen the gate refuses with reason `replayed_envelope` and does NOT lower the Biba floor again (already absorbed once); otherwise it records the tuple with expiry `now + MAX_ENVELOPE_AGE_SECONDS` (imported from the wheel so TTL == the verifier's freshness window) and proceeds. Entries past the window are pruned each call — safe because the verifier age-rejects anything older before it reaches the cache.
- **New acceptance case `replay_seen`** exercises real verbatim replay two ways: (1) in-process `tests/test_harness.py::test_verbatim_replay_refused` — same signed envelope through `gate.evaluate()` twice, 1st `proceed`, 2nd `refuse`/`replayed_envelope`; (2) over sockets — new MITM mode `replay_cache` caches the first upstream response and re-serves it verbatim, and `consumer/driver.py` does two real round-trips through one consumer session (1st proceeds, 2nd refused). Wire capture cross-checked: the MITM re-serves the **identical `binding.nonce`** to the consumer on both frames (`QZvhcuIuMGoFmMypM93aXg` in one run) — the replay is genuine on the wire, not simulated.
- **Result:** `tests/test_harness.py` 9 passed; `run_demo.sh` 8/8 over sockets, exit 0; `logs/verdicts.jsonl` 9 lines (replay_seen logs 2 verdicts — accept then `replayed_envelope`). Distinction from the older `replay` case preserved: that one still proves cross-call replay (`signature_invalid`); `replay_seen` proves same-call verbatim replay (`replayed_envelope`).
- **Still not done (unchanged, honestly):** real fast-agent LLM loop — fast-agent is still not cloned in this env; `consumer/hooks.py` + the no-LLM `driver.py` call the identical gate. Packet-level tcpdump on lo0 — `sudo -n` still unavailable here; app-level `captures/mitm.jsonl` remains the primary on-wire artifact, sudo command documented in `captures/HOWTO-tcpdump.md`.

**Acceptance case table** (from `logs/verdicts.jsonl`, 9 lines — `replay_seen` logs 2; verified via `run_demo.sh` exit 0, `tests/test_harness.py` 9 passed):

| Case | Expected | Verdict / reason | rank | floor | Pass |
|---|---|---|---|---|---|
| valid | proceed (accepted) | accepted / — | 1 | 1 | ✅ |
| mitm_tamper | refuse | rejected / `content_hash_mismatch` | 0 | 4 | ✅ |
| rogue_cert | refuse | rejected / `chain_validation_failed` | 0 | 4 | ✅ |
| no_envelope | refuse (fail-closed) | rejected / `no_envelope` | 0 | 4 | ✅ |
| replay (cross-call) | refuse | rejected / `signature_invalid` | 0 | 4 | ✅ |
| replay_seen (verbatim) | 1st proceed, 2nd refuse | accepted → rejected / `replayed_envelope` | 1→0 | — | ✅ |
| stale | refuse | rejected / `envelope_too_old` | 0 | 4 | ✅ |
| layer_b | proceed (rank 0, floor 0) | accepted / — | 0 | 0 | ✅ |

8/8 cases over sockets (`run_demo.sh` exit 0) + 9 in-process tests. Not vacuous — log/wire values cross-checked (verbatim replay re-serves the identical `binding.nonce` on the wire).

**Security findings (Loop 2):**
- ✅ **RESOLVED (was Loop 1's HIGH) — verbatim same-call replay** now refused by the `_seen` cache (`replayed_envelope`), reproduced by `replay_seen`.
- 🔴 **NEW HIGH (unresolved) — refused content is not redacted before it reaches the LLM.** `consumer/hooks.py:after_tool_call` calls `gate.evaluate()` and only does `setattr(context, "trust_verdict", rec)`; it returns `context.result` untouched even on refuse. Enforcement is entirely `before_tool_call`'s Biba floor, which only blocks a *subsequent* integrity-gated tool. Injection that needs no second privileged call — model leaking data in its own final answer, or calling a `required_integrity=0` tool — is unmitigated. Confirmed by inspection: no code path strips/replaces `context.result`. Fix next loop: on a refuse verdict, replace `context.result` content with a redaction stub (keep the verdict for audit) so poisoned text never enters the LLM turn.

**Unresolved HIGH/CRITICAL: 1** (hooks redaction gap). No CRITICAL.

**Top remaining gaps for next loop:**
1. Redact/replace refused tool results in `after_tool_call` (the new HIGH) + a case proving poisoned text does not reach the LLM context on refuse.
2. Real fast-agent LLM loop — needs the clone; `driver.py` calls the identical gate without the LLM (honestly stubbed).
3. Packet-level tcpdump capture — needs interactive sudo; app-level wire dump is the standing artifact.

### Loop 3 — close both Loop 2 HIGHs: content containment + durable replay (2026-07-23)
- **Fixed HIGH #1 (containment).** `consumer/hooks.py:after_tool_call` now calls `_redact_result` on any refuse verdict (`refuse` or `refuse_privileged`): the tool result's content is replaced in place with `[trust-gate REFUSED (<reason>): tool output withheld from the model]`, `structuredContent`/`_meta` nulled, so the poisoned bytes NEVER enter the LLM turn. Dict shape (harness/MITM wire form) redacted fully; a real pydantic `CallToolResult` best-effort in place, fail-closed to empty content if it can't be rewritten. This closes the gap where injection needing no second privileged call (model leaking in its own answer, or a `required_integrity=0` tool) was unmitigated. Before was the ONLY untested integration point; now `tests/test_hooks.py` (4 tests) drives the hook directly and asserts the `SYSTEM OVERRIDE`/`id_rsa` payload is gone from `context.result` on refuse, present on a valid result, and that `before_tool_call` still fail-closes a privileged tool after a floor drop.
- **Fixed HIGH #2 (durable/cross-instance replay).** The replay cache was in-process only. `consumer/harness.py` now has two backends behind one `check_and_add(key, expiry, now)` seam: `_MemStore` (default, isolated per instance — tests / single short-lived consumer) and `_SqliteStore` (pass a `replay_store` path). The sqlite store persists across consumer restart AND is shared by any consumer pointed at the same file (`BEGIN IMMEDIATE` write-lock so two instances can't both accept the same new envelope). `tests/test_harness.py::test_persistent_replay_across_instances` proves a fresh gate (a restart / second instance) refuses an envelope a prior gate already consumed via the same db. The `result_id`-must-be-a-consumer-minted-nonce contract (and why the demo uses fixed ids) is now documented in the `TrustGate.__init__` comment. `consumer/driver.py` + `run_demo.sh` use the sqlite store (`.run/replay_cache.db`, cleared once at demo start so reruns stay green — its persistence is exactly why a rerun would otherwise refuse `valid`).
- **Result:** `tests/` 14 passed (9 harness + 1 persistence + 4 hooks); `run_demo.sh` 8/8 over sockets, exit 0; `logs/verdicts.jsonl` 9 lines; `captures/mitm.jsonl` 26 frames. Regression behaviour (exit 1 on any miss) unchanged.
- **Correction to the IMPL claim of "0 unresolved HIGH":** an independent security re-review found the redaction fix is **not wired into the over-the-wire path** — see findings below. Unresolved HIGH is **1**, not 0.
- **Still not done (unchanged, honestly):** real fast-agent LLM loop — fast-agent is still not cloned in this env; `consumer/hooks.py` + no-LLM `driver.py` call `TrustGate` but by **different paths** (see finding). Cross-instance replay is now durable, but a distributed multi-node store (Redis etc.) is out of scope — the sqlite file covers restart + same-host fleet. Packet-level tcpdump on lo0 — `sudo -n` still unavailable; app-level `captures/mitm.jsonl` remains the primary on-wire artifact.

**Acceptance case table** (from `logs/verdicts.jsonl`, 9 lines — `replay_seen` logs 2; `run_demo.sh` exit 0, `tests/` 14 passed):

| Case | Expected | Verdict / reason | rank | floor | Pass |
|---|---|---|---|---|---|
| valid | proceed (accepted) | accepted / — | 1 | 1 | ✅ |
| mitm_tamper | refuse | rejected / `content_hash_mismatch` | 0 | 4 | ✅ |
| rogue_cert | refuse | rejected / `chain_validation_failed` | 0 | 4 | ✅ |
| no_envelope | refuse (fail-closed) | rejected / `no_envelope` | 0 | 4 | ✅ |
| replay (cross-call) | refuse | rejected / `signature_invalid` | 0 | 4 | ✅ |
| replay_seen (verbatim) | 1st proceed, 2nd refuse | accepted → rejected / `replayed_envelope` | 1→1 | — | ✅ |
| stale | refuse | rejected / `envelope_too_old_age=1201s` | 0 | 4 | ✅ |
| layer_b | proceed (rank 0, floor 0) | accepted / — | 0 | 0 | ✅ |

8/8 over sockets + 14 in-process tests. Crypto/anti-replay/staleness/fail-closed hold on the wire (independently re-verified: label, content_hash, nonce, signed_at, tool_name, server_id, result_id all inside the JCS-signed payload; chain pinned to the out-of-band anchor, not the on-wire x5c).

**Security findings (Loop 3, independent re-review):**
- 🔴 **HIGH (unresolved) — the containment/redaction fix is not exercised on the wire.** `consumer/driver.py` (the acceptance driver) calls `TrustGate.evaluate()` directly and never calls `consumer/hooks.py:after_tool_call`, so `_redact_result` never runs against real MITM-tampered bytes. The spec asked for a driver that calls the SAME hook functions; it doesn't. The headline claim (poisoned content withheld from the model on refuse) is proven only by `tests/test_hooks.py` with a synthetic context object — a vacuous pass on the harness's core purpose. Fix next loop: route `driver.py` through `after_tool_call`/`before_tool_call` (or add a hook-path case to `run_demo.sh`) and assert the redaction stub appears in the wire-fetched result on every refuse case.
- 🟡 **MEDIUM (design limitation) — `session_floor` is global + monotonic with no per-tool `required_integrity`.** Once any low-integrity source taints the floor, every subsequent privileged tool in the session is refused globally (confirmed by PoC). This is a faithful Biba "lowest source" reading but coarse: there is no per-tool integrity label, so a benign high-integrity tool is blocked after one poisoned read with no path to compartmentalize or reset within a session. Acceptable for the demo; note it before any real deployment.
- ✅ Chain validation pins the out-of-band anchor (`.run/sub_ca.pem`), ignoring on-wire `x5c` — rogue_cert non-bypassable. Verbatim + cross-call replay both refused. Durable sqlite replay store survives restart / shared across instances (`BEGIN IMMEDIATE` write-lock).

**Unresolved HIGH/CRITICAL: 1** (redaction not wired into the wire path). No CRITICAL.

**Top remaining gaps for next loop:**
1. Wire the redaction path into the acceptance run — `driver.py` must call `consumer/hooks.py:after_tool_call` (not `gate.evaluate` directly) and `run_demo.sh` must assert the stub replaces poisoned bytes in the wire result on every refuse case. Closes the HIGH.
2. Per-tool `required_integrity` labels + a session compartment/reset story for the global-floor MEDIUM.
3. Real fast-agent LLM loop — needs the clone; today's driver stubs the LLM turn.
4. Packet-level tcpdump capture — needs interactive sudo; app-level wire dump is the standing artifact.

### Loop 4 — close the HIGH: wire the redaction path into the acceptance run (2026-07-23)
- **Fixed the 1 unresolved HIGH (containment not on the wire).** `consumer/driver.py` no longer calls `TrustGate.evaluate()` directly. It now wraps each wire-fetched result in a minimal `Ctx` (the same dict shape `tests/test_hooks.py` uses) and drives it through the REAL fast-agent hook entrypoints — `consumer.hooks.before_tool_call` (Biba-floor entry guard) then `consumer.hooks.after_tool_call` (verify + taint + `_redact_result` on refuse). The security path under acceptance test is now byte-identical to the one the real agent's `ToolRunnerHooks` would run; only the LLM turn is stubbed (fast-agent still not cloned).
- **run_demo.sh now asserts containment on the wire, not just the verdict.** The driver checks that on every refuse action the poisoned markers (`SYSTEM OVERRIDE` / `id_rsa` / `evil.example`) are absent from `ctx.result` and the `[trust-gate REFUSED …]` stub replaced them; on proceed the original content passes through untouched (and for `layer_b`, the `LAYER-B-UNTRUSTED` boundary must survive). All 6 refuse cases now prove containment against real MITM-tampered bytes. `run_demo.sh` exits non-zero if any case's action OR redaction check fails.
- **Non-vacuous, verified.** Monkeypatching `_redact_result` to a no-op makes the `mitm_tamper` wire check fail with `CONTAINMENT FAILED: poisoned marker(s) ['SYSTEM OVERRIDE', 'id_rsa', 'evil.example'] survived redaction` — the assertion bites.
- `consumer/hooks.py:_get_gate` now also reads `HARNESS_REPLAY_STORE` so the hook-built gate shares the durable sqlite replay cache the driver/`run_demo.sh` use (`.run/replay_cache.db`) — needed for `replay_seen` over the hook path.
- **Result:** `run_demo.sh` 8/8 over sockets, exit 0, all `redacted_ok=True`; `tests/` 14 passed; `logs/verdicts.jsonl` 9 lines; `captures/mitm.jsonl` 26 frames.
- **Still not done (unchanged, honestly):** real fast-agent LLM loop (fast-agent not cloned — the hook seam is real, the LLM turn is stubbed); packet-level tcpdump on lo0 (`sudo -n` unavailable — app-level `captures/mitm.jsonl` is the standing on-wire artifact); global monotonic Biba floor with no per-tool `required_integrity` (MEDIUM, documented).

**Acceptance case table** (from `logs/verdicts.jsonl`, 9 lines — `replay_seen` logs 2; `run_demo.sh` exit 0, `tests/` 14 passed; every refuse case wire-verified `redacted_ok=True`):

| Case | Expected | Verdict / reason | rank | floor | Contained | Pass |
|---|---|---|---|---|---|---|
| valid | proceed (accepted) | accepted / — | 1 | 1 | content untouched | ✅ |
| mitm_tamper | refuse | rejected / `content_hash_mismatch` | 0 | 4 | poisoned bytes redacted | ✅ |
| rogue_cert | refuse | rejected / `chain_validation_failed` | 0 | 4 | poisoned bytes redacted | ✅ |
| no_envelope | refuse (fail-closed) | rejected / `no_envelope` (has_meta=false) | 0 | 4 | poisoned bytes redacted | ✅ |
| replay (cross-call) | refuse | rejected / `signature_invalid` | 0 | 4 | poisoned bytes redacted | ✅ |
| replay_seen (verbatim) | 1st proceed, 2nd refuse | accepted → refuse / `replayed_envelope` | 1 | 1 | 2nd result redacted | ✅ |
| stale | refuse | rejected / `envelope_too_old_age=1200s` | 0 | 4 | poisoned bytes redacted | ✅ |
| layer_b | proceed (rank 0, floor 0) | accepted / — | 0 | 0 | `LAYER-B-UNTRUSTED` boundary survives | ✅ |

8/8 over sockets + 14 in-process tests. Non-vacuous: neutering `_redact_result` to a no-op makes `mitm_tamper`'s wire check fail (`CONTAINMENT FAILED: poisoned marker(s) ['SYSTEM OVERRIDE', 'id_rsa', 'evil.example'] survived redaction`) — the containment assertion bites.

**Security findings (Loop 4):**
- ✅ **RESOLVED (was Loop 3's HIGH) — containment is now proven on the wire.** The redaction hook runs against real MITM-tampered bytes in the acceptance path; the demo fails if poisoned content survives.
- 🟡 **MEDIUM (unchanged, design limitation) — `session_floor` is global + monotonic with no per-tool `required_integrity`.** Once any low-integrity source taints the floor, every subsequent privileged tool in the session is refused globally. Faithful Biba "lowest source" reading but coarse; acceptable for the demo, note before any real deployment.
- 🟡 **MEDIUM (design/boundary) — containment invariant lives in the integration layer (`consumer/hooks.py`), not in `TrustGate` itself.** `TrustGate.evaluate()` computes the `refuse` action but never mutates the caller's result; the redaction only happens because `after_tool_call` remembers to call `_redact_result`. Same bug class this project fixed in Loop 2→3 and again in Loop 3→4 — both fixes landed in the integration layer, not the class boundary. Today the only production call site (`hooks.py`) does it correctly and `grep` confirms `evaluate()` has no other non-test caller, so there is no live bypass; but "refuse ⇒ contained" is not structurally guaranteed. Fold redaction into `TrustGate` (or return an already-contained result) so a future caller can't reintroduce the gap.

**Unresolved HIGH/CRITICAL: 0.** No CRITICAL. (2 MEDIUM open: global monotonic Biba floor; containment-invariant lives one layer up from `TrustGate`.)

**Top remaining gaps for next loop:**
1. Move the containment invariant into `TrustGate` so `refuse` structurally implies a contained result — remove the "integration layer must remember to redact" foot-gun (the MEDIUM above).
2. Per-tool `required_integrity` labels + a session compartment/reset story for the global-floor MEDIUM.
3. Real fast-agent LLM loop — needs the clone; today's `driver.py` drives the real hook seam but stubs the LLM turn.
4. Packet-level tcpdump capture — needs interactive sudo; app-level `captures/mitm.jsonl` remains the standing on-wire artifact.

### Loop 5 — REAL fast-agent conformance + platform trust-floor/enforce truth-fixes (2026-07-24)

Purpose: the 3-critic (Codex) REJECTED Article 4 for code-verified overclaims. This loop makes the four contested claims TRUE, with runnable proof. Two repos touched. **No commits — left for the user.**

**WI-2 — REAL fast-agent conformance (the hard one). DONE, real.**
- Installed `fast-agent-mcp` 0.9.22 into `.venv` (`pip install fast-agent-mcp`; network was up — the scratchpad clone at `.../scratchpad/fast-agent` was used only to read the contract, not needed at runtime).
- **The old `consumer/hooks.py` was SYNC one-arg `after_tool_call(context)` — it did NOT match fast-agent's real contract.** Wired into real fast-agent it would have raised on the missing `runner` arg / wrong shape, and fast-agent CATCHES hook exceptions (`tool_runner.py` `generate_tool_call_response` ~639) and continues with the ORIGINAL result = fail-OPEN — the exact bypass Article 4 claims to prevent.
- Rewrote `hooks.py` to the REAL contract: **async two-arg** `after_tool_call(runner, message)` / `before_tool_call(runner, request)`, awaited by fast-agent. Operates on `message.tool_results` (dict of `mcp.types.CallToolResult`); resolves `tool_name` from `runner._pending_tool_request` (the authoritative, signature-bound source); redacts each poisoned `CallToolResult` IN PLACE (content→stub, `structuredContent`+`_meta` nulled) and never raises (fail-open-safe). `before_tool_call` raising IS fail-closed there — fast-agent turns it into a tool error response, so the privileged tool never runs.
- New `consumer/fastagent_runner.py` drives the REAL `fast_agent.agents.tool_runner.ToolRunner.generate_tool_call_response()` with a fake tool-loop agent (only the LLM is stubbed). fast-agent's OWN code `await`s our hook and uses the mutated message for the next turn ⇒ **redaction provably happens BEFORE the model turn.**
- **Non-vacuity proven:** `tests/test_fastagent_conformance.py::test_non_vacuous_neuter_hook_leaks_poison` — with a neuter (do-nothing) hook the SAME poison SURVIVES into the message the model would consume. So a broken/no-op hook fails the suite; the green is load-bearing.
- One real subtlety fixed: pydantic `CallToolResult.model_dump(by_alias=True)` re-adds `annotations:None,_meta:None` to each content item, which changes the JCS canonical bytes and breaks `content_hash` for otherwise-valid results — `_result_to_dict` now dumps with `exclude_none=True` to match what the signer signed.
- `consumer/driver.py` + `run_demo.sh` now route the whole 8-case socket demo through the REAL ToolRunner too (not a stand-in `Ctx`). **All 8 socket cases + 19 pytest tests pass** (`tests/test_hooks.py` rewritten to the real path, `tests/test_fastagent_conformance.py` added, `tests/test_harness.py` unchanged).
- Honesty note: fast-agent needs an LLM for a *full* turn; a live LLM was not driven. Per the task's allowance, the REAL fast-agent ToolRunner hook-firing path is driven with a fake model — the point (fast-agent's real code calls our conformant hook and the result is redacted pre-model) is proven directly, non-vacuously.

**Platform-side (mcp-security-platform, branch `feat/trust-envelope-consumer`) — WI-1, WI-3, WI-4.** Summarised here because Article 4 cites both repos; full detail in that repo's `CHANGES-article4-truth.md`.
- **WI-1 taint floor notify-vs-enforce, BOTH real + tested.** New `TAINT_FLOOR_MODE=notify|enforce` (config) + pure `resolve_taint_action(decision, mode)` helper; `invocation.py` Step 1.6 now branches: enforce ⇒ raises the (already router-wired) `TaintFloorDenyError` ⇒ 403 / JSON-RPC error, audited `outcome="deny"`; notify ⇒ current allow-with-disclaimer. Tests both modes end-to-end + the pure helper (incl. unknown-mode degrades to notify, never silently starts denying).
- **WI-3 full reason coverage.** ENFORCE now denies on ANY non-accepted verdict (`trust_enforce_denies(enforce, verdict) = enforce and not verdict.accepted`), replacing the 4-reason `startswith` allowlist. Test proves a **stale** and an **EKU-rejected** envelope — reasons the OLD allowlist MISSED (advisory-logged then returned) — now DENY. REST invoke path (`routers/tools.py`) scoped-in-comments as signer-only.
- **WI-4 enforce-semantics decision (the reconciliation the article must cite).** Documented in code at the enforce seam: the gateway ENFORCE verifies its OWN freshly-signed envelope, so it CANNOT catch a downstream wire MITM (that tamper happens after signing); it only guarantees "don't emit a result we can't self-verify". End-to-end integrity against a MITM is the INDEPENDENT CONSUMER's job (this harness's `TrustGate` against a pinned anchor). The article must not conflate the two.

**Still not done (honestly):** a real LLM turn (fake model drives the real hook path — sufficient for the conformance claim, but not a live agent conversation); the two Loop-4 MEDIUMs (global monotonic Biba floor; containment invariant lives in `hooks.py` not `TrustGate`) are unchanged.

### Code loop 1 — verify the four Article-4 truth-fixes are real, tested, and non-vacuous (2026-07-24)

Purpose: an independent code-review + 3-critic pass on the Loop 5 work items (WI-1..WI-4, spanning this harness and `mcp-security-platform` branch `feat/trust-envelope-consumer`). Goal was to confirm each contested Article-4 claim is code-verified — real implementation, real test, and the test bites (non-vacuous). **No commits.**

**What shipped per WI (verified present, not just claimed):**
- **WI-1 — taint floor notify-vs-enforce.** Real mode selector `resolve_taint_action(decision, mode)` at `proxy/app/services/taint_floor.py:93` returns `TAINT_ACTION_BLOCK` (`"block"`) iff `mode=="enforce"`, else `"notify"`. Config default `TAINT_FLOOR_MODE="notify"` (`config.py:147`). `invocation.py:650-712` drives it: `_action==BLOCK` ⇒ audit deny + raise `TaintFloorDenyError` (403 / JSON-RPC error); `_action=="notify"` ⇒ allow + `_taint_notice` in `_meta`, `outcome="allow"` audit.
- **WI-2 — REAL fast-agent conformance.** `consumer/hooks.py` async two-arg contract + `consumer/fastagent_runner.py` driving the real `ToolRunner.generate_tool_call_response()`; redaction proven to happen pre-model turn (this harness, unchanged from Loop 5).
- **WI-3 — full reason coverage in enforce.** `trust_enforce_denies(enforce, verdict) = enforce and not verdict.accepted` replaces the 4-reason `startswith` allowlist; stale + EKU-rejected envelopes (missed by the old allowlist) now DENY.
- **WI-4 — enforce-semantics reconciliation.** Documented at the enforce seam: the gateway self-verifies its OWN freshly-signed envelope (cannot catch a downstream wire MITM — that is the independent consumer's job against a pinned anchor). Article must not conflate the two.

**3-critic verdict (Codex critic): `wi_true = {WI1: true, WI2: true, WI3: true, WI4: true}`, `still_false = []`.** All four contested claims are now code-verified true; nothing left false.

**Critic evidence (WI-1 taint floor — notify vs enforce, both real + tested + comparable):**
- Real, comparable code paths as above (`taint_floor.py:93`, `config.py:147`, `invocation.py:650-712`).
- Test run (`proxy/.venv/bin/python -m pytest ... -v`): **5 passed in 0.29s**
  - `tests/unit/test_taint_floor.py::test_deny_in_enforce_mode_blocks`
  - `tests/unit/test_taint_floor.py::test_deny_in_notify_mode_notifies`
  - `tests/unit/test_taint_floor.py::test_unknown_mode_degrades_to_notify_never_blocks`
  - `tests/unit/services/test_invocation_taint_notices.py::test_taint_enforce_mode_denies_and_audits_deny`
  - `tests/unit/services/test_invocation_taint_notices.py::test_taint_notify_only_call_site_emits_empty_deny_reasons_and_notice`
- **Non-vacuous:** the enforce test patches `TAINT_FLOOR_MODE="enforce"` and calls the REAL `inv_mod.invoke_tool(...)`, asserting `pytest.raises(TaintFloorDenyError)` + exactly one `outcome=="deny"` audit carrying a `taint_floor` deny_reason; the notify test asserts `deny_reasons==[]` + the notice text. Full taint-floor test file: 28 passed.

**Remaining `still_false`: none.** All four WIs verified true; the two Loop-4 MEDIUMs (global monotonic Biba floor; containment invariant living in `hooks.py` rather than `TrustGate`) remain open design notes, unchanged. Real live-LLM turn still stubbed (fake model over the real hook path).

### Loop 6 — demonstrate why the envelope crosses a boundary (2026-08-01)

- Added `federation/producer.py`, `relay.py`, and `consumer.py` as separate socket processes representing Org A, an untrusted intermediary, and Org B.
- Org A's one server returns both rank-2 internal content and rank-0 public-writable content. This makes the comparison non-vacuous: default-trusted unsigned handling permits the attack action, while default-untrusted unsigned handling blocks legitimate work.
- Signed per-result handling achieves both outcomes: internal work proceeds, public poison lowers the floor and blocks the privileged action, and a relay attempt to raise rank 0→2 fails with `signature_invalid`.
- `tests/test_federation_demo.py` asserts all five comparison cases plus ten captured relay frames. Verified with the shipped verifier environment: **1 federation test passed; 23 federation + existing regression tests passed** after normal APT runtime setup.
- Clarified that “RFC §6 federation” is not an IETF RFC. It refers to internal RFC-0002, whose current executable oracle places federation/trust-scope in §5 and AI provenance in §6. Full trust-list governance, scope ceilings, transparency, revocation, and rollback protection remain out of scope for this demo.
