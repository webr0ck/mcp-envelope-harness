#!/usr/bin/env bash
# End-to-end demo over REAL localhost sockets: producer -> MITM -> consumer.
# For each case, starts a MITM in the right mode, runs the wire result through the
# REAL fast-agent hook seam (consumer.hooks.before/after_tool_call via consumer.driver),
# and checks BOTH: observed action == expected AND (on refuse) the poisoned bytes were
# actually redacted out of the wire result. Exits NON-ZERO on any failing case. Reproducible.
#
# Artifacts: logs/verdicts.jsonl (one verdict/action per case),
#            captures/mitm.jsonl (app-level on-the-wire frame dump incl. the _meta envelope),
#            captures/tcpdump.txt (best-effort loopback capture; needs sudo, see HOWTO).
set -u
cd "$(dirname "$0")"
PY=.venv/bin/python
PROD_PORT=8811
MITM_PORT=8899
ANCHOR=.run/sub_ca.pem
mkdir -p logs captures .run
: > logs/verdicts.jsonl
: > captures/mitm.jsonl
# Durable replay cache is shared across the per-case consumer processes AND persists
# across runs (that's the point — it survives restart). Clear it once at demo start so
# a rerun doesn't refuse `valid` as an already-seen envelope.
rm -f .run/replay_cache.db .run/replay_cache.db-wal .run/replay_cache.db-shm

cleanup() { [ -n "${PROD_PID:-}" ] && kill "$PROD_PID" 2>/dev/null; [ -n "${MITM_PID:-}" ] && kill "$MITM_PID" 2>/dev/null; }
trap cleanup EXIT

wait_port() { for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; }; sleep 0.1; done; return 1; }

# ── producer (long-lived; writes the pinned anchor) ────────────────────────
$PY -m producer.server --port $PROD_PORT --anchor $ANCHOR & PROD_PID=$!
wait_port $PROD_PORT || { echo "producer failed to start"; exit 2; }

# ── best-effort loopback tcpdump (non-interactive; do NOT hang on a password) ─
# sudo -n returns immediately if it would prompt, so this never blocks on a password.
if sudo -n true 2>/dev/null; then
  sudo -n tcpdump -i lo0 -c 40 -w captures/loopback.pcap "tcp port $MITM_PORT" >captures/tcpdump.txt 2>&1 &
  TCPDUMP_PID=$!; echo "tcpdump: non-interactive loopback capture started (pid $TCPDUMP_PID)"
else
  echo "tcpdump: skipped (sudo -n unavailable) — app-level captures/mitm.jsonl is the primary artifact" | tee captures/tcpdump.txt
fi

# case -> mitm mode (bash 3.2 on macOS: no associative arrays -> case statement).
# stale/valid/layer_b pass through the MITM; the producer emits the edge via query params.
mode_for() {
  case "$1" in
    mitm_tamper) echo tamper ;;
    rogue_cert)  echo rogue_cert ;;
    no_envelope) echo strip_meta ;;
    replay)      echo replay ;;
    replay_seen) echo replay_cache ;;
    *)           echo passthrough ;;   # valid, stale, layer_b
  esac
}

FAIL=0
for c in valid mitm_tamper rogue_cert no_envelope replay replay_seen stale layer_b; do
  $PY -m attacks.mitm --port $MITM_PORT --producer-port $PROD_PORT --mode "$(mode_for "$c")" \
      --capture captures/mitm.jsonl & MITM_PID=$!
  wait_port $MITM_PORT || { echo "[$c] mitm failed to start"; FAIL=1; continue; }
  $PY -m consumer.driver --case "$c" --url "http://127.0.0.1:$MITM_PORT/tool" \
      --anchor $ANCHOR --tool import_conversation --result-id "rid-$c" --log logs/verdicts.jsonl
  [ $? -ne 0 ] && FAIL=1
  kill "$MITM_PID" 2>/dev/null; wait "$MITM_PID" 2>/dev/null; MITM_PID=""
done

[ -n "${TCPDUMP_PID:-}" ] && { kill "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null; }

echo "----"
echo "verdicts: $(wc -l < logs/verdicts.jsonl) lines -> logs/verdicts.jsonl"
echo "wire cap: $(wc -l < captures/mitm.jsonl) frames -> captures/mitm.jsonl"
if [ $FAIL -eq 0 ]; then echo "ALL CASES PASSED"; else echo "SOME CASES FAILED"; fi
exit $FAIL
