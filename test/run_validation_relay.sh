#!/usr/bin/env bash
# Remote (over-IP) fuzzing template, end to end on loopback.
#
# Exercises the real pieces a remote setup ships -- the on-device relay
# (tools/suzzer-relay), the off-device brain (tools/suzzer_brain.py), and the
# template daemon (test/target_netd) -- with everything on 127.0.0.1:
#
#   1. HELLO is negotiated (the brain learns map_size/arch from the relay).
#   2. Distinct seeds (A.., B.., C..) each reach NEW coverage -- i.e. the
#      coverage genuinely discriminates inputs across the network.
#   3. A planted crash input (X..) comes back as a CRASH frame and is saved.
#   4. The brain finishes cleanly, growing its corpus (edges > 0).
#
# Native only: the binaries run on the host over real TCP. A cross run would
# need qemu-user TCP for both daemon and relay (finicky); not covered here.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"

if [[ "$ARCH" != "$(uname -m)" ]]; then
    echo "SKIP: the relay template runs natively over TCP (ARCH=$ARCH)"
    exit 0
fi
command -v python3 >/dev/null || { echo "SKIP: python3 not found (brain needs it)"; exit 0; }
[[ -e "$B/libcov_st.so" ]] || { echo "missing $B/libcov_st.so. Run 'make'." >&2; exit 1; }

# Build the template-specific artifacts on demand (like the demalloc suite).
make -C "$ROOT/test"  ARCH="$ARCH" BUILD="$B" netd  >/dev/null 2>&1 \
    || { echo "FAIL: could not build target_netd" >&2; exit 1; }
make -C "$ROOT/tools" ARCH="$ARCH" BUILD="$B" relay >/dev/null 2>&1 \
    || { echo "FAIL: could not build suzzer-relay" >&2; exit 1; }

WORK=$(mktemp -d)
BRAIN_PID=""; RELAY_PID=""
cleanup() {
    local rc=$?
    [[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2>/dev/null || true
    [[ -n "$BRAIN_PID" ]] && kill "$BRAIN_PID" 2>/dev/null || true
    # Reap any target the relay left behind.
    pkill -P "${RELAY_PID:-0}" 2>/dev/null || true
    # Kept (and its path printed) when the suite fails.
    if [[ $rc -eq 0 ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK" >&2; fi
    return $rc
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

echo ">> generate patchlist + paired boundary sidecar for target_netd"
"$ROOT/tools/gen_patchlist.py" "$B/target_netd" "$WORK/n.lcv" --root main \
    >/dev/null 2>&1 || fail "gen_patchlist"
"$ROOT/tools/gen_boundary.py" "$B/target_netd" "$WORK/n.lcvb" \
    req_begin:begin req_end:end --patchlist "$WORK/n.lcv" >/dev/null 2>&1 \
    || fail "gen_boundary (are req_begin/req_end patched sites?)"

mkdir -p "$WORK/seeds"
printf 'Ahello'  > "$WORK/seeds/a"
printf 'Bzork'   > "$WORK/seeds/b"
printf 'Cworld!' > "$WORK/seeds/c"
printf 'Xboom'   > "$WORK/seeds/x"   # planted crash (handle() aborts on 'X')

echo ">> run brain (loopback) + relay + target_netd"
# Brain listens on an ephemeral port and prints it; relay then dials in.
( cd "$ROOT" && timeout 60 python3 tools/suzzer_brain.py \
      --listen 127.0.0.1:0 --seeds "$WORK/seeds" --out "$WORK/out" \
      --iters 40 --seed-rng 1 ) > "$WORK/brain.log" 2>&1 &
BRAIN_PID=$!

PORT=""
for _ in $(seq 1 200); do
    PORT=$(sed -n 's/.*listening on 127\.0\.0\.1:\([0-9]*\).*/\1/p' "$WORK/brain.log" 2>/dev/null | head -1)
    [[ -n "$PORT" ]] && break
    kill -0 "$BRAIN_PID" 2>/dev/null || fail "brain exited early: $(cat "$WORK/brain.log")"
    sleep 0.05
done
[[ -n "$PORT" ]] || fail "brain never announced a port: $(cat "$WORK/brain.log")"

timeout 60 "$B/suzzer-relay" --brain "127.0.0.1:$PORT" --port-file "$WORK/pf" \
    --libcov "$B/libcov_st.so" --patchlist "$WORK/n.lcv" \
    --boundary "$WORK/n.lcvb" --shm "$WORK/cov" \
    -- "$B/target_netd" "$WORK/pf" > "$WORK/relay.log" 2>&1 &
RELAY_PID=$!

rc=0; wait "$BRAIN_PID" || rc=$?
kill "$RELAY_PID" 2>/dev/null || true
[[ $rc -eq 0 ]] || fail "brain exited $rc. brain.log:
$(cat "$WORK/brain.log")
relay.log (tail):
$(tail -15 "$WORK/relay.log")"

echo "----- brain.log -----"; cat "$WORK/brain.log"; echo "---------------------"

# 1. HELLO negotiated.
grep -q "HELLO proto=" "$WORK/brain.log" || fail "no HELLO negotiated"
grep -q "HELLO .* scheme=n=2 model=site rotate=0" "$WORK/brain.log" \
    || fail "HELLO did not carry the default coverage scheme"
echo "   OK: HELLO negotiated over TCP (scheme n=2 model=site rotate=0)"

# 2. Each distinct seed reached new coverage (coverage discriminates inputs).
for s in Ahello Bzork 'Cworld!'; do
    grep -qF "new coverage" "$WORK/brain.log" || fail "no new-coverage reports"
    grep -qF "from b'$s'" "$WORK/brain.log" \
        || fail "seed '$s' produced no new coverage (coverage not discriminating?)"
done
echo "   OK: seeds A../B../C.. each reached distinct new coverage"

# 3. The planted crash came back as CRASH and was saved.
grep -q "CRASH id=.* reason=2" "$WORK/brain.log" \
    || fail "planted crash input not reported as a signal CRASH"
ls "$WORK/out/crashes"/* >/dev/null 2>&1 || fail "no crash file saved"
echo "   OK: planted crash reported (SIGABRT) and saved to crashes/"

# 4. Clean finish with a grown corpus.
# The planted crash was already verified deterministically in step 3. The
# brain is a randomized mutator, so the *total* crash-event count is not fixed
# (it can re-trigger the same one bug from several mutated inputs -- e.g.
# "crashes=2 (unique=1)"); only "at least one crash was found" is stable here.
summary=$(grep "done:" "$WORK/brain.log") || fail "brain printed no summary"
crashes=$(echo "$summary" | sed -n 's/.*crashes=\([0-9]*\).*/\1/p')
[[ "${crashes:-0}" -ge 1 ]] || fail "expected at least one crash: $summary"
edges=$(echo "$summary" | sed -n 's/.* edges=\([0-9]*\).*/\1/p')
[[ "${edges:-0}" -gt 0 ]] || fail "no cumulative edges recorded: $summary"
echo "   OK: $summary"

echo
echo "ALL RELAY VALIDATIONS PASSED ($ARCH)"
