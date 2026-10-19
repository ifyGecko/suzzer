#!/usr/bin/env bash
# The brain against an executor that is not suzzer-relay.
#
# test/fake_executor.py implements SZR1 from docs/FORMATS.md alone (no
# libcov, no relay, a made-up "fake32" arch, ring_size 1). Against it the
# brain must:
#
#   1. complete a session: HELLO, the unsolicited id-0 INIT snapshot is
#      skipped (not scored, not taken as a reply), every input gets its own
#      reply, the run ends with BYE and exit 0;
#   2. name the executor-neutral crash reasons (GUEST_FAULT, ORACLE, HANG,
#      TIMEOUT) in its log and .info sidecars, with the status of
#      GUEST_FAULT / ORACLE in hex;
#   3. keep an unknown reason (42) as an opaque crash, dedup key
#      (reason, status);
#   4. save HANG / TIMEOUT inputs under hangs/, count them apart from
#      crashes in the status feed (and status_tui shows them), and not
#      minimize them -- unless --minimize-timeouts;
#   5. end cleanly when the executor sends BYE instead of a reply -- and
#      when that happens mid-minimization, the crash is already saved;
#   6. not score the INIT snapshot (the final edge count is exactly the
#      union of the inputs' coverage), keep every distinct hang input, and
#      minimize a fault only to inputs with the same status (fault PC);
#   7. exit with an error when a reply carries the wrong id.
#
# Needs only python3; no target, no libcov.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v python3 >/dev/null || { echo "SKIP: python3 not found"; exit 0; }

WORK=$(mktemp -d)
BRAIN_PID=""
cleanup() {
    local rc=$?
    [[ -n "$BRAIN_PID" ]] && kill "$BRAIN_PID" 2>/dev/null || true
    if [[ $rc -eq 0 ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK" >&2; fi
    return $rc
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# Seeds load in name order, so the order the brain replays them is known.
mkdir -p "$WORK/seeds"
printf 'Ahello'   > "$WORK/seeds/1_a"
printf 'Gfault'   > "$WORK/seeds/2_g"
printf 'Gsame'    > "$WORK/seeds/3_g"    # same (reason, status): a dup
printf 'Hhang'    > "$WORK/seeds/4_h"
printf 'Ooracle'  > "$WORK/seeds/5_o"
printf 'Ttimeout' > "$WORK/seeds/6_t"
printf 'Zunknown' > "$WORK/seeds/7_z"
printf 'Bworld'   > "$WORK/seeds/8_b"

# run_session NAME [brain args...]: brain + fake executor, both must exit 0.
# EXEC_ARGS (array) goes to the executor; BRAIN_RC_OK=1 lets either side
# fail (the brain's rc is left in BRAIN_RC).
EXEC_ARGS=()
BRAIN_RC_OK=0
run_session() {
    local name=$1; shift
    local log="$WORK/$name.brain.log"
    ( cd "$ROOT" && timeout 60 python3 tools/suzzer_brain.py \
          --listen 127.0.0.1:0 --seeds "$WORK/seeds" --out "$WORK/$name" \
          --seed-rng 1 --io-timeout 20 --accept-timeout 20 \
          --status-file "$WORK/$name.jsonl" "$@" ) > "$log" 2>&1 &
    BRAIN_PID=$!
    local port=""
    for _ in $(seq 1 200); do
        port=$(sed -n 's/.*listening on 127\.0\.0\.1:\([0-9]*\).*/\1/p' "$log" | head -1)
        [[ -n "$port" ]] && break
        kill -0 "$BRAIN_PID" 2>/dev/null || fail "$name: brain exited early: $(cat "$log")"
        sleep 0.05
    done
    [[ -n "$port" ]] || fail "$name: brain never announced a port"
    timeout 60 python3 "$ROOT/test/fake_executor.py" --brain "127.0.0.1:$port" \
        --record "$WORK/$name.inputs" "${EXEC_ARGS[@]}" > "$WORK/$name.exec.log" 2>&1 \
        || [[ $BRAIN_RC_OK == 1 ]] \
        || fail "$name: fake executor failed: $(cat "$WORK/$name.exec.log")"
    BRAIN_RC=0
    wait "$BRAIN_PID" || BRAIN_RC=$?
    BRAIN_PID=""
    [[ $BRAIN_RC -eq 0 || $BRAIN_RC_OK == 1 ]] \
        || fail "$name: brain exited $BRAIN_RC: $(cat "$log")"
}

# next_after NAME TEXT: the input the brain sent right after TEXT.
next_after() {
    local hex; hex=$(printf '%s' "$2" | od -An -tx1 | tr -d ' \n')
    awk -v h="$hex" 'f { print; exit } $0 == h { f = 1 }' "$WORK/$1.inputs" \
        | xxd -r -p
}

echo ">> 1. a session with an executor that is not suzzer-relay"
run_session default --iters 5
L="$WORK/default.brain.log"
grep -q "HELLO proto=1 arch=fake32 map_size=512 ring=1" "$L" || fail "HELLO not logged: $(cat "$L")"
grep -q "executor connected from" "$L" || fail "connect message does not say 'executor'"
grep -q "executor sent its INIT snapshot" "$L" || fail "id-0 INIT snapshot not recognised"
grep -q "new coverage .* from b'Ahello'" "$L" || fail "no coverage scored for Ahello"
grep -q "done: execs=" "$L" || fail "no summary"
echo "   OK: HELLO, INIT skipped, lockstep replies, BYE, exit 0"

echo ">> 2. new crash reasons are named; GUEST_FAULT / ORACLE status in hex"
grep -q "CRASH id=.* reason=5(GUEST_FAULT) status=0x80001234 NEW" "$L" || fail "GUEST_FAULT: $(grep CRASH "$L")"
grep -q "CRASH id=.* reason=6(ORACLE) status=0x2a NEW" "$L" || fail "ORACLE: $(grep CRASH "$L")"
grep -q "HANG id=.* reason=7(HANG) status=0 NEW" "$L" || fail "HANG: $(grep HANG "$L")"
grep -q "HANG id=.* reason=8(TIMEOUT) status=1000 NEW" "$L" || fail "TIMEOUT: $(grep HANG "$L")"
info=$(cat "$WORK"/default/crashes/crash_r5_*.info) || fail "no GUEST_FAULT .info"
grep -qx "reason_name=GUEST_FAULT" <<<"$info" || fail "GUEST_FAULT .info: $info"
grep -qx "status_hex=0x80001234" <<<"$info" || fail "GUEST_FAULT .info status: $info"
grep -qx "sig=r5/s-2147478988" <<<"$info" || fail "GUEST_FAULT dedup key: $info"
grep -qx "status_hex=0x2a" "$WORK"/default/crashes/crash_r6_*.info || fail "ORACLE .info"
echo "   OK: named in log and .info; hex status"

echo ">> 3. an unknown reason is an opaque crash, dedup by (reason, status)"
grep -q "CRASH id=.* reason=42(r42) status=7 NEW" "$L" || fail "reason 42: $(grep CRASH "$L")"
grep -qx "reason_name=r42" "$WORK"/default/crashes/crash_r42_s7_*.info || fail "reason 42 .info"
grep -q "reason=5(GUEST_FAULT) status=0x80001234 dup (count=2" "$L" \
    || fail "second GUEST_FAULT with the same status not deduplicated"
echo "   OK: r42 saved; same (reason, status) deduplicated"

echo ">> 4. hangs/timeouts: saved apart, counted apart, not minimized"
ls "$WORK"/default/hangs/hang_r7_s0_* >/dev/null 2>&1 || fail "no HANG under hangs/"
ls "$WORK"/default/hangs/hang_r8_s1000_* >/dev/null 2>&1 || fail "no TIMEOUT under hangs/"
ls "$WORK"/default/crashes/*_r7_* "$WORK"/default/crashes/*_r8_* >/dev/null 2>&1 \
    && fail "hangs saved under crashes/"
python3 - "$WORK/default.jsonl" <<'EOF'
import json, sys
snaps = [o for o in map(json.loads, open(sys.argv[1])) if "execs" in o]
last = snaps[-1]
# Mutated inputs may crash too (same first byte), so totals are lower
# bounds; the unique counts are exact (status is fixed per reason).
got = {k: last.get(k) for k in ("crashes", "crashes_unique", "hangs", "hangs_unique")}
if not (got["crashes"] >= 4 and got["crashes_unique"] == 3 and got["hangs"] >= 2
        and got["hangs_unique"] == 2 and last.get("finished")):
    sys.exit(f"FAIL: status feed {got} finished={last.get('finished')}")
if last["config"].get("executor") is None or last["config"].get("arch") != "fake32":
    sys.exit(f"FAIL: run config {last['config']}")
kinds = [o["event"]["kind"] for o in map(json.loads, open(sys.argv[1])) if "event" in o]
if kinds.count("hang") != 2 or kinds.count("crash") != 3:   # NEW ones only
    sys.exit(f"FAIL: events {kinds}")
EOF
board=$(python3 "$ROOT/tools/status_tui.py" --input "$WORK/default.jsonl" --dump)
grep -q "total hangs *: *[0-9]* *(2 unique)" <<<"$board" || fail "status_tui hangs: $board"
grep -q "total crashes *: *[0-9]* *(3 unique)" <<<"$board" || fail "status_tui crashes: $board"
[[ "$(next_after default Hhang)" == Ooracle ]] || fail "HANG input was minimized (next input: $(next_after default Hhang))"
[[ "$(next_after default Ttimeout)" == Zunknown ]] || fail "TIMEOUT input was minimized"
[[ "$(next_after default Gfault)" != Gsame ]] || fail "GUEST_FAULT input was not minimized"
echo "   OK: hangs/ apart from crashes/, feed and board count them apart; only crashes minimized"

echo ">> 4b. --minimize-timeouts opts in"
run_session mint --iters 1 --minimize-timeouts
[[ "$(next_after mint Hhang)" != Ooracle ]] || fail "--minimize-timeouts did not minimize the HANG"
echo "   OK: HANG minimized with --minimize-timeouts"

echo ">> 5. executor-initiated BYE ends the session cleanly"
printf 'Quit' > "$WORK/seeds/9_q"
run_session bye --iters 1000
grep -q "executor said BYE; ending the session" "$WORK/bye.brain.log" || fail "BYE not handled: $(cat "$WORK/bye.brain.log")"
echo "   OK: brain exits 0 on BYE"

rm -f "$WORK/seeds/9_q"

echo ">> 5b. BYE during minimization: the crash was saved before minimizing"
mkdir -p "$WORK/seeds_g"; printf 'Gfault-long-input' > "$WORK/seeds_g/g"
( cd "$ROOT" && timeout 60 python3 tools/suzzer_brain.py --listen 127.0.0.1:0 \
      --seeds "$WORK/seeds_g" --out "$WORK/byemin" --io-timeout 20 \
      --accept-timeout 20 ) > "$WORK/byemin.brain.log" 2>&1 &
BRAIN_PID=$!
port=""
for _ in $(seq 1 200); do
    port=$(sed -n 's/.*listening on 127\.0\.0\.1:\([0-9]*\).*/\1/p' "$WORK/byemin.brain.log" | head -1)
    [[ -n "$port" ]] && break; sleep 0.05
done
[[ -n "$port" ]] || fail "byemin: brain never announced a port"
timeout 60 python3 "$ROOT/test/fake_executor.py" --brain "127.0.0.1:$port" \
    --record "$WORK/byemin.inputs" --bye-after-crash >/dev/null 2>&1 || true
wait "$BRAIN_PID" || true; BRAIN_PID=""
f=$(ls "$WORK"/byemin/crashes/crash_r5_* 2>/dev/null | grep -v '\.info$' | head -1 || true)
[[ -n "$f" && "$(cat "$f")" == "Gfault-long-input" ]] \
    || fail "crash lost when the executor left mid-minimization: $(cat "$WORK/byemin.brain.log")"
echo "   OK: original crash input on disk"

echo ">> 6. INIT not scored; distinct hangs kept; minimize keeps the fault PC"
run_session nomin --iters 30 --no-minimize
python3 - "$WORK/nomin.jsonl" "$WORK/nomin.inputs" "$WORK/nomin/hangs" <<'EOF'
import json, os, sys
feed, inputs, hangs = sys.argv[1:]
last = [o for o in map(json.loads, open(feed)) if "execs" in o][-1]
seen = [bytes.fromhex(l.strip()) for l in open(inputs)]
cov = set()
for d in seen:
    if not d or d[0] not in b"GOHTZQ":
        cov |= set(d)
if last["edges"] != len(cov):
    sys.exit(f"FAIL: edges {last['edges']} != {len(cov)} distinct bytes of the "
             f"covered inputs (INIT bucket scored?)")
want = {d for d in seen if d and d[0] in b"HT"}
got = {open(os.path.join(hangs, n), "rb").read() for n in os.listdir(hangs)
       if not n.endswith(".info")}
if got != want:
    sys.exit(f"FAIL: hangs/ holds {len(got)} inputs, executor saw {len(want)} distinct")
print(f"   OK: edges={last['edges']} (INIT bucket not counted); {len(got)} distinct hang inputs kept")
EOF
for f in "$WORK"/default/crashes/crash_r5_s-2147478988_*; do
    [[ $f == *.info ]] && continue
    [[ $(wc -c < "$f") -ge 4 ]] || fail "GUEST_FAULT minimized into an input that faults at another PC: $(cat "$f")"
done
echo "   OK: minimized GUEST_FAULT input still faults at 0x80001234"

echo ">> 7. a reply with the wrong id is a protocol error"
EXEC_ARGS=(--bad-id); BRAIN_RC_OK=1
run_session badid --iters 1
EXEC_ARGS=(); BRAIN_RC_OK=0
[[ $BRAIN_RC -ne 0 ]] || fail "brain accepted a reply with the wrong id"
grep -q "lockstep broken" "$WORK/badid.brain.log" || fail "no lockstep error: $(cat "$WORK/badid.brain.log")"
echo "   OK: brain exits $BRAIN_RC (lockstep broken)"

echo
echo "ALL BRAIN/EXECUTOR VALIDATIONS PASSED"
