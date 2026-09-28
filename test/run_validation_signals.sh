#!/usr/bin/env bash
# Signal-handling regression test (native arch, ST and MT).
#
# Every mode of target_signals must behave exactly as it does without
# libcov: same stdout, same exit status (realill must still die with
# SIGILL), and the instrumented work() must record coverage.
#
# MT only, for LIBCOV_SYNC_FALLBACK=auto and =tgkill: the rt* modes, which
# exercise the signal libcov_mt.so's sync broadcast owns (see
# target_signals.c). Under tgkill, also: rtown logs the hand-back, rtign
# (signal ignored before exec) logs that the fallback stayed off, and
# rtblock finishes in RTBLOCK_MAX_S seconds (a blocked peer would cost
# LIBCOV_SYNC_TIMEOUT_NS on every broadcast).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Per-run scratch dir: fixed /tmp paths made parallel runs collide.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
ARCH="${ARCH:-$(uname -m)}"
BUILD="$ROOT/build/$ARCH"
TARGET="$BUILD/target_signals"
SHM="$WORK/libcov_validate_signals"

${CC:-gcc} -O0 -g -no-pie -pthread -o "$TARGET" "$ROOT/test/target_signals.c" \
    || { echo "FAIL: build target_signals"; exit 1; }

nonzero_buckets() {
    python3 -c "
import struct,sys
d=open(sys.argv[1],'rb').read()
ms=struct.unpack_from('<I',d,8)[0]; off=struct.unpack_from('<Q',d,40)[0]
print(sum(1 for b in d[off:off+ms] if b))" "$1"
}

fail=0
for th in st mt; do
    LIB="$BUILD/libcov_$th.so"
    if [[ ! -f "$LIB" ]]; then
        echo "SKIP: $LIB missing (make THREADING=$th)"; continue
    fi
    LCV="$WORK/target_signals_$th.lcv"
    "$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV" --threading "$th" \
        --include-pat 'work$' >/dev/null 2>&1 \
        || { echo "FAIL: gen_patchlist ($th)"; fail=1; continue; }
    for mode in block tblock probe siginfo realill; do
        want_out=$("$TARGET" "$mode" 2>/dev/null); want_rc=$?
        rm -f "$SHM"
        got_out=$(LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_LOG=/dev/null \
                  LD_PRELOAD="$LIB" "$TARGET" "$mode" 2>/dev/null); got_rc=$?
        if [[ "$got_rc" != "$want_rc" || "$got_out" != "$want_out" ]]; then
            echo "FAIL: $th/$mode rc=$got_rc (want $want_rc) out=[$got_out] want=[$want_out]"
            fail=1; continue
        fi
        if [[ "$mode" != realill ]]; then
            n=$(nonzero_buckets "$SHM")
            [[ "$n" -gt 0 ]] || { echo "FAIL: $th/$mode recorded no coverage"; fail=1; continue; }
        fi
        echo "   OK: $th/$mode (rc=$got_rc)"
    done
done

RTBLOCK_MAX_S="${RTBLOCK_MAX_S:-2}"
LIB="$BUILD/libcov_mt.so"
LCV="$WORK/target_signals_mt.lcv"
run_rt() {  # <mode> [env...]: run with SIG_IGN on the sync signal for rtign
    local mode=$1; shift
    if [[ $mode == rtign ]]; then
        ( trap '' RTMAX-2; exec env "$@" "$TARGET" "$mode" )
    else
        env "$@" "$TARGET" "$mode"
    fi
}
if [[ -f "$LIB" && -f "$LCV" ]]; then
    for fb in auto tgkill; do
        for mode in rtown rtdfl rtign rtblock; do
            want_out=$(run_rt $mode 2>/dev/null); want_rc=$?
            rm -f "$SHM"
            log="$WORK/rt.$fb.$mode.log"
            start=$(date +%s%N)
            got_out=$(run_rt $mode LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" \
                      LIBCOV_LOG="$log" LIBCOV_SYNC_FALLBACK=$fb LD_PRELOAD="$LIB" \
                      2>/dev/null); got_rc=$?
            ms=$(( ($(date +%s%N) - start) / 1000000 ))
            if [[ "$got_rc" != "$want_rc" || "$got_out" != "$want_out" ]]; then
                echo "FAIL: mt/$fb/$mode rc=$got_rc (want $want_rc) out=[$got_out] want=[$want_out]"
                fail=1; continue
            fi
            if [[ $fb == tgkill ]]; then
                case $mode in
                    rtown)   grep -q 'handing it back' "$log" \
                                 || { echo "FAIL: mt/$fb/$mode: no hand-back logged"; fail=1; continue; } ;;
                    rtign)   grep -q 'already handles signal' "$log" \
                                 || { echo "FAIL: mt/$fb/$mode: fallback not refused"; fail=1; continue; } ;;
                    *)       grep -q 'tgkill broadcast fallback active' "$log" \
                                 || { echo "FAIL: mt/$fb/$mode: fallback not active"; fail=1; continue; } ;;
                esac
                if [[ $mode == rtblock && $ms -gt $((RTBLOCK_MAX_S * 1000)) ]]; then
                    echo "FAIL: mt/$fb/$mode took ${ms}ms (> ${RTBLOCK_MAX_S}s): blocked peer never acks?"
                    fail=1; continue
                fi
            fi
            echo "   OK: mt/$fb/$mode (rc=$got_rc, ${ms}ms)"
        done
    done
fi

[[ $fail -eq 0 ]] && echo "ALL SIGNAL VALIDATIONS PASSED ($ARCH)" || exit 1
