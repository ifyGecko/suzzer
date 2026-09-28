#!/usr/bin/env bash
# Signal-handling regression test (native arch, ST and MT).
#
# Every mode of target_signals must behave exactly as it does without
# libcov: same stdout, same exit status (realill must still die with
# SIGILL), and the instrumented work() must record coverage.
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

[[ $fail -eq 0 ]] && echo "ALL SIGNAL VALIDATIONS PASSED ($ARCH)" || exit 1
