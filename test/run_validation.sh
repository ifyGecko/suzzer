#!/usr/bin/env bash
# Basic end-to-end validation. Run from anywhere; uses absolute paths.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
LIB="$ROOT/build/$ARCH/libcov.so"
TARGET="$ROOT/build/$ARCH/target_simple"
LCV="/tmp/target_simple.lcv"
SHM="/tmp/libcov_validate"

if [[ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]]; then
    echo "WARN: ASLR is on; PoC assumes ASLR off for deterministic addresses" >&2
fi

[[ -f "$LIB" ]]   || { echo "missing $LIB. Run 'make' first." >&2; exit 1; }
[[ -x "$TARGET" ]] || { echo "missing $TARGET" >&2; exit 1; }

echo ">> regenerate patch list"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV" \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline)$'

run_one() {
    local mode="$1" input="$2" out="$3"
    rm -f "$SHM"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_MODE="$mode" \
        LIBCOV_LOG=/dev/null LD_PRELOAD="$LIB" "$TARGET" "$input" > "$out"
    cp "$SHM" "$out.bitmap"
}

echo ">> oneshot: same input twice should produce identical bitmap"
run_one oneshot 42 /tmp/v_a
run_one oneshot 42 /tmp/v_b
diff -q /tmp/v_a.bitmap /tmp/v_b.bitmap || { echo "FAIL: oneshot non-deterministic"; exit 1; }
echo "   OK"

echo ">> oneshot: different inputs should differ"
run_one oneshot 42  /tmp/v_42
run_one oneshot -3  /tmp/v_neg
if cmp -s /tmp/v_42.bitmap /tmp/v_neg.bitmap; then
    echo "FAIL: bitmaps identical for different inputs"; exit 1
fi
echo "   OK"

echo ">> leapfrog: should record hit-counts > 1 (loop iterations)"
run_one leapfrog 99 /tmp/v_lf
max=$(python3 -c "import sys; d=open('/tmp/v_lf.bitmap','rb').read(); print(max(d))")
if [[ "$max" -lt 2 ]]; then
    echo "FAIL: leapfrog never recorded a multi-hit (max=$max)"; exit 1
fi
echo "   OK (max hits = $max)"

echo ">> target output unchanged under libcov"
LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_MODE=leapfrog \
    LIBCOV_LOG=/dev/null LD_PRELOAD="$LIB" "$TARGET" 42 > /tmp/v_with
"$TARGET" 42 > /tmp/v_without
diff -q /tmp/v_with /tmp/v_without || { echo "FAIL: target output differs"; exit 1; }
echo "   OK"

echo
echo "ALL VALIDATIONS PASSED"
