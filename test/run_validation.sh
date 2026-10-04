#!/usr/bin/env bash
# Basic end-to-end validation. Run from anywhere; uses absolute paths.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Per-run scratch dir: fixed /tmp paths made parallel runs collide.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
ARCH="${ARCH:-$(uname -m)}"
LIB="$ROOT/build/$ARCH/libcov_st.so"
TARGET="$ROOT/build/$ARCH/target_simple"
LCV="$WORK/target_simple.lcv"
SHM="$WORK/libcov_validate"

if [[ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]]; then
    echo "WARN: ASLR is on; PoC assumes ASLR off for deterministic addresses" >&2
fi

[[ -f "$LIB" ]]   || { echo "missing $LIB. Run 'make' first." >&2; exit 1; }
[[ -x "$TARGET" ]] || { echo "missing $TARGET" >&2; exit 1; }

echo ">> regenerate patch list"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV" \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline)$'

# The shm file starts with a 72-byte libcov_shm_header followed by the
# live bitmap (hdr->map_size bytes, auto-sized) and the snapshot ring;
# shm_bitmap.py reads the layout from the header. The legacy single-bitmap
# checks below only care about the bitmap region. Use python to avoid
# the SIGPIPE-vs-pipefail interaction of a tail|head pipeline.
extract_bitmap() {
    python3 "$ROOT/test/shm_bitmap.py" extract "$1" "$2"
}

run_one() {
    local mode="$1" input="$2" out="$3"
    rm -f "$SHM"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_MODE="$mode" \
        LIBCOV_LOG=/dev/null LD_PRELOAD="$LIB" "$TARGET" "$input" > "$out"
    extract_bitmap "$SHM" "$out.bitmap"
}

echo ">> oneshot: same input twice should produce identical bitmap"
run_one oneshot 42 $WORK/v_a
run_one oneshot 42 $WORK/v_b
diff -q $WORK/v_a.bitmap $WORK/v_b.bitmap || { echo "FAIL: oneshot non-deterministic"; exit 1; }
echo "   OK"

echo ">> oneshot: different inputs should differ"
run_one oneshot 42  $WORK/v_42
run_one oneshot -3  $WORK/v_neg
if cmp -s $WORK/v_42.bitmap $WORK/v_neg.bitmap; then
    echo "FAIL: bitmaps identical for different inputs"; exit 1
fi
echo "   OK"

echo ">> leapfrog: should record hit-counts > 1 (loop iterations)"
run_one leapfrog 99 $WORK/v_lf
max=$(python3 -c "import sys; d=open('$WORK/v_lf.bitmap','rb').read(); print(max(d))")
if [[ "$max" -lt 2 ]]; then
    echo "FAIL: leapfrog never recorded a multi-hit (max=$max)"; exit 1
fi
echo "   OK (max hits = $max)"

echo ">> target output unchanged under libcov"
LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_MODE=leapfrog \
    LIBCOV_LOG=/dev/null LD_PRELOAD="$LIB" "$TARGET" 42 > $WORK/v_with
"$TARGET" 42 > $WORK/v_without
diff -q $WORK/v_with $WORK/v_without || { echo "FAIL: target output differs"; exit 1; }
echo "   OK"

echo
echo "ALL VALIDATIONS PASSED"
