#!/usr/bin/env bash
# Native MT validation for libcov_mt.so. Drives target_simple_mt with
# multiple pthread workers hammering the same patched sites concurrently.
#
# Checks:
#   1. Patch list generated with --threading mt loads cleanly.
#   2. Multi-threaded run under libcov_mt.so does not crash.
#   3. Per-thread checksums (target output) match those from a clean run
#      with no libcov -- proves the trap-and-resume path is transparent.
#   4. Oneshot mode under MT: bitmap has edges.
#   5. Leapfrog mode under MT: bitmap has at least one site with > 1 hits
#      from concurrent thread re-entries.
#   6. All of the above again with LIBCOV_SYNC_FALLBACK=tgkill: the signal
#      broadcast that replaces membarrier(SYNC_CORE) on older kernels
#      (the script re-runs itself; a shorter stress, since every patch
#      batch then wakes every peer).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Per-run scratch dir: fixed /tmp paths made parallel runs collide.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
ARCH="${ARCH:-$(uname -m)}"
LIB="$ROOT/build/$ARCH/libcov_mt.so"
TARGET="$ROOT/build/$ARCH/target_simple_mt"
LCV="$WORK/target_simple_mt.lcv"
SHM="$WORK/libcov_validate_mt"

THREADS="${THREADS:-8}"
ITERS="${ITERS:-200}"
INPUTS=( 42 -3 0 abcdef 99 1 200 5 )

if [[ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]]; then
    echo "WARN: ASLR is on; PoC assumes ASLR off for deterministic addresses" >&2
fi

[[ -f "$LIB" ]]    || { echo "missing $LIB. Run 'make THREADING=mt' first."   >&2; exit 1; }
[[ -x "$TARGET" ]] || { echo "missing $TARGET. Run 'make -C test mt' first." >&2; exit 1; }

echo ">> generate MT patch list"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV" --threading mt \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline|worker)$' \
    >/dev/null 2>$WORK/v_mt.gen.log
records=$(python3 -c "
import struct
with open('$LCV','rb') as f: h=f.read(16)
m,v,c=struct.unpack('<4sII', h[:12])
th=h[12]
print(f'magic={m.decode()} version={v} records={c} threading={th}')")
echo "   $records"

echo ">> baseline run without libcov"
"$TARGET" "$THREADS" "$ITERS" "${INPUTS[@]}" > $WORK/v_mt.bare 2>&1
bare_total=$(grep '^TOTAL=' $WORK/v_mt.bare)
echo "   $bare_total"

# The shm file starts with a 72-byte libcov_shm_header followed by the
# 64 KB live bitmap and the snapshot ring. Tests below operate on the
# live bitmap only. python avoids the SIGPIPE-vs-pipefail interaction
# of a tail|head pipeline.
extract_bitmap() {
    python3 "$ROOT/test/shm_bitmap.py" extract "$1" "$2"
}

run_under_libcov() {
    local mode=$1 out=$2
    rm -f "$SHM"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_MODE="$mode" \
        LIBCOV_LOG=$WORK/v_mt.${mode}.log LD_PRELOAD="$LIB" \
        "$TARGET" "$THREADS" "$ITERS" "${INPUTS[@]}" > "$out" 2>&1
    extract_bitmap "$SHM" "$out.bitmap"
}

# Accepts either a pre-extracted bitmap file or a raw shm (detected by
# the "LCVS" magic; see test/shm_bitmap.py).
bitmap_stats() {
    python3 "$ROOT/test/shm_bitmap.py" stats "$1"
}

echo ">> oneshot MT run (threads=$THREADS iters=$ITERS)"
run_under_libcov oneshot $WORK/v_mt.os
read edges total maxh < <(bitmap_stats $WORK/v_mt.os.bitmap)
echo "   edges=$edges total=$total max_hits=$maxh"
[[ "$edges" -gt 0 ]] || { echo "FAIL: oneshot recorded zero edges"; exit 1; }

# Output equivalence: with libcov_mt loaded, the per-thread checksums must
# match the bare run. Thread completion order is not deterministic, so we
# compare sorted line sets.
sort $WORK/v_mt.bare > $WORK/v_mt.bare.s
sort $WORK/v_mt.os   > $WORK/v_mt.os.s
diff -q $WORK/v_mt.bare.s $WORK/v_mt.os.s >/dev/null \
    || { echo "FAIL: oneshot MT target output differs from baseline"; \
         diff $WORK/v_mt.bare.s $WORK/v_mt.os.s | head -20; exit 1; }
echo "   OK: target output unchanged under libcov_mt"

echo ">> leapfrog MT run"
run_under_libcov leapfrog $WORK/v_mt.lf
read edges total maxh < <(bitmap_stats $WORK/v_mt.lf.bitmap)
echo "   edges=$edges total=$total max_hits=$maxh"
[[ "$edges" -gt 0 ]] || { echo "FAIL: leapfrog recorded zero edges"; exit 1; }
[[ "$maxh"  -ge 2 ]] || { echo "FAIL: leapfrog never accumulated multi-hit (max=$maxh)"; exit 1; }

sort $WORK/v_mt.lf  > $WORK/v_mt.lf.s
diff -q $WORK/v_mt.bare.s $WORK/v_mt.lf.s >/dev/null \
    || { echo "FAIL: leapfrog MT target output differs from baseline"; \
         diff $WORK/v_mt.bare.s $WORK/v_mt.lf.s | head -20; exit 1; }
echo "   OK: target output unchanged under leapfrog MT"

echo ">> stress: many threads, many iters, leapfrog"
THREADS_STRESS="${THREADS_STRESS:-16}"
ITERS_STRESS="${ITERS_STRESS:-2000}"
rm -f "$SHM"
LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_MODE=leapfrog \
    LIBCOV_LOG=$WORK/v_mt.stress.log LD_PRELOAD="$LIB" \
    "$TARGET" "$THREADS_STRESS" "$ITERS_STRESS" "${INPUTS[@]}" > $WORK/v_mt.stress 2>&1
read edges total maxh < <(bitmap_stats "$SHM")
echo "   threads=$THREADS_STRESS iters=$ITERS_STRESS edges=$edges total=$total max_hits=$maxh"

# Stress baseline equivalence too.
"$TARGET" "$THREADS_STRESS" "$ITERS_STRESS" "${INPUTS[@]}" > $WORK/v_mt.stress.bare 2>&1
sort $WORK/v_mt.stress       > $WORK/v_mt.stress.s
sort $WORK/v_mt.stress.bare  > $WORK/v_mt.stress.bare.s
diff -q $WORK/v_mt.stress.bare.s $WORK/v_mt.stress.s >/dev/null \
    || { echo "FAIL: stress run output differs from baseline"; \
         diff $WORK/v_mt.stress.bare.s $WORK/v_mt.stress.s | head -20; exit 1; }
echo "   OK: stress output matches baseline"

if [[ "${LIBCOV_SYNC_FALLBACK:-}" == tgkill ]]; then
    grep -q 'tgkill broadcast fallback active' $WORK/v_mt.stress.log \
        || { echo "FAIL: forced fallback not active: $(grep membarrier $WORK/v_mt.stress.log)"; exit 1; }
    echo "   OK: ran with the tgkill broadcast fallback"
elif [[ -z "${LIBCOV_SYNC_FALLBACK:-}" ]]; then
    echo
    echo ">> again with LIBCOV_SYNC_FALLBACK=tgkill"
    LIBCOV_SYNC_FALLBACK=tgkill ITERS_STRESS="${ITERS_STRESS_TGKILL:-500}" "$0"
fi

echo
echo "ALL MT VALIDATIONS PASSED ($ARCH)"
