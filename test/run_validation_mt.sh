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

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
LIB="$ROOT/build/$ARCH/libcov_mt.so"
TARGET="$ROOT/build/$ARCH/target_simple_mt"
LCV="/tmp/target_simple_mt.lcv"
SHM="/tmp/libcov_validate_mt"

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
    >/dev/null 2>/tmp/v_mt.gen.log
records=$(python3 -c "
import struct
with open('$LCV','rb') as f: h=f.read(16)
m,v,c=struct.unpack('<4sII', h[:12])
th=h[12]
print(f'magic={m.decode()} version={v} records={c} threading={th}')")
echo "   $records"

echo ">> baseline run without libcov"
"$TARGET" "$THREADS" "$ITERS" "${INPUTS[@]}" > /tmp/v_mt.bare 2>&1
bare_total=$(grep '^TOTAL=' /tmp/v_mt.bare)
echo "   $bare_total"

# The shm file starts with a 72-byte libcov_shm_header followed by the
# 64 KB live bitmap and the snapshot ring. Tests below operate on the
# live bitmap only. python avoids the SIGPIPE-vs-pipefail interaction
# of a tail|head pipeline.
extract_bitmap() {
    python3 -c "
import sys
with open(sys.argv[1],'rb') as f:
    f.seek(72); d = f.read(65536)
with open(sys.argv[2],'wb') as f:
    f.write(d)" "$1" "$2"
}

run_under_libcov() {
    local mode=$1 out=$2
    rm -f "$SHM"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_MODE="$mode" \
        LIBCOV_LOG=/tmp/v_mt.${mode}.log LD_PRELOAD="$LIB" \
        "$TARGET" "$THREADS" "$ITERS" "${INPUTS[@]}" > "$out" 2>&1
    extract_bitmap "$SHM" "$out.bitmap"
}

# Accepts either a pre-extracted bitmap file or a raw shm. It auto-detects
# by checking the first 4 bytes for the "LCVS" magic; if present, skips
# the 72-byte header.
bitmap_stats() {
    python3 -c "
import sys
with open(sys.argv[1],'rb') as f: d=f.read()
if d[:4] == b'LCVS': d = d[72:72+65536]
n=sum(1 for b in d if b); t=sum(d); m=max(d) if d else 0
print(n, t, m)" "$1"
}

echo ">> oneshot MT run (threads=$THREADS iters=$ITERS)"
run_under_libcov oneshot /tmp/v_mt.os
read edges total maxh < <(bitmap_stats /tmp/v_mt.os.bitmap)
echo "   edges=$edges total=$total max_hits=$maxh"
[[ "$edges" -gt 0 ]] || { echo "FAIL: oneshot recorded zero edges"; exit 1; }

# Output equivalence: with libcov_mt loaded, the per-thread checksums must
# match the bare run. Thread completion order is not deterministic, so we
# compare sorted line sets.
sort /tmp/v_mt.bare > /tmp/v_mt.bare.s
sort /tmp/v_mt.os   > /tmp/v_mt.os.s
diff -q /tmp/v_mt.bare.s /tmp/v_mt.os.s >/dev/null \
    || { echo "FAIL: oneshot MT target output differs from baseline"; \
         diff /tmp/v_mt.bare.s /tmp/v_mt.os.s | head -20; exit 1; }
echo "   OK: target output unchanged under libcov_mt"

echo ">> leapfrog MT run"
run_under_libcov leapfrog /tmp/v_mt.lf
read edges total maxh < <(bitmap_stats /tmp/v_mt.lf.bitmap)
echo "   edges=$edges total=$total max_hits=$maxh"
[[ "$edges" -gt 0 ]] || { echo "FAIL: leapfrog recorded zero edges"; exit 1; }
[[ "$maxh"  -ge 2 ]] || { echo "FAIL: leapfrog never accumulated multi-hit (max=$maxh)"; exit 1; }

sort /tmp/v_mt.lf  > /tmp/v_mt.lf.s
diff -q /tmp/v_mt.bare.s /tmp/v_mt.lf.s >/dev/null \
    || { echo "FAIL: leapfrog MT target output differs from baseline"; \
         diff /tmp/v_mt.bare.s /tmp/v_mt.lf.s | head -20; exit 1; }
echo "   OK: target output unchanged under leapfrog MT"

echo ">> stress: many threads, many iters, leapfrog"
THREADS_STRESS="${THREADS_STRESS:-16}"
ITERS_STRESS="${ITERS_STRESS:-2000}"
rm -f "$SHM"
LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_MODE=leapfrog \
    LIBCOV_LOG=/tmp/v_mt.stress.log LD_PRELOAD="$LIB" \
    "$TARGET" "$THREADS_STRESS" "$ITERS_STRESS" "${INPUTS[@]}" > /tmp/v_mt.stress 2>&1
read edges total maxh < <(bitmap_stats "$SHM")
echo "   threads=$THREADS_STRESS iters=$ITERS_STRESS edges=$edges total=$total max_hits=$maxh"

# Stress baseline equivalence too.
"$TARGET" "$THREADS_STRESS" "$ITERS_STRESS" "${INPUTS[@]}" > /tmp/v_mt.stress.bare 2>&1
sort /tmp/v_mt.stress       > /tmp/v_mt.stress.s
sort /tmp/v_mt.stress.bare  > /tmp/v_mt.stress.bare.s
diff -q /tmp/v_mt.stress.bare.s /tmp/v_mt.stress.s >/dev/null \
    || { echo "FAIL: stress run output differs from baseline"; \
         diff /tmp/v_mt.stress.bare.s /tmp/v_mt.stress.s | head -20; exit 1; }
echo "   OK: stress output matches baseline"

echo
echo "ALL MT VALIDATIONS PASSED ($ARCH)"
