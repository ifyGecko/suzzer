#!/usr/bin/env bash
# Multi-module LCV3 validation. Confirms that gen_patchlist.py --module
# produces a patch list whose runtime resolves both module load bases
# and emits coverage edges from both. Compares against an exe-only patch
# list to prove the helper library's contribution is real.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
LIB="$ROOT/build/$ARCH/libcov_st.so"
TARGET="$ROOT/build/$ARCH/target_multimod"
HELPER="$ROOT/build/$ARCH/libmultimod_helper.so"

LCV_ONE="/tmp/multimod_one.lcv"   # only the main executable
LCV_BOTH="/tmp/multimod_both.lcv" # main exe + helper.so
SHM_ONE="/tmp/multimod_one.shm"
SHM_BOTH="/tmp/multimod_both.shm"

if [[ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]]; then
    echo "WARN: ASLR is on; helper load base will vary but coverage hash is base-relative" >&2
fi

[[ -f "$LIB"    ]] || { echo "missing $LIB. Run 'make'." >&2; exit 1; }
[[ -x "$TARGET" ]] || { echo "missing $TARGET. Run 'make -C test multimod ARCH=$ARCH BUILD=$ROOT/build/$ARCH'." >&2; exit 1; }
[[ -f "$HELPER" ]] || { echo "missing $HELPER. Run 'make -C test multimod ARCH=$ARCH BUILD=$ROOT/build/$ARCH'." >&2; exit 1; }

INPUTS=( 42 -3 0 hello 99 abc )
INCLUDE='^dbg\.(main_classify|main_print|helper_classify|helper_print)$'

extract_stats() {
    python3 -c "
import sys
with open(sys.argv[1],'rb') as f: d=f.read()
bm = d[72:72+65536]
n = sum(1 for b in bm if b)
t = sum(bm)
print(f'{n} {t}')" "$1"
}

extract_lcv_meta() {
    python3 -c "
import struct,sys
with open(sys.argv[1],'rb') as f: d=f.read()
magic,ver,cnt,th,fl,mc,_,mo,ms = struct.unpack('<4sIIBBBBII', d[:24])
print(f'magic={magic.decode()} version={ver} count={cnt} threading={th} module_count={mc}')
names = d[mo:mo+ms].split(b'\\x00')
print('modules:', [n.decode() for n in names if n])
recs = d[24:24+cnt*14]
per = {}
for i in range(cnt):
    midx = recs[i*14+9]
    per[midx] = per.get(midx,0)+1
print('records per module:', per)" "$1"
}

echo ">> baseline output (no libcov)"
"$TARGET" "${INPUTS[@]}" > /tmp/multimod.bare 2>&1

echo ">> generate single-module patch list (exe only)"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV_ONE" \
    --include-pat "$INCLUDE" >/dev/null 2>/tmp/multimod.gen_one.log
extract_lcv_meta "$LCV_ONE" | sed 's/^/   /'

echo ">> generate multi-module patch list (exe + helper.so)"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV_BOTH" \
    --module "libmultimod_helper.so:$HELPER" \
    --include-pat "$INCLUDE" >/dev/null 2>/tmp/multimod.gen_both.log
extract_lcv_meta "$LCV_BOTH" | sed 's/^/   /'

rm -f "$SHM_ONE" "$SHM_BOTH"

echo ">> run with single-module patch list"
LIBCOV_PATCHLIST="$LCV_ONE" LIBCOV_SHM_PATH="$SHM_ONE" LIBCOV_MODE=leapfrog \
    LIBCOV_LOG=/tmp/multimod.one.log LD_PRELOAD="$LIB" \
    "$TARGET" "${INPUTS[@]}" > /tmp/multimod.one.out 2>&1
diff -q /tmp/multimod.bare /tmp/multimod.one.out >/dev/null \
    || { echo "FAIL: exe-only run output differs from baseline"; \
         diff /tmp/multimod.bare /tmp/multimod.one.out | head -10; exit 1; }
read one_edges one_total < <(extract_stats "$SHM_ONE")
echo "   edges=$one_edges total=$one_total (exe-only)"

echo ">> run with multi-module patch list"
LIBCOV_PATCHLIST="$LCV_BOTH" LIBCOV_SHM_PATH="$SHM_BOTH" LIBCOV_MODE=leapfrog \
    LIBCOV_LOG=/tmp/multimod.both.log LD_PRELOAD="$LIB" \
    "$TARGET" "${INPUTS[@]}" > /tmp/multimod.both.out 2>&1
diff -q /tmp/multimod.bare /tmp/multimod.both.out >/dev/null \
    || { echo "FAIL: multi-module run output differs from baseline"; \
         diff /tmp/multimod.bare /tmp/multimod.both.out | head -10; exit 1; }
read both_edges both_total < <(extract_stats "$SHM_BOTH")
echo "   edges=$both_edges total=$both_total (exe + helper)"

# The multi-module run must contribute strictly more edges than exe-only,
# because the helper library's functions are now instrumented too.
if [[ "$both_edges" -le "$one_edges" ]]; then
    echo "FAIL: multi-module edges ($both_edges) not greater than exe-only ($one_edges);"
    echo "      helper library may not be contributing to the bitmap"
    exit 1
fi
echo "   OK: multi-module bitmap covers more edges than exe-only"

# Confirm both module bases were resolved.
if ! grep -q "config: module\[0\]" /tmp/multimod.both.log \
   || ! grep -q "config: module\[1\]" /tmp/multimod.both.log; then
    echo "FAIL: log missing one of the module base resolution lines"
    grep "config: module" /tmp/multimod.both.log
    exit 1
fi
echo "   OK: both module bases resolved at init"

echo
echo "ALL MULTIMOD VALIDATIONS PASSED ($ARCH)"
