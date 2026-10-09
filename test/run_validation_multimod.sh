#!/usr/bin/env bash
# Multi-module LCV3 validation. Confirms that gen_patchlist.py --module
# produces a patch list whose runtime resolves both module load bases
# and emits coverage edges from both. Compares against an exe-only patch
# list to prove the helper library's contribution is real.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Per-run scratch dir: fixed /tmp paths made parallel runs collide.
WORK=$(mktemp -d)
# Kept (and its path printed) when the suite fails: the generator and
# target logs in it are how you debug.
keep_work_on_failure() {
    local rc=$?
    if [[ $rc -eq 0 ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK" >&2; fi
    return $rc
}
trap keep_work_on_failure EXIT
ARCH="${ARCH:-$(uname -m)}"
LIB="$ROOT/build/$ARCH/libcov_st.so"
TARGET="$ROOT/build/$ARCH/target_multimod"
HELPER="$ROOT/build/$ARCH/libmultimod_helper.so"

LCV_ONE="$WORK/multimod_one.lcv"   # only the main executable
LCV_BOTH="$WORK/multimod_both.lcv" # main exe + helper.so
SHM_ONE="$WORK/multimod_one.shm"
SHM_BOTH="$WORK/multimod_both.shm"

if [[ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]]; then
    echo "WARN: ASLR is on; helper load base will vary but coverage hash is base-relative" >&2
fi

[[ -f "$LIB"    ]] || { echo "missing $LIB. Run 'make'." >&2; exit 1; }
[[ -x "$TARGET" ]] || { echo "missing $TARGET. Run 'make -C test multimod ARCH=$ARCH BUILD=$ROOT/build/$ARCH'." >&2; exit 1; }
[[ -f "$HELPER" ]] || { echo "missing $HELPER. Run 'make -C test multimod ARCH=$ARCH BUILD=$ROOT/build/$ARCH'." >&2; exit 1; }

INPUTS=( 42 -3 0 hello 99 abc )
INCLUDE='^dbg\.(main_classify|main_print|helper_classify|helper_print)$'

extract_stats() {  # "<nonzero> <sum>" of the live bitmap
    python3 "$ROOT/test/shm_bitmap.py" stats "$1" | cut -d' ' -f1,2
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
"$TARGET" "${INPUTS[@]}" > $WORK/multimod.bare 2>&1

echo ">> generate single-module patch list (exe only)"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV_ONE" \
    --include-pat "$INCLUDE" >/dev/null 2>$WORK/multimod.gen_one.log \
    || { echo "FAIL: gen_patchlist exe-only (log: $WORK/multimod.gen_one.log)" >&2; exit 1; }
extract_lcv_meta "$LCV_ONE" | sed 's/^/   /'

echo ">> generate multi-module patch list (exe + helper.so)"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV_BOTH" \
    --module "libmultimod_helper.so:$HELPER" \
    --include-pat "$INCLUDE" >/dev/null 2>$WORK/multimod.gen_both.log \
    || { echo "FAIL: gen_patchlist exe+helper (log: $WORK/multimod.gen_both.log)" >&2; exit 1; }
extract_lcv_meta "$LCV_BOTH" | sed 's/^/   /'

rm -f "$SHM_ONE" "$SHM_BOTH"

echo ">> run with single-module patch list"
LIBCOV_PATCHLIST="$LCV_ONE" LIBCOV_SHM_PATH="$SHM_ONE" LIBCOV_MODE=leapfrog \
    LIBCOV_LOG=$WORK/multimod.one.log LD_PRELOAD="$LIB" \
    "$TARGET" "${INPUTS[@]}" > $WORK/multimod.one.out 2>&1
diff -q $WORK/multimod.bare $WORK/multimod.one.out >/dev/null \
    || { echo "FAIL: exe-only run output differs from baseline"; \
         diff $WORK/multimod.bare $WORK/multimod.one.out | head -10; exit 1; }
read one_edges one_total < <(extract_stats "$SHM_ONE")
echo "   edges=$one_edges total=$one_total (exe-only)"

echo ">> run with multi-module patch list"
LIBCOV_PATCHLIST="$LCV_BOTH" LIBCOV_SHM_PATH="$SHM_BOTH" LIBCOV_MODE=leapfrog \
    LIBCOV_LOG=$WORK/multimod.both.log LD_PRELOAD="$LIB" \
    "$TARGET" "${INPUTS[@]}" > $WORK/multimod.both.out 2>&1
diff -q $WORK/multimod.bare $WORK/multimod.both.out >/dev/null \
    || { echo "FAIL: multi-module run output differs from baseline"; \
         diff $WORK/multimod.bare $WORK/multimod.both.out | head -10; exit 1; }
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
if ! grep -q "config: module\[0\]" $WORK/multimod.both.log \
   || ! grep -q "config: module\[1\]" $WORK/multimod.both.log; then
    echo "FAIL: log missing one of the module base resolution lines"
    grep "config: module" $WORK/multimod.both.log
    exit 1
fi
echo "   OK: both module bases resolved at init"

echo
echo ">> call-graph slices across modules (--root / --cutoff with --module)"
MOD="libmultimod_helper.so:$HELPER"
per_module() {  # "<records in module 0> <records in module 1>" of an LCV
    python3 -c "
import struct,sys
d=open(sys.argv[1],'rb').read()
cnt=struct.unpack_from('<I',d,8)[0]
per=[0,0]
for i in range(cnt): per[d[24+i*14+9]]+=1
print(per[0], per[1])" "$1"
}
gen() { "$ROOT/tools/gen_patchlist.py" "$TARGET" "$@" --module "$MOD" \
            --include-pat "$INCLUDE" >"$WORK/slice.out" 2>&1; }

# A root only the executable has, and a helper with no root: used to
# abort the whole run; now the helper is skipped with a warning.
gen "$WORK/s1.lcv" --root main || { echo "FAIL: --root main --module: $(tail -2 "$WORK/slice.out")"; exit 1; }
read m0 m1 < <(per_module "$WORK/s1.lcv")
[[ $m0 -gt 0 && $m1 -eq 0 ]] && grep -q "module\[1\].*no --root resolves here" "$WORK/slice.out" \
    || { echo "FAIL: --root main: records m0=$m0 m1=$m1 (want >0, 0) + a warning"; exit 1; }
echo "   OK: --root main with --module: exe sliced ($m0), helper skipped with a warning"

# MODULE!NAME pins a root to the helper: only helper_classify there.
gen "$WORK/s2.lcv" --root main --root 'libmultimod_helper.so!helper_classify' \
    || { echo "FAIL: qualified root: $(tail -2 "$WORK/slice.out")"; exit 1; }
read q0 q1 < <(per_module "$WORK/s2.lcv")
[[ $q0 -eq $m0 && $q1 -gt 0 && $q1 -lt $(per_module "$LCV_BOTH" | cut -d' ' -f2) ]] \
    || { echo "FAIL: qualified root: m0=$q0 m1=$q1 (want m0=$m0, 0 < m1 < helper total)"; exit 1; }
echo "   OK: 'libmultimod_helper.so!helper_classify' slices the helper ($q1 of its records)"

# An unqualified name resolves in the module that defines it -- not in
# the executable's PLT stub for it.
gen "$WORK/s3.lcv" --root helper_print || { echo "FAIL: --root helper_print"; exit 1; }
read u0 u1 < <(per_module "$WORK/s3.lcv")
[[ $u0 -eq 0 && $u1 -gt 0 ]] \
    || { echo "FAIL: --root helper_print: m0=$u0 m1=$u1 (want 0, >0)"; exit 1; }
echo "   OK: unqualified helper_print resolves in the helper, not the exe's PLT stub"

# Errors: a name no module defines, an unknown module, an address past
# the last function (was silently the last function).
for bad in "--root nosuch|could not resolve it in any module" \
           "--root libnope.so!main|no module 'libnope.so'" \
           "--root 0xdeadbeef|not within any known function"; do
    args=${bad%%|*}; want=${bad#*|}
    if gen "$WORK/bad.lcv" $args; then
        echo "FAIL: '$args' accepted"; exit 1
    fi
    grep -q "$want" "$WORK/slice.out" \
        || { echo "FAIL: '$args': want /$want/, got: $(tail -1 "$WORK/slice.out")"; exit 1; }
done
echo "   OK: unknown name / module and out-of-range address are errors"

# --print-reachable covers every module.
gen /dev/null --root main --root 'libmultimod_helper.so!helper_print' --print-reachable
grep -q "module\[0\] 'target_multimod': reachable" "$WORK/slice.out" \
    && grep -q "module\[1\] 'libmultimod_helper.so': reachable" "$WORK/slice.out" \
    && grep -q "dbg.helper_print" "$WORK/slice.out" \
    || { echo "FAIL: --print-reachable didn't list both modules: $(grep module "$WORK/slice.out")"; exit 1; }
echo "   OK: --print-reachable lists both modules"

# The sliced two-module list runs: same output, coverage from both.
rm -f "$WORK/s2.shm"
LIBCOV_PATCHLIST="$WORK/s2.lcv" LIBCOV_SHM_PATH="$WORK/s2.shm" LIBCOV_MODE=leapfrog \
    LIBCOV_LOG="$WORK/s2.log" LD_PRELOAD="$LIB" "$TARGET" "${INPUTS[@]}" > "$WORK/s2.out" 2>&1
diff -q "$WORK/multimod.bare" "$WORK/s2.out" >/dev/null \
    || { echo "FAIL: sliced two-module run output differs"; exit 1; }
grep -q "armed=$((q0 + q1)) " "$WORK/s2.log" \
    || { echo "FAIL: sliced run: $(grep 'armed=' "$WORK/s2.log")"; exit 1; }
echo "   OK: sliced two-module list: output matches, all $((q0 + q1)) sites armed"

echo
echo "ALL MULTIMOD VALIDATIONS PASSED ($ARCH)"
