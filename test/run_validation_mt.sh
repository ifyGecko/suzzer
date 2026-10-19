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
# Kept (and its path printed) when the suite fails: the generator and
# target logs in it are how you debug.
keep_work_on_failure() {
    local rc=$?
    if [[ $rc -eq 0 ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK" >&2; fi
    return $rc
}
trap keep_work_on_failure EXIT
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
    >/dev/null 2>$WORK/v_mt.gen.log \
    || { echo "FAIL: gen_patchlist (log: $WORK/v_mt.gen.log)" >&2; exit 1; }
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
# live bitmap (hdr->map_size bytes, auto-sized) and the snapshot ring;
# shm_bitmap.py reads the layout from the header. Tests below operate on the
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

if [[ "$ARCH" == x86_64 ]]; then
    # A peer thread fetching a site while it is rewritten takes the two
    # bytes from two fetches when they cross an instruction-fetch block
    # (16 bytes on Intel, 32 on AMD), and can run a torn mix: UD2's 0f with
    # a jmp's 06 is CLTS -> SIGSEGV (about 1 leapfrog run in 250 on Zen 4
    # before both checks below existed; see src/patch_mt.c).
    echo ">> x86: no MT site crosses a 16-byte instruction-fetch block"
    python3 - "$LCV" <<'PYEOF'
import struct, sys
d = open(sys.argv[1], "rb").read()
n = struct.unpack_from("<I", d, 8)[0]
bad = [hex(struct.unpack_from("<Q", d, 24 + 14 * i)[0]) for i in range(n)
       if (struct.unpack_from("<Q", d, 24 + 14 * i)[0] & 15) + d[24 + 14 * i + 8] > 16]
if bad:
    sys.exit(f"FAIL: --threading mt kept {len(bad)} block-straddling sites: {bad}")
print(f"   OK: none of {n} sites crosses a 16-byte block")
PYEOF

    # libcov_mt itself refuses such sites in a list that has them (an MT
    # list from an older generator, or an ANY list): here an ST list
    # relabelled ANY. Exactly the straddling sites stay unarmed.
    echo ">> x86: libcov_mt refuses block-straddling sites in a list that has them"
    "$ROOT/tools/gen_patchlist.py" "$TARGET" "$WORK/any.lcv" --threading st \
        --include-pat '^dbg\.(main|classify|loop_sum|cmdline|worker)$' \
        >/dev/null 2>$WORK/v_mt.gen_any.log \
        || { echo "FAIL: gen_patchlist (log: $WORK/v_mt.gen_any.log)" >&2; exit 1; }
    want=$(python3 - "$WORK/any.lcv" <<'PYEOF'
import struct, sys
p = sys.argv[1]
d = bytearray(open(p, "rb").read())
d[12] = 0   # threading hint: ANY
open(p, "wb").write(d)
n = struct.unpack_from("<I", d, 8)[0]
print(sum((struct.unpack_from("<Q", d, 24 + 14 * i)[0] & 15) + d[24 + 14 * i + 8] > 16
          for i in range(n)))
PYEOF
)
    if [[ "$want" -eq 0 ]]; then
        echo "   SKIP: this build of target_simple_mt has no block-straddling site"
    else
        rm -f "$SHM"
        LIBCOV_PATCHLIST="$WORK/any.lcv" LIBCOV_SHM_PATH="$SHM" LIBCOV_MODE=leapfrog \
            LIBCOV_LOG=$WORK/v_mt.any.log LD_PRELOAD="$LIB" \
            "$TARGET" "$THREADS" "$ITERS" "${INPUTS[@]}" > $WORK/v_mt.any 2>&1 \
            || { echo "FAIL: leapfrog run with the ANY list exited $?"; exit 1; }
        grep -q "fetch_unsafe=$want\$" $WORK/v_mt.any.log \
            || { echo "FAIL: want fetch_unsafe=$want: $(grep 'armed=' $WORK/v_mt.any.log)"; exit 1; }
        sort $WORK/v_mt.any > $WORK/v_mt.any.s
        diff -q $WORK/v_mt.bare.s $WORK/v_mt.any.s >/dev/null \
            || { echo "FAIL: ANY-list MT target output differs from baseline"; exit 1; }
        echo "   OK: $want straddling sites left unarmed; output unchanged"
    fi
fi

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
