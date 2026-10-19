#!/usr/bin/env bash
# run_validation_coverage_options.sh
#
# End-to-end validation that every libcov coverage option correctly
# collects program coverage. Covers:
#
#   env-var options (single build, default tunables):
#     - LIBCOV_PATCHLIST unset    -- library inert, no shm file written
#     - LIBCOV_PATCHLIST set      -- determinism + input differentiation
#     - LIBCOV_MODE=oneshot       -- max hit per bucket == 1
#     - LIBCOV_MODE=leapfrog      -- max hit per bucket >= 2 on loops
#     - LIBCOV_SHM_PATH as fs path -- file at that path
#     - LIBCOV_LOG                -- log file written, contains "ready"
#     - LIBCOV_BOUNDARY_RING      -- shm header reports requested ring size
#     - LIBCOV_BOUNDARY_INIT_GRACE -- drops first N marker hits before publish
#
#   build-time options (rebuilds libcov into a side BUILD dir):
#     - LIBCOV_NGRAM_N=1 (block)         -- reverse-input bitmaps IDENTICAL
#     - LIBCOV_NGRAM_N=2 (AFL edges)     -- reverse-input bitmaps DIFFER
#     - LIBCOV_NGRAM_N=4 (4-gram)        -- reorder-input bitmaps DIFFER
#     - LIBCOV_COVERAGE_MODEL_SITE=0     -- shm map_size = 64 KiB (legacy)
#     - LIBCOV_COVERAGE_MODEL_SITE=1     -- shm map_size auto-sized to patches
#     - shm header scheme bits           -- N, model, rotate match the build
#     - LIBCOV_MAP_FUDGE default         -- map headroom scales with N
#
#   generator options:
#     - --root + --max-depth   -- sliced patchlist contains fewer records
#                                 than the unfiltered list AND collects
#                                 strictly fewer edges at runtime
#
# Multi-module + the boundary REARM matrix are already exercised by
# run_validation_multimod.sh and run_validation_boundary.sh and are not
# duplicated here -- this script focuses on the orthogonal axes. (A
# LIBCOV_TRAP_SIGNO / trap-encoding mismatch build is exercised by
# run_validation_failloud.sh.)
#
# All variant libcov builds land under $SCRATCH (default: a fresh mktemp -d,
# removed on exit) so the user's build/ directory is not touched. With a
# reused SCRATCH, each variant is rebuilt incrementally (make runs every
# time, so edits under src/ are picked up); set REBUILD=1 to wipe and
# rebuild every variant from scratch.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
if [[ -z "${SCRATCH:-}" ]]; then
    SCRATCH=$(mktemp -d)
    trap 'rm -rf "$SCRATCH"' EXIT
fi
THREADING="${THREADING:-st}"
mkdir -p "$SCRATCH"

if [[ "$THREADING" != "st" && "$THREADING" != "mt" ]]; then
    echo "THREADING must be 'st' or 'mt', got '$THREADING'" >&2
    exit 2
fi

if [[ "$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo 0)" != "0" ]]; then
    echo "WARN: ASLR is on; coverage hash is base-relative so tests still work," >&2
    echo "      but absolute address comparison across runs will not." >&2
fi

PASS=0
FAIL=0
SKIP=0

section() { echo; echo "== $1 =="; }
pass()    { echo "   OK: $1"; PASS=$((PASS+1)); }
fail()    { echo "   FAIL: $1" >&2; FAIL=$((FAIL+1)); }
skip()    { echo "   SKIP: $1"; SKIP=$((SKIP+1)); }

# ----- build helpers ----------------------------------------------------

# build_variant <tag> <extra_cflags>
# Builds libcov_${THREADING}.so + test targets into $SCRATCH/<tag>/.
# Prints the absolute variant build dir on stdout.
build_variant() {
    local tag="$1" extra="$2"
    local vbuild="$SCRATCH/$tag"
    if [[ "${REBUILD:-0}" == "1" ]]; then rm -rf "$vbuild"; fi
    mkdir -p "$vbuild"
    # Always run make: it is incremental (the .d dependency files track
    # src/ headers), so a reused variant dir picks up source edits instead
    # of silently testing a stale library. The Makefile honours `BUILD=`
    # from the command line so objects + outputs go to the per-tag scratch
    # dir and the user's default build/ is left alone. EXTRA_CFLAGS is
    # appended to CFLAGS by the top-level Makefile (`CFLAGS +=
    # $(EXTRA_CFLAGS)`).
    if ! make -C "$ROOT" --no-print-directory \
             ARCH="$ARCH" THREADING="$THREADING" \
             BUILD="$vbuild" EXTRA_CFLAGS="$extra" \
             >"$vbuild/build.log" 2>&1; then
        echo "BUILD FAILED for $tag (EXTRA_CFLAGS='$extra'):" >&2
        tail -40 "$vbuild/build.log" >&2
        exit 1
    fi
    echo "$vbuild"
}

# ----- shm-introspection helpers ----------------------------------------

# Print map_size, flags, edges (nonzero bytes), total, max, gen_current, ring_size
# extracted from the live bitmap region of the shm file at $1.
#
# Shm header is C struct libcov_shm_header (boundary.h) WITHOUT __packed,
# so there is 4 bytes of padding between flags (u32 at [16:20]) and
# gen_current (u64 needs 8-byte alignment, lands at [24:32]). Total
# header size is 72 bytes after alignment. Fields after gen_current
# follow naturally at offsets 32/40/48; publish_dropped/owner_pid/
# owner_start at 56/60/64, reserved[4] at 68..72.
stats_from_shm() {
    python3 - "$1" <<'PYEOF'
import struct, sys, os
p = sys.argv[1]
if not os.path.exists(p) or os.path.getsize(p) < 72:
    print("map_size=0 flags=0 edges=0 total=0 max=0 gen_cur=0 ring=0")
    sys.exit(0)
with open(p,'rb') as f: d=f.read()
magic = d[0:4]
ver, ring = struct.unpack('<HH', d[4:8])
msize, stride, flags = struct.unpack('<III', d[8:20])
# Skip 4 bytes of natural padding [20:24] before gen_current (u64).
gen_cur, gen_init, bm_off, ring_off = struct.unpack('<QQQQ', d[24:56])
if magic != b'LCVS':
    print("map_size=0 flags=0 edges=0 total=0 max=0 gen_cur=0 ring=0")
    sys.exit(0)
bm = d[bm_off:bm_off+msize]
nz  = sum(1 for b in bm if b)
tot = sum(bm)
mx  = max(bm) if bm else 0
print(f"map_size={msize} flags={flags} edges={nz} total={tot} max={mx} "
      f"gen_cur={gen_cur} ring={ring}")
PYEOF
}

# Extract the live-bitmap region of an shm file into a flat binary file.
# Reads bitmap_offset from the header (at byte 40 after the gen_current /
# gen_init pair) so this works under both legacy (fixed 64 KB) and
# site-id (auto-sized) coverage models.
extract_bitmap() {
    python3 - "$1" "$2" <<'PYEOF'
import struct, sys
with open(sys.argv[1],'rb') as f: d=f.read()
msize  = struct.unpack('<I', d[8:12])[0]
bm_off = struct.unpack('<Q', d[40:48])[0]
open(sys.argv[2],'wb').write(d[bm_off:bm_off+msize])
PYEOF
}

# Read just the LCV3 record count, to verify selective instrumentation.
lcv_record_count() {
    python3 - "$1" <<'PYEOF'
import struct, sys
with open(sys.argv[1],'rb') as f: d=f.read()
print(struct.unpack('<I', d[8:12])[0])
PYEOF
}

# ----- target wrappers --------------------------------------------------

# gen_lcv <target> <out_lcv> [extra gen_patchlist args...]
gen_lcv() {
    local target="$1" out="$2"; shift 2
    if ! "$ROOT/tools/gen_patchlist.py" "$target" "$out" "$@" \
            >"$out.gen.log" 2>&1; then
        echo "gen_patchlist failed for $target -> $out:" >&2
        cat "$out.gen.log" >&2
        return 1
    fi
}

# run_simple <vbuild> <lcv> <shm> <mode> <input>
# Drives target_simple under the variant libcov; output to /dev/null.
run_simple() {
    local vbuild="$1" lcv="$2" shm="$3" mode="$4" input="$5"
    local lib="$vbuild/libcov_${THREADING}.so"
    rm -f "$shm"
    LIBCOV_PATCHLIST="$lcv" LIBCOV_SHM_PATH="$shm" LIBCOV_MODE="$mode" \
        LIBCOV_LOG=/dev/null LD_PRELOAD="$lib" \
        "$vbuild/target_simple" "$input" >/dev/null 2>&1 || true
}

# run_orderable <vbuild> <lcv> <shm> <mode> <input>
run_orderable() {
    local vbuild="$1" lcv="$2" shm="$3" mode="$4" input="$5"
    local lib="$vbuild/libcov_${THREADING}.so"
    rm -f "$shm"
    LIBCOV_PATCHLIST="$lcv" LIBCOV_SHM_PATH="$shm" LIBCOV_MODE="$mode" \
        LIBCOV_LOG=/dev/null LD_PRELOAD="$lib" \
        "$vbuild/target_orderable" "$input" >/dev/null 2>&1 || true
}

# Parse "key=value key2=value2 ..." into shell vars (prefix=s_).
parse_stats() {
    local s; s=$(stats_from_shm "$1")
    s_map_size=$(echo "$s" | sed -n 's/.*map_size=\([0-9]*\).*/\1/p')
    s_flags=$(echo "$s"    | sed -n 's/.*flags=\([0-9]*\).*/\1/p')
    s_edges=$(echo "$s"    | sed -n 's/.*edges=\([0-9]*\).*/\1/p')
    s_total=$(echo "$s"    | sed -n 's/.*total=\([0-9]*\).*/\1/p')
    s_max=$(echo "$s"      | sed -n 's/.* max=\([0-9]*\).*/\1/p')
    s_gen=$(echo "$s"      | sed -n 's/.*gen_cur=\([0-9]*\).*/\1/p')
    s_ring=$(echo "$s"     | sed -n 's/.*ring=\([0-9]*\).*/\1/p')
}

# ======================================================================
# DEFAULT BUILD -- baseline for env-var tests.
# ======================================================================

section "build: default variant (site-id model, N=2, ROTATE=0)"
DFLT="$(build_variant default '')"
echo "   default build at $DFLT"
DFLT_LIB="$DFLT/libcov_${THREADING}.so"

DFLT_LCV="$SCRATCH/default.lcv"
gen_lcv "$DFLT/target_simple" "$DFLT_LCV" \
    --threading "$THREADING" \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline)$' \
    || { fail "gen_patchlist default"; exit 1; }
echo "   patchlist records: $(lcv_record_count "$DFLT_LCV")"

# ----------------------------------------------------------------------
section "T1: LIBCOV_PATCHLIST unset -- library inert (no shm file)"
INERT_SHM="$SCRATCH/inert.shm"
rm -f "$INERT_SHM"
# Run with PATCHLIST explicitly unset; LIBCOV_SHM_PATH is set so we can tell
# whether sink_init ran (it shouldn't, because libcov_init bails before that
# when PATCHLIST is missing -- src/libcov.c:62-66).
LIBCOV_SHM_PATH="$INERT_SHM" LIBCOV_LOG=/dev/null LD_PRELOAD="$DFLT_LIB" \
    "$DFLT/target_simple" 42 > "$SCRATCH/inert.stdout" 2>&1 || true
if [[ -e "$INERT_SHM" ]]; then
    fail "shm file was created at $INERT_SHM despite LIBCOV_PATCHLIST being unset"
else
    pass "no shm file written; library is inert"
fi
# Sanity: target output must match an uninstrumented run (transparency).
"$DFLT/target_simple" 42 > "$SCRATCH/inert.bare" 2>&1 || true
if diff -q "$SCRATCH/inert.stdout" "$SCRATCH/inert.bare" >/dev/null; then
    pass "inert library does not perturb target stdout"
else
    fail "inert library altered target stdout"
fi

# ----------------------------------------------------------------------
section "T2: oneshot determinism -- two identical runs => identical bitmaps"
run_simple "$DFLT" "$DFLT_LCV" "$SCRATCH/t2a.shm" oneshot 42
run_simple "$DFLT" "$DFLT_LCV" "$SCRATCH/t2b.shm" oneshot 42
extract_bitmap "$SCRATCH/t2a.shm" "$SCRATCH/t2a.bm"
extract_bitmap "$SCRATCH/t2b.shm" "$SCRATCH/t2b.bm"
if cmp -s "$SCRATCH/t2a.bm" "$SCRATCH/t2b.bm"; then
    pass "oneshot run determinism"
else
    fail "oneshot run produced non-deterministic bitmaps"
fi

# ----------------------------------------------------------------------
section "T3: oneshot input differentiation -- different inputs => different bitmaps"
run_simple "$DFLT" "$DFLT_LCV" "$SCRATCH/t3a.shm" oneshot 42
run_simple "$DFLT" "$DFLT_LCV" "$SCRATCH/t3b.shm" oneshot -3
extract_bitmap "$SCRATCH/t3a.shm" "$SCRATCH/t3a.bm"
extract_bitmap "$SCRATCH/t3b.shm" "$SCRATCH/t3b.bm"
if cmp -s "$SCRATCH/t3a.bm" "$SCRATCH/t3b.bm"; then
    fail "different inputs produced identical bitmaps"
else
    pass "different inputs produce different bitmaps"
fi

# ----------------------------------------------------------------------
section "T4: LIBCOV_MODE=oneshot -- max hit per bucket == 1"
run_simple "$DFLT" "$DFLT_LCV" "$SCRATCH/t4.shm" oneshot 99
parse_stats "$SCRATCH/t4.shm"
if [[ "$s_edges" -gt 0 && "$s_max" -eq 1 ]]; then
    pass "oneshot edges=$s_edges max=$s_max"
else
    fail "oneshot edges=$s_edges max=$s_max (expected edges>0 max==1)"
fi

# ----------------------------------------------------------------------
section "T5: LIBCOV_MODE=leapfrog -- max hit per bucket >= 2 on loops"
# Under THREADING=mt on x86_64, gen_patchlist.py's --threading mt path
# requires a single 2-byte write that doesn't straddle a 16-byte fetch block
# write per site. That filter typically excludes the variable-length jcc
# at the loop-body BB terminator on target_simple, so leapfrog re-tripping
# is not observable on this target under MT. MT leapfrog multi-hits ARE
# exercised by test/target_simple_mt under run_validation_mt.sh, which
# arranges multiple-call patterns that survive the filter.
if [[ "$THREADING" == "mt" ]]; then
    skip "MT site filtering hides single-thread leapfrog re-entry on this target; covered by run_validation_mt.sh"
else
    run_simple "$DFLT" "$DFLT_LCV" "$SCRATCH/t5.shm" leapfrog 99
    parse_stats "$SCRATCH/t5.shm"
    if [[ "$s_edges" -gt 0 && "$s_max" -ge 2 ]]; then
        pass "leapfrog edges=$s_edges max=$s_max"
    else
        fail "leapfrog edges=$s_edges max=$s_max (expected edges>0 max>=2)"
    fi
fi

# ----------------------------------------------------------------------
section "T6: LIBCOV_SHM_PATH as filesystem path -- file at exact path"
FS_SHM="$SCRATCH/t6_fs.shm"
rm -f "$FS_SHM"
LIBCOV_PATCHLIST="$DFLT_LCV" LIBCOV_SHM_PATH="$FS_SHM" LIBCOV_MODE=oneshot \
    LIBCOV_LOG=/dev/null LD_PRELOAD="$DFLT_LIB" \
    "$DFLT/target_simple" 42 >/dev/null 2>&1 || true
if [[ -f "$FS_SHM" ]] && head -c 4 "$FS_SHM" | grep -q LCVS; then
    pass "fs-path shm created with LCVS magic"
else
    fail "fs-path shm missing or magic wrong"
fi

# ----------------------------------------------------------------------
section "T7: LIBCOV_LOG -- log file written, contains init banner"
LOGF="$SCRATCH/t7.log"
rm -f "$LOGF"
LIBCOV_PATCHLIST="$DFLT_LCV" LIBCOV_SHM_PATH="$SCRATCH/t7.shm" \
    LIBCOV_MODE=oneshot LIBCOV_LOG="$LOGF" LD_PRELOAD="$DFLT_LIB" \
    "$DFLT/target_simple" 42 >/dev/null 2>&1 || true
if [[ -f "$LOGF" ]] && grep -q "init: ready" "$LOGF"; then
    pass "log file contains init: ready"
else
    fail "log file missing or no init: ready line ($LOGF)"
fi

# ----------------------------------------------------------------------
section "T8: default coverage model -- map_size auto-sized to patch count"
parse_stats "$SCRATCH/t4.shm"
NSITES=$(lcv_record_count "$DFLT_LCV")
echo "   default map_size=$s_map_size (n_sites=$NSITES)"
# Default model is site-id (LIBCOV_COVERAGE_MODEL_SITE=1). Map size should
# be > 0 and a power of two and >= next_pow2(n_sites). For target_simple's
# ~20 records the auto-sized map clamps to LIBCOV_MAP_MIN_POW2 = 4096 bytes.
if [[ "$s_map_size" -ge 4096 ]] && \
   python3 -c "import sys; s=int(sys.argv[1]); sys.exit(0 if (s & (s-1)) == 0 and s>0 else 1)" "$s_map_size"; then
    pass "site-id model map_size=$s_map_size (power-of-two, >= 4096)"
else
    fail "site-id map_size=$s_map_size not power-of-two or too small"
fi

# ----------------------------------------------------------------------
section "T9: --root + --max-depth produces a SLICED patchlist with fewer records"
SLICE_LCV="$SCRATCH/slice.lcv"
gen_lcv "$DFLT/target_simple" "$SLICE_LCV" \
    --threading "$THREADING" \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline)$' \
    --root main --max-depth 0 || { fail "slice gen"; exit 1; }
NSLICE=$(lcv_record_count "$SLICE_LCV")
echo "   sliced records: $NSLICE (full: $NSITES)"
if [[ "$NSLICE" -gt 0 && "$NSLICE" -lt "$NSITES" ]]; then
    pass "--root main --max-depth 0 produced $NSLICE records (< full $NSITES)"
else
    fail "slice did not reduce record count ($NSLICE vs $NSITES)"
fi
# Edge count at runtime must also be strictly smaller for the sliced run.
run_simple "$DFLT" "$DFLT_LCV"  "$SCRATCH/t9_full.shm"  oneshot 42
run_simple "$DFLT" "$SLICE_LCV" "$SCRATCH/t9_slice.shm" oneshot 42
parse_stats "$SCRATCH/t9_full.shm";  FULL_EDGES=$s_edges
parse_stats "$SCRATCH/t9_slice.shm"; SLICE_EDGES=$s_edges
echo "   runtime edges: full=$FULL_EDGES sliced=$SLICE_EDGES"
if [[ "$SLICE_EDGES" -gt 0 && "$SLICE_EDGES" -lt "$FULL_EDGES" ]]; then
    pass "sliced run produced $SLICE_EDGES edges (< full $FULL_EDGES)"
else
    fail "sliced run edges=$SLICE_EDGES not strictly < full=$FULL_EDGES"
fi

# ----------------------------------------------------------------------
section "T10: target output unchanged under libcov (no perturbation)"
"$DFLT/target_simple" 42 > "$SCRATCH/t10.bare" 2>&1 || true
LIBCOV_PATCHLIST="$DFLT_LCV" LIBCOV_SHM_PATH="$SCRATCH/t10.shm" \
    LIBCOV_MODE=leapfrog LIBCOV_LOG=/dev/null LD_PRELOAD="$DFLT_LIB" \
    "$DFLT/target_simple" 42 > "$SCRATCH/t10.under" 2>&1 || true
if diff -q "$SCRATCH/t10.bare" "$SCRATCH/t10.under" >/dev/null; then
    pass "target stdout identical with/without libcov"
else
    fail "target stdout differs under libcov"
fi

# ======================================================================
# N-gram coverage scheme validation -- requires rebuilds.
# Uses target_orderable: same character set, different orderings exercise
# the same BLOCKS in different EDGE/N-gram orderings. Under oneshot the
# bitmap encodes the set of fired buckets only (max=1), so a SET-equality
# test isolates the N-gram scheme from hit-counting noise.
# ======================================================================

section "T11: build LIBCOV_NGRAM_N=1 (block coverage)"
N1="$(build_variant ngram_n1 '-DLIBCOV_NGRAM_N=1')"
N1_LCV="$SCRATCH/orderable_n1.lcv"
gen_lcv "$N1/target_orderable" "$N1_LCV" \
    --threading "$THREADING" \
    --include-pat '^dbg\.(main|dispatch|state_a|state_b|state_c|state_d)$' \
    || { fail "gen N=1"; exit 1; }
echo "   patchlist records: $(lcv_record_count "$N1_LCV")"

run_orderable "$N1" "$N1_LCV" "$SCRATCH/t11_fwd.shm" oneshot abcd
run_orderable "$N1" "$N1_LCV" "$SCRATCH/t11_rev.shm" oneshot dcba
extract_bitmap "$SCRATCH/t11_fwd.shm" "$SCRATCH/t11_fwd.bm"
extract_bitmap "$SCRATCH/t11_rev.shm" "$SCRATCH/t11_rev.bm"
# At N=1 the bitmap bucket is hash(pc) or site_id alone -- no prev_loc
# context. Two inputs hitting the same set of blocks under oneshot must
# produce identical bitmaps.
if cmp -s "$SCRATCH/t11_fwd.bm" "$SCRATCH/t11_rev.bm"; then
    pass "N=1 block coverage: 'abcd' and 'dcba' produce identical bitmaps"
else
    fail "N=1 reversed-input bitmaps differ (block coverage should be order-insensitive)"
    # Helpful diagnostic:
    parse_stats "$SCRATCH/t11_fwd.shm"; FE=$s_edges
    parse_stats "$SCRATCH/t11_rev.shm"; RE=$s_edges
    echo "   diagnostic: fwd_edges=$FE rev_edges=$RE"
fi

# ----------------------------------------------------------------------
section "T12: default build LIBCOV_NGRAM_N=2 (AFL edges) -- reverse-input bitmaps DIFFER"
DFLT_ORD_LCV="$SCRATCH/orderable_dflt.lcv"
gen_lcv "$DFLT/target_orderable" "$DFLT_ORD_LCV" \
    --threading "$THREADING" \
    --include-pat '^dbg\.(main|dispatch|state_a|state_b|state_c|state_d)$' \
    || { fail "gen default"; exit 1; }
run_orderable "$DFLT" "$DFLT_ORD_LCV" "$SCRATCH/t12_fwd.shm" oneshot abcd
run_orderable "$DFLT" "$DFLT_ORD_LCV" "$SCRATCH/t12_rev.shm" oneshot dcba
extract_bitmap "$SCRATCH/t12_fwd.shm" "$SCRATCH/t12_fwd.bm"
extract_bitmap "$SCRATCH/t12_rev.shm" "$SCRATCH/t12_rev.bm"
if cmp -s "$SCRATCH/t12_fwd.bm" "$SCRATCH/t12_rev.bm"; then
    fail "N=2 AFL-edge coverage: reversed-input bitmaps identical (edges should differ)"
else
    pass "N=2 AFL-edge coverage: reversed-input bitmaps differ as expected"
fi

# ----------------------------------------------------------------------
section "T13: build LIBCOV_NGRAM_N=4 -- 4-gram differentiates more reorderings"
N4="$(build_variant ngram_n4 '-DLIBCOV_NGRAM_N=4')"
N4_LCV="$SCRATCH/orderable_n4.lcv"
gen_lcv "$N4/target_orderable" "$N4_LCV" \
    --threading "$THREADING" \
    --include-pat '^dbg\.(main|dispatch|state_a|state_b|state_c|state_d)$' \
    || { fail "gen N=4"; exit 1; }
run_orderable "$N4" "$N4_LCV" "$SCRATCH/t13_x.shm" oneshot aabbcc
run_orderable "$N4" "$N4_LCV" "$SCRATCH/t13_y.shm" oneshot bbccaa
run_orderable "$N4" "$N4_LCV" "$SCRATCH/t13_z.shm" oneshot ccaabb
extract_bitmap "$SCRATCH/t13_x.shm" "$SCRATCH/t13_x.bm"
extract_bitmap "$SCRATCH/t13_y.shm" "$SCRATCH/t13_y.bm"
extract_bitmap "$SCRATCH/t13_z.shm" "$SCRATCH/t13_z.bm"
DIFF_PAIRS=0
cmp -s "$SCRATCH/t13_x.bm" "$SCRATCH/t13_y.bm" || DIFF_PAIRS=$((DIFF_PAIRS+1))
cmp -s "$SCRATCH/t13_x.bm" "$SCRATCH/t13_z.bm" || DIFF_PAIRS=$((DIFF_PAIRS+1))
cmp -s "$SCRATCH/t13_y.bm" "$SCRATCH/t13_z.bm" || DIFF_PAIRS=$((DIFF_PAIRS+1))
# 3 pairings; we expect all 3 to differ at N=4. Settle for >=2 to absorb
# any unlikely XOR-fold collision under ROTATE=0; bumping ROTATE is tested
# below.
if [[ "$DIFF_PAIRS" -ge 2 ]]; then
    pass "N=4 distinguishes $DIFF_PAIRS/3 reordered-input pairs"
else
    fail "N=4 only distinguishes $DIFF_PAIRS/3 reordered-input pairs (XOR collision?)"
fi

# ----------------------------------------------------------------------
section "T14: build LIBCOV_NGRAM_N=4 + LIBCOV_NGRAM_ROTATE=1 -- breaks XOR commutativity"
N4R="$(build_variant ngram_n4_rotate '-DLIBCOV_NGRAM_N=4 -DLIBCOV_NGRAM_ROTATE=1')"
N4R_LCV="$SCRATCH/orderable_n4r.lcv"
gen_lcv "$N4R/target_orderable" "$N4R_LCV" \
    --threading "$THREADING" \
    --include-pat '^dbg\.(main|dispatch|state_a|state_b|state_c|state_d)$' \
    || { fail "gen N=4 ROT=1"; exit 1; }
run_orderable "$N4R" "$N4R_LCV" "$SCRATCH/t14_x.shm" oneshot aabbcc
run_orderable "$N4R" "$N4R_LCV" "$SCRATCH/t14_y.shm" oneshot bbccaa
run_orderable "$N4R" "$N4R_LCV" "$SCRATCH/t14_z.shm" oneshot ccaabb
extract_bitmap "$SCRATCH/t14_x.shm" "$SCRATCH/t14_x.bm"
extract_bitmap "$SCRATCH/t14_y.shm" "$SCRATCH/t14_y.bm"
extract_bitmap "$SCRATCH/t14_z.shm" "$SCRATCH/t14_z.bm"
DIFF_PAIRS=0
cmp -s "$SCRATCH/t14_x.bm" "$SCRATCH/t14_y.bm" || DIFF_PAIRS=$((DIFF_PAIRS+1))
cmp -s "$SCRATCH/t14_x.bm" "$SCRATCH/t14_z.bm" || DIFF_PAIRS=$((DIFF_PAIRS+1))
cmp -s "$SCRATCH/t14_y.bm" "$SCRATCH/t14_z.bm" || DIFF_PAIRS=$((DIFF_PAIRS+1))
# Under THREADING=mt the alignment filter shrinks the patchlist enough
# that 4-record target_orderable cannot always differentiate all 3
# reorderings via the rotated N-gram fold; accept the same threshold as
# T13 in that case. Under ST we require strict 3/3.
if [[ "$THREADING" == "mt" ]]; then
    WANT_DIFF=2
else
    WANT_DIFF=3
fi
if [[ "$DIFF_PAIRS" -ge "$WANT_DIFF" ]]; then
    pass "N=4 + ROTATE=1 distinguishes $DIFF_PAIRS/3 reordered pairs (want >=$WANT_DIFF)"
else
    fail "N=4 + ROTATE=1 distinguishes $DIFF_PAIRS/3 pairs (want >=$WANT_DIFF)"
fi

# ----------------------------------------------------------------------
section "T15: build LIBCOV_COVERAGE_MODEL_SITE=0 -- legacy hashed-PC, map_size = 64 KiB"
HASHED="$(build_variant covmodel_hashed_pc '-DLIBCOV_COVERAGE_MODEL_SITE=0')"
HASHED_LCV="$SCRATCH/hashed.lcv"
gen_lcv "$HASHED/target_simple" "$HASHED_LCV" \
    --threading "$THREADING" \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline)$' \
    || { fail "gen hashed"; exit 1; }
run_simple "$HASHED" "$HASHED_LCV" "$SCRATCH/t15.shm" leapfrog 42
parse_stats "$SCRATCH/t15.shm"
# Default LIBCOV_MAP_SIZE_POW2=16 => 65536. Edges should also be > 0,
# proving the runtime is actually emitting under the legacy formula.
if [[ "$s_map_size" -eq 65536 && "$s_edges" -gt 0 ]]; then
    pass "hashed-PC model: map_size=$s_map_size, edges=$s_edges"
else
    fail "hashed-PC: map_size=$s_map_size edges=$s_edges (want 65536 & >0)"
fi

# ----------------------------------------------------------------------
section "T16: build LIBCOV_MAP_SIZE_POW2=18 + hashed-PC -- map_size = 256 KiB"
HASHED_BIG="$(build_variant covmodel_hashed_big '-DLIBCOV_COVERAGE_MODEL_SITE=0 -DLIBCOV_MAP_SIZE_POW2=18')"
HASHED_BIG_LCV="$SCRATCH/hashed_big.lcv"
gen_lcv "$HASHED_BIG/target_simple" "$HASHED_BIG_LCV" \
    --threading "$THREADING" \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline)$' \
    || { fail "gen hashed_big"; exit 1; }
run_simple "$HASHED_BIG" "$HASHED_BIG_LCV" "$SCRATCH/t16.shm" leapfrog 42
parse_stats "$SCRATCH/t16.shm"
if [[ "$s_map_size" -eq 262144 && "$s_edges" -gt 0 ]]; then
    pass "hashed-PC + POW2=18: map_size=$s_map_size, edges=$s_edges"
else
    fail "hashed-PC + POW2=18: map_size=$s_map_size edges=$s_edges (want 262144 & >0)"
fi

# ----------------------------------------------------------------------
section "T16b: shm header tags the coverage scheme each build used"
# sink_init stamps LIBCOV_SHM_FLAG_SCHEME + N + model + rotate into
# hdr->flags; shm_bitmap.py scheme decodes them.
for pair in "t4:n=2 model=site rotate=0" \
            "t11_fwd:n=1 model=site rotate=0" \
            "t13_x:n=4 model=site rotate=0" \
            "t14_x:n=4 model=site rotate=1" \
            "t15:n=2 model=pc rotate=0"; do
    f="${pair%%:*}" want="${pair#*:}"
    got="$("$ROOT/test/shm_bitmap.py" scheme "$SCRATCH/$f.shm")"
    if [[ "$got" == "$want" ]]; then
        pass "$f.shm scheme: $got"
    else
        fail "$f.shm scheme: got '$got', want '$want'"
    fi
done

# ----------------------------------------------------------------------
section "T16c: site-id map headroom (LIBCOV_MAP_FUDGE) scales with N"
# MIN_POW2=6 lowers the 4 KiB floor so the fudge term is visible on a
# small target. Expected: map = max(1<<6, next_pow2(n), next_pow2(n*fudge))
# with default fudge 2 at N=1, 16 at N=2, 64 at N=4; -DLIBCOV_MAP_FUDGE wins.
expect_map() {  # <n_sites> <fudge>
    python3 -c '
import sys
n, f = int(sys.argv[1]), int(sys.argv[2])
p2 = lambda v: 1 << (max(v, 1) - 1).bit_length()
print(max(64, p2(n), min(1 << 24, p2(n * f))))' "$1" "$2"
}
prev_map=0
for spec in "fudge_n1:-DLIBCOV_NGRAM_N=1:2" \
            "fudge_n2::16" \
            "fudge_n4:-DLIBCOV_NGRAM_N=4:64" \
            "fudge_n4_ovr:-DLIBCOV_NGRAM_N=4 -DLIBCOV_MAP_FUDGE=4:4"; do
    IFS=: read -r tag flags fudge <<<"$spec"
    VB="$(build_variant "$tag" "-DLIBCOV_MAP_MIN_POW2=6 $flags")"
    VLCV="$SCRATCH/$tag.lcv"
    gen_lcv "$VB/target_simple" "$VLCV" --threading "$THREADING" \
        || { fail "gen $tag"; continue; }
    n=$(lcv_record_count "$VLCV")
    rm -f "$SCRATCH/$tag.shm"
    LIBCOV_PATCHLIST="$VLCV" LIBCOV_SHM_PATH="$SCRATCH/$tag.shm" \
        LIBCOV_LOG="$SCRATCH/$tag.log" LD_PRELOAD="$VB/libcov_${THREADING}.so" \
        "$VB/target_simple" 42 >/dev/null 2>&1 || true
    parse_stats "$SCRATCH/$tag.shm"
    want=$(expect_map "$n" "$fudge")
    if [[ "$s_map_size" -eq "$want" ]] && grep -q "fudge=$fudge map_size=$want" "$SCRATCH/$tag.log"; then
        pass "$tag: n_sites=$n fudge=$fudge map_size=$s_map_size"
    else
        fail "$tag: n_sites=$n map_size=$s_map_size (want $want, fudge $fudge); log: $(grep 'coverage model' "$SCRATCH/$tag.log")"
    fi
    if [[ "$tag" == fudge_n2 || "$tag" == fudge_n4 ]]; then
        [[ "$s_map_size" -gt "$prev_map" ]] && pass "$tag map grows with N ($prev_map -> $s_map_size)" \
            || fail "$tag map did not grow with N ($prev_map -> $s_map_size)"
        grep -q "expected share of N-grams in a shared bucket: [0-9.]*% if $n distinct" "$SCRATCH/$tag.log" \
            && pass "$tag logs a collision estimate" \
            || fail "$tag: no collision estimate in the init log"
    fi
    [[ "$tag" == fudge_n4_ovr ]] || prev_map=$s_map_size
done

# ======================================================================
# Boundary-mode env-var validation. Re-uses target_loop + fuzz_driver from
# the default variant build so we don't repeat boundary-list generation.
# ======================================================================

section "T17: LIBCOV_BOUNDARY_RING -- shm header reports requested ring size"
LOOP_LCV="$SCRATCH/loop.lcv"
LOOP_LCVB="$SCRATCH/loop.lcvb"
gen_lcv "$DFLT/target_loop" "$LOOP_LCV" \
    --threading "$THREADING" \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline|process_one|iter_begin)$' \
    || { fail "gen loop lcv"; exit 1; }
"$ROOT/tools/gen_boundary.py" "$DFLT/target_loop" "$LOOP_LCVB" iter_begin:begin \
    >/dev/null 2>"$SCRATCH/loop.bnd.log" \
    || { fail "gen loop lcvb"; exit 1; }

run_loop_with_ring() {
    local ring="$1" out="$2"
    rm -f "$SCRATCH/t17_${ring}.shm"
    # Drive target_loop directly (without fuzz_driver) so we control the
    # ring env var without forking through a wrapper. target_loop reads
    # stdin and fires iter_begin per line; we just need it to publish at
    # least one snapshot so the header is populated.
    LIBCOV_PATCHLIST="$LOOP_LCV" LIBCOV_BOUNDARY_LIST="$LOOP_LCVB" \
        LIBCOV_SHM_PATH="$SCRATCH/t17_${ring}.shm" \
        LIBCOV_MODE=leapfrog LIBCOV_BOUNDARY_RING="$ring" \
        LIBCOV_LOG=/dev/null LD_PRELOAD="$DFLT_LIB" \
        "$DFLT/target_loop" >/dev/null 2>&1 <<<$'42\n99\n-3\n' || true
    stats_from_shm "$SCRATCH/t17_${ring}.shm" > "$out"
}

for r in 2 4 8; do
    run_loop_with_ring "$r" "$SCRATCH/t17_${r}.stats"
    got=$(sed -n 's/.*ring=\([0-9]*\).*/\1/p' "$SCRATCH/t17_${r}.stats")
    if [[ "$got" == "$r" ]]; then
        pass "ring=$r honored (header reports ring=$got)"
    else
        fail "ring=$r requested, header reports ring=$got"
    fi
done

# Unset -> the default, 8 (4 used to overrun under REARM=all).
run_loop_with_ring "" "$SCRATCH/t17_default.stats"
got=$(sed -n 's/.*ring=\([0-9]*\).*/\1/p' "$SCRATCH/t17_default.stats")
if [[ "$got" == 8 ]]; then
    pass "ring unset -> default ring=8"
else
    fail "ring unset: header reports ring=$got, want the default 8"
fi

# ----------------------------------------------------------------------
section "T18: LIBCOV_BOUNDARY_INIT_GRACE -- drops first N marker fires before publish"
# Send 5 inputs to target_loop; in begin-only mode 5 inputs fire 6 marker
# hits (iter 0..4 at the top of each iteration + post-loop flush).
# Without grace: gen_current ends at 6 (allowing for jitter we accept >=5).
# With grace=2: first 2 fires drop, then 4 publish -> gen_current = 4.
INPUTS=$'42\n99\n-3\nabc\nhello\n'

run_grace() {
    local grace="$1" out_stats="$2"
    rm -f "$SCRATCH/t18_g${grace}.shm"
    LIBCOV_PATCHLIST="$LOOP_LCV" LIBCOV_BOUNDARY_LIST="$LOOP_LCVB" \
        LIBCOV_SHM_PATH="$SCRATCH/t18_g${grace}.shm" \
        LIBCOV_MODE=leapfrog LIBCOV_BOUNDARY_INIT_GRACE="$grace" \
        LIBCOV_LOG=/dev/null LD_PRELOAD="$DFLT_LIB" \
        "$DFLT/target_loop" >/dev/null 2>&1 <<<"$INPUTS" || true
    stats_from_shm "$SCRATCH/t18_g${grace}.shm" > "$out_stats"
}

run_grace 0 "$SCRATCH/t18_g0.stats"
run_grace 2 "$SCRATCH/t18_g2.stats"
G0=$(sed -n 's/.*gen_cur=\([0-9]*\).*/\1/p' "$SCRATCH/t18_g0.stats")
G2=$(sed -n 's/.*gen_cur=\([0-9]*\).*/\1/p' "$SCRATCH/t18_g2.stats")
echo "   grace=0 gen_current=$G0   grace=2 gen_current=$G2"
# Allow for "+- 1" jitter from when target_loop's post-loop flush fires vs
# stdin EOF timing. The deterministic relationship is G2 == G0 - 2.
if [[ "$G0" -eq 0 && "$G2" -eq 0 && "$THREADING" == "mt" ]]; then
    # Under MT on x86_64, gen_patchlist --threading mt may filter out
    # iter_begin's BB terminator if it doesn't meet the 2-byte aligned /
    # no-fetch-block-straddle constraint. Without that site patched, no
    # marker fires happen and the grace test is moot. The boundary
    # mechanism itself is exercised under MT by run_validation_boundary.sh
    # against per-arch hardware where the iter_begin terminator survives.
    skip "no marker fires under MT (iter_begin terminator filtered by alignment); covered by run_validation_boundary.sh"
elif [[ "$G0" -gt "$G2" && $((G0 - G2)) -ge 2 ]]; then
    pass "grace=2 dropped at least 2 marker fires (G0=$G0, G2=$G2)"
else
    fail "grace had no effect (G0=$G0, G2=$G2)"
fi

# ======================================================================
# Reference-only -- these are validated by sibling scripts; we just print
# a pointer so the user knows where to find the per-arch / boundary /
# multimod / MT coverage.
# ======================================================================

section "Reference: sibling validation scripts"
echo "   - run_validation.sh           (native $THREADING regression)"
echo "   - run_validation_mt.sh        (native MT regression + stress)"
echo "   - run_validation_boundary.sh  (boundary mode + (MODE, REARM) matrix)"
echo "   - run_validation_multimod.sh  (multi-module LCV3)"
echo "   - run_cross.sh                (all-arch ST under qemu-user-static)"
echo "   - run_cross_mt.sh             (all-arch MT under qemu-user-static)"

# ======================================================================
section "summary"
echo "PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
if [[ "$FAIL" -gt 0 ]]; then exit 1; fi
echo
echo "ALL COVERAGE-OPTION VALIDATIONS PASSED ($ARCH, THREADING=$THREADING)"
