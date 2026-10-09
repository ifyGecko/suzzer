#!/usr/bin/env bash
# Misconfigurations must be loud, not silently coverage-free.
#
#   1. LIBCOV_PATCHLIST unset: inert by default; LIBCOV_REQUIRE=1 aborts.
#   2. MODE=oneshot + BOUNDARY_REARM=none + a boundary list: boundaries are
#      refused with an ERROR (unless LIBCOV_ALLOW_ONESHOT_NOREARM=1). An
#      unrecognised REARM value (a typo) counts as none: refused under
#      oneshot, and a WARNING under leapfrog.
#   3. libcov_st.so in a multi-threaded target: WARNING.
#   4. LIBCOV_TRAP_SIGNO that doesn't match the trap encoding: the init
#      self-test catches it and libcov stays inert instead of the target
#      dying on its first trap (needs a rebuild; skipped with SKIP_REBUILD=1).
#   5. gen_patchlist.py selecting zero sites: non-zero exit, no file
#      (unless --allow-empty).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"
LIB_ST="$B/libcov_st.so"

for f in "$LIB_ST" "$B/target_simple" "$B/target_loop" "$B/target_simple_mt"; do
    [[ -e "$f" ]] || { echo "missing $f. Run 'make' and 'make -C test mt ARCH=$ARCH BUILD=$B'." >&2; exit 1; }
done

WORK=$(mktemp -d)
# Kept (and its path printed) when the suite fails: the generator and
# target logs in it are how you debug.
keep_work_on_failure() {
    local rc=$?
    if [[ $rc -eq 0 ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK" >&2; fi
    return $rc
}
trap keep_work_on_failure EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

"$ROOT/tools/gen_patchlist.py" "$B/target_simple" "$WORK/simple.lcv" \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline)$' >/dev/null 2>"$WORK/gen.simple.log" \
    || fail "gen_patchlist target_simple: $(tail -5 "$WORK/gen.simple.log")"
"$ROOT/tools/gen_patchlist.py" "$B/target_loop" "$WORK/loop.lcv" \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline|process_one|iter_begin)$' \
    >/dev/null 2>"$WORK/gen.loop.log" \
    || fail "gen_patchlist target_loop: $(tail -5 "$WORK/gen.loop.log")"
"$ROOT/tools/gen_boundary.py" "$B/target_loop" "$WORK/loop.lcvb" iter_begin:begin \
    >/dev/null 2>"$WORK/gen.loop_bnd.log" \
    || fail "gen_boundary target_loop: $(tail -5 "$WORK/gen.loop_bnd.log")"
"$ROOT/tools/gen_patchlist.py" "$B/target_simple_mt" "$WORK/simple_mt_st.lcv" \
    >/dev/null 2>"$WORK/gen.simple_mt.log" \
    || fail "gen_patchlist target_simple_mt: $(tail -5 "$WORK/gen.simple_mt.log")"

run() {  # <log> <env...> -- <cmd...>; returns the target's exit code
    local log="$1"; shift
    local envs=()
    while [[ "$1" != "--" ]]; do envs+=("$1"); shift; done
    shift
    set +e
    # Outer 2>/dev/null: some cases die by signal on purpose (abort), and
    # bash would report that on the script's stderr.
    ( env LIBCOV_SHM_PATH="$WORK/cov" "${envs[@]}" "$@" \
          </dev/null >/dev/null 2>"$log" ) 2>/dev/null
    local rc=$?
    set -e
    return $rc
}

echo ">> 1. LIBCOV_PATCHLIST unset"
rc=0; run "$WORK/1a" LD_PRELOAD="$LIB_ST" -- "$B/target_simple" 42 || rc=$?
[[ $rc -eq 0 ]] && grep -q "library inert" "$WORK/1a" \
    || fail "inert run: rc=$rc, log: $(cat "$WORK/1a")"
echo "   OK: inert by default"
rc=0; run "$WORK/1b" LD_PRELOAD="$LIB_ST" LIBCOV_REQUIRE=1 -- "$B/target_simple" 42 || rc=$?
[[ $rc -eq 134 ]] && grep -q "LIBCOV_REQUIRE is set -- aborting" "$WORK/1b" \
    || fail "LIBCOV_REQUIRE=1: want SIGABRT (134), got rc=$rc"
echo "   OK: LIBCOV_REQUIRE=1 aborts"

echo ">> 2. MODE=oneshot + BOUNDARY_REARM=none with a boundary list"
common=(LD_PRELOAD="$LIB_ST" LIBCOV_PATCHLIST="$WORK/loop.lcv"
        LIBCOV_BOUNDARY_LIST="$WORK/loop.lcvb" LIBCOV_MODE=oneshot)
rc=0; run "$WORK/2a" "${common[@]}" -- "$B/target_loop" || rc=$?
grep -q "boundaries NOT enabled" "$WORK/2a" && ! grep -q "boundary: active" "$WORK/2a" \
    || fail "oneshot+none not refused: $(cat "$WORK/2a")"
echo "   OK: refused with an ERROR"
rc=0; run "$WORK/2b" "${common[@]}" LIBCOV_ALLOW_ONESHOT_NOREARM=1 -- "$B/target_loop" || rc=$?
grep -q "boundary: active" "$WORK/2b" || fail "override didn't enable boundaries"
echo "   OK: LIBCOV_ALLOW_ONESHOT_NOREARM=1 enables it"
rc=0; run "$WORK/2c" "${common[@]}" LIBCOV_BOUNDARY_REARM=touched -- "$B/target_loop" || rc=$?
grep -q "boundary: active" "$WORK/2c" && ! grep -q "NOT enabled" "$WORK/2c" \
    || fail "oneshot+touched wrongly refused"
echo "   OK: oneshot+touched unaffected"
rc=0; run "$WORK/2d" "${common[@]}" LIBCOV_BOUNDARY_REARM=touchd -- "$B/target_loop" || rc=$?
grep -q "boundaries NOT enabled" "$WORK/2d" && ! grep -q "boundary: active" "$WORK/2d" \
    || fail "oneshot+REARM typo not refused: $(cat "$WORK/2d")"
echo "   OK: oneshot+REARM=touchd (typo) refused like none"
rc=0; run "$WORK/2e" "${common[@]}" LIBCOV_BOUNDARY_REARM=touchd LIBCOV_REQUIRE=1 \
    -- "$B/target_loop" || rc=$?
[[ $rc -eq 134 ]] || fail "oneshot+REARM typo with LIBCOV_REQUIRE=1: want 134, got rc=$rc"
echo "   OK: ... and aborts under LIBCOV_REQUIRE=1"
rc=0; run "$WORK/2f" "${common[@]/LIBCOV_MODE=oneshot/LIBCOV_MODE=leapfrog}" \
    LIBCOV_BOUNDARY_REARM=touchd -- "$B/target_loop" || rc=$?
grep -q "unknown LIBCOV_BOUNDARY_REARM='touchd'" "$WORK/2f" \
    && grep -q "boundary: active.*rearm=none" "$WORK/2f" \
    || fail "leapfrog+REARM typo: no WARNING / not none: $(cat "$WORK/2f")"
echo "   OK: leapfrog+REARM=touchd warns and uses none"

echo ">> 3. libcov_st.so in a multi-threaded target"
# The warning is the point: without it this configuration may simply
# crash (a peer thread faults on a page ST made briefly non-executable).
rc=0; run "$WORK/3" LD_PRELOAD="$LIB_ST" LIBCOV_PATCHLIST="$WORK/simple_mt_st.lcv" \
    LIBCOV_MODE=oneshot -- "$B/target_simple_mt" 4 2 42 99 || rc=$?
grep -q "libcov_st.so is running in a multi-threaded process" "$WORK/3" \
    || fail "no ST-in-MT warning: $(cat "$WORK/3")"
echo "   OK: warned"

echo ">> 4. trap signal / encoding mismatch"
if [[ "${SKIP_REBUILD:-0}" == 1 ]]; then
    echo "   SKIP (SKIP_REBUILD=1)"
else
    make -C "$ROOT" BUILD="$WORK/sigtrap" ARCH="$ARCH" \
        EXTRA_CFLAGS=-DLIBCOV_TRAP_SIGNO=SIGTRAP native >"$WORK/4.build.log" 2>&1 \
        || fail "mismatch build: $(tail -5 "$WORK/4.build.log")"
    rc=0; run "$WORK/4" LD_PRELOAD="$WORK/sigtrap/libcov_st.so" \
        LIBCOV_PATCHLIST="$WORK/simple.lcv" -- "$B/target_simple" 42 || rc=$?
    [[ $rc -eq 0 ]] && grep -q "trap self-test failed" "$WORK/4" \
        || fail "mismatch not caught: rc=$rc, log: $(cat "$WORK/4")"
    echo "   OK: self-test caught it; target ran inert (rc=0)"
fi

echo ">> 5. gen_patchlist.py with zero selected sites"
rc=0
"$ROOT/tools/gen_patchlist.py" "$B/target_simple" "$WORK/empty.lcv" \
    --include-pat '^main$' >/dev/null 2>"$WORK/5" || rc=$?
[[ $rc -ne 0 && ! -e "$WORK/empty.lcv" ]] && grep -q "no patch sites selected" "$WORK/5" \
    || fail "empty selection: rc=$rc: $(tail -5 "$WORK/5")"
echo "   OK: non-zero exit, nothing written"
"$ROOT/tools/gen_patchlist.py" "$B/target_simple" "$WORK/empty.lcv" \
    --include-pat '^main$' --allow-empty >/dev/null 2>"$WORK/5b" \
    && [[ -e "$WORK/empty.lcv" ]] || fail "--allow-empty didn't write the file: $(tail -5 "$WORK/5b")"
echo "   OK: --allow-empty writes it"

echo
echo "ALL FAIL-LOUD VALIDATIONS PASSED ($ARCH)"
