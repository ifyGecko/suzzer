#!/usr/bin/env bash
# Validation harness for the libcov injector tool. Mirrors libcov's own
# test/run_validation.sh in structure but exercises the inject-into-
# running-process path instead of LD_PRELOAD-at-spawn:
#
#   1. Start target_inject_loop (long-running, stdin-driven)
#   2. Inject libcov via inject_ptrace
#   3. Feed N inputs through the target's stdin
#   4. Read the shm bitmap and assert:
#      A. Determinism      -- two separate runs with same inputs produce
#                             identical bitmaps
#      B. Differentiation  -- different inputs produce different bitmaps
#      C. Leapfrog hits    -- under MODE=leapfrog, max hit count >= 2
#      D. Output unchanged -- target's stdout under injection is the same
#                             as without injection (for the same inputs)
#
# Runs the assertions against BOTH threading variants of libcov
# (libcov_st.so and libcov_mt.so, if both are built). Each (injector,
# threading) cell contributes 4 assertions.
#
# Exit code: 0 if all assertions pass; non-zero otherwise, including when
# no cell ran at all (neither libcov variant built, or patch-list
# generation failed for both). The script prints "PASS=N FAIL=M" at the
# end.
#
# Env knobs:
#   ARCH        -- override host arch detection (default: uname -m)
#   ROOT        -- path to suzzer repo root (default: ../../../ from script)
#   KEEP_TMP    -- set to keep the per-run scratch dir (patch lists, shm
#                  files, logs) for debugging; it is also kept on failure

set -eu
set -o pipefail

ROOT="${ROOT:-$(cd "$(dirname "$0")/../../.." && pwd)}"
ARCH="${ARCH:-$(uname -m)}"
INJ_DIR="$ROOT/tools/inject"
INJ="$INJ_DIR/build/$ARCH/inject_ptrace"
TARGET="$INJ_DIR/build/$ARCH/target_inject_loop"
GEN_PATCHLIST="$ROOT/tools/gen_patchlist.py"

LIBCOV_ST="$ROOT/build/$ARCH/libcov_st.so"
LIBCOV_MT="$ROOT/build/$ARCH/libcov_mt.so"

# Per-run scratch dir (fixed /tmp/inj_* paths made parallel runs collide).
WORK=$(mktemp -d -t libcov_inject.XXXXXX)
LCV_ST="$WORK/target.st.lcv"
LCV_MT="$WORK/target.mt.lcv"
SHM_PREFIX="$WORK/validate"
LOG_PREFIX="$WORK/validate.log"
FIFO_PREFIX="$WORK/validate.fifo"

PASS=0
FAIL=0
CELLS=0
FAIL_LIST=()

note()  { printf '   %s\n' "$*"; }
hdr()   { printf '\n== %s ==\n' "$*"; }
ok()    { PASS=$((PASS + 1)); printf '   PASS: %s\n' "$*"; }
fail()  { FAIL=$((FAIL + 1)); FAIL_LIST+=("$*"); printf '   FAIL: %s\n' "$*"; }

cleanup() {
    local rc=$? pid
    for pid in "$@"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    if [[ -z "${KEEP_TMP:-}" && $rc -eq 0 ]]; then
        rm -rf "$WORK"
    else
        echo "scratch files kept in $WORK" >&2
    fi
    return $rc
}
trap 'cleanup ${TARGET_PIDS:-}' EXIT

# Sanity-check the inputs.
[[ -x "$INJ" ]]    || { echo "missing $INJ; run: make -C $INJ_DIR test" >&2; exit 1; }
[[ -x "$TARGET" ]] || { echo "missing $TARGET; run: make -C $INJ_DIR test" >&2; exit 1; }
[[ -x "$GEN_PATCHLIST" ]] || { echo "missing $GEN_PATCHLIST" >&2; exit 1; }

if [[ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]]; then
    note "warning: ASLR is on; deterministic bitmap comparison still works"
    note "         because patch records are offsets, but disassembly debugging"
    note "         is easier with ASLR off."
fi

if [[ "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)" -gt 0 ]]; then
    note "warning: Yama ptrace_scope > 0; injector needs same-UID + ptrace_scope=0,"
    note "         CAP_SYS_PTRACE, or root."
fi

# Generate the patch lists -- ST and MT are not interchangeable. libcov
# enforces the LCV3 threading hint: an ST-generated list given to
# libcov_mt is refused at init, leaving the library inert (bitmap stays
# empty -> validation B/C fail with cryptic results). So we generate
# one of each.
# A failed generator leaves no .lcv, so that cell is skipped below (and
# counted as a FAIL); its log tail is shown here.
hdr "Regenerate patch lists for target_inject_loop"
for th in st mt; do
    lcv="$WORK/target.$th.lcv"
    if "$GEN_PATCHLIST" "$TARGET" "$lcv" --threading $th \
            --include-pat '^dbg\.(main|classify|loop_sum|cmdline|process_one)$' \
            >/dev/null 2>"$WORK/gen.$th.log"; then
        note "$th patchlist: $(stat -c '%s bytes' "$lcv")"
    else
        rm -f "$lcv"
        fail "gen_patchlist --threading $th: $(tail -3 "$WORK/gen.$th.log")"
    fi
done

# Capture a baseline target stdout (no injection at all) for assertion D.
hdr "Capture baseline stdout (no libcov)"
BASELINE_OUT="$WORK/baseline.out"
(
    "$TARGET" <<EOF
42
-3
helloworld
EOF
) > "$BASELINE_OUT" 2>&1
# Drop the "PID=N" line (changes per run) and "E:enter"/"E:exit" framing
grep -v '^PID=' "$BASELINE_OUT" > "$BASELINE_OUT.norm"
note "baseline stdout captured ($(wc -l < "$BASELINE_OUT.norm") lines after PID strip)"

# ---- run_one: do an injection, feed inputs, snapshot the bitmap -----------
# Usage: run_one <lib> <patchlist> <mode> <shm-suffix> <input-list>
run_one() {
    local lib="$1" lcv="$2" mode="$3" suffix="$4" inputs="$5"
    local shm="$SHM_PREFIX.$suffix"
    local log="$LOG_PREFIX.$suffix"
    local fifo="$FIFO_PREFIX.$suffix"
    local out="$SHM_PREFIX.$suffix.targetout"

    rm -f "$shm" "$log" "$out" "$fifo"
    mkfifo "$fifo"

    # Start target with fifo as stdin
    "$TARGET" < "$fifo" > "$out" 2>&1 &
    local tpid=$!
    TARGET_PIDS="${TARGET_PIDS:-} $tpid"

    # Open the fifo for writing so target's open() unblocks; keep fd 9 open
    # for the duration so subsequent writes work.
    exec 9>"$fifo"

    # Wait for target to print "E:enter" + PID (means it's at the read() loop)
    local tries=0
    while [[ $tries -lt 50 ]]; do
        if grep -q '^PID=' "$out" 2>/dev/null; then break; fi
        sleep 0.05
        tries=$((tries + 1))
    done
    if ! grep -q '^PID=' "$out" 2>/dev/null; then
        kill -9 $tpid 2>/dev/null || true
        exec 9>&-
        rm -f "$fifo"
        echo "ERROR: target didn't reach read() loop in 2.5s" >&2
        return 1
    fi

    # Inject libcov.
    "$INJ" -P "$lcv" -S "$shm" -M "$mode" -L "$log" $tpid "$lib" > "$WORK/injout" 2>&1
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        cat "$WORK/injout" >&2
        kill -9 $tpid 2>/dev/null || true
        exec 9>&-
        rm -f "$fifo"
        echo "ERROR: inject_ptrace exited $rc" >&2
        return 1
    fi

    # Feed inputs.
    printf '%s\n' $inputs >&9

    # Give libcov a beat to record. We don't have boundary mode here so
    # there's no synchronisation point; 200ms is generous for the small
    # branch graph we exercise.
    sleep 0.2

    # Capture the live bitmap. Its size and offset come from the shm
    # header (auto-sized map, target ABI), so let shm_bitmap.py find it.
    python3 "$ROOT/test/shm_bitmap.py" extract "$shm" "$shm.bitmap" || {
        kill -9 $tpid 2>/dev/null || true
        exec 9>&-
        rm -f "$fifo"
        echo "ERROR: could not read the bitmap from $shm" >&2
        return 1
    }

    # Close fifo to send EOF; target exits its read loop.
    exec 9>&-
    rm -f "$fifo"

    # Wait briefly for target to exit; SIGKILL if it doesn't.
    local wpid
    for wpid in 1 2 3 4 5; do
        if ! kill -0 $tpid 2>/dev/null; then break; fi
        sleep 0.05
    done
    kill -9 $tpid 2>/dev/null || true
    wait $tpid 2>/dev/null || true

    return 0
}

# ---- assertion battery for one (lib, threading) pair ---------------------
assert_for_lib() {
    local lib="$1" lcv="$2" tag="$3"
    if [[ ! -f "$lib" ]]; then
        note "skip $tag: $lib not built (run: make ARCH=$ARCH THREADING=$tag in repo root)"
        return 0
    fi
    if [[ ! -f "$lcv" ]]; then
        note "skip $tag: $lcv not generated"
        return 0
    fi
    hdr "Assertions against $tag (lib=$lib, lcv=$lcv)"
    CELLS=$((CELLS + 1))

    local inputs1="42 -3 helloworld"
    # inputs2 is chosen for maximum cross-input divergence: different
    # input count (4 vs 3), wider value range (forces different
    # classify branches), and a dedicated 'a*' / 'b*' prefix series
    # that hits cmdline branches inputs1 doesn't. Important especially
    # for MT runs, where libcov_mt instruments only the MT-safe subset
    # of patches (~37% of the ST patch set on x86_64 for this target);
    # a narrower input contrast can hit only common edges and report
    # spuriously identical bitmaps.
    local inputs2="999 0 aaaaaa 1"

    # A. Determinism. Run inputs1 twice; compare bitmaps.
    run_one "$lib" "$lcv" oneshot "${tag}_a" "$inputs1" || { fail "$tag/A run #1 failed"; return; }
    run_one "$lib" "$lcv" oneshot "${tag}_b" "$inputs1" || { fail "$tag/A run #2 failed"; return; }
    if cmp -s "$SHM_PREFIX.${tag}_a.bitmap" "$SHM_PREFIX.${tag}_b.bitmap"; then
        ok "$tag/A determinism: identical inputs -> identical bitmap"
    else
        local a_set b_set
        a_set=$(python3 "$ROOT/test/shm_bitmap.py" stats "$SHM_PREFIX.${tag}_a.bitmap" | cut -d' ' -f1)
        b_set=$(python3 "$ROOT/test/shm_bitmap.py" stats "$SHM_PREFIX.${tag}_b.bitmap" | cut -d' ' -f1)
        fail "$tag/A determinism: bitmaps differ (a=$a_set b=$b_set set bytes)"
    fi

    # B. Differentiation. Different inputs should produce different bitmaps.
    #
    # We deliberately use leapfrog here (not oneshot). Rationale: oneshot
    # records only "did this edge fire" -- with a sparse patch set (e.g.
    # libcov_mt's MT-safe subset is ~37% of ST's patches on x86_64) two
    # divergent input sets can easily fire the SAME small set of patched
    # edges and produce identical oneshot bitmaps. Leapfrog accumulates
    # hit counts; counts differ across input sets even when the touched
    # edge set overlaps perfectly. Use a separate run pair instead of
    # reusing the oneshot ones because the mode change would otherwise
    # compare apples to oranges.
    run_one "$lib" "$lcv" leapfrog "${tag}_b_lf" "$inputs1" || { fail "$tag/B base-run failed"; return; }
    run_one "$lib" "$lcv" leapfrog "${tag}_c"    "$inputs2" || { fail "$tag/B alt-run failed"; return; }
    if cmp -s "$SHM_PREFIX.${tag}_b_lf.bitmap" "$SHM_PREFIX.${tag}_c.bitmap"; then
        fail "$tag/B differentiation: bitmaps identical for different inputs (leapfrog)"
    else
        ok "$tag/B differentiation: different inputs -> different bitmaps"
    fi

    # C. Leapfrog hit counts. Under MODE=leapfrog, the loop site should
    # record multiple hits (max byte value >= 2). Use an input that
    # forces a several-iter loop_sum.
    run_one "$lib" "$lcv" leapfrog "${tag}_d" "99 50 7" || { fail "$tag/C run failed"; return; }
    local max
    max=$(python3 "$ROOT/test/shm_bitmap.py" stats "$SHM_PREFIX.${tag}_d.bitmap" | cut -d' ' -f3)
    if [[ "$max" -ge 2 ]]; then
        ok "$tag/C leapfrog: recorded hit count > 1 (max=$max)"
    else
        fail "$tag/C leapfrog: never recorded a multi-hit (max=$max)"
    fi

    # D. Output unchanged. Inject and feed the baseline inputs; the
    # target's stdout (minus PID line) should match the un-injected
    # baseline. This catches injection bugs that corrupt target state.
    run_one "$lib" "$lcv" leapfrog "${tag}_e" "42 -3 helloworld" || { fail "$tag/D run failed"; return; }
    grep -v '^PID=' "$SHM_PREFIX.${tag}_e.targetout" > "$SHM_PREFIX.${tag}_e.targetout.norm"
    if diff -q "$BASELINE_OUT.norm" "$SHM_PREFIX.${tag}_e.targetout.norm" >/dev/null; then
        ok "$tag/D output unchanged after injection"
    else
        fail "$tag/D output diverges after injection"
        if [[ -n "${KEEP_TMP:-}" ]]; then
            diff "$BASELINE_OUT.norm" "$SHM_PREFIX.${tag}_e.targetout.norm" || true
        fi
    fi
}

assert_for_lib "$LIBCOV_ST" "$LCV_ST" st
assert_for_lib "$LIBCOV_MT" "$LCV_MT" mt

if [[ $CELLS -eq 0 ]]; then
    fail "nothing ran: no (libcov, patch list) cell was available -- build with:" \
         "make ARCH=$ARCH && make ARCH=$ARCH THREADING=mt (and check gen_patchlist above)"
fi

echo
echo "==================================================="
echo " inject_ptrace validation:  PASS=$PASS  FAIL=$FAIL"
echo "==================================================="
if [[ $FAIL -gt 0 ]]; then
    echo "Failed assertions:"
    for f in "${FAIL_LIST[@]}"; do echo "  - $f"; done
    exit 1
fi
exit 0
