#!/usr/bin/env bash
# libdemalloc validation. Smoke-tests every detection path plus the
# OOM-resistance property that justifies libdemalloc's existence.
#
# Run from anywhere; uses absolute paths.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
LIB="$ROOT/build/$ARCH/libdemalloc.so"
TARGET="$ROOT/build/$ARCH/target_demalloc"

PASS=0
FAIL=0

# ---------------------------------------------------------------- helpers

# Build artifacts on demand so this script Just Works after `make tools`.
if [[ ! -f "$LIB" ]]; then
    echo ">> building libdemalloc.so"
    make -C "$ROOT" tools >/dev/null
fi
if [[ ! -x "$TARGET" ]]; then
    echo ">> building target_demalloc"
    make -C "$ROOT/test" demalloc \
        BUILD="$ROOT/build/$ARCH" >/dev/null
fi

[[ -f "$LIB" ]]   || { echo "FATAL: missing $LIB"   >&2; exit 1; }
[[ -x "$TARGET" ]] || { echo "FATAL: missing $TARGET" >&2; exit 1; }

# Run target_demalloc with libdemalloc preloaded. Returns the raw
# exit status (0..255 = normal exit, 128+N = killed by signal N).
run_target() {
    local mode="$1"
    LD_PRELOAD="$LIB" "$TARGET" "$mode" >/dev/null 2>&1
    echo $?
}

# Assert clean exit (0).
expect_clean() {
    local mode="$1" rc
    rc=$(run_target "$mode")
    if [[ "$rc" == "0" ]]; then
        echo "   OK ($mode -> exit 0)"
        PASS=$((PASS+1))
    else
        echo "   FAIL ($mode expected exit 0, got $rc)"
        FAIL=$((FAIL+1))
    fi
}

# Assert termination by signal (any signal -- SIGSEGV from the guard
# page or PROT_NONE quarantine, SIGABRT/SIGILL from FATAL traps,
# SIGBUS in some kernels' guard-page handling).
expect_crash() {
    local mode="$1" rc
    rc=$(run_target "$mode")
    if [[ "$rc" -ge 128 ]]; then
        local sig=$((rc - 128))
        echo "   OK ($mode -> killed by signal $sig)"
        PASS=$((PASS+1))
    else
        echo "   FAIL ($mode expected crash, got exit $rc)"
        FAIL=$((FAIL+1))
    fi
}

# ---------------------------------------------------------------- tests

echo
echo "== libdemalloc validation (ARCH=$ARCH) =="
echo

echo ">> 1. clean malloc/free roundtrip"
expect_clean clean

echo ">> 2. high-churn alloc/free survives without OOM"
expect_clean alloc_free

echo ">> 3. high-churn beyond quarantine horizon (eviction path)"
expect_clean uaf_evict

echo ">> 4. heap overflow write (trailing guard page)"
expect_crash overflow_w

echo ">> 5. underflow write (header canary check on free)"
expect_crash underflow_w

echo ">> 6. double free (canary read on PROT_NONE region)"
expect_crash double_free

echo ">> 7. use-after-free read (PROT_NONE in quarantine)"
expect_crash uaf

echo ">> 8. use-after-realloc read (old buffer quarantined)"
expect_crash uar

echo ">> 9. calloc() size overflow (multiplication wraps)"
expect_crash calloc_ovf

# ---------------------------------------------------------------- summary

echo
echo "PASS=$PASS  FAIL=$FAIL"
[[ "$FAIL" == "0" ]] || exit 1
echo "ALL libdemalloc VALIDATIONS PASSED"
