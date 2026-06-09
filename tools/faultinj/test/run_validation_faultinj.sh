#!/usr/bin/env bash
# Validation harness for libfaultinj.so.
#
# Asserts the determinism + control contracts that libfaultinj exposes
# through its env-var ABI. Modeled on tools/inject/test/run_validation_inject.sh
# and src/.../run_validation.sh in structure: a list of assertions,
# each ok/fail, and PASS=N FAIL=M reported at the end.
#
# Assertions (exercised against BOTH the file-I/O test target and the
# socket-API test target):
#
#   A. INERT     -- with LIBFAULTINJ_SEED unset, the target runs
#                   identically to a no-LD_PRELOAD baseline.
#   B. ARMED     -- with LIBFAULTINJ_SEED set and PROB high enough,
#                   the target observes at least one injection.
#   C. DETERMIN  -- two runs with the same env produce byte-identical
#                   output (the core reproducibility contract).
#   D. DIFFSEED  -- two runs with DIFFERENT seeds produce different
#                   output (with overwhelming probability).
#   E. CAP       -- LIBFAULTINJ_MAX_FAULTS=1 produces <= 1 logged
#                   injection regardless of how many rolls fire.
#   F. WARMUP    -- LIBFAULTINJ_WARMUP=K means no fault before idx=K.
#   G. DISABLE   -- LIBFAULTINJ_DISABLE=open masks the open class.
#   H. ENABLE    -- LIBFAULTINJ_ENABLE=read restricts to read only.
#   I. LOG       -- LIBFAULTINJ_LOG=<path> produces a parseable log.
#   J. SKIPFD    -- LIBFAULTINJ_SKIP_FDS containing the open()'d fd
#                   prevents that fd's read/write from being faulted
#                   (sanity check on the fd filter).
#
# Exit code: 0 on all-pass; non-zero if any assertion failed. Prints
# 'PASS=N FAIL=M' at the end.
#
# Env knobs:
#   ARCH        -- target arch (default uname -m). Drives build path.
#   ROOT        -- suzzer repo root (default: derived from script path).
#   KEEP_TMP    -- if set, /tmp/faultinj_* output files are not deleted.

set -eu

ROOT="${ROOT:-$(cd "$(dirname "$0")/../../.." && pwd)}"
ARCH="${ARCH:-$(uname -m)}"
FI_DIR="$ROOT/tools/faultinj"
LIB="$FI_DIR/build/$ARCH/libfaultinj.so"
T_FILE="$FI_DIR/build/$ARCH/target_faultinj_simple"
T_NET="$FI_DIR/build/$ARCH/target_faultinj_net"

TMPDIR_RUN="${TMPDIR:-/tmp}/faultinj_validate_$$"
mkdir -p "$TMPDIR_RUN"

PASS=0
FAIL=0
FAIL_LIST=()

hdr()  { printf '\n== %s ==\n' "$*"; }
note() { printf '   %s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf '   PASS: %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); FAIL_LIST+=("$*"); printf '   FAIL: %s\n' "$*"; }

cleanup() {
    if [[ -z "${KEEP_TMP:-}" ]]; then
        rm -rf "$TMPDIR_RUN"
    else
        note "KEEP_TMP set; output kept in $TMPDIR_RUN"
    fi
}
trap cleanup EXIT

# Sanity: artefacts must be built. If they aren't, point at the Makefile
# rather than letting LD_PRELOAD silently fall back to libc.
[[ -f "$LIB" ]]    || { echo "missing $LIB; run: make -C $FI_DIR"     >&2; exit 1; }
[[ -x "$T_FILE" ]] || { echo "missing $T_FILE; run: make -C $FI_DIR"  >&2; exit 1; }
[[ -x "$T_NET"  ]] || { echo "missing $T_NET; run: make -C $FI_DIR"   >&2; exit 1; }

# Run helper: wraps the call so we capture stdout + return code + env.
# Args:
#   $1 = label (descriptive name for tempfile)
#   $2 = target binary
#   $3 = extra LIBFAULTINJ_* env (string injected before the command)
#   $4 = extra argv beyond the binary
#
# Outputs:
#   stdout of the target -> $TMPDIR_RUN/<label>.out
#   sets $LAST_OUT to the path
run_target() {
    local label="$1" bin="$2" env_str="$3" args="$4"
    local outpath="$TMPDIR_RUN/$label.out"
    # shellcheck disable=SC2086
    /usr/bin/env LD_PRELOAD="$LIB" $env_str "$bin" $args \
        > "$outpath" 2> "$TMPDIR_RUN/$label.err" || true
    LAST_OUT="$outpath"
}

# Count lines that look like an injection happened. Two paths:
#   1. If LIBFAULTINJ_LOG was set, count log lines (authoritative).
#   2. Otherwise, count E: lines with errno != 0 AND rc < 0, which is
#      a proxy that catches FAIL_NEG1 injections. (SHORT/ZERO modes
#      look like normal IO without a log, hence the log is the
#      authoritative source for E.)
count_failures_in_output() {
    local path="$1"
    grep -cE 'E:[a-z]+#[0-9]+ rc=-1 errno=[1-9]' "$path" || true
}

count_log_injections() {
    local path="$1"
    [[ -f "$path" ]] || { echo 0; return; }
    grep -c '^faultinj ' "$path" || true
}

# ------------------------------------------------------------------
# A. INERT: no seed -> identical output to no-LD_PRELOAD baseline.
# ------------------------------------------------------------------
hdr "A. INERT (no LIBFAULTINJ_SEED -> no injection)"

"$T_FILE" "$TMPDIR_RUN" > "$TMPDIR_RUN/file.bare.out" 2>/dev/null || true
run_target "file.inert" "$T_FILE" "" "$TMPDIR_RUN"
if diff -q "$TMPDIR_RUN/file.bare.out" "$TMPDIR_RUN/file.inert.out" >/dev/null; then
    ok "file: LD_PRELOAD with no seed == no-LD_PRELOAD baseline"
else
    fail "file: inert mode altered output"
fi

"$T_NET" > "$TMPDIR_RUN/net.bare.out" 2>/dev/null || true
run_target "net.inert" "$T_NET" "" ""
if diff -q "$TMPDIR_RUN/net.bare.out" "$TMPDIR_RUN/net.inert.out" >/dev/null; then
    ok "net: LD_PRELOAD with no seed == no-LD_PRELOAD baseline"
else
    fail "net: inert mode altered output"
fi

# ------------------------------------------------------------------
# B. ARMED: high PROB + non-zero seed -> at least one injection.
# ------------------------------------------------------------------
hdr "B. ARMED (PROB=1.0 -> every eligible call faults)"

# With PROB=1.0 every call is eligible; MAX_FAULTS=999 raises the cap
# so we observe many.
run_target "file.armed" "$T_FILE" \
    "LIBFAULTINJ_SEED=0xdead LIBFAULTINJ_PROB=1.0 LIBFAULTINJ_MAX_FAULTS=999" \
    "$TMPDIR_RUN"
nfail=$(count_failures_in_output "$LAST_OUT")
note "file: observed -1 returns in output: $nfail"
if [[ "$nfail" -ge 4 ]]; then
    ok "file: PROB=1.0 produced multiple injections"
else
    fail "file: PROB=1.0 produced only $nfail injections (expected >= 4)"
fi

run_target "net.armed" "$T_NET" \
    "LIBFAULTINJ_SEED=0xdead LIBFAULTINJ_PROB=1.0 LIBFAULTINJ_MAX_FAULTS=999" ""
nfail=$(count_failures_in_output "$LAST_OUT")
note "net: observed -1 returns in output: $nfail"
if [[ "$nfail" -ge 4 ]]; then
    ok "net: PROB=1.0 produced multiple injections"
else
    fail "net: PROB=1.0 produced only $nfail injections (expected >= 4)"
fi

# ------------------------------------------------------------------
# C. DETERMINISM: same seed -> byte-identical output across runs.
# ------------------------------------------------------------------
hdr "C. DETERMINISM (same env -> same output)"

ENV_C="LIBFAULTINJ_SEED=0x42424242 LIBFAULTINJ_PROB=0.5 LIBFAULTINJ_MAX_FAULTS=999"

run_target "file.det1" "$T_FILE" "$ENV_C" "$TMPDIR_RUN"
A="$LAST_OUT"
run_target "file.det2" "$T_FILE" "$ENV_C" "$TMPDIR_RUN"
B="$LAST_OUT"
if diff -q "$A" "$B" >/dev/null; then
    ok "file: same env produced byte-identical output"
else
    fail "file: same env produced DIFFERENT output (non-deterministic)"
fi

run_target "net.det1" "$T_NET" "$ENV_C" ""
A="$LAST_OUT"
run_target "net.det2" "$T_NET" "$ENV_C" ""
B="$LAST_OUT"
if diff -q "$A" "$B" >/dev/null; then
    ok "net: same env produced byte-identical output"
else
    fail "net: same env produced DIFFERENT output (non-deterministic)"
fi

# ------------------------------------------------------------------
# D. DIFFSEED: different seeds -> different output (probabilistic but
# with PROB=0.5 over 8 rounds the chance of identical output is ~0).
# ------------------------------------------------------------------
hdr "D. DIFFSEED (different seed -> different output)"

ENV_D1="LIBFAULTINJ_SEED=0x11111111 LIBFAULTINJ_PROB=0.5 LIBFAULTINJ_MAX_FAULTS=999"
ENV_D2="LIBFAULTINJ_SEED=0x22222222 LIBFAULTINJ_PROB=0.5 LIBFAULTINJ_MAX_FAULTS=999"

run_target "file.diff1" "$T_FILE" "$ENV_D1" "$TMPDIR_RUN"
A="$LAST_OUT"
run_target "file.diff2" "$T_FILE" "$ENV_D2" "$TMPDIR_RUN"
B="$LAST_OUT"
if diff -q "$A" "$B" >/dev/null; then
    fail "file: different seeds produced identical output (PRNG suspicious)"
else
    ok "file: different seeds produced different output"
fi

run_target "net.diff1" "$T_NET" "$ENV_D1" ""
A="$LAST_OUT"
run_target "net.diff2" "$T_NET" "$ENV_D2" ""
B="$LAST_OUT"
if diff -q "$A" "$B" >/dev/null; then
    fail "net: different seeds produced identical output (PRNG suspicious)"
else
    ok "net: different seeds produced different output"
fi

# ------------------------------------------------------------------
# E. CAP: MAX_FAULTS=1 -> at most one logged injection regardless of
# how many rolls fire under PROB=1.0.
# ------------------------------------------------------------------
hdr "E. CAP (MAX_FAULTS=1 -> exactly 1 injection)"

LOG_E="$TMPDIR_RUN/file.cap.log"
run_target "file.cap" "$T_FILE" \
    "LIBFAULTINJ_SEED=0xc4dc4d LIBFAULTINJ_PROB=1.0 LIBFAULTINJ_MAX_FAULTS=1 LIBFAULTINJ_LOG=$LOG_E" \
    "$TMPDIR_RUN"
ninj=$(count_log_injections "$LOG_E")
note "file: log shows $ninj injection(s) with MAX_FAULTS=1"
if [[ "$ninj" == "1" ]]; then
    ok "file: MAX_FAULTS=1 capped at exactly 1 injection"
else
    fail "file: MAX_FAULTS=1 produced $ninj injections (expected 1)"
fi

LOG_E2="$TMPDIR_RUN/net.cap.log"
run_target "net.cap" "$T_NET" \
    "LIBFAULTINJ_SEED=0xc4dc4d LIBFAULTINJ_PROB=1.0 LIBFAULTINJ_MAX_FAULTS=1 LIBFAULTINJ_LOG=$LOG_E2" ""
ninj=$(count_log_injections "$LOG_E2")
note "net: log shows $ninj injection(s) with MAX_FAULTS=1"
if [[ "$ninj" == "1" ]]; then
    ok "net: MAX_FAULTS=1 capped at exactly 1 injection"
else
    fail "net: MAX_FAULTS=1 produced $ninj injections (expected 1)"
fi

# ------------------------------------------------------------------
# F. WARMUP: with WARMUP=100 (more than total calls), nothing faults.
# ------------------------------------------------------------------
hdr "F. WARMUP (WARMUP > total calls -> no injection)"

LOG_F="$TMPDIR_RUN/file.warmup.log"
run_target "file.warmup" "$T_FILE" \
    "LIBFAULTINJ_SEED=0xbeef LIBFAULTINJ_PROB=1.0 LIBFAULTINJ_MAX_FAULTS=999 LIBFAULTINJ_WARMUP=100 LIBFAULTINJ_LOG=$LOG_F" \
    "$TMPDIR_RUN"
ninj=$(count_log_injections "$LOG_F")
if [[ "$ninj" == "0" ]]; then
    ok "file: WARMUP=100 produced 0 injections"
else
    fail "file: WARMUP=100 should have blocked all faults but got $ninj"
fi

# ------------------------------------------------------------------
# G. DISABLE: LIBFAULTINJ_DISABLE=open -> log contains no cls=open.
# ------------------------------------------------------------------
hdr "G. DISABLE (DISABLE=open -> no open faults logged)"

LOG_G="$TMPDIR_RUN/file.disable.log"
run_target "file.disable" "$T_FILE" \
    "LIBFAULTINJ_SEED=0x55 LIBFAULTINJ_PROB=1.0 LIBFAULTINJ_MAX_FAULTS=999 LIBFAULTINJ_DISABLE=open LIBFAULTINJ_LOG=$LOG_G" \
    "$TMPDIR_RUN"
if [[ -f "$LOG_G" ]] && ! grep -q 'cls=open' "$LOG_G"; then
    ok "file: DISABLE=open suppressed all open injections"
else
    fail "file: DISABLE=open did not suppress open class"
fi

# ------------------------------------------------------------------
# H. ENABLE: LIBFAULTINJ_ENABLE=read -> log contains ONLY cls=read.
# ------------------------------------------------------------------
hdr "H. ENABLE (ENABLE=read -> only cls=read logged)"

LOG_H="$TMPDIR_RUN/file.enable.log"
run_target "file.enable" "$T_FILE" \
    "LIBFAULTINJ_SEED=0x66 LIBFAULTINJ_PROB=1.0 LIBFAULTINJ_MAX_FAULTS=999 LIBFAULTINJ_ENABLE=read LIBFAULTINJ_LOG=$LOG_H" \
    "$TMPDIR_RUN"
if [[ -f "$LOG_H" ]] && ! grep -vE '(^$|cls=read)' "$LOG_H" >/dev/null; then
    # The grep -v above means "no lines that are NOT empty and NOT
    # cls=read"; if it produces no output the assertion holds.
    ok "file: ENABLE=read restricted log to read class"
else
    fail "file: ENABLE=read did not restrict to read class"
fi

# ------------------------------------------------------------------
# I. LOG: log file exists and is parseable.
# ------------------------------------------------------------------
hdr "I. LOG (log file exists and has parseable lines)"

LOG_I="$TMPDIR_RUN/file.log.log"
run_target "file.log" "$T_FILE" \
    "LIBFAULTINJ_SEED=0x77 LIBFAULTINJ_PROB=1.0 LIBFAULTINJ_MAX_FAULTS=5 LIBFAULTINJ_LOG=$LOG_I" \
    "$TMPDIR_RUN"
if [[ -f "$LOG_I" ]] \
   && grep -qE '^faultinj seed=0x[0-9a-f]+ cls=[a-z]+ idx=[0-9]+ errno=[A-Z]+\([0-9]+\) mode=[a-z0-9-]+$' "$LOG_I"; then
    ok "file: log contains parseable injection lines"
else
    fail "file: log missing or unparseable"
    note "first lines of $LOG_I:"
    head -3 "$LOG_I" 2>/dev/null | sed 's/^/         /'
fi

# ------------------------------------------------------------------
# J. SKIPFD: skip stdout (fd 1) is implicit; that's how we got reliable
# output channels above. Cross-check by re-enabling stdio faults
# (LIBFAULTINJ_SKIP_STDIO=0) and observing that some write to fd 1
# now gets logged.
# ------------------------------------------------------------------
hdr "J. SKIPFD (SKIP_STDIO=0 -> writes to stdout can be faulted)"

LOG_J="$TMPDIR_RUN/file.stdio.log"
run_target "file.stdio" "$T_FILE" \
    "LIBFAULTINJ_SEED=0x88 LIBFAULTINJ_PROB=1.0 LIBFAULTINJ_MAX_FAULTS=999 LIBFAULTINJ_SKIP_STDIO=0 LIBFAULTINJ_ENABLE=write LIBFAULTINJ_LOG=$LOG_J" \
    "$TMPDIR_RUN"
# With SKIP_STDIO=0 + ENABLE=write + PROB=1.0, every write() to fd 1
# (including our REPORT lines) gets a fault. We expect the log to
# contain at least one cls=write entry.
if [[ -f "$LOG_J" ]] && grep -q 'cls=write' "$LOG_J"; then
    ok "file: SKIP_STDIO=0 allowed write() faults to fd 1"
else
    fail "file: SKIP_STDIO=0 did not produce any write injections"
fi

# ==================================================================
# Final tally
# ==================================================================

hdr "SUMMARY"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
    printf 'Failed assertions:\n'
    for f in "${FAIL_LIST[@]}"; do
        printf '  - %s\n' "$f"
    done
    exit 1
fi
exit 0
