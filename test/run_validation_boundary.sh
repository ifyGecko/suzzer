#!/usr/bin/env bash
# Boundary-mode end-to-end validation (ST).
#
# Spawns target_loop once under libcov with LIBCOV_BOUNDARY_LIST set, pipes
# several inputs through the fuzz_driver, and verifies that:
#   1. The driver successfully reads N+1 snapshots for N inputs (init
#      slot + per-input slots + EOF-flush slot).
#   2. The seqlock reader never reports torn reads or overruns.
#   3. gen_init is recorded.
#   4. Per-iteration bitmaps differ across inputs (proves libcov really
#      clears the bitmap between iterations -- otherwise every iter's
#      bitmap would be a cumulative union).
#   5. All three viable (MODE, BOUNDARY_REARM) combinations produce gens.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Per-run scratch dir: fixed /tmp paths made parallel runs collide.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
ARCH="${ARCH:-$(uname -m)}"
LIB="$ROOT/build/$ARCH/libcov_st.so"
TARGET="$ROOT/build/$ARCH/target_loop"
DRIVER="$ROOT/build/$ARCH/fuzz_driver"
LCV="$WORK/target_loop.lcv"
LCVB="$WORK/target_loop.lcvb"

if [[ "$(cat /proc/sys/kernel/randomize_va_space)" != "0" ]]; then
    echo "WARN: ASLR is on; PoC assumes ASLR off for deterministic addresses" >&2
fi

[[ -f "$LIB" ]]    || { echo "missing $LIB. Run 'make' first." >&2; exit 1; }
[[ -x "$TARGET" ]] || { echo "missing $TARGET. Run 'make' first." >&2; exit 1; }
[[ -x "$DRIVER" ]] || { echo "missing $DRIVER. Run 'make' first." >&2; exit 1; }

echo ">> regenerate patch list for target_loop"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV" \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline|process_one|iter_begin)$' \
    >/dev/null 2>$WORK/v_b.gen.log

echo ">> generate boundary sidecar (iter_begin = begin marker)"
"$ROOT/tools/gen_boundary.py" "$TARGET" "$LCVB" iter_begin:begin \
    >/dev/null 2>$WORK/v_b.bnd.log

echo ">> a begin-only sidecar with depth_filter=zero is refused unless --force"
if "$ROOT/tools/gen_boundary.py" "$TARGET" "$WORK/zero.lcvb" iter_begin:begin:zero \
        >/dev/null 2>"$WORK/zero.err"; then
    echo "FAIL: begin-only :zero accepted" >&2; exit 1
fi
grep -q 'no effect without END markers' "$WORK/zero.err" && [[ ! -e "$WORK/zero.lcvb" ]] \
    || { echo "FAIL: refusal message missing or file written: $(cat "$WORK/zero.err")" >&2; exit 1; }
"$ROOT/tools/gen_boundary.py" "$TARGET" "$WORK/zero.lcvb" iter_begin:begin:zero --force \
    >/dev/null 2>"$WORK/zero.err" && [[ -s "$WORK/zero.lcvb" ]] \
    && grep -q '^warning: depth_filter=zero' "$WORK/zero.err" \
    || { echo "FAIL: --force did not write the sidecar with a warning" >&2; exit 1; }
echo "   OK: refused without --force (nothing written); written with a warning under --force"

OUT="$WORK/driver.out"

INPUTS=$'42\n99\n-3\nabc\nhello\n'

echo ">> run driver against target_loop"
printf '%s' "$INPUTS" | "$DRIVER" "$LIB" "$LCV" "$LCVB" "$TARGET" > "$OUT" 2>&1

echo "----- driver output -----"
cat "$OUT"
echo "-------------------------"

# Begin-only markers fire at the START of each iteration, publishing the
# PREVIOUS iter's coverage. For N inputs that's N+1 gens total:
#   gen=1: init coverage (caused by sending input 1, fires iter_begin(0))
#   gen=k for k in [2..N]: input k-1's coverage
#   gen=N+1: EOF-flush -- post-loop iter_begin publishes the last input
# 5 inputs -> 6 gens expected.
gens=$(grep -c '^gen=' "$OUT" || true)
if [[ "$gens" -lt 6 ]]; then
    echo "FAIL: expected at least 6 published gens, got $gens" >&2; exit 1
fi
echo "   OK: $gens gens published"

if grep -q 'OVERRUN\|torn\|read_slot.*failed' "$OUT"; then
    echo "FAIL: driver reported desync/overrun" >&2; exit 1
fi
echo "   OK: no desync / overrun reported"

if ! grep -q 'gen_init=1' "$OUT"; then
    echo "FAIL: gen_init was not recorded" >&2; exit 1
fi
echo "   OK: gen_init=1 recorded (init coverage captured)"

# Per-iter bitmaps must differ across inputs. We check by comparing hit
# counts -- if libcov were not clearing the bitmap between iterations,
# hit counts would be monotonically non-decreasing AND each iter's
# bitmap would be a cumulative superset. Instead we expect variation.
hits=$(awk '/^gen=/{for(i=1;i<=NF;i++)if($i~/^hit=/){gsub("hit=","",$i);print $i}}' "$OUT")
distinct=$(echo "$hits" | sort -un | wc -l)
if [[ "$distinct" -lt 2 ]]; then
    echo "FAIL: every iteration reported the same hit count ($hits); bitmap may not be clearing" >&2
    exit 1
fi
echo "   OK: per-iteration hit counts vary (distinct=$distinct) -- bitmap is being cleared"

total_final=$(awk '/^gen=/{for(i=1;i<=NF;i++)if($i~/^total=/){gsub("total=","",$i);t=$i}}END{print t}' "$OUT")
if [[ -z "$total_final" || "$total_final" -lt 5 ]]; then
    echo "FAIL: final cumulative coverage suspiciously low (total=$total_final)" >&2; exit 1
fi
echo "   OK: cumulative coverage = $total_final edges"

grep -q ' overruns=0 lost_gens=0 read_failures=0 ' "$OUT" \
    || { echo "FAIL: driver summary reports lost coverage" >&2; exit 1; }
echo "   OK: driver summary: no overruns, no lost gens"

echo
echo ">> overrun accounting: burst all inputs, then read (FUZZ_DRIVER_BURST=1)"
# The driver reads nothing until the target has exited, so every gen is
# already published. A 2-slot ring keeps only the newest one readable:
# the driver must count the loss and exit 3. A 16-slot ring holds all 6.
burst() {  # <ring> <out>; prints the driver's exit status
    local rc=0
    printf '%s' "$INPUTS" | FUZZ_DRIVER_BURST=1 LIBCOV_BOUNDARY_RING="$1" \
        "$DRIVER" "$LIB" "$LCV" "$LCVB" "$TARGET" > "$2" 2>&1 || rc=$?
    echo "$rc"
}
rc=$(burst 2 "$WORK/burst2.out")
lost=$(sed -n 's/.* lost_gens=\([0-9]*\).*/\1/p' "$WORK/burst2.out")
if [[ "$rc" != 3 ]] || ! grep -q '^OVERRUN: ' "$WORK/burst2.out" \
        || [[ -z "$lost" || "$lost" -lt 1 ]]; then
    echo "FAIL: ring=2 burst: rc=$rc lost_gens=$lost (want rc=3, lost>=1)" >&2
    cat "$WORK/burst2.out" >&2; exit 1
fi
# What survived is still reported: the newest gen is read after the skip.
grep -q '^gen=.*(burst)' "$WORK/burst2.out" \
    || { echo "FAIL: ring=2 burst read nothing after the overrun" >&2; exit 1; }
echo "   OK: ring=2: overrun counted (lost_gens=$lost), exit 3, newest gen still read"
rc=$(burst 16 "$WORK/burst16.out")
g16=$(grep -c '^gen=' "$WORK/burst16.out" || true)
if [[ "$rc" != 0 || "$g16" -lt 6 ]] || grep -q '^OVERRUN' "$WORK/burst16.out"; then
    echo "FAIL: ring=16 burst: rc=$rc gens=$g16 (want rc=0, >=6 gens, no overrun)" >&2
    cat "$WORK/burst16.out" >&2; exit 1
fi
echo "   OK: ring=16: all $g16 gens read, exit 0"

echo
echo ">> sanity-check the (MODE, REARM) matrix"
check_combo() {
    local mode="$1" rearm="$2" want_min="$3"
    local out
    out="$WORK/combo.out"
    LIBCOV_MODE="$mode" LIBCOV_BOUNDARY_REARM="$rearm" \
        "$DRIVER" "$LIB" "$LCV" "$LCVB" "$TARGET" \
        < <(printf '42\n99\n-3\n') > "$out" 2>&1
    local g
    g=$(grep -c '^gen=' "$out" || true)
    if [[ "$g" -lt "$want_min" ]]; then
        echo "FAIL: MODE=$mode REARM=$rearm produced $g gens (want >= $want_min)" >&2
        cat "$out" >&2
        exit 1
    fi
    if grep -q 'OVERRUN\|torn\|read_slot.*failed' "$out"; then
        echo "FAIL: MODE=$mode REARM=$rearm reported desync" >&2
        cat "$out" >&2
        exit 1
    fi
    echo "   OK: MODE=$mode REARM=$rearm produced $g gens"
}
# 3 inputs -> 4 gens published (init + 3 coverage slots).
check_combo leapfrog none    4
check_combo oneshot  all     4
check_combo oneshot  touched 4

echo
echo ">> LIBCOV_BOUNDARY_NOTIFY_FD: eventfd accepted and signalled, pipe refused"
# The notify write runs inside the trap handler; a pipe could block it
# forever (full) or SIGPIPE the target (reader gone), so libcov must only
# accept an eventfd.
python3 - "$LIB" "$LCV" "$LCVB" "$TARGET" "$WORK" <<'PYEOF'
import os, subprocess, sys
lib, lcv, lcvb, target, work = sys.argv[1:]

def run(fd):
    env = dict(os.environ, LD_PRELOAD=lib, LIBCOV_PATCHLIST=lcv,
               LIBCOV_BOUNDARY_LIST=lcvb, LIBCOV_MODE="leapfrog",
               LIBCOV_SHM_PATH=f"{work}/notify_{fd}.shm",
               LIBCOV_BOUNDARY_NOTIFY_FD=str(fd))
    p = subprocess.run([target], input=b"42\n99\n", env=env, pass_fds=(fd,),
                       capture_output=True, timeout=30)
    try: os.unlink(env["LIBCOV_SHM_PATH"])
    except FileNotFoundError: pass
    return p.returncode, p.stderr.decode(errors="replace")

efd = os.eventfd(0, os.EFD_NONBLOCK)
rc, err = run(efd)
if rc != 0 or f"notify fd={efd}" not in err:
    sys.exit(f"FAIL: eventfd not accepted (rc={rc})\n{err}")
count = os.eventfd_read(efd)
if count < 3:
    sys.exit(f"FAIL: eventfd signalled {count} times, want >= 3 (one per publish)")
print(f"   OK: eventfd accepted, signalled {count} times")

r, w = os.pipe()
rc, err = run(w)
if rc != 0 or "is not an inherited eventfd" not in err:
    sys.exit(f"FAIL: pipe not refused (rc={rc})\n{err}")
print("   OK: pipe refused with a warning")
PYEOF

echo
echo "ALL BOUNDARY VALIDATIONS PASSED ($ARCH)"
