#!/usr/bin/env bash
# Cross-arch end-to-end validation. For each supported ARCH:
#   1. Build libcov_st.so + target_simple.
#   2. Generate a patch list with gen_patchlist.py.
#   3. Run target_simple under qemu-user-static (x86_64 natively) with
#      LD_PRELOAD=libcov_st.so.
#   4. Confirm target output and report bitmap statistics.
#
# Requires Debian-flavored cross toolchains and qemu-user-static binaries
# (see HOWTO.md "Prerequisites" for the apt list). An arch whose cross gcc
# or qemu binary is missing is SKIPped, not failed.
#
# RUN_TIMEOUT (seconds, default 60) bounds every target/qemu run; a run
# that hits it is a FAIL ("timed out").

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Per-run scratch dir (fixed /tmp paths made parallel runs collide). Kept
# when anything fails, since the per-arch logs in it are how you debug.
WORK=$(mktemp -d -t libcov_cross.XXXXXX)
keep_work_on_failure() {
    local rc=$?
    if [[ $rc -eq 0 ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK" >&2; fi
    return $rc
}
trap keep_work_on_failure EXIT
cd "$ROOT"

ARCHES=( x86_64 aarch64 arm arm-thumb mips mipsel mips64 mips64el powerpc powerpc64 powerpc64le riscv64 )
INPUTS=( 42 -3 0 abcdef )
EXPECTED='E:enter\nE:med\nE:loop=1\nE:startx\nE:short\nE:exit'  # for input 42

declare -A QEMU=(
  [x86_64]=          [aarch64]=qemu-aarch64-static
  [arm]=qemu-arm-static
  [mips]=qemu-mips-static          [mipsel]=qemu-mipsel-static
  [mips64]=qemu-mips64-static      [mips64el]=qemu-mips64el-static
  [powerpc]=qemu-ppc-static
  [powerpc64]=qemu-ppc64-static    [powerpc64le]=qemu-ppc64le-static
  [riscv64]=qemu-riscv64-static
)
declare -A CROSS=(
  [x86_64]=                        [aarch64]=aarch64-linux-gnu-
  [arm]=arm-linux-gnueabihf-
  [mips]=mips-linux-gnu-           [mipsel]=mipsel-linux-gnu-
  [mips64]=mips64-linux-gnuabi64-  [mips64el]=mips64el-linux-gnuabi64-
  [powerpc]=powerpc-linux-gnu-
  [powerpc64]=powerpc64-linux-gnu- [powerpc64le]=powerpc64le-linux-gnu-
  [riscv64]=riscv64-linux-gnu-
)
declare -A SYSROOT=(
  [aarch64]=/usr/aarch64-linux-gnu
  [arm]=/usr/arm-linux-gnueabihf
  [mips]=/usr/mips-linux-gnu
  [mipsel]=/usr/mipsel-linux-gnu
  [mips64]=/usr/mips64-linux-gnuabi64
  [mips64el]=/usr/mips64el-linux-gnuabi64
  [powerpc]=/usr/powerpc-linux-gnu
  [powerpc64]=/usr/powerpc64-linux-gnu
  [powerpc64le]=/usr/powerpc64le-linux-gnu
  [riscv64]=/usr/riscv64-linux-gnu
)

RUN_TIMEOUT="${RUN_TIMEOUT:-60}"

# Both runners are bounded by RUN_TIMEOUT (rc 124 = timed out). env sets
# LD_PRELOAD after timeout(1) has started, so libcov never loads into it.
run_target() {
    # args: <build_arch> <libcov.so path> <target args...>
    local arch=$1; shift
    local lib=$1; shift
    local q=${QEMU[$arch]:-}
    local sr=${SYSROOT[$arch]:-}
    if [[ -z "$q" ]]; then
        timeout "$RUN_TIMEOUT" env LD_PRELOAD="$lib" "$@"
    else
        timeout "$RUN_TIMEOUT" "$q" -L "$sr" -E LD_PRELOAD="$lib" "$@"
    fi
}

run_target_clean() {
    local arch=$1; shift
    local q=${QEMU[$arch]:-}
    local sr=${SYSROOT[$arch]:-}
    if [[ -z "$q" ]]; then
        timeout "$RUN_TIMEOUT" "$@"
    else
        timeout "$RUN_TIMEOUT" "$q" -L "$sr" "$@"
    fi
}

# timed_out <rc> <what>: on rc 124 report the timeout, count a FAIL, and
# return 0 so the caller can `continue`.
timed_out() {
    (( $1 == 124 )) || return 1
    echo "FAIL $2 timed out after ${RUN_TIMEOUT}s (RUN_TIMEOUT)"
    FAIL=$((FAIL+1)); FAILED+=("$arch:${2// /_}_timeout")
    return 0
}

# Live-bitmap statistics, "<nonzero> <sum>". test/shm_bitmap.py reads the
# size and offset from the header (both vary: auto-sized map, target ABI
# and byte order).
count_edges() {
    python3 "$ROOT/test/shm_bitmap.py" stats "$1" | cut -d' ' -f1,2
}

PASS=0
FAIL=0
SKIP=0
FAILED=()

mkdir -p build

for arch in "${ARCHES[@]}"; do
    echo
    echo "================= $arch ================="

    # Missing toolchain / emulator: SKIP, not FAIL.
    tc_arch=$arch; [[ $arch == arm-thumb ]] && tc_arch=arm
    tc_gcc="${CROSS[$tc_arch]:-}gcc"; tc_q=${QEMU[$tc_arch]:-}
    if ! command -v "$tc_gcc" >/dev/null; then
        echo "SKIP ($tc_gcc not found)"; SKIP=$((SKIP+1)); continue
    fi
    if [[ -n $tc_q ]] && ! command -v "$tc_q" >/dev/null; then
        echo "SKIP ($tc_q not found)"; SKIP=$((SKIP+1)); continue
    fi

    # arm-thumb reuses arm libcov + a thumb-mode target binary.
    if [[ "$arch" == "arm-thumb" ]]; then
        build_arch=arm
        target_name=target_simple_thumb
        if ! make --no-print-directory ARCH=arm >/dev/null 2>build/arm.build.log; then
            echo "FAIL build (arm)"; FAIL=$((FAIL+1)); FAILED+=("$arch:build"); continue
        fi
        if ! make -C test --no-print-directory ARCH=arm CROSS=arm-linux-gnueabihf- \
                BUILD="$ROOT/build/arm" thumb >/dev/null 2>build/arm.thumb.log; then
            echo "FAIL build thumb"; FAIL=$((FAIL+1)); FAILED+=("$arch:build_thumb"); continue
        fi
    else
        build_arch=$arch
        target_name=target_simple
        if ! make --no-print-directory ARCH=$arch >/dev/null 2>build/$arch.build.log; then
            echo "FAIL build"; FAIL=$((FAIL+1)); FAILED+=("$arch:build"); continue
        fi
    fi

    target_bin=build/$build_arch/$target_name

    LCV=$WORK/$arch.lcv
    SHM=$WORK/$arch.shm
    LOG=$WORK/$arch.log
    OUT=$WORK/$arch.out

    if ! ./tools/gen_patchlist.py "$target_bin" "$LCV" \
            --include-pat '^dbg\.(main|classify|loop_sum|cmdline)$' \
            >/dev/null 2>$WORK/$arch.gen.log; then
        echo "FAIL gen_patchlist"; FAIL=$((FAIL+1)); FAILED+=("$arch:gen"); continue
    fi

    record_count=$(python3 -c "
import struct,sys
with open('$LCV','rb') as f:
    h=f.read(16)
    m,v,c,r=struct.unpack('<4sIII',h)
    print(c)")
    echo "  patch records: $record_count"

    libcov_so="$ROOT/build/$build_arch/libcov_st.so"

    # Determinism check: same input twice = identical bitmaps. Compare the
    # live bitmaps, not whole files: the header records each run's pid.
    rm -f "$SHM" "$LOG"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_LOG="$LOG" \
        LIBCOV_MODE=oneshot \
        run_target "$build_arch" "$libcov_so" "$target_bin" 42 > "$OUT.a" 2>&1
    timed_out $? "oneshot run (42)" && continue
    python3 "$ROOT/test/shm_bitmap.py" extract "$SHM" "$SHM.a"

    rm -f "$SHM"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_LOG=/dev/null \
        LIBCOV_MODE=oneshot \
        run_target "$build_arch" "$libcov_so" "$target_bin" 42 > "$OUT.b" 2>&1
    timed_out $? "oneshot rerun (42)" && continue
    python3 "$ROOT/test/shm_bitmap.py" extract "$SHM" "$SHM.b"

    if ! cmp -s "$SHM.a" "$SHM.b"; then
        echo "FAIL non-deterministic oneshot bitmap"
        FAIL=$((FAIL+1)); FAILED+=("$arch:nondeterm"); continue
    fi

    # Input differentiation check.
    rm -f "$SHM"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_LOG=/dev/null \
        LIBCOV_MODE=oneshot \
        run_target "$build_arch" "$libcov_so" "$target_bin" -3 > "$OUT.neg" 2>&1
    timed_out $? "oneshot run (-3)" && continue
    python3 "$ROOT/test/shm_bitmap.py" extract "$SHM" "$SHM.neg"
    if cmp -s "$SHM.a" "$SHM.neg"; then
        echo "FAIL bitmaps identical for input=42 vs -3"
        FAIL=$((FAIL+1)); FAILED+=("$arch:same_bitmap"); continue
    fi

    # Leapfrog hit-count check.
    rm -f "$SHM"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_LOG=/dev/null \
        LIBCOV_MODE=leapfrog \
        run_target "$build_arch" "$libcov_so" "$target_bin" 99 > "$OUT.lf" 2>&1
    timed_out $? "leapfrog run" && continue
    maxhits=$(python3 "$ROOT/test/shm_bitmap.py" stats "$SHM" | cut -d' ' -f3)
    if (( maxhits < 2 )); then
        echo "FAIL leapfrog never recorded multi-hit (max=$maxhits)"
        FAIL=$((FAIL+1)); FAILED+=("$arch:leapfrog"); continue
    fi

    # Target output unchanged under libcov.
    run_target_clean "$build_arch" "$target_bin" 42 > "$OUT.bare"
    timed_out $? "bare run" && continue
    if ! diff -q "$OUT.a" "$OUT.bare" >/dev/null; then
        echo "FAIL target output differs with libcov vs without"
        diff "$OUT.a" "$OUT.bare" | head -10
        FAIL=$((FAIL+1)); FAILED+=("$arch:output"); continue
    fi

    read edges total < <(count_edges "$SHM")
    echo "  edges=$edges total_events=$total max_hits=$maxhits"
    echo "  PASS"
    PASS=$((PASS+1))
done

echo
echo "============ SUMMARY ============"
echo "PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
if (( PASS == 0 && FAIL == 0 && SKIP > 0 )); then
    echo "NOTE: every arch was skipped -- nothing was tested. Install the cross"
    echo "      toolchains and qemu-user-static (HOWTO.md \"Prerequisites\")."
fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
    printf '  %s\n' "${FAILED[@]}"
    exit 1
fi
