#!/usr/bin/env bash
# Cross-arch end-to-end validation. For each supported ARCH:
#   1. Build libcov.so + target_simple.
#   2. Generate a patch list with gen_patchlist.py.
#   3. Run target_simple under qemu-user-static with LD_PRELOAD=libcov.so.
#   4. Confirm target output and report bitmap statistics.
#
# Requires Debian-flavored cross toolchains and qemu-user-static binaries
# (see top of repository README for the apt list).

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

run_target() {
    # args: <build_arch> <libcov.so path> <target args...>
    local arch=$1; shift
    local lib=$1; shift
    local q=${QEMU[$arch]:-}
    local sr=${SYSROOT[$arch]:-}
    if [[ -z "$q" ]]; then
        LD_PRELOAD="$lib" "$@"
    else
        "$q" -L "$sr" -E LD_PRELOAD="$lib" "$@"
    fi
}

run_target_clean() {
    local arch=$1; shift
    local q=${QEMU[$arch]:-}
    local sr=${SYSROOT[$arch]:-}
    if [[ -z "$q" ]]; then
        "$@"
    else
        "$q" -L "$sr" "$@"
    fi
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

    # Determinism check: same input twice = identical bitmaps.
    rm -f "$SHM" "$LOG"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_LOG="$LOG" \
        LIBCOV_MODE=oneshot \
        run_target "$build_arch" "$libcov_so" "$target_bin" 42 > "$OUT.a" 2>&1
    cp "$SHM" "$SHM.a"

    rm -f "$SHM"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_LOG=/dev/null \
        LIBCOV_MODE=oneshot \
        run_target "$build_arch" "$libcov_so" "$target_bin" 42 > "$OUT.b" 2>&1
    cp "$SHM" "$SHM.b"

    if ! cmp -s "$SHM.a" "$SHM.b"; then
        echo "FAIL non-deterministic oneshot bitmap"
        FAIL=$((FAIL+1)); FAILED+=("$arch:nondeterm"); continue
    fi

    # Input differentiation check.
    rm -f "$SHM"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_LOG=/dev/null \
        LIBCOV_MODE=oneshot \
        run_target "$build_arch" "$libcov_so" "$target_bin" -3 > "$OUT.neg" 2>&1
    if cmp -s "$SHM.a" "$SHM"; then
        echo "FAIL bitmaps identical for input=42 vs -3"
        FAIL=$((FAIL+1)); FAILED+=("$arch:same_bitmap"); continue
    fi

    # Leapfrog hit-count check.
    rm -f "$SHM"
    LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$SHM" LIBCOV_LOG=/dev/null \
        LIBCOV_MODE=leapfrog \
        run_target "$build_arch" "$libcov_so" "$target_bin" 99 > "$OUT.lf" 2>&1
    maxhits=$(python3 "$ROOT/test/shm_bitmap.py" stats "$SHM" | cut -d' ' -f3)
    if (( maxhits < 2 )); then
        echo "FAIL leapfrog never recorded multi-hit (max=$maxhits)"
        FAIL=$((FAIL+1)); FAILED+=("$arch:leapfrog"); continue
    fi

    # Target output unchanged under libcov.
    run_target_clean "$build_arch" "$target_bin" 42 > "$OUT.bare"
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
if [[ ${#FAILED[@]} -gt 0 ]]; then
    printf '  %s\n' "${FAILED[@]}"
    exit 1
fi
