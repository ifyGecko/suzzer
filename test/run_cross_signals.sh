#!/usr/bin/env bash
# Cross-arch signal-handling regression (ST and MT, under qemu-user).
#
# The native test/run_validation_signals.sh, for every cross backend: each
# target_signals mode must print the same output and exit the same way
# with libcov as without. Real illegal instructions come from
# test/sigill.h, so they raise SIGILL on every arch (never SIGTRAP), and
# realill must die with SIGILL (rc 132). The MT-only rt* modes stay in the
# native suite (qemu-user's signal delivery isn't what they measure).
#
# Usage: test/run_cross_signals.sh [arch...]   (default: every cross arch)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=$(mktemp -d -t libcov_xsig.XXXXXX)
keep_work_on_failure() {
    local rc=$?
    if [[ $rc -eq 0 ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK" >&2; fi
    return $rc
}
trap keep_work_on_failure EXIT
cd "$ROOT"

MODES=( realill probe siginfo block tblock ignore hold bsd sysv sigset suspend
        mask race logsock )
ARCHES=( aarch64 arm arm-thumb mips mipsel mips64 mips64el powerpc powerpc64
         powerpc64le riscv64 )
(( $# )) && ARCHES=( "$@" )

declare -A TRIPLE=(
  [aarch64]=aarch64-linux-gnu    [arm]=arm-linux-gnueabihf
  [mips]=mips-linux-gnu          [mipsel]=mipsel-linux-gnu
  [mips64]=mips64-linux-gnuabi64 [mips64el]=mips64el-linux-gnuabi64
  [powerpc]=powerpc-linux-gnu    [powerpc64]=powerpc64-linux-gnu
  [powerpc64le]=powerpc64le-linux-gnu [riscv64]=riscv64-linux-gnu
)
declare -A QEMU=(
  [aarch64]=qemu-aarch64-static  [arm]=qemu-arm-static
  [mips]=qemu-mips-static        [mipsel]=qemu-mipsel-static
  [mips64]=qemu-mips64-static    [mips64el]=qemu-mips64el-static
  [powerpc]=qemu-ppc-static      [powerpc64]=qemu-ppc64-static
  [powerpc64le]=qemu-ppc64le-static [riscv64]=qemu-riscv64-static
)

fail=0
for arch in "${ARCHES[@]}"; do
    base=$arch; tflags=
    case $arch in
        arm)       tflags=-marm ;;
        arm-thumb) base=arm; tflags=-mthumb ;;   # arm libcov, Thumb target
    esac
    tri=${TRIPLE[$base]:-}; q=${QEMU[$base]:-}
    [[ -n $tri ]] || { echo "FAIL: unknown arch $arch"; fail=1; continue; }
    command -v "$tri-gcc" >/dev/null && command -v "$q" >/dev/null \
        || { echo "SKIP: $arch ($tri-gcc or $q missing)"; continue; }
    sr=/usr/$tri
    B="$ROOT/build/$base"
    built=1
    for th in st mt; do
        make --no-print-directory ARCH=$base THREADING=$th native \
            >"$WORK/$arch.$th.build.log" 2>&1 \
            || { echo "FAIL: $arch/$th: libcov build (log: $WORK/$arch.$th.build.log)"
                 fail=1; built=0; break; }
    done
    (( built )) || continue   # skip the whole arch, not just this variant
    T="$WORK/target_signals.$arch"
    "$tri-gcc" -O0 -g -no-pie -pthread $tflags -o "$T" test/target_signals.c \
        2>"$WORK/$arch.cc.log" \
        || { echo "FAIL: $arch: build target_signals"; fail=1; continue; }
    for th in st mt; do
        LCV="$WORK/$arch.$th.lcv"
        tools/gen_patchlist.py "$T" "$LCV" --threading $th --include-pat 'work$' \
            >"$WORK/$arch.$th.gen.log" 2>&1 \
            || { echo "FAIL: $arch/$th: gen_patchlist"; fail=1; continue; }
        bad=()
        for m in "${MODES[@]}"; do
            want_out=$(timeout 120 "$q" -L "$sr" "$T" $m 2>/dev/null); want_rc=$?
            got_out=$(timeout 120 env LIBCOV_PATCHLIST="$LCV" \
                      LIBCOV_SHM_PATH="$WORK/$arch.$th.shm" LIBCOV_LOG=/dev/null \
                      "$q" -L "$sr" -E LD_PRELOAD="$B/libcov_$th.so" "$T" $m \
                      2>/dev/null); got_rc=$?
            exp=0; [[ $m == realill ]] && exp=132
            if [[ $want_rc != "$exp" ]]; then
                bad+=("$m:bare-rc=$want_rc")
            elif [[ $got_rc != "$want_rc" || $got_out != "$want_out" ]]; then
                bad+=("$m:rc=$got_rc")
                printf '%s\n--- want\n%s\n--- got\n%s\n' "$m" "$want_out" "$got_out" \
                    >>"$WORK/$arch.$th.diff"
            fi
        done
        if (( ${#bad[@]} )); then
            echo "FAIL: $arch/$th: ${bad[*]}"; fail=1
        else
            echo "   OK: $arch/$th (${#MODES[@]} modes)"
        fi
    done
done

[[ $fail -eq 0 ]] && echo "ALL CROSS SIGNAL VALIDATIONS PASSED" || exit 1
