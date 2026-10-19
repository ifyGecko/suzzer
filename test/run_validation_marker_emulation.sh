#!/usr/bin/env bash
# Boundary-marker emulation. On every backend libcov never disarms a
# marker it can emulate: the trap handler performs the marker's
# instruction itself and moves the PC past it. A wrong emulation sends the
# target down the wrong branch (or corrupts a register), so:
#
#   target_markers calls four marker functions n times each; their
#   branches cover the conditional forms each emulator decodes (see
#   target_markers.c), taken and not taken. For ST and MT, emulation on
#   and off (LIBCOV_BOUNDARY_EMULATE=0, the disarm/re-arm fallback):
#     1. the printed branch trace is identical to a run without libcov;
#     2. every marker call fired a boundary (gen_current == markers * n);
#     3. the log reports every marker emulated (or 0 when disabled).
#
# MIPS (mips, mipsel, mips64, mips64el) puts markers on block-entry
# instructions (delay slots rule out branches), which in target_markers
# are prologue ALU ops (lui, daddiu); src/arch_mips_emulate.h performs
# those, so there too every marker is emulated. Its decoder is also
# unit-tested natively on every run (test/unit_mips_emulate.c): every
# supported instruction, o32 vs n64 sign extension, and the instructions
# it must refuse.
#
# ARCH=<cross arch> runs that build under qemu-<arch>-static. MT runs only
# natively and for aarch64: qemu-user's translation cache can't follow
# MT's in-place patching on the other backends (README, Limitations).
# ARCH=arm checks both target_markers (ARM) and target_markers_thumb.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"
N=40

declare -A QEMU=(
  [aarch64]=qemu-aarch64-static   [arm]=qemu-arm-static
  [powerpc]=qemu-ppc-static       [powerpc64]=qemu-ppc64-static
  [powerpc64le]=qemu-ppc64le-static [riscv64]=qemu-riscv64-static
  [mips]=qemu-mips-static         [mipsel]=qemu-mipsel-static
  [mips64]=qemu-mips64-static     [mips64el]=qemu-mips64el-static
)
declare -A SYSROOT=(
  [aarch64]=/usr/aarch64-linux-gnu   [arm]=/usr/arm-linux-gnueabihf
  [powerpc]=/usr/powerpc-linux-gnu   [powerpc64]=/usr/powerpc64-linux-gnu
  [powerpc64le]=/usr/powerpc64le-linux-gnu [riscv64]=/usr/riscv64-linux-gnu
  [mips]=/usr/mips-linux-gnu         [mipsel]=/usr/mipsel-linux-gnu
  [mips64]=/usr/mips64-linux-gnuabi64 [mips64el]=/usr/mips64el-linux-gnuabi64
)
if [[ "$ARCH" == "$(uname -m)" ]]; then
    RUN=()
elif [[ -n "${QEMU[$ARCH]:-}" ]]; then
    RUN=("${QEMU[$ARCH]}" -L "${SYSROOT[$ARCH]}")
else
    echo "ARCH=$ARCH: add a qemu runner here" >&2; exit 1
fi
EMULATES=1     # every backend now emulates its markers
case "$ARCH" in
    "$(uname -m)"|aarch64) THREADINGS=(st mt) ;;
    *)                     THREADINGS=(st) ;;
esac
TARGETS=(target_markers)
[[ "$ARCH" == arm ]] && TARGETS+=(target_markers_thumb)
# On ppc64 ELFv1 (BE) m_zero's -O2 body starts with a nop, which rizin
# misses; the generators recover its name from the .opd descriptor.
MARKERS=(m_short m_near m_bit m_zero)
NM=${#MARKERS[@]}

need=("$B/libcov_st.so")
[[ " ${THREADINGS[*]} " == *" mt "* ]] && need+=("$B/libcov_mt.so")
for t in "${TARGETS[@]}"; do need+=("$B/$t"); done
for f in "${need[@]}"; do
    [[ -e "$f" ]] || { echo "missing $f. Run 'make ARCH=$ARCH', 'make ARCH=$ARCH THREADING=mt' and build the test targets." >&2; exit 1; }
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

# run_bounded <out> <what> <cmd...>: run under RUN_TIMEOUT (seconds), stdout
# to <out>; a nonzero exit or a timeout (rc 124) fails the suite.
RUN_TIMEOUT="${RUN_TIMEOUT:-60}"
run_bounded() {
    local out=$1 what=$2 rc=0; shift 2
    timeout "$RUN_TIMEOUT" "$@" > "$out" || rc=$?
    [[ $rc -eq 0 ]] && return 0
    [[ $rc -eq 124 ]] && fail "$what: timed out after ${RUN_TIMEOUT}s (RUN_TIMEOUT)"
    fail "$what: rc=$rc"
}

${HOSTCC:-gcc} -O2 -Wall -Wextra -o "$WORK/unit_mips_emulate" "$ROOT/test/unit_mips_emulate.c" \
    || fail "build unit_mips_emulate"
"$WORK/unit_mips_emulate" | sed 's/^/   /' || fail "MIPS emulator unit test"   # pipefail

for tgt in "${TARGETS[@]}"; do
T="$B/$tgt"
run_bounded "$WORK/bare.out" "$tgt bare run" "${RUN[@]}" "$T" "$N"

for th in "${THREADINGS[@]}"; do
    "$ROOT/tools/gen_patchlist.py" "$T" "$WORK/$th.lcv" --threading "$th" \
        --include-pat '^dbg\.(main|rec|m_short|m_near|m_bit|m_zero)$' \
        >/dev/null 2>"$WORK/$th.gen.log" \
        || fail "gen_patchlist ($tgt, $th): $(tail -3 "$WORK/$th.gen.log")"
    specs=(); for m in "${MARKERS[@]}"; do specs+=("$m:begin"); done
    "$ROOT/tools/gen_boundary.py" "$T" "$WORK/$th.lcvb" "${specs[@]}" \
        --patchlist "$WORK/$th.lcv" >/dev/null 2>"$WORK/$th.bnd.log" \
        || fail "gen_boundary ($tgt, $th): $(tail -3 "$WORK/$th.bnd.log")"
    # Under MT on x86 a marker's branch whose 2 bytes cross a 16-byte
    # instruction-fetch block can't be a site (src/patch_mt.c), so the
    # marker walks back to an earlier instruction, which isn't emulated
    # (m_zero's je sits at +0xf of its 16-aligned function with gcc -O2).
    # Count the markers placed differently from the ST list (st runs first).
    walked=0
    if [[ $th == mt && -f "$WORK/st.lcvb" ]]; then
        walked=$(python3 -c 'import sys
r = lambda p: [open(p, "rb").read()[16 + 16 * i:24 + 16 * i] for i in range(int(sys.argv[3]))]
print(sum(a != b for a, b in zip(r(sys.argv[1]), r(sys.argv[2]))))' \
            "$WORK/st.lcvb" "$WORK/mt.lcvb" "$NM")
    fi

    for emu in 1 0; do
        tag="$th.emu$emu"
        want=$([[ $emu == 1 && $EMULATES == 1 ]] && echo "$((NM - walked))" || echo 0)
        for mode in leapfrog oneshot; do
            rearm=$([[ $mode == oneshot ]] && echo touched || echo none)
            shm="$WORK/$tag.$mode.shm"
            env=(LD_PRELOAD="$B/libcov_$th.so" LIBCOV_PATCHLIST="$WORK/$th.lcv"
                 LIBCOV_BOUNDARY_LIST="$WORK/$th.lcvb" LIBCOV_SHM_PATH="$shm"
                 LIBCOV_MODE=$mode LIBCOV_BOUNDARY_REARM=$rearm
                 LIBCOV_BOUNDARY_EMULATE=$emu LIBCOV_LOG="$WORK/$tag.$mode.log")
            if [[ ${#RUN[@]} -gt 0 ]]; then
                qenv=(); for kv in "${env[@]}"; do qenv+=(-E "$kv"); done
                run_bounded "$WORK/$tag.$mode.out" "$tgt $th emulate=$emu $mode" \
                    "${RUN[@]}" "${qenv[@]}" "$T" "$N"
            else
                run_bounded "$WORK/$tag.$mode.out" "$tgt $th emulate=$emu $mode" \
                    env "${env[@]}" "$T" "$N"
            fi
            cmp -s "$WORK/bare.out" "$WORK/$tag.$mode.out" \
                || fail "$tgt $th emulate=$emu $mode: branch trace differs from bare run:
  bare:   $(cut -c1-120 "$WORK/bare.out")
  libcov: $(cut -c1-120 "$WORK/$tag.$mode.out")"
            grep -q "boundary: $want of $NM marker(s) emulated" "$WORK/$tag.$mode.log" \
                || fail "$tgt $th emulate=$emu $mode: want $want emulated markers: $(grep 'emulated' "$WORK/$tag.$mode.log")"
            gen=$(python3 "$ROOT/test/shm_bitmap.py" gen "$shm")
            [[ $gen -eq $((NM * N)) ]] || fail "$tgt $th emulate=$emu $mode: gen_current=$gen, want $((NM * N))"
        done
        echo "   OK: $tgt $th, emulation $([[ $emu == 1 ]] && echo on || echo off)" \
             "($want/$NM emulated): traces match, $((NM * N)) boundaries (leapfrog, oneshot+touched)"
    done
done
done

echo
echo "ALL MARKER-EMULATION VALIDATIONS PASSED ($ARCH)"
