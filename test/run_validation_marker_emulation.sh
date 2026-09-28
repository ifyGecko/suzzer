#!/usr/bin/env bash
# Boundary-marker emulation. On backends that support it (x86_64,
# aarch64, arm/Thumb, riscv64, powerpc, powerpc64) libcov never disarms a
# marker: the trap handler performs the marker's instruction itself and
# moves the PC past it. A wrong emulation sends the target down the wrong
# branch, so:
#
#   target_markers calls four marker functions n times each; their
#   branches cover the conditional forms each emulator decodes (see
#   target_markers.c), taken and not taken. For ST and MT, emulation on
#   and off (LIBCOV_BOUNDARY_EMULATE=0, the disarm/re-arm fallback):
#     1. the printed branch trace is identical to a run without libcov;
#     2. every marker call fired a boundary (gen_current == markers * n);
#     3. the log reports every marker emulated (or 0 when disabled).
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
)
declare -A SYSROOT=(
  [aarch64]=/usr/aarch64-linux-gnu   [arm]=/usr/arm-linux-gnueabihf
  [powerpc]=/usr/powerpc-linux-gnu   [powerpc64]=/usr/powerpc64-linux-gnu
  [powerpc64le]=/usr/powerpc64le-linux-gnu [riscv64]=/usr/riscv64-linux-gnu
)
if [[ "$ARCH" == "$(uname -m)" ]]; then
    RUN=()
elif [[ -n "${QEMU[$ARCH]:-}" ]]; then
    RUN=("${QEMU[$ARCH]}" -L "${SYSROOT[$ARCH]}")
else
    echo "ARCH=$ARCH: add a qemu runner here" >&2; exit 1
fi
case "$ARCH" in
    x86_64|aarch64|arm|riscv64|powerpc|powerpc64|powerpc64le) EMULATES=1 ;;
    *)                                                        EMULATES=0 ;;
esac
case "$ARCH" in
    "$(uname -m)"|aarch64) THREADINGS=(st mt) ;;
    *)                     THREADINGS=(st) ;;
esac
TARGETS=(target_markers)
[[ "$ARCH" == arm ]] && TARGETS+=(target_markers_thumb)
# ppc64 ELFv1 (BE): rizin doesn't recognise m_zero, whose -O2 body starts
# with a nop, as a function, so neither generator can place its marker.
MARKERS=(m_short m_near m_bit m_zero)
[[ "$ARCH" == powerpc64 ]] && MARKERS=(m_short m_near m_bit)
NM=${#MARKERS[@]}

need=("$B/libcov_st.so")
[[ " ${THREADINGS[*]} " == *" mt "* ]] && need+=("$B/libcov_mt.so")
for t in "${TARGETS[@]}"; do need+=("$B/$t"); done
for f in "${need[@]}"; do
    [[ -e "$f" ]] || { echo "missing $f. Run 'make ARCH=$ARCH', 'make ARCH=$ARCH THREADING=mt' and build the test targets." >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

for tgt in "${TARGETS[@]}"; do
T="$B/$tgt"
"${RUN[@]}" "$T" "$N" > "$WORK/bare.out"

for th in "${THREADINGS[@]}"; do
    "$ROOT/tools/gen_patchlist.py" "$T" "$WORK/$th.lcv" --threading "$th" \
        --include-pat '^dbg\.(main|rec|m_short|m_near|m_bit|m_zero)$' >/dev/null 2>&1
    specs=(); for m in "${MARKERS[@]}"; do specs+=("$m:begin"); done
    "$ROOT/tools/gen_boundary.py" "$T" "$WORK/$th.lcvb" "${specs[@]}" \
        --patchlist "$WORK/$th.lcv" >/dev/null 2>"$WORK/$th.bnd.log" \
        || fail "gen_boundary ($tgt, $th): $(tail -3 "$WORK/$th.bnd.log")"

    for emu in 1 0; do
        tag="$th.emu$emu"
        want=$([[ $emu == 1 && $EMULATES == 1 ]] && echo "$NM" || echo 0)
        for mode in leapfrog oneshot; do
            rearm=$([[ $mode == oneshot ]] && echo touched || echo none)
            shm="$WORK/$tag.$mode.shm"
            env=(LD_PRELOAD="$B/libcov_$th.so" LIBCOV_PATCHLIST="$WORK/$th.lcv"
                 LIBCOV_BOUNDARY_LIST="$WORK/$th.lcvb" LIBCOV_SHM_PATH="$shm"
                 LIBCOV_MODE=$mode LIBCOV_BOUNDARY_REARM=$rearm
                 LIBCOV_BOUNDARY_EMULATE=$emu LIBCOV_LOG="$WORK/$tag.$mode.log")
            if [[ ${#RUN[@]} -gt 0 ]]; then
                qenv=(); for kv in "${env[@]}"; do qenv+=(-E "$kv"); done
                "${RUN[@]}" "${qenv[@]}" "$T" "$N" > "$WORK/$tag.$mode.out"
            else
                env "${env[@]}" "$T" "$N" > "$WORK/$tag.$mode.out"
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
