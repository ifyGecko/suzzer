#!/usr/bin/env bash
# Boundary-marker emulation. On backends that support it (x86_64,
# aarch64) libcov never disarms a marker: the trap handler performs the
# marker's instruction itself and moves the PC past it. A wrong emulation
# sends the target down the wrong branch, so:
#
#   target_markers calls four marker functions n times each; their
#   branches cover x86 jcc rel8/rel32 and aarch64 b.cond/tbz/cbz, taken
#   and not taken. For ST and MT, emulation on (where supported) and off
#   (LIBCOV_BOUNDARY_EMULATE=0, the disarm/re-arm fallback):
#     1. the printed branch trace is identical to a run without libcov;
#     2. every marker call fired a boundary (gen_current == 4n);
#     3. the log reports all 4 markers emulated (or 0 when disabled / on
#        backends without an emulator).
#
# ARCH=aarch64 runs the aarch64 build under qemu-aarch64-static.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"
N=40

case "$ARCH" in
    "$(uname -m)") RUN=() ;;
    aarch64)       RUN=(qemu-aarch64-static -L /usr/aarch64-linux-gnu) ;;
    *)             echo "ARCH=$ARCH: add a qemu runner here" >&2; exit 1 ;;
esac
case "$ARCH" in
    x86_64|aarch64) EMULATED=4 ;;
    *)              EMULATED=0 ;;
esac

for f in "$B/libcov_st.so" "$B/libcov_mt.so" "$B/target_markers"; do
    [[ -e "$f" ]] || { echo "missing $f. Run 'make ARCH=$ARCH' and 'make ARCH=$ARCH THREADING=mt'." >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

"${RUN[@]}" "$B/target_markers" "$N" > "$WORK/bare.out"

for th in st mt; do
    "$ROOT/tools/gen_patchlist.py" "$B/target_markers" "$WORK/$th.lcv" --threading "$th" \
        --include-pat '^dbg\.(main|rec|m_short|m_near|m_bit|m_zero)$' >/dev/null 2>&1
    "$ROOT/tools/gen_boundary.py" "$B/target_markers" "$WORK/$th.lcvb" \
        m_short:begin m_near:begin m_bit:begin m_zero:begin \
        --patchlist "$WORK/$th.lcv" >/dev/null 2>"$WORK/$th.bnd.log" \
        || fail "gen_boundary ($th): $(tail -3 "$WORK/$th.bnd.log")"

    for emu in 1 0; do
        tag="$th.emu$emu"
        want=$([[ $emu == 1 ]] && echo $EMULATED || echo 0)
        for mode in leapfrog oneshot; do
            rearm=$([[ $mode == oneshot ]] && echo touched || echo none)
            shm="$WORK/$tag.$mode.shm"
            env=(LD_PRELOAD="$B/libcov_$th.so" LIBCOV_PATCHLIST="$WORK/$th.lcv"
                 LIBCOV_BOUNDARY_LIST="$WORK/$th.lcvb" LIBCOV_SHM_PATH="$shm"
                 LIBCOV_MODE=$mode LIBCOV_BOUNDARY_REARM=$rearm
                 LIBCOV_BOUNDARY_EMULATE=$emu LIBCOV_LOG="$WORK/$tag.$mode.log")
            if [[ ${#RUN[@]} -gt 0 ]]; then
                qenv=(); for kv in "${env[@]}"; do qenv+=(-E "$kv"); done
                "${RUN[@]}" "${qenv[@]}" "$B/target_markers" "$N" > "$WORK/$tag.$mode.out"
            else
                env "${env[@]}" "$B/target_markers" "$N" > "$WORK/$tag.$mode.out"
            fi
            cmp -s "$WORK/bare.out" "$WORK/$tag.$mode.out" \
                || fail "$th emulate=$emu $mode: branch trace differs from bare run:
  bare:   $(cut -c1-120 "$WORK/bare.out")
  libcov: $(cut -c1-120 "$WORK/$tag.$mode.out")"
            grep -q "boundary: $want of 4 marker(s) emulated" "$WORK/$tag.$mode.log" \
                || fail "$th emulate=$emu $mode: want $want emulated markers: $(grep 'emulated' "$WORK/$tag.$mode.log")"
            gen=$(python3 -c "import struct,sys; print(struct.unpack_from('<Q', open(sys.argv[1],'rb').read(), 24)[0])" "$shm")
            [[ $gen -eq $((4 * N)) ]] || fail "$th emulate=$emu $mode: gen_current=$gen, want $((4 * N))"
        done
        echo "   OK: $th, emulation $([[ $emu == 1 ]] && echo on || echo off)" \
             "($want/4 emulated): traces match, $((4 * N)) boundaries (leapfrog, oneshot+touched)"
    done
done

echo
echo "ALL MARKER-EMULATION VALIDATIONS PASSED ($ARCH)"
