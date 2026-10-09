#!/usr/bin/env bash
# How libcov writes to code pages (native, ST and MT).
#
#   ST default (LIBCOV_ST_PATCH=auto): code pages go R|W|X once at init
#   and arm/disarm are plain stores -- no mprotect on the trap path.
#   LIBCOV_ST_PATCH=mprotect keeps the per-write R|W -> R|X dance, and a
#   kernel that refuses R|W|X (W^X: SELinux execmem, PaX) makes auto fall
#   back to it. MT has its own no-RWX fallback (pwrite /proc/self/mem).
#
# test/wx_deny simulates the W^X kernel with a seccomp filter. For every
# mode: same stdout as a bare run (leapfrog, lots of arm/disarm), the
# expected mode in the log, and the same oneshot bitmap as the default.
# With strace available, also: auto mode's mprotect count doesn't grow
# with the number of traps.
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=$(mktemp -d)
# Kept (and its path printed) when the suite fails: the generator and
# target logs in it are how you debug.
keep_work_on_failure() {
    local rc=$?
    if [[ $rc -eq 0 ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK" >&2; fi
    return $rc
}
trap keep_work_on_failure EXIT
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"
T="$B/target_loop"
[[ -x "$T" ]] || { echo "missing $T. Run 'make'." >&2; exit 1; }
${CC:-gcc} -O2 -o "$WORK/wx_deny" "$ROOT/test/wx_deny.c" \
    || { echo "FAIL: build wx_deny"; exit 1; }

fail=0 ran=0
bad() { echo "FAIL: $*"; fail=1; }
INPUTS=$'42\n99\n-3\nabc\nhello\n7\n0\n1000\n'
want=$(printf '%s' "$INPUTS" | "$T")

for th in st mt; do
    LIB="$B/libcov_$th.so"
    [[ -f "$LIB" ]] || { echo "SKIP: $LIB missing"; continue; }
    ran=$((ran + 1))
    LCV="$WORK/$th.lcv"
    "$ROOT/tools/gen_patchlist.py" "$T" "$LCV" --threading $th >/dev/null 2>&1 \
        || { bad "$th: gen_patchlist"; continue; }
    # run <tag> <mode> [wrapper...] -- leapfrog output + oneshot bitmap
    run() {
        local tag=$1 mode=$2; shift 2
        out=$(printf '%s' "$INPUTS" | env LIBCOV_PATCHLIST="$LCV" \
              LIBCOV_SHM_PATH="$WORK/$tag.lf.shm" LIBCOV_LOG="$WORK/$tag.log" \
              LIBCOV_MODE=leapfrog LIBCOV_ST_PATCH="$mode" LD_PRELOAD="$LIB" "$@" "$T")
        printf '%s' "$INPUTS" | env LIBCOV_PATCHLIST="$LCV" \
            LIBCOV_SHM_PATH="$WORK/$tag.os.shm" LIBCOV_LOG=/dev/null \
            LIBCOV_MODE=oneshot LIBCOV_ST_PATCH="$mode" LD_PRELOAD="$LIB" "$@" "$T" >/dev/null
        python3 "$ROOT/test/shm_bitmap.py" extract "$WORK/$tag.os.shm" "$WORK/$tag.bm"
    }
    check() {  # <tag> <log regex> <description>
        [[ "$out" == "$want" ]] || { bad "$th/$1: output differs"; return; }
        grep -qE "$2" "$WORK/$1.log" \
            || { bad "$th/$1: log lacks /$2/: $(grep -E 'patch' "$WORK/$1.log" | head -3)"; return; }
        cmp -s "$WORK/$th.auto.bm" "$WORK/$1.bm" \
            || { bad "$th/$1: oneshot bitmap differs from the default mode"; return; }
        echo "   OK: $th/$1: $3"
    }

    run "$th.auto" auto
    if [[ $th == st ]]; then
        check "$th.auto" 'patch: code pages R\|W\|X; direct-store' "default: RWX once, direct stores"
        run "$th.mprotect" mprotect
        check "$th.mprotect" 'LIBCOV_ST_PATCH=mprotect; per-write' "LIBCOV_ST_PATCH=mprotect"
        run "$th.wx" auto "$WORK/wx_deny"
        check "$th.wx" 'falling back to per-write mprotect' "W^X kernel: falls back to per-write mprotect"
        if command -v strace >/dev/null; then
            count() {  # mprotect calls for N copies of the inputs, <mode>
                local n=$1 mode=$2 in=""
                for ((i = 0; i < n; i++)); do in+=$INPUTS; done
                printf '%s' "$in" | strace -f -e trace=mprotect -o "$WORK/strace" \
                    env LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$WORK/c.shm" \
                    LIBCOV_LOG=/dev/null LIBCOV_MODE=leapfrog LIBCOV_ST_PATCH="$mode" \
                    LD_PRELOAD="$LIB" "$T" >/dev/null 2>&1
                grep -c 'mprotect(' "$WORK/strace"
            }
            a1=$(count 1 auto); a20=$(count 20 auto); m20=$(count 20 mprotect)
            if [[ $a20 -eq $a1 && $m20 -gt $((a20 * 4)) ]]; then
                echo "   OK: st: mprotect calls: auto $a1 (1x input) = $a20 (20x), mprotect mode $m20"
            else
                bad "st: mprotect calls auto 1x=$a1 20x=$a20, mprotect mode 20x=$m20"
            fi
        fi
    else
        check "$th.auto" 'patch_mt: code pages R\|W\|X' "default: RWX once, atomic stores"
        run "$th.wx" auto "$WORK/wx_deny"
        check "$th.wx" 'patch_mt: WARNING -- cannot make code pages writable' \
            "W^X kernel: falls back (pwrite /proc/self/mem) with a warning"
    fi
done

(( ran )) || bad "no libcov_{st,mt}.so in $B -- nothing ran; build with: make && make THREADING=mt"
[[ $fail -eq 0 ]] && echo "ALL PATCH-MODE VALIDATIONS PASSED ($ARCH)" || exit 1
