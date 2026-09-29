#!/usr/bin/env bash
# Re-exec / fork+exec safety of the shared region (native, ST and MT).
#
# A daemon that re-execs itself inherits LD_PRELOAD and LIBCOV_SHM_PATH,
# so libcov initialises again in the new image. That must never zero a
# region someone is still using:
#
#   1. reexec (same pid): the new image attaches -- coverage from before
#      the exec survives, and with boundaries gen_current keeps counting
#      (3 markers before + 3 after = gen 6) with the ring intact.
#   2. forkexec (live parent, child execs): the child leaves the parent's
#      region alone (logs it and runs inert); the parent's coverage
#      survives. With LIBCOV_SHM_PATH=...%p each process gets its own
#      region and the child's has its coverage.
#   3. stale region from an exited process: a new run still starts from a
#      clean region (the previous run's coverage is gone).
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
ARCH="${ARCH:-$(uname -m)}"
BUILD="$ROOT/build/$ARCH"
TARGET="$BUILD/target_reexec"

${CC:-gcc} -O0 -g -no-pie -o "$TARGET" "$ROOT/test/target_reexec.c" \
    || { echo "FAIL: build target_reexec"; exit 1; }

# shm <file> <what>: gen | owner | buckets (nonzero live-bitmap indices)
#                    | ringok (slot of gen_current is stamped with it)
shm() {
    python3 - "$1" "$2" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
ring = struct.unpack_from("<H", d, 6)[0]
ms, stride = struct.unpack_from("<II", d, 8)
gen = struct.unpack_from("<Q", d, 24)[0]
boff, roff = struct.unpack_from("<QQ", d, 40)
owner = struct.unpack_from("<I", d, 60)[0]
w = sys.argv[2]
if w == "gen":
    print(gen)
elif w == "owner":
    print(owner)
elif w == "buckets":
    print(" ".join(str(i) for i, b in enumerate(d[boff:boff + ms]) if b))
elif w == "ringok":
    slot = struct.unpack_from("<Q", d, roff + (gen % ring) * stride)[0]
    print("yes" if gen and slot == gen else f"no(slot_gen={slot} gen={gen})")
PY
}
subset() {  # "<a buckets>" "<b buckets>": is every a bucket in b?
    python3 -c "import sys; a=set(sys.argv[1].split()); b=set(sys.argv[2].split()); sys.exit(0 if a and a <= b else 1)" "$1" "$2"
}
disjoint() {  # "<a>" "<b>" "<c>": (a - b) nonempty and disjoint from c?
    python3 -c "import sys; a,b,c=(set(x.split()) for x in sys.argv[1:]); d=a-b; sys.exit(0 if d and not d & c else 1)" "$1" "$2" "$3"
}

fail=0
bad() { echo "FAIL: $*"; fail=1; }

for th in st mt; do
    LIB="$BUILD/libcov_$th.so"
    [[ -f "$LIB" ]] || { echo "SKIP: $LIB missing (make THREADING=$th)"; continue; }
    LCV="$WORK/$th.lcv"; LCVB="$WORK/$th.lcvb"
    "$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV" --threading $th \
        --include-pat '^dbg\.(work_a|work_b|iter_begin)$' >/dev/null 2>&1 \
        || { bad "$th: gen_patchlist"; continue; }
    "$ROOT/tools/gen_boundary.py" "$TARGET" "$LCVB" iter_begin:begin \
        --patchlist "$LCV" >/dev/null 2>&1 \
        || { bad "$th: gen_boundary"; continue; }
    run() {  # <shm path> <log> <mode> [env...]
        local shmp=$1 log=$2 mode=$3; shift 3
        env LIBCOV_PATCHLIST="$LCV" LIBCOV_SHM_PATH="$shmp" LIBCOV_LOG="$log" \
            "$@" LD_PRELOAD="$LIB" "$TARGET" "$mode"
    }

    rm -f "$WORK/a.shm" "$WORK/b.shm"
    run "$WORK/a.shm" /dev/null a >/dev/null
    run "$WORK/b.shm" /dev/null b >/dev/null
    A=$(shm "$WORK/a.shm" buckets); Bk=$(shm "$WORK/b.shm" buckets)

    # 1a. in-place re-exec keeps the coverage from before the exec.
    rm -f "$WORK/r.shm"; : >"$WORK/r.log"
    run "$WORK/r.shm" "$WORK/r.log" reexec >/dev/null
    R=$(shm "$WORK/r.shm" buckets)
    # (Bk isn't comparable here: the new image reaches work_b after the
    # markers, so its first edge has a different predecessor.)
    if subset "$A" "$R" && [[ $(wc -w <<<"$R") -gt $(wc -w <<<"$A") ]]; then
        echo "   OK: $th/reexec: coverage from both images kept"
    else
        bad "$th/reexec: pre-exec coverage lost (a=[$A] got=[$R])"
    fi
    grep -q 'sink: attached' "$WORK/r.log" \
        || bad "$th/reexec: no 'attached' log line: $(grep sink: "$WORK/r.log")"

    # 1b. same, with boundaries: generations keep counting, ring intact.
    rm -f "$WORK/rb.shm"
    run "$WORK/rb.shm" /dev/null reexec LIBCOV_BOUNDARY_LIST="$LCVB" \
        LIBCOV_MODE=leapfrog >/dev/null
    g=$(shm "$WORK/rb.shm" gen); ok=$(shm "$WORK/rb.shm" ringok)
    if [[ "$g" == 6 && "$ok" == yes ]]; then
        echo "   OK: $th/reexec+boundaries: gen_current=6, ring slot stamped"
    else
        bad "$th/reexec+boundaries: gen_current=$g (want 6), ring=$ok"
    fi

    # 2a. fork+exec child next to a live parent: parent's region untouched.
    rm -f "$WORK/f.shm"; : >"$WORK/f.log"
    out=$(run "$WORK/f.shm" "$WORK/f.log" forkexec)
    F=$(shm "$WORK/f.shm" buckets)
    ppid=$(sed -n '1s/^pid=//p' <<<"$out")
    if subset "$A" "$F" && [[ "$(shm "$WORK/f.shm" owner)" == "$ppid" ]] \
            && grep -q "child=.* rc=0" <<<"$out"; then
        echo "   OK: $th/forkexec: parent's region kept (owner=$ppid)"
    else
        bad "$th/forkexec: parent's region clobbered (owner=$(shm "$WORK/f.shm" owner) want $ppid, a=[$A] got=[$F]) out=[$out]"
    fi
    grep -q 'in use by live pid' "$WORK/f.log" \
        || bad "$th/forkexec: child did not report the live owner"

    # 2b. %p: one region per process.
    out=$(run "$WORK/p.%p.shm" /dev/null forkexec)
    ppid=$(sed -n '1s/^pid=//p' <<<"$out"); cpid=$(sed -n 's/^child=\([0-9]*\).*/\1/p' <<<"$out")
    if [[ -f "$WORK/p.$ppid.shm" && -f "$WORK/p.$cpid.shm" ]] \
            && subset "$A" "$(shm "$WORK/p.$ppid.shm" buckets)" \
            && subset "$Bk" "$(shm "$WORK/p.$cpid.shm" buckets)"; then
        echo "   OK: $th/forkexec+%p: parent and child regions separate"
    else
        bad "$th/forkexec+%p: expected p.$ppid.shm (a) and p.$cpid.shm (b); have: $(ls "$WORK" | grep '^p\.' | tr '\n' ' ')"
    fi

    # 3. a stale region from an exited run is reset, not reused.
    rm -f "$WORK/s.shm"
    run "$WORK/s.shm" /dev/null a >/dev/null
    run "$WORK/s.shm" /dev/null b >/dev/null
    S=$(shm "$WORK/s.shm" buckets)
    if disjoint "$A" "$Bk" "$S"; then
        echo "   OK: $th/stale: previous run's coverage cleared"
    else
        bad "$th/stale: previous run's coverage leaked into a new run"
    fi
done

[[ $fail -eq 0 ]] && echo "ALL RE-EXEC VALIDATIONS PASSED ($ARCH)" || exit 1
