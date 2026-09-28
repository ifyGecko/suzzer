#!/usr/bin/env bash
# MT boundary-mode validation: per-iteration snapshots must not mix
# threads.
#
# target_loop_mt runs worker threads that each hit the iter_begin marker
# once per iteration; worker 'a' only runs path_a_*, worker 'b' only
# path_b_*. We:
#   1. run each worker solo and take the union of its snapshots as that
#      worker's signature; the buckets only 'a' produces (UA) and only 'b'
#      produces (UB) identify which worker a snapshot came from;
#   2. run 'a' and 'b' workers concurrently and require that no per-
#      iteration snapshot contains both UA and UB buckets, and that each
#      publishing tid only ever produces one kind of snapshot;
#   3. require every generation to be readable (no OVERRUN / MISSING).
#
# A small number of stray buckets is tolerated (MISMATCH_TOLERANCE):
# under MT a site disarmed by one thread doesn't trap for the other, which
# perturbs the N-gram history and can land an edge on a bucket by hash
# collision. Snapshot mixing puts a whole iteration of the other worker's
# coverage in the snapshot, far above the tolerance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
LIB="$ROOT/build/$ARCH/libcov_mt.so"
TARGET="$ROOT/build/$ARCH/target_loop_mt"
DUMP="$ROOT/build/$ARCH/ring_dump"
ITERS="${ITERS:-150}"
MISMATCH_TOLERANCE="${MISMATCH_TOLERANCE:-1}"

for f in "$LIB" "$TARGET" "$DUMP"; do
    [[ -e "$f" ]] || { echo "missing $f. Run 'make THREADING=mt' and 'make -C test mt ARCH=$ARCH BUILD=$ROOT/build/$ARCH'." >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
LCV="$WORK/t.lcv"
LCVB="$WORK/t.lcvb"

echo ">> generate MT patch list + boundary sidecar for target_loop_mt"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV" --threading mt \
    --include-pat '^dbg\.(iter_begin|worker|path_a|path_a_leaf|path_b|path_b_leaf)$' \
    >/dev/null 2>"$WORK/gen.log"
"$ROOT/tools/gen_boundary.py" "$TARGET" "$LCVB" iter_begin:begin \
    --patchlist "$LCV" >/dev/null 2>"$WORK/bnd.log"

run_dump() {  # <out> <workers> <iters>
    "$DUMP" "$LIB" "$LCV" "$LCVB" "$TARGET" "$2" "$3" > "$1" 2>"$1.err"
    if grep -q '^OVERRUN\|^MISSING' "$1"; then
        echo "FAIL: ring reader lost generations ($2):" >&2
        grep '^OVERRUN\|^MISSING\|^ring_dump' "$1" >&2
        exit 1
    fi
}

check_combo() {  # <mode> <rearm>
    local mode="$1" rearm="$2"
    export LIBCOV_MODE="$mode" LIBCOV_BOUNDARY_REARM="$rearm"
    run_dump "$WORK/a.out"  a  "$ITERS"
    run_dump "$WORK/b.out"  b  "$ITERS"
    run_dump "$WORK/ab.out" ab "$ITERS"
    python3 - "$WORK/a.out" "$WORK/b.out" "$WORK/ab.out" \
              "$MISMATCH_TOLERANCE" "$mode" "$rearm" "$ITERS" <<'EOF'
import re, sys
a_path, b_path, ab_path, tol, mode, rearm, iters = sys.argv[1:]
tol, iters = int(tol), int(iters)

def load(path):
    gens, init = [], 0
    for line in open(path):
        m = re.match(r"gen=(\d+) tid=(\d+) idx=(.*)$", line)
        if m:
            idx = set(int(x) for x in m.group(3).split(",") if x)
            gens.append((int(m.group(1)), int(m.group(2)), idx))
        m = re.search(r"gen_init=(\d+)", line)
        if m:
            init = int(m.group(1))
    # Drop the init snapshot: it holds pre-boundary (startup) coverage
    # from every thread by design.
    return [g for g in gens if g[0] != init]

def union(gens):
    u = set()
    for _, _, idx in gens:
        u |= idx
    return u

sa, sb = union(load(a_path)), union(load(b_path))
ua, ub = sa - sb, sb - sa
tag = f"MODE={mode} REARM={rearm}"
if len(ua) < 3 or len(ub) < 3:
    sys.exit(f"FAIL {tag}: solo signatures too small (|UA|={len(ua)} |UB|={len(ub)})")

gens = load(ab_path)
# About one publish per worker iteration (each worker's first iter_begin
# only switches it to its own live bitmap). Not exact under MT: while one
# worker's handler holds the marker disarmed, the other can run
# iter_begin without trapping (two iterations merge into one snapshot),
# and a peer's re-arm can catch the marker before its thread has executed
# it (one extra, near-empty snapshot). Require 90%; losing whole threads'
# worth of boundaries is what this guards against.
if len(gens) < 0.9 * 2 * iters:
    sys.exit(f"FAIL {tag}: only {len(gens)} per-iteration gens (want ~{2 * iters})")

mixed, kinds = [], {}
for gen, tid, idx in gens:
    na, nb = len(idx & ua), len(idx & ub)
    if na > tol and nb > tol:
        mixed.append((gen, na, nb))
    kind = "a" if na > nb else "b" if nb > na else None
    if kind:
        kinds.setdefault(tid, set()).add(kind)
if mixed:
    head = ", ".join(f"gen={g}(a={x},b={y})" for g, x, y in mixed[:5])
    sys.exit(f"FAIL {tag}: {len(mixed)}/{len(gens)} snapshots mix both workers: {head}")
multi = {t: k for t, k in kinds.items() if len(k) > 1}
if multi:
    sys.exit(f"FAIL {tag}: tids published both kinds of snapshot: {multi}")
print(f"   OK: {tag}: {len(gens)} per-iteration snapshots, none mixed "
      f"(|UA|={len(ua)} |UB|={len(ub)}, tids={len(kinds)})")
EOF
}

echo ">> concurrent workers: snapshots must stay per-thread"
check_combo leapfrog none
check_combo oneshot  touched
check_combo oneshot  all

echo
echo "ALL MT BOUNDARY VALIDATIONS PASSED ($ARCH)"
