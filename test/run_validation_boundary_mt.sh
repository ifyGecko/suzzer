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
#   3. require every generation to be readable (no OVERRUN / MISSING);
#   4. with 4 workers (two per path), require boundaries to keep firing:
#      no stall, and at least MIN_FRACTION_4 of the expected snapshots.
#      (A marker is one shared trap site, so while one worker is between
#      its marker trap and its next trap, others pass it untrapped and
#      two of their iterations merge. That costs ~10-20% with 4 workers;
#      a stall costs ~100%.)
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
MIN_FRACTION_4="${MIN_FRACTION_4:-0.6}"

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
    run_dump "$WORK/a.out"    a    "$ITERS"
    run_dump "$WORK/b.out"    b    "$ITERS"
    run_dump "$WORK/ab.out"   ab   "$ITERS"
    run_dump "$WORK/aabb.out" aabb "$ITERS"
    python3 - "$WORK/a.out" "$WORK/b.out" "$WORK/ab.out" "$WORK/aabb.out" \
              "$MISMATCH_TOLERANCE" "$mode" "$rearm" "$ITERS" "$MIN_FRACTION_4" <<'EOF'
import re, sys
a_path, b_path, ab_path, aabb_path, tol, mode, rearm, iters, frac4 = sys.argv[1:]
tol, iters, frac4 = int(tol), int(iters), float(frac4)

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

def check(path, workers, floor):
    gens = load(path)
    # About one publish per worker iteration (each worker's first
    # iter_begin only switches it to its own live bitmap), minus merges
    # where a worker passed the marker while a peer held it disarmed.
    want = workers * iters
    if len(gens) < floor * want:
        sys.exit(f"FAIL {tag} x{workers}: only {len(gens)} per-iteration gens "
                 f"(want >= {floor:.0%} of {want})")
    tiny = sum(1 for _, _, idx in gens if len(idx) <= 1)
    if tiny > 0.05 * len(gens):
        sys.exit(f"FAIL {tag} x{workers}: {tiny}/{len(gens)} near-empty snapshots "
                 f"(spurious marker re-traps)")
    mixed, kinds = [], {}
    for gen, tid, idx in gens:
        na, nb = len(idx & ua), len(idx & ub)
        if na > tol and nb > tol:
            mixed.append((gen, na, nb))
        # Same tolerance as above: a snapshot with at most `tol` exclusive
        # buckets (e.g. a sparse, sampled iteration plus one colliding
        # edge) doesn't identify its worker.
        kind = None
        if max(na, nb) > tol:
            kind = "a" if na > nb else "b" if nb > na else None
        if kind:
            kinds.setdefault(tid, set()).add(kind)
    if mixed:
        head = ", ".join(f"gen={g}(a={x},b={y})" for g, x, y in mixed[:5])
        sys.exit(f"FAIL {tag} x{workers}: {len(mixed)}/{len(gens)} snapshots mix "
                 f"workers: {head}")
    multi = {t: k for t, k in kinds.items() if len(k) > 1}
    if multi:
        sys.exit(f"FAIL {tag} x{workers}: tids published both kinds: {multi}")
    print(f"   OK: {tag} x{workers}: {len(gens)}/{want} snapshots, none mixed, "
          f"{tiny} near-empty (|UA|={len(ua)} |UB|={len(ub)}, tids={len(kinds)})")

check(ab_path, 2, 0.9)
check(aabb_path, 4, frac4)
EOF
}

echo ">> concurrent workers: snapshots must stay per-thread"
check_combo leapfrog none
check_combo oneshot  touched
check_combo oneshot  all

echo
echo "ALL MT BOUNDARY VALIDATIONS PASSED ($ARCH)"
