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
#   4. with 2, 4 and 8 workers, the marker is emulated (x86_64/aarch64:
#      never disarmed), so every iteration must publish a snapshot
#      (MIN_FRACTION_EMU, default 97%, leaves room for reader overruns);
#   5. with emulation off (LIBCOV_BOUNDARY_EMULATE=0, the disarm/re-arm
#      fallback other arches use) and 4 workers: no stall, at least
#      MIN_FRACTION_4 of the snapshots. (While one worker holds the marker
#      disarmed, others pass it untrapped and two iterations merge, ~10-20%
#      with 4 workers; a stall costs ~100%.)
#   6. with LIBCOV_SYNC_FALLBACK=tgkill (the signal broadcast that replaces
#      membarrier(SYNC_CORE) on older kernels) and 4 workers: the same
#      bar as 4.
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
MIN_FRACTION_EMU="${MIN_FRACTION_EMU:-0.97}"

for f in "$LIB" "$TARGET" "$DUMP"; do
    [[ -e "$f" ]] || { echo "missing $f. Run 'make THREADING=mt' and 'make -C test mt ARCH=$ARCH BUILD=$ROOT/build/$ARCH'." >&2; exit 1; }
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
LCV="$WORK/t.lcv"
LCVB="$WORK/t.lcvb"

echo ">> generate MT patch list + boundary sidecar for target_loop_mt"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$LCV" --threading mt \
    --include-pat '^dbg\.(iter_begin|worker|path_a|path_a_leaf|path_b|path_b_leaf)$' \
    >/dev/null 2>"$WORK/gen.log" \
    || { echo "FAIL: gen_patchlist (log: $WORK/gen.log)" >&2; exit 1; }
"$ROOT/tools/gen_boundary.py" "$TARGET" "$LCVB" iter_begin:begin \
    --patchlist "$LCV" >/dev/null 2>"$WORK/bnd.log" \
    || { echo "FAIL: gen_boundary (log: $WORK/bnd.log)" >&2; exit 1; }

run_dump() {  # <out> <workers> <iters>
    # 100us of pause per worker keeps the total publish rate (~10k/s)
    # within what ring_dump drains from the 16-slot ring.
    "$DUMP" "$LIB" "$LCV" "$LCVB" "$TARGET" "$2" "$3" $((100 * ${#2})) \
        > "$1" 2>"$1.err"
    if grep -q '^OVERRUN\|^MISSING' "$1"; then
        echo "FAIL: ring reader lost generations ($2):" >&2
        grep '^OVERRUN\|^MISSING\|^ring_dump' "$1" >&2
        exit 1
    fi
}

check_combo() {  # <mode> <rearm>
    local mode="$1" rearm="$2"
    export LIBCOV_MODE="$mode" LIBCOV_BOUNDARY_REARM="$rearm"
    run_dump "$WORK/a.out"        a        "$ITERS"
    run_dump "$WORK/b.out"        b        "$ITERS"
    run_dump "$WORK/ab.out"       ab       "$ITERS"
    run_dump "$WORK/aabb.out"     aabb     "$ITERS"
    run_dump "$WORK/aaaabbbb.out" aaaabbbb "$ITERS"
    LIBCOV_BOUNDARY_EMULATE=0 run_dump "$WORK/aabb.noemu.out" aabb "$ITERS"
    LIBCOV_SYNC_FALLBACK=tgkill run_dump "$WORK/aabb.tgkill.out" aabb "$ITERS"
    grep -q 'tgkill broadcast fallback active' "$WORK/aabb.tgkill.out.err" \
        || { echo "FAIL: forced sync fallback not active" >&2; exit 1; }
    python3 - "$WORK" "$MISMATCH_TOLERANCE" "$mode" "$rearm" "$ITERS" \
              "$MIN_FRACTION_4" "$MIN_FRACTION_EMU" <<'EOF'
import re, sys
work, tol, mode, rearm, iters, frac4, frac_emu = sys.argv[1:]
tol, iters, frac4, frac_emu = int(tol), int(iters), float(frac4), float(frac_emu)
a_path, b_path = f"{work}/a.out", f"{work}/b.out"

def load(path):
    gens, kinds, init = [], {}, 0
    for line in open(path):
        m = re.match(r"gen=(\d+) tid=(\d+) kind=(\w+) idx=(.*)$", line)
        if m:
            idx = set(int(x) for x in m.group(4).split(",") if x)
            gens.append((int(m.group(1)), int(m.group(2)), idx))
            kinds[int(m.group(1))] = m.group(3)
        m = re.search(r"gen_init=(\d+)", line)
        if m:
            init = int(m.group(1))
    # Slot kinds (begin-only sidecar): the init snapshot is tagged init,
    # every other one iter.
    for g, k in kinds.items():
        if k != ("init" if g == init else "iter"):
            sys.exit(f"FAIL {path}: gen {g} tagged {k} (gen_init={init})")
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

def check(path, workers, floor, label=""):
    gens = load(path)
    tag_w = f"x{workers}{label}"
    # About one publish per worker iteration (each worker's first
    # iter_begin only switches it to its own live bitmap), minus merges
    # where a worker passed the marker while a peer held it disarmed.
    want = workers * iters
    if len(gens) < floor * want:
        sys.exit(f"FAIL {tag} {tag_w}: only {len(gens)} per-iteration gens "
                 f"(want >= {floor:.0%} of {want})")
    tiny = sum(1 for _, _, idx in gens if len(idx) <= 1)
    if tiny > 0.05 * len(gens):
        sys.exit(f"FAIL {tag} {tag_w}: {tiny}/{len(gens)} near-empty snapshots "
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
        sys.exit(f"FAIL {tag} {tag_w}: {len(mixed)}/{len(gens)} snapshots mix "
                 f"workers: {head}")
    multi = {t: k for t, k in kinds.items() if len(k) > 1}
    if multi:
        sys.exit(f"FAIL {tag} {tag_w}: tids published both kinds: {multi}")
    print(f"   OK: {tag} {tag_w}: {len(gens)}/{want} snapshots, none mixed, "
          f"{tiny} near-empty (|UA|={len(ua)} |UB|={len(ub)}, tids={len(kinds)})")

check(f"{work}/ab.out", 2, frac_emu)
check(f"{work}/aabb.out", 4, frac_emu)
check(f"{work}/aaaabbbb.out", 8, frac_emu)
check(f"{work}/aabb.noemu.out", 4, frac4, " no-emulation")
check(f"{work}/aabb.tgkill.out", 4, frac_emu, " tgkill-sync")
EOF
}

echo ">> concurrent workers: snapshots must stay per-thread"
check_combo leapfrog none
check_combo oneshot  touched
check_combo oneshot  all

echo
echo "ALL MT BOUNDARY VALIDATIONS PASSED ($ARCH)"
