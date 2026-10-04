#!/usr/bin/env bash
# Paired-mode boundaries (BEGIN and END markers), ST and MT.
#
# Every published ring slot is tagged with what it holds (slot flags,
# boundary.h): INIT (startup), ITER (an END closing BEGIN..END: one
# input), GAP (a later BEGIN closing END..BEGIN: harness code between
# inputs). target_paired runs N inputs, so a reader must see:
#
#   1. gen 1 = init, then iter/gap alternating: exactly N iter and N gap;
#   2. every gap snapshot the same non-empty set (gap_work only), iter
#      snapshots differing by input, and no gap equal to an iter;
#   3. fuzz_driver's summary agrees (init=1 iter=N gap=N).
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"
T="$B/target_paired"
for f in "$B/ring_dump" "$B/fuzz_driver"; do
    [[ -x "$f" ]] || { echo "missing $f. Run 'make'." >&2; exit 1; }
done
${CC:-gcc} -O0 -g -no-pie -o "$T" "$ROOT/test/target_paired.c" \
    || { echo "FAIL: build target_paired"; exit 1; }

INPUTS=$'42\n-3\n0\nabc\n1000\n7\n'
N=6
fail=0
bad() { echo "FAIL: $*"; fail=1; }

for th in st mt; do
    LIB="$B/libcov_$th.so"
    [[ -f "$LIB" ]] || { echo "SKIP: $LIB missing"; continue; }
    LCV="$WORK/$th.lcv"; LCVB="$WORK/$th.lcvb"
    "$ROOT/tools/gen_patchlist.py" "$T" "$LCV" --threading $th \
        --include-pat '^dbg\.(iter_begin|iter_end|process|gap_work)$' >/dev/null 2>&1 \
        || { bad "$th: gen_patchlist"; continue; }
    "$ROOT/tools/gen_boundary.py" "$T" "$LCVB" iter_begin:begin:zero iter_end:end:zero \
        --patchlist "$LCV" >/dev/null 2>&1 || { bad "$th: gen_boundary"; continue; }

    printf '%s' "$INPUTS" | LIBCOV_MODE=leapfrog LIBCOV_BOUNDARY_RING=16 \
        "$B/ring_dump" "$LIB" "$LCV" "$LCVB" "$T" > "$WORK/$th.dump" 2>&1
    if python3 - "$WORK/$th.dump" "$N" <<'PY'
import re, sys
path, n = sys.argv[1], int(sys.argv[2])
gens = []
for line in open(path):
    m = re.match(r"gen=(\d+) tid=\d+ kind=(\w+) idx=(.*)$", line)
    if m:
        gens.append((int(m.group(1)), m.group(2),
                     frozenset(int(x) for x in m.group(3).split(",") if x)))
kinds = [k for _, k, _ in gens]
want = ["init"] + ["iter", "gap"] * n
if kinds != want:
    sys.exit(f"kind sequence {kinds}, want {want}")
gaps = [s for _, k, s in gens if k == "gap"]
iters = [s for _, k, s in gens if k == "iter"]
if not gaps[0] or len(set(gaps)) != 1:
    sys.exit(f"gap snapshots differ or are empty: {[sorted(g) for g in gaps]}")
if len(set(iters)) < 3:
    sys.exit(f"iter snapshots don't vary with the input: {len(set(iters))} distinct")
if gaps[0] in set(iters):
    sys.exit("a gap snapshot equals an iteration's")
print(f"   {len(iters)} iter ({len(set(iters))} distinct), {len(gaps)} gap (identical)")
PY
    then
        echo "   OK: $th/ring_dump: init, then iter/gap alternating; gaps hold only harness code"
    else
        bad "$th/ring_dump: $(tail -1 "$WORK/$th.dump")"
    fi

    printf '%s' "$INPUTS" | LIBCOV_MODE=leapfrog LIBCOV_BOUNDARY_RING=16 \
        "$B/fuzz_driver" "$LIB" "$LCV" "$LCVB" "$T" > "$WORK/$th.drv" 2>&1
    grep -q " init=1 iter=$N gap=$N" "$WORK/$th.drv" \
        && echo "   OK: $th/fuzz_driver: init=1 iter=$N gap=$N" \
        || bad "$th/fuzz_driver: $(grep '^driver:' "$WORK/$th.drv")"
done

[[ $fail -eq 0 ]] && echo "ALL PAIRED-MODE VALIDATIONS PASSED ($ARCH)" || exit 1
