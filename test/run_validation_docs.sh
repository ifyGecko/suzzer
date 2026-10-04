#!/usr/bin/env bash
# The documented recipes must actually work. Commands are extracted from
# HOWTO.md and README.md at test time -- not copied here -- so editing a
# recipe into something broken (a renamed symbol, a missing argument, a
# changed CLI) fails this suite instead of silently misleading readers.
#
#   1. HOWTO §13 Recipe 1: one-shot target, coverage per input.
#   2. HOWTO §13 Recipe 2: stdin loop under fuzz_driver, init + 3 iter.
#   3. HOWTO §13 Recipe 3: MT target; the worker thread must be covered.
#   4. HOWTO §13 Recipe 6: slice dry-run + write with indirect-call roots.
#   5. README "Selective instrumentation" example block.
#   6. Documented behaviour: in ST boundary mode the live bitmap is empty
#      (LIBCOV_SHM_FLAG_LIVE_EMPTY) and shm_bitmap.py stats prints 0 0 0 --
#      HOWTO §8 tells readers to expect exactly this.
#
# Recipes 4 (aarch64 under qemu) and 5 (ssh to a device) aren't run here.
# Lines that only build (`make ...`) are skipped: `make test` built
# everything already. The recipes hard-code build/x86_64, so the suite
# only runs on an x86_64 host.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"

if [[ "$ARCH" != x86_64 ]]; then
    echo "SKIP: the documented recipes use build/x86_64 (ARCH=$ARCH)"
    exit 0
fi
for f in "$ROOT/HOWTO.md" "$ROOT/README.md" "$B/libcov_st.so" "$B/libcov_mt.so" \
         "$B/target_simple" "$B/target_loop" "$B/target_dispatch" \
         "$B/target_simple_mt" "$B/target_multimod" "$B/fuzz_driver"; do
    [[ -e "$f" ]] || { echo "missing $f. Run 'make test' (or make; make THREADING=mt;" \
        "make -C test all mt multimod ARCH=$ARCH BUILD=$B)." >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# extract <doc> <heading-regex>: print the first ```bash/``` block after
# the heading, with /tmp/ redirected into $WORK and make lines dropped.
extract() {
    python3 - "$1" "$2" "$WORK" <<'EOF'
import re, sys
doc, heading, work = sys.argv[1:]
lines = open(doc).read().splitlines()
start = next((i for i, l in enumerate(lines) if re.match(heading, l)), None)
if start is None:
    sys.exit(f"heading /{heading}/ not found in {doc}")
i = start + 1
while i < len(lines) and not lines[i].startswith("```"):
    if lines[i].startswith("#"):
        sys.exit(f"no code block under /{heading}/ in {doc}")
    i += 1
out, i = [], i + 1
while i < len(lines) and not lines[i].startswith("```"):
    out.append(lines[i]); i += 1
script = "\n".join(out).replace("/tmp/", work + "/")
# Drop build-only commands (whole logical lines, including continuations).
kept, skip = [], False
for l in script.splitlines():
    if not skip and re.match(r"\s*make(\s|$)", l):
        skip = l.rstrip().endswith("\\"); continue
    if skip:
        skip = l.rstrip().endswith("\\"); continue
    kept.append(l)
print("\n".join(kept))
EOF
}

# run_block <name> <doc> <heading-regex>: run the block from $ROOT, keep
# its combined output in $WORK/<name>.out, fail on a non-zero exit.
run_block() {
    local name="$1"
    extract "$2" "$3" > "$WORK/$name.sh"
    [[ -s "$WORK/$name.sh" ]] || fail "$name: extracted an empty block"
    if ! (cd "$ROOT" && bash -eo pipefail "$WORK/$name.sh") \
            > "$WORK/$name.out" 2>&1; then
        fail "$name: documented commands failed:
--- commands ---
$(cat "$WORK/$name.sh")
--- output (tail) ---
$(tail -20 "$WORK/$name.out")"
    fi
}

echo ">> 1. HOWTO Recipe 1 (one-shot, coverage per input)"
run_block r1 "$ROOT/HOWTO.md" '^### Recipe 1\b'
n=$(grep -cE '^input=[0-9]+ -> [1-9][0-9]* ' "$WORK/r1.out" || true)
[[ $n -eq 4 ]] || fail "recipe 1: want 4 non-empty bitmaps, got $n: $(cat "$WORK/r1.out")"
echo "   OK: 4 inputs, 4 non-empty bitmaps"

echo ">> 2. HOWTO Recipe 2 (stdin loop under fuzz_driver)"
run_block r2 "$ROOT/HOWTO.md" '^### Recipe 2\b'
grep -q 'init=1 iter=3 gap=0' "$WORK/r2.out" && grep -q 'lost_gens=0' "$WORK/r2.out" \
    || fail "recipe 2: want init + 3 iter, no loss: $(tail -3 "$WORK/r2.out")"
echo "   OK: init + 3 iter snapshots, nothing lost"

echo ">> 3. HOWTO Recipe 3 (multi-threaded target)"
run_block r3 "$ROOT/HOWTO.md" '^### Recipe 3\b'
nz=$(tail -1 "$WORK/r3.out" | awk '{print $1}')
# With --root main alone the worker threads are uninstrumented and only a
# handful of main-thread buckets light up (~16); with the worker rooted
# it is several times that.
[[ "$nz" =~ ^[0-9]+$ && $nz -ge 40 ]] \
    || fail "recipe 3: only '$nz' buckets -- are the worker threads instrumented?"
echo "   OK: $nz buckets (worker threads covered)"

echo ">> 4. HOWTO Recipe 6 (slice dry-run, then write)"
run_block r6 "$ROOT/HOWTO.md" '^### Recipe 6\b'
grep -q 'dispatch .*indirect: 1 call' "$WORK/r6.out" \
    || fail "recipe 6: dry-run doesn't flag dispatch()'s indirect call"
grep -q 'wrote [1-9][0-9]* records' "$WORK/r6.out" || fail "recipe 6: nothing written"
echo "   OK: indirect call flagged; list written"

echo ">> 5. README slicing example"
run_block readme_slice "$ROOT/README.md" '^### Example$'
[[ $(grep -c 'wrote [1-9][0-9]* records' "$WORK/readme_slice.out") -eq 2 ]] \
    || fail "README example: want 2 lists written: $(cat "$WORK/readme_slice.out")"
echo "   OK: both example lists written"

echo ">> 6. documented behaviour: ST boundary mode leaves the live bitmap empty"
"$ROOT/tools/gen_patchlist.py" "$B/target_loop" "$WORK/l.lcv" --root main >/dev/null 2>&1
"$ROOT/tools/gen_boundary.py" "$B/target_loop" "$WORK/l.lcvb" iter_begin \
    --patchlist "$WORK/l.lcv" >/dev/null 2>&1
printf 'alpha\nbeta\n' | LIBCOV_PATCHLIST="$WORK/l.lcv" LIBCOV_BOUNDARY_LIST="$WORK/l.lcvb" \
    LIBCOV_SHM_PATH="$WORK/bcov" LD_PRELOAD="$B/libcov_st.so" "$B/target_loop" >/dev/null 2>&1
[[ "$("$ROOT/test/shm_bitmap.py" stats "$WORK/bcov")" == "0 0 0" ]] \
    || fail "ST boundary mode: live bitmap not empty -- update HOWTO §8/README"
[[ "$("$ROOT/test/shm_bitmap.py" gen "$WORK/bcov")" -ge 2 ]] \
    || fail "ST boundary mode: no generations published"
python3 - "$WORK/bcov" <<'EOF' || fail "LIBCOV_SHM_FLAG_LIVE_EMPTY not set"
import struct, sys
flags = struct.unpack_from("<I", open(sys.argv[1], "rb").read(), 16)[0]
sys.exit(0 if flags & 4 else 1)
EOF
grep -q 'stats` reports `0 0 0`' "$ROOT/HOWTO.md" \
    || fail "HOWTO no longer documents the 0 0 0 boundary-mode caveat"
echo "   OK: stats = 0 0 0, LIVE_EMPTY set, generations in the ring (as documented)"

echo
echo "ALL DOCUMENTATION VALIDATIONS PASSED ($ARCH)"
