#!/bin/bash
# Baremetal MIPS coverage validation (self-contained; no other project).
#
# Builds a tiny MIPS firmware image = libcov's freestanding baremetal core
# (PLAT=baremetal-mips) + an instrumented app, boots it under stock
# qemu-system-mips (malta, 24Kc, big-endian), and reads coverage fingerprints
# back over the QEMU gdbstub. Asserts the trap-trampoline works through a real
# CPU exception vector (Reserved Instruction), that coverage is deterministic
# for a repeated input, and that different inputs produce different coverage.
#
# SKIPs (exit 0) when the cross toolchain / qemu-system-mips / gdb-multiarch
# are absent, like the other optional suites.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BM="$HERE/baremetal"

need() { command -v "$1" >/dev/null 2>&1; }
for t in mips-linux-gnu-gcc mips-linux-gnu-objdump qemu-system-mips gdb-multiarch python3; do
    need "$t" || { echo "SKIP: $t not found (baremetal suite needs the mips cross toolchain + qemu-system-mips + gdb-multiarch)"; exit 0; }
done

RES="$("$BM/build_and_run.sh" 2>/tmp/bm_build.log)"
if ! echo "$RES" | grep -q "INIT="; then
    echo "FAIL: no results from emulated run"; echo "--- build log ---"; tail -30 /tmp/bm_build.log; exit 1
fi
echo "$RES" | grep -E "INIT=|RUN "

fail() { echo "FAIL: $*"; exit 1; }
getf() { echo "$RES" | sed -n "$1p" | grep -oE "$2=[0-9a-fx]+" | cut -d= -f2; }

INIT=$(echo "$RES" | grep -oE "INIT=-?[0-9]+" | cut -d= -f2)
NRUNS=$(echo "$RES" | grep -oE "NRUNS=[0-9]+" | cut -d= -f2)
[ "$INIT" = "0" ]   || fail "libcov_init returned $INIT (expected 0)"
[ "$NRUNS" = "5" ]  || fail "expected 5 runs, got $NRUNS"

# RUN lines (in order): in=3, in=3, in=8, in=15, in=0
mapfile -t RUNS < <(echo "$RES" | grep -E "^RUN ")
edges() { echo "${RUNS[$1]}" | grep -oE "edges=[0-9]+" | cut -d= -f2; }
hash()  { echo "${RUNS[$1]}" | grep -oE "hash=0x[0-9a-f]+" | cut -d= -f2; }

# coverage recorded at all
for i in 0 1 2 3 4; do [ "$(edges $i)" -gt 0 ] || fail "run $i recorded zero edges"; done
# determinism: input 3 measured twice -> identical edges AND hash
[ "$(edges 0)" = "$(edges 1)" ] && [ "$(hash 0)" = "$(hash 1)" ] \
    || fail "nondeterministic: run0 ($(edges 0)/$(hash 0)) != run1 ($(edges 1)/$(hash 1))"
# differentiation: inputs 3 / 8 / 15 / 0 -> distinct coverage fingerprints
[ "$(hash 0)" != "$(hash 2)" ] || fail "input 3 and 8 produced identical coverage"
[ "$(hash 0)" != "$(hash 3)" ] || fail "input 3 and 15 produced identical coverage"
[ "$(hash 0)" != "$(hash 4)" ] || fail "input 3 and 0 produced identical coverage"
# sanity: input 15 (more branches taken) covers at least as much as input 0
[ "$(edges 3)" -ge "$(edges 4)" ] || fail "edge counts inconsistent with control flow"

echo "   OK: init ok, 5 runs; input 3 deterministic ($(edges 0) edges); inputs 3/8/15/0 distinct"
echo "   OK: baremetal Reserved-Instruction trap path records coverage under qemu-system-mips"
rm -rf "$BM/_out"
exit 0
