#!/usr/bin/env bash
# Generator (tools/gen_patchlist.py) regressions on target_dispatch:
#
#   1. A block with a call in its middle is probed at the call, so a
#      callee that never returns (exit, abort, longjmp, a crash) can't hide
#      the block. exit_path's `call maybe_exit` must be a patched site, and
#      the n=7 run (which exits inside maybe_exit) must still work under
#      libcov.
#   2. --root main --print-reachable reports the indirect call in
#      dispatch() and leaves the handlers behind it out of the slice.
#   3. op_class / is_indirect_transfer recognise every rizin branch type
#      variant, including the ones the old exact-match list missed.
#   4. gen_boundary.py's resolve() rejects an ambiguous name like
#      gen_patchlist does, instead of falling back to the symbol table;
#      only a not-found name falls back.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1   # we import tools/gen_patchlist.py

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"
TARGET="$B/target_dispatch"
LIB="$B/libcov_st.so"

for f in "$TARGET" "$LIB"; do
    [[ -e "$f" ]] || { echo "missing $f. Run 'make'." >&2; exit 1; }
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
fail() { echo "FAIL: $*" >&2; exit 1; }

echo ">> 1. call-terminated blocks are probed at the call"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$WORK/t.lcv" >/dev/null 2>"$WORK/gen.log" \
    || fail "gen_patchlist: $(tail -5 "$WORK/gen.log")"
python3 - "$TARGET" "$WORK/t.lcv" <<'EOF'
import struct, sys, rzpipe
target, lcv = sys.argv[1:]
data = open(lcv, "rb").read()
count = struct.unpack_from("<I", data, 8)[0]
sites = {struct.unpack_from("<Q", data, 24 + 14 * i)[0] for i in range(count)}

rz = rzpipe.open(target, flags=["-2"])
rz.cmd("aaa")
base = rz.cmdj("ij")["bin"]["baddr"]
ops = rz.cmdj("pdfj @ dbg.exit_path")["ops"]
call = next(o for o in ops if o.get("type", "").endswith("call")
            and "maybe_exit" in o.get("disasm", ""))
off = call["offset"] - base
if off not in sites:
    sys.exit(f"FAIL: call maybe_exit at 0x{call['offset']:x} is not a patched site")
print(f"   OK: 'call maybe_exit' (0x{call['offset']:x}) is a patched site")
EOF
set +e
out=$(LD_PRELOAD="$LIB" LIBCOV_PATCHLIST="$WORK/t.lcv" LIBCOV_SHM_PATH="$WORK/cov" \
      "$TARGET" 7 2>"$WORK/run.log")
rc=$?
set -e
[[ $rc -eq 7 && "$out" == *"E:exit7"* ]] || fail "n=7 under libcov: rc=$rc out=$out"
grep -q "init: ready" "$WORK/run.log" || fail "libcov didn't initialise: $(cat "$WORK/run.log")"
echo "   OK: n=7 exits inside the callee under libcov (rc=7)"

echo ">> 2. indirect calls are reported for --root slices"
"$ROOT/tools/gen_patchlist.py" "$TARGET" /dev/null --root main --print-reachable \
    >/dev/null 2>"$WORK/reach.log" \
    || fail "gen_patchlist --print-reachable: $(tail -5 "$WORK/reach.log")"
grep -q "note: the slice has 1 indirect call" "$WORK/reach.log" \
    || fail "no indirect-call note: $(grep -v WARNING "$WORK/reach.log")"
grep -Eq "dispatch .*indirect: 1 call" "$WORK/reach.log" \
    || fail "dispatch() not flagged in --print-reachable"
if grep -Eq "op_(add|mul|neg)" "$WORK/reach.log"; then
    fail "handlers behind the function-pointer table appear in the slice"
fi
echo "   OK: 1 indirect call reported (in dispatch); handlers not in the slice"

echo ">> 3. rizin branch type classification"
python3 - "$ROOT/tools" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
from gen_patchlist import op_class, is_indirect_transfer
cases = {
    "call": "call", "ucall": "call", "rcall": "call", "icall": "call",
    "ircall": "call", "ccall": "call", "uccall": "call",
    "jmp": "jmp", "cjmp": "jmp", "ujmp": "jmp", "rjmp": "jmp", "ijmp": "jmp",
    "irjmp": "jmp", "mjmp": "jmp", "mcjmp": "jmp", "rcjmp": "jmp", "ucjmp": "jmp",
    "ret": "ret", "cret": "ret",
    "mov": None, "add": None, "nop": None, "trap": None, "": None, None: None,
}
bad = {t: (op_class(t), want) for t, want in cases.items() if op_class(t) != want}
if bad:
    sys.exit(f"FAIL: op_class mismatches (got, want): {bad}")
indirect = {t for t in cases if is_indirect_transfer(t)}
want = {"ucall", "rcall", "icall", "ircall", "uccall", "ujmp", "rjmp", "ijmp",
        "irjmp", "mjmp", "mcjmp", "rcjmp", "ucjmp"}
if indirect != want:
    sys.exit(f"FAIL: indirect set {sorted(indirect)} != {sorted(want)}")
print(f"   OK: {len(cases)} op types classified")
EOF

echo ">> 4. gen_boundary.py name resolution matches gen_patchlist"
python3 - "$ROOT/tools" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
from gen_boundary import resolve
fns = [{"offset": 0x1000, "name": "dbg.net.handle", "size": 16, "maxbound": 0x1010},
       {"offset": 0x2000, "name": "dbg.ipc.handle", "size": 16, "maxbound": 0x2010}]
try:
    got = resolve("handle", fns, {"sym.handle": 0x9999})
    sys.exit(f"FAIL: ambiguous 'handle' resolved to 0x{got:x} via the symbol table")
except ValueError as e:
    if "ambiguous" not in str(e):
        sys.exit(f"FAIL: wrong error for an ambiguous name: {e}")
if resolve("dbg.net.handle", fns, {}) != 0x1000:
    sys.exit("FAIL: exact name did not resolve")
if resolve("other", fns, {"sym.other": 0x3000}) != 0x3000:
    sys.exit("FAIL: not-found name did not fall back to the symbol table")
print("   OK: ambiguous name is an error; not-found falls back to symbols")
EOF

echo
echo "ALL GENERATOR VALIDATIONS PASSED ($ARCH)"
