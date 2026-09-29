#!/usr/bin/env bash
# Generator data-in-text safety (tools/gen_patchlist.py):
#
#   1. Unit tests for the pure filters: _is_data, the Thumb IT-block span,
#      pick_terminator / pick_entry skipping data + IT-conditional sites, and
#      validate_no_overlap (drop-with-warning and --fail-on-overlap).
#   2. Real-binary regression: the sites gen_patchlist actually emits for
#      target_dispatch never overlap, and --include-fcn / --fail-on-overlap
#      run cleanly.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1   # we import tools/gen_patchlist.py

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"
TARGET="$B/target_dispatch"

[[ -e "$TARGET" ]] || { echo "missing $TARGET. Run 'make'." >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

echo ">> 1. unit tests for the data / IT / overlap filters"
python3 - "$ROOT/tools" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
from gen_patchlist import (validate_no_overlap, pick_terminator, pick_entry,
                           _thumb_it_conditional_offsets, _is_data)

def I(off, dis, typ="mov", size=2, b="0000"):
    return {"offset": off, "disasm": dis, "type": typ, "size": size, "bytes": b}

def req(cond, name):
    if not cond:
        sys.exit(f"FAIL: {name}")

# _is_data
req(_is_data({"type": "invalid", "disasm": "x"}), "_is_data invalid")
req(_is_data({"type": "", "disasm": ".word 0x1234"}), "_is_data .word")
req(not _is_data({"type": "jmp", "disasm": "b 0x100"}), "_is_data real insn")

# Thumb IT span: it->1, itte->3 conditional insns; no false positive on isb.
req(_thumb_it_conditional_offsets([I(0, "it eq"), I(2, "moveq r0,r1"),
                                   I(4, "bx lr", "ret")]) == {2}, "IT it->1")
req(_thumb_it_conditional_offsets([I(0, "itte ne"), I(2, "movne r0,r1"),
                                   I(4, "movne r2,r3"), I(6, "moveq r4,r5"),
                                   I(8, "bx lr", "ret")]) == {2, 4, 6}, "IT itte->3")
req(_thumb_it_conditional_offsets([I(0, "isb")]) == set(), "IT no-false isb")

# pick_terminator: skip IT-conditional branches, trailing data, all-data.
p = pick_terminator([I(0, "itt eq"), I(2, "beq 0x50", "cjmp"), I(4, "beq 0x60", "cjmp")])
req(p is not None and p["offset"] == 0, "terminator skips IT-conditional")
p = pick_terminator([I(0, "push {r4,lr}", "upush"), I(2, ".word 0xd", "", 4)])
req(p is not None and p["offset"] == 0, "terminator skips trailing data")
req(pick_terminator([I(0, ".word 0x1", "", 4)]) is None, "terminator all-data None")
p = pick_terminator([I(0, "mov r0,r1"), I(2, "bx lr", "ret")],
                    ok=lambda i: int(i["offset"]) != 2)
req(p is not None and p["offset"] == 0, "terminator honours ok")

# pick_entry: skip leading data.
p = pick_entry([I(0, ".word 0x0", "", 4), I(4, "push {lr}", "upush")], False)
req(p is not None and p["offset"] == 4, "entry skips leading data")
req(pick_entry([I(0, ".word 0x0", "", 4)], False) is None, "entry all-data None")

# validate_no_overlap.
R = lambda off, size: (off, size, 0, b"\x00" * size)
clean = [R(0, 4), R(4, 2), R(8, 4)]
req(validate_no_overlap(clean, "m", False) == clean, "overlap clean")
req(validate_no_overlap([R(0, 4), R(2, 2), R(8, 4)], "m", False) == [R(0, 4), R(8, 4)],
    "overlap drop later")
req(validate_no_overlap([R(8, 4), R(0, 4), R(2, 2)], "m", False) == [R(8, 4), R(0, 4)],
    "overlap keeps discovery order")
try:
    validate_no_overlap([R(0, 4), R(2, 2)], "m", True)
    sys.exit("FAIL: --fail-on-overlap did not raise")
except SystemExit as e:
    req("overlap" in str(e), "overlap fail message")
print("   OK: all filter unit tests passed")
EOF

echo ">> 2. emitted sites for target_dispatch never overlap"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$WORK/t.lcv" >/dev/null 2>&1
python3 - "$WORK/t.lcv" <<'EOF'
import struct, sys
data = open(sys.argv[1], "rb").read()
count = struct.unpack_from("<I", data, 8)[0]
# record = <QBB4s: offset(8), len(1), module_idx(1), orig(4)
recs = []
for i in range(count):
    off, size, midx = struct.unpack_from("<QBB", data, 24 + 14 * i)
    recs.append((midx, off, size))
recs.sort()
prev = None
for midx, off, size in recs:
    if prev and prev[0] == midx and off < prev[1] + prev[2]:
        sys.exit(f"FAIL: overlap in module {midx}: 0x{off:x} vs "
                 f"0x{prev[1]:x}-0x{prev[1] + prev[2]:x}")
    prev = (midx, off, size)
print(f"   OK: {count} emitted sites, no overlaps")
EOF

echo ">> 3. --include-fcn and --fail-on-overlap run cleanly"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$WORK/t2.lcv" --include-fcn \
    --fail-on-overlap >/dev/null 2>&1 \
    || fail "--include-fcn --fail-on-overlap failed on target_dispatch"
echo "   OK: flags accepted, no overlap error on a real binary"

echo
echo "ALL GENERATOR SAFETY VALIDATIONS PASSED ($ARCH)"
