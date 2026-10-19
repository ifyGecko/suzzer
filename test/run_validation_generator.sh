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
#   5. The LCV3 module-base table (header flags bit 0) is purely additive:
#      a file with it is the --no-module-bases file plus the flag bit and a
#      u64 table at align8(end of the name table) holding rizin's baddr; a
#      reader that never looks at flags (every reader before the table
#      existed) loads it identically -- same libcov log, same bitmap, same
#      gen_boundary --patchlist view -- and a truncated table is ignored.
#   6. Raw images (--raw --base --arch --bits --endian --symbols): a
#      freestanding image (test/target_raw.c) as an ELF and as its
#      objcopy -O binary .text give the same records (address, len, orig)
#      for MIPS BE, MIPS LE and RV32 -- each needs its cross gcc, else
#      skipped; orig[] is the image's own bytes; the base table holds
#      --base; threading defaults to ANY; markers agree.
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

echo ">> 5. module-base table is additive (old and new readers agree)"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$WORK/nb.lcv" --no-module-bases \
    >/dev/null 2>"$WORK/gen_nb.log" || fail "gen_patchlist --no-module-bases"
python3 - "$TARGET" "$WORK/t.lcv" "$WORK/nb.lcv" "$WORK" <<'EOF'
import struct, sys, rzpipe
target, new, old, work = sys.argv[1:]
n, o = open(new, "rb").read(), open(old, "rb").read()
(_m, _v, _c, _th, nflags, mcount, _r, moff, msize) = struct.unpack_from("<4sIIBBBBII", n, 0)
if nflags != 1:
    sys.exit(f"FAIL: new file flags=0x{nflags:x}, want 0x1 (MODULE_BASES)")
if o[13] != 0:
    sys.exit(f"FAIL: --no-module-bases file flags=0x{o[13]:x}, want 0")
end = moff + msize
if len(o) != end:
    sys.exit(f"FAIL: --no-module-bases file has {len(o) - end} trailing bytes")
if n[:13] + b"\0" + n[14:end] != o:
    sys.exit("FAIL: new file is not the old file plus flag bit + table")
tab = (end + 7) & ~7
if len(n) != tab + 8 * mcount or any(n[end:tab]):
    sys.exit(f"FAIL: base table not at align8({end})={tab} or padding not 0")
rz = rzpipe.open(target, flags=["-2"])
baddr = rz.cmdj("ij")["bin"]["baddr"]
got = struct.unpack_from("<Q", n, tab)[0]
if got != baddr:
    sys.exit(f"FAIL: recorded base 0x{got:x} != rizin baddr 0x{baddr:x}")
# What a reader that never consults flags sees: the same bytes with the bit
# clear. Plus a file whose table is cut short.
open(work + "/oldview.lcv", "wb").write(n[:13] + b"\0" + n[14:])
open(work + "/trunc.lcv", "wb").write(n[:-3])
print(f"   OK: flags=0x1, table at 0x{tab:x} = 0x{got:x} (rizin baddr); prefix identical")
EOF
for v in t nb oldview trunc; do
    LD_PRELOAD="$LIB" LIBCOV_PATCHLIST="$WORK/$v.lcv" LIBCOV_SHM_PATH="$WORK/cov_$v" \
        LIBCOV_LOG="$WORK/run_$v.log" "$TARGET" 2 >/dev/null \
        || fail "target under libcov with $v.lcv: $(cat "$WORK/run_$v.log")"
    grep -q "init: ready" "$WORK/run_$v.log" || fail "$v.lcv: libcov didn't initialise"
    grep "config:" "$WORK/run_$v.log" | grep -v "base table" > "$WORK/cfg_$v.txt" || true
    python3 "$ROOT/test/shm_bitmap.py" extract "$WORK/cov_$v" "$WORK/bm_$v"
done
for v in nb oldview trunc; do
    cmp -s "$WORK/cfg_t.txt" "$WORK/cfg_$v.txt" \
        || fail "$v.lcv loads differently: $(diff "$WORK/cfg_t.txt" "$WORK/cfg_$v.txt")"
    cmp -s "$WORK/bm_t" "$WORK/bm_$v" || fail "$v.lcv gives a different bitmap"
done
[[ -s "$WORK/cfg_t.txt" ]] || fail "no config: lines in the libcov log"
if grep -q "link base .* != mapped base" "$WORK/run_t.log"; then
    fail "spurious link-base mismatch for a non-PIE target: $(grep 'link base' "$WORK/run_t.log")"
fi
grep -q "base table runs past end of file; ignored" "$WORK/run_trunc.log" \
    || fail "truncated base table not reported as ignored"
python3 - "$ROOT/tools" "$WORK/t.lcv" "$WORK/nb.lcv" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
from gen_boundary import patchlist_offsets
if patchlist_offsets(sys.argv[2]) != patchlist_offsets(sys.argv[3]):
    sys.exit("FAIL: gen_boundary --patchlist reads the two files differently")
EOF
echo "   OK: with/without/flag-cleared/truncated tables load identically"

echo ">> 6. raw images: same records as the ELF, orig[] in the image's byte order"
# name  toolchain-prefix  extra-cflags  rizin-arch  endian  base
RAW_CASES=(
    "mipsbe mips-linux-gnu -fno-pic|-mno-abicalls|-march=mips32r2 mips big 0x80010000"
    "mipsel mipsel-linux-gnu -fno-pic|-mno-abicalls|-march=mips32r2 mips little 0x80010000"
    "rv32 riscv64-linux-gnu -march=rv32imac|-mabi=ilp32 riscv little 0x20000000"
)
raw_ran=0
for c in "${RAW_CASES[@]}"; do
    read -r name tc cflags rarch endian base <<<"$c"
    if ! command -v "$tc-gcc" >/dev/null || ! command -v "$tc-objcopy" >/dev/null; then
        echo "   SKIP $name: no $tc-gcc / $tc-objcopy"
        continue
    fi
    elf="$WORK/raw_$name.elf"; img="$WORK/raw_$name.bin"
    # shellcheck disable=SC2086
    "$tc-gcc" -O1 -ffreestanding -nostdlib -static ${cflags//|/ } \
        -Wl,--build-id=none -Wl,-Ttext="$base" -e fw_entry \
        -o "$elf" "$ROOT/test/target_raw.c" 2>"$WORK/raw_$name.cc.log" \
        || fail "$name: building target_raw: $(cat "$WORK/raw_$name.cc.log")"
    "$tc-objcopy" -O binary -j .text "$elf" "$img"
    "$tc-nm" "$elf" > "$WORK/raw_$name.nm"
    raw_args=(--raw --base "$base" --arch "$rarch" --bits 32 --endian "$endian"
              --symbols "$WORK/raw_$name.nm")
    "$ROOT/tools/gen_patchlist.py" "$elf" "$WORK/raw_$name.elf.lcv" \
        >/dev/null 2>"$WORK/raw_$name.gen1.log" || fail "$name: gen_patchlist (ELF)"
    "$ROOT/tools/gen_patchlist.py" "$img" "$WORK/raw_$name.img.lcv" "${raw_args[@]}" -v \
        >/dev/null 2>"$WORK/raw_$name.gen2.log" \
        || fail "$name: gen_patchlist --raw: $(grep -v WARNING "$WORK/raw_$name.gen2.log" | tail -3)"
    if [[ $rarch == mips ]]; then
        grep -q "strategy=entry" "$WORK/raw_$name.gen2.log" || fail "$name: raw MIPS not on the entry strategy"
    fi
    "$ROOT/tools/gen_boundary.py" "$elf" "$WORK/raw_$name.elf.lcvb" handle:begin \
        --patchlist "$WORK/raw_$name.elf.lcv" >/dev/null 2>&1 || fail "$name: gen_boundary (ELF)"
    "$ROOT/tools/gen_boundary.py" "$img" "$WORK/raw_$name.img.lcvb" handle:begin \
        "${raw_args[@]}" --patchlist "$WORK/raw_$name.img.lcv" >/dev/null 2>&1 \
        || fail "$name: gen_boundary --raw"
    python3 - "$ROOT/test" "$WORK/raw_$name" "$img" "$base" <<'EOF' || exit 1
import sys
sys.path.insert(0, sys.argv[1])
from formats_reader import read_lcv3, read_lcvb
stem, img, base = sys.argv[2], open(sys.argv[3], "rb").read(), int(sys.argv[4], 0)
e, r = (read_lcv3(open(f"{stem}.{k}.lcv", "rb").read()) for k in ("elf", "img"))
def absolute(p):
    return [(p["module_bases"][x["module_idx"]] + x["offset"], x["len"], x["orig"])
            for x in p["records"]]
if not r["records"]:
    sys.exit("FAIL: no records from the raw image")
if absolute(e) != absolute(r):
    sys.exit(f"FAIL: ELF and raw image give different records:\n {absolute(e)}\n {absolute(r)}")
if r["module_bases"] != [base] or r["threading"] != 0 or not r["flags"] & 1:
    sys.exit(f"FAIL: raw header: bases={r['module_bases']} threading={r['threading']}")
for x in r["records"]:
    if img[x["offset"]:x["offset"] + x["len"]].hex() != x["orig"]:
        sys.exit(f"FAIL: orig of site +{x['offset']:#x} is not the image's bytes")
be, bi = (read_lcvb(open(f"{stem}.{k}.lcvb", "rb").read()) for k in ("elf", "img"))
if be["records"][0]["offset"] + e["module_bases"][0] != bi["records"][0]["offset"] + base:
    sys.exit("FAIL: ELF and raw boundary markers differ")
print(f"   OK: {sys.argv[2].rsplit('_', 1)[1]}: {len(r['records'])} records == ELF's, "
      f"orig from the image, base {base:#x}, threading ANY, marker agrees")
EOF
    raw_ran=$((raw_ran + 1))
done
# The raw options are validated up front.
out=$("$ROOT/tools/gen_patchlist.py" "$TARGET" "$WORK/x.lcv" --raw 2>&1 || true)
grep -q -- "--raw needs --base" <<<"$out" \
    || fail "--raw without --base/--arch/--bits/--endian not refused: $out"
out=$("$ROOT/tools/gen_patchlist.py" "$TARGET" "$WORK/x.lcv" --threading any 2>&1 || true)
grep -q "threading any is for raw images" <<<"$out" \
    || fail "--threading any accepted for an ELF: $out"
echo "   OK: $raw_ran raw-image case(s); option errors refused"

echo
echo "ALL GENERATOR VALIDATIONS PASSED ($ARCH)"
