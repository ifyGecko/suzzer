#!/usr/bin/env python3
"""
gen_boundary.py -- produce an LCVB1 iteration-boundary sidecar.

Boundary markers tell libcov "this address means a new iteration has
started." The marker set is per-target and orthogonal to the patch list;
this script lets you generate one from a small list of symbol names.

Each named function is resolved to the last patchable (>= 2 byte)
instruction of its FIRST basic block -- the same address gen_patchlist.py
picks with its terminator strategy -- so the marker coincides with a
patched site. Without that, the trap never fires and the boundary never
publishes. Pass --patchlist to verify this against the actual patch list
(recommended: include/exclude filters, --root slicing, MT alignment and
MIPS entry strategy can all leave the chosen address unpatched).

Output layout matches src/boundary.h:
  header: magic[4]='LCVB', version=1, count, flags
  record: u64 offset, u8 kind (0=BEGIN, 1=END), u8 depth_filter,
          u8 reserved[6]

Usage:
  ./gen_boundary.py <binary> <out.lcvb> SYM[:kind[:depth_filter]] ...

  kind         : "begin" (default) or "end"
  depth_filter : "any" (default) or "zero"

Example:
  ./gen_boundary.py build/x86_64/target_loop /tmp/loop.lcvb \\
      iter_begin:begin:zero
"""
import argparse
import json
import os
import struct
import subprocess
import sys

sys.dont_write_bytecode = True  # no tools/__pycache__ from the import below
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_patchlist import pick_terminator  # noqa: E402


def rizin(binary, cmds):
    out = subprocess.check_output(
        ["rizin", "-q", "-c", "; ".join(cmds), binary],
        stderr=subprocess.DEVNULL,
    )
    return out.decode("utf-8", errors="replace")


def rizin_json(binary, cmds):
    raw = rizin(binary, cmds).strip()
    if not raw:
        return None
    return json.loads(raw)


def get_image_info(binary):
    info = rizin_json(binary, ["ij"])["bin"]
    return int(info["baddr"]), info.get("arch"), int(info.get("bits", 0))


def get_function_addrs(binary):
    """Return ({name: entry}, {name: vaddr}): rizin's analysed functions
    (sym.foo, dbg.foo, fcn.*), and symbol-table names as a fallback. The
    two are kept apart because on ppc64 ELFv1 a bare symbol like `foo`
    is the .opd function descriptor (data), not the code at dbg.foo."""
    fns = {}
    raw = rizin_json(binary, ["aaa", "aflj"]) or []
    for f in raw:
        name = f.get("name", "")
        if name:
            fns[name] = int(f["offset"])
    syms = {}
    for s in rizin_json(binary, ["isj"]) or []:
        name = s.get("name", "")
        vaddr = s.get("vaddr")  # imports lack vaddr
        if name and vaddr:
            syms[name] = int(vaddr)
    return fns, syms


def resolve(name, fns, syms):
    for table in (fns, syms):
        if name in table:
            return table[name]
        for prefix in ("dbg.", "sym.", "sym.imp.", "fcn."):
            if (prefix + name) in table:
                return table[prefix + name]
    raise KeyError(name)


def local_entry(fn_addr, fns):
    """PPC64 ELFv2: rizin splits a function with a TOC setup into an
    8-byte global entry and a separate function at +8 (the local entry,
    which direct calls use). A marker in the global-entry stub never fires
    on a direct call, so use the local entry -- the same function
    gen_patchlist.py adds as `<name>[local]`."""
    starts = set(fns.values())
    return fn_addr + 8 if (fn_addr + 8) in starts else fn_addr


def first_bb_terminator(binary, fn_addr):
    """Return the absolute address of the last instruction of the first
    basic block of the function at fn_addr.

    gen_patchlist.py patches each BB's last instruction. For a boundary
    marker to actually fire (trap), it must point at a patched site -- so
    we pick the same address gen_patchlist would pick for this function's
    first BB. For a one-BB function shaped like the canonical `iter_begin`
    shim that's the function's terminator; for multi-BB functions it's
    the first branch terminator. Either way, "execution reached this
    address" means "the function was entered." """
    blocks = rizin_json(binary, ["aaa", f"afbj @ {fn_addr}"]) or []
    if not blocks:
        return None
    # The function's *entry* basic block is the one starting at fn_addr.
    # Cold-split blocks (e.g. the .cold half of a __builtin_trap branch)
    # can appear at lower addresses than the entry, so we can't just take
    # min(addr); we have to match the block whose addr == fn_addr. Fall
    # back to the smallest addr >= fn_addr if there's no exact match, and
    # only then to the absolute smallest (preserves prior behaviour for
    # one-BB functions whose lone block addr might not equal fn_addr).
    first = next((b for b in blocks if int(b["addr"]) == int(fn_addr)), None)
    if first is None:
        forward = [b for b in blocks if int(b["addr"]) >= int(fn_addr)]
        first = (min(forward, key=lambda b: int(b["addr"])) if forward
                 else min(blocks, key=lambda b: int(b["addr"])))
    n = int(first.get("ninstr", 0))
    if n == 0:
        return None
    insns = rizin_json(binary, ["aaa", f"pdj {n} @ {int(first['addr'])}"]) or []
    if not insns:
        return None
    pick = pick_terminator(insns)
    return int(pick["offset"]) if pick else None


def patchlist_offsets(path):
    """Set of module-0 record offsets in an LCV3 patch list."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"LCV3":
        sys.exit(f"{path}: not an LCV3 patch list")
    count = struct.unpack_from("<I", data, 8)[0]
    out = set()
    for i in range(count):
        off, _ln, midx = struct.unpack_from("<QBB", data, 24 + i * 14)
        if midx == 0:
            out.add(off)
    return out


KIND_MAP = {"begin": 0, "end": 1}
DEPTH_MAP = {"any": 0, "zero": 1}


def parse_spec(spec):
    parts = spec.split(":")
    name = parts[0]
    kind = parts[1] if len(parts) > 1 else "begin"
    depth = parts[2] if len(parts) > 2 else "any"
    if kind not in KIND_MAP:
        raise ValueError(f"bad kind {kind!r} (want begin|end)")
    if depth not in DEPTH_MAP:
        raise ValueError(f"bad depth_filter {depth!r} (want any|zero)")
    return name, KIND_MAP[kind], DEPTH_MAP[depth]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("output")
    ap.add_argument("specs", nargs="+",
                    help="SYM[:kind[:depth_filter]] (e.g. iter_begin:begin:zero)")
    ap.add_argument("--patchlist", metavar="LCV",
                    help="verify every marker lands on a site in this LCV3 "
                         "patch list (module 0); exit non-zero if not")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()
    patched = patchlist_offsets(args.patchlist) if args.patchlist else None

    baddr, arch, bits = get_image_info(args.binary)
    fns, syms = get_function_addrs(args.binary)
    if args.verbose:
        print(f"image base: 0x{baddr:x}", file=sys.stderr)
        print(f"functions: {len(fns)}", file=sys.stderr)

    records = []
    for spec in args.specs:
        name, kind, depth = parse_spec(spec)
        fn_addr = resolve(name, fns, syms)
        if arch == "ppc" and bits == 64:
            fn_addr = local_entry(fn_addr, fns)
        term = first_bb_terminator(args.binary, fn_addr)
        if term is None:
            sys.exit(f"could not find first-BB terminator for {name} @ 0x{fn_addr:x}")
        offset = term - baddr
        if patched is not None and offset not in patched:
            sys.exit(f"error: marker {name} at off=0x{offset:x} is not a patched "
                     f"site in {args.patchlist}; the boundary would never fire")
        records.append((offset, kind, depth))
        if args.verbose:
            print(f"  marker {name} entry=0x{fn_addr:x} term=0x{term:x} "
                  f"off=0x{offset:x} kind={kind} depth={depth}",
                  file=sys.stderr)

    with open(args.output, "wb") as f:
        f.write(b"LCVB")
        f.write(struct.pack("<III", 1, len(records), 0))  # version, count, flags
        for offset, kind, depth in records:
            f.write(struct.pack("<QBB6s", offset, kind, depth, b"\x00" * 6))

    if not any(k == 1 for _, k, _ in records) and any(d for _, _, d in records):
        print("warning: depth_filter=zero has no effect without END markers "
              "(begin-only sidecar)", file=sys.stderr)
    print(f"wrote {len(records)} marker(s) to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
