#!/usr/bin/env python3
"""
gen_boundary.py -- produce an LCVB1 iteration-boundary sidecar.

Boundary markers tell libcov "this address means a new iteration has
started." The marker set is per-target and orthogonal to the patch list;
this script lets you generate one from a small list of symbol names.

Each named function is resolved to the LAST instruction of its FIRST basic
block (the same address gen_patchlist.py would pick when patching that
function), so the boundary marker is guaranteed to coincide with a
patched site -- without that, the trap never fires and the boundary
never publishes.

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
import struct
import subprocess
import sys


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


def get_image_base(binary):
    info = rizin_json(binary, ["ij"])
    return int(info["bin"]["baddr"])


def get_function_addrs(binary):
    """Return dict of {function_name: absolute_entry_addr} covering both
    symbol-table names and rizin's analysis names (sym.foo, dbg.foo, etc)."""
    fns = {}
    raw = rizin_json(binary, ["aaa", "aflj"]) or []
    for f in raw:
        name = f.get("name", "")
        if name:
            fns[name] = int(f["offset"])
    syms = rizin_json(binary, ["isj"]) or []
    for s in syms:
        name = s.get("name", "")
        vaddr = s.get("vaddr")  # imports lack vaddr
        if name and vaddr:
            fns.setdefault(name, int(vaddr))
    return fns


def resolve(name, fns):
    if name in fns:
        return fns[name]
    for prefix in ("dbg.", "sym.", "sym.imp.", "fcn."):
        if (prefix + name) in fns:
            return fns[prefix + name]
    raise KeyError(name)


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
    return int(insns[-1]["offset"])


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
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    baddr = get_image_base(args.binary)
    fns = get_function_addrs(args.binary)
    if args.verbose:
        print(f"image base: 0x{baddr:x}", file=sys.stderr)
        print(f"functions: {len(fns)}", file=sys.stderr)

    records = []
    for spec in args.specs:
        name, kind, depth = parse_spec(spec)
        fn_addr = resolve(name, fns)
        term = first_bb_terminator(args.binary, fn_addr)
        if term is None:
            sys.exit(f"could not find first-BB terminator for {name} @ 0x{fn_addr:x}")
        offset = term - baddr
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

    print(f"wrote {len(records)} marker(s) to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
