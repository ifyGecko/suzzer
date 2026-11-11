## -*- coding: utf-8 -*-
## Ghidra Jython 2.7 port of tools/gen_boundary.py
#@runtime Jython
##@category suzzer
##@keybinding
##@menupath
##@toolbar
"""
gen_boundary_ghidra.py -- produce an LCVB1 iteration-boundary sidecar from
the program currently open in Ghidra. Jython 2.7; run as a Ghidra script.

This is the Ghidra counterpart of tools/gen_boundary.py and the sibling of
gen_patchlist_ghidra.py. The OUTPUT is the same LCVB1 wire format (see
src/boundary.h); the marker-site selection reuses the exact same
pick_terminator / pick_entry helpers as the patch-list generator (imported
from gen_patchlist_ghidra), so a boundary marker lands on the same address
gen_patchlist_ghidra.py would patch for a function's first basic block --
which is what makes the marker actually fire.

Each named function is resolved to its first-basic-block site under the
chosen strategy (--strategy, default the arch's: terminator everywhere but
MIPS, entry on MIPS). Pass --patchlist to verify every marker coincides
with a real site in an LCV3 patch list.

As with the patch-list port, the data comes from Ghidra's Program API
instead of a rizin process, and the interface drops the positional
<binary> (module 0 is the open program); the first positional is OUTPUT.

Output layout matches src/boundary.h:
  header: magic[4]='LCVB', version=1, count, flags
  record: u64 offset, u8 kind (0=BEGIN, 1=END), u8 depth_filter,
          u8 reserved[6]

Headless usage:
  analyzeHeadless <proj_dir> <proj_name> -process target_loop \\
      -postScript gen_boundary_ghidra.py loop.lcvb iter_begin:begin \\
          --patchlist out.lcv
"""
from __future__ import print_function

import argparse
import os
import struct
import sys

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor

_HERE = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() \
    else os.getcwd()
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from ghidra_resolve import NotFound, add_symbols_arg, load_symbols, \
    resolve_to_offset
# Reuse the patch-list port's Ghidra adapters AND the ported pick logic, so
# markers are co-located with patched sites by construction.
from gen_patchlist_ghidra import (addr_of, uoff, _block_instructions,
                                   _insn_dict, _is_branch_before,
                                   default_strategy, get_all_functions,
                                   get_bin_info, mt_addr_safe, mt_atomic_width,
                                   op_class, pick_entry, pick_terminator)


def get_function_addrs(program, symbols):
    """Return ({name: entry}, {name: vaddr}, all_fns). The analysed
    functions as a name->entry dict, every symbol-table name as a fallback
    dict, and the all_fns list resolve_to_offset() expects. Mirrors the
    rizin tool's aflj + isj gather."""
    all_fns = get_all_functions(program, symbols)
    fns = {}
    for f in all_fns:
        if f["name"]:
            fns[f["name"]] = f["offset"]
    syms = {}
    for sym in program.getSymbolTable().getSymbolIterator(True):
        a = sym.getAddress()
        if a is None or not a.isMemoryAddress():
            continue
        name = sym.getName()
        if name:
            syms.setdefault(name, uoff(a))
    for addr, name in symbols.items():
        syms.setdefault(name, addr)
    return fns, syms, all_fns


def resolve(name, all_fns, syms):
    """Resolve `name` to an entry address. resolve_to_offset first (so this
    and the patch-list generator resolve names identically), then the symbol
    table for names not analysed as functions. Ambiguous = error."""
    try:
        off, _ = resolve_to_offset(name, all_fns)
        return off
    except NotFound:
        pass
    if name in syms:
        return syms[name]
    for prefix in ("dbg.", "sym.", "sym.imp.", "fcn."):
        if (prefix + name) in syms:
            return syms[prefix + name]
    raise ValueError("could not resolve '%s' to a function or symbol" % name)


def local_entry(fn_addr, fns):
    """PPC64 ELFv2 local entry: use entry+8 when it is itself a function
    start (the same site gen_patchlist adds as `<name>[local]`)."""
    starts = set(fns.values())
    return fn_addr + 8 if (fn_addr + 8) in starts else fn_addr


def mt_candidate_filter(arch, bits):
    """The candidate filter gen_patchlist_ghidra --threading mt applies, so a
    marker lands where that list put the site. Only x86 rejects real
    instructions."""
    if arch != "x86":
        return None
    width = mt_atomic_width(arch, bits)
    return lambda insn: mt_addr_safe(arch, int(insn["offset"]), width)


def _entry_block_insns_fallback(program, fn_addr):
    """When no Function exists at fn_addr (e.g. a --symbols address Ghidra
    didn't turn into a function), approximate the entry basic block: the
    straight-line run of instructions from fn_addr up to and including the
    first jump/return."""
    listing = program.getListing()
    out = []
    ins = listing.getInstructionAt(addr_of(program, fn_addr))
    while ins is not None:
        d = _insn_dict(program, ins)
        out.append(d)
        if op_class(d["type"]) in ("jmp", "ret"):
            break
        nxt = ins.getFallThrough()
        if nxt is None:
            break
        ins = listing.getInstructionAt(nxt)
    return out


def first_bb_site(program, bbm, monitor, fn_addr, strategy, is_mips, ok=None):
    """The absolute address gen_patchlist_ghidra would patch for the first
    basic block of the function at fn_addr under `strategy`."""
    func = program.getFunctionManager().getFunctionAt(addr_of(program, fn_addr))
    blocks = []
    if func is not None:
        bit = bbm.getCodeBlocksContaining(func.getBody(), monitor)
        while bit.hasNext():
            blocks.append(bit.next())
    if blocks:
        entry = None
        for b in blocks:
            if uoff(b.getMinAddress()) == fn_addr:
                entry = b
                break
        if entry is None:
            forward = [b for b in blocks if uoff(b.getMinAddress()) >= fn_addr]
            entry = (min(forward, key=lambda b: uoff(b.getMinAddress()))
                     if forward
                     else min(blocks, key=lambda b: uoff(b.getMinAddress())))
        insns = _block_instructions(program, entry)
    else:
        insns = _entry_block_insns_fallback(program, fn_addr)
    if not insns:
        return None
    if strategy == "entry":
        in_slot = is_mips and _is_branch_before(program, int(insns[0]["offset"]))
        pick = pick_entry(insns, in_slot)
    else:
        pick = pick_terminator(insns, ok)
    return int(pick["offset"]) if pick else None


def patchlist_offsets(path):
    """Set of module-0 record offsets in an LCV3 patch list. (Verbatim.)"""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"LCV3":
        sys.exit("%s: not an LCV3 patch list" % path)
    count = struct.unpack_from("<I", data, 8)[0]
    out = set()
    for i in range(count):
        off, _ln, midx = struct.unpack_from("<QBB", data, 24 + i * 14)
        if midx == 0:
            out.add(off)
    return out


def patchlist_threading(path):
    """The LCV3 header's threading hint: 0 ANY, 1 ST, 2 MT. (Verbatim.)"""
    with open(path, "rb") as f:
        return ord(f.read(13)[12:13])


KIND_MAP = {"begin": 0, "end": 1}
DEPTH_MAP = {"any": 0, "zero": 1}


def parse_spec(spec):
    """Parse SYM[:kind[:depth_filter]]. (Verbatim from the rizin tool,
    including the C++ '::' handling.)"""
    if "::" not in spec:
        parts = spec.split(":")
        if len(parts) > 3:
            raise ValueError("too many ':' fields in spec %r "
                             "(want SYM[:kind[:depth_filter]])" % spec)
        name = parts[0]
        kind = parts[1] if len(parts) > 1 else "begin"
        depth = parts[2] if len(parts) > 2 else "any"
        if not name:
            raise ValueError("empty symbol in spec %r" % spec)
        if kind not in KIND_MAP:
            raise ValueError("bad kind %r (want begin|end)" % kind)
        if depth not in DEPTH_MAP:
            raise ValueError("bad depth_filter %r (want any|zero)" % depth)
        return name, KIND_MAP[kind], DEPTH_MAP[depth]

    parts = spec.split(":")
    kind = "begin"
    depth = "any"
    if len(parts) >= 3 and parts[-1] in DEPTH_MAP and parts[-2] in KIND_MAP:
        depth = parts.pop()
        kind = parts.pop()
    elif len(parts) >= 2 and parts[-1] in KIND_MAP:
        kind = parts.pop()
    name = ":".join(parts)
    if not name:
        raise ValueError("empty symbol in spec %r" % spec)
    return name, KIND_MAP[kind], DEPTH_MAP[depth]


def _monitor():
    try:
        return monitor
    except NameError:
        return TaskMonitor.DUMMY


def main():
    program = getCurrentProgram()
    if program is None:
        sys.exit("error: no program open in Ghidra (import one, or run with "
                 "-process/-import under analyzeHeadless)")
    ap = argparse.ArgumentParser(
        prog="gen_boundary_ghidra.py",
        description="LCVB1 boundary sidecar from the program open in Ghidra "
                    "(Jython port of gen_boundary.py).")
    ap.add_argument("output")
    ap.add_argument("specs", nargs="+",
                    help="SYM[:kind[:depth_filter]] (e.g. iter_begin:begin:zero)")
    ap.add_argument("--patchlist", metavar="LCV",
                    help="verify every marker lands on a site in this LCV3 "
                         "patch list (module 0); exit non-zero if not")
    ap.add_argument("--strategy", choices=["auto", "entry", "terminator"],
                    default="auto",
                    help="marker site selection; must match the patch list's "
                         "--strategy (auto = arch default)")
    ap.add_argument("--threading", choices=["st", "mt"], default=None,
                    help="the patch list's --threading, so markers land on the "
                         "same sites (default: the hint in --patchlist, else st)")
    ap.add_argument("--force", action="store_true",
                    help="write a begin-only sidecar that uses depth_filter="
                         "zero anyway (no effect without END markers)")
    ap.add_argument("--verbose", "-v", action="store_true")
    add_symbols_arg(ap)
    args = ap.parse_args([str(a) for a in getScriptArgs()])
    symbols = load_symbols(args.symbols) if args.symbols else {}

    monitor = _monitor()
    bbm = BasicBlockModel(program)

    patched = patchlist_offsets(args.patchlist) if args.patchlist else None
    threading = args.threading or (
        "mt" if args.patchlist and patchlist_threading(args.patchlist) == 2
        else "st")

    info = get_bin_info(program)
    baddr, arch, bits = info["baddr"], info["arch"], info["bits"]
    strategy = (args.strategy if args.strategy != "auto"
                else default_strategy(arch, bits))
    if arch == "mips" and strategy == "terminator":
        sys.exit("error: --strategy terminator is unsafe on MIPS (delay "
                 "slots); use entry")
    ok = mt_candidate_filter(arch, bits) if threading == "mt" else None
    fns, syms, all_fns = get_function_addrs(program, symbols)
    if args.verbose:
        print("image base: 0x%x strategy=%s" % (baddr, strategy),
              file=sys.stderr)
        print("functions: %d" % len(fns), file=sys.stderr)

    records = []
    for spec in args.specs:
        try:
            name, kind, depth = parse_spec(spec)
            fn_addr = resolve(name, all_fns, syms)
        except ValueError as e:
            sys.exit("error: %s" % e)
        if arch == "ppc" and bits == 64:
            fn_addr = local_entry(fn_addr, fns)
        site = first_bb_site(program, bbm, monitor, fn_addr, strategy,
                             arch == "mips", ok)
        if site is None:
            sys.exit("could not find a first-BB %s site for %s @ 0x%x"
                     % (strategy, name, fn_addr))
        offset = site - baddr
        if patched is not None and offset not in patched:
            sys.exit("error: marker %s at off=0x%x is not a patched site in "
                     "%s; the boundary would never fire"
                     % (name, offset, args.patchlist))
        records.append((offset, kind, depth))
        if args.verbose:
            print("  marker %s entry=0x%x site=0x%x off=0x%x kind=%d depth=%d"
                  % (name, fn_addr, site, offset, kind, depth), file=sys.stderr)

    if not any(k == 1 for _, k, _ in records) and any(d for _, _, d in records):
        msg = ("depth_filter=zero has no effect without END markers "
               "(begin-only sidecar)")
        if not args.force:
            sys.exit("error: %s; drop ':zero', add an END marker, or pass "
                     "--force" % msg)
        print("warning: %s" % msg, file=sys.stderr)

    with open(args.output, "wb") as f:
        f.write(b"LCVB")
        f.write(struct.pack("<III", 1, len(records), 0))
        for offset, kind, depth in records:
            f.write(struct.pack("<QBB6s", offset, kind, depth, b"\x00" * 6))

    print("wrote %d marker(s) to %s" % (len(records), args.output),
          file=sys.stderr)


if __name__ == "__main__":
    main()
