## -*- coding: utf-8 -*-
## Ghidra Jython 2.7 port of tools/gen_patchlist.py
#@runtime Jython
##@category suzzer
##@keybinding
##@menupath
##@toolbar
"""
gen_patchlist_ghidra.py -- produce an LCV3 binary patch list from the
program currently open in Ghidra. Jython 2.7; run as a Ghidra script.

This is the Ghidra counterpart of tools/gen_patchlist.py. The OUTPUT is
byte-for-byte the same LCV3 wire format (see src/patchlist_format.h and
docs/FORMATS.md); the per-arch site-selection logic, the MT single-copy-
atomic filtering, the --root/--cutoff call-graph slicing, the overlap
check and the LCV3 packing are ported unchanged. Only the data source
differs: where the rizin version drives a rizin process through rzpipe
(aaa / aflj / afbj / pdj / afij @@F / ij / isj / iSj), this version reads
the same facts from Ghidra's Program API on the already-analysed program.

How this maps to the rizin commands:
  rizin                         Ghidra
  ----------------------------  --------------------------------------------
  rzpipe.open + aaa             currentProgram (import + auto-analysis)
  ij / bin info                 Language: processor, size, endianness, base
  aflj (functions)              FunctionManager.getFunctions(True)
  afbj @ fn (basic blocks)      BasicBlockModel.getCodeBlocksContaining(body)
  pdj N @ addr (instructions)   Listing.getInstructions(block, True)
  op type (call/jmp/ret/ind.)   Instruction.getFlowType() (isCall/isJump/
                                isTerminal/isComputed)
  afij @@F callrefs (CALL)      Function.getCalledFunctions(monitor)
  isj / iSj                     SymbolTable / Memory blocks

Interface differences from the rizin tool (necessary, documented here):
  - No positional <binary>: module 0 is the program open in Ghidra. The
    first positional is the OUTPUT path.
  - No --raw/--base/--arch/--bits/--endian: a headerless image's processor,
    base and byte order are chosen when you import it into Ghidra. --symbols
    is kept, to name functions Ghidra left as FUN_xxxx.
  - --module NAME:PROJECTPATH opens an additional module from the SAME
    Ghidra project (it must already be imported & analysed there), where
    PROJECTPATH is the program's path inside the project (e.g. "/libfoo.so").
  - rizin's sym./dbg./fcn./sym.imp. name prefixes don't exist in Ghidra;
    the default exclusion of PLT/CRT stubs is done by skipping thunk
    functions plus a CRT-stub name regex, and the "heuristic function"
    skip (rizin fcn.*) targets Ghidra's default-named FUN_xxxx functions.

Headless usage (recommended):
  analyzeHeadless <proj_dir> <proj_name> -import target_exe \\
      -postScript gen_patchlist_ghidra.py out.lcv --threading st

  # add already-imported shared libraries:
  analyzeHeadless <proj_dir> <proj_name> -process target_exe \\
      -postScript gen_patchlist_ghidra.py out.lcv \\
          --module libfoo.so:/libfoo.so

In the Ghidra GUI, run it from the Script Manager on the open program and
pass the arguments through "Edit Script Arguments" (or askFile/askString
prompts are not used -- arguments come from the script-args mechanism).

See tools/gen_patchlist.py for the authoritative behavioural documentation
of --root/--cutoff/--max-depth, the threading modes and the LCV3 layout.
"""
from __future__ import print_function

import argparse
import binascii
import os
import re
import struct
import sys

import jarray

# Ghidra API
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor

# Make this script's own directory importable so the shared resolver loads
# whether run headless or from the GUI Script Manager.
_HERE = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() \
    else os.getcwd()
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from ghidra_resolve import (NotFound, add_symbols_arg, apply_symbol_names,
                            load_symbols, resolve_to_offset)


# Functions excluded from instrumentation by default. The rizin tool uses a
# name regex over sym.imp./CRT symbols; under Ghidra, PLT/import thunks are
# dropped programmatically (Function.isThunk()), and this regex drops the
# CRT/init stubs by their (undecorated) Ghidra names. --exclude-pat is ORed
# with this; --no-default-exclude drops both this regex AND the thunk skip.
DEFAULT_EXCLUDE = (r"^(_init|_fini|_start|__libc_start_main|__libc_csu_init|"
                   r"__libc_csu_fini|__do_global_dtors_aux|frame_dummy|"
                   r"register_tm_clones|deregister_tm_clones|__cxa_finalize|"
                   r"__gmon_start__|call_weak_fn|_dl_relocate_static_pie)$")

# Threading-hint values written into the LCV3 header.
TH_ANY = 0
TH_ST = 1
TH_MT = 2

# Bytes of original instruction stored per record (LIBCOV_PATCH_ORIG_MAX).
LCV3_ORIG_LEN = 4

# LCV3 record layout: u64 offset, u8 len, u8 module_idx, u8 orig[4].
LCV3_RECORD_STRUCT = struct.Struct("<QBB4s")
assert LCV3_RECORD_STRUCT.size == 14

# LCV3 header layout: magic[4], version, count, threading, flags,
# module_count, reserved, modules_offset, modules_size.
LCV3_HEADER_STRUCT = struct.Struct("<4sIIBBBBII")
assert LCV3_HEADER_STRUCT.size == 24

# Header flags (LCV_FLAG_* in src/lcv_formats.h).
LCV_FLAG_MODULE_BASES = 1 << 0

# Ghidra processor name -> the arch string the shared logic expects
# (mt_atomic_width / mt_addr_safe / default_strategy use "x86"/"arm"/
# "arm64"/"mips"/"ppc"/"riscv").
ARCH_MAP = {
    "x86": "x86",
    "ARM": "arm",
    "AARCH64": "arm64",
    "MIPS": "mips",
    "PowerPC": "ppc",
    "RISCV": "riscv",
    "RISCV64": "riscv",
}


# ----------------------------------------------------------------------
# Ghidra address / data helpers.
# ----------------------------------------------------------------------

def _text(x):
    """Coerce a Java String (what the Ghidra API returns) to a Python
    unicode string, so re.search, .encode() and dict comparisons behave."""
    if x is None:
        return u""
    if isinstance(x, unicode):
        return x
    try:
        return unicode(x)
    except Exception:
        return x


def uoff(address):
    """Unsigned offset of a Ghidra Address (getOffset() is a signed Java
    long; high addresses would come back negative)."""
    return address.getOffset() & 0xFFFFFFFFFFFFFFFF


def addr_of(program, off):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(
        off & 0xFFFFFFFFFFFFFFFF)


def read_bytes(program, off, n):
    buf = jarray.zeros(n, "b")
    got = program.getMemory().getBytes(addr_of(program, off), buf)
    return "".join(chr(buf[i] & 0xFF) for i in range(got))


# ----------------------------------------------------------------------
# Program facts (the ij / aflj / isj / iSj equivalents).
# ----------------------------------------------------------------------

def get_bin_info(program):
    lang = program.getLanguage()
    proc = lang.getProcessor().toString()
    arch = ARCH_MAP.get(proc, proc.lower())
    bits = int(lang.getLanguageDescription().getSize())
    endian = "BE" if lang.isBigEndian() else "LE"
    return {"arch": arch, "bits": bits, "endian": endian,
            "baddr": uoff(program.getImageBase())}


def _func_bits(program, func):
    """rizin's per-function `bits` (16 = Thumb) drives the arm MT width and
    the Thumb head-only clamp. On ARM, read the TMode context register at the
    entry; elsewhere it's the address size and only x86/arm care."""
    lang = program.getLanguage()
    if lang.getProcessor().toString() != "ARM":
        return int(lang.getLanguageDescription().getSize())
    ctx = program.getProgramContext()
    tmode = ctx.getRegister("TMode")
    if tmode is None:
        return 32
    val = ctx.getRegisterValue(tmode, func.getEntryPoint())
    try:
        if val is not None and val.getUnsignedValueIgnoreMask().intValue() == 1:
            return 16
    except Exception:
        pass
    return 32


def get_all_functions(program, symbols):
    """Unfiltered function list, shaped like rizin's aflj entries, with
    --symbols names applied. Caller filters via regex."""
    fm = program.getFunctionManager()
    out = []
    for func in fm.getFunctions(True):
        if func.isExternal():
            continue
        entry = uoff(func.getEntryPoint())
        body = func.getBody()
        if body is None or body.isEmpty():
            maxbound = entry
        else:
            maxbound = uoff(body.getMaxAddress()) + 1
        out.append({
            "offset":   entry,
            "name":     _text(func.getName()),
            "bits":     _func_bits(program, func),
            "size":     0,            # maxbound carries the extent for bounds
            "maxbound": maxbound,
            "is_thunk": bool(func.isThunk()),
        })
    out = fix_elfv1_nop_entries(program, out)
    return apply_symbol_names(out, symbols)


def fix_elfv1_nop_entries(program, fns):
    """PPC64 ELFv1 parallel of the rizin fixup. Ghidra's ELF loader normally
    resolves .opd descriptors and names the code functions itself, so this is
    a defensive best-effort: if a FUNC symbol's address lands in .opd and the
    8-byte big-endian descriptor there points at entry+4 of a still-default
    FUN_ function whose first instruction is a nop, adopt the symbol's name.
    A no-op on every non-ELFv1 program."""
    mem = program.getMemory()
    opd = mem.getBlock(".opd")
    if opd is None:
        return fns
    lo, hi = uoff(opd.getStart()), uoff(opd.getEnd()) + 1
    by_off = {f["offset"]: f for f in fns}
    listing = program.getListing()
    for sym in program.getSymbolTable().getAllSymbols(False):
        a = sym.getAddress()
        if a is None:
            continue
        desc = uoff(a)
        if not (lo <= desc < hi):
            continue
        try:
            raw = read_bytes(program, desc, 8)
        except Exception:
            continue
        if len(raw) != 8:
            continue
        entry = 0
        for ch in raw:                      # ELFv1 is big-endian
            entry = (entry << 8) | (ord(ch) & 0xFF)
        f = by_off.get(entry + 4)
        if entry in by_off or f is None or not f["name"].startswith("FUN_"):
            continue
        ins = listing.getInstructionAt(addr_of(program, entry))
        if ins is None or ins.getMnemonicString().lower() != "nop":
            continue
        f["name"] = _text(sym.getName())
    return fns


def filter_functions(all_fns, include_re, exclude_re, drop_thunks):
    out = []
    for f in all_fns:
        name = f.get("name", "")
        if drop_thunks and f.get("is_thunk"):
            continue
        if include_re and not include_re.search(name):
            continue
        if exclude_re and exclude_re.search(name):
            continue
        out.append({
            "offset":   int(f["offset"]),
            "name":     name,
            "bits":     int(f.get("bits", 0)),
            "size":     int(f.get("size") or 0),
            "maxbound": int(f.get("maxbound") or 0),
            "is_thunk": bool(f.get("is_thunk")),
        })
    return out


def report_include_matches(fns, pattern, module_name, verbose):
    """Make --include-pat's effect visible: list what it matched under -v,
    and warn when a bare name matched under two spellings."""
    if verbose:
        print("--include-pat %r matched %d function(s) in '%s':"
              % (pattern, len(fns), module_name), file=sys.stderr)
        for f in fns:
            print("  0x%x %s" % (f["offset"], f["name"]), file=sys.stderr)
    by_base = {}
    for f in fns:
        base = re.sub(r"^(sym|dbg|fcn|loc)\.", "", f["name"])
        by_base.setdefault(base, []).append(f["name"])
    for base, names in sorted(by_base.items()):
        if len(names) > 1:
            print("warning: --include-pat %r matched %r under several names "
                  "(%s); sites at the same address are deduplicated"
                  % (pattern, base, ", ".join(names)), file=sys.stderr)


# ----------------------------------------------------------------------
# Instruction classification + per-block site picking (ported verbatim from
# the rizin tool; they consume plain dicts).
# ----------------------------------------------------------------------

def _insn_dict(program, ins):
    """One instruction as the picker dicts expect: offset, size, raw bytes,
    a normalised flow class ("call"/"jmp"/"ret"/""), an indirect flag and
    the lowercased mnemonic."""
    ft = ins.getFlowType()
    if ft.isCall():
        cls = "call"
    elif ft.isJump():
        cls = "jmp"
    elif ft.isTerminal():
        cls = "ret"
    else:
        cls = ""
    jb = ins.getBytes()
    raw = "".join(chr(jb[i] & 0xFF) for i in range(len(jb)))
    return {
        "offset":   uoff(ins.getAddress()),
        "size":     int(ins.getLength()),
        "bytes":    raw,
        "type":     cls,
        "indirect": bool(ft.isComputed()),
        "disasm":   ins.getMnemonicString().lower(),
    }


def op_class(insn_type):
    """Classify a flow class. The Ghidra adapter already stores one of
    "call"/"jmp"/"ret"/""; the rizin suffix fallback is kept so the helper
    behaves identically if ever fed a rizin-style op type."""
    t = insn_type or ""
    if t in ("call", "jmp", "ret"):
        return t
    for cls in ("call", "jmp", "ret"):
        if t.endswith(cls):
            return cls
    return None


# Mnemonics that denote data decoded as an instruction (literal pools,
# tbb/tbh payloads). In Ghidra we only ever collect real instructions, so
# this is effectively inert, but it is kept for parity with the rizin tool.
_DATA_MNEMONICS = frozenset(
    (".byte", ".word", ".short", ".hword", ".dword", ".qword", ".long",
     ".asciz", ".ascii", ".string", ".data", ".fill"))


def _insn_mnemonic(insn):
    disasm = (insn.get("disasm") or "").strip().lower()
    return disasm.split(None, 1)[0] if disasm else ""


def _is_data(insn):
    """True if this "instruction" is really data. Inert under Ghidra (the
    Listing only hands back decoded instructions), kept for parity."""
    if (insn.get("type") or "") == "invalid":
        return True
    return _insn_mnemonic(insn) in _DATA_MNEMONICS


def _thumb_it_conditional_offsets(insns):
    """Offsets of instructions made conditional by a preceding Thumb IT
    block. A trap on a conditional instruction is architecturally
    unpredictable, so those must not be chosen. Detected from the mnemonic;
    a no-op on every other arch."""
    cond = set()
    n = len(insns)
    for i, insn in enumerate(insns):
        mnem = _insn_mnemonic(insn)
        if mnem.startswith("it") and set(mnem[2:]) <= set(("t", "e")):
            span = len(mnem) - 1
            for j in range(i + 1, min(i + 1 + span, n)):
                cond.add(int(insns[j].get("offset", -1)))
    return cond


def pick_terminator(insns, ok=None):
    """Instruction to patch for a block under the terminator strategy, or
    None. Candidates are >= 2 bytes, code not data, not inside a Thumb IT
    block, and satisfy `ok`. First mid-block call if any, else the last
    eligible instruction. (Verbatim from the rizin tool.)"""
    it_cond = _thumb_it_conditional_offsets(insns)

    def eligible(insn):
        return (int(insn.get("size", 0)) >= 2
                and not _is_data(insn)
                and int(insn.get("offset", -1)) not in it_cond
                and (ok is None or ok(insn)))

    for insn in insns[:-1]:
        if op_class(insn.get("type")) == "call" and eligible(insn):
            return insn
    for insn in reversed(insns):
        if eligible(insn):
            return insn
    return None


def pick_entry(insns, in_delay_slot):
    """Instruction to patch for a block under the entry strategy, or None.
    The first instruction (second if the block starts in a MIPS delay slot);
    leading data words are skipped. (Verbatim from the rizin tool.)"""
    idx = 1 if in_delay_slot else 0
    while idx < len(insns):
        insn = insns[idx]
        if int(insn.get("size", 0)) >= 2 and not _is_data(insn):
            return insn
        idx += 1
    return None


def _is_branch_before(program, block_start_off):
    """MIPS delay-slot test: is the instruction immediately before the block
    a branch/call? (rizin checked `pdj 1 @ addr-4`.)"""
    ins = program.getListing().getInstructionBefore(
        addr_of(program, block_start_off))
    if ins is None:
        return False
    ft = ins.getFlowType()
    return ft.isCall() or ft.isJump()


def _block_instructions(program, block):
    listing = program.getListing()
    out = []
    it = listing.getInstructions(block, True)
    while it.hasNext():
        out.append(_insn_dict(program, it.next()))
    return out


def pick_sites(program, bbm, monitor, fn, strategy, arch, ok=None):
    is_mips = arch == "mips"
    func = program.getFunctionManager().getFunctionAt(
        addr_of(program, fn["offset"]))
    if func is None:
        return []
    sites = []
    bit = bbm.getCodeBlocksContaining(func.getBody(), monitor)
    while bit.hasNext():
        block = bit.next()
        insns = _block_instructions(program, block)
        if not insns:
            continue
        start = int(insns[0]["offset"])
        if strategy == "entry":
            pick = pick_entry(insns, is_mips and _is_branch_before(program, start))
            if pick is None:
                continue
        else:
            pick = pick_terminator(insns, ok)
            if pick is None:
                continue
        sites.append((int(pick["offset"]), int(pick["size"]), pick["bytes"]))
    return sites


def default_strategy(arch, bits):
    if arch == "mips":
        return "entry"
    return "terminator"


def mt_atomic_width(arch, fn_bits):
    """Largest single-copy-atomic store width the ISA guarantees for our
    trap encoding (drives the MT patch-record `len`). (Verbatim.)"""
    if arch == "arm":
        return 2 if fn_bits == 16 else 4
    if arch in ("ppc",):
        return 4
    if arch in ("mips",):
        return 4
    if arch == "x86":
        return 2
    if arch == "riscv":
        return 2
    if arch == "arm64":
        return 4
    return 4


def mt_addr_safe(arch, addr, width):
    """Is a single atomic write of `width` bytes safe at `addr`? x86 keeps
    the 2 bytes inside one 16-byte instruction-fetch block; fixed-width ISAs
    require natural alignment. (Verbatim; keep the 16 in sync with
    LIBCOV_X86_FETCH_BLOCK in patch_mt.c.)"""
    if arch == "x86":
        return (addr & 15) + width <= 16
    return addr % width == 0


# ----------------------------------------------------------------------
# Selective instrumentation: call-graph build + BFS (Ghidra-native edges).
# ----------------------------------------------------------------------

def count_indirect_transfers(program, offsets):
    """offset -> (indirect calls, indirect jumps) for each function in
    `offsets` that has any. (rizin walked pdfj ops.)"""
    fm = program.getFunctionManager()
    listing = program.getListing()
    out = {}
    for off in offsets:
        func = fm.getFunctionAt(addr_of(program, off))
        if func is None:
            continue
        calls = jumps = 0
        it = listing.getInstructions(func.getBody(), True)
        while it.hasNext():
            ft = it.next().getFlowType()
            if ft.isComputed() and (ft.isCall() or ft.isJump()):
                if ft.isCall():
                    calls += 1
                else:
                    jumps += 1
        if calls or jumps:
            out[off] = (calls, jumps)
    return out


def report_indirect_transfers(indirect):
    calls = sum(c for c, _ in indirect.values())
    jumps = sum(j for _, j in indirect.values())
    if not calls and not jumps:
        return
    print("note: the slice has %d indirect call(s) and %d indirect jump(s) "
          "in %d function(s). Their targets are not followed: code reached "
          "only through function pointers, vtables or dispatch tables is NOT "
          "instrumented unless you add it with --root (see --print-reachable)."
          % (calls, jumps, len(indirect)), file=sys.stderr)


def build_call_graph(program, monitor, all_fns):
    """Outgoing-CALL adjacency: offset -> set(offset), restricted to entries
    in all_fns. Uses Ghidra's own call references (Function.getCalledFunctions),
    which follow CALL edges and stop at an import thunk exactly as the rizin
    BFS stopped at a PLT stub."""
    fn_set = set(int(f["offset"]) for f in all_fns)
    fm = program.getFunctionManager()
    adj = {}
    for off in fn_set:
        func = fm.getFunctionAt(addr_of(program, off))
        callees = set()
        if func is not None:
            for callee in func.getCalledFunctions(monitor):
                d = uoff(callee.getEntryPoint())
                if d in fn_set:
                    callees.add(d)
        adj[off] = callees
    return adj


def bfs_reachable(roots, adj, cutoffs, max_depth=None):
    """BFS from `roots` over `adj`, treating each offset in `cutoffs` as a
    hard boundary. (Verbatim from the rizin tool.)"""
    out = set()
    seen = set()
    queue = []
    for r in roots:
        if r in cutoffs:
            continue
        seen.add(r)
        queue.append((r, 0))
    while queue:
        fn, depth = queue.pop(0)
        if fn in cutoffs:
            continue
        out.add(fn)
        if max_depth is not None and depth >= max_depth:
            continue
        for callee in adj.get(fn, ()):
            if callee in seen or callee in cutoffs:
                continue
            seen.add(callee)
            queue.append((callee, depth + 1))
    return out


def validate_no_overlap(records, module_name, fail):
    """Reject records whose [offset, offset+len) byte ranges overlap.
    (Verbatim from the rizin tool.)"""
    ordered = sorted(records, key=lambda r: (r[0], r[1]))
    dropped = set()
    prev = None
    for rec in ordered:
        off, size = rec[0], rec[1]
        if prev is not None:
            poff, psize = prev[0], prev[1]
            if off < poff + psize:
                msg = ("site 0x%x (len %d) overlaps 0x%x-0x%x"
                       % (off, size, poff, poff + psize))
                if fail:
                    sys.exit("error: %s: %s" % (module_name, msg))
                print("warning: %s: %s; dropping 0x%x"
                      % (module_name, msg, off), file=sys.stderr)
                dropped.add(id(rec))
                continue
        prev = rec
    if not dropped:
        return records
    return [r for r in records if id(r) not in dropped]


def parse_slice_specs(tokens, module_specs, flag):
    """Parse --root / --cutoff tokens into specs. (Verbatim; MOD!TOKEN pins
    a module, an unqualified address means module 0.)"""
    specs = []
    for tok in tokens:
        mod = None
        body = tok
        if "!" in tok:
            mname, body = tok.split("!", 1)
            found = False
            for i, (name, _prog) in enumerate(module_specs):
                if mname == name:
                    mod = i
                    found = True
                    break
            if not found:
                names = ", ".join(n for n, _ in module_specs)
                sys.exit("error: %s '%s': no module '%s' (modules: %s)"
                         % (flag, tok, mname, names))
            if not body:
                sys.exit("error: %s '%s': empty name after '!'" % (flag, tok))
        b = body.strip()
        is_addr = b.startswith(("0x", "0X")) or b.isdigit()
        specs.append({"tok": body, "mod": mod, "addr": is_addr, "orig": tok})
    return specs


def resolve_slice_specs(specs, module_idx, all_fns, found, stubs, flag, verbose):
    """Resolve the specs applying to `module_idx` to entry offsets.
    (Ported; the sym.imp. import-stub special case becomes a thunk check.)"""
    out = set()
    for i, sp in enumerate(specs):
        if sp["mod"] is not None and sp["mod"] != module_idx:
            continue
        if sp["mod"] is None and sp["addr"] and module_idx != 0:
            continue
        try:
            off, fn = resolve_to_offset(sp["tok"], all_fns)
        except NotFound as e:
            if sp["mod"] is not None or sp["addr"]:
                sys.exit("error: %s '%s': %s" % (flag, sp["orig"], e))
            continue
        except ValueError as e:          # ambiguous within this module
            sys.exit("error: %s '%s': %s" % (flag, sp["orig"], e))
        if sp["mod"] is None and fn.get("is_thunk"):
            stubs.setdefault(i, (module_idx, fn["name"]))
            continue
        out.add(off)
        found.setdefault(i, []).append(module_idx)
        if verbose:
            print("%s: module[%d] '%s' -> 0x%x (%s)"
                  % (flag[2:], module_idx, sp["orig"], off, fn["name"]),
                  file=sys.stderr)
    return out


# ----------------------------------------------------------------------
# Per-module record collection + LCV3 output.
# ----------------------------------------------------------------------

def collect_module_records(args, program, monitor, module_idx, module_name,
                           slicing=None, symbols=None):
    """Walk one module's functions and return (records, mt_skipped). Each
    record is (offset, len, module_idx, orig_bytes). (Logic ported; data
    from Ghidra.)"""
    inc = re.compile(args.include_pat) if args.include_pat else None
    exc_pats = []
    if not args.no_default_exclude:
        exc_pats.append(DEFAULT_EXCLUDE)
    if args.exclude_pat:
        exc_pats.append(args.exclude_pat)
    exc = re.compile("|".join("(?:%s)" % p for p in exc_pats)) if exc_pats \
        else None
    drop_thunks = not args.no_default_exclude

    bbm = BasicBlockModel(program)
    info = get_bin_info(program)
    baddr = info["baddr"]
    arch = info["arch"]
    bits = info["bits"]
    strategy = args.strategy if args.strategy != "auto" \
        else default_strategy(arch, bits)
    if arch == "mips" and strategy == "terminator":
        sys.exit("error: --strategy terminator is unsafe on MIPS (delay "
                 "slots); use entry")

    if args.verbose:
        print("module[%d] '%s': arch=%s bits=%d endian=%s baddr=0x%x "
              "strategy=%s" % (module_idx, module_name, arch, bits,
                               info["endian"], baddr, strategy), file=sys.stderr)

    all_fns_raw = get_all_functions(program, symbols)
    fns = filter_functions(all_fns_raw, inc, exc, drop_thunks)
    if inc:
        report_include_matches(fns, args.include_pat, module_name, args.verbose)

    if args.root:
        all_fns = filter_functions(all_fns_raw, None, None, False)
        roots = resolve_slice_specs(slicing["roots"], module_idx, all_fns,
                                    slicing["found_roots"],
                                    slicing["stub_roots"], "--root",
                                    args.verbose)
        cutoffs = resolve_slice_specs(slicing["cutoffs"], module_idx, all_fns,
                                      slicing["found_cutoffs"],
                                      slicing["stub_cutoffs"], "--cutoff",
                                      args.verbose)
        if not roots:
            print("warning: module[%d] '%s': no --root resolves here, so "
                  "nothing in it is instrumented (add --root '%s!FUNC')"
                  % (module_idx, module_name, module_name), file=sys.stderr)
            if args.print_reachable:
                print("module[%d] '%s': no roots"
                      % (module_idx, module_name), file=sys.stderr)
            return [], 0

        bad_roots = roots & cutoffs
        if bad_roots:
            bad_hex = ", ".join("0x%x" % x for x in sorted(bad_roots))
            print("warning: root(s) %s are also cutoffs; slice will exclude "
                  "them and BFS will not expand from them" % bad_hex,
                  file=sys.stderr)

        print("building call graph over %d functions..." % len(all_fns),
              file=sys.stderr)
        adj = build_call_graph(program, monitor, all_fns)
        reachable_offsets = bfs_reachable(roots, adj, cutoffs, args.max_depth)
        depth_note = (", max-depth=%d" % args.max_depth
                      if args.max_depth is not None else "")
        print("module[%d] '%s': reachable: %d function(s) from %d root(s), "
              "%d cutoff(s)%s" % (module_idx, module_name,
                                  len(reachable_offsets), len(roots),
                                  len(cutoffs), depth_note), file=sys.stderr)

        indirect = count_indirect_transfers(program, reachable_offsets)
        report_indirect_transfers(indirect)

        if args.print_reachable:
            by_off = {int(f["offset"]): f for f in all_fns}
            for off in sorted(reachable_offsets):
                f = by_off.get(off, {"name": "?", "bits": 0})
                calls, jumps = indirect.get(off, (0, 0))
                note = (" indirect: %d call(s), %d jump(s)" % (calls, jumps)
                        if calls or jumps else "")
                print("  0x%x %s bits=%d%s"
                      % (off, f["name"], f.get("bits", 0), note),
                      file=sys.stderr)
            return [], 0

        before = len(fns)
        fns = [f for f in fns if int(f["offset"]) in reachable_offsets]
        if args.verbose:
            print("regex AND reachable: %d -> %d functions"
                  % (before, len(fns)), file=sys.stderr)

    # PowerPC64 dual entry: also pull in the local entry at +8.
    if arch == "ppc" and bits == 64:
        by_offset = {int(f["offset"]): f for f in all_fns_raw}
        extra = []
        seen_offsets = set(f["offset"] for f in fns)
        for f in fns:
            local = f["offset"] + 8
            if local in by_offset and local not in seen_offsets:
                lf = by_offset[local]
                extra.append({
                    "offset": local,
                    "name":   f["name"] + "[local]",
                    "bits":   int(lf.get("bits", 64)),
                })
                seen_offsets.add(local)
        fns.extend(extra)

    if args.verbose:
        print("functions to instrument: %d" % len(fns), file=sys.stderr)
        for fn in fns:
            print("  0x%x %s bits=%d" % (fn["offset"], fn["name"], fn["bits"]),
                  file=sys.stderr)

    seen = set()
    records = []
    mt_skipped_alignment = 0
    fcn_skipped = 0
    for fn in fns:
        # Ghidra default-named functions (FUN_xxxx) are the analogue of
        # rizin's heuristic fcn.* -- least reliable block/code-data info.
        if not args.include_fcn and fn["name"].startswith("FUN_"):
            fcn_skipped += 1
            if args.verbose:
                print("  skip fn %s (default-named FUN_*; use --include-fcn)"
                      % fn["name"], file=sys.stderr)
            continue
        ok = None
        if args.threading == "mt":
            width = mt_atomic_width(arch, fn["bits"])
            ok = (lambda insn, w=width:
                  mt_addr_safe(arch, int(insn["offset"]), w))
        sites = pick_sites(program, bbm, monitor, fn, strategy, arch, ok)
        for addr, size, orig in sites:
            if addr in seen:
                continue
            if len(orig) != size:
                continue

            if size < 2:
                if args.verbose:
                    print("  skip 0x%x len=%d (too short for illegal encoding)"
                          % (addr, size), file=sys.stderr)
                continue

            # Thumb override (ST and MT both): first 2 bytes only.
            if arch == "arm" and fn["bits"] == 16:
                size = 2
                orig = orig[:2]

            # x86 head-only UD2: always 2 bytes.
            if arch == "x86":
                size = 2
                orig = orig[:2]

            if args.threading == "mt":
                width = mt_atomic_width(arch, fn["bits"])
                if not mt_addr_safe(arch, addr, width):
                    mt_skipped_alignment += 1
                    if args.verbose:
                        print("  skip 0x%x (mt: not safe for %d-byte atomic "
                              "write)" % (addr, width), file=sys.stderr)
                    continue
                size = width
                orig = orig[:width]

            if size < 2 or size > LCV3_ORIG_LEN:
                if args.verbose:
                    print("  skip 0x%x len=%d (out of range)" % (addr, size),
                          file=sys.stderr)
                continue

            offset = addr - baddr
            records.append((offset, size, module_idx, orig))
            seen.add(addr)
            if args.verbose:
                print("  patch 0x%x off=0x%x len=%d midx=%d bytes=%s (%s)"
                      % (addr, offset, size, module_idx,
                         binascii.hexlify(orig), fn["name"]), file=sys.stderr)

    if fcn_skipped and args.verbose:
        print("  skipped %d default-named FUN_* function(s) (use "
              "--include-fcn to instrument them)" % fcn_skipped,
              file=sys.stderr)

    records = validate_no_overlap(records, module_name, args.fail_on_overlap)
    return records, mt_skipped_alignment


def write_lcv3(output_path, module_names, records, threading_hint,
               module_bases=None):
    """Pack module records + name table into the LCV3 wire format.
    (Verbatim from the rizin tool.)"""
    name_blob = b"".join(n.encode("utf-8") + b"\x00" for n in module_names)
    header_size = LCV3_HEADER_STRUCT.size
    records_size = LCV3_RECORD_STRUCT.size * len(records)
    modules_offset = header_size + records_size
    modules_size = len(name_blob)
    flags = 0
    bases_blob = b""
    if module_bases is not None:
        assert len(module_bases) == len(module_names)
        flags |= LCV_FLAG_MODULE_BASES
        end = modules_offset + modules_size
        pad = (-end) % 8
        bases_blob = b"\x00" * pad + b"".join(struct.pack("<Q", b)
                                              for b in module_bases)

    with open(output_path, "wb") as f:
        f.write(LCV3_HEADER_STRUCT.pack(
            b"LCV3", 3, len(records),
            threading_hint, flags, len(module_names), 0,
            modules_offset, modules_size))
        for offset, size, module_idx, orig in records:
            padded = orig + b"\x00" * (LCV3_ORIG_LEN - len(orig))
            f.write(LCV3_RECORD_STRUCT.pack(offset, size, module_idx, padded))
        f.write(name_blob)
        f.write(bases_blob)


# ----------------------------------------------------------------------
# Opening additional modules from the current Ghidra project.
# ----------------------------------------------------------------------

def open_project_program(proj_path):
    """Open an additional module by its path inside the current Ghidra
    project (it must already be imported and analysed). Returns (program,
    release) where release() frees it. sys.exit with guidance on failure."""
    try:
        project = getState().getProject()
    except Exception:
        project = None
    if project is None:
        sys.exit("error: --module needs a Ghidra project (run via "
                 "analyzeHeadless so additional modules can be opened)")
    data = project.getProjectData()
    df = data.getFile(proj_path)
    if df is None and not proj_path.startswith("/"):
        df = data.getFile("/" + proj_path)
    if df is None:
        sys.exit("error: --module: no program '%s' in the project; import & "
                 "analyse it first, and pass its project path (e.g. "
                 "'/libfoo.so')" % proj_path)
    consumer = java_object()
    try:
        prog = df.getDomainObject(consumer, False, False, monitor_or_dummy())
    except Exception as e:
        sys.exit("error: --module: could not open '%s': %s" % (proj_path, e))

    def release():
        try:
            prog.release(consumer)
        except Exception:
            pass
    return prog, release


def java_object():
    import java.lang
    return java.lang.Object()


def monitor_or_dummy():
    try:
        return monitor
    except NameError:
        return TaskMonitor.DUMMY


def module_runtime_name(program):
    """The basename the runtime looks up in /proc/self/maps."""
    try:
        path = program.getExecutablePath()
    except Exception:
        path = None
    if path:
        base = os.path.basename(path)
        if base:
            return base
    return program.getName()


def run(args, primary_program, monitor):
    threading_hint = {"mt": TH_MT, "st": TH_ST, "any": TH_ANY}[args.threading]

    # Module 0 is the program open in Ghidra.
    module_specs = [(module_runtime_name(primary_program), primary_program)]
    releases = []
    for spec in args.module:
        if ":" not in spec:
            sys.exit("error: --module requires NAME:PROJECTPATH form, got '%s'"
                     % spec)
        name, path = spec.split(":", 1)
        if not name or not path:
            sys.exit("error: --module '%s' has empty NAME or PATH" % spec)
        prog, release = open_project_program(path)
        releases.append(release)
        module_specs.append((name, prog))

    if len(module_specs) > 255:
        sys.exit("error: too many modules (%d); LCV3 caps at 255"
                 % len(module_specs))

    slicing = {
        "roots":   parse_slice_specs(args.root, module_specs, "--root"),
        "cutoffs": parse_slice_specs(args.cutoff, module_specs, "--cutoff"),
        "found_roots": {}, "found_cutoffs": {},
        "stub_roots": {}, "stub_cutoffs": {},
    }

    all_records = []
    module_bases = []
    total_skipped = 0
    try:
        for module_idx, (name, prog) in enumerate(module_specs):
            if args.verbose:
                print("collecting module[%d] '%s'" % (module_idx, name),
                      file=sys.stderr)
            symbols = args.symbols_map if module_idx == 0 else None
            module_bases.append(get_bin_info(prog)["baddr"])
            records, skipped = collect_module_records(
                args, prog, monitor, module_idx, name, slicing, symbols)
            all_records.extend(records)
            total_skipped += skipped
    finally:
        for release in releases:
            release()

    for key, flag in (("roots", "--root"), ("cutoffs", "--cutoff")):
        found = slicing["found_" + key]
        for i, sp in enumerate(slicing[key]):
            mods = found.get(i, [])
            if not mods:
                stub = slicing["stub_" + key].get(i)
                why = (" (module[%d] has only an import thunk %s; add the "
                       "module that defines it with --module)"
                       % (stub[0], stub[1]) if stub else "")
                sys.exit("error: %s '%s': could not resolve it in any module%s"
                         % (flag, sp["orig"], why))
            if len(mods) > 1:
                where = ", ".join("module[%d] '%s'" % (m, module_specs[m][0])
                                  for m in mods)
                print("note: %s '%s' resolved in %s (qualify it as "
                      "MODULE!NAME to pick one)" % (flag, sp["orig"], where),
                      file=sys.stderr)

    if args.print_reachable:
        print("(--print-reachable: exiting before writing patchlist)",
              file=sys.stderr)
        return

    if not all_records and not args.allow_empty:
        hint = ""
        if args.include_pat:
            hint = (" Check --include-pat against Ghidra's function names "
                    "(run with -v to see what matched).")
        sys.exit("error: no patch sites selected; not writing %s.%s Pass "
                 "--allow-empty to write an empty patch list anyway."
                 % (args.output, hint))

    write_lcv3(args.output, [n for n, _ in module_specs], all_records,
               threading_hint,
               None if args.no_module_bases else module_bases)

    skipped_note = (", skipped %d mt-unsafe sites" % total_skipped
                    if total_skipped else "")
    print("wrote %d records across %d module(s) to %s (threading=%s%s)"
          % (len(all_records), len(module_specs), args.output,
             args.threading, skipped_note), file=sys.stderr)


def build_arg_parser():
    ap = argparse.ArgumentParser(
        prog="gen_patchlist_ghidra.py",
        description="LCV3 patch list from the program open in Ghidra "
                    "(Jython port of gen_patchlist.py).")
    ap.add_argument("output")
    ap.add_argument("--module", action="append", default=[],
                    metavar="NAME:PROJECTPATH",
                    help="add an auxiliary module already imported into this "
                         "Ghidra project. NAME is the basename the runtime "
                         "looks up in /proc/self/maps; PROJECTPATH is the "
                         "program's path inside the project (e.g. '/libfoo.so')."
                         " Repeatable; each gets the next module_idx from 1.")
    ap.add_argument("--include-pat", default=None,
                    help="only include functions whose name matches this regex")
    ap.add_argument("--exclude-pat", default=None,
                    help="also exclude functions whose name matches this "
                         "regex; added to the built-in exclusions")
    ap.add_argument("--no-default-exclude", action="store_true",
                    help="do not apply the built-in exclusions (import "
                         "thunks + CRT/init stubs)")
    ap.add_argument("--include-fcn", action="store_true",
                    help="instrument Ghidra default-named FUN_* functions too "
                         "(skipped by default)")
    ap.add_argument("--fail-on-overlap", action="store_true",
                    help="treat overlapping patch sites as a hard error")
    ap.add_argument("--strategy", choices=["auto", "entry", "terminator"],
                    default="auto",
                    help="per-block patch site selection (auto = arch default)")
    ap.add_argument("--threading", choices=["st", "mt", "any"], default="st",
                    help="target libcov threading variant: st (default), mt "
                         "(keeps only atomically patchable sites), or any")
    ap.add_argument("--root", action="append", default=[],
                    metavar="SYM_OR_ADDR",
                    help="instrument only the call-graph slice reachable from "
                         "this function/address. Repeatable. MODULE!NAME pins "
                         "a module.")
    ap.add_argument("--cutoff", action="append", default=[],
                    metavar="SYM_OR_ADDR",
                    help="stop call-graph traversal at this function (itself "
                         "excluded). Repeatable.")
    ap.add_argument("--max-depth", type=int, default=None, metavar="N",
                    help="bound the BFS to N edges below each root")
    ap.add_argument("--print-reachable", action="store_true",
                    help="resolve the slice, print it, and exit without "
                         "writing the patchlist")
    ap.add_argument("--allow-empty", action="store_true",
                    help="write the patch list even when no sites were "
                         "selected")
    ap.add_argument("--no-module-bases", action="store_true",
                    help="leave out the per-module link-base table")
    ap.add_argument("--verbose", "-v", action="store_true")
    add_symbols_arg(ap)
    return ap


def main():
    program = getCurrentProgram()
    if program is None:
        sys.exit("error: no program open in Ghidra (import one, or run with "
                 "-process/-import under analyzeHeadless)")
    ap = build_arg_parser()
    args = ap.parse_args([str(a) for a in getScriptArgs()])
    args.symbols_map = load_symbols(args.symbols) if args.symbols else {}

    if (args.cutoff or args.max_depth is not None or args.print_reachable) \
            and not args.root:
        ap.error("--cutoff / --max-depth / --print-reachable require --root")

    run(args, program, monitor_or_dummy())


if __name__ == "__main__":
    main()
