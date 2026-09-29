#!/usr/bin/env python3
"""
gen_patchlist.py -- produce an LCV3 binary patch list for one or more
modules (the main executable and optionally a set of shared libraries).

Drives rizin via the rzpipe Python module: one long-lived rizin process
per module, `aaa` runs exactly once per module at startup, and every
subsequent query reuses the cached analysis. The previous shell-
subprocess implementation re-ran `aaa` for every command and was
wall-clock dominated by it on medium-sized binaries.

Per-arch behavior:
  x86_64, aarch64, arm (ARM mode), powerpc, riscv64: patch block terminators
                                                     (last >= 2-byte insn)
  arm (Thumb mode):                                  patch first 2 bytes only
  mips, mips64:                                      patch block ENTRIES
                                                     (avoids branch delay slots)

x86_64 patches are head-only UD2 (2 bytes) regardless of original
instruction length; the tail of a variable-length x86 instruction is
never touched. ST and MT use the same patch shape.

Threading-mode selection (--threading):
  st (default) -- single-threaded libcov: arch-natural patch width
                  (x86=2, fixed-width 4-byte ISAs=4, Thumb/RV-C=2).
  mt           -- multi-threaded libcov: same widths, plus filtering so
                  every site's write is a single-copy-atomic store. On
                  fixed-width ISAs that means naturally aligned. On x86
                  any address works except one whose 2-byte write would
                  straddle a 64-byte cache line (Intel guarantees atomicity
                  for unaligned 16-bit stores only within a line).

Multi-module instrumentation:
  The positional `binary` is always module index 0 (typically the main
  executable). Additional shared libraries can be instrumented in the
  same patch list by passing `--module NAME:PATH` one or more times:

      gen_patchlist.py target_exe out.lcv \\
          --module libfoo.so:/path/to/libfoo.so \\
          --module libasdf.so:/path/to/libasdf.so

  NAME is the basename the runtime looks up in /proc/self/maps at init
  time; PATH is the file rizin analyzes. Each module's records are
  tagged with its index so the runtime can subtract the correct module
  load base for the ASLR-invariant coverage hash.

Selective instrumentation (--root / --cutoff / --max-depth):
  By default the generator emits sites for every function that survives
  --include-pat / --exclude-pat. For real-world fuzzing you usually want
  to instrument only the input-handling region of the binary -- not the
  whole address space. The selective flags scope the output to a
  reachability slice of the static call graph:

    --root SYM_OR_ADDR  (repeatable) -- BFS seed. Function name or
                                        address (0x401234 or 4198964).
    --cutoff SYM_OR_ADDR (repeatable) -- boundary; not instrumented and
                                         not traversed.
    --max-depth N        -- bound the BFS at N call-edges below each root.
    --print-reachable    -- dump the resolved slice and exit (no output
                            file written; useful for iterating).

  Resolution rules for --root / --cutoff arguments:
    - 0x-prefixed hex, plain hex (>=4 chars), or decimal -> address.
      Address inside a function (not at entry) resolves to the enclosing
      function's entry, with a note printed to stderr.
    - Bare names try (in order): exact rizin name, then 'dbg.<name>',
      'sym.<name>', 'fcn.<name>', 'sym.imp.<name>', then suffix match on
      the last dotted segment of every function name.  Ambiguous suffix
      matches are an error.

  The call graph is built from rizin's `afij` callrefs: outgoing CALL
  edges to functions inside the analyzed binary. PLT/import targets are
  *not* in the function-offset set and so naturally act as implicit
  cutoffs at the library boundary.

  When --root is combined with --include-pat / --exclude-pat the result
  is the intersection: a function must be both reachable AND pass the
  regex filters to be instrumented.

  Known limits (see TODO.md for planned improvements):
    - Indirect calls (function pointers, vtables) are invisible to
      static analysis. The BFS will not follow them; downstream
      functions reached only through fn-pointers will be missing from
      the slice and must be added with another --root.
    - Tail calls implemented as `jmp` may or may not appear in
      callrefs depending on rizin's classification; verify with
      --print-reachable.
    - Cutoffs are function-granular. Per-basic-block excision is a
      separate feature on the backlog.

Output layout matches src/patchlist_format.h:
  LCV3 header (24 bytes): magic[4]='LCV3', version=3, count, threading,
                           flags, module_count, reserved,
                           modules_offset, modules_size
  record (14 bytes):       u64 offset, u8 len, u8 module_idx, u8 orig[4]
  name table:              module_count NUL-terminated basenames at
                           modules_offset

Usage:
  # single module (the main executable):
  ./gen_patchlist.py <binary> <out.lcv> [--include-pat REGEX]
                                        [--exclude-pat REGEX]
                                        [--strategy auto|entry|terminator]
                                        [--threading st|mt]

  # multi-module (executable + two shared libraries):
  ./gen_patchlist.py <binary> <out.lcv> \\
        --module libfoo.so:/path/to/libfoo.so \\
        --module libasdf.so:/path/to/libasdf.so

  # selective (instrument only the slice rooted at parse_request,
  # but don't recurse into the logging or crypto subsystems):
  ./gen_patchlist.py <binary> <out.lcv> \\
        --root parse_request \\
        --cutoff log_writev --cutoff crypto_hash_update \\
        --max-depth 6 \\
        --threading st
"""
import argparse
import json
import os
import re
import struct
import sys

import rzpipe

from rz_resolve import NotFound, resolve_to_offset


# Functions excluded from instrumentation by default: PLT/import
# thunks and CRT/init stubs, none of which are meaningful coverage
# sites. --exclude-pat is ORed with this; --no-default-exclude drops it.
DEFAULT_EXCLUDE = r"^(sym\.imp\.|sym\._init|sym\._fini|sym\.deregister|sym\.register|sym\.frame_dummy|sym\.__libc_csu)"


# Threading-hint values written into the LCV3 header.
TH_ANY = 0
TH_ST  = 1
TH_MT  = 2

# Bytes of original instruction stored per record. Must match
# LIBCOV_PATCH_ORIG_MAX in src/patchlist_format.h.
LCV3_ORIG_LEN = 4

# LCV3 record layout: u64 offset, u8 len, u8 module_idx, u8 orig[4].
LCV3_RECORD_STRUCT = struct.Struct("<QBB4s")
assert LCV3_RECORD_STRUCT.size == 14

# LCV3 header layout: magic[4], version, count, threading, flags,
# module_count, reserved, modules_offset, modules_size.
LCV3_HEADER_STRUCT = struct.Struct("<4sIIBBBBII")
assert LCV3_HEADER_STRUCT.size == 24


# rizin still emits a few ANSI CSI sequences (clear-line etc.) even from
# rzpipe with default settings; strip them before raw-JSON decoding of
# `afij @@F` output. cmdj()-returned values are already JSON-parsed so
# this only matters for the raw `cmd()` path.
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def open_rizin(binary):
    """Open a persistent rizin session and run analysis exactly once.

    All subsequent queries reuse the cached analysis, which is the whole
    point of the rzpipe rewrite -- the previous shell-subprocess version
    re-ran `aaa` on every command and that dominated wall-clock cost on
    anything larger than the toy test target.
    """
    # rzpipe busy-loops forever (100% CPU, no error) when rizin cannot
    # open the file, so check up front.
    if not os.path.isfile(binary) or not os.access(binary, os.R_OK):
        sys.exit(f"error: cannot read binary {binary!r}")
    try:
        rz = rzpipe.open(binary)
    except Exception as e:
        sys.exit(f"error: failed to open {binary} with rizin: {e}")
    # Silence ANSI/colour from cmd() output; cmdj() is unaffected.
    rz.cmd("e scr.color=0")
    rz.cmd("aaa")
    return rz


def get_bin_info(rz):
    info = rz.cmdj("ij") or {}
    b = info.get("bin", {})
    return {
        "arch":   b.get("arch", ""),
        "bits":   int(b.get("bits", 64)),
        "endian": b.get("endian", "LE"),
        "baddr":  int(b.get("baddr", 0)),
    }


def get_all_functions(rz):
    """Unfiltered function list from `aflj`. Caller filters via regex."""
    return fix_elfv1_nop_entries(rz.cmdj, rz.cmdj("aflj") or [])


def fix_elfv1_nop_entries(cmdj, fns):
    """PPC64 ELFv1: rizin doesn't recognise a function whose body starts
    with a `nop` (common at -O2). It finds the code from entry+4 as an
    anonymous `fcn.<entry+4>`, so name filters, --root and gen_boundary
    can't find it. Rename each such function after the symbol whose .opd
    descriptor points at its entry -- `dbg.<name>` if rizin named other
    functions from DWARF, else `sym.<name>`. The offset stays at entry+4:
    the nop falls through, so the function's blocks and sites are those
    rizin found. `cmdj` runs a rizin command and returns parsed JSON.
    Returns `fns` (modified in place)."""
    opd = next((s for s in cmdj("iSj") or [] if s.get("name") == ".opd"), None)
    if opd is None:
        return fns
    lo, hi = int(opd["vaddr"]), int(opd["vaddr"]) + int(opd.get("vsize", 0))
    by_off = {int(f["offset"]): f for f in fns}
    prefix = "dbg." if any(f.get("name", "").startswith("dbg.") for f in fns) else "sym."
    for s in cmdj("isj") or []:
        desc = s.get("vaddr")
        if s.get("type") != "FUNC" or not desc or not lo <= int(desc) < hi:
            continue
        raw = cmdj(f"pxj 8 @ {int(desc)}") or []
        if len(raw) != 8:
            continue
        entry = int.from_bytes(bytes(raw), "big")  # ELFv1 is big-endian
        f = by_off.get(entry + 4)
        if entry in by_off or f is None or not f.get("name", "").startswith("fcn."):
            continue
        insn = cmdj(f"pdj 1 @ {entry}") or []
        if not insn or insn[0].get("type") != "nop":
            continue
        f["name"] = prefix + s["name"]
    return fns


def filter_functions(all_fns, include_re, exclude_re):
    out = []
    for f in all_fns:
        name = f.get("name", "")
        if include_re and not include_re.search(name):
            continue
        if exclude_re and exclude_re.search(name):
            continue
        out.append({
            "offset":   int(f["offset"]),
            "name":     name,
            "bits":     int(f.get("bits", 0)),
            # extent, so resolve_to_offset can bound address lookups
            "size":     int(f.get("size") or 0),
            "maxbound": int(f.get("maxbound") or 0),
        })
    return out


def report_include_matches(fns, pattern, module_name, verbose):
    """Make --include-pat's effect visible: list what it matched under -v,
    and warn when one function name matched under two rizin prefixes
    (sym.X and dbg.X), which usually means the pattern is looser than
    intended."""
    if verbose:
        print(f"--include-pat {pattern!r} matched {len(fns)} function(s) in "
              f"'{module_name}':", file=sys.stderr)
        for f in fns:
            print(f"  0x{f['offset']:x} {f['name']}", file=sys.stderr)
    by_base = {}
    for f in fns:
        base = re.sub(r"^(sym|dbg|fcn|loc)\.", "", f["name"])
        by_base.setdefault(base, []).append(f["name"])
    for base, names in sorted(by_base.items()):
        if len(names) > 1:
            print(f"warning: --include-pat {pattern!r} matched {base!r} under "
                  f"several names ({', '.join(names)}); sites at the same "
                  f"address are deduplicated", file=sys.stderr)


def get_block_insns(rz, addr, ninstr):
    return rz.cmdj(f"pdj {ninstr} @ {addr}") or []


def op_class(insn_type):
    """Classify a rizin op type as "call", "jmp", "ret" or None.

    Matches by suffix rather than an exact list: rizin has many variants
    (ucall/rcall/icall/ircall/ccall/uccall, ujmp/rjmp/ijmp/irjmp/mjmp/
    rcjmp/mcjmp/cjmp/ucjmp, cret, ...), which differ across arches and
    versions. MIPS branch-likely forms (beql, bnezl, bgezall, bc1tl) come
    back as cjmp/ccall like their non-likely versions. An exact list that
    missed one made the MIPS delay-slot check below fail, and the entry
    strategy then patched a delay slot, which crashes the target."""
    t = insn_type or ""
    for cls in ("call", "jmp", "ret"):
        if t.endswith(cls):
            return cls
    return None


def is_indirect_transfer(insn_type):
    """Call or jump whose target comes from a register or memory (function
    pointers, vtables, jump tables, PLT-free tail calls through a
    pointer). Static call-graph slicing can't see past these."""
    t = insn_type or ""
    return op_class(t) in ("call", "jmp") and t[:1] in ("u", "r", "i", "m")


def _is_branch_at(rz, addr):
    insns = get_block_insns(rz, addr, 1)
    if not insns:
        return False
    return op_class(insns[0].get("type")) is not None


# Mnemonics rizin emits when it decodes bytes as data, not code (literal
# pools, tbb/tbh jump-table payloads). Matched on the disasm mnemonic.
_DATA_MNEMONICS = frozenset(
    (".byte", ".word", ".short", ".hword", ".dword", ".qword", ".long",
     ".asciz", ".ascii", ".string", ".data", ".fill"))


def _insn_mnemonic(insn):
    disasm = (insn.get("disasm") or "").strip().lower()
    return disasm.split(None, 1)[0] if disasm else ""


def _is_data(insn):
    """True if rizin decoded this "instruction" as data rather than code: an
    invalid/undecodable opcode, or a data directive (a literal-pool word, a
    tbb/tbh jump-table payload). Patching data is PERMANENT corruption -- a
    data read never traps, so the original bytes are never restored.

    A literal word that happens to decode as a plausible instruction can't be
    caught by type alone; the overlap check and --strategy entry are the
    backstops for that residual case."""
    if (insn.get("type") or "") == "invalid":
        return True
    return _insn_mnemonic(insn) in _DATA_MNEMONICS


def _thumb_it_conditional_offsets(insns):
    """Offsets of instructions made conditional by a preceding Thumb IT block.
    A UDF trap on a conditional instruction is architecturally unpredictable,
    so those instructions must not be chosen. The IT instruction itself stays
    eligible -- it re-executes cleanly after restore.

    Detected purely from the disasm mnemonic: an IT block opener is 'it'
    optionally followed by 1-3 of {t,e} ('it','itt','ite','ittt',...), and it
    conditionalises the next len(mnemonic)-1 instructions (1-4). This shape
    only appears in real Thumb code, so it is a no-op on every other arch.
    Limitation: an IT block that spans a basic-block boundary (rare -- rizin
    seldom splits one) is not tracked across the split."""
    cond = set()
    n = len(insns)
    for i, insn in enumerate(insns):
        mnem = _insn_mnemonic(insn)
        if mnem.startswith("it") and set(mnem[2:]) <= {"t", "e"}:
            span = len(mnem) - 1  # conditional instructions after the IT
            for j in range(i + 1, min(i + 1 + span, n)):
                cond.add(int(insns[j].get("offset", -1)))
    return cond


def pick_terminator(insns, ok=None):
    """Return the instruction to patch for a block under the terminator
    strategy, or None. Candidates must be at least 2 bytes long (the
    smallest trap encoding), must be code rather than data (_is_data), must
    not sit inside a Thumb IT block, and must satisfy `ok`.

    - If the block makes a call before its last instruction, the first
      such call. rizin doesn't split blocks at calls, so a block whose
      callee never returns (abort, exit, longjmp, a throw -- or the
      callee crashing, which is the interesting case when fuzzing) never
      reaches its terminator and would never report. The call instruction
      itself executes before the callee runs.
    - Otherwise the LAST candidate. Walking back matters on x86: blocks
      ending in a 1-byte `ret` (every function exit) used to be dropped
      entirely. Any earlier instruction of a straight-line block executes
      whenever the block completes, so it is an equally valid probe.

    gen_boundary.py uses this same helper so boundary markers stay
    co-located with patched sites (and inherit the data/IT-block skips)."""
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
    """Return the instruction to patch for a block under the entry
    strategy, or None. Normally the block's first instruction; if the
    block starts in a MIPS branch delay slot (the instruction before it is
    a branch), the second one -- trapping in a delay slot reports the
    branch's PC and resumes at the branch. Skips leading data words (a
    literal pool at the block head) rather than patching them.

    gen_boundary.py uses this same helper so MIPS boundary markers stay
    co-located with patched sites."""
    idx = 1 if in_delay_slot else 0
    while idx < len(insns):
        insn = insns[idx]
        if int(insn.get("size", 0)) >= 2 and not _is_data(insn):
            return insn
        idx += 1
    return None


def pick_sites(rz, fn, strategy, arch, ok=None):
    is_mips = arch in ("mips", )
    blocks = rz.cmdj(f"afbj @ {fn['offset']}") or []
    sites = []
    for b in blocks:
        n = int(b.get("ninstr", 0))
        if n == 0:
            continue
        addr = int(b["addr"])
        insns = get_block_insns(rz, addr, n)
        if not insns:
            continue

        if strategy == "entry":
            pick = pick_entry(insns, is_mips and _is_branch_at(rz, addr - 4))
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
    """The largest single-copy-atomic write width the arch's ISA guarantees
    for our trap encoding. Drives the patch-record `len` field under MT.

    arm:   ARM mode = 4 (aligned word); Thumb = 2 (aligned half-word).
    aarch64, mips, mips64, ppc, ppc64: 4 (aligned word).
    riscv64: 2 (covers both c.unimp and the leading half of a 4-byte zero
             insn, both decode as illegal at the first 2 bytes).
    x86:   2 (UD2 fits in 2 bytes; SDM 8.1.1 guarantees 16-bit stores are
             atomic when they don't span a cache line, aligned or not --
             enforced by mt_addr_safe).
    """
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
    if arch == "arm64":  # rizin sometimes reports aarch64 as arm64
        return 4
    # default for fixed-width 4-byte ISAs we may have missed
    return 4


def mt_addr_safe(arch, addr, width):
    """Is a single atomic write of `width` bytes safe at `addr`?

    All fixed-width ISAs naturally align instructions to their width by
    ISA rule, so the address-mod check is a tautology there; we still
    enforce it as a defensive guard against malformed rizin output.

    x86 is the exception: unaligned 16-bit stores are single-copy atomic
    as long as they stay inside one 64-byte cache line (SDM 8.1.1), and
    libcov_mt's write_bytes() uses a plain `movw` for them. Only a write
    that spans a line is unsafe. The module load base is page-aligned, so
    checking the link-time address is equivalent to checking the runtime
    one. Keep the 64 in sync with LIBCOV_X86_CACHE_LINE in patch_mt.c."""
    if arch == "x86":
        return (addr & 63) + width <= 64
    return addr % width == 0


# ----------------------------------------------------------------------
# Selective instrumentation: symbol resolution + call-graph BFS.
# ----------------------------------------------------------------------

# resolve_to_offset / parse_int_maybe live in rz_resolve.py so gen_boundary.py
# resolves names identically (shared prefix + suffix matching).


def count_indirect_transfers(rz, offsets):
    """offset -> (indirect calls, indirect jumps) for each function in
    `offsets` that has any."""
    out = {}
    for off in offsets:
        ops = rz.cmdj(f"pdfj @ {off}") or {}
        calls = jumps = 0
        for op in ops.get("ops", []) if isinstance(ops, dict) else []:
            t = op.get("type")
            if is_indirect_transfer(t):
                if op_class(t) == "call":
                    calls += 1
                else:
                    jumps += 1
        if calls or jumps:
            out[off] = (calls, jumps)
    return out


def report_indirect_transfers(indirect):
    """The static call graph stops at indirect transfers, so code reached
    only through function pointers, vtables or dispatch tables is silently
    left out of a --root slice. Say how many there are. (Review C5)"""
    calls = sum(c for c, _ in indirect.values())
    jumps = sum(j for _, j in indirect.values())
    if not calls and not jumps:
        return
    print(f"note: the slice has {calls} indirect call(s) and {jumps} indirect "
          f"jump(s) in {len(indirect)} function(s). Their targets are not "
          f"followed: code reached only through function pointers, vtables "
          f"or dispatch tables is NOT instrumented unless you add it with "
          f"--root (see --print-reachable for which functions).",
          file=sys.stderr)


def build_call_graph(rz, all_fns):
    """Build outgoing-call adjacency: offset -> set(offset).

    Runs `afij @@F` in the persistent session. The `@@F` iterator runs
    `afij` at every function rizin discovered, emitting each as its own
    JSON array. We parse the concatenated arrays with
    `json.JSONDecoder.raw_decode` and key results by each entry's
    `offset` field (NOT positionally -- the iteration order isn't a
    documented contract).

    Edges are restricted to in-binary function entries. PLT stubs,
    imports, and any callee whose target is not in the analyzed
    function set are dropped -- so the BFS implicitly stops at the
    library boundary.

    Earlier attempt used `aaa; afij @ X; ?e SEP; afij @ Y; ...` to
    delimit per-function output, but rizin's command parser rejects
    that exact chaining (`?e` between two `@`-suffixed commands).
    `@@F` is both cleaner and the documented all-functions iterator.
    """
    fn_set = {int(f["offset"]) for f in all_fns}
    raw = rz.cmd("afij @@F")
    raw = _ANSI_CSI_RE.sub("", raw).strip()

    # Walk the concatenated JSON arrays.
    decoder = json.JSONDecoder()
    pos = 0
    adj = {off: set() for off in fn_set}
    while pos < len(raw):
        while pos < len(raw) and raw[pos] in " \t\r\n":
            pos += 1
        if pos >= len(raw):
            break
        try:
            obj, end = decoder.raw_decode(raw, pos)
        except json.JSONDecodeError as e:
            print(f"warning: could not parse rizin 'afij @@F' output at "
                  f"offset {pos} ({e.msg}); the call graph is truncated and "
                  f"the slice may be missing functions", file=sys.stderr)
            break
        pos = end
        # obj is a list with (typically) one entry per afij invocation.
        entries = obj if isinstance(obj, list) else [obj]
        for entry in entries:
            off = int(entry.get("offset", -1))
            if off not in fn_set:
                continue
            callees = adj.setdefault(off, set())
            for c in (entry.get("callrefs") or []):
                # Current rizin emits {"from": <call-site>, "to":
                # <callee>, "type": ...}. Older versions used
                # {"addr": <callee>, "at": <call-site>, "type": ...}.
                # Accept either; prefer `to`. Type values seen in the
                # wild: "CALL" (direct), "CODE" (jmp-edge tail-call or
                # unresolved indirect), "JMP". We follow CALL only --
                # CODE picks up too many false positives. If `type` is
                # missing (very old rizin), accept.
                ctype = c.get("type")
                if ctype is not None and ctype != "CALL":
                    continue
                try:
                    d = int(c.get("to", c.get("addr", -1)))
                except (TypeError, ValueError):
                    continue
                if d in fn_set:
                    callees.add(d)
    return adj


def bfs_reachable(roots, adj, cutoffs, max_depth=None):
    """BFS from `roots` over `adj`, treating each offset in `cutoffs` as
    a hard boundary: not added to the reachable set, not traversed
    through. Returns the set of reachable offsets (including roots that
    aren't themselves cutoffs).

    `max_depth` (if not None) bounds traversal to that many call-edges
    below each root. A root is depth 0; its direct callees are depth 1.
    """
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
    """Reject records whose [offset, offset+len) byte ranges overlap. An
    overlap means one site would patch bytes another site owns -- a
    double-patch that corrupts the target (a partial restore leaves stale
    illegal bytes behind). Exact-duplicate addresses are already deduped
    upstream, so only partial-range overlaps reach here.

    `records` is a list of (offset, size, module_idx, orig). Offsets are
    module-relative, so this is called per module. By default the later
    (higher-offset) site of an overlapping pair is dropped with a warning;
    with `fail` set the first overlap is a hard error. Returns the surviving
    records in their original (discovery) order so downstream output is
    otherwise unchanged."""
    ordered = sorted(records, key=lambda r: (r[0], r[1]))
    dropped = set()
    prev = None
    for rec in ordered:
        off, size = rec[0], rec[1]
        if prev is not None:
            poff, psize = prev[0], prev[1]
            if off < poff + psize:
                msg = (f"site 0x{off:x} (len {size}) overlaps "
                       f"0x{poff:x}-0x{poff + psize:x}")
                if fail:
                    sys.exit(f"error: {module_name}: {msg}")
                print(f"warning: {module_name}: {msg}; dropping 0x{off:x}",
                      file=sys.stderr)
                dropped.add(id(rec))
                # Keep `prev` as the earlier site so a run of overlaps all
                # measure against the site actually retained.
                continue
        prev = rec
    if not dropped:
        return records
    return [r for r in records if id(r) not in dropped]


def parse_slice_specs(tokens, module_specs, flag):
    """Parse --root / --cutoff tokens into specs.

    `MOD!TOKEN` pins a spec to one module (MOD = the module's name, or the
    basename of its path); `!` can't clash with --module's NAME:PATH or a
    C++ `ns::fn`. An unqualified name resolves in every module that has
    it; an unqualified explicit address (0x..., decimal) means module 0,
    since module address ranges overlap."""
    specs = []
    for tok in tokens:
        mod = None
        body = tok
        if "!" in tok:
            mname, body = tok.split("!", 1)
            for i, (name, path) in enumerate(module_specs):
                if mname in (name, os.path.basename(path)):
                    mod = i
                    break
            else:
                names = ", ".join(n for n, _ in module_specs)
                sys.exit(f"error: {flag} '{tok}': no module '{mname}' "
                         f"(modules: {names})")
            if not body:
                sys.exit(f"error: {flag} '{tok}': empty name after '!'")
        b = body.strip()
        is_addr = b.startswith(("0x", "0X")) or b.isdigit()
        specs.append({"tok": body, "mod": mod, "addr": is_addr, "orig": tok})
    return specs


def resolve_slice_specs(specs, module_idx, all_fns, found, stubs, flag, verbose):
    """Resolve the specs that apply to module `module_idx` to function
    entry offsets. Records in `found[i]` which modules spec i resolved in.
    A qualified spec or an address must resolve where it applies; an
    unqualified name that isn't here may live in another module (run()
    checks it resolved somewhere). An unqualified name that only matches
    an import stub (sym.imp.NAME: a PLT jump into the defining module)
    doesn't count; `stubs[i]` remembers it for the error message."""
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
                sys.exit(f"error: {flag} '{sp['orig']}': {e}")
            continue
        except ValueError as e:          # ambiguous within this module
            sys.exit(f"error: {flag} '{sp['orig']}': {e}")
        if (sp["mod"] is None and fn["name"].startswith("sym.imp.")
                and not sp["tok"].startswith("sym.imp.")):
            stubs.setdefault(i, (module_idx, fn["name"]))
            continue
        out.add(off)
        found.setdefault(i, []).append(module_idx)
        if verbose:
            print(f"{flag[2:]}: module[{module_idx}] '{sp['orig']}' -> 0x{off:x} "
                  f"({fn['name']})", file=sys.stderr)
    return out


def collect_module_records(args, rz, module_idx, module_name, slicing=None):
    """Walk one module's functions and return its patch records.

    Returns (records, mt_skipped_alignment). Each record is a tuple
    (offset, len, module_idx, orig_bytes) ready to be packed into the
    LCV3 wire format. The caller is responsible for combining records
    across modules and writing the final file.

    `slicing` carries the parsed --root / --cutoff specs and the per-spec
    "resolved in" maps shared across modules (see run()). With
    --print-reachable the slice is printed and no records are returned.
    """
    inc = re.compile(args.include_pat) if args.include_pat else None
    exc_pats = []
    if not args.no_default_exclude:
        exc_pats.append(DEFAULT_EXCLUDE)
    if args.exclude_pat:
        exc_pats.append(args.exclude_pat)
    exc = re.compile("|".join(f"(?:{pat})" for pat in exc_pats)) if exc_pats else None

    info = get_bin_info(rz)
    baddr = info["baddr"]
    arch  = info["arch"]
    bits  = info["bits"]
    strategy = args.strategy if args.strategy != "auto" else default_strategy(arch, bits)
    if arch == "mips" and strategy == "terminator":
        # rizin places the branch delay slot inside the branch's block, so
        # the terminator IS the delay slot: trapping there reports the
        # branch's PC semantics wrong and restoring it crashes the target.
        sys.exit("error: --strategy terminator is unsafe on MIPS (delay slots); use entry")

    if args.verbose:
        print(f"module[{module_idx}] '{module_name}': arch={arch} bits={bits} "
              f"endian={info['endian']} baddr=0x{baddr:x} strategy={strategy}",
              file=sys.stderr)

    # One canonical `aflj` snapshot, reused for filtering, slice
    # resolution, and PPC64 dual-entry lookup.
    all_fns_raw = get_all_functions(rz)
    fns = filter_functions(all_fns_raw, inc, exc)
    if inc:
        report_include_matches(fns, args.include_pat, module_name, args.verbose)

    # Selective instrumentation: resolve --root / --cutoff and intersect the
    # regex-filtered fns with the call-graph slice reachable from the roots.
    # Resolution and BFS run over the UNFILTERED function list, because the
    # user's regex may exclude intermediate functions that sit between a
    # --root and a downstream callee that the user does want to instrument.
    if args.root:
        all_fns = filter_functions(all_fns_raw, None, None)
        roots = resolve_slice_specs(slicing["roots"], module_idx, all_fns,
                                    slicing["found_roots"], slicing["stub_roots"],
                                    "--root", args.verbose)
        cutoffs = resolve_slice_specs(slicing["cutoffs"], module_idx, all_fns,
                                      slicing["found_cutoffs"],
                                      slicing["stub_cutoffs"], "--cutoff",
                                      args.verbose)
        if not roots:
            # Calls into another module go through its PLT and aren't
            # followed, so a slice never reaches a module without its own
            # root: instrumenting all of it would ignore the slice.
            print(f"warning: module[{module_idx}] '{module_name}': no --root "
                  f"resolves here, so nothing in it is instrumented (add "
                  f"--root '{module_name}!FUNC')", file=sys.stderr)
            if args.print_reachable:
                print(f"module[{module_idx}] '{module_name}': no roots",
                      file=sys.stderr)
            return [], 0

        bad_roots = roots & cutoffs
        if bad_roots:
            bad_hex = ", ".join(f"0x{x:x}" for x in sorted(bad_roots))
            print(f"warning: root(s) {bad_hex} are also cutoffs; slice will "
                  f"exclude them and BFS will not expand from them",
                  file=sys.stderr)

        print(f"building call graph over {len(all_fns)} functions...",
              file=sys.stderr)
        adj = build_call_graph(rz, all_fns)
        reachable_offsets = bfs_reachable(roots, adj, cutoffs, args.max_depth)
        depth_note = (f", max-depth={args.max_depth}"
                      if args.max_depth is not None else "")
        print(f"module[{module_idx}] '{module_name}': reachable: "
              f"{len(reachable_offsets)} function(s) from "
              f"{len(roots)} root(s), {len(cutoffs)} cutoff(s){depth_note}",
              file=sys.stderr)

        indirect = count_indirect_transfers(rz, reachable_offsets)
        report_indirect_transfers(indirect)

        if args.print_reachable:
            by_off = {int(f["offset"]): f for f in all_fns}
            for off in sorted(reachable_offsets):
                f = by_off.get(off, {"name": "?", "bits": 0})
                calls, jumps = indirect.get(off, (0, 0))
                note = (f" indirect: {calls} call(s), {jumps} jump(s)"
                        if calls or jumps else "")
                print(f"  0x{off:x} {f['name']} bits={f.get('bits', 0)}{note}",
                      file=sys.stderr)
            return [], 0

        before = len(fns)
        fns = [f for f in fns if int(f["offset"]) in reachable_offsets]
        if args.verbose:
            print(f"regex \u2229 reachable: {before} -> {len(fns)} functions",
                  file=sys.stderr)

    # PowerPC64 dual entry: also pull in fcn.<offset+8> for each matched
    # fn. Reuses the same cached aflj snapshot -- no fresh query.
    if arch == "ppc" and bits == 64:
        by_offset = {int(f["offset"]): f for f in all_fns_raw}
        extra = []
        seen_offsets = {f["offset"] for f in fns}
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
        print(f"functions to instrument: {len(fns)}", file=sys.stderr)
        for fn in fns:
            print(f"  0x{fn['offset']:x} {fn['name']} bits={fn['bits']}",
                  file=sys.stderr)

    seen = set()
    records = []
    mt_skipped_alignment = 0
    fcn_skipped = 0
    for fn in fns:
        # rizin heuristic functions (fcn.<addr>, no symbol) have the least
        # reliable block boundaries and code/data classification, so patching
        # inside them is the riskiest for data-in-text corruption. Skip them
        # unless the user opts in. Only emission is skipped -- the call-graph
        # BFS still traverses through them to reach real callees.
        if not args.include_fcn and fn["name"].startswith("fcn."):
            fcn_skipped += 1
            if args.verbose:
                print(f"  skip fn {fn['name']} (heuristic fcn.*; use --include-fcn)",
                      file=sys.stderr)
            continue
        # Let the terminator walk-back skip candidates MT would reject, so
        # a line-straddling x86 terminator falls back to an earlier
        # instruction instead of losing the whole block.
        ok = None
        if args.threading == "mt":
            width = mt_atomic_width(arch, fn["bits"])
            ok = lambda insn, w=width: mt_addr_safe(arch, int(insn["offset"]), w)
        sites = pick_sites(rz, fn, strategy, arch, ok)
        for addr, size, bhex in sites:
            if addr in seen:
                continue
            try:
                orig = bytes.fromhex(bhex)
            except ValueError:
                continue
            if len(orig) != size:
                continue

            # Skip sites whose ORIGINAL instruction is shorter than the
            # smallest illegal we can emit (2 bytes for every supported
            # arch). Must run BEFORE the per-arch clamps below, otherwise
            # a 1-byte x86 ret would have its record `len` bumped to 2
            # while orig still holds only 1 real byte; the runtime would
            # then write a 2-byte UD2 over the ret + the first byte of
            # the next instruction, and disarm would restore only 1 byte
            # of orig followed by a zero padding byte -- corrupting that
            # next instruction.
            if size < 2:
                if args.verbose:
                    print(f"  skip 0x{addr:x} len={size} (too short for illegal encoding)",
                          file=sys.stderr)
                continue

            # Thumb override (ST and MT both): write only first 2 bytes.
            if arch == "arm" and fn["bits"] == 16:
                size = 2
                orig = orig[:2]

            # x86 head-only UD2: always 2 bytes regardless of original
            # instruction length. Matches LIBCOV_ARCH_X86_64_MAX_PATCH_LEN
            # in src/tunables_x86_64.h.
            if arch == "x86":
                size = 2
                orig = orig[:2]

            if args.threading == "mt":
                width = mt_atomic_width(arch, fn["bits"])
                if not mt_addr_safe(arch, addr, width):
                    mt_skipped_alignment += 1
                    if args.verbose:
                        print(f"  skip 0x{addr:x} (mt: not safe for "
                              f"{width}-byte atomic write)", file=sys.stderr)
                    continue
                # Force record `len` to the atomic width; truncate orig
                # bytes accordingly. arm/disarm at runtime touches exactly
                # this many bytes.
                size = width
                orig = orig[:width]

            if size < 2 or size > LCV3_ORIG_LEN:
                if args.verbose:
                    print(f"  skip 0x{addr:x} len={size} (out of range)",
                          file=sys.stderr)
                continue

            offset = addr - baddr
            records.append((offset, size, module_idx, orig))
            seen.add(addr)
            if args.verbose:
                print(f"  patch 0x{addr:x} off=0x{offset:x} len={size} "
                      f"midx={module_idx} bytes={orig.hex()} ({fn['name']})",
                      file=sys.stderr)

    if fcn_skipped and args.verbose:
        print(f"  skipped {fcn_skipped} heuristic fcn.* function(s) "
              f"(use --include-fcn to instrument them)", file=sys.stderr)

    records = validate_no_overlap(records, module_name, args.fail_on_overlap)
    return records, mt_skipped_alignment


def runtime_module_name(name, path):
    """The name libcov will find `path` under in /proc/self/maps.

    maps lists the file actually mapped, i.e. the symlink target: a
    patch list generated from /bin/ls -> busybox or libfoo.so.1 ->
    libfoo.so.1.2.3 must name busybox / libfoo.so.1.2.3. Prints a note
    when that differs from `name`."""
    real = os.path.basename(os.path.realpath(path))
    if real and real != name:
        print(f"note: {path} is a symlink to {real}; naming the module "
              f"'{real}' (the name /proc/self/maps shows)", file=sys.stderr)
        return real
    return name


def write_lcv3(output_path, module_names, records, threading_hint):
    """Pack module records + name table into the LCV3 wire format."""
    name_blob = b"".join(n.encode("utf-8") + b"\x00" for n in module_names)
    header_size  = LCV3_HEADER_STRUCT.size
    records_size = LCV3_RECORD_STRUCT.size * len(records)
    modules_offset = header_size + records_size
    modules_size   = len(name_blob)

    with open(output_path, "wb") as f:
        f.write(LCV3_HEADER_STRUCT.pack(
            b"LCV3", 3, len(records),
            threading_hint, 0, len(module_names), 0,
            modules_offset, modules_size))
        for offset, size, module_idx, orig in records:
            padded = orig + b"\x00" * (LCV3_ORIG_LEN - len(orig))
            f.write(LCV3_RECORD_STRUCT.pack(offset, size, module_idx, padded))
        f.write(name_blob)


def run(args):
    """Collect records from every requested module and emit an LCV3 file."""
    threading_hint = TH_MT if args.threading == "mt" else TH_ST

    # Module index 0 is always the positional `binary`. Additional
    # `--module name:path` flags become module indices 1, 2, ... in the
    # order they appear on the command line.
    primary_name = runtime_module_name(os.path.basename(args.binary), args.binary)
    module_specs = [(primary_name, args.binary)]
    for spec in args.module:
        if ":" not in spec:
            sys.exit(f"error: --module requires NAME:PATH form, got '{spec}'")
        name, path = spec.split(":", 1)
        if not name or not path:
            sys.exit(f"error: --module '{spec}' has empty NAME or PATH")
        # NAME spelled as PATH's own (symlink) basename means "this file":
        # store the real name, as for the primary. Any other NAME is the
        # user's explicit choice and is kept.
        if name == os.path.basename(path):
            name = runtime_module_name(name, path)
        module_specs.append((name, path))

    if len(module_specs) > 255:
        sys.exit(f"error: too many modules ({len(module_specs)}); LCV3 caps at 255")

    slicing = {
        "roots":   parse_slice_specs(args.root, module_specs, "--root"),
        "cutoffs": parse_slice_specs(args.cutoff, module_specs, "--cutoff"),
        "found_roots": {}, "found_cutoffs": {},
        "stub_roots": {}, "stub_cutoffs": {},
    }

    all_records = []
    total_skipped = 0
    for module_idx, (name, path) in enumerate(module_specs):
        if args.verbose:
            print(f"opening rizin on module[{module_idx}] '{name}' ({path})",
                  file=sys.stderr)
        rz = open_rizin(path)
        try:
            records, skipped = collect_module_records(args, rz, module_idx,
                                                      name, slicing)
        finally:
            try:
                rz.quit()
            except Exception:
                pass
        all_records.extend(records)
        total_skipped += skipped

    # Every unqualified --root / --cutoff name must have resolved in at
    # least one module; say where a name resolved in several.
    for key, flag in (("roots", "--root"), ("cutoffs", "--cutoff")):
        found = slicing["found_" + key]
        for i, sp in enumerate(slicing[key]):
            mods = found.get(i, [])
            if not mods:
                stub = slicing["stub_" + key].get(i)
                why = (f" (module[{stub[0]}] has only the import stub {stub[1]}; "
                       f"add the module that defines it with --module)"
                       if stub else "")
                sys.exit(f"error: {flag} '{sp['orig']}': could not resolve it "
                         f"in any module{why}")
            if len(mods) > 1:
                where = ", ".join(f"module[{m}] '{module_specs[m][0]}'" for m in mods)
                print(f"note: {flag} '{sp['orig']}' resolved in {where} "
                      f"(qualify it as MODULE!NAME to pick one)", file=sys.stderr)

    if args.print_reachable:
        print("(--print-reachable: exiting before writing patchlist)",
              file=sys.stderr)
        return

    if not all_records and not args.allow_empty:
        hint = ""
        if args.include_pat:
            hint = (" Check --include-pat: rizin names functions with debug "
                    "info 'dbg.NAME' and others 'sym.NAME' (run with -v to "
                    "see what matched).")
        sys.exit(f"error: no patch sites selected; not writing {args.output}."
                 f"{hint} Pass --allow-empty to write an empty patch list "
                 f"anyway.")

    write_lcv3(args.output, [n for n, _ in module_specs], all_records,
               threading_hint)

    skipped_note = (f", skipped {total_skipped} mt-unsafe sites"
                    if total_skipped else "")
    print(f"wrote {len(all_records)} records across {len(module_specs)} "
          f"module(s) to {args.output} (threading={args.threading}{skipped_note})",
          file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary",
                    help="primary module to instrument (module index 0). "
                         "Typically the main executable; the runtime resolves "
                         "its load base from /proc/self/maps using the file's "
                         "basename.")
    ap.add_argument("output")
    ap.add_argument("--module", action="append", default=[],
                    metavar="NAME:PATH",
                    help="add an auxiliary module to instrument alongside the "
                         "primary binary. NAME is the basename the runtime "
                         "looks up in /proc/self/maps (e.g. 'libfoo.so'); "
                         "PATH is the ELF file rizin analyses. If NAME is "
                         "PATH's basename and PATH is a symlink, the real "
                         "file's name is stored instead. Repeatable; "
                         "each --module gets the next module_idx starting at 1.")
    ap.add_argument("--include-pat", default=None,
                    help="only include functions whose name matches this regex")
    ap.add_argument("--exclude-pat", default=None,
                    help="also exclude functions whose name matches this "
                         "regex; added to (not replacing) the built-in "
                         "exclusions. Use --no-default-exclude to drop those.")
    ap.add_argument("--no-default-exclude", action="store_true",
                    help="do not apply the built-in exclusions "
                         "(sym.imp.*, CRT/init stubs); only --exclude-pat, "
                         "if given, is used")
    ap.add_argument("--include-fcn", action="store_true",
                    help="instrument rizin heuristic functions (fcn.*) too; "
                         "skipped by default because their block boundaries and "
                         "code/data classification are least reliable")
    ap.add_argument("--fail-on-overlap", action="store_true",
                    help="treat overlapping patch sites as a hard error instead "
                         "of dropping the later site with a warning")
    ap.add_argument("--strategy", choices=["auto", "entry", "terminator"],
                    default="auto",
                    help="per-block patch site selection (auto = arch default)")
    ap.add_argument("--threading", choices=["st", "mt"], default="st",
                    help="target libcov threading variant (st default, mt for "
                         "thread-safe runtime)")
    ap.add_argument("--root", action="append", default=[],
                    metavar="SYM_OR_ADDR",
                    help="instrument only the call-graph slice reachable from "
                         "this function/address. Repeatable. Accepts function "
                         "names (main, dbg.main, sym.parse_request) or "
                         "addresses (0x401234, which must fall inside a "
                         "function). With --module, a name resolves in every "
                         "module that has it, an address means the primary "
                         "binary, and MODULE!NAME (e.g. 'libfoo.so!parse') "
                         "pins one module; a module no root resolves in is "
                         "not instrumented. Combine with --cutoff to "
                         "scope further. If omitted, all functions matching "
                         "--include-pat/--exclude-pat are instrumented "
                         "(legacy behavior).")
    ap.add_argument("--cutoff", action="append", default=[],
                    metavar="SYM_OR_ADDR",
                    help="stop call-graph traversal at this function. The "
                         "cutoff itself is excluded from the slice. "
                         "Repeatable. Resolution rules match --root.")
    ap.add_argument("--max-depth", type=int, default=None, metavar="N",
                    help="bound the call-graph BFS to N edges below each root "
                         "(default: unbounded). A root is depth 0.")
    ap.add_argument("--print-reachable", action="store_true",
                    help="resolve --root/--cutoff, print the reachable "
                         "function set of every module to stderr, and exit "
                         "without writing the patchlist. Useful for iterating "
                         "on a slice.")
    ap.add_argument("--allow-empty", action="store_true",
                    help="write the patch list even when no sites were "
                         "selected (by default that is an error: an empty "
                         "list makes libcov silently record nothing)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if (args.cutoff or args.max_depth is not None or args.print_reachable) \
            and not args.root:
        ap.error("--cutoff / --max-depth / --print-reachable require --root")

    run(args)


if __name__ == "__main__":
    main()
