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
  mt           -- multi-threaded libcov: same widths, plus alignment
                  filtering so every site's write is a single naturally-
                  aligned store (the largest atomic write each ISA
                  guarantees). For x86, also skips any site whose 2-byte
                  write would straddle a 64-byte cache line (Intel does
                  not guarantee atomicity in that case).

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
    return rz.cmdj("aflj") or []


def filter_functions(all_fns, include_re, exclude_re):
    out = []
    for f in all_fns:
        name = f.get("name", "")
        if include_re and not include_re.search(name):
            continue
        if exclude_re and exclude_re.search(name):
            continue
        out.append({
            "offset": int(f["offset"]),
            "name":   name,
            "bits":   int(f.get("bits", 0)),
        })
    return out


def get_block_insns(rz, addr, ninstr):
    return rz.cmdj(f"pdj {ninstr} @ {addr}") or []


BRANCH_TYPES = {
    "jmp", "ujmp", "cjmp", "ucjmp", "rjmp",
    "call", "ucall", "ccall", "rcall", "icall",
    "ret",
}


def _is_branch_at(rz, addr):
    insns = get_block_insns(rz, addr, 1)
    if not insns:
        return False
    t = insns[0].get("type", "")
    return t in BRANCH_TYPES


def pick_terminator(insns, ok=None):
    """Return the instruction to patch for a block under the terminator
    strategy: the LAST instruction that is at least 2 bytes long (the
    smallest trap encoding) and satisfies `ok`, or None.

    Walking back matters on x86: blocks ending in a 1-byte `ret` (every
    function exit) used to be dropped entirely. Any earlier instruction of
    a straight-line block executes whenever the block completes, so it is
    an equally valid probe. gen_boundary.py uses this same helper so
    boundary markers stay co-located with patched sites."""
    for insn in reversed(insns):
        if int(insn.get("size", 0)) < 2:
            continue
        if ok is not None and not ok(insn):
            continue
        return insn
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
            idx = 0
            if is_mips and _is_branch_at(rz, addr - 4):
                idx = 1
                if idx >= len(insns):
                    continue
            pick = insns[idx]
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
    x86:   2 (UD2 fits in 2 bytes; SDM guarantees aligned 16-bit stores
             are atomic; we additionally require it not span a cache line,
             enforced by the cache-line check below).
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

    For x86 only: also require the write not span a 64-byte cache line.
    Intel SDM does not guarantee atomicity for accesses that cross a
    cache-line boundary; a peer CPU could observe a partial write."""
    if addr % width != 0:
        return False
    if arch == "x86":
        if (addr & 63) + width > 64:
            return False
    return True


# ----------------------------------------------------------------------
# Selective instrumentation: symbol resolution + call-graph BFS.
# ----------------------------------------------------------------------

def _parse_int_maybe(tok):
    """Try to parse `tok` as an integer (hex with 0x prefix, plain hex of
    >=4 chars, or decimal). Return int on success, None on failure.

    The >=4-char heuristic for unprefixed hex avoids treating short
    identifiers like 'fd' as addresses."""
    s = tok.strip()
    try:
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        if s.isdigit():
            return int(s)
        if len(s) >= 4 and all(c in "0123456789abcdefABCDEF" for c in s):
            return int(s, 16)
    except ValueError:
        pass
    return None


def resolve_to_offset(token, all_fns):
    """Resolve a user-supplied symbol-or-address token to a function entry
    offset and its rizin function dict.

    Accepts:
      - hex address ('0x401234'), plain-hex address ('401234'), decimal.
        Addresses inside a function (not at entry) resolve to the
        enclosing function's entry, with a note printed to stderr.
      - Exact rizin function name from aflj ('dbg.main', 'sym.classify').
      - Bare name: tries 'dbg.', 'sym.', 'fcn.', 'sym.imp.' prefixes,
        then a suffix match against the last dotted segment of every
        function name.

    Raises ValueError if unresolvable or if a suffix match is ambiguous.
    """
    addr = _parse_int_maybe(token)
    if addr is not None:
        for f in all_fns:
            if int(f["offset"]) == addr:
                return int(f["offset"]), f
        # not a function entry -- find enclosing function by largest offset <= addr
        best = None
        for f in all_fns:
            o = int(f["offset"])
            if o <= addr and (best is None or o > int(best["offset"])):
                best = f
        if best is not None:
            print(f"note: address 0x{addr:x} not a function entry; "
                  f"using enclosing fn {best['name']} at 0x{int(best['offset']):x}",
                  file=sys.stderr)
            return int(best["offset"]), best
        raise ValueError(f"address {token} not within any known function")

    # exact name match
    for f in all_fns:
        if f["name"] == token:
            return int(f["offset"]), f
    # common-prefix tries
    for prefix in ("dbg.", "sym.", "fcn.", "sym.imp."):
        candidate = prefix + token
        for f in all_fns:
            if f["name"] == candidate:
                return int(f["offset"]), f
    # last-segment suffix match (e.g. user said 'main', match 'dbg.main')
    matches = [f for f in all_fns if f["name"].rsplit(".", 1)[-1] == token]
    if len(matches) == 1:
        return int(matches[0]["offset"]), matches[0]
    if len(matches) > 1:
        names = ", ".join(m["name"] for m in matches)
        raise ValueError(f"ambiguous symbol '{token}': matches {names}")
    raise ValueError(f"could not resolve '{token}' to any function")


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
        except json.JSONDecodeError:
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


def collect_module_records(args, rz, module_idx, module_name):
    """Walk one module's functions and return its patch records.

    Returns (records, mt_skipped_alignment). Each record is a tuple
    (offset, len, module_idx, orig_bytes) ready to be packed into the
    LCV3 wire format. The caller is responsible for combining records
    across modules and writing the final file.
    """
    inc = re.compile(args.include_pat) if args.include_pat else None
    exc = re.compile(args.exclude_pat) if args.exclude_pat else None

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

    # Selective instrumentation: resolve --root / --cutoff and intersect the
    # regex-filtered fns with the call-graph slice reachable from the roots.
    # Resolution and BFS run over the UNFILTERED function list, because the
    # user's regex may exclude intermediate functions that sit between a
    # --root and a downstream callee that the user does want to instrument.
    if args.root:
        all_fns = filter_functions(all_fns_raw, None, None)
        try:
            roots = set()
            for r in args.root:
                off, fn = resolve_to_offset(r, all_fns)
                roots.add(off)
                if args.verbose:
                    print(f"root:   '{r}' -> 0x{off:x} ({fn['name']})",
                          file=sys.stderr)
            cutoffs = set()
            for c in args.cutoff:
                off, fn = resolve_to_offset(c, all_fns)
                cutoffs.add(off)
                if args.verbose:
                    print(f"cutoff: '{c}' -> 0x{off:x} ({fn['name']})",
                          file=sys.stderr)
        except ValueError as e:
            sys.exit(f"error: {e}")

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
        print(f"reachable: {len(reachable_offsets)} function(s) from "
              f"{len(roots)} root(s), {len(cutoffs)} cutoff(s){depth_note}",
              file=sys.stderr)

        if args.print_reachable:
            by_off = {int(f["offset"]): f for f in all_fns}
            for off in sorted(reachable_offsets):
                f = by_off.get(off, {"name": "?", "bits": 0})
                print(f"  0x{off:x} {f['name']} bits={f.get('bits', 0)}",
                      file=sys.stderr)
            print("(--print-reachable: exiting before writing patchlist)",
                  file=sys.stderr)
            return None, 0

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
    for fn in fns:
        # Let the terminator walk-back skip candidates MT would reject, so
        # an odd-address x86 terminator falls back to an earlier, aligned
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

    return records, mt_skipped_alignment


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
    primary_name = args.binary.rsplit("/", 1)[-1]
    module_specs = [(primary_name, args.binary)]
    for spec in args.module:
        if ":" not in spec:
            sys.exit(f"error: --module requires NAME:PATH form, got '{spec}'")
        name, path = spec.split(":", 1)
        if not name or not path:
            sys.exit(f"error: --module '{spec}' has empty NAME or PATH")
        module_specs.append((name, path))

    if len(module_specs) > 255:
        sys.exit(f"error: too many modules ({len(module_specs)}); LCV3 caps at 255")

    all_records = []
    total_skipped = 0
    for module_idx, (name, path) in enumerate(module_specs):
        if args.verbose:
            print(f"opening rizin on module[{module_idx}] '{name}' ({path})",
                  file=sys.stderr)
        rz = open_rizin(path)
        try:
            result = collect_module_records(args, rz, module_idx, name)
        finally:
            try:
                rz.quit()
            except Exception:
                pass
        if result is None or result[0] is None:
            # --print-reachable returned early; no file written.
            return
        records, skipped = result
        all_records.extend(records)
        total_skipped += skipped

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
                         "PATH is the ELF file rizin analyses. Repeatable; "
                         "each --module gets the next module_idx starting at 1.")
    ap.add_argument("--include-pat", default=None,
                    help="only include functions whose name matches this regex")
    ap.add_argument("--exclude-pat",
                    default=r"^(sym\.imp\.|sym\._init|sym\._fini|sym\.deregister|sym\.register|sym\.frame_dummy|sym\.__libc_csu)",
                    help="exclude functions whose name matches this regex")
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
                         "addresses (0x401234). Combine with --cutoff to "
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
                         "function set to stderr, and exit without writing "
                         "the patchlist. Useful for iterating on a slice.")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if (args.cutoff or args.max_depth is not None or args.print_reachable) \
            and not args.root:
        ap.error("--cutoff / --max-depth / --print-reachable require --root")

    run(args)


if __name__ == "__main__":
    main()
