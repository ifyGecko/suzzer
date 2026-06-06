#!/usr/bin/env python3
"""
gen_patchlist.py -- produce an LCV2 binary patch list for a target binary.

Per-arch behavior:
  x86_64, aarch64, arm (ARM mode), powerpc, riscv64: patch block terminators
  arm (Thumb mode):                                  patch first 2 bytes only
  mips, mips64:                                      patch block ENTRIES
                                                     (avoids branch delay slots)

Threading-mode selection (--threading):
  st (default) -- single-threaded libcov:
                  full insn length recorded (x86: up to 15 bytes);
                  arm/disarm writes len bytes (UD2 + NOP pad on x86).
  mt           -- multi-threaded libcov:
                  every record's `len` reduced to the arch's atomic
                  write width (x86=2, aarch64/arm/mips/ppc=4,
                  thumb/riscv-compressed=2). Required so the runtime can
                  perform a single naturally-aligned store, which is the
                  largest atomic write the ISA guarantees.
                  For x86, also skips any site whose 2-byte write would
                  straddle a 64-byte cache line (Intel does not guarantee
                  atomicity in that case).

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
      the last dotted segment. Ambiguous suffix matches are an error.

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

Output layout matches src/config.h:
  LCV2 header: magic[4]='LCV2', version=2, count, threading, flags, reserved
  record:      u64 offset, u8 len, u8 orig[15]

Usage:
  # full-binary (legacy):
  ./gen_patchlist.py <binary> <out.lcv> [--include-pat REGEX]
                                        [--exclude-pat REGEX]
                                        [--strategy auto|entry|terminator]
                                        [--threading st|mt]

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
import re
import struct
import subprocess
import sys


# Threading-hint values written into the LCV2 header.
TH_ANY = 0
TH_ST  = 1
TH_MT  = 2


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


def get_bin_info(binary):
    info = rizin_json(binary, ["ij"]) or {}
    b = info.get("bin", {})
    return {
        "arch":   b.get("arch", ""),
        "bits":   int(b.get("bits", 64)),
        "endian": b.get("endian", "LE"),
        "baddr":  int(b.get("baddr", 0)),
    }


def get_functions(binary, include_re, exclude_re):
    fns = rizin_json(binary, ["aaa", "aflj"]) or []
    out = []
    for f in fns:
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


def get_block_insns(binary, addr, ninstr):
    return rizin_json(binary, ["aaa", f"pdj {ninstr} @ {addr}"]) or []


BRANCH_TYPES = {
    "jmp", "ujmp", "cjmp", "ucjmp", "rjmp",
    "call", "ucall", "ccall", "rcall", "icall",
    "ret",
}


def _is_branch_at(binary, addr):
    insns = get_block_insns(binary, addr, 1)
    if not insns:
        return False
    t = insns[0].get("type", "")
    return t in BRANCH_TYPES


def pick_sites(binary, fn, strategy, arch):
    is_mips = arch in ("mips", )
    blocks = rizin_json(binary, ["aaa", f"afbj @ {fn['offset']}"]) or []
    sites = []
    for b in blocks:
        n = int(b.get("ninstr", 0))
        if n == 0:
            continue
        addr = int(b["addr"])
        insns = get_block_insns(binary, addr, n)
        if not insns:
            continue

        if strategy == "entry":
            idx = 0
            if is_mips and _is_branch_at(binary, addr - 4):
                idx = 1
                if idx >= len(insns):
                    continue
            pick = insns[idx]
        else:
            pick = insns[-1]
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


# ANSI CSI strip: rizin prints terminal control sequences (e.g. clear-
# line "\x1b[2K") even with -q, which break a literal-string startswith
# check on JSON output. We strip them before JSON-parsing.
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def build_call_graph(binary, all_fns):
    """Build outgoing-call adjacency: offset -> set(offset).

    Runs a single rizin session: `aaa; afij @@F`. The `@@F` iterator
    runs `afij` at every function rizin discovered, emitting each as
    its own JSON array. We parse the concatenated arrays with
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
    raw = rizin(binary, ["aaa", "afij @@F"])
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("output")
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

    inc = re.compile(args.include_pat) if args.include_pat else None
    exc = re.compile(args.exclude_pat) if args.exclude_pat else None

    info = get_bin_info(args.binary)
    baddr = info["baddr"]
    arch  = info["arch"]
    bits  = info["bits"]
    strategy = args.strategy if args.strategy != "auto" else default_strategy(arch, bits)
    threading_hint = TH_MT if args.threading == "mt" else TH_ST

    if args.verbose:
        print(f"arch={arch} bits={bits} endian={info['endian']} "
              f"baddr=0x{baddr:x} strategy={strategy} threading={args.threading}",
              file=sys.stderr)

    fns = get_functions(args.binary, inc, exc)

    # Selective instrumentation: resolve --root / --cutoff and intersect the
    # regex-filtered fns with the call-graph slice reachable from the roots.
    # Resolution and BFS run over the UNFILTERED function list, because the
    # user's regex may exclude intermediate functions that sit between a
    # --root and a downstream callee that the user does want to instrument.
    reachable_offsets = None
    if args.root:
        all_fns = get_functions(args.binary, None, None)
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
        adj = build_call_graph(args.binary, all_fns)
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
            return

        before = len(fns)
        fns = [f for f in fns if int(f["offset"]) in reachable_offsets]
        if args.verbose:
            print(f"regex \u2229 reachable: {before} -> {len(fns)} functions",
                  file=sys.stderr)

    # PowerPC64 dual entry: also pull in fcn.<offset+8> for each matched fn.
    if arch == "ppc" and bits == 64:
        all_fns = rizin_json(args.binary, ["aaa", "aflj"]) or []
        by_offset = {int(f["offset"]): f for f in all_fns}
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
        sites = pick_sites(args.binary, fn, strategy, arch)
        for addr, size, bhex in sites:
            if addr in seen:
                continue
            try:
                orig = bytes.fromhex(bhex)
            except ValueError:
                continue
            if len(orig) != size:
                continue

            # Thumb override (ST and MT both): write only first 2 bytes.
            if arch == "arm" and fn["bits"] == 16:
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

            if size < 2 or size > 15:
                if args.verbose:
                    print(f"  skip 0x{addr:x} len={size} (out of range)",
                          file=sys.stderr)
                continue

            offset = addr - baddr
            records.append((offset, size, orig))
            seen.add(addr)
            if args.verbose:
                print(f"  patch 0x{addr:x} off=0x{offset:x} len={size} "
                      f"bytes={orig.hex()} ({fn['name']})", file=sys.stderr)

    with open(args.output, "wb") as f:
        # LCV2 header: magic, version, count, threading, flags, reserved
        f.write(b"LCV2")
        f.write(struct.pack("<II", 2, len(records)))
        f.write(struct.pack("<BBH", threading_hint, 0, 0))
        for offset, size, orig in records:
            padded = orig + b"\x00" * (15 - size)
            f.write(struct.pack("<QB15s", offset, size, padded))

    print(f"wrote {len(records)} records to {args.output} "
          f"(threading={args.threading}"
          + (f", skipped {mt_skipped_alignment} mt-unsafe sites" if mt_skipped_alignment else "")
          + ")", file=sys.stderr)


if __name__ == "__main__":
    main()
