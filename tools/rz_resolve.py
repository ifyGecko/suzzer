#!/usr/bin/env python3
"""
rz_resolve.py -- shared symbol/address resolution for the suzzer tools.

Both gen_patchlist.py and gen_boundary.py resolve a user-supplied token
(a function name or an address) to a rizin function entry. Keeping the
logic here means the same name resolves to the same site in both tools --
previously each had its own resolver and, e.g., a bare `main` or a
suffix-only name could land differently.

It also holds the raw-image support both generators share (Image,
add_image_args, load_symbols): the --raw/--base/--arch/--bits/--endian
options and the --symbols file that names functions in an image without
symbols.

`all_fns` is a list of dicts, each at least {"offset": int, "name": str}.
Optional "size" / "maxbound" (from aflj) bound address lookups: an address
past the end of the function below it is rejected instead of silently
landing in whatever function happens to come last.
"""

import os
import sys


class NotFound(ValueError):
    """The token names no function (as opposed to an ambiguous name). Lets
    multi-module callers try the next module."""


def parse_int_maybe(tok):
    """Try to parse `tok` as an integer (hex with 0x prefix, plain hex of
    >=4 chars, or decimal). Return int on success, None on failure.

    The >=4-char heuristic for unprefixed hex avoids treating short
    identifiers like 'fd' as addresses. Note that resolve_to_offset only
    reaches this for unprefixed tokens AFTER name resolution has failed,
    so a function actually named e.g. 'cafe' resolves as a symbol; use a
    '0x' prefix to force address interpretation."""
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


def _resolve_name(token, all_fns):
    """Return (offset, fn) for a name match, or None. Tries exact, then the
    common rizin prefixes, then a last-dotted-segment suffix match. Raises
    ValueError only for an ambiguous suffix match."""
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
    return None


def _fn_end(f):
    """Exclusive end of f's code, or None if aflj gave no size."""
    ends = []
    size = int(f.get("size") or 0)
    if size > 0:
        ends.append(int(f["offset"]) + size)
    maxbound = int(f.get("maxbound") or 0)
    if maxbound > int(f["offset"]):
        ends.append(maxbound)   # split functions (.cold parts) reach further
    return max(ends) if ends else None


def _resolve_addr(addr, token, all_fns):
    """Return (offset, fn) for an address, resolving an in-function address
    to the enclosing function's entry (with a stderr note). Raises NotFound
    if the address is not within any known function -- below the first one,
    or past the end of the one below it (when its size is known)."""
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
        end = _fn_end(best)
        if end is not None and addr >= end:
            raise NotFound(f"address {token} is not within any known function "
                           f"(past the end of {best['name']}, "
                           f"0x{int(best['offset']):x}-0x{end:x})")
        print(f"note: address 0x{addr:x} not a function entry; "
              f"using enclosing fn {best['name']} at 0x{int(best['offset']):x}",
              file=sys.stderr)
        return int(best["offset"]), best
    raise NotFound(f"address {token} not within any known function")


def resolve_to_offset(token, all_fns):
    """Resolve a user-supplied symbol-or-address token to a function entry
    offset and its rizin function dict.

    Accepts:
      - Exact rizin function name from aflj ('dbg.main', 'sym.classify').
      - Bare name: tries 'dbg.', 'sym.', 'fcn.', 'sym.imp.' prefixes,
        then a suffix match against the last dotted segment of every
        function name.
      - hex address ('0x401234'), plain-hex address ('401234'), decimal.
        Addresses inside a function (not at entry) resolve to the
        enclosing function's entry, with a note printed to stderr.

    Resolution order: a '0x'-prefixed or decimal token is treated as an
    address first; every other token is resolved as a NAME first and only
    falls back to plain-hex address interpretation when no name matches.
    That way a function literally named 'beef'/'cafe' resolves as a symbol;
    use a '0x' prefix to force the address reading.

    Raises NotFound (a ValueError) if unresolvable, ValueError if a suffix
    match is ambiguous.
    """
    s = token.strip()
    # Explicit address forms bind as addresses first.
    if s.startswith(("0x", "0X")) or s.isdigit():
        addr = parse_int_maybe(s)
        if addr is not None:
            return _resolve_addr(addr, token, all_fns)

    # Otherwise prefer a name match; fall back to a plain-hex address.
    hit = _resolve_name(token, all_fns)
    if hit is not None:
        return hit

    addr = parse_int_maybe(s)
    if addr is not None:
        return _resolve_addr(addr, token, all_fns)

    raise NotFound(f"could not resolve '{token}' to any function")


# ---- raw images (bootloaders, RTOS blobs): shared by both generators ------

class Image:
    """How to open the positional binary in rizin, and what to tell the
    generators about it that rizin can't know for a raw image.

    For an ELF (raw=False) only the optional symbols apply. For a raw image
    every fact rizin would read from ELF headers comes from the command line
    instead: --base is where the image is loaded (and module 0's link base
    in the patch list), --arch/--bits/--endian pick the disassembler."""

    def __init__(self, raw=False, base=None, arch=None, bits=None,
                 endian=None, symbols=None):
        self.raw, self.base, self.arch = raw, base, arch
        self.bits, self.endian = bits, endian
        self.symbols = symbols or {}          # addr -> name (no rizin prefix)

    def rizin_flags(self):
        """rizin command-line flags that load the image."""
        if not self.raw:
            return []
        return ["-m", "0x%x" % self.base, "-a", self.arch, "-b", str(self.bits),
                "-E", self.endian]

    def post_aaa(self):
        """Commands to run right after `aaa`: make sure every symbol from
        --symbols is an analysed function (a no-op where one exists)."""
        return ["af @ 0x%x" % a for a in sorted(self.symbols)]

    def info(self):
        """The ij-like facts for a raw image (None for an ELF)."""
        if not self.raw:
            return None
        return {"arch": self.arch, "bits": self.bits,
                "endian": "BE" if self.endian == "big" else "LE",
                "baddr": self.base}

    def name_functions(self, fns):
        """Rename analysed functions that start at a --symbols address to
        sym.NAME (in place); returns fns."""
        for f in fns:
            name = self.symbols.get(int(f.get("offset", -1)))
            if name:
                f["name"] = "sym." + name
        return fns


def add_image_args(ap):
    """The raw-image / symbols options, shared by both generators."""
    g = ap.add_argument_group(
        "raw images",
        "Analyse a raw binary (bootloader, RTOS image, flash dump) instead of "
        "an ELF. rizin is given -m BASE -a ARCH -b BITS -E ENDIAN; BASE is "
        "also module 0's link base in the patch list, so offsets are "
        "address - BASE.")
    g.add_argument("--raw", action="store_true",
                   help="the binary is a raw image (needs --base, --arch, "
                        "--bits, --endian)")
    g.add_argument("--base", type=lambda s: int(s, 0), metavar="ADDR",
                   help="load address of the raw image (e.g. 0x80010000)")
    g.add_argument("--arch", metavar="ARCH",
                   help="rizin arch name: mips, arm, riscv, ppc, x86, ...")
    g.add_argument("--bits", type=int, choices=[16, 32, 64])
    g.add_argument("--endian", choices=["big", "little"])
    g.add_argument("--symbols", metavar="FILE",
                   help="name functions from FILE: `nm` output (ADDR TYPE "
                        "NAME; text symbols only), ADDR NAME lines, or a "
                        "Ghidra symbol-table CSV export (Name and Location "
                        "columns). Names become sym.NAME, for --root, "
                        "--cutoff and marker names. Works for ELFs too")


def image_from_args(ap, args):
    """Validate the raw-image options and build the Image (or ap.error)."""
    raw_opts = {"--base": args.base, "--arch": args.arch, "--bits": args.bits,
                "--endian": args.endian}
    if args.raw:
        missing = [k for k, v in raw_opts.items() if v is None]
        if missing:
            ap.error("--raw needs " + ", ".join(missing))
    else:
        given = [k for k, v in raw_opts.items() if v is not None]
        if given:
            ap.error(", ".join(given) + " need --raw")
    syms = load_symbols(args.symbols) if args.symbols else {}
    if args.raw and syms:
        # Only addresses inside the image can be functions of it.
        try:
            end = args.base + os.path.getsize(args.binary)
        except OSError:
            end = None
        if end is not None:
            syms = {a: n for a, n in syms.items() if args.base <= a < end}
            if not syms:
                sys.exit(f"error: --symbols {args.symbols}: no symbol falls inside "
                         f"the image (0x{args.base:x}-0x{end:x}); is --base right?")
    return Image(args.raw, args.base, args.arch, args.bits, args.endian, syms)


# nm symbol types that name code.
_NM_CODE_TYPES = set("TtWw")


def _parse_addr(tok):
    tok = tok.strip()
    if ":" in tok:                      # Ghidra "ram:80010000"
        space, tok = tok.rsplit(":", 1)
        if space.upper() == "EXTERNAL":  # imports: no address in the image
            raise ValueError(tok)
    if tok.lower().startswith("0x"):
        tok = tok[2:]
    return int(tok, 16)


def load_symbols(path):
    """Parse a symbols file into {addr: name}. Formats (detected per file):
      - Ghidra symbol-table CSV export: a header row with a Name column and
        a Location / Address / Entry Point column (with a Type column, only
        Function rows are kept);
      - `nm` output: ADDR TYPE NAME (only code types T t W w are kept;
        undefined symbols, which have no address, are skipped);
      - ADDR NAME or NAME ADDR per line.
    Where several names share an address the first one not starting with
    '_' wins (else the first). Blank lines and '#' comments are skipped."""
    import csv

    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError as e:
        sys.exit(f"error: --symbols {path}: {e}")
    body = [l for l in lines if l.strip() and not l.lstrip().startswith("#")]
    pairs = []
    if body and "," in body[0]:
        rows = list(csv.reader(body))
        head = [c.strip().lower() for c in rows[0]]
        try:
            ni = head.index("name")
            ai = next(head.index(c) for c in ("location", "address", "entry point",
                                              "entry", "addr") if c in head)
        except (ValueError, StopIteration):
            sys.exit(f"error: --symbols {path}: CSV needs Name and Location "
                     f"(or Address) columns, got {rows[0]}")
        # Ghidra's symbol table lists data labels too; with a Type column,
        # only functions may become instrumented functions.
        ti = head.index("type") if "type" in head else None
        for r in rows[1:]:
            if ti is not None and (len(r) <= ti or r[ti].strip().lower() != "function"):
                continue
            if len(r) > max(ni, ai):
                try:
                    pairs.append((_parse_addr(r[ai]), r[ni].strip()))
                except ValueError:
                    pass                 # External/no-address rows
    else:
        for l in body:
            f = l.split()
            try:
                if len(f) >= 3 and len(f[1]) == 1:
                    if f[1] in _NM_CODE_TYPES:
                        pairs.append((_parse_addr(f[0]), f[2]))
                elif len(f) == 2 and len(f[0]) == 1 and f[0].isalpha():
                    continue              # nm: undefined (U, w, v): no address
                elif len(f) == 2:
                    try:
                        pairs.append((_parse_addr(f[0]), f[1]))
                    except ValueError:
                        pairs.append((_parse_addr(f[1]), f[0]))
            except ValueError:
                sys.exit(f"error: --symbols {path}: cannot parse line {l!r}")
    out = {}
    for addr, name in pairs:
        if not name:
            continue
        cur = out.get(addr)
        if cur is None or (cur.startswith("_") and not name.startswith("_")):
            out[addr] = name
    if not out:
        sys.exit(f"error: --symbols {path}: no code symbols found")
    return out
