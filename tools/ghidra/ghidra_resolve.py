## -*- coding: utf-8 -*-
"""
ghidra_resolve.py -- shared symbol/address resolution for the Ghidra Jython
ports of the suzzer tools.  Jython 2.7 (Ghidra's bundled interpreter).

This is the Ghidra counterpart of tools/rz_resolve.py.  The resolution
logic is identical by design: both gen_patchlist_ghidra.py and
gen_boundary_ghidra.py resolve a user-supplied token (a function name or an
address) to a function entry through resolve_to_offset(), so the same name
lands on the same site in both tools -- exactly as the rizin pair does.

What differs from the rizin version:
  - There is no rizin process and no --raw/--base/--arch/--bits/--endian.
    Ghidra already imported the binary with a chosen processor, base and
    byte order, so those facts are read from `currentProgram` instead of a
    command line.  The raw-image Image class is therefore gone.
  - rizin decorates names with prefixes (sym./dbg./fcn./sym.imp.); Ghidra
    uses bare names (`main`) or namespaced ones (`ns::fn`).  _resolve_name
    keeps the prefix tries anyway -- they simply never match in Ghidra and
    do no harm -- so this file stays a line-for-line sibling of the rizin
    one and the suffix/exact behaviour is unchanged.
  - --symbols is kept (Ghidra can leave stripped functions as FUN_xxxx; a
    symbols file still names them), but the parsed names are applied WITHOUT
    a "sym." prefix, because Ghidra function names are bare.

`all_fns` is a list of dicts, each at least {"offset": int, "name": str}.
Optional "size" / "maxbound" bound address lookups just as in the rizin
version.
"""
from __future__ import print_function

import io
import os
import sys


class NotFound(ValueError):
    """The token names no function (as opposed to an ambiguous name). Lets
    multi-module callers try the next module."""


def parse_int_maybe(tok):
    """Try to parse `tok` as an integer (hex with 0x prefix, plain hex of
    >=4 chars, or decimal). Return int on success, None on failure.

    The >=4-char heuristic for unprefixed hex avoids treating short
    identifiers like 'fd' as addresses. resolve_to_offset only reaches this
    for unprefixed tokens AFTER name resolution has failed, so a function
    actually named e.g. 'cafe' resolves as a symbol; use a '0x' prefix to
    force address interpretation."""
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
    common rizin prefixes (harmless no-ops in Ghidra), then a last-dotted-
    segment suffix match. Raises ValueError only for an ambiguous suffix
    match."""
    # exact name match
    for f in all_fns:
        if f["name"] == token:
            return int(f["offset"]), f
    # common-prefix tries (kept for parity with the rizin resolver)
    for prefix in ("dbg.", "sym.", "fcn.", "sym.imp."):
        candidate = prefix + token
        for f in all_fns:
            if f["name"] == candidate:
                return int(f["offset"]), f
    # last-segment suffix match (e.g. user said 'main', match 'ns.main')
    matches = [f for f in all_fns if f["name"].rsplit(".", 1)[-1] == token]
    if len(matches) == 1:
        return int(matches[0]["offset"]), matches[0]
    if len(matches) > 1:
        names = ", ".join(m["name"] for m in matches)
        raise ValueError("ambiguous symbol '%s': matches %s" % (token, names))
    return None


def _fn_end(f):
    """Exclusive end of f's code, or None if unknown."""
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
    or past the end of the one below it (when its extent is known)."""
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
            raise NotFound("address %s is not within any known function "
                           "(past the end of %s, 0x%x-0x%x)"
                           % (token, best["name"], int(best["offset"]), end))
        print("note: address 0x%x not a function entry; using enclosing fn "
              "%s at 0x%x" % (addr, best["name"], int(best["offset"])),
              file=sys.stderr)
        return int(best["offset"]), best
    raise NotFound("address %s not within any known function" % token)


def resolve_to_offset(token, all_fns):
    """Resolve a user-supplied symbol-or-address token to a function entry
    offset and its function dict.

    Accepts:
      - Exact function name as Ghidra lists it ('main', 'parse_request',
        'ns::handler').
      - Bare name: tries the rizin-style prefixes (no-ops in Ghidra) then a
        suffix match against the last dotted segment of every function name.
      - hex address ('0x401234'), plain-hex address ('401234'), decimal.
        Addresses inside a function (not at entry) resolve to the enclosing
        function's entry, with a note printed to stderr.

    Resolution order: a '0x'-prefixed or decimal token is treated as an
    address first; every other token is resolved as a NAME first and only
    falls back to plain-hex address interpretation when no name matches.

    Raises NotFound (a ValueError) if unresolvable, ValueError if a suffix
    match is ambiguous."""
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

    raise NotFound("could not resolve '%s' to any function" % token)


# ---- --symbols support (name functions Ghidra left as FUN_xxxx) -----------

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
        lines = io.open(path, encoding="utf-8",
                        errors="replace").read().splitlines()
    except (OSError, IOError) as e:
        sys.exit("error: --symbols %s: %s" % (path, e))
    body = [l for l in lines if l.strip() and not l.lstrip().startswith("#")]
    pairs = []
    if body and "," in body[0]:
        rows = list(csv.reader(body))
        head = [c.strip().lower() for c in rows[0]]
        try:
            ni = head.index("name")
            ai = next(head.index(c) for c in ("location", "address",
                                              "entry point", "entry", "addr")
                      if c in head)
        except (ValueError, StopIteration):
            sys.exit("error: --symbols %s: CSV needs Name and Location "
                     "(or Address) columns, got %s" % (path, rows[0]))
        # Ghidra's symbol table lists data labels too; with a Type column,
        # only functions may become instrumented functions.
        ti = head.index("type") if "type" in head else None
        for r in rows[1:]:
            if ti is not None and (len(r) <= ti
                                   or r[ti].strip().lower() != "function"):
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
                sys.exit("error: --symbols %s: cannot parse line %r" % (path, l))
    out = {}
    for addr, name in pairs:
        if not name:
            continue
        cur = out.get(addr)
        if cur is None or (cur.startswith("_") and not name.startswith("_")):
            out[addr] = name
    if not out:
        sys.exit("error: --symbols %s: no code symbols found" % path)
    return out


def add_symbols_arg(ap):
    """The --symbols option, shared by both Ghidra generators.

    The rizin tools also take --raw/--base/--arch/--bits/--endian to load a
    headerless image; under Ghidra those are chosen when the blob is
    imported (Language + base address), so only --symbols remains."""
    ap.add_argument("--symbols", metavar="FILE",
                    help="name functions from FILE: `nm` output (ADDR TYPE "
                         "NAME; text symbols only), ADDR NAME lines, or a "
                         "Ghidra symbol-table CSV export (Name and Location "
                         "columns). Applied to functions Ghidra left "
                         "unnamed (FUN_xxxx) so --root/--cutoff and marker "
                         "names can find them.")


def apply_symbol_names(all_fns, symbols):
    """Rename entries in `all_fns` whose offset is named by `symbols`
    (in place); returns all_fns. Mirrors Image.name_functions() but keeps
    the bare name, since Ghidra names are undecorated."""
    if not symbols:
        return all_fns
    for f in all_fns:
        name = symbols.get(int(f.get("offset", -1)))
        if name:
            f["name"] = name
    return all_fns
