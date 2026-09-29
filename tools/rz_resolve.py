#!/usr/bin/env python3
"""
rz_resolve.py -- shared symbol/address resolution for the suzzer tools.

Both gen_patchlist.py and gen_boundary.py resolve a user-supplied token
(a function name or an address) to a rizin function entry. Keeping the
logic here means the same name resolves to the same site in both tools --
previously each had its own resolver and, e.g., a bare `main` or a
suffix-only name could land differently.

`all_fns` is a list of dicts, each at least {"offset": int, "name": str}.
Optional "size" / "maxbound" (from aflj) bound address lookups: an address
past the end of the function below it is rejected instead of silently
landing in whatever function happens to come last.
"""

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
