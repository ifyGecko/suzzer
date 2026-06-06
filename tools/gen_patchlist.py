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

Output layout matches src/config.h:
  LCV2 header: magic[4]='LCV2', version=2, count, threading, flags, reserved
  record:      u64 offset, u8 len, u8 orig[15]

Usage:
  ./gen_patchlist.py <binary> <out.lcv> [--include-pat REGEX] [--exclude-pat REGEX]
                                        [--strategy auto|entry|terminator]
                                        [--threading st|mt]
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
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

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
