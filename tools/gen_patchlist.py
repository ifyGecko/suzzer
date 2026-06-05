#!/usr/bin/env python3
"""
gen_patchlist.py -- produce an LCV1 binary patch list for a target binary.

Per-arch behavior:
  x86_64, aarch64, arm (ARM mode), powerpc, riscv64: patch block terminators
  arm (Thumb mode):                                  patch first 2 bytes only
  mips, mips64:                                      patch block ENTRIES
                                                     (avoids branch delay slots)

Output layout matches src/config.h:
  header: magic[4]='LCV1', version=1, count, reserved
  record: u64 offset, u8 len, u8 orig[15]

Usage:
  ./gen_patchlist.py <binary> <out.lcv> [--include-pat REGEX] [--exclude-pat REGEX]
                                        [--strategy auto|entry|terminator]
"""
import argparse
import json
import re
import struct
import subprocess
import sys


def rizin(binary, cmds):
    """Run a rizin batch and return stdout."""
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
    """Return decoded instructions starting at addr."""
    return rizin_json(binary, ["aaa", f"pdj {ninstr} @ {addr}"]) or []


BRANCH_TYPES = {
    "jmp", "ujmp", "cjmp", "ucjmp", "rjmp",
    "call", "ucall", "ccall", "rcall", "icall",
    "ret",
}


def _is_branch_at(binary, addr):
    """True if the single instruction at addr is a branch/jump/call/ret.
    Used by the MIPS path to detect that addr+4 is a branch delay slot."""
    insns = get_block_insns(binary, addr, 1)
    if not insns:
        return False
    t = insns[0].get("type", "")
    return t in BRANCH_TYPES


def pick_sites(binary, fn, strategy, arch):
    """For one function, return list of (addr, size, bytes_hex) patch sites.

    Strategy:
      'terminator' -- last instruction of each basic block (the branch).
      'entry'      -- first instruction of each basic block.

    MIPS-specific: with strategy='entry', the first instruction of some
    rizin-reported blocks is the branch *delay slot* of the previous
    branch (rizin models the delay slot as the head of the next block).
    A trap fired in a delay slot reports the branch's PC, not the delay
    slot's -- so address-keyed lookup misses and we crash. We detect this
    by checking whether (block.addr - 4) is a branch, and skip insn[0]
    when it is."""
    is_mips = arch in ("mips", )  # rizin's arch name for MIPS32/64
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
                # First insn is a delay slot; use the next instruction.
                idx = 1
                if idx >= len(insns):
                    continue
            pick = insns[idx]
        else:
            pick = insns[-1]
        sites.append((int(pick["offset"]), int(pick["size"]), pick["bytes"]))
    return sites


def default_strategy(arch, bits):
    """Per-arch default for which insn in each basic block to patch.

    MIPS has branch delay slots: the last instruction of a block (in rizin's
    CFG model) can be the delay slot rather than the branch, and trapping
    in a delay slot reports the branch PC -- our address-keyed lookup
    misses. Patching the FIRST insn of each block sidesteps this entirely.

    Everything else uses block-terminator patching, which is a more
    informative coverage signal (we know the block was *fully* executed)."""
    if arch == "mips":
        return "entry"
    return "terminator"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("output")
    ap.add_argument("--include-pat", default=None,
                    help="only include functions whose name matches this regex")
    ap.add_argument("--exclude-pat", default=r"^(sym\.imp\.|sym\._init|sym\._fini|sym\.deregister|sym\.register|sym\.frame_dummy|sym\.__libc_csu)",
                    help="exclude functions whose name matches this regex")
    ap.add_argument("--strategy", choices=["auto", "entry", "terminator"],
                    default="auto",
                    help="per-block patch site selection (auto = arch default)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    inc = re.compile(args.include_pat) if args.include_pat else None
    exc = re.compile(args.exclude_pat) if args.exclude_pat else None

    info = get_bin_info(args.binary)
    baddr = info["baddr"]
    arch  = info["arch"]
    bits  = info["bits"]
    strategy = args.strategy if args.strategy != "auto" else default_strategy(arch, bits)

    # Arch-specific patch length / payload rules:
    #   x86:   min 2 bytes, max 15 (variable-length insns).
    #   arm 32-bit (ARM mode): fixed 4. Thumb mode (per-function bits=16): 2.
    #   arm 64-bit (aarch64): fixed 4.
    #   mips, ppc, riscv: fixed 4 (riscv can also be 2 if compressed insns).
    #
    # The rule we apply per record:
    #   If function bits=16 (Thumb): force len=2, truncate orig bytes to 2.
    #   Otherwise: use the instruction's natural size, capped at 15.
    if args.verbose:
        print(f"arch={arch} bits={bits} endian={info['endian']} "
              f"baddr=0x{baddr:x} strategy={strategy}", file=sys.stderr)

    fns = get_functions(args.binary, inc, exc)

    # PowerPC64 ABI: each function has a global entry point (loads TOC) and
    # a local entry point typically 8 bytes later. Rizin's analysis names the
    # global entry as dbg.<name> (only 2 insns) and the local entry as
    # fcn.<addr+8> (the actual function body). For each matched function on
    # ppc64 we also pull in the rizin-detected function at offset+8 so we
    # cover the real body.
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

            # Thumb override: regardless of rizin's reported insn size for
            # Thumb-2 (which may be 4), we patch the first 2 bytes only and
            # restore those 2 bytes. The back half of a 4-byte Thumb-2 insn
            # is never modified. rizin uses arch="arm" for both ARM32 and
            # AArch64; per-function bits=16 marks Thumb mode.
            if arch == "arm" and fn["bits"] == 16:
                size = 2
                orig = orig[:2]

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
        f.write(b"LCV1")
        f.write(struct.pack("<III", 1, len(records), 0))
        for offset, size, orig in records:
            padded = orig + b"\x00" * (15 - size)
            f.write(struct.pack("<QB15s", offset, size, padded))

    print(f"wrote {len(records)} records to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
