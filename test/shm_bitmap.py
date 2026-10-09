#!/usr/bin/env python3
"""Extract the live bitmap from a libcov shm file, using the header.

    shm_bitmap.py extract <shm> <out>   write the live bitmap to <out>
    shm_bitmap.py stats   <shm>         print "<nonzero> <sum> <max>"
    shm_bitmap.py gen     <shm>         print the header's gen_current
    shm_bitmap.py scheme  <shm>         print "n=<N> model=site|pc rotate=0|1"
                                        ("unknown" for regions from older builds)

The bitmap is not a fixed 64 KB at offset 72: the site-id model sizes it
from the patch count, and the header's size and byte order follow the
target ABI (cross runs read big-endian and 32-bit targets' files on the
host). So everything is derived from the header:

  - byte order: the u16 `version` at offset 4 is 1;
  - map_size (u32 @ 8), slot_stride (u32 @ 12), ring_size (u16 @ 6) sit
    before any 8-byte field, so their offsets don't depend on alignment;
  - the header size (= bitmap_offset) is what's left of the file after
    the bitmap and the ring (sink_shm.c: total = hdr + map + ring*stride).

A file without the "LCVS" magic is treated as a bare bitmap.
"""
import struct
import sys


def byte_order(data):
    for order in ("<", ">"):
        if struct.unpack_from(order + "H", data, 4)[0] == 1:
            return order
    sys.exit("shm_bitmap: unknown header version")


def gen_current(data):
    # u64 @ 24: the first 8-byte field, after 20 bytes of smaller ones.
    # Every supported ABI (including arm EABI and ppc32) aligns it to 8.
    if data[:4] != b"LCVS":
        sys.exit("shm_bitmap: no LCVS header")
    return struct.unpack_from(byte_order(data) + "Q", data, 24)[0]


# Header flag bits (src/boundary.h): SCHEME says the rest are valid.
FLAG_SCHEME, FLAG_MODEL_PC, FLAG_ROTATE = 1 << 3, 1 << 4, 1 << 5
NGRAM_SHIFT, NGRAM_MASK = 8, 0xf << 8


def scheme(data):
    # flags: u32 @ 16, before any 8-byte field.
    if data[:4] != b"LCVS":
        sys.exit("shm_bitmap: no LCVS header")
    flags = struct.unpack_from(byte_order(data) + "I", data, 16)[0]
    if not flags & FLAG_SCHEME:
        return "unknown"
    return "n=%d model=%s rotate=%d" % (
        (flags & NGRAM_MASK) >> NGRAM_SHIFT,
        "pc" if flags & FLAG_MODEL_PC else "site",
        1 if flags & FLAG_ROTATE else 0)


def live_bitmap(data):
    if data[:4] != b"LCVS":
        return data
    order = byte_order(data)
    ring_size, map_size, slot_stride = struct.unpack_from(order + "HII", data, 6)
    hdr_size = len(data) - map_size - ring_size * slot_stride
    if hdr_size < 24 or hdr_size > 256:
        sys.exit(f"shm_bitmap: inconsistent header (derived size {hdr_size})")
    return data[hdr_size:hdr_size + map_size]


def main():
    if len(sys.argv) >= 2 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return
    if (len(sys.argv) < 3 or sys.argv[1] not in ("extract", "stats", "gen", "scheme")
            or (sys.argv[1] == "extract" and len(sys.argv) < 4)):
        sys.exit(__doc__)
    with open(sys.argv[2], "rb") as f:
        data = f.read()
    if sys.argv[1] == "gen":
        print(gen_current(data))
        return
    if sys.argv[1] == "scheme":
        print(scheme(data))
        return
    bm = live_bitmap(data)
    if sys.argv[1] == "extract":
        with open(sys.argv[3], "wb") as f:
            f.write(bm)
    else:
        print(sum(1 for b in bm if b), sum(bm), max(bm) if bm else 0)


if __name__ == "__main__":
    main()
