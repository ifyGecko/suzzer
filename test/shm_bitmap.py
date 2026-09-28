#!/usr/bin/env python3
"""Extract the live bitmap from a libcov shm file, using the header.

    shm_bitmap.py extract <shm> <out>   write the live bitmap to <out>
    shm_bitmap.py stats   <shm>         print "<nonzero> <sum> <max>"

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


def live_bitmap(data):
    if data[:4] != b"LCVS":
        return data
    for order in ("<", ">"):
        if struct.unpack_from(order + "H", data, 4)[0] == 1:
            break
    else:
        sys.exit("shm_bitmap: unknown header version")
    ring_size, map_size, slot_stride = struct.unpack_from(order + "HII", data, 6)
    hdr_size = len(data) - map_size - ring_size * slot_stride
    if hdr_size < 24 or hdr_size > 256:
        sys.exit(f"shm_bitmap: inconsistent header (derived size {hdr_size})")
    return data[hdr_size:hdr_size + map_size]


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("extract", "stats"):
        sys.exit(__doc__)
    with open(sys.argv[2], "rb") as f:
        bm = live_bitmap(f.read())
    if sys.argv[1] == "extract":
        with open(sys.argv[3], "wb") as f:
            f.write(bm)
    else:
        print(sum(1 for b in bm if b), sum(bm), max(bm) if bm else 0)


if __name__ == "__main__":
    main()
