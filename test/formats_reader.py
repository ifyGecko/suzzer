#!/usr/bin/env python3
"""formats_reader.py -- LCV3 / LCVB1 / LCVS readers written from docs/FORMATS.md.

An independent implementation of the published formats (it shares no code
with libcov, the generators or ring_reader.h), used by
test/run_validation_formats.sh to check the specification against what
suzzer actually writes. Each reader applies the spec's validation rules and
returns a plain dict; the CLI prints it as JSON.

  formats_reader.py lcv3 FILE      patch list
  formats_reader.py lcvb FILE      boundary file
  formats_reader.py lcvs FILE      coverage region (a file-backed snapshot)
"""
import json
import struct
import sys


class FormatError(Exception):
    pass


def need(cond, msg):
    if not cond:
        raise FormatError(msg)


# ---- LCV3 (FORMATS.md §1) ------------------------------------------------

def read_lcv3(data):
    need(len(data) >= 24, "LCV3: shorter than the 24-byte header")
    magic, version, count, threading, flags, mcount, _res, moff, msize = \
        struct.unpack_from("<4sIIBBBBII", data, 0)
    need(magic == b"LCV3", f"LCV3: bad magic {magic!r}")
    need(version == 3, f"LCV3: bad version {version}")
    need(count <= (len(data) - 24) // 14, f"LCV3: {count} records do not fit")
    need(mcount >= 1, "LCV3: module_count is 0")
    need(1 <= msize <= 4096, f"LCV3: modules_size {msize}")
    need(moff + msize <= len(data), "LCV3: name table runs past the end")
    table = data[moff:moff + msize]
    need(table[-1] == 0, "LCV3: name table not NUL-terminated")
    names = table[:-1].split(b"\0")
    need(len(names) >= mcount, "LCV3: fewer names than module_count")
    names = [n.decode() for n in names[:mcount]]
    need(all(names), "LCV3: empty module name")
    records = []
    for i in range(count):
        off, ln, midx, orig = struct.unpack_from("<QBB4s", data, 24 + 14 * i)
        need(midx < mcount, f"LCV3: record {i} module_idx {midx} >= {mcount}")
        need(ln in (2, 4), f"LCV3: record {i} len {ln}")
        need(not any(orig[ln:]), f"LCV3: record {i} orig tail not zero")
        records.append({"site_id": i, "offset": off, "len": ln,
                        "module_idx": midx, "orig": orig[:ln].hex()})
    out = {"threading": threading, "flags": flags, "modules": names,
           "records": records, "module_bases": None}
    if flags & 1:
        tab = (moff + msize + 7) & ~7
        if tab + 8 * mcount <= len(data):          # else: ignored (§1.5)
            out["module_bases"] = [struct.unpack_from("<Q", data, tab + 8 * m)[0]
                                   for m in range(mcount)]
    return out


# ---- LCVB1 (§2) -------------------------------------------------------------

def read_lcvb(data):
    need(len(data) >= 16, "LCVB1: shorter than the 16-byte header")
    magic, version, count, _flags = struct.unpack_from("<4sIII", data, 0)
    need(magic == b"LCVB", f"LCVB1: bad magic {magic!r}")
    need(version == 1, f"LCVB1: bad version {version}")
    need(count <= (len(data) - 16) // 16, f"LCVB1: {count} records do not fit")
    recs = []
    for i in range(count):
        off, kind, depth = struct.unpack_from("<QBB", data, 16 + 16 * i)
        need(kind in (0, 1), f"LCVB1: record {i} kind {kind}")
        need(depth in (0, 1), f"LCVB1: record {i} depth_filter {depth}")
        recs.append({"offset": off, "kind": "end" if kind else "begin",
                     "depth_filter": depth})
    paired = any(r["kind"] == "end" for r in recs)
    return {"mode": "paired" if paired else "begin-only", "records": recs}


# ---- LCVS (§3) --------------------------------------------------------------

SLOT_KINDS = {1: "init", 2: "iter", 4: "gap"}


def read_lcvs(data):
    need(len(data) >= 72 and data[:4] == b"LCVS", "LCVS: no LCVS header")
    for bo in ("<", ">"):                      # creator's byte order (§3)
        if struct.unpack_from(bo + "H", data, 4)[0] == 1:
            break
    else:
        raise FormatError("LCVS: version is not 1 in either byte order")
    (version, ring, msize, stride, flags, _pad, gen_cur, gen_init, boff, roff,
     dropped, opid, ostart) = struct.unpack_from(bo + "HHIIIIQQQQIII", data, 4)
    need(msize and msize & (msize - 1) == 0, f"LCVS: map_size {msize} not a power of two")
    need(boff + msize <= len(data), "LCVS: live bitmap runs past the end")
    need(roff + ring * stride <= len(data), "LCVS: ring runs past the end")
    need(stride >= 32 + msize, f"LCVS: slot_stride {stride} < 32 + map_size")
    scheme = None
    if flags & (1 << 3):
        scheme = {"model": "pc" if flags & (1 << 4) else "site",
                  "rotate": 1 if flags & (1 << 5) else 0,
                  "n": (flags >> 8) & 0xf}
    slots = []
    for i in range(ring):
        base = roff + i * stride
        sgen, tid, ns, sflags = struct.unpack_from(bo + "QQQQ", data, base)
        if sgen == 0:
            continue                            # empty / being written
        need(sgen % ring == i, f"LCVS: gen {sgen} in slot {i} of {ring}")
        need(sgen <= gen_cur, f"LCVS: slot gen {sgen} > gen_current {gen_cur}")
        bm = data[base + 32:base + 32 + msize]
        slots.append({"gen": sgen, "kind": SLOT_KINDS.get(sflags, sflags),
                      "tid": tid, "nonzero": sum(1 for b in bm if b)})
    slots.sort(key=lambda s: s["gen"])
    live = data[boff:boff + msize]
    return {"byte_order": "little" if bo == "<" else "big", "ring_size": ring,
            "map_size": msize, "slot_stride": stride, "flags": flags,
            "active": bool(flags & 1), "mt": bool(flags & 2),
            "live_empty": bool(flags & 4), "scheme": scheme,
            "gen_current": gen_cur, "gen_init": gen_init,
            "bitmap_offset": boff, "ring_offset": roff,
            "publish_dropped": dropped, "owner_pid": opid,
            "owner_start": ostart, "live_nonzero": sum(1 for b in live if b),
            "slots": slots}


READERS = {"lcv3": read_lcv3, "lcvb": read_lcvb, "lcvs": read_lcvs}


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in READERS:
        sys.exit(__doc__)
    try:
        out = READERS[sys.argv[1]](open(sys.argv[2], "rb").read())
    except FormatError as e:
        sys.exit(f"formats_reader: {e}")
    json.dump(out, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
