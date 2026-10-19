#!/usr/bin/env python3
"""vectors_check.py -- check the conformance vectors with a second implementation.

A pure-Python implementation of the coverage bucket formula, written from
docs/FORMATS.md ("Coverage bucket formula", "Map size") and sharing no code
with src/sink.h. It replays every vector under test/vectors/ and requires
the bitmap it computes to equal expected.bin byte for byte, re-derives the
values scheme.json records (rotation amounts, LCVS scheme flags, counts),
and checks map_size.jsonl against the map-size rule.

Usage: vectors_check.py [VECTORS_DIR]      (default: test/vectors)
Exit 0 when every vector agrees.
"""
import json
import os
import struct
import sys

M64 = (1 << 64) - 1
MIX = 0xff51afd7ed558ccd
GOLDEN = 0x9E3779B97F4A7C15

# LCVS header flag bits (docs/FORMATS.md, LCVS "flags").
SHM_FLAG_SCHEME, SHM_FLAG_MODEL_PC, SHM_FLAG_ROTATE, SHM_NGRAM_SHIFT = 1 << 3, 1 << 4, 1 << 5, 8

# Map-size constants (libcov defaults).
MAP_MIN_POW2, MAP_MAX_POW2 = 12, 24


def mix64(v):
    v ^= v >> 33
    v = (v * MIX) & M64
    v ^= v >> 33
    return v


def rotation_amounts(map_size, win):
    bits = map_size.bit_length() - 1
    step = max(1, (bits - 1) // win)
    out = []
    for j in range(win):
        r = 1 + j * step
        if r >= bits:
            r = 1 + (r % (bits - 1))
        out.append(r)
    return bits, out


class Sink:
    def __init__(self, model, n, rotate, map_size, bases=()):
        self.model, self.n, self.rotate = model, n, rotate
        self.mask = map_size - 1
        self.bitmap = bytearray(map_size)
        self.win = max(1, n - 1)
        self.bits, self.rot = rotation_amounts(map_size, self.win)
        self.bases = list(bases)
        self.reset()

    def reset(self):
        self.prev = [0] * self.win

    def rotl(self, v, j):
        r, b = self.rot[j], self.bits
        return ((v << r) | (v >> (b - r))) & self.mask

    def emit_site(self, site_id):
        self._emit(site_id, mix64(site_id) & self.mask, site_id_model=True)

    def emit_pc(self, pc, module):
        off = (pc - self.bases[module]) & M64
        h = mix64(off ^ ((module * GOLDEN) & M64)) & self.mask
        self._emit(h, h, site_id_model=False)

    def _emit(self, cur, cur_win, site_id_model):
        idx = cur
        if self.n >= 2:
            for j, p in enumerate(self.prev):
                idx ^= self.rotl(p, j) if self.rotate else p
        idx &= self.mask
        if self.bitmap[idx] != 255:
            self.bitmap[idx] += 1
        if self.n >= 2:
            self.prev = [cur_win if site_id_model else cur_win >> 1] + self.prev[:-1]


def check_vector(path):
    scheme = json.load(open(os.path.join(path, "scheme.json")))
    seq = open(os.path.join(path, "sequence.bin"), "rb").read()
    expected = open(os.path.join(path, "expected.bin"), "rb").read()
    model, n, rot, size = (scheme["model"], scheme["ngram_n"], scheme["rotate"],
                           scheme["map_size"])
    errs = []
    if len(expected) != size:
        errs.append(f"expected.bin is {len(expected)} bytes, map_size {size}")
    bases = [int(b, 16) for b in scheme.get("module_bases", [])]
    sink = Sink(model, n, rot, size, bases)
    emits = resets = 0
    if model == "site":
        for (sid,) in struct.iter_unpack("<I", seq):
            if sid == 0xffffffff:
                sink.reset()
                resets += 1
            else:
                sink.emit_site(sid)
                emits += 1
    elif model == "pc":
        for pc, mod in struct.iter_unpack("<QB", seq):
            if pc == M64 and mod == 0xff:
                sink.reset()
                resets += 1
            else:
                sink.emit_pc(pc, mod)
                emits += 1
    else:
        return [f"unknown model {model!r}"]
    if bytes(sink.bitmap) != expected:
        diff = sum(1 for a, b in zip(sink.bitmap, expected) if a != b)
        errs.append(f"bitmap differs in {diff} bucket(s)")
    flags = (SHM_FLAG_SCHEME | (SHM_FLAG_MODEL_PC if model == "pc" else 0)
             | (SHM_FLAG_ROTATE if rot else 0) | (n << SHM_NGRAM_SHIFT))
    want = {"emits": emits, "resets": resets,
            "nonzero": sum(1 for b in sink.bitmap if b),
            "saturated": sum(1 for b in sink.bitmap if b == 255),
            "lcvs_scheme_flags": "0x%x" % flags}
    if rot:
        want["map_bits"], want["rot_amounts"] = sink.bits, sink.rot
    for k, v in want.items():
        if scheme.get(k) != v:
            errs.append(f"scheme.json {k}={scheme.get(k)!r}, computed {v!r}")
    return errs


def next_pow2(v):
    p = 1
    while p < v:
        p <<= 1
    return p


def map_size_for(n_sites, n):
    fudge = 2 if n <= 1 else 16 << (n - 2)
    n_sites = max(1, n_sites)
    sz = min(next_pow2(n_sites * fudge), 1 << MAP_MAX_POW2)
    return max(sz, 1 << MAP_MIN_POW2, next_pow2(n_sites))


def check_map_sizes(path):
    errs, seen = [], set()
    for line in open(path):
        row = json.loads(line)
        n = row["n"]
        seen.add(n)
        for sites, size in row["sizes"]:
            if map_size_for(sites, n) != size:
                errs.append(f"N={n} n_sites={sites}: file {size}, "
                            f"rule {map_size_for(sites, n)}")
    if seen != set(range(1, 9)):
        errs.append(f"map_size.jsonl covers N={sorted(seen)}, want 1..8")
    return errs


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "vectors")
    dirs = sorted(d for d in os.listdir(root)
                  if os.path.isfile(os.path.join(root, d, "scheme.json")))
    if not dirs:
        sys.exit(f"vectors_check: no vectors under {root}")
    bad = 0
    for d in dirs:
        errs = check_vector(os.path.join(root, d))
        for e in errs:
            print(f"FAIL {d}: {e}")
        bad += bool(errs)
    errs = check_map_sizes(os.path.join(root, "map_size.jsonl"))
    for e in errs:
        print(f"FAIL map_size.jsonl: {e}")
    bad += bool(errs)
    if bad:
        sys.exit(f"vectors_check: {bad} failure(s)")
    print(f"vectors_check: {len(dirs)} vectors and the map-size rule agree "
          f"with the Python implementation")


if __name__ == "__main__":
    main()
