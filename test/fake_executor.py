#!/usr/bin/env python3
"""fake_executor.py -- an SZR1 executor written from docs/FORMATS.md alone.

Stands in for suzzer-relay to prove that the brain only depends on the
published protocol, not on the relay or libcov: it dials the brain, says
HELLO for a made-up target ("fake32", ring_size 1), sends an unsolicited
INIT snapshot (id 0), then answers every INPUT according to its first byte:

    G  CRASH GUEST_FAULT, status = 0x80001234 (a PC with the top bit set);
       inputs shorter than 4 bytes fault elsewhere, status = 0x80009999
    O  CRASH ORACLE,      status = 0x2a
    H  CRASH HANG,        status = 0
    T  CRASH TIMEOUT,     status = 1000
    Z  CRASH reason 42 (unknown to every brain), status = 7
    Q  BYE instead of a reply (executor-initiated shutdown)
    *  COVERAGE kind=ITER, one bucket per distinct input byte (buckets
       0..255; the INIT snapshot uses bucket 300, which no input reaches)

Test modes: --bad-id answers every INPUT with the wrong id;
--bye-after-crash sends BYE instead of the reply to the first INPUT after
a CRASH (where the brain's minimizer probes).

Every INPUT it receives is appended (hex, one per line) to --record, so a
test can see what the brain sent, e.g. whether it minimized an input.

Usage: fake_executor.py --brain HOST:PORT --record FILE [--map-size N]
                        [--bad-id] [--bye-after-crash]
"""
import argparse
import socket
import struct
import sys

# SZR1 (docs/FORMATS.md)
MAGIC = b"SZR1"
HELLO, INPUT, COVERAGE, CRASH, BYE = 1, 2, 3, 4, 5
KIND_INIT, KIND_ITER = 1, 2
FLAG_SCHEME = 0x4
NGRAM_SHIFT = 8
GUEST_FAULT, ORACLE, HANG, TIMEOUT = 5, 6, 7, 8

REPLIES = {
    ord("G"): (GUEST_FAULT, 0x80001234),
    ord("O"): (ORACLE, 0x2a),
    ord("H"): (HANG, 0),
    ord("T"): (TIMEOUT, 1000),
    ord("Z"): (42, 7),
}


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("brain closed the connection")
        buf += chunk
    return buf


def send(s, ftype, payload=b""):
    s.sendall(struct.pack(">IB", 1 + len(payload), ftype) + payload)


def coverage(ident, gen, kind, bitmap):
    return struct.pack(">QQBI", ident, gen, kind, len(bitmap)) + bytes(bitmap)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--brain", required=True)
    ap.add_argument("--record", required=True)
    ap.add_argument("--map-size", type=int, default=512)
    ap.add_argument("--bad-id", action="store_true")
    ap.add_argument("--bye-after-crash", action="store_true")
    a = ap.parse_args()
    host, _, port = a.brain.rpartition(":")
    s = socket.create_connection((host, int(port)), timeout=30)
    rec = open(a.record, "w", buffering=1)

    s.sendall(MAGIC)
    arch = b"fake32"
    flags = FLAG_SCHEME | (1 << NGRAM_SHIFT)          # site-id, N=1, no rotate
    send(s, HELLO, struct.pack(">HHIHH", 1, flags, a.map_size, 1, len(arch)) + arch)
    init = bytearray(a.map_size)
    init[300] = 1
    send(s, COVERAGE, coverage(0, 1, KIND_INIT, init))  # unsolicited, id 0

    gen = 1
    crashed = False
    while True:
        (length,) = struct.unpack(">I", recvn(s, 4))
        body = recvn(s, length)
        ftype, payload = body[0], body[1:]
        if ftype == BYE:
            break
        if ftype != INPUT:
            continue
        ident, n = struct.unpack(">QI", payload[:12])
        data = payload[12:12 + n]
        rec.write(data.hex() + "\n")
        first = data[0] if data else None
        if a.bad_id:
            ident += 1
        if first == ord("Q") or (a.bye_after_crash and crashed):
            send(s, BYE)
            break
        if first in REPLIES:
            reason, status = REPLIES[first]
            if first == ord("G") and len(data) < 4:
                status = 0x80009999
            send(s, CRASH, struct.pack(">QBI", ident, reason, status))
            crashed = True
            continue
        gen += 1
        bm = bytearray(a.map_size)
        for b in set(data):
            bm[b] = min(255, bm[b] + 1)
        send(s, COVERAGE, coverage(ident, gen, KIND_ITER, bm))
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
