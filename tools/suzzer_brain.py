#!/usr/bin/env python3
"""suzzer_brain.py -- off-device coverage-guided fuzzing brain.

Reference "brain" for the remote fuzzing template. It listens for one
suzzer-relay connection (the relay dials in from the device), then runs a
coverage-guided loop entirely off the device:

  - mutates inputs with tools/mutate.py (Engine);
  - sends each input to the relay, which delivers it to the target daemon and
    returns one COVERAGE (or CRASH) frame;
  - folds the returned bitmap into a cumulative map, keeps inputs that reached
    new coverage in the corpus, and saves crashing inputs.

Protocol: tools/relay_proto.h. The relay decodes the shm header on the device,
so this never parses a foreign-ABI header -- it receives map_size plus raw
uint8 counters.

This is a readable reference, not a production fuzzer (no scheduler, no corpus
minimisation, no crash triage). Swap in AFL++ or your own loop as needed.

Usage:
  suzzer_brain.py --listen HOST:PORT --seeds DIR [--out DIR]
                  [--iters N] [--seed-rng N] [--accept-timeout S]
                  [--io-timeout S] [--quiet]

Runs in the foreground: start it first (backgrounded, or in another
terminal), then start suzzer-relay within --accept-timeout seconds. It exits
after the seeds plus --iters mutated inputs. A missing or empty --seeds
directory falls back to built-in seeds.
"""
import argparse
import os
import random
import socket
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutate import Engine  # noqa: E402

# ---- protocol (mirror of tools/relay_proto.h) --------------------------
SZR_MAGIC = b"SZR1"
SZR_HELLO, SZR_INPUT, SZR_COVERAGE, SZR_CRASH, SZR_BYE = 1, 2, 3, 4, 5
SLOT_INIT, SLOT_ITER, SLOT_GAP = 1, 2, 4
CRASH_EXIT, CRASH_SIGNAL, CRASH_DELIVERY, CRASH_MALFORMED = 1, 2, 3, 4


def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("relay closed the connection")
        buf += chunk
    return buf


def recv_frame(sock):
    (length,) = struct.unpack(">I", recvn(sock, 4))
    body = recvn(sock, length)
    return body[0], body[1:]        # type, payload


def send_frame(sock, ftype, payload=b""):
    sock.sendall(struct.pack(">I", len(payload) + 1) + bytes([ftype]) + payload)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="HOST:PORT to listen on")
    ap.add_argument("--seeds", required=True, help="directory of seed inputs")
    ap.add_argument("--out", default=None, help="output dir (crashes, corpus)")
    ap.add_argument("--iters", type=int, default=200, help="mutation execs")
    ap.add_argument("--seed-rng", type=int, default=0xC0FFEE)
    ap.add_argument("--accept-timeout", type=float, default=15.0,
                    help="seconds to wait for the relay to connect")
    ap.add_argument("--io-timeout", type=float, default=60.0,
                    help="seconds to wait for each relay reply (0 = forever)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    host, _, port = args.listen.rpartition(":")
    if not port.isdigit():
        sys.exit("brain: --listen must be HOST:PORT (e.g. 127.0.0.1:7000), got %r"
                 % args.listen)
    out = args.out or os.path.join(os.getcwd(), "suzzer_out")
    crash_dir = os.path.join(out, "crashes")
    os.makedirs(crash_dir, exist_ok=True)

    seeds = []
    if not os.path.isdir(args.seeds):
        print("brain: WARNING: seed directory %r does not exist; using built-in seeds"
              % args.seeds, file=sys.stderr)
    for name in (sorted(os.listdir(args.seeds)) if os.path.isdir(args.seeds) else []):
        p = os.path.join(args.seeds, name)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                seeds.append(f.read())
    if not seeds:
        seeds = [b"A", b"B", b"C"]

    def log(*a):
        if not args.quiet:
            print("brain:", *a, flush=True)

    # ---- accept one relay ----
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((host, int(port)))
    lsock.listen(1)
    lsock.settimeout(args.accept_timeout)
    # Print the bound port so a caller that passed :0 can discover it.
    log("listening on %s:%d" % (host, lsock.getsockname()[1]))
    try:
        conn, peer = lsock.accept()
    except socket.timeout:
        sys.exit("brain: no relay connected within %gs (--accept-timeout)"
                 % args.accept_timeout)
    conn.settimeout(args.io_timeout or None)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    log("relay connected from %s:%d" % peer)

    if recvn(conn, 4) != SZR_MAGIC:
        sys.exit("brain: bad magic from relay")
    ftype, payload = recv_frame(conn)
    if ftype != SZR_HELLO:
        sys.exit("brain: expected HELLO, got type %d" % ftype)
    ver, flags, map_size, ring_size, arch_len = struct.unpack(">HHIHH", payload[:12])
    arch = payload[12:12 + arch_len].decode("ascii", "replace")
    if flags & 0x4:   # SZR_HELLO_FLAG_SCHEME (relay_proto.h)
        scheme = "n=%d model=%s rotate=%d" % (
            (flags >> 8) & 0xf, "pc" if flags & 0x8 else "site",
            1 if flags & 0x10 else 0)
    else:
        scheme = "unknown"
    log("HELLO proto=%d arch=%s map_size=%d ring=%d flags=0x%x scheme=%s"
        % (ver, arch, map_size, ring_size, flags, scheme))

    cumulative = bytearray(map_size)
    rng = random.Random(args.seed_rng)
    corpus = list(seeds)

    def splice_donor():
        return rng.choice(corpus) if corpus else b""

    engine = Engine(rng, corpus=splice_donor, max_size=max(64, map_size))

    execs = new_cov = crashes = 0
    next_id = 1

    def fold(bitmap):
        """Merge bitmap into cumulative; return count of newly-set bytes."""
        newly = 0
        for i, b in enumerate(bitmap):
            if b and not cumulative[i]:
                cumulative[i] = b
                newly += 1
        return newly

    def run_one(data):
        nonlocal execs, new_cov, crashes, next_id
        ident = next_id
        next_id += 1
        send_frame(conn, SZR_INPUT, struct.pack(">QI", ident, len(data)) + data)
        ftype, payload = recv_frame(conn)
        execs += 1
        if ftype == SZR_CRASH:
            cid, reason, status = struct.unpack(">QBi", payload[:13])
            crashes += 1
            name = "crash_%06d_r%d_s%d" % (cid, reason, status)
            with open(os.path.join(crash_dir, name), "wb") as f:
                f.write(data)
            log("CRASH id=%d reason=%d status=%d (saved %s)"
                % (cid, reason, status, name))
            return
        if ftype != SZR_COVERAGE:
            log("unexpected frame type %d" % ftype)
            return
        cid, gen, kind, msz = struct.unpack(">QQBI", payload[:21])
        bitmap = payload[21:21 + msz]
        if kind != SLOT_ITER:          # only score per-request (ITER) coverage
            return
        newly = fold(bitmap)
        if newly:
            new_cov += 1
            corpus.append(data)
            log("new coverage +%d (corpus=%d) from %r" % (newly, len(corpus), data[:24]))

    try:
        # ---- baseline: run every seed once ----
        for s in seeds:
            run_one(s)
        # ---- fuzz: mutate corpus entries ----
        for _ in range(args.iters):
            base = rng.choice(corpus) if corpus else b"\n"
            run_one(engine.mutate(base))
    except socket.timeout:
        sys.exit("brain: relay sent no reply within %gs (--io-timeout)"
                 % args.io_timeout)
    except ConnectionError as e:
        sys.exit("brain: %s" % e)

    send_frame(conn, SZR_BYE)
    total = sum(1 for b in cumulative if b)
    log("done: execs=%d new_cov=%d crashes=%d corpus=%d edges=%d"
        % (execs, new_cov, crashes, len(corpus), total))
    conn.close()
    lsock.close()


if __name__ == "__main__":
    main()
