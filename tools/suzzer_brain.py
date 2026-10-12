#!/usr/bin/env python3
"""suzzer_brain.py -- off-device coverage-guided fuzzing brain.

Reference "brain" for the remote fuzzing template, and a worked example of a
*strong-by-default* coverage-guided loop. The relay (tools/suzzer-relay.c)
dials in from the device; everything below runs off-device:

  - mutates inputs with tools/mutate.py (Engine);
  - sends each input to the relay, which delivers it to the target daemon and
    returns one COVERAGE (or CRASH) frame;
  - folds the returned bitmap into a cumulative map, keeps inputs that reached
    new coverage, and saves + triages crashing inputs.

What makes this a fuzzing setup rather than a coverage dump (copy these
choices; do not strip them back out):

  * Runs **until you stop it** (Ctrl-C / SIGTERM). `--iters N` caps the run
    only if you ask; the default (0) is an open-ended campaign.
  * Keeps a **disk-backed corpus** under <out>/corpus and **reloads it on
    start**, so a restart resumes the campaign instead of throwing it away.
  * Saves each crash as the **full input plus a .info sidecar** (reason,
    status, size, hex) so it can be replayed, and **deduplicates** by crash
    signature so one bug does not fill the directory with hundreds of copies.
  * **Minimizes** a newly-found crash (bounded block-dropping) before saving.
  * Default `--max-size` is 64 KB -- a real input budget, not a 1 KB stub.
    (The 64 KB is an input-size cap; it is unrelated to the coverage map size.)

Pair it with the heap oracle: start the relay with libdemalloc co-loaded in
its --libcov argument (a colon list), so heap overflows/UAFs that would die
silently become visible CRASH frames.

Protocol: tools/relay_proto.h. The relay decodes the shm header on the device,
so this never parses a foreign-ABI header -- it receives map_size plus raw
uint8 counters.

Usage:
  suzzer_brain.py --listen HOST:PORT --seeds DIR [--out DIR]
                  [--iters N] [--max-size N] [--no-minimize]
                  [--seed-rng N] [--accept-timeout S] [--io-timeout S] [--quiet]

Start it first (backgrounded, or in another terminal), then start
suzzer-relay within --accept-timeout seconds. A missing or empty --seeds
directory falls back to built-in seeds (plus any resumed corpus).
"""
import argparse
import hashlib
import json
import os
import random
import signal
import socket
import struct
import sys
import time

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
    ap.add_argument("--out", default=None,
                    help="output dir (holds crashes/ and the resumable corpus/)")
    ap.add_argument("--iters", type=int, default=0,
                    help="stop after N mutated execs (0 = run until stopped)")
    ap.add_argument("--max-size", type=int, default=65536,
                    help="max mutated input bytes (default 65536; an input "
                         "budget, not a protocol limit -- do not shrink to ~1KB)")
    ap.add_argument("--no-minimize", dest="minimize", action="store_false",
                    help="skip crash minimization (on by default)")
    ap.add_argument("--seed-rng", type=int, default=0xC0FFEE)
    ap.add_argument("--accept-timeout", type=float, default=15.0,
                    help="seconds to wait for the relay to connect")
    ap.add_argument("--io-timeout", type=float, default=60.0,
                    help="seconds to wait for each relay reply (0 = forever)")
    ap.add_argument("--status-file",
                    help="append a JSON-lines status feed here for a live "
                         "status board (watch with tools/status_tui.py --input)")
    ap.add_argument("--status-interval", type=float, default=1.0,
                    help="seconds between status snapshots (default 1.0)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    host, _, port = args.listen.rpartition(":")
    if not port.isdigit():
        sys.exit("brain: --listen must be HOST:PORT (e.g. 127.0.0.1:7000), got %r"
                 % args.listen)
    out = args.out or os.path.join(os.getcwd(), "suzzer_out")
    crash_dir = os.path.join(out, "crashes")
    corpus_dir = os.path.join(out, "corpus")
    os.makedirs(crash_dir, exist_ok=True)
    os.makedirs(corpus_dir, exist_ok=True)

    def log(*a):
        if not args.quiet:
            print("brain:", *a, flush=True)

    # ---- load seeds, and RESUME any previously-saved corpus --------------
    def load_dir(d):
        out_list = []
        for name in (sorted(os.listdir(d)) if os.path.isdir(d) else []):
            p = os.path.join(d, name)
            if os.path.isfile(p) and not name.endswith(".info"):
                with open(p, "rb") as f:
                    out_list.append(f.read())
        return out_list

    if not os.path.isdir(args.seeds):
        print("brain: WARNING: seed directory %r does not exist; using built-in seeds"
              % args.seeds, file=sys.stderr)
    seeds = load_dir(args.seeds)
    resumed = load_dir(corpus_dir)
    if resumed:
        log("resumed %d inputs from %s" % (len(resumed), corpus_dir))
    # de-dup by content so reload is idempotent
    seen_inputs = set()
    corpus = []
    for data in seeds + resumed:
        h = hashlib.sha1(data).digest()
        if h not in seen_inputs:
            seen_inputs.add(h)
            corpus.append(data)
    if not corpus:
        corpus = [b"A", b"B", b"C"]

    def save_corpus_input(data):
        """Persist a new-coverage input so the campaign is resumable."""
        h = hashlib.sha1(data).hexdigest()
        if h in save_corpus_input.seen:
            return
        save_corpus_input.seen.add(h)
        with open(os.path.join(corpus_dir, "cov_%s" % h[:16]), "wb") as f:
            f.write(data)
    save_corpus_input.seen = set(hashlib.sha1(d).hexdigest() for d in corpus)

    # ---- stop cleanly on Ctrl-C / SIGTERM (campaign state is on disk) ----
    stop = {"flag": False}

    def _stop(_signum, _frame):
        stop["flag"] = True
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

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
        ngram = (flags >> 8) & 0xf
        scheme = "n=%d model=%s rotate=%d" % (
            ngram, "pc" if flags & 0x8 else "site",
            1 if flags & 0x10 else 0)
        if ngram < 3:
            log("NOTE: coverage scheme is n=%d; for fuzzing rebuild libcov with "
                "-DLIBCOV_NGRAM_N=3 -DLIBCOV_NGRAM_ROTATE=1 (path-sensitive)" % ngram)
    else:
        scheme = "unknown"
    log("HELLO proto=%d arch=%s map_size=%d ring=%d flags=0x%x scheme=%s"
        % (ver, arch, map_size, ring_size, flags, scheme))

    cumulative = bytearray(map_size)
    rng = random.Random(args.seed_rng)

    def splice_donor():
        return rng.choice(corpus) if corpus else b""

    engine = Engine(rng, corpus=splice_donor, max_size=args.max_size)

    execs = new_cov = crashes = 0
    crash_sigs = {}        # (reason, status) -> count; the dedup key
    next_id = [1]

    # ---- optional JSON-lines status feed (for tools/status_tui.py) -------
    start = time.monotonic()
    status_fp = open(args.status_file, "a", buffering=1) if args.status_file else None
    last_status = [0.0]

    def emit_status(finished=False):
        if not status_fp:
            return
        el = time.monotonic() - start
        edges = sum(1 for b in cumulative if b)
        status_fp.write(json.dumps({
            "t": round(el, 1), "execs": execs,
            "execs_per_sec": round(execs / el, 1) if el > 0 else 0.0,
            "corpus": len(corpus), "edges": edges, "map_size": map_size,
            "new_edges": edges, "crashes": crashes,
            "crashes_unique": len(crash_sigs), "stage": "havoc + splice",
            "finished": finished,
            "config": {"arch": arch, "max_size": args.max_size,
                       "minimize": str(bool(args.minimize))},
        }) + "\n")

    def emit_event(kind, msg, edges=None):
        if not status_fp:
            return
        ev = {"kind": kind, "msg": msg}
        if edges is not None:
            ev["edges"] = edges
        status_fp.write(json.dumps({"event": ev}) + "\n")

    def maybe_status():
        now = time.monotonic()
        if now - last_status[0] >= args.status_interval:
            emit_status()
            last_status[0] = now

    def fold(bitmap):
        """Merge bitmap into cumulative; return count of newly-set bytes."""
        newly = 0
        for i, b in enumerate(bitmap):
            if b and not cumulative[i]:
                cumulative[i] = b
                newly += 1
        return newly

    def probe(data):
        """Send one input, return a parsed result with no accounting:
        ('crash', reason, status) | ('iter', bitmap) | ('other', None)."""
        ident = next_id[0]
        next_id[0] += 1
        send_frame(conn, SZR_INPUT, struct.pack(">QI", ident, len(data)) + data)
        ftype, payload = recv_frame(conn)
        if ftype == SZR_CRASH:
            _cid, reason, status = struct.unpack(">QBi", payload[:13])
            return ("crash", reason, status)
        if ftype != SZR_COVERAGE:
            return ("other", None)
        _cid, _gen, kind, msz = struct.unpack(">QQBI", payload[:21])
        if kind != SLOT_ITER:      # only score per-request (ITER) coverage
            return ("other", None)
        return ("iter", payload[21:21 + msz])

    def minimize(data, reason):
        """Bounded block-dropping: shrink `data` while it still crashes with
        the same reason. A readable tmin, not an optimal one."""
        if not args.minimize or len(data) <= 1:
            return data
        best = data
        chunk = max(1, len(best) // 2)
        budget = 200                      # cap re-sends so minimize stays cheap
        while chunk >= 1 and budget > 0:
            i = 0
            while i < len(best) and budget > 0:
                cand = best[:i] + best[i + chunk:]
                budget -= 1
                if cand and probe(cand)[:2] == ("crash", reason):
                    best = cand           # drop kept the crash
                else:
                    i += chunk
            chunk //= 2
        return best

    def save_crash(data, reason, status):
        nonlocal crashes
        crashes += 1
        sig = (reason, status)
        n = crash_sigs.get(sig, 0) + 1
        crash_sigs[sig] = n
        if n > 1:                         # already have this bug -> don't flood
            log("CRASH id=%d reason=%d status=%d dup (count=%d, not saved)"
                % (crashes, reason, status, n))
            return
        data = minimize(data, reason)
        name = "crash_r%d_s%d_%s" % (reason, status,
                                     hashlib.sha1(data).hexdigest()[:12])
        with open(os.path.join(crash_dir, name), "wb") as f:
            f.write(data)
        with open(os.path.join(crash_dir, name + ".info"), "w") as f:
            f.write("reason=%d\nstatus=%d\nlen=%d\nsig=r%d/s%d\nhex=%s\n"
                    % (reason, status, len(data), reason, status, data.hex()))
        log("CRASH id=%d reason=%d status=%d NEW len=%d (saved %s)"
            % (crashes, reason, status, len(data), name))
        emit_event("crash", "r%d/s%d %s" % (reason, status, name))

    def run_one(data):
        nonlocal execs, new_cov
        kind, a, b = _unpack3(probe(data))
        execs += 1
        if kind == "crash":
            save_crash(data, a, b)
            return
        if kind == "iter":
            newly = fold(a)
            if newly:
                new_cov += 1
                corpus.append(data)
                save_corpus_input(data)
                log("new coverage +%d (corpus=%d) from %r"
                    % (newly, len(corpus), data[:24]))
                emit_event("find", "corpus=%d" % len(corpus), edges=newly)

    try:
        # ---- baseline: run the resumed corpus once ----
        emit_status()
        for s in list(corpus):
            if stop["flag"]:
                break
            run_one(s)
            maybe_status()
        # ---- fuzz: mutate corpus entries until stopped (or --iters) ----
        mutated = 0
        while not stop["flag"]:
            if args.iters and mutated >= args.iters:
                break
            base = rng.choice(corpus) if corpus else b"\n"
            run_one(engine.mutate(base))
            mutated += 1
            maybe_status()
    except socket.timeout:
        sys.exit("brain: relay sent no reply within %gs (--io-timeout)"
                 % args.io_timeout)
    except ConnectionError as e:
        sys.exit("brain: %s" % e)

    try:
        send_frame(conn, SZR_BYE)
    except OSError:
        pass
    total = sum(1 for b in cumulative if b)
    log("done: execs=%d new_cov=%d crashes=%d (unique=%d) corpus=%d edges=%d"
        % (execs, new_cov, crashes, len(crash_sigs), len(corpus), total))
    emit_status(finished=True)
    if status_fp:
        status_fp.close()
    conn.close()
    lsock.close()


def _unpack3(t):
    """Normalize a 2- or 3-tuple probe() result to (kind, a, b)."""
    if len(t) == 3:
        return t
    return (t[0], t[1], None)


if __name__ == "__main__":
    main()
