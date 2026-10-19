#!/usr/bin/env python3
"""suzzer_brain.py -- off-device coverage-guided fuzzing brain.

Reference "brain" for the remote fuzzing template, and a worked example of a
*strong-by-default* coverage-guided loop. An executor dials in -- normally
suzzer-relay (tools/suzzer-relay.c) on the device, but any program that
speaks SZR1 (docs/FORMATS.md) will do; everything below runs off-device:

  - mutates inputs with tools/mutate.py (Engine);
  - sends each input to the executor, which runs it (suzzer-relay: delivers
    it to the target daemon) and returns one COVERAGE (or CRASH) frame;
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
    Hangs and timeouts (an executor's HANG / TIMEOUT reasons) go to
    <out>/hangs, counted apart from crashes; every distinct hang input is
    kept (up to --max-hangs), since (reason, status) says little about one.
    A finding is written before it is minimized, so it survives a lost
    executor.
  * **Minimizes** a newly-found crash (bounded block-dropping) before saving.
    Not hangs/timeouts: every probe of one costs a full timeout
    (--minimize-timeouts opts in).
  * Default `--max-size` is 64 KB -- a real input budget, not a 1 KB stub.
    (The 64 KB is an input-size cap; it is unrelated to the coverage map size.)

Pair it with the heap oracle: start the relay with libdemalloc co-loaded in
its --libcov argument (a colon list), so heap overflows/UAFs that would die
silently become visible CRASH frames.

Protocol: SZR1, specified in docs/FORMATS.md (constants in src/lcv_formats.h).
The executor decodes any shm header on its side, so this never parses a
foreign-ABI header -- it receives map_size plus raw uint8 counters. Crash
reasons it does not know are kept as opaque crashes, keyed by (reason, status).

Usage:
  suzzer_brain.py --listen HOST:PORT --seeds DIR [--out DIR]
                  [--iters N] [--max-size N] [--no-minimize]
                  [--minimize-timeouts]
                  [--seed-rng N] [--accept-timeout S] [--hello-timeout S]
                  [--io-timeout S] [--quiet]

Start it first (backgrounded, or in another terminal), then start the
executor (e.g. suzzer-relay) within --accept-timeout seconds. A missing or
empty --seeds directory falls back to built-in seeds (plus any resumed corpus).
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

# ---- protocol (mirror of src/lcv_formats.h, SZR1 section) -------------
SZR_MAGIC = b"SZR1"
SZR_HELLO, SZR_INPUT, SZR_COVERAGE, SZR_CRASH, SZR_BYE = 1, 2, 3, 4, 5
SLOT_INIT, SLOT_ITER, SLOT_GAP = 1, 2, 4
CRASH_EXIT, CRASH_SIGNAL, CRASH_DELIVERY, CRASH_MALFORMED = 1, 2, 3, 4
CRASH_GUEST_FAULT, CRASH_ORACLE, CRASH_HANG, CRASH_TIMEOUT = 5, 6, 7, 8
HELLO_ARCH_MAX = 64
SZR_PROTO_VERSION = 1
SZR_FRAME_MAX = 64 << 20          # suzzer-relay's limit (FORMATS.md 4.1)
SZR_HELLO_HDR_LEN, SZR_COVERAGE_HDR_LEN, SZR_CRASH_LEN = 12, 21, 13

CRASH_NAMES = {
    CRASH_EXIT: "EXIT", CRASH_SIGNAL: "SIGNAL", CRASH_DELIVERY: "DELIVERY",
    CRASH_MALFORMED: "MALFORMED", CRASH_GUEST_FAULT: "GUEST_FAULT",
    CRASH_ORACLE: "ORACLE", CRASH_HANG: "HANG", CRASH_TIMEOUT: "TIMEOUT",
}
# status is a PC / oracle id / cause code for these: shown in hex.
HEX_STATUS = (CRASH_GUEST_FAULT, CRASH_ORACLE)
# No forward progress / budget exceeded: saved under hangs/, not crashes/.
HANG_REASONS = (CRASH_HANG, CRASH_TIMEOUT)


def crash_name(reason):
    """Symbolic name of a crash reason; unknown ones stay opaque ('r<N>')."""
    return CRASH_NAMES.get(reason, "r%d" % reason)


def fmt_status(reason, status):
    if reason in HEX_STATUS:
        return "0x%x" % (status & 0xffffffff)
    return "%d" % status


class ExecutorBye(Exception):
    """The executor sent BYE: a clean end of the session."""


def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("executor closed the connection")
        buf += chunk
    return buf


class ProtocolError(Exception):
    """The executor broke the SZR1 framing or a frame's layout."""


def recv_frame(sock):
    (length,) = struct.unpack(">I", recvn(sock, 4))
    # length counts the type byte, so 0 is not a frame; past the limit the
    # stream is most likely out of sync (FORMATS.md 4.1).
    if length < 1 or length > SZR_FRAME_MAX + 1:
        raise ProtocolError("frame length %d (must be 1..%d)" % (length, SZR_FRAME_MAX + 1))
    body = recvn(sock, length)
    return body[0], body[1:]        # type, payload


def send_frame(sock, ftype, payload=b""):
    sock.sendall(struct.pack(">I", len(payload) + 1) + bytes([ftype]) + payload)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="HOST:PORT to listen on")
    ap.add_argument("--seeds", required=True, help="directory of seed inputs")
    ap.add_argument("--out", default=None,
                    help="output dir (holds crashes/, hangs/ and the resumable "
                         "corpus/)")
    ap.add_argument("--iters", type=int, default=0,
                    help="stop after N mutated execs (0 = run until stopped)")
    ap.add_argument("--max-size", type=int, default=65536,
                    help="max mutated input bytes (default 65536; an input "
                         "budget, not a protocol limit -- do not shrink to ~1KB)")
    ap.add_argument("--no-minimize", dest="minimize", action="store_false",
                    help="skip crash minimization (on by default)")
    ap.add_argument("--minimize-timeouts", action="store_true",
                    help="also minimize HANG/TIMEOUT inputs (off by default: "
                         "every probe costs the executor a full timeout)")
    ap.add_argument("--max-hangs", type=int, default=64,
                    help="save at most N distinct HANG/TIMEOUT inputs "
                         "(default 64)")
    ap.add_argument("--seed-rng", type=int, default=0xC0FFEE)
    ap.add_argument("--accept-timeout", type=float, default=15.0,
                    help="seconds to wait for the executor (e.g. "
                         "suzzer-relay) to connect")
    ap.add_argument("--hello-timeout", type=float, default=600.0,
                    help="seconds to wait for the executor's HELLO once it has "
                         "connected (0 = forever; default 600: an emulator may "
                         "boot its firmware before it says HELLO)")
    ap.add_argument("--io-timeout", type=float, default=60.0,
                    help="seconds to wait for each executor reply (0 = forever)")
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
    hang_dir = os.path.join(out, "hangs")
    corpus_dir = os.path.join(out, "corpus")
    os.makedirs(crash_dir, exist_ok=True)
    os.makedirs(hang_dir, exist_ok=True)
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

    # ---- accept one executor ----
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((host, int(port)))
    lsock.listen(1)
    lsock.settimeout(args.accept_timeout)
    # Print the bound port so a caller that passed :0 can discover it.
    listen_addr = "%s:%d" % (host, lsock.getsockname()[1])
    log("listening on %s" % listen_addr)
    try:
        conn, peer = lsock.accept()
    except socket.timeout:
        sys.exit("brain: no executor connected within %gs (--accept-timeout)"
                 % args.accept_timeout)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    log("executor connected from %s:%d" % peer)

    conn.settimeout(args.hello_timeout or None)
    try:
        if recvn(conn, 4) != SZR_MAGIC:
            sys.exit("brain: bad magic from executor")
        ftype, payload = recv_frame(conn)
    except socket.timeout:
        sys.exit("brain: executor sent no HELLO within %gs (--hello-timeout)"
                 % args.hello_timeout)
    except (ConnectionError, ProtocolError) as e:
        sys.exit("brain: before HELLO: %s" % e)
    conn.settimeout(args.io_timeout or None)
    if ftype == SZR_BYE:
        sys.exit("brain: executor said BYE before HELLO (it could not start)")
    if ftype != SZR_HELLO:
        sys.exit("brain: expected HELLO, got type %d" % ftype)
    if len(payload) < SZR_HELLO_HDR_LEN:
        sys.exit("brain: HELLO payload is %d bytes (needs %d)"
                 % (len(payload), SZR_HELLO_HDR_LEN))
    ver, flags, map_size, ring_size, arch_len = struct.unpack(">HHIHH", payload[:12])
    if ver != SZR_PROTO_VERSION:
        sys.exit("brain: executor speaks SZR1 protocol version %d; this brain speaks %d"
                 % (ver, SZR_PROTO_VERSION))
    if len(payload) < SZR_HELLO_HDR_LEN + arch_len:
        sys.exit("brain: HELLO arch_len %d overruns its %d-byte payload"
                 % (arch_len, len(payload)))
    if map_size == 0:
        sys.exit("brain: HELLO map_size is 0")
    # Free-form ASCII (<= 64 bytes): only logged and recorded in run_config.
    arch = payload[12:12 + arch_len].decode("ascii", "replace")
    if arch_len > HELLO_ARCH_MAX:
        log("NOTE: HELLO arch string is %d bytes (spec: <= %d)"
            % (arch_len, HELLO_ARCH_MAX))
    if flags & 0x4:   # SZR_HELLO_FLAG_SCHEME (src/lcv_formats.h)
        ngram = (flags >> 8) & 0xf
        scheme = "n=%d model=%s rotate=%d" % (
            ngram, "pc" if flags & 0x8 else "site",
            1 if flags & 0x10 else 0)
        if ngram < 3:
            log("NOTE: coverage scheme is n=%d; an N>=3 scheme with rotation is "
                "more path-sensitive for fuzzing, if the executor supports one "
                "(libcov: rebuild with -DLIBCOV_NGRAM_N=3 -DLIBCOV_NGRAM_ROTATE=1)"
                % ngram)
    else:
        scheme = "unknown"
    log("HELLO proto=%d arch=%s map_size=%d ring=%d flags=0x%x scheme=%s"
        % (ver, arch, map_size, ring_size, flags, scheme))

    cumulative = bytearray(map_size)
    rng = random.Random(args.seed_rng)

    def splice_donor():
        return rng.choice(corpus) if corpus else b""

    engine = Engine(rng, corpus=splice_donor, max_size=args.max_size)

    execs = new_cov = crashes = hangs = 0
    crash_sigs = {}        # (reason, status) -> count; the dedup key
    hang_sigs = {}         # same, for HANG / TIMEOUT
    next_id = [1]

    # ---- optional JSON-lines status feed (for tools/status_tui.py) -------
    start = time.monotonic()
    status_fp = open(args.status_file, "a", buffering=1) if args.status_file else None
    last_status = [0.0]
    stage = ["baseline 0/%d" % len(corpus)]
    baseline_edges = [None]   # edges after the corpus replay; new_edges counts past it
    run_config = {"arch": arch, "scheme": scheme, "proto": ver, "ring": ring_size,
                  "executor": "%s:%d" % peer, "listen": listen_addr, "out": out,
                  "seeds": len(seeds), "resumed": len(resumed),
                  "max_size": args.max_size, "minimize": str(bool(args.minimize))}
    if args.iters:
        run_config["iters_limit"] = args.iters

    def emit_status(finished=False):
        if not status_fp:
            return
        el = time.monotonic() - start
        edges = sum(1 for b in cumulative if b)
        status_fp.write(json.dumps({
            "t": round(el, 1), "execs": execs,
            "execs_per_sec": round(execs / el, 1) if el > 0 else 0.0,
            "corpus": len(corpus), "edges": edges, "map_size": map_size,
            "new_edges": edges - baseline_edges[0] if baseline_edges[0] is not None else 0,
            "crashes": crashes, "crashes_unique": len(crash_sigs),
            "hangs": hangs, "hangs_unique": len(hang_sigs),
            "hangs_saved": len(hang_inputs),
            "stage": stage[0], "finished": finished, "config": run_config,
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
        while True:
            ftype, payload = recv_frame(conn)
            if ftype == SZR_BYE:
                raise ExecutorBye()
            if ftype == SZR_CRASH:
                if len(payload) < SZR_CRASH_LEN:
                    raise ProtocolError("CRASH payload is %d bytes (needs %d)"
                                        % (len(payload), SZR_CRASH_LEN))
                cid, reason, status = struct.unpack(">QBi", payload[:13])
            elif ftype == SZR_COVERAGE:
                if len(payload) < SZR_COVERAGE_HDR_LEN:
                    raise ProtocolError("COVERAGE payload is %d bytes (needs %d)"
                                        % (len(payload), SZR_COVERAGE_HDR_LEN))
                cid, _gen, kind, msz = struct.unpack(">QQBI", payload[:21])
                if msz != map_size or len(payload) < SZR_COVERAGE_HDR_LEN + msz:
                    raise ProtocolError("COVERAGE map_size %d with %d bitmap bytes "
                                        "(HELLO said %d)" % (msz, len(payload) - 21, map_size))
                if cid == 0 and kind == SLOT_INIT:
                    # Unsolicited startup snapshot (id 0): not a reply to
                    # this input; the reply is still to come.
                    log("executor sent its INIT snapshot (%d edges); not scored"
                        % sum(1 for b in payload[21:21 + msz] if b))
                    continue
            else:
                log("ignoring unexpected frame type %d (%d bytes)"
                    % (ftype, len(payload)))
                continue
            if cid != ident:
                sys.exit("brain: executor answered input id=%d with id=%d "
                         "(lockstep broken: one reply per INPUT, echoing its id)"
                         % (ident, cid))
            if ftype == SZR_CRASH:
                return ("crash", reason, status)
            if kind != SLOT_ITER:      # only score per-request (ITER) coverage
                return ("other", None)
            return ("iter", payload[21:21 + msz])

    def minimize(data, reason, status):
        """Bounded block-dropping: shrink `data` while it still fails with
        the same (reason, status) -- for GUEST_FAULT / ORACLE the status (a
        PC or oracle id) is the bug's identity. A readable tmin, not an
        optimal one."""
        if not args.minimize or len(data) <= 1:
            return data
        if reason in HANG_REASONS and not args.minimize_timeouts:
            return data                   # each probe would cost a timeout
        best = data
        chunk = max(1, len(best) // 2)
        budget = 200                      # cap re-sends so minimize stays cheap
        while chunk >= 1 and budget > 0:
            i = 0
            while i < len(best) and budget > 0:
                cand = best[:i] + best[i + chunk:]
                budget -= 1
                if cand and probe(cand) == ("crash", reason, status):
                    best = cand           # drop kept the crash
                else:
                    i += chunk
            chunk //= 2
        return best

    def write_finding(where, prefix, data, reason, status):
        """Write one finding plus its .info sidecar; return the file name."""
        rname, st = crash_name(reason), fmt_status(reason, status)
        name = "%s_r%d_s%d_%s" % (prefix, reason, status,
                                  hashlib.sha1(data).hexdigest()[:12])
        with open(os.path.join(where, name), "wb") as f:
            f.write(data)
        with open(os.path.join(where, name + ".info"), "w") as f:
            f.write("reason=%d\nreason_name=%s\nstatus=%d\n"
                    % (reason, rname, status))
            if reason in HEX_STATUS:
                f.write("status_hex=%s\n" % st)
            f.write("len=%d\nsig=r%d/s%d\nhex=%s\n"
                    % (len(data), reason, status, data.hex()))
        return name

    def drop_finding(where, name):
        for n in (name, name + ".info"):
            try:
                os.unlink(os.path.join(where, n))
            except OSError:
                pass

    hang_inputs = set()    # sha1 of every hang/timeout input already saved

    def save_crash(data, reason, status):
        nonlocal crashes, hangs
        is_hang = reason in HANG_REASONS
        if is_hang:
            hangs += 1
            nth, sigs, where, label, ev = hangs, hang_sigs, hang_dir, "HANG", "hang"
        else:
            crashes += 1
            nth, sigs, where, label, ev = crashes, crash_sigs, crash_dir, "CRASH", "crash"
        sig = (reason, status)
        n = sigs.get(sig, 0) + 1
        sigs[sig] = n
        rname, st = crash_name(reason), fmt_status(reason, status)
        if is_hang:
            # (reason, status) says little about a hang (TIMEOUT's status is
            # usually the budget), so keep every distinct input, up to a cap.
            h = hashlib.sha1(data).digest()
            if h in hang_inputs or len(hang_inputs) >= args.max_hangs:
                log("%s id=%d reason=%d(%s) status=%s not saved (%s)"
                    % (label, nth, reason, rname, st,
                       "already saved" if h in hang_inputs
                       else "--max-hangs %d reached" % args.max_hangs))
                return
            hang_inputs.add(h)
        elif n > 1:                       # already have this bug -> don't flood
            log("%s id=%d reason=%d(%s) status=%s dup (count=%d, not saved)"
                % (label, nth, reason, rname, st, n))
            return
        prefix = "hang" if is_hang else "crash"
        # Save the input as found first: minimizing re-sends it to the
        # executor, and a BYE, a timeout or a dropped connection there must
        # not lose the finding.
        name = write_finding(where, prefix, data, reason, status)
        small = minimize(data, reason, status)
        if small != data:
            drop_finding(where, name)
            name = write_finding(where, prefix, small, reason, status)
            data = small
        log("%s id=%d reason=%d(%s) status=%s NEW len=%d (saved %s)"
            % (label, nth, reason, rname, st, len(data), name))
        emit_event(ev, "%s r%d/s%s %s" % (rname, reason, st, name))

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
        replay = list(corpus)
        for i, s in enumerate(replay, 1):
            if stop["flag"]:
                break
            stage[0] = "baseline %d/%d" % (i, len(replay))
            run_one(s)
            maybe_status()
        baseline_edges[0] = sum(1 for b in cumulative if b)
        stage[0] = "havoc + splice"
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
        sys.exit("brain: executor sent no reply within %gs (--io-timeout)"
                 % args.io_timeout)
    except ConnectionError as e:
        sys.exit("brain: %s" % e)
    except ProtocolError as e:
        sys.exit("brain: protocol error from the executor: %s" % e)
    except ExecutorBye:
        log("executor said BYE; ending the session")
        executor_bye = True
    else:
        executor_bye = False

    if not executor_bye:
        try:
            send_frame(conn, SZR_BYE)
        except OSError:
            pass
    total = sum(1 for b in cumulative if b)
    # Hangs are deduplicated by input, not by (reason, status): unique counts
    # the keys, saved the distinct inputs kept under hangs/.
    log("done: execs=%d new_cov=%d crashes=%d (unique=%d) hangs=%d (unique=%d, "
        "saved=%d) corpus=%d edges=%d"
        % (execs, new_cov, crashes, len(crash_sigs), hangs, len(hang_sigs),
           len(hang_inputs), len(corpus), total))
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
