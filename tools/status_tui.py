#!/usr/bin/env python3
"""status_tui.py -- generic AFL/afl++-style live status screen for a fuzzer.

A reusable suzzer component and a worked example: a target-agnostic terminal
status board (the boxed "process timing / overall results / map coverage / ..."
panels you know from afl-fuzz, afl++ and honggfuzz), plus a rate/coverage chart
and an event feed. It is deliberately NOT tied to any particular fuzzer -- you
point it at a data feed and it renders.

It is stdlib-only (curses + json) and self-contained: copy this one file into
your project, keep `render()` as-is, and either emit the JSON feed below from
your fuzzer or replace the small parser with one for your own log format.

Two ways to feed it (pick one; the renderer never changes):

  1. JSON-lines feed (default, recommended).  Your fuzzer appends one JSON
     object per line to a file (or stdout); this tool follows it.  Scalars are
     "latest wins"; an {"event": ...} entry is appended to the feed.  Keys
     (all optional -- unknown keys are ignored, missing ones render as "?"):

       t              run time, seconds (int/float)
       execs          total executions
       execs_per_sec  current exec rate            (alias: "rate")
       corpus         corpus / queue size
       cycles         queue cycles done (else derived execs//corpus)
       edges          coverage units hit (bitmap tuples / blocks / edges)
       map_size       coverage map size (for the density %)
       sites          instrumented sites (optional)
       new_edges      cumulative new edges
       crashes        total crashes            crashes_unique  distinct crashes
       hangs          total hangs              hangs_unique    distinct hangs
       stage          current stage string, e.g. "havoc + splice"
       config         object of free-form label:value for the "run config" panel
       finished       true when the run is over
       event          {"kind":"find"|"crash"|"hang"|"info", "msg":"...",
                        "edges":N(optional)}  -- appended to the event feed

     Example producer (any language): print one line per update, e.g.
       {"t":42,"execs":165607,"execs_per_sec":4.6,"corpus":274,"edges":1921,
        "map_size":131072,"crashes":207,"crashes_unique":1,
        "config":{"workers":8,"max_size":8192}}
       {"event":{"kind":"crash","msg":"SIGSEGV in parse_header"}}
     suzzer's reference brain does exactly this: `suzzer_brain.py --status-file`.

  2. Your own text log.  See the "ADAPT ME" block near the bottom: write a
     `parse_text_line(st, line)` using regexes (like a real fuzzer's stderr)
     that calls the same setters, and pass --format text.

Usage:
  status_tui.py --input run.jsonl        # curses TUI, follows the feed (tty)
  status_tui.py --input run.jsonl --dump # one-shot text frame (no curses/CI)
  status_tui.py --input -                # read the JSON feed from stdin (--dump)
  status_tui.py --demo                   # render synthetic data (no feed needed)
  status_tui.py --selftest               # render checks on synthetic data, exit 0
  status_tui.py --input run.jsonl --artifacts ./crashes   # add a file browser

Keys (TUI):  q quit   a artifacts   g graphs   f freeze follow   r refresh
             h help    j/k/arrows scroll (subscreens)   Esc back
"""
import argparse
import json
import os
import re  # used by the ADAPT ME text-parser example
import sys
import time
from collections import deque

RAMP = "▁▂▃▄▅▆▇█"
DEFAULT_MAP = 65536


# ---- format helpers ------------------------------------------------------------

def fmt_n(x):
    try:
        return f"{int(x):,}"
    except (TypeError, ValueError):
        return str(x)


def fmt_dur(sec):
    sec = int(max(0, sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def fmt_afl_dur(sec):
    """afl's '0 days, 1 hrs, 23 min, 45 sec'."""
    sec = int(max(0, sec))
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return f"{d} days, {h} hrs, {m} min, {s} sec"


def fmt_wall(t):
    return time.strftime("%H:%M:%S", time.localtime(t))


# ---- chart helpers -------------------------------------------------------------

def downsample(vals, w, how="max"):
    if len(vals) <= w:
        return list(vals)
    out, step = [], len(vals) / w
    for i in range(w):
        a = int(i * step)
        b = min(len(vals), max(a + 1, int((i + 1) * step)))
        seg = vals[a:b]
        out.append(max(seg) if how == "max" else seg[-1])
    return out


def sparkline(vals, w):
    vals = downsample(list(vals), w, "max")
    if not vals:
        return " " * w
    mx = max(vals) or 1
    return "".join(RAMP[int(v / mx * (len(RAMP) - 1))] for v in vals)


def column_chart(vals, w, h):
    vals = downsample(list(vals), w, "max")
    if not vals:
        return [" " * w] * h
    mx = max(vals) or 1
    out = []
    for r in range(h):
        need = (h - 1) - r
        line = []
        for v in vals:
            lv = int(v / mx * (h - 1))
            line.append(RAMP[lv] if lv >= need else " ")
        out.append("".join(line).rstrip())
    return out


def bar_pct(pct, width):
    filled = int(round(max(0.0, min(100.0, pct)) / 100.0 * width))
    return "|" + "#" * filled + " " * (width - filled) + "|"


# ---- afl-style boxed panels ----------------------------------------------------

def _field(label, value, labw):
    return f"{label:>{labw}} : {value}"


def _panel(title, fields, width):
    """One bordered box; every returned line is exactly `width` columns wide."""
    inner = max(8, width - 2)
    pre = "─ " + title + " "
    if len(pre) > inner:
        pre = pre[:inner]
    out = ["┌" + pre + "─" * (inner - len(pre)) + "┐"]
    for f in fields:
        s = " " + f
        if len(s) > inner:
            s = s[:inner]
        out.append("│" + s + " " * (inner - len(s)) + "│")
    out.append("└" + "─" * inner + "┘")
    return out


def _cols(left, right):
    lw = len(left[0]) if left else 0
    rw = len(right[0]) if right else 0
    n = max(len(left), len(right))
    out = []
    for i in range(n):
        out.append((left[i] if i < len(left) else " " * lw)
                   + (right[i] if i < len(right) else " " * rw))
    return out


# ---- generic status model ------------------------------------------------------

class Event:
    __slots__ = ("id", "kind", "text", "t", "edges")

    def __init__(self, id_, kind, text, t, edges=None):
        self.id, self.kind, self.text, self.t, self.edges = id_, kind, text, t, edges


class Status:
    """Target-agnostic fuzzer state. Feed it with apply(obj); render() draws it."""

    SCALARS = {
        "t": "t", "execs": "execs", "execs_per_sec": "execs_per_sec",
        "rate": "execs_per_sec", "corpus": "corpus", "cycles": "cycles",
        "edges": "edges", "map_size": "map_size", "sites": "sites",
        "new_edges": "new_edges", "crashes": "crashes",
        "crashes_unique": "crashes_unique", "hangs": "hangs",
        "hangs_unique": "hangs_unique", "stage": "stage",
    }

    def __init__(self):
        self.t = 0.0
        self.execs = 0
        self.execs_per_sec = 0.0
        self.corpus = 0
        self.cycles = None
        self.edges = 0
        self.map_size = DEFAULT_MAP
        self.sites = None
        self.new_edges = 0
        self.crashes = 0
        self.crashes_unique = 0
        self.hangs = 0
        self.hangs_unique = 0
        self.stage = "—"
        self.config = {}
        self.finished = False
        self.last_find_t = None
        self.last_crash_t = None
        self.last_hang_t = None
        self.finds = 0
        self._crash_evs = 0
        self._hang_evs = 0
        self.find_times = deque(maxlen=4000)
        self.events = deque(maxlen=400)
        self.cov_hist = deque(maxlen=20000)
        self.rate_hist = deque(maxlen=20000)
        self._ev_id = 0
        self.flash = deque()
        self.have_data = False

    # -- feed -------------------------------------------------------------------
    def apply(self, obj, live=False):
        """Merge one JSON status object (scalars latest-wins; event appended)."""
        if not isinstance(obj, dict):
            return
        touched_snapshot = False
        for k, attr in self.SCALARS.items():
            if k in obj:
                setattr(self, attr, obj[k])
                touched_snapshot = True
        cfg = obj.get("config")
        if isinstance(cfg, dict):
            self.config.update(cfg)
        if "finished" in obj:
            self.finished = bool(obj["finished"])
        if touched_snapshot:
            self.have_data = True
            self.cov_hist.append((self.t, self.edges))
            self.rate_hist.append((self.t, self.execs_per_sec))
        ev = obj.get("event")
        if isinstance(ev, dict):
            self.add_event(ev.get("kind", "info"), ev.get("msg", ""),
                           ev.get("edges"), live)

    def add_event(self, kind, msg, edges=None, live=False):
        self.have_data = True
        self._ev_id += 1
        txt = msg
        if kind == "find" and edges is not None:
            txt = f"+{edges} edges  {msg}" if msg else f"+{edges} edges"
        ev = Event(self._ev_id, kind, txt, self.t, edges)
        self.events.append(ev)
        if kind == "find":
            self.finds += 1
            self.find_times.append(self.t)
            self.last_find_t = self.t
        elif kind == "crash":
            self._crash_evs += 1
            self.last_crash_t = self.t
        elif kind == "hang":
            self._hang_evs += 1
            self.last_hang_t = self.t
        if live:
            self.flash.append(ev.id)
        return ev

    # -- derived ----------------------------------------------------------------
    def uniq_crashes(self):
        return max(self.crashes_unique, self._crash_evs)

    def uniq_hangs(self):
        return max(self.hangs_unique, self._hang_evs)

    def cycles_done(self):
        if self.cycles is not None:
            return self.cycles
        return self.execs // self.corpus if self.corpus else 0

    def finds_per_min(self):
        if not self.find_times:
            return 0.0
        lo = self.t - 600.0
        n = sum(1 for x in self.find_times if x >= lo)
        return n * 60.0 / 600.0


# ---- JSON-lines feed follower --------------------------------------------------

class JsonFeed:
    """Follows a growing JSON-lines file (or a FIFO); apply()s each line."""

    def __init__(self, path, status):
        self.path = path
        self.st = status
        self.fh = None
        self.off = 0
        self.buf = b""

    def read_new(self, live=False):
        if self.fh is None:
            try:
                self.fh = open(self.path, "rb", buffering=0)
            except OSError:
                return 0
        try:
            self.fh.seek(self.off)
            data = self.fh.read(1 << 20)
        except OSError:
            return 0
        if not data:
            return 0
        self.off += len(data)
        blob = self.buf + data
        parts = blob.split(b"\n")
        self.buf = parts.pop()            # trailing partial line
        for ln in parts:
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
            except ValueError:
                continue
            self.st.apply(obj, live=live)
        return len(data)

    def initial_scan(self):
        while self.read_new(live=False):
            pass


def feed_from_stdin(status):
    for ln in sys.stdin:
        ln = ln.strip()
        if not ln:
            continue
        try:
            status.apply(json.loads(ln), live=False)
        except ValueError:
            continue


# ---- the renderer (keep this; swap only the parser above) ----------------------

FOOTER_KEYS = (" [q]uit  [a]rtifacts  [g]raphs  [f]reeze  [r]efresh  [h]elp")


def _clamp(rows, tw, h):
    """Truncate every row to the panel width so nothing overflows the frame."""
    return [(t if len(t) <= tw else t[:tw], a) for t, a in rows[:h]]


def _ev_line(st, ev):
    ts = fmt_dur(ev.t)
    mark = "*" if ev.id in st.flash else " "
    return f"{mark} T+{ts:>8}  {ev.text}", {
        "find": "ok", "crash": "err", "hang": "warn", "info": "dim",
    }.get(ev.kind, "")


def render(st, w, h, title="fuzzer status :: afl-style"):
    """Render the status board as a list of (text, attr) rows."""
    rows = []
    tw = min(max(w - 1, 44), 104)
    rows.append((title.center(tw), "head"))

    if not st.have_data:
        rows.append(("", ""))
        rows.append((" waiting for status data (no feed lines yet)", "warn"))
        while len(rows) < h - 1:
            rows.append(("", ""))
        rows.append((FOOTER_KEYS, "dim"))
        return _clamp(rows, tw, h)

    pct = 100.0 * st.edges / st.map_size if st.map_size else 0.0
    uc, uh = st.uniq_crashes(), st.uniq_hangs()

    def ago(t_ev):
        if t_ev is None:
            return "none seen yet"
        return fmt_afl_dur(max(0, st.t - t_ev))

    lw = (tw * 56) // 100          # wider left column (afl-style asymmetry)
    rw = tw - lw

    L = _panel("process timing", [
        _field("run time", fmt_afl_dur(st.t), 16),
        _field("last new find", ago(st.last_find_t), 16),
        _field("last saved crash", ago(st.last_crash_t), 16),
        _field("last saved hang", ago(st.last_hang_t), 16),
    ], lw)
    R = _panel("overall results", [
        _field("cycles done", fmt_n(st.cycles_done()), 14),
        _field("corpus count", fmt_n(st.corpus), 14),
        _field("saved crashes", f"{fmt_n(st.crashes)}  ({uc} unique)", 14),
        _field("saved hangs", f"{fmt_n(st.hangs)}  ({uh} unique)", 14),
    ], rw)
    rows += [(ln, "") for ln in _cols(L, R)]

    L = _panel("map coverage", [
        _field("map edges", f"{fmt_n(st.edges)} / {fmt_n(st.map_size)}", 12),
        _field("map density", f"{pct:5.2f}%  {bar_pct(pct, 10)}", 12),
        _field("sites armed", fmt_n(st.sites) if st.sites else "?", 12),
        _field("new edges", fmt_n(st.new_edges), 12),
    ], lw)
    R = _panel("stage progress", [
        _field("now trying", str(st.stage), 13),
        _field("total execs", fmt_n(st.execs), 13),
        _field("exec speed", f"{st.execs_per_sec:.1f}/sec"
               + ("" if st.execs_per_sec > 1.0 else "  (slow!)"), 13),
        _field("new finds/min", f"{st.finds_per_min():.2f}", 13),
    ], rw)
    rows += [(ln, "") for ln in _cols(L, R)]

    cfg_items = list(st.config.items())[:4]
    labw = max([11] + [len(str(k)) for k, _ in cfg_items])
    cfg_fields = [_field(str(k), str(v), labw) for k, v in cfg_items]
    while len(cfg_fields) < 4:
        cfg_fields.append("")
    L = _panel("findings in depth", [
        _field("corpus paths", fmt_n(st.corpus), 14),
        _field("new-cov finds", fmt_n(st.finds), 14),
        _field("total crashes", f"{fmt_n(st.crashes)}  ({uc} unique)", 14),
        _field("total hangs", f"{fmt_n(st.hangs)}  ({uh} unique)", 14),
    ], lw)
    R = _panel("run config", cfg_fields, rw)
    rows += [(ln, "") for ln in _cols(L, R)]

    if st.finished:
        rows.append((" RUN FINISHED", "head"))

    if len(st.cov_hist) > 2:
        vs = [p[1] for p in st.cov_hist]
        ts = [p[0] for p in st.cov_hist]
        cw = min(tw - 6, 92)
        rows.append((f" map coverage over time  T+{fmt_dur(ts[0])}..T+"
                     f"{fmt_dur(ts[-1])}   {fmt_n(vs[0])} → {fmt_n(vs[-1])} "
                     f"edges", "dim"))
        for ln in column_chart(vs, cw, 3):
            rows.append(("   " + ln, "ok"))

    rows.append((" last events", "dim"))
    n_ev = max(1, h - len(rows) - 2)
    for ev in list(st.events)[-n_ev:]:
        txt, attr = _ev_line(st, ev)
        if ev.id in st.flash:
            attr = "flash"
        rows.append((txt, attr))
    while len(rows) < h - 1:
        rows.append(("", ""))
    rows.append((FOOTER_KEYS, "dim"))
    return _clamp(rows, tw, h)


# ---- generic artifacts browser + help -----------------------------------------

def list_dir(d):
    out = []
    try:
        names = os.listdir(d)
    except OSError:
        return out
    for n in names:
        p = os.path.join(d, n)
        if os.path.isfile(p):
            out.append((os.path.getmtime(p), n, os.path.getsize(p)))
    out.sort(key=lambda r: r[0], reverse=True)
    return out


def build_artifacts(path, w, h, scroll):
    rows = [(" artifacts  (newest first)   q/esc:back  j/k:scroll", "head")]
    if not path:
        rows.append((" (no --artifacts DIR given)", "dim"))
        return rows + [("", "")] * (h - len(rows))
    entries = list_dir(path)
    rows.append((f" {len(entries)} file(s) in {path}", "dim"))
    rows.append(("", ""))
    for mtime, name, size in entries[scroll:scroll + (h - len(rows) - 1)]:
        rows.append((f" {fmt_wall(mtime)}  {name:32s} {size:8d}B", "ok"))
    rows.append((" -- esc/q back --", "dim"))
    return rows[:h]


def build_graphs(st, w, h):
    rows = [(" graphs   q/esc:back", "head"), ("", "")]

    def plot(label, series, height, fmt):
        rows.append((label, "dim"))
        if len(series) < 2:
            rows.append(("   (not enough data yet)", "dim"))
            return
        vs = [p[1] for p in series]
        cw = min(w - 10, 90)
        rows.append((f"   min {fmt(min(vs))}  max {fmt(max(vs))}  "
                     f"last {fmt(vs[-1])}", "dim"))
        for ln in column_chart(vs, cw, height):
            rows.append(("   " + ln, "ok"))
        rows.append(("", ""))

    plot(" coverage (edges):", list(st.cov_hist), 6, fmt_n)
    plot(" exec speed (execs/sec):", list(st.rate_hist), 6, lambda v: f"{v:.1f}")
    rows.append((" -- esc/q back --", "dim"))
    return rows[:h]


HELP_TEXT = [
    (" status_tui.py -- generic afl-style fuzzer status board", "head"),
    ("", ""),
    (" Feed it JSON-lines (one status object per line) via --input FILE/-,",
     ""),
    (" or adapt the parser for your own log format (see ADAPT ME in source).",
     ""),
    ("", ""),
    (" panels      process timing | overall results, map coverage | stage",
     ""),
    ("              progress, findings in depth | run config (from config{})",
     ""),
    (" graphs      coverage + exec-speed history (block charts)", ""),
    (" events      newest find/crash/hang/info messages; new ones flash once",
     ""),
    ("", ""),
    (" keys        q quit   a artifacts browser (--artifacts DIR)   g graphs",
     ""),
    ("              f freeze follow   r refresh   h help   j/k scroll   Esc back",
     ""),
]


# ---- curses UI -----------------------------------------------------------------

ATTR_MAP = {
    "": (0, 0), "dim": ("dim", 0), "head": ("bold", 7), "ok": (0, 2),
    "err": ("bold", 3), "warn": ("bold", 4), "flash": ("rev", 6),
}
ASCII_RAMP = str.maketrans({c: a for c, a in zip(RAMP, ".:-=+*#%")})


def run_curses(feed, st, artifacts):
    import curses

    def on_term(_term):
        scr = curses.initscr()
        curses.cbreak()
        curses.noecho()
        scr.keypad(True)
        scr.timeout(400)
        try:
            curses.start_color()
            curses.use_default_colors()
            for i, name in enumerate(("black", "green", "red", "magenta",
                                      "yellow", "cyan", "white"), start=1):
                try:
                    curses.init_pair(i, getattr(curses, "COLOR_" + name.upper()),
                                     -1)
                except curses.error:
                    pass
        except curses.error:
            pass
        try:
            curses.curs_set(0)
        except curses.error:
            pass

        def attr(name):
            a, pair = ATTR_MAP.get(name, (0, 0))
            flags = 0
            if a == "bold":
                flags |= curses.A_BOLD
            elif a == "dim":
                flags |= curses.A_DIM
            elif a == "rev":
                flags |= curses.A_REVERSE
            if pair:
                flags |= curses.color_pair(pair)
            return flags

        def add(r, txt, a, w):
            try:
                scr.addnstr(r, 0, txt, max(0, w - 1), a)
            except curses.error:
                try:
                    scr.addnstr(r, 0, txt.translate(ASCII_RAMP), max(0, w - 1), a)
                except curses.error:
                    pass

        def draw(rows, w, h):
            scr.erase()
            for r, (txt, a) in enumerate(rows[:h]):
                add(r, txt, attr(a), w)
            scr.refresh()

        frozen = False
        screen = "main"
        scroll = {"artifacts": 0}
        while True:
            h, w = scr.getmaxyx()
            if not frozen and feed is not None:
                feed.read_new(live=True)
            if screen == "main":
                rows = render(st, w, h)
                if frozen:
                    rows[-1] = (rows[-1][0] + "   ** FROZEN (f) **", "warn")
            elif screen == "artifacts":
                rows = build_artifacts(artifacts, w, h, scroll["artifacts"])
            elif screen == "graphs":
                rows = build_graphs(st, w, h)
            else:
                rows = HELP_TEXT + [("", "")] * max(0, h - len(HELP_TEXT) - 1)
            draw(rows, w, h)
            st.flash.clear()

            ch = scr.getch()
            if ch == -1:
                continue
            if ch == 27 or ch == ord("q"):
                if screen != "main":
                    screen = "main"
                    continue
                if ch == ord("q"):
                    break
                continue
            if screen == "main":
                if ch == ord("a"):
                    scroll["artifacts"] = 0
                    screen = "artifacts"
                elif ch == ord("g"):
                    screen = "graphs"
                elif ch == ord("h"):
                    screen = "help"
                elif ch == ord("f"):
                    frozen = not frozen
                elif ch == ord("r") and feed is not None:
                    feed.read_new(live=True)
            elif screen == "artifacts":
                if ch in (ord("j"), curses.KEY_DOWN):
                    scroll["artifacts"] += 1
                elif ch in (ord("k"), curses.KEY_UP):
                    scroll["artifacts"] = max(0, scroll["artifacts"] - 1)

    curses.wrapper(on_term)


# ---- ADAPT ME: parse your own fuzzer's text log instead of JSON ----------------
#
# Prefer the JSON feed above. But if your fuzzer already emits a bespoke text
# log (like afl's fuzzer_stats or a custom stderr), keep render()/Status and
# replace ONLY this function: match your lines and call the same setters /
# st.add_event(...). Keep render()/Status unchanged; swap only the parser.
# Enable it with --format text.
#
_EX_PROGRESS = re.compile(
    r"execs=(\d+)\s+rate=([\d.]+)\s+corpus=(\d+)\s+edges=(\d+)\s+t=(\d+)")
_EX_CRASH = re.compile(r"CRASH\s+(.*)")


def parse_text_line(st, line):
    """Example text adapter (replace with your fuzzer's real format)."""
    m = _EX_PROGRESS.search(line)
    if m:
        st.apply({"execs": int(m.group(1)), "execs_per_sec": float(m.group(2)),
                  "corpus": int(m.group(3)), "edges": int(m.group(4)),
                  "t": int(m.group(5))})
        return
    m = _EX_CRASH.search(line)
    if m:
        st.add_event("crash", m.group(1).strip())


class TextFeed(JsonFeed):
    """Same file-follower, but parses each line as text via parse_text_line."""

    def read_new(self, live=False):
        if self.fh is None:
            try:
                self.fh = open(self.path, "rb", buffering=0)
            except OSError:
                return 0
        try:
            self.fh.seek(self.off)
            data = self.fh.read(1 << 20)
        except OSError:
            return 0
        if not data:
            return 0
        self.off += len(data)
        blob = self.buf + data
        parts = blob.split(b"\n")
        self.buf = parts.pop()
        for ln in parts:
            parse_text_line(self.st, ln.decode("utf-8", "replace"))
        return len(data)


# ---- demo + selftest -----------------------------------------------------------

def make_demo_status():
    st = Status()
    st.map_size = 131072
    for i in range(1, 46):
        t = i * 85
        edges = int(700 + 760 * (1 - 0.5 ** (i / 10.0)))
        st.apply({"t": t, "execs": i * 6800, "execs_per_sec": 79.5,
                  "corpus": 180 + i, "edges": edges, "map_size": 131072,
                  "sites": 3097, "new_edges": edges, "crashes": i * 4,
                  "crashes_unique": min(i, 3), "stage": "havoc + splice",
                  "config": {"workers": 8, "demalloc": "1/8",
                             "max_size": 8192, "resumed": 228}})
        if i == 6:
            st.add_event("find", "reached parse_header", edges=180)
        if i == 20:
            st.add_event("crash", "SIGSEGV in parse_record")
        if i == 40:
            st.add_event("find", "new state in handle_request()", edges=25)
    return st


def selftest():
    st = make_demo_status()
    assert st.uniq_crashes() >= 1
    assert st.cycles_done() > 0
    titles = ["process timing", "overall results", "map coverage",
              "stage progress", "findings in depth", "run config"]
    for w in (60, 80, 100, 132):
        rows = render(st, w, 40)
        blob = "\n".join(t for t, _ in rows)
        for title in titles:
            assert title in blob, f"missing panel {title!r} at w={w}"
        for t, _ in rows:
            assert len(t) <= w, f"row wider than {w}: {t!r}"
    # feed/apply round-trip
    s2 = Status()
    s2.apply({"execs": 10, "edges": 5, "map_size": 100,
              "event": {"kind": "find", "edges": 5}})
    assert s2.execs == 10 and s2.finds == 1 and s2.last_find_t is not None
    print("[selftest] ok: panels render at 60/80/100/132 cols, apply() works")
    return 0


# ---- main ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Generic afl-style fuzzer status board (suzzer).")
    ap.add_argument("--input", "-i", default=None,
                    help="JSON-lines feed file to follow, or '-' for stdin")
    ap.add_argument("--format", choices=("json", "text"), default="json",
                    help="feed format: json (default) or text (ADAPT ME parser)")
    ap.add_argument("--dump", action="store_true",
                    help="print one text frame and exit (no curses; CI/tty-less)")
    ap.add_argument("--demo", action="store_true",
                    help="render synthetic data (no feed needed)")
    ap.add_argument("--selftest", action="store_true",
                    help="render checks on synthetic data; exit 0 on success")
    ap.add_argument("--artifacts", default=None,
                    help="directory to browse in the 'a' screen (e.g. crashes/)")
    ap.add_argument("--title", default="fuzzer status :: afl-style")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    st = Status()
    feed = None
    if args.demo:
        st = make_demo_status()
    elif args.input == "-":
        feed_from_stdin(st)            # drain stdin (one-shot; implies --dump)
        args.dump = True
    elif args.input:
        feed = (TextFeed if args.format == "text" else JsonFeed)(args.input, st)
        feed.initial_scan()
    else:
        ap.error("need --input FILE, --input -, or --demo")

    if args.dump or not sys.stdout.isatty():
        import shutil
        w, h = shutil.get_terminal_size((100, 44))
        for txt, attr in render(st, w, max(24, h), title=args.title):
            tag = {"err": "!!", "warn": "**", "flash": "**", "head": ">>",
                   "ok": "++", "dim": "  "}.get(attr, "  ")
            print(f"{tag} {txt}")
        return 0

    run_curses(feed, st, args.artifacts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
