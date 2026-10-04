#!/usr/bin/env python3
"""
mutate.py -- generic AFL++-style mutation engine for suzzer-built fuzzers.

A drop-in mutation core that any fuzzer driving a suzzer-instrumented
target can import (`from tools.mutate import Engine, Dictionary,
StructuredInsert`), subclass for project-specific tweaks, or vendor
into their own tree. Stdlib-only, single file, no suzzer-runtime
dependencies. Designed to slot in next to `gen_patchlist.py` and
`gen_boundary.py` as the third "LEGO brick" every suzzer-built fuzzer
needs.

Three audiences
---------------

  1. Quick start:   instantiate `Engine(rng)` and call `.mutate(seed)`.
                    All defaults are AFL++-equivalent havoc.

  2. Tuned use:     supply a `Dictionary`, a list of `StructuredInsert`
                    callables, an `op_weights` dict, and a `corpus`
                    callable for splice. Hook `pre_mutate` /
                    `post_process` for framing-aware fixups.

  3. Example impl:  every op is a small method with a one-line
                    rationale. Copy-paste pieces into a project-
                    specific mutator if the abstraction is in the way.

Architecture
------------

A *mutation* is one or more stacked *ops* applied to a copy of the
seed buffer. Op selection is weighted; weights are materialized as a
flat alias array at construct time so each op pick is O(1).

Stack count follows the AFL distribution: `1 << (1 + randint(0, 7))`
yields {2,4,8,16,32,64,128,256}. The engine samples log-uniformly
between `stack_min` and `stack_max`.

The op menu (21 entries) covers AFL++-equivalent havoc:

  bit/byte:        BIT_FLIP, BYTE_FLIP, BYTE_ARITH, RANDOM_BYTE
  multi-byte arith:
                   WORD_ARITH_LE, WORD_ARITH_BE,
                   DWORD_ARITH_LE, DWORD_ARITH_BE
  interesting set:
                   SET_INTERESTING_U8,
                   SET_INTERESTING_U16_LE, SET_INTERESTING_U16_BE,
                   SET_INTERESTING_U32_LE, SET_INTERESTING_U32_BE
  chunk:           DELETE_CHUNK, CLONE_CHUNK, OVERWRITE_CHUNK,
                   SWAP_CHUNKS
  dictionary:      DICT_INSERT, DICT_OVERWRITE
  structured:      STRUCTURED_INSERT, STRUCTURED_OVERWRITE

Splice is *not* in the havoc op menu; it's a separate strategy. When
a `corpus` callable is configured, `mutate()` may, with probability
`splice_prob` (default 0.15, matching AFL), splice the seed against
a donor from the corpus *before* the havoc stack runs.

Dictionary
----------

A `Dictionary` is a list of byte fragments with optional weights. The
expected use is well-known protocol tokens / magic constants / API
keywords that pure byte havoc is statistically unlikely to synthesize
(e.g. `IAC SB <opt> <body> IAC SE` for telnet, HTTP method strings,
DNS label sequences, X.509 OIDs). When no dictionary is supplied the
two dict ops have weight 0 and are never picked.

`parse_afl_dict()` reads the standard AFL/AFL++ `name="hex-escaped
string"` text format, so existing oss-fuzz / AFL++ dictionaries
work unchanged.

Structured inserts
------------------

A `StructuredInsert` wraps a user-defined callable
`(rng) -> bytes` that synthesizes one *structurally valid* chunk.
Where a dictionary is a fixed set of static fragments, a structured
insert is a *generator function* that produces fresh, valid-by-
construction bytes on every call -- random length, random body
content, but always honoring whatever framing the target requires
(length prefixes, IAC escaping, checksums, etc.).

This is the bridge between pure byte fuzzing and grammar-based
generation. Users supply as many StructuredInsert instances as they
want; the engine picks one weighted-random when a structured op
fires, then optionally runs a post-`escape` over the result for
protocol-specific byte stuffing.

Pre/post mutation hooks
-----------------------

Two optional callables, both outside the op menu:

  pre_mutate(src) -> src'
      Runs once at the top of `mutate()`, before splice. Typical
      use: strip framing the engine shouldn't fuzz; decode an
      envelope so byte havoc lands on the payload, not the
      wrapper.

  post_process(out) -> out'
      Runs once at the bottom of `mutate()`, after the length cap.
      Typical use: recompute a checksum, re-wrap a framing layer,
      enforce a minimum length.

Reproducibility
---------------

Set `trace=True` to record the sequence of ops + parameters applied
in each `mutate()` call. Access via `engine.last_trace` (a list of
`OpRecord`) and `engine.last_trace_hash` (16-char sha1 prefix). Off
by default to keep the hot path allocation-free.

Trace records cover *only* havoc-stack ops, not splice and not the
pre/post hooks. For bit-exact replay across splice, the caller must
also ensure their `corpus` callable is deterministic given a fixed
RNG seed.

CLI
---

  python3 mutate.py --selftest
      Run built-in correctness checks (determinism, length cap, op
      weighting, dict parsing, trace+hash, structured insert).
      Exits 0 on success.

  python3 mutate.py --seed FILE --out DIR/ --count N [--dict D]
                    [--splice-from CORPUS_DIR] [--weights W.json]
                    [--max-size N] [--seed-rng K] [--trace]
      Dump N mutants of FILE to DIR/. Useful for ad-hoc tooling
      (priming a corpus, sanity-checking a dictionary, A/B
      comparing weight profiles).

Files / cross-references
------------------------

  /home/user/suzzer/README.md            -- tools/ section lists this
                                            file alongside gen_*.
  /home/user/suzzer/Design.md            -- tools/ section in repo
                                            layout.

Vendor-friendliness
-------------------

This file is intentionally self-contained: stdlib-only, no external
imports, no runtime dependency on libcov / suzzer shm / etc. Drop
it into any project unchanged. The only assumption is Python 3.7+
(for dataclasses).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import struct
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# AFL "interesting" values: live near branch boundaries (off-by-one,
# signed/unsigned transitions, MSB-set checks, RFC-defined sentinels).
INTERESTING_I8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
INTERESTING_U8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
INTERESTING_U16 = [0, 1, 128, 255, 256, 512, 1000, 1024,
                   4096, 32767, 32768, 65535]
INTERESTING_U32 = [0, 1, 32768, 65535, 65536, 100663045,
                   2147483647, 2147483648, 4294967295]

ARITH_MAX = 35              # AFL default; per-op delta range [-N, +N]
MAX_BLOCK = 32              # cap on chunk-op extent
DEFAULT_MAX_SIZE = 65536    # hard cap on output length


# ---------------------------------------------------------------------------
# Op IDs
# ---------------------------------------------------------------------------

class OP(IntEnum):
    """Stable IDs for every op the engine can apply.

    Stable across versions: never renumber. New ops append. Used by
    `op_weights`, `OpRecord.op`, and the trace hash.
    """
    BIT_FLIP                 = 1
    BYTE_FLIP                = 2
    BYTE_ARITH               = 3
    WORD_ARITH_LE            = 4
    WORD_ARITH_BE            = 5
    DWORD_ARITH_LE           = 6
    DWORD_ARITH_BE           = 7
    SET_INTERESTING_U8       = 8
    SET_INTERESTING_U16_LE   = 9
    SET_INTERESTING_U16_BE   = 10
    SET_INTERESTING_U32_LE   = 11
    SET_INTERESTING_U32_BE   = 12
    RANDOM_BYTE              = 13
    DELETE_CHUNK             = 14
    CLONE_CHUNK              = 15
    OVERWRITE_CHUNK          = 16
    SWAP_CHUNKS              = 17
    DICT_INSERT              = 18
    DICT_OVERWRITE           = 19
    STRUCTURED_INSERT        = 20
    STRUCTURED_OVERWRITE     = 21


# Default relative weights. Tunable via `Engine(op_weights={...})`.
# Set a weight to 0 to disable an op.
DEFAULT_OP_WEIGHTS = {
    OP.BIT_FLIP:                 8,
    OP.BYTE_FLIP:                6,
    OP.BYTE_ARITH:               6,
    OP.WORD_ARITH_LE:            6,
    OP.WORD_ARITH_BE:            4,
    OP.DWORD_ARITH_LE:           4,
    OP.DWORD_ARITH_BE:           3,
    OP.SET_INTERESTING_U8:       8,
    OP.SET_INTERESTING_U16_LE:   4,
    OP.SET_INTERESTING_U16_BE:   3,
    OP.SET_INTERESTING_U32_LE:   3,
    OP.SET_INTERESTING_U32_BE:   2,
    OP.RANDOM_BYTE:              6,
    OP.DELETE_CHUNK:             6,
    OP.CLONE_CHUNK:              5,
    OP.OVERWRITE_CHUNK:          5,
    OP.SWAP_CHUNKS:              2,
    OP.DICT_INSERT:              8,    # auto-zeroed when no dict
    OP.DICT_OVERWRITE:           6,    # auto-zeroed when no dict
    OP.STRUCTURED_INSERT:        8,    # auto-zeroed when no inserts
    OP.STRUCTURED_OVERWRITE:     4,    # auto-zeroed when no inserts
}


# ---------------------------------------------------------------------------
# Dictionary
# ---------------------------------------------------------------------------

@dataclass
class Dictionary:
    """A weighted collection of byte fragments inserted verbatim during
    mutation.

    Example:
        d = Dictionary([b"GET ", b"POST ", b"HTTP/1.1\\r\\n"])
        d.add(b"\\xff\\xfd\\x18")             # IAC DO TTYPE
        d.add(b"important", weight=10)       # 10x more likely

    `pick(rng)` returns one fragment per weighted random draw via a
    pre-built flat alias array (O(1) selection). Empty dictionaries
    are valid; the engine simply disables DICT_* ops in that case.
    """
    fragments: List[bytes] = field(default_factory=list)
    weights: List[int] = field(default_factory=list)

    def __post_init__(self):
        if not self.weights:
            self.weights = [1] * len(self.fragments)
        if len(self.fragments) != len(self.weights):
            raise ValueError("fragments and weights length mismatch")
        self.fragments = [bytes(f) for f in self.fragments]
        self.weights = [max(1, int(w)) for w in self.weights]
        self._rebuild()

    def _rebuild(self):
        self._alias = [i for i, w in enumerate(self.weights)
                       for _ in range(w)]

    def add(self, fragment: bytes, weight: int = 1):
        if not fragment:
            return
        self.fragments.append(bytes(fragment))
        self.weights.append(max(1, int(weight)))
        self._rebuild()

    def extend(self, fragments: Iterable[bytes]):
        for f in fragments:
            self.add(f)

    def pick(self, rng: random.Random) -> bytes:
        return self.fragments[rng.choice(self._alias)]

    def __len__(self):
        return len(self.fragments)

    def __bool__(self):
        return bool(self.fragments)


def parse_afl_dict(path) -> Dictionary:
    """Parse a standard AFL / AFL++ dictionary file.

    Format (one entry per line):
        # comment
        name="hex-or-printable-escaped string"
        name@level="..."

    Recognized escapes inside the quoted body:
        \\\\  ->  0x5c
        \\"  ->  0x22
        \\t   ->  0x09
        \\n   ->  0x0a
        \\r   ->  0x0d
        \\xHH ->  the byte with hex value HH

    Empty/whitespace lines and `#` comments are ignored. Each entry's
    `name` and `@level` qualifier are discarded; only the byte payload
    is kept (with weight=1). Decode errors on a single line raise
    `ValueError` with line number.
    """
    d = Dictionary()
    p = Path(path)
    with p.open("rb") as fh:
        for lineno, raw in enumerate(fh, 1):
            try:
                line = raw.decode("utf-8", "strict").strip()
            except UnicodeDecodeError as e:
                raise ValueError(f"{p}:{lineno}: invalid utf-8: {e}")
            if not line or line.startswith("#"):
                continue
            try:
                qstart = line.index('"')
                qend = line.rindex('"')
            except ValueError:
                raise ValueError(f"{p}:{lineno}: missing quoted body")
            if qstart == qend:
                raise ValueError(f"{p}:{lineno}: unterminated string")
            body = line[qstart + 1:qend]
            payload = bytearray()
            i = 0
            while i < len(body):
                c = body[i]
                if c == "\\":
                    if i + 1 >= len(body):
                        raise ValueError(
                            f"{p}:{lineno}: trailing backslash")
                    nxt = body[i + 1]
                    if nxt == "\\":
                        payload.append(0x5c); i += 2
                    elif nxt == '"':
                        payload.append(0x22); i += 2
                    elif nxt == "t":
                        payload.append(0x09); i += 2
                    elif nxt == "n":
                        payload.append(0x0a); i += 2
                    elif nxt == "r":
                        payload.append(0x0d); i += 2
                    elif nxt == "x":
                        if i + 3 >= len(body):
                            raise ValueError(
                                f"{p}:{lineno}: truncated \\x escape")
                        try:
                            payload.append(int(body[i + 2:i + 4], 16))
                        except ValueError:
                            raise ValueError(
                                f"{p}:{lineno}: bad \\x escape")
                        i += 4
                    else:
                        raise ValueError(
                            f"{p}:{lineno}: unknown escape \\{nxt}")
                else:
                    payload.append(ord(c))
                    i += 1
            if payload:
                d.add(bytes(payload))
    return d


# ---------------------------------------------------------------------------
# Structured inserts
# ---------------------------------------------------------------------------

@dataclass
class StructuredInsert:
    """A user-defined generator for a structurally valid chunk.

    `factory(rng) -> bytes` returns a fresh, well-formed payload on
    every call. `escape`, when provided, runs once over the factory's
    output for protocol-specific byte stuffing (e.g. RFC 855 IAC-IAC
    escaping in telnet, byte-stuffing in PPP, length-recompute in
    LV/TLV protocols). `weight` controls relative probability when
    the engine selects among multiple structured inserts.

    Example -- telnet SB envelope with RFC 855 body escaping:

        def _telnet_sb_body(rng):
            opt = rng.choice([0, 1, 24, 31, 34, 39])
            body = bytes(rng.randint(0, 255)
                         for _ in range(rng.randint(0, 64)))
            return b"\\xff\\xfa" + bytes([opt]) + body + b"\\xff\\xf0"

        def _iac_escape(b):
            head, tail = b[:3], b[-2:]
            middle = b[3:-2].replace(b"\\xff", b"\\xff\\xff")
            return head + middle + tail

        telnet_sb = StructuredInsert(
            name="telnet_sb",
            factory=_telnet_sb_body,
            escape=_iac_escape,
            weight=2)

    `name` is purely informational (shows up in introspection logs);
    it does not need to be unique.
    """
    name: str
    factory: Callable[[random.Random], bytes]
    weight: int = 1
    escape: Optional[Callable[[bytes], bytes]] = None

    def produce(self, rng: random.Random) -> bytes:
        out = self.factory(rng)
        if self.escape is not None:
            out = self.escape(out)
        return bytes(out)


# ---------------------------------------------------------------------------
# Trace records (opt-in reproducibility)
# ---------------------------------------------------------------------------

@dataclass
class OpRecord:
    """One entry in `engine.last_trace`.

    `op` is the `OP` int; `pos` is the byte offset where the op
    operated; `payload` is the op-specific bytes used (insert
    fragment, overwrite delta, etc.). Records describe only the
    havoc stack -- splice and pre/post hooks are not recorded.
    """
    op: int
    pos: int
    payload: bytes = b""

    def to_json(self) -> dict:
        return {"op": int(self.op),
                "op_name": OP(self.op).name,
                "pos": self.pos,
                "payload": self.payload.hex()}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class Engine:
    """Generic AFL++-style mutation engine.

    Parameters
    ----------
    rng :
        A `random.Random` instance. Inject the same seed twice and
        you get the same outputs (modulo what your factories /
        corpus callable / hooks do).
    dictionary :
        Optional `Dictionary`. When None or empty, DICT_* ops are
        disabled (weight forced to 0).
    structured_inserts :
        Optional sequence of `StructuredInsert` (or bare
        `(rng) -> bytes` callables, which are promoted to
        StructuredInsert with weight=1 and no escape). When empty,
        STRUCTURED_* ops are disabled.
    corpus :
        Optional `() -> bytes` callable returning a donor for splice.
        When None, splice is disabled and `mutate()` is havoc-only.
        The callable is invoked at most once per `mutate()` call
        (only when splice fires).
    max_size :
        Hard cap on output bytes; truncation after every op and
        before return.
    op_weights :
        Optional dict[OP -> int] overriding `DEFAULT_OP_WEIGHTS`. Set
        a weight to 0 to disable an op. Backings (dict, inserts) are
        re-checked after override -- a user can't enable
        STRUCTURED_INSERT when no inserts are configured.
    pre_mutate :
        Optional `(bytes) -> bytes` run at the top of `mutate()`,
        before splice. Use to strip framing the engine shouldn't
        touch.
    post_process :
        Optional `(bytes) -> bytes` run at the bottom of `mutate()`,
        after the length cap. Use to recompute checksums, re-wrap
        framing, enforce minimum length.
    stack_min, stack_max :
        Inclusive bounds on per-call stacked op count, sampled from
        AFL's log-uniform distribution `1 << (1 + r)`. Defaults
        (2, 256) match AFL exactly.
    splice_prob :
        Probability in [0,1] that `mutate()` first splices the seed
        against a corpus donor before havoc. Default 0.15. Ignored
        when no `corpus` callable was provided.
    trace :
        When True, record each op's (id, pos, payload) into
        `last_trace` and compute `last_trace_hash` (16-char sha1).
        Costs memory + a hash pass; off by default.

    Public methods
    --------------
    mutate(src) -> bytes
        Top-level entry. Runs pre_mutate, optional splice, havoc
        stack, length cap, post_process. Always returns a new bytes
        object.
    havoc(src) -> bytes
        Run only the havoc stack. Skips splice, pre_mutate,
        post_process. Useful when the caller wants its own
        scheduling.
    splice(a, b) -> bytes
        AFL-style splice: random crossover point between the first
        and last differing byte positions of a and b. Returns a
        unchanged if there's no usable crossover point.

    Public attributes
    -----------------
    op_weights : dict[OP, int]
        The post-resolution weight table actually in use.
    last_trace : list[OpRecord]
        Populated when `trace=True`.
    last_trace_hash : str
        Populated when `trace=True`; empty string otherwise.
    """

    def __init__(
        self,
        rng: random.Random,
        dictionary: Optional[Dictionary] = None,
        structured_inserts: Optional[Sequence] = None,
        corpus: Optional[Callable[[], bytes]] = None,
        max_size: int = DEFAULT_MAX_SIZE,
        op_weights: Optional[dict] = None,
        pre_mutate: Optional[Callable[[bytes], bytes]] = None,
        post_process: Optional[Callable[[bytes], bytes]] = None,
        stack_min: int = 2,
        stack_max: int = 256,
        splice_prob: float = 0.15,
        trace: bool = False,
    ):
        self.rng = rng
        self.dictionary = dictionary
        self.corpus = corpus
        self.max_size = max(1, int(max_size))
        self.pre_mutate = pre_mutate
        self.post_process = post_process
        self.splice_prob = float(splice_prob)
        self.trace_enabled = bool(trace)

        # Normalize structured inserts: bare callables become
        # StructuredInsert("anon_N", fn, weight=1).
        self.structured_inserts: List[StructuredInsert] = []
        if structured_inserts:
            for i, s in enumerate(structured_inserts):
                if isinstance(s, StructuredInsert):
                    self.structured_inserts.append(s)
                else:
                    self.structured_inserts.append(
                        StructuredInsert(name=f"anon_{i}",
                                         factory=s, weight=1))
        self._structured_alias = [
            i for i, s in enumerate(self.structured_inserts)
            for _ in range(max(1, s.weight))
        ]

        # Resolve op weights: defaults -> user overrides -> backing
        # availability (last word).
        weights = dict(DEFAULT_OP_WEIGHTS)
        if op_weights:
            for k, v in op_weights.items():
                weights[OP(k)] = int(v)
        if not (dictionary and len(dictionary)):
            weights[OP.DICT_INSERT] = 0
            weights[OP.DICT_OVERWRITE] = 0
        if not self.structured_inserts:
            weights[OP.STRUCTURED_INSERT] = 0
            weights[OP.STRUCTURED_OVERWRITE] = 0
        self.op_weights = weights

        self._op_alias = [
            op for op, w in weights.items() if w > 0
            for _ in range(w)
        ]
        if not self._op_alias:
            raise ValueError(
                "no enabled ops -- check op_weights or supply a "
                "dictionary / structured inserts")

        # Stack-count alias: AFL's log-uniform 1 << (1 + r), bounded.
        self.stack_min = max(1, int(stack_min))
        self.stack_max = max(self.stack_min, int(stack_max))
        self._stack_choices = self._afl_stack_choices(
            self.stack_min, self.stack_max)

        # Op dispatch table.
        self._dispatch = {
            OP.BIT_FLIP:                self._op_bit_flip,
            OP.BYTE_FLIP:               self._op_byte_flip,
            OP.BYTE_ARITH:              self._op_byte_arith,
            OP.WORD_ARITH_LE:           self._op_word_arith_le,
            OP.WORD_ARITH_BE:           self._op_word_arith_be,
            OP.DWORD_ARITH_LE:          self._op_dword_arith_le,
            OP.DWORD_ARITH_BE:          self._op_dword_arith_be,
            OP.SET_INTERESTING_U8:      self._op_set_interesting_u8,
            OP.SET_INTERESTING_U16_LE:  self._op_set_interesting_u16_le,
            OP.SET_INTERESTING_U16_BE:  self._op_set_interesting_u16_be,
            OP.SET_INTERESTING_U32_LE:  self._op_set_interesting_u32_le,
            OP.SET_INTERESTING_U32_BE:  self._op_set_interesting_u32_be,
            OP.RANDOM_BYTE:             self._op_random_byte,
            OP.DELETE_CHUNK:            self._op_delete_chunk,
            OP.CLONE_CHUNK:             self._op_clone_chunk,
            OP.OVERWRITE_CHUNK:         self._op_overwrite_chunk,
            OP.SWAP_CHUNKS:             self._op_swap_chunks,
            OP.DICT_INSERT:             self._op_dict_insert,
            OP.DICT_OVERWRITE:          self._op_dict_overwrite,
            OP.STRUCTURED_INSERT:       self._op_structured_insert,
            OP.STRUCTURED_OVERWRITE:    self._op_structured_overwrite,
        }

        self.last_trace: List[OpRecord] = []
        self.last_trace_hash: str = ""

    @staticmethod
    def _afl_stack_choices(lo: int, hi: int) -> List[int]:
        # AFL: 1 << (1 + randint(0, 7)) -> {2,4,8,16,32,64,128,256}.
        choices = []
        v = 2
        while v <= hi:
            if v >= lo:
                choices.append(v)
            v *= 2
        if not choices:
            choices = [lo]
        return choices

    # ---- top-level entry --------------------------------------------------

    def mutate(self, src: bytes) -> bytes:
        """Return a mutated copy of `src`.

        Pipeline (in order):
          1. `pre_mutate(src)` if configured.
          2. With probability `splice_prob`, splice against
             `corpus()`.
          3. Stack 2..256 (AFL log-uniform) havoc ops.
          4. Length cap at `max_size`.
          5. `post_process(out)` if configured.
          6. If `trace`, compute `last_trace_hash`.
        """
        if self.pre_mutate is not None:
            src = self.pre_mutate(src)

        if (self.corpus is not None
                and self.splice_prob > 0.0
                and self.rng.random() < self.splice_prob):
            donor = self.corpus()
            if donor:
                src = self.splice(src, donor)

        buf = bytearray(src)
        if self.trace_enabled:
            self.last_trace = []

        n_ops = self.rng.choice(self._stack_choices)
        for _ in range(n_ops):
            self._apply_op(buf)
            if len(buf) > self.max_size:
                del buf[self.max_size:]

        out = bytes(buf)
        if self.post_process is not None:
            out = self.post_process(out)
            if len(out) > self.max_size:
                out = out[:self.max_size]

        if self.trace_enabled:
            h = hashlib.sha1()
            for r in self.last_trace:
                h.update(struct.pack("<HI", int(r.op), r.pos))
                h.update(r.payload)
            self.last_trace_hash = h.hexdigest()[:16]
        return out

    def havoc(self, src: bytes) -> bytes:
        """Run only the havoc stack.

        Skips splice, `pre_mutate`, `post_process`. Useful when the
        caller wants explicit control over splice scheduling.
        """
        buf = bytearray(src)
        if self.trace_enabled:
            self.last_trace = []
        n_ops = self.rng.choice(self._stack_choices)
        for _ in range(n_ops):
            self._apply_op(buf)
            if len(buf) > self.max_size:
                del buf[self.max_size:]
        return bytes(buf)

    def splice(self, a: bytes, b: bytes) -> bytes:
        """AFL-style splice: random crossover point between the first
        and last differing byte positions of `a` and `b`.

        Returns `a` unchanged when `a` and `b` have no differing bytes
        in their common prefix (so no usable crossover point exists).
        Either input being empty returns the other.
        """
        if not a:
            return bytes(b)
        if not b:
            return bytes(a)
        n = min(len(a), len(b))
        first = -1
        last = -1
        for i in range(n):
            if a[i] != b[i]:
                if first < 0:
                    first = i
                last = i
        if first < 0 or first == last:
            return bytes(a)
        p = self.rng.randint(first + 1, last)
        out = a[:p] + b[p:]
        if len(out) > self.max_size:
            out = out[:self.max_size]
        return bytes(out)

    # ---- op dispatch ------------------------------------------------------

    def _apply_op(self, buf: bytearray):
        op = self.rng.choice(self._op_alias)
        # Empty buffer: only ops that grow the buffer make sense.
        # Fall back to whichever growth-op is available.
        if not buf and op not in (
                OP.DICT_INSERT, OP.STRUCTURED_INSERT,
                OP.CLONE_CHUNK, OP.RANDOM_BYTE):
            if self.dictionary:
                op = OP.DICT_INSERT
            elif self.structured_inserts:
                op = OP.STRUCTURED_INSERT
            else:
                op = OP.RANDOM_BYTE
        try:
            self._dispatch[op](buf)
        except (IndexError, struct.error):
            # An op declined (buf too small for its width / empty
            # alias). Silently skip -- matches AFL behavior.
            return

    def _record(self, op: OP, pos: int, payload: bytes = b""):
        if self.trace_enabled:
            self.last_trace.append(OpRecord(int(op), pos, payload))

    # ---- bit/byte ops -----------------------------------------------------

    def _op_bit_flip(self, buf: bytearray):
        # Flip one bit. The cheapest interesting op.
        if not buf: return
        pos = self.rng.randrange(len(buf))
        bit = self.rng.randrange(8)
        buf[pos] ^= 1 << bit
        self._record(OP.BIT_FLIP, pos, bytes([bit]))

    def _op_byte_flip(self, buf: bytearray):
        # XOR a byte with 0xff. Faster than 8 bit_flips for the
        # all-bits-toggle case.
        if not buf: return
        pos = self.rng.randrange(len(buf))
        buf[pos] ^= 0xff
        self._record(OP.BYTE_FLIP, pos)

    def _op_byte_arith(self, buf: bytearray):
        # Add/sub a small delta mod 256. Hits off-by-one length
        # checks better than bit flips do.
        if not buf: return
        pos = self.rng.randrange(len(buf))
        delta = self.rng.randint(-ARITH_MAX, ARITH_MAX)
        if delta == 0: delta = 1
        buf[pos] = (buf[pos] + delta) & 0xff
        self._record(OP.BYTE_ARITH, pos, struct.pack("<b", delta))

    def _op_word_arith_le(self, buf: bytearray):
        # Add/sub on a 16-bit little-endian word.
        if len(buf) < 2: return
        pos = self.rng.randrange(len(buf) - 1)
        v = struct.unpack_from("<H", buf, pos)[0]
        delta = self.rng.randint(-ARITH_MAX, ARITH_MAX)
        if delta == 0: delta = 1
        struct.pack_into("<H", buf, pos, (v + delta) & 0xffff)
        self._record(OP.WORD_ARITH_LE, pos, struct.pack("<h", delta))

    def _op_word_arith_be(self, buf: bytearray):
        # Add/sub on a 16-bit big-endian word. Common in network
        # protocols.
        if len(buf) < 2: return
        pos = self.rng.randrange(len(buf) - 1)
        v = struct.unpack_from(">H", buf, pos)[0]
        delta = self.rng.randint(-ARITH_MAX, ARITH_MAX)
        if delta == 0: delta = 1
        struct.pack_into(">H", buf, pos, (v + delta) & 0xffff)
        self._record(OP.WORD_ARITH_BE, pos, struct.pack(">h", delta))

    def _op_dword_arith_le(self, buf: bytearray):
        if len(buf) < 4: return
        pos = self.rng.randrange(len(buf) - 3)
        v = struct.unpack_from("<I", buf, pos)[0]
        delta = self.rng.randint(-ARITH_MAX, ARITH_MAX)
        if delta == 0: delta = 1
        struct.pack_into("<I", buf, pos, (v + delta) & 0xffffffff)
        self._record(OP.DWORD_ARITH_LE, pos, struct.pack("<i", delta))

    def _op_dword_arith_be(self, buf: bytearray):
        if len(buf) < 4: return
        pos = self.rng.randrange(len(buf) - 3)
        v = struct.unpack_from(">I", buf, pos)[0]
        delta = self.rng.randint(-ARITH_MAX, ARITH_MAX)
        if delta == 0: delta = 1
        struct.pack_into(">I", buf, pos, (v + delta) & 0xffffffff)
        self._record(OP.DWORD_ARITH_BE, pos, struct.pack(">i", delta))

    def _op_set_interesting_u8(self, buf: bytearray):
        # Replace one byte with a known boundary value.
        if not buf: return
        pos = self.rng.randrange(len(buf))
        v = self.rng.choice(INTERESTING_U8)
        buf[pos] = v
        self._record(OP.SET_INTERESTING_U8, pos, bytes([v]))

    def _op_set_interesting_u16_le(self, buf: bytearray):
        if len(buf) < 2: return
        pos = self.rng.randrange(len(buf) - 1)
        v = self.rng.choice(INTERESTING_U16)
        struct.pack_into("<H", buf, pos, v)
        self._record(OP.SET_INTERESTING_U16_LE, pos,
                     struct.pack("<H", v))

    def _op_set_interesting_u16_be(self, buf: bytearray):
        if len(buf) < 2: return
        pos = self.rng.randrange(len(buf) - 1)
        v = self.rng.choice(INTERESTING_U16)
        struct.pack_into(">H", buf, pos, v)
        self._record(OP.SET_INTERESTING_U16_BE, pos,
                     struct.pack(">H", v))

    def _op_set_interesting_u32_le(self, buf: bytearray):
        if len(buf) < 4: return
        pos = self.rng.randrange(len(buf) - 3)
        v = self.rng.choice(INTERESTING_U32)
        struct.pack_into("<I", buf, pos, v)
        self._record(OP.SET_INTERESTING_U32_LE, pos,
                     struct.pack("<I", v))

    def _op_set_interesting_u32_be(self, buf: bytearray):
        if len(buf) < 4: return
        pos = self.rng.randrange(len(buf) - 3)
        v = self.rng.choice(INTERESTING_U32)
        struct.pack_into(">I", buf, pos, v)
        self._record(OP.SET_INTERESTING_U32_BE, pos,
                     struct.pack(">I", v))

    def _op_random_byte(self, buf: bytearray):
        # Plain random byte. Grows empty buffers by one byte.
        v = self.rng.randint(0, 255)
        if not buf:
            buf.append(v)
            self._record(OP.RANDOM_BYTE, 0, bytes([v]))
            return
        pos = self.rng.randrange(len(buf))
        buf[pos] = v
        self._record(OP.RANDOM_BYTE, pos, bytes([v]))

    # ---- chunk ops --------------------------------------------------------

    def _op_delete_chunk(self, buf: bytearray):
        # Delete a 1..MAX_BLOCK byte run. Essential for length
        # mismatch / truncation bugs.
        if len(buf) < 2: return
        n = self.rng.randint(1, min(MAX_BLOCK, len(buf) - 1))
        start = self.rng.randint(0, len(buf) - n)
        del buf[start:start + n]
        self._record(OP.DELETE_CHUNK, start, bytes([n]))

    def _op_clone_chunk(self, buf: bytearray):
        # Insert a copy of an existing region elsewhere in the
        # buffer. Grows the buffer by 1..MAX_BLOCK bytes.
        if not buf:
            v = self.rng.randint(0, 255)
            buf.append(v)
            self._record(OP.CLONE_CHUNK, 0, bytes([v]))
            return
        n = self.rng.randint(1, min(MAX_BLOCK, len(buf)))
        src_pos = self.rng.randint(0, len(buf) - n)
        dst_pos = self.rng.randint(0, len(buf))
        chunk = bytes(buf[src_pos:src_pos + n])
        buf[dst_pos:dst_pos] = chunk
        self._record(OP.CLONE_CHUNK, dst_pos, chunk)

    def _op_overwrite_chunk(self, buf: bytearray):
        # Overwrite a 1..MAX_BLOCK byte run. 70% clone-from-elsewhere,
        # 30% constant-fill -- AFL has these as two separate ops; we
        # collapse them with a coin flip to keep the op menu small.
        if len(buf) < 2: return
        n = self.rng.randint(1, min(MAX_BLOCK, len(buf)))
        dst_pos = self.rng.randint(0, len(buf) - n)
        if self.rng.random() < 0.7:
            src_pos = self.rng.randint(0, len(buf) - n)
            chunk = bytes(buf[src_pos:src_pos + n])
        else:
            val = self.rng.randint(0, 255)
            chunk = bytes([val] * n)
        buf[dst_pos:dst_pos + n] = chunk
        self._record(OP.OVERWRITE_CHUNK, dst_pos, chunk)

    def _op_swap_chunks(self, buf: bytearray):
        # Swap two non-overlapping equal-length regions. Useful for
        # state-machine reordering bugs (option A before option B vs.
        # the reverse).
        if len(buf) < 4: return
        n = self.rng.randint(1, min(MAX_BLOCK // 2, len(buf) // 2))
        a_pos = self.rng.randint(0, len(buf) - n)
        b_pos = self.rng.randint(0, len(buf) - n)
        if abs(a_pos - b_pos) < n:
            return
        a_chunk = bytes(buf[a_pos:a_pos + n])
        b_chunk = bytes(buf[b_pos:b_pos + n])
        buf[a_pos:a_pos + n] = b_chunk
        buf[b_pos:b_pos + n] = a_chunk
        self._record(OP.SWAP_CHUNKS, a_pos,
                     struct.pack("<II", b_pos, n))

    # ---- dictionary ops ---------------------------------------------------

    def _op_dict_insert(self, buf: bytearray):
        # Splice in a verbatim dictionary fragment.
        if not self.dictionary: return
        frag = self.dictionary.pick(self.rng)
        pos = self.rng.randint(0, len(buf)) if buf else 0
        buf[pos:pos] = frag
        self._record(OP.DICT_INSERT, pos, frag)

    def _op_dict_overwrite(self, buf: bytearray):
        # Paste a dictionary fragment over existing bytes (no length
        # change).
        if not self.dictionary or not buf: return
        frag = self.dictionary.pick(self.rng)
        if len(frag) > len(buf): return
        pos = self.rng.randint(0, len(buf) - len(frag))
        buf[pos:pos + len(frag)] = frag
        self._record(OP.DICT_OVERWRITE, pos, frag)

    # ---- structured ops ---------------------------------------------------

    def _pick_structured(self) -> StructuredInsert:
        return self.structured_inserts[
            self.rng.choice(self._structured_alias)]

    def _op_structured_insert(self, buf: bytearray):
        # Insert a freshly synthesized, structurally valid chunk.
        if not self.structured_inserts: return
        si = self._pick_structured()
        chunk = si.produce(self.rng)
        if not chunk: return
        pos = self.rng.randint(0, len(buf)) if buf else 0
        buf[pos:pos] = chunk
        self._record(OP.STRUCTURED_INSERT, pos, chunk)

    def _op_structured_overwrite(self, buf: bytearray):
        # Paste a freshly synthesized chunk over existing bytes.
        if not self.structured_inserts or not buf: return
        si = self._pick_structured()
        chunk = si.produce(self.rng)
        if not chunk or len(chunk) > len(buf): return
        pos = self.rng.randint(0, len(buf) - len(chunk))
        buf[pos:pos + len(chunk)] = chunk
        self._record(OP.STRUCTURED_OVERWRITE, pos, chunk)


# ---------------------------------------------------------------------------
# CLI / self-test
# ---------------------------------------------------------------------------

def _selftest() -> int:
    """Built-in correctness checks. Exit 0 on success, nonzero on
    failure with a printed diagnostic."""

    print("[selftest] determinism ...", end=" ", flush=True)
    rng_a = random.Random(42)
    rng_b = random.Random(42)
    eng_a = Engine(rng_a)
    eng_b = Engine(rng_b)
    seed = b"AAAAAAAA" * 8
    out_a = [eng_a.mutate(seed) for _ in range(20)]
    out_b = [eng_b.mutate(seed) for _ in range(20)]
    assert out_a == out_b, "determinism broken"
    print("ok")

    print("[selftest] max_size cap ...", end=" ", flush=True)
    rng = random.Random(1)
    eng = Engine(rng, max_size=128)
    for _ in range(200):
        out = eng.mutate(b"x" * 100)
        assert len(out) <= 128, f"cap broken: {len(out)}"
    print("ok")

    print("[selftest] empty input ...", end=" ", flush=True)
    rng = random.Random(2)
    eng = Engine(rng, dictionary=Dictionary([b"\x01\x02\x03"]))
    for _ in range(20):
        out = eng.mutate(b"")
        assert isinstance(out, bytes)
    print("ok")

    print("[selftest] no-dict/no-inserts works ...", end=" ", flush=True)
    rng = random.Random(3)
    eng = Engine(rng)
    for _ in range(20):
        eng.mutate(b"hello world")
    print("ok")

    print("[selftest] op weights honored ...", end=" ", flush=True)
    rng = random.Random(4)
    w = {op: 0 for op in OP}
    w[OP.BIT_FLIP] = 1
    eng = Engine(rng, op_weights=w, stack_min=1, stack_max=1)
    for _ in range(50):
        out = eng.mutate(b"A" * 32)
        assert len(out) == 32
        diff = bytes(a ^ b for a, b in zip(out, b"A" * 32))
        popcount = sum(bin(b).count("1") for b in diff)
        assert popcount == 1, f"expected 1-bit diff, got {popcount}"
    print("ok")

    print("[selftest] splice degrades ...", end=" ", flush=True)
    rng = random.Random(5)
    eng = Engine(rng)
    assert eng.splice(b"AAA", b"AAA") == b"AAA"
    assert eng.splice(b"", b"BBB") == b"BBB"
    assert eng.splice(b"AAA", b"") == b"AAA"
    s = eng.splice(b"AAA", b"BBB")
    assert s in (b"ABB", b"AAB"), f"unexpected splice: {s!r}"
    print("ok")

    print("[selftest] AFL dict parse ...", end=" ", flush=True)
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".dict",
                                     delete=False) as fh:
        fh.write('# comment\n')
        fh.write('greet="hello"\n')
        fh.write('iac_do_ttype="\\xff\\xfd\\x18"\n')
        fh.write('crlf="\\r\\n"\n')
        path = fh.name
    try:
        d = parse_afl_dict(path)
        assert len(d) == 3
        assert b"hello" in d.fragments
        assert b"\xff\xfd\x18" in d.fragments
        assert b"\r\n" in d.fragments
    finally:
        os.unlink(path)
    print("ok")

    print("[selftest] trace + hash ...", end=" ", flush=True)
    rng = random.Random(6)
    eng = Engine(rng, trace=True, stack_min=4, stack_max=4)
    eng.mutate(b"hello world")
    assert len(eng.last_trace) == 4
    assert len(eng.last_trace_hash) == 16
    print("ok")

    print("[selftest] structured insert ...", end=" ", flush=True)
    rng = random.Random(7)
    def make_sb(r):
        return b"\xff\xfa\x1f\x00\x00\x00\x18\xff\xf0"
    w = {op: 0 for op in OP}
    w[OP.STRUCTURED_INSERT] = 1
    eng = Engine(
        rng,
        structured_inserts=[StructuredInsert("sb", make_sb, weight=1)],
        op_weights=w, stack_min=1, stack_max=1)
    out = eng.mutate(b"x")
    assert b"\xff\xfa\x1f" in out, f"structured chunk missing: {out!r}"
    print("ok")

    print("[selftest] ALL PASSED")
    return 0


def _cli() -> int:
    ap = argparse.ArgumentParser(
        prog="mutate.py",
        description=(
            "suzzer generic AFL++-style mutation engine. Use "
            "--selftest to verify, or --seed/--out/--count to dump "
            "mutants for tooling."))
    ap.add_argument("--selftest", action="store_true",
                    help="run built-in correctness checks and exit")
    ap.add_argument("--seed", type=Path,
                    help="seed input file")
    ap.add_argument("--out", type=Path,
                    help="output directory (will be created)")
    ap.add_argument("--count", type=int, default=100,
                    help="number of mutants to emit (default 100)")
    ap.add_argument("--dict", type=Path, action="append", default=[],
                    help="AFL-format dictionary; repeat for multiple")
    ap.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE,
                    help="hard cap on mutant length")
    ap.add_argument("--seed-rng", type=int, default=0xC0FFEE,
                    help="RNG seed for reproducibility")
    ap.add_argument("--splice-from", type=Path,
                    help="corpus dir whose files become splice donors")
    ap.add_argument("--splice-prob", type=float, default=0.15,
                    help="splice probability per mutate() call")
    ap.add_argument("--weights", type=Path,
                    help="JSON file: {op_name: int_weight} overrides")
    ap.add_argument("--trace", action="store_true",
                    help="print per-mutant op-trace hash to stderr")
    args = ap.parse_args()

    if args.selftest:
        return _selftest()

    if not args.seed or not args.out:
        ap.error("--seed and --out are required (unless --selftest)")

    seed_data = args.seed.read_bytes()
    args.out.mkdir(parents=True, exist_ok=True)

    dictionary = None
    if args.dict:
        dictionary = Dictionary()
        for p in args.dict:
            d = parse_afl_dict(p)
            for frag, w in zip(d.fragments, d.weights):
                dictionary.add(frag, w)

    corpus_cb = None
    if args.splice_from:
        donors = [p.read_bytes()
                  for p in sorted(args.splice_from.iterdir())
                  if p.is_file()]
        if donors:
            donor_rng = random.Random(args.seed_rng ^ 0xD0D0D0)
            corpus_cb = lambda: donor_rng.choice(donors)

    weights = None
    if args.weights:
        raw = json.loads(args.weights.read_text())
        weights = {OP[k]: int(v) for k, v in raw.items()}

    rng = random.Random(args.seed_rng)
    eng = Engine(
        rng, dictionary=dictionary, corpus=corpus_cb,
        max_size=args.max_size, op_weights=weights,
        splice_prob=args.splice_prob, trace=args.trace)

    width = len(str(max(0, args.count - 1))) or 1
    for i in range(args.count):
        out = eng.mutate(seed_data)
        (args.out / f"{i:0{width}d}.bin").write_bytes(out)
        if args.trace:
            print(f"{i:0{width}d}\t{eng.last_trace_hash}",
                  file=sys.stderr)
    print(f"[ok] wrote {args.count} mutants to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
