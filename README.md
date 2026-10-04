# libcov (suzzer)

A trap-trampoline coverage library for embedded Linux fuzzing. Two
threading variants are built as separate LEGO bricks:

- **`libcov_st.so`** -- single-threaded, low overhead, smallest possible
  surface area.
- **`libcov_mt.so`** -- thread-safe: per-thread TLS prev_loc, atomic
  saturating bitmap, atomic per-site state machine (spinlock-serialized
  writes), single-copy-atomic stores into code pages made R|W|X once at
  init, then per-write cache maintenance plus `membarrier(SYNC_CORE)`
  for cross-CPU instruction visibility.

Both variants share the same backends across 11 architectures. Pick the
brick that fits your target.

## Idea

Replace selected instructions in a target binary with an architecture's
trap-raising encoding. When the CPU traps, our `LD_PRELOAD`-injected
signal handler:

1. Reads the faulting PC from `ucontext`.
2. Emits an AFL-style edge into a shared bitmap (auto-sized from the
   patch count by default -- see [Coverage model](#coverage-model)).
3. Restores the original instruction so execution continues.

No JIT, no embedded interpreter, no ptrace, no kernel module. Just libc +
sigaction + mprotect. Suitable for memory-constrained embedded targets
where Frida or DynamoRIO are too heavy.

## Supported backends

Every backend raises `LIBCOV_TRAP_SIGNO` (= `SIGILL` by default). Every
encoding below is the *shipped default* and is overridable via the
per-backend tunables header (see [Tunables](#tunables)).

| Backend           | Default trap insn        | Patch len | Notes                                   |
|-------------------|--------------------------|-----------|-----------------------------------------|
| x86_64            | UD2 (`0F 0B`)            | 2         | Head-only; MT sites can't span a 64B line |
| aarch64           | UDF #0 (`0x00000000`)    | 4         |                                         |
| arm (ARM mode)    | UDF `0xE7F000F0`         | 4         |                                         |
| arm (Thumb mode)  | UDF.N `0xDE00`           | 2         | Per-function bits=16 detection          |
| mips, mipsel      | user-mode `MFC0 $0,$0`   | 4         | Was BREAK 0 / SIGTRAP; skips delay slots|
| mips64, mips64el  | user-mode `MFC0 $0,$0`   | 4         | Same rationale as mips32                |
| powerpc           | all-zero (`0x00000000`)  | 4         | Was `tw 31,0,0` / SIGTRAP               |
| powerpc64 BE+LE   | all-zero (`0x00000000`)  | 4         | Was `tw 31,0,0` / SIGTRAP               |
| riscv64           | c.unimp (`0x0000`)       | 2 or 4    | Mixed 2-byte (C) / 4-byte insns         |

All backends validated end-to-end under `qemu-<arch>-static`:
`test/run_cross.sh`.

## Build

```
make                                    # native ST build
make THREADING=mt                       # native MT build
make ARCH=aarch64                       # cross-build ST for aarch64
make ARCH=aarch64 THREADING=mt          # cross-build MT for aarch64
make all-arch                           # ST for every supported backend
make all-arch THREADING=mt              # MT for every supported backend
make all-variants                       # ST and MT for every backend
make test                               # build everything, run every native suite
```

Outputs land in `build/<arch>/libcov_<threading>.so` (and
`build/<arch>/target_simple` for the ST test target;
`build/<arch>/target_simple_mt` for the pthread stress target via
`make -C test ... mt`).

## Tunables

Build-time configuration lives in two layers of headers, each using the
same `#ifndef`-guard pattern. There are two ways to change a default and
either is fine — `-D` wins because the preprocessor sees it first:

1. **Edit the value in the header**, next to the `#define`.
2. **Pass `-D` on the build line**, e.g.
   `make EXTRA_CFLAGS='-DLIBCOV_ARCH_MIPS_ILLEGAL=0xDEADBEEFu'`.

| Concern                                                     | Header                  |
|-------------------------------------------------------------|-------------------------|
| Trap signal, bitmap size, **N-gram width**, log buffer      | `src/tunables.h`        |
| x86_64 illegal encoding / widths                            | `src/tunables_x86_64.h` |
| aarch64 illegal encoding / widths                           | `src/tunables_aarch64.h`|
| arm + Thumb illegal encodings / widths                      | `src/tunables_arm.h`    |
| MIPS / MIPS64 illegal encodings / widths                    | `src/tunables_mips.h`, `src/tunables_mips64.h` |
| PowerPC / PowerPC64 illegal encodings                       | `src/tunables_powerpc.h`, `src/tunables_powerpc64.h` |
| RISC-V illegal encodings / widths                           | `src/tunables_riscv64.h`|

Each tunables file opens with a banner explaining both override paths;
each individual knob carries its own doc block (purpose, default,
override syntax, constraints). The headers are the source of truth for
the configurable surface area — there is no separate options table.

**Worked example: retarget the MIPS illegal encoding for a chip rev
that traps the default differently.** Either:

```sh
# (a) edit the default in the header
$EDITOR src/tunables_mips.h    # change LIBCOV_ARCH_MIPS_ILLEGAL
make ARCH=mips

# (b) or override at build time without touching the file
make ARCH=mips \
    EXTRA_CFLAGS='-DLIBCOV_ARCH_MIPS_ILLEGAL=0xDEADBEEFu'
```

Note: `src/patchlist_format.h` (renamed from `src/config.h`) is the
on-disk patch-list wire format and the runtime `patch_entry` struct —
**not** a tunables header.

## Quick start

```
# 1. build for your target's architecture (default ST; add THREADING=mt for MT)
make ARCH=aarch64

# 2. generate a patch list. --threading st by default; --threading mt for
#    libcov_mt.so (the two patch lists are not interchangeable and the
#    library refuses a mismatched LCV3 hint).
./tools/gen_patchlist.py build/aarch64/target_simple /tmp/t.lcv \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline)$'

# 3. run the target under libcov_st
LIBCOV_PATCHLIST=/tmp/t.lcv \
LIBCOV_SHM_PATH=/tmp/cov \
LIBCOV_MODE=leapfrog \
LD_PRELOAD=./build/aarch64/libcov_st.so \
    qemu-aarch64-static -L /usr/aarch64-linux-gnu \
    -E LD_PRELOAD=$PWD/build/aarch64/libcov_st.so \
    build/aarch64/target_simple 42
```

The shm region (header + bitmap + snapshot ring) is written to `/tmp/cov`
(or whatever path `LIBCOV_SHM_PATH` points at). An external fuzzer mmaps
the same file/SHM and reads hit-counts. **Read `map_size` and
`bitmap_offset` from the header** -- the bitmap is not a fixed 64 KB.

**Boundary mode and the live bitmap.** When boundaries are active
(`LIBCOV_SHM_FLAG_ACTIVE` set), whether the live bitmap at `bitmap_offset`
is meaningful depends on the threading variant, and the header says which:
in the **ST** build emits rotate through ring slots and `bitmap_offset`
stays zero -- the header sets `LIBCOV_SHM_FLAG_LIVE_EMPTY`, and a legacy
cumulative-bitmap driver must read the ring (below) instead. In the **MT**
build `bitmap_offset` still accumulates non-worker / pre-first-boundary
coverage (flag clear). With boundaries off, `bitmap_offset` is the single
cumulative map as before.

## Selective instrumentation (call-graph slicing)

Real-world fuzz targets rarely need every function in the binary
instrumented; the interesting coverage lives in the input-parsing and
state-machine code reached from the request handler. The generator
supports hand-picking that region with three flags:

```
--root SYM_OR_ADDR     # BFS seed: function name or address (repeatable)
--cutoff SYM_OR_ADDR   # boundary: excluded and not traversed (repeatable)
--max-depth N          # bound BFS to N call-edges below each root
--print-reachable      # dump the slice to stderr and exit (dry-run)
```

The slice is built from rizin's static call graph (`afij` callrefs). PLT
stubs and library imports are automatically out-of-graph and so act as
implicit cutoffs at the library boundary. When `--root` is combined with
`--include-pat` / `--exclude-pat` the result is their **intersection**:
a function must be both reachable from a root AND pass the regex filter
to be instrumented.

### Resolution rules for SYM_OR_ADDR

- `0x401234` / `401234` / `4198964` → address. If the address is inside a
  function but not at its entry, the enclosing function's entry is used
  (with a note printed to stderr). An address past the end of the
  function below it (a typo, or another module's address) is an error.
- `main` → tries exact match, then `dbg.main`, `sym.main`, `fcn.main`,
  `sym.imp.main`, then matches the last dotted segment of any function
  name. Ambiguous suffix matches are an error.
- `dbg.parse_request` → exact rizin name.

With `--module`, each module is sliced on its own call graph: calls into
another module go through its PLT and aren't followed, so give each
module you want instrumented its own root.

- An unqualified name resolves in every module that defines it (the
  executable's `sym.imp.NAME` PLT stub doesn't count). A name no module
  defines is an error.
- An unqualified address means the primary binary; module address ranges
  overlap.
- `MODULE!NAME` pins a root or cutoff to one module (the name given to
  `--module`, or its file's basename), e.g. `--root 'libfoo.so!parse'`.
- A module that no root resolves in is not instrumented, with a warning.
- `--print-reachable` lists every module's slice under a
  `module[i] 'name'` header.

### Example

```
# Iterate on the slice first (no patchlist written):
./tools/gen_patchlist.py build/x86_64/target_simple /dev/null \
    --root main \
    --cutoff cmdline \
    --print-reachable -v

# Then write the patchlist:
./tools/gen_patchlist.py build/x86_64/target_simple /tmp/t.lcv \
    --root main \
    --cutoff cmdline \
    --max-depth 4

# Executable plus one library, each with its own root:
./tools/gen_patchlist.py build/x86_64/target_multimod /tmp/m.lcv \
    --module libmultimod_helper.so:build/x86_64/libmultimod_helper.so \
    --root main --root 'libmultimod_helper.so!helper_classify'
```

### Known limits

- **Indirect calls** (function pointers, vtables, dispatch tables) are
  invisible to rizin's static analysis. Slices through them require
  another `--root` at the callee. Every `--root` run prints how many
  indirect calls and jumps the slice contains, and `--print-reachable`
  marks the functions that have them.
- **ppc64 ELFv1 functions whose body starts with a `nop`** show up in
  rizin as `fcn.<entry+4>`. Both generators rename them after their
  `.opd` symbol (`dbg.NAME`, or `sym.NAME` without DWARF), so name
  filters, `--root` and markers work; `--print-reachable` shows the
  entry+4 address.
- **Tail calls** lowered to `jmp` may or may not appear as `CALL`
  callrefs depending on rizin's classification. Verify a suspect slice
  with `--print-reachable`.
- **Cutoffs are function-granular**. Excising a single basic block
  inside a function is a future feature (see `TODO.md`).
- **Recursion bounds matter** for huge binaries. `--max-depth` is the
  primary throttle; without it a `--root main` on a 5000-function
  binary will likely BFS the entire executable.

## Environment variables

| Var | Default | Meaning |
|---|---|---|
| `LIBCOV_PATCHLIST` | *(required)* | Path to LCV3 patch list. If unset, the library is inert. |
| `LIBCOV_REQUIRE` | unset | `1`: abort the process if libcov ends up inert or any init step fails (unset patch list, unresolvable module, trap self-test failure, refused boundary config). Off by default because children that inherit `LD_PRELOAD` are usually meant to run inert. |
| `LIBCOV_SHM_PATH` | `/libcov_<pid>` | Bitmap path. Leading `/` and no other slashes → `shm_open`; otherwise a filesystem path. Falls back to `$TMPDIR/<name>` if `shm_open` fails. `%p` expands to the pid (`%%` to `%`), giving each process of a forking/re-execing daemon its own region. See "Re-exec and fork+exec". |
| `LIBCOV_ST_PATCH` | `auto` | `libcov_st.so` only. `auto`: make patched code pages `R|W|X` once at init, so arming/disarming is a plain store (no syscalls per trap, about 3x faster in leapfrog); falls back to `mprotect` if the kernel refuses `R|W|X`. `mprotect`: two `mprotect` calls per arm/disarm, code pages never writable and executable at once. |
| `LIBCOV_MODE` | `leapfrog` | `oneshot` (each site fires once, fastest) or `leapfrog` (re-arm previous site each trap; gives hit counts). |
| `LIBCOV_MODULE` | the main executable | Module name for boundary-mode sidecar resolution only. The patch list itself carries its own module name table (LCV3) so this only affects `LIBCOV_BOUNDARY_LIST` lookups. A bare name or an absolute path, as for `LIBCOV_MODULE_RENAME`. |
| `LIBCOV_MODULE_RENAME` | unset | `old=new[,old=new…]`: resolve patch-list module `old` as `new`. For a binary run under another name than it was generated from (`target=target.stripped`), or, with an absolute path as `new`, to pick one of several mapped files with the same basename. |
| `LIBCOV_LOG` | unset (stderr) | Diagnostic log. Never written from the signal handler; after init, only while the fd still refers to the same non-socket file (see Hardening). |
| `LIBCOV_BOUNDARY_LIST` | unset | Path to LCVB1 iteration-boundary sidecar. Iteration framing is inert if unset. |
| `LIBCOV_BOUNDARY_REARM` | `none` | `none` / `all` / `touched`. What to re-arm at each boundary fire. |
| `LIBCOV_BOUNDARY_RING` | `8` | Number of snapshot slots (2..16), each one `map_size` bytes. Driver lag tolerance = `RING - 1` iterations. |
| `LIBCOV_BOUNDARY_INIT_GRACE` | `0` | Drop the first N boundary fires (process-wide, across all threads) before publishing (skip init noise). |
| `LIBCOV_BOUNDARY_NOTIFY_FD` | unset | Inherited **eventfd**; libcov writes 8 bytes after each snapshot. Anything else (e.g. a pipe, which could block or SIGPIPE the target inside the trap handler) is ignored with a warning. Counter polling works without it. |
| `LIBCOV_BOUNDARY_EMULATE` | `1` | `0`: never emulate boundary markers; always use disarm + deferred re-arm (see Threading). |
| `LIBCOV_SYNC_FALLBACK` | `auto` | `libcov_mt.so` only. Cross-core sync when the kernel lacks `membarrier(PRIVATE_EXPEDITED_SYNC_CORE)`: `auto` broadcasts `LIBCOV_SYNC_SIGNO` (default `SIGRTMAX-2`, `src/tunables.h`) to every peer thread after each patch batch; `tgkill` forces that even when SYNC_CORE works; `off` relies on cache maintenance alone. The broadcast is slow (about 10x on a 16-thread stress) and can make non-restarting syscalls return `EINTR`; see Design.md §17.2.5. |
| `LIBCOV_ALLOW_ONESHOT_NOREARM` | unset | `1`: allow `MODE=oneshot` with `BOUNDARY_REARM=none` (first-hit-only snapshots). Otherwise that combination is refused and boundaries stay off. |

## Coverage model

`LIBCOV_COVERAGE_MODEL_SITE` in `src/tunables.h` picks how a trap becomes
a bucket index:

- `1` (**default**) -- **site-id**: each patch record's index in the
  patch list is its id. The bitmap auto-sizes to
  `next_pow2(n_sites * LIBCOV_MAP_FUDGE)` (clamped by
  `LIBCOV_MAP_MIN_POW2`/`MAX_POW2`, never below `next_pow2(n_sites)`),
  so at N=1 there are zero collisions. At N>=2 the history is folded in
  and collisions become possible again (bump `LIBCOV_MAP_FUDGE` for
  path-sensitive work).
- `0` -- legacy **hashed-PC**: `hash(pc - module_base)` into a fixed
  `1 << LIBCOV_MAP_SIZE_POW2` (64 KB) map.

## Coverage scheme (N-gram)

How much history goes into a bucket index is configurable at build time
through `LIBCOV_NGRAM_N` (and `LIBCOV_NGRAM_ROTATE`) in `src/tunables.h`.
`cur` below is the site id (site-id model) or `hash(pc)` (hashed-PC model).
The bitmap layout (size, hash, saturating uint8 counters, atomic emit
under MT) is identical across all settings — readers, AFL-style
drivers, and the snapshot ring need no changes.

| `LIBCOV_NGRAM_N` | Scheme            | Index formula                                  | When to use                                 |
|------------------|-------------------|------------------------------------------------|---------------------------------------------|
| `1`              | Block coverage    | `idx = cur`                                    | Lowest overhead; "did this block run" only. |
| `2` (**default**)| AFL-style edges   | `idx = cur ^ prev[0]`                          | Hashed-PC model: bit-identical to historical libcov. |
| `3..8`           | N-gram coverage   | `idx = cur ^ prev[0] ^ ... ^ prev[N-2]`        | Path-sensitive; distinguishes loop trips, dispatch sequences, and call-chain variants the same edge map collapses. |

```sh
# Block coverage (cheapest):
make EXTRA_CFLAGS='-DLIBCOV_NGRAM_N=1'

# 4-gram coverage:
make EXTRA_CFLAGS='-DLIBCOV_NGRAM_N=4'

# 8-gram with per-position rotation (defeats A,B,C == B,A,C history-permutation collisions;
# recommended for any N >= 3):
make EXTRA_CFLAGS='-DLIBCOV_NGRAM_N=8 -DLIBCOV_NGRAM_ROTATE=1'
```

Cost is roughly `N-1` extra XORs and `N-1` TLS stores per emit — well
below the SIGILL trap entry cost on every architecture. Constraints:
`N` in `[1, 8]` (enforced via a compile-time `_Static_assert`); higher
caps inflate TLS pressure and collision rate without proportional
sensitivity gain. The window is cleared at each iteration boundary
under boundary mode and at process init under either threading
variant. The two knobs are documented in detail next to their
`#define`s in `src/tunables.h`.

## Modes

Two orthogonal axes:

**Per-trap mode** (`LIBCOV_MODE`)

- `oneshot` -- On the first trap at site X, restore the original
  instruction and leave it alone. Fastest; gives "edge-was-reached"
  coverage with no hit-count. Recommended for the corpus-explore phase
  of fuzzing. Safe under `libcov_mt.so`, and under `libcov_st.so` for
  single-threaded targets only (see Leapfrog below).
- `leapfrog` -- On trap at X, restore X *and* re-arm the previously
  restored site. Lets the bitmap accumulate hit counts on hot edges
  and gives full per-iter edge sets when used with the boundary
  mechanism. Higher overhead.
  - Under `libcov_st.so`: safe only for single-threaded targets.
  - Under `libcov_mt.so`: safe under arbitrary thread counts. Each
    thread leapfrogs through its own TLS `g_last_restored`; per-entry
    spinlocks serialize concurrent arm/disarm byte writes; the AFL
    bitmap uses saturating atomic increments; cross-CPU instruction
    visibility comes from `clear_cache` after each write plus one
    `membarrier(SYNC_CORE)` per batch.

**Boundary re-arm policy** (`LIBCOV_BOUNDARY_REARM`, ignored when no
boundary list is loaded)

- `none` -- boundaries publish snapshots and clear the live bitmap; no
  extra re-arming. Correct default with `MODE=leapfrog` (leapfrog
  handles re-arm internally).
- `all` -- on each boundary fire, re-arm every disarmed site in the
  patch table. Heaviest, but gives full per-iter edge sets even in
  `MODE=oneshot`.
- `touched` -- on each boundary fire, re-arm only the sites that have
  trapped since the previous boundary fire (on any thread). Mid-cost
  between `none` and `all`; same per-iter semantics as `all` in
  practice.

Recommended pairings:

| `MODE` | `BOUNDARY_REARM` | When |
|---|---|---|
| `leapfrog` | `none` | Default for boundary mode. Per-iter bitmaps with full edge sets. |
| `oneshot` | `all` or `touched` | Many traps per iteration, cheaper than leapfrog's per-trap cost. |
| `oneshot` | `none` | **Anti-pattern** when boundaries are active -- per-iter bitmaps go empty after warmup. libcov refuses it (logs an ERROR, boundaries stay off) unless `LIBCOV_ALLOW_ONESHOT_NOREARM=1`. |
| `leapfrog` | `all` / `touched` | Redundant; leapfrog already re-arms. Allowed but no benefit. |

## Iteration boundaries

For long-running targets (network daemons, persistent fuzz harnesses)
libcov needs to know when one logical "fuzz iteration" ends and the next
begins. That knowledge is target-specific, so libcov exposes the
mechanism (marker detection + snapshot + re-arm) but pushes the policy
(which addresses are markers) into a per-target sidecar file (LCVB1).

### Snapshot ring

The shm region grows beyond the live bitmap:

```
offset                       contents
0                            struct libcov_shm_header  (72 B with x86_64 alignment)
bitmap_offset                live bitmap               (map_size bytes)
ring_offset                  RING * slot_stride        (per-iter snapshots)
```

Each ring slot is preceded by a 32-byte header carrying `slot_gen`,
`tid`, a publish timestamp and `flags`, which say what the snapshot
holds (exactly one bit is set; see "Marker semantics"):

| Flag | Value | Snapshot |
|---|---|---|
| `LIBCOV_SLOT_FLAG_INIT` | 1 | startup up to the first boundary (`gen_init`) |
| `LIBCOV_SLOT_FLAG_ITER` | 2 | one iteration (one input) |
| `LIBCOV_SLOT_FLAG_GAP` | 4 | paired mode: the harness code between an `END` and the next `BEGIN` |

A fuzzer that wants one snapshot per input keeps the `ITER` slots.
Drivers read snapshots via a seqlock pattern:

1. Read `hdr->gen_current` with acquire ordering -- this is the highest
   completed iteration.
2. Pick slot = `ring[target_gen % ring_size]`.
3. Read `slot->slot_gen` with acquire ordering. If != `target_gen` the
   slot's content belongs to a different generation; retry.
4. `memcpy` the bitmap out of the slot.
5. Read `slot->slot_gen` again. If it still equals `target_gen` the
   bitmap you copied is for `target_gen`; commit. If not, the writer
   started overwriting your slot mid-read; retry.
6. If `hdr->gen_current - target_gen >= ring_size`, the writer has
   advanced past your window: data is lost. Skip ahead to the oldest
   generation still readable (`gen_current - ring_size + 2`: under ST
   the writer is already filling the slot after `gen_current`) and
   report it.

`fuzz_driver` counts overruns and lost generations, prints them in its
exit summary together with `publish_dropped` (MT publishes libcov had
to drop because a newer generation held the slot), and exits 3 if any
coverage was lost. `FUZZ_DRIVER_BURST=1` feeds every input before
reading anything, which makes an overrun of a small ring reproducible.

`test/fuzz_driver.c` implements this in `read_slot`. There's no way to
misattribute a snapshot to the wrong iteration -- the slot's own stamp
is the source of truth.

### Marker semantics

Two modes inferred from the sidecar contents:

- **begin-only** -- the sidecar contains only `BEGIN` markers. Every
  marker hit fires a boundary; depth tracking is collapsed (no `END`
  marker to balance the tree). Recursion guards do not work in this mode.
- **paired** -- the sidecar contains at least one `END` marker. Depth
  is tracked per-iteration; `depth_filter=zero` markers fire only at
  depth 0 (skipping recursive sub-calls). Useful for nested request
  handlers.

What each boundary publishes, as tagged in the slot `flags`:

- The first boundary in the process publishes the startup coverage:
  `INIT`.
- Begin-only: every later `BEGIN` publishes the iteration it ends:
  `ITER`. So N inputs give INIT + N ITER; in `fuzz_driver`'s stdin loop
  the last one arrives at EOF, when the loop's final `BEGIN` fires.
- Paired: an `END` publishes the `BEGIN..END` span: `ITER`. A `BEGIN`
  at depth 0 publishes what ran since the previous `END` (reading the
  next input, logging, bookkeeping): `GAP`. So N inputs give INIT, then
  ITER and GAP alternating, N of each. A `GAP` is coverage too (nothing
  is dropped) but belongs to no input; skip it to score inputs. With
  `depth_filter=any`, a nested boundary publishes the segment since the
  previous one as `ITER`.

`fuzz_driver` and `ring_dump` print each snapshot's kind
(`kind=init|iter|gap`), and `fuzz_driver`'s exit summary counts them.

For begin-only markers, the marker function's body must include
something that produces a multi-byte branch instruction (>= the arch's
trap-encoding length). `gen_patchlist.py` patches basic-block
terminators, and a straight-line function ending in a single short
return won't get patched -- so the boundary would never fire.
`test/target_loop.c` shows the canonical pattern: an unreachable
conditional branch inside `iter_begin` forces a 2-byte `jcc` that
gen_patchlist picks up.

### Where init coverage goes

The first boundary hit captures whatever was emitted during process
startup (constructor, target init, the first `fgets()`, etc.) into the
ring slot for `gen=1` and records `hdr->gen_init = 1`. The driver can
read that slot once and either include init in its baseline or exclude
it from per-input attribution.

### Threading

Per-thread state is `__thread` under `libcov_mt.so`: the depth counter
and the live bitmap itself.

- **Worker threads get private live bitmaps.** A thread's first boundary
  fire switches it from the shared bitmap to its own; every later fire
  copies that into a ring slot (stamped with the thread's `tid`) and
  clears it. A snapshot therefore holds exactly one thread's iteration,
  however many workers run concurrently. That thread's first fire
  publishes nothing (its earlier coverage isn't attributable to an
  iteration), except for the first fire in the process, which publishes
  the init snapshot.
- **Other threads** (acceptors, timers, anything that never hits a
  marker) keep emitting into the shared bitmap at `bitmap_offset`, which
  under MT boundary mode is a cumulative map of non-iteration coverage.
  (Under ST boundary mode that area is unused.)
- **Markers are emulated (every backend).** The trap handler
  performs the marker's original instruction itself and moves the PC
  past it, so the marker is never disarmed and no worker can pass it
  untrapped. Supported forms:
  - x86_64: `jmp`/`jcc` rel8/rel32, `endbr64`, `nop`;
  - aarch64: `b`, `bl`, `b.cond`, `cbz`/`cbnz`, `tbz`/`tbnz`, `nop`, `bti`;
  - arm: `b`/`bl` (any condition), `nop`; Thumb: `b` (all four
    encodings), `bl`, `cbz`/`cbnz`, `nop`/`nop.w`, IT blocks honoured;
  - riscv64: `jal`, `jalr`, `beq`..`bgeu`, `nop`, and the compressed
    `c.j`, `c.jr`, `c.jalr`, `c.beqz`/`c.bnez`, `c.nop`;
  - powerpc, powerpc64: `b`/`bl`/`ba`, `bc` (CR and CTR forms), `bclr`
    (`blr`), `bcctr` (`bctr`), `nop`;
  - mips, mips64: MIPS markers sit on the function's entry instruction
    (the generator's MIPS entry strategy; delay slots rule out branches),
    which is a prologue ALU op, so the register-only ones are emulated:
    `lui`, `addiu`, `ori`, `andi`, `xori`, `addu`, `subu`, `and`, `or`
    (`move`), `xor`, `nor`, `sll` (`nop`, `ehb`), and on mips64 `daddiu`,
    `daddu`, `dsubu`. A marker on anything else (a store, say) uses the
    fallback below.

  Init logs `N of M marker(s) emulated`. `LIBCOV_BOUNDARY_EMULATE=0`
  turns this off.
- **Other markers are re-armed process-wide** (other backends, or an
  instruction the emulator doesn't decode): by any thread's trap, once
  every thread that trapped on the marker has trapped again somewhere
  else (proof it executed the marker's original instruction), or after
  `LIBCOV_MARKER_REARM_TIMEOUT_NS` (`src/tunables.h`, 1 ms) if one
  hasn't. Re-arming any sooner makes that thread re-trap and fire a
  spurious, near-empty boundary.
- **`REARM=touched` is process-wide:** a boundary re-arms every site any
  thread disarmed since the last boundary. (Per-thread sets starved
  under oneshot: workers kept disarming each other's re-armed sites
  until no thread trapped and boundaries stopped.)
- **MT coverage is sampled.** A site one thread has disarmed doesn't
  trap for another until it's re-armed. Emulated markers are exempt:
  measured on `target_loop_mt` (x86_64), every boundary is captured with
  2, 4 and 8 workers. A non-emulated marker is missed while another worker holds
  it disarmed, and two iterations merge into one snapshot: ~1-3% of
  boundaries with 2 workers, ~5-20% with 4, ~20-30% with 8. Snapshots
  never mix threads.

Publish costs one `map_size` copy per iteration under MT; ST keeps the
zero-copy pointer swap. Generations are assigned by `fetch_add` on
`gen_current`, so concurrent publishers may stamp their slots out of
order; the reader's seqlock check handles a slot that isn't stamped yet.

## Patch list format (LCV3)

The library accepts only LCV3. The generator (`tools/gen_patchlist.py`)
emits LCV3 and the library mmaps it at init.

LCV3 header (24 bytes):

```c
char     magic[4]       = "LCV3";
uint32_t version        = 3;
uint32_t count;            // number of records
uint8_t  threading;        // 0=ANY, 1=ST, 2=MT
uint8_t  flags;            // reserved, must be 0
uint8_t  module_count;     // 1..255
uint8_t  reserved;
uint32_t modules_offset;   // file offset of module name table
uint32_t modules_size;     // bytes in the name table
```

Records (14 bytes each):

```c
uint64_t offset;       // from libcov_module_bases[module_idx]
uint8_t  len;          // bytes to patch and restore (2 or 4)
uint8_t  module_idx;   // index into the name table
uint8_t  orig[4];      // first `len` bytes meaningful
```

After the records, the file contains a module name table -- a flat
blob of `module_count` NUL-terminated basenames concatenated at
`modules_offset` (e.g. `"target_simple\0libfoo.so\0"`). Index 0 is the
primary module (the positional `binary` arg to gen_patchlist); indices
1..N are the `--module NAME:PATH` modules in command-line order.

All little-endian. The library byte-swaps on big-endian targets. A
mismatched `threading` hint (e.g. an MT-generated list given to
`libcov_st.so`) is refused at init with a clear log line.

To instrument multiple modules in one patch list:

```
./tools/gen_patchlist.py build/x86_64/target_exe /tmp/t.lcv \
    --module libfoo.so:/path/to/libfoo.so \
    --module libasdf.so:/path/to/libasdf.so
```

At init `config_load` calls `util_module_base(name)` for each module
name. The base is the first matching mapping in `/proc/self/maps` minus
its `pgoffset`. Each entry's runtime address is then
`libcov_module_bases[module_idx] + record.offset`. If any named module
is not currently mapped, init refuses to finish loading and logs the
unresolved name, with a hint (for module 0, the main executable's
actual name).

Names are basenames, since the host path you generate from rarely
matches the device's. Rules that keep them resolving:

- The generator stores the name of the file a symlink points to
  (`/bin/ls → busybox` is stored as `busybox`, `libfoo.so.1 →
  libfoo.so.1.2.3` as `libfoo.so.1.2.3`), because that is what
  `/proc/self/maps` shows. An explicit `--module NAME:PATH` whose NAME
  differs from PATH's basename is stored as given.
- A mapping whose file was deleted or replaced after it was loaded (a
  daemon upgraded in place) still matches: the ` (deleted)` suffix is
  ignored.
- If two mapped files share the basename, libcov logs that the name is
  ambiguous and uses the first. `LIBCOV_MODULE_RENAME=name=/abs/path`
  picks the right one. The per-site byte check then confirms it: a wrong
  pick shows up as `stale=` entries in the log.
- A binary run under another name (a renamed copy) needs
  `LIBCOV_MODULE_RENAME=generated-name=runtime-name`.

## Boundary sidecar format (LCVB1)

Header (16 bytes):

```c
char     magic[4]  = "LCVB";
uint32_t version   = 1;
uint32_t count;
uint32_t flags;    // reserved
```

Records (16 bytes each):

```c
uint64_t offset;        // from module load base; MUST coincide with a patched site
uint8_t  kind;          // 0=BEGIN, 1=END
uint8_t  depth_filter;  // 0=any depth, 1=depth-zero only (paired mode)
uint8_t  reserved[6];
```

All little-endian. `tools/gen_boundary.py` emits this. The generator
resolves a function name to the site `gen_patchlist.py` would pick for its
FIRST basic block under the same `--strategy` (default: the arch's): the
last >= 2-byte instruction under `terminator`, the first instruction
under `entry` (the MIPS default, which skips branch delay slots).
Pass `--patchlist <lcv>` to have it verify each marker really is a patched
site (filters, slicing and MT alignment can all exclude it).

## Shm header layout

`struct libcov_shm_header` (defined in `src/boundary.h`):

```c
char     magic[4]    = "LCVS";
uint16_t version     = 1;
uint16_t ring_size;
uint32_t map_size;        // live bitmap bytes (power of two)
uint32_t slot_stride;     // sizeof(ring_slot_hdr) + map_size
uint32_t flags;           // bit0 = boundaries active, bit1 = MT-variant libcov,
                          // bit2 = live bitmap not maintained (read the ring)
uint64_t gen_current;     // atomic; last fully-published iteration
uint64_t gen_init;        // gen at which init snapshot was captured
uint64_t bitmap_offset;   // shm-base relative
uint64_t ring_offset;     // shm-base relative
uint32_t publish_dropped; // atomic; MT publishes dropped (slot held by a newer gen)
uint32_t owner_pid;       // process that created the region
uint32_t owner_start;     // its start time (/proc/<pid>/stat field 22, low 32 bits)
uint8_t  reserved[4];
```

After natural alignment the struct is 72 bytes. Drivers should read
`bitmap_offset` / `ring_offset` from the header rather than hard-coding
offsets.

## ASLR

The library reads `/proc/self/maps` and adds the runtime module base to
every offset, so it works under PIE+ASLR. For deterministic test runs we
recommend `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space` while
iterating on the patch list. With ASLR on, addresses still resolve
correctly because patch records are offsets — but ground-truth comparisons
across runs are easier with ASLR off.

## Re-exec and fork+exec

A daemon that execs itself inherits `LD_PRELOAD` and `LIBCOV_SHM_PATH`,
so libcov initialises again in the new image. The shm header records
the process that created the region (pid + start time, both unchanged
by `exec`), and the new image decides under an `flock`:

- **Same process** (in-place re-exec, e.g. `sshd -R`): it attaches. The
  bitmap, ring and `gen_current` carry on, so a reading driver sees
  nothing unusual.
- **Another live process** (a fork+exec child, an nginx binary upgrade
  while the old master runs): the region is left alone and the new
  process runs inert, logging `in use by live pid N`. Use `%p` in
  `LIBCOV_SHM_PATH` to give it its own region instead.
- **Nobody alive** (a file left by an earlier run): the region is reset,
  as for any new run.

`fork` without `exec` still shares one region with the parent (and, in
ST builds, non-atomic bitmap increments).

## Hardening

- The library refuses to patch addresses inside its own mapping
  (`/proc/self/maps` lookup of the function `util_self_range`).
- `sigaction(2)` and `signal(2)` are intercepted; if the target tries to
  install its own handler for the backend's trap signal post-init, the
  request is acknowledged with success but our handler stays installed.
  The target's intended handler (or the pre-init one) is stashed and
  chained for *real* traps (faults at addresses not in our patch table),
  honouring `SA_SIGINFO` and `SA_RESETHAND`; `SIG_DFL`/`SIG_IGN` die with
  the default action as the kernel would. The chained handler runs with
  the mask the kernel would have given it (interrupted mask + its
  `sa_mask` + the signal unless `SA_NODEFER`), except that the trap
  signal itself stays unblocked, since the handler may run instrumented
  code. The stash is safe to update from one thread while another traps.
- glibc's older wrappers reach the kernel without going through
  `sigaction`/`sigprocmask`, so they are intercepted too: `bsd_signal`,
  `ssignal`, `sysv_signal`/`__sysv_signal`, `sigset`, `sigignore`,
  `siginterrupt` (all stash instead of replacing our handler), `sighold`
  (a no-op for the trap signal) and `sigsuspend` (trap signal stripped).
  Raw `rt_sigaction`/`rt_sigprocmask` syscalls still bypass libcov.
- `sigprocmask(2)` and `pthread_sigmask(3)` are intercepted to strip the
  trap signal from any mask the target blocks: a blocked synchronous trap
  signal is fatal.
- After init, a log line is written only while the log fd (`LIBCOV_LOG`
  or stderr) still refers to the file it did at init and is not a
  socket, so a daemon that reuses the fd number or `dup2`s a socket onto
  fd 2 never receives libcov output.
- The trap handler runs with every asynchronous signal blocked, so a
  target signal handler can never run instrumented code mid-patch.
- Init-time trap self-test: each trap encoding is executed once from a
  scratch page and must arrive as `LIBCOV_TRAP_SIGNO`; otherwise libcov
  stays inert (a mismatch would kill the target on its first trap).
- `libcov_st.so` warns when the process has, or creates, a second thread:
  its patch writes aren't atomic (and in the `mprotect` fallback make
  code pages briefly non-executable) and its leapfrog state isn't
  thread-safe, so peer threads can crash in any mode.
- Init-time byte validation: every patch record's `orig[]` is compared
  against the actual bytes at the target address; mismatches abort with a
  clear log line so stale patch lists are caught immediately.

## Limitations

- **MT cross-validation under qemu-user is limited to x86_64 and aarch64.**
  qemu-user's TCG (translation cache) only invalidates on `mprotect` with
  a permission change, and the perm-change strips PROT_EXEC long enough
  to SIGSEGV any peer guest thread mid-fetch. Without the perm change,
  TCG keeps replaying its cached translation of the trap encoding after
  we restore the original bytes, infinite-looping the handler. On real
  hardware neither problem exists: the CPU re-fetches and there is no
  TCG layer. MT correctness for the other 9 backends is established by
  build-and-link smoke + the per-arch atomic-write argument in
  `src/patch_mt.c`; real-hardware validation is a TODO.
- **Cross-modifying code is outside the ISA guarantees.** Sites trap
  with SIGILL from an illegal encoding by design, and neither UD2 nor
  UDF is in the x86 (SDM 8.1.3) or AArch64 (CMODX) sets that may be
  rewritten while another core executes them. `libcov_mt.so` narrows
  the window as far as it can (single-copy-atomic store, cache
  maintenance, `membarrier(SYNC_CORE)` or, on kernels without it, a
  signal broadcast to every peer thread); see `Design.md` §17.2.5.
- **x86 blocks made only of 1-byte instructions** (`leave; ret`,
  `pop; ret`, a lone `ret`) can't hold the 2-byte UD2 and are not
  instrumented.
- **No JIT/self-modifying code support.** Newly-generated code is not in
  the patch list and won't be instrumented.
- **W^X-strict kernels.** Both variants make each patched code page
  `RWX` once at init and then patch with plain stores. If the kernel
  refuses (SELinux `execmem`, PaX `MPROTECT`), `libcov_st.so` falls back
  to two `mprotect` calls per arm/disarm (transient `RW`, never `RWX`;
  about 3x slower in leapfrog), and `libcov_mt.so` to non-atomic
  `pwrite(/proc/self/mem)` with a WARNING (torn instructions become
  possible under concurrency). `LIBCOV_ST_PATCH=mprotect` forces the ST
  fallback. `test/wx_deny` reproduces such a kernel with seccomp.
- **Per-arch length minimums.** Fixed-width-insn architectures (everything
  except x86) can only patch full instructions. x86_64 can patch any
  instruction >= 2 bytes; 1-byte insns (`ret`, `push rbp`) are skipped by
  the generator.

## Files

```
src/
  libcov.c            constructor; env parsing; sigaction/signal interception
  util.c/.h           /proc/self/maps parsing; init-time logger
  config.c            LCV3 mmap loader; per-module base resolution from
                      /proc/self/maps; sorted patch_entry table (endian-safe);
                      threading-hint enforcement
  patchlist_format.h  on-disk LCV3 wire format + runtime patch_entry struct
                      (renamed from config.h; not a tunables file)
  tunables.h          project-wide knobs (trap signo default SIGILL, bitmap size,
                      log buf); every knob -D-overridable
  tunables_<arch>.h   per-backend knobs (illegal encoding(s), instruction-width
                      bounds); one per backend, every knob -D-overridable
  patch.h             arm/disarm/lookup + batch rearm interface (same ABI both variants)
  patch_st.c          ST: RWX-once direct stores (or mprotect fallback) + cache flush
  patch_mt.c          MT: RWX-once atomic store + per-entry spinlock + clear_cache
                      + membarrier(SYNC_CORE);
                      batch rearm
  handler.h           trap-handler interface
  handler_st.c        ST handler; global g_last_restored
  handler_mt.c        MT handler; TLS g_last_restored
  sink.h              AFL-style edge hash; macro-gated TLS prev_loc + atomic emit (MT)
  sink_shm.c          shm region (header + bitmap + ring); prev_loc def
  boundary.h/.c       LCVB1 parser; marker lookup; snapshot publish; re-arm;
                      per-thread depth + live bitmaps under MT
  membarrier.h/.c     MT-only; PRIVATE_EXPEDITED_SYNC_CORE, or a signal broadcast
                      to every peer thread on kernels without it
  arch.h              backend interface (extern symbols, no #ifdefs)
  arch_x86_64.c       x86 UD2 head-only / 2 bytes (ST+MT share)
  arch_aarch64.c      UDF #0 / 4-byte fixed (ST+MT)
  arch_arm.c          ARM UDF + Thumb UDF.N / 2 or 4 bytes (ST+MT)
  arch_mips.c         user-mode MFC0 / 4-byte fixed MIPS32 BE+LE (ST+MT)
  arch_mips64.c       same / 4-byte fixed (ST+MT)
  arch_powerpc.c      all-zero illegal / PPC32 BE (ST+MT)
  arch_powerpc64.c    all-zero illegal / PPC64 BE+LE (ST+MT)
  arch_riscv64.c      c.unimp / 2-or-4-byte (ST+MT)
test/
  target_simple.c             single-shot ground-truth target (10+ branches)
  target_simple_mt.c          pthread stress target for MT validation
  target_loop.c               stdin-driven loop target with iter_begin marker
  target_loop_mt.c            multi-worker boundary target (per-thread paths)
  target_dispatch.c           generator target (function-pointer dispatch, exiting callee)
  target_markers.c            marker functions covering every emulated branch form
  target_multimod.c           multi-module target (links libmultimod_helper.so)
  libmultimod_helper.c/.h     helper shared library for multi-module test
  fuzz_driver.c               boundary-aware driver (seqlock reader)
  ring_dump.c                 passive ring reader for self-iterating targets
  run_validation.sh           native ST regression test (single-shot)
  run_validation_mt.sh        native MT regression test + stress
  run_validation_boundary.sh  native boundary-mode test + (MODE, REARM) matrix
  run_validation_boundary_mt.sh  MT boundary test: concurrent workers' snapshots
                              must not mix threads
  run_validation_multimod.sh  native multi-module LCV3 test (exe + helper.so)
  target_signals.c            signal-mask / SIGILL-handler regression target
  run_validation_signals.sh   native ST+MT signal-handling regression test, incl. the
                              MT sync-broadcast signal (target use, blocking, SIG_IGN)
  run_validation_generator.sh generator: call-terminated blocks, indirect-call report,
                              branch-type classification
  run_validation_o2pie.sh     -O2 PIE builds of target_simple/target_dispatch under ST+MT
  run_validation_marker_emulation.sh  marker emulation: branch traces unchanged, one
                              boundary per marker call (ARCH=<arch> runs under qemu,
                              MIPS included; ST only except x86_64/aarch64)
  run_all.sh                  suite runner behind `make test`
  shm_bitmap.py               reads the live bitmap using the shm header (size,
                              offset and byte order vary)
  run_validation_failloud.sh  misconfigurations fail loudly (REQUIRE, oneshot+none,
                              ST in MT target, trap self-test, empty patch list)
  run_cross.sh                all-arch ST validation under qemu-user-static
  run_cross_mt.sh             all-arch MT validation (full run for x86_64+aarch64;
                              build-only for the other 9 due to qemu-user TCG limits)
tools/
  gen_patchlist.py    rizin-based LCV3 generator; per-arch strategy
                      (terminator -- or the block's first call, so blocks
                      whose callee never returns still report -- vs entry,
                      Thumb-aware, delay-slot-aware,
                      ppc64 local-entry-aware); --threading st|mt;
                      --module name:path adds auxiliary modules
  gen_boundary.py     rizin-based LCVB1 sidecar generator; resolves symbol
                      names to their first-BB site (terminator, or entry
                      on MIPS)
  mutate.py           generic AFL++-style mutation engine (library + CLI):
                      stdlib-only, weighted havoc + splice, AFL-format
                      dictionaries, user-defined StructuredInsert
                      factories, pre/post hooks, opt-in trace hash;
                      `python3 tools/mutate.py --selftest` to verify
TODO.md               deferred design work (daemons, transport, etc.)
```

## Validation

`make test` builds both library variants and every test target, then runs
every native suite below and prints a PASS/FAIL summary (logs of failing
suites are kept). Suites use a fresh `mktemp -d` each, so they can run in
parallel. To run one by hand:

```
# Native (x86_64) ST regression:
make
./test/run_validation.sh

# Native (x86_64) MT regression + 16-thread/2000-iter stress:
make THREADING=mt
./test/run_validation_mt.sh

# Native (x86_64) boundary mode (long-running target_loop + ring reader):
./test/run_validation_boundary.sh

# Native signal handling (blocked masks, target SIGILL handlers), ST + MT:
./test/run_validation_signals.sh

# Native MT boundary mode with concurrent workers (snapshots must not mix):
./test/run_validation_boundary_mt.sh

# Misconfigurations fail loudly (REQUIRE, oneshot+none, trap self-test, ...):
./test/run_validation_failloud.sh

# Patch-list generator regressions (call-terminated blocks, indirect calls):
./test/run_validation_generator.sh

# -O2 PIE targets (tail calls, cold splits, jump tables, ASLR):
./test/run_validation_o2pie.sh

# Boundary-marker emulation (also ARCH=aarch64|arm|riscv64|powerpc|
# powerpc64|powerpc64le under qemu; ARCH=mips|mipsel|mips64|mips64el
# checks the non-emulated fallback):
./test/run_validation_marker_emulation.sh

# All backends, ST, under qemu-user-static:
./test/run_cross.sh        # PASS=12  FAIL=0  SKIP=0

# All backends, MT, under qemu-user-static:
./test/run_cross_mt.sh     # FULL_PASS=2 BUILD_ONLY=9 FAIL=0 SKIP=0
```

ST per-backend checks: bitmap determinism, input differentiation
(different inputs => different bitmaps), leapfrog hit-count recording,
and target output unchanged with libcov loaded.

MT per-backend checks (full-run arches): the same four checks, plus
sorted-output equivalence under multiple pthread workers, plus a stress
run (16 threads / 2000 iters by default; tunable via THREADS_STRESS and
ITERS_STRESS env vars). Build-only arches confirm clean compile, link,
target build, and patch-list generation; runtime validation requires
real hardware -- see `src/patch_mt.c` for the per-arch atomic-write
argument and `TODO.md` for the real-hardware backlog.

Boundary-mode checks: per-iteration snapshots arrive in the ring (one
per input + init slot + EOF-flush slot), `gen_init` is recorded, the
seqlock reader never reports torn reads or overruns at this rate,
per-iteration bitmaps differ across inputs (confirming libcov really
clears the live bitmap between iterations), and all three viable
`(MODE, BOUNDARY_REARM)` combinations publish gens.

## What's next

See [TODO.md](TODO.md) for the design backlog. Short version: this PoC
proves the trampoline mechanism across architectures. The next phase
makes it useful against long-running network daemons (iteration boundary
detection, multi-module patch lists, fork-per-connection, multi-thread,
remote coverage transport via a separate relay binary).
