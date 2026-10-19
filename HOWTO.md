# HOWTO: Collect Coverage and Fuzz with libcov (suzzer)

This is an operational guide for an engineer or an automated agent who has
**never seen this project before** and needs to drive it end to end: build
the harness, pick the right configuration, generate patch-point files,
collect coverage from a target (locally or across a network), and verify the
whole setup works.

Read [README.md](README.md) for the design rationale and
[Design.md](Design.md) for internals. **This document tells you what to run,
in what order, and how to know it worked.** Every command here is literal and
copy-pasteable. Where a choice exists, this guide tells you how to choose.

> **Building a fuzzer? Start at [Recipe 1 — Fuzz a target](#13-recipes).**
> Most people reach for libcov to *fuzz*, and the strong fuzzing setup differs
> from a bare coverage dump in several knobs at once (leapfrog mode, ordered
> 3-gram, a persistent driver, a heap oracle, a disk corpus, real crash
> triage). Recipe 1 wires all of them up in one copy-pasteable block; the
> intervening sections explain each piece. **Do not** assemble a fuzzer from
> the earliest/simplest snippets below (`oneshot`, `N=1`, fork-exec per input)
> — those are coverage *sanity checks* and they miss bugs. See the
> [coverage-vs-fuzzing table](README.md#collecting-coverage-vs-building-a-fuzzer-read-this-first)
> in the README for the one-glance summary.

> **One rule to never break:** readers must learn the bitmap size and layout
> from the shm **header**, never by hard-coding `64 KB @ offset 72`. The
> site-id coverage model sizes the bitmap from the patch count, and the
> header's byte order follows the *target's* ABI (a big-endian or 32-bit
> target writes a header the host must byte-swap). Use
> [`test/shm_bitmap.py`](test/shm_bitmap.py) or copy its header parsing.

---

## Table of contents

1. [Mental model: how a trap becomes a coverage bit](#1-mental-model)
2. [Prerequisites and one-time setup](#2-prerequisites)
3. [Decision tree: which variant and mode do I want?](#3-decision-tree)
4. [Step 1 — Build the library and test targets](#4-step-1-build)
5. [Step 2 — Generate the patch list (the coverage points)](#5-step-2-patchlist)
6. [Step 3 — Generate the iteration-boundary sidecar (long-running targets)](#6-step-3-boundary)
7. [Step 4 — Run the target under libcov and collect coverage](#7-step-4-run)
8. [Step 5 — Read the bitmap from a fuzzer/driver](#8-step-5-read)
9. [Remote / across-the-network collection](#9-remote)
10. [Full environment-variable reference](#10-env-reference)
11. [Testing and validating your setup](#11-testing)
12. [Troubleshooting (symptom → cause → fix)](#12-troubleshooting)
13. [Worked end-to-end recipes](#13-recipes)
14. [Fuzzing tooling (relay/brain, heap oracle, mutator, status board, injector)](#14-tooling)

---

<a name="1-mental-model"></a>
## 1. Mental model: how a trap becomes a coverage bit

1. **Offline**, [`tools/gen_patchlist.py`](tools/gen_patchlist.py) uses rizin
   to analyse your target ELF, picks one address inside each basic block it
   wants to track ("patch sites"), records each site's original bytes, and
   writes an **LCV3 patch-list file**.
2. **At runtime**, `libcov_st.so` / `libcov_mt.so` is injected via
   `LD_PRELOAD`. Its constructor mmaps the patch list, finds the target's
   load base from `/proc/self/maps`, and **overwrites each site with an
   illegal/trap instruction** (SIGILL by default).
3. When the CPU executes a patched site it **traps**. libcov's signal handler
   reads the faulting PC, computes a bucket index (by default an edge
   bucket built from the hit site's id and the previous site's id — not
   AFL's hash-of-PC; see `src/sink.h`), bumps that byte in a **shared-memory bitmap**, restores the original
   instruction, and returns so the program continues.
4. An external **driver/fuzzer** mmaps the same shm region and reads hit
   counts to make decisions (did this input reach new code?).

No ptrace, no JIT, no kernel module — just libc + `sigaction` + `mprotect`.
That is why it fits memory-constrained embedded targets.

Traps are **always SIGILL raised by an illegal instruction encoding** — this
is a deliberate, load-bearing design choice. Do **not** switch the trap
mechanism to `INT3`/`BRK`/breakpoints; keep it SIGILL + illegal instructions.

---

<a name="2-prerequisites"></a>
## 2. Prerequisites and one-time setup

### Host tools (always needed)

| Tool | Why | Install (Debian/Ubuntu) |
|---|---|---|
| `gcc`, `make` | build the library | `build-essential` |
| `python3` (3.8+) | run the generators | `python3` |
| **rizin** + **rzpipe** | static analysis in the generators | `rizin`; `pip install rzpipe` |

`gen_patchlist.py` drives **rizin** through the `rzpipe` Python module (one
long-lived rizin process per binary). `gen_boundary.py` instead runs a fresh
`rizin -q -c` subprocess per query, but it still imports `gen_patchlist`, so
it needs `rzpipe` too. If `rizin` is not on `PATH` or `rzpipe` is not
importable, both generators fail. Verify:

```bash
rizin -v && python3 -c "import rzpipe; print('rzpipe ok')"
```

### Cross-compile + emulation (only for non-host architectures)

To build for a foreign arch you need its cross-gcc; to *run* it on your host
you need the matching `qemu-<arch>-static`. The Makefile maps each `ARCH` to a
`CROSS` prefix and a `QEMU` binary (see [Makefile](Makefile) lines 40–96):

| `ARCH` | `CROSS` prefix | QEMU |
|---|---|---|
| `x86_64` | *(none)* | `qemu-x86_64-static` |
| `aarch64` | `aarch64-linux-gnu-` | `qemu-aarch64-static` |
| `arm` | `arm-linux-gnueabihf-` | `qemu-arm-static` |
| `mips` / `mipsel` | `mips-linux-gnu-` / `mipsel-linux-gnu-` | `qemu-mips[el]-static` |
| `mips64` / `mips64el` | `mips64-linux-gnuabi64-` / `mips64el-…` | `qemu-mips64[el]-static` |
| `powerpc` | `powerpc-linux-gnu-` | `qemu-ppc-static` |
| `powerpc64` / `powerpc64le` | `powerpc64-linux-gnu-` / `powerpc64le-…` | `qemu-ppc64[le]-static` |
| `riscv64` | `riscv64-linux-gnu-` | `qemu-riscv64-static` |

On Debian: `apt install gcc-aarch64-linux-gnu qemu-user-static` (repeat the
`gcc-<arch>` package per arch). Confirm a toolchain exists:
`aarch64-linux-gnu-gcc --version`.

### Deterministic runs (recommended while iterating)

ASLR does not break libcov (offsets are added to the runtime base), but
ground-truth diffs across runs are easier with it off:

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space   # restore with "2"
```

---

<a name="3-decision-tree"></a>
## 3. Decision tree: which variant and mode do I want?

Answer these in order. Each answer sets one knob.

**Q1. Is the target multi-threaded (does it ever create a second thread)?**
- **No** → build and generate for **ST** (`libcov_st.so`, `--threading st`).
  Lowest overhead, smallest surface.
- **Yes** → build and generate for **MT** (`libcov_mt.so`, `--threading mt`).
  ST on a threaded target **will crash peer threads** (its patch writes are
  not atomic). The ST library warns loudly if it sees a second thread.

> The patch list carries a threading hint. An MT-generated list given to
> `libcov_st.so` (or vice-versa) is **refused at init**. Match them.

**Q2. Are you fuzzing, or just taking a one-off coverage reading?**
- **Fuzzing** → `LIBCOV_MODE=leapfrog` (**default**). A fuzzer needs coverage
  that keeps responding as inputs evolve; leapfrog gives per-iteration edge
  sets and hit counts. This is the right answer for essentially every fuzzing
  campaign.
- **One-off "did this edge get reached" reading**, nothing evolving →
  `LIBCOV_MODE=oneshot` is faster, but it goes path-blind after warmup (each
  site fires once), so **never use it to fuzz**.

**Q3. Is the target a one-shot program (runs once per input, then exits) or a
long-running loop/daemon (one process handles many inputs)?**
- **One-shot** → simplest to wire up: run the process per input and read the
  cumulative bitmap. You still want `leapfrog` + ordered 3-gram for fuzzing;
  boundaries are optional (per-input scoping comes for free from the fresh
  process). A fast fuzzer will still prefer a persistent driver to avoid
  paying process-startup + re-instrumentation on every input.
- **Long-running / daemon** → add an **iteration-boundary sidecar** (Step 3)
  so libcov knows where one input ends and the next begins and publishes a
  per-iteration snapshot into the ring. This is the stronger model: the target
  stays resident (no fork+exec per input) and is driven by `fuzz_driver` or
  `suzzer-relay`. (A fork-per-connection daemon is covered too — see
  [Pattern C](#9-remote).)

**Q4. Only for long-running targets — pick `(MODE, BOUNDARY_REARM)`:**

| `LIBCOV_MODE` | `LIBCOV_BOUNDARY_REARM` | Use when |
|---|---|---|
| `leapfrog` | `none` | **Default for boundary mode.** Per-iter bitmaps, full edge sets. |
| `oneshot` | `all` | Many traps/iteration; cheaper than leapfrog's per-trap cost. |
| `oneshot` | `touched` | Like `all` but re-arms only sites touched since last boundary. |
| `oneshot` | `none` | **Refused** (per-iter maps go empty after warmup) unless `LIBCOV_ALLOW_ONESHOT_NOREARM=1`. Don't. |

**Q5. Only for MT — cross-core instruction sync fallback:** leave
`LIBCOV_SYNC_FALLBACK=auto`. Only change it if the kernel lacks
`membarrier(SYNC_CORE)` and you see correctness issues (see §10).

---

<a name="4-step-1-build"></a>
## 4. Step 1 — Build the library and test targets

All build output lands in `build/<arch>/`. The key artifacts are
`libcov_st.so` / `libcov_mt.so`.

### Native build (host arch)

```bash
make                      # ST library + ST test targets
make THREADING=mt         # MT library + the default (ST) test targets
```

### Cross build

```bash
make ARCH=aarch64                    # ST for aarch64
make ARCH=aarch64 THREADING=mt       # MT for aarch64
```

### Build everything

```bash
make all-arch                 # ST for all 11 architectures (8 backends)
make all-arch THREADING=mt    # MT for all 11 architectures
make all-variants             # ST and MT for every backend
```

### Build test targets for a given arch

`make` (with either `THREADING`) builds the default ST test targets:
`target_simple`, `target_loop`, `target_orderable`, `target_dispatch`,
`target_markers`, `fuzz_driver`. The MT targets, `ring_dump`, the
multi-module target and the -O2 PIE variants are **not** built by plain
`make`. Build them with the test Makefile:

```bash
# MT targets (target_simple_mt, target_loop_mt, ring_dump):
make -C test ARCH=aarch64 CROSS=aarch64-linux-gnu- BUILD=$PWD/build/aarch64 mt
# Multi-module test target + helper .so:
make -C test ARCH=x86_64 BUILD=$PWD/build/x86_64 multimod
# -O2 PIE variants:
make -C test ARCH=x86_64 BUILD=$PWD/build/x86_64 o2pie
```

### Confirm the build

```bash
ls build/x86_64/libcov_st.so        # should exist
make print-vars                     # shows resolved ARCH/BACKEND/THREADING, SRC, LIB
```

### Build-time tunables (optional)

Defaults are shipped; override only if needed. Two equivalent ways — editing
the header, or passing `-D` via `EXTRA_CFLAGS` (the `-D` wins):

```bash
# Ordered 3-gram -- RECOMMENDED FOR FUZZING (path-sensitive; rotation defeats
# A,B,C == B,A,C history-permutation collisions). Build your fuzzing libcov with this:
make EXTRA_CFLAGS='-DLIBCOV_NGRAM_N=3 -DLIBCOV_NGRAM_ROTATE=1'
# Wider window (8-gram) for deeper path sensitivity at higher cost:
make EXTRA_CFLAGS='-DLIBCOV_NGRAM_N=8 -DLIBCOV_NGRAM_ROTATE=1'
# Block coverage, path-blind (cheapest) -- sanity checks only, NOT for fuzzing:
make EXTRA_CFLAGS='-DLIBCOV_NGRAM_N=1'
# Retarget the MIPS illegal encoding for an odd chip rev
# (mips64 uses LIBCOV_ARCH_MIPS64_ILLEGAL instead):
make ARCH=mips EXTRA_CFLAGS='-DLIBCOV_ARCH_MIPS_ILLEGAL=0xDEADBEEFu'
```

Knob locations: project-wide (`trap signal`, coverage model, bitmap sizing,
N-gram width, log buffer) in [`src/tunables.h`](src/tunables.h). Under the
default site-id model the bitmap is sized from the patch count
(`LIBCOV_MAP_FUDGE`, which defaults higher for larger N-gram widths;
`LIBCOV_MAP_MIN_POW2`/`MAX_POW2`); `LIBCOV_MAP_SIZE_POW2`
only applies to the legacy PC-hash model. Per-backend illegal encodings live
in `src/tunables_<arch>.h`. **Keep the trap mechanism SIGILL + illegal
instructions** — only change *which* illegal encoding, never switch to
breakpoints.

---

<a name="5-step-2-patchlist"></a>
## 5. Step 2 — Generate the patch list (the coverage points)

The patch list (`*.lcv`, format **LCV3**) is the list of addresses libcov
will trap on. Generate it with [`tools/gen_patchlist.py`](tools/gen_patchlist.py).

### Minimal invocation

```bash
./tools/gen_patchlist.py <binary> <output.lcv> [options]
```

- `<binary>`: the ELF to analyse (module index 0; usually the main executable).
- `<output.lcv>`: file to write.

**Critical:** pass `--threading mt` if (and only if) you will run under
`libcov_mt.so`. Default is `st`.

```bash
# ST, whole binary minus the built-in CRT/import exclusions:
./tools/gen_patchlist.py build/x86_64/target_simple /tmp/t.lcv

# MT variant:
./tools/gen_patchlist.py build/x86_64/target_simple /tmp/t.lcv --threading mt
```

### Scoping what gets instrumented

Instrumenting every function is rarely what you want. Two complementary
filters:

**(a) Name regex filters:**

```bash
--include-pat '^dbg\.(main|parse_request|classify)$'   # only these
--exclude-pat '^dbg\.log_.*'                            # add to built-in exclusions
--no-default-exclude                                    # drop built-in CRT/imp exclusions
--include-fcn                                           # also instrument rizin fcn.* heuristics
```

**(b) Call-graph slicing (recommended for real targets):** instrument only
what is reachable from a chosen entry point.

```bash
--root SYM_OR_ADDR     # BFS seed (repeatable)
--cutoff SYM_OR_ADDR   # stop traversal here; the cutoff is excluded (repeatable)
--max-depth N          # limit BFS to N call-edges below each root
--print-reachable      # dry-run: print the slice to stderr, write nothing
```

`SYM_OR_ADDR` resolution:
- `0x401234` → hex address, snapped to the enclosing function's entry.
- All-digit tokens are **decimal**: `4198964` is 0x401234, but `401234` is
  0x61f32. Always use the `0x` prefix for hex.
- `main` → exact name, then `dbg.main`, `sym.main`, `fcn.main`,
  `sym.imp.main`, then a unique last-dotted-segment match (ambiguous → error).
- `dbg.parse_request` → exact rizin name.
- An unprefixed hex-looking token (e.g. `cafe`) is tried as a name first and
  only then as hex.
`--root` combined with `--include-pat` is an **intersection**.

> **Indirect calls aren't followed**, and that includes **thread entry
> points**: `pthread_create(…, worker, …)` passes `worker` as a function
> pointer, so `--root main` alone leaves every worker thread uninstrumented.
> Add a `--root` for each thread function and for each function-pointer
> callback. Every slicing run prints how many indirect calls it saw, and
> `--print-reachable -v` shows where they are.

> `--cutoff`, `--max-depth`, and `--print-reachable` **require** at least one
> `--root`.

**Iterate on the slice first, then write it:**

```bash
# 1. Dry-run — see exactly which functions would be instrumented:
./tools/gen_patchlist.py build/x86_64/target_simple /dev/null \
    --root main --cutoff cmdline --print-reachable -v

# 2. Happy with it? Write the list:
./tools/gen_patchlist.py build/x86_64/target_simple /tmp/t.lcv \
    --root main --cutoff cmdline --max-depth 4
```

### Multiple modules (executable + shared libraries)

Each `--module NAME:PATH` adds an auxiliary module. `NAME` is the **basename
the runtime finds in `/proc/self/maps`** (e.g. `libfoo.so`); `PATH` is the ELF
rizin analyses. With slicing, **each module is sliced on its own call graph**,
so give each one its own `--root` (calls into another module go through the
PLT and are not followed).

```bash
./tools/gen_patchlist.py build/x86_64/target_multimod /tmp/m.lcv \
    --module libmultimod_helper.so:build/x86_64/libmultimod_helper.so \
    --root main --root 'libmultimod_helper.so!helper_classify'
```

### Raw firmware images (no ELF)

A bootloader, RTOS image or flash dump has no ELF headers, so tell both
generators what rizin would otherwise read from them:

- `--raw --base ADDR --arch ARCH --bits N --endian big|little`. `ARCH` is a
  rizin arch name (`mips`, `arm`, `riscv`, `ppc`, ...). `--base` is the load
  address. It becomes module 0's link base in the patch list's base table
  ([docs/FORMATS.md](docs/FORMATS.md) §1.5), so record offsets are
  `address − base`.
- `--symbols FILE` names the functions: `nm` output, `ADDR NAME` lines, or a
  Ghidra symbol-table CSV export. Names become `sym.NAME`, usable with
  `--root`, `--cutoff`, `--include-pat` and as boundary marker names.
  Without it, every function is a heuristic `fcn.*`, which is skipped unless
  you pass `--include-fcn`.

The safety rules are the same as for ELFs: the MIPS entry strategy, no delay
slots, the overlap checks, `--threading mt` alignment filtering.
`--threading` defaults to `any` for a raw image (header hint ANY). `orig[]`
is the image's own bytes (`--endian` only tells the disassembler how to
read them). libcov itself doesn't
load raw images. These lists are for other executors, e.g. an emulator.

```bash
./tools/gen_patchlist.py fw.bin /tmp/fw.lcv --raw --base 0x80010000 \
    --arch mips --bits 32 --endian big --symbols fw.nm --root fw_entry
./tools/gen_boundary.py fw.bin /tmp/fw.lcvb handle:begin --patchlist /tmp/fw.lcv \
    --raw --base 0x80010000 --arch mips --bits 32 --endian big --symbols fw.nm
```

### Other useful flags

- `--strategy {auto,entry,terminator}`: per-block site selection. Leave `auto`
  (entry on MIPS, terminator elsewhere). **If you also build a boundary
  sidecar, the two `--strategy` values must match.**
- `--fail-on-overlap`: hard-error on overlapping sites instead of dropping the
  later one.
- `--allow-empty`: write an empty list instead of erroring (almost never what
  you want — an empty list silently records nothing).
- `-v` / `--verbose`: print per-function decisions, indirect-call counts, etc.

### Sanity-check the result

A non-empty list and a plausible site count:

```bash
ls -l /tmp/t.lcv
xxd /tmp/t.lcv | head          # first 4 bytes must be "LCV3"
```

---

<a name="6-step-3-boundary"></a>
## 6. Step 3 — Generate the iteration-boundary sidecar (long-running targets)

Needed for long-running targets — a loop or daemon where one process handles
many inputs and you want per-input coverage (this is the stronger, persistent
fuzzing model). One-shot programs that exit per input can skip it (the fresh
process already scopes coverage per input), though a persistent driver is
still faster for a real campaign.

The sidecar (format **LCVB1**) names the addresses that mark iteration
boundaries. [`tools/gen_boundary.py`](tools/gen_boundary.py) resolves function
names to the site `gen_patchlist.py` would normally pick. That only lands on
a real patched site if your patch list didn't filter it out (slicing,
`--include-pat`, MT alignment, `fcn.*`), which is why `--patchlist` matters.

```bash
./tools/gen_boundary.py <binary> <output.lcvb> SPEC [SPEC ...] \
    [--patchlist LCV] [--strategy {auto,entry,terminator}] [--force] [-v]
```

Markers can only be in the **main executable** (module 0); there is no
`--module` option, and `--patchlist` checks only module-0 sites.

Each `SPEC` is `SYM[:kind[:depth_filter]]`:
- `kind`: `begin` (default) or `end`.
- `depth_filter`: `any` (default) or `zero` (fires only at recursion depth 0;
  paired mode only — `:zero` with no `end` marker is refused unless `--force`).
- C++ names containing `::` are fine; the spec is split from the right.

**Two marker modes (inferred from contents):**
- **begin-only** (only `begin` markers): every marker hit fires a boundary.
  No recursion guards.
- **paired** (at least one `end` marker): depth tracked per-iteration;
  `:zero` markers skip recursive sub-calls. Good for nested handlers.

```bash
# begin-only: iter_begin marks the top of each loop iteration
./tools/gen_boundary.py build/x86_64/target_loop /tmp/b.lcvb iter_begin \
    --patchlist /tmp/t.lcv

# paired with depth filtering:
./tools/gen_boundary.py build/x86_64/daemon /tmp/b.lcvb \
    handle_request:begin:zero handle_request_done:end:zero \
    --patchlist /tmp/t.lcv
```

> **Always pass `--patchlist`** so the generator verifies each marker really
> landed on a patched site (slicing/filters/MT-alignment can exclude it). It
> exits non-zero if a marker is not a site.

> **Marker site gotcha (x86):** the marker function's first basic block must
> contain at least one instruction of 2+ bytes (it does not have to be a
> branch), or `gen_patchlist` picks no site there and the boundary never
> fires. This mostly bites tiny `-O2` functions whose first block is just
> `ret`. [`test/target_loop.c`](test/target_loop.c) shows one way to make
> sure: an unreachable conditional inside `iter_begin` adds a 2-byte `jcc`.

`--strategy` must match the patch list's strategy.

---

<a name="7-step-4-run"></a>
## 7. Step 4 — Run the target under libcov and collect coverage

Set the environment, `LD_PRELOAD` the right library, run the target.
(These examples *collect coverage*. To actually fuzz, see
[Recipe 1 — Fuzz a target](#13-recipes), which adds leapfrog + ordered 3-gram
+ a persistent driver + the heap oracle on top of this.)

### Native, single run (one coverage reading)

```bash
LIBCOV_PATCHLIST=/tmp/t.lcv \
LIBCOV_SHM_PATH=/tmp/cov \
LIBCOV_MODE=leapfrog \
LD_PRELOAD=$PWD/build/x86_64/libcov_st.so \
    build/x86_64/target_simple 42
```

The coverage region (header + bitmap + ring) appears at `/tmp/cov`. A path
with a non-leading `/` is an ordinary file; a bare name such as `cov` or
`/cov` is a POSIX shm object at `/dev/shm/cov` (see §10). Read it with
`test/shm_bitmap.py` (next section).

### Cross arch under qemu-user

Pass `LD_PRELOAD` to the guest with qemu's `-E`. Do **not** also set it in
the host environment: it would try to load an aarch64 `.so` into the host
qemu process. The `LIBCOV_*` variables pass through to the guest unchanged.
This matches [`test/run_cross.sh`](test/run_cross.sh).

```bash
LIBCOV_PATCHLIST=/tmp/t.lcv \
LIBCOV_SHM_PATH=/tmp/cov \
LIBCOV_MODE=leapfrog \
    qemu-aarch64-static -L /usr/aarch64-linux-gnu \
    -E LD_PRELOAD=$PWD/build/aarch64/libcov_st.so \
    build/aarch64/target_simple 42
```

### Multi-threaded target

Use the MT library and an MT-generated patch list. `target_simple_mt` takes
`<threads> <iters> <input1> [input2 ...]`. With no arguments it prints usage
and exits 2.

```bash
LIBCOV_PATCHLIST=/tmp/t.mt.lcv \
LIBCOV_SHM_PATH=/tmp/cov \
LD_PRELOAD=$PWD/build/x86_64/libcov_mt.so \
    build/x86_64/target_simple_mt 4 100 1 2 42
```

### Long-running target with boundaries

Add the boundary list and a re-arm policy; the ring holds per-iteration
snapshots. Easiest is to let `fuzz_driver` set it all up (next section).
To do it manually:

```bash
LIBCOV_PATCHLIST=/tmp/t.lcv \
LIBCOV_BOUNDARY_LIST=/tmp/b.lcvb \
LIBCOV_BOUNDARY_REARM=none \
LIBCOV_MODE=leapfrog \
LIBCOV_SHM_PATH=/tmp/cov \
LD_PRELOAD=$PWD/build/x86_64/libcov_st.so \
    build/x86_64/target_loop < inputs.txt
```

### Make misconfigurations fatal (recommended in automation)

By default libcov runs **inert** if something is wrong (so children that
inherit `LD_PRELOAD` don't die). In a controlled harness you usually want the
opposite — fail fast:

```bash
LIBCOV_REQUIRE=1 ...   # abort if the patch list is unset/unresolvable,
                       # the trap self-test fails, nothing could be armed,
                       # or a boundary config is refused
```

Without `LIBCOV_REQUIRE`, every init failure (including a threading
mismatch) only logs a `libcov:` line to stderr and leaves the library inert.
A refused boundary config, such as `oneshot` with `REARM=none`, disables
**only boundaries**; plain coverage keeps running.

### Per-process regions for forking/re-execing daemons

If a daemon forks+execs workers that each inherit `LD_PRELOAD`, give each its
own region with `%p` (expands to pid):

```bash
LIBCOV_SHM_PATH=/dev/shm/cov_%p ...
```

See §10 and README "Re-exec and fork+exec" for the attach/reset rules.

---

<a name="8-step-5-read"></a>
## 8. Step 5 — Read the bitmap from a fuzzer/driver

### Quick inspection (CLI)

```bash
# nonzero-byte count, sum, max — a fast "did anything get covered?" check:
./test/shm_bitmap.py stats /tmp/cov
# dump the live bitmap to a file:
./test/shm_bitmap.py extract /tmp/cov /tmp/bitmap.bin
# current generation (boundary mode):
./test/shm_bitmap.py gen /tmp/cov
# coverage scheme the library was built with, e.g. "n=2 model=site rotate=0":
./test/shm_bitmap.py scheme /tmp/cov
```

Only compare or merge bitmaps whose `scheme` matches: an N=1 map and an N=4
map index buckets differently.

`stats` prints three bare numbers: `<nonzero> <sum> <max>`. `extract` always
needs an output **file** path; `-` is not stdout, it creates a file named
`-`. `shm_bitmap.py` derives size, offsets and byte order from the header.

> **Boundary mode caveat:** these commands read only the *live* bitmap at
> `bitmap_offset`. In **ST boundary mode** coverage goes into the ring slots,
> the live bitmap stays all zero, and the header sets
> `LIBCOV_SHM_FLAG_LIVE_EMPTY`. So `stats` reports `0 0 0` even when
> everything works. Use `fuzz_driver`/`ring_dump` (or the seqlock read below)
> instead. See README.md (search for `LIVE_EMPTY`).

When writing your own reader, copy `shm_bitmap.py`'s header parsing rather
than hard-coding offsets.

### One-shot workflow (no boundaries)

Run → `shm_bitmap.py stats` (or mmap + sum) → compare against the previous
bitmap to decide "new coverage" → next input. With boundaries off, the
cumulative bitmap lives at `bitmap_offset`.

### Long-running workflow — `fuzz_driver` (the reference driver)

[`test/fuzz_driver.c`](test/fuzz_driver.c) spawns the target **once**, pipes
inputs (one per line, at most 1023 bytes each; longer lines are split — this
1023 is `fuzz_driver`'s newline framing of stdin, **not** a recommended input
size; mutate.py defaults to 64 KB inputs, and binary/stateful protocols should
use a length-framed driver such as `suzzer-relay`, not newline framing) to
its stdin, and reads one coverage snapshot per iteration from the ring using
the correct seqlock protocol. It sets up the required env for you: its own
region at `/tmp/libcov_driver_<pid>` and `LIBCOV_MODE=leapfrog` unless you
set one. The target's stdout goes to `/dev/null`, and the driver's exit code
is **not** the target's.

```bash
./build/x86_64/fuzz_driver \
    build/x86_64/libcov_st.so \
    /tmp/t.lcv \
    /tmp/b.lcvb \
    build/x86_64/target_loop  < inputs.txt
```

Usage: `fuzz_driver <libcov.so> <patchlist> <boundary-list> <target> [args...]`.
It prints each snapshot's `kind=init|iter|gap`. The `(input#k='…')` label is
the input most recently *sent* when the snapshot arrived, not necessarily the
input the snapshot covers. With begin-only markers, input k's coverage is
published when input k+1 starts, so N inputs give `init` + N `iter`, the last
one labelled `EOF-flush`. The driver also counts overruns/lost
generations/`publish_dropped`, and **exits 3 on any ring overrun or
failed read**.
`FUZZ_DRIVER_BURST=1` feeds everything before reading (useful to force/observe
ring overrun).

### Self-iterating targets — `ring_dump`

For a target that drives its own iterations (not fed via stdin by the driver),
[`test/ring_dump.c`](test/ring_dump.c) is a passive ring reader:
`ring_dump <libcov.so> <patchlist> <boundary-list> <target> [args...]`.
It defaults `LIBCOV_BOUNDARY_RING=16`, prints `OVERRUN`/`MISSING` lines, and
**always exits 0**, so grep its output rather than trusting the exit code.

### Writing your own reader — the seqlock protocol

The shm header is `struct libcov_shm_header` (see
[`src/lcv_formats.h`](src/lcv_formats.h); 72 bytes on every target;
specified in [docs/FORMATS.md](docs/FORMATS.md) §3). Read `bitmap_offset`
and `ring_offset` from it. To read generation `g` safely:

1. Read `hdr->gen_current` (acquire): the highest generation *assigned*. It
   is bumped before the slot is stamped, so the newest one may not be
   readable yet; step 3 handles that.
2. `slot = ring[g % ring_size]`.
3. Read `slot->slot_gen` (acquire); if `!= g`, retry (slot is another gen).
4. `memcpy` the bitmap out of the slot.
5. Re-read `slot->slot_gen`; if still `== g`, commit, else retry (writer
   overwrote mid-read).
6. If `gen_current - g >= ring_size`, the writer lapped you and data is lost.
   Skip to `gen_current - ring_size + 2`, the oldest readable gen (under ST
   the writer is already clearing the slot after `gen_current`), and record
   the loss.
7. Under **MT**, a generation can be dropped and never stamped (counted in
   `hdr->publish_dropped`). Bound your step-3 retries and treat it as lost.

Slot `flags` tell you what a snapshot holds: `INIT` (startup), `ITER` (one
input), `GAP` (paired-mode harness code between `END` and next `BEGIN` —
belongs to no input; skip it when scoring inputs).

Tune ring depth with `LIBCOV_BOUNDARY_RING` (clamped to 2–16, default 8). Lag tolerance
is `RING − 1` iterations; raise it if your reader can fall behind.

### Event-driven reads (avoid polling)

Pass an inherited **eventfd** via `LIBCOV_BOUNDARY_NOTIFY_FD`; libcov writes 8
bytes after each snapshot so your reader can block on the eventfd instead of
spinning. **Only an eventfd** is accepted (a pipe could block/`SIGPIPE` the
target inside the trap handler and is ignored with a warning). Counter polling
still works without it.

---

<a name="9-remote"></a>
## 9. Remote / across-the-network collection

**What exists today:** libcov writes coverage to a **shared-memory region or a
file** (`LIBCOV_SHM_PATH`) and optionally signals an **eventfd**
(`LIBCOV_BOUNDARY_NOTIFY_FD`). Any reader that can reach that region reads
coverage. There is no *in-library* network transport, but there **is a shipped
over-IP template**: the on-device relay [`tools/suzzer-relay.c`](tools/suzzer-relay.c)
and the off-device reference brain [`tools/suzzer_brain.py`](tools/suzzer_brain.py),
talking TCP (Pattern C below; driven in §14.1, protocol in
[docs/FORMATS.md](docs/FORMATS.md) §4 and Design.md §24).

The usual split: the **target runs on a device** (embedded board, VM, remote
host); the **fuzzer brain runs elsewhere** and needs the bitmap. Pick a
transport by how tightly coupled the two are — Pattern C (the relay) is the
push-based default; A/B/D are lighter-weight alternatives.

### Pattern A — Shared filesystem (simplest; NFS / 9p / virtio-fs)

Put `LIBCOV_SHM_PATH` on a filesystem both sides mount.

- On device: `LIBCOV_SHM_PATH=/mnt/shared/cov_%p`
- On the brain host: mmap/read `/mnt/shared/cov_<pid>` with the header-aware
  reader.

Caveats: the header's **byte order follows the target ABI** — a big-endian or
32-bit device writes a header the brain must byte-swap; `shm_bitmap.py`
already handles this, reuse its logic. Network-filesystem mmap coherence can
lag; prefer `extract`-then-copy semantics or the eventfd notify over relying
on live mmap coherence across the mount.

### Pattern B — Poll/copy over SSH (loosely coupled; no shared FS)

Device writes to a local path; the brain copies snapshots over SSH.

```bash
# On the device (target side):
LIBCOV_SHM_PATH=/dev/shm/cov \
LIBCOV_PATCHLIST=/data/t.lcv \
LD_PRELOAD=/data/libcov_st.so  /data/target < input

# On the brain host: pull the raw region and parse it locally.
# (shm_bitmap.py handles the device's byte order; `extract` cannot write to stdout.)
ssh dev 'cat /dev/shm/cov' > local_cov.raw
./test/shm_bitmap.py extract local_cov.raw local_bitmap.bin
# or stream stats cheaply:
ssh dev 'python3 /data/shm_bitmap.py stats /dev/shm/cov'
```

This is the lowest-effort remote setup: the device needs only `cat`. To
compute `stats` on the device instead, ship the stdlib-only `shm_bitmap.py`
along with a Python install. For a long-running target in ST boundary mode,
the live bitmap is empty (§8 caveat), so you need Pattern C.

### Pattern C — On-device relay pushes snapshots (tightest; a shipped template)

When the network link is the only channel and you want coverage pushed as it
happens, run [`tools/suzzer-relay.c`](tools/suzzer-relay.c) on the device and
the reference brain [`tools/suzzer_brain.py`](tools/suzzer_brain.py)
off-device. This is the worked template; see §14.1 for how to drive it and
Design.md §24 for the protocol. The shape:

1. **Device:** `suzzer-relay` spawns the target daemon under libcov (it sets
   `LD_PRELOAD`, the patch list, the boundary list, and an **eventfd** on
   `LIBCOV_BOUNDARY_NOTIFY_FD`), attaches to the shm ring, and dials the
   brain over TCP.
2. For each input the brain sends, the relay delivers it to the daemon's own
   port, wakes on the eventfd, does the seqlock read (§8), and sends back one
   `COVERAGE` frame (the request's `ITER` snapshot) — or a `CRASH` frame if
   the daemon died, after which it restarts the daemon.
3. **Brain:** mutates with [`tools/mutate.py`](tools/mutate.py), folds each
   returned bitmap into a cumulative map, keeps inputs that found new
   coverage, and saves crashes.

The relay parses the shm header **on the device**, so each frame carries a
decoded `map_size` plus the raw `uint8` bitmap — the brain never parses a
foreign-ABI header, which sidesteps the byte-order pitfalls of Patterns A/B.
**Do not** hand the target a notify fd that is a pipe — it must be an eventfd
(the relay uses one; see §8).

This template targets a **single-process** daemon (one process handles
requests in a loop). **Fork-per-connection daemons (many inetd-style
services) are fuzzable too** — just don't let the children share one coverage
region (ST increments aren't atomic and snapshots would interleave). Two
working approaches:

- **Per-process regions:** give each child its own region with
  `LIBCOV_SHM_PATH=/dev/shm/cov_%p` (the `%p` expands to the pid; see §10 and
  "Per-process regions for forking/re-execing daemons"). The driver reads the
  child's region for the connection it drove.
- **One connection per process (simplest and robust):** drive exactly one
  connection per target process — accept, hand the socket to a freshly started
  instance, send the input, read that process's own region, let it exit. This
  trades some throughput for perfectly isolated per-input coverage and crash
  attribution. Keep per-exec cost low (persist expensive setup, avoid fixed
  sleeps so you don't pay a full timeout per connection) so throughput stays
  usable.

### Pattern D — qemu-user on the brain host (no real device at all)

For bring-up and CI you don't need hardware: run the foreign-arch target under
`qemu-<arch>-static` on the brain host (§7 "Cross arch"). The shm region is
local; this is "remote architecture, local collection." This is exactly what
the cross test suites do.

### Choosing a pattern

| Situation | Pattern |
|---|---|
| Device and brain share storage (VM + virtio-fs, board + NFS) | **A** |
| Device reachable by SSH, modest iteration rate | **B** |
| High iteration rate, push-based, only a network socket | **C** (`suzzer-relay` + the brain, §14.1) |
| No device yet / CI / bring-up | **D** (qemu-user) |

### Remote correctness checklist

- Byte order and word size: always parse the header; never hard-code.
- Per-process regions on forking daemons: `%p` in `LIBCOV_SHM_PATH`.
- Use `LIBCOV_REQUIRE=1` on the device so a bad patch list fails loudly
  instead of silently recording nothing over the wire.
- Keep ASLR off on the device while validating ground truth; turn it back on
  for real runs (offsets still resolve).
- Make sure every module in the patch list is actually mapped on the device;
  basename mismatches are the #1 remote failure (see §12, `LIBCOV_MODULE_RENAME`).

---

<a name="10-env-reference"></a>
## 10. Full environment-variable reference

| Var | Default | Meaning |
|---|---|---|
| `LIBCOV_PATCHLIST` | *(required)* | Path to the LCV3 patch list. Unset → library is inert. |
| `LIBCOV_REQUIRE` | unset | Any non-empty value other than `0`: abort the process if libcov ends up inert or any init step fails. Use in controlled harnesses. |
| `LIBCOV_SHM_PATH` | `/libcov_<pid>` | Coverage region path. No `/` other than an optional leading one (`/cov` or `cov`) → `shm_open`, i.e. the file `/dev/shm/cov`; anything with a non-leading `/` (`/tmp/cov`, `./cov`) is an ordinary file. Init logs the resolved location. `%p`→pid, `%%`→`%`. If `shm_open` fails, falls back to `$TMPDIR/<name>` (or `/tmp`). A filesystem path has no fallback. |
| `LIBCOV_MODE` | `leapfrog` | `oneshot` (each site fires once, fastest) or `leapfrog` (re-arm previous site each trap; approximate hit counts — a block that loops back to itself directly counts once per alternation). **Any value other than exactly `oneshot` means leapfrog**; a typo (neither `oneshot` nor `leapfrog`) also logs a WARNING. |
| `LIBCOV_ST_PATCH` | `auto` | ST only. `auto`: code pages made `R|W|X` once (patch = plain store, ~3× faster in leapfrog); `mprotect`: two mprotects per arm/disarm, never `RWX`. `auto` drops to per-write mprotect by itself if the kernel refuses RWX. Unknown values → `auto`. |
| `LIBCOV_MODULE` | main exe | Module name for **boundary sidecar** resolution only (the LCV3 list carries its own module table). |
| `LIBCOV_MODULE_RENAME` | unset | `old=new[,old=new…]`: resolve patch-list module `old` as `new`. For renamed/stripped copies, or `new=/abs/path` to disambiguate duplicate basenames. |
| `LIBCOV_LOG` | unset (stderr) | Diagnostic log path. Never written from the signal handler. If it can't be opened (e.g. missing directory), a one-line notice goes to stderr and logging stays on stderr. |
| `LIBCOV_BOUNDARY_LIST` | unset | Path to the LCVB1 boundary sidecar. Boundaries inert if unset. |
| `LIBCOV_BOUNDARY_REARM` | `none` | `none` / `all` / `touched` — what to re-arm at each boundary (see §3 Q4). Any other value (a typo) means `none`, with a WARNING; with `MODE=oneshot` that triggers the refusal. |
| `LIBCOV_BOUNDARY_RING` | `8` | Ring snapshot slots, clamped to 2–16; a non-numeric value gives 2. Reader lag tolerance = `RING − 1` iters. |
| `LIBCOV_BOUNDARY_INIT_GRACE` | `0` | Don't publish the first N boundary fires (process-wide, counted after depth filtering). Their coverage is **not discarded**; it is merged into the first published snapshot, which is flagged `INIT`. Negative/non-numeric → WARNING, treated as `0`. |
| `LIBCOV_BOUNDARY_NOTIFY_FD` | unset | Inherited **eventfd** (fd > 0); libcov writes a `uint64` 1 after each snapshot. Anything else is ignored with a warning. |
| `LIBCOV_BOUNDARY_EMULATE` | `1` | `0`: never emulate markers; always disarm + deferred re-arm. |
| `LIBCOV_SYNC_FALLBACK` | `auto` | MT only. Cross-core sync: `auto` (use `membarrier(SYNC_CORE)`; if the kernel lacks it, broadcast a signal to peers after each batch), `tgkill` (always broadcast, skipping membarrier even when it works), `off` (no broadcast fallback; cache maintenance only). Unknown values → `auto`. Broadcast is roughly 7–10× slower on a 16-thread stress and can `EINTR` non-restarting syscalls. |
| `LIBCOV_ALLOW_ONESHOT_NOREARM` | unset | Non-empty, not `0`: permit `MODE=oneshot` + `BOUNDARY_REARM=none` (first-hit-only snapshots). Otherwise boundaries are refused, but plain coverage still runs. |

Driver-side (test tools, not libcov): `FUZZ_DRIVER_BURST=1` feeds all inputs
before reading (forces ring overrun for testing). Test-suite knobs:
`THREADS_STRESS`, `ITERS_STRESS`, `ITERS_STRESS_TGKILL`; `SUITE_TIMEOUT`
(seconds per suite in `make test`, default 900; a hang prints `TIMEOUT` and
counts as a failure); `RUN_TIMEOUT` (seconds per target/driver/qemu run in the
cross, signals, paired, boundary and marker-emulation suites, default 60).

---

<a name="11-testing"></a>
## 11. Testing and validating your setup

### The one-command check

```bash
make test
```

Builds both library variants and every test target (`all mt multimod
o2pie`), runs all 20 **native** suites one after another, and prints a
PASS/FAIL summary (failing-suite logs are kept). It refuses to run when
`ARCH` is not the host arch. Each suite uses its own `mktemp -d`, so you can
safely run suites concurrently by hand; `make test` itself is sequential.
Each suite is bounded by `SUITE_TIMEOUT` (default 900 s; the whole run takes
under a minute on a modern x86_64). A failing suite keeps its temp directory
and prints `logs kept in <dir>`; `run_all.sh` keeps its log too. A suite that
finds neither `libcov_st.so` nor `libcov_mt.so` fails with "nothing ran"
instead of passing vacuously.

### Run a single suite by hand

Most suites need more than plain `make`. Build every prerequisite once
first; otherwise suites exit 1 with "missing …":

```bash
make && make THREADING=mt && make -C test all mt multimod o2pie
./test/run_validation.sh                      # ST single-shot regression
./test/run_validation_mt.sh                   # MT + 16-thread/2000-iter stress (+ tgkill pass)
./test/run_validation_boundary.sh             # boundary mode + (MODE,REARM) matrix
./test/run_validation_boundary_mt.sh          # MT boundary: snapshots must not mix threads
./test/run_validation_signals.sh              # blocked masks, target SIGILL handlers (ST+MT)
./test/run_validation_failloud.sh             # misconfigs abort (REQUIRE, oneshot+none, self-test)
./test/run_validation_generator.sh            # generator: call-terminated blocks, indirect calls
./test/run_validation_multimod.sh             # multi-module LCV3 (exe + helper.so)
./test/run_validation_o2pie.sh                # -O2 PIE targets (tail calls, jump tables, ASLR)
./test/run_validation_marker_emulation.sh     # marker emulation across backends (+ MIPS emulator unit test)
./test/run_validation_coverage_options.sh     # N-gram widths, site model, RING, INIT_GRACE, LOG, TRAP_SIGNO
./test/run_validation_generator_safety.sh     # data-in-text / Thumb IT filters, --fail-on-overlap
./test/run_validation_reexec.sh               # re-exec and fork+exec region safety, %p
./test/run_validation_modules.sh              # symlinked/renamed/deleted/duplicate modules, MODULE_RENAME
./test/run_validation_patch_mode.sh           # LIBCOV_ST_PATCH auto/mprotect, W^X simulation
./test/run_validation_paired.sh               # BEGIN/END markers, init/iter/gap counts
./test/run_validation_docs.sh                 # runs this guide's Recipes 1-3, 6 + README example
./test/run_validation_relay.sh                # remote fuzzing template, end to end on loopback
```

> **Editing this guide?** `run_validation_docs.sh` extracts the code blocks
> under "### Recipe 1/2/3/6" and README's "### Example" and runs them, so a
> broken recipe fails `make test`. Keep those headings, and keep the blocks
> runnable from the repo root.

Not part of `make test`: `./test/run_validation_demalloc.sh` (libdemalloc,
see §14) and `./test/run_cross_signals.sh [arch...]` (cross-arch signal
regression under qemu).

Tune the MT stress with `THREADS_STRESS=` / `ITERS_STRESS=`.

### Cross-architecture validation (under qemu-user)

```bash
./test/run_cross.sh      # 11 arches + arm-thumb, ST → expect: PASS=12  FAIL=0  SKIP=0
./test/run_cross_mt.sh   # 11 arches, MT            → expect: FULL_PASS=2  BUILD_ONLY=9  FAIL=0  SKIP=0
```

A missing cross `gcc` or `qemu-<arch>-static` counts as **SKIP**, not FAIL,
so on a host without cross toolchains expect `SKIP=` > 0 and exit 0; only
`FAIL=` > 0 is a real failure.

> **Known limit:** full MT *runtime* validation under qemu-user works only for
> **x86_64 and aarch64** (qemu's TCG translation cache mishandles the
> cross-modifying write). The other 9 architectures are **build-only** under qemu;
> their MT correctness rests on the per-arch atomic-write argument in
> [`src/patch_mt.c`](src/patch_mt.c) and needs **real hardware** to validate.

### Tool self-tests

```bash
python3 tools/mutate.py --selftest      # mutation engine sanity checks
```

### What "it works" looks like for *your* target (smoke test)

1. `gen_patchlist.py … --print-reachable -v` lists the functions you expect.
2. The written `.lcv` starts with `LCV3` and has a sane site count.
3. Running the target under libcov produces a non-empty bitmap:
   `./test/shm_bitmap.py stats /tmp/cov` prints a first number > 0. (Not in
   ST boundary mode; see the §8 caveat.)
4. **Different inputs produce different bitmaps** (coverage actually
   discriminates). Diff two `extract`ed bitmaps.
5. The target's own output is **unchanged** with libcov loaded (instrumentation
   is transparent).
6. Boundary mode only: one `iter` snapshot per input plus one `init` slot;
   `gen_init` recorded; no torn reads/overruns at your rate.

---

<a name="12-troubleshooting"></a>
## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Bitmap stays all-zero | patch list unset/empty, library inert, or ST boundary mode (live bitmap is empty by design) | Read the `libcov:` stderr lines (or `LIBCOV_LOG`); add `LIBCOV_REQUIRE=1` to make it fatal; check the `.lcv` isn't empty. In boundary mode, read the ring (§8). |
| `config: patch list built for threading=mt, this library is st -- refusing` (inert; aborts only with `LIBCOV_REQUIRE`) | MT list given to ST lib (or vice-versa) | Regenerate with the matching `--threading`, or use the matching `.so`. |
| `config: cannot resolve module base for '…': not mapped` (inert) | patch-list basename ≠ mapped basename, or duplicate basenames | `LIBCOV_MODULE_RENAME=gen-name=runtime-name`, or `=/abs/path` to disambiguate. |
| `patch: stale entry at 0x… (bytes mismatch)` and `stale=N` in the `armed=… skipped=… stale=…` summary | stale patch list (binary changed). Those sites are skipped; init goes inert only if **nothing** was armed | Regenerate the patch list from the exact binary you run. |
| Target crashes with a second thread | ST library on a threaded target | Rebuild `THREADING=mt`, regenerate list `--threading mt`. |
| Trap self-test fails → inert | trap encoding not delivered as SIGILL on this platform | Check `tunables_<arch>.h`; keep SIGILL + illegal insn; pick a different illegal encoding if the chip rev differs. |
| Boundaries never fire | marker not a patched site, or (x86) the marker's first block has only 1-byte instructions | Pass `--patchlist` to `gen_boundary.py`; see the gotcha in §6. libcov also logs a WARNING for a marker that isn't a site. |
| Per-iter bitmaps empty after warmup | `MODE=oneshot` + `REARM=none` | Use `leapfrog`/`none` or `oneshot`/`all`\|`touched`. |
| Reader reports lost generations / overruns | ring too small for reader lag | Raise `LIBCOV_BOUNDARY_RING` (≤16); read faster; use the eventfd notify. |
| x86 block not instrumented | block is only 1-byte insns (`ret`, `leave; ret`) — can't hold 2-byte UD2 | Expected; those blocks are skipped by design. |
| Garbled bitmap over the network | reader assumed host byte order / word size | Parse the shm header; reuse `shm_bitmap.py` byte-order logic. |
| Generator errors on startup / can't open binary | rizin not on `PATH`, `rzpipe` missing, or the binary path is wrong or unreadable | Confirm `rizin -v`, `python3 -c 'import rzpipe'` and the path. (rzpipe can busy-loop when rizin can't open the file; `gen_patchlist.py` checks for that up front.) |
| MT syscalls returning `EINTR` unexpectedly | `LIBCOV_SYNC_FALLBACK` signal broadcast | Expected with `tgkill`, or with `auto` on kernels without `membarrier(SYNC_CORE)`; set `off` if you accept cache-maintenance-only sync. |
| `fuzz_driver` exit 3 | ring overrun or failed read | Raise `LIBCOV_BOUNDARY_RING`, read faster, or stop using `FUZZ_DRIVER_BURST`. |

---

<a name="13-recipes"></a>
## 13. Worked end-to-end recipes

**If you are building a fuzzer, copy the Fuzzing recipe immediately below.**
The numbered "Recipe N" blocks after it are smaller, single-purpose coverage
demos (one-shot reading, MT, qemu, ssh, slicing) — useful building blocks, but
each is deliberately minimal and **none of them on its own is a fuzzing setup**.

### Fuzzing recipe (start here): the strong end-to-end setup

This is the configuration to copy for a real campaign. It differs from the
coverage demos below in every row of the
[coverage-vs-fuzzing table](README.md#collecting-coverage-vs-building-a-fuzzer-read-this-first):
leapfrog + ordered 3-gram + a persistent (boundary) model + a heap oracle + a
resumable on-disk corpus + real crash triage. The full mutate→run→score→save
loop is the relay + brain on a network daemon (`target_netd`); for a
fork-per-connection daemon use the one-connection-per-process pattern
([§9 Pattern C](#9-remote)) with the same knobs.

```bash
# 1. Build libcov with ORDERED 3-GRAM (path-sensitive) -- not the default N=2.
make EXTRA_CFLAGS='-DLIBCOV_NGRAM_N=3 -DLIBCOV_NGRAM_ROTATE=1'
# 2. Build the heap-bug oracle (your bug detector), the relay, and the demo daemon.
make tools
make -C tools relay ARCH=x86_64 BUILD=$PWD/build/x86_64
make -C test  netd  ARCH=x86_64 BUILD=$PWD/build/x86_64
# 3. Coverage points + PAIRED request boundaries wrapping the handler.
./tools/gen_patchlist.py build/x86_64/target_netd /tmp/n.lcv --root main
./tools/gen_boundary.py  build/x86_64/target_netd /tmp/n.lcvb \
    req_begin:begin req_end:end --patchlist /tmp/n.lcv
# 4. Brain off-device: mutates, scores novelty, keeps a RESUMABLE ./corpus on
#    disk, saves full crash inputs + metadata. Runs until stopped.
mkdir -p ./corpus && printf 'hello' > ./corpus/s1
python3 tools/suzzer_brain.py --listen 0.0.0.0:7000 --seeds ./corpus --out ./out &
# 5. Relay on-device: spawns the daemon under libcov with the HEAP ORACLE
#    CO-LOADED (colon LD_PRELOAD list). leapfrog is libcov's default, so the
#    strong per-trap mode is automatic here.
./build/x86_64/suzzer-relay \
    --brain 127.0.0.1:7000 --port-file /tmp/netd.port \
    --libcov "$PWD/build/x86_64/libcov_st.so:$PWD/build/x86_64/libdemalloc.so" \
    --patchlist /tmp/n.lcv --boundary /tmp/n.lcvb --shm /tmp/relaycov \
    -- $PWD/build/x86_64/target_netd /tmp/netd.port
# 6. Watch it live, afl-style: have the brain write a status feed and render it.
#    Add `--status-file /tmp/fuzz.jsonl` to the brain (step 4), then:
python3 tools/status_tui.py --input /tmp/fuzz.jsonl
```

**Fuzzing essentials the demos below don't show (do these):**
- **Fuzz a sequence, not one buffer.** For a stateful protocol (a
  login-then-commands session, an HTTP/1.1 keep-alive connection, any
  handshake-then-messages flow) mutate the *whole session* — the ordered list
  of messages — not just a trailing payload. One fixed handshake + one mutated
  tail reaches only a sliver of the state machine.
- **Keep a disk corpus and resume.** Save every new-coverage input to a seed
  directory and reload it on start. An in-memory-only corpus throws away the
  campaign on every restart.
- **Triage-ready crashes.** Save the full input/session that crashed (plus the
  config to replay it), then minimize it — a bare 64 KB payload with no
  transcript is expensive to debug. Dedup by crash site/coverage so one bug
  doesn't fill the directory with hundreds of copies.
- **Vary the target's invocation.** Fuzz more than one argv/config/entry path;
  a single fixed invocation leaves most of the binary's attack surface unreached.
- **Input size:** leave mutate.py's 64 KB `--max-size` default; don't cap at
  ~1 KB. The `1023` you see near `fuzz_driver` is stdin line-framing, not a
  recommended size.

### Recipe 1 — One-shot coverage sanity check (NOT a fuzzing setup)

> This reads cumulative coverage with the *weakest* knobs (`oneshot`, one
> process per input, no boundaries). It is a "did instrumentation fire" check,
> not a fuzzer — to fuzz, use the Fuzzing recipe above.

```bash
make
./tools/gen_patchlist.py build/x86_64/target_simple /tmp/t.lcv --root main
for input in 1 2 3 42; do
  LIBCOV_PATCHLIST=/tmp/t.lcv LIBCOV_SHM_PATH=/tmp/cov_$input \
  LIBCOV_MODE=oneshot LIBCOV_REQUIRE=1 \
  LD_PRELOAD=$PWD/build/x86_64/libcov_st.so \
    build/x86_64/target_simple $input
  echo -n "input=$input -> "; ./test/shm_bitmap.py stats /tmp/cov_$input
done
```

### Recipe 2 — Long-running stdin loop, per-iteration coverage, local (persistent model)

```bash
make
./tools/gen_patchlist.py build/x86_64/target_loop /tmp/t.lcv --root main
./tools/gen_boundary.py  build/x86_64/target_loop /tmp/b.lcvb iter_begin --patchlist /tmp/t.lcv
printf 'alpha\nbeta\ngamma\n' | \
  ./build/x86_64/fuzz_driver \
     build/x86_64/libcov_st.so /tmp/t.lcv /tmp/b.lcvb build/x86_64/target_loop
# expect: init + 3 iter snapshots, exit 0, no lost generations
```

### Recipe 3 — Multi-threaded target, local

```bash
make THREADING=mt
make -C test ARCH=x86_64 BUILD=$PWD/build/x86_64 mt
# --root worker: the thread entry is reached only via pthread_create's pointer
./tools/gen_patchlist.py build/x86_64/target_simple_mt /tmp/t.mt.lcv --threading mt \
    --root main --root worker
LIBCOV_PATCHLIST=/tmp/t.mt.lcv LIBCOV_SHM_PATH=/tmp/cov LIBCOV_REQUIRE=1 \
LD_PRELOAD=$PWD/build/x86_64/libcov_mt.so \
  build/x86_64/target_simple_mt 4 100 1 2 42   # <threads> <iters> <inputs...>
./test/shm_bitmap.py stats /tmp/cov
```

### Recipe 4 — aarch64 target under qemu (remote architecture, local collection)

```bash
make ARCH=aarch64          # also builds the aarch64 ST test targets
./tools/gen_patchlist.py build/aarch64/target_simple /tmp/t.lcv --root main
LIBCOV_PATCHLIST=/tmp/t.lcv LIBCOV_SHM_PATH=/tmp/cov \
  qemu-aarch64-static -L /usr/aarch64-linux-gnu \
  -E LD_PRELOAD=$PWD/build/aarch64/libcov_st.so \
  build/aarch64/target_simple 42
./test/shm_bitmap.py stats /tmp/cov   # byte-order handled by the header
```

### Recipe 5 — Remote device over SSH (Pattern B)

```bash
# Host: build for the device arch and generate the list from the device binary.
make ARCH=arm
./tools/gen_patchlist.py ./device_rootfs/usr/bin/parser /tmp/t.lcv --root parse_request
# Copy artifacts to the device:
scp build/arm/libcov_st.so /tmp/t.lcv dev:/data/
# On the device: run the target against a test input.
ssh dev 'LIBCOV_PATCHLIST=/data/t.lcv LIBCOV_SHM_PATH=/dev/shm/cov LIBCOV_REQUIRE=1 \
         LD_PRELOAD=/data/libcov_st.so /usr/bin/parser < /tmp/input'
# Back on the host: pull the raw region, then extract it locally (byte order handled).
ssh dev 'cat /dev/shm/cov' > /tmp/dev_cov.raw
./test/shm_bitmap.py extract /tmp/dev_cov.raw /tmp/dev_bitmap.bin
```

### Recipe 6 — Selective slice + dry-run iteration

```bash
# See the slice without writing anything:
./tools/gen_patchlist.py build/x86_64/target_dispatch /dev/null \
    --root main --cutoff maybe_exit --max-depth 3 --print-reachable -v
# dispatch() shows "indirect: 1 call(s)": it calls through ops_table, so the
# op_* handlers are not in the slice. Add a --root for each one, then write:
./tools/gen_patchlist.py build/x86_64/target_dispatch /tmp/t.lcv \
    --root main --root op_add --root op_mul --root op_neg --max-depth 3
```

---

---

<a name="14-tooling"></a>
## 14. Fuzzing tooling

Not needed for a bare one-off coverage reading, but **most of this is exactly
what you want for a fuzzing campaign** — the remote relay/brain, the heap-bug
oracle, and the mutation engine. None of it is built by plain `make`; build
the pieces you need with `make tools` / `make -C tools relay` as shown below.

<a name="14-1-remote"></a>
### 14.1 Remote fuzzing: `suzzer-relay` + the brain

The on-device relay [`tools/suzzer-relay.c`](tools/suzzer-relay.c) and the
off-device reference brain [`tools/suzzer_brain.py`](tools/suzzer_brain.py)
are the worked template for Pattern C (§9). The relay spawns a **single-process
network daemon** under libcov, reads the snapshot ring on the device, and
bridges one TCP connection to the brain; the brain mutates, scores novelty and
saves crashes. [`test/target_netd.c`](test/target_netd.c) is a template daemon
(paired `req_begin`/`req_end` markers around its request handler).

Build the relay (cross-compiles like any other backend tool):

```bash
make -C tools relay ARCH=x86_64 BUILD=$PWD/build/x86_64
make -C test  netd  ARCH=x86_64 BUILD=$PWD/build/x86_64
```

Generate a patch list and a **paired** boundary sidecar whose markers wrap the
request handler:

```bash
./tools/gen_patchlist.py build/x86_64/target_netd /tmp/n.lcv --root main
./tools/gen_boundary.py  build/x86_64/target_netd /tmp/n.lcvb \
    req_begin:begin req_end:end --patchlist /tmp/n.lcv
```

Run the brain off-device and the relay on the device. The brain listens; the
relay dials in. **The brain runs in the foreground and blocks**, so start it
in another terminal or in the background, then start the relay within its
`--accept-timeout` (default 15 s). It prints the port it bound (pass port
`0` for an ephemeral one), runs the corpus once, then mutates **until you stop
it** (`--iters N` caps the run only if you ask; default 0 = open-ended). It
keeps a **resumable on-disk corpus** under `<out>/corpus` (reloaded on the next
start) and a built-in-seed fallback if `--seeds` is missing/empty.
`--io-timeout` (default 60 s) bounds the wait for each executor reply, and
`--hello-timeout` (default 600 s) the wait for its HELLO once it has connected.

```bash
# Brain (off-device), backgrounded so the relay can be started next.
mkdir -p ./seeds && printf 'hello' > ./seeds/s1
python3 tools/suzzer_brain.py --listen 0.0.0.0:7000 --seeds ./seeds --out ./out &

# Relay (on the device). It spawns target_netd, which writes its own port to
# the --port-file; the relay delivers each input to 127.0.0.1:<that port>.
./build/x86_64/suzzer-relay \
    --brain BRAIN_HOST:7000 --port-file /tmp/netd.port \
    --libcov $PWD/build/x86_64/libcov_st.so \
    --patchlist /tmp/n.lcv --boundary /tmp/n.lcvb --shm /tmp/relaycov \
    -- $PWD/build/x86_64/target_netd /tmp/netd.port
```

The brain saves each new crash to `./out/crashes/` as the **minimized input
plus a `.info` sidecar** (reason, status, size, hex for replay), **deduplicated
by crash signature** so one bug does not pile up hundreds of files; and it
persists every new-coverage input to `./out/corpus/`. One `INPUT` gets exactly
one `COVERAGE` or `CRASH` reply
(lockstep); the relay also answers a malformed `INPUT` with a `CRASH` frame
(reason 4, saved by the brain as `crash_r4_s0_<hash>`) rather than dropping it, so the brain never waits forever.
Inputs an executor reports as `HANG` or `TIMEOUT` go to `./out/hangs/`
instead, counted apart from crashes and not minimized (each probe would cost
a full timeout; `--minimize-timeouts` opts in). Every distinct hang input is
kept, up to `--max-hangs` (default 64), because a hang's status says little
about which one it is. A finding is always written before it is minimized,
so it survives the executor going away mid-minimization. `--shm` follows the
same naming rule as `LIBCOV_SHM_PATH` (§10). To point it at your own daemon, give the relay your binary and a
boundary sidecar for your handler's entry/exit, and make sure the daemon binds
a port it writes to `--port-file` (or adapt the relay's delivery to your
transport). `test/run_validation_relay.sh` runs this whole path on loopback.

**Scope:** this relay template drives a single-process daemon over plain TCP
(no auth), one input in flight. Fork-per-connection daemons are still fuzzable —
drive one connection per process with per-process coverage regions; see
[Pattern C](#9-remote). Encryption/auth transports need you to adapt the
relay's `deliver`.

### 14.2 Other tools

- **Mutation engine — [`tools/mutate.py`](tools/mutate.py).** An AFL++-style
  havoc mutator, used as a CLI or imported as a library
  (`from tools.mutate import Engine, Dictionary, StructuredInsert`). Run it
  with `python3`:
  ```bash
  python3 tools/mutate.py --seed seed.bin --out /tmp/mutants --count 100 [--dict x.dict]
  ```
  Other flags: `--max-size`, `--seed-rng`, `--splice-from`, `--splice-prob`,
  `--weights`, `--trace`, `--selftest`.
- **Status board — [`tools/status_tui.py`](tools/status_tui.py).** A generic,
  target-agnostic afl/afl++-style static status screen: the boxed process-timing /
  overall-results / map-coverage / stage-progress / findings panels, a run-config
  box showing every `config{}` entry, and a static log of the latest events. It
  has **no hotkeys**: it redraws every `--refresh` seconds (default 1), marks the
  run `STALLED` when the feed stops updating or `RUN FINISHED` when it ends, and
  exits on Ctrl-C. It is a **template you copy**: it reads a simple JSON-lines
  status feed (one object per line — `t`, `execs`, `corpus`, `edges`,
  `map_size`, `crashes`, `crashes_unique`, `config{}`, and `event{}` entries;
  full key list in the file header), so any fuzzer that prints those lines gets
  the board for free — or you replace the one small parser (see the "ADAPT ME"
  block) to read your own log format, keeping `render()` unchanged. suzzer's
  reference brain emits the feed directly. Its `config{}` carries the target
  `arch`, coverage `scheme`, SZR1 `proto` and `ring` size, the `executor` peer, the
  `listen` address, the `out` dir, the `seeds`/`resumed` counts, `max_size`,
  `minimize`, and `iters_limit` when set. `stage` reads `baseline i/N` while the
  corpus is replayed, and `new_edges` counts edges found beyond that baseline.
  ```bash
  # produce a feed from the reference brain, render it live:
  python3 tools/suzzer_brain.py --listen … --seeds … --status-file /tmp/fuzz.jsonl &
  python3 tools/status_tui.py --input /tmp/fuzz.jsonl
  # or just see the layout with no fuzzer at all:
  python3 tools/status_tui.py --demo         # synthetic data
  python3 tools/status_tui.py --selftest     # render checks, exits 0
  ```
  `--dump` prints one text frame (no curses) for CI / tty-less use; `--input -`
  reads the JSON feed from stdin.
- **Heap-bug oracle — [`tools/libdemalloc.c`](tools/libdemalloc.c). Load this
  whenever you are bug-finding.** Without it, the only bugs you catch are the
  ones that happen to hit an unmapped page; most heap overflows and
  use-after-frees die silently. It is an `LD_PRELOAD` allocator, a "poor man's
  ASan": guard pages, an underflow canary, and a bounded quarantine that
  catches UAF and double-free while keeping memory use bounded for daemons.
  Co-load it with libcov: `LD_PRELOAD="$PWD/build/<arch>/libcov_st.so:$PWD/build/<arch>/libdemalloc.so"`.
  Build it with
  `make tools [ARCH=…]`, which writes `build/<arch>/libdemalloc.so`. Tune it
  at compile time, e.g.
  `make tools EXTRA_CFLAGS='-DLIBDEM_QUARANTINE_SLOTS=128'`. Load it
  alongside libcov in `LD_PRELOAD`. Pointers are placed flush against the
  guard page to catch overflows, so by default they are **not 16-byte
  aligned**; for SSE code or strict-alignment CPUs build with
  `EXTRA_CFLAGS='-DLIBDEM_ALIGN_ALLOCATIONS=1'` (see the header of
  `tools/libdemalloc.c` for the per-arch default). Tested by
  `test/run_validation_demalloc.sh`.
- **Attach to a running process — [`tools/inject/`](tools/inject/README.md).**
  For daemons that can't be restarted under `LD_PRELOAD`. `inject_ptrace`
  loads libcov into a live PID (flags `-P` patchlist, `-S` region, `-M` mode,
  `-L` log, `-B` boundary list, `-e KEY=VAL`). It is a separate build:
  `make -C tools/inject [ARCH=…]`.
  **Status:** works on x86_64; aarch64 builds but has no runtime validation
  yet; every other arch is a build-only stub that refuses to attach.
  `inject_procmem` is a stub (ENOSYS). Exit status: `0` injected and the
  coverage region exists, `1` attach/dlopen failed, `2` usage error, `3`
  dlopen worked but libcov looks **inert** (no region; re-run with `-L
  <log>` and `-e LIBCOV_REQUIRE=1`). See its README for details.

<a name="14-3-executor"></a>
### 14.3 Writing your own executor

`suzzer-relay` is one **executor**: the program that runs each input and
reports coverage. An emulator, a QEMU plugin, a bare-metal harness or a
hardware-trace decoder can be another one and still use suzzer's generators
and brain, without linking libcov or building suzzer. Everything it needs is
published:

- **[docs/FORMATS.md](docs/FORMATS.md)**: the specification.
  - LCV3 (§1): the sites to instrument. Record order is the site id, and the
    module base table turns offsets back into addresses with no
    `/proc/self/maps`.
  - LCVB1 (§2): where an iteration begins and ends.
  - LCVS (§3): the shared-memory region, if you want `fuzz_driver`-style
    readers to work.
  - SZR1 (§4): the brain protocol.
  - The coverage bucket formula (§5).
- **[src/lcv_formats.h](src/lcv_formats.h)**: every struct and constant,
  header-only, `<stdint.h>` only, strict-C11 clean. Either copy it into your
  tree at a pinned suzzer commit (with that commit's hash), or read it from
  a suzzer checkout your build is pointed at, and check the format versions
  it defines (`LIBCOV_VERSION`, `LIBCOV_BOUNDARY_VERSION`,
  `LIBCOV_SHM_VERSION`, `SZR_PROTO_VERSION`) at compile time so a format
  change stops your build instead of being misread. Either way, nothing
  links libcov or needs suzzer built.
- **[test/vectors/](test/vectors/)**: conformance vectors. Replay each
  `sequence.bin` through your implementation of FORMATS.md §5 and compare
  with `expected.bin`. Byte-identical maps for the schemes you claim mean your
  bitmaps mean what libcov's do, so corpora carry over between the two.
  [test/vectors_check.py](test/vectors_check.py) is a short reference.
- **[test/fake_executor.py](test/fake_executor.py)**: a ~150-line SZR1
  executor to start from. `test/run_validation_brain.sh` runs it against
  the brain.

For a target that isn't a Linux process:

- Report failures with the executor-neutral crash reasons:
  - `GUEST_FAULT` (5): `status` = faulting PC or a cause code;
  - `ORACLE` (6): an assert/crash check fired;
  - `HANG` (7): no forward progress;
  - `TIMEOUT` (8): the per-input budget ran out.
- The brain saves hangs and timeouts under `<out>/hangs/` and doesn't
  minimize them unless `--minimize-timeouts` is set. A reason the brain
  doesn't know is still saved as a crash, keyed by `(reason, status)`.
- Send HELLO when you are ready to take the first input: the brain waits up
  to `--hello-timeout` (600 s) for it after you connect, then `--io-timeout`
  for each reply. An emulator can connect, boot its firmware, and only then
  say HELLO.
- In HELLO, send a short ASCII arch string (`mips32be`, `rv32`, ...) and a
  `ring_size` of 1 if you deliver one snapshot per input. Set the scheme bits
  for the formula you implement. Leave `MT`/`LIVE_EMPTY` clear unless they
  apply.
- Optionally send your startup coverage as an unsolicited COVERAGE frame
  with `id` 0 and kind INIT before the first reply. Then answer every INPUT
  with exactly one COVERAGE (kind ITER) or CRASH carrying its id.
- Reset the N-gram history before each input (FORMATS.md §5.3).
- To match libcov's maps, emit the way libcov's default `leapfrog` mode does
  (FORMATS.md §5.7):
  - skip a site that was also the last site to emit, so tight self-loops
    count once;
  - count a boundary marker's own hit before resetting the history.

---

*For design internals see [Design.md](Design.md). Note that parts of it
predate the site-id coverage model; where it disagrees with this guide or
README (e.g. a fixed 64 KB bitmap), the code, README and this guide are
current. The deferred-work backlog (daemon lifecycle, fork-per-connection
`suzzer-forkserver`, runtime-selectable N-gram) is in [TODO.md](TODO.md).*
