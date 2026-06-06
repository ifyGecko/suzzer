# libcov (suzzer)

A trap-trampoline coverage library for embedded Linux fuzzing. Two
threading variants are built as separate LEGO bricks:

- **`libcov_st.so`** -- single-threaded, low overhead, smallest possible
  surface area.
- **`libcov_mt.so`** -- thread-safe: per-thread TLS prev_loc, atomic
  saturating bitmap, atomic per-site state machine (spinlock-serialized
  byte writes), `/proc/self/mem` for mprotect-free patching, and
  `membarrier(SYNC_CORE)` for cross-CPU instruction-cache visibility.

Both variants share the same backends across 11 architectures. Pick the
brick that fits your target.

## Idea

Replace selected instructions in a target binary with an architecture's
trap-raising encoding. When the CPU traps, our `LD_PRELOAD`-injected
signal handler:

1. Reads the faulting PC from `ucontext`.
2. Emits an AFL-style edge into a 64 KB shared bitmap.
3. Restores the original instruction so execution continues.

No JIT, no embedded interpreter, no ptrace, no kernel module. Just libc +
sigaction + mprotect. Suitable for memory-constrained embedded targets
where Frida or DynamoRIO are too heavy.

## Supported backends

| Backend           | Trap insn       | Signal  | Patch len | Notes                              |
|-------------------|-----------------|---------|-----------|------------------------------------|
| x86_64            | UD2             | SIGILL  | 2..15     | Variable insn length               |
| aarch64           | UDF #0 (zeros)  | SIGILL  | 4         |                                    |
| arm (ARM mode)    | UDF 0xE7F000F0  | SIGILL  | 4         |                                    |
| arm (Thumb mode)  | UDF.N 0xDE00    | SIGILL  | 2         | Per-function bits=16 detection     |
| mips, mipsel      | BREAK 0         | SIGTRAP | 4         | Generator skips branch delay slots |
| mips64, mips64el  | BREAK 0         | SIGTRAP | 4         | Same as mips32                     |
| powerpc           | tw 31,0,0       | SIGTRAP | 4         |                                    |
| powerpc64 BE+LE   | tw 31,0,0       | SIGTRAP | 4         | Local-entry-aware patch generation |
| riscv64           | c.unimp (zero)  | SIGILL  | 2 or 4    | Mixed 2-byte (C) / 4-byte insns    |

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
```

Outputs land in `build/<arch>/libcov_<threading>.so` (and
`build/<arch>/target_simple` for the ST test target;
`build/<arch>/target_simple_mt` for the pthread stress target via
`make -C test ... mt`).

## Quick start

```
# 1. build for your target's architecture (default ST; add THREADING=mt for MT)
make ARCH=aarch64

# 2. generate a patch list. --threading st by default; --threading mt for
#    libcov_mt.so (the two patch lists are not interchangeable and the
#    library refuses a mismatched LCV2 hint).
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

The 64 KB AFL-style bitmap is written to `/tmp/cov` (or whatever path
`LIBCOV_SHM_PATH` points at). An external fuzzer mmaps the same file/SHM
and reads hit-counts.

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
  (with a note printed to stderr).
- `main` → tries exact match, then `dbg.main`, `sym.main`, `fcn.main`,
  `sym.imp.main`, then matches the last dotted segment of any function
  name. Ambiguous suffix matches are an error.
- `dbg.parse_request` → exact rizin name.

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
```

### Known limits

- **Indirect calls** (function pointers, vtables, dispatch tables) are
  invisible to rizin's static analysis. Slices through them require
  another `--root` at the callee.
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
| `LIBCOV_PATCHLIST` | *(required)* | Path to LCV1-format patch list. If unset, the library is inert. |
| `LIBCOV_SHM_PATH` | `/libcov_<pid>` | Bitmap path. Leading `/` and no other slashes → `shm_open`; otherwise a filesystem path. Falls back to `$TMPDIR/<name>` if `shm_open` fails. |
| `LIBCOV_MODE` | `leapfrog` | `oneshot` (each site fires once, fastest) or `leapfrog` (re-arm previous site each trap; gives hit counts). |
| `LIBCOV_MODULE` | basename of `argv[0]` | Module name in `/proc/self/maps` whose base is used for offset resolution. |
| `LIBCOV_LOG` | unset (stderr) | Init-time diagnostic log. Never written from the signal handler. |

## Modes

**oneshot** -- On the first trap at site X, restore the original
instruction and leave it alone. Fastest; gives "edge-was-reached"
coverage with no hit-count. Recommended for the corpus-explore phase of
fuzzing. Safe under both ST and MT.

**leapfrog** -- On trap at X, restore X *and* re-arm the previously
restored site. Lets the bitmap accumulate hit counts on hot edges.
Higher overhead.

- Under `libcov_st.so`: safe only for single-threaded targets. No
  concurrency primitives.
- Under `libcov_mt.so`: safe under arbitrary thread counts. Each thread
  leapfrogs through its own TLS `g_last_restored`; per-entry spinlocks
  serialize concurrent arm/disarm byte writes; the AFL bitmap uses
  saturating atomic increments; cross-CPU instruction-cache coherence
  comes from `membarrier(SYNC_CORE)`.

## Patch list format (LCV1 and LCV2)

The library accepts two header versions. The legacy LCV1 layout is
preserved as a read-only format; the generator emits LCV2.

LCV1 header (legacy, 16 bytes):

```c
char     magic[4]  = "LCV1";
uint32_t version   = 1;
uint32_t count;
uint32_t reserved;
```

LCV2 header (current, 16 bytes):

```c
char     magic[4]  = "LCV2";
uint32_t version   = 2;
uint32_t count;
uint8_t  threading;  // 0=ANY, 1=ST, 2=MT
uint8_t  flags;      // reserved for future use
uint16_t reserved;
```

Records (24 bytes each, same in both versions):

```c
uint64_t offset;   // from module load base
uint8_t  len;      // original insn length, 1..15
uint8_t  orig[15]; // original bytes; only [0..len) meaningful
```

All little-endian. The library byte-swaps on big-endian targets. A
mismatched `threading` hint (e.g. an MT-generated list given to
`libcov_st.so`) is refused at init with a clear log line.

`tools/gen_patchlist.py` emits LCV2 and the library mmaps it at init.

## ASLR

The library reads `/proc/self/maps` and adds the runtime module base to
every offset, so it works under PIE+ASLR. For deterministic test runs we
recommend `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space` while
iterating on the patch list. With ASLR on, addresses still resolve
correctly because patch records are offsets — but ground-truth comparisons
across runs are easier with ASLR off.

## Hardening

- The library refuses to patch addresses inside its own mapping
  (`/proc/self/maps` lookup of the function `util_self_range`).
- `sigaction(2)` and `signal(2)` are intercepted; if the target tries to
  install its own handler for the backend's trap signal post-init, the
  request is acknowledged with success but our handler stays installed.
  The target's intended handler is stashed and chained for *real* traps
  (faults at addresses not in our patch table).
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
- **One module per patch list.** LCV2 currently still covers a single
  target module (the main executable). Multi-module support (header
  module table + per-record module index) is the next iteration of the
  wire format; LCV2's header already has room.
- **No JIT/self-modifying code support.** Newly-generated code is not in
  the patch list and won't be instrumented.
- **W^X-strict kernels** that refuse a transient `RW` on a code page will
  fail at `patch_arm`. The library uses two `mprotect` calls per site
  (never `RWX`) to maximise compatibility.
- **Per-arch length minimums.** Fixed-width-insn architectures (everything
  except x86) can only patch full instructions. x86_64 can patch any
  instruction >= 2 bytes; 1-byte insns (`ret`, `push rbp`) are skipped by
  the generator.

## Files

```
src/
  libcov.c            constructor; env parsing; sigaction/signal interception
  util.c/.h           /proc/self/maps parsing; init-time logger
  config.c/.h         LCV1+LCV2 mmap loader; sorted patch_entry table (endian-safe);
                      threading-hint enforcement
  patch.h             arm/disarm/lookup interface (same ABI both variants)
  patch_st.c          ST: mprotect + memcpy + cache flush
  patch_mt.c          MT: /proc/self/mem + per-entry spinlock + membarrier(SYNC_CORE)
  handler.h           trap-handler interface
  handler_st.c        ST handler; global g_last_restored
  handler_mt.c        MT handler; TLS g_last_restored
  sink.h              AFL-style edge hash; macro-gated TLS prev_loc + atomic emit (MT)
  sink_shm.c          bitmap mmap (shm_open + filesystem fallback); prev_loc def
  membarrier.h/.c     MT-only; PRIVATE_EXPEDITED_SYNC_CORE wrapper with fallback
  arch.h              backend interface (extern symbols, no #ifdefs)
  arch_x86_64.c       ST x86: UD2 + NOP padding / SIGILL / 2..15 bytes
  arch_x86_64_mt.c    MT x86: UD2 head-only (single atomic 2-byte write)
  arch_aarch64.c      UDF #0 / SIGILL / 4-byte fixed (ST+MT)
  arch_arm.c          ARM UDF + Thumb UDF.N / SIGILL / 2 or 4 bytes (ST+MT)
  arch_mips.c         BREAK 0 / SIGTRAP / 4-byte fixed MIPS32 BE+LE (ST+MT)
  arch_mips64.c       same / 4-byte fixed (ST+MT)
  arch_powerpc.c      tw 31,0,0 / SIGTRAP / PPC32 BE (ST+MT)
  arch_powerpc64.c    tw 31,0,0 / SIGTRAP / PPC64 BE+LE (ST+MT)
  arch_riscv64.c      c.unimp / SIGILL / 2-or-4-byte (ST+MT)
test/
  target_simple.c       ground-truth target (10+ branches)
  target_simple_mt.c    pthread stress target for MT validation
  fuzz_driver.c         toy external driver
  run_validation.sh     native ST regression test
  run_validation_mt.sh  native MT regression test + stress
  run_cross.sh          all-arch ST validation under qemu-user-static
  run_cross_mt.sh       all-arch MT validation (full run for x86_64+aarch64;
                        build-only for the other 9 due to qemu-user TCG limits)
tools/
  gen_patchlist.py    rizin-based LCV2 generator; per-arch strategy
                      (terminator vs entry, Thumb-aware, delay-slot-aware,
                      ppc64 local-entry-aware); --threading st|mt
TODO.md               deferred design work (daemons, transport, etc.)
```

## Validation

```
# Native (x86_64) ST regression:
make
./test/run_validation.sh

# Native (x86_64) MT regression + 16-thread/2000-iter stress:
make THREADING=mt
./test/run_validation_mt.sh

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

## What's next

See [TODO.md](TODO.md) for the design backlog. Short version: this PoC
proves the trampoline mechanism across architectures. The next phase
makes it useful against long-running network daemons (iteration boundary
detection, multi-module patch lists, fork-per-connection, multi-thread,
remote coverage transport via a separate relay binary).
