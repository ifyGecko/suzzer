# libcov (suzzer)

A trap-trampoline coverage library for embedded Linux fuzzing. Proof of
concept. Currently single-threaded; supports 11 backends across the
common embedded-Linux architectures.

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
make                      # native build (auto-detects host arch)
make ARCH=aarch64         # cross-build with aarch64-linux-gnu-gcc
make all-arch             # build every supported backend
```

Outputs land in `build/<arch>/libcov.so` (and `build/<arch>/target_simple`
for the test target).

## Quick start

```
# 1. build for your target's architecture
make ARCH=aarch64

# 2. generate a patch list (uses rizin under the hood; auto-picks per-arch
#    instrumentation strategy: terminator vs entry, Thumb-aware, etc.)
./tools/gen_patchlist.py build/aarch64/target_simple /tmp/t.lcv \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline)$'

# 3. run the target under libcov
LIBCOV_PATCHLIST=/tmp/t.lcv \
LIBCOV_SHM_PATH=/tmp/cov \
LIBCOV_MODE=leapfrog \
LD_PRELOAD=./build/aarch64/libcov.so \
    qemu-aarch64-static -L /usr/aarch64-linux-gnu \
    -E LD_PRELOAD=$PWD/build/aarch64/libcov.so \
    build/aarch64/target_simple 42
```

The 64 KB AFL-style bitmap is written to `/tmp/cov` (or whatever path
`LIBCOV_SHM_PATH` points at). An external fuzzer mmaps the same file/SHM
and reads hit-counts.

## Environment variables

| Var | Default | Meaning |
|---|---|---|
| `LIBCOV_PATCHLIST` | *(required)* | Path to LCV1-format patch list. If unset, the library is inert. |
| `LIBCOV_SHM_PATH` | `/libcov_<pid>` | Bitmap path. Leading `/` and no other slashes → `shm_open`; otherwise a filesystem path. Falls back to `$TMPDIR/<name>` if `shm_open` fails. |
| `LIBCOV_MODE` | `leapfrog` | `oneshot` (each site fires once, fastest) or `leapfrog` (re-arm previous site each trap; gives hit counts). |
| `LIBCOV_MODULE` | basename of `argv[0]` | Module name in `/proc/self/maps` whose base is used for offset resolution. |
| `LIBCOV_LOG` | unset (stderr) | Init-time diagnostic log. Never written from the signal handler. |

## Modes

**oneshot** — On the first trap at site X, restore the original instruction
and leave it alone. Fastest; gives "edge-was-reached" coverage with no
hit-count. Recommended for the corpus-explore phase of fuzzing.

**leapfrog** — On trap at X, restore X *and* re-arm the previously
restored site. Lets the bitmap accumulate hit counts on hot edges. Higher
overhead; only safe for single-threaded targets (the PoC assumption).

## Patch list format (LCV1)

Header (16 bytes):

```c
char     magic[4]  = "LCV1";
uint32_t version   = 1;
uint32_t count;
uint32_t reserved;
```

Records (24 bytes each):

```c
uint64_t offset;   // from module load base
uint8_t  len;      // original insn length, 1..15
uint8_t  orig[15]; // original bytes; only [0..len) meaningful
```

All little-endian. `tools/gen_patchlist.py` emits this format and consumes
it directly via mmap at init.

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

## Limitations (PoC)

- **Single-threaded targets only.** Leapfrog mode is unsafe under threads
  (one thread may be executing a site another is re-arming). Edge hashing
  uses a plain `prev_loc` global with no atomics. TLS `prev_loc` + per-arch
  re-arm safety is a planned extension (see `TODO.md`).
- **One module per patch list.** The current LCV1 format covers a single
  target module (typically the main executable). Multi-module support
  (LCV2 with a module name table) is on the list.
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
  config.c/.h         LCV1 mmap loader; sorted patch_entry table (endian-safe)
  patch.c/.h          mprotect + memcpy + cache flush; arm/disarm/lookup
  handler.c/.h        trap handler; oneshot vs leapfrog mode
  sink.h              AFL-style edge hash; inline sink_emit
  sink_shm.c          bitmap mmap (shm_open + filesystem fallback)
  arch.h              backend interface (extern symbols, no #ifdefs)
  arch_x86_64.c       UD2 / SIGILL / variable-length
  arch_aarch64.c      UDF #0 / SIGILL / 4-byte fixed
  arch_arm.c          ARM UDF + Thumb UDF.N / SIGILL / 2 or 4 bytes
  arch_mips.c         BREAK 0 / SIGTRAP / 4-byte fixed (MIPS32 BE+LE)
  arch_mips64.c       same / SIGTRAP / 4-byte fixed
  arch_powerpc.c      tw 31,0,0 / SIGTRAP / PPC32 BE
  arch_powerpc64.c    tw 31,0,0 / SIGTRAP / PPC64 BE+LE
  arch_riscv64.c      c.unimp / SIGILL / 2-or-4-byte
test/
  target_simple.c     ground-truth target (10+ branches)
  fuzz_driver.c       toy external driver
  run_validation.sh   native (x86_64) regression test
  run_cross.sh        all-arch validation under qemu-user-static
tools/
  gen_patchlist.py    rizin-based LCV1 generator; per-arch strategy
                      (terminator vs entry, Thumb-aware, delay-slot-aware,
                      ppc64 local-entry-aware)
TODO.md               deferred design work (daemons, MT, transport, etc.)
```

## Validation

```
# Native (x86_64) regression check:
make
./test/run_validation.sh

# All backends under qemu-user-static (requires gcc-<arch>-linux-gnu*
# and qemu-user-static; see top of file for the apt package list):
./test/run_cross.sh
```

Each backend is validated for: bitmap determinism, input differentiation
(different inputs ⇒ different bitmaps), leapfrog hit-count recording, and
target output unchanged with libcov loaded.

## What's next

See [TODO.md](TODO.md) for the design backlog. Short version: this PoC
proves the trampoline mechanism across architectures. The next phase
makes it useful against long-running network daemons (iteration boundary
detection, multi-module patch lists, fork-per-connection, multi-thread,
remote coverage transport via a separate relay binary).
