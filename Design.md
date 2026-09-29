# suzzer / libcov — Design Document

This document describes every component of the suzzer coverage library
("libcov") as currently implemented. It covers the runtime library, the
patch-list wire format, each architecture backend, the patch-list
generator, the build system, and the validation harness. It is intended
as a reference for understanding *what* exists and *why* it was designed
that way.

---

## 1. Goals and motivation

Vulnerability research on embedded Linux devices commonly needs coverage
feedback to drive a guided fuzzer. The conventional approaches are:

- **Source-instrumented builds** (AFL's `afl-gcc`, SanitizerCoverage):
  require rebuilding the target with a toolchain we control. Usually
  impossible for closed-source firmware.
- **Full-system emulation** (qemu-system, Unicorn, AFL++ qemu-mode):
  expensive setup; many embedded devices use peripherals, kernel
  modules, or boot processes that resist emulation.
- **Dynamic binary instrumentation** (Frida, DynamoRIO, PIN): drags in a
  large runtime (Frida embeds a JavaScript engine, DynamoRIO is its own
  code-cache JIT). Memory-constrained embedded targets often can't host
  these.

If we can get shell access on the device — typically easier than
emulating it — we can `LD_PRELOAD` a tiny library that adds coverage at
the cost of a few KB of code and a 64 KB shared bitmap. The whole
mechanism uses only libc primitives that exist on essentially every
Linux device: `mmap`, `mprotect`, `sigaction`, and the `__builtin___clear_cache`
intrinsic (which expands to a syscall on architectures with separate
I-cache and D-cache).

**The single insight that makes this viable**: synchronous CPU faults
(illegal-instruction, breakpoint, alignment, etc.) deliver a signal to
the faulting process synchronously, the signal handler receives the
trap's PC via `ucontext`, and on return from the handler the kernel
re-executes the instruction at the (possibly modified) PC. This gives us
a callback-on-execute primitive at any address we choose — we just
replace the instruction there with a guaranteed-trap encoding.

The trap signal is `LIBCOV_TRAP_SIGNO` (default `SIGILL`), shared by
every backend. Each backend's default illegal-instruction encoding is
chosen so the Linux kernel delivers SIGILL on the target arch:

- x86_64: UD2.
- AArch64: UDF #0 (all-zero word).
- ARM / Thumb: UDF / UDF.N.
- RISC-V: c.unimp.
- MIPS / MIPS64: user-mode COP0 access (`MFC0 $0, $0`) — kernel-rejected
  via Coprocessor Unusable handler on every revision.
- PowerPC / PowerPC64: all-zero word (PowerISA-reserved illegal).

The signal is a "synchronous fault" signal: blocking it at a
`pthread_sigmask` level does not prevent delivery for the faulting
thread; the kernel forces termination if the signal is blocked. We rely
on this to ensure our handler always runs. The signal choice and every
per-arch encoding are overridable through `src/tunables.h` and
`src/tunables_<arch>.h` (see section 6.4).

---

## 2. High-level architecture

```
                            ┌────────────────────────┐
                            │ external fuzz driver   │
                            │  - mmaps the bitmap    │
                            │  - drives inputs       │
                            └──────────┬─────────────┘
                                       │ reads
                                       ▼
                            ┌────────────────────────┐
                            │ 64KB shm bitmap        │
                            │ (AFL hit-count style)  │
                            └──────────┬─────────────┘
                                       ▲ writes (sink_emit)
                                       │
LD_PRELOAD libcov.so loaded into target process:

  ┌─────────────────────────────────────────────────────────────┐
  │  constructor(101) — libcov_init                             │
  │    1. open log fd (LIBCOV_LOG or stderr)                    │
  │    2. resolve module base via /proc/self/maps               │
  │    3. mmap LCV3 patch list                                  │
  │    4. mmap 64KB shm bitmap                                  │
  │    5. allocate sorted patch_table[]                         │
  │    6. for each entry: mprotect→memcpy(illegal insn)→        │
  │           mprotect→cache flush                              │
  │    7. install LIBCOV_TRAP_SIGNO handler                     │
  │    8. install sigaction/signal interceptors                 │
  │  return to main()                                           │
  └─────────────────────────────────────────────────────────────┘

  Target executes normally until it hits a patched instruction:

  ┌─────────────────────────────────────────────────────────────┐
  │  kernel delivers LIBCOV_TRAP_SIGNO (default SIGILL)         │
  │  trap_handler:                                              │
  │    pc = arch_pc_from_uctx(uc)                               │
  │    e  = patch_lookup(pc)             [signal-safe bsearch]  │
  │    if (!e || !e->patched)                                   │
  │       chain_or_default(...)          [real fault path]      │
  │    else:                                                    │
  │       sink_emit(pc)                  [bitmap update]        │
  │       patch_disarm(e)                [restore original]     │
  │       if (leapfrog && g_last_restored && g_last != e)       │
  │           patch_arm(g_last_restored)                        │
  │       g_last_restored = e                                   │
  │  return → kernel re-executes restored insn                  │
  └─────────────────────────────────────────────────────────────┘
```

The library is **strictly single-threaded** in its current form. The
patch table and the bitmap have no concurrency primitives. Leapfrog mode
specifically requires a single-thread target.

---

## 3. The trap-trampoline mechanism

### 3.1 Patching

For each address in the patch list, we replace the original instruction
bytes with the architecture's chosen trap-raising encoding. The replacement
is performed atomically from the CPU's perspective via the standard
`mprotect → write → mprotect` sequence; the original bytes are recorded
in the patch table for later restoration.

### 3.2 Trap and handler

When execution reaches the patched address, the CPU raises the trap.
The kernel delivers LIBCOV_TRAP_SIGNO (default SIGILL) synchronously to the
faulting thread. Our handler examines `ucontext_t`, extracts the PC, and
looks the address up in our sorted patch table.

### 3.3 Coverage emission

If the PC is in our table, we emit into the bitmap. The exact index
formula is selected at build time by `LIBCOV_NGRAM_N` (default 2 =
AFL edges; see §9.2 for block / AFL / N-gram schemes):

```c
cur_loc  = hash16(pc)
idx      = (prev_loc[0] ^ ... ^ prev_loc[N-2] ^ cur_loc) & MAP_MASK
bitmap[idx]++                                  // saturating at 255
// shift window; freshest slot becomes cur_loc >> 1
```

### 3.4 Restore and continue

We `mprotect → memcpy → mprotect` to restore the original bytes,
`__builtin___clear_cache` over the range (a no-op on x86, a real cache
flush on ARM/MIPS/PPC/RISC-V), and return from the handler. The kernel's
signal frame restore puts the PC back to the same address; the CPU
re-fetches the now-restored instruction and proceeds.

### 3.5 Two modes

**Oneshot** (`LIBCOV_MODE=oneshot`):
After restoration the site is permanently disarmed. Each site fires at
most once per process lifetime. Fastest mode; coverage is "did this
edge fire" rather than "how many times".

**Leapfrog** (`LIBCOV_MODE=leapfrog`, default):
When the handler runs, in addition to disarming the current site, it
re-arms the *previously* restored site (stored in `g_last_restored`).
This keeps every patched edge "live" across the whole run; the bitmap
accumulates hit counts. We never re-arm the current PC's site (that
would infinite-loop). Single-threaded targets only — re-arming a site
that another thread is executing is a race.

---

## 4. Wire format -- LCV3

Patch lists are flat binary, little-endian regardless of target endian.
The library accepts only LCV3; there is no backward-compatibility path
for earlier versions.

### 4.1 LCV3 header (24 bytes)

```c
struct patchlist_header_v3 {
    char     magic[4];        // "LCV3"
    uint32_t version;         // 3
    uint32_t count;           // number of records
    uint8_t  threading;       // 0=ANY, 1=ST, 2=MT
    uint8_t  flags;           // reserved, must be 0
    uint8_t  module_count;    // 1..255
    uint8_t  reserved;
    uint32_t modules_offset;  // file offset of module name table
    uint32_t modules_size;    // bytes in the name table
} __attribute__((packed));
```

The `threading` byte enforces variant-correctness: an MT-generated
patch list (per-arch atomic-width records, x86 cache-line-safe sites
only) given to `libcov_st.so` (or vice-versa) is refused at init with
a clear log line rather than producing subtly-wrong coverage.

`module_count` is the number of entries in the trailing module name
table. The runtime resolves one load base per module name at init from
`/proc/self/maps` and stores them in `libcov_module_bases[]`.

### 4.2 Record (14 bytes)

```c
struct patchlist_record {
    uint64_t offset;       // from libcov_module_bases[module_idx]
    uint8_t  len;          // bytes to patch and restore (2 or 4)
    uint8_t  module_idx;   // index into the name table
    uint8_t  orig[4];      // first `len` bytes meaningful
} __attribute__((packed));
```

Per-record `len` lets back-to-back 2-byte ISAs (arm-Thumb, riscv64-C)
coexist with 4-byte ISAs in the same list without one site's arm
clobbering a neighboring armed site. `orig[4]` is sized for the widest
cross-arch case (4-byte fixed-width ISAs); x86 (UD2) and 2-byte ISAs
store 2 meaningful bytes and ignore the tail. See §17.1.1 for the
per-arch patch-byte table.

### 4.3 Module name table

A flat blob of `module_count` NUL-terminated basenames concatenated at
`modules_offset` (typically immediately after the records). Names are
the basenames the runtime looks up in `/proc/self/maps` -- e.g.
`"target_simple\0libfoo.so\0libasdf.so\0"`. Index 0 is the primary
module (typically the executable); indices 1..N are auxiliary modules
in the order the generator was given them.

### 4.4 Endian handling

The library reads multi-byte header fields and `offset` through
`le32toh` / `le64toh` from `<endian.h>`, so a big-endian target running
on a BE build of libcov correctly parses an LE wire file. Without this,
a BE target would read version=3 as 0x03000000 and reject the file.

### 4.5 Address resolution

Each record's `offset` is relative to `libcov_module_bases[module_idx]`.
At init `config_load` walks the name table and calls
`util_module_base(name)` for each entry; `util_module_base` parses
`/proc/self/maps` and returns `lo - file_offset` for the first mapping
whose path basename matches. For non-PIE binaries the result is the
binary's linked base (e.g. 0x400000 on x86_64, 0x10000 on 32-bit ARM).
For PIE binaries and shared libraries it is the ASLR'd load address.
The generator emits `offset = absolute_addr - rizin.bin.baddr`, which
composes correctly with either case.

If any named module is not currently mapped, `config_load` refuses to
finish loading and logs which name failed -- better to fail loudly at
init than to leave half the patch table silently misindexed.

### 4.6 Why a custom format

Alternatives considered: text/CSV (slow parse on weak embedded CPUs;
parser bugs); a serialized struct from libelf; YAML/JSON. The flat
binary form maps with one `mmap` call, parses with a pointer cast, and
has zero parser surface area to get wrong.

---

## 5. Module layout

```
src/
  libcov.c              constructor + sigaction/signal interception
  util.c, util.h        /proc/self/maps parsing + init-time logger
  config.c, config.h    LCV3 mmap loader + per-module base resolution +
                        sorted patch_entry table; threading-hint enforcement
  patch.h               arm/disarm/lookup interface (shared by ST and MT)
  patch_st.c            ST patch engine: mprotect dance + memcpy
  patch_mt.c            MT patch engine: RWX-once pages + single atomic store
                        + per-entry spinlock + clear_cache + membarrier(SYNC_CORE)
  handler.h             trap-handler interface
  handler_st.c          ST trap handler (global g_last_restored)
  handler_mt.c          MT trap handler (TLS g_last_restored)
  sink.h                inline N-gram emit + edge hashing + sink_emit;
                        macro-gated TLS vs global prev_loc window + atomic vs
                        plain inc; LIBCOV_NGRAM_N selects block / AFL edge /
                        N-gram scheme
  sink_shm.c            64KB bitmap (shm_open + filesystem fallback);
                        prev_loc window definition (TLS for MT)
  membarrier.h, membarrier.c
                        MT-only; PRIVATE_EXPEDITED_SYNC_CORE wrapper
                        with init-time detection + graceful fallback
  arch.h                backend interface (extern symbol contract)
  arch_x86_64.c         x86 UD2 head-only (ST+MT share, no NOP padding)
  arch_aarch64.c        UDF #0 / 4-byte fixed (ST+MT share)
  arch_arm.c            ARM UDF + Thumb UDF.N (ST+MT share)
  arch_mips.c           MIPS32 user-mode MFC0 / SIGILL (ST+MT share)
  arch_mips64.c         MIPS64 user-mode MFC0 / SIGILL (ST+MT share)
  arch_powerpc.c        PPC32 all-zero illegal / SIGILL (ST+MT share)
  arch_powerpc64.c      PPC64 BE+LE all-zero illegal / SIGILL (ST+MT share)
  arch_riscv64.c        c.unimp (ST+MT share)
  tunables.h            project-wide knobs (trap signo, bitmap size, log buf)
  tunables_<arch>.h     per-backend knobs (illegal encoding(s) + widths);
                        one per backend, every knob -D-overridable
  patchlist_format.h    on-disk LCV3 wire format + runtime patch_entry
                        (formerly config.h; renamed to avoid confusion with
                        tunables headers)

tools/
  gen_patchlist.py      rizin-based LCV3 generator; per-arch strategies;
                        --threading st|mt selects record-length encoding;
                        --module name:path adds auxiliary modules
  gen_boundary.py       rizin-based LCVB1 sidecar generator; resolves
                        symbol names to their first-BB terminator
  mutate.py             generic AFL++-style mutation engine; stdlib-only;
                        importable Engine/Dictionary/StructuredInsert +
                        CLI for ad-hoc mutant dumping and selftest. See
                        the file's module docstring for the full API
                        surface and the fuzz_telnetd/DESIGN.md
                        section-6 retrospective for the design rationale

test/
  target_simple.c       ground-truth ST target with known branch graph
  target_simple_mt.c    pthread MT stress target
  fuzz_driver.c         toy stdin-driven external driver
  run_validation.sh     native ST validation
  run_validation_mt.sh  native MT validation + stress
  run_cross.sh          all-backend ST validation under qemu-user-static
  run_cross_mt.sh       MT validation (full run for x86_64+aarch64;
                        build-only for the other 9 due to qemu-user TCG)
  Makefile              test target build rules

Makefile               top-level: ARCH x THREADING selection
README.md              user-facing
TODO.md                deferred design backlog
Context.md             dense reload state
Design.md              this file
```

---

## 6. Backend interface (`src/arch.h`)

Exactly one `arch_<name>.c` is linked into each `libcov.so` build. Each
backend provides:

```c
extern const char    *libcov_arch_name;        // "x86_64", "aarch64", ...
extern const uint8_t  libcov_min_patch_len;    // smallest patchable insn
extern const uint8_t  libcov_max_patch_len;    // largest patchable insn

void      libcov_arch_write_illegal(void *dst, uint8_t len);
uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc);
```

The trap signal is project-wide, not per-backend: every backend uses
`LIBCOV_TRAP_SIGNO` (default `SIGILL`) from `src/tunables.h`. To switch
the whole project to a different signal you change `LIBCOV_TRAP_SIGNO`
and any per-arch ILLEGAL encoding(s) together so the encoding agrees
with the signal it must raise.

This is the entire ABI. No `#ifdef ARCH` exists in the core code. The
core (`libcov.c`, `handler.c`, `patch.c`, `config.c`, `util.c`,
`sink_shm.c`) is byte-for-byte identical across all backends.

The per-backend constants the `extern`s above expose (name, widths, the
bytes written by `libcov_arch_write_illegal`) are not hardcoded in the
`.c` file — each backend pulls them from `src/tunables_<arch>.h`, which
is `#ifndef`-guarded so every knob is overridable either by editing the
default or by passing `-D` at build time. See section 6.4.

### 6.1 Backend matrix

Every backend raises `LIBCOV_TRAP_SIGNO` (= `SIGILL` by default).

| Backend          | Default trap insn        | Min len | Max len | Special handling                          |
|------------------|--------------------------|---------|---------|-------------------------------------------|
| x86_64 (ST)      | UD2 (`0F 0B`)            | 2       | 15      | Variable insn length; pad with 0x90       |
| x86_64 (MT)      | UD2 (`0F 0B`)            | 2       | 2       | Head-only write; single-copy-atomic       |
| aarch64          | UDF #0 (`0x00000000`)    | 4       | 4       | Fixed                                     |
| arm (ARM mode)   | UDF (`0xE7F000F0`)       | 2       | 4       | Per-site dispatch on len                  |
| arm (Thumb mode) | UDF.N (`0xDE00`)         | 2       | 4       | len=2 selects Thumb encoding              |
| mips, mipsel     | MFC0 $0,$0 (`0x40000000`)| 4       | 4       | Was BREAK 0 / SIGTRAP; see 6.2            |
| mips64, mips64el | MFC0 $0,$0 (`0x40000000`)| 4       | 4       | Was BREAK 0 / SIGTRAP; see 6.2            |
| powerpc          | all-zero (`0x00000000`)  | 4       | 4       | Was `tw 31,0,0` / SIGTRAP; see 6.2        |
| powerpc64 BE+LE  | all-zero (`0x00000000`)  | 4       | 4       | Was `tw 31,0,0` / SIGTRAP; see 6.2        |
| riscv64          | c.unimp (`0x0000`)       | 2       | 4       | 2 or 4 selects len; 4 = two c.unimps      |

x86_64 ST/MT live in one source file (`arch_x86_64.c`) that selects
behaviour via `#ifdef LIBCOV_THREADING_MT` (set by the Makefile).
Defaults for `MAX_PATCH_LEN` follow the same switch in
`tunables_x86_64.h`.

### 6.2 Per-backend rationale

**x86_64 / UD2**: canonical illegal opcode, 2 bytes, well-defined since
the 286. ST mode writes UD2 + (len-2) NOP padding because instructions
are variable-length; the trap fires on the first 2 bytes, padding never
executes. MT mode writes only the 2-byte UD2 because a naturally-aligned
2-byte store is the largest single-copy-atomic write x86_64 guarantees
(Intel SDM Vol 3 Sec 8.1.1); the tail bytes of the original instruction
are never touched.

**aarch64 / UDF #0**: ARMv8 ARM specifies the all-zero word as
"permanently undefined". The encoding `D4 20 00 00` (`UDF #0` proper) is
equivalent; we use the all-zero form for simplicity.

**arm / UDF (ARM) + UDF.N (Thumb)**: ARMv7 has two instruction sets in
the same binary. Functions are tagged ARM or Thumb by the LSB of the
symbol address (ARM ELF convention). `0xE7F000F0` is the ARMv7
permanently-undefined ARM-mode encoding; `0xDE00` is the Thumb UDF.N.
Our backend dispatches on `len`: 4 → ARM, 2 → Thumb. For 4-byte Thumb-2
instructions we still write a 2-byte UDF.N at the leading half-word; the
trap fires before the back half is fetched, and the original 4-byte
sequence is intact after restore because we never modified bytes [2,4).
The generator forces `len=2` for any site in a Thumb function.

**mips / `MFC0 $0, $0` (was: BREAK 0 / SIGTRAP)**: MIPS has no
universally-portable always-RI (Reserved Instruction) encoding across
r1..r6; chip-revision-specific reserved opcodes get repurposed. The
default `0x40000000` sidesteps this by encoding a user-mode access to
coprocessor 0, which the Linux MIPS kernel rejects unconditionally on
every revision by delivering `SIGILL` (`ILL_PRVOPC`) via the Coprocessor
Unusable handler. The historical backend used `BREAK 0` (raises
SIGTRAP); the switch to a SIGILL-raising encoding lets the whole project
share one signal handler. If your target restricts COP0 access through a
custom emulator path, override `LIBCOV_ARCH_MIPS_ILLEGAL` in
`tunables_mips.h`.

**mips64**: identical encoding rationale as mips32. The glibc
`ucontext_t.uc_mcontext.pc` field name is the same across both.

**powerpc / all-zero (was: `tw 31, 0, 0` / SIGTRAP)**: the PowerISA spec
reserves the all-zero 32-bit word as illegal across every variant (32/64,
BE/LE). Linux delivers `SIGILL` (`ILL_ILLOPC`) via a Program Check
interrupt. The historical backend used `tw 31, 0, 0` (raises SIGTRAP);
the switch matches the project-wide SIGILL default. PC accessor on glibc
ppc32 is `uc->uc_mcontext.uc_regs->gregs[PT_NIP]`.

**powerpc64**: same encoding rationale. Glibc ppc64 puts PC at
`uc->uc_mcontext.gp_regs[PT_NIP]` (no `uc_regs` indirection). The
backend file uses that path.

**riscv64 / c.unimp**: the all-zero compressed instruction (`0x0000`) is
defined as the "canonical illegal" by the RVC spec. Mixed C
(compressed) / standard encoding means original instructions can be
2 or 4 bytes. For `len=4` we write four zero bytes which decodes as two
back-to-back c.unimps; the first traps immediately. SIGILL.

### 6.3 Endianness

Each `libcov_arch_write_illegal` writes its trap encoding as a native
`uint32_t` (or `uint16_t`). Because the backend is compiled for the
target's endianness, native stores produce the byte order the CPU
expects when it later fetches the instruction. No explicit byte-swapping
is needed in the backends.

### 6.4 Tunables and configuration

The project ships two layers of tunables headers, both using the same
`#ifndef`-guard pattern. Every knob can be changed either by editing
the value in the header or by passing `-D` flags at build time; the
`-D` wins because the preprocessor sees it first.

**`src/tunables.h`** — cross-cutting knobs:
- `LIBCOV_TRAP_SIGNO` (default `SIGILL`).
- `LIBCOV_MAP_SIZE_POW2` (default 16; coverage bitmap = 1 << POW2 bytes).
- `LIBCOV_NGRAM_N` (default 2; window length for coverage scheme.
  1 = block, 2 = AFL edges, 3..8 = N-gram. See §9.2.)
- `LIBCOV_NGRAM_ROTATE` (default 0; when 1, per-position rotation
  before XOR so reordered windows index to distinct buckets. Useful
  at higher N to reduce XOR-commutativity collisions.)
- `LIBCOV_LOG_BUFFER_SIZE` (default 512; per-message buffer in libcov_logf).

**`src/tunables_<arch>.h`** — per-backend knobs. One file per arch:
`tunables_x86_64.h`, `tunables_aarch64.h`, `tunables_arm.h`,
`tunables_mips.h`, `tunables_mips64.h`, `tunables_powerpc.h`,
`tunables_powerpc64.h`, `tunables_riscv64.h`. Each defines:
- `LIBCOV_ARCH_<NAME>_NAME` — backend identifier string.
- `LIBCOV_ARCH_<NAME>_ILLEGAL[_*]` — illegal-instruction byte(s).
- `LIBCOV_ARCH_<NAME>_MIN_PATCH_LEN` / `_MAX_PATCH_LEN` — width bounds.

The Makefile honors `EXTRA_CFLAGS` for the `-D` path. Example:

```sh
make ARCH=mips THREADING=st \
    EXTRA_CFLAGS='-DLIBCOV_ARCH_MIPS_ILLEGAL=0xDEADBEEFu'
```

Each tunable header opens with a banner explaining both override paths;
each knob carries its own doc block explaining purpose, default, range,
and override syntax. These files are the source of truth for the
configurable surface area.

Note: `src/patchlist_format.h` (formerly `src/config.h`) is the on-disk
patch-list wire format + runtime `patch_entry` struct, **not** a
tunables header. Different concern.

---

## 7. Patch engine (`src/patch.c`)

### 7.1 Page protection sequence

By default (`LIBCOV_ST_PATCH=auto`) the ST engine makes every page that
holds a patch site `PROT_READ | PROT_WRITE | PROT_EXEC` once, in
`patch_arm_all`, exactly as the MT engine does (17.2.4). Every later
arm/disarm is then

```c
libcov_arch_write_illegal(addr, len)    // or memcpy(addr, orig, len)
__builtin___clear_cache(addr, addr + len)
```

with no syscall: leapfrog used to spend four `mprotect` calls per trap,
and the page never goes non-executable under a running thread.

Many hardened embedded kernels refuse `R|W|X` (SELinux `execmem`, PaX
`MPROTECT`). If the one-time `mprotect` fails -- or with
`LIBCOV_ST_PATCH=mprotect` -- each write uses the W^X-safe sequence,
which never asks for write and execute at once:

```c
mprotect(page, span, PROT_READ | PROT_WRITE)
libcov_arch_write_illegal(addr, len)    // or memcpy(addr, orig, len)
mprotect(page, span, PROT_READ | PROT_EXEC)
__builtin___clear_cache(addr, addr + len)
```

### 7.2 Page-span calculation

We compute `page = addr & ~(pagesize - 1)` and `end_page = (addr + len +
pagesize - 1) & ~(pagesize - 1)`, then mprotect that range. This
correctly handles patches that straddle a page boundary (rare on
fixed-width archs, possible on x86 for 15-byte instructions).

### 7.3 Cache flush

`__builtin___clear_cache` expands to:
- x86_64: nothing (single coherent cache).
- ARM/AArch64: a libc `__clear_cache` call → syscall.
- MIPS: a `cacheflush(2)` syscall.
- PPC, RISC-V: appropriate cache management.

Mandatory on every arch with split I/D caches. We call it on every
arm/disarm.

### 7.4 Init-time validation

`patch_validate(e)` compares the bytes at `e->addr` to `e->orig[0..len)`.
At init we validate every entry before writing. Mismatches indicate the
patch list is stale relative to the binary (rebuild without
regenerating). We abort the offending entry with a clear log line:
```
libcov: patch: stale entry at 0x4011a3 (bytes mismatch)
```
This catches the very common error of forgetting to regenerate after a
target rebuild.

### 7.5 Self-protection

`util_self_range()` returns `[lo, hi)` of libcov.so's own mapping in
`/proc/self/maps`. Any patch entry whose address falls in that range is
refused with a log line. This prevents a malformed patch list from
clobbering libcov's own code.

### 7.6 Lookup

`patch_lookup(pc)` is a signal-safe binary search over the sorted
`patch_table`. The table is allocated in the constructor and never
resized, so handler-time reads are race-free against init-time writes
(init completes before any traps can fire).

---

## 8. Signal handler (`src/handler.c`)

### 8.1 Installation

The handler is installed via `sigaction` (resolved through
`dlsym(RTLD_NEXT, "sigaction")` so our own `sigaction` interceptor —
defined in `libcov.c` — does not recurse). The signal number is
`LIBCOV_TRAP_SIGNO` (default SIGILL; project-wide, see section 6.4). Flags:

- `SA_SIGINFO`: we want `siginfo_t` + `ucontext_t`.
- `SA_NODEFER`: we never want the trap signal blocked during our
  handler. Synchronous-fault signals that are blocked at delivery time
  kill the process — this flag prevents accidental masking.

The previous handler (if any) is saved into `g_prev_sa` for chaining.

### 8.2 Trap path

```c
static void trap_handler(int signo, siginfo_t *info, void *uctx) {
    uintptr_t pc = libcov_arch_pc_from_uctx((ucontext_t *)uctx);
    struct patch_entry *e = patch_lookup(pc);
    if (!e || !e->patched) {
        chain_or_default(signo, info, uctx);
        return;
    }
    sink_emit(pc);                    // record edge BEFORE restoring
    patch_disarm(e);
    if (g_mode == LIBCOV_MODE_LEAPFROG) {
        if (g_last_restored && g_last_restored != e
                            && !g_last_restored->patched)
            patch_arm(g_last_restored);
        g_last_restored = e;
    }
}
```

### 8.3 Real-fault chaining

`chain_or_default` handles LIBCOV_TRAP_SIGNO at addresses not in our patch
table — i.e., genuine illegal-instruction or trap conditions in the
target. If a previous handler was registered before us, we forward to
it. If `SIG_DFL`, we restore default disposition (via our cached real
`sigaction` pointer); return causes the kernel to re-deliver and the
process dies, preserving the original-crash semantics for things like
core dumps.

### 8.4 Signal-safety contract

The handler runs in async-signal context. We strictly limit ourselves to
operations on the POSIX "async-signal-safe" list plus a few extensions
known to be safe:

- `mprotect`, `mmap`-region reads/writes, atomic byte stores, `write(2)`
  to a pre-opened fd.
- `__builtin___clear_cache` (a single syscall or no-op).
- Binary search of an immutable table.

Strictly forbidden in the handler: `malloc`, any stdio, `pthread_*`,
`dlsym`, `signal`, `sigaction` (other than via our pre-cached function
pointer), and anything that takes a non-trivial lock.

The init-time logger (`libcov_logf`) uses `write(2)` to a pre-opened fd
and is technically signal-safe, but as a discipline we don't call it
from the handler at all — only from constructor code.

---

## 9. Coverage sink (`src/sink_shm.c`, `src/sink.h`)

### 9.1 Bitmap layout

- Size: 65536 bytes (`1 << 16`).
- `uint8_t` per slot, saturating at 255.
- Compatible with AFL's classic bitmap layout — an external driver
  written for AFL bitmaps can read it directly.

### 9.2 Coverage scheme (block / AFL / N-gram)

`sink_emit` folds a window of the last `N-1` PCs into the bitmap
bucket. `N` is the compile-time tunable `LIBCOV_NGRAM_N` in
`src/tunables.h`; the bitmap layout, hash, saturating counter, and
atomic emit path are all independent of `N`.

```c
sink_emit(pc):
    cur          = hash16(pc)
    idx          = cur
    for j in 0..N-2:                          // unrolled / elided at N<=1
        idx     ^= prev[j]                    // or rotated prev[j] (ROTATE=1)
    idx         &= MAP_MASK
    bitmap[idx] += 1                          // saturating; CAS loop under MT
    for j in N-2 .. 1:                        // shift window: oldest drops off
        prev[j]  = prev[j-1]
    prev[0]      = cur >> 1                   // freshest entry
```

| `N` | Index formula                              | Meaning of a bucket                                  |
|-----|--------------------------------------------|------------------------------------------------------|
| 1   | `idx = hash(pc)`                           | "block was hit"                                      |
| 2   | `idx = hash(pc) ^ prev[0]`                 | "edge prev->cur was taken" (AFL math; default)       |
| k>=3| `idx = hash(pc) ^ prev[0] ^ ... ^ prev[k-2]`| "last k control transfers in this thread were this tuple" |

`hash16` is the standard splitmix-style 64-bit mixer truncated to 16
bits. It's defined as a `static inline` in `sink.h` so the handler
inlines the whole thing.

The `cur >> 1` shift when inserting into `prev[0]` is what makes AFL's
A->B and B->A index to different buckets at N=2; the same shift keeps
short reorderings distinguishable at higher N. With `LIBCOV_NGRAM_ROTATE=1`
each `prev[j]` is rotated by a position-dependent amount before being
XOR'd in, so windows `{A,B,C}` and `{C,B,A}` index to distinct buckets
(plain XOR commutes); this reduces collisions when running at higher N
in dense code.

Per-thread storage is a fixed array `libcov_prev_loc[LIBCOV_NGRAM_WIN]`
where `LIBCOV_NGRAM_WIN = max(N-1, 1)` — N=1 still allocates one
(unused) slot so the array never has zero length. Under MT the array
is `__thread`; under ST it is a process-wide global. boundary.c clears
the whole window at every iteration boundary so cross-iteration
context doesn't leak.

The first `N-1` emits per thread XOR with zero-initialised window
slots, biasing toward low buckets; this is the same warmup bias AFL
already exhibits at iter-1 and is harmless in practice.

The shipped consumers (`test/fuzz_driver.c`, the AFL-bitmap reader
pattern) don't need to know `N` — the bitmap is still 64 KiB of
saturating-count buckets and any "novelty" comparison works
unchanged. If a future consumer wants to interpret the bitmap with
knowledge of `N`, the spare bytes in `flags` or `reserved[4]` in
`struct libcov_shm_header` are the natural place to record it
(deferred until a consumer actually needs it).

### 9.3 Backing storage

Path comes from `LIBCOV_SHM_PATH` (default `/libcov_<pid>`).

- If the path looks like a shm name (leading `/` and no other slashes),
  we try `shm_open` + `ftruncate` + `mmap(MAP_SHARED)`.
- Otherwise, treat as a filesystem path: `open(O_RDWR|O_CREAT)` +
  `ftruncate` + `mmap`.
- If `shm_open` fails for a shm-style name, fall back to a file under
  `$TMPDIR` (or `/tmp`). Lets us run on embedded targets where
  `/dev/shm` is not mounted.

The mmap pointer is stored in the exported global `libcov_bitmap`. The
fd is closed after the mmap; the mapping survives the close, which is
important because daemons commonly `closefrom(3)` after init.

### 9.4 Why a single bitmap

A driver reads coverage via a separate mmap of the same shm region. No
serialization needed in the library. Per-iteration boundary detection
is a driver concern — the library just keeps writing.

Multi-bitmap / per-thread / per-child bitmaps are noted in TODO.md for
later phases. For now: one bitmap, single thread, single process.

---

## 10. Module base resolution (`src/util.c`)

### 10.1 `util_module_base(modname)`

Parses `/proc/self/maps` looking for the first mapping whose pathname
basename matches `modname` (or basename of `/proc/self/exe` if NULL).
The load base is `mapping.start - mapping.file_offset` — typically
`mapping.start` if the first mapping is at file offset 0.

For non-PIE binaries on x86_64 this returns 0x400000. For PIE binaries
under ASLR-off it returns a fixed but Linux-default base. With ASLR on
it returns the randomized base; addresses still resolve correctly
because patch records carry offsets, not absolutes.

### 10.2 `util_self_range`

Locates libcov.so's own mapping range by taking the function's own
address (`(uintptr_t)&util_self_range`), finding the containing mapping
in `/proc/self/maps`, then scanning for all mappings of the same
pathname to compute `[min_lo, max_hi)`.

### 10.3 Init-time logger

`libcov_logf(fmt, ...)` writes to `LIBCOV_LOG` (or stderr). Uses
`vsnprintf` into a stack buffer then `write(2)`. Init-time only, never
called from the handler. The fd is opened during `libcov_log_init()`
before any constructor work; this lets logging survive a daemon's later
`closefrom()`.

---

## 11. Constructor and lifecycle (`src/libcov.c`)

### 11.1 Constructor priority

```c
__attribute__((constructor(101)))
static void libcov_init(void);
```

Priority 101 places us *after* ld.so's relocation work but *before*
typical user constructors (the lowest user-defined priority is 100;
anything below is reserved for the toolchain). This is the earliest we
can run user code that uses libc.

### 11.2 Init sequence

```
1. libcov_log_init()      // open LIBCOV_LOG if set
2. parse LIBCOV_MODE       // default leapfrog
3. sink_init(env)          // mmap bitmap
4. config_load(patchlist)  // mmap LCV3, resolve module bases, build patch_table
5. patch_arm_all()         // code pages R|W|X once (or per-write mprotect), write+flush every entry
6. handler_install(mode)   // sigaction(LIBCOV_TRAP_SIGNO, &sa, &g_prev_sa)
7. set g_initialized = 1
```

Any step's failure logs and returns; the library becomes inert (no
patches, no handler, no interception). If `LIBCOV_PATCHLIST` is unset,
the library is fully inert — useful for sanity-checking a daemon under
LD_PRELOAD without instrumenting.

### 11.3 Resource discipline

All resource acquisition happens in the constructor:

- Patch list mmap'd then closed (mapping survives).
- Bitmap mmap'd then fd closed.
- Real `sigaction` pointer cached via `dlsym(RTLD_NEXT)`.
- Log fd opened.

This makes the library robust against the standard daemon-init
operations (`chroot`, `setuid`, `closefrom`, `setsid` + double-fork to
`daemonize`). None of these can revoke an existing mmap or break a
cached function pointer.

---

## 12. Hardening (`src/libcov.c`)

### 12.1 sigaction / signal interception

```c
int sigaction(int signo, const struct sigaction *act,
              struct sigaction *oldact);
sighandler_fn signal(int signo, sighandler_fn h);
```

Both are exported by libcov.so. The dynamic linker resolves them in the
target before libc's. Inside, we check `signo == LIBCOV_TRAP_SIGNO`:

- If yes: silently report success, stash the requested handler, but
  **don't actually install it**. Our handler stays in place. The stash
  (`g_tsa` in libcov.c) is a sequence-indexed double buffer: writers
  serialize on a spinlock with async signals blocked and fill the
  unpublished buffer; the trap handler reads it lock-free and retries
  only if two writes landed during its copy.
- If no: forward to the real implementation via
  `dlsym(RTLD_NEXT, "sigaction")` / `"signal"`.

The stashed target handler is chained for *real* traps in
`chain_or_default` (`libcov_chain_trap`) — at addresses not in our patch
table. The target's behavior for genuine LIBCOV_TRAP_SIGNO (default
SIGILL) is preserved, including its signal mask: the handler runs under
the interrupted mask plus its `sa_mask` plus the signal (unless
`SA_NODEFER`), not libcov's everything-blocked mask. The one deviation is
that the trap signal (and the MT sync signal) stay unblocked, because
the target's handler may itself run instrumented code.

glibc's `bsd_signal`, `ssignal`, `sysv_signal`, `sigset`, `sigignore`,
`sighold`, `siginterrupt` and `sigsuspend` call the kernel through
internal aliases, not through the exported `sigaction`/`sigprocmask`, so
they are interposed separately and each stashes the disposition glibc
would have installed (e.g. `sysv_signal` → `SA_RESETHAND|SA_NODEFER`).

`g_initialized` gates the interception: before constructor finishes, we
forward everything to the real handlers, so an init-time `sigaction`
call (e.g., from inside libc) is not interfered with.

### 12.2 Init-time validation

Every patch record is byte-compared against the binary at init. Stale
patch lists are caught immediately rather than producing
silently-wrong coverage.

### 12.3 Self-patch prevention

Documented in §7.5. Refuses any patch entry whose address lies in
libcov.so's own mappings.

### 12.4 Constructor-only resource acquisition

Documented in §11.3.

---

## 13. Patch list generator (`tools/gen_patchlist.py`)

### 13.1 Rizin interaction

The generator shells out to `rizin -q -c "<commands>" <binary>` and
parses JSON. No `rzpipe` / `r2pipe` Python module is required; this
keeps the dependency footprint minimal. Calls:

- `ij` → architecture, bits, endian, image base.
- `aflj` (after `aaa`) → function list with per-function `bits` (ARM/Thumb).
- `afbj @ <fn>` → basic blocks for a function.
- `pdj <n> @ <addr>` → first `n` instructions of a block as JSON
  (includes `size`, `bytes`, `type`).

### 13.2 Per-arch strategy selection

```python
def default_strategy(arch, bits):
    if arch == "mips": return "entry"
    return "terminator"
```

- **terminator** (default for x86, AArch64, ARM, Thumb, PPC, RISC-V):
  patch the *last* instruction of each basic block. This is the branch
  instruction itself. Coverage signal is "the block ran to completion".
- **entry** (MIPS): patch the *first* instruction of each block.
  Coverage signal is "the block was entered".

The choice for MIPS is forced by branch delay slots (next section).

### 13.3 MIPS branch delay slot avoidance

Rizin's MIPS basic-block model puts the delay slot at the **start** of
the next block. So:

```
block A:          (ends with cjmp branch B)
  ...
  cjmp B          ← branch terminator
block B:
  nop             ← THIS is the delay slot of A's branch
  lw v0, ...
  ...
```

If we patch B's first instruction (the delay slot), the trap fires
inside the delay slot. The MIPS kernel sets the BD (Branch Delay) bit
in Cause and reports `EPC = branch_address` (A's branch PC), not the
delay slot PC. Our handler does `patch_lookup(branch_addr)` which
*misses* (we patched delay_slot_addr). We fall through to
`chain_or_default`, default handler kills the process.

Fix: detect delay slots in the generator. For each block at address `X`,
check whether the instruction at `X - 4` is a branch (`type ∈ {jmp,
ujmp, cjmp, ucjmp, rjmp, call, ucall, ccall, rcall, icall, ret}`). If
yes, use `insns[1]` (second instruction) instead of `insns[0]` (the
delay slot). If the block has fewer than 2 instructions, skip it
entirely.

### 13.4 Thumb mode handling

When `rizin.bin.arch == "arm"` and per-function `bits == 16`, the
function is Thumb. For each patch site in such a function:

- Force `size = 2`.
- Truncate `orig = orig[:2]`.

This works whether the actual instruction is 2-byte Thumb or 4-byte
Thumb-2: we only modify the first half-word and restore the first
half-word. Bytes [2,4) of a Thumb-2 instruction are never touched.

The runtime backend's `libcov_arch_write_illegal(dst, 2)` writes
`0xDE00` (Thumb UDF.N), which is what the CPU needs to fetch in Thumb
mode at that address.

### 13.5 PPC64 dual entry points

PPC64 ELF defines two entry points per function:

- **Global entry**: loads the TOC pointer (r2). Typically 2 instructions
  (`lis r2, ...; addi r2, r2, ...`).
- **Local entry**: assumes TOC is already correct. Located 8 bytes after
  the global entry.

Rizin treats these as separate functions:

- `dbg.<name>` at the global entry — size 8, two TOC-setup instructions.
- `fcn.<name+8>` at the local entry — the real function body.

If we only collect `dbg.<name>` matches, we miss the function body.
Generator detection: `arch == "ppc" and bits == 64`. For each matched
function at offset X, look up `fcn.<X+8>` in the rizin function list
and include it as a companion entry.

### 13.6 Invocation

```
./tools/gen_patchlist.py <binary> <out.lcv> \
    [--include-pat REGEX]    # default: all functions matching strict embed exclusion
    [--exclude-pat REGEX]    # default excludes sym.imp.*, sym._init, sym._fini, etc.
    [--strategy auto|entry|terminator]
    [--verbose]
```

The default exclusion pattern filters out PLT stubs, ctor/dtor sections,
register/deregister tm clones, frame_dummy, and `__libc_csu*`.

---

## 14. Build system

### 14.1 Top-level Makefile

```
make                      # native (auto-detects host arch)
make ARCH=aarch64         # cross-build for aarch64
make all-arch             # build every supported backend
make ARCH=<arch> clean    # clean all
```

The `ARCH` variable maps to:

- a backend source file `src/arch_<backend>.c`,
- a cross-compiler prefix (`aarch64-linux-gnu-`, `arm-linux-gnueabihf-`,
  etc.),
- a `qemu-<arch>-static` binary for validation.

The mapping table covers: x86_64, aarch64, arm, mips, mipsel, mips64,
mips64el, powerpc, powerpc64, powerpc64le, riscv64.

Outputs:
```
build/<arch>/libcov.so
build/<arch>/<core object files>
build/<arch>/target_simple    (from test/Makefile)
build/<arch>/target_simple_thumb (arm only, via `make -C test ... thumb`)
build/<arch>/fuzz_driver
```

### 14.2 Test Makefile

`test/Makefile` is invoked from the top-level with `ARCH`, `CROSS`, and
absolute `BUILD` paths. It builds `target_simple` with `-no-pie -O0
-fno-stack-protector` so the branch graph is deterministic and easy to
disassemble.

ARM: targets default to ARM mode (`-marm`). A separate `thumb` make
target builds `target_simple_thumb` with `-mthumb`.

### 14.3 Library compile flags

```
-O2 -g -Wall -Wextra -Wno-unused-parameter -fPIC
```

Linker: `-shared -fPIC -Wl,-z,now -ldl -lrt`.

`-Wl,-z,now` forces full relocation at load time so we don't get
surprised by lazy PLT resolution during the constructor.

---

## 15. Validation infrastructure

### 15.1 `test/target_simple.c`

Small C program with a known branch graph:

- `classify(int)`: 5-way if/else chain (`<0`, `==0`, `<10`, `<100`, else).
- `loop_sum(int n)`: for-loop with even/odd branch inside.
- `cmdline(const char *)`: nested if/else on first char and length.
- `main`: orchestrates the above and prints `E:<edge>` markers to stdout.

Same source compiles for all 11 architectures.

### 15.2 `test/run_validation.sh` (native)

For the host arch, runs four checks:

1. **Determinism**: two identical runs produce identical bitmaps.
2. **Input differentiation**: input "42" vs input "-3" produce
   different bitmaps.
3. **Leapfrog hit counts**: leapfrog mode records ≥ 2 hits on the loop
   site.
4. **Output unchanged**: target stdout under libcov equals target stdout
   without libcov.

### 15.3 `test/run_cross.sh` (all backends)

Runs the same four checks against every supported backend under
`qemu-<arch>-static -L /usr/<triple> -E LD_PRELOAD=...`. Output:

```
PASS=12  FAIL=0  SKIP=0
```

Backends covered: x86_64, aarch64, arm, arm-thumb, mips, mipsel, mips64,
mips64el, powerpc, powerpc64, powerpc64le, riscv64.

### 15.4 `test/fuzz_driver.c`

Toy external driver. Reads stdin line by line; for each line:

1. Zero the shared bitmap.
2. Fork + exec the target with the line as argv[1] and
   `LD_PRELOAD=libcov.so`.
3. Wait for exit.
4. Count set bytes (edges hit) and newly-discovered edges (bytes set
   this iteration that were zero in the cumulative bitmap).
5. Print one line per iteration: `iter=N input=... hit=H new=K total=T
   exit=E`.

Not a real fuzz loop — no mutation, no corpus management, no crash
dedup. Demonstrates the bitmap-driven driver pattern.

---

## 16. Configuration interface

| Env var | Default | Purpose |
|---|---|---|
| `LIBCOV_PATCHLIST` | (none — library inert if unset) | Path to LCV3 patch list |
| `LIBCOV_SHM_PATH` | `/libcov_<pid>` | Bitmap location (shm name or FS path) |
| `LIBCOV_MODE` | `leapfrog` | `oneshot` or `leapfrog` |
| `LIBCOV_MODULE` | basename of `/proc/self/exe` | Module name for boundary-mode sidecar resolution. The patch list itself carries its own module name table (LCV3) so this only affects `LIBCOV_BOUNDARY_LIST` lookups. |
| `LIBCOV_LOG` | unset (stderr) | Init-time log path |

All read once in the constructor. Changing them after init has no
effect.

---

## 17. Threading models (`libcov_st.so` and `libcov_mt.so`)

The library is built as two separate `.so` files at the same interfaces.
Pick the brick that matches your target.

### 17.1 ST brick -- `libcov_st.so`

Designed for single-threaded targets. Smallest possible surface area.

- `prev_loc` is a single `uint16_t` global; no atomics.
- `g_last_restored` (leapfrog) is a single pointer global; no atomics.
- The patch table is allocated once at init and never resized; handler
  reads are race-free against init writes because init completes before
  any trap can fire (no patched sites exist yet).
- The bitmap increment is a non-atomic `uint8_t` increment.
- Byte writes are plain stores into pages made `R|W|X` at init, or,
  where the kernel refuses that, the classic mprotect dance
  `R|X -> R|W -> memcpy -> R|X` (a brief non-executable window on the
  code page).

Under a multi-threaded target:

- Oneshot: edges from different threads interleave; results are noisy
  but the library does not corrupt or crash.
- Leapfrog: **unsafe**. Thread A may be re-arming a site that thread B
  is executing. The library will not detect this; behavior is
  undefined. Use `libcov_mt.so` instead.

### 17.2 MT brick -- `libcov_mt.so`

Designed for arbitrary-thread-count targets. Safe under contention.

#### 17.2.1 Per-thread state

- `prev_loc` is `__thread uint16_t`: each thread has its own. Concurrent
  threads compute their own edge sequences with no interference.
- `g_last_restored` (leapfrog) is `__thread`: each thread independently
  leapfrogs through its own history. Two threads' leapfrog tails never
  collide because per-entry arm/disarm is serialized (see 17.2.3).

#### 17.2.2 Atomic bitmap

`sink_emit` increments `bitmap[idx]` via a saturating CAS loop. The
saturation point (255) is preserved without ever decrementing.

```c
old = __atomic_load_n(&bitmap[idx], RELAXED);
while (old < 255) {
    if (__atomic_compare_exchange_n(&bitmap[idx], &old, old+1,
                                    0, RELAXED, RELAXED))
        break;
}
```

#### 17.2.3 Per-entry spinlock

Each `patch_entry` has a `lock` byte. `patch_arm` and `patch_disarm`
acquire it by spinning on a `0->1` cmpxchg before doing the byte write,
and release it after.

The lock guards both the state field (`patched`) and the byte write
together, closing a race where an in-flight `arm` and an in-flight
`disarm` could otherwise complete their `pwrite`s in the opposite
order from their state transitions and leave the bytes inconsistent
with `patched`. Under leapfrog with N threads, this race is
guaranteed to happen at the per-trap rate; without the spinlock, the
trap handler enters an infinite loop on the stale-state site and
exhausts the signal stack.

The lock is signal-safe by construction:

- The critical section is just one atomic store + `clear_cache`
  (the batched `membarrier` runs after the lock is released), so bounded
  spin.
- A thread never recursively acquires the same entry's lock: arm/disarm
  are called outside the trap PC's basic block. A secondary trap inside
  the critical section can only be for a *different* entry.
- No syscall sleeps inside the lock that would risk deadlocking the
  caller's signal context.

#### 17.2.4 Patching: RWX-once pages + single atomic store

At init `patch_mt.c` mprotects every page holding a patch site
`R|W|X` once (never dropping `X`, so peer threads keep executing).
After that, arm/disarm is a single single-copy-atomic store of the 2- or
4-byte encoding -- no syscall on the hot path, and a peer fetching the
site sees either the old or the new instruction, never a mix of bytes.

`pwrite(/proc/self/mem)` used to be the primary path. It tears: the
kernel copies through `memcpy`, which stores 2-4 byte lengths byte by
byte, and a peer could execute half UD2 and half original instruction
(`0f 07` = SYSRET -> SIGSEGV; about 1 run in 10 of the 16-thread
stress test). It is now only a fallback, used when the kernel refuses
`R|W|X` (W^X-strict / SELinux execmod), and init logs a WARNING that
writes are no longer atomic. If `/proc/self/mem` can't be opened
either, the last resort is an `R|W|X` mprotect + `memcpy` dance.

The mprotect fallback is serialized globally by `g_fallback_lock` (a
signal-safe spinlock matching the per-entry pattern). The per-entry
`e->lock` from 17.2.3 is keyed on a `patch_entry`, but mprotect's
permission bits are keyed on the page: two threads patching different
entries on the same page would otherwise race on the page protection.

#### 17.2.5 Cross-CPU instruction visibility

Two separate steps, both required on weakly-ordered ISAs:

1. **Cache maintenance, after every write:** `__builtin___clear_cache`
   over the patched bytes (aarch64 `DC CVAU` + `IC IVAU`, broadcast to
   the inner-shareable domain; the arm/mips/riscv cacheflush syscalls;
   ppc `dcbst`/`icbi`). It compiles to nothing on x86, whose I-cache is
   coherent.
2. **Context synchronization, once per batch:**
   `membarrier(PRIVATE_EXPEDITED_SYNC_CORE)` via
   `patch_sync_batch_end()`. It IPIs every CPU running the process so
   each one discards instructions it already fetched. On x86 the IPI's
   `iret` is the serializing event SDM 8.1.3 asks for.

`membarrier` does not do step 1. (An earlier version skipped
`clear_cache` whenever SYNC_CORE was available, which could leave
peers -- and the writer -- fetching stale bytes on non-coherent
I-caches.)

Without SYNC_CORE (Linux < 4.16, or arches that gained it later),
step 2 becomes a **signal broadcast** (`membarrier.c`,
`LIBCOV_SYNC_FALLBACK=auto`, the default):

- `LIBCOV_SYNC_SIGNO` (default `SIGRTMAX-2`) goes to every other thread
  listed in `/proc/self/task`, via `rt_tgsigqueueinfo`, tagged with a
  cookie and a broadcast generation. The broadcaster waits, up to
  `LIBCOV_SYNC_TIMEOUT_NS` (1 ms), for each thread's handler to
  acknowledge. Taking a signal and returning from it is an exception
  return on that thread (iret / ERET / rfid / sret), which
  context-synchronizes it.
- Broadcasts are serialized, so acknowledgements are counted exactly.
  They are also coalesced: a trapper whose writes precede the start of a
  later broadcast skips its own, so a queue of waiting trappers costs
  one or two broadcasts.
- The trap handler's mask leaves the sync signal deliverable (its
  handler only bumps a counter), and the `sigprocmask`/`pthread_sigmask`
  interposers strip it, so peers inside the trap handler or with
  everything blocked still acknowledge.
- The signal belongs to the target if it wants it. A handler or
  `SIG_IGN` present at init, or a handler installed later, turns the
  fallback off (WARNING). A foreign instance of the signal arriving while
  libcov owns it restores `SIG_DFL` and is re-raised, so the default
  action happens as it would have.
- Costs: every patch batch wakes every peer. `run_validation_mt.sh`'s
  16-thread stress takes about 19 s against 1.8 s with SYNC_CORE on x86_64.
  Syscalls that don't restart after a handler (`epoll_wait`, `poll` with
  a timeout, `nanosleep`) can return `EINTR` in the target. A thread that
  never acknowledges (uninterruptible sleep, stopped, blocked through a
  raw syscall) costs the full timeout per broadcast. After a chroot
  without `/proc`, broadcasts do nothing.

`LIBCOV_SYNC_FALLBACK=off` keeps the old behaviour: rely on step 1 alone
(WARNING on weakly-ordered ISAs), and peers pick up the change at their
next context-synchronizing event. `=tgkill` forces the broadcast even
when SYNC_CORE works; the test suites use it.

**Residual architectural gap.** The trap design is fixed: sites raise
SIGILL from an illegal encoding. Neither UD2 nor UDF is in the
architectures' blessed cross-modification sets (x86 SDM 8.1.3; AArch64
CMODX allows only B/BL/NOP/BRK/SVC/HVC/SMC/ISB). For a peer fetching
the site at the exact moment of the store, the spec permits
CONSTRAINED UNPREDICTABLE behaviour. The atomic store plus steps 1-2
make this window as small as it can be; real-hardware MT validation
(TODO.md) is what confirms it is harmless in practice.

#### 17.2.6 Atomic-write argument by arch

`patch_mt.c` writes the trap encoding as a single store. For this to be
single-copy-atomic on the host CPU:

| Arch                                         | Atomic-write width | Source of atomicity                |
|----------------------------------------------|--------------------|------------------------------------|
| aarch64, arm-ARM, mips, mips64, ppc, ppc64   | 4 bytes            | ARM ARM B2.2.1; MIPS, Power ISA    |
| arm-Thumb, riscv64                           | 2 bytes            | Aligned half-word stores by ISA    |
| x86_64                                       | 2 bytes (UD2 head) | Intel SDM Vol 3 Sec 8.1.1 (aligned, or unaligned within one cache line) |

For x86 specifically, the patch is the leading 2-byte UD2 only; the
remaining bytes of the original variable-length instruction are never
touched. Sites need not be 2-aligned: an unaligned 16-bit store is
still atomic when both bytes are in one 64-byte cache line, and
`write_bytes()` uses a plain `movw` for it. The generator's
`--threading mt` mode skips only candidates whose write would straddle
a line, so x86 MT instruments the same sites as ST in practice.

### 17.3 Threading-hint enforcement

Each variant's `config.c` is compiled with `-DLIBCOV_THREADING_ST` or
`-DLIBCOV_THREADING_MT`. The LCV3 header carries a matching threading
hint (0=ANY, 1=ST, 2=MT); a mismatched hint is refused at init with a
clear log line. Patch lists emitted with the ANY hint are accepted by
both variants.

### 17.4 Signal-safety contract (both bricks)

The trap handler runs in async-signal context. The safety contract:

**Allowed**:
- `mprotect`, `pwrite` (POSIX-listed safe).
- Reads of mmap'd memory.
- Writes to mmap'd bitmap with `__atomic_*` builtins.
- `write(2)` to a pre-opened fd.
- `__builtin___clear_cache`.
- `membarrier` syscall (MT only; documented signal-safe by Linux ABI).
- Calls to *pre-cached* function pointers (e.g. `real_sigaction`).
- Binary search of an immutable table.
- Inline `static` helpers compiled from C (`sink_emit`, `hash16`).
- Per-entry spinlock cmpxchg (MT only; bounded wait).

**Forbidden**:
- `malloc` family.
- Any stdio (`printf`, `fprintf`, `puts`).
- `pthread_*` (including mutex; spinlock is fine).
- `dlsym` (not safe even though it appears in some implementations'
  safe-list).
- `signal` / `sigaction` (would deadlock the kernel signal table).
- `errno` reads that have been clobbered by a libc call we made
  earlier -- we avoid making such calls.

Code review gate: every function called from the handler must be marked
"signal-safe" mentally; new helpers go through the same scrutiny.

---

## 18. Test target spec

`test/target_simple.c` is the ground-truth for validation. Its branch
graph is documented in §15.1. It deliberately:

- Builds with `-no-pie -O0` so the linked addresses are stable and
  disassembly-friendly.
- Uses `__attribute__((noinline))` on each helper to prevent inlining
  collapsing the graph.
- Prints `E:<marker>` lines so we can confirm the target's logical
  execution path matches expectations independently of bitmap state.

A Thumb variant (`target_simple_thumb`) is built with `-mthumb` on ARM
for Thumb-mode validation.

`test/target_simple_mt.c` is the MT counterpart. It reuses the same
noinline `classify`/`loop_sum`/`cmdline` helpers but drives them
concurrently from N pthread workers, each iterating a configured
number of times on its own input. Designed to maximise the chance of
two threads hitting the same patched site at the same time. The native
MT validation (`test/run_validation_mt.sh`) drives it with a 16-thread
/ 2000-iter stress (tunable via `THREADS_STRESS` and `ITERS_STRESS`)
to exercise the per-entry spinlock and the atomic bitmap under
high contention.

Future work: a stress harness that spins threads via raw `clone(2)`
rather than pthreads, for targets whose threading model is non-libc.
Captured in TODO.md.

---

## 19. Limitations of the current implementation

These are inherent to the present scope, not bugs:

1. **No JIT / self-modifying code coverage.** Code generated after init
   isn't in the patch list and isn't instrumented.
2. **No iteration boundary for daemons.** The library writes the bitmap
   continuously; per-input scoping is the driver's responsibility.
3. **No remote transport.** Coverage is local-only (shared memory). A
   relay binary is planned (see TODO.md).
4. **Raw signal syscalls bypass interception.** `sigaction`, `signal`,
   `sigprocmask`, `pthread_sigmask` and glibc's older wrappers
   (`bsd_signal`, `ssignal`, `sysv_signal`/`__sysv_signal`, `sigset`,
   `sigignore`, `sighold`, `siginterrupt`, `sigsuspend`) are interposed,
   but raw `rt_sigaction`/`rt_sigprocmask` syscalls, the compat-only
   `sigvec` and `sigpause` are not (syscall-level coverage needs seccomp
   or libsyscall_intercept).
5. **W^X-strict kernels that refuse any transient writable mapping over
   text** will trip the ST patch path's `mprotect(R|W)`. The MT path
   needs `R|W|X` once at init; if refused it falls back to non-atomic
   `pwrite(/proc/self/mem)` with a WARNING (see 17.2.4).
6. **MT cross-validation is limited under qemu-user.** qemu-user only
   invalidates its TCG translation cache on `mprotect` with a perm
   change, and that perm change strips `PROT_EXEC` long enough to
   SIGSEGV peer guest fetches. We therefore run the full MT cross
   suite only on `x86_64` and `aarch64` (where qemu happens to
   cooperate); for the other 9 backends the MT cross check is build +
   link + generator only. Real-hardware MT validation is in TODO.md.
7. **Raw-`clone(2)` thread targets are not covered by the MT stress
   test.** `target_simple_mt.c` uses pthreads. A `clone()`-based
   stress harness is captured in TODO.md.

Each of these has a corresponding plan in `TODO.md`.

---

## 20. References

- `README.md` — user-facing usage, environment variables, quick start.
- `TODO.md` — deferred design backlog, structured by phase.
- `Context.md` — dense reload state for re-engaging with the work.
- `tools/gen_patchlist.py` — per-arch generator strategies, regex
  conventions for rizin function names.
- `test/run_cross.sh` — canonical "is everything still working" command.

---

End of document.
