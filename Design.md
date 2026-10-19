# suzzer / libcov — Design Document

This document describes every component of the suzzer coverage library
("libcov") as currently implemented. For usage see README.md (reference)
and HOWTO.md (step-by-step); where this document summarises, those two
and the code are authoritative. It covers the runtime library, the
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
the cost of a few KB of code and one shared-memory region (a 72-byte
header, a bitmap auto-sized from the patch count, and a small snapshot
ring). The mechanism uses only libc primitives that exist on essentially
every Linux device: `mmap`, `mprotect`, `sigaction`, `shm_open`, `flock`,
`dlsym`, `/proc/self/maps`, and the `__builtin___clear_cache` intrinsic
(a syscall on some architectures with separate I- and D-caches). The MT
build also uses `membarrier(2)`.

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

The signal is a "synchronous fault" signal. If it fires while blocked,
the kernel resets it to `SIG_DFL` and kills the process -- the handler
does *not* run. libcov therefore interposes `sigprocmask`,
`pthread_sigmask`, `sighold` and `sigsuspend` and strips the trap signal
from every mask the target installs (§12.1). The signal choice and every
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
                            │ shm region: header +   │
                            │ auto-sized bitmap+ring │
                            └──────────┬─────────────┘
                                       ▲ writes (sink_emit)
                                       │
LD_PRELOAD libcov.so loaded into target process:

  ┌─────────────────────────────────────────────────────────────┐
  │  constructor(101) — libcov_init  (full order: §11.2)        │
  │    1. open log fd (LIBCOV_LOG or stderr)                    │
  │    2. config_load: mmap LCV3, check threading hint,         │
  │       resolve module bases, build sorted patch_table[]      │
  │    3. size the bitmap from the site count; map shm region   │
  │    4. trap self-test (each encoding must raise TRAP_SIGNO)  │
  │    5. install LIBCOV_TRAP_SIGNO handler (before arming)     │
  │    6. arm: pages R|W|X once (or mprotect per write),        │
  │       validate bytes, write trap, cache flush               │
  │    7. boundary_init (if LIBCOV_BOUNDARY_LIST is set)        │
  │    8. g_initialized = 1 -> signal interposers go live       │
  │  return to main()                                           │
  └─────────────────────────────────────────────────────────────┘

  Target executes normally until it hits a patched instruction:

  ┌─────────────────────────────────────────────────────────────┐
  │  kernel delivers LIBCOV_TRAP_SIGNO (default SIGILL)         │
  │  trap_handler:                                              │
  │    pc = arch_pc_from_uctx(uc)                               │
  │    e  = patch_lookup(pc)        [PC cache + bsearch]        │
  │    if (!e || !e->patched)                                   │
  │       libcov_chain_trap(...)    [real fault path]           │
  │    sink_emit(pc, module_idx, site_id)   [bitmap update]     │
  │    if (e->emulate)              [boundary marker, §21]      │
  │       re-arm previous; boundary_on_trap; emulate insn; ret  │
  │    patch_disarm(e)              [restore original]          │
  │    if (leapfrog) re-arm previous site; remember e           │
  │    boundary_on_trap(pc, e)      [no-op without boundaries]  │
  │  return → kernel re-executes restored insn                  │
  └─────────────────────────────────────────────────────────────┘
```

Two builds share this structure. `libcov_st.so` assumes a
single-threaded target. `libcov_mt.so` is thread-safe, leapfrog included:
it has an atomic bitmap, per-thread state and per-entry spinlocks (§17).

---

## 3. The trap-trampoline mechanism

### 3.1 Patching

For each address in the patch list, we replace the original instruction
bytes with the architecture's chosen trap-raising encoding. By default
every page holding a site is made `R|W|X` once at init, and each later
write is a plain store (ST) or a single single-copy-atomic store (MT).
On kernels that refuse `R|W|X`, ST falls back to
`mprotect(RW) → write → mprotect(RX)` per write (§7.1) and MT to
`/proc/self/mem` (§17.2.4). The original bytes are recorded in the patch
table for later restoration.

### 3.2 Trap and handler

When execution reaches the patched address, the CPU raises the trap.
The kernel delivers LIBCOV_TRAP_SIGNO (default SIGILL) synchronously to the
faulting thread. Our handler examines `ucontext_t`, extracts the PC, and
looks the address up in our sorted patch table.

### 3.3 Coverage emission

If the PC is in our table, we emit into the bitmap. The coverage model
(`LIBCOV_COVERAGE_MODEL_SITE`) and window length (`LIBCOV_NGRAM_N`,
default 2 = edges) are build-time choices; see §9.2. The default
(site-id model, N=2):

```c
cur   = e->site_id                      // record index in the patch list
idx   = (cur ^ prev[0]) & libcov_map_mask
bitmap[idx]++                           // saturating at 255
prev[0] = sink_spread(cur)              // spread copy enters the window
```

### 3.4 Restore and continue

We restore the original bytes through the same write path as arming
(a direct store by default, the mprotect sequence as fallback), run
`__builtin___clear_cache` over the range (a no-op on x86, a real cache
flush on ARM/MIPS/PPC/RISC-V), and return from the handler. The kernel's
signal frame restore puts the PC back to the same address; the CPU
re-fetches the now-restored instruction and proceeds.

Exception: an *emulatable boundary marker* is never restored. The
backend performs its instruction in software and advances the PC past
it (`libcov_arch_emulate`, §21), so the marker stays armed.

### 3.5 Two modes

**Oneshot** (`LIBCOV_MODE=oneshot`):
After restoration the site is permanently disarmed. Each site fires at
most once per process lifetime. Fastest mode; coverage is "did this
edge fire" rather than "how many times".

**Leapfrog** (`LIBCOV_MODE=leapfrog`, default):
When the handler runs, in addition to disarming the current site, it
re-arms the *previously* restored site (stored in `g_last_restored`).
This keeps every patched edge "live" across the whole run; the bitmap
accumulates hit counts (approximate: a block that loops straight back to
itself stays restored, so it counts once per alternation). We never re-arm
the current PC's site (that would infinite-loop), and boundary markers
are re-armed by boundary.c instead. With `libcov_st.so` this is safe only
for single-threaded targets. `libcov_mt.so` keeps `g_last_restored` per
thread and serialises arm/disarm per entry (§17.2).

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
    uint8_t  flags;           // reserved; writers set 0 (the loader ignores it)
    uint8_t  module_count;    // 1..255
    uint8_t  reserved;
    uint32_t modules_offset;  // file offset of module name table
    uint32_t modules_size;    // bytes in the name table
} __attribute__((packed));
```

The `threading` byte enforces variant-correctness: an MT-generated
patch list (per-arch atomic-width records, x86 fetch-block-safe sites
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
store 2 meaningful bytes and ignore the tail. See §6.1 for the per-arch
patch-byte table.

A site's **site id** is its record index in the file, assigned before
the runtime sorts the table by address. The site-id coverage model uses
it as the bucket base (§9.2).

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

Matching details:
- A name that is an absolute path is realpath'd and matched against the
  full mapped path. A NULL or empty name means the main executable.
- A ` (deleted)` suffix (a binary replaced in place) is ignored.
- If two different mapped files share the basename, libcov warns and uses
  the first.
- `LIBCOV_MODULE_RENAME=old=new[,…]` rewrites names before lookup, for
  renamed copies or to pick one of several same-basename files by
  absolute path.

If any named module is not currently mapped, `config_load` fails and
logs which name failed. The library then runs inert (aborting under
`LIBCOV_REQUIRE`) -- better than leaving half the patch table silently
misindexed.

### 4.6 Why a custom format

Alternatives considered: text/CSV (slow parse on weak embedded CPUs;
parser bugs); a serialized struct from libelf; YAML/JSON. The flat
binary form maps with one `mmap` call, parses with a pointer cast, and
has zero parser surface area to get wrong.

---

## 5. Module layout

```
src/
  libcov.c              constructor; env parsing; trap self-test;
                        signal-API interposers (sigaction, signal, legacy
                        glibc wrappers, sigprocmask/pthread_sigmask);
                        real-trap chaining (libcov_chain_trap);
                        ST second-thread warning (pthread_create interposer)
  util.c, util.h        /proc/self/maps parsing (module base, self range);
                        init-time logger (sealed after init)
  config.c              LCV3 mmap loader + per-module base resolution
                        (LIBCOV_MODULE_RENAME) + sorted patch_entry table;
                        threading-hint enforcement (prototypes in
                        patchlist_format.h)
  patchlist_format.h    on-disk LCV3 wire format + runtime patch_entry
                        (formerly config.h; renamed to avoid confusion with
                        tunables headers)
  patch.h               arm/disarm/lookup + batch interface (shared by ST and MT)
  patch_st.c            ST patch engine: RWX-once + direct store
                        (LIBCOV_ST_PATCH=auto) or per-write mprotect;
                        16-slot PC cache in front of the bsearch
  patch_mt.c            MT patch engine: RWX-once pages + single atomic store
                        + per-entry spinlock + clear_cache + membarrier(SYNC_CORE);
                        fallbacks: /proc/self/mem write, signal-broadcast sync
  handler.h             trap-handler interface
  handler_st.c          ST trap handler (global g_last_restored)
  handler_mt.c          MT trap handler (TLS g_last_restored)
  sink.h                inline emit: site-id or hashed-PC bucket base, N-gram
                        window fold, saturating (atomic under MT) increment
  sink_shm.c            shm region (72-byte header + auto-sized bitmap + ring);
                        %p path expansion; TMPDIR fallback; region ownership
                        and re-exec attach (§20)
  boundary.c, boundary.h
                        LCVB1 sidecar, marker detection, snapshot ring
                        publish, re-arm policies, per-thread bitmaps (§21)
  ring_reader.h         header-only client-side ring reader (attach, seqlock,
                        overrun accounting); for consumers, not the library (§24)
  membarrier.h, membarrier.c
                        MT-only; PRIVATE_EXPEDITED_SYNC_CORE wrapper with
                        init-time detection + signal-broadcast fallback
  arch.h                backend interface (extern symbol contract)
  arch_x86_64.c         x86 UD2 head-only, 2 bytes (ST+MT share)
  arch_aarch64.c        UDF #0 / 4-byte fixed (ST+MT share)
  arch_arm.c            ARM UDF + Thumb UDF.N (ST+MT share)
  arch_mips.c           MIPS32 user-mode MFC0 / SIGILL (ST+MT share)
  arch_mips64.c         MIPS64 user-mode MFC0 / SIGILL (ST+MT share)
  arch_mips_emulate.h   shared MIPS marker emulator
  arch_powerpc.c        PPC32 all-zero illegal / SIGILL (ST+MT share)
  arch_powerpc64.c      PPC64 BE+LE all-zero illegal / SIGILL (ST+MT share)
  arch_ppc_emulate.h    shared PowerPC marker emulator
  arch_riscv64.c        c.unimp (ST+MT share)
  tunables.h            project-wide knobs (trap signo, coverage model and
                        map sizing, N-gram, log buf, marker re-arm timeout,
                        MT sync signal/timeout)
  tunables_<arch>.h     per-backend knobs (illegal encoding(s) + widths);
                        one per backend, every knob -D-overridable

tools/
  gen_patchlist.py      rizin (rzpipe) LCV3 generator; per-arch strategies;
                        call-graph slicing; --threading st|mt;
                        --module name:path adds auxiliary modules
  gen_boundary.py       rizin-based LCVB1 sidecar generator; resolves symbol
                        names to the site gen_patchlist would pick in their
                        first basic block
  rz_resolve.py         SYM_OR_ADDR resolver shared by both generators
  mutate.py             generic AFL++-style mutation engine; stdlib-only;
                        importable Engine/Dictionary/StructuredInsert +
                        CLI for ad-hoc mutant dumping and selftest. See
                        the file's module docstring for the full API
  libdemalloc.c, Makefile
                        opt-in LD_PRELOAD heap-bug catcher (`make tools`)
  suzzer-relay.c, relay_proto.h
                        on-device coverage relay for remote fuzzing; `make -C
                        tools relay` (§24)
  suzzer_brain.py       off-device reference fuzzing brain (§24);
                        --status-file emits a JSON-lines feed for status_tui.py
  status_tui.py         generic target-agnostic afl-style status board; reads a
                        JSON-lines status feed (or an adapted parser); a copy-me
                        template (render() + Status model + JSON adapter)
  inject/               standalone live-process injector (own Makefile,
                        README and Design.md)

test/
  target_*.c            ground-truth targets (simple, simple_mt, loop,
                        loop_mt, dispatch, markers, multimod, orderable,
                        paired, reexec, signals, demalloc, netd)
  fuzz_driver.c         boundary-aware driver (seqlock ring reader)
  ring_dump.c           passive ring reader for self-iterating targets
  shm_bitmap.py         header-aware live-bitmap reader
  run_validation*.sh    native suites (18 run by `make test` via run_all.sh)
  run_cross*.sh         cross-arch suites under qemu-user-static
  wx_deny.c, sigill.h, unit_mips_emulate.c, libmultimod_helper.c
                        test helpers
  Makefile              test target build rules

Makefile               top-level: ARCH x THREADING selection
README.md              user-facing reference
HOWTO.md               step-by-step operational guide
TODO.md                deferred design backlog
Review.md              coverage-options review (superseded by TODO.md)
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

void        libcov_arch_write_illegal(void *dst, uint8_t len);
const void *libcov_arch_illegal_bytes(uint8_t len);   // static trap bytes (MT, self-test)
uintptr_t   libcov_arch_pc_from_uctx(const ucontext_t *uc);
int         libcov_arch_emulate(ucontext_t *uc, uintptr_t addr,
                                const uint8_t *orig, uint8_t len);
                                // marker emulation (§21); uc==NULL asks "can you?"
```

The trap signal is project-wide, not per-backend: every backend uses
`LIBCOV_TRAP_SIGNO` (default `SIGILL`) from `src/tunables.h`. To switch
the whole project to a different signal you change `LIBCOV_TRAP_SIGNO`
and any per-arch ILLEGAL encoding(s) together so the encoding agrees
with the signal it must raise.

This is the entire ABI. The core files (`libcov.c`, `config.c`,
`util.c`, `sink_shm.c`, `boundary.c`, `patch_{st,mt}.c`,
`handler_{st,mt}.c`) contain no backend logic. The only arch `#ifdef`s
are small ones: the trap self-test (disabled on ppc64 ELFv1, Thumb bit
on ARM) and the spin-wait `pause` on x86.

The per-backend constants the `extern`s above expose (name, widths, the
bytes written by `libcov_arch_write_illegal`) are not hardcoded in the
`.c` file — each backend pulls them from `src/tunables_<arch>.h`, which
is `#ifndef`-guarded so every knob is overridable either by editing the
default or by passing `-D` at build time. See section 6.4.

### 6.1 Backend matrix

Every backend raises `LIBCOV_TRAP_SIGNO` (= `SIGILL` by default).

| Backend          | Default trap insn        | Min len | Max len | Special handling                          |
|------------------|--------------------------|---------|---------|-------------------------------------------|
| x86_64           | UD2 (`0F 0B`)            | 2       | 2       | Head-only; tail never touched; MT sites can't straddle a 16-byte fetch block |
| aarch64          | UDF #0 (`0x00000000`)    | 4       | 4       | Fixed                                     |
| arm (ARM mode)   | UDF (`0xE7F000F0`)       | 2       | 4       | Per-site dispatch on len                  |
| arm (Thumb mode) | UDF.N (`0xDE00`)         | 2       | 4       | len=2 selects Thumb encoding              |
| mips, mipsel     | MFC0 $0,$0 (`0x40000000`)| 4       | 4       | Was BREAK 0 / SIGTRAP; see 6.2            |
| mips64, mips64el | MFC0 $0,$0 (`0x40000000`)| 4       | 4       | Was BREAK 0 / SIGTRAP; see 6.2            |
| powerpc          | all-zero (`0x00000000`)  | 4       | 4       | Was `tw 31,0,0` / SIGTRAP; see 6.2        |
| powerpc64 BE+LE  | all-zero (`0x00000000`)  | 4       | 4       | Was `tw 31,0,0` / SIGTRAP; see 6.2        |
| riscv64          | c.unimp (`0x0000`)       | 2       | 4       | 2 or 4 selects len; 4 = two c.unimps      |

Every backend uses the same source and encoding for ST and MT. The only
threading difference is in the generator: `--threading mt` drops x86
sites whose 2 bytes would straddle a 16-byte instruction-fetch block, and
unaligned sites on fixed-width ISAs. `libcov_mt` also refuses such x86
sites at init, for lists that still have them.

### 6.2 Per-backend rationale

**x86_64 / UD2**: canonical illegal opcode, 2 bytes, well-defined since
the 286. Both ST and MT write only the 2-byte UD2 head. The trap fires
before the tail is decoded, so the tail bytes of the original
instruction are never touched, and disarm restores just the head. Under
MT, a 2-byte store is single-copy-atomic as long as it doesn't cross a
64-byte cache line (Intel SDM Vol 3 Sec 8.1.1). That is not enough: a
peer's instruction fetch reads aligned 16-byte (Intel) or 32-byte (AMD)
blocks, and can take a site's two bytes from two fetches when they cross
a block, running a mix of old and new (`0f` + a jmp's `06` = CLTS ->
SIGSEGV). So MT sites must not cross a 16-byte boundary; the generator
and `libcov_mt` both enforce that (§17.2). Instructions shorter than 2 bytes can't hold UD2 and get no site.

**aarch64 / UDF #0**: the all-zero word *is* `UDF #0` (Permanently
Undefined, `0x0000iiii` with imm16 = 0) and raises SIGILL. (Not to be
confused with `BRK #0` = `0xD4200000`, which raises SIGTRAP.)

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

Each backend `memcpy`s its trap encoding from a host-endian `static
const` constant. Because the backend is compiled for the target's
endianness, that produces the byte order the CPU expects when it later
fetches the instruction. (Only little-endian ARM, armhf, is built; ARM
BE8 is untested.) No explicit byte-swapping
is needed in the backends.

### 6.4 Tunables and configuration

The project ships two layers of tunables headers, both using the same
`#ifndef`-guard pattern. Every knob can be changed either by editing
the value in the header or by passing `-D` flags at build time; the
`-D` wins because the preprocessor sees it first.

**`src/tunables.h`** — cross-cutting knobs:
- `LIBCOV_TRAP_SIGNO` (default `SIGILL`).
- `LIBCOV_COVERAGE_MODEL_SITE` (default 1 = site-id model; 0 = legacy
  hashed-PC model). See §9.
- `LIBCOV_MAP_FUDGE` (scales with N: 2 at N=1, 16 at N=2, `16 << (N-2)`
  above), `LIBCOV_MAP_MIN_POW2` (12), `LIBCOV_MAP_MAX_POW2`
  (24): site-id map sizing, `next_pow2(n_sites * FUDGE)` clamped to
  `[1<<MIN, 1<<MAX]` and never below `next_pow2(n_sites)`.
- `LIBCOV_MAP_SIZE_POW2` (default 16): fixed map size, **hashed-PC model
  only**.
- `LIBCOV_NGRAM_N` (default 2; window length for coverage scheme.
  1 = block, 2 = AFL edges, 3..8 = N-gram. See §9.2.)
- `LIBCOV_NGRAM_ROTATE` (default 0; when 1, per-position rotation
  before XOR so reordered windows index to distinct buckets. Useful
  at higher N to reduce XOR-commutativity collisions.)
- `LIBCOV_LOG_BUFFER_SIZE` (default 512; per-message buffer in libcov_logf).
- `LIBCOV_MARKER_REARM_TIMEOUT_NS` (1 ms): deferred re-arm of
  non-emulated markers (§21).
- `LIBCOV_SYNC_SIGNO` (`SIGRTMAX-2`), `LIBCOV_SYNC_TIMEOUT_NS` (1 ms): the
  MT signal-broadcast sync fallback (§17.2.5).

**`src/tunables_<arch>.h`** — per-backend knobs. One file per arch:
`tunables_x86_64.h`, `tunables_aarch64.h`, `tunables_arm.h`,
`tunables_mips.h`, `tunables_mips64.h`, `tunables_powerpc.h`,
`tunables_powerpc64.h`, `tunables_riscv64.h`. Each defines:
(PowerPC files use the `LIBCOV_ARCH_PPC_` / `LIBCOV_ARCH_PPC64_` prefix;
mips64 uses `LIBCOV_ARCH_MIPS64_`.)
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

## 7. Patch engine (`src/patch_st.c`, `src/patch_mt.c`)

This section describes the ST engine. The MT engine's differences are in
§17.2.3–17.2.5.

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
correctly handles patches that straddle a page boundary (impossible for
aligned fixed-width sites; possible on x86 when the 2-byte UD2 head
starts at the last byte of a page).

### 7.3 Cache flush

`__builtin___clear_cache` expands to:
- x86_64: nothing (coherent I-cache).
- AArch64: inline `DC CVAU` + `IC IVAU` in user space, no syscall.
- 32-bit ARM, MIPS, RISC-V: a cacheflush-style syscall.
- PPC: `dcbst` / `icbi`.

Mandatory on every arch with split I/D caches. We call it on every
arm/disarm.

### 7.4 Init-time validation

`patch_validate(e)` compares the bytes at `e->addr` to `e->orig[0..len)`.
At init we validate every entry before writing. Mismatches indicate the
patch list is stale relative to the binary (rebuild without
regenerating). The offending entry is skipped (left unarmed) with a log
line, and the arm summary counts it:
```
libcov: patch: stale entry at 0x4011a3 (bytes mismatch)
libcov: patch: armed=29 skipped=0 stale=2
```
Init goes inert only if *nothing* could be armed. This catches the very
common error of forgetting to regenerate after a target rebuild.

### 7.5 Self-protection

`util_self_range()` returns `[lo, hi)` of libcov.so's own mapping in
`/proc/self/maps`. Any patch entry whose address falls in that range is
refused with a log line. This prevents a malformed patch list from
clobbering libcov's own code.

### 7.6 Lookup

`patch_lookup(pc)` is a signal-safe binary search over the sorted
`patch_table`, behind a 16-entry direct-mapped PC cache (per thread
under MT). The table is allocated in the constructor and never
resized, so handler-time reads are race-free against init-time writes
(init completes before any traps can fire).

---

## 8. Signal handler (`src/handler_st.c`, `src/handler_mt.c`; chaining in `src/libcov.c`)

### 8.1 Installation

The handler is installed via `sigaction` (resolved through
`dlsym(RTLD_NEXT, "sigaction")`, falling back to `RTLD_DEFAULT`, so our
own `sigaction` interceptor in `libcov.c` doesn't recurse). It is
installed *before* any site is armed. The signal number is
`LIBCOV_TRAP_SIGNO` (default SIGILL; project-wide, see section 6.4). Flags:

- `SA_SIGINFO`: we want `siginfo_t` + `ucontext_t`.
- `SA_NODEFER`: we never want the trap signal blocked during our
  handler. Synchronous-fault signals that are blocked at delivery time
  kill the process — this flag prevents accidental masking.
- `sa_mask` (built by `handler_build_mask`) blocks every asynchronous
  signal, so a target handler can never run instrumented code mid-patch.
  It leaves the synchronous faults (SIGILL/SEGV/BUS/FPE/TRAP), the trap
  signal and the MT sync signal deliverable.

The previous disposition is seeded into `g_tsa`, a lock-free double
buffer (§12.1). The interposers keep it updated as the target installs
handlers, and chaining reads from it.

### 8.2 Trap path

Condensed from `handler_st.c` (the MT handler is the same with
`__thread` state):

```c
static void trap_handler(int signo, siginfo_t *info, void *uctx) {
    ucontext_t *uc = uctx;
    uintptr_t pc = libcov_arch_pc_from_uctx(uc);
    struct patch_entry *e = patch_lookup(pc);
    if (!e || !e->patched) {
        libcov_chain_trap(signo, info, uctx);   // real fault (§8.3)
        return;
    }
    sink_emit(pc, e->module_idx, e->site_id);   // record BEFORE restoring
    if (e->emulate) {                           // boundary marker (§21)
        if (leapfrog && prev && !prev->marker && !prev->patched)
            patch_arm(prev);
        prev = NULL;
        boundary_on_trap(pc, e);
        libcov_arch_emulate(uc, pc, e->orig, e->len);  // stays armed
        return;
    }
    patch_disarm(e);
    if (leapfrog) {
        if (prev && prev != e && !prev->marker && !prev->patched)
            patch_arm(prev);
        prev = e;                               // g_last_restored
    }
    boundary_on_trap(pc, e);                    // no-op without boundaries
}
```

### 8.3 Real-fault chaining

`libcov_chain_trap` handles LIBCOV_TRAP_SIGNO at addresses not in our
patch table — i.e., genuine illegal-instruction conditions in the
target. It forwards to whatever disposition the target last installed
(before init, or later through the interposers):
- A handler runs under the mask the kernel would have given it
  (interrupted mask + `sa_mask` + the signal unless `SA_NODEFER`),
  minus the trap and sync signals. `SA_SIGINFO` and `SA_RESETHAND` are
  honoured.
- `SIG_DFL` or `SIG_IGN`: restore the default disposition (via the
  cached real `sigaction`). Returning makes the kernel re-deliver and the
  process dies, preserving original-crash semantics such as core dumps.

### 8.4 Signal-safety contract

The handler runs in async-signal context. The full contract (what may
and may not be called on the handler path) is in §17.4. In short: no
`malloc`, no stdio, no `dlsym`, no sleeping locks, and no logging. Real
`sigaction`/`pthread_sigmask` are called only through pointers resolved
in the constructor.

---

## 9. Coverage sink (`src/sink_shm.c`, `src/sink.h`)

### 9.1 Bitmap layout

- One `uint8_t` per bucket, saturating at 255 (AFL-style hit counts).
- Size: under the default site-id model,
  `next_pow2(n_sites * LIBCOV_MAP_FUDGE)` (FUDGE 16 at the default N=2), clamped to
  `[1<<LIBCOV_MAP_MIN_POW2, 1<<LIBCOV_MAP_MAX_POW2]` = [4 KiB, 16 MiB] but
  never below `next_pow2(n_sites)`. Under the legacy hashed-PC model it
  is a fixed `1 << LIBCOV_MAP_SIZE_POW2` (64 KiB). The runtime value is in
  `hdr->map_size` and `libcov_map_size`.
- The bitmap is not a bare AFL map. It sits at `hdr->bitmap_offset`
  inside an `LCVS` region (72-byte header, live bitmap, ring of snapshot
  slots). Readers must take `map_size`, offsets and `flags` from the
  header. In ST boundary mode the live bitmap stays zero
  (`LIBCOV_SHM_FLAG_LIVE_EMPTY`), and coverage is in the ring (§21).

### 9.2 Coverage scheme (site-id / hashed-PC; block / edge / N-gram)

Two build-time choices shape a bucket index:

- **Coverage model** (`LIBCOV_COVERAGE_MODEL_SITE`). `1` (default),
  **site-id**: the bucket base is the site's dense id (its record index
  in the patch list). `0`, **hashed-PC**: the base is
  `sink_hash_pc(pc - module_base[midx], midx)`, a murmur3-fmix-style mix
  masked to the map.
- **Window length** (`LIBCOV_NGRAM_N`, default 2). The last `N-1` entries
  are XOR-folded into the index.

```c
sink_emit(pc, midx, site_id):
    if SITE model: cur = site_id;              win = sink_spread(site_id)
    else:          cur = sink_hash_pc(pc,midx); win = cur
    idx = cur
    for j in 0..N-2:                          // elided at N=1
        idx ^= prev[j]                        // or rotated prev[j] (ROTATE=1)
    idx &= libcov_map_mask
    bitmap[idx] = min(255, bitmap[idx] + 1)   // CAS loop under MT
    shift window; prev[0] = SITE ? win : (win >> 1)
```

| `N` | Site-id model (default)                   | Meaning of a bucket                     |
|-----|-------------------------------------------|-----------------------------------------|
| 1   | `idx = site_id`                           | "site was hit" -- zero collisions       |
| 2   | `idx = site_id ^ spread(prev site)`       | "edge prev->cur was taken" (default)    |
| k>=3| `idx = site_id ^ prev[0] ^ ... ^ prev[k-2]`| "last k sites in this thread were this tuple" |

Under the site-id model the current site contributes its *raw* id, and
only the history is spread across the map, so collisions arise only in
the fold step. N=1 is collision-free by construction; at N>=2 the
default `LIBCOV_MAP_FUDGE` doubles per history position, and init logs
an expected collision share (`1 - e^{-(k-1)/map_size}` for k distinct
N-grams, at k = n_sites and 8 * n_sites). Under the hashed-PC model,
N=2 is AFL's exact math, and the `cur >> 1` shift when inserting into
`prev[0]` is what makes A->B and B->A index to different buckets. The
site-id model doesn't need the shift, because raw-current vs.
spread-history is already asymmetric.

With `LIBCOV_NGRAM_ROTATE=1` each `prev[j]` is rotated by a
position-dependent amount *within the map width* before being XOR'd in.
So windows `{A,B,C}` and `{C,B,A}` index to distinct buckets (plain XOR
commutes).

Per-thread storage is `uint32_t libcov_prev_loc[LIBCOV_NGRAM_WIN]`
where `LIBCOV_NGRAM_WIN = max(N-1, 1)`; N=1 still allocates one unused
slot so the array never has zero length. Under MT the array is
`__thread`; under ST it is a process-wide global. boundary.c clears the
whole window at every iteration boundary so cross-iteration context
doesn't leak.

The first `N-1` emits per thread XOR with zero-initialised window
slots, biasing toward low buckets; this is the same warmup bias AFL
already exhibits at iter-1 and is harmless in practice.

Consumers (`test/fuzz_driver.c`, `test/shm_bitmap.py`) don't need to
know `N` or the model -- a bucket is a saturating counter either way,
and "novelty" comparisons work unchanged. Neither choice is recorded in
the shm header today. Init logs both
(`init: coverage model=site ngram_n=2 n_sites=… map_size=…`).

### 9.3 Backing storage

Path comes from `LIBCOV_SHM_PATH` (default `/libcov_<pid>`).

- `%p` expands to the pid and `%%` to `%` (only if the path contains
  `%`), so each process of a forking daemon can get its own region.
- If the path has no `/` after the first character, it is a shm name:
  `shm_open` (adding a leading `/` if needed) + `ftruncate` +
  `mmap(MAP_SHARED)`.
- Otherwise, treat as a filesystem path: `open(O_RDWR|O_CREAT)` +
  `ftruncate` + `mmap`.
- If `shm_open` fails for a shm-style name, fall back to a file under
  `$TMPDIR` (or `/tmp`), opened `O_NOFOLLOW`. Lets us run on embedded
  targets where `/dev/shm` is not mounted. A filesystem path has no
  fallback.
- Ownership is decided under `flock` from the header's `owner_pid` and
  `owner_start`: an in-place re-exec attaches, another live owner makes
  this process run inert, and a stale region is reset (§20).

The mmap base (the header) is `libcov_shm_base`; `libcov_bitmap` is
`base + bitmap_offset`. The fd is closed after the mmap; the mapping
survives the close, which is important because daemons commonly
`closefrom(3)` after init.

### 9.4 One live bitmap per process

A driver reads coverage via a separate mmap of the same shm region, so
the library needs no serialization. Without a boundary sidecar the live
bitmap is simply cumulative. With `LIBCOV_BOUNDARY_LIST` set, libcov
itself slices coverage per iteration into the snapshot ring (§21). Under
MT, each worker thread then gets a private live bitmap. One region per
process: use `%p` for forking daemons.

---

## 10. Module base resolution (`src/util.c`)

### 10.1 `util_module_base(modname)`

Parses `/proc/self/maps` for the first mapping that matches:
- `modname` NULL or empty → the main executable, by the exact path
  `readlink(/proc/self/exe)` returns;
- `modname` an absolute path → exact match against its `realpath`;
- otherwise → basename match.

A ` (deleted)` suffix is stripped before comparing. The scan continues
after the first match so that a second, different file with the same
basename logs an "ambiguous" warning suggesting `LIBCOV_MODULE_RENAME`.
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

`libcov_logf(fmt, ...)` writes to `LIBCOV_LOG` (or stderr). It uses
`vsnprintf` into a stack buffer then `write(2)`, and is never called from
the trap handler. Most lines come from init, but the interposers and the
MT sync fallback also log after init. At the end of init,
`libcov_log_seal()` records the fd's device/inode. From then on a line
is written only while the fd still refers to that same non-socket file.
After a daemon's `closefrom()` or a `dup2` of a socket onto fd 2, lines
are silently dropped rather than leaking into a reused fd.

---

## 11. Constructor and lifecycle (`src/libcov.c`)

### 11.1 Constructor priority

```c
__attribute__((constructor(101)))
static void libcov_init(void);
```

Priority 101 places us *after* ld.so's relocation work but *before*
typical user constructors. GCC reserves priorities 0-100 for the
implementation, so 101 is the earliest priority available to user code.

### 11.2 Init sequence

```
 1. libcov_log_init()          // open LIBCOV_LOG if set
 2. LIBCOV_PATCHLIST unset?    // -> init_fail (inert)
 3. parse LIBCOV_MODE          // exactly "oneshot", else leapfrog
 4. config_load(patchlist)     // mmap LCV3, check threading hint, resolve
                               //   module bases, copy into sorted table, munmap
 5. compute_map_size(n_sites)  // site-id model needs N before the region exists
 6. sink_init(path, ring, map) // map/attach the shm region (owner check, §20)
 7. trap_selftest()            // each encoding must raise LIBCOV_TRAP_SIGNO
 8. membarrier_init()          // MT only; picks SYNC_CORE or the fallback
 9. prime_real_fns()           // resolve real sigaction/pthread_sigmask now
10. handler_install(mode)      // BEFORE arming; prior disposition -> g_tsa
11. patch_arm_all()            // RWX-once or mprotect; validate; arm. 0 armed -> fail
12. oneshot+REARM=none guard, else boundary_init()   // §21
13. st_check_threads()         // ST only: warn if Threads > 1
14. g_initialized = 1; libcov_log_seal()
```

Every failure goes through `init_fail()`. That logs, and the library
stays inert -- or calls `abort()` if `LIBCOV_REQUIRE` is set to anything
other than empty or `0`. Steps 2–11 make the library inert (from step 10
on, the handler is installed but nothing is armed). Step 12 failing only
disables boundaries; plain coverage continues. With `LIBCOV_PATCHLIST`
unset and no `LIBCOV_REQUIRE`, the library is fully inert -- useful for
children that inherit `LD_PRELOAD` and for sanity-checking a daemon
without instrumenting.

### 11.3 Resource discipline

The resources that matter are acquired in the constructor:

- The patch list (and boundary sidecar) are mmap'd, copied into
  calloc'd tables, and munmap'd.
- The shm region is mmap'd, then its fd closed (the mapping survives).
- Real `sigaction` and `pthread_sigmask` are cached via `dlsym` before
  the handler is installed.
- The log fd is opened (and sealed, §10.3).

This makes the library robust against the standard daemon-init
operations (`chroot`, `setuid`, `closefrom`, `setsid` + double-fork to
`daemonize`). None of these can revoke an existing mmap or break a
cached function pointer.

Exceptions, all designed to be safe where they run:
- The other interposers resolve their real symbol lazily, on first call
  from the target (not from the trap handler).
- MT boundary mode `mmap`s a worker thread's private bitmap on its first
  boundary, from inside the trap handler.
- The MT sync fallback reads `/proc/self/task` per broadcast, so it does
  nothing after a chroot without `/proc`.

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
`libcov_chain_trap` — at addresses not in our patch table, or at a
table entry that isn't currently armed. The target's behavior for genuine LIBCOV_TRAP_SIGNO (default
SIGILL) is preserved, including its signal mask: the handler runs under
the interrupted mask plus its `sa_mask` plus the signal (unless
`SA_NODEFER`), not libcov's everything-blocked mask. The one deviation is
that the trap signal (and the MT sync signal) stay unblocked, because
the target's handler may itself run instrumented code.

glibc's `bsd_signal`, `ssignal`, `sysv_signal`/`__sysv_signal`,
`sigset`, `sigignore` and `siginterrupt` call the kernel through
internal aliases, not through the exported `sigaction`, so they are
interposed separately. Each stashes the disposition glibc would have
installed (e.g. `sysv_signal` → `SA_RESETHAND|SA_NODEFER`).

**Signal-mask filtering.** A synchronous trap that fires while blocked
kills the process. So `sigprocmask`, `pthread_sigmask`, `sighold` and
`sigsuspend` are also interposed, and they strip `LIBCOV_TRAP_SIGNO`
(and the MT sync signal) from any mask the target installs. `sighold`
of the trap signal becomes a no-op.

**ST thread warning.** `libcov_st.so` also interposes `pthread_create`.
It warns once, at init if `/proc/self/status` shows `Threads > 1` or on
the first `pthread_create`, because ST is unsafe under any second
thread (§17.1).

`g_initialized` gates the interception: before constructor finishes, we
forward everything to the real handlers, so an init-time `sigaction`
call (e.g., from inside libc) is not interfered with.

### 12.2 Init-time validation

Every patch record is byte-compared against the binary at init (§7.4).
Stale sites are skipped and counted (`stale=N`); init fails only if no
site at all could be armed. A partly stale list therefore runs with
partial coverage, and the log is where you see it.

### 12.3 Self-patch prevention

Documented in §7.5. Refuses any patch entry whose address lies in
libcov.so's own mappings.

### 12.4 Constructor-only resource acquisition

Documented in §11.3.

### 12.5 Trap-encoding self-test

Before the handler is installed, every trap encoding the backend can
write (both lengths on ARM/RISC-V) is executed once from a scratch page.
Temporary handlers sit on every signal an illegal instruction could
plausibly raise (SIGILL, SIGTRAP, SIGSEGV, SIGBUS, SIGFPE, SIGSYS). The
encoding must arrive as `LIBCOV_TRAP_SIGNO`. Otherwise init fails and nothing
is armed: a mismatch (e.g. `-DLIBCOV_TRAP_SIGNO=SIGTRAP` with a SIGILL
encoding, or a chip that traps the default encoding differently) would
kill the target on its first trap. Skipped on ppc64 ELFv1.

---

## 13. Patch list generator (`tools/gen_patchlist.py`)

### 13.1 Rizin interaction

`gen_patchlist.py` drives rizin through the **`rzpipe`** Python module:
one persistent rizin session per module, with `aaa` run once. (It
pre-checks that the binary is readable, because rzpipe busy-loops when
rizin can't open the file.) `gen_boundary.py` instead runs a fresh
`rizin -q -c` per query, but imports `gen_patchlist`, so it needs rzpipe
too. Calls:

- `ij` → architecture, bits, endian, image base.
- `aflj` (after `aaa`) → function list with per-function `bits` (ARM/Thumb).
- `afbj @ <fn>` → basic blocks for a function.
- `pdj <n> @ <addr>` → first `n` instructions of a block as JSON
  (includes `size`, `bytes`, `type`).
- `afij @@F` callrefs → the static call graph for `--root` slicing.

### 13.2 Per-arch strategy selection

```python
def default_strategy(arch, bits):
    if arch == "mips": return "entry"
    return "terminator"
```

- **terminator** (default for x86, AArch64, ARM, Thumb, PPC, RISC-V):
  patch the block's first mid-block *call* if it has one, so blocks
  whose callee never returns (`exit`, `abort`) still report. Otherwise
  patch the *last eligible* instruction: at least 2 bytes, not a data
  word, not inside a Thumb IT block, and (MT) atomically writable. Usually
  this is the branch itself; a block ending in a 1-byte `ret` gets an
  earlier instruction instead. Coverage signal is "the block ran (to its
  call or end)".
- **entry** (MIPS): patch the *first* instruction of each block.
  Coverage signal is "the block was entered".

The choice for MIPS is forced by branch delay slots (next section).

### 13.3 MIPS branch delay slot avoidance

A trap in a branch delay slot is fatal to this design. The MIPS kernel
sets the BD (Branch Delay) bit in Cause and reports
`EPC = branch_address`, not the delay-slot PC. `patch_lookup` therefore
misses, the trap is chained as a real fault, and the process dies.

Rizin places a branch's delay slot *inside* the branch's block, so on
MIPS the terminator **is** the delay slot. The generator refuses
`--strategy terminator` on MIPS with a hard error, and the default is
`entry`.

The entry strategy also guards the other case: a block can start in a
delay slot when the instruction before it (at `X - 4`) is a branch
(matched by type suffix: call/jmp/ret). In that case it patches the
block's second instruction, skipping leading data words too; a block
with no eligible instruction gets no site. `gen_boundary.py` uses the
same helper, so MIPS markers stay co-located with patched sites.

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
function at offset X, the function at X+8 (whatever rizin named it) is
included as a companion `[local]` entry.

ELFv1 functions whose body starts with a `nop` show up in rizin as
`fcn.<entry+4>`. Both generators rename them after their `.opd` symbol
(`dbg.NAME`, or `sym.NAME` without DWARF), so name filters, `--root` and
markers work.

### 13.6 Invocation

```
./tools/gen_patchlist.py <binary> <out.lcv> \
    [--threading st|mt]                 # default st; must match the .so
    [--include-pat REGEX] [--exclude-pat REGEX]   # exclude is ORed with the defaults
    [--no-default-exclude] [--include-fcn]        # fcn.* skipped by default
    [--root SYM_OR_ADDR ...] [--cutoff SYM_OR_ADDR ...] [--max-depth N]
    [--print-reachable]                 # dry run; needs --root
    [--module NAME:PATH ...]            # extra modules; MODULE!SYM in roots
    [--strategy auto|entry|terminator]
    [--fail-on-overlap] [--allow-empty] [-v]
```

The default exclusion pattern filters out PLT stubs, ctor/dtor sections,
register/deregister tm clones, frame_dummy, and `__libc_csu*`. An empty
selection is an error unless `--allow-empty`. Modules (and the primary
binary) are stored under their symlink-resolved basename, since that is
what `/proc/self/maps` shows. The generator writes the threading hint
ST (1) or MT (2), never ANY. Name and address resolution is in
`tools/rz_resolve.py`, shared with `gen_boundary.py`; a bare all-digit
token is **decimal**. README.md and HOWTO.md §5 document slicing in
detail.

---

## 14. Build system

### 14.1 Top-level Makefile

```
make                      # native ST (auto-detects host arch)
make THREADING=mt         # native MT
make ARCH=aarch64         # cross-build for aarch64
make all-arch             # every ARCH (11 architectures, 8 backends)
make all-variants         # ST and MT for every ARCH
make native               # library only, no test targets
make test                 # build both variants + all test targets, run 20 native suites
make tools                # opt-in libdemalloc.so
make print-vars           # resolved ARCH/BACKEND/THREADING/SRC/LIB
make clean                # rm -rf build
```

The `ARCH` variable maps to:

- a backend source file `src/arch_<backend>.c`,
- a cross-compiler prefix (`aarch64-linux-gnu-`, `arm-linux-gnueabihf-`,
  etc.),
- a qemu-user binary for validation (`qemu-<arch>-static`; PowerPC uses
  `qemu-ppc[64[le]]-static`).

The mapping table covers: x86_64, aarch64, arm, mips, mipsel, mips64,
mips64el, powerpc, powerpc64, powerpc64le, riscv64.

Outputs:
```
build/<arch>/libcov_<st|mt>.so
build/<arch>/obj_<st|mt>/       (object + .d dependency files)
build/<arch>/target_* , fuzz_driver   (from test/Makefile, see 14.2)
build/<arch>/libdemalloc.so      (make tools)
```

### 14.2 Test Makefile

`test/Makefile` is invoked from the top-level with `ARCH`, `CROSS`, and
absolute `BUILD` paths. Ground-truth targets are built with `-no-pie -O0
-fno-stack-protector`, so the branch graph is deterministic and easy to
disassemble. Goals:

- `all` (what plain `make` builds): `target_simple`, `target_loop`,
  `target_orderable`, `target_dispatch`, `target_markers`, `fuzz_driver`
- `mt`: `target_simple_mt`, `target_loop_mt`, `ring_dump`
- `multimod`: `target_multimod` + `libmultimod_helper.so`
- `o2pie`: `-O2` PIE variants of `target_simple` and `target_dispatch`
- `thumb` (ARM): `target_simple_thumb`, `target_markers_thumb` with `-mthumb`
- `demalloc`, `loop`

ARM targets otherwise default to ARM mode (`-marm`). `target_paired`,
`target_reexec` and `target_signals` are compiled inline by their suites.

### 14.3 Library compile flags

```
-O2 -g -Wall -Wextra -Wno-unused-parameter -fPIC -MMD -MP
-ftls-model=initial-exec -DLIBCOV_THREADING_{ST,MT}   [+ -marm on arm]
```

Linker: `-shared -fPIC -Wl,-z,now -ldl -lrt [-lpthread for MT]
-Wl,--as-needed -latomic`. libatomic is pulled in only where 64-bit
atomics aren't inline (32-bit mips/powerpc). `initial-exec` TLS keeps
every TLS access in the trap handler free of `__tls_get_addr`, which can
allocate.

`-Wl,-z,now` forces full relocation at load time so we don't get
surprised by lazy PLT resolution during the constructor.

---

## 15. Validation infrastructure

### 15.1 `test/target_simple.c`

Small C program with a known branch graph:

- `classify(int)`: 5-way if/else chain (`<0`, `==0`, `<10`, `<100`, else).
- `loop_sum(int n)`: for-loop with even/odd branch inside.
- `cmdline(const char *)`: an if/else chain on the first char, then a
  separate if/else on the length.
- `main`: orchestrates the above and prints `E:<edge>` markers to stdout
  (including `E:noargs` and `E:big`).

Same source compiles for all 11 architectures.

### 15.2 `test/run_validation.sh` (native)

For the host arch, runs four checks:

1. **Determinism**: two identical runs produce identical bitmaps.
2. **Input differentiation**: input "42" vs input "-3" produce
   different bitmaps.
3. **Leapfrog hit counts**: with input 99, the maximum bucket reaches
   ≥ 2.
4. **Output unchanged**: target stdout under libcov equals target stdout
   without libcov.

`make test` runs 20 native suites one after another through
`test/run_all.sh` (the `NATIVE_SUITES` list in the Makefile):

- run_validation, _mt, _boundary, _boundary_mt, _multimod, _signals
- _coverage_options, _failloud, _generator, _generator_safety, _o2pie
- _marker_emulation, _reexec, _modules, _patch_mode, _paired
- _docs (runs HOWTO.md/README.md recipes extracted from the docs)
- _relay (remote fuzzing template end to end on loopback; §24)

Not in `make test`: `run_cross.sh`, `run_cross_mt.sh`,
`run_cross_signals.sh`, `run_validation_demalloc.sh`. HOWTO.md §11
summarises what each suite covers.

### 15.3 `test/run_cross.sh` (all backends)

Runs the same four checks against libcov_st.so for every ARCH (plus
arm-thumb). x86_64 runs natively; the others run under
`qemu-<arch>-static -L /usr/<triple> -E LD_PRELOAD=...`. Output:

```
PASS=12  FAIL=0  SKIP=0
```

Backends covered: x86_64, aarch64, arm, arm-thumb, mips, mipsel, mips64,
mips64el, powerpc, powerpc64, powerpc64le, riscv64.

### 15.4 `test/fuzz_driver.c`

Reference boundary-aware driver:
`fuzz_driver <libcov.so> <patchlist> <boundary-list> <target> [args...]`.

1. Spawns the target **once** with `LD_PRELOAD`, its own region
   (`/tmp/libcov_driver_<pid>`) and `LIBCOV_MODE=leapfrog` unless set.
   The target's stdout goes to `/dev/null`.
2. Writes each stdin line (up to 1023 bytes) to the target's stdin.
3. Reads one snapshot per generation from the ring with the seqlock
   protocol (`read_slot`, §21).
4. Prints `gen=… (input#k='…') kind=init|iter|gap tid= ns= hit= new=
   total=` per snapshot, then a summary with overruns, lost_gens,
   read_failures, publish_dropped and init/iter/gap counts.
5. Exits 3 on any overrun or read failure, otherwise 0 (not the target's
   exit code). `FUZZ_DRIVER_BURST=1` writes every input before reading,
   to force ring overruns in tests.

Not a real fuzz loop — no mutation, no corpus management, no crash
dedup. Demonstrates the snapshot-reading driver pattern.
`test/ring_dump.c` is the passive equivalent for self-iterating targets.

---

## 16. Configuration interface

All `LIBCOV_*` environment variables, read once in the constructor
(changing them after init has no effect). README.md "Environment
variables" has the full semantics; this is the index.

| Env var | Default | Purpose |
|---|---|---|
| `LIBCOV_PATCHLIST` | (none — inert if unset) | Path to LCV3 patch list |
| `LIBCOV_REQUIRE` | unset | Non-empty and not `0`: `abort()` on any init failure instead of running inert |
| `LIBCOV_SHM_PATH` | `/libcov_<pid>` | Region location (shm name or FS path; `%p` → pid, `%%` → `%`) |
| `LIBCOV_MODE` | `leapfrog` | `oneshot` or `leapfrog` (anything but exactly `oneshot` → leapfrog) |
| `LIBCOV_ST_PATCH` | `auto` | ST only: `auto` (RWX once) or `mprotect` (per write) |
| `LIBCOV_MODULE` | the main executable | Module for boundary-sidecar resolution only |
| `LIBCOV_MODULE_RENAME` | unset | `old=new[,…]` module-name rewrites (§4.5) |
| `LIBCOV_LOG` | unset (stderr) | Log path |
| `LIBCOV_BOUNDARY_LIST` | unset | LCVB1 sidecar; boundaries inert if unset (§21) |
| `LIBCOV_BOUNDARY_REARM` | `none` | `none` / `touched` / `all` (unknown → `none` + WARNING) |
| `LIBCOV_BOUNDARY_RING` | `8` | Ring slots, clamped to 2..16 |
| `LIBCOV_BOUNDARY_INIT_GRACE` | `0` | Boundary fires not published (merged into INIT) |
| `LIBCOV_BOUNDARY_NOTIFY_FD` | unset | Inherited eventfd, written after each publish |
| `LIBCOV_BOUNDARY_EMULATE` | `1` | `0` disables marker emulation |
| `LIBCOV_ALLOW_ONESHOT_NOREARM` | unset | Permit oneshot + REARM=none with boundaries |
| `LIBCOV_SYNC_FALLBACK` | `auto` | MT only: `auto` / `tgkill` / `off` (§17.2.5) |

`LIBCOV_SYNC_SIGNO`, `LIBCOV_SYNC_TIMEOUT_NS` and every other
`LIBCOV_*` name in §6.4 are build-time `-D` macros, not environment
variables.

---

## 17. Threading models (`libcov_st.so` and `libcov_mt.so`)

The library is built as two separate `.so` files at the same interfaces.
Pick the brick that matches your target.

### 17.1 ST brick -- `libcov_st.so`

Designed for single-threaded targets. Smallest possible surface area.

- The N-gram window `libcov_prev_loc[LIBCOV_NGRAM_WIN]` (`uint32_t`) is a
  global; no atomics.
- `g_last_restored` (leapfrog) is a single pointer global; no atomics.
- The patch table is allocated once at init and never resized; handler
  reads are race-free against init writes because init completes before
  any trap can fire (no patched sites exist yet).
- The bitmap increment is a non-atomic `uint8_t` increment, saturating
  at 255.
- Byte writes are plain stores into pages made `R|W|X` at init
  (`LIBCOV_ST_PATCH=auto`). Where the kernel refuses that, or with
  `LIBCOV_ST_PATCH=mprotect`, they use the mprotect sequence
  `R|X -> R|W -> memcpy -> R|X` (a brief non-executable window on the
  code page).

Under a multi-threaded target, `libcov_st.so` is **unsafe in every
mode**. Its patch writes aren't atomic, the mprotect fallback makes code
pages briefly non-executable, and its leapfrog state isn't thread-safe,
so peer threads can crash. It warns at init (or on the first
`pthread_create`). Use `libcov_mt.so` instead.

### 17.2 MT brick -- `libcov_mt.so`

Designed for arbitrary-thread-count targets. Safe under contention.

#### 17.2.1 Per-thread state

- The N-gram window `libcov_prev_loc[]` is `__thread`: each thread has
  its own. Concurrent threads compute their own edge sequences with no
  interference.
- `g_last_restored` (leapfrog) is `__thread`: each thread independently
  leapfrogs through its own history. Two threads' leapfrog tails never
  collide because per-entry arm/disarm is serialized (see 17.2.3).
- Also per thread: the 16-slot PC lookup cache, and in boundary mode the
  live bitmap (`libcov_thread_bitmap`, after the thread's first
  boundary), the depth counter and held-marker state (§21).

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
`disarm` could otherwise complete their writes in the opposite order
from their state transitions and leave the bytes inconsistent
with `patched`. Under leapfrog with N threads, this race is
guaranteed to happen at the per-trap rate; without the spinlock, the
trap handler enters an infinite loop on the stale-state site and
exhausts the signal stack.

The lock is signal-safe by construction:

- On the primary path the critical section is just one atomic store +
  `clear_cache` (the batched `membarrier` runs after the lock is
  released), so the spin is bounded. On the W^X fallback paths the lock is
  held across a `pwrite`, or across mprotect + memcpy + mprotect. Spinners
  `sched_yield()` after 64 spins.
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

The atomic store needs the site's bytes to fit one store: aligned on
fixed-width ISAs, within one 64-byte line on x86. The generator's
`--threading mt` only emits such sites; any other site goes through the
fallback below. On x86 the fetch side asks for more (below the table).

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
| x86_64                                       | 2 bytes (UD2 head) | Intel SDM Vol 3 Sec 8.1.1 (aligned, or unaligned within one cache line); fetch: within one 16-byte block |

For x86 specifically, the patch is the leading 2-byte UD2 only; the
remaining bytes of the original variable-length instruction are never
touched. Sites need not be 2-aligned: an unaligned 16-bit store is
still atomic when both bytes are in one 64-byte cache line, and
`write_bytes()` uses a plain `movw` for it.

The store being atomic does not make the *fetch* atomic. Instruction
fetch reads aligned blocks (16 bytes on Intel's legacy decoder, 32 on
AMD Zen), so a peer fetching a site whose two bytes cross a block can
take them from two fetches, one before the write and one after, and run
a mix: UD2's `0f` with the second byte of `eb 06` is `0f 06` (CLTS, a
privileged instruction: #GP -> SIGSEGV). `run_validation_mt`'s leapfrog
run hit exactly that about once in 250 runs on a Zen 4, always at the
one site that crossed a 32-byte boundary, and never in 3000 runs without
it. Both sides now keep an x86 MT site's 2 bytes inside one 16-byte
block, which is also inside any larger block and the cache line:
`--threading mt` skips other candidates (the terminator walk-back
usually finds another instruction in the block, so `target_simple_mt`
keeps all its sites), and `libcov_mt` refuses them at init
(`fetch_unsafe=` in its `armed=` log line) for older MT lists and ANY
lists.

### 17.3 Threading-hint enforcement

Each variant's `config.c` is compiled with `-DLIBCOV_THREADING_ST` or
`-DLIBCOV_THREADING_MT`. The LCV3 header carries a matching threading
hint (0=ANY, 1=ST, 2=MT). A mismatched hint makes init fail with
`config: patch list built for threading=…, this library is … --
refusing`: inert, or abort under `LIBCOV_REQUIRE`. A list with the ANY
hint would be accepted by both variants, but `gen_patchlist.py` never
writes ANY. Its default (`--threading st`) list is therefore refused by
`libcov_mt.so`.

### 17.4 Signal-safety contract (both bricks)

The trap handler runs in async-signal context. The contract is about
what can deadlock or allocate, not a literal POSIX async-signal-safe
list. Calls on the handler path are restricted to:

- Raw syscalls and syscall-thin libc wrappers: `mprotect`, `pwrite`,
  `mmap` (MT per-thread bitmap), `write` to a pre-opened fd or eventfd,
  `clock_gettime`, `gettid`, `sched_yield`, `membarrier`, and for the MT
  sync fallback `open`/`getdents64`/`rt_tgsigqueueinfo`/`close` on
  `/proc/self/task`.
- *Pre-resolved* function pointers to the real `sigaction` (restoring
  `SIG_DFL` when chaining) and `pthread_sigmask` (giving a chained target
  handler its kernel-equivalent mask). These are resolved in the
  constructor, never `dlsym`'d in the handler.
- `pthread_setspecific`, only to register the MT per-thread bitmap's
  destructor. For libcov's low key numbers glibc stores it without
  allocating.
- `__builtin___clear_cache`, `__atomic_*` builtins, bounded spinlocks.
- Reads of mmap'd memory and binary search of the immutable patch table.
- Inline helpers compiled from C (`sink_emit`, `sink_hash_pc`,
  `sink_spread`).

**Forbidden**: `malloc` and friends (including `__tls_get_addr`, hence
`-ftls-model=initial-exec`), stdio, `dlsym`, `libcov_logf`, any lock that
sleeps (pthread mutexes, condvars), and using `errno` from a libc call
without saving it.

Code review gate: every function called from the handler must be checked
against this list; new helpers go through the same scrutiny.

---

## 18. Test target spec

`test/target_simple.c` is the ground-truth for validation. Its branch
graph is documented in §15.1. It deliberately:

- Builds with `-no-pie -O0` so the linked addresses are stable and
  disassembly-friendly. (`make -C test o2pie` adds `-O2` PIE variants for
  tail calls, jump tables and ASLR.)
- Uses `__attribute__((noinline))` on each helper to prevent inlining
  collapsing the graph.
- Prints `E:<marker>` lines so we can confirm the target's logical
  execution path matches expectations independently of bitmap state.

A Thumb variant (`target_simple_thumb`) is built with `-mthumb` on ARM
for Thumb-mode validation.

`test/target_simple_mt.c` is the MT counterpart. It has its own copies
of `classify`/`loop_sum`/`cmdline`-style helpers and drives them
concurrently from N pthread workers
(`target_simple_mt <threads> <iters> <inputs...>`), each iterating a configured
number of times on its own input. Designed to maximise the chance of
two threads hitting the same patched site at the same time. The native
MT validation (`test/run_validation_mt.sh`) drives it with a 16-thread
/ 2000-iter stress (tunable via `THREADS_STRESS` and `ITERS_STRESS`)
to exercise the per-entry spinlock and the atomic bitmap under
high contention. Its patch list must root the `worker` thread function
explicitly: it is reached only through `pthread_create`'s function
pointer.

Other targets, each the ground truth for one feature:
- `target_loop` / `target_loop_mt`: stdin loop with an `iter_begin`
  marker, single / multi-worker.
- `target_paired`: BEGIN/END markers.
- `target_markers`(`_thumb`): every emulated branch form.
- `target_dispatch`: function-pointer dispatch and a non-returning callee.
- `target_orderable`: block vs edge vs N-gram.
- `target_multimod` + `libmultimod_helper.so`: multi-module lists.
- `target_reexec`: re-exec and fork+exec.
- `target_signals`: signal masks and target SIGILL handlers.
- `target_demalloc`: libdemalloc.

Future work: a stress harness that spins threads via raw `clone(2)`
rather than pthreads, for targets whose threading model is non-libc.
Captured in TODO.md.

---

## 19. Limitations of the current implementation

These are inherent to the present scope, not bugs:

1. **No JIT / self-modifying code coverage.** Code generated after init
   isn't in the patch list and isn't instrumented.
2. **Iteration boundaries need markers.** Per-input scoping (§21) works
   only where a sidecar can name a marker function in the main
   executable. Without one, the bitmap is cumulative and the driver must
   scope per process.
3. **No in-library remote transport.** libcov itself writes only to local
   shared memory. Over-IP collection is an out-of-process template
   (`tools/suzzer-relay` + `tools/suzzer_brain.py`, §24), not a library
   feature; a fork-per-connection daemon is still out of scope there.
4. **Raw signal syscalls bypass interception.** `sigaction`, `signal`,
   `sigprocmask`, `pthread_sigmask` and glibc's older wrappers
   (`bsd_signal`, `ssignal`, `sysv_signal`/`__sysv_signal`, `sigset`,
   `sigignore`, `sighold`, `siginterrupt`, `sigsuspend`) are interposed,
   but raw `rt_sigaction`/`rt_sigprocmask` syscalls, the compat-only
   `sigvec` and `sigpause` are not (syscall-level coverage needs seccomp
   or libsyscall_intercept).
5. **W^X-strict kernels.** Both variants first try `R|W|X` once at init.
   If that's refused, ST falls back to a transient `mprotect(R|W)` per
   write, about 3x slower in leapfrog, which a kernel that refuses *any*
   writable text mapping will also block. MT falls back to non-atomic
   `pwrite(/proc/self/mem)` with a WARNING (see 17.2.4).
6. **MT cross-validation is limited under qemu-user.** qemu-user only
   invalidates its TCG translation cache on `mprotect` with a perm
   change, and that perm change strips `PROT_EXEC` long enough to
   SIGSEGV peer guest fetches. We therefore run the full MT cross
   suite only on `x86_64` (natively) and `aarch64` (where qemu happens to
   cooperate); for the other 9 architectures the MT cross check is build +
   link + generator only. Real-hardware MT validation is in TODO.md.
7. **Raw-`clone(2)` thread targets are not covered by the MT stress
   test.** `target_simple_mt.c` uses pthreads. A `clone()`-based
   stress harness is captured in TODO.md.

Each of these has a corresponding plan in `TODO.md`.

---

## 20. Region ownership, re-exec and fork+exec (`src/sink_shm.c`)

A daemon that execs itself inherits `LD_PRELOAD` and `LIBCOV_SHM_PATH`,
so libcov initialises again in the new image. The header records the
process that created the region: `owner_pid`, plus `owner_start` (the
low 32 bits of `/proc/<pid>/stat` field 22). Both survive `exec`. Under
an `flock` on the region, the new image decides:

- **Same process** (in-place re-exec, e.g. `sshd -R`): attach. The
  bitmap, ring and `gen_current` carry on.
- **Another live process** (a fork+exec child, an nginx binary upgrade):
  leave the region alone; this process runs inert and logs
  `in use by live pid N`. `%p` in `LIBCOV_SHM_PATH` gives it its own
  region instead.
- **Nobody alive** (left over from an earlier run): reset.

`fork` without `exec` still shares one region with the parent. In ST
builds, increments from the two processes are not atomic.

---

## 21. Iteration boundaries (`src/boundary.c`)

For long-running targets, libcov can slice coverage per input itself.
README.md "Iteration boundaries" is the reference for drivers. This is
the design summary.

**Sidecar.** `LIBCOV_BOUNDARY_LIST` names an LCVB1 file written by
`tools/gen_boundary.py`:
- Header: magic `LCVB`, version 1, count, flags.
- 16-byte records: module offset, kind BEGIN/END, depth filter any/zero.

Markers must coincide with patched sites in the main executable
(`LIBCOV_MODULE` overrides which module). A marker that isn't a site
logs a WARNING and never fires.

**Modes.** Begin-only (every BEGIN fires a boundary) or paired (at least
one END: depth is tracked per iteration, and `zero` markers skip
recursive calls).

**Snapshot ring.** `LIBCOV_BOUNDARY_RING` slots follow the live bitmap
(default 8, clamped to 2..16). Each slot is a 32-byte header
(`slot_gen`, `tid`, timestamp, `flags`) plus `map_size` bytes. A
boundary publishes the segment since the previous one:
- the first boundary in the process publishes startup coverage, flagged
  `INIT` (and sets `hdr->gen_init`);
- an iteration is flagged `ITER`;
- in paired mode, the harness code between END and the next BEGIN is
  flagged `GAP`.

Publishing clears the live bitmap and the N-gram window, then applies
`LIBCOV_BOUNDARY_REARM`:
- `none`: leapfrog re-arms on its own;
- `touched`: re-arm sites disarmed since the last boundary, process-wide;
- `all`: re-arm every disarmed site.

oneshot + `none` is refused, unless `LIBCOV_ALLOW_ONESHOT_NOREARM` is set,
because per-iteration maps would go empty after warmup.
`LIBCOV_BOUNDARY_INIT_GRACE` withholds the first N publishes; their
coverage merges into the INIT snapshot.

**Publish and read protocol.** Generations come from `fetch_add` on
`hdr->gen_current`, *before* the slot is stamped, so `gen_current` is the
highest generation assigned, not necessarily readable yet.
- **ST** swaps a pointer (zero-copy). The live area at `bitmap_offset`
  stays zero, signalled by `LIBCOV_SHM_FLAG_LIVE_EMPTY`. It stamps
  `slot_gen` with a release store after the data, then invalidates the
  next slot.
- **MT** copies the thread's private bitmap into a slot. A slot still
  held by a newer generation is dropped and counted in
  `hdr->publish_dropped`.

Readers use the seqlock check. For generation `g`:
1. Take `slot = ring[g % ring_size]` and check `slot_gen == g` before
   and after the copy.
2. If `gen_current - g >= ring_size`, data has been lost; resume at
   `gen_current - ring_size + 2`.

`LIBCOV_BOUNDARY_NOTIFY_FD` (an eventfd only) is written after each
publish, so readers can block instead of polling.
`test/fuzz_driver.c` (`read_slot`) is the reference reader.

**Marker emulation.** A marker that is disarmed like a normal site can be
passed untrapped by a peer thread, and two iterations merge into one
snapshot. So by default (`LIBCOV_BOUNDARY_EMULATE=1`) markers whose
instruction the backend can execute in software stay armed for good.
The handler emulates the instruction (`libcov_arch_emulate`) and
advances the PC. Supported forms:
- branches and NOP-like hints on x86, AArch64, ARM/Thumb, RISC-V and
  PowerPC;
- on MIPS, whose markers are block-entry prologue instructions,
  register-only ALU ops (`arch_mips_emulate.h`).

Init logs `N of M marker(s) emulated`. Other markers are disarmed and
re-armed process-wide, once every thread that trapped on them has
trapped elsewhere, or after `LIBCOV_MARKER_REARM_TIMEOUT_NS`.

**MT.** A worker thread's first boundary moves it from the shared live
bitmap to a private, `mmap`'d one. So a snapshot holds exactly one
thread's iteration and snapshots never mix threads. Threads that never
hit a marker keep emitting into the shared bitmap at `bitmap_offset`.

---

## 22. Optional tooling

- `tools/mutate.py`: stdlib-only AFL++-style havoc/splice mutator,
  usable as a library or a CLI.
- `tools/libdemalloc.c`: an opt-in `LD_PRELOAD` heap-bug catcher (guard
  pages, canary, bounded UAF/double-free quarantine), built by
  `make tools`.
- `tools/inject/`: a standalone injector that loads libcov into an
  already-running PID through ptrace (working on x86_64, build-only stubs
  elsewhere). It has its own Makefile, README.md and Design.md.
- `tools/suzzer-relay` + `tools/suzzer_brain.py`: the remote fuzzing
  template (§24).

---

## 23. References

- `README.md` — reference: usage, environment variables, formats, quick start.
- `HOWTO.md` — step-by-step operational guide and troubleshooting.
- `TODO.md` — deferred design backlog, structured by phase.
- `Review.md` — coverage-options review (superseded by TODO.md).
- `tools/gen_patchlist.py` — per-arch generator strategies, regex
  conventions for rizin function names.
- `test/run_cross.sh` — canonical "is everything still working across
  architectures" command; `make test` for the native suites.

---

## 24. Remote coverage transport (`tools/suzzer-relay`, `tools/suzzer_brain.py`)

libcov writes only to a local shm region (§9, §20–§21). Over-IP fuzzing is an
out-of-process template, not a library feature: a small C relay on the device
and a Python brain off-device, one TCP connection between them. HOWTO.md §14.1
is the operator's guide; this is the design. The wire protocol (SZR1) is
specified normatively in docs/FORMATS.md §4, in terms of an *executor* (the
relay is one) and a brain, so other executors can stand in for the relay.

**Components.**
- `src/ring_reader.h` — header-only client-side ring reader (attach, seqlock
  `rr_read_slot`, overrun-accounting `rr_drain_to`), shared by `fuzz_driver`,
  `ring_dump` and the relay so the seqlock lives in one place.
- `tools/suzzer-relay.c` (device) — spawns the target under libcov with an
  **eventfd** on `LIBCOV_BOUNDARY_NOTIFY_FD`, attaches to the ring, and
  bridges to the brain.
- `tools/relay_proto.h` — the wire framing (shared reference for both ends).
- `tools/suzzer_brain.py` (off-device) — mutates with `tools/mutate.py`,
  folds returned bitmaps into a cumulative map, keeps new-coverage inputs,
  saves crashes.
- `test/target_netd.c` — a single-process TCP template daemon with paired
  `req_begin`/`req_end` markers around its handler.

**Protocol.** One persistent TCP connection; the relay dials the brain,
sends a 4-byte magic, then both exchange `[u32 len][u8 type][payload]` frames
(`SZR_HELLO`, `SZR_INPUT`, `SZR_COVERAGE`, `SZR_CRASH`, `SZR_BYE`). All
header integers are network byte order.

**Why the brain never parses a foreign header.** The relay decodes the shm
header *on the device* (native byte order) and sends a `COVERAGE` frame
carrying an already-decoded `map_size` plus the raw `uint8` counter bitmap.
Counter bytes are order-independent, so a big-endian or 32-bit device needs no
special handling on the brain — unlike the shared-filesystem / ssh patterns
(HOWTO §9 A/B), which ship the raw header and must byte-swap it.

**Lockstep.** One input is in flight at a time, and every `INPUT` gets exactly
one reply:
1. Brain sends `INPUT(id, bytes)`.
2. Relay connects to the daemon's own port, writes the bytes, half-closes and
   drains the reply. For a paired-marker daemon the reply EOF arrives *after*
   `req_end` has fired the boundary, so by then the eventfd is already
   signalled — the relay wakes on it, reads the ring, and replies.
3. Relay sends `COVERAGE(id, gen, kind, map_size, bitmap)` — the request's
   `ITER` snapshot (it drains and drops the between-request `GAP`/startup
   `INIT` gens). If the daemon died, it sends `CRASH(id, reason, status)` and
   restarts the daemon (and re-attaches, since the region resets under a new
   owner, §20). Reasons (`relay_proto.h`): 1 exit, 2 signal, 3 delivery
   failed, 4 malformed `INPUT` frame (rejected by the relay; the daemon is
   untouched). Every `INPUT` gets exactly one reply.

The brain scores only `ITER` frames (new nonzero bytes vs. its cumulative
map), enqueues inputs that found coverage, and writes `CRASH` inputs to
`out/crashes/`.

**Scope and limitations.** Single-process daemon (one process handles requests
in a loop); plain TCP, no auth; one input in flight. A fork-per-connection
daemon shares one region across children (§19 limitation, TODO.md
fork-per-connection) and is not handled. A one-shot / process-per-input target
would instead have the relay re-spawn per input and read the cumulative
`bitmap_offset` after `waitpid` — a future variant.

`test/run_validation_relay.sh` runs relay + brain + `target_netd` on loopback:
HELLO negotiated, distinct seeds reach distinct coverage, a planted crash is
reported and saved.

---

End of document.
