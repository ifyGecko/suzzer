# Baremetal / RTOS backend (PLAT=baremetal-mips)

libcov's coverage mechanism — overwrite an instruction with a trap-raising
encoding, catch the fault, record an edge, restore, resume — is OS-neutral.
The Linux build takes control through a `SIGILL` `sigaction` handler injected
with `LD_PRELOAD`; the baremetal build takes control through the CPU's own
**exception vector**, so the same framework instruments a raw firmware or RTOS
image that has no userland, no dynamic linker, and no libc.

This is a framework backend, not a product: it is **board-agnostic**. Nothing
here names a particular device. You point it at your target with a handful of
compile-time macros and one or two weak hooks.

## Build

    make baremetal EXTRA_CFLAGS='-DLIBCOV_ARCH_MIPS_ILLEGAL=0x00000038u'

produces `build/baremetal-mips/libcov_core.{elf,bin}`: a freestanding, no-libc,
fully self-contained blob (`nm` shows zero undefined symbols).

## What is shared vs. what is per-platform

The OS-neutral core is reused verbatim from the Linux build: `src/arch_mips.c`
+ `src/arch_mips_emulate.h` (ISA decode / marker emulation), `src/sink.h` (the
edge-emit math), `src/patchlist_format.h` (the LCV3 wire format) and
`src/tunables.h` (coverage model + map sizing). The platform seam is
`src/plat.h`: exactly one `plat_<name>.c` per build provides the trap frame,
code write + I-cache sync, the coverage region, module base, logging and timing.

- `src/plat_linux.c` — Linux userland (sigaction, mprotect, shm, /proc/maps).
- `src/plat_baremetal_mips.c` + `src/plat_baremetal_mips_vector.S` — baremetal
  MIPS32: an exception-vector trampoline filters Reserved-Instruction traps and
  calls the shared dispatcher; `plat_code_sync` does `synci`/`sync` cache
  maintenance; the coverage bitmap lives in a free-RAM arena.
- `src/core_bm.c` — the freestanding assembly of the coverage core for a target
  with no OS: an in-memory LCV3 parser, the patch table + bsearch lookup, the
  trap dispatcher, `libcov_init`.

## The illegal encoding: kernel vs. user mode

The default MIPS trap encoding, `MFC0 $0,$0`, only raises Reserved Instruction
in **user** mode (it is a privileged-op fault). A baremetal image — and most
kernel-mode RTOSes — run in **kernel/supervisor** mode, where `MFC0` is
legal and would not trap. The baremetal build therefore overrides the encoding
with a word that is reserved in every mode on MIPS32:

    -DLIBCOV_ARCH_MIPS_ILLEGAL=0x00000038u   # DSLL: a 64-bit op, illegal on MIPS32

## Pointing it at a target

Override per target (defaults are generic placeholders):

| macro | meaning |
|---|---|
| `LIBCOV_BM_MODULE_LO/HI`   | address range of the instrumented code |
| `LIBCOV_BM_ARENA_LO/HI`    | free RAM for the coverage bitmap + scratch (must not overlap the OS, the code, or the libcov blob) |
| `LIBCOV_BM_EXC_VECTOR`     | general-exception vector (default `0x80000180`, BEV=0) |
| `LIBCOV_ARCH_MIPS_ILLEGAL` | trap encoding (use `0x00000038` for kernel-mode RI) |

Supply weak hooks (optional for logging; recommended for a real OS so non-RI
exceptions still reach the firmware's own handler):

    void libcov_bm_putc(char c);              /* board UART; logging is off the hot path */
    void libcov_bm_chain(libcov_frame *f);    /* hand a non-RI trap to the OS handler */

Build the patch list from your image's block entries with
`tools/gen_patchlist_baremetal.py` (ELF + symbols -> an LCV3 C array), bake the
array in (it exposes `libcov_bm_patchlist[]` / `libcov_bm_patchlist_len`), load
the blob into free RAM, and call `libcov_init()` once after the OS has installed
its own vectors. Read the bitmap back over a debug probe or the emulator's
gdbstub.

## Worked example

`test/run_validation_baremetal.sh` is a complete, self-contained example: it
builds the core plus a small instrumented app, boots it under stock
`qemu-system-mips -M malta` (big-endian 24Kc), and reads coverage back over the
QEMU gdbstub, asserting determinism and input differentiation. A real firmware image
(whose recon gives its RAM map and exception vector) is instrumented the same way — only the macros, the `putc`/`chain` hooks, and
the patch list change.
