/*
 * arch.h -- backend interface. Exactly one src/arch_<NAME>.c file is linked
 * into a given libcov.so build. Each backend provides the symbols and
 * functions declared below.
 *
 * Trap signal: every backend uses LIBCOV_TRAP_SIGNO (default SIGILL) -- see
 * src/tunables.h. The illegal-instruction encoding each backend writes is
 * specified in src/tunables_<arch>.h (also user-overridable). To switch
 * the whole project to a different signal (e.g. SIGTRAP) you change
 * LIBCOV_TRAP_SIGNO and the per-arch ILLEGAL encodings together so they
 * agree.
 */
#ifndef LIBCOV_ARCH_H
#define LIBCOV_ARCH_H

#include <stdint.h>
#include <stddef.h>
#include "plat.h"   /* libcov_frame -- the platform's view of trapped state */

extern const char    *libcov_arch_name;
extern const uint8_t  libcov_min_patch_len;  /* smallest patchable insn (bytes) */
extern const uint8_t  libcov_max_patch_len;  /* largest patchable insn (bytes) */

/* Write `len` bytes of trap-raising sequence to dst.
 *  - Fixed-length-insn archs: len must equal the natural insn width
 *    (2 for THUMB, 4 for ARM/AArch64/MIPS/PPC/RISC-V), and the function
 *    writes exactly one trap instruction.
 *  - x86_64: len is always 2. The function writes the 2-byte UD2 head;
 *    the rest of the original instruction is never touched.
 *  - RISC-V mixed C/regular: len=2 writes c.unimp (0x0000); len=4 writes
 *    two c.unimps (= 4-byte 0x00000000), which is also illegal. */
void libcov_arch_write_illegal(void *dst, uint8_t len);

/* Return a pointer to a static-const buffer holding the trap-raising
 * sequence for `len` bytes. The buffer is at least `len` bytes long.
 * Used by patch_mt.c (its atomic store reads the encoding straight from
 * .rodata instead of staging it via libcov_arch_write_illegal() on every
 * arm/disarm) and by libcov.c's init-time trap self-test. */
const void *libcov_arch_illegal_bytes(uint8_t len);

/* PC of the trapped instruction (faulting address), read from the frame. */
uintptr_t libcov_arch_pc_from_frame(const libcov_frame *f);

/* Execute a boundary marker's original instruction in software.
 *
 * `addr` is the patched site, `orig`/`len` its saved original bytes. Any
 * bytes of the instruction beyond `len` are read from `addr` itself (x86
 * patches only a 2-byte head; the tail is never modified).
 *
 * With f == NULL: return 1 if the instruction is one this backend can
 * emulate, else 0 (called at init to decide per marker). With f != NULL:
 * perform it on the trapped context -- update the PC (and any register
 * the instruction writes) -- and return 1.
 *
 * Only instructions whose whole effect is on the PC and general registers
 * are supported: branches and NOP-like hints, and on MIPS (whose markers
 * are block-entry prologue instructions, never branches) register-only
 * ALU ops such as lui/addiu. No memory access. A marker that can be
 * emulated is never disarmed, so a peer
 * thread can never pass it untrapped (see boundary.c). Backends without
 * support return 0 and markers fall back to disarm + deferred re-arm. */
int libcov_arch_emulate(libcov_frame *f, uintptr_t addr,
                        const uint8_t *orig, uint8_t len);

#endif
