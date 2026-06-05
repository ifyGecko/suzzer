/*
 * arch.h -- backend interface. Exactly one src/arch_<NAME>.c file is linked
 * into a given libcov.so build. Each backend provides the symbols and
 * functions declared below.
 *
 * Trap signal: most architectures use SIGILL via an undefined-instruction
 * encoding. MIPS and PowerPC use SIGTRAP via the BREAK / TW instructions
 * because those are the universally-portable "raise a trap" encodings on
 * those ISAs and SIGTRAP is just as unused by normal application code as
 * SIGILL is. The handler installs whichever signal the backend declares.
 */
#ifndef LIBCOV_ARCH_H
#define LIBCOV_ARCH_H

#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <ucontext.h>

extern const char    *libcov_arch_name;
extern const int      libcov_trap_signo;     /* SIGILL or SIGTRAP */
extern const uint8_t  libcov_min_patch_len;  /* smallest patchable insn (bytes) */
extern const uint8_t  libcov_max_patch_len;  /* largest patchable insn (bytes) */

/* Write `len` bytes of trap-raising sequence to dst.
 *  - Fixed-length-insn archs: len must equal the natural insn width
 *    (2 for THUMB, 4 for ARM/AArch64/MIPS/PPC/RISC-V), and the function
 *    writes exactly one trap instruction.
 *  - x86_64: len is the original instruction length (2..15). The function
 *    writes a 2-byte UD2 followed by single-byte NOPs as padding.
 *  - RISC-V mixed C/regular: len=2 writes c.unimp (0x0000); len=4 writes
 *    two c.unimps (= 4-byte 0x00000000), which is also illegal. */
void libcov_arch_write_illegal(void *dst, uint8_t len);

/* PC of the trapped instruction (faulting address). */
uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc);

#endif
