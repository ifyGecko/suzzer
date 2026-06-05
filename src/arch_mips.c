/*
 * arch_mips.c -- MIPS32 backend (BE and LE; the cross compiler picks).
 *
 * Trap: BREAK 0 instruction, 0x0000000D. Universal across MIPS r1..r6.
 *       Raises SIGTRAP (TRAP_BRKPT). We use SIGTRAP -- the original libcov
 *       design called for SIGILL, but on MIPS the only universally
 *       reliable user-mode-triggerable trap encoding is BREAK; SIGTRAP is
 *       just as unused by normal application code.
 *
 * Branch delay slots: NEVER patch the instruction after a branch (the
 * delay slot). When a trap fires in a delay slot the kernel reports the
 * branch PC and sets the BD cause bit, which would break our lookup. The
 * generator avoids delay slots by patching block-entry instructions, which
 * are never delay slots.
 *
 * Fixed 4-byte instructions. PC in uc_mcontext.pc.
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"

const char    *libcov_arch_name     = "mips";
const int      libcov_trap_signo    = SIGTRAP;
const uint8_t  libcov_min_patch_len = 4;
const uint8_t  libcov_max_patch_len = 4;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;
    static const uint32_t brk = 0x0000000Du;  /* BREAK 0 */
    memcpy(dst, &brk, 4);
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.pc;
}
