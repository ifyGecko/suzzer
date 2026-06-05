/*
 * arch_powerpc.c -- PowerPC 32-bit BE backend.
 *
 * Trap: tw 31, 0, 0  (encoding 0x7FE00008). Unconditional trap. Raises
 *       SIGTRAP -- the same rationale as MIPS: SIGILL would require us to
 *       pick a reserved-opcode encoding that depends on the chip
 *       revision, while TW is universal across all 32/64-bit POWER
 *       variants and SIGTRAP is just as unused by application code.
 *
 * Fixed 4-byte instructions. PC via uc_mcontext.uc_regs->gregs[PT_NIP].
 */
#define _GNU_SOURCE
#include <string.h>
#include <asm/ptrace.h>   /* PT_NIP */
#include "arch.h"

const char    *libcov_arch_name     = "powerpc";
const int      libcov_trap_signo    = SIGTRAP;
const uint8_t  libcov_min_patch_len = 4;
const uint8_t  libcov_max_patch_len = 4;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;
    static const uint32_t tw = 0x7FE00008u;  /* tw 31, 0, 0 */
    memcpy(dst, &tw, 4);
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.uc_regs->gregs[PT_NIP];
}
