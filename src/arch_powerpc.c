/*
 * arch_powerpc.c -- PowerPC 32-bit BE backend.
 *
 * All tunable values come from src/tunables_powerpc.h -- edit there or
 * pass -D flags.
 *
 * Historically SIGTRAP-based (`tw 31,0,0` = 0x7FE00008). Now SIGILL by
 * default via the all-zero word, which PowerISA reserves as illegal
 * across every variant; Linux delivers SIGILL.
 *
 * Fixed 4-byte instructions. PC via uc_mcontext.uc_regs->gregs[PT_NIP].
 */
#define _GNU_SOURCE
#include <string.h>
#include <asm/ptrace.h>   /* PT_NIP */
#include "arch.h"
#include "tunables_powerpc.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_PPC_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_PPC_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_PPC_MAX_PATCH_LEN;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;
    const uint32_t illegal = LIBCOV_ARCH_PPC_ILLEGAL;
    memcpy(dst, &illegal, 4);
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.uc_regs->gregs[PT_NIP];
}
