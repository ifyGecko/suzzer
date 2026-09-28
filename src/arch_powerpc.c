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
#include "arch_ppc_emulate.h"
#include "tunables_powerpc.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_PPC_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_PPC_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_PPC_MAX_PATCH_LEN;

/* Pre-baked trap pattern in .rodata (see arch_x86_64.c). */
static const uint32_t k_illegal = LIBCOV_ARCH_PPC_ILLEGAL;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;
    memcpy(dst, &k_illegal, 4);
}

const void *libcov_arch_illegal_bytes(uint8_t len) {
    (void)len;
    return &k_illegal;
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.uc_regs->gregs[PT_NIP];
}

/* See arch_ppc_emulate.h for the supported forms. */
int libcov_arch_emulate(ucontext_t *uc, uintptr_t addr,
                        const uint8_t *orig, uint8_t len) {
    if (!uc) return ppc_emulate(NULL, addr, orig, len);
    unsigned long *g = (unsigned long *)uc->uc_mcontext.uc_regs->gregs;
    struct ppc_regs r = { &g[PT_NIP], &g[PT_LNK], &g[PT_CTR], &g[PT_CCR] };
    return ppc_emulate(&r, addr, orig, len);
}
