/*
 * arch_powerpc64.c -- PowerPC 64-bit backend (BE and LE; toolchain picks).
 *
 * All tunable values come from src/tunables_powerpc64.h -- edit there or
 * pass -D flags. Encoding-wise this mirrors PPC32; only the ucontext
 * layout differs: PC lives at uc_mcontext.gp_regs[PT_NIP].
 *
 * Historically SIGTRAP (`tw 31,0,0`); now SIGILL by default via all-zero.
 */
#define _GNU_SOURCE
#include <string.h>
#include <asm/ptrace.h>   /* PT_NIP */
#include "arch.h"
#include "arch_ppc_emulate.h"
#include "tunables_powerpc64.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_PPC64_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_PPC64_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_PPC64_MAX_PATCH_LEN;

/* Pre-baked trap pattern in .rodata (see arch_x86_64.c). */
static const uint32_t k_illegal = LIBCOV_ARCH_PPC64_ILLEGAL;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;
    memcpy(dst, &k_illegal, 4);
}

const void *libcov_arch_illegal_bytes(uint8_t len) {
    (void)len;
    return &k_illegal;
}

uintptr_t libcov_arch_pc_from_frame(const libcov_frame *f) {
    return (uintptr_t)libcov_frame_uc(f)->uc_mcontext.gp_regs[PT_NIP];
}

/* See arch_ppc_emulate.h for the supported forms. */
int libcov_arch_emulate(libcov_frame *f, uintptr_t addr,
                        const uint8_t *orig, uint8_t len) {
    if (!f) return ppc_emulate(NULL, addr, orig, len);
    ucontext_t *uc = libcov_frame_uc(f);
    unsigned long *g = (unsigned long *)uc->uc_mcontext.gp_regs;
    struct ppc_regs r = { &g[PT_NIP], &g[PT_LNK], &g[PT_CTR], &g[PT_CCR] };
    return ppc_emulate(&r, addr, orig, len);
}
