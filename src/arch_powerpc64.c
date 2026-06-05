/*
 * arch_powerpc64.c -- PowerPC 64-bit backend (BE and LE; toolchain picks).
 *
 * Same trap encoding as ppc32 (tw 31,0,0 = 0x7FE00008, SIGTRAP).
 * Different ucontext layout: PC lives at uc_mcontext.gp_regs[PT_NIP].
 */
#define _GNU_SOURCE
#include <string.h>
#include <asm/ptrace.h>   /* PT_NIP */
#include "arch.h"

const char    *libcov_arch_name     = "powerpc64";
const int      libcov_trap_signo    = SIGTRAP;
const uint8_t  libcov_min_patch_len = 4;
const uint8_t  libcov_max_patch_len = 4;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;
    static const uint32_t tw = 0x7FE00008u;
    memcpy(dst, &tw, 4);
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.gp_regs[PT_NIP];
}
