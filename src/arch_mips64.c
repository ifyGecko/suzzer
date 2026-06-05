/*
 * arch_mips64.c -- MIPS64 backend.
 * Same trap encoding as MIPS32 (BREAK 0, SIGTRAP); the ucontext layout is
 * compatible at the field-name level on glibc.
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"

const char    *libcov_arch_name     = "mips64";
const int      libcov_trap_signo    = SIGTRAP;
const uint8_t  libcov_min_patch_len = 4;
const uint8_t  libcov_max_patch_len = 4;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;
    static const uint32_t brk = 0x0000000Du;
    memcpy(dst, &brk, 4);
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.pc;
}
