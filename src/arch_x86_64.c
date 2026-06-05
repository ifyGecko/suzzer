/*
 * arch_x86_64.c -- x86_64 backend.
 * Illegal: UD2 (0F 0B), 2 bytes. PC in REG_RIP.
 * Variable-length insns: original len is 2..15; we write UD2 + NOP padding.
 */
#define _GNU_SOURCE
#include "arch.h"

const char    *libcov_arch_name     = "x86_64";
const int      libcov_trap_signo    = SIGILL;
const uint8_t  libcov_min_patch_len = 2;
const uint8_t  libcov_max_patch_len = 15;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    unsigned char *p = (unsigned char *)dst;
    p[0] = 0x0F;
    p[1] = 0x0B;
    for (uint8_t i = 2; i < len; i++) p[i] = 0x90;  /* NOP padding */
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
}
