/*
 * arch_aarch64.c -- aarch64 backend.
 * Illegal: UDF #0 (all-zero 32-bit word). Permanently undefined per ARM ARM.
 * Fixed 4-byte instructions. PC in uc_mcontext.pc.
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"

const char    *libcov_arch_name     = "aarch64";
const int      libcov_trap_signo    = SIGILL;
const uint8_t  libcov_min_patch_len = 4;
const uint8_t  libcov_max_patch_len = 4;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;  /* always 4 for aarch64 */
    static const uint32_t illegal = 0x00000000u;  /* UDF #0 */
    memcpy(dst, &illegal, 4);
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.pc;
}
