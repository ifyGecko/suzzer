/*
 * arch_x86_64.c -- x86_64 backend (ST and MT in one file).
 *
 * Head-only UD2 (2 bytes) for both threading models. Bytes 2..N of the
 * original instruction are never touched: the trap fires at UD2 before
 * the tail is decoded, and disarm restores the 2-byte head so the
 * original instruction is intact when execution resumes.
 *
 * In MT this is also the only encoding that satisfies the single-copy-
 * atomic store contract from Intel SDM Vol 3 Sec 8.1.1 -- a naturally
 * aligned 2-byte store is atomic; longer stores are not. The generator's
 * --threading mt mode also skips sites that would straddle a 64-byte
 * cache line, where even 2-byte atomicity is not architecturally
 * guaranteed.
 *
 * All tunable values come from src/tunables_x86_64.h -- edit there or
 * pass -D flags.
 */
#define _GNU_SOURCE
#include "arch.h"
#include "tunables_x86_64.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_X86_64_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_X86_64_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_X86_64_MAX_PATCH_LEN;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    unsigned char *p = (unsigned char *)dst;
    p[0] = (unsigned char)LIBCOV_ARCH_X86_64_ILLEGAL_BYTE0;
    p[1] = (unsigned char)LIBCOV_ARCH_X86_64_ILLEGAL_BYTE1;
    (void)len; /* always 2; len is in the patch_entry for symmetry with other arches */
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
}
