/*
 * arch_aarch64.c -- aarch64 backend.
 *
 * All tunable values (illegal encoding, instruction-width bounds) come
 * from src/tunables_aarch64.h -- edit there or pass -D flags. Fixed
 * 4-byte instruction width on aarch64.
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"
#include "tunables_aarch64.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_AARCH64_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_AARCH64_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_AARCH64_MAX_PATCH_LEN;

/* Pre-baked trap pattern in .rodata (see arch_x86_64.c). */
static const uint32_t k_illegal = LIBCOV_ARCH_AARCH64_ILLEGAL;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;  /* always 4 for aarch64 */
    memcpy(dst, &k_illegal, 4);
}

const void *libcov_arch_illegal_bytes(uint8_t len) {
    (void)len;
    return &k_illegal;
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.pc;
}
