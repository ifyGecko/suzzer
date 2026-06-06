/*
 * arch_mips64.c -- MIPS64 backend.
 *
 * All tunable values come from src/tunables_mips64.h -- edit there or
 * pass -D flags. Encoding-wise this mirrors MIPS32; only the ucontext
 * layout differs (the glibc field name happens to be the same here).
 *
 * Historically SIGTRAP (BREAK 0); now SIGILL by default via user-mode
 * MFC0 -- see tunables_mips64.h.
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"
#include "tunables_mips64.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_MIPS64_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_MIPS64_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_MIPS64_MAX_PATCH_LEN;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;
    const uint32_t illegal = LIBCOV_ARCH_MIPS64_ILLEGAL;
    memcpy(dst, &illegal, 4);
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.pc;
}
