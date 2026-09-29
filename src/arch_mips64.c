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
#include "arch_mips_emulate.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_MIPS64_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_MIPS64_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_MIPS64_MAX_PATCH_LEN;

/* Pre-baked trap pattern in .rodata (see arch_x86_64.c). */
static const uint32_t k_illegal = LIBCOV_ARCH_MIPS64_ILLEGAL;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;
    memcpy(dst, &k_illegal, 4);
}

const void *libcov_arch_illegal_bytes(uint8_t len) {
    (void)len;
    return &k_illegal;
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.pc;
}

/* Marker emulation: markers are block-entry (prologue) instructions on
 * MIPS, never branches; arch_mips_emulate.h performs the register-only
 * ones. Others fall back to disarm + deferred re-arm (see arch.h). */
int libcov_arch_emulate(ucontext_t *uc, uintptr_t addr,
                        const uint8_t *orig, uint8_t len) {
    (void)addr;
    if (!uc) return mips_emulate(NULL, NULL, orig, len, 1);
    return mips_emulate(uc->uc_mcontext.gregs, &uc->uc_mcontext.pc, orig, len, 1);
}
