/*
 * arch_mips.c -- MIPS32 backend (BE and LE; cross compiler picks).
 *
 * All tunable values (illegal encoding, instruction-width bounds) come
 * from src/tunables_mips.h -- edit there or pass -D flags.
 *
 * This backend was historically SIGTRAP-based (BREAK 0). It is now SIGILL
 * by default; the default illegal encoding is `MFC0 $0, $0` which the
 * Linux MIPS kernel rejects as a user-mode coprocessor-0 access via
 * SIGILL (ILL_PRVOPC). Works on every MIPS revision (r1..r6).
 *
 * Branch delay slots: NEVER patch the instruction after a branch. When a
 * trap fires in a delay slot the kernel reports the branch PC and sets
 * the BD cause bit, which would break our lookup. The generator avoids
 * delay slots by patching block-entry instructions.
 *
 * Fixed 4-byte instructions. PC in uc_mcontext.pc.
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"
#include "tunables_mips.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_MIPS_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_MIPS_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_MIPS_MAX_PATCH_LEN;

/* Pre-baked trap pattern in .rodata (see arch_x86_64.c). */
static const uint32_t k_illegal = LIBCOV_ARCH_MIPS_ILLEGAL;

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
