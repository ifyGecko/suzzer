/*
 * arch_riscv64.c -- RISC-V 64-bit backend.
 *
 * All tunable values come from src/tunables_riscv64.h -- edit there or
 * pass -D flags.
 *
 * RISC-V mixes 2-byte (C extension) and 4-byte instructions. For a
 * 4-byte patch site we write two c.unimps back-to-back (32 bits of
 * zero); the first traps immediately, the second is never decoded.
 *
 * PC: uc_mcontext.__gregs[REG_PC].
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"
#include "tunables_riscv64.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_RISCV64_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_RISCV64_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_RISCV64_MAX_PATCH_LEN;

/* Pre-baked trap patterns in .rodata. RVC (compressed) sites = 2 bytes,
 * 4-byte sites get two back-to-back c.unimps. */
static const uint16_t k_illegal_c = LIBCOV_ARCH_RISCV64_ILLEGAL_C;
static const uint32_t k_illegal_w = LIBCOV_ARCH_RISCV64_ILLEGAL_W;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    if (len == 2) {
        memcpy(dst, &k_illegal_c, 2);
    } else {
        memcpy(dst, &k_illegal_w, 4);
    }
}

const void *libcov_arch_illegal_bytes(uint8_t len) {
    return (len == 2) ? (const void *)&k_illegal_c
                      : (const void *)&k_illegal_w;
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.__gregs[REG_PC];
}
