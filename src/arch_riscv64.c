/*
 * arch_riscv64.c -- RISC-V 64-bit backend.
 *
 * Illegal: c.unimp = 0x0000 (2-byte compressed all-zero instruction,
 *          permanently illegal per the RVC spec).
 *
 * RISC-V has mixed 2-byte (C extension) and 4-byte instructions. For a
 * 4-byte patch site we write 0x00000000 (two c.unimps); the first traps
 * immediately, the second is never decoded. Restore puts the original
 * 4 bytes back.
 *
 * PC: uc_mcontext.__gregs[REG_PC].
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"

const char    *libcov_arch_name     = "riscv64";
const int      libcov_trap_signo    = SIGILL;
const uint8_t  libcov_min_patch_len = 2;
const uint8_t  libcov_max_patch_len = 4;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    if (len == 2) {
        static const uint16_t cunimp = 0x0000u;
        memcpy(dst, &cunimp, 2);
    } else {
        static const uint32_t z = 0x00000000u;  /* two c.unimps back-to-back */
        memcpy(dst, &z, 4);
    }
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.__gregs[REG_PC];
}
