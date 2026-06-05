/*
 * arch_arm.c -- ARMv7 backend (ARM and Thumb).
 *
 * Two illegal encodings:
 *   ARM mode   (len=4): UDF (perm-undefined) = 0xE7F000F0
 *   Thumb mode (len=2): UDF.N                = 0xDE00
 *
 * The generator selects mode per patch site via the patch record's `len`
 * field (4 = ARM, 2 = Thumb). For 4-byte Thumb-2 instructions we still
 * only patch the first 2 bytes with UDF.N -- the kernel traps before the
 * back half of the original is decoded, and restore leaves the back half
 * intact.
 *
 * PC: uc_mcontext.arm_pc. CPSR T-bit tells us mode at the trap site but
 * isn't needed for our flow -- we look up the entry by PC and use its
 * stored `len` to drive restore.
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"

const char    *libcov_arch_name     = "arm";
const int      libcov_trap_signo    = SIGILL;
const uint8_t  libcov_min_patch_len = 2;
const uint8_t  libcov_max_patch_len = 4;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    if (len == 4) {
        /* ARM mode UDF. Encoded little-endian on standard armhf. */
        static const uint32_t arm_udf = 0xE7F000F0u;
        memcpy(dst, &arm_udf, 4);
    } else {
        /* Thumb UDF.N. */
        static const uint16_t thumb_udf = 0xDE00u;
        memcpy(dst, &thumb_udf, 2);
    }
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.arm_pc;
}
