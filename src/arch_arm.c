/*
 * arch_arm.c -- ARMv7 backend (ARM + Thumb).
 *
 * All tunable values (illegal encodings for ARM and Thumb, width bounds)
 * come from src/tunables_arm.h -- edit there or pass -D flags.
 *
 * Per-site mode selection: the generator records len=4 for ARM-mode
 * sites and len=2 for Thumb sites. The runtime picks the encoding from
 * len at arm time. For 4-byte Thumb-2 instructions we patch only the
 * first 2 bytes with the Thumb UDF -- the kernel traps before the back
 * half is decoded, and restore leaves the back half intact.
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"
#include "tunables_arm.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_ARM_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_ARM_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_ARM_MAX_PATCH_LEN;

/* Pre-baked trap patterns in .rodata. ARM mode = 4 bytes, Thumb = 2.
 * libcov_arch_illegal_bytes() dispatches on len. */
static const uint32_t k_illegal_arm   = LIBCOV_ARCH_ARM_ILLEGAL_ARM;
static const uint16_t k_illegal_thumb = LIBCOV_ARCH_ARM_ILLEGAL_THUMB;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    if (len == 4) {
        memcpy(dst, &k_illegal_arm, 4);
    } else {
        memcpy(dst, &k_illegal_thumb, 2);
    }
}

const void *libcov_arch_illegal_bytes(uint8_t len) {
    return (len == 4) ? (const void *)&k_illegal_arm
                      : (const void *)&k_illegal_thumb;
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.arm_pc;
}

/* Marker emulation not implemented for this backend: markers use the
 * disarm + deferred re-arm protocol (see arch.h). */
int libcov_arch_emulate(ucontext_t *uc, uintptr_t addr,
                        const uint8_t *orig, uint8_t len) {
    (void)uc; (void)addr; (void)orig; (void)len;
    return 0;
}
