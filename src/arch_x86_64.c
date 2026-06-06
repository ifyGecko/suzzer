/*
 * arch_x86_64.c -- x86_64 backend (ST and MT in one file).
 *
 * Threading models share one source. The MT-specific behaviour (head-only
 * UD2 write, no NOP padding) is selected by -DLIBCOV_THREADING_MT, which
 * the Makefile sets for `make THREADING=mt`.
 *
 * All tunable values (illegal bytes, NOP padding byte, instruction-width
 * bounds) come from src/tunables_x86_64.h -- edit there or pass -D flags.
 *
 * ST mode: UD2 (2 bytes) + (len-2) NOPs as padding. Original instruction
 *   length is 2..15. Trap fires on UD2; padding bytes are never executed.
 *
 * MT mode: UD2 only (2 bytes), no padding. A single naturally-aligned
 *   2-byte store is the largest write x86_64 guarantees is single-copy-
 *   atomic per Intel SDM Vol 3 Sec 8.1.1. Bytes 2..N of the original
 *   instruction are never touched: arm/disarm only rewrite the head, the
 *   trap fires before the tail is decoded, and disarm restores the head
 *   so the original instruction is intact.
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
#if defined(LIBCOV_THREADING_MT)
    /* Head-only write; tail bytes of the original instruction are untouched. */
    (void)len;
#else
    for (uint8_t i = 2; i < len; i++) p[i] = (unsigned char)LIBCOV_ARCH_X86_64_NOP_BYTE;
#endif
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
}
