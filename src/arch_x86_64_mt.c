/*
 * arch_x86_64_mt.c -- x86_64 backend, MT variant.
 *
 * Identical to arch_x86_64.c except for the patch width: we only ever
 * write the 2-byte UD2 (0F 0B) and never the NOP padding that the ST
 * variant uses for variable-length instructions.
 *
 * Why head-only:
 *  - A single naturally-aligned 2-byte store is the largest write the x86
 *    architecture guarantees is single-copy-atomic (Intel SDM Vol 3
 *    Sec 8.1.1). Two separate 1-byte writes for UD2+NOPs are not atomic;
 *    a peer CPU could fetch a partial sequence and execute garbage.
 *  - Bytes 2..N of the original instruction are never touched by arm or
 *    disarm. The trap fires on the first 2 bytes (UD2) before the back
 *    half is decoded, so the unchanged tail is irrelevant.
 *  - On disarm we write back only the first 2 bytes of orig. The tail
 *    bytes are still the original instruction bytes (we never wrote them
 *    in the first place), so the full original instruction is intact.
 *
 * Consequence for the generator: --threading mt for x86 must emit
 * records with len=2 (orig truncated to first 2 bytes). The runtime
 * refuses any record with len != 2 via min_patch_len/max_patch_len.
 *
 * Atomicity assumption: the 2-byte UD2 write must fit within a single
 * cache line. Intel does not guarantee atomicity for a 2-byte access that
 * straddles a cache-line boundary. The generator's --threading mt mode
 * skips any candidate site at addr where (addr & 63) == 63 to enforce
 * this.
 */
#define _GNU_SOURCE
#include "arch.h"

const char    *libcov_arch_name     = "x86_64";
const int      libcov_trap_signo    = SIGILL;
const uint8_t  libcov_min_patch_len = 2;
const uint8_t  libcov_max_patch_len = 2;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;  /* always 2 for x86_64 MT */
    unsigned char *p = (unsigned char *)dst;
    p[0] = 0x0F;
    p[1] = 0x0B;
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
}
