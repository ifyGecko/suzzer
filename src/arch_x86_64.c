/*
 * arch_x86_64.c -- x86_64 backend (ST and MT in one file).
 *
 * Head-only UD2 (2 bytes) for both threading models. Bytes 2..N of the
 * original instruction are never touched: the trap fires at UD2 before
 * the tail is decoded, and disarm restores the 2-byte head so the
 * original instruction is intact when execution resumes.
 *
 * In MT this is also what satisfies the single-copy-atomic store
 * contract (Intel SDM Vol 3 Sec 8.1.1): a 2-byte store is atomic when
 * aligned or, P6 onward, when it doesn't cross a cache line. patch_mt.c
 * and the generator's --threading mt mode accept any site whose 2 bytes
 * stay within one 64-byte line.
 *
 * All tunable values come from src/tunables_x86_64.h -- edit there or
 * pass -D flags.
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"
#include "tunables_x86_64.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_X86_64_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_X86_64_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_X86_64_MAX_PATCH_LEN;

/* Pre-baked trap pattern in .rodata. patch_mt.c stores it straight from
 * here (libcov_arch_illegal_bytes); ST and the init self-test use it
 * too. */
static const unsigned char k_illegal[2] = {
    (unsigned char)LIBCOV_ARCH_X86_64_ILLEGAL_BYTE0,
    (unsigned char)LIBCOV_ARCH_X86_64_ILLEGAL_BYTE1,
};

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    unsigned char *p = (unsigned char *)dst;
    p[0] = k_illegal[0];
    p[1] = k_illegal[1];
    (void)len; /* always 2; len is in the patch_entry for symmetry with other arches */
}

const void *libcov_arch_illegal_bytes(uint8_t len) {
    (void)len;
    return k_illegal;
}

uintptr_t libcov_arch_pc_from_uctx(const ucontext_t *uc) {
    return (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
}

/* Condition code cc (low nibble of Jcc) against RFLAGS. Even codes are
 * the condition, odd codes its negation. */
static int x86_cond(unsigned cc, uint64_t fl) {
    const int cf = !!(fl & 0x001), pf = !!(fl & 0x004), zf = !!(fl & 0x040);
    const int sf = !!(fl & 0x080), of = !!(fl & 0x800);
    int r;
    switch (cc >> 1) {
    case 0:  r = of;                   break;  /* O  / NO */
    case 1:  r = cf;                   break;  /* B  / AE */
    case 2:  r = zf;                   break;  /* E  / NE */
    case 3:  r = cf || zf;             break;  /* BE / A  */
    case 4:  r = sf;                   break;  /* S  / NS */
    case 5:  r = pf;                   break;  /* P  / NP */
    case 6:  r = sf != of;             break;  /* L  / GE */
    default: r = zf || (sf != of);     break;  /* LE / G  */
    }
    return (cc & 1) ? !r : r;
}

/* Supported: jmp rel8/rel32, jcc rel8/rel32, endbr64, 2-byte nop
 * (66 90). No prefixes. orig[0..1] is the patched head; the rest of the
 * instruction is read from memory. */
int libcov_arch_emulate(ucontext_t *uc, uintptr_t addr,
                        const uint8_t *orig, uint8_t len) {
    if (len < 2) return 0;
    const uint8_t *code = (const uint8_t *)addr;
    uint8_t b0 = orig[0], b1 = orig[1];
    uintptr_t next, target;
    int cc = -1;          /* -1: unconditional */
    int32_t rel;

    if (b0 == 0xEB) {                                  /* jmp rel8 */
        next = addr + 2; target = next + (int8_t)b1;
    } else if (b0 >= 0x70 && b0 <= 0x7F) {             /* jcc rel8 */
        cc = b0 & 0xF; next = addr + 2; target = next + (int8_t)b1;
    } else if (b0 == 0x0F && b1 >= 0x80 && b1 <= 0x8F) {  /* jcc rel32 */
        memcpy(&rel, code + 2, 4);
        cc = b1 & 0xF; next = addr + 6; target = next + rel;
    } else if (b0 == 0xE9) {                           /* jmp rel32 */
        uint8_t d[4] = { b1, code[2], code[3], code[4] };
        memcpy(&rel, d, 4);
        next = addr + 5; target = next + rel;
    } else if (b0 == 0xF3 && b1 == 0x0F && code[2] == 0x1E && code[3] == 0xFA) {
        next = target = addr + 4;                      /* endbr64 */
    } else if (b0 == 0x66 && b1 == 0x90) {
        next = target = addr + 2;                      /* 2-byte nop */
    } else {
        return 0;
    }
    if (!uc) return 1;
    greg_t *g = uc->uc_mcontext.gregs;
    int taken = cc < 0 || x86_cond((unsigned)cc, (uint64_t)g[REG_EFL]);
    g[REG_RIP] = (greg_t)(taken ? target : next);
    return 1;
}
