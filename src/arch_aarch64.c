/*
 * arch_aarch64.c -- aarch64 backend.
 *
 * All tunable values (illegal encoding, instruction-width bounds) come
 * from src/tunables_aarch64.h -- edit there or pass -D flags. Fixed
 * 4-byte instruction width on aarch64.
 */
#define _GNU_SOURCE
#include <string.h>
#include "arch.h"
#include "tunables_aarch64.h"

const char    *libcov_arch_name     = LIBCOV_ARCH_AARCH64_NAME;
const uint8_t  libcov_min_patch_len = LIBCOV_ARCH_AARCH64_MIN_PATCH_LEN;
const uint8_t  libcov_max_patch_len = LIBCOV_ARCH_AARCH64_MAX_PATCH_LEN;

/* Pre-baked trap pattern in .rodata (see arch_x86_64.c). */
static const uint32_t k_illegal = LIBCOV_ARCH_AARCH64_ILLEGAL;

void libcov_arch_write_illegal(void *dst, uint8_t len) {
    (void)len;  /* always 4 for aarch64 */
    memcpy(dst, &k_illegal, 4);
}

const void *libcov_arch_illegal_bytes(uint8_t len) {
    (void)len;
    return &k_illegal;
}

uintptr_t libcov_arch_pc_from_frame(const libcov_frame *f) {
    return (uintptr_t)libcov_frame_uc(f)->uc_mcontext.pc;
}

/* Condition field of B.cond against PSTATE.NZCV. */
static int a64_cond(unsigned cond, uint64_t pstate) {
    const int n = !!(pstate & (1ull << 31)), z = !!(pstate & (1ull << 30));
    const int c = !!(pstate & (1ull << 29)), v = !!(pstate & (1ull << 28));
    int r;
    switch (cond >> 1) {
    case 0:  r = z;                break;  /* EQ / NE */
    case 1:  r = c;                break;  /* CS / CC */
    case 2:  r = n;                break;  /* MI / PL */
    case 3:  r = v;                break;  /* VS / VC */
    case 4:  r = c && !z;          break;  /* HI / LS */
    case 5:  r = n == v;           break;  /* GE / LT */
    case 6:  r = !z && n == v;     break;  /* GT / LE */
    default: return 1;                     /* AL / NV: always */
    }
    return (cond & 1) ? !r : r;
}

static int64_t sext(uint64_t v, unsigned bits) {
    uint64_t m = 1ull << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

/* Supported: B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, NOP, BTI. */
int libcov_arch_emulate(libcov_frame *f, uintptr_t addr,
                        const uint8_t *orig, uint8_t len) {
    if (len != 4) return 0;
    uint32_t i;
    memcpy(&i, orig, 4);
    uintptr_t next = addr + 4, target = next;
    int kind;                      /* 0 skip, 1 b, 2 bl, 3 b.cond, 4 cb, 5 tb */

    if ((i & 0x7C000000u) == 0x14000000u) {            /* B / BL */
        kind = (i >> 31) ? 2 : 1;
        target = addr + (uintptr_t)(sext(i & 0x3FFFFFFu, 26) * 4);
    } else if ((i & 0xFF000010u) == 0x54000000u) {     /* B.cond */
        kind = 3;
        target = addr + (uintptr_t)(sext((i >> 5) & 0x7FFFFu, 19) * 4);
    } else if ((i & 0x7E000000u) == 0x34000000u) {     /* CBZ / CBNZ */
        kind = 4;
        target = addr + (uintptr_t)(sext((i >> 5) & 0x7FFFFu, 19) * 4);
    } else if ((i & 0x7E000000u) == 0x36000000u) {     /* TBZ / TBNZ */
        kind = 5;
        target = addr + (uintptr_t)(sext((i >> 5) & 0x3FFFu, 14) * 4);
    } else if (i == 0xD503201Fu || (i & 0xFFFFFF3Fu) == 0xD503241Fu) {
        kind = 0;                                      /* NOP / BTI */
    } else {
        return 0;
    }
    if (!f) return 1;

    ucontext_t *uc = libcov_frame_uc(f);
    mcontext_t *m = &uc->uc_mcontext;
    unsigned rt = i & 0x1F;
    uint64_t rv = (rt == 31) ? 0 : m->regs[rt];        /* 31 = xzr here */
    int taken;
    switch (kind) {
    case 0:  taken = 0; break;
    case 1:  taken = 1; break;
    case 2:  taken = 1; m->regs[30] = next; break;
    case 3:  taken = a64_cond(i & 0xF, m->pstate); break;
    case 4:
        if (!(i >> 31)) rv &= 0xFFFFFFFFu;             /* 32-bit form */
        taken = ((i >> 24) & 1) ? rv != 0 : rv == 0;
        break;
    default: {
        unsigned bit = ((i >> 31) << 5) | ((i >> 19) & 0x1F);
        int set = (rv >> bit) & 1;
        taken = ((i >> 24) & 1) ? set : !set;
        break;
    }
    }
    m->pc = taken ? target : next;
    return 1;
}
