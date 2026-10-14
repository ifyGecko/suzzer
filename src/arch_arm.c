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

uintptr_t libcov_arch_pc_from_frame(const libcov_frame *f) {
    return (uintptr_t)libcov_frame_uc(f)->uc_mcontext.arm_pc;
}

/* Condition field against CPSR.NZCV (same bit positions as AArch64). */
static int arm_cond(unsigned cond, uint32_t cpsr) {
    const int n = !!(cpsr & (1u << 31)), z = !!(cpsr & (1u << 30));
    const int c = !!(cpsr & (1u << 29)), v = !!(cpsr & (1u << 28));
    int r;
    switch (cond >> 1) {
    case 0:  r = z;                break;  /* EQ / NE */
    case 1:  r = c;                break;  /* CS / CC */
    case 2:  r = n;                break;  /* MI / PL */
    case 3:  r = v;                break;  /* VS / VC */
    case 4:  r = c && !z;          break;  /* HI / LS */
    case 5:  r = n == v;           break;  /* GE / LT */
    case 6:  r = !z && n == v;     break;  /* GT / LE */
    default: return 1;                     /* AL */
    }
    return (cond & 1) ? !r : r;
}

static int32_t sext(uint32_t v, unsigned bits) {
    uint32_t m = 1u << (bits - 1);
    return (int32_t)((v ^ m) - m);
}

/* Thumb ITSTATE, IT[7:0] = CPSR[15:10]:CPSR[26:25]. */
static unsigned it_get(uint32_t cpsr) {
    return (((cpsr >> 10) & 0x3F) << 2) | ((cpsr >> 25) & 3);
}

static uint32_t it_put(uint32_t cpsr, unsigned it) {
    cpsr &= ~((0x3Fu << 10) | (3u << 25));
    return cpsr | ((it >> 2) & 0x3F) << 10 | (it & 3) << 25;
}

/* Supported. ARM (len 4): B, BL, NOP. Thumb (len 2; the second halfword
 * of a 32-bit instruction is read from memory): B T1-T4, CBZ/CBNZ, BL,
 * NOP, NOP.W. BLX (state switch) is not. Inside an IT block the IT
 * condition is applied and ITSTATE advanced, as the CPU would. */
int libcov_arch_emulate(libcov_frame *f, uintptr_t addr,
                        const uint8_t *orig, uint8_t len) {
    uintptr_t next, target = 0;
    unsigned cond = 14;            /* AL */
    int kind;                      /* 0 skip, 1 b, 2 bl, 3 cbz, 4 cbnz */
    unsigned rn = 0;

    if (len == 4) {
        uint32_t i;
        memcpy(&i, orig, 4);
        next = addr + 4;
        cond = i >> 28;
        if (cond == 0xF) return 0;                     /* BLX imm, uncond space */
        if ((i & 0x0E000000u) == 0x0A000000u) {        /* B / BL */
            kind = (i >> 24) & 1 ? 2 : 1;
            target = addr + 8 + (uintptr_t)(sext(i & 0xFFFFFFu, 24) * 4);
        } else if ((i & 0x0FFFFFFFu) == 0x0320F000u) { /* NOP */
            kind = 0;
        } else {
            return 0;
        }
    } else if (len == 2) {
        uint16_t h1, h2;
        memcpy(&h1, orig, 2);
        if ((h1 >> 11) >= 0x1D) {                      /* 32-bit Thumb-2 */
            memcpy(&h2, (const uint8_t *)addr + 2, 2);
            next = addr + 4;
            uint32_t s = (h1 >> 10) & 1, j1 = (h2 >> 13) & 1, j2 = (h2 >> 11) & 1;
            if ((h1 & 0xF800) == 0xF000 && (h2 & 0xD000) == 0x8000) {
                cond = (h1 >> 6) & 0xF;                /* B.W T3 */
                if (cond >= 0xE) return 0;
                kind = 1;
                uint32_t imm = s << 20 | j2 << 19 | j1 << 18 |
                               (uint32_t)(h1 & 0x3F) << 12 | (uint32_t)(h2 & 0x7FF) << 1;
                target = addr + 4 + (uintptr_t)sext(imm, 21);
            } else if ((h1 & 0xF800) == 0xF000 && (h2 & 0x9000) == 0x9000) {
                kind = (h2 & 0x4000) ? 2 : 1;          /* BL T1 / B.W T4 */
                uint32_t i1 = !(j1 ^ s), i2 = !(j2 ^ s);
                uint32_t imm = s << 24 | i1 << 23 | i2 << 22 |
                               (uint32_t)(h1 & 0x3FF) << 12 | (uint32_t)(h2 & 0x7FF) << 1;
                target = addr + 4 + (uintptr_t)sext(imm, 25);
            } else if (h1 == 0xF3AF && h2 == 0x8000) { /* NOP.W */
                kind = 0;
            } else {
                return 0;
            }
        } else {
            next = addr + 2;
            if ((h1 & 0xF000) == 0xD000) {             /* B T1 */
                cond = (h1 >> 8) & 0xF;
                if (cond >= 0xE) return 0;             /* UDF / SVC */
                kind = 1;
                target = addr + 4 + (uintptr_t)(sext(h1 & 0xFF, 8) * 2);
            } else if ((h1 & 0xF800) == 0xE000) {      /* B T2 */
                kind = 1;
                target = addr + 4 + (uintptr_t)(sext(h1 & 0x7FF, 11) * 2);
            } else if ((h1 & 0xF500) == 0xB100) {      /* CBZ / CBNZ */
                kind = (h1 & 0x0800) ? 4 : 3;
                rn = h1 & 7;
                target = addr + 4 + ((((uintptr_t)h1 >> 9) & 1) << 6) +
                         ((((uintptr_t)h1 >> 3) & 0x1F) << 1);
            } else if (h1 == 0xBF00) {                 /* NOP */
                kind = 0;
            } else {
                return 0;
            }
        }
    } else {
        return 0;
    }
    if (!f) return 1;

    ucontext_t *uc = libcov_frame_uc(f);
    mcontext_t *m = &uc->uc_mcontext;
    uint32_t cpsr = (uint32_t)m->arm_cpsr;
    if (len == 2) {
        unsigned it = it_get(cpsr);
        if (it & 0xF) {
            int pass = arm_cond(it >> 4, cpsr);
            m->arm_cpsr = it_put(cpsr, (it & 7) ? ((it & 0xE0) | ((it << 1) & 0x1F)) : 0);
            if (!pass) { m->arm_pc = next; return 1; }
        }
    }
    int taken;
    switch (kind) {
    case 0:  taken = 0; break;
    case 1:  taken = arm_cond(cond, cpsr); break;
    case 2:
        taken = arm_cond(cond, cpsr);
        if (taken) m->arm_lr = len == 2 ? (next | 1) : next;
        break;
    default: {
        unsigned long rv = (&m->arm_r0)[rn];
        taken = (kind == 3) ? rv == 0 : rv != 0;
        break;
    }
    }
    m->arm_pc = taken ? target : next;
    return 1;
}
