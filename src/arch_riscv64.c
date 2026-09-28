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

static int64_t sext(uint64_t v, unsigned bits) {
    uint64_t m = 1ull << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

/* Supported: JAL, JALR, BEQ/BNE/BLT/BGE/BLTU/BGEU, NOP, and the
 * compressed C.J, C.JR, C.JALR, C.BEQZ/C.BNEZ, C.NOP. MT patches only the
 * first 2 bytes of a 4-byte instruction (len 2); the upper half is then
 * read from memory. */
int libcov_arch_emulate(ucontext_t *uc, uintptr_t addr,
                        const uint8_t *orig, uint8_t len) {
    if (len != 2 && len != 4) return 0;
    uint16_t h1;
    memcpy(&h1, orig, 2);
    uintptr_t next, target = 0;
    int kind;              /* 0 skip, 1 jal, 2 jalr, 3 branch */
    unsigned rd = 0, rs1 = 0, rs2 = 0, f3 = 0;
    int64_t imm = 0;

    if ((h1 & 3) == 3) {                               /* 32-bit */
        uint16_t h2;
        memcpy(&h2, len == 4 ? orig + 2 : (const uint8_t *)addr + 2, 2);
        uint32_t i = (uint32_t)h1 | (uint32_t)h2 << 16;
        next = addr + 4;
        rd = (i >> 7) & 0x1F; rs1 = (i >> 15) & 0x1F; rs2 = (i >> 20) & 0x1F;
        f3 = (i >> 12) & 7;
        switch (i & 0x7F) {
        case 0x6F:                                     /* JAL */
            kind = 1;
            imm = sext((i >> 31) << 20 | ((i >> 12) & 0xFF) << 12 |
                       ((i >> 20) & 1) << 11 | ((i >> 21) & 0x3FF) << 1, 21);
            target = addr + (uintptr_t)imm;
            break;
        case 0x67:                                     /* JALR */
            if (f3 != 0) return 0;
            kind = 2;
            imm = sext(i >> 20, 12);
            break;
        case 0x63:                                     /* Bxx */
            if (f3 == 2 || f3 == 3) return 0;
            kind = 3;
            imm = sext((i >> 31) << 12 | ((i >> 7) & 1) << 11 |
                       ((i >> 25) & 0x3F) << 5 | ((i >> 8) & 0xF) << 1, 13);
            target = addr + (uintptr_t)imm;
            break;
        default:
            if (i != 0x00000013u) return 0;            /* NOP */
            kind = 0;
            break;
        }
    } else {                                           /* compressed */
        next = addr + 2;
        unsigned q = h1 & 3, f = h1 >> 13;
        if (q == 1 && f == 5) {                        /* C.J */
            kind = 1;
            imm = sext(((h1 >> 12) & 1) << 11 | ((h1 >> 11) & 1) << 4 |
                       ((h1 >> 9) & 3) << 8 | ((h1 >> 8) & 1) << 10 |
                       ((h1 >> 7) & 1) << 6 | ((h1 >> 6) & 1) << 7 |
                       ((h1 >> 3) & 7) << 1 | ((h1 >> 2) & 1) << 5, 12);
            target = addr + (uintptr_t)imm;
        } else if (q == 1 && (f == 6 || f == 7)) {     /* C.BEQZ / C.BNEZ */
            kind = 3;
            f3 = (f == 6) ? 0 : 1;                     /* as BEQ / BNE x0 */
            rs1 = 8 + ((h1 >> 7) & 7);
            imm = sext(((h1 >> 12) & 1) << 8 | ((h1 >> 10) & 3) << 3 |
                       ((h1 >> 5) & 3) << 6 | ((h1 >> 3) & 3) << 1 |
                       ((h1 >> 2) & 1) << 5, 9);
            target = addr + (uintptr_t)imm;
        } else if (q == 2 && (h1 >> 12) >= 8 && (h1 >> 12) <= 9 &&
                   ((h1 >> 2) & 0x1F) == 0 && ((h1 >> 7) & 0x1F) != 0) {
            kind = 2;                                  /* C.JR / C.JALR */
            rs1 = (h1 >> 7) & 0x1F;
            rd = ((h1 >> 12) & 1) ? 1 : 0;
        } else if (h1 == 0x0001) {                     /* C.NOP */
            kind = 0;
        } else {
            return 0;
        }
    }
    if (!uc) return 1;

    unsigned long *x = uc->uc_mcontext.__gregs;        /* x[0] is the PC */
#define XREG(n) ((n) ? x[(n)] : 0ul)
    uintptr_t pc = next;
    switch (kind) {
    case 0:
        break;
    case 1:
        if (rd) x[rd] = next;
        pc = target;
        break;
    case 2:
        pc = (XREG(rs1) + (uintptr_t)imm) & ~(uintptr_t)1;  /* before rd */
        if (rd) x[rd] = next;
        break;
    default: {
        unsigned long a = XREG(rs1), b = XREG(rs2);
        int taken;
        switch (f3) {
        case 0:  taken = a == b; break;
        case 1:  taken = a != b; break;
        case 4:  taken = (long)a <  (long)b; break;
        case 5:  taken = (long)a >= (long)b; break;
        case 6:  taken = a <  b; break;
        default: taken = a >= b; break;
        }
        if (taken) pc = target;
        break;
    }
    }
#undef XREG
    x[REG_PC] = pc;
    return 1;
}
