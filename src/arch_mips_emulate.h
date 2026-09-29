/*
 * arch_mips_emulate.h -- marker emulation shared by arch_mips.c (o32) and
 * arch_mips64.c (n64).
 *
 * MIPS markers sit on block ENTRY instructions (gen_boundary/gen_patchlist
 * use the entry strategy there, because of delay slots), so a marker is
 * never a branch: it is almost always a function-prologue instruction --
 * `lui gp,..`, `addiu sp,sp,-N`, `daddiu sp,sp,-N`, `move`, a nop. Those
 * only write a general register, so emulating them is exact. Supported:
 *
 *   LUI, ADDIU, ORI, ANDI, XORI                        (both)
 *   SPECIAL: SLL (incl. nop/ssnop/ehb), ADDU, SUBU,
 *            AND, OR (move), XOR, NOR                  (both)
 *   DADDIU, DADDU, DSUBU                                (mips64 only)
 *
 * Anything else -- branches, jumps, loads/stores, trapping ADD/ADDI,
 * HI/LO users -- returns 0 and the marker uses the disarm + re-arm
 * fallback. A marker is never in a delay slot (it is a block entry); were
 * it one, the kernel would report the branch's PC and the trap would not
 * be looked up as this marker at all.
 *
 * Register slots are 64-bit in both ABIs' mcontext (greg_t). 32-bit
 * results are stored sign-extended, which is what a 64-bit kernel running
 * o32 code expects and what a 32-bit kernel truncates back losslessly.
 */
#ifndef LIBCOV_ARCH_MIPS_EMULATE_H
#define LIBCOV_ARCH_MIPS_EMULATE_H

#include <stdint.h>
#include <string.h>

static inline uint64_t mips_sext32(uint32_t v) {
    return (uint64_t)(int64_t)(int32_t)v;
}

/* With gregs == NULL: 1 if `orig` is an instruction we emulate. Otherwise
 * perform it on gregs/pc and return 1. The word is read in memory order,
 * i.e. the target's own byte order (mips BE, mipsel LE). */
static inline int mips_emulate(unsigned long long *gregs, unsigned long long *pc,
                               const uint8_t *orig, uint8_t len, int is64) {
    if (len != 4) return 0;
    uint32_t i;
    memcpy(&i, orig, 4);
    unsigned op = i >> 26, rs = (i >> 21) & 31, rt = (i >> 16) & 31;
    unsigned rd = (i >> 11) & 31, sa = (i >> 6) & 31, fn = i & 63;
    uint32_t imm = i & 0xffffu;
    uint64_t simm = (uint64_t)(int64_t)(int16_t)imm;

    unsigned dst;
    uint64_t v = 0;
    uint64_t a = gregs ? gregs[rs] : 0, b = gregs ? gregs[rt] : 0;
    switch (op) {
    case 0x0f: if (rs) return 0;                     /* LUI (r6: AUI rs=0) */
               dst = rt; v = mips_sext32(imm << 16); break;
    case 0x09: dst = rt; v = mips_sext32((uint32_t)a + (uint32_t)simm); break; /* ADDIU */
    case 0x19: if (!is64) return 0;                  /* DADDIU */
               dst = rt; v = a + simm; break;
    case 0x0d: dst = rt; v = a | imm; break;         /* ORI */
    case 0x0c: dst = rt; v = a & imm; break;         /* ANDI */
    case 0x0e: dst = rt; v = a ^ imm; break;         /* XORI */
    case 0x00:                                       /* SPECIAL */
        dst = rd;
        switch (fn) {
        case 0x00: if (rs) return 0;                 /* SLL (nop, ssnop, ehb) */
                   v = mips_sext32((uint32_t)b << sa); break;
        case 0x21: if (sa) return 0; v = mips_sext32((uint32_t)a + (uint32_t)b); break; /* ADDU */
        case 0x23: if (sa) return 0; v = mips_sext32((uint32_t)a - (uint32_t)b); break; /* SUBU */
        case 0x24: if (sa) return 0; v = a & b; break;          /* AND */
        case 0x25: if (sa) return 0; v = a | b; break;          /* OR / move */
        case 0x26: if (sa) return 0; v = a ^ b; break;          /* XOR */
        case 0x27: if (sa) return 0; v = ~(a | b); break;       /* NOR */
        case 0x2d: if (sa || !is64) return 0; v = a + b; break; /* DADDU */
        case 0x2f: if (sa || !is64) return 0; v = a - b; break; /* DSUBU */
        default:   return 0;
        }
        break;
    default:
        return 0;
    }
    if (!gregs) return 1;
    if (dst) gregs[dst] = v;                         /* $zero stays zero */
    *pc += 4;
    return 1;
}

#endif
