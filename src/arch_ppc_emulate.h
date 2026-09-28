/*
 * arch_ppc_emulate.h -- marker emulation shared by arch_powerpc.c and
 * arch_powerpc64.c. The two differ only in where the ucontext keeps
 * NIP/LR/CTR/CR, so each backend passes pointers to those slots.
 *
 * Supported: b/ba/bl/bla, bc (CR-bit and CTR forms, CTR is decremented),
 * bclr and bcctr (blr, bctr and their conditional/linking forms), nop.
 */
#ifndef LIBCOV_ARCH_PPC_EMULATE_H
#define LIBCOV_ARCH_PPC_EMULATE_H

#include <stdint.h>
#include <string.h>

struct ppc_regs {
    unsigned long *nip, *lr, *ctr, *cr;
};

static inline long ppc_sext(unsigned long v, unsigned bits) {
    unsigned long m = 1ul << (bits - 1);
    return (long)((v ^ m) - m);
}

/* With r == NULL: 1 if `orig` is an instruction we emulate. Otherwise
 * perform it on r and return 1. The word is read in memory order, which
 * is the target's own byte order (BE or LE). */
static inline int ppc_emulate(const struct ppc_regs *r, uintptr_t addr,
                              const uint8_t *orig, uint8_t len) {
    if (len != 4) return 0;
    uint32_t i;
    memcpy(&i, orig, 4);
    unsigned op = i >> 26, aa = (i >> 1) & 1, lk = i & 1;
    unsigned bo = 0x14, bi = 0;                     /* default: always */
    int kind;                                       /* 0 nop, 1 imm, 2 lr, 3 ctr */
    long disp = 0;

    if (op == 18) {                                 /* b[l][a] */
        kind = 1;
        disp = ppc_sext(i & 0x03FFFFFCu, 26);
    } else if (op == 16) {                          /* bc[l][a] */
        kind = 1;
        bo = (i >> 21) & 0x1F; bi = (i >> 16) & 0x1F;
        disp = ppc_sext(i & 0xFFFCu, 16);
    } else if (op == 19 && (((i >> 1) & 0x3FF) == 16 || ((i >> 1) & 0x3FF) == 528)) {
        kind = ((i >> 1) & 0x3FF) == 16 ? 2 : 3;    /* bclr / bcctr */
        bo = (i >> 21) & 0x1F; bi = (i >> 16) & 0x1F;
        aa = 0;
        if (kind == 3 && !(bo & 0x04)) return 0;    /* bcctr + CTR-- : invalid */
    } else if (i == 0x60000000u) {                  /* nop (ori 0,0,0) */
        kind = 0;
    } else {
        return 0;
    }
    if (!r) return 1;

    uintptr_t next = addr + 4;
    if (kind == 0) { *r->nip = next; return 1; }

    uintptr_t target = kind == 1 ? (aa ? 0 : addr) + (uintptr_t)disp
                     : kind == 2 ? (uintptr_t)(*r->lr & ~3ul)
                     :             (uintptr_t)(*r->ctr & ~3ul);
    /* BO bits, MSB first: 0 = ignore CR, 1 = CR value wanted,
     * 2 = don't touch CTR, 3 = branch on CTR == 0 (else != 0). */
    int ctr_ok = 1;
    if (!(bo & 0x04)) {
        *r->ctr -= 1;
        ctr_ok = (*r->ctr != 0) ^ !!(bo & 0x02);
    }
    int cond_ok = (bo & 0x10) ||
                  (((*r->cr >> (31 - bi)) & 1) == ((bo >> 3) & 1));
    if (lk) *r->lr = next;
    *r->nip = (ctr_ok && cond_ok) ? target : next;
    return 1;
}

#endif
