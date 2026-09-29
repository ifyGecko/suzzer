/*
 * unit_mips_emulate.c -- host-side unit test of src/arch_mips_emulate.h.
 *
 * The decoder is a pure function of (instruction word, register file), so
 * it is checked natively: every supported instruction against a known
 * result, the o32/n64 differences (sign extension, 64-bit ops refused on
 * mips32), writes to $zero, and a list of instructions that must NOT be
 * emulated (control flow, memory, trapping arithmetic). Words are built
 * in host byte order, which is how the decoder reads `orig`.
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "../src/arch_mips_emulate.h"

static int fails;

#define I_TYPE(op, rs, rt, imm) \
    ((uint32_t)(op) << 26 | (uint32_t)(rs) << 21 | (uint32_t)(rt) << 16 | ((uint32_t)(imm) & 0xffffu))
#define R_TYPE(rs, rt, rd, sa, fn) \
    ((uint32_t)(rs) << 21 | (uint32_t)(rt) << 16 | (uint32_t)(rd) << 11 | (uint32_t)(sa) << 6 | (fn))

static void check(const char *name, uint32_t insn, int is64, unsigned dst, uint64_t want) {
    unsigned long long g[32], pc = 0x1000;
    for (int r = 0; r < 32; r++) g[r] = 0x1111111111111111ull * (unsigned)(r & 15);
    g[0] = 0;
    g[4] = 0x7ffffff0ull;                     /* a0: near INT32_MAX */
    g[5] = 0x20ull;                           /* a1 */
    g[6] = 0xffffffffffff0000ull;             /* a2: negative */
    g[29] = 0x7fff0000ull;                    /* sp */
    uint8_t b[4];
    memcpy(b, &insn, 4);
    if (!mips_emulate(NULL, NULL, b, 4, is64)) {
        printf("FAIL %s: not accepted\n", name); fails++; return;
    }
    unsigned long long before[32];
    memcpy(before, g, sizeof g);
    if (!mips_emulate(g, &pc, b, 4, is64) || pc != 0x1004) {
        printf("FAIL %s: pc=0x%llx\n", name, pc); fails++; return;
    }
    for (unsigned r = 0; r < 32; r++) {
        uint64_t exp = (r == dst && r != 0) ? want : before[r];
        if (g[r] != exp) {
            printf("FAIL %s: $%u=0x%016llx want 0x%016" PRIx64 "\n", name, r, g[r], exp);
            fails++; return;
        }
    }
}

static void reject(const char *name, uint32_t insn, int is64) {
    uint8_t b[4];
    memcpy(b, &insn, 4);
    if (mips_emulate(NULL, NULL, b, 4, is64)) { printf("FAIL %s: accepted\n", name); fails++; }
}

int main(void) {
    for (int is64 = 0; is64 <= 1; is64++) {
        check("lui gp,0x2",        I_TYPE(0x0f, 0, 28, 0x0002), is64, 28, 0x20000ull);
        check("lui v0,0x8000",     I_TYPE(0x0f, 0, 2, 0x8000), is64, 2, 0xffffffff80000000ull);
        check("addiu sp,sp,-32",   I_TYPE(0x09, 29, 29, -32), is64, 29, 0x7ffeffe0ull);
        check("addiu wraps 32",    I_TYPE(0x09, 4, 2, 0x20), is64, 2, 0xffffffff80000010ull);
        check("ori v0,a1,0xf00f",  I_TYPE(0x0d, 5, 2, 0xf00f), is64, 2, 0xf02full);
        check("andi v0,a2,0xffff", I_TYPE(0x0c, 6, 2, 0xffff), is64, 2, 0);
        check("xori v0,a1,0x21",   I_TYPE(0x0e, 5, 2, 0x21), is64, 2, 0x01ull);
        check("nop",               0x00000000u, is64, 0, 0);
        check("ehb",               R_TYPE(0, 0, 0, 3, 0x00), is64, 0, 0);
        check("sll v0,a1,4",       R_TYPE(0, 5, 2, 4, 0x00), is64, 2, 0x200ull);
        check("sll sign-extends",  R_TYPE(0, 4, 2, 4, 0x00), is64, 2, 0xffffffffffffff00ull);
        check("addu v0,a0,a1",     R_TYPE(4, 5, 2, 0, 0x21), is64, 2, 0xffffffff80000010ull);
        check("subu v0,a1,a0",     R_TYPE(5, 4, 2, 0, 0x23), is64, 2, 0xffffffff80000030ull);
        check("and v0,a0,a2",      R_TYPE(4, 6, 2, 0, 0x24), is64, 2, 0x7fff0000ull);
        check("move s8,sp",        R_TYPE(29, 0, 30, 0, 0x25), is64, 30, 0x7fff0000ull);
        check("xor v0,a0,a1",      R_TYPE(4, 5, 2, 0, 0x26), is64, 2, 0x7fffffd0ull);
        check("nor v0,a1,zero",    R_TYPE(5, 0, 2, 0, 0x27), is64, 2, ~0x20ull);
        check("addiu zero (no-op)",I_TYPE(0x09, 29, 0, 8), is64, 0, 0);
    }
    check("daddiu sp,sp,-48",  I_TYPE(0x19, 29, 29, -48), 1, 29, 0x7ffeffd0ull);
    check("daddiu no wrap",    I_TYPE(0x19, 4, 2, 0x20), 1, 2, 0x80000010ull);
    check("daddu v0,a0,a1",    R_TYPE(4, 5, 2, 0, 0x2d), 1, 2, 0x80000010ull);
    check("dsubu v0,a1,a0",    R_TYPE(5, 4, 2, 0, 0x2f), 1, 2, 0xffffffff80000030ull);

    reject("daddiu on mips32", I_TYPE(0x19, 29, 29, -48), 0);
    reject("daddu on mips32",  R_TYPE(4, 5, 2, 0, 0x2d), 0);
    reject("dsubu on mips32",  R_TYPE(5, 4, 2, 0, 0x2f), 0);
    for (int is64 = 0; is64 <= 1; is64++) {
        reject("beq",            I_TYPE(0x04, 4, 5, 8), is64);
        reject("bne",            I_TYPE(0x05, 4, 5, 8), is64);
        reject("j",              0x08000100u, is64);
        reject("jal",            0x0c000100u, is64);
        reject("jr ra",          R_TYPE(31, 0, 0, 0, 0x08), is64);
        reject("jalr",           R_TYPE(25, 0, 31, 0, 0x09), is64);
        reject("lw",             I_TYPE(0x23, 29, 2, 16), is64);
        reject("sw ra",          I_TYPE(0x2b, 29, 31, 28), is64);
        reject("sd ra",          I_TYPE(0x3f, 29, 31, 40), is64);
        reject("addi (traps)",   I_TYPE(0x08, 29, 29, -32), is64);
        reject("add (traps)",    R_TYPE(4, 5, 2, 0, 0x20), is64);
        reject("aui (r6, rs!=0)",I_TYPE(0x0f, 4, 2, 1), is64);
        reject("sll with rs",    R_TYPE(1, 5, 2, 4, 0x00), is64);
        reject("addu with sa",   R_TYPE(4, 5, 2, 1, 0x21), is64);
        reject("mfhi",           R_TYPE(0, 0, 2, 0, 0x10), is64);
        reject("syscall",        0x0000000cu, is64);
        reject("mfc0 (libcov)",  0x40000000u, is64);
    }
    uint8_t b[4] = {0};
    if (mips_emulate(NULL, NULL, b, 2, 0)) { puts("FAIL: len 2 accepted"); fails++; }

    if (fails) { printf("%d failure(s)\n", fails); return 1; }
    puts("unit_mips_emulate: all checks passed");
    return 0;
}
