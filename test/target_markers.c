/*
 * target_markers.c -- boundary-marker emulation target.
 *
 * Usage: target_markers <n>
 *
 * Each m_* function is a begin marker (gen_boundary.py puts it on the
 * last instruction of the function's first block -- here, its branch).
 * libcov emulates marker instructions in the trap handler instead of
 * disarming them, so a wrong emulation takes the wrong arm. Every arm
 * records a letter into a trace; main prints the trace, which must be
 * identical with and without libcov. The branches are shaped to cover
 * the forms the emulators decode (as built by test/Makefile, gcc 14):
 *
 *   m_short: x86 jcc rel8 / aarch64 b.cond / arm beq / Thumb beq (T1)
 *   m_near:  x86 jcc rel32 (the skipped arm is > 127 bytes) / Thumb beq.w (T3)
 *   m_bit:   -O2: x86 test+jcc / aarch64 tbz/tbnz / Thumb bpl
 *   m_zero:  -O2: x86 test+jcc / aarch64 cbz/cbnz / Thumb cbz
 *
 * riscv64 compiles every marker to beqz (beq rs, x0) and powerpc/ppc64 to
 * bc on a CR bit (bt/bf eq).
 *
 * Each of the n iterations calls every marker once: 4n boundary fires.
 */
#include <stdio.h>
#include <stdlib.h>

static char trace[1 << 16];
static unsigned tlen;

__attribute__((noinline)) static void rec(char c) {
    if (tlen < sizeof trace - 1) trace[tlen++] = c;
}

__attribute__((noinline, used)) void m_short(unsigned x) {
    if (x & 1) rec('o');
    else       rec('e');
}

static volatile unsigned g_sink;

__attribute__((noinline, used)) void m_near(unsigned x) {
    if (x % 3) {
        /* Long enough that the branch jumping over it needs a rel32 on
         * x86. */
        g_sink += x * 3; g_sink ^= x << 1; g_sink += x * 5; g_sink ^= x << 2;
        g_sink += x * 7; g_sink ^= x << 3; g_sink += x * 11; g_sink ^= x << 4;
        g_sink += x * 13; g_sink ^= x << 5; g_sink += x * 17; g_sink ^= x << 6;
        g_sink += x * 19; g_sink ^= x << 7; g_sink += x * 23; g_sink ^= x << 8;
        rec('n');
    } else {
        rec('N');
    }
}

__attribute__((noinline, used, optimize("O2"))) void m_bit(unsigned x) {
    if (x & 4) rec('B');
    else       rec('b');
}

static unsigned g_vals[8] = { 0, 1, 0, 2, 3, 0, 4, 0 };

__attribute__((noinline, used, optimize("O2"))) void m_zero(unsigned x) {
    if (g_vals[x & 7]) rec('z');
    else               rec('Z');
}

int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 20;
    for (unsigned i = 0; i < n; i++) {
        m_short(i);
        m_near(i);
        m_bit(i);
        m_zero(i);
    }
    trace[tlen] = 0;
    printf("calls=%u trace=%s\n", 4 * n, trace);
    return 0;
}
