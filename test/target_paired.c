/*
 * target_paired.c -- a paired-mode harness: BEGIN and END markers around
 * each input, harness work between iterations.
 *
 *   for (;;) { iter_begin(i); read a line or stop; process(line);
 *              iter_end(i); gap_work(); }
 *
 * With both markers in the sidecar, libcov publishes one ITER snapshot per
 * input (at iter_end: process()'s coverage) and one GAP snapshot per
 * iter_begin after the first (gap_work()'s coverage -- the same every
 * time, and no input's). The first iter_begin publishes the INIT snapshot.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Marker shape as in target_loop.c: the impossible branch gives the first
 * block a patchable multi-byte terminator. */
__attribute__((noinline, used)) void iter_begin(unsigned i) {
    if (i == 0xffffffffu) abort();
    __asm__ __volatile__("" : : "r"(i) : "memory");
}

__attribute__((noinline, used)) void iter_end(unsigned i) {
    if (i == 0xffffffffu) abort();
    __asm__ __volatile__("" : : "r"(i) : "memory");
}

__attribute__((noinline)) int process(const char *s) {
    int v = atoi(s);
    if (v < 0)        return -1;
    if (v == 0)       return s[0] == '0' ? 0 : 9;     /* number vs text */
    if (v < 100)      return 1;
    return 2;
}

/* Harness bookkeeping between iterations: takes the same path every
 * time, so every GAP snapshot is identical. */
static volatile unsigned g_ticks;
__attribute__((noinline)) void gap_work(void) {
    g_ticks++;
    if (g_ticks > 1000000) g_ticks = 0;
}

int main(void) {
    char line[256];
    for (unsigned i = 0;; i++) {
        iter_begin(i);
        if (!fgets(line, sizeof line, stdin)) break;
        printf("%d\n", process(line));
        fflush(stdout);
        iter_end(i);
        gap_work();
    }
    return 0;
}
