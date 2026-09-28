/*
 * target_orderable.c -- ordering-sensitive ground-truth target.
 *
 * Used to validate libcov's coverage SCHEME (block vs edge vs N-gram).
 *
 * The four state functions are independent leaf calls; main() dispatches
 * to one per character in argv[1]. Two inputs with the same characters
 * in a different order (e.g. "abcd" vs "dcba") hit the SAME SET OF
 * BLOCKS but with DIFFERENT EDGE SEQUENCES. That is precisely the
 * distinction the N-gram knob is supposed to capture:
 *
 *   N=1 (block coverage)   -- "abcd" and "dcba" should produce the same
 *                             bitmap (modulo the shifting prev_loc
 *                             window, which N=1 ignores).
 *   N=2 (AFL edges)        -- bitmaps must differ; the edge a->b is not
 *                             the same bucket as b->a.
 *   N>=3 (N-gram)          -- bitmaps must differ; tuples differ.
 *
 * Built -no-pie -O0 so the dispatch block and state-function entries are
 * at deterministic addresses for gen_patchlist.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) static void state_a(int v) { printf("A:%d\n", v ^ 0xA); }
__attribute__((noinline)) static void state_b(int v) { printf("B:%d\n", v ^ 0xB); }
__attribute__((noinline)) static void state_c(int v) { printf("C:%d\n", v ^ 0xC); }
__attribute__((noinline)) static void state_d(int v) { printf("D:%d\n", v ^ 0xD); }

__attribute__((noinline)) static void dispatch(const char *s) {
    int acc = 0;
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case 'a': state_a(acc++); break;
            case 'b': state_b(acc++); break;
            case 'c': state_c(acc++); break;
            case 'd': state_d(acc++); break;
            default:  break;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { puts("usage"); return 1; }
    dispatch(argv[1]);
    return 0;
}
