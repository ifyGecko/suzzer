/*
 * target_dispatch.c -- generator regression target.
 *
 * Usage: target_dispatch <n>
 *
 * - dispatch(): calls a handler through a function-pointer table. A
 *   `--root main` slice cannot see the handlers; gen_patchlist.py must
 *   report the indirect call.
 * - exit_path(): a block that calls maybe_exit() in its middle. For n==7
 *   maybe_exit() never returns, so a probe at the block's terminator would
 *   never fire; gen_patchlist.py must probe the call instead.
 *
 * Built with -no-pie -O0 like the other test targets.
 */
#include <stdio.h>
#include <stdlib.h>

static volatile int g;

__attribute__((noinline)) static int op_add(int x) { return x + 1; }
__attribute__((noinline)) static int op_mul(int x) { return x * 3; }
__attribute__((noinline)) static int op_neg(int x) { return -x; }

static int (*const ops_table[])(int) = { op_add, op_mul, op_neg };

__attribute__((noinline)) static int dispatch(int n) {
    return ops_table[(unsigned)n % 3](n);
}

/* Deliberately not declared noreturn, so the compiler keeps the code
 * after the call in the same basic block. */
__attribute__((noinline)) static void maybe_exit(int n) {
    if (n == 7) {
        puts("E:exit7");
        fflush(stdout);
        exit(7);
    }
}

__attribute__((noinline, used)) static int exit_path(int n) {
    g = n * 5;
    maybe_exit(n);
    g += 2;
    if (g > 40) return 1;
    return 0;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 0;
    printf("E:dispatch=%d\n", dispatch(n));
    printf("E:exit_path=%d\n", exit_path(n));
    return 0;
}
