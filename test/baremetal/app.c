/* Instrumented "application": branchy functions whose execution path depends
 * on the input, so different inputs produce different coverage. Not tied to
 * any real firmware -- it is suzzer's own baremetal exercise target. */
#include <stdint.h>
__attribute__((noinline)) int app_leaf(int x) { volatile int r = x + 7; return r; }
__attribute__((noinline)) int app_a(int x) { int r = x * 3 + 1; for (int i = 0; i < (x & 3); i++) r += app_leaf(i); return r; }
__attribute__((noinline)) int app_b(int x) { int r = x ^ 0x55; if (x > 5) r += app_leaf(x); return r; }
__attribute__((noinline)) int app_c(int x) { return (x << 1) + app_leaf(x & 7); }
__attribute__((noinline)) int app_run(int x) {
    int r = 0;
    if (x & 1) r += app_a(x); else r += app_b(x);
    if (x > 10) r += app_c(x);
    return r;
}
