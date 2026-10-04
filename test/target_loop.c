/*
 * target_loop.c -- boundary-aware ground-truth target.
 *
 * Reads inputs from stdin, one per line, and processes each through
 * iter_begin(), which is registered as the iteration boundary marker. This
 * lets libcov scope coverage per input even though the process is
 * long-lived (no fork+exec per input).
 *
 * Built with -no-pie -O0 so addresses are static and easy to disassemble.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Iteration boundary marker. gen_boundary.py puts the marker where
 * gen_patchlist.py would put this function's first-block site (a
 * mid-block call if any, else the last instruction of >= 2 bytes). A
 * body that compiled to a lone 1-byte `ret` would get no site at all.
 * The runtime-impossible branch guarantees a 2-byte conditional jump
 * there, which the branch-emulating backends execute in software
 * (libcov_arch_emulate), so the marker stays armed. (MIPS markers sit on
 * the entry instruction instead; see gen_boundary.py.) The
 * __builtin_trap() only gives the impossible side a body the compiler
 * keeps; it never executes (on several arches it would be a SIGTRAP
 * instruction, which libcov never uses -- tests that need a real illegal
 * instruction use test/sigill.h).
 * The boundary trap fires before the branch executes; the handler then
 * emulates it (or, with LIBCOV_BOUNDARY_EMULATE=0, restores the bytes),
 * so the branch goes exactly the way the original program's would. */
__attribute__((noinline, used)) void iter_begin(unsigned iter) {
    if (iter == 0xffffffffu) {
        __builtin_trap();
    }
    /* Empty asm with a "memory" clobber prevents the compiler from
     * folding the function down to just `ret`. No real instructions
     * emitted; portable across every libcov backend. */
    __asm__ __volatile__("" : : "r"(iter) : "memory");
}

__attribute__((noinline)) static int classify(int x) {
    if (x < 0)        { puts("E:neg");  return -1; }
    if (x == 0)       { puts("E:zero"); return  0; }
    if (x < 10)       { puts("E:small"); return 1; }
    if (x < 100)      { puts("E:med");   return 2; }
    return 3;
}

__attribute__((noinline)) static void loop_sum(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (i % 2 == 0) { s += i; }
        else            { s -= i; }
    }
    printf("E:loop=%d\n", s);
}

__attribute__((noinline)) static void cmdline(const char *s) {
    if (!s)              { puts("E:null");  return; }
    if (s[0] == 'a')     { puts("E:starta"); }
    else if (s[0] == 'b'){ puts("E:startb"); }
    else                 { puts("E:startx"); }

    if (strlen(s) > 4)   { puts("E:long"); }
    else                 { puts("E:short"); }
}

__attribute__((noinline)) static void process_one(const char *line) {
    int x = atoi(line);
    int c = classify(x);
    loop_sum(c < 0 ? 1 : c + 1);
    cmdline(line);
    if (c == 3) puts("E:big");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    char buf[1024];
    unsigned iter = 0;
    puts("E:enter");
    fflush(stdout);
    while (fgets(buf, sizeof buf, stdin)) {
        size_t L = strlen(buf);
        if (L && buf[L - 1] == '\n') buf[L - 1] = 0;
        iter_begin(iter++);
        process_one(buf);
        fflush(stdout);
    }
    /* Final marker fires the boundary that publishes the LAST input's
     * coverage. Without this, begin-only markers leave the trailing
     * iteration's bitmap unpublished -- the driver wouldn't see what the
     * last input exercised. */
    iter_begin(iter);
    puts("E:exit");
    return 0;
}
