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

/* Iteration boundary marker. The body is shaped so the first basic block
 * ends in a multi-byte branch instruction -- gen_patchlist.py skips
 * 1-byte BB terminators (some arches' returns are short), so a straight-
 * line function ending in `ret` alone would never be patched and the
 * boundary would never fire. The runtime-impossible branch forces a
 * conditional jump that *is* patchable. The __builtin_trap() only gives
 * the impossible side a body the compiler keeps; it never executes (on
 * several arches it would be a SIGTRAP instruction, which libcov never
 * uses -- tests that need a real illegal instruction use test/sigill.h).
 * The boundary trap fires before the branch executes; once the handler
 * restores the bytes, the branch is taken to the unreachable side or
 * not, exactly as the original program would. */
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
