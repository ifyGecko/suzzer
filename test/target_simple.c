/*
 * target_simple.c -- ground-truth target for libcov PoC.
 *
 * Reads a small input from argv[1] and walks a deterministic branch graph,
 * printing the edge sequence to stdout. Built with -no-pie -O0 so the
 * branch addresses are static and easy to disassemble.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(int argc, char **argv) {
    puts("E:enter");
    if (argc < 2) { puts("E:noargs"); return 1; }

    int x = atoi(argv[1]);
    int c = classify(x);
    loop_sum(c < 0 ? 1 : c + 1);
    cmdline(argv[1]);

    if (c == 3) { puts("E:big"); }
    puts("E:exit");
    return 0;
}
