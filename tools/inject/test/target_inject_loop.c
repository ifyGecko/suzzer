/*
 * target_inject_loop.c -- long-running daemon-style target used by the
 * injector test harness. Stands in for an embedded service / network
 * daemon that's already running when we want to attach libcov to it.
 *
 * Reads stdin lines forever; per line, walks a deterministic branch
 * graph (mirrors test/target_simple.c's classify/loop_sum/cmdline
 * shape). Prints E:* markers so the harness can pace itself.
 *
 * Built with -no-pie -O0 -fno-stack-protector for stable / disassembly-
 * friendly addresses, same as libcov's other test targets.
 *
 * This source lives under tools/inject/test/ and is built by
 * tools/inject/Makefile -- it deliberately does NOT live under
 * suzzer's test/ so the injector tree stays self-contained.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
        if (i % 2 == 0) s += i;
        else            s -= i;
    }
    printf("E:loop=%d\n", s);
}

__attribute__((noinline)) static void cmdline(const char *s) {
    if (!s)               { puts("E:null");   return; }
    if (s[0] == 'a')      { puts("E:starta"); }
    else if (s[0] == 'b') { puts("E:startb"); }
    else                  { puts("E:startx"); }

    if (strlen(s) > 4)    { puts("E:long");   }
    else                  { puts("E:short");  }
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

    /* Print our PID on the *third* line of output (preceded by an
     * E:enter marker the harness uses for readiness sync) so the
     * test script knows what to inject into. */
    puts("E:enter");
    printf("PID=%d\n", (int)getpid());
    fflush(stdout);

    char buf[1024];
    while (fgets(buf, sizeof buf, stdin)) {
        size_t L = strlen(buf);
        if (L && buf[L - 1] == '\n') buf[L - 1] = 0;
        if (!*buf) continue;
        process_one(buf);
        fflush(stdout);
    }
    puts("E:exit");
    return 0;
}
