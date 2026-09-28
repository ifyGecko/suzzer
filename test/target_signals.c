/*
 * target_signals.c -- signal-handling regression target.
 *
 * Each mode reproduces a real-world pattern that used to kill the target
 * under libcov (see TODO.md "Fixed"):
 *
 *   block    -- sigfillset + sigprocmask(SIG_BLOCK) before running
 *               instrumented code (daemon style). A blocked synchronous
 *               SIGILL is not queued; the kernel kills the process.
 *   tblock   -- same, but in a worker thread via pthread_sigmask.
 *   probe    -- install a SIGILL handler after libcov init and execute a
 *               real UD2 (OpenSSL-style CPU feature probe). The handler
 *               must be chained to, not dropped.
 *   siginfo  -- same as probe with an SA_SIGINFO handler.
 *   realill  -- no handler: a real UD2 must still die with SIGILL.
 *
 * Every mode prints "work=<n>" from the instrumented work() so the test
 * can also check coverage was collected.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

static sigjmp_buf jb;
static void on_ill(int s) { (void)s; siglongjmp(jb, 1); }
static void on_ill_info(int s, siginfo_t *si, void *u) { (void)s; (void)si; (void)u; siglongjmp(jb, 1); }

__attribute__((noinline)) int work(int x) {
    int r = 0;
    if (x > 3) r += x * 2; else r -= x;
    if (r % 3 == 0) r++;
    return r;
}

static void *worker(void *arg) {
    sigset_t s;
    sigfillset(&s);
    pthread_sigmask(SIG_BLOCK, &s, NULL);
    *(int *)arg = work(*(int *)arg);
    return NULL;
}

static void probe(int use_siginfo) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    if (use_siginfo) { sa.sa_sigaction = on_ill_info; sa.sa_flags = SA_SIGINFO; }
    else             { sa.sa_handler = on_ill; }
    sigaction(SIGILL, &sa, NULL);
    if (sigsetjmp(jb, 1) == 0) {
        __builtin_trap();
        puts("probe: no trap");
    } else {
        puts("probe: handled");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *m = argv[1];
    if (!strcmp(m, "block")) {
        sigset_t s; sigfillset(&s); sigprocmask(SIG_BLOCK, &s, NULL);
    } else if (!strcmp(m, "tblock")) {
        int v = 9; pthread_t t;
        pthread_create(&t, NULL, worker, &v);
        pthread_join(t, NULL);
        printf("thread=%d\n", v);
    } else if (!strcmp(m, "probe")) {
        probe(0);
    } else if (!strcmp(m, "siginfo")) {
        probe(1);
    } else if (!strcmp(m, "realill")) {
        __builtin_trap();
    }
    printf("work=%d\n", work(argc + 5));
    return 0;
}
