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
 * The rt* modes use SIGRTMAX-2, the default LIBCOV_SYNC_SIGNO that
 * libcov_mt.so's signal broadcast (LIBCOV_SYNC_FALLBACK=tgkill) owns:
 *
 *   rtown    -- install a handler for it after init and raise it: libcov
 *               must hand the signal back and the handler must run.
 *   rtdfl    -- raise it with no handler: must die by it, as without libcov.
 *   rtign    -- raise it when it was ignored before exec (the test sets
 *               SIG_IGN): libcov must leave it alone, so nothing happens.
 *   rtblock  -- a peer thread blocks every signal and spins while main
 *               traps repeatedly. libcov must strip the sync signal from
 *               the mask, or every broadcast waits out its timeout (the
 *               test checks wall time).
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

static volatile int g_rt_hits, g_stop;
static void on_rt(int s) { (void)s; g_rt_hits++; }

static void *spinner(void *arg) {
    (void)arg;
    sigset_t s;
    sigfillset(&s);
    pthread_sigmask(SIG_BLOCK, &s, NULL);
    while (!g_stop) { }
    return NULL;
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
    } else if (!strcmp(m, "rtown")) {
        signal(SIGRTMAX - 2, on_rt);
        raise(SIGRTMAX - 2);
        printf("rt: handled=%d\n", g_rt_hits);
    } else if (!strcmp(m, "rtdfl") || !strcmp(m, "rtign")) {
        raise(SIGRTMAX - 2);
        puts("rt: survived");
    } else if (!strcmp(m, "rtblock")) {
        pthread_t t;
        pthread_create(&t, NULL, spinner, NULL);
        int acc = 0;
        for (int i = 0; i < 3000; i++) acc += work(i & 7);
        g_stop = 1;
        pthread_join(t, NULL);
        printf("acc=%d\n", acc);
    }
    printf("work=%d\n", work(argc + 5));
    return 0;
}
