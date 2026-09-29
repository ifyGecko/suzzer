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
 *               real illegal instruction (OpenSSL-style CPU feature probe). The handler
 *               must be chained to, not dropped.
 *   siginfo  -- same as probe with an SA_SIGINFO handler.
 *   realill  -- no handler: a real illegal instruction must still die
 *               with SIGILL.
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
 * libc aliases that reach the kernel through glibc-internal calls, so the
 * sigaction()/sigprocmask() interposers never see them:
 *
 *   ignore   -- sigignore(SIGILL): would set SIG_IGN over libcov's handler,
 *               and the next libcov trap kills the target.
 *   hold     -- sighold(SIGILL): would block the trap signal.
 *   bsd      -- bsd_signal(SIGILL, h), then work(), then a real trap.
 *   sysv     -- same via sysv_signal (SA_RESETHAND semantics).
 *   sigset   -- same via sigset, plus siginterrupt.
 *   suspend  -- sigsuspend() with SIGILL in the mask; the woken SIGUSR1
 *               handler runs instrumented code.
 *
 * Chaining fidelity:
 *
 *   mask     -- a SIGILL handler with sa_mask={SIGUSR2} must run with
 *               exactly the kernel's mask: USR2 blocked, USR1 not.
 *   race     -- two threads keep swapping the SIGILL handler while main
 *               runs real traps; every trap must reach a valid handler.
 *   logsock  -- close every fd >= 3, dup2 a socket onto fd 2, then call
 *               sigaction(SIGILL): libcov's post-init log lines must not
 *               land on the socket (via fd 2 or a reused LIBCOV_LOG fd).
 *
 * Every mode prints "work=<n>" from the instrumented work() so the test
 * can also check coverage was collected.
 */
#define _GNU_SOURCE
/* sighold/sigignore/sigset are deprecated in glibc, but real targets still
 * call them -- which is exactly what this target reproduces. */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sigill.h"

/* Still exported by glibc, no longer declared in <signal.h>. */
extern sighandler_t bsd_signal(int, sighandler_t);

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
        TEST_SIGILL();
        puts("probe: no trap");
    } else {
        puts("probe: handled");
    }
}

/* One real trap through whatever SIGILL handler is installed now. */
static void trap_once(const char *tag) {
    if (sigsetjmp(jb, 1) == 0) {
        TEST_SIGILL();
        printf("%s: no trap\n", tag);
    } else {
        printf("%s: handled\n", tag);
    }
}

static volatile int g_usr1_work;
static void on_usr1(int s) { (void)s; g_usr1_work = work(4); }

static volatile int g_mask_usr1 = -1, g_mask_usr2 = -1;
static void on_ill_mask(int s) {
    (void)s;
    sigset_t cur;
    pthread_sigmask(SIG_BLOCK, NULL, &cur);
    g_mask_usr1 = sigismember(&cur, SIGUSR1);
    g_mask_usr2 = sigismember(&cur, SIGUSR2);
    siglongjmp(jb, 1);
}

static void *flipper(void *arg) {
    (void)arg;
    struct sigaction a, b;
    memset(&a, 0, sizeof a);
    a.sa_handler = on_ill;
    memset(&b, 0, sizeof b);
    b.sa_sigaction = on_ill_info;
    b.sa_flags = SA_SIGINFO;
    for (unsigned i = 0; !g_stop; i++)
        sigaction(SIGILL, (i & 1) ? &a : &b, NULL);
    return NULL;
}

static int drain(int fd) {
    char buf[4096];
    int total = 0;
    for (;;) {
        ssize_t r = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (r <= 0) return total;
        total += (int)r;
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
        TEST_SIGILL();
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
    } else if (!strcmp(m, "ignore")) {
        sigignore(SIGILL);
        printf("ignore: work=%d\n", work(2));
    } else if (!strcmp(m, "hold")) {
        sighold(SIGILL);
        printf("hold: work=%d\n", work(2));
        sigrelse(SIGILL);
    } else if (!strcmp(m, "bsd")) {
        bsd_signal(SIGILL, on_ill);
        printf("bsd: work=%d\n", work(2));
        trap_once("bsd");
    } else if (!strcmp(m, "sysv")) {
        sysv_signal(SIGILL, on_ill);
        printf("sysv: work=%d\n", work(2));
        trap_once("sysv");
    } else if (!strcmp(m, "sigset")) {
        sigset(SIGILL, on_ill);
        siginterrupt(SIGILL, 1);
        printf("sigset: work=%d\n", work(2));
        trap_once("sigset");
    } else if (!strcmp(m, "suspend")) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_usr1;
        sigaction(SIGUSR1, &sa, NULL);
        sigset_t blk, wait;
        sigemptyset(&blk);
        sigaddset(&blk, SIGUSR1);
        sigprocmask(SIG_BLOCK, &blk, NULL);
        raise(SIGUSR1);                 /* pending until sigsuspend */
        sigfillset(&wait);
        sigdelset(&wait, SIGUSR1);
        sigsuspend(&wait);
        printf("suspend: work=%d\n", g_usr1_work);
    } else if (!strcmp(m, "mask")) {
        sigset_t un;
        sigemptyset(&un);
        sigaddset(&un, SIGUSR1);
        sigaddset(&un, SIGUSR2);
        sigprocmask(SIG_UNBLOCK, &un, NULL);
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_ill_mask;
        sigemptyset(&sa.sa_mask);
        sigaddset(&sa.sa_mask, SIGUSR2);
        sigaction(SIGILL, &sa, NULL);
        trap_once("mask");
        printf("mask: usr1=%d usr2=%d\n", g_mask_usr1, g_mask_usr2);
    } else if (!strcmp(m, "race")) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_ill;
        sigaction(SIGILL, &sa, NULL);
        pthread_t t1, t2;
        pthread_create(&t1, NULL, flipper, NULL);
        pthread_create(&t2, NULL, flipper, NULL);
        int handled = 0;
        for (int i = 0; i < 2000; i++) {
            if (sigsetjmp(jb, 1) == 0) TEST_SIGILL();
            else handled++;
        }
        g_stop = 1;
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        printf("race: handled=%d\n", handled);
    } else if (!strcmp(m, "logsock")) {
        for (int fd = 3; fd < 1024; fd++) close(fd);
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 3;
        dup2(sv[0], 2);
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_ill;
        sigaction(SIGILL, &sa, NULL);
        signal(SIGILL, on_ill);
        printf("logsock: leaked=%d\n", drain(sv[0]) + drain(sv[1]));
    }
    printf("work=%d\n", work(argc + 5));
    return 0;
}
