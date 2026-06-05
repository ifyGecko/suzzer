#define _GNU_SOURCE
#include "util.h"
#include "config.h"
#include "patch.h"
#include "handler.h"
#include "sink.h"
#include "arch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>

static int g_initialized = 0;

__attribute__((constructor(101)))
static void libcov_init(void) {
    libcov_log_init();
    libcov_logf("init: starting");

    const char *patchlist = getenv("LIBCOV_PATCHLIST");
    if (!patchlist || !*patchlist) {
        libcov_logf("init: LIBCOV_PATCHLIST unset, library inert");
        return;
    }

    enum libcov_mode mode = LIBCOV_MODE_LEAPFROG;
    const char *mode_str = getenv("LIBCOV_MODE");
    if (mode_str && !strcmp(mode_str, "oneshot")) mode = LIBCOV_MODE_ONESHOT;

    if (sink_init(getenv("LIBCOV_SHM_PATH")) != 0) {
        libcov_logf("init: sink_init failed");
        return;
    }
    if (config_load(patchlist) != 0) {
        libcov_logf("init: config_load failed");
        return;
    }
    if (patch_arm_all() == 0) {
        libcov_logf("init: nothing armed, aborting");
        return;
    }
    if (handler_install(mode) != 0) {
        libcov_logf("init: handler_install failed");
        return;
    }

    g_initialized = 1;
    libcov_logf("init: ready");
}

/* ---- sigaction / signal interception (hardening) ---------------- *
 * If the target tries to install its own handler for our trap signal
 * (SIGILL or SIGTRAP depending on arch) after we've armed, silently keep
 * ours and report success so the target's flow isn't broken, but stash
 * the requested handler so a *real* trap still chains through. */

typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);
typedef void (*sighandler_fn)(int);
typedef sighandler_fn (*signal_fn)(int, sighandler_fn);

static sigaction_fn real_sigaction_fn(void) {
    static sigaction_fn p;
    if (!p) p = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    return p;
}

static signal_fn real_signal_fn(void) {
    static signal_fn p;
    if (!p) p = (signal_fn)dlsym(RTLD_NEXT, "signal");
    return p;
}

/* Storage for what the target *thinks* its trap-signal handler is. */
static struct sigaction g_target_trap_sa;
static int              g_target_trap_sa_valid = 0;

int sigaction(int signo, const struct sigaction *act, struct sigaction *oldact) {
    sigaction_fn real = real_sigaction_fn();
    if (!real) { errno = ENOSYS; return -1; }
    if (g_initialized && signo == libcov_trap_signo) {
        if (oldact) {
            if (g_target_trap_sa_valid) *oldact = g_target_trap_sa;
            else { memset(oldact, 0, sizeof *oldact); oldact->sa_handler = SIG_DFL; }
        }
        if (act) { g_target_trap_sa = *act; g_target_trap_sa_valid = 1; }
        libcov_logf("sigaction: trap signo=%d install intercepted", signo);
        return 0;
    }
    return real(signo, act, oldact);
}

sighandler_fn signal(int signo, sighandler_fn h) {
    signal_fn real = real_signal_fn();
    if (!real) { errno = ENOSYS; return SIG_ERR; }
    if (g_initialized && signo == libcov_trap_signo) {
        sighandler_fn prev = g_target_trap_sa_valid ? g_target_trap_sa.sa_handler : SIG_DFL;
        memset(&g_target_trap_sa, 0, sizeof g_target_trap_sa);
        g_target_trap_sa.sa_handler = h;
        g_target_trap_sa_valid = 1;
        libcov_logf("signal: trap signo=%d install intercepted", signo);
        return prev;
    }
    return real(signo, h);
}
