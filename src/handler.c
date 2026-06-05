#define _GNU_SOURCE
#include "handler.h"
#include "patch.h"
#include "arch.h"
#include "sink.h"
#include "util.h"

#include <stddef.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

static enum libcov_mode  g_mode = LIBCOV_MODE_LEAPFROG;
static struct sigaction  g_prev_sa;
static struct patch_entry *g_last_restored = NULL;

/* Real sigaction symbol from libc; resolved at install time so our own
 * exported sigaction interceptor (added in hardening phase) can't recurse. */
#include <dlfcn.h>
typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);
static sigaction_fn real_sigaction = NULL;

static void chain_or_default(int signo, siginfo_t *info, void *uctx) {
    /* If a previous handler was registered, dispatch to it; otherwise
     * restore the default disposition so the process dies as it normally
     * would (with a useful core / signal exit code). */
    if (g_prev_sa.sa_flags & SA_SIGINFO) {
        if (g_prev_sa.sa_sigaction) g_prev_sa.sa_sigaction(signo, info, uctx);
    } else if (g_prev_sa.sa_handler == SIG_DFL) {
        struct sigaction dfl;
        memset(&dfl, 0, sizeof dfl);
        dfl.sa_handler = SIG_DFL;
        if (real_sigaction) real_sigaction(signo, &dfl, NULL);
        /* Returning will re-execute the illegal instruction and re-trigger
         * SIGILL, which now goes to the default handler. */
    } else if (g_prev_sa.sa_handler != SIG_IGN) {
        g_prev_sa.sa_handler(signo);
    }
}

static void trap_handler(int signo, siginfo_t *info, void *uctx) {
    ucontext_t *uc = (ucontext_t *)uctx;
    uintptr_t pc = libcov_arch_pc_from_uctx(uc);

    struct patch_entry *e = patch_lookup(pc);
    if (!e || !e->patched) {
        chain_or_default(signo, info, uctx);
        return;
    }

    /* Record coverage edge BEFORE restoring, so prev/cur ordering is stable. */
    sink_emit(pc);

    /* Restore the original instruction so execution can resume. */
    patch_disarm(e);

    if (g_mode == LIBCOV_MODE_LEAPFROG) {
        /* Re-arm the previously hit site so we keep getting edge events from
         * it. Never re-arm the current PC (would infinite-loop). */
        if (g_last_restored && g_last_restored != e && !g_last_restored->patched) {
            patch_arm(g_last_restored);
        }
        g_last_restored = e;
    }
    /* Returning resumes execution at pc; kernel re-fetches the now-valid insn. */
}

int handler_install(enum libcov_mode mode) {
    g_mode = mode;

    real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    if (!real_sigaction) {
        /* Fall back to libc sigaction directly. */
        real_sigaction = (sigaction_fn)dlsym(RTLD_DEFAULT, "sigaction");
    }
    if (!real_sigaction) {
        libcov_logf("handler: cannot resolve real sigaction");
        return -1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = trap_handler;
    sa.sa_flags     = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    if (real_sigaction(libcov_trap_signo, &sa, &g_prev_sa) < 0) {
        libcov_logf("handler: sigaction(signo=%d): %s",
                    libcov_trap_signo, strerror(errno));
        return -1;
    }
    libcov_logf("handler: arch=%s trap_signo=%d mode=%s",
                libcov_arch_name, libcov_trap_signo,
                mode == LIBCOV_MODE_LEAPFROG ? "leapfrog" : "oneshot");
    return 0;
}
