#define _GNU_SOURCE
#include "handler.h"
#include "patch.h"
#include "arch.h"
#include "sink.h"
#include "util.h"
#include "boundary.h"
#include "tunables.h"   /* LIBCOV_TRAP_SIGNO */

#include <stddef.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

static enum libcov_mode  g_mode = LIBCOV_MODE_LEAPFROG;
static struct patch_entry *g_last_restored = NULL;

/* Real sigaction symbol from libc; resolved at install time so our own
 * exported sigaction interceptor (added in hardening phase) can't recurse. */
#include <dlfcn.h>
typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);
static sigaction_fn real_sigaction = NULL;

static void trap_handler(int signo, siginfo_t *info, void *uctx) {
    ucontext_t *uc = (ucontext_t *)uctx;
    uintptr_t pc = libcov_arch_pc_from_uctx(uc);

    struct patch_entry *e = patch_lookup(pc);
    if (!e || !e->patched) {
        libcov_chain_trap(signo, info, uctx);
        return;
    }

    /* Record coverage edge BEFORE restoring, so prev/cur ordering is stable.
     * module_idx selects the module base for the hashed-PC model; site_id is
     * the dense bucket base for the site-id model. The active model picks. */
    sink_emit(pc, e->module_idx, e->site_id);

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

    /* Iteration boundary: no-op when LIBCOV_BOUNDARY_LIST is unset. When
     * boundaries are active, this tracks the disarm of e, checks whether
     * pc is a marker, and if so publishes a snapshot + clears the live
     * bitmap + applies the configured boundary re-arm policy. */
    boundary_on_trap(pc, e);
    boundary_trap_exit();

    /* Returning resumes execution at pc; kernel re-fetches the now-valid insn. */
}

int handler_install(enum libcov_mode mode, struct sigaction *prev_out) {
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
    handler_build_mask(&sa.sa_mask);

    if (real_sigaction(LIBCOV_TRAP_SIGNO, &sa, prev_out) < 0) {
        libcov_logf("handler: sigaction(signo=%d): %s",
                    LIBCOV_TRAP_SIGNO, strerror(errno));
        return -1;
    }
    libcov_logf("handler: arch=%s trap_signo=%d mode=%s",
                libcov_arch_name, LIBCOV_TRAP_SIGNO,
                mode == LIBCOV_MODE_LEAPFROG ? "leapfrog" : "oneshot");
    return 0;
}
