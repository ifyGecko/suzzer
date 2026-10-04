/*
 * handler_mt.c -- MT-safe signal handler.
 *
 * Differences from handler_st.c:
 *
 *   g_last_restored is per-thread (__thread). Each thread independently
 *   leapfrogs through its own history; two threads' leapfrog tails never
 *   collide because per-entry arm/disarm is serialized by the cmpxchg in
 *   patch_mt.c. The shared `patched` flag is the single source of truth
 *   for "is this site currently a trap"; per-thread last_restored is just
 *   a hint for which site to re-arm next.
 *
 *   Non-libcov traps chain through libcov_chain_trap() (libcov.c), shared
 *   with the ST handler.
 *
 *   The real_sigaction pointer is resolved once at install (under the main
 *   thread) and then read-only.
 */
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
#include <dlfcn.h>

static enum libcov_mode  g_mode = LIBCOV_MODE_LEAPFROG;
static __thread struct patch_entry *g_last_restored = NULL;

typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);
static sigaction_fn real_sigaction = NULL;

static void trap_handler(int signo, siginfo_t *info, void *uctx) {
    ucontext_t *uc = (ucontext_t *)uctx;
    uintptr_t pc = libcov_arch_pc_from_uctx(uc);

    struct patch_entry *e = patch_lookup(pc);
    if (!e) {
        libcov_chain_trap(signo, info, uctx);
        return;
    }
    /* Concurrent traps at the same site from multiple threads converge here.
     * The first one's patch_disarm wins the cmpxchg and does the byte write;
     * losers no-op. Both paths record an edge in TLS prev_loc + the thread's
     * live bitmap (the shared atomic one until its first boundary).
     *
     * A1: we deliberately use the _unsynced patch variants throughout the
     * trap body and issue ONE patch_sync_batch_end() at the tail. That
     * coalesces the per-write membarrier IPIs (disarm + leapfrog arm +
     * any boundary rearms) into a single broadcast. */
    sink_emit(pc, e->module_idx, e->site_id);

    if (e->emulate) {
        /* Boundary marker the backend can execute itself: it stays armed
         * (so no peer can pass it untrapped). Do the leapfrog re-arm of
         * our previous site, the boundary work, then perform the marker's
         * instruction on the context and return past it. */
        struct patch_entry *last = g_last_restored;
        if (g_mode == LIBCOV_MODE_LEAPFROG && last && !last->marker &&
            !__atomic_load_n(&last->patched, __ATOMIC_RELAXED))
            patch_arm_unsynced(last);
        g_last_restored = NULL;
        boundary_on_trap(pc, e);
        libcov_arch_emulate(uc, pc, e->orig, e->len);
        patch_sync_batch_end();
        return;
    }

    patch_disarm_unsynced(e);

    if (g_mode == LIBCOV_MODE_LEAPFROG) {
        /* Per-thread leapfrog. The arm cmpxchg in patch_arm guards against
         * arming a site that another thread already armed via its own
         * leapfrog -- in that case our arm is a no-op, which is correct.
         * Boundary markers are skipped: boundary.c re-arms them once every
         * thread that trapped on them has moved past. */
        struct patch_entry *last = g_last_restored;
        if (last && last != e && !last->marker &&
            !__atomic_load_n(&last->patched, __ATOMIC_RELAXED)) {
            patch_arm_unsynced(last);
        }
        g_last_restored = e;
    }

    /* Iteration boundary: no-op when LIBCOV_BOUNDARY_LIST is unset. When
     * boundaries are active, per-thread state tracks the disarm of e,
     * checks whether pc is a marker on this thread, and if so publishes
     * a snapshot + clears the live bitmap + applies the configured
     * boundary re-arm policy. Per-thread depth + touched-set state means
     * concurrent worker threads scope their own iterations cleanly.
     * boundary_on_trap also uses _unsynced internally for its rearm
     * loops so the trailing IPI below covers everything. */
    boundary_on_trap(pc, e);

    /* A1: single trailing IPI for every write this handler did. */
    patch_sync_batch_end();
}

int handler_install(enum libcov_mode mode, struct sigaction *prev_out) {
    g_mode = mode;

    real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    if (!real_sigaction) {
        real_sigaction = (sigaction_fn)dlsym(RTLD_DEFAULT, "sigaction");
    }
    if (!real_sigaction) {
        libcov_logf("handler_mt: cannot resolve real sigaction");
        return -1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = trap_handler;
    sa.sa_flags     = SA_SIGINFO | SA_NODEFER;
    handler_build_mask(&sa.sa_mask);

    if (real_sigaction(LIBCOV_TRAP_SIGNO, &sa, prev_out) < 0) {
        libcov_logf("handler_mt: sigaction(signo=%d): %s",
                    LIBCOV_TRAP_SIGNO, strerror(errno));
        return -1;
    }
    libcov_logf("handler_mt: arch=%s trap_signo=%d mode=%s",
                libcov_arch_name, LIBCOV_TRAP_SIGNO,
                mode == LIBCOV_MODE_LEAPFROG ? "leapfrog" : "oneshot");
    return 0;
}
