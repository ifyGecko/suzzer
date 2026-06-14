#define _GNU_SOURCE
#include "util.h"
#include "patchlist_format.h"
#include "patch.h"
#include "handler.h"
#include "sink.h"
#include "arch.h"
#include "boundary.h"
#include "tunables.h"   /* LIBCOV_TRAP_SIGNO */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>

static int g_initialized = 0;

static unsigned parse_ring_size(void) {
    const char *s = getenv("LIBCOV_BOUNDARY_RING");
    if (!s || !*s) return 4;
    int v = atoi(s);
    if (v < 2)  v = 2;
    if (v > 16) v = 16;
    return (unsigned)v;
}

static size_t next_pow2(size_t v) {
    size_t p = 1;
    while (p < v) p <<= 1;
    return p;
}

/* Pick the live-bitmap byte length. Site-id model: next_pow2(n*FUDGE),
 * clamped to [1<<MIN, 1<<MAX] for the fudge term, but never below
 * next_pow2(n) so every site_id fits the mask (the N=1 zero-collision
 * guarantee) even when the fudge would exceed the cap. Hashed-PC model:
 * the legacy compile-time constant. */
static size_t compute_map_size(size_t n_sites) {
#if LIBCOV_COVERAGE_MODEL_SITE
    if (n_sites == 0) n_sites = 1;
    size_t floor_min  = (size_t)1u << LIBCOV_MAP_MIN_POW2;
    size_t cap        = (size_t)1u << LIBCOV_MAP_MAX_POW2;
    size_t hard_floor = next_pow2(n_sites);
    size_t sz         = next_pow2(n_sites * (size_t)LIBCOV_MAP_FUDGE);
    if (sz > cap)        sz = cap;
    if (sz < floor_min)  sz = floor_min;
    if (sz < hard_floor) sz = hard_floor;   /* honoured even above the cap */
    return sz;
#else
    (void)n_sites;
    return (size_t)1u << LIBCOV_MAP_SIZE_POW2;
#endif
}

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

    /* config_load first: it only resolves module bases + builds the patch
     * table (no shm/bitmap touch), and the site-id model needs the patch
     * count N to auto-size the bitmap before sink_init allocates it. */
    if (config_load(patchlist) != 0) {
        libcov_logf("init: config_load failed");
        return;
    }
    size_t n_sites = 0;
    config_table(&n_sites);
    size_t map_size = compute_map_size(n_sites);
    libcov_logf("init: coverage model=%s n_sites=%zu map_size=%zu",
                LIBCOV_COVERAGE_MODEL_SITE ? "site" : "hash", n_sites, map_size);
    if (sink_init(getenv("LIBCOV_SHM_PATH"), parse_ring_size(), map_size) != 0) {
        libcov_logf("init: sink_init failed");
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

    int boundary_state = boundary_init();
    if (boundary_state < 0) {
        libcov_logf("init: boundary_init failed; continuing without iteration scoping");
    } else if (boundary_state == 1) {
        /* Sanity check: oneshot + REARM=none + active boundaries makes per-
         * iteration snapshots go empty after warmup. Warn loudly; not fatal. */
        const char *rearm = getenv("LIBCOV_BOUNDARY_REARM");
        if (mode == LIBCOV_MODE_ONESHOT && (!rearm || !*rearm || !strcmp(rearm, "none"))) {
            libcov_logf("init: WARNING -- MODE=oneshot with BOUNDARY_REARM=none means "
                        "per-iter bitmaps empty after warmup; use REARM=all or "
                        "REARM=touched, or switch to MODE=leapfrog");
        }
    }

    g_initialized = 1;
    libcov_logf("init: ready");
}

/* ---- sigaction / signal interception (hardening) ---------------- *
 * If the target tries to install its own handler for our trap signal
 * (LIBCOV_TRAP_SIGNO -- SIGILL by default) after we've armed, silently keep
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
    if (g_initialized && signo == LIBCOV_TRAP_SIGNO) {
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
    if (g_initialized && signo == LIBCOV_TRAP_SIGNO) {
        sighandler_fn prev = g_target_trap_sa_valid ? g_target_trap_sa.sa_handler : SIG_DFL;
        memset(&g_target_trap_sa, 0, sizeof g_target_trap_sa);
        g_target_trap_sa.sa_handler = h;
        g_target_trap_sa_valid = 1;
        libcov_logf("signal: trap signo=%d install intercepted", signo);
        return prev;
    }
    return real(signo, h);
}
