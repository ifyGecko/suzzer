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
#include <setjmp.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#if defined(LIBCOV_THREADING_ST)
#  include <pthread.h>
#endif
#if defined(LIBCOV_THREADING_MT)
#  include "membarrier.h"
#endif

/* The MT sync-broadcast signal while it is active (membarrier.h), else -1. */
static int sync_signo(void) {
#if defined(LIBCOV_THREADING_MT)
    return membarrier_sync_signo();
#else
    return -1;
#endif
}

static int g_initialized = 0;

static int trap_selftest(void);
#if defined(LIBCOV_THREADING_ST)
static void st_check_threads(void);
#endif

static int env_true(const char *name) {
    const char *v = getenv(name);
    return v && *v && strcmp(v, "0") != 0;
}

/* An init step failed and libcov will run inert (or without boundaries).
 * Log it; with LIBCOV_REQUIRE=1, abort instead -- a fuzz run whose
 * coverage is silently all-zero wastes the whole campaign. Opt-in because
 * children that inherit LD_PRELOAD (a daemon's /bin/sh, helpers) are
 * normally meant to run inert. */
static void init_fail(const char *what) {
    libcov_logf("init: %s", what);
    if (env_true("LIBCOV_REQUIRE")) {
        libcov_logf("init: LIBCOV_REQUIRE is set -- aborting");
        abort();
    }
}

/* What the target *thinks* its trap-signal handler is (defined with the
 * interposers below). */
static void tsa_seed(const struct sigaction *prev);
static void prime_real_fns(void);

/* Ring slots. The default is 8 so REARM=all (O(n_sites) in the handler)
 * or a briefly descheduled driver doesn't overrun it; each slot costs
 * one map_size bitmap. */
static unsigned parse_ring_size(void) {
    const char *s = getenv("LIBCOV_BOUNDARY_RING");
    if (!s || !*s) return 8;
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

#if LIBCOV_COVERAGE_MODEL_SITE
/* exp(-x) for x >= 0 without libm: halve x into Taylor range, square back. */
static double neg_exp(double x) {
    int k = 0;
    while (x > 0.5) { x /= 2; k++; }
    double r = 1 - x + x * x / 2 - x * x * x / 6 + x * x * x * x / 24;
    while (k--) r *= r;
    return r;
}

/* Expected fraction of k distinct N-grams, hashed uniformly into m buckets,
 * that share their bucket with at least one other: 1 - e^{-(k-1)/m}. The
 * site-id fold isn't a perfect hash, so this is an estimate, not a bound. */
static double collision_share(size_t k, size_t m) {
    if (k < 2 || m == 0) return 0.0;
    return 1.0 - neg_exp((double)(k - 1) / (double)m);
}
#endif

__attribute__((constructor(101)))
static void libcov_init(void) {
    libcov_log_init();
    libcov_logf("init: starting");

    const char *patchlist = getenv("LIBCOV_PATCHLIST");
    if (!patchlist || !*patchlist) {
        init_fail("LIBCOV_PATCHLIST unset, library inert");
        return;
    }

    enum libcov_mode mode = LIBCOV_MODE_LEAPFROG;
    const char *mode_str = getenv("LIBCOV_MODE");
    if (mode_str && !strcmp(mode_str, "oneshot")) mode = LIBCOV_MODE_ONESHOT;

    /* config_load first: it only resolves module bases + builds the patch
     * table (no shm/bitmap touch), and the site-id model needs the patch
     * count N to auto-size the bitmap before sink_init allocates it. */
    if (config_load(patchlist) != 0) {
        init_fail("config_load failed, library inert");
        return;
    }
    size_t n_sites = 0;
    config_table(&n_sites);
    size_t map_size = compute_map_size(n_sites);
#if LIBCOV_COVERAGE_MODEL_SITE
    libcov_logf("init: coverage model=site ngram_n=%d n_sites=%zu fudge=%u map_size=%zu",
                (int)LIBCOV_NGRAM_N, n_sites, (unsigned)LIBCOV_MAP_FUDGE, map_size);
    /* Only N=1 is collision-free: at N>=2 each bucket hashes a site with
     * its predecessors, so distinct N-grams can share one. */
    if (LIBCOV_NGRAM_N >= 2 && n_sites) {
        libcov_logf("init: ngram_n=%d: collisions possible, %zu bucket(s) per site; "
                    "expected share of N-grams in a shared bucket: %.1f%% if %zu "
                    "distinct are hit, %.1f%% if %zu (raise LIBCOV_MAP_FUDGE to lower)",
                    (int)LIBCOV_NGRAM_N, map_size / n_sites,
                    100.0 * collision_share(n_sites, map_size), n_sites,
                    100.0 * collision_share(8 * n_sites, map_size), 8 * n_sites);
    }
#else
    libcov_logf("init: coverage model=hash ngram_n=%d n_sites=%zu map_size=%zu",
                (int)LIBCOV_NGRAM_N, n_sites, map_size);
#endif
    if (sink_init(getenv("LIBCOV_SHM_PATH"), parse_ring_size(), map_size) != 0) {
        init_fail("sink_init failed, library inert");
        return;
    }
    /* A trap encoding that raises some other signal than the one our
     * handler is installed for kills the target on its first trap (e.g.
     * -DLIBCOV_TRAP_SIGNO=SIGTRAP with a SIGILL encoding). Check first. */
    if (trap_selftest() != 0) {
        init_fail("trap self-test failed, library inert (nothing armed)");
        return;
    }
#if defined(LIBCOV_THREADING_MT)
    /* Before handler_install: the trap handler's mask must leave the sync
     * broadcast signal deliverable if that fallback is active. */
    membarrier_init();
#endif
    /* Install the handler BEFORE arming: if install fails we must not
     * leave trap encodings in the target with nothing to catch them. */
    /* Resolve the real sigaction/pthread_sigmask now, single-threaded:
     * libcov_chain_trap uses them from the trap handler, where dlsym is
     * not safe (the self-test that used to warm them is skipped on some
     * targets). */
    prime_real_fns();
    struct sigaction prev;
    memset(&prev, 0, sizeof prev);
    if (handler_install(mode, &prev) != 0) {
        init_fail("handler_install failed, library inert");
        return;
    }
    tsa_seed(&prev);
    if (patch_arm_all() == 0) {
        init_fail("nothing armed, library inert");
        return;
    }

    /* oneshot + REARM=none + boundaries: every site fires once and is
     * never re-armed, so per-iteration snapshots are empty after warmup
     * and the driver sees a plateaued corpus instead of an error. Refuse
     * to enable boundaries unless explicitly allowed (a "first hit only"
     * novelty stream is a legitimate, if unusual, choice). */
    const char *blist = getenv("LIBCOV_BOUNDARY_LIST");
    int no_rearm = boundary_parse_rearm(getenv("LIBCOV_BOUNDARY_REARM")) ==
                   LIBCOV_REARM_NONE;
    if (blist && *blist && mode == LIBCOV_MODE_ONESHOT && no_rearm &&
        !env_true("LIBCOV_ALLOW_ONESHOT_NOREARM")) {
        init_fail("ERROR -- MODE=oneshot with BOUNDARY_REARM=none (unset, empty, "
                  "'none' or unrecognised) would leave "
                  "per-iteration snapshots empty after warmup; boundaries NOT "
                  "enabled. Use LIBCOV_BOUNDARY_REARM=touched or =all, or "
                  "LIBCOV_MODE=leapfrog, or set LIBCOV_ALLOW_ONESHOT_NOREARM=1 "
                  "to get first-hit-only snapshots on purpose.");
    } else if (boundary_init() < 0) {
        init_fail("boundary_init failed; continuing without iteration scoping");
    }

#if defined(LIBCOV_THREADING_ST)
    st_check_threads();
#endif
    g_initialized = 1;
    libcov_logf("init: ready");
    libcov_log_seal();
}

/* ---- real libc entry points --------------------------------------- */

typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);
typedef void (*sighandler_fn)(int);
typedef sighandler_fn (*signal_fn)(int, sighandler_fn);
typedef int (*sigmask_fn)(int, const sigset_t *, sigset_t *);
typedef int (*signo_fn)(int);                   /* sigignore, sighold */
typedef int (*siginterrupt_fn)(int, int);
typedef int (*sigsuspend_fn)(const sigset_t *);

/* Resolved once; prime_real_fns() runs them from libcov_init so the trap
 * handler never reaches dlsym. */
static sigaction_fn real_sigaction_fn(void) {
    static sigaction_fn p;
    if (!p) p = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    return p;
}

static sigmask_fn real_pthread_sigmask_fn(void) {
    static sigmask_fn p;
    if (!p) p = (sigmask_fn)dlsym(RTLD_NEXT, "pthread_sigmask");
    return p;
}

static void prime_real_fns(void) {
    (void)real_sigaction_fn();
    (void)real_pthread_sigmask_fn();
}

/* Declare `real_`, the next definition of an interposed libc symbol,
 * resolved on first use (NULL if there is none). */
#define REAL(type, name)                                        \
    static type real_;                                          \
    if (!real_) real_ = (type)dlsym(RTLD_NEXT, name);

/* ---- the target's trap-signal disposition ------------------------- *
 * What the target *thinks* its trap-signal handler is: the pre-init
 * disposition (seeded in libcov_init) or whatever it installed later
 * through the interposers below. The trap handler reads it lock-free
 * (libcov_chain_trap) while another thread's interposer may be writing
 * it, so it is a double buffer indexed by a sequence counter:
 *
 *   seq even: stable, published buffer = g_tsa[(seq >> 1) & 1].
 *   seq odd:  a writer is filling the OTHER buffer; the published one is
 *             untouched, so readers carry on.
 *
 * A reader that started at seq in {2k, 2k+1} copied g_tsa[k & 1]. That
 * buffer is next overwritten only after seq moves from 2k+2 to 2k+3, so
 * the copy is intact iff seq <= 2k+2 afterwards; otherwise retry (it
 * takes two back-to-back writes). Writers serialize on a spinlock. */

struct target_sa { struct sigaction sa; int valid; };
static struct target_sa g_tsa[2];
static unsigned         g_tsa_seq;
static int              g_tsa_lock;

static void tsa_read(struct target_sa *out) {
    unsigned spins = 0;
    for (;;) {
        unsigned s1 = __atomic_load_n(&g_tsa_seq, __ATOMIC_ACQUIRE);
        unsigned k  = s1 >> 1;
        *out = g_tsa[k & 1];
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        unsigned s2 = __atomic_load_n(&g_tsa_seq, __ATOMIC_RELAXED);
        if (s2 - 2u * k <= 2u) return;
        libcov_spin_backoff(&spins);
    }
}

/* Writer: lock and return the current value; tsa_write_end publishes a
 * new one (or NULL to keep it) and unlocks. Interposers call these with
 * async signals blocked (tsa_block_signals), so a target signal handler
 * that calls sigaction() can't spin on a lock its own thread holds. The
 * trap handler already runs with them blocked. */
static struct target_sa tsa_write_begin(void) {
    unsigned spins = 0;
    while (__atomic_exchange_n(&g_tsa_lock, 1, __ATOMIC_ACQUIRE))
        libcov_spin_backoff(&spins);
    return g_tsa[(__atomic_load_n(&g_tsa_seq, __ATOMIC_RELAXED) >> 1) & 1];
}

static void tsa_write_end(const struct target_sa *v) {
    if (v) {
        unsigned s = __atomic_load_n(&g_tsa_seq, __ATOMIC_RELAXED);
        __atomic_store_n(&g_tsa_seq, s + 1, __ATOMIC_RELAXED);
        __atomic_thread_fence(__ATOMIC_RELEASE);
        g_tsa[((s >> 1) + 1) & 1] = *v;
        __atomic_store_n(&g_tsa_seq, s + 2, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&g_tsa_lock, 0, __ATOMIC_RELEASE);
}

/* Returns 1 if the mask was changed and tsa_unblock_signals must run. */
static int tsa_block_signals(sigset_t *old) {
    sigset_t m;
    handler_build_mask(&m);
    sigmask_fn set = real_pthread_sigmask_fn();
    return set && set(SIG_BLOCK, &m, old) == 0;
}

static void tsa_unblock_signals(int blocked, const sigset_t *old) {
    if (blocked) real_pthread_sigmask_fn()(SIG_SETMASK, old, NULL);
}

static void tsa_seed(const struct sigaction *prev) {
    struct target_sa v = { *prev, 1 };
    (void)tsa_write_begin();
    tsa_write_end(&v);
}

/* Atomically record `act` (if non-NULL) as the target's disposition and
 * return the previous one in `oldact` (if non-NULL). */
static void tsa_swap(const struct sigaction *act, struct sigaction *oldact) {
    sigset_t saved;
    int blocked = tsa_block_signals(&saved);
    struct target_sa cur = tsa_write_begin();
    if (oldact) {
        if (cur.valid) *oldact = cur.sa;
        else { memset(oldact, 0, sizeof *oldact); oldact->sa_handler = SIG_DFL; }
    }
    struct target_sa next = { act ? *act : cur.sa, 1 };
    tsa_write_end(act ? &next : NULL);
    tsa_unblock_signals(blocked, &saved);
}

/* Record a plain handler with the given flags / self-masking, as the libc
 * wrapper would have installed it, and return the previous handler. */
static sighandler_fn tsa_swap_handler(int signo, sighandler_fn h, int flags,
                                      int mask_self) {
    struct sigaction act, old;
    memset(&act, 0, sizeof act);
    act.sa_handler = h;
    act.sa_flags = flags;
    sigemptyset(&act.sa_mask);
    if (mask_self) sigaddset(&act.sa_mask, signo);
    tsa_swap(&act, &old);
    return old.sa_handler;
}

/* ---- sigaction / signal interception (hardening) ---------------- *
 * If the target tries to install its own handler for our trap signal
 * (LIBCOV_TRAP_SIGNO -- SIGILL by default) after we've armed, silently keep
 * ours and report success so the target's flow isn't broken, but stash
 * the requested handler so a *real* trap still chains through.
 *
 * glibc's older wrappers (bsd_signal, sysv_signal, sigset, sigignore,
 * sighold, siginterrupt, sigsuspend) reach the kernel through internal
 * calls that never pass through the sigaction()/sigprocmask() symbols, so
 * each is interposed too. Raw rt_sigaction/rt_sigprocmask syscalls still
 * bypass all of this (see Design.md §19). */

static int trap_intercepted(int signo) {
    return g_initialized && signo == LIBCOV_TRAP_SIGNO;
}

/* MT: the target taking over the sync-broadcast signal ends the tgkill
 * fallback (membarrier.c hands the signal back). */
static void note_sync_install(int signo, int is_default) {
#if defined(LIBCOV_THREADING_MT)
    if (g_initialized && signo == sync_signo() && !is_default)
        membarrier_release_signal("the target installed a handler for");
#else
    (void)signo; (void)is_default;
#endif
}

int sigaction(int signo, const struct sigaction *act, struct sigaction *oldact) {
    sigaction_fn real = real_sigaction_fn();
    if (!real) { errno = ENOSYS; return -1; }
    if (act) {
        int dfl = (act->sa_flags & SA_SIGINFO) ? act->sa_sigaction == NULL
                                               : act->sa_handler == SIG_DFL;
        note_sync_install(signo, dfl);
    }
    if (trap_intercepted(signo)) {
        tsa_swap(act, oldact);
        libcov_logf("sigaction: trap signo=%d install intercepted", signo);
        return 0;
    }
    return real(signo, act, oldact);
}

/* glibc signal()/bsd_signal()/ssignal(): BSD semantics -- SA_RESTART, and
 * the signal masked while its handler runs. */
static sighandler_fn bsd_style(const char *name, signal_fn real, int signo,
                               sighandler_fn h) {
    note_sync_install(signo, h == SIG_DFL);
    if (trap_intercepted(signo)) {
        libcov_logf("%s: trap signo=%d install intercepted", name, signo);
        return tsa_swap_handler(signo, h, SA_RESTART, 1);
    }
    if (!real) { errno = ENOSYS; return SIG_ERR; }
    return real(signo, h);
}

sighandler_fn signal(int signo, sighandler_fn h) {
    REAL(signal_fn, "signal");
    return bsd_style("signal", real_, signo, h);
}

sighandler_fn bsd_signal(int signo, sighandler_fn h) {
    REAL(signal_fn, "bsd_signal");
    return bsd_style("bsd_signal", real_, signo, h);
}

sighandler_fn ssignal(int signo, sighandler_fn h) {
    REAL(signal_fn, "ssignal");
    return bsd_style("ssignal", real_, signo, h);
}

/* sysv_signal: one-shot, not self-masking, no SA_RESTART. */
static sighandler_fn sysv_style(const char *name, signal_fn real, int signo,
                                sighandler_fn h) {
    note_sync_install(signo, h == SIG_DFL);
    if (trap_intercepted(signo)) {
        libcov_logf("%s: trap signo=%d install intercepted", name, signo);
        return tsa_swap_handler(signo, h, SA_RESETHAND | SA_NODEFER, 0);
    }
    if (!real) { errno = ENOSYS; return SIG_ERR; }
    return real(signo, h);
}

sighandler_fn sysv_signal(int signo, sighandler_fn h) {
    REAL(signal_fn, "sysv_signal");
    return sysv_style("sysv_signal", real_, signo, h);
}

sighandler_fn __sysv_signal(int signo, sighandler_fn h) {
    REAL(signal_fn, "__sysv_signal");
    return sysv_style("__sysv_signal", real_, signo, h);
}

/* sigset(sig, SIG_HOLD) blocks the signal; anything else installs `disp`
 * and unblocks it. The trap signal is never blocked under libcov, so its
 * "previous disposition" is always the stored handler. */
sighandler_fn sigset(int signo, sighandler_fn disp) {
    if (disp != SIG_HOLD) note_sync_install(signo, disp == SIG_DFL);
    if (trap_intercepted(signo)) {
        libcov_logf("sigset: trap signo=%d install intercepted", signo);
        if (disp == SIG_HOLD) {
            struct sigaction old;
            tsa_swap(NULL, &old);
            return old.sa_handler;
        }
        return tsa_swap_handler(signo, disp, 0, 0);
    }
    REAL(signal_fn, "sigset");
    if (!real_) { errno = ENOSYS; return SIG_ERR; }
    return real_(signo, disp);
}

/* sigignore would put SIG_IGN over libcov's handler, and the kernel kills
 * the target on the next (synchronous) trap. */
int sigignore(int signo) {
    note_sync_install(signo, 0);
    if (trap_intercepted(signo)) {
        libcov_logf("sigignore: trap signo=%d intercepted", signo);
        (void)tsa_swap_handler(signo, SIG_IGN, 0, 0);
        return 0;
    }
    REAL(signo_fn, "sigignore");
    if (!real_) { errno = ENOSYS; return -1; }
    return real_(signo);
}

/* siginterrupt toggles SA_RESTART on the current disposition. */
int siginterrupt(int signo, int flag) {
    if (trap_intercepted(signo)) {
        sigset_t saved;
        int blocked = tsa_block_signals(&saved);
        struct target_sa cur = tsa_write_begin();
        if (!cur.valid) {
            memset(&cur, 0, sizeof cur);
            cur.sa.sa_handler = SIG_DFL;
            cur.valid = 1;
        }
        if (flag) cur.sa.sa_flags &= ~SA_RESTART;
        else      cur.sa.sa_flags |= SA_RESTART;
        tsa_write_end(&cur);
        tsa_unblock_signals(blocked, &saved);
        return 0;
    }
    REAL(siginterrupt_fn, "siginterrupt");
    if (!real_) { errno = ENOSYS; return -1; }
    return real_(signo, flag);
}

/* ---- chaining non-libcov traps to the target's handler ------------ */

void handler_build_mask(sigset_t *mask) {
    sigfillset(mask);
    sigdelset(mask, SIGILL);
    sigdelset(mask, SIGSEGV);
    sigdelset(mask, SIGBUS);
    sigdelset(mask, SIGFPE);
    sigdelset(mask, SIGTRAP);
    sigdelset(mask, LIBCOV_TRAP_SIGNO);
    /* The sync-broadcast handler only bumps a counter, so it is safe
     * mid-trap, and a broadcaster waits for every peer, including peers
     * inside this handler. */
    if (sync_signo() > 0) sigdelset(mask, sync_signo());
}

/* Give the target's handler the mask the kernel would have: the
 * interrupted context's mask, plus its sa_mask, plus the signal itself
 * unless SA_NODEFER -- instead of libcov's own everything-blocked mask.
 * One deviation: the trap signal (and MT sync signal) stay unblocked,
 * because the handler's own code may contain armed sites. Returns 1 if
 * the mask was changed and `old` must be restored. */
static int chain_mask_enter(int signo, const struct sigaction *sa, void *uctx,
                            sigset_t *old) {
    sigmask_fn set = real_pthread_sigmask_fn();
    if (!set) return 0;
    sigset_t m;
    if (uctx) m = ((ucontext_t *)uctx)->uc_sigmask;
    else if (set(SIG_BLOCK, NULL, &m) != 0) return 0;
    sigorset(&m, &m, &sa->sa_mask);
    if (!(sa->sa_flags & SA_NODEFER)) sigaddset(&m, signo);
    sigdelset(&m, LIBCOV_TRAP_SIGNO);
    if (sync_signo() > 0) sigdelset(&m, sync_signo());
    return set(SIG_SETMASK, &m, old) == 0;
}

void libcov_chain_trap(int signo, siginfo_t *info, void *uctx) {
    struct target_sa t;
    tsa_read(&t);
    struct sigaction sa = t.sa;

    int with_info = t.valid && (sa.sa_flags & SA_SIGINFO) && sa.sa_sigaction;
    int plain = t.valid && !(sa.sa_flags & SA_SIGINFO) &&
                sa.sa_handler != SIG_DFL && sa.sa_handler != SIG_IGN;
    if (with_info || plain) {
        if (sa.sa_flags & SA_RESETHAND) {
            /* One-shot: reset to SIG_DFL, unless another thread already
             * replaced the handler we are about to call. */
            struct target_sa cur = tsa_write_begin();
            if (cur.valid && cur.sa.sa_handler == sa.sa_handler) {
                memset(&cur, 0, sizeof cur);
                cur.sa.sa_handler = SIG_DFL;
                cur.valid = 1;
                tsa_write_end(&cur);
            } else {
                tsa_write_end(NULL);
            }
        }
        sigset_t old;
        int restore = chain_mask_enter(signo, &sa, uctx, &old);
        if (with_info) sa.sa_sigaction(signo, info, uctx);
        else           sa.sa_handler(signo);
        /* Not reached if the handler siglongjmp'd out; sigsetjmp(.., 1)
         * restores its own saved mask then, as it would without libcov. */
        if (restore) real_pthread_sigmask_fn()(SIG_SETMASK, &old, NULL);
        return;
    }
    /* SIG_DFL, or SIG_IGN (which the kernel also overrides to the default
     * action for a synchronous fault -- returning would re-execute the
     * faulting instruction forever): restore the default disposition so
     * the re-executed instruction kills the process with the usual
     * signal exit status / core. */
    struct sigaction dfl;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    sigaction_fn real = real_sigaction_fn();
    if (real) real(signo, &dfl, NULL);
}

/* ---- signal-mask interception (hardening) ------------------------- *
 * A synchronous trap signal that is blocked when it fires is not queued:
 * the kernel resets the disposition to SIG_DFL and kills the process.
 * Daemons routinely block every signal in worker threads (sigfillset +
 * pthread_sigmask), so strip our trap signal from any mask the target
 * installs while libcov is active. The MT sync-broadcast signal is
 * stripped too: a peer that blocks it never acknowledges, and every
 * broadcast would wait out LIBCOV_SYNC_TIMEOUT_NS. */

static int filter_mask(int how, const sigset_t *set, sigset_t *copy) {
    if (!g_initialized || !set) return 0;
    if (how != SIG_BLOCK && how != SIG_SETMASK) return 0;
    int ss = sync_signo();
    if (!sigismember(set, LIBCOV_TRAP_SIGNO) && !(ss > 0 && sigismember(set, ss)))
        return 0;
    *copy = *set;
    sigdelset(copy, LIBCOV_TRAP_SIGNO);
    if (ss > 0) sigdelset(copy, ss);
    return 1;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
    REAL(sigmask_fn, "sigprocmask");
    if (!real_) { errno = ENOSYS; return -1; }
    sigset_t copy;
    if (filter_mask(how, set, &copy)) set = &copy;
    return real_(how, set, oldset);
}

int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) {
    sigmask_fn real = real_pthread_sigmask_fn();
    if (!real) return ENOSYS;
    sigset_t copy;
    if (filter_mask(how, set, &copy)) set = &copy;
    return real(how, set, oldset);
}

/* sighold(sig) is sigprocmask(SIG_BLOCK, {sig}) via an internal call. */
int sighold(int signo) {
    int ss = sync_signo();
    if (g_initialized && (signo == LIBCOV_TRAP_SIGNO || (ss > 0 && signo == ss)))
        return 0;
    REAL(signo_fn, "sighold");
    if (!real_) { errno = ENOSYS; return -1; }
    return real_(signo);
}

/* sigsuspend installs its mask for the wait; handlers that run meanwhile
 * inherit it, so the trap signal must not be in it either. */
int sigsuspend(const sigset_t *mask) {
    REAL(sigsuspend_fn, "sigsuspend");
    if (!real_) { errno = ENOSYS; return -1; }
    sigset_t copy;
    if (filter_mask(SIG_SETMASK, mask, &copy)) mask = &copy;
    return real_(mask);
}

/* ---- trap-encoding self-test --------------------------------------- *
 * Execute each trap encoding this backend can write, once, from a scratch
 * page, with temporary handlers on every signal an illegal instruction
 * can plausibly raise, and check it arrives as LIBCOV_TRAP_SIGNO. Runs
 * before handler_install, single-threaded, from the constructor. */

#if defined(__powerpc64__) && (!defined(_CALL_ELF) || _CALL_ELF != 2)
/* ELFv1: a function pointer is a descriptor, not a code address. */
#  define LIBCOV_SELFTEST_SUPPORTED 0
#else
#  define LIBCOV_SELFTEST_SUPPORTED 1
#endif

#if LIBCOV_SELFTEST_SUPPORTED
static sigjmp_buf            g_probe_jmp;
static volatile sig_atomic_t g_probe_signo;

static void probe_handler(int signo) {
    g_probe_signo = signo;
    siglongjmp(g_probe_jmp, 1);
}

static const int k_probe_signals[] = {
    SIGILL, SIGTRAP, SIGSEGV, SIGBUS, SIGFPE, SIGSYS, LIBCOV_TRAP_SIGNO,
};
#define N_PROBE_SIGNALS (sizeof k_probe_signals / sizeof k_probe_signals[0])

/* Returns the signal raised by the `len`-byte encoding, or -1 if the
 * probe could not run (e.g. the kernel refuses an executable page). */
static int probe_encoding(uint8_t len) {
    long ps = sysconf(_SC_PAGESIZE);
    uint8_t *page = mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return -1;
    memcpy(page, libcov_arch_illegal_bytes(len), len);
    __builtin___clear_cache((char *)page, (char *)page + len);
    if (mprotect(page, (size_t)ps, PROT_READ | PROT_EXEC) != 0) {
        munmap(page, (size_t)ps);
        return -1;
    }
    uintptr_t entry = (uintptr_t)page;
#if defined(__arm__)
    if (len == 2) entry |= 1;   /* the 2-byte encoding is Thumb */
#endif

    sigaction_fn real = real_sigaction_fn();
    struct sigaction sa, old[N_PROBE_SIGNALS];
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = probe_handler;
    sa.sa_flags   = SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigset_t unblock, saved_mask;
    sigemptyset(&unblock);
    for (size_t i = 0; i < N_PROBE_SIGNALS; i++) {
        real(k_probe_signals[i], &sa, &old[i]);
        sigaddset(&unblock, k_probe_signals[i]);
    }
    sigprocmask(SIG_UNBLOCK, &unblock, &saved_mask);

    g_probe_signo = 0;
    if (sigsetjmp(g_probe_jmp, 1) == 0)
        ((void (*)(void))entry)();

    sigprocmask(SIG_SETMASK, &saved_mask, NULL);
    for (size_t i = N_PROBE_SIGNALS; i-- > 0; )
        real(k_probe_signals[i], &old[i], NULL);
    munmap(page, (size_t)ps);
    return g_probe_signo;
}
#endif

static int trap_selftest(void) {
#if !LIBCOV_SELFTEST_SUPPORTED
    libcov_logf("init: trap self-test not supported on this ABI; skipped");
    return 0;
#else
    uint8_t lens[2] = { libcov_min_patch_len, libcov_max_patch_len };
    size_t  nlens   = (lens[0] == lens[1]) ? 1 : 2;
    for (size_t i = 0; i < nlens; i++) {
        int got = probe_encoding(lens[i]);
        if (got < 0) {
            libcov_logf("init: trap self-test could not run (no executable "
                        "scratch page); skipped");
            return 0;
        }
        if (got != LIBCOV_TRAP_SIGNO) {
            libcov_logf("init: ERROR -- the %u-byte %s trap encoding raises "
                        "signal %d, but LIBCOV_TRAP_SIGNO is %d. Change "
                        "LIBCOV_TRAP_SIGNO or the encoding in "
                        "src/tunables_*.h so they agree.",
                        (unsigned)lens[i], libcov_arch_name, got,
                        LIBCOV_TRAP_SIGNO);
            return -1;
        }
    }
    libcov_logf("init: trap self-test ok (signal %d)", LIBCOV_TRAP_SIGNO);
    return 0;
#endif
}

/* ---- ST library in a multi-threaded process ------------------------- *
 * libcov_st.so is unsafe with more than one thread in ANY mode: each
 * arm/disarm mprotects the code page RW (no X) for a moment, so a peer
 * thread executing on that page faults, and leapfrog state is a plain
 * global. Warn once, at init if threads already exist, or when the target
 * creates its first one. */
#if defined(LIBCOV_THREADING_ST)
static void st_warn_threads(const char *why) {
    static int warned;
    if (warned) return;
    warned = 1;
    libcov_logf("WARNING -- libcov_st.so is running in a multi-threaded "
                "process (%s). ST patch writes aren't atomic (and with "
                "LIBCOV_ST_PATCH=mprotect make code pages briefly "
                "non-executable), and its leapfrog state is not thread-safe, "
                "so peer threads can crash or lose coverage: use "
                "libcov_mt.so with a --threading mt patch list.", why);
}

static void st_check_threads(void) {
    FILE *f = fopen("/proc/self/status", "re");
    if (!f) return;
    char line[128];
    int threads = 0;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "Threads: %d", &threads) == 1) break;
    fclose(f);
    if (threads > 1) st_warn_threads("Threads > 1 at init");
}

typedef int (*pthread_create_fn)(pthread_t *, const pthread_attr_t *,
                                 void *(*)(void *), void *);

int pthread_create(pthread_t *t, const pthread_attr_t *attr,
                   void *(*fn)(void *), void *arg) {
    static pthread_create_fn real;
    if (!real) real = (pthread_create_fn)dlsym(RTLD_NEXT, "pthread_create");
    if (!real) return EAGAIN;
    if (g_initialized) st_warn_threads("pthread_create called");
    return real(t, attr, fn, arg);
}
#endif
