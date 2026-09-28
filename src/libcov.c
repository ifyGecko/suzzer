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

/* Storage for what the target *thinks* its trap-signal handler is. */
static struct sigaction g_target_trap_sa;
static int              g_target_trap_sa_valid = 0;

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
    libcov_logf("init: coverage model=%s n_sites=%zu map_size=%zu",
                LIBCOV_COVERAGE_MODEL_SITE ? "site" : "hash", n_sites, map_size);
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
    struct sigaction prev;
    memset(&prev, 0, sizeof prev);
    if (handler_install(mode, &prev) != 0) {
        init_fail("handler_install failed, library inert");
        return;
    }
    g_target_trap_sa = prev;
    g_target_trap_sa_valid = 1;
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
    const char *rearm = getenv("LIBCOV_BOUNDARY_REARM");
    int no_rearm = !rearm || !*rearm || !strcmp(rearm, "none");
    if (blist && *blist && mode == LIBCOV_MODE_ONESHOT && no_rearm &&
        !env_true("LIBCOV_ALLOW_ONESHOT_NOREARM")) {
        init_fail("ERROR -- MODE=oneshot with BOUNDARY_REARM=none would leave "
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

int sigaction(int signo, const struct sigaction *act, struct sigaction *oldact) {
    sigaction_fn real = real_sigaction_fn();
    if (!real) { errno = ENOSYS; return -1; }
#if defined(LIBCOV_THREADING_MT)
    if (g_initialized && act && signo == sync_signo()) {
        int dfl = (act->sa_flags & SA_SIGINFO) ? act->sa_sigaction == NULL
                                               : act->sa_handler == SIG_DFL;
        if (!dfl) membarrier_release_signal("the target installed a handler for");
    }
#endif
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
#if defined(LIBCOV_THREADING_MT)
    if (g_initialized && signo == sync_signo() && h != SIG_DFL)
        membarrier_release_signal("the target installed a handler for");
#endif
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

void libcov_chain_trap(int signo, siginfo_t *info, void *uctx) {
    /* g_target_trap_sa holds the pre-init disposition (seeded in
     * libcov_init) or whatever the target installed later through the
     * sigaction()/signal() interposers above. */
    struct sigaction sa = g_target_trap_sa;
    int have = g_target_trap_sa_valid;

    if (have && (sa.sa_flags & SA_SIGINFO) && sa.sa_sigaction) {
        if (sa.sa_flags & SA_RESETHAND) {
            memset(&g_target_trap_sa, 0, sizeof g_target_trap_sa);
            g_target_trap_sa.sa_handler = SIG_DFL;
        }
        sa.sa_sigaction(signo, info, uctx);
        return;
    }
    if (have && !(sa.sa_flags & SA_SIGINFO) &&
        sa.sa_handler != SIG_DFL && sa.sa_handler != SIG_IGN) {
        if (sa.sa_flags & SA_RESETHAND) {
            memset(&g_target_trap_sa, 0, sizeof g_target_trap_sa);
            g_target_trap_sa.sa_handler = SIG_DFL;
        }
        sa.sa_handler(signo);
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

typedef int (*sigmask_fn)(int, const sigset_t *, sigset_t *);

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
    static sigmask_fn real;
    if (!real) real = (sigmask_fn)dlsym(RTLD_NEXT, "sigprocmask");
    if (!real) { errno = ENOSYS; return -1; }
    sigset_t copy;
    if (filter_mask(how, set, &copy)) set = &copy;
    return real(how, set, oldset);
}

int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) {
    static sigmask_fn real;
    if (!real) real = (sigmask_fn)dlsym(RTLD_NEXT, "pthread_sigmask");
    if (!real) return ENOSYS;
    sigset_t copy;
    if (filter_mask(how, set, &copy)) set = &copy;
    return real(how, set, oldset);
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
                "process (%s). ST patching makes code pages briefly "
                "non-executable and its leapfrog state is not thread-safe, "
                "so peer threads can crash: use libcov_mt.so with a "
                "--threading mt patch list.", why);
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
