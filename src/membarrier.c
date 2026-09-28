#define _GNU_SOURCE
#include "membarrier.h"
#include "util.h"
#include "tunables.h"   /* LIBCOV_SYNC_SIGNO, LIBCOV_SYNC_TIMEOUT_NS */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

/* The Linux constants live in <linux/membarrier.h>. That header isn't always
 * present (e.g. minimal toolchains). Provide our own copy of the bits we
 * use; the values are kernel-ABI-stable. */
#ifndef MEMBARRIER_CMD_QUERY
#define MEMBARRIER_CMD_QUERY 0
#endif
#ifndef MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE (1 << 7)
#endif
#ifndef MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1 << 8)
#endif

enum { SYNC_NONE, SYNC_MEMBARRIER, SYNC_SIGNAL };
static int g_sync = SYNC_NONE;          /* atomic: SIGNAL can drop to NONE */

/* ---- signal broadcast fallback ------------------------------------- *
 * Each broadcast sends LIBCOV_SYNC_SIGNO to every other thread with
 * rt_tgsigqueueinfo, tagged with a cookie and the broadcast's generation,
 * and waits (bounded) for each to acknowledge from its handler. Taking a
 * signal and returning from the handler is a kernel exception return on
 * that thread (iret / ERET / rfid / sret), which is context-synchronizing.
 * Broadcasts are serialized so acknowledgements are counted exactly, and
 * coalesced: a caller whose writes were already done when some later
 * broadcast started is covered by that one and skips its own. Under
 * contention a queue of waiting trappers costs one or two broadcasts,
 * not one each. */

#define SYNC_COOKIE 0x4C43u            /* "LC" in the upper 16 bits of sival_int */

static pid_t    g_pid;
static uid_t    g_uid;
static uint32_t g_bcast_gen;            /* last started; written under the lock */
static uint32_t g_bcast_done;           /* last completed */
static unsigned g_acks;                 /* atomic */
static uint8_t  g_bcast_lock;

typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);
static sigaction_fn g_real_sigaction;

static long sys_membarrier(int cmd, unsigned int flags) {
#ifdef SYS_membarrier
    return syscall(SYS_membarrier, cmd, flags);
#else
    (void)cmd; (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

/* Stop using the signal and give it back to the target with the default
 * disposition. Callers log (outside a signal handler) or re-raise. */
static void sync_signal_release(void) {
    __atomic_store_n(&g_sync, SYNC_NONE, __ATOMIC_RELEASE);
    struct sigaction dfl;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    if (g_real_sigaction) g_real_sigaction(LIBCOV_SYNC_SIGNO, &dfl, NULL);
}

static void sync_handler(int signo, siginfo_t *si, void *uc) {
    (void)uc;
    int saved_errno = errno;
    if (si && si->si_code == SI_QUEUE && si->si_pid == g_pid &&
        ((unsigned)si->si_value.sival_int >> 16) == SYNC_COOKIE) {
        uint32_t gen = __atomic_load_n(&g_bcast_gen, __ATOMIC_ACQUIRE);
        if (((unsigned)si->si_value.sival_int & 0xFFFFu) == (gen & 0xFFFFu))
            __atomic_add_fetch(&g_acks, 1, __ATOMIC_RELEASE);
        errno = saved_errno;
        return;
    }
    /* Not ours: the target sent it without a handler of its own (default
     * action). Hand the signal back and let the kernel act on it. */
    sync_signal_release();
    siginfo_t again;
    memcpy(&again, si, sizeof again);
    syscall(SYS_rt_tgsigqueueinfo, g_pid, (pid_t)syscall(SYS_gettid), signo, &again);
    errno = saved_errno;
}

static int sync_signal_init(void) {
    g_real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    if (!g_real_sigaction) g_real_sigaction = (sigaction_fn)dlsym(RTLD_DEFAULT, "sigaction");
    if (!g_real_sigaction) {
        libcov_logf("membarrier: cannot resolve real sigaction");
        return -1;
    }
    struct sigaction old;
    if (g_real_sigaction(LIBCOV_SYNC_SIGNO, NULL, &old) == 0 &&
        ((old.sa_flags & SA_SIGINFO) ? old.sa_sigaction != NULL
                                     : old.sa_handler != SIG_DFL)) {
        libcov_logf("membarrier: WARNING -- the target already handles signal %d "
                    "(LIBCOV_SYNC_SIGNO); signal broadcast fallback disabled. "
                    "Rebuild with -DLIBCOV_SYNC_SIGNO=<unused signal>.",
                    LIBCOV_SYNC_SIGNO);
        return -1;
    }
    g_pid = getpid();
    g_uid = getuid();
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sync_handler;
    sa.sa_flags     = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (g_real_sigaction(LIBCOV_SYNC_SIGNO, &sa, NULL) != 0) {
        libcov_logf("membarrier: sigaction(%d): %s", LIBCOV_SYNC_SIGNO, strerror(errno));
        return -1;
    }
    return 0;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

struct linux_dirent64 {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

/* Async-signal-safe: open + getdents64 + rt_tgsigqueueinfo, no libc
 * allocation. Runs inside the trap handler, so errno is preserved. */
static void sync_signal_broadcast(void) {
    int saved_errno = errno;
    /* Any broadcast numbered `want` or later starts after this point, so
     * after our code writes (seq_cst orders the stores before the load). */
    uint32_t want = __atomic_load_n(&g_bcast_gen, __ATOMIC_SEQ_CST) + 1;
    unsigned spins = 0;
    while (__atomic_exchange_n(&g_bcast_lock, 1, __ATOMIC_ACQUIRE))
        libcov_spin_backoff(&spins);
    if ((int32_t)(__atomic_load_n(&g_bcast_done, __ATOMIC_ACQUIRE) - want) >= 0) {
        __atomic_store_n(&g_bcast_lock, 0, __ATOMIC_RELEASE);
        errno = saved_errno;
        return;
    }

    int fd = open("/proc/self/task", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {                       /* e.g. after chroot: nothing to do */
        __atomic_store_n(&g_bcast_lock, 0, __ATOMIC_RELEASE);
        errno = saved_errno;
        return;
    }
    uint32_t gen = g_bcast_gen + 1;
    __atomic_store_n(&g_bcast_gen, gen, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_acks, 0, __ATOMIC_RELEASE);

    pid_t self = (pid_t)syscall(SYS_gettid);
    siginfo_t info;
    memset(&info, 0, sizeof info);
    info.si_signo = LIBCOV_SYNC_SIGNO;
    info.si_code  = SI_QUEUE;
    info.si_pid   = g_pid;
    info.si_uid   = g_uid;
    info.si_value.sival_int = (int)(SYNC_COOKIE << 16 | (gen & 0xFFFFu));

    unsigned sent = 0;
    char buf[1024] __attribute__((aligned(8)));
    for (;;) {
        long n = syscall(SYS_getdents64, fd, buf, sizeof buf);
        if (n <= 0) break;
        for (long off = 0; off < n; ) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + off);
            off += d->d_reclen;
            pid_t tid = 0;
            const char *p = d->d_name;
            if (*p < '0' || *p > '9') continue;
            while (*p >= '0' && *p <= '9') tid = tid * 10 + (*p++ - '0');
            if (tid == self) continue;
            if (syscall(SYS_rt_tgsigqueueinfo, g_pid, tid, LIBCOV_SYNC_SIGNO, &info) == 0)
                sent++;                 /* ESRCH: exited meanwhile */
        }
    }
    close(fd);

    if (sent) {
        uint64_t deadline = now_ns() + LIBCOV_SYNC_TIMEOUT_NS;
        spins = 0;
        while (__atomic_load_n(&g_acks, __ATOMIC_ACQUIRE) < sent &&
               __atomic_load_n(&g_sync, __ATOMIC_RELAXED) == SYNC_SIGNAL &&
               now_ns() < deadline)
            libcov_spin_backoff(&spins);
    }
    __atomic_store_n(&g_bcast_done, gen, __ATOMIC_RELEASE);
    __atomic_store_n(&g_bcast_lock, 0, __ATOMIC_RELEASE);
    errno = saved_errno;
}

/* ---- public ----------------------------------------------------------- */

void membarrier_init(void) {
    static int done;
    if (done) return;
    done = 1;
    const char *fb = getenv("LIBCOV_SYNC_FALLBACK");
    int force = fb && !strcmp(fb, "tgkill");
    int allow = !(fb && !strcmp(fb, "off"));
    if (fb && *fb && !force && allow && strcmp(fb, "auto"))
        libcov_logf("membarrier: unknown LIBCOV_SYNC_FALLBACK=%s; using auto", fb);

    if (!force) {
        long supported = sys_membarrier(MEMBARRIER_CMD_QUERY, 0);
        if (supported < 0) {
            libcov_logf("membarrier: kernel does not support membarrier (errno=%d)",
                        errno);
        } else if (!((unsigned long)supported &
                     MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)) {
            libcov_logf("membarrier: kernel lacks PRIVATE_EXPEDITED_SYNC_CORE "
                        "(supported_mask=0x%lx)", (unsigned long)supported);
        } else if (sys_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
                                  0) < 0) {
            libcov_logf("membarrier: register PRIVATE_EXPEDITED_SYNC_CORE: errno=%d",
                        errno);
        } else {
            g_sync = SYNC_MEMBARRIER;
            libcov_logf("membarrier: PRIVATE_EXPEDITED_SYNC_CORE active");
            return;
        }
    }
    if (!allow) {
        libcov_logf("membarrier: LIBCOV_SYNC_FALLBACK=off; no cross-core sync");
        return;
    }
    if (sync_signal_init() != 0) return;
    g_sync = SYNC_SIGNAL;
    libcov_logf("membarrier: tgkill broadcast fallback active (signal %d, "
                "timeout %lluns)%s. WARNING -- peer threads take this signal "
                "after every patch: calls that don't restart after a handler "
                "(epoll_wait, poll/select with a timeout, nanosleep, ...) can "
                "return EINTR in the target. LIBCOV_SYNC_FALLBACK=off disables it.",
                LIBCOV_SYNC_SIGNO, (unsigned long long)LIBCOV_SYNC_TIMEOUT_NS,
                force ? " (forced)" : "");
}

void membarrier_sync_core(void) {
    switch (__atomic_load_n(&g_sync, __ATOMIC_ACQUIRE)) {
    case SYNC_MEMBARRIER:
        (void)sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0);
        break;
    case SYNC_SIGNAL:
        sync_signal_broadcast();
        break;
    default:
        /* No cross-core sync: the caller already issued clear_cache for
         * the modified range; peers pick the change up at their next
         * context-synchronizing event (documented in membarrier.h). */
        break;
    }
}

int membarrier_has_sync_core(void) {
    return __atomic_load_n(&g_sync, __ATOMIC_RELAXED) != SYNC_NONE;
}

int membarrier_sync_signo(void) {
    return __atomic_load_n(&g_sync, __ATOMIC_RELAXED) == SYNC_SIGNAL
         ? LIBCOV_SYNC_SIGNO : -1;
}

void membarrier_release_signal(const char *why) {
    if (__atomic_load_n(&g_sync, __ATOMIC_RELAXED) != SYNC_SIGNAL) return;
    sync_signal_release();
    libcov_logf("membarrier: WARNING -- %s signal %d (LIBCOV_SYNC_SIGNO); "
                "handing it back and disabling the signal broadcast fallback. "
                "Rebuild with -DLIBCOV_SYNC_SIGNO=<unused signal>.",
                why, LIBCOV_SYNC_SIGNO);
}
