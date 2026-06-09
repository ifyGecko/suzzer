/*
 * libfaultinj -- deterministic LD_PRELOAD libc-level fault injector for
 * ===========    suzzer.
 *
 * PURPOSE
 * -------
 * Inject controlled, reproducible failures into a target process's libc
 * calls so a fuzzer (or a human) can exercise the error-handling code
 * paths that normal fuzzers like AFL++ / honggfuzz / libFuzzer never
 * reach. The target binary is unmodified -- you LD_PRELOAD this .so,
 * set a handful of LIBFAULTINJ_* environment variables, and the
 * library intercepts a curated set of libc functions, occasionally
 * returning failure instead of calling through to libc. Every fault
 * decision is a pure function of (LIBFAULTINJ_SEED, class, call_index)
 * so reproducing a crash is "same env + same input + same target".
 *
 * COMPOSABILITY
 * -------------
 * libfaultinj is engineered to coexist with the other LD_PRELOAD
 * libraries in the suzzer ecosystem:
 *
 *   libcov.so       coverage. We do not hook anything libcov uses
 *                   in its hot path (sigaction, mprotect, mmap,
 *                   /proc/self/mem writes), so a libcov + libfaultinj
 *                   chain is safe regardless of LD_PRELOAD order.
 *
 *   libforksrv.so   fork-server park. We auto-detect the LIBFORKSRV_*
 *                   ctl/sts fds from env and never fault on them; the
 *                   protocol stays intact across iterations.
 *
 *   libdemalloc.so  heap corruption catcher. We do NOT hook
 *                   malloc/calloc/realloc/free in v1 because the
 *                   composition with libdemalloc needs a careful
 *                   decision (return NULL after libdemalloc's guard
 *                   page setup? before? skip when libdemalloc is
 *                   loaded?) that isn't yet locked in. Adding alloc
 *                   classes later only requires extending
 *                   FAULTINJ_CLASSES in faultinj_classes.h.
 *
 * V1 HOOKED FUNCTIONS (14)
 * ------------------------
 *   open    open openat
 *   read    read pread
 *   write   write pwrite
 *   close   close
 *   recv    recv recvfrom
 *   send    send sendto
 *   socket  socket
 *   accept  accept accept4
 *
 * Deliberately deferred: recvmsg/sendmsg/readv/writev (vectorized,
 * buffered fread/fwrite (stdio layer accounting), stat/access (low
 * yield), getaddrinfo (threaded), bind/listen/connect (init-only),
 * and the entire alloc class (see libdemalloc note above).
 *
 * THE DETERMINISM CONTRACT
 * ------------------------
 * Given the same:
 *
 *   - target binary
 *   - input on stdin / argv / network
 *   - LIBFAULTINJ_SEED
 *   - LIBFAULTINJ_PROB
 *   - LIBFAULTINJ_MAX_FAULTS
 *   - LIBFAULTINJ_WARMUP
 *   - LIBFAULTINJ_ENABLE / LIBFAULTINJ_DISABLE
 *
 * the library will inject the exact same fault sequence. The decision
 * for call N of class C is fi_roll(seed, C, N) -- a pure function
 * with no global PRNG state to advance, so out-of-order calls from
 * other threads can't perturb each other's decisions and the
 * fork-server "execve once, fork N times" pattern is reproducible
 * across iterations as long as the call ordering inside the iter is
 * deterministic (which is the target's responsibility, not ours).
 *
 * REPRODUCTION (no separate replay tool)
 * --------------------------------------
 * The library IS the replay tool. To reproduce a crash:
 *
 *     LD_PRELOAD=./libfaultinj.so \
 *     LIBFAULTINJ_SEED=0xdeadbeef \
 *     LIBFAULTINJ_PROB=0.001 \
 *     LIBFAULTINJ_MAX_FAULTS=1 \
 *     ./your_target < crashing_input.bin
 *
 * No shm, no plan files, no separate binary. Crashes save these
 * env vars alongside the input bytes; replay reads them back.
 *
 * SAFETY FILTERS
 * --------------
 *   - stdio (fd 0/1/2) skipped by default; opt out via
 *     LIBFAULTINJ_SKIP_STDIO=0.
 *   - LIBFORKSRV_CTLFD / LIBFORKSRV_STSFD auto-skipped if those
 *     env vars are set -- this keeps the fork server protocol
 *     intact.
 *   - The log fd (LIBFAULTINJ_LOG / LIBFAULTINJ_LOG_FD) is skipped
 *     to prevent recursion through our write() hook.
 *   - Any extra fd the user wants protected: LIBFAULTINJ_SKIP_FDS.
 *
 * LOGGING
 * -------
 * Optional. When LIBFAULTINJ_LOG=<path> or LIBFAULTINJ_LOG_FD=<n> is
 * set, every injection writes a single line. The formatter is
 * async-signal-safe (no malloc, no printf, no errno mutation) so the
 * logger is safe to call from any context where syscalls are legal.
 *
 * THREADING
 * ---------
 * All per-class call counters are __atomic_fetch_add(..., RELAXED)
 * so a multithreaded target won't race-corrupt them. The DECISION
 * for "call_idx = N of class C" is a pure function of (seed, C, N)
 * so the choice (errno + mode) for that call is reproducible. What
 * is NOT reproducible across runs is the global INTERLEAVING of
 * threads -- but the set of (cls, idx) injection points is. Tighter
 * per-thread determinism (a __thread call counter) is deferred to
 * v2.
 *
 * SOURCE
 * ------
 * Inspired by FATE/EIO failure-injection literature and AFL++'s
 * libdislocator design pattern (LD_PRELOAD + abort()-on-bug). All
 * code original. No external library deps beyond libc + -ldl.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "faultinj_classes.h"
#include "faultinj_prng.h"

/* ================================================================== */
/* Global state                                                       */
/* ================================================================== */

/* Maximum number of fds the user can pin in the "do not fault me"
 * list. Eight ought to cover {0,1,2, ctl, sts, log, slack, slack}
 * with room to spare; if a target actually needs more, bumping this
 * is a one-line change. Kept as a small fixed array (linear search)
 * because the alternative -- a hash or bitset -- adds code for no
 * measurable speedup at this size. */
#define FI_MAX_SKIP_FDS 16

/* Single global state struct so the loader places it in one BSS
 * region and the constructor initializes it with a single memset.
 * Marked volatile-by-discipline: only fi_init writes the non-atomic
 * fields, and only after env parsing completes; readers in the hot
 * path see published values via the same execution order. */
struct fi_state {
    /* --- decision parameters (set once in constructor) --- */
    uint64_t seed;             /* LIBFAULTINJ_SEED (0 == disabled)    */
    uint32_t prob_thresh_32;   /* probability * 2^32, integer compare */
    uint64_t warmup;           /* LIBFAULTINJ_WARMUP                  */
    uint64_t max_faults;       /* LIBFAULTINJ_MAX_FAULTS              */
    int      armed;            /* 1 iff seed != 0 after parsing       */

    /* --- per-class state --- */
    /* enabled bit (post LIBFAULTINJ_ENABLE / DISABLE resolution) */
    uint8_t  cls_enabled[FI_CLS_MAX];
    /* monotonic call counter; never reset. Atomic for MT safety. */
    uint64_t cls_count[FI_CLS_MAX];

    /* --- global budget --- */
    uint64_t faults_so_far;    /* atomic                              */

    /* --- safety: fds we never fault on --- */
    int      skip_fds[FI_MAX_SKIP_FDS];
    int      skip_fd_count;

    /* --- logging --- */
    int      log_fd;           /* -1 when disabled                    */
};

static struct fi_state fi_state;

/* ================================================================== */
/* Real-function pointers (resolved once in constructor)              */
/* ================================================================== */

/* Resolving lazily on first call would dodge any constructor-order
 * issues with libcov, but libcov doesn't hook anything we resolve,
 * so eager resolution is safe AND removes the per-call NULL check
 * from the hot path. dlsym(RTLD_NEXT, ...) returns NULL if libc
 * doesn't export the symbol on this platform; we tolerate that for
 * the GNU-only entrypoints (accept4, etc.) -- the hook just calls
 * through to a fallback or returns -1/ENOSYS. */

static int     (*real_open)    (const char *, int, ...);
static int     (*real_openat)  (int, const char *, int, ...);
static ssize_t (*real_read)    (int, void *, size_t);
static ssize_t (*real_pread)   (int, void *, size_t, off_t);
static ssize_t (*real_write)   (int, const void *, size_t);
static ssize_t (*real_pwrite)  (int, const void *, size_t, off_t);
static int     (*real_close)   (int);
static ssize_t (*real_recv)    (int, void *, size_t, int);
static ssize_t (*real_recvfrom)(int, void *, size_t, int,
                                struct sockaddr *, socklen_t *);
static ssize_t (*real_send)    (int, const void *, size_t, int);
static ssize_t (*real_sendto)  (int, const void *, size_t, int,
                                const struct sockaddr *, socklen_t);
static int     (*real_socket)  (int, int, int);
static int     (*real_accept)  (int, struct sockaddr *, socklen_t *);
static int     (*real_accept4) (int, struct sockaddr *, socklen_t *, int);

/* ================================================================== */
/* Async-signal-safe logging                                          */
/* ================================================================== */

/* All log output goes through syscall(SYS_write, ...) -- not write(2)
 * -- so we bypass our own write() hook and any other LD_PRELOAD'd
 * write shim in the chain. This keeps the logger reentrancy-free
 * without needing a TLS recursion guard. */
static void fi_raw_write(const void *buf, size_t n)
{
    if (fi_state.log_fd < 0) return;
    /* syscall() is itself a libc function but is not commonly
     * overridden by LD_PRELOAD shims (we don't, libcov doesn't,
     * libdemalloc doesn't). Worst case if someone DID override
     * it, the log line goes through their shim -- not a
     * correctness issue. */
    (void)syscall(SYS_write, fi_state.log_fd, buf, n);
}

/* Append a NUL-terminated string into [p, end), truncating if it
 * doesn't fit. Returns the new cursor. No heap allocation. */
static char *fi_append_str(char *p, char *end, const char *s)
{
    while (*s && p < end) *p++ = *s++;
    return p;
}

/* Append a base-10 decimal of v into [p, end). */
static char *fi_append_u64(char *p, char *end, uint64_t v)
{
    char tmp[24];
    int  i = 0;
    if (v == 0) tmp[i++] = '0';
    while (v) { tmp[i++] = '0' + (v % 10); v /= 10; }
    while (i > 0 && p < end) *p++ = tmp[--i];
    return p;
}

/* Append a base-16 representation of v with a "0x" prefix. */
static char *fi_append_x64(char *p, char *end, uint64_t v)
{
    static const char hex[] = "0123456789abcdef";
    char tmp[16];
    int  i = 0;
    if (v == 0) tmp[i++] = '0';
    while (v) { tmp[i++] = hex[v & 0xf]; v >>= 4; }
    p = fi_append_str(p, end, "0x");
    while (i > 0 && p < end) *p++ = tmp[--i];
    return p;
}

/* One line per injection. Format:
 *
 *   faultinj seed=0x<hex> cls=<name> idx=<dec> errno=<NAME>(<int>) mode=<name>
 *
 * The line is built into a stack buffer and emitted with a single
 * write() so MT log output isn't interleaved at the line level. */
static void fi_log_injection(enum fi_class cls,
                             uint64_t       idx,
                             int            err,
                             enum fi_mode   mode)
{
    if (fi_state.log_fd < 0) return;

    char buf[160];
    char *p   = buf;
    char *end = buf + sizeof(buf);

    p = fi_append_str(p, end, "faultinj seed=");
    p = fi_append_x64(p, end, fi_state.seed);
    p = fi_append_str(p, end, " cls=");
    p = fi_append_str(p, end, fi_class_table[cls].name);
    p = fi_append_str(p, end, " idx=");
    p = fi_append_u64(p, end, idx);
    p = fi_append_str(p, end, " errno=");
    p = fi_append_str(p, end, fi_errno_name(err));
    p = fi_append_str(p, end, "(");
    p = fi_append_u64(p, end, (uint64_t)err);
    p = fi_append_str(p, end, ") mode=");
    p = fi_append_str(p, end, fi_mode_name(mode));
    if (p < end) *p++ = '\n';

    fi_raw_write(buf, (size_t)(p - buf));
}

/* ================================================================== */
/* Env parsing helpers                                                */
/* ================================================================== */

/* Parse an unsigned 64-bit int. Supports "0x..." hex, decimal, and
 * leading "+". Returns 0 on parse failure (caller's default sticks
 * if it pre-initialized the dest). */
static uint64_t fi_parse_u64(const char *s)
{
    if (!s || !*s) return 0;
    char *end = NULL;
    /* base 0: strtoull autodetects 0x prefix. */
    unsigned long long v = strtoull(s, &end, 0);
    if (end == s) return 0;
    return (uint64_t)v;
}

/* Parse a probability in [0.0, 1.0]; clamps to range. */
static double fi_parse_prob(const char *s)
{
    if (!s || !*s) return 0.0;
    char *end = NULL;
    double v = strtod(s, &end);
    if (end == s) return 0.0;
    if (v < 0.0) v = 0.0;
    if (v > 1.0) v = 1.0;
    return v;
}

/* Add fd to the skip list, no-op if already there or list is full. */
static void fi_add_skip_fd(int fd)
{
    if (fd < 0) return;
    for (int i = 0; i < fi_state.skip_fd_count; i++)
        if (fi_state.skip_fds[i] == fd) return;
    if (fi_state.skip_fd_count < FI_MAX_SKIP_FDS)
        fi_state.skip_fds[fi_state.skip_fd_count++] = fd;
}

/* Linear-search membership test; tiny list so this is cache-warm and
 * faster than any hash-set we could fit in our memory budget. */
static int fi_fd_is_protected(int fd)
{
    for (int i = 0; i < fi_state.skip_fd_count; i++)
        if (fi_state.skip_fds[i] == fd) return 1;
    return 0;
}

/* Look up a class by lowercase name. Returns -1 if unknown. */
static int fi_class_from_name(const char *s, size_t len)
{
    for (int i = 0; i < FI_CLS_MAX; i++) {
        const char *n  = fi_class_table[i].name;
        size_t      nl = strlen(n);
        if (nl == len && memcmp(n, s, len) == 0) return i;
    }
    return -1;
}

/* Walk a comma-separated env string; call on_token() for each
 * non-empty token with a pointer + length (no NUL-termination). */
static void fi_split_csv(const char *csv,
                         void (*on_token)(const char *, size_t))
{
    if (!csv) return;
    const char *p = csv;
    while (*p) {
        const char *start = p;
        while (*p && *p != ',') p++;
        size_t len = (size_t)(p - start);
        if (len > 0) on_token(start, len);
        if (*p == ',') p++;
    }
}

static void fi_enable_only_cb(const char *s, size_t len)
{
    int c = fi_class_from_name(s, len);
    if (c >= 0) fi_state.cls_enabled[c] = 1;
}

static void fi_disable_cb(const char *s, size_t len)
{
    int c = fi_class_from_name(s, len);
    if (c >= 0) fi_state.cls_enabled[c] = 0;
}

static void fi_skip_fds_cb(const char *s, size_t len)
{
    /* Copy to a small stack buffer so we can strtol() it. CSV tokens
     * are bounded by env-var length; 32 chars per int is overkill. */
    char tmp[32];
    if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
    memcpy(tmp, s, len);
    tmp[len] = 0;
    char *end = NULL;
    long v = strtol(tmp, &end, 10);
    if (end != tmp && v >= 0) fi_add_skip_fd((int)v);
}

/* ================================================================== */
/* The decision function                                              */
/* ================================================================== */

/* Output of fi_decide(): when injected != 0, the hook should fail
 * with the given errno + mode. roll lets the hook compute mode-
 * dependent extras (e.g. short read length) without re-rolling. */
struct fi_decision {
    int          injected;
    int          err;
    enum fi_mode mode;
    uint64_t     roll;
    uint64_t     call_idx;
};

/* Decide whether and how to fault one call. Pure function of
 * (fi_state.seed, cls, atomic call counter), with the budget check
 * the only side-effecting branch. The decision pattern itself is
 * INDEPENDENT of max_faults -- raising the budget reveals additional
 * latent faults from the same seed; lowering it just truncates the
 * sequence. This way bisecting a crash by tweaking MAX_FAULTS down
 * keeps the same prefix of injections in play. */
static int fi_decide(enum fi_class cls, int fd, struct fi_decision *out)
{
    /* Fast path: armed-bit check first. The branch predictor pins
     * it after the first miss, so untouched targets pay near zero. */
    if (!fi_state.armed) return 0;

    /* The per-class call counter is bumped unconditionally. This is
     * what gives us reproducible call ordering: the Nth open() in
     * the target always carries idx=N, regardless of whether prior
     * opens were faulted or how many of them there were. */
    uint64_t idx = __atomic_fetch_add(&fi_state.cls_count[cls], 1,
                                     __ATOMIC_RELAXED);

    if (!fi_state.cls_enabled[cls])         return 0;
    if (idx < fi_state.warmup)              return 0;
    if (fd >= 0 && fi_fd_is_protected(fd))  return 0;

    /* Roll the dice for this (seed, cls, idx). */
    uint64_t roll = fi_roll(fi_state.seed, (uint32_t)cls, idx);

    /* Compare the upper 32 bits of the roll against the scaled
     * probability threshold. (roll >> 32) is uniform in [0, 2^32).
     * Strictly less -> fault. */
    if ((uint32_t)(roll >> 32) >= fi_state.prob_thresh_32) return 0;

    /* Budget cap: only AFTER we've decided to fault. This makes the
     * fault DECISIONS independent of max_faults (raise the cap and
     * existing faults stay at the same call indices), at the cost
     * of one extra atomic increment per fault. faults_so_far can
     * over-count under MT contention beyond max_faults; harmless
     * since the comparison stays >= forever after. */
    uint64_t prev = __atomic_fetch_add(&fi_state.faults_so_far, 1,
                                      __ATOMIC_RELAXED);
    if (prev >= fi_state.max_faults) {
        /* Budget exhausted. We "spent" the increment but no fault
         * is actually applied. */
        return 0;
    }

    /* Pick errno + mode from the per-class pools. Each pool has a
     * power-of-two-or-less count so % is cheap; we explicitly do
     * NOT require power-of-two so adding errnos doesn't force a
     * rejection-sampling loop. */
    const struct fi_class_info *info = &fi_class_table[cls];
    out->err  = info->errnos[(roll        & 0xff) % info->errno_count];
    out->mode = info->modes [((roll >> 8) & 0xff) % info->mode_count];
    out->roll = roll;
    out->call_idx = idx;
    out->injected = 1;
    return 1;
}

/* ================================================================== */
/* Constructor: parse env, resolve symbols                            */
/* ================================================================== */

/* No explicit priority -- we want to load AFTER libcov's
 * constructor (priority 101) so libcov is fully armed before we
 * possibly start counting any libc calls libcov internally makes
 * during its own init. Default priority places us toward the end
 * of the queue, which is what we want. */
__attribute__((constructor))
static void fi_init(void)
{
    memset(&fi_state, 0, sizeof(fi_state));
    fi_state.log_fd = -1;

    /* Resolve real-function pointers. dlsym(RTLD_NEXT, ...) finds
     * the next definition in the loader's search order, which is
     * libc.so for everything we hook (none of the other suzzer
     * preloads shadow these symbols). */
    real_open     = dlsym(RTLD_NEXT, "open");
    real_openat   = dlsym(RTLD_NEXT, "openat");
    real_read     = dlsym(RTLD_NEXT, "read");
    real_pread    = dlsym(RTLD_NEXT, "pread");
    real_write    = dlsym(RTLD_NEXT, "write");
    real_pwrite   = dlsym(RTLD_NEXT, "pwrite");
    real_close    = dlsym(RTLD_NEXT, "close");
    real_recv     = dlsym(RTLD_NEXT, "recv");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    real_send     = dlsym(RTLD_NEXT, "send");
    real_sendto   = dlsym(RTLD_NEXT, "sendto");
    real_socket   = dlsym(RTLD_NEXT, "socket");
    real_accept   = dlsym(RTLD_NEXT, "accept");
    real_accept4  = dlsym(RTLD_NEXT, "accept4");

    /* --- knobs --- */
    fi_state.seed       = fi_parse_u64(getenv("LIBFAULTINJ_SEED"));
    fi_state.armed      = (fi_state.seed != 0);

    /* Probability: default 0.001 (1 in 1000 calls). */
    const char *probstr = getenv("LIBFAULTINJ_PROB");
    double prob = (probstr && *probstr) ? fi_parse_prob(probstr) : 0.001;
    /* Scale to a uint32 threshold: prob * 2^32 (truncated). prob ==
     * 1.0 caps at UINT32_MAX which means "fault every call"; prob
     * == 0 means "fault nothing" and the armed bit handles that. */
    if (prob >= 1.0)      fi_state.prob_thresh_32 = 0xFFFFFFFFu;
    else if (prob <= 0.0) fi_state.prob_thresh_32 = 0;
    else                  fi_state.prob_thresh_32 =
                              (uint32_t)(prob * 4294967296.0);

    /* MAX_FAULTS: default 1 (single-fault hypothesis). 0 means
     * "no faulting" (effectively disables -- explicit kill switch
     * separate from unset seed). */
    const char *mfs = getenv("LIBFAULTINJ_MAX_FAULTS");
    if (mfs && *mfs) fi_state.max_faults = fi_parse_u64(mfs);
    else             fi_state.max_faults = 1;

    /* WARMUP: default 0 (no skipping). */
    fi_state.warmup = fi_parse_u64(getenv("LIBFAULTINJ_WARMUP"));

    /* --- class enable/disable --- */
    /* Default: all classes enabled. LIBFAULTINJ_ENABLE switches to
     * "deny by default, allow the listed ones". LIBFAULTINJ_DISABLE
     * is applied AFTER ENABLE so a user can express "enable all
     * except close" with just DISABLE=close. */
    for (int i = 0; i < FI_CLS_MAX; i++) fi_state.cls_enabled[i] = 1;
    const char *en = getenv("LIBFAULTINJ_ENABLE");
    if (en && *en) {
        for (int i = 0; i < FI_CLS_MAX; i++) fi_state.cls_enabled[i] = 0;
        fi_split_csv(en, fi_enable_only_cb);
    }
    const char *dis = getenv("LIBFAULTINJ_DISABLE");
    if (dis && *dis) fi_split_csv(dis, fi_disable_cb);

    /* --- fd protection list --- */
    /* Stdio first (unless opted out). */
    const char *skip_stdio = getenv("LIBFAULTINJ_SKIP_STDIO");
    if (!skip_stdio || *skip_stdio != '0') {
        fi_add_skip_fd(0);
        fi_add_skip_fd(1);
        fi_add_skip_fd(2);
    }
    /* libforksrv ctl/sts -- auto-detected. */
    fi_add_skip_fd((int)fi_parse_u64(getenv("LIBFORKSRV_CTLFD")));
    fi_add_skip_fd((int)fi_parse_u64(getenv("LIBFORKSRV_STSFD")));
    /* User-specified extras. */
    fi_split_csv(getenv("LIBFAULTINJ_SKIP_FDS"), fi_skip_fds_cb);

    /* --- logging --- */
    /* LIBFAULTINJ_LOG_FD takes precedence (caller already has an fd
     * open), otherwise LIBFAULTINJ_LOG opens the file via real_open
     * directly -- NOT via our own open() hook, which would
     * (correctly) bump the OPEN call counter and possibly fault
     * our own log open. O_APPEND so concurrent fork-server iters
     * all write into the same file safely. O_CLOEXEC so the fd
     * doesn't leak across any execve()s the target performs. */
    const char *log_fd_str = getenv("LIBFAULTINJ_LOG_FD");
    const char *log_path   = getenv("LIBFAULTINJ_LOG");
    if (log_fd_str && *log_fd_str) {
        fi_state.log_fd = (int)fi_parse_u64(log_fd_str);
    } else if (log_path && *log_path && real_open) {
        int fd = real_open(log_path,
                           O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
        if (fd >= 0) fi_state.log_fd = fd;
    }

    /* The log fd, whatever its origin, must never get faulted by
     * our own write/pwrite hooks. */
    if (fi_state.log_fd >= 0) fi_add_skip_fd(fi_state.log_fd);
}

/* ================================================================== */
/* Hooks                                                              */
/* ================================================================== */
/*
 * Pattern for every hook below:
 *
 *   1. Resolve mode (for *at / variadic functions).
 *   2. Call fi_decide(class, fd_if_any, &decision).
 *   3. If injected: log + apply per-mode failure semantics.
 *   4. Otherwise pass-through to real_<func>.
 *
 * For variadic functions (open, openat) we extract the mode_t
 * argument with va_list because the underlying syscall takes the
 * full triple even when the user-facing signature is variadic.
 *
 * For "short" modes the byte count is `1 + roll % (count - 1)`
 * which is in [1, count - 1]. We deliberately never return 0 from
 * a short read/write because zero has different semantics (EOF for
 * read, no-op for write) covered by the FAIL_ZERO mode.
 */

/* ---------- open / openat ---------- */

int open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);  /* mode_t promotes to int   */
        va_end(ap);
    }

    struct fi_decision d;
    if (fi_decide(FI_CLS_OPEN, -1, &d)) {
        fi_log_injection(FI_CLS_OPEN, d.call_idx, d.err, FI_MODE_FAIL_NEG1);
        errno = d.err;
        return -1;
    }
    return real_open ? real_open(pathname, flags, mode)
                     : (errno = ENOSYS, -1);
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    struct fi_decision d;
    if (fi_decide(FI_CLS_OPEN, -1, &d)) {
        fi_log_injection(FI_CLS_OPEN, d.call_idx, d.err, FI_MODE_FAIL_NEG1);
        errno = d.err;
        return -1;
    }
    return real_openat ? real_openat(dirfd, pathname, flags, mode)
                       : (errno = ENOSYS, -1);
}

/* ---------- read / pread ---------- */

/* Compute the deterministic short length for an I/O call where the
 * caller asked for `count` bytes. Returns a value in [1, count - 1]
 * iff count >= 2; for count <= 1 the caller is expected to skip
 * SHORT mode entirely. */
static size_t fi_short_len(uint64_t roll, size_t count)
{
    if (count <= 1) return 0;
    return 1 + (size_t)((roll >> 16) % (count - 1));
}

ssize_t read(int fd, void *buf, size_t count)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_READ, fd, &d)) {
        fi_log_injection(FI_CLS_READ, d.call_idx, d.err, d.mode);
        switch (d.mode) {
        case FI_MODE_FAIL_NEG1:
            errno = d.err;
            return -1;
        case FI_MODE_FAIL_ZERO:
            /* Don't touch errno -- EOF is not an error. */
            return 0;
        case FI_MODE_FAIL_SHORT: {
            size_t shortn = fi_short_len(d.roll, count);
            if (shortn == 0) break;     /* fall through to real call */
            return real_read ? real_read(fd, buf, shortn)
                             : (errno = ENOSYS, -1);
        }
        default: break;
        }
    }
    return real_read ? real_read(fd, buf, count)
                     : (errno = ENOSYS, -1);
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_READ, fd, &d)) {
        fi_log_injection(FI_CLS_READ, d.call_idx, d.err, d.mode);
        switch (d.mode) {
        case FI_MODE_FAIL_NEG1: errno = d.err; return -1;
        case FI_MODE_FAIL_ZERO:                return 0;
        case FI_MODE_FAIL_SHORT: {
            size_t shortn = fi_short_len(d.roll, count);
            if (shortn == 0) break;
            return real_pread ? real_pread(fd, buf, shortn, offset)
                              : (errno = ENOSYS, -1);
        }
        default: break;
        }
    }
    return real_pread ? real_pread(fd, buf, count, offset)
                      : (errno = ENOSYS, -1);
}

/* ---------- write / pwrite ---------- */

ssize_t write(int fd, const void *buf, size_t count)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_WRITE, fd, &d)) {
        fi_log_injection(FI_CLS_WRITE, d.call_idx, d.err, d.mode);
        switch (d.mode) {
        case FI_MODE_FAIL_NEG1: errno = d.err; return -1;
        case FI_MODE_FAIL_SHORT: {
            size_t shortn = fi_short_len(d.roll, count);
            if (shortn == 0) break;
            return real_write ? real_write(fd, buf, shortn)
                              : (errno = ENOSYS, -1);
        }
        default: break;
        }
    }
    return real_write ? real_write(fd, buf, count)
                      : (errno = ENOSYS, -1);
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_WRITE, fd, &d)) {
        fi_log_injection(FI_CLS_WRITE, d.call_idx, d.err, d.mode);
        switch (d.mode) {
        case FI_MODE_FAIL_NEG1: errno = d.err; return -1;
        case FI_MODE_FAIL_SHORT: {
            size_t shortn = fi_short_len(d.roll, count);
            if (shortn == 0) break;
            return real_pwrite ? real_pwrite(fd, buf, shortn, offset)
                               : (errno = ENOSYS, -1);
        }
        default: break;
        }
    }
    return real_pwrite ? real_pwrite(fd, buf, count, offset)
                       : (errno = ENOSYS, -1);
}

/* ---------- close ---------- */

int close(int fd)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_CLOSE, fd, &d)) {
        fi_log_injection(FI_CLS_CLOSE, d.call_idx, d.err, FI_MODE_FAIL_NEG1);
        /* IMPORTANT: still call the real close. Per Linux semantics
         * close(2) always releases the fd, even when it returns -1
         * (the canonical example is a flush error on NFS). Caller
         * bug pattern we're targeting: "close failed, retry close",
         * which then hits EBADF on the second call -- a real bug
         * class we want to surface. Leaking the fd would actively
         * mask different bugs. */
        if (real_close) (void)real_close(fd);
        errno = d.err;
        return -1;
    }
    return real_close ? real_close(fd)
                      : (errno = ENOSYS, -1);
}

/* ---------- recv / recvfrom ---------- */

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_RECV, sockfd, &d)) {
        fi_log_injection(FI_CLS_RECV, d.call_idx, d.err, d.mode);
        switch (d.mode) {
        case FI_MODE_FAIL_NEG1: errno = d.err; return -1;
        case FI_MODE_FAIL_ZERO:                return 0;
        case FI_MODE_FAIL_SHORT: {
            size_t shortn = fi_short_len(d.roll, len);
            if (shortn == 0) break;
            return real_recv ? real_recv(sockfd, buf, shortn, flags)
                             : (errno = ENOSYS, -1);
        }
        default: break;
        }
    }
    return real_recv ? real_recv(sockfd, buf, len, flags)
                     : (errno = ENOSYS, -1);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_RECV, sockfd, &d)) {
        fi_log_injection(FI_CLS_RECV, d.call_idx, d.err, d.mode);
        switch (d.mode) {
        case FI_MODE_FAIL_NEG1: errno = d.err; return -1;
        case FI_MODE_FAIL_ZERO:                return 0;
        case FI_MODE_FAIL_SHORT: {
            size_t shortn = fi_short_len(d.roll, len);
            if (shortn == 0) break;
            return real_recvfrom
                ? real_recvfrom(sockfd, buf, shortn, flags, src_addr, addrlen)
                : (errno = ENOSYS, -1);
        }
        default: break;
        }
    }
    return real_recvfrom
        ? real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen)
        : (errno = ENOSYS, -1);
}

/* ---------- send / sendto ---------- */

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_SEND, sockfd, &d)) {
        fi_log_injection(FI_CLS_SEND, d.call_idx, d.err, d.mode);
        switch (d.mode) {
        case FI_MODE_FAIL_NEG1: errno = d.err; return -1;
        case FI_MODE_FAIL_SHORT: {
            size_t shortn = fi_short_len(d.roll, len);
            if (shortn == 0) break;
            return real_send ? real_send(sockfd, buf, shortn, flags)
                             : (errno = ENOSYS, -1);
        }
        default: break;
        }
    }
    return real_send ? real_send(sockfd, buf, len, flags)
                     : (errno = ENOSYS, -1);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_SEND, sockfd, &d)) {
        fi_log_injection(FI_CLS_SEND, d.call_idx, d.err, d.mode);
        switch (d.mode) {
        case FI_MODE_FAIL_NEG1: errno = d.err; return -1;
        case FI_MODE_FAIL_SHORT: {
            size_t shortn = fi_short_len(d.roll, len);
            if (shortn == 0) break;
            return real_sendto
                ? real_sendto(sockfd, buf, shortn, flags, dest_addr, addrlen)
                : (errno = ENOSYS, -1);
        }
        default: break;
        }
    }
    return real_sendto
        ? real_sendto(sockfd, buf, len, flags, dest_addr, addrlen)
        : (errno = ENOSYS, -1);
}

/* ---------- socket / accept / accept4 ---------- */

int socket(int domain, int type, int protocol)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_SOCKET, -1, &d)) {
        fi_log_injection(FI_CLS_SOCKET, d.call_idx, d.err, FI_MODE_FAIL_NEG1);
        errno = d.err;
        return -1;
    }
    return real_socket ? real_socket(domain, type, protocol)
                       : (errno = ENOSYS, -1);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_ACCEPT, sockfd, &d)) {
        fi_log_injection(FI_CLS_ACCEPT, d.call_idx, d.err, FI_MODE_FAIL_NEG1);
        errno = d.err;
        return -1;
    }
    return real_accept ? real_accept(sockfd, addr, addrlen)
                       : (errno = ENOSYS, -1);
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    struct fi_decision d;
    if (fi_decide(FI_CLS_ACCEPT, sockfd, &d)) {
        fi_log_injection(FI_CLS_ACCEPT, d.call_idx, d.err, FI_MODE_FAIL_NEG1);
        errno = d.err;
        return -1;
    }
    return real_accept4 ? real_accept4(sockfd, addr, addrlen, flags)
                        : (errno = ENOSYS, -1);
}
