/*
 * boundary.c -- iteration boundary detection, snapshot ring, re-arm.
 *
 * See boundary.h for the design summary. This file is signal-safety
 * critical: boundary_on_trap runs from inside the trap signal handler.
 *
 * Async-signal-safe ops used here: memcpy, memset, mprotect (in patch_arm),
 * __builtin___clear_cache, __atomic_* intrinsics, clock_gettime, syscall
 * (gettid via SYS_gettid), write. All of these are documented as safe.
 *
 * Threading: marker table + sidecar metadata are shared and read-only
 * after init (apart from each marker's atomic `pending` flag). Depth and
 * the touched set are __thread under LIBCOV_THREADING_MT.
 *
 * Live bitmaps. ST keeps one live bitmap that IS the next ring slot
 * (pointer-swap publish, no copy). MT can't: with one shared live bitmap,
 * every snapshot mixed in whatever peer threads emitted, and two
 * concurrent publishers could move the shared pointer backwards. Under
 * MT, a thread's first boundary fire gives it a private live bitmap
 * (libcov_thread_bitmap); each later fire copies that into its own ring
 * slot and clears it, so a snapshot holds exactly one thread's
 * iteration. Threads that never fire a boundary (acceptors, timers) keep
 * emitting into the shared bitmap at hdr->bitmap_offset, which becomes a
 * cumulative "background" map. The first boundary in the process
 * publishes a copy of that shared map as the init snapshot (gen_init).
 */
#define _GNU_SOURCE
#include "boundary.h"
#include "patchlist_format.h"
#include "patch.h"
#include "sink.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#if defined(LIBCOV_THREADING_MT)
#  include <pthread.h>
#endif

#if defined(LIBCOV_THREADING_MT)
#  define TLS __thread
#else
#  define TLS /* nothing */
#endif

/* ---- shared (read-only after init) -------------------------------- */

static int                       g_enabled = 0;
static enum libcov_rearm_policy  g_rearm   = LIBCOV_REARM_NONE;

/* Marker table -- sorted by addr, lookup is binary-searched in the
 * signal handler hot path. */
struct marker {
    uintptr_t           addr;
    struct patch_entry *pe;           /* the patch site at addr (NULL: unpatched) */
    uint8_t             kind;         /* LIBCOV_BOUNDARY_KIND_BEGIN / END */
    uint8_t             depth_filter; /* 1 = depth-zero only */
    uint8_t             pending;      /* atomic: MARKER_{IDLE,HELD,RELEASED} */
};
static struct marker *g_markers = NULL;
static size_t         g_marker_count = 0;

/* "Paired mode" iff the sidecar contains at least one END marker. In
 * begin-only mode we can't observe iteration ends, so depth tracking
 * collapses: every BEGIN hit fires a boundary (the prior iter's snapshot)
 * and depth is reset to 0 after each fire. Recursion protection requires
 * paired markers. */
static int g_paired_mode = 0;

static uint32_t g_init_grace_initial = 0;

/* Process-wide: LIBCOV_BOUNDARY_INIT_GRACE=N drops the first N boundary
 * fires in the whole process, not N per thread (a 16-thread daemon with
 * a per-thread counter would silently drop 16*N). Decremented by CAS. */
static uint32_t g_init_grace_remaining = 0;

static struct libcov_shm_header *g_hdr      = NULL;
static uint8_t                  *g_ring_base = NULL;
static size_t                    g_slot_stride = 0;
static unsigned                  g_ring_size = 0;

/* Optional caller-passed eventfd for low-latency notification. Inherited
 * fd; libcov never closes it. */
static int g_eventfd = -1;

/* Upper bound for per-thread touched array sizing. Set to patchlist count
 * at init. */
static size_t g_touched_cap = 0;

/* ---- per-thread (MT) / global (ST) ------------------------------- */

static TLS uint32_t g_depth = 0;

/* "Touched this iter" set -- a stack of patch_entry pointers appended on
 * every disarm during the current iteration, drained at boundary. Sized
 * to the full patchlist count at init; never grows past that. Allocated
 * lazily per thread so MT workers get their own scratch without paying
 * for it at process init. */
static TLS struct patch_entry **g_touched     = NULL;
static TLS size_t               g_touched_len = 0;

/* Deferred marker re-arm, process-wide. A marker that just trapped must
 * stay disarmed until the thread that hit it has executed the original
 * instruction -- re-arming it earlier makes that thread trap at the
 * marker again (a spurious boundary fire). (This used to be a per-thread
 * slot: a marker one worker had hit stayed disarmed for every other
 * worker until that worker trapped again, so their boundaries were
 * silently missed.)
 *
 * States of marker.pending:
 *   HELD     -- the marker trapped and its thread is still in the handler
 *               (publishing, re-arming, membarrier). Nobody re-arms it.
 *   RELEASED -- boundary_trap_exit() ran: the thread is about to return
 *               and execute the original instruction. The next trap at a
 *               different site, on ANY thread, re-arms it.
 *
 * Releasing only at handler exit matters: the handler body takes tens of
 * microseconds, during which a busy peer traps many times. The residual
 * window is the owner's sigreturn itself; a peer re-arming inside it
 * causes one extra, near-empty boundary fire for the owner. */
enum { MARKER_IDLE = 0, MARKER_HELD = 1, MARKER_RELEASED = 2 };
static uint32_t g_pending_markers = 0;   /* atomic: markers not IDLE */

/* The marker this thread's current trap is holding, if any. */
static TLS struct marker *g_held_marker = NULL;

#if defined(LIBCOV_THREADING_MT)
/* Serializes writers of one ring slot. Two publishers only share a slot
 * when their gens are RING apart (the reader has lost one of them
 * anyway), but their copies must not interleave. */
static uint8_t g_slot_lock[16];

/* Set by the first boundary fire in the process, which publishes the
 * shared bitmap as the init snapshot. */
static uint8_t g_init_published = 0;

/* Frees a worker's private live bitmap at thread exit. */
static pthread_key_t g_bitmap_key;
static int           g_bitmap_key_ok = 0;
#endif

/* ---- helpers ------------------------------------------------------ */

int boundary_enabled(void) { return g_enabled; }

static struct marker *marker_lookup(uintptr_t addr) {
    if (!g_markers || g_marker_count == 0) return NULL;
    size_t lo = 0, hi = g_marker_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_markers[mid].addr == addr) return &g_markers[mid];
        if (g_markers[mid].addr <  addr) lo = mid + 1;
        else                              hi = mid;
    }
    return NULL;
}

static int cmp_marker(const void *a, const void *b) {
    uintptr_t aa = ((const struct marker *)a)->addr;
    uintptr_t bb = ((const struct marker *)b)->addr;
    return (aa > bb) - (aa < bb);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t cur_tid(void) {
#ifdef SYS_gettid
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

static struct libcov_ring_slot_hdr *slot_at(uint64_t gen) {
    size_t idx = (size_t)(gen % g_ring_size);
    return (struct libcov_ring_slot_hdr *)(g_ring_base + idx * g_slot_stride);
}

static uint8_t *slot_bitmap(struct libcov_ring_slot_hdr *s) {
    return (uint8_t *)(s + 1);
}

#if defined(LIBCOV_THREADING_MT)
/* pthread_key destructor, run on the exiting thread. Drop the TLS pointer
 * before unmapping so any later emit on this thread (another key's
 * destructor running instrumented code) goes to the shared bitmap. */
static void thread_bitmap_free(void *p) {
    if (libcov_thread_bitmap == p) {
        libcov_thread_bitmap = NULL;
        __atomic_signal_fence(__ATOMIC_SEQ_CST);
    }
    munmap(p, libcov_map_size);
}

/* Allocate this thread's private live bitmap. Called from the trap
 * handler, so no malloc: anonymous mmap is a plain syscall. The
 * pthread_setspecific only registers the destructor; for the low key
 * numbers libcov gets at init, glibc stores it in the thread descriptor
 * without allocating. */
static uint8_t *thread_bitmap_alloc(void) {
    void *p = mmap(NULL, libcov_map_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (g_bitmap_key_ok) pthread_setspecific(g_bitmap_key, p);
    return p;
}
#endif

/* ---- sidecar parsing -------------------------------------------------- */

static int load_sidecar(const char *path, uintptr_t module_base) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { libcov_logf("boundary: open(%s): %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); libcov_logf("boundary: fstat: %s", strerror(errno)); return -1; }
    if ((size_t)st.st_size < sizeof(struct lcvb_header)) {
        close(fd); libcov_logf("boundary: file too small"); return -1;
    }
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) { libcov_logf("boundary: mmap: %s", strerror(errno)); return -1; }

    const struct lcvb_header *h = map;
    if (memcmp(h->magic, LIBCOV_BOUNDARY_MAGIC, 4) != 0) {
        libcov_logf("boundary: bad magic in %s", path);
        munmap(map, st.st_size); return -1;
    }
    if (h->version != LIBCOV_BOUNDARY_VERSION) {
        libcov_logf("boundary: bad version %u", h->version);
        munmap(map, st.st_size); return -1;
    }
    size_t need = sizeof(*h) + (size_t)h->count * sizeof(struct lcvb_record);
    if ((size_t)st.st_size < need) {
        libcov_logf("boundary: truncated (count=%u)", h->count);
        munmap(map, st.st_size); return -1;
    }

    g_markers = calloc(h->count, sizeof(struct marker));
    if (!g_markers) { munmap(map, st.st_size); return -1; }
    g_marker_count = h->count;

    const struct lcvb_record *rec =
        (const struct lcvb_record *)((const char *)map + sizeof(*h));
    int saw_end = 0, saw_filter = 0;
    for (size_t i = 0; i < g_marker_count; i++) {
        g_markers[i].addr         = module_base + (uintptr_t)rec[i].offset;
        g_markers[i].kind         = rec[i].kind;
        g_markers[i].depth_filter = rec[i].depth_filter;
        if (rec[i].kind == LIBCOV_BOUNDARY_KIND_END) saw_end = 1;
        if (rec[i].depth_filter) saw_filter = 1;
    }
    g_paired_mode = saw_end;
    if (!saw_end && saw_filter)
        libcov_logf("boundary: WARNING -- depth_filter set on a begin-only sidecar "
                    "(no END markers); it has no effect and recursive BEGIN hits "
                    "will each fire a boundary. Add END markers for depth tracking.");
    munmap(map, st.st_size);

    qsort(g_markers, g_marker_count, sizeof(*g_markers), cmp_marker);
    libcov_logf("boundary: loaded %zu marker(s) from %s (mode=%s)",
                g_marker_count, path, g_paired_mode ? "paired" : "begin-only");
    return 0;
}

/* ---- env parsing ------------------------------------------------------ */

static enum libcov_rearm_policy parse_rearm(const char *s) {
    if (!s || !*s)         return LIBCOV_REARM_NONE;
    if (!strcmp(s, "all"))     return LIBCOV_REARM_ALL;
    if (!strcmp(s, "touched")) return LIBCOV_REARM_TOUCHED;
    return LIBCOV_REARM_NONE;
}

/* ---- public init ------------------------------------------------------ */

int boundary_init(void) {
    const char *list = getenv("LIBCOV_BOUNDARY_LIST");
    if (!list || !*list) {
        libcov_logf("boundary: LIBCOV_BOUNDARY_LIST unset, boundaries inert");
        return 0;
    }

    if (!libcov_shm_base) {
        libcov_logf("boundary: sink not initialized -- cannot enable boundaries");
        return -1;
    }
    g_hdr = (struct libcov_shm_header *)libcov_shm_base;

    const char *modname = getenv("LIBCOV_MODULE");
    uintptr_t base = util_module_base(modname);
    if (!base) { libcov_logf("boundary: cannot resolve module base"); return -1; }

    if (load_sidecar(list, base) < 0) return -1;
    if (g_marker_count == 0) {
        libcov_logf("boundary: sidecar empty, boundaries inert");
        return 0;
    }

    g_rearm = parse_rearm(getenv("LIBCOV_BOUNDARY_REARM"));

    const char *grace_str = getenv("LIBCOV_BOUNDARY_INIT_GRACE");
    if (grace_str && *grace_str) g_init_grace_initial = (uint32_t)atoi(grace_str);
    g_init_grace_remaining = g_init_grace_initial;

    const char *efd_str = getenv("LIBCOV_BOUNDARY_NOTIFY_FD");
    if (efd_str && *efd_str) {
        int fd = atoi(efd_str);
        if (fd > 0) {
            g_eventfd = fd;
            libcov_logf("boundary: notify fd=%d", fd);
        }
    }

    /* Cap for per-thread touched-set storage. Allocation is deferred to
     * first use per thread (in touched_append) so non-trapping threads
     * cost nothing. */
    size_t patch_n = 0;
    config_table_mut(&patch_n);
    g_touched_cap = patch_n;
    /* Pre-allocate the init thread's touched set so ST (and the MT main
     * thread) never calls calloc from inside the signal handler. Other MT
     * threads still allocate lazily on first trap -- see TODO.md. */
    if (g_rearm == LIBCOV_REARM_TOUCHED && g_touched_cap > 0)
        g_touched = calloc(g_touched_cap, sizeof(struct patch_entry *));

    g_ring_size   = g_hdr->ring_size;
    g_slot_stride = g_hdr->slot_stride;
    g_ring_base   = (uint8_t *)libcov_shm_base + g_hdr->ring_offset;

    /* Resolve each marker's patch site for the deferred re-arm. A marker
     * that isn't a patched site never traps, so it can never fire. */
    for (size_t i = 0; i < g_marker_count; i++) {
        g_markers[i].pe = patch_lookup(g_markers[i].addr);
        if (!g_markers[i].pe)
            libcov_logf("boundary: WARNING -- marker 0x%lx is not a patched site "
                        "and will never fire (check gen_boundary.py --patchlist)",
                        (unsigned long)g_markers[i].addr);
    }

#if defined(LIBCOV_THREADING_MT)
    if (pthread_key_create(&g_bitmap_key, thread_bitmap_free) == 0)
        g_bitmap_key_ok = 1;
    else
        libcov_logf("boundary: pthread_key_create failed; per-thread live "
                    "bitmaps will not be freed at thread exit");
    /* The live bitmap stays the shared one at hdr->bitmap_offset until a
     * thread fires its first boundary (see the file header). */
#else

    /* A5: under boundary mode the live bitmap rotates through ring slots.
     * Switch libcov_bitmap to slot[1].bitmap now -- gen=1 is the first
     * gen that publish_snapshot() will stamp, so writes accumulated
     * during the rest of init (target constructors, the first parse
     * call, etc.) end up exactly where the first publish needs them.
     *
     * The dedicated bitmap area (hdr->bitmap_offset) goes unused under
     * boundary mode. Drivers under boundary mode read ring slots only,
     * so this is invisible to them. Legacy (no-boundary) users keep
     * the libcov_bitmap pointer at hdr->bitmap_offset from sink_init
     * -- this branch isn't taken when LIBCOV_BOUNDARY_LIST is unset. */
    struct libcov_ring_slot_hdr *first_slot = slot_at(1);
    __atomic_store_n(&first_slot->slot_gen, (uint64_t)0, __ATOMIC_RELEASE);
    libcov_bitmap = slot_bitmap(first_slot);
#endif

    uint32_t mt_flag = 0;
#if defined(LIBCOV_THREADING_MT)
    mt_flag = LIBCOV_SHM_FLAG_MT;
#endif
    __atomic_or_fetch(&g_hdr->flags,
                      LIBCOV_SHM_FLAG_ACTIVE | mt_flag,
                      __ATOMIC_RELEASE);
    g_enabled = 1;

    libcov_logf("boundary: active markers=%zu rearm=%s grace=%u ring=%u",
                g_marker_count,
                g_rearm == LIBCOV_REARM_ALL     ? "all"     :
                g_rearm == LIBCOV_REARM_TOUCHED ? "touched" : "none",
                g_init_grace_initial, g_ring_size);
    return 1;
}

/* ---- hot path: trap handler integration ------------------------------- */

/* Lazy per-thread allocation of the touched-set scratch. Allocation in a
 * signal handler is technically not async-signal-safe in general, but
 * malloc() in glibc under our usage pattern (no longjmp / no fork from
 * inside the handler) is safe in practice. If this turns out to be a
 * problem on a specific target we can preallocate at thread_init. */
static inline void touched_append(struct patch_entry *e) {
    if (!g_touched && g_touched_cap > 0) {
        g_touched = calloc(g_touched_cap, sizeof(struct patch_entry *));
        if (!g_touched) return;  /* OOM -- silently degrade to REARM=all-style scan */
    }
    if (g_touched_len < g_touched_cap) {
        g_touched[g_touched_len++] = e;
    }
}

#if !defined(LIBCOV_THREADING_MT)
/* ST publish (MT uses publish_copy below).
 *
 * Publish the live bitmap to ring[gen % RING] and rotate the live
 * pointer to the next slot's bitmap area. Per-slot generation stamps
 * let the driver detect torn reads via the seqlock pattern. The caller
 * has already incremented hdr->gen_current (via fetch_add); we don't
 * touch it here. The reader's seqlock check accommodates the brief
 * window where gen_current points at `gen` but the slot's stamp is
 * still the previous value.
 *
 * A5: pointer-swap publish.
 * The live bitmap (libcov_bitmap) IS slot[gen % RING].bitmap -- writers
 * have been incrementing it directly. So publishing gen=N is just:
 *   1. stamp slot[N].header (tid, ns, slot_gen=N)
 *   2. move libcov_bitmap to slot[(N+1) % RING].bitmap
 *   3. zero the new live area
 *
 * This eliminates the per-publish 64-256 KB memcpy(slot, live, MAP_SIZE)
 * the old layout required. Cost is one MAP_SIZE memset (the new live
 * area) instead of memcpy + memset (two MAP_SIZE passes).
 *
 * Wire-format: the shm header still describes a dedicated bitmap area
 * at hdr->bitmap_offset. When boundary mode is active, libcov_bitmap is
 * initialised inside the ring (see boundary_init below), so the
 * dedicated area goes unused under boundary mode. Drivers under
 * boundary mode read ring slots only -- that contract is unchanged. */
static void publish_snapshot(uint64_t gen) {
    struct libcov_ring_slot_hdr *s = slot_at(gen);

    s->tid   = cur_tid();
    s->ns    = now_ns();
    s->flags = 0;

    /* Stamp the slot with our gen as the final visibility signal. The
     * slot's bitmap data IS what writers have been emitting into all
     * iter. */
    __atomic_store_n(&s->slot_gen, gen, __ATOMIC_RELEASE);

    /* Best-effort notify. */
    if (g_eventfd >= 0) {
        uint64_t one = 1;
        (void)write(g_eventfd, &one, sizeof one);
    }

    /* Rotate the live bitmap pointer to the next slot's data area. New
     * emits will land there. The next slot's previous slot_gen (from the
     * generation that wrapped around RING ago) is invalidated by writing
     * 0 before the bitmap is cleared, so a driver that's exactly RING
     * generations behind doesn't see a half-zeroed slot stamped with a
     * stale gen. */
    struct libcov_ring_slot_hdr *next = slot_at(gen + 1);
    __atomic_store_n(&next->slot_gen, (uint64_t)0, __ATOMIC_RELAXED);
    /* Seqlock writer: slot_gen=0 must be visible before any of the memset
     * stores below. A release *store* only orders earlier accesses; the
     * fence orders it against the later plain stores (dmb on ARM). */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    libcov_bitmap = slot_bitmap(next);
    memset(libcov_bitmap, 0, libcov_map_size);

    /* Clear the whole prev-PC window (N-gram coverage uses the last
     * N-1 PCs as context; AFL-style at N=2 reduces to a single
     * uint16_t) so cross-iteration context doesn't leak. Under MT,
     * racing emits from peer threads may land in the wrong iteration's
     * snapshot by a few edges; that jitter is bounded (each peer
     * thread does one emit at most before noticing the boundary's
     * clear) and acceptable for AFL-style fuzzing. */
    memset(libcov_prev_loc, 0, sizeof libcov_prev_loc);
}
#endif

#if defined(LIBCOV_THREADING_MT)
static inline void slot_lock(uint8_t *l) {
    uint8_t expected = 0;
    while (!__atomic_compare_exchange_n(l, &expected, 1, 0,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        expected = 0;
        __asm__ volatile ("" ::: "memory");
    }
}

static inline void slot_unlock(uint8_t *l) {
    __atomic_store_n(l, 0, __ATOMIC_RELEASE);
}

/* MT publish: copy `src` into ring[gen % RING] under the seqlock protocol.
 * `src` is the publishing thread's private live bitmap (only it writes
 * there, and it's inside its own trap handler, so the copy is exact), or
 * the shared bitmap for the init snapshot (a best-effort copy while peers
 * may still be emitting). Costs one map_size memcpy per iteration -- the
 * price of per-thread attribution; ST keeps the zero-copy pointer swap. */
static void publish_copy(uint64_t gen, const uint8_t *src) {
    struct libcov_ring_slot_hdr *s = slot_at(gen);
    uint8_t *lock = &g_slot_lock[gen % g_ring_size];

    slot_lock(lock);
    /* A publisher RING gens ahead already took this slot: our snapshot
     * is outside every reader's window, so drop it rather than overwrite
     * newer data with older. */
    if (__atomic_load_n(&s->slot_gen, __ATOMIC_RELAXED) > gen) {
        slot_unlock(lock);
        return;
    }
    __atomic_store_n(&s->slot_gen, (uint64_t)0, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);   /* see publish_snapshot */
    s->tid   = cur_tid();
    s->ns    = now_ns();
    s->flags = 0;
    memcpy(slot_bitmap(s), src, libcov_map_size);
    __atomic_store_n(&s->slot_gen, gen, __ATOMIC_RELEASE);
    slot_unlock(lock);

    if (g_eventfd >= 0) {
        uint64_t one = 1;
        (void)write(g_eventfd, &one, sizeof one);
    }
}
#endif

static void apply_rearm_policy(struct patch_entry *exclude) {
    /* A1: every rearm uses _unsynced; the handler issues one
     * patch_sync_batch_end() at the tail. Under MT with membarrier(SYNC_CORE)
     * this collapses N IPIs per boundary fire into 1. Under ST the
     * _unsynced/_synced variants are aliases and this loop is identical
     * to the previous behaviour. */
    switch (g_rearm) {
    case LIBCOV_REARM_NONE:
        break;
    case LIBCOV_REARM_TOUCHED:
        for (size_t i = 0; i < g_touched_len; i++) {
            struct patch_entry *p = g_touched[i];
            if (!p || p == exclude) continue;
#if defined(LIBCOV_THREADING_MT)
            if (__atomic_load_n(&p->patched, __ATOMIC_RELAXED)) continue;
#else
            if (p->patched) continue;
#endif
            patch_arm_unsynced(p);
        }
        break;
    case LIBCOV_REARM_ALL: {
        size_t n;
        struct patch_entry *t = config_table_mut(&n);
        for (size_t i = 0; i < n; i++) {
            if (&t[i] == exclude) continue;
#if defined(LIBCOV_THREADING_MT)
            if (__atomic_load_n(&t[i].patched, __ATOMIC_RELAXED)) continue;
#else
            if (t[i].patched) continue;
#endif
            patch_arm_unsynced(&t[i]);
        }
        break;
    }
    }
    g_touched_len = 0;
    /* The excluded (current) site is the marker; its re-arm is deferred
     * through the marker's pending flag (see g_pending_markers). */
}

/* Re-arm every RELEASED marker, whichever thread hit it, except the site
 * trapping right now. Fast path: one load when nothing is pending. */
static void flush_pending_markers(struct patch_entry *cur) {
    if (!__atomic_load_n(&g_pending_markers, __ATOMIC_ACQUIRE)) return;
    for (size_t i = 0; i < g_marker_count; i++) {
        struct marker *m = &g_markers[i];
        if (m->pe == cur) continue;
        uint8_t released = MARKER_RELEASED;
        if (!__atomic_compare_exchange_n(&m->pending, &released, MARKER_IDLE, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            continue;
        __atomic_sub_fetch(&g_pending_markers, 1, __ATOMIC_RELEASE);
        /* A1: unsynced; the handler tail's patch_sync_batch_end() covers it. */
        if (!__atomic_load_n(&m->pe->patched, __ATOMIC_RELAXED))
            patch_arm_unsynced(m->pe);
    }
}

/* Hold a marker that this thread just trapped on. A marker already HELD
 * by a peer that trapped on it at the same moment (MT: both traps
 * converged) keeps the peer as holder; we then have nothing to release. */
static void hold_marker(struct marker *m) {
    uint8_t cur = __atomic_load_n(&m->pending, __ATOMIC_RELAXED);
    for (;;) {
        if (!m->pe || cur == MARKER_HELD) return;
        if (__atomic_compare_exchange_n(&m->pending, &cur, MARKER_HELD, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            break;
    }
    if (cur == MARKER_IDLE)
        __atomic_add_fetch(&g_pending_markers, 1, __ATOMIC_RELEASE);
    g_held_marker = m;
}

void boundary_trap_exit(void) {
    struct marker *m = g_held_marker;
    if (!m) return;
    g_held_marker = NULL;
    __atomic_store_n(&m->pending, MARKER_RELEASED, __ATOMIC_RELEASE);
}

static void maybe_record_init(uint64_t gen) {
    /* If gen_init is still 0 the first time any thread hits a boundary,
     * stamp it. Use a one-shot CAS so the first writer wins. */
    uint64_t expected = 0;
    __atomic_compare_exchange_n(&g_hdr->gen_init, &expected, gen,
                                0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}

void boundary_on_trap(uintptr_t pc, struct patch_entry *e) {
    if (!g_enabled) return;

    /* Re-arm markers left disarmed by earlier marker traps (any thread),
     * but never the site trapping right now -- we'd re-trap on the
     * instruction we're about to return to. */
    flush_pending_markers(e);

    /* Track this disarm so 'touched' re-arm can find it later. Only needed
     * (and only allocates) under REARM=touched. */
    if (e && g_rearm == LIBCOV_REARM_TOUCHED) touched_append(e);

    struct marker *m = marker_lookup(pc);
    if (!m) return;

    /* Every marker trap leaves the marker disarmed, whether or not it
     * fires a boundary below (depth filter, init grace). */
    hold_marker(m);

    /* Depth tracking:
     *   paired mode (sidecar contains END markers): BEGIN increments depth,
     *     END decrements. depth_filter=zero means "fire only at depth 0",
     *     i.e. skip recursive sub-calls.
     *   begin-only mode: no way to observe end-of-iter, so depth is reset
     *     to 0 after each fire. Every BEGIN hit fires; depth_filter has no
     *     effect because we never see ENDs to balance the tree. */
    int is_boundary = 0;
    if (m->kind == LIBCOV_BOUNDARY_KIND_BEGIN) {
        if (g_paired_mode) {
            uint32_t prev = g_depth++;
            if (!m->depth_filter || prev == 0) is_boundary = 1;
        } else {
            is_boundary = 1;
        }
    } else { /* END */
        if (g_depth > 0) g_depth--;
        if (!m->depth_filter || g_depth == 0) is_boundary = 1;
    }
    if (!is_boundary) return;

    uint32_t grace = __atomic_load_n(&g_init_grace_remaining, __ATOMIC_RELAXED);
    while (grace) {
        if (__atomic_compare_exchange_n(&g_init_grace_remaining, &grace, grace - 1,
                                        0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            return;
    }

    /* Advance generation and publish. gen 0 is reserved as "no snapshot
     * yet" so we start at 1. fetch_add gives each MT thread a unique gen;
     * the reader's seqlock check handles the brief window where
     * gen_current has advanced but the corresponding slot's stamp has
     * not yet been written. */
#if defined(LIBCOV_THREADING_MT)
    if (!libcov_thread_bitmap) {
        /* This thread's first boundary: from now on it emits into its own
         * live bitmap. What it emitted before went to the shared bitmap
         * and isn't attributable to one iteration, so it publishes
         * nothing -- except the first boundary in the process, which
         * publishes the shared bitmap as the init snapshot. */
        uint8_t *mine = thread_bitmap_alloc();
        if (!mine) return;   /* stay on the shared bitmap; can't publish */
        libcov_thread_bitmap = mine;
        if (!__atomic_exchange_n(&g_init_published, 1, __ATOMIC_ACQ_REL)) {
            uint64_t gen = __atomic_add_fetch(&g_hdr->gen_current, 1,
                                              __ATOMIC_ACQ_REL);
            maybe_record_init(gen);
            publish_copy(gen, libcov_bitmap);
        }
    } else {
        uint64_t gen = __atomic_add_fetch(&g_hdr->gen_current, 1, __ATOMIC_ACQ_REL);
        publish_copy(gen, libcov_thread_bitmap);
        memset(libcov_thread_bitmap, 0, libcov_map_size);
    }
    memset(libcov_prev_loc, 0, sizeof libcov_prev_loc);
#else
    uint64_t gen = __atomic_add_fetch(&g_hdr->gen_current, 1, __ATOMIC_ACQ_REL);
    maybe_record_init(gen);
    publish_snapshot(gen);
#endif
    apply_rearm_policy(e);

    /* In begin-only mode, depth tracking has no end-of-iter signal -- we
     * collapse it after each fire so the next BEGIN hit is also treated
     * as a boundary (no spurious "we're still inside iter N" filtering). */
    if (!g_paired_mode) g_depth = 0;
}
