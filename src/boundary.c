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
 * after init. Depth, touched set, and deferred-marker-rearm are __thread
 * under LIBCOV_THREADING_MT so concurrent worker threads scope their own
 * iterations cleanly. Snapshot publish to the ring is "last writer wins"
 * on gen_current; a small jitter where two threads boundary-fire in close
 * succession is acceptable for AFL-style fuzzing.
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
    uintptr_t addr;
    uint8_t   kind;          /* LIBCOV_BOUNDARY_KIND_BEGIN / END */
    uint8_t   depth_filter;  /* 1 = depth-zero only */
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
static TLS uint32_t g_init_grace_remaining = 0;
static TLS int      g_init_grace_initialized = 0;

/* "Touched this iter" set -- a stack of patch_entry pointers appended on
 * every disarm during the current iteration, drained at boundary. Sized
 * to the full patchlist count at init; never grows past that. Allocated
 * lazily per thread so MT workers get their own scratch without paying
 * for it at process init. */
static TLS struct patch_entry **g_touched     = NULL;
static TLS size_t               g_touched_len = 0;

/* Deferred marker re-arm. When REARM=all/touched fires we deliberately
 * leave the just-trapped marker site disarmed; re-arming it before the
 * handler returns would cause the kernel to re-fetch the trap encoding
 * and instantly re-trap (infinite loop). Instead we stash the site here
 * and arm it on the next trap whose pc differs (mirrors leapfrog's
 * "previous site" logic, applied specifically to the boundary marker). */
static TLS struct patch_entry *g_pending_marker_rearm = NULL;

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
    int saw_end = 0;
    for (size_t i = 0; i < g_marker_count; i++) {
        g_markers[i].addr         = module_base + (uintptr_t)rec[i].offset;
        g_markers[i].kind         = rec[i].kind;
        g_markers[i].depth_filter = rec[i].depth_filter;
        if (rec[i].kind == LIBCOV_BOUNDARY_KIND_END) saw_end = 1;
    }
    g_paired_mode = saw_end;
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

    g_ring_size   = g_hdr->ring_size;
    g_slot_stride = g_hdr->slot_stride;
    g_ring_base   = (uint8_t *)libcov_shm_base + g_hdr->ring_offset;

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

/* Publish the live bitmap to ring[gen % RING] and clear the live bitmap.
 * Per-slot generation stamps let the driver detect torn reads via the
 * seqlock pattern. The caller has already incremented hdr->gen_current
 * (via fetch_add); we don't touch it here. The reader's seqlock check
 * accommodates the brief window where gen_current points at `gen` but
 * the slot's stamp is still the previous value. */
static void publish_snapshot(uint64_t gen) {
    struct libcov_ring_slot_hdr *s = slot_at(gen);

    /* Mark slot in-progress (slot_gen=0) before touching its bitmap. */
    __atomic_store_n(&s->slot_gen, (uint64_t)0, __ATOMIC_RELEASE);

    /* Copy live bitmap into the slot's bitmap region. */
    memcpy(slot_bitmap(s), libcov_bitmap, LIBCOV_MAP_SIZE);

    s->tid   = cur_tid();
    s->ns    = now_ns();
    s->flags = 0;

    /* Stamp the slot with our gen as the final visibility signal. */
    __atomic_store_n(&s->slot_gen, gen, __ATOMIC_RELEASE);

    /* Best-effort notify. */
    if (g_eventfd >= 0) {
        uint64_t one = 1;
        (void)write(g_eventfd, &one, sizeof one);
    }

    /* Clear live bitmap so iter N+1 starts at zero. Also reset prev_loc so
     * AFL-style edge hashing doesn't carry across iterations. Under MT,
     * racing emits from peer threads may land in the wrong iteration's
     * snapshot by a few edges; that jitter is bounded (each peer thread
     * does one emit at most before noticing the boundary's clear) and
     * acceptable for AFL-style fuzzing. */
    memset(libcov_bitmap, 0, LIBCOV_MAP_SIZE);
    libcov_prev_loc = 0;
}

static void apply_rearm_policy(struct patch_entry *exclude) {
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
            patch_arm(p);
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
            patch_arm(&t[i]);
        }
        break;
    }
    }
    g_touched_len = 0;
    /* Defer the excluded (current) site's re-arm to the next trap so the
     * kernel doesn't immediately re-trap on the instruction we're about
     * to return to. */
    if (g_rearm != LIBCOV_REARM_NONE) g_pending_marker_rearm = exclude;
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

    /* Initialize per-thread grace counter on first use. (TLS guarantees
     * one-time init per thread; we use a flag to detect that.) */
    if (!g_init_grace_initialized) {
        g_init_grace_remaining   = g_init_grace_initial;
        g_init_grace_initialized = 1;
    }

    /* Flush any deferred marker re-arm from a previous boundary fire on
     * this thread -- but only if this trap is at a different pc
     * (otherwise we'd re-trap on the same site we're trying to leave). */
    if (g_pending_marker_rearm && g_pending_marker_rearm != e) {
#if defined(LIBCOV_THREADING_MT)
        if (!__atomic_load_n(&g_pending_marker_rearm->patched,
                             __ATOMIC_RELAXED))
            patch_arm(g_pending_marker_rearm);
#else
        if (!g_pending_marker_rearm->patched) patch_arm(g_pending_marker_rearm);
#endif
        g_pending_marker_rearm = NULL;
    }

    /* Track this disarm so 'touched' re-arm can find it later. */
    if (e) touched_append(e);

    struct marker *m = marker_lookup(pc);
    if (!m) return;

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

    if (g_init_grace_remaining) {
        g_init_grace_remaining--;
        return;
    }

    /* Advance generation and publish. gen 0 is reserved as "no snapshot
     * yet" so we start at 1. fetch_add gives each MT thread a unique gen;
     * the reader's seqlock check handles the brief window where
     * gen_current has advanced but the corresponding slot's stamp has
     * not yet been written. */
    uint64_t gen = __atomic_add_fetch(&g_hdr->gen_current, 1, __ATOMIC_ACQ_REL);
    maybe_record_init(gen);
    publish_snapshot(gen);
    apply_rearm_policy(e);

    /* In begin-only mode, depth tracking has no end-of-iter signal -- we
     * collapse it after each fire so the next BEGIN hit is also treated
     * as a boundary (no spurious "we're still inside iter N" filtering). */
    if (!g_paired_mode) g_depth = 0;
}
