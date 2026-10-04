/*
 * sink.h -- shared-memory bitmap + iteration ring. Threading-mode aware.
 *
 * The .so build defines exactly one of LIBCOV_THREADING_ST or
 * LIBCOV_THREADING_MT. This header switches the inline emit body and the
 * type of the prev-PC window accordingly:
 *
 *   ST: a global uint32_t window (libcov_prev_loc[LIBCOV_NGRAM_WIN]);
 *       bitmap byte incremented directly (saturating at 255).
 *   MT: a per-thread (__thread) window; bitmap byte incremented via an
 *       atomic CAS loop that saturates at 255 without ever decrementing.
 *
 * Both implementations of sink_emit are async-signal-safe and inline at
 * the trap-handler call site.
 *
 * Coverage scheme (LIBCOV_NGRAM_N in tunables.h):
 *
 *   cur is site_id under the default site-id model, hash(pc) under the
 *   legacy hashed-PC model (LIBCOV_COVERAGE_MODEL_SITE=0).
 *
 *   N=1   block coverage: idx = cur. Window unused.
 *   N=2   edges: idx = cur ^ prev[0]. Default; bit-for-bit identical to
 *         the historical libcov emit only under the hashed-PC model.
 *   N>=3  N-gram coverage: idx XORs in prev[0..N-2], encoding the last
 *         N control transfers in this thread. Bitmap layout (size, hash,
 *         saturation, atomics) is unchanged regardless of N.
 *
 * The window is stored as `libcov_prev_loc[LIBCOV_NGRAM_WIN]` -- one slot
 * per remembered PC. N=1 still allocates one (unused) slot so the array
 * never has zero length. boundary.c clears the whole window at each
 * iteration boundary so cross-iteration context doesn't leak.
 *
 * Shm layout (created by sink_init):
 *
 *   offset 0                   struct libcov_shm_header (see boundary.h)
 *   offset bitmap_offset       live bitmap, map_size bytes (hdr->map_size)
 *   offset ring_offset         RING slots, each slot_stride bytes
 *
 * The header is always present; the ring stays unused (zeroed, SHM_FLAG_ACTIVE
 * clear) when LIBCOV_BOUNDARY_LIST is unset, so drivers wanting a single
 * cumulative bitmap (legacy use) only read `bitmap_offset`-relative data.
 *
 * When boundaries ARE active the `bitmap_offset` region's meaning depends on
 * the threading variant, so the header advertises it: in ST boundary mode
 * emits rotate through ring slots and the `bitmap_offset` region stays zero
 * (SHM_FLAG_LIVE_EMPTY set -- a legacy driver must read the ring); in MT
 * boundary mode `bitmap_offset` still accumulates non-worker/pre-first-boundary
 * coverage (LIVE_EMPTY clear). See boundary.h for the flag bits.
 */
#ifndef LIBCOV_SINK_H
#define LIBCOV_SINK_H

#include <stdint.h>
#include <stddef.h>

#include "tunables.h"   /* LIBCOV_MAP_SIZE_POW2, LIBCOV_NGRAM_N, LIBCOV_NGRAM_ROTATE */
#include "patchlist_format.h"  /* LIBCOV_MAX_MODULES */

/* Legacy default map dimensions. Under the hashed-PC model the map is this
 * size; under the site-id model the map auto-sizes from the patch count and
 * these macros are unused. The authoritative runtime size/mask live in the
 * globals below -- the hot path masks with libcov_map_mask, not the macro. */
#define LIBCOV_MAP_SIZE      (1u << LIBCOV_MAP_SIZE_POW2)
#define LIBCOV_MAP_MASK      (LIBCOV_MAP_SIZE - 1u)

/* Runtime bitmap dimensions, set by sink_init(). Always a power of two.
 * Read in the trap-handler hot path (one global load, negligible vs the
 * SIGILL round-trip). */
extern uint32_t libcov_map_size;
extern uint32_t libcov_map_mask;

/* Compile-time clamp on N. Bumping this cap requires accepting a few
 * more TLS bytes per thread and (slightly) more collision pressure;
 * adjust here together with the doc in tunables.h. */
_Static_assert(LIBCOV_NGRAM_N >= 1 && LIBCOV_NGRAM_N <= 8,
               "LIBCOV_NGRAM_N must be in [1, 8]");

/* Number of remembered prev-PC slots. At least 1 so the storage array
 * never has zero length (N=1 leaves the slot unused). */
#if LIBCOV_NGRAM_N >= 2
#  define LIBCOV_NGRAM_WIN (LIBCOV_NGRAM_N - 1)
#else
#  define LIBCOV_NGRAM_WIN 1
#endif

/* Allocate header + live bitmap + ring; map them as one contiguous shm
 * region. ring_size is clamped to [2, 16]. map_size is the live bitmap
 * byte length (must be a power of two); it is recorded in libcov_map_size /
 * libcov_map_mask and in the shm header. Computed by the caller from the
 * patch count (site-id model) or the legacy constant (hashed-PC model). */
int sink_init(const char *path, unsigned ring_size, size_t map_size);

/* The mmap base (== &header). Used by boundary.c to compute ring/bitmap
 * pointers from the header's *_offset fields. */
extern void  *libcov_shm_base;
extern size_t libcov_shm_size;
/* 1 if sink_init attached to this process's own region from before an
 * in-place re-exec (contents, generations and ring kept), 0 if it created
 * or reset the region. */
extern int    libcov_shm_attached;

extern uint8_t *libcov_bitmap;

#if defined(LIBCOV_THREADING_MT)
/* MT boundary mode: a worker thread's private live bitmap. NULL until the
 * thread fires its first iteration boundary; until then (and always, for
 * threads that never fire one) emits go to the shared libcov_bitmap.
 * Owned by boundary.c, which publishes it into the ring and clears it at
 * each boundary so a snapshot holds exactly one thread's iteration. */
extern __thread uint8_t *libcov_thread_bitmap;
#endif

/* Per-module runtime load bases, indexed by the module_idx field on each
 * patch_entry. Populated by config_load from /proc/self/maps for each
 * named module in the LCV3 header's name table.
 *
 * sink_hash_pc subtracts the entry's module base before hashing so the
 * bitmap layout is ASLR-invariant: the same patch site indexes into the
 * same bucket on every fresh execve of a PIE target. With multi-module
 * support the right base depends on which module the site lives in, so
 * we look it up by module_idx (carried on the patch_entry).
 *
 * Without this subtraction, hashing the absolute PC produces a fresh
 * pseudo-random bucket set per process under ASLR; the cumulative
 * bitmap then fills monotonically with random noise regardless of
 * actual coverage, the queue grows 1:1 with iters, and discovery
 * signal is completely lost. The bug was silent on systems with
 * randomize_va_space=0 (which used to be common in fuzz farms) and
 * surfaces immediately on the default Linux setting (= 2).
 *
 * Slot 0 of libcov_module_bases is the positional binary given to
 * gen_patchlist.py (normally the main executable); slots 1..N are the
 * --module libraries in command-line order. Slots >= module_count are 0. A 0 base
 * for a referenced slot means config_load couldn't resolve the module
 * and refused to finish loading, so this state never reaches the
 * handler. */
extern uintptr_t libcov_module_bases[LIBCOV_MAX_MODULES];

#if defined(LIBCOV_THREADING_MT)
extern __thread uint32_t libcov_prev_loc[LIBCOV_NGRAM_WIN];
#else
extern uint32_t libcov_prev_loc[LIBCOV_NGRAM_WIN];
#endif

static inline uint32_t sink_hash_pc(uintptr_t pc, uint8_t module_idx) {
    /* Hash module-offset (pc - base[module_idx]), not absolute pc, so
     * PIE/ASLR doesn't randomise the bitmap layout per execve. See the
     * comment on libcov_module_bases above. module_idx is mixed in so the
     * same offset in two different modules doesn't land in the same
     * bucket; the term is 0 for module 0, so single-module bitmaps are
     * unchanged. */
    uint64_t v = (uint64_t)(pc - libcov_module_bases[module_idx])
               ^ ((uint64_t)module_idx * 0x9E3779B97F4A7C15ULL);
    v ^= v >> 33;
    v *= 0xff51afd7ed558ccdULL;
    v ^= v >> 33;
    return (uint32_t)(v & libcov_map_mask);
}

/* Spread a dense site_id across the whole map before it enters the N-gram
 * window, so folded history scatters over all buckets even though the raw
 * ids are small consecutive integers. The current site still contributes
 * its *raw* id to the index base (collision-free at N=1); only spread
 * history is XOR-folded, so collisions arise solely in the fold step. */
static inline uint32_t sink_spread(uint32_t id) {
    uint64_t v = (uint64_t)id;
    v ^= v >> 33;
    v *= 0xff51afd7ed558ccdULL;
    v ^= v >> 33;
    return (uint32_t)(v & libcov_map_mask);
}

#if LIBCOV_NGRAM_ROTATE
/* Per-slot rotation amounts, set by sink_init() from the runtime map
 * width. Distinct, non-zero and < map bits, so every history slot is a
 * bijection on [0, map_size) and keeps its full entropy.
 *
 * (The previous version rotated the full 32-bit word and then masked to
 * the map: bits rotated above the mask were discarded, so on a 4 KiB map
 * slots 2 and 3 contributed 0 bits and slot 1 only 2 -- ROTATE=1 made
 * high-N coverage *less* path-sensitive, not more.) */
extern uint8_t libcov_ngram_rot_r[LIBCOV_NGRAM_WIN];
extern uint8_t libcov_map_bits;

/* Position-dependent rotate within the map width so {A,B,C} and {B,A,C}
 * (history-slot permutations, which plain XOR folds together) index
 * differently. */
static inline uint32_t sink_ngram_rot(uint32_t v, unsigned j) {
    unsigned r = libcov_ngram_rot_r[j];
    unsigned b = libcov_map_bits;
    return ((v << r) | (v >> (b - r))) & libcov_map_mask;
}
#endif

/* Coverage emit. The handler always passes pc, module_idx, and site_id;
 * the active coverage model selects which it uses for the bucket base. */
static inline void sink_emit(uintptr_t pc, uint8_t module_idx, uint32_t site_id) {
#if LIBCOV_COVERAGE_MODEL_SITE
    uint32_t cur     = site_id;              /* raw id -> exact index base */
    uint32_t cur_win = sink_spread(site_id); /* spread copy for the window  */
    (void)pc; (void)module_idx;
#else
    uint32_t cur     = sink_hash_pc(pc, module_idx);
    uint32_t cur_win = cur;
#endif
#if LIBCOV_NGRAM_N < 2
    (void)cur_win;   /* window unused at N=1 */
#endif

    /* Fold the last N-1 entries into the bucket index. N=1 collapses to
     * idx = cur (the for-loop body is preprocessed away): under the site-id
     * model that is exactly site_id, so the map has zero collisions. N=2
     * collapses to idx = cur ^ prev[0] -- AFL's exact math under the
     * hashed-PC model. */
    uint32_t idx = cur;
#if LIBCOV_NGRAM_N >= 2
    for (int j = 0; j < LIBCOV_NGRAM_WIN; j++) {
#  if LIBCOV_NGRAM_ROTATE
        idx ^= sink_ngram_rot(libcov_prev_loc[j], (unsigned)j);
#  else
        idx ^= libcov_prev_loc[j];
#  endif
    }
#endif
    idx &= libcov_map_mask;

#if defined(LIBCOV_THREADING_MT)
    /* Saturating atomic increment: load + CAS loop, never decrement past 255.
     * The private per-thread bitmap is only written by its owner, but the
     * shared one isn't, so both take the same atomic path. */
    uint8_t *bm = libcov_thread_bitmap ? libcov_thread_bitmap : libcov_bitmap;
    uint8_t old = __atomic_load_n(&bm[idx], __ATOMIC_RELAXED);
    while (old < 255) {
        uint8_t want = (uint8_t)(old + 1);
        if (__atomic_compare_exchange_n(&bm[idx], &old, want,
                                        0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            break;
        /* old now holds the value we observed; loop and retry. */
    }
#else
    if (libcov_bitmap[idx] != 255) libcov_bitmap[idx]++;
#endif

    /* Shift the window: oldest slot (prev[WIN-1]) drops off; freshest slot
     * (prev[0]) takes the current entry. Under the hashed-PC model the
     * stored value is (cur >> 1) -- AFL's shift that makes A->B and B->A
     * index to different buckets at N=2 -- preserving bit-for-bit identity.
     * Under the site-id model the stored value is the spread copy: the raw
     * current id and the spread history are already asymmetric, so the
     * shift is unnecessary and would only throw away a bit of the spread. */
#if LIBCOV_NGRAM_N >= 2
    for (int j = LIBCOV_NGRAM_WIN - 1; j > 0; j--)
        libcov_prev_loc[j] = libcov_prev_loc[j - 1];
#  if LIBCOV_COVERAGE_MODEL_SITE
    libcov_prev_loc[0] = cur_win;
#  else
    libcov_prev_loc[0] = (cur_win >> 1);
#  endif
#endif
}

#endif
