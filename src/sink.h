/*
 * sink.h -- shared-memory bitmap + iteration ring. Threading-mode aware.
 *
 * The .so build defines exactly one of LIBCOV_THREADING_ST or
 * LIBCOV_THREADING_MT. This header switches the inline emit body and the
 * type of the prev-PC window accordingly:
 *
 *   ST: a single uint16_t window global; bitmap byte incremented directly.
 *   MT: a per-thread (__thread) window; bitmap byte incremented via an
 *       atomic CAS loop that saturates at 255 without ever decrementing.
 *
 * Both implementations of sink_emit are async-signal-safe and inline at
 * the trap-handler call site.
 *
 * Coverage scheme (LIBCOV_NGRAM_N in tunables.h):
 *
 *   N=1   block coverage: idx = hash(pc). Window unused.
 *   N=2   AFL-style edges: idx = hash(pc) ^ prev[0]. Default; bit-for-bit
 *         identical to the historical libcov emit.
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
 *   offset bitmap_offset       live bitmap, LIBCOV_MAP_SIZE bytes
 *   offset ring_offset         RING slots, each slot_stride bytes
 *
 * The header is always present; the ring stays unused (zeroed, SHM_FLAG_ACTIVE
 * clear) when LIBCOV_BOUNDARY_LIST is unset, so drivers wanting a single
 * cumulative bitmap (legacy use) only read `bitmap_offset`-relative data.
 */
#ifndef LIBCOV_SINK_H
#define LIBCOV_SINK_H

#include <stdint.h>
#include <stddef.h>

#include "tunables.h"   /* LIBCOV_MAP_SIZE_POW2, LIBCOV_NGRAM_N, LIBCOV_NGRAM_ROTATE */

#define LIBCOV_MAP_SIZE      (1u << LIBCOV_MAP_SIZE_POW2)
#define LIBCOV_MAP_MASK      (LIBCOV_MAP_SIZE - 1u)

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
 * region. ring_size is clamped to [2, 16]. */
int sink_init(const char *path, unsigned ring_size);

/* The mmap base (== &header). Used by boundary.c to compute ring/bitmap
 * pointers from the header's *_offset fields. */
extern void  *libcov_shm_base;
extern size_t libcov_shm_size;

extern uint8_t *libcov_bitmap;

/* Runtime base address of the instrumented module (== util_module_base
 * result, set in config_load). sink_hash_pc subtracts this before
 * hashing so the bitmap layout is ASLR-invariant: the same patch site
 * indexes into the same bucket on every fresh execve of a PIE target.
 *
 * Without this subtraction, hashing the absolute PC produces a fresh
 * pseudo-random bucket set per process under ASLR; the cumulative
 * bitmap then fills monotonically with random noise regardless of
 * actual coverage, the queue grows 1:1 with iters, and discovery
 * signal is completely lost. The bug was silent on systems with
 * randomize_va_space=0 (which used to be common in fuzz farms) and
 * surfaces immediately on the default Linux setting (= 2).
 *
 * Value 0 means "not initialised"; sink_hash_pc then falls back to
 * hashing absolute PC (preserves the legacy behaviour and avoids
 * accidentally producing identical indices for distinct addresses
 * pre-init -- which only matters for log lines emitted before
 * config_load runs). */
extern uintptr_t libcov_module_base;

#if defined(LIBCOV_THREADING_MT)
extern __thread uint16_t libcov_prev_loc[LIBCOV_NGRAM_WIN];
#else
extern uint16_t libcov_prev_loc[LIBCOV_NGRAM_WIN];
#endif

static inline uint16_t sink_hash_pc(uintptr_t pc) {
    /* Hash module-offset (pc - base), not absolute pc, so PIE/ASLR
     * doesn't randomise the bitmap layout per execve. See the comment
     * on libcov_module_base above. */
    uint64_t v = (uint64_t)(pc - libcov_module_base);
    v ^= v >> 33;
    v *= 0xff51afd7ed558ccdULL;
    v ^= v >> 33;
    return (uint16_t)(v & LIBCOV_MAP_MASK);
}

#if LIBCOV_NGRAM_ROTATE
/* Position-dependent rotate so {A,B,C} and {C,B,A} index differently.
 * The rotation amounts are chosen non-zero and coprime-ish vs. 16 so
 * adjacent slots don't share rotation amounts. */
static inline uint16_t sink_ngram_rot(uint16_t v, unsigned j) {
    unsigned r = ((j + 1u) * 3u) & 15u;   /* 3, 6, 9, 12, 15, 2, 5 */
    if (!r) return v;
    return (uint16_t)((v << r) | (v >> (16u - r)));
}
#endif

static inline void sink_emit(uintptr_t pc) {
    uint16_t cur = sink_hash_pc(pc);

    /* Fold the last N-1 PCs into the bucket index. N=1 collapses to
     * idx = hash(pc) (the for-loop body is preprocessed away). N=2
     * collapses to idx = cur ^ prev[0] -- AFL's exact math. */
    uint16_t idx = cur;
#if LIBCOV_NGRAM_N >= 2
    for (int j = 0; j < LIBCOV_NGRAM_WIN; j++) {
#  if LIBCOV_NGRAM_ROTATE
        idx ^= sink_ngram_rot(libcov_prev_loc[j], (unsigned)j);
#  else
        idx ^= libcov_prev_loc[j];
#  endif
    }
#endif
    idx &= LIBCOV_MAP_MASK;

#if defined(LIBCOV_THREADING_MT)
    /* Saturating atomic increment: load + CAS loop, never decrement past 255. */
    uint8_t old = __atomic_load_n(&libcov_bitmap[idx], __ATOMIC_RELAXED);
    while (old < 255) {
        uint8_t want = (uint8_t)(old + 1);
        if (__atomic_compare_exchange_n(&libcov_bitmap[idx], &old, want,
                                        0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            break;
        /* old now holds the value we observed; loop and retry. */
    }
#else
    if (libcov_bitmap[idx] != 255) libcov_bitmap[idx]++;
#endif

    /* Shift the window: oldest slot (prev[WIN-1]) drops off; freshest
     * slot (prev[0]) holds (cur >> 1). The shift is what makes AFL's
     * A->B and B->A index to different buckets at N=2; the same shift
     * keeps short reorderings distinguishable at higher N. */
#if LIBCOV_NGRAM_N >= 2
    for (int j = LIBCOV_NGRAM_WIN - 1; j > 0; j--)
        libcov_prev_loc[j] = libcov_prev_loc[j - 1];
    libcov_prev_loc[0] = (uint16_t)(cur >> 1);
#endif
}

#endif
