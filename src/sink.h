/*
 * sink.h -- AFL-style 64KB shared-memory bitmap. Threading-mode aware.
 *
 * The .so build defines exactly one of LIBCOV_THREADING_ST or
 * LIBCOV_THREADING_MT. This header switches the inline emit body and the
 * type of prev_loc accordingly:
 *
 *   ST: single uint16_t prev_loc global; bitmap byte incremented directly.
 *   MT: per-thread (__thread) prev_loc; bitmap byte incremented via an
 *       atomic CAS loop that saturates at 255 without ever decrementing.
 *
 * Both implementations of sink_emit are async-signal-safe and inline at
 * the trap-handler call site.
 */
#ifndef LIBCOV_SINK_H
#define LIBCOV_SINK_H

#include <stdint.h>
#include <stddef.h>

#define LIBCOV_MAP_SIZE_POW2 16
#define LIBCOV_MAP_SIZE      (1u << LIBCOV_MAP_SIZE_POW2)
#define LIBCOV_MAP_MASK      (LIBCOV_MAP_SIZE - 1u)

int sink_init(const char *path);

extern uint8_t *libcov_bitmap;

#if defined(LIBCOV_THREADING_MT)
extern __thread uint16_t libcov_prev_loc;
#else
extern uint16_t libcov_prev_loc;
#endif

static inline uint16_t sink_hash_pc(uintptr_t pc) {
    /* Cheap mixer chosen so adjacent PCs don't collide. */
    uint64_t v = (uint64_t)pc;
    v ^= v >> 33;
    v *= 0xff51afd7ed558ccdULL;
    v ^= v >> 33;
    return (uint16_t)(v & LIBCOV_MAP_MASK);
}

static inline void sink_emit(uintptr_t pc) {
    uint16_t cur = sink_hash_pc(pc);
    uint16_t idx = (uint16_t)(libcov_prev_loc ^ cur) & LIBCOV_MAP_MASK;
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
    libcov_prev_loc = (uint16_t)(cur >> 1);
}

#endif
