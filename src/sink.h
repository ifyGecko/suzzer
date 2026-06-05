/*
 * sink.h -- AFL-style 64KB shared-memory bitmap.
 *
 * Single-threaded PoC: no atomics needed. The handler computes a 16-bit
 * cur_loc from PC, indexes bitmap[prev_loc ^ cur_loc] with saturating
 * increment, then updates prev_loc = cur_loc >> 1.
 */
#ifndef LIBCOV_SINK_H
#define LIBCOV_SINK_H

#include <stdint.h>
#include <stddef.h>

#define LIBCOV_MAP_SIZE_POW2 16
#define LIBCOV_MAP_SIZE      (1u << LIBCOV_MAP_SIZE_POW2)
#define LIBCOV_MAP_MASK      (LIBCOV_MAP_SIZE - 1u)

int sink_init(const char *path);

/* Pointer to the mmap'd region. Single allocation, never moves. */
extern uint8_t  *libcov_bitmap;
extern uint16_t  libcov_prev_loc;

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
    if (libcov_bitmap[idx] != 255) libcov_bitmap[idx]++;
    libcov_prev_loc = (uint16_t)(cur >> 1);
}

#endif
