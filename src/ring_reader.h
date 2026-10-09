/*
 * ring_reader.h -- client-side reader for the libcov coverage shm region.
 *
 * Header-only helpers for an out-of-process reader (fuzz_driver, ring_dump,
 * suzzer-relay): attach to the shm region, read per-iteration snapshots from
 * the ring with the seqlock protocol, and account for overruns. The library
 * itself never includes this -- it is purely for consumers.
 *
 * Depends only on boundary.h (the shm ABI). All functions are `static inline`
 * so each including translation unit gets its own copy with no link
 * collisions and no unused-function warnings when a consumer uses only some.
 *
 * The seqlock read (rr_read_slot) is the canonical implementation; see the
 * step-by-step in README "Iteration boundaries" and Design.md §21.
 */
#ifndef LIBCOV_RING_READER_H
#define LIBCOV_RING_READER_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "boundary.h"

/* Lost-coverage accounting, filled by rr_drain_to. Zero-initialise it. */
struct rr_stats {
    unsigned overruns;
    unsigned read_failures;
    uint64_t lost_gens;
    unsigned kind_init, kind_iter, kind_gap;
};

/* Called once per successfully read snapshot. `bitmap` is map_size bytes,
 * valid only for the duration of the call (it is the reader's scratch
 * buffer). Return value ignored. */
typedef void (*rr_slot_cb)(uint64_t gen, const uint8_t *bitmap, size_t map_size,
                           uint64_t tid, uint64_t ns, uint64_t flags, void *user);

/* Map an existing shm region read-only. 0 on success. Not-yet-created is a
 * normal transient failure (-1); the caller polls. */
static inline int rr_open_shm(const char *path, void **base_out, size_t *size_out) {
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    if ((size_t)st.st_size < sizeof(struct libcov_shm_header)) {
        close(fd); return -1;
    }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return -1;
    *base_out = m;
    *size_out = (size_t)st.st_size;
    return 0;
}

/* Wait for the target's libcov constructor to create the region, present the
 * LCVS magic, and (if it uses boundaries) flip LIBCOV_SHM_FLAG_ACTIVE.
 * Returns 0 and fills base_out, size_out and map_size_out on success,
 * -1 on timeout.
 *
 * require_active: pass 1 for a boundary-mode reader (ring snapshots);
 * pass 0 to attach to a region whose boundaries may be inert. */
static inline int rr_attach(const char *path, int require_active, unsigned timeout_ms,
                     void **base_out, size_t *size_out, size_t *map_size_out) {
    void *base = NULL;
    size_t size = 0;
    unsigned waited = 0;
    const unsigned step = 10;  /* ms */
    for (;;) {
        if (!base && rr_open_shm(path, &base, &size) == 0) {
            volatile struct libcov_shm_header *hdr = base;
            if (memcmp((const void *)hdr->magic, LIBCOV_SHM_MAGIC, 4) != 0) {
                munmap(base, size); base = NULL;
            }
        }
        if (base) {
            volatile struct libcov_shm_header *hdr = base;
            uint32_t flags = __atomic_load_n((uint32_t *)&hdr->flags,
                                             __ATOMIC_ACQUIRE);
            if (!require_active || (flags & LIBCOV_SHM_FLAG_ACTIVE)) {
                size_t ms = __atomic_load_n((uint32_t *)&hdr->map_size,
                                            __ATOMIC_ACQUIRE);
                if (ms != 0) {
                    *base_out = base; *size_out = size; *map_size_out = ms;
                    return 0;
                }
            }
        }
        if (waited >= timeout_ms) {
            if (base) munmap(base, size);
            return -1;
        }
        struct timespec sl = {0, (long)step * 1000000};
        nanosleep(&sl, NULL);
        waited += step;
    }
}

/* "n=<N> model=site|pc rotate=0|1" from the header's scheme bits, or
 * "unknown" for a region written by a libcov that predates them. */
static inline const char *rr_scheme(uint32_t flags, char *buf, size_t n) {
    if (!(flags & LIBCOV_SHM_FLAG_SCHEME)) {
        snprintf(buf, n, "unknown");
    } else {
        snprintf(buf, n, "n=%u model=%s rotate=%d",
                 (unsigned)LIBCOV_SHM_NGRAM(flags),
                 (flags & LIBCOV_SHM_FLAG_MODEL_PC) ? "pc" : "site",
                 (flags & LIBCOV_SHM_FLAG_ROTATE) ? 1 : 0);
    }
    return buf;
}

static inline unsigned rr_count_set(const uint8_t *map, size_t map_size) {
    unsigned c = 0;
    for (size_t i = 0; i < map_size; i++) if (map[i]) c++;
    return c;
}

/* Fold `cur` into `cumulative`; return the number of bytes newly set. */
static inline unsigned rr_count_new(const uint8_t *cur, uint8_t *cumulative,
                             size_t map_size) {
    unsigned newly = 0;
    for (size_t i = 0; i < map_size; i++) {
        if (cur[i] && !cumulative[i]) { newly++; cumulative[i] = cur[i]; }
    }
    return newly;
}

static inline const char *rr_slot_kind(uint64_t flags) {
    switch (flags) {
    case LIBCOV_SLOT_FLAG_INIT: return "init";
    case LIBCOV_SLOT_FLAG_ITER: return "iter";
    case LIBCOV_SLOT_FLAG_GAP:  return "gap";
    case 0:                     return "none";
    default:                    return "?";
    }
}

/* Read one snapshot with the seqlock pattern. 0 on success (target_gen's
 * snapshot copied into out), 1 on torn/not-yet (retry), -1 on overrun. */
static inline int rr_read_slot(void *shm_base, uint64_t target_gen, uint8_t *out,
                        uint64_t *tid_out, uint64_t *ns_out,
                        uint64_t *flags_out) {
    volatile struct libcov_shm_header *hdr = shm_base;
    uint64_t gen_now = __atomic_load_n((uint64_t *)&hdr->gen_current,
                                       __ATOMIC_ACQUIRE);
    if (gen_now < target_gen) return 1;
    if (gen_now - target_gen >= (uint64_t)hdr->ring_size) return -1;

    size_t idx = (size_t)(target_gen % hdr->ring_size);
    struct libcov_ring_slot_hdr *s = (struct libcov_ring_slot_hdr *)
        ((uint8_t *)shm_base + hdr->ring_offset + idx * hdr->slot_stride);

    uint64_t pre = __atomic_load_n(&s->slot_gen, __ATOMIC_ACQUIRE);
    if (pre != target_gen) return 1;

    memcpy(out, (uint8_t *)(s + 1), hdr->map_size);
    uint64_t tid = s->tid, ns = s->ns, fl = s->flags;

    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    uint64_t post = __atomic_load_n(&s->slot_gen, __ATOMIC_RELAXED);
    if (post != target_gen) return 1;

    if (tid_out) *tid_out = tid;
    if (ns_out)  *ns_out  = ns;
    if (flags_out) *flags_out = fl;
    return 0;
}

/* Block until gen_current > prev_gen, or timeout. Returns the latest gen. */
static inline uint64_t rr_wait_gen_advance(void *shm_base, uint64_t prev_gen,
                                    unsigned timeout_ms) {
    volatile struct libcov_shm_header *hdr = shm_base;
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        uint64_t g = __atomic_load_n((uint64_t *)&hdr->gen_current,
                                     __ATOMIC_ACQUIRE);
        if (g > prev_gen) return g;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
                          (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed_ms >= (long)timeout_ms) return g;
        struct timespec sl = {0, 100000};  /* 100 us */
        nanosleep(&sl, NULL);
    }
}

/* Read every generation in (*prev_gen, target_gen], invoking cb per slot.
 * Updates *prev_gen and st. On overrun it skips to the oldest readable gen
 * (lag tolerance = ring_size - 1) and records the loss. `scratch` must be at
 * least map_size bytes. */
static inline void rr_drain_to(void *shm_base, uint64_t *prev_gen, uint64_t target_gen,
                        uint8_t *scratch, size_t map_size, struct rr_stats *st,
                        rr_slot_cb cb, void *user) {
    while (*prev_gen < target_gen) {
        uint64_t g = *prev_gen + 1;
        uint64_t tid = 0, ns = 0, flags = 0;
        int attempts = 0, rc;
        do {
            rc = rr_read_slot(shm_base, g, scratch, &tid, &ns, &flags);
            if (rc == 1) {
                struct timespec sl = {0, 50000};
                nanosleep(&sl, NULL);
            }
        } while (rc == 1 && ++attempts < 100);

        if (rc == -1) {
            volatile struct libcov_shm_header *hdr = shm_base;
            uint64_t now = __atomic_load_n((uint64_t *)&hdr->gen_current,
                                           __ATOMIC_ACQUIRE);
            uint64_t ring = hdr->ring_size;
            uint64_t oldest = now + 2 > ring ? now + 2 - ring : 1;
            if (oldest <= g) oldest = g + 1;
            fprintf(stderr,
                    "OVERRUN: writer at gen=%lu, gens %lu..%lu lost (ring=%lu); "
                    "resuming at %lu\n",
                    (unsigned long)now, (unsigned long)g,
                    (unsigned long)(oldest - 1), (unsigned long)ring,
                    (unsigned long)oldest);
            st->overruns++;
            st->lost_gens += oldest - g;
            *prev_gen = oldest - 1;
            continue;
        }
        if (rc != 0) {
            fprintf(stderr, "rr_read_slot gen=%lu failed (rc=%d) after %d attempts\n",
                    (unsigned long)g, rc, attempts);
            st->read_failures++;
            return;
        }

        if (flags == LIBCOV_SLOT_FLAG_INIT) st->kind_init++;
        else if (flags == LIBCOV_SLOT_FLAG_ITER) st->kind_iter++;
        else if (flags == LIBCOV_SLOT_FLAG_GAP) st->kind_gap++;
        if (cb) cb(g, scratch, map_size, tid, ns, flags, user);
        *prev_gen = g;
    }
}

#endif /* LIBCOV_RING_READER_H */
