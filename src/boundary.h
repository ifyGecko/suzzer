/*
 * boundary.h -- iteration boundary detection.
 *
 * libcov on its own emits edges as they happen; it has no concept of a
 * "fuzz iteration." The boundary module gives the engineer a way to tell
 * libcov "this address means a new logical unit of work has started," so
 * coverage can be sliced per input.
 *
 * Mechanism (policy is per-target config):
 *   - A sidecar LCVB1 file lists marker addresses (module-relative offsets).
 *   - When the trap handler hits a marker, libcov publishes the current
 *     bitmap to a ring of snapshots, bumps a generation counter, optionally
 *     re-arms patch sites, and clears the live bitmap for the next iter.
 *   - The external driver/shim reads ring[gen % RING] for the most recent
 *     completed iteration. Per-slot generation stamps + double-read protect
 *     against desync.
 *
 * Threading: most state is shared across threads; depth tracking, the
 * touched-this-iter stack, and (once a thread fires its first boundary)
 * the live bitmap are per-thread (__thread) under LIBCOV_THREADING_MT so
 * two concurrent request handlers don't corrupt each other's iteration
 * scoping or snapshots. The same source compiles with plain globals under
 * LIBCOV_THREADING_ST. See boundary.c's header for the details.
 *
 * Boundaries are inert unless LIBCOV_BOUNDARY_LIST is set; existing
 * coverage runs are unaffected.
 */
#ifndef LIBCOV_BOUNDARY_H
#define LIBCOV_BOUNDARY_H

#include <stdint.h>
#include <stddef.h>

#include "patchlist_format.h"

/* ---- on-disk sidecar format -------------------------------------------- */

#define LIBCOV_BOUNDARY_MAGIC   "LCVB"
#define LIBCOV_BOUNDARY_VERSION 1u

#define LIBCOV_BOUNDARY_KIND_BEGIN 0
#define LIBCOV_BOUNDARY_KIND_END   1

struct lcvb_header {
    char     magic[4];
    uint32_t version;
    uint32_t count;
    uint32_t flags;     /* bit0 = paired (begin+end), reserved otherwise */
} __attribute__((packed));

struct lcvb_record {
    uint64_t offset;        /* from target module base */
    uint8_t  kind;          /* BEGIN or END */
    uint8_t  depth_filter;  /* 0 = any depth, 1 = depth-zero only */
    uint8_t  reserved[6];
} __attribute__((packed));

/* ---- shm layout (extends sink_shm.c) ---------------------------------- *
 *
 *   offset                       contents
 *   0                            struct libcov_shm_header (72 B after alignment)
 *   bitmap_offset                live bitmap, MAP_SIZE bytes
 *   ring_offset                  RING slots; each slot is slot_stride bytes
 *
 * Driver reads gen_current with acquire ordering, picks slot
 * ring[(gen_current - 1) % ring_size], verifies slot_gen pre- and
 * post-memcpy to detect torn reads. */

#define LIBCOV_SHM_MAGIC        "LCVS"
#define LIBCOV_SHM_VERSION      1u
#define LIBCOV_SHM_FLAG_ACTIVE  (1u << 0)  /* boundaries active */
#define LIBCOV_SHM_FLAG_MT      (1u << 1)  /* MT-variant libcov */
/* Set when the live bitmap at bitmap_offset is NOT maintained and a driver
 * must read the ring instead. Set in ST boundary mode (emits go straight into
 * ring slots; the bitmap_offset region stays zero). Clear in MT boundary mode
 * (bitmap_offset accumulates non-worker/pre-first-boundary coverage) and with
 * boundaries off (bitmap_offset is the cumulative map). */
#define LIBCOV_SHM_FLAG_LIVE_EMPTY (1u << 2)

struct libcov_shm_header {
    char     magic[4];
    uint16_t version;
    uint16_t ring_size;
    uint32_t map_size;
    uint32_t slot_stride;     /* bytes per ring slot (slot hdr + bitmap) */
    uint32_t flags;
    uint64_t gen_current;     /* atomic: last fully-published gen */
    uint64_t gen_init;        /* gen when init snapshot was captured (0 = none) */
    uint64_t bitmap_offset;   /* shm-base relative */
    uint64_t ring_offset;     /* shm-base relative */
    /* atomic: MT publishes libcov dropped because a publisher RING gens
     * ahead already held the slot (that generation never reached the
     * ring). Always 0 under ST. Readers compare it across a run. */
    uint32_t publish_dropped;
    /* The process that created the region: pid and its start time (clock
     * ticks since boot, low 32 bits). exec keeps both, so an in-place
     * re-exec recognises its own region and attaches instead of zeroing
     * it; another live process leaves it alone (sink_shm.c). */
    uint32_t owner_pid;
    uint32_t owner_start;
    uint8_t  reserved[4];
};
/* The layout is an ABI with out-of-process drivers: fields only ever take
 * over reserved bytes. */
_Static_assert(sizeof(struct libcov_shm_header) == 72, "shm header is 72 bytes");
_Static_assert(__builtin_offsetof(struct libcov_shm_header, publish_dropped) == 56,
               "publish_dropped sits at offset 56");
_Static_assert(__builtin_offsetof(struct libcov_shm_header, owner_pid) == 60,
               "owner_pid sits at offset 60");

struct libcov_ring_slot_hdr {
    uint64_t slot_gen;        /* atomic: 0 = empty/in-progress; otherwise gen */
    uint64_t tid;
    uint64_t ns;              /* CLOCK_MONOTONIC at publish */
    uint64_t flags;           /* reserved */
};
/* followed by MAP_SIZE bytes of bitmap */

/* ---- public API ------------------------------------------------------- */

enum libcov_rearm_policy {
    LIBCOV_REARM_NONE    = 0,
    LIBCOV_REARM_ALL     = 1,
    LIBCOV_REARM_TOUCHED = 2,
};

/* Parse env vars and load the sidecar. Returns 1 if boundaries are active,
 * 0 if LIBCOV_BOUNDARY_LIST is unset (inert), -1 on error.
 *
 * Must be called after sink_init (needs shm layout) and after config_load
 * (needs module base + patchlist size to allocate per-thread touched
 * scratch space). */
int boundary_init(void);

/* Fast accessor for the trap handler's hot path. */
int boundary_enabled(void);

/* Called from the trap handler after sink_emit + patch_disarm + the
 * per-trap re-arm policy (leapfrog or none), with the pc that trapped and
 * the patch_entry pointer that was just disarmed.
 *
 * Records the disarm for the per-iteration "touched" set, then checks
 * whether pc is a boundary marker; if so, publishes a snapshot and applies
 * the boundary re-arm policy. Signal-safe. No-op when boundaries are
 * disabled. */
void boundary_on_trap(uintptr_t pc, struct patch_entry *e);

#endif
