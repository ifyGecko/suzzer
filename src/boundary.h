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

#include "lcv_formats.h"
#include "patchlist_format.h"

/* ---- formats ------------------------------------------------------------ *
 *
 * The LCVB1 sidecar (struct lcvb_header / lcvb_record, LIBCOV_BOUNDARY_*)
 * and the LCVS shm region (struct libcov_shm_header, struct
 * libcov_ring_slot_hdr, every LIBCOV_SHM_* / LIBCOV_SLOT_* constant) are
 * defined in lcv_formats.h, the header-only contract out-of-process drivers
 * vendor; docs/FORMATS.md specifies them.
 *
 *   offset                       contents
 *   0                            struct libcov_shm_header (72 B)
 *   bitmap_offset                live bitmap, map_size bytes
 *   ring_offset                  RING slots; each slot is slot_stride bytes
 *
 * Driver reads gen_current with acquire ordering, picks slot
 * ring[gen % ring_size] for the generation it wants (readable while
 * gen_current - gen < ring_size), and verifies slot_gen == gen pre- and
 * post-memcpy to detect torn reads (ring_reader.h: rr_read_slot).
 *
 * Which slot flag libcov stamps when:
 *   INIT  coverage from startup to the first boundary (hdr->gen_init).
 *   ITER  one iteration: in begin-only mode every later BEGIN publishes
 *         the iteration it ends; in paired mode an END publishes the
 *         BEGIN..END span (and a nested boundary, with depth_filter=any,
 *         the segment since the previous one).
 *   GAP   paired mode only: a BEGIN at depth 0 publishes what ran since the
 *         previous END -- the harness between iterations, not an input.
 *
 * LIVE_EMPTY is set in ST boundary mode (emits go straight into ring slots;
 * the bitmap_offset region stays zero), clear in MT boundary mode
 * (bitmap_offset accumulates non-worker/pre-first-boundary coverage) and
 * with boundaries off (bitmap_offset is the cumulative map). */

/* ---- public API ------------------------------------------------------- */

enum libcov_rearm_policy {
    LIBCOV_REARM_NONE    = 0,
    LIBCOV_REARM_ALL     = 1,
    LIBCOV_REARM_TOUCHED = 2,
};

/* Parse a LIBCOV_BOUNDARY_REARM value. Unset, empty, "none" and any
 * unrecognised value mean LIBCOV_REARM_NONE (boundary_init logs a warning
 * for the unrecognised case). libcov.c's oneshot+REARM=none refusal uses
 * this too, so both agree on what "none" means. */
enum libcov_rearm_policy boundary_parse_rearm(const char *s);

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
