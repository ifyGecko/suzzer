/*
 * patch.h -- low-level instruction patching primitives.
 */
#ifndef LIBCOV_PATCH_H
#define LIBCOV_PATCH_H

#include <stdint.h>
#include <stddef.h>
#include "patchlist_format.h"

/* Validate that the byte sequence at e->addr matches e->orig[0..len).
 * Returns 0 on match, -1 on mismatch. Safe to call before patching. */
int patch_validate(const struct patch_entry *e);

/* Replace the first e->len bytes with the arch's trap encoding. Sets
 * e->patched = 1 on success. Signal-safe.
 * Issues a full cross-core I-cache sync after the write -- safe to call
 * standalone. For batched arm/disarm in a tight loop (handler, boundary
 * rearm) prefer patch_arm_unsynced + patch_sync_batch_end below. */
int patch_arm(struct patch_entry *e);

/* Restore original bytes. Sets e->patched = 0. Signal-safe. */
int patch_disarm(struct patch_entry *e);

/* Batched-rearm variants: write the bytes and do the per-write cache
 * maintenance (clear_cache), but skip the trailing cross-core membarrier
 * broadcast. The caller MUST issue exactly one patch_sync_batch_end()
 * after one or more _unsynced calls so peer threads context-synchronize
 * before they next fetch from the patched range.
 *
 * Rationale: when membarrier(SYNC_CORE) is available, one IPI is enough
 * to serialize every CPU regardless of how many sites we just touched.
 * Coalescing the IPIs cuts the handler's leapfrog tail from 2 broadcast
 * IPIs to 1, and the boundary touched/all-rearm loop from N to 1.
 *
 * On kernels without SYNC_CORE, batch_end does the signal broadcast
 * instead (membarrier.h), unless LIBCOV_SYNC_FALLBACK=off; see the
 * residual-window note in patch_mt.c. */
int  patch_arm_unsynced(struct patch_entry *e);
int  patch_disarm_unsynced(struct patch_entry *e);
void patch_sync_batch_end(void);

/* Bulk arm at init time. Returns number armed. */
size_t patch_arm_all(void);

/* Signal-safe binary search by absolute address. */
struct patch_entry *patch_lookup(uintptr_t addr);

#endif
