/*
 * patch.h -- low-level instruction patching primitives.
 */
#ifndef LIBCOV_PATCH_H
#define LIBCOV_PATCH_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"

/* Validate that the byte sequence at e->addr matches e->orig[0..len).
 * Returns 0 on match, -1 on mismatch. Safe to call before patching. */
int patch_validate(const struct patch_entry *e);

/* Replace original instruction with the arch's trap encoding (+ pad if
 * len > trap-encoding-len). Sets e->patched = 1 on success. Signal-safe. */
int patch_arm(struct patch_entry *e);

/* Restore original bytes. Sets e->patched = 0. Signal-safe. */
int patch_disarm(struct patch_entry *e);

/* Bulk arm at init time. Returns number armed. */
size_t patch_arm_all(void);

/* Signal-safe binary search by absolute address. */
struct patch_entry *patch_lookup(uintptr_t addr);

/* Re-arm an explicit set of patch_entry pointers (caller-owned array).
 * Skips entries that are already armed. Signal-safe. Returns number armed.
 * Used by boundary mode when BOUNDARY_REARM=touched. */
size_t patch_rearm_set(struct patch_entry **set, size_t n);

/* Walk the global patch table and re-arm every entry that's currently
 * disarmed. Signal-safe. Returns number armed. Used by boundary mode when
 * BOUNDARY_REARM=all. */
size_t patch_rearm_all_disarmed(void);

#endif
