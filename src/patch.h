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

/* Replace original instruction with UD2 (+ NOP pad if len > 2).
 * Sets e->patched = 1 on success. Signal-safe. */
int patch_arm(struct patch_entry *e);

/* Restore original bytes. Sets e->patched = 0. Signal-safe. */
int patch_disarm(struct patch_entry *e);

/* Bulk arm at init time. Returns number armed. */
size_t patch_arm_all(void);

/* Signal-safe binary search by absolute address. */
struct patch_entry *patch_lookup(uintptr_t addr);

#endif
