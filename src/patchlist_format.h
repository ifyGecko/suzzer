/*
 * patchlist_format.h -- the LCV3 patch list as libcov's runtime sees it.
 *
 * The on-disk format itself (header and record structs, magic, version,
 * LIBCOV_TH_*, header flags, module tables) is defined in lcv_formats.h,
 * the header-only contract other executors vendor; docs/FORMATS.md is its
 * specification. This file adds only what libcov needs at runtime: the
 * patch_entry table built from the records, and the loader.
 *
 * Header flags: bit 0 (LCV_FLAG_MODULE_BASES) says a u64 link-base table
 * follows the name table; the other bits must be 0, and readers ignore bits
 * they don't know. config_load reads the base table only to log a mismatch
 * against the actual mapping (debug aid); offsets are always resolved
 * against the runtime base from /proc/self/maps.
 *
 * `len` is per-record so back-to-back 2-byte ISAs (arm-Thumb, riscv64-C)
 * can coexist with 4-byte ISAs in the same list without one site's arm
 * clobbering a neighboring armed site. The arch backend's write_illegal
 * is given `len` and writes exactly that many bytes; patch_arm /
 * patch_disarm validate and restore the same span.
 *
 * `orig[4]` is sized for the widest cross-arch case (4-byte fixed-width
 * ISAs). x86's UD2 patches store 2 meaningful bytes and ignore the tail.
 */
#ifndef LIBCOV_PATCHLIST_FORMAT_H
#define LIBCOV_PATCHLIST_FORMAT_H

#include <stdint.h>
#include <stddef.h>

#include "lcv_formats.h"

/* Runtime entry built from a record + module base. Sorted by addr; built
 * once at init, never resized, so reads are safe in a signal handler.
 *
 * `patched` is plain uint8_t. ST-mode code reads/writes it directly.
 *
 * `lock` is MT-only: a single-byte spinlock acquired around the byte-write
 * critical section in patch_mt.c, so an in-flight arm and an in-flight
 * disarm on the same entry can't interleave their writes and leave the
 * bytes inconsistent with `patched`. ST-mode ignores this field.
 *
 * `module_idx` is carried from the wire record so the trap handler can
 * subtract the correct module base in sink_hash_pc (ASLR invariance).
 *
 * `marker` is set by boundary_init on the sites that are iteration-boundary
 * markers. Their re-arm is owned by boundary.c's pending protocol; the
 * leapfrog and bulk re-arm paths skip them (re-arming a marker another
 * thread is still inside the handler for makes that thread re-trap).
 *
 * `emulate` is set by boundary_init on markers whose original instruction
 * the arch backend can execute in software (libcov_arch_emulate): the
 * handler performs it and advances the PC, so the site is never disarmed.
 *
 * `touched` is set while the entry sits in boundary.c's REARM=touched
 * queue, so each disarmed site is queued at most once.
 *
 * `dead` is set by patch_arm_all on every entry it declined to arm (a
 * self-patch, a stale entry, an MT-unsafe x86 site, a failed write).
 * patch_arm/patch_disarm refuse a dead entry, so no later path (leapfrog,
 * boundary REARM=all, a marker's pending re-arm) can write it, and the
 * handlers treat a trap there as not libcov's.
 *
 * `site_id` is a dense identifier in [0, count) assigned at config_load
 * time as the file record index, BEFORE the table is sorted by addr (the
 * sort carries it along). It is the bitmap bucket base under the site-id
 * coverage model and is ASLR-invariant + decodable straight back to the
 * Nth patchlist record. Not part of the on-disk wire record. */
struct patch_entry {
    uintptr_t addr;
    uint8_t   len;
    uint8_t   module_idx;
    uint8_t   orig[LIBCOV_PATCH_ORIG_MAX];
    uint8_t   patched;
    uint8_t   lock;
    uint8_t   marker;
    uint8_t   touched;
    uint8_t   emulate;
    uint8_t   dead;
    uint32_t  site_id;
};

int  config_load(const char *path);
const struct patch_entry *config_table(size_t *n_out);
struct patch_entry       *config_table_mut(size_t *n_out);

#endif
