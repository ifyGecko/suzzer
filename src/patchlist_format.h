/*
 * patchlist_format.h -- on-disk patch-list wire format + runtime patch_entry.
 *
 * Format: LCV3. Single-version, no backward-compat readers retained.
 *
 *   struct patchlist_header_v3 {
 *       char     magic[4];        // "LCV3"
 *       uint32_t version;         // 3
 *       uint32_t count;           // number of records that follow the header
 *       uint8_t  threading;       // 0=ANY, 1=ST, 2=MT
 *       uint8_t  flags;           // reserved, must be 0
 *       uint8_t  module_count;    // 1..255 entries in the name table
 *       uint8_t  reserved;
 *       uint32_t modules_offset;  // file offset of the module-name table
 *       uint32_t modules_size;    // total bytes in the name table
 *   };
 *
 * Layout in file:
 *   [header_v3]
 *   [count * struct patchlist_record]
 *   [module name table: module_count NUL-terminated basenames concatenated]
 *
 * The module name table can sit immediately after the records (typical) or
 * anywhere else in the file (modules_offset is authoritative). Each name is
 * the basename of a loaded ELF (e.g. "target_simple", "libfoo.so") and is
 * resolved at init through /proc/self/maps. Record.module_idx is an index
 * into this table; the runtime resolves one load base per module name and
 * uses base[module_idx] + offset for each entry's absolute address.
 *
 * All multi-byte fields are little-endian on disk regardless of target endian.
 *
 * Record:
 *
 *   struct patchlist_record {
 *       uint64_t offset;       // from g_module_bases[module_idx]
 *       uint8_t  len;          // bytes to patch and restore (2 or 4)
 *       uint8_t  module_idx;   // index into the name table
 *       uint8_t  orig[4];      // first `len` bytes are meaningful
 *   } __attribute__((packed)); // 14 bytes
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
#ifndef LIBCOV_CONFIG_H
#define LIBCOV_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#define LIBCOV_MAGIC   "LCV3"
#define LIBCOV_VERSION 3u

/* Threading hint stored in the header. */
#define LIBCOV_TH_ANY 0u
#define LIBCOV_TH_ST  1u
#define LIBCOV_TH_MT  2u

/* Maximum bytes ever written by libcov_arch_write_illegal across all
 * supported arches. Sized so a single naturally-aligned 4-byte write
 * covers fixed-width 4-byte ISAs (aarch64/arm-ARM/mips/ppc/riscv64), and
 * 2-byte writes (x86 UD2, arm-Thumb, riscv64-C) fit with room to spare. */
#define LIBCOV_PATCH_ORIG_MAX 4u

/* Caps on the module name table. 255 modules is plenty for typical
 * targets (executable + a handful of shared libs). 4 KiB total name
 * bytes leaves room for fully-qualified long basenames if ever needed. */
#define LIBCOV_MAX_MODULES         255u
#define LIBCOV_MAX_MODULES_BYTES   4096u

struct patchlist_header_v3 {
    char     magic[4];
    uint32_t version;
    uint32_t count;
    uint8_t  threading;
    uint8_t  flags;
    uint8_t  module_count;
    uint8_t  reserved;
    uint32_t modules_offset;
    uint32_t modules_size;
} __attribute__((packed));

struct patchlist_record {
    uint64_t offset;
    uint8_t  len;
    uint8_t  module_idx;
    uint8_t  orig[LIBCOV_PATCH_ORIG_MAX];
} __attribute__((packed));

/* Runtime entry built from a record + module base. Sorted by addr; built
 * once at init, never resized, so reads are safe in a signal handler.
 *
 * `patched` is plain uint8_t. ST-mode code reads/writes it directly.
 *
 * `lock` is MT-only: a single-byte spinlock acquired around the byte-write
 * critical section in patch_mt.c, so an in-flight arm and an in-flight
 * disarm on the same entry can't interleave their syscalls and leave the
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
    uint32_t  site_id;
};

int  config_load(const char *path);
const struct patch_entry *config_table(size_t *n_out);
struct patch_entry       *config_table_mut(size_t *n_out);

#endif
