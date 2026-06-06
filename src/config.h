/*
 * config.h -- on-disk patch-list format.
 *
 * Two versions are accepted by the loader:
 *
 *   LCV1 (legacy): 16-byte header, no threading hint. Treated as "any".
 *
 *     struct patchlist_header_v1 {
 *         char     magic[4];   // "LCV1"
 *         uint32_t version;    // 1
 *         uint32_t count;
 *         uint32_t reserved;
 *     };
 *
 *   LCV2 (current): 16-byte header, carries a threading-mode hint so a
 *   library built for one threading model refuses a patch list built for
 *   another. Field layout matches LCV1's first 12 bytes; the last 4 bytes
 *   are a one-byte hint, one-byte flags, two-byte reserved.
 *
 *     struct patchlist_header_v2 {
 *         char     magic[4];   // "LCV2"
 *         uint32_t version;    // 2
 *         uint32_t count;
 *         uint8_t  threading;  // 0=ANY, 1=ST, 2=MT
 *         uint8_t  flags;      // reserved
 *         uint16_t reserved;
 *     };
 *
 * Both versions are followed by `count` records of struct patchlist_record.
 * All multi-byte fields little-endian on disk regardless of target endian.
 */
#ifndef LIBCOV_CONFIG_H
#define LIBCOV_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#define LIBCOV_MAGIC_V1   "LCV1"
#define LIBCOV_MAGIC_V2   "LCV2"
#define LIBCOV_VERSION_V1 1u
#define LIBCOV_VERSION_V2 2u

/* Back-compat aliases. New code should use the _V2 names. */
#define LIBCOV_MAGIC   LIBCOV_MAGIC_V2
#define LIBCOV_VERSION LIBCOV_VERSION_V2

/* Threading hint stored in LCV2 header. */
#define LIBCOV_TH_ANY 0u
#define LIBCOV_TH_ST  1u
#define LIBCOV_TH_MT  2u

struct patchlist_header_v1 {
    char     magic[4];
    uint32_t version;
    uint32_t count;
    uint32_t reserved;
} __attribute__((packed));

struct patchlist_header_v2 {
    char     magic[4];
    uint32_t version;
    uint32_t count;
    uint8_t  threading;
    uint8_t  flags;
    uint16_t reserved;
} __attribute__((packed));

struct patchlist_record {
    uint64_t offset;    /* offset from module base */
    uint8_t  len;       /* original instruction length (1..15) */
    uint8_t  orig[15];  /* original bytes, only [0..len) meaningful */
} __attribute__((packed));

/* Runtime entry built from a record + module base. Sorted by addr; built
 * once at init, never resized, so reads are safe in a signal handler.
 *
 * `patched` is plain uint8_t. ST-mode code reads/writes it directly.
 *
 * `lock` is MT-only: a single-byte spinlock acquired around the byte-write
 * critical section in patch_mt.c, so an in-flight arm and an in-flight
 * disarm on the same entry can't interleave their syscalls and leave the
 * bytes inconsistent with `patched`. ST-mode ignores this field. */
struct patch_entry {
    uintptr_t addr;          /* absolute address in target process */
    uint8_t   len;           /* original instruction length */
    uint8_t   orig[15];      /* original bytes */
    uint8_t   patched;       /* 1 if currently illegal, 0 if restored */
    uint8_t   lock;          /* MT-only: 1 if arm/disarm in progress */
};

int  config_load(const char *path);
const struct patch_entry *config_table(size_t *n_out);
struct patch_entry       *config_table_mut(size_t *n_out);

#endif
