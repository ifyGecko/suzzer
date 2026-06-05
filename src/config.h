/*
 * config.h -- on-disk patch-list format.
 *
 * File layout:
 *   struct patchlist_header  (16 bytes)
 *   struct patchlist_record  count times (24 bytes each)
 *
 * All fields little-endian. Offsets are relative to the runtime base of the
 * target module (typically the main executable) as observed in
 * /proc/self/maps.
 */
#ifndef LIBCOV_CONFIG_H
#define LIBCOV_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#define LIBCOV_MAGIC   "LCV1"
#define LIBCOV_VERSION 1u

struct patchlist_header {
    char     magic[4];
    uint32_t version;
    uint32_t count;
    uint32_t reserved;
} __attribute__((packed));

struct patchlist_record {
    uint64_t offset;    /* offset from module base */
    uint8_t  len;       /* original instruction length (1..15) */
    uint8_t  orig[15];  /* original bytes, only [0..len) meaningful */
} __attribute__((packed));

/* Runtime entry built from a record + module base. Sorted by addr; built
 * once at init, never resized, so reads are safe in a signal handler. */
struct patch_entry {
    uintptr_t addr;          /* absolute address in target process */
    uint8_t   len;           /* original instruction length */
    uint8_t   orig[15];      /* original bytes */
    uint8_t   patched;       /* 1 if currently illegal, 0 if restored */
};

int  config_load(const char *path);
const struct patch_entry *config_table(size_t *n_out);
struct patch_entry       *config_table_mut(size_t *n_out);

#endif
