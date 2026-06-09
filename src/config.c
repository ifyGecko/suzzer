#define _GNU_SOURCE
#include "patchlist_format.h"
#include "util.h"
#include "sink.h"   /* libcov_module_bases */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* This translation unit is compiled twice (once for each variant build) with
 * exactly one of LIBCOV_THREADING_ST / LIBCOV_THREADING_MT defined. The macro
 * controls the threading-hint check at load time so a wrong-variant patch
 * list is refused with a clear log message. */
#if defined(LIBCOV_THREADING_MT)
#  define LIBCOV_TH_SELF LIBCOV_TH_MT
#  define LIBCOV_TH_SELF_NAME "mt"
#else
#  define LIBCOV_TH_SELF LIBCOV_TH_ST
#  define LIBCOV_TH_SELF_NAME "st"
#endif

/* LCV3 fields are little-endian on disk. Reads must be byte-swapped on BE
 * targets. We use memcpy + le32toh / le64toh to avoid alignment issues. */
static inline uint32_t rd_u32le(const void *p) {
    uint32_t v;
    memcpy(&v, p, sizeof v);
    return le32toh(v);
}
static inline uint64_t rd_u64le(const void *p) {
    uint64_t v;
    memcpy(&v, p, sizeof v);
    return le64toh(v);
}

static struct patch_entry *g_table = NULL;
static size_t              g_count = 0;

static int cmp_entry(const void *a, const void *b) {
    uintptr_t aa = ((const struct patch_entry *)a)->addr;
    uintptr_t bb = ((const struct patch_entry *)b)->addr;
    return (aa > bb) - (aa < bb);
}

/* Parse the LCV3 header. Sets the output fields and returns the byte
 * offset of the first record (== sizeof(header_v3)) on success, or 0
 * on error. */
static size_t parse_header(const char *bytes, size_t size,
                           uint32_t *count_out, uint8_t *threading_out,
                           uint8_t *module_count_out,
                           uint32_t *modules_offset_out,
                           uint32_t *modules_size_out) {
    if (size < sizeof(struct patchlist_header_v3)) {
        libcov_logf("config: file too small for LCV3 header");
        return 0;
    }
    if (memcmp(bytes, LIBCOV_MAGIC, 4) != 0) {
        libcov_logf("config: bad magic (expected LCV3)");
        return 0;
    }
    uint32_t version = rd_u32le(bytes + 4);
    if (version != LIBCOV_VERSION) {
        libcov_logf("config: LCV3 bad version %u", version);
        return 0;
    }
    *count_out          = rd_u32le(bytes + 8);
    *threading_out      = (uint8_t)bytes[12];
    /* bytes[13] = flags, must be 0 (reserved). */
    *module_count_out   = (uint8_t)bytes[14];
    /* bytes[15] = reserved. */
    *modules_offset_out = rd_u32le(bytes + 16);
    *modules_size_out   = rd_u32le(bytes + 20);
    return sizeof(struct patchlist_header_v3);
}

int config_load(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { libcov_logf("config: open(%s): %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); libcov_logf("config: fstat: %s", strerror(errno)); return -1; }
    if ((size_t)st.st_size < sizeof(struct patchlist_header_v3)) {
        close(fd); libcov_logf("config: file too small"); return -1;
    }
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) { libcov_logf("config: mmap: %s", strerror(errno)); return -1; }

    const char *hbytes = map;
    uint32_t count = 0;
    uint8_t  threading = LIBCOV_TH_ANY;
    uint8_t  module_count = 0;
    uint32_t modules_offset = 0;
    uint32_t modules_size = 0;
    size_t recs_off = parse_header(hbytes, (size_t)st.st_size,
                                   &count, &threading,
                                   &module_count,
                                   &modules_offset, &modules_size);
    if (recs_off == 0) { munmap(map, st.st_size); return -1; }

    /* Threading-hint check: ANY accepts anything; otherwise must match self. */
    if (threading != LIBCOV_TH_ANY && threading != LIBCOV_TH_SELF) {
        const char *want = (threading == LIBCOV_TH_ST) ? "st" :
                           (threading == LIBCOV_TH_MT) ? "mt" : "?";
        libcov_logf("config: patch list built for threading=%s, this library is %s -- refusing",
                    want, LIBCOV_TH_SELF_NAME);
        munmap(map, st.st_size);
        return -1;
    }

    if (module_count < 1) {
        libcov_logf("config: invalid module_count=%u", (unsigned)module_count);
        munmap(map, st.st_size);
        return -1;
    }
    /* module_count is uint8_t so it can't exceed LIBCOV_MAX_MODULES (255)
     * by construction; no upper-bound check needed here. */

    size_t need_records = recs_off + (size_t)count * sizeof(struct patchlist_record);
    if ((size_t)st.st_size < need_records) {
        libcov_logf("config: truncated records (count=%u)", count); munmap(map, st.st_size); return -1;
    }
    if (modules_size == 0 || modules_size > LIBCOV_MAX_MODULES_BYTES) {
        libcov_logf("config: invalid modules_size=%u", modules_size);
        munmap(map, st.st_size); return -1;
    }
    if ((size_t)modules_offset + modules_size > (size_t)st.st_size) {
        libcov_logf("config: module table runs past end of file");
        munmap(map, st.st_size); return -1;
    }

    /* Walk the name table once, resolving each module's load base via
     * /proc/self/maps. Refuse to load if any named module is not mapped --
     * better to fail loudly at init than to leave half the bitmap silently
     * misindexed. The trailing byte of the table must be NUL so the last
     * name terminates cleanly. */
    const char *names = hbytes + modules_offset;
    if (names[modules_size - 1] != 0) {
        libcov_logf("config: module table not NUL-terminated");
        munmap(map, st.st_size); return -1;
    }

    /* Reset bases each call so re-init under the same process doesn't
     * leak stale entries. */
    for (size_t i = 0; i < LIBCOV_MAX_MODULES; i++) libcov_module_bases[i] = 0;

    size_t name_pos = 0;
    for (unsigned m = 0; m < module_count; m++) {
        if (name_pos >= modules_size) {
            libcov_logf("config: module table truncated at module %u", m);
            munmap(map, st.st_size); return -1;
        }
        const char *name = names + name_pos;
        size_t name_len  = strlen(name);
        name_pos += name_len + 1;
        if (!*name) {
            libcov_logf("config: empty module name at index %u", m);
            munmap(map, st.st_size); return -1;
        }
        uintptr_t b = util_module_base(name);
        if (!b) {
            libcov_logf("config: cannot resolve module base for '%s'", name);
            munmap(map, st.st_size); return -1;
        }
        libcov_module_bases[m] = b;
        libcov_logf("config: module[%u] '%s' base=0x%lx", m, name, (unsigned long)b);
    }

    g_count = count;
    g_table = calloc(g_count, sizeof(struct patch_entry));
    if (!g_table) { munmap(map, st.st_size); return -1; }

    const char *rec_base = hbytes + recs_off;
    size_t per_module_armed[LIBCOV_MAX_MODULES] = {0};
    for (size_t i = 0; i < g_count; i++) {
        const char *r = rec_base + i * sizeof(struct patchlist_record);
        uint64_t off  = rd_u64le(r);
        uint8_t  len  = (uint8_t)r[8];
        uint8_t  midx = (uint8_t)r[9];
        if (midx >= module_count) {
            libcov_logf("config: record %zu has module_idx=%u out of range (count=%u)",
                        i, (unsigned)midx, (unsigned)module_count);
            free(g_table); g_table = NULL; g_count = 0;
            munmap(map, st.st_size); return -1;
        }
        g_table[i].addr       = libcov_module_bases[midx] + (uintptr_t)off;
        g_table[i].len        = len;
        g_table[i].module_idx = midx;
        memcpy(g_table[i].orig, r + 10, LIBCOV_PATCH_ORIG_MAX);
        g_table[i].patched    = 0;
        g_table[i].lock       = 0;
        per_module_armed[midx]++;
    }
    munmap(map, st.st_size);

    qsort(g_table, g_count, sizeof(*g_table), cmp_entry);
    libcov_logf("config: loaded %zu records across %u module(s) (libcov threading=%s)",
                g_count, (unsigned)module_count, LIBCOV_TH_SELF_NAME);
    for (unsigned m = 0; m < module_count; m++) {
        libcov_logf("config:   module[%u] records=%zu", m, per_module_armed[m]);
    }
    return 0;
}

const struct patch_entry *config_table(size_t *n_out) {
    if (n_out) *n_out = g_count;
    return g_table;
}

struct patch_entry *config_table_mut(size_t *n_out) {
    if (n_out) *n_out = g_count;
    return g_table;
}
