#define _GNU_SOURCE
#include "config.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <endian.h>

/* LCV1 fields are little-endian on disk. Reads must be byte-swapped on BE
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

int config_load(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { libcov_logf("config: open(%s): %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); libcov_logf("config: fstat: %s", strerror(errno)); return -1; }
    if ((size_t)st.st_size < sizeof(struct patchlist_header)) {
        close(fd); libcov_logf("config: file too small"); return -1;
    }
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) { libcov_logf("config: mmap: %s", strerror(errno)); return -1; }

    const char *hbytes = map;
    if (memcmp(hbytes, LIBCOV_MAGIC, 4) != 0) {
        libcov_logf("config: bad magic"); munmap(map, st.st_size); return -1;
    }
    uint32_t version = rd_u32le(hbytes + 4);
    uint32_t count   = rd_u32le(hbytes + 8);
    if (version != LIBCOV_VERSION) {
        libcov_logf("config: bad version %u", version); munmap(map, st.st_size); return -1;
    }
    size_t need = sizeof(struct patchlist_header)
                + (size_t)count * sizeof(struct patchlist_record);
    if ((size_t)st.st_size < need) {
        libcov_logf("config: truncated (count=%u)", count); munmap(map, st.st_size); return -1;
    }

    const char *modname = getenv("LIBCOV_MODULE");
    uintptr_t base = util_module_base(modname);
    if (!base) { libcov_logf("config: cannot resolve module base"); munmap(map, st.st_size); return -1; }
    libcov_logf("config: module base = 0x%lx", (unsigned long)base);

    g_count = count;
    g_table = calloc(g_count, sizeof(struct patch_entry));
    if (!g_table) { munmap(map, st.st_size); return -1; }

    const char *rec_base = hbytes + sizeof(struct patchlist_header);
    for (size_t i = 0; i < g_count; i++) {
        const char *r = rec_base + i * sizeof(struct patchlist_record);
        uint64_t off  = rd_u64le(r);
        uint8_t  len  = (uint8_t)r[8];
        g_table[i].addr = base + (uintptr_t)off;
        g_table[i].len  = len;
        memcpy(g_table[i].orig, r + 9, sizeof g_table[i].orig);
        g_table[i].patched = 0;
    }
    munmap(map, st.st_size);

    qsort(g_table, g_count, sizeof(*g_table), cmp_entry);
    libcov_logf("config: loaded %zu records", g_count);
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
