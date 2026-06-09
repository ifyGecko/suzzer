#define _GNU_SOURCE
#include "sink.h"
#include "boundary.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

void   *libcov_shm_base = NULL;
size_t  libcov_shm_size = 0;
uint8_t *libcov_bitmap  = NULL;

/* Per-module load bases. Populated in config.c::config_load() from
 * util_module_base() for each module name in the LCV3 header's name
 * table. Indexed by patch_entry.module_idx in sink_hash_pc. Entries
 * for unused slots stay 0. See the longer comment in sink.h. */
uintptr_t libcov_module_bases[LIBCOV_MAX_MODULES] = {0};

/* prev_loc window: shared global for ST builds; TLS for MT builds so
 * concurrent threads don't fight over edge attribution. Length is
 * LIBCOV_NGRAM_WIN = max(N-1, 1) -- N=1 still allocates one (unused)
 * slot so the array never has zero length. The declaration in sink.h
 * picks the same qualifier; keep them in sync. */
#if defined(LIBCOV_THREADING_MT)
__thread uint16_t libcov_prev_loc[LIBCOV_NGRAM_WIN] = {0};
#else
uint16_t libcov_prev_loc[LIBCOV_NGRAM_WIN] = {0};
#endif

static int try_shm_open(const char *name, int *fd_out) {
    /* shm_open requires a leading slash. */
    char buf[256];
    if (name[0] != '/') {
        snprintf(buf, sizeof buf, "/%s", name);
        name = buf;
    }
    int fd = shm_open(name, O_RDWR | O_CREAT, 0600);
    if (fd < 0) return -1;
    *fd_out = fd;
    return 0;
}

static int try_file_open(const char *path, int *fd_out) {
    int fd = open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) return -1;
    *fd_out = fd;
    return 0;
}

/* Total shm size = header + live bitmap + ring*slot_stride. */
static size_t compute_shm_size(unsigned ring_size, size_t *bitmap_off_out,
                               size_t *ring_off_out, size_t *slot_stride_out) {
    size_t hdr      = sizeof(struct libcov_shm_header);
    size_t bmap_off = hdr;
    size_t ring_off = bmap_off + LIBCOV_MAP_SIZE;
    size_t stride   = sizeof(struct libcov_ring_slot_hdr) + LIBCOV_MAP_SIZE;
    size_t total    = ring_off + (size_t)ring_size * stride;
    if (bitmap_off_out)  *bitmap_off_out = bmap_off;
    if (ring_off_out)    *ring_off_out   = ring_off;
    if (slot_stride_out) *slot_stride_out = stride;
    return total;
}

int sink_init(const char *path, unsigned ring_size) {
    char default_path[128];
    if (!path || !*path) {
        snprintf(default_path, sizeof default_path, "/libcov_%d", (int)getpid());
        path = default_path;
    }

    if (ring_size < 2)  ring_size = 2;
    if (ring_size > 16) ring_size = 16;

    size_t bitmap_off, ring_off, slot_stride;
    size_t total = compute_shm_size(ring_size, &bitmap_off, &ring_off, &slot_stride);

    int fd = -1;
    /* Heuristic: if path looks like a filesystem path (contains a non-leading
     * '/'), use open(); otherwise try shm_open first then fall back to a
     * tmpfile under TMPDIR or /tmp. */
    int looks_like_fs = 0;
    for (const char *p = path + (path[0] == '/'); *p; p++) {
        if (*p == '/') { looks_like_fs = 1; break; }
    }

    if (looks_like_fs) {
        if (try_file_open(path, &fd) < 0) {
            libcov_logf("sink: open(%s): %s", path, strerror(errno));
            return -1;
        }
    } else {
        if (try_shm_open(path, &fd) < 0) {
            const char *tmpdir = getenv("TMPDIR");
            if (!tmpdir || !*tmpdir) tmpdir = "/tmp";
            char fallback[256];
            const char *bare = (path[0] == '/') ? path + 1 : path;
            snprintf(fallback, sizeof fallback, "%s/%s", tmpdir, bare);
            if (try_file_open(fallback, &fd) < 0) {
                libcov_logf("sink: shm_open + fallback failed for %s", path);
                return -1;
            }
            libcov_logf("sink: using file fallback %s", fallback);
        }
    }

    if (ftruncate(fd, (off_t)total) < 0) {
        libcov_logf("sink: ftruncate(%zu): %s", total, strerror(errno));
        close(fd);
        return -1;
    }
    void *m = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) {
        libcov_logf("sink: mmap: %s", strerror(errno));
        return -1;
    }

    /* Zero the entire region so the driver sees clean state at attach
     * and the ring slots start with slot_gen=0 ("empty"). The previous
     * "don't zero" comment predated the boundary mechanism: iteration
     * framing now lives in the header + ring, and per-iter clearing of
     * the live bitmap is libcov's job (not the driver's). */
    memset(m, 0, total);
    struct libcov_shm_header *hdr = (struct libcov_shm_header *)m;
    memcpy(hdr->magic, LIBCOV_SHM_MAGIC, 4);
    hdr->version       = (uint16_t)LIBCOV_SHM_VERSION;
    hdr->ring_size     = (uint16_t)ring_size;
    hdr->map_size      = LIBCOV_MAP_SIZE;
    hdr->slot_stride   = (uint32_t)slot_stride;
    hdr->flags         = 0;        /* SHM_FLAG_ACTIVE set later by boundary_init */
    hdr->gen_current   = 0;
    hdr->gen_init      = 0;
    hdr->bitmap_offset = bitmap_off;
    hdr->ring_offset   = ring_off;

    libcov_shm_base = m;
    libcov_shm_size = total;
    libcov_bitmap   = (uint8_t *)m + bitmap_off;
    memset(libcov_prev_loc, 0, sizeof libcov_prev_loc);

    libcov_logf("sink: shm @ %p total=%zu bitmap@+%zu ring@+%zu slots=%u stride=%zu",
                m, total, bitmap_off, ring_off, ring_size, slot_stride);
    return 0;
}
