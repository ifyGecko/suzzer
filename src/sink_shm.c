#define _GNU_SOURCE
#include "sink.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

uint8_t  *libcov_bitmap   = NULL;
uint16_t  libcov_prev_loc = 0;

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

int sink_init(const char *path) {
    char default_path[128];
    if (!path || !*path) {
        snprintf(default_path, sizeof default_path, "/libcov_%d", (int)getpid());
        path = default_path;
    }

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

    if (ftruncate(fd, LIBCOV_MAP_SIZE) < 0) {
        libcov_logf("sink: ftruncate: %s", strerror(errno));
        close(fd);
        return -1;
    }
    void *m = mmap(NULL, LIBCOV_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) {
        libcov_logf("sink: mmap: %s", strerror(errno));
        return -1;
    }
    /* Don't zero the map; an external driver may want hit-counts to accumulate
     * across runs, or clear them between iterations on its side. */
    libcov_bitmap = (uint8_t *)m;
    libcov_logf("sink: bitmap @ %p size=%u", m, (unsigned)LIBCOV_MAP_SIZE);
    return 0;
}
