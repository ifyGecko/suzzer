#define _GNU_SOURCE
#include "util.h"
#include "tunables.h"   /* LIBCOV_LOG_BUFFER_SIZE */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <sched.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

static int log_fd = 2;  /* stderr by default */

/* Identity of log_fd at init, and whether init has finished. After init
 * the interposers still log, but the target may by then have closed our
 * fd and reused the number (closefrom + socket) or dup2'd a socket onto
 * fd 2 -- a daemon's client would receive our log lines. So once sealed,
 * a line is written only while the fd still refers to the same file and
 * is not a socket. */
static dev_t log_dev;
static ino_t log_ino;
static int   log_identity_known, log_sealed;

void libcov_log_init(void) {
    const char *p = getenv("LIBCOV_LOG");
    if (p && *p) {
        int fd = open(p, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd >= 0) log_fd = fd;
        else libcov_logf("cannot open LIBCOV_LOG '%s': %s; logging to stderr",
                         p, strerror(errno));
    }
    struct stat st;
    if (fstat(log_fd, &st) == 0) {
        log_dev = st.st_dev;
        log_ino = st.st_ino;
        log_identity_known = 1;
    }
}

void libcov_log_seal(void) {
    log_sealed = 1;
}

static int log_fd_still_ours(void) {
    if (!log_sealed) return 1;
    struct stat st;
    if (!log_identity_known || fstat(log_fd, &st) != 0) return 0;
    return !S_ISSOCK(st.st_mode) && st.st_dev == log_dev && st.st_ino == log_ino;
}

void libcov_logf(const char *fmt, ...) {
    char buf[LIBCOV_LOG_BUFFER_SIZE];
    int n = snprintf(buf, sizeof buf, "libcov: ");
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(buf + n, sizeof buf - n, fmt, ap);
    va_end(ap);
    /* vsnprintf returns the untruncated length; clamp so a long message
     * (e.g. a 4 KiB path) doesn't make write() read past buf. */
    if (n < 0) return;
    if (n > (int)sizeof buf - 1) n = (int)sizeof buf - 1;
    buf[n++] = '\n';
    if (!log_fd_still_ours()) return;
    (void)write(log_fd, buf, (size_t)n);
}

static const char *basename_c(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

/* A mapping whose file was unlinked or replaced after it was mapped (a
 * daemon upgraded in place) shows up in /proc/self/maps, and readlink of
 * /proc/self/exe, with this suffix. */
static void strip_deleted(char *path) {
    static const char sfx[] = " (deleted)";
    size_t L = strlen(path), S = sizeof sfx - 1;
    if (L > S && !strcmp(path + L - S, sfx)) path[L - S] = 0;
}

uintptr_t util_module_base(const char *modname) {
    char want[4096];
    int by_path;
    if (!modname || !*modname) {
        /* The main executable, by its exact mapped path. */
        ssize_t r = readlink("/proc/self/exe", want, sizeof want - 1);
        if (r <= 0) return 0;
        want[r] = 0;
        strip_deleted(want);
        by_path = 1;
    } else if (modname[0] == '/') {
        /* An absolute path picks one file among same-basename modules;
         * resolve symlinks, since maps shows the real path. */
        if (!realpath(modname, want)) {
            strncpy(want, modname, sizeof want - 1);
            want[sizeof want - 1] = 0;
        }
        by_path = 1;
    } else {
        strncpy(want, basename_c(modname), sizeof want - 1);
        want[sizeof want - 1] = 0;
        by_path = 0;
    }

    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    char line[4096], first[4096] = "";
    uintptr_t base = 0;
    int warned = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long lo, hi, off, ino;
        char perms[8];
        int devmaj, devmin;
        int n;
        if (sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %n",
                   &lo, &hi, perms, &off, &devmaj, &devmin, &ino, &n) < 7) continue;
        char *path = line + n;
        while (*path == ' ') path++;
        size_t L = strlen(path);
        if (L && path[L - 1] == '\n') path[L - 1] = 0;
        if (!*path) continue;
        strip_deleted(path);
        if (strcmp(by_path ? path : basename_c(path), want) != 0) continue;
        if (!base) {
            /* First mapping for this module is the base. */
            base = lo - off;
            strncpy(first, path, sizeof first - 1);
        } else if (!warned && strcmp(path, first) != 0) {
            /* Keep scanning: a second file with the same basename means
             * the first match may well be the wrong one. */
            libcov_logf("module '%s' is ambiguous: %s and %s are both mapped; "
                        "using %s (set LIBCOV_MODULE_RENAME=%s=<absolute path> "
                        "to choose)", want, first, path, first, want);
            warned = 1;
        }
    }
    fclose(f);
    return base;
}

/* One mapping from the snapshot. base is the load base of its file (the
 * first mapping of that path: lo - off, as in util_module_base), 0 for
 * anonymous mappings. /proc/self/maps lists mappings in address order. */
struct maps_ent {
    uintptr_t lo, hi, base;
    int       readable;
};
static struct maps_ent *g_maps;
static size_t           g_maps_n;

int util_maps_load(void) {
    util_maps_free();
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return -1;
    /* Distinct file paths seen so far, with their base. */
    struct { char *path; uintptr_t base; } *files = NULL;
    size_t n_files = 0, cap = 0, fcap = 0;
    char line[4096];
    int rv = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long lo, hi, off, ino;
        char perms[8];
        int devmaj, devmin;
        int n;
        if (sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %n",
                   &lo, &hi, perms, &off, &devmaj, &devmin, &ino, &n) < 7) continue;
        char *path = line + n;
        while (*path == ' ') path++;
        size_t L = strlen(path);
        if (L && path[L - 1] == '\n') path[L - 1] = 0;
        strip_deleted(path);
        uintptr_t base = 0;
        if (*path) {
            size_t i;
            for (i = 0; i < n_files && strcmp(files[i].path, path); i++) {}
            if (i == n_files) {
                if (n_files == fcap) {
                    size_t nc = fcap ? 2 * fcap : 64;
                    void *p = realloc(files, nc * sizeof *files);
                    if (!p) { rv = -1; break; }
                    files = p; fcap = nc;
                }
                files[i].path = strdup(path);
                if (!files[i].path) { rv = -1; break; }
                files[i].base = (uintptr_t)(lo - off);
                n_files++;
            }
            base = files[i].base;
        }
        if (g_maps_n == cap) {
            size_t nc = cap ? 2 * cap : 256;
            void *p = realloc(g_maps, nc * sizeof *g_maps);
            if (!p) { rv = -1; break; }
            g_maps = p; cap = nc;
        }
        g_maps[g_maps_n].lo       = (uintptr_t)lo;
        g_maps[g_maps_n].hi       = (uintptr_t)hi;
        g_maps[g_maps_n].base     = base;
        g_maps[g_maps_n].readable = perms[0] == 'r';
        g_maps_n++;
    }
    fclose(f);
    for (size_t i = 0; i < n_files; i++) free(files[i].path);
    free(files);
    if (rv != 0) util_maps_free();
    return rv;
}

int util_range_in_module(uintptr_t module_base, uintptr_t addr, size_t len) {
    if (!g_maps) return 1;
    if (addr + len < addr) return 0;
    /* Last mapping with lo <= addr. */
    size_t lo = 0, hi = g_maps_n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_maps[mid].lo <= addr) lo = mid + 1;
        else                        hi = mid;
    }
    if (lo == 0) return 0;
    uintptr_t end = addr + len;
    for (size_t i = lo - 1; i < g_maps_n; i++) {
        const struct maps_ent *m = &g_maps[i];
        if (m->lo > addr || addr >= m->hi) return 0;
        if (!m->readable || m->base != module_base) return 0;
        if (end <= m->hi) return 1;
        addr = m->hi;   /* the site straddles into the next mapping */
    }
    return 0;
}

void util_maps_free(void) {
    free(g_maps);
    g_maps = NULL;
    g_maps_n = 0;
}

void util_self_range(uintptr_t *lo_out, uintptr_t *hi_out) {
    *lo_out = 0;
    *hi_out = 0;
    /* Use this function's own address to locate libcov.so in /proc/self/maps. */
    uintptr_t self_pc = (uintptr_t)&util_self_range;
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return;
    char line[4096];
    char target_path[4096] = {0};
    while (fgets(line, sizeof line, f)) {
        unsigned long lo, hi, off, ino;
        char perms[8];
        int devmaj, devmin;
        int n;
        if (sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %n",
                   &lo, &hi, perms, &off, &devmaj, &devmin, &ino, &n) < 7) continue;
        if (self_pc >= (uintptr_t)lo && self_pc < (uintptr_t)hi) {
            char *path = line + n;
            while (*path == ' ') path++;
            size_t L = strlen(path);
            if (L && path[L - 1] == '\n') path[L - 1] = 0;
            strncpy(target_path, path, sizeof target_path - 1);
            break;
        }
    }
    if (!*target_path) { fclose(f); return; }

    rewind(f);
    uintptr_t lo_all = (uintptr_t)-1, hi_all = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long lo, hi, off, ino;
        char perms[8];
        int devmaj, devmin;
        int n;
        if (sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %n",
                   &lo, &hi, perms, &off, &devmaj, &devmin, &ino, &n) < 7) continue;
        char *path = line + n;
        while (*path == ' ') path++;
        size_t L = strlen(path);
        if (L && path[L - 1] == '\n') path[L - 1] = 0;
        if (strcmp(path, target_path) != 0) continue;
        if ((uintptr_t)lo < lo_all) lo_all = (uintptr_t)lo;
        if ((uintptr_t)hi > hi_all) hi_all = (uintptr_t)hi;
    }
    fclose(f);
    if (hi_all > lo_all) { *lo_out = lo_all; *hi_out = hi_all; }
}

void libcov_spin_backoff(unsigned *spins) {
    if (++*spins >= LIBCOV_SPIN_YIELD_AFTER) {
        *spins = 0;
        sched_yield();
    } else {
#if defined(__x86_64__) || defined(__i386__)
        __builtin_ia32_pause();
#endif
        __asm__ volatile ("" ::: "memory");
    }
}
