#define _GNU_SOURCE
#include "util.h"
#include "tunables.h"   /* LIBCOV_LOG_BUFFER_SIZE */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int log_fd = 2;  /* stderr by default */

void libcov_log_init(void) {
    const char *p = getenv("LIBCOV_LOG");
    if (!p || !*p) return;
    int fd = open(p, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) log_fd = fd;
}

void libcov_logf(const char *fmt, ...) {
    char buf[LIBCOV_LOG_BUFFER_SIZE];
    int n = snprintf(buf, sizeof buf, "libcov: ");
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(buf + n, sizeof buf - n, fmt, ap);
    va_end(ap);
    if (n < (int)sizeof buf - 1) { buf[n++] = '\n'; }
    (void)write(log_fd, buf, (size_t)n);
}

static const char *basename_c(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

uintptr_t util_module_base(const char *modname) {
    char exe[4096];
    if (!modname || !*modname) {
        ssize_t r = readlink("/proc/self/exe", exe, sizeof exe - 1);
        if (r <= 0) return 0;
        exe[r] = 0;
        modname = basename_c(exe);
    } else {
        modname = basename_c(modname);
    }

    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[4096];
    uintptr_t base = 0;
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
        const char *b = basename_c(path);
        if (strcmp(b, modname) != 0) continue;
        /* First mapping for this module is the base. */
        base = lo - off;
        break;
    }
    fclose(f);
    return base;
}

void util_self_range(uintptr_t *lo_out, uintptr_t *hi_out) {
    *lo_out = 0;
    *hi_out = 0;
    /* Use this function's own address to locate libcov.so in /proc/self/maps. */
    uintptr_t self_pc = (uintptr_t)&util_self_range;
    FILE *f = fopen("/proc/self/maps", "r");
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
