/*
 * fuzz_driver.c -- boundary-aware driver. Spawns the target ONCE, pipes
 * inputs to its stdin, and reads per-iteration coverage from the libcov
 * snapshot ring.
 *
 * Coverage scoping is libcov's job now -- the driver never clears the
 * bitmap. Per-iteration scoping comes from the boundary mechanism: the
 * target calls a marker function (iter_begin or equivalent) at each
 * iteration; the trap fires libcov's boundary handler, which snapshots
 * the live bitmap into ring[gen % ring_size] and clears the live bitmap.
 *
 * Desync detection: each slot carries its own gen stamp; we read it
 * before and after the bitmap memcpy with acquire ordering. Mismatches
 * mean the writer overwrote our slot mid-read; we retry. If the writer
 * has advanced past us by >= ring_size iterations we've lost data and
 * report it loudly.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>

#include "../src/boundary.h"
#include "../src/sink.h"

static int open_shm(const char *path, void **base_out, size_t *size_out) {
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;  /* caller polls; not-yet-created is common */
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    if ((size_t)st.st_size < sizeof(struct libcov_shm_header)) {
        close(fd); return -1;
    }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return -1;
    *base_out = m;
    *size_out = (size_t)st.st_size;
    return 0;
}

static unsigned count_set(const uint8_t *map, size_t map_size) {
    unsigned c = 0;
    for (size_t i = 0; i < map_size; i++) if (map[i]) c++;
    return c;
}

static unsigned count_new(const uint8_t *cur, uint8_t *cumulative, size_t map_size) {
    unsigned newly = 0;
    for (size_t i = 0; i < map_size; i++) {
        if (cur[i] && !cumulative[i]) { newly++; cumulative[i] = cur[i]; }
    }
    return newly;
}

/* Read a single slot with the seqlock pattern. Returns 0 on success
 * (target_gen's snapshot copied into out), 1 on torn read (retry),
 * -1 on overrun (writer advanced past our window), -2 on bad shm. */
static int read_slot(void *shm_base, uint64_t target_gen, uint8_t *out,
                     uint64_t *tid_out, uint64_t *ns_out) {
    volatile struct libcov_shm_header *hdr = shm_base;
    uint64_t gen_now = __atomic_load_n((uint64_t *)&hdr->gen_current,
                                       __ATOMIC_ACQUIRE);
    if (gen_now < target_gen) return 1;  /* not yet published */
    if (gen_now - target_gen >= (uint64_t)hdr->ring_size) return -1;

    size_t idx = (size_t)(target_gen % hdr->ring_size);
    struct libcov_ring_slot_hdr *s = (struct libcov_ring_slot_hdr *)
        ((uint8_t *)shm_base + hdr->ring_offset + idx * hdr->slot_stride);

    uint64_t pre = __atomic_load_n(&s->slot_gen, __ATOMIC_ACQUIRE);
    if (pre != target_gen) return 1;  /* writer hasn't stamped this slot yet */

    memcpy(out, (uint8_t *)(s + 1), hdr->map_size);
    uint64_t tid = s->tid;
    uint64_t ns  = s->ns;

    uint64_t post = __atomic_load_n(&s->slot_gen, __ATOMIC_ACQUIRE);
    if (post != target_gen) return 1;  /* writer overwrote our slot mid-read */

    if (tid_out) *tid_out = tid;
    if (ns_out)  *ns_out  = ns;
    return 0;
}

static uint64_t wait_gen_advance(void *shm_base, uint64_t prev_gen,
                                 unsigned timeout_ms) {
    volatile struct libcov_shm_header *hdr = shm_base;
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        uint64_t g = __atomic_load_n((uint64_t *)&hdr->gen_current,
                                     __ATOMIC_ACQUIRE);
        if (g > prev_gen) return g;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
                          (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed_ms >= (long)timeout_ms) return g;
        struct timespec sl = {0, 100000};  /* 100 us */
        nanosleep(&sl, NULL);
    }
}

static void drain_to(void *shm_base, uint64_t *prev_gen, uint64_t target_gen,
                     uint8_t *scratch, uint8_t *cumulative, size_t map_size,
                     const char *label) {
    while (*prev_gen < target_gen) {
        uint64_t g = *prev_gen + 1;
        uint64_t tid = 0, ns = 0;
        int attempts = 0;
        int rc;
        do {
            rc = read_slot(shm_base, g, scratch, &tid, &ns);
            if (rc == 1) {
                struct timespec sl = {0, 50000};
                nanosleep(&sl, NULL);
            }
        } while (rc == 1 && ++attempts < 100);

        if (rc == -1) {
            fprintf(stderr,
                    "OVERRUN: writer advanced past gen=%lu, data lost; skipping ahead\n",
                    (unsigned long)g);
            volatile struct libcov_shm_header *hdr = shm_base;
            *prev_gen = __atomic_load_n((uint64_t *)&hdr->gen_current,
                                        __ATOMIC_ACQUIRE);
            return;
        }
        if (rc != 0) {
            fprintf(stderr, "read_slot gen=%lu failed (rc=%d) after %d attempts\n",
                    (unsigned long)g, rc, attempts);
            return;
        }

        unsigned hit = count_set(scratch, map_size);
        unsigned newly = count_new(scratch, cumulative, map_size);
        unsigned total = count_set(cumulative, map_size);
        printf("gen=%-3lu (%s) tid=%lu ns=%lu hit=%u new=%u total=%u\n",
               (unsigned long)g, label, (unsigned long)tid, (unsigned long)ns,
               hit, newly, total);
        fflush(stdout);
        *prev_gen = g;
    }
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
                "usage: %s <libcov.so> <patchlist> <boundary-list> <target> [target args...]\n"
                "  Inputs read from stdin, one per line, piped to the target's stdin.\n"
                "  Per-iteration coverage is published via libcov's boundary mechanism\n"
                "  and read from the shm ring.\n",
                argv[0]);
        return 2;
    }
    const char *lib    = argv[1];
    const char *plist  = argv[2];
    const char *blist  = argv[3];
    const char *target = argv[4];

    char shm_path[128];
    snprintf(shm_path, sizeof shm_path, "/tmp/libcov_driver_%d", (int)getpid());
    unlink(shm_path);

    int pipefd[2];
    if (pipe(pipefd) < 0) { perror("pipe"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        /* Required env: LD_PRELOAD, LIBCOV_PATCHLIST, LIBCOV_BOUNDARY_LIST,
         * LIBCOV_SHM_PATH. We set these unconditionally so the driver
         * works even when none of them are in the parent env.
         *
         * Optional env (LIBCOV_MODE, LIBCOV_BOUNDARY_REARM, ...): set only
         * when missing from the parent env so the caller can override
         * via the calling shell. */
        char envlib[512], envmap[256], envmod[512], envblist[512];
        snprintf(envlib,   sizeof envlib,   "LD_PRELOAD=%s", lib);
        snprintf(envmap,   sizeof envmap,   "LIBCOV_SHM_PATH=%s", shm_path);
        snprintf(envmod,   sizeof envmod,   "LIBCOV_PATCHLIST=%s", plist);
        snprintf(envblist, sizeof envblist, "LIBCOV_BOUNDARY_LIST=%s", blist);
        putenv(envlib);
        putenv(envmap);
        putenv(envmod);
        putenv(envblist);
        if (!getenv("LIBCOV_MODE")) putenv((char *)"LIBCOV_MODE=leapfrog");

        dup2(pipefd[0], 0);
        close(pipefd[0]);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); close(devnull); }

        int nargs = argc - 4 + 1;  /* target + passed-args + NULL */
        char **ar = calloc(nargs + 1, sizeof(char *));
        int k = 0;
        ar[k++] = (char *)target;
        for (int i = 5; i < argc; i++) ar[k++] = argv[i];
        ar[k++] = NULL;
        execv(target, ar);
        perror("execv");
        _exit(127);
    }
    close(pipefd[0]);

    /* The target's libcov constructor creates the shm file. Wait for it
     * to appear and have the expected header. */
    void *shm_base = NULL;
    size_t shm_size = 0;
    for (int tries = 0; tries < 100; tries++) {
        if (open_shm(shm_path, &shm_base, &shm_size) == 0) {
            volatile struct libcov_shm_header *hdr = shm_base;
            if (memcmp((const void *)hdr->magic, LIBCOV_SHM_MAGIC, 4) == 0) break;
            munmap(shm_base, shm_size);
            shm_base = NULL;
        }
        struct timespec sl = {0, 10000000};  /* 10 ms */
        nanosleep(&sl, NULL);
    }
    if (!shm_base) {
        fprintf(stderr, "driver: shm never appeared at %s\n", shm_path);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 1;
    }

    volatile struct libcov_shm_header *hdr = shm_base;
    int waited_ms = 0;
    while (!(__atomic_load_n((uint32_t *)&hdr->flags, __ATOMIC_ACQUIRE)
             & LIBCOV_SHM_FLAG_ACTIVE)) {
        if (waited_ms >= 500) {
            fprintf(stderr,
                    "driver: boundaries never activated (LIBCOV_BOUNDARY_LIST=%s)\n",
                    blist);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            return 1;
        }
        struct timespec sl = {0, 10000000};
        nanosleep(&sl, NULL);
        waited_ms += 10;
    }

    /* Bitmap size is runtime (site-id model auto-sizes from the patch
     * count). Read it from the shm header and allocate accordingly rather
     * than assuming the compile-time LIBCOV_MAP_SIZE. */
    size_t map_size = __atomic_load_n((uint32_t *)&hdr->map_size, __ATOMIC_ACQUIRE);
    if (map_size == 0) {
        fprintf(stderr, "driver: shm header reports map_size=0\n");
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 1;
    }
    uint8_t *scratch    = malloc(map_size);
    uint8_t *cumulative = calloc(1, map_size);
    if (!scratch || !cumulative) {
        fprintf(stderr, "driver: OOM allocating %zu-byte bitmaps\n", map_size);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 1;
    }

    uint64_t consumed_gen = 0;
    char line[1024];
    unsigned input_idx = 0;
    while (fgets(line, sizeof line, stdin)) {
        size_t L = strlen(line);
        if (L && line[L - 1] == '\n') line[L - 1] = 0;

        uint64_t prev_gen = __atomic_load_n((uint64_t *)&hdr->gen_current,
                                            __ATOMIC_ACQUIRE);

        size_t to_write = strlen(line);
        if (write(pipefd[1], line, to_write) < 0 ||
            write(pipefd[1], "\n", 1) < 0) {
            perror("write to target");
            break;
        }

        uint64_t new_gen = wait_gen_advance(shm_base, prev_gen, 2000);
        char label[64];
        snprintf(label, sizeof label, "input#%u='%s'", input_idx++, line);
        drain_to(shm_base, &consumed_gen, new_gen, scratch, cumulative, map_size, label);
    }

    /* Close pipe to signal EOF; the target's post-loop iter_begin then
     * flushes the last input's coverage. */
    close(pipefd[1]);

    uint64_t final_gen = wait_gen_advance(shm_base, consumed_gen, 2000);
    drain_to(shm_base, &consumed_gen, final_gen, scratch, cumulative, map_size, "EOF-flush");

    int st = 0;
    waitpid(pid, &st, 0);

    printf("driver: target exited %d  total_edges=%u  consumed_gen=%lu  gen_init=%lu\n",
           WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st),
           count_set(cumulative, map_size),
           (unsigned long)consumed_gen,
           (unsigned long)__atomic_load_n((uint64_t *)&hdr->gen_init,
                                          __ATOMIC_ACQUIRE));

    free(scratch);
    free(cumulative);
    munmap(shm_base, shm_size);
    unlink(shm_path);
    return 0;
}
