/*
 * ring_dump.c -- passive snapshot-ring reader for autonomous targets.
 *
 * Usage: ring_dump <libcov.so> <patchlist> <boundary-list> <target> [args...]
 *
 * Unlike fuzz_driver (which feeds stdin one input at a time), this runs a
 * target that iterates on its own -- e.g. target_loop_mt's worker threads
 * -- and dumps every published generation as it appears:
 *
 *   gen=<n> tid=<tid> idx=<i>,<j>,...     (indices of non-zero buckets)
 *
 * followed by a final "ring_dump: ..." summary line. Generations lost to
 * a ring overrun are reported as "OVERRUN gen=<n>"; a slot that never
 * receives its stamp is reported as "MISSING gen=<n>".
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../src/boundary.h"

static void sleep_us(long us) {
    struct timespec ts = { us / 1000000, (us % 1000000) * 1000 };
    nanosleep(&ts, NULL);
}

static uint64_t mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Seqlock read of one slot; same protocol as fuzz_driver.c::read_slot.
 * 0 = copied, 1 = not ready / torn (retry), -1 = overrun. */
static int read_slot(void *base, uint64_t gen, uint8_t *out, uint64_t *tid) {
    struct libcov_shm_header *hdr = base;
    uint64_t now = __atomic_load_n(&hdr->gen_current, __ATOMIC_ACQUIRE);
    if (now < gen) return 1;
    if (now - gen >= hdr->ring_size) return -1;
    struct libcov_ring_slot_hdr *s = (struct libcov_ring_slot_hdr *)
        ((uint8_t *)base + hdr->ring_offset +
         (size_t)(gen % hdr->ring_size) * hdr->slot_stride);
    if (__atomic_load_n(&s->slot_gen, __ATOMIC_ACQUIRE) != gen) return 1;
    memcpy(out, s + 1, hdr->map_size);
    *tid = s->tid;
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (__atomic_load_n(&s->slot_gen, __ATOMIC_RELAXED) != gen) return 1;
    return 0;
}

static void dump(uint64_t gen, uint64_t tid, const uint8_t *map, size_t n) {
    printf("gen=%lu tid=%lu idx=", (unsigned long)gen, (unsigned long)tid);
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        if (!map[i]) continue;
        printf(first ? "%zu" : ",%zu", i);
        first = 0;
    }
    putchar('\n');
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <libcov.so> <patchlist> <boundary-list> "
                        "<target> [args...]\n", argv[0]);
        return 2;
    }
    char shm_path[128];
    snprintf(shm_path, sizeof shm_path, "/tmp/libcov_ringdump_%d", (int)getpid());
    unlink(shm_path);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        setenv("LD_PRELOAD", argv[1], 1);
        setenv("LIBCOV_PATCHLIST", argv[2], 1);
        setenv("LIBCOV_BOUNDARY_LIST", argv[3], 1);
        setenv("LIBCOV_SHM_PATH", shm_path, 1);
        setenv("LIBCOV_MODE", getenv("LIBCOV_MODE") ? getenv("LIBCOV_MODE")
                                                    : "leapfrog", 1);
        if (!getenv("LIBCOV_BOUNDARY_RING"))
            setenv("LIBCOV_BOUNDARY_RING", "16", 1);
        execv(argv[4], &argv[4]);
        perror("execv");
        _exit(127);
    }

    void *base = NULL;
    size_t size = 0;
    for (int tries = 0; tries < 500 && !base; tries++) {
        int fd = open(shm_path, O_RDONLY);
        struct stat st;
        if (fd >= 0 && fstat(fd, &st) == 0 &&
            (size_t)st.st_size >= sizeof(struct libcov_shm_header)) {
            void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
            if (m != MAP_FAILED) {
                struct libcov_shm_header *h = m;
                if (!memcmp(h->magic, LIBCOV_SHM_MAGIC, 4) &&
                    (__atomic_load_n(&h->flags, __ATOMIC_ACQUIRE) &
                     LIBCOV_SHM_FLAG_ACTIVE)) {
                    base = m; size = (size_t)st.st_size;
                } else {
                    munmap(m, (size_t)st.st_size);
                }
            }
        }
        if (fd >= 0) close(fd);
        if (!base) sleep_us(2000);
    }
    if (!base) {
        fprintf(stderr, "ring_dump: shm never became active at %s\n", shm_path);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 1;
    }

    struct libcov_shm_header *hdr = base;
    size_t map_size = hdr->map_size;
    uint8_t *buf = malloc(map_size);
    if (!buf) return 1;

    uint64_t next = 1, overruns = 0, missing = 0, published = 0;
    int exited = 0, status = 0;
    for (;;) {
        if (!exited && waitpid(pid, &status, WNOHANG) == pid) exited = 1;
        uint64_t now = __atomic_load_n(&hdr->gen_current, __ATOMIC_ACQUIRE);
        /* Spin (yielding) rather than sleep: with several workers the
         * target publishes in bursts, and a 16-slot ring leaves no room
         * for a reader that naps ~100us between polls. */
        if (next > now) {
            if (exited) break;
            sched_yield();
            continue;
        }
        uint64_t tid = 0;
        int rc = 1;
        /* A publisher may have taken gen `next` but not stamped its slot
         * yet; give it up to 200 ms. */
        uint64_t deadline = mono_ns() + 200000000ull;
        while ((rc = read_slot(base, next, buf, &tid)) == 1 && mono_ns() < deadline)
            sched_yield();
        if (rc == 0)       { dump(next, tid, buf, map_size); published++; }
        else if (rc == -1) { printf("OVERRUN gen=%lu\n", (unsigned long)next); overruns++; }
        else               { printf("MISSING gen=%lu\n", (unsigned long)next); missing++; }
        next++;
    }

    printf("ring_dump: target exited %d gens=%lu overruns=%lu missing=%lu "
           "gen_init=%lu\n",
           WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status),
           (unsigned long)published, (unsigned long)overruns,
           (unsigned long)missing,
           (unsigned long)__atomic_load_n(&hdr->gen_init, __ATOMIC_ACQUIRE));
    free(buf);
    munmap(base, size);
    unlink(shm_path);
    return 0;
}
