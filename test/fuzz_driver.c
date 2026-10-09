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
 * The ring read (seqlock, overrun/resume accounting) lives in
 * src/ring_reader.h, shared with ring_dump and tools/suzzer-relay.
 *
 * FUZZ_DRIVER_BURST=1 writes every input and waits for the target to
 * exit before reading anything -- a deterministic way to overrun a small
 * ring (tests use it to check the overrun accounting).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdint.h>
#include <signal.h>

#include "../src/ring_reader.h"

/* Per-snapshot callback context: the cumulative map and the current input's
 * label, updated before each rr_drain_to call. */
struct drv_ctx {
    uint8_t    *cumulative;
    const char *label;
};

static void drv_slot(uint64_t gen, const uint8_t *bm, size_t map_size,
                     uint64_t tid, uint64_t ns, uint64_t flags, void *user) {
    struct drv_ctx *c = user;
    unsigned hit   = rr_count_set(bm, map_size);
    unsigned newly = rr_count_new(bm, c->cumulative, map_size);
    unsigned total = rr_count_set(c->cumulative, map_size);
    printf("gen=%-3lu (%s) kind=%s tid=%lu ns=%lu hit=%u new=%u total=%u\n",
           (unsigned long)gen, c->label, rr_slot_kind(flags),
           (unsigned long)tid, (unsigned long)ns, hit, newly, total);
    fflush(stdout);
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
        /* Required env set unconditionally; optional env (LIBCOV_MODE, ...)
         * only when missing so the caller's shell can override it. */
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

    /* Wait for libcov to create the region and activate boundaries. */
    void *shm_base = NULL;
    size_t shm_size = 0, map_size = 0;
    if (rr_attach(shm_path, 1 /*require_active*/, 2000,
                  &shm_base, &shm_size, &map_size) != 0) {
        fprintf(stderr, "driver: shm never appeared/activated at %s "
                "(LIBCOV_BOUNDARY_LIST=%s)\n", shm_path, blist);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 1;
    }
    volatile struct libcov_shm_header *hdr = shm_base;
    {
        char sch[64];
        printf("driver: scheme %s\n",
               rr_scheme(__atomic_load_n((uint32_t *)&hdr->flags, __ATOMIC_ACQUIRE),
                         sch, sizeof sch));
    }

    uint8_t *scratch    = malloc(map_size);
    uint8_t *cumulative = calloc(1, map_size);
    if (!scratch || !cumulative) {
        fprintf(stderr, "driver: OOM allocating %zu-byte bitmaps\n", map_size);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 1;
    }

    struct rr_stats stats = {0};
    struct drv_ctx ctx = { cumulative, "init" };
    uint64_t consumed_gen = 0;
    char line[1024];
    unsigned input_idx = 0;
    const char *burst_env = getenv("FUZZ_DRIVER_BURST");
    int burst = burst_env && !strcmp(burst_env, "1");
    int st = 0, reaped = 0;
    if (burst) {
        while (fgets(line, sizeof line, stdin)) {
            if (write(pipefd[1], line, strlen(line)) < 0) {
                perror("write to target");
                break;
            }
        }
        close(pipefd[1]);
        waitpid(pid, &st, 0);
        reaped = 1;
        uint64_t last = __atomic_load_n((uint64_t *)&hdr->gen_current,
                                        __ATOMIC_ACQUIRE);
        ctx.label = "burst";
        rr_drain_to(shm_base, &consumed_gen, last, scratch, map_size, &stats,
                    drv_slot, &ctx);
    }
    while (!burst && fgets(line, sizeof line, stdin)) {
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

        uint64_t new_gen = rr_wait_gen_advance(shm_base, prev_gen, 2000);
        char label[64];
        snprintf(label, sizeof label, "input#%u='%s'", input_idx++, line);
        ctx.label = label;
        rr_drain_to(shm_base, &consumed_gen, new_gen, scratch, map_size, &stats,
                    drv_slot, &ctx);
    }

    if (!burst) {
        /* Close pipe to signal EOF; the target's post-loop iter_begin then
         * flushes the last input's coverage. */
        close(pipefd[1]);
        uint64_t final_gen = rr_wait_gen_advance(shm_base, consumed_gen, 2000);
        ctx.label = "EOF-flush";
        rr_drain_to(shm_base, &consumed_gen, final_gen, scratch, map_size,
                    &stats, drv_slot, &ctx);
    }

    if (!reaped) waitpid(pid, &st, 0);

    uint32_t dropped = __atomic_load_n((uint32_t *)&hdr->publish_dropped,
                                       __ATOMIC_ACQUIRE);
    printf("driver: target exited %d  total_edges=%u  consumed_gen=%lu  gen_init=%lu"
           "  overruns=%u lost_gens=%lu read_failures=%u publish_dropped=%u"
           "  init=%u iter=%u gap=%u\n",
           WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st),
           rr_count_set(cumulative, map_size),
           (unsigned long)consumed_gen,
           (unsigned long)__atomic_load_n((uint64_t *)&hdr->gen_init,
                                          __ATOMIC_ACQUIRE),
           stats.overruns, (unsigned long)stats.lost_gens, stats.read_failures,
           dropped, stats.kind_init, stats.kind_iter, stats.kind_gap);

    free(scratch);
    free(cumulative);
    munmap(shm_base, shm_size);
    unlink(shm_path);
    /* Lost coverage is a failed run, not a warning. */
    return (stats.overruns || stats.read_failures) ? 3 : 0;
}
