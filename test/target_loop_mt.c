/*
 * target_loop_mt.c -- multi-worker boundary target (MT regression).
 *
 * Usage: target_loop_mt <workers> <iters>
 *   workers: a string over {a, b}; one worker thread per character.
 *            "a" / "b" run a single worker (solo signature runs); "ab"
 *            runs both concurrently.
 *   iters:   iterations per worker.
 *
 * Every iteration starts with iter_begin() (the boundary marker) and then
 * runs that worker's own path: worker 'a' only ever runs path_a_*, worker
 * 'b' only path_b_*. A per-iteration snapshot published by an 'a' worker
 * must therefore never contain coverage that only path_b produces. Before
 * libcov gave each MT worker its own live bitmap, one shared live bitmap
 * mixed both workers into every snapshot.
 *
 * Built with -no-pie -O0 like the other test targets.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Same shape as target_loop.c's marker: the impossible branch gives the
 * first basic block a patchable multi-byte terminator. */
__attribute__((noinline, used)) void iter_begin(unsigned iter) {
    if (iter == 0xffffffffu) {
        __builtin_trap();
    }
    __asm__ __volatile__("" : : "r"(iter) : "memory");
}

static volatile int g_sink;

__attribute__((noinline)) static void path_a_leaf(int i) {
    if (i & 1) g_sink += 3;
    else       g_sink -= 3;
}

__attribute__((noinline)) static void path_a(int i) {
    for (int k = 0; k < 4; k++) {
        if (k == 2) g_sink ^= i;
        path_a_leaf(i + k);
    }
}

__attribute__((noinline)) static void path_b_leaf(int i) {
    if (i % 3 == 0) g_sink *= 5;
    else            g_sink += 7;
}

__attribute__((noinline)) static void path_b(int i) {
    for (int k = 0; k < 6; k++) {
        if (k > 3) g_sink |= i;
        path_b_leaf(i + k);
    }
}

struct worker_arg {
    char     kind;
    unsigned iters;
};

static void pause_us(long us) {
    struct timespec ts = { 0, us * 1000 };
    nanosleep(&ts, NULL);
}

static void *worker(void *p) {
    const struct worker_arg *w = p;
    for (unsigned i = 0; i < w->iters; i++) {
        iter_begin(i);
        if (w->kind == 'a') path_a((int)i);
        else                path_b((int)i);
        /* Keep workers overlapping while giving the ring reader time to
         * drain; the ring is only a handful of slots deep. */
        pause_us(200);
    }
    /* Publish the last iteration (begin-only markers publish the
     * previous one). */
    iter_begin(w->iters);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <workers:[ab]+> <iters>\n", argv[0]);
        return 2;
    }
    size_t n = strlen(argv[1]);
    unsigned iters = (unsigned)atoi(argv[2]);
    pthread_t *th = calloc(n, sizeof *th);
    struct worker_arg *args = calloc(n, sizeof *args);
    if (!th || !args) return 1;
    for (size_t i = 0; i < n; i++) {
        args[i].kind  = argv[1][i];
        args[i].iters = iters;
        if (pthread_create(&th[i], NULL, worker, &args[i]) != 0) return 1;
    }
    for (size_t i = 0; i < n; i++) pthread_join(th[i], NULL);
    return 0;
}
