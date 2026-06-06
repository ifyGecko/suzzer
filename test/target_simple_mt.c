/*
 * target_simple_mt.c -- pthread stress target for libcov MT validation.
 *
 * Reuses the noinline classify/loop_sum/cmdline helpers from target_simple
 * but runs them concurrently across N worker threads, each iterating their
 * own input the requested number of times. Designed to maximize the
 * probability of two threads hitting the same patched site simultaneously.
 *
 * Usage:
 *   target_simple_mt <threads> <iters> <input1> [input2 ...]
 *
 * If the input list is shorter than <threads>, threads wrap around.
 *
 * Build with -no-pie -O0 so addresses match what target_simple uses.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

__attribute__((noinline)) static int classify(int x) {
    if (x < 0)        { return -1; }
    if (x == 0)       { return  0; }
    if (x < 10)       { return  1; }
    if (x < 100)      { return  2; }
    return 3;
}

__attribute__((noinline)) static int loop_sum(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (i % 2 == 0) { s += i; }
        else            { s -= i; }
    }
    return s;
}

__attribute__((noinline)) static int cmdline(const char *s) {
    int score = 0;
    if (!s)              { return -1; }
    if (s[0] == 'a')     { score += 1; }
    else if (s[0] == 'b'){ score += 2; }
    else                 { score += 3; }
    if (strlen(s) > 4)   { score += 10; }
    else                 { score += 20; }
    return score;
}

struct worker_arg {
    int          tid;
    int          iters;
    const char  *input;
    unsigned long checksum;
};

static void *worker(void *p) {
    struct worker_arg *a = p;
    unsigned long acc = 0;
    int x = atoi(a->input);
    for (int i = 0; i < a->iters; i++) {
        int c = classify(x + (i & 0xF));
        int s = loop_sum(c < 0 ? 1 : c + 1 + (i & 0x3));
        int k = cmdline(a->input);
        acc += (unsigned long)((c * 31 + s) * 17 + k) ^ (unsigned long)i;
    }
    a->checksum = acc;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <threads> <iters> <input1> [input2 ...]\n",
                argv[0]);
        return 2;
    }
    int nthreads = atoi(argv[1]);
    int iters    = atoi(argv[2]);
    if (nthreads < 1 || nthreads > 64) { fprintf(stderr, "bad threads\n"); return 2; }
    if (iters    < 1)                  { fprintf(stderr, "bad iters\n");   return 2; }

    int ninputs = argc - 3;
    pthread_t *tids = calloc(nthreads, sizeof *tids);
    struct worker_arg *args = calloc(nthreads, sizeof *args);
    if (!tids || !args) { perror("calloc"); return 1; }

    for (int t = 0; t < nthreads; t++) {
        args[t].tid    = t;
        args[t].iters  = iters;
        args[t].input  = argv[3 + (t % ninputs)];
        if (pthread_create(&tids[t], NULL, worker, &args[t]) != 0) {
            perror("pthread_create"); return 1;
        }
    }
    unsigned long total = 0;
    for (int t = 0; t < nthreads; t++) {
        pthread_join(tids[t], NULL);
        total += args[t].checksum;
        printf("t%d input=%s csum=%lu\n", t, args[t].input, args[t].checksum);
    }
    printf("TOTAL=%lu threads=%d iters=%d\n", total, nthreads, iters);
    free(tids);
    free(args);
    return 0;
}
