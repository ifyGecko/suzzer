/* Baremetal test driver: init libcov, measure coverage for several inputs
 * (one input twice, to prove determinism), store fingerprints in globals the
 * gdbstub reads. No UART, no OS, no other project. */
#include <stdint.h>
extern int  libcov_init(void);
extern void libcov_bm_reset(void);
extern unsigned char *libcov_bitmap;
extern uint32_t libcov_map_size;
extern int  app_run(int);

struct runres { int32_t input; uint32_t edges; uint32_t hash; };
volatile struct runres g_runs[8];
volatile int32_t g_nruns = 0;
volatile int32_t g_init_rc = -999;
__attribute__((noinline)) void test_done(void) { __asm__ volatile(""); }

static void measure(int input) {
    libcov_bm_reset();
    app_run(input);
    uint32_t edges = 0, h = 2166136261u;         /* FNV-1a over hit buckets */
    for (uint32_t i = 0; i < libcov_map_size; i++) {
        unsigned b = libcov_bitmap[i];
        if (b) { edges++; h = (h ^ i) * 16777619u; h = (h ^ b) * 16777619u; }
    }
    int k = g_nruns;
    g_runs[k].input = input; g_runs[k].edges = edges; g_runs[k].hash = h;
    g_nruns = k + 1;
}
int test_main(void) {
    g_init_rc = libcov_init();
    measure(3); measure(3); measure(8); measure(15); measure(0);
    test_done();
    for (;;) { }
}
