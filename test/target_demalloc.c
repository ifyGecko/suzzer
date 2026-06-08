/*
 * target_demalloc -- exerciser for libdemalloc's detection paths.
 *
 * Each mode triggers exactly one bug class. The validation script
 * sets LD_PRELOAD=libdemalloc.so and asserts that the bug-triggering
 * modes terminate via signal (SIGSEGV or SIGABRT depending on the
 * detection path) while the clean modes exit 0.
 *
 * Modes:
 *
 *   clean         -- malloc + use + free, no bugs
 *   alloc_free    -- repeated alloc/free pattern to drive eviction
 *   overflow_w    -- write 1 byte past the buffer (guard page -> SEGV)
 *   underflow_w   -- write -1 byte before the buffer (canary -> ABORT)
 *   double_free   -- free twice in a row (canary read on PROT_NONE -> SEGV)
 *   uaf           -- read after free (PROT_NONE -> SEGV)
 *   uar           -- read original buffer after realloc (PROT_NONE -> SEGV)
 *   calloc_ovf    -- calloc(SIZE_MAX/2, 4) overflow (-> ABORT)
 *   uaf_evict     -- alloc/free more than QUARANTINE_SLOTS times then
 *                    free the cycle's first ptr again (-> munmap'd
 *                    so SIGSEGV is best-effort, may exit clean).
 *                    Used only for "did we not OOM" checks, not crash
 *                    assertion.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This file deliberately commits the heap bugs libdemalloc is meant to
 * catch. Suppress the corresponding GCC diagnostics so the validation
 * build is warning-free.                                            */
#if defined(__GNUC__) && !defined(__clang__)
  #pragma GCC diagnostic ignored "-Wuse-after-free"
#endif

#ifndef LIBDEM_QUARANTINE_SLOTS_TEST
  #define LIBDEM_QUARANTINE_SLOTS_TEST 1024
#endif

static int do_clean(void) {
  char *p = malloc(64);
  if (!p) return 1;
  memset(p, 'A', 64);
  free(p);
  return 0;
}

static int do_alloc_free(void) {
  /* Many alloc/free cycles -- proves we never OOM with bounded
   * quarantine even at high churn. Size mixed deliberately.       */
  for (int i = 0; i < 16384; i++) {
    size_t n = 16 + (i % 8) * 64;
    char  *p = malloc(n);
    if (!p) return 1;
    p[0] = (char)i;
    p[n - 1] = (char)i;
    free(p);
  }
  return 0;
}

static int do_overflow_w(void) {
  char *p = malloc(8);
  if (!p) return 1;
  /* Right-aligned against trailing guard page: writing the byte at
   * the page boundary after the buffer must segfault.             */
  p[4096] = 'X';
  /* Defeat dead-store elimination: print something dependent on the
   * write so the compiler can't optimize it out.                  */
  printf("%c\n", p[4096]);
  return 0;
}

static int do_underflow_w(void) {
  char *p = malloc(8);
  if (!p) return 1;
  /* Clobber the canary -- header is at p[-8..p-1].                */
  p[-1] = 0;
  p[-2] = 0;
  p[-3] = 0;
  p[-4] = 0;
  free(p);
  return 0;
}

static int do_double_free(void) {
  char *p = malloc(8);
  if (!p) return 1;
  free(p);
  free(p);
  return 0;
}

static int do_uaf(void) {
  char *p = malloc(8);
  if (!p) return 1;
  p[0] = 'A';
  free(p);
  /* Use-after-free read: PROT_NONE in quarantine -> SIGSEGV.      */
  volatile char c = p[0];
  printf("%c\n", c);
  return 0;
}

static int do_uar(void) {
  char *p = malloc(8);
  if (!p) return 1;
  p[0] = 'A';
  char *q = realloc(p, 16);
  if (!q) return 1;
  /* libdemalloc always returns a NEW buffer from realloc. Reading
   * the old pointer must hit the quarantined PROT_NONE region.   */
  volatile char c = p[0];
  printf("%c\n", c);
  free(q);
  return 0;
}

static int do_calloc_ovf(void) {
  size_t huge = ((size_t)-1) / 2;
  void  *p = calloc(huge, 4);
  /* With LIBDEM_CHECK_CALLOC_OVERFLOW=1 (default), this should not
   * return -- the process aborts. With =0 it returns NULL.       */
  if (!p) {
    fprintf(stderr, "calloc returned NULL\n");
    return 2;
  }
  return 0;
}

static int do_uaf_evict(void) {
  /* Churn enough allocations that the very first free has been
   * evicted from quarantine. We just need this to not OOM and
   * exit 0 -- the validation script only checks survival.        */
  int N = LIBDEM_QUARANTINE_SLOTS_TEST * 4;
  for (int i = 0; i < N; i++) {
    char *p = malloc(128);
    if (!p) return 1;
    p[0] = (char)i;
    free(p);
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <mode>\n", argv[0]);
    return 64;
  }
  const char *m = argv[1];
  if (!strcmp(m, "clean"))        return do_clean();
  if (!strcmp(m, "alloc_free"))   return do_alloc_free();
  if (!strcmp(m, "overflow_w"))   return do_overflow_w();
  if (!strcmp(m, "underflow_w")) return do_underflow_w();
  if (!strcmp(m, "double_free"))  return do_double_free();
  if (!strcmp(m, "uaf"))          return do_uaf();
  if (!strcmp(m, "uar"))          return do_uar();
  if (!strcmp(m, "calloc_ovf"))   return do_calloc_ovf();
  if (!strcmp(m, "uaf_evict"))    return do_uaf_evict();
  fprintf(stderr, "unknown mode: %s\n", m);
  return 64;
}
