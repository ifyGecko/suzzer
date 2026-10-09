/*
 * libdemalloc -- bounded-quarantine "poor man's ASan" for suzzer
 * =============================================================
 *
 * An LD_PRELOAD allocator that:
 *
 *   - places every allocation against a trailing PROT_NONE guard page
 *     so overflows segfault instantly,
 *   - stores a canary + length in the 8 bytes below the buffer so
 *     write-underflows are caught at free()/realloc(),
 *   - on free() marks the entire region PROT_NONE and pushes it onto a
 *     fixed-size FIFO quarantine: double-free and use-after-free fire
 *     SIGSEGV as long as the freed region is still in quarantine,
 *   - when the quarantine is full, munmaps the oldest region so the
 *     library never grows unbounded -- safe for long-running embedded
 *     daemons,
 *   - is thread-safe via a single hand-rolled spinlock around the
 *     quarantine ring (no pthread/libatomic linkage).
 *
 * Derived from AFL++ libdislocator (Michal Zalewski, 2016; AFLplusplus
 * Project, 2019-2024 -- Apache-2.0). Re-licensed Apache-2.0.
 *
 * Configuration is compile-time only. Every knob below is #ifndef-guarded
 * so a -D flag at build time wins. The build system (tools/Makefile)
 * honours EXTRA_CFLAGS; example:
 *
 *     make tools EXTRA_CFLAGS='-DLIBDEM_QUARANTINE_SLOTS=128 \
 *                              -DLIBDEM_ALIGN_ALLOCATIONS=1'
 *
 * Alignment: by default on x86 (LIBDEM_ALIGN_ALLOCATIONS=0) malloc()
 * places the buffer flush against the guard page, so a malloc(n) pointer
 * is only as aligned as n is (malloc(13) returns an odd-ish address,
 * NOT 16-byte / max_align_t aligned). That is deliberate: a one-byte
 * overflow then faults immediately. x86 tolerates the misalignment for
 * ordinary loads/stores, but SSE code using aligned moves (movaps etc.)
 * on malloc'd memory will fault. Strict-alignment targets (ARM, MIPS,
 * PowerPC, SPARC, ...) and SSE-heavy x86 targets should build with
 * -DLIBDEM_ALIGN_ALLOCATIONS=1, which is the default on every non-x86
 * architecture. posix_memalign / memalign / aligned_alloc / valloc /
 * pvalloc always honour the requested alignment, including alignments
 * larger than the page size.
 *
 * Sizes: the per-allocation length is stored as a uint32_t, so requests
 * above UINT32_MAX bytes fail with NULL / ENOMEM.
 *
 * Catches:
 *   - heap overflow reads/writes  (trailing guard page)
 *   - heap underflow writes       (header canary check on free/realloc)
 *   - double free                 (PROT_NONE quarantined page)
 *   - use-after-free within the quarantine horizon
 *   - use-after-realloc           (free path quarantines the old buffer)
 *   - some uninitialized reads    (malloc() clobbers with LIBDEM_CLOBBER_BYTE)
 *   - calloc() size overflow
 *
 * Doesn't catch:
 *   - stack bugs (use -fstack-protector-strong on the target)
 *   - UAF beyond the quarantine horizon (increase LIBDEM_QUARANTINE_SLOTS)
 *   - intra-allocation overflows
 *
 * VA / RSS sizing: at the default N=128 slots and ~1-page allocations,
 * quarantine cost is ~1 MB virtual (2 pages per slot: data + guard),
 * and with LIBDEM_RELEASE_RSS_ON_FREE=1 (default) almost none of it
 * stays resident. Raising LIBDEM_QUARANTINE_SLOTS scales this linearly
 * (e.g. 1024 slots ~ 8 MB virtual). On 32-bit
 * embedded targets, reduce LIBDEM_QUARANTINE_SLOTS at compile time.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(LIBDEM_NAME_PAGES) && LIBDEM_NAME_PAGES
  #include <sys/prctl.h>
  #ifndef PR_SET_VMA
    #define PR_SET_VMA           0x53564d41
    #define PR_SET_VMA_ANON_NAME 0
  #endif
#endif

#if defined(LIBDEM_USE_GETRANDOM) && LIBDEM_USE_GETRANDOM
  #include <sys/syscall.h>
#endif

#ifndef MAP_ANONYMOUS
  #define MAP_ANONYMOUS MAP_ANON
#endif

/* ---------------------------------------------------------------- */
/* Compile-time knobs.                                              */
/* ---------------------------------------------------------------- */

/* Quarantine FIFO depth. Bigger -> catches longer-lived UAFs at the
 * cost of more held virtual / physical memory.                     */
#ifndef LIBDEM_QUARANTINE_SLOTS
  #define LIBDEM_QUARANTINE_SLOTS 128
#endif

/* Header canary stored in the 4 bytes just below the returned pointer.
 * Detects underflow writes that hit the metadata area.             */
#ifndef LIBDEM_ALLOC_CANARY
  #define LIBDEM_ALLOC_CANARY 0xAACCAACCu
#endif

/* Tail-pad byte (only used when LIBDEM_ALIGN_ALLOCATIONS=1).       */
#ifndef LIBDEM_TAIL_CANARY
  #define LIBDEM_TAIL_CANARY 0xAC
#endif

/* malloc() clobbers fresh buffers with this byte so accidental reads
 * of uninitialized memory tend to misbehave loudly.                */
#ifndef LIBDEM_CLOBBER_BYTE
  #define LIBDEM_CLOBBER_BYTE 0xCC
#endif

/* When 1, round each allocation up to _Alignof(max_align_t) and stamp
 * the trailing slack with LIBDEM_TAIL_CANARY for end-of-buffer write
 * detection. Trades a little overflow-detection precision for strict
 * C-standard alignment. Defaults to 0 on x86 (unaligned access is
 * legal, and byte-exact overflow detection is worth more) and to 1
 * everywhere else, where a misaligned malloc() pointer can SIGBUS.  */
#ifndef LIBDEM_ALIGN_ALLOCATIONS
  #if defined(__x86_64__) || defined(__i386__)
    #define LIBDEM_ALIGN_ALLOCATIONS 0
  #else
    #define LIBDEM_ALIGN_ALLOCATIONS 1
  #endif
#endif

/* When 1, abort the process on calloc(a,b) where a*b overflows.
 * When 0, return NULL instead.                                     */
#ifndef LIBDEM_CHECK_CALLOC_OVERFLOW
  #define LIBDEM_CHECK_CALLOC_OVERFLOW 1
#endif

/* When 1, label our anonymous VMAs in /proc/<pid>/maps as
 * "libdemalloc". Requires Linux >= 5.17.                           */
#ifndef LIBDEM_NAME_PAGES
  #define LIBDEM_NAME_PAGES 0
#endif

/* fd written to with warnings / fatal messages. -1 disables all
 * logging entirely (smaller code, useful for production daemons). */
#ifndef LIBDEM_LOG_FD
  #define LIBDEM_LOG_FD 2
#endif

/* When defined, hard-code page size at compile time (e.g. 4096) and
 * skip the sysconf() call in the constructor.                      */
#ifndef LIBDEM_PAGE_SIZE
  /* leave undefined -> use sysconf */
#endif

/* When 1, free() drops the physical pages backing the quarantined
 * region via madvise(MADV_DONTNEED) before mprotect(PROT_NONE)'ing it.
 * The PROT_NONE still makes any UAF/double-free SIGSEGV (the access
 * can't happen, so DONTNEED's "next read returns zero" semantic never
 * fires) -- we just stop holding the RSS while the entry sits in
 * quarantine waiting to be munmap'd.
 *
 * This matters a lot for fuzzers targeting parsers that allocate
 * large containers (string tables, section data, debug info, etc.):
 * a few KB-MB allocations × LIBDEM_QUARANTINE_SLOTS quarantine slots
 * (128 by default; often raised for long UAF horizons) would otherwise
 * pin hundreds of MB of resident memory per harness lifetime, even
 * though every byte is unreachable.
 *
 * Disable (set to 0) on kernels where MADV_DONTNEED on anonymous
 * pages has surprising semantics, or where the syscall is unavailable
 * (very old / heavily stripped embedded kernels). The behavioural
 * outcome of disabling: bug detection is unchanged; per-process RSS
 * grows back to roughly (slots × avg_alloc_size).             */
#ifndef LIBDEM_RELEASE_RSS_ON_FREE
  #define LIBDEM_RELEASE_RSS_ON_FREE 1
#endif

/* When 1, draw a runtime-random canary at constructor time via the
 * getrandom(2) syscall. Defeats targets that read the canary value.
 * Off by default; not every embedded kernel exposes the syscall.   */
#ifndef LIBDEM_USE_GETRANDOM
  #define LIBDEM_USE_GETRANDOM 0
#endif

/* ---------------------------------------------------------------- */
/* Compile-time invariants.                                         */
/* ---------------------------------------------------------------- */

#if LIBDEM_QUARANTINE_SLOTS < 1
  #error "LIBDEM_QUARANTINE_SLOTS must be >= 1"
#endif

#if __STDC_VERSION__ < 201112L
typedef struct {
  long long   __ll;
  long double __ld;
} max_align_t;
#endif

#define ALLOC_ALIGN_SIZE (_Alignof(max_align_t))

#ifdef LIBDEM_PAGE_SIZE
  #define PAGE_SIZE ((size_t)LIBDEM_PAGE_SIZE)
#else
static size_t cached_page_size = 4096;
  #define PAGE_SIZE cached_page_size
#endif

#define PG_COUNT(_l) (((_l) + (PAGE_SIZE - 1)) / PAGE_SIZE)

/* Header metadata sits immediately below the returned pointer.
 * Two u32 fields: canary at [-1], length at [-2].                  */
#define PTR_C(_p) (((uint32_t *)(_p))[-1])
#define PTR_L(_p) (((uint32_t *)(_p))[-2])

/* ---------------------------------------------------------------- */
/* Minimal logging. write(2) is async-signal-safe and never recurses
 * through the allocator, so it is safe to call from free().        */
/* ---------------------------------------------------------------- */

#if LIBDEM_LOG_FD >= 0

static void log_str(const char *s) {
  size_t n = 0;
  while (s[n]) n++;
  (void)!write(LIBDEM_LOG_FD, s, n);
}

  #define LOG(_s) log_str("[libdemalloc] " _s "\n")
  /* abort() (SIGABRT) is used over __builtin_trap()/UD2 (SIGILL) so
   * that fuzzers running with libcov LD_PRELOAD'd alongside us see our
   * detections as crashes rather than as escaped libcov-trap signals.
   * abort() is async-signal-safe per POSIX; none of our FATAL sites
   * are reachable while the quarantine spinlock is held.            */
  #define FATAL(_s)         \
    do {                    \
      log_str("*** [libdemalloc] " _s " ***\n"); \
      abort();              \
    } while (0)

#else

  #define LOG(_s) ((void)0)
  #define FATAL(_s) abort()

#endif

/* ---------------------------------------------------------------- */
/* Hand-rolled spinlock guarding the quarantine ring. No pthread,   */
/* no libatomic. C11 __atomic_* on a plain byte is supported by GCC */
/* >= 4.7 and any vaguely modern Clang on every Linux arch we care  */
/* about (x86, ARM, AArch64, MIPS, PPC, RISC-V).                    */
/* ---------------------------------------------------------------- */

static volatile unsigned char q_lock_byte;

static inline void cpu_relax(void) {
#if defined(__x86_64__) || defined(__i386__)
  __asm__ __volatile__("pause" ::: "memory");
#elif defined(__aarch64__)
  __asm__ __volatile__("yield" ::: "memory");
#elif defined(__arm__)
  /* YIELD is a hint encoded as NOP on cores that don't implement it.
   * Safe on every ARMv6+.                                          */
  __asm__ __volatile__("yield" ::: "memory");
#elif defined(__powerpc__) || defined(__powerpc64__)
  /* "or 27,27,27" is the architecturally-defined low-priority hint. */
  __asm__ __volatile__("or 27,27,27" ::: "memory");
#else
  /* Generic fallback: just a compiler barrier. Works correctly but
   * doesn't tell the CPU we're spinning.                           */
  __asm__ __volatile__("" ::: "memory");
#endif
}

static inline void q_lock_acquire(void) {
  /* Test-and-test-and-set keeps cache lines shared while contended. */
  for (;;) {
    if (!__atomic_test_and_set(&q_lock_byte, __ATOMIC_ACQUIRE)) return;
    while (__atomic_load_n(&q_lock_byte, __ATOMIC_RELAXED))
      cpu_relax();
  }
}

static inline void q_lock_release(void) {
  __atomic_clear(&q_lock_byte, __ATOMIC_RELEASE);
}

/* ---------------------------------------------------------------- */
/* Quarantine ring.                                                 */
/* ---------------------------------------------------------------- */

struct q_slot {
  void  *base;  /* mmap base (page-aligned) */
  size_t span;  /* total mmap length in bytes */
};

static struct q_slot q_ring[LIBDEM_QUARANTINE_SLOTS];
static size_t        q_head;   /* next write index   */
static size_t        q_count;  /* current occupancy  */

/* Push a {base, span} entry onto the quarantine. If the ring is full,
 * the oldest entry is evicted and its pages are munmap'd, returning
 * them to the kernel. Caller must NOT hold q_lock_byte.            */
static void q_push(void *base, size_t span) {
  void  *evict_base = NULL;
  size_t evict_span = 0;

  q_lock_acquire();

  if (q_count == LIBDEM_QUARANTINE_SLOTS) {
    evict_base = q_ring[q_head].base;
    evict_span = q_ring[q_head].span;
  } else {
    q_count++;
  }

  q_ring[q_head].base = base;
  q_ring[q_head].span = span;
  q_head = (q_head + 1) % LIBDEM_QUARANTINE_SLOTS;

  q_lock_release();

  /* munmap outside the lock: it's a syscall, and the slot is already
   * overwritten so no other thread can race on this address.       */
  if (evict_base) (void)munmap(evict_base, evict_span);
}

/* Drain the quarantine: munmap every region currently held and reset
 * the ring to empty. Intended for persistent-mode fuzz harnesses that
 * iterate the target inside a single long-lived process: between
 * iterations the harness calls this so the prior iteration's freed
 * allocations stop carrying their VA / RSS / slot occupancy forward.
 *
 * Trade-off worth understanding before calling: UAF / double-free
 * detection only fires while the offending region is still
 * quarantined. Flushing therefore drops the detection window for
 * everything freed before the flush -- which is precisely the point
 * for persistent loop fuzzing, where the harness is asserting that
 * no live pointers from iteration N may leak into iteration N+1.
 *
 * Drains one slot at a time so munmap() runs outside the spinlock,
 * matching q_push()'s eviction path.                                */
void libdem_flush_quarantine(void) {
  for (;;) {
    void  *base;
    size_t span;
    size_t tail;

    q_lock_acquire();
    if (q_count == 0) {
      q_lock_release();
      return;
    }
    tail = (q_head + LIBDEM_QUARANTINE_SLOTS - q_count) %
           LIBDEM_QUARANTINE_SLOTS;
    base = q_ring[tail].base;
    span = q_ring[tail].span;
    q_count--;
    q_lock_release();

    (void)munmap(base, span);
  }
}

/* ---------------------------------------------------------------- */
/* Constructor: page-size lookup + optional canary randomization.   */
/* ---------------------------------------------------------------- */

static uint32_t alloc_canary = LIBDEM_ALLOC_CANARY;

__attribute__((constructor)) static void libdem_init(void) {
#ifndef LIBDEM_PAGE_SIZE
  long ps = sysconf(_SC_PAGESIZE);
  if (ps > 0) cached_page_size = (size_t)ps;
#endif

#if LIBDEM_USE_GETRANDOM
  uint32_t c;
  long     rd = syscall(SYS_getrandom, &c, sizeof(c), 0);
  if (rd == (long)sizeof(c)) alloc_canary = c;
#endif

#if LIBDEM_NAME_PAGES
  /* prctl is called from individual allocations; nothing to do here. */
#endif
}

/* ---------------------------------------------------------------- */
/* Core allocator.                                                  */
/* ---------------------------------------------------------------- */

/* Allocate len bytes. align is the caller's required alignment of the
 * returned pointer: 0 for plain malloc. For align <= PAGE_SIZE the
 * caller must pass a len that is a multiple of align (the buffer ends
 * on a page boundary, so its start is then aligned). For align >
 * PAGE_SIZE we additionally place the guard page on an align
 * boundary by over-mapping and trimming; the surviving mapping has
 * exactly the normal {base, span} layout so dem_region() / free()
 * need no extra metadata.                                          */
static void *dem_alloc_aligned(size_t len, size_t align) {
  uint8_t *ret;
  size_t   tlen, rlen, extra = 0;

  /* The length is stored as a uint32_t in the header (PTR_L).       */
#if SIZE_MAX > UINT32_MAX
  if (len > UINT32_MAX) { errno = ENOMEM; return NULL; }
#endif

  /* Overflow checks: len + ALIGN + PAGE_SIZE must not wrap.         */
  if (len > SIZE_MAX - PAGE_SIZE - ALLOC_ALIGN_SIZE - 16) {
    errno = ENOMEM;
    return NULL;
  }

#if LIBDEM_ALIGN_ALLOCATIONS
  if (len & (ALLOC_ALIGN_SIZE - 1))
    rlen = (len & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE;
  else
    rlen = len;
#else
  rlen = len;
#endif

  /* +8 for header metadata (length + canary).                      */
  tlen = (1 + PG_COUNT(rlen + 8)) * PAGE_SIZE;

  if (align > PAGE_SIZE) {
    extra = align - PAGE_SIZE;
    if (tlen > SIZE_MAX - extra) { errno = ENOMEM; return NULL; }
  }

  ret = (uint8_t *)mmap(NULL, tlen + extra, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ret == MAP_FAILED) { errno = ENOMEM; return NULL; }

  if (extra) {
    /* Slide the layout so the guard page (and hence, with len a
     * multiple of align, the buffer start) lands on an align
     * boundary, then unmap the unused head and tail. Both pieces are
     * whole pages because mmap results and align are page-aligned. */
    uintptr_t guard  = (uintptr_t)ret + PG_COUNT(rlen + 8) * PAGE_SIZE;
    size_t    shift  = (size_t)(((guard + align - 1) & ~(uintptr_t)(align - 1))
                                - guard);
    if (shift) (void)munmap(ret, shift);
    if (extra - shift) (void)munmap(ret + shift + tlen, extra - shift);
    ret += shift;
  }

#if LIBDEM_NAME_PAGES
  (void)prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, (unsigned long)ret, tlen,
              (unsigned long)"libdemalloc");
#endif

  /* Make the trailing page a guard.                                */
  if (mprotect(ret + PG_COUNT(rlen + 8) * PAGE_SIZE, PAGE_SIZE,
               PROT_NONE)) {
    (void)munmap(ret, tlen);
    return NULL;
  }

  /* Right-align the user buffer against the guard page so the very
   * last user byte is adjacent to PROT_NONE.                       */
  ret += PAGE_SIZE * PG_COUNT(rlen + 8) - rlen - 8;
  ret += 8;

  PTR_L(ret) = (uint32_t)len;
  PTR_C(ret) = alloc_canary;

#if LIBDEM_ALIGN_ALLOCATIONS
  if (rlen != len) {
    size_t i;
    for (i = len; i < rlen; ++i) ret[i] = LIBDEM_TAIL_CANARY;
  }
#endif

  return ret;
}

static void *dem_alloc(size_t len) {
  return dem_alloc_aligned(len, 0);
}

/* Recover the (mmap_base, mmap_span) for a user pointer ptr whose
 * stored length is len.                                            */
static inline void dem_region(void *ptr, size_t len, void **base_out,
                              size_t *span_out) {
  size_t   rlen;
  uint8_t *p = (uint8_t *)ptr;

#if LIBDEM_ALIGN_ALLOCATIONS
  if (len & (ALLOC_ALIGN_SIZE - 1))
    rlen = (len & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE;
  else
    rlen = len;
#else
  rlen = len;
#endif

  /* Reverse of the right-alignment + 8-byte header skip in dem_alloc. */
  uint8_t *header = p - 8;
  uint8_t *base   = header - (PAGE_SIZE * PG_COUNT(rlen + 8) - rlen - 8);
  size_t   span   = (1 + PG_COUNT(rlen + 8)) * PAGE_SIZE;

  *base_out = base;
  *span_out = span;
}

/* ---------------------------------------------------------------- */
/* Public wrappers.                                                 */
/* ---------------------------------------------------------------- */

__attribute__((malloc)) __attribute__((alloc_size(1)))
void *malloc(size_t len) {
  void *ret = dem_alloc(len);
  if (ret && len) memset(ret, LIBDEM_CLOBBER_BYTE, len);
  return ret;
}

__attribute__((malloc)) __attribute__((alloc_size(1, 2)))
void *calloc(size_t elem_len, size_t elem_cnt) {
  if (elem_cnt && elem_len > SIZE_MAX / elem_cnt) {
#if LIBDEM_CHECK_CALLOC_OVERFLOW
    FATAL("calloc() size overflow");
#else
    return NULL;
#endif
  }
  /* mmap zero-fills; no explicit memset needed.                    */
  return dem_alloc(elem_len * elem_cnt);
}

void free(void *ptr) {
  if (!ptr) return;

  if (PTR_C(ptr) != alloc_canary) FATAL("bad canary on free()");

  size_t len = PTR_L(ptr);

#if LIBDEM_ALIGN_ALLOCATIONS
  {
    size_t rlen;
    if (len & (ALLOC_ALIGN_SIZE - 1))
      rlen = (len & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE;
    else
      rlen = len;
    uint8_t *p = (uint8_t *)ptr;
    size_t   i;
    for (i = len; i < rlen; ++i)
      if (p[i] != LIBDEM_TAIL_CANARY)
        FATAL("bad tail canary on free()");
  }
#endif

  void  *base;
  size_t span;
  dem_region(ptr, len, &base, &span);

#if LIBDEM_RELEASE_RSS_ON_FREE
  /* Release the physical pages backing this allocation while it sits
   * in quarantine. Combined with the PROT_NONE below this makes the
   * pages unreachable AND unbacked -- UAF/double-free still segfaults
   * (the access can't happen) but the kernel reclaims the RSS now
   * instead of when the slot is munmap'd LIBDEM_QUARANTINE_SLOTS frees
 * later (128 by default). Ignore the
   * return: a kernel that refuses MADV_DONTNEED here (e.g. on a hugepage
   * VMA) just leaves the pages resident, which is the pre-D1 behaviour. */
  (void)madvise(base, span, MADV_DONTNEED);
#endif

  /* Disarm the region. Any subsequent read/write -- including the
   * canary check on a double-free -- will segfault.                */
  if (mprotect(base, span, PROT_NONE))
    FATAL("mprotect(PROT_NONE) failed in free()");

  q_push(base, span);
}

__attribute__((alloc_size(2)))
void *realloc(void *ptr, size_t len) {
  void *ret = malloc(len);
  if (ret && ptr) {
    if (PTR_C(ptr) != alloc_canary) FATAL("bad canary on realloc()");
    size_t oldlen = PTR_L(ptr);
    memcpy(ret, ptr, oldlen < len ? oldlen : len);
    free(ptr);
  } else if (!ret && ptr) {
    /* C requires that on failure the old block remains valid; we
     * keep it.                                                     */
  }
  return ret;
}

int posix_memalign(void **ptr, size_t align, size_t len) {
  /* glibc declares ptr as __nonnull; we trust that contract and skip
   * the redundant NULL check that would otherwise trip -Wnonnull. */
  if ((align % sizeof(void *)) || (align & (align - 1)) || align == 0)
    return EINVAL;
  if (len == 0) { *ptr = NULL; return 0; }

  /* Round len up to a multiple of align: dem_alloc_aligned() ends the
   * buffer on an align boundary, so this aligns its start.          */
  size_t rem = len % align;
  if (rem) {
    if (len > SIZE_MAX - (align - rem)) return ENOMEM;
    len += align - rem;
  }

  void *p = dem_alloc_aligned(len, align);
  if (!p) return ENOMEM;
  memset(p, LIBDEM_CLOBBER_BYTE, len);
  *ptr = p;
  return 0;
}

__attribute__((malloc)) __attribute__((alloc_size(2)))
void *memalign(size_t align, size_t len) {
  /* glibc's memalign accepts any alignment: small ones are raised to
   * pointer size, non-powers of two rounded up to the next power.   */
  if (align < sizeof(void *)) align = sizeof(void *);
  if (align & (align - 1)) {
    size_t a = sizeof(void *);
    while (a < align) {
      if (a > SIZE_MAX / 2) { errno = EINVAL; return NULL; }
      a <<= 1;
    }
    align = a;
  }
  void *ret = NULL;
  int   rc  = posix_memalign(&ret, align, len);
  if (rc) errno = rc;
  return ret;
}

__attribute__((malloc)) __attribute__((alloc_size(2)))
void *aligned_alloc(size_t align, size_t len) {
  if (align == 0 || (len % align)) return NULL;
  void *ret = NULL;
  int   rc  = posix_memalign(&ret, align, len);
  if (rc) { errno = rc; return NULL; }
  return ret;
}

/* Page-aligned allocation. valloc(0) / pvalloc(0) return a usable
 * one-page buffer (like glibc), not NULL.                          */
__attribute__((malloc)) __attribute__((alloc_size(1)))
void *valloc(size_t len) {
  void *ret = NULL;
  int   rc  = posix_memalign(&ret, PAGE_SIZE, len ? len : 1);
  if (rc) { errno = rc; return NULL; }
  return ret;
}

/* As valloc(), with len rounded up to a whole number of pages.
 * (posix_memalign already rounds len to the alignment, so the only
 * difference is making that rounding explicit and overflow-checked.) */
__attribute__((malloc))
void *pvalloc(size_t len) {
  size_t plen = len ? len : 1;
  if (plen > SIZE_MAX - (PAGE_SIZE - 1)) { errno = ENOMEM; return NULL; }
  plen = PG_COUNT(plen) * PAGE_SIZE;
  return valloc(plen);
}

__attribute__((alloc_size(2, 3)))
void *reallocarray(void *ptr, size_t elem_len, size_t elem_cnt) {
  if (elem_cnt && elem_len > SIZE_MAX / elem_cnt) return NULL;
  return realloc(ptr, elem_len * elem_cnt);
}

size_t malloc_usable_size(void *ptr) {
  return ptr ? PTR_L(ptr) : 0;
}
