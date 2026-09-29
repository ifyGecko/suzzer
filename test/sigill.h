/*
 * sigill.h -- execute one illegal instruction that raises SIGILL.
 *
 * libcov's traps are SIGILL from illegal encodings on every backend, never
 * SIGTRAP, so tests that need a *real* (non-libcov) illegal instruction
 * must raise the same signal. __builtin_trap() does not on most of them:
 * it is `brk` on aarch64, `trap` on powerpc, `ebreak` on riscv64 and a
 * `break`/`teq` on mips -- all SIGTRAP.
 *
 * The encodings are the backends' defaults from src/tunables_<arch>.h.
 */
#ifndef LIBCOV_TEST_SIGILL_H
#define LIBCOV_TEST_SIGILL_H

#if defined(__x86_64__) || defined(__i386__)
#  define TEST_SIGILL() __asm__ __volatile__("ud2")
#elif defined(__aarch64__)
#  define TEST_SIGILL() __asm__ __volatile__(".inst 0x00000000")   /* udf #0 */
#elif defined(__arm__) && defined(__thumb__)
#  define TEST_SIGILL() __asm__ __volatile__(".inst.n 0xde00")     /* udf #0 (T1) */
#elif defined(__arm__)
#  define TEST_SIGILL() __asm__ __volatile__(".inst 0xe7f000f0")   /* udf #0 (A1) */
#elif defined(__mips__)
#  define TEST_SIGILL() __asm__ __volatile__(".word 0x40000000")   /* mfc0 $0,$0 */
#elif defined(__powerpc__) || defined(__powerpc64__)
#  define TEST_SIGILL() __asm__ __volatile__(".long 0x00000000")
#elif defined(__riscv)
#  define TEST_SIGILL() __asm__ __volatile__(".2byte 0x0000")      /* c.unimp */
#else
#  error "no SIGILL encoding for this architecture"
#endif

#endif
