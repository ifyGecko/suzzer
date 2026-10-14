/*
 * plat_baremetal_mips.c -- baremetal MIPS32 platform backend.
 *
 * suzzer is a standalone framework: this file is board-AGNOSTIC. Everything
 * board-specific (where the instrumented code lives, where free RAM for the
 * coverage bitmap is, how to emit a log byte) is a compile-time macro or a
 * weak hook the integrator supplies -- it never hard-codes a particular
 * product. The defaults below are generic; override with -D at build time.
 *
 * Example integrations (NOT dependencies of suzzer):
 *   - a QEMU 'malta' test image (see test/baremetal/): defines libcov_bm_putc
 *     for the Malta 16550 UART and sets the arena macros to its RAM map.
 *   - a real firmware (e.g. an AR9330/VxWorks router): sets the module/arena
 *     macros to that image's RECON values and points libcov_bm_putc at its
 *     own UART MMIO.
 *
 * Memory-map macros (override per target):
 *   LIBCOV_BM_MODULE_LO/HI : address range of the instrumented code (the one
 *                            compiled-in module); plat_range_mapped checks it.
 *   LIBCOV_BM_ARENA_LO/HI  : free RAM for the coverage bitmap + scratch. Must
 *                            not overlap the OS, the instrumented code, or the
 *                            loaded libcov blob image.
 */
#include "plat.h"

const char *libcov_plat_name = "baremetal-mips";

/* ELF entry anchor for the linker (ENTRY in baremetal_mips.ld). The blob is
 * driven by calling libcov_init() explicitly once loaded, not via _start. */
void libcov_core_entry(void) { }

#ifndef LIBCOV_BM_MODULE_LO
#define LIBCOV_BM_MODULE_LO 0x80000000ull
#endif
#ifndef LIBCOV_BM_MODULE_HI
#define LIBCOV_BM_MODULE_HI 0x80400000ull
#endif
#ifndef LIBCOV_BM_ARENA_LO
#define LIBCOV_BM_ARENA_LO  0x80440000ull
#endif
#ifndef LIBCOV_BM_ARENA_HI
#define LIBCOV_BM_ARENA_HI  0x80800000ull
#endif

/* ---- freestanding libc shims (-nostdlib; -fno-builtin stops self-calls) -- */
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst; const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}
void *memset(void *dst, int c, size_t n) {
    unsigned char *d = dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}
int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
    for (; n--; x++, y++) if (*x != *y) return (int)*x - (int)*y;
    return 0;
}

/* ---- (B) trap delivery + chaining ----
 *
 * plat_trap_install writes a 4-instruction jump to libcov_vector_entry (the
 * asm trampoline) over the CPU general-exception vector, saving the words it
 * overwrites so a real OS handler can be chained. The vector address is the
 * standard 0x80000180 (BEV=0, EBase=0x80000000); override per target. */
#ifndef LIBCOV_BM_EXC_VECTOR
#define LIBCOV_BM_EXC_VECTOR 0x80000180ull
#endif

extern void libcov_vector_entry(void);        /* plat_baremetal_mips_vector.S */
extern void libcov_bm_chain(libcov_frame *f) __attribute__((weak));

static uint32_t g_saved_vector[4];
static int      g_vector_saved = 0;

int plat_trap_install(void) {
    volatile uint32_t *v = (volatile uint32_t *)(uintptr_t)LIBCOV_BM_EXC_VECTOR;
    for (int i = 0; i < 4; i++) g_saved_vector[i] = v[i];
    g_vector_saved = 1;

    uintptr_t e = (uintptr_t)&libcov_vector_entry;
    uint32_t ins[4];
    ins[0] = 0x3C1A0000u | ((uint32_t)(e >> 16) & 0xffffu);  /* lui  $k0, hi16(e) */
    ins[1] = 0x375A0000u | ((uint32_t)e & 0xffffu);          /* ori  $k0, $k0, lo16(e) */
    ins[2] = 0x03400008u;                                    /* jr   $k0 */
    ins[3] = 0x00000000u;                                    /* nop */
    plat_code_write((uintptr_t)LIBCOV_BM_EXC_VECTOR, ins, sizeof ins);
    plat_code_sync((uintptr_t)LIBCOV_BM_EXC_VECTOR, sizeof ins);
    return 0;
}

/* Reached only for a Reserved-Instruction trap whose PC is NOT one of our
 * sites (a genuine RI). Defer to the integrator's handler if provided. */
void plat_trap_chain(libcov_frame *f) {
    if (libcov_bm_chain) { libcov_bm_chain(f); return; }
    for (;;) { }   /* no chain configured: halt rather than loop on the fault */
}

/* ---- (C) code write + I-cache coherency ----
 *
 * The instrumented code is in writable RAM, so protect is a nop. After a
 * word store, MIPS32r2 'synci' writes back the D-cache line and invalidates
 * the matching I-cache line; 'sync' + 'ehb' order it and clear execution
 * hazards. (Real silicon also wants a jr.hb to clear instruction hazards
 * before the patched word is re-fetched; QEMU flushes its translation block
 * on synci, so sync+ehb suffices under emulation. A board that runs on metal
 * can strengthen this hook.) */
int plat_code_protect(uintptr_t page, size_t span, int writable) {
    (void)page; (void)span; (void)writable;
    return 0;
}
void plat_code_write(uintptr_t addr, const void *bytes, size_t len) {
    memcpy((void *)addr, bytes, len);
}
void plat_code_sync(uintptr_t addr, size_t len) {
    uintptr_t end = addr + len;
    unsigned long step;
    __asm__ volatile(".set push; .set mips32r2; rdhwr %0, $1; .set pop"
                     : "=r"(step));          /* HWR 1 = SYNCI step */
    if (step == 0) { /* synci is a nop on this core; invalidate whole range */
        __asm__ volatile(".set push; .set mips32r2; sync; ehb; .set pop"
                         ::: "memory");
        return;
    }
    for (uintptr_t p = addr & ~(uintptr_t)(step - 1); p < end; p += step)
        __asm__ volatile(".set push; .set mips32r2; synci 0(%0); .set pop"
                         :: "r"(p) : "memory");
    __asm__ volatile(".set push; .set mips32r2; sync; ehb; .set pop" ::: "memory");
}
void plat_code_sync_batch_end(void) { }          /* single core */

/* ---- arena: one bump watermark shared by the sink region and scratch ---- */
static uintptr_t g_bump = LIBCOV_BM_ARENA_LO;
static void *arena_alloc(size_t n) {
    uintptr_t p = (g_bump + 15) & ~(uintptr_t)15;
    if (p + n > LIBCOV_BM_ARENA_HI) return (void *)0;
    g_bump = p + n;
    return (void *)p;
}

/* ---- (D) coverage sink region ---- */
void *plat_map_region(const char *name, size_t total, int *attached_out) {
    (void)name;
    if (attached_out) *attached_out = 0;         /* no persistence across boots */
    return arena_alloc(total);
}

/* ---- (E) module base + range check ---- */
uintptr_t plat_module_base(const char *modname) {
    (void)modname;
    return (uintptr_t)LIBCOV_BM_MODULE_LO;
}
int plat_range_mapped(uintptr_t module_base, uintptr_t addr, size_t len) {
    (void)module_base;
    return addr >= LIBCOV_BM_MODULE_LO && (addr + len) <= LIBCOV_BM_MODULE_HI;
}

/* ---- (F) logging: board supplies libcov_bm_putc (weak; nop if absent) ---- */
extern void libcov_bm_putc(char c) __attribute__((weak));
void plat_log_init(void) { }
void plat_log_write(const char *buf, size_t n) {
    if (!libcov_bm_putc) return;
    for (size_t i = 0; i < n; i++) libcov_bm_putc(buf[i]);
}
void plat_log_seal(void) { }

/* ---- (G) small runtime services ---- */
uint64_t plat_mono_ns(void) {
    uint32_t c;
    __asm__ volatile("mfc0 %0, $9" : "=r"(c));   /* CP0 Count (cycles, monotonic) */
    return (uint64_t)c;
}
const char *plat_config(const char *key) { (void)key; return (const char *)0; }
void *plat_scratch_alloc(size_t n) { return arena_alloc(n); }
