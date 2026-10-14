/*
 * plat.h -- platform/runtime backend interface.
 *
 * libcov's coverage mechanism (overwrite an instruction with an illegal
 * encoding, catch the fault, record an edge, restore, resume) is OS-neutral.
 * Everything that *is* OS-specific -- how we take control on a trap, how we
 * read the faulting register context, how we patch code, where the coverage
 * bitmap lives, how we resolve module bases, how we log -- is factored behind
 * this header. Exactly one src/plat_<NAME>.c links into a given build,
 * selected by the Makefile's PLAT variable, mirroring how one arch_<BACKEND>.c
 * is selected by ARCH.
 *
 * Staging: the trap-frame abstraction (A) landed first so the ISA backends
 * and the trap dispatcher stop naming ucontext_t directly, keeping Linux
 * byte-identical. The remaining OS services (B..G) are declared here as the
 * framework contract; the Linux implementations are lifted out of
 * libcov.c/patch_*.c/sink_shm.c/util.c behind these functions in a later
 * phase, as the baremetal backend grows a real consumer for each. Until then
 * the Linux build does not call B..G, so leaving them unimplemented on Linux
 * is not a link error; the baremetal backend implements them (stubs first).
 */
#ifndef LIBCOV_PLAT_H
#define LIBCOV_PLAT_H

#include <stdint.h>
#include <stddef.h>

/* Default the platform to Linux when the Makefile did not pick one, so a
 * stray includer (a tool, a one-off compile) still works on a hosted system.
 * The Makefile defines exactly one LIBCOV_PLAT_* for libcov's own sources. */
#if !defined(LIBCOV_PLAT_LINUX) && !defined(LIBCOV_PLAT_BAREMETAL_MIPS)
#  if defined(__linux__)
#    define LIBCOV_PLAT_LINUX 1
#  endif
#endif

/* Short platform name, for logs / HELLO negotiation. One per plat_<NAME>.c. */
extern const char *libcov_plat_name;

/* ---- (A) trap frame ------------------------------------------------------
 *
 * `libcov_frame` is the platform's view of the trapped CPU state. It is
 * opaque to the trap dispatcher, which only passes a pointer around. The ISA
 * backend reads/writes registers through the accessors below:
 *   - libcov_frame_gregs: canonical general-register file (GPR[0..31] on
 *     MIPS; 64-bit slots, matching glibc greg_t).
 *   - libcov_frame_pcptr: pointer to the PC/EPC slot, so a marker emulation
 *     can advance it in place (bit-identical to writing uc_mcontext.pc on
 *     Linux).
 * Linux-only backends (x86_64, arm, aarch64, powerpc, riscv) additionally
 * reach the native ucontext via libcov_frame_uc(); they never build for a
 * baremetal platform, so that coupling is confined to them.
 */

#if defined(LIBCOV_PLAT_LINUX)

#include <ucontext.h>

typedef struct libcov_frame { ucontext_t *uc; } libcov_frame;

static inline void libcov_frame_from_uctx(libcov_frame *f, void *uctx) {
    f->uc = (ucontext_t *)uctx;
}
static inline ucontext_t *libcov_frame_uc(const libcov_frame *f) {
    return f->uc;
}

#if defined(__mips__)
/* glibc mips mcontext: gregs[] is greg_t[32] in canonical order, pc is a
 * greg_t. greg_t is unsigned long long, so these casts are identity and the
 * MIPS emulate math is unchanged from reading uc_mcontext.* directly. */
static inline unsigned long long *libcov_frame_gregs(libcov_frame *f) {
    return (unsigned long long *)f->uc->uc_mcontext.gregs;
}
static inline unsigned long long *libcov_frame_pcptr(libcov_frame *f) {
    return (unsigned long long *)&f->uc->uc_mcontext.pc;
}
#endif /* __mips__ */

#elif defined(LIBCOV_PLAT_BAREMETAL_MIPS)

/* Filled by the exception-vector stub (later phase): all 32 GPRs plus EPC and
 * the CP0 Cause of the trap. No ucontext, no libc. */
typedef struct libcov_frame {
    unsigned long long gpr[32];
    unsigned long long epc;
    uint32_t           cause;
} libcov_frame;

static inline unsigned long long *libcov_frame_gregs(libcov_frame *f) {
    return f->gpr;
}
static inline unsigned long long *libcov_frame_pcptr(libcov_frame *f) {
    return &f->epc;
}

#else
#  error "plat.h: no LIBCOV_PLAT_* backend selected (define LIBCOV_PLAT_LINUX or LIBCOV_PLAT_BAREMETAL_MIPS)"
#endif

/* ---- (B) trap delivery + chaining ----------------------------------------
 *
 * plat_trap_install arms fault delivery: sigaction(SIGILL) on Linux; install
 * the exception-vector trampoline at 0x80000180 on baremetal MIPS. The plat
 * calls the shared dispatcher on each trap and uses plat_trap_chain for a
 * trap whose PC is not one of ours (the target's own handler on Linux; the
 * saved VxWorks vector on baremetal). */
int  plat_trap_install(void);
void plat_trap_chain(libcov_frame *f);

/* ---- (C) code write + instruction-cache coherency ------------------------
 *
 * Linux: mprotect W^X flip + __builtin___clear_cache (+ membarrier in MT).
 * Baremetal MIPS: protect is a nop (OS text is already rwx); write stores the
 * word; sync does D-cache writeback + I-cache invalidate (synci / cache ops);
 * sync_batch_end is a nop on a single core. */
int  plat_code_protect(uintptr_t page, size_t span, int writable);
void plat_code_write(uintptr_t addr, const void *bytes, size_t len);
void plat_code_sync(uintptr_t addr, size_t len);
void plat_code_sync_batch_end(void);

/* ---- (D) coverage sink region --------------------------------------------
 *
 * Linux: shm_open + ftruncate + mmap. Baremetal: a fixed slice of free RAM.
 * *attached_out is set to 1 when an existing region was reattached. */
void *plat_map_region(const char *name, size_t total, int *attached_out);

/* ---- (E) module base + range check ---------------------------------------
 *
 * Linux: resolve from /proc/self/maps. Baremetal: the one compiled-in base. */
uintptr_t plat_module_base(const char *modname);
int       plat_range_mapped(uintptr_t module_base, uintptr_t addr, size_t len);

/* ---- (F) logging ---------------------------------------------------------
 *
 * Linux: a log fd. Baremetal: UART MMIO or a free-RAM ring. Off the hot path. */
void plat_log_init(void);
void plat_log_write(const char *buf, size_t n);
void plat_log_seal(void);

/* ---- (G) small runtime services ------------------------------------------ */
uint64_t    plat_mono_ns(void);            /* boundary.c marker-rearm timing */
const char *plat_config(const char *key);  /* getenv on Linux; baked table otherwise */
void       *plat_scratch_alloc(size_t n);  /* calloc on Linux; bump alloc otherwise */

#endif /* LIBCOV_PLAT_H */
