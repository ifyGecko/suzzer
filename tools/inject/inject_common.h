/*
 * inject_common.h -- shared types + public API used by inject_ptrace.c
 * and inject_procmem.c.
 *
 * This header is the source of truth for the injector's data model:
 *
 *   - struct proc_map / proc_map_table:  /proc/<pid>/maps in memory.
 *   - struct inject_session:             open handle on a target process
 *                                        with all resolved symbols, the
 *                                        scratch page, saved regs, etc.
 *   - struct env_list:                   -e KEY=VAL pairs from the CLI.
 *
 * Everything that the per-arch backends DON'T need to see lives here.
 */

#ifndef INJECT_COMMON_H
#define INJECT_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <limits.h>
#include "arch_inject.h"

/* ---- logging ------------------------------------------------------ */

/* Verbosity. Bumped to 1 by -v, 2 by -vv. */
extern int inject_verbose;

/* Logging macros. All write to stderr with an "inject: " prefix. */
#define LOG_ERR(fmt, ...) \
    fprintf(stderr, "inject: " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) do { \
        if (inject_verbose >= 1) \
            fprintf(stderr, "inject: " fmt "\n", ##__VA_ARGS__); \
    } while (0)
#define LOG_DBG(fmt, ...) do { \
        if (inject_verbose >= 2) \
            fprintf(stderr, "inject: " fmt "\n", ##__VA_ARGS__); \
    } while (0)

/* ---- sentinel return-trap PC ------------------------------------- */

/* Address we plant as the fake return address before each remote function
 * call. The function's RET transfers here; the resulting SIGSEGV is caught
 * by the injector via waitpid.
 *
 * Chosen well outside any plausible userspace mapping on Linux (low
 * canonical, sub-1MB on every supported arch). inject_pick_trap_pc()
 * scans /proc/<pid>/maps to validate that this address is not mapped
 * in the target; if it ever is, we walk down by page until we find
 * an unmapped one. */
#define INJECT_TRAP_PC_DEFAULT  ((uintptr_t)0xdead0000UL)

/* ---- /proc/<pid>/maps parsing ----------------------------------- */

struct proc_map {
    uintptr_t   start;      /* inclusive */
    uintptr_t   end;        /* exclusive */
    uintptr_t   file_off;
    char        perms[5];           /* "rwxp\0" */
    char        path[PATH_MAX];     /* "" for anonymous mappings */
};

struct proc_map_table {
    struct proc_map *m;
    size_t           n;
    size_t           cap;
};

/* Parse /proc/<pid>/maps into `t`. Returns 0 on success, -1 on errno. */
int  proc_maps_load(pid_t pid, struct proc_map_table *t);
void proc_maps_free(struct proc_map_table *t);

/* Find the first mapping whose pathname basename matches `basename_glob`,
 * using fnmatch(3) semantics on the basename only. Examples:
 *   "libc.so.6"          exact basename
 *   "libc.so*"           any libc.so variant
 *   "ld-linux-*.so*"     any glibc dynamic linker
 *   "ld-musl-*.so*"      musl dynamic linker
 *
 * Returns the matching entry (with read+exec perms, so we pick up the
 * .text mapping not the data one), or NULL. */
const struct proc_map *proc_maps_find_lib(const struct proc_map_table *t,
                                          const char *basename_glob);

/* Returns the load base of the named library, i.e. the runtime address
 * corresponding to ELF vaddr 0. For prelinked / PIE shared objects this
 * is the address of the lowest PT_LOAD segment after relocation. The
 * function reads the on-disk ELF at map->path to find the first
 * PT_LOAD's p_vaddr (usually 0 but not guaranteed) and computes:
 *
 *     load_base = map->start - first_LOAD.p_vaddr + map->file_off
 *
 * For the *exec* of a non-PIE binary on x86_64 this returns 0x400000
 * etc. For libc.so on any modern system this returns the ASLR-chosen
 * base.
 *
 * Note: many .so files have multiple PT_LOAD segments (text + data).
 * The mapping `map` we were given is for ONE of those segments
 * (typically the first / .text one). We use map->file_off to back-
 * compute correctly even if the caller handed us the data mapping.
 *
 * Returns 0 on success, -1 on ELF parse failure. */
int proc_maps_load_base(const struct proc_map *map, uintptr_t *out_base);

/* Returns 1 if `addr` falls inside any mapping in `t`, else 0. Used
 * by inject_pick_trap_pc to validate the sentinel. */
int proc_maps_addr_mapped(const struct proc_map_table *t, uintptr_t addr);

/* Pick a guaranteed-unmapped page-aligned address suitable for use as
 * the return-trap sentinel. Starts at INJECT_TRAP_PC_DEFAULT; walks
 * down by page until finding an unmapped address. Returns 0 (caller
 * treats as fatal) if it can't find one in 1024 attempts (which would
 * mean the target's address space is wedged). */
uintptr_t inject_pick_trap_pc(const struct proc_map_table *t);

/* ---- ELF symbol resolution -------------------------------------- */

/* Open the library at `path` (host filesystem path; the caller is
 * responsible for any /proc/<pid>/root/ prefix), parse its dynamic
 * symbol table (DT_SYMTAB + DT_STRTAB, with DT_GNU_HASH/DT_HASH
 * lookup), and resolve `name` to its ELF-internal virtual address.
 *
 * Returns 0 on success and writes the ELF vaddr to *out_vaddr; -1 on
 * not-found or parse failure.
 *
 * Symbol versioning: we walk DT_VERSYM/DT_VERDEF only enough to skip
 * version markers; if multiple definitions of the same name exist
 * with different versions (e.g. dlopen@GLIBC_2.34 vs older), we pick
 * the highest-versioned one. This matches what the dynamic linker
 * does for un-versioned external references. */
int elf_lookup_symbol(const char *lib_path, const char *name,
                      uintptr_t *out_vaddr);

/* Convenience wrapper: find a symbol in a library identified by its
 * basename glob (e.g. "libc.so*"). Searches /proc/<pid>/maps for the
 * library, opens the on-disk path (with /proc/<pid>/root/ fallback for
 * chrooted targets), resolves the symbol, returns the runtime address
 * (load-base-adjusted). Returns 0 if the library isn't loaded or the
 * symbol isn't found. */
uintptr_t resolve_lib_symbol(pid_t pid, const struct proc_map_table *t,
                             const char *lib_basename_glob,
                             const char *symbol);

/* Resolve `dlopen` with the standard fallback chain:
 *
 *   1. libc.so:dlopen                  (glibc 2.34+, musl, uClibc-ng)
 *   2. libc.so:__libc_dlopen_mode      (older glibc; needs the
 *                                       __RTLD_DLOPEN flag bit ored in)
 *   3. libdl.so*:dlopen                (only if libdl is ALREADY loaded
 *                                       into the target; we can't load
 *                                       it ourselves -- chicken/egg)
 *
 * On success, writes the resolved runtime address to *out_addr and
 * (if non-NULL) writes 1 to *out_is_libc_dlopen_mode iff fallback #2
 * was used; the caller must then pass mode = RTLD_NOW | 0x80000000
 * (= __RTLD_DLOPEN) instead of plain RTLD_NOW.
 *
 * Returns 0 on success, -1 if all three fallbacks fail. */
int resolve_dlopen(pid_t pid, const struct proc_map_table *t,
                   uintptr_t *out_addr, int *out_is_libc_dlopen_mode);

/* Read /proc/<pid>/exe and return the target's ELF e_machine value
 * (EM_X86_64, EM_AARCH64, EM_ARM, ...). Used to pick the per-arch
 * backend. Returns 0 on success, -1 on parse failure. */
int proc_target_machine(pid_t pid, int *out_machine);

/* ---- target memory I/O ------------------------------------------ */

/* Write `len` bytes from `local` to target address `remote`. Uses
 * process_vm_writev (Linux 3.2+), which avoids the ptrace word-by-word
 * dance for bulk transfers. Returns 0 on success, -1 on errno set
 * (EFAULT if remote isn't writable in target). */
int target_write(pid_t pid, uintptr_t remote, const void *local, size_t len);

/* Read `len` bytes from target address `remote` into `local`.
 * Same semantics via process_vm_readv. */
int target_read(pid_t pid, uintptr_t remote, void *local, size_t len);

/* ---- env-var parsing -------------------------------------------- */

struct env_kv {
    const char *key;
    const char *val;
};

#define INJECT_MAX_ENV 32
struct env_list {
    struct env_kv items[INJECT_MAX_ENV];
    int           n;
};

/* Parse a single "KEY=VAL" string from the CLI into the list. The
 * string is NOT copied -- the caller's storage must outlive the list.
 * Returns 0 on success, -1 on malformed input or list full. */
int env_list_add_kv(struct env_list *e, const char *kv_string);

/* Add a (key, val) pair directly. Same lifetime rules. */
int env_list_add(struct env_list *e, const char *key, const char *val);

/* ---- inject_session: open handle on the target ----------------- */

struct inject_session {
    pid_t                          pid;
    const struct inject_arch      *arch;
    struct proc_map_table          maps;

    /* Snapshot of target's registers at attach time -- restored at
     * detach. The trap_pc redirection means the target's stack/heap
     * is unmodified by our remote calls (we only push args), so
     * restoring regs returns the target to its pre-injection state
     * exactly. */
    struct inject_regs             regs_saved;

    /* Unmapped sentinel address used as the fake return PC for remote
     * function calls. Validated against `maps` at attach time. */
    uintptr_t                      trap_pc;

    /* RW page allocated in target via remote mmap. Used to stage env
     * strings, libcov path, dlerror buffer, etc. */
    uintptr_t                      scratch;
    size_t                         scratch_len;

    /* Resolved target functions. */
    uintptr_t                      addr_setenv;
    uintptr_t                      addr_dlopen;
    uintptr_t                      addr_dlerror;       /* 0 if not resolved */

    /* True iff addr_dlopen points at __libc_dlopen_mode (which takes a
     * mode = RTLD_NOW | __RTLD_DLOPEN as its second arg instead of
     * plain RTLD_NOW). */
    int                            dlopen_is_libc_mode;

    /* Address of a syscall instruction in the target (in libc or vDSO),
     * used for remote-syscall single-stepping. */
    uintptr_t                      syscall_pc;

    /* True iff we're currently ptrace-attached and the target is in
     * a stopped state. Used by inject_detach to know whether to
     * PTRACE_DETACH or just abandon. */
    int                            attached;
};

/* PTRACE_ATTACH + waitpid for the group-stop. Loads /proc/<pid>/maps,
 * picks the per-arch backend, saves regs, picks a trap_pc.
 * Returns 0 on success, -1 on errno (EPERM = Yama denied,
 * EACCES = wrong UID, ESRCH = pid gone, etc.). */
int inject_attach(struct inject_session *s, pid_t pid);

/* Restore saved regs (if applicable), PTRACE_DETACH. Idempotent. */
void inject_detach(struct inject_session *s);

/* Resolve setenv + dlopen + (optionally) dlerror in target's libc.
 * Locates the syscall_pc by scanning libc for the arch's syscall
 * instruction. Returns 0 on success, -1 if any required symbol is
 * missing (dlerror is optional). */
int inject_resolve_symbols(struct inject_session *s);

/* Allocate `len` bytes (rounded up to a page) in the target via remote
 * mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,
 * -1, 0). Stores the result in s->scratch + s->scratch_len. Returns 0
 * on success, -1 on remote mmap failure.
 *
 * We deliberately DON'T request PROT_EXEC here -- the scratch page only
 * needs to be RW (it holds env strings, the libcov path, etc.). The
 * procmem variant uses a separate RWX allocation for its shellcode. */
int inject_alloc_scratch(struct inject_session *s, size_t len);

/* Write `str` (NUL-terminated) plus its trailing NUL into the scratch
 * buffer starting at *cursor. Advances *cursor past the NUL. Returns
 * the absolute target address at which `str` was placed, or 0 if the
 * scratch is too small. */
uintptr_t inject_stage_string(struct inject_session *s, size_t *cursor,
                              const char *str);

/* Run `func(args[0..n_args-1])` in the target via the trap-on-return
 * mechanism. n_args is 0..6.
 *
 * On success, writes the function's return value to *retval (if non-
 * NULL) and returns 0. On failure (target died, ptrace error, or the
 * stop happened for a signal other than SIGSEGV-at-trap_pc), returns
 * -1 and sets errno. */
int inject_call(struct inject_session *s, uintptr_t func,
                const uintptr_t *args, int n_args, uintptr_t *retval);

/* High-level: setenv(key, val, 1) in target. Returns 0 on success
 * (whether the env was newly set or already present), -1 on remote
 * call failure or remote setenv returning -1. */
int inject_setenv(struct inject_session *s, const char *key, const char *val);

/* High-level: dlopen(libpath, flags) in target. *out_handle gets the
 * dlopen handle (0 means dlopen returned NULL -- failure). Returns 0
 * iff the remote call mechanism succeeded; the caller checks
 * *out_handle for dlopen-level success. */
int inject_dlopen(struct inject_session *s, const char *libpath,
                  int flags, uintptr_t *out_handle);

/* High-level: dlerror() in target. Writes the error string into `buf`
 * (up to buflen-1 chars + NUL). Returns 0 on success, -1 if dlerror
 * isn't resolved or the call mechanism failed. */
int inject_dlerror(struct inject_session *s, char *buf, size_t buflen);

#endif /* INJECT_COMMON_H */
