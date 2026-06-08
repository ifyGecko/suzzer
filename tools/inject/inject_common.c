/*
 * inject_common.c -- shared logic for the ptrace + procmem injector mains.
 *
 * Contents:
 *
 *   1. /proc/<pid>/maps loader and lookup helpers.
 *   2. ELF parser for resolving symbols out of a target's libc / libdl
 *      on the host filesystem (faster than going through /proc/PID/mem).
 *   3. Remote-memory read/write via process_vm_readv / process_vm_writev.
 *   4. Symbol-resolution wrappers including the dlopen fallback chain.
 *   5. inject_session lifecycle: attach / detach / resolve / scratch.
 *   6. Remote function-call primitive using the trap-on-return convention
 *      (the heart of the ptrace injector).
 *   7. High-level setenv / dlopen / dlerror wrappers.
 *
 * Note on style: the file is deliberately laid out top-to-bottom in order
 * of increasing abstraction. /proc and ELF helpers come first; the
 * inject_session lifecycle and high-level wrappers come last. Cross-
 * references are forward-declared at the top.
 *
 * All ptrace operations are wrapped in helpers that surface errno via
 * LOG_ERR + return -1. Callers check return values and bail.
 */

/* _GNU_SOURCE is set by the Makefile (-D_GNU_SOURCE); redefining here
 * would warn. */
#include "inject_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <fnmatch.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <signal.h>

/* <elf.h> (pulled in by arch_inject.h) defines all the Elf32 and Elf64
 * types and DT_*, PT_*, ST_* macros we use. We DO NOT include
 * <linux/elf.h> because it redefines the same types incompatibly with
 * glibc's userspace <elf.h>. NT_PRSTATUS is the one constant
 * historically outside <elf.h>; recent glibc puts it in <elf.h>, but
 * for portability across glibc, musl, uClibc-ng we fall back to a
 * hard-coded value (the kernel ABI fixes it at 1). */
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

/* Override-able verbosity; declared extern in inject_common.h. */
int inject_verbose = 0;

/* ================================================================ *
 *                      /proc/<pid>/maps loader                     *
 * ================================================================ */

static int
maps_push(struct proc_map_table *t, const struct proc_map *m)
{
    if (t->n == t->cap) {
        size_t newcap = t->cap ? t->cap * 2 : 64;
        struct proc_map *p = realloc(t->m, newcap * sizeof(*p));
        if (!p) return -1;
        t->m = p;
        t->cap = newcap;
    }
    t->m[t->n++] = *m;
    return 0;
}

int
proc_maps_load(pid_t pid, struct proc_map_table *t)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) { LOG_ERR("open %s: %s", path, strerror(errno)); return -1; }

    t->m = NULL; t->n = 0; t->cap = 0;

    char line[PATH_MAX + 256];
    while (fgets(line, sizeof line, f)) {
        struct proc_map m;
        memset(&m, 0, sizeof m);

        /* Lines look like:
         *   7f0e3a000000-7f0e3a200000 r-xp 00000000 fd:01 12345 /usr/lib/x86_64-linux-gnu/libc.so.6
         * Optional trailing pathname; anonymous mappings have none. */
        unsigned long start, end, off, ino;
        unsigned dev_major, dev_minor;
        char perms[5] = {0};
        int  pathstart = 0;
        int  matched = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %n",
                              &start, &end, perms, &off,
                              &dev_major, &dev_minor, &ino, &pathstart);
        if (matched < 7) continue;       /* malformed line; skip */
        m.start = (uintptr_t)start;
        m.end   = (uintptr_t)end;
        m.file_off = (uintptr_t)off;
        memcpy(m.perms, perms, 4); m.perms[4] = 0;

        if (pathstart > 0 && (size_t)pathstart < strlen(line)) {
            const char *p = line + pathstart;
            while (*p == ' ' || *p == '\t') p++;
            size_t L = strlen(p);
            while (L && (p[L - 1] == '\n' || p[L - 1] == '\r')) L--;
            if (L >= sizeof m.path) L = sizeof m.path - 1;
            memcpy(m.path, p, L); m.path[L] = 0;
        }

        if (maps_push(t, &m) < 0) {
            LOG_ERR("oom while loading maps");
            fclose(f);
            proc_maps_free(t);
            return -1;
        }
    }
    fclose(f);
    LOG_DBG("loaded %zu maps for pid %d", t->n, (int)pid);
    return 0;
}

void
proc_maps_free(struct proc_map_table *t)
{
    free(t->m);
    t->m = NULL; t->n = 0; t->cap = 0;
}

static const char *
basename_of(const char *p)
{
    const char *b = strrchr(p, '/');
    return b ? b + 1 : p;
}

const struct proc_map *
proc_maps_find_lib(const struct proc_map_table *t, const char *basename_glob)
{
    /* Prefer the executable mapping (has 'x' in perms) when multiple
     * mappings of the same library exist (.text + .data + .bss). */
    for (size_t i = 0; i < t->n; i++) {
        const struct proc_map *m = &t->m[i];
        if (!m->path[0]) continue;
        if (m->perms[2] != 'x') continue;        /* skip non-exec */
        if (fnmatch(basename_glob, basename_of(m->path), 0) == 0)
            return m;
    }
    /* Fall back to any mapping if the executable one isn't there. */
    for (size_t i = 0; i < t->n; i++) {
        const struct proc_map *m = &t->m[i];
        if (!m->path[0]) continue;
        if (fnmatch(basename_glob, basename_of(m->path), 0) == 0)
            return m;
    }
    return NULL;
}

int
proc_maps_addr_mapped(const struct proc_map_table *t, uintptr_t addr)
{
    for (size_t i = 0; i < t->n; i++) {
        if (addr >= t->m[i].start && addr < t->m[i].end) return 1;
    }
    return 0;
}

uintptr_t
inject_pick_trap_pc(const struct proc_map_table *t)
{
    uintptr_t a = INJECT_TRAP_PC_DEFAULT;
    for (int i = 0; i < 1024; i++) {
        if (!proc_maps_addr_mapped(t, a)) return a;
        a -= 0x1000;
        if (a < 0x10000) break;  /* don't go into the kernel-reserved low pages */
    }
    LOG_ERR("inject_pick_trap_pc: no unmapped page found in target");
    return 0;
}

/* ================================================================ *
 *               ELF parsing (in-host filesystem)                  *
 * ================================================================ */

/* We support both ELF32 and ELF64. The lookup walks DT_SYMTAB linearly
 * (no hash table), which costs O(N) where N is the number of dynsyms
 * (~5000 for libc). Negligible for the few lookups we do. */

struct elf_view {
    uint8_t *base;
    size_t   len;
    int      class;       /* ELFCLASS32 or ELFCLASS64 */
    int      machine;     /* e_machine */
    int      endian;      /* ELFDATA2LSB / 2MSB */
};

static int
elf_open(const char *path, struct elf_view *v)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG_DBG("elf_open %s: %s", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) {
        LOG_DBG("mmap %s: %s", path, strerror(errno));
        return -1;
    }
    v->base = (uint8_t *)m;
    v->len  = (size_t)st.st_size;
    if (v->len < EI_NIDENT || memcmp(v->base, ELFMAG, SELFMAG) != 0) {
        munmap(v->base, v->len);
        return -1;
    }
    v->class   = v->base[EI_CLASS];
    v->endian  = v->base[EI_DATA];
    /* Native endian assumed (we don't run on BE injectors for now;
     * the BE-target case is for cross-compiled injectors running on
     * BE hardware). Most production injection use is little-endian. */
    if (v->class == ELFCLASS64) {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)v->base;
        v->machine = eh->e_machine;
    } else if (v->class == ELFCLASS32) {
        Elf32_Ehdr *eh = (Elf32_Ehdr *)v->base;
        v->machine = eh->e_machine;
    } else {
        munmap(v->base, v->len);
        return -1;
    }
    return 0;
}

static void
elf_close(struct elf_view *v)
{
    if (v->base) munmap(v->base, v->len);
    v->base = NULL; v->len = 0;
}

/* Find the first PT_LOAD; its p_vaddr - p_offset is the bias relative
 * to which the runtime mapping's start is computed. */
static int
elf_first_load_offset(const struct elf_view *v,
                      uintptr_t *out_vaddr, uintptr_t *out_offset)
{
    if (v->class == ELFCLASS64) {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)v->base;
        Elf64_Phdr *ph = (Elf64_Phdr *)(v->base + eh->e_phoff);
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type == PT_LOAD) {
                *out_vaddr  = (uintptr_t)ph[i].p_vaddr;
                *out_offset = (uintptr_t)ph[i].p_offset;
                return 0;
            }
        }
    } else {
        Elf32_Ehdr *eh = (Elf32_Ehdr *)v->base;
        Elf32_Phdr *ph = (Elf32_Phdr *)(v->base + eh->e_phoff);
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type == PT_LOAD) {
                *out_vaddr  = (uintptr_t)ph[i].p_vaddr;
                *out_offset = (uintptr_t)ph[i].p_offset;
                return 0;
            }
        }
    }
    return -1;
}

int
proc_maps_load_base(const struct proc_map *map, uintptr_t *out_base)
{
    struct elf_view v = {0};
    if (elf_open(map->path, &v) < 0) {
        /* Try the /proc/<self>/root-style path */
        return -1;
    }
    uintptr_t first_vaddr = 0, first_off = 0;
    int rc = elf_first_load_offset(&v, &first_vaddr, &first_off);
    elf_close(&v);
    if (rc < 0) return -1;

    /* Runtime address of the first byte of the first PT_LOAD =
     *   map->start - (map->file_off - first_off)
     * If map is the first PT_LOAD itself (file_off==first_off), this
     * is just map->start. */
    uintptr_t adj = (uintptr_t)((long)map->file_off - (long)first_off);
    *out_base = map->start - adj - first_vaddr;
    return 0;
}

/* ---- dynsym walk ---------------------------------------------------- */

/* Locate the dynamic table (PT_DYNAMIC), then walk it to find the
 * symbol table base, string table, and the .dynstr / .dynsym /
 * .gnu.hash addresses. We linear-scan symbols by name. */
struct elf_dyninfo {
    uint8_t *symtab;
    size_t   syment;
    size_t   symcnt;
    const char *strtab;
    size_t   strsz;
    /* Versioning */
    uint16_t *versym;
    uint8_t  *verdef;
    uint8_t  *verneed;
};

/* Compute symcnt from DT_GNU_HASH or DT_HASH. If GNU_HASH is present,
 * we walk its buckets to find the highest symbol index in use. */
static size_t
elf_compute_symcnt_gnu_hash(const uint8_t *gnu_hash)
{
    /* GNU hash layout:
     *   uint32_t nbuckets;
     *   uint32_t symbias;
     *   uint32_t bloom_size;        // in words
     *   uint32_t bloom_shift;
     *   <bloom_size> ELF_xword bloom[];
     *   uint32_t buckets[nbuckets];
     *   uint32_t chain[];           // ends when chain[i] & 1
     */
    const uint32_t *h = (const uint32_t *)gnu_hash;
    uint32_t nbuckets   = h[0];
    uint32_t symbias    = h[1];
    uint32_t bloom_size = h[2];
    /* Skip header + bloom array (size depends on ELFCLASS; we assume
     * ELFCLASS64 here -- the 32-bit case is checked in the caller).
     * For accuracy across both classes we'd need to know the class;
     * but symcnt computation works in both because we only walk the
     * buckets after the bloom. */
    const uint32_t *buckets = h + 4 + bloom_size * 2;  /* ELFCLASS64 */
    const uint32_t *chain   = buckets + nbuckets;

    uint32_t maxidx = symbias;
    for (uint32_t i = 0; i < nbuckets; i++) {
        if (buckets[i] > maxidx) maxidx = buckets[i];
    }
    /* Walk the chain from maxidx until we hit a terminator (low bit set). */
    if (maxidx >= symbias) {
        const uint32_t *c = chain + (maxidx - symbias);
        while (!(*c & 1)) { c++; maxidx++; }
    }
    return (size_t)(maxidx + 1);
}

static int
elf_load_dyninfo(const struct elf_view *v, struct elf_dyninfo *d)
{
    memset(d, 0, sizeof *d);

    uintptr_t first_vaddr = 0, first_off = 0;
    if (elf_first_load_offset(v, &first_vaddr, &first_off) < 0) return -1;

    if (v->class == ELFCLASS64) {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)v->base;
        Elf64_Phdr *ph = (Elf64_Phdr *)(v->base + eh->e_phoff);

        Elf64_Dyn *dyn = NULL;
        size_t     dyn_count = 0;
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type == PT_DYNAMIC) {
                dyn = (Elf64_Dyn *)(v->base + ph[i].p_offset);
                dyn_count = ph[i].p_filesz / sizeof(Elf64_Dyn);
                break;
            }
        }
        if (!dyn) return -1;

        uint64_t symtab_va = 0, strtab_va = 0, gnu_hash_va = 0, hash_va = 0;
        uint64_t versym_va = 0, verdef_va = 0, verneed_va = 0;
        for (size_t i = 0; i < dyn_count && dyn[i].d_tag != DT_NULL; i++) {
            switch (dyn[i].d_tag) {
            case DT_SYMTAB:   symtab_va    = dyn[i].d_un.d_ptr; break;
            case DT_SYMENT:   d->syment    = dyn[i].d_un.d_val; break;
            case DT_STRTAB:   strtab_va    = dyn[i].d_un.d_ptr; break;
            case DT_STRSZ:    d->strsz     = dyn[i].d_un.d_val; break;
            case DT_GNU_HASH: gnu_hash_va  = dyn[i].d_un.d_ptr; break;
            case DT_HASH:     hash_va      = dyn[i].d_un.d_ptr; break;
            case DT_VERSYM:   versym_va    = dyn[i].d_un.d_ptr; break;
            case DT_VERDEF:   verdef_va    = dyn[i].d_un.d_ptr; break;
            case DT_VERNEED:  verneed_va   = dyn[i].d_un.d_ptr; break;
            }
        }
        if (!symtab_va || !strtab_va) return -1;
        if (!d->syment) d->syment = sizeof(Elf64_Sym);

        /* Translate vaddrs to file offsets via first PT_LOAD bias. */
        #define VA2FO(va) ((va) - first_vaddr + first_off)
        d->symtab = v->base + VA2FO(symtab_va);
        d->strtab = (const char *)v->base + VA2FO(strtab_va);

        /* symcnt: prefer GNU_HASH, fall back to DT_HASH. */
        if (gnu_hash_va) {
            d->symcnt = elf_compute_symcnt_gnu_hash(v->base + VA2FO(gnu_hash_va));
        } else if (hash_va) {
            /* DT_HASH: nbuckets,nchains,buckets[],chains[] -- nchains == symcnt */
            uint32_t *h = (uint32_t *)(v->base + VA2FO(hash_va));
            d->symcnt = h[1];
        } else {
            /* No hash at all -- can't reliably know symcnt. Be conservative
             * and walk until we hit an obviously-empty entry. */
            d->symcnt = 0;
        }

        if (versym_va)  d->versym  = (uint16_t *)(v->base + VA2FO(versym_va));
        if (verdef_va)  d->verdef  = v->base + VA2FO(verdef_va);
        if (verneed_va) d->verneed = v->base + VA2FO(verneed_va);
        #undef VA2FO
        return 0;
    } else {  /* ELFCLASS32 */
        Elf32_Ehdr *eh = (Elf32_Ehdr *)v->base;
        Elf32_Phdr *ph = (Elf32_Phdr *)(v->base + eh->e_phoff);

        Elf32_Dyn *dyn = NULL;
        size_t     dyn_count = 0;
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type == PT_DYNAMIC) {
                dyn = (Elf32_Dyn *)(v->base + ph[i].p_offset);
                dyn_count = ph[i].p_filesz / sizeof(Elf32_Dyn);
                break;
            }
        }
        if (!dyn) return -1;

        uint32_t symtab_va = 0, strtab_va = 0, hash_va = 0;
        for (size_t i = 0; i < dyn_count && dyn[i].d_tag != DT_NULL; i++) {
            switch (dyn[i].d_tag) {
            case DT_SYMTAB: symtab_va = dyn[i].d_un.d_ptr; break;
            case DT_SYMENT: d->syment = dyn[i].d_un.d_val; break;
            case DT_STRTAB: strtab_va = dyn[i].d_un.d_ptr; break;
            case DT_STRSZ:  d->strsz  = dyn[i].d_un.d_val; break;
            case DT_HASH:   hash_va   = dyn[i].d_un.d_ptr; break;
            }
        }
        if (!symtab_va || !strtab_va) return -1;
        if (!d->syment) d->syment = sizeof(Elf32_Sym);

        #define VA2FO32(va) ((va) - (uint32_t)first_vaddr + (uint32_t)first_off)
        d->symtab = v->base + VA2FO32(symtab_va);
        d->strtab = (const char *)v->base + VA2FO32(strtab_va);
        if (hash_va) {
            uint32_t *h = (uint32_t *)(v->base + VA2FO32(hash_va));
            d->symcnt = h[1];
        } else d->symcnt = 0;
        #undef VA2FO32
        return 0;
    }
}

int
elf_lookup_symbol(const char *lib_path, const char *name, uintptr_t *out_vaddr)
{
    struct elf_view v = {0};
    if (elf_open(lib_path, &v) < 0) return -1;

    struct elf_dyninfo d;
    if (elf_load_dyninfo(&v, &d) < 0) { elf_close(&v); return -1; }

    /* If symcnt is 0 (no hash present) we walk until we see a sentinel
     * with all-zero fields. This is safe because DT_SYMTAB always starts
     * with one zero entry by convention. */
    size_t limit = d.symcnt ? d.symcnt : 100000;

    uintptr_t best_vaddr = 0;
    int       best_found = 0;

    if (v.class == ELFCLASS64) {
        for (size_t i = 1; i < limit; i++) {
            Elf64_Sym *s = (Elf64_Sym *)(d.symtab + i * d.syment);
            if (!d.symcnt && s->st_name == 0 && s->st_value == 0 && s->st_size == 0)
                break;
            if (s->st_name >= d.strsz) continue;
            const char *n = d.strtab + s->st_name;
            if (strcmp(n, name) != 0) continue;
            /* Skip undefined / weak-undef refs */
            if (s->st_shndx == SHN_UNDEF) continue;
            /* Prefer FUNC/IFUNC over OBJECT. Last definition wins
             * (matches the dynamic linker's "highest version" behavior
             * roughly enough for libc.so where symbol versions are
             * sorted increasing). */
            unsigned char st_type = ELF64_ST_TYPE(s->st_info);
            if (st_type != STT_FUNC && st_type != STT_GNU_IFUNC &&
                st_type != STT_OBJECT) continue;
            best_vaddr = (uintptr_t)s->st_value;
            best_found = 1;
        }
    } else {
        for (size_t i = 1; i < limit; i++) {
            Elf32_Sym *s = (Elf32_Sym *)(d.symtab + i * d.syment);
            if (!d.symcnt && s->st_name == 0 && s->st_value == 0 && s->st_size == 0)
                break;
            if (s->st_name >= d.strsz) continue;
            const char *n = d.strtab + s->st_name;
            if (strcmp(n, name) != 0) continue;
            if (s->st_shndx == SHN_UNDEF) continue;
            unsigned char st_type = ELF32_ST_TYPE(s->st_info);
            if (st_type != STT_FUNC && st_type != STT_GNU_IFUNC &&
                st_type != STT_OBJECT) continue;
            best_vaddr = (uintptr_t)s->st_value;
            best_found = 1;
        }
    }

    elf_close(&v);
    if (!best_found) return -1;
    *out_vaddr = best_vaddr;
    return 0;
}

uintptr_t
resolve_lib_symbol(pid_t pid, const struct proc_map_table *t,
                   const char *lib_basename_glob, const char *symbol)
{
    const struct proc_map *m = proc_maps_find_lib(t, lib_basename_glob);
    if (!m) {
        LOG_DBG("no mapping matched %s in target", lib_basename_glob);
        return 0;
    }

    uintptr_t base = 0;
    if (proc_maps_load_base(m, &base) < 0) {
        /* Try /proc/<pid>/root/<path> fallback for chrooted targets.
         * We build the proxy path in a heap allocation sized
         * generously so it never collides with proc_map.path's
         * PATH_MAX limit. */
        size_t need = strlen(m->path) + 64;
        char *proxy = malloc(need);
        if (!proxy) { LOG_ERR("oom"); return 0; }
        snprintf(proxy, need, "/proc/%d/root%s", (int)pid, m->path);
        /* Build a temporary proc_map with the proxy path. We have to
         * memcpy because proc_map.path is a fixed-size array; the
         * proxy may exceed it. If proxy is too long for proc_map.path
         * (rare; would need a libc path > PATH_MAX-64), we fall back
         * to a direct elf_open via the proxy without going through
         * proc_maps_load_base -- not strictly needed because the load
         * base of the original mapping is what we care about anyway,
         * not the file we read it from. */
        struct elf_view ev = {0};
        int ok = (elf_open(proxy, &ev) == 0);
        free(proxy);
        if (!ok) {
            LOG_ERR("can't read ELF for %s (path=%s; chroot fallback failed)",
                    lib_basename_glob, m->path);
            return 0;
        }
        uintptr_t first_vaddr = 0, first_off = 0;
        int rc = elf_first_load_offset(&ev, &first_vaddr, &first_off);
        elf_close(&ev);
        if (rc < 0) {
            LOG_ERR("can't parse ELF for %s", lib_basename_glob);
            return 0;
        }
        uintptr_t adj = (uintptr_t)((long)m->file_off - (long)first_off);
        base = m->start - adj - first_vaddr;
    }

    uintptr_t vaddr = 0;
    if (elf_lookup_symbol(m->path, symbol, &vaddr) < 0) {
        /* chroot fallback path also for symbol lookup */
        char proxy[PATH_MAX + 64];
        snprintf(proxy, sizeof proxy, "/proc/%d/root%s", (int)pid, m->path);
        if (elf_lookup_symbol(proxy, symbol, &vaddr) < 0) {
            LOG_DBG("symbol %s not found in %s", symbol, m->path);
            return 0;
        }
    }
    LOG_DBG("resolved %s in %s: vaddr=0x%lx base=0x%lx runtime=0x%lx",
            symbol, m->path, (unsigned long)vaddr,
            (unsigned long)base, (unsigned long)(base + vaddr));
    return base + vaddr;
}

int
resolve_dlopen(pid_t pid, const struct proc_map_table *t,
               uintptr_t *out_addr, int *out_is_libc_dlopen_mode)
{
    if (out_is_libc_dlopen_mode) *out_is_libc_dlopen_mode = 0;

    /* Try libc.so first. Both glibc 2.34+ and musl export `dlopen` from
     * libc directly. */
    const char *libc_globs[] = { "libc.so*", "libc-*.so*", "libc.musl*", NULL };
    for (const char **g = libc_globs; *g; g++) {
        uintptr_t a = resolve_lib_symbol(pid, t, *g, "dlopen");
        if (a) { *out_addr = a; return 0; }
    }

    /* Fall back to __libc_dlopen_mode (older glibc). */
    for (const char **g = libc_globs; *g; g++) {
        uintptr_t a = resolve_lib_symbol(pid, t, *g, "__libc_dlopen_mode");
        if (a) {
            *out_addr = a;
            if (out_is_libc_dlopen_mode) *out_is_libc_dlopen_mode = 1;
            return 0;
        }
    }

    /* Try libdl.so (only if already loaded). */
    const char *libdl_globs[] = { "libdl.so*", "libdl-*.so*", NULL };
    for (const char **g = libdl_globs; *g; g++) {
        uintptr_t a = resolve_lib_symbol(pid, t, *g, "dlopen");
        if (a) { *out_addr = a; return 0; }
    }

    return -1;
}

int
proc_target_machine(pid_t pid, int *out_machine)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/exe", (int)pid);
    struct elf_view v = {0};
    if (elf_open(path, &v) < 0) return -1;
    *out_machine = v.machine;
    elf_close(&v);
    return 0;
}

const struct inject_arch *
inject_arch_select(int elf_machine)
{
    switch (elf_machine) {
    case EM_X86_64:  return &inject_arch_x86_64;
    case EM_AARCH64: return &inject_arch_aarch64;
    case EM_ARM:     return &inject_arch_arm;
    case EM_MIPS:    return &inject_arch_mips;
    /* MIPS64 also reports EM_MIPS; the caller would need to inspect
     * EI_CLASS to disambiguate. For now we route to mips32 stub; the
     * real implementation (phase 6 follow-up) will fork on class. */
    case EM_PPC:     return &inject_arch_powerpc;
    case EM_PPC64:   return &inject_arch_powerpc64;
    case EM_RISCV:   return &inject_arch_riscv64;
    default:         return NULL;
    }
}

/* ================================================================ *
 *                    target memory I/O wrappers                    *
 * ================================================================ */

int
target_write(pid_t pid, uintptr_t remote, const void *local, size_t len)
{
    struct iovec liov = { .iov_base = (void *)local, .iov_len = len };
    struct iovec riov = { .iov_base = (void *)remote, .iov_len = len };
    ssize_t n = process_vm_writev(pid, &liov, 1, &riov, 1, 0);
    if (n < 0) { LOG_ERR("process_vm_writev: %s", strerror(errno)); return -1; }
    if ((size_t)n != len) {
        LOG_ERR("short write to target: %zd of %zu", n, len);
        return -1;
    }
    return 0;
}

int
target_read(pid_t pid, uintptr_t remote, void *local, size_t len)
{
    struct iovec liov = { .iov_base = local, .iov_len = len };
    struct iovec riov = { .iov_base = (void *)remote, .iov_len = len };
    ssize_t n = process_vm_readv(pid, &liov, 1, &riov, 1, 0);
    if (n < 0) { LOG_ERR("process_vm_readv: %s", strerror(errno)); return -1; }
    if ((size_t)n != len) {
        LOG_ERR("short read from target: %zd of %zu", n, len);
        return -1;
    }
    return 0;
}

/* ================================================================ *
 *                       env_list helpers                           *
 * ================================================================ */

int
env_list_add(struct env_list *e, const char *key, const char *val)
{
    if (e->n >= INJECT_MAX_ENV) {
        LOG_ERR("too many -e entries (max %d)", INJECT_MAX_ENV);
        return -1;
    }
    e->items[e->n].key = key;
    e->items[e->n].val = val;
    e->n++;
    return 0;
}

int
env_list_add_kv(struct env_list *e, const char *kv_string)
{
    /* Split at the first '='. We DO mutate the input string (replacing
     * '=' with NUL) and stash the two halves. The caller's argv
     * storage outlives the env_list, so this is safe. */
    char *eq = strchr(kv_string, '=');
    if (!eq || eq == kv_string) {
        LOG_ERR("-e expects KEY=VAL, got '%s'", kv_string);
        return -1;
    }
    *eq = 0;
    return env_list_add(e, kv_string, eq + 1);
}

/* ================================================================ *
 *                   ptrace helper wrappers                         *
 * ================================================================ */

static int
pt_getregs(pid_t pid, struct inject_regs *regs)
{
    struct iovec iov = { .iov_base = regs->raw, .iov_len = sizeof regs->raw };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        LOG_ERR("PTRACE_GETREGSET: %s", strerror(errno));
        return -1;
    }
    regs->len = iov.iov_len;
    return 0;
}

static int
pt_setregs(pid_t pid, const struct inject_regs *regs)
{
    struct iovec iov = { .iov_base = (void *)regs->raw, .iov_len = regs->len };
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        LOG_ERR("PTRACE_SETREGSET: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* Continue, then wait for any stop. Returns the wait status, or -1
 * on error. */
static int
pt_cont_and_wait(pid_t pid, int sig)
{
    if (ptrace(PTRACE_CONT, pid, 0, (void *)(long)sig) < 0) {
        LOG_ERR("PTRACE_CONT: %s", strerror(errno));
        return -1;
    }
    int status;
    if (waitpid(pid, &status, __WALL) < 0) {
        LOG_ERR("waitpid: %s", strerror(errno));
        return -1;
    }
    return status;
}

static int
pt_singlestep_and_wait(pid_t pid)
{
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
        LOG_ERR("PTRACE_SINGLESTEP: %s", strerror(errno));
        return -1;
    }
    int status;
    if (waitpid(pid, &status, __WALL) < 0) {
        LOG_ERR("waitpid: %s", strerror(errno));
        return -1;
    }
    return status;
}

/* ================================================================ *
 *                  inject_session lifecycle                        *
 * ================================================================ */

int
inject_attach(struct inject_session *s, pid_t pid)
{
    memset(s, 0, sizeof *s);
    s->pid = pid;

    /* Detect arch from /proc/<pid>/exe. */
    int machine = 0;
    if (proc_target_machine(pid, &machine) < 0) {
        LOG_ERR("can't read /proc/%d/exe ELF header", (int)pid);
        return -1;
    }
    s->arch = inject_arch_select(machine);
    if (!s->arch) {
        LOG_ERR("target ELF e_machine=%d is unknown to this injector", machine);
        return -1;
    }
    if (!s->arch->supported) {
        LOG_ERR("target arch '%s' is not yet implemented in this injector "
                "(only x86_64 and aarch64 are full backends; the others are "
                "build-only stubs -- see arch_inject_%s.c)",
                s->arch->name, s->arch->name);
        return -1;
    }
    LOG_INFO("target pid=%d arch=%s", (int)pid, s->arch->name);

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        LOG_ERR("PTRACE_ATTACH pid=%d: %s", (int)pid, strerror(errno));
        if (errno == EPERM) {
            LOG_ERR("hint: check /proc/sys/kernel/yama/ptrace_scope (need 0 or "
                    "CAP_SYS_PTRACE), or that no other tracer is already "
                    "attached (gdb/strace/another injector)");
        }
        return -1;
    }
    int status;
    if (waitpid(pid, &status, __WALL) < 0) {
        LOG_ERR("waitpid after ATTACH: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        LOG_ERR("attach: target didn't stop (status=0x%x)", status);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }
    s->attached = 1;

    if (pt_getregs(pid, &s->regs_saved) < 0) {
        inject_detach(s);
        return -1;
    }
    LOG_INFO("attached; saved regs (%zu bytes); pre-inject pc=0x%lx",
             s->regs_saved.len,
             (unsigned long)s->arch->get_pc(&s->regs_saved));

    if (proc_maps_load(pid, &s->maps) < 0) {
        inject_detach(s);
        return -1;
    }

    s->trap_pc = inject_pick_trap_pc(&s->maps);
    if (!s->trap_pc) {
        inject_detach(s);
        return -1;
    }
    LOG_INFO("trap_pc sentinel = 0x%lx", (unsigned long)s->trap_pc);

    return 0;
}

void
inject_detach(struct inject_session *s)
{
    if (s->attached) {
        /* Restore registers to the saved snapshot so the target resumes
         * exactly where it was. Errors here are non-fatal; we still
         * detach so we don't leave the target stopped. */
        if (pt_setregs(s->pid, &s->regs_saved) < 0) {
            LOG_ERR("inject_detach: register restore failed -- target may "
                    "crash on resume");
        }
        if (ptrace(PTRACE_DETACH, s->pid, 0, 0) < 0) {
            LOG_ERR("PTRACE_DETACH: %s", strerror(errno));
        } else {
            LOG_INFO("detached cleanly from pid %d", (int)s->pid);
        }
        s->attached = 0;
    }
    proc_maps_free(&s->maps);
}

int
inject_resolve_symbols(struct inject_session *s)
{
    s->addr_setenv = resolve_lib_symbol(s->pid, &s->maps, "libc.so*", "setenv");
    if (!s->addr_setenv) {
        s->addr_setenv = resolve_lib_symbol(s->pid, &s->maps, "libc-*.so*", "setenv");
    }
    if (!s->addr_setenv) {
        s->addr_setenv = resolve_lib_symbol(s->pid, &s->maps, "libc.musl*", "setenv");
    }
    if (!s->addr_setenv) {
        LOG_ERR("can't resolve setenv in target libc");
        return -1;
    }
    LOG_INFO("setenv  @ 0x%lx", (unsigned long)s->addr_setenv);

    if (resolve_dlopen(s->pid, &s->maps,
                       &s->addr_dlopen, &s->dlopen_is_libc_mode) < 0) {
        LOG_ERR("can't resolve dlopen / __libc_dlopen_mode in target");
        return -1;
    }
    LOG_INFO("dlopen  @ 0x%lx (%s)",
             (unsigned long)s->addr_dlopen,
             s->dlopen_is_libc_mode ? "__libc_dlopen_mode" : "dlopen");

    /* dlerror is optional; we use it only for diagnostics on dlopen failure. */
    s->addr_dlerror = resolve_lib_symbol(s->pid, &s->maps, "libc.so*", "dlerror");
    if (!s->addr_dlerror) {
        s->addr_dlerror = resolve_lib_symbol(s->pid, &s->maps, "libdl.so*", "dlerror");
    }
    if (s->addr_dlerror) LOG_DBG("dlerror @ 0x%lx", (unsigned long)s->addr_dlerror);
    else LOG_DBG("dlerror not resolved (diagnostic only; not fatal)");

    /* Find a syscall instruction in libc. We read a chunk of the .text
     * mapping via process_vm_readv. 64 KB is enough to find one in any
     * libc -- there are dozens. */
    const struct proc_map *libc = proc_maps_find_lib(&s->maps, "libc.so*");
    if (!libc) libc = proc_maps_find_lib(&s->maps, "libc-*.so*");
    if (!libc) libc = proc_maps_find_lib(&s->maps, "libc.musl*");
    if (!libc) {
        LOG_ERR("no libc mapping in target");
        return -1;
    }
    size_t want = 64 * 1024;
    if (want > libc->end - libc->start) want = libc->end - libc->start;
    uint8_t *buf = malloc(want);
    if (!buf) { LOG_ERR("oom"); return -1; }
    if (target_read(s->pid, libc->start, buf, want) < 0) {
        free(buf);
        return -1;
    }
    long off = s->arch->find_syscall_insn(buf, want);
    free(buf);
    if (off < 0) {
        LOG_ERR("no syscall instruction found in libc's first 64 KB");
        return -1;
    }
    s->syscall_pc = libc->start + (uintptr_t)off;
    LOG_INFO("syscall insn @ 0x%lx (in %s)",
             (unsigned long)s->syscall_pc, basename_of(libc->path));
    return 0;
}

/* ---- remote mmap to allocate the scratch buffer -------------------- */

/* Linux NR_mmap is arch-specific; helper picks per inject_arch.name. */
static long
syscall_nr_mmap(const struct inject_arch *a)
{
    /* Names match libcov's ARCH BACKEND naming. */
    if (!strcmp(a->name, "x86_64"))    return 9;     /* __NR_mmap */
    if (!strcmp(a->name, "aarch64"))   return 222;   /* __NR_mmap (asm-generic) */
    if (!strcmp(a->name, "arm"))       return 192;   /* __NR_mmap2 (page-shift offset!) -- caveat in stub */
    if (!strcmp(a->name, "mips"))      return 4090;  /* __NR_mmap; O32 base 4000+90 */
    if (!strcmp(a->name, "mips64"))    return 5009;  /* __NR_mmap; N64 base 5000+9 */
    if (!strcmp(a->name, "powerpc"))   return 90;
    if (!strcmp(a->name, "powerpc64")) return 90;
    if (!strcmp(a->name, "riscv64"))   return 222;   /* asm-generic */
    return -1;
}

int
inject_alloc_scratch(struct inject_session *s, size_t len)
{
    size_t pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0) pg = 4096;
    size_t want = (len + pg - 1) & ~(pg - 1);

    long nr = syscall_nr_mmap(s->arch);
    if (nr < 0) {
        LOG_ERR("no mmap syscall nr for arch %s", s->arch->name);
        return -1;
    }

    long args[6] = {
        0,                                  /* addr */
        (long)want,                         /* length */
        PROT_READ | PROT_WRITE,             /* prot */
        MAP_PRIVATE | MAP_ANONYMOUS,        /* flags */
        -1,                                 /* fd */
        0,                                  /* offset */
    };

    /* Build the syscall reg set on top of saved regs (we want SP/etc
     * preserved). */
    struct inject_regs regs = s->regs_saved;
    s->arch->setup_syscall(&regs, s->syscall_pc, nr, args, 6);
    if (pt_setregs(s->pid, &regs) < 0) return -1;

    int status = pt_singlestep_and_wait(s->pid);
    if (status < 0) return -1;
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        LOG_ERR("remote mmap: unexpected stop status 0x%x (wanted SIGTRAP)", status);
        return -1;
    }
    if (pt_getregs(s->pid, &regs) < 0) return -1;
    uintptr_t ret = s->arch->get_retval(&regs);
    if ((long)ret < 0 && (long)ret > -4096) {
        LOG_ERR("remote mmap returned errno=%ld", -(long)ret);
        return -1;
    }
    s->scratch     = ret;
    s->scratch_len = want;
    LOG_INFO("scratch @ 0x%lx (%zu bytes)",
             (unsigned long)s->scratch, s->scratch_len);
    return 0;
}

uintptr_t
inject_stage_string(struct inject_session *s, size_t *cursor, const char *str)
{
    size_t len = strlen(str) + 1;
    if (*cursor + len > s->scratch_len) {
        LOG_ERR("scratch overflow staging '%s'", str);
        return 0;
    }
    uintptr_t addr = s->scratch + *cursor;
    if (target_write(s->pid, addr, str, len) < 0) return 0;
    *cursor += len;
    return addr;
}

/* ---- remote function call (the heart of the injector) -------------- */

int
inject_call(struct inject_session *s, uintptr_t func,
            const uintptr_t *args, int n_args, uintptr_t *retval)
{
    /* Always start from the saved snapshot so we don't carry over state
     * from any previous remote call (a previous call may have left
     * registers in unexpected states; using a fresh baseline is robust). */
    struct inject_regs regs = s->regs_saved;
    s->arch->setup_call(&regs, func, s->trap_pc, args, n_args);

    /* Stack-based-return arches (x86_64): setup_call reserved the
     * stack slot; we now write trap_pc into it via process_vm_writev.
     * LR-based arches (aarch64/arm/ppc/riscv): no write needed --
     * trap_pc is already in the LR/return register from setup_call.
     * Branch chosen via the arch vtable, not by name strcmp. */
    if (s->arch->stack_return_addr) {
        uintptr_t sp = s->arch->get_sp(&regs);
        uintptr_t tp = s->trap_pc;
        if (target_write(s->pid, sp, &tp, sizeof tp) < 0) {
            LOG_ERR("inject_call: write trap_pc to stack at 0x%lx failed",
                    (unsigned long)sp);
            return -1;
        }
    }

    if (inject_verbose >= 2) {
        LOG_DBG("inject_call: func=0x%lx trap_pc=0x%lx pc_set=0x%lx",
                (unsigned long)func, (unsigned long)s->trap_pc,
                (unsigned long)s->arch->get_pc(&regs));
        for (int i = 0; i < n_args; i++)
            LOG_DBG("  arg%d=0x%lx", i, (unsigned long)args[i]);
    }
    if (pt_setregs(s->pid, &regs) < 0) return -1;

    int status = pt_cont_and_wait(s->pid, 0);
    if (status < 0) return -1;

    if (!WIFSTOPPED(status)) {
        LOG_ERR("remote call: target didn't stop (status=0x%x); pid may have died",
                status);
        return -1;
    }
    int sig = WSTOPSIG(status);
    if (sig != SIGSEGV) {
        /* Possibly the function we called itself raised a signal, or
         * the target had a pending non-trap signal queued. Log loudly. */
        siginfo_t si;
        if (ptrace(PTRACE_GETSIGINFO, s->pid, 0, &si) == 0) {
            LOG_ERR("remote call: stopped on signal %d (si_code=%d si_addr=%p) "
                    "-- expected SIGSEGV at trap_pc",
                    sig, si.si_code, si.si_addr);
        } else {
            LOG_ERR("remote call: stopped on signal %d (expected SIGSEGV)", sig);
        }
        return -1;
    }

    /* Verify the SIGSEGV was at our trap_pc (sanity check; rules out
     * a genuine SIGSEGV inside the called function). */
    siginfo_t si;
    if (ptrace(PTRACE_GETSIGINFO, s->pid, 0, &si) == 0) {
        if ((uintptr_t)si.si_addr != s->trap_pc) {
            /* Function faulted internally. Dump enough state to help
             * diagnose: actual PC at fault + fault address. The two
             * combined usually pinpoint the issue. */
            struct inject_regs r2 = {0};
            if (pt_getregs(s->pid, &r2) == 0) {
                LOG_ERR("remote call: SIGSEGV at fault_addr=0x%lx pc=0x%lx "
                        "(not trap_pc 0x%lx) -- function faulted internally",
                        (unsigned long)(uintptr_t)si.si_addr,
                        (unsigned long)s->arch->get_pc(&r2),
                        (unsigned long)s->trap_pc);
            } else {
                LOG_ERR("remote call: SIGSEGV at fault_addr=0x%lx (pc unknown) "
                        "-- function faulted internally",
                        (unsigned long)(uintptr_t)si.si_addr);
            }
            return -1;
        }
    }

    if (pt_getregs(s->pid, &regs) < 0) return -1;
    if (retval) *retval = s->arch->get_retval(&regs);

    /* Eat the SIGSEGV: don't re-deliver it on the next PTRACE_CONT.
     * (We do this by passing 0 as the signal to deliver next; the
     * waitpid above already consumed the stop notification.) */
    return 0;
}

int
inject_setenv(struct inject_session *s, const char *key, const char *val)
{
    /* Place env strings in the SECOND half of the scratch buffer so
     * the dlopen path (staged at the low end by inject_dlopen) doesn't
     * collide. We track a single bump cursor as a function-local static
     * because the injector is strictly single-threaded and single-shot
     * (it exits after detach), so reusing across multiple inject_setenv
     * calls in the same process is fine. The cursor is initialised on
     * first call to scratch_len/2; subsequent calls bump it. */
    static size_t env_cursor = 0;
    if (env_cursor == 0) env_cursor = s->scratch_len / 2;

    size_t cur = env_cursor;
    uintptr_t k_addr = inject_stage_string(s, &cur, key);
    if (!k_addr) return -1;
    uintptr_t v_addr = inject_stage_string(s, &cur, val);
    if (!v_addr) return -1;
    env_cursor = cur;

    uintptr_t args[3] = { k_addr, v_addr, 1 /* overwrite */ };
    uintptr_t ret = 0;
    if (inject_call(s, s->addr_setenv, args, 3, &ret) < 0) {
        LOG_ERR("setenv(%s=...) remote-call failed", key);
        return -1;
    }
    if ((long)ret != 0) {
        LOG_ERR("target setenv(%s=...) returned %ld", key, (long)ret);
        return -1;
    }
    LOG_INFO("setenv(%s) = OK", key);
    return 0;
}

int
inject_dlopen(struct inject_session *s, const char *libpath,
              int flags, uintptr_t *out_handle)
{
    size_t cur = 0;       /* low end of scratch; env vars use the high end */
    uintptr_t p_addr = inject_stage_string(s, &cur, libpath);
    if (!p_addr) return -1;

    int mode = flags;
    if (s->dlopen_is_libc_mode) {
        /* __libc_dlopen_mode requires the __RTLD_DLOPEN bit (0x80000000)
         * ORed into the mode flags. Without it, the symbol search
         * scopes are wrong and many .so loads fail. */
        mode |= 0x80000000;
    }

    uintptr_t args[2] = { p_addr, (uintptr_t)mode };
    uintptr_t handle = 0;
    if (inject_call(s, s->addr_dlopen, args, 2, &handle) < 0) {
        LOG_ERR("dlopen remote-call failed");
        return -1;
    }
    *out_handle = handle;
    return 0;
}

int
inject_dlerror(struct inject_session *s, char *buf, size_t buflen)
{
    if (!s->addr_dlerror || buflen == 0) return -1;
    uintptr_t msg_ptr = 0;
    if (inject_call(s, s->addr_dlerror, NULL, 0, &msg_ptr) < 0) return -1;
    if (!msg_ptr) {
        buf[0] = 0;
        return 0;
    }
    /* Read up to buflen-1 bytes from target. We try progressively
     * smaller chunks because we don't know the string length. */
    size_t to_read = buflen - 1;
    if (target_read(s->pid, msg_ptr, buf, to_read) < 0) {
        /* short string: try a one-byte-at-a-time read until NUL */
        size_t i = 0;
        for (; i < buflen - 1; i++) {
            uint8_t b;
            if (target_read(s->pid, msg_ptr + i, &b, 1) < 0) break;
            buf[i] = (char)b;
            if (b == 0) return 0;
        }
        buf[i] = 0;
        return 0;
    }
    buf[buflen - 1] = 0;
    /* Truncate at first NUL */
    for (size_t i = 0; i < buflen; i++) if (buf[i] == 0) return 0;
    buf[buflen - 1] = 0;
    return 0;
}
