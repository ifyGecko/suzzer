/*
 * core_bm.c -- freestanding baremetal coverage core.
 *
 * The OS-neutral coverage logic for a baremetal/RTOS target, assembled from
 * the SAME shared pieces the Linux build uses -- sink.h (the edge-emit math),
 * arch.h / arch_mips.c (ISA decode + marker emulation), tunables.h (coverage
 * model + map sizing), patchlist_format.h (the LCV3 wire format) -- plus the
 * plat.h primitives. It provides what the Linux side gets from libcov.c +
 * sink_shm.c + patch_st.c + config.c, but with no libc, no files, no shm:
 *
 *   - the sink globals + sink_init over a free-RAM region (plat_map_region);
 *   - an LCV3 parser that reads a patch list already resident in memory
 *     (baked into the blob by the integrator), module bases via
 *     plat_module_base;
 *   - a patch table + bsearch lookup + arm/disarm via plat_code_*;
 *   - the trap dispatcher the exception-vector stub calls;
 *   - libcov_init(), called once after the blob is loaded.
 *
 * Boundaries/ring/multi-threading are Linux-only features and are not part of
 * the baremetal core (every site uses the disarm+resume / leapfrog path).
 */
#include "plat.h"
#include "arch.h"
#include "sink.h"
#include "tunables.h"
#include "patchlist_format.h"

/* freestanding libc shims provided by plat_baremetal_mips.c */
void *memcpy(void *, const void *, size_t);
int   memcmp(const void *, const void *, size_t);

/* ---- sink globals (this is the baremetal "region brick"; exactly one of
 * sink_shm.c / core_bm.c is linked, like one arch_<x>.c). The emit body in
 * sink.h reads these. ---- */
void    *libcov_shm_base     = 0;
size_t   libcov_shm_size     = 0;
int      libcov_shm_attached = 0;
uint8_t *libcov_bitmap       = 0;
uint32_t libcov_map_size     = LIBCOV_MAP_SIZE;
uint32_t libcov_map_mask     = LIBCOV_MAP_MASK;
#if LIBCOV_NGRAM_ROTATE
uint8_t  libcov_map_bits = LIBCOV_MAP_SIZE_POW2;
uint8_t  libcov_ngram_rot_r[LIBCOV_NGRAM_WIN];
static void compute_ngram_rot(unsigned bits) {
    unsigned step = (bits - 1) / LIBCOV_NGRAM_WIN;
    if (step == 0) step = 1;
    for (unsigned j = 0; j < LIBCOV_NGRAM_WIN; j++) {
        unsigned r = 1 + j * step;
        if (r >= bits) r = 1 + (r % (bits - 1));
        libcov_ngram_rot_r[j] = (uint8_t)r;
    }
}
#endif
uintptr_t libcov_module_bases[LIBCOV_MAX_MODULES] = {0};
uint32_t  libcov_prev_loc[LIBCOV_NGRAM_WIN] = {0};

/* ---- little-endian readers (LCV3 is LE on the wire, target may be BE) ---- */
static uint32_t rd_u32le(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t rd_u64le(const unsigned char *p) {
    return (uint64_t)rd_u32le(p) | ((uint64_t)rd_u32le(p + 4) << 32);
}

/* ---- map sizing (mirrors libcov.c compute_map_size for the site model) ---- */
static size_t next_pow2(size_t v) { size_t p = 1; while (p < v) p <<= 1; return p; }
static size_t compute_map_size(size_t n_sites) {
#if LIBCOV_COVERAGE_MODEL_SITE
    if (n_sites == 0) n_sites = 1;
    size_t floor_min  = (size_t)1u << LIBCOV_MAP_MIN_POW2;
    size_t cap        = (size_t)1u << LIBCOV_MAP_MAX_POW2;
    size_t hard_floor = next_pow2(n_sites);
    size_t sz         = next_pow2(n_sites * (size_t)LIBCOV_MAP_FUDGE);
    if (sz > cap)        sz = cap;
    if (sz < floor_min)  sz = floor_min;
    if (sz < hard_floor) sz = hard_floor;
    return sz;
#else
    (void)n_sites;
    return (size_t)1u << LIBCOV_MAP_SIZE_POW2;
#endif
}

/* ---- patch table (sorted by addr; built once at init) ---- */
static struct patch_entry *g_table = 0;
static size_t              g_count = 0;

struct patch_entry *config_table_mut(size_t *n) { if (n) *n = g_count; return g_table; }
const struct patch_entry *config_table(size_t *n) { if (n) *n = g_count; return g_table; }

static void sort_by_addr(struct patch_entry *t, size_t n) {
    for (size_t i = 1; i < n; i++) {           /* insertion sort (no libc qsort) */
        struct patch_entry key = t[i];
        size_t j = i;
        while (j > 0 && t[j - 1].addr > key.addr) { t[j] = t[j - 1]; j--; }
        t[j] = key;
    }
}

/* Parse an LCV3 image already resident in memory. Returns 0 on success. */
static int config_load_mem(const unsigned char *b, size_t size) {
    if (size < sizeof(struct patchlist_header_v3)) return -1;
    if (b[0] != 'L' || b[1] != 'C' || b[2] != 'V' || b[3] != '3') return -1;
    if (rd_u32le(b + 4) != LIBCOV_VERSION) return -1;
    uint32_t count          = rd_u32le(b + 8);
    uint8_t  module_count   = b[14];
    uint32_t modules_offset = rd_u32le(b + 16);
    uint32_t modules_size   = rd_u32le(b + 20);
    size_t   recs_off       = sizeof(struct patchlist_header_v3);
    if (module_count < 1) return -1;
    if (count > (size - recs_off) / sizeof(struct patchlist_record)) return -1;
    if (modules_size == 0 || (size_t)modules_offset > size ||
        (size_t)modules_size > size - modules_offset) return -1;

    for (size_t i = 0; i < LIBCOV_MAX_MODULES; i++) libcov_module_bases[i] = 0;
    /* One base per module. plat_module_base ignores the name on a baremetal
     * target (single compiled-in module), but we still walk the table so a
     * multi-module list is accepted. */
    const char *names = (const char *)b + modules_offset;
    size_t name_pos = 0;
    for (unsigned m = 0; m < module_count; m++) {
        const char *name = (name_pos < modules_size) ? names + name_pos : "";
        size_t nl = 0; while (name[nl]) nl++;
        name_pos += nl + 1;
        libcov_module_bases[m] = plat_module_base(name);
        if (!libcov_module_bases[m]) return -1;
    }

    g_count = count;
    g_table = (struct patch_entry *)plat_scratch_alloc(g_count * sizeof(*g_table));
    if (!g_table && g_count) return -1;

    const unsigned char *rec = b + recs_off;
    for (size_t i = 0; i < g_count; i++) {
        const unsigned char *r = rec + i * sizeof(struct patchlist_record);
        uint64_t off  = rd_u64le(r);
        uint8_t  len  = r[8];
        uint8_t  midx = r[9];
        if (midx >= module_count) { g_table = 0; g_count = 0; return -1; }
        g_table[i].addr       = libcov_module_bases[midx] + (uintptr_t)off;
        g_table[i].len        = len;
        g_table[i].module_idx = midx;
        memcpy(g_table[i].orig, r + 10, LIBCOV_PATCH_ORIG_MAX);
        g_table[i].patched = g_table[i].lock = g_table[i].marker = 0;
        g_table[i].touched = g_table[i].emulate = 0;
        g_table[i].site_id = (uint32_t)i;
    }
    sort_by_addr(g_table, g_count);
    return 0;
}

/* ---- sink init over a free-RAM region ---- */
static int sink_init_bm(size_t map_size) {
    int attached = 0;
    libcov_bitmap = (uint8_t *)plat_map_region("libcov-cov", map_size, &attached);
    if (!libcov_bitmap) return -1;
    libcov_shm_base = libcov_bitmap;
    libcov_shm_size = map_size;
    libcov_shm_attached = attached;
    libcov_map_size = (uint32_t)map_size;
    libcov_map_mask = (uint32_t)(map_size - 1);
#if LIBCOV_NGRAM_ROTATE
    { unsigned bits = 0, s = (unsigned)map_size; while (s > 1) { s >>= 1; bits++; }
      libcov_map_bits = (uint8_t)bits; compute_ngram_rot(bits); }
#endif
    for (size_t i = 0; i < map_size; i++) libcov_bitmap[i] = 0;
    for (int j = 0; j < LIBCOV_NGRAM_WIN; j++) libcov_prev_loc[j] = 0;
    return 0;
}

/* ---- patch arm/disarm via plat_code_* ---- */
static int validate(const struct patch_entry *e) {
    if (e->len < libcov_min_patch_len || e->len > libcov_max_patch_len) return -1;
    return memcmp((const void *)e->addr, e->orig, e->len) == 0 ? 0 : -1;
}
static int bm_arm(struct patch_entry *e) {
    plat_code_write(e->addr, libcov_arch_illegal_bytes(e->len), e->len);
    plat_code_sync(e->addr, e->len);
    e->patched = 1;
    return 0;
}
static int bm_disarm(struct patch_entry *e) {
    plat_code_write(e->addr, e->orig, e->len);
    plat_code_sync(e->addr, e->len);
    e->patched = 0;
    return 0;
}
static size_t bm_arm_all(void) {
    size_t armed = 0;
    for (size_t i = 0; i < g_count; i++) {
        struct patch_entry *e = &g_table[i];
        if (!plat_range_mapped(libcov_module_bases[e->module_idx], e->addr, e->len))
            continue;
        if (validate(e) != 0) continue;
        if (bm_arm(e) == 0) armed++;
    }
    return armed;
}

/* ---- signal-safe lookup: direct-mapped PC cache + bsearch ---- */
#define BM_PC_CACHE_SIZE 16
#define BM_PC_CACHE_MASK (BM_PC_CACHE_SIZE - 1)
static struct { uintptr_t pc; struct patch_entry *e; } g_pc_cache[BM_PC_CACHE_SIZE];
static unsigned pc_cache_idx(uintptr_t pc) {
    return (unsigned)((pc * 0x9E3779B97F4A7C15ULL) >> 60) & BM_PC_CACHE_MASK;
}
static struct patch_entry *bm_lookup(uintptr_t addr) {
    unsigned idx = pc_cache_idx(addr);
    if (g_pc_cache[idx].pc == addr && g_pc_cache[idx].e) return g_pc_cache[idx].e;
    size_t lo = 0, hi = g_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_table[mid].addr == addr) {
            g_pc_cache[idx].pc = addr; g_pc_cache[idx].e = &g_table[mid];
            return &g_table[mid];
        }
        if (g_table[mid].addr < addr) lo = mid + 1; else hi = mid;
    }
    return 0;
}

/* ---- trap dispatcher (mirrors handler_st trap_body, leapfrog, no boundary) --
 * Called by the exception-vector stub with a frame it filled from the trap. */
static int g_leapfrog = 1;
static struct patch_entry *g_last = 0;

void libcov_trap_dispatch(libcov_frame *f) {
    uintptr_t pc = libcov_arch_pc_from_frame(f);
    struct patch_entry *e = bm_lookup(pc);
    if (!e || !e->patched) { plat_trap_chain(f); return; }

    sink_emit(pc, e->module_idx, e->site_id);

    if (e->emulate) {
        if (g_leapfrog && g_last && !g_last->marker && !g_last->patched) bm_arm(g_last);
        g_last = 0;
        libcov_arch_emulate(f, pc, e->orig, e->len);
        return;
    }
    bm_disarm(e);
    if (g_leapfrog) {
        if (g_last && g_last != e && !g_last->marker && !g_last->patched) bm_arm(g_last);
        g_last = e;
    }
}

/* Reset coverage for a fresh run: zero the bitmap + N-gram window, forget the
 * leapfrog predecessor, and re-arm every site (sites disarmed by the previous
 * run validate clean and re-arm; still-armed sites stay armed). Lets an
 * integrator measure one input, reset, and measure another in the same boot. */
void libcov_bm_reset(void) {
    if (libcov_bitmap)
        for (uint32_t i = 0; i < libcov_map_size; i++) libcov_bitmap[i] = 0;
    for (int j = 0; j < LIBCOV_NGRAM_WIN; j++) libcov_prev_loc[j] = 0;
    g_last = 0;
    bm_arm_all();
}

/* ---- init ---- */
static const char bm_banner[] = "libcov: baremetal core init\n";

int libcov_init_mem(const void *patchlist, size_t len) {
    plat_log_init();
    plat_log_write(bm_banner, sizeof bm_banner - 1);
    if (config_load_mem((const unsigned char *)patchlist, len) != 0) {
        static const char m[] = "libcov: config_load_mem failed\n";
        plat_log_write(m, sizeof m - 1);
        return -1;
    }
    size_t n = 0; config_table(&n);
    if (sink_init_bm(compute_map_size(n)) != 0) {
        static const char m[] = "libcov: sink_init failed\n";
        plat_log_write(m, sizeof m - 1);
        return -1;
    }
    size_t armed = bm_arm_all();
    (void)armed;
    if (plat_trap_install() != 0) {
        static const char m[] = "libcov: WARN trap vector not installed (stub)\n";
        plat_log_write(m, sizeof m - 1);
        /* not fatal here: the integrator may install the vector separately */
    }
    return 0;
}

/* Convenience entry: the integrator bakes the LCV3 image in and exposes it
 * via these weak symbols; libcov_init() wires them up. */
extern const unsigned char libcov_bm_patchlist[] __attribute__((weak));
extern const unsigned long libcov_bm_patchlist_len __attribute__((weak));

int libcov_init(void) {
    if (!libcov_bm_patchlist || !(&libcov_bm_patchlist_len)) {
        static const char m[] = "libcov: no baked patchlist\n";
        plat_log_write(m, sizeof m - 1);
        return -1;
    }
    return libcov_init_mem(libcov_bm_patchlist, (size_t)libcov_bm_patchlist_len);
}
