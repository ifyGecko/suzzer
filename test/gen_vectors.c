/*
 * gen_vectors.c -- conformance vectors for the coverage bucket formula.
 *
 * Built from src/sink.h itself -- the same sink_emit, sink_set_map_dims and
 * sink_map_size_for libcov runs -- so the vectors cannot drift from the
 * runtime. One binary per coverage scheme: test/gen_vectors.sh compiles
 * this file once for each (model, N, rotate) with
 *   -DLIBCOV_COVERAGE_MODEL_SITE=0|1 -DLIBCOV_NGRAM_N=N -DLIBCOV_NGRAM_ROTATE=0|1
 * and each binary writes, for every map size in MAP_SIZES, one directory
 *
 *   <outdir>/<model>_n<N>_r<R>_<size>/
 *     scheme.json    model, ngram_n, rotate, map_size, derived constants
 *                    and (PC model) the module bases
 *     sequence.bin   the emits, little-endian:
 *                      site model: u32 site_id per emit
 *                      PC model:   u64 pc + u8 module_idx per emit (9 bytes)
 *                    the all-ones record (0xffffffff / 0xff..ff + 0xff) is
 *                    a reset of the N-gram history (an iteration boundary)
 *     expected.bin   the bitmap after the whole sequence, map_size bytes
 *
 * The sequences are fixed (no clock, no host state) and cover repeated
 * sites past the 255 saturation point, self-loops, permutations of the
 * same sites (what rotation tells apart), a history reset mid-sequence,
 * more than one module (PC model) and a long pseudo-random walk.
 *
 * With --map-size-table it instead prints map_size.json: the map size the
 * site-id model picks for a list of site counts (sink_map_size_for), for
 * this binary's N.
 *
 * Needs a 64-bit host (PCs are full 64-bit values here).
 */
#define LIBCOV_THREADING_ST 1
#include "../src/sink.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

_Static_assert(sizeof(uintptr_t) == 8, "gen_vectors needs a 64-bit host");

/* The globals sink.h declares (libcov defines them in sink_shm.c). */
uint32_t  libcov_map_size;
uint32_t  libcov_map_mask;
uint8_t  *libcov_bitmap;
uintptr_t libcov_module_bases[LIBCOV_MAX_MODULES];
uint32_t  libcov_prev_loc[LIBCOV_NGRAM_WIN];
#if LIBCOV_NGRAM_ROTATE
uint8_t   libcov_ngram_rot_r[LIBCOV_NGRAM_WIN];
uint8_t   libcov_map_bits;
#endif

static const uint32_t MAP_SIZES[] = { 4096u, 65536u, 1048576u };

/* PC model: three modules, one of them above 4 GiB. */
#define N_MODULES 3
static const uint64_t MODULE_BASES[N_MODULES] = {
    0x400000ull, 0x7f3a5c000000ull, 0x10000000ull,
};

#define RESET_SITE UINT32_MAX
#define MAX_SITE   4095u          /* every id fits the smallest map */

/* ---- the abstract sequence: site ids and resets ----------------------- */

static uint32_t seq[16384];
static size_t   seq_n;

static void put(uint32_t id) {
    if (seq_n == sizeof seq / sizeof seq[0]) { fprintf(stderr, "seq overflow\n"); exit(1); }
    seq[seq_n++] = id;
}

static void build_sequence(void) {
    /* A small loop body run a few times. */
    for (int k = 0; k < 3; k++)
        for (uint32_t id = 1; id <= 5; id++) put(id);
    /* A self-loop well past saturation. */
    for (int k = 0; k < 300; k++) put(7);
    put(RESET_SITE);
    /* The same three sites in every order: N>=3 sees different histories;
     * plain XOR folds some of them together, rotation keeps them apart. */
    static const uint32_t perm[6][3] = {
        {10, 11, 12}, {10, 12, 11}, {11, 10, 12},
        {11, 12, 10}, {12, 10, 11}, {12, 11, 10},
    };
    for (int p = 0; p < 6; p++) {
        put(9);
        for (int j = 0; j < 3; j++) put(perm[p][j]);
        put(13);
    }
    /* Site 0 alone, past saturation, then the highest id. */
    for (int k = 0; k < 260; k++) put(0);
    put(MAX_SITE);
    put(RESET_SITE);
    /* A long pseudo-random walk (LCG, fixed seed) with short repeats. */
    uint32_t x = 0x12345678u;
    for (int k = 0; k < 6000; k++) {
        x = x * 1664525u + 1013904223u;
        uint32_t id = (x >> 8) % (MAX_SITE + 1u);
        put(id);
        if ((x & 0xf) == 0) put(id);                 /* a self-edge */
        if ((x & 0x3ff) == 0x3ff) put(RESET_SITE);   /* occasional boundary */
    }
    put(RESET_SITE);
    /* The first loop again from a clean history: buckets already hit. */
    for (uint32_t id = 1; id <= 5; id++) put(id);
}

#if !LIBCOV_COVERAGE_MODEL_SITE
/* PC model: where site `id` lives. */
static uint8_t  site_module(uint32_t id) { return (uint8_t)(id % N_MODULES); }
static uint64_t site_pc(uint32_t id) {
    return MODULE_BASES[site_module(id)] + 0x1000u + 4u * (uint64_t)id;
}
#endif

/* ---- output ------------------------------------------------------------ */

static void die(const char *what, const char *path) {
    fprintf(stderr, "gen_vectors: %s %s: %s\n", what, path, strerror(errno));
    exit(1);
}

static FILE *open_out(const char *dir, const char *name) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) die("open", path);
    return f;
}

static void put_le(FILE *f, uint64_t v, int n) {
    for (int i = 0; i < n; i++) fputc((int)((v >> (8 * i)) & 0xff), f);
}

static void reset_history(void) {
    memset(libcov_prev_loc, 0, sizeof libcov_prev_loc);   /* as boundary.c */
}

static void write_vector(const char *outdir, uint32_t map_size) {
    const char *model = LIBCOV_COVERAGE_MODEL_SITE ? "site" : "pc";
    char dir[4096];
    snprintf(dir, sizeof dir, "%s/%s_n%d_r%d_%u", outdir, model,
             (int)LIBCOV_NGRAM_N, (int)LIBCOV_NGRAM_ROTATE, (unsigned)map_size);
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) die("mkdir", dir);

    sink_set_map_dims(map_size);
    libcov_bitmap = calloc(map_size, 1);
    if (!libcov_bitmap) { fprintf(stderr, "gen_vectors: OOM\n"); exit(1); }
    for (int m = 0; m < N_MODULES; m++) libcov_module_bases[m] = (uintptr_t)MODULE_BASES[m];
    reset_history();

    FILE *sf = open_out(dir, "sequence.bin");
    size_t emits = 0, resets = 0;
    for (size_t i = 0; i < seq_n; i++) {
        uint32_t id = seq[i];
        if (id == RESET_SITE) {
#if LIBCOV_COVERAGE_MODEL_SITE
            put_le(sf, UINT32_MAX, 4);
#else
            put_le(sf, UINT64_MAX, 8);
            put_le(sf, 0xff, 1);
#endif
            reset_history();
            resets++;
            continue;
        }
#if LIBCOV_COVERAGE_MODEL_SITE
        put_le(sf, id, 4);
        sink_emit(0, 0, id);
#else
        put_le(sf, site_pc(id), 8);
        put_le(sf, site_module(id), 1);
        sink_emit((uintptr_t)site_pc(id), site_module(id), 0);
#endif
        emits++;
    }
    if (fclose(sf) != 0) die("write", "sequence.bin");

    FILE *ef = open_out(dir, "expected.bin");
    if (fwrite(libcov_bitmap, 1, map_size, ef) != map_size || fclose(ef) != 0)
        die("write", "expected.bin");

    size_t nonzero = 0, saturated = 0;
    for (uint32_t i = 0; i < map_size; i++) {
        nonzero += libcov_bitmap[i] != 0;
        saturated += libcov_bitmap[i] == 255;
    }

    FILE *jf = open_out(dir, "scheme.json");
    fprintf(jf, "{\n");
    fprintf(jf, "  \"model\": \"%s\",\n", model);
    fprintf(jf, "  \"ngram_n\": %d,\n", (int)LIBCOV_NGRAM_N);
    fprintf(jf, "  \"rotate\": %d,\n", (int)LIBCOV_NGRAM_ROTATE);
    fprintf(jf, "  \"map_size\": %u,\n", (unsigned)map_size);
#if LIBCOV_NGRAM_ROTATE
    fprintf(jf, "  \"map_bits\": %u,\n", (unsigned)libcov_map_bits);
    fprintf(jf, "  \"rot_amounts\": [");
    for (int j = 0; j < LIBCOV_NGRAM_WIN; j++)
        fprintf(jf, "%s%u", j ? ", " : "", (unsigned)libcov_ngram_rot_r[j]);
    fprintf(jf, "],\n");
#endif
#if LIBCOV_COVERAGE_MODEL_SITE
    fprintf(jf, "  \"sequence_format\": \"u32le site_id\",\n");
    fprintf(jf, "  \"reset_record\": \"ffffffff\",\n");
#else
    fprintf(jf, "  \"sequence_format\": \"u64le pc, u8 module_idx\",\n");
    fprintf(jf, "  \"reset_record\": \"ffffffffffffffffff\",\n");
    fprintf(jf, "  \"module_bases\": [");
    for (int m = 0; m < N_MODULES; m++)
        fprintf(jf, "%s\"0x%llx\"", m ? ", " : "", (unsigned long long)MODULE_BASES[m]);
    fprintf(jf, "],\n");
#endif
    uint32_t shm_flags = LIBCOV_SHM_FLAG_SCHEME
        | (LIBCOV_COVERAGE_MODEL_SITE ? 0u : LIBCOV_SHM_FLAG_MODEL_PC)
        | (LIBCOV_NGRAM_ROTATE ? LIBCOV_SHM_FLAG_ROTATE : 0u)
        | ((uint32_t)LIBCOV_NGRAM_N << LIBCOV_SHM_NGRAM_SHIFT);
    fprintf(jf, "  \"lcvs_scheme_flags\": \"0x%x\",\n", (unsigned)shm_flags);
    fprintf(jf, "  \"emits\": %zu,\n", emits);
    fprintf(jf, "  \"resets\": %zu,\n", resets);
    fprintf(jf, "  \"nonzero\": %zu,\n", nonzero);
    fprintf(jf, "  \"saturated\": %zu\n", saturated);
    fprintf(jf, "}\n");
    if (fclose(jf) != 0) die("write", "scheme.json");
    free(libcov_bitmap);
    libcov_bitmap = NULL;
}

/* One line of map_size.json per N: {"n": N, "fudge": F, "sizes": [[sites, size], ...]} */
static void map_size_table(void) {
    static const size_t sites[] = {
        0, 1, 2, 100, 255, 256, 257, 1000, 4096, 4097, 65536, 100000,
        1000000, 16777216, 16777217, 40000000,
    };
    printf("{\"n\": %d, \"fudge\": %u, \"min_pow2\": %d, \"max_pow2\": %d, \"sizes\": [",
           (int)LIBCOV_NGRAM_N, (unsigned)LIBCOV_MAP_FUDGE,
           (int)LIBCOV_MAP_MIN_POW2, (int)LIBCOV_MAP_MAX_POW2);
    for (size_t i = 0; i < sizeof sites / sizeof sites[0]; i++)
        printf("%s[%zu, %zu]", i ? ", " : "", sites[i], sink_map_size_for(sites[i]));
    printf("]}\n");
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--map-size-table")) {
        map_size_table();
        return 0;
    }
    if (argc != 2) {
        fprintf(stderr, "usage: %s OUTDIR | --map-size-table\n", argv[0]);
        return 2;
    }
    build_sequence();
    for (size_t i = 0; i < sizeof MAP_SIZES / sizeof MAP_SIZES[0]; i++)
        write_vector(argv[1], MAP_SIZES[i]);
    return 0;
}
