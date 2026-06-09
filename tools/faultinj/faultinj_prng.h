/*
 * faultinj_prng.h -- the deterministic PRNG libfaultinj uses to decide
 *                    whether and how to fault each hooked call.
 *
 * Design goal: every decision the library makes is a pure function of
 * the user-supplied 64-bit seed plus the (class_id, call_index) of the
 * call being considered. Same seed + same call ordering => bit-
 * identical injection pattern. That property is the entire user-facing
 * value proposition for reproducibility, so the PRNG choice and the
 * seeding mixing function matter.
 *
 * Algorithm:
 *
 *   1. SplitMix64 the input bits (seed, class_id, call_idx). SplitMix64
 *      decorrelates close inputs ("call_idx 7 vs 8" or "seed N vs N+1")
 *      so the first xoshiro output isn't biased by trivially-related
 *      seeds. It's a 64-bit mixing finalizer designed for exactly this.
 *
 *   2. Seed an xoshiro256** state with four SplitMix64 outputs derived
 *      from the mixed bits. Avoid the all-zero state (xoshiro
 *      degenerates to a fixed point there) by OR'ing one bit if the
 *      mix happens to be zero -- statistically vanishing chance but
 *      the check is a single branch.
 *
 *   3. Pull ONE xoshiro256** output. That 64-bit roll is the basis of
 *      every downstream decision for this call:
 *        - the upper 32 bits decide PASS vs FAIL by comparison against
 *          a scaled probability,
 *        - bits[0..7] pick the errno from the per-class pool,
 *        - bits[8..15] pick the failure mode from the per-class pool,
 *        - bits[16..47] (if FAIL_SHORT is picked) become the
 *          truncation length seed.
 *
 *   We pull a single xoshiro output (not multiple) so the decision is
 *   atomically derivable from the roll. Pulling multiple outputs would
 *   work too but adds advance-state complexity without adding entropy
 *   that matters for our use case.
 *
 * No global state, no thread-local state, no syscalls. The PRNG state
 * is constructed fresh per hooked call and discarded. This is
 * (relatively) expensive vs a single global PRNG advance, but makes
 * fork-server use deterministic without any per-iter reset bookkeeping:
 * the child's first call after fork() sees (seed, class, idx=N+1) and
 * computes the right roll regardless of what the parent rolled.
 *
 * xoshiro256** is by Blackman & Vigna (2018), public domain. SplitMix64
 * is by Steele, Lea, Flood (2014) and is in the public domain via Doug
 * Lea's notes. Both are short enough to reproduce inline.
 */

#ifndef FAULTINJ_PRNG_H
#define FAULTINJ_PRNG_H

#include <stdint.h>

static inline uint64_t fi_splitmix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z =  z ^ (z >> 31);
    return z;
}

static inline uint64_t fi_rotl64(uint64_t x, int k)
{
    return (x << k) | (x >> (64 - k));
}

/* Compute one xoshiro256** roll deterministically from (seed, class_id,
 * call_idx). No state is preserved between calls.
 *
 * The mixing scheme combines the three inputs into a single 64-bit
 * "logical seed" and then derives the four xoshiro state words from
 * sequential SplitMix64 applications of that seed -- this is the
 * standard recommended xoshiro seeding pattern.
 */
static inline uint64_t fi_roll(uint64_t seed,
                               uint32_t class_id,
                               uint64_t call_idx)
{
    /* Mix the three inputs into a single 64-bit logical seed. The
     * constants are SplitMix64 increments (golden ratio derivatives);
     * any well-mixing constants would do. The point is that close
     * (class, idx) pairs produce diverged logical seeds.
     */
    uint64_t s = fi_splitmix64(seed
                               ^ ((uint64_t)class_id * 0x9E3779B97F4A7C15ULL)
                               ^ (call_idx * 0xBB67AE8584CAA73BULL));

    /* Seed xoshiro256** state from four splitmix64 outputs. The
     * standard pattern (see xoshiro256.c in the original distribution)
     * advances a local splitmix state to produce each xoshiro word.
     */
    uint64_t a = s;
    uint64_t b = fi_splitmix64(a + 0x9E3779B97F4A7C15ULL);
    uint64_t c = fi_splitmix64(b + 0x9E3779B97F4A7C15ULL);
    uint64_t d = fi_splitmix64(c + 0x9E3779B97F4A7C15ULL);

    /* Guard against the all-zero state. Astronomically unlikely
     * given the seeding above but the check is one cmp. */
    if ((a | b | c | d) == 0) a = 1;

    /* xoshiro256** output function on the seeded state. We don't
     * advance the state because we only need one roll per call.
     */
    return fi_rotl64(b * 5, 7) * 9;
}

#endif /* FAULTINJ_PRNG_H */
