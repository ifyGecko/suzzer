# Review.md — libcov coverage-options review

> **Status (2026-09):** superseded by `TODO.md`, which is the live backlog.
> C1 and C4 are fixed; C3 and C7 are partly fixed; the remaining items are
> tracked there by priority. The safety table at the end has been corrected
> to match; the per-item text below is the original review, kept for its
> reasoning.

Scope: a full read of `src/`, `test/`, and `tools/` looking for design
issues that could **silently** limit or prevent uncovering bugs when a
user builds a fuzzer with suzzer. Performance is explicitly out of scope
here — only correctness of the coverage signal and the fuzz-loop
contract matter.

Coverage options (the user-facing knobs) audited:

| Axis | Where it lives | Values |
|---|---|---|
| Threading variant | top-level Makefile `THREADING=` | `st`, `mt` |
| Per-trap mode | `LIBCOV_MODE` | `oneshot`, `leapfrog` (default) |
| Coverage model | `LIBCOV_COVERAGE_MODEL_SITE` | `1` (site-id, default), `0` (hashed-PC) |
| N-gram width | `LIBCOV_NGRAM_N` | 1..8 (default 2 = AFL edges) |
| N-gram rotation | `LIBCOV_NGRAM_ROTATE` | 0 (default), 1 |
| Map size | `LIBCOV_MAP_SIZE_POW2` (hashed-PC), or `LIBCOV_MAP_FUDGE` + clamps (site-id) | see tunables.h |
| Trap signal | `LIBCOV_TRAP_SIGNO` | default `SIGILL` |
| Per-arch illegal encoding | `tunables_<arch>.h` knobs | arch-specific |
| Shm backing | `LIBCOV_SHM_PATH` | shm name or fs path |
| Boundary list | `LIBCOV_BOUNDARY_LIST` | path or unset (inert) |
| Boundary re-arm | `LIBCOV_BOUNDARY_REARM` | `none`, `all`, `touched` |
| Boundary ring depth | `LIBCOV_BOUNDARY_RING` | 2..16 (default 4) |
| Boundary init grace | `LIBCOV_BOUNDARY_INIT_GRACE` | uint (default 0) |
| Boundary notify fd | `LIBCOV_BOUNDARY_NOTIFY_FD` | inherited fd or unset |
| Selective instrumentation | `gen_patchlist.py --root/--cutoff/--max-depth` | per invocation |
| Multi-module | `gen_patchlist.py --module NAME:PATH` | repeatable |

What follows is a focused list of design problems that can damage
**fuzzing result quality** without obvious user-visible signal. Items
ordered by impact on bug-finding capability.

---

## Critical: silent loss of coverage signal

### C1. Cross-module bitmap collisions under hashed-PC model

`src/sink.h::sink_hash_pc` hashes `pc - libcov_module_bases[module_idx]`
without mixing `module_idx` into the hash. Two distinct sites at the
same module-relative offset in different modules (very common: the
first basic block of two functions in two .so's both at offset
0x1000) land in the same bucket. The comment in `sink.h` acknowledges
this — `"cross-module hash collisions are possible but accepted"` —
but in practice this can quietly halve the discoverable surface of any
multi-module fuzz target.

The site-id model (`LIBCOV_COVERAGE_MODEL_SITE=1`, default) avoids
this because `site_id` is a unique file-record index across all
modules. **Anyone who flips back to the legacy hashed-PC model for a
multi-module target will lose coverage signal without warning.**

Recommended fix: when `LIBCOV_COVERAGE_MODEL_SITE=0` and
`module_count > 1`, log a loud warning at init, or mix `module_idx`
into the hash:
```c
uint64_t v = (uint64_t)(pc - libcov_module_bases[module_idx])
           ^ ((uint64_t)module_idx * 0x9E3779B97F4A7C15ULL);
```

### C2. `MODE=oneshot` + `BOUNDARY_REARM=none` produces empty per-iter snapshots after warmup

`src/libcov.c::libcov_init` logs a warning when this combination is
detected, but the library still loads and runs. After the first few
iterations every site has been disarmed once; subsequent per-iteration
bitmap snapshots are empty. A fuzz loop driven by per-iter snapshots
(via `LIBCOV_BOUNDARY_LIST`) will see "no new coverage" for every input
and the queue will stop growing. To the user this looks like a
plateaued corpus, not a misconfiguration.

Recommended fix: refuse to enable boundaries in this combination
(return `-1` from `boundary_init`) rather than warning. Cost of
fail-loud is one rerun; cost of fail-quiet is an entire wasted fuzzing
campaign.

### C3. Begin-only boundaries silently ignore `depth_filter` and recursion protection

`src/boundary.c::boundary_on_trap`, paired-mode block at lines
458-468. In begin-only mode (sidecar has no END markers, `g_paired_mode
= 0`) the comment says depth tracking is collapsed and every BEGIN
fires, but the `depth_filter` byte on the marker record is **read from
disk and then ignored**. A user who builds a sidecar with
`depth_filter=zero` expecting "only fire at top-level invocations" gets
recursive sub-calls firing boundaries too, mixing iteration scoping.

`gen_boundary.py` advertises `kind:depth_filter` syntax for begin-only
sidecars (e.g. `iter_begin:begin:zero`), so users actively reach for
this footgun.

Recommended fix: either reject `depth_filter != 0` records at
`load_sidecar` time when no END markers are present, or honor the
filter via best-effort depth tracking (return-to-zero on every fire,
as today, but skip the fire when filter=zero and `g_depth > 0` from a
nested-call pattern — recognizing this is approximate without END
markers).

### C4. `LIBCOV_BOUNDARY_INIT_GRACE` is per-thread, not per-process

`src/boundary.c` lines 81-83 declare `g_init_grace_remaining` with the
`TLS` macro (which is `__thread` under MT). Each worker thread
independently drops `LIBCOV_BOUNDARY_INIT_GRACE` marker hits before
publishing. A user who sets `INIT_GRACE=3` expecting to skip the first
three init-noise iterations from a 16-thread daemon actually skips
**48** marker hits. The init coverage of every thread except the first
batch is lost, and the per-iteration bitmaps for the first ~3 marker
fires per thread go un-published.

Recommended fix: either make `g_init_grace_remaining` a process-global
atomic counter (decrement-on-fire from any thread), or document the
per-thread semantics prominently in the env-var table. The atomic-
counter fix is one line of code and matches user mental model.

### C5. Indirect-call invisibility cuts arbitrary chunks out of fuzzed code

`tools/gen_patchlist.py` builds its call graph from rizin's `afij`
direct-call edges. Function pointers, vtable dispatch, jump tables,
and any other indirect transfer are invisible. With `--root
parse_request --max-depth 8` on a target whose request handler
dispatches on `ops_table[type](req)`, the entire backend is silently
omitted from the slice — and the user can't tell from the
`--print-reachable` output that anything is missing.

This is fundamental to static analysis and called out in `README.md`,
but the consequences for fuzz quality are not obvious. A driver seeing
"60% bitmap coverage steady state" thinks coverage has plateaued; in
reality 90% of the dispatch tree was never instrumented.

Recommended fix: `--print-reachable` should also dump a count of
**indirect-call sites encountered during BFS** (`rizin` exposes them
via `aflj`'s `indirect_calls` field per fn or via `afij`'s
`calltype=icall` edges). Even an approximate count tells the user
"there are 47 indirect call sites in your slice; consider adding
roots". Out of scope for runtime libcov but easy to add to the
generator.

### C6. MT cross-CPU instruction-cache coherence is best-effort on kernels < 4.16

`src/patch_mt.c::mt_init_once` caches `g_have_sync_core =
membarrier_has_sync_core()`. When 0 (Linux < 4.16, some hardened
embedded kernels) the runtime falls back to local `clear_cache` only.
On weakly-ordered ISAs (arm, aarch64, mips, ppc, riscv64) peer threads
can fetch stale-instruction bytes for a small but non-zero window
after a disarm/re-arm. The result is a coverage signal that
**non-deterministically misses edges** — which looks like benign
flakiness in a fuzz queue but actually drops legitimate novelty
events.

This is documented in `src/membarrier.c` and `Design.md` §17.2.5, but
the runtime silently degrades without a loud init-time warning.
Recommended fix: when `LIBCOV_THREADING_MT` is in use AND
`membarrier_has_sync_core() == 0` AND the arch is weakly-ordered, log
a `WARNING` (not a debug-level message) so the user can spot it in
init logs.

### C7. `malloc`/`calloc` from a signal handler in boundary touched-set lazy init

`src/boundary.c::touched_append` (lines 295-303) calls `calloc()`
lazily on first use per thread, inside the signal-handler call chain.
The inline comment says "malloc in glibc under our usage pattern is
safe in practice". This is not async-signal-safe by POSIX, and the
"in practice" depends on glibc never trying to take its arena lock —
which it absolutely does once the heap is non-trivially used.

Symptoms in real fuzzing: hung worker threads under `BOUNDARY_REARM=touched`
when a regular allocation in target code interleaves with the
first-trap calloc on the same thread. Won't show up in the
`run_validation_boundary.sh` matrix because target_loop barely
touches the heap.

Recommended fix: pre-allocate `g_touched` at first-trap per thread via
a TLS callback installed by `pthread_key_create(..., destructor)`, or
preallocate at `boundary_init` time using a fixed worst-case thread
count (env-var configurable, default 64).

---

## Moderate: distortion of coverage signal under specific options

### M1. `LIBCOV_NGRAM_ROTATE=0` + `LIBCOV_NGRAM_N >= 3` collapses reorderings

The XOR-fold index formula is commutative:
`idx = cur ^ prev[0] ^ prev[1] ^ ... ^ prev[N-2]`.
Sequences `{A,B,C}` and `{C,B,A}` index to the same bucket. The
shift-by-1 in `prev_loc[0] = (cur_win >> 1)` (hashed-PC model) breaks
adjacent A↔B pair commutativity only.

For N=3+ in dense code this is a real collision source. The shipped
default is `LIBCOV_NGRAM_ROTATE=0` (the comment in `tunables.h`
explicitly trades collisions for AFL-compatible math at N=2). A user
who bumps N to 4 to chase path-sensitive bugs without flipping ROTATE
loses much of the sensitivity bump.

Recommended fix: change the default to `LIBCOV_NGRAM_ROTATE=1` when
`LIBCOV_NGRAM_N >= 3`, and document the AFL-compatibility tradeoff in
the existing per-knob doc block.

### M2. Site-id zero-collision claim only holds at N=1

`tunables.h` documents that the site-id model gives "ZERO collisions"
because `idx == site_id` at N=1. For N>=2 the formula becomes
`idx = site_id ^ spread(prev_site_1) ^ ...`. The raw `site_id`
contributes a dense [0, n_sites) range; the `spread(...)` copies
contribute pseudo-random offsets across the whole `map_mask`.
Collisions are possible whenever `site_id ^ spread(...)` lands in
`[0, n_sites)`. The map is sized `next_pow2(n_sites * FUDGE)` so
collision probability at N=2 is roughly `1/FUDGE` per emit — about 6%
at the default FUDGE=16.

This is not a bug, but the docstring's "ZERO collisions" is mode-
gated and easy to read as a global claim. Anyone using site-id at
N>=2 should know to bump FUDGE for path-sensitive workloads.

### M3. `apply_rearm_policy(REARM=all)` runs O(n_sites) inside the signal handler

For multi-thousand-site patch lists, every boundary fire walks the
entire patch table inside the trap handler. Not a coverage-quality
bug per se, but the long-tail latency causes per-iteration jitter
that can push slow snapshots out of the ring under `LIBCOV_BOUNDARY_RING=2`.
The driver then sees `OVERRUN: writer advanced past gen=N` and skips
ahead — silently losing per-input coverage attribution for the
overrun batch. The OVERRUN message goes to stderr, which a real fuzz
driver typically suppresses.

Recommended fix: raise the default `LIBCOV_BOUNDARY_RING` to 8, or
have the driver path treat OVERRUN as a fatal-config event rather
than a recoverable one.

### M4. PC cache (`patch_st.c` / `patch_mt.c`) Fibonacci-hash entry pointer never invalidates

The 16-slot PC cache uses `pc * 0x9E3779B9...` mod 16. Cache holds
`(pc, struct patch_entry *)` pairs and is never invalidated because
the entries are allocated once at init and stable for the process
lifetime. **However**, the cache returns a pointer to a `patch_entry`
that may be in transitional state (`patched=0` mid-disarm). The
caller in `trap_handler` checks `e->patched` AFTER `patch_lookup` —
under ST that's fine; under MT the load is relaxed but the comment
in `patch_mt.c::patch_lookup` is silent on whether the returned entry
needs an acquire fence. Reading the MT trap path it looks correct
(the cmpxchg inside `patch_disarm_unsynced` provides the
happens-before edge for any subsequent observer), but a future
refactor that bypasses the lock could miss the invariant. Worth a
comment block.

### M5. `LIBCOV_PATCHLIST` unset → library completely inert with only a debug log line

`libcov_init` returns early with `libcov_logf("init: LIBCOV_PATCHLIST
unset, library inert")`. The log line is informational. A user who
forgets to set the env var (very easy under nested LD_PRELOAD shims)
gets a fuzz run that produces no coverage at all. The driver sees an
all-zero bitmap and treats every input as duplicate.

Recommended fix: gate the inert path behind an opt-in env var
`LIBCOV_ALLOW_INERT=1`. Without it, refuse to construct the library
with a non-zero exit-style log line that the dynamic linker will
relay back to stderr.

### M6. ST library used against a multi-threaded target = arbitrary undefined behavior under leapfrog

`Design.md` §17.1 says "Under a multi-threaded target ... Leapfrog:
unsafe. The library will not detect this; behavior is undefined."
The LCV3 `threading` byte hint prevents the patch list from being
mismatched, but nothing prevents a user from running an
ST-generated patch list against a target that happens to be
multi-threaded (a daemon that fork+execs into a pthreaded handler).

Recommended fix: at init under ST, parse `/proc/self/status` for
`Threads:` and warn loudly if > 1 by the time `handler_install`
finishes. False positives on early-init thread spawn are acceptable
since this is a warning not a fault.

### M7. MIPS likely-branch (`beql`, `bnezl`, etc.) delay slot is conditionally executed

`gen_patchlist.py::pick_sites` MIPS handling skips the delay slot at
position 0 when the previous instruction is a branch. This is correct
for unconditional/conditional non-likely branches: the delay slot
always executes. For "likely" branches (`*L` variants) the delay slot
executes ONLY if the branch is taken — patching it makes the trap
fire fewer times than the actual block entries. Coverage signal
becomes path-sensitive in a way the bitmap can't distinguish.

Likely branches are uncommon in -O0/-O2 GCC output, but they exist on
older MIPS targets compiled with `-mips32` and on hand-written
assembly. Worth either documenting the limit or extending the
delay-slot check to look at the previous opcode's family.

---

## Low / informational

### L1. Site-id model under boundary mode leaves the dedicated bitmap area unused

`src/boundary.c::boundary_init` redirects `libcov_bitmap` to
`slot_bitmap(slot[1])`, so the bitmap area at `hdr->bitmap_offset`
goes unused. A legacy driver that reads `hdr->bitmap_offset` rather
than the ring slots sees all-zero buckets. The shm header carries the
`LIBCOV_SHM_FLAG_ACTIVE` bit to indicate boundary mode, but a driver
that ignores flags has no way to know.

### L2. `LIBCOV_NGRAM_N` cap is 8 (compile-time `_Static_assert`)

Raising the cap costs a few TLS bytes per thread. No reason given for
the specific limit beyond "TLS pressure and collision rate" — fine
as-is for current usage, but worth a note that higher N is a
single-line `tunables.h` change plus a `_Static_assert` bump.

### L3. `LIBCOV_TRAP_SIGNO` override is project-wide but not validated at link time

If the user passes `-DLIBCOV_TRAP_SIGNO=SIGTRAP` but the per-arch
`LIBCOV_ARCH_<NAME>_ILLEGAL` still encodes a SIGILL-raising
instruction, the kernel delivers SIGILL to our handler which is
installed for SIGTRAP. Default handler runs, process dies. The
mismatch is visible only at runtime crash. No build-time assertion
links the two knobs.

### L4. `gen_patchlist.py` accepts ambiguous regex matches without erroring

`--include-pat '^classify$'` matching both `sym.classify` and
`dbg.classify` (which is normal under rizin) will instrument BOTH.
That's harmless because the addresses collapse via `seen` dedup —
but for users who hand-write include patterns expecting unique
matches, the behavior is surprising. The `--root` path explicitly
errors on ambiguous suffix matches; the regex path silently unions
them.

### L5. Boundary mode's `g_eventfd` write returns ignored

`src/boundary.c::publish_snapshot` does
`(void)write(g_eventfd, &one, sizeof one)`. Under a normal eventfd
this is non-blocking and the write count is irrelevant. If the
inherited fd happens to be a pipe whose reader has gone away, the
write fails silently; the driver loses the wakeup and falls back to
polling (which still works). Worth a one-time warning if the write
returns -1 with `EPIPE`/`EBADF`.

---

## Summary: which options are safe to combine right now

| Combination | Status | Notes |
|---|---|---|
| ST + leapfrog + single-thread target | safe | original PoC path |
| ST + leapfrog + multi-thread target | unsafe | undefined behavior; warn at init |
| ST + oneshot + any | safe (one-shot coverage only) | no per-iter snapshots |
| MT + leapfrog + multi-thread target | sampled on kernel >= 4.16 | a site disarmed by one thread doesn't trap for others until re-armed (TODO P1); C6 on older kernels |
| MT + boundaries + 1 worker thread | safe | recommended for per-iteration attribution |
| MT + boundaries + >1 worker thread | distorted | shared live bitmap: snapshots mix threads, concurrent publishers can reorder (TODO P1) |
| MT + oneshot + boundary REARM=all/touched | safe with 1 worker | same thread caveat as above |
| MT + oneshot + boundary REARM=none | broken | empties bitmap after warmup (C2) |
| Multi-module + site-id model | safe | unique site_ids across modules |
| Multi-module + hashed-PC model | safe | fixed: `module_idx` mixed into the hash (C1) |
| N=2 (default) + ROTATE=0 | safe | bit-identical to historical libcov |
| N>=3 + ROTATE=0 | leaky | XOR-commutative reorderings collide (M1) |
| N>=3 + ROTATE=1 | safe | recommended for path-sensitive workloads |
| Boundary begin-only + depth_filter=zero | broken | filter ignored; now warns at load (C3) |
| Boundary INIT_GRACE + MT > 1 thread | safe | fixed: process-wide counter (C4) |
| Selective `--root` + heavy indirect dispatch | leaky | rizin static graph misses icalls (C5) |

The good news is that the **default configuration** (MT or ST with
defaults, site-id model, N=2, no boundary list) avoids all of the
critical issues. The risk shows up specifically when users start
flipping non-default options to chase deeper coverage or to scope
iterations on long-running targets — which is exactly when fuzz
quality is most sensitive to silent regressions.
