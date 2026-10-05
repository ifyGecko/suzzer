# TODO

Backlog for libcov / suzzer. Sources: a full code review of `src/`,
`tools/` and `test/` (2026-09), the still-valid items from `Review.md`,
and the still-relevant items from the previous TODO.md (removed in
`04de25b`).

Priorities:
- **P0**: crashes the target or silently corrupts coverage in a
  configuration users are told is supported.
- **P1**: wrong or lossy coverage in a specific, documented configuration.
- **P2**: robustness, ergonomics, polish.
- **Backlog**: feature work.

---

## Fixed in the 2026-09 pass (for context)

Every fix has a regression check. `test/run_validation_signals.sh` and
the MT stress test fail against the pre-fix code.

- **Remote (over-IP) fuzzing template** (2026-10). `tools/suzzer-relay.c`
  (on-device TCP relay: spawns the target under libcov with an eventfd notify,
  reads the ring with the new shared `src/ring_reader.h`, delivers inputs to
  the daemon's port, forwards one COVERAGE/CRASH per input) +
  `tools/suzzer_brain.py` (off-device loop over `tools/mutate.py`) +
  `tools/relay_proto.h` + template daemon `test/target_netd.c`. The relay
  decodes the shm header on the device, so the brain never parses a foreign
  ABI. `test/run_validation_relay.sh` runs the whole path on loopback (HELLO,
  per-seed new coverage, a planted crash). `fuzz_driver` was refactored onto
  `ring_reader.h` with identical output. Design.md §24, HOWTO §14.1. Scope:
  single-process daemons, plain TCP; fork-per-connection is still open.
- **MT torn instruction writes** (`src/patch_mt.c`). The old primary
  path, `pwrite(/proc/self/mem)`, uses the kernel's memcpy, which stores
  2-4 byte lengths byte by byte. A peer CPU could fetch half UD2 and half
  original instruction (e.g. `0f 07` = SYSRET, which gives SIGSEGV). The
  16-thread stress test crashed in about 1 run out of 10. Code pages are
  now made R|W|X once at init, and arm/disarm is a single
  `__atomic_store_n`. `pwrite` is kept as a fallback that logs a WARNING.
  After the fix: 0 crashes in 40 runs.
- **Blocked trap signal kills the target** (`src/libcov.c`).
  `sigprocmask` and `pthread_sigmask` are now interposed, and the trap
  signal is removed from any mask the target blocks.
- **The target's own SIGILL handler was never called** (`src/libcov.c`).
  The handler it installed after init was saved but never chained to,
  which broke OpenSSL-style CPU probes. Both handlers now share
  `libcov_chain_trap()`, which honours `SA_SIGINFO` and `SA_RESETHAND`.
  `SIG_IGN` now dies with the default action instead of looping forever.
- **Async signals during a trap** (`handler_*.c`). `sa_mask` now blocks
  every asynchronous signal, which removes the MT spinlock self-deadlock
  and the ST path that could jump into a page made non-executable.
- **Init order** (`src/libcov.c`). The handler is now installed *before*
  sites are armed, so a failed install can't leave traps in place with
  nothing to catch them.
- **The MT fallback dropped PROT_EXEC.** The mprotect fallback used plain
  RW, which faults peer threads on the same page. It now uses RWX.
- **`LIBCOV_NGRAM_ROTATE=1` discarded history** (`src/sink.h`,
  `sink_shm.c`). It rotated a 32-bit value and then masked it to the map
  size. On a 4 KiB map, 160,000 distinct 4-grams landed in 1,600
  buckets. It now rotates within the map width, and the rotation amounts
  are computed at `sink_init`.
- **Log buffer over-read** (`src/util.c`). A truncated message made
  `write()` read past the end of the stack buffer.
- **Cross-module collisions in the hashed-PC model** (`sink.h`).
  `module_idx` is now mixed into the hash; module 0 is unchanged. (Review
  C1)
- **INIT_GRACE was per thread** (`boundary.c`). It is now a process-wide
  CAS counter. (Review C4)
- **`calloc` in the handler for every boundary config.** It now happens
  only under `REARM=touched`, and the init thread's set is pre-allocated.
  (Review C7, partly; finished below)
- **Begin-only sidecar with `depth_filter`.** This now logs a WARNING at
  load, and `gen_boundary.py` warns too. (Review C3, partly)
- **Seqlock fences.** A writer fence was added between `slot_gen=0` and
  the memset, and the driver has an acquire fence before its re-check.
- **Generator: blocks ending in a 1-byte instruction were dropped.** The
  terminator strategy now walks back to the last instruction of at least
  2 bytes. Under MT it also walks back past sites MT can't write atomically. `target_simple`
  MT went from 8 to 30 sites.
- **Generator: busy-loop on a missing binary.** rzpipe spins at 100% CPU
  forever when rizin can't open a file. There is now an up-front check.
- **Generator: `--strategy terminator` on MIPS** (patches the delay slot)
  is now refused.
- **`gen_boundary.py --patchlist`** checks that every marker is a
  patched site, and shares `pick_terminator()` with gen_patchlist.
- **MT skipped cache maintenance under SYNC_CORE** (`patch_mt.c`).
  `membarrier(SYNC_CORE)` only context-synchronizes; it doesn't clean
  the D-cache or invalidate the I-cache. `clear_cache` now runs after
  every write (a no-op on x86), with one membarrier per batch.
- **x86 MT dropped odd-address sites.** Unaligned 16-bit stores within
  a cache line are atomic, so the runtime uses `movw` for them and the
  generator only rejects line-straddling sites. MT now instruments the
  same sites as ST (`target_simple_mt`: 45 → 57).
- **Design.md §17.2** described `/proc/self/mem` as the primary MT
  write path. Rewritten for RWX-once + atomic store.
- **MT boundary snapshots mixed threads** (`boundary.c`). One shared
  live bitmap meant every snapshot held peers' in-flight coverage, and
  concurrent publishers could move the live pointer backwards. Under MT
  each worker thread now gets a private live bitmap at its first boundary
  and publishes a copy of it; non-worker threads keep the shared map.
  New `test/run_validation_boundary_mt.sh` (two concurrent workers on
  disjoint paths): before the fix 69/300 snapshots mixed both workers,
  now 0.
- **Markers were re-armed per thread.** A marker one worker hit stayed
  disarmed for the others until that worker trapped again. Markers now
  carry a HELD/RELEASED state: the next trap on any thread re-arms a
  marker once its thread has left the handler.
- **`calloc` in the trap handler** (Review C7). The REARM=touched set
  is now one process-wide queue allocated at init (see below), so
  nothing allocates in the handler except the MT per-thread live bitmap,
  which uses `mmap`.
- **REARM=touched starved with several MT workers.** Per-thread touched
  sets meant a site one worker re-armed was disarmed by another and only
  re-armed at *that* worker's boundary; with 4 workers boundaries
  stopped entirely. The queue is now process-wide, drained at any
  boundary.
- **Markers were re-armed too early under MT.** Leapfrog and the bulk
  re-arm loops re-armed a marker that another thread had just trapped on
  but not yet executed, so it re-trapped: ~35% of snapshots were
  spurious near-empty fires with 4 workers. Markers are now flagged in
  `patch_entry` and re-armed only once every thread that trapped on them
  has trapped elsewhere (or after `LIBCOV_MARKER_REARM_TIMEOUT_NS`).
  `run_validation_boundary_mt.sh` now also runs 4 workers and fails on
  stalls and on >5% near-empty snapshots.
- **Notify fd** (Review L5). `LIBCOV_BOUNDARY_NOTIFY_FD` is accepted only
  if it's an eventfd (`/proc/self/fd/N` → `anon_inode:[eventfd]`); a pipe
  could block the handler forever or SIGPIPE the target. Regression check
  in `run_validation_boundary.sh`.
- **Spinlocks yield** after 64 spins (`libcov_spin_backoff`), so a
  preempted holder on a single-core SCHED_FIFO system can run.
- **TLS model.** The library is built with `-ftls-model=initial-exec`, so
  handler TLS never goes through `__tls_get_addr` (`STATIC_TLS` is set in
  the dynamic section).
- **Fail loud** (Review C2, M5, M6, L3, L4). All covered by
  `test/run_validation_failloud.sh`:
  - `MODE=oneshot` + `REARM=none` with a boundary list is refused (ERROR,
    boundaries stay off) unless `LIBCOV_ALLOW_ONESHOT_NOREARM=1`.
  - `LIBCOV_REQUIRE=1` aborts when libcov ends up inert or any init step
    fails.
  - `libcov_st.so` warns when the process has or creates a second thread.
    This turned out to crash even in oneshot (ST's mprotect dance makes
    pages briefly non-executable), so Review.md's "ST + oneshot + any:
    safe" was wrong.
  - Init-time trap self-test: each encoding is executed once from a
    scratch page and must raise `LIBCOV_TRAP_SIGNO`, else libcov stays
    inert. Skipped on ppc64 ELFv1 (function descriptors).
  - `gen_patchlist.py` exits non-zero without writing when no sites are
    selected (`--allow-empty` to override), lists `--include-pat` matches
    under `-v`, and warns when one name matched under several prefixes.
- **Generator coverage holes** (Review C5, M7; `run_validation_generator.sh`):
  - Branch types are classified by suffix (`*call`/`*jmp`/`*ret`), so
    `ijmp`, `irjmp`, `ircall`, `mjmp`, `cret`, ... are recognised; an
    unrecognised one before a MIPS delay slot used to get the slot
    patched. Checked with rizin 0.9 on assembled MIPS: branch-likely
    forms come back as `cjmp`/`ccall`, and the entry strategy's
    delay-slot skip is correct for them (the next instruction is exactly
    the not-taken path).
  - The terminator strategy probes a block at its first call if it has
    one before its last instruction: a callee that never returns (exit,
    abort, longjmp, a crash) used to hide the block entirely.
  - `--root` runs report indirect calls/jumps in the slice, and
    `--print-reachable` marks the functions that have them.
  - An unparseable `afij @@F` chunk now warns instead of silently
    truncating the call graph.
- **Test infrastructure.** `make test` builds both variants and every
  test target and runs all native suites (`test/run_all.sh`). Suites use
  `mktemp -d` instead of fixed `/tmp` paths (the cross suites keep theirs
  on failure). Bitmaps are read via `test/shm_bitmap.py`, which takes
  size, offset and byte order from the header instead of assuming 64 KB
  at offset 72. New `-O2` PIE targets and `run_validation_o2pie.sh`.
  test/Makefile no longer bakes a relative runpath into target_multimod.
- **Missed boundaries with concurrent workers** (x86_64, aarch64). The
  trap handler now emulates the marker's original instruction (branches
  and NOP-like hints) and never disarms it, so no worker can pass a
  marker untrapped. `target_loop_mt`, 2/4/8 workers, all modes: every
  boundary captured (was 68-78% with 8). New
  `run_validation_marker_emulation.sh` checks every emulated branch form
  both ways (native and aarch64 under qemu); inverting either decoder's
  condition fails it. `run_validation_boundary_mt.sh` now demands >= 97%
  at 2/4/8 workers and still covers the fallback with emulation off.
- **Marker emulators for arm/Thumb, riscv64, powerpc, powerpc64.**
  Same contract as x86_64/aarch64 (branches plus NOPs; the PPC decoder is
  shared in `arch_ppc_emulate.h`). `run_validation_marker_emulation.sh`
  now runs under qemu for every one of them (ST; Thumb via
  `target_markers_thumb`), and inverting each decoder's condition fails
  it. Three bugs fixed on the way:
  - LCVB1 sidecars were read without byte-swapping, so boundaries never
    loaded on big-endian targets (`boundary: bad version 16777216`);
  - on ppc64 ELFv1, `gen_boundary.py` resolved a bare name to its `.opd`
    descriptor instead of the code;
  - on ppc64 ELFv2, it put the marker in the 8-byte global-entry stub,
    which direct calls skip. It now uses the local entry, as
    gen_patchlist does.
- **Signal broadcast when there is no `membarrier(SYNC_CORE)`**
  (`membarrier.c`). The context-synchronization step now works on
  pre-4.16 kernels: `LIBCOV_SYNC_SIGNO` goes to every peer, each one
  acknowledges from its handler, and broadcasts are coalesced (Design.md
  §17.2.5). `LIBCOV_SYNC_FALLBACK=auto|tgkill|off`. The target keeps the
  signal if it uses it. `run_validation_mt.sh`, `_boundary_mt.sh` and
  `_signals.sh` run with it forced (target handler, default action,
  `SIG_IGN` before exec, a peer blocking every signal).
- **MIPS markers weren't patched sites.** `gen_boundary.py` put the
  marker on the first block's terminator while MIPS patches block
  entries, so on every MIPS backend the boundary never fired. It now
  shares `pick_entry()` with gen_patchlist and follows the same
  `--strategy` (entry on MIPS). `run_validation_marker_emulation.sh`
  now runs for mips, mipsel, mips64 and mips64el under qemu (fallback,
  0 emulated) and fails against the old generator.
- **ppc64 ELFv1 functions starting with a `nop` were anonymous.** rizin
  finds an -O2 body that opens with a `nop` as `fcn.<entry+4>`, so name
  filters, `--root` and gen_boundary couldn't find it. Both generators
  now rename it after the symbol whose `.opd` descriptor points at the
  entry (`fix_elfv1_nop_entries()`). `run_validation_marker_emulation.sh`
  now checks `m_zero` on powerpc64 too (4/4 markers emulated).
- **README drift.** Fixed: the 64 KB bitmap claims, the x86 patch
  length, the chaining claim, the missing coverage-model docs, the
  "threads scope iterations cleanly" claim, and the `LIBCOV_MODULE`
  default.
- **Header dependencies.** The top-level, `test/` and `tools/` Makefiles
  build with `-MMD -MP`, so editing a header (tunables, `patch.h`, ...)
  rebuilds every object that includes it. The top-level include first
  sat above `all:`, so once `.d` files existed a plain `make` built only
  `libcov.o` (and `run_cross.sh` found no targets); `.DEFAULT_GOAL` is now
  pinned, the include is last, and `make test` checks plain `make`
  still builds the test targets.
- **shm file fallback symlink attack** (`sink_shm.c`). The `$TMPDIR`
  fallback opens with `O_NOFOLLOW | O_CLOEXEC`; `LIBCOV_LOG` is opened
  with `O_CLOEXEC`.
- **ST boundary mode left the live bitmap silently empty.** The shm
  header now sets `LIBCOV_SHM_FLAG_LIVE_EMPTY` when the `bitmap_offset`
  area isn't maintained, so drivers know to read the ring. (Review L1)
- **MT `patch_lookup` mid-transition invariant** is written down in
  `patch_mt.c`. (Review M4)
- **Generator name handling.** `--exclude-pat` adds to the default
  exclusions (`--no-default-exclude` drops them). Both generators share
  `tools/rz_resolve.py`: names resolve before plain-hex addresses (so
  `cafe` is a symbol), with the same suffix matching in both tools.
  gen_boundary parses C++ `ns::fn` specs and reports bad specs as errors,
  not tracebacks.
- **Data in text** (`gen_patchlist.py`). Candidate sites that are data
  (`invalid`, `.word`, ...) or Thumb IT-block conditional instructions are
  skipped (also for gen_boundary's markers); overlapping sites are
  dropped with a warning (`--fail-on-overlap` makes it an error); rizin
  heuristic `fcn.*` functions are no longer instrumented unless
  `--include-fcn` (the call-graph walk still goes through them).
  `run_validation_generator_safety.sh`, plus a real `-mthumb` `ite` block
  checked by hand.
- **Signal interposer robustness** (`libcov.c`, `util.c`). Each one is a
  `target_signals` mode in `run_validation_signals.sh`, and all but
  `race` failed against the old code (ST and MT):
  - the target's stashed trap disposition is a sequence-indexed double
    buffer, so an interposer on one thread can't tear the copy the trap
    handler reads on another (`race`);
  - a chained target handler runs with the kernel's mask (interrupted
    mask + `sa_mask` + signal unless `SA_NODEFER`), not libcov's
    everything-blocked mask (`mask`);
  - `bsd_signal`, `ssignal`, `sysv_signal`/`__sysv_signal`, `sigset`,
    `sigignore`, `sighold`, `siginterrupt` and `sigsuspend` are
    interposed: glibc routes them through internal calls, so
    `sigignore(SIGILL)`/`sighold(SIGILL)` killed the target on its next
    trap and `sigset`/`bsd_signal` replaced libcov's handler;
  - post-init log lines are dropped once the log fd no longer refers to
    the file it did at init, or is a socket (`logsock`, with `LIBCOV_LOG`
    set and unset);
  - the real `sigaction`/`pthread_sigmask` are resolved at init, never
    by `dlsym` from the trap handler.
- **Test traps are SIGILL on every arch.** `target_signals` used
  `__builtin_trap()` for its "real illegal instruction" cases, which is
  SIGTRAP (`brk`, `trap`, `ebreak`, `break`) on most backends, so those
  checks compared one death with another. `test/sigill.h` now uses each
  backend's own illegal encoding, and the new
  `test/run_cross_signals.sh` runs every mode under qemu for all 11
  cross targets (incl. arm-thumb), ST and MT.
- **Ring overruns were silent.** (Review M3, partly) Default
  `LIBCOV_BOUNDARY_RING` is 8 (was 4). The shm header counts MT
  publishes dropped for a stale slot (`publish_dropped`, in former
  reserved bytes). `fuzz_driver` resumes at the oldest readable
  generation instead of the newest, counts overruns and lost gens,
  reports them on exit and exits 3. `run_validation_boundary.sh` forces
  an overrun (`FUZZ_DRIVER_BURST=1`, ring 2) and checks the accounting.
- **Begin-only `depth_filter=zero`** is refused by `gen_boundary.py`
  unless `--force` (it filters nothing without END markers). (Review C3)
- **Re-exec wiped the shared region under the driver** (`sink_shm.c`).
  The header records its creator (pid + start time, kept by `exec`);
  `sink_init` decides under an `flock`: an in-place re-exec attaches and
  keeps bitmap, ring and generations (ST resumes in slot
  `gen_current + 1`); another live process's region is left alone (the
  newcomer runs inert and logs it); a stale file is reset as before.
  `%p` in `LIBCOV_SHM_PATH` gives each process its own region.
  `run_validation_reexec.sh` (ST and MT) failed on everything but the
  stale-file case before the fix. `run_cross.sh` now compares extracted
  bitmaps rather than whole shm files (the header differs per run).
- **Module resolution** (`util.c`, `config.c`, `gen_patchlist.py`). A
  symlinked binary (busybox-style), a renamed copy and a binary deleted
  after exec all left libcov inert, and two libraries with the same
  basename silently resolved to the first (every site then failed its
  byte check: zero coverage, no warning). Now: the generator names a
  module after its symlink target; ` (deleted)` is ignored; an ambiguous
  basename is logged; `LIBCOV_MODULE_RENAME=old=new` (bare name or
  absolute path) maps renamed or same-basename modules; an unresolved
  module 0 names the running executable in its hint. The main-exe lookup
  (boundary sidecars) matches the exact path.
  `run_validation_modules.sh` failed all four cases before.
- **MIPS markers were never emulated** (`arch_mips_emulate.h`). They sit
  on block-entry instructions, not branches, so the delay-slot objection
  didn't apply: they are prologue ALU ops (`lui gp`, `daddiu sp`). The
  register-only ones are now emulated on mips/mipsel/mips64/mips64el, so
  MIPS markers are never disarmed either. `test/unit_mips_emulate.c`
  checks every supported instruction, o32/n64 sign extension and the
  refusals (mutations are caught); `run_validation_marker_emulation.sh`
  expects 4/4 emulated under qemu on all four.
- **ST patched with two `mprotect` calls per arm/disarm** (`patch_st.c`).
  It now makes the patched pages `R|W|X` once, like MT, and arms/disarms
  with plain stores: a leapfrog microbenchmark went from 1.98 s to 0.68 s
  (1.2M `mprotect` calls to 9), bitmaps identical. W^X kernels that
  refuse `R|W|X` fall back to the old path automatically;
  `LIBCOV_ST_PATCH=mprotect` forces it. `test/wx_deny` (seccomp) plays
  the W^X kernel, so `run_validation_patch_mode.sh` also covers MT's
  `pwrite` fallback, which nothing exercised before.
- **`--root`/`--cutoff` with `--module`** (`gen_patchlist.py`,
  `rz_resolve.py`). Every root was resolved in every module, so the
  combination always exited with an error; an address root had no upper
  bound (a typo became the module's last function); `--print-reachable`
  stopped after module 0. Now unqualified names resolve wherever they
  are defined (PLT stubs don't count), `MODULE!NAME` pins a module, an
  unqualified address means the primary binary, a module without a root
  is skipped with a warning, addresses must fall inside a function's
  `aflj` extent (also in gen_boundary), and `--print-reachable` lists
  every module. `run_validation_multimod.sh` covers each case and runs
  a sliced two-module list end to end.
- **Paired-mode semantics** (`boundary.c`/`.h`). A driver couldn't tell
  an iteration from the END→BEGIN gap, both published as generations.
  Decided: keep publishing both (nothing lost, an iteration without its
  END isn't silently dropped) and tag every ring slot in its formerly
  reserved `flags`: INIT, ITER or GAP. `fuzz_driver`/`ring_dump` print
  the kind; README documents what each mode publishes. Paired mode had
  no test at all: `run_validation_paired.sh` (new `target_paired`, ST
  and MT) checks the kind sequence, that gaps hold only harness code
  and that iterations vary with the input; `run_validation_boundary_mt.sh`
  checks begin-only tagging under 2-8 workers.

---

## P0

- [ ] **Instruction-modification rules across CPUs.** Design
  constraint: traps stay SIGILL from illegal encodings (no INT3/BRK).
  Neither UD2 nor UDF is in the blessed cross-modification sets (x86
  SDM 8.1.3; AArch64 CMODX), so a peer fetching a site at the instant
  of the store is architecturally unpredictable. Done so far: the
  store is single-copy atomic, cache maintenance runs after every
  write, and `membarrier(SYNC_CORE)` context-synchronizes every core
  per batch (Design.md §17.2.5). Remaining:
  - confirm on real hardware that the residual window is harmless
    (next item).
- [ ] **Real-hardware MT validation.** 9 of 11 backends are build-only in
  `run_cross_mt.sh`. The new RWX + atomic store path has only run on
  x86_64 hardware (and under qemu for x86_64 and aarch64). CI boards:
  Raspberry Pi (arm and aarch64), a MIPS dev kit, a ppc64 box, a HiFive
  (riscv64).

## P1: coverage correctness

- [ ] **MT leapfrog/oneshot is sampled coverage.** A site that thread A
  has disarmed doesn't trap for thread B until it's re-armed, so B's
  coverage there is missed. Markers are solved on every backend by
  emulation (see the fixed list). Remaining: for coverage sites,
  consider a "re-arm after K traps process-wide" policy, or accept and
  keep documenting that MT is sampled coverage. A MIPS marker that lands
  on a store (not a register-only op) still uses disarm + re-arm.
- [ ] **x86: blocks made only of 1-byte instructions are unpatchable**
  (`leave; ret`, `pop; ret`, a lone `ret`). A limit of the 2-byte UD2
  encoding; now documented in README. A generator-side mitigation would
  be patching the block's predecessor edge instead.
- [ ] **Leapfrog never records self-loops.** An A→A edge is never seen,
  because the current site is never re-armed by its own trap. A
  single-site hot loop counts once until some other site traps. Document
  it, or add a per-thread "re-arm self after N instructions"
  (single-step is too costly; accept it).
- [ ] **Site-id collisions at N>=2.** The zero-collision guarantee holds
  only at N=1. Init now logs N and the buckets per site; still open:
  auto-scaling `LIBCOV_MAP_FUDGE` with N, and an actual expected
  collision-rate estimate. (Review M2)
- [ ] **`REARM=all` is O(n_sites) inside the signal handler.** It causes
  jitter. Overruns are now visible (see the fixed list); the handler
  cost itself is unchanged -- a per-page or batched re-arm would cut it.
  (Review M3, rest)

## P1: robustness

- [ ] **Fork without exec shares one region.** The child keeps the
  parent's mapping (with ST non-atomic increments, and interleaved
  boundary publishes if both run markers). See the fork-per-connection
  backlog item.
- [ ] **Raw signal syscalls bypass the interposers.** `rt_sigaction` and
  `rt_sigprocmask` issued directly (and the compat-only `sigvec`,
  `sigpause`) aren't intercepted; the libc wrappers are. Syscall-level
  coverage needs seccomp or libsyscall_intercept. Other mask-restoring
  paths (`siglongjmp`, `setcontext`) also use glibc-internal calls.

## P2: generator (`tools/gen_patchlist.py`, `tools/gen_boundary.py`)

- [ ] **Data in text, residual.** Data that decodes as a plausible
  instruction can't be told apart by type; the overlap check and
  `--strategy entry` are the backstops. An IT block that straddles a
  basic-block boundary isn't detected. Thumb mode is still decided per
  function (`fn["bits"]`).
- [ ] **LCVB1 has no `module_idx`,** so markers can only live in the
  primary module. Add an LCVB2 with a module index.
- [ ] **Indirect-call follow-ups.** `--root` runs now report the
  indirect calls/jumps in the slice (see the fixed list). Carried over
  from the old TODO:
  - an `--include-addr-taken` heuristic (functions with DATA xrefs);
  - runtime augmentation (a broad oneshot run, then re-slice);
  - tail-call edges (`--follow-tail`);
  - `--root @0xADDR` dereferencing function-pointer tables.
- [ ] **Ergonomics** (carried over): `--root 'parse_*'` globbing,
  `--root-file`, `--symbols name=0xADDR` for stripped binaries,
  `--dump-graph slice.dot`, `--diff baseline.lcv`, `--exclude-reachable`,
  `--callers-of`, per-basic-block cutoffs (`FUNC+0x40`), and verifying a
  slice against runtime bitmap hits.

## P2: tests and docs

- [ ] Add a raw `clone(2)` MT stress harness (carried over).

---

## Backlog (feature work, carried over)

### Daemon fuzzing
- **Daemon lifecycle resilience.** Handle chroot, dropping privileges,
  daemonize and closefrom: confirm everything we need is mapped, not
  just held by an fd, before the daemon's setup runs.
- **Fork-per-connection.** Hook `fork()` so each child gets its own
  bitmap segment, and announce the segment name on a control fd.
- **Hot-loop policy.** A per-site hit cap in leapfrog mode (auto-disarm
  above N). This matters even more under MT (atomic per-site counter).
- **dlopen hook.** Instrument libraries loaded after init (an LCV3
  extension).

### N-gram
- Runtime-selectable N (compile-time N becomes the maximum).
- Tag N and the coverage model in the shm header's spare flag bits.
- Hybrid publish (an edge map plus an N-gram map) when a consumer needs it.

### Tooling
- `suzzer-relay` / `suzzer-driver`: **delivered as a template** (see the
  fixed list) -- `tools/suzzer-relay.c` (on-device TCP relay) and
  `tools/suzzer_brain.py` (off-device fuzz loop), `test/run_validation_relay.sh`.
  Remaining follow-ups: fork-per-connection daemons (shared region; ties to
  the P1 fork item and the daemon backlog), other transports (serial), TLS,
  multi-device, and a one-shot/process-per-input delivery mode.
- `suzzer-forkserver`: AFL++-compatible, for short-lived targets; keep
  it out of core. Still open.

### Architectures
- i386 (UD2, `REG_EIP`), mips r6 / nanoMIPS validation, aarch64_be,
  s390x (low priority).
