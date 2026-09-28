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
  (Review C7, partly; see P1 below)
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
- **README drift.** Fixed: the 64 KB bitmap claims, the x86 patch
  length, the chaining claim, the missing coverage-model docs, the
  "threads scope iterations cleanly" claim, and the `LIBCOV_MODULE`
  default.

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
    (next item);
  - `tgkill` broadcast fallback for kernels without SYNC_CORE (see
    Backlog → MT).
- [ ] **Real-hardware MT validation.** 9 of 11 backends are build-only in
  `run_cross_mt.sh`. The new RWX + atomic store path has only run on
  x86_64 hardware (and under qemu for x86_64 and aarch64). CI boards:
  Raspberry Pi (arm and aarch64), a MIPS dev kit, a ppc64 box, a HiFive
  (riscv64).

## P1: coverage correctness

- [ ] **MT boundary snapshots mix threads.** `libcov_bitmap` is one
  process-global pointer, and `publish_snapshot` (`boundary.c`) moves it
  for every thread. Another thread's in-flight coverage ends up in the
  publisher's snapshot or the next one. Two concurrent publishers can
  also move the pointer backwards: B stamps N+1 before A stamps N, then A
  moves the live pointer to slot N+1 and zeroes it. `memset(libcov_prev_loc)`
  only clears the publisher's own TLS window. Options:
  - a TLS live pointer with per-thread live slots, where a publish only
    rotates the publishing thread's slot;
  - per-thread bitmaps that are merged at publish;
  - failing that, documenting (and at init, warning about) "one worker
    thread per process" for boundary mode.

  README now documents the limitation.
- [ ] **MT leapfrog/oneshot loses coverage from other threads.** A site
  that thread A has disarmed doesn't trap for thread B, so B's coverage
  (and B's boundary markers) are missed until A re-arms it.
  - For markers: keep marker sites armed globally. Any thread that
    traps on a different site re-arms a globally pending marker; today
    `g_pending_marker_rearm` is TLS.
  - For coverage: consider a "re-arm after K traps process-wide" policy,
    or accept it and document that MT is sampled coverage.

  The Review.md safety table now reflects this (it used to rate MT +
  boundaries as "safe").
- [ ] **x86: blocks made only of 1-byte instructions are unpatchable**
  (`leave; ret`, `pop; ret`, a lone `ret`). A limit of the 2-byte UD2
  encoding; now documented in README. A generator-side mitigation would
  be patching the block's predecessor edge instead.
- [ ] **Paired-mode semantics.** When both BEGIN and END fire, the gap
  between iterations (END → next BEGIN) is published as its own
  generation, so a driver sees two generations per input. Decide whether
  a BEGIN in paired mode should only reset (not publish), and document
  what drivers should expect.
- [ ] **`MODE=oneshot` + `REARM=none` with boundaries** only warns, and
  per-iteration bitmaps are empty after warmup. Make it a hard error
  unless `LIBCOV_ALLOW_ONESHOT_NOREARM=1` is set. (Review C2)
- [ ] **Begin-only `depth_filter`.** It now warns. Consider rejecting it
  in `gen_boundary.py` unless `--force`. (Review C3)
- [ ] **Leapfrog never records self-loops.** An A→A edge is never seen,
  because the current site is never re-armed by its own trap. A
  single-site hot loop counts once until some other site traps. Document
  it, or add a per-thread "re-arm self after N instructions"
  (single-step is too costly; accept it).
- [ ] **MIPS branch-likely delay slots.** With the entry strategy, a
  block that starts in the delay slot of a `*L` branch only runs when
  the branch is taken. Extend `_is_branch_at` to recognise likely
  branches, and add rizin's missing types `ijmp`, `irjmp`, `ircall`,
  `mjmp`, `cret` to `BRANCH_TYPES` (`tools/gen_patchlist.py`). A block
  that starts in a delay slot after one of those is currently patched at
  idx 0 and crashes. (Review M7 + generator audit)
- [ ] **The terminator strategy under-reports blocks that don't
  complete.** rizin doesn't split blocks at calls, so a block containing
  a call that never returns (abort, exit, longjmp, throw, or the
  crashing call itself) never reports. That is the most interesting
  block on a crash path. Consider patching a call-free instruction
  before the call, or an `--strategy entry` hybrid for blocks with calls.
- [ ] **Site-id collisions at N>=2.** The zero-collision guarantee holds
  only at N=1. Consider auto-scaling `LIBCOV_MAP_FUDGE` with N, and log
  the expected collision rate at init. (Review M2)
- [ ] **`REARM=all` is O(n_sites) inside the signal handler.** It causes
  jitter, and with `RING=2` it can overrun the ring. Consider a default
  ring of 8, and make `fuzz_driver` treat OVERRUN as fatal (or at least
  count it and report it on exit). (Review M3)

## P1: robustness

- [ ] **`calloc` in the handler for MT worker threads under
  `REARM=touched`** (`touched_append`). It deadlocks if the allocator is
  instrumented or interposed and the trap fires while the allocator lock
  is held. Use `mmap` (a raw syscall) for per-thread sets, or
  pre-allocate a pool sized by `LIBCOV_MAX_THREADS`. (Review C7)
- [ ] **Notify-fd hazards** (`publish_snapshot`). If `LIBCOV_BOUNDARY_NOTIFY_FD`
  is a pipe:
  - a full pipe blocks the target inside the signal handler forever;
  - a pipe whose reader has gone raises SIGPIPE and kills the target.

  At init, check that it's an eventfd (`readlink /proc/self/fd/N` ==
  `anon_inode:[eventfd]`) and refuse anything else. Don't set
  `O_NONBLOCK` on the fd: it's a shared open file description and would
  change the driver's reads. (Review L5, understated there)
- [ ] **Spinlocks never yield** (`patch_mt.c` `entry_lock`, `fallback_lock`).
  On single-core embedded parts with SCHED_FIFO threads, a low-priority
  holder can be starved forever. Call `sched_yield()` (a raw syscall)
  after N spins.
- [ ] **fork / re-exec re-initialises the shared region.** A daemon that
  re-execs itself (sshd per connection, nginx upgrade) inherits the
  environment, runs `sink_init` again, and memsets the header and ring
  while the driver is reading. If the header magic is already present,
  attach instead of zeroing, or support a `%p` pid placeholder in
  `LIBCOV_SHM_PATH`. Fork without exec shares one bitmap with ST
  non-atomic increments. See the fork-per-connection backlog item.
- [ ] **Race on `g_target_trap_sa`** (`libcov.c`). The `sigaction`
  interposer on one thread can write it while a handler on another
  thread reads it. Swap two buffers with an atomic index. Also, the
  target handler's own `sa_mask` isn't applied when we chain to it.
- [ ] **Bypasses of the handler interposers.** Raw `rt_sigaction` and
  `rt_sigprocmask` syscalls, and `bsd_signal`/`sigset`/`__sysv_signal`,
  aren't intercepted. Add the libc aliases; syscall-level coverage needs
  seccomp or libsyscall_intercept.
- [ ] **ST library in a multi-threaded target** is undefined behaviour
  under leapfrog, with no warning. Warn when `/proc/self/status`
  `Threads:` > 1, or intercept `pthread_create` and warn once. (Review M6)
- [ ] **Inert without `LIBCOV_PATCHLIST`.** The library does nothing and
  only logs an informational line. Aborting would break children that
  inherit `LD_PRELOAD`. Instead:
  - drivers should check the shm header magic;
  - add opt-in `LIBCOV_REQUIRE=1` that aborts when inert.

  (Review M5, with a different fix)
- [ ] **Trap signal vs encoding mismatch** (`-DLIBCOV_TRAP_SIGNO=SIGTRAP`
  with a SIGILL encoding) only shows up as a crash. At init, execute the
  trap encoding once in a private scratch page and verify it arrives as
  `LIBCOV_TRAP_SIGNO`. (Review L3)
- [ ] **TLS model.** Signal-handler TLS (`libcov_prev_loc`, the PC
  cache, `g_last_restored`) uses global-dynamic TLS. Build with
  `-ftls-model=initial-exec` so `__tls_get_addr` (which may allocate)
  can never run inside the handler, e.g. if libcov is ever dlopen'ed.
- [ ] **Runtime logging.** The `sigaction` interposer logs to fd 2 after
  init, and a daemon may have reused fd 2 for a socket. `LIBCOV_LOG` is
  opened without `O_CLOEXEC`.
- [ ] **Module resolution** (`util_module_base`). It matches on
  basename, so two libraries with the same basename in different
  directories are ambiguous, and `"… (deleted)"` paths never match. The
  primary module name is the basename of the path given to the
  generator, so a symlinked or renamed binary won't resolve.
- [ ] **shm file fallback** opens `$TMPDIR/<name>` with `O_CREAT` and no
  `O_NOFOLLOW`, which allows a symlink attack on shared hosts.
- [ ] **Boundary mode leaves the `bitmap_offset` area unused.** A
  legacy driver reads zeros. Set a header flag or field that points
  drivers at the ring, or document it prominently. (Review L1)
- [ ] **MT `patch_lookup` returns an entry whose `patched` may be
  mid-transition.** It's correct today because the handler never reads
  `patched` for the trapping entry and relies on the cmpxchg. Write that
  invariant down in a comment. (Review M4)
- [ ] **ST still does two `mprotect` calls per arm/disarm.** It could use
  the same RWX-once approach as MT: much faster, with no transient
  non-executable window. The current approach is kept for W^X
  compatibility, so make it a tunable.

## P2: generator (`tools/gen_patchlist.py`, `tools/gen_boundary.py`)

- [ ] **`--root` or `--cutoff` with `--module` exits with an error**,
  because roots are resolved inside every module. Address roots have no
  upper bound: any address, including another module's or a typo,
  resolves to the module's last function with only a note on stderr.
  `--print-reachable` returns after module 0.
- [ ] **Empty output.** A 0-record output exits 0 (e.g.
  `--include-pat '^main$'` when rizin names it `dbg.main`). Warn loudly,
  or exit non-zero unless `--allow-empty` is given.
- [ ] **Passing `--exclude-pat` replaces the default exclusions**
  (`sym.imp.`, `_init`, …) instead of adding to them.
- [ ] **Regex matches aren't reported.** Print the functions each
  include pattern matched under `-v`, and warn when one pattern matches
  both `sym.X` and `dbg.X`. (Review L4)
- [ ] **Data in text and overlaps.** There is no overlap check between
  sites, and heuristic `fcn.*` functions are included. Blocks that run
  into literal pools or Thumb `tbb`/`tbh` tables could patch data. Data
  reads never trap, so the corruption is permanent. Validate that sites
  don't overlap, and skip functions with `fcn.` names unless opted in.
- [ ] **Thumb detection is per function** (`fn["bits"]`). A UDF inside
  an IT block has unpredictable behaviour. Skip IT-block terminators.
- [ ] **A `JSONDecodeError` from `afij @@F`** silently truncates the call
  graph. Warn about it.
- [ ] **Name parsing.** Names of 4+ hex characters (`cafe`, `beef`) are
  parsed as addresses. gen_boundary's `split(":")` breaks on C++
  `ns::fn`. gen_boundary raises raw tracebacks on bad specs. It lacks
  gen_patchlist's suffix-match resolution, so the same name can resolve
  differently in the two tools; share `resolve_to_offset`.
- [ ] **LCVB1 has no `module_idx`,** so markers can only live in the
  primary module. Add an LCVB2 with a module index.
- [ ] **Indirect-call visibility.** `--print-reachable` should count the
  indirect call sites (`icall`/`ucall`) found during the BFS, so users
  know where to add roots. (Review C5) Follow-ups carried from the old
  TODO:
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

- [ ] Add a top-level `make test` that builds every target (`mt`,
  `multimod`, `orderable`, signals) and runs every native suite. Today
  the MT and multimod scripts fail with "missing target" until you run
  `make -C test …` by hand.
- [ ] All test targets are `-O0 -no-pie`. Add `-O2` PIE variants: real
  targets have tail calls, cold splits, jump tables and shrink-wrapped
  prologues, and the generator heuristics are untested against them.
- [ ] `run_validation.sh extract_bitmap` hard-codes 64 KB at offset 72.
  Read `map_size`/`bitmap_offset` from the header instead (the default
  map is now auto-sized).
- [ ] Tests write fixed `/tmp/...` paths, so parallel runs collide. Use
  `mktemp -d`.
- [ ] Commit (or drop) `test/run_validation_coverage_options.sh` and
  `test/target_orderable.c`, which are currently untracked. The Makefile
  rule for `target_orderable` now exists; the suite passes 22/22.
- [ ] Add an MT boundary test with more than one concurrent worker. It
  would expose the snapshot mixing (P1).
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

### MT
- A `tgkill` broadcast fallback for kernels without `membarrier(SYNC_CORE)`.

### Tooling
- `suzzer-relay`: an on-device bitmap server (TCP, serial, …).
- `suzzer-driver`: a real fuzz loop to replace `test/fuzz_driver.c`.
- `suzzer-forkserver`: AFL++-compatible, for short-lived targets; keep
  it out of core.

### Architectures
- i386 (UD2, `REG_EIP`), mips r6 / nanoMIPS validation, aarch64_be,
  s390x (low priority).
