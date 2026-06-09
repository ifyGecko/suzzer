# suzzer libcov injector

Standalone tools that inject `libcov_<st|mt>.so` into an already-running
target process, for cases where the usual `LD_PRELOAD`-at-spawn path
isn't viable -- chiefly embedded device daemons that come up at boot
under a watchdog and can't be restarted.

End-state after a successful injection is byte-identical to having
spawned the target with `LD_PRELOAD=libcov.so`: libcov's
`constructor(101)` has run, the patch table is armed, the trap handler
is installed, the shared bitmap is mapped, and the target continues
from exactly where it was at attach time.

This project is **standalone**: zero edits to libcov internals,
top-level Makefile, or anything outside `tools/inject/`. Build it
separately, ship it separately, ignore it if you don't need it.

## Two tools

| Binary           | Status        | When to use                                                                                                                                                                                                  |
|------------------|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `inject_ptrace`  | Working       | Default. Attach via `PTRACE_ATTACH`, do remote function calls + syscalls via the standard "trap-on-return" convention, detach. Works as long as you have ptrace permission on the target (root or same UID + `ptrace_scope <= 1`). |
| `inject_procmem` | Stubbed (phase 7) | Future ptrace-less variant for when another tracer is already attached (one-tracer rule), `ptrace_scope == 2`, or you want to stay invisible in `/proc/<pid>/status`'s `TracerPid` field. Currently exits with ENOSYS; design is in `Design.md`. |

Both share the same per-arch backend table and the same end-state.

## Arch support

| ARCH         | Backend         | Status                                          |
|--------------|-----------------|-------------------------------------------------|
| x86_64       | full            | Full runtime + 8/8 validation assertions pass   |
| aarch64      | full            | Cross-build OK; runtime validation pending real-hw runner (qemu-user ptrace too weak) |
| arm          | stub            | Build only; refuses at attach with clear msg    |
| mips, mipsel | stub            | Build only                                      |
| mips64, mips64el | stub        | Build only                                      |
| powerpc      | stub            | Build only                                      |
| powerpc64, powerpc64le | stub  | Build only                                      |
| riscv64      | stub            | Build only                                      |

Stub backends compile cleanly into the cross-build matrix; at runtime
they refuse to attach with a clear "not yet implemented" message. See
`arch_inject_<arch>.c` for the planned per-arch implementation notes.

## Build

```sh
cd tools/inject
make                              # native build
make ARCH=aarch64                 # cross-build
make all-arch                     # every supported ARCH
make test                         # also build target_inject_loop for tests
make clean
```

Outputs:

```
tools/inject/build/<arch>/inject_ptrace
tools/inject/build/<arch>/inject_procmem
tools/inject/build/<arch>/target_inject_loop      # only with `make test`
```

No edits to the top-level Makefile or anything under `src/` are
required (or performed).

## Usage

```sh
# Find the target PID
$ pgrep -fa dropbear
1234  /usr/sbin/dropbear -F

# Generate a patch list for it (one-time; from suzzer root)
$ ./tools/gen_patchlist.py /usr/sbin/dropbear /tmp/dropbear.lcv \
      --include-pat '^dbg\.(svr_main|handle.*|process.*|read_packet)$'

# Inject libcov
$ sudo ./tools/inject/build/x86_64/inject_ptrace \
      -P /tmp/dropbear.lcv \
      -S /libcov_dropbear \
      -M leapfrog \
      -L /tmp/libcov_dropbear.log \
      1234 \
      ./build/x86_64/libcov_st.so

injected /path/to/libcov_st.so into pid 1234 (arch=x86_64, handle=0x...)

# Coverage bitmap is now in /dev/shm/libcov_dropbear (since we used a
# shm-style path); your fuzz driver mmaps it as usual.
```

### Flags

```
Env-var setup (libcov reads these in its constructor):
  -e KEY=VAL        set env var in target before dlopen (repeatable)
  -P <patchlist>    shortcut for -e LIBCOV_PATCHLIST=<patchlist>
  -S <shm>          shortcut for -e LIBCOV_SHM_PATH=<shm>
  -M <mode>         shortcut for -e LIBCOV_MODE=<mode>    (oneshot|leapfrog)
  -L <log>          shortcut for -e LIBCOV_LOG=<log>
  -B <boundary>     shortcut for -e LIBCOV_BOUNDARY_LIST=<boundary>

dlopen flags:
  --rtld-now        dlopen with RTLD_NOW (default)
  --rtld-lazy       dlopen with RTLD_LAZY

Debug:
  --dry-run         attach, resolve symbols, print the plan; do NOT call
                    setenv/dlopen. Detaches cleanly.
  --scratch-size N  bytes to allocate in target for env strings + libpath
                    (default 4096). Increase for many or long -e values.
  -v                verbose; -vv for debug-level register dumps.
  -h                this help.
```

## ST vs MT patch lists

libcov enforces the LCV3 threading hint at init: handing an ST-generated
patch list to `libcov_mt.so` (or vice versa) is refused, and the library
becomes inert (no patches, empty bitmap). Generate the right kind:

```sh
./tools/gen_patchlist.py target out.lcv --include-pat ...               # ST (default)
./tools/gen_patchlist.py target out.lcv --include-pat ... --threading mt # MT
```

When using `inject_ptrace`, pass the matching combo:

```sh
inject_ptrace -P /tmp/target.st.lcv ... 1234 build/x86_64/libcov_st.so
inject_ptrace -P /tmp/target.mt.lcv ... 1234 build/x86_64/libcov_mt.so
```

## Validation

The harness mirrors the structure of libcov's `test/run_validation.sh`
but exercises the inject-into-running-process path:

```sh
# Native (x86_64) validation: 8 assertions across (st, mt) × (det, diff, leapfrog, output)
./tools/inject/test/run_validation_inject.sh
# -> "inject_ptrace validation:  PASS=8  FAIL=0"

# Cross matrix: confirms all 11 ARCH builds compile + link cleanly,
# runs the native validation for x86_64.
./tools/inject/test/run_validation_inject_cross.sh
# -> "inject_ptrace cross matrix:  FULL_PASS=1  BUILD_ONLY=10  FAIL=0"
```

The assertions (per-`(injector, threading)`):

- **A. Determinism** -- inject + feed inputs twice; bitmaps must be
  byte-identical.
- **B. Differentiation** -- inject + feed different input sets; bitmaps
  must differ (uses leapfrog mode to differentiate via hit counts, which
  works even when patch-set coverage is sparse).
- **C. Leapfrog hit counts** -- under MODE=leapfrog, the loop site
  records a hit count >= 2.
- **D. Output unchanged** -- target's stdout (modulo the PID line) is
  identical with and without injection. Catches register-restore bugs
  that corrupt target state.

`run_validation_inject.sh` writes intermediate `/tmp/inj_validate.*`
files which it cleans up on exit. Set `KEEP_TMP=1` to preserve them
for debugging.

## Limitations / edge cases

These are caveats inherent to the trust boundary, not bugs:

1. **Static binaries** can't `dlopen` -- no dynamic linker present.
   The injector detects this via `/proc/<pid>/maps` (no `ld-linux*`
   mapping) and refuses.
2. **chroot / containers**: `libcov.so` must be reachable from the
   target's filesystem view. The injector auto-tries
   `/proc/<pid>/root/<path>` as a fallback for ELF reads, but the
   *target* dlopens the library by the literal path you pass on the
   CLI -- if that path isn't visible inside the chroot you need to
   either copy libcov in or use a path that resolves to the same file
   from both the injector's and the target's filesystem views.
3. **setuid / capability-dropped processes**: injector needs
   `CAP_SYS_PTRACE` or root, same trust boundary as gdb.
4. **Yama `ptrace_scope` >= 2**: blocks `PTRACE_ATTACH` even for same-
   UID. Either run as root, lower the sysctl, or wait for
   `inject_procmem` to land (which has the same trust boundary but
   uses `/proc/<pid>/mem` writes directly without becoming the tracer).
5. **Existing tracer attached** (gdb, strace, another debugger):
   `inject_ptrace` fails with EPERM. Detach the other tracer or use
   `inject_procmem` (when implemented).
6. **fork-after-inject**: a child `fork()`ed *after* injection inherits
   libcov's mappings + signal handler. Per-pid `LIBCOV_SHM_PATH`
   defaults (`/libcov_<pid>` from libcov's POV is the *original*
   injected pid) will collide if both processes try to write to the
   same shm. Use an absolute filesystem path with `-S` for fork-heavy
   daemons.
7. **Re-injecting** the same libcov into the same pid is idempotent:
   `dlopen` refcounts the handle, env vars get re-`setenv`'d harmlessly,
   but libcov's constructor already ran and does not re-run. To
   re-configure you'd unload (out of scope) or restart the target.
8. **musl edge case**: musl folds dl into libc.so but exposes `dlopen`
   only when the link line asked for it (`-ldl`). For a daemon linked
   without `-ldl`, the resolver may not find `dlopen`; injector falls
   back to `libdl.so` lookup but if libdl isn't loaded that's
   chicken-and-egg. Solution: link the target binary against `-ldl`,
   or use a glibc target (where `dlopen` is unconditionally in libc).
9. **Target arch != injector arch**: doesn't work today. The injector
   could in principle do this with separate per-arch backends + a
   non-native ptrace layer; not currently implemented. Match the
   injector's ARCH to the target's.
10. **The 0xdead0000 sentinel** is checked against `/proc/<pid>/maps`
    at attach time; if it ever collides (extremely rare on real
    targets) the injector scans down by page and picks the first
    unmapped one.

## Files

```
tools/inject/
  Makefile                  -- standalone build (mirrors top-level ARCH map)
  README.md                 -- this file
  Design.md                 -- deep design doc (mechanism + per-arch + edge cases)

  inject_ptrace.c           -- main() for the ptrace variant
  inject_procmem.c          -- main() for the procmem variant (stub)

  inject_common.{h,c}       -- /proc parser, ELF symbol resolver, remote
                               syscall + function-call orchestration

  arch_inject.h             -- per-arch backend interface
  arch_inject_x86_64.c      -- full backend
  arch_inject_aarch64.c     -- full backend
  arch_inject_{arm,mips,mips64,powerpc,powerpc64,riscv64}.c
                            -- stubs; refuse at runtime with clear msg

  test/
    target_inject_loop.c    -- long-running stdin-driven target (daemon stand-in)
    run_validation_inject.sh        -- 8-assertion native harness
    run_validation_inject_cross.sh  -- cross-build matrix harness
```

## See also

- `tools/inject/Design.md` -- full design doc: mechanism, per-arch
  details, every edge case with rationale.
- The top-level `Design.md` for libcov internals.
- `arch_inject_<arch>.c` headers for per-arch implementation notes
  (including the planned per-arch implementation for the stub backends).
- `inject_procmem.c` top comment for the phase-7 design of the
  ptrace-less variant.
