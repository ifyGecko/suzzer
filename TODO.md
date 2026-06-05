# TODO

Items deferred from the current PoC scope, ordered roughly by when they'll
become blocking. Captured here so design context isn't lost.

## Daemon-fuzzing feature work (next focus)

The PoC validates the trampoline mechanism end-to-end across 11 backends
(x86_64, aarch64, arm + thumb, mips/mipsel/mips64/mips64el, powerpc,
powerpc64 BE+LE, riscv64). It assumes a single-threaded short-lived
program. The next phase makes it useful against network daemons.

- **Iteration boundary**: driver-side quiescence heuristic and/or an
  optional control socket so a remote driver can scope coverage to a
  single request/response cycle.
- **Multi-thread support**: TLS `prev_loc` for thread-safe edge coverage;
  oneshot-only under MT (leapfrog stays single-thread).
- **Multi-module patch list (LCV2)**: header carries a module name table;
  each record has a module_idx. Loader resolves each module's base via
  `/proc/self/maps`. Lets us instrument linked libraries (libssl, libxml2,
  etc.) where parser bugs typically live.
- **Signal-mask hardening**: intercept `sigprocmask` / `pthread_sigmask`
  and silently strip the trap signal from any "block" set, so a daemon
  that masks signals around critical sections can't accidentally kill
  itself by deferring a synchronous trap.
- **Daemon lifecycle resilience**: explicit handling around chroot,
  drop-privileges, daemonize, closefrom — confirm everything we need is
  mapped (not just fd-held) before the daemon's setup runs.
- **Fork-per-connection support**: hook `fork()` in libcov so each child
  gets its own bitmap segment; library writes the per-child segment name
  to a control fd the driver listens on.
- **Hot-loop policy**: per-site hit cap in leapfrog mode (env-configurable
  threshold; auto-disarm above N hits) to keep traffic-jammed parser
  inner loops from collapsing throughput.
- **dlopen hook**: instrument libraries loaded *after* libcov init
  (plugins, lazily-loaded modules). Probably an LCV2 extension.

## Tooling / transport

- **`suzzer-relay`**: tiny standalone tool to be deployed on the target
  device. mmaps the libcov bitmap and serves bytes over TCP/Unix on
  request. Keeps libcov small and signal-safe; transport stays pluggable
  (TCP/serial/MQTT/whatever the device speaks).
- **`suzzer-driver`**: minimal fuzz loop using the bitmap, the relay,
  and a configurable input mutator (radamsa? zzuf?). Replaces the
  current `test/fuzz_driver.c` proof-of-concept.

## Forkserver (separate tool, not core)

Forkserver-style execution model is **not** appropriate for daemon
fuzzing (daemons don't fork-per-request in general), but is the right
tool for **short-lived target binaries** fuzzed at high throughput
(parsers, CLI tools, format converters). When that use case arrives:

- Build a standalone `suzzer-forkserver` binary that takes a target +
  patch list and exposes an AFL++-compatible control pipe interface
  (handshake + per-iter "go" + child pid/status messages).
- Reuses the libcov library wholesale; just adds the fork-loop wrapper
  in a separate process.
- Keep it cleanly separate from core libcov so daemon-fuzzing doesn't
  drag in forkserver complexity.

## Architecture work after current backends

- **i386**: trivial extension of x86_64 (UD2 same, PC = `REG_EIP`).
- **mips r6 / nanoMIPS**: validate the BREAK encoding still triggers
  RI/SIGTRAP cleanly. Probably no change.
- **arm64 BE**: aarch64_be toolchain exists in Debian; verify illegal
  opcode and PC accessor under qemu-aarch64_be-static.
- **s390x**: low priority (uncommon in embedded), but mainframes exist.

## Hardening to defer until a real target needs it

- **Refuse to clear our trap handler**: today we intercept `sigaction`
  for the trap signo, but a target using `rt_sigaction` syscall directly
  would bypass us. If we see this in the wild, add a syscall-level
  interceptor via seccomp-bpf or `libsyscall_intercept`.
- **Per-thread coverage maps**: only if a real target's threading model
  produces uselessly noisy edge attribution.
- **W^X-strict embedded kernels**: today our two-step (R|W → R|X) works
  on all common Linux configurations. If we hit one that refuses, fall
  back to opening `/proc/self/mem` and writing through that — it
  bypasses page protection for ptrace-style debugging.
