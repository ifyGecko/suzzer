#!/usr/bin/env bash
# Cross-arch validation matrix for the injector.
#
# Mirrors libcov's test/run_cross.sh layout. For each ARCH:
#
#   FULL_PASS    -- cross-built injector + libcov + target run end-to-end
#                   under qemu-<arch>-static OR on real hardware, and the
#                   4 assertions of run_validation_inject.sh all pass.
#
#   BUILD_ONLY   -- cross-build of the injector binaries succeeds (the
#                   per-arch backend was wired up cleanly), but runtime
#                   validation is skipped. Either because:
#                     - The arch backend is a stub (arch_inject_<arch>.c
#                       returns supported=0 -> the injector refuses to
#                       attach at runtime with a clear message).
#                     - qemu-<arch>-static's ptrace support is too weak
#                       to drive the inject -> we don't bother trying.
#                     - The arch is fully supported but no qemu /
#                       real-hw runner is available in this environment.
#
#   FAIL         -- cross-build failed, or runtime validation was
#                   attempted and one or more assertions failed.
#
# Final line: "FULL_PASS=N  BUILD_ONLY=M  FAIL=K"
#
# We deliberately don't try to run all 11 backends under qemu-user-
# static even though the binaries cross-build cleanly:
#
#   - qemu-user's ptrace emulation is incomplete for several arches.
#     It works well enough for syscall emulation but PTRACE_GETREGSET
#     with NT_PRSTATUS, single-stepping through SYSCALL, and SIGSEGV
#     delivery at unmapped guest addresses are not all reliable.
#   - Spending ~30s per arch on a qemu run that may flake is not a
#     productive default.
#
# Real-hardware runtime validation for the 6 stub arches is
# blocked on those backends being implemented; see arch_inject_<arch>.c
# headers for the planned implementation.

set -eu

ROOT="${ROOT:-$(cd "$(dirname "$0")/../../.." && pwd)}"
INJ_DIR="$ROOT/tools/inject"
HOST_ARCH="$(uname -m)"

FULL_PASS=0
BUILD_ONLY=0
FAIL=0
RESULTS=()

ARCHES_FULL=(x86_64 aarch64)
# All other arches stay in build-only until either the per-arch backend
# implementation lands OR a real-hardware runner is added to this
# environment. Each is buildable today, so the cross-build matrix
# stays green.
ARCHES_BUILDONLY=(arm mips mipsel mips64 mips64el powerpc powerpc64 powerpc64le riscv64)

note() { printf '   %s\n' "$*"; }
hdr()  { printf '\n=== %s ===\n' "$*"; }

# Build everything first.
hdr "Cross-build every backend"
make -C "$INJ_DIR" all-arch > /tmp/inj_cross_build.log 2>&1 ||
    { echo "cross-build failed; see /tmp/inj_cross_build.log" >&2; exit 1; }
note "OK (11 arches built)"

# Full-pass: x86_64 (native), aarch64 (qemu attempt or skip).
for a in "${ARCHES_FULL[@]}"; do
    hdr "ARCH=$a -- FULL run"

    if ! [[ -x "$INJ_DIR/build/$a/inject_ptrace" ]]; then
        note "binary missing -> FAIL"
        FAIL=$((FAIL + 1))
        RESULTS+=("FAIL  $a (binary missing)")
        continue
    fi

    if [[ "$a" == "$HOST_ARCH" ]]; then
        # Native run -- delegate to run_validation_inject.sh
        if ARCH="$a" "$INJ_DIR/test/run_validation_inject.sh" > /tmp/inj_cross.$a.log 2>&1; then
            tail -1 /tmp/inj_cross.$a.log
            FULL_PASS=$((FULL_PASS + 1))
            RESULTS+=("PASS  $a (native)")
        else
            tail -5 /tmp/inj_cross.$a.log
            FAIL=$((FAIL + 1))
            RESULTS+=("FAIL  $a (native run)")
        fi
        continue
    fi

    # Non-native: would need qemu-<arch>-static. ptrace under qemu-user
    # is unreliable for our use case; document and skip.
    note "non-native $a: qemu-user ptrace emulation is unreliable for"
    note "this injector (PTRACE_GETREGSET / SINGLESTEP / SIGSEGV at"
    note "unmapped guest addresses); cross-build verified, runtime"
    note "validation skipped pending real-hardware runner."
    BUILD_ONLY=$((BUILD_ONLY + 1))
    RESULTS+=("BUILD_ONLY  $a (qemu ptrace too weak)")
done

# Build-only: stub arches.
for a in "${ARCHES_BUILDONLY[@]}"; do
    hdr "ARCH=$a -- BUILD-ONLY"

    if ! [[ -x "$INJ_DIR/build/$a/inject_ptrace" ]]; then
        note "binary missing -> FAIL"
        FAIL=$((FAIL + 1))
        RESULTS+=("FAIL  $a (binary missing)")
        continue
    fi
    note "cross-build OK; arch backend is a stub (see arch_inject_$(echo $a | sed 's/mipsel/mips/;s/mips64el/mips64/;s/powerpc64le/powerpc64/').c)"
    BUILD_ONLY=$((BUILD_ONLY + 1))
    RESULTS+=("BUILD_ONLY  $a (stub backend)")
done

echo
echo "================================================================"
printf " inject_ptrace cross matrix:  FULL_PASS=%d  BUILD_ONLY=%d  FAIL=%d\n" \
    "$FULL_PASS" "$BUILD_ONLY" "$FAIL"
echo "================================================================"
for r in "${RESULTS[@]}"; do printf '  %s\n' "$r"; done
if [[ $FAIL -gt 0 ]]; then exit 1; fi
exit 0
