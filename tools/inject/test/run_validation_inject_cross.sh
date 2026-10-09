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
#   SKIP         -- the arch's cross gcc is not installed; nothing was
#                   built or run for it.
#
#   FAIL         -- cross-build failed, or runtime validation was
#                   attempted and one or more assertions failed.
#
# Summary line: "FULL_PASS=N  BUILD_ONLY=M  SKIP=S  FAIL=K"
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
# Real-hardware runtime validation for the build-only arches
# (ARCHES_BUILDONLY below: arm, mips, mipsel, mips64, mips64el, powerpc,
# powerpc64, powerpc64le, riscv64 -- 9 arches sharing 6 stub backends,
# arch_inject_{arm,mips,mips64,powerpc,powerpc64,riscv64}.c) is blocked on
# those backends being implemented; see the arch_inject_<arch>.c headers
# for the planned implementation.

set -eu

ROOT="${ROOT:-$(cd "$(dirname "$0")/../../.." && pwd)}"
INJ_DIR="$ROOT/tools/inject"
HOST_ARCH="$(uname -m)"

FULL_PASS=0
BUILD_ONLY=0
SKIP=0
FAIL=0
RESULTS=()

# Per-run scratch dir for the build / run logs (fixed /tmp paths made
# parallel runs collide). Kept, with its path printed, when anything fails.
WORK=$(mktemp -d -t libcov_inject_cross.XXXXXX)
keep_work_on_failure() {
    local rc=$?
    if [[ $rc -eq 0 ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK" >&2; fi
    return $rc
}
trap keep_work_on_failure EXIT

ARCHES_FULL=(x86_64 aarch64)
# All other arches stay in build-only until either the per-arch backend
# implementation lands OR a real-hardware runner is added to this
# environment. Each is buildable today, so the cross-build matrix
# stays green.
ARCHES_BUILDONLY=(arm mips mipsel mips64 mips64el powerpc powerpc64 powerpc64le riscv64)

note() { printf '   %s\n' "$*"; }
hdr()  { printf '\n=== %s ===\n' "$*"; }

# Build every arch first, one at a time, so a missing toolchain or one
# broken backend doesn't stop the matrix. STATUS[arch] = built | skip | fail.
declare -A STATUS=()
hdr "Cross-build every backend"
for a in "${ARCHES_FULL[@]}" "${ARCHES_BUILDONLY[@]}"; do
    cc=$(make -s --no-print-directory -C "$INJ_DIR" ARCH="$a" print-vars \
         | sed -n 's/^CC=//p')
    if [[ -z "$cc" ]] || ! command -v "$cc" >/dev/null; then
        note "$a: SKIP (${cc:-cross gcc} not found)"
        STATUS[$a]=skip; SKIP=$((SKIP + 1))
        RESULTS+=("SKIP  $a (${cc:-cross gcc} not found)")
        continue
    fi
    if make --no-print-directory -C "$INJ_DIR" ARCH="$a" > "$WORK/build.$a.log" 2>&1; then
        note "$a: built"
        STATUS[$a]=built
    else
        note "$a: build FAILED (log: $WORK/build.$a.log)"
        tail -5 "$WORK/build.$a.log" | sed 's/^/      /'
        STATUS[$a]=fail; FAIL=$((FAIL + 1))
        RESULTS+=("FAIL  $a (build)")
    fi
done

# Full-pass: x86_64 (native), aarch64 (qemu attempt or skip).
for a in "${ARCHES_FULL[@]}"; do
    [[ ${STATUS[$a]} == built ]] || continue
    hdr "ARCH=$a -- FULL run"

    if ! [[ -x "$INJ_DIR/build/$a/inject_ptrace" ]]; then
        note "binary missing -> FAIL"
        FAIL=$((FAIL + 1))
        RESULTS+=("FAIL  $a (binary missing)")
        continue
    fi

    if [[ "$a" == "$HOST_ARCH" ]]; then
        # Native run -- delegate to run_validation_inject.sh, which needs
        # the test target (`make test`) on top of the injectors.
        if ! make --no-print-directory -C "$INJ_DIR" ARCH="$a" test \
                > "$WORK/build.$a.test.log" 2>&1; then
            tail -5 "$WORK/build.$a.test.log"
            FAIL=$((FAIL + 1))
            RESULTS+=("FAIL  $a (build target_inject_loop)")
            continue
        fi
        if ARCH="$a" "$INJ_DIR/test/run_validation_inject.sh" > "$WORK/run.$a.log" 2>&1; then
            tail -1 "$WORK/run.$a.log"
            FULL_PASS=$((FULL_PASS + 1))
            RESULTS+=("PASS  $a (native)")
        else
            tail -5 "$WORK/run.$a.log"
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
    [[ ${STATUS[$a]} == built ]] || continue
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
printf " inject_ptrace cross matrix:  FULL_PASS=%d  BUILD_ONLY=%d  SKIP=%d  FAIL=%d\n" \
    "$FULL_PASS" "$BUILD_ONLY" "$SKIP" "$FAIL"
echo "================================================================"
for r in "${RESULTS[@]}"; do printf '  %s\n' "$r"; done
if [[ $FULL_PASS -eq 0 && $BUILD_ONLY -eq 0 && $FAIL -eq 0 ]]; then
    echo "NOTE: every arch was skipped -- nothing was built or tested."
fi
if [[ $FAIL -gt 0 ]]; then exit 1; fi
exit 0
