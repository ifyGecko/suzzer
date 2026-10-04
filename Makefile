# libcov -- trap-trampoline coverage library (multi-arch, multi-threading).
#
# Trap signal is SIGILL by default for every backend. Override via
# -DLIBCOV_TRAP_SIGNO=<signo> (and a matching per-arch illegal encoding)
# through EXTRA_CFLAGS; see src/tunables.h and src/tunables_<arch>.h.
#
# Two threading variants are built as separate LEGO bricks:
#   THREADING=st (default) -- single-threaded, low overhead, the original PoC.
#   THREADING=mt           -- multi-threaded safe: TLS prev_loc, atomic bitmap,
#                              atomic per-site state machine,
#                              /proc/self/mem writes + membarrier(SYNC_CORE).
#
# Usage:
#   make                                 -- native ST build
#   make THREADING=mt                    -- native MT build
#   make ARCH=aarch64 THREADING=mt       -- cross-build MT for aarch64
#   make all-arch                        -- ST for every arch
#   make all-arch THREADING=mt           -- MT for every arch
#   make all-variants                    -- ST and MT for every arch
#
# Output (one .so per (ARCH, THREADING) combo):
#   build/<arch>/libcov_<threading>.so
#   build/<arch>/target_simple
#   build/<arch>/fuzz_driver
#
# target_simple_mt (pthread stress) is built on demand by the MT validation
# scripts via `make -C test target_simple_mt`.

ifeq ($(ARCH),)
ARCH := $(shell uname -m)
endif

THREADING ?= st
ifeq ($(filter $(THREADING),st mt),)
$(error THREADING must be 'st' or 'mt', got '$(THREADING)')
endif

# Map ARCH to backend source + cross-compiler prefix.
# Backend source: src/arch_<BACKEND>.c (ST) or src/arch_<BACKEND>_mt.c (MT
# if an arch-specific MT variant exists; else the same ST source).
ifeq ($(ARCH),x86_64)
  BACKEND := x86_64
  CROSS   :=
  QEMU    := qemu-x86_64-static
else ifeq ($(ARCH),aarch64)
  BACKEND := aarch64
  CROSS   := aarch64-linux-gnu-
  QEMU    := qemu-aarch64-static
else ifeq ($(ARCH),arm)
  BACKEND := arm
  CROSS   := arm-linux-gnueabihf-
  QEMU    := qemu-arm-static
else ifeq ($(ARCH),mips)
  BACKEND := mips
  CROSS   := mips-linux-gnu-
  QEMU    := qemu-mips-static
else ifeq ($(ARCH),mipsel)
  BACKEND := mips
  CROSS   := mipsel-linux-gnu-
  QEMU    := qemu-mipsel-static
else ifeq ($(ARCH),mips64)
  BACKEND := mips64
  CROSS   := mips64-linux-gnuabi64-
  QEMU    := qemu-mips64-static
else ifeq ($(ARCH),mips64el)
  BACKEND := mips64
  CROSS   := mips64el-linux-gnuabi64-
  QEMU    := qemu-mips64el-static
else ifeq ($(ARCH),powerpc)
  BACKEND := powerpc
  CROSS   := powerpc-linux-gnu-
  QEMU    := qemu-ppc-static
else ifeq ($(ARCH),powerpc64)
  BACKEND := powerpc64
  CROSS   := powerpc64-linux-gnu-
  QEMU    := qemu-ppc64-static
else ifeq ($(ARCH),powerpc64le)
  BACKEND := powerpc64
  CROSS   := powerpc64le-linux-gnu-
  QEMU    := qemu-ppc64le-static
else ifeq ($(ARCH),riscv64)
  BACKEND := riscv64
  CROSS   := riscv64-linux-gnu-
  QEMU    := qemu-riscv64-static
else
  $(error unsupported ARCH=$(ARCH))
endif

CC      := $(CROSS)gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?=

ifeq ($(ARCH),arm)
  CFLAGS += -marm
endif

# Every TLS variable libcov touches in the trap handler (prev_loc window,
# PC cache, leapfrog state, boundary scratch) must resolve without
# __tls_get_addr, which can allocate. initial-exec makes each access a
# fixed offset from the thread pointer. Fine for LD_PRELOAD (loaded at
# startup); a dlopen'ed libcov needs glibc's static TLS surplus, which
# comfortably covers libcov's few hundred bytes.
CFLAGS += -ftls-model=initial-exec

# Pick threading-specific source set. Some files (config.c, sink_shm.c) are
# the same source compiled with a different -D toggle; others (patch_*.c,
# handler_*.c) are separate sources entirely.
ifeq ($(THREADING),mt)
  CFLAGS += -DLIBCOV_THREADING_MT
  PATCH_SRC   := src/patch_mt.c
  HANDLER_SRC := src/handler_mt.c
  EXTRA_SRC   := src/membarrier.c
  ARCH_SRC    := src/arch_$(BACKEND).c
  # The arch backend handles ST/MT differences internally via
  # #ifdef LIBCOV_THREADING_MT (e.g. arch_x86_64.c writes UD2 head-only
  # in MT, UD2+NOPs in ST). For fixed-width arches the natural 2- or
  # 4-byte write is already single-copy-atomic, so no #ifdef is needed.
  #
  # MT prev_loc uses __thread; pthreads linkage is required because libc
  # only allocates the static TLS area when the binary or any DSO it loads
  # is linked against pthreads. LD_PRELOAD'ing a TLS-using .so into a
  # non-pthread target works on glibc only with -lpthread on the .so.
  LDLIBS_EXTRA := -lpthread
else
  CFLAGS += -DLIBCOV_THREADING_ST
  PATCH_SRC   := src/patch_st.c
  HANDLER_SRC := src/handler_st.c
  EXTRA_SRC   :=
  ARCH_SRC    := src/arch_$(BACKEND).c
  LDLIBS_EXTRA :=
endif

# User pass-through for tunables overrides. Example:
#   make EXTRA_CFLAGS='-DLIBCOV_ARCH_MIPS_ILLEGAL=0xDEADBEEFu'
# CFLAGS is the toolchain baseline (already overridable); EXTRA_CFLAGS is
# appended so users can add -D flags without losing the defaults.
CFLAGS += $(EXTRA_CFLAGS)

BUILD := build/$(ARCH)

COMMON_SRC := src/libcov.c src/util.c src/config.c src/sink_shm.c src/boundary.c
SRC := $(COMMON_SRC) $(PATCH_SRC) $(HANDLER_SRC) $(EXTRA_SRC) $(ARCH_SRC)

# Object files go into a threading-suffixed subdir to keep ST and MT builds
# from clobbering each other's .o files for the same source.
OBJDIR := $(BUILD)/obj_$(THREADING)
OBJ    := $(patsubst src/%.c,$(OBJDIR)/%.o,$(SRC))

DEP := $(OBJ:.o=.d)

LIB := $(BUILD)/libcov_$(THREADING).so

# Plain `make` means `all`. Pinned because the included .d files (end of
# file) contain rules, and the first rule make sees is otherwise the
# default goal: `make` would just rebuild libcov.o.
.DEFAULT_GOAL := all

.PHONY: all clean test test-targets all-arch all-variants native print-vars tools tools-clean

all: $(LIB) test-targets

native: $(LIB)

$(BUILD) $(OBJDIR):
	mkdir -p $@

$(OBJDIR)/%.o: src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -MMD -MP -fPIC -c $< -o $@

$(LIB): $(OBJ) | $(BUILD)
	$(CC) $(CFLAGS) -shared -fPIC -Wl,-z,now -o $@ $^ \
	    -ldl -lrt $(LDLIBS_EXTRA) -Wl,--as-needed -latomic
# -Wl,--as-needed -latomic pulls libatomic in only when the toolchain
# can't inline 64-bit atomics (32-bit arches: mips, mipsel, powerpc).
# boundary.c's gen_current/gen_init use 64-bit atomics; on 64-bit
# arches __atomic_*_8 is inline and libatomic stays unlinked.

test-targets: $(LIB)
	$(MAKE) -C test ARCH=$(ARCH) CROSS=$(CROSS) BUILD=$(abspath $(BUILD))

# `make test`: build both library variants and every test target, then
# run every native validation suite (test/run_all.sh prints a summary and
# keeps the logs of failing suites). Native only -- the cross suites are
# test/run_cross.sh and test/run_cross_mt.sh.
NATIVE_SUITES := run_validation run_validation_mt run_validation_boundary \
                 run_validation_boundary_mt run_validation_multimod \
                 run_validation_signals run_validation_coverage_options \
                 run_validation_failloud run_validation_generator \
                 run_validation_generator_safety \
                 run_validation_o2pie run_validation_marker_emulation \
                 run_validation_reexec run_validation_modules \
                 run_validation_patch_mode run_validation_paired

test:
ifneq ($(ARCH),$(shell uname -m))
	$(error make test runs the native suites; for ARCH=$(ARCH) use test/run_cross.sh / test/run_cross_mt.sh)
endif
	@# Plain `make` must still build the test targets (a stray rule from an
	@# included .d file once became the default goal).
	@$(MAKE) --no-print-directory -n 2>/dev/null | grep -q -- '-C test' \
	    || { echo "FAIL: plain 'make' no longer builds 'all'" >&2; exit 1; }
	$(MAKE) --no-print-directory THREADING=st native
	$(MAKE) --no-print-directory THREADING=mt native
	$(MAKE) --no-print-directory -C test ARCH=$(ARCH) BUILD=$(abspath $(BUILD)) all mt multimod o2pie
	./test/run_all.sh $(NATIVE_SUITES)

# Opt-in build of the auxiliary tooling LD_PRELOADs (currently
# libdemalloc.so). Independent of THREADING and intentionally NOT
# pulled by `all` or `all-arch` -- libdemalloc is opt-in.
tools: | $(BUILD)
	$(MAKE) -C tools ARCH=$(ARCH) CROSS=$(CROSS) BUILD=$(abspath $(BUILD)) \
	    EXTRA_CFLAGS='$(EXTRA_CFLAGS)'

tools-clean:
	$(MAKE) -C tools ARCH=$(ARCH) CROSS=$(CROSS) BUILD=$(abspath $(BUILD)) clean

clean:
	rm -rf build
	$(MAKE) -C test clean

ARCHES_ALL := x86_64 aarch64 arm mips mipsel mips64 mips64el \
              powerpc powerpc64 powerpc64le riscv64

all-arch:
	@for a in $(ARCHES_ALL); do \
	    echo "=== ARCH=$$a THREADING=$(THREADING) ==="; \
	    $(MAKE) --no-print-directory ARCH=$$a THREADING=$(THREADING) || exit $$?; \
	done

all-variants:
	@for t in st mt; do \
	    $(MAKE) --no-print-directory all-arch THREADING=$$t || exit $$?; \
	done

print-vars:
	@echo "ARCH=$(ARCH) BACKEND=$(BACKEND) THREADING=$(THREADING)"
	@echo "SRC=$(SRC)"
	@echo "LIB=$(LIB)"

# Auto-generated header dependencies (-MMD -MP in the compile rule).
# Editing a header rebuilds every object that includes it. .d files live
# in OBJDIR (per arch+threading) and are removed by `clean` (rm -rf build).
# Kept last so none of their rules can become the default goal.
-include $(DEP)
