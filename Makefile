# libcov -- SIGILL-trampoline coverage library (multi-arch, multi-threading).
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

# Pick threading-specific source set. Some files (config.c, sink_shm.c) are
# the same source compiled with a different -D toggle; others (patch_*.c,
# handler_*.c) are separate sources entirely.
ifeq ($(THREADING),mt)
  CFLAGS += -DLIBCOV_THREADING_MT
  PATCH_SRC   := src/patch_mt.c
  HANDLER_SRC := src/handler_mt.c
  EXTRA_SRC   := src/membarrier.c
  # x86_64 has a dedicated MT backend (UD2 head-only); other arches reuse
  # their ST backend since their natural 2- or 4-byte writes are already
  # single-copy-atomic at the trap-encoding width.
  ifeq ($(BACKEND),x86_64)
    ARCH_SRC := src/arch_x86_64_mt.c
  else
    ARCH_SRC := src/arch_$(BACKEND).c
  endif
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

BUILD := build/$(ARCH)

COMMON_SRC := src/libcov.c src/util.c src/config.c src/sink_shm.c
SRC := $(COMMON_SRC) $(PATCH_SRC) $(HANDLER_SRC) $(EXTRA_SRC) $(ARCH_SRC)

# Object files go into a threading-suffixed subdir to keep ST and MT builds
# from clobbering each other's .o files for the same source.
OBJDIR := $(BUILD)/obj_$(THREADING)
OBJ    := $(patsubst src/%.c,$(OBJDIR)/%.o,$(SRC))

LIB := $(BUILD)/libcov_$(THREADING).so

.PHONY: all clean test all-arch all-variants native print-vars

all: $(LIB) test

native: $(LIB)

$(BUILD) $(OBJDIR):
	mkdir -p $@

$(OBJDIR)/%.o: src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(LIB): $(OBJ) | $(BUILD)
	$(CC) $(CFLAGS) -shared -fPIC -Wl,-z,now -o $@ $^ -ldl -lrt $(LDLIBS_EXTRA)

test: $(LIB)
	$(MAKE) -C test ARCH=$(ARCH) CROSS=$(CROSS) BUILD=$(abspath $(BUILD))

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
