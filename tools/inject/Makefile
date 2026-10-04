# tools/inject/Makefile -- standalone build for the libcov injector tools.
#
# Produces two binaries per (ARCH) cell of the matrix:
#
#   tools/inject/build/<arch>/inject_ptrace   -- ptrace-based injector
#                                                (PHASE 1-6: fully working
#                                                 on x86_64 + aarch64;
#                                                 other arches refuse at
#                                                 runtime with a clear msg)
#   tools/inject/build/<arch>/inject_procmem  -- ptrace-less injector
#                                                (PHASE 7: build only;
#                                                 exits 64 at runtime
#                                                 pending shellcode + sigframe
#                                                 implementation)
#
# Plus the test target (used by run_validation_inject.sh):
#
#   tools/inject/build/<arch>/target_inject_loop
#
# This Makefile is DELIBERATELY standalone -- it does not touch the
# top-level Makefile, and the top-level Makefile does not invoke it.
# This honours the project's "injector stays out of libcov internals"
# constraint. Build it manually:
#
#   make                                  -- native build
#   make ARCH=aarch64                     -- cross-build
#   make all-arch                         -- both injectors for every arch
#   make test                             -- build the test target too
#   make clean
#
# Output paths are disjoint from the libcov build tree (build/<arch>/
# at the project root) so the two never collide.

ifeq ($(ARCH),)
ARCH := $(shell uname -m)
endif

# Same ARCH -> BACKEND + CROSS mapping as the top-level Makefile.
# Kept locally so this Makefile is standalone.
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
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
LDFLAGS ?=
CFLAGS  += $(EXTRA_CFLAGS)

ifeq ($(ARCH),arm)
  CFLAGS += -marm
endif

BUILD := build/$(ARCH)

# All arch backends are linked into both injectors -- the runtime
# vtable selector picks one. Stub backends are tiny (one struct) so
# the size cost is negligible.
ARCH_OBJS := \
    $(BUILD)/arch_inject_x86_64.o \
    $(BUILD)/arch_inject_aarch64.o \
    $(BUILD)/arch_inject_arm.o \
    $(BUILD)/arch_inject_mips.o \
    $(BUILD)/arch_inject_mips64.o \
    $(BUILD)/arch_inject_powerpc.o \
    $(BUILD)/arch_inject_powerpc64.o \
    $(BUILD)/arch_inject_riscv64.o

COMMON_OBJ := $(BUILD)/inject_common.o

PTRACE_BIN  := $(BUILD)/inject_ptrace
PROCMEM_BIN := $(BUILD)/inject_procmem

PTRACE_OBJ  := $(BUILD)/inject_ptrace.o
PROCMEM_OBJ := $(BUILD)/inject_procmem.o

LOOP_BIN := $(BUILD)/target_inject_loop

.PHONY: all clean all-arch test print-vars

all: $(PTRACE_BIN) $(PROCMEM_BIN)

test: all $(LOOP_BIN)

$(BUILD):
	mkdir -p $@

# Generic C compile rule. Header dependencies are listed explicitly per
# object so a header change forces a rebuild of every dependent .o.
$(BUILD)/%.o: %.c arch_inject.h inject_common.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# Both injectors link the same common+arch object set, with a different
# main on top.
$(PTRACE_BIN): $(PTRACE_OBJ) $(COMMON_OBJ) $(ARCH_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(PROCMEM_BIN): $(PROCMEM_OBJ) $(COMMON_OBJ) $(ARCH_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Test target -- a long-running daemon-style program with a known branch
# graph. Built with -no-pie -O0 for deterministic addresses, same as
# libcov's other test targets. The injector targets THIS binary in
# tools/inject/test/run_validation_inject.sh.
LOOP_CFLAGS := -O0 -g -no-pie -fno-stack-protector
ifeq ($(ARCH),arm)
  LOOP_CFLAGS += -marm
endif

$(LOOP_BIN): test/target_inject_loop.c | $(BUILD)
	$(CC) $(LOOP_CFLAGS) -o $@ $<

ARCHES_ALL := x86_64 aarch64 arm mips mipsel mips64 mips64el \
              powerpc powerpc64 powerpc64le riscv64

all-arch:
	@for a in $(ARCHES_ALL); do \
	    echo "=== inject ARCH=$$a ==="; \
	    $(MAKE) --no-print-directory ARCH=$$a || exit $$?; \
	done

clean:
	rm -rf build

print-vars:
	@echo "ARCH=$(ARCH) BACKEND=$(BACKEND) CROSS=$(CROSS)"
	@echo "CC=$(CC)"
	@echo "CFLAGS=$(CFLAGS)"
	@echo "BUILD=$(BUILD)"
	@echo "PTRACE_BIN=$(PTRACE_BIN)"
	@echo "PROCMEM_BIN=$(PROCMEM_BIN)"
