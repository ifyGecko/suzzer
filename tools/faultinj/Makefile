# tools/faultinj/Makefile -- standalone build for libfaultinj.so and
# its test targets.
#
# Produces, per ARCH cell:
#
#   tools/faultinj/build/<arch>/libfaultinj.so      -- the LD_PRELOAD shim
#   tools/faultinj/build/<arch>/target_faultinj_simple
#   tools/faultinj/build/<arch>/target_faultinj_net
#
# Like tools/inject/Makefile, this Makefile is DELIBERATELY standalone:
# it does not touch the top-level Makefile, and the top-level Makefile
# does not invoke it. libfaultinj is opt-in and orthogonal to the
# libcov ST/MT axis, so it stays out of the main build matrix until
# someone explicitly asks for it.
#
# Invocation:
#
#   make                        -- native build of .so + test targets
#   make ARCH=aarch64           -- cross-build
#   make all-arch               -- build for every supported arch
#   make test                   -- alias for `all` (kept for symmetry)
#   make validate               -- build + run tools/faultinj/test/
#                                  run_validation_faultinj.sh
#   make clean
#
# Compile-time knob pass-through follows the tools/Makefile convention:
#
#   make EXTRA_CFLAGS='-DFI_MAX_SKIP_FDS=32'
#
# Output paths are disjoint from libcov's build tree (build/<arch>/ at
# project root) and from tools/inject/build/<arch>/ -- the three never
# collide.

ifeq ($(ARCH),)
ARCH := $(shell uname -m)
endif

# ARCH -> cross-compiler prefix + qemu binary. Kept inline (not
# included from the top-level Makefile) so this file stays standalone.
ifeq ($(ARCH),x86_64)
  CROSS   :=
  QEMU    := qemu-x86_64-static
else ifeq ($(ARCH),aarch64)
  CROSS   := aarch64-linux-gnu-
  QEMU    := qemu-aarch64-static
else ifeq ($(ARCH),arm)
  CROSS   := arm-linux-gnueabihf-
  QEMU    := qemu-arm-static
else ifeq ($(ARCH),mips)
  CROSS   := mips-linux-gnu-
  QEMU    := qemu-mips-static
else ifeq ($(ARCH),mipsel)
  CROSS   := mipsel-linux-gnu-
  QEMU    := qemu-mipsel-static
else ifeq ($(ARCH),mips64)
  CROSS   := mips64-linux-gnuabi64-
  QEMU    := qemu-mips64-static
else ifeq ($(ARCH),mips64el)
  CROSS   := mips64el-linux-gnuabi64-
  QEMU    := qemu-mips64el-static
else ifeq ($(ARCH),powerpc)
  CROSS   := powerpc-linux-gnu-
  QEMU    := qemu-ppc-static
else ifeq ($(ARCH),powerpc64)
  CROSS   := powerpc64-linux-gnu-
  QEMU    := qemu-ppc64-static
else ifeq ($(ARCH),powerpc64le)
  CROSS   := powerpc64le-linux-gnu-
  QEMU    := qemu-ppc64le-static
else ifeq ($(ARCH),riscv64)
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

LIB         := $(BUILD)/libfaultinj.so
TARGET_FILE := $(BUILD)/target_faultinj_simple
TARGET_NET  := $(BUILD)/target_faultinj_net

# Test targets are built -O0 -no-pie -fno-stack-protector for the same
# reason as test/target_simple.c in the top-level libcov tree: predictable
# branch layout for the validation harness. They don't need -fPIC.
TARGET_CFLAGS := -O0 -g -no-pie -fno-stack-protector -D_GNU_SOURCE
ifeq ($(ARCH),arm)
  TARGET_CFLAGS += -marm
endif

.PHONY: all test validate clean all-arch print-vars

all: $(LIB) $(TARGET_FILE) $(TARGET_NET)

# Alias kept for parity with the inject Makefile's "make test" recipe.
test: all

$(BUILD):
	mkdir -p $@

# The library has zero non-libc deps. -ldl for dlsym(RTLD_NEXT, ...).
# -Wl,-z,now matches the libdemalloc / libcov posture: full relro +
# eager binding so the loader resolves everything at load time and
# our hooks can't trip a lazy-binding fault during signal handling.
$(LIB): libfaultinj.c faultinj_classes.h faultinj_prng.h | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -shared -Wl,-z,now -o $@ libfaultinj.c -ldl

$(TARGET_FILE): test/target_faultinj_simple.c | $(BUILD)
	$(CC) $(TARGET_CFLAGS) -o $@ $<

$(TARGET_NET): test/target_faultinj_net.c | $(BUILD)
	$(CC) $(TARGET_CFLAGS) -o $@ $<

# Run the validation harness against the just-built artefacts. ARCH is
# forwarded so the script picks up the right build/<arch>/ directory.
validate: all
	ARCH=$(ARCH) ./test/run_validation_faultinj.sh

ARCHES_ALL := x86_64 aarch64 arm mips mipsel mips64 mips64el \
              powerpc powerpc64 powerpc64le riscv64

all-arch:
	@for a in $(ARCHES_ALL); do \
	    echo "=== faultinj ARCH=$$a ==="; \
	    $(MAKE) --no-print-directory ARCH=$$a || exit $$?; \
	done

clean:
	rm -rf build

print-vars:
	@echo "ARCH=$(ARCH) CROSS=$(CROSS)"
	@echo "CC=$(CC)"
	@echo "CFLAGS=$(CFLAGS)"
	@echo "BUILD=$(BUILD)"
	@echo "LIB=$(LIB)"
	@echo "TARGET_FILE=$(TARGET_FILE)"
	@echo "TARGET_NET=$(TARGET_NET)"
