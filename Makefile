# libcov -- SIGILL/SIGTRAP-trampoline coverage library (multi-arch PoC)
#
# Usage:
#   make                    -- native build
#   make ARCH=aarch64       -- cross-compile (auto-picks aarch64-linux-gnu-gcc)
#   make ARCH=arm           -- cross-compile armv7 (arm-linux-gnueabihf-gcc)
#   make all-arch           -- build every supported arch
#   make ARCH=aarch64 test  -- build + run target/driver for that arch
#
# Output:
#   build/<arch>/libcov.so
#   build/<arch>/target_simple
#   build/<arch>/fuzz_driver

ifeq ($(ARCH),)
ARCH := $(shell uname -m)
endif

# Map ARCH to backend source + cross-compiler prefix.
# Backend source: src/arch_<BACKEND>.c
# CROSS prefix:   <prefix>gcc, <prefix>strip, etc.
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

# arm needs -marm so the library itself is built ARM (not Thumb) to keep
# our code reachable from any caller; target_simple may be either.
ifeq ($(ARCH),arm)
  CFLAGS += -marm
endif

# For mipsel/mips64el, the toolchain prefix already selects the endianness.

BUILD := build/$(ARCH)

COMMON_SRC := src/libcov.c src/util.c src/config.c src/patch.c src/handler.c src/sink_shm.c
ARCH_SRC   := src/arch_$(BACKEND).c
SRC        := $(COMMON_SRC) $(ARCH_SRC)
OBJ        := $(patsubst src/%.c,$(BUILD)/%.o,$(SRC))

LIB := $(BUILD)/libcov.so

.PHONY: all clean test all-arch native

all: $(LIB) test

native: $(LIB)

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(LIB): $(OBJ) | $(BUILD)
	$(CC) $(CFLAGS) -shared -fPIC -Wl,-z,now -o $@ $^ -ldl -lrt

test: $(LIB)
	$(MAKE) -C test ARCH=$(ARCH) CROSS=$(CROSS) BUILD=$(abspath $(BUILD))

clean:
	rm -rf build
	$(MAKE) -C test clean

ARCHES_ALL := x86_64 aarch64 arm mips mipsel mips64 mips64el \
              powerpc powerpc64 powerpc64le riscv64

all-arch:
	@for a in $(ARCHES_ALL); do \
	    echo "=== ARCH=$$a ==="; \
	    $(MAKE) --no-print-directory ARCH=$$a || exit $$?; \
	done
