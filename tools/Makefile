# tools/Makefile -- builds the auxiliary LD_PRELOAD libraries shipped
# with suzzer. Currently:
#
#   libdemalloc.so   -- bounded-quarantine heap-corruption catcher,
#                       suzzer's "poor man's ASan" for long-running
#                       embedded daemons. See libdemalloc.c for the
#                       full design and the compile-time knob list.
#   suzzer-relay      -- on-device coverage relay for remote (over-IP)
#                       fuzzing; built by the `relay` goal (not `all`,
#                       which stays the opt-in libdemalloc). See
#                       suzzer-relay.c and HOWTO.md Pattern C.
#
# Invocation patterns:
#
#   make tools                       (from project root: native libdemalloc)
#   make tools ARCH=aarch64          (from project root: cross build)
#   make -C tools relay ARCH=.. CROSS=..- BUILD=/path/to/build/<arch>
#
# Direct invocation (from this directory):
#
#   make ARCH=<arch> CROSS=<prefix>- BUILD=/path/to/build/<arch>
#
# The top-level Makefile passes ARCH, CROSS, and BUILD when descending.
# `make tools` is intentionally NOT pulled by `make all-arch` -- libdemalloc
# is opt-in and independent of libcov's ST/MT threading axis.
#
# EXTRA_CFLAGS is forwarded to the compile line so users can override any
# compile-time tunable, e.g.:
#
#   make tools EXTRA_CFLAGS='-DLIBDEM_QUARANTINE_SLOTS=256 \
#                            -DLIBDEM_ALIGN_ALLOCATIONS=1'

ARCH  ?= $(shell uname -m)
CROSS ?=
BUILD ?= ../build/$(ARCH)

CC      := $(CROSS)gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?=

ifeq ($(ARCH),arm)
  CFLAGS += -marm
endif

CFLAGS += $(EXTRA_CFLAGS)

LIB   := $(BUILD)/libdemalloc.so
RELAY := $(BUILD)/suzzer-relay

.PHONY: all clean print-vars relay

all: $(LIB)

relay: $(RELAY)

$(BUILD):
	mkdir -p $@

# On-device coverage relay. Reuses the client-side ring reader in
# src/ring_reader.h (-I../src) and, like fuzz_driver, pulls in libatomic
# only where 64-bit atomics aren't inline (32-bit mips/powerpc).
$(RELAY): suzzer-relay.c relay_proto.h ../src/ring_reader.h ../src/boundary.h | $(BUILD)
	$(CC) $(CFLAGS) -MMD -MP -I../src -o $@ suzzer-relay.c \
	    -Wl,--as-needed -latomic

# Single translation unit. No external deps -- not libpthread, not
# libatomic, not librt, not libdl. Whatever embedded toolchain you have
# should be able to build it. -MMD -MP emits a .d sidecar so editing a
# header libdemalloc.c includes rebuilds it; -include'd below.
$(LIB): libdemalloc.c | $(BUILD)
	$(CC) $(CFLAGS) -MMD -MP -fPIC -shared -Wl,-z,now -o $@ $<

-include $(wildcard $(BUILD)/*.d)

clean:
	rm -f $(LIB) $(RELAY) $(BUILD)/*.d

print-vars:
	@echo "ARCH=$(ARCH) CROSS=$(CROSS) BUILD=$(BUILD)"
	@echo "CFLAGS=$(CFLAGS)"
	@echo "LIB=$(LIB)"
	@echo "RELAY=$(RELAY)"
