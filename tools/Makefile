# tools/Makefile -- builds the auxiliary LD_PRELOAD libraries shipped
# with suzzer. Currently:
#
#   libdemalloc.so   -- bounded-quarantine heap-corruption catcher,
#                       suzzer's "poor man's ASan" for long-running
#                       embedded daemons. See libdemalloc.c for the
#                       full design and the compile-time knob list.
#
# Invocation patterns:
#
#   make tools                       (from project root: native build)
#   make tools ARCH=aarch64          (from project root: cross build)
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

LIB := $(BUILD)/libdemalloc.so

.PHONY: all clean print-vars

all: $(LIB)

$(BUILD):
	mkdir -p $@

# Single translation unit. No external deps -- not libpthread, not
# libatomic, not librt, not libdl. Whatever embedded toolchain you have
# should be able to build it.
$(LIB): libdemalloc.c | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -shared -Wl,-z,now -o $@ $<

clean:
	rm -f $(LIB)

print-vars:
	@echo "ARCH=$(ARCH) CROSS=$(CROSS) BUILD=$(BUILD)"
	@echo "CFLAGS=$(CFLAGS)"
	@echo "LIB=$(LIB)"
