/*
 * plat_linux.c -- Linux-userland platform backend.
 *
 * Phase 0: the trap-frame accessors are static-inline in plat.h (so the hot
 * path keeps the exact codegen it had when it read uc_mcontext.* directly),
 * which leaves this translation unit holding the platform identity only.
 * Later phases move the Linux implementations of trap install/chain, code
 * patching (mprotect + clear_cache + membarrier), the shm sink region,
 * /proc/self/maps module-base resolution, and fd logging here, behind the
 * plat_* interface, so plat_baremetal_mips.c can provide its own.
 */
#define _GNU_SOURCE
#include "plat.h"

const char *libcov_plat_name = "linux";
