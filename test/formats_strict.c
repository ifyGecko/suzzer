/*
 * formats_strict.c -- src/lcv_formats.h must stand alone.
 *
 * Built by `make test` with the strictest flags a known consumer uses
 * (-std=c11 -Wall -Wextra -Werror -Wshadow -Wstrict-prototypes
 * -Wmissing-prototypes) and nothing else on the include path, so a
 * dependency on another suzzer header, glibc or a runtime type fails the
 * build. Compiled with -c only; there is nothing to run.
 */
#include "../src/lcv_formats.h"

/* Touch one definition from each format so an accidental #if around a
 * section is caught too. */
typedef char lcv_formats_strict_check[
    (sizeof(struct patchlist_header_v3) + sizeof(struct patchlist_record) +
     sizeof(struct lcvb_header) + sizeof(struct lcvb_record) +
     sizeof(struct libcov_shm_header) + sizeof(struct libcov_ring_slot_hdr) +
     SZR_CRASH_TIMEOUT + LCV_FLAG_MODULE_BASES) > 0 ? 1 : -1];
