/*
 * baremetal_mips.ld -- link the freestanding libcov core blob for a baremetal
 * MIPS32 (big-endian) target. The blob is loaded into the target's free RAM
 * and driven by calling libcov_init() explicitly; there is no C runtime, so
 * ENTRY is only a nominal symbol.
 *
 * The load base below is a generic default in kseg0 RAM. Set it (and the
 * LIBCOV_BM_ARENA_* / LIBCOV_BM_MODULE_* macros in plat_baremetal_mips.c) to
 * addresses in your target's free RAM that do not overlap its OS, the
 * instrumented code, or the blob's own image. See BAREMETAL.md.
 */
OUTPUT_ARCH(mips)
OUTPUT_FORMAT("elf32-tradbigmips")
ENTRY(libcov_core_entry)

SECTIONS
{
    . = 0x80430000;
    __libcov_core_start = .;

    .text : {
        *(.text.libcov_core_entry)
        *(.text .text.*)
    }

    . = ALIGN(16);
    .rodata : { *(.rodata .rodata.*) }

    . = ALIGN(16);
    .data : { *(.data .data.* .sdata .sdata.*) }

    . = ALIGN(16);
    __libcov_bss_start = .;
    .bss : { *(.sbss .sbss.*) *(.bss .bss.*) *(COMMON) }
    . = ALIGN(16);
    __libcov_bss_end = .;

    __libcov_core_end = .;

    /DISCARD/ : {
        *(.MIPS.abiflags)
        *(.reginfo)
        *(.gnu.attributes)
        *(.comment)
        *(.note .note.*)
        *(.pdr)
        *(.eh_frame .eh_frame_hdr)
    }
}
