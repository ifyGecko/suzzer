/*
 * baremetal_mips.ld -- link the freestanding libcov core blob for the
 * TP-Link WR720N v2 (MIPS32 big-endian, VxWorks). The blob is loaded into
 * the firmware's free RAM and driven by calling libcov_init() explicitly;
 * there is no C runtime, so ENTRY is only a nominal symbol.
 *
 * Base 0x80430000 sits in the free-RAM arena (heap/stacks region
 * 0x80429ad0..0x81000000, RECON.md), clear of the OS text/data/BSS below it.
 * Phase 2/3 reconcile this with the bitmap/scratch arena so they don't
 * overlap the blob's own image.
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
