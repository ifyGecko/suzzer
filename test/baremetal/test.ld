OUTPUT_ARCH(mips)
OUTPUT_FORMAT("elf32-tradbigmips")
ENTRY(_start)
SECTIONS {
    . = 0x80100000;
    .text : { *(.text._start) *(.text .text.*) }
    . = ALIGN(16); .rodata : { *(.rodata .rodata.*) }
    . = ALIGN(16); .data   : { *(.data .data.* .sdata .sdata.*) }
    . = ALIGN(16); __bss_start = .;
    .bss : { *(.sbss .sbss.*) *(.bss .bss.*) *(COMMON) }
    . = ALIGN(16); __bss_end = .;
    . = ALIGN(16); . = . + 0x10000; _stack_top = .;
    /DISCARD/ : { *(.MIPS.abiflags) *(.reginfo) *(.gnu.attributes) *(.comment) *(.note .note.*) *(.pdr) *(.eh_frame*) }
}
