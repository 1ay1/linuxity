/* Lays the fast path blob out flat: header first, then code, read-only
   constants last. Nothing may need a runtime relocation. */
ENTRY(lx_fp_header)
SECTIONS {
    . = 0;
    .lx_header : { KEEP(*(.lx_header)) }
    .text : { *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    /DISCARD/ : { *(.data .data.* .bss .bss.* .got .got.* .comment .note.* .eh_frame* .dynamic .dynsym .dynstr .rela.* .hash .gnu.hash) }
}
