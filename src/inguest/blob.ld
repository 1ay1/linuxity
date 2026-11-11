/* Lays the in-guest blob out flat: header first, then code, read-only
   constants last. Nothing may need a runtime relocation. */
ENTRY(lx_ig_header)
SECTIONS {
    . = 0;
    .lx_header : { KEEP(*(.lx_header)) }
    .text : { *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    /* GNU ld on aarch64 always emits .got and .got.plt with their reserved
       header words (all zero) and refuses to discard them, which failed the
       Linux/aarch64 link. Nothing in the blob refers to them; they trail the
       image as inert bytes. That no object actually USES a GOT is checked by
       CMake on the objects themselves (no GOT relocations), which is the
       real invariant: a GOT entry would need a runtime relocation. */
    .got : { *(.got .got.*) }
    /DISCARD/ : { *(.data .data.* .bss .bss.* .comment .note.* .eh_frame* .dynamic .dynsym .dynstr .rela.* .hash .gnu.hash) }
}
ASSERT(SIZEOF(.got) <= 32, "the in-guest blob must not use a GOT: no globals through pointers")
