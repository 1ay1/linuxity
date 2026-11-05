/* Linker script for the linuxity vDSO. The whole object is ONE flat, R+X
 * PT_LOAD (like the kernel's), so linuxity can copy the file verbatim into
 * guest memory at any page-aligned address: no relocation, no padding.
 *
 * The data page lives one page BELOW the image; the code reaches it with
 * ADRP/ADD (PC-relative), so it moves with the image:
 *
 *   base + 0x0000   struct vdso_data (filled by linuxity; guest read-only)
 *   base + 0x1000   this ELF: AT_SYSINFO_EHDR points here
 */
PHDRS {
    text    PT_LOAD    FILEHDR PHDRS FLAGS(5);   /* R + X */
    dynamic PT_DYNAMIC FLAGS(4);
}
SECTIONS {
    __lx_vdso_data = -0x1000;
    . = SIZEOF_HEADERS;
    .hash          : { *(.hash) }          :text
    .gnu.hash      : { *(.gnu.hash) }      :text
    .dynsym        : { *(.dynsym) }        :text
    .dynstr        : { *(.dynstr) }        :text
    .gnu.version   : { *(.gnu.version) }   :text
    .gnu.version_d : { *(.gnu.version_d) } :text
    .dynamic       : { *(.dynamic) }       :text :dynamic
    .rodata        : { *(.rodata*) }       :text
    .text          : { *(.text*) }         :text
    /DISCARD/      : { *(.data*) *(.bss*) *(.got*) *(.comment) *(.eh_frame*)
                       *(.note*) *(.gnu.version_r) }
}
