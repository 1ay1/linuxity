#!/usr/bin/env python3
"""Emit a tiny statically-linked x86-64 Linux ELF for testing linuxity.

No cross-toolchain required: this writes the ELF header, one PT_LOAD and a
handful of hand-assembled instructions. The program is a real Linux binary --
`file` identifies it as "ELF 64-bit LSB executable, x86-64, statically
linked", and it runs under Linux unchanged.

The program does:
    write(1, "hello from a real linux elf\n", 28)
    exit(argc)

so the stdout text proves the write syscall path and the exit status proves
the SysV startup stack (argc at [rsp]).
"""
import struct, sys

MSG = b"hello from a real linux elf\n"

VADDR = 0x400000
CODE_OFF = 0x1000

# The message is placed right after the code, inside the same PT_LOAD.
# Compute its address once the code length is known; the code below is a
# fixed length, so just lay it out explicitly.
#
#   mov edx, len            ; BA imm32
#   mov esi, msg_addr       ; BE imm32
#   mov edi, 1              ; BF 01000000
#   mov eax, 1              ; B8 01000000   (__NR_write)
#   syscall                 ; 0F 05
#   mov rdi, [rsp]          ; 48 8B 3C 24   (argc)
#   mov eax, 60             ; B8 3C000000   (__NR_exit)
#   syscall                 ; 0F 05
CODE_LEN = 5 + 5 + 5 + 5 + 2 + 4 + 5 + 2
MSG_ADDR = VADDR + CODE_OFF + CODE_LEN

code = b""
code += b"\xba" + struct.pack("<I", len(MSG))      # mov edx, len
code += b"\xbe" + struct.pack("<I", MSG_ADDR)      # mov esi, msg
code += b"\xbf" + struct.pack("<I", 1)             # mov edi, 1
code += b"\xb8" + struct.pack("<I", 1)             # mov eax, 1 (write)
code += b"\x0f\x05"                                # syscall
code += b"\x48\x8b\x3c\x24"                        # mov rdi, [rsp] (argc)
code += b"\xb8" + struct.pack("<I", 60)            # mov eax, 60 (exit)
code += b"\x0f\x05"                                # syscall
assert len(code) == CODE_LEN, (len(code), CODE_LEN)

payload = code + MSG

# ELF64 Ehdr
ehdr = b""
ehdr += b"\x7fELF"          # magic
ehdr += b"\x02"             # ELFCLASS64
ehdr += b"\x01"             # ELFDATA2LSB
ehdr += b"\x01"             # EV_CURRENT
ehdr += b"\x00"             # ELFOSABI_SYSV
ehdr += b"\x00" * 8         # padding
ehdr += struct.pack("<H", 2)        # e_type = ET_EXEC
ehdr += struct.pack("<H", 62)       # e_machine = EM_X86_64
ehdr += struct.pack("<I", 1)        # e_version
ehdr += struct.pack("<Q", VADDR + CODE_OFF)   # e_entry
ehdr += struct.pack("<Q", 64)       # e_phoff
ehdr += struct.pack("<Q", 0)        # e_shoff
ehdr += struct.pack("<I", 0)        # e_flags
ehdr += struct.pack("<H", 64)       # e_ehsize
ehdr += struct.pack("<H", 56)       # e_phentsize
ehdr += struct.pack("<H", 1)        # e_phnum
ehdr += struct.pack("<H", 0)        # e_shentsize
ehdr += struct.pack("<H", 0)        # e_shnum
ehdr += struct.pack("<H", 0)        # e_shstrndx
assert len(ehdr) == 64

filesz = CODE_OFF + len(payload)
phdr = b""
phdr += struct.pack("<I", 1)        # p_type = PT_LOAD
phdr += struct.pack("<I", 5)        # p_flags = PF_R | PF_X
phdr += struct.pack("<Q", 0)        # p_offset
phdr += struct.pack("<Q", VADDR)    # p_vaddr
phdr += struct.pack("<Q", VADDR)    # p_paddr
phdr += struct.pack("<Q", filesz)   # p_filesz
phdr += struct.pack("<Q", filesz)   # p_memsz
phdr += struct.pack("<Q", 0x1000)   # p_align
assert len(phdr) == 56

out = bytearray(filesz)
out[0:64] = ehdr
out[64:120] = phdr
out[CODE_OFF:CODE_OFF + len(payload)] = payload

path = sys.argv[1] if len(sys.argv) > 1 else "hello.elf"
with open(path, "wb") as f:
    f.write(out)
print(f"wrote {path}: {filesz} bytes, entry=0x{VADDR + CODE_OFF:x}, msg=0x{MSG_ADDR:x}")
