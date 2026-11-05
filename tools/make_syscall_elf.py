#!/usr/bin/env python3
"""Emit a static x86-64 Linux ELF that exercises linuxity's syscall surface.

No cross-toolchain needed. The program:

    1. uname(buf)                 -> prints sysname
    2. brk(0), brk(cur + 64Ki)    -> heap grows, then WRITES to it
                                     (proves the lazy soft-fault path)
    3. mmap(anon, 1 MiB)          -> then writes to the first/last page
                                     (proves overcommit + fault-fill)
    4. openat(AT_FDCWD, argv[1])  -> read 64 bytes -> write to stdout
                                     (proves the fd table + rootfs paths)
    5. arch_prctl(ARCH_SET_FS)    -> sets %fs, then reads via %fs:0
                                     (proves TLS works -- errno needs it)
    6. exit(0) / exit(code) on any failure, so the exit status pinpoints
       which step broke.

Written as raw bytes so the test has no dependency beyond python.
"""
import struct, sys

VADDR = 0x400000
CODE_OFF = 0x1000

code = bytearray()
data = bytearray()          # appended after code; addresses computed below

def d_off():
    return len(data)

def emit(b):
    code.extend(b)

# ---- helpers --------------------------------------------------------------
def mov_eax(v):   emit(b"\xb8" + struct.pack("<I", v))
def mov_edi(v):   emit(b"\xbf" + struct.pack("<I", v))
def mov_esi(v):   emit(b"\xbe" + struct.pack("<I", v))
def mov_edx(v):   emit(b"\xba" + struct.pack("<I", v))
def mov_r10(v):   emit(b"\x49\xc7\xc2" + struct.pack("<i", v))
def mov_rdi_imm64(v): emit(b"\x48\xbf" + struct.pack("<Q", v))
def mov_rsi_imm64(v): emit(b"\x48\xbe" + struct.pack("<Q", v))
def syscall():    emit(b"\x0f\x05")

def sys_write(fd, addr, ln):
    mov_eax(1); mov_edi(fd); mov_esi(addr); mov_edx(ln); syscall()

def exit_with(code_):
    mov_eax(60); mov_edi(code_); syscall()

# exit(code) if rax < 0  (i.e. the syscall failed)
def exit_if_neg(code_):
    emit(b"\x48\x85\xc0")                 # test rax, rax
    emit(b"\x79\x00")                     # jns +len(fail)
    patch = len(code) - 1
    start = len(code)
    exit_with(code_)
    code[patch] = len(code) - start

# ---- strings --------------------------------------------------------------
MSG_START = b"[1] uname: "
MSG_NL    = b"\n"
MSG_BRK   = b"[2] brk grew and heap write OK\n"
MSG_MMAP  = b"[3] mmap 1MiB + page writes OK\n"
MSG_FILE  = b"[4] file read: "
MSG_TLS   = b"[5] TLS via %fs OK\n"
MSG_DONE  = b"[6] all syscall-surface checks passed\n"

off_start = d_off(); data.extend(MSG_START)
off_nl    = d_off(); data.extend(MSG_NL)
off_brk   = d_off(); data.extend(MSG_BRK)
off_mmap  = d_off(); data.extend(MSG_MMAP)
off_file  = d_off(); data.extend(MSG_FILE)
off_tls   = d_off(); data.extend(MSG_TLS)
off_done  = d_off(); data.extend(MSG_DONE)

# scratch buffers
data.extend(b"\0" * 8)
off_utsname = d_off(); data.extend(b"\0" * 390)   # struct utsname = 6*65
off_rdbuf   = d_off(); data.extend(b"\0" * 128)
# A TLS block: we point %fs at this, then read [%fs:0]. The sentinel must fit
# in a signed imm32 because `cmp rax, imm32` sign-extends -- a larger value
# would compare against the wrong number.
TLS_SENTINEL = 0x5EED1234
off_tlsblk  = d_off(); data.extend(struct.pack("<Q", TLS_SENTINEL))
# The guest path to open.
off_path    = d_off(); data.extend(b"/testfile\0")

# Code length is needed to place data; assemble with a placeholder base then
# recompute. Simplest: assemble twice.
def assemble(data_base):
    code.clear()
    A = lambda off: data_base + off

    # --- [1] uname ---------------------------------------------------------
    mov_eax(63); mov_edi(A(off_utsname)); syscall()
    exit_if_neg(11)
    sys_write(1, A(off_start), len(MSG_START))
    sys_write(1, A(off_utsname), 5)          # "Linux"
    sys_write(1, A(off_nl), 1)

    # --- [2] brk ----------------------------------------------------------
    mov_eax(12); mov_edi(0); syscall()       # brk(0) -> current
    exit_if_neg(12)
    emit(b"\x49\x89\xc4")                    # mov r12, rax   (save old break)
    emit(b"\x48\x05" + struct.pack("<I", 0x10000))   # add rax, 64Ki
    emit(b"\x48\x89\xc7")                    # mov rdi, rax
    mov_eax(12); syscall()                   # brk(old + 64Ki)
    exit_if_neg(13)
    # Write through the NEW heap page -> triggers the lazy soft fault.
    emit(b"\x49\x8d\x7c\x24\x08")            # lea rdi, [r12+8]
    emit(b"\x48\xc7\x07" + struct.pack("<i", 0x5A5A))  # mov qword [rdi], 0x5A5A
    emit(b"\x48\x8b\x07")                    # mov rax, [rdi]   (read it back)
    emit(b"\x48\x3d" + struct.pack("<i", 0x5A5A))      # cmp rax, 0x5A5A
    emit(b"\x74\x00")                        # je +n
    p = len(code) - 1; s = len(code); exit_with(14); code[p] = len(code) - s
    sys_write(1, A(off_brk), len(MSG_BRK))

    # --- [3] mmap 1 MiB anonymous ------------------------------------------
    mov_rdi_imm64(0)                         # addr = NULL
    mov_rsi_imm64(0x100000)                  # len  = 1 MiB
    mov_edx(3)                               # prot = READ|WRITE
    mov_r10(0x22)                            # flags= PRIVATE|ANONYMOUS
    emit(b"\x49\xc7\xc0" + struct.pack("<i", -1))      # r8  = fd -1
    emit(b"\x4d\x31\xc9")                    # r9  = 0 (offset)
    mov_eax(9); syscall()
    exit_if_neg(15)
    emit(b"\x49\x89\xc5")                    # mov r13, rax  (base)
    # Touch the FIRST page.
    emit(b"\x49\xc7\x45\x00" + struct.pack("<i", 0x1234))   # mov [r13+0], imm
    # Touch the LAST page (base + 1MiB - 8).
    emit(b"\x4d\x8d\xbd" + struct.pack("<i", 0x100000 - 8)) # lea r15,[r13+...]
    emit(b"\x49\xc7\x07" + struct.pack("<i", 0x4321))       # mov [r15], imm
    # Read both back.
    emit(b"\x49\x8b\x45\x00")                # mov rax, [r13]
    emit(b"\x48\x3d" + struct.pack("<i", 0x1234))
    emit(b"\x74\x00"); p = len(code)-1; s=len(code); exit_with(16); code[p]=len(code)-s
    emit(b"\x49\x8b\x07")                    # mov rax, [r15]
    emit(b"\x48\x3d" + struct.pack("<i", 0x4321))
    emit(b"\x74\x00"); p = len(code)-1; s=len(code); exit_with(17); code[p]=len(code)-s
    sys_write(1, A(off_mmap), len(MSG_MMAP))

    # --- [4] openat + read -------------------------------------------------
    # openat(AT_FDCWD=-100, path=argv-provided via a fixed guest path, O_RDONLY)
    mov_eax(257)
    emit(b"\xbf" + struct.pack("<i", -100))  # edi = AT_FDCWD
    mov_esi(A(off_path))
    mov_edx(0)                               # O_RDONLY
    mov_r10(0)
    syscall()
    exit_if_neg(18)
    emit(b"\x49\x89\xc6")                    # mov r14, rax (fd)
    # read(fd, rdbuf, 32)
    mov_eax(0)
    emit(b"\x4c\x89\xf7")                    # mov rdi, r14
    mov_esi(A(off_rdbuf)); mov_edx(32); syscall()
    exit_if_neg(19)
    emit(b"\x48\x89\xc2")                    # mov rdx, rax  (bytes read)
    sys_write(1, A(off_file), len(MSG_FILE))
    # write(1, rdbuf, n)  -- rdx still holds n? recompute to be safe
    mov_eax(1); mov_edi(1); mov_esi(A(off_rdbuf)); mov_edx(16); syscall()
    sys_write(1, A(off_nl), 1)
    # close(fd)
    mov_eax(3); emit(b"\x4c\x89\xf7"); syscall()

    # --- [5] arch_prctl(ARCH_SET_FS) + TLS read ---------------------------
    mov_eax(158); mov_edi(0x1002)            # ARCH_SET_FS
    mov_esi(A(off_tlsblk))
    syscall()
    exit_if_neg(20)
    # Read [%fs:0] -- must equal 0xCAFEBABE.
    emit(b"\x64\x48\x8b\x04\x25" + struct.pack("<i", 0))   # mov rax, fs:[0]
    emit(b"\x48\x3d" + struct.pack("<i", TLS_SENTINEL))
    emit(b"\x74\x00"); p = len(code)-1; s=len(code); exit_with(21); code[p]=len(code)-s
    sys_write(1, A(off_tls), len(MSG_TLS))

    # --- done --------------------------------------------------------------
    sys_write(1, A(off_done), len(MSG_DONE))
    exit_with(0)
    return bytes(code)

# Two passes: the first gives us the code length, the second uses the real
# data base address.
probe = assemble(VADDR + CODE_OFF + 4096)
data_base = VADDR + CODE_OFF + len(probe)
# Align data to 16 for cleanliness, then re-assemble at the true base.
data_base = (data_base + 15) & ~15
final = assemble(data_base)
# The code length can shift between passes (different immediate encodings are
# not used here, so it should be stable); assert it.
assert len(final) == len(probe), (len(final), len(probe))

payload = bytearray(final)
payload.extend(b"\0" * (data_base - (VADDR + CODE_OFF + len(final))))
payload.extend(data)

ehdr = bytearray(64)
ehdr[0:4] = b"\x7fELF"
ehdr[4] = 2; ehdr[5] = 1; ehdr[6] = 1
struct.pack_into("<H", ehdr, 16, 2)       # ET_EXEC
struct.pack_into("<H", ehdr, 18, 62)      # EM_X86_64
struct.pack_into("<I", ehdr, 20, 1)
struct.pack_into("<Q", ehdr, 24, VADDR + CODE_OFF)
struct.pack_into("<Q", ehdr, 32, 64)      # e_phoff
struct.pack_into("<H", ehdr, 52, 64)      # e_ehsize
struct.pack_into("<H", ehdr, 54, 56)      # e_phentsize
struct.pack_into("<H", ehdr, 56, 1)       # e_phnum

filesz = CODE_OFF + len(payload)
phdr = bytearray(56)
struct.pack_into("<I", phdr, 0, 1)        # PT_LOAD
struct.pack_into("<I", phdr, 4, 7)        # RWX: the data area is written
struct.pack_into("<Q", phdr, 8, 0)
struct.pack_into("<Q", phdr, 16, VADDR)
struct.pack_into("<Q", phdr, 24, VADDR)
struct.pack_into("<Q", phdr, 32, filesz)
struct.pack_into("<Q", phdr, 40, filesz)
struct.pack_into("<Q", phdr, 48, 0x1000)

out = bytearray(filesz)
out[0:64] = ehdr
out[64:120] = phdr
out[CODE_OFF:CODE_OFF + len(payload)] = payload

path = sys.argv[1] if len(sys.argv) > 1 else "syscalls.elf"
with open(path, "wb") as f:
    f.write(out)
print(f"wrote {path}: {filesz} bytes, entry=0x{VADDR+CODE_OFF:x}, "
      f"data=0x{data_base:x}")
