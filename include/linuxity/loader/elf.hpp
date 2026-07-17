// linuxity/loader/elf.hpp
//
// ELF64 format definitions — self-contained, zero-dependency.
//
// We deliberately do NOT include the host's <elf.h>: the guest ELF format is
// part of the Linux ABI we implement, not a host detail, so we own the
// definitions. This keeps the loader portable to any host (an iOS build has
// no <elf.h> for Linux ELF anyway) and makes every field's meaning explicit.
//
// Only the ELF64 little-endian subset the loader needs is defined; it covers
// static and dynamically-linked PIE/ET_EXEC executables for x86-64 and
// aarch64 — the two ISAs that matter for "run the native distro".
#pragma once

#include <cstdint>

namespace lx::loader {

// -- e_ident indices and magic --------------------------------------------
inline constexpr std::uint8_t kMag0 = 0x7f, kMag1 = 'E', kMag2 = 'L', kMag3 = 'F';
inline constexpr std::uint8_t kClass64 = 2;   // EI_CLASS = ELFCLASS64
inline constexpr std::uint8_t kData2LSB = 1;  // EI_DATA  = little-endian

// -- e_type ----------------------------------------------------------------
enum class EType : std::uint16_t {
    none = 0, rel = 1, exec = 2, dyn = 3 /* PIE / shared */, core = 4,
};

// -- e_machine (the ISA the binary targets) --------------------------------
enum class EMachine : std::uint16_t {
    x86_64  = 62,   // AMD x86-64
    aarch64 = 183,  // ARM 64-bit
};

// -- Program header types --------------------------------------------------
enum class PType : std::uint32_t {
    null = 0, load = 1, dynamic = 2, interp = 3, note = 4,
    phdr = 6, tls = 7, gnu_stack = 0x6474e551, gnu_relro = 0x6474e552,
};

// -- Segment permission flags (p_flags) ------------------------------------
inline constexpr std::uint32_t kPfX = 1, kPfW = 2, kPfR = 4;

// -- ELF64 header ----------------------------------------------------------
#pragma pack(push, 1)
struct Ehdr {
    std::uint8_t  e_ident[16];
    std::uint16_t e_type;
    std::uint16_t e_machine;
    std::uint32_t e_version;
    std::uint64_t e_entry;      // virtual entry point
    std::uint64_t e_phoff;      // program header table file offset
    std::uint64_t e_shoff;
    std::uint32_t e_flags;
    std::uint16_t e_ehsize;
    std::uint16_t e_phentsize;
    std::uint16_t e_phnum;      // number of program headers
    std::uint16_t e_shentsize;
    std::uint16_t e_shnum;
    std::uint16_t e_shstrndx;
};

struct Phdr {
    std::uint32_t p_type;
    std::uint32_t p_flags;
    std::uint64_t p_offset;     // file offset of segment
    std::uint64_t p_vaddr;      // virtual address to map at
    std::uint64_t p_paddr;
    std::uint64_t p_filesz;     // bytes present in the file
    std::uint64_t p_memsz;      // bytes in memory (>= filesz; rest is .bss, zeroed)
    std::uint64_t p_align;
};
#pragma pack(pop)

static_assert(sizeof(Ehdr) == 64, "ELF64 Ehdr must be 64 bytes");
static_assert(sizeof(Phdr) == 56, "ELF64 Phdr must be 56 bytes");

// -- Auxiliary vector entry types (SysV AMD64 process init) ----------------
// The kernel hands the dynamic linker / libc these via the initial stack.
enum class AuxType : std::uint64_t {
    null = 0, phdr = 3, phent = 4, phnum = 5, pagesz = 6,
    base = 7, flags = 8, entry = 9, uid = 11, euid = 12,
    gid = 13, egid = 14, hwcap = 16, random = 25, execfn = 31,
};

} // namespace lx::loader
