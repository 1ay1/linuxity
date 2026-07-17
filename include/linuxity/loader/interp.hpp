// linuxity/loader/interp.hpp
//
// Read an ELF's PT_INTERP (dynamic-linker path) straight from a file on disk.
//
// A dynamically-linked executable names its interpreter (ld-linux / ld-musl)
// in a PT_INTERP segment. When linuxity execs the guest binary, the HOST
// kernel is the one that loads that interpreter — and it resolves the interp
// path against the HOST root, where a guest rootfs's /lib/ld-musl-x86_64.so.1
// does not exist. So the exec silently fails.
//
// The fix stays fully unprivileged (no chroot): read the interp path here,
// translate BOTH it and the program through linuxity's namespace to their
// real host locations, and exec the INTERPRETER directly with the program as
// its first argument (ld.so <prog> <args...>). From then on the interpreter
// opens every shared library via ordinary openat syscalls, which linuxity
// already redirects into the rootfs. Only this first hop needs special care.
//
// This is a tiny, self-contained reader — it does NOT pull in the full loader
// or address space; it just peeks the program headers.
#pragma once

#include "linuxity/loader/elf.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

namespace lx::loader {

// Return the PT_INTERP path of the ELF at `host_path`, or "" if the file is
// static, unreadable, or not an ELF64 we recognize. Reads only the ELF header
// and program-header table (a few hundred bytes).
[[nodiscard]] inline std::string read_elf_interp(const std::string& host_path) {
    std::FILE* f = std::fopen(host_path.c_str(), "rb");
    if (!f) return {};
    struct Closer { std::FILE* f; ~Closer() { std::fclose(f); } } closer{f};

    Ehdr eh{};
    if (std::fread(&eh, 1, sizeof eh, f) != sizeof eh) return {};
    if (eh.e_ident[0] != kMag0 || eh.e_ident[1] != kMag1 ||
        eh.e_ident[2] != kMag2 || eh.e_ident[3] != kMag3) return {};
    if (eh.e_ident[4] != kClass64) return {};   // only ELF64
    if (eh.e_phentsize != sizeof(Phdr) || eh.e_phnum == 0) return {};
    if (eh.e_phnum > 256) return {};            // sanity bound

    for (std::uint16_t i = 0; i < eh.e_phnum; ++i) {
        if (std::fseek(f, static_cast<long>(eh.e_phoff + i * sizeof(Phdr)),
                       SEEK_SET) != 0)
            return {};
        Phdr ph{};
        if (std::fread(&ph, 1, sizeof ph, f) != sizeof ph) return {};
        if (static_cast<PType>(ph.p_type) != PType::interp) continue;
        if (ph.p_filesz == 0 || ph.p_filesz > 4096) return {};
        std::string interp(ph.p_filesz, '\0');
        if (std::fseek(f, static_cast<long>(ph.p_offset), SEEK_SET) != 0) return {};
        if (std::fread(interp.data(), 1, ph.p_filesz, f) != ph.p_filesz) return {};
        if (!interp.empty() && interp.back() == '\0') interp.pop_back();
        return interp;
    }
    return {};   // static: no PT_INTERP
}

} // namespace lx::loader
