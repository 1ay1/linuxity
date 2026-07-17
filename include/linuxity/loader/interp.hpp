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

// A parsed `#!` script header: the interpreter path and its single optional
// argument (the kernel passes at most one). Empty `interp` means "not a
// shebang script".
struct Shebang { std::string interp; std::string arg; };

// Read the `#!interp [arg]` line of the file at `host_path`. Returns an empty
// interp if the file doesn't start with "#!" (or is unreadable). Matches the
// kernel's rule: everything after the interpreter up to the first whitespace
// is the interpreter; the REMAINDER of the line (trimmed) is ONE argument.
[[nodiscard]] inline Shebang read_shebang(const std::string& host_path) {
    std::FILE* f = std::fopen(host_path.c_str(), "rb");
    if (!f) return {};
    struct Closer { std::FILE* f; ~Closer() { std::fclose(f); } } closer{f};
    char line[256];
    std::size_t n = std::fread(line, 1, sizeof line - 1, f);
    if (n < 2 || line[0] != '#' || line[1] != '!') return {};
    line[n] = '\0';
    // Terminate at the newline.
    for (std::size_t i = 0; i < n; ++i)
        if (line[i] == '\n') { line[i] = '\0'; n = i; break; }
    std::size_t i = 2;
    while (i < n && (line[i] == ' ' || line[i] == '\t')) ++i;   // skip ws
    std::size_t is = i;
    while (i < n && line[i] != ' ' && line[i] != '\t') ++i;     // interp token
    Shebang sh;
    sh.interp.assign(line + is, i - is);
    while (i < n && (line[i] == ' ' || line[i] == '\t')) ++i;   // skip ws
    // The remainder (trimmed of trailing ws) is one argument.
    std::size_t end = n;
    while (end > i && (line[end - 1] == ' ' || line[end - 1] == '\t')) --end;
    if (end > i) sh.arg.assign(line + i, end - i);
    return sh;
}

} // namespace lx::loader
