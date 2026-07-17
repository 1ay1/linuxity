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

// The ISA the running linuxity binary itself targets — i.e. the host CPU a
// native guest must match. Compile-time constant; guest ELFs whose e_machine
// differs cannot run natively (they'd need cross-emulation, out of scope).
[[nodiscard]] inline constexpr EMachine host_machine() noexcept {
#if defined(__x86_64__)
    return EMachine::x86_64;
#elif defined(__aarch64__)
    return EMachine::aarch64;
#else
    return EMachine::x86_64;   // default; foreign-arch guests fail cleanly
#endif
}

// A tri-state verdict on an exec target's ISA, so the exec path can refuse a
// foreign binary without conflating "not an ELF at all" (a script, or garbage
// — handled elsewhere) with "an ELF, but the wrong CPU".
enum class ForeignArch : std::uint8_t {
    native,      // ELF for the host ISA (or the file isn't an ELF we judge)
    foreign,     // ELF whose e_machine != host — cannot run natively
};

// Read ONLY the ELF e_machine of `host_path` and compare it to the host ISA.
// Returns `foreign` iff the file is a well-formed ELF64 whose target ISA does
// NOT match the host; everything else (not an ELF, a shebang script, an
// unreadable/short file) is `native` so the normal exec path handles it. This
// is the cheap single-field guard the exec hot path wants — it reads 20 bytes.
[[nodiscard]] inline ForeignArch read_elf_machine(const std::string& host_path) {
    std::FILE* f = std::fopen(host_path.c_str(), "rb");
    if (!f) return ForeignArch::native;
    struct Closer { std::FILE* f; ~Closer() { std::fclose(f); } } closer{f};
    unsigned char hdr[20];
    if (std::fread(hdr, 1, sizeof hdr, f) != sizeof hdr) return ForeignArch::native;
    if (!(hdr[0] == kMag0 && hdr[1] == kMag1 && hdr[2] == kMag2 && hdr[3] == kMag3))
        return ForeignArch::native;                     // not an ELF (script?)
    std::uint16_t em = static_cast<std::uint16_t>(hdr[18] | (hdr[19] << 8));
    return static_cast<EMachine>(em) == host_machine() ? ForeignArch::native
                                                       : ForeignArch::foreign;
}

// The verdict of inspecting a program's first file-header block ONCE — exactly
// termux-exec's inspectFileHeader(), modernized. A single 256-byte read tells
// us everything the exec path needs to decide how to launch the file:
//
//   * a `#!` script  -> interp + optional arg (run the interpreter)
//   * a dynamic ELF  -> pt_interp is the ld.so to run
//   * a static ELF   -> run it directly
//   * a FOREIGN-arch ELF -> refuse cleanly (e_machine != host)
//   * neither ELF nor shebang -> ENOEXEC
//
// Doing it in one pass (vs. read_shebang THEN read_elf_interp: two opens, two
// reads per exec) both halves the syscalls and, crucially, gives one place to
// catch a foreign binary before the host kernel execs it into a cryptic
// SIGSEGV/SIGILL. termux flags isNonNativeElf and routes it to qemu; linuxity
// has no cross-emulator, so it fails with a precise diagnostic instead.
struct FileHeaderInfo {
    enum class Kind : std::uint8_t { unreadable, not_executable, foreign_elf,
                                     static_elf, dynamic_elf, script };
    Kind        kind{Kind::unreadable};
    EMachine    machine{};        // valid for the *_elf kinds
    std::string interp;           // pt_interp (dynamic_elf) or shebang interp (script)
    std::string arg;              // shebang's single optional argument (script only)
    [[nodiscard]] bool is_elf() const noexcept {
        return kind == Kind::static_elf || kind == Kind::dynamic_elf ||
               kind == Kind::foreign_elf;
    }
};

// Inspect the file at `host_path` in a single read. See FileHeaderInfo. This
// is the one function the exec path should call; read_shebang/read_elf_interp
// remain for callers that only need one axis.
[[nodiscard]] inline FileHeaderInfo inspect_file_header(const std::string& host_path) {
    FileHeaderInfo out;
    std::FILE* f = std::fopen(host_path.c_str(), "rb");
    if (!f) return out;                        // unreadable
    struct Closer { std::FILE* f; ~Closer() { std::fclose(f); } } closer{f};

    // One header block big enough for the ELF ident+header prefix and a
    // generous shebang line (the kernel caps the shebang at BINPRM_BUF_SIZE,
    // historically 128; 256 is safely beyond that).
    unsigned char hdr[256];
    std::size_t n = std::fread(hdr, 1, sizeof hdr, f);
    if (n < 4) { out.kind = FileHeaderInfo::Kind::not_executable; return out; }

    // --- ELF? ---
    if (hdr[0] == kMag0 && hdr[1] == kMag1 && hdr[2] == kMag2 && hdr[3] == kMag3) {
        // We can only read e_machine if the full Ehdr prefix is present
        // (e_machine is a u16 at offset 18).
        if (n < 20) { out.kind = FileHeaderInfo::Kind::not_executable; return out; }
        std::uint16_t em = static_cast<std::uint16_t>(hdr[18] | (hdr[19] << 8));
        out.machine = static_cast<EMachine>(em);
        if (out.machine != host_machine()) {
            out.kind = FileHeaderInfo::Kind::foreign_elf;
            return out;
        }
        // Native ELF: dynamic if it names a PT_INTERP, else static. Reuse the
        // dedicated phdr reader (it seeks past our 256-byte window as needed).
        out.interp = read_elf_interp(host_path);
        out.kind = out.interp.empty() ? FileHeaderInfo::Kind::static_elf
                                      : FileHeaderInfo::Kind::dynamic_elf;
        return out;
    }

    // --- shebang? ---
    if (n >= 2 && hdr[0] == '#' && hdr[1] == '!') {
        // Terminate at the first newline (the shebang is one line).
        std::size_t end = n;
        for (std::size_t i = 0; i < n; ++i)
            if (hdr[i] == '\n') { end = i; break; }
        auto ws = [](unsigned char c) { return c == ' ' || c == '\t'; };
        std::size_t i = 2;
        while (i < end && ws(hdr[i])) ++i;             // skip ws before interp
        std::size_t is = i;
        while (i < end && !ws(hdr[i])) ++i;            // interp token
        if (i == is) { out.kind = FileHeaderInfo::Kind::not_executable; return out; }
        out.interp.assign(reinterpret_cast<const char*>(hdr) + is, i - is);
        while (i < end && ws(hdr[i])) ++i;            // skip ws before arg
        std::size_t ae = end;
        while (ae > i && ws(hdr[ae - 1])) --ae;       // trim trailing ws
        if (ae > i) out.arg.assign(reinterpret_cast<const char*>(hdr) + i, ae - i);
        out.kind = FileHeaderInfo::Kind::script;
        return out;
    }

    out.kind = FileHeaderInfo::Kind::not_executable;
    return out;
}

} // namespace lx::loader
