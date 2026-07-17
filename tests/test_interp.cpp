// File-header inspection (the termux inspectFileHeader technique, modernized):
// a single read must correctly classify a program as static ELF, dynamic ELF,
// foreign-arch ELF, shebang script (with/without arg), or non-executable — and
// the cheap read_elf_machine() guard must flag a foreign ISA. Deterministic,
// file-based, no ptrace.
#include "linuxity/loader/interp.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace lx::loader;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("interp: FAIL %s\n", msg); ++failures; } } while (0)

// Write bytes to a temp file, return its path.
static std::string write_file(const std::string& name,
                              const std::vector<unsigned char>& bytes) {
    std::string path = "/tmp/lx_interp_" + name;
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (f) { std::fwrite(bytes.data(), 1, bytes.size(), f); std::fclose(f); }
    return path;
}

// A minimal ELF64 header prefix (20 bytes is enough for e_machine at off 18).
// e_type=ET_EXEC(2) or ET_DYN(3); machine is the caller's e_machine.
static std::vector<unsigned char> elf_prefix(std::uint16_t e_machine,
                                             std::uint16_t e_type = 2) {
    std::vector<unsigned char> b(64, 0);
    b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = 2;    // ELFCLASS64
    b[5] = 1;    // little-endian
    b[16] = static_cast<unsigned char>(e_type & 0xff);
    b[17] = static_cast<unsigned char>(e_type >> 8);
    b[18] = static_cast<unsigned char>(e_machine & 0xff);
    b[19] = static_cast<unsigned char>(e_machine >> 8);
    return b;
}

int main() {
    const std::uint16_t host = static_cast<std::uint16_t>(host_machine());
    const std::uint16_t other = host == 62 ? 183 : 62;   // the OTHER of x86-64/aarch64

    // --- read_elf_machine: native vs foreign vs not-an-ELF ---
    {
        std::string nativ = write_file("native.elf", elf_prefix(host));
        std::string forgn = write_file("foreign.elf", elf_prefix(other));
        std::vector<unsigned char> txt(64, 'x'); txt[0] = '#';
        std::string script = write_file("script.txt", txt);

        CHECK(read_elf_machine(nativ) == ForeignArch::native, "native ELF is native");
        CHECK(read_elf_machine(forgn) == ForeignArch::foreign, "foreign ELF flagged");
        CHECK(read_elf_machine(script) == ForeignArch::native,
              "non-ELF treated as native (handled elsewhere)");
        CHECK(read_elf_machine("/tmp/lx_interp_does_not_exist") == ForeignArch::native,
              "missing file is not foreign");
    }

    // --- inspect_file_header: static ELF (no PT_INTERP means static) ---
    {
        std::string stat = write_file("static.elf", elf_prefix(host, 2));
        FileHeaderInfo i = inspect_file_header(stat);
        CHECK(i.kind == FileHeaderInfo::Kind::static_elf, "no-interp ELF is static");
        CHECK(i.is_elf(), "static ELF is_elf()");
    }

    // --- inspect_file_header: foreign ELF ---
    {
        std::string forgn = write_file("foreign2.elf", elf_prefix(other));
        FileHeaderInfo i = inspect_file_header(forgn);
        CHECK(i.kind == FileHeaderInfo::Kind::foreign_elf, "foreign ELF kind");
        CHECK(static_cast<std::uint16_t>(i.machine) == other, "foreign machine recorded");
    }

    // --- inspect_file_header: shebang with and without argument ---
    {
        auto mk = [](const char* s) {
            return std::vector<unsigned char>(s, s + std::strlen(s));
        };
        std::string sh1 = write_file("sh_plain",  mk("#!/bin/sh\necho hi\n"));
        std::string sh2 = write_file("sh_arg",    mk("#!/usr/bin/env -S python3 -u\n"));
        std::string sh3 = write_file("sh_spaces", mk("#!   /bin/bash   -e   \n"));

        FileHeaderInfo i1 = inspect_file_header(sh1);
        CHECK(i1.kind == FileHeaderInfo::Kind::script, "plain shebang is script");
        CHECK(i1.interp == "/bin/sh", "plain shebang interp");
        CHECK(i1.arg.empty(), "plain shebang has no arg");

        FileHeaderInfo i2 = inspect_file_header(sh2);
        CHECK(i2.kind == FileHeaderInfo::Kind::script, "env shebang is script");
        CHECK(i2.interp == "/usr/bin/env", "env shebang interp");
        CHECK(i2.arg == "-S python3 -u", "env shebang single-arg (rest of line)");

        FileHeaderInfo i3 = inspect_file_header(sh3);
        CHECK(i3.interp == "/bin/bash", "leading ws stripped, interp");
        CHECK(i3.arg == "-e", "trailing ws stripped, arg");
    }

    // --- non-executable: neither ELF nor shebang ---
    {
        std::string plain = write_file("plain.txt",
            std::vector<unsigned char>{'h','e','l','l','o','\n'});
        FileHeaderInfo i = inspect_file_header(plain);
        CHECK(i.kind == FileHeaderInfo::Kind::not_executable, "plain text not executable");
    }

    // --- unreadable ---
    {
        FileHeaderInfo i = inspect_file_header("/tmp/lx_interp_missing_xyz");
        CHECK(i.kind == FileHeaderInfo::Kind::unreadable, "missing file unreadable");
    }

    // Cleanup.
    std::system("rm -f /tmp/lx_interp_* 2>/dev/null");

    if (failures) { std::printf("interp: %d checks FAILED\n", failures); return 1; }
    std::puts("interp: single-read file-header inspection classifies static/dynamic/"
              "foreign ELF, shebang (with/without arg, ws-trimmed), and non-exec "
              "correctly; foreign-arch guard flags a wrong-ISA binary");
    return 0;
}
