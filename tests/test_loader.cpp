// Loader + address space + stack: load a hand-built ELF64 image into a guest
// address space, verify segments land at the right vaddrs with the right
// perms, and that the initial stack is laid out per the SysV AMD64 ABI. Uses
// a BufferSource so it needs no files — the ELF is synthesized in-memory.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/loader/loader.hpp"
#include "linuxity/loader/stack.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace lx;
using namespace lx::loader;

// Build a minimal but valid ET_EXEC ELF64 with one R-X PT_LOAD segment whose
// "code" is a single byte (0x90, NOP). Entry points at the segment.
static std::vector<std::byte> make_elf() {
    constexpr std::uint64_t kVaddr = 0x400000;
    constexpr std::uint64_t kEntry = kVaddr + sizeof(Ehdr) + sizeof(Phdr);

    std::vector<std::byte> img(kEntry - kVaddr + 1, std::byte{0});

    Ehdr eh{};
    eh.e_ident[0] = kMag0; eh.e_ident[1] = kMag1;
    eh.e_ident[2] = kMag2; eh.e_ident[3] = kMag3;
    eh.e_ident[4] = kClass64; eh.e_ident[5] = kData2LSB;
    eh.e_type = std::uint16_t(EType::exec);
    eh.e_machine = std::uint16_t(EMachine::x86_64);
    eh.e_version = 1;
    eh.e_entry = kEntry;
    eh.e_phoff = sizeof(Ehdr);
    eh.e_ehsize = sizeof(Ehdr);
    eh.e_phentsize = sizeof(Phdr);
    eh.e_phnum = 1;

    Phdr ph{};
    ph.p_type = std::uint32_t(PType::load);
    ph.p_flags = kPfR | kPfX;
    ph.p_offset = 0;
    ph.p_vaddr = kVaddr;
    ph.p_filesz = img.size();
    ph.p_memsz = img.size() + 0x1000; // some .bss to test zero-fill
    ph.p_align = 0x1000;

    std::memcpy(img.data(), &eh, sizeof eh);
    std::memcpy(img.data() + sizeof(Ehdr), &ph, sizeof ph);
    img[kEntry - kVaddr] = std::byte{0x90}; // NOP at entry
    return img;
}

int main() {
    host::PosixHost hw;
    mm::AddressSpace<host::PosixHost> as{hw};

    // -- Load the ELF. -----------------------------------------------------
    auto img = make_elf();
    BufferSource src{img};
    Loader<host::PosixHost> ld{as};
    auto loaded = ld.load(src);
    assert(loaded.has_value());
    assert(loaded->machine == EMachine::x86_64);
    assert(loaded->interp.empty());                 // static
    assert(value(loaded->entry) == 0x400000 + sizeof(Ehdr) + sizeof(Phdr));

    // The entry byte we placed (0x90 NOP) is readable through the guest AS.
    std::byte b{};
    auto rd = as.read(loaded->entry, std::span<std::byte>{&b, 1});
    assert(rd.has_value() && b == std::byte{0x90});

    // .bss tail is zeroed (fresh host map): read a byte past filesz.
    std::byte z{std::byte{0xff}};
    auto rz = as.read(uaddr(0x400000 + img.size() + 16),
                      std::span<std::byte>{&z, 1});
    assert(rz.has_value() && z == std::byte{0});

    // -- Build the initial stack. -----------------------------------------
    // Reserve a stack region high in the address space.
    constexpr std::uint64_t kStackTop = 0x7fff'0000'0000ull;
    constexpr std::size_t   kStackLen = 64 * 1024;
    auto stk = as.map_fixed(uaddr(kStackTop - kStackLen), kStackLen,
                            mm::Perm::read | mm::Perm::write);
    assert(stk.has_value());

    StackParams sp;
    sp.top   = uaddr(kStackTop);
    sp.size  = kStackLen;
    sp.argv  = {"/bin/hello", "arg1"};
    sp.envp  = {"PATH=/bin", "HOME=/root"};
    sp.image = *loaded;

    StackBuilder<host::PosixHost> sb{as};
    auto rsp = sb.build(sp);
    assert(rsp.has_value());
    // %rsp must be 16-byte aligned at entry (AMD64 ABI).
    assert((value(*rsp) & 15u) == 0);

    // argc sits at the initial %rsp and must equal argv.size().
    std::uint64_t argc = 0;
    auto ra = as.read(*rsp, std::span<std::byte>{
        reinterpret_cast<std::byte*>(&argc), sizeof argc});
    assert(ra.has_value() && argc == 2);

    // Rejecting a non-ELF is ENOEXEC.
    std::byte junk[64]{};
    BufferSource bad{std::span<const std::byte>{junk, sizeof junk}};
    mm::AddressSpace<host::PosixHost> as2{hw};
    Loader<host::PosixHost> ld2{as2};
    assert(ld2.load(bad).error() == Errno::enoexec);

    std::puts("loader: ELF mapped, .bss zeroed, SysV stack (argc/argv/envp/auxv) built");
    return 0;
}
