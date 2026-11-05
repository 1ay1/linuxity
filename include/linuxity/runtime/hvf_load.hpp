// linuxity/runtime/hvf_load.hpp
//
// Load a Linux aarch64 ELF into guest RAM and build its startup stack.
//
// The portable loader (loader/loader.hpp) writes through mm::AddressSpace<H>,
// which allocates host memory per region. This backend instead has ONE flat
// guest-physical region with VA == GPA, so segments are written straight to
// their p_vaddr inside it. Same ELF validation, different destination.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/abi/result.hpp"
#include "linuxity/loader/elf.hpp"
#include "linuxity/runtime/hvf_vm.hpp"
#include "linuxity/runtime/hvf_vma.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace lx::runtime {

struct HvfImage {
    std::uint64_t entry{};       // e_entry (+ load_bias for a PIE)
    std::uint64_t phdr_addr{};   // guest address of the program headers
    std::uint64_t phnum{}, phent{};
    std::uint64_t image_end{};   // highest mapped vaddr, where brk starts
    std::uint64_t load_bias{};
    // Each PT_LOAD as it now exists in guest RAM, so the caller can enter it
    // into the VMA map (the guest will mprotect these: RELRO).
    struct Segment {
        std::uint64_t begin{}, end{};
        std::uint64_t flags{};   // PF_R/W/X as the ELF declared them
    };
    std::vector<Segment> segments;
};

// Map every PT_LOAD of `host_path` into guest RAM. A PIE (ET_DYN, as every
// musl/glibc binary and ld.so is) has p_vaddr near 0, which would collide
// with our hypervisor-private area, so it is loaded at `bias`.
[[nodiscard]] inline Result<HvfImage> hvf_load_elf(HvfMachine& vm,
                                                   const std::string& host_path,
                                                   std::uint64_t bias) {
    std::FILE* f = std::fopen(host_path.c_str(), "rb");
    if (!f) return err<HvfImage>(Errno::enoent);
    struct Closer { std::FILE* f; ~Closer() { std::fclose(f); } } c{f};

    loader::Ehdr eh{};
    if (std::fread(&eh, 1, sizeof eh, f) != sizeof eh)
        return err<HvfImage>(Errno::enoexec);
    if (eh.e_ident[0] != 0x7f || eh.e_ident[1] != 'E' ||
        eh.e_ident[2] != 'L' || eh.e_ident[3] != 'F')
        return err<HvfImage>(Errno::enoexec);
    if (eh.e_ident[4] != 2 /*ELFCLASS64*/)
        return err<HvfImage>(Errno::enoexec);
    if (static_cast<loader::EMachine>(eh.e_machine) != loader::EMachine::aarch64)
        return err<HvfImage>(Errno::enoexec);

    const bool pie = static_cast<loader::EType>(eh.e_type) == loader::EType::dyn;
    HvfImage img{};
    img.load_bias = pie ? bias : 0;
    img.phnum = eh.e_phnum;
    img.phent = eh.e_phentsize;
    // AT_PHDR must point at the program headers IN GUEST MEMORY. A PT_PHDR
    // segment names them explicitly, but ld.so itself (and any ELF linked
    // without one) has none -- so fall back to e_phoff, which is correct
    // whenever the headers lie inside a PT_LOAD, as they do for every real
    // binary. Getting this wrong hands glibc's loader a null AT_PHDR; it
    // dereferences it while locating its own dynamic segment and dies in a
    // null-pointer write long before main.
    img.phdr_addr = img.load_bias + eh.e_phoff;
    bool have_pt_phdr = false;

    for (std::uint16_t i = 0; i < eh.e_phnum; ++i) {
        loader::Phdr ph{};
        if (std::fseek(f, static_cast<long>(eh.e_phoff + i * eh.e_phentsize),
                       SEEK_SET) != 0)
            return err<HvfImage>(Errno::enoexec);
        if (std::fread(&ph, 1, sizeof ph, f) != sizeof ph)
            return err<HvfImage>(Errno::enoexec);
        if (static_cast<loader::PType>(ph.p_type) == loader::PType::phdr) {
            img.phdr_addr = img.load_bias + ph.p_vaddr;
            have_pt_phdr = true;
        }
        if (static_cast<loader::PType>(ph.p_type) != loader::PType::load)
            continue;
        // No PT_PHDR: locate the headers by FILE OFFSET inside this LOAD and
        // translate to its vaddr. bias + e_phoff is only right when the first
        // LOAD maps offset 0 at vaddr 0 (a PIE); a static ET_EXEC at 0x400000
        // got AT_PHDR=0x40, and its libc walked the phdrs through address
        // 0x40 -- agentty died with a SIGSEGV at addr=0x40 before main.
        if (!have_pt_phdr && eh.e_phoff >= ph.p_offset &&
            eh.e_phoff < ph.p_offset + ph.p_filesz)
            img.phdr_addr = img.load_bias + ph.p_vaddr + (eh.e_phoff - ph.p_offset);

        std::uint64_t va = img.load_bias + ph.p_vaddr;
        // Zero the whole [filesz, memsz) span first so .bss reads as zero,
        // then fill the file-backed part.
        std::uint64_t beg = AddressSpace::page_down(va);
        std::uint64_t end = AddressSpace::page_up(va + ph.p_memsz);
        if (vm.ram().at(beg, end - beg).empty())
            return err<HvfImage>(Errno::enomem);
        vm.zero(beg, end - beg);
        if (ph.p_filesz) {
            auto dst = vm.ram().at(va, ph.p_filesz);
            if (dst.empty()) return err<HvfImage>(Errno::enomem);
            if (std::fseek(f, static_cast<long>(ph.p_offset), SEEK_SET) != 0)
                return err<HvfImage>(Errno::enoexec);
            if (std::fread(dst.data(), 1, ph.p_filesz, f) != ph.p_filesz)
                return err<HvfImage>(Errno::enoexec);
        }
        if (end > img.image_end) img.image_end = end;
        img.segments.push_back({beg, end, ph.p_flags});
    }
    img.entry = img.load_bias + eh.e_entry;
    // Guest code was just written through the host's data mapping; the guest
    // will FETCH it. Flush each segment (not one span from the RAM floor,
    // which would also cover unrelated memory between images).
    for (const auto& sg : img.segments) vm.publish_code(sg.begin, sg.end - sg.begin);
    return ok(img);
}

// Build the System V / Linux aarch64 process startup stack:
//
//    [ argc ][ argv... NULL ][ envp... NULL ][ auxv... AT_NULL ][ strings ]
//
// musl's __libc_start_main reads exactly this. AT_PHDR/AT_PHNUM/AT_ENTRY let
// a dynamic loader find the program it must relocate, and AT_RANDOM must
// point at 16 real bytes or musl's stack-guard init faults.
[[nodiscard]] inline Result<std::uint64_t> hvf_build_stack(
        HvfMachine& vm, const HvfImage& img,
        const std::vector<std::string>& argv,
        const std::vector<std::string>& envp,
        std::uint64_t at_base = 0,
        const std::string& execfn = {},
        std::uint64_t sysinfo_ehdr = 0) {
    std::uint64_t sp = vm.mem_size() - HvfLayout::stack_guard;

    auto push_bytes = [&](const void* data, std::size_t n) -> std::uint64_t {
        sp -= n;
        sp &= ~std::uint64_t{0xf};
        if (auto win = vm.ram().at(sp, n); !win.empty())
            std::memcpy(win.data(), data, n);
        return sp;
    };
    auto push_str = [&](const std::string& s) {
        return push_bytes(s.c_str(), s.size() + 1);
    };

    std::vector<std::uint64_t> argp, envp_addr;
    for (const auto& s : envp) envp_addr.push_back(push_str(s));
    for (const auto& s : argv) argp.push_back(push_str(s));
    const std::uint64_t execfn_addr =
        push_str(execfn.empty() ? (argv.empty() ? std::string{} : argv[0]) : execfn);
    const std::uint64_t platform_addr = push_str("aarch64");
    // AT_RANDOM: 16 bytes seeding glibc's stack protector and pointer guard.
    // Real entropy -- a fixed value would make every guest's canary equal.
    unsigned char rnd[16];
    ::arc4random_buf(rnd, sizeof rnd);
    std::uint64_t rnd_addr = push_bytes(rnd, sizeof rnd);

    // The vector itself, built bottom-up then pushed as one block so the
    // final sp is 16-byte aligned with argc at [sp].
    std::vector<std::uint64_t> v;
    v.push_back(argv.size());
    for (auto a : argp) v.push_back(a);
    v.push_back(0);
    for (auto e : envp_addr) v.push_back(e);
    v.push_back(0);
    auto aux = [&](std::uint64_t t, std::uint64_t val) {
        v.push_back(t); v.push_back(val);
    };
    aux(3,  img.phdr_addr);                    // AT_PHDR
    aux(4,  img.phent);                        // AT_PHENT
    aux(5,  img.phnum);                        // AT_PHNUM
    aux(6,  0x1000);                           // AT_PAGESZ
    aux(7,  at_base);                          // AT_BASE: the interpreter
    aux(8,  0);                                // AT_FLAGS
    aux(9,  img.entry);                        // AT_ENTRY
    aux(11, 0); aux(12, 0); aux(13, 0); aux(14, 0);  // AT_UID/EUID/GID/EGID
    aux(15, platform_addr);                    // AT_PLATFORM
    // AT_HWCAP: FP | ASIMD | AES | PMULL | SHA1 | SHA2 | CRC32 | ATOMICS.
    // All are present on every Apple Silicon core, and glibc's ifunc
    // resolvers pick the fast memcpy/strlen variants from these bits.
    aux(16, 0x1 | 0x2 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100);
    aux(17, 100);                              // AT_CLKTCK
    aux(23, 0);                                // AT_SECURE
    aux(25, rnd_addr);                         // AT_RANDOM
    aux(31, execfn_addr);                      // AT_EXECFN
    // AT_SYSINFO_EHDR: the vDSO. glibc takes clock_gettime/gettimeofday
    // from it instead of trapping (a VM exit each, ~50x a native read).
    if (sysinfo_ehdr) aux(33, sysinfo_ehdr);
    aux(0,  0);                                // AT_NULL
    if (v.size() % 2) v.push_back(0);          // keep sp 16-aligned

    sp -= v.size() * 8;
    sp &= ~std::uint64_t{0xf};
    auto win = vm.ram().at(sp, v.size() * 8);
    if (win.empty())
        return err<std::uint64_t>(Errno::enomem);
    std::memcpy(win.data(), v.data(), v.size() * 8);
    return ok(sp);
}

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
