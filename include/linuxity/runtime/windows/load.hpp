// linuxity/runtime/windows/load.hpp
//
// Load a Linux x86-64 ELF into guest RAM and build its startup stack.
//
// The portable loader (loader/loader.hpp) writes through mm::AddressSpace<H>,
// which allocates host memory per region. This backend instead owns ONE flat
// guest-physical RAM region, so segments are written straight to their
// p_vaddr inside it. Same ELF validation, different destination -- the same
// split hvf_load.hpp makes on Darwin.
//
// WHAT DIFFERS FROM THE ARM64 (HVF) LOADER, and why each matters:
//
//   PAGE TABLES. On arm64 we hand the guest a flat space and VA == GPA needs
//   no tables. x86-64 long mode REQUIRES paging, so every segment must also
//   be ENTERED into the page tables with its real permissions. That is the
//   one genuinely new step here, and skipping it means the guest faults on
//   its own entry point.
//
//   W^X. Because we map per-segment at 4KiB granularity, a PT_LOAD without
//   PF_W gets a read-only mapping and one without PF_X gets NX. The arm64
//   loader could rely on a blanket RWX window; doing that here would let a
//   guest bug silently write its own text.
//
//   NO I-CACHE FLUSH. hvf_load calls sys_icache_invalidate because arm64
//   has separate I/D caches with no coherency guarantee, so code written
//   through the data mapping may not be fetched. x86-64's instruction cache
//   is coherent with stores, so there is deliberately no publish_code step --
//   its absence is correct, not an omission.
//
//   AT_PLATFORM / AT_HWCAP. "x86_64", and HWCAP is not the bitmask arm64
//   uses -- on x86-64 glibc's ifunc resolvers read CPUID, not AT_HWCAP, so
//   reporting 0 is both honest and harmless.
#pragma once

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))

#include "linuxity/abi/result.hpp"
#include "linuxity/loader/elf.hpp"
#include "linuxity/runtime/windows/vm.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace lx::runtime {

// Where things live in the guest's flat space.
//
// Because this backend identity-maps (GVA == GPA), every address here must
// lie inside actual guest RAM -- unlike a real kernel, we cannot put the PIE
// at 0x5555_5555_0000 and the stack at 0x7fff_ffff_f000 and let paging sort
// it out. So the bases are DERIVED from the RAM size rather than hardcoded:
// a fixed 256MiB pie_base silently made every PIE unloadable on a machine
// configured with less RAM than that, which is every default except the
// 2GiB one -- and since all modern distro binaries are PIEs, that would have
// meant "nothing runs" on a small guest.
struct WhpLayout {
    static constexpr std::uint64_t stack_guard = 0x10000;
    static constexpr std::uint64_t stack_size  = 8ull << 20;

    // The executable goes just above the private table/GDT region. A
    // conventional non-PIE ET_EXEC at 0x400000 also lands here, so the two
    // cases agree.
    [[nodiscard]] static constexpr std::uint64_t pie_base(std::uint64_t ram) noexcept {
        (void)ram;
        return 0x40'0000;              // 4MiB
    }

    // The top of usable guest RAM: everything above this is the page-table
    // arena, which the guest must never see. The stack hangs just below it.
    [[nodiscard]] static constexpr std::uint64_t usable_top(std::uint64_t ram) noexcept {
        const std::uint64_t arena = WhpMachine::kTableArenaSize;
        return ram > arena ? ram - arena : 0;
    }

    // The dynamic linker is placed in the upper half of the region between
    // the image and the stack, so neither can grow into the other on any
    // RAM size. (ld.so is ~2MiB mapped; the gap below it is the guest's mmap
    // and brk arena.)
    [[nodiscard]] static constexpr std::uint64_t interp_base(std::uint64_t ram) noexcept {
        const std::uint64_t stack_bot = stack_top(ram) - stack_size;
        const std::uint64_t base = stack_bot - (16ull << 20);
        return base & ~(kPageSize - 1);
    }

    [[nodiscard]] static constexpr std::uint64_t stack_top(std::uint64_t ram) noexcept {
        return usable_top(ram) - stack_guard;
    }

    // The ceiling of the mmap arena: below the stack, so a growing mmap
    // region and the stack cannot collide.
    [[nodiscard]] static constexpr std::uint64_t mmap_top(std::uint64_t ram) noexcept {
        return (stack_top(ram) - stack_size - (1ull << 20)) & ~(kPageSize - 1);
    }

    // The smallest guest RAM this layout is coherent for: the image needs
    // room below the interpreter, which needs room below the stack.
    static constexpr std::uint64_t min_ram = 64ull << 20;
};

struct WhpImage {
    std::uint64_t entry{};       // e_entry (+ load_bias for a PIE)
    std::uint64_t phdr_addr{};   // guest address of the program headers
    std::uint64_t phnum{}, phent{};
    std::uint64_t image_end{};   // highest mapped vaddr, where brk starts
    std::uint64_t load_bias{};
    struct Segment {
        std::uint64_t begin{}, end{};
        std::uint64_t flags{};   // PF_R/W/X as the ELF declared them
    };
    std::vector<Segment> segments;
};

// Map every PT_LOAD of `host_path` into guest RAM and into the page tables.
// A PIE (ET_DYN, as every musl/glibc binary and ld.so is) has p_vaddr near 0,
// so it is loaded at `bias`.
[[nodiscard]] inline Result<WhpImage> whp_load_elf(WhpMachine& vm,
                                                   const std::string& host_path,
                                                   std::uint64_t bias) {
    std::FILE* f = std::fopen(host_path.c_str(), "rb");
    if (!f) return err<WhpImage>(Errno::enoent);
    struct Closer { std::FILE* f; ~Closer() { std::fclose(f); } } c{f};

    loader::Ehdr eh{};
    if (std::fread(&eh, 1, sizeof eh, f) != sizeof eh)
        return err<WhpImage>(Errno::enoexec);
    if (eh.e_ident[0] != loader::kMag0 || eh.e_ident[1] != loader::kMag1 ||
        eh.e_ident[2] != loader::kMag2 || eh.e_ident[3] != loader::kMag3)
        return err<WhpImage>(Errno::enoexec);
    if (eh.e_ident[4] != loader::kClass64)
        return err<WhpImage>(Errno::enoexec);
    // A foreign-arch ELF cannot run natively -- there is no emulator here, so
    // ENOEXEC is the honest answer rather than a crash at the entry point.
    if (static_cast<loader::EMachine>(eh.e_machine) != loader::EMachine::x86_64)
        return err<WhpImage>(Errno::enoexec);

    const bool pie = static_cast<loader::EType>(eh.e_type) == loader::EType::dyn;
    WhpImage img{};
    img.load_bias = pie ? bias : 0;
    img.phnum = eh.e_phnum;
    img.phent = eh.e_phentsize;
    // AT_PHDR must point at the program headers IN GUEST MEMORY. A PT_PHDR
    // segment names them explicitly, but ld.so itself (and any ELF linked
    // without one) has none -- so fall back to e_phoff, correct whenever the
    // headers lie inside a PT_LOAD, as they do for every real binary. Getting
    // this wrong hands glibc's loader a bogus AT_PHDR, which it dereferences
    // while locating its own dynamic segment, dying long before main.
    img.phdr_addr = img.load_bias + eh.e_phoff;
    bool have_pt_phdr = false;

    for (std::uint16_t i = 0; i < eh.e_phnum; ++i) {
        loader::Phdr ph{};
        if (std::fseek(f, static_cast<long>(eh.e_phoff + i * eh.e_phentsize),
                       SEEK_SET) != 0)
            return err<WhpImage>(Errno::enoexec);
        if (std::fread(&ph, 1, sizeof ph, f) != sizeof ph)
            return err<WhpImage>(Errno::enoexec);

        if (static_cast<loader::PType>(ph.p_type) == loader::PType::phdr) {
            img.phdr_addr = img.load_bias + ph.p_vaddr;
            have_pt_phdr = true;
        }
        if (static_cast<loader::PType>(ph.p_type) != loader::PType::load)
            continue;

        // No PT_PHDR: locate the headers by FILE OFFSET inside this LOAD and
        // translate to its vaddr. bias + e_phoff is only right when the first
        // LOAD maps offset 0 at vaddr 0 (a PIE); a static ET_EXEC at 0x400000
        // would otherwise get AT_PHDR=0x40 and walk the phdrs through a null
        // page.
        if (!have_pt_phdr && eh.e_phoff >= ph.p_offset &&
            eh.e_phoff < ph.p_offset + ph.p_filesz)
            img.phdr_addr = img.load_bias + ph.p_vaddr + (eh.e_phoff - ph.p_offset);

        const std::uint64_t va  = img.load_bias + ph.p_vaddr;
        const std::uint64_t beg = va & ~kPageMask;
        const std::uint64_t end = (va + ph.p_memsz + kPageMask) & ~kPageMask;

        // Enter the segment into the page tables with the ELF's own
        // permissions BEFORE writing it. Note we must map writable here even
        // for a read-only segment, because we are about to fill it; the final
        // protection is applied after the copy.
        if (auto st = vm.map_pages(beg, end - beg, /*writable=*/true,
                                   (ph.p_flags & loader::kPfX) != 0);
            !st)
            return err<WhpImage>(Errno::enomem);

        // Zero [filesz, memsz) so .bss reads as zero, then fill the
        // file-backed part.
        auto span = vm.ram().at(beg, end - beg);
        if (span.empty()) return err<WhpImage>(Errno::enomem);
        std::memset(span.data(), 0, span.size());

        if (ph.p_filesz) {
            auto dst = vm.ram().at(va, ph.p_filesz);
            if (dst.empty()) return err<WhpImage>(Errno::enomem);
            if (std::fseek(f, static_cast<long>(ph.p_offset), SEEK_SET) != 0)
                return err<WhpImage>(Errno::enoexec);
            if (std::fread(dst.data(), 1, ph.p_filesz, f) != ph.p_filesz)
                return err<WhpImage>(Errno::enoexec);
        }

        if (end > img.image_end) img.image_end = end;
        img.segments.push_back({beg, end, ph.p_flags});
    }

    // Now that the bytes are in place, drop write permission on segments the
    // ELF declared read-only. Done as a second pass so W^X holds for the
    // guest without having to write through a read-only mapping.
    for (const auto& sg : img.segments) {
        if ((sg.flags & loader::kPfW) == 0) {
            if (auto st = vm.map_pages(sg.begin, sg.end - sg.begin,
                                       /*writable=*/false,
                                       (sg.flags & loader::kPfX) != 0);
                !st)
                return err<WhpImage>(Errno::enomem);
        }
    }

    img.entry = img.load_bias + eh.e_entry;
    // No I-cache maintenance: x86-64's instruction cache is coherent with
    // stores. (The arm64 backend must flush here.)
    return ok(img);
}

// Read PT_INTERP, if the image names a dynamic linker. Returned as a guest
// path, which the caller translates through the file namespace before load.
[[nodiscard]] inline Result<std::string> whp_read_interp(const std::string& host_path) {
    std::FILE* f = std::fopen(host_path.c_str(), "rb");
    if (!f) return err<std::string>(Errno::enoent);
    struct Closer { std::FILE* f; ~Closer() { std::fclose(f); } } c{f};

    loader::Ehdr eh{};
    if (std::fread(&eh, 1, sizeof eh, f) != sizeof eh)
        return err<std::string>(Errno::enoexec);

    for (std::uint16_t i = 0; i < eh.e_phnum; ++i) {
        loader::Phdr ph{};
        if (std::fseek(f, static_cast<long>(eh.e_phoff + i * eh.e_phentsize),
                       SEEK_SET) != 0)
            return err<std::string>(Errno::enoexec);
        if (std::fread(&ph, 1, sizeof ph, f) != sizeof ph)
            return err<std::string>(Errno::enoexec);
        if (static_cast<loader::PType>(ph.p_type) != loader::PType::interp)
            continue;
        if (ph.p_filesz == 0 || ph.p_filesz > 4096)
            return err<std::string>(Errno::enoexec);
        std::string s(static_cast<std::size_t>(ph.p_filesz), '\0');
        if (std::fseek(f, static_cast<long>(ph.p_offset), SEEK_SET) != 0)
            return err<std::string>(Errno::enoexec);
        if (std::fread(s.data(), 1, s.size(), f) != s.size())
            return err<std::string>(Errno::enoexec);
        if (auto nul = s.find('\0'); nul != std::string::npos) s.resize(nul);
        return ok(s);
    }
    return ok(std::string{});   // statically linked
}

// Build the System V / Linux x86-64 process startup stack:
//
//    [ argc ][ argv... NULL ][ envp... NULL ][ auxv... AT_NULL ][ strings ]
//
// glibc's and musl's __libc_start_main read exactly this. AT_PHDR/AT_PHNUM/
// AT_ENTRY let a dynamic linker find the program it must relocate, and
// AT_RANDOM must point at 16 real bytes or musl's stack-guard init faults.
//
// The ABI requires rsp to be 16-byte aligned AT THE ENTRY POINT, with argc
// at [rsp]. Getting that wrong misaligns every SSE spill in libc's startup
// and crashes in movaps -- which looks like a libc bug, not a loader bug.
[[nodiscard]] inline Result<std::uint64_t> whp_build_stack(
        WhpMachine& vm,
        const WhpImage& img,
        const std::vector<std::string>& argv,
        const std::vector<std::string>& envp,
        std::uint64_t at_base = 0,
        const std::string& execfn = {}) {
    const std::uint64_t ram = vm.ram().size();
    if (ram <= WhpLayout::stack_guard + WhpLayout::stack_size +
                   WhpMachine::kTableArenaSize)
        return err<std::uint64_t>(Errno::enomem);

    const std::uint64_t stack_top = WhpLayout::stack_top(ram);
    const std::uint64_t stack_bot = stack_top - WhpLayout::stack_size;

    // The stack must be mapped for the guest: writable, never executable.
    if (auto st = vm.map_pages(stack_bot, WhpLayout::stack_size,
                               /*writable=*/true, /*executable=*/false);
        !st)
        return err<std::uint64_t>(Errno::enomem);

    std::uint64_t sp = stack_top;

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
    const std::uint64_t platform_addr = push_str("x86_64");

    // AT_RANDOM: 16 bytes seeding the stack protector and pointer guard.
    // Real entropy -- a fixed value would make every guest's canary equal.
    unsigned char rnd[16];
    if (!whp_random_bytes(rnd, sizeof rnd))
        return err<std::uint64_t>(Errno::eio);
    const std::uint64_t rnd_addr = push_bytes(rnd, sizeof rnd);

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
    aux(6,  kPageSize);                        // AT_PAGESZ
    aux(7,  at_base);                          // AT_BASE: the interpreter
    aux(8,  0);                                // AT_FLAGS
    aux(9,  img.entry);                        // AT_ENTRY
    aux(11, 0); aux(12, 0); aux(13, 0); aux(14, 0);  // AT_UID/EUID/GID/EGID
    aux(15, platform_addr);                    // AT_PLATFORM
    // AT_HWCAP: on x86-64, glibc's ifunc resolvers use CPUID rather than
    // this word, so 0 is honest and costs nothing.
    aux(16, 0);
    aux(17, 100);                              // AT_CLKTCK
    aux(23, 0);                                // AT_SECURE
    aux(25, rnd_addr);                         // AT_RANDOM
    aux(31, execfn_addr);                      // AT_EXECFN
    aux(0,  0);                                // AT_NULL

    // Align so that AFTER pushing the vector, rsp is 16-byte aligned with
    // argc at [rsp] -- the ABI's entry condition.
    if (v.size() % 2) v.push_back(0);

    sp -= v.size() * 8;
    sp &= ~std::uint64_t{0xf};
    auto win = vm.ram().at(sp, v.size() * 8);
    if (win.empty()) return err<std::uint64_t>(Errno::enomem);
    std::memcpy(win.data(), v.data(), v.size() * 8);
    return ok(sp);
}

} // namespace lx::runtime

#endif // _WIN32 && x86-64
