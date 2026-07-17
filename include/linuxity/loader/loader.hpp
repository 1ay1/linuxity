// linuxity/loader/loader.hpp
//
// The ELF loader: turn an ELF image into a ready-to-run address space.
//
// This is the step that makes native execution possible. On x86-64 the
// guest binary IS x86-64 machine code, so we do not interpret it — we map
// its PT_LOAD segments at their virtual addresses, zero the .bss tail, apply
// R/W/X permissions, and hand back the entry point. Control then transfers
// to guest code directly (see runtime/enter). No emulation, native speed.
//
// The loader is generic over a byte source (so it reads equally from the VFS
// or a raw buffer) and over the host (so the segments land in a real
// AddressSpace<H>). It validates the ELF against the Linux ABI it targets.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/loader/elf.hpp"
#include "linuxity/mm/address_space.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace lx::loader {

// A minimal random-access byte source. Anything the loader can pread from:
// a VFS file, an in-memory buffer, a mmap. Modeled as a concept so the
// loader stays decoupled from where the bytes live.
template <class S>
concept ByteSource = requires(S s, std::uint64_t off, std::span<std::byte> buf) {
    { s.pread(off, buf) } -> std::same_as<Result<std::size_t>>;
    { s.size() }          -> std::same_as<std::uint64_t>;
};

// A trivial ByteSource over a contiguous buffer (tests, embedded images).
class BufferSource {
public:
    explicit BufferSource(std::span<const std::byte> data) : data_{data} {}
    [[nodiscard]] Result<std::size_t> pread(std::uint64_t off, std::span<std::byte> buf) const {
        if (off >= data_.size()) return ok(std::size_t{0});
        std::size_t n = std::min(buf.size(), data_.size() - off);
        std::memcpy(buf.data(), data_.data() + off, n);
        return ok(n);
    }
    [[nodiscard]] std::uint64_t size() const noexcept { return data_.size(); }
private:
    std::span<const std::byte> data_;
};

// The result of loading: everything the process-init needs to start.
struct Loaded {
    UAddr    entry{};          // where to begin execution
    UAddr    phdr{};           // guest address of the program headers (AT_PHDR)
    std::uint64_t phent{};     // size of one phdr (AT_PHENT)
    std::uint64_t phnum{};     // number of phdrs (AT_PHNUM)
    UAddr    load_base{};      // base the image was loaded at (0 for ET_EXEC)
    EMachine machine{};        // ISA — must equal the host ISA for native run
    std::string interp;        // PT_INTERP path (dynamic linker), empty if static
};

inline constexpr std::size_t kPageSize = 4096;
[[nodiscard]] constexpr std::uint64_t page_down(std::uint64_t a) noexcept {
    return a & ~(kPageSize - 1);
}
[[nodiscard]] constexpr std::uint64_t page_up(std::uint64_t a) noexcept {
    return (a + kPageSize - 1) & ~(kPageSize - 1);
}

template <host::Host H>
class Loader {
public:
    explicit Loader(mm::AddressSpace<H>& as) : as_{as} {}

    template <ByteSource S>
    [[nodiscard]] Result<Loaded> load(const S& src) {
        // -- 1. Read + validate the ELF header. ---------------------------
        Ehdr eh{};
        LX_TRY(read_exact(src, 0, as_bytes(eh)));
        LX_TRY(validate(eh));

        Loaded out;
        out.machine = static_cast<EMachine>(eh.e_machine);
        out.phent   = eh.e_phentsize;
        out.phnum   = eh.e_phnum;

        // ET_DYN (PIE) loads at a base we choose; ET_EXEC uses its vaddrs.
        std::uint64_t base = (static_cast<EType>(eh.e_type) == EType::dyn)
                                 ? kPieBase : 0;
        out.load_base = uaddr(base);

        // -- 2. Read the program header table. ----------------------------
        std::vector<Phdr> phdrs(eh.e_phnum);
        for (std::uint16_t i = 0; i < eh.e_phnum; ++i) {
            std::uint64_t off = eh.e_phoff + std::uint64_t(i) * eh.e_phentsize;
            LX_TRY(read_exact(src, off, as_bytes(phdrs[i])));
        }

        // -- 3. Map each PT_LOAD; note PT_INTERP / PT_PHDR. ---------------
        for (const Phdr& ph : phdrs) {
            switch (static_cast<PType>(ph.p_type)) {
                case PType::load:
                    LX_TRY(map_segment(src, ph, base));
                    break;
                case PType::interp:
                    out.interp = LX_TRY(read_interp(src, ph));
                    break;
                case PType::phdr:
                    out.phdr = uaddr(base + ph.p_vaddr);
                    break;
                default:
                    break;
            }
        }
        // If no PT_PHDR, derive AT_PHDR from the first PT_LOAD covering phoff.
        if (value(out.phdr) == 0)
            out.phdr = uaddr(base + eh.e_phoff);

        out.entry = uaddr(base + eh.e_entry);
        return ok(out);
    }

private:
    // The base address at which we load PIE / ET_DYN images (below the
    // typical mmap region, well clear of the null page).
    static constexpr std::uint64_t kPieBase = 0x55'5555'000000ull;

    template <class T>
    static std::span<std::byte> as_bytes(T& v) {
        return {reinterpret_cast<std::byte*>(&v), sizeof(T)};
    }

    [[nodiscard]] static Status validate(const Ehdr& eh) {
        if (eh.e_ident[0] != kMag0 || eh.e_ident[1] != kMag1 ||
            eh.e_ident[2] != kMag2 || eh.e_ident[3] != kMag3)
            return err(Errno::enoexec);              // not an ELF
        if (eh.e_ident[4] != kClass64) return err(Errno::enoexec);   // not 64-bit
        if (eh.e_ident[5] != kData2LSB) return err(Errno::enoexec);  // not LE
        auto t = static_cast<EType>(eh.e_type);
        if (t != EType::exec && t != EType::dyn) return err(Errno::enoexec);
        return ok();
    }

    template <ByteSource S>
    [[nodiscard]] Status read_exact(const S& src, std::uint64_t off,
                                    std::span<std::byte> buf) {
        std::size_t got = LX_TRY(src.pread(off, buf));
        return got == buf.size() ? ok() : err(Errno::enoexec);
    }

    template <ByteSource S>
    [[nodiscard]] Result<std::string> read_interp(const S& src, const Phdr& ph) {
        std::string s(ph.p_filesz, '\0');
        std::size_t n = LX_TRY(src.pread(
            ph.p_offset, {reinterpret_cast<std::byte*>(s.data()), s.size()}));
        s.resize(n);
        if (!s.empty() && s.back() == '\0') s.pop_back();
        return ok(std::move(s));
    }

    template <ByteSource S>
    [[nodiscard]] Status map_segment(const S& src, const Phdr& ph, std::uint64_t base) {
        std::uint64_t vaddr = base + ph.p_vaddr;
        std::uint64_t start = page_down(vaddr);
        std::uint64_t end   = page_up(vaddr + ph.p_memsz);
        std::size_t   len   = static_cast<std::size_t>(end - start);

        mm::Perm perm = mm::Perm::none;
        if (ph.p_flags & kPfR) perm = perm | mm::Perm::read;
        if (ph.p_flags & kPfW) perm = perm | mm::Perm::write;
        if (ph.p_flags & kPfX) perm = perm | mm::Perm::exec;

        LX_TRY(as_.map_fixed(uaddr(start), len, perm));

        // Fill the file-backed portion, then rely on fresh-mapped zero for
        // the .bss tail (memsz > filesz).
        if (ph.p_filesz > 0) {
            std::vector<std::byte> tmp(ph.p_filesz);
            std::size_t got = LX_TRY(src.pread(ph.p_offset, tmp));
            if (got != ph.p_filesz) return err(Errno::enoexec);
            LX_TRY(as_.write(uaddr(vaddr), tmp));
        }
        return ok();
    }

    mm::AddressSpace<H>& as_;
};

} // namespace lx::loader
