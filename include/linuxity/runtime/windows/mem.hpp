// linuxity/runtime/windows/mem.hpp
//
// Typed views onto guest memory, and the page-table walk that gets there.
//
// WHvMapGpaRange SHARES host pages with the guest (it takes a host VA and
// pins it into the partition's physical space), so guest memory is directly
// addressable from the runtime while the vCPU is stopped. That makes a guest
// access a bounds-checked memcpy rather than ptrace's process_vm_readv -- but
// "directly addressable" is precisely the condition under which a kernel bug
// becomes HOST memory corruption. So every access funnels through one checked
// choke point that hands back a std::span, and a raw pointer never escapes.
//
// THE X86-64 DIFFERENCE FROM DARWIN. On aarch64 we can hand the guest a flat
// address space. On x86-64 there is no such option: 64-bit long mode REQUIRES
// CR0.PG with 4-level paging, so every guest virtual address must be walked
// through the page tables we built to find its guest-physical address before
// we can touch it. Two consequences, both handled here:
//
//   1. GVA != GPA, so reading a syscall's char* argument means WALKING. The
//      walk is the same one the CPU's MMU does (PML4 -> PDPT -> PD -> PT),
//      reading our own tables out of guest RAM.
//   2. A guest buffer can STRADDLE pages that are not physically contiguous.
//      A naive `span` over a straddling buffer would silently read the wrong
//      page, so the scatter helpers below split at page boundaries and the
//      single-span `at()` refuses a straddle rather than lying.
#pragma once

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))

#include "linuxity/abi/wire/iovec.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace lx::runtime {

inline constexpr std::uint64_t kPageSize  = 4096;
inline constexpr std::uint64_t kPageShift = 12;
inline constexpr std::uint64_t kPageMask  = kPageSize - 1;

// x86-64 page-table entry bits.
inline constexpr std::uint64_t kPtePresent = 1ull << 0;
inline constexpr std::uint64_t kPteWrite   = 1ull << 1;
inline constexpr std::uint64_t kPteUser    = 1ull << 2;
inline constexpr std::uint64_t kPtePageSize= 1ull << 7;  // PS: 2MiB/1GiB leaf
inline constexpr std::uint64_t kPteNx      = 1ull << 63;
// The physical address field of a PTE (bits 51:12).
inline constexpr std::uint64_t kPteAddrMask = 0x000ffffffffff000ull;

// -- Guest physical memory -------------------------------------------------
// A bounds-checked window onto guest RAM. Constructed only by WhpMachine, so
// the invariant "this span lies inside guest RAM and outside the runtime's
// private area" holds by construction.
class GuestRam {
public:
    GuestRam() = default;
    GuestRam(std::byte* base, std::uint64_t size, std::uint64_t floor) noexcept
        : base_{base}, size_{size}, floor_{floor} {}

    // Is [gpa, gpa+n) guest-accessible? Subtraction order avoids the overflow
    // that `gpa + n > size_` suffers for a hostile gpa.
    [[nodiscard]] bool permits(std::uint64_t gpa, std::size_t n) const noexcept {
        if (gpa >= size_ || n > size_ - gpa) return false;
        return gpa >= floor_;
    }

    // The guest-visible range, or an empty span if it escapes RAM.
    [[nodiscard]] std::span<std::byte> at(std::uint64_t gpa, std::size_t n) const noexcept {
        if (!permits(gpa, n)) return {};
        return {base_ + gpa, n};
    }

    // Like at(), but CLAMPS rather than refusing: a transfer whose buffer runs
    // off the end moves what fits, which is what a real kernel does for a
    // partially valid iovec (a short count, not EFAULT).
    [[nodiscard]] std::span<std::byte> clamp(std::uint64_t gpa, std::size_t n) const noexcept {
        if (gpa >= size_ || gpa < floor_) return {};
        return {base_ + gpa, std::min<std::uint64_t>(n, size_ - gpa)};
    }

    // Unchecked access to the table region BELOW floor_. Only the page-table
    // builder and the MMU walk may use this -- hence the explicit name, so an
    // audit can grep for every caller. The range is still bounds-checked
    // against RAM; what it waives is the guest-accessibility floor.
    [[nodiscard]] std::span<std::byte> at_table(std::uint64_t gpa, std::size_t n) const noexcept {
        if (gpa >= size_ || n > size_ - gpa) return {};
        return {base_ + gpa, n};
    }

    [[nodiscard]] bool valid() const noexcept { return base_ != nullptr; }
    [[nodiscard]] std::uint64_t size() const noexcept { return size_; }
    [[nodiscard]] std::uint64_t floor() const noexcept { return floor_; }
    [[nodiscard]] std::byte* host_base() const noexcept { return base_; }

    template <class T>
    [[nodiscard]] bool put_phys(std::uint64_t gpa, const T& v) const noexcept {
        auto win = at(gpa, sizeof(T));
        if (win.empty()) return false;
        std::memcpy(win.data(), &v, sizeof(T));
        return true;
    }
    template <class T>
    [[nodiscard]] bool get_phys(std::uint64_t gpa, T& v) const noexcept {
        auto win = at(gpa, sizeof(T));
        if (win.empty()) return false;
        std::memcpy(&v, win.data(), sizeof(T));
        return true;
    }

private:
    std::byte* base_{nullptr};
    std::uint64_t size_{0};
    std::uint64_t floor_{0};   // first guest-accessible gpa (tables live below)
};

// -- The MMU walk ----------------------------------------------------------
// Translate a guest VIRTUAL address to guest-physical by walking the same
// 4-level tables the hardware walks. We read them from guest RAM rather than
// keeping a shadow copy, so the answer is by construction the one the CPU
// would compute -- a shadow map that drifts from the real tables is the
// classic source of "works until it doesn't" address-space bugs.
//
// Honors 1GiB and 2MiB leaves (the PS bit), because the loader uses large
// pages to map the bulk of RAM and a walker that only understood 4KiB leaves
// would fail on exactly the common case.
struct Walk {
    std::uint64_t gpa = 0;
    bool present = false;
    bool writable = false;
    bool user = false;
    // Bytes from `gpa` to the end of the containing leaf page. A buffer longer
    // than this straddles into a different (possibly non-contiguous) frame.
    std::uint64_t to_page_end = 0;

    [[nodiscard]] explicit operator bool() const noexcept { return present; }
};

class Mmu {
public:
    Mmu() = default;
    Mmu(const GuestRam& ram, std::uint64_t cr3) noexcept : ram_{ram}, cr3_{cr3} {}

    [[nodiscard]] std::uint64_t cr3() const noexcept { return cr3_; }

    [[nodiscard]] Walk translate(std::uint64_t gva) const noexcept {
        Walk w{};
        if (!ram_.valid()) return w;

        // Canonical-address check: bits 63:48 must replicate bit 47. A
        // non-canonical address is a #GP on real hardware, so refusing it here
        // keeps the runtime's view identical to the CPU's.
        const std::uint64_t hi = gva >> 47;
        if (hi != 0 && hi != 0x1ffff) return w;

        std::uint64_t table = cr3_ & kPteAddrMask;
        bool writable = true, user = true;

        // Levels 4,3,2,1 -> shifts 39,30,21,12.
        for (int level = 4; level >= 1; --level) {
            const unsigned shift = unsigned(12 + 9 * (level - 1));
            const std::uint64_t idx = (gva >> shift) & 0x1ff;
            // Tables live BELOW the guest floor, so read them through the
            // table accessor (bounds-checked against RAM, floor waived).
            auto cell = ram_.at_table(table + idx * 8, 8);
            if (cell.empty()) return w;
            std::uint64_t e = 0;
            std::memcpy(&e, cell.data(), 8);

            if (!(e & kPtePresent)) return w;
            writable = writable && (e & kPteWrite) != 0;
            user     = user     && (e & kPteUser)  != 0;

            const bool leaf = (level == 1) || ((e & kPtePageSize) != 0);
            if (leaf) {
                // The leaf's size is determined by the level it terminated at:
                // level 1 = 4KiB, level 2 = 2MiB, level 3 = 1GiB.
                const std::uint64_t leaf_size = 1ull << shift;
                const std::uint64_t frame = e & kPteAddrMask & ~(leaf_size - 1);
                const std::uint64_t off = gva & (leaf_size - 1);
                w.gpa = frame + off;
                w.present = true;
                w.writable = writable;
                w.user = user;
                w.to_page_end = leaf_size - off;
                return w;
            }
            table = e & kPteAddrMask;
        }
        return w;
    }

private:
    GuestRam ram_{};
    std::uint64_t cr3_{0};
};

// -- The guest memory accessor --------------------------------------------
// What the syscall layer actually uses: virtual-address reads and writes that
// transparently handle page straddling. This is the x86-64 analogue of
// hvf_mem's GuestRam, with the MMU folded in.
class GuestMemView {
public:
    GuestMemView() = default;
    GuestMemView(const GuestRam& ram, const Mmu& mmu) noexcept
        : ram_{ram}, mmu_{mmu} {}

    [[nodiscard]] bool valid() const noexcept { return ram_.valid(); }
    [[nodiscard]] const GuestRam& ram() const noexcept { return ram_; }
    [[nodiscard]] const Mmu& mmu() const noexcept { return mmu_; }

    // A contiguous span for [gva, gva+n) -- ONLY if the range lies within a
    // single leaf page, so the host pointer really is contiguous. Returns an
    // empty span on a straddle; callers that must handle long buffers use
    // copy_in/copy_out, which stitch page by page.
    [[nodiscard]] std::span<std::byte> at(std::uint64_t gva, std::size_t n) const noexcept {
        auto w = mmu_.translate(gva);
        if (!w || n > w.to_page_end) return {};
        return ram_.at(w.gpa, n);
    }

    // Copy OUT of the guest (guest -> host buffer), stitching across pages.
    // Returns bytes transferred, which is short if the guest range becomes
    // unmapped partway -- exactly a real kernel's partial-copy behavior.
    [[nodiscard]] std::size_t copy_in(std::uint64_t gva, std::span<std::byte> dst) const noexcept {
        std::size_t done = 0;
        while (done < dst.size()) {
            auto w = mmu_.translate(gva + done);
            if (!w) break;
            const std::size_t chunk =
                std::min<std::uint64_t>(dst.size() - done, w.to_page_end);
            auto src = ram_.at(w.gpa, chunk);
            if (src.empty()) break;
            std::memcpy(dst.data() + done, src.data(), chunk);
            done += chunk;
        }
        return done;
    }

    // Copy INTO the guest (host buffer -> guest). Refuses read-only pages, so
    // a guest that passes a const buffer to a writing syscall gets EFAULT
    // instead of silently having its text segment modified.
    [[nodiscard]] std::size_t copy_out(std::uint64_t gva, std::span<const std::byte> src) const noexcept {
        std::size_t done = 0;
        while (done < src.size()) {
            auto w = mmu_.translate(gva + done);
            if (!w || !w.writable) break;
            const std::size_t chunk =
                std::min<std::uint64_t>(src.size() - done, w.to_page_end);
            auto dst = ram_.at(w.gpa, chunk);
            if (dst.empty()) break;
            std::memcpy(dst.data(), src.data() + done, chunk);
            done += chunk;
        }
        return done;
    }

    // Read a NUL-terminated guest string, bounded by `limit` (PATH_MAX by
    // default) and by the mapping, so an unterminated pointer costs a bounded
    // scan rather than a walk off the end of RAM. Crosses pages, because a
    // path can straddle and refusing that would break long paths at random.
    [[nodiscard]] std::string cstr(std::uint64_t gva, std::size_t limit = 4096) const {
        std::string out;
        out.reserve(64);
        while (out.size() < limit) {
            auto w = mmu_.translate(gva + out.size());
            if (!w) break;
            const std::size_t chunk =
                std::min<std::uint64_t>(limit - out.size(), w.to_page_end);
            auto win = ram_.at(w.gpa, chunk);
            if (win.empty()) break;
            const char* p = reinterpret_cast<const char*>(win.data());
            const std::size_t n = ::strnlen(p, win.size());
            out.append(p, n);
            if (n < win.size()) break;   // found the terminator
        }
        return out;
    }

    // Typed transfers: the guest buffer must hold the WHOLE object or the call
    // fails. A half-written struct stat is worse than EFAULT.
    template <class T>
    [[nodiscard]] bool put(std::uint64_t gva, const T& v) const noexcept {
        std::byte buf[sizeof(T)];
        std::memcpy(buf, &v, sizeof(T));
        return copy_out(gva, std::span<const std::byte>{buf, sizeof(T)}) == sizeof(T);
    }
    template <class T>
    [[nodiscard]] bool get(std::uint64_t gva, T& v) const noexcept {
        std::byte buf[sizeof(T)];
        if (copy_in(gva, std::span<std::byte>{buf, sizeof(T)}) != sizeof(T))
            return false;
        std::memcpy(&v, buf, sizeof(T));
        return true;
    }

private:
    GuestRam ram_{};
    Mmu mmu_{};
};

// A guest iovec, as the Linux ABI lays it out.
// struct iovec as the guest lays it out. Declared ONCE in
// abi/wire/iovec.hpp -- the shape is ABI and was identical in both backends.
using GuestIovec = abi::wire::Iovec;

} // namespace lx::runtime

#endif // _WIN32 && x86-64
