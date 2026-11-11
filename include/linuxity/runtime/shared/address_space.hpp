// linuxity/runtime/shared/address_space.hpp
//
// The guest address space: an interval map of virtual memory areas.
//
// Linux mmap/munmap/mprotect/brk operate on an ordered set of VMAs, and the
// hard part is not allocation but SPLITTING: munmap of the middle of a
// mapping leaves two, mprotect of a sub-range leaves three. A backend that
// models only whole mappings (a flat map keyed by start address) leaks
// address space on every partial unmap, and musl's malloc does partial
// unmaps constantly -- so a long-running guest dies of ENOMEM.
//
// So this is a real interval map: a sorted vector of disjoint, non-adjacent
// VMAs with split/merge, plus first-fit placement from the top down. Sorted
// vector rather than a node-based map because the VMA count is small (tens,
// not thousands) and a linear scan over contiguous memory beats pointer
// chasing at that size -- while keeping O(log n) lookup via binary search.
//
// HOST-AGNOSTIC: this is pure interval arithmetic -- no hypervisor, no OS
// calls -- so it is deliberately NOT platform-gated. Both kernel-less
// backends build on it: HVF (macOS/arm64) and WHP (Windows/x86-64) need the
// identical mmap/munmap/mprotect/brk semantics, and duplicating a splitting
// interval map per backend is how the two drift apart.
#pragma once

#include "linuxity/abi/wire/mmap.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

namespace lx::runtime {

// Guest page protection, mirroring PROT_*. Kept as a strong enum so a raw
// Linux flag word can never be passed where a translated one is wanted.
enum class GuestProt : unsigned { none = 0, read = 1, write = 2, exec = 4 };

[[nodiscard]] constexpr GuestProt operator|(GuestProt a, GuestProt b) noexcept {
    return static_cast<GuestProt>(static_cast<unsigned>(a) | static_cast<unsigned>(b));
}
[[nodiscard]] constexpr bool has(GuestProt set, GuestProt p) noexcept {
    return (static_cast<unsigned>(set) & static_cast<unsigned>(p)) != 0;
}

// Translate Linux PROT_* into GuestProt. The bit values come from
// abi/wire/mmap.hpp rather than the literals 1/2/4, so there is one place
// that says what PROT_WRITE is.
[[nodiscard]] constexpr GuestProt prot_from_linux(std::uint64_t p) noexcept {
    auto out = GuestProt::none;
    if (abi::wire::has_prot(p, abi::wire::Prot::read))  out = out | GuestProt::read;
    if (abi::wire::has_prot(p, abi::wire::Prot::write)) out = out | GuestProt::write;
    if (abi::wire::has_prot(p, abi::wire::Prot::exec))  out = out | GuestProt::exec;
    return out;
}

// GuestProt deliberately uses the SAME bit values as the guest's PROT_*, so
// the translation above is a widening rather than a remap. Pinned, because a
// future divergence would make the two silently interchangeable at the call
// sites that pass raw integers around.
static_assert(static_cast<unsigned>(GuestProt::read) ==
              abi::wire::bits(abi::wire::Prot::read));
static_assert(static_cast<unsigned>(GuestProt::write) ==
              abi::wire::bits(abi::wire::Prot::write));
static_assert(static_cast<unsigned>(GuestProt::exec) ==
              abi::wire::bits(abi::wire::Prot::exec));

// ELF PF_X=1, PF_W=2, PF_R=4 -> GuestProt.
[[nodiscard]] constexpr GuestProt prot_from_elf(std::uint64_t pf) noexcept {
    auto out = GuestProt::none;
    if (pf & 4) out = out | GuestProt::read;
    if (pf & 2) out = out | GuestProt::write;
    if (pf & 1) out = out | GuestProt::exec;
    return out;
}

struct Vma {
    std::uint64_t begin{}, end{};      // [begin, end), page-aligned
    GuestProt prot{GuestProt::none};
    bool anonymous{true};

    [[nodiscard]] std::uint64_t size() const noexcept { return end - begin; }
};

class AddressSpace {
public:
    static constexpr std::uint64_t kPageSize = 0x1000;
    static constexpr std::uint64_t kFail = ~std::uint64_t{0};

    [[nodiscard]] static constexpr std::uint64_t page_up(std::uint64_t a) noexcept {
        return (a + kPageSize - 1) & ~(kPageSize - 1);
    }
    [[nodiscard]] static constexpr std::uint64_t page_down(std::uint64_t a) noexcept {
        return a & ~(kPageSize - 1);
    }

    // [low, high) is the region mmap may place into; brk grows up from `low`.
    void reset(std::uint64_t low, std::uint64_t high) {
        vmas_.clear();
        arena_low_ = brk_base_ = brk_cur_ = page_up(low);
        arena_high_ = page_down(high);
    }

    // The allocator's bounds, so a fork child resumes with an identical map.
    struct Arena { std::uint64_t low{}, high{}, brk_base{}; };
    [[nodiscard]] Arena arena() const noexcept { return {arena_low_, arena_high_, brk_base_}; }
    void restore(std::vector<Vma> vmas, std::uint64_t brk, Arena a) {
        vmas_ = std::move(vmas);
        arena_low_ = a.low;
        arena_high_ = a.high;
        brk_base_ = a.brk_base;
        brk_cur_ = brk;
    }

    // -- brk ---------------------------------------------------------------
    [[nodiscard]] std::uint64_t brk() const noexcept { return brk_cur_; }
    [[nodiscard]] std::uint64_t set_brk(std::uint64_t want) {
        if (want == 0) return brk_cur_;                 // query
        if (want < brk_base_) return brk_cur_;          // below the heap floor
        // The heap may grow until the first mapping above the CURRENT break,
        // as on Linux (mm/mmap.c checks the range being added). Measuring
        // from the heap's base instead counted anything mapped inside the
        // heap: musl puts a PROT_NONE guard page just past its first brk
        // pages (mmap MAP_FIXED at the break), and from then on every grow
        // was refused. (Testing against the lowest mapping overall -- the
        // program's own text and data, BELOW the heap -- refused every grow
        // from the start.)
        const std::uint64_t from = page_up(brk_cur_ > brk_base_ ? brk_cur_ : brk_base_);
        if (page_up(want) > from && page_up(want) > ceiling_above(from)) return brk_cur_;
        // Linux returns the requested (unrounded) break, and libc compares
        // against exactly what it asked for.
        brk_cur_ = want;
        return brk_cur_;
    }

    // -- mmap --------------------------------------------------------------
    // MAP_FIXED replaces whatever is there (Linux semantics: it unmaps the
    // range first). Otherwise place top-down in the first gap that fits,
    // which keeps the heap and mmap arena growing toward each other.
    // `align` (a power of two, at least a page) is for a backend whose host
    // pages are bigger than the guest's: a range it backs with host-shared
    // pages must start on a host page.
    [[nodiscard]] std::uint64_t map(std::uint64_t hint, std::uint64_t len,
                                    GuestProt prot, bool fixed, bool anon,
                                    std::uint64_t align = kPageSize) {
        len = page_up(len);
        if (len == 0) return kFail;
        std::uint64_t at;
        if (fixed && hint) {
            at = page_down(hint);
            if (at < arena_low_ || at + len > arena_high_) return kFail;
            unmap(at, len);                   // MAP_FIXED clobbers
        } else {
            auto found = find_gap(len, align);
            if (!found) return kFail;
            at = *found;
        }
        insert({at, at + len, prot, anon});
        return at;
    }

    // -- munmap ------------------------------------------------------------
    // Removes [addr, addr+len) from every overlapping VMA, SPLITTING those it
    // only partially covers. This is the operation a flat map gets wrong.
    void unmap(std::uint64_t addr, std::uint64_t len) {
        const std::uint64_t lo = page_down(addr), hi = page_up(addr + len);
        if (hi <= lo) return;
        std::vector<Vma> rebuilt;
        rebuilt.reserve(vmas_.size() + 2);
        for (const Vma& v : vmas_) {
            if (v.end <= lo || v.begin >= hi) { rebuilt.push_back(v); continue; }
            if (v.begin < lo) rebuilt.push_back({v.begin, lo, v.prot, v.anonymous});
            if (v.end > hi)   rebuilt.push_back({hi, v.end, v.prot, v.anonymous});
        }
        vmas_.swap(rebuilt);
    }

    // -- mprotect ----------------------------------------------------------
    // Same split logic, but the middle piece survives with new permissions.
    // Returns false if the range isn't fully mapped (Linux gives ENOMEM).
    [[nodiscard]] bool protect(std::uint64_t addr, std::uint64_t len, GuestProt prot) {
        const std::uint64_t lo = page_down(addr), hi = page_up(addr + len);
        if (hi <= lo) return true;
        if (!fully_mapped(lo, hi)) return false;
        std::vector<Vma> rebuilt;
        rebuilt.reserve(vmas_.size() + 2);
        for (const Vma& v : vmas_) {
            if (v.end <= lo || v.begin >= hi) { rebuilt.push_back(v); continue; }
            if (v.begin < lo) rebuilt.push_back({v.begin, lo, v.prot, v.anonymous});
            rebuilt.push_back({std::max(v.begin, lo), std::min(v.end, hi),
                               prot, v.anonymous});
            if (v.end > hi)   rebuilt.push_back({hi, v.end, v.prot, v.anonymous});
        }
        vmas_.swap(rebuilt);
        coalesce();
        return true;
    }

    // Record a region that was mapped OUTSIDE this allocator (ELF segments
    // and the startup stack, which the loader writes straight into guest
    // RAM). Such a region may sit below arena_low_; it still has to appear
    // in the map so the guest's mprotect/munmap on it behave, and so
    // /proc/self/maps is truthful.
    void adopt(Vma v) {
        if (v.end <= v.begin) return;
        unmap(v.begin, v.size());        // idempotent: re-adopting is fine
        insert(v);
    }

    // The VMA containing `addr`, for fault diagnosis and /proc/self/maps.
    [[nodiscard]] const Vma* find(std::uint64_t addr) const noexcept {
        auto it = std::upper_bound(vmas_.begin(), vmas_.end(), addr,
                                   [](std::uint64_t a, const Vma& v) { return a < v.begin; });
        if (it == vmas_.begin()) return nullptr;
        --it;
        return addr < it->end ? &*it : nullptr;
    }

    [[nodiscard]] const std::vector<Vma>& vmas() const noexcept { return vmas_; }
    [[nodiscard]] std::uint64_t mapped_bytes() const noexcept {
        std::uint64_t n = 0;
        for (const Vma& v : vmas_) n += v.size();
        return n;
    }

private:
    // First-fit from the TOP of the arena down, mirroring Linux's default
    // topdown layout so the heap (growing up) and mmap (growing down) share
    // the arena without a fixed split point.
    [[nodiscard]] std::optional<std::uint64_t> find_gap(std::uint64_t len,
                                                        std::uint64_t align = kPageSize) const {
        const std::uint64_t mask = ~(align - 1);
        std::uint64_t ceiling = arena_high_;
        for (auto it = vmas_.rbegin(); it != vmas_.rend(); ++it) {
            if (ceiling >= it->end && ceiling - it->end >= len &&
                ((ceiling - len) & mask) >= it->end)
                return (ceiling - len) & mask;
            ceiling = std::min(ceiling, it->begin);
        }
        std::uint64_t floor = std::max(page_up(brk_cur_), arena_low_);
        if (ceiling >= floor && ceiling - floor >= len && ((ceiling - len) & mask) >= floor)
            return (ceiling - len) & mask;
        return std::nullopt;
    }

    // The lowest address at or above `addr` that is already mapped, or the
    // arena top: the hard ceiling for anything growing upward from `addr`.
    [[nodiscard]] std::uint64_t ceiling_above(std::uint64_t addr) const noexcept {
        for (const Vma& v : vmas_)
            if (v.begin >= addr) return v.begin;
        return arena_high_;
    }

    [[nodiscard]] bool fully_mapped(std::uint64_t lo, std::uint64_t hi) const noexcept {
        std::uint64_t cursor = lo;
        for (const Vma& v : vmas_) {
            if (v.end <= cursor) continue;
            if (v.begin > cursor) return false;        // hole
            cursor = v.end;
            if (cursor >= hi) return true;
        }
        return cursor >= hi;
    }

    void insert(Vma v) {
        auto it = std::lower_bound(vmas_.begin(), vmas_.end(), v.begin,
                                   [](const Vma& a, std::uint64_t b) { return a.begin < b; });
        vmas_.insert(it, v);
        coalesce();
    }

    // Merge adjacent VMAs with identical attributes, so a guest that maps
    // page-by-page doesn't grow the vector without bound.
    void coalesce() {
        if (vmas_.size() < 2) return;
        std::vector<Vma> out;
        out.reserve(vmas_.size());
        out.push_back(vmas_.front());
        for (std::size_t i = 1; i < vmas_.size(); ++i) {
            Vma& last = out.back();
            const Vma& cur = vmas_[i];
            if (last.end == cur.begin && last.prot == cur.prot &&
                last.anonymous == cur.anonymous)
                last.end = cur.end;
            else
                out.push_back(cur);
        }
        vmas_.swap(out);
    }

    std::vector<Vma> vmas_;
    std::uint64_t arena_low_{0}, arena_high_{0};
    std::uint64_t brk_base_{0}, brk_cur_{0};
};

} // namespace lx::runtime
