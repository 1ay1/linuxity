// linuxity/runtime/darwin/mem.hpp
//
// Typed views onto guest physical memory.
//
// hv_vm_map SHARES the host pages with the guest, so guest memory is directly
// addressable while the vCPU is stopped. That makes guest access a memcpy
// instead of ptrace's process_vm_readv -- but "directly addressable" is
// exactly the condition under which a kernel bug becomes a host memory
// corruption, so every access goes through one bounds-checked choke point
// that hands back a std::span. A raw pointer never escapes this file.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/abi/wire/iovec.hpp"
#include "linuxity/abi/result.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>

namespace lx::runtime {

// A bounds-checked window onto guest RAM. Constructed only by HvfVm, so the
// invariant "this span lies inside guest memory and outside the hypervisor's
// private area" holds by construction.
class GuestRam {
public:
    GuestRam() = default;
    GuestRam(std::byte* base, std::uint64_t size, std::uint64_t floor) noexcept
        : base_{base}, size_{size}, floor_{floor} {}
    // `hole` is a guest-owned range that lies BELOW floor_ (the non-PIE
    // window: the table array sits above it, so a fixed-address ET_EXEC
    // image loads there). Without it, loading gcc hit floor_ and failed
    // ENOMEM.
    GuestRam(std::byte* base, std::uint64_t size, std::uint64_t floor,
             std::uint64_t hole_beg, std::uint64_t hole_end) noexcept
        : base_{base}, size_{size}, floor_{floor},
          hole_beg_{hole_beg}, hole_end_{hole_end} {}

    // Is [gpa, gpa+n) guest-accessible? Either wholly at/above floor_, or
    // wholly inside the carve-out hole. Subtraction order avoids overflow.
    [[nodiscard]] bool permits(std::uint64_t gpa, std::size_t n) const noexcept {
        if (gpa >= size_ || n > size_ - gpa) return false;
        if (gpa >= floor_) return true;
        return gpa >= hole_beg_ && n <= hole_end_ - gpa;
    }

    // The guest-visible range, or an empty span if [gpa, gpa+n) escapes it.
    // Note the subtraction order: `n > size_ - gpa` cannot overflow, whereas
    // the obvious `gpa + n > size_` can wrap for a hostile gpa.
    [[nodiscard]] std::span<std::byte> at(std::uint64_t gpa, std::size_t n) const noexcept {
        if (!permits(gpa, n)) return {};
        return {base_ + gpa, n};
    }

    // Like at(), but CLAMPS instead of refusing: a read/write whose buffer
    // runs off the end of RAM transfers what fits, which is what a real
    // kernel does for a partially valid iovec (short count, not EFAULT).
    [[nodiscard]] std::span<std::byte> clamp(std::uint64_t gpa, std::size_t n) const noexcept {
        if (gpa >= size_) return {};
        std::uint64_t top = size_;
        if (gpa < floor_) {
            if (gpa < hole_beg_ || gpa >= hole_end_) return {};
            top = hole_end_;                    // clamp within the hole
        }
        return {base_ + gpa, std::min<std::uint64_t>(n, top - gpa)};
    }

    [[nodiscard]] bool valid() const noexcept { return base_ != nullptr; }
    [[nodiscard]] std::uint64_t size() const noexcept { return size_; }

    // Read a NUL-terminated guest string. Bounded by the mapping end and by
    // `limit` (PATH_MAX by default), so a guest pointing at unterminated
    // memory costs a bounded scan, not a walk off the end.
    [[nodiscard]] std::string cstr(std::uint64_t gpa, std::size_t limit = 4096) const {
        auto win = clamp(gpa, limit);
        if (win.empty()) return {};
        auto* p = reinterpret_cast<const char*>(win.data());
        std::size_t n = ::strnlen(p, win.size());
        return std::string{p, n};
    }

    // Typed struct store: the guest buffer must hold the WHOLE object or the
    // call fails -- a partially written struct stat is worse than EFAULT.
    template <class T>
    [[nodiscard]] bool put(std::uint64_t gpa, const T& v) const noexcept {
        auto win = at(gpa, sizeof(T));
        if (win.empty()) return false;
        std::memcpy(win.data(), &v, sizeof(T));
        return true;
    }
    template <class T>
    [[nodiscard]] bool get(std::uint64_t gpa, T& v) const noexcept {
        auto win = at(gpa, sizeof(T));
        if (win.empty()) return false;
        std::memcpy(&v, win.data(), sizeof(T));
        return true;
    }

private:
    std::byte* base_{nullptr};
    std::uint64_t size_{0};
    std::uint64_t floor_{0};       // first guest-accessible gpa
    // A guest-owned carve-out BELOW floor_ (empty when hole_beg_==hole_end_).
    std::uint64_t hole_beg_{0};
    std::uint64_t hole_end_{0};
};

// A guest iovec, as the Linux ABI lays it out.
// struct iovec as the guest lays it out. Declared ONCE in
// abi/wire/iovec.hpp -- the shape is ABI and was identical in both backends.
using GuestIovec = abi::wire::Iovec;

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
