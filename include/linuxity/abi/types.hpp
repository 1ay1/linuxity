// linuxity/abi/types.hpp
//
// Strong integer newtypes for the kernel ABI.
//
// In C, everything is `int` — a pid, an fd, a signal number, and an errno
// are all the same type, so the compiler happily lets you pass a signal
// where an fd belongs. We recover the distinctions the *specification*
// makes but C erases, via a zero-cost phantom-tagged newtype. This is the
// programming-language equivalent of a units-of-measure system.
#pragma once

#include <compare>
#include <cstdint>
#include <functional>

namespace lx {

// A phantom-tagged newtype over an integral representation. Two Ids with
// different Tag types are unrelated types even if their reprs coincide, so
// `Fd{3}` can never be passed where a `Pid` is expected.
template <class Tag, class Repr = std::int32_t>
class Id {
public:
    using repr_type = Repr;

    constexpr Id() = default;
    constexpr explicit Id(Repr v) noexcept : v_{v} {}

    [[nodiscard]] constexpr Repr raw() const noexcept { return v_; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return v_ >= 0; }

    friend constexpr auto operator<=>(Id, Id) = default;

    // In-place successor — handy for monotonic allocators.
    constexpr Id& operator++() noexcept { ++v_; return *this; }

private:
    Repr v_{-1}; // -1 = the canonical "invalid" inhabitant
};

// -- The tags. Empty structs; they exist only to distinguish Id<> instances.
struct FdTag;    struct PidTag;   struct TidTag;   struct UidTag;
struct GidTag;   struct SignalTag; struct InodeTag; struct MountTag;

using Fd     = Id<FdTag,    std::int32_t>;   // file descriptor
using Pid    = Id<PidTag,   std::int32_t>;   // process id
using Tid    = Id<TidTag,   std::int32_t>;   // thread id
using Uid    = Id<UidTag,   std::uint32_t>;  // user id
using Gid    = Id<GidTag,   std::uint32_t>;  // group id
using Signal = Id<SignalTag,std::int32_t>;   // signal number
using Ino    = Id<InodeTag, std::uint64_t>;  // inode number
using MountId= Id<MountTag, std::uint64_t>;  // mount table entry

// -- Guest addresses -------------------------------------------------------
// A pointer *in the guest's address space*. It is deliberately NOT a real
// C++ pointer: the runtime must translate + bounds-check it before touching
// memory, so making it un-dereferenceable at the type level prevents the
// entire class of "kernel followed a userspace pointer blindly" bugs.
enum class UAddr : std::uint64_t {};

[[nodiscard]] constexpr UAddr uaddr(std::uint64_t a) noexcept { return UAddr{a}; }
[[nodiscard]] constexpr std::uint64_t value(UAddr a) noexcept {
    return static_cast<std::uint64_t>(a);
}

// A typed guest pointer: carries the element type so copy_in/copy_out can be
// checked against it, but still cannot be dereferenced directly.
template <class T>
struct UserPtr {
    UAddr addr{};
    [[nodiscard]] constexpr bool null() const noexcept { return value(addr) == 0; }
};

} // namespace lx

// Make the strong ids hashable so they can key unordered_maps.
template <class Tag, class Repr>
struct std::hash<lx::Id<Tag, Repr>> {
    std::size_t operator()(lx::Id<Tag, Repr> id) const noexcept {
        return std::hash<Repr>{}(id.raw());
    }
};

// UAddr is likewise a keyable strong type.
template <>
struct std::hash<lx::UAddr> {
    std::size_t operator()(lx::UAddr a) const noexcept {
        return std::hash<std::uint64_t>{}(lx::value(a));
    }
};
