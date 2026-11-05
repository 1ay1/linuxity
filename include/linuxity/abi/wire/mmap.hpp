// linuxity/abi/wire/mmap.hpp
//
// The guest's mmap(2) protection and flag bits, defined once.
//
// WHY THIS FILE EXISTS. These were spread across three places:
//
//   runtime/windows/mm.hpp     kMapShared/Private/Fixed/Anonymous/...
//   runtime/windows/win32.hpp  kProtRead/Write/Exec
//   runtime/darwin/trap.hpp    `constexpr kFixed = 0x10, kAnon = 0x20;`
//                              declared INLINE inside a function body
//
// The darwin one is the tell: when a constant is cheap to redeclare, it gets
// redeclared at the point of use, and then there is no single place to fix.
// All four copies agreed here -- values checked against this host's real
// <sys/mman.h> -- but MAP_* is exactly where a near-miss hides, because the
// bits are sparse and similar (0x2000 MAP_LOCKED vs 0x4000 MAP_NORESERVE vs
// 0x8000 MAP_POPULATE). Mistaking one for another silently changes mapping
// semantics instead of failing.
//
// These are ABI: the numbers the guest's libc puts in a register. They are
// NOT the host's PROT_*/MAP_* values -- Linux and Darwin happen to agree on
// PROT_* but diverge on MAP_* (MAP_ANON is 0x1000 on Darwin, 0x20 on Linux),
// and Win32 has no such bits at all. Translating to the host is the backend's
// job; only the guest-side definition lives here.
#pragma once

#include <cstdint>

namespace lx::abi::wire {

// -- PROT_* ----------------------------------------------------------------
// Arch-independent on every Linux ABI we target.
enum class Prot : std::uint64_t {
    none  = 0,
    read  = 1,
    write = 2,
    exec  = 4,
};

[[nodiscard]] constexpr std::uint64_t bits(Prot p) noexcept {
    return static_cast<std::uint64_t>(p);
}

[[nodiscard]] constexpr bool has_prot(std::uint64_t prot, Prot p) noexcept {
    return (prot & bits(p)) != 0;
}

// -- MAP_* -----------------------------------------------------------------
// x86-64 / asm-generic values (they agree on all of these).
enum class MapFlag : std::uint64_t {
    shared          = 0x01,
    priv            = 0x02,      // MAP_PRIVATE ("private" is a keyword)
    fixed           = 0x10,
    anonymous       = 0x20,
    growsdown       = 0x100,
    denywrite       = 0x800,
    locked          = 0x2000,
    noreserve       = 0x4000,
    populate        = 0x8000,
    stack           = 0x20000,
    fixed_noreplace = 0x100000,
};

[[nodiscard]] constexpr std::uint64_t bits(MapFlag f) noexcept {
    return static_cast<std::uint64_t>(f);
}

[[nodiscard]] constexpr bool has_map(std::uint64_t flags, MapFlag f) noexcept {
    return (flags & bits(f)) != 0;
}

// An anonymous mapping ignores the fd argument entirely. A backend that
// forgets this tries to map fd -1 and fails a perfectly valid allocation.
[[nodiscard]] constexpr bool is_anonymous(std::uint64_t flags) noexcept {
    return has_map(flags, MapFlag::anonymous);
}

// MAP_FIXED and MAP_FIXED_NOREPLACE both pin the address, but differ on
// collision: FIXED silently replaces an existing mapping, FIXED_NOREPLACE
// returns EEXIST. Treating the second as the first is a silent data-loss bug,
// so they are separate questions.
[[nodiscard]] constexpr bool wants_fixed(std::uint64_t flags) noexcept {
    return has_map(flags, MapFlag::fixed) ||
           has_map(flags, MapFlag::fixed_noreplace);
}

[[nodiscard]] constexpr bool fixed_must_not_replace(std::uint64_t flags) noexcept {
    return has_map(flags, MapFlag::fixed_noreplace) &&
           !has_map(flags, MapFlag::fixed);
}

// -- pinned against the kernel's own numbers -------------------------------
// Verified against this host's <sys/mman.h> before being written down.
static_assert(bits(Prot::read) == 1 && bits(Prot::write) == 2 &&
              bits(Prot::exec) == 4 && bits(Prot::none) == 0);
static_assert(bits(MapFlag::shared) == 0x01);
static_assert(bits(MapFlag::priv) == 0x02);
static_assert(bits(MapFlag::fixed) == 0x10);
static_assert(bits(MapFlag::anonymous) == 0x20);
static_assert(bits(MapFlag::growsdown) == 0x100);
static_assert(bits(MapFlag::denywrite) == 0x800);
static_assert(bits(MapFlag::locked) == 0x2000);
static_assert(bits(MapFlag::noreserve) == 0x4000);
static_assert(bits(MapFlag::populate) == 0x8000);
static_assert(bits(MapFlag::stack) == 0x20000);
static_assert(bits(MapFlag::fixed_noreplace) == 0x100000);

// The sparse neighbours must stay distinct -- this is the near-miss family.
static_assert(bits(MapFlag::locked) != bits(MapFlag::noreserve));
static_assert(bits(MapFlag::noreserve) != bits(MapFlag::populate));
static_assert(bits(MapFlag::fixed) != bits(MapFlag::fixed_noreplace));

// MAP_SHARED and MAP_PRIVATE are the low two bits and mutually exclusive.
static_assert((bits(MapFlag::shared) | bits(MapFlag::priv)) == 0x03);

static_assert(is_anonymous(bits(MapFlag::anonymous) | bits(MapFlag::priv)));
static_assert(!is_anonymous(bits(MapFlag::priv)));
static_assert(wants_fixed(bits(MapFlag::fixed)));
static_assert(wants_fixed(bits(MapFlag::fixed_noreplace)));
static_assert(!wants_fixed(bits(MapFlag::priv)));
static_assert(fixed_must_not_replace(bits(MapFlag::fixed_noreplace)));
static_assert(!fixed_must_not_replace(bits(MapFlag::fixed)));

} // namespace lx::abi::wire
