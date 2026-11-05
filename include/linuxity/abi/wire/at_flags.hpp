// linuxity/abi/wire/at_flags.hpp
//
// The guest's `*at()` syscall flags and the AT_FDCWD sentinel, defined once.
//
// WHY THIS FILE EXISTS. These were redeclared inline at each point of use:
//
//   abi/syscall.hpp:733   constexpr kAtEmptyPath = 0x1000;
//   abi/syscall.hpp:872   constexpr kAtEmptyPath = 0x1000;   (again)
//   darwin/trap.hpp:4129  constexpr kNoFollow = 0x100;
//   darwin/trap.hpp:4141  constexpr kNoFollow = 0x100, kEmptyPath = 0x1000;
//   darwin/trap.hpp:4213  constexpr kRemoveDir = 0x200;
//
// Five declarations of four constants, two of them in the same file. This is
// the pattern that produced every ABI bug in this tree: a value cheap enough
// to retype gets retyped, and then nothing connects the copies.
//
// THE TRAP IN THIS FAMILY: AT_REMOVEDIR and AT_EACCESS are BOTH 0x200. They
// are disjoint in practice because no syscall accepts both (unlinkat takes
// REMOVEDIR, faccessat takes EACCESS), but a backend that tests the bit
// without knowing which syscall it is in will read "remove a directory" from
// an access check. Naming them separately here, with that collision asserted,
// is the only thing standing between those two meanings.
//
// Values verified against this host's <fcntl.h>.
#pragma once

#include <cstdint>

namespace lx::abi::wire {

// AT_FDCWD: "resolve relative to the current directory". NEGATIVE, and that
// matters -- it is a sentinel fd, not a flag, so it is compared with == and
// must stay signed. Storing it in an unsigned dirfd silently turns it into a
// huge positive number that no fd table will match.
inline constexpr std::int32_t kAtFdCwd = -100;

enum class AtFlag : std::uint64_t {
    // Do not follow a final symlink. lstat semantics for fstatat/fchownat.
    symlink_nofollow = 0x100,
    // unlinkat: remove a directory instead of a file (i.e. rmdir).
    removedir        = 0x200,
    // faccessat: check with effective rather than real ids. SAME BIT as
    // removedir -- see the note at the top of this file.
    eaccess          = 0x200,
    // linkat: DO follow the final symlink (the inverse default of link).
    symlink_follow   = 0x400,
    no_automount     = 0x800,
    // An empty pathname means "operate on dirfd itself". This is how
    // fstatat(fd, "", AT_EMPTY_PATH) becomes fstat(fd), and how a guest
    // stats an O_PATH descriptor.
    empty_path       = 0x1000,
};

[[nodiscard]] constexpr std::uint64_t bits(AtFlag f) noexcept {
    return static_cast<std::uint64_t>(f);
}

[[nodiscard]] constexpr bool has_at(std::uint64_t flags, AtFlag f) noexcept {
    return (flags & bits(f)) != 0;
}

[[nodiscard]] constexpr bool is_cwd_fd(std::int64_t dirfd) noexcept {
    return dirfd == kAtFdCwd;
}

// -- pinned against the kernel's own numbers -------------------------------
static_assert(kAtFdCwd == -100, "AT_FDCWD is -100");
static_assert(kAtFdCwd < 0, "AT_FDCWD must stay negative to work as a sentinel");
static_assert(bits(AtFlag::symlink_nofollow) == 0x100);
static_assert(bits(AtFlag::removedir)        == 0x200);
static_assert(bits(AtFlag::eaccess)          == 0x200);
static_assert(bits(AtFlag::symlink_follow)   == 0x400);
static_assert(bits(AtFlag::no_automount)     == 0x800);
static_assert(bits(AtFlag::empty_path)       == 0x1000);

// The collision is real and deliberate. Asserting it means a reader who
// expects these to differ finds out here rather than from a wrong answer.
static_assert(bits(AtFlag::removedir) == bits(AtFlag::eaccess),
              "AT_REMOVEDIR and AT_EACCESS share 0x200; which one a bit means "
              "depends on the syscall, so never test it syscall-agnostically");

// nofollow and follow are opposite requests and must not be the same bit.
static_assert(bits(AtFlag::symlink_nofollow) != bits(AtFlag::symlink_follow));

static_assert(has_at(bits(AtFlag::empty_path), AtFlag::empty_path));
static_assert(!has_at(bits(AtFlag::removedir), AtFlag::empty_path));
static_assert(is_cwd_fd(kAtFdCwd));
static_assert(!is_cwd_fd(0));
static_assert(!is_cwd_fd(3));

} // namespace lx::abi::wire
