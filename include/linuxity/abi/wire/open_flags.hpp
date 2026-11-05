// linuxity/abi/wire/open_flags.hpp
//
// The guest's `open`/`openat` flag bits, defined once.
//
// WHY THIS FILE EXISTS. These were spelled three times:
//
//   abi/syscall.hpp    constexpr kCreat = 0100, kTrunc = 01000, kExcl = 0200
//   darwin/darwin.hpp  enum class LinuxOpen { creat = 0100, ... }   (octal)
//   windows/win32.hpp  enum class LinuxOpen { creat = 0x40, ... }   (hex)
//
// All three agreed, which is luck rather than design: 0100 and 0x40 are the
// same number, so nothing would have caught them diverging. And these bits
// decide whether a path is opened FOR WRITE, which is what selects the
// copy-on-write branch in the overlay -- getting one wrong silently writes
// into the pristine lower layer, or fails a create that should have succeeded.
//
// These are ABI: they are the numbers the guest's libc puts in a register.
// They are NOT the host's O_* values -- on Darwin O_CREAT is 0x200, on Win32
// there is no such bit at all -- so a backend must TRANSLATE. That translation
// is genuinely host-specific and stays in the backend; only the guest-side
// definition lives here.
#pragma once

#include <cstdint>

namespace lx::abi::wire {

// Linux's open(2) flags for both targeted ABIs. x86-64 and aarch64 agree on
// every one of these (they are asm-generic values, with x86-64 inheriting
// them), so unlike `struct stat` there is no per-arch variant.
enum class OpenFlag : std::uint64_t {
    rdonly    = 0,
    wronly    = 01,
    rdwr      = 02,
    creat     = 0100,        // 0x40
    excl      = 0200,        // 0x80
    noctty    = 0400,        // 0x100
    trunc     = 01000,       // 0x200
    append    = 02000,       // 0x400
    nonblock  = 04000,       // 0x800
    directio  = 040000,      // 0x4000  (O_DIRECT)
    directory = 0200000,     // 0x10000
    nofollow  = 0400000,     // 0x20000
    noatime   = 01000000,    // 0x40000
    cloexec   = 02000000,    // 0x80000
    path      = 010000000,   // 0x200000
    tmpfile   = 020200000,   // 0x410000 (O_TMPFILE includes O_DIRECTORY)
};

[[nodiscard]] constexpr std::uint64_t bits(OpenFlag f) noexcept {
    return static_cast<std::uint64_t>(f);
}

[[nodiscard]] constexpr bool has(std::uint64_t flags, OpenFlag f) noexcept {
    return (flags & bits(f)) != 0;
}

// The low two bits are an access MODE, not a bitmask: O_RDONLY is 0, so
// `flags & O_RDONLY` is always false and testing it that way is a classic
// bug. Extract it instead.
inline constexpr std::uint64_t kAccessMask = 03;

[[nodiscard]] constexpr bool writable(std::uint64_t flags) noexcept {
    const std::uint64_t acc = flags & kAccessMask;
    return acc == bits(OpenFlag::wronly) || acc == bits(OpenFlag::rdwr) ||
           has(flags, OpenFlag::creat) || has(flags, OpenFlag::trunc);
}

// O_TMPFILE is defined as (0200000 | 020000000), i.e. it has O_DIRECTORY set.
// A backend checking "is this a directory open" must therefore exclude it, or
// it treats a tmpfile create as a directory open.
static_assert(bits(OpenFlag::tmpfile) & bits(OpenFlag::directory),
              "O_TMPFILE contains O_DIRECTORY; directory checks must exclude it");

// The octal/hex equivalences that made the old triplication look harmless.
static_assert(bits(OpenFlag::creat)     == 0x40);
static_assert(bits(OpenFlag::excl)      == 0x80);
static_assert(bits(OpenFlag::trunc)     == 0x200);
static_assert(bits(OpenFlag::directory) == 0x10000);
static_assert(bits(OpenFlag::cloexec)   == 0x80000);

// Access-mode handling, pinned: O_RDONLY must not be testable as a bit.
static_assert(bits(OpenFlag::rdonly) == 0);
static_assert(!writable(bits(OpenFlag::rdonly)));
static_assert(writable(bits(OpenFlag::wronly)));
static_assert(writable(bits(OpenFlag::rdwr)));
// A read-only open that CREATES or TRUNCATES still mutates the filesystem, so
// it must take the copy-up path.
static_assert(writable(bits(OpenFlag::rdonly) | bits(OpenFlag::creat)));
static_assert(writable(bits(OpenFlag::rdonly) | bits(OpenFlag::trunc)));
// ...but O_CLOEXEC or O_DIRECTORY alone do not make it writable.
static_assert(!writable(bits(OpenFlag::cloexec)));
static_assert(!writable(bits(OpenFlag::directory)));

} // namespace lx::abi::wire
