// linuxity/abi/wire/fd_flags.hpp
//
// The guest's descriptor-creation flags, named once and named PRECISELY.
//
// WHY THIS FILE EXISTS. `kCloexec` was declared FIVE times in
// runtime/darwin/trap.hpp, with two different values:
//
//   :3106  kCloexec = 02000000   (pipe2 -- O_CLOEXEC)
//   :3159  kCloexec = 1          (memfd_create -- MFD_CLOEXEC)
//   :3281  kCloexec = 02000000   (socket -- actually SOCK_CLOEXEC)
//   :3504  kCloexec = 0x80000    (epoll_create1 -- EPOLL_CLOEXEC)
//   :4125  kCloexec = 02000000   (open)
//
// Verified against this host's headers:
//
//   O_CLOEXEC = EPOLL_CLOEXEC = SOCK_CLOEXEC = EFD_CLOEXEC = TFD_CLOEXEC
//     = 02000000 = 0x80000
//   MFD_CLOEXEC = FD_CLOEXEC = 1
//
// So four of those five were the same number written two ways, and the fifth
// was a DIFFERENT constant wearing the same name. That is the worst possible
// arrangement: a reader who sees `kCloexec` in one function and reuses the
// habit in another picks up 0x80000 where the syscall wants 1, and
// memfd_create silently stops setting close-on-exec. The leaked fd then
// survives into every exec'd child.
//
// The fix is not just "share the constant" -- it is to stop calling two
// different things by one name. Hence the explicit split below.
#pragma once

#include <cstdint>

namespace lx::abi::wire {

// -- the 0x80000 family ----------------------------------------------------
// O_CLOEXEC, and the *_CLOEXEC flags that deliberately reuse its bit so
// open-like calls can share a flag word: epoll_create1, socket, eventfd,
// timerfd, signalfd, inotify_init1, pipe2.
inline constexpr std::uint64_t kOCloexec   = 02000000;   // == 0x80000
inline constexpr std::uint64_t kONonblock  = 04000;      // == 0x800

// Named aliases, so a call site says which syscall's flag it means. They are
// the same bit on purpose; spelling them out is what stops the next reader
// guessing.
inline constexpr std::uint64_t kEpollCloexec = kOCloexec;
inline constexpr std::uint64_t kSockCloexec  = kOCloexec;
inline constexpr std::uint64_t kEfdCloexec   = kOCloexec;
inline constexpr std::uint64_t kTfdCloexec   = kOCloexec;
inline constexpr std::uint64_t kSockNonblock = kONonblock;
inline constexpr std::uint64_t kEfdNonblock  = kONonblock;
inline constexpr std::uint64_t kTfdNonblock  = kONonblock;

// -- the "1" family --------------------------------------------------------
// These are NOT the bit above. memfd_create takes its own tiny flag space,
// and fcntl's FD_CLOEXEC is a descriptor attribute rather than a creation
// flag. Using 0x80000 for either is a silent no-op.
inline constexpr std::uint64_t kMfdCloexec = 1;
inline constexpr std::uint64_t kFdCloexec  = 1;

// -- the collision, asserted -----------------------------------------------
// Four names, one bit -- by design.
static_assert(kOCloexec == 0x80000);
static_assert(kEpollCloexec == kOCloexec);
static_assert(kSockCloexec == kOCloexec);
static_assert(kEfdCloexec == kOCloexec);
static_assert(kTfdCloexec == kOCloexec);
static_assert(kONonblock == 0x800);
static_assert(kSockNonblock == kONonblock);

// ...and the two that are emphatically NOT that bit. This is the assertion
// that would have caught the bug: if someone "unifies" MFD_CLOEXEC onto
// O_CLOEXEC because the names match, the build stops here.
static_assert(kMfdCloexec == 1);
static_assert(kFdCloexec == 1);
static_assert(kMfdCloexec != kOCloexec,
              "MFD_CLOEXEC is 1, not O_CLOEXEC's 0x80000 -- using the wrong "
              "one makes memfd_create silently NOT set close-on-exec, and the "
              "leaked fd survives every subsequent exec");
static_assert(kFdCloexec != kOCloexec,
              "FD_CLOEXEC (fcntl) is 1, not O_CLOEXEC's 0x80000");

// Octal vs hex is the other way this family hides: 02000000 and 0x80000 are
// the same number, so a copy written in the other base looks unrelated.
static_assert(02000000 == 0x80000);
static_assert(04000 == 0x800);

} // namespace lx::abi::wire
