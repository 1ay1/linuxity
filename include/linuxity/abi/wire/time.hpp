// linuxity/abi/wire/time.hpp
//
// The guest's time structs, defined once.
//
// WHY THIS FILE EXISTS. `struct timespec` as the guest sees it was declared
// three times, identically:
//
//   runtime/hostcalls.hpp      struct Timespec      { i64 sec; i64 nsec; }
//   runtime/darwin/timer.hpp   struct LinuxTimespec { i64 sec, nsec; }
//   runtime/windows/win32.hpp  struct LinuxTimespec { i64 sec; i64 nsec; }
//
// Three copies of a two-field struct is not dangerous by itself. What IS
// dangerous is what grows around them: Windows already had a `from_filetime`
// converting FILETIME to its LinuxTimespec, and when I wrote WhpHostCalls I
// added a SECOND one against my own Timespec -- with different clamping for
// pre-1970 timestamps. Two conversions, one struct per conversion, quietly
// disagreeing about a file older than the epoch.
//
// So the struct lives here and everyone aliases it. The HOST conversions stay
// in their backends, because FILETIME and Darwin's timespec are host types --
// but there is now exactly one conversion per host, not one per struct.
//
// These are ABI: the guest's libc reads these bytes directly, so the field
// widths are fixed by the kernel contract, not by what's convenient.
#pragma once

#include <cstdint>

namespace lx::abi::wire {

// struct timespec: the kernel's 64-bit time representation on both targeted
// ABIs. Note nsec is SIGNED in the kernel's own headers (a negative value is
// invalid, and syscalls return EINVAL for it rather than treating it as huge).
struct Timespec {
    std::int64_t sec{};
    std::int64_t nsec{};
};

// struct timeval: microsecond resolution, used by gettimeofday and the
// itimer family.
struct Timeval {
    std::int64_t sec{};
    std::int64_t usec{};
};

struct Itimerval {
    Timeval interval{};
    Timeval value{};
};

struct Itimerspec {
    Timespec interval{};
    Timespec value{};
};

inline constexpr std::int64_t kNsecPerSec  = 1'000'000'000;
inline constexpr std::int64_t kUsecPerSec  = 1'000'000;
inline constexpr std::int64_t kNsecPerUsec = 1'000;

// A timespec is VALID only with nsec in [0, 1e9). The kernel rejects anything
// else with EINVAL, so a backend that computes a timespec must normalize
// rather than hand the guest a denormal it would have refused.
[[nodiscard]] constexpr bool normalized(Timespec t) noexcept {
    return t.nsec >= 0 && t.nsec < kNsecPerSec;
}

// Carry excess nanoseconds into seconds. Used after arithmetic on a timespec,
// where adding two valid values can overflow the nsec field.
[[nodiscard]] constexpr Timespec normalize(Timespec t) noexcept {
    if (t.nsec >= kNsecPerSec) {
        t.sec += t.nsec / kNsecPerSec;
        t.nsec %= kNsecPerSec;
    } else if (t.nsec < 0) {
        const std::int64_t borrow = (-t.nsec + kNsecPerSec - 1) / kNsecPerSec;
        t.sec  -= borrow;
        t.nsec += borrow * kNsecPerSec;
    }
    return t;
}

[[nodiscard]] constexpr Timeval to_timeval(Timespec t) noexcept {
    return Timeval{t.sec, t.nsec / kNsecPerUsec};
}

[[nodiscard]] constexpr Timespec from_timeval(Timeval t) noexcept {
    return Timespec{t.sec, t.usec * kNsecPerUsec};
}

// Whole milliseconds, rounding UP, for host sleep APIs that take ms.
//
// The rounding direction matters: a guest asking for 100us expects to yield.
// Rounding down to 0 turns Win32's Sleep(0) into a spin that pegs a core, so
// any non-zero request becomes at least 1ms.
[[nodiscard]] constexpr std::int64_t to_millis_ceil(Timespec t) noexcept {
    const std::int64_t ms = t.sec * 1000 + (t.nsec + 999'999) / 1'000'000;
    return ms < 0 ? 0 : ms;
}

static_assert(normalized(Timespec{0, 0}));
static_assert(normalized(Timespec{5, 999'999'999}));
static_assert(!normalized(Timespec{0, kNsecPerSec}));
static_assert(!normalized(Timespec{0, -1}));
static_assert(normalize(Timespec{0, kNsecPerSec}).sec == 1);
static_assert(normalize(Timespec{0, kNsecPerSec}).nsec == 0);
static_assert(normalize(Timespec{1, -1}).sec == 0);
static_assert(normalize(Timespec{1, -1}).nsec == kNsecPerSec - 1);
static_assert(normalized(normalize(Timespec{3, 2'500'000'000})));
// Sub-millisecond requests round UP, never to zero.
static_assert(to_millis_ceil(Timespec{0, 1}) == 1);
static_assert(to_millis_ceil(Timespec{0, 100'000}) == 1);
static_assert(to_millis_ceil(Timespec{0, 0}) == 0);
static_assert(to_millis_ceil(Timespec{2, 500'000'000}) == 2500);
static_assert(to_timeval(Timespec{7, 1'500}).usec == 1);
static_assert(from_timeval(Timeval{7, 1}).nsec == 1000);

} // namespace lx::abi::wire
