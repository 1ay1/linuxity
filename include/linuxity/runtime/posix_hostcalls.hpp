// linuxity/runtime/posix_hostcalls.hpp
//
// The POSIX implementation of runtime::HostCalls.
//
// This is the reference implementation of the host-facility seam, and it is
// deliberately thin: on a POSIX host every member is a direct syscall. It
// exists so the seam is PROVEN on the host we can actually build and test on,
// before the kernel-less backends (HVF, WHP) are migrated onto it.
//
// Note what is NOT here: no path resolution, no overlay logic, no fd table, no
// dirent encoding, no credentials. All of that is policy and lives once in
// abi/ and kernel/. This file only moves bytes, reads clocks and draws
// entropy -- the operations where two correct hosts genuinely must write
// different code.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"
#include "linuxity/abi/wire/errno_map.hpp"
#include "linuxity/abi/wire/time.hpp"
#include "linuxity/runtime/hostcalls.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <span>
#include <time.h>
#include <unistd.h>

namespace lx::runtime {

class PosixHostCalls {
public:
    // -- descriptor I/O ----------------------------------------------------
    [[nodiscard]] Result<std::size_t> read_fd(Fd fd, std::span<std::byte> out) {
        for (;;) {
            const auto n = ::read(fd.raw(), out.data(), out.size());
            if (n >= 0) return ok(static_cast<std::size_t>(n));
            // EINTR is not a guest-visible error here: the dispatcher asked
            // for bytes, a host signal interrupted us, and retrying is what
            // the guest's own libc would do. Everything else is reported with
            // its REAL errno -- the old PosixHost::read collapsed every
            // failure to EIO, which told a guest "I/O error" for ENOSPC,
            // EPIPE and EBADF alike.
            if (errno != EINTR) return err<std::size_t>(abi::wire::errno_from_host(errno));
        }
    }

    [[nodiscard]] Result<std::size_t> write_fd(Fd fd,
                                               std::span<const std::byte> in) {
        for (;;) {
            const auto n = ::write(fd.raw(), in.data(), in.size());
            if (n >= 0) return ok(static_cast<std::size_t>(n));
            if (errno != EINTR) return err<std::size_t>(abi::wire::errno_from_host(errno));
        }
    }

    [[nodiscard]] Result<std::size_t> pread_fd(Fd fd, std::span<std::byte> out,
                                                std::uint64_t off) {
        for (;;) {
            const auto n = ::pread(fd.raw(), out.data(), out.size(),
                                   static_cast<::off_t>(off));
            if (n >= 0) return ok(static_cast<std::size_t>(n));
            if (errno != EINTR) return err<std::size_t>(abi::wire::errno_from_host(errno));
        }
    }

    [[nodiscard]] Status close_fd(Fd fd) {
        // close() must not be retried on EINTR: on Linux the descriptor is
        // already gone, so a retry would close whatever reused the number.
        return ::close(fd.raw()) == 0 ? ok() : err(abi::wire::errno_from_host(errno));
    }

    // -- time --------------------------------------------------------------
    [[nodiscard]] Result<Timespec> clock_now(ClockId id) {
        ::timespec ts{};
        if (::clock_gettime(to_posix(id), &ts) != 0)
            return err<Timespec>(abi::wire::errno_from_host(errno));
        return ok(Timespec{ts.tv_sec, ts.tv_nsec});
    }

    [[nodiscard]] Result<Timespec> clock_res(ClockId id) {
        ::timespec ts{};
        if (::clock_getres(to_posix(id), &ts) != 0)
            return err<Timespec>(abi::wire::errno_from_host(errno));
        return ok(Timespec{ts.tv_sec, ts.tv_nsec});
    }

    [[nodiscard]] Status sleep_for(Timespec d) {
        ::timespec req{static_cast<::time_t>(d.sec),
                       static_cast<long>(d.nsec)};
        ::timespec rem{};
        // Resume across host signal interruptions with the remaining time, so
        // a guest nanosleep() sleeps for as long as it asked.
        while (::nanosleep(&req, &rem) != 0) {
            if (errno != EINTR) return err(abi::wire::errno_from_host(errno));
            req = rem;
        }
        return ok();
    }

    // -- entropy -----------------------------------------------------------
    [[nodiscard]] Result<std::size_t> random_bytes(std::span<std::byte> out) {
        std::size_t filled = 0;
        while (filled < out.size()) {
            // getentropy() caps at 256 bytes per call and is the portable
            // spelling available on both glibc and musl.
            const std::size_t chunk =
                std::min<std::size_t>(256, out.size() - filled);
            if (::getentropy(out.data() + filled, chunk) != 0) {
                if (errno == EINTR) continue;
                return err<std::size_t>(abi::wire::errno_from_host(errno));
            }
            filled += chunk;
        }
        return ok(filled);
    }

private:
    // The guest's clock ids are the Linux ABI numbers; map them to this
    // host's CLOCK_* constants in one place.
    [[nodiscard]] static ::clockid_t to_posix(ClockId id) noexcept {
        switch (id) {
            case ClockId::realtime:         return CLOCK_REALTIME;
            case ClockId::monotonic:        return CLOCK_MONOTONIC;
            case ClockId::process_cputime:  return CLOCK_PROCESS_CPUTIME_ID;
            case ClockId::thread_cputime:   return CLOCK_THREAD_CPUTIME_ID;
#ifdef CLOCK_MONOTONIC_RAW
            case ClockId::monotonic_raw:    return CLOCK_MONOTONIC_RAW;
#endif
#ifdef CLOCK_REALTIME_COARSE
            case ClockId::realtime_coarse:  return CLOCK_REALTIME_COARSE;
#endif
#ifdef CLOCK_MONOTONIC_COARSE
            case ClockId::monotonic_coarse: return CLOCK_MONOTONIC_COARSE;
#endif
#ifdef CLOCK_BOOTTIME
            case ClockId::boottime:         return CLOCK_BOOTTIME;
#endif
            default:                        return CLOCK_REALTIME;
        }
    }
};

// The seam is checked where it is implemented, so a signature drift is a
// build error here rather than a mystery at a call site.
static_assert(HostCalls<PosixHostCalls>,
              "PosixHostCalls must model the host-facility contract");

} // namespace lx::runtime
