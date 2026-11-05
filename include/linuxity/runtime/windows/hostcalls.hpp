// linuxity/runtime/windows/hostcalls.hpp
//
// The Win32 implementation of runtime::HostCalls.
//
// This is the ENTIRE legitimate content of what used to be a second syscall
// dispatcher. Measured against `windows/sys.hpp` (775 lines):
//
//   13 lines  genuine Win32 I/O         -> this file
//   50 lines  hardcoded policy answers  -> already in abi/syscall.hpp, correctly
//   ~700      path / fd / dirent logic  -> already in kernel/ + abi/
//
// The duplication was not neutral. `windows/sys.hpp` answers getpid, gettid
// and getppid with a hardcoded 1, so every process on Windows sees pid 1,
// while the portable dispatcher has returned real per-task guest pids all
// along. Routing Windows through `abi::Syscalls` with this file supplying the
// host primitives deletes that whole class of bug, because there is only one
// implementation left to be right.
//
// Nothing here resolves a path, consults an fd table, encodes a dirent or
// decides a credential. If a function in this file is doing any of that, it
// belongs in `abi/` or `kernel/` instead.
#pragma once

#if defined(_WIN32)

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"
#include "linuxity/runtime/hostcalls.hpp"
#include "linuxity/runtime/windows/api.hpp"
#include "linuxity/runtime/windows/fd.hpp"
#include "linuxity/runtime/windows/win32.hpp"

#include <cstdint>
#include <span>

namespace lx::runtime {

// Win32 host facilities, over the backend's own fd table.
//
// The fd table stays in the backend because mapping a guest fd number to a
// HANDLE is irreducibly Win32; what the guest fd MEANS (its path binding, its
// virtual-dir entries) is the dispatcher's business and lives in kernel/.
class WhpHostCalls {
public:
    explicit WhpHostCalls(FdTable& fds) noexcept : fds_{fds} {}

    // -- descriptor I/O ----------------------------------------------------
    [[nodiscard]] Result<std::size_t> read_fd(Fd fd, std::span<std::byte> out) {
        auto h = fds_.host(fd.raw());
        if (!h) return err<std::size_t>(Errno::ebadf);
        DWORD got = 0;
        if (!::ReadFile(*h, out.data(), static_cast<DWORD>(out.size()),
                        &got, nullptr)) {
            // A read at end-of-pipe reports ERROR_BROKEN_PIPE; POSIX calls
            // that EOF (0 bytes), not an error, and a guest's libc loops
            // forever if it sees EPIPE from read().
            const DWORD e = ::GetLastError();
            if (e == ERROR_BROKEN_PIPE || e == ERROR_HANDLE_EOF) return ok(std::size_t{0});
            return err<std::size_t>(win32::error_to_errno(e));
        }
        return ok(static_cast<std::size_t>(got));
    }

    [[nodiscard]] Result<std::size_t> write_fd(Fd fd,
                                               std::span<const std::byte> in) {
        auto h = fds_.host(fd.raw());
        if (!h) return err<std::size_t>(Errno::ebadf);
        DWORD put = 0;
        if (!::WriteFile(*h, in.data(), static_cast<DWORD>(in.size()),
                         &put, nullptr))
            return err<std::size_t>(win32::error_to_errno(::GetLastError()));
        return ok(static_cast<std::size_t>(put));
    }

    // pread(2): must NOT disturb the descriptor's own file position. Win32 has
    // no positional read for a synchronous handle, so save the pointer, seek,
    // read, and restore it -- and restore it even when the read fails, or the
    // guest's next sequential read lands at the wrong offset.
    [[nodiscard]] Result<std::size_t> pread_fd(Fd fd, std::span<std::byte> out,
                                                std::uint64_t off) {
        auto h = fds_.host(fd.raw());
        if (!h) return err<std::size_t>(Errno::ebadf);
        LARGE_INTEGER zero{}, saved{};
        if (!::SetFilePointerEx(*h, zero, &saved, FILE_CURRENT))
            return err<std::size_t>(win32::error_to_errno(::GetLastError()));
        LARGE_INTEGER to{};
        to.QuadPart = static_cast<LONGLONG>(off);
        if (!::SetFilePointerEx(*h, to, nullptr, FILE_BEGIN))
            return err<std::size_t>(win32::error_to_errno(::GetLastError()));
        DWORD got = 0;
        const BOOL okread = ::ReadFile(*h, out.data(),
                                       static_cast<DWORD>(out.size()),
                                       &got, nullptr);
        const DWORD e = okread ? ERROR_SUCCESS : ::GetLastError();
        ::SetFilePointerEx(*h, saved, nullptr, FILE_BEGIN);   // always restore
        if (!okread) {
            if (e == ERROR_HANDLE_EOF) return ok(std::size_t{0});
            return err<std::size_t>(win32::error_to_errno(e));
        }
        return ok(static_cast<std::size_t>(got));
    }

    [[nodiscard]] Status close_fd(Fd fd) {
        return fds_.close(fd.raw()) == 0 ? ok() : err(Errno::ebadf);
    }

    // -- time --------------------------------------------------------------
    [[nodiscard]] Result<Timespec> clock_now(ClockId id) {
        switch (id) {
            case ClockId::monotonic:
            case ClockId::monotonic_raw:
            case ClockId::monotonic_coarse:
            case ClockId::boottime:
                return ok(from_qpc());
            default:
                return ok(from_filetime());
        }
    }

    [[nodiscard]] Result<Timespec> clock_res(ClockId id) {
        switch (id) {
            case ClockId::monotonic:
            case ClockId::monotonic_raw:
            case ClockId::boottime: {
                // QPC's period, as nanoseconds.
                LARGE_INTEGER f{};
                if (!::QueryPerformanceFrequency(&f) || f.QuadPart == 0)
                    return ok(Timespec{0, 100});
                return ok(Timespec{0, abi::wire::kNsecPerSec / f.QuadPart});
            }
            default:
                // GetSystemTimeAsFileTime ticks in 100ns units.
                return ok(Timespec{0, 100});
        }
    }

    [[nodiscard]] Status sleep_for(Timespec d) {
        // Sleep() takes whole milliseconds, and the rounding direction is in
        // the shared helper: a sub-millisecond request rounds UP, because
        // Sleep(0) is a spin that pegs a core rather than a yield.
        ::Sleep(static_cast<DWORD>(abi::wire::to_millis_ceil(d)));
        return ok();
    }

    // -- entropy -----------------------------------------------------------
    [[nodiscard]] Result<std::size_t> random_bytes(std::span<std::byte> out) {
        // RtlGenRandom, via the existing helper in windows/api.hpp -- the
        // CSPRNG available without a CryptoAPI handle. A guest's ld.so, ASLR
        // and stack canaries all depend on this being real entropy.
        if (!whp_random_bytes(out.data(), static_cast<unsigned>(out.size())))
            return err<std::size_t>(Errno::eio);
        return ok(out.size());
    }

private:
    // Wall clock. Uses win32::from_filetime -- the conversion that was ALREADY
    // here. I first wrote a second one against my own Timespec, with different
    // pre-epoch clamping; that is exactly the drift a shared struct prevents.
    [[nodiscard]] static Timespec from_filetime() noexcept {
        FILETIME ft{};
        ::GetSystemTimeAsFileTime(&ft);
        return win32::from_filetime(ft);
    }

    // Monotonic: QPC, which is what Windows guarantees never goes backwards.
    [[nodiscard]] static Timespec from_qpc() noexcept {
        LARGE_INTEGER c{}, f{};
        if (!::QueryPerformanceCounter(&c) ||
            !::QueryPerformanceFrequency(&f) || f.QuadPart == 0)
            return Timespec{0, 0};
        const std::int64_t sec = c.QuadPart / f.QuadPart;
        const std::int64_t rem = c.QuadPart % f.QuadPart;
        return Timespec{sec, (rem * abi::wire::kNsecPerSec) / f.QuadPart};
    }

    FdTable& fds_;
};

// Checked where it is implemented, so a signature drift is a build error here
// rather than a mystery at a call site in the dispatcher.
static_assert(HostCalls<WhpHostCalls>,
              "WhpHostCalls must model the host-facility contract");

} // namespace lx::runtime

#endif // _WIN32
