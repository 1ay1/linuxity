// The host-facility seam (runtime/hostcalls.hpp) and the one errno table.
//
// These are the pieces that let ONE dispatcher serve three hosts, so the
// contract is checked here rather than discovered at a call site.
#include "linuxity/abi/wire/errno_map.hpp"
#include "linuxity/runtime/posix_hostcalls.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

using namespace lx;
using namespace lx::runtime;

// -- the seam is a real contract, checked where it's implemented ----------
static_assert(HostCalls<PosixHostCalls>,
              "the POSIX host must model the facility contract");

// A type missing one member must NOT satisfy it -- otherwise the concept is
// decoration rather than a check.
struct Incomplete {
    Result<std::size_t> read_fd(Fd, std::span<std::byte>);
    Result<std::size_t> write_fd(Fd, std::span<const std::byte>);
    // close_fd, pread_fd, clocks and entropy deliberately absent
};
static_assert(!HostCalls<Incomplete>,
              "a partial host must fail the contract, not slip through");

static int failures = 0;
static void check(bool cond, const char* what) {
    if (!cond) { std::fprintf(stderr, "FAIL: %s\n", what); ++failures; }
}

int main() {
    // -- the errno table is the regression that matters -------------------
    // PosixHost::read/write used to return EIO for EVERY failure, and
    // from_errno mapped six values. A guest then saw "I/O error" for a full
    // disk, a closed pipe, or a would-block on a non-blocking fd -- exactly
    // the errors programs branch on. Each of these must survive the trip.
    using abi::wire::errno_from_host;
    check(errno_from_host(ENOSPC) == Errno::enospc, "ENOSPC is not EIO");
    check(errno_from_host(EPIPE)  == Errno::epipe,  "EPIPE is not EIO");
    check(errno_from_host(EAGAIN) == Errno::eagain, "EAGAIN is not EIO");
    check(errno_from_host(EBADF)  == Errno::ebadf,  "EBADF is not EIO");
    check(errno_from_host(EINTR)  == Errno::eintr,  "EINTR is not EIO");
    check(errno_from_host(EEXIST) == Errno::eexist, "EEXIST is not EIO");
    check(errno_from_host(EROFS)  == Errno::erofs,  "EROFS is not EIO");
    check(errno_from_host(ERANGE) == Errno::erange, "ERANGE is not EIO");
    check(errno_from_host(ELOOP)  == Errno::eloop,  "ELOOP is not EIO");
    check(errno_from_host(ENOTEMPTY) == Errno::enotempty, "ENOTEMPTY kept");
    check(errno_from_host(ENAMETOOLONG) == Errno::enametoolong,
          "ENAMETOOLONG kept");
    // The ones the old six-entry table did cover must still work.
    check(errno_from_host(ENOENT) == Errno::enoent, "ENOENT kept");
    check(errno_from_host(EACCES) == Errno::eacces, "EACCES kept");
    // 0 is success, and EIO maps to itself.
    check(errno_from_host(0)     == Errno::ok,  "errno 0 is ok");
    check(errno_from_host(EIO)   == Errno::eio, "EIO maps to EIO");

    // The guest's errno numbers are ABI: these are the values that land in
    // the return register, so pin a few against the kernel's own numbering.
    check(static_cast<int>(Errno::enoent) == 2,  "ENOENT is 2");
    check(static_cast<int>(Errno::eagain) == 11, "EAGAIN is 11");
    check(static_cast<int>(Errno::enospc) == 28, "ENOSPC is 28");

    PosixHostCalls h;

    // -- clocks -----------------------------------------------------------
    {
        auto mono1 = h.clock_now(ClockId::monotonic);
        check(mono1.has_value(), "CLOCK_MONOTONIC readable");
        auto real = h.clock_now(ClockId::realtime);
        check(real.has_value(), "CLOCK_REALTIME readable");
        // Wall clock is well past 2020, so the epoch conversion is sane.
        check(real && real->sec > 1'600'000'000, "realtime looks like an epoch");
        check(real && real->nsec >= 0 && real->nsec < 1'000'000'000,
              "nsec is normalized");

        auto mono2 = h.clock_now(ClockId::monotonic);
        check(mono1 && mono2 &&
              (mono2->sec > mono1->sec ||
               (mono2->sec == mono1->sec && mono2->nsec >= mono1->nsec)),
              "monotonic never goes backwards");

        check(h.clock_res(ClockId::monotonic).has_value(), "resolution readable");
    }

    // -- sleep ------------------------------------------------------------
    {
        auto before = h.clock_now(ClockId::monotonic);
        check(h.sleep_for(Timespec{0, 2'000'000}).has_value(), "2ms sleep ok");
        auto after = h.clock_now(ClockId::monotonic);
        check(before && after, "clock readable around the sleep");
        if (before && after) {
            const std::int64_t elapsed_ns =
                (after->sec - before->sec) * 1'000'000'000 +
                (after->nsec - before->nsec);
            check(elapsed_ns >= 1'000'000, "slept at least ~1ms");
        }
    }

    // -- entropy ----------------------------------------------------------
    {
        std::byte a[64]{}, b[64]{};
        auto ra = h.random_bytes(a);
        auto rb = h.random_bytes(b);
        check(ra && *ra == 64, "filled the whole buffer");
        check(rb && *rb == 64, "filled it again");
        bool differ = false;
        for (int i = 0; i < 64; ++i) if (a[i] != b[i]) differ = true;
        check(differ, "two draws differ (a real CSPRNG, not a stub)");

        // > 256 bytes exercises the chunking loop (getentropy's per-call cap).
        std::byte big[1000]{};
        auto rc = h.random_bytes(big);
        check(rc && *rc == 1000, "chunked draw fills past the 256-byte cap");
        int zeros = 0;
        for (std::byte v : big) if (v == std::byte{0}) ++zeros;
        check(zeros < 100, "chunked draw is not mostly zeros");
    }

    // -- descriptor I/O ---------------------------------------------------
    {
        int fds[2]{};
        check(::pipe(fds) == 0, "made a pipe");
        const char msg[] = "linuxity";
        auto w = h.write_fd(Fd{fds[1]},
                            std::as_bytes(std::span{msg, sizeof msg - 1}));
        check(w && *w == sizeof msg - 1, "wrote the whole message");

        std::byte buf[32]{};
        auto r = h.read_fd(Fd{fds[0]}, buf);
        check(r && *r == sizeof msg - 1, "read it back");
        check(std::memcmp(buf, msg, sizeof msg - 1) == 0, "bytes round-trip");

        check(h.close_fd(Fd{fds[1]}).has_value(), "close write end");
        // Reading a pipe whose write end is closed gives EOF (0), not an error.
        auto eof = h.read_fd(Fd{fds[0]}, buf);
        check(eof && *eof == 0, "EOF is 0 bytes, not an error");
        check(h.close_fd(Fd{fds[0]}).has_value(), "close read end");
    }

    // -- a bad fd reports EBADF, not EIO ----------------------------------
    // This is the whole point of the errno table: the dispatcher needs to
    // know WHICH failure happened so it can hand the guest the right answer.
    {
        std::byte buf[8]{};
        auto r = h.read_fd(Fd{-1}, buf);
        check(!r, "reading fd -1 fails");
        check(!r && r.error() == Errno::ebadf, "and it fails with EBADF");

        auto w = h.write_fd(Fd{-1}, std::as_bytes(std::span{buf}));
        check(!w && w.error() == Errno::ebadf, "writing fd -1 gives EBADF");
    }

    // -- positioned read is independent of the file offset ----------------
    {
        char path[] = "/tmp/lx-hostcalls-XXXXXX";
        const int fd = ::mkstemp(path);
        check(fd >= 0, "made a temp file");
        const char body[] = "0123456789";
        check(h.write_fd(Fd{fd}, std::as_bytes(std::span{body, 10})).has_value(),
              "wrote the body");

        std::byte buf[4]{};
        auto p = h.pread_fd(Fd{fd}, buf, 4);
        check(p && *p == 4, "pread returned 4 bytes");
        check(std::memcmp(buf, "4567", 4) == 0, "pread honoured the offset");
        // pread must not disturb the descriptor's own offset.
        auto p2 = h.pread_fd(Fd{fd}, buf, 0);
        check(p2 && std::memcmp(buf, "0123", 4) == 0, "pread is stateless");

        (void)h.close_fd(Fd{fd});
        ::unlink(path);
    }

    // -- the Win32 time conversions, checked on ANY host -------------------
    // WhpHostCalls can't be compiled here (no Win32 headers), but its
    // arithmetic is pure and is the part most likely to be wrong, so the same
    // formulas are checked directly. Keep these in sync with
    // runtime/windows/hostcalls.hpp.
    {
        auto from_filetime = [](std::uint64_t ticks) {
            constexpr std::uint64_t kEpochDelta = 116'444'736'000'000'000ULL;
            const std::uint64_t t = ticks > kEpochDelta ? ticks - kEpochDelta : 0;
            return Timespec{std::int64_t(t / 10'000'000),
                            std::int64_t((t % 10'000'000) * 100)};
        };
        auto from_qpc = [](std::int64_t c, std::int64_t f) {
            return Timespec{c / f, ((c % f) * 1'000'000'000) / f};
        };
        auto sleep_ms = [](Timespec d) {
            return d.sec * 1000 + (d.nsec + 999'999) / 1'000'000;
        };

        // FILETIME is 100ns ticks since 1601-01-01; the guest wants the Unix
        // epoch. 2024-01-01T00:00:00Z is FILETIME 133485408000000000.
        const auto t2024 = from_filetime(133'485'408'000'000'000ULL);
        check(t2024.sec == 1'704'067'200, "FILETIME -> Unix epoch seconds");
        check(t2024.nsec == 0, "FILETIME -> nsec");
        // A pre-1970 FILETIME must clamp, not go negative.
        check(from_filetime(1000).sec == 0, "pre-epoch FILETIME clamps to 0");

        // QPC: a 10MHz counter at 3.5s.
        const auto q = from_qpc(35'000'000, 10'000'000);
        check(q.sec == 3 && q.nsec == 500'000'000, "QPC -> 3.5s");
        // nsec must stay normalized even just under a full second.
        const auto q2 = from_qpc(9'999'999, 10'000'000);
        check(q2.sec == 0 && q2.nsec < 1'000'000'000, "QPC nsec normalized");

        // Sleep() takes whole ms. A sub-millisecond request must round UP:
        // rounding 100us down to 0 turns a guest's yield into a busy-spin.
        check(sleep_ms(Timespec{0, 100'000}) == 1, "100us rounds up to 1ms");
        check(sleep_ms(Timespec{0, 1}) == 1, "1ns rounds up to 1ms");
        check(sleep_ms(Timespec{0, 0}) == 0, "a zero sleep stays 0");
        check(sleep_ms(Timespec{2, 500'000'000}) == 2500, "2.5s -> 2500ms");
    }

    if (failures == 0) std::puts("hostcalls: all checks passed");
    return failures == 0 ? 0 : 1;
}
