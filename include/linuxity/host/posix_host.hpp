// POSIX host backend (Linux + Darwin/iOS share this).
#pragma once
#include "linuxity/host/host.hpp"

#include <sys/mman.h>
#include <unistd.h>
#include <ctime>

namespace lx::host {

class PosixHost {
public:
    Result<void*> map(std::size_t n, Prot p) {
        int prot = 0;
        if (unsigned(p) & unsigned(Prot::read))  prot |= PROT_READ;
        if (unsigned(p) & unsigned(Prot::write)) prot |= PROT_WRITE;
        if (unsigned(p) & unsigned(Prot::exec))  prot |= PROT_EXEC;
        if (prot == 0) prot = PROT_NONE;
        void* m = ::mmap(nullptr, n, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) return err<void*>(Errno::enomem);
        return ok(m);
    }

    Status unmap(void* p, std::size_t n) {
        return ::munmap(p, n) == 0 ? ok() : err(Errno::einval);
    }

    Status protect(void* p, std::size_t n, Prot pr) {
        int prot = 0;
        if (unsigned(pr) & unsigned(Prot::read))  prot |= PROT_READ;
        if (unsigned(pr) & unsigned(Prot::write)) prot |= PROT_WRITE;
        if (unsigned(pr) & unsigned(Prot::exec))  prot |= PROT_EXEC;
        return ::mprotect(p, n, prot) == 0 ? ok() : err(Errno::eacces);
    }

    Nanos mono_now() {
        std::timespec ts{};
        ::clock_gettime(CLOCK_MONOTONIC, &ts);
        return Nanos{static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ull
                     + static_cast<std::uint64_t>(ts.tv_nsec)};
    }

    Status sleep_until(Nanos t) {
        std::timespec ts{ .tv_sec = static_cast<time_t>(t.v / 1'000'000'000ull),
                          .tv_nsec = static_cast<long>(t.v % 1'000'000'000ull) };
        ::clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, nullptr);
        return ok();
    }

    Result<std::size_t> read(int fd, std::span<std::byte> b) {
        auto n = ::read(fd, b.data(), b.size());
        if (n < 0) return err<std::size_t>(Errno::eio);
        return ok(static_cast<std::size_t>(n));
    }

    Result<std::size_t> write(int fd, std::span<const std::byte> b) {
        auto n = ::write(fd, b.data(), b.size());
        if (n < 0) return err<std::size_t>(Errno::eio);
        return ok(static_cast<std::size_t>(n));
    }

    Status close(int fd) {
        return ::close(fd) == 0 ? ok() : err(Errno::ebadf);
    }
};

static_assert(Host<PosixHost>, "PosixHost must satisfy the Host concept");

} // namespace lx::host
