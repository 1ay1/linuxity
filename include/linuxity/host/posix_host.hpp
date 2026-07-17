// POSIX host backend (Linux + Darwin/iOS share this).
#pragma once
#include "linuxity/host/host.hpp"

#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <ctime>
#include <string_view>

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

    // -- HostFiles capability: path-based access for HostFs -----------------
    Result<int> open_path(const char* path) {
        int fd = ::open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return err<int>(from_errno(errno));
        return ok(fd);
    }

    Result<HStat> stat_path(const char* path) {
        struct ::stat st{};
        if (::lstat(path, &st) != 0) return err<HStat>(from_errno(errno));
        HStat h;
        h.size     = static_cast<std::uint64_t>(st.st_size);
        h.mode     = static_cast<std::uint32_t>(st.st_mode) & 0777u;
        h.mtime_ns = static_cast<std::uint64_t>(st.st_mtime) * 1'000'000'000ull;
        if      (S_ISDIR(st.st_mode))  h.type = HFileType::directory;
        else if (S_ISLNK(st.st_mode))  h.type = HFileType::symlink;
        else if (S_ISREG(st.st_mode))  h.type = HFileType::regular;
        else                           h.type = HFileType::other;
        return ok(h);
    }

    Result<std::size_t> pread(int fd, std::uint64_t off, std::span<std::byte> b) {
        auto n = ::pread(fd, b.data(), b.size(), static_cast<off_t>(off));
        if (n < 0) return err<std::size_t>(from_errno(errno));
        return ok(static_cast<std::size_t>(n));
    }

    Result<std::vector<HDirent>> list_dir(const char* path) {
        DIR* d = ::opendir(path);
        if (!d) return err<std::vector<HDirent>>(from_errno(errno));
        std::vector<HDirent> out;
        while (struct ::dirent* e = ::readdir(d)) {
            std::string_view name{e->d_name};
            if (name == "." || name == "..") continue;
            HDirent de;
            de.name = std::string{name};
            switch (e->d_type) {
                case DT_DIR: de.type = HFileType::directory; break;
                case DT_LNK: de.type = HFileType::symlink;   break;
                case DT_REG: de.type = HFileType::regular;   break;
                default:     de.type = HFileType::other;     break;
            }
            out.push_back(std::move(de));
        }
        ::closedir(d);
        return ok(std::move(out));
    }

private:
    static Errno from_errno(int e) noexcept {
        switch (e) {
            case ENOENT:  return Errno::enoent;
            case EACCES:  return Errno::eacces;
            case ENOTDIR: return Errno::enotdir;
            case EISDIR:  return Errno::eisdir;
            case ENFILE:  return Errno::enfile;
            case EMFILE:  return Errno::emfile;
            default:      return Errno::eio;
        }
    }
};

static_assert(Host<PosixHost>, "PosixHost must satisfy the Host concept");
static_assert(HostFiles<PosixHost>, "PosixHost must satisfy HostFiles");

} // namespace lx::host
