// linuxity/runtime/darwin/memsvc.hpp
//
// Another process's memory, for a host that won't hand it out (macOS
// refuses task_for_pid without the debugger entitlement). Every guest
// process is its own linuxity with its own copy of guest RAM, so
// /proc/<pid>/mem and process_vm_readv/writev of ANOTHER guest pid have
// to ask that process.
//
// Each linuxity runs one small host thread serving its own RAM on an
// AF_UNIX socket named after its guest pid in the env's shared directory.
// It answers whether the guest is running, blocked in a host call or
// stopped: the request never waits for the guest. A request is
//
//   { u32 op (1 read, 2 write, 3 resident), u32 pad, u64 addr, u64 len } [+ len bytes for a write]
//
// and the reply { i64 result (bytes moved, or -errno) } [+ bytes for a read].
// Only guest addresses inside RAM are served; anything else is EFAULT.
// Op 3 ignores addr/len and answers the guest's resident bytes (another
// reader's /proc/<pid>/stat RSS: the host task's count includes linuxity).
#pragma once
#if defined(__APPLE__)

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <functional>
#include <span>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace lx::runtime::memsvc {

struct Request { std::uint32_t op, pad; std::uint64_t addr, len; };
inline constexpr std::uint64_t kMaxChunk = 1 << 20;

[[nodiscard]] inline bool full_io(int fd, void* p, std::size_t n, bool reading) {
    auto* b = static_cast<char*>(p);
    while (n) {
        const ssize_t r = reading ? ::read(fd, b, n) : ::write(fd, b, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        b += r; n -= static_cast<std::size_t>(r);
    }
    return true;
}

[[nodiscard]] inline std::string sock_path(const std::string& dir, std::int32_t pid) {
    return dir + "/.mem." + std::to_string(pid);
}

// Bytes of `ranges` (host spans) that are resident, by mincore. Host pages
// may be larger than the guest's (16 KiB on Apple Silicon): a resident host
// page counts only the part of it the range covers.
[[nodiscard]] inline std::uint64_t resident_bytes(const std::vector<std::span<std::byte>>& ranges) {
    const auto pg = static_cast<std::uintptr_t>(::getpagesize());
    std::uint64_t n = 0;
    std::vector<char> vec;
    for (const auto& r : ranges) {
        if (r.empty()) continue;
        const auto lo = reinterpret_cast<std::uintptr_t>(r.data());
        const auto hi = lo + r.size();
        const auto alo = lo & ~(pg - 1), ahi = (hi + pg - 1) & ~(pg - 1);
        vec.assign((ahi - alo) / pg, 0);
        if (::mincore(reinterpret_cast<caddr_t>(alo), ahi - alo, vec.data()) != 0) continue;
        for (std::size_t i = 0; i < vec.size(); ++i) {
            if (!(vec[i] & MINCORE_INCORE)) continue;
            const auto p0 = alo + i * pg;
            n += std::min(hi, p0 + pg) - std::max(lo, p0);
        }
    }
    return n;
}

using RamFn = std::function<std::span<std::byte>(std::uint64_t, std::uint64_t)>;
using ResidentFn = std::function<std::uint64_t()>;
// op 4: a /proc/<pid>/<leaf> this process alone can answer (maps, smaps,
// environ, auxv: its own address space); nullopt = not known.
using FactFn = std::function<std::optional<std::string>(std::string_view leaf)>;
inline constexpr std::size_t kMaxFact = 64u << 20;

// The server: binds `path`, serves `ram` (guest address -> host span, empty
// if unmapped) until the process exits. Detached; never returns an error to
// the guest (a client that can't connect sees ESRCH).
inline void serve(std::string path, RamFn ram, ResidentFn resident = {}, FactFn fact = {}) {
    ::unlink(path.c_str());
    const int s = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return;
    ::sockaddr_un a{};
    a.sun_family = AF_UNIX;
    if (path.size() >= sizeof a.sun_path) { ::close(s); return; }
    std::memcpy(a.sun_path, path.c_str(), path.size() + 1);
    if (::bind(s, reinterpret_cast<::sockaddr*>(&a), sizeof a) < 0 || ::listen(s, 8) < 0) { ::close(s); return; }
    std::thread([s, ram = std::move(ram), resident = std::move(resident), fact = std::move(fact)] {
        for (;;) {
            const int c = ::accept(s, nullptr, nullptr);
            if (c < 0) { if (errno == EINTR) continue; return; }
            Request q{};
            if (!full_io(c, &q, sizeof q, true)) { ::close(c); continue; }
            if (q.op == 3) {
                std::int64_t rc = resident ? static_cast<std::int64_t>(resident()) : -ENOSYS;
                (void)full_io(c, &rc, sizeof rc, false);
            } else if (q.op == 4) {
                std::string leaf(std::min<std::uint64_t>(q.len, 64), '\0');
                if (!full_io(c, leaf.data(), leaf.size(), true)) { ::close(c); continue; }
                const auto f = fact ? fact(leaf) : std::nullopt;
                std::int64_t rc = f ? static_cast<std::int64_t>(std::min(f->size(), kMaxFact)) : -ENOENT;
                (void)full_io(c, &rc, sizeof rc, false);
                if (rc > 0) (void)full_io(c, const_cast<char*>(f->data()), static_cast<std::size_t>(rc), false);
            } else if (q.len <= kMaxChunk) {
                auto win = ram(q.addr, q.len);
                std::int64_t rc = win.size() == q.len ? static_cast<std::int64_t>(q.len) : -EFAULT;
                if (q.op == 2) {
                    std::vector<std::byte> in(q.len);
                    if (!full_io(c, in.data(), in.size(), true)) { ::close(c); continue; }
                    if (rc > 0) std::memcpy(win.data(), in.data(), in.size());
                    (void)full_io(c, &rc, sizeof rc, false);
                } else {
                    (void)full_io(c, &rc, sizeof rc, false);
                    if (rc > 0) (void)full_io(c, win.data(), win.size(), false);
                }
            }
            ::close(c);
        }
    }).detach();
}

// The client: one read or write of another process's guest memory.
// Bytes moved, or -errno (ESRCH: no such process serving).
[[nodiscard]] inline std::int64_t transfer(const std::string& path, bool writing, std::uint64_t addr,
                                           std::span<std::byte> buf) {
    std::int64_t done = 0;
    while (done < static_cast<std::int64_t>(buf.size())) {
        const std::uint64_t n = std::min<std::uint64_t>(buf.size() - static_cast<std::size_t>(done), kMaxChunk);
        const int c = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (c < 0) return done ? done : -errno;
        ::sockaddr_un a{};
        a.sun_family = AF_UNIX;
        std::memcpy(a.sun_path, path.c_str(), std::min(path.size() + 1, sizeof a.sun_path));
        if (::connect(c, reinterpret_cast<::sockaddr*>(&a), sizeof a) < 0) { ::close(c); return done ? done : -ESRCH; }
        Request q{writing ? 2u : 1u, 0, addr + static_cast<std::uint64_t>(done), n};
        std::int64_t rc = -EIO;
        bool ok = full_io(c, &q, sizeof q, false);
        if (ok && writing) ok = full_io(c, buf.data() + done, n, false);
        ok = ok && full_io(c, &rc, sizeof rc, true);
        if (ok && rc > 0 && !writing) ok = full_io(c, buf.data() + done, static_cast<std::size_t>(rc), true);
        ::close(c);
        if (!ok) return done ? done : -EIO;
        if (rc <= 0) return done ? done : rc;
        done += rc;
    }
    return done;
}

// The client for op 3: the serving process's guest resident bytes, or -errno.
// Bounded: a process that can't answer (stopped by a signal, wedged) must
// not hang the ps that asked -- it gets the host's count instead.
[[nodiscard]] inline std::int64_t resident(const std::string& path) {
    const int c = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (c < 0) return -errno;
    const ::timeval tv{0, 100'000};
    (void)::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    (void)::setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    ::sockaddr_un a{};
    a.sun_family = AF_UNIX;
    std::memcpy(a.sun_path, path.c_str(), std::min(path.size() + 1, sizeof a.sun_path));
    if (::connect(c, reinterpret_cast<::sockaddr*>(&a), sizeof a) < 0) { ::close(c); return -ESRCH; }
    Request q{3u, 0, 0, 0};
    std::int64_t rc = -EIO;
    const bool ok = full_io(c, &q, sizeof q, false) && full_io(c, &rc, sizeof rc, true);
    ::close(c);
    return ok ? rc : -EIO;
}

// Another guest process's /proc/<pid>/<leaf>, as it answers it (op 4).
[[nodiscard]] inline std::optional<std::string> fact(const std::string& path, std::string_view leaf) {
    if (leaf.empty() || leaf.size() > 64) return std::nullopt;
    const int c = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (c < 0) return std::nullopt;
    const ::timeval tv{10, 0};               // under load the peer may be slow to answer
    (void)::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    (void)::setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    ::sockaddr_un a{};
    a.sun_family = AF_UNIX;
    std::memcpy(a.sun_path, path.c_str(), std::min(path.size() + 1, sizeof a.sun_path));
    if (::connect(c, reinterpret_cast<::sockaddr*>(&a), sizeof a) < 0) { ::close(c); return std::nullopt; }
    Request q{4u, 0, 0, leaf.size()};
    std::int64_t rc = -EIO;
    std::optional<std::string> out;
    if (full_io(c, &q, sizeof q, false) && full_io(c, const_cast<char*>(leaf.data()), leaf.size(), false) &&
        full_io(c, &rc, sizeof rc, true) && rc >= 0 && static_cast<std::size_t>(rc) <= kMaxFact) {
        std::string s(static_cast<std::size_t>(rc), '\0');
        if (rc == 0 || full_io(c, s.data(), s.size(), true)) out = std::move(s);
    }
    ::close(c);
    return out;
}

}  // namespace lx::runtime::memsvc

#endif  // __APPLE__
