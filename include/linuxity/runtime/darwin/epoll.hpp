// linuxity/runtime/darwin/epoll.hpp
//
// Linux epoll on Darwin kqueue.
//
// epoll is how every modern Linux event loop waits: systemd, nginx, redis,
// Go's netpoller, libuv/node, Python's asyncio, glib. A backend that refuses
// it does not merely lose performance -- those programs have no fallback and
// fail outright.
//
// kqueue is the same idea with a different shape, and three differences
// matter:
//
//   1. epoll is LEVEL-triggered by default and edge-triggered on request;
//      kqueue is the reverse. So EPOLLET maps to EV_CLEAR, and its absence
//      must NOT set EV_CLEAR.
//   2. epoll takes one event mask per fd; kqueue takes one kevent per
//      (fd, filter) pair, so a read/write registration is TWO kevents that
//      must be added and removed together.
//   3. epoll remembers an opaque 64-bit user token per fd and reports it
//      back; kqueue's udata is per kevent. We keep the token ourselves, so
//      EPOLL_CTL_MOD can change the mask without losing it.
//
// Keeping the registration table on our side also gives correct ENOENT/EEXIST
// semantics for EPOLL_CTL_ADD/MOD/DEL, which kqueue alone does not express.
#pragma once

#if defined(__APPLE__)

#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <map>
#include <vector>

namespace lx::runtime {

// epoll event bits (identical on every Linux arch).
namespace epoll_bit {
inline constexpr std::uint32_t in        = 0x001;
inline constexpr std::uint32_t pri       = 0x002;
inline constexpr std::uint32_t out       = 0x004;
inline constexpr std::uint32_t err       = 0x008;
inline constexpr std::uint32_t hup       = 0x010;
inline constexpr std::uint32_t rdnorm    = 0x040;
inline constexpr std::uint32_t rdhup     = 0x2000;
inline constexpr std::uint32_t exclusive = 1u << 28;
inline constexpr std::uint32_t wakeup    = 1u << 29;
inline constexpr std::uint32_t oneshot   = 1u << 30;
inline constexpr std::uint32_t et        = 1u << 31;
}  // namespace epoll_bit

// EPOLL_CTL_*
inline constexpr int kEpollCtlAdd = 1, kEpollCtlDel = 2, kEpollCtlMod = 3;

// struct epoll_event is PACKED on every Linux ABI: a u32 followed by a u64
// with no padding between them. Getting this wrong shifts the user token.
struct __attribute__((packed)) LinuxEpollEvent {
    std::uint32_t events;
    std::uint64_t data;
};
static_assert(sizeof(LinuxEpollEvent) == 12);

// One epoll set: a kqueue plus the registrations we own.
class EpollSet {
public:
    EpollSet() : kq_{::kqueue()} {}
    EpollSet(const EpollSet&) = delete;
    EpollSet& operator=(const EpollSet&) = delete;
    ~EpollSet() { if (kq_ >= 0) ::close(kq_); }

    [[nodiscard]] bool valid() const noexcept { return kq_ >= 0; }

    // ctl(op, host_fd, guest_fd, mask, token) -> 0 or -errno (Linux values).
    [[nodiscard]] std::int64_t ctl(int op, int host_fd, int guest_fd,
                                   std::uint32_t mask, std::uint64_t token) {
        const bool known = regs_.contains(guest_fd);
        switch (op) {
            case kEpollCtlAdd:
                if (known) return -17;                   // EEXIST
                break;
            case kEpollCtlMod:
                if (!known) return -2;                   // ENOENT
                break;
            case kEpollCtlDel:
                if (!known) return -2;
                // best-effort: the host fd may already be closed, which
                // drops its kevents anyway
                (void)apply(guest_fd, host_fd, 0, regs_[guest_fd].mask);
                regs_.erase(guest_fd);
                return 0;
            default:
                return -22;                              // EINVAL
        }
        const std::uint32_t old = known ? regs_[guest_fd].mask : 0;
        if (const std::int64_t rc = apply(guest_fd, host_fd, mask, old); rc < 0) return rc;
        regs_[guest_fd] = {host_fd, mask, token};
        return 0;
    }

    // wait(out, max, timeout_ms) -> number of ready events, or -errno.
    [[nodiscard]] std::int64_t wait(std::vector<LinuxEpollEvent>& out, int max,
                                    int timeout_ms) {
        if (max <= 0) return -22;
        std::vector<struct ::kevent> evs(static_cast<std::size_t>(max));
        struct ::timespec ts{};
        const struct ::timespec* tp = nullptr;
        if (timeout_ms >= 0) {
            ts.tv_sec = timeout_ms / 1000;
            ts.tv_nsec = (timeout_ms % 1000) * 1'000'000;
            tp = &ts;
        }
        const int n = ::kevent(kq_, nullptr, 0, evs.data(), max, tp);
        if (n < 0) return errno == EINTR ? -4 : -static_cast<std::int64_t>(errno);

        // Collapse the (fd, filter) pairs back into one entry per fd, which
        // is the shape epoll_wait promises.
        out.clear();
        for (int i = 0; i < n; ++i) {
            const auto& ev = evs[static_cast<std::size_t>(i)];
            const int gfd = static_cast<int>(ev.udata ? reinterpret_cast<std::intptr_t>(ev.udata) : -1);
            auto it = regs_.find(gfd);
            if (it == regs_.end()) continue;
            std::uint32_t bits = 0;
            if (ev.filter == EVFILT_READ)  bits |= epoll_bit::in;
            if (ev.filter == EVFILT_WRITE) bits |= epoll_bit::out;
            if (ev.flags & EV_EOF) {
                // A read filter at EOF is a peer hangup; epoll reports both
                // EPOLLHUP and (for a half-close) EPOLLRDHUP, and callers
                // branch on which.
                bits |= epoll_bit::hup;
                if (ev.filter == EVFILT_READ) bits |= epoll_bit::rdhup;
            }
            if (ev.flags & EV_ERROR) bits |= epoll_bit::err;
            bits &= it->second.mask | epoll_bit::err | epoll_bit::hup
                  | epoll_bit::rdhup;    // err/hup are always reportable
            if (!bits) continue;
            // Merge with an entry already emitted for this fd.
            auto same = std::find_if(out.begin(), out.end(),
                [&](const LinuxEpollEvent& e) { return e.data == it->second.token; });
            if (same != out.end()) same->events |= bits;
            else out.push_back({bits, it->second.token});
            if (it->second.mask & epoll_bit::oneshot) {
                (void)apply(gfd, it->second.host_fd, 0, it->second.mask);   // best-effort, as DEL
                regs_.erase(it);
            }
        }
        return static_cast<std::int64_t>(out.size());
    }

private:
    struct Reg { int host_fd; std::uint32_t mask; std::uint64_t token; };

    // Add/remove the kevent pair for one fd so the kqueue matches `want`.
    // The GUEST fd rides in each kevent's udata, which is how wait() maps a
    // readiness report back to its registration (and its user token).
    [[nodiscard]] std::int64_t apply(int guest_fd, int host_fd,
                                     std::uint32_t want, std::uint32_t had) {
        struct ::kevent ch[2];
        int n = 0;
        auto* tag = reinterpret_cast<void*>(static_cast<std::intptr_t>(guest_fd));
        auto change = [&](std::int16_t filter, bool on, bool edge) {
            const std::uint16_t flags = on ? static_cast<std::uint16_t>(EV_ADD | (edge ? EV_CLEAR : 0))
                                           : static_cast<std::uint16_t>(EV_DELETE);
            EV_SET(&ch[n++], host_fd, filter, flags, 0, 0, tag);
        };
        const bool edge = (want & epoll_bit::et) != 0;
        const bool want_r = (want & (epoll_bit::in | epoll_bit::pri | epoll_bit::rdnorm)) != 0;
        const bool want_w = (want & epoll_bit::out) != 0;
        const bool had_r = (had & (epoll_bit::in | epoll_bit::pri | epoll_bit::rdnorm)) != 0;
        const bool had_w = (had & epoll_bit::out) != 0;
        if (want_r != had_r) change(EVFILT_READ, want_r, edge);
        if (want_w != had_w) change(EVFILT_WRITE, want_w, edge);
        if (n == 0) return 0;
        if (::kevent(kq_, ch, n, nullptr, 0, nullptr) < 0) {
            // A regular file can't be registered with kqueue's read filter,
            // but epoll accepts it and always reports it ready. Treat that
            // as success: the fd simply stays level-ready.
            if (errno == EINVAL || errno == ENODEV) return 0;
            return -static_cast<std::int64_t>(errno);
        }
        return 0;
    }

    int kq_;
    std::map<int, Reg> regs_;
};

} // namespace lx::runtime

#endif // __APPLE__
