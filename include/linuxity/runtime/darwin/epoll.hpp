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
#include <sys/stat.h>
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

// struct epoll_event is PACKED only on x86-64 (__EPOLL_PACKED); on aarch64,
// the only guest this backend runs, it is naturally aligned: a u32, four
// bytes of padding, a u64 -- 16 bytes. Packing it here shifted every event
// after the first by 4 bytes, so the guest read tokens out of the padding.
struct LinuxEpollEvent {
    std::uint32_t events;
    std::uint32_t pad_{};
    std::uint64_t data;
};
static_assert(sizeof(LinuxEpollEvent) == 16);

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
        bool fifo = known && regs_[guest_fd].fifo;
        if (!known) {
            // epoll refuses what can never block: regular files and
            // directories (EPERM). kqueue would take them.
            struct ::stat st{};
            if (::fstat(host_fd, &st) == 0 && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)))
                return -1;                               // EPERM
            fifo = S_ISFIFO(st.st_mode);
        }
        // EPOLLEXCLUSIVE may only be ADDed; MOD of (or to) it is EINVAL.
        if (op == kEpollCtlMod &&
            ((mask | regs_[guest_fd].armed) & epoll_bit::exclusive)) return -22;
        if (const std::int64_t rc = apply(guest_fd, host_fd, mask, old); rc < 0) return rc;
        regs_[guest_fd] = {host_fd, mask, token, mask, fifo};
        return 0;
    }

    // The kqueue itself: readable when any armed event is pending, so a
    // caller can block on it in poll()/select() alongside other fds (a
    // signal wake pipe) and then collect with wait(..., 0).
    [[nodiscard]] int fd() const noexcept { return kq_; }

    // Host fds of FIFOs armed for input. kqueue never reports a FIFO's
    // writer leaving (macOS), so the caller must also wait on these where
    // the hangup is visible -- select() -- and pass the hung-up ones back.
    [[nodiscard]] std::vector<std::pair<int, int>> input_fifos() const {
        std::vector<std::pair<int, int>> out;     // guest fd, host fd
        for (const auto& [g, r] : regs_)
            if (r.fifo && (r.mask & (epoll_bit::in | epoll_bit::rdnorm))) out.emplace_back(g, r.host_fd);
        return out;
    }

    // wait(out, max, timeout_ms, hups) -> number of ready events, or -errno.
    // `hups`: guest fds of FIFOs the caller saw hang up (input_fifos);
    // each is reported EPOLLHUP.
    [[nodiscard]] std::int64_t wait(std::vector<LinuxEpollEvent>& out, int max,
                                    int timeout_ms, const std::vector<int>& hups = {}) {
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
        std::vector<int> out_fd;     // which guest fd each `out` entry is
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
                  ;    // err/hup are always reportable; RDHUP only if asked
            if (!bits) continue;
            // Merge with an entry already emitted for this fd (by fd: two
            // registrations may well carry the same token).
            auto same = std::find(out_fd.begin(), out_fd.end(), gfd);
            if (same != out_fd.end()) {
                out[static_cast<std::size_t>(same - out_fd.begin())].events |= bits;
                continue;
            }
            out.push_back({bits, 0, it->second.token});
            out_fd.push_back(gfd);
            if (it->second.mask & epoll_bit::oneshot) {
                // Fired once: DISARMED, not forgotten -- the registration
                // stays (a second ADD is EEXIST) until EPOLL_CTL_MOD re-arms it.
                (void)apply(gfd, it->second.host_fd, 0, it->second.mask);
                it->second.mask = 0;
            }
        }
        // The FIFO hangups the caller found: EPOLLHUP, which is always
        // reportable (merged into an EPOLLIN for the same fd, if any).
        for (const int gfd : hups) {
            if (static_cast<int>(out.size()) >= max) break;
            auto it = regs_.find(gfd);
            if (it == regs_.end() || !it->second.mask) continue;
            auto same = std::find(out_fd.begin(), out_fd.end(), gfd);
            if (same != out_fd.end()) {
                out[static_cast<std::size_t>(same - out_fd.begin())].events |= epoll_bit::hup;
                continue;
            }
            out.push_back({epoll_bit::hup, 0, it->second.token});
            out_fd.push_back(gfd);
            if (it->second.mask & epoll_bit::oneshot) {
                (void)apply(gfd, it->second.host_fd, 0, it->second.mask);
                it->second.mask = 0;
            }
        }
        return static_cast<std::int64_t>(out.size());
    }

private:
    // mask: what is armed in the kqueue now (0 once a ONESHOT fired);
    // armed: what the guest last asked for. fifo: a FIFO, whose hangup
    // only select() can see (input_fifos).
    struct Reg {
        int host_fd; std::uint32_t mask; std::uint64_t token; std::uint32_t armed;
        bool fifo{false};
    };

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
        const bool flip = ((want ^ had) & epoll_bit::et) != 0;   // EV_CLEAR changes
        if (want_r != had_r || (want_r && flip)) change(EVFILT_READ, want_r, edge);
        if (want_w != had_w || (want_w && flip)) change(EVFILT_WRITE, want_w, edge);
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
