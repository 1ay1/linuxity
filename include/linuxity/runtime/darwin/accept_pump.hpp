// linuxity/runtime/darwin/accept_pump.hpp
//
// Deep listen backlogs on a host that caps them. Linux keeps up to
// listen(2)'s backlog of completed connections queued (net.core.somaxconn
// is 4096 on current kernels); Darwin clamps the backlog to
// kern.ipc.somaxconn -- 128 unless root raised it -- and RESETS each
// connection that arrives once that queue is full, where Linux would merely
// drop the SYN and let the client retry. So a server that asks for a
// backlog of 1024 and is slow to accept (asyncio under a burst, a test
// opening 500 connections before accepting any) saw ECONNRESET on Darwin.
//
// An AcceptPump makes up the difference for ONE listener whose guest
// backlog exceeds the host's cap. Its thread sleeps in kevent on the
// listener and accepts arriving connections into a private FIFO, leaving a
// few queued on the host so the listener stays readable (poll/epoll/select
// see it ready, as they would on Linux). The guest's accept takes from the
// FIFO first, so connections are still handed out oldest first. The pump
// holds at most backlog - host cap, so the total stays the guest's backlog.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include <deque>
#include <mutex>
#include <thread>

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/event.h>
#include <sys/qos.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

namespace lx::runtime {

class AcceptPump {
public:
    // The host's listen-queue cap (kern.ipc.somaxconn).
    [[nodiscard]] static int host_cap() noexcept {
        static const int cap = [] {
            int v = 0;
            std::size_t n = sizeof v;
            return ::sysctlbyname("kern.ipc.somaxconn", &v, &n, nullptr, 0) == 0 && v > 0 ? v : 128;
        }();
        return cap;
    }

    // Pump `listener` (borrowed: the pump takes its own reference) for a
    // guest backlog of `backlog`. valid() is false if the host refused.
    AcceptPump(int listener, int backlog) {
        struct ::stat st{};
        if (::fstat(listener, &st) == 0) { dev_ = st.st_dev; ino_ = st.st_ino; }
        lfd_ = ::fcntl(listener, F_DUPFD_CLOEXEC, 3);
        kq_ = ::kqueue();
        if (lfd_ < 0 || kq_ < 0 || ::pipe(wake_) < 0) { release(); return; }
        for (int e : wake_) ::fcntl(e, F_SETFD, FD_CLOEXEC);
        const int cap = host_cap();
        cap_ = static_cast<std::size_t>(backlog > cap ? backlog - cap : 0);
        // Drain eagerly, leaving a few on the host so the listener stays
        // readable: a burst (asyncio firing hundreds of connects at once)
        // then has the WHOLE host queue as headroom while this thread is
        // still waking. Waiting until the host queue was 3/4 full lost the
        // race under load.
        keep_ = 4;
        high_ = keep_ + 1;
        struct ::kevent ch[2];
        EV_SET(&ch[0], lfd_, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, nullptr);
        EV_SET(&ch[1], wake_[0], EVFILT_READ, EV_ADD, 0, 0, nullptr);
        if (::kevent(kq_, ch, 2, nullptr, 0, nullptr) < 0) { release(); return; }
        thread_ = std::thread([this] {
            // Latency is the whole job: run ahead of the guest's vCPUs.
            (void)::pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
            loop();
        });
    }
    AcceptPump(const AcceptPump&) = delete;
    AcceptPump& operator=(const AcceptPump&) = delete;
    ~AcceptPump() {
        if (thread_.joinable()) {
            { std::lock_guard g{mu_}; stop_ = true; }
            poke();
            thread_.join();
        }
        // Connections still queued are refused, as Linux refuses the ones
        // left in a closed listener's queue.
        for (int c : q_) ::close(c);
        release();
    }

    [[nodiscard]] bool valid() const noexcept { return thread_.joinable(); }
    // Is `fd` (still) the socket this pump serves?
    [[nodiscard]] bool serves(int fd) const noexcept {
        struct ::stat st{};
        return ::fstat(fd, &st) == 0 && st.st_dev == dev_ && st.st_ino == ino_;
    }
    // The guest's backlog changed (listen again).
    void set_backlog(int backlog) {
        const int cap = host_cap();
        std::lock_guard g{mu_};
        cap_ = static_cast<std::size_t>(backlog > cap ? backlog - cap : 0);
    }

    // The oldest connection the pump holds, or -1 (then accept on the host).
    [[nodiscard]] int take() {
        int c = -1;
        bool was_full = false;
        {
            std::lock_guard g{mu_};
            if (q_.empty()) return -1;
            was_full = q_.size() >= cap_;
            c = q_.front();
            q_.pop_front();
        }
        if (was_full) poke();          // room again: look at the host queue
        return c;
    }

private:
    void poke() noexcept { const char b = 1; (void)!::write(wake_[1], &b, 1); }

    void loop() {
        for (;;) {
            struct ::kevent ev[2];
            const int n = ::kevent(kq_, nullptr, 0, ev, 2, nullptr);
            if (n < 0) { if (errno == EINTR) continue; return; }
            std::intptr_t pending = -1;
            for (int i = 0; i < n; ++i) {
                if (static_cast<int>(ev[i].ident) == wake_[0]) {
                    char buf[64];
                    (void)!::read(wake_[0], buf, sizeof buf);
                } else {
                    pending = ev[i].data;
                }
            }
            {
                std::lock_guard g{mu_};
                if (stop_) return;
            }
            if (pending < 0) pending = queued_on_host();
            if (pending < high_) continue;
            for (std::intptr_t k = pending - keep_; k > 0; --k) {
                {
                    std::lock_guard g{mu_};
                    if (q_.size() >= cap_) break;
                }
                // The host queue said it holds this many, but another
                // process sharing the socket may have taken some: never block.
                struct ::pollfd p{lfd_, POLLIN, 0};
                if (::poll(&p, 1, 0) != 1) break;
                const int c = ::accept(lfd_, nullptr, nullptr);
                if (c < 0) break;
                ::fcntl(c, F_SETFD, FD_CLOEXEC);
                std::lock_guard g{mu_};
                q_.push_back(c);
            }
        }
    }
    // A level-triggered look at the host queue's length.
    [[nodiscard]] std::intptr_t queued_on_host() const noexcept {
        const int k = ::kqueue();
        if (k < 0) return 0;
        struct ::kevent ch, ev;
        EV_SET(&ch, lfd_, EVFILT_READ, EV_ADD, 0, 0, nullptr);
        const struct ::timespec zero{0, 0};
        const int n = ::kevent(k, &ch, 1, &ev, 1, &zero);
        ::close(k);
        return n == 1 ? ev.data : 0;
    }
    void release() noexcept {
        for (int* f : {&lfd_, &kq_, &wake_[0], &wake_[1]})
            if (*f >= 0) { ::close(*f); *f = -1; }
    }

    int lfd_{-1}, kq_{-1};
    int wake_[2]{-1, -1};
    dev_t dev_{};
    ino_t ino_{};
    std::thread thread_;
    std::mutex mu_;
    std::deque<int> q_;
    std::size_t cap_{0};
    std::intptr_t high_{1}, keep_{1};
    bool stop_{false};
};

}  // namespace lx::runtime

#endif  // __APPLE__ && __aarch64__
