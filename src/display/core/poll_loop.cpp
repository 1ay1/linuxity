// src/display/core/poll_loop.cpp -- EventLoop on poll(2), for headless runs.
#include "loop.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <deque>
#include <memory>
#include <vector>

#include <poll.h>

namespace lx::display {

namespace {

class PollLoop final : public EventLoop {
    struct Entry {
        int fd{-1};
        short events{0};
        std::chrono::microseconds period{0};
        std::chrono::steady_clock::time_point due{};
        Fn fn;
        bool live{true};
    };
    class Src final : public Source {
    public:
        explicit Src(std::shared_ptr<Entry> e) : e_(std::move(e)) {}
        ~Src() override { e_->live = false; }
    private:
        std::shared_ptr<Entry> e_;
    };

public:
    std::unique_ptr<Source> on_readable(int fd, Fn fn) override { return add(fd, POLLIN, {}, std::move(fn)); }
    std::unique_ptr<Source> on_writable(int fd, Fn fn) override { return add(fd, POLLOUT, {}, std::move(fn)); }
    std::unique_ptr<Source> every(std::chrono::microseconds p, Fn fn) override { return add(-1, 0, p, std::move(fn)); }
    void defer(Fn fn) override { deferred_.push_back(std::move(fn)); }
    void stop() override { stop_ = true; }

    void run() override {
        stop_ = false;
        while (!stop_) {
            run_deferred();
            if (stop_) break;
            std::erase_if(entries_, [](const auto& e) { return !e->live; });
            std::vector<pollfd> pfds;
            std::vector<std::shared_ptr<Entry>> who;
            auto now = std::chrono::steady_clock::now();
            int timeout = -1;
            for (auto& e : entries_) {
                if (e->fd >= 0) {
                    pfds.push_back({e->fd, e->events, 0});
                    who.push_back(e);
                } else {
                    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(e->due - now).count();
                    const int t = static_cast<int>(std::max<long long>(0, ms));
                    timeout = timeout < 0 ? t : std::min(timeout, t);
                }
            }
            if (!deferred_.empty()) timeout = 0;
            const int n = ::poll(pfds.data(), static_cast<nfds_t>(pfds.size()), timeout);
            if (n < 0 && errno != EINTR) return;
            for (std::size_t k = 0; n > 0 && k < pfds.size(); ++k)
                if (pfds[k].revents && who[k]->live) { auto keep = who[k]; keep->fn(); run_deferred(); }
            now = std::chrono::steady_clock::now();
            for (std::size_t k = 0; k < entries_.size(); ++k) {
                auto e = entries_[k];
                if (e->fd >= 0 || !e->live || e->due > now) continue;
                e->due = now + e->period;
                e->fn();
                run_deferred();
            }
        }
    }

private:
    std::unique_ptr<Source> add(int fd, short ev, std::chrono::microseconds p, Fn fn) {
        auto e = std::make_shared<Entry>();
        e->fd = fd;
        e->events = ev;
        e->period = p;
        e->due = std::chrono::steady_clock::now() + p;
        e->fn = std::move(fn);
        entries_.push_back(e);
        return std::make_unique<Src>(e);
    }
    void run_deferred() {
        while (!deferred_.empty()) {
            auto fn = std::move(deferred_.front());
            deferred_.pop_front();
            fn();
        }
    }
    std::vector<std::shared_ptr<Entry>> entries_;
    std::deque<Fn> deferred_;
    bool stop_{false};
};

}  // namespace

std::unique_ptr<EventLoop> make_poll_loop() { return std::make_unique<PollLoop>(); }

}  // namespace lx::display
