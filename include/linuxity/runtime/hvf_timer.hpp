// linuxity/runtime/hvf_timer.hpp
//
// Linux interval and POSIX timers.
//
// setitimer(ITIMER_REAL) and timer_create(CLOCK_REALTIME, SIGEV_SIGNAL) are
// the two mechanisms behind every "operation timed out": alarm(3), SIGALRM
// loops, glibc's timer_*, curl's and ssh's connect timeouts, vim's
// 'timeoutlen'. An ENOSYS here is the "Could not set timeout: Function not
// implemented" class of failure -- the program asks for a deadline, is told
// the kernel has no timers at all, and gives up.
//
// Darwin has setitimer, but only ITIMER_REAL maps cleanly and there is no
// POSIX timer_create. So linuxity implements both itself, which is also more
// honest: the signal has to arrive as a GUEST signal through our own
// delivery path (hvf_signal.hpp), not as a host SIGALRM that happens to
// interrupt whatever linuxity was doing.
//
// One host thread per process runs the timer wheel: it sleeps until the
// nearest deadline, then marks the signal pending and kicks the vCPUs, so
// the signal is delivered at the next trap boundary exactly like any other.
#pragma once

#if defined(__APPLE__)

#include "linuxity/runtime/hvf_signal.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace lx::runtime {

// Linux struct itimerval / itimerspec, as the guest lays them out.
struct LinuxTimeval { std::int64_t sec, usec; };
struct LinuxTimespec { std::int64_t sec, nsec; };
struct LinuxItimerval { LinuxTimeval interval, value; };
struct LinuxItimerspec { LinuxTimespec interval, value; };

// sigevent's notify kinds.
inline constexpr int kSigevSignal = 0;
inline constexpr int kSigevNone   = 1;
inline constexpr int kSigevThread = 2;

// ITIMER_* ids.
inline constexpr int kItimerReal    = 0;
inline constexpr int kItimerVirtual = 1;
inline constexpr int kItimerProf    = 2;

class TimerSet {
public:
    using Clock = std::chrono::steady_clock;
    using Nanos = std::chrono::nanoseconds;

    ~TimerSet() { stop(); }

    // Start the wheel thread. `raise` marks a guest signal pending and
    // kicks the vCPUs; the caller supplies it so this file knows nothing
    // about delivery.
    void start(std::function<void(int)> raise) {
        raise_ = std::move(raise);
        running_.store(true, std::memory_order_release);
        worker_ = std::thread{[this] { run(); }};
    }
    void stop() {
        if (!running_.exchange(false)) return;
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    // -- setitimer/getitimer ------------------------------------------------
    // Three interval timers per process, identified by ITIMER_*. VIRTUAL and
    // PROF measure CPU time rather than wall time; approximating them with
    // wall time is standard for an emulator and far better than refusing
    // them (profilers and watchdogs both just want periodic signals).
    struct Interval { Nanos value{}, interval{}; };

    [[nodiscard]] Interval set_interval(int which, Interval next) {
        std::lock_guard g{mu_};
        const Interval prev = remaining_locked(itimer_[idx(which)]);
        Entry& e = itimer_[idx(which)];
        e.interval = next.interval;
        e.deadline = next.value.count() ? Clock::now() + next.value : Clock::time_point{};
        e.signal = which == kItimerReal ? 14        // SIGALRM
                 : which == kItimerVirtual ? 26     // SIGVTALRM
                 : 27;                              // SIGPROF
        cv_.notify_all();
        return prev;
    }
    [[nodiscard]] Interval get_interval(int which) {
        std::lock_guard g{mu_};
        return remaining_locked(itimer_[idx(which)]);
    }
    [[nodiscard]] static bool valid_itimer(int which) noexcept {
        return which >= kItimerReal && which <= kItimerProf;
    }

    // -- timer_create/settime/gettime/delete --------------------------------
    [[nodiscard]] int create(int signo, int notify) {
        std::lock_guard g{mu_};
        const int id = next_id_++;
        Entry e{};
        e.signal = notify == kSigevNone ? 0 : signo;
        posix_[id] = e;
        return id;
    }
    [[nodiscard]] bool erase(int id) {
        std::lock_guard g{mu_};
        return posix_.erase(id) > 0;
    }
    [[nodiscard]] std::optional<Interval> set_posix(int id, Interval next, bool absolute) {
        std::lock_guard g{mu_};
        auto it = posix_.find(id);
        if (it == posix_.end()) return std::nullopt;
        const Interval prev = remaining_locked(it->second);
        it->second.interval = next.interval;
        it->second.deadline = next.value.count()
            ? (absolute ? Clock::time_point{next.value} : Clock::now() + next.value)
            : Clock::time_point{};
        cv_.notify_all();
        return prev;
    }
    [[nodiscard]] std::optional<Interval> get_posix(int id) {
        std::lock_guard g{mu_};
        auto it = posix_.find(id);
        if (it == posix_.end()) return std::nullopt;
        return remaining_locked(it->second);
    }
    // A timerfd delivers expirations by WRITING to a pipe rather than by
    // raising a signal, so each POSIX timer may carry its own notifier.
    void set_notifier(int id, std::function<void()> fn) {
        std::lock_guard g{mu_};
        auto it = posix_.find(id);
        if (it != posix_.end()) it->second.notify = std::move(fn);
    }

    [[nodiscard]] std::optional<int> overrun(int id) {
        std::lock_guard g{mu_};
        auto it = posix_.find(id);
        if (it == posix_.end()) return std::nullopt;
        return std::exchange(it->second.overrun, 0);
    }

private:
    struct Entry {
        Clock::time_point deadline{};     // zero = disarmed
        Nanos interval{};                 // zero = one-shot
        int signal{};
        int overrun{};
        std::function<void()> notify;     // timerfd: write to its pipe instead
    };

    [[nodiscard]] static std::size_t idx(int which) noexcept {
        return static_cast<std::size_t>(which < 0 || which > kItimerProf ? 0 : which);
    }

    [[nodiscard]] Interval remaining_locked(const Entry& e) const {
        if (e.deadline == Clock::time_point{}) return {};
        const auto now = Clock::now();
        return {e.deadline > now ? std::chrono::duration_cast<Nanos>(e.deadline - now)
                                 : Nanos{1},         // about to fire: never report 0
                e.interval};
    }

    // Fire every entry whose deadline has passed, rearm the periodic ones,
    // and return the next deadline to sleep until.
    [[nodiscard]] std::optional<Clock::time_point> fire_due(
            std::vector<int>& signals, std::vector<std::function<void()>>& notifies) {
        const auto now = Clock::now();
        std::optional<Clock::time_point> next;
        auto visit = [&](Entry& e) {
            if (e.deadline == Clock::time_point{}) return;
            if (e.deadline <= now) {
                if (e.signal) signals.push_back(e.signal);
                if (e.notify) notifies.push_back(e.notify);
                if (e.interval.count()) {
                    // Catch up without drifting; count missed ticks as
                    // overruns, which is what timer_getoverrun reports.
                    do {
                        e.deadline += e.interval;
                        if (e.deadline <= now) ++e.overrun;
                    } while (e.deadline <= now);
                } else {
                    e.deadline = Clock::time_point{};      // one-shot: disarm
                    return;
                }
            }
            if (!next || e.deadline < *next) next = e.deadline;
        };
        for (Entry& e : itimer_) visit(e);
        for (auto& [id, e] : posix_) visit(e);
        return next;
    }

    void run() {
        std::unique_lock lk{mu_};
        while (running_.load(std::memory_order_acquire)) {
            std::vector<int> signals;
            std::vector<std::function<void()>> notifies;
            const auto next = fire_due(signals, notifies);
            lk.unlock();
            for (int s : signals) raise_(s);
            for (auto& fn : notifies) fn();
            lk.lock();
            if (!running_.load(std::memory_order_acquire)) break;
            if (next) cv_.wait_until(lk, *next);
            else      cv_.wait(lk);
        }
    }

    std::mutex mu_;
    std::condition_variable cv_;
    std::thread worker_;
    std::atomic<bool> running_{false};
    std::function<void(int)> raise_;
    Entry itimer_[3]{};
    std::map<int, Entry> posix_;
    int next_id_{1};
};

} // namespace lx::runtime

#endif // __APPLE__
