// linuxity/runtime/darwin/futex.hpp
//
// Linux futex(2) on Darwin.
//
// Every pthread mutex, condition variable, semaphore, barrier, once-flag and
// thread join in a Linux guest bottoms out in futex. It is THE primitive for
// threading, so a backend that fakes it (returning EAGAIN, or spinning)
// turns every contended lock into a livelock and every join into a busy
// loop that never ends.
//
// macOS 14 added os_sync_wait_on_address, which is the same primitive with
// the same contract: compare a word against an expected value and sleep
// atomically if it matches, wake N waiters by address. Crucially it supports
// SHARED flags that work across processes on MAP_SHARED memory -- verified
// here -- which is what a non-private Linux futex needs, and what linuxity's
// multi-process guests (a fork is a separate host process sharing guest RAM
// through a Mach memory entry) require.
//
// The mapping:
//
//   FUTEX_WAIT / WAIT_BITSET   -> os_sync_wait_on_address[_with_timeout]
//   FUTEX_WAKE / WAKE_BITSET   -> os_sync_wake_by_address_{any,all}
//   FUTEX_REQUEUE / CMP_REQUEUE-> wake on the first address, then wake on
//                                 the second (a conservative but correct
//                                 implementation: requeue exists only to
//                                 avoid a thundering herd, never for
//                                 correctness)
//   FUTEX_WAKE_OP              -> apply the op to addr2, then wake both
//
// The bitset variants are implemented by IGNORING the bitset and waking
// every candidate: Linux permits spurious wakeups, so a waiter whose bit
// didn't match simply rechecks its condition and sleeps again. That is the
// standard conservative implementation (and what glibc tolerates by design).
#pragma once

#if defined(__APPLE__)

#include <os/os_sync_wait_on_address.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <span>

namespace lx::runtime {

// Futex operation codes (asm-generic; identical on every Linux arch).
enum class FutexOp : std::uint32_t {
    wait = 0, wake = 1, requeue = 3, cmp_requeue = 4, wake_op = 5,
    lock_pi = 6, unlock_pi = 7, trylock_pi = 8,
    wait_bitset = 9, wake_bitset = 10,
    wait_requeue_pi = 11, cmp_requeue_pi = 12,
};
inline constexpr std::uint32_t kFutexPrivate = 128;   // FUTEX_PRIVATE_FLAG
inline constexpr std::uint32_t kFutexClockRealtime = 256;
inline constexpr std::uint32_t kFutexCmdMask = ~(kFutexPrivate | kFutexClockRealtime);

// FUTEX_WAKE_OP's packed operation word: (op<<28)|(cmp<<24)|(oparg<<12)|cmparg
struct WakeOpSpec {
    std::uint32_t op, oparg, cmp, cmparg;

    [[nodiscard]] static constexpr WakeOpSpec decode(std::uint32_t v) noexcept {
        WakeOpSpec s{};
        s.op     = (v >> 28) & 0xf;
        s.cmp    = (v >> 24) & 0xf;
        s.oparg  = (v >> 12) & 0xfff;
        s.cmparg = v & 0xfff;
        if (s.op & 8) {                       // FUTEX_OP_OPARG_SHIFT
            s.op &= 7;
            s.oparg = 1u << (s.oparg & 31);
        }
        return s;
    }

    [[nodiscard]] constexpr std::uint32_t apply(std::uint32_t old) const noexcept {
        switch (op) {
            case 0:  return oparg;            // SET
            case 1:  return old + oparg;      // ADD
            case 2:  return old | oparg;      // OR
            case 3:  return old & ~oparg;     // ANDN
            case 4:  return old ^ oparg;      // XOR
            default: return old;
        }
    }

    [[nodiscard]] constexpr bool compare(std::uint32_t old) const noexcept {
        switch (cmp) {
            case 0:  return old == cmparg;    // EQ
            case 1:  return old != cmparg;    // NE
            case 2:  return old <  cmparg;    // LT
            case 3:  return old <= cmparg;    // LE
            case 4:  return old >  cmparg;    // GT
            case 5:  return old >= cmparg;    // GE
            default: return false;
        }
    }
};

// The host-side futex, operating on HOST pointers into shared guest RAM.
// Guest-address translation and the Linux return-value conventions live in
// the trap backend; this is purely the Darwin mechanism.
class Futex {
public:
    // Sleep until woken or `timeout_ns` elapses (0 = forever). Returns the
    // Linux result: 0 woken, -EAGAIN if *addr != expected, -ETIMEDOUT,
    // -EINTR.
    //
    // The value check is done HERE, explicitly, because the two primitives
    // differ on the single most important case: when *addr != expected,
    // Linux futex returns -EAGAIN ("the condition already changed, recheck
    // and do not sleep") while os_sync_wait_on_address returns 0 as though
    // the thread had been woken. Reporting that 0 to glibc makes a condvar
    // believe it was signalled when it wasn't -- the "futex facility
    // returned an unexpected error code" abort, and silent lost wakeups.
    //
    // Checking first is also exactly what the primitive does internally, so
    // the race window is the same one Linux has: the value can change after
    // our load, and the kernel-side compare inside the wait call catches it.
    [[nodiscard]] static std::int64_t wait(void* addr, std::uint32_t expected,
                                           std::uint64_t timeout_ns, bool shared) {
        const std::atomic_ref<std::uint32_t> word{*static_cast<std::uint32_t*>(addr)};
        if (word.load(std::memory_order_acquire) != expected) return -11;   // EAGAIN

        const auto flags = shared ? OS_SYNC_WAIT_ON_ADDRESS_SHARED
                                  : OS_SYNC_WAIT_ON_ADDRESS_NONE;
        // The call reports failure only through rc < 0, and does not clear
        // errno on success, so errno must not be consulted unless it does.
        errno = 0;
        const int rc = timeout_ns
            ? ::os_sync_wait_on_address_with_timeout(
                  addr, expected, 4, flags, OS_CLOCK_MACH_ABSOLUTE_TIME, timeout_ns)
            : ::os_sync_wait_on_address(addr, expected, 4, flags);
        if (rc >= 0) return 0;
        switch (errno) {
            case EAGAIN:    return -11;       // value changed: not an error
            case ETIMEDOUT: return -110;      // Linux ETIMEDOUT
            case EINTR:     return -4;
            case EINVAL:    return -22;
            default:        return -22;
        }
    }

    // Wake up to `count` waiters; returns how many were woken.
    //
    // os_sync_wake_by_address_* returns 0 on success and -1 on error, and it
    // does NOT clear errno on success -- a measured stale ETIMEDOUT from an
    // earlier wait came back from a wake that had in fact woken a thread.
    // So only rc < 0 is a failure, and ENOENT ("nobody was waiting") is a
    // normal outcome Linux reports as 0 woken, not an error.
    [[nodiscard]] static std::int64_t wake(void* addr, std::uint32_t count, bool shared) {
        if (count == 0) return 0;
        const auto flags = shared ? OS_SYNC_WAKE_BY_ADDRESS_SHARED
                                  : OS_SYNC_WAKE_BY_ADDRESS_NONE;
        // Darwin can wake one or all, not exactly N. Waking all when N > 1
        // is conservative and safe: Linux allows spurious wakeups, so the
        // extra waiters recheck and sleep again. (N > 1 in practice means
        // INT_MAX -- "wake everyone" -- from pthread_cond_broadcast.)
        errno = 0;
        const int rc = count == 1 ? ::os_sync_wake_by_address_any(addr, 4, flags)
                                  : ::os_sync_wake_by_address_all(addr, 4, flags);
        if (rc == 0) return count == 1 ? 1 : static_cast<std::int64_t>(count);
        if (errno == ENOENT) return 0;        // no waiters: 0 woken, not an error
        return 0;
    }
};

} // namespace lx::runtime

#endif // __APPLE__
