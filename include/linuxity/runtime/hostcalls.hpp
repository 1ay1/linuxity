// linuxity/runtime/hostcalls.hpp
//
// The HOST-FACILITY contract: the thin set of operations that genuinely need
// something only the host OS can provide.
//
// WHY THIS EXISTS
// ---------------
// The portable dispatcher (abi/syscall.hpp) ends unhandled syscalls with
// `return fwd()` -- forward to the host kernel. That is correct on Linux,
// where a real Linux kernel sits underneath and can run `read` for us. On
// macOS and Windows there is no Linux kernel, so `read`/`write`/`mmap`/
// `clock_gettime` have to be IMPLEMENTED rather than forwarded.
//
// Windows answered that by growing a second dispatcher
// (runtime/windows/sys.hpp, 751 lines). Once it existed, 46 syscalls that had
// nothing to do with the problem drifted into it too, and drifted APART:
//
//   syscall   abi/syscall.hpp                 windows/sys.hpp
//   getpid    ids().pid  (real guest pid)     hardcoded 1
//   gettid    ids().tid  (real per-task)      hardcoded 1
//   getppid   ids().ppid (real)               hardcoded 1
//   getdents  real inode + real DT_*          pos+1 + DT_UNKNOWN  (fixed)
//
// So on Windows every process saw pid 1. That is not a backend difference --
// nothing about Hyper-V makes getpid mean something else -- it is a worse
// reimplementation of code that already existed.
//
// THE AXIS WAS WRONG. The question is not "which host am I on", it is:
//
//     Does this syscall need a HOST FACILITY, or is it policy over state
//     linuxity already owns?
//
//   * POLICY (getpid, uname, getdents64 encoding, credentials, path
//     resolution, the overlay) -- lives ONCE in abi/syscall.hpp and
//     kernel/. Every host gets the same answer because it is the same code.
//
//   * HOST FACILITY (move these bytes to that fd, map this memory, what time
//     is it) -- this file. One narrow interface, three implementations.
//
// Linux implements it by FORWARDING to the real kernel, which is what it
// already does, so nothing about the Linux path changes. macOS implements it
// with Darwin syscalls, Windows with Win32. A backend then implements exactly
// two things and nothing else: how to trap (runtime/backend.hpp) and how to
// reach its host (this file).
//
// WHAT BELONGS HERE. Only operations whose IMPLEMENTATION is host-specific,
// never POLICY. `read` belongs: ReadFile vs read(2) is irreplaceable. The
// iovec walk around readv does NOT -- that is the same loop everywhere, so it
// stays in the dispatcher and calls read_fd() per segment. The test for a new
// member is: "would two correct hosts write different code here?" If no, it
// is policy and belongs in abi/.
#pragma once

#include <cstdint>
#include <span>
#include <string>

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"

namespace lx::runtime {

// -- clocks ----------------------------------------------------------------
// The guest's clock ids, as the Linux ABI numbers them. Named here so no
// backend open-codes the integers.
enum class ClockId : std::int32_t {
    realtime          = 0,
    monotonic         = 1,
    process_cputime   = 2,
    thread_cputime    = 3,
    monotonic_raw     = 4,
    realtime_coarse   = 5,
    monotonic_coarse  = 6,
    boottime          = 7,
};

// A POSIX timespec, as the guest sees it. Host-free: this is the ABI shape,
// not any host's struct.
struct Timespec {
    std::int64_t sec{};
    std::int64_t nsec{};
};

// -- the contract ----------------------------------------------------------
//
// Every member is REQUIRED. There is deliberately no capability tier here
// (unlike runtime/backend.hpp, where optional abilities are real): a host
// that cannot read a file descriptor cannot run a guest at all, so a missing
// member is a build error naming it rather than a silent degradation.
template <class T>
concept HostCalls = requires(T h, Fd fd, std::span<std::byte> out,
                             std::span<const std::byte> in) {
    // -- descriptor I/O ----------------------------------------------------
    // Move bytes between a host fd and a buffer the DISPATCHER owns. The
    // guest-memory copy, the iovec walk, the short-write retry and the errno
    // mapping all stay in the dispatcher, because they are identical on every
    // host. Only the transfer itself is here.
    { h.read_fd(fd, out) }  -> std::same_as<Result<std::size_t>>;
    { h.write_fd(fd, in) }  -> std::same_as<Result<std::size_t>>;
    { h.close_fd(fd) }      -> std::same_as<Status>;

    // Positioned read: pread(2). Separate from read_fd because the host
    // primitive differs (an OVERLAPPED offset on Win32, a pread syscall on
    // POSIX), not because the policy does.
    { h.pread_fd(fd, out, std::uint64_t{}) } -> std::same_as<Result<std::size_t>>;

    // -- time --------------------------------------------------------------
    // One source of truth for every clock syscall: clock_gettime,
    // gettimeofday, time, and the timestamps in synthesized /proc all read
    // through this, so they cannot disagree with each other.
    { h.clock_now(ClockId{}) }  -> std::same_as<Result<Timespec>>;
    { h.clock_res(ClockId{}) }  -> std::same_as<Result<Timespec>>;
    { h.sleep_for(Timespec{}) } -> std::same_as<Status>;

    // -- entropy -----------------------------------------------------------
    // getrandom(2) / RtlGenRandom. Must be the real host CSPRNG: a guest's
    // ld.so, ASLR and TLS canaries depend on it.
    { h.random_bytes(out) } -> std::same_as<Result<std::size_t>>;
};

// -- host-backed memory ----------------------------------------------------
//
// Kept SEPARATE from HostCalls because the two kernel-less backends manage
// guest memory in genuinely different ways (HVF maps host pages into the
// guest's IPA space; WHP maps into a partition), while the Linux backend does
// not implement it at all -- it forwards mmap to the host kernel, which maps
// directly into the traced child. Folding these into HostCalls would force
// Linux to implement members it has no use for.
template <class T>
concept HostMemory = requires(T h) {
    { h.map(UAddr{}, std::size_t{}, int{}, int{}, Fd{}, std::uint64_t{}) }
        -> std::same_as<Result<UAddr>>;
    { h.unmap(UAddr{}, std::size_t{}) }   -> std::same_as<Status>;
    { h.protect(UAddr{}, std::size_t{}, int{}) } -> std::same_as<Status>;
    { h.set_brk(UAddr{}) }                -> std::same_as<Result<UAddr>>;
};

// A backend that services syscalls WITHOUT a Linux kernel underneath needs
// both halves: the facilities, and memory management. Assert this in such a
// backend's header to get one build error listing what is missing.
template <class T>
concept KernellessHost = HostCalls<T> && HostMemory<T>;

} // namespace lx::runtime
