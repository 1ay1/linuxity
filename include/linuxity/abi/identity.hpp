// linuxity/abi/identity.hpp
//
// The guest's identity syscalls, answered once.
//
// WHY THIS FILE EXISTS. getpid/gettid/getppid and the credential calls were
// answered by THREE dispatchers, and all three disagreed:
//
//   abi/syscall.hpp      ids().pid / .tid / .ppid   -- real per-task guest ids
//   darwin/trap.hpp      task_.tid / parent_        -- right, separately derived
//   windows/sys.hpp      hardcoded 1                -- WRONG for every process
//
// Nothing about a hypervisor changes what getpid means. These are pure policy
// over state linuxity already owns -- no host facility is involved at all --
// so three implementations is three chances to be wrong, and Windows took one:
// every process there reports pid 1, so a guest cannot tell its children
// apart and `$!`, `wait`, job control and pgrep are all broken by design.
//
// The credential calls are the same shape. linuxity presents a root-owned
// world (uid 0 is the whole point of the fake-root model), so getuid and
// friends must answer 0 everywhere. A backend that forwarded them raw would
// report the real host uid -- 1000, say -- which has no /etc/passwd entry in
// the guest, and bash greets you with "I have no name!".
#pragma once

#include <cstdint>
#include <optional>

#include "linuxity/abi/sysno.hpp"

namespace lx::abi {

// The trapped task's guest identity. A backend supplies this (the ptrace
// backend from its live task map, HVF from its task struct); the ANSWERS below
// are shared.
struct TaskIdentity {
    std::int32_t pid{1};
    std::int32_t tid{1};
    std::int32_t ppid{0};
};

// Answer an identity or credential syscall, or nullopt if `sc` isn't one.
//
// Returns the raw value for the guest's return register, which is what every
// dispatcher wants: the portable one wraps it in Virtualize, the kernel-less
// backends write it straight to x0/rax.
[[nodiscard]] constexpr std::optional<std::int64_t>
identity_answer(Sysno sc, const TaskIdentity& id) noexcept {
    switch (sc) {
        // -- who am I ------------------------------------------------------
        case Sysno::getpid:  return id.pid;
        case Sysno::gettid:  return id.tid;
        case Sysno::getppid: return id.ppid;

        // -- credentials: a root-owned world -------------------------------
        // Not "pretend to be root" as a convenience -- the overlay's whole
        // model is that the guest owns its tree, and a package manager
        // verifies ownership after every install.
        case Sysno::getuid:  case Sysno::geteuid:
        case Sysno::getgid:  case Sysno::getegid:
            return 0;

        // NOTE setuid/setgid are deliberately NOT here. The portable
        // dispatcher answers them as part of a WIDER credential group
        // (setreuid/setresuid/setgroups/setfsuid...), all of which accept and
        // ignore, and duplicating two of that set here would be the same
        // mistake this file exists to remove. A kernel-less backend wanting
        // them should answer the whole group, not a subset.

        default: return std::nullopt;
    }
}

// NOT HERE: process groups and sessions (getpgrp/getpgid/getsid/setpgid/
// setsid). I wrote a flat_session_answer() for them and then deleted it,
// because the three backends have three DIFFERENT fidelities and each is
// right for its own situation:
//
//   portable  a flat fallback, but FORWARDS when the backend models groups
//             (`requires { mem_.models_process_groups(); }`)
//   darwin    a real pgid/sid table (pids_.pgid_of / set_sid), which is
//             strictly better than flat -- setsid even refuses correctly
//             when the caller is already a group leader
//   windows   flat, because it has no process model at all
//
// Sharing a flat answer would have made darwin WORSE. That is the test for
// this file: an answer belongs here only when every backend should give the
// same one. Identity passes that test; sessions do not.

static_assert(identity_answer(Sysno::getpid, {7, 7, 1}) == 7);
static_assert(identity_answer(Sysno::gettid, {7, 9, 1}) == 9);
static_assert(identity_answer(Sysno::getppid, {7, 7, 1}) == 1);
static_assert(identity_answer(Sysno::getuid, {7, 7, 1}) == 0);
static_assert(identity_answer(Sysno::geteuid, {7, 7, 1}) == 0);
// set*id belong to the dispatcher's wider credential group, not here.
static_assert(!identity_answer(Sysno::setuid, {7, 7, 1}).has_value());
// A non-identity syscall must fall through, not be swallowed.
static_assert(!identity_answer(Sysno::read, {7, 7, 1}).has_value());
static_assert(!identity_answer(Sysno::mmap, {7, 7, 1}).has_value());
// pid 1 is a legal answer, but only when the task really IS pid 1 -- this is
// the assertion Windows' hardcoded 1 would fail for any other task.
static_assert(identity_answer(Sysno::getpid, {1, 1, 0}) == 1);
static_assert(identity_answer(Sysno::getpid, {42, 42, 1}) == 42);

} // namespace lx::abi
