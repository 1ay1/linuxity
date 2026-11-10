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
// The credential calls are NOT answered here any more. They have one
// authority: the portable dispatcher's per-process credentials, moved only by
// the kernel's rules (abi/creds.hpp) -- so `su nobody` really is nobody, a
// setuid sudo really raises euid, and a backend that answers getuid in-guest
// (darwin) republishes the dispatcher's value (Syscalls::caller_ids) rather
// than a constant. The one exception is a backend with no process model to
// hold credentials (windows): it asks root_credentials_answer() below.
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

// Answer an identity syscall (getpid/gettid/getppid), or nullopt if `sc`
// isn't one.
//
// Returns the raw value for the guest's return register, which is what every
// dispatcher wants: the portable one wraps it in Virtualize, the kernel-less
// backends write it straight to x0/rax.
[[nodiscard]] constexpr std::optional<std::int64_t>
identity_answer(Sysno sc, const TaskIdentity& id) noexcept {
    switch (sc) {
        case Sysno::getpid:  return id.pid;
        case Sysno::gettid:  return id.tid;
        case Sysno::getppid: return id.ppid;
        default: return std::nullopt;
    }
}

// get[e]uid/get[e]gid for a backend with NO process model to hold
// credentials (windows): the guest owns its tree as root. Anything that can
// keep per-process credentials uses the dispatcher's instead (see top).
[[nodiscard]] constexpr std::optional<std::int64_t> root_credentials_answer(Sysno sc) noexcept {
    switch (sc) {
        case Sysno::getuid: case Sysno::geteuid:
        case Sysno::getgid: case Sysno::getegid:
            return 0;
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
// credentials are not identity: the dispatcher (or, with no process model,
// root_credentials_answer) answers them
static_assert(!identity_answer(Sysno::getuid, {7, 7, 1}).has_value());
static_assert(root_credentials_answer(Sysno::geteuid) == 0);
static_assert(!root_credentials_answer(Sysno::getpid).has_value());
static_assert(!identity_answer(Sysno::setuid, {7, 7, 1}).has_value());
// A non-identity syscall must fall through, not be swallowed.
static_assert(!identity_answer(Sysno::read, {7, 7, 1}).has_value());
static_assert(!identity_answer(Sysno::mmap, {7, 7, 1}).has_value());
// pid 1 is a legal answer, but only when the task really IS pid 1 -- this is
// the assertion Windows' hardcoded 1 would fail for any other task.
static_assert(identity_answer(Sysno::getpid, {1, 1, 0}) == 1);
static_assert(identity_answer(Sysno::getpid, {42, 42, 1}) == 42);

} // namespace lx::abi
