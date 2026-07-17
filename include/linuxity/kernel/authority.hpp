// linuxity/kernel/authority.hpp
//
// The authority boundary, made first-class.
//
//     Linux program → Linux ABI → [ your virtual kernel ] → Darwin/iOS → host kernel
//                                 ──────────────────────── the line ────
//
// Everything ABOVE the line we own completely: if every process, fd, mount
// and futex is one WE created, we can implement its semantics *faithfully*.
// Below the line we are a guest of another kernel that may simply refuse.
//
// The classic mistake is to discover this at runtime, scattering ad-hoc
// EPERM/ENOSYS returns through the subsystems. Instead we lift the
// distinction into the type system: every privileged operation is tagged
// with the *kind of authority* it needs, and the runtime resolves — once,
// explicitly — whether the host can back it. Unbacked authority fails in
// exactly one, well-labelled place.
#pragma once

#include "linuxity/abi/result.hpp"

#include <array>
#include <string_view>

namespace lx::kernel {

// -- Where does an operation's authority come from? ------------------------
enum class Realm {
    // Fully virtual: we own every object involved, so we can be bit-exact
    // with Linux. Never fails for lack of host authority.
    Virtual,
    // Host-delegated: needs a real capability from the layer below. May be
    // present (Linux host) or permanently absent (iOS app sandbox).
    HostDelegated,
};

// -- The concrete authorities a Linux program can demand. ------------------
// Each names a Linux capability/facility and states which realm it lives in.
// The realm is a *property of the facility*, independent of host — it says
// whether faithful emulation is even theoretically possible in-process.
enum class Cap {
    // ---- Virtual realm: we synthesize these completely. -----------------
    VfsNamespace,     // mounts, symlinks, permissions, xattrs (our VFS)
    ProcFs,           // /proc describing OUR processes
    Scheduling,       // scheduling OUR tasks
    SignalsIpc,       // signals, pipes, sockets between OUR processes
    EventPolling,     // epoll, eventfd, timerfd, signalfd
    Futex,            // futex for threads WE control
    PidNamespace,     // PID / mount / user namespaces within our world
    UserNamespace,
    Uname,            // uname, prctl, personality — pure information
    Personality,

    // ---- Host-delegated realm: authority we cannot conjure. -------------
    SysAdmin,         // CAP_SYS_ADMIN over the *host* (administer iOS — no)
    MountRealDevice,  // mount a USB drive the host won't expose
    LoadKernelModule, // nowhere to load it
    RawEthernet,      // raw AF_PACKET / arbitrary netns without host support
    BlockDeviceRaw,   // /dev/mem, real block devices
    KernelTracing,    // ftrace, kprobes, /sys/kernel/debug
};

// -- The realm classification (the load-bearing table). -------------------
[[nodiscard]] constexpr Realm realm_of(Cap c) noexcept {
    switch (c) {
        case Cap::VfsNamespace:
        case Cap::ProcFs:
        case Cap::Scheduling:
        case Cap::SignalsIpc:
        case Cap::EventPolling:
        case Cap::Futex:
        case Cap::PidNamespace:
        case Cap::UserNamespace:
        case Cap::Uname:
        case Cap::Personality:
            return Realm::Virtual;

        case Cap::SysAdmin:
        case Cap::MountRealDevice:
        case Cap::LoadKernelModule:
        case Cap::RawEthernet:
        case Cap::BlockDeviceRaw:
        case Cap::KernelTracing:
            return Realm::HostDelegated;
    }
    return Realm::HostDelegated; // unknown ⇒ assume we lack the authority
}

[[nodiscard]] constexpr bool is_virtual(Cap c) noexcept {
    return realm_of(c) == Realm::Virtual;
}

[[nodiscard]] constexpr std::string_view name(Cap c) noexcept {
    switch (c) {
        case Cap::VfsNamespace:     return "VfsNamespace";
        case Cap::ProcFs:           return "ProcFs";
        case Cap::Scheduling:       return "Scheduling";
        case Cap::SignalsIpc:       return "SignalsIpc";
        case Cap::EventPolling:     return "EventPolling";
        case Cap::Futex:            return "Futex";
        case Cap::PidNamespace:     return "PidNamespace";
        case Cap::UserNamespace:    return "UserNamespace";
        case Cap::Uname:            return "Uname";
        case Cap::Personality:      return "Personality";
        case Cap::SysAdmin:         return "SysAdmin";
        case Cap::MountRealDevice:  return "MountRealDevice";
        case Cap::LoadKernelModule: return "LoadKernelModule";
        case Cap::RawEthernet:      return "RawEthernet";
        case Cap::BlockDeviceRaw:   return "BlockDeviceRaw";
        case Cap::KernelTracing:    return "KernelTracing";
    }
    return "?";
}

// -- The host's grant set --------------------------------------------------
// What the layer BELOW the line actually offers. A Virtual cap is always
// granted (we back it ourselves); a HostDelegated cap is granted only if the
// concrete host advertises it. An iOS grant set has none of the delegated
// bits; a privileged-Linux host may have several.
class Grants {
public:
    // Every host implicitly grants the entire Virtual realm.
    constexpr Grants() = default;

    // Additionally grant specific host-delegated capabilities.
    constexpr Grants& allow(Cap c) noexcept {
        if (realm_of(c) == Realm::HostDelegated)
            delegated_ |= bit(c);
        return *this;
    }

    [[nodiscard]] constexpr bool has(Cap c) const noexcept {
        return is_virtual(c) || (delegated_ & bit(c)) != 0;
    }

    // Resolve a demanded authority to a Result. THE single place an
    // unbacked capability turns into an errno — no scattered EPERMs.
    [[nodiscard]] constexpr Status require(Cap c) const noexcept {
        if (has(c)) return ok();
        // Faithful Linux distinction: a facility that structurally cannot
        // exist here reads as ENOSYS; one gated on privilege reads as EPERM.
        return err(structurally_absent(c) ? Errno::enosys : Errno::eperm);
    }

private:
    static constexpr std::uint32_t bit(Cap c) noexcept {
        return std::uint32_t{1} << static_cast<unsigned>(c);
    }
    // A subset that Linux itself would report as "not implemented here"
    // rather than "not permitted".
    static constexpr bool structurally_absent(Cap c) noexcept {
        return c == Cap::LoadKernelModule || c == Cap::KernelTracing;
    }
    std::uint32_t delegated_{0};
};

// -- Ready-made host profiles ---------------------------------------------
// The iOS app sandbox: pure virtual world, zero delegated authority.
[[nodiscard]] constexpr Grants ios_sandbox() noexcept { return Grants{}; }

// A privileged Linux host can pass several delegated caps straight through.
[[nodiscard]] constexpr Grants privileged_linux() noexcept {
    return Grants{}
        .allow(Cap::MountRealDevice)
        .allow(Cap::RawEthernet)
        .allow(Cap::BlockDeviceRaw)
        .allow(Cap::SysAdmin);
}

} // namespace lx::kernel
