// linuxity/conform/platform.hpp
//
// The PLATFORM axis, which is orthogonal to both the host and the ABI.
//
// Three different questions, and conflating any two of them corrupts goldens:
//
//   HOST      -- who services the syscall? (probe_runner.hpp / host.hpp)
//   ARCH      -- which Linux ABI is the guest speaking? (arch.hpp)
//   PLATFORM  -- whose POLICY is the kernel enforcing? (this file)
//
// WHY ARCH IS NOT ENOUGH. Android and a desktop distro can be the SAME kernel
// ABI -- aarch64, same syscall table, same struct layouts -- and still disagree
// about what a syscall RETURNS. Android ships an SELinux policy that denies
// the `shell` domain ioctls a desktop allows, measured on a Pixel (bluejay,
// Android 17, kernel 6.1 GKI, domain u:r:shell:s0):
//
//     ioctl(pty_slave, TCGETS)    -> ok on both
//     ioctl(pty_slave, TCGETS2)   -> ok on desktop, EACCES on Android
//     ioctl(pty_slave, TIOCGSID)  -> ok on desktop, EACCES on Android
//     ioctl(pty_slave, TIOCNOTTY) -> ok on desktop, EACCES on Android
//
// Those are not linuxity bugs and not ABI differences -- they are the host
// platform's policy, and they are exactly the behaviour a guest must survive.
// Recording them into tests/goldens/aarch64/ would make a desktop arm64 run
// fail against Android's denials (or worse, the reverse: a desktop recording
// would tell us Android "should" allow TCGETS2 and hide the real downgrade
// path). So the platform is part of a golden's IDENTITY, the same way the arch
// already is.
//
// WHY A SEPARATE AXIS AND NOT A NEW `Arch` ARM. abi::Arch answers "which
// syscall table", and Android's is identical to any other aarch64 Linux.
// Adding Arch::android would lie about that, and would make arch_has() wrong.
// Keeping them separate means the product stays additive: N arches x M
// platforms is one tag each, not a new enum arm per combination.
#pragma once

#include <cstdint>
#include <string_view>

namespace lx::conform {

// The platform whose kernel policy a golden was recorded under.
//
// `linux_` is the default: an ordinary distro kernel with no extra denial
// layer. `android` carries the SELinux-confined behaviour above. The names
// are deliberately coarse -- this axis is about POLICY FAMILIES, not distro
// versions, because a Debian and an Arch kernel answer these identically
// while Android does not.
enum class Platform : std::uint8_t {
    linux_,
    android,
};

// Which platform is this build targeting?
//
// Bionic defines __ANDROID__, so an NDK build tags itself automatically and
// a cross-glibc build of the same arch does not -- no configuration needed,
// and no way to record an Android golden from a non-Android toolchain by
// accident.
[[nodiscard]] constexpr Platform host_platform() noexcept {
#if defined(__ANDROID__)
    return Platform::android;
#else
    return Platform::linux_;
#endif
}

// Stable, filesystem-safe names. These appear in golden paths, so renaming
// one invalidates every recording under it -- correct if the meaning changed,
// and a reason not to churn them.
//
// Platform::linux_ renders as the EMPTY string, so a desktop golden keeps its
// existing `aarch64/foo.trace` path. That is not cosmetic: it means adding
// this axis does not re-record or move a single committed golden, so the
// change is provably behaviour-preserving for every host that already worked.
[[nodiscard]] constexpr std::string_view platform_name(Platform p) noexcept {
    switch (p) {
        case Platform::linux_:  return "";
        case Platform::android: return "android";
    }
    return "unknown-platform";
}

// The path component for a platform, including the separator, so callers
// concatenate without special-casing the empty default.
[[nodiscard]] constexpr std::string_view platform_prefix(Platform p) noexcept {
    switch (p) {
        case Platform::linux_:  return "";
        case Platform::android: return "android-";
    }
    return "unknown-platform-";
}

static_assert(platform_name(Platform::linux_).empty(),
              "the desktop platform must not change existing golden paths");
static_assert(!platform_name(Platform::android).empty(),
              "Android goldens must live under their own identity");

} // namespace lx::conform
