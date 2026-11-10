// linuxity/host/self_exe.hpp
//
// The path of the running linuxity binary, for re-executing itself (`up` in
// the background, macOS fork children and zygotes). One answer per host:
// /proc/self/exe on Linux, _NSGetExecutablePath on Darwin, GetModuleFileName
// on Windows. It was spelled twice, and the /proc copy fell back to a bare
// "linuxity" on a Mac -- which then exec'd whatever was first on PATH.
#pragma once

#include <string>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <mach-o/dyld.h>
#else
#include <unistd.h>
#endif

namespace lx::host {

[[nodiscard]] inline std::string self_exe() {
#if defined(_WIN32)
    char buf[MAX_PATH];
    const DWORD n = ::GetModuleFileNameA(nullptr, buf, sizeof buf);
    return n > 0 && n < sizeof buf ? std::string(buf, n) : std::string{"linuxity.exe"};
#elif defined(__APPLE__)
    char buf[PATH_MAX];
    std::uint32_t n = sizeof buf;
    if (::_NSGetExecutablePath(buf, &n) != 0) return "linuxity";
    char real[PATH_MAX];
    return ::realpath(buf, real) ? std::string{real} : std::string{buf};
#else
    char buf[4096];
    const ::ssize_t n = ::readlink("/proc/self/exe", buf, sizeof buf - 1);
    return n > 0 ? std::string(buf, static_cast<std::size_t>(n)) : std::string{"linuxity"};
#endif
}

}  // namespace lx::host
