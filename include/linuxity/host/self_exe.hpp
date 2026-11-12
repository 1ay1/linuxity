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
#include <cstdio>
#include <cstdlib>
#include <copyfile.h>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <mach-o/dyld.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <string>

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

// The binary a session should start its OWN processes from.
//
// On macOS every guest process is a fresh linuxity spawned from a path, and
// they hand state to each other in an internal format. Spawning from the
// build output meant a rebuild mid-session started the NEW binary for the
// next command, which can't read the old one's handoff: you had to exit
// before building. So a session pins what it started with: an APFS clone
// (instant, no space until the original changes) named after the source's
// identity, reused by every session of the same build. A process already
// running from a pin keeps using it. Elsewhere: self_exe().
[[nodiscard]] inline const std::string& pinned_self_exe() {
    static const std::string pinned = [] {
        const std::string self = self_exe();
#if defined(__APPLE__)
        const char* tmp = std::getenv("TMPDIR");
        std::string dir = std::string{tmp && *tmp == '/' ? tmp : "/tmp"};
        while (dir.size() > 1 && dir.back() == '/') dir.pop_back();
        dir += "/linuxity-bin";
        if (self.rfind(dir + "/", 0) == 0) return self;            // already pinned
        struct ::stat st{};
        if (::stat(self.c_str(), &st) != 0) return self;
        (void)::mkdir(dir.c_str(), 0700);
        char name[96];
        std::snprintf(name, sizeof name, "/linuxity-%llx-%llx-%llx",
                      static_cast<unsigned long long>(st.st_ino),
                      static_cast<unsigned long long>(st.st_mtimespec.tv_sec),
                      static_cast<unsigned long long>(st.st_size));
        const std::string pin = dir + name;
        if (::access(pin.c_str(), X_OK) == 0) return pin;
        const std::string part = pin + "." + std::to_string(::getpid());
        if (::clonefile(self.c_str(), part.c_str(), 0) != 0 &&
            ::copyfile(self.c_str(), part.c_str(), nullptr, COPYFILE_ALL) != 0)
            return self;                                            // keep working unpinned
        if (::rename(part.c_str(), pin.c_str()) != 0) { (void)::unlink(part.c_str()); return self; }
        // A new build: drop pins no session has started from in a week
        // (each is a private 2 MB copy once its build is gone).
        if (::DIR* d = ::opendir(dir.c_str())) {
            const auto week_ago = ::time(nullptr) - 7 * 24 * 3600;
            while (const ::dirent* e = ::readdir(d)) {
                if (std::strncmp(e->d_name, "linuxity-", 9) != 0) continue;
                const std::string p = dir + "/" + e->d_name;
                struct ::stat ps{};
                if (p != pin && ::stat(p.c_str(), &ps) == 0 && ps.st_atimespec.tv_sec < week_ago)
                    (void)::unlink(p.c_str());
            }
            ::closedir(d);
        }
        return pin;
#else
        return self;
#endif
    }();
    return pinned;
}

// Which build a binary is: its path, size and mtime. A running instance
// reports the one it started from, so the CLI can tell it's out of date
// after linuxity was rebuilt or updated.
[[nodiscard]] inline std::string binary_id(const std::string& path) {
#if defined(_WIN32)
    return path;
#else
    struct ::stat st{};
    if (::stat(path.c_str(), &st) != 0) return path;
    return path + ":" + std::to_string(static_cast<long long>(st.st_size)) + ":" +
           std::to_string(static_cast<long long>(st.st_mtime));
#endif
}

}  // namespace lx::host
