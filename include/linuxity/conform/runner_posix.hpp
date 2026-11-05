// linuxity/conform/runner_posix.hpp
//
// The POSIX ProbeRunner: Linux arm64, Linux x86-64 and macOS arm64.
//
// THREE of the four targets share this file, because the host facility they
// need (spawn a process, read a file, write a file) is the same POSIX API on
// all three. What differs between Linux and macOS is not how to spawn a
// process -- it is whether a LINUX KERNEL is underneath, and that is reported
// by linux_native() as a value rather than branched on with #ifdef at each
// use site.
//
// So the host axis collapses to one bit here, and the oracles above never see
// it: LiveOracle is constrained on HasLinuxKernel, so asking for one on macOS
// is a compile error, and macOS gets RecordedOracle instead.
#pragma once

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "linuxity/conform/probe_runner.hpp"

namespace lx::conform {

class PosixProbeRunner {
public:
    [[nodiscard]] ProbeOutput run(std::string_view path,
                                  std::span<const std::string> args,
                                  std::uint32_t deadline_ms) const {
        ProbeOutput out;

        int fds[2];
        if (::pipe(fds) != 0) {
            out.exit_code = -1;
            return out;
        }

        // argv must outlive the spawn, and posix_spawn wants char* const*.
        std::string prog{path};
        std::vector<std::string> owned;
        owned.push_back(prog);
        for (const std::string& a : args) owned.push_back(a);

        std::vector<char*> argv;
        argv.reserve(owned.size() + 1);
        for (std::string& s : owned) argv.push_back(s.data());
        argv.push_back(nullptr);

        // Child's stdout -> the pipe; stderr kept off the trace so a warning
        // cannot corrupt a golden.
        posix_spawn_file_actions_t acts;
        ::posix_spawn_file_actions_init(&acts);
        ::posix_spawn_file_actions_adddup2(&acts, fds[1], STDOUT_FILENO);
        ::posix_spawn_file_actions_addclose(&acts, fds[0]);

        ::pid_t pid = -1;
        const int rc = ::posix_spawn(&pid, prog.c_str(), &acts, nullptr,
                                     argv.data(), ::environ);
        ::posix_spawn_file_actions_destroy(&acts);
        ::close(fds[1]);

        if (rc != 0) {
            ::close(fds[0]);
            out.exit_code = -1;
            return out;
        }

        // Read to EOF. The child holds the only other write end, so EOF means
        // it exited or closed stdout.
        std::array<char, 4096> buf{};
        for (;;) {
            const ::ssize_t n = ::read(fds[0], buf.data(), buf.size());
            if (n > 0) {
                out.stdout_text.append(buf.data(), static_cast<std::size_t>(n));
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        ::close(fds[0]);

        // The deadline. A probe that has closed stdout but not exited still
        // gets killed, so a hung child can never wedge CI.
        out.timed_out = !reap_within(pid, deadline_ms, out.exit_code);
        return out;
    }

    [[nodiscard]] std::optional<std::string> read_file(std::string_view path) const {
        std::FILE* f = std::fopen(std::string{path}.c_str(), "rb");
        if (f == nullptr) return std::nullopt;

        std::string text;
        std::array<char, 4096> buf{};
        for (;;) {
            const std::size_t n = std::fread(buf.data(), 1, buf.size(), f);
            text.append(buf.data(), n);
            if (n < buf.size()) break;
        }
        std::fclose(f);
        return text;
    }

    [[nodiscard]] bool write_file(std::string_view path,
                                  std::string_view text) const {
        std::FILE* f = std::fopen(std::string{path}.c_str(), "wb");
        if (f == nullptr) return false;
        const std::size_t n = std::fwrite(text.data(), 1, text.size(), f);
        return std::fclose(f) == 0 && n == text.size();
    }

    // -- the capabilities --------------------------------------------------

    // The one bit that distinguishes Linux from macOS here. A VALUE, not an
    // #ifdef at each use: the oracles stay host-agnostic and the constraint
    // is checked once, by the concept.
    [[nodiscard]] bool linux_native() const {
#if defined(__linux__)
        return true;
#else
        return false;
#endif
    }

    [[nodiscard]] std::string kernel_release() const {
        ::utsname u{};
        if (::uname(&u) != 0) return "unknown";
        return std::string{u.sysname} + " " + u.release;
    }

private:
    // Wait for the child, killing it past the deadline. Returns false if it
    // had to be killed.
    [[nodiscard]] static bool reap_within(::pid_t pid, std::uint32_t deadline_ms,
                                          int& exit_code) {
        constexpr std::uint32_t slice_ms = 10;
        for (std::uint32_t waited = 0; waited < deadline_ms; waited += slice_ms) {
            int status = 0;
            const ::pid_t r = ::waitpid(pid, &status, WNOHANG);
            if (r == pid) {
                exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
                return true;
            }
            if (r < 0) {
                exit_code = -1;
                return true;  // already reaped; not a timeout
            }
            ::usleep(slice_ms * 1000);
        }

        ::kill(pid, SIGKILL);
        int status = 0;
        ::waitpid(pid, &status, 0);
        exit_code = -1;
        return false;
    }
};

static_assert(ProbeRunner<PosixProbeRunner>,
              "the POSIX runner must satisfy the core contract");
static_assert(KnowsKernelRelease<PosixProbeRunner>);
static_assert(HasLinuxKernel<PosixProbeRunner>,
              "linux_native() is how the oracles tell Linux from macOS");

} // namespace lx::conform
