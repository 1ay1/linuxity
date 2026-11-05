// linuxity/conform/runner_windows.hpp
//
// The Win32 ProbeRunner: Windows x86-64.
//
// The ONLY conformance code that is Windows-specific, and it is three members
// long. Everything else -- the law, the trace format, both oracles, the
// scenario registry, staleness detection -- is shared with the other three
// targets.
//
// Windows has no Linux kernel, so linux_native() is false and LiveOracle
// cannot be instantiated here: `requires HasLinuxKernel<R>` makes that a
// compile error rather than a runtime surprise. Windows runs RecordedOracle
// against goldens captured on Linux CI, which is real coverage of linuxity's
// own handlers -- the guest side is what we are testing, and that runs here.
#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "linuxity/conform/probe_runner.hpp"

// Win32 is included only in the Windows TU; the header is otherwise inert so
// it can be parsed for layering checks on any host.
#if defined(_WIN32)
#include <windows.h>
#endif

namespace lx::conform {

#if defined(_WIN32)

class WindowsProbeRunner {
public:
    [[nodiscard]] ProbeOutput run(std::string_view path,
                                  std::span<const std::string> args,
                                  std::uint32_t deadline_ms) const {
        ProbeOutput out;

        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof sa;
        sa.bInheritHandle = TRUE;

        HANDLE rd = nullptr;
        HANDLE wr = nullptr;
        if (CreatePipe(&rd, &wr, &sa, 0) == 0) {
            out.exit_code = -1;
            return out;
        }
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

        // One command line, quoted. Probe paths and args are ours (never
        // guest-controlled), but quoting still matters for paths with spaces.
        std::string cmd = quote(path);
        for (const std::string& a : args) cmd += " " + quote(a);

        STARTUPINFOA si{};
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = wr;
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION pi{};
        const BOOL ok =
            CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, 0,
                           nullptr, nullptr, &si, &pi);
        CloseHandle(wr);

        if (ok == 0) {
            CloseHandle(rd);
            out.exit_code = -1;
            return out;
        }

        // Read to EOF: the child holds the only other write end.
        for (;;) {
            char  buf[4096];
            DWORD n = 0;
            if (ReadFile(rd, buf, sizeof buf, &n, nullptr) == 0 || n == 0) break;
            out.stdout_text.append(buf, n);
        }
        CloseHandle(rd);

        if (WaitForSingleObject(pi.hProcess, deadline_ms) == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            out.timed_out = true;
            out.exit_code = -1;
        } else {
            DWORD code = 0;
            GetExitCodeProcess(pi.hProcess, &code);
            out.exit_code = static_cast<int>(code);
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return out;
    }

    [[nodiscard]] std::optional<std::string> read_file(std::string_view path) const {
        const HANDLE h = CreateFileA(std::string{path}.c_str(), GENERIC_READ,
                                     FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                     FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return std::nullopt;

        std::string text;
        for (;;) {
            char  buf[4096];
            DWORD n = 0;
            if (ReadFile(h, buf, sizeof buf, &n, nullptr) == 0 || n == 0) break;
            text.append(buf, n);
        }
        CloseHandle(h);
        return text;
    }

    [[nodiscard]] bool write_file(std::string_view path,
                                  std::string_view text) const {
        const HANDLE h = CreateFileA(std::string{path}.c_str(), GENERIC_WRITE, 0,
                                     nullptr, CREATE_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;

        DWORD written = 0;
        const BOOL ok = WriteFile(h, text.data(),
                                  static_cast<DWORD>(text.size()), &written,
                                  nullptr);
        CloseHandle(h);
        return ok != 0 && written == text.size();
    }

    // -- the capabilities --------------------------------------------------

    // No Linux kernel here. This is the bit that makes LiveOracle
    // uninstantiable on Windows, by concept rather than by #ifdef.
    [[nodiscard]] static bool linux_native() noexcept { return false; }

private:
    [[nodiscard]] static std::string quote(std::string_view s) {
        if (s.find(' ') == std::string_view::npos) return std::string{s};
        return "\"" + std::string{s} + "\"";
    }
};

static_assert(ProbeRunner<WindowsProbeRunner>,
              "the Win32 runner must satisfy the core contract");
static_assert(HasLinuxKernel<WindowsProbeRunner>,
              "linux_native() must be reportable (it answers false here)");

#endif // _WIN32

} // namespace lx::conform
