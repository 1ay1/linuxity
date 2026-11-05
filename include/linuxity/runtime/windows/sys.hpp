// linuxity/runtime/windows/sys.hpp
//
// The syscall emulation surface: Linux syscalls served against Win32.
//
// On the Linux backend most syscalls are FORWARDED to the host kernel, which
// already implements them. Here there is no host Linux kernel, so "forward"
// means "emulate", and this file is that emulation. It is the Windows
// counterpart of hvf_sys/hvf_fd/hvf_proc on Darwin, and the reason the
// kernel-less backends carry more weight than ptrace.
//
// SCOPE, stated honestly: this covers the syscalls a dynamically linked
// program needs to START and do file I/O -- which is what makes `ld.so` and
// a real libc work, and is the difference between "traps a syscall" and
// "runs a distro binary". It does NOT cover threads, signals, sockets, or
// fork/exec; those route to the portable kernel in the full runtime and are
// explicitly ENOSYS here rather than being half-implemented.
//
// PATH TRANSLATION. Every guest path is resolved through the rootfs before
// it reaches Win32. Unlike the ptrace backend there is NO TOCTOU window: the
// guest is stopped and we read the path out of guest memory ourselves, so
// nothing can swap it between our check and our use.
#pragma once

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))

#include "linuxity/abi/identity.hpp"
#include "linuxity/abi/wire/at_flags.hpp"
#include "linuxity/abi/wire/dirent64.hpp"
#include "linuxity/abi/wire/open_flags.hpp"
#include "linuxity/abi/wire/path.hpp"
#include "linuxity/runtime/windows/fd.hpp"
#include "linuxity/runtime/windows/mm.hpp"
#include "linuxity/runtime/windows/trap.hpp"
#include "linuxity/runtime/windows/vm.hpp"
#include "linuxity/runtime/windows/win32.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace lx::runtime {

// The x86-64 Linux syscall numbers this layer serves. Spelled out rather
// than pulled from sysno.hpp so the switch below reads as the ABI does.
enum : std::uint64_t {
    SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_close = 3,
    SYS_stat = 4, SYS_fstat = 5, SYS_lstat = 6, SYS_poll = 7,
    SYS_lseek = 8, SYS_mmap = 9, SYS_mprotect = 10, SYS_munmap = 11,
    SYS_brk = 12, SYS_rt_sigaction = 13, SYS_rt_sigprocmask = 14,
    SYS_ioctl = 16, SYS_pread64 = 17, SYS_pwrite64 = 18,
    SYS_readv = 19, SYS_writev = 20, SYS_access = 21,
    SYS_dup = 32, SYS_dup2 = 33, SYS_nanosleep = 35,
    SYS_getpid = 39, SYS_sendfile = 40,
    SYS_exit = 60, SYS_uname = 63, SYS_fcntl = 72, SYS_getdents = 78,
    SYS_getcwd = 79, SYS_chdir = 80, SYS_rename = 82, SYS_mkdir = 83,
    SYS_rmdir = 84, SYS_creat = 85, SYS_unlink = 87, SYS_readlink = 89,
    SYS_chmod = 90, SYS_fchmod = 91, SYS_umask = 95,
    SYS_gettimeofday = 96, SYS_getrlimit = 97, SYS_getuid = 102,
    SYS_getgid = 104, SYS_setuid = 105, SYS_setgid = 106,
    SYS_geteuid = 107, SYS_getegid = 108, SYS_setpgid = 109,
    SYS_getppid = 110, SYS_getpgrp = 111, SYS_setsid = 112,
    SYS_sigaltstack = 131, SYS_statfs = 137, SYS_fstatfs = 138,
    SYS_arch_prctl = 158, SYS_gettid = 186,
    SYS_futex = 202, SYS_sched_getaffinity = 204,
    SYS_getdents64 = 217,
    SYS_set_tid_address = 218, SYS_clock_gettime = 228,
    SYS_clock_getres = 229, SYS_exit_group = 231,
    SYS_tgkill = 234, SYS_openat = 257, SYS_newfstatat = 262,
    SYS_unlinkat = 263, SYS_readlinkat = 267, SYS_faccessat = 269,
    SYS_ppoll = 271, SYS_set_robust_list = 273,
    SYS_prlimit64 = 302, SYS_getrandom = 318,
    SYS_rseq = 334, SYS_faccessat2 = 439,
    SYS_clock_gettime64 = 403,
};

// The result of servicing one syscall: the value to put in rax, plus whether
// the guest should stop.
struct SysResult {
    std::int64_t ret{0};
    bool exited{false};
    int exit_status{0};
};

// Serves guest syscalls against Win32 + the rootfs.
class WhpSys {
public:
    WhpSys(WhpMachine& vm, WhpMm& mm, FdTable& fds, std::string rootfs)
        : vm_{vm}, mm_{mm}, fds_{fds}, root_{std::move(rootfs)} {
        if (!root_.empty()) {
            // Normalize: no trailing slash, so joins are unambiguous.
            while (root_.size() > 1 &&
                   (root_.back() == '/' || root_.back() == '\\'))
                root_.pop_back();
        }
        cwd_ = "/";
    }

    // Translate a guest path to a host path under the rootfs.
    //
    // Containment is enforced by resolving ".." LEXICALLY before joining: a
    // guest path of "/../../etc/passwd" must not escape the rootfs. Doing it
    // lexically (rather than with the host's realpath) is deliberate -- the
    // guest's view of symlinks is its own, and asking Win32 to resolve the
    // path would leak host structure into the answer.
    [[nodiscard]] std::string host_path(std::string_view guest) const {
        std::string p = guest.empty() ? cwd_ : std::string{guest};
        if (p.front() != '/') {
            p = cwd_ == "/" ? "/" + p : cwd_ + "/" + p;
        }
        // Resolve . and .. against the guest root.
        std::vector<std::string> parts;
        std::size_t i = 0;
        while (i < p.size()) {
            while (i < p.size() && p[i] == '/') ++i;
            std::size_t j = i;
            while (j < p.size() && p[j] != '/') ++j;
            if (j > i) {
                std::string seg = p.substr(i, j - i);
                if (seg == ".") {
                    // skip
                } else if (seg == "..") {
                    if (!parts.empty()) parts.pop_back();   // clamps at root
                } else {
                    parts.push_back(std::move(seg));
                }
            }
            i = j;
        }
        std::string out = root_;
        for (const auto& seg : parts) { out += '/'; out += seg; }
        if (parts.empty() && root_.empty()) out = "/";
        return out;
    }

    // Service one trapped syscall.
    [[nodiscard]] SysResult service(const TrapFrame& f) {
        const std::uint64_t nr = f.regs.nr;
        const auto& a = f.regs.arg;
        auto mem = vm_.mem();

        switch (nr) {
            // -- process lifetime -----------------------------------------
            case SYS_exit:
            case SYS_exit_group:
                return SysResult{0, true, int(a[0] & 0xff)};

            // -- memory ----------------------------------------------------
            case SYS_brk:
                return ret(std::int64_t(mm_.do_brk(a[0])));
            case SYS_mmap: {
                HANDLE h = nullptr;
                if (!(a[3] & kMapAnonymous) && std::int64_t(a[4]) >= 0) {
                    auto fh = fds_.host(int(a[4]));
                    if (!fh) return ret(-win32::LBADF);
                    h = *fh;
                }
                return ret(mm_.do_mmap(a[0], a[1], a[2], a[3], h, a[5]));
            }
            case SYS_munmap:
                return ret(mm_.do_munmap(a[0], a[1]));
            case SYS_mprotect:
                return ret(mm_.do_mprotect(a[0], a[1], a[2]));

            // -- file I/O --------------------------------------------------
            case SYS_openat:
            case SYS_open: {
                const bool at = nr == SYS_openat;
                const std::uint64_t pathp = at ? a[1] : a[0];
                const std::uint64_t flags = at ? a[2] : a[1];
                std::string gp = mem.cstr(pathp);
                if (gp.empty()) return ret(-win32::LFAULT);
                // openat with a dirfd and a RELATIVE path resolves against
                // that fd's path, which is why the fd table remembers it.
                if (at && !gp.empty() && gp.front() != '/' &&
                    std::int64_t(a[0]) >= 0) {
                    const std::string& base = fds_.path(int(a[0]));
                    if (!base.empty()) gp = base + "/" + gp;
                }
                return ret(do_open(gp, flags));
            }
            case SYS_close:
                return ret(fds_.close(int(a[0])));
            case SYS_read: {
                auto h = fds_.host(int(a[0]));
                if (!h) return ret(-win32::LBADF);
                if (a[2] == 0) return ret(0);
                std::vector<std::byte> buf(static_cast<std::size_t>(
                    std::min<std::uint64_t>(a[2], 1u << 20)));
                DWORD got = 0;
                if (!::ReadFile(*h, buf.data(), DWORD(buf.size()), &got, nullptr))
                    return ret(win32::fail());
                if (got == 0) return ret(0);           // EOF
                const std::size_t wrote =
                    mem.copy_out(a[1], std::span<const std::byte>{buf.data(), got});
                if (wrote != got) return ret(-win32::LFAULT);
                return ret(std::int64_t(got));
            }
            case SYS_write: {
                auto h = fds_.host(int(a[0]));
                if (!h) return ret(-win32::LBADF);
                if (a[2] == 0) return ret(0);
                std::vector<std::byte> buf(static_cast<std::size_t>(
                    std::min<std::uint64_t>(a[2], 1u << 20)));
                const std::size_t n = mem.copy_in(a[1], buf);
                if (n == 0) return ret(-win32::LFAULT);
                return ret(write_handle(int(a[0]), *h, buf.data(), n));
            }
            case SYS_writev: {
                auto h = fds_.host(int(a[0]));
                if (!h) return ret(-win32::LBADF);
                std::int64_t total = 0;
                for (std::uint64_t k = 0; k < a[2]; ++k) {
                    GuestIovec iov{};
                    if (!mem.get(a[1] + k * sizeof(GuestIovec), iov))
                        return ret(-win32::LFAULT);
                    if (iov.len == 0) continue;
                    std::vector<std::byte> buf(static_cast<std::size_t>(iov.len), std::byte{0});
                    const std::size_t n = mem.copy_in(iov.base, buf);
                    if (n == 0) break;
                    const std::int64_t w =
                        write_handle(int(a[0]), *h, buf.data(), n);
                    if (w < 0) return ret(total ? total : w);
                    total += w;
                    if (std::uint64_t(w) < iov.len) break;   // short write
                }
                return ret(total);
            }
            case SYS_readv: {
                auto h = fds_.host(int(a[0]));
                if (!h) return ret(-win32::LBADF);
                std::int64_t total = 0;
                for (std::uint64_t k = 0; k < a[2]; ++k) {
                    GuestIovec iov{};
                    if (!mem.get(a[1] + k * sizeof(GuestIovec), iov))
                        return ret(-win32::LFAULT);
                    if (iov.len == 0) continue;
                    std::vector<std::byte> buf(static_cast<std::size_t>(iov.len), std::byte{0});
                    DWORD got = 0;
                    if (!::ReadFile(*h, buf.data(), DWORD(buf.size()), &got,
                                    nullptr))
                        return ret(total ? total : win32::fail());
                    if (got == 0) break;
                    mem.copy_out(iov.base,
                                 std::span<const std::byte>{buf.data(), got});
                    total += got;
                    if (got < iov.len) break;
                }
                return ret(total);
            }
            case SYS_pread64: {
                auto h = fds_.host(int(a[0]));
                if (!h) return ret(-win32::LBADF);
                // pread must NOT disturb the file position, so save/restore
                // it -- Win32 has no positional read for synchronous handles.
                LARGE_INTEGER zero{}, saved{};
                if (!::SetFilePointerEx(*h, zero, &saved, FILE_CURRENT))
                    return ret(win32::fail());
                LARGE_INTEGER to{};
                to.QuadPart = LONGLONG(a[3]);
                if (!::SetFilePointerEx(*h, to, nullptr, FILE_BEGIN))
                    return ret(win32::fail());
                std::vector<std::byte> buf(static_cast<std::size_t>(a[2]), std::byte{0});
                DWORD got = 0;
                const BOOL okread =
                    ::ReadFile(*h, buf.data(), DWORD(buf.size()), &got, nullptr);
                ::SetFilePointerEx(*h, saved, nullptr, FILE_BEGIN);
                if (!okread) return ret(win32::fail());
                if (got) mem.copy_out(a[1],
                    std::span<const std::byte>{buf.data(), got});
                return ret(std::int64_t(got));
            }
            case SYS_lseek: {
                auto h = fds_.host(int(a[0]));
                if (!h) return ret(-win32::LBADF);
                DWORD from = FILE_BEGIN;
                if (a[2] == 1) from = FILE_CURRENT;
                else if (a[2] == 2) from = FILE_END;
                else if (a[2] != 0) return ret(-win32::LINVAL);
                LARGE_INTEGER to{}, now{};
                to.QuadPart = LONGLONG(a[1]);
                if (!::SetFilePointerEx(*h, to, &now, from))
                    return ret(win32::fail());
                return ret(now.QuadPart);
            }

            // -- metadata --------------------------------------------------
            case SYS_fstat: {
                auto h = fds_.host(int(a[0]));
                if (!h) return ret(-win32::LBADF);
                BY_HANDLE_FILE_INFORMATION bhfi{};
                if (!::GetFileInformationByHandle(*h, &bhfi)) {
                    // A character device (our dup'd stdio) has no file info;
                    // report it as a chardev so libc line-buffers correctly.
                    win32::LinuxStat st{};
                    st.st_mode = win32::kSIfchr | 0620;
                    st.st_nlink = 1;
                    st.st_blksize = 1024;
                    return ret(mem.put(a[1], st) ? 0 : -win32::LFAULT);
                }
                auto st = win32::stat_from_win(bhfi);
                return ret(mem.put(a[1], st) ? 0 : -win32::LFAULT);
            }
            case SYS_stat:
            case SYS_lstat: {
                std::string gp = mem.cstr(a[0]);
                return ret(stat_path(gp, a[1]));
            }
            case SYS_newfstatat: {
                std::string gp = mem.cstr(a[1]);
                if (gp.empty() && std::int64_t(a[0]) >= 0) {
                    // AT_EMPTY_PATH: stat the fd itself.
                    auto h = fds_.host(int(a[0]));
                    if (!h) return ret(-win32::LBADF);
                    BY_HANDLE_FILE_INFORMATION bhfi{};
                    if (!::GetFileInformationByHandle(*h, &bhfi))
                        return ret(win32::fail());
                    auto st = win32::stat_from_win(bhfi);
                    return ret(mem.put(a[2], st) ? 0 : -win32::LFAULT);
                }
                if (!gp.empty() && gp.front() != '/' &&
                    std::int64_t(a[0]) >= 0) {
                    const std::string& base = fds_.path(int(a[0]));
                    if (!base.empty()) gp = base + "/" + gp;
                }
                return ret(stat_path(gp, a[2]));
            }
            case SYS_access:
            case SYS_faccessat:
            case SYS_faccessat2: {
                const std::uint64_t pathp = nr == SYS_access ? a[0] : a[1];
                std::string gp = mem.cstr(pathp);
                const auto w = win32::to_win_path(host_path(gp));
                return ret(::GetFileAttributesW(w.c_str()) != INVALID_FILE_ATTRIBUTES
                               ? 0 : -win32::LNOENT);
            }
            case SYS_readlink:
            case SYS_readlinkat:
                // No POSIX symlinks on Win32; EINVAL is what readlink(2)
                // returns for a non-symlink, so this is correct rather than
                // a stub. (ld.so probes /proc/self/exe with this and copes.)
                return ret(-win32::LINVAL);

            // -- directories -----------------------------------------------
            case SYS_getcwd: {
                const std::string& c = cwd_;
                if (a[1] < c.size() + 1) return ret(-win32::LRANGE);
                if (mem.copy_out(a[0], std::span<const std::byte>{
                        reinterpret_cast<const std::byte*>(c.data()),
                        c.size() + 1}) != c.size() + 1)
                    return ret(-win32::LFAULT);
                return ret(std::int64_t(c.size() + 1));
            }
            case SYS_chdir: {
                std::string gp = mem.cstr(a[0]);
                const auto w = win32::to_win_path(host_path(gp));
                const DWORD at = ::GetFileAttributesW(w.c_str());
                if (at == INVALID_FILE_ATTRIBUTES) return ret(-win32::LNOENT);
                if (!(at & FILE_ATTRIBUTE_DIRECTORY)) return ret(-win32::LNOTDIR);
                cwd_ = normalize_guest(gp);
                return ret(0);
            }
            case SYS_mkdir: {
                std::string gp = mem.cstr(a[0]);
                const auto w = win32::to_win_path(host_path(gp));
                return ret(::CreateDirectoryW(w.c_str(), nullptr)
                               ? 0 : win32::fail());
            }
            case SYS_rmdir: {
                std::string gp = mem.cstr(a[0]);
                const auto w = win32::to_win_path(host_path(gp));
                return ret(::RemoveDirectoryW(w.c_str()) ? 0 : win32::fail());
            }
            case SYS_unlink:
            case SYS_unlinkat: {
                const std::uint64_t pathp = nr == SYS_unlink ? a[0] : a[1];
                std::string gp = mem.cstr(pathp);
                const auto w = win32::to_win_path(host_path(gp));
                // AT_REMOVEDIR
                if (nr == SYS_unlinkat && abi::wire::has_at(a[2], abi::wire::AtFlag::removedir))
                    return ret(::RemoveDirectoryW(w.c_str()) ? 0 : win32::fail());
                return ret(::DeleteFileW(w.c_str()) ? 0 : win32::fail());
            }
            case SYS_rename: {
                const auto from = win32::to_win_path(host_path(mem.cstr(a[0])));
                const auto to   = win32::to_win_path(host_path(mem.cstr(a[1])));
                // MOVEFILE_REPLACE_EXISTING, because POSIX rename() silently
                // replaces the destination and programs depend on that for
                // atomic file updates.
                return ret(::MoveFileExW(from.c_str(), to.c_str(),
                                         MOVEFILE_REPLACE_EXISTING)
                               ? 0 : win32::fail());
            }
            case SYS_getdents:
            case SYS_getdents64:
                return ret(do_getdents(int(a[0]), a[1], a[2]));

            // -- descriptors -----------------------------------------------
            case SYS_dup:
                return ret(fds_.dup(int(a[0]), std::nullopt, false));
            case SYS_dup2:
                return ret(fds_.dup(int(a[0]), int(a[1]), false));
            case SYS_fcntl: {
                if (!fds_.host(int(a[0]))) return ret(-win32::LBADF);
                switch (a[1]) {
                    case 0:  return ret(fds_.dup(int(a[0]), std::nullopt, false)); // F_DUPFD
                    case 1:  return ret(fds_.cloexec(int(a[0])) ? 1 : 0);          // F_GETFD
                    case 2:  fds_.set_cloexec(int(a[0]), (a[2] & 1) != 0);         // F_SETFD
                             return ret(0);
                    case 3:  return ret(fds_.is_append(int(a[0])) ? 0x400 : 0);    // F_GETFL
                    case 4:  fds_.set_append(int(a[0]), (a[2] & abi::wire::bits(abi::wire::OpenFlag::append)) != 0);      // F_SETFL
                             return ret(0);
                    default: return ret(0);   // locks etc.: succeed benignly
                }
            }
            case SYS_ioctl: {
                if (!fds_.host(int(a[0]))) return ret(-win32::LBADF);
                // TCGETS on a tty must SUCCEED and on a pipe must fail with
                // ENOTTY -- that is precisely how libc decides to line-buffer
                // vs block-buffer, so a blanket 0 here reorders all output.
                if (a[1] == 0x5401 /*TCGETS*/)
                    return ret(fds_.is_tty(int(a[0])) ? 0 : -win32::LNOTTY);
                if (a[1] == 0x5413 /*TIOCGWINSZ*/) {
                    if (!fds_.is_tty(int(a[0]))) return ret(-win32::LNOTTY);
                    struct { std::uint16_t row, col, xp, yp; } ws{24, 80, 0, 0};
                    CONSOLE_SCREEN_BUFFER_INFO csbi{};
                    if (::GetConsoleScreenBufferInfo(
                            ::GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
                        ws.col = std::uint16_t(csbi.srWindow.Right -
                                               csbi.srWindow.Left + 1);
                        ws.row = std::uint16_t(csbi.srWindow.Bottom -
                                               csbi.srWindow.Top + 1);
                    }
                    return ret(mem.put(a[2], ws) ? 0 : -win32::LFAULT);
                }
                return ret(-win32::LNOTTY);
            }

            // -- identity (virtualized: the guest believes it is root) -----
            //
            // The ANSWERS come from abi/identity.hpp, shared with the portable
            // dispatcher and the HVF backend, so the three cannot drift.
            //
            // The ids themselves really are {1,1,0} here, and that is correct
            // rather than a stub: this backend implements no clone/fork and
            // has no task table, so there is exactly one guest process. If it
            // ever grows one, THIS is the line that must start reporting real
            // per-task ids -- the shared helper already does, so only the
            // identity source changes, not the answers.
            case SYS_getuid: case SYS_geteuid:
            case SYS_getgid: case SYS_getegid:
            case SYS_getpid: case SYS_getppid: case SYS_gettid:
                if (auto a = abi::identity_answer(
                        abi::decode(abi::Arch::x86_64, nr),
                        abi::TaskIdentity{1, 1, 0}))
                    return ret(*a);
                return ret(-win32::LNOSYS);
            case SYS_setuid: case SYS_setgid:
                return ret(0);               // compatibility shim: say yes
            case SYS_getpgrp:
                return ret(1);
            case SYS_setpgid: case SYS_setsid:
                return ret(0);
            case SYS_umask:
                return ret(0022);

            // -- time -------------------------------------------------------
            case SYS_clock_gettime:
            case SYS_clock_gettime64: {
                FILETIME ft{};
                ::GetSystemTimeAsFileTime(&ft);
                auto t = win32::from_filetime(ft);
                struct { std::int64_t sec, nsec; } ts{t.sec, t.nsec};
                return ret(mem.put(a[1], ts) ? 0 : -win32::LFAULT);
            }
            case SYS_gettimeofday: {
                FILETIME ft{};
                ::GetSystemTimeAsFileTime(&ft);
                auto t = win32::from_filetime(ft);
                struct { std::int64_t sec, usec; } tv{t.sec, t.nsec / 1000};
                return ret(mem.put(a[0], tv) ? 0 : -win32::LFAULT);
            }
            case SYS_clock_getres: {
                struct { std::int64_t sec, nsec; } ts{0, 100};
                return ret(mem.put(a[1], ts) ? 0 : -win32::LFAULT);
            }
            case SYS_nanosleep: {
                struct { std::int64_t sec, nsec; } ts{};
                if (!mem.get(a[0], ts)) return ret(-win32::LFAULT);
                ::Sleep(DWORD(ts.sec * 1000 + ts.nsec / 1'000'000));
                return ret(0);
            }

            // -- misc that libc startup needs ------------------------------
            case SYS_uname:
                return ret(do_uname(a[0]));
            case SYS_getrandom: {
                std::vector<std::byte> buf(static_cast<std::size_t>(a[1]), std::byte{0});
                if (!whp_random_bytes(buf.data(), unsigned(buf.size())))
                    return ret(-win32::LIO);
                mem.copy_out(a[0], buf);
                return ret(std::int64_t(a[1]));
            }
            case SYS_arch_prctl: {
                // ARCH_SET_FS is how glibc installs the thread pointer, and
                // it MUST work: every TLS access (errno included) goes
                // through %fs. Writing FS_BASE is the whole implementation.
                constexpr std::uint64_t kArchSetFs = 0x1002;
                constexpr std::uint64_t kArchGetFs = 0x1003;
                if (a[0] == kArchSetFs)
                    return ret(set_fs_base(a[1]) ? 0 : -win32::LINVAL);
                if (a[0] == kArchGetFs) {
                    std::uint64_t base = 0;
                    if (!get_fs_base(base)) return ret(-win32::LINVAL);
                    return ret(mem.put(a[1], base) ? 0 : -win32::LFAULT);
                }
                return ret(-win32::LINVAL);
            }
            case SYS_set_tid_address:
                return ret(1);
            case SYS_set_robust_list:
            case SYS_rseq:
                // Optional kernel features; libc proceeds without them. The
                // honest answer is ENOSYS, and glibc handles it.
                return ret(-win32::LNOSYS);
            case SYS_rt_sigaction:
            case SYS_rt_sigprocmask:
            case SYS_sigaltstack:
                // Accepted but inert: no signal delivery on this backend yet,
                // so recording dispositions we cannot honor would be a lie.
                // Succeeding lets libc finish initializing.
                return ret(0);
            case SYS_sched_getaffinity: {
                // One CPU. Returning the mask size is what glibc expects.
                std::uint64_t mask = 1;
                if (a[1] >= 8) mem.put(a[2], mask);
                return ret(8);
            }
            case SYS_getrlimit:
            case SYS_prlimit64: {
                const std::uint64_t outp = nr == SYS_getrlimit ? a[1] : a[3];
                if (outp) {
                    struct { std::uint64_t cur, max; } rl{
                        FdTable::kMaxFds, FdTable::kMaxFds};
                    mem.put(outp, rl);
                }
                return ret(0);
            }
            case SYS_futex:
                // Single-threaded here: an uncontended futex wake/wait is a
                // no-op, which is correct for one thread and wrong for many.
                // Threads are not supported on this backend yet.
                return ret(0);
            case SYS_poll:
            case SYS_ppoll:
                return ret(0);
            case SYS_statfs:
            case SYS_fstatfs:
                return ret(-win32::LNOSYS);

            default:
                last_unimplemented_ = nr;
                return ret(-win32::LNOSYS);
        }
    }

    [[nodiscard]] std::uint64_t last_unimplemented() const noexcept {
        return last_unimplemented_;
    }
    [[nodiscard]] const std::string& cwd() const noexcept { return cwd_; }

    // The vCPU, needed to write FS_BASE for arch_prctl.
    void bind_cpu(WhpCpu* cpu) noexcept { cpu_ = cpu; }

private:
    static SysResult ret(std::int64_t v) { return SysResult{v, false, 0}; }

    // ARCH_SET_FS writes the FS segment BASE. We go through the segment
    // register rather than the IA32_FS_BASE MSR because the segment form is
    // in every WHP header (MinGW's omits the MSR name) and is the
    // architecturally primary view in long mode -- the MSR is an alias of
    // this field. Selector/limit/attributes must be preserved, so the
    // register is read-modify-written rather than built from scratch: a
    // zeroed Present bit here makes the guest's very next TLS access fault.
    [[nodiscard]] bool set_fs_base(std::uint64_t base) {
        if (!cpu_) return false;
        const WHV_REGISTER_NAME n[1]{WHvX64RegisterFs};
        WHV_REGISTER_VALUE v[1]{};
        if (FAILED(whp().GetVirtualProcessorRegisters(
                vm_.partition(), cpu_->index(), n, 1, v)))
            return false;
        v[0].Segment.Base = base;
        return SUCCEEDED(whp().SetVirtualProcessorRegisters(
            vm_.partition(), cpu_->index(), n, 1, v));
    }
    [[nodiscard]] bool get_fs_base(std::uint64_t& base) {
        if (!cpu_) return false;
        const WHV_REGISTER_NAME n[1]{WHvX64RegisterFs};
        WHV_REGISTER_VALUE v[1]{};
        if (FAILED(whp().GetVirtualProcessorRegisters(
                vm_.partition(), cpu_->index(), n, 1, v)))
            return false;
        base = v[0].Segment.Base;
        return true;
    }

    // Append must seek to EOF before each write, which is what O_APPEND
    // guarantees. We are single-threaded per fd, so this is sound.
    [[nodiscard]] std::int64_t write_handle(int g, HANDLE h, const std::byte* p,
                                            std::size_t n) {
        if (fds_.is_append(g)) {
            LARGE_INTEGER zero{};
            ::SetFilePointerEx(h, zero, nullptr, FILE_END);
        }
        DWORD put = 0;
        if (!::WriteFile(h, p, DWORD(n), &put, nullptr))
            return win32::fail();
        return std::int64_t(put);
    }

    [[nodiscard]] std::int64_t do_open(const std::string& gp,
                                       std::uint64_t flags) {
        const auto w = win32::to_win_path(host_path(gp));
        const auto t = win32::translate_open(flags);
        HANDLE h = ::CreateFileW(w.c_str(), t.access, t.share, nullptr,
                                 t.disposition, t.attrs, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            // O_DIRECTORY and plain opens of a directory both need BACKUP
            // semantics; retry once rather than failing a legitimate open.
            const DWORD at = ::GetFileAttributesW(w.c_str());
            if (at != INVALID_FILE_ATTRIBUTES &&
                (at & FILE_ATTRIBUTE_DIRECTORY)) {
                h = ::CreateFileW(w.c_str(), FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                                  t.share, nullptr, OPEN_EXISTING,
                                  FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            }
            if (h == INVALID_HANDLE_VALUE) return win32::fail();
        }
        if (t.want_directory) {
            BY_HANDLE_FILE_INFORMATION bhfi{};
            if (::GetFileInformationByHandle(h, &bhfi) &&
                !(bhfi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                ::CloseHandle(h);
                return -win32::LNOTDIR;   // O_DIRECTORY on a plain file
            }
        }
        const int g = fds_.install(h, (flags & 0x8'0000) != 0 /*O_CLOEXEC*/);
        if (g < 0) { ::CloseHandle(h); return g; }
        fds_.set_append(g, t.want_append);
        fds_.set_path(g, normalize_guest(gp));
        fds_.set_tty(g, false);
        return g;
    }

    [[nodiscard]] std::int64_t stat_path(const std::string& gp,
                                         std::uint64_t outp) {
        const auto w = win32::to_win_path(host_path(gp));
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (!::GetFileAttributesExW(w.c_str(), GetFileExInfoStandard, &fad))
            return win32::fail();
        BY_HANDLE_FILE_INFORMATION bhfi{};
        bhfi.dwFileAttributes = fad.dwFileAttributes;
        bhfi.ftCreationTime = fad.ftCreationTime;
        bhfi.ftLastAccessTime = fad.ftLastAccessTime;
        bhfi.ftLastWriteTime = fad.ftLastWriteTime;
        bhfi.nFileSizeHigh = fad.nFileSizeHigh;
        bhfi.nFileSizeLow = fad.nFileSizeLow;
        bhfi.nNumberOfLinks = 1;
        auto st = win32::stat_from_win(bhfi);
        return vm_.mem().put(outp, st) ? 0 : -win32::LFAULT;
    }

    // getdents64: enumerate once into the cursor, then stream entries out via
    // the ONE linux_dirent64 encoder (abi/wire/dirent64.hpp). The snapshot
    // matters -- a guest reads a directory across several calls and expects a
    // stable sequence.
    //
    // This used to hand-roll the record and substitute d_ino = pos + 1 and
    // d_type = DT_UNKNOWN. Both were bugs: Windows already tells us the real
    // type and file index, and a positional d_ino breaks any guest that
    // cross-checks it against a later stat().
    [[nodiscard]] std::int64_t do_getdents(int g, std::uint64_t outp,
                                           std::uint64_t cap) {
        DirCursor* dc = fds_.dir(g);
        if (!dc) return -win32::LBADF;
        if (!dc->loaded) {
            const std::string& gp = fds_.path(g);
            auto pattern = win32::to_win_path(host_path(gp) + "/*");
            WIN32_FIND_DATAW fd{};
            HANDLE fh = ::FindFirstFileW(pattern.c_str(), &fd);
            if (fh != INVALID_HANDLE_VALUE) {
                do {
                    DirEntry e;
                    e.name = win32::from_win_path(fd.cFileName);
                    // A reparse point is the closest thing to a symlink; a
                    // directory attribute is exact. Everything else is a
                    // regular file as far as the guest is concerned.
                    e.type = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                                 ? abi::wire::DType::symlink
                           : (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                                 ? abi::wire::DType::dir
                                 : abi::wire::DType::regular;
                    // d_ino: FindFirstFileW does NOT carry the NTFS file id
                    // (that needs an open handle and
                    // GetFileInformationByHandle, i.e. one open per entry --
                    // too costly to do while enumerating). Leave it 0 so the
                    // encoder substitutes a positional value.
                    //
                    // KNOWN GAP: a guest that cross-checks d_ino against a
                    // later stat() -- libalpm does -- will still disagree here,
                    // because stat DOES report the real file id. Closing it
                    // means resolving the id lazily on the first guest stat,
                    // or opening each entry during enumeration. Tracked rather
                    // than silently papered over.
                    e.ino = 0;
                    dc->entries.push_back(std::move(e));
                } while (::FindNextFileW(fh, &fd));
                ::FindClose(fh);
            }
            dc->loaded = true;
        }

        auto mem = vm_.mem();
        std::uint64_t off = 0;
        while (dc->pos < dc->entries.size()) {
            const DirEntry& e = dc->entries[dc->pos];
            const std::size_t reclen = abi::wire::dirent_reclen(e.name.size());
            if (off + reclen > cap) break;
            std::vector<std::byte> rec(reclen);
            const abi::wire::Dirent de{
                e.ino ? e.ino : dc->pos + 1,
                static_cast<std::int64_t>(dc->pos + 1),
                e.type,
                e.name,
            };
            if (abi::wire::encode_dirent64(rec, de) == 0) break;
            if (mem.copy_out(outp + off, rec) != rec.size()) break;
            off += reclen;
            ++dc->pos;
        }
        return std::int64_t(off);
    }

    [[nodiscard]] std::int64_t do_uname(std::uint64_t outp) {
        // struct utsname: six 65-byte fields.
        struct Uts { char s[6][65]; } u{};
        auto set = [](char* d, const char* v) {
            std::strncpy(d, v, 64);
            d[64] = '\0';
        };
        set(u.s[0], "Linux");
        set(u.s[1], "linuxity");
        set(u.s[2], "6.6.0-linuxity");
        set(u.s[3], "#1 linuxity portable Linux ABI");
        set(u.s[4], "x86_64");
        set(u.s[5], "(none)");
        return vm_.mem().put(outp, u) ? 0 : -win32::LFAULT;
    }

    // Absolutize a guest path against this process's cwd, then normalize it.
    //
    // The `.`/`..` collapsing is NOT reimplemented here: it is
    // FileNamespace::normalize, which is static and host-free, so there is one
    // algorithm. This file used to carry a second one -- a different
    // implementation of the same semantics (vector-of-parts instead of
    // in-place truncation). I diffed them across 20 cases, including "/..",
    // "/a/b/../../..", "///a", "/..." and "/a/..b", and they agreed on all of
    // them -- but two implementations that agree today is a coincidence to be
    // removed, not a property to rely on.
    [[nodiscard]] std::string normalize_guest(std::string_view gp) const {
        return abi::wire::absolutize_path(gp, cwd_);
    }

    WhpMachine& vm_;
    WhpMm& mm_;
    FdTable& fds_;
    WhpCpu* cpu_{nullptr};
    std::string root_;
    std::string cwd_;
    std::uint64_t last_unimplemented_{0};
};

} // namespace lx::runtime

#endif // _WIN32 && x86-64
