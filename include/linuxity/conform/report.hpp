// linuxity/conform/report.hpp
//
// Rendering for conformance results, and the scenario registry.
//
// Header-only with `inline`, because linuxity_core is an INTERFACE (header-
// only) target and this must stay usable on all four hosts without adding a
// compiled library to the portable test set.
#pragma once

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

#include "linuxity/conform/observation.hpp"
#include "linuxity/conform/oracle.hpp"
#include "linuxity/conform/scenario.hpp"

namespace lx::conform {

namespace detail {

// errno -> name, for reports. Unlisted values render as a number, which is
// still unambiguous; this is presentation, never comparison.
[[nodiscard]] inline const char* errno_name(std::int32_t e) noexcept {
    switch (e) {
        case EPERM:   return "EPERM";
        case ENOENT:  return "ENOENT";
        case EBADF:   return "EBADF";
        case EACCES:  return "EACCES";
        case EEXIST:  return "EEXIST";
        case ENOTDIR: return "ENOTDIR";
        case EISDIR:  return "EISDIR";
        case EINVAL:  return "EINVAL";
        case ENOSYS:  return "ENOSYS";
        case ERANGE:  return "ERANGE";
        case ESPIPE:  return "ESPIPE";
        case ELOOP:   return "ELOOP";
        case ENOTTY:  return "ENOTTY";
        case ESRCH:   return "ESRCH";
        case ENODATA: return "ENODATA";
        case EOPNOTSUPP: return "EOPNOTSUPP";
        case EFAULT:  return "EFAULT";
        default:      return nullptr;
    }
}

} // namespace detail

inline std::string Returned::describe() const {
    return match(
        [](std::int64_t v) { return std::to_string(v); },
        [](std::int32_t e) {
            const char* n = detail::errno_name(e);
            return n ? std::string{"-"} + n
                     : std::string{"-errno("} + std::to_string(e) + ")";
        });
}

inline std::string render_buffers(std::span<const Written> bufs) {
    if (bufs.empty()) return "(wrote nothing)";

    std::string out;
    for (const Written& w : bufs) {
        out += "arg" + std::to_string(w.arg) + "[" +
               std::to_string(w.bytes.size()) + "B]=";
        // A short hex prefix: enough to see WHICH bytes differ without
        // dumping kilobytes into a failure message.
        constexpr std::size_t preview = 16;
        const std::size_t n = std::min(preview, w.bytes.size());
        for (std::size_t i = 0; i < n; ++i) {
            char hex[4] = {};
            std::snprintf(hex, sizeof hex, "%02x ",
                          static_cast<unsigned>(
                              static_cast<unsigned char>(w.bytes[i])));
            out += hex;
        }
        if (w.bytes.size() > n) out += "...";
        out += "; ";
    }
    return out;
}

inline std::string Divergence::describe() const {
    std::string s = "step " + std::to_string(index);
    if (!note.empty()) s += " (" + note + ")";
    s += ": ";
    s += field_name(field);
    s += " differs\n";
    s += "    native: " + native + "\n";
    s += "    guest:  " + guest;
    return s;
}

inline std::string Unavailable::describe() const {
    std::string s{cause_name(cause)};
    if (!this->detail.empty()) s += ": " + this->detail;
    return s;
}

inline std::string Scenario::key() const {
    std::string k{name};
    for (const std::string& a : args) {
        k += '_';
        // Keep the key filesystem-safe: a scenario arg is usually a path.
        for (const char c : a) k += (c == '/' || c == '.') ? '-' : c;
    }
    return k;
}

// -- the registry ----------------------------------------------------------
//
// THE single place conformance scenarios are declared. A case added here runs
// under linuxity on all four hosts, natively on the Linux hosts, and against
// the recorded golden on macOS/Windows, with no other edit.
[[nodiscard]] inline std::vector<Scenario> all_scenarios() {
    std::vector<Scenario> v;

    // Directory seek/cookie behaviour, per flavour. The flavours are the whole
    // point: the lseek-cookie bug was invisible on host_backed (which forwards
    // to the real kernel) and appeared only on virtualised.
    // /etc rather than /usr/bin: the scenario has to run on EVERY Linux host
    // that might record a golden, and Android has no /usr/bin. /etc is a
    // host-backed directory with plenty of entries on both.
    v.push_back(Scenario{"dirseek-host", "dirseek"}
                    .with("/etc")
                    .exercising(abi::Sysno::getdents64)
                    .exercising(abi::Sysno::lseek)
                    .on(DirFlavour::host_backed));

    v.push_back(Scenario{"dirseek-proc", "dirseek"}
                    .with("/proc")
                    .exercising(abi::Sysno::getdents64)
                    .exercising(abi::Sysno::lseek)
                    .on(DirFlavour::virtualised));

    v.push_back(Scenario{"dirseek-sys", "dirseek"}
                    .with("/sys")
                    .exercising(abi::Sysno::getdents64)
                    .exercising(abi::Sysno::lseek)
                    .on(DirFlavour::virtualised));

    // stat/access/statx/readlink across realms, with the error paths that
    // matter: empty path (ENOENT), trailing slash on a file (ENOTDIR),
    // file-as-directory (ENOTDIR), and /proc/self as a real symlink. All four
    // were divergent before the differential harness found them.
    v.push_back(Scenario{"statpaths", "statpaths"}
                    .exercising(abi::Sysno::newfstatat)
                    .exercising(abi::Sysno::faccessat)
                    .exercising(abi::Sysno::statx)
                    .exercising(abi::Sysno::readlinkat)
                    .exercising(abi::Sysno::fstat)
                    .on(DirFlavour::virtualised));

    // fd lifecycle: dup/dup2/dup3, fcntl, and the EBADF boundaries. This is
    // where linuxity keeps its own table alongside the host's real fds, so a
    // drift between the two surfaces as a wrong errno -- a bad dirfd with a
    // relative path was ENOENT instead of EBADF.
    v.push_back(Scenario{"fdops", "fdops"}
                    .exercising(abi::Sysno::dup)
                    .exercising(abi::Sysno::dup2)
                    .exercising(abi::Sysno::dup3)
                    .exercising(abi::Sysno::fcntl)
                    .exercising(abi::Sysno::close)
                    .exercising(abi::Sysno::openat)
                    .exercising(abi::Sysno::read)
                    .on(DirFlavour::host_backed));

    // read/write/pread/readv/lseek on a regular file. Most of these FORWARD
    // on Linux, which is the point: this pins that the forwarding path keeps
    // offsets, short reads and errnos exact, and catches it if someone later
    // decides to intercept one. Buffer CONTENT is compared here (unlike a
    // directory listing) because a file this probe wrote is deterministic.
    v.push_back(Scenario{"rwio", "rwio"}
                    .exercising(abi::Sysno::read)
                    .exercising(abi::Sysno::write)
                    .exercising(abi::Sysno::pread64)
                    .exercising(abi::Sysno::pwrite64)
                    .exercising(abi::Sysno::readv)
                    .exercising(abi::Sysno::writev)
                    .exercising(abi::Sysno::ftruncate)
                    .exercising(abi::Sysno::unlinkat)
                    .on(DirFlavour::host_backed));

    // Process identity and the /proc views of it. linuxity SYNTHESIZES almost
    // all of this -- fake pid 1, own pid namespace, procfs built from its own
    // process table -- so interception is near-total and the risk is highest.
    // The pid VALUE is exempt (the guest is 1, a native run is not), so this
    // asserts invariants instead: tid == pid for a thread-group leader, and
    // /proc/self/status agreeing with the syscalls. The tid invariant is what
    // caught gettid returning the raw host tid.
    v.push_back(Scenario{"procid", "procid"}
                    .exercising(abi::Sysno::getpid)
                    .exercising(abi::Sysno::gettid)
                    .exercising(abi::Sysno::getppid)
                    .exercising(abi::Sysno::getuid)
                    .exercising(abi::Sysno::getgid)
                    .exercising(abi::Sysno::uname)
                    .exercising(abi::Sysno::prlimit64)
                    .exercising(abi::Sysno::sched_getaffinity)
                    .exercising(abi::Sysno::kill)
                    .on(DirFlavour::virtualised));

    // Filesystem MUTATION through the overlay. Every write has to land in the
    // UPPER layer, copying up from the read-only lower first, and that
    // machinery (classify for_write, WriteIntent, whiteouts) is linuxity's own
    // code. It is where a wrong errno or a write to the wrong layer hides:
    // mkdir was behaving like `mkdir -p`, and chmod on a missing file reported
    // success. Both found here.
    v.push_back(Scenario{"fsmutate", "fsmutate"}
                    .exercising(abi::Sysno::mkdirat)
                    .exercising(abi::Sysno::linkat)
                    .exercising(abi::Sysno::symlinkat)
                    .exercising(abi::Sysno::renameat)
                    .exercising(abi::Sysno::fchmodat)
                    .exercising(abi::Sysno::fchownat)
                    .exercising(abi::Sysno::truncate)
                    .exercising(abi::Sysno::utimensat)
                    .on(DirFlavour::host_backed));

    // mmap/munmap/mprotect/mremap/madvise/brk. linuxity tracks the guest's
    // address space itself, so this has the same two-bookkeepings risk as the
    // fd table. ADDRESSES are not comparable (ASLR alone differs every run),
    // so the probe asserts invariants: anonymous memory is zero-filled,
    // contents survive an mremap, MADV_DONTNEED zeroes, a too-low brk returns
    // the old break rather than an errno.
    v.push_back(Scenario{"memory", "memory"}
                    .exercising(abi::Sysno::mmap)
                    .exercising(abi::Sysno::munmap)
                    .exercising(abi::Sysno::mprotect)
                    .exercising(abi::Sysno::mremap)
                    .exercising(abi::Sysno::madvise)
                    .exercising(abi::Sysno::brk)
                    .on(DirFlavour::host_backed));

    // Signal dispositions and masks. linuxity delivers signals itself and
    // translates guest pids to host tids on the way, so this is mostly its own
    // code. No handler is ever RUN -- delivery timing is not deterministic --
    // but the bookkeeping is: what sigaction reports, what the mask holds,
    // which errnos the edges give. This caught tgkill/tkill returning EPERM
    // for the standard thread-liveness probe.
    v.push_back(Scenario{"signals", "signals"}
                    .exercising(abi::Sysno::rt_sigaction)
                    .exercising(abi::Sysno::rt_sigprocmask)
                    .exercising(abi::Sysno::rt_sigpending)
                    .exercising(abi::Sysno::sigaltstack)
                    .exercising(abi::Sysno::tgkill)
                    .exercising(abi::Sysno::tkill)
                    .on(DirFlavour::virtualised));

    // ioctl on a pty: termios, window size, foreground process group.
    //
    // ioctl is the widest syscall in Linux and had NO probe, which is how four
    // tty bugs shipped in one day: the termios2 requests denied by Android's
    // SELinux ioctl whitelist (`tty` reported "not a tty" on a working pty),
    // the fix then missing musl's sign-extended spelling of the same request,
    // and TIOCGPGRP disagreeing with getpgrp so every shell concluded it was a
    // background job and turned off line editing.
    //
    // The probe makes its OWN pty rather than using stdin, which is a pipe in
    // CI and a terminal by hand -- tty ioctls answer differently on each, and
    // the comparison has to be deterministic. The slave is the interesting
    // device: /dev/ptmx and a devpts slave are different SELinux classes, and
    // the Android denial applied only to the slave.
    v.push_back(Scenario{"ioctls", "ioctls"}
                    .exercising(abi::Sysno::ioctl)
                    .exercising(abi::Sysno::setpgid)
                    .on(DirFlavour::host_backed));

    // The x86-64-only syscalls that predate the *at family, and the
    // invariant that each answers like its modern equivalent.
    //
    // These are the calls an x86-64 glibc actually issues -- open, stat,
    // access, chmod, rename, unlink -- and not one of them had differential
    // coverage, because every other probe uses the portable *at spelling
    // (the only one that compiles on aarch64 too). Two spellings of one
    // operation with only one of them tested is precisely the hole the
    // sign-extended TCGETS2 fell through.
    //
    // On aarch64 the probe emits the same steps marked not-applicable: the
    // syscalls do not exist there, and the traces must stay the same length.
    v.push_back(Scenario{"legacy", "legacy"}
                    .exercising(abi::Sysno::open)
                    .exercising(abi::Sysno::creat)
                    .exercising(abi::Sysno::stat)
                    .exercising(abi::Sysno::lstat)
                    .exercising(abi::Sysno::access)
                    .exercising(abi::Sysno::readlink)
                    .exercising(abi::Sysno::chmod)
                    .exercising(abi::Sysno::chown)
                    .exercising(abi::Sysno::lchown)
                    .exercising(abi::Sysno::link)
                    .exercising(abi::Sysno::unlink)
                    .exercising(abi::Sysno::symlink)
                    .exercising(abi::Sysno::rename)
                    .exercising(abi::Sysno::mkdir)
                    .exercising(abi::Sysno::rmdir)
                    .exercising(abi::Sysno::utimes)
                    .on(DirFlavour::host_backed));

    // Extended attributes: 16 handlers that had zero differential coverage.
    //
    // Not obscure -- they carry file capabilities, SELinux labels and ACLs,
    // and tar/cp -a/setcap/rsync -X all depend on them, where a wrong answer
    // is silent (the file copies, the attribute quietly does not). They also
    // sit on the confinement boundary: the path forms take a GUEST path that
    // must be translated before the host sees it, and the *at forms were
    // once decoded on aarch64 but not x86-64, so there they reached the
    // host's real file from a guest tree that has none.
    v.push_back(Scenario{"xattrs", "xattrs"}
                    .exercising(abi::Sysno::setxattr)
                    .exercising(abi::Sysno::getxattr)
                    .exercising(abi::Sysno::listxattr)
                    .exercising(abi::Sysno::removexattr)
                    .exercising(abi::Sysno::lsetxattr)
                    .exercising(abi::Sysno::lgetxattr)
                    .exercising(abi::Sysno::llistxattr)
                    .exercising(abi::Sysno::lremovexattr)
                    .exercising(abi::Sysno::fsetxattr)
                    .exercising(abi::Sysno::fgetxattr)
                    .exercising(abi::Sysno::flistxattr)
                    .exercising(abi::Sysno::fremovexattr)
                    .on(DirFlavour::host_backed));

    // Credentials, sessions and process groups.
    //
    // 19 handlers were unverified here, including every setter. The
    // job-control bug lived in this family: setpgid was discarded while
    // getpgrp reported it, and nothing compared the two.
    //
    // Values cannot be compared -- the guest is fake-root in its own
    // namespace, the native run is whatever user CI uses -- so the probe
    // asserts RELATIONSHIPS that hold for any correct credential model:
    // getresuid agrees with getuid/geteuid, a setter to the current value is
    // a no-op, -1 means leave unchanged, getpgid(0) == getpgrp. An invariant
    // is portable across the very difference that makes values incomparable.
    v.push_back(Scenario{"creds", "creds"}
                    .exercising(abi::Sysno::geteuid)
                    .exercising(abi::Sysno::getegid)
                    .exercising(abi::Sysno::getresuid)
                    .exercising(abi::Sysno::getresgid)
                    .exercising(abi::Sysno::setuid)
                    .exercising(abi::Sysno::setgid)
                    .exercising(abi::Sysno::setreuid)
                    .exercising(abi::Sysno::setregid)
                    .exercising(abi::Sysno::setresuid)
                    .exercising(abi::Sysno::setresgid)
                    .exercising(abi::Sysno::setfsuid)
                    .exercising(abi::Sysno::setfsgid)
                    .exercising(abi::Sysno::setgroups)
                    .exercising(abi::Sysno::getsid)
                    .exercising(abi::Sysno::getpgid)
                    .exercising(abi::Sysno::getpriority)
                    .exercising(abi::Sysno::setpriority)
                    .on(DirFlavour::virtualised));

    // The current directory, filesystem info, and the newer *at forms.
    //
    // The cwd is the one with teeth: linuxity keeps its OWN per-process cwd
    // (it must -- the guest's "/" is a host directory somewhere else), and
    // every relative path the guest opens resolves against it. Drift there
    // means relative paths silently reach the wrong file. So the probe
    // checks relationships: getcwd reports where chdir went, fchdir lands
    // where chdir to the same path lands, a relative open resolves in the
    // cwd last set.
    //
    // statfs/sysinfo values are NOT compared -- free space moves between two
    // runs seconds apart, and linuxity deliberately reports its own virtual
    // machine rather than the host's. The structure is what must hold: a
    // power-of-two block size, free <= total, ENOENT on a missing path.
    v.push_back(Scenario{"cwdfs", "cwdfs"}
                    .exercising(abi::Sysno::chdir)
                    .exercising(abi::Sysno::fchdir)
                    .exercising(abi::Sysno::getcwd)
                    .exercising(abi::Sysno::statfs)
                    .exercising(abi::Sysno::fstatfs)
                    .exercising(abi::Sysno::sysinfo)
                    .exercising(abi::Sysno::fchmod)
                    .exercising(abi::Sysno::fchown)
                    .exercising(abi::Sysno::faccessat2)
                    .exercising(abi::Sysno::renameat2)
                    .exercising(abi::Sysno::mknodat)
                    .on(DirFlavour::host_backed));

    // The W^X JIT sequence: mmap W, write code, mprotect X, flush, call.
    //
    // `memory` exercises mmap/mprotect as memory management but never
    // EXECUTES from a mapping it made, and that is the contract every JIT
    // depends on -- Java, V8, .NET, LuaJIT, every node process. It is more
    // fragile on arm64 than x86-64: the architecture does not guarantee
    // i-cache/d-cache coherence, so the flush is mandatory rather than
    // advisory, and arm64 has arch-private syscalls in the 0xf0000 range
    // (__ARM_NR_cacheflush) the generic decoder does not know.
    //
    // Also covers re-protecting a LIVE mapping, which is how a JIT patches
    // code in place -- the case where stale bookkeeping would show up.
    v.push_back(Scenario{"jitwx", "jitwx"}
                    .exercising(abi::Sysno::mmap)
                    .exercising(abi::Sysno::mprotect)
                    .exercising(abi::Sysno::munmap)
                    .on(DirFlavour::host_backed));

    return v;
}

} // namespace lx::conform
