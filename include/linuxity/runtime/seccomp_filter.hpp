// linuxity/runtime/seccomp_filter.hpp
//
// SECCOMP-BPF trap acceleration — the single biggest performance lever, taken
// from proot and done the linuxity way.
//
// Without this, the ptrace backend drives every task with PTRACE_SYSCALL, so
// the guest STOPS on EVERY syscall (entry AND exit). A build or a `pacman
// -Syu` issues millions of read/write/mmap/futex/lseek calls that linuxity
// does not care about — each one pays two context switches into the tracer for
// nothing.
//
// The fix, exactly as proot does it: install a classic BPF seccomp filter in
// the guest that returns SECCOMP_RET_TRACE only for the syscalls linuxity must
// intercept (the path-carrying, identity, exec, process, tty and namespace
// calls), and SECCOMP_RET_ALLOW for everything else. Allowed syscalls then run
// natively in the guest with ZERO tracer involvement. The tracer switches from
// PTRACE_SYSCALL to PTRACE_CONT and only wakes on a PTRACE_EVENT_SECCOMP stop
// (or fork/exec/exit), servicing the intercepted call and continuing.
//
// The filter is installed pre-execve (in the same child hook that chroots and
// joins the cgroup) and, thanks to SECCOMP_FILTER_FLAG_TSYNC-free inheritance,
// applies to the whole forked tree — every descendant is filtered identically.
//
// A guest without seccomp support (old kernel, no CONFIG_SECCOMP_FILTER) is
// handled by the caller: install_trap_filter() returns false and the backend
// falls back to PTRACE_SYSCALL, so correctness never depends on seccomp.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace lx::runtime {

// The x86-64 syscall numbers linuxity INTERCEPTS. Every one is virtualized,
// redirected, translated, or otherwise serviced by abi::SyscallDispatch; all
// others are safe to run natively. Keep this in lock-step with the non-default
// cases of abi::SyscallDispatch::dispatch() and sysno.hpp's x86-64 decode. A
// syscall MISSING here that the dispatcher needs would silently run raw (e.g.
// an untranslated path hitting the host's /usr); an EXTRA one here only costs
// a needless stop, never correctness. When in doubt, include it.
inline constexpr int kTrappedX86_64[] = {
    // -- identity & process model ------------------------------------------
    39,   // getpid
    110,  // getppid
    // gettid(186) is NOT filtered: glibc's raise()/abort() call it, and the
    // bootstrap SIGSTOP (raise) must work BEFORE TRACESECCOMP is armed. gettid
    // returns the host tid, which for a single-threaded guest process equals
    // its pid; a monitor reads tid from /proc (already virtualized), so
    // running gettid natively is harmless.
    102, 104, 107, 108,          // getuid/getgid/geteuid/getegid
    118, 120,                    // getresuid/getresgid (bash/sudo $UID at init)
    56, 57, 58,                  // clone/fork/vfork      (pid translated)
    // execve(59)/execveat(322) are NOT filtered. Trapping execve is what makes
    // the bootstrap fragile: the child must run execve after installing the
    // filter but before the tracer can arm TRACESECCOMP, and a trapped execve
    // ENOSYS-fails there, aborting the launch. linuxity's guest binaries are
    // launched by the real ld.so (opened through the trapped openat, which IS
    // filtered and path-translated), so native execve is correct; the process
    // monitor still sees each exec via PTRACE_EVENT_EXEC.
    61,                          // wait4                 (pid translated both ways)
    62,                          // kill                  (signal to guest pid)
    // tgkill(234)/tkill(200) are intentionally NOT filtered: glibc's raise()
    // uses tgkill, and the child raises SIGSTOP during bootstrap BEFORE the
    // tracer sets TRACESECCOMP; a filtered tgkill would ENOSYS and abort the
    // launch. A guest tgkill targets a thread that shares the host tgid, so
    // running it natively is already correct.
    63,                          // uname
    99,                          // sysinfo
    204,                         // sched_getaffinity
    // -- session / process groups ------------------------------------------
    111, 121, 124, 112, 109,     // getpgrp/getpgid/getsid/setsid/setpgid
    140, 141,                    // getpriority/setpriority
    // -- tty job control (virtualized so the shell owns its terminal) ------
    16,                          // ioctl
    // -- filesystem namespace (path args resolved through OUR tree) --------
    2, 257,                      // open/openat
    437,                         // openat2
    4, 6, 262,                   // stat/lstat/newfstatat
    332,                         // statx
    137,                         // statfs        (path -> overlay redirect)
    21, 269, 439,                // access/faccessat/faccessat2
    80,                          // chdir
    161,                         // chroot        (accepted namespace no-op)
    89, 267,                     // readlink/readlinkat
    79,                          // getcwd
    217,                         // getdents64
    // extended attributes: the path variants translate to the overlay; the
    // f* variants act on an already-open fd (still trapped so the dispatcher
    // can forward them uniformly).
    191, 192, 193,               // getxattr/lgetxattr/fgetxattr
    188, 189, 190,               // setxattr/lsetxattr/fsetxattr
    194, 195, 196,               // listxattr/llistxattr/flistxattr
    197, 198, 199,               // removexattr/lremovexattr/fremovexattr
    // close(3) is intentionally NOT filtered: it fires constantly (every fd
    // teardown) and linuxity only uses it for fd->path bookkeeping, which is
    // non-essential (readlink recovers paths lazily). Trapping it would also
    // fire during bootstrap before TRACESECCOMP is set. Left native.
    // -- namespace MUTATION (create/remove/rename/relink/perm) -------------
    83, 258,                     // mkdir/mkdirat
    133, 259,                    // mknod/mknodat
    84, 87, 263,                 // rmdir/unlink/unlinkat
    90, 268,                     // chmod/fchmodat
    91,                          // fchmod        (records mode; then fwd)
    92, 94, 93, 260,             // chown/lchown/fchown/fchownat
    76,                          // truncate
    235, 132, 280, 261,          // utimes/utime/utimensat/futimesat
    82, 264, 316,                // rename/renameat/renameat2
    86, 265,                     // link/linkat
    88, 266,                     // symlink/symlinkat
    // -- AF_UNIX socket path translation -----------------------------------
    // bind/connect carry a filesystem path inside a `struct sockaddr_un`. An
    // absolute guest path (e.g. gpg-agent's /etc/pacman.d/gnupg/S.gpg-agent)
    // must be rewritten to its overlay-upper host path so the socket file is
    // created/looked-up in the SAME place stat/chmod see it. Untrapped, the
    // bind lands in the chroot's lower layer and diverges from the overlay,
    // and gpg-agent's connect then fails.
    49, 42,                      // bind/connect
    // -- privilege drops (vacuous in a root-owned world) -------------------
    105, 106, 114, 113, 117, 119, 122, 123, 116,
    // setuid/setgid/setregid/setreuid/setresuid/setresgid/setfsuid/setfsgid/setgroups
    // -- landlock (accepted no-op; the namespace already confines) ---------
    444, 445, 446,               // landlock_create_ruleset/add_rule/restrict_self
    // -- mount ops we own --------------------------------------------------
    165, 166,                    // mount/umount2 (accepted no-op)
    // -- file watchers: translate the watched path to the overlay ----------
    254,                         // inotify_add_watch
    301,                         // fanotify_mark
    // -- file-handle API: refused (leaks host inode identity) --------------
    303, 304,                    // name_to_handle_at/open_by_handle_at
    // -- new mount + mount-info API: refused (privileged, host-scoped) ------
    430, 431, 432,               // fsopen/fsconfig/fsmount
    429, 428, 442,               // move_mount/open_tree/mount_setattr
    457, 458,                    // statmount/listmount
    // -- privileged sysadmin ops: refused cleanly (never host-scoped raw) ---
    155,                         // pivot_root
    167, 168,                    // swapon/swapoff
    163,                         // acct
    179,                         // quotactl
    136,                         // ustat
};

// Install the seccomp trap filter in the CURRENT process (called in the child
// after chroot, before TRACEME + execve). Returns true if the filter was
// installed, false if seccomp filtering is unavailable — in which case the
// caller must drive tasks with PTRACE_SYSCALL instead.
//
// The classic-BPF program:
//   1. load arch; if not the expected AUDIT_ARCH, ALLOW (never mis-filter a
//      foreign personality — those calls simply run, the tracer decodes arch
//      independently).
//   2. load nr; for each trapped nr, RET TRACE; otherwise RET ALLOW.
//
// A per-nr linear compare is O(n) in the filter but n is ~90 and the filter
// runs in-kernel per syscall — negligible next to the context switch it saves.
[[nodiscard]] inline bool install_trap_filter() {
    // No-new-privs is mandatory before a non-root process may load a filter.
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return false;

    constexpr std::uint32_t kArch = AUDIT_ARCH_X86_64;
    constexpr std::size_t nTrapped = sizeof(kTrappedX86_64) / sizeof(int);

    // Program layout (leaves LAST, so every match is a simple forward jump):
    //
    //   idx 0 : A = arch
    //   idx 1 : if (A == kArch) skip 1 else fall through   [JEQ jt=1,jf=0]
    //   idx 2 : RET ALLOW        (arch mismatch -> run natively)
    //   idx 3 : A = nr
    //   idx 4..4+n-1 : for each trapped nr: JEQ nr -> jump to TRACE leaf
    //   idx 4+n     : RET ALLOW   (no match -> run natively)
    //   idx 4+n+1   : RET TRACE   (matched -> notify the tracer)
    //
    // For the JEQ at position (4 + i), the TRACE leaf is the LAST statement.
    // Statements strictly after this JEQ and before TRACE are:
    //   remaining JEQs (n-1-i) + the ALLOW leaf (1)  => jt = (n-1-i) + 1.
    std::vector<sock_filter> f;
    f.reserve(nTrapped + 6);

    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                         offsetof(seccomp_data, arch)));       // 0
    f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kArch, 1, 0)); // 1
    f.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));  // 2 (foreign arch)
    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                         offsetof(seccomp_data, nr)));          // 3
    for (std::size_t i = 0; i < nTrapped; ++i) {
        std::uint8_t jt = static_cast<std::uint8_t>((nTrapped - 1 - i) + 1);
        f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                             static_cast<std::uint32_t>(kTrappedX86_64[i]),
                             jt, 0));                            // 4 + i
    }
    f.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));  // 4 + n
    f.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE));  // 4 + n + 1

    sock_fprog prog{
        static_cast<unsigned short>(f.size()),
        f.data(),
    };

    // SECCOMP_SET_MODE_FILTER via the direct syscall (no libseccomp dep). The
    // filter is inherited across fork and preserved across execve, so the
    // whole guest tree is filtered from one install in the root child.
    long rc = ::syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
    if (rc != 0) {
        // Fall back to the legacy prctl entry point on kernels without the
        // seccomp(2) syscall.
        if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
            return false;
    }
    return true;
}

}  // namespace lx::runtime
