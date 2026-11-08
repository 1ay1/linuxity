// linuxity/runtime/linux/seccomp_filter.hpp
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
//
// WHY NOT SECCOMP_RET_USER_NOTIF. It is the obvious next lever and it is
// measurably faster -- 4.04us against 6.63us per answered call on this host,
// cache-cold (a tight loop flatters it to 2.55 vs 5.24, which is not the
// pattern a real workload has). That would take `ls -lR /usr/include` from
// ~1.6s to ~0.8s.
//
// It cannot carry a REDIRECT, which is most of what linuxity does. To let a
// notified syscall proceed the supervisor replies with
// SECCOMP_USER_NOTIF_FLAG_CONTINUE, and linux/seccomp.h is blunt about what
// that means:
//
//     "This is problematic because of an inherent TOCTOU. An attacker can
//      exploit the time while the supervised process is waiting on a response
//      from the supervising process to rewrite syscall arguments which are
//      passed as pointers of the intercepted syscall. It should be absolutely
//      clear that this means that the seccomp notifier _cannot_ be used to
//      implement a security policy!"
//
// Path translation IS a security policy here -- it is what keeps a guest's
// /etc/passwd inside its rootfs. The race is live, not theoretical: guests get
// real threads sharing an address space (verified -- a guest pthread program
// reports tids 1, 2, 3), so while thread A waits for its openat to be
// answered, thread B can rewrite the path buffer A passed.
//
// RET_TRACE has no such window. The task is STOPPED, not merely blocked, and
// the kernel re-reads the arguments from registers the tracer controls.
//
// So a notif-fd backend could only serve the calls we ANSWER outright
// (identity, the one-stop stat), never the ones we rewrite -- which would mean
// running both mechanisms and keeping ptrace for the security-critical half.
// Worth revisiting if the answered set ever dominates; today it does not.
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

#include "linuxity/runtime/linux/seccomp_arch.hpp"

namespace lx::runtime {

// The x86-64 syscall numbers linuxity INTERCEPTS. Every one is virtualized,
// redirected, translated, or otherwise serviced by abi::SyscallDispatch; all
// others are safe to run natively. Keep this in lock-step with the non-default
// cases of abi::SyscallDispatch::dispatch() and sysno.hpp's x86-64 decode. A
// syscall MISSING here that the dispatcher needs would silently run raw (e.g.
// an untranslated path hitting the host's /usr); an EXTRA one here only costs
// a needless stop, never correctness. When in doubt, include it.
// Deliberately untrapped, each declared with an explicit UNTRAPPED(name,nr)
// marker that tools/check_syscall_coverage.sh reads. A marker rather than
// prose: that check is a security boundary (an untrapped path-bearing syscall
// is a sandbox escape), and it must not be silenceable by rewording a comment.
//
// UNTRAPPED(exit,60) UNTRAPPED(exit_group,231): the task really does exit;
//   the trap observes the reap instead, so there is nothing to intercept.
// UNTRAPPED(rt_sigreturn,15): pops a signal frame. Trapping it would corrupt
//   the very frame it exists to restore.
inline constexpr int kTrappedX86_64[] = {
    // -- identity & process model ------------------------------------------
    39,   // getpid
    110,  // getppid
    // gettid(186) IS trapped. It used to be left native on the reasoning that
    // "the host tid equals the pid for a single-threaded process, so running
    // it natively is harmless" -- true of the HOST's pid, but the guest's pid
    // is virtualised to 1, so the guest saw getpid()==1 and gettid()==1507743
    // (the raw host tid). Linux guarantees tid == pid for a thread-group
    // leader, and every threading runtime relies on it.
    //
    // This is the fifth bug of the handled-but-untrapped shape, after
    // lseek/rewinddir, fchmodat2, creat and set_tid_address below. Found by
    // the differential harness.
    //
    // The bootstrap worry was real but misplaced: glibc's raise()/abort() call
    // gettid before TRACESECCOMP is armed, and an unarmed filter means the
    // call runs natively anyway -- trapping it cannot break what happens
    // before the trap exists.
    186,  // gettid
    102, 104, 107, 108,          // getuid/getgid/geteuid/getegid
    // set_tid_address(218): the dispatcher answers it with the GUEST tid, but
    // it was never trapped, so the handler was dead and glibc's _start got
    // the HOST tid instead (measured: 1370571 where the guest's is 1). Found
    // by tools/check_syscall_coverage.sh, which exists because this
    // handled-but-untrapped shape keeps causing bugs.
    218,                         // set_tid_address
    118, 120,                    // getresuid/getresgid (bash/sudo $UID at init)
    56, 57, 58,                  // clone/fork/vfork      (pid translated)
    435,                         // clone3 (glibc fork/posix_spawn) (pid translated)
    59, 322,                     // execve/execveat
    // A NATIVE guest execve resolves its target against the child's ROOT.
    // Unprivileged, chroot(2) fails, so that root is the HOST tree: a native
    // execve then runs the HOST's binary (namespace escape), and a #!-script
    // or static binary present only in the rootfs fails outright. Trapping
    // execve routes every exec through path_exec, which translates the target
    // into the overlay and rewrites dynamic/#! execs through the in-rootfs
    // interpreter. The bootstrap hazard (first exec trapping before the tracer
    // arms TRACESECCOMP) is handled in start(): the child tgkill-SIGSTOPs
    // itself after TRACEME so the parent arms options first.
    61,                          // wait4                 (pid translated both ways)
    101,                         // ptrace (a guest tracing a guest is emulated)
    247,                         // waitid    (id in, siginfo.si_pid out, both xlated)
    62,                          // kill                  (signal to guest pid)
    // tkill(200)/tgkill(234) ARE trapped. The old note claimed "a guest tgkill
    // targets a thread that shares the host tgid, so running it natively is
    // already correct" -- false. The guest passes a GUEST pid (1), the host has
    // no such thread in its group, and both returned EPERM where Linux
    // succeeds. tgkill(self,self,0) is the thread-liveness probe every
    // threading runtime uses, and kill(self,0) worked while these did not.
    //
    // The bootstrap hazard the note described is real: the child self-stops
    // before the tracer arms TRACESECCOMP. It now does that through
    // rt_tgsigqueueinfo(297) -- untrapped, no handler, never needed -- so the
    // whole kill family can be intercepted. See ptrace_trap.hpp start().
    200,                         // tkill                 (guest tid in)
    234,                         // tgkill                (guest tid in)
    434,                         // pidfd_open            (guest pid in)
    129,                         // rt_sigqueueinfo       (guest pid in, siginfo ids)
    55,                          // getsockopt            (SO_PEERCRED pid out)
    51, 52,                      // getsockname/getpeername (AF_UNIX names in guest spelling)
    46, 47,                      // sendmsg/recvmsg       (SCM_CREDENTIALS ids, both ways)
    63,                          // uname
    99,                          // sysinfo
    204,                         // sched_getaffinity
    // pid in, translated at entry (see pid_arg_of in ptrace_trap.hpp):
    203, 144, 145, 142, 143, 148, // sched_setaffinity/setscheduler/getscheduler/setparam/getparam/rr_get_interval
    314, 315,                    // sched_setattr/getattr
    302, 310, 311, 312,          // prlimit64/process_vm_readv/writev/kcmp
    251, 252,                    // ioprio_set/get
    298,                         // perf_event_open (pid in arg1)
    103,                         // syslog (the guest's own kernel log)
    272, 308,                    // unshare/setns (the guest's own namespaces)
    170, 171,                    // sethostname/setdomainname (per UTS namespace)
    // SysV IPC: served by linuxity where the host has none (Android)
    29, 30, 31, 67,              // shmget/shmat/shmctl/shmdt
    64, 65, 66, 220,             // semget/semop/semctl/semtimedop
    68, 69, 70, 71,              // msgget/msgsnd/msgrcv/msgctl
    115,                         // getgroups (the guest's own list, not the host user's)
    // -- session / process groups ------------------------------------------
    111, 121, 124, 112, 109,     // getpgrp/getpgid/getsid/setsid/setpgid
    140, 141,                    // getpriority/setpriority
    // -- tty job control (virtualized so the shell owns its terminal) ------
    16,                          // ioctl
    // -- filesystem namespace (path args resolved through OUR tree) --------
    2, 257,                      // open/openat
    437,                         // openat2
    // creat(85) is open(O_CREAT|O_WRONLY|O_TRUNC). It was NOT trapped and NOT
    // handled, which made it a real sandbox escape: a direct
    // syscall(SYS_creat, "/tmp/x") had its path passed straight to the host
    // kernel and created the file on the HOST, outside the rootfs. Verified
    // by doing it. glibc routes creat() through openat, so nothing ordinary
    // hits this -- but "nothing ordinary" is not a security boundary.
    85,                          // creat
    // fchmodat2(452) was the inverse: the dispatcher HANDLES it (do_chmod)
    // but it was never trapped, so that handler was dead code and the chmod
    // went to the host path. Same shape as the lseek/rewinddir bug -- a
    // correct handler is useless if the syscall never reaches it.
    452,                         // fchmodat2
    // fspick(433) takes a path for the new mount API. linuxity does not model
    // mount namespaces, so the dispatcher refuses it -- but it must TRAP to
    // refuse, rather than letting the host resolve the path.
    433,                         // fspick
    4, 6, 262,                   // stat/lstat/newfstatat
    5,                           // fstat (owner as the guest's world says)
    332,                         // statx
    137,                         // statfs        (path -> overlay redirect)
    // fstatfs on an fd linuxity synthesized (/proc, /sys, /dev) must report
    // THAT filesystem, not the host temp file behind it. Untrapped, fstatfs
    // on an open /proc said tmpfs, and systemd's proc_mounted() -- which
    // fstatfs's an O_PATH fd -- concluded /proc was not mounted.
    138,                         // fstatfs
    21, 269, 439,                // access/faccessat/faccessat2
    80,                          // chdir
    81,                          // fchdir        (syncs tracked cwd from fd)
    161,                         // chroot        (accepted namespace no-op)
    89, 267,                     // readlink/readlinkat
    79,                          // getcwd
    217,                         // getdents64
    // lseek MUST be trapped, for directory fds specifically. rewinddir(3) and
    // seekdir(3) are an lseek on the dirfd, and an overlay-union or virtual
    // directory's entries live in OUR dir_stream, not in the backing host fd.
    // Run natively, the host lseek rewinds a directory that holds only the
    // upper layer's entries (or nothing at all for a synthesized dir) while
    // our cursor stays at EOF -- so the second readdir pass returns ZERO
    // entries. That broke every rewinddir-driven tree walk: libalpm rewinds
    // the package DB, so `pacman -Q` found nothing on an intact database.
    // The dispatcher's Sysno::lseek case was already written for this and was
    // simply unreachable, which is exactly the failure this list's header
    // comment warns about: a syscall missing here silently runs raw.
    8,                           // lseek         (dir cursor is ours)
    // extended attributes: the path variants translate to the overlay; the
    // f* variants act on an already-open fd (still trapped so the dispatcher
    // can forward them uniformly).
    191, 192, 193,               // getxattr/lgetxattr/fgetxattr
    188, 189, 190,               // setxattr/lsetxattr/fsetxattr
    194, 195, 196,               // listxattr/llistxattr/flistxattr
    // The 6.13+ *at xattr family and the 6.14+ attribute calls. All carry a
    // path, and all were decoded on aarch64 but NOT on x86-64 -- so on this
    // ABI they reached the host with an untranslated path. Verified before
    // fixing: getxattrat(AT_FDCWD, "/etc/hostname", ...) returned ENODATA
    // from a guest whose tree has no /etc/hostname, i.e. it read the HOST's.
    463, 464, 465, 466,          // setxattrat/getxattrat/listxattrat/removexattrat
    467,                         // open_tree_attr (refused, but must not reach the host)
    468, 469,                    // file_getattr/file_setattr (refused)
    470,                         // listns (refused)
    197, 198, 199,               // removexattr/lremovexattr/fremovexattr
    // close(3) IS trapped, despite firing on every fd teardown, because a
    // virtual dir fd's DirStream has to die with it. Untrapped, the stream
    // outlived the fd and getdents64 kept serving it: a closed /proc fd
    // returned 0 (clean EOF) where Linux returns EBADF, so a guest looping
    // "read until 0" never saw the error. The fd-reuse half of this was
    // already patched in do_openat (the `ps aux` SIGFPE), which only works
    // when the number gets reused -- a closed-and-not-reused fd slipped
    // through. Found by the differential harness against the host kernel.
    //
    // Cost: one trap per close, ~25us, measured against openat's 200 traps
    // in 5ms. Worth it for an errno the guest can actually branch on.
    3,                           // close
    // dup/dup2/dup3/fcntl(F_DUPFD*) ARE trapped: a dup'd fd must inherit the
    // original's fd->path and virtual-dir bindings, or an *at call relative to
    // the new fd resolves against the wrong directory. coreutils `rm -rf`
    // opens a dir, dups the fd (fts's fd cache), then unlinkat(dupfd, name) --
    // without mirroring, `name` resolves against cwd, the unlink misses
    // (ENOENT), and the parent rmdir fails "Directory not empty".
    32, 33, 292,                 // dup/dup2/dup3
    72,                          // fcntl (only F_DUPFD/F_DUPFD_CLOEXEC acted on)
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
    // socket: for the one family linuxity does not provide. There is no audit
    // subsystem behind the guest, so a NETLINK_AUDIT socket answers as a
    // kernel built without CONFIG_AUDIT does. Untrapped it reached the host,
    // and Android's EACCES made systemd log "Failed to connect to audit log"
    // on every run.
    41,                          // socket
    // -- prctl: intercept PR_SET_DUMPABLE. A guest (gpg-agent, dirmngr, ssh)
    // drops dumpable for security, which makes its memory unreadable via BOTH
    // process_vm_readv AND ptrace peek for our unprivileged tracer — so we can
    // no longer read a bind()'s sockaddr to translate the AF_UNIX path (the
    // socket then leaks to the HOST). linuxity IS the kernel here; the guest
    // must stay inspectable. We no-op PR_SET_DUMPABLE and forward every other
    // prctl unchanged.
    157,                         // prctl
    // -- credentials (tracked per process, see abi/creds.hpp) --------------
    105, 106, 114, 113, 117, 119, 122, 123, 116,
    // setuid/setgid/setregid/setreuid/setresuid/setresgid/setfsuid/setfsgid/setgroups
    125, 126,                    // capget/capset
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
//   1. load arch; if not the expected AUDIT_ARCH, ENOSYS (an i386 int 0x80
//      would otherwise bypass path translation entirely).
//   2. load nr; x32 (bit 30) and io_uring -> ENOSYS.
//   3. for each trapped nr, RET TRACE; otherwise RET ALLOW.
//
// A per-nr linear compare is O(n) in the filter but n is ~90 and the filter
// runs in-kernel per syscall — negligible next to the context switch it saves.
[[nodiscard]] inline bool install_trap_filter() {
    // No-new-privs is mandatory before a non-root process may load a filter.
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return false;

    // Everything arch-specific comes from seccomp_arch.hpp, derived from the
    // one trapped list above. Getting kArch wrong is invisible until a guest
    // runs, then it ENOSYS-es every syscall and spins.
    constexpr abi::Arch kHostArch = conform::host_arch();
    constexpr std::uint32_t kArch = seccomp_audit_arch(kHostArch);
    constexpr auto kTrappedAll = trapped_for(kHostArch, kTrappedX86_64);

    // Drop the syscalls this arch doesn't have (aarch64 has no open/stat/
    // fork), so the filter has no dead compares.
    std::vector<std::uint32_t> trapped;
    trapped.reserve(kTrappedAll.size());
    for (const std::uint64_t nr : kTrappedAll)
        if (nr != kNoSysno) trapped.push_back(static_cast<std::uint32_t>(nr));
    const std::size_t nTrapped = trapped.size();

    // Program layout (leaves LAST, so every match is a simple forward jump):
    //
    //   idx 0 : A = arch
    //   idx 1 : if (A == kArch) skip 1 else fall through   [JEQ jt=1,jf=0]
    //   idx 2 : RET ERRNO(ENOSYS) (foreign personality, e.g. i386 int 0x80)
    //   idx 3 : A = nr
    //   idx 4 : if (A >= X32_BIT) -> ENOSYS leaf             [JGE]
    //   idx 5 : if (A in [io_uring_setup, io_uring_register]) -> ENOSYS leaf
    //   idx 6 :   (second half of the range check)
    //   idx 7..7+n-1 : for each trapped nr: JEQ nr -> jump to TRACE leaf
    //   idx 7+n     : RET ALLOW   (no match -> run natively)
    //   idx 7+n+1   : RET TRACE   (matched -> notify the tracer)
    //   idx 7+n+2   : RET ERRNO(ENOSYS)
    //
    // SECURITY: the three ENOSYS gates close raw-path escapes. The audit arch
    // for x32 is AUDIT_ARCH_X86_64, so an x32 call (nr | 0x40000000) would
    // otherwise miss every JEQ and run open() etc. untranslated on the host;
    // an i386 `int 0x80` has a different arch and used to be ALLOWed outright;
    // io_uring's IORING_OP_OPENAT/STATX/RENAMEAT/... take paths from a shared
    // ring the kernel reads asynchronously, which no tracer can rewrite.
    // liburing users and runtimes (Go, Node, Rust tokio-uring) all fall back
    // to plain syscalls on ENOSYS.
    //
    // The x32 gate is emitted only where that personality exists, and the
    // io_uring numbers are translated like every other number, so neither is
    // an x86-64 literal leaking into an aarch64 filter.
    //
    // For the JEQ at position (7 + i), the TRACE leaf is at 7+n+1.
    // Statements strictly after this JEQ and before TRACE are:
    //   remaining JEQs (n-1-i) + the ALLOW leaf (1)  => jt = (n-1-i) + 1.
    std::vector<sock_filter> f;
    f.reserve(nTrapped + 10);

    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                         offsetof(seccomp_data, arch)));       // 0
    f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kArch, 1, 0)); // 1
    constexpr std::uint32_t kEnosys = SECCOMP_RET_ERRNO | 38u;  // ENOSYS
    constexpr std::uint32_t kX32Bit = 0x40000000u;
    // io_uring_setup/enter/register are contiguous on both arches; take the
    // span from the numbering authority rather than hardcoding 425..427.
    constexpr std::uint64_t kUringSetup =
        encode(kHostArch, abi::Sysno::io_uring_setup);
    constexpr std::uint64_t kUringRegister =
        encode(kHostArch, abi::Sysno::io_uring_register);
    f.push_back(BPF_STMT(BPF_RET | BPF_K, kEnosys));            // 2 (foreign arch)
    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                         offsetof(seccomp_data, nr)));          // 3

    // The gates between `A = nr` and the first JEQ. Emitting them
    // conditionally would shift every later index, so count them first and
    // let the jump arithmetic read the count.
    const bool emit_x32 = has_x32_personality(kHostArch);
    const bool emit_uring =
        kUringSetup != kNoSysno && kUringRegister != kNoSysno;
    const std::size_t nGates =
        (emit_x32 ? 1u : 0u) + (emit_uring ? 2u : 0u);
    const std::size_t firstJeq = 4 + nGates;

    // Jump distance to the ENOSYS leaf, which sits after the n JEQs, the
    // pread64 check and the ALLOW and TRACE leaves.
    //
    // pread64 is trapped only at offset 0: that is how a monitor rereads a
    // kept-open /proc file, which linuxity must regenerate. Every other
    // pread (databases, linkers) stays native.
    // UNTRAPPED(pread64,17): trapped below by argument, offset 0 only
    constexpr std::uint64_t kPread = encode(kHostArch, abi::Sysno::pread64);
    constexpr std::size_t kPre = 5;   // statements in the pread64 check
    const auto to_enosys = [&](std::size_t idx) {
        return static_cast<std::uint8_t>((firstJeq + nTrapped + kPre + 2) - idx - 1);
    };
    if (emit_x32) {
        f.push_back(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, kX32Bit,
                             to_enosys(f.size()), 0));
    }
    if (emit_uring) {
        // nr >= setup ? (fall through to the upper bound) : (skip it)
        f.push_back(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
                             static_cast<std::uint32_t>(kUringSetup), 0, 1));
        // nr > register ? (continue to the JEQs) : ENOSYS
        f.push_back(BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K,
                             static_cast<std::uint32_t>(kUringRegister), 0,
                             to_enosys(f.size())));
    }
    for (std::size_t i = 0; i < nTrapped; ++i) {
        std::uint8_t jt = static_cast<std::uint8_t>((nTrapped - 1 - i) + kPre + 1);
        f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                             trapped[i], jt, 0));                // firstJeq + i
    }
    // nr == pread64 && args[3] == 0 -> TRACE, else ALLOW (little-endian words)
    constexpr std::uint32_t kArg3 = offsetof(seccomp_data, args) + 3 * 8;
    f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                         static_cast<std::uint32_t>(kPread), 0, 4));
    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, kArg3));
    f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2));
    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, kArg3 + 4));
    f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0));
    f.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));  // 7 + n + kPre
    f.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE));  // + 1
    f.push_back(BPF_STMT(BPF_RET | BPF_K, kEnosys));            // + 2

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
