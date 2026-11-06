// linuxity/abi/syscall.hpp
//
// The syscall boundary: from a trapped register file to a typed subsystem call.
//
// A guest issues a syscall as an opaque tuple of arg words plus a number. We
// decode the arch-specific number into a canonical Sysno (see sysno.hpp),
// then switch on that identity — so the dispatcher is written ONCE and works
// for any guest ISA that equals the host ISA. Everything dangerous (guest
// pointers, untrusted lengths) is validated against the address space before
// the subsystem ever touches memory.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/sysno.hpp"
#include "linuxity/abi/types.hpp"
#include "linuxity/kernel/file_namespace.hpp"
#include "linuxity/kernel/machine.hpp"
#include "linuxity/kernel/process_table.hpp"
#include "linuxity/kernel/subsystem.hpp"
#include "linuxity/abi/identity.hpp"
#include "linuxity/abi/outcome.hpp"
#include "linuxity/abi/wire/at_flags.hpp"
#include "linuxity/abi/wire/dirent64.hpp"
#include "linuxity/abi/wire/open_flags.hpp"
#include "linuxity/abi/wire/stat.hpp"
#include "linuxity/loader/interp.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <sys/stat.h>
#include "linuxity/host/win_posix.hpp"
#include <optional>
#include <span>
#include <set>
#include <string>
#include <vector>

// -- Host portability: lstat ------------------------------------------------
// The core calls lstat(2) in exactly one place (is_symlink below), to avoid a
// pointless host chmod on a symlink. The Win32 CRT has no lstat and no
// S_ISLNK, because NTFS reparse points are not POSIX symlinks and the CRT
// does not pretend otherwise -- so on Windows the honest answer is "this
// path is not a POSIX symlink", and the chmod proceeds.
//
// Confining the difference to this one shim is what keeps the WHP backend
// from having to fork the core. (A full reparse-point query belongs in the
// Win32 host backend, not in the portable ABI layer.)
namespace lx::abi::hostcompat {

#if defined(_WIN32)
inline constexpr bool kHasLstat = false;
[[nodiscard]] inline bool path_is_symlink(const char*) noexcept { return false; }
// Read back the mode that actually landed on the host inode. Win32's stat
// has no lstat variant, but since there are no POSIX symlinks there, stat
// and lstat would agree anyway.
[[nodiscard]] inline bool host_mode_of(const char* path,
                                      std::uint32_t& mode) noexcept {
    struct ::stat st{};
    if (::stat(path, &st) != 0) return false;
    mode = static_cast<std::uint32_t>(st.st_mode);
    return true;
}
#else
inline constexpr bool kHasLstat = true;
[[nodiscard]] inline bool path_is_symlink(const char* path) noexcept {
    struct ::stat st{};
    return ::lstat(path, &st) == 0 && S_ISLNK(st.st_mode);
}
[[nodiscard]] inline bool host_mode_of(const char* path,
                                      std::uint32_t& mode) noexcept {
    struct ::stat st{};
    if (::lstat(path, &st) != 0) return false;
    mode = static_cast<std::uint32_t>(st.st_mode);
    return true;
}
#endif

} // namespace lx::abi::hostcompat

namespace lx::abi {

// The trapped register file: 6 args + the raw (arch-specific) syscall number.
struct Regs {
    std::array<std::uint64_t, 6> arg{};
    std::uint64_t nr{};
};


// A guest-memory accessor the dispatcher uses to copy_in/copy_out. Modeled as
// a concept so the dispatcher stays decoupled from the concrete AddressSpace;
// a trap backend that shares the guest's real memory (ptrace on the same
// pages) supplies a peek/poke over /proc/pid/mem or process_vm_readv.
template <class M>
concept GuestMem = requires(M m, UAddr a, std::span<std::byte> out,
                            std::span<const std::byte> in) {
    { m.copy_in(a, out) } -> std::same_as<Status>;   // guest -> host buffer
    { m.copy_out(a, in) } -> std::same_as<Status>;   // host buffer -> guest
};

// -- The dispatcher --------------------------------------------------------
// Generic over any kernel and any guest-memory accessor.
template <kernel::IsKernel K, GuestMem M>
class Syscalls {
public:
    Syscalls(K& k, M& mem, Arch arch) noexcept : k_{k}, mem_{mem}, arch_{arch} {}

    [[nodiscard]] Outcome dispatch(const Regs& r) {
        const Sysno sc = decode(arch_, r.nr);
        // Select the trapped task's per-process cwd for this syscall, so
        // chdir/fchdir/getcwd and every relative-path absolutize act on THIS
        // process's directory rather than a single shared one (a forked
        // child's chdir must not clobber the parent's cwd). Passing ppid lets
        // a first-seen child inherit the parent's cwd automatically.
        {
            auto id = ids();
            k_.files().set_current_pid(id.pid, id.ppid);
        }
        switch (sc) {
            // -- process lifecycle: let the task ACTUALLY exit in the kernel
            //    (forward), so the trap reaps it and attributes the code. In
            //    a multi-process tree only the root task's exit ends the run.
            case Sysno::exit:
            case Sysno::exit_group:
                return fwd();

            // -- signals: kill/tgkill/tkill target a GUEST pid in linuxity's
            //    own namespace. Forwarding the raw number would signal an
            //    unrelated HOST task (or fail). Emit a SIGNAL outcome; the
            //    loop maps the guest pid to its host tid and delivers there.
            //    kill(pid,sig): arg0=pid arg1=sig. tgkill(tgid,tid,sig):
            //    arg0=tgid arg2=sig (we signal the process). tkill(tid,sig):
            //    arg0=tid arg1=sig.
            case Sysno::kill:
                return sig(static_cast<std::int32_t>(r.arg[0]),
                           static_cast<std::int32_t>(r.arg[1]));
            // tkill/tgkill address a THREAD, so unlike kill they have no
            // process-group form: a non-positive id is EINVAL, not a group.
            // Both used to accept it and report success.
            case Sysno::tkill: {
                const auto tid = static_cast<std::int32_t>(r.arg[0]);
                if (tid <= 0) return eno(Errno::einval);
                return sig(tid, static_cast<std::int32_t>(r.arg[1]));
            }
            case Sysno::tgkill: {
                const auto tgid = static_cast<std::int32_t>(r.arg[0]);
                const auto tid  = static_cast<std::int32_t>(r.arg[1]);
                if (tgid <= 0 || tid <= 0) return eno(Errno::einval);
                return sig(tid, static_cast<std::int32_t>(r.arg[2]));
            }

            // -- identity + credentials. Each task answers with ITS OWN
            //    guest pid/tid/ppid (from the trap's live task map) so every
            //    process sees a coherent identity, not a fixed "pid 1". A
            //    backend without the identity bridge falls back to init.
            //
            //    The ANSWERS live in abi/identity.hpp, shared with the
            //    kernel-less backends: these are pure policy over state we
            //    already own, so three implementations was three chances to
            //    be wrong -- and Windows took one, hardcoding pid 1 for every
            //    process.
            case Sysno::getpid:  case Sysno::gettid:  case Sysno::getppid:
            case Sysno::getuid:  case Sysno::geteuid:
            case Sysno::getgid:  case Sysno::getegid: {
                const auto i = ids();
                if (auto a = identity_answer(sc, {i.pid, i.tid, i.ppid}))
                    return val(*a);
                return fwd();
            }

            // -- getresuid(ruid*,euid*,suid*) / getresgid(rgid*,egid*,sgid*):
            //    bash and sudo read these at startup to populate $UID/$EUID.
            //    Like getuid/geteuid they MUST answer 0 for our root-owned
            //    world; forwarded raw they return the HOST uid (e.g. 1000),
            //    which has no /etc/passwd entry -> bash's "I have no name!".
            //    Write all three id-out pointers (arg0/1/2) to 0.
            case Sysno::getresuid:
            case Sysno::getresgid:
                return do_getres(r);

            // -- benign process-init syscalls libc issues early ----------
            // set_tid_address carries no host resource; serve it trivially so
            // _start proceeds (return a plausible tid).
            case Sysno::set_tid_address:
                return val(ids().tid);

            // -- signal state MUST reach the real host task. rt_sigaction
            //    installs the guest's handler/disposition and
            //    rt_sigprocmask sets its blocked mask; if we faked success
            //    the host task would have NO handler and our delivered
            //    signal would kill it instead of running the guest's handler.
            //    Forward them so the traced task's real sigaction table and
            //    blocked mask match what the guest asked for.
            case Sysno::rt_sigaction:
            case Sysno::rt_sigprocmask:
            case Sysno::rt_sigpending:
            case Sysno::rt_sigsuspend:
            case Sysno::rt_sigreturn:
            case Sysno::sigaltstack:
                return fwd();

            // -- uname (virtual: report LINUXITY's identity, not the host)
            // The guest must believe it runs on linuxity, so we synthesize
            // the utsname and copy_out into the guest buffer ourselves
            // rather than forwarding to the host kernel.
            case Sysno::uname:
                return do_uname(uaddr(r.arg[0]));

            // -- process groups & sessions. A backend that keeps a REAL group
            //    model (the macOS backend does, in its shared pid table)
            //    advertises it and gets these forwarded; the flat fallback
            //    -- every task its own leader -- is only for backends that
            //    don't. The flat model is wrong for anything that treats a
            //    group as a unit: `timeout` calls setpgid(0,0) and then
            //    signals its group, and under the flat model that group
            //    silently included the shell that launched it.
            //
            //    The flat model still has to be SELF-CONSISTENT. setpgid is
            //    discarded, but bash's job-control setup then loops on
            //    "tcgetpgrp(tty) == getpgrp()" -- so if getpgrp reports the
            //    group bash just asked for while TIOCGPGRP reports the pid,
            //    the two never meet, bash gives up with "no job control" and
            //    turns OFF line editing (arrow keys echo as ^[[A). So record
            //    the group the guest set and answer BOTH from it.
            case Sysno::getpgrp:
                if constexpr (requires { mem_.models_process_groups(); }) return fwd();
                return val(flat_pgrp());
            case Sysno::getpgid:
                if constexpr (requires { mem_.models_process_groups(); }) return fwd();
                if (!flat_pid_exists(r.arg[0])) return eno(Errno::esrch);
                return val(r.arg[0] ? static_cast<std::int64_t>(r.arg[0])
                                    : flat_pgrp());
            case Sysno::getsid:
                if constexpr (requires { mem_.models_process_groups(); }) return fwd();
                if (!flat_pid_exists(r.arg[0])) return eno(Errno::esrch);
                return val(r.arg[0] ? static_cast<std::int64_t>(r.arg[0])
                                    : ids().pid);
            case Sysno::setpgid: {
                if constexpr (requires { mem_.models_process_groups(); }) return fwd();
                // setpgid(pid, pgid): either argument may be 0, meaning "the
                // caller". Only the CALLER's own group is tracked -- that is
                // all tcgetpgrp needs, and it keeps this a pure bookkeeping
                // note rather than a second process-group model.
                if (!flat_pid_exists(r.arg[0])) return eno(Errno::esrch);
                const std::int32_t who = static_cast<std::int32_t>(r.arg[0]);
                if (who == 0 || who == ids().pid) {
                    const std::int32_t grp = static_cast<std::int32_t>(r.arg[1]);
                    flat_pgrp_ = grp ? grp : ids().pid;
                }
                return val(0);                     // accepted, flat model
            }
            case Sysno::setsid:
                if constexpr (requires { mem_.models_process_groups(); }) return fwd();
                flat_pgrp_ = ids().pid;            // a new session resets it
                return val(ids().pid);             // new session == pid
            // nice 0 for everything, but the KERNEL still validates `which`:
            // only PRIO_PROCESS/PRIO_PGRP/PRIO_USER (0/1/2) exist and
            // anything else is EINVAL. Returning 0 for any argument meant a
            // bogus `which` succeeded where the kernel fails -- caught by the
            // creds probe diffing against the live kernel.
            case Sysno::getpriority:
            case Sysno::setpriority:
                if (r.arg[0] > 2) return eno(Errno::einval);
                return val(0);

            // -- sysinfo(2): report linuxity's virtual machine (total/free RAM,
            //    process count, a plausible uptime), not the host's numbers.
            case Sysno::sysinfo:
                return do_sysinfo(uaddr(r.arg[0]));

            // -- sched_getaffinity(pid, cpusetsize, mask): the guest may run
            //    on N CPUs; report a mask with our ncpu bits set so a runtime
            //    sizes its thread pool to linuxity's machine, not the host.
            case Sysno::sched_getaffinity:
                return do_sched_getaffinity(r);

            // -- the filesystem namespace (virtual: the guest's whole tree
            //    is linuxity's; host-backed paths get translated + forwarded,
            //    virtual paths get synthesized). This is what makes --root a
            //    real, unprivileged Linux world.
            case Sysno::open:        return path_open(r, 0, /*at=*/false);
            case Sysno::openat:      return path_open(r, 1, /*at=*/true);
            // creat(path, mode) is open(path, O_CREAT|O_WRONLY|O_TRUNC, mode).
            // Its flags are NOT in a register -- they are implied by the
            // syscall itself -- so it needs the explicit-flags entry point.
            //
            // This was an unhandled AND untrapped path-bearing syscall, i.e. a
            // real sandbox escape: a guest calling creat("/tmp/x") had the path
            // passed straight to the host kernel and created the file on the
            // HOST filesystem, outside the rootfs. Verified before fixing --
            // creat("/tmp/LINUXITY_ESCAPE_PROOF") returned fd 4 and the file
            // appeared in the host's /tmp, with no /tmp in the guest tree at
            // all. glibc's creat() routes to openat so this is rare in
            // practice, but a direct syscall() reaches it, and "rare" is not a
            // security boundary.
            case Sysno::creat:
                return path_open_flags(r, 0, /*at=*/false,
                                       wire::bits(wire::OpenFlag::creat) |
                                       wire::bits(wire::OpenFlag::wronly) |
                                       wire::bits(wire::OpenFlag::trunc));
            // openat2(dirfd, path, struct open_how*, size): the modern openat.
            // Its open flags live in the FIRST 8 bytes of the open_how struct
            // (arg[2]) rather than a register, so read them from guest memory
            // and drive the same translation/injection path as openat.
            case Sysno::openat2:     return path_openat2(r);
            case Sysno::stat:        return path_stat(r, 0, false, true);
            case Sysno::lstat:       return path_stat(r, 0, false, false);
            case Sysno::access:      return path_at(r, 0, false);
            case Sysno::chdir:       return do_chdir(r);
            case Sysno::newfstatat: {
                // Honor AT_SYMLINK_NOFOLLOW (flags = arg3, bit 0x100): with it
                // set, stat the LINK itself (follow=false) so a symlink reports
                // S_IFLNK, not its target's type. git probes symlink support
                // via fstatat(...,AT_SYMLINK_NOFOLLOW) + S_ISLNK; following the
                // link made it see a regular file and disable symlinks.
                bool nofollow = wire::has_at(r.arg[3], wire::AtFlag::symlink_nofollow);
                return path_stat(r, 1, true, !nofollow);
            }
            case Sysno::statx:       return path_statx(r);
            case Sysno::faccessat:
            case Sysno::faccessat2:  return path_at(r, 1, true);
            case Sysno::readlink:    return do_readlink(r, 0, false);
            case Sysno::readlinkat:  return do_readlink(r, 1, true);
            case Sysno::getcwd:      return do_getcwd(r);
            case Sysno::getdents64:  return do_getdents64(r);
            case Sysno::lseek: {
                // rewinddir()/seekdir() on a VIRTUAL or overlay-union directory:
                // our stream keeps its own position, so a real lseek on the
                // backing fd rewinds the WRONG thing -- the host fd sees only
                // the upper layer (or nothing, for a synthesized dir) while
                // our cursor stays at EOF, and the next readdir pass returns
                // zero entries.
                //
                // This case existed but was UNREACHABLE: lseek was missing
                // from the seccomp trapped set, so it ran natively and never
                // reached us. That is what made `pacman -Q` report nothing --
                // libalpm rewinds the package DB before loading it. See the
                // note next to 8 in runtime/linux/seccomp_filter.hpp.
                //
                // COST, measured rather than estimated. Trapping a syscall
                // is ~4.7us on this machine (a getpid that does nothing
                // costs the same), against ~70ns untrapped -- so an lseek on
                // a REGULAR file pays ~60x for a correctness problem only
                // directories have. The handler itself is free: one hash
                // lookup that misses, then fwd().
                //
                // It stays trapped because the alternative is wrong, not
                // because it is cheap: `pacman -Q` reported nothing without
                // it. The earlier note here said "~3% on ls -lR", which is
                // true of that WORKLOAD (lseek is rare in it) and says
                // nothing about the call. tests/bench_syscall.c measures
                // both, so the distinction stops being guesswork.
                //
                // Position is a BYTE cookie matching the d_off getdents64
                // hands out, so seek arithmetic on those values works. Map
                // the target back to an entry by walking record lengths.
                const int fd = static_cast<int>(r.arg[0]);
                if (auto* ds = k_.files().dir_stream(fd)) {
                    const auto off = static_cast<std::int64_t>(r.arg[1]);
                    const int whence = static_cast<int>(r.arg[2]);
                    std::int64_t target =
                        whence == 0 ? off
                      : whence == 1 ? static_cast<std::int64_t>(ds->byte_off) + off
                      : -1;
                    if (target < 0) return eno(Errno::einval);
                    // Walk to the entry whose record starts at `target`. A
                    // cookie past the last record is end-of-directory.
                    std::uint64_t cur = 0;
                    std::size_t idx = 0;
                    for (; idx < ds->entries.size(); ++idx) {
                        if (cur >= static_cast<std::uint64_t>(target)) break;
                        cur += wire::dirent_reclen(ds->entries[idx].name.size());
                    }
                    ds->pos      = idx;
                    ds->byte_off = cur;
                    return val(static_cast<std::int64_t>(ds->byte_off));
                }
                return fwd();
            }

            // -- statfs(path, buf): translate the path and REDIRECT so the
            //    host reports the overlay filesystem's stats. fstatfs acts on
            //    an already-open (already-translated) fd — forward it. Virtual
            //    procfs/sysfs paths have no real backing fs, so synthesize a
            //    plausible statfs (tmpfs-like) for them instead of leaking the
            //    host's numbers.
            case Sysno::statfs:      return path_statfs(r);
            case Sysno::fstatfs:     return fwd();

            // -- chroot(path): a guest chroot would chroot our HOST child to
            //    an untranslated host path — an isolation break. linuxity's
            //    path translation already confines the guest to the rootfs, so
            //    accept it vacuously (the guest believes it chrooted; the host
            //    process is unchanged) after verifying the target exists.
            case Sysno::chroot:      return do_chroot(r);

            // -- extended attributes. The path variants (get/set/list/remove
            //    xattr and their l* no-follow forms) carry a guest path in
            //    arg0 that must be translated to the overlay host path; the f*
            //    variants act on an already-open fd and just forward. Writes
            //    (set/remove) go through for_write so they land in the upper
            //    layer, matching `setcap`, `tar --xattrs`, `cp -a`.
            case Sysno::getxattr:
            case Sysno::listxattr:    return path_xattr(r, /*for_write=*/false);
            case Sysno::lgetxattr:
            case Sysno::llistxattr:   return path_xattr(r, /*for_write=*/false, /*follow=*/false);
            case Sysno::setxattr:
            case Sysno::removexattr:  return path_xattr(r, /*for_write=*/true);
            case Sysno::lsetxattr:
            case Sysno::lremovexattr: return path_xattr(r, /*for_write=*/true, /*follow=*/false);
            // The *at xattr calls (6.13+): path in arg[1], relative to the
            // dirfd in arg[0]. These were decoded on aarch64 but NOT on
            // x86-64, so there they fell through to the host with an
            // untranslated path -- a confinement hole, verified before fixing
            // (getxattrat of "/etc/hostname" reached the HOST's file from a
            // guest tree that has none). AT_SYMLINK_NOFOLLOW lives in arg[2].
            case Sysno::getxattrat:
            case Sysno::listxattrat:
                return path_xattr(r, /*for_write=*/false,
                                  !wire::has_at(r.arg[2],
                                                wire::AtFlag::symlink_nofollow),
                                  /*path_arg=*/1, /*at=*/true);
            case Sysno::setxattrat:
            case Sysno::removexattrat:
                return path_xattr(r, /*for_write=*/true,
                                  !wire::has_at(r.arg[2],
                                                wire::AtFlag::symlink_nofollow),
                                  /*path_arg=*/1, /*at=*/true);
            case Sysno::fgetxattr:    case Sysno::flistxattr:
                return fwd();
            // fsetxattr/fremovexattr act on an already-open fd (this is what
            // libarchive/pacman actually use to restore a package's xattrs).
            // A privileged namespace (security.*/system.*/trusted.*) can never
            // be applied by our unprivileged host -> the forwarded call EPERMs
            // and libarchive warns "Cannot restore extended attributes:
            // security.capability". Fake success (name = arg1), same policy as
            // the path variants above; other namespaces still forward.
            case Sysno::fsetxattr:
            case Sysno::fremovexattr: {
                std::string name = read_cstr(uaddr(r.arg[1]));
                if (name.rfind("security.", 0) == 0 ||
                    name.rfind("system.",   0) == 0 ||
                    name.rfind("trusted.",  0) == 0)
                    return val(0);
                return fwd();
            }

            // -- inotify_add_watch(fd, path, mask): translate the guest path
            //    (arg1) and REDIRECT so a file watcher registers against the
            //    ROOTFS tree, not the host's. inotify_init[1]/inotify_rm_watch
            //    carry no path and fall through to forward.
            case Sysno::inotify_add_watch:
                return path_watch(r, /*path_arg=*/1);
            // -- fanotify_mark(fanotify_fd, flags, mask, dirfd, path): the
            //    path is arg4 with dirfd arg3. Translate it so even a
            //    privileged host acts on the rootfs path, never the raw guest
            //    string against the host tree. (fanotify itself needs
            //    CAP_SYS_ADMIN and will EPERM unprivileged — that's fine.)
            case Sysno::fanotify_mark:
                return path_watch(r, /*path_arg=*/4, /*at=*/true);

            // -- file-handle API: name_to_handle_at / open_by_handle_at. The
            //    handle encodes HOST-filesystem inode identity; round-tripping
            //    it would leak host-fs structure into the guest and can't be
            //    made coherent with the overlay. Refuse with ENOTSUP — glibc,
            //    nfs-utils, and tar's handle fast-paths fall back to path ops.
            case Sysno::name_to_handle_at:
            case Sysno::open_by_handle_at:
                return eno(Errno::enotsup);

            // -- the new mount API (fsopen/fsconfig/fsmount/move_mount/
            //    open_tree/mount_setattr) and mount-info API (statmount/
            //    listmount). All are privileged and describe/mutate the HOST
            //    mount namespace. linuxity owns a synthesized mount table
            //    surfaced through /proc/self/mountinfo (already virtualized),
            //    so refuse these with ENOSYS: util-linux/systemd fall back to
            //    classic mount(2) + the procfs mount views we serve.
            case Sysno::fsopen:        case Sysno::fsconfig:
            case Sysno::fsmount:       case Sysno::move_mount:
            case Sysno::open_tree:     case Sysno::mount_setattr:
            case Sysno::statmount:     case Sysno::listmount:
            // fspick takes a PATH, so refusing it here (rather than letting it
            // fall through to the host) is what keeps that path inside our
            // namespace. It was neither trapped nor handled before.
            case Sysno::fspick:
            // open_tree_attr / file_getattr / file_setattr (6.14+) also carry
            // a path. linuxity models no mount namespaces and no per-file
            // attribute API, so ENOSYS is the honest answer -- but it must be
            // ANSWERED here, because forwarding would hand the host a guest
            // path. listns enumerates namespaces we do not have.
            case Sysno::open_tree_attr:
            case Sysno::file_getattr:
            case Sysno::file_setattr:
            case Sysno::listns:
                return eno(Errno::enosys);

            // -- classic mount/umount: an unprivileged guest cannot really
            //    (u)mount, and the well-known pseudo-filesystems (proc, sysfs,
            //    devtmpfs, tmpfs on /tmp,/run,/dev/shm) already EXIST as
            //    virtual/host mounts in our namespace. So accept them as
            //    satisfied no-ops: init scripts and containers that mount
            //    /proc etc. proceed instead of aborting on EPERM. A real
            //    block-device mount has no backing here — still accepted
            //    vacuously (the guest sees its target directory unchanged).
            case Sysno::mount: {
                // Accepted as a satisfied no-op, but NOT unconditionally. The
                // kernel validates arguments before it ever consults
                // privilege, and a guest told that mounting "nosuchfs"
                // succeeded will go on to use a filesystem that is not there.
                // Same mistake as the landlock no-op: say yes to the request,
                // not to nonsense.
                //
                // Only the filesystem TYPE is checked, against the names our
                // /proc/filesystems advertises. The source and target are
                // not: a mount's target is routinely a directory the guest is
                // about to populate, and second-guessing that is how a
                // working init script starts failing.
                const std::string type = read_cstr(uaddr(r.arg[2]));
                if (!type.empty() && !known_fs_type(type))
                    return eno(Errno::enodev);
                // A BIND mount's source is a real path that must exist --
                // unlike a filesystem mount, where the source is a device
                // name or ignored entirely. Accepting a bind from a missing
                // directory tells the guest its tree is in two places when
                // it is in neither.
                constexpr std::uint64_t kMsBind = 0x1000;
                if (r.arg[3] & kMsBind) {
                    const std::string src = read_cstr(uaddr(r.arg[0]));
                    if (!src.empty()) {
                        const auto pc = k_.files().classify(
                            k_.files().absolutize(src, k_.files().cwd()));
                        if (pc.realm == kernel::Realm2::absent)
                            return eno(pc.error);
                        if (pc.realm == kernel::Realm2::host_backed &&
                            !pc.host_path.empty())
                            if constexpr (requires { mem_.stat_host_path(pc.host_path); })
                                if (!mem_.stat_host_path(pc.host_path))
                                    return eno(Errno::enoent);
                    }
                }
                // REMEMBER it. The mount is a no-op on our side, but the
                // guest now believes something is mounted there, and the
                // matching umount2 has to agree -- otherwise a program that
                // mounts and then unmounts its own scratch tree gets EINVAL
                // for an unmount that should obviously work.
                if (const std::string tgt = read_cstr(uaddr(r.arg[1])); !tgt.empty())
                    guest_mounts_.insert(k_.files().absolutize(tgt, k_.files().cwd()));
                return val(0);
            }
            case Sysno::umount2: {
                // Unmounting something that was never mounted is EINVAL, and
                // that is how a program tests whether it holds a mount. Both
                // OUR mounts and the ones the guest asked for count.
                const std::string raw = read_cstr(uaddr(r.arg[0]));
                if (raw.empty()) return eno(Errno::efault);
                const std::string tgt =
                    k_.files().absolutize(raw, k_.files().cwd());
                if (!guest_mounts_.erase(tgt) &&
                    !k_.files().is_mount_point(tgt))
                    return eno(Errno::einval);
                return val(0);
            }

            // -- privileged system-administration ops with no coherent guest
            //    meaning. pivot_root swaps the root mount; swapon/swapoff
            //    manage HOST swap; acct toggles HOST process accounting;
            //    quotactl touches HOST quotas; ustat reports a HOST device's
            //    fs stats. Never forward a raw host-scoped operation — refuse
            //    cleanly the way the real kernel would for an unprivileged or
            //    unsupported caller.
            case Sysno::pivot_root:
            case Sysno::swapon:
            case Sysno::swapoff:
            case Sysno::acct:
                return eno(Errno::eperm);
            case Sysno::quotactl:
            case Sysno::ustat:
                return eno(Errno::enosys);

            // -- execve/execveat: translate the program path to its real
            //    host location under the rootfs, then let the kernel exec it.
            //    argv/envp are consumed from the OLD image before the new one
            //    loads, so only the path needs rewriting. This keeps forked
            //    shell children inside linuxity's namespace.
            case Sysno::execve:      return path_exec(r, 0);
            case Sysno::execveat:    return path_exec(r, 1);

            // -- fd-lifecycle bookkeeping: keep our guest fd->path table in
            //    sync so readlinkat/getdents on the fd recover its path.
            case Sysno::close:       return do_close(r);

            // -- fd DUPLICATION: forward the real dup, then mirror the source
            //    fd's path / virtual-dir binding onto the new fd so *at calls
            //    relative to the dup resolve correctly (fixes rm -rf's fts).
            case Sysno::dup:         return do_dup(r);
            case Sysno::dup2:        return do_dup2(r);
            case Sysno::dup3:        return do_dup2(r);
            case Sysno::fcntl:       return do_fcntl(r);

            // -- NAMESPACE MUTATION. Each names a guest path that must be
            //    translated to its overlay UPPER host path (for_write=true)
            //    before the kernel touches the real filesystem; otherwise the
            //    raw guest path would hit the host's own /usr, /etc, .... This
            //    is what lets a package manager install its whole world into
            //    the rootfs. Single-path ops reuse the redirect machinery;
            //    the create-class ones also request implicit parent mkdir so
            //    a write into a fresh upper layer doesn't ENOENT.
            //
            //    path_arg picks the register: the *at forms carry a dirfd in
            //    arg0 and the path in arg1; the legacy forms carry the path in
            //    arg0. mkdir/mknod CREATE, so make_parents; rmdir/unlink
            //    remove; chmod/chown/truncate/utimensat retarget metadata.
            case Sysno::mkdir:      return path_mut(r, 0, false, Wi::parents_only, true);
            case Sysno::mkdirat:    return path_mut(r, 1, true,  Wi::parents_only, true);
            case Sysno::mknod:      return path_mut(r, 0, false, Wi::parents_only, true);
            case Sysno::mknodat:    return path_mut(r, 1, true,  Wi::parents_only, true);
            case Sysno::rmdir:      return path_mut(r, 0, false, Wi::remove);
            case Sysno::unlink:     return path_mut(r, 0, false, Wi::remove);
            case Sysno::unlinkat:   return path_mut(r, 1, true,  Wi::remove);
            case Sysno::chmod:      return do_chmod(r, 0, false, Wi::copy_leaf);
            case Sysno::fchmodat:   return do_chmod(r, 1, true,  Wi::copy_leaf);
            // fchmodat2(dirfd, path, mode, flags): fchmodat WITH flags, so
            // AT_SYMLINK_NOFOLLOW finally works. Same path argument, so the
            // same translation -- without this it reached the backend
            // untranslated and every symlink chmod failed ENOENT, which is
            // what made `pacman -Syu` warn "Can't set permissions to 0777"
            // for thousands of files.
            case Sysno::fchmodat2:  return do_chmod(r, 1, true,  Wi::copy_leaf);
            // chown/lchown/fchown/fchownat: linuxity presents a ROOT-OWNED
            // world and the guest runs as our single UNPRIVILEGED host process,
            // so a forwarded chown (even to uid 0) EPERMs and breaks `tar -p`,
            // `install -o`, `useradd`. Instead we RECORD the guest-intended
            // owner in the shadow metadata store and report success: a later
            // stat overlays the recorded uid/gid, so ownership round-trips
            // coherently (fake_id0-grade) without touching the real inode.
            case Sysno::chown:      return do_chown(r, 0, 1, 2, false, true);
            case Sysno::lchown:     return do_chown(r, 0, 1, 2, false, false);
            // fchownat's flags word carries AT_SYMLINK_NOFOLLOW, which is how
            // a caller asks for lchown semantics through the *at form --
            // `cp -a` and `tar -x` both use it. Hardcoding either answer
            // makes one of the two spellings wrong.
            case Sysno::fchownat:
                return do_chown(r, 1, 2, 3, true,
                                !wire::has_at(r.arg[4],
                                              wire::AtFlag::symlink_nofollow));
            case Sysno::fchown:     return do_fchown(r);
            case Sysno::truncate:   return path_mut(r, 0, false, Wi::copy_leaf);
            case Sysno::utimes:     return path_mut(r, 0, false, Wi::copy_leaf);
            case Sysno::utime:      return path_mut(r, 0, false, Wi::copy_leaf);
            case Sysno::utimensat:  return path_mut(r, 1, true,  Wi::copy_leaf);
            case Sysno::futimesat:  return path_mut(r, 1, true,  Wi::copy_leaf);
            // fchmod acts on an already-open fd: record the guest-intended
            // mode against the fd's bound path in the shadow store, then
            // forward (the host applies what bits it can). ftruncate/fchdir
            // carry no metadata, so just forward.
            case Sysno::fchmod:     return do_fchmod(r);
            case Sysno::ftruncate:  return fwd();
            case Sysno::fchdir:     return do_fchdir(r);

            // -- TWO-PATH mutations: both operands are guest paths. rename /
            //    link translate both; symlink stores its first operand as the
            //    link's literal text (guest-absolute, NOT resolved on the
            //    host) and translates only the destination.
            case Sysno::rename:     return path_mut2(r, 0, 1, false, false, true);
            case Sysno::renameat:   return path_mut2(r, 1, 3, true,  true, true);
            case Sysno::renameat2:  return path_mut2(r, 1, 3, true,  true, true);
            case Sysno::link:       return path_mut2(r, 0, 1, false, false, false);
            case Sysno::linkat:     return path_mut2(r, 1, 3, true,  true, false);
            case Sysno::symlink:    return path_symlink(r, 0, 1, false);
            case Sysno::symlinkat:  return path_symlink(r, 0, 2, true);

            // -- PRIVILEGE DROPS. linuxity presents a root-owned world and the
            //    guest runs as our single unprivileged host process. A real
            //    setuid/setgid to a non-root user (pacman's 'alpm', apk's
            //    build user) would EPERM on the host and abort the program.
            //    Ownership is already virtually root and there is only ONE
            //    identity to be, so accept every privilege change vacuously:
            //    the guest believes it dropped to the sandbox user; the host
            //    process is untouched. Subsequent geteuid/getuid still report
            //    0 (the guest's coherent root world).
            case Sysno::setuid:     case Sysno::setgid:
            case Sysno::setreuid:   case Sysno::setregid:
            case Sysno::setresuid:  case Sysno::setresgid:
            case Sysno::setfsuid:   case Sysno::setfsgid:
            case Sysno::setgroups:  return val(0);

            // -- LANDLOCK (pacman 7's download sandbox). We cannot apply an
            //    LSM ruleset to a ptraced tree, but linuxity's own namespace
            //    already confines the guest to the rootfs. Accept the sandbox
            //    calls as satisfied no-ops so pacman proceeds instead of
            //    treating the failure as fatal. create_ruleset returns a
            //    plausible ruleset fd number (a small positive int); add_rule
            //    and restrict_self return success.
            case Sysno::landlock_create_ruleset:
                // If the guest is only querying the ABI version (flags has
                // LANDLOCK_CREATE_RULESET_VERSION == 1 and attr==NULL), report
                // a supported version; otherwise hand back a dummy ruleset fd.
                return val((r.arg[2] & 1u) ? 1 : 3);
            case Sysno::landlock_add_rule:
                // Accepted as a no-op, but NOT unconditionally: the kernel
                // validates its arguments before it ever consults policy, and
                // a null rule_attr is EFAULT. Returning 0 for anything at all
                // means a sandbox library probing for support with a
                // deliberately bad call concludes the opposite of the truth.
                // An unknown rule type is EINVAL for the same reason.
                if (r.arg[2] == 0) return eno(Errno::efault);
                if (r.arg[1] != 1 /*LANDLOCK_RULE_PATH_BENEATH*/ &&
                    r.arg[1] != 2 /*LANDLOCK_RULE_NET_PORT*/)
                    return eno(Errno::einval);
                return val(0);
            case Sysno::landlock_restrict_self:
                return val(0);

            // -- AF_UNIX bind/connect: the chroot'd guest resolves an
            //    absolute sun_path correctly on its own, so we forward the
            //    call unchanged. For a bind we first materialize the socket's
            //    parent directory chain in the writable overlay upper (via
            //    do_sockaddr_un) so a socket whose parent only exists in the
            //    lower layer still has a writable home. arg1 = sockaddr*,
            //    arg2 = socklen.
            case Sysno::bind:
                return do_sockaddr_un(r, /*for_bind=*/true);
            case Sysno::connect:
                return do_sockaddr_un(r, /*for_bind=*/false);

            // -- prctl(PR_SET_DUMPABLE, 0): a security-conscious guest
            //    (gpg-agent, dirmngr, ssh-agent) makes itself non-dumpable so
            //    other processes can't read its memory. But linuxity IS the
            //    kernel: it MUST read guest memory to translate paths/sockaddrs
            //    and service syscalls. A non-dumpable task also blocks our
            //    unprivileged ptrace peek, breaking AF_UNIX path translation
            //    (the socket then leaks to the host). So we ACCEPT the call
            //    (return 0) without dropping dumpability. PR_GET_DUMPABLE then
            //    reports the real (still-dumpable) state, forwarded normally.
            //    Every other prctl forwards unchanged.
            case Sysno::prctl: {
                const int op = static_cast<int>(r.arg[0]);
                if (op == 4 /*PR_SET_DUMPABLE*/) return val(0);
                // PR_SET_NAME(15) renames the thread, and /proc/<pid>/comm is
                // the SAME FACT read back. procfs answers comm from our own
                // process table, which never learned about the rename, so the
                // two disagreed: a runtime that sets its thread name and then
                // reads comm (every JVM, Go runtime and thread-pool logger
                // does) saw the old one. Forward so the host applies it, and
                // record it so our view matches.
                if (op == 15 /*PR_SET_NAME*/) {
                    std::array<std::byte, 16> raw{};
                    if (mem_.copy_in(uaddr(r.arg[1]), raw)) {
                        std::string nm;
                        for (std::byte b : raw) {
                            const char c = static_cast<char>(b);
                            if (c == '\0') break;
                            nm.push_back(c);
                        }
                        if (!nm.empty()) k_.procs().set_comm(ids().pid, nm);
                    }
                }
                return fwd();
            }

            // -- ioctl: MOST requests act on a real host fd (TCGETS, winsize,
            //    FIONREAD, ...) and must forward. But the JOB-CONTROL group
            //    of tty ioctls read/write PIDs, and the host tty's foreground
            //    process group is our host child's pgid — a number that has
            //    NOTHING to do with the guest's flat pid space. A guest shell
            //    (busybox ash, bash) compares TIOCGPGRP against its own
            //    getpgrp(): when the host answer doesn't match, it believes it
            //    is a BACKGROUND job, tries to seize the terminal, and spins
            //    forever (ioctl/getpgid/kill in a tight loop pinning a core).
            //    Virtualize these so the guest's session leader owns its tty:
            //    report the caller's own pgrp as the foreground group and
            //    accept TIOCSPGRP as a satisfied no-op.
            case Sysno::ioctl:
                return do_ioctl(r);

            // -- everything else: FORWARD to the real host kernel. -------
            // Memory (mmap/brk/mprotect) MUST run in the child so it gets
            // real pages in its own address space; file I/O, arch_prctl,
            // clock, random, etc. likewise need real host action.
            // This is what carries native libc all the way to main().
            default:
                return fwd();
        }
    }

private:
    // Mount points the GUEST asked for. Its mounts are no-ops on our side,
    // but it believes they exist, so the matching umount2 must succeed --
    // a program that mounts and then unmounts its own scratch tree should
    // not get EINVAL. Only the targets are kept; nothing is really mounted.
    std::set<std::string> guest_mounts_;

    // Is this a filesystem type our namespace actually offers? The set is
    // the one /proc/filesystems advertises, so a guest that reads that file
    // and a guest that calls mount(2) are told the same story.
    [[nodiscard]] static bool known_fs_type(std::string_view t) noexcept {
        return t == "proc" || t == "sysfs" || t == "tmpfs" || t == "ext4" ||
               t == "devtmpfs" || t == "devpts" || t == "overlay" ||
               t == "ramfs" || t == "bind" || t == "none";
    }

    // The four shorthands every handler returns through. They now just name
    // a fate, so no handler touches a flag or a payload field directly.
    static Outcome val(std::int64_t v) { return Outcome::value(v); }
    static Outcome fwd() { return Outcome::forward(); }
    static Outcome sig(std::int32_t pid, std::int32_t signum) {
        return Outcome::raise_at(pid, signum);
    }
    static Outcome eno(Errno e) { return Outcome::error(e); }

    // Does this guest pid name a live process? 0 means "the caller", which
    // always does. Used by the flat getpgid/getsid/setpgid: they echoed any
    // pid back as success, so getsid(0x3fffffff) reported a session instead
    // of ESRCH -- caught by the creds probe diffing against the live kernel.
    [[nodiscard]] bool flat_pid_exists(std::uint64_t pid) {
        if (pid == 0) return true;
        const auto p = static_cast<std::int32_t>(pid);
        if (p < 0) return false;
        if (p == ids().pid) return true;
        return k_.procs().has(p);
    }

    // The caller's process group under the flat model: whatever setpgid last
    // asked for, defaulting to its own pid (every task its own leader). Only
    // meaningful when the backend does NOT model real groups; those forward.
    [[nodiscard]] std::int32_t flat_pgrp() {
        return flat_pgrp_ ? flat_pgrp_ : ids().pid;
    }
    std::int32_t flat_pgrp_{0};

    // The trapped task's guest identity. When the memory backend also exposes
    // the live task map (the ptrace trap does), report that task's real
    // pid/tid/ppid; otherwise fall back to init (pid 1, ppid 0) so the
    // dispatcher stays usable with a bare GuestMem in tests.
    struct Ids { std::int32_t pid, tid, ppid; };
    [[nodiscard]] Ids ids() {
        if constexpr (requires { mem_.current_ids(); }) {
            auto t = mem_.current_ids();
            return Ids{t.pid, t.tid, t.ppid};
        } else {
            return Ids{static_cast<std::int32_t>(k_.self().raw()), 
                       static_cast<std::int32_t>(k_.self().raw()), 0};
        }
    }

    // Read a NUL-terminated C string from guest memory (bounded).
    //
    // process_vm_readv reads a WHOLE iovec or nothing: if a 64-byte chunk
    // straddles the end of a mapped page into an unmapped one, the entire
    // chunk read faults (EFAULT) even though the string's bytes before the
    // page boundary are perfectly valid. A dynamic loader routinely places a
    // library path right up against a page end, so a naive chunked read loses
    // the path and yields "" — which then classifies as "/" and REDIRECTS the
    // open to the overlay ROOT (a directory), so the loader's read/mmap gets
    // EISDIR ("cannot read file data"). To avoid that, on a chunk fault we
    // fall back to reading up to the next page boundary, then byte-by-byte,
    // so we always recover the maximal valid prefix up to the NUL.
    [[nodiscard]] std::string read_cstr(UAddr a) {
        std::string s;
        const std::uint64_t base = value(a);
        std::uint64_t off = 0;
        constexpr std::uint64_t kPage = 4096;
        for (;;) {
            // How many bytes remain until the next page boundary from here;
            // never read across it in one process_vm_readv (that's the read
            // that can spuriously fault on a valid string).
            std::uint64_t to_page = kPage - ((base + off) & (kPage - 1));
            std::size_t want = static_cast<std::size_t>(to_page < 64 ? to_page : 64);
            std::array<std::byte, 64> chunk{};
            std::span<std::byte> dst{chunk.data(), want};
            if (mem_.copy_in(uaddr(base + off), dst)) {
                for (std::size_t i = 0; i < want; ++i) {
                    char c = static_cast<char>(chunk[i]);
                    if (c == '\0') return s;
                    s.push_back(c);
                    if (s.size() > 4096) return s;
                }
                off += want;
                continue;
            }
            // Even the page-bounded read faulted. Recover byte-by-byte so a
            // valid prefix isn't lost to one unreadable trailing byte.
            bool progressed = false;
            for (std::size_t i = 0; i < want; ++i) {
                std::array<std::byte, 1> one{};
                if (!mem_.copy_in(uaddr(base + off + i), one)) return s;
                progressed = true;
                char c = static_cast<char>(one[0]);
                if (c == '\0') return s;
                s.push_back(c);
                if (s.size() > 4096) return s;
            }
            if (!progressed) return s;
            off += want;
        }
    }

    // The path bound to a guest dirfd, or empty for AT_FDCWD (-100).
    // A dirfd is an `int` in the kernel ABI: only the low 32 bits of the
    // register are meaningful. glibc may pass AT_FDCWD (-100) as a bare 32-bit
    // value (0xFFFFFF9C) that is NOT sign-extended in the 64-bit register, so
    // we MUST narrow to int32 before comparing/looking up — otherwise -100
    // reads as 4294967196, misses the AT_FDCWD check, and the path resolves
    // relative to a bogus "fd" instead of the cwd (breaking `mkdir -p`, and
    // every *at call a relative path is passed to).
    [[nodiscard]] std::string_view dir_of(std::int64_t dirfd) const {
        std::int32_t fd = static_cast<std::int32_t>(dirfd);
        if (fd == wire::kAtFdCwd) return {};
        return k_.files().path_of_fd(fd);
    }

    // An *at syscall with a RELATIVE path needs the dirfd's directory to
    // resolve against. dir_of returns "" for an fd whose path we never
    // recorded, and absolutize then treats "" as the CWD -- so the call
    // silently resolved against the wrong directory. For a bad fd that turned
    // EBADF into ENOENT; for a good-but-unrecorded fd it would resolve the
    // wrong file, which is worse.
    //
    // Either way we cannot answer, so FORWARD and let the host kernel decide.
    // It owns the real fd table and returns the true errno. Found by the
    // differential harness (newfstatat on a bad dirfd).
    [[nodiscard]] bool at_dirfd_unresolvable(const Regs& r, int path_arg,
                                             bool at) {
        if (!at) return false;
        return at_dirfd_unresolvable(
            r, read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)])));
    }
    // Same check on a path already read. Each read_cstr is a guest-memory
    // copy, and path_stat used to do three of them for one stat.
    [[nodiscard]] bool at_dirfd_unresolvable(const Regs& r,
                                             std::string_view raw) const {
        const auto dirfd = static_cast<std::int64_t>(r.arg[0]);
        if (static_cast<std::int32_t>(dirfd) == wire::kAtFdCwd) return false;
        // An absolute path ignores the dirfd entirely -- nothing to resolve.
        if (raw.empty() || raw.front() == '/') return false;
        return dir_of(dirfd).empty();
    }

    // Resolve arg-carried path to an absolute, normalized guest path.
    //
    // /proc/<pid>/{exe,cwd,root} are magic links: the kernel FOLLOWS them in
    // path walk, so `/proc/self/cwd/foo` is foo in the cwd and opening
    // `/proc/self/exe` opens the binary. Expand them here, for every path
    // syscall, unless the link is the LEAF and the caller asked not to follow
    // it (readlink, lstat, AT_SYMLINK_NOFOLLOW) -- those see the link itself.

    // Two kernel rules live in the path's SYNTAX and are lost once it is
    // normalized -- a trailing slash gets stripped, and an empty string gets
    // absolutized to the cwd:
    //
    //   stat("")              -> ENOENT   (not the cwd)
    //   stat("/etc/passwd/")  -> ENOTDIR  (a trailing slash demands a dir)
    //
    // Both were silently succeeding. Found by the differential harness.
    enum class PathSyntax { ok, empty, needs_dir };

    [[nodiscard]] PathSyntax path_syntax(const Regs& r, int path_arg) {
        return path_syntax(
            read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)])));
    }
    [[nodiscard]] static PathSyntax path_syntax(std::string_view raw) noexcept {
        if (raw.empty()) return PathSyntax::empty;
        if (raw.size() > 1 && raw.back() == '/') return PathSyntax::needs_dir;
        return PathSyntax::ok;
    }

    [[nodiscard]] std::string resolve_arg(const Regs& r, int path_arg, bool at,
                                          bool follow_leaf = true) {
        return resolve_raw(
            r, read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)])), at,
            follow_leaf);
    }
    [[nodiscard]] std::string resolve_raw(const Regs& r, const std::string& raw,
                                          bool at, bool follow_leaf = true) {
        std::string_view dir = at ? dir_of(static_cast<std::int64_t>(r.arg[0]))
                                  : std::string_view{};
        std::string abs = k_.files().absolutize(raw, dir);
        return expand_proc_links(bind_proc_self(std::move(abs)), follow_leaf);
    }

    // /proc/self and /proc/thread-self mean "the task making THIS syscall".
    //
    // procfs is a producer of bytes with no idea who is asking, so it used to
    // canonicalize /proc/self to /proc/1 unconditionally. That gave every
    // process pid 1's view: a forked child reading /proc/self/cmdline got its
    // PARENT's argv (10 bytes, "/tmp/argv\0") where the kernel returns its own
    // (22 bytes, all four args), and /proc/self/stat reported pid 1 for every
    // task. Anything that introspects itself through /proc -- argv-based
    // re-exec, a daemon reading its own status, `ps -p $$` -- saw the wrong
    // process.
    //
    // The dispatcher is the layer that KNOWS the caller (ids()), so `self` is
    // bound here, before the path reaches procfs. procfs's own fallback stays
    // for callers with no task context.
    [[nodiscard]] std::string bind_proc_self(std::string abs) {
        auto rebind = [&](std::string_view prefix, std::int32_t id) {
            if (abs == prefix || (abs.starts_with(prefix) &&
                                  abs.size() > prefix.size() &&
                                  abs[prefix.size()] == '/')) {
                abs = "/proc/" + std::to_string(id) + abs.substr(prefix.size());
                return true;
            }
            return false;
        };
        if (!abs.starts_with("/proc/")) return abs;
        const auto id = ids();
        // The caller's OWN fds stay in (or are folded into) /proc/self/fd form.
        // The guest is a real host process, so the host kernel's
        // /proc/self/fd/N, resolved in the guest's context, IS the guest's fd
        // N -- procfs redirects that form to the host on purpose. Rebinding it
        // to /proc/<pid>/fd/N first made that redirect dead code: the pid arm
        // has no fd/N, so readlink("/proc/self/fd/0") was ENOENT, ttyname()
        // failed, and `script -c tty` printed "Inappropriate ioctl for device"
        // on a perfectly good pty. Same for open("/proc/self/fd/1").
        {
            const std::string own = "/proc/" + std::to_string(id.pid);
            for (const std::string_view who : {std::string_view{"/proc/self"},
                                               std::string_view{own}}) {
                const std::string fd_prefix = std::string{who} + "/fd";
                if (abs == fd_prefix || abs.starts_with(fd_prefix + "/"))
                    return "/proc/self/fd" + abs.substr(fd_prefix.size());
            }
        }
        if (rebind("/proc/self", id.pid)) return abs;
        // thread-self is a TID, not a pid: /proc/thread-self is
        // /proc/<pid>/task/<tid> on a real kernel.
        if (abs == "/proc/thread-self" || abs.starts_with("/proc/thread-self/")) {
            const std::string rest = abs.substr(std::string_view{"/proc/thread-self"}.size());
            abs = "/proc/" + std::to_string(id.pid) + "/task/" +
                  std::to_string(id.tid) + rest;
        }
        return abs;
    }
    [[nodiscard]] std::string expand_proc_links(std::string abs, bool follow_leaf) {
        if (!abs.starts_with("/proc/")) return abs;
        // /proc/<who>/<leaf>[/rest]
        const auto s1 = abs.find('/', 6);
        if (s1 == std::string::npos) return abs;
        const auto s2 = abs.find('/', s1 + 1);
        const std::string link = abs.substr(0, s2);
        if (!proc_is_link(link)) return abs;
        if (s2 == std::string::npos && !follow_leaf) return abs;
        std::string tgt = proc_symlink_target(link);
        if (tgt.empty() || tgt.front() != '/') return abs;
        if (s2 != std::string::npos) tgt += abs.substr(s2);
        return kernel::FileNamespace::normalize(tgt);
    }

    // open/openat: translate to a host-backed path (REDIRECT) or synthesize a
    // virtual file into a memfd (INJECT). Either way the child ends up with a
    // real fd it can read AND mmap — so native ld.so works.
    [[nodiscard]] Outcome path_open(const Regs& r, int path_arg, bool at) {
        // Open flags follow the path arg: openat(dirfd,path,flags,mode) ->
        // arg[2]; open(path,flags,mode) -> arg[1].
        std::uint64_t flags = r.arg[static_cast<std::size_t>(path_arg) + 1];
        return path_open_flags(r, path_arg, at, flags);
    }

    // openat2(dirfd, path, struct open_how*, size): the modern openat. Its
    // open flags are NOT in a register — they sit in the first 8 bytes of the
    // `struct open_how` at arg[2] (the layout is { __u64 flags; __u64 mode;
    // __u64 resolve; }). Read them from guest memory, then drive the same
    // translation/injection core as openat. path_arg is 1 (dirfd is arg[0]).
    [[nodiscard]] Outcome path_openat2(const Regs& r) {
        std::uint64_t flags = 0;
        std::array<std::byte, 8> raw{};
        if (mem_.copy_in(uaddr(r.arg[2]), raw)) {
            for (std::size_t i = 0; i < 8; ++i)
                flags |= static_cast<std::uint64_t>(std::to_integer<unsigned>(raw[i])) << (i * 8);
        }
        return path_open_flags(r, /*path_arg=*/1, /*at=*/true, flags);
    }

    // The shared open core: `flags` is already resolved (from a register for
    // open/openat, or from the open_how struct for openat2). Selects the
    // overlay upper layer on write intent and REDIRECTs or INJECTs.
    [[nodiscard]] Outcome path_open_flags(const Regs& r, int path_arg, bool at,
                                          std::uint64_t flags) {
        // An empty path string is NOT the root directory. openat(dirfd,"",...)
        // without AT_EMPTY_PATH is ENOENT per the kernel; resolving "" to "/"
        // (and then REDIRECTing to the overlay root, a directory) is wrong and
        // faults the loader (glibc probes openat("") during library search).
        // AT_EMPTY_PATH (0x1000) would mean "operate on dirfd itself" — we
        // don't service that here, so forward it to the host unchanged.
        {
            std::string raw0 =
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
            if (raw0.empty())
                return wire::has_at(flags, wire::AtFlag::empty_path) ? fwd() : eno(Errno::enoent);
        }
        std::string abs = resolve_arg(r, path_arg, at);
        // Write intent (O_WRONLY / O_RDWR / O_CREAT / O_TRUNC) selects the
        // overlay upper layer.
        // Guest open flags come from abi/wire/open_flags.hpp -- the one
        // definition, shared with both backends. `writable()` is the test
        // that selects the copy-on-write branch: a create or truncate mutates
        // the filesystem even when the access mode is O_RDONLY, and the low
        // two bits are a MODE (O_RDONLY == 0), not a bit you can mask for.
        const bool for_write = wire::writable(flags);
        // WriteIntent for the overlay copy-up decision. copy_leaf (the
        // default) copies the read-only lower file UP into the writable upper
        // before returning, so an in-place edit (O_WRONLY without O_TRUNC)
        // sees the existing bytes. But for a create that discards the old
        // contents — O_CREAT|O_EXCL (must fail if it exists) or O_TRUNC
        // (truncate to zero) — copying the leaf up is WRONG: it materializes
        // the file in the upper, so the child's O_EXCL open then finds it and
        // fails EEXIST (libarchive/libalpm extraction hit exactly this on
        // EVERY overwrite, warning "Can't create <path>"). Use parents_only
        // there: mirror the parent chain, leave the leaf absent, let the
        // syscall create it fresh in the upper (which also clears any
        // whiteout). A lower-only file thus reads as replaced, not duplicated.
        Wi open_wi = Wi::copy_leaf;
        if (for_write &&
            ((wire::has(flags, wire::OpenFlag::creat) &&
              wire::has(flags, wire::OpenFlag::excl)) ||
             wire::has(flags, wire::OpenFlag::trunc)))
            open_wi = Wi::parents_only;
        auto pc = k_.files().classify(abs, for_write, /*follow=*/true, open_wi);
        if (pc.realm == kernel::Realm2::host_backed) {
            // Remember the guest path for this fd after the trap assigns it.
            pending_open_ = abs;
            // If this opens a directory that is overlaid (writable upper over
            // the read-only rootfs lower), enumerate the UNION of both layers
            // and serve THAT from getdents64 on the resulting fd — otherwise a
            // freshly-created (empty) upper would hide the whole rootfs, and
            // `ls /` would show nothing. Non-overlay dirs enumerate natively.
            //
            // Computing that union costs two readdir sweeps plus a hash map,
            // so do it LAZILY: record the path and let the first getdents64
            // build it. Opens vastly outnumber directory reads (every *at
            // base dirfd, every O_PATH handle, every library probe), and
            // doing it eagerly made open O(directory size) — it was 96% of
            // host CPU on `pacman -S python`. Skip even the marker when the
            // open plainly cannot be a directory read: O_WRONLY/O_RDWR can't
            // getdents (EISDIR/EBADF), and any open carrying O_CREAT/O_TRUNC
            // names a file. The marker is cheap and self-cancelling — if the
            // path turns out not to be an overlaid directory, the union comes
            // back empty and getdents64 falls through to the real fd.
            if (!for_write) {
                pending_dir_   = true;
                pending_lazy_  = abs;
            }
            return Redirect{PathArg{path_arg, std::move(pc.host_path)}};
        }
        if (pc.realm == kernel::Realm2::virtual_file) {
            // Follow a cross-mount symlink to the RESOLVED virtual path (e.g.
            // /etc/mtab -> /proc/self/mounts); produce that, not the link.
            const std::string& vp = pc.virtual_path.empty() ? abs : pc.virtual_path;
            auto vf = k_.files().produce(vp);
            if (!vf) return eno(vf.error());
            // /proc/<pid>/maps is a STUB in procfs -- it has no idea what the
            // process mapped. The guest is a real host process, so the
            // backend can read its actual map; fill it in here, where both
            // the backend and the namespace are reachable. An empty maps
            // file is not a plausible process, and pstack, a debugger
            // attaching to a guest, and any allocator or sanitizer that
            // walks its own mappings all read it.
            if (vf->bytes.empty() && is_proc_maps(vp))
                if (auto m = guest_maps(); !m.empty())
                    vf->bytes.assign(
                        reinterpret_cast<const std::byte*>(m.data()),
                        reinterpret_cast<const std::byte*>(m.data() + m.size()));
            pending_open_ = vp;
            // A virtual DIRECTORY: stash its entries so getdents64 on the
            // resulting fd enumerates them (the backing temp node is a real
            // empty directory so O_DIRECTORY opens succeed).
            pending_dir_ = vf->is_dir;
            pending_entries_ = std::move(vf->entries);
            return Inject{path_arg, std::move(vf->bytes), vf->is_dir};
        }
        return eno(pc.error);
    }

    // Is this /proc/<pid>/maps (or the self/thread-self spellings)? The
    // caller has already bound /proc/self to a real pid.
    [[nodiscard]] static bool is_proc_maps(std::string_view p) noexcept {
        return p.starts_with("/proc/") && p.ends_with("/maps");
    }

    // The guest's real memory map, with HOST paths rewritten back into the
    // guest namespace. Without that rewrite the file would tell the guest
    // its own binary lives at /tmp/linuxity-tmp-N/usr/bin/sh, which both
    // leaks where the rootfs really is and is a path the guest cannot open.
    [[nodiscard]] std::string guest_maps() {
        if constexpr (!requires { mem_.host_maps(); }) {
            return {};
        } else {
            auto raw = mem_.host_maps();
            if (!raw) return {};
            std::string out;
            out.reserve(raw->size());
            std::size_t pos = 0;
            while (pos < raw->size()) {
                const std::size_t eol = raw->find('\n', pos);
                std::string_view line{*raw};
                line = line.substr(pos, (eol == std::string::npos ? raw->size() : eol) - pos);
                // The path, if any, is the last field and always absolute.
                const std::size_t slash = line.find(" /");
                if (slash == std::string_view::npos) {
                    out.append(line);
                } else {
                    const std::string_view head = line.substr(0, slash + 1);
                    const std::string_view hp = line.substr(slash + 1);
                    out.append(head);
                    if (auto g = k_.files().guest_path_of(hp); !g.empty())
                        out.append(g);
                    else
                        out.append(hp);   // not ours: a host lib, leave it
                }
                out.push_back('\n');
                if (eol == std::string::npos) break;
                pos = eol + 1;
            }
            return out;
        }
    }

    // stat/lstat/newfstatat: redirect host-backed to the real path; for
    // virtual files synthesize a stat buffer into guest memory ourselves.
    [[nodiscard]] Outcome path_stat(const Regs& r, int path_arg, bool at,
                                    bool follow = true) {
        // Syntax first: an empty path is ENOENT (not the cwd), and a trailing
        // slash demands a directory. Both were succeeding before -- found by
        // the differential harness. AT_EMPTY_PATH means "stat the dirfd
        // itself", which we don't service, so let the host answer that.
        const std::uint64_t at_flags = at ? r.arg[3] : 0;
        // Read the guest path ONCE. It used to be copied out of guest memory
        // three times per stat (syntax, dirfd check, resolve).
        const std::string raw =
            read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
        const PathSyntax syn = path_syntax(raw);
        if (syn == PathSyntax::empty)
            return wire::has_at(at_flags, wire::AtFlag::empty_path)
                       ? fwd()
                       : eno(Errno::enoent);

        // A dirfd we cannot resolve means we'd resolve the path against the
        // wrong directory; the host owns the real fd table, so let it answer.
        if (at && at_dirfd_unresolvable(r, raw)) return fwd();

        std::string abs = resolve_raw(r, raw, at, follow);
        auto pc = k_.files().classify(abs, /*for_write=*/false, follow);

        // "/etc/passwd/" must be ENOTDIR. The Redirect below hands the host a
        // NORMALIZED path with the slash already stripped, so the host kernel
        // never sees the constraint -- we have to enforce it. A virtual node
        // has no host inode either, so both realms are decided here.
        if (syn == PathSyntax::needs_dir) {
            if (pc.realm == kernel::Realm2::virtual_file) {
                const std::string& vp =
                    pc.virtual_path.empty() ? abs : pc.virtual_path;
                auto vf = k_.files().produce(vp);
                if (vf && !vf->is_dir) return eno(Errno::enotdir);
            } else if (pc.realm == kernel::Realm2::host_backed) {
                // Re-stat the host path WITH the slash restored and let the
                // host kernel apply its own rule, rather than reimplementing
                // "is a directory" here.
                return Redirect{PathArg{path_arg, pc.host_path + "/"}}
                    .with(Scrub{Scrub::Layout::stat,
                                uaddr(r.arg[static_cast<std::size_t>(path_arg) + 1]),
                                abs});
            }
        }
        if (pc.realm == kernel::Realm2::host_backed) {
            if (auto fast = fast_stat(pc.host_path, abs))
                return write_statbuf(
                    uaddr(r.arg[static_cast<std::size_t>(path_arg) + 1]), *fast);
            // The host kernel will fill the statbuf with the host file's
            // owner; scrub it to root afterwards. statbuf is arg[1] for
            // stat/lstat, arg[2] for newfstatat.
            return Redirect{PathArg{path_arg, std::move(pc.host_path)}}
                .with(Scrub{Scrub::Layout::stat,
                            at ? uaddr(r.arg[2]) : uaddr(r.arg[1]), abs});
        }
        // Virtual stat: forward is impossible, so synthesize a stat64 buffer.
        if (pc.realm == kernel::Realm2::virtual_file) {
            const std::string& vp = pc.virtual_path.empty() ? abs : pc.virtual_path;
            auto vf = k_.files().produce(vp);
            // /proc/<pid>/{exe,cwd,root} are SYMLINKS whose targets only the
            // dispatcher knows (see proc_symlink_target). procfs itself has
            // no entry for them, so lstat said ENOENT -- `ls -l
            // /proc/self/exe` and every `test -L` failed. Synthesize the link,
            // and for a following stat, stat its target instead.
            if (vf && vf->symlink_target == "(proc-link)") vf = err<kernel::VirtualFile>(Errno::enoent);
            if (!vf && proc_is_link(vp)) {
                const std::string tgt = proc_symlink_target(vp);
                if (!tgt.empty()) {
                    if (follow) {
                        auto tc = k_.files().classify(tgt, false, true);
                        if (tc.realm == kernel::Realm2::host_backed) {
                            return Redirect{
                                PathArg{path_arg, std::move(tc.host_path)}}
                                .with(Scrub{Scrub::Layout::stat,
                                            at ? uaddr(r.arg[2])
                                               : uaddr(r.arg[1]),
                                            tgt});
                        }
                    }
                    kernel::VirtualFile lf;
                    lf.symlink_target = tgt;
                    vf = ok(std::move(lf));
                }
            }
            if (!vf) return eno(vf.error());
            UAddr sb = at ? uaddr(r.arg[2]) : uaddr(r.arg[1]);
            // A PROCFS symlink reports st_size 0, unlike a real one whose
            // size is its target's length. These are all procfs links
            // (/proc/self/{exe,cwd,root}, /proc/<pid>/fd/N), so reporting
            // the target length was wrong in a way `find -type l -size` and
            // archivers that preallocate from st_size can see.
            return write_statbuf(sb, vf->is_dir,
                                 vf->symlink_target.empty() ? vf->bytes.size() : 0,
                                 !vf->symlink_target.empty());
        }
        return eno(pc.error);
    }

    // statx(dirfd, path, flags, mask, buf): host-backed -> redirect; virtual
    // -> synthesize a `struct statx` into the guest buffer (arg[4]).
    [[nodiscard]] Outcome path_statx(const Regs& r) {
        // statx(dirfd, path, flags, mask, buf). With AT_EMPTY_PATH (0x1000) and
        // an empty path the call stats the dirfd ITSELF (fstat-equivalent) —
        // fish opens config.fish then statx(fd,"",AT_EMPTY_PATH) to check it.
        // Resolve to the fd's bound guest path so we stat the right inode; a
        // real (host-backed) fd we don't track just forwards to the kernel,
        // which fstats the fd correctly.
        std::uint64_t flags = r.arg[2];
        std::string raw1 = read_cstr(uaddr(r.arg[1]));
        if (raw1.empty() && wire::has_at(flags, wire::AtFlag::empty_path)) {
            std::string_view gp = k_.files().path_of_fd(static_cast<int>(r.arg[0]));
            if (gp.empty()) return fwd();   // untracked fd: kernel fstats it
            auto pc = k_.files().classify(std::string{gp});
            if (pc.realm == kernel::Realm2::virtual_file) {
                const std::string& vp = pc.virtual_path.empty()
                                            ? std::string{gp} : pc.virtual_path;
                auto vf = k_.files().produce(vp);
                if (!vf) return eno(vf.error());
                return write_statx(uaddr(r.arg[4]), vf->is_dir, vf->bytes.size());
            }
            // A host-backed fd is already open on the correct inode — the
            // kernel fstats it directly; forward unchanged (do NOT re-resolve
            // the empty path, which would wrongly stat the cwd/root).
            return fwd();
        }
        bool nofollow = wire::has_at(flags, wire::AtFlag::symlink_nofollow);
        std::string abs = resolve_arg(r, 1, true, /*follow_leaf=*/!nofollow);
        // Honor AT_SYMLINK_NOFOLLOW (0x100): coreutils `stat`/`ls -la` statx a
        // symlink with this flag and expect S_IFLNK; following it reported the
        // target's type ("regular file") and made git's symlink probe fail.
        auto pc = k_.files().classify(abs, /*for_write=*/false, /*follow=*/!nofollow);
        if (pc.realm == kernel::Realm2::host_backed) {
            if (auto fast = fast_stat(pc.host_path, abs))
                return write_statx(uaddr(r.arg[4]), *fast);
            return Redirect{PathArg{1, std::move(pc.host_path)}}
                .with(Scrub{Scrub::Layout::statx, uaddr(r.arg[4]), abs});
        }
        if (pc.realm == kernel::Realm2::virtual_file) {
            const std::string& vp = pc.virtual_path.empty() ? abs : pc.virtual_path;
            auto vf = k_.files().produce(vp);
            if (vf && vf->symlink_target == "(proc-link)") vf = err<kernel::VirtualFile>(Errno::enoent);
            if (!vf && proc_is_link(vp)) {
                const std::string tgt = proc_symlink_target(vp);
                if (!tgt.empty()) {
                    if (!nofollow) {
                        auto tc = k_.files().classify(tgt, false, true);
                        if (tc.realm == kernel::Realm2::host_backed) {
                            return Redirect{PathArg{1, std::move(tc.host_path)}}
                                .with(Scrub{Scrub::Layout::statx,
                                            uaddr(r.arg[4]), tgt});
                        }
                    }
                    // size 0: a PROCFS symlink reports st_size 0, unlike a
                    // real one whose size is its target's length. Same rule
                    // as the stat path above.
                    return write_statx(uaddr(r.arg[4]), false, 0, true);
                }
            }
            if (!vf) return eno(vf.error());
            return write_statx(uaddr(r.arg[4]), vf->is_dir, vf->bytes.size(),
                               !vf->symlink_target.empty());
        }
        return eno(pc.error);
    }

    // access/readlink[at]/faccessat: host-backed -> redirect; virtual
    // paths that exist -> success (0); absent -> error.
    [[nodiscard]] Outcome path_at(const Regs& r, int path_arg, bool at) {
        std::string raw0 =
            read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
        if (raw0.empty()) return at ? fwd() : eno(Errno::enoent);
        std::string abs = resolve_arg(r, path_arg, at);
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) {
            return Redirect{PathArg{path_arg, std::move(pc.host_path)}};
        }
        if (pc.realm == kernel::Realm2::virtual_file) return val(0);
        return eno(pc.error);
    }

    // inotify_add_watch(fd, path, mask) / fanotify_mark(fd, flags, mask,
    // dirfd, path): translate the WATCHED guest path to its overlay host path
    // and REDIRECT, so a file watcher registers against the ROOTFS tree, not
    // the host's. The path lives at `path_arg` (1 for inotify, 4 for
    // fanotify); fanotify's `at` form takes its dirfd from the register just
    // before the path. A virtual (procfs/sysfs) target has no inode a real
    // inotify fd can watch — refuse with ENOENT so the watcher skips it
    // rather than the raw guest path leaking to the host.
    [[nodiscard]] Outcome path_watch(const Regs& r, int path_arg,
                                     bool at = false) {
        std::string raw =
            read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
        std::string_view dir =
            at ? dir_of(static_cast<std::int64_t>(
                     r.arg[static_cast<std::size_t>(path_arg) - 1]))
               : std::string_view{};
        std::string abs = k_.files().absolutize(raw, dir);
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) {
            return Redirect{PathArg{path_arg, std::move(pc.host_path)}};
        }
        if (pc.realm == kernel::Realm2::virtual_file) return eno(Errno::enoent);
        return eno(pc.error);
    }

    // readlink[at]: host-backed symlinks redirect to the real path; the
    // virtual /proc symlinks (self/exe, <pid>/exe, self/cwd, self/root,
    // self/fd/N) are SYNTHESIZED here, since a monitor / dynamic loader /
    // language runtime routinely reads /proc/self/exe to find its own binary.
    [[nodiscard]] Outcome do_readlink(const Regs& r, int path_arg, bool at) {
        // An empty path is ENOENT (readlink(2)); don't resolve "" to "/" and
        // redirect to the overlay root (a directory) — that faults the caller.
        // (readlinkat with AT_EMPTY_PATH would read the dirfd's own link; we
        // don't service that, so forward it.)
        std::string raw0 =
            read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
        if (raw0.empty()) return at ? fwd() : eno(Errno::enoent);

        // /proc/self and /proc/thread-self ARE symlinks -- to "<pid>" and
        // "<pid>/task/<tid>". readlink must see them as such, but resolve_arg
        // rebinds them to /proc/<pid> first (so every OTHER path syscall
        // reaches the right directory), after which readlink saw a directory
        // and returned EINVAL where Linux returns the pid. Answer before the
        // rebind can erase the link. Found by the differential harness.
        {
            const std::string pre = kernel::FileNamespace::normalize(
                k_.files().absolutize(raw0,
                                      at ? dir_of(static_cast<std::int64_t>(r.arg[0]))
                                         : std::string_view{}));
            const std::size_t bi0 = static_cast<std::size_t>(path_arg) + 1;
            const auto id = ids();
            if (pre == "/proc/self")
                return write_link(uaddr(r.arg[bi0]),
                                  static_cast<std::size_t>(r.arg[bi0 + 1]),
                                  std::to_string(id.pid));
            if (pre == "/proc/thread-self")
                return write_link(uaddr(r.arg[bi0]),
                                  static_cast<std::size_t>(r.arg[bi0 + 1]),
                                  std::to_string(id.pid) + "/task/" +
                                      std::to_string(id.tid));
        }

        std::string abs = resolve_arg(r, path_arg, at, /*follow_leaf=*/false);
        // The buffer + size follow the path arg: readlink(path,buf,sz) ->
        // arg1/arg2; readlinkat(dirfd,path,buf,sz) -> arg2/arg3.
        std::size_t bi = static_cast<std::size_t>(path_arg) + 1;
        UAddr buf = uaddr(r.arg[bi]);
        std::size_t cap = static_cast<std::size_t>(r.arg[bi + 1]);

        if (std::string tgt = proc_symlink_target(abs); !tgt.empty())
            return write_link(buf, cap, tgt);

        auto pc = k_.files().classify(abs, /*for_write=*/false, /*follow=*/false);
        if (pc.realm == kernel::Realm2::host_backed) {
            return Redirect{PathArg{path_arg, std::move(pc.host_path)}};
        }
        if (pc.realm == kernel::Realm2::virtual_file) {
            // A synthesized symlink (e.g. /dev/stdin -> /proc/self/fd/0)
            // carries its target in the produced node; serve it directly.
            if (auto vf = k_.files().produce(abs); vf && !vf->symlink_target.empty()) {
                // ...but NEVER the "(proc-link)" sentinel. procfs uses it to
                // say "this is a symlink whose target only the dispatcher
                // knows" (cwd/root/exe), expecting proc_symlink_target()
                // above to substitute the real value. When that returns empty
                // -- an exe we cannot name, a pid that just exited -- this
                // line happily handed the guest the literal string
                // "(proc-link)".
                //
                // glibc's _dl_get_origin readlinks /proc/self/exe and asserts
                // linkval[0]=='/'. An 11-byte relative "(proc-link)" fails
                // that and ABORTS the process: "Fatal glibc error:
                // dl-origin.c:42 assertion failed", which is what killed
                // every pacman scriptlet. ENOENT is the honest answer -- the
                // link exists but we cannot resolve it -- and callers handle
                // it, where they cannot handle a lie.
                if (vf->symlink_target == "(proc-link)") return eno(Errno::enoent);
                return write_link(buf, cap, vf->symlink_target);
            }
            return eno(Errno::einval);   // a plain virtual file is not a symlink
        }
        return eno(pc.error);
    }

    // Is this a /proc/<pid|self|thread-self>/{exe,cwd,root} link?
    [[nodiscard]] static bool proc_is_link(std::string_view p) {
        if (!p.starts_with("/proc/")) return false;
        const auto slash = p.rfind('/');
        const auto leaf = p.substr(slash + 1);
        if (leaf != "exe" && leaf != "cwd" && leaf != "root") return false;
        const auto who = p.substr(6, slash - 6);
        if (who == "self" || who == "thread-self") return true;
        return !who.empty() && who.find_first_not_of("0123456789") == std::string_view::npos;
    }

    // The target of a synthesized /proc symlink, or "" if `abs` is not one.
    // self/<pid> both resolve against the CURRENT task (linuxity runs one
    // guest tree; the monitor asks about its own members).
    [[nodiscard]] std::string proc_symlink_target(const std::string& abs) {
        auto id = ids();
        auto exe_of = [&](std::int32_t pid) -> std::string {
            // The backend knows what every process in the tree is running
            // (each guest process is its own host process, so only the
            // backend's shared table can see across them). Prefer it: the
            // argv[0] heuristic below fails for anything run by bare name
            // (`bash` -> "realpath: /proc/2/exe: No such file", which broke
            // screenfetch's shell detection).
            if constexpr (requires { mem_.exe_of_pid(pid); }) {
                if (std::string e = mem_.exe_of_pid(pid); !e.empty()) return e;
            }
            if (const auto* pi = k_.procs().find(pid)) {
                // cmdline is NUL-joined argv (ProcInfo::cmdline's documented
                // format, and the /proc wire format), so argv[0] ends at the
                // first NUL -- not the first space. Splitting on a space here
                // used to be right when the field was space-joined; once it
                // became NUL-joined this returned the WHOLE command line as
                // the exe target, so readlink("/proc/self/exe") handed glibc
                // "/bin/prog\0arg" and _dl_get_origin aborted the process
                // ("assertion failed: linkval[0] == '/'" is the next check
                // after it mangles that into a relative path).
                std::string c = pi->cmdline;
                auto nul = c.find('\0');
                std::string a0 = nul == std::string::npos ? c : c.substr(0, nul);
                // Only an ABSOLUTE argv[0] is a valid exe link target; a bare
                // name ("linuxity", "bash") or the spawn placeholder is not,
                // so we leave the link to the host-backed /proc (redirect).
                if (!a0.empty() && a0[0] == '/' && a0 != "(spawning)") return a0;
            }
            return {};
        };
        // /proc/self/exe  and  /proc/<pid>/exe
        if (abs == "/proc/self/exe") return exe_of(id.pid);
        constexpr std::string_view kProc = "/proc/";
        if (abs.rfind(kProc, 0) == 0) {
            std::string rest = abs.substr(kProc.size());
            auto slash = rest.find('/');
            if (slash != std::string::npos) {
                std::string who = rest.substr(0, slash);
                std::string tail = rest.substr(slash + 1);
                std::int32_t pid = (who == "self" || who == "thread-self")
                                       ? id.pid : atoi_safe(who);
                if (pid > 0) {
                    if (tail == "exe")  return exe_of(pid);
                    if (tail == "cwd") {
                        if constexpr (requires { mem_.cwd_of_pid(pid); })
                            if (pid != id.pid)
                                if (std::string c = mem_.cwd_of_pid(pid); !c.empty()) return c;
                        return std::string{k_.files().cwd()};
                    }
                    if (tail == "root") return "/";
                    // /proc/<pid>/fd/N -> the GUEST-namespace path the fd was
                    // opened as. Without this the readlink falls to the host
                    // procfs redirect and leaks the real host fd target — for
                    // an overlay-upper file that is /tmp/linuxity-upper-XXXX,
                    // a path that does NOT exist in the guest namespace. gpg
                    // /gpg-agent readlink their own fds to locate their socket
                    // dir; the leaked host path then faults the runtime.
                    // Only OUR own tree's fds are known here (one guest tree);
                    // an unknown fd (e.g. inherited stdio 0/1/2 -> the real
                    // tty) returns "" and correctly falls back to the host
                    // redirect so /dev/stdout still reaches fd 1.
                    constexpr std::string_view kFd = "fd/";
                    if (tail.rfind(kFd, 0) == 0 && pid == id.pid) {
                        std::int32_t fd = atoi_safe(tail.substr(kFd.size()));
                        if (fd >= 0) {
                            std::string_view gp =
                                k_.files().path_of_fd(fd);
                            if (!gp.empty()) return std::string{gp};
                        }
                    }
                }
            }
        }
        return {};
    }

    static std::int32_t atoi_safe(const std::string& s) {
        std::int32_t v = 0;
        for (char c : s) { if (c < '0' || c > '9') return -1; v = v * 10 + (c - '0'); }
        return s.empty() ? -1 : v;
    }

    // Write a readlink target (NOT NUL-terminated, per readlink(2)) into the
    // guest buffer, truncated to `cap`; returns the number of bytes written.
    [[nodiscard]] Outcome write_link(UAddr buf, std::size_t cap,
                                     const std::string& tgt) {
        std::size_t n = tgt.size() < cap ? tgt.size() : cap;
        std::vector<std::byte> bytes(n);
        for (std::size_t i = 0; i < n; ++i)
            bytes[i] = static_cast<std::byte>(tgt[i]);
        if (n && !mem_.copy_out(buf, bytes)) return eno(Errno::efault);
        return val(static_cast<std::int64_t>(n));
    }

    // Does this pacman invocation perform a SYNC or UPGRADE transaction (-S /
    // --sync / -U / --upgrade)? `--overwrite` is only a valid option for those
    // operations; appending it to a query (-Q) or other op makes pacman abort
    // with "invalid option '--overwrite'". Scan argv (the guest pointer array
    // at path_arg+1): a short cluster like -Syu counts if it contains S or U;
    // a long --sync/--upgrade counts; tokens after `--` or non-flag operands
    // are ignored.
    [[nodiscard]] bool pacman_is_transaction(const Regs& r, int path_arg) {
        std::uint64_t argv_ptr = r.arg[static_cast<std::size_t>(path_arg) + 1];
        if (argv_ptr == 0) return false;
        bool end_opts = false;
        for (std::size_t i = 0; i < 256; ++i) {
            std::array<std::byte, 8> b{};
            if (!mem_.copy_in(uaddr(argv_ptr + i * 8), b)) break;
            std::uint64_t p = 0; std::memcpy(&p, b.data(), 8);
            if (p == 0) break;
            if (i == 0) continue;                 // argv[0] is the program name
            std::string a = read_cstr(uaddr(p));
            if (a == "--") { end_opts = true; continue; }
            if (end_opts || a.size() < 2 || a[0] != '-') continue;
            if (a[1] == '-') {                    // long option
                if (a == "--sync" || a == "--upgrade") return true;
            } else {                              // short cluster, e.g. -Syu
                for (std::size_t k = 1; k < a.size(); ++k)
                    if (a[k] == 'S' || a[k] == 'U') return true;
            }
        }
        return false;
    }

    // execve/execveat: rewrite the program-path argument to the translated
    // host path (host-backed) and forward. Virtual exec targets are refused.
    [[nodiscard]] Outcome path_exec(const Regs& r, int path_arg) {
        std::string abs = resolve_arg(r, path_arg, path_arg == 1);
        auto pc = k_.files().classify(abs);
        // Should this exec get `--overwrite "*"` appended? Only when the
        // program is pacman AND the transparent-overwrite mode is on
        // (LINUXITY_PACMAN_OVERWRITE, set by main.cpp's --pacman-overwrite,
        // default ON with --root). A bootstrap rootfs ships library files
        // (libgcc_s, libstdc++, ...) that no local-DB package owns yet; pacman
        // correctly refuses to clobber an unowned file, so EVERY install of a
        // package delivering one aborts with "<file> exists in filesystem".
        // On a real system those files ARE owned, so overwriting is exactly
        // right; --overwrite "*" makes the first install succeed and REGISTER
        // ownership, after which it's a no-op. Scoped to argv[0]==pacman so no
        // other program is affected.
        std::vector<std::string> extra;
        {
            auto slash = abs.find_last_of('/');
            std::string base = slash == std::string::npos ? abs : abs.substr(slash + 1);
            if (base == "pacman" && std::getenv("LINUXITY_PACMAN_OVERWRITE") &&
                pacman_is_transaction(r, path_arg))
                extra = {"--overwrite", "*"};
        }
        if (pc.realm == kernel::Realm2::host_backed) {
            // termux-exec's inspectFileHeader lesson: a FOREIGN-arch ELF (an
            // aarch64 binary on an x86-64 host, say) cannot run natively —
            // linuxity executes guest code directly on the host CPU, there is
            // no cross-emulator. If we let the host kernel exec it, the guest
            // dies in a cryptic SIGSEGV/SIGILL deep in the loader. Catch it
            // here and fail with a clean ENOEXEC, exactly what the kernel
            // returns for an unrunnable binary format. (termux routes this to
            // qemu; linuxity's scope is native-speed same-ISA execution.)
            if (loader::read_elf_machine(pc.host_path) ==
                    loader::ForeignArch::foreign)
                return eno(Errno::enoexec);
            // A dynamically-linked program names its interpreter in PT_INTERP;
            // the host kernel would resolve that against the host root and
            // fail. If this binary has an interp, exec the interpreter instead
            // (with the program as argv[1]) so the loader opens the program +
            // its libraries through redirected syscalls inside the rootfs.
            std::string interp = loader::read_elf_interp(pc.host_path);
            if (!interp.empty()) {
                std::string interp_abs = k_.files().absolutize(interp);
                auto ipc = k_.files().classify(interp_abs);
                // prog_guest is the GUEST path; the loader's openat redirects.
                ExecInterp ei{path_arg,
                              ipc.realm == kernel::Realm2::host_backed
                                  ? std::move(ipc.host_path) : interp,
                              abs};
                ei.extra_args = std::move(extra);
                return ei;
            }
            // A `#!` script: the host kernel would launch the shebang
            // interpreter with the HOST-translated script path, which OUR
            // namespace then re-translates (double-rooting). So resolve the
            // shebang ourselves and exec the interpreter with the script as a
            // GUEST path. If the interpreter is itself dynamic, chain through
            // its ld.so as well.
            if (loader::Shebang sh = loader::read_shebang(pc.host_path);
                !sh.interp.empty()) {
                std::string si_abs = k_.files().absolutize(sh.interp);
                auto sic = k_.files().classify(si_abs);
                std::string si_host = sic.realm == kernel::Realm2::host_backed
                                          ? sic.host_path : sh.interp;
                // Is the shebang interpreter ITSELF dynamic? Then exec its
                // ld.so, and pass the interpreter's host path as the first
                // prefix token (ld.so <sh-host> [-e] <script-guest> ...).
                std::string si_interp = loader::read_elf_interp(si_host);
                std::vector<std::string> prefix;
                std::string interp_host;
                if (!si_interp.empty()) {
                    std::string ld_abs = k_.files().absolutize(si_interp);
                    auto ldc = k_.files().classify(ld_abs);
                    interp_host = ldc.realm == kernel::Realm2::host_backed
                                      ? std::move(ldc.host_path) : si_interp;
                    // ld.so opens its program argument through redirected
                    // openat, so pass the interpreter's GUEST path (si_abs),
                    // not its host path — else ld re-translates and double-roots.
                    prefix.push_back(std::move(si_abs));
                } else {
                    interp_host = std::move(si_host);   // static interpreter
                }
                if (!sh.arg.empty()) prefix.push_back(std::move(sh.arg));
                // prog_guest is the script, as a guest path.
                ExecInterp ei{path_arg, std::move(interp_host), abs};
                ei.prefix = std::move(prefix);
                return ei;
            }
            return Redirect{PathArg{path_arg, std::move(pc.host_path)}};
        }
        return eno(pc.realm == kernel::Realm2::virtual_file ? Errno::eacces
                                                            : pc.error);
    }

    [[nodiscard]] Outcome do_chdir(const Regs& r) {
        std::string abs = k_.files().absolutize(read_cstr(uaddr(r.arg[0])),
                                                k_.files().cwd());
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::absent) return eno(pc.error);
        // chdir is fully virtualized (we track cwd and never forward), so we
        // MUST verify the target actually exists as a directory ourselves.
        // classify() on a read never returns `absent` for a path under the
        // rootfs mount -- it points host_backed at the lower layer and lets a
        // FORWARDED syscall report ENOENT. But chdir doesn't forward, so
        // without this check it would report SUCCESS for a nonexistent dir.
        // That broke `git init <newdir>`: git does chdir(dir); if it ENOENTs,
        // mkdir(dir) then retry -- our false-success made git skip the mkdir,
        // never create the work tree, and die "Cannot access work tree".
        if (pc.realm == kernel::Realm2::host_backed) {
            struct ::stat st{};
            if (::stat(pc.host_path.c_str(), &st) != 0) return eno(Errno::enoent);
            if (!S_ISDIR(st.st_mode))                   return eno(Errno::enotdir);
        }
        k_.files().set_cwd(abs);
        return val(0);
    }

    // fchdir(fd): the guest changes cwd to an already-open directory fd. The
    // FORWARDED call moves the real child's cwd, but the guest's *tracked* cwd
    // (used to absolutize every later relative path) would go stale unless we
    // also sync it here. coreutils `mkdir -p`, `tar -C`, `rm -r`, and libalpm's
    // scriptlet runner all fchdir into a saved dir fd and then issue RELATIVE
    // paths; without this the relative paths resolve against the wrong (stale)
    // cwd and land in the wrong overlay location or ENOENT. We look up the
    // guest path bound to the fd and REDIRECT the fd to its overlay host path
    // (so the real fchdir lands in the same layer we believe it does), and
    // update the tracked cwd. If the fd isn't one we bound, just forward.
    [[nodiscard]] Outcome do_fchdir(const Regs& r) {
        std::string_view gp = k_.files().path_of_fd(static_cast<int>(r.arg[0]));
        if (!gp.empty()) k_.files().set_cwd(std::string{gp});
        return fwd();
    }

    // chroot(path): a guest chroot would chroot our real HOST child to an
    // UNTRANSLATED host path — either failing (unprivileged) or, worse,
    // escaping linuxity's namespace onto the host tree. linuxity already
    // confines the guest by translating every path through the rootfs, so we
    // accept chroot as a satisfied no-op: verify the target exists in the
    // guest namespace (so a bogus chroot still ENOENTs like the real call),
    // then report success without touching the host process. Programs that
    // chroot-then-serve (sshd, some init scripts) proceed believing they are
    // jailed; the jail is linuxity itself.
    [[nodiscard]] Outcome do_chroot(const Regs& r) {
        std::string abs = k_.files().absolutize(read_cstr(uaddr(r.arg[0])),
                                                k_.files().cwd());
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::absent) return eno(pc.error);
        // Same non-forwarding hazard as do_chdir: verify the target really
        // exists as a directory so a bogus chroot ENOENTs like the real call
        // instead of falsely succeeding.
        if (pc.realm == kernel::Realm2::host_backed) {
            struct ::stat st{};
            if (::stat(pc.host_path.c_str(), &st) != 0) return eno(Errno::enoent);
            if (!S_ISDIR(st.st_mode))                   return eno(Errno::enotdir);
        }
        return val(0);
    }

    // statfs(path, buf): translate the path and REDIRECT so the host fills the
    // guest buffer with the OVERLAY filesystem's real statistics (block size,
    // free space) — what `df`, glibc statvfs, and installer space checks read.
    // A virtual procfs/sysfs path has no backing block device, so synthesize a
    // plausible tmpfs-like statfs rather than leak the host's numbers or fail.
    [[nodiscard]] Outcome path_statfs(const Regs& r) {
        std::string abs = resolve_arg(r, 0, /*at=*/false);
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) {
            return Redirect{PathArg{0, std::move(pc.host_path)}};   // host fills arg[1] with the real overlay-fs statfs
        }
        if (pc.realm == kernel::Realm2::virtual_file)
            return write_statfs(uaddr(r.arg[1]), abs);
        return eno(pc.error);
    }

    // Extended-attribute path family: get/set/list/remove xattr and their l*
    // (no-follow) forms. All carry the guest path in arg0; translate it to the
    // overlay host path and REDIRECT so the operation lands on the ROOTFS
    // inode, not the host's. Writes (set/remove) pass for_write=true so the
    // leaf is copied up into the writable upper layer first — matching
    // `setcap`, `tar --xattrs -x`, `cp --preserve=xattr`. Virtual paths carry
    // no xattrs (ENOTSUP); absent paths yield their errno.
    // path_arg/at describe WHERE the path is: setxattr(path,...) puts it in
    // arg[0]; setxattrat(dirfd,path,...) in arg[1] relative to a dirfd. Same
    // translation either way, so the *at variants share this rather than
    // getting a second copy.
    [[nodiscard]] Outcome path_xattr(const Regs& r, bool for_write,
                                     bool follow = true,
                                     int path_arg = 0, bool at = false) {
        std::string abs = resolve_arg(r, path_arg, at);
        // A WRITE (set/remove) whose attribute lives in a PRIVILEGED xattr
        // namespace can never be applied by our unprivileged host process:
        //   * security.*  -- LSM/capabilities. security.capability is the file
        //                    capability set libarchive restores from a pacman
        //                    package; the host setxattr EPERMs -> "Cannot
        //                    restore extended attributes: security.capability".
        //   * system.*    -- ACLs / kernel-managed attrs, privileged outside
        //                    of specific fs support.
        //   * trusted.*   -- requires CAP_SYS_ADMIN.
        // linuxity runs the guest as fake-root and does not ENFORCE file
        // capabilities, so faking success is coherent -- the same policy as
        // do_chmod/do_chown, which record privileged metadata and report 0
        // rather than forward a doomed host call. Accept the write vacuously
        // instead of forwarding a setxattr that can only fail; this silences
        // the extraction warning. (get/list on these still fall through and
        // read whatever the host actually stored.) name = arg1 for both
        // setxattr(path,name,...) and removexattr(path,name).
        if (for_write) {
            std::string name = read_cstr(uaddr(r.arg[1]));
            if (name.rfind("security.", 0) == 0 ||
                name.rfind("system.",   0) == 0 ||
                name.rfind("trusted.",  0) == 0)
                return val(0);
        }
        auto pc = for_write
            ? k_.files().classify(abs, /*for_write=*/true, follow, Wi::copy_leaf)
            : k_.files().classify(abs, /*for_write=*/false, follow);
        if (pc.realm == kernel::Realm2::virtual_file) return eno(Errno::enotsup);
        if (pc.host_path.empty()) return eno(pc.error);
        // Hand the guest path along so PathArg can see this is an identity
        // translation and the trap loop can forward instead of rewriting.
        return Redirect{PathArg{path_arg, std::move(pc.host_path), abs}};
    }

    [[nodiscard]] Outcome do_getcwd(const Regs& r) {
        std::string_view cwd = k_.files().cwd();
        std::size_t need = cwd.size() + 1;
        std::size_t cap = static_cast<std::size_t>(r.arg[1]);
        // A buffer too small for the path is ERANGE, not EINVAL. glibc's
        // getcwd(NULL, 0) GROWS its buffer by looping while the kernel says
        // ERANGE, so EINVAL turns that loop into an immediate failure --
        // every caller that lets glibc size the buffer breaks. EINVAL is
        // only for size 0 with a non-NULL buffer.
        if (cap == 0) return eno(Errno::einval);
        if (cap < need) return eno(Errno::erange);
        std::vector<std::byte> buf(need);
        for (std::size_t i = 0; i < cwd.size(); ++i)
            buf[i] = static_cast<std::byte>(cwd[i]);
        buf[cwd.size()] = std::byte{0};
        if (!mem_.copy_out(uaddr(r.arg[0]), buf)) return eno(Errno::efault);
        return val(static_cast<std::int64_t>(need));   // getcwd returns length
    }

    [[nodiscard]] Outcome do_close(const Regs& r) {
        k_.files().unbind_fd(static_cast<int>(r.arg[0]));
        return fwd();   // let the child actually close its real fd
    }

    // dup(oldfd): forward, then mirror oldfd's bindings onto the new fd (the
    // forwarded return value). do_dup only knows oldfd here; the run loop
    // reads the result and calls files().mirror_fd(dup_from, retfd).
    [[nodiscard]] Outcome do_dup(const Regs& r) {
        return Forward{DupMirror{static_cast<int>(r.arg[0])}};
    }

    // dup2(oldfd,newfd) / dup3(oldfd,newfd,flags): the new fd number is fixed
    // (arg1). It implicitly closes newfd first, so drop newfd's stale binding,
    // then forward and mirror oldfd -> newfd (== the return value on success).
    [[nodiscard]] Outcome do_dup2(const Regs& r) {
        return Forward{DupMirror{static_cast<int>(r.arg[0]),
                                 static_cast<int>(r.arg[1])}};
    }

    // fcntl(fd,cmd,arg): only F_DUPFD(0)/F_DUPFD_CLOEXEC(1030) create a new fd
    // that must inherit fd's bindings; every other cmd (locks, flags, ...) is
    // a plain forward with no fd->path consequence.
    [[nodiscard]] Outcome do_fcntl(const Regs& r) {
        constexpr std::uint64_t kFDupFd = 0, kFDupFdCloexec = 1030;
        if (r.arg[1] == kFDupFd || r.arg[1] == kFDupFdCloexec)
            return Forward{DupMirror{static_cast<int>(r.arg[0])}};
        return fwd();
    }

    // A single-path mutation (mkdir/rmdir/unlink/chmod/chown/truncate/...):
    // translate the guest path at `path_arg` to its overlay UPPER host path
    // and REDIRECT, with the WriteIntent selecting how the upper layer is
    // prepared (create the leaf itself, copy an existing leaf up, or just
    // resolve for removal). A virtual path (procfs/sysfs) is read-only —
    // refuse with EROFS; an absent target yields its errno.
    using Wi = kernel::FileNamespace::WriteIntent;
    // strict_parent: mkdir/mknod must FAIL when the parent is missing, so they
    // opt out of pre-creating the chain and let the host kernel apply the rule.
    [[nodiscard]] Outcome path_mut(const Regs& r, int path_arg, bool at, Wi wi,
                                   bool strict_parent = false) {
        std::string abs = resolve_arg(r, path_arg, at);
        auto pc = k_.files().classify(abs, /*for_write=*/true, /*follow=*/false, wi);
        if (pc.realm == kernel::Realm2::virtual_file)
            return eno(Errno::erofs);
        // A removal whose target lives ONLY in the read-only lower layer:
        // forwarding the unlink would destroy the pristine rootfs. Record a
        // whiteout (hides the lower file in the overlay view) and report
        // success WITHOUT touching the host. Also drop any shadow meta.
        if (pc.whiteout_lower) {
            k_.files().add_whiteout(abs);
            k_.files().meta().forget(abs);
            return val(0);
        }
        if (pc.host_path.empty()) return eno(pc.error);
        // A removal drops any shadow record so a fresh file created at the same
        // path later starts from the host defaults, not a stale owner/mode.
        if (wi == Wi::remove) k_.files().meta().forget(abs);
        Redirect o{PathArg{path_arg, std::move(pc.host_path)}};
        // Only creates need their parent chain pre-built by the trap; the
        // parents_only classify already mirrored them, so this is belt-and-
        // suspenders for the deep-create case.
        //
        // But make_parents must NOT invent a parent the guest cannot see. It
        // exists so an overlay UPPER layer can mirror a directory chain that
        // already exists in the read-only lower -- not so mkdir behaves like
        // `mkdir -p`. mkdir("/d/a/b") with no /d/a succeeded and created the
        // whole chain where Linux returns ENOENT, so mkdir/mknod opt out and
        // let the host kernel apply the rule against the translated path.
        // Found by the differential harness.
        if (wi == Wi::parents_only) o.make_parents = !strict_parent;
        return o;
    }

    // chmod/fchmodat: RECORD the guest-intended permission bits in the shadow
    // store keyed by guest path, THEN still redirect the syscall to the host
    // (so bits the unprivileged host CAN apply take real effect on the inode,
    // e.g. the executable bit that a real exec needs). The stat overlay later
    // presents the full guest-intended mode regardless of what the host kept.
    // The mode argument follows the path: chmod(path,mode) -> arg1;
    // fchmodat(dirfd,path,mode,flags) -> arg2.
    //
    // Like do_chown, this RECORDS the guest-intended mode in the shadow meta
    // store and reports success WITHOUT forwarding the real chmod. Forwarding
    // was both redundant and failure-prone: linuxity already overlays the
    // recorded mode onto every future stat/statx via scrub_ids (so the guest
    // sees exactly what it set, including setuid/sticky/0000 bits the
    // unprivileged host would silently drop), AND the forwarded host chmod
    // frequently returned EPERM — gpg-agent's `chmod 0700` on its freshly
    // created private-keys-v1.d aborted with "can't set permissions ...:
    // Operation not permitted" purely because the real host chmod on the
    // overlay-upper node failed. Recording-only makes the mode authoritative
    // and coherent regardless of host privilege.
    [[nodiscard]] Outcome do_chmod(const Regs& r, int path_arg, bool at, Wi /*wi*/) {
        std::string abs = resolve_arg(r, path_arg, at);
        std::uint32_t mode = static_cast<std::uint32_t>(
            r.arg[static_cast<std::size_t>(path_arg) + 1]);
        auto pc = k_.files().classify(abs, /*for_write=*/false, /*follow=*/false);
        if (pc.realm == kernel::Realm2::virtual_file) return eno(Errno::erofs);
        if (pc.realm == kernel::Realm2::absent)       return eno(pc.error);
        // ALSO apply the mode to the real host inode, best-effort. The shadow
        // store makes the FULL guest-intended mode authoritative at stat time,
        // but some bits must physically land on the inode to have any effect:
        // above all the EXECUTE bits, which a later execve(2) reads straight
        // from the host file (a pacman/apk .INSTALL scriptlet is chmod 0755'd
        // then execve'd — record-only left it non-executable → EACCES
        // "Permission denied"). We chmod the file we actually own in the
        // overlay upper; a copy-up first ensures a lower-only file gains a
        // writable upper twin to mark. When the inode then carries the bits
        // exactly, the shadow store keeps NO record (it would add nothing).
        std::uint32_t landed = 0xffffffffu;
        {
            auto wc = k_.files().classify(abs, /*for_write=*/true,
                                          /*follow=*/false, Wi::copy_leaf);
            // Skip a symlink: chmod on a symlink either follows it (wrong
            // target) or, with AT_SYMLINK_NOFOLLOW as libarchive passes,
            // returns EOPNOTSUPP on Linux -> "Can't set permissions to 0777"
            // when a package ships a .so symlink. A symlink's own mode is
            // fixed at 0777 and ignored by the kernel, so there is nothing to
            // apply; the shadow store still presents the intended mode at stat
            // time. Only chmod a REGULAR file/dir we own in the upper.
            if (!wc.host_path.empty() && !is_symlink(wc.host_path.c_str())) {
                errno = 0;
                if (::chmod(wc.host_path.c_str(), mode & wire::kPermMask) == 0) {
                    std::uint32_t got = 0;
                    if (hostcompat::host_mode_of(wc.host_path.c_str(), got))
                        landed = got;
                } else if (errno == ENOENT || errno == ENOTDIR) {
                    // Recording-only (see above) must still refuse a path that
                    // does not exist: chmod on a missing file reported success
                    // where Linux returns ENOENT, and the shadow store then
                    // held a mode for a file that was never there. EPERM and
                    // friends stay swallowed -- that is the whole point of
                    // recording. Found by the differential harness.
                    return eno(errno == ENOENT ? Errno::enoent : Errno::enotdir);
                }
            }
        }
        k_.files().meta().set_mode(abs, mode, landed);
        return val(0);
    }

    // fchmod(fd, mode): recover the fd's bound guest path, record the mode in
    // the shadow store, and report success WITHOUT forwarding — same rationale
    // as do_chmod (the recorded mode is authoritative via scrub_ids, and a
    // forwarded host fchmod on an unprivileged process can EPERM/drop bits).
    [[nodiscard]] Outcome do_fchmod(const Regs& r) {
        std::string_view gp = k_.files().path_of_fd(static_cast<int>(r.arg[0]));
        std::uint32_t mode = static_cast<std::uint32_t>(r.arg[1]);
        if (gp.empty()) {
            // No recorded path for this fd. It may still be a perfectly good
            // host fd (one the guest inherited, or opened before we tracked
            // it), so the KERNEL decides: forward and let it answer EBADF
            // for a closed fd. Returning 0 here meant fchmod on a closed fd
            // silently succeeded -- caught by the cwdfs probe.
            return fwd();
        }
        // Best-effort apply to the host inode (execute bit for execve);
        // record in the shadow store only what the inode couldn't take.
        auto wc = k_.files().classify(std::string{gp}, /*for_write=*/true,
                                      /*follow=*/false, Wi::copy_leaf);
        std::uint32_t landed = 0xffffffffu;
        if (!wc.host_path.empty() && ::chmod(wc.host_path.c_str(), mode & wire::kPermMask) == 0) {
            std::uint32_t got = 0;
            if (hostcompat::host_mode_of(wc.host_path.c_str(), got))
                landed = got;
        }
        k_.files().meta().set_mode(std::string{gp}, mode, landed);
        return val(0);
    }

    // chown/lchown/fchownat: RECORD the guest-intended owner in the shadow
    // store and report success WITHOUT touching the host inode (an unprivileged
    // host process cannot chown). A later stat overlays the recorded uid/gid.
    // owner/group args are the two registers after the path (or dirfd+path):
    // chown(path,uid,gid)=>1,2; fchownat(dirfd,path,uid,gid,flags)=>2,3. A
    // component of (uid_t)-1 means "leave unchanged" per chown(2).
    // `follow` distinguishes chown/fchownat (which resolve a symlink to its
    // target) from lchown (which acts on the link itself). It was hardcoded
    // false for all three, so chown through a DANGLING link reported success
    // where the kernel says ENOENT: the existence check stat'ed the link,
    // which is there, instead of the target, which is not.
    [[nodiscard]] Outcome do_chown(const Regs& r, int path_arg, int uid_arg,
                                   int gid_arg, bool at, bool follow) {
        std::string abs = resolve_arg(r, path_arg, at);
        auto pc = k_.files().classify(abs, /*for_write=*/false, follow);
        if (pc.realm == kernel::Realm2::virtual_file) return eno(Errno::erofs);
        if (pc.realm == kernel::Realm2::absent)       return eno(pc.error);
        // classify() MAPS a path, it does not test for existence: a plain
        // host mount returns host_backed for a name that is not there, since
        // the host path is still computable. Ownership is recorded in our own
        // metadata rather than on the inode, so without this check chown on a
        // missing file quietly returned 0 where the kernel says ENOENT --
        // caught by the legacy probe diffing against the live kernel.
        //
        // stat_host_path is an LSTAT, which is right for lchown but would
        // call a dangling link "present" for chown. When following, the
        // target is what must exist.
        if constexpr (requires { mem_.stat_host_path(pc.host_path); }) {
            if (!mem_.stat_host_path(pc.host_path)) return eno(Errno::enoent);
            if (follow && !host_target_exists(pc.host_path))
                return eno(Errno::enoent);
        }
        k_.files().meta().set_owner(
            abs, static_cast<std::uint32_t>(r.arg[static_cast<std::size_t>(uid_arg)]),
            static_cast<std::uint32_t>(r.arg[static_cast<std::size_t>(gid_arg)]));
        return val(0);
    }

    // Does this host path resolve to something real when symlinks are
    // followed? ::access with F_OK is the cheapest way to ask, and unlike
    // the lstat-based fast path it reports a dangling link as absent.
    [[nodiscard]] static bool host_target_exists(const std::string& p) {
        return !p.empty() && ::access(p.c_str(), F_OK) == 0;
    }

    // fchown(fd, uid, gid): same as do_chown but the target is an open fd.
    [[nodiscard]] Outcome do_fchown(const Regs& r) {
        std::string_view gp = k_.files().path_of_fd(static_cast<int>(r.arg[0]));
        if (gp.empty()) {
            // No recorded path for this fd. It may still be a good host fd
            // (inherited, or opened before we tracked it), so let the KERNEL
            // decide and answer EBADF for a closed one. Returning 0 here
            // meant fchown on a closed fd silently succeeded -- the same bug
            // as its sibling fchmod, caught by the cwdfs probe.
            return fwd();
        }
        k_.files().meta().set_owner(std::string{gp},
                                    static_cast<std::uint32_t>(r.arg[1]),
                                    static_cast<std::uint32_t>(r.arg[2]));
        return val(0);
    }

    // A two-path mutation (rename/link and their *at forms): BOTH operands are
    // guest paths, so translate each to its overlay upper host path and hand
    // the trap two rewrites. rename's *at forms carry (olddirfd, oldpath,
    // newdirfd, newpath) => path args 1 and 3; the legacy forms carry
    // (oldpath, newpath) => args 0 and 1. The source is resolved for REMOVAL
    // (it must already exist), the destination CREATES its leaf.
    [[nodiscard]] Outcome path_mut2(const Regs& r, int a1, int a2, bool at,
                                    bool /*at2*/, bool move_meta = false) {
        std::string src = resolve_arg(r, a1, at);
        std::string dst = resolve_second(r, a2, at);
        auto ps = k_.files().classify(src, true, false, Wi::copy_leaf);
        auto pd = k_.files().classify(dst, true, false, Wi::parents_only);
        if (ps.realm == kernel::Realm2::virtual_file ||
            pd.realm == kernel::Realm2::virtual_file)
            return eno(Errno::erofs);
        if (ps.host_path.empty() || pd.host_path.empty())
            return eno(ps.host_path.empty() ? ps.error : pd.error);
        // rename carries the shadow metadata with the file (a hardlink/link
        // does NOT: both names share the inode, so the original keeps its own
        // record). Do the in-store move BEFORE the redirect returns.
        if (move_meta) k_.files().meta().rename(src, dst);
        // Both operands are guest paths, so both get translated, and the
        // destination's parent chain must exist before the host runs it.
        return Redirect{PathArg{a1, std::move(ps.host_path)}}
            .with(PathArg{a2, std::move(pd.host_path)})
            .parents();
    }

    // symlink(target, linkpath) / symlinkat(target, newdirfd, linkpath):
    // `target` is the link's literal CONTENTS — a guest-absolute string the
    // guest will later resolve through OUR namespace — so it must NOT be
    // rewritten to a host path. Only the linkpath (where the symlink lives)
    // is translated to its overlay upper host path.
    // bind/connect(fd, const sockaddr* addr, socklen_t len): for an AF_UNIX
    // socket the filesystem path lives in `addr->sun_path`. linuxity runs the
    // guest UNPRIVILEGED, so chroot(2) is unavailable and the guest is NOT
    // confined by the kernel — path confinement is done by TRANSLATION. A raw
    // absolute sun_path forwarded to bind/connect would therefore resolve on
    // the HOST filesystem, leaking the socket outside the sandbox. So we
    // translate the sun_path into the overlay (below) for BOTH bind and
    // connect, keeping the socket inside the guest's world and letting the two
    // peers meet at the same node.
    [[nodiscard]] Outcome do_sockaddr_un(const Regs& r, bool for_bind) {
        constexpr std::uint16_t kAfUnix = 1;
        const std::uint64_t addr = r.arg[1];
        const std::size_t   len  = static_cast<std::size_t>(r.arg[2]);
        if (addr == 0 || len < 3) return fwd();
        if (get_u16(addr) != kAfUnix) return fwd();

        const std::size_t path_bytes = std::min<std::size_t>(len - 2, 108);
        std::vector<std::byte> pb(path_bytes);
        if (!mem_.copy_in(uaddr(addr + 2), pb)) return fwd();
        if (pb.empty() || pb[0] == std::byte{0}) return fwd();   // abstract
        std::string guest_path(reinterpret_cast<const char*>(pb.data()),
                               ::strnlen(reinterpret_cast<const char*>(pb.data()),
                                         path_bytes));
        if (guest_path.empty() || guest_path.front() != '/') return fwd();

        // ALREADY TRANSLATED? The rewrite below overwrites the guest's
        // sockaddr IN PLACE (it is the caller's own buffer, and the bytes
        // must go in via POKEDATA to be ordered against copy_from_user), so
        // a program that reuses one sockaddr for bind and then connect hands
        // us back a HOST path the second time. Translating that again
        // doubled the prefix -- /tmp is mounted on a directory under /tmp,
        // so bind landed on /tmp/linuxity-tmp-N/sock while connect looked
        // for /tmp/linuxity-tmp-N/linuxity-tmp-N/sock and got ENOENT. The
        // two peers never met, which is every AF_UNIX client/server pair in
        // one process: dbus, gpg-agent, a test harness talking to itself.
        //
        // Translation has to be idempotent. A path that is already inside
        // one of our own mount roots is one we produced, so leave it be.
        if (k_.files().is_host_side_path(guest_path)) return fwd();

        // Where this host lets us put a socket. On Android no directory an
        // app can write permits an AF_UNIX bind (SELinux), so a filesystem
        // translation would be correct and still fail with EACCES; the
        // abstract namespace is the only one available. Both bind and connect
        // come through here and hash the same GUEST path, so the peers still
        // meet -- the name is derived from what they agree on, not from the
        // host path they each translate separately.
        if (k_.files().socket_ns() == kernel::SocketNs::abstract) {
            const std::string name = kernel::abstract_name_for(
                guest_path, k_.files().instance_id());
            // An abstract address is a leading NUL then the name, and its
            // LENGTH is what delimits it -- there is no terminator. Hand the
            // trap the exact bytes to poke.
            std::string addr_bytes;
            addr_bytes.push_back('\0');
            addr_bytes += name;
            if (addr_bytes.size() > 108) return fwd();
            const std::uint64_t alen = 2 + addr_bytes.size();
            return SockRewrite{uaddr(addr + 2), std::move(addr_bytes),
                               /*len_arg=*/2, alen};
        }

        // Translate the AF_UNIX filesystem path into the SAME host path a file
        // open of guest_path would resolve to. The guest is NOT chroot'd when
        // linuxity runs unprivileged (chroot(2) needs CAP_SYS_CHROOT), so a
        // raw-forwarded absolute sun_path binds/connects against the HOST
        // filesystem — leaking the socket onto the host and colliding with
        // stale host sockets ("Address already in use", stat "Bad address").
        // Redirecting the path keeps the socket inside the overlay, and
        // because BOTH bind and connect run through here they resolve to the
        // identical node, so the two peers meet.
        //
        // For a bind we want the WRITABLE upper layer (create the node there)
        // and materialize its parent chain; for a connect we want wherever the
        // socket currently lives. classify(for_write=for_bind) yields that.
        auto pc = k_.files().classify(guest_path, /*for_write=*/for_bind,
                                      /*follow=*/false,
                                      for_bind ? Wi::parents_only : Wi::copy_leaf);
        if (pc.realm == kernel::Realm2::virtual_file || pc.host_path.empty())
            return fwd();
        std::string host_path = std::move(pc.host_path);

        // The translated host path must fit in sun_path (108 bytes incl. NUL).
        // The overlay prefix (/tmp/linuxity-upper-<pid>) is short so real
        // socket paths fit; a pathological overflow falls back to a raw
        // forward rather than truncating (truncation is worse).
        if (host_path.size() + 1 > 108) return fwd();

        if (for_bind) {
            // Pre-unlink any stale socket at the translated path so the
            // forwarded bind never hits EADDRINUSE. Cover both layers.
            auto rd = k_.files().classify(guest_path, /*for_write=*/false,
                                          /*follow=*/false);
            (void)::unlink(host_path.c_str());
            if (!rd.host_path.empty() && rd.host_path != host_path)
                (void)::unlink(rd.host_path.c_str());
        }

        // Emit a socket-path rewrite: the trap pokes host_path into the
        // guest's sun_path and sets the socklen register, then forwards the
        // (now overlay-targeted) bind/connect to the kernel.
        // sizeof(sa_family_t) == 2, then the path bytes and its NUL.
        const std::uint64_t new_len = 2 + host_path.size() + 1;
        return SockRewrite{uaddr(addr + 2), std::move(host_path),
                           /*len_arg=*/2, new_len};
    }

    [[nodiscard]] Outcome path_symlink(const Regs& r, int /*target_arg*/,
                                       int link_arg, bool at) {
        std::string link = at ? resolve_second(r, link_arg, true)
                              : k_.files().absolutize(
                                    read_cstr(uaddr(r.arg[static_cast<std::size_t>(link_arg)])),
                                    k_.files().cwd());
        auto pc = k_.files().classify(link, true, false, Wi::parents_only);
        if (pc.realm == kernel::Realm2::virtual_file)
            return eno(Errno::erofs);
        if (pc.host_path.empty()) return eno(pc.error);
        // Rewrite ONLY the linkpath; `target` stays guest-literal.
        return Redirect{PathArg{link_arg, std::move(pc.host_path)}}.parents();
    }

    // Resolve the SECOND path of an *at two-operand syscall. Its dirfd is the
    // register just before the path (renameat: newdirfd=arg2,newpath=arg3;
    // linkat: newdirfd=arg2,newpath=arg3; symlinkat: newdirfd=arg1,
    // linkpath=arg2). For the legacy (non-at) forms there is no dirfd.
    [[nodiscard]] std::string resolve_second(const Regs& r, int path_arg,
                                             bool at) {
        std::string raw =
            read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
        std::string_view dir =
            at ? dir_of(static_cast<std::int64_t>(r.arg[static_cast<std::size_t>(path_arg) - 1]))
               : std::string_view{};
        return k_.files().absolutize(raw, dir);
    }

    // getdents64(fd, buf, count): if fd names a VIRTUAL directory (procfs),
    // synthesize the linux_dirent64 stream into the guest buffer ourselves.
    // Otherwise forward — host-backed dirs enumerate natively on the real fd.
    // Returns bytes written; 0 at end-of-directory (the getdents contract).
    [[nodiscard]] Outcome do_getdents64(const Regs& r) {
        int fd = static_cast<int>(r.arg[0]);
        auto* ds = k_.files().dir_stream(fd);
        if (!ds) return fwd();               // real (host-backed) directory

        const std::size_t cap = static_cast<std::size_t>(r.arg[2]);
        std::vector<std::byte> out;
        out.reserve(cap < 4096 ? cap : 4096);

        while (ds->pos < ds->entries.size()) {
            const auto& e = ds->entries[ds->pos];
            const std::size_t reclen = wire::dirent_reclen(e.name.size());
            if (out.size() + reclen > cap) break;             // buffer full
            const std::size_t base = out.size();
            out.resize(base + reclen);

            // d_ino must match what a later stat() of this name reports --
            // libalpm matches st_ino against the d_ino it saw, and a
            // positional counter made `pacman -Q` report nothing on an
            // intact DB. The merge records the real host inode; 0 means a
            // purely synthesized node (procfs/sysfs) with no host file
            // behind it, where a positional value is all we have.
            // d_off is a cumulative BYTE cookie, the same unit lseek uses --
            // callers do arithmetic on it (fish seeks by `saved - current`),
            // so an entry index here gave EINVAL on the resulting seek.
            const wire::Dirent de{
                e.ino ? e.ino : ds->pos + 1,
                static_cast<std::int64_t>(ds->byte_off + reclen),
                e.is_symlink() ? wire::DType::symlink
                               : e.is_dir() ? wire::DType::dir
                                            : wire::DType::regular,
                e.name,
            };
            const std::size_t n =
                wire::encode_dirent64(std::span{out}.subspan(base), de);
            if (n == 0) { out.resize(base); break; }          // did not fit
            ds->byte_off += reclen;
            ++ds->pos;
        }
        if (out.empty()) {
            // Either end-of-directory (return 0) or the caller's buffer is too
            // small for even one entry (EINVAL, per getdents(2)).
            if (ds->pos < ds->entries.size()) return eno(Errno::einval);
            return val(0);
        }
        if (!mem_.copy_out(uaddr(r.arg[1]), out)) return eno(Errno::efault);
        return val(static_cast<std::int64_t>(out.size()));
    }

    // Can this host-backed path be stat'd by US, and answered in the SAME
    // trap stop? Returns the fields on yes, nullopt to take the slow path.
    //
    // THE one place that decides, asked by both stat and statx. The
    // alternative -- redirect, step the guest to its syscall exit, scrub the
    // owner out of the buffer the kernel filled -- costs a second ptrace stop,
    // and a host-backed stat is the most common trapped syscall in real
    // workloads (127884 of 150K traps in one `ls -lR /usr/include`, counting
    // both forms). Measured: 0.31us for the host stat plus 0.51us to write the
    // buffer, against ~4.9us for a second stop.
    //
    // Two reasons to decline, both deliberate:
    //
    //   * the backend cannot stat a host path. Asked with `requires` through
    //     mem_ -- the seam already used for current_ids and
    //     models_process_groups -- rather than a new Kernel::host() accessor,
    //     which would widen the portable dispatcher's reach to the whole host
    //     interface for one optimisation. A backend without it keeps the
    //     redirect path, so the failure mode is slower, never wrong.
    //
    //   * the shadow store has a record for this path. A chmod/chown'd file
    //     needs the overlay applied on top of the host's answer, and
    //     scrub_ids already does that correctly against a kernel-filled
    //     buffer. Duplicating that policy here is how the two would drift.
    //
    // A stat that FAILS also declines, so the kernel reports its own errno
    // rather than us guessing which one.
    [[nodiscard]] std::optional<wire::StatFields>
    fast_stat(const std::string& host_path, const std::string& guest_path) {
        if constexpr (requires { mem_.stat_host_path(host_path); }) {
            if (k_.files().meta().lookup(guest_path)) return std::nullopt;
            // NEVER for a host /proc path. The supervisor stats it in ITS OWN
            // context, and /proc is the one tree where that changes the
            // answer: /proc/self/fd/0 is the supervisor's fd 0, as a symlink,
            // not the guest's terminal. ttyname() stats exactly that path and
            // got "symbolic link 0:0" back, so script(1)'s child was "not a
            // tty". Redirecting lets the kernel resolve it in the GUEST, which
            // is right by construction. Cheap to give up: these are rare.
            if (host_path == "/proc" || host_path.starts_with("/proc/"))
                return std::nullopt;
            return mem_.stat_host_path(host_path);
        } else {
            return std::nullopt;
        }
    }

    // Synthesize a `struct statx` (the flat, versioned stat the kernel fills
    // for statx(2)) for a virtual node into the guest buffer.
    [[nodiscard]] Outcome write_statx(UAddr buf, bool is_dir, std::uint64_t size,
                                      bool is_link = false) {
        return write_statx(buf, synth_hstat(is_dir, size, is_link));
    }

    // The HStat a VIRTUAL node implies. Built once, here, so the synthesized
    // mode/ino/blocks story is told in one place and both ABI encoders agree
    // on it.
    [[nodiscard]] static wire::StatFields synth_hstat(bool is_dir, std::uint64_t size,
                                                 bool is_link) {
        wire::StatFields h;
        h.mode = is_link ? wire::bits(wire::FileType::symlink) | 0777u
                   : is_dir  ? wire::bits(wire::FileType::dir) | 0555u
                             : wire::bits(wire::FileType::regular) | 0444u;
        h.ino    = 1;
        h.nlink  = 1;
        h.size   = size;
        h.blocks = static_cast<std::int64_t>((size + 511) / 512);
        return h;
    }

    // The HStat form: a REAL host file. See write_statbuf's overload.
    [[nodiscard]] Outcome write_statx(UAddr buf, const wire::StatFields& h) {
        struct Statx {
            std::uint32_t stx_mask, stx_blksize;
            std::uint64_t stx_attributes;
            std::uint32_t stx_nlink, stx_uid, stx_gid;
            std::uint16_t stx_mode; std::uint16_t __spare0[1];
            std::uint64_t stx_ino, stx_size, stx_blocks, stx_attributes_mask;
            struct { std::int64_t tv_sec; std::uint32_t tv_nsec; std::int32_t __pad; }
                stx_atime, stx_btime, stx_ctime, stx_mtime;
            std::uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
            std::uint64_t stx_mnt_id, __spare2;
            std::uint64_t __spare3[12];
        } sx{};
        constexpr std::uint32_t kBasicStats = 0x7ff;  // STATX_BASIC_STATS
        sx.stx_mask    = kBasicStats;
        sx.stx_blksize = static_cast<std::uint32_t>(h.blksize);
        sx.stx_nlink   = static_cast<std::uint32_t>(h.nlink);
        // uid/gid stay 0: the guest is root and sees root-owned files, the
        // same policy scrub_ids applies to a forwarded stat.
        sx.stx_mode    = static_cast<std::uint16_t>(h.mode);
        sx.stx_ino     = h.ino;
        sx.stx_size    = h.size;
        sx.stx_blocks  = static_cast<std::uint64_t>(h.blocks);
        sx.stx_mtime   = {static_cast<std::int64_t>(h.mtime_ns / 1'000'000'000ull),
                          static_cast<std::uint32_t>(h.mtime_ns % 1'000'000'000ull), 0};
        sx.stx_atime   = {static_cast<std::int64_t>(h.atime_ns / 1'000'000'000ull),
                          static_cast<std::uint32_t>(h.atime_ns % 1'000'000'000ull), 0};
        sx.stx_ctime   = {static_cast<std::int64_t>(h.ctime_ns / 1'000'000'000ull),
                          static_cast<std::uint32_t>(h.ctime_ns % 1'000'000'000ull), 0};
        sx.stx_btime   = sx.stx_ctime;
        // Device numbers. statx carries them split into major/minor, and
        // these were simply never written -- so the one-stop stat reported
        // EVERY device as 0:0. That broke ttyname(): glibc stats the
        // /dev/pts/N it found and compares st_rdev against fd 0's, and 0:0
        // never matched the real 136:N, so script(1)'s child got "not a tty".
        // Split with the kernel's own new_decode_dev() layout, the inverse of
        // makedev(): major in bits 8-19 and 32-43, minor in bits 0-7 and 20-31.
        const auto major_of = [](std::uint64_t d) {
            return static_cast<std::uint32_t>(((d >> 8) & 0xfffu) |
                                              ((d >> 32) & 0xfffff000u));
        };
        const auto minor_of = [](std::uint64_t d) {
            return static_cast<std::uint32_t>((d & 0xffu) |
                                              ((d >> 12) & 0xffffff00u));
        };
        sx.stx_rdev_major = major_of(h.rdev);
        sx.stx_rdev_minor = minor_of(h.rdev);
        sx.stx_dev_major  = major_of(h.dev);
        sx.stx_dev_minor  = minor_of(h.dev);
        if (!mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(&sx), sizeof sx}))
            return eno(Errno::efault);
        return val(0);
    }

    // Synthesize a `struct stat` for a virtual file into the guest buffer,
    // in THIS GUEST ARCH's layout. The two 64-bit Linux ABIs differ: x86-64
    // has st_nlink as u64 before st_mode and is 144 bytes; aarch64 (the
    // asm-generic layout) has u32 st_mode then u32 st_nlink and is 128
    // bytes. Writing the x86-64 struct into an aarch64 guest overruns its
    // buffer by 16 bytes -- glibc's stack protector catches that as "stack
    // smashing detected" the first time anything stats /dev/pts.
    [[nodiscard]] Outcome write_statbuf(UAddr buf, bool is_dir, std::uint64_t size,
                                        bool is_link = false) {
        return write_statbuf(buf, synth_hstat(is_dir, size, is_link));
    }

    // The HStat form: a REAL host file, stat'd by the dispatcher so a
    // host-backed stat is answered in the SAME trap stop instead of
    // redirecting the call and stepping the guest to its syscall exit. Shares
    // this encoder with the synthesized form above, so one place knows each
    // ABI's layout.
    [[nodiscard]] Outcome write_statbuf(UAddr buf, const wire::StatFields& h) {
        const std::uint32_t mode = h.mode;
        const std::int64_t blocks = h.blocks;
        const std::uint64_t size = h.size;
        if (arch_ == Arch::aarch64) {
            struct StatGeneric {
                std::uint64_t st_dev, st_ino;
                std::uint32_t st_mode, st_nlink, st_uid, st_gid;
                std::uint64_t st_rdev, pad1_;
                std::int64_t st_size;
                std::int32_t st_blksize, pad2_;
                std::int64_t st_blocks;
                std::int64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
                std::uint32_t unused_[2];
            } st{};
            static_assert(sizeof(StatGeneric) == 128);
            st.st_dev = h.dev; st.st_ino = h.ino;
            st.st_nlink = static_cast<std::uint32_t>(h.nlink);
            st.st_mode = mode; st.st_rdev = h.rdev;
            // uid/gid stay 0: the guest is root and sees root-owned files,
            // the same policy scrub_ids applies to a forwarded stat.
            st.st_size = static_cast<std::int64_t>(size);
            st.st_blksize = static_cast<std::int32_t>(h.blksize);
            st.st_blocks = blocks;
            st.mtime = static_cast<std::int64_t>(h.mtime_ns / 1'000'000'000ull);
            st.mtime_ns = static_cast<std::int64_t>(h.mtime_ns % 1'000'000'000ull);
            st.atime = static_cast<std::int64_t>(h.atime_ns / 1'000'000'000ull);
            st.atime_ns = static_cast<std::int64_t>(h.atime_ns % 1'000'000'000ull);
            st.ctime = static_cast<std::int64_t>(h.ctime_ns / 1'000'000'000ull);
            st.ctime_ns = static_cast<std::int64_t>(h.ctime_ns % 1'000'000'000ull);
            if (!mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(&st), sizeof st}))
                return eno(Errno::efault);
            return val(0);
        }
        struct Stat64 {
            std::uint64_t st_dev; std::uint64_t st_ino; std::uint64_t st_nlink;
            std::uint32_t st_mode; std::uint32_t st_uid; std::uint32_t st_gid;
            std::uint32_t __pad0; std::uint64_t st_rdev; std::int64_t st_size;
            std::int64_t st_blksize; std::int64_t st_blocks;
            std::uint64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
            std::int64_t reserved_[3];
        } st{};
        static_assert(sizeof(Stat64) == 144);
        st.st_dev     = h.dev;
        st.st_ino     = h.ino;
        st.st_nlink   = h.nlink;
        st.st_mode    = mode;
        st.st_rdev    = h.rdev;
        st.st_size    = static_cast<std::int64_t>(size);
        st.st_blksize = h.blksize;
        st.st_blocks  = blocks;
        st.mtime      = h.mtime_ns / 1'000'000'000ull;
        st.mtime_ns   = h.mtime_ns % 1'000'000'000ull;
        st.atime      = h.atime_ns / 1'000'000'000ull;
        st.atime_ns   = h.atime_ns % 1'000'000'000ull;
        st.ctime      = h.ctime_ns / 1'000'000'000ull;
        st.ctime_ns   = h.ctime_ns % 1'000'000'000ull;
        if (!mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(&st), sizeof st}))
            return eno(Errno::efault);
        return val(0);
    }

    // Synthesize a `struct statfs` for a VIRTUAL path (procfs/sysfs), which
    // has no backing block device. We report a plausible in-memory
    // filesystem so `df` and statvfs on /proc or /sys return coherent
    // numbers instead of the host's real device stats. The layout is the
    // x86-64 kernel `struct statfs` (64-bit fields; f_type..f_spare) used by
    // statfs(2)/fstatfs(2).
    //
    // f_type MUST match the mount. It was TMPFS_MAGIC for everything, so
    // statfs("/proc") reported tmpfs where the kernel says PROC_SUPER_MAGIC
    // -- and f_type is exactly what a program branches on to decide whether
    // a path is procfs (systemd, util-linux and container runtimes all do
    // this before trusting /proc). Caught by diffing against the live
    // kernel once the statfs path had a probe at all.
    [[nodiscard]] Outcome write_statfs(UAddr buf, std::string_view path) {
        struct Statfs {
            std::int64_t  f_type;
            std::int64_t  f_bsize;
            std::uint64_t f_blocks, f_bfree, f_bavail;
            std::uint64_t f_files, f_ffree;
            struct { std::int32_t v[2]; } f_fsid;
            std::int64_t  f_namelen;
            std::int64_t  f_frsize;
            std::int64_t  f_flags;
            std::int64_t  f_spare[4];
        } sf{};
        // The magic each of these filesystems really reports.
        constexpr std::int64_t kProcMagic  = 0x9fa0;
        constexpr std::int64_t kSysfsMagic = 0x62656572;
        constexpr std::int64_t kDevtmpfs   = 0x01021994;   // devtmpfs IS tmpfs
        constexpr std::int64_t kTmpfsMagic = 0x01021994;
        sf.f_type    = path.starts_with("/proc") ? kProcMagic
                     : path.starts_with("/sys")  ? kSysfsMagic
                     : path.starts_with("/dev")  ? kDevtmpfs
                                                 : kTmpfsMagic;
        sf.f_bsize   = 4096;
        sf.f_frsize  = 4096;
        sf.f_namelen = 255;
        // A synthesized in-memory fs: advertise capacity but report it as
        // fully free (procfs/sysfs never "fill up").
        sf.f_blocks  = 1u << 20;   // 4 GiB @ 4 KiB blocks
        sf.f_bfree   = sf.f_blocks;
        sf.f_bavail  = sf.f_blocks;
        sf.f_files   = 1u << 16;
        sf.f_ffree   = sf.f_files;
        if (!mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(&sf), sizeof sf}))
            return eno(Errno::efault);
        return val(0);
    }

    // The virtual machine's canonical spec. The real Kernel owns ONE
    // MachineSpec (kernel/machine.hpp) and every /proc & /sys synthesizer
    // reads the same instance, so sysinfo/sched_getaffinity here agree with
    // them by construction. A bare kernel (tests) falls back to the default
    // spec, which is the same struct with its default field values.
    [[nodiscard]] const kernel::MachineSpec& machine() {
        if constexpr (requires { k_.machine(); }) {
            return k_.machine();
        } else {
            static const kernel::MachineSpec fallback{};
            return fallback;
        }
    }

    // sysinfo(2): fill `struct sysinfo` for linuxity's virtual machine. The
    // layout is the x86-64 kernel ABI (mem_unit == 1, so *ram fields are in
    // bytes). Only the fields tools read are populated meaningfully.
    [[nodiscard]] Outcome do_sysinfo(UAddr buf) {
        struct Sysinfo {
            std::int64_t uptime;
            std::uint64_t loads[3];
            std::uint64_t totalram, freeram, sharedram, bufferram;
            std::uint64_t totalswap, freeswap;
            std::uint16_t procs; std::uint16_t pad;
            std::uint64_t totalhigh, freehigh;
            std::uint32_t mem_unit;
            std::uint32_t _pad2;   // align to 8; kernel's _f[] is empty on 64-bit
        } si{};
        const auto& m = machine();
        si.uptime    = static_cast<std::int64_t>(m.uptime_seconds());
        si.loads[0]  = si.loads[1] = si.loads[2] = 0;
        si.totalram  = m.mem_total;
        si.freeram   = m.mem_free();
        si.bufferram = m.mem_buffers();
        si.totalswap = m.swap_total;
        si.freeswap  = m.swap_total;
        si.procs     = static_cast<std::uint16_t>(k_.procs().count());
        si.mem_unit  = 1;                            // ram fields are bytes
        if (!mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(&si), sizeof si}))
            return eno(Errno::efault);
        return val(0);
    }

    // sched_getaffinity(pid, cpusetsize, mask): write a cpu_set with the low
    // `ncpu` bits set into the guest mask, and return the number of bytes
    // used (the kernel returns the size of the affinity mask it wrote).
    [[nodiscard]] Outcome do_sched_getaffinity(const Regs& r) {
        std::size_t cap = static_cast<std::size_t>(r.arg[1]);
        UAddr mask = uaddr(r.arg[2]);
        long ncpu = machine().ncpu;
        std::size_t bytes = ((static_cast<std::size_t>(ncpu) + 63) / 64) * 8;
        if (bytes < 8) bytes = 8;
        if (cap < bytes) bytes = cap;           // honor the caller's buffer
        if (bytes == 0) return eno(Errno::einval);
        std::vector<std::byte> buf(bytes, std::byte{0});
        for (long c = 0; c < ncpu; ++c) {
            std::size_t byte = static_cast<std::size_t>(c) / 8;
            if (byte >= bytes) break;
            buf[byte] |= static_cast<std::byte>(1u << (static_cast<unsigned>(c) & 7u));
        }
        if (!mem_.copy_out(mask, buf)) return eno(Errno::efault);
        return val(static_cast<std::int64_t>(bytes));
    }

    // ioctl(fd, request, argp): MOST requests act on a real host fd (TCGETS,
    // winsize, FIONREAD, ...) and forward. The JOB-CONTROL group reads/writes
    // PIDs; we virtualize it so the guest session leader cleanly owns its tty.
    // TIOCGPGRP/TIOCGSID report the caller's own pgrp and TIOCSPGRP is a
    // satisfied no-op, so a guest shell settles at its prompt (and runs bg
    // jobs) instead of spinning to seize the terminal. Forwarding these to the
    // real tty is NOT reliable under ptrace: the terminal's foreground-group
    // bookkeeping is against pids the guest doesn't own coherently, and a
    // forwarded TIOCGPGRP that answers -1 makes bash disable job control
    // outright ("cannot set terminal process group"). The stable contract is a
    // fully virtualized job-control view.
    [[nodiscard]] Outcome do_ioctl(const Regs& r) {
        constexpr std::uint64_t kTIOCGPGRP = 0x540F;  // get fg process group
        constexpr std::uint64_t kTIOCSPGRP = 0x5410;  // set fg process group
        constexpr std::uint64_t kTIOCGSID  = 0x5429;  // get session id
        // The classic termios requests, and the termios2 ones glibc >= 2.42
        // uses instead. Raw numbers: the TCGETS2 macro needs struct termios2,
        // which isn't in every host's headers, and these are arch-independent.
        constexpr std::uint64_t kTCGETS   = 0x5401;
        constexpr std::uint64_t kTCSETS   = 0x5402;
        constexpr std::uint64_t kTCSETSW  = 0x5403;   // ...after draining
        constexpr std::uint64_t kTCSETSF  = 0x5404;   // ...after flushing
        constexpr std::uint64_t kTCGETS2  = 0x802c542a;
        constexpr std::uint64_t kTCSETS2  = 0x402c542b;
        constexpr std::uint64_t kTCSETSW2 = 0x402c542c;
        constexpr std::uint64_t kTCSETSF2 = 0x402c542d;
        // An ioctl request is a 32-bit number, but it rides in a 64-bit
        // register and the direction bit makes TCGETS2 (0x802c542a) negative
        // as a signed int -- so a guest that passes it through an int argument
        // sign-extends it to 0xffffffff802c542a. musl does, glibc does not.
        // Compare the low 32 bits so both spellings hit the same arm.
        const std::uint64_t request = r.arg[1] & 0xffffffffULL;
        // Android's SELinux ioctl whitelist permits the classic termios
        // requests on a pty slave but not the termios2 ones, so the rootfs's
        // glibc gets EACCES on every tcgetattr/tcsetattr/isatty/ttyname and
        // `tty` claims "not a tty". Serve them with the classic request and fix
        // the struct: termios2 is termios plus c_ispeed/c_ospeed, and the
        // leading bytes are identical, so a set needs no conversion at all and
        // a get only needs the two speeds appended.
        {
            const std::uint64_t classic = [&]() -> std::uint64_t {
                switch (request) {
                    case kTCGETS2:  return kTCGETS;
                    case kTCSETS2:  return kTCSETS;
                    case kTCSETSW2: return kTCSETSW;
                    case kTCSETSF2: return kTCSETSF;
                    default:        return 0;
                }
            }();
            if (classic != 0)
                return ArgRewrite{
                    1, classic,
                    request == kTCGETS2
                        ? ArgRewrite::Convert::termios_to_termios2
                        : ArgRewrite::Convert::none,
                    uaddr(r.arg[2])};
        }
        // A backend that models real process groups (HVF) also owns the
        // terminal's foreground group: forward, so tcsetpgrp actually moves
        // ^C/^Z delivery to the job and the shell survives ^Z.
        if constexpr (requires { mem_.models_process_groups(); })
            if (request == kTIOCGPGRP || request == kTIOCSPGRP || request == kTIOCGSID)
                return fwd();
        switch (request) {
            // Report the caller's OWN pgrp as the terminal's foreground group
            // (and its own sid as the session): the guest owns its tty, so the
            // shell settles at the prompt instead of looping to acquire it.
            //
            // TIOCGPGRP must agree with getpgrp, so it reports the group
            // setpgid last set rather than the bare pid. They disagreed once
            // bash called setpgid (discarded by the flat model, but getpgrp
            // reported it), so bash's "loop until tcgetpgrp == getpgrp" never
            // converged, it gave up with "no job control", and that turns off
            // line editing -- arrow keys echo as ^[[A. The session id is a
            // different question and stays the pid.
            //
            // Only when the fd really is the caller's CONTROLLING terminal,
            // though. Answering for any fd meant TIOCGPGRP succeeded on
            // /dev/null and on a closed fd, where the kernel says ENOTTY and
            // EBADF -- the ioctls probe caught both by diffing against the
            // live kernel. "Is it a tty" is not the test either: a pty slave
            // opened O_NOCTTY IS a terminal but is not OUR controlling one,
            // and the kernel still says ENOTTY. Only the kernel knows, so ask
            // it: forward, and rewrite the answer only if it succeeded.
            case kTIOCGPGRP:
                return ArgRewrite{1, request,
                                  ArgRewrite::Convert::own_pgrp,
                                  uaddr(r.arg[2]), flat_pgrp()};
            case kTIOCGSID:
                return ArgRewrite{1, request,
                                  ArgRewrite::Convert::own_sid,
                                  uaddr(r.arg[2]), ids().pid};
            // Accept a foreground-group change and REMEMBER it: the next
            // tcgetpgrp has to report what was just set or the shell decides
            // it lost the terminal.
            //
            // The VALUE must not reach the kernel. tcgetpgrp above reports
            // the guest's pgrp (pid 1 and friends), so the shell hands that
            // straight back here -- and pgid 1 does not exist on the host,
            // so a forwarded TIOCSPGRP is EPERM and bash prints "cannot set
            // terminal process group" and drops job control. The guest is
            // already the terminal's foreground group as far as the host is
            // concerned; what it is really asking is to move the group
            // WITHIN its own namespace, which is ours to track.
            //
            // The fd still has to be vetted, or this succeeds on /dev/null
            // where the kernel says ENOTTY. TIOCGPGRP is the read-only probe
            // for exactly that question, so rewrite to it: the kernel decides
            // whether this fd is our controlling terminal, and the recorded
            // group is updated only if it said yes.
            case kTIOCSPGRP: {
                const std::uint32_t want = get_u32(r.arg[2]);
                if (want != 0) flat_pgrp_ = static_cast<std::int32_t>(want);
                // Convert::none: TIOCGPGRP writes the host's pgrp into the
                // buffer, but this is a SETTER and that buffer is the
                // caller's input -- leave it exactly as the guest wrote it.
                // Only the kernel's verdict on the fd is wanted.
                return ArgRewrite{1, kTIOCGPGRP,
                                  ArgRewrite::Convert::restore_u32,
                                  uaddr(r.arg[2]), static_cast<std::int32_t>(want)};
            }
            default:
                return fwd();   // real host tty/device ioctl
        }
    }

    // getresuid/getresgid: write real=eff=saved id, all 0 (our root world),
    // into the three uid_t* the guest passed (arg0/arg1/arg2). Answers
    // identically to getuid/geteuid so bash's $UID/$EUID and sudo's
    // credential check see uid 0.
    //
    // All three pointers are REQUIRED. The kernel has no "skip NULL" rule
    // here -- unlike, say, waitpid's status -- so a null is EFAULT. Skipping
    // them instead returned 0 where the kernel fails, which the creds probe
    // caught by diffing against the live kernel.
    [[nodiscard]] Outcome do_getres(const Regs& r) {
        if (!r.arg[0] || !r.arg[1] || !r.arg[2]) return eno(Errno::efault);
        // A non-null pointer can still be unwritable. put_u32 used to
        // swallow that, so writing through 0x1 reported success where the
        // kernel says EFAULT -- the null check caught only the easy half.
        if (!put_u32(r.arg[0], 0) || !put_u32(r.arg[1], 0) ||
            !put_u32(r.arg[2], 0))
            return eno(Errno::efault);
        return val(0);
    }

    // struct utsname: 6 fixed-size NUL-terminated char[65] fields. We
    // synthesize linuxity's identity and copy it into the guest buffer.
    Outcome do_uname(UAddr buf) {
        struct Uts { char sysname[65], nodename[65], release[65],
                          version[65], machine[65], domainname[65]; };
        Uts u{};
        auto set = [](char (&dst)[65], const char* s) {
            std::size_t i = 0; for (; s[i] && i < 64; ++i) dst[i] = s[i]; dst[i] = 0;
        };
        set(u.sysname,  "Linux");
        const auto& m = machine();
        set(u.nodename, m.nodename.c_str());
        set(u.release,  m.release.c_str());
        set(u.version,  "#1 linuxity portable Linux ABI");
        set(u.machine,  m.machine_arch.c_str());
        set(u.domainname, "(none)");
        if (!mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(&u), sizeof u}))
            return val(-static_cast<std::int64_t>(Errno::efault));
        return val(0);
    }

    K& k_;
    M& mem_;
    Arch arch_;
    std::string pending_open_;   // guest path awaiting fd assignment by trap
    bool pending_dir_{false};    // the pending open is a virtual directory
    std::string pending_lazy_;   // overlaid host dir: union built on 1st getdents
    std::vector<kernel::VirtualDirent> pending_entries_;
public:
    // The trap calls this after a redirect/inject syscall returns a real fd,
    // so the namespace can bind the guest path to that fd (readlinkat etc.),
    // and — for a virtual directory — the entries getdents64 will enumerate.
    void note_opened_fd(std::int64_t fd) {
        if (fd >= 0) {
            // A newly opened fd REPLACES whatever that number meant before.
            //
            // close(2) is deliberately untrapped on the seccomp fast path (it
            // fires on every fd teardown), so when a guest closes a directory
            // fd we never hear about it -- its DirStream stays registered. The
            // kernel then hands the SAME number to the next open(). If that
            // open is a FILE, the stale stream turns its lseek into a virtual
            // directory seek: the host fd never rewinds, the re-read returns
            // the wrong bytes, and a parser sees garbage.
            //
            // That is exactly how `ps aux` died with SIGFPE. libproc2 opens
            // /proc/meminfo, gets the fd a just-closed /proc dir had, and
            // re-reads it via lseek(fd, 0, SEEK_SET). The seek was swallowed,
            // MemTotal parsed as 0, and pr_pmem divided by it. It only became
            // reachable once lseek was trapped (for rewinddir) -- the two fixes
            // are correct individually and wrong together.
            //
            // The open is the one event we DO see, so drop the stale binding
            // (path and dir stream) here; bind_fd/bind_dir below re-establish
            // whatever this open actually is.
            k_.files().unbind_fd(static_cast<int>(fd));
        }
        if (fd >= 0 && !pending_open_.empty()) {
            k_.files().bind_fd(static_cast<int>(fd), pending_open_);
            if (pending_dir_) {
                // An overlaid host directory defers its union to the first
                // getdents64; a virtual (procfs/sysfs) directory already has
                // its entries synthesized.
                if (!pending_lazy_.empty())
                    k_.files().bind_lazy_dir(static_cast<int>(fd),
                                             std::move(pending_lazy_));
                else
                    k_.files().bind_dir(static_cast<int>(fd),
                                        std::move(pending_entries_));
            }
        }
        pending_open_.clear();
        pending_dir_ = false;
        pending_lazy_.clear();
        pending_entries_.clear();
    }

    // Called by the run loop after a forwarded dup/dup2/dup3/fcntl(F_DUPFD*)
    // succeeds: mirror the source fd's path/dir binding onto the new fd so an
    // *at call or getdents on the dup resolves the same path/entries.
    void on_fd_dup(int from, int to) { k_.files().mirror_fd(from, to); }
    // Called when a dup2/dup3 target fd is implicitly closed before the dup.
    void on_fd_closed(int fd) { k_.files().unbind_fd(fd); }

    // After a host-backed stat/statx REDIRECT returns success, the guest
    // buffer holds the HOST inode's mode/uid/gid. linuxity presents a root-
    // owned world AND honors the guest's own chmod/chown history, so we OVERLAY
    // the shadow metadata store on top of the host result in place:
    //
    //   * uid/gid default to 0 (root world), OR to the guest-intended owner if
    //     the guest chown'd this path (fake_id0-grade coherent ownership).
    //   * mode keeps the host inode's FILE-TYPE bits (S_IFMT) but takes the
    //     guest-intended permission+special bits (07777) when the guest chmod'd
    //     it — so setuid/sticky/0000 round-trip even when the unprivileged host
    //     silently dropped them.
    //
    // The field offsets match the layouts write_statbuf/write_statx synthesize,
    // so there is one definition of where mode/uid/gid live. No-op unless
    // o.scrub is set. Reads the current bytes back via copy_in so the host's
    // real file-type and any bits we keep are preserved.
    // Called only when a Redirect actually carried a Scrub, so there is no
    // "none" case to test for: the caller's `if (r.scrub)` is the only check.
    void scrub_ids(const Scrub& s) {
        const bool is_statx = s.layout == Scrub::Layout::statx;
        // Field offsets differ per ABI, and the definition lives in ONE place
        // (abi/wire/stat.hpp) that both backends' LinuxStat/LinuxStatx structs
        // static_assert against. They used to be computed inline here as a
        // third independent copy -- all three correct, which is precisely the
        // danger: a drift in any one reports a plausible WRONG mode (0644 for
        // a 0755 file) or reads st_uid out of padding.
        //
        //   struct stat x86-64  : st_mode u32 @24, st_uid @28, st_gid @32.
        //   struct stat aarch64 : st_mode u32 @16, st_uid @24, st_gid @28
        //                         (asm-generic: nlink is u32 and AFTER mode).
        //   struct statx (both) : stx_mode u16 @28, stx_uid @20, stx_gid @24.
        const wire::StatLayout& L =
            is_statx ? wire::kStatx : wire::stat_layout(arch_);
        const std::size_t mode_off = L.mode;
        const std::size_t uid_off  = L.uid;
        const std::size_t gid_off  = L.gid;
        const std::uint64_t base = value(s.buf);

        // The shadow record for this guest path, if the guest ever chmod/chown'd
        // it. Default (no record) => root-owned, host mode untouched.
        std::optional<kernel::MetaRecord> rec;
        if (!s.guest_path.empty())
            rec = k_.files().meta().lookup(s.guest_path);

        // --- uid/gid: default root (0,0); honor recorded owner if present ---
        std::uint32_t uid = 0, gid = 0;
        if (rec) {
            if (rec->have & kernel::MetaRecord::kUid) uid = rec->uid;
            if (rec->have & kernel::MetaRecord::kGid) gid = rec->gid;
        }
        // uid and gid are ADJACENT u32s on every layout we serve (x86-64
        // stat @28/@32, aarch64 stat @24/@28, statx @20/@24), so write them as
        // one 8-byte copy: one process_vm_writev per stat instead of two.
        // Fall back to two writes if a future layout ever splits them.
        // The scrub overlays fields on a buffer the KERNEL already filled
        // successfully, so the address is known good and a failed write here
        // is not an EFAULT the guest should see -- the syscall it asked for
        // worked. Discarding is deliberate; the casts say so, since put_u32
        // is [[nodiscard]] precisely so the callers that CAN fail (getresuid
        // writing through a guest pointer) cannot ignore it by accident.
        if (gid_off == uid_off + 4) {
            std::array<std::byte, 8> b{};
            std::memcpy(b.data(), &uid, 4);
            std::memcpy(b.data() + 4, &gid, 4);
            (void)mem_.copy_out(uaddr(base + uid_off), b);
        } else {
            (void)put_u32(base + uid_off, uid);
            (void)put_u32(base + gid_off, gid);
        }

        // --- mode: overlay the guest-intended permission bits when recorded ---
        if (rec && (rec->have & kernel::MetaRecord::kMode)) {
            if (is_statx) {
                std::uint16_t host_mode = get_u16(base + mode_off);
                std::uint16_t eff = static_cast<std::uint16_t>(
                    kernel::MetaStore::effective_mode(host_mode, *rec));
                put_u16(base + mode_off, eff);
            } else {
                std::uint32_t host_mode = get_u32(base + mode_off);
                (void)put_u32(base + mode_off,
                              kernel::MetaStore::effective_mode(host_mode, *rec));
            }
        }
    }

    // Small typed guest-memory pokes/peeks for the scrub overlay.
    // Returns false if the guest buffer could not be written -- an unmapped
    // or read-only address, which the kernel answers with EFAULT. The result
    // used to be discarded, so a handler that wrote through a bad pointer
    // reported success: getresuid(0x1,0x1,0x1) returned 0 where the kernel
    // returns -1. Callers that can fail must check it.
    [[nodiscard]] bool put_u32(std::uint64_t addr, std::uint32_t v) {
        std::array<std::byte, 4> b{};
        std::memcpy(b.data(), &v, 4);
        return static_cast<bool>(mem_.copy_out(uaddr(addr), b));
    }
    void put_u16(std::uint64_t addr, std::uint16_t v) {
        std::array<std::byte, 2> b{};
        std::memcpy(b.data(), &v, 2);
        (void)mem_.copy_out(uaddr(addr), b);
    }
    [[nodiscard]] std::uint32_t get_u32(std::uint64_t addr) {
        std::array<std::byte, 4> b{};
        if (!mem_.copy_in(uaddr(addr), b)) return 0;
        std::uint32_t v = 0; std::memcpy(&v, b.data(), 4); return v;
    }
    [[nodiscard]] std::uint16_t get_u16(std::uint64_t addr) {
        std::array<std::byte, 2> b{};
        if (!mem_.copy_in(uaddr(addr), b)) return 0;
        std::uint16_t v = 0; std::memcpy(&v, b.data(), 2); return v;
    }

    // True iff `path` is a symbolic link (lstat, no follow). Used to skip a
    // pointless/failing host chmod on a symlink the guest is "chmod"ing.
    // Delegates to the host shim: Win32 has no POSIX symlinks, so there the
    // answer is always false.
    static bool is_symlink(const char* path) {
        return hostcompat::path_is_symlink(path);
    }
};

} // namespace lx::abi
