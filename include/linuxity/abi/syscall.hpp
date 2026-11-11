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
#include "linuxity/host/tmpdir.hpp"
#include "linuxity/kernel/file_namespace.hpp"
#include "linuxity/kernel/machine.hpp"
#include "linuxity/kernel/nl80211.hpp"
#include "linuxity/kernel/process_table.hpp"
#include "linuxity/kernel/subsystem.hpp"
#include "linuxity/abi/identity.hpp"
#include "linuxity/abi/outcome.hpp"
#include "linuxity/abi/wire/at_flags.hpp"
#include "linuxity/abi/wire/dirent64.hpp"
#include "linuxity/abi/wire/open_flags.hpp"
#include "linuxity/abi/wire/stat.hpp"
#include "linuxity/loader/interp.hpp"
#include "linuxity/vfs/pty_names.hpp"

#include <array>
#include "linuxity/abi/creds.hpp"
#include "linuxity/abi/fsnotify_events.hpp"
#include "linuxity/abi/wire/errno_map.hpp"
#include <cstdint>
#include <cstring>
#include <sys/stat.h>
#include "linuxity/host/win_posix.hpp"
#include <optional>
#include <span>
#include <set>
#include <string>
#include <map>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <dirent.h>
#include <fcntl.h>
#if !defined(_WIN32)
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <termios.h>
#include <unistd.h>
#endif
#if defined(__linux__)
// rtnetlink, for host_ifindex/nl80211 below (themselves __linux__-only)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif
#include <ctime>
#include "linuxity/host/fd_link.hpp"
#include "linuxity/host/long_path.hpp"
#include "linuxity/host/real_netns.hpp"
#include "linuxity/host/stat_fields.hpp"

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

    // -- for the in-guest handler ------------------------------------------
    template <class F> void for_each_sock_placeholder(F&& f) const {
        for (const auto& p : sock_placeholders_) f(p);
    }
    [[nodiscard]] std::size_t sock_placeholder_count() const noexcept { return sock_placeholders_.size(); }
    // A guest landlock domain is enforced by the dispatcher, so the fast
    // path stays off once one exists.
    [[nodiscard]] bool landlock_active() const noexcept { return ll_layers_ > 0; }
    // The guest path an open in flight will bind its fd to (see note_opened_fd).
    [[nodiscard]] const std::string& pending_open_path() const noexcept { return pending_open_; }
    // The current caller bypasses file permission checks (CAP_DAC_OVERRIDE).
    [[nodiscard]] bool caller_privileged() { return privileged(); }
    // What getuid/geteuid/getgid/getegid answer for the current caller. A
    // backend that answers those IN-GUEST (a published constant, no trap)
    // publishes exactly these, so the answer has one source: the per-process
    // credentials abi/creds.hpp maintains.
    struct CallerIds { std::uint32_t uid, euid, gid, egid; };
    [[nodiscard]] CallerIds caller_ids() {
        const auto& p = me();
        return {ns_id(p.uids[0], false), ns_id(p.uids[1], false),
                ns_id(p.gids[0], true), ns_id(p.gids[1], true)};
    }
    // The caller's controlling terminal, as a pty slave number, or -1. ONE
    // answer for every reader (/dev/tty, the tty ioctls, auto-acquire on
    // open). A backend whose guest processes are real host processes in
    // real sessions (HVF: models_process_groups) holds it in the HOST's tty
    // layer -- TIOCSCTTY is forwarded there -- so the host decides.
    // Otherwise it is ours to track.
    [[nodiscard]] std::int32_t caller_ctty() {
        if constexpr (requires { mem_.models_process_groups(); mem_.host_fd_of(0); }) {
            // Darwin's /dev/tty never names the terminal behind it, but
            // tcgetsid() succeeds only on the CALLER'S controlling terminal:
            // ask it of each pty this process has open. (A ctty with no fd
            // left open on it is unreachable by name anyway.)
            std::int32_t found = -1;
            k_.files().for_each_fd_path_in(ids().pid, [&](int gfd, const std::string& p) {
                if (found >= 0 || !p.starts_with("/dev/pts/")) return;
                const int h = mem_.host_fd_of(gfd);
                if (h >= 0 && ::tcgetsid(h) >= 0) found = pty_slave_of_fd(gfd);
            });
            if (found < 0)
                for (int gfd = 0; gfd < 256 && found < 0; ++gfd) {   // inherited, untracked fds
                    const int h = mem_.host_fd_of(gfd);
                    if (h >= 0 && ::isatty(h) && ::tcgetsid(h) >= 0) found = host_fd_slave_no(gfd);
                }
            return found;
        } else {
            return k_.procs().ctty_of(ids().pid);
        }
    }
    // Did `sc` (just dispatched) possibly change the caller's credentials?
    [[nodiscard]] static constexpr bool changes_creds(Sysno sc) noexcept {
        switch (sc) {
            case Sysno::setuid: case Sysno::setgid: case Sysno::setreuid: case Sysno::setregid:
            case Sysno::setresuid: case Sysno::setresgid: case Sysno::setfsuid: case Sysno::setfsgid:
            case Sysno::setgroups: case Sysno::capset: case Sysno::prctl:
            case Sysno::unshare: case Sysno::setns: case Sysno::execve: case Sysno::execveat:
                return true;
            default: return false;
        }
    }

    [[nodiscard]] Outcome dispatch(const Regs& r) {
        const Sysno sc = decode(arch_, r.nr);
        cstr_valid_ = false;
        struct DropCstr { bool& v; ~DropCstr() { v = false; } } drop_cstr{cstr_valid_};
        // Select the trapped task's per-process cwd for this syscall, so
        // chdir/fchdir/getcwd and every relative-path absolutize act on THIS
        // process's directory rather than a single shared one (a forked
        // child's chdir must not clobber the parent's cwd). Passing ppid lets
        // a first-seen child inherit the parent's cwd automatically.
        {
            auto id = ids();
            k_.files().set_current_pid(id.pid, id.ppid);
            k_.procs().set_reader(id.pid);
            k_.files().set_current_mnt_ns(k_.procs().ns_of(id.pid)[kernel::NsKind::mnt]);
            // A task can trap before its spawn event is folded in (or, on a
            // fresh-process fork, have no parent record at all); build its
            // fork-time record now -- inherited credentials included -- so
            // no handler (setpgid, a comm write) creates a default, root one.
            if (!k_.procs().find_mut(id.pid)) (void)me();
        }
        // a process under a landlock domain linuxity keeps (no host Landlock)
        if (ll_layers_ > 0)
            if (const Errno e = ll_gate(sc, r); e != Errno::ok) return eno(e);
        path_too_long_ = false;
        plan_fsnotify(sc, r);           // before: a close unbinds its path
        Outcome o = dispatch_calls(sc, r);
        // The kernel's getname(): a path argument of PATH_MAX bytes or more
        // (NUL included) is ENAMETOOLONG before any lookup. A forwarding
        // backend gets that from the host kernel; one that performs calls
        // itself (HVF walks long host paths) must hear it from here, or a
        // 5000-byte guest path resolved and the call succeeded. Every path
        // argument is read through read_cstr, which notes an over-long one.
        if (path_too_long_) return eno(Errno::enametoolong);
        return o;
    }

private:
    // Set by read_cstr when a string ran past PATH_MAX (see dispatch).
    bool path_too_long_{false};

    // -- inotify, where linuxity keeps it (kernel/fsnotify.hpp) -------------
    // The events this call will cause if it succeeds, planned before it runs
    // (while the guest paths are known: an unlink's name is gone after) and
    // committed by the backend with the result, through fsnotify_commit.
    // Nothing at all unless some process in the tree is watching.
    std::vector<kernel::fsnotify::Event> fsn_plan_;

    // O_ACCMODE of guest fd `fd` (0 read, 1 write, 2 read-write; 0 unknown).
    [[nodiscard]] unsigned fd_access_mode(int fd) {
        if constexpr (requires { mem_.host_fd_of(fd); } && !requires { mem_.host_tid(); }) {
            const int h = mem_.host_fd_of(fd);
            const int fl = h >= 0 ? ::fcntl(h, F_GETFL) : -1;
            return fl < 0 ? 0u : static_cast<unsigned>(fl & O_ACCMODE);
        } else if constexpr (requires { mem_.host_tid(); }) {
            return fdinfo_flags(mem_.host_tid(), std::to_string(fd).c_str()) & 3u;
        } else {
            (void)fd;
            return 0u;
        }
    }

    // Evaluate abi/fsnotify_events.hpp's row for this call.
    void plan_fsnotify(Sysno sc, const Regs& r) {
        namespace fn = kernel::fsnotify;
        namespace fe = fsnotify_events;
        fsn_plan_.clear();
        const auto row = fe::row_of(sc);
        if (!row) return;
        auto& hub = k_.files().fsnotify();
        if (!hub.attached() || !hub.active()) return;
        auto is_dir = [&](const std::string& g) {
            const auto pc = k_.files().classify(g, false, false);
            struct ::stat st{};
            return pc.realm == kernel::Realm2::host_backed &&
                   ::lstat(pc.host_path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
        };
        auto ev = [&](std::uint32_t m, const std::string& p, std::uint32_t cookie = 0) {
            if (!p.empty() && p.front() == '/') fsn_plan_.push_back({m, cookie, p});   // a pipe names nothing
        };
        const int fd0 = static_cast<int>(r.arg[0]);
        auto object = [&](int arg) -> std::string {
            switch (row->obj) {
                case fe::Obj::fd: return std::string{k_.files().path_of_fd(fd0)};
                case fe::Obj::path_or_fd:
                    if (r.arg[static_cast<std::size_t>(arg)] == 0) return std::string{k_.files().path_of_fd(fd0)};
                    [[fallthrough]];
                case fe::Obj::path: return resolve_arg(r, arg, row->at, row->follow);
            }
            return {};
        };
        const std::string g = object(row->arg);
        const std::uint32_t dir = row->isdir_from_object && is_dir(g) ? fn::kIsDir : 0u;
        switch (row->kind) {
            case fe::Kind::plain: ev(row->bit | dir, g); break;
            case fe::Kind::open:
                if (wire::has(r.arg[2], wire::OpenFlag::creat) && !guest_exists(g)) ev(fn::kCreate, g);
                ev(fn::kOpen | dir, g);
                if (wire::has(r.arg[2], wire::OpenFlag::trunc)) ev(fn::kModify, g);
                break;
            case fe::Kind::unlink: ev(fn::kDelete | ((r.arg[2] & 0x200) ? fn::kIsDir : 0u), g); break;
            case fe::Kind::rename: {
                const std::string to = resolve_arg(r, 3, true, false);
                const std::uint32_t d = is_dir(g) ? fn::kIsDir : 0u, c = fn::new_cookie();
                ev(fn::kMovedFrom | d, g, c);
                ev(fn::kMovedTo | d, to, c);
                break;
            }
            case fe::Kind::close:
                ev(((fd_access_mode(fd0) & 3u) ? fn::kCloseWrite : fn::kCloseNowrite) | dir, g);
                break;
            case fe::Kind::access:
                if (!is_dir(g)) ev(fn::kAccess, g);
                break;
        }
    }

public:
    // The call finished with `rc`: what it did happens, for watchers.
    void fsnotify_commit(std::int64_t rc) {
        if (fsn_plan_.empty()) return;
        if (rc >= 0) k_.files().fsnotify().emit_all(fsn_plan_);
        fsn_plan_.clear();
    }
private:

    // Every syscall linuxity answers, by number (dispatch wraps it).
    [[nodiscard]] Outcome dispatch_calls(const Sysno sc, const Regs& r) {
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
            case Sysno::kill: {
                const auto pid = static_cast<std::int32_t>(r.arg[0]);
                const auto signum = static_cast<std::int32_t>(r.arg[1]);
                // Group forms. The Linux backend does not model groups, so it
                // used to treat "group pgid" as "the process TREE under pid
                // pgid". That broke the moment groups became real: fish's
                // own group is inherited (no tracee leads it), so kill(0)
                // found nothing and the signal was lost. Resolve the members
                // here, where the groups live, and hand the backend a list.
                if constexpr (!requires { mem_.models_process_groups(); }) {
                    if (pid == 0 || pid < -1) {
                        const std::int32_t g =
                            pid == 0 ? flat_pgrp() : -pid;
                        auto m = k_.procs().members_of(g);
                        if (m.empty()) return eno(Errno::esrch);
                        return Outcome::raise_group(pid, signum, std::move(m));
                    }
                }
                return sig(pid, signum);
            }
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
            case Sysno::getpid:  case Sysno::gettid:  case Sysno::getppid: {
                const auto i = ids();
                // as the caller's pid namespace numbers them; a parent
                // outside it reads as 0, like on Linux
                const auto pns = kernel::ProcessTable::pid_ns(k_.procs().ns_of(i.pid));
                const auto& t = k_.procs();
                if (auto a = identity_answer(sc, {t.pid_in(pns, i.pid), t.pid_in(pns, i.tid),
                                                  t.pid_in(pns, i.ppid)}))
                    return val(*a);
                return fwd();
            }
            // The guest's own credentials, tracked per process (abi/creds.hpp),
            // as its user namespace names them -- caller_ids, the same answer
            // a backend publishes for in-guest getuid.
            case Sysno::getuid:  return val(caller_ids().uid);
            case Sysno::geteuid: return val(caller_ids().euid);
            case Sysno::getgid:  return val(caller_ids().gid);
            case Sysno::getegid: return val(caller_ids().egid);

            // -- getresuid(ruid*,euid*,suid*) / getresgid(rgid*,egid*,sgid*):
            //    bash and sudo read these at startup to populate $UID/$EUID.
            //    Like getuid/geteuid they MUST answer 0 for our root-owned
            //    world; forwarded raw they return the HOST uid (e.g. 1000),
            //    which has no /etc/passwd entry -> bash's "I have no name!".
            //    Write all three id-out pointers (arg0/1/2) to 0.
            case Sysno::getresuid:
            case Sysno::getresgid:
                return do_getres(r, sc == Sysno::getresuid ? me().uids : me().gids);

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
                // The group of the NAMED process, from the process table.
                // This used to echo the pid back for any non-zero argument,
                // i.e. "every task is its own group leader". Two consequences,
                // both wrong: a freshly forked child reported its own pid
                // instead of the parent's group (a child INHERITS the group),
                // and the two halves of a shell pipeline -- which setpgid puts
                // in ONE group -- read back as two. fish asserts that a job's
                // group differs from its own, and panicked in tty_handoff.rs
                // as soon as the numbering collided.
                return val(r.arg[0]
                               ? k_.procs().pgid_of(
                                     static_cast<std::int32_t>(r.arg[0]))
                               : flat_pgrp());
            case Sysno::getsid:
                if constexpr (requires { mem_.models_process_groups(); }) return fwd();
                if (!flat_pid_exists(r.arg[0])) return eno(Errno::esrch);
                return val(k_.procs().sid_of(
                    r.arg[0] ? static_cast<std::int32_t>(r.arg[0]) : ids().pid));
            case Sysno::setpgid: {
                if constexpr (requires { mem_.models_process_groups(); }) return fwd();
                // setpgid(pid, pgid): either argument may be 0, meaning "the
                // caller". Record it against the TARGET -- a shell always
                // moves its CHILD into a new group, never itself, so tracking
                // only the caller's own group dropped every write a shell
                // makes and left the answer to come out of the bogus
                // "pid is its own leader" default.
                if (!flat_pid_exists(r.arg[0])) return eno(Errno::esrch);
                const std::int32_t who = static_cast<std::int32_t>(r.arg[0]);
                const std::int32_t target = who ? who : ids().pid;
                const std::int32_t grp = static_cast<std::int32_t>(r.arg[1]);
                if (grp < 0) return eno(Errno::einval);
                const std::int32_t want = grp ? grp : target;
                // The kernel's rules: the target is the caller or its child,
                // in the caller's session, not a session leader; the group
                // is the target itself or one already in that session.
                const std::int32_t me_pid = ids().pid;
                if (auto* mp = k_.procs().find_mut(me_pid); mp && mp->ppid == 0 && ids().ppid > 0)
                    mp->ppid = ids().ppid;
                if (target != me_pid) {
                    const auto* tp = k_.procs().find(target);
                    if (!tp || tp->ppid != me_pid) return eno(Errno::esrch);
                    if (k_.procs().sid_of(target) != k_.procs().sid_of(me_pid)) return eno(Errno::eperm);
                }
                if (k_.procs().sid_of(target) == target) return eno(Errno::eperm);
                if (want != target) {
                    bool exists = false;
                    for (std::int32_t p : k_.procs().pids())
                        if (k_.procs().pgid_of(p) == want &&
                            k_.procs().sid_of(p) == k_.procs().sid_of(target)) { exists = true; break; }
                    if (!exists) return eno(Errno::eperm);
                }
                k_.procs().set_pgid(target, want);
                Virtualize v{0};
                v.host_mirror = Virtualize::Mirror::setpgid;
                v.m_a = who;
                v.m_b = grp;
                return v;
            }
            case Sysno::setsid:
                if constexpr (requires { mem_.models_process_groups(); }) return fwd();
                // A group leader may not start a session (EPERM): its group
                // would then straddle two sessions.
                if (k_.procs().pgid_of(ids().pid) == ids().pid)
                    return eno(Errno::eperm);
                k_.procs().set_sid(ids().pid);
                // new session == pid; the host's session has to follow, or
                // the pty this session takes never signals it
                return Virtualize::mirrored(ids().pid);
            // nice 0 for everything, but the KERNEL still validates `which`:
            // only PRIO_PROCESS/PRIO_PGRP/PRIO_USER (0/1/2) exist and
            // anything else is EINVAL. Returning 0 for any argument meant a
            // bogus `which` succeeded where the kernel fails -- caught by the
            // creds probe diffing against the live kernel.
            case Sysno::getpriority:
            case Sysno::setpriority:
                return do_priority(r, sc == Sysno::setpriority);

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
                if (r.arg[1] == 0 && r.arg[2] == 0) refresh_virtual_fd(fd);
                return fwd();
            }
            // pread at offset 0 (the filter only traps that offset) rereads
            // a kept-open /proc file, which the kernel regenerates.
            case Sysno::pread64: {
                if (r.arg[3] == 0) refresh_virtual_fd(static_cast<int>(r.arg[0]));
                return fwd();
            }

            // -- statfs(path, buf): translate the path and REDIRECT so the
            //    host reports the overlay filesystem's stats. fstatfs acts on
            //    an already-open (already-translated) fd — forward it. Virtual
            //    procfs/sysfs paths have no real backing fs, so synthesize a
            //    plausible statfs (tmpfs-like) for them instead of leaking the
            //    host's numbers.
            case Sysno::statfs:      return path_statfs(r);
            case Sysno::fstatfs:     return do_fstatfs(r);
            case Sysno::socket:      return do_socket(r);
            case Sysno::getsockname: return do_sockname(r, false);
            case Sysno::syslog:      return do_syslog(r);
            case Sysno::unshare:     return do_unshare(r);
            case Sysno::fstat:       return stat_fd(static_cast<int>(r.arg[0]), uaddr(r.arg[1]), false);
            case Sysno::ptrace:      return do_ptrace(r);
            case Sysno::wait4:       return do_wait4_traced(r);
            case Sysno::msgget:      return do_msgget(r);
            case Sysno::msgsnd:      return do_msgsnd(r);
            case Sysno::msgrcv:      return do_msgrcv(r);
            case Sysno::msgctl:      return do_msgctl(r);
            case Sysno::semget:      return do_semget(r);
            case Sysno::semop:       return do_semop(r, false);
            case Sysno::semtimedop:  return do_semop(r, true);
            case Sysno::semctl:      return do_semctl(r);
            case Sysno::shmget:      return do_shmget(r);
            case Sysno::shmat:       return do_shmat(r);
            case Sysno::shmdt:       return do_shmdt(r);
            case Sysno::shmctl:      return do_shmctl(r);
            case Sysno::setns:       return do_setns(r);
            case Sysno::sethostname: return do_set_uts(r, false);
            case Sysno::setdomainname: return do_set_uts(r, true);
            case Sysno::getpeername: return do_sockname(r, true);

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
                std::string name = read_string(uaddr(r.arg[1]));
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
            case Sysno::open_tree:
            case Sysno::statmount:     case Sysno::listmount:
                return eno(Errno::enosys);
            case Sysno::mount_setattr:
                return do_mount_setattr(r);
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
                const std::string type = read_string(uaddr(r.arg[2]));
                if (!type.empty() && !known_fs_type(type))
                    return eno(Errno::enodev);
                // A BIND mount's source is a real path that must exist --
                // unlike a filesystem mount, where the source is a device
                // name or ignored entirely. Accepting a bind from a missing
                // directory tells the guest its tree is in two places when
                // it is in neither.
                constexpr std::uint64_t kMsBind = 0x1000, kMsRemount = 0x20;
                if ((r.arg[3] & kMsBind) && !(r.arg[3] & kMsRemount)) {
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
                // In a mount namespace of its own the guest's tmpfs and bind
                // mounts are real: a scratch dir (or the bind's source) at the
                // target, seen only there. In the shared one they stay
                // remembered no-ops, so nothing outside changes.
                if (const std::string tgt = read_cstr(uaddr(r.arg[1])); !tgt.empty()) {
                    const std::string abs_tgt = k_.files().absolutize(tgt, k_.files().cwd());
                    const auto mns = me().ns[kernel::NsKind::mnt];
                    if (mns) return mount_in_ns(r, type, abs_tgt, mns);
                    guest_mounts_.insert(abs_tgt);
                }
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
                const auto mns = me().ns[kernel::NsKind::mnt];
                if (mns) {
                    const bool detach = r.arg[1] & 0x2;   // MNT_DETACH
                    const Errno e = k_.files().umount_guest(tgt, mns, detach);
                    if (e == Errno::ok) return val(0);
                    if (e == Errno::ebusy) return eno(e);
                }
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
                return do_pivot_root(r);
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
            case Sysno::rmdir:      return path_mut(r, 0, false, Wi::remove, false, true);
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
            case Sysno::fchmodat2:  return do_chmod(r, 1, true,  Wi::copy_leaf, /*with_flags=*/true);
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
            case Sysno::utimes:     return do_utimes(r, 0, false, -1);
            case Sysno::utime:      return do_utimes(r, 0, false, -1);
            case Sysno::utimensat:  return do_utimes(r, 1, true,   3);
            // futimesat takes (dirfd, path, times) -- no flags register, so
            // there is no AT_EMPTY_PATH form to honour.
            case Sysno::futimesat:  return do_utimes(r, 1, true,  -1);
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
            case Sysno::renameat2:  return path_mut2(r, 1, 3, true,  true, true, -1, 4);
            case Sysno::link:       return path_mut2(r, 0, 1, false, false, false);
            case Sysno::linkat:     return path_mut2(r, 1, 3, true,  true, false, 4);
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
            // -- CREDENTIALS. Tracked per process with the kernel's rules, so
            //    a drop to an unprivileged user sticks and later checks see
            //    it. The host process is never changed: one host user runs
            //    the whole tree, and ownership is ours to present anyway.
            case Sysno::setuid:    return creds_result(creds::set_one(me(), me().uids, creds::kCapSetuid, in_ns(u32(r, 0), false)));
            case Sysno::setgid:    return creds_result(creds::set_one(me(), me().gids, creds::kCapSetgid, in_ns(u32(r, 0), true)));
            case Sysno::setreuid:  return creds_result(creds::setre(me(), me().uids, creds::kCapSetuid, in_ns(u32(r, 0), false), in_ns(u32(r, 1), false)));
            case Sysno::setregid:  return creds_result(creds::setre(me(), me().gids, creds::kCapSetgid, in_ns(u32(r, 0), true), in_ns(u32(r, 1), true)));
            case Sysno::setresuid: return creds_result(creds::setres(me(), me().uids, creds::kCapSetuid, in_ns(u32(r, 0), false), in_ns(u32(r, 1), false), in_ns(u32(r, 2), false)));
            case Sysno::setresgid: return creds_result(creds::setres(me(), me().gids, creds::kCapSetgid, in_ns(u32(r, 0), true), in_ns(u32(r, 1), true), in_ns(u32(r, 2), true)));
            case Sysno::setfsuid:  return val(creds::set_fs(me(), me().uids, creds::kCapSetuid, u32(r, 0)));
            case Sysno::setfsgid:  return val(creds::set_fs(me(), me().gids, creds::kCapSetgid, u32(r, 0)));
            case Sysno::setgroups: return do_setgroups(r);
            case Sysno::getgroups: return do_getgroups(r);
            case Sysno::capget:    return do_capget(r);
            case Sysno::capset:    return do_capset(r);

            // -- LANDLOCK. Real where the host has it: the ruleset and the
            //    restriction are the host kernel's, so the guest gets the walls
            //    it asked for, and a path rule is added for every host layer
            //    behind the guest path (overlay upper and lower).
            //
            //    Where the host has none (Android's 6.1 GKI) we keep the rule
            //    sets ourselves (kernel/landlock.hpp) and check every path,
            //    port and signal call against them. We see all of those calls
            //    already, so the walls hold just the same.
            case Sysno::landlock_create_ruleset:
                if (host_has_landlock()) return fwd();
                return do_ll_create_ruleset(r);
            case Sysno::landlock_add_rule:
                if (host_has_landlock()) return do_landlock_add_rule(r);
                return do_ll_add_rule(r);
            case Sysno::landlock_restrict_self:
                if (host_has_landlock()) {
                    // from now on this process (and what it forks) can't open
                    // our paths: inject differently for it (see path_open)
                    landlocked_.insert(ids().pid);
                    return fwd();
                }
                return do_ll_restrict_self(r);

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
                if (auto a = prctl_creds(op, r)) return *a;
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
                        for (std::size_t i = 0; i < 15; ++i) {   // TASK_COMM_LEN - 1
                            const char c = static_cast<char>(raw[i]);
                            if (c == '\0') break;
                            nm.push_back(c);
                        }
                        k_.procs().set_thread_comm(ids().pid, ids().tid, nm);
                    }
                }
                // PR_GET_NAME reads our table, so a write to comm shows here too
                if (op == 16 /*PR_GET_NAME*/) {
                    if (!comm_files_.empty()) apply_comm_writes();
                    const auto i = ids();
                    if (const auto* p = k_.procs().find(i.pid)) {
                        std::array<std::byte, 16> out{};
                        const std::string& c = kernel::ProcessTable::comm_of(*p, i.tid);
                        std::memcpy(out.data(), c.data(), std::min<std::size_t>(c.size(), 15));
                        if (!mem_.copy_out(uaddr(r.arg[1]), out)) return eno(Errno::efault);
                        return val(0);
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

            // -- a request on an emulated nl80211 socket (see do_socket);
            //    anything else is the host's
            case Sysno::sendto:
                if (auto o = nl_answer(static_cast<int>(r.arg[0]), uaddr(r.arg[1]),
                                       static_cast<std::size_t>(r.arg[2])))
                    return std::move(*o);
                return fwd();
            case Sysno::sendmsg:
                if (!nl_socks_.empty()) {
                    // msghdr: name, namelen, iov, iovlen; one iovec is enough
                    const std::uint64_t iov = get_u64(r.arg[1] + 16);
                    if (iov && get_u64(r.arg[1] + 24) >= 1)
                        if (auto o = nl_answer(static_cast<int>(r.arg[0]), uaddr(get_u64(iov)),
                                               static_cast<std::size_t>(get_u64(iov + 8))))
                            return std::move(*o);
                }
                return fwd();

            // -- fork/clone: the task limit (limits.pids). pids.max needs a
            //    delegated cgroup; this works on every host.
            case Sysno::clone:
            case Sysno::clone3:
            case Sysno::fork:
            case Sysno::vfork:
                if (const auto lim = machine().task_limit; lim && task_count() >= lim)
                    return eno(Errno::eagain);
                return fwd();

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
    // Does process group `pg` still have a live member (in session `sid`,
    // when given)? The sentinel group is always alive.
    [[nodiscard]] bool fg_group_alive(std::int32_t pg, std::int32_t sid) {
        if (pg <= 0 || pg == flat_pgrp()) return true;
        for (const std::int32_t p : k_.procs().members_of(pg))
            if (sid <= 0 || k_.procs().sid_of(p) == sid) return true;
        return false;
    }

    // Live guest tasks: every process plus its extra threads.
    [[nodiscard]] std::uint64_t task_count() const {
        std::uint64_t n = 0;
        for (const std::int32_t pid : k_.procs().pids())
            if (const auto* p = k_.procs().find(pid); p && p->state != 'Z')
                n += 1 + p->threads.size();
        return n;
    }

    // Mount points the GUEST asked for. Its mounts are no-ops on our side,
    // but it believes they exist, so the matching umount2 must succeed --
    // a program that mounts and then unmounts its own scratch tree should
    // not get EINVAL. Only the targets are kept; nothing is really mounted.
    std::set<std::string> guest_mounts_;

    // mount(2) in a mount namespace of the guest's own: changes our mount
    // table, seen only there. tmpfs is a fresh scratch dir, proc/sysfs/devpts
    // a copy of ours, a bind copies the mount holding its source.
    [[nodiscard]] Outcome mount_in_ns(const Regs& r, const std::string& type,
                                      const std::string& tgt, std::uint64_t ns) {
        constexpr std::uint64_t kRdonly = 0x1, kRemount = 0x20, kBind = 0x1000, kMove = 0x2000,
                                kRec = 0x4000, kPropagation = 0x40000 | 0x80000 | 0x100000 | 0x20000;
        const std::uint64_t f = r.arg[3];
        auto& fs = k_.files();
        if (f & kPropagation) return val(0);   // we have no propagation to change
        const auto tc = fs.classify(tgt);
        if (tc.realm == kernel::Realm2::absent) return eno(tc.error);
        if (f & kRemount) {
            // a bind remount changes this mount's flags; a plain one would
            // change the filesystem's, which for us is the same thing
            if (!fs.set_mount_ro(tgt, ns, f & kRdonly, false)) return eno(Errno::einval);
            return val(0);
        }
        const std::string src = fs.absolutize(read_cstr(uaddr(r.arg[0])), fs.cwd());
        if (f & kMove) {
            if (!fs.move_guest(src, tgt, ns)) return eno(Errno::einval);
            return val(0);
        }
        if (f & kBind) {
            if (!fs.bind_guest(src, tgt, ns, f & kRec)) return eno(Errno::enoent);
            return val(0);
        }
        std::string host_dir;
        if (type == "tmpfs" || type == "ramfs") {
            std::string tmpl = host::tmp_path("linuxity-tmpfs-XXXXXX");
            if (!::mkdtemp(tmpl.data())) return eno(Errno::enospc);
            host_dir = tmpl;
            fs.mount_guest(tgt, host_dir, ns, f & kRdonly);
            return val(0);
        }
        const char* origin = type == "proc" ? "/proc" : type == "sysfs" ? "/sys"
                           : type == "devpts" ? "/dev/pts" : type == "devtmpfs" ? "/dev"
                           : type == "mqueue" ? "/dev/mqueue" : nullptr;
        if (origin && fs.mount_like(origin, tgt, ns)) {
            if (f & kRdonly) (void)fs.set_mount_ro(tgt, ns, true, false);
            return val(0);
        }
        // a filesystem we can't make (ext4 on a device, overlay): remember
        // it, as outside a namespace
        guest_mounts_.insert(tgt);
        return val(0);
    }

    // pivot_root(new_root, put_old), on our mount table. Only inside a mount
    // namespace of the guest's own; elsewhere it is the host's root.
    [[nodiscard]] Outcome do_pivot_root(const Regs& r) {
        const auto mns = me().ns[kernel::NsKind::mnt];
        if (!mns) return eno(Errno::eperm);
        auto& fs = k_.files();
        const std::string nr = fs.absolutize(read_cstr(uaddr(r.arg[0])), fs.cwd());
        const std::string po = fs.absolutize(read_cstr(uaddr(r.arg[1])), fs.cwd());
        for (const auto* p : {&nr, &po}) {
            const auto pc = fs.classify(*p);
            if (pc.realm == kernel::Realm2::absent) return eno(pc.error);
        }
        std::vector<std::int32_t> pids;
        for (const std::int32_t p : k_.procs().pids())
            if (k_.procs().ns_of(p)[kernel::NsKind::mnt] == mns) pids.push_back(p);
        if (const Errno e = fs.pivot_root(mns, nr, po, pids); e != Errno::ok) return eno(e);
        return val(0);
    }

    // mount_setattr(dfd, path, flags, attr, size): only the read-only bit
    // means anything to us; inside a mount namespace it changes our table.
    [[nodiscard]] Outcome do_mount_setattr(const Regs& r) {
        const auto mns = me().ns[kernel::NsKind::mnt];
        if (!mns) return eno(Errno::enosys);
        if (r.arg[4] < 32) return eno(Errno::einval);
        std::array<std::byte, 16> a{};
        if (!mem_.copy_in(uaddr(r.arg[3]), a)) return eno(Errno::efault);
        auto u64 = [&](std::size_t at) {
            std::uint64_t v = 0;
            for (std::size_t i = 0; i < 8; ++i)
                v |= static_cast<std::uint64_t>(std::to_integer<unsigned>(a[at + i])) << (i * 8);
            return v;
        };
        const std::uint64_t set = u64(0), clr = u64(8);
        const std::string path = resolve_arg(r, 1, /*at=*/true);
        const bool rec = r.arg[2] & 0x8000;   // AT_RECURSIVE
        if (!k_.files().is_mount_point(path)) return eno(Errno::einval);
        if ((set | clr) & 0x1)
            if (!k_.files().set_mount_ro(path, mns, set & 0x1, rec)) return eno(Errno::einval);
        return val(0);
    }

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

    // The CALLER's process group, straight from the per-pid table.
    //
    // There used to be a flat_pgrp_ scalar here too. This object serves the
    // WHOLE traced tree, so one scalar was shared by every process: when
    // fish's job ran setpgid(0,0) on itself, fish's own getpgrp() moved to
    // the job's group, and tty_handoff.rs panicked ("Job should not have
    // fish's pgroup"). Groups belong to pids, so they live only in the table.
    [[nodiscard]] std::int32_t flat_pgrp() {
        return k_.procs().pgid_of(ids().pid);
    }
    // Each terminal's foreground group, by pty slave number. Absent means
    // unclaimed: answer the caller's own group. Per terminal, because a
    // pty.fork() child's new session must not see the outer shell's job.
    std::unordered_map<std::int32_t, std::int32_t> fg_pgrp_;
    std::pair<std::int32_t, std::int32_t> pending_fg_{-2, 0};
public:
    // The trap finished handing the host terminal over: the guest's
    // tcgetpgrp may now report the new foreground group.
    void note_foreground() {
        if (pending_fg_.first != -2) fg_pgrp_[pending_fg_.first] = pending_fg_.second;
        pending_fg_ = {-2, 0};
    }
private:

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
    // Handlers read the same path arg several times per syscall; keep the
    // last one until the next dispatch.
    // A guest string read AS A PATH: at PATH_MAX or more it makes the whole
    // call ENAMETOOLONG (see dispatch). Every path argument is read here.
    [[nodiscard]] std::string read_cstr(UAddr a) {
        std::string s = read_string(a);
        if (s.size() >= 4096) path_too_long_ = true;
        return s;
    }
    // Any other guest string (an argv entry, a label): no length rule.
    [[nodiscard]] std::string read_string(UAddr a) {
        if (cstr_valid_ && cstr_addr_ == value(a)) return cstr_;
        std::string s = read_cstr_uncached(a);
        cstr_valid_ = true;
        cstr_addr_ = value(a);
        cstr_ = s;
        return s;
    }
    bool cstr_valid_ = false;
    std::uint64_t cstr_addr_ = 0;
    std::string cstr_;

    [[nodiscard]] std::string read_cstr_uncached(UAddr a) {
        std::string s;
        const std::uint64_t base = value(a);
        std::uint64_t off = 0;
        constexpr std::uint64_t kPage = 4096;
        for (;;) {
            // How many bytes remain until the next page boundary from here;
            // never read across it in one process_vm_readv (that's the read
            // that can spuriously fault on a valid string).
            std::uint64_t to_page = kPage - ((base + off) & (kPage - 1));
            // 256 bytes covers nearly every path in one read.
            constexpr std::size_t kChunk = 256;
            std::size_t want = static_cast<std::size_t>(to_page < kChunk ? to_page : kChunk);
            std::array<char, kChunk> chunk;
            std::span<std::byte> dst{reinterpret_cast<std::byte*>(chunk.data()), want};
            if (mem_.copy_in(uaddr(base + off), dst)) {
                const void* nul = std::memchr(chunk.data(), '\0', want);
                const std::size_t n = nul ? static_cast<std::size_t>(static_cast<const char*>(nul) - chunk.data()) : want;
                s.append(chunk.data(), n);
                if (nul) return s;
                if (s.size() >= 4096) { s.resize(4097); return s; }
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
                if (s.size() >= 4096) return s;
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

    // Which synthesized files accept a write? Almost none: procfs is a view
    // of kernel state, and the handful that are writable are the ones that
    // SET state rather than report it. /proc/<pid>/comm is the one a guest
    // actually uses -- it renames the thread, the same fact PR_SET_NAME
    // writes -- so refusing it would break every runtime that names its
    // threads through the file rather than the prctl.
    [[nodiscard]] static bool virtual_is_writable(std::string_view p) noexcept {
        return p.ends_with("/comm") || p == "/proc/sys/vm/drop_caches" || p == "/dev/kmsg" ||
               p.ends_with("/oom_score_adj") ||
               p.ends_with("/uid_map") || p.ends_with("/gid_map") || p.ends_with("/setgroups") ||
               p == "/proc/sys/kernel/hostname" || p == "/proc/sys/kernel/domainname";
    }
    // Files whose mode has no read bit for anyone, root included.
    [[nodiscard]] static bool virtual_is_write_only(std::string_view p) noexcept {
        return p == "/proc/sys/vm/drop_caches";
    }

    // What a mutation of a synthesized path reports. EROFS is the intuitive
    // answer and the wrong one: procfs is not mounted read-only, so the error
    // comes from the missing inode OP, and which one is missing depends on
    // the operation. Checked against the live kernel:
    //   create a new name -> ENOENT. procfs dirs have no mkdir/symlink/mknod/
    //     create op, so the VFS cannot even make the name exist. Holds even
    //     when the parent is there, which is why it is not EPERM.
    //   create over a name that DOES exist -> EEXIST. The existence check
    //     runs before the missing-op one, so this wins over the ENOENT above;
    //     it is the only answer the virtual_file branch of a creation handler
    //     can give, since that branch means the leaf resolved.
    //   set metadata (mode, owner) -> EPERM, the classic "no such inode op",
    //     at any depth.
    //   remove or modify CONTENT (truncate, utimes) -> EPERM too, EXCEPT
    //     directly under /proc, where write permission on the root directory
    //     is checked first and denies with EACCES before the missing inode op
    //     is ever reached.
    enum class VMut { create, exists, remove, meta };
    [[nodiscard]] static Errno virtual_mut_errno(std::string_view abs,
                                                 VMut op) noexcept {
        if (op == VMut::create) return Errno::enoent;
        if (op == VMut::exists) return Errno::eexist;
        if (op == VMut::meta) return Errno::eperm;
        // Depth 2 ("/proc/version") is refused by the root's own permissions;
        // deeper ("/proc/self/comm") reaches the inode.
        auto body = abs;
        while (!body.empty() && body.front() == '/') body.remove_prefix(1);
        auto slash = body.find('/');
        bool at_root = slash == std::string_view::npos ||
                       body.find('/', slash + 1) == std::string_view::npos;
        return at_root ? Errno::eacces : Errno::eperm;
    }

    // An EMPTY path argument is ENOENT for every path syscall, and that is
    // not a detail -- it is how a caller distinguishes "nothing supplied"
    // from "the current directory". Only openat and stat checked it, so the
    // other twelve absolutized "" to the cwd and acted on the DIRECTORY:
    // symlinkat(x, "") reported EEXIST, mkdirat("") EEXIST, unlinkat("")
    // EISDIR, linkat("", y) EXDEV -- four different wrong answers where the
    // kernel says ENOENT four times. Found by the differential fuzzer, which
    // generates "" as a path tail precisely because handlers forget it.
    //
    // An EMPTY path is ENOENT for most path syscalls, but some accept it with
    // AT_EMPTY_PATH to mean "the dirfd itself". That is per-syscall, not
    // uniform -- newfstatat/utimensat/fchownat/linkat honour the flag,
    // fchmodat does not (it is not in its ABI) -- so a caller opts in by
    // passing the register index of its flags word as `flags_arg`, and -1
    // means "this syscall has no such form".
    [[nodiscard]] bool empty_path_arg(const Regs& r, int path_arg,
                                      int flags_arg = -1) {
        // A NULL pointer is NOT an empty string. read_cstr cannot tell them
        // apart (a failed read yields ""), but the kernel does, and for
        // utimensat/futimesat a NULL path is legal -- it means "the dirfd
        // itself". Checking the pointer keeps the two apart.
        if (null_path_arg(r, path_arg)) return false;
        if (!read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)])).empty())
            return false;
        if (flags_arg >= 0 &&
            wire::has_at(r.arg[static_cast<std::size_t>(flags_arg)],
                         wire::AtFlag::empty_path))
            return false;  // the dirfd IS the target; not an empty path
        return true;
    }

    // Is this removal a DIRECTORY removal? unlinkat says so with
    // AT_REMOVEDIR (its flags are the register after the path); unlink and
    // rmdir take no flags, so they state it directly via `rmdir_syscall`.
    [[nodiscard]] bool removedir_flag(const Regs& r, int path_arg, bool at,
                                      bool rmdir_syscall) const noexcept {
        if (!at) return rmdir_syscall;
        return wire::has_at(r.arg[static_cast<std::size_t>(path_arg) + 1],
                            wire::AtFlag::removedir);
    }

    // Resolving "." or ".." still TRAVERSES the directory they sit in, so it
    // needs search (+x) permission there -- `mkdir d/.` on a d without +x is
    // EACCES, not the EEXIST that d's own existence would suggest.
    // Normalizing the component away loses that requirement, so ask the host
    // directly: for a raw path with a dot tail, the directory being traversed
    // is the normalized path itself.
    //
    // Only the dot case needs this. Any other final component leaves a real
    // parent in the host path, and the host's own call checks it.
    [[nodiscard]] bool dot_traversal_denied(const std::string& raw,
                                            const std::string& host_path) {
        if (dot_tail(raw) == DotTail::none) return false;
        if (host_path.empty()) return false;
        return ::access(host_path.c_str(), X_OK) != 0 && errno == EACCES;
    }

    // Lexically normalizing "."/".." DROPS the requirement that whatever
    // came before them exists. The kernel WALKS a path, so "gone/.." fails at
    // `gone` even though the rewritten path is a perfectly good parent --
    // without this, `stat gone/../f1` succeeded and `mkdir gone/../x`
    // actually created the directory.
    //
    // So: every component that appears BEFORE a dot component must itself
    // resolve to a directory. Returns the errno that walk would produce, or
    // Errno::ok if the path is fine (including when it has no dot at all, the
    // common case, which costs one find()).
    [[nodiscard]] Errno dot_prefix_error(const Regs& r, int path_arg, bool at) {
        const std::string raw =
            read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
        if (raw.find('.') == std::string::npos) return Errno::ok;

        // Split into components, remembering where the first dot sits.
        std::vector<std::string> comps;
        std::size_t first_dot = std::string::npos;
        for (std::size_t i = 0, n = 0; i <= raw.size(); ++i) {
            if (i == raw.size() || raw[i] == '/') {
                if (n < i) {
                    std::string c = raw.substr(n, i - n);
                    if ((c == "." || c == "..") && first_dot == std::string::npos)
                        first_dot = comps.size();
                    comps.push_back(std::move(c));
                }
                n = i + 1;
            }
        }
        if (first_dot == std::string::npos) return Errno::ok;
        // A dot as the FIRST component has no prefix to walk, but it still
        // resolves THROUGH the directory it starts from -- so that directory
        // must be searchable. readlink(".") in an unsearchable cwd is EACCES,
        // not the EINVAL "not a symlink" would give.
        //
        // Only when the dot is the WHOLE path, though: for "./f1" the leaf is
        // what is being asked about, and if it is reachable the answer is
        // about the leaf (EINVAL for "not a symlink"), not the walk.
        if (first_dot == 0) {
            if (comps.size() > 1) return Errno::ok;
            const std::string base =
                (!raw.empty() && raw.front() == '/') ? std::string{"/"}
                                                     : dir_base(r, at);
            auto pc = k_.files().classify(base, /*for_write=*/false,
                                          /*follow=*/true);
            if (pc.realm == kernel::Realm2::host_backed &&
                !pc.host_path.empty() &&
                ::access(pc.host_path.c_str(), X_OK) != 0 && errno == EACCES)
                return Errno::eacces;
            return Errno::ok;
        }

        // Rebuild the guest path one component at a time, up to the dot, and
        // require each to be a real directory.
        std::string cur = (!raw.empty() && raw.front() == '/')
                              ? std::string{"/"}
                              : std::string{dir_base(r, at)};
        for (std::size_t i = 0; i < first_dot; ++i) {
            if (cur.empty() || cur.back() != '/') cur += '/';
            cur += comps[i];
            auto pc = k_.files().classify(kernel::FileNamespace::normalize(cur),
                                          /*for_write=*/false, /*follow=*/true);
            if (pc.realm != kernel::Realm2::host_backed) continue;
            if (pc.host_path.empty()) continue;
            struct ::stat st{};
            if (::stat(pc.host_path.c_str(), &st) != 0) {
                // A prefix we cannot even stat is not necessarily absent: a
                // directory above it may deny search (EACCES) or the walk may
                // be caught in a symlink loop (ELOOP).
                return access_errno();
            }
            if (!S_ISDIR(st.st_mode)) return Errno::enotdir;
            // The component exists and is a directory, but a dot AFTER it
            // still has to be traversed INTO, which needs +x.
            if (::access(pc.host_path.c_str(), X_OK) != 0 && errno == EACCES)
                return Errno::eacces;
        }
        return Errno::ok;
    }

    // The directory a relative path starts from: the dirfd for an *at form,
    // otherwise the cwd.
    [[nodiscard]] std::string dir_base(const Regs& r, bool at) {
        if (at) {
            std::string_view d = dir_of(static_cast<std::int64_t>(r.arg[0]));
            if (!d.empty()) return std::string{d};
        }
        std::string_view c = k_.files().cwd();
        return c.empty() ? std::string{"/"} : std::string{c};
    }

    // Is the PARENT directory of this host path searchable? A name cannot be
    // looked up or created without +x on the directory holding it, and that
    // check precedes the structural ones (slash, dot, exists).
    //
    // Only a real DIRECTORY can be unsearchable: access(X_OK) on a regular
    // file also fails with EACCES, and reporting that would mask the ENOTDIR
    // the kernel owes for a file used as a path component. An unmapped or
    // unknown path answers true, leaving the host call to report the rest.
    [[nodiscard]] static bool host_dir_searchable(const std::string& p) noexcept {
        if (p.empty()) return true;
        const auto slash = p.rfind('/');
        if (slash == std::string::npos || slash == 0) return true;
        const std::string parent = p.substr(0, slash);
        struct ::stat st{};
        if (::stat(parent.c_str(), &st) != 0) return true;
        if (!S_ISDIR(st.st_mode)) return true;
        return ::access(parent.c_str(), X_OK) == 0;
    }

    // Why will this GUEST path not resolve? classify() collapses several
    // distinct lookup failures into absent/ENOENT, but a caller has to report
    // the one the kernel would: a symlink loop is ELOOP, a file used as a
    // directory component is ENOTDIR, an unsearchable ancestor is EACCES.
    //
    // classify leaves host_path empty for an absent result, so map the path
    // again purely to get a host name to ask about, then let ::access answer.
    // Falls back to `fallback` when there is nothing to ask.
    [[nodiscard]] Errno resolve_failure_errno(const std::string& guest_abs,
                                              Errno fallback) {
        // copy_leaf maps the LEAF itself (parents_only stops at the parent
        // chain and leaves host_path empty for a prefix that cannot resolve,
        // which is exactly the case we are here to explain).
        auto mapped = k_.files().classify(guest_abs, /*for_write=*/false,
                                          /*follow=*/false, Wi::copy_leaf);
        if (mapped.host_path.empty()) return fallback;
        if (::access(mapped.host_path.c_str(), F_OK) == 0) return fallback;
        const Errno e = access_errno();
        return e == Errno::enoent ? fallback : e;
    }

    // Is the PREFIX of this guest path caught in a symlink cycle? The leaf is
    // deliberately excluded: rename and link act on the name, so even a
    // self-referential link is a valid operand. Resolving with follow=true is
    // what runs the namespace's own loop detector, and only its ELOOP is
    // taken -- every other answer is about the leaf, which the caller decides.
    [[nodiscard]] Errno guest_prefix_loop(const std::string& guest_abs) {
        const auto slash = guest_abs.rfind('/');
        if (slash == std::string::npos || slash == 0) return Errno::ok;
        auto pc = k_.files().classify(guest_abs.substr(0, slash),
                                      /*for_write=*/false, /*follow=*/true);
        return pc.error == Errno::eloop ? Errno::eloop : Errno::ok;
    }

    // Does this NAME exist, without following a final symlink? rename and
    // unlink act on the link itself, so a dangling one is still there as far
    // as they are concerned -- an F_OK probe would call it missing.
    [[nodiscard]] static bool host_lexists(const std::string& p,
                                           Errno* why = nullptr) noexcept {
        if (p.empty()) {
            if (why != nullptr) *why = Errno::enoent;
            return false;
        }
        struct ::stat st{};
        if (::lstat(p.c_str(), &st) == 0) return true;
        if (why != nullptr) *why = access_errno();
        return false;
    }

    // Is this host path a SYMLINK (not what it points at)? A dangling link
    // occupies its name, so an exclusive create through it is EEXIST even
    // though the target resolves to nothing.
    [[nodiscard]] static bool host_path_is_symlink(const std::string& p) noexcept {
        if (p.empty()) return false;
        struct ::stat st{};
        return ::lstat(p.c_str(), &st) == 0 && S_ISLNK(st.st_mode);
    }

    // Does the PARENT of this host path resolve at all (symlinks followed)?
    // A dangling link used as a path component is ENOENT, which the kernel
    // reports before anything about what is being linked. `why` separates
    // that from the EACCES an unsearchable ancestor gives.
    [[nodiscard]] static bool parent_resolves(const std::string& p,
                                              Errno* why = nullptr) noexcept {
        if (p.empty()) return true;
        const auto slash = p.rfind('/');
        if (slash == std::string::npos || slash == 0) return true;
        const std::string parent = p.substr(0, slash);
        if (::access(parent.c_str(), F_OK) == 0) return true;
        if (why != nullptr) *why = access_errno();
        return false;
    }

    // Is `anc` a prefix DIRECTORY of `p` -- i.e. would moving p into anc mean
    // absorbing a directory that contains it? The kernel answers ENOTEMPTY
    // for that, distinct from the plain "destination is a directory" case.
    [[nodiscard]] static bool path_is_ancestor(const std::string& anc,
                                               const std::string& p) noexcept {
        if (anc.empty() || p.empty()) return false;
        if (p.size() <= anc.size()) return false;
        if (p.compare(0, anc.size(), anc) != 0) return false;
        return p[anc.size()] == '/' || (anc.back() == '/');
    }

    // Is this host path itself a directory? Used where a trailing slash
    // asserts the name is one. An unmapped path answers false, so the
    // trailing-slash assertion fails and the host call reports the rest.
    // Is this host path a directory WITHOUT following a final symlink? A
    // trailing slash asserts "this name is a directory", and a symlink is
    // not one however good its target -- `rename lnk sub/` with lnk pointing
    // at a directory is ENOTDIR, not the EISDIR that following it gives.
    [[nodiscard]] static bool host_path_is_dir_nofollow(const std::string& p) noexcept {
        if (p.empty()) return false;
        struct ::stat st{};
        if (::lstat(p.c_str(), &st) != 0) return false;
        return S_ISDIR(st.st_mode);
    }

    [[nodiscard]] static bool host_path_is_regular(const std::string& p) noexcept {
        if (p.empty()) return false;
        struct ::stat st{};
        return ::stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
    }

    [[nodiscard]] static bool host_path_is_dir(const std::string& p) noexcept {
        if (p.empty()) return false;
        struct ::stat st{};
        if (::stat(p.c_str(), &st) != 0) return false;
        return S_ISDIR(st.st_mode);
    }

    // Is the PARENT of this host path really a directory? A rename whose
    // path uses a regular file as a directory component is ENOTDIR, and the
    // kernel reports that in preference to EBUSY. classify() maps a path for
    // creation without stating the prefix, so this asks the host directly.
    // An unknown/empty path is treated as fine -- the host call will produce
    // the real error.
    [[nodiscard]] static bool parent_is_dir(std::string_view host_path) noexcept {
        if (host_path.empty()) return true;
        const auto slash = host_path.rfind('/');
        if (slash == std::string_view::npos || slash == 0) return true;
        const std::string parent{host_path.substr(0, slash)};
        struct ::stat st{};
        if (::stat(parent.c_str(), &st) != 0) return true;
        return S_ISDIR(st.st_mode);
    }

    // Does this path's FINAL component (ignoring trailing slashes) name the
    // directory itself or its parent? "." and ".." are not names you can
    // remove or rename away -- they are the self and parent entries, and the
    // kernel refuses before it ever looks at what they point to. Normalizing
    // them away first turns `rmdir "d/."` into `rmdir "d"` and `rmdir "d/.."`
    // into `rmdir` of the PARENT, so the guest silently deleted directories
    // the kernel would never have touched.
    enum class DotTail { none, dot, dotdot };
    [[nodiscard]] static DotTail dot_tail(std::string_view p) noexcept {
        while (p.size() > 1 && p.back() == '/') p.remove_suffix(1);
        if (p == "." || p.ends_with("/.")) return DotTail::dot;
        if (p == ".." || p.ends_with("/..")) return DotTail::dotdot;
        return DotTail::none;
    }

    // Was the path pointer itself NULL? utime/utimensat spell "operate on the
    // fd" that way, so it has to be told apart from a "" that resolves to
    // nothing. Every other path syscall treats NULL as EFAULT.
    [[nodiscard]] static bool null_path_arg(const Regs& r, int path_arg) noexcept {
        return r.arg[static_cast<std::size_t>(path_arg)] == 0;
    }

    // A non-NULL pointer to an empty string, with no flag interpretation.
    [[nodiscard]] bool empty_cstr_arg(const Regs& r, int path_arg) {
        return !null_path_arg(r, path_arg) &&
               read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)])).empty();
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
        // /proc/self/cwd/.. is the parent of the cwd, not /proc/self: swap
        // the link for its target before the .. walk folds it lexically
        if (raw.starts_with("/proc/") && raw.find("/..") != std::string::npos) {
            const auto s1 = raw.find('/', 6);
            const auto s2 = s1 == std::string::npos ? s1 : raw.find('/', s1 + 1);
            if (s2 != std::string::npos) {
                const std::string link = bind_proc_self(raw.substr(0, s2));
                if (proc_is_link(link))
                    if (const std::string tgt = proc_symlink_target(link); !tgt.empty() && tgt.front() == '/')
                        return resolve_raw(r, tgt + raw.substr(s2), at, follow_leaf);
            }
        }
        std::string abs = k_.files().absolutize(raw, dir);
        // A synthesized symlink at the leaf (/dev/stdin -> /proc/self/fd/0)
        // is followed like any link when the call follows: opening
        // /dev/stdout opens the guest's fd 1.
        if (follow_leaf && abs.starts_with("/dev/")) {
            for (int hops = 0; hops < 8; ++hops) {
                auto vf = k_.files().produce(abs);
                if (!vf || vf->symlink_target.empty() || vf->symlink_target == "(proc-link)") break;
                abs = k_.files().absolutize(vf->symlink_target, "/dev");
            }
        }
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
        // Paths stay in the reader's own pid numbering (procfs maps them to
        // global pids), so a dirfd bound to one re-resolves the same way.
        const auto vpid = k_.procs().view_pid(id.pid), vtid = k_.procs().view_pid(id.tid);
        // The caller's OWN fds stay in (or are folded into) /proc/self/fd form.
        // The guest is a real host process, so the host kernel's
        // /proc/self/fd/N, resolved in the guest's context, IS the guest's fd
        // N -- procfs redirects that form to the host on purpose. Rebinding it
        // to /proc/<pid>/fd/N first made that redirect dead code: the pid arm
        // has no fd/N, so readlink("/proc/self/fd/0") was ENOENT, ttyname()
        // failed, and `script -c tty` printed "Inappropriate ioctl for device"
        // on a perfectly good pty. Same for open("/proc/self/fd/1").
        {
            const std::string own = "/proc/" + std::to_string(vpid);
            for (const std::string_view who : {std::string_view{"/proc/self"},
                                               std::string_view{own}}) {
                for (const std::string_view leaf : {std::string_view{"/fd"},
                                                    std::string_view{"/fdinfo"}}) {
                    const std::string pre = std::string{who} + std::string{leaf};
                    if (abs == pre || abs.starts_with(pre + "/"))
                        return "/proc/self" + std::string{leaf} + abs.substr(pre.size());
                }
            }
        }
        if (rebind("/proc/self", vpid)) return ns_to_host(std::move(abs));
        // thread-self is a TID, not a pid: /proc/thread-self is
        // /proc/<pid>/task/<tid> on a real kernel.
        if (abs == "/proc/thread-self" || abs.starts_with("/proc/thread-self/")) {
            const std::string rest = abs.substr(std::string_view{"/proc/thread-self"}.size());
            abs = "/proc/" + std::to_string(vpid) + "/task/" +
                  std::to_string(vtid) + rest;
        }
        return ns_to_host(std::move(abs));
    }

    // The guest shares the host's namespaces (unshare is refused), so
    // /proc/<pid>[/task/<tid>]/ns is the tracee's own host one.
    [[nodiscard]] std::string ns_to_host(std::string abs) const {
        std::string_view v = abs;
        v.remove_prefix(6);   // "/proc/"
        auto skip_num = [&] {
            const auto n = v.find_first_not_of("0123456789");
            const auto digits = v.substr(0, n);
            v.remove_prefix(digits.size());
            return digits;
        };
        const auto who = skip_num();
        if (who.empty()) return abs;
        if (v.starts_with("/task/")) { v.remove_prefix(6); if (skip_num().empty()) return abs; }
        if (v != "/ns" && !v.starts_with("/ns/")) return abs;
        std::int32_t pid = 0;
        for (const char c : who) pid = pid * 10 + (c - '0');
        if (const auto pns = k_.procs().reader_pid_ns(); pns) pid = k_.procs().pid_from(pns, pid);
        if (pid <= 0) return abs;
        if (!k_.procs().find(pid) && !k_.procs().thread_group_of(pid)) return abs;
        // a process in a namespace of its own reads its links from procfs;
        // everyone else shares the host's
        const std::int32_t owner = k_.procs().find(pid) ? pid : k_.procs().thread_group_of(pid);
        const auto set = k_.procs().ns_of(owner);
        for (const auto id : set.id) if (id) return abs;
        if (set.pid_for_children || set.time_for_children) return abs;
        return "/proc/self" + std::string{v};
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
    //
    // RESOLVE_* is about the guest's tree, so we walk it here and give the
    // host an open_how with resolve cleared. Left in, it would judge our
    // absolute host path (EXDEV for BENEATH) or our /proc/<us>/fd reopen.
    [[nodiscard]] Outcome path_openat2(const Regs& r) {
        const std::size_t size = static_cast<std::size_t>(r.arg[3]);
        if (size < 24) return eno(Errno::einval);
        if (size > 4096) return eno(Errno::e2big);
        std::vector<std::byte> how(size);
        if (!mem_.copy_in(uaddr(r.arg[2]), how)) return eno(Errno::efault);
        auto u64 = [&](std::size_t at) {
            std::uint64_t v = 0;
            for (std::size_t i = 0; i < 8; ++i)
                v |= static_cast<std::uint64_t>(std::to_integer<unsigned>(how[at + i])) << (i * 8);
            return v;
        };
        const std::uint64_t flags = u64(0), resolve = u64(16);
        if (resolve == 0) return path_open_flags(r, /*path_arg=*/1, /*at=*/true, flags);

        constexpr std::uint64_t kNoXdev = 0x01, kNoMagic = 0x02, kNoSym = 0x04,
                                kBeneath = 0x08, kInRoot = 0x10, kCached = 0x20;
        if (resolve & ~std::uint64_t{0x3f}) return eno(Errno::einval);
        if ((resolve & kBeneath) && (resolve & kInRoot)) return eno(Errno::einval);
        if ((resolve & kCached) &&
            (wire::has(flags, wire::OpenFlag::creat) || wire::has(flags, wire::OpenFlag::trunc)))
            return eno(Errno::eagain);
        const std::string raw = read_cstr(uaddr(r.arg[1]));
        if (raw.empty()) return eno(Errno::enoent);   // openat2 has no AT_EMPTY_PATH
        const bool follow_leaf =
            !wire::has_for(arch_, flags, wire::OpenFlag::nofollow) &&
            !(wire::has(flags, wire::OpenFlag::creat) && wire::has(flags, wire::OpenFlag::excl));
        auto walked = resolve_walk(dir_base(r, /*at=*/true), raw, resolve & (kNoXdev | kNoMagic | kNoSym | kBeneath | kInRoot),
                                   follow_leaf);
        if (!walked) return eno(walked.error());

        for (std::size_t i = 16; i < 24; ++i) how[i] = std::byte{0};
        Outcome o = path_open_flags(r, /*path_arg=*/1, /*at=*/true, flags, &*walked);
        return std::move(o).match(
            [&](Redirect rd) -> Outcome { rd.blob = ArgBlob{2, std::move(how)}; return rd; },
            [&](Inject in) -> Outcome { in.blob = ArgBlob{2, std::move(how)}; return in; },
            [](auto other) -> Outcome { return other; });
    }

    // The guest path an openat2 lands on, walked a component at a time with
    // the kernel's RESOLVE_* rules (fs/namei.c), or the errno it gives.
    [[nodiscard]] Result<std::string> resolve_walk(const std::string& base, const std::string& raw,
                                                   std::uint64_t resolve, bool follow_leaf) {
        constexpr std::uint64_t kNoXdev = 0x01, kNoMagic = 0x02, kNoSym = 0x04,
                                kBeneath = 0x08, kInRoot = 0x10;
        const bool scoped = resolve & (kBeneath | kInRoot);
        const std::string root = (resolve & kInRoot) ? base : std::string{"/"};
        auto split = [](std::string_view p, std::vector<std::string>& out) {
            std::vector<std::string> comps;
            for (std::size_t i = 0, n = 0; i <= p.size(); ++i)
                if (i == p.size() || p[i] == '/') {
                    if (n < i) comps.emplace_back(p.substr(n, i - n));
                    n = i + 1;
                }
            // `out` is a stack, next component last
            out.insert(out.end(), comps.rbegin(), comps.rend());
        };
        auto join = [](const std::string& d, const std::string& n) {
            return d == "/" ? "/" + n : d + "/" + n;
        };
        auto parent = [](const std::string& d) {
            const auto s = d.rfind('/');
            return s == 0 || s == std::string::npos ? std::string{"/"} : d.substr(0, s);
        };
        auto mnt = [&](const std::string& p) { return k_.files().mount_of(p).id; };

        std::string cur = base.empty() ? std::string{"/"} : base;
        if (!raw.empty() && raw.front() == '/') {
            if (resolve & kBeneath) return err<std::string>(Errno::exdev);
            cur = root;
        }
        std::vector<std::string> todo;
        split(raw, todo);
        int links = 0;
        while (!todo.empty()) {
            std::string c = std::move(todo.back());
            todo.pop_back();
            if (c == ".") continue;
            if (c == "..") {
                if (cur == root || cur == "/") {
                    if (resolve & kBeneath) return err<std::string>(Errno::exdev);
                    continue;
                }
                if ((resolve & kBeneath) && cur == base) return err<std::string>(Errno::exdev);
                const std::string up = parent(cur);
                if ((resolve & kNoXdev) && mnt(up) != mnt(cur)) return err<std::string>(Errno::exdev);
                cur = up;
                continue;
            }
            const std::string next = join(cur, c);
            if ((resolve & kNoXdev) && mnt(next) != mnt(cur)) return err<std::string>(Errno::exdev);
            if (todo.empty() && !follow_leaf) { cur = next; break; }
            // a /proc magic link jumps rather than naming a path
            if (is_magic_link(next)) {
                if (resolve & kNoMagic) return err<std::string>(Errno::eloop);
                if (resolve & kNoSym) return err<std::string>(Errno::eloop);
                if (scoped) return err<std::string>(Errno::exdev);
                cur = next;
                for (auto it = todo.rbegin(); it != todo.rend(); ++it) cur = join(cur, *it);
                return cur;
            }
            std::string target;
            const auto pc = k_.files().classify(next, false, /*follow=*/false);
            if (pc.realm == kernel::Realm2::host_backed && !pc.host_path.empty()) {
                char buf[PATH_MAX];
                const ::ssize_t n = ::readlink(pc.host_path.c_str(), buf, sizeof buf - 1);
                if (n > 0) target.assign(buf, static_cast<std::size_t>(n));
            } else if (pc.realm == kernel::Realm2::virtual_file) {
                if (auto vf = k_.files().produce(next); vf && vf->symlink_target != "(proc-link)")
                    target = vf->symlink_target;
            }
            if (target.empty()) { cur = next; continue; }
            if (resolve & kNoSym) return err<std::string>(Errno::eloop);
            if (++links > 40) return err<std::string>(Errno::eloop);
            if (target.front() == '/') {
                if (resolve & kBeneath) return err<std::string>(Errno::exdev);
                cur = root;
            }
            split(target, todo);
        }
        return cur;
    }

    // /proc/<pid>/{exe,cwd,root,fd/N,map_files/X,ns/X}, self and task forms too.
    [[nodiscard]] static bool is_magic_link(std::string_view p) {
        if (!p.starts_with("/proc/")) return false;
        p.remove_prefix(6);
        auto take = [&] {
            const auto s = p.find('/');
            const auto c = p.substr(0, s);
            p = s == std::string_view::npos ? std::string_view{} : p.substr(s + 1);
            return c;
        };
        auto num = [](std::string_view c) {
            return !c.empty() && c.find_first_not_of("0123456789") == std::string_view::npos;
        };
        const auto who = take();
        if (who != "self" && who != "thread-self" && !num(who)) return false;
        if (p.starts_with("task/")) { take(); if (!num(take())) return false; }
        const auto a = take();
        if (p.empty()) return a == "exe" || a == "cwd" || a == "root";
        const auto b = take();
        return p.empty() && !b.empty() && (a == "fd" || a == "map_files" || a == "ns");
    }

    // The shared open core: `flags` is already resolved (from a register for
    // open/openat, or from the open_how struct for openat2). Selects the
    // overlay upper layer on write intent and REDIRECTs or INJECTs.
    // `walked`: the guest path openat2 already resolved, used as is.
    [[nodiscard]] Outcome path_open_flags(const Regs& r, int path_arg, bool at,
                                          std::uint64_t flags,
                                          const std::string* walked = nullptr) {
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
        // A "."/".." component does not excuse the components before it:
        // the kernel walks the path, so open("gone/../f1") is ENOENT.
        if (!walked)
            if (const Errno e = dot_prefix_error(r, path_arg, at); e != Errno::ok)
                return eno(e);
        std::string abs = walked ? resolve_raw(r, *walked, at) : resolve_arg(r, path_arg, at);
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
#if defined(__linux__)
        // the guest's kernel log, whatever node stat shows for it (a packet
        // pipe handed over through /proc/<pid>/fd -- Linux hosts only)
        if ((abs == "/dev/kmsg" || abs == "/proc/kmsg") &&
            (pc.realm == kernel::Realm2::virtual_file || pc.realm == kernel::Realm2::host_backed) &&
            !wire::has_for(arch_, flags, wire::OpenFlag::path))
            return kmsg_open(flags, path_arg, /*proc_style=*/abs == "/proc/kmsg");
#endif
        // A TRAILING SLASH asserts the path is a directory, and that
        // assertion is judged BEFORE O_EXCL's "the name is taken": so
        // open("d/", O_CREAT|O_EXCL) on an existing directory is EISDIR,
        // while the same call without the slash is EEXIST. The slash was
        // normalized away, so both came back EEXIST.
        if (wire::has(flags, wire::OpenFlag::creat) &&
            wire::has(flags, wire::OpenFlag::excl) &&
            path_syntax(read_cstr(
                uaddr(r.arg[static_cast<std::size_t>(path_arg)]))) ==
                PathSyntax::needs_dir &&
            host_path_is_dir(pc.host_path))
            return eno(Errno::eisdir);
        // O_EXCL asks about the NAME, not what it resolves to: a dangling
        // symlink occupies the name, so creating through it is EEXIST. We
        // classify with follow=true, which resolves the link to its absent
        // target -- so the overlay happily CREATED that target, a file the
        // caller had explicitly asked not to create.
        if (wire::has(flags, wire::OpenFlag::creat) &&
            wire::has(flags, wire::OpenFlag::excl)) {
            // Ask about the layer the create is actually going to use. `pc`
            // above already resolved that (the overlay UPPER, with parents
            // mirrored), and for an overlay the lower layer's copy does not
            // occupy the name -- an exclusive create over a pristine
            // read-only file has to succeed, which is how a package manager
            // overwrites a shipped file.
            //
            // Using a fresh follow=false classify here consulted the LOWER
            // layer and answered EEXIST for a file the guest had just
            // unlinked, so pacman's unlink-then-O_EXCL failed on every file
            // in a package ("warning given when extracting ... Can't
            // create"). The dangling-symlink case below still needs the
            // name-not-target question, so it asks separately.
            if (pc.realm == kernel::Realm2::host_backed &&
                host_lexists(pc.host_path))
                return eno(Errno::eexist);
            // A dangling symlink occupies the NAME even though it resolves
            // to nothing, so creating through it is EEXIST. classify above
            // followed the link to its absent target, which would have let
            // the overlay create that target instead.
            auto named = k_.files().classify(abs, /*for_write=*/false,
                                             /*follow=*/false);
            if (named.realm == kernel::Realm2::host_backed &&
                host_path_is_symlink(named.host_path))
                return eno(Errno::eexist);
        }
        // O_NOFOLLOW refuses to traverse a final symlink. Without O_PATH
        // that is ELOOP for ANY link -- good, dangling or a cycle -- which is
        // precisely the check a program makes to avoid a symlink attack, and
        // the guest was silently following it. WITH O_PATH the pair means
        // "open the link itself", which succeeds.
        //
        // has_for, not has: O_NOFOLLOW and O_PATH sit at DIFFERENT bits on
        // aarch64, and reading the x86-64 constant made an earlier attempt at
        // this check pass on x86-64 while doing nothing at all on the device.
        if (wire::has_for(arch_, flags, wire::OpenFlag::nofollow)) {
            auto named = k_.files().classify(abs, /*for_write=*/false,
                                             /*follow=*/false);
            if (!named.host_path.empty()) {
                struct ::stat lst{};
                if (::lstat(named.host_path.c_str(), &lst) == 0 &&
                    S_ISLNK(lst.st_mode)) {
                    if (!wire::has_for(arch_, flags, wire::OpenFlag::path))
                        return eno(Errno::eloop);
                    // O_PATH|O_NOFOLLOW: hand the LINK to the host.
                    pending_open_ = abs;
                    pending_flags_ = 0;   // O_PATH never acquires a ctty
                    return Redirect{PathArg{path_arg,
                                            std::move(named.host_path)}};
                }
            }
        }
        // A "."/".." component was normalized away during resolution, but
        // traversing it needs +x on that directory. Only matters when we are
        // CREATING: a plain open of an unsearchable dir is refused by the
        // host call itself, while O_CREAT would otherwise see the normalized
        // name already exist and answer EEXIST.
        if (open_wi == Wi::parents_only &&
            dot_traversal_denied(
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)])),
                pc.host_path))
            return eno(Errno::eacces);
        if (pc.realm == kernel::Realm2::host_backed) {
            // /dev/tty with no controlling terminal: the node is there, the
            // open is ENXIO. (The host task may still have linuxity's own
            // terminal, which is not the guest's.)
            if (abs == "/dev/tty" && pc.host_path == "/dev/tty" && caller_ctty() < 0)
                return eno(Errno::enxio);
            pending_new_ = wire::has(flags, wire::OpenFlag::creat) && !guest_exists(abs);
            // creating a name writes its directory, like mkdir and unlink
            if (pending_new_ && !privileged())
                if (Errno e = dir_entry_allowed(abs, false); e != Errno::ok) return eno(e);
            // An unprivileged guest user gets the kernel's answer for the
            // mode and owner it sees; the host only ever sees its own user.
            if (!pending_new_ && !wire::has_for(arch_, flags, wire::OpenFlag::path)) {
                const std::uint64_t acc = flags & 3u;
                int want = acc == 0 ? 4 : acc == 1 ? 2 : 6;
                if (wire::has(flags, wire::OpenFlag::trunc)) want |= 2;
                if (!guest_may(abs, want)) return eno(Errno::eacces);
                if (privileged()) grant_root_dir_access(abs, pc.host_path);
            }
            // An emulated FIFO opens onto its shared pipe instead (only the
            // Linux launcher turns the emulation on; see fifo_open).
#if defined(__linux__)
            if (k_.files().fifos_emulated() &&
                !wire::has_for(arch_, flags, wire::OpenFlag::path) &&
                k_.files().meta().is_fifo(abs)) {
                struct ::stat st{};
                if (::stat(pc.host_path.c_str(), &st) == 0 && S_ISREG(st.st_mode))
                    return fifo_open(abs, st, flags, path_arg);
            }
#endif
            // Remember the guest path for this fd after the trap assigns it.
            pending_open_ = abs;
            pending_flags_ = flags;
            if (for_write) grant_root_write(abs, pc.host_path);
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
            // A FIFO open without O_NONBLOCK waits for the other end, which
            // is another guest task the tracer must keep serving.
            const bool may_block =
                !wire::has_for(arch_, flags, wire::OpenFlag::nonblock) &&
                !wire::has_for(arch_, flags, wire::OpenFlag::path) && [&] {
                    struct ::stat st{};
                    return ::stat(pc.host_path.c_str(), &st) == 0 && S_ISFIFO(st.st_mode);
                }();
            Redirect rd{PathArg{path_arg, std::move(pc.host_path)}};
            rd.may_block = may_block;
            return rd;
        }
        if (pc.realm == kernel::Realm2::virtual_file) {
            // A virtual file is SYNTHESIZED -- for most of procfs there is
            // nothing to write to. The branch ignored the open mode, so
            // open("/proc/version", O_WRONLY) returned a usable fd and the
            // write that followed reported success and went nowhere. A
            // program told its write worked when it did not is worse off
            // than one that is refused, so these are EACCES like the kernel.
            //
            // NOT everything, though: /proc/<pid>/comm is genuinely writable
            // (it is how a process renames itself, and PR_SET_NAME's twin),
            // and blanket-refusing it broke that. The rule is the kernel's:
            // refuse unless this particular file accepts writes.
            //
            // O_TRUNC counts even with O_RDONLY since it mutates, which is
            // why writable() is the test rather than the access-mode bits.
            const std::string& vpw = pc.virtual_path.empty() ? abs : pc.virtual_path;
            if (for_write && !virtual_is_writable(vpw)) return eno(Errno::eacces);
            if ((flags & 3) != 1 /*not O_WRONLY*/ && virtual_is_write_only(vpw))
                return eno(Errno::eacces);
            // Follow a cross-mount symlink to the RESOLVED virtual path (e.g.
            // /etc/mtab -> /proc/self/mounts); produce that, not the link.
            const std::string& vp = pc.virtual_path.empty() ? abs : pc.virtual_path;
            if (!comm_files_.empty()) apply_comm_writes();
            else if (!map_files_.empty()) apply_map_writes();
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
            pending_flags_ = 0;   // a virtual file is never a terminal
            pending_comm_ = for_write && vp.ends_with("/comm") ? comm_target(vp)
                                                               : std::pair<std::int32_t, std::int32_t>{0, 0};
            pending_map_ = {};
            if (for_write)
                for (const char* leaf : {"/uid_map", "/gid_map", "/setgroups", "/oom_score_adj"})
                    if (vp.ends_with(leaf)) {
                        std::int32_t pid = 0;
                        if (std::sscanf(vp.c_str(), "/proc/%d/", &pid) == 1 && pid > 0)
                            pending_map_ = {global_of_view(pid), leaf + 1};
                    }
            if (for_write && (vp == "/proc/sys/kernel/hostname" || vp == "/proc/sys/kernel/domainname")) {
                // needs CAP_SYS_ADMIN, like sethostname
                if (!creds::capable(me(), 21)) return eno(Errno::eacces);
                pending_map_ = {ids().pid, vp.ends_with("hostname") ? "hostname" : "domainname"};
            }
            if (!pending_map_.second.empty()) vf->bytes.clear();
            // a write sets the name to just what was written, so start empty
            if (pending_comm_.first) vf->bytes.clear();
            // A virtual DIRECTORY: stash its entries so getdents64 on the
            // resulting fd enumerates them (the backing temp node is a real
            // empty directory so O_DIRECTORY opens succeed).
            pending_dir_ = vf->is_dir;
            pending_entries_ = std::move(vf->entries);
            const bool reopen_ok = !wire::has_for(arch_, flags, wire::OpenFlag::nofollow) &&
                                   !wire::has_for(arch_, flags, wire::OpenFlag::path);
            Inject in{path_arg, std::move(vf->bytes), vf->is_dir, for_write, reopen_ok};
            // A guest that put up its own Landlock walls can't open anything
            // by our paths (/proc/<us>/fd/N, a temp file): the open itself
            // would be refused. The guest makes the memfd instead, needing no
            // path, and we fill it before it runs on. Only for plain reads.
            if constexpr (requires { mem_.host_tid(); }) {
                if (!vf->is_dir && !for_write && is_landlocked(ids().pid)) {
                    const bool cloexec = wire::has_for(arch_, flags, wire::OpenFlag::cloexec);
                    GuestCalls gc;
                    gc.strings = {"linuxity-vfile"};
                    gc.steps = {{Sysno::memfd_create, {GuestCalls::str0, cloexec ? 1u : 0u, 0, 0, 0, 0}}};
                    gc.result_of = 0;
                    gc.before_resume = [this, bytes = std::move(in.content)](std::int64_t fd) {
                        if (fd < 0) return;
                        char link[64];
                        std::snprintf(link, sizeof link, "/proc/%d/fd/%d", mem_.host_tid(), static_cast<int>(fd));
                        if (const int w = ::open(link, O_WRONLY | O_CLOEXEC); w >= 0) {
                            std::size_t off = 0;
                            while (off < bytes.size()) {
                                const auto n = ::pwrite(w, bytes.data() + off, bytes.size() - off,
                                                        static_cast<off_t>(off));
                                if (n <= 0) break;
                                off += static_cast<std::size_t>(n);
                            }
                            ::close(w);
                        }
                        note_opened_fd(fd);
                    };
                    return gc;
                }
            }
            if (vf->is_dir && !for_write)
                for (const char* top : {"/proc", "/sys", "/dev"})
                    if (vp == top || (vp.starts_with(top) && vp[std::strlen(top)] == '/')) {
                        in.dir_host = top;
                        break;
                    }
            return in;
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
    // fstat(fd, buf), and the AT_EMPTY_PATH forms: the inode the fd is open
    // on, owned the way the guest's world says (root, or what it chown'd),
    // exactly as a stat by path reports it.
    [[nodiscard]] Outcome stat_fd(int fd, UAddr buf, bool statx) {
        const std::string gp{k_.files().path_of_fd(fd)};
        if (!gp.empty()) {
            auto pc = k_.files().classify(gp);
            if (pc.realm == kernel::Realm2::virtual_file) {
                const std::string& vp = pc.virtual_path.empty() ? gp : pc.virtual_path;
                if (auto vf = k_.files().produce(vp); vf && vf->redirect_host.empty())
                    return statx ? write_statx(buf, vf->is_dir, vf->bytes.size(), false, gp)
                                 : write_statbuf(buf, vf->is_dir, vf->bytes.size());
            }
        }
        if constexpr (!requires { mem_.host_tid(); } && !requires { mem_.host_fd_of(0); }) {
            return fwd();
        } else {
            // the inode itself, through the task's fd (works for unlinked
            // files, pipes and sockets too)
            struct ::stat st{};
            if (const Errno e = host_fstat(fd, st); e != Errno::ok) return eno(e);
            // An anonymous object (socket, pipe) has no path to overlay, and
            // a backend that performs calls itself spells its identity its
            // own way (HVF: a socket's inode is net::socket_inode, matching
            // its /proc/self/fd link). Let the backend answer those.
            if constexpr (!requires { mem_.host_tid(); })
                if (gp.empty() || S_ISSOCK(st.st_mode) || S_ISFIFO(st.st_mode)) return fwd();
            wire::StatFields h = host::stat_fields(st);
            // the same inode by path: fill in what a path stat would (emulated
            // link counts, socket placeholders), only if it IS that inode.
            // Without either, the path stat could only repeat the fd's.
            if (!gp.empty() && (!k_.files().links().empty() || !sock_placeholders_.empty())) {
                auto pc = k_.files().classify(gp);
                if (pc.realm == kernel::Realm2::host_backed)
                    if (auto f = fast_stat(pc.host_path, gp); f && f->ino == h.ino && f->dev == h.dev) {
                        h.nlink = f->nlink;
                        h.mode = f->mode;
                    }
            }
            const Outcome out = statx ? write_statx(buf, h, gp) : write_statbuf(buf, h);
            // owner: root, or what the guest chown/chmod'd on this path
            scrub_ids(Scrub{statx ? Scrub::Layout::statx : Scrub::Layout::stat, buf, gp});
            return out;
        }
    }

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
                       ? stat_fd(static_cast<int>(r.arg[0]), uaddr(r.arg[2]), false)
                       : eno(Errno::enoent);

        // A dirfd we cannot resolve means we'd resolve the path against the
        // wrong directory; the host owns the real fd table, so let it answer.
        if (at && at_dirfd_unresolvable(r, raw)) return fwd();

        // A "."/".." component does not excuse the components before it: the
        // kernel walks the path, so stat("gone/..") is ENOENT even though the
        // normalized form is a directory that exists.
        if (const Errno e = dot_prefix_error(r, path_arg, at); e != Errno::ok)
            return eno(e);

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
        if (raw1.empty() && wire::has_at(flags, wire::AtFlag::empty_path))
            return stat_fd(static_cast<int>(r.arg[0]), uaddr(r.arg[4]), true);
        bool nofollow = wire::has_at(flags, wire::AtFlag::symlink_nofollow);
        if (empty_path_arg(r, 1)) return eno(Errno::enoent);
        // A "."/".." component does not excuse the components before it.
        if (const Errno e = dot_prefix_error(r, 1, /*at=*/true); e != Errno::ok)
            return eno(e);
        std::string abs = resolve_arg(r, 1, true, /*follow_leaf=*/!nofollow);
        // Honor AT_SYMLINK_NOFOLLOW (0x100): coreutils `stat`/`ls -la` statx a
        // symlink with this flag and expect S_IFLNK; following it reported the
        // target's type ("regular file") and made git's symlink probe fail.
        auto pc = k_.files().classify(abs, /*for_write=*/false, /*follow=*/!nofollow);
        if (pc.realm == kernel::Realm2::host_backed) {
            if (auto fast = fast_stat(pc.host_path, abs))
                return write_statx(uaddr(r.arg[4]), *fast, abs);
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
                               !vf->symlink_target.empty(), abs);
        }
        return eno(pc.error);
    }

    // access/readlink[at]/faccessat: host-backed -> redirect; virtual
    // paths that exist -> success (0); absent -> error.
    [[nodiscard]] Outcome path_at(const Regs& r, int path_arg, bool at) {
        std::string raw0 =
            read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
        if (raw0.empty()) return at ? fwd() : eno(Errno::enoent);
        // A "."/".." component does not excuse the components before it: the
        // kernel walks the path, so access("gone/..") is ENOENT even though
        // the normalized form is a directory that exists.
        if (const Errno e = dot_prefix_error(r, path_arg, at); e != Errno::ok)
            return eno(e);
        std::string abs = resolve_arg(r, path_arg, at);
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) {
            // access/faccessat answer for the guest's own ids. Root reads
            // and writes anything but still needs an x bit to execute.
            const auto sc = decode(arch_, r.nr);
            if (sc == Sysno::access || sc == Sysno::faccessat || sc == Sysno::faccessat2) {
                const int want = static_cast<int>(r.arg[static_cast<std::size_t>(path_arg) + 1] & 7u);
                if (want != 0 && guest_exists(abs)) {
                    if (!guest_may(abs, want)) return eno(Errno::eacces);
                    if (!(want & 1)) return val(0);
                }
            }
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
        std::string raw0 =
            read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
        if (raw0.empty() && !at) return eno(Errno::enoent);
        if (raw0.empty()) {
#if defined(__linux__)
            return fwd();   // the host kernel reads an O_PATH link fd itself
#else
            // readlinkat(fd, ""): the link the fd itself names (an O_PATH |
            // O_NOFOLLOW handle). Forwarding handed the host an empty path,
            // which a host that resolves names itself answers ENOENT.
            const std::string p{dir_of(static_cast<std::int64_t>(r.arg[0]))};
            if (p.empty()) return fwd();
            const std::size_t bi0 = static_cast<std::size_t>(path_arg) + 1;
            const UAddr buf0 = uaddr(r.arg[bi0]);
            const std::size_t cap0 = static_cast<std::size_t>(r.arg[bi0 + 1]);
            if (static_cast<std::int64_t>(r.arg[bi0 + 1]) <= 0) return eno(Errno::einval);
            if (std::string tgt = proc_symlink_target(p); !tgt.empty())
                return write_link(buf0, cap0, tgt);
            auto pc = k_.files().classify(p, /*for_write=*/false, /*follow=*/false);
            if (pc.realm == kernel::Realm2::host_backed) {
                char tgt[4096];
                const ::ssize_t n = ::readlink(pc.host_path.c_str(), tgt, sizeof tgt);
                if (n < 0) return eno(errno == EINVAL ? Errno::enoent : wire::errno_from_host(errno));
                const std::size_t len = std::min(static_cast<std::size_t>(n), cap0);
                if (len && !mem_.copy_out(buf0, {reinterpret_cast<const std::byte*>(tgt), len}))
                    return eno(Errno::efault);
                return val(static_cast<std::int64_t>(len));
            }
            if (pc.realm == kernel::Realm2::virtual_file)
                if (auto vf = k_.files().produce(p); vf && !vf->symlink_target.empty() &&
                                                     vf->symlink_target != "(proc-link)")
                    return write_link(buf0, cap0, vf->symlink_target);
            return eno(Errno::enoent);   // the fd is not a symlink
#endif
        }
        // A non-positive bufsiz is EINVAL, and the kernel checks it BEFORE it
        // resolves the path -- so it outranks every lookup error, including
        // the EACCES an unsearchable component would give. (bufsiz is the
        // register after the buffer, which is after the path.)
        if (static_cast<std::int64_t>(
                r.arg[static_cast<std::size_t>(path_arg) + 2]) <= 0)
            return eno(Errno::einval);
        // A "."/".." component does not excuse the components before it: an
        // unsearchable directory mid-path is EACCES, ahead of the EINVAL
        // that "this is not a symlink" would give.
        if (const Errno e = dot_prefix_error(r, path_arg, at); e != Errno::ok)
            return eno(e);
        // A symlink CYCLE in the prefix is ELOOP, ahead of the EINVAL that
        // "the leaf is not a link" would give. readlink resolves the prefix
        // but not the leaf, so the namespace has to be asked directly.
        if (const Errno e = guest_prefix_loop(resolve_arg(r, path_arg, at,
                                                          /*follow_leaf=*/false));
            e != Errno::ok)
            return eno(e);

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
            const auto vp = k_.procs().view_pid(id.pid), vt = k_.procs().view_pid(id.tid);
            if (pre == "/proc/self")
                return write_link(uaddr(r.arg[bi0]),
                                  static_cast<std::size_t>(r.arg[bi0 + 1]),
                                  std::to_string(vp));
            if (pre == "/proc/thread-self")
                return write_link(uaddr(r.arg[bi0]),
                                  static_cast<std::size_t>(r.arg[bi0 + 1]),
                                  std::to_string(vp) + "/task/" +
                                      std::to_string(vt));
            // A synthesized symlink outside /proc (/dev/stdin -> /proc/self/fd/0,
            // /dev/fd): its own target, before resolve_arg expands the leaf
            // through it.
            if (!pre.starts_with("/proc/")) {
                if (auto vf = k_.files().produce(pre);
                    vf && !vf->symlink_target.empty() && vf->symlink_target != "(proc-link)")
                    return write_link(uaddr(r.arg[bi0]),
                                      static_cast<std::size_t>(r.arg[bi0 + 1]),
                                      vf->symlink_target);
            }
        }

        if (empty_path_arg(r, path_arg)) return eno(Errno::enoent);
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
#if defined(__linux__)
            // Most links read the same from any process, so read them here:
            // one stop instead of a redirect's two. /proc and /dev links
            // depend on who reads them (/proc/self), so the guest still does.
            const std::string_view hp = pc.host_path;
            if (hp.starts_with("/proc/") || hp.starts_with("/dev/"))
                return Redirect{PathArg{path_arg, std::move(pc.host_path)}};
            char tgt[4096];
            const ::ssize_t n = ::readlink(pc.host_path.c_str(), tgt, sizeof tgt);
            if (n < 0) return eno(wire::errno_from_host(errno));
            const std::size_t len = std::min(static_cast<std::size_t>(n), cap);
            if (len && !mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(tgt), len}))
                return eno(Errno::efault);
            return val(static_cast<std::int64_t>(len));
#else
            return Redirect{PathArg{path_arg, std::move(pc.host_path)}};
#endif
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
                            if (!gp.empty()) {
                                // a synthesized file's temp is unlinked on open
                                const bool virt = k_.files().classify(std::string{gp}).realm ==
                                                  kernel::Realm2::virtual_file;
                                return std::string{gp} + (!virt && host_fd_deleted(fd) ? " (deleted)" : "");
                            }
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

    // stat(2) the host object behind guest fd `fd`: our own host fd where
    // the backend holds it (HVF), else the tracee's /proc/<tid>/fd magic
    // link (ptrace). EBADF for an fd the guest doesn't have.
    [[nodiscard]] Errno host_fstat(int fd, struct ::stat& st) {
        if constexpr (requires { mem_.host_fd_of(fd); } && !requires { mem_.host_tid(); }) {
            const int h = mem_.host_fd_of(fd);
            if (h < 0) return Errno::ebadf;
            return ::fstat(h, &st) == 0 ? Errno::ok : wire::errno_from_host(errno);
        } else if constexpr (requires { mem_.host_tid(); }) {
            char link[64];
            std::snprintf(link, sizeof link, "/proc/%d/fd/%d", mem_.host_tid(), fd);
            if (::stat(link, &st) == 0) return Errno::ok;
            return errno == ENOENT ? Errno::ebadf : wire::errno_from_host(errno);
        } else {
            (void)fd; (void)st;
            return Errno::enosys;
        }
    }

    // Does the host say the file behind the tracee's fd was unlinked?
    [[nodiscard]] bool host_fd_deleted(int fd) {
        if constexpr (requires { mem_.host_fd_of(fd); } && !requires { mem_.host_tid(); }) {
            // The guest's fd is OUR host fd: an unlinked file has no links left.
            struct ::stat st{};
            const int h = mem_.host_fd_of(fd);
            return h >= 0 && ::fstat(h, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 0;
        } else if constexpr (!requires { mem_.host_tid(); }) {
            return false;
        } else {
            char link[64], tgt[4096];
            std::snprintf(link, sizeof link, "/proc/%d/fd/%d", mem_.host_tid(), fd);
            const ::ssize_t n = ::readlink(link, tgt, sizeof tgt);
            constexpr std::string_view kDel = " (deleted)";
            return n >= static_cast<::ssize_t>(kDel.size()) &&
                   std::string_view{tgt, static_cast<std::size_t>(n)}.ends_with(kDel);
        }
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
            std::string a = read_string(uaddr(p));
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
        if (empty_path_arg(r, path_arg)) return eno(Errno::enoent);
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
            // A set-user/group-ID program raises the caller's effective id, and
            // the guest's ids are ours to keep, so note the owner here for
            // creds::on_exec to apply once the image is in. Without this a
            // guest that dropped to a normal user could never get back:
            // `sudo` saw euid != 0 and blamed a nosuid mount.
            //
            // The mode the GUEST sees is what counts (the overlay records it,
            // so a host that cannot keep the s-bit still shows it), and the
            // owner comes from the same view -- a rootfs unpacked by an
            // ordinary user still has a root-owned sudo.
            {
                struct ::stat st{};
                if (::stat(pc.host_path.c_str(), &st) == 0) {
                    std::uint32_t mode = st.st_mode, uid = 0, gid = 0;
                    if (auto rec = k_.files().meta().lookup(k_.files().resolve_links(abs))) {
                        mode = kernel::MetaStore::effective_mode(mode, *rec);
                        if (rec->have & kernel::MetaRecord::kUid) uid = rec->uid;
                        if (rec->have & kernel::MetaRecord::kGid) gid = rec->gid;
                    }
                    auto& p = me();
                    p.exec_setuid = (mode & 04000u) ? uid : creds::kKeep;
                    p.exec_setgid = (mode & 02000u) ? gid : creds::kKeep;
                }
            }
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
                // the interpreter is the same file on the host: the kernel can
                // load both itself, with the auxv a debugger expects
                if (ipc.realm == kernel::Realm2::host_backed && ipc.host_path == interp_abs &&
                    extra.empty()) {
                    // an exec waits for its other threads to be reaped, so
                    // the tree must keep running meanwhile
                    Redirect rd{PathArg{path_arg, std::move(pc.host_path)}};
                    rd.may_block = true;
                    return rd;
                }
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
                // The kernel hands the interpreter the script path exactly as
                // given to execve, so $0 / sys.argv[0] read "./s2". A
                // relative path only resolves if the host cwd is the guest's,
                // so fall back to the absolute one when it isn't.
                std::string script = abs;
                const std::string given = read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
                if (!given.empty() && given.front() != '/') {
                    const auto cc = k_.files().classify(std::string{k_.files().cwd()});
                    if (cc.realm == kernel::Realm2::host_backed && host_cwd_is(cc.host_path))
                        script = given;
                }
                // prog_guest is the script, as a guest path.
                ExecInterp ei{path_arg, std::move(interp_host), std::move(script)};
                ei.prefix = std::move(prefix);
                return ei;
            }
            return Redirect{PathArg{path_arg, std::move(pc.host_path)}};
        }
        return eno(pc.realm == kernel::Realm2::virtual_file ? Errno::eacces
                                                            : pc.error);
    }

    [[nodiscard]] Outcome do_chdir(const Regs& r) {
        const std::string old_cwd{k_.files().cwd()};
        std::string abs = k_.files().absolutize(read_cstr(uaddr(r.arg[0])),
                                                old_cwd);
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
            // a deep dir's host path can pass PATH_MAX; walk it instead
            struct ::stat st{};
            const int dfd = host::open_long(pc.host_path, host::kWalkDirFlags);
            if (dfd < 0) return eno(errno == ENOTDIR ? Errno::enotdir : Errno::enoent);
            const int rc = ::fstat(dfd, &st);
            ::close(dfd);
            if (rc != 0)            return eno(Errno::enoent);
            if (!S_ISDIR(st.st_mode)) return eno(Errno::enotdir);
        }
        k_.files().set_cwd(abs);
        // Move the host cwd too, best effort and answer ignored, so an
        // over-long cwd-relative path can be rebased on it (see
        // rebase_on_dirfd). The guest's answer is the check above.
        if constexpr (requires { mem_.host_tid(); }) {
            if (pc.realm == kernel::Realm2::host_backed) {
                std::string hp = std::move(pc.host_path);
                if (hp.size() >= 4096) {
                    // too long for the host: step from the old cwd instead
                    const auto oc = k_.files().classify(old_cwd);
                    const std::string base = oc.host_path + "/";
                    if (oc.realm != kernel::Realm2::host_backed || !hp.starts_with(base) ||
                        hp.size() - base.size() >= 4096 || !host_cwd_is(oc.host_path))
                        return val(0);   // host cwd can't follow; guest view is fine
                    hp = hp.substr(base.size());
                }
                Redirect rd{PathArg{0, std::move(hp)}};
                rd.force_ret = 0;
                return rd;
            }
        }
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
        if (empty_path_arg(r, 0)) return eno(Errno::enoent);
        std::string abs = resolve_arg(r, 0, /*at=*/false);
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) {
            return Redirect{PathArg{0, std::move(pc.host_path)}};   // host fills arg[1] with the real overlay-fs statfs
        }
        if (pc.realm == kernel::Realm2::virtual_file)
            return write_statfs(uaddr(r.arg[1]), abs);
        return eno(pc.error);
    }

    // fstatfs(fd, buf). An fd opened through a SYNTHESIZED mount (/proc,
    // /sys, /dev) is backed by a host temp file or directory, so the host
    // would answer tmpfs. Answer for the filesystem the guest opened. Every
    // other fd is a real host file, and the host's answer is the truth.
    [[nodiscard]] Outcome do_fstatfs(const Regs& r) {
        const std::string_view gp =
            k_.files().path_of_fd(static_cast<int>(r.arg[0]));
        if (!gp.empty() && k_.files().under_virtual_mount(std::string{gp}))
            return write_statfs(uaddr(r.arg[1]), gp);
        return fwd();
    }

    // socket(domain, type, protocol). Only one combination is answered here:
    // a NETLINK_AUDIT socket, which needs an audit subsystem linuxity does not
    // have. A kernel built without CONFIG_AUDIT answers EPROTONOSUPPORT, and
    // that is what systemd, auditd clients and libaudit treat as "no audit
    // here" and stay quiet about. Forwarded, the host's answer (EACCES on
    // Android) made systemd log an error on every run. Everything else is a
    // real host socket.
    [[nodiscard]] Outcome do_socket(const Regs& r) {
        constexpr std::uint64_t kAfNetlink = 16, kNetlinkAudit = 9, kNetlinkGeneric = 16;
        // a network namespace the host couldn't make real is one on paper:
        // its sockets would be on the host's network. Refuse those, so the
        // guest is as cut off as it asked to be.
        constexpr std::uint64_t kAfInet = 2, kAfInet6 = 10, kAfPacket = 17;
        if ((r.arg[0] == kAfInet || r.arg[0] == kAfInet6 || r.arg[0] == kAfPacket) &&
            k_.procs().net_isolated(ids().pid) && !host::host_can_netns())
            return eno(Errno::eacces);
        if (r.arg[0] == kAfNetlink && r.arg[2] == kNetlinkAudit)
            return eno(Errno::eprotonosupport);
        // Generic netlink where the host refuses it (Android's shell): a
        // local datagram socket the guest binds to a private abstract name,
        // whose nl80211 requests we answer (see nl_answer).
        if (r.arg[0] == kAfNetlink && r.arg[2] == kNetlinkGeneric && host_refuses_genl()) {
            constexpr std::uint64_t kAfUnix = 1, kDgram = 2, kKeepFlags = 0x80800;  // CLOEXEC|NONBLOCK
            const std::string name = "lx-nl-" + std::to_string(::getpid()) + "-" +
                                     std::to_string(++nl_seq_);
            std::string sa(2, '\0');
            sa[0] = 1;                                 // AF_UNIX, little-endian
            sa += '\0';                                // abstract
            sa += name;
            GuestCalls gc;
            gc.strings = {sa};
            // Moved into the fd band the filter traps sendto for (see
            // kNlFdLo), so sendto on every other socket stays native.
            const std::uint64_t dupcmd = (r.arg[1] & 0x80000) ? 1030 /*F_DUPFD_CLOEXEC*/ : 0 /*F_DUPFD*/;
            gc.steps = {{Sysno::socket, {kAfUnix, kDgram | (r.arg[1] & kKeepFlags), 0, 0, 0, 0}},
                        {Sysno::bind, {GuestCalls::prev_of(0), GuestCalls::str0,
                                       static_cast<std::uint64_t>(sa.size()), 0, 0, 0}},
                        {Sysno::fcntl, {GuestCalls::prev_of(0), dupcmd, kNlFdLo, 0, 0, 0}},
                        {Sysno::close, {GuestCalls::prev_of(0), 0, 0, 0, 0, 0}}};
            gc.result_of = 2;
            gc.done = [this, name](std::int64_t fd) {
                if (fd < 0) return;
                if (const std::uint64_t ino = socket_inode(static_cast<int>(fd)))
                    nl_socks_[ino] = name;
            };
            return gc;
        }
        return fwd();
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
        if (empty_path_arg(r, path_arg)) return eno(Errno::enoent);
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
            std::string name = read_string(uaddr(r.arg[1]));
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
        // A read needs nothing from the guest's own context, so answer it
        // here: one stop, where a redirect is two plus poking the path into
        // its memory word by word. `ls -l` makes one of these per file.
#if defined(__linux__)
        if (!for_write && !at && !pc.host_path.starts_with("/proc/") &&
            !pc.host_path.starts_with("/dev/")) {
            if (const auto sc = decode(arch_, r.nr);
                sc == Sysno::listxattr || sc == Sysno::llistxattr ||
                sc == Sysno::getxattr || sc == Sysno::lgetxattr)
                return host_xattr_read(r, sc, pc.host_path);
        }
#endif
        // Hand the guest path along so PathArg can see this is an identity
        // translation and the trap loop can forward instead of rewriting.
        return Redirect{PathArg{path_arg, std::move(pc.host_path), abs}};
    }

#if defined(__linux__)
    // getxattr/lgetxattr/listxattr/llistxattr on a host path, done by us and
    // copied out. Same errors the kernel would give the guest: we run as the
    // same host user it does.
    [[nodiscard]] Outcome host_xattr_read(const Regs& r, Sysno sc, const std::string& host) {
        const bool list = sc == Sysno::listxattr || sc == Sysno::llistxattr;
        const bool nofollow = sc == Sysno::llistxattr || sc == Sysno::lgetxattr;
        // list(path, buf, size); get(path, name, buf, size)
        const UAddr buf = uaddr(r.arg[list ? 1 : 2]);
        const auto cap = static_cast<std::size_t>(std::min<std::uint64_t>(r.arg[list ? 2 : 3], 1u << 16));
        std::string name;
        if (!list) name = read_string(uaddr(r.arg[1]));
        std::vector<std::byte> out(cap);
        void* p = cap ? out.data() : nullptr;
        const ::ssize_t n = list ? (nofollow ? ::llistxattr(host.c_str(), static_cast<char*>(p), cap)
                                             : ::listxattr(host.c_str(), static_cast<char*>(p), cap))
                                 : (nofollow ? ::lgetxattr(host.c_str(), name.c_str(), p, cap)
                                             : ::getxattr(host.c_str(), name.c_str(), p, cap));
        if (n < 0) return eno(wire::errno_from_host(errno));
        if (cap && n > 0 && !mem_.copy_out(buf, {out.data(), static_cast<std::size_t>(n)}))
            return eno(Errno::efault);
        return val(n);
    }
#endif

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

    // uid_map/gid_map/setgroups writes: each is set once per user namespace,
    // like the kernel (a second uid_map write is EPERM there).
    void apply_map_writes() {
        for (auto it = map_files_.begin(); it != map_files_.end();) {
            std::string text;
            if (const int h = ::open(it->host.c_str(), O_RDONLY | O_CLOEXEC); h >= 0) {
                char buf[4096];
                const ::ssize_t n = ::read(h, buf, sizeof buf);
                ::close(h);
                if (n > 0) text.assign(buf, static_cast<std::size_t>(n));
            }
            if (text.empty()) { ++it; continue; }   // not written yet
            auto* p = k_.procs().find_mut(it->pid);
            auto& reg = k_.procs().ns();
            if (p) {
                const auto un = p->ns[kernel::NsKind::user];
                if (it->which == "oom_score_adj") {
                    // -1000..1000; lowering it needs CAP_SYS_RESOURCE (root has it)
                    const long v = std::strtol(text.c_str(), nullptr, 10);
                    if (v >= -1000 && v <= 1000) p->oom_score_adj = static_cast<std::int32_t>(v);
                } else if (it->which == "hostname" || it->which == "domainname") {
                    while (!text.empty() && text.back() == '\n') text.pop_back();
                    if (text.size() > 64) text.resize(64);
                    const auto uid = p->ns[kernel::NsKind::uts];
                    if (it->which == "domainname") reg.set_domainname(uid, text);
                    else if (uid) reg.set_hostname(uid, text);
                    else {
                        if constexpr (requires { k_.machine().nodename = text; }) k_.machine().nodename = text;
                    }
                } else if (auto* u = reg.user_ns(un)) {
                    if (it->which == "setgroups") u->setgroups_allowed = !text.starts_with("deny");
                    else if (it->which == "uid_map" && !u->uid_set) {
                        u->uid_map = kernel::Namespaces::parse_map(text);
                        u->uid_set = true;
                    } else if (it->which == "gid_map" && !u->gid_set) {
                        u->gid_map = kernel::Namespaces::parse_map(text);
                        u->gid_set = true;
                    }
                }
            }
            it = map_files_.erase(it);
        }
    }

    // A write to a comm file lands in its backing temp file. Pick up any that
    // changed and rename the thread, before anything reads a name.
    void apply_comm_writes() {
        apply_map_writes();
        for (auto it = comm_files_.begin(); it != comm_files_.end();) {
            auto& c = *it;
            const int h = k_.procs().find(c.pid) ? ::open(c.host.c_str(), O_RDONLY | O_CLOEXEC) : -1;
            if (h < 0) { it = comm_files_.erase(it); continue; }
            char buf[15];   // Linux keeps 15 bytes
            const ssize_t n = ::read(h, buf, sizeof buf);
            ::close(h);
            if (n > 0 && std::string_view(buf, static_cast<std::size_t>(n)) != c.seen) {
                c.seen.assign(buf, static_cast<std::size_t>(n));
                k_.procs().set_thread_comm(c.pid, c.tid, c.seen);
            }
            ++it;
        }
    }

    // A pid as the caller numbers it (its pid namespace) -> the global pid.
    [[nodiscard]] std::int32_t global_of_view(std::int32_t pid) const {
        const auto pns = k_.procs().reader_pid_ns();
        return pns ? k_.procs().pid_from(pns, pid) : pid;
    }

    // /proc/<pid>/comm, /proc/<pid>/task/<tid>/comm or /proc/<tid>/comm ->
    // the (process, thread) it names, or {0, 0}
    [[nodiscard]] std::pair<std::int32_t, std::int32_t> comm_target(std::string_view vp) const {
        auto num = [&](std::string_view& s) {
            std::int32_t v = 0;
            std::size_t i = 0;
            for (; i < s.size() && s[i] >= '0' && s[i] <= '9'; ++i) v = v * 10 + (s[i] - '0');
            s.remove_prefix(i);
            return i ? v : 0;
        };
        if (!vp.starts_with("/proc/")) return {0, 0};
        vp.remove_prefix(6);
        const std::int32_t a = global_of_view(num(vp));
        std::int32_t b = 0;
        if (vp.starts_with("/task/")) { vp.remove_prefix(6); b = global_of_view(num(vp)); }
        if (a <= 0 || b < 0 || vp != "/comm") return {0, 0};
        if (k_.procs().find(a)) return {a, b ? b : a};
        if (const auto tg = k_.procs().thread_group_of(a)) return {tg, a};
        return {0, 0};
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

    // utimes/utimensat with a NULL path. That is not a missing argument -- it
    // is the documented "set the times on the dirfd itself" form, and it is
    // what touch(1) and anything that stamps a file actually use, so treating
    // it as an empty path made all of them fail with ENOENT.
    //
    // With a real path it is an ordinary content mutation (copy_leaf). With
    // NULL there is no path to map, so forward and let the kernel act on the
    // host fd: timestamps are not virtualised and the fd is already the
    // host's. That also gets the error cases right for free -- a closed fd is
    // EBADF, and NULL with no fd to fall back on (AT_FDCWD, or the utimes
    // forms that take no dirfd at all) is EFAULT.
    [[nodiscard]] Outcome do_utimes(const Regs& r, int path_arg, bool at,
                                    int flags_arg) {
        // AT_EMPTY_PATH makes "" mean the dirfd, same as a NULL path -- both
        // forward to the host fd. Only utimensat has a flags register.
        const bool null_path = null_path_arg(r, path_arg);
        const bool empty_with_flag =
            flags_arg >= 0 && empty_cstr_arg(r, path_arg) &&
            wire::has_at(r.arg[static_cast<std::size_t>(flags_arg)],
                         wire::AtFlag::empty_path);
        if (null_path || empty_with_flag) {
            if (!at) return eno(Errno::efault);
            if (static_cast<std::int32_t>(r.arg[0]) == wire::kAtFdCwd)
                return eno(null_path ? Errno::efault : Errno::enoent);
            return fwd();
        }
        return path_mut(r, path_arg, at, Wi::copy_leaf);
    }

    // A single-path mutation (mkdir/rmdir/unlink/chmod/chown/truncate/...):
    // translate the guest path at `path_arg` to its overlay UPPER host path
    // and REDIRECT, with the WriteIntent selecting how the upper layer is
    // prepared (create the leaf itself, copy an existing leaf up, or just
    // resolve for removal). A virtual path (procfs/sysfs) gets the errno its
    // missing inode op implies -- see virtual_mut_errno; an absent target
    // yields its own errno.
    using Wi = kernel::FileNamespace::WriteIntent;
    // strict_parent: mkdir/mknod must FAIL when the parent is missing, so they
    // opt out of pre-creating the chain and let the host kernel apply the rule.
    [[nodiscard]] Outcome path_mut(const Regs& r, int path_arg, bool at, Wi wi,
                                   bool strict_parent = false,
                                   bool rmdir_syscall = false) {
        if (empty_path_arg(r, path_arg)) return eno(Errno::enoent);
        // A "."/".." component does not excuse the components before it.
        if (const Errno e = dot_prefix_error(r, path_arg, at); e != Errno::ok)
            return eno(e);
        // A removal has to see the path as WRITTEN: resolve_arg normalizes
        // "."/".." away, which would turn `rmdir d/.` into a removal of d
        // and `rmdir d/..` into a removal of its PARENT. The kernel refuses
        // both outright, so check before resolving.
        if (wi == Wi::remove) {
            const std::string raw =
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
            const DotTail dt = dot_tail(raw);
            if (dt != DotTail::none) {
                // ...but the kernel has to TRAVERSE the directory to discover
                // the dot at all, so no-search is EACCES and outranks the
                // EINVAL/ENOTEMPTY below.
                auto dotpc = k_.files().classify(resolve_arg(r, path_arg, at),
                                                 /*for_write=*/true,
                                                 /*follow=*/false, wi);
                if (dot_traversal_denied(raw, dotpc.host_path))
                    return eno(Errno::eacces);
            }
            switch (dt) {
            case DotTail::dot:
                // rmdir says EINVAL ("." is not a removable name); plain
                // unlink got as far as seeing a directory, so EISDIR.
                return eno(removedir_flag(r, path_arg, at, rmdir_syscall)
                               ? Errno::einval
                               : Errno::eisdir);
            case DotTail::dotdot:
                // The parent still holds the entry we came through, so even
                // as a directory removal it is not empty.
                return eno(removedir_flag(r, path_arg, at, rmdir_syscall)
                               ? Errno::enotempty
                               : Errno::eisdir);
            case DotTail::none: break;
            }
        }
        std::string abs = resolve_arg(r, path_arg, at);
        auto pc = k_.files().classify(abs, /*for_write=*/true, /*follow=*/false, wi);
        // A "."/".." component was normalized away above, but resolving it
        // traverses its directory, which needs +x there.
        if (dot_traversal_denied(
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)])),
                pc.host_path))
            return eno(Errno::eacces);
        // A symlink CYCLE in the prefix is ELOOP. classify here uses
        // follow=false (these ops act on the NAME), which is what skips the
        // detector, so ask the namespace -- the host cannot see the cycle,
        // because the overlay upper holds guest-absolute link targets.
        if (const Errno e = guest_prefix_loop(abs); e != Errno::ok)
            return eno(e);
        if (pc.realm == kernel::Realm2::virtual_file) {
            // This branch means the leaf RESOLVED, so a creating op (mkdir,
            // mknod) is refused for the name being taken, before procfs's
            // missing create op is ever consulted.
            if (wi == Wi::parents_only)
                return eno(virtual_mut_errno(abs, VMut::exists));
            // A writable virtual file (comm) accepts content changes, the way
            // the kernel's does.
            if (wi == Wi::copy_leaf && virtual_is_writable(abs)) return val(0);
            // remove and copy_leaf share the rule: both need write access to
            // the containing directory before reaching the inode op.
            return eno(virtual_mut_errno(abs, VMut::remove));
        }
        // A removal whose target lives ONLY in the read-only lower layer:
        // forwarding the unlink would destroy the pristine rootfs. Record a
        // whiteout (hides the lower file in the overlay view) and report
        // success WITHOUT touching the host. Also drop any shadow meta.
        //
        // With an UPPER copy as well, the whiteout is still needed -- removing
        // the upper file would unshadow the lower one and the file would come
        // back -- but the upper copy is ours to delete, so fall through and
        // forward the unlink too.
        if (pc.whiteout_lower) {
            k_.files().add_whiteout(abs);
            k_.files().meta().forget(abs);
            if (pc.host_path.empty()) return val(0);
        }
        if (pc.host_path.empty()) return eno(pc.error);
        // Creating or removing a name writes the parent directory, and in a
        // sticky one only the file's or the directory's owner may remove it.
        if ((wi == Wi::remove || wi == Wi::parents_only) && !privileged()) {
            if (Errno e = dir_entry_allowed(abs, wi == Wi::remove); e != Errno::ok) return eno(e);
        }
        // mkfifo on a host that refuses FIFOs (Android): make the placeholder
        // ourselves. The mode is the register after the path.
        if (wi == Wi::parents_only && k_.files().fifos_emulated()) {
            const Sysno sc = decode(arch_, r.nr);
            const auto mode = static_cast<std::uint32_t>(r.arg[static_cast<std::size_t>(path_arg) + 1]);
            if ((sc == Sysno::mknod || sc == Sysno::mknodat) && (mode & 0170000u) == 0010000u)
                return fifo_create(abs, pc.host_path, mode);
        }
        // A removal drops any shadow record so a fresh file created at the same
        // path later starts from the host defaults, not a stale owner/mode.
        if (wi == Wi::remove) {
            k_.files().meta().forget(abs);
            // An emulated hardlink name: removing an alias drops it from the
            // table; removing the backing while aliases remain must keep the
            // data alive under one of them, as the kernel keeps an inode
            // alive while any link remains. Done synchronously so the table
            // only changes if the host unlink succeeds.
            auto& lt = k_.files().links();
            if (!lt.empty() && (lt.backing_of(pc.host_path) != nullptr ||
                                lt.has_aliases(pc.host_path)))
                return unlink_with_links(pc.host_path);
        }
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
        if (wi == Wi::parents_only) {
            o.make_parents = !strict_parent;
            const Sysno sc = decode(arch_, r.nr);
            o.created = abs;
            o.created_dir = sc == Sysno::mkdir || sc == Sysno::mkdirat;
        }
        return o;
    }

    // May the caller add or remove the name `guest` in its parent directory?
    [[nodiscard]] Errno dir_entry_allowed(const std::string& guest, bool removing) {
        const std::size_t cut = guest.rfind('/');
        const std::string parent = cut == 0 ? std::string{"/"} : guest.substr(0, cut);
        if (!guest_may(parent, 3)) return Errno::eacces;
        if (!removing) return Errno::ok;
        // the sticky bit: only the file's owner or the dir's owner (or
        // CAP_FOWNER) may remove or rename a name in it
        const auto pc = k_.files().classify(parent);
        struct ::stat st{};
        std::uint32_t mode = 0;
        if (auto rec = k_.files().meta().lookup(parent); rec && (rec->have & kernel::MetaRecord::kMode))
            mode = rec->mode;
        else if (pc.realm == kernel::Realm2::host_backed && ::stat(pc.host_path.c_str(), &st) == 0)
            mode = st.st_mode;
        if (!(mode & 01000u) || creds::capable(me(), creds::kCapFowner)) return Errno::ok;
        const std::uint32_t fsuid = me().uids[3];
        if (owner_of(guest).first == fsuid || owner_of(parent).first == fsuid) return Errno::ok;
        return Errno::eperm;
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
    [[nodiscard]] Outcome do_chmod(const Regs& r, int path_arg, bool at, Wi /*wi*/,
                                   bool with_flags = false) {
        // Only fchmodat2 has a flags argument. fchmodat has three arguments,
        // so reading a fourth register for it read whatever was left there.
        const std::uint64_t flags =
            with_flags ? r.arg[static_cast<std::size_t>(path_arg) + 2] : 0;
        std::uint32_t mode = static_cast<std::uint32_t>(
            r.arg[static_cast<std::size_t>(path_arg) + 1]);
        std::string abs;
        if (with_flags && empty_cstr_arg(r, path_arg) &&
            wire::has_at(flags, wire::AtFlag::empty_path)) {
            // fchmodat2(fd, "", mode, AT_EMPTY_PATH): chmod the file the fd
            // refers to. systemd copies a file's permissions onto its
            // replacement this way, and treating "" as a missing path made
            // every systemd-sysusers run abort: "Failed to copy permissions
            // from /etc/group", and no user or group was ever created.
            const int fd = static_cast<int>(r.arg[0]);
            std::string_view gp = k_.files().path_of_fd(fd);
            if (gp.empty()) {
                // No guest path to record the mode against: set it on the
                // host inode the fd refers to, which is all we can know.
                const int sfd = open_tracee_fd(fd);
                if (sfd < 0) return eno(Errno::ebadf);
                const int rc = ::fchmod(sfd, mode & wire::kPermMask);
                const int e = errno;
                ::close(sfd);
                return rc == 0 ? val(0) : eno(static_cast<Errno>(e));
            }
            abs = std::string{gp};
            // An O_PATH fd can name a symlink itself, and a symlink has no
            // mode of its own: EOPNOTSUPP, as for AT_SYMLINK_NOFOLLOW below.
            if (fd_is_o_path(fd)) {
                auto lc = k_.files().classify(abs, false, /*follow=*/false);
                if (lc.realm == kernel::Realm2::host_backed &&
                    host_path_is_symlink(lc.host_path))
                    return eno(Errno::enotsup);
            }
        } else {
            if (empty_path_arg(r, path_arg)) return eno(Errno::enoent);
            // A "."/".." component does not excuse the components before it.
            if (const Errno e = dot_prefix_error(r, path_arg, at); e != Errno::ok)
                return eno(e);
            abs = resolve_arg(r, path_arg, at);
            // AT_SYMLINK_NOFOLLOW on a SYMLINK is EOPNOTSUPP. Linux has no
            // lchmod: a symlink's own mode is fixed at 0777 and the kernel
            // ignores it, so the request is refused outright rather than applied
            // to the target. libarchive asks for exactly this on every symlink a
            // package ships, and treats EOPNOTSUPP as "fine, nothing to do" --
            // reporting success instead made it complain "Can't set permissions
            // to 0777" for every .so link in the archive.
            if (wire::has_at(flags, wire::AtFlag::symlink_nofollow)) {
                auto lc = k_.files().classify(abs, /*for_write=*/false,
                                              /*follow=*/false);
                if (lc.realm == kernel::Realm2::host_backed &&
                    host_path_is_symlink(lc.host_path))
                    return eno(Errno::enotsup);
            }
        }
        // chmod FOLLOWS a final symlink -- there is no lchmod -- so a
        // DANGLING link is ENOENT. classify() maps a path without proving
        // its target exists, and the lstat-based probe sees the link itself,
        // so chmod through a dangling link reported success where the kernel
        // says ENOENT. Same bug its sibling do_chown already fixed, and the
        // same ::access test fixes it.
        auto pc = k_.files().classify(abs, /*for_write=*/false, /*follow=*/true);
        if (pc.realm == kernel::Realm2::virtual_file)
            // Even comm, which accepts writes, refuses a mode change: procfs
            // inodes have no setattr for the mode.
            return eno(virtual_mut_errno(abs, VMut::meta));
        if (pc.realm == kernel::Realm2::absent)
            // classify collapses several lookup failures to ENOENT. When the
            // host can still be asked (the path maps somewhere), let IT name
            // the reason -- a symlink loop in a prefix is ELOOP, not absent.
            return eno(pc.error == Errno::enoent
                           ? resolve_failure_errno(abs, pc.error)
                           : pc.error);
        // A regular file used as a directory component is ENOTDIR, and that
        // outranks the dangling-link ENOENT below -- checking existence
        // first turned `chmod f1/bad` (f1 a file) into ENOENT.
        if (!parent_is_dir(pc.host_path)) return eno(Errno::enotdir);
        if (Errno why = Errno::ok; !host_target_exists(pc.host_path, &why))
            return eno(why);
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
        // chmod follows the final link, so the mode belongs to the target.
        // Recording it under the link's name meant stat of the target never
        // saw it.
        const std::string target = k_.files().resolve_links(abs);
        if (!creds_may_chown_or_chmod(target)) return eno(Errno::eperm);
        std::uint32_t landed = 0xffffffffu;
        {
            auto wc = k_.files().classify(target, /*for_write=*/true,
                                          /*follow=*/false, Wi::copy_leaf);
            // Skip a symlink: chmod on a symlink either follows it (wrong
            // target) or, with AT_SYMLINK_NOFOLLOW as libarchive passes,
            // returns EOPNOTSUPP on Linux -> "Can't set permissions to 0777"
            // when a package ships a .so symlink. A symlink's own mode is
            // fixed at 0777 and ignored by the kernel, so there is nothing to
            // apply; the shadow store still presents the intended mode at stat
            // time. Only chmod a REGULAR file/dir we own in the upper.
            if (!wc.host_path.empty() && !is_symlink(wc.host_path.c_str())) {
                // The guest runs as root, and root writes files whose mode
                // says nobody may; linuxity, an ordinary host user, cannot.
                // So a regular file's host inode keeps owner read/write
                // whatever the guest asked for, and the shadow store reports
                // the exact guest mode. Applying 0444 literally left a file
                // linuxity itself could no longer open for writing, so guest
                // root got EACCES writing its own read-only file.
                //
                // Regular files only. A directory's mode goes on literally,
                // because its search bit is a lookup rule the guest relies
                // on: chmod 0644 on a directory must make it unsearchable
                // (conform_diff pins `mkdir dir/.` as EACCES there), and a
                // floor of 0700 had quietly kept it searchable.
                const std::uint32_t keep =
                    host_path_is_regular(wc.host_path) ? 0600u : 0u;
                errno = 0;
                if (::chmod(wc.host_path.c_str(), static_cast<mode_t>((mode & wire::kPermMask) | keep)) == 0) {
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
        // A setgid bit only survives when the caller is in the file's group
        // (or has CAP_FSETID), as in the kernel's chmod.
        if ((mode & 02000u) && !creds::capable(me(), creds::kCapFsetid) &&
            !in_group(owner_of(target).second))
            mode &= ~02000u;
        k_.files().meta().set_mode(target, mode, landed);
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
        // An O_PATH descriptor names a file without opening it, and fchmod
        // on one is EBADF -- the fd has no access mode to act through. That
        // is not a corner case: glibc implements
        // fchmodat(AT_SYMLINK_NOFOLLOW) as open(O_PATH|O_NOFOLLOW) + fchmod,
        // so this is the path libarchive takes for every symlink a package
        // ships. Answering 0 made it believe it had chmod'ed the link and
        // then complain "Can't set permissions to 0777" when the mode did
        // not stick; worse, the chmod below followed the link and
        // re-permissioned its TARGET.
        if (fd_is_o_path(static_cast<int>(r.arg[0])))
            return eno(Errno::ebadf);
        // A symlink has no mode of its own (Linux has no lchmod), so a
        // chmod that reached one without following it is EOPNOTSUPP.
        if (!gp.empty()) {
            auto lc = k_.files().classify(std::string{gp}, /*for_write=*/false,
                                          /*follow=*/false);
            if (lc.realm == kernel::Realm2::host_backed &&
                host_path_is_symlink(lc.host_path))
                return eno(Errno::enotsup);
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
        // fchownat(fd, "", ..., AT_EMPTY_PATH) means the dirfd itself, which
        // is fchown. Resolve through the fd's bound path so the shadow store
        // records it against the right file.
        if (at && empty_cstr_arg(r, path_arg) &&
            wire::has_at(r.arg[4], wire::AtFlag::empty_path)) {
            std::string_view gp =
                k_.files().path_of_fd(static_cast<int>(r.arg[0]));
            if (gp.empty()) return fwd();
            k_.files().meta().set_owner(
                std::string{gp},
                static_cast<std::uint32_t>(r.arg[static_cast<std::size_t>(uid_arg)]),
                static_cast<std::uint32_t>(r.arg[static_cast<std::size_t>(gid_arg)]));
            return val(0);
        }
        if (empty_path_arg(r, path_arg)) return eno(Errno::enoent);
        std::string abs = resolve_arg(r, path_arg, at);
        auto pc = k_.files().classify(abs, /*for_write=*/false, follow);
        if (pc.realm == kernel::Realm2::virtual_file) {
            if (virtual_is_writable(abs)) return val(0);
            return eno(virtual_mut_errno(abs, VMut::meta));
        }
        if (pc.realm == kernel::Realm2::absent)       return eno(pc.error);
        // classify() MAPS a path, it does not test for existence: a plain
        // host mount returns host_backed for a name that is not there, since
        // the host path is still computable. Ownership is recorded in our own
        // metadata rather than on the inode, so without this check chown on a
        // missing file quietly returned 0 where the kernel says ENOENT --
        // caught by the legacy probe diffing against the live kernel.
        //
        // A regular file used as a directory component is ENOTDIR, and the
        // kernel reports that before any existence check -- the lstat below
        // just fails, which would answer ENOENT.
        if (!parent_is_dir(pc.host_path)) return eno(Errno::enotdir);
        // stat_host_path is an LSTAT, which is right for lchown but would
        // call a dangling link "present" for chown. When following, the
        // target is what must exist.
        if constexpr (requires { mem_.stat_host_path(pc.host_path); }) {
            if (!mem_.stat_host_path(pc.host_path)) {
                // An lstat that fails because a directory above denies search
                // is EACCES, not a missing name.
                Errno why = Errno::ok;
                (void)host_target_exists(pc.host_path, &why);
                return eno(why == Errno::ok ? Errno::enoent : why);
            }
            if (Errno why = Errno::ok;
                follow && !host_target_exists(pc.host_path, &why))
                return eno(why);
        }
        const std::string target = follow ? k_.files().resolve_links(abs) : abs;
        const std::uint32_t nu = static_cast<std::uint32_t>(r.arg[static_cast<std::size_t>(uid_arg)]);
        const std::uint32_t ng = static_cast<std::uint32_t>(r.arg[static_cast<std::size_t>(gid_arg)]);
        if (Errno e = chown_allowed(target, nu, ng); e != Errno::ok) return eno(e);
        k_.files().meta().set_owner(target, nu, ng);
        // A chown by someone without CAP_FSETID drops set-user-ID, and
        // set-group-ID when group exec is set. Root keeps them, which is how
        // a package install leaves sudo setuid.
        if (auto rec = k_.files().meta().lookup(target);
            !creds::capable(me(), creds::kCapFsetid) && (nu != creds::kKeep || ng != creds::kKeep) &&
            rec && (rec->have & kernel::MetaRecord::kMode)) {
            std::uint32_t m = rec->mode;
            m &= ~04000u;
            if (m & 010u) m &= ~02000u;
            if (m != rec->mode) k_.files().meta().set_mode(target, m);
        }
        return val(0);
    }

    // chown(2)'s rules: changing the owner needs CAP_CHOWN; changing only
    // the group needs ownership and membership of the new group.
    [[nodiscard]] Errno chown_allowed(const std::string& guest, std::uint32_t uid, std::uint32_t gid) {
        if (creds::capable(me(), creds::kCapChown)) return Errno::ok;
        const auto [ou, og] = owner_of(guest);
        if (uid != creds::kKeep && uid != ou) return Errno::eperm;
        if (gid != creds::kKeep && gid != og) {
            if (ou != me().uids[3] || !in_group(gid)) return Errno::eperm;
        }
        return Errno::ok;
    }

    // Does the TARGET of this path exist, with symlinks followed? ::access
    // with F_OK is the cheapest way to ask, and unlike the lstat-based fast
    // path it reports a dangling link as absent.
    //
    // `why` distinguishes the two reasons it can answer no: a name that
    // is not there (ENOENT) versus one hidden behind a directory that denies
    // search (EACCES). Collapsing them made chmod in an unsearchable
    // directory report ENOENT.
    [[nodiscard]] static bool host_target_exists(const std::string& p,
                                                 Errno* why = nullptr) {
        if (p.empty()) {
            if (why != nullptr) *why = Errno::enoent;
            return false;
        }
        if (::access(p.c_str(), F_OK) == 0) return true;
        if (why != nullptr) *why = access_errno();
        return false;
    }

    // Map the errno a failed ::access/::stat left behind onto the answer the
    // kernel would give. Three distinct reasons a lookup can fail to see a
    // file, and collapsing them to ENOENT was wrong for all but one: a
    // directory above denying search is EACCES, and a symlink loop is ELOOP.
    [[nodiscard]] static Errno access_errno() noexcept {
        switch (errno) {
        case EACCES:  return Errno::eacces;
        case ELOOP:   return Errno::eloop;
        case ENOTDIR: return Errno::enotdir;
        case ENAMETOOLONG: return Errno::enametoolong;
        default:      return Errno::enoent;
        }
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
                                    bool /*at2*/, bool move_meta = false,
                                    int link_flags_arg = -1,
                                    int rename_flags_arg = -1) {
        // A link whose SOURCE is an open fd rather than a name:
        //   linkat(fd, "", ..., AT_EMPTY_PATH)
        //   linkat(AT_FDCWD, "/proc/self/fd/N", ..., AT_SYMLINK_FOLLOW)
        // Both are how a program gives an O_TMPFILE its name (the second is
        // the unprivileged form, and what python's os.link does by default).
        // /proc/self/fd/N is a magic link to the open file itself, not a
        // file in procfs -- treating it as a procfs path made the link cross
        // mounts and answered EXDEV.
        if (link_flags_arg >= 0) {
            const std::uint64_t lf = r.arg[static_cast<std::size_t>(link_flags_arg)];
            int link_fd = -1;
            if (empty_cstr_arg(r, a1) && wire::has_at(lf, wire::AtFlag::empty_path))
                link_fd = static_cast<int>(r.arg[0]);
            else if (wire::has_at(lf, wire::AtFlag::symlink_follow))
                link_fd = magic_fd_of(resolve_arg(r, a1, at));
            if (link_fd >= 0) return link_from_fd(r, link_fd, a2, at);
        }
        // BOTH operands. Checking only the source left symlinkat(x, "") and
        // renameat(x, "") absolutizing the empty destination to the cwd and
        // acting on the directory -- EEXIST where the kernel says ENOENT.
        // An AT_EMPTY_PATH source never gets here: link_from_fd took it.
        if (empty_path_arg(r, a1) || empty_path_arg(r, a2))
            return eno(Errno::enoent);
        std::string src = resolve_arg(r, a1, at);
        std::string dst = resolve_second(r, a2, at);
        // rename acts on NAMES: an emulated hardlink alias must move as a
        // name (its placeholder), not drag the shared file behind it along.
        // link's source is the opposite -- the new name joins the inode the
        // source NAMES, so it is alias-resolved.
        auto ps = move_meta ? k_.files().classify_name(src, true, false, Wi::copy_leaf)
                            : k_.files().classify(src, true, false, Wi::copy_leaf);
        auto pd = move_meta ? k_.files().classify_name(dst, true, false, Wi::parents_only)
                            : k_.files().classify(dst, true, false, Wi::parents_only);
        // Traversal comes first: if the kernel cannot search its way to the
        // name, EACCES is the answer and none of the slash/dot reasoning
        // below is ever reached.
        //
        // dot_prefix_error walks the COMPONENTS before a dot, which is what
        // catches an unsearchable directory in the middle of the path --
        // `link sub/../f1 d/` with sub at 0644 is EACCES, and testing only
        // the leaf's own parent answered EEXIST. The other path handlers all
        // go through the same walker.
        //
        // And strictly SOURCE-then-DESTINATION: the kernel resolves the first
        // operand completely before it looks at the second, so a cycle in the
        // source's prefix is reported even when the destination's directory
        // is unsearchable. Interleaving the two let the destination's EACCES
        // mask it.
        if (const Errno e1 = dot_prefix_error(r, a1, at); e1 != Errno::ok)
            return eno(e1);
        if (const Errno e = guest_prefix_loop(src); e != Errno::ok)
            return eno(e);
        // A LINK whose source is not there never walks the destination at
        // all: link only READS the source, so the lookup ends on that ENOENT.
        // rename must write BOTH ends, so its destination errors do surface.
        // Measured both ways. Deliberately narrow -- it suppresses only the
        // destination's EACCES paths, because procfs and whiteouts have their
        // own notion of "absent source" that a host lstat cannot see.
        const bool link_src_gone =
            !move_meta && !ps.host_path.empty() &&
            ps.realm == kernel::Realm2::host_backed &&
            !host_lexists(ps.host_path);
        if (!link_src_gone)
            if (const Errno e2 = dot_prefix_error(r, a2, at); e2 != Errno::ok)
                return eno(e2);
        {
            const std::string raw1 =
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(a1)]));
            const std::string raw2 =
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(a2)]));
            // The SOURCE is resolved before the destination is touched at
            // all, so every failure on its path is reported first. Checking
            // both operands together made the destination's unsearchable
            // directory mask a symlink cycle in the source's prefix.
            if (dot_traversal_denied(raw1, ps.host_path))
                return eno(Errno::eacces);
            if (!host_dir_searchable(ps.host_path))
                return eno(Errno::eacces);
            // Now the destination, same exemption as above.
            if (!link_src_gone) {
                if (dot_traversal_denied(raw2, pd.host_path))
                    return eno(Errno::eacces);
                if (!host_dir_searchable(pd.host_path))
                    return eno(Errno::eacces);
            }
            // A symlink cycle the walk must pass THROUGH is ELOOP. Both
            // classify calls above use follow=false (link and rename act on
            // the NAME), which is exactly what skips the cycle detector, and
            // the host cannot stand in for it: the overlay upper stores
            // GUEST-absolute link targets, so a host ::access reads a cycle
            // as a dangling link. Ask the namespace.
            //
            // The LEAF is exempt -- renaming a self-link is legal, verified
            // against the kernel -- and a MISSING SOURCE outranks a cycle in
            // the destination.
            if (host_lexists(ps.host_path))
                if (const Errno e = guest_prefix_loop(dst); e != Errno::ok)
                    return eno(e);
        }
        // A rename cannot name "." or ".." on either side -- they are not
        // entries you can move, and the kernel reports EBUSY. But it resolves
        // BOTH paths first, so a structurally bad path wins: rename(".",
        // "f1/bad") is ENOTDIR because f1 is a file being used as a
        // directory, not EBUSY. classify() maps for creation and never stats
        // the prefix, so ask the host whether each parent is really a
        // directory before refusing on the dot.
        if (move_meta) {
            const std::string raw1 =
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(a1)]));
            const std::string raw2 =
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(a2)]));
            if (dot_tail(raw1) != DotTail::none ||
                dot_tail(raw2) != DotTail::none) {
                // The PREFIX is walked before the dot is refused: a missing
                // component is ENOENT and a file used as one is ENOTDIR.
                // (A missing LEAF is not -- rename("gone", "d/.") is still
                // EBUSY, because the dot is rejected before the leaf is
                // looked up. Hence parent_resolves, not host_lexists.)
                if (!parent_is_dir(ps.host_path) || !parent_is_dir(pd.host_path))
                    return eno(Errno::enotdir);
                if (Errno why = Errno::ok; !parent_resolves(ps.host_path, &why))
                    return eno(why);
                if (Errno why = Errno::ok; !parent_resolves(pd.host_path, &why))
                    return eno(why);
                return eno(Errno::ebusy);
            }
        }
        // A TRAILING SLASH asserts "this name is a directory". For rename
        // that is checked against BOTH operands before the move: renaming a
        // regular file to "new/" is ENOTDIR, and so is renaming "f1/" to
        // anything. Normalizing the slash away let a file be created under a
        // name the caller had explicitly marked as a directory.
        if (move_meta) {
            const std::string raw1 =
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(a1)]));
            const std::string raw2 =
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(a2)]));
            const bool slash1 = path_syntax(raw1) == PathSyntax::needs_dir;
            const bool slash2 = path_syntax(raw2) == PathSyntax::needs_dir;
            Errno src_why = Errno::ok;
            if (slash1 || slash2) {
                // The SOURCE is judged first: a missing one is ENOENT and a
                // file used as its directory component is ENOTDIR, both
                // ahead of anything about the destination. Checking the
                // ancestor rule first answered ENOTEMPTY for all of them.
                //
                // LSTAT, not access: rename moves the LINK, so a dangling
                // symlink source is perfectly renameable. Following it
                // reported ENOENT for a name that is plainly there.
                if (!parent_is_dir(ps.host_path)) return eno(Errno::enotdir);
                if (!host_lexists(ps.host_path, &src_why))
                    return eno(src_why);
                // ...then a destination that is an ANCESTOR of the source:
                // the move would absorb a directory containing itself, which
                // the kernel reports as ENOTEMPTY. Any other existing-
                // directory destination just fails the slash assertion.
                if (host_path_is_dir(pd.host_path) &&
                    path_is_ancestor(pd.host_path, ps.host_path))
                    return eno(Errno::enotempty);
                if (!host_path_is_dir_nofollow(ps.host_path))
                    return eno(Errno::enotdir);
            }
        } else {
            // A hardlink is never a directory, so a trailing slash can never
            // be satisfied -- but it is the LAST thing the kernel concludes.
            // Against the live kernel, strictly in this order:
            //   source missing                    -> ENOENT
            //   source has a slash, is no dir      -> ENOTDIR
            //   destination already exists         -> EEXIST
            //   destination's parent unsearchable  -> EACCES
            //   destination's parent is a file     -> ENOTDIR
            //   source is a directory              -> EPERM (no dir links)
            //   nothing else to say                -> ENOENT
            const std::string raw1 =
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(a1)]));
            const std::string raw2 =
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(a2)]));
            const bool slash1 = path_syntax(raw1) == PathSyntax::needs_dir;
            const bool slash2 = path_syntax(raw2) == PathSyntax::needs_dir;
            if (slash1 || slash2) {
                // LSTAT throughout: link acts on the NAME, so a dangling
                // symlink is both a valid source and an occupied destination.
                if (Errno why = Errno::ok;
                    !host_lexists(ps.host_path, &why))
                    return eno(why);
                if (slash1 && !host_path_is_dir_nofollow(ps.host_path))
                    return eno(Errno::enotdir);
                // LSTAT: a DANGLING symlink still occupies the name, so
                // linking onto it is EEXIST. Following it reported ENOENT and
                // then fell through to the no-directory-links EPERM.
                if (host_lexists(pd.host_path)) return eno(Errno::eexist);
                // Unsearchable comes before "does not resolve": an F_OK probe
                // fails for both reasons, and the permission is what the
                // kernel hits first.
                if (!host_dir_searchable(pd.host_path))
                    return eno(Errno::eacces);
                if (Errno why = Errno::ok;
                    !parent_resolves(pd.host_path, &why))
                    return eno(why);
                if (!parent_is_dir(pd.host_path)) return eno(Errno::enotdir);
                // A trailing slash on the DESTINATION asserts a directory
                // that is not there, and that ENOENT comes before the
                // no-directory-links EPERM -- which only applies when the
                // caller named the destination without a slash.
                if (slash2) return eno(Errno::enoent);
                if (host_path_is_dir(ps.host_path)) return eno(Errno::eperm);
                return eno(Errno::enoent);
            }
        }
        bool sv = k_.files().under_virtual_mount(src);
        bool dv = k_.files().under_virtual_mount(dst);
        // Crossing between a synthesized path and a real one is a genuine
        // cross-mount move, which rename/link report as EXDEV.
        if (sv != dv) return eno(Errno::exdev);
        // Both ends under a virtual mount -- but "virtual" is about who
        // ANSWERS the path, not whether anything is behind it. /dev/shm is
        // served by devfs and yet redirects to real storage, so a link there
        // is an ordinary link between two real files and must be allowed.
        // Treating every virtual mount as procfs returned ENOENT for it,
        // which is where glibc's sem_open died -- and with it every
        // multiprocessing.Lock, Queue and ProcessPoolExecutor.
        const bool both_real = ps.realm == kernel::Realm2::host_backed &&
                               !ps.host_path.empty() &&
                               !pd.host_path.empty();
        if (sv && !both_real) {
            // Both ends inside procfs. An absent source is ENOENT before
            // anything else is considered.
            if (ps.realm == kernel::Realm2::absent) return eno(Errno::enoent);
            // link checks the destination name first, so a taken name is
            // EEXIST; rename replaces instead, so it reaches the missing
            // rename inode op and reports EPERM. (move_meta marks rename.)
            if (pd.realm == kernel::Realm2::virtual_file)
                return eno(move_meta ? Errno::eperm : Errno::eexist);
            // Destination name does not exist and cannot be created here.
            return eno(Errno::enoent);
        }
        if (ps.host_path.empty() || pd.host_path.empty())
            return eno(ps.host_path.empty() ? ps.error : pd.error);
        // rename carries the shadow metadata with the file (a hardlink/link
        // does NOT: both names share the inode, so the original keeps its own
        // record). Do the in-store move BEFORE the redirect returns.
        if (move_meta) k_.files().meta().rename(src, dst);
        // Both operands are guest paths, so both get translated.
        //
        // NO .parents(): the chain is pre-created to MIRROR a lower-layer
        // directory into the upper, never to conjure one. Asking for it here
        // meant `rename f1 absent/x` created absent/ and MOVED THE FILE
        // there, and link did the same -- both ENOENT on the kernel. The
        // destination's own parent must already exist; let the host say so.
        //
        // A HARDLINK the host refuses gets EMULATED.
        //
        // Android denies the SELinux `link` permission on /data for every
        // process -- verified natively, `ln a b` fails there outside
        // linuxity too -- so forwarding can never work. Not handling it is
        // not cosmetic: the gcc package ships /usr/bin/gcc, g++, cc and five
        // more as hardlink entries, so without it there is no compiler.
        //
        // The new name becomes an ALIAS of the existing file (see
        // link_table.hpp): a placeholder on disk, with every open and stat
        // of it resolved to the file the source names. Both names share one
        // inode, so a write through either is seen through the other.
        // Copying the content instead -- the first version -- gave two
        // independent files that drifted apart on the first write. ps was
        // classified with alias resolution, so linking an alias joins the
        // same inode rather than aliasing a placeholder.
        if (!move_meta && !host_links_work(pd.host_path)) {
            struct ::stat sst{};
            if (::lstat(ps.host_path.c_str(), &sst) != 0)
                return eno(static_cast<Errno>(errno));
            if (S_ISDIR(sst.st_mode)) return eno(Errno::eperm);
            const int fd = ::open(pd.host_path.c_str(),
                                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (fd < 0) return eno(static_cast<Errno>(errno));
            ::close(fd);
            k_.files().links().add(pd.host_path, ps.host_path);
            note_linked(src, dst);
            return val(0);
        }
        // A rename that moves, replaces or carries a name the link table
        // knows (an alias, a file with aliases, or a directory holding
        // either) must keep the table in step. Do it here, synchronously, so
        // the table is only updated if the host rename really happened.
        if (move_meta && !k_.files().links().empty() &&
            (k_.files().links().touches(ps.host_path) ||
             k_.files().links().touches(pd.host_path)))
            return rename_with_links(r, ps.host_path, pd.host_path,
                                     rename_flags_arg);
        Redirect rd{PathArg{a1, std::move(ps.host_path)}};
        rd.second = PathArg{a2, std::move(pd.host_path)};
        // a rename (not a link): tell note_moved what moved where
        if (link_flags_arg < 0) rd.moved = std::pair{src, dst};
        else rd.linked = std::pair{src, dst};
        return rd;
    }

    // unlink of a name the link table knows.
    [[nodiscard]] Outcome unlink_with_links(const std::string& name) {
        auto& lt = k_.files().links();
        if (lt.backing_of(name) != nullptr) {          // an alias: drop the name
            if (::unlink(name.c_str()) != 0) return eno(static_cast<Errno>(errno));
            lt.drop(name);
            return val(0);
        }
        // The backing itself. Moving it onto an heir replaces the heir's
        // placeholder and removes `name` in one atomic rename.
        if (auto heir = lt.promote(name)) {
            if (::rename(name.c_str(), heir->c_str()) != 0)
                return eno(static_cast<Errno>(errno));
            return val(0);
        }
        if (::unlink(name.c_str()) != 0) return eno(static_cast<Errno>(errno));
        return val(0);
    }

    // The fd number if `p` is this process's /proc/self/fd/N magic link,
    // else -1. Only the caller's own fds: /proc/<other>/fd/N names another
    // process's descriptor, which linuxity cannot reach from here.
    [[nodiscard]] int magic_fd_of(const std::string& p) {
        const std::string own = "/proc/" + std::to_string(ids().pid) + "/fd/";
        std::string_view s{p};
        bool matched = false;
        for (std::string_view pre : {std::string_view{"/proc/self/fd/"},
                                     std::string_view{"/proc/thread-self/fd/"},
                                     std::string_view{own}})
            if (s.starts_with(pre)) { s.remove_prefix(pre.size()); matched = true; break; }
        if (!matched || s.empty() || s.size() > 9 ||
            s.find_first_not_of("0123456789") != std::string_view::npos)
            return -1;
        return std::atoi(std::string{s}.c_str());
    }

    // linkat with an open fd as the source: give that file a new name.
    //
    // Where the host allows link(2), link the fd's own inode through the
    // supervisor's /proc/self/fd -- the unprivileged form, which works for an
    // O_TMPFILE too. Where it does not (Android), a named file becomes an
    // alias like any other hardlink. An O_TMPFILE has no name to alias, so it
    // is copied: the new name gets the data written so far.
    [[nodiscard]] Outcome link_from_fd(const Regs& r, int fd, int a2, bool at) {
        if (empty_path_arg(r, a2)) return eno(Errno::enoent);
        const std::string dst = resolve_second(r, a2, at);
        auto pd = k_.files().classify(dst, true, false, Wi::parents_only);
        if (pd.realm != kernel::Realm2::host_backed || pd.host_path.empty())
            return eno(Errno::exdev);
        const int sfd = open_tracee_fd(fd);
        if (sfd < 0) return eno(Errno::ebadf);
        struct Closer { int f; ~Closer() { ::close(f); } } closer{sfd};
        struct ::stat st{};
        if (::fstat(sfd, &st) != 0) return eno(static_cast<Errno>(errno));
        if (S_ISDIR(st.st_mode)) return eno(Errno::eperm);
        struct ::stat dt{};
        if (::lstat(pd.host_path.c_str(), &dt) == 0) return eno(Errno::eexist);
        if (host_links_work(pd.host_path)) {
            const int e = host::link_fd(sfd, pd.host_path);
            if (e == 0) return val(0);
            // an unnamed file the host can't link (no /proc/self/fd): copy
            if (!(e == ENOENT && st.st_nlink == 0)) return eno(wire::errno_from_host(e));
        }
        if (st.st_nlink == 0) {                           // O_TMPFILE: no name
            const Errno e = k_.files().emulate_link_from_fd(sfd, pd.host_path);
            return e == Errno::ok ? val(0) : eno(e);
        }
        // A named file: alias whatever host path the fd really refers to.
        const std::string tgt = host::fd_path(sfd);
        if (tgt.empty()) return eno(Errno::enoent);
        const int out = ::open(pd.host_path.c_str(),
                               O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (out < 0) return eno(static_cast<Errno>(errno));
        ::close(out);
        auto& lt = k_.files().links();
        lt.add(pd.host_path, lt.resolve(tgt));
        return val(0);
    }

    // rename(2) when the link table is involved. `from`/`to` are NAMES (not
    // alias-resolved). Replacing a name that the table knows has to keep its
    // inode's other names alive, exactly as the kernel keeps an inode alive
    // while any link to it remains.
    [[nodiscard]] Outcome rename_with_links(const Regs& r, const std::string& from,
                                            const std::string& to,
                                            int flags_arg) {
        constexpr unsigned kNoReplace = 1, kExchange = 2;
        const unsigned flags =
            flags_arg >= 0 ? static_cast<unsigned>(
                                 r.arg[static_cast<std::size_t>(flags_arg)])
                           : 0u;
        auto& lt = k_.files().links();
        struct ::stat st{}, fs{};
        if (::lstat(from.c_str(), &fs) != 0) return eno(static_cast<Errno>(errno));
        const bool to_exists = ::lstat(to.c_str(), &st) == 0;
        if ((flags & kNoReplace) != 0 && to_exists) return eno(Errno::eexist);
        // Two names for the same file: Linux renames nothing and succeeds,
        // leaving both names in place.
        if (to_exists && (flags & kExchange) == 0 && lt.resolve(from) == lt.resolve(to))
            return val(0);
        std::optional<std::string> heir;
        if ((flags & kExchange) == 0 && to_exists && to != from) {
            // Every name the table knows is a non-directory, so the one way
            // replacing it can fail on type is a directory source. Check
            // BEFORE moving anything: once the destination's data has been
            // moved onto an heir, the name is free and the kernel would let
            // a directory take it -- rename(dir, file) answered 0, not
            // ENOTDIR.
            if (S_ISDIR(fs.st_mode) && !S_ISDIR(st.st_mode))
                return eno(Errno::enotdir);
            if (lt.backing_of(to) == nullptr) {
                // `to` holds data other names still share: move it onto one
                // of them before the rename overwrites it.
                heir = lt.promote(to);
                if (heir && ::rename(to.c_str(), heir->c_str()) != 0) {
                    const int e = errno;
                    lt.rename_prefix(*heir, to);
                    lt.add(*heir, to);
                    return eno(static_cast<Errno>(e));
                }
            }
        }
        // flags==0 is a plain rename. NOREPLACE was checked above; EXCHANGE
        // needs the real call, which only Linux has (and only Linux-family
        // hosts refuse link(2), the one way into this table).
        int rc = -1;
        if (flags == 0) {
            rc = ::rename(from.c_str(), to.c_str());
        } else {
#if defined(__linux__)
            rc = ::renameat2(AT_FDCWD, from.c_str(), AT_FDCWD, to.c_str(), flags);
#else
            errno = EINVAL;
#endif
        }
        if (rc != 0) {
            const int e = errno;
            // Put the destination's data back where it was: the rename that
            // was going to replace it did not happen.
            if (heir) {
                (void)::rename(heir->c_str(), to.c_str());
                const int ph = ::open(heir->c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
                if (ph >= 0) ::close(ph);
                lt.rename_prefix(*heir, to);
                lt.add(*heir, to);
            }
            return eno(static_cast<Errno>(e));
        }
        // An alias that was REPLACED is gone now; only drop it from the
        // table once the replacement really happened.
        if ((flags & kExchange) == 0 && to_exists && lt.backing_of(to) != nullptr)
            lt.drop(to);
        if ((flags & kExchange) != 0) {
            const std::string mark = from + "\x01lx-swap";
            lt.rename_prefix(from, mark);
            lt.rename_prefix(to, from);
            lt.rename_prefix(mark, to);
        } else {
            lt.rename_prefix(from, to);
        }
        return val(0);
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
    [[nodiscard]] static std::string inode_key(const struct ::stat& st) {
        return "ino:" + std::to_string(static_cast<std::uint64_t>(st.st_dev)) + ":" +
               std::to_string(static_cast<std::uint64_t>(st.st_ino));
    }

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
        if (guest_path.empty()) return fwd();
        const std::string raw_guest_path = guest_path;   // getsockname reports this spelling
        // A relative sun_path resolves against the caller's cwd. Ours is
        // virtual, so the host's cwd is somewhere else entirely: forwarding
        // it raw put the socket in whatever dir linuxity was started from.
        if (guest_path.front() != '/')
            guest_path = k_.files().absolutize(guest_path, k_.files().cwd());

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

        // A name that already exists is the kernel's EADDRINUSE, socket or
        // not. (This used to unlink it first, so a second bind silently
        // stole the first one's name.)
        if (for_bind && guest_exists(guest_path)) return eno(Errno::eaddrinuse);

        // Where this host lets us put a socket. On Android no directory an
        // app can write permits an AF_UNIX bind (SELinux), so a filesystem
        // translation would be correct and still fail with EACCES; the
        // abstract namespace is the only one available. Bind and connect both
        // derive the name from the placeholder's inode, so the peers meet.
        if (k_.files().socket_ns() == kernel::SocketNs::abstract) {
            // The name follows the placeholder file's inode, like a real
            // socket node: unlink frees it, rename and link keep it.
            std::string key = guest_path;
            // A BIND also has to leave the NAME behind. The socket itself
            // lives in the abstract namespace, where nothing is on disk --
            // but a guest that binds a path expects to find it there
            // afterwards, and the next thing it does is usually chmod or
            // stat it. python's multiprocessing forkserver does exactly
            // that (os.chmod(address, 0o600) right after bind) and died
            // with ENOENT on a socket that had bound successfully.
            //
            // So drop a real, empty file at the translated path. It is not
            // the socket, it is the name, and its inode picks the abstract
            // address connect looks up.
            if (for_bind) {
                auto pc = k_.files().classify(guest_path, /*for_write=*/true,
                                              /*follow=*/false,
                                              Wi::parents_only);
                if (pc.realm == kernel::Realm2::host_backed &&
                    !pc.host_path.empty()) {
                    const int fd = ::open(pc.host_path.c_str(),
                                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                    if (fd < 0)
                        return eno(errno == EEXIST ? Errno::eaddrinuse
                                                   : wire::errno_from_host(errno));
                    struct ::stat st{};
                    if (::fstat(fd, &st) == 0) key = inode_key(st);
                    ::close(fd);
                    // stat should see a socket, as on Linux
                    sock_placeholders_.insert(guest_path);
                }
            } else {
                auto pc = k_.files().classify(guest_path, /*for_write=*/false,
                                              /*follow=*/true, Wi::copy_leaf);
                if (pc.realm == kernel::Realm2::host_backed && !pc.host_path.empty()) {
                    struct ::stat st{};
                    if (::stat(pc.host_path.c_str(), &st) != 0)
                        return eno(errno == ENOTDIR ? Errno::enotdir : Errno::enoent);
                    key = inode_key(st);
                }
            }
            const std::string name = kernel::abstract_name_for(key, k_.files().instance_id());
            // An abstract address is a leading NUL then the name, and its
            // LENGTH is what delimits it -- there is no terminator. Hand the
            // trap the exact bytes to poke.
            std::string addr_bytes;
            addr_bytes.push_back('\0');
            addr_bytes += name;
            if (addr_bytes.size() > 108) return fwd();
            const std::uint64_t alen = 2 + addr_bytes.size();
            SockRewrite sr{uaddr(addr + 2), std::move(addr_bytes), /*len_arg=*/2, alen};
            sr.guest_path = raw_guest_path;
            sr.binds = for_bind;
            return sr;
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

        // Emit a socket-path rewrite: the trap pokes host_path into the
        // guest's sun_path and sets the socklen register, then forwards the
        // (now overlay-targeted) bind/connect to the kernel.
        // sizeof(sa_family_t) == 2, then the path bytes and its NUL.
        const std::uint64_t new_len = 2 + host_path.size() + 1;
        SockRewrite sr{uaddr(addr + 2), std::move(host_path), /*len_arg=*/2, new_len};
        sr.guest_path = raw_guest_path;
        sr.binds = for_bind;
        return sr;
    }

    [[nodiscard]] Outcome path_symlink(const Regs& r, int target_arg,
                                       int link_arg, bool at) {
        // Only the LINK NAME is a path: the target is literal text that is
        // never resolved, so a dangling or even nonsense target is legal.
        // Both being EMPTY is still ENOENT though -- an empty name has
        // nothing to create, and an empty target is rejected outright.
        if (empty_path_arg(r, link_arg)) return eno(Errno::enoent);
        // The empty-target check comes BEFORE anything about the link name,
        // so it outranks the trailing-slash rule below: symlink("",
        // "existing-dir/") is ENOENT, not the EEXIST the name alone gives.
        if (empty_path_arg(r, target_arg)) return eno(Errno::enoent);
        // A "."/".." in the link name does not excuse the components before
        // it: an unsearchable directory mid-path is EACCES, and a missing one
        // ENOENT, both ahead of anything about the name being taken. Same
        // walker every other path handler uses.
        if (const Errno e = dot_prefix_error(r, link_arg, at); e != Errno::ok)
            return eno(e);
        // A TRAILING SLASH means "this must be a directory", and a symlink
        // being created never is -- so the kernel refuses whatever the
        // target. WHICH refusal depends on what is already there: an
        // existing name is EEXIST (you cannot create over it), a missing one
        // is ENOENT (the slash demands a directory that is not there).
        // linuxity normalized the slash away and created the link, which
        // `tar -x` and install scripts hit because they write
        // trailing-slash paths routinely. Found by the differential fuzzer
        // as the FIRST generated operation, with every later divergence in
        // that run cascading from this one link existing where it should
        // not -- and the first fix here returned a blanket ENOENT, which
        // the fuzzer then caught again for the existing-name case.
        if (path_syntax(read_cstr(uaddr(r.arg[static_cast<std::size_t>(link_arg)])))
                == PathSyntax::needs_dir) {
            std::string probe = at ? resolve_second(r, link_arg, true)
                                   : k_.files().absolutize(
                                         read_cstr(uaddr(r.arg[static_cast<std::size_t>(link_arg)])),
                                         k_.files().cwd());
            // Probe the name WITHOUT the slash -- classify() resolves a
            // path, and the trailing slash is the very thing being asked
            // about, so leaving it on makes the lookup fail and every case
            // look like ENOENT.
            while (probe.size() > 1 && probe.back() == '/') probe.pop_back();
            auto pc = k_.files().classify(probe, false, false);
            if (pc.realm == kernel::Realm2::virtual_file) return eno(Errno::eexist);
            if (pc.realm == kernel::Realm2::host_backed && !pc.host_path.empty())
                if constexpr (requires { mem_.stat_host_path(pc.host_path); })
                    if (mem_.stat_host_path(pc.host_path)) return eno(Errno::eexist);
            // Neither existing nor plainly missing: an unsearchable parent
            // means we could not LOOK, which the kernel reports as EACCES
            // before any slash reasoning.
            if (pc.realm == kernel::Realm2::host_backed &&
                !host_dir_searchable(pc.host_path))
                return eno(Errno::eacces);
            return eno(Errno::enoent);
        }
        std::string link = at ? resolve_second(r, link_arg, true)
                              : k_.files().absolutize(
                                    read_cstr(uaddr(r.arg[static_cast<std::size_t>(link_arg)])),
                                    k_.files().cwd());
        auto pc = k_.files().classify(link, true, false, Wi::parents_only);
        // A "."/".." in the link name was normalized away; traversing it
        // still needs +x on that directory.
        if (dot_traversal_denied(
                read_cstr(uaddr(r.arg[static_cast<std::size_t>(link_arg)])),
                pc.host_path))
            return eno(Errno::eacces);
        // A cycle in the link name's prefix is ELOOP, same as path_mut.
        if (const Errno e = guest_prefix_loop(link); e != Errno::ok)
            return eno(e);
        if (pc.realm == kernel::Realm2::virtual_file)
            // Reached only when the link name RESOLVED, so the name is taken.
            return eno(virtual_mut_errno(link, VMut::exists));
        if (pc.host_path.empty()) return eno(pc.error);
        if (!privileged())
            if (Errno e = dir_entry_allowed(link, false); e != Errno::ok) return eno(e);
        // Rewrite ONLY the linkpath; `target` stays guest-literal.
        //
        // NO .parents(): creating the chain is for mirroring a directory that
        // already exists in the read-only lower layer, not for inventing one.
        // `ln -s t d/missing/link` was CREATING `missing/` and succeeding,
        // where the kernel says ENOENT -- and with a FILE in that position it
        // said EEXIST instead of ENOTDIR. Same rule mkdir/mknod opt into with
        // strict_parent; let the host kernel judge the translated path.
        // created: the link is its creator's, or a sticky /tmp won't let
        // them remove it (emacs lock files).
        Redirect o{PathArg{link_arg, std::move(pc.host_path)}};
        o.created = link;
        return o;
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
            // a pty slave's owner is ours to report (scrub_ids), not root
            if (pts_owner(guest_path)) return std::nullopt;
            auto fields = mem_.stat_host_path(host_path);
            // An inode with emulated extra names: the host counts only the
            // backing, so report every name, as the scrub does on the slow
            // path. Missing this made os.stat say 1 right after a link.
            if (fields && !k_.files().links().empty() &&
                k_.files().links().has_aliases(host_path))
                fields->nlink = k_.files().links().count(host_path);
            // the empty file an abstract-namespace bind left is a socket
            if (fields && sock_placeholders_.count(guest_path)) {
                if ((fields->mode & 0170000u) == 0100000u)
                    fields->mode = (fields->mode & ~0170000u) | 0140000u;
                else
                    sock_placeholders_.erase(guest_path);
            }
            return fields;
        } else {
            return std::nullopt;
        }
    }

    // Synthesize a `struct statx` (the flat, versioned stat the kernel fills
    // for statx(2)) for a virtual node into the guest buffer.
    [[nodiscard]] Outcome write_statx(UAddr buf, bool is_dir, std::uint64_t size,
                                      bool is_link = false, std::string_view guest = {}) {
        return write_statx(buf, synth_hstat(is_dir, size, is_link), guest);
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
    [[nodiscard]] Outcome write_statx(UAddr buf, const wire::StatFields& h,
                                      std::string_view guest = {}) {
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
        // Mount id and mount-root, from our mount table. systemd's path walk
        // (libudev, so lsusb) demands STATX_MNT_ID back and gave up at "/"
        // when the mask lacked it.
        if (!guest.empty()) {
            const auto mo = k_.files().mount_of(guest);
            constexpr std::uint32_t kMntId = 0x1000, kMntIdUnique = 0x4000;
            constexpr std::uint64_t kMountRoot = 0x2000;
            sx.stx_mask |= kMntId | kMntIdUnique;
            sx.stx_mnt_id = mo.id;
            sx.stx_attributes_mask |= kMountRoot;
            if (mo.root) sx.stx_attributes |= kMountRoot;
        }
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
        // the host's load, in the kernel's fixed point (1 << SI_LOAD_SHIFT)
        if (std::FILE* lf = std::fopen("/proc/loadavg", "re")) {
            double l[3]{};
            if (std::fscanf(lf, "%lf %lf %lf", &l[0], &l[1], &l[2]) == 3)
                for (int i = 0; i < 3; ++i) si.loads[i] = static_cast<std::uint64_t>(l[i] * 65536.0);
            std::fclose(lf);
        }
        si.totalram  = m.mem_total;
        si.freeram   = m.mem_free();
        si.bufferram = m.mem_buffers();
        si.totalswap = m.swap_total;
        si.freeswap  = m.swap_free();
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
        // like the kernel: the buffer must hold the whole mask, in longs
        if (cap < bytes || cap % sizeof(long) != 0) return eno(Errno::einval);
        std::vector<std::byte> buf(bytes, std::byte{0});
        for (long c = 0; c < ncpu; ++c)
            buf[static_cast<std::size_t>(c) / 8] |=
                static_cast<std::byte>(1u << (static_cast<unsigned>(c) & 7u));
        // The task's REAL mask, so sched_setaffinity reads back. Clipped to
        // the CPUs we advertise; if that leaves none, the advertised set.
        // (Only a ptrace backend has host tids, and only Linux has the call.)
#if defined(__linux__)
        if constexpr (requires { mem_.host_tid(); mem_.host_tid_of(0); }) {
            const auto pid = static_cast<std::int32_t>(r.arg[0]);
            if (pid < 0) return eno(Errno::esrch);
            const ::pid_t host = pid == 0 ? mem_.host_tid() : mem_.host_tid_of(pid);
            if (host <= 0) return eno(Errno::esrch);
            ::cpu_set_t real;
            CPU_ZERO(&real);
            if (::sched_getaffinity(host, sizeof real, &real) == 0) {
                std::vector<std::byte> clip(bytes, std::byte{0});
                bool any = false;
                for (long c = 0; c < ncpu && c < CPU_SETSIZE; ++c)
                    if (CPU_ISSET(static_cast<int>(c), &real)) {
                        clip[static_cast<std::size_t>(c) / 8] |=
                            static_cast<std::byte>(1u << (static_cast<unsigned>(c) & 7u));
                        any = true;
                    }
                if (any) buf = std::move(clip);
            } else if (errno == ESRCH) {
                return eno(Errno::esrch);
            }
        }
#endif
        // A backend that keeps affinity itself (HVF: XNU has no pinning).
        if constexpr (requires { mem_.affinity_of(0); }) {
            const auto pid = static_cast<std::int32_t>(r.arg[0]);
            const auto m = mem_.affinity_of(pid);
            if (!m) return eno(Errno::esrch);
            if (*m) {
                std::fill(buf.begin(), buf.end(), std::byte{0});
                for (long c = 0; c < ncpu && c < 64; ++c)
                    if (*m & (1ull << c))
                        buf[static_cast<std::size_t>(c) / 8] |=
                            static_cast<std::byte>(1u << (static_cast<unsigned>(c) & 7u));
            }
        }
        if (!mem_.copy_out(mask, buf)) return eno(Errno::efault);
        return val(static_cast<std::int64_t>(bytes));
    }

    // setgroups(size, list): root may set anything up to NGROUPS_MAX.
    [[nodiscard]] Outcome do_setgroups(const Regs& r) {
        const std::size_t n = static_cast<std::size_t>(r.arg[0]);
        if (n > 65536) return eno(Errno::einval);
        std::vector<std::uint32_t> g(n);
        if (n && !mem_.copy_in(uaddr(r.arg[1]), std::as_writable_bytes(std::span{g})))
            return eno(Errno::efault);
        k_.procs().set_groups(ids().pid, std::move(g));
        return val(0);
    }

    // getgroups(size, list): size 0 asks for the count only.
    [[nodiscard]] Outcome do_getgroups(const Regs& r) {
        const auto g = k_.procs().groups_of(ids().pid);
        const auto size = static_cast<std::int32_t>(r.arg[0]);
        if (size < 0) return eno(Errno::einval);
        if (size == 0) return val(static_cast<std::int64_t>(g.size()));
        if (static_cast<std::size_t>(size) < g.size()) return eno(Errno::einval);
        if (!g.empty() && !mem_.copy_out(uaddr(r.arg[1]), std::as_bytes(std::span{g})))
            return eno(Errno::efault);
        return val(static_cast<std::int64_t>(g.size()));
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
        constexpr std::uint64_t kTIOCSCTTY = 0x540E;  // claim as ctty
        constexpr std::uint64_t kTIOCNOTTY = 0x5422;  // give up the ctty
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
        // A terminal request on something that isn't a char device is ENOTTY
        // on every kernel. Answer it here: Android's SELinux says EACCES first.
        if (is_tty_request(request) && host_fd_is_file(static_cast<int>(r.arg[0])))
            return eno(Errno::enotty);
        // SIOCGIFINDEX (if_nametoindex): Android's SELinux refuses it, but
        // rtnetlink still names every link. Answer from that where the host
        // refuses generic netlink, the same sandbox.
        if (request == 0x8933 /*SIOCGIFINDEX*/ && host_refuses_genl() && r.arg[2]) {
            char name[16] = {};
            if (!mem_.copy_in(uaddr(r.arg[2]), std::as_writable_bytes(std::span{name})))
                return eno(Errno::efault);
            name[15] = '\0';
            const std::uint32_t idx = host_ifindex(name);
            if (!idx) return eno(Errno::enodev);
            if (!put_u32(r.arg[2] + 16, idx)) return eno(Errno::efault);
            return val(0);
        }
        // tcdrain/tcsendbreak: on a pty this is a no-op (writes reach the
        // other end at once, no break op). Android's SELinux refuses it, so
        // answer it there.
        if ((request == 0x5409 /*TCSBRK*/ || request == 0x5425 /*TCSBRKP*/) &&
            host_refuses_tcsbrk() && host_fd_is_pty(static_cast<int>(r.arg[0])))
            return val(0);
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
        // terminal's foreground group AND its controlling terminal: each
        // guest process is a real host process that setsid()s for real, so
        // the host's tty layer is the authority. Forward all four, so
        // tcsetpgrp actually moves ^C/^Z delivery to the job, and so the
        // ctty the host's TIOCGPGRP checks is the one TIOCSCTTY claimed (a
        // virtual TIOCSCTTY left the host child with no ctty, and its
        // tcgetpgrp said ENOTTY -- pty.fork's child, every time).
        if constexpr (requires { mem_.models_process_groups(); })
            if (request == kTIOCGPGRP || request == kTIOCSPGRP || request == kTIOCGSID ||
                request == kTIOCSCTTY || request == kTIOCNOTTY)
                return fwd();
        switch (request) {
            // TIOCSCTTY / TIOCNOTTY: who owns the terminal.
            //
            // These cannot be forwarded. The kernel only lets a SESSION
            // LEADER claim a ctty, and in host terms the guest's tasks are
            // not session leaders -- linuxity's own process is. So the host
            // said EPERM, the guest never acquired a controlling terminal,
            // and everything downstream unravelled: the TIOCGPGRP probe
            // below (which asks the kernel to vet the fd) answered ENOTTY,
            // so bash printed "cannot set terminal process group" and then
            // "no job control in this shell". Caught on Android, where the
            // host refuses TIOCSCTTY every time.
            //
            // The session bookkeeping is already ours, so answer from it.
            case kTIOCSCTTY: {
                // A slave from TIOCGPTPEER (glibc's openpty) or an inherited
                // fd has no path binding, so ask the host which pts it is.
                std::int32_t n = pty_slave_of_fd(static_cast<int>(r.arg[0]));
                if (n < 0) n = host_fd_slave_no(static_cast<int>(r.arg[0]));
                if (n < 0) return eno(Errno::enotty);   // not a pty at all
                const std::int32_t me = ids().pid;
                // Only a session leader may claim one. getsid == pid is the
                // definition, and it is what setsid just arranged.
                if (k_.procs().sid_of(me) != me) return eno(Errno::eperm);
                const std::int32_t have = k_.procs().ctty_of(me);
                // Already ours is success; a DIFFERENT terminal is EPERM
                // unless arg is 1 (steal), which is what the kernel does.
                if (have >= 0 && have != n && r.arg[2] != 1)
                    return eno(Errno::eperm);
                k_.procs().set_ctty(me, n);
                // a terminal a session just took has no foreground group yet
                fg_pgrp_.erase(n);
                // Best effort on the host too, so the pty's own ^C and
                // hangup reach this session. Android refuses it; that's fine.
                return Virtualize::mirrored(0);
            }
            case kTIOCNOTTY: {
                const std::int32_t me = ids().pid;
                if (k_.procs().ctty_of(me) < 0) return ctty_refusal(r);
                k_.procs().clear_ctty(me);
                // TIOCSCTTY was mirrored on the host, so give it up there too,
                // or a forwarded TIOCGPGRP still sees the old claim
                return Virtualize::mirrored(0);
            }

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
            // and the kernel still says ENOTTY.
            //
            // We used to forward and let the KERNEL vet the fd. That read
            // well but was wrong off Linux-with-a-real-tty: the guest's
            // ctty is ours, claimed via TIOCSCTTY above, and the host knows
            // nothing about it. On Android the forward answered ENOTTY for
            // the guest's own terminal and bash lost job control. So vet it
            // against OUR bookkeeping, which is the authority.
            //
            // But only once we OWN the fd. If it is a terminal we have not
            // claimed, the host gets asked after all: its answer may be a
            // POLICY denial that outranks the tty question entirely, and
            // Android proves it -- SELinux returns EACCES for TIOCGSID on a
            // pty where a desktop kernel returns ENOTTY. Answering ENOTTY
            // ourselves hid that, and the on-device golden caught it.
            case kTIOCGPGRP: {
                // On a pty MASTER this asks about the slave's session, which
                // need not be ours.
                if (const std::int32_t m = pty_master_slave(static_cast<int>(r.arg[0])); m >= 0) {
                    auto it = fg_pgrp_.find(m);
                    if (it != fg_pgrp_.end() && !fg_group_alive(it->second, 0)) { fg_pgrp_.erase(it); it = fg_pgrp_.end(); }
                    std::int32_t fg = 0;
                    if (it != fg_pgrp_.end()) {
                        fg = it->second;
                    } else {
                        for (std::int32_t p : k_.procs().pids())
                            if (const auto* pi = k_.procs().find(p); pi && pi->ctty == m && k_.procs().sid_of(p) == p) {
                                fg = k_.procs().pgid_of(p);
                                break;
                            }
                    }
                    if (fg <= 0) return fwd();
                    if (!put_u32(r.arg[2], static_cast<std::uint32_t>(fg))) return eno(Errno::efault);
                    return val(0);
                }
                if (!fd_is_our_ctty(static_cast<int>(r.arg[0])))
                    return ctty_refusal(r);
                // Whoever TIOCSPGRP last handed the terminal to; the caller's
                // own group until someone claims it. Always answering the
                // caller's own group is what bash needs at the prompt (it
                // loops until tcgetpgrp == getpgrp), and it stays true there
                // because a shell sets the foreground group to ITSELF when it
                // takes the terminal back. But it must not be true while a
                // JOB holds the tty, or a shell can never tell that the job
                // is in the foreground and not itself.
                // The sentinel is pid 1's group (born into linuxity's group,
                // never a leader, so its first setsid() isn't EPERM), and
                // getpgrp reports it. tcgetpgrp has to say the same, or
                // bash's "loop until tcgetpgrp == getpgrp" never ends and it
                // prints "no job control in background". bash then makes
                // itself a leader and hands the terminal to that group.
                const std::int32_t tty = k_.procs().ctty_of(ids().pid);
                auto it = fg_pgrp_.find(tty);
                // No tcsetpgrp yet: the terminal's foreground is the group
                // of the session that claimed it (its leader's), not the
                // caller's. Answering the caller's own group made a job
                // think it owned the tty before its shell handed it over.
                std::int32_t fg;
                if (it != fg_pgrp_.end() && !fg_group_alive(it->second, k_.procs().sid_of(ids().pid))) {
                    // the terminal's last foreground group is gone: a pts
                    // number reused by a new session (every tab, every exec
                    // in a long-running instance). bash would wait on it and
                    // give up with "no job control in background".
                    fg_pgrp_.erase(it);
                    it = fg_pgrp_.end();
                }
                if (it != fg_pgrp_.end()) fg = it->second;
                else if (tty >= 0)        fg = k_.procs().pgid_of(k_.procs().sid_of(ids().pid));
                else                      fg = flat_pgrp();
                if (fg == kernel::ProcessTable::kInheritedPgid) fg = flat_pgrp();
                if (!put_u32(r.arg[2], static_cast<std::uint32_t>(fg)))
                    return eno(Errno::efault);
                return val(0);
            }
            case kTIOCGSID: {
                if (!fd_is_our_ctty(static_cast<int>(r.arg[0])))
                    return ctty_refusal(r);
                const std::int32_t sid = k_.procs().sid_of(ids().pid);
                if (!put_u32(r.arg[2], static_cast<std::uint32_t>(sid)))
                    return eno(Errno::efault);
                return val(0);
            }
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
                if (!fd_is_our_ctty(static_cast<int>(r.arg[0])))
                    return ctty_refusal(r);
                const std::uint32_t want = get_u32(r.arg[2]);
                // Record the FOREGROUND group. Writing flat_pgrp_ here moved
                // the caller itself into the group it was handing the tty to.
                //
                // Reject the sentinel: a shell reads tcgetpgrp and hands the
                // value straight back, so if 0x7fff0000 ever escaped it
                // would be stored here and re-served forever. Treat it as
                // the caller claiming the terminal for itself.
                // Handing back the sentinel (what tcgetpgrp reported for an
                // unclaimed tty) means "my own group", i.e. unclaimed again.
                const std::int32_t tty = k_.procs().ctty_of(ids().pid);
                if (want == static_cast<std::uint32_t>(
                                kernel::ProcessTable::kInheritedPgid)) {
                    fg_pgrp_.erase(tty);
                    return val(0);
                }
                if (static_cast<std::int32_t>(want) <= 0) return eno(Errno::einval);
                // the group has to exist in the caller's session
                bool found = false;
                const std::int32_t sess = k_.procs().sid_of(ids().pid);
                for (std::int32_t p : k_.procs().pids())
                    if (k_.procs().pgid_of(p) == static_cast<std::int32_t>(want) &&
                        k_.procs().sid_of(p) == sess) { found = true; break; }
                if (!found) return eno(Errno::eperm);
                // Hand the real terminal to the same group, so the line
                // discipline's ^C/^Z/SIGTTIN reach the job the guest chose.
                // The guest-visible foreground group is updated after that
                // (note_foreground), so a job that polls tcgetpgrp can't see
                // the terminal as its own before the host agrees.
                pending_fg_ = {tty, static_cast<std::int32_t>(want)};
                Virtualize v{0};
                v.host_mirror = Virtualize::Mirror::tcsetpgrp;
                v.m_a = static_cast<std::int32_t>(want);
                v.m_ptr = r.arg[2];
                return v;
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
    [[nodiscard]] Outcome do_getres(const Regs& r, const std::array<std::uint32_t, 4>& ids) {
        if (!r.arg[0] || !r.arg[1] || !r.arg[2]) return eno(Errno::efault);
        const bool gid = &ids == &me().gids;
        // A non-null pointer can still be unwritable. put_u32 used to
        // swallow that, so writing through 0x1 reported success where the
        // kernel says EFAULT -- the null check caught only the easy half.
        if (!put_u32(r.arg[0], ns_id(ids[0], gid)) || !put_u32(r.arg[1], ns_id(ids[1], gid)) ||
            !put_u32(r.arg[2], ns_id(ids[2], gid)))
            return eno(Errno::efault);
        return val(0);
    }

    // getpriority/setpriority on PRIO_PROCESS, PRIO_PGRP and PRIO_USER,
    // over each process's nice. The host process is also renice'd, best
    // effort, so the scheduler sees it. getpriority returns 20 - nice.
    [[nodiscard]] Outcome do_priority(const Regs& r, bool set) {
        const std::uint64_t which = r.arg[0];
        if (which > 2) return eno(Errno::einval);
        const auto who = static_cast<std::int32_t>(r.arg[1]);
        std::vector<std::int32_t> targets;
        const std::int32_t self = ids().pid;
        if (which == 0) {                       // PRIO_PROCESS
            const std::int32_t p = who ? who : self;
            if (p != self && !k_.procs().has(p)) return eno(Errno::esrch);
            targets.push_back(p);
        } else {
            const std::int32_t g = which == 1 ? (who ? who : k_.procs().pgid_of(self)) : -1;
            const std::uint32_t u = which == 2 ? (who ? static_cast<std::uint32_t>(who) : me().uids[1]) : 0;
            for (std::int32_t p : k_.procs().pids()) {
                const auto* pi = k_.procs().find(p);
                if (!pi) continue;
                if (which == 1 ? k_.procs().pgid_of(p) == g : pi->uids[0] == u) targets.push_back(p);
            }
            if (targets.empty()) return eno(Errno::esrch);
        }
        // A backend whose every guest process is a host process (HVF) keeps
        // nice in its SHARED table: fork inherits it there and every process
        // in the tree reads the same answer (this table is per-process). The
        // host process can't hold it -- unprivileged, it may never go back
        // down, which a root guest may.
        auto host_nice = [&](std::int32_t p) -> std::optional<int> {
            if constexpr (requires { mem_.nice_of(p); }) {
                return mem_.nice_of(p);
            }
            return std::nullopt;
        };
        if (!set) {
            int best = 19;
            for (std::int32_t p : targets)
                if (const auto hn = host_nice(p)) best = std::min(best, *hn);
                else if (const auto* pi = k_.procs().find(p)) best = std::min(best, static_cast<int>(p == self ? me().nice : pi->nice));
            return val(20 - best);
        }
        int nv = static_cast<int>(static_cast<std::int32_t>(r.arg[2]));
        nv = std::clamp(nv, -20, 19);
        for (std::int32_t p : targets) {
            auto* pi = p == self ? &me() : k_.procs().find_mut(p);
            if constexpr (requires { mem_.set_nice(p, nv); }) {
                // the backend's tree-wide table is the authority; our own
                // record of another process may be absent or a stale copy
                const int cur = host_nice(p).value_or(pi ? pi->nice : 0);
                if (!creds::capable(me(), creds::kCapSysNice) && nv < cur) return eno(Errno::eacces);
                mem_.set_nice(p, nv);
                if (pi) pi->nice = nv;
                continue;
            }
            if (!pi) continue;
            const int cur = host_nice(p).value_or(pi->nice);
            if (!creds::capable(me(), creds::kCapSysNice)) {
                if (pi->uids[0] != me().uids[1] && pi->uids[1] != me().uids[1]) return eno(Errno::eperm);
                if (nv < cur) return eno(Errno::eacces);
            }
            pi->nice = nv;
            if constexpr (requires { mem_.host_tid_of(0); }) {
#if !defined(_WIN32)
                if (const auto h = mem_.host_tid_of(p); h > 0) (void)::setpriority(PRIO_PROCESS, static_cast<id_t>(h), nv);
#endif
            }
        }
        return val(0);
    }

    // The prctls whose state is the process's credentials. no_new_privs is
    // forwarded as well: the host's own copy is what blocks a set-ID exec
    // outside our view, and the kernel won't let anyone clear it.
    [[nodiscard]] std::optional<Outcome> prctl_creds(int op, const Regs& r) {
        auto& p = me();
        const std::uint64_t a = r.arg[1];
        switch (op) {
            case 7:   // PR_GET_KEEPCAPS
                return val(p.keepcaps ? 1 : 0);
            case 8:   // PR_SET_KEEPCAPS
                if (a > 1) return eno(Errno::einval);
                p.keepcaps = a == 1;
                return val(0);
            case 23:  // PR_CAPBSET_READ
                if (a > static_cast<std::uint64_t>(creds::kCapLast)) return eno(Errno::einval);
                return val((p.cap_bnd >> a) & 1);
            case 24:  // PR_CAPBSET_DROP
                if (a > static_cast<std::uint64_t>(creds::kCapLast)) return eno(Errno::einval);
                if (!creds::capable(p, creds::kCapSetpcap)) return eno(Errno::eperm);
                p.cap_bnd &= ~creds::bit(static_cast<int>(a));
                return val(0);
            case 38:  // PR_SET_NO_NEW_PRIVS
                if (a != 1 || r.arg[2] || r.arg[3] || r.arg[4]) return eno(Errno::einval);
                p.no_new_privs = true;
                return std::nullopt;   // forward too
            case 39:  // PR_GET_NO_NEW_PRIVS
                if (a || r.arg[2] || r.arg[3] || r.arg[4]) return eno(Errno::einval);
                return val(p.no_new_privs ? 1 : 0);
            case 47: {   // PR_CAP_AMBIENT
                const int c = static_cast<int>(r.arg[2]);
                if (a == 4) {    // CLEAR_ALL
                    p.cap_amb = 0;
                    return val(0);
                }
                if (c < 0 || c > creds::kCapLast) return eno(Errno::einval);
                const std::uint64_t b = creds::bit(c);
                if (a == 1) return val((p.cap_amb & b) ? 1 : 0);            // IS_SET
                if (a == 2) {                                                // RAISE
                    if (!(p.cap_prm & b) || !(p.cap_inh & b)) return eno(Errno::eperm);
                    p.cap_amb |= b;
                    return val(0);
                }
                if (a == 3) { p.cap_amb &= ~b; return val(0); }              // LOWER
                return eno(Errno::einval);
            }
            default:
                return std::nullopt;
        }
    }

    // The calling process's record, created on first use. A task can run
    // before its spawn event is folded in, so a missing record is built the
    // way fork would: the parent's credentials, groups and nice.
    [[nodiscard]] kernel::ProcInfo& me() {
        const auto id = ids();
        if (auto* p = k_.procs().find_mut(id.pid)) return *p;
        kernel::ProcInfo pi;
        pi.pid = id.pid;
        pi.ppid = id.ppid;
        if (const auto* pp = id.ppid > 0 ? k_.procs().find(id.ppid) : nullptr) {
            pi.comm = pp->comm;
            pi.cmdline = pp->cmdline;
            pi.creds() = pp->creds();       // fork: one value, every field
            k_.procs().inherit_ns(pi, *pp, 0);
        }
        // A fork child in a FRESH process: its parent's real record lives in
        // the parent's linuxity -- the one here is only this process's seed
        // (pid 1, default root) -- so the creds the fork handed over win.
        if (const auto& ic = k_.procs().inherited_creds()) pi.creds() = *ic;
        pi.creds_given = true;
        pi.live_seen = true;
        k_.procs().upsert(pi);
        if (id.ppid > 0) k_.procs().assign_ns_pid_from(id.pid, id.ppid);
        return *k_.procs().find_mut(id.pid);
    }

#include "linuxity/abi/sysv_handlers.inc"

    // -- guest ptrace (runtime/linux/guest_ptrace.inc) ----------------------
    // A guest tracing another guest is emulated by the backend, which is
    // every guest task's real tracer.
    [[nodiscard]] Outcome do_ptrace(const Regs& r) {
        if constexpr (requires { mem_.guest_ptrace(0, 0, 0, 0); }) {
            const auto req = static_cast<std::int64_t>(r.arg[0]);
            const auto pid = static_cast<std::int32_t>(r.arg[1]);
            if (req == 16 /*ATTACH*/ || req == 0x4206 /*SEIZE*/) {
                // ptrace_may_access: CAP_SYS_PTRACE, or the same uids; then
                // Yama (scope 1: only descendants without the capability)
                const auto& m = me();
                if (!creds::capable(m, 19 /*CAP_SYS_PTRACE*/)) {
                    const auto g = global_of_view(pid);
                    const auto* t = g > 0 ? k_.procs().find(g) : nullptr;
                    if (!t) return eno(Errno::esrch);
                    if (t->uids[0] != m.uids[0] || t->uids[1] != m.uids[0] || t->uids[2] != m.uids[0] ||
                        t->gids[0] != m.gids[0] || t->gids[1] != m.gids[0] || t->gids[2] != m.gids[0])
                        return eno(Errno::eperm);
                    int scope = 1;
                    if (std::FILE* f = std::fopen("/proc/sys/kernel/yama/ptrace_scope", "re")) {
                        if (std::fscanf(f, "%d", &scope) != 1) scope = 1;
                        std::fclose(f);
                    }
                    if (scope >= 2) return eno(Errno::eperm);
                    if (scope == 1) {
                        bool below = false;
                        for (std::int32_t p = g, hops = 0; p > 1 && hops < 4096; ++hops) {
                            const auto* pi = k_.procs().find(p);
                            if (!pi) break;
                            if (pi->ppid == ids().pid) { below = true; break; }
                            p = pi->ppid;
                        }
                        if (!below) return eno(Errno::eperm);
                    }
                }
            }
            const std::int64_t ret = mem_.guest_ptrace(req, pid, r.arg[2], r.arg[3]);
            return val(ret);
        } else {
            return eno(Errno::eperm);
        }
    }
    // wait4 by a tracer: its tracees' stops first; with tracees but nothing
    // to report, poll the real wait4 so real children are still reaped.
    [[nodiscard]] Outcome do_wait4_traced(const Regs& r) {
        if constexpr (requires { mem_.guest_wait4(0, 0, 0, 0, std::declval<std::int64_t&>()); }) {
            const auto pid = static_cast<std::int64_t>(static_cast<std::int32_t>(r.arg[0]));
            const int options = static_cast<int>(r.arg[2]);
            // the backend already turned a positive pid into its host tid
            const std::int64_t hp = pid;
            std::int64_t ret = 0;
            switch (mem_.guest_wait4(hp, r.arg[1], options, r.arg[3], ret)) {
                case std::remove_reference_t<decltype(mem_)>::GtWait::answered:
                    return val(ret);
                case std::remove_reference_t<decltype(mem_)>::GtWait::block:
                    if (options & 1 /*WNOHANG*/) return fwd();
                    {
                        // the real wait4 without blocking; a real child's exit
                        // still comes through, otherwise wait and look again
                        GuestCalls gc;
                        gc.steps = {{Sysno::wait4, {r.arg[0], r.arg[1],
                                                    static_cast<std::uint64_t>(options | 1), r.arg[3], 0, 0}}};
                        gc.retry_if_zero_ns = 1'000'000;
                        gc.echild_is_zero = true;
                        return gc;
                    }
                case std::remove_reference_t<decltype(mem_)>::GtWait::forward:
                    break;
            }
        }
        return fwd();
    }

    // -- namespaces (kernel/namespaces.hpp) ----------------------------------
    // An id of the guest's initial user namespace, as the caller's own user
    // namespace names it (the overflow id 65534 when it isn't mapped).
    [[nodiscard]] std::uint32_t ns_id(std::uint32_t id, bool gid) {
        if (!map_files_.empty()) apply_map_writes();
        const auto un = me().ns[kernel::NsKind::user];
        return un ? k_.procs().ns().to_ns(un, id, gid) : id;
    }
    // The reverse, for an id the caller passes in. An unmapped id becomes
    // one no credential holds, so the set call fails EINVAL/EPERM like Linux.
    [[nodiscard]] std::uint32_t in_ns(std::uint32_t id, bool gid) {
        if (id == creds::kKeep) return id;
        if (!map_files_.empty()) apply_map_writes();
        const auto un = me().ns[kernel::NsKind::user];
        if (!un) return id;
        return k_.procs().ns().from_ns(un, id, gid).value_or(0xfffffffeu);
    }
    // Who may make namespaces: CAP_SYS_ADMIN, or anyone for a user namespace
    // (and anything alongside a new one, which grants them CAP_SYS_ADMIN in it).
    [[nodiscard]] Errno ns_allowed(const kernel::ProcInfo& p, std::uint64_t flags) const {
        if (flags & ~(kernel::kCloneNewMask | 0x00000200 /*CLONE_FS*/ | 0x00000400 /*FILES*/ |
                      0x00040000 /*SYSVSEM*/ | 0x00000100 /*VM*/ | 0x00000800 /*SIGHAND*/ |
                      0x00010000 /*THREAD*/))
            return Errno::einval;
        const bool newuser = flags & 0x10000000;
        if (!newuser && (flags & kernel::kCloneNewMask) && !creds::capable(p, 21 /*CAP_SYS_ADMIN*/))
            return Errno::eperm;
        return Errno::ok;
    }
    // unshare(flags)
    [[nodiscard]] Outcome do_unshare(const Regs& r) {
        auto& p = me();
        const std::uint64_t flags = r.arg[0];
        if (const Errno e = ns_allowed(p, flags); e != Errno::ok) return eno(e);
        // a multithreaded process can't change its user namespace
        if ((flags & 0x10000000) && !p.threads.empty()) return eno(Errno::einval);
        k_.procs().unshare_ns(p, flags & kernel::kCloneNewMask);
        if (flags & 0x10000000) {
            // the creator holds every capability in its new user namespace,
            // and until a map is written its ids read as the overflow id
            p.cap_eff = p.cap_prm = p.cap_bnd = kernel::ProcInfo::kAllCaps;
        }
        // the non-namespace bits (CLONE_FS, FILES, SYSVSEM) are per-task
        // sharing the host already gives an unshared process
        if constexpr (requires { mem_.host_tid(); }) {
            // a network namespace only on paper leaves the guest on the
            // host's network, so make it for real where the host can
            if ((flags & host::kCloneNewnet) && host::host_can_netns()) {
                GuestCalls gc;
                gc.steps = {{Sysno::unshare, {host::real_netns_flags(), 0, 0, 0, 0, 0}}};
                gc.before_resume = [this](std::int64_t rc) {
                    if (rc == 0) (void)host::write_identity_maps(mem_.host_tid());
                };
                return gc;
            }
        }
        return val(0);
    }
    // setns(fd, nstype): join the namespace an /proc/<pid>/ns/* fd names
    [[nodiscard]] Outcome do_setns(const Regs& r) {
        auto& p = me();
        const int fd = static_cast<int>(r.arg[0]);
        const std::uint64_t want = r.arg[1];
        const std::string gp{k_.files().path_of_fd(fd)};
        if (gp.empty()) {
            // not one of ours: EBADF if it isn't open at all
            if (const int h = open_tracee_fd(fd); h >= 0) ::close(h);
            else return eno(Errno::ebadf);
        }
        // the guest path names the target: /proc/<pid>/ns/<kind>
        std::int32_t pid = 0;
        std::string kind;
        if (std::sscanf(gp.c_str(), "/proc/%d/ns/", &pid) == 1) {
            kind = gp.substr(gp.rfind('/') + 1);
            pid = global_of_view(pid);
        }
        if (gp.starts_with("/proc/self/ns/")) { pid = ids().pid; kind = gp.substr(14); }
        if (pid <= 0 || kind.empty()) return eno(Errno::einval);
        const auto leaf = kernel::parse_ns_leaf(kind);
        if (!leaf) return eno(Errno::einval);
        const auto kd = leaf->kind;
        const std::size_t k = kernel::ns_index(kd);
        if (want && want != kernel::kNsFlag[k]) return eno(Errno::einval);
        if (!creds::capable(p, 21 /*CAP_SYS_ADMIN*/)) return eno(Errno::eperm);
        const auto target = k_.procs().ns_of(pid);
        if (kd == kernel::NsKind::pid) p.ns.pid_for_children = k_.procs().ns().resolve(target, kd);
        else if (kd == kernel::NsKind::time) p.ns.time_for_children = k_.procs().ns().resolve(target, kd);
        else p.ns.id[k] = target.id[k];
        return val(0);
    }
    // sethostname/setdomainname: per UTS namespace
    [[nodiscard]] Outcome do_set_uts(const Regs& r, bool domain) {
        auto& p = me();
        if (!creds::capable(p, 21 /*CAP_SYS_ADMIN*/)) return eno(Errno::eperm);
        const auto len = static_cast<std::size_t>(r.arg[1]);
        if (len > 64) return eno(Errno::einval);
        std::vector<std::byte> raw(len);
        if (len && !mem_.copy_in(uaddr(r.arg[0]), raw)) return eno(Errno::efault);
        std::string s(reinterpret_cast<const char*>(raw.data()), len);
        auto& ns = k_.procs().ns();
        const auto id = p.ns[kernel::NsKind::uts];
        if (domain) ns.set_domainname(id, std::move(s));
        else if (id) ns.set_hostname(id, std::move(s));
        else {
            // the initial namespace is the machine
            if constexpr (requires { k_.machine().nodename = s; }) k_.machine().nodename = std::move(s);
        }
        return val(0);
    }
    [[nodiscard]] static std::uint32_t u32(const Regs& r, int i) {
        return static_cast<std::uint32_t>(r.arg[static_cast<std::size_t>(i)]);
    }

    // The owner the guest sees for a file: what it chown'd, else root.
    [[nodiscard]] std::pair<std::uint32_t, std::uint32_t> owner_of(const std::string& guest) {
        std::uint32_t uid = 0, gid = 0;
        if (auto rec = k_.files().meta().lookup(guest)) {
            if (rec->have & kernel::MetaRecord::kUid) uid = rec->uid;
            if (rec->have & kernel::MetaRecord::kGid) gid = rec->gid;
        }
        return {uid, gid};
    }
    [[nodiscard]] bool in_group(std::uint32_t gid) {
        const auto& p = me();
        if (p.gids[3] == gid) return true;
        for (std::uint32_t g : k_.procs().groups_of(p.pid))
            if (g == gid) return true;
        return false;
    }
    // chmod and setting a file's group need ownership or CAP_FOWNER.
    [[nodiscard]] bool creds_may_chown_or_chmod(const std::string& guest) {
        return creds::capable(me(), creds::kCapFowner) || owner_of(guest).first == me().uids[3];
    }
    [[nodiscard]] static Outcome creds_result(Errno e) {
        return e == Errno::ok ? val(0) : eno(e);
    }

    // capget(hdr, data): versions 1 (32-bit sets) and 2/3 (two u32 halves).
    // A bad version writes the preferred one back and is EINVAL.
    [[nodiscard]] Outcome do_capget(const Regs& r) {
        std::uint32_t ver = 0;
        if (!get_u32_checked(r.arg[0], ver)) return eno(Errno::efault);
        constexpr std::uint32_t kV1 = 0x19980330, kV2 = 0x20071026, kV3 = 0x20080522;
        if (ver != kV1 && ver != kV2 && ver != kV3) {
            (void)put_u32(r.arg[0], kV3);
            // probing for the version: a null data pointer makes it success
            return r.arg[1] ? eno(Errno::einval) : val(0);
        }
        std::int32_t pid = 0;
        std::uint32_t raw = 0;
        if (!get_u32_checked(r.arg[0] + 4, raw)) return eno(Errno::efault);
        pid = static_cast<std::int32_t>(raw);
        if (pid < 0) return eno(Errno::einval);
        const kernel::ProcInfo* p = pid == 0 || pid == ids().pid ? &me() : k_.procs().find(pid);
        if (p == nullptr) return eno(Errno::esrch);
        if (r.arg[1] == 0) return val(0);
        const int halves = ver == kV1 ? 1 : 2;
        for (int i = 0; i < halves; ++i) {
            const std::uint64_t at = r.arg[1] + static_cast<std::uint64_t>(i) * 12;
            const int sh = 32 * i;
            if (!put_u32(at, static_cast<std::uint32_t>(p->cap_eff >> sh)) ||
                !put_u32(at + 4, static_cast<std::uint32_t>(p->cap_prm >> sh)) ||
                !put_u32(at + 8, static_cast<std::uint32_t>(p->cap_inh >> sh)))
                return eno(Errno::efault);
        }
        return val(0);
    }

    [[nodiscard]] Outcome do_capset(const Regs& r) {
        std::uint32_t ver = 0, raw = 0;
        if (!get_u32_checked(r.arg[0], ver) || !get_u32_checked(r.arg[0] + 4, raw))
            return eno(Errno::efault);
        constexpr std::uint32_t kV1 = 0x19980330, kV2 = 0x20071026, kV3 = 0x20080522;
        if (ver != kV1 && ver != kV2 && ver != kV3) {
            (void)put_u32(r.arg[0], kV3);
            return eno(Errno::einval);
        }
        const auto pid = static_cast<std::int32_t>(raw);
        if (pid != 0 && pid != ids().pid) return eno(Errno::eperm);
        std::uint64_t set[3] = {0, 0, 0};
        for (int i = 0; i < (ver == kV1 ? 1 : 2); ++i) {
            for (int k = 0; k < 3; ++k) {
                std::uint32_t v = 0;
                if (!get_u32_checked(r.arg[1] + static_cast<std::uint64_t>(i * 12 + k * 4), v))
                    return eno(Errno::efault);
                set[k] |= static_cast<std::uint64_t>(v) << (32 * i);
            }
        }
        const std::uint64_t mask = kernel::ProcInfo::kAllCaps;
        return creds_result(creds::capset(me(), set[0] & mask, set[1] & mask, set[2] & mask));
    }

    [[nodiscard]] bool get_u32_checked(std::uint64_t addr, std::uint32_t& out) {
        std::array<std::byte, 4> b{};
        if (!mem_.copy_in(uaddr(addr), b)) return false;
        std::memcpy(&out, b.data(), 4);
        return true;
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
        if (!map_files_.empty()) apply_map_writes();
        const auto& m = machine();
        // the caller's UTS namespace; the initial one is the machine's name
        const auto uts_id = me().ns[kernel::NsKind::uts];
        const auto& names = k_.procs().ns().uts(uts_id);
        set(u.nodename, uts_id ? names.first.c_str() : m.nodename.c_str());
        set(u.release,  m.release.c_str());
        set(u.version,  "#1 linuxity portable Linux ABI");
        set(u.machine,  m.machine_arch.c_str());
        set(u.domainname, uts_id ? names.second.c_str() : "(none)");
        if (!mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(&u), sizeof u}))
            return val(-static_cast<std::int64_t>(Errno::efault));
        return val(0);
    }

    K& k_;
    M& mem_;
    Arch arch_;
    std::string pending_open_;   // guest path awaiting fd assignment by trap
    // The open flags that go with pending_open_, so note_opened_fd can apply
    // the ctty rule: opening a tty WITHOUT O_NOCTTY in a session that has
    // none makes it the controlling terminal.
    std::uint64_t pending_flags_{0};
    // a comm file opened for write: the (pid, tid) it renames
    std::pair<std::int32_t, std::int32_t> pending_comm_{0, 0};
    struct CommFile {
        std::string host;    // the backing temp file
        std::int32_t pid, tid;
        std::string seen;    // what it held last time we looked
    };
    std::vector<CommFile> comm_files_;
    // an id-map file opened for write: (pid, "uid_map"|"gid_map"|"setgroups")
    std::pair<std::int32_t, std::string> pending_map_;
    struct MapFile { std::string host; std::int32_t pid; std::string which; };
    std::vector<MapFile> map_files_;
    // SysV IPC: segment file serial, and when each blocked semop started
    std::uint64_t shm_serial_{0};
    std::unordered_map<std::int32_t, std::chrono::steady_clock::time_point> sem_waits_;
    // The guest's kernel log: /dev/kmsg, /proc/kmsg and syslog(2) read it,
    // writes to /dev/kmsg append to it.
    struct KmsgRec { std::uint64_t seq; std::uint64_t ts_us; int prio; std::string text; };
    std::vector<KmsgRec> kmsg_;
    std::uint64_t kmsg_seq_{0}, kmsg_cleared_{0};
    std::vector<int> kmsg_writers_;   // read ends of pipes guest writers hold
    bool pending_new_{false};    // the pending O_CREAT open makes a new name
    // guest paths of abstract-socket placeholders (see do_sockaddr_un)
    std::unordered_set<std::string> sock_placeholders_;
    std::unordered_map<std::uint64_t, std::string> sock_names_, sock_peers_;
    struct EmuFifo {
        int anchor{-1};
        int hold_r{-1}, hold_w{-1};
        // tasks retrying a blocking open, by guest tid, with when they last tried
        std::map<std::int32_t, std::chrono::steady_clock::time_point> wait_r{}, wait_w{};
    };
    // emulated FIFOs by placeholder (dev, ino), and holds to drop once an
    // open lands
    std::map<std::pair<std::uint64_t, std::uint64_t>, EmuFifo> fifos_;
    std::vector<int> fifo_release_;
    // Per-filesystem answer to "does link(2) work here", keyed by st_dev.
    std::unordered_map<std::uint64_t, bool> links_work_;
    bool pending_dir_{false};    // the pending open is a virtual directory
    std::string pending_lazy_;   // overlaid host dir: union built on 1st getdents
    std::vector<kernel::VirtualDirent> pending_entries_;
public:
    // Root writes files whose mode says nobody may write them; linuxity,
    // being an ordinary host user, cannot. So before a write open of a file
    // linuxity owns in the upper that lacks owner write, give the host inode
    // owner read/write and record the real mode in the shadow store -- every
    // guest stat reads that, so the file still looks 0444.
    //
    // At open time rather than when the mode was set, so it also repairs
    // files that reached the upper read-only some other way: an fchmod, an
    // archive extraction, or an older linuxity that applied modes literally.
    // Without it, systemd-machine-id-setup could not write the 0444 file it
    // had just created and concluded /etc was read-only.
    //
    // Only our own files, so the read-only rootfs lower is never touched.
    void grant_root_write(const std::string& abs, const std::string& host) {
        struct ::stat st{};
        if (::stat(host.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return;
        if ((st.st_mode & 0600) == 0600 || st.st_uid != ::getuid()) return;
        const std::uint32_t real = st.st_mode & wire::kPermMask;
        if (::chmod(host.c_str(), static_cast<mode_t>(real | 0600)) != 0) return;
        // A mode recorded earlier is the truth already; only fill in a
        // missing one.
        const auto rec = k_.files().meta().lookup(abs);
        if (!rec || (rec->have & kernel::MetaRecord::kMode) == 0)
            k_.files().meta().set_mode(abs, real);
    }

    // A file the guest just CREATED, as guest root, with a mode that leaves
    // no owner write (0444, as systemd creates /etc/machine-id).
    //
    // Root ignores permission bits; linuxity, an ordinary host user, does
    // not. So the host inode is given owner read/write and the requested
    // mode is recorded in the shadow store, where every stat reads it from.
    // Left at 0444, the guest's very next write to its own new file failed
    // with EACCES. Only when the host mode is actually missing owner access:
    // the common 0644 create is untouched. Only when the inode is the file
    // this open just made (st_nlink 1, owned by us) -- O_CREAT on an existing
    // file does not change its mode, and neither does this.
    void record_created_mode(int fd) {
        // stat through the magic link, not open: an open here is an extra
        // IN_OPEN/IN_CLOSE that inotify watchers see
        if constexpr (!requires { mem_.host_tid(); }) {
            (void)fd;
            return;
        } else {
            char link[64];
            std::snprintf(link, sizeof link, "/proc/%d/fd/%d", mem_.host_tid(), fd);
            struct ::stat st{};
            if (::stat(link, &st) != 0 || !S_ISREG(st.st_mode)) return;
            const std::uint32_t want = st.st_mode & wire::kPermMask;
            if ((want & 0600u) == 0600u || st.st_uid != ::getuid()) return;
            // only now does the host inode need owner rw (root writes 0444)
            const int sfd = open_tracee_fd(fd);
            if (sfd < 0) return;
            if (::fchmod(sfd, want | 0600u) == 0) k_.files().meta().set_mode(pending_open_, want);
            ::close(sfd);
        }
    }

    // Root reads and searches any directory. The host user owns the tree
    // but not always the bits (a guest chmod 0000 lands on the host inode),
    // so give the host owner rwx and keep the guest-visible mode recorded.
    void grant_root_dir_access(const std::string& abs, const std::string& host) {
        struct ::stat st{};
        if (::stat(host.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return;
        if ((st.st_mode & 0700u) == 0700u || st.st_uid != ::geteuid()) return;
        const auto rec = k_.files().meta().lookup(abs);
        if (!rec || (rec->have & kernel::MetaRecord::kMode) == 0)
            k_.files().meta().set_mode(abs, st.st_mode & 07777u);
        (void)::chmod(host.c_str(), (st.st_mode & 07777u) | 0700u);
    }

    // AF_UNIX names the guest gave, by the socket's host inode. bind names
    // the socket itself; connect names its peer. getsockname/getpeername
    // report these instead of the translated host path the kernel holds.
    // `host_tid` is the task the fd belongs to: this runs from a deferred
    // exit hook, after the trap may have moved on to another task.
    void note_socket_name(int host_tid, int fd, const std::string& name, bool binds) {
        const std::uint64_t ino = socket_inode_of(host_tid, fd);
        if (ino == 0) return;
        (binds ? sock_names_ : sock_peers_)[ino] = name;
    }
    [[nodiscard]] static std::uint64_t socket_inode_of(int host_tid, int fd) {
        char link[64], tgt[64];
        std::snprintf(link, sizeof link, "/proc/%d/fd/%d", host_tid, fd);
        const ::ssize_t n = ::readlink(link, tgt, sizeof tgt - 1);
        if (n <= 8) return 0;
        tgt[n] = '\0';
        unsigned long long ino = 0;
        return std::sscanf(tgt, "socket:[%llu]", &ino) == 1 ? ino : 0;
    }
    [[nodiscard]] std::uint64_t socket_inode(int fd) {
        if constexpr (!requires { mem_.host_tid(); }) {
            return 0;
        } else {
            return socket_inode_of(mem_.host_tid(), fd);
        }
    }

    // Does the host refuse the guest a generic netlink socket? Asked once:
    // the tracer runs in the same sandbox as the guest.
    [[nodiscard]] static bool host_refuses_genl() {
#if defined(__linux__)
        static const bool refuses = [] {
            if (std::getenv("LINUXITY_EMULATE_NL80211")) return true;
            const int s = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 16);
            if (s >= 0) { ::close(s); return false; }
            return errno == EACCES || errno == EPERM;
        }();
        return refuses;
#else
        return false;
#endif
    }

    // A request sent on an emulated nl80211 socket: queue the kernel's reply
    // on it and report the request sent. nullopt = not one of ours.
    [[nodiscard]] std::optional<Outcome> nl_answer(int fd, UAddr buf, std::size_t len) {
#if defined(__linux__)
        if (nl_socks_.empty()) return std::nullopt;
        const auto it = nl_socks_.find(socket_inode(fd));
        if (it == nl_socks_.end()) return std::nullopt;
        std::vector<std::uint8_t> req(std::min<std::size_t>(len, 65536));
        if (!req.empty() && !mem_.copy_in(buf, std::as_writable_bytes(std::span{req})))
            return eno(Errno::efault);
        const std::string ifname = "wlan0";
        const auto reply = kernel::nl80211::answer(
            req.data(), req.size(), kernel::nl80211::android_status(), host_ifindex(ifname),
            ifname, static_cast<std::uint32_t>(ids().pid));
        if (!reply.empty()) {
            if (nl_reply_fd_ < 0) nl_reply_fd_ = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            sockaddr_un to{};
            to.sun_family = AF_UNIX;
            std::memcpy(to.sun_path + 1, it->second.data(), it->second.size());
            const auto tl = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + it->second.size());
            (void)::sendto(nl_reply_fd_, reply.data(), reply.size(), MSG_DONTWAIT,
                           reinterpret_cast<sockaddr*>(&to), tl);
        }
        return val(static_cast<std::int64_t>(len));
#else
        (void)fd; (void)buf; (void)len;
        return std::nullopt;
#endif
    }

    // An interface's index from rtnetlink, which Android lets the shell use
    // where it refuses SIOCGIFINDEX. 0 when unknown.
    [[nodiscard]] static std::uint32_t host_ifindex(const std::string& name) {
#if defined(__linux__)
        if (const unsigned i = ::if_nametoindex(name.c_str())) return i;
        const int s = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 0 /*NETLINK_ROUTE*/);
        if (s < 0) return 0;
        struct { nlmsghdr h; ifinfomsg i; } q{};
        q.h.nlmsg_len = sizeof q;
        q.h.nlmsg_type = RTM_GETLINK;
        q.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        q.h.nlmsg_seq = 1;
        std::uint32_t found = 0;
        timeval tv{0, 300000};
        ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        if (::send(s, &q, sizeof q, 0) == static_cast<ssize_t>(sizeof q)) {
            std::vector<char> b(65536);
            for (bool more = true; more && !found;) {
                const ssize_t n = ::recv(s, b.data(), b.size(), 0);
                if (n <= 0) break;
                int left = static_cast<int>(n);
                for (auto* h = reinterpret_cast<nlmsghdr*>(b.data()); NLMSG_OK(h, left);
                     h = NLMSG_NEXT(h, left)) {
                    if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR) { more = false; break; }
                    if (h->nlmsg_type != RTM_NEWLINK) continue;
                    const auto* ifi = static_cast<const ifinfomsg*>(NLMSG_DATA(h));
                    int alen = static_cast<int>(IFLA_PAYLOAD(h));
                    for (auto* a = IFLA_RTA(ifi); RTA_OK(a, alen); a = RTA_NEXT(a, alen))
                        if (a->rta_type == IFLA_IFNAME &&
                            name == static_cast<const char*>(RTA_DATA(a)))
                            found = static_cast<std::uint32_t>(ifi->ifi_index);
                }
            }
        }
        ::close(s);
        return found;
#else
        (void)name;
        return 0;
#endif
    }

    // emulated generic netlink sockets: socket inode -> its abstract name.
    // They live at fds kNlFdLo..kNlFdHi so the filter can trap their sendto
    // alone (seccomp sees fd numbers, not socket types).
    static constexpr std::uint64_t kNlFdLo = 1008, kNlFdHi = 1023;
    std::unordered_map<std::uint64_t, std::string> nl_socks_;
    std::uint32_t nl_seq_{0};
    int nl_reply_fd_{-1};

    // getsockname(fd, addr, len) / getpeername: an AF_UNIX socket the guest
    // named gets its own spelling back, not the translated host path.
    [[nodiscard]] Outcome do_sockname(const Regs& r, bool peer) {
        if (!r.arg[1] || !r.arg[2]) return fwd();
        const std::uint64_t ino = socket_inode(static_cast<int>(r.arg[0]));
        if (ino == 0) return fwd();
        // an emulated netlink socket names itself as netlink does
        if (nl_socks_.count(ino)) {
            std::uint32_t cap = 0;
            if (!mem_.copy_in(uaddr(r.arg[2]), std::as_writable_bytes(std::span{&cap, 1})))
                return eno(Errno::efault);
            std::array<std::uint8_t, 12> nl{};
            nl[0] = 16;                                   // AF_NETLINK
            const auto pid = peer ? 0u : static_cast<std::uint32_t>(ids().pid);
            std::memcpy(nl.data() + 4, &pid, 4);
            const std::size_t n = std::min<std::size_t>(cap, nl.size());
            if (!mem_.copy_out(uaddr(r.arg[1]), std::as_bytes(std::span{nl.data(), n})) ||
                !put_u32(r.arg[2], 12))
                return eno(Errno::efault);
            return val(0);
        }
        const auto& m = peer ? sock_peers_ : sock_names_;
        auto it = m.find(ino);
        if (it == m.end()) {
            // A peer that accepted us: its name is the listener's, which the
            // host shows as our translated path. Translate it back.
            return fwd();
        }
        ArgRewrite ar{0, r.arg[0], ArgRewrite::Convert::unix_name, uaddr(r.arg[1])};
        ar.len = uaddr(r.arg[2]);
        ar.name = it->second;
        return ar;
    }

    // May the calling guest process access `guest` for `want` (4 r, 2 w,
    // 1 x), judged on the mode and owner the guest sees? Absent files pass;
    // the host call that follows reports ENOENT itself.
    [[nodiscard]] bool guest_may(const std::string& guest, int want) {
        // CAP_DAC_OVERRIDE passes every check except exec of a file with no
        // x bit, so skip the lookup for plain read/write.
        if (!(want & 1) && privileged()) return true;
        // /dev/tty is 0666; whether there's a terminal behind it is the
        // ctty check's call, not the slave's mode.
        if (guest == "/dev/tty") return !(want & 1);
        const auto pc = k_.files().classify(guest);
        if (pc.realm != kernel::Realm2::host_backed || pc.host_path.empty()) return true;
        struct ::stat st{};
        if (::stat(pc.host_path.c_str(), &st) != 0) return true;
        std::uint32_t mode = st.st_mode & 07777u;
        if (auto rec = k_.files().meta().lookup(guest); rec && (rec->have & kernel::MetaRecord::kMode))
            mode = rec->mode & 07777u;
        auto [uid, gid] = owner_of(guest);
        auto p = me();
        if (const auto o = pts_owner(guest)) {
            // a pty we never saw handed out: the host says it's ours
            uid = o->first < 0 ? p.uids[3] : static_cast<std::uint32_t>(o->first);
            gid = o->second;
        }
        p.groups = k_.procs().groups_of(p.pid);
        return creds::permitted(p, mode, uid, gid, want, S_ISDIR(st.st_mode));
    }

    // The guest owner of /dev/pts/N: {uid, tty group}, uid -1 when nobody
    // told us. nullopt for any other path. The host's devpts says every pty
    // is linuxity's, which reads as root to the guest.
    [[nodiscard]] std::optional<std::pair<std::int64_t, std::uint32_t>> pts_owner(std::string_view guest) const {
        constexpr std::string_view kPre = "/dev/pts/";
        if (!guest.starts_with(kPre)) return std::nullopt;
        const std::string_view n = guest.substr(kPre.size());
        if (n.empty() || n.find_first_not_of("0123456789") != std::string_view::npos) return std::nullopt;
        constexpr std::uint32_t kTtyGid = 5;
        const auto uid = k_.procs().pty_owner(std::atoi(std::string{n}.c_str()));
        return std::pair<std::int64_t, std::uint32_t>{uid ? std::int64_t{*uid} : -1, kTtyGid};
    }
    [[nodiscard]] bool privileged() { return creds::capable(me(), creds::kCapDacOverride); }

    // A translated host path at or over PATH_MAX fails on the host even when
    // the guest named it relative to a dirfd or its cwd, which have no length
    // limit on Linux. If the call's base dir sits at a prefix of `host`,
    // return the rest so the host walks from there too. In *at calls the
    // dirfd is always the register right before the path.
    [[nodiscard]] std::optional<std::string> rebase_on_dirfd(const Regs& r, int path_arg,
                                                             const std::string& host) {
        constexpr std::size_t kPathMax = 4096;
        constexpr int kAtFdcwd = -100;
        if (host.size() < kPathMax || path_arg < 0) return std::nullopt;
        bool at = false;
        switch (decode(arch_, r.nr)) {
            case Sysno::openat: case Sysno::openat2: case Sysno::mkdirat:
            case Sysno::mknodat: case Sysno::unlinkat: case Sysno::newfstatat:
            case Sysno::statx: case Sysno::fchmodat: case Sysno::fchmodat2:
            case Sysno::fchownat: case Sysno::faccessat: case Sysno::faccessat2:
            case Sysno::utimensat: case Sysno::readlinkat: case Sysno::symlinkat:
            case Sysno::linkat: case Sysno::renameat: case Sysno::renameat2:
                at = path_arg >= 1;
                break;
            default:
                break;
        }
        const int dirfd = at ? static_cast<int>(r.arg[static_cast<std::size_t>(path_arg - 1)])
                             : kAtFdcwd;
        std::string gdir;
        if (dirfd == kAtFdcwd) {
            gdir = k_.files().cwd();
        } else if (dirfd >= 0) {
            gdir = std::string{k_.files().path_of_fd(dirfd)};
        }
        if (gdir.empty()) return std::nullopt;
        const auto pc = k_.files().classify(gdir);
        if (pc.realm != kernel::Realm2::host_backed || pc.host_path.empty()) return std::nullopt;
        const std::string base = pc.host_path.back() == '/' ? pc.host_path : pc.host_path + "/";
        if (host.size() == base.size() - 1 && base.starts_with(host)) return std::string{"."};
        // the shared leading directories, then ".." for each one of the
        // base's that's left, then the rest of the target
        std::size_t common = 0;
        for (std::size_t k = 0; k < base.size() && k < host.size() && base[k] == host[k]; ++k)
            if (base[k] == '/') common = k + 1;
        std::string rest;
        for (std::size_t k = common; k < base.size(); ++k)
            if (base[k] == '/') rest += "../";
        rest += host.substr(std::min(common, host.size()));
        if (rest.empty()) rest = ".";
        if (rest.size() >= kPathMax) return std::nullopt;
        // The host cwd only follows chdir best effort; make sure it's there.
        if (dirfd == kAtFdcwd && !host_cwd_is(pc.host_path)) return std::nullopt;
        return rest;
    }

    // Is the tracee's real host cwd the directory at `host_dir`? Compared by
    // inode, walking the path a component at a time since it may be longer
    // than PATH_MAX.
    [[nodiscard]] bool host_cwd_is(const std::string& host_dir) {
        if constexpr (!requires { mem_.host_tid(); }) {
            return false;
        } else {
            char link[64];
            std::snprintf(link, sizeof link, "/proc/%d/cwd", mem_.host_tid());
            struct ::stat a{}, b{};
            if (::stat(link, &a) != 0) return false;
            const int fd = host::open_long(host_dir, host::kWalkDirFlags);
            if (fd < 0) return false;
            const bool same = ::fstat(fd, &b) == 0 && a.st_dev == b.st_dev && a.st_ino == b.st_ino;
            ::close(fd);
            return same;
        }
    }

    // -- FIFOs on a host that forbids them ---------------------------------
    // The name is an empty regular file marked as a FIFO in the meta store.
    // Each one gets a real kernel pipe, kept by an O_PATH fd on its inode.
    // Every guest open reopens that inode through /proc, so all openers
    // share one pipe and read/write/EOF/SIGPIPE/poll are the kernel's own.
    //
    // Reopening a pipe never blocks the way opening a FIFO does, so a
    // blocking open with nobody at the other end waits in the guest's kernel
    // and retries. When the other end arrives it goes ahead and holds the
    // far end until the waiter's retry lands, so the waiter can't read EOF
    // (or the writer's data be lost) in between.

    [[nodiscard]] Outcome fifo_create(const std::string& abs, const std::string& host,
                                      std::uint32_t mode) {
        // EEXIST against the guest's view, which may be the lower layer
        {
            const auto now = k_.files().classify(abs, false, /*follow=*/false);
            struct ::stat st{};
            if (now.realm == kernel::Realm2::host_backed && !now.host_path.empty() &&
                ::lstat(now.host_path.c_str(), &st) == 0)
                return eno(Errno::eexist);
        }
        for (std::size_t i = host.find('/', 1); i != std::string::npos; i = host.find('/', i + 1))
            (void)::mkdir(host.substr(0, i).c_str(), 0755);
        const int fd = ::open(host.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) return eno(wire::errno_from_host(errno));
        ::close(fd);
        k_.files().clear_whiteout_if_any(abs);
        k_.files().meta().set_mode(abs, mode & 07777u & ~guest_umask());
        k_.files().meta().set_fifo(abs);
        return val(0);
    }

    // An emulated FIFO's open: a shared host pipe handed over through
    // /proc/<pid>/fd, opened O_PATH so it pins the pipe without being an end
    // of it. All three are Linux-host facts; only the Linux launcher enables
    // the emulation (main.cpp, for hosts whose filesystem refuses mkfifo).
#if defined(__linux__)
    [[nodiscard]] Outcome fifo_open(const std::string& abs, const struct ::stat& node,
                                    std::uint64_t flags, int path_arg) {
        // keyed by the placeholder's inode, so a rename keeps the pipe and a
        // new mkfifo at the same name gets a new one
        EmuFifo& f = fifos_[{static_cast<std::uint64_t>(node.st_dev),
                             static_cast<std::uint64_t>(node.st_ino)}];
        if (f.anchor < 0) {
            int p[2];
            if (::pipe2(p, O_CLOEXEC) != 0) return eno(wire::errno_from_host(errno));
            struct ::stat st{};
            (void)::fstat(p[0], &st);
            f.anchor = ::open(self_fd(p[0]).c_str(), O_PATH | O_CLOEXEC);
            ::close(p[0]);
            ::close(p[1]);
            if (f.anchor < 0) return eno(Errno::enfile);
        }
        const std::uint64_t acc = flags & 3u;   // O_RDONLY 0, O_WRONLY 1, O_RDWR 2
        const bool nonblock = wire::has_for(arch_, flags, wire::OpenFlag::nonblock);
        const auto [readers, writers] = fifo_peers(f.anchor);
        const auto now = std::chrono::steady_clock::now();
        // a waiter that hasn't retried in a while gave up (or died)
        auto alive = [&](std::map<std::int32_t, std::chrono::steady_clock::time_point>& m) {
            std::erase_if(m, [&](const auto& e) { return now - e.second > std::chrono::milliseconds{500}; });
            return !m.empty();
        };
        const std::int32_t me = ids().tid;
        f.wait_r.erase(me);
        f.wait_w.erase(me);
        const bool reader_waiting = alive(f.wait_r), writer_waiting = alive(f.wait_w);
        auto hold = [&](int& h, int mode) {
            if (h < 0) h = ::open(self_fd(f.anchor).c_str(), mode | O_NONBLOCK | O_CLOEXEC);
        };
        constexpr std::int64_t kRetryNs = 10'000'000;   // 10 ms
        if (acc == 0 && !nonblock) {
            // a writer is here, came and left data (hold_r), or is waiting
            if (writers == 0 && f.hold_r < 0 && !writer_waiting) {
                f.wait_r[me] = now;
                return Virtualize::retry_after(kRetryNs);
            }
            if (writers == 0 && f.hold_r < 0) hold(f.hold_w, O_WRONLY);   // until it lands
        } else if (acc == 1) {
            // the reader goes first: a blocking writer waits until one has
            // really opened (or opened and is holding the write end for us)
            const bool reader_open = readers > 0 || f.hold_w >= 0;
            if (!reader_open && nonblock) {
                // a reader blocked in open counts, as in the kernel; keep
                // what this writer sends until that reader lands
                if (!reader_waiting) return eno(Errno::enxio);
                hold(f.hold_r, O_RDONLY);
            } else if (!reader_open) {
                f.wait_w[me] = now;
                return Virtualize::retry_after(kRetryNs);
            }
        }
        // the end held for us is replaced by ours once the open lands
        if (acc != 1 && f.hold_r >= 0) fifo_release_.push_back(std::exchange(f.hold_r, -1));
        if (acc != 0 && f.hold_w >= 0) fifo_release_.push_back(std::exchange(f.hold_w, -1));
        pending_open_ = abs;
        pending_flags_ = flags;
        return Redirect{PathArg{path_arg, "/proc/" + std::to_string(::getpid()) +
                                              "/fd/" + std::to_string(f.anchor)}};
    }

    [[nodiscard]] static std::string self_fd(int fd) {
        return "/proc/self/fd/" + std::to_string(fd);
    }
#endif

    // -- the guest's kernel log ----------------------------------------------
    void kmsg_add(int prio, std::string text) {
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
        const double up = machine().uptime_seconds();
        kmsg_.push_back({kmsg_seq_++, static_cast<std::uint64_t>(up * 1e6), prio, std::move(text)});
        if (kmsg_.size() > 4096) kmsg_.erase(kmsg_.begin(), kmsg_.begin() + 1024);
    }
    // The first records a kernel logs at boot, from what linuxity knows is
    // true of this machine.
    void kmsg_seed() {
        if (kmsg_seq_) return;
        const auto& m = machine();
        auto at = [&](double t, int prio, std::string s) {
            kmsg_.push_back({kmsg_seq_++, static_cast<std::uint64_t>(t * 1e6), prio, std::move(s)});
        };
        at(0, 5, "Linux version " + m.release + " (linuxity@" + m.nodename +
                    ") (linuxity portable Linux ABI) #1");
        at(0, 6, "Machine model: linuxity " + m.machine_arch);
        at(0, 6, "Memory: " + std::to_string(m.mem_total >> 10) + "K available");
        at(0.000001, 6, "smp: Brought up 1 node, " + std::to_string(m.ncpu) + " CPUs");
        at(0.000002, 6, "clocksource: Switched to clocksource " +
                            std::string{m.machine_arch == "aarch64" ? "arch_sys_counter" : "tsc"});
        at(0.000003, 6, "Run /sbin/init as init process");
    }
    // Pick up whatever guest writers have put into their pipes. Each write
    // is one record; "<N>" at the front sets its level, like the kernel.
    void kmsg_drain() {
        char buf[8192];
        for (auto it = kmsg_writers_.begin(); it != kmsg_writers_.end();) {
            const ::ssize_t n = ::read(*it, buf, sizeof buf);
            if (n > 0) {
                std::string_view s{buf, static_cast<std::size_t>(n)};
                int prio = 12;   // LOG_USER | LOG_WARNING, the kernel's default
                if (s.size() > 2 && s[0] == '<') {
                    const auto close = s.find('>');
                    if (close != std::string_view::npos && close < 5) {
                        prio = std::atoi(std::string{s.substr(1, close - 1)}.c_str());
                        s.remove_prefix(close + 1);
                    }
                }
                kmsg_add(prio, std::string{s});
                continue;   // more may be queued
            }
            if (n == 0) { ::close(*it); it = kmsg_writers_.erase(it); continue; }   // all closed
            ++it;   // EAGAIN: nothing yet
        }
    }
    // Open /dev/kmsg: a reader gets a packet pipe holding the records, one
    // per read, then EOF; a writer gets a pipe linuxity drains into the log.
    // (O_DIRECT packet pipes and F_SETPIPE_SZ are Linux's; elsewhere the
    // guest opens the overlay's node and syslog(2) still serves the log.)
#if defined(__linux__)
    [[nodiscard]] Outcome kmsg_open(std::uint64_t flags, int path_arg, bool proc_style = false) {
        kmsg_seed();
        kmsg_drain();
        int p[2];
        const int pflags = O_CLOEXEC | O_NONBLOCK | (proc_style ? 0 : O_DIRECT);
        if (::pipe2(p, pflags) != 0) return eno(wire::errno_from_host(errno));
        const std::uint64_t acc = flags & 3u;
        int give;
        if (acc == 1 && !proc_style) {   // write-only
            (void)::fcntl(p[0], F_SETPIPE_SZ, 1 << 20);
            kmsg_writers_.push_back(p[0]);
            give = p[1];
        } else {
            (void)::fcntl(p[1], F_SETPIPE_SZ, 1 << 20);
            for (const auto& r : kmsg_) {
                if (r.seq < kmsg_cleared_) continue;
                char head[64];
                if (proc_style)
                    std::snprintf(head, sizeof head, "<%d>", r.prio & 7);
                else
                    std::snprintf(head, sizeof head, "%d,%llu,%llu,-;", r.prio,
                                  static_cast<unsigned long long>(r.seq),
                                  static_cast<unsigned long long>(r.ts_us));
                const std::string rec = head + r.text + "\n";
                if (::write(p[1], rec.data(), rec.size()) < 0) break;
            }
            ::close(p[1]);
            give = p[0];
        }
        fifo_release_.push_back(give);   // our copy goes once the guest has its own
        pending_open_ = proc_style ? "/proc/kmsg" : "/dev/kmsg";
        pending_flags_ = 0;
        return Redirect{PathArg{path_arg, "/proc/" + std::to_string(::getpid()) +
                                              "/fd/" + std::to_string(give)}};
    }
#endif
    // syslog(2)/klogctl over the same log, in its classic text form.
    [[nodiscard]] Outcome do_syslog(const Regs& r) {
        kmsg_seed();
        kmsg_drain();
        const int type = static_cast<int>(r.arg[0]);
        auto text = [&](bool from_clear) {
            std::string s;
            for (const auto& k : kmsg_) {
                if (from_clear && k.seq < kmsg_cleared_) continue;
                char head[48];
                std::snprintf(head, sizeof head, "<%d>[%5llu.%06llu] ", k.prio & 7,
                              static_cast<unsigned long long>(k.ts_us / 1000000),
                              static_cast<unsigned long long>(k.ts_us % 1000000));
                s += head + k.text + "\n";
            }
            return s;
        };
        switch (type) {
            case 0: case 1: return val(0);                       // close, open
            case 2: case 3: case 4: {                            // read, read all, read+clear
                const std::string all = text(true);
                const std::size_t cap = static_cast<std::size_t>(r.arg[2]);
                if (static_cast<std::int64_t>(r.arg[2]) < 0) return eno(Errno::einval);
                const std::string_view out = std::string_view{all}.substr(all.size() > cap ? all.size() - cap : 0);
                if (!out.empty() && !mem_.copy_out(uaddr(r.arg[1]),
                        {reinterpret_cast<const std::byte*>(out.data()), out.size()}))
                    return eno(Errno::efault);
                if (type == 4) kmsg_cleared_ = kmsg_seq_;
                return val(static_cast<std::int64_t>(out.size()));
            }
            case 5: kmsg_cleared_ = kmsg_seq_; return val(0);  // clear
            case 6: case 7: case 8: return val(0);               // console on/off/level
            case 9: return val(0);                               // unread bytes
            case 10: return val(1 << 17);                        // buffer size
            default: return eno(Errno::einval);
        }
    }

    // How many guest fds have the anchor's pipe open for reading and writing.
    // The supervisor's own holds aren't guest fds, so they don't count.
    [[nodiscard]] std::pair<int, int> fifo_peers(int anchor) {
        int rd = 0, wr = 0;
        if constexpr (requires { mem_.host_tgids(); }) {
            struct ::stat ast{};
            if (::fstat(anchor, &ast) != 0) return {0, 0};
            const std::string want = "pipe:[" + std::to_string(ast.st_ino) + "]";
            for (const ::pid_t pid : mem_.host_tgids()) {
                const std::string dir = "/proc/" + std::to_string(pid) + "/fd";
                ::DIR* d = ::opendir(dir.c_str());
                if (!d) continue;
                while (const ::dirent* e = ::readdir(d)) {
                    if (e->d_name[0] == '.') continue;
                    char tgt[64];
                    const std::string link = dir + "/" + e->d_name;
                    const ::ssize_t n = ::readlink(link.c_str(), tgt, sizeof tgt);
                    if (n != static_cast<::ssize_t>(want.size()) || want.compare(0, want.size(), tgt, static_cast<std::size_t>(n)) != 0)
                        continue;
                    const unsigned acc = fdinfo_flags(pid, e->d_name) & 3u;
                    if (acc != 1) ++rd;
                    if (acc != 0) ++wr;
                }
                ::closedir(d);
            }
        }
        return {rd, wr};
    }

    [[nodiscard]] static unsigned fdinfo_flags(::pid_t pid, const char* fd) {
        const std::string p = "/proc/" + std::to_string(pid) + "/fdinfo/" + fd;
        std::FILE* f = std::fopen(p.c_str(), "re");
        if (!f) return 0;
        char line[128];
        unsigned out = 0;
        while (std::fgets(line, sizeof line, f))
            if (std::sscanf(line, "flags: %o", &out) == 1) break;
        std::fclose(f);
        return out;
    }

    // The calling task's umask, from /proc ("Umask:\t0022"), or the distro's.
    [[nodiscard]] std::uint32_t guest_umask() {
        if constexpr (requires { mem_.host_tid(); }) {
            const std::string p = "/proc/" + std::to_string(mem_.host_tid()) + "/status";
            if (std::FILE* f = std::fopen(p.c_str(), "re")) {
                char line[128];
                unsigned m = 022;
                bool got = false;
                while (!got && std::fgets(line, sizeof line, f))
                    got = std::sscanf(line, "Umask: %o", &m) == 1;
                std::fclose(f);
                if (got) return m;
            }
        }
        return 022;
    }

    // The open state note_opened_fd needs, taken out of the dispatcher so a
    // call that finishes later (a blocking FIFO open) can apply it then.
    struct PendingOpen {
        std::int32_t pid{0}, ppid{0};
        std::string path;
        std::uint64_t flags{0};
    };
    [[nodiscard]] PendingOpen take_pending_open() {
        auto id = ids();
        PendingOpen p{id.pid, id.ppid, std::exchange(pending_open_, {}), pending_flags_};
        pending_dir_ = false;
        pending_lazy_.clear();
        pending_entries_.clear();
        return p;
    }
    void finish_pending_open(PendingOpen p, std::int64_t fd) {
        k_.files().set_current_pid(p.pid, p.ppid);
        pending_open_ = std::move(p.path);
        // only an existing FIFO is deferred, so O_CREAT made nothing
        pending_flags_ = p.flags & ~static_cast<std::uint64_t>(wire::OpenFlag::creat);
        note_opened_fd(fd);
    }

    // A hard link is the same inode, so the new name gets the source's
    // owner and mode. They're kept per path, so copy them over.
    void note_linked(const std::string& src, const std::string& dst) {
        auto& m = k_.files().meta();
        const auto rec = m.lookup(src);
        if (!rec) return;
        const bool hu = rec->have & kernel::MetaRecord::kUid, hg = rec->have & kernel::MetaRecord::kGid;
        if (hu || hg) m.set_owner(dst, hu ? rec->uid : 0xffffffffu, hg ? rec->gid : 0xffffffffu);
        if (rec->have & kernel::MetaRecord::kMode) m.set_mode(dst, rec->mode);
    }

    // A rename went through: guest path `from` is now `to`. The kernel ties a
    // landlock rule to the inode, so the rule moves with it; ours are keyed
    // by path, so rewrite them, in rule sets being built and in live domains.
    void note_moved(const std::string& from, const std::string& to) {
        namespace ll = kernel::landlock;
        if (ll_sets_.empty() && ll_layers_ == 0) return;
        auto fix = [&](std::string& p) {
            if (ll::under(p, from) && from != "/") p = to + p.substr(from.size());
        };
        for (auto& [ino, rs] : ll_sets_)
            for (auto& rule : rs.paths) fix(rule.path);
        // a domain is shared by every process that inherited it: give each
        // distinct one a single rewritten copy
        std::map<const void*, ll::Domain> done;
        for (const std::int32_t pid : k_.procs().pids()) {
            auto* p = k_.procs().find_mut(pid);
            if (!p || !p->landlock) continue;
            auto [it, fresh] = done.try_emplace(p->landlock.get());
            if (fresh) {
                auto layers = *p->landlock;
                for (auto& l : layers)
                    for (auto& rule : l.rules.paths) fix(rule.path);
                it->second = std::make_shared<const std::vector<ll::Layer>>(std::move(layers));
            }
            p->landlock = it->second;
        }
    }

    // A file this guest process just created: its owner is the creator's
    // fsuid, its group the fsgid or, under a setgid directory, the
    // directory's group (and a new subdirectory inherits the setgid bit).
    // Root creating as root is the default view, so that records nothing.
    void note_created(const std::string& guest, bool is_dir) {
        const auto& p = me();
        const std::string parent = guest.substr(0, std::max<std::size_t>(guest.rfind('/'), 1));
        std::uint32_t gid = p.gids[3];
        bool sgid_parent = false;
        if (auto rec = k_.files().meta().lookup(parent); rec && (rec->have & kernel::MetaRecord::kMode))
            sgid_parent = (rec->mode & 02000u) != 0;
        else {
            const auto pc = k_.files().classify(parent);
            struct ::stat st{};
            sgid_parent = pc.realm == kernel::Realm2::host_backed &&
                          ::stat(pc.host_path.c_str(), &st) == 0 && (st.st_mode & S_ISGID);
        }
        if (sgid_parent) gid = owner_of(parent).second;
        if (p.uids[3] != 0 || gid != 0) k_.files().meta().set_owner(guest, p.uids[3], gid);
        if (is_dir && sgid_parent) {
            const auto pc = k_.files().classify(guest);
            struct ::stat st{};
            std::uint32_t m = 0755;
            if (auto rec = k_.files().meta().lookup(guest); rec && (rec->have & kernel::MetaRecord::kMode))
                m = rec->mode;
            else if (pc.realm == kernel::Realm2::host_backed && ::stat(pc.host_path.c_str(), &st) == 0)
                m = st.st_mode & 07777u;
            k_.files().meta().set_mode(guest, m | 02000u);
        }
    }

    // Does the guest see anything at `abs` (without following a final link)?
    [[nodiscard]] bool guest_exists(const std::string& abs) {
        const auto pc = k_.files().classify(abs, false, /*follow=*/false);
        if (pc.realm == kernel::Realm2::virtual_file) return true;
        if (pc.realm != kernel::Realm2::host_backed || pc.host_path.empty()) return false;
        struct ::stat st{};
        return ::lstat(pc.host_path.c_str(), &st) == 0;
    }

    // The trap calls this after a redirect/inject syscall returns a real fd,
    // so the namespace can bind the guest path to that fd (readlinkat etc.),
    // and — for a virtual directory — the entries getdents64 will enumerate.
    void note_opened_fd(std::int64_t fd) {
        // holds an emulated-FIFO open replaced; the guest's end is in place now
        for (const int h : std::exchange(fifo_release_, {})) ::close(h);
        if (fd >= 0) {
            // A newly opened fd REPLACES whatever that number meant before.
            //
            // close(2) is deliberately untrapped on the seccomp filter (it
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
            // the rights this file keeps: those of the layers in force now
            if (ll_layers_ > 0)
                if (const auto* p = k_.procs().find(ids().pid); p && p->landlock)
                    k_.files().set_fd_ll_layers(static_cast<int>(fd),
                                                static_cast<std::uint32_t>(p->landlock->size()));
            k_.files().bind_fd(static_cast<int>(fd), pending_open_);
            if (const auto [cp, ct] = std::exchange(pending_comm_, {0, 0}); cp)
                if (auto host = tracee_fd_target(static_cast<int>(fd)); !host.empty()) {
                    apply_comm_writes();
                    std::erase_if(comm_files_, [&](const CommFile& c) {
                        return c.pid == cp && c.tid == ct;
                    });
                    comm_files_.push_back({std::move(host), cp, ct, {}});
                }
            if (auto pm = std::exchange(pending_map_, {}); pm.first)
                if (auto host = tracee_fd_target(static_cast<int>(fd)); !host.empty())
                    map_files_.push_back({std::move(host), pm.first, std::move(pm.second)});
            // The create succeeded, so an upper-layer file now shadows the
            // lower one: the path is no longer deleted. classify() leaves the
            // whiteout in place for a parents_only create (it must still be
            // deleted while O_EXCL asks whether the name is taken), so this
            // is where it gets dropped.
            if (wire::has(static_cast<std::uint64_t>(pending_flags_),
                          wire::OpenFlag::creat)) {
                k_.files().clear_whiteout_if_any(pending_open_);
                record_created_mode(static_cast<int>(fd));
                if (std::exchange(pending_new_, false)) note_created(pending_open_, false);
            }

            // The OTHER way to get a controlling terminal, besides
            // TIOCSCTTY: a session leader with no ctty that opens a terminal
            // without O_NOCTTY acquires it. Most programs rely on exactly
            // this and never call TIOCSCTTY at all -- util-linux `script`
            // does not, which is why bash under it still had no terminal
            // and printed "cannot set terminal process group".
            if (pending_open_.starts_with("/dev/pts/") &&
                (pending_flags_ & static_cast<std::uint64_t>(wire::OpenFlag::noctty)) == 0) {
                const std::int32_t me = ids().pid;
                if (k_.procs().sid_of(me) == me && caller_ctty() < 0) {
                    const std::int32_t n = pty_slave_of_fd(static_cast<int>(fd));
                    if (n >= 0) k_.procs().set_ctty(me, n);
                }
            }
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
        } else if (const auto o = pts_owner(s.guest_path)) {
            uid = o->first < 0 ? me().uids[3] : static_cast<std::uint32_t>(o->first);
            gid = o->second;
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
        if (rec && (rec->have & (kernel::MetaRecord::kMode | kernel::MetaRecord::kFifo))) {
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
        // The placeholder an abstract-namespace bind left (see do_sockaddr_un)
        // is a socket to the guest. Only while it's still the empty file we
        // made; anything else at that name now is what it says it is.
        if (!s.guest_path.empty() && sock_placeholders_.count(s.guest_path)) {
            const std::uint32_t m = is_statx ? get_u16(base + mode_off) : get_u32(base + mode_off);
            if ((m & 0170000u) == 0100000u) {
                const std::uint32_t sm = (m & ~0170000u) | 0140000u;
                if (is_statx) put_u16(base + mode_off, static_cast<std::uint16_t>(sm));
                else          (void)put_u32(base + mode_off, sm);
            } else {
                sock_placeholders_.erase(s.guest_path);
            }
        }
        // st_nlink, for an inode whose extra names are EMULATED (see
        // link_table.hpp): the host sees one name and one placeholder per
        // alias, so it says 1 where Linux would count every name. Ask the
        // table, keyed by the backing file this path resolves to.
        if (L.nlink_width != 0 && !s.guest_path.empty() &&
            !k_.files().links().empty()) {
            const auto pc = k_.files().classify(s.guest_path, false, false);
            if (pc.realm == kernel::Realm2::host_backed &&
                k_.files().links().has_aliases(pc.host_path)) {
                const std::uint32_t n = k_.files().links().count(pc.host_path);
                if (L.nlink_width == 8) (void)put_u64(base + L.nlink, n);
                else                    (void)put_u32(base + L.nlink, n);
            }
        }
        // statx filled by the host carries the HOST's mount id, which means
        // nothing against our mount table; restate it as write_statx would.
        if (is_statx && !s.guest_path.empty()) {
            const auto mo = k_.files().mount_of(s.guest_path);
            constexpr std::uint32_t kMntId = 0x1000, kMntIdUnique = 0x4000;
            constexpr std::uint64_t kMountRoot = 0x2000;
            // offsets: stx_mask 0, stx_attributes 8, stx_blocks 48,
            // stx_attributes_mask 56, stx_mnt_id 144
            constexpr std::uint64_t kMaskOff = 0, kAttrOff = 8, kMnt = 144, kAttrMask = 56;
            (void)put_u32(base + kMaskOff, get_u32(base + kMaskOff) | kMntId | kMntIdUnique);
            (void)put_u64(base + kMnt, mo.id);
            (void)put_u64(base + kAttrMask, get_u64(base + kAttrMask) | kMountRoot);
            const std::uint64_t a = get_u64(base + kAttrOff);
            (void)put_u64(base + kAttrOff, mo.root ? (a | kMountRoot) : (a & ~kMountRoot));
        }
    }

    // Small typed guest-memory pokes/peeks for the scrub overlay.
    // Returns false if the guest buffer could not be written -- an unmapped
    // or read-only address, which the kernel answers with EFAULT. The result
    // used to be discarded, so a handler that wrote through a bad pointer
    // reported success: getresuid(0x1,0x1,0x1) returned 0 where the kernel
    // returns -1. Callers that can fail must check it.

    // If `fd` is a pty master, the number of its slave, else -1.
    [[nodiscard]] std::int32_t pty_master_slave(int fd) {
        if constexpr (!requires { mem_.host_tid(); }) {
            return -1;
        } else {
            const int sfd = open_tracee_fd(fd);
            if (sfd < 0) return -1;
            unsigned n = 0;
            // The libc's own TIOCGPTN: its type is whatever this libc's
            // ioctl takes (glibc unsigned long, musl int), which a spelled-out
            // 0x80045430 overflowed on musl.
#if defined(TIOCGPTN)
            const bool is_master = ::ioctl(sfd, TIOCGPTN, &n) == 0;
#else
            const bool is_master = false;
#endif
            ::close(sfd);
            return is_master ? static_cast<std::int32_t>(n) : -1;
        }
    }

    // The pty slave NUMBER behind an fd, or -1 if the fd is not a pty slave.
    //
    // The fd table already records the guest path every open resolved to, and
    // the guest spelling of a slave is always /dev/pts/N (devfs maps that to
    // whatever the host calls it), so the number is a parse away. An fd we
    // never tracked answers -1 rather than guessing.
    [[nodiscard]] std::int32_t pty_slave_of_fd(int fd) {
        const std::string_view gp = k_.files().path_of_fd(fd);
        constexpr std::string_view kPre = "/dev/pts/";
        if (!gp.starts_with(kPre)) return -1;
        const std::string_view n = gp.substr(kPre.size());
        if (n.empty() || n.find_first_not_of("0123456789") != std::string_view::npos)
            return -1;
        return static_cast<std::int32_t>(std::atoi(std::string{n}.c_str()));
    }

    // Is `fd` this process's CONTROLLING terminal?
    //
    // The gate on every session ioctl. A non-tty is ENOTTY, and so is a pty
    // the caller never claimed -- opening a slave O_NOCTTY gives you a
    // terminal that is not yours, which is exactly the case the ioctls probe
    // caught us faking success on.
    //
    // An fd with no recorded path but a live ctty is accepted: the guest's
    // terminal is usually INHERITED (fd 0/1/2 from the launching shell), so
    // it was never opened through us and has no tracked path. That is the
    // common case for an interactive session, not an edge case.
    [[nodiscard]] bool fd_is_our_ctty(int fd) {
        const std::int32_t have = caller_ctty();
        const std::int32_t n = pty_slave_of_fd(fd);
        if (n >= 0) return have == n;
        // Untracked fd (bash reaches the terminal as dup(2)->9, dup3(9,255),
        // and a dup of an INHERITED fd has no path to mirror). The fd lives
        // in the tracee, so read what the host says it points at: our pid
        // view is the host's, so /proc/<pid>/fd/<n> resolves it.
        return have >= 0 && host_fd_slave_no(fd) == have;
    }

    // The pty slave number the HOST says `fd` refers to, or -1.
    //
    // Reads /proc/<tid>/fd/<fd> in the tracee. That is the only way to
    // identify an fd we never saw opened -- and an inherited-then-duped
    // terminal is the common case, not an edge case.
    [[nodiscard]] std::int32_t host_fd_slave_no(int fd) {
        if constexpr (requires { mem_.host_fd_of(0); }) {
            // a kernel-less backend holds the real fd itself: ask the host
            // which pty it is (ttyname: /dev/pts/N or /dev/ttysNNN)
            const int h = mem_.host_fd_of(fd);
            char name[128];
            if (h < 0 || ::ttyname_r(h, name, sizeof name) != 0) return -1;
            return lx::vfs::pty_slave_number(name);
        } else if constexpr (!requires { mem_.host_tid(); }) {
            return -1;   // no tracee /proc to consult
        } else {
            char link[64];
            std::snprintf(link, sizeof link, "/proc/%d/fd/%d", mem_.host_tid(), fd);
            char tgt[128];
            const ssize_t k = ::readlink(link, tgt, sizeof tgt - 1);
            if (k <= 0) return -1;
            tgt[k] = '\0';
            return lx::vfs::pty_slave_number(tgt);
        }
    }

    // A terminal ioctl ('T' type), minus the generic FIO* ones files accept.
    [[nodiscard]] static bool is_tty_request(std::uint64_t req) noexcept {
        if (((req >> 8) & 0xff) != 'T') return false;
        switch (req & 0xffff) {
            case 0x541B: case 0x5421: case 0x5450: case 0x5451:   // FIONREAD FIONBIO FIONCLEX FIOCLEX
            case 0x5452: case 0x5460:                            // FIOASYNC FIOQSIZE
                return false;
            default: return true;
        }
    }

    // The host path the tracee's fd points at, or "".
    [[nodiscard]] std::string tracee_fd_target(int fd) {
        if constexpr (requires { mem_.host_fd_of(fd); }) {
#if defined(F_GETPATH)
            // A backend whose guest fds are OUR host fds (HVF): ask the fd.
            const int h = mem_.host_fd_of(fd);
            char p[PATH_MAX];
            if (h >= 0 && ::fcntl(h, F_GETPATH, p) == 0) return p;
#endif
        }
        if constexpr (!requires { mem_.host_tid(); }) {
            return {};
        } else {
            char link[64], tgt[4096];
            std::snprintf(link, sizeof link, "/proc/%d/fd/%d", mem_.host_tid(), fd);
            const ssize_t k = ::readlink(link, tgt, sizeof tgt - 1);
            return k > 0 ? std::string(tgt, static_cast<std::size_t>(k)) : std::string{};
        }
    }

    // Is the tracee's fd a regular file or directory on the host?
    [[nodiscard]] bool host_fd_is_file(int fd) {
        if constexpr (!requires { mem_.host_tid(); }) {
            return false;
        } else {
            char link[64];
            std::snprintf(link, sizeof link, "/proc/%d/fd/%d", mem_.host_tid(), fd);
            struct ::stat st{};
            return ::stat(link, &st) == 0 && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode));
        }
    }

    // Is the tracee's fd either end of a pty?
    [[nodiscard]] bool host_fd_is_pty(int fd) {
        if (pty_slave_of_fd(fd) >= 0 || host_fd_slave_no(fd) >= 0) return true;
        if constexpr (!requires { mem_.host_tid(); }) {
            return false;
        } else {
            char link[64];
            std::snprintf(link, sizeof link, "/proc/%d/fd/%d", mem_.host_tid(), fd);
            char tgt[64];
            const ssize_t k = ::readlink(link, tgt, sizeof tgt - 1);
            if (k <= 0) return false;
            tgt[k] = '\0';
            return std::string_view{tgt}.ends_with("ptmx");
        }
    }

    // Does the host's policy refuse TCSBRK on a pty? Asked once.
    [[nodiscard]] static bool host_refuses_tcsbrk() {
#if defined(_WIN32)
        return false;
#else
        static const bool refuses = [] {
            const int m = ::posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
            if (m < 0) return false;
            bool r = false;
            if (::grantpt(m) == 0 && ::unlockpt(m) == 0)
                if (const char* n = ::ptsname(m)) {
                    const int s = ::open(n, O_RDWR | O_NOCTTY | O_CLOEXEC);
                    if (s >= 0) {
                        r = ::ioctl(s, 0x5409, 1) != 0 && errno == EACCES;
                        ::close(s);
                    }
                }
            ::close(m);
            return r;
        }();
        return refuses;
#endif
    }

    // How to refuse a session ioctl on an fd we do not own.
    //
    // Two different refusals, and picking the wrong one is a conformance bug:
    //
    //   - a real TERMINAL that is not ours: FORWARD, and let the host say
    //     why. Its reason may outrank "not your controlling terminal" --
    //     Android's SELinux answers EACCES for TIOCGSID on a pty where a
    //     desktop kernel answers ENOTTY, and only the host knows which.
    //     Answering ENOTTY from here hid the denial, and the on-device
    //     golden caught it at `ioctls` step 25.
    //   - anything else (a plain file, a pipe, a closed fd): ENOTTY from
    //     here. ENOTTY is the kernel's answer for those on every host, and
    //     forwarding an fd we never tracked risks acting on the wrong thing.
    [[nodiscard]] Outcome ctty_refusal(const Regs& r) {
        const int fd = static_cast<int>(r.arg[0]);
        if (pty_slave_of_fd(fd) >= 0 || host_fd_slave_no(fd) >= 0)
            return fwd();
        return eno(Errno::enotty);
    }

    // Open the tracee's fd `fd` for reading, as a descriptor of OURS.
    //
    // /proc/<tid>/fd/<n> is a magic link: opening it reopens the underlying
    // inode, even when the link TEXT is unusable. That is what makes an
    // O_TMPFILE reachable -- its text renders "/dir/#1234 (deleted)", which
    // no open() would accept, while opening the magic link itself works.
    //
    // Returns -1 when the backend exposes no host tid, or the open fails.
    [[nodiscard]] int open_tracee_fd(int fd) {
        if constexpr (requires { mem_.host_fd_of(fd); } && !requires { mem_.host_tid(); }) {
            const int h = mem_.host_fd_of(fd);
            return h >= 0 ? ::fcntl(h, F_DUPFD_CLOEXEC, 0) : -1;
        } else if constexpr (!requires { mem_.host_tid(); }) {
            return -1;
        } else {
            char link[64];
            std::snprintf(link, sizeof link, "/proc/%d/fd/%d",
                          mem_.host_tid(), fd);
            return ::open(link, O_RDONLY | O_CLOEXEC);
        }
    }

    // A synthesized file is a snapshot taken at open. Rereading it from offset
    // 0 should give fresh contents, as the kernel's seq_file does, so produce
    // it again and rewrite the temp behind the guest's fd. Monitors keep
    // /proc/<pid>/stat open and pread it every tick.
    void refresh_virtual_fd(int fd) {
        if constexpr (requires { mem_.host_tid(); } || requires { mem_.host_fd_of(fd); }) {
            const std::string gp{k_.files().path_of_fd(fd)};
            if (gp.empty() || k_.files().is_virtual_dir_fd(fd)) return;
            const auto pc = k_.files().classify(gp);
            if (pc.realm != kernel::Realm2::virtual_file) return;
            const std::string& vp = pc.virtual_path.empty() ? gp : pc.virtual_path;
            auto vf = k_.files().produce(vp);
            if (!vf || vf->is_dir || !vf->redirect_host.empty() || !vf->symlink_target.empty())
                return;
            int w = -1;
            if constexpr (requires { mem_.host_tid(); }) {
                char link[64];
                std::snprintf(link, sizeof link, "/proc/%d/fd/%d", mem_.host_tid(), fd);
                w = ::open(link, O_WRONLY | O_CLOEXEC);
            } else {
                // the guest's fd is OUR host fd: write the temp behind it
                if (const std::string t = tracee_fd_target(fd); !t.empty()) w = ::open(t.c_str(), O_WRONLY | O_CLOEXEC);
            }
            if (w < 0) return;
            std::size_t off = 0;
            while (off < vf->bytes.size()) {
                const auto n = ::pwrite(w, vf->bytes.data() + off, vf->bytes.size() - off,
                                        static_cast<off_t>(off));
                if (n <= 0) break;
                off += static_cast<std::size_t>(n);
            }
            if (off == vf->bytes.size()) (void)::ftruncate(w, static_cast<off_t>(off));
            ::close(w);
        } else {
            (void)fd;
        }
    }

    // Does the host kernel enforce Landlock? Asked once.
    // guest processes that Landlocked themselves (a fork inherits it)
    std::set<std::int32_t> landlocked_;

    // -- landlock kept by us, for a host whose kernel has none --------------
    // Rule sets under construction, keyed by the inode of the fd the guest
    // holds for each (a memfd it made), so dup, fork and close need no help.
    std::map<std::uint64_t, kernel::landlock::Ruleset> ll_sets_;
    std::uint64_t ll_next_domain_{1};
    int ll_layers_{0};   // processes restricted so far; 0 skips the gate

    // The inode behind guest fd `fd`, or 0.
    [[nodiscard]] std::uint64_t ll_fd_ino(int fd) {
        if constexpr (!requires { mem_.host_tid(); }) {
            (void)fd;
            return 0;
        } else {
            char link[64];
            std::snprintf(link, sizeof link, "/proc/%d/fd/%d", mem_.host_tid(), fd);
            struct ::stat st{};
            return ::stat(link, &st) == 0 ? static_cast<std::uint64_t>(st.st_ino) : 0;
        }
    }
    [[nodiscard]] std::uint64_t u64_at(std::uint64_t at) {
        std::array<std::byte, 8> b{};
        if (!mem_.copy_in(uaddr(at), b)) return 0;
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < 8; ++i)
            v |= static_cast<std::uint64_t>(std::to_integer<unsigned>(b[i])) << (i * 8);
        return v;
    }

    // landlock_create_ruleset(attr, size, flags)
    [[nodiscard]] Outcome do_ll_create_ruleset(const Regs& r) {
        namespace ll = kernel::landlock;
        const std::uint64_t flags = r.arg[2];
        if (flags == 1 /*VERSION*/) {
            if (r.arg[0] || r.arg[1]) return eno(Errno::einval);
            return val(ll::kAbi);
        }
        if (flags == 2 /*ERRATA*/) return val(0);
        if (flags != 0) return eno(Errno::einval);
        const std::size_t size = static_cast<std::size_t>(r.arg[1]);
        if (size < 8) return eno(Errno::einval);
        if (size > 4096) return eno(Errno::e2big);
        ll::Ruleset rs;
        rs.handled_fs = u64_at(r.arg[0]);
        if (size >= 16) rs.handled_net = u64_at(r.arg[0] + 8);
        if (size >= 24) rs.scoped = u64_at(r.arg[0] + 16);
        if ((rs.handled_fs & ~ll::kAllFs) || (rs.handled_net & ~ll::kAllNet) ||
            (rs.scoped & ~ll::kAllScope))
            return eno(Errno::einval);
        if (!rs.handled_fs && !rs.handled_net && !rs.scoped) return eno(Errno::enomsg);
        GuestCalls gc;
        gc.strings = {"landlock-ruleset"};
        gc.steps = {{Sysno::memfd_create, {GuestCalls::str0, 1u /*MFD_CLOEXEC*/, 0, 0, 0, 0}}};
        gc.before_resume = [this, rs = std::move(rs)](std::int64_t fd) mutable {
            if (fd >= 0)
                if (const auto ino = ll_fd_ino(static_cast<int>(fd))) ll_sets_[ino] = std::move(rs);
        };
        return gc;
    }

    // landlock_add_rule(ruleset_fd, type, attr, flags)
    [[nodiscard]] Outcome do_ll_add_rule(const Regs& r) {
        namespace ll = kernel::landlock;
        if (r.arg[3] != 0) return eno(Errno::einval);
        auto it = ll_sets_.find(ll_fd_ino(static_cast<int>(r.arg[0])));
        if (it == ll_sets_.end()) return eno(Errno::ebadf);
        ll::Ruleset& rs = it->second;
        if (r.arg[2] == 0) return eno(Errno::efault);
        const std::uint64_t access = u64_at(r.arg[2]);
        if (r.arg[1] == 1 /*PATH_BENEATH*/) {
            std::array<std::byte, 4> fb{};
            if (!mem_.copy_in(uaddr(r.arg[2] + 8), fb)) return eno(Errno::efault);
            std::int32_t pfd = 0;
            std::memcpy(&pfd, fb.data(), 4);
            if (access == 0) return eno(Errno::enomsg);
            if (access & ~rs.handled_fs) return eno(Errno::einval);
            std::string gp{k_.files().path_of_fd(pfd)};
            if (gp.empty()) return eno(Errno::ebadf);
            gp = k_.files().resolve_links(gp);
            // rights that only a directory can hold, on something else
            const auto pc = k_.files().classify(gp);
            bool dir = false;
            if (pc.realm == kernel::Realm2::host_backed) {
                struct ::stat st{};
                dir = ::stat(pc.host_path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
            } else if (pc.realm == kernel::Realm2::virtual_file) {
                if (auto vf = k_.files().produce(gp)) dir = vf->is_dir;
            }
            if (!dir && (access & ll::kDirOnly)) return eno(Errno::einval);
            rs.paths.push_back({std::move(gp), access});
            return val(0);
        }
        if (r.arg[1] == 2 /*NET_PORT*/) {
            const std::uint64_t port = u64_at(r.arg[2] + 8);
            if (access == 0) return eno(Errno::enomsg);
            if (access & ~rs.handled_net) return eno(Errno::einval);
            if (port > 65535) return eno(Errno::einval);
            rs.ports.push_back({port, access});
            return val(0);
        }
        return eno(Errno::einval);
    }

    // landlock_restrict_self(ruleset_fd, flags)
    [[nodiscard]] Outcome do_ll_restrict_self(const Regs& r) {
        namespace ll = kernel::landlock;
        if (r.arg[1] != 0) return eno(Errno::einval);   // ABI 6 has no flags
        auto it = ll_sets_.find(ll_fd_ino(static_cast<int>(r.arg[0])));
        if (it == ll_sets_.end()) return eno(Errno::ebadf);
        auto& p = me();
        // the kernel's rule: no_new_privs, or CAP_SYS_ADMIN in the namespace
        if (!p.no_new_privs && !creds::capable(p, 21)) return eno(Errno::eperm);
        auto layers = p.landlock ? *p.landlock : std::vector<ll::Layer>{};
        if (layers.size() >= 16) return eno(Errno::e2big);
        layers.push_back({it->second, ll_next_domain_++});
        p.landlock = std::make_shared<const std::vector<ll::Layer>>(std::move(layers));
        ++ll_layers_;
        return val(0);
    }

    // Which access a call needs, checked against the caller's domain: the
    // same hooks fs/landlock attaches in the kernel. EACCES when refused.
    [[nodiscard]] Errno ll_gate(Sysno sc, const Regs& r) {
        namespace ll = kernel::landlock;
        const auto* self = k_.procs().find(ids().pid);
        if (!self || !self->landlock) return Errno::ok;
        const ll::Domain& d = self->landlock;
        // the object a path names (links followed unless told otherwise)
        auto obj = [&](int arg, bool at, bool follow = true) {
            return k_.files().resolve_links(resolve_arg(r, arg, at, follow));
        };
        auto parent = [](const std::string& p) {
            const auto s = p.rfind('/');
            return s == 0 || s == std::string::npos ? std::string{"/"} : p.substr(0, s);
        };
        auto exists = [&](const std::string& p, bool* dir = nullptr) {
            const auto pc = k_.files().classify(p, false, /*follow=*/false);
            if (pc.realm == kernel::Realm2::virtual_file) {
                if (dir) if (auto vf = k_.files().produce(p)) *dir = vf->is_dir;
                return true;
            }
            struct ::stat st{};
            if (pc.realm != kernel::Realm2::host_backed || ::lstat(pc.host_path.c_str(), &st) != 0) return false;
            if (dir) *dir = S_ISDIR(st.st_mode);
            return true;
        };
        auto need = [&](const std::string& p, std::uint64_t want) {
            return ll::allows(d, p, want) ? Errno::ok : Errno::eacces;
        };
        // the make-right a new node of mknod `mode` needs on its directory
        auto make_right = [](std::uint32_t mode) -> std::uint64_t {
            switch (mode & 0170000u) {
                case 0020000u: return ll::kMakeChar;
                case 0060000u: return ll::kMakeBlock;
                case 0010000u: return ll::kMakeFifo;
                case 0140000u: return ll::kMakeSock;
                default:       return ll::kMakeReg;
            }
        };
        auto open_check = [&](int arg, bool at, std::uint64_t flags) {
            if (wire::has_for(arch_, flags, wire::OpenFlag::path)) return Errno::ok;
            const bool nofollow = wire::has_for(arch_, flags, wire::OpenFlag::nofollow);
            const std::string p = obj(arg, at, !nofollow);
            bool dir = false;
            if (!exists(p, &dir)) {
                if (!wire::has(flags, wire::OpenFlag::creat)) return Errno::ok;   // ENOENT is the host's
                return need(parent(p), ll::kMakeReg);
            }
            std::uint64_t want = 0;
            const std::uint64_t acc = flags & 3u;
            if (dir) want |= ll::kReadDir;
            else {
                if (acc == 0 || acc == 2) want |= ll::kReadFile;
                if (acc == 1 || acc == 2) want |= ll::kWriteFile;
                if (wire::has(flags, wire::OpenFlag::trunc)) want |= ll::kTruncate;
            }
            return need(p, want);
        };
        // rename/link: make-rights where it lands, remove-rights where it
        // leaves (rename), and REFER when it changes directory
        auto move_check = [&](int a1, int a2, bool at, bool keep_src) {
            const std::string src = obj(a1, at, false), dst = obj(a2, at, false);
            bool dir = false;
            if (!exists(src, &dir)) return Errno::ok;
            const std::uint64_t make = dir ? ll::kMakeDir : ll::kMakeReg;
            if (const Errno e = need(parent(dst), make); e != Errno::ok) return e;
            if (!keep_src)
                if (const Errno e = need(parent(src), dir ? ll::kRemoveDir : ll::kRemoveFile); e != Errno::ok)
                    return e;
            if (parent(src) != parent(dst)) {
                if (const Errno e = need(parent(src), ll::kRefer); e != Errno::ok) return Errno::exdev;
                if (const Errno e = need(parent(dst), ll::kRefer); e != Errno::ok) return Errno::exdev;
            }
            return Errno::ok;
        };
        switch (sc) {
            case Sysno::open:    return open_check(0, false, r.arg[1]);
            case Sysno::openat:  return open_check(1, true, r.arg[2]);
            case Sysno::creat:   return open_check(0, false, 0101u | 01000u);
            case Sysno::openat2: return open_check(1, true, u64_at(r.arg[2]));
            case Sysno::execve:  return need(obj(0, false), ll::kExecute);
            case Sysno::execveat:return need(obj(1, true), ll::kExecute);
            case Sysno::truncate:return need(obj(0, false), ll::kTruncate);
            case Sysno::ftruncate:
            case Sysno::ioctl: {
                const int fd = static_cast<int>(r.arg[0]);
                const std::uint32_t upto = k_.files().fd_ll_layers(fd);
                if (upto == 0) return Errno::ok;   // opened before any restriction
                const std::string p{k_.files().path_of_fd(fd)};
                if (p.empty()) return Errno::ok;
                const std::string real = k_.files().resolve_links(p);
                if (sc == Sysno::ftruncate)
                    return ll::allows(d, real, ll::kTruncate, upto) ? Errno::ok : Errno::eacces;
                // IOCTL_DEV covers char and block devices only
                if (ll::ioctl_always_ok(static_cast<std::uint32_t>(r.arg[1]))) return Errno::ok;
                const auto pc = k_.files().classify(real);
                struct ::stat st{};
                if (pc.realm != kernel::Realm2::host_backed || ::stat(pc.host_path.c_str(), &st) != 0 ||
                    !(S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)))
                    return Errno::ok;
                return ll::allows(d, real, ll::kIoctlDev, upto) ? Errno::ok : Errno::eacces;
            }
            case Sysno::mkdir:   return need(parent(obj(0, false, false)), ll::kMakeDir);
            case Sysno::mkdirat: return need(parent(obj(1, true, false)), ll::kMakeDir);
            case Sysno::mknod:   return need(parent(obj(0, false, false)), make_right(static_cast<std::uint32_t>(r.arg[1])));
            case Sysno::mknodat: return need(parent(obj(1, true, false)), make_right(static_cast<std::uint32_t>(r.arg[2])));
            case Sysno::symlink: return need(parent(obj(1, false, false)), ll::kMakeSym);
            case Sysno::symlinkat: return need(parent(obj(2, true, false)), ll::kMakeSym);
            case Sysno::unlink:  return need(parent(obj(0, false, false)), ll::kRemoveFile);
            case Sysno::rmdir:   return need(parent(obj(0, false, false)), ll::kRemoveDir);
            case Sysno::unlinkat:
                return need(parent(obj(1, true, false)),
                            wire::has_at(r.arg[2], wire::AtFlag::removedir) ? ll::kRemoveDir : ll::kRemoveFile);
            case Sysno::rename:    return move_check(0, 1, false, false);
            case Sysno::renameat:
            case Sysno::renameat2: return move_check(1, 3, true, false);
            case Sysno::link:      return move_check(0, 1, false, true);
            case Sysno::linkat:    return move_check(1, 3, true, true);
            case Sysno::kill:
            case Sysno::tkill:
            case Sysno::tgkill: {
                if (!ll::scopes(d, ll::kScopeSignal)) return Errno::ok;
                const auto target = static_cast<std::int32_t>(r.arg[sc == Sysno::tgkill ? 1 : 0]);
                if (target <= 0) return Errno::ok;   // groups: each member is checked by the kernel's rule below
                const auto* t = k_.procs().find(target);
                if (!t || target == ids().pid) return Errno::ok;
                return ll::within(t->landlock, d) ? Errno::ok : Errno::eperm;
            }
            case Sysno::bind:
            case Sysno::connect: {
                if (sc == Sysno::connect)
                    if (const Errno e = ll_abstract_scope(d, r.arg[1], r.arg[2]); e != Errno::ok) return e;
                // TCP ports, for an inet stream socket
                std::array<std::byte, 4> sa{};
                if (r.arg[1] == 0 || !mem_.copy_in(uaddr(r.arg[1]), sa)) return Errno::ok;
                const unsigned fam = std::to_integer<unsigned>(sa[0]) | (std::to_integer<unsigned>(sa[1]) << 8);
                if (fam != 2 && fam != 10) return Errno::ok;
                const std::uint64_t want = sc == Sysno::bind ? ll::kBindTcp : ll::kConnectTcp;
                if (!std::any_of(d->begin(), d->end(), [&](const ll::Layer& l) { return l.rules.handled_net & want; }))
                    return Errno::ok;
                const int hfd = fetch_guest_fd(static_cast<int>(r.arg[0]));
                if (hfd < 0) return Errno::ok;
                int type = 0, proto = 0;
                ::socklen_t tl = sizeof type, pl = sizeof proto;
                (void)::getsockopt(hfd, SOL_SOCKET, SO_TYPE, &type, &tl);
#if defined(SO_PROTOCOL)
                (void)::getsockopt(hfd, SOL_SOCKET, SO_PROTOCOL, &proto, &pl);
#else
                (void)pl;   // no SO_PROTOCOL (Darwin): an inet stream socket is TCP
#endif
                ::close(hfd);
                if (type != SOCK_STREAM || (proto != 0 && proto != 6 /*IPPROTO_TCP*/)) return Errno::ok;
                const std::uint64_t port = (std::to_integer<unsigned>(sa[2]) << 8) | std::to_integer<unsigned>(sa[3]);
                return ll::allows_port(d, port, want) ? Errno::ok : Errno::eacces;
            }
            case Sysno::sendto:
                return ll_abstract_scope(d, r.arg[4], r.arg[5]);
            case Sysno::sendmsg: {
                // msghdr: msg_name at +0, msg_namelen (u32) at +8
                if (r.arg[1] == 0) return Errno::ok;
                const std::uint64_t name = u64_at(r.arg[1]);
                const std::uint64_t namelen = u64_at(r.arg[1] + 8) & 0xffffffffu;
                return ll_abstract_scope(d, name, namelen);
            }
            default:
                return Errno::ok;
        }
    }

    // LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: a scoped process may only reach an
    // abstract socket whose owner is in its own domain or one nested inside.
    // The owner is found when asked (the netns's socket table, then which
    // process holds that socket), so a failed bind can't claim a name.
    [[nodiscard]] Errno ll_abstract_scope(const kernel::landlock::Domain& d, std::uint64_t addr,
                                          std::uint64_t len) {
        namespace ll = kernel::landlock;
        if (!ll::scopes(d, ll::kScopeAbstractUnix) || addr == 0 || len < 3 || len > 110) return Errno::ok;
        std::vector<std::byte> sa(len);
        if (!mem_.copy_in(uaddr(addr), sa)) return Errno::ok;
        if (std::to_integer<unsigned>(sa[0]) != 1 || std::to_integer<unsigned>(sa[1]) != 0) return Errno::ok;
        if (std::to_integer<unsigned>(sa[2]) != 0) return Errno::ok;   // a path, not abstract
        // the table shows an abstract name as '@' + name, NULs as '@' too
        std::string want = "@";
        for (std::size_t i = 3; i < len; ++i) {
            const char c = static_cast<char>(std::to_integer<unsigned>(sa[i]));
            want += c == '\0' ? '@' : c;
        }
        if constexpr (!requires { mem_.host_tid(); }) {
            return Errno::ok;
        } else {
            std::set<std::string> inodes;
            {
                const std::string table = "/proc/" + std::to_string(mem_.host_tid()) + "/net/unix";
                FILE* f = std::fopen(table.c_str(), "r");
                if (!f) return Errno::ok;
                char line[512];
                while (std::fgets(line, sizeof line, f)) {
                    std::string l{line};
                    while (!l.empty() && (l.back() == '\n' || l.back() == '\r')) l.pop_back();
                    // Num RefCount Protocol Flags Type St Inode Path
                    std::size_t pos = 0;
                    std::vector<std::string> cols;
                    for (int c = 0; c < 7; ++c) {
                        while (pos < l.size() && l[pos] == ' ') ++pos;
                        const auto end = l.find(' ', pos);
                        cols.push_back(l.substr(pos, end - pos));
                        pos = end == std::string::npos ? l.size() : end;
                    }
                    while (pos < l.size() && l[pos] == ' ') ++pos;
                    if (cols.size() == 7 && l.substr(pos) == want) inodes.insert(cols[6]);
                }
                std::fclose(f);
            }
            if (inodes.empty()) return Errno::ok;   // nobody bound it: the host says ECONNREFUSED
            // which of our processes holds it
            for (const std::int32_t pid : k_.procs().pids()) {
                const int host = k_.procs().host_of(pid);
                if (host <= 0) continue;
                const std::string dir = "/proc/" + std::to_string(host) + "/fd";
                DIR* dd = ::opendir(dir.c_str());
                if (!dd) continue;
                bool held = false;
                while (const auto* e = ::readdir(dd)) {
                    char tgt[64];
                    const std::string link = dir + "/" + e->d_name;
                    const ::ssize_t n = ::readlink(link.c_str(), tgt, sizeof tgt - 1);
                    if (n <= 9) continue;
                    tgt[n] = '\0';
                    std::string_view t{tgt};
                    if (t.starts_with("socket:[") && t.ends_with("]") &&
                        inodes.count(std::string{t.substr(8, t.size() - 9)})) { held = true; break; }
                }
                ::closedir(dd);
                if (held) {
                    const auto* owner = k_.procs().find(pid);
                    return owner && ll::within(owner->landlock, d) ? Errno::ok : Errno::eperm;
                }
            }
            return Errno::eperm;   // held outside the guest tree: outside the domain
        }
    }
    // Is `pid` under a Landlock domain? The domain is inherited, so walk up.
    [[nodiscard]] bool is_landlocked(std::int32_t pid) const {
        if (landlocked_.empty()) return false;
        for (int hops = 0; hops < 64 && pid > 0; ++hops) {
            if (landlocked_.count(pid)) return true;
            const auto* p = k_.procs().find(pid);
            if (!p || p->ppid == pid) return false;
            pid = p->ppid;
        }
        return false;
    }
    [[nodiscard]] static bool host_has_landlock() {
#if defined(__linux__)
        // LINUXITY_NO_HOST_LANDLOCK=1 runs our own, to test it on a host
        // that has one
        static const bool yes = !std::getenv("LINUXITY_NO_HOST_LANDLOCK") &&
                                ::syscall(444, nullptr, 0, 1 /*VERSION*/) >= 1;
        return yes;
#else
        return false;
#endif
    }

    // Bring a guest fd into the tracer. -1 if we can't (no pidfd_getfd).
    [[nodiscard]] int fetch_guest_fd(int fd) {
        if constexpr (!requires { mem_.host_tid(); }) {
            return -1;
        } else {
#if defined(__linux__)
            const int pfd = static_cast<int>(::syscall(434 /*pidfd_open*/, mem_.host_tid(), 0));
            if (pfd < 0) return -1;
            const int out = static_cast<int>(::syscall(438 /*pidfd_getfd*/, pfd, fd, 0));
            ::close(pfd);
            return out;
#else
            (void)fd;
            return -1;
#endif
        }
    }

    // landlock_add_rule(ruleset, PATH_BENEATH, {access, parent_fd}, 0): the
    // parent fd names a guest directory, which may be several host
    // directories (an overlay's upper and lower). Add the rule to the
    // guest's own ruleset, through a copy of its fd, once per host layer.
    [[nodiscard]] Outcome do_landlock_add_rule(const Regs& r) {
#if defined(__linux__)
        if (r.arg[1] != 1 /*PATH_BENEATH*/) return fwd();
        if (r.arg[2] == 0) return eno(Errno::efault);
        struct __attribute__((packed)) { std::uint64_t access; std::int32_t parent; } attr{};
        if (!mem_.copy_in(uaddr(r.arg[2]), std::as_writable_bytes(std::span{&attr, 1})))
            return eno(Errno::efault);
        // the fd was opened through any symlink in its name, so the rule is
        // for where that lands
        const std::string guest = [&] {
            std::string g{k_.files().path_of_fd(attr.parent)};
            return g.empty() ? g : k_.files().resolve_links(g);
        }();
        const auto layers = guest.empty() ? std::vector<std::string>{} : k_.files().host_layers(guest);
        if (layers.empty()) return fwd();   // a path we don't translate: the host's answer
        const int rs = fetch_guest_fd(static_cast<int>(r.arg[0]));
        if (rs < 0) return fwd();
        // A rule granting writes on a directory that so far lives only in the
        // lower layer must also cover the upper one, where those writes will
        // land: make it now (with its parent chain), as a copy-up would.
        constexpr std::uint64_t kWrites = ~std::uint64_t{(1u << 0) | (1u << 2) | (1u << 3)};
        if ((attr.access & kWrites) && layers.size() > 1) {
            for (std::size_t i = 1; i <= layers[0].size(); ++i)
                if (i == layers[0].size() || layers[0][i] == '/')
                    (void)::mkdir(layers[0].substr(0, i).c_str(), 0755);
        }
        int added = 0, err = 0;
        for (const auto& h : layers) {
            const int d = ::open(h.c_str(), O_PATH | O_CLOEXEC);
            if (d < 0) continue;   // a layer the path doesn't exist in yet
            struct __attribute__((packed)) { std::uint64_t a; std::int32_t p; } one{attr.access, d};
            if (::syscall(445 /*landlock_add_rule*/, rs, 1, &one, 0) == 0) ++added;
            else err = errno;
            ::close(d);
        }
        ::close(rs);
        if (added) return val(0);
        return eno(wire::errno_from_host(err ? err : ENOENT));
#else
        (void)r;
        return fwd();
#endif
    }

    // Was this guest fd opened O_PATH?
    //
    // Read it from the tracee's /proc rather than tracking it ourselves: the
    // fd may have been inherited or duped, and fdinfo is the authority the
    // host kernel already maintains. A missing fdinfo answers "no", so the
    // caller falls through to its normal path.
    [[nodiscard]] bool fd_is_o_path(int fd) {
        if constexpr (!requires { mem_.host_tid(); }) {
            return false;
        } else {
            char p[64];
            std::snprintf(p, sizeof p, "/proc/%d/fdinfo/%d", mem_.host_tid(), fd);
            std::FILE* f = std::fopen(p, "re");
            if (f == nullptr) return false;
            char line[128];
            unsigned long long fl = 0;
            bool have = false;
            while (std::fgets(line, sizeof line, f) != nullptr)
                if (std::sscanf(line, "flags:\t%llo", &fl) == 1) { have = true; break; }
            std::fclose(f);
            // O_PATH is 010000000 on every Linux arch.
            return have && (fl & 010000000ULL) != 0;
        }
    }

    // Does link(2) work on the filesystem holding `near`?
    //
    // Asked once and cached: the answer is a property of the host's policy,
    // not of the call. Android denies the SELinux `link` permission on
    // /data for every process, so probing per-call would cost two syscalls
    // on every hardlink for an answer that never changes.
    [[nodiscard]] bool host_links_work(const std::string& near) {
        // Test hook: behave as a host that refuses link(2) (Android), so the
        // emulation can be exercised by the suite on a host where links work.
        static const bool forced = std::getenv("LINUXITY_FORCE_LINK_EMULATION") != nullptr;
        if (forced) return false;
        const std::size_t slash = near.find_last_of('/');
        if (slash == std::string::npos) return false;
        const std::string dir = near.substr(0, slash);
        // Keyed by the DIRECTORY's filesystem, not cached once globally.
        // One answer for the whole run was wrong: the probe ran first on a
        // path where links work and the result was then reused for
        // /dev/shm, where they do not, so glibc's sem_open got a forwarded
        // link(2) and EACCES. st_dev names the filesystem exactly.
        struct ::stat dst{};
        if (::stat(dir.c_str(), &dst) != 0) return false;
        if (const auto it = links_work_.find(static_cast<std::uint64_t>(dst.st_dev));
            it != links_work_.end())
            return it->second;
        const std::string a = dir + "/.lx-linkprobe-a";
        const std::string b = dir + "/.lx-linkprobe-b";
        ::unlink(a.c_str());
        ::unlink(b.c_str());
        const int fd = ::open(a.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) return false;   // unwritable: do not cache a guess
        ::close(fd);
        const bool works = ::link(a.c_str(), b.c_str()) == 0;
        ::unlink(a.c_str());
        ::unlink(b.c_str());
        links_work_[static_cast<std::uint64_t>(dst.st_dev)] = works;
        return works;
    }

    [[nodiscard]] bool put_u64(std::uint64_t addr, std::uint64_t v) {
        std::array<std::byte, 8> b{};
        std::memcpy(b.data(), &v, 8);
        return static_cast<bool>(mem_.copy_out(uaddr(addr), b));
    }

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
    [[nodiscard]] std::uint64_t get_u64(std::uint64_t addr) {
        std::array<std::byte, 8> b{};
        if (!mem_.copy_in(uaddr(addr), b)) return 0;
        std::uint64_t v = 0; std::memcpy(&v, b.data(), 8); return v;
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
