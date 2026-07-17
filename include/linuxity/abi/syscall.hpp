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
#include "linuxity/loader/interp.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace lx::abi {

// The trapped register file: 6 args + the raw (arch-specific) syscall number.
struct Regs {
    std::array<std::uint64_t, 6> arg{};
    std::uint64_t nr{};
};

// The outcome of servicing one syscall: the value to place in the guest's
// return register, whether to FORWARD it to the host kernel instead, and
// whether the guest asked to terminate.
//
// Two additional fates exist for the virtualized filesystem:
//
//   * REDIRECT — the guest named a HostFs-backed path; we rewrite the path
//     argument (register `path_arg`) to point at the translated *real host
//     path* placed in the child's scratch page, then let the host kernel run
//     the (now-redirected) syscall. This is how native ld.so mmaps real
//     library files while the guest still sees only linuxity's namespace.
//
//   * INJECT — the guest opened a purely virtual file (procfs/tmpfs); we
//     materialize its bytes into a host memfd and splice that fd into the
//     child, returning the fd number. Reads and mmaps then hit real memory.
struct Outcome {
    std::int64_t ret{};
    bool         forward{false};   // let the host kernel run it in the guest
    bool         exited{false};
    int          exit_code{0};

    bool         redirect{false};  // rewrite a path arg, then forward
    int          path_arg{0};      // which arg register holds the char* path
    std::string  host_path;        // translated real host path to splice in

    // A SECOND path arg to translate in the same call (rename/link/symlink,
    // whose two operands are BOTH guest paths). When path_arg2 >= 0 the trap
    // pokes host_path2 into that register too before forwarding. For symlink
    // the FIRST operand is the link's literal text (a guest path stored as
    // data, NOT resolved on the host) — only the destination is translated,
    // so symlink sets path_arg2 to the destination and leaves path_arg = -1.
    int          path_arg2{-1};
    std::string  host_path2;

    // Ensure the parent host directory of host_path exists before forwarding.
    // A create into a freshly-materialized overlay upper dir would ENOENT if
    // the intermediate dirs were never made; a package manager relies on
    // `mkdir -p` semantics being implicit under the upper layer.
    bool         make_parents{false};

    bool                inject{false};  // splice a host memfd, return its fd
    bool                inject_dir{false}; // the injected node is a directory
    std::vector<std::byte> content;     // bytes to back the injected fd

    // SIGNAL - the guest issued kill/tgkill/tkill against a GUEST pid. Guest
    // pids are linuxity's own tiny namespace, unrelated to host pids, so we
    // must NOT forward the raw number (it would hit an unrelated host task).
    // The loop translates the target guest pid to its real host tid and
    // delivers the real signal there.
    bool         signal{false};
    std::int32_t sig_pid{0};       // target GUEST pid (0 => current task)
    std::int32_t sig_num{0};       // signal number to deliver

    // EXEC_INTERP - the guest execve'd a DYNAMIC binary. The host kernel would
    // resolve its PT_INTERP against the host root and fail, so we rewrite the
    // exec into `interp_host <prog_guest> <orig-argv...>`: the child execs the
    // real interpreter, which then opens the program + its libraries through
    // redirected syscalls inside the rootfs. path_arg names the execve's path
    // register; the trap rebuilds argv in the child before forwarding.
    bool         exec_interp{false};
    std::string  interp_host;      // real host path of the dynamic linker
    std::string  prog_guest;      // guest path of the program (new argv[0..1])
    // Extra argv tokens inserted BETWEEN the interpreter (argv[0]) and the
    // program. For a plain dynamic ELF this is empty. For a `#!` script it
    // carries the shebang's optional argument (e.g. "-e" from `#!/bin/sh -e`)
    // and, when the script's interpreter is ITSELF dynamic, the interpreter's
    // own host path (so argv = ld.so, /bin/sh-host, [-e], script-guest, ...).
    std::vector<std::string> interp_prefix;

    // POST-REDIRECT id scrub. Host-backed stat/lstat/newfstatat/statx are
    // REDIRECTED, so the host kernel fills the guest buffer with the HOST
    // file's uid/gid (whatever user unpacked the rootfs). linuxity presents a
    // root-owned world, so after the redirect returns 0 we read the buffer
    // back and rewrite the owner fields to 0. scrub_stat names the buffer
    // address and which layout to patch.
    enum class ScrubKind : std::uint8_t { none, stat, statx };
    ScrubKind    scrub{ScrubKind::none};
    UAddr        scrub_buf{};
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
            case Sysno::tkill:
                return sig(static_cast<std::int32_t>(r.arg[0]),
                           static_cast<std::int32_t>(r.arg[1]));
            case Sysno::tgkill:
                return sig(static_cast<std::int32_t>(r.arg[1]),
                           static_cast<std::int32_t>(r.arg[2]));

            // -- identity + credentials. Each task answers with ITS OWN
            //    guest pid/tid/ppid (from the trap's live task map) so every
            //    process sees a coherent identity, not a fixed "pid 1". A
            //    backend without the identity bridge falls back to init.
            case Sysno::getpid:  return val(ids().pid);
            case Sysno::gettid:  return val(ids().tid);
            case Sysno::getppid: return val(ids().ppid);
            case Sysno::getuid:  case Sysno::geteuid:
            case Sysno::getgid:  case Sysno::getegid:
                return val(0);

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

            // -- getpgrp: our process group is the caller's own pid.
            case Sysno::getpgrp: return val(ids().pid);

            // -- process groups & sessions. These read/write PIDs, so
            //    forwarding would leak host pgids/sids into linuxity's world.
            //    We model a flat namespace: a task's group and session are
            //    its own pid (or the argument for get*id of another task).
            case Sysno::getpgid:
                return val(r.arg[0] ? static_cast<std::int64_t>(r.arg[0])
                                    : ids().pid);
            case Sysno::getsid:
                return val(r.arg[0] ? static_cast<std::int64_t>(r.arg[0])
                                    : ids().pid);
            case Sysno::setpgid:  return val(0);   // accepted, flat model
            case Sysno::setsid:   return val(ids().pid);  // new session == pid
            case Sysno::getpriority: return val(0);       // nice 0
            case Sysno::setpriority: return val(0);

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
            case Sysno::stat:        return path_stat(r, 0, false, true);
            case Sysno::lstat:       return path_stat(r, 0, false, false);
            case Sysno::access:      return path_at(r, 0, false);
            case Sysno::chdir:       return do_chdir(r);
            case Sysno::newfstatat:  return path_stat(r, 1, true);
            case Sysno::statx:       return path_statx(r);
            case Sysno::faccessat:
            case Sysno::faccessat2:  return path_at(r, 1, true);
            case Sysno::readlink:    return do_readlink(r, 0, false);
            case Sysno::readlinkat:  return do_readlink(r, 1, true);
            case Sysno::getcwd:      return do_getcwd(r);
            case Sysno::getdents64:  return do_getdents64(r);

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
            case Sysno::mkdir:      return path_mut(r, 0, false, Wi::parents_only);
            case Sysno::mkdirat:    return path_mut(r, 1, true,  Wi::parents_only);
            case Sysno::mknod:      return path_mut(r, 0, false, Wi::parents_only);
            case Sysno::mknodat:    return path_mut(r, 1, true,  Wi::parents_only);
            case Sysno::rmdir:      return path_mut(r, 0, false, Wi::remove);
            case Sysno::unlink:     return path_mut(r, 0, false, Wi::remove);
            case Sysno::unlinkat:   return path_mut(r, 1, true,  Wi::remove);
            case Sysno::chmod:      return path_mut(r, 0, false, Wi::copy_leaf);
            case Sysno::fchmodat:   return path_mut(r, 1, true,  Wi::copy_leaf);
            // chown/chgrp: linuxity presents a ROOT-OWNED world (every stat is
            // scrubbed to uid=gid=0), and the guest itself runs as uid 0. But
            // the real host process is UNPRIVILEGED, so a forwarded chown to
            // uid 0 would fail EPERM — breaking `apk add`, `tar -p`, `install`.
            // Since ownership is already virtually root, chown is a vacuous
            // no-op: accept it and report success without touching the host.
            case Sysno::chown:
            case Sysno::lchown:
            case Sysno::fchown:
            case Sysno::fchownat:   return val(0);
            case Sysno::truncate:   return path_mut(r, 0, false, Wi::copy_leaf);
            case Sysno::utimes:     return path_mut(r, 0, false, Wi::copy_leaf);
            case Sysno::utime:      return path_mut(r, 0, false, Wi::copy_leaf);
            case Sysno::utimensat:  return path_mut(r, 1, true,  Wi::copy_leaf);
            case Sysno::futimesat:  return path_mut(r, 1, true,  Wi::copy_leaf);
            // fchmod/ftruncate/fchdir act on an already-open fd (no path) —
            // the fd is real, so just forward. (fchown is handled above as a
            // vacuous no-op alongside the other chown forms.)
            case Sysno::fchmod:
            case Sysno::ftruncate:
            case Sysno::fchdir:     return fwd();

            // -- TWO-PATH mutations: both operands are guest paths. rename /
            //    link translate both; symlink stores its first operand as the
            //    link's literal text (guest-absolute, NOT resolved on the
            //    host) and translates only the destination.
            case Sysno::rename:     return path_mut2(r, 0, 1, false, false);
            case Sysno::renameat:   return path_mut2(r, 1, 3, true,  true);
            case Sysno::renameat2:  return path_mut2(r, 1, 3, true,  true);
            case Sysno::link:       return path_mut2(r, 0, 1, false, false);
            case Sysno::linkat:     return path_mut2(r, 1, 3, true,  true);
            case Sysno::symlink:    return path_symlink(r, 0, 1, false);
            case Sysno::symlinkat:  return path_symlink(r, 0, 2, true);

            // -- everything else: FORWARD to the real host kernel. -------
            // Memory (mmap/brk/mprotect) MUST run in the child so it gets
            // real pages in its own address space; file I/O, arch_prctl,
            // ioctl, clock, random, etc. likewise need real host action.
            // This is what carries native libc all the way to main().
            default:
                return fwd();
        }
    }

private:
    static Outcome val(std::int64_t v) { Outcome o{}; o.ret = v; return o; }
    static Outcome fwd() { Outcome o{}; o.forward = true; return o; }
    static Outcome sig(std::int32_t pid, std::int32_t signum) {
        Outcome o{}; o.signal = true; o.sig_pid = pid; o.sig_num = signum;
        return o;
    }
    static Outcome eno(Errno e) { return val(-static_cast<std::int64_t>(e)); }

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
    [[nodiscard]] std::string read_cstr(UAddr a) {
        std::string s;
        std::array<std::byte, 64> chunk{};
        std::uint64_t off = 0;
        for (;;) {
            if (!mem_.copy_in(uaddr(value(a) + off), chunk)) break;
            for (std::byte b : chunk) {
                char c = static_cast<char>(b);
                if (c == '\0') return s;
                s.push_back(c);
                if (s.size() > 4096) return s;
            }
            off += chunk.size();
        }
        return s;
    }

    // The path bound to a guest dirfd, or empty for AT_FDCWD (-100).
    [[nodiscard]] std::string_view dir_of(std::int64_t dirfd) const {
        constexpr std::int64_t kAtFdCwd = -100;
        if (dirfd == kAtFdCwd) return {};
        return k_.files().path_of_fd(static_cast<int>(dirfd));
    }

    // Resolve arg-carried path to an absolute, normalized guest path.
    [[nodiscard]] std::string resolve_arg(const Regs& r, int path_arg, bool at) {
        std::string raw = read_cstr(uaddr(r.arg[static_cast<std::size_t>(path_arg)]));
        std::string_view dir = at ? dir_of(static_cast<std::int64_t>(r.arg[0]))
                                  : std::string_view{};
        return k_.files().absolutize(raw, dir);
    }

    // open/openat: translate to a host-backed path (REDIRECT) or synthesize a
    // virtual file into a memfd (INJECT). Either way the child ends up with a
    // real fd it can read AND mmap — so native ld.so works.
    [[nodiscard]] Outcome path_open(const Regs& r, int path_arg, bool at) {
        std::string abs = resolve_arg(r, path_arg, at);
        // Open flags follow the path arg: openat(dirfd,path,flags,mode) ->
        // arg[2]; open(path,flags,mode) -> arg[1]. Write intent (O_WRONLY /
        // O_RDWR / O_CREAT / O_TRUNC) selects the overlay upper layer.
        std::uint64_t flags = r.arg[static_cast<std::size_t>(path_arg) + 1];
        constexpr std::uint64_t kWrOnly = 1, kRdWr = 2, kCreat = 0100, kTrunc = 01000;
        bool for_write = (flags & 3) == kWrOnly || (flags & 3) == kRdWr ||
                         (flags & kCreat) || (flags & kTrunc);
        auto pc = k_.files().classify(abs, for_write);
        if (pc.realm == kernel::Realm2::host_backed) {
            Outcome o{};
            o.redirect  = true;
            o.path_arg  = path_arg;
            o.host_path = std::move(pc.host_path);
            o.ret       = 0;               // trap fills ret with the real fd
            o.forward   = false;
            // Remember the guest path for this fd after the trap assigns it.
            pending_open_ = abs;
            // If this opens a directory that is overlaid (writable upper over
            // the read-only rootfs lower), enumerate the UNION of both layers
            // and serve THAT from getdents64 on the resulting fd — otherwise a
            // freshly-created (empty) upper would hide the whole rootfs, and
            // `ls /` would show nothing. Non-overlay dirs enumerate natively.
            if (!for_write) {
                auto merged = k_.files().overlay_dir_union(abs);
                if (!merged.empty()) {
                    pending_dir_ = true;
                    pending_entries_ = std::move(merged);
                }
            }
            return o;
        }
        if (pc.realm == kernel::Realm2::virtual_file) {
            // Follow a cross-mount symlink to the RESOLVED virtual path (e.g.
            // /etc/mtab -> /proc/self/mounts); produce that, not the link.
            const std::string& vp = pc.virtual_path.empty() ? abs : pc.virtual_path;
            auto vf = k_.files().produce(vp);
            if (!vf) return eno(vf.error());
            Outcome o{};
            o.inject  = true;
            o.path_arg = path_arg;              // which reg holds the char* path
            o.content = std::move(vf->bytes);   // empty for a dir
            pending_open_ = vp;
            // A virtual DIRECTORY: stash its entries so getdents64 on the
            // resulting fd enumerates them (the backing temp node is a real
            // empty directory so O_DIRECTORY opens succeed).
            pending_dir_ = vf->is_dir;
            o.inject_dir = vf->is_dir;
            pending_entries_ = std::move(vf->entries);
            return o;
        }
        return eno(pc.error);
    }

    // stat/lstat/newfstatat: redirect host-backed to the real path; for
    // virtual files synthesize a stat buffer into guest memory ourselves.
    [[nodiscard]] Outcome path_stat(const Regs& r, int path_arg, bool at,
                                    bool follow = true) {
        std::string abs = resolve_arg(r, path_arg, at);
        auto pc = k_.files().classify(abs, /*for_write=*/false, follow);
        if (pc.realm == kernel::Realm2::host_backed) {
            Outcome o{};
            o.redirect = true; o.path_arg = path_arg; o.host_path = std::move(pc.host_path);
            // The host kernel will fill the statbuf with the host file's
            // owner; scrub it to root afterwards. statbuf is arg[1] for
            // stat/lstat, arg[2] for newfstatat.
            o.scrub = Outcome::ScrubKind::stat;
            o.scrub_buf = at ? uaddr(r.arg[2]) : uaddr(r.arg[1]);
            return o;
        }
        // Virtual stat: forward is impossible, so synthesize a stat64 buffer.
        if (pc.realm == kernel::Realm2::virtual_file) {
            const std::string& vp = pc.virtual_path.empty() ? abs : pc.virtual_path;
            auto vf = k_.files().produce(vp);
            if (!vf) return eno(vf.error());
            // statbuf is arg[1] for stat/lstat, arg[2] for newfstatat.
            UAddr sb = at ? uaddr(r.arg[2]) : uaddr(r.arg[1]);
            return write_statbuf(sb, vf->is_dir, vf->bytes.size());
        }
        return eno(pc.error);
    }

    // statx(dirfd, path, flags, mask, buf): host-backed -> redirect; virtual
    // -> synthesize a `struct statx` into the guest buffer (arg[4]).
    [[nodiscard]] Outcome path_statx(const Regs& r) {
        std::string abs = resolve_arg(r, 1, true);
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) {
            Outcome o{};
            o.redirect = true; o.path_arg = 1; o.host_path = std::move(pc.host_path);
            o.scrub = Outcome::ScrubKind::statx;
            o.scrub_buf = uaddr(r.arg[4]);
            return o;
        }
        if (pc.realm == kernel::Realm2::virtual_file) {
            const std::string& vp = pc.virtual_path.empty() ? abs : pc.virtual_path;
            auto vf = k_.files().produce(vp);
            if (!vf) return eno(vf.error());
            return write_statx(uaddr(r.arg[4]), vf->is_dir, vf->bytes.size());
        }
        return eno(pc.error);
    }

    // access/readlink[at]/faccessat: host-backed -> redirect; virtual
    // paths that exist -> success (0); absent -> error.
    [[nodiscard]] Outcome path_at(const Regs& r, int path_arg, bool at) {
        std::string abs = resolve_arg(r, path_arg, at);
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) {
            Outcome o{};
            o.redirect = true; o.path_arg = path_arg; o.host_path = std::move(pc.host_path);
            return o;
        }
        if (pc.realm == kernel::Realm2::virtual_file) return val(0);
        return eno(pc.error);
    }

    // readlink[at]: host-backed symlinks redirect to the real path; the
    // virtual /proc symlinks (self/exe, <pid>/exe, self/cwd, self/root,
    // self/fd/N) are SYNTHESIZED here, since a monitor / dynamic loader /
    // language runtime routinely reads /proc/self/exe to find its own binary.
    [[nodiscard]] Outcome do_readlink(const Regs& r, int path_arg, bool at) {
        std::string abs = resolve_arg(r, path_arg, at);
        // The buffer + size follow the path arg: readlink(path,buf,sz) ->
        // arg1/arg2; readlinkat(dirfd,path,buf,sz) -> arg2/arg3.
        std::size_t bi = static_cast<std::size_t>(path_arg) + 1;
        UAddr buf = uaddr(r.arg[bi]);
        std::size_t cap = static_cast<std::size_t>(r.arg[bi + 1]);

        if (std::string tgt = proc_symlink_target(abs); !tgt.empty())
            return write_link(buf, cap, tgt);

        auto pc = k_.files().classify(abs, /*for_write=*/false, /*follow=*/false);
        if (pc.realm == kernel::Realm2::host_backed) {
            Outcome o{};
            o.redirect = true; o.path_arg = path_arg;
            o.host_path = std::move(pc.host_path);
            return o;
        }
        if (pc.realm == kernel::Realm2::virtual_file) {
            // A synthesized symlink (e.g. /dev/stdin -> /proc/self/fd/0)
            // carries its target in the produced node; serve it directly.
            if (auto vf = k_.files().produce(abs); vf && !vf->symlink_target.empty())
                return write_link(buf, cap, vf->symlink_target);
            return eno(Errno::einval);   // a plain virtual file is not a symlink
        }
        return eno(pc.error);
    }

    // The target of a synthesized /proc symlink, or "" if `abs` is not one.
    // self/<pid> both resolve against the CURRENT task (linuxity runs one
    // guest tree; the monitor asks about its own members).
    [[nodiscard]] std::string proc_symlink_target(const std::string& abs) {
        auto id = ids();
        auto exe_of = [&](std::int32_t pid) -> std::string {
            if (const auto* pi = k_.procs().find(pid)) {
                // cmdline is space-joined argv; the first token is argv[0].
                std::string c = pi->cmdline;
                auto sp = c.find(' ');
                std::string a0 = sp == std::string::npos ? c : c.substr(0, sp);
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
                    if (tail == "cwd")  return std::string{k_.files().cwd()};
                    if (tail == "root") return "/";
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

    // execve/execveat: rewrite the program-path argument to the translated
    // host path (host-backed) and forward. Virtual exec targets are refused.
    [[nodiscard]] Outcome path_exec(const Regs& r, int path_arg) {
        std::string abs = resolve_arg(r, path_arg, path_arg == 1);
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) {
            // A dynamically-linked program names its interpreter in PT_INTERP;
            // the host kernel would resolve that against the host root and
            // fail. If this binary has an interp, exec the interpreter instead
            // (with the program as argv[1]) so the loader opens the program +
            // its libraries through redirected syscalls inside the rootfs.
            std::string interp = loader::read_elf_interp(pc.host_path);
            if (!interp.empty()) {
                std::string interp_abs = k_.files().absolutize(interp);
                auto ipc = k_.files().classify(interp_abs);
                Outcome o{};
                o.exec_interp = true;
                o.path_arg    = path_arg;
                o.interp_host = ipc.realm == kernel::Realm2::host_backed
                                    ? std::move(ipc.host_path) : interp;
                o.prog_guest  = abs;   // guest path; loader's openat redirects
                return o;
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
                Outcome o{};
                o.exec_interp = true;
                o.path_arg    = path_arg;
                o.prog_guest  = abs;   // the script, as a guest path
                // Is the shebang interpreter ITSELF dynamic? Then exec its
                // ld.so, and pass the interpreter's host path as the first
                // prefix token (ld.so <sh-host> [-e] <script-guest> ...).
                std::string si_interp = loader::read_elf_interp(si_host);
                if (!si_interp.empty()) {
                    std::string ld_abs = k_.files().absolutize(si_interp);
                    auto ldc = k_.files().classify(ld_abs);
                    o.interp_host = ldc.realm == kernel::Realm2::host_backed
                                        ? std::move(ldc.host_path) : si_interp;
                    // ld.so opens its program argument through redirected
                    // openat, so pass the interpreter's GUEST path (si_abs),
                    // not its host path — else ld re-translates and double-roots.
                    o.interp_prefix.push_back(std::move(si_abs));
                } else {
                    o.interp_host = std::move(si_host);   // static interpreter
                }
                if (!sh.arg.empty()) o.interp_prefix.push_back(std::move(sh.arg));
                return o;
            }
            Outcome o{};
            o.redirect = true; o.path_arg = path_arg;
            o.host_path = std::move(pc.host_path);
            return o;
        }
        return eno(pc.realm == kernel::Realm2::virtual_file ? Errno::eacces
                                                            : pc.error);
    }

    [[nodiscard]] Outcome do_chdir(const Regs& r) {
        std::string abs = k_.files().absolutize(read_cstr(uaddr(r.arg[0])),
                                                k_.files().cwd());
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::absent) return eno(pc.error);
        k_.files().set_cwd(abs);
        return val(0);
    }

    [[nodiscard]] Outcome do_getcwd(const Regs& r) {
        std::string_view cwd = k_.files().cwd();
        std::size_t need = cwd.size() + 1;
        std::size_t cap = static_cast<std::size_t>(r.arg[1]);
        if (cap < need) return eno(Errno::einval);
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

    // A single-path mutation (mkdir/rmdir/unlink/chmod/chown/truncate/...):
    // translate the guest path at `path_arg` to its overlay UPPER host path
    // and REDIRECT, with the WriteIntent selecting how the upper layer is
    // prepared (create the leaf itself, copy an existing leaf up, or just
    // resolve for removal). A virtual path (procfs/sysfs) is read-only —
    // refuse with EROFS; an absent target yields its errno.
    using Wi = kernel::FileNamespace::WriteIntent;
    [[nodiscard]] Outcome path_mut(const Regs& r, int path_arg, bool at, Wi wi) {
        std::string abs = resolve_arg(r, path_arg, at);
        auto pc = k_.files().classify(abs, /*for_write=*/true, /*follow=*/false, wi);
        if (pc.realm == kernel::Realm2::virtual_file)
            return eno(Errno::erofs);
        if (pc.host_path.empty()) return eno(pc.error);
        Outcome o{};
        o.redirect = true;
        o.path_arg = path_arg;
        o.host_path = std::move(pc.host_path);
        // Only creates need their parent chain pre-built by the trap; the
        // parents_only classify already mirrored them, so this is belt-and-
        // suspenders for the deep-create case.
        o.make_parents = (wi == Wi::parents_only);
        return o;
    }

    // A two-path mutation (rename/link and their *at forms): BOTH operands are
    // guest paths, so translate each to its overlay upper host path and hand
    // the trap two rewrites. rename's *at forms carry (olddirfd, oldpath,
    // newdirfd, newpath) => path args 1 and 3; the legacy forms carry
    // (oldpath, newpath) => args 0 and 1. The source is resolved for REMOVAL
    // (it must already exist), the destination CREATES its leaf.
    [[nodiscard]] Outcome path_mut2(const Regs& r, int a1, int a2, bool at,
                                    bool /*at2*/) {
        std::string src = resolve_arg(r, a1, at);
        std::string dst = resolve_second(r, a2, at);
        auto ps = k_.files().classify(src, true, false, Wi::copy_leaf);
        auto pd = k_.files().classify(dst, true, false, Wi::parents_only);
        if (ps.realm == kernel::Realm2::virtual_file ||
            pd.realm == kernel::Realm2::virtual_file)
            return eno(Errno::erofs);
        if (ps.host_path.empty() || pd.host_path.empty())
            return eno(ps.host_path.empty() ? ps.error : pd.error);
        Outcome o{};
        o.redirect     = true;
        o.path_arg     = a1;
        o.host_path    = std::move(ps.host_path);
        o.path_arg2    = a2;
        o.host_path2   = std::move(pd.host_path);
        o.make_parents = true;   // ensure the destination's parent exists
        return o;
    }

    // symlink(target, linkpath) / symlinkat(target, newdirfd, linkpath):
    // `target` is the link's literal CONTENTS — a guest-absolute string the
    // guest will later resolve through OUR namespace — so it must NOT be
    // rewritten to a host path. Only the linkpath (where the symlink lives)
    // is translated to its overlay upper host path.
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
        Outcome o{};
        o.redirect     = true;
        o.path_arg     = link_arg;      // rewrite ONLY the linkpath
        o.host_path    = std::move(pc.host_path);
        o.make_parents = true;
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

        // struct linux_dirent64 { u64 d_ino; s64 d_off; u16 d_reclen;
        //                         u8 d_type; char d_name[]; } — 8-aligned.
        constexpr std::uint8_t kDtDir = 4, kDtReg = 8;
        while (ds->pos < ds->entries.size()) {
            const auto& e = ds->entries[ds->pos];
            std::size_t namelen = e.name.size() + 1;                 // incl NUL
            std::size_t reclen  = (19 + namelen + 7) & ~std::size_t{7};
            if (out.size() + reclen > cap) break;                   // buffer full
            std::size_t base = out.size();
            out.resize(base + reclen, std::byte{0});
            auto put64 = [&](std::size_t off, std::uint64_t v) {
                for (int i = 0; i < 8; ++i)
                    out[base + off + static_cast<std::size_t>(i)] =
                        static_cast<std::byte>((v >> (8 * i)) & 0xff);
            };
            put64(0, ds->pos + 1);                                  // d_ino
            put64(8, static_cast<std::uint64_t>(ds->pos + 1));      // d_off
            out[base + 16] = static_cast<std::byte>(reclen & 0xff); // d_reclen lo
            out[base + 17] = static_cast<std::byte>((reclen >> 8) & 0xff);
            out[base + 18] = static_cast<std::byte>(e.is_dir ? kDtDir : kDtReg);
            for (std::size_t i = 0; i < e.name.size(); ++i)
                out[base + 19 + i] = static_cast<std::byte>(e.name[i]);
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

    // Synthesize a `struct statx` (the flat, versioned stat the kernel fills
    // for statx(2)) for a virtual node into the guest buffer.
    [[nodiscard]] Outcome write_statx(UAddr buf, bool is_dir, std::uint64_t size) {
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
        constexpr std::uint16_t kIfDir = 0040000, kIfReg = 0100000;
        sx.stx_mask    = kBasicStats;
        sx.stx_blksize = 4096;
        sx.stx_nlink   = 1;
        sx.stx_mode    = static_cast<std::uint16_t>(is_dir ? kIfDir | 0555u
                                                           : kIfReg | 0444u);
        sx.stx_ino     = 1;
        sx.stx_size    = size;
        sx.stx_blocks  = (size + 511) / 512;
        if (!mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(&sx), sizeof sx}))
            return eno(Errno::efault);
        return val(0);
    }

    // Synthesize a `struct stat` (x86-64 layout) for a virtual file into the
    // guest buffer. Only the fields programs read are populated.
    [[nodiscard]] Outcome write_statbuf(UAddr buf, bool is_dir, std::uint64_t size) {
        struct Stat64 {
            std::uint64_t st_dev; std::uint64_t st_ino; std::uint64_t st_nlink;
            std::uint32_t st_mode; std::uint32_t st_uid; std::uint32_t st_gid;
            std::uint32_t __pad0; std::uint64_t st_rdev; std::int64_t st_size;
            std::int64_t st_blksize; std::int64_t st_blocks;
            std::uint64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
            std::int64_t __unused[3];
        } st{};
        constexpr std::uint32_t kIfDir = 0040000, kIfReg = 0100000;
        st.st_ino     = 1;
        st.st_nlink   = 1;
        st.st_mode    = (is_dir ? kIfDir | 0555u : kIfReg | 0444u);
        st.st_size    = static_cast<std::int64_t>(size);
        st.st_blksize = 4096;
        st.st_blocks  = static_cast<std::int64_t>((size + 511) / 512);
        if (!mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(&st), sizeof st}))
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
    std::vector<kernel::VirtualDirent> pending_entries_;
public:
    // The trap calls this after a redirect/inject syscall returns a real fd,
    // so the namespace can bind the guest path to that fd (readlinkat etc.),
    // and — for a virtual directory — the entries getdents64 will enumerate.
    void note_opened_fd(std::int64_t fd) {
        if (fd >= 0 && !pending_open_.empty()) {
            k_.files().bind_fd(static_cast<int>(fd), pending_open_);
            if (pending_dir_)
                k_.files().bind_dir(static_cast<int>(fd), std::move(pending_entries_));
        }
        pending_open_.clear();
        pending_dir_ = false;
        pending_entries_.clear();
    }

    // After a host-backed stat/statx REDIRECT returns success, the guest
    // buffer holds the HOST file's uid/gid. linuxity presents a root-owned
    // world, so rewrite the owner fields to 0 in place. The field offsets are
    // the SAME layouts write_statbuf/write_statx synthesize, so there is one
    // definition of where uid/gid live. No-op unless o.scrub is set.
    void scrub_ids(const Outcome& o) {
        if (o.scrub == Outcome::ScrubKind::none) return;
        // struct stat (x86-64): st_uid at byte 28, st_gid at byte 32 (both
        // u32, contiguous). struct statx: stx_uid at 20, stx_gid at 24 (both
        // u32, contiguous). Zeroing 8 bytes from the uid offset clears both
        // owner fields without touching neighbours (st_gid's pad / stx_mode).
        const std::size_t uid_off = o.scrub == Outcome::ScrubKind::stat ? 28 : 20;
        std::array<std::byte, 8> zero{};   // clears uid AND the adjacent gid
        (void)mem_.copy_out(uaddr(value(o.scrub_buf) + uid_off), zero);
    }
};

} // namespace lx::abi
