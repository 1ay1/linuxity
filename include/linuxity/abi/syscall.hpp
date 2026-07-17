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
#include "linuxity/kernel/subsystem.hpp"

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

    bool                inject{false};  // splice a host memfd, return its fd
    std::vector<std::byte> content;     // bytes to back the injected fd
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

            // -- identity + credentials (virtual: our world is pid 1, root)
            case Sysno::getpid:  return val(k_.self().raw());
            case Sysno::gettid:  return val(k_.self().raw());
            case Sysno::getuid:  case Sysno::geteuid:
            case Sysno::getgid:  case Sysno::getegid:
                return val(0);

            // -- benign process-init syscalls libc issues early ----------
            // Serviced trivially so _start proceeds; they carry no host
            // resource we need to allocate.
            case Sysno::set_tid_address:
            case Sysno::rt_sigaction:
            case Sysno::rt_sigprocmask:
                return val(0);

            // -- uname (virtual: report LINUXITY's identity, not the host)
            // The guest must believe it runs on linuxity, so we synthesize
            // the utsname and copy_out into the guest buffer ourselves
            // rather than forwarding to the host kernel.
            case Sysno::uname:
                return do_uname(uaddr(r.arg[0]));

            // -- getppid: our init has no parent; getpgrp: our group is 1.
            case Sysno::getppid: return val(0);
            case Sysno::getpgrp: return val(k_.self().raw());

            // -- the filesystem namespace (virtual: the guest's whole tree
            //    is linuxity's; host-backed paths get translated + forwarded,
            //    virtual paths get synthesized). This is what makes --root a
            //    real, unprivileged Linux world.
            case Sysno::open:        return path_open(r, 0, /*at=*/false);
            case Sysno::openat:      return path_open(r, 1, /*at=*/true);
            case Sysno::stat:        return path_stat(r, 0, false);
            case Sysno::lstat:       return path_stat(r, 0, false);
            case Sysno::access:      return path_at(r, 0, false);
            case Sysno::chdir:       return do_chdir(r);
            case Sysno::newfstatat:  return path_stat(r, 1, true);
            case Sysno::statx:       return path_at(r, 1, true);
            case Sysno::faccessat:
            case Sysno::faccessat2:  return path_at(r, 1, true);
            case Sysno::readlink:    return path_at(r, 0, false);
            case Sysno::readlinkat:  return path_at(r, 1, true);
            case Sysno::getcwd:      return do_getcwd(r);

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
    static Outcome eno(Errno e) { return val(-static_cast<std::int64_t>(e)); }

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
            return o;
        }
        if (pc.realm == kernel::Realm2::virtual_file) {
            auto vf = k_.files().produce(abs);
            if (!vf) return eno(vf.error());
            Outcome o{};
            o.inject  = true;
            o.content = std::move(vf->bytes);
            pending_open_ = abs;
            return o;
        }
        return eno(pc.error);
    }

    // stat/lstat/newfstatat: redirect host-backed to the real path; for
    // virtual files synthesize a stat buffer into guest memory ourselves.
    [[nodiscard]] Outcome path_stat(const Regs& r, int path_arg, bool at) {
        std::string abs = resolve_arg(r, path_arg, at);
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) {
            Outcome o{};
            o.redirect = true; o.path_arg = path_arg; o.host_path = std::move(pc.host_path);
            return o;
        }
        // Virtual stat: forward is impossible, so synthesize a stat64 buffer.
        if (pc.realm == kernel::Realm2::virtual_file) {
            auto vf = k_.files().produce(abs);
            if (!vf) return eno(vf.error());
            // statbuf is arg[1] for stat/lstat, arg[2] for newfstatat.
            UAddr sb = at ? uaddr(r.arg[2]) : uaddr(r.arg[1]);
            return write_statbuf(sb, vf->is_dir, vf->bytes.size());
        }
        return eno(pc.error);
    }

    // access/statx/readlink[at]/faccessat: host-backed -> redirect; virtual
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

    // execve/execveat: rewrite the program-path argument to the translated
    // host path (host-backed) and forward. Virtual exec targets are refused.
    [[nodiscard]] Outcome path_exec(const Regs& r, int path_arg) {
        std::string abs = resolve_arg(r, path_arg, path_arg == 1);
        auto pc = k_.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) {
            Outcome o{};
            o.redirect = true; o.path_arg = path_arg; o.host_path = std::move(pc.host_path);
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
        set(u.nodename, "linuxity");
        set(u.release,  "6.6.0-linuxity");
        set(u.version,  "#1 linuxity portable Linux ABI");
        set(u.machine,  arch_ == Arch::aarch64 ? "aarch64" : "x86_64");
        set(u.domainname, "(none)");
        if (!mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(&u), sizeof u}))
            return val(-static_cast<std::int64_t>(Errno::efault));
        return val(0);
    }

    K& k_;
    M& mem_;
    Arch arch_;
    std::string pending_open_;   // guest path awaiting fd assignment by trap
public:
    // The trap calls this after a redirect/inject syscall returns a real fd,
    // so the namespace can bind the guest path to that fd (readlinkat etc.).
    void note_opened_fd(std::int64_t fd) {
        if (fd >= 0 && !pending_open_.empty())
            k_.files().bind_fd(static_cast<int>(fd), pending_open_);
        pending_open_.clear();
    }
};

} // namespace lx::abi
