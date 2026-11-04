// linuxity/runtime/hvf_trap.hpp
//
// The macOS trap backend: run a Linux aarch64 guest on Apple Silicon.
//
// On Linux the ptrace backend borrows the HOST kernel: the guest is a real
// child process, and syscalls linuxity doesn't virtualize are FORWARDED to
// the host kernel, which already speaks Linux. On macOS there is no such
// kernel to borrow. XNU does not implement the Linux ABI, so EVERY guest
// syscall must be serviced by linuxity itself.
//
// So the guest doesn't get a host process; it gets a bare VM:
//
//   * Hypervisor.framework gives us an EL1/EL0 address space with no guest
//     kernel in it. We map one flat chunk of host anonymous memory as guest
//     physical memory (IPA 0..mem_size) and build 3-level page tables inside
//     it, so the guest runs with the MMU on at EL0.
//   * The guest's own instructions execute BARE on the CPU — this is an
//     aarch64 rootfs on an aarch64 host, no translation, native speed.
//   * `svc #0` from EL0 traps to our EL1 vector stub, which immediately
//     `hvc`s out to the hypervisor, i.e. to us. We decode x8/x0..x5 into
//     abi::Regs, hand them to abi::Syscalls, write the result into x0, and
//     resume at ELR_EL1. Exactly the SyscallTrap contract the Cpu loop in
//     runtime/trap.hpp already drives on Linux.
//
// Consequences of having no host kernel underneath, and how we answer them:
//
//   FORWARD    — there is nothing to forward to. On this backend `forward()`
//                means "emulate it against the macOS host": file I/O becomes
//                real Darwin pread/pwrite on the translated host path, and
//                memory syscalls (mmap/brk/mprotect) are served by our own
//                guest-physical allocator. See hvf_sys.hpp.
//   REDIRECT   — the path rewrite the dispatcher asks for is applied in our
//                own syscall emulation, not poked into guest memory. There is
//                no race (nothing else can run while we're stopped).
//   fork/clone — Hypervisor.framework refuses to operate in a forked child
//                (hv_vm_create returns HV_BAD_ARGUMENT there). Verified on
//                macOS 27: the VM must be TORN DOWN before fork(2) and
//                re-created on both sides, which works because guest physical
//                memory is ordinary COW anonymous memory. See fork_guest().
//   zeroing     — host writes into mapped guest memory ARE visible to the
//                guest, but mmap(MAP_FIXED) over it silently detaches the
//                guest's view (the IPA still points at the old pages). So a
//                fresh guest page is cleared with madvise(MADV_ZERO), never
//                by remapping. Verified on macOS 27.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/syscall.hpp"
#include "linuxity/runtime/hvf_darwin.hpp"
#include "linuxity/runtime/hvf_exec.hpp"
#include "linuxity/runtime/hvf_fd.hpp"
#include "linuxity/runtime/hvf_futex.hpp"
#include "linuxity/runtime/hvf_proc.hpp"
#include "linuxity/runtime/hvf_signal.hpp"
#include "linuxity/runtime/hvf_task.hpp"
#include "linuxity/runtime/hvf_timer.hpp"
#include "linuxity/runtime/hvf_tty.hpp"
#include "linuxity/runtime/hvf_mem.hpp"
#include "linuxity/runtime/hvf_net.hpp"
#include "linuxity/runtime/hvf_regs.hpp"
#include "linuxity/runtime/hvf_vm.hpp"
#include "linuxity/runtime/hvf_vma.hpp"
#include "linuxity/runtime/trap.hpp"

#include <Hypervisor/Hypervisor.h>
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>
#include <time.h>
#include <stdlib.h>

#include <bit>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <poll.h>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace lx::runtime {

// -- The trap backend ------------------------------------------------------
// Models runtime::SyscallTrap, so the SAME Cpu loop that drives ptrace on
// Linux drives this. Every difference follows from one fact: there is no
// host Linux kernel beneath us.
//
//   next()      reads the register snapshot once (nine hypervisor calls),
//               not once per accessor.
//   resume()    writes x0 + PC + PSTATE: three calls, the minimum. No
//               syscall ran, so unlike ptrace there is nothing to neutralize.
//   forward()   cannot mean "let the kernel do it". It emulates against
//               Darwin: memory from the VMA map, I/O via real Darwin calls.
//               Anything unimplemented returns ENOSYS, which libc handles;
//               a plausible-looking wrong answer would corrupt it silently.
//   redirect()  needs no guest write at all -- we hold the translated host
//               path as a std::string. The ptrace backend must poke it into
//               guest memory for the host kernel to read, which is where its
//               check-then-use race lives. Structurally absent here.
class HvfTrap {
public:
    // A trap serves ONE guest thread: its own vCPU and TaskState, plus the
    // ProcessState it shares with its siblings. `proc` and `machine` outlive
    // every trap built on them (main owns them); `cpu` and `task` belong to
    // this thread alone.
    HvfTrap(HvfMachine& machine, HvfCpu& cpu, ProcessState& proc,
            TaskState& task, PidSpace& pids) noexcept
        : machine_{machine}, cpu_{cpu}, proc_{proc}, task_{task}, pids_{pids} {}

    // Translate a guest path to a host path through the portable namespace.
    // Installed by the embedder (main/test), which owns the Kernel; the trap
    // needs it only for execve, where the PROGRAM image must be found.
    using Resolver = std::function<std::string(const std::string&)>;
    void set_resolver(Resolver r) { resolve_ = std::move(r); }
    // host path -> guest path, for readlink("/proc/self/fd/N").
    void set_unresolver(Resolver r) { unresolve_ = std::move(r); }
    void set_env_fallback(std::vector<std::string> env) { env_ = std::move(env); }

    // -- Identity bridge to the portable core. abi::Syscalls asks the memory
    //    accessor for current_ids(); HvfMem forwards here, so getpid/getppid
    //    and /proc/self answer with this process's GUEST pid.
    struct TaskIds { std::int32_t pid, tid, ppid; };
    [[nodiscard]] TaskIds current_ids() const noexcept {
        return {task_.tid, task_.tid, parent_};
    }

    // The loader has already written the image and stack into guest RAM, so
    // starting is just placing the entry state. `image_end` seeds the heap.
    [[nodiscard]] Status start(UAddr entry, UAddr sp) {
        if (value(entry)) cpu_.set_entry(value(entry), value(sp));
        return ok();
    }

    void set_arena(std::uint64_t image_end, std::uint64_t stack_floor) {
        proc_.with_space([&](AddressSpace& t) { return t.reset(image_end, stack_floor); });
    }

    // Record a region the LOADER mapped directly into guest RAM (ELF
    // segments, the stack). Without this the VMA map doesn't know they
    // exist, and the guest's own mprotect on them -- which glibc's ld.so
    // does to apply RELRO right before transferring control -- fails ENOMEM
    // and the program dies with "cannot apply additional memory protection
    // after relocation".
    void adopt(std::uint64_t begin, std::uint64_t end, GuestProt prot) {
        proc_.with_space([&](AddressSpace& t) { return t.adopt({AddressSpace::page_down(begin), AddressSpace::page_up(end),
                   prot, /*anonymous=*/false}); });
    }

    // The startup stack: from the initial sp's page up to the top of RAM.
    void adopt_stack(std::uint64_t sp, std::uint64_t mem_top) {
        proc_.with_space([&](AddressSpace& t) { return t.adopt({AddressSpace::page_down(sp) - kStackReserve,
                   AddressSpace::page_down(mem_top),
                   GuestProt::read | GuestProt::write, /*anonymous=*/true}); });
    }
    // Room below the initial sp for the stack to grow (Linux's default
    // RLIMIT_STACK, which is what prlimit64 reports).
    static constexpr std::uint64_t kStackReserve = ExecArena::stack_reserve;

    [[nodiscard]] Result<bool> next(TrapFrame& f) {
        constexpr std::uint64_t kEcSvc64 = 0x15;
        for (;;) {
            if (exited_) return ok(false);
            // A sibling called exit_group(2): this thread dies too, with the
            // group's status. Checked here (and again after every trap)
            // because the kick that woke us may have arrived while we were
            // inside the guest.
            if (proc_.group_exiting()) {
                exited_ = true;
                code_ = proc_.group_status();
                return ok(false);
            }
            // Signals are delivered here -- after resume() has written the
            // previous syscall's result into the vCPU, so the frame captures
            // the COMPLETED call (x0 = its return value, PC past the svc).
            // Delivering before the result is written makes the handler
            // return into a context whose x0 is the syscall's first ARGUMENT,
            // and the interrupted code then dereferences garbage.
            (void)deliver_pending();
            if (exited_) return ok(false);
            auto regs = cpu_.run();
            if (!regs) {
                if (regs.error() == Errno::eintr) continue;   // kicked: deliver
                return err<bool>(regs.error());
            }
            regs_ = *regs;
            if (regs_.ec() != kEcSvc64) return ok(report_fault());
            // aarch64 Linux: nr in x8, args x0..x5.
            f.regs.nr = regs_.nr();
            for (std::size_t i = 0; i < 6; ++i) f.regs.arg[i] = regs_.arg(i);
            f.pc = regs_.elr;
            return ok(true);
        }
    }

    [[nodiscard]] Status resume(std::int64_t ret) {
        // rt_sigreturn restored the ENTIRE interrupted context, x0 and PC
        // included; writing a return value would corrupt it.
        if (std::exchange(task_.in_sigreturn, false)) return ok();
        // A successful execve has REPLACED the image: the vCPU already points
        // at the new entry with a clean register file. Writing a return value
        // into x0 would hand the new program's _start a garbage argument.
        if (std::exchange(execed_, false)) {
            cpu_.set_entry(regs_.elr, cpu_.sp());
            return ok();
        }
        cpu_.set_result(regs_, ret);
        return ok();
    }

    [[nodiscard]] bool exited() const noexcept { return exited_; }
    [[nodiscard]] int exit_code() const noexcept { return code_; }

    // The portable dispatcher turns kill/tkill/tgkill into a SIGNAL outcome
    // and asks the backend to deliver it (runtime/trap.hpp). Map the guest
    // pid to its host process and send the HOST signal: a self-kill comes
    // back to our own handler and is delivered on the next trap; a signal to
    // another guest process is delivered by its own linuxity the same way.
    [[nodiscard]] std::int64_t deliver_signal(std::int32_t gpid, std::int32_t sig) {
        if (sig < 0 || sig > kLinuxNsig) return -22;
        const int hs = signal_from_linux(sig);

        // A GROUP or broadcast signal must stay INSIDE the guest's process
        // tree. Passing 0 or -1 to the host kill(2) would signal linuxity's
        // own host process group -- which is the user's terminal session, so
        // `timeout` sending SIGTERM to its group killed linuxity itself (and
        // would kill the shell that launched it). Enumerate the guest's
        // processes from the shared pid table instead.
        if (gpid <= 0) {
            const bool to_self = gpid == 0 || gpid == -1;
            std::int64_t delivered = 0;
            if (to_self) {
                mark_self_pending(sig);
                delivered = 1;
            }
            for (const Child& c : children_) {
                if (auto h = pids_.host_of(c.guest); h && ::kill(*h, hs) == 0)
                    ++delivered;
            }
            return delivered ? 0 : -3;                               // ESRCH
        }

        if (gpid == task_.tid) { mark_self_pending(sig); return 0; }
        auto h = pids_.host_of(gpid);
        if (!h) return -3;
        if (sig == 0) return ::kill(*h, 0) < 0 ? darwin::fail() : 0;
        return ::kill(*h, hs) < 0 ? darwin::fail() : 0;
    }

    // A signal to OURSELVES is marked pending directly rather than sent
    // through the host: Linux delivers it before kill(2) returns to user
    // space, and our trap boundary is that point.
    void mark_self_pending(int sig) {
        if (sig == 0) return;
        if (sig == 9 || sig == 19) { kill_with(sig); return; }   // unblockable
        g_pending.bits.fetch_or(sigbit(sig), std::memory_order_relaxed);
        g_pending.notify_waiters();
    }

    [[nodiscard]] Result<std::int64_t> forward() {
        return complete(service(nullptr, nullptr));
    }

    // On ptrace, forward_sync exists only to observe the real return value at
    // the syscall-exit stop (dup fd mirroring). We always have it immediately.
    template <class F>
    [[nodiscard]] Result<std::int64_t> forward_sync(F&& observe) {
        std::int64_t rc = service(nullptr, nullptr);
        observe(rc);
        return complete(rc);
    }

    // `post` observes the result inside the stopped window (the dispatcher
    // uses it to scrub a stat buffer's owner before the guest can read it).
    // Accepts any invocable OR nullptr, so a caller that doesn't care pays
    // nothing: the branch is resolved at compile time.
    template <class F = std::nullptr_t>
    [[nodiscard]] Result<std::int64_t> redirect(int, const std::string& host_path,
                                                F post = nullptr, int = -1,
                                                const std::string& host_path2 = {}) {
        const auto sc = abi::decode(abi::Arch::aarch64, regs_.nr());
        if (sc == abi::Sysno::execve) return complete(do_execve(host_path));
        std::int64_t rc = service(&host_path,
                                  host_path2.empty() ? nullptr : &host_path2);
        if constexpr (std::is_invocable_v<F, std::int64_t>) post(rc);
        return complete(rc);
    }

    // The dispatcher asks for this when a guest execs a DYNAMIC program: on
    // ptrace it rewrites the call into "exec ld.so prog" because the host
    // kernel would resolve PT_INTERP against the host root. Our exec loads
    // PT_INTERP itself, from the guest namespace, so the original program is
    // all we need -- this collapses to a normal execve.
    [[nodiscard]] Result<std::int64_t> exec_through_interp(
            int, const std::string&, const std::string& prog_guest,
            const std::vector<std::string>& = {},
            const std::vector<std::string>& = {}) {
        if (!resolve_) return complete(-38);
        return complete(do_execve(resolve_(prog_guest)));
    }

    // A snapshot of the address space, for diagnostics and tests. Copies
    // under the lock rather than handing out a reference that another
    // thread could mutate while the caller walks it.
    [[nodiscard]] std::vector<Vma> address_space_snapshot() {
        return proc_.with_space([&](AddressSpace& t) { return t.vmas(); });
    }

private:
    [[nodiscard]] Result<std::int64_t> complete(std::int64_t rc) {
        // strace-style line with the REAL result. The core's LINUXITY_TRACE
        // shows the dispatcher's decision; only the backend knows what the
        // emulated call actually returned, which is what debugging needs.
        static const bool strace = std::getenv("LINUXITY_STRACE") != nullptr;
        if (strace)
            std::fprintf(stderr, "[%d] %3llu(%#llx, %#llx, %#llx, %#llx) = %lld\n",
                         task_.tid, static_cast<unsigned long long>(regs_.nr()),
                         static_cast<unsigned long long>(regs_.arg(0)),
                         static_cast<unsigned long long>(regs_.arg(1)),
                         static_cast<unsigned long long>(regs_.arg(2)),
                         static_cast<unsigned long long>(regs_.arg(3)),
                         static_cast<long long>(rc));
        LX_TRY(resume(rc));
        return ok(rc);
    }

    // A non-SVC exception is a genuine guest fault. On Linux this would be a
    // SIGSEGV/SIGILL delivered to the guest; until signal delivery exists,
    // end the run with the shell's 128+signal convention and say why --
    // resuming would spin forever on the faulting instruction.
    [[nodiscard]] bool report_fault() {
        const char* kind = "exception";
        int sig = 11;                                  // SIGSEGV
        switch (regs_.ec()) {
            case 0x24: case 0x25: kind = "data abort";        break;
            case 0x20: case 0x21: kind = "instruction abort"; break;
            case 0x26: kind = "SP alignment fault";           break;
            case 0x0e: kind = "illegal execution state"; sig = 4; break;
            case 0x00: kind = "undefined instruction";   sig = 4; break;
            default: break;
        }
        const Vma* v = proc_.with_space([&](AddressSpace& t) { return t.find(regs_.far); });
        std::fprintf(stderr,
            "linuxity: guest %s at pc=%#llx addr=%#llx (%s) esr=%#llx\n",
            kind, static_cast<unsigned long long>(regs_.elr),
            static_cast<unsigned long long>(regs_.far),
            v ? "mapped" : "UNMAPPED",
            static_cast<unsigned long long>(regs_.esr));
        exited_ = true;
        code_ = 128 + sig;
        return false;
    }

    // -- The Darwin service routine ---------------------------------------
    // Dispatch is split by CONCERN rather than one long switch: memory, fd
    // I/O, and path operations have different inputs (the VMA map, a guest
    // fd, a translated host path) and different failure modes. Each handler
    // returns std::nullopt when the syscall isn't one of its own, so adding a
    // group never touches the others.
    [[nodiscard]] std::int64_t service(const std::string* path,
                                       const std::string* path2) {
        const auto sc = abi::decode(abi::Arch::aarch64, regs_.nr());
        if (auto r = do_signal(sc))         return *r;
        if (auto r = do_lifecycle(sc))      return *r;
        if (auto r = do_process(sc))        return *r;
        if (auto r = do_memory(sc))         return *r;
        if (auto r = do_io(sc))             return *r;
        if (auto r = do_socket(sc))         return *r;
        if (auto r = do_path(sc, path, path2)) return *r;
        return -38;                                     // ENOSYS, honestly
    }

    using Maybe = std::optional<std::int64_t>;

    // -- Sockets -------------------------------------------------------------
    // The guest's network IS the host's: linuxity translates the ABI rather
    // than routing packets, so a guest gets the Mac's real connectivity
    // (including whatever VPN or resolver the host uses). See hvf_net.hpp
    // for why every field crossing this boundary is translated by name.
    [[nodiscard]] Maybe do_socket(abi::Sysno sc) {
        using S = abi::Sysno;
        const GuestRam ram = machine_.ram();
        const std::uint64_t a1 = regs_.arg(1), a2 = regs_.arg(2),
                            a3 = regs_.arg(3), a4 = regs_.arg(4);
        const auto gfd = static_cast<int>(regs_.arg(0));

        switch (sc) {
            case S::socket: {
                const auto af = net::af_to_darwin(static_cast<std::uint16_t>(regs_.arg(0)));
                if (!af) return -97;                                 // EAFNOSUPPORT
                // Linux packs SOCK_NONBLOCK/SOCK_CLOEXEC into the type word;
                // Darwin has no such flags, so apply them with fcntl.
                const int type = static_cast<int>(a1 & ~(net::kSockNonblock | net::kSockCloexec));
                const int h = ::socket(*af, type, static_cast<int>(a2));
                if (h < 0) return darwin::fail();
                finish_socket(h, a1);
                return install_socket(h, (a1 & net::kSockCloexec) != 0);
            }
            case S::socketpair: {
                const auto af = net::af_to_darwin(static_cast<std::uint16_t>(regs_.arg(0)));
                if (!af) return -97;
                const int type = static_cast<int>(a1 & ~(net::kSockNonblock | net::kSockCloexec));
                int hp[2];
                if (::socketpair(*af, type, static_cast<int>(a2), hp) < 0)
                    return darwin::fail();
                for (int e : hp) finish_socket(e, a1);
                const bool cx = (a1 & net::kSockCloexec) != 0;
                const auto g = proc_.with_fds([&](FdTable& t) {
                    return std::pair{t.install(hp[0], cx), t.install(hp[1], cx)};
                });
                if (g.first < 0 || g.second < 0) return -24;
                const std::int32_t pair[2] = {g.first, g.second};
                return ram.put(a3, pair) ? 0 : -14;
            }
            case S::listen: {
                const int h = host_fd(gfd);
                if (h < 0) return -9;
                return ::listen(h, static_cast<int>(a1)) < 0 ? darwin::fail() : 0;
            }
            case S::accept: case S::accept4: {
                const int h = host_fd(gfd);
                if (h < 0) return -9;
                ::sockaddr_storage ss{};
                socklen_t len = sizeof ss;
                const int c = ::accept(h, reinterpret_cast<::sockaddr*>(&ss), &len);
                if (c < 0) return darwin::fail();
                if (a1 && !write_sockaddr(ss, a1, a2)) { ::close(c); return -14; }
                const std::uint64_t flags = sc == S::accept4 ? a3 : 0;
                finish_socket(c, flags);
                return install_socket(c, (flags & net::kSockCloexec) != 0);
            }
            case S::getsockname: case S::getpeername: {
                const int h = host_fd(gfd);
                if (h < 0) return -9;
                ::sockaddr_storage ss{};
                socklen_t len = sizeof ss;
                const int rc = sc == S::getsockname
                    ? ::getsockname(h, reinterpret_cast<::sockaddr*>(&ss), &len)
                    : ::getpeername(h, reinterpret_cast<::sockaddr*>(&ss), &len);
                if (rc < 0) return darwin::fail();
                return write_sockaddr(ss, a1, a2) ? 0 : -14;
            }
            case S::shutdown: {
                const int h = host_fd(gfd);
                if (h < 0) return -9;
                return ::shutdown(h, static_cast<int>(a1)) < 0 ? darwin::fail() : 0;
            }
            case S::sendto: {
                const int h = host_fd(gfd);
                if (h < 0) return -9;
                auto buf = ram.clamp(a1, a2);
                if (buf.empty() && a2) return -14;
                ::sockaddr_storage ss{};
                socklen_t slen = 0;
                if (a4) {
                    auto addr = ram.at(a4, regs_.arg(5));
                    if (addr.empty()) return -14;
                    auto n = net::to_darwin(addr, ss);
                    if (!n) return -97;
                    slen = *n;
                }
                const auto n = ::sendto(h, buf.data(), buf.size(),
                                        net::msg_flags_to_darwin(a3),
                                        slen ? reinterpret_cast<::sockaddr*>(&ss) : nullptr,
                                        slen);
                return n < 0 ? darwin::fail() : n;
            }
            case S::recvfrom: {
                const int h = host_fd(gfd);
                if (h < 0) return -9;
                auto buf = ram.clamp(a1, a2);
                if (buf.empty() && a2) return -14;
                ::sockaddr_storage ss{};
                socklen_t slen = sizeof ss;
                const auto n = ::recvfrom(h, buf.data(), buf.size(),
                                          net::msg_flags_to_darwin(a3),
                                          a4 ? reinterpret_cast<::sockaddr*>(&ss) : nullptr,
                                          a4 ? &slen : nullptr);
                if (n < 0) return darwin::fail();
                if (a4 && !write_sockaddr(ss, a4, regs_.arg(5))) return -14;
                return n;
            }
            case S::setsockopt: {
                const int h = host_fd(gfd);
                if (h < 0) return -9;
                const auto opt = net::opt_to_darwin(static_cast<int>(a1),
                                                    static_cast<int>(a2));
                // An unknown option is accepted silently rather than failed:
                // libcurl and openssl set a long tail of tuning options and
                // treat EINVAL as fatal, though none of them is required for
                // correctness.
                if (!opt) return 0;
                auto val = ram.at(a3, a4);
                if (val.empty() && a4) return -14;
                return ::setsockopt(h, opt->level, opt->name, val.data(),
                                    static_cast<socklen_t>(a4)) < 0
                           ? darwin::fail() : 0;
            }
            case S::getsockopt: {
                const int h = host_fd(gfd);
                if (h < 0) return -9;
                const auto opt = net::opt_to_darwin(static_cast<int>(a1),
                                                    static_cast<int>(a2));
                if (!opt) return -92;                                // ENOPROTOOPT
                std::uint32_t want = 0;
                if (!ram.get(a4, want)) return -14;
                auto val = ram.at(a3, want);
                if (val.empty() && want) return -14;
                socklen_t len = static_cast<socklen_t>(want);
                if (::getsockopt(h, opt->level, opt->name, val.data(), &len) < 0)
                    return darwin::fail();
                return ram.put(a4, static_cast<std::uint32_t>(len)) ? 0 : -14;
            }
            case S::sendmsg: case S::recvmsg:
                return do_msg(sc == S::sendmsg, gfd, a1, a2);
            default:
                return std::nullopt;
        }
    }

    // Apply the Linux type-word flags Darwin's socket() doesn't take, and
    // make the socket behave like Linux's default: a write to a closed peer
    // must return EPIPE, not kill the process. Linux programs ask for that
    // per-call with MSG_NOSIGNAL; Darwin's equivalent is per-socket.
    void finish_socket(int h, std::uint64_t linux_type_flags) const noexcept {
        int on = 1;
        ::setsockopt(h, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
        if (linux_type_flags & net::kSockNonblock)
            ::fcntl(h, F_SETFL, ::fcntl(h, F_GETFL) | O_NONBLOCK);
        ::fcntl(h, F_SETFD, FD_CLOEXEC);      // the HOST fd is ours; never leak it
    }

    [[nodiscard]] int host_fd(int gfd) {
        return proc_.with_fds([&](FdTable& t) { return t.host(gfd).value_or(-1); });
    }
    [[nodiscard]] std::int64_t install_socket(int h, bool cloexec) {
        const int g = proc_.with_fds([&](FdTable& t) { return t.install(h, cloexec); });
        if (g < 0) { ::close(h); return -24; }
        return g;
    }

    // Write a Darwin address back in Linux form. Linux reports the FULL
    // length even when the guest's buffer was too small (the address is
    // truncated, the length is not), which is what tells a caller to retry
    // with a bigger buffer.
    [[nodiscard]] bool write_sockaddr(const ::sockaddr_storage& ss,
                                      std::uint64_t addr_at, std::uint64_t len_at) {
        const GuestRam ram = machine_.ram();
        std::uint32_t cap = 0;
        if (len_at && !ram.get(len_at, cap)) return false;
        auto out = ram.clamp(addr_at, cap);
        const std::size_t full = net::to_linux(ss, out);
        return !len_at || ram.put(len_at, static_cast<std::uint32_t>(full));
    }

    // sendmsg/recvmsg: walk the guest msghdr. Ancillary data (SCM_RIGHTS fd
    // passing) is NOT translated -- the fd numbers inside would name host
    // fds, not guest ones -- so it is dropped, which is what a guest sees
    // from a peer that sends none.
    [[nodiscard]] std::int64_t do_msg(bool sending, int gfd,
                                      std::uint64_t msg_at, std::uint64_t flags) {
        const int h = host_fd(gfd);
        if (h < 0) return -9;
        struct LinuxMsghdr {
            std::uint64_t name; std::uint32_t namelen; std::uint32_t pad_;
            std::uint64_t iov; std::uint64_t iovlen;
            std::uint64_t control; std::uint64_t controllen;
            std::int32_t flags; std::uint32_t pad2_;
        };
        static_assert(sizeof(LinuxMsghdr) == 56);
        const GuestRam ram = machine_.ram();
        LinuxMsghdr m{};
        if (!ram.get(msg_at, m)) return -14;

        // Translate the iovec array into host pointers into guest RAM.
        constexpr std::uint64_t kIovMax = 1024;
        if (m.iovlen > kIovMax) return -22;
        std::vector<::iovec> hiov(m.iovlen);
        for (std::uint64_t i = 0; i < m.iovlen; ++i) {
            GuestIovec gi{};
            if (!ram.get(m.iov + i * sizeof(GuestIovec), gi)) return -14;
            auto win = ram.clamp(gi.base, gi.len);
            if (win.empty() && gi.len) return -14;
            hiov[i] = {win.data(), win.size()};
        }

        ::sockaddr_storage ss{};
        ::msghdr hm{};
        hm.msg_iov = hiov.data();
        hm.msg_iovlen = static_cast<int>(hiov.size());
        if (sending && m.name) {
            auto addr = ram.at(m.name, m.namelen);
            if (addr.empty()) return -14;
            auto n = net::to_darwin(addr, ss);
            if (!n) return -97;
            hm.msg_name = &ss;
            hm.msg_namelen = *n;
        } else if (!sending && m.name) {
            hm.msg_name = &ss;
            hm.msg_namelen = sizeof ss;
        }

        const auto n = sending
            ? ::sendmsg(h, &hm, net::msg_flags_to_darwin(flags))
            : ::recvmsg(h, &hm, net::msg_flags_to_darwin(flags));
        if (n < 0) return darwin::fail();
        if (!sending) {
            if (m.name && !write_sockaddr(ss, m.name, msg_at + offsetof(LinuxMsghdr, namelen)))
                return -14;
            m.controllen = 0;                  // no ancillary data passed through
            m.flags = 0;
            (void)ram.put(msg_at, m);
        }
        return n;
    }
    // TimerSet speaks std::chrono; the guest speaks struct itimerval /
    // itimerspec. Two small converters keep that boundary in one place.
    [[nodiscard]] static LinuxItimerval to_itimerval(const TimerSet::Interval& i) {
        using namespace std::chrono;
        return {{duration_cast<seconds>(i.interval).count(),
                 duration_cast<microseconds>(i.interval % seconds{1}).count()},
                {duration_cast<seconds>(i.value).count(),
                 duration_cast<microseconds>(i.value % seconds{1}).count()}};
    }
    [[nodiscard]] static LinuxItimerspec to_itimerspec(const TimerSet::Interval& i) {
        using namespace std::chrono;
        return {{duration_cast<seconds>(i.interval).count(),
                 (i.interval % seconds{1}).count()},
                {duration_cast<seconds>(i.value).count(),
                 (i.value % seconds{1}).count()}};
    }

    [[nodiscard]] Maybe do_signal(abi::Sysno sc) {
        using S = abi::Sysno;
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1),
                            a2 = regs_.arg(2), a3 = regs_.arg(3);
        const GuestRam ram = machine_.ram();
        switch (sc) {
            case S::rt_sigaction: {
                // rt_sigaction(sig, act*, oact*, sigsetsize)
                const int s = static_cast<int>(a0);
                if (s < 1 || s > kLinuxNsig || a3 != 8) return -22;
                if (a2 && !ram.put(a2, proc_.with_signals([&](SignalDispositions& t) { return t.get(s); }))) return -14;
                if (!a1) return 0;
                if (s == 9 || s == 19) return -22;              // KILL/STOP fixed
                LinuxSigaction act{};
                if (!ram.get(a1, act)) return -14;
                if (!proc_.with_signals([&](SignalDispositions& t) { return t.set(s, act); })) return -22;
                // Catch the host signal only while the guest has a handler
                // (or ignores it); otherwise leave the host default so a
                // terminal Ctrl-C kills us exactly like it kills a process.
                route_host_signal(s, act.handler != 0);
                if (act.handler == 1) {                          // SIG_IGN
                    const int hs = signal_from_linux(s);
                    if (hs > 0 && hs != SIGKILL && hs != SIGSTOP) ::signal(hs, SIG_IGN);
                }
                return 0;
            }
            case S::rt_sigprocmask: {
                // rt_sigprocmask(how, set*, oset*, sigsetsize)
                if (a3 != 8) return -22;
                if (a2 && !ram.put(a2, task_.sig_mask)) return -14;
                if (!a1) return 0;
                std::uint64_t set = 0;
                if (!ram.get(a1, set)) return -14;
                set &= ~(sigbit(9) | sigbit(19));               // never blockable
                switch (a0) {
                    case 0: task_.sig_mask |= set;  break;               // SIG_BLOCK
                    case 1: task_.sig_mask &= ~set; break;               // SIG_UNBLOCK
                    case 2: task_.sig_mask = set;   break;               // SIG_SETMASK
                    default: return -22;
                }
                return 0;
            }
            case S::rt_sigpending:
                return ram.put(a0, std::uint64_t{
                    g_pending.bits.load(std::memory_order_relaxed) & task_.sig_mask}) ? 0 : -14;
            case S::rt_sigreturn:
                return do_sigreturn();
            case S::sigaltstack: {
                // sigaltstack(ss*, oss*): record it; delivery honours SA_ONSTACK.
                if (a1 && !ram.put(a1, task_.alt_stack)) return -14;
                if (a0) {
                    LinuxStack ss{};
                    if (!ram.get(a0, ss)) return -14;
                    task_.alt_stack = ss;
                }
                return 0;
            }
            case S::rt_sigsuspend: {
                // Replace the blocked mask, then WAIT until a signal we will
                // actually deliver becomes pending.
                //
                // The subtlety: this must genuinely block. A spin that keeps
                // returning EINTR turns `timeout 1 sleep 5` -- which loops
                // wait4(WNOHANG) + sigsuspend -- into a busy loop that burns
                // a core and never lets the alarm fire. Sleep on a condition
                // variable the signal path notifies instead, so the thread is
                // genuinely idle and wakes the instant a signal arrives.
                std::uint64_t tmp = 0;
                if (!ram.get(a0, tmp)) return -14;
                const std::uint64_t saved = task_.sig_mask;
                task_.sig_mask = tmp & ~(sigbit(9) | sigbit(19));
                g_pending.wait_for_signal(~task_.sig_mask);
                task_.suspend_restore = saved;
                return -4;                                       // EINTR, as Linux
            }
            default:
                return std::nullopt;
        }
    }

    // Deliver at most one unblocked pending signal by building an rt_sigframe
    // on the guest stack and redirecting the vCPU into the handler. Returns
    // true if the guest's state changed (a handler was entered, or it died).
    [[nodiscard]] bool deliver_pending() {
        // Signals pending for this thread specifically (tgkill) plus the
        // process-wide set (kill).
        const std::uint64_t pending = g_pending.bits.load(std::memory_order_relaxed)
                                    | task_.pending.load(std::memory_order_relaxed);
        const std::uint64_t ready = pending & ~task_.sig_mask;
        if (!ready) {
            // Nothing deliverable. If sigsuspend replaced the mask and no
            // signal arrived, restore it now -- but ONLY now: restoring
            // before this test would re-block the very signal sigsuspend
            // was waiting for, so the handler would never run and
            // `timeout 1 sleep 5` would spin forever.
            if (task_.suspend_restore) {
                task_.sig_mask = *task_.suspend_restore;
                task_.suspend_restore.reset();
            }
            return false;
        }
        const int s = std::countr_zero(ready) + 1;
        g_pending.bits.fetch_and(~sigbit(s), std::memory_order_relaxed);
        task_.pending.fetch_and(~sigbit(s), std::memory_order_relaxed);
        // The sigsuspend mask covered exactly this delivery; the handler
        // runs with it, and the saved mask is what sigreturn restores.
        if (task_.suspend_restore) {
            task_.sig_mask = *task_.suspend_restore;
            task_.suspend_restore.reset();
        }
        LinuxSigaction act = proc_.with_signals([&](SignalDispositions& t) { return t.get(s); });

        if (act.handler == 1) return false;                      // SIG_IGN
        if (act.handler == 0) {                                  // SIG_DFL
            switch (default_action(s)) {
                case Default::ignore: case Default::cont: return false;
                case Default::stop:
                    ::raise(signal_from_linux(s) == SIGTSTP ? SIGSTOP : SIGSTOP);
                    return false;
                case Default::term: case Default::core:
                    // Die BY the signal so the parent's wait sees WIFSIGNALED.
                    route_host_signal(s, false);
                    std::fflush(nullptr);
                    ::raise(signal_from_linux(s));
                    exited_ = true;                              // if it was masked
                    code_ = 128 + s;
                    return true;
            }
        }

        // -- Build the frame. The interrupted state is the vCPU's CURRENT
        // state: we are between guest instructions (after a syscall's result
        // was written, or after a kick out of hv_vcpu_run).
        const HvfCpu::CpuState cpu = cpu_.save();
        std::uint64_t sp = cpu.sp_el0;
        if ((act.flags & sigflag::kOnstack) && task_.alt_stack.ss_size &&
            !(sp > task_.alt_stack.ss_sp && sp <= task_.alt_stack.ss_sp + task_.alt_stack.ss_size))
            sp = task_.alt_stack.ss_sp + task_.alt_stack.ss_size;
        // Stack layout, top to bottom:  [trampoline (16)] [rt_sigframe] <- sp
        // rt_sigreturn finds the frame at the SP the handler returns with,
        // which is exactly where we entered it -- so the frame must be the
        // LOWEST thing pushed. (Pushing the trampoline after the frame put
        // it at sp, and sigreturn read the trampoline as a ucontext: PC 0.)
        std::uint64_t ret = act.restorer;
        const bool need_tramp = !(act.flags & sigflag::kRestorer) || !ret;
        if (need_tramp) {
            sp -= 16;
            if (!machine_.ram().put(sp, kSigreturnTrampoline)) { kill_with(11); return true; }
            machine_.publish_code(sp, 8);
            ret = sp;
        }
        sp = (sp - sizeof(RtSigframe)) & ~std::uint64_t{15};
        const std::uint64_t frame_at = sp;

        RtSigframe frame{};
        frame.info.si_signo = s;
        frame.info.si_code = 0;                                  // SI_USER
        frame.uc.uc_stack = task_.alt_stack;
        frame.uc.uc_sigmask = task_.sig_mask;
        auto& mc = frame.uc.uc_mcontext;
        std::memcpy(mc.regs, cpu.x, sizeof mc.regs);
        mc.sp = cpu.sp_el0;
        mc.pc = cpu.pc;
        mc.pstate = cpu.cpsr;
        FpsimdContext fp{};
        fp.fpsr = static_cast<std::uint32_t>(cpu.fpsr);
        fp.fpcr = static_cast<std::uint32_t>(cpu.fpcr);
        std::memcpy(fp.vregs, cpu.q, sizeof fp.vregs);
        std::memcpy(mc.reserved, &fp, sizeof fp);                // then a zero terminator

        if (!machine_.ram().put(frame_at, frame)) { kill_with(11); return true; }

        // Enter the handler: x0 = signo, x1 = &info, x2 = &uc, lr = restorer.
        HvfCpu::CpuState h = cpu;
        h.x[0] = static_cast<std::uint64_t>(s);
        h.x[1] = frame_at + offsetof(RtSigframe, info);
        h.x[2] = frame_at + offsetof(RtSigframe, uc);
        h.x[30] = ret;
        h.sp_el0 = sp;
        h.pc = act.handler;
        h.cpsr = 0;
        cpu_.load(h);

        task_.sig_mask |= act.mask;
        if (!(act.flags & sigflag::kNodefer)) task_.sig_mask |= sigbit(s);
        if (act.flags & sigflag::kResethand) { act = {}; route_host_signal(s, false); }
        return true;
    }

    // rt_sigreturn: restore the frame the handler was entered with. The
    // handler may have MODIFIED it (that's how siglongjmp-free coroutine
    // libraries and some JITs work), so read it back from guest memory.
    [[nodiscard]] std::int64_t do_sigreturn() {
        RtSigframe frame{};
        if (!machine_.ram().get(cpu_.save().sp_el0, frame)) { kill_with(11); return 0; }
        HvfCpu::CpuState c = cpu_.save();
        const auto& mc = frame.uc.uc_mcontext;
        std::memcpy(c.x, mc.regs, sizeof c.x);
        c.sp_el0 = mc.sp;
        c.pc = mc.pc;
        c.cpsr = mc.pstate & 0xf0000000;                         // NZCV only: stay EL0
        FpsimdContext fp{};
        std::memcpy(&fp, mc.reserved, sizeof fp);
        if (fp.magic == 0x46508001) {
            c.fpsr = fp.fpsr;
            c.fpcr = fp.fpcr;
            std::memcpy(c.q, fp.vregs, sizeof c.q);
        }
        cpu_.load(c);
        task_.sig_mask = frame.uc.uc_sigmask & ~(sigbit(9) | sigbit(19));
        task_.in_sigreturn = true;           // resume() must not clobber x0/PC
        return 0;
    }

    void kill_with(int linux_sig) {
        route_host_signal(linux_sig, false);
        std::fflush(nullptr);
        ::raise(signal_from_linux(linux_sig));
        exited_ = true;
        code_ = 128 + linux_sig;
    }

    // vfork(2) ordering: block the parent until the child has exec'd or
    // exited. The child signals "exec'd" through the shared pid table (it
    // flips its slot's exec flag); exit is observed with a non-reaping
    // waitid(WNOWAIT), so the zombie stays for the parent's real wait4.
    void wait_for_exec(std::int32_t child) {
        auto host = pids_.host_of(child);
        if (!host) return;
        for (int spin = 0;; ++spin) {
            if (pids_.has_execed(child)) return;
            siginfo_t si{};
            if (::waitid(P_PID, static_cast<id_t>(*host), &si,
                         WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == *host)
                return;
            ::usleep(spin < 100 ? 50 : 500);
        }
    }

    // -- Process lifecycle: fork, exec, wait, signals ------------------------
    //
    // A guest process is a host process. The host kernel does the hard parts
    // (COW, scheduling, reaping); we translate numbering and flags.
    [[nodiscard]] Maybe do_lifecycle(abi::Sysno sc) {
        using S = abi::Sysno;
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1),
                            a2 = regs_.arg(2), a3 = regs_.arg(3);
        switch (sc) {
            // clone(flags, stack, ptid, tls, ctid). glibc's fork() is clone
            // with SIGCHLD and no CLONE_VM; that we implement exactly. A
            // clone that SHARES the address space (a pthread) needs a second
            // vCPU over the same RAM, which is a separate, larger feature --
            // refuse it honestly (EAGAIN is what pthread_create reports when
            // a thread can't be made, and callers handle it).
            case S::clone: {
                const CloneRequest req{a0, a1, a2, a3, regs_.arg(4)};
                if (req.is_thread()) return do_clone_thread(req);
                const std::int64_t child = do_fork(req);
                // vfork: the parent must not run until the child has exec'd
                // or exited. posix_spawn reads an error the child writes
                // into what it believes is shared memory; waiting for exec
                // keeps the observable ordering identical.
                if (req.is_vfork() && child > 0)
                    wait_for_exec(static_cast<std::int32_t>(child));
                return child;
            }
            case S::clone3: return -38;     // glibc falls back to clone

            case S::wait4:  return do_wait4(static_cast<std::int32_t>(a0), a1,
                                            static_cast<int>(a2), a3);

            case S::kill: case S::tkill: case S::tgkill: {
                // One implementation, in deliver_signal: it keeps group and
                // broadcast signals inside the guest's process tree instead
                // of letting them reach linuxity's host process group.
                const bool tg = sc == S::tgkill;
                return deliver_signal(static_cast<std::int32_t>(tg ? a1 : a0),
                                      static_cast<std::int32_t>(tg ? a2 : a1));
            }

            case S::getpid: case S::gettid: return task_.tid;
            case S::getppid:                 return parent_;
            default:                         return std::nullopt;
        }
    }

    // A host pointer to a 4-byte guest word, for the futex primitives.
    // Guest RAM is a shared mapping, so this address is valid in every
    // thread AND every forked process -- which is what makes a shared
    // (non-private) futex work across a guest's whole process tree.
    [[nodiscard]] void* futex_ptr(std::uint64_t gaddr) const noexcept {
        if (gaddr % 4) return nullptr;                   // Linux requires 4-byte alignment
        auto win = machine_.ram().at(gaddr, 4);
        return win.empty() ? nullptr : win.data();
    }

    // clone(CLONE_VM|CLONE_THREAD|...): a new thread in THIS process.
    //
    // The new thread gets a host thread of its own, which creates its own
    // vCPU over the same guest RAM -- so guest threads are scheduled by XNU
    // across the physical cores and genuinely run in parallel. Everything
    // the Linux flags say is shared (address space, fd table, signal
    // dispositions, pid) lives in ProcessState; everything per-thread
    // (stack, TLS, tid, blocked mask) is the new TaskState.
    [[nodiscard]] std::int64_t do_clone_thread(const CloneRequest& req) {
        if (!spawn_thread_) return -38;
        if (!req.stack) return -22;                      // a thread needs a stack
        const std::int32_t tid = proc_.next_tid();

        // The child resumes at the same PC as the parent (right after the
        // svc) with x0 = 0 and its own stack/TLS -- exactly what the kernel
        // hands a cloned thread.
        ThreadStart start;
        start.cpu = cpu_.save();
        start.cpu.x[0] = 0;
        start.cpu.pc = regs_.elr;
        start.cpu.cpsr = regs_.spsr;
        start.cpu.sp_el0 = req.stack;
        if (req.flags & clone_flag::settls) start.cpu.tpidr_el0 = req.tls;
        start.tid = tid;
        start.sig_mask = task_.sig_mask;        // inherited, per POSIX
        start.clear_child_tid =
            (req.flags & clone_flag::child_cleartid) ? req.child_tid_addr : 0;

        if (req.flags & clone_flag::child_settid)
            (void)machine_.ram().put(req.child_tid_addr, std::int32_t{tid});
        if (req.flags & clone_flag::parent_settid)
            (void)machine_.ram().put(req.parent_tid_addr, std::int32_t{tid});

        if (!spawn_thread_(std::move(start))) return -11;   // EAGAIN
        return tid;
    }

    // Guest fork, the macOS way (see runtime/hvf_fork.hpp for why fork(2) of
    // linuxity itself is not an option). The parent:
    //   1. pre-allocates the child's GUEST pid (so the return value is known
    //      before the child exists -- no race, no spinning),
    //   2. serializes everything that isn't RAM into a ForkImage,
    //   3. hands RAM (COW snapshot) + image to the embedder's spawn hook,
    //      which starts a fresh linuxity that resumes the guest with x0 = 0.
    [[nodiscard]] std::int64_t do_fork(const CloneRequest& req) {
        if (!pids_.valid() || !spawn_) return -38;
        const std::int32_t child = pids_.allocate(0);   // placeholder host pid
        if (child < 0) return -11;                       // EAGAIN

        ForkImage img;
        img.cpu = cpu_.save();
        img.cpu.x[0] = 0;                                // fork() returns 0 in the child
        img.cpu.pc = regs_.elr;                          // resume after the svc
        img.cpu.cpsr = regs_.spsr;
        if (req.stack) img.cpu.sp_el0 = req.stack;
        if (req.flags & clone_flag::settls) img.cpu.tpidr_el0 = req.tls;
        img.self = child;
        img.parent = task_.tid;
        img.child_settid =
            (req.flags & clone_flag::child_settid) ? req.child_tid_addr : 0;
        img.clear_child_tid =
            (req.flags & clone_flag::child_cleartid) ? req.child_tid_addr : 0;
        img.umask = proc_.umask.load(std::memory_order_relaxed);
        img.sig_mask = task_.sig_mask;
        img.altstack = task_.alt_stack;
        proc_.with_space([&](AddressSpace& sp) {
            img.vmas = sp.vmas();
            img.brk = sp.brk();
            img.arena = sp.arena();
        });
        img.fds = proc_.with_fds([&](FdTable& t) { return t.export_table(); });
        proc_.with_signals([&](SignalDispositions& d) {
            for (int s = 1; s <= kLinuxNsig; ++s) img.sig_actions[s - 1] = d.get(s);
        });

        std::fflush(nullptr);
        const pid_t host = spawn_(img);
        if (host < 0) { pids_.release(child); return -11; }
        pids_.bind(child, host);
        if (req.flags & clone_flag::parent_settid)
            (void)machine_.ram().put(req.parent_tid_addr, std::int32_t{child});
        children_.push_back({child, host});
        return child;
    }

public:
    // Everything a fork child needs that isn't guest RAM. Plain data: the
    // embedder serializes it into the handoff message.
    struct ForkImage {
        HvfCpu::CpuState cpu{};
        std::int32_t self{}, parent{};
        std::uint64_t child_settid{}, clear_child_tid{};
        std::uint32_t umask{022};
        std::vector<Vma> vmas;
        std::uint64_t brk{};
        AddressSpace::Arena arena{};
        std::vector<FdTable::Exported> fds;
        std::array<LinuxSigaction, kLinuxNsig> sig_actions{};
        std::uint64_t sig_mask{};
        LinuxStack altstack{};
        std::string namespace_state;    // FileNamespace::export_process_state
    };
    using SpawnFork = std::function<pid_t(ForkImage&)>;
    void set_fork_spawner(SpawnFork f) { spawn_ = std::move(f); }

    // What a new guest THREAD needs: its starting CPU state plus the
    // per-thread fields. The embedder turns this into a host thread that
    // creates its own vCPU and runs its own Cpu loop.
    struct ThreadStart {
        HvfCpu::CpuState cpu{};
        std::int32_t tid{};
        std::uint64_t sig_mask{};
        std::uint64_t clear_child_tid{};
    };
    using SpawnThread = std::function<bool(ThreadStart)>;
    void set_thread_spawner(SpawnThread f) { spawn_thread_ = std::move(f); }

    // Arm the timer wheel. A fire marks the signal pending and kicks the
    // vCPUs, so it is delivered at the next trap boundary through the SAME
    // path as any other signal -- never as a host signal interrupting
    // linuxity's own work.
    void start_timers() {
        // SIGCHLD from a dying guest child arrives as a host SIGCHLD; route
        // it so `timeout`, `wait` and job control see it.
        route_host_signal(17, true);
        timers_.start([](int linux_sig) {
            if (std::getenv("LINUXITY_STRACE"))
                std::fprintf(stderr, "[timer] fire signal %d\n", linux_sig);
            if (linux_sig > 0 && linux_sig <= kLinuxNsig) {
                g_pending.bits.fetch_or(sigbit(linux_sig), std::memory_order_relaxed);
                g_pending.kick_all();
            }
        });
    }

    // This thread is done but the process may live on (exit(2) vs
    // exit_group(2)); the embedder uses this to join rather than tear down.
    [[nodiscard]] bool thread_exited() const noexcept { return thread_exited_; }

    // Child side: become the forked process described by `img`. The VM is
    // already up over the snapshot RAM; restore everything else.
    void resume_fork_child(const ForkImage& img, const std::vector<int>& host_fds) {
        cpu_.load(img.cpu);
        task_.tid = img.self;
        parent_ = img.parent;
        proc_.umask = img.umask;
        proc_.with_space([&](AddressSpace& t) { return t.restore(img.vmas, img.brk, img.arena); });
        proc_.with_fds([&](FdTable& t) { return t.import_table(img.fds, host_fds); });
        // fork(2): the child inherits handlers, mask and alt stack verbatim.
        proc_.with_signals([&](SignalDispositions& d) {
            for (int s = 1; s <= kLinuxNsig; ++s) (void)d.set(s, img.sig_actions[s - 1]);
        });
        task_.sig_mask = img.sig_mask;
        task_.alt_stack = img.altstack;
        for (int s = 1; s <= kLinuxNsig; ++s) {
            const auto h = proc_.with_signals([&](SignalDispositions& t) { return t.get(s); }).handler;
            if (h == 1) { const int hs = signal_from_linux(s);
                          if (hs > 0 && hs != SIGKILL && hs != SIGSTOP) ::signal(hs, SIG_IGN); }
            else if (h) route_host_signal(s, true);
        }
        if (img.child_settid) (void)machine_.ram().put(img.child_settid, std::int32_t{task_.tid});
        task_.clear_child_tid = img.clear_child_tid;
        regs_.elr = img.cpu.pc;
        regs_.spsr = img.cpu.cpsr;
    }
    [[nodiscard]] PidSpace& pids() noexcept { return pids_; }

private:

    // wait4(pid, status*, options, rusage*). Linux and Darwin share the wait
    // option bits we accept (WNOHANG=1, WUNTRACED=2); the STATUS is
    // re-encoded so signal numbers match the guest's.
    [[nodiscard]] std::int64_t do_wait4(std::int32_t gpid, std::uint64_t status,
                                        int options, std::uint64_t rusage) {
        pid_t which;
        if (gpid == -1)      which = -1;
        else if (gpid == 0)  which = 0;
        else if (gpid < -1) { auto h = pids_.host_of(-gpid); if (!h) return -10; which = -*h; }
        else                { auto h = pids_.host_of(gpid);  if (!h) return -10; which = *h; }
        int st = 0;
        const pid_t got = ::waitpid(which, &st, options & (WNOHANG | WUNTRACED));
        if (got < 0) return darwin::fail();
        if (got == 0) return 0;                                   // WNOHANG
        std::int32_t g = pids_.guest_of(got);
        if (status) (void)machine_.ram().put(status, std::int32_t{wstatus_to_linux(st)});
        if (rusage) {
            std::byte zero[144]{};                                // struct rusage
            (void)machine_.ram().put(rusage, zero);
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            pids_.release(g);
            std::erase_if(children_, [got](const Child& c) { return c.host == got; });
        }
        return g < 0 ? 0 : g;
    }

    // execve's recoverable failures, checked against the HOST file before any
    // guest state is destroyed. Follows #! and PT_INTERP so a script whose
    // interpreter is missing fails with ENOENT, as on Linux.
    [[nodiscard]] static std::int64_t exec_precheck(
            const std::function<std::string(const std::string&)>& resolve,
            std::string guest) {
        for (int depth = 0; depth < 4; ++depth) {
            const std::string host = resolve(guest);
            if (host.empty()) return -2;                             // ENOENT
            struct ::stat st{};
            if (::stat(host.c_str(), &st) < 0) return darwin::fail();
            if (S_ISDIR(st.st_mode)) return -13;                     // EACCES
            if (::access(host.c_str(), X_OK) < 0) return -13;
            if (auto sh = loader::read_shebang(host); !sh.interp.empty()) {
                guest = sh.interp;
                continue;
            }
            if (loader::read_elf_machine(host) == loader::ForeignArch::foreign) return -8;
            if (auto in = loader::read_elf_interp(host); !in.empty()) {
                if (resolve(in).empty()) return -2;
            }
            return 0;
        }
        return -40;                                                  // ELOOP
    }

    // execve(path, argv, envp): REPLACE this process's image, in place.
    //
    // On Linux the kernel does this; here it is our job, and the order is the
    // whole subtlety. Read argv/envp out of guest RAM FIRST -- the reset that
    // follows destroys them -- then wipe the address space, load the new
    // program (and its PT_INTERP loader, and resolve #! chains), and point
    // the vCPU at the new entry. Nothing of the old image may survive except
    // what POSIX says does: the pid, the fd table minus FD_CLOEXEC, and cwd.
    [[nodiscard]] std::int64_t do_execve(const std::string& host_path) {
        const GuestRam ram = machine_.ram();
        auto read_vec = [&](std::uint64_t at) {
            std::vector<std::string> v;
            for (std::size_t i = 0; at && i < 4096; ++i) {
                std::uint64_t p = 0;
                if (!ram.get(at + i * 8, p) || p == 0) break;
                v.push_back(ram.cstr(p, 128 * 1024));
            }
            return v;
        };
        std::string guest_path = ram.cstr(regs_.arg(0));
        std::vector<std::string> argv = read_vec(regs_.arg(1));
        std::vector<std::string> envp = read_vec(regs_.arg(2));
        if (argv.empty()) argv.push_back(guest_path);
        if (!resolve_) return -38;

        // The dispatcher already translated the program path; let the exec
        // resolver use that answer for the program itself and the namespace
        // for everything it chains to (interpreters, #! targets).
        auto resolve = [&](const std::string& g) {
            return g == guest_path ? host_path : resolve_(g);
        };

        // Everything that can fail with an ordinary errno is checked BEFORE
        // the old image is touched, exactly like the kernel's execve: missing
        // file, not executable, not an ELF/script, missing interpreter. This
        // is load-bearing, not pedantry -- execvp() and posix_spawnp() probe
        // each $PATH entry in turn and rely on ENOENT/EACCES to move to the
        // next one. Treating the first miss as fatal broke xargs, find -exec
        // and every program that runs a command by name.
        if (const std::int64_t e = exec_precheck(resolve, guest_path); e < 0) return e;
        // Point of no return: from here a failure cannot return to the old
        // image, which is gone. Linux kills the process in that case too.
        //
        // Zero only what the old image MAPPED, not all of guest RAM. The
        // VMA map knows exactly which ranges were ever handed out; clearing
        // the whole 2 GiB instead cost ~170 ms per exec, because a fork
        // child's RAM is a COW snapshot and every page written -- even with
        // zeros -- is a page fault plus a page copy. Untouched pages are
        // already zero (fresh anonymous memory) or stale-but-unmapped, and
        // the loader zeroes every segment and .bss it places.
        for (const Vma& v : proc_.with_space([&](AddressSpace& t) { return t.vmas(); })) machine_.zero(v.begin, v.size());
        auto ex = hvf_exec(machine_, resolve, guest_path, argv, envp);
        if (!ex) {
            std::fprintf(stderr, "linuxity: execve %s failed (errno %d)\n",
                         guest_path.c_str(), static_cast<int>(ex.error()));
            exited_ = true;
            code_ = 127;
            return 0;
        }
        set_arena(ex->brk_base, ExecArena::mmap_top(machine_.mem_size()));
        for (const auto& sg : ex->segments)
            adopt(sg.begin, sg.end, prot_from_elf(sg.flags));
        adopt_stack(ex->sp, machine_.mem_size());
        proc_.with_fds([&](FdTable& t) { return t.on_exec(); });
        dirs_.clear();
        // execve(2): caught signals revert to SIG_DFL (the handler code is
        // gone); ignored stay ignored; the blocked mask is preserved; the
        // alt stack is cleared.
        for (int s = 1; s <= kLinuxNsig; ++s)
            if (proc_.with_signals([&](SignalDispositions& t) { return t.get(s); }).handler > 1) route_host_signal(s, false);
        proc_.with_signals([&](SignalDispositions& t) { return t.on_exec(); });
        task_.alt_stack = {};
        // The new image starts fresh: clear every GPR (no state may leak from
        // the old program into the new one), then enter.
        for (int i = 0; i < 31; ++i) cpu_.set_x(i, 0);
        cpu_.set_tls(0);
        regs_.elr = ex->entry;
        regs_.spsr = 0;
        cpu_.set_sp(ex->sp);
        execed_ = true;
        pids_.mark_execed(task_.tid);           // releases a vfork parent
        return 0;
    }

    [[nodiscard]] Maybe do_process(abi::Sysno sc) {
        using S = abi::Sysno;
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1),
                            a2 = regs_.arg(2), a3 = regs_.arg(3);
        const GuestRam ram = machine_.ram();
        switch (sc) {
            case S::exit:
                // exit(2) ends THIS THREAD. With siblings alive the process
                // lives on, so this thread just unwinds: clear its
                // clear_child_tid word and wake anyone joining on it (that
                // is precisely how pthread_join learns the thread is gone),
                // then stop running it.
                if (task_.clear_child_tid) {
                    (void)machine_.ram().put(task_.clear_child_tid, std::int32_t{0});
                    if (auto* p = futex_ptr(task_.clear_child_tid))
                        (void)Futex::wake(p, 1, true);
                }
                exited_ = true;
                code_ = static_cast<int>(a0 & 0xff);
                thread_exited_ = true;
                return 0;
            case S::exit_group:
                // exit_group(2) ends every thread. Mark the group dead and
                // kick the siblings out of the guest so they observe it.
                proc_.request_group_exit(static_cast<int>(a0 & 0xff));
                exited_ = true;
                code_ = static_cast<int>(a0 & 0xff);
                return 0;

            // Thread/signal state libc installs at startup. There is no host
            // task to carry it and nothing reads it back on this backend.
            case S::set_tid_address: case S::rt_sigaction:
            case S::rt_sigprocmask:  case S::sigaltstack:
                return 0;

            // -- getrandom(buf, len, flags). glibc's startup REQUIRES this
            //    for its stack guard and malloc's randomization; an ENOSYS
            //    here aborts the program. Darwin has arc4random_buf, which
            //    is the same cryptographic contract.
            case S::getrandom: {
                auto win = ram.clamp(a0, a1);
                if (win.empty()) return -14;
                ::arc4random_buf(win.data(), win.size());
                return static_cast<std::int64_t>(win.size());
            }

            // -- clock_gettime(clkid, timespec*). Both kernels agree on the
            //    struct (two 64-bit words) and on CLOCK_REALTIME=0 /
            //    MONOTONIC=1, so only the clock id needs mapping.
            case S::clock_gettime: {
                ::clockid_t id = CLOCK_REALTIME;
                switch (a0) {
                    case 1: case 5: id = CLOCK_MONOTONIC;        break;
                    case 2: case 3: id = CLOCK_PROCESS_CPUTIME_ID; break;
                    default:        id = CLOCK_REALTIME;         break;
                }
                struct ::timespec ts{};
                if (::clock_gettime(id, &ts) < 0) return darwin::fail();
                struct LinuxTimespec { std::int64_t sec; std::int64_t nsec; };
                LinuxTimespec out{ts.tv_sec, ts.tv_nsec};
                return ram.put(a1, out) ? 0 : -14;
            }

            // -- prlimit64(pid, res, new*, old*). Report the host's limit
            //    for the one that matters (RLIMIT_STACK/NOFILE drive libc's
            //    buffer sizing); setting is accepted as a no-op.
            case S::prlimit64: {
                if (a2) return 0;                 // a set: accept silently
                struct LinuxRlimit { std::uint64_t cur, max; };
                LinuxRlimit out{~std::uint64_t{0}, ~std::uint64_t{0}};
                if (a1 == 3) {                    // RLIMIT_STACK
                    out.cur = 8ull << 20;
                } else if (a1 == 7) {             // RLIMIT_NOFILE
                    out.cur = out.max = 1024;
                }
                return ram.put(regs_.arg(3), out) ? 0 : -14;
            }

            // -- futex(uaddr, op, val, timeout/val2, uaddr2, val3).
            //
            // THE threading primitive: every pthread mutex, condvar,
            // semaphore, barrier, once-flag and join bottoms out here.
            // macOS 14's os_sync_wait_on_address has the same contract
            // (compare-and-sleep atomically, wake by address) including
            // cross-process SHARED support, so this is a real futex rather
            // than an approximation -- see hvf_futex.hpp.
            case S::futex: {
                const std::uint32_t cmd = static_cast<std::uint32_t>(a1) & kFutexCmdMask;
                const bool shared = (static_cast<std::uint32_t>(a1) & kFutexPrivate) == 0;
                void* p = futex_ptr(a0);
                if (!p) return -14;                                  // EFAULT
                switch (static_cast<FutexOp>(cmd)) {
                    case FutexOp::wait:
                    case FutexOp::wait_bitset: {
                        // The bitset is ignored: Linux permits spurious
                        // wakeups, so a waiter whose bit did not match
                        // rechecks and sleeps again.
                        std::uint64_t ns = 0;
                        if (a3) {
                            struct { std::int64_t sec, nsec; } ts{};
                            if (!machine_.ram().get(a3, ts)) return -14;
                            ns = static_cast<std::uint64_t>(ts.sec) * 1'000'000'000ull
                               + static_cast<std::uint64_t>(ts.nsec);
                            if (ns == 0) ns = 1;        // 0 would mean "forever"
                        }
                        return Futex::wait(p, static_cast<std::uint32_t>(a2), ns, shared);
                    }
                    case FutexOp::wake:
                    case FutexOp::wake_bitset:
                        return Futex::wake(p, static_cast<std::uint32_t>(a2), shared);

                    case FutexOp::requeue:
                    case FutexOp::cmp_requeue: {
                        // Requeue exists to avoid a thundering herd, never
                        // for correctness: waking both addresses is a valid
                        // (if less efficient) implementation.
                        if (cmd == static_cast<std::uint32_t>(FutexOp::cmp_requeue)) {
                            std::uint32_t cur = 0;
                            if (!machine_.ram().get(a0, cur)) return -14;
                            if (cur != static_cast<std::uint32_t>(regs_.arg(5))) return -11;
                        }
                        std::int64_t woke = Futex::wake(p, static_cast<std::uint32_t>(a2), shared);
                        if (void* p2 = futex_ptr(regs_.arg(4)))
                            woke += Futex::wake(p2, ~0u, shared);
                        return woke;
                    }
                    case FutexOp::wake_op: {
                        // FUTEX_WAKE_OP: atomically apply an op to *uaddr2,
                        // wake val waiters on uaddr, and wake val2 on uaddr2
                        // if the OLD value satisfies the comparison.
                        void* p2 = futex_ptr(regs_.arg(4));
                        if (!p2) return -14;
                        const auto spec = WakeOpSpec::decode(
                            static_cast<std::uint32_t>(regs_.arg(5)));
                        // The guest word is plain shared memory; atomic_ref
                        // gives it atomic semantics without copying it.
                        std::atomic_ref<std::uint32_t> ref{
                            *static_cast<std::uint32_t*>(p2)};
                        std::uint32_t old = ref.load(std::memory_order_relaxed);
                        while (!ref.compare_exchange_weak(old, spec.apply(old),
                                                          std::memory_order_acq_rel,
                                                          std::memory_order_relaxed)) {}
                        std::int64_t woke = Futex::wake(p, static_cast<std::uint32_t>(a2), shared);
                        if (spec.compare(old))
                            woke += Futex::wake(p2, static_cast<std::uint32_t>(a3), shared);
                        return woke;
                    }
                    default:
                        // Priority-inheritance futexes need a real PI mutex
                        // in the kernel. glibc only uses them for
                        // PTHREAD_PRIO_INHERIT mutexes, which it falls back
                        // from on ENOSYS.
                        return -38;
                }
            }

            case S::set_robust_list:
                return 0;
            case S::rseq:
                return -38;       // glibc disables rseq when registration fails
            case S::membarrier:
                // Guest threads are host threads on real cores; a full
                // barrier here orders this thread, and the host's own
                // coherency does the rest.
                std::atomic_thread_fence(std::memory_order_seq_cst);
                return 0;
            case S::sched_yield:
                ::sched_yield();
                return 0;

            case S::nanosleep: case S::clock_nanosleep: {
                // nanosleep(req, rem) / clock_nanosleep(clk, flags, req, rem).
                const bool clk = sc == S::clock_nanosleep;
                struct LinuxTimespec { std::int64_t sec; std::int64_t nsec; };
                LinuxTimespec req{};
                if (!ram.get(clk ? a2 : a0, req)) return -14;
                struct ::timespec ts{static_cast<time_t>(req.sec),
                                     static_cast<long>(req.nsec)};
                constexpr std::uint64_t kTimerAbstime = 1;
                if (clk && (a1 & kTimerAbstime)) {
                    struct ::timespec now{};
                    ::clock_gettime(a0 == 1 ? CLOCK_MONOTONIC : CLOCK_REALTIME, &now);
                    std::int64_t d = (req.sec - now.tv_sec) * 1'000'000'000LL +
                                     (req.nsec - now.tv_nsec);
                    if (d <= 0) return 0;
                    ts = {static_cast<time_t>(d / 1'000'000'000LL),
                          static_cast<long>(d % 1'000'000'000LL)};
                }
                return ::nanosleep(&ts, nullptr) < 0 ? darwin::fail() : 0;
            }

            case S::umask: {
                return proc_.umask.exchange(static_cast<std::uint32_t>(a0 & 0777),
                                           std::memory_order_relaxed);
            }
            case S::getgroups:
                return 0;           // root, no supplementary groups

            // -- Credentials. linuxity's world is uid 0 and has exactly one
            //    identity, so a request to BECOME root (or stay root) is
            //    satisfied; a request to become someone else cannot be, and
            //    EPERM is what a real kernel tells an unprivileged caller.
            //    Refusing with ENOSYS instead makes libc think the kernel is
            //    broken rather than the operation disallowed.
            case S::setuid: case S::setgid: case S::setfsuid: case S::setfsgid:
                return a0 == 0 || a0 == static_cast<std::uint64_t>(-1) ? 0 : -1;
            case S::setreuid: case S::setregid:
                return (a0 == 0 || a0 == ~0ull) && (a1 == 0 || a1 == ~0ull) ? 0 : -1;
            case S::setresuid: case S::setresgid:
                return (a0 == 0 || a0 == ~0ull) && (a1 == 0 || a1 == ~0ull) &&
                       (a2 == 0 || a2 == ~0ull) ? 0 : -1;
            case S::setgroups:
                return 0;                        // only the empty/root set exists

            // -- Time of day. gettimeofday is the single most-called syscall
            //    in a shell session (every prompt, every `date`, every log
            //    line), and the core forwards it here.
            case S::gettimeofday: {
                struct ::timeval tv{};
                if (::gettimeofday(&tv, nullptr) < 0) return darwin::fail();
                if (a0) {
                    const LinuxTimeval out{tv.tv_sec, tv.tv_usec};
                    if (!ram.put(a0, out)) return -14;
                }
                if (a1) {                        // struct timezone: obsolete, zeros
                    const std::int32_t tz[2] = {0, 0};
                    if (!ram.put(a1, tz)) return -14;
                }
                return 0;
            }
            case S::clock_settime: case S::settimeofday:
                return -1;                       // EPERM: the host clock is not ours

            // -- Interval timers (alarm, SIGALRM timeouts). See hvf_timer.hpp.
            case S::setitimer: {
                const int which = static_cast<int>(a0);
                if (!TimerSet::valid_itimer(which)) return -22;
                TimerSet::Interval next{};
                if (a1) {
                    LinuxItimerval v{};
                    if (!ram.get(a1, v)) return -14;
                    next.value = std::chrono::seconds{v.value.sec}
                               + std::chrono::microseconds{v.value.usec};
                    next.interval = std::chrono::seconds{v.interval.sec}
                                  + std::chrono::microseconds{v.interval.usec};
                }
                const auto prev = timers_.set_interval(which, next);
                if (a2 && !ram.put(a2, to_itimerval(prev))) return -14;
                return 0;
            }
            case S::getitimer: {
                const int which = static_cast<int>(a0);
                if (!TimerSet::valid_itimer(which)) return -22;
                return ram.put(a1, to_itimerval(timers_.get_interval(which))) ? 0 : -14;
            }

            // -- POSIX timers (timer_create and friends).
            case S::timer_create: {
                // sigevent { sigval, signo, notify, ... }: we need signo and
                // notify. SIGEV_THREAD is implemented as SIGEV_SIGNAL --
                // glibc itself builds SIGEV_THREAD on a helper thread plus a
                // signal, so the observable behaviour is a signal either way.
                int signo = 14, notify = kSigevSignal;
                if (a1) {
                    struct LinuxSigevent {
                        std::uint64_t value;
                        std::int32_t signo, notify;
                    } ev{};
                    if (!ram.get(a1, ev)) return -14;
                    signo = ev.signo;
                    notify = ev.notify;
                }
                const int id = timers_.create(signo, notify);
                return ram.put(a2, std::int32_t{id}) ? 0 : -14;
            }
            case S::timer_settime: {
                constexpr std::uint64_t kAbstime = 1;
                LinuxItimerspec v{};
                if (a2 && !ram.get(a2, v)) return -14;
                TimerSet::Interval next{
                    std::chrono::seconds{v.value.sec} + std::chrono::nanoseconds{v.value.nsec},
                    std::chrono::seconds{v.interval.sec} + std::chrono::nanoseconds{v.interval.nsec}};
                const auto prev = timers_.set_posix(static_cast<int>(a0), next,
                                                    (a1 & kAbstime) != 0);
                if (!prev) return -22;           // EINVAL: no such timer
                if (a3 && !ram.put(a3, to_itimerspec(*prev))) return -14;
                return 0;
            }
            case S::timer_gettime: {
                const auto cur = timers_.get_posix(static_cast<int>(a0));
                if (!cur) return -22;
                return ram.put(a1, to_itimerspec(*cur)) ? 0 : -14;
            }
            case S::timer_getoverrun: {
                const auto n = timers_.overrun(static_cast<int>(a0));
                return n ? *n : -22;
            }
            case S::timer_delete:
                return timers_.erase(static_cast<int>(a0)) ? 0 : -22;

            default:
                return std::nullopt;
        }
    }

    [[nodiscard]] Maybe do_memory(abi::Sysno sc) {
        using S = abi::Sysno;
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1),
                            a2 = regs_.arg(2), a3 = regs_.arg(3);
        switch (sc) {
            case S::brk:
                return static_cast<std::int64_t>(proc_.with_space([&](AddressSpace& t) { return t.set_brk(a0); }));
            case S::mmap: {
                constexpr std::uint64_t kFixed = 0x10, kAnon = 0x20;
                const bool anon = (a3 & kAnon) != 0;
                const std::uint64_t len = AddressSpace::page_up(a1);
                std::uint64_t at = proc_.with_space([&](AddressSpace& t) { return t.map(a0, a1, prot_from_linux(a2),
                                           (a3 & kFixed) != 0, anon); });
                if (at == AddressSpace::kFail) return -12;          // ENOMEM
                auto win = machine_.ram().at(at, len);
                if (win.empty()) return -12;

                if (anon) {
                    // A fresh anonymous mapping must read as zero -- and for
                    // an ANON map the guest asked for the whole page span, so
                    // clearing to the page-rounded end is correct here.
                    machine_.zero(at, len);
                    return static_cast<std::int64_t>(at);
                }

                // File-backed. Read what the file actually has, then zero the
                // remainder of the mapping.
                //
                // The zeroing is NOT optional, and it is the subtlety that
                // cost the most debugging here. ld.so loads a library in
                // layers: first one big PROT_NONE reservation, then each
                // PT_LOAD MAP_FIXED over it with a length rounded up to the
                // segment's MEMORY size -- which exceeds its FILE size
                // whenever the segment has a .bss tail. Linux satisfies the
                // excess with zero-filled pages; a backend that just preads
                // leaves whatever the previous layer wrote there. For glibc's
                // libc.so.6 that means the text map's bytes stay visible in
                // the data segment's tail, and the guest loads an ELF header
                // where a GOT pointer belongs -- faulting on 0x...464c4587,
                // which is "\x7fELF" read as an address.
                //
                // Note `a1` (the requested length), not `len` (page-rounded):
                // segments SHARE pages. libc's data segment starts at vaddr
                // 0x1bd090, 0x90 bytes into a page the text segment already
                // covers, so rounding up here would wipe a neighbour.
                const int ffd = proc_.with_fds([&](FdTable& t) { return t.host(static_cast<int>(regs_.arg(4))); }).value_or(-1);
                if (ffd < 0) return -9;                              // EBADF
                const auto foff = static_cast<off_t>(regs_.arg(5));
                auto n = ::pread(ffd, win.data(), a1, foff);
                if (n < 0) return darwin::fail();
                const auto got = static_cast<std::uint64_t>(n);
                if (got < a1) {
                    auto tail = machine_.ram().at(at + got, a1 - got);
                    if (!tail.empty()) std::memset(tail.data(), 0, tail.size());
                }
                // The mapping may be an executable segment written through the
                // host's data view; publish it to the instruction stream.
                if (has(prot_from_linux(a2), GuestProt::exec))
                    machine_.publish_code(at, len);
                return static_cast<std::int64_t>(at);
            }
            case S::munmap:
                proc_.with_space([&](AddressSpace& t) { return t.unmap(a0, a1); });
                return 0;
            case S::mprotect:
                // Tracked in the VMA map but NOT enforced in the page tables:
                // the stage-1 tables are built RWX once, and per-page
                // reprotection would need a table walk plus TLB maintenance
                // on every call. Recorded so /proc/self/maps is truthful and
                // so enforcement can be added without an ABI change.
                return proc_.with_space([&](AddressSpace& t) { return t.protect(a0, a1, prot_from_linux(a2)); }) ? 0 : -12;
            case S::madvise: {
                // Only MADV_DONTNEED changes visible state: anonymous pages
                // must read back as zero afterwards. glibc's malloc relies
                // on it when trimming. Every other advice is a hint.
                constexpr std::uint64_t kDontNeed = 4;
                if (a2 == kDontNeed) {
                    const Vma* v = proc_.with_space([&](AddressSpace& t) { return t.find(a0); });
                    if (v && v->anonymous) machine_.zero(a0, AddressSpace::page_up(a1));
                }
                return 0;
            }
            case S::mremap: {
                // mremap(old, old_len, new_len, flags, new_addr). Grow or
                // move by allocating fresh space and copying: guest RAM is
                // one flat region, so a copy IS the remap. MREMAP_MAYMOVE
                // must be set for a move (else ENOMEM, as Linux does).
                constexpr std::uint64_t kMayMove = 1;
                const std::uint64_t old_len = AddressSpace::page_up(a1);
                const std::uint64_t new_len = AddressSpace::page_up(a2);
                const Vma* v = proc_.with_space([&](AddressSpace& t) { return t.find(a0); });
                if (!v) return -14;
                if (new_len <= old_len) {
                    proc_.with_space([&](AddressSpace& t) { return t.unmap(a0 + new_len, old_len - new_len); });
                    return static_cast<std::int64_t>(a0);
                }
                if (!(a3 & kMayMove)) return -12;
                const GuestProt prot = v->prot;
                const bool anon = v->anonymous;
                std::uint64_t to = proc_.with_space([&](AddressSpace& t) { return t.map(0, new_len, prot, false, anon); });
                if (to == AddressSpace::kFail) return -12;
                auto src = machine_.ram().at(a0, old_len);
                auto dst = machine_.ram().at(to, new_len);
                if (src.empty() || dst.empty()) return -14;
                std::memmove(dst.data(), src.data(), old_len);
                machine_.zero(to + old_len, new_len - old_len);
                proc_.with_space([&](AddressSpace& t) { return t.unmap(a0, old_len); });
                return static_cast<std::int64_t>(to);
            }
            default:
                return std::nullopt;
        }
    }

    [[nodiscard]] Maybe do_io(abi::Sysno sc) {
        using S = abi::Sysno;
        const auto gfd = static_cast<int>(regs_.arg(0));
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1),
                            a2 = regs_.arg(2), a3 = regs_.arg(3);
        const GuestRam ram = machine_.ram();

        // fd-table operations first: they don't need a resolved host fd.
        switch (sc) {
            case S::close:
                dirs_.erase(gfd);                  // drop any directory stream
                return proc_.with_fds([&](FdTable& t) { return t.close(gfd); });
            case S::dup:   return proc_.with_fds([&](FdTable& t) { return t.dup(gfd, std::nullopt, false); });
            case S::dup3: {
                constexpr std::uint64_t kCloexec = 02000000;
                if (static_cast<int>(a1) == gfd) return -22;          // EINVAL
                return proc_.with_fds([&](FdTable& t) { return t.dup(gfd, static_cast<int>(a1), (a2 & kCloexec) != 0); });
            }
            case S::fcntl: return do_fcntl(gfd, a1, a2);
            case S::ioctl: {
                auto h = proc_.with_fds([&](FdTable& t) { return t.host(gfd); });
                if (!h) return -9;
                return do_ioctl(*h, a1, a2);
            }
            case S::ppoll:    return do_ppoll(regs_.arg(0), a1, a2);
            case S::pselect6: return do_pselect(regs_.arg(0), a1, a2, a3, regs_.arg(4));

            // eventfd2(initval, flags): a counter you can poll. curl, glib
            // and every event loop uses one as a wakeup channel, and curl
            // reports a failure here as "Out of memory". Darwin has no
            // eventfd, but a pipe has the property that matters -- it is
            // pollable and can be written from another thread -- and the
            // counter semantics only have to be consistent, since nothing
            // but the owner interprets the bytes.
            case S::eventfd2: {
                constexpr std::uint64_t kNonblock = 0x800, kCloexec = 0x80000;
                int p[2];
                if (::pipe(p) < 0) return darwin::fail();
                for (int e : p) {
                    ::fcntl(e, F_SETFD, FD_CLOEXEC);
                    if (a1 & kNonblock)
                        ::fcntl(e, F_SETFL, ::fcntl(e, F_GETFL) | O_NONBLOCK);
                }
                // One guest fd, both pipe ends: a read drains, a write
                // signals. The write end is kept alive by the EventFd record
                // so the read end never sees EOF.
                const int g = proc_.with_fds([&](FdTable& t) {
                    return t.install_eventfd(p[0], p[1], (a1 & kCloexec) != 0);
                });
                if (g < 0) { ::close(p[0]); ::close(p[1]); return -24; }
                if (a0) {
                    const std::uint64_t init = a0;
                    (void)::write(p[1], &init, sizeof init);
                }
                return g;
            }
            case S::sync:  ::sync(); return 0;
            case S::pipe2: {
                // pipe2(int fds[2], flags): a real Darwin pipe, installed
                // into the guest's table. Host ends are CLOEXEC regardless.
                constexpr std::uint64_t kCloexec = 02000000, kNonblock = 04000;
                int p[2];
                if (::pipe(p) < 0) return darwin::fail();
                for (int e : p) {
                    ::fcntl(e, F_SETFD, FD_CLOEXEC);
                    if (a1 & kNonblock)
                        ::fcntl(e, F_SETFL, ::fcntl(e, F_GETFL) | O_NONBLOCK);
                }
                const bool cx = (a1 & kCloexec) != 0;
                // BOTH ends in ONE locked section. Two separate install()
                // calls would also be correct here, but doing it atomically
                // keeps the guest's fd numbering deterministic when another
                // thread is opening files concurrently -- pipe(2) promises
                // the two lowest free descriptors.
                const auto g = proc_.with_fds([&](FdTable& t) {
                    return std::pair{t.install(p[0], cx), t.install(p[1], cx)};
                });
                if (g.first < 0 || g.second < 0) return -24;         // EMFILE
                const std::int32_t pair[2] = {g.first, g.second};
                return ram.put(regs_.arg(0), pair) ? 0 : -14;
            }
            default: break;
        }

        const auto hfd = proc_.with_fds([&](FdTable& t) { return t.host(gfd); });
        // An eventfd is one guest fd over a pipe PAIR: reads drain the read
        // end, writes signal the write end.
        const auto wfd = proc_.with_fds([&](FdTable& t) { return t.write_host(gfd); });
        auto need_fd = [&]() -> bool { return hfd.has_value(); };
        switch (sc) {
            case S::read: {
                if (!need_fd()) return -9;                          // EBADF
                auto win = ram.clamp(a1, a2);
                if (win.empty() && a2) return -14;                  // EFAULT
                auto n = ::read(*hfd, win.data(), win.size());
                return n < 0 ? darwin::fail() : n;
            }
            case S::write: {
                if (!need_fd()) return -9;
                auto win = ram.clamp(a1, a2);
                if (win.empty() && a2) return -14;
                auto n = ::write(*wfd, win.data(), win.size());
                return n < 0 ? darwin::fail() : n;
            }
            case S::pread64: {
                if (!need_fd()) return -9;
                auto win = ram.clamp(a1, a2);
                if (win.empty() && a2) return -14;
                auto n = ::pread(*hfd, win.data(), win.size(), static_cast<off_t>(a3));
                return n < 0 ? darwin::fail() : n;
            }
            case S::pwrite64: {
                if (!need_fd()) return -9;
                auto win = ram.clamp(a1, a2);
                if (win.empty() && a2) return -14;
                auto n = ::pwrite(*wfd, win.data(), win.size(), static_cast<off_t>(a3));
                return n < 0 ? darwin::fail() : n;
            }
            case S::readv: case S::writev:
                if (!need_fd()) return -9;
                return do_vector(sc == S::writev, sc == S::writev ? *wfd : *hfd, a1, a2);
            case S::lseek: {
                if (!need_fd()) return -9;
                auto off = ::lseek(*hfd, static_cast<off_t>(a1), static_cast<int>(a2));
                return off < 0 ? darwin::fail() : off;
            }
            case S::fstat: {
                if (!need_fd()) return -9;
                struct ::stat st{};
                if (::fstat(*hfd, &st) < 0) return darwin::fail();
                return ram.put(a1, darwin::to_linux(st)) ? 0 : -14;
            }
            case S::ftruncate:
                if (!need_fd()) return -9;
                return ::ftruncate(*hfd, static_cast<off_t>(a1)) < 0
                           ? darwin::fail() : 0;
            case S::fsync: case S::fdatasync:
                if (!need_fd()) return -9;
                return ::fsync(*hfd) < 0 ? darwin::fail() : 0;
            case S::fstatfs: {
                if (!need_fd()) return -9;
                struct ::statfs s{};
                if (::fstatfs(*hfd, &s) < 0) return darwin::fail();
                return ram.put(a1, darwin::statfs_to_linux(s)) ? 0 : -14;
            }
            case S::fchdir:
                // The core maps the fd back to its guest path and updates the
                // namespace cwd; we only check the fd is a real directory.
                if (!need_fd()) return -9;
                {
                    struct ::stat st{};
                    if (::fstat(*hfd, &st) < 0) return darwin::fail();
                    if (!S_ISDIR(st.st_mode)) return -20;
                }
                return 0;
            case S::flock:
                if (!need_fd()) return -9;
                return ::flock(*hfd, static_cast<int>(a1)) < 0 ? darwin::fail() : 0;
            case S::getdents64:
                if (!need_fd()) return -9;
                return do_getdents(gfd, *hfd, a1, a2);
            // close_range(first, last, flags): libc's closefrom(), used by
            // every spawn helper right before exec.
            case S::close_range: {
                const auto lo = static_cast<int>(a0);
                const auto hi = static_cast<int>(std::min<std::uint64_t>(a1, FdTable::kMaxFds - 1));
                proc_.with_fds([&](FdTable& t) {
                    for (int fd = lo; fd <= hi; ++fd) (void)t.close(fd);
                });
                return 0;
            }
            default:
                return std::nullopt;
        }
    }

    // getdents64(fd, buf, len): Darwin's on-disk record format differs from
    // linux_dirent64, so read entries with readdir(3) and re-encode.
    //
    // The DIR* is opened ONCE per guest fd over a dup of the host fd and kept
    // until close: getdents is called repeatedly until it returns 0, and the
    // stream position must persist across calls. An entry that doesn't fit
    // the guest's buffer is held back (`pending`) for the next call rather
    // than skipped -- dropping it is the classic getdents bug that makes `ls`
    // silently lose files in large directories.
    [[nodiscard]] std::int64_t do_getdents(int gfd, int hfd, std::uint64_t buf,
                                           std::uint64_t cap) {
        DirStream& ds = dirs_[gfd];
        if (!ds.dir) {
            int d = ::dup(hfd);
            if (d < 0) return darwin::fail();
            ds.dir = ::fdopendir(d);
            if (!ds.dir) { ::close(d); return darwin::fail(); }
        }
        auto out = machine_.ram().clamp(buf, cap);
        if (out.empty()) return -14;
        std::size_t used = 0;
        for (;;) {
            if (!ds.pending) {
                errno = 0;
                struct ::dirent* e = ::readdir(ds.dir);
                if (!e) { if (errno) return used ? std::int64_t(used) : darwin::fail(); break; }
                ds.pending = Entry{e->d_ino, e->d_type, e->d_name};
            }
            const Entry& e = *ds.pending;
            const std::size_t rec = darwin::dirent_reclen(e.name.size());
            if (used + rec > out.size()) {
                if (used == 0) return -22;           // EINVAL: buffer too small
                break;
            }
            std::byte* p = out.data() + used;
            std::memset(p, 0, rec);
            const std::uint64_t ino = e.ino;
            const std::int64_t off = static_cast<std::int64_t>(++ds.index);
            const auto reclen = static_cast<std::uint16_t>(rec);
            std::memcpy(p, &ino, 8);
            std::memcpy(p + 8, &off, 8);
            std::memcpy(p + 16, &reclen, 2);
            p[18] = static_cast<std::byte>(e.type);   // DT_* values agree
            std::memcpy(p + 19, e.name.data(), e.name.size());
            used += rec;
            ds.pending.reset();
        }
        return static_cast<std::int64_t>(used);
    }

    // fcntl: the descriptor-flag and dup commands live in OUR table (they're
    // properties of the guest fd, not the host file); status flags pass
    // through to the host file description.
    [[nodiscard]] std::int64_t do_fcntl(int gfd, std::uint64_t cmd, std::uint64_t arg) {
        constexpr std::uint64_t kDupfd = 0, kGetfd = 1, kSetfd = 2, kGetfl = 3,
                                kSetfl = 4, kDupfdCloexec = 1030;
        constexpr std::uint64_t kFdCloexec = 1;

        // The descriptor-flag and dup commands are properties of the GUEST
        // fd, so they are decided entirely inside the table -- one locked
        // section, no nested locking.
        switch (cmd) {
            case kDupfd:
            case kDupfdCloexec:
                return proc_.with_fds([&](FdTable& t) -> std::int64_t {
                    if (!t.host(gfd)) return -9;                     // EBADF
                    // Lowest free guest fd at or above `arg`.
                    for (int to = static_cast<int>(arg); to < FdTable::kMaxFds; ++to)
                        if (!t.host(to)) return t.dup(gfd, to, cmd == kDupfdCloexec);
                    return -24;                                      // EMFILE
                });
            case kGetfd:
                return proc_.with_fds([&](FdTable& t) -> std::int64_t {
                    if (!t.host(gfd)) return -9;
                    return t.cloexec(gfd) ? static_cast<std::int64_t>(kFdCloexec) : 0;
                });
            case kSetfd:
                return proc_.with_fds([&](FdTable& t) -> std::int64_t {
                    if (!t.host(gfd)) return -9;
                    t.set_cloexec(gfd, (arg & kFdCloexec) != 0);
                    return 0;
                });
            default:
                break;
        }

        // The rest act on the host file description. Resolve the fd, release
        // the lock, then do the blocking-capable host call outside it.
        const int h = proc_.with_fds([&](FdTable& t) { return t.host(gfd).value_or(-1); });
        if (h < 0) return -9;
        switch (cmd) {
            case kGetfl: {
                const int fl = ::fcntl(h, F_GETFL);
                return fl < 0 ? darwin::fail() : darwin::open_flags_to_linux(fl);
            }
            case kSetfl: {
                int cur = ::fcntl(h, F_GETFL);
                if (cur < 0) return darwin::fail();
                cur &= ~(O_APPEND | O_NONBLOCK);
                cur |= darwin::open_flags(arg) & (O_APPEND | O_NONBLOCK);
                return ::fcntl(h, F_SETFL, cur) < 0 ? darwin::fail() : 0;
            }
            default:
                return -22;                                          // EINVAL
        }
    }

    // ioctl(fd, req, arg). Terminals are the whole story for an interactive
    // shell; see hvf_tty.hpp for why every field is translated by name.
    [[nodiscard]] std::int64_t do_ioctl(int hfd, std::uint64_t req, std::uint64_t arg) {
        const GuestRam ram = machine_.ram();
        using namespace tty;
        switch (req) {
            case L_TCGETS: case L_TCGETS2: {
                struct ::termios t{};
                if (::tcgetattr(hfd, &t) < 0) return darwin::fail();   // ENOTTY: not a tty
                if (req == L_TCGETS) return ram.put(arg, from_darwin(t)) ? 0 : -14;
                LinuxTermios2 t2{from_darwin(t), static_cast<std::uint32_t>(::cfgetispeed(&t)),
                                 static_cast<std::uint32_t>(::cfgetospeed(&t))};
                return ram.put(arg, t2) ? 0 : -14;
            }
            case L_TCSETS: case L_TCSETSW: case L_TCSETSF:
            case L_TCSETS2: case L_TCSETSW2: case L_TCSETSF2: {
                // termios2 starts with a plain termios, so reading the base
                // struct serves both; the explicit speeds are ignored (a
                // pty has no line speed).
                LinuxTermios l{};
                if (!ram.get(arg, l)) return -14;
                struct ::termios t{};
                if (::tcgetattr(hfd, &t) < 0) return darwin::fail();
                to_darwin(l, t);
                const int when = (req == L_TCSETS || req == L_TCSETS2)   ? TCSANOW
                               : (req == L_TCSETSW || req == L_TCSETSW2) ? TCSADRAIN
                                                                         : TCSAFLUSH;
                return ::tcsetattr(hfd, when, &t) < 0 ? darwin::fail() : 0;
            }
            case L_TIOCGWINSZ: {
                struct ::winsize w{};
                if (::ioctl(hfd, TIOCGWINSZ, &w) < 0) return darwin::fail();
                LinuxWinsize l{w.ws_row, w.ws_col, w.ws_xpixel, w.ws_ypixel};
                return ram.put(arg, l) ? 0 : -14;
            }
            case L_TIOCSWINSZ: {
                LinuxWinsize l{};
                if (!ram.get(arg, l)) return -14;
                struct ::winsize w{l.row, l.col, l.xpixel, l.ypixel};
                return ::ioctl(hfd, TIOCSWINSZ, &w) < 0 ? darwin::fail() : 0;
            }
            case L_FIONREAD: {
                int n = 0;
                if (::ioctl(hfd, FIONREAD, &n) < 0) return darwin::fail();
                return ram.put(arg, std::int32_t{n}) ? 0 : -14;
            }
            case L_FIONBIO: {
                std::int32_t on = 0;
                if (!ram.get(arg, on)) return -14;
                int fl = ::fcntl(hfd, F_GETFL);
                return ::fcntl(hfd, F_SETFL, on ? fl | O_NONBLOCK : fl & ~O_NONBLOCK) < 0
                           ? darwin::fail() : 0;
            }
            case L_TCFLSH:
                return ::tcflush(hfd, arg == 0 ? TCIFLUSH : arg == 1 ? TCOFLUSH : TCIOFLUSH) < 0
                           ? darwin::fail() : 0;
            case L_TCXONC: case L_TIOCSCTTY: case L_TIOCNOTTY:
                return 0;
            default:
                return -25;                                          // ENOTTY
        }
    }

    // ppoll(fds, nfds, timeout*, sigmask*) / pselect6: block on real Darwin
    // fds. struct pollfd and the POLL* bits agree between the two kernels for
    // everything but POLLRDHUP, which Darwin lacks and we drop. Guest fds are
    // translated in place and translated BACK, so revents land on the guest
    // numbers the program asked about.
    [[nodiscard]] std::int64_t do_ppoll(std::uint64_t fds_at, std::uint64_t n,
                                        std::uint64_t ts_at) {
        struct LinuxPollfd { std::int32_t fd; std::int16_t events, revents; };
        constexpr std::uint64_t kMax = FdTable::kMaxFds;
        if (n > kMax) return -22;
        const GuestRam ram = machine_.ram();
        std::vector<LinuxPollfd> g(n);
        std::vector<struct ::pollfd> h(n);
        for (std::uint64_t i = 0; i < n; ++i) {
            if (!ram.get(fds_at + i * sizeof(LinuxPollfd), g[i])) return -14;
            auto hfd = g[i].fd < 0 ? std::nullopt : proc_.with_fds([&](FdTable& t) { return t.host(g[i].fd); });
            h[i].fd = hfd ? *hfd : -1;
            h[i].events = static_cast<short>(g[i].events & 0x3f);   // drop POLLRDHUP
            h[i].revents = 0;
        }
        int timeout = -1;
        if (ts_at) {
            struct { std::int64_t sec, nsec; } ts{};
            if (!ram.get(ts_at, ts)) return -14;
            timeout = static_cast<int>(ts.sec * 1000 + ts.nsec / 1'000'000);
        }
        const int rc = ::poll(h.data(), static_cast<nfds_t>(n), timeout);
        if (rc < 0) return darwin::fail();
        for (std::uint64_t i = 0; i < n; ++i) {
            // An fd the guest named that we don't know is POLLNVAL, per POSIX.
            g[i].revents = h[i].fd < 0 && g[i].fd >= 0 ? 0x20 : h[i].revents;
            if (!ram.put(fds_at + i * sizeof(LinuxPollfd), g[i])) return -14;
        }
        return rc;
    }

    // pselect6(nfds, rd*, wr*, ex*, timeout*, sigmask*): rebuild as poll so
    // there's one blocking implementation. fd_set is a bitmap of guest fds.
    [[nodiscard]] std::int64_t do_pselect(std::uint64_t nfds, std::uint64_t rd,
                                          std::uint64_t wr, std::uint64_t ex,
                                          std::uint64_t ts_at) {
        if (nfds > FdTable::kMaxFds) return -22;
        const GuestRam ram = machine_.ram();
        const std::size_t bytes = (nfds + 7) / 8;
        std::vector<std::uint8_t> sets[3];
        const std::uint64_t at[3] = {rd, wr, ex};
        for (int s = 0; s < 3; ++s) {
            sets[s].assign(bytes, 0);
            if (at[s]) {
                auto win = ram.at(at[s], bytes);
                if (win.empty() && bytes) return -14;
                std::memcpy(sets[s].data(), win.data(), bytes);
            }
        }
        std::vector<struct ::pollfd> p;
        std::vector<int> guest;
        for (std::uint64_t fd = 0; fd < nfds; ++fd) {
            short ev = 0;
            if (sets[0][fd / 8] & (1u << (fd % 8))) ev |= POLLIN;
            if (sets[1][fd / 8] & (1u << (fd % 8))) ev |= POLLOUT;
            if (sets[2][fd / 8] & (1u << (fd % 8))) ev |= POLLPRI;
            if (!ev) continue;
            auto h = proc_.with_fds([&](FdTable& t) { return t.host(static_cast<int>(fd)); });
            if (!h) return -9;                                        // EBADF
            p.push_back({*h, ev, 0});
            guest.push_back(static_cast<int>(fd));
        }
        int timeout = -1;
        if (ts_at) {
            struct { std::int64_t sec, nsec; } ts{};
            if (!ram.get(ts_at, ts)) return -14;
            timeout = static_cast<int>(ts.sec * 1000 + ts.nsec / 1'000'000);
        }
        const int rc = ::poll(p.data(), static_cast<nfds_t>(p.size()), timeout);
        if (rc < 0) return darwin::fail();
        for (auto& s : sets) std::fill(s.begin(), s.end(), 0);
        int ready = 0;
        for (std::size_t i = 0; i < p.size(); ++i) {
            const int fd = guest[i];
            const auto bit = static_cast<std::uint8_t>(1u << (fd % 8));
            if (p[i].revents & (POLLIN | POLLHUP | POLLERR)) { sets[0][fd / 8] |= bit; ++ready; }
            if (p[i].revents & POLLOUT) { sets[1][fd / 8] |= bit; ++ready; }
            if (p[i].revents & POLLPRI) { sets[2][fd / 8] |= bit; ++ready; }
        }
        for (int s = 0; s < 3; ++s)
            if (at[s] && bytes) std::memcpy(ram.at(at[s], bytes).data(), sets[s].data(), bytes);
        return ready;
    }

    // readv/writev: one Darwin call per entry. Building a host iovec array
    // would need every guest base translated and bounds-checked anyway, and
    // real vectors are short (musl's stdio uses two).
    [[nodiscard]] std::int64_t do_vector(bool writing, int fd,
                                         std::uint64_t vec, std::uint64_t cnt) {
        const GuestRam ram = machine_.ram();
        std::int64_t total = 0;
        constexpr std::uint64_t kIovMax = 1024;
        for (std::uint64_t i = 0; i < std::min(cnt, kIovMax); ++i) {
            GuestIovec iov{};
            if (!ram.get(vec + i * sizeof(GuestIovec), iov)) return total ? total : -14;
            if (iov.len == 0) continue;
            auto win = ram.clamp(iov.base, iov.len);
            if (win.empty()) return total ? total : -14;
            auto n = writing ? ::write(fd, win.data(), win.size())
                             : ::read(fd, win.data(), win.size());
            if (n < 0) return total ? total : darwin::fail();
            total += n;
            if (static_cast<std::uint64_t>(n) < win.size()) break;  // short
        }
        return total;
    }

    // "/proc/self/fd/7" (or thread-self) -> 7.
    [[nodiscard]] static std::optional<int> proc_fd_number(std::string_view p) {
        for (std::string_view pre : {"/proc/self/fd/", "/proc/thread-self/fd/"}) {
            if (!p.starts_with(pre)) continue;
            p.remove_prefix(pre.size());
            int n = 0;
            auto [end, ec] = std::from_chars(p.data(), p.data() + p.size(), n);
            if (ec == std::errc{} && end == p.data() + p.size()) return n;
        }
        return std::nullopt;
    }

    // What readlink("/proc/self/fd/N") shows, in the GUEST's namespace:
    //   a terminal  -> its device path, which main() binds into the guest at
    //                  the same name, so glibc's ttyname() check -- stat(path)
    //                  must match fstat(fd) -- passes;
    //   a pipe      -> "pipe:[inode]", the Linux spelling programs parse;
    //   a file      -> the host path, reverse-mapped into the guest tree.
    [[nodiscard]] std::string describe_fd(int hfd) const {
        if (::isatty(hfd)) {
            if (const char* n = ::ttyname(hfd)) return n;
        }
        struct ::stat st{};
        if (::fstat(hfd, &st) == 0) {
            if (S_ISFIFO(st.st_mode)) return "pipe:[" + std::to_string(st.st_ino) + "]";
            if (S_ISSOCK(st.st_mode)) return "socket:[" + std::to_string(st.st_ino) + "]";
        }
        char buf[PATH_MAX];
        if (::fcntl(hfd, F_GETPATH, buf) == 0)
            return unresolve_ ? unresolve_(buf) : std::string{buf};
        return "anon_inode:[unknown]";
    }

    [[nodiscard]] Maybe do_path(abi::Sysno sc, const std::string* path,
                                const std::string* path2) {
        using S = abi::Sysno;
        // /proc/self/fd/N: the portable procfs forwards these to the HOST's
        // /proc (on Linux the guest is a real process, so that is exact).
        // macOS has no /proc, so answer from the guest fd table here.
        if (path) {
            if (auto g = proc_fd_number(*path)) {
                auto h = proc_.with_fds([&](FdTable& t) { return t.host(*g); });
                if (!h) return -2;                                   // ENOENT
                if (sc == S::readlinkat) {
                    const std::string target = describe_fd(*h);
                    auto win = machine_.ram().clamp(regs_.arg(2), regs_.arg(3));
                    if (win.empty()) return -14;
                    const std::size_t n = std::min(win.size(), target.size());
                    std::memcpy(win.data(), target.data(), n);
                    return static_cast<std::int64_t>(n);             // no NUL, like Linux
                }
                // open/stat of /proc/self/fd/N reopen the SAME file: Darwin's
                // /dev/fd/K does exactly that for host fd K.
                fd_path_storage_ = "/dev/fd/" + std::to_string(*h);
                path = &fd_path_storage_;
            }
        }
        const GuestRam ram = machine_.ram();
        const std::uint64_t a2 = regs_.arg(2), a3 = regs_.arg(3);
        switch (sc) {
            case S::open: case S::openat: {
                if (!path) return -2;                               // ENOENT
                const bool at = sc == S::openat;
                const std::uint64_t lflags = at ? a2 : regs_.arg(1);
                const std::uint64_t lmode  = at ? a3 : a2;
                // Open CLOEXEC on the host side unconditionally: the host fd
                // belongs to linuxity, and must never leak into a process we
                // spawn. The GUEST's O_CLOEXEC is tracked in the fd table.
                int fd = ::open(path->c_str(),
                                darwin::open_flags(lflags) | O_CLOEXEC,
                                static_cast<mode_t>(lmode));
                if (fd < 0) return darwin::fail();
                constexpr std::uint64_t kCloexec = 02000000;
                return proc_.with_fds([&](FdTable& t) { return t.install(fd, (lflags & kCloexec) != 0); });
            }
            case S::newfstatat: {
                if (!path) return -2;
                constexpr std::uint64_t kNoFollow = 0x100;   // AT_SYMLINK_NOFOLLOW
                struct ::stat st{};
                int rc = (a3 & kNoFollow) ? ::lstat(path->c_str(), &st)
                                          : ::stat(path->c_str(), &st);
                if (rc < 0) return darwin::fail();
                return ram.put(a2, darwin::to_linux(st)) ? 0 : -14;
            }
            case S::faccessat: case S::faccessat2:
                if (!path) return -2;
                return ::access(path->c_str(), static_cast<int>(a2)) < 0
                           ? darwin::fail() : 0;
            case S::readlinkat: {
                if (!path) return -2;
                auto win = ram.clamp(a2, a3);
                if (win.empty()) return -14;
                auto n = ::readlink(path->c_str(),
                                    reinterpret_cast<char*>(win.data()), win.size());
                return n < 0 ? darwin::fail() : n;
            }
            case S::mkdirat:
                if (!path) return -2;
                return ::mkdir(path->c_str(), static_cast<mode_t>(a2)) < 0
                           ? darwin::fail() : 0;
            case S::unlinkat: {
                if (!path) return -2;
                constexpr std::uint64_t kRemoveDir = 0x200;        // AT_REMOVEDIR
                int rc = (a2 & kRemoveDir) ? ::rmdir(path->c_str())
                                           : ::unlink(path->c_str());
                return rc < 0 ? darwin::fail() : 0;
            }
            case S::renameat: case S::renameat2:
                if (!path || !path2) return -2;
                return ::rename(path->c_str(), path2->c_str()) < 0
                           ? darwin::fail() : 0;
            case S::linkat:
                if (!path || !path2) return -2;
                return ::link(path->c_str(), path2->c_str()) < 0
                           ? darwin::fail() : 0;
            case S::symlinkat:
                // symlinkat(target, newdirfd, linkpath): only the LINK PATH
                // is translated (it's the dispatcher's path_arg); the target
                // is stored verbatim -- it's resolved later in the guest's
                // namespace, exactly as Linux stores it.
                if (!path) return -2;
                return ::symlink(ram.cstr(regs_.arg(0)).c_str(),
                                 (path2 ? *path2 : *path).c_str()) < 0
                           ? darwin::fail() : 0;
            case S::utimensat: {
                // utimensat(dirfd, path, times[2], flags). A NULL path with
                // a real fd is futimens(); times may be NULL (= now) and each
                // entry may be UTIME_NOW/UTIME_OMIT -- the same encoding on
                // both kernels except the magic values.
                struct LinuxTs { std::int64_t sec, nsec; };
                constexpr std::int64_t kNowL = (1l << 30) - 1, kOmitL = (1l << 30) - 2;
                struct ::timespec ts[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
                if (a2) {
                    LinuxTs l[2]{};
                    if (!ram.get(a2, l)) return -14;
                    for (int i = 0; i < 2; ++i) {
                        ts[i].tv_sec = l[i].sec;
                        ts[i].tv_nsec = l[i].nsec == kNowL ? UTIME_NOW
                                      : l[i].nsec == kOmitL ? UTIME_OMIT : l[i].nsec;
                    }
                }
                constexpr std::uint64_t kNoFollow = 0x100;
                if (!path) {
                    auto h = proc_.with_fds([&](FdTable& t) { return t.host(static_cast<int>(regs_.arg(0))); });
                    if (!h) return -9;
                    return ::futimens(*h, ts) < 0 ? darwin::fail() : 0;
                }
                return ::utimensat(AT_FDCWD, path->c_str(), ts,
                                   (a3 & kNoFollow) ? AT_SYMLINK_NOFOLLOW : 0) < 0
                           ? darwin::fail() : 0;
            }
            case S::statfs: {
                if (!path) return -2;
                struct ::statfs s{};
                if (::statfs(path->c_str(), &s) < 0) return darwin::fail();
                return ram.put(regs_.arg(1), darwin::statfs_to_linux(s)) ? 0 : -14;
            }
            case S::chdir:
                // The NAMESPACE already moved the guest's cwd (the core
                // tracks it per process); only validate the target exists.
                if (!path) return -2;
                {
                    struct ::stat st{};
                    if (::stat(path->c_str(), &st) < 0) return darwin::fail();
                    if (!S_ISDIR(st.st_mode)) return -20;          // ENOTDIR
                }
                return 0;
            case S::fchmodat:
                if (!path) return -2;
                return ::chmod(path->c_str(), static_cast<mode_t>(a2)) < 0
                           ? darwin::fail() : 0;
            case S::truncate:
                if (!path) return -2;
                return ::truncate(path->c_str(), static_cast<off_t>(regs_.arg(1))) < 0
                           ? darwin::fail() : 0;
            case S::bind: case S::connect: {
                // The CORE decides these: for AF_UNIX it translates the
                // sockaddr_un path into the rootfs (so a guest's
                // /run/foo.sock is a real file under the rootfs), which is
                // why they arrive here as a path syscall rather than in
                // do_socket. `path` is that translated path, or null for an
                // IP address the guest supplied directly.
                const int h = host_fd(static_cast<int>(regs_.arg(0)));
                if (h < 0) return -9;
                ::sockaddr_storage ss{};
                socklen_t slen = 0;
                if (path) {
                    auto* sun = reinterpret_cast<::sockaddr_un*>(&ss);
                    if (path->size() >= sizeof sun->sun_path) return -36;  // ENAMETOOLONG
                    sun->sun_family = AF_UNIX;
                    std::memcpy(sun->sun_path, path->c_str(), path->size() + 1);
                    sun->sun_len = static_cast<std::uint8_t>(
                        offsetof(::sockaddr_un, sun_path) + path->size() + 1);
                    slen = sun->sun_len;
                } else {
                    auto addr = ram.at(regs_.arg(1), regs_.arg(2));
                    if (addr.empty()) return -14;
                    auto n = net::to_darwin(addr, ss);
                    if (!n) return -97;
                    slen = *n;
                }
                const int rc = sc == S::bind
                    ? ::bind(h, reinterpret_cast<::sockaddr*>(&ss), slen)
                    : ::connect(h, reinterpret_cast<::sockaddr*>(&ss), slen);
                return rc < 0 ? darwin::fail() : 0;
            }
            default:
                return std::nullopt;
        }
    }

    HvfMachine& machine_;
    HvfCpu& cpu_;
    ProcessState& proc_;
    TaskState& task_;
    PidSpace& pids_;
    std::int32_t parent_{0};
    struct Child { std::int32_t guest; pid_t host; };
    std::vector<Child> children_;
    Resolver resolve_;
    Resolver unresolve_;
    std::string fd_path_storage_;
    SpawnFork spawn_;
    SpawnThread spawn_thread_;
    std::vector<std::string> env_;
    bool execed_{false};
    bool thread_exited_{false};
    TimerSet timers_;
    // Open directory streams for getdents64, keyed by guest fd.
    struct Entry {
        std::uint64_t ino{};
        std::uint8_t type{};
        std::string name;
    };
    struct DirStream {
        DIR* dir{nullptr};
        std::optional<Entry> pending;   // read but not yet delivered
        std::uint64_t index{0};         // d_off: a monotonically rising cookie
        DirStream() = default;
        DirStream(const DirStream&) = delete;
        DirStream& operator=(const DirStream&) = delete;
        ~DirStream() { if (dir) ::closedir(dir); }
    };
    std::map<int, DirStream> dirs_;
    GuestRegs regs_{};
    bool exited_{false};
    int code_{0};
};

// -- Guest memory accessor (abi::GuestMem) --------------------------------
// The payoff of hv_vm_map sharing pages: copy_in/copy_out are a bounds-checked
// memcpy against live guest RAM. The ptrace backend needs process_vm_readv
// into another process, with a PTRACE_PEEKDATA word-at-a-time fallback when a
// buffer straddles an unmapped page -- and a TOCTOU window besides.
class HvfMem {
public:
    explicit HvfMem(const HvfMachine& machine, const HvfTrap* trap = nullptr) noexcept
        : machine_{machine}, trap_{trap} {}

    // The identity bridge abi::Syscalls probes for (`requires { mem_.current_ids(); }`),
    // so the portable core's getpid/getppid and /proc/self see this
    // process's GUEST pid. Without a trap attached, the core falls back to
    // init's identity, which is right for single-process tests.
    struct TaskIds { std::int32_t pid, tid, ppid; };
    [[nodiscard]] TaskIds current_ids() const noexcept {
        if (!trap_) return {1, 1, 0};
        auto t = trap_->current_ids();
        return {t.pid, t.tid, t.ppid};
    }

    [[nodiscard]] Status copy_in(UAddr src, std::span<std::byte> dst) const {
        auto win = machine_.ram().at(value(src), dst.size());
        if (win.empty() && !dst.empty()) return err(Errno::efault);
        std::memcpy(dst.data(), win.data(), dst.size());
        return ok();
    }

    [[nodiscard]] Status copy_out(UAddr dst, std::span<const std::byte> src) const {
        auto win = machine_.ram().at(value(dst), src.size());
        if (win.empty() && !src.empty()) return err(Errno::efault);
        std::memcpy(win.data(), src.data(), src.size());
        return ok();
    }

private:
    const HvfMachine& machine_;
    const HvfTrap* trap_;
};

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
