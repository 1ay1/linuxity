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
#include "linuxity/runtime/hvf_proc.hpp"
#include "linuxity/runtime/hvf_signal.hpp"
#include "linuxity/runtime/hvf_tty.hpp"
#include "linuxity/runtime/hvf_mem.hpp"
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
    HvfTrap(HvfVm& vm, PidSpace& pids) noexcept : vm_{vm}, pids_{pids} {}

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
        return {self_, self_, parent_};
    }

    // The loader has already written the image and stack into guest RAM, so
    // starting is just placing the entry state. `image_end` seeds the heap.
    [[nodiscard]] Status start(UAddr entry, UAddr sp) {
        if (value(entry)) vm_.set_entry(value(entry), value(sp));
        return ok();
    }

    void set_arena(std::uint64_t image_end, std::uint64_t stack_floor) {
        as_.reset(image_end, stack_floor);
    }

    // Record a region the LOADER mapped directly into guest RAM (ELF
    // segments, the stack). Without this the VMA map doesn't know they
    // exist, and the guest's own mprotect on them -- which glibc's ld.so
    // does to apply RELRO right before transferring control -- fails ENOMEM
    // and the program dies with "cannot apply additional memory protection
    // after relocation".
    void adopt(std::uint64_t begin, std::uint64_t end, GuestProt prot) {
        as_.adopt({AddressSpace::page_down(begin), AddressSpace::page_up(end),
                   prot, /*anonymous=*/false});
    }

    // The startup stack: from the initial sp's page up to the top of RAM.
    void adopt_stack(std::uint64_t sp, std::uint64_t mem_top) {
        as_.adopt({AddressSpace::page_down(sp) - kStackReserve,
                   AddressSpace::page_down(mem_top),
                   GuestProt::read | GuestProt::write, /*anonymous=*/true});
    }
    // Room below the initial sp for the stack to grow (Linux's default
    // RLIMIT_STACK, which is what prlimit64 reports).
    static constexpr std::uint64_t kStackReserve = ExecArena::stack_reserve;

    [[nodiscard]] Result<bool> next(TrapFrame& f) {
        constexpr std::uint64_t kEcSvc64 = 0x15;
        g_pending.vcpu.store(vm_.vcpu(), std::memory_order_relaxed);
        g_pending.vcpu_valid.store(true, std::memory_order_relaxed);
        for (;;) {
            if (exited_) return ok(false);
            // Signals are delivered here -- after resume() has written the
            // previous syscall's result into the vCPU, so the frame captures
            // the COMPLETED call (x0 = its return value, PC past the svc).
            // Delivering before the result is written makes the handler
            // return into a context whose x0 is the syscall's first ARGUMENT,
            // and the interrupted code then dereferences garbage.
            (void)deliver_pending();
            if (exited_) return ok(false);
            auto regs = vm_.run();
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
        if (std::exchange(sigreturned_, false)) return ok();
        // A successful execve has REPLACED the image: the vCPU already points
        // at the new entry with a clean register file. Writing a return value
        // into x0 would hand the new program's _start a garbage argument.
        if (std::exchange(execed_, false)) {
            vm_.set_entry(regs_.elr, vm_.sp());
            return ok();
        }
        vm_.set_result(regs_, ret);
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
        const int hs = signal_from_linux(sig);
        if (sig < 0 || sig > kLinuxNsig) return -22;
        pid_t target;
        if (gpid > 0) {
            auto h = gpid == self_ ? std::optional<pid_t>{::getpid()} : pids_.host_of(gpid);
            if (!h) return -3;                                       // ESRCH
            target = *h;
        } else if (gpid == 0) {
            target = 0;
        } else if (gpid == -1) {
            target = -1;
        } else {
            auto h = pids_.host_of(-gpid);
            if (!h) return -3;
            target = -*h;
        }
        if (sig == 0) return ::kill(target, 0) < 0 ? darwin::fail() : 0;
        // A self-signal must not race past the syscall return: Linux delivers
        // it before kill() returns to user space. Mark it pending directly so
        // the very next trap boundary delivers it, independent of when the
        // host handler runs.
        if (target == ::getpid() && sig != 9 && sig != 19) {
            g_pending.bits.fetch_or(sigbit(sig), std::memory_order_relaxed);
            return 0;
        }
        return ::kill(target, hs) < 0 ? darwin::fail() : 0;
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

    [[nodiscard]] const AddressSpace& address_space() const noexcept { return as_; }

private:
    [[nodiscard]] Result<std::int64_t> complete(std::int64_t rc) {
        // strace-style line with the REAL result. The core's LINUXITY_TRACE
        // shows the dispatcher's decision; only the backend knows what the
        // emulated call actually returned, which is what debugging needs.
        static const bool strace = std::getenv("LINUXITY_STRACE") != nullptr;
        if (strace)
            std::fprintf(stderr, "[%d] %3llu(%#llx, %#llx, %#llx, %#llx) = %lld\n",
                         self_, static_cast<unsigned long long>(regs_.nr()),
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
        const Vma* v = as_.find(regs_.far);
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
        if (auto r = do_path(sc, path, path2)) return *r;
        return -38;                                     // ENOSYS, honestly
    }

    using Maybe = std::optional<std::int64_t>;

    // -- Signals ------------------------------------------------------------
    [[nodiscard]] Maybe do_signal(abi::Sysno sc) {
        using S = abi::Sysno;
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1),
                            a2 = regs_.arg(2), a3 = regs_.arg(3);
        const GuestRam ram = vm_.ram();
        switch (sc) {
            case S::rt_sigaction: {
                // rt_sigaction(sig, act*, oact*, sigsetsize)
                const int s = static_cast<int>(a0);
                if (s < 1 || s > kLinuxNsig || a3 != 8) return -22;
                if (a2 && !ram.put(a2, actions_[s - 1])) return -14;
                if (!a1) return 0;
                if (s == 9 || s == 19) return -22;              // KILL/STOP fixed
                LinuxSigaction act{};
                if (!ram.get(a1, act)) return -14;
                actions_[s - 1] = act;
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
                if (a2 && !ram.put(a2, mask_)) return -14;
                if (!a1) return 0;
                std::uint64_t set = 0;
                if (!ram.get(a1, set)) return -14;
                set &= ~(sigbit(9) | sigbit(19));               // never blockable
                switch (a0) {
                    case 0: mask_ |= set;  break;               // SIG_BLOCK
                    case 1: mask_ &= ~set; break;               // SIG_UNBLOCK
                    case 2: mask_ = set;   break;               // SIG_SETMASK
                    default: return -22;
                }
                return 0;
            }
            case S::rt_sigpending:
                return ram.put(a0, std::uint64_t{
                    g_pending.bits.load(std::memory_order_relaxed) & mask_}) ? 0 : -14;
            case S::rt_sigreturn:
                return do_sigreturn();
            case S::sigaltstack: {
                // sigaltstack(ss*, oss*): record it; delivery honours SA_ONSTACK.
                if (a1 && !ram.put(a1, altstack_)) return -14;
                if (a0) {
                    LinuxStack ss{};
                    if (!ram.get(a0, ss)) return -14;
                    altstack_ = ss;
                }
                return 0;
            }
            case S::rt_sigsuspend: {
                // Wait with a temporary mask until a signal we deliver arrives.
                std::uint64_t tmp = 0;
                if (!ram.get(a0, tmp)) return -14;
                const std::uint64_t saved = mask_;
                mask_ = tmp;
                while (!(g_pending.bits.load() & ~mask_)) ::usleep(1000);
                suspend_restore_ = saved;
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
        if (suspend_restore_) { mask_ = *suspend_restore_; suspend_restore_.reset(); }
        const std::uint64_t ready =
            g_pending.bits.load(std::memory_order_relaxed) & ~mask_;
        if (!ready) return false;
        const int s = std::countr_zero(ready) + 1;
        g_pending.bits.fetch_and(~sigbit(s), std::memory_order_relaxed);
        LinuxSigaction& act = actions_[s - 1];

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
        const HvfVm::CpuState cpu = vm_.save();
        std::uint64_t sp = cpu.sp_el0;
        if ((act.flags & sigflag::kOnstack) && altstack_.ss_size &&
            !(sp > altstack_.ss_sp && sp <= altstack_.ss_sp + altstack_.ss_size))
            sp = altstack_.ss_sp + altstack_.ss_size;
        // Stack layout, top to bottom:  [trampoline (16)] [rt_sigframe] <- sp
        // rt_sigreturn finds the frame at the SP the handler returns with,
        // which is exactly where we entered it -- so the frame must be the
        // LOWEST thing pushed. (Pushing the trampoline after the frame put
        // it at sp, and sigreturn read the trampoline as a ucontext: PC 0.)
        std::uint64_t ret = act.restorer;
        const bool need_tramp = !(act.flags & sigflag::kRestorer) || !ret;
        if (need_tramp) {
            sp -= 16;
            if (!vm_.ram().put(sp, kSigreturnTrampoline)) { kill_with(11); return true; }
            vm_.publish_code(sp, 8);
            ret = sp;
        }
        sp = (sp - sizeof(RtSigframe)) & ~std::uint64_t{15};
        const std::uint64_t frame_at = sp;

        RtSigframe frame{};
        frame.info.si_signo = s;
        frame.info.si_code = 0;                                  // SI_USER
        frame.uc.uc_stack = altstack_;
        frame.uc.uc_sigmask = mask_;
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

        if (!vm_.ram().put(frame_at, frame)) { kill_with(11); return true; }

        // Enter the handler: x0 = signo, x1 = &info, x2 = &uc, lr = restorer.
        HvfVm::CpuState h = cpu;
        h.x[0] = static_cast<std::uint64_t>(s);
        h.x[1] = frame_at + offsetof(RtSigframe, info);
        h.x[2] = frame_at + offsetof(RtSigframe, uc);
        h.x[30] = ret;
        h.sp_el0 = sp;
        h.pc = act.handler;
        h.cpsr = 0;
        vm_.load(h);

        mask_ |= act.mask;
        if (!(act.flags & sigflag::kNodefer)) mask_ |= sigbit(s);
        if (act.flags & sigflag::kResethand) { act = {}; route_host_signal(s, false); }
        return true;
    }

    // rt_sigreturn: restore the frame the handler was entered with. The
    // handler may have MODIFIED it (that's how siglongjmp-free coroutine
    // libraries and some JITs work), so read it back from guest memory.
    [[nodiscard]] std::int64_t do_sigreturn() {
        RtSigframe frame{};
        if (!vm_.ram().get(vm_.save().sp_el0, frame)) { kill_with(11); return 0; }
        HvfVm::CpuState c = vm_.save();
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
        vm_.load(c);
        mask_ = frame.uc.uc_sigmask & ~(sigbit(9) | sigbit(19));
        sigreturned_ = true;           // resume() must not clobber x0/PC
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
                constexpr std::uint64_t kCloneVm = 0x100, kCloneVfork = 0x4000,
                                        kSetTls = 0x80000, kChildCleartid = 0x200000,
                                        kChildSettid = 0x1000000, kParentSettid = 0x100000;
                const bool vfork = (a0 & kCloneVfork) != 0;
                // CLONE_VM|CLONE_VFORK (glibc's posix_spawn, behind xargs,
                // make, find -exec, every spawn helper) is "share memory
                // and suspend the parent until the child execs or exits".
                // A full fork is a valid implementation of that contract:
                // the child can only exec or _exit, so the memory it would
                // have shared is never observably written. The one subtle
                // part is the child's stack: posix_spawn hands it a
                // private one in arg1, which do_fork installs.
                if ((a0 & kCloneVm) && !vfork) return -11;            // EAGAIN
                const std::int64_t child = do_fork(a0, a1, a2, a3, regs_.arg(4),
                               (a0 & kSetTls) != 0, (a0 & kChildSettid) != 0,
                               (a0 & kParentSettid) != 0, (a0 & kChildCleartid) != 0);
                // vfork: the parent must not run until the child has exec'd
                // or exited (posix_spawn reads an error the child writes into
                // shared memory, which with a real fork is never shared --
                // waiting for exec keeps the observable ordering identical).
                if (vfork && child > 0) wait_for_exec(static_cast<std::int32_t>(child));
                return child;
            }
            case S::clone3: return -38;     // glibc falls back to clone

            case S::wait4:  return do_wait4(static_cast<std::int32_t>(a0), a1,
                                            static_cast<int>(a2), a3);

            case S::kill: case S::tkill: case S::tgkill: {
                const bool tg = sc == S::tgkill;
                const auto gpid = static_cast<std::int32_t>(tg ? a1 : a0);
                const int sig = signal_from_linux(static_cast<int>(tg ? a2 : a1));
                pid_t target;
                if (gpid == 0)      target = 0;                    // own group
                else if (gpid == -1) target = -1;                  // everyone
                else if (gpid < -1) {
                    auto h = pids_.host_of(-gpid);
                    if (!h) return -3;                             // ESRCH
                    target = -*h;
                } else {
                    auto h = pids_.host_of(gpid);
                    if (!h) return -3;
                    target = *h;
                }
                return ::kill(target, sig) < 0 ? darwin::fail() : 0;
            }

            case S::getpid: case S::gettid: return self_;
            case S::getppid:                 return parent_;
            default:                         return std::nullopt;
        }
    }

    // Guest fork, the macOS way (see runtime/hvf_fork.hpp for why fork(2) of
    // linuxity itself is not an option). The parent:
    //   1. pre-allocates the child's GUEST pid (so the return value is known
    //      before the child exists -- no race, no spinning),
    //   2. serializes everything that isn't RAM into a ForkImage,
    //   3. hands RAM (COW snapshot) + image to the embedder's spawn hook,
    //      which starts a fresh linuxity that resumes the guest with x0 = 0.
    [[nodiscard]] std::int64_t do_fork(std::uint64_t, std::uint64_t stack,
                                       std::uint64_t ptid, std::uint64_t tls,
                                       std::uint64_t ctid, bool set_tls,
                                       bool child_settid, bool parent_settid,
                                       bool child_cleartid) {
        if (!pids_.valid() || !spawn_) return -38;
        const std::int32_t child = pids_.allocate(0);   // placeholder host pid
        if (child < 0) return -11;                       // EAGAIN

        ForkImage img;
        img.cpu = vm_.save();
        img.cpu.x[0] = 0;                                // fork() returns 0 in the child
        img.cpu.pc = regs_.elr;                          // resume after the svc
        img.cpu.cpsr = regs_.spsr;
        if (stack) img.cpu.sp_el0 = stack;
        if (set_tls) img.cpu.tpidr_el0 = tls;
        img.self = child;
        img.parent = self_;
        img.child_settid = child_settid ? ctid : 0;
        img.clear_child_tid = child_cleartid ? ctid : 0;
        img.umask = umask_;
        img.vmas = as_.vmas();
        img.brk = as_.brk();
        img.arena = as_.arena();
        img.fds = fds_.export_table();
        img.sig_actions = actions_;
        img.sig_mask = mask_;
        img.altstack = altstack_;

        std::fflush(nullptr);
        const pid_t host = spawn_(img);
        if (host < 0) { pids_.release(child); return -11; }
        pids_.bind(child, host);
        if (parent_settid) (void)vm_.ram().put(ptid, std::int32_t{child});
        children_.push_back({child, host});
        return child;
    }

public:
    // Everything a fork child needs that isn't guest RAM. Plain data: the
    // embedder serializes it into the handoff message.
    struct ForkImage {
        HvfVm::CpuState cpu{};
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

    // Child side: become the forked process described by `img`. The VM is
    // already up over the snapshot RAM; restore everything else.
    void resume_fork_child(const ForkImage& img, const std::vector<int>& host_fds) {
        vm_.load(img.cpu);
        self_ = img.self;
        parent_ = img.parent;
        umask_ = img.umask;
        as_.restore(img.vmas, img.brk, img.arena);
        fds_.import_table(img.fds, host_fds);
        // fork(2): the child inherits handlers, mask and alt stack verbatim.
        actions_ = img.sig_actions;
        mask_ = img.sig_mask;
        altstack_ = img.altstack;
        for (int s = 1; s <= kLinuxNsig; ++s) {
            const auto h = actions_[s - 1].handler;
            if (h == 1) { const int hs = signal_from_linux(s);
                          if (hs > 0 && hs != SIGKILL && hs != SIGSTOP) ::signal(hs, SIG_IGN); }
            else if (h) route_host_signal(s, true);
        }
        if (img.child_settid) (void)vm_.ram().put(img.child_settid, std::int32_t{self_});
        clear_child_tid_ = img.clear_child_tid;
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
        if (status) (void)vm_.ram().put(status, std::int32_t{wstatus_to_linux(st)});
        if (rusage) {
            std::byte zero[144]{};                                // struct rusage
            (void)vm_.ram().put(rusage, zero);
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
        const GuestRam ram = vm_.ram();
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
        for (const Vma& v : as_.vmas()) vm_.zero(v.begin, v.size());
        auto ex = hvf_exec(vm_, resolve, guest_path, argv, envp);
        if (!ex) {
            std::fprintf(stderr, "linuxity: execve %s failed (errno %d)\n",
                         guest_path.c_str(), static_cast<int>(ex.error()));
            exited_ = true;
            code_ = 127;
            return 0;
        }
        set_arena(ex->brk_base, ExecArena::mmap_top(vm_.mem_size()));
        for (const auto& sg : ex->segments)
            adopt(sg.begin, sg.end, prot_from_elf(sg.flags));
        adopt_stack(ex->sp, vm_.mem_size());
        fds_.on_exec();
        dirs_.clear();
        // execve(2): caught signals revert to SIG_DFL (the handler code is
        // gone); ignored stay ignored; the mask is preserved; the alt stack
        // is cleared.
        for (int s = 1; s <= kLinuxNsig; ++s) {
            auto& a = actions_[s - 1];
            if (a.handler > 1) { a = {}; route_host_signal(s, false); }
        }
        altstack_ = {};
        // The new image starts fresh: clear every GPR (no state may leak from
        // the old program into the new one), then enter.
        for (int i = 0; i < 31; ++i) vm_.set_x(i, 0);
        vm_.set_tls(0);
        regs_.elr = ex->entry;
        regs_.spsr = 0;
        vm_.set_sp(ex->sp);
        execed_ = true;
        pids_.mark_execed(self_);           // releases a vfork parent
        return 0;
    }

    [[nodiscard]] Maybe do_process(abi::Sysno sc) {
        using S = abi::Sysno;
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1), a2 = regs_.arg(2);
        const GuestRam ram = vm_.ram();
        switch (sc) {
            case S::exit:
            case S::exit_group:
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

            // -- futex(uaddr, op, val, ...). This backend runs ONE guest
            //    thread, which makes futex exact rather than approximate:
            //      WAIT: if *uaddr != val the caller must see EAGAIN (that is
            //            the whole race-free contract). If it still matches,
            //            no other thread exists to ever change it, so blocking
            //            would be a deadlock -- report EAGAIN as well, which
            //            every libc treats as "recheck and retry".
            //      WAKE: there is nobody to wake; 0 woken is the true answer.
            //    glibc's "futex facility returned an unexpected error code"
            //    abort is what ENOSYS here produced.
            case S::futex: {
                constexpr std::uint64_t kCmdMask = 0x7f;   // strip PRIVATE/CLOCK
                constexpr std::uint64_t kWait = 0, kWake = 1, kWaitBitset = 9,
                                        kWakeBitset = 10;
                switch (a1 & kCmdMask) {
                    case kWait: case kWaitBitset: {
                        std::uint32_t cur = 0;
                        if (!ram.get(a0, cur)) return -14;            // EFAULT
                        return -11;                                   // EAGAIN
                    }
                    case kWake: case kWakeBitset:
                        return 0;
                    default:
                        return -38;
                }
            }

            // Per-thread registrations glibc makes at startup. Accepting them
            // is correct for a single thread: robust-list cleanup only runs
            // when a thread dies holding a lock, and rseq is an optimization
            // glibc already disables when registration fails -- but it
            // probes with a specific errno, so answer the way an old kernel
            // would (ENOSYS) and let it take its fallback.
            case S::set_robust_list:
                return 0;
            case S::rseq:
                return -38;
            case S::membarrier:
                return 0;           // one thread: every barrier is trivially met
            case S::sched_yield:
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
                const auto old = umask_;
                umask_ = static_cast<std::uint32_t>(a0 & 0777);
                return old;
            }
            case S::getgroups:
                return 0;           // root, no supplementary groups

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
                return static_cast<std::int64_t>(as_.set_brk(a0));
            case S::mmap: {
                constexpr std::uint64_t kFixed = 0x10, kAnon = 0x20;
                const bool anon = (a3 & kAnon) != 0;
                const std::uint64_t len = AddressSpace::page_up(a1);
                std::uint64_t at = as_.map(a0, a1, prot_from_linux(a2),
                                           (a3 & kFixed) != 0, anon);
                if (at == AddressSpace::kFail) return -12;          // ENOMEM
                auto win = vm_.ram().at(at, len);
                if (win.empty()) return -12;

                if (anon) {
                    // A fresh anonymous mapping must read as zero -- and for
                    // an ANON map the guest asked for the whole page span, so
                    // clearing to the page-rounded end is correct here.
                    vm_.zero(at, len);
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
                const int ffd = fds_.host(static_cast<int>(regs_.arg(4))).value_or(-1);
                if (ffd < 0) return -9;                              // EBADF
                const auto foff = static_cast<off_t>(regs_.arg(5));
                auto n = ::pread(ffd, win.data(), a1, foff);
                if (n < 0) return darwin::fail();
                const auto got = static_cast<std::uint64_t>(n);
                if (got < a1) {
                    auto tail = vm_.ram().at(at + got, a1 - got);
                    if (!tail.empty()) std::memset(tail.data(), 0, tail.size());
                }
                // The mapping may be an executable segment written through the
                // host's data view; publish it to the instruction stream.
                if (has(prot_from_linux(a2), GuestProt::exec))
                    vm_.publish_code(at, len);
                return static_cast<std::int64_t>(at);
            }
            case S::munmap:
                as_.unmap(a0, a1);
                return 0;
            case S::mprotect:
                // Tracked in the VMA map but NOT enforced in the page tables:
                // the stage-1 tables are built RWX once, and per-page
                // reprotection would need a table walk plus TLB maintenance
                // on every call. Recorded so /proc/self/maps is truthful and
                // so enforcement can be added without an ABI change.
                return as_.protect(a0, a1, prot_from_linux(a2)) ? 0 : -12;
            case S::madvise: {
                // Only MADV_DONTNEED changes visible state: anonymous pages
                // must read back as zero afterwards. glibc's malloc relies
                // on it when trimming. Every other advice is a hint.
                constexpr std::uint64_t kDontNeed = 4;
                if (a2 == kDontNeed) {
                    const Vma* v = as_.find(a0);
                    if (v && v->anonymous) vm_.zero(a0, AddressSpace::page_up(a1));
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
                const Vma* v = as_.find(a0);
                if (!v) return -14;
                if (new_len <= old_len) {
                    as_.unmap(a0 + new_len, old_len - new_len);
                    return static_cast<std::int64_t>(a0);
                }
                if (!(a3 & kMayMove)) return -12;
                const GuestProt prot = v->prot;
                const bool anon = v->anonymous;
                std::uint64_t to = as_.map(0, new_len, prot, false, anon);
                if (to == AddressSpace::kFail) return -12;
                auto src = vm_.ram().at(a0, old_len);
                auto dst = vm_.ram().at(to, new_len);
                if (src.empty() || dst.empty()) return -14;
                std::memmove(dst.data(), src.data(), old_len);
                vm_.zero(to + old_len, new_len - old_len);
                as_.unmap(a0, old_len);
                return static_cast<std::int64_t>(to);
            }
            default:
                return std::nullopt;
        }
    }

    [[nodiscard]] Maybe do_io(abi::Sysno sc) {
        using S = abi::Sysno;
        const auto gfd = static_cast<int>(regs_.arg(0));
        const std::uint64_t a1 = regs_.arg(1), a2 = regs_.arg(2), a3 = regs_.arg(3);
        const GuestRam ram = vm_.ram();

        // fd-table operations first: they don't need a resolved host fd.
        switch (sc) {
            case S::close:
                dirs_.erase(gfd);                  // drop any directory stream
                return fds_.close(gfd);
            case S::dup:   return fds_.dup(gfd, std::nullopt, false);
            case S::dup3: {
                constexpr std::uint64_t kCloexec = 02000000;
                if (static_cast<int>(a1) == gfd) return -22;          // EINVAL
                return fds_.dup(gfd, static_cast<int>(a1), (a2 & kCloexec) != 0);
            }
            case S::fcntl: return do_fcntl(gfd, a1, a2);
            case S::ioctl: {
                auto h = fds_.host(gfd);
                if (!h) return -9;
                return do_ioctl(*h, a1, a2);
            }
            case S::ppoll:    return do_ppoll(regs_.arg(0), a1, a2);
            case S::pselect6: return do_pselect(regs_.arg(0), a1, a2, a3, regs_.arg(4));
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
                std::int32_t g[2] = {fds_.install(p[0], cx), fds_.install(p[1], cx)};
                if (g[0] < 0 || g[1] < 0) return -24;
                return ram.put(regs_.arg(0), g) ? 0 : -14;
            }
            default: break;
        }

        const auto hfd = fds_.host(gfd);
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
                auto n = ::write(*hfd, win.data(), win.size());
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
                auto n = ::pwrite(*hfd, win.data(), win.size(), static_cast<off_t>(a3));
                return n < 0 ? darwin::fail() : n;
            }
            case S::readv: case S::writev:
                if (!need_fd()) return -9;
                return do_vector(sc == S::writev, *hfd, a1, a2);
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
        auto out = vm_.ram().clamp(buf, cap);
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
        auto h = fds_.host(gfd);
        if (!h) return -9;
        switch (cmd) {
            case kDupfd:
            case kDupfdCloexec: {
                // Lowest free fd >= arg: dup to the first gap at or above it.
                for (int to = static_cast<int>(arg); to < FdTable::kMaxFds; ++to)
                    if (!fds_.host(to))
                        return fds_.dup(gfd, to, cmd == kDupfdCloexec);
                return -24;                                          // EMFILE
            }
            case kGetfd: return fds_.cloexec(gfd) ? kFdCloexec : 0;
            case kSetfd: fds_.set_cloexec(gfd, (arg & kFdCloexec) != 0); return 0;
            case kGetfl: {
                int fl = ::fcntl(*h, F_GETFL);
                if (fl < 0) return darwin::fail();
                return darwin::open_flags_to_linux(fl);
            }
            case kSetfl: {
                int cur = ::fcntl(*h, F_GETFL);
                if (cur < 0) return darwin::fail();
                cur &= ~(O_APPEND | O_NONBLOCK);
                cur |= darwin::open_flags(arg) & (O_APPEND | O_NONBLOCK);
                return ::fcntl(*h, F_SETFL, cur) < 0 ? darwin::fail() : 0;
            }
            default:
                return -22;                                          // EINVAL
        }
    }

    // ioctl(fd, req, arg). Terminals are the whole story for an interactive
    // shell; see hvf_tty.hpp for why every field is translated by name.
    [[nodiscard]] std::int64_t do_ioctl(int hfd, std::uint64_t req, std::uint64_t arg) {
        const GuestRam ram = vm_.ram();
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
        const GuestRam ram = vm_.ram();
        std::vector<LinuxPollfd> g(n);
        std::vector<struct ::pollfd> h(n);
        for (std::uint64_t i = 0; i < n; ++i) {
            if (!ram.get(fds_at + i * sizeof(LinuxPollfd), g[i])) return -14;
            auto hfd = g[i].fd < 0 ? std::nullopt : fds_.host(g[i].fd);
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
        const GuestRam ram = vm_.ram();
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
            auto h = fds_.host(static_cast<int>(fd));
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
        const GuestRam ram = vm_.ram();
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
                auto h = fds_.host(*g);
                if (!h) return -2;                                   // ENOENT
                if (sc == S::readlinkat) {
                    const std::string target = describe_fd(*h);
                    auto win = vm_.ram().clamp(regs_.arg(2), regs_.arg(3));
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
        const GuestRam ram = vm_.ram();
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
                return fds_.install(fd, (lflags & kCloexec) != 0);
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
                    auto h = fds_.host(static_cast<int>(regs_.arg(0)));
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
            default:
                return std::nullopt;
        }
    }

    HvfVm& vm_;
    AddressSpace as_;
    FdTable fds_;
    PidSpace& pids_;
    std::int32_t self_{1}, parent_{0};
    struct Child { std::int32_t guest; pid_t host; };
    std::vector<Child> children_;
    std::uint64_t clear_child_tid_{0};
    Resolver resolve_;
    Resolver unresolve_;
    std::string fd_path_storage_;
    SpawnFork spawn_;
    std::vector<std::string> env_;
    bool execed_{false};
    // Signal state: the guest's dispositions, blocked mask and alt stack.
    std::array<LinuxSigaction, kLinuxNsig> actions_{};
    std::uint64_t mask_{0};
    LinuxStack altstack_{};
    std::optional<std::uint64_t> suspend_restore_;
    bool sigreturned_{false};
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
    std::uint32_t umask_{022};
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
    explicit HvfMem(const HvfVm& vm, const HvfTrap* trap = nullptr) noexcept
        : vm_{vm}, trap_{trap} {}

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
        auto win = vm_.ram().at(value(src), dst.size());
        if (win.empty() && !dst.empty()) return err(Errno::efault);
        std::memcpy(dst.data(), win.data(), dst.size());
        return ok();
    }

    [[nodiscard]] Status copy_out(UAddr dst, std::span<const std::byte> src) const {
        auto win = vm_.ram().at(value(dst), src.size());
        if (win.empty() && !src.empty()) return err(Errno::efault);
        std::memcpy(win.data(), src.data(), src.size());
        return ok();
    }

private:
    const HvfVm& vm_;
    const HvfTrap* trap_;
};

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
