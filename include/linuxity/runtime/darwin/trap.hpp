// linuxity/runtime/darwin/trap.hpp
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

#include "linuxity/host/entropy.hpp"
#include "linuxity/abi/identity.hpp"
#include "linuxity/abi/result.hpp"
#include "linuxity/abi/syscall.hpp"
#include "linuxity/abi/wire/at_flags.hpp"
#include "linuxity/abi/wire/fd_flags.hpp"
#include "linuxity/abi/wire/dirent64.hpp"
#include "linuxity/abi/wire/stat.hpp"
#include "linuxity/abi/wire/mmap.hpp"
#include "linuxity/abi/wire/open_flags.hpp"
#include "linuxity/host/long_path.hpp"
#include "linuxity/runtime/backend.hpp"
#include "linuxity/runtime/darwin/darwin.hpp"
#include "linuxity/runtime/darwin/epoll.hpp"
#include "linuxity/runtime/darwin/exec.hpp"
#include "linuxity/runtime/darwin/fd.hpp"
#include "linuxity/runtime/darwin/fdobj.hpp"
#include "linuxity/runtime/darwin/futex.hpp"
#include "linuxity/runtime/darwin/ipc.hpp"
#include "linuxity/runtime/darwin/proc.hpp"
#include "linuxity/runtime/darwin/signal.hpp"
#include "linuxity/runtime/darwin/task.hpp"
#include "linuxity/runtime/darwin/timer.hpp"
#include "linuxity/runtime/darwin/tty.hpp"
#include "linuxity/runtime/darwin/mem.hpp"
#include "linuxity/runtime/darwin/net.hpp"
#include "linuxity/runtime/darwin/regs.hpp"
#include "linuxity/runtime/darwin/vm.hpp"
#include "linuxity/runtime/shared/address_space.hpp"
#include "linuxity/runtime/trap.hpp"

#include <Hypervisor/Hypervisor.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <sys/clonefile.h>
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
#include <unordered_map>
#include <unordered_set>
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

    // runtime::WalksLongPaths: every redirected call is performed here, and
    // an over-long host path is walked a component at a time (do_path's
    // long-path retry), so the loop hands over absolute paths unchanged.
    [[nodiscard]] static constexpr bool walks_long_paths() noexcept { return true; }

    // Translate a guest path to a host path through the portable namespace.
    // Installed by the embedder (main/test), which owns the Kernel; the trap
    // needs it only for execve, where the PROGRAM image must be found.
    using Resolver = std::function<std::string(const std::string&)>;
    void set_resolver(Resolver r) { resolve_ = std::move(r); }
    // host path -> guest path, for readlink("/proc/self/fd/N").
    void set_unresolver(Resolver r) { unresolve_ = std::move(r); }
    // The tree's inotify hub (kernel/fsnotify.hpp), owned by the kernel.
    void set_fsnotify_hub(kernel::fsnotify::Hub* h) noexcept { hub_ = h; }
    void set_env_fallback(std::vector<std::string> env) { env_ = std::move(env); }

    // -- Identity bridge to the portable core. abi::Syscalls asks the memory
    //    accessor for current_ids(); HvfMem forwards here, so getpid/getppid
    //    and /proc/self answer with this process's GUEST pid.
    struct TaskIds { std::int32_t pid, tid, ppid; };
    [[nodiscard]] TaskIds current_ids() const noexcept {
        return {task_.tid, task_.tid, parent_};
    }
    // The host pid of guest pid `g` (this process included), or nullopt.
    // And back: a host pid -- or a host group/session id, which is its
    // leader's pid -- as the guest numbers it. A host id outside the guest
    // tree (linuxity's own launching shell's group or session) reads as 1:
    // the guest's world begins at its init, as in a container.
    [[nodiscard]] std::optional<pid_t> host_pid_of(std::int32_t g) const noexcept {
        if (g == task_.tid || g == tgid_) return ::getpid();
        return pids_.host_of(g);
    }
    [[nodiscard]] std::int32_t guest_pid_of(pid_t host) const noexcept {
        if (host == ::getpid()) return tgid_;
        const std::int32_t g = pids_.guest_of(host);
        return g > 0 ? g : 1;
    }
    // The host fd behind guest fd `gfd`, or -1 (for HvfMem::host_fd_of).
    [[nodiscard]] int host_fd_of(int gfd) const {
        return proc_.with_fds([&](const FdTable& t) { return t.host(gfd).value_or(-1); });
    }
    // The same facts in abi/identity.hpp's shape, so the shared answers can
    // be used by this backend's own service routine too (not just through
    // the portable dispatcher's current_ids() probe).
    [[nodiscard]] abi::TaskIdentity task_identity() const noexcept {
        return {task_.tid, task_.tid, parent_};
    }
    // /proc/<pid>/exe for ANY pid in the tree (shared table, set on exec).
    [[nodiscard]] std::string exe_of_pid(std::int32_t pid) const {
        return pids_.exe_of(pid);
    }
    // A new task starts with its creator's nice, policy and affinity.
    void inherit_sched(std::int32_t from, std::int32_t to) noexcept {
        pids_.set_nice(to, pids_.nice_of(from));
        pids_.set_policy(to, pids_.policy_of(from));
        pids_.set_affinity(to, pids_.affinity_of(from));
    }
    [[nodiscard]] PidSpace& pid_space() const noexcept { return pids_; }
    [[nodiscard]] std::int32_t tgid() const noexcept { return tgid_; }
    [[nodiscard]] std::int32_t tid() const noexcept { return task_.tid; }

    // The loader has already written the image and stack into guest RAM, so
    // starting is just placing the entry state. `image_end` seeds the heap.
    [[nodiscard]] Status start(UAddr entry, UAddr sp) {
        if (value(entry)) cpu_.set_entry(value(entry), value(sp));
        // A cloned THREAD also comes through here (its loop calls start with
        // a null entry, already positioned). It must keep the tgid its
        // creator gave it -- adopting its own tid would publish the wrong
        // getpid for the whole process.
        if (!threaded_) tgid_ = task_.tid;
        refresh_guest_answers();
        return ok();
    }

    // Publish the syscalls the guest may answer WITHOUT a VM exit (see
    // darwin/inguest.hpp). The rule: a constant for this process image, no
    // side effect, nothing written to guest memory. Identity is exactly
    // that -- and it is ~8-20% of the syscalls a real workload makes
    // (measured over screenfetch, python, ls, git).
    //
    // Called whenever identity can change: start, after fork, after exec,
    // after setpgid/setsid. Anything NOT listed keeps trapping, so a
    // missing refresh is a lost optimisation, never a wrong answer.
    void refresh_guest_answers() {
        // The table is PROCESS-wide (one VM, one private page), so only a
        // value every thread agrees on may go in it. getpid is the THREAD
        // GROUP id -- the main thread's tid -- which is exactly that;
        // gettid is not, so a second thread revokes it for good.
        machine_.set_guest_answer(172, static_cast<std::uint64_t>(tgid_));          // getpid
        if (!threaded_) machine_.set_guest_answer(178, static_cast<std::uint64_t>(task_.tid));  // gettid
        machine_.set_guest_answer(173, static_cast<std::uint64_t>(parent_));         // getppid
        machine_.set_guest_answer(124, 0);                                          // sched_yield
        publish_ids();
    }
    // getuid & co: the dispatcher's per-process credentials (abi/creds.hpp),
    // as last learned by ig_after_dispatch. Until then they are NOT
    // published -- the guest's getuid traps and the dispatcher answers --
    // because a default (0) here would be a wrong answer, not a slow one.
    void publish_ids() {
        const auto ids = proc_.ids();
        if (!ids) {
            for (int nr : {174, 175, 176, 177}) machine_.clear_guest_answer(nr);
            return;
        }
        machine_.set_guest_answer(174, ids->uid);    // getuid
        machine_.set_guest_answer(175, ids->euid);   // geteuid
        machine_.set_guest_answer(176, ids->gid);    // getgid
        machine_.set_guest_answer(177, ids->egid);   // getegid
    }

    // After every dispatch (runtime::AnswersInGuest): a call that may have
    // changed the caller's credentials republishes them, so a getuid the
    // guest answers in-VM agrees with what the dispatcher would say.
    template <class K, class S>
    void ig_after_dispatch(const abi::Regs& r, K&, S& sys) {
        if (!S::changes_creds(abi::decode(abi::Arch::aarch64, r.nr)) && proc_.ids()) return;
        if (!proc_events_.empty()) return;   // an exec not yet applied: wait for it
        const auto c = sys.caller_ids();
        if (proc_.note_ids({c.uid, c.euid, c.gid, c.egid})) publish_ids();
    }

    // -- Process events (runtime::ReportsProcEvents) ------------------------
    // The exec this backend performs in-process, reported so the shared
    // loop applies execve's kernel-side transform (abi/creds.hpp
    // exec_happened): set-ID credentials, SysV detach. Forks and exits
    // need no event here -- each is its own linuxity with its own table.
    struct ProcEvent {
        enum Kind { spawn, exec, reap, thread, stop, cont, reparent } kind;
        std::int32_t pid;
        std::int32_t ppid;
        std::string comm;
        std::string cmdline;
    };
    [[nodiscard]] std::vector<ProcEvent> drain_proc_events() {
        // An exec queued here changes credentials only once the loop has
        // applied it -- after this returns -- so the published ids are
        // stale until then: withdraw them, and the image's first getuid
        // traps and relearns them from the dispatcher.
        if (!proc_events_.empty()) {
            proc_.forget_ids();
            publish_ids();
        }
        return std::exchange(proc_events_, {});
    }

    // A thread adopts its creator's process identity (tgid) and its own tid.
    void adopt_thread(std::int32_t tgid) noexcept {
        tgid_ = tgid;
        threaded_ = true;                      // never publish gettid here
    }

    void set_arena(std::uint64_t image_end, std::uint64_t stack_floor) {
        sync_all_shared();                     // exec discards the old image
        proc_.with_space([&](AddressSpace& t) { return t.reset(image_end, stack_floor); });
        // A non-PIE image sits in the low window BELOW the page tables, so
        // its arena [image_end, ...) spans them. Reserve the table range as
        // a no-access VMA: brk stops at it (ceiling_above) and mmap's gap
        // search skips it, instead of handing the guest EL1-only memory.
        const std::uint64_t ram = machine_.mem_size();
        const std::uint64_t lo = HvfLayout::tables_lo(ram), hi = HvfLayout::priv_end(ram);
        if (image_end < hi && lo < hi)
            proc_.with_space([&](AddressSpace& t) {
                t.adopt(Vma{lo, hi, GuestProt::none, false});
                return 0;
            });
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
        proc_.name(AddressSpace::page_down(sp) - kStackReserve, AddressSpace::page_down(mem_top), "[stack]");
    }
    // A fresh image: what /proc/<pid>/maps names its ranges, and environ.
    void note_image(const ExecResult& ex) {
        proc_.with_names([](auto& v) { v.clear(); return 0; });
        for (std::size_t i = 0; i < ex.segments.size(); ++i) {
            const auto& sg = ex.segments[i];
            proc_.name(AddressSpace::page_down(sg.begin), AddressSpace::page_up(sg.end),
                       i < ex.program_segments ? ex.program : ex.interp);
        }
        proc_.set_environ(ex.environ);
    }
    // Room below the initial sp for the stack to grow (Linux's default
    // RLIMIT_STACK, which is what prlimit64 reports).
    static constexpr std::uint64_t kStackReserve = ExecArena::stack_reserve;

    // A parent's setpgid of us, posted to the shared table (see setpgid):
    // apply it ourselves, which Darwin always allows.
    void apply_posted_pgid() {
        if (!pids_.pgid_posted(tgid_)) return;
        // apply FIRST, then acknowledge: the parent's setpgid returns when
        // the post is gone, and must find the group already changed
        const std::int32_t g = pids_.posted_pgid(tgid_);
        const auto hg = g == tgid_ ? std::optional<pid_t>{::getpid()} : pids_.host_of(g);
        if (hg) (void)::setpgid(0, *hg);
        (void)pids_.take_pgid(tgid_);
    }

    [[nodiscard]] Result<bool> next(TrapFrame& f) {
        constexpr std::uint64_t kEcSvc64 = 0x15;
        if (!ready_announced_) { pids_.mark_ready(tgid_); ready_announced_ = true; }
        for (;;) {
            if (exited_) return ok(false);
            apply_posted_pgid();
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
            if (regs_.ec() != kEcSvc64) {
                // A fault the guest HANDLES (handler frame now loaded into
                // the vCPU) must simply resume. Returning true here would
                // tell the caller "a syscall trapped": it would dispatch a
                // stale frame, write -EINVAL into x0 and reset PC to the
                // faulting instruction -- clobbering the handler entry, so
                // the fault recurred with x0=-22 and the program died.
                if (report_fault()) continue;
                return ok(false);
            }
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
        if (on_result_) on_result_(ret);
        return ok();
    }
    // Called with every syscall's final result (the dispatcher's fsnotify
    // commit). Installed by the loop, which owns the dispatcher.
    void set_result_observer(std::function<void(std::int64_t)> f) { on_result_ = std::move(f); }

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
        // Send `sig` to guest process `g` (host pid `h`). A signal with a
        // host twin goes by kill(2): the host merges and delivers it, and
        // job control (SIGSTOP/SIGCONT) is the host's. A real-time signal
        // (it must queue, one per send, with its sender) or one with no
        // twin goes through the target's mailbox, and a kick wakes it.
        auto send_to = [&](std::int32_t g, pid_t h) -> bool {
            if (sig == 0) return ::kill(h, 0) == 0;
            if (hs > 0 && sig < 32) {
                // the host delivers it; the record says who sent it (si_pid)
                (void)pids_.post_signal(g, {sig, tgid_, 0 /*SI_USER*/, 0});
                return ::kill(h, hs) == 0;
            }
            if (!pids_.post_signal(g, {sig, tgid_, 0 /*SI_USER*/, 0})) { errno = EAGAIN; return false; }
            if (pids_.ready(g)) (void)::kill(h, kKickSignal);
            return true;
        };

        // A GROUP or broadcast signal must stay INSIDE the guest's process
        // tree. Passing 0 or -1 to the host kill(2) would signal linuxity's
        // own host process group -- which is the user's terminal session, so
        // `timeout` sending SIGTERM to its group killed linuxity itself (and
        // would kill the shell that launched it).
        //
        // The group is looked up in the shared pid table, so `kill(-pgid)`
        // and `kill(0)` reach exactly the guest processes that are really in
        // it -- and, crucially, a positive pid that happens to BE a group
        // leader signals only that one process, as Linux does.
        if (gpid <= 0) {
            const std::int32_t own = guest_pid_of(::getpgrp());
            const std::int32_t pgid = gpid == 0 ? own : (gpid == -1 ? 0 : -gpid);
            std::int64_t delivered = 0;
            const auto members = pids_.members_of(pgid ? pgid : own);
            for (std::int32_t member : members) {
                if (member == task_.tid) { mark_self_pending(sig); ++delivered; continue; }
                if (auto h = pids_.host_of(member); h && send_to(member, *h))
                    ++delivered;
            }
            // kill(-1) means "every process we may signal", which for a
            // guest is its whole tree, not just its group.
            if (gpid == -1)
                for (const Child& c : children_)
                    if (auto h = pids_.host_of(c.guest); h && send_to(c.guest, *h))
                        ++delivered;
            return delivered ? 0 : -3;                               // ESRCH
        }

        if (gpid == task_.tid) { mark_self_pending(sig); return 0; }

        auto h = pids_.host_of(gpid);
        if (!h) return -3;
        return send_to(gpid, *h) ? 0 : darwin::fail();
    }

    // signalfd: a pending signal in a signalfd's mask -- and blocked, which
    // is how signalfd is meant to be used -- becomes a 128-byte record in
    // that fd's pipe instead of being delivered. One pipe write per signal,
    // so a read sees whole records, each with its sender and code.
    void feed_signalfds() {
        if (signalfds_.empty()) return;
        for (auto& [gfd, sf] : signalfds_) {
            const std::uint64_t want = sf.mask & task_.sig_mask;
            if (!want) continue;
            for (int n = 0; n < 64; ++n) {
                const auto got = g_pending.take(want);
                if (!got) break;
                LinuxSignalfdSiginfo r{};
                r.ssi_signo = static_cast<std::uint32_t>(got->signo);
                r.ssi_code = static_cast<std::uint32_t>(got->code);
                r.ssi_pid = static_cast<std::uint32_t>(got->pid);
                r.ssi_uid = proc_.ids() ? proc_.ids()->uid : 0;
                r.ssi_int = got->value;
                if (::write(sf.write_end, &r, sizeof r) != static_cast<ssize_t>(sizeof r)) {
                    g_pending.enqueue(*got);                     // full: keep it pending
                    break;
                }
            }
        }
    }

    // drain_mail: what other guest processes posted for us (see
    // PidSpace::post_signal) joins the pending queue. A classic signal's
    // record only names its sender -- the host signal itself is what makes
    // it pending -- so it merges; a real-time one IS the signal, and queues.
    void drain_mail() {
        for (int n = 0; n < PidSpace::kSigRing; ++n) {
            const auto r = pids_.take_signal(tgid_);
            if (!r.signo) break;
            if (r.signo < 32 && signal_from_linux(r.signo) > 0) {
                // the host signal may not have landed yet: record the sender
                // without making it pending on its own
                g_pending.note_sender({r.signo, r.sender, r.code, r.value});
            } else {
                g_pending.enqueue({r.signo, r.sender, r.code, r.value});
            }
        }
    }
    // A signal to OURSELVES is marked pending directly rather than sent
    // through the host: Linux delivers it before kill(2) returns to user
    // space, and our trap boundary is that point.
    void mark_self_pending(int sig) {
        if (sig == 0) return;
        if (sig == 9 || sig == 19) {
            // SIGKILL/SIGSTOP from INSIDE the namespace cannot touch its init
            // (only an ancestor namespace can) -- see is_namespace_init().
            if (is_namespace_init()) return;
            kill_with(sig);
            return;
        }
        g_pending.enqueue({sig, tgid_, 0 /*SI_USER*/, 0});
        g_pending.notify_waiters();
    }

    // linuxity's pid 1 is the init of the guest's pid namespace, and Linux
    // gives that process SIGNAL_UNKILLABLE: a signal whose disposition is
    // SIG_DFL is DISCARDED rather than acted on -- whoever sent it, the init
    // itself included. That is what lets a stray `kill(1, SIGTERM)` be
    // harmless on every Linux system.
    //
    // It matters in practice because `bash -c 'pacman -Sy'` execs pacman as
    // pid 1, and pacman's cleanup signals a pid list that ends up containing
    // 1. On Linux that is a no-op against init; without this rule it was
    // suicide -- "Terminated" right after "aur is up to date".
    [[nodiscard]] bool is_namespace_init() const noexcept { return task_.tid == 1; }

    // The portable dispatcher decides AF_UNIX bind/connect: it translates the
    // socket's filesystem path into the overlay (the writable upper for a
    // bind, wherever the node lives for a connect) and hands the result here
    // as a SOCK_REWRITE outcome. The ptrace backend pokes the new path into
    // the guest's sockaddr; we never need to touch guest memory, because we
    // build the Darwin sockaddr directly from the translated string.
    //
    // Without this hook the Cpu loop falls back to a plain forward with the
    // UNTRANSLATED path, which is why gpg-agent failed with "error binding
    // socket to '/etc/pacman.d/gnupg/S.gpg-agent': No such file or
    // directory" -- the host has no /etc/pacman.d -- and `pacman -S` then
    // died with "keyring is not writable".
    [[nodiscard]] Result<std::int64_t> rewrite_sockaddr(UAddr path_addr, const std::string& host_path,
                                                        int, unsigned long long) {
        const auto sc = abi::decode(abi::Arch::aarch64, regs_.nr());
        const int h = host_fd(static_cast<int>(regs_.arg(0)));
        if (h < 0) return complete(-9);
        ::sockaddr_un sun{};
        if (host_path.size() >= sizeof sun.sun_path) return complete(-36);   // ENAMETOOLONG
        sun.sun_family = AF_UNIX;
        std::memcpy(sun.sun_path, host_path.c_str(), host_path.size() + 1);
        sun.sun_len = static_cast<std::uint8_t>(offsetof(::sockaddr_un, sun_path)
                                                + host_path.size() + 1);
        const int rc = sc == abi::Sysno::bind
            ? ::bind(h, reinterpret_cast<::sockaddr*>(&sun), sun.sun_len)
            : ::connect(h, reinterpret_cast<::sockaddr*>(&sun), sun.sun_len);
        if (rc < 0) return complete(darwin::fail());
        // getsockname/getpeername give the guest back ITS spelling (a
        // relative "rel.sock" stays relative), not the translated host path.
        if (sc == abi::Sysno::bind)
            if (auto win = machine_.ram().clamp(value(path_addr), 108); !win.empty()) {
                const char* p = reinterpret_cast<const char*>(win.data());
                std::string name{p, ::strnlen(p, win.size())};
                if (!name.empty()) bound_paths_[host_path] = std::move(name);
            }
        return complete(0);
    }
    // The guest's spelling of an AF_UNIX path the host reports: what this
    // process bound it as, else the guest path the host path lies at.
    [[nodiscard]] std::optional<std::string> guest_unix_name(const ::sockaddr_storage& ss) const {
        if (ss.ss_family != AF_UNIX) return std::nullopt;
        const auto* sun = reinterpret_cast<const ::sockaddr_un*>(&ss);
        const std::string host{sun->sun_path, ::strnlen(sun->sun_path, sizeof sun->sun_path)};
        if (host.empty() || net::abstract_name_of(host)) return std::nullopt;
        if (auto it = bound_paths_.find(host); it != bound_paths_.end()) return it->second;
        if (unresolve_) return unresolve_(host);
        return std::nullopt;
    }
    [[nodiscard]] static std::uint64_t sock_ino(int h) noexcept {
        struct ::stat st{};
        return ::fstat(h, &st) == 0 ? static_cast<std::uint64_t>(st.st_ino) : 0;
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

    // Is guest address `a` in a file-backed mapping, on a page that starts
    // at or past the file's current end?
    [[nodiscard]] bool past_file_end(std::uint64_t a) {
        return proc_.with_backings([&](auto& v) {
            for (const auto& b : v) {
                if (a < b.at || a >= b.at + b.len) continue;
                struct ::stat st{};
                if (::fstat(b.fd, &st) != 0) return false;
                const std::uint64_t page_off = static_cast<std::uint64_t>(b.off) + ((a - b.at) & ~std::uint64_t{4095});
                return page_off >= static_cast<std::uint64_t>(st.st_size);
            }
            return false;
        });
    }


private:
    [[nodiscard]] Result<std::int64_t> complete(std::int64_t rc) {
        // strace-style line with the REAL result. The core's LINUXITY_TRACE
        // shows the dispatcher's decision; only the backend knows what the
        // emulated call actually returned, which is what debugging needs.
        static const bool strace = std::getenv("LINUXITY_STRACE") != nullptr;
        // LINUXITY_STRACE=2 also shows the bytes a write carried. A failing
        // program usually SAYS why -- to a log, a pipe, or its parent -- and
        // seeing that text beats reverse-engineering it from return codes.
        static const bool payloads = [] {
            const char* v = std::getenv("LINUXITY_STRACE");
            return v && v[0] == '2';
        }();
        if (strace)
            std::fprintf(stderr, "[%d] %3llu(%#llx, %#llx, %#llx, %#llx) = %lld\n",
                         task_.tid, static_cast<unsigned long long>(regs_.nr()),
                         static_cast<unsigned long long>(regs_.arg(0)),
                         static_cast<unsigned long long>(regs_.arg(1)),
                         static_cast<unsigned long long>(regs_.arg(2)),
                         static_cast<unsigned long long>(regs_.arg(3)),
                         static_cast<long long>(rc));
        if (payloads && regs_.nr() == 64 && rc > 0) {          // aarch64 write
            auto win = machine_.ram().clamp(regs_.arg(1), static_cast<std::size_t>(rc));
            std::string shown;
            for (std::byte b : win.first(std::min<std::size_t>(win.size(), 200))) {
                const auto c = static_cast<unsigned char>(b);
                if (c >= 0x20 && c < 0x7f) shown.push_back(static_cast<char>(c));
                else { char hex[5]; std::snprintf(hex, sizeof hex, "\\x%02x", c); shown += hex; }
            }
            std::fprintf(stderr, "      \"%s\"\n", shown.c_str());
        }
        account_io(rc);
        LX_TRY(resume(rc));
        return ok(rc);
    }
    // getrlimit/setrlimit/prlimit64 on this process's table: `set` and
    // `old` are guest addresses of struct rlimit64 (either may be 0).
    [[nodiscard]] std::int64_t rlimit(std::uint64_t res, std::uint64_t set, std::uint64_t old) {
        if (res >= proc_.rlimits.size()) return -22;
        struct L { std::uint64_t cur, max; };
        const GuestRam ram = machine_.ram();
        auto& slot = proc_.rlimits[res];
        const L prev{slot.cur, slot.max};
        if (set) {
            L n{};
            if (!ram.get(set, n)) return -14;
            if (n.cur > n.max) return -22;
            // NOFILE can't exceed what the fd table holds (Linux: nr_open)
            if (res == 7 && n.max > static_cast<std::uint64_t>(FdTable::kMaxFds)) return -1;
            const auto ids = proc_.ids();
            const bool root = !ids || ids->euid == 0;
            if (n.max > slot.max && !root) return -1;             // EPERM
            slot = {n.cur, n.max};
            // Every guest process is its own host process, so a limit on
            // what the process itself consumes is enforced for it here:
            // CPU time by the timer wheel (the host never raises SIGXCPU
            // inside hv_vcpu_run), file size by the host (SIGXFSZ/EFBIG).
            if (res == 0 /*RLIMIT_CPU*/) timers_.set_cpu_limit(n.cur, n.max);
            if (res == 1 /*RLIMIT_FSIZE*/) {
                struct ::rlimit hl{};
                hl.rlim_cur = n.cur == ~0ull ? RLIM_INFINITY : static_cast<rlim_t>(n.cur);
                hl.rlim_max = n.max == ~0ull ? RLIM_INFINITY : static_cast<rlim_t>(n.max);
                (void)::setrlimit(RLIMIT_FSIZE, &hl);
            }
        }
        if (old && !ram.put(old, prev)) return -14;
        return 0;
    }
    // /proc/<pid>/io: rchar/wchar are bytes moved by read- and write-class
    // calls (files, pipes, sockets alike), syscr/syscw the calls made.
    void account_io(std::int64_t rc) noexcept {
        using S = abi::Sysno;
        switch (abi::decode(abi::Arch::aarch64, regs_.nr())) {
            case S::read: case S::pread64: case S::readv: case S::preadv:
            case S::preadv2: case S::recvfrom: case S::recvmsg:
                proc_.syscr.fetch_add(1, std::memory_order_relaxed);
                if (rc > 0) proc_.rchar.fetch_add(static_cast<std::uint64_t>(rc), std::memory_order_relaxed);
                break;
            case S::write: case S::pwrite64: case S::writev: case S::pwritev:
            case S::pwritev2: case S::sendto: case S::sendmsg:
                proc_.syscw.fetch_add(1, std::memory_order_relaxed);
                if (rc > 0) proc_.wchar.fetch_add(static_cast<std::uint64_t>(rc), std::memory_order_relaxed);
                break;
            default: break;
        }
    }
    // A non-SVC exception is a genuine guest fault. Linux turns these into a
    // SYNCHRONOUS signal at the faulting instruction -- SIGSEGV for a bad
    // address, SIGBUS for misalignment, SIGILL for a bad opcode -- and a
    // handler that longjmps out, remaps the page, or just prints a backtrace
    // resumes normally. Tearing down the VM instead broke real programs:
    // gpg probes memory to size its secure heap and expects to CATCH the
    // SIGSEGV, so `pacman-key` failed the whole transaction with "no secret
    // key available" on what Linux treats as a routine recoverable fault.
    //
    // Returns true to keep running (a handler was entered, or the signal is
    // ignored and the instruction will be retried), false to stop.
    [[nodiscard]] bool report_fault() {
        const char* kind = "exception";
        int sig = 11;                                  // SIGSEGV
        std::int32_t code = sicode::kSegvMaperr;
        switch (regs_.ec()) {
            case 0x24: case 0x25: kind = "data abort";        break;
            case 0x20: case 0x21: kind = "instruction abort"; break;
            case 0x26: kind = "SP alignment fault";
                sig = 7; code = sicode::kBusAdraln; break;     // SIGBUS
            case 0x0e: kind = "illegal execution state";
                sig = 4;  code = sicode::kIllIllopc; break;    // SIGILL
            case 0x00: kind = "undefined instruction";
                sig = 4;  code = sicode::kIllIllopc; break;
            default: break;
        }
        // A fault inside a MAPPED range is a permission problem (ACCERR);
        // outside any VMA it is an unmapped address (MAPERR). That
        // distinction is what a guard-page handler keys on. FAR_EL1 is read
        // HERE, not on every trap: faults are rare and syscalls are not.
        const std::uint64_t far = cpu_.fault_address();
        const Vma* v = proc_.with_space([&](AddressSpace& t) { return t.find(far); });
        if (sig == 11 && v) code = sicode::kSegvAccerr;
        // A page of a file mapping that lies wholly past the file's end (it
        // was truncated after the map): Linux has no page to give, and that
        // is SIGBUS/BUS_ADRERR, not SIGSEGV.
        if (sig == 11 && v && past_file_end(far)) { sig = 7; code = sicode::kBusAdrerr; }

        // If the guest installed a handler, deliver the fault to it. The
        // frame must capture the FAULTING instruction (pc unchanged, not
        // advanced past it) so that returning from the handler retries the
        // access -- that is how a demand-paging or guard-page handler works.
        const LinuxSigaction act =
            proc_.with_signals([&](SignalDispositions& t) { return t.get(sig); });
        if (act.handler > 1 && !(task_.sig_mask & sigbit(sig))) {
            if (deliver_fault(sig, code, far)) return true;
        }

        // No handler (or the signal is blocked, which Linux treats as fatal
        // for a synchronous fault): die BY the signal, so the parent's wait
        // sees WIFSIGNALED (a shell's "Segmentation fault", Python's -11) --
        // an exit(139) is a different answer. Where it happened goes to
        // stderr only when debugging: Linux prints nothing.
        if (std::getenv("LINUXITY_DEBUG"))
            std::fprintf(stderr,
                "linuxity: guest %s at pc=%#llx addr=%#llx (%s) esr=%#llx\n",
                kind, static_cast<unsigned long long>(regs_.elr),
                static_cast<unsigned long long>(far),
                v ? "mapped" : "UNMAPPED",
                static_cast<unsigned long long>(regs_.esr));
        if (!is_namespace_init()) {
            // The host default for SIGSEGV/SIGBUS/SIGILL would also write a
            // crash report for LINUXITY; the guest's death needs only the
            // status, so leave via the signal with the core bit unset.
            kill_with(sig);
            return false;
        }
        std::fflush(nullptr);
        exited_ = true;
        code_ = 128 + sig;
        return false;
    }

    // Build an rt_sigframe for a SYNCHRONOUS fault and enter the handler.
    // Shares the layout rules with deliver_pending() but differs in two ways
    // that matter: siginfo carries si_addr (not a sender pid), and the saved
    // PC is the faulting instruction itself.
    [[nodiscard]] bool deliver_fault(int s, std::int32_t code, std::uint64_t addr) {
        const LinuxSigaction act =
            proc_.with_signals([&](SignalDispositions& t) { return t.get(s); });
        const HvfCpu::CpuState cpu = cpu_.save();
        std::uint64_t sp = cpu.sp_el0;
        // SIGSEGV from stack overflow can only be handled on an ALTERNATE
        // stack -- the normal one is what overflowed. This is the whole
        // reason sigaltstack exists.
        if ((act.flags & sigflag::kOnstack) && task_.alt_stack.ss_size &&
            !(sp > task_.alt_stack.ss_sp && sp <= task_.alt_stack.ss_sp + task_.alt_stack.ss_size))
            sp = task_.alt_stack.ss_sp + task_.alt_stack.ss_size;

        std::uint64_t ret = act.restorer;
        if (!(act.flags & sigflag::kRestorer) || !ret) {
            sp -= 16;
            if (!machine_.ram().put(sp, kSigreturnTrampoline)) return false;
            machine_.publish_code(sp, 8);
            ret = sp;
        }
        sp = (sp - sizeof(RtSigframe)) & ~std::uint64_t{15};
        const std::uint64_t frame_at = sp;

        RtSigframe frame{};
        LinuxSigfault fi{};
        fi.si_signo = s;
        fi.si_code  = code;
        fi.si_addr  = addr;
        std::memcpy(&frame.info, &fi, sizeof fi);
        frame.uc.uc_stack   = task_.alt_stack;
        frame.uc.uc_sigmask = task_.sig_mask;
        auto& mc = frame.uc.uc_mcontext;
        std::memcpy(mc.regs, cpu.x, sizeof mc.regs);
        mc.sp     = cpu.sp_el0;
        mc.pc     = regs_.elr;        // the FAULTING instruction, not past it
        // The exception was taken to our EL1 vector, so the live CPSR is the
        // stub's EL1h state; the interrupted EL0 PSTATE is in SPSR_EL1.
        mc.pstate = regs_.spsr;
        FpsimdContext fp{};
        fp.fpsr = static_cast<std::uint32_t>(cpu.fpsr);
        fp.fpcr = static_cast<std::uint32_t>(cpu.fpcr);
        std::memcpy(fp.vregs, cpu.q, sizeof fp.vregs);
        std::memcpy(mc.reserved, &fp, sizeof fp);

        // If the frame itself cannot be written the stack is unusable; let
        // the caller fall through to the fatal path rather than looping.
        if (!machine_.ram().put(frame_at, frame)) return false;

        HvfCpu::CpuState h = cpu;
        h.x[0]   = static_cast<std::uint64_t>(s);
        h.x[1]   = frame_at + offsetof(RtSigframe, info);
        h.x[2]   = frame_at + offsetof(RtSigframe, uc);
        h.x[30]  = ret;
        h.sp_el0 = sp;
        h.pc     = act.handler;
        h.cpsr   = 0;
        cpu_.load(h);

        task_.sig_mask |= act.mask;
        if (!(act.flags & sigflag::kNodefer)) task_.sig_mask |= sigbit(s);
        if (act.flags & sigflag::kResethand) route_host_signal(s, false);
        return true;
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
        if (auto r = do_ipc(sc))            return *r;
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
                int type = static_cast<int>(a1 & ~(net::kSockNonblock | net::kSockCloexec));
                // Darwin has no SOCK_SEQPACKET for AF_UNIX. A socketpair is
                // connected from birth, so a DATAGRAM pair gives the same
                // contract: reliable, ordered, message edges kept (local
                // datagrams are never dropped). SO_TYPE still answers 5.
                const bool seqpacket = *af == AF_UNIX && type == 5;
                if (seqpacket) type = SOCK_DGRAM;
                int hp[2];
                if (::socketpair(*af, type, static_cast<int>(a2), hp) < 0)
                    return darwin::fail();
                for (int e : hp) finish_socket(e, a1);
                if (seqpacket)
                    for (int e : hp) seqpacket_.insert(sock_ino(e));
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
                const int backlog = static_cast<int>(a1);
                if (::listen(h, backlog) < 0) return darwin::fail();
                // Deeper than Darwin queues (it resets the overflow, Linux
                // holds it): pump the difference (darwin/accept_pump.hpp).
                if (backlog > AcceptPump::host_cap() || proc_.has_pumps())
                    proc_.with_pumps([&](ProcessState::Pumps& m) {
                        auto it = m.find(h);
                        if (it != m.end() && it->second->serves(h)) {
                            it->second->set_backlog(backlog);
                        } else if (backlog > AcceptPump::host_cap()) {
                            auto p = std::make_unique<AcceptPump>(h, backlog);
                            if (p->valid()) m[h] = std::move(p);
                            else m.erase(h);
                        }
                        proc_.note_pumps(!m.empty());
                        return 0;
                    });
                return 0;
            }
            case S::accept: case S::accept4: {
                const int h = host_fd(gfd);
                if (h < 0) return -9;
                ::sockaddr_storage ss{};
                socklen_t len = sizeof ss;
                int c = -1;
                if (proc_.has_pumps())
                    proc_.with_pumps([&](ProcessState::Pumps& m) {
                        if (auto it = m.find(h); it != m.end() && it->second->serves(h))
                            c = it->second->take();
                        return 0;
                    });
                if (c >= 0) {
                    if (::getpeername(c, reinterpret_cast<::sockaddr*>(&ss), &len) < 0)
                        len = 0;
                } else {
                    c = ::accept(h, reinterpret_cast<::sockaddr*>(&ss), &len);
                }
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
                // MSG_TRUNC (0x20) on a datagram socket: return the
                // datagram's REAL length, however much fit. Darwin ignores
                // the flag, but SO_NREAD says the size of the first datagram.
                int real = -1;
                if (a3 & 0x20) {
                    int typ = 0; socklen_t tl = sizeof typ;
                    socklen_t nl = sizeof real;
                    if (::getsockopt(h, SOL_SOCKET, SO_TYPE, &typ, &tl) < 0 || typ != SOCK_DGRAM ||
                        ::getsockopt(h, SOL_SOCKET, SO_NREAD, &real, &nl) < 0)
                        real = -1;
                }
                ::sockaddr_storage ss{};
                socklen_t slen = sizeof ss;
                const auto n = ::recvfrom(h, buf.data(), buf.size(),
                                          net::msg_flags_to_darwin(a3),
                                          a4 ? reinterpret_cast<::sockaddr*>(&ss) : nullptr,
                                          a4 ? &slen : nullptr);
                if (n < 0) return darwin::fail();
                if (a4 && !write_sockaddr(ss, a4, regs_.arg(5))) return -14;
                return real > n ? real : n;
            }
            case S::setsockopt: {
                const int h = host_fd(gfd);
                if (h < 0) return -9;
                const auto opt = net::opt_to_darwin(static_cast<int>(a1),
                                                    static_cast<int>(a2));
                // SO_PASSCRED (SOL_SOCKET, 16): recvmsg on this socket
                // reports the sender's SCM_CREDENTIALS. Darwin has no such
                // thing; remember it and synthesize them (see do_msg).
                if (a1 == 1 && a2 == 16) {
                    std::int32_t on = 0;
                    if (a4 < sizeof on || !ram.get(a3, on)) return -14;
                    if (on) passcred_.insert(sock_ino(h)); else passcred_.erase(sock_ino(h));
                    return 0;
                }
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
                // SO_TYPE of an emulated SEQPACKET pair, and SO_PASSCRED.
                if (a1 == 1 && (a2 == 3 || a2 == 16)) {
                    const auto ino = sock_ino(h);
                    const bool ours = a2 == 3 ? seqpacket_.count(ino) != 0 : true;
                    if (ours) {
                        const std::int32_t v = a2 == 3 ? 5 : (passcred_.count(ino) ? 1 : 0);
                        std::uint32_t want = 0;
                        if (!ram.get(a4, want)) return -14;
                        if (want < sizeof v) return -22;
                        return ram.put(a3, v) && ram.put(a4, std::uint32_t{sizeof v}) ? 0 : -14;
                    }
                }
                // SO_PEERCRED (SOL_SOCKET=1, 17): struct ucred {pid,uid,gid}.
                // Darwin has no such option, so the generic path said
                // ENOPROTOOPT and libassuan's get_peercred failed -- the
                // agent then dropped every client, gpg reported "can't
                // connect to the gpg-agent: End of file" and pacman-key
                // could not generate its master key. Build it from
                // LOCAL_PEERPID (host pid -> guest pid) and the guest's
                // single identity (root).
                if (a1 == 1 && a2 == 17) {
                    std::uint32_t want = 0;
                    if (!ram.get(a4, want)) return -14;
                    pid_t hpid = 0;
                    socklen_t pl = sizeof hpid;
                    // LOCAL_PEERPID can fail (ENOTCONN) on an accepted socket
                    // once the peer has written and the connect side's PCB
                    // detached, and on socketpair ends; the CREDENTIALS are
                    // still what the guest is asking about. Fall back to
                    // getpeereid(), and finally to "same process". Linux
                    // never fails SO_PEERCRED on a connected AF_UNIX socket,
                    // and libassuan treats any failure as a dead client.
                    if (::getsockopt(h, SOL_LOCAL, LOCAL_PEERPID, &hpid, &pl) < 0) {
                        uid_t u; gid_t gg;
                        int typ = 0; socklen_t tl = sizeof typ;
                        if (::getpeereid(h, &u, &gg) < 0 &&
                            ::getsockopt(h, SOL_SOCKET, SO_TYPE, &typ, &tl) < 0)
                            return darwin::fail();
                        hpid = ::getpid();
                    }
                    const std::int32_t g = pids_.guest_of(hpid);
                    const std::int32_t gpid = g > 0 ? g : 1;
                    const std::int32_t cred[3] = {gpid, 0, 0};
                    const std::uint32_t n = std::min<std::uint32_t>(want, sizeof cred);
                    auto val = ram.at(a3, n);
                    if (val.empty() && n) return -14;
                    std::memcpy(val.data(), cred, n);
                    return ram.put(a4, n) ? 0 : -14;
                }
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
                // the VALUE's encoding (net::Val), for an int-sized answer
                if (opt->val != net::Val::raw && len == sizeof(int)) {
                    int v = 0;
                    std::memcpy(&v, val.data(), sizeof v);
                    switch (opt->val) {
                        case net::Val::boolean:  v = v != 0; break;
                        case net::Val::errno_:   v = v ? darwin::errno_to_linux(v) : 0; break;
                        case net::Val::socktype: break;   // SOCK_STREAM/DGRAM/RAW/SEQPACKET agree
                        case net::Val::raw:      break;
                    }
                    std::memcpy(val.data(), &v, sizeof v);
                }
                return ram.put(a4, static_cast<std::uint32_t>(len)) ? 0 : -14;
            }
            case S::sendmsg: case S::recvmsg:
                return do_msg(sc == S::sendmsg, gfd, a1, a2);

            // -- sendmmsg/recvmmsg: a batch of msghdrs in one call, used by
            //    DNS resolvers and high-throughput servers. struct mmsghdr
            //    is { msghdr msg_hdr; unsigned msg_len; }, so the batch is
            //    a loop over do_msg -- which is also how Linux implements it
            //    when the driver has no batch path.
            case S::sendmmsg: case S::recvmmsg: {
                const bool sending = sc == S::sendmmsg;
                constexpr std::size_t kMmsgSize = 64;        // sizeof(struct mmsghdr)
                const auto n = std::min<std::uint64_t>(a2, 1024);
                std::int64_t done = 0;
                for (std::uint64_t i = 0; i < n; ++i) {
                    const std::uint64_t hdr = a1 + i * kMmsgSize;
                    const std::int64_t rc = do_msg(sending, gfd, hdr, a3);
                    if (rc < 0) return done ? done : rc;
                    // msg_len follows the msghdr: report what moved.
                    if (!ram.put(hdr + 56, static_cast<std::uint32_t>(rc)))
                        return done ? done : -14;
                    ++done;
                    if (!sending && rc == 0) break;          // peer closed
                }
                return done;
            }
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
        // Linux's default buffers (net.core.{w,r}mem_default, 212992).
        // Darwin's are tiny -- 2 KiB for a unix datagram, 9 KiB for UDP --
        // and on Darwin the SEND buffer is also the largest datagram, so a
        // 30000-byte socketpair message or a 60000-byte UDP packet was
        // EMSGSIZE where Linux sends it. Raising them only ever matches
        // Linux; a guest that sets its own still wins.
        int buf = 212992;
        (void)::setsockopt(h, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
        (void)::setsockopt(h, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
        if (linux_type_flags & net::kSockNonblock)
            ::fcntl(h, F_SETFL, ::fcntl(h, F_GETFL) | O_NONBLOCK);
        ::fcntl(h, F_SETFD, FD_CLOEXEC);      // the HOST fd is ours; never leak it
    }

    [[nodiscard]] int host_fd(int gfd) { return host_fd_of(gfd); }
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
        std::size_t full = 0;
        if (const auto name = guest_unix_name(ss)) {
            // the guest's own spelling, NUL-terminated like Linux reports it
            std::array<std::byte, 2 + 108> la{};
            la[0] = std::byte{1};                          // AF_UNIX, little-endian
            const std::size_t n = std::min<std::size_t>(name->size(), 107);
            std::memcpy(la.data() + 2, name->data(), n);
            full = 2 + n + 1;
            std::memcpy(out.data(), la.data(), std::min(full, out.size()));
        } else {
            full = net::to_linux(ss, out);
        }
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

        // -- Ancillary data: SCM_RIGHTS (fd passing) ----------------------
        // tmux's client sends its terminal to the server this way; so do
        // sshd's privsep, systemd-style socket activation, dbus, podman.
        // Dropping cmsgs made the tmux server "open terminal failed: not a
        // terminal". Linux cmsghdr is {u64 len; i32 level; i32 type} with
        // 8-byte alignment; Darwin's is {u32 len; i32 level; i32 type}, 4-
        // byte aligned -- re-encode, translating guest fds <-> host fds.
        // SOL_SOCKET is 1 on Linux, 0xffff on Darwin; SCM_RIGHTS is 1 on both.
        struct LinuxCmsg { std::uint64_t len; std::int32_t level, type; };
        constexpr std::size_t kLHdr = sizeof(LinuxCmsg);
        auto lalign = [](std::size_t n) { return (n + 7) & ~std::size_t{7}; };
        std::vector<std::byte> hctl;
        std::vector<int> fds_out;                // guest fds being sent
        if (sending && m.control && m.controllen >= kLHdr) {
            auto ctl = ram.at(m.control, m.controllen);
            if (ctl.empty()) return -14;
            for (std::size_t off = 0; off + kLHdr <= ctl.size();) {
                LinuxCmsg c{};
                std::memcpy(&c, ctl.data() + off, kLHdr);
                if (c.len < kLHdr || off + c.len > ctl.size()) break;
                if (c.level == 1 && c.type == 1) {
                    const std::size_t n = (c.len - kLHdr) / sizeof(std::int32_t);
                    for (std::size_t i = 0; i < n; ++i) {
                        std::int32_t gfdx = 0;
                        std::memcpy(&gfdx, ctl.data() + off + kLHdr + i * 4, 4);
                        const int hx = host_fd(gfdx);
                        if (hx < 0) return -9;
                        fds_out.push_back(hx);
                    }
                }
                off += lalign(c.len);
            }
            if (!fds_out.empty()) {
                hctl.resize(CMSG_SPACE(fds_out.size() * sizeof(int)));
                auto* hc = reinterpret_cast<::cmsghdr*>(hctl.data());
                hc->cmsg_len = static_cast<socklen_t>(CMSG_LEN(fds_out.size() * sizeof(int)));
                hc->cmsg_level = SOL_SOCKET;
                hc->cmsg_type = SCM_RIGHTS;
                std::memcpy(CMSG_DATA(hc), fds_out.data(), fds_out.size() * sizeof(int));
                hm.msg_control = hctl.data();
                hm.msg_controllen = static_cast<socklen_t>(hctl.size());
            }
        } else if (!sending && m.control && m.controllen >= kLHdr) {
            // Room for as many fds as the guest's buffer could take (Linux
            // caps one message at SCM_MAX_FD = 253); a fixed 64 truncated a
            // 200-fd message.
            const std::size_t room = std::max<std::size_t>(m.controllen / 4, 253);
            hctl.resize(CMSG_SPACE(room * sizeof(int)));
            hm.msg_control = hctl.data();
            hm.msg_controllen = static_cast<socklen_t>(hctl.size());
        }

        const auto n = sending
            ? ::sendmsg(h, &hm, net::msg_flags_to_darwin(flags))
            : ::recvmsg(h, &hm, net::msg_flags_to_darwin(flags));
        if (n < 0) return darwin::fail();
        if (!sending) {
            if (m.name && !write_sockaddr(ss, m.name, msg_at + offsetof(LinuxMsghdr, namelen)))
                return -14;
            // Re-encode received SCM_RIGHTS into the guest's control buffer,
            // installing each received host fd as a new guest fd.
            std::vector<std::byte> lctl;
            const bool cloexec = (flags & 0x40000000) != 0;   // MSG_CMSG_CLOEXEC
            if (hm.msg_controllen > 0) {
                for (::cmsghdr* hc = CMSG_FIRSTHDR(&hm); hc; hc = CMSG_NXTHDR(&hm, hc)) {
                    if (hc->cmsg_level != SOL_SOCKET || hc->cmsg_type != SCM_RIGHTS) continue;
                    const std::size_t cnt = (hc->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                    std::vector<std::int32_t> g(cnt);
                    for (std::size_t i = 0; i < cnt; ++i) {
                        int hx = -1;
                        std::memcpy(&hx, CMSG_DATA(hc) + i * sizeof(int), sizeof(int));
                        ::fcntl(hx, F_SETFD, FD_CLOEXEC);      // host side is always private
                        const int gx = proc_.with_fds([&](FdTable& t) { return t.install(hx, cloexec); });
                        if (gx < 0) { ::close(hx); g[i] = -1; } else g[i] = gx;
                    }
                    const std::size_t len = kLHdr + cnt * 4;
                    const std::size_t at = lctl.size();
                    lctl.resize(at + lalign(len));
                    LinuxCmsg c{len, 1, 1};
                    std::memcpy(lctl.data() + at, &c, kLHdr);
                    std::memcpy(lctl.data() + at + kLHdr, g.data(), cnt * 4);
                }
            }
            // SO_PASSCRED: every message carries the sender's ucred. Darwin
            // has no SCM_CREDENTIALS, so build it from the peer's pid (the
            // guest's single identity owns every process: uid/gid are ours).
            if (passcred_.count(sock_ino(h))) {
                pid_t hpid = 0;
                socklen_t pl = sizeof hpid;
                if (::getsockopt(h, SOL_LOCAL, LOCAL_PEERPID, &hpid, &pl) < 0) hpid = ::getpid();
                const auto ids = proc_.ids();
                const std::int32_t g = hpid == ::getpid() ? tgid_ : pids_.guest_of(hpid);
                const std::int32_t cred[3] = {g > 0 ? g : 1,
                                              static_cast<std::int32_t>(ids ? ids->uid : 0),
                                              static_cast<std::int32_t>(ids ? ids->gid : 0)};
                const std::size_t at = lctl.size();
                lctl.resize(at + lalign(kLHdr + sizeof cred));
                LinuxCmsg c{kLHdr + sizeof cred, 1, 2};          // SOL_SOCKET, SCM_CREDENTIALS
                std::memcpy(lctl.data() + at, &c, kLHdr);
                std::memcpy(lctl.data() + at + kLHdr, cred, sizeof cred);
            }
            std::int32_t mflags = 0;
            if (lctl.size() > m.controllen) { lctl.resize(m.controllen); mflags |= 0x8; }  // MSG_CTRUNC
            if (!lctl.empty()) {
                auto dst = ram.at(m.control, lctl.size());
                if (dst.empty()) return -14;
                std::memcpy(dst.data(), lctl.data(), lctl.size());
            }
            if (hm.msg_flags & MSG_TRUNC) mflags |= 0x20;
            m.controllen = lctl.size();
            m.flags = mflags;
            (void)ram.put(msg_at, m);
        }
        return n;
    }
    // Linux clock id -> Darwin clock id.
    //
    // The table matters more than it looks: id 5 is CLOCK_REALTIME_COARSE, a
    // WALL clock, and an earlier mapping sent it to CLOCK_MONOTONIC (time
    // since boot). gpg reads the wall clock through the coarse id, saw
    // ~1970, and rejected every key as "created 16088 days in the future" --
    // so `pacman-key --populate` could not sign the distro's keys.
    //
    // Darwin has no COARSE variants or BOOTTIME; the precise clock of the
    // same KIND is a correct substitute (coarse only promises lower cost,
    // never a different epoch). Negative ids are per-process/thread CPU
    // clocks encoded by glibc (clock_getcpuclockid); report this process.
    [[nodiscard]] static std::optional<::clockid_t> linux_clock_to_darwin(std::int64_t id) noexcept {
        switch (id) {
            case 0:  return CLOCK_REALTIME;            // REALTIME
            case 5:  return CLOCK_REALTIME;            // REALTIME_COARSE  (wall clock!)
            case 8:  return CLOCK_REALTIME;            // REALTIME_ALARM
            case 11: return CLOCK_REALTIME;            // TAI (leap offset ignored)
            case 1:  return CLOCK_MONOTONIC;           // MONOTONIC
            case 6:  return CLOCK_MONOTONIC;           // MONOTONIC_COARSE
            case 4:  return CLOCK_MONOTONIC_RAW;       // MONOTONIC_RAW
            case 7:  return CLOCK_MONOTONIC;           // BOOTTIME (Darwin's counts sleep too)
            case 9:  return CLOCK_MONOTONIC;           // BOOTTIME_ALARM
            case 2:  return CLOCK_PROCESS_CPUTIME_ID;  // PROCESS_CPUTIME_ID
            case 3:  return CLOCK_THREAD_CPUTIME_ID;   // THREAD_CPUTIME_ID
            default:
                if (id < 0) return CLOCK_PROCESS_CPUTIME_ID;   // CPUCLOCK encodings
                return std::nullopt;
        }
    }

    // The physical core this host thread is running on, from the ARM
    // TPIDRRO-free source Darwin exposes to user space.
    [[nodiscard]] static std::uint32_t current_cpu() noexcept {
        std::uint64_t mpidr = 0;
        // Darwin publishes the CPU number in the low bits of TPIDRRO_EL0's
        // shadow via the commpage; fall back to 0 if unavailable.
        __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(mpidr));
        return static_cast<std::uint32_t>(mpidr & 0x7);
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

    // -- SysV IPC and POSIX message queues ----------------------------------
    // Darwin is a BSD, so it has all three SysV families with the same
    // semantics; only the ABI differs (see hvf_ipc.hpp). PostgreSQL, X11 and
    // `ipcs` all depend on these.
    [[nodiscard]] Maybe do_ipc(abi::Sysno sc) {
        using S = abi::Sysno;
        using namespace ipc;
        const GuestRam ram = machine_.ram();
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1),
                            a2 = regs_.arg(2), a3 = regs_.arg(3);
        switch (sc) {
            // -- Semaphores.
            case S::semget:
                return ::semget(static_cast<key_t>(a0), static_cast<int>(a1),
                                static_cast<int>(a2)) < 0
                           ? darwin::fail()
                           : ::semget(static_cast<key_t>(a0), static_cast<int>(a1),
                                      static_cast<int>(a2));
            case S::semop: case S::semtimedop: {
                // struct sembuf { unsigned short sem_num; short sem_op, sem_flg; }
                // is the same 6 bytes on both kernels. semtimedop's timeout
                // has no Darwin form, so a timed wait degrades to a blocking
                // one -- which is the behaviour on a kernel without it.
                constexpr std::uint64_t kMaxOps = 256;
                if (a2 == 0 || a2 > kMaxOps) return -22;
                std::vector<struct ::sembuf> ops(a2);
                for (std::uint64_t i = 0; i < a2; ++i) {
                    struct { std::uint16_t num; std::int16_t op, flg; } b{};
                    if (!ram.get(a1 + i * 6, b)) return -14;
                    ops[i] = {b.num, b.op, b.flg};
                }
                return ::semop(static_cast<int>(a0), ops.data(), ops.size()) < 0
                           ? darwin::fail() : 0;
            }
            case S::semctl: {
                const int cmd = static_cast<int>(a2);
                switch (cmd) {
                    case kIpcRmid:
                        return ::semctl(static_cast<int>(a0), 0, IPC_RMID) < 0
                                   ? darwin::fail() : 0;
                    case kGetVal: case kGetPid: case kGetNcnt: case kGetZcnt: {
                        const int dcmd = cmd == kGetVal ? GETVAL
                                       : cmd == kGetPid ? GETPID
                                       : cmd == kGetNcnt ? GETNCNT : GETZCNT;
                        const int rc = ::semctl(static_cast<int>(a0),
                                                static_cast<int>(a1), dcmd);
                        return rc < 0 ? darwin::fail() : rc;
                    }
                    case kSetVal: {
                        ::semun u{};
                        u.val = static_cast<int>(a3);
                        return ::semctl(static_cast<int>(a0), static_cast<int>(a1),
                                        SETVAL, u) < 0 ? darwin::fail() : 0;
                    }
                    case kIpcStat: case kSemStat: {
                        struct ::semid_ds ds{};
                        ::semun u{};
                        u.buf = &ds;
                        if (::semctl(static_cast<int>(a0), 0, IPC_STAT, u) < 0)
                            return darwin::fail();
                        LinuxSemidDs out{};
                        out.sem_perm = perm_to_linux(ds.sem_perm);
                        out.sem_otime = ds.sem_otime;
                        out.sem_ctime = ds.sem_ctime;
                        out.sem_nsems = ds.sem_nsems;
                        return ram.put(a3, out) ? 0 : -14;
                    }
                    default:
                        return -22;
                }
            }

            // -- Message queues.
            case S::msgget: {
                const int rc = ::msgget(static_cast<key_t>(a0), static_cast<int>(a1));
                return rc < 0 ? darwin::fail() : rc;
            }
            case S::msgsnd: {
                // The message is { long mtype; char mtext[]; } in guest RAM.
                auto win = ram.clamp(a1, a2 + sizeof(long));
                if (win.empty()) return -14;
                return ::msgsnd(static_cast<int>(a0), win.data(),
                                static_cast<std::size_t>(a2), static_cast<int>(a3)) < 0
                           ? darwin::fail() : 0;
            }
            case S::msgrcv: {
                auto win = ram.clamp(a1, a2 + sizeof(long));
                if (win.empty()) return -14;
                const auto n = ::msgrcv(static_cast<int>(a0), win.data(),
                                        static_cast<std::size_t>(a2),
                                        static_cast<long>(a3),
                                        static_cast<int>(regs_.arg(4)));
                return n < 0 ? darwin::fail() : n;
            }
            case S::msgctl: {
                const int cmd = static_cast<int>(a1);
                if (cmd == kIpcRmid)
                    return ::msgctl(static_cast<int>(a0), IPC_RMID, nullptr) < 0
                               ? darwin::fail() : 0;
                if (cmd == kIpcStat || cmd == kMsgStat) {
                    struct ::msqid_ds ds{};
                    if (::msgctl(static_cast<int>(a0), IPC_STAT, &ds) < 0)
                        return darwin::fail();
                    LinuxMsqidDs out{};
                    out.msg_perm = perm_to_linux(ds.msg_perm);
                    out.msg_stime = ds.msg_stime;
                    out.msg_rtime = ds.msg_rtime;
                    out.msg_ctime = ds.msg_ctime;
                    out.msg_cbytes = ds.msg_cbytes;
                    out.msg_qnum = ds.msg_qnum;
                    out.msg_qbytes = ds.msg_qbytes;
                    out.msg_lspid = ds.msg_lspid;
                    out.msg_lrpid = ds.msg_lrpid;
                    return ram.put(a2, out) ? 0 : -14;
                }
                return -22;
            }

            // -- Shared memory. shmat must return a GUEST address the guest
            //    can dereference, so a segment is allocated inside guest RAM
            //    (via the VMA map) and backed by a Darwin shm segment only
            //    for cross-process sharing of its CONTENTS.
            case S::shmget: {
                const int rc = ::shmget(static_cast<key_t>(a0),
                                        static_cast<std::size_t>(a1),
                                        static_cast<int>(a2));
                return rc < 0 ? darwin::fail() : rc;
            }
            case S::shmat: {
                struct ::shmid_ds ds{};
                if (::shmctl(static_cast<int>(a0), IPC_STAT, &ds) < 0)
                    return darwin::fail();
                // The segment's CONTENTS live in a named host shm object
                // (one per segment id) that every attach maps MAP_SHARED, so
                // a fork child's or another process's attach really shares
                // the parent's pages. (They used to be copied in at shmat and
                // out at shmdt, so concurrent attaches never saw each other.)
                // The Darwin segment stays the authority for ids, keys,
                // permissions and IPC_STAT; holding a host attach for the
                // guest's keeps its nattch/lpid/atime honest.
                const std::uint64_t hp = HvfMachine::host_page();
                const std::uint64_t span = (ds.shm_segsz + hp - 1) / hp * hp;
                const bool rdonly = (a2 & 010000) != 0;         // SHM_RDONLY
                const GuestProt prot = rdonly ? GuestProt::read : GuestProt::read | GuestProt::write;
                if (a1 % hp) return -22;                        // (SHM_RND unsupported)
                if (const int obj = sysv_shm_object(static_cast<int>(a0), span); obj >= 0) {
                    const std::uint64_t at = proc_.with_space([&](AddressSpace& sp) {
                        return sp.map(a1, span, prot, a1 != 0, /*anonymous=*/true, hp);
                    });
                    if (at == AddressSpace::kFail) { ::close(obj); return -12; }
                    const bool ok = add_backing(at, span, obj, 0);
                    ::close(obj);
                    if (ok) {
                        if (rdonly) set_pte_prot(at, span, prot);
                        else reset_pte_prot(at, span);
                        void* host = ::shmat(static_cast<int>(a0), nullptr, rdonly ? SHM_RDONLY : 0);
                        shm_attached_[at] = {static_cast<int>(a0),
                                             static_cast<std::uint64_t>(ds.shm_segsz), span,
                                             host == reinterpret_cast<void*>(-1) ? nullptr : host};
                        return static_cast<std::int64_t>(at);
                    }
                    proc_.with_space([&](AddressSpace& sp) { sp.unmap(at, span); return 0; });
                }
                const std::uint64_t len = AddressSpace::page_up(ds.shm_segsz);
                const std::uint64_t at = proc_.with_space([&](AddressSpace& sp) {
                    return sp.map(a1, len, GuestProt::read | GuestProt::write,
                                  a1 != 0, /*anonymous=*/true);
                });
                if (at == AddressSpace::kFail) return -12;
                // No host object (shm_open refused): copy the segment's
                // current contents in, and write changes back at shmdt.
                if (void* p = ::shmat(static_cast<int>(a0), nullptr, SHM_RDONLY);
                    p != reinterpret_cast<void*>(-1)) {
                    auto win = machine_.ram().at(at, ds.shm_segsz);
                    if (!win.empty()) std::memcpy(win.data(), p, ds.shm_segsz);
                    ::shmdt(p);
                }
                shm_attached_[at] = {static_cast<int>(a0),
                                     static_cast<std::uint64_t>(ds.shm_segsz), 0, nullptr};
                return static_cast<std::int64_t>(at);
            }
            case S::shmdt: {
                auto it = shm_attached_.find(a0);
                if (it == shm_attached_.end()) return -22;
                if (it->second.span) {                         // a shared backing
                    drop_backings(a0, it->second.span);
                    proc_.with_space([&](AddressSpace& sp) { sp.unmap(a0, it->second.span); return 0; });
                    if (it->second.host) ::shmdt(it->second.host);
                    shm_attached_.erase(it);
                    return 0;
                }
                // Publish our changes before detaching.
                if (void* p = ::shmat(it->second.id, nullptr, 0);
                    p != reinterpret_cast<void*>(-1)) {
                    auto win = machine_.ram().at(a0, it->second.size);
                    if (!win.empty()) std::memcpy(p, win.data(), it->second.size);
                    ::shmdt(p);
                }
                proc_.with_space([&](AddressSpace& sp) {
                    sp.unmap(a0, AddressSpace::page_up(it->second.size));
                });
                shm_attached_.erase(it);
                return 0;
            }
            case S::shmctl: {
                const int cmd = static_cast<int>(a1);
                if (cmd == kIpcRmid) {
                    if (::shmctl(static_cast<int>(a0), IPC_RMID, nullptr) < 0)
                        return darwin::fail();
                    // Live attaches keep their mapping of the object; a new
                    // segment that reuses the id must start from zeros.
                    ::shm_unlink(sysv_shm_name(static_cast<int>(a0)).c_str());
                    return 0;
                }
                if (cmd == kIpcStat || cmd == kShmStat) {
                    struct ::shmid_ds ds{};
                    if (::shmctl(static_cast<int>(a0), IPC_STAT, &ds) < 0)
                        return darwin::fail();
                    LinuxShmidDs out{};
                    out.shm_perm = perm_to_linux(ds.shm_perm);
                    out.shm_segsz = ds.shm_segsz;
                    out.shm_atime = ds.shm_atime;
                    out.shm_dtime = ds.shm_dtime;
                    out.shm_ctime = ds.shm_ctime;
                    out.shm_cpid = ds.shm_cpid;
                    out.shm_lpid = ds.shm_lpid;
                    out.shm_nattch = ds.shm_nattch;
                    return ram.put(a2, out) ? 0 : -14;
                }
                return -22;
            }

            default:
                return std::nullopt;
        }
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
                // Catch the host signal only while the guest has a handler,
                // ignores it, or BLOCKS it (then it must wait as pending);
                // otherwise leave the host default so a terminal Ctrl-C
                // kills us exactly like it kills a process.
                route_host_signal(s, act.handler != 0 || (task_.sig_mask & sigbit(s)));
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
                const std::uint64_t before = task_.sig_mask;
                switch (a0) {
                    case 0: task_.sig_mask |= set;  break;               // SIG_BLOCK
                    case 1: task_.sig_mask &= ~set; break;               // SIG_UNBLOCK
                    case 2: task_.sig_mask = set;   break;               // SIG_SETMASK
                    default: return -22;
                }
                // A BLOCKED signal must become pending, not act: with a
                // SIG_DFL disposition the host default would kill (or stop)
                // us the moment one arrived -- sigwait/sigtimedwait/signalfd
                // never saw it. So the host catches every signal the guest
                // blocks, and gets its default back when unblocked with no
                // handler (delivery then applies the guest's default).
                if (const std::uint64_t changed = before ^ task_.sig_mask) {
                    for (int s = 1; s <= kLinuxNsig; ++s) {
                        if (!(changed & sigbit(s)) || s == 9 || s == 19) continue;
                        const auto act = proc_.with_signals([&](SignalDispositions& t) { return t.get(s); });
                        if (act.handler != 0) continue;                  // caught or ignored already
                        const bool blocked = (task_.sig_mask & sigbit(s)) != 0;
                        // unblocked SIG_DFL: back to the host default -- but
                        // a default-IGNORED one (SIGCHLD, SIGWINCH...) stays
                        // caught: the host default would just drop it, and
                        // catching it costs nothing
                        if (!blocked && default_action(s) == Default::ignore) continue;
                        route_host_signal(s, blocked);
                    }
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
        drain_mail();
        feed_signalfds();
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
        int s = std::countr_zero(ready) + 1;
        PendingSignals::Info info{s, 0, 0, 0};
        if (task_.pending.load(std::memory_order_relaxed) & sigbit(s)) {
            task_.pending.fetch_and(~sigbit(s), std::memory_order_relaxed);   // thread-directed
        } else if (auto t = g_pending.take(sigbit(s))) {
            info = *t;
        }
        s = info.signo;
        // The sigsuspend mask covered exactly this delivery; the handler
        // runs with it, and the saved mask is what sigreturn restores.
        if (task_.suspend_restore) {
            task_.sig_mask = *task_.suspend_restore;
            task_.suspend_restore.reset();
        }
        LinuxSigaction act = proc_.with_signals([&](SignalDispositions& t) { return t.get(s); });

        if (act.handler == 1) return false;                      // SIG_IGN
        if (act.handler == 0 && is_namespace_init()) return false;  // init: SIG_DFL discarded
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
        frame.info.si_code = info.code;                          // SI_USER / SI_QUEUE / ...
        frame.info.si_pid = info.pid;
        frame.info.si_uid = static_cast<std::int32_t>(proc_.ids() ? proc_.ids()->uid : 0);
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
        // Dying by SIGSEGV/SIGABRT/... is the GUEST's death; without this
        // the host's crash reporter would file (and take time writing) a
        // report for linuxity itself. Unhooking the task's crash exception
        // ports leaves the signal -- and the wait status -- untouched.
        (void)::task_set_exception_ports(::mach_task_self(),
                                         EXC_MASK_CRASH | EXC_MASK_CORPSE_NOTIFY,
                                         MACH_PORT_NULL, EXCEPTION_DEFAULT, 0);
        {
            // the host thread may have it blocked (a tty shield): unblock
            sigset_t one;
            sigemptyset(&one);
            sigaddset(&one, signal_from_linux(linux_sig));
            ::pthread_sigmask(SIG_UNBLOCK, &one, nullptr);
        }
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

            // Identity: pid/tid/ppid are this backend's own task facts (the
            // shared answers in abi/identity.hpp). The CREDENTIAL calls are
            // not here: the portable dispatcher owns them (abi/creds.hpp),
            // and ig_after_dispatch republishes them for the in-guest table.
            case S::getpid: case S::gettid: case S::getppid:
                if (auto a = abi::identity_answer(sc, task_identity()))
                    return *a;
                return -38;                                  // ENOSYS

            // -- Process groups and sessions --------------------------------
            // Every guest process is a real host process, so the HOST
            // kernel's groups and sessions are the one truth -- the same
            // ones the terminal driver uses to deliver ^C/^Z and to stop a
            // background reader. Keeping a second copy in the shared table
            // made getpgrp (table) and tcgetpgrp (host) disagree whenever the
            // two calls of a setpgid race (parent and child each set it, as
            // POSIX shells do) -- a job spun forever waiting to be in the
            // foreground. The table only translates pids (a group id is its
            // leader's pid); its pgid/sid fields are a published copy for
            // other processes' /proc.
            case S::setpgid: {
                const std::int32_t pid = a0 ? static_cast<std::int32_t>(a0) : task_.tid;
                const std::int32_t pgid = a1 ? static_cast<std::int32_t>(a1) : pid;
                const auto hp = host_pid_of(pid);
                const auto hg = pgid == pid ? hp : host_pid_of(pgid);
                if (!hp) return -3;                                  // ESRCH
                if (!hg) return -1;                                  // EPERM: no such group
                if (::setpgid(*hp, *hg) < 0) {
                    // Darwin: EACCES for a child that has exec'd, and every
                    // HVF child has (on the host) -- but the GUEST child has
                    // not unless execed() says so. Then the child moves
                    // itself: post the group, kick it, wait until it took it.
                    if (errno != EACCES || pid == task_.tid || pids_.has_execed(pid)) return darwin::fail();
                    // Already there (the child set its own group first, as
                    // a job-control child does): nothing to do, as on Linux.
                    if (::getpgid(*hp) == *hg) { pids_.set_pgid(pid, pgid); return 0; }
                    pids_.post_pgid(pid, pgid);
                    // Kick it only once it can take a kick: before its first
                    // trap it is still starting up (SIGEMT's default kills),
                    // and it reads the post at that first trap anyway.
                    if (pids_.ready(pid)) (void)::kill(*hp, kKickSignal);
                    // until it took it, or is in that group by its own hand,
                    // or has died: getpgid fails for a zombie on Darwin, but
                    // Linux still lets a parent set an unreaped child's
                    // group, so a gone child is success (its group no longer
                    // matters to anyone).
                    while (pids_.pgid_posted(pid) && ::getpgid(*hp) > 0 && ::getpgid(*hp) != *hg)
                        ::usleep(200);
                    (void)pids_.take_pgid(pid);
                    const pid_t now = ::getpgid(*hp);
                    if (now > 0 && now != *hg) return -1;
                }
                pids_.set_pgid(pid, pgid);
                return 0;
            }
            case S::getpgid: {
                const std::int32_t pid = a0 ? static_cast<std::int32_t>(a0) : task_.tid;
                const auto hp = host_pid_of(pid);
                if (!hp) return -3;
                const pid_t g = ::getpgid(*hp);
                return g < 0 ? darwin::fail() : guest_pid_of(g);
            }
            case S::getpgrp:
                return guest_pid_of(::getpgrp());
            case S::setsid: {
                // Linux: EPERM if the caller already leads a process group.
                const pid_t s = ::setsid();
                if (s < 0) return darwin::fail();
                pids_.set_sid(task_.tid, task_.tid);
                pids_.set_pgid(task_.tid, task_.tid);
                return task_.tid;
            }
            case S::getsid: {
                const std::int32_t pid = a0 ? static_cast<std::int32_t>(a0) : task_.tid;
                const auto hp = host_pid_of(pid);
                if (!hp) return -3;
                const pid_t s = ::getsid(*hp);
                return s < 0 ? darwin::fail() : guest_pid_of(s);
            }
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
        // A second thread means gettid is no longer a process constant, and
        // the in-guest table can't tell threads apart: give it back to the
        // trap path, for every thread, permanently.
        threaded_ = true;
        machine_.clear_guest_answer(178);
        if (!spawn_thread_) return -38;
        if (!req.stack) return -22;                      // a thread needs a stack
        // A thread's tid lives in the SAME number space as every pid in the
        // guest (Linux: tids and pids are one namespace, and a process's pid
        // IS its main thread's tid). So it is allocated from the SHARED pid
        // table, never from a per-process counter.
        //
        // A per-process counter starting at 1 is exactly the bug this
        // replaces: a fork child (pid 2) handed its first thread tid 1 --
        // the PARENT's pid -- and tid 2 -- its OWN pid. A later
        // tgkill/exit/futex aimed at "tid 1" then hit the wrong task, and
        // `pacman -Sy` was killed by a SIGTERM no guest had sent.
        const std::int32_t tid = pids_.allocate(::getpid());
        if (tid < 0) return -11;                         // EAGAIN: namespace full
        inherit_sched(task_.tid, tid);

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
        start.tgid = tgid_;                     // same process, new thread
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

    // Guest fork, the macOS way (see runtime/darwin/fork.hpp for why fork(2) of
    // linuxity itself is not an option). The parent:
    //   1. pre-allocates the child's GUEST pid (so the return value is known
    //      before the child exists -- no race, no spinning),
    //   2. serializes everything that isn't RAM into a ForkImage,
    //   3. hands RAM (COW snapshot) + image to the embedder's spawn hook,
    //      which starts a fresh linuxity that resumes the guest with x0 = 0.
    [[nodiscard]] std::int64_t do_fork(const CloneRequest& req) {
        if (!pids_.valid() || !spawn_) return -38;
        const auto fstart = std::chrono::steady_clock::now();
        const std::int32_t child = pids_.allocate(0);   // placeholder host pid
        if (child < 0) return -11;                       // EAGAIN
        inherit_sched(task_.tid, child);

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
        img.rlimits = proc_.rlimits;
        img.pte_lo = proc_.pte_lo;
        img.pte_hi = proc_.pte_hi;
        img.environ = proc_.environ();
        proc_.with_names([&](auto& v) {
            for (const auto& r : v)
                img.range_names += std::to_string(r.begin) + " " + std::to_string(r.end) + " " +
                                   r.name + "\n";
            return 0;
        });
        proc_.with_space([&](AddressSpace& sp) {
            img.vmas = sp.vmas();
            img.brk = sp.brk();
            img.arena = sp.arena();
        });
        {
            auto ex = proc_.with_fds([&](FdTable& t) { return t.export_table(); });
            img.fds = std::move(ex.entries);
            img.fd_hosts = std::move(ex.host_fds);
        }
        // Shared backings ride as extra fd groups after the table's own: the
        // child maps the SAME objects, so writes on either side are seen by
        // the other, as MAP_SHARED promises across fork.
        proc_.with_backings([&](auto& v) {
            for (const auto& b : v) {
                img.backings.push_back({b.at, b.len, b.off, static_cast<std::int32_t>(img.fd_hosts.size())});
                img.fd_hosts.push_back(b.fd);
            }
            return 0;
        });
        proc_.with_signals([&](SignalDispositions& d) {
            img.sig_actions = d.table();
        });

        std::fflush(nullptr);
        static const bool fprof = std::getenv("LINUXITY_PROFILE_FORK") != nullptr;
        const auto f0 = std::chrono::steady_clock::now();
        const pid_t host = spawn_(img);
        if (fprof) std::fprintf(stderr, "[do_fork] spawn_ %lld us\n",
            static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - f0).count()));
        if (host < 0) { pids_.release(child); return -11; }
        pids_.bind(child, host);
        // A forked child inherits its parent's process group and session,
        // which is what makes a shell's pipeline one killable unit.
        pids_.set_pgid(child, pids_.pgid_of(task_.tid));
        pids_.set_sid(child, pids_.sid_of(task_.tid));
        pids_.set_exe(child, pids_.exe_of(task_.tid));   // same image until it execs
        pids_.set_ppid(child, task_.tid);
        if (req.flags & clone_flag::parent_settid)
            (void)machine_.ram().put(req.parent_tid_addr, std::int32_t{child});
        children_.push_back({child, host});
        if (fprof) std::fprintf(stderr, "[do_fork] total %lld us\n",
            static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - fstart).count()));
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
        std::vector<int> fd_hosts;        // parent-side host fd per open-file group
        SignalDispositions::Table sig_actions{};
        std::uint64_t sig_mask{};
        LinuxStack altstack{};
        std::string namespace_state;    // Kernel::export_fork: creds, cwd, fd paths
        std::array<ProcessState::Rlim, 16> rlimits{};
        std::string environ;            // /proc/<pid>/environ, until exec
        std::string range_names;        // "begin end name\n"..., for maps
        struct Backed { std::uint64_t at, len; std::int64_t off; std::int32_t group; };
        std::vector<Backed> backings;   // shared host pages; `group` indexes fd_hosts
        std::uint64_t pte_lo{~std::uint64_t{0}}, pte_hi{0};   // narrowed page permissions
    };
    using SpawnFork = std::function<pid_t(ForkImage&)>;
    void set_fork_spawner(SpawnFork f) { spawn_ = std::move(f); }

    // What a new guest THREAD needs: its starting CPU state plus the
    // per-thread fields. The embedder turns this into a host thread that
    // creates its own vCPU and runs its own Cpu loop.
    struct ThreadStart {
        HvfCpu::CpuState cpu{};
        std::int32_t tid{};
        std::int32_t tgid{};            // the process this thread belongs to
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
        tgid_ = img.self;             // a fork child is its own thread group
        // fork(2) puts the child in the parent's process group as it is
        // NOW. A pre-spawned spare inherited its creator's group from back
        // when it was spawned, and the parent may have moved since (a
        // job-control shell's setpgid, a pty child's setsid); join it. Only
        // the child may: Darwin refuses a parent's setpgid of an exec'd
        // process. (The session cannot move: the forker never hands over a
        // spare from another session.)
        if (const auto hp = pids_.host_of(img.parent))
            if (const pid_t g = ::getpgid(*hp); g > 0 && g != ::getpgrp()) (void)::setpgid(0, g);
        refresh_guest_answers();          // new pid/ppid for this process
        proc_.umask = img.umask;
        ::umask(static_cast<mode_t>(img.umask));
        proc_.with_space([&](AddressSpace& t) { return t.restore(img.vmas, img.brk, img.arena); });
        proc_.with_fds([&](FdTable& t) { return t.import_table(img.fds, host_fds); });
        for (const auto& b : img.backings) {
            const auto gi = static_cast<std::size_t>(b.group);
            if (gi >= host_fds.size()) continue;
            // The snapshot COPIED these pages; map the shared object back.
            if (add_backing(b.at, b.len, host_fds[gi], b.off)) {}
        }
        // The extra groups are ours alone (the fd table never names them).
        for (const auto& b : img.backings)
            if (static_cast<std::size_t>(b.group) < host_fds.size()) ::close(host_fds[static_cast<std::size_t>(b.group)]);
        proc_.rlimits = img.rlimits;
        proc_.pte_lo = img.pte_lo;              // the tables came in the snapshot
        proc_.pte_hi = img.pte_hi;
        proc_.set_environ(img.environ);
        for (std::size_t at = 0; at < img.range_names.size();) {
            const std::size_t nl = std::min(img.range_names.find('\n', at), img.range_names.size());
            unsigned long long b = 0, e = 0;
            int used = 0;
            const std::string line = img.range_names.substr(at, nl - at);
            if (std::sscanf(line.c_str(), "%llu %llu %n", &b, &e, &used) == 2)
                proc_.name(b, e, line.substr(static_cast<std::size_t>(used)));
            at = nl + 1;
        }
        // fork(2): the child inherits handlers, mask and alt stack verbatim.
        proc_.with_signals([&](SignalDispositions& d) {
            d.set_table(img.sig_actions);
        });
        task_.sig_mask = img.sig_mask;
        task_.alt_stack = img.altstack;
        for (int s = 1; s <= kLinuxNsig; ++s) {
            const auto h = proc_.with_signals([&](SignalDispositions& t) { return t.get(s); }).handler;
            if (h == 1) { const int hs = signal_from_linux(s);
                          if (hs > 0 && hs != SIGKILL && hs != SIGSTOP) ::signal(hs, SIG_IGN); }
            else if (h) route_host_signal(s, true);
            // blocked with SIG_DFL: caught, so it waits as pending (see
            // rt_sigprocmask) instead of acting on the host
            else if (task_.sig_mask & sigbit(s)) route_host_signal(s, true);
        }
        if (img.child_settid) (void)machine_.ram().put(img.child_settid, std::int32_t{task_.tid});
        task_.clear_child_tid = img.clear_child_tid;
        regs_.elr = img.cpu.pc;
        regs_.spsr = img.cpu.cpsr;
    }
    [[nodiscard]] PidSpace& pids() noexcept { return pids_; }

private:

    // wait4(pid, status*, options, rusage*). Linux and Darwin share WNOHANG=1
    // and WUNTRACED=2, but Linux's WCONTINUED is 8 and Darwin's 0x10 --
    // dropping it made waitpid(pid, WCONTINUED) sleep until the child EXITED.
    // The STATUS is re-encoded so signal numbers match the guest's.
    //
    // "Any child" (-1) and "any in my group" (0, -pgid) mean the GUEST's
    // children. The host process also parents its warm zygotes, which never
    // exit while it lives -- so a host waitpid(-1) in a guest with no children
    // left blocked forever instead of answering ECHILD (busybox xargs calls
    // wait4(-1) after reaping its command, and hung every time). So: no guest
    // children is ECHILD at once; otherwise sleep in one kevent on exactly
    // those pids (EVFILT_PROC/NOTE_EXIT), which a signal interrupts with
    // EINTR the same way it interrupts waitpid.
    [[nodiscard]] std::int64_t do_wait4(std::int32_t gpid, std::uint64_t status,
                                        int options, std::uint64_t rusage) {
        int st = 0;
        pid_t got = 0;
        if (options & ~(1 | 2 | 8 | 0x01000000 | 0x20000000 | 0x40000000 | static_cast<int>(0x80000000u)))
            return -22;                                   // EINVAL: unknown option
        const int hopts = (options & (WNOHANG | WUNTRACED)) | ((options & 8) ? WCONTINUED : 0);
        if (gpid > 0) {
            auto h = pids_.host_of(gpid);
            if (!h) return -10;
            got = ::waitpid(*h, &st, hopts);
            if (got < 0) return darwin::fail();
        } else {
            // -1: every child; 0: our group; < -1: that group.
            std::optional<std::int32_t> want_pgid;
            if (gpid == 0) want_pgid = guest_pid_of(::getpgrp());
            else if (gpid < -1) want_pgid = -gpid;
            for (;;) {
                std::vector<pid_t> hs;
                for (const Child& c : children_)
                    if (!want_pgid || pids_.pgid_of(c.guest) == *want_pgid) hs.push_back(c.host);
                if (hs.empty()) return -10;                     // ECHILD
                for (pid_t h : hs) {
                    got = ::waitpid(h, &st, WNOHANG | (hopts & (WUNTRACED | WCONTINUED)));
                    if (got > 0) break;
                    if (got < 0 && errno == ECHILD)            // reaped elsewhere
                        std::erase_if(children_, [h](const Child& c) { return c.host == h; });
                }
                if (got > 0) break;
                if (hopts & WNOHANG) return 0;
                // Sleep until one of them exits (or stops, for WUNTRACED: a
                // stop raises no NOTE_EXIT, so bound the sleep and re-poll).
                const int kq = ::kqueue();
                if (kq < 0) return darwin::fail();
                std::vector<struct ::kevent> evs(hs.size());
                for (std::size_t i = 0; i < hs.size(); ++i)
                    EV_SET(&evs[i], static_cast<uintptr_t>(hs[i]), EVFILT_PROC,
                           EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, nullptr);
                struct ::kevent out{};
                const struct ::timespec tick{0, 50'000'000};
                const int n = ::kevent(kq, evs.data(), static_cast<int>(evs.size()), &out, 1,
                                       (hopts & (WUNTRACED | WCONTINUED)) ? &tick : nullptr);
                const int e = errno;
                ::close(kq);
                if (n < 0 && e == EINTR) return -4;             // EINTR, as Linux
                // n > 0: an exit (or an EV_ERROR for a pid already gone --
                // either way the WNOHANG sweep above now finds it).
            }
        }
        if (got == 0) return 0;                                   // WNOHANG
        std::int32_t g = pids_.guest_of(got);
        if (status) (void)machine_.ram().put(status, std::int32_t{wstatus_to_linux(st)});
        if (rusage) {
            // struct rusage: utime, stime (timevals), then 14 longs. Reaped
            // children's totals are what the host accounts after the wait.
            struct ::rusage ru{};
            (void)::getrusage(RUSAGE_CHILDREN, &ru);
            std::int64_t lr[18]{};
            lr[0] = ru.ru_utime.tv_sec; lr[1] = ru.ru_utime.tv_usec;
            lr[2] = ru.ru_stime.tv_sec; lr[3] = ru.ru_stime.tv_usec;
            lr[4] = ru.ru_maxrss / 1024;                          // Darwin: bytes; Linux: KiB
            lr[9] = ru.ru_minflt; lr[10] = ru.ru_majflt;
            lr[16] = ru.ru_nvcsw; lr[17] = ru.ru_nivcsw;
            (void)machine_.ram().put(rusage, lr);
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
            {
                // Neither #! nor ELF: ENOEXEC before the old image is gone
                // (execvp then runs it with /bin/sh, as POSIX says).
                unsigned char mag[4]{};
                std::FILE* f = std::fopen(host.c_str(), "rb");
                const std::size_t got = f ? std::fread(mag, 1, 4, f) : 0;
                if (f) std::fclose(f);
                if (got < 4 || mag[0] != 0x7f || mag[1] != 'E' || mag[2] != 'L' || mag[3] != 'F')
                    return -8;                                       // ENOEXEC
            }
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
        // argv and envp in full: Linux bounds them by size (a quarter of
        // RLIMIT_STACK, 2 MiB here), not by count -- a 4096-entry cap cut
        // `xargs`-sized command lines short. Past the limit is E2BIG, and so
        // is one string over MAX_ARG_STRLEN (32 pages).
        constexpr std::uint64_t kArgMax = ExecArena::stack_reserve / 4;
        constexpr std::size_t kStrMax = 32 * 4096;
        std::uint64_t total = 0;
        bool too_big = false;
        auto read_vec = [&](std::uint64_t at) {
            std::vector<std::string> v;
            for (std::size_t i = 0; at && !too_big; ++i) {
                std::uint64_t p = 0;
                if (!ram.get(at + i * 8, p) || p == 0) break;
                std::string s = ram.cstr(p, kStrMax + 1);
                total += s.size() + 1 + 8;
                if (s.size() > kStrMax || total > kArgMax) { too_big = true; break; }
                v.push_back(std::move(s));
            }
            return v;
        };
        std::string guest_path = ram.cstr(regs_.arg(0));
        std::vector<std::string> argv = read_vec(regs_.arg(1));
        std::vector<std::string> envp = read_vec(regs_.arg(2));
        if (too_big) return -7;                                      // E2BIG
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
        static const bool eprof = std::getenv("LINUXITY_PROFILE_EXEC") != nullptr;
        const auto e0 = std::chrono::steady_clock::now();
        auto emark = [&](const char* w) {
            if (eprof) std::fprintf(stderr, "[exec %d] %-8s %6lld us\n", task_.tid, w,
                static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - e0).count()));
        };
        std::uint64_t zeroed = 0, nvma = 0;
        // Shared objects leave the address space FIRST: zeroing a range still
        // backed by one would wipe it for every other process mapping it.
        drop_backings(0, ~std::uint64_t{0} >> 1);
        if (proc_.pte_hi > proc_.pte_lo) {
            // the old image's page permissions go with it
            machine_.protect(proc_.pte_lo, proc_.pte_hi - proc_.pte_lo, true, true, true);
            proc_.pte_lo = ~std::uint64_t{0};
            proc_.pte_hi = 0;
            cpu_.flush_tlb_on_entry();
        }
        for (const Vma& v : proc_.with_space([&](AddressSpace& t) { return t.vmas(); })) {
            // Read-only, file-backed mappings (library text, rodata, the
            // program image) were never written by the guest; their bytes
            // are file contents, not secrets, and the loader overwrites
            // whatever it reuses. Zeroing them is pure cost -- 1 ms of
            // every exec, mostly copying COW pages of libc's text just to
            // clear them. Writable or anonymous ranges are still cleared.
            if (!v.anonymous && !has(v.prot, GuestProt::write)) continue;
            const auto z0 = std::chrono::steady_clock::now();
            machine_.zero(v.begin, v.size());
            zeroed += v.size(); ++nvma;
            if (eprof) {
                const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - z0).count();
                if (us > 50) std::fprintf(stderr, "[exec %d]   vma %#llx +%llu KiB prot=%d: %lld us\n", task_.tid,
                    static_cast<unsigned long long>(v.begin),
                    static_cast<unsigned long long>(v.size() >> 10), static_cast<int>(v.prot),
                    static_cast<long long>(us));
            }
        }
        if (eprof) std::fprintf(stderr, "[exec %d] zeroed %llu KiB in %llu vmas\n", task_.tid,
                                static_cast<unsigned long long>(zeroed >> 10),
                                static_cast<unsigned long long>(nvma));
        emark("zero");
        auto ex = hvf_exec(machine_, resolve, guest_path, argv, envp);
        emark("load");
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
        note_image(*ex);                          // before the stack names itself
        adopt_stack(ex->sp, machine_.mem_size());
        proc_.with_fds([&](FdTable& t) { return t.on_exec(); });
        dirs_.clear();
        // execve(2): caught signals revert to SIG_DFL (the handler code is
        // gone); ignored stay ignored; the blocked mask is preserved; the
        // alt stack is cleared.
        for (int s = 1; s <= kLinuxNsig; ++s)
            if (proc_.with_signals([&](SignalDispositions& t) { return t.get(s); }).handler > 1)
                route_host_signal(s, (task_.sig_mask & sigbit(s)) != 0);   // blocked: still pending-able
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
        tgid_ = task_.tid;            // exec collapses the thread group to us
        threaded_ = false;            // ...and kills every other thread
        refresh_guest_answers();          // same pid, but a fresh image
        pids_.set_exe(task_.tid, exe_path_of(host_path, guest_path));
        pids_.mark_execed(task_.tid);           // releases a vfork parent
        // The kernel side of execve (set-ID credentials, SysV detach) is the
        // shared loop's: report the exec like any backend would.
        proc_events_.push_back({ProcEvent::exec, tgid_, parent_, {}, {}});
        return 0;
    }

    // The path /proc/<pid>/exe should name: the real binary, with symlinks
    // resolved (`/bin/bash` -> `/usr/bin/bash`), as the kernel reports it.
    // A #! script's exe is its INTERPRETER, which hvf_exec followed for us;
    // the guest path we have is the script, so resolve via the host image.
    [[nodiscard]] std::string exe_path_of(const std::string& host,
                                          const std::string& guest, int depth = 0) const {
        if (host.empty() || !unresolve_ || depth > 4) return guest;
        char real[PATH_MAX];
        if (!::realpath(host.c_str(), real)) return guest;
        std::string g = unresolve_(real);
        // A shebang script: report the interpreter, as Linux does.
        if (FILE* f = std::fopen(real, "rb")) {
            char hdr[256]{};
            const std::size_t n = std::fread(hdr, 1, sizeof hdr - 1, f);
            std::fclose(f);
            if (n > 2 && hdr[0] == '#' && hdr[1] == '!') {
                std::string_view l{hdr + 2, n - 2};
                l = l.substr(0, l.find('\n'));
                while (!l.empty() && (l.front() == ' ' || l.front() == '\t')) l.remove_prefix(1);
                l = l.substr(0, l.find_first_of(" \t"));
                if (!l.empty() && resolve_) {
                    const std::string ig{l};
                    return exe_path_of(resolve_(ig), ig, depth + 1);
                }
            }
        }
        return g.empty() ? guest : g;
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
                // exit_group(2) ends every thread, NOW -- including ones
                // blocked in host calls (futex, poll, read) that a vCPU kick
                // cannot reach. Linux tears them down wherever they stand,
                // and _exit gives exactly that: all threads stop, all fds
                // close (so a parent reading our pipes sees EOF), and the
                // parent's wait sees this status. Waiting for siblings
                // instead hung pacman's download child -- see run() in
                // src/run_darwin.cpp for the whole story.
                end_process(static_cast<int>(a0 & 0xff));

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
                (void)host::random_bytes(win.data(), win.size());
                return static_cast<std::int64_t>(win.size());
            }

            // -- clock_gettime(clkid, timespec*). Both kernels agree on the
            //    struct (two 64-bit words); the clock IDs need mapping.
            case S::clock_gettime: case S::clock_getres: {
                const auto id = linux_clock_to_darwin(static_cast<std::int64_t>(a0));
                if (!id) return -22;                             // EINVAL: no such clock
                struct ::timespec ts{};
                const int rc = sc == S::clock_gettime ? ::clock_gettime(*id, &ts)
                                                      : ::clock_getres(*id, &ts);
                if (rc < 0) return darwin::fail();
                if (!a1) return 0;                               // clock_getres(id, NULL)
                const LinuxTimespec out{ts.tv_sec, ts.tv_nsec};
                return ram.put(a1, out) ? 0 : -14;
            }

            // -- prlimit64(pid, res, new*, old*). The limits are this
            //    process's own table (inherited across fork and exec): a set
            //    reads back, a raise past the hard limit is EPERM only for
            //    the unprivileged, and NOFILE's hard cap is the fd table's.
            case S::prlimit64: {
                if (a0 != 0 && static_cast<std::int32_t>(a0) != tgid_) {
                    if (!pids_.host_of(static_cast<std::int32_t>(a0))) return -3;   // ESRCH
                }
                return rlimit(a1, a2, regs_.arg(3));
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
                        //
                        // The TIMEOUT KIND differs between the two ops, and
                        // getting it wrong is what produced glibc's "futex
                        // facility returned an unexpected error code":
                        //   FUTEX_WAIT         -- RELATIVE timeout.
                        //   FUTEX_WAIT_BITSET  -- ABSOLUTE deadline, against
                        //                         CLOCK_REALTIME if the
                        //                         FUTEX_CLOCK_REALTIME bit
                        //                         is set, else CLOCK_MONOTONIC.
                        // pthread_cond_timedwait uses the second form.
                        std::uint64_t ns = 0;
                        if (a3) {
                            struct { std::int64_t sec, nsec; } ts{};
                            if (!machine_.ram().get(a3, ts)) return -14;
                            const bool absolute =
                                static_cast<FutexOp>(cmd) == FutexOp::wait_bitset;
                            const auto want = static_cast<std::uint64_t>(ts.sec) * 1'000'000'000ull
                                            + static_cast<std::uint64_t>(ts.nsec);
                            if (absolute) {
                                const bool realtime =
                                    (static_cast<std::uint32_t>(a1) & kFutexClockRealtime) != 0;
                                struct ::timespec now{};
                                ::clock_gettime(realtime ? CLOCK_REALTIME : CLOCK_MONOTONIC, &now);
                                const auto cur = static_cast<std::uint64_t>(now.tv_sec) * 1'000'000'000ull
                                               + static_cast<std::uint64_t>(now.tv_nsec);
                                if (want <= cur) return -110;      // already expired
                                ns = want - cur;
                            } else {
                                ns = want;
                            }
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
                        // PTHREAD_PRIO_INHERIT mutexes and falls back on
                        // ENOSYS, so that answer is correct HERE -- but any
                        // OTHER unknown op must be EINVAL, because glibc
                        // treats an unexpected errno from futex as fatal
                        // ("The futex facility returned an unexpected error
                        // code") rather than retrying.
                        switch (static_cast<FutexOp>(cmd)) {
                            case FutexOp::lock_pi: case FutexOp::unlock_pi:
                            case FutexOp::trylock_pi:
                            case FutexOp::wait_requeue_pi:
                            case FutexOp::cmp_requeue_pi:
                                return -38;                      // ENOSYS
                            default:
                                return -22;                      // EINVAL
                        }
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

            // -- futex2 (Linux 6.7+). glibc still prefers the classic futex,
            //    but newer runtimes probe these. Same semantics, different
            //    argument shapes.
            case S::futex_wake: {
                void* p = futex_ptr(a0);
                if (!p) return -14;
                return Futex::wake(p, static_cast<std::uint32_t>(a2), /*shared=*/true);
            }
            case S::futex_wait: {
                void* p = futex_ptr(a0);
                if (!p) return -14;
                std::uint64_t ns = 0;
                if (a3) {
                    struct { std::int64_t sec, nsec; } ts{};
                    if (!ram.get(a3, ts)) return -14;
                    ns = static_cast<std::uint64_t>(ts.sec) * 1'000'000'000ull
                       + static_cast<std::uint64_t>(ts.nsec);
                    if (!ns) ns = 1;
                }
                return Futex::wait(p, static_cast<std::uint32_t>(a1), ns, true);
            }
            case S::futex_requeue: {
                // Wake on the first address, then on the second -- the same
                // conservative lowering the classic FUTEX_REQUEUE uses here.
                void* p = futex_ptr(a0);
                if (!p) return -14;
                std::int64_t woke = Futex::wake(p, 1, true);
                if (void* p2 = futex_ptr(a1)) woke += Futex::wake(p2, ~0u, true);
                return woke;
            }
            case S::futex_waitv: {
                // Wait on up to 128 futexes at once. Without a multi-address
                // primitive on Darwin, poll each in turn: if ANY has already
                // changed we return its index (the common fast path), and
                // otherwise wait on the first with the caller's timeout.
                constexpr std::uint64_t kMaxWaiters = 128;
                const auto n = a1;
                if (n == 0 || n > kMaxWaiters) return -22;
                struct Waiter { std::uint64_t val, uaddr; std::uint32_t flags, pad_; };
                for (std::uint64_t i = 0; i < n; ++i) {
                    Waiter w{};
                    if (!ram.get(a0 + i * sizeof(Waiter), w)) return -14;
                    std::uint32_t cur = 0;
                    if (!ram.get(w.uaddr, cur)) return -14;
                    if (cur != static_cast<std::uint32_t>(w.val))
                        return static_cast<std::int64_t>(i);   // already differs
                }
                Waiter first{};
                if (!ram.get(a0, first)) return -14;
                void* p = futex_ptr(first.uaddr);
                if (!p) return -14;
                const std::int64_t rc = Futex::wait(p, static_cast<std::uint32_t>(first.val),
                                                    1'000'000, /*shared=*/true);
                return rc == -110 ? -110 : 0;
            }
            case S::rseq_slice_yield:
                ::sched_yield();
                return 0;

            // -- process_vm_readv/writev: read or write ANOTHER process's
            //    memory. Every guest process shares one guest RAM mapping,
            //    so this is a copy between two guest address ranges -- and
            //    because guest VA == GPA here, the "remote" pid's memory is
            //    at the same addresses we can already reach.
            case S::process_vm_readv: case S::process_vm_writev: {
                const auto target = static_cast<std::int32_t>(a0);
                if (!pids_.host_of(target) && target != task_.tid) return -3;   // ESRCH
                const bool reading = sc == S::process_vm_readv;
                std::uint64_t moved = 0;
                for (std::uint64_t i = 0; i < a2; ++i) {
                    GuestIovec local{};
                    if (!ram.get(a1 + i * sizeof(GuestIovec), local)) return -14;
                    // Walk the remote vector in step, splitting as needed.
                    for (std::uint64_t j = 0; j < regs_.arg(4); ++j) {
                        GuestIovec remote{};
                        if (!ram.get(regs_.arg(3) + j * sizeof(GuestIovec), remote))
                            return -14;
                        const auto n = std::min(local.len, remote.len);
                        if (!n) continue;
                        auto dst = ram.at(reading ? local.base : remote.base, n);
                        auto src = ram.at(reading ? remote.base : local.base, n);
                        if (dst.empty() || src.empty()) return -14;
                        std::memmove(dst.data(), src.data(), n);
                        moved += n;
                        break;
                    }
                }
                return static_cast<std::int64_t>(moved);
            }

            // -- Memory protection keys. Darwin has no MPK, and the WHOLE
            //    point of a pkey is that it enforces something; pretending
            //    to allocate one would make a guest believe memory is
            //    protected when it is not. pkey_mprotect with the "no key"
            //    sentinel is just mprotect, so that case is honoured.
            case S::pkey_alloc: case S::pkey_free:
                return -38;
            case S::pkey_mprotect:
                if (static_cast<std::int32_t>(a3) != -1) return -22;   // a real key
                return proc_.with_space([&](AddressSpace& sp) {
                    return sp.protect(a0, a1, prot_from_linux(a2)) ? 0 : -12;
                });

            // -- NUMA. One node exists, so the answers are exact rather
            //    than approximate: binding to "all nodes" succeeds, asking
            //    where a page lives always says node 0.
            case S::mbind: case S::set_mempolicy: case S::set_mempolicy_home_node:
                return 0;
            case S::get_mempolicy: {
                if (a0 && !ram.put(a0, std::int32_t{0})) return -14;   // MPOL_DEFAULT
                if (a1 && !ram.put(a1, std::uint64_t{1})) return -14;  // node 0 only
                return 0;
            }
            case S::migrate_pages:
                return 0;              // one node: nothing to migrate
            case S::move_pages: {
                // Report every page as resident on node 0.
                const auto n = a1;
                for (std::uint64_t i = 0; i < n; ++i)
                    if (regs_.arg(4) && !ram.put(regs_.arg(4) + i * 4, std::int32_t{0}))
                        return -14;
                return 0;
            }
            case S::process_madvise:
                return 0;              // advice for another process: a hint
            case S::process_mrelease:
                return 0;              // reclaim a dying process's memory
            case S::cachestat: {
                // Page-cache residency for a range. Guest RAM is always
                // resident, so report everything cached -- which is true.
                struct Cachestat {
                    std::uint64_t cache, dirty, writeback, evicted, recently_evicted;
                };
                struct Range { std::uint64_t off, len; };
                Range r{};
                if (!ram.get(a1, r)) return -14;
                const std::uint64_t pages = (r.len + 4095) / 4096;
                const Cachestat out{pages, 0, 0, 0, 0};
                return ram.put(a2, out) ? 0 : -14;
            }
            case S::mseal:
                return -38;            // sealing a mapping: no Darwin analogue
            case S::map_shadow_stack:
                return -38;            // needs hardware shadow-stack support
            case S::remap_file_pages:
                return -38;            // removed from Linux itself

            // -- Operations a kernel reserves for itself. linuxity is not
            //    the host kernel and takes no host privilege, so these
            //    CANNOT be honoured -- and faking success would be a lie
            //    about something a caller is entitled to rely on. EPERM is
            //    the answer an unprivileged Linux process gets, which is
            //    exactly our situation; ENOSYS is reserved for features the
            //    kernel genuinely lacks.
            case S::init_module: case S::finit_module: case S::delete_module:
            case S::kexec_load: case S::kexec_file_load:
            case S::nfsservctl: case S::quotactl_fd:
            case S::lookup_dcookie:
                return -1;             // EPERM

            // -- Kernel subsystems with no userspace-reconstructible form.
            //    bpf and perf_event_open need in-kernel program loading and
            //    hardware counters; userfaultfd needs the page-fault path
            //    (which on this backend belongs to the hypervisor);
            //    io_uring and aio need an in-kernel submission queue. Every
            //    caller probes these and has a fallback -- that is WHY they
            //    probe -- so ENOSYS routes them to it.
            case S::bpf: case S::perf_event_open: case S::userfaultfd:
            case S::io_setup: case S::io_destroy: case S::io_submit:
            case S::io_cancel: case S::io_getevents: case S::io_pgetevents:
            case S::io_uring_setup: case S::io_uring_enter: case S::io_uring_register:
                return -38;            // ENOSYS

            // -- The kernel keyring. A real implementation needs kernel-side
            //    key storage with its own permission model; gnome-keyring
            //    and ssh-agent use userspace agents instead (and that is
            //    what works here).
            case S::add_key: case S::request_key: case S::keyctl:
                return -38;

            // -- LSM query interface (Linux 6.8+). There is no LSM to
            //    describe, and claiming one exists would mislead a caller
            //    into believing policy is enforced.
            case S::lsm_get_self_attr: case S::lsm_set_self_attr:
            case S::lsm_list_modules:
                return -38;
            case S::fanotify_init:
                // Whole-filesystem event notification with permission
                // decisions; inotify (implemented above) covers the watch
                // use case that programs actually fall back to.
                return -38;

            // -- Namespaces. unshare/setns create or enter kernel
            //    namespaces; the guest ALREADY lives in linuxity's own
            //    namespace (its pid space, its mount table, its uid 0), and
            //    a nested one would need kernel support we do not have.
            //    Accepting a no-op unshare is right where it asks for what
            //    the guest already has.
            case S::unshare: {
                constexpr std::uint64_t kNewns = 0x00020000, kNewuser = 0x10000000,
                                        kNewpid = 0x20000000, kNewnet = 0x40000000,
                                        kNewipc = 0x08000000, kNewuts = 0x04000000,
                                        kNewcgroup = 0x02000000, kFiles = 0x00000400;
                constexpr std::uint64_t already_ours =
                    kNewns | kNewuser | kNewpid | kNewipc | kNewuts | kNewcgroup | kFiles;
                if (a0 & kNewnet) return -1;        // a separate network: EPERM
                return (a0 & ~already_ours) ? -22 : 0;
            }
            case S::setns: case S::listns:
                return -38;

            // -- The *at xattr forms (Linux 6.13+) and the file attribute
            //    pair (6.14+). The core owns extended attributes (they are
            //    how it stores guest uid/mode), so these route through it
            //    once it grows the *at spellings; until then the non-at
            //    forms it already handles are what libc uses.
            case S::setxattrat: case S::getxattrat:
            case S::listxattrat: case S::removexattrat:
            case S::file_getattr: case S::file_setattr:
            case S::open_tree_attr:
                return -38;
            case S::fspick:
                return -38;            // new mount API; the core handles mount()
            case S::ptrace:
                // Debugging a guest from inside the guest needs us to be its
                // tracer, which on this backend the hypervisor already is.
                // A real implementation would re-enter our own trap loop as a
                // nested tracer; it is a feature, not a translation.
                return -38;
            case S::epoll_pwait2: {
                // epoll_pwait with a timespec instead of milliseconds.
                auto it = epolls_.find(static_cast<int>(a0));
                if (it == epolls_.end()) return -22;
                int timeout_ms = -1;
                if (a3) {
                    struct { std::int64_t sec, nsec; } ts{};
                    if (!ram.get(a3, ts)) return -14;
                    timeout_ms = static_cast<int>(ts.sec * 1000 + ts.nsec / 1'000'000);
                }
                std::vector<LinuxEpollEvent> ready;
                const auto n = it->second->wait(ready, static_cast<int>(a2), timeout_ms);
                if (n < 0) return n;
                for (std::size_t i = 0; i < ready.size(); ++i)
                    if (!ram.put(a1 + i * sizeof(LinuxEpollEvent), ready[i])) return -14;
                return n;
            }

            // -- POSIX message queues. Darwin has no mq_* at all. Unlike the
            //    SysV families (which Darwin shares), there is no primitive
            //    to translate to -- a faithful implementation means building
            //    priority queues with blocking send/receive from scratch,
            //    which is a feature in its own right rather than an ABI
            //    translation. glibc reports ENOSYS as "mqueue not supported",
            //    which is the truth.
            case S::mq_open: case S::mq_unlink: case S::mq_timedsend:
            case S::mq_timedreceive: case S::mq_notify: case S::mq_getsetattr:
                return -38;

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
                    const auto id = linux_clock_to_darwin(static_cast<std::int64_t>(a0));
                    if (!id) return -22;
                    struct ::timespec now{};
                    ::clock_gettime(*id, &now);
                    std::int64_t d = (req.sec - now.tv_sec) * 1'000'000'000LL +
                                     (req.nsec - now.tv_nsec);
                    if (d <= 0) return 0;
                    ts = {static_cast<time_t>(d / 1'000'000'000LL),
                          static_cast<long>(d % 1'000'000'000LL)};
                }
                // Sleep until the deadline or a deliverable guest signal --
                // whichever is first. Linux's nanosleep is interruptible
                // (never restarted, even under SA_RESTART): EINTR, with the
                // time left in `rem`, and the handler runs before the guest
                // sees it. A plain host nanosleep held every signal until
                // the whole sleep ended (100s of SIGALRMs became 4).
                const auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds{ts.tv_sec} + std::chrono::nanoseconds{ts.tv_nsec};
                for (;;) {
                    const auto left = deadline - std::chrono::steady_clock::now();
                    if (left <= std::chrono::nanoseconds::zero()) return 0;
                    const auto ms = std::chrono::ceil<std::chrono::milliseconds>(left).count();
                    std::vector<struct ::pollfd> none;
                    const int rc = signal_aware_poll(none, static_cast<int>(std::min<std::int64_t>(ms, INT32_MAX)));
                    if (rc != -4) continue;                        // timed out (or spurious): recheck
                    const std::uint64_t remp = clk ? regs_.arg(3) : a1;
                    const auto rem = std::max(std::chrono::nanoseconds::zero(),
                                              std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                  deadline - std::chrono::steady_clock::now()));
                    if (remp && !(clk && (a1 & kTimerAbstime))) {
                        const LinuxTimespec r{rem.count() / 1'000'000'000LL, rem.count() % 1'000'000'000LL};
                        if (!ram.put(remp, r)) return -14;
                    }
                    return -4;                                     // EINTR
                }
            }

            case S::umask: {
                // Every create below is a HOST create, so the guest's mask has
                // to be the host's: tracking it alone left files made under
                // umask 027 at 0755 (the host's 022 applied instead).
                const auto m = static_cast<std::uint32_t>(a0 & 0777);
                ::umask(static_cast<mode_t>(m));
                return proc_.umask.exchange(m, std::memory_order_relaxed);
            }
            // -- Resource limits and accounting -----------------------------
            case S::getrlimit: case S::setrlimit: {
                // The legacy 2-arg forms of prlimit64, on the same table.
                return sc == S::setrlimit ? rlimit(a0, a1, 0) : rlimit(a0, 0, a1);
            }
            case S::times: {
                // times(struct tms*) -> clock ticks since an arbitrary epoch.
                // Linux's CLK_TCK is 100, so report centiseconds.
                struct ::rusage ru{};
                ::getrusage(RUSAGE_SELF, &ru);
                struct LinuxTms { std::int64_t utime, stime, cutime, cstime; };
                auto ticks = [](const struct ::timeval& tv) {
                    return static_cast<std::int64_t>(tv.tv_sec) * 100 + tv.tv_usec / 10'000;
                };
                struct ::rusage ch{};
                ::getrusage(RUSAGE_CHILDREN, &ch);
                const LinuxTms out{ticks(ru.ru_utime), ticks(ru.ru_stime),
                                   ticks(ch.ru_utime), ticks(ch.ru_stime)};
                if (a0 && !ram.put(a0, out)) return -14;
                struct ::timespec up{};
                ::clock_gettime(CLOCK_MONOTONIC, &up);
                return up.tv_sec * 100 + up.tv_nsec / 10'000'000;
            }
            case S::getrusage: {
                // struct rusage: the two timevals plus the counters programs
                // actually read (maxrss, faults, context switches).
                struct LinuxRusage {
                    std::int64_t utime_sec, utime_usec, stime_sec, stime_usec;
                    std::int64_t maxrss, ixrss, idrss, isrss;
                    std::int64_t minflt, majflt, nswap, inblock, oublock;
                    std::int64_t msgsnd, msgrcv, nsignals, nvcsw, nivcsw;
                };
                static_assert(sizeof(LinuxRusage) == 144);
                const int who = static_cast<int>(a0) == -1 ? RUSAGE_CHILDREN : RUSAGE_SELF;
                struct ::rusage ru{};
                if (::getrusage(who, &ru) < 0) return darwin::fail();
                LinuxRusage out{};
                out.utime_sec  = ru.ru_utime.tv_sec;
                out.utime_usec = ru.ru_utime.tv_usec;
                out.stime_sec  = ru.ru_stime.tv_sec;
                out.stime_usec = ru.ru_stime.tv_usec;
                // Darwin reports maxrss in BYTES, Linux in kilobytes.
                out.maxrss  = ru.ru_maxrss / 1024;
                out.minflt  = ru.ru_minflt;
                out.majflt  = ru.ru_majflt;
                out.inblock = ru.ru_inblock;
                out.oublock = ru.ru_oublock;
                out.nsignals = ru.ru_nsignals;
                out.nvcsw   = ru.ru_nvcsw;
                out.nivcsw  = ru.ru_nivcsw;
                return ram.put(a1, out) ? 0 : -14;
            }

            case S::getgroups:
                return 0;           // root, no supplementary groups

            // -- waitid(idtype, id, infop, options, rusage). The modern
            //    wait; systemd and Go's os/exec use it. Both kernels share
            //    the idtype values (P_ALL=0, P_PID=1, P_PGID=2).
            case S::waitid: {
                ::idtype_t idt = P_ALL;
                ::id_t id = 0;
                if (a0 == 1) {                               // P_PID
                    auto h = pids_.host_of(static_cast<std::int32_t>(a1));
                    if (!h) return -10;                      // ECHILD
                    idt = P_PID;
                    id = static_cast<::id_t>(*h);
                } else if (a0 == 2) {                        // P_PGID
                    auto h = pids_.host_of(static_cast<std::int32_t>(a1));
                    if (!h) return -10;
                    idt = P_PGID;
                    id = static_cast<::id_t>(*h);
                }
                siginfo_t si{};
                // The option BITS differ: Linux WSTOPPED=2, WCONTINUED=8,
                // WNOWAIT=0x01000000; Darwin 0x08, 0x10, 0x20 (WEXITED=4 and
                // WNOHANG=1 agree). Passing Linux's straight through dropped
                // WNOWAIT -- the "peek" reaped the zombie -- and turned
                // WSTOPPED into WUNTRACED.
                const std::uint64_t lo = a3;
                const int opts = ((lo & 1) ? WNOHANG : 0) | ((lo & 2) ? WSTOPPED : 0)
                               | ((lo & 4) ? WEXITED : 0) | ((lo & 8) ? WCONTINUED : 0)
                               | ((lo & 0x01000000) ? WNOWAIT : 0);
                const bool nowait = (lo & 0x01000000) != 0;
                if (::waitid(idt, id, &si, opts) < 0) return darwin::fail();
                if (a2) {
                    // The guest's siginfo_t: signo/errno/code then the
                    // pid/uid/status union, which is what callers read.
                    struct LinuxSiginfoWait {
                        std::int32_t si_signo, si_errno, si_code, pad_;
                        std::int32_t si_pid, si_uid, si_status;
                        std::uint8_t rest[100];
                    };
                    LinuxSiginfoWait out{};
                    out.si_signo = 17;                       // SIGCHLD
                    out.si_code = si.si_code;
                    out.si_pid = si.si_pid ? pids_.guest_of(si.si_pid) : 0;
                    out.si_status = si.si_status;
                    if (!ram.put(a2, out)) return -14;
                }
                if (si.si_pid && (si.si_code == CLD_EXITED || si.si_code == CLD_KILLED
                                  || si.si_code == CLD_DUMPED)) {
                    const auto g = pids_.guest_of(si.si_pid);
                    if (g > 0 && !nowait) {
                        int st = 0;
                        ::waitpid(si.si_pid, &st, 0);        // actually reap
                        pids_.release(g);
                        std::erase_if(children_,
                                      [&](const Child& c) { return c.host == si.si_pid; });
                    }
                }
                return 0;
            }

            // -- Queued signals. rt_sigqueueinfo(pid, sig, info*) carries
            //    si_code (SI_QUEUE, -1) and a value; they travel in the
            //    target's mailbox with the signal, so the receiver's
            //    siginfo (sigwaitinfo, SA_SIGINFO, signalfd) shows them.
            case S::rt_sigqueueinfo: case S::rt_tgsigqueueinfo: {
                const bool tg = sc == S::rt_tgsigqueueinfo;
                const auto pid = static_cast<std::int32_t>(a0);       // tgid for the tg form
                const auto sig = static_cast<std::int32_t>(tg ? a2 : a1);
                const std::uint64_t ip = tg ? a3 : a2;
                struct { std::int32_t signo, errno_, code, pad_; std::int32_t pid, uid, value; } li{};
                if (!ram.get(ip, li)) return -14;
                if (li.code >= 0 && pid != tgid_) return -1;        // EPERM: only negative codes
                if (sig < 1 || sig > kLinuxNsig) return -22;
                if (pid == tgid_) {
                    g_pending.enqueue({sig, tgid_, li.code, li.value});
                    g_pending.kick_all(); g_pending.notify_waiters();
                    return 0;
                }
                const auto h = pids_.host_of(pid);
                if (!h) return -3;
                if (!pids_.post_signal(pid, {sig, tgid_, li.code, li.value})) return -11;
                if (pids_.ready(pid)) (void)::kill(*h, kKickSignal);
                return 0;
            }

            // -- rt_sigtimedwait(set, info, timeout, size): synchronous
            //    signal reception, how a program waits for SIGCHLD or a
            //    timer without a handler.
            case S::rt_sigtimedwait: {
                std::uint64_t set = 0;
                if (!ram.get(a0, set)) return -14;
                std::uint64_t deadline_ns = 0;
                const bool timed = a2 != 0;          // a {0,0} timeout POLLS: EAGAIN at once
                if (a2) {
                    struct { std::int64_t sec, nsec; } ts{};
                    if (!ram.get(a2, ts)) return -14;
                    deadline_ns = static_cast<std::uint64_t>(ts.sec) * 1'000'000'000ull
                                + static_cast<std::uint64_t>(ts.nsec);
                }
                const auto start = std::chrono::steady_clock::now();
                for (;;) {
                    drain_mail();
                    std::optional<PendingSignals::Info> got;
                    if (const std::uint64_t mine = task_.pending.load(std::memory_order_relaxed) & set) {
                        const int s = std::countr_zero(mine) + 1;
                        task_.pending.fetch_and(~sigbit(s), std::memory_order_relaxed);
                        got = PendingSignals::Info{s, 0, -6 /*SI_TKILL*/, 0};
                    } else {
                        got = g_pending.take(set);
                    }
                    if (got) {
                        if (a1) {
                            LinuxSiginfo si{};
                            si.si_signo = got->signo;
                            si.si_code = got->code;
                            si.si_pid = got->pid;
                            si.si_uid = static_cast<std::int32_t>(proc_.ids() ? proc_.ids()->uid : 0);
                            std::memcpy(si.rest, &got->value, sizeof got->value);   // si_value
                            if (!ram.put(a1, si)) return -14;
                        }
                        return got->signo;
                    }
                    if (timed) {
                        const auto spent = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now() - start).count();
                        if (static_cast<std::uint64_t>(spent) >= deadline_ns) return -11;  // EAGAIN
                    }
                    // Sleep until one of `set` -- or any signal the guest
                    // would take, which interrupts the wait (EINTR).
                    const std::uint64_t wake = set | ~task_.sig_mask;
                    if (timed) {
                        const auto spent = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now() - start).count());
                        g_pending.wait_for_signal(wake, deadline_ns > spent ? deadline_ns - spent : 0);
                    } else {
                        g_pending.wait_for_signal(wake);
                    }
                    drain_mail();
                    if ((g_pending.bits.load(std::memory_order_relaxed) & set) == 0 &&
                        (g_pending.bits.load(std::memory_order_relaxed) & ~task_.sig_mask) != 0)
                        return -4;                                                       // EINTR
                }
            }
            case S::get_robust_list:
                // The head is per-thread state we accept but never walk
                // (robust-list cleanup only matters when a thread dies
                // holding a lock). Report an empty list.
                if (a1 && !ram.put(a1, std::uint64_t{0})) return -14;
                if (a2 && !ram.put(a2, std::uint64_t{24})) return -14;   // sizeof head
                return 0;

            // -- Identity of the machine. The core owns the hostname (it is
            //    part of MachineSpec and uname reports it), so a guest may
            //    not change it out from under /proc.
            case S::sethostname: case S::setdomainname:
                return -1;                                   // EPERM
            case S::personality:
                // Only the default Linux personality exists here; a guest
                // asking for it back gets 0, asking to CHANGE it gets EINVAL
                // rather than a silent lie.
                return (a0 == 0 || a0 == 0xffffffff) ? 0 : -22;
            case S::capset:
                return 0;                                    // uid 0 holds everything
            case S::restart_syscall:
                // Only the kernel issues this, after a signal interrupted a
                // restartable call. We complete calls before delivering, so
                // it can only arrive spuriously.
                return -4;                                   // EINTR
            case S::vhangup: case S::reboot:
                return -1;                                   // EPERM
            case S::syslog:
                // klogctl: there is no kernel ring buffer to read.
                return a0 == 9 || a0 == 10 ? 0 : -1;         // size queries -> 0
            case S::adjtimex: case S::clock_adjtime:
                return -1;                                   // EPERM: not our clock
            case S::ioprio_get:
                return 4 << 13;                              // IOPRIO_CLASS_BE, level 4
            case S::ioprio_set:
                return 0;
            case S::sched_rr_get_interval: {
                struct { std::int64_t sec, nsec; } ts{0, 10'000'000};   // 10 ms
                return ram.put(a1, ts) ? 0 : -14;
            }
            case S::sched_getattr: case S::sched_setattr:
                // The extended scheduler interface; SCHED_OTHER with no
                // deadline parameters is all this backend offers, and
                // sched_getscheduler already reports that.
                return sc == S::sched_setattr ? 0 : -22;
            case S::kcmp:
                // Compare two processes' resources. Only KCMP_FILE is used in
                // practice (by sandboxes checking fd identity); without the
                // other process's table we cannot answer, and a WRONG answer
                // is worse than a refusal.
                return -38;

            // -- Scheduling. Guest threads are host threads, so the honest
            //    answer for every query comes from the host.
            case S::sched_setaffinity: {
                // Darwin has no hard CPU pinning; XNU places threads itself.
                // The mask is still the guest's: kept per task in the shared
                // table, it reads back, is inherited, and applies by pid.
                const auto pid = static_cast<std::int32_t>(a0);
                const std::int32_t t = pid ? pid : task_.tid;
                if (pid && !pids_.host_of(t)) return -3;              // ESRCH
                std::uint64_t m = 0;
                auto win = ram.at(a2, std::min<std::uint64_t>(a1, 8));
                if (win.empty() && a1) return -14;
                std::memcpy(&m, win.data(), win.size());
                const long ncpu = std::max(1L, ::sysconf(_SC_NPROCESSORS_ONLN));
                const std::uint64_t all = ncpu >= 64 ? ~0ull : (1ull << ncpu) - 1;
                m &= all;
                if (!m) return -22;                                   // EINVAL: no CPU
                pids_.set_affinity(t, m == all ? 0 : m);
                return 0;
            }
            // Policies: SCHED_OTHER(0), BATCH(3) and IDLE(5) take priority 0
            // and are the guest's to choose; FIFO(1)/RR(2) take 1..99 and
            // need CAP_SYS_NICE, which root has -- XNU won't run them, but
            // the guest sees what it set. Kept per task, tree-wide.
            case S::sched_getscheduler: {
                const auto pid = static_cast<std::int32_t>(a0);
                if (static_cast<std::int64_t>(a0) < 0) return -22;
                const std::int32_t t = pid ? pid : task_.tid;
                if (pid && !pids_.host_of(t)) return -3;
                return pids_.policy_of(t) & 0x7f;
            }
            case S::sched_setscheduler: case S::sched_setparam: {
                const auto pid = static_cast<std::int32_t>(a0);
                if (static_cast<std::int64_t>(a0) < 0) return -22;
                const std::int32_t t = pid ? pid : task_.tid;
                if (pid && !pids_.host_of(t)) return -3;
                const std::uint64_t pp = sc == S::sched_setscheduler ? a2 : a1;
                std::int32_t prio = 0;
                if (!pp || !ram.get(pp, prio)) return pp ? -14 : -22;
                const int pol = sc == S::sched_setscheduler
                    ? static_cast<int>(a1 & ~0x40000000ull)            // minus SCHED_RESET_ON_FORK
                    : (pids_.policy_of(t) & 0x7f);
                const bool rt = pol == 1 || pol == 2;
                if (pol != 0 && pol != 1 && pol != 2 && pol != 3 && pol != 5) return -22;
                if (rt ? (prio < 1 || prio > 99) : prio != 0) return -22;
                if (rt) {
                    const auto ids = proc_.ids();
                    if (ids && ids->euid != 0) return -1;              // EPERM
                }
                pids_.set_policy(t, pol);
                rt_prio_[t] = rt ? prio : 0;
                return 0;
            }
            case S::sched_getparam: {
                const auto pid = static_cast<std::int32_t>(a0);
                const std::int32_t t = pid ? pid : task_.tid;
                if (pid && !pids_.host_of(t)) return -3;
                const auto it = rt_prio_.find(t);
                return ram.put(a1, std::int32_t{it == rt_prio_.end() ? 0 : it->second}) ? 0 : -14;
            }
            case S::sched_get_priority_max: case S::sched_get_priority_min:
                // SCHED_FIFO/RR (1/2) span 1..99 on Linux; SCHED_OTHER is 0.
                return (a0 == 1 || a0 == 2) ? (sc == S::sched_get_priority_max ? 99 : 1) : 0;
            case S::getcpu: {
                // getcpu(cpu*, node*, cache*). Report the core this host
                // thread is on right now -- what the guest is actually doing.
                if (a0 && !ram.put(a0, std::uint32_t{current_cpu()})) return -14;
                if (a1 && !ram.put(a1, std::uint32_t{0})) return -14;   // one NUMA node
                return 0;
            }

            // -- prctl(option, ...). A grab-bag; these are the options real
            //    programs depend on.
            case S::prctl: {
                constexpr std::uint64_t kSetName = 15, kGetName = 16,
                                        kSetNoNewPrivs = 38, kGetNoNewPrivs = 39,
                                        kSetDumpable = 4, kGetDumpable = 3,
                                        kSetPdeathsig = 1, kGetPdeathsig = 2,
                                        kSetSeccomp = 22, kGetSeccomp = 21,
                                        kCapbsetRead = 23, kSetChildSubreaper = 36;
                switch (a0) {
                    case kSetName: {
                        // The thread name; /proc/self/comm reads it back.
                        auto name = ram.cstr(a1, 16);
                        ::pthread_setname_np(name.c_str());
                        return 0;
                    }
                    case kGetName: {
                        char buf[16]{};
                        ::pthread_getname_np(::pthread_self(), buf, sizeof buf);
                        auto win = ram.at(a1, sizeof buf);
                        if (win.empty()) return -14;
                        std::memcpy(win.data(), buf, sizeof buf);
                        return 0;
                    }
                    // PR_SET_NO_NEW_PRIVS is a one-way latch that only
                    // RESTRICTS: nothing in linuxity's world grants
                    // privilege anyway (there is no setuid execution), so
                    // honouring it is exact, not a pretence. pacman 7's
                    // download sandbox sets it and aborts if it fails --
                    // which is why `pacman -Sy` died here.
                    case kSetNoNewPrivs:
                        no_new_privs_ = a1 != 0;
                        return 0;
                    case kGetNoNewPrivs:
                        return no_new_privs_ ? 1 : 0;
                    case kSetDumpable: case kGetDumpable:
                        return a0 == kGetDumpable ? 1 : 0;
                    case kSetPdeathsig:
                        // The signal to send this process when its parent
                        // dies. Recorded; nothing to arm on Darwin, and a
                        // guest that relies on it for cleanup is no worse
                        // off than on a kernel that delivered it late.
                        pdeathsig_ = static_cast<int>(a1);
                        return 0;
                    case kGetPdeathsig:
                        return ram.put(a1, std::int32_t{pdeathsig_}) ? 0 : -14;
                    case kSetSeccomp:
                        return 0;               // see S::seccomp below
                    case kGetSeccomp:
                        return seccomp_mode_;
                    case kCapbsetRead:
                        return 1;               // uid 0: every bound capability
                    case kSetChildSubreaper:
                        return 0;
                    default:
                        // An unknown prctl is EINVAL, not ENOSYS: the
                        // SYSCALL exists, the option doesn't. libc branches
                        // on exactly that difference.
                        return -22;
                }
            }

            // -- seccomp(op, flags, args). linuxity is not a sandbox (see
            //    doc/ROADMAP.md): a filter is ACCEPTED and not enforced,
            //    which is the same contract as the Linux ptrace backend.
            //    The alternative is worse than useless -- pacman, systemd,
            //    OpenSSH and Chrome all treat a seccomp failure as fatal,
            //    so ENOSYS turns "no extra hardening" into "cannot run".
            case S::seccomp: {
                constexpr std::uint64_t kSetModeStrict = 0,
                                        kSetModeFilter = 1,
                                        kGetActionAvail = 2;
                switch (a0) {
                    case kSetModeStrict: seccomp_mode_ = 1; return 0;
                    case kSetModeFilter: seccomp_mode_ = 2; return 0;
                    case kGetActionAvail: return 0;    // every action "available"
                    default: return -22;
                }
            }

            // -- capget/capset: uid 0 holds everything, and nothing here
            //    drops privilege, so report a full set.
            case S::capget: {
                struct CapData { std::uint32_t effective, permitted, inheritable; };
                if (a1) {
                    const CapData full{~0u, ~0u, ~0u};
                    const CapData sets[2] = {full, full};   // two 32-bit chunks
                    if (!ram.put(a1, sets)) return -14;
                }
                return 0;
            }

            // (Credentials -- set*id, setgroups -- are the portable
            //  dispatcher's: abi/creds.hpp's rules over per-process state.)

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

public:
    // Write back and forget EVERY shared file mapping: the address space is
    // going away (exec, exit) and the guest's stores must not go with it.
    void sync_all_shared() { sync_shared(0, ~std::uint64_t{0} >> 1, /*drop=*/true); }

    // The ONE way this process ends, from exit_group or the end of the
    // main loop: every thread stops (Linux does not wait for them, and one
    // blocked in a host call can't be kicked), shared mappings reach their
    // files, the embedder's exit hooks run (zygote VM budget), stdio
    // flushes, and _exit. Never returns.
    using ExitHook = std::function<void()>;
    void on_exit(ExitHook h) { exit_hooks_.push_back(std::move(h)); }
    [[noreturn]] void end_process(int status) {
        proc_.request_group_exit(status);
        sync_all_shared();
        for (auto& h : exit_hooks_) h();
        std::fflush(nullptr);
        ::_exit(status);
    }
private:

    // Write the shared file mappings overlapping [at, at+len) back to their
    // files; with `drop`, the range is going away, so forget the covered
    // mappings (a partial unmap keeps the rest registered). The ONE place a
    // MAP_SHARED store reaches its file: munmap, MAP_FIXED, msync, exit.
    void sync_shared(std::uint64_t at, std::uint64_t len, bool drop) {
        struct Job { std::uint64_t from, n; int fd; std::int64_t off; bool close; };
        std::vector<Job> jobs;
        proc_.with_shared_maps([&](auto& v) {
            for (auto it = v.begin(); it != v.end();) {
                const std::uint64_t lo = std::max(at, it->at);
                const std::uint64_t hi = std::min(at + len, it->at + it->len);
                if (lo >= hi) { ++it; continue; }
                const bool whole = drop && lo <= it->at && hi >= it->at + it->len;
                jobs.push_back({lo, hi - lo, it->fd,
                                it->off + static_cast<std::int64_t>(lo - it->at), whole});
                if (whole) { it = v.erase(it); continue; }
                if (drop && lo == it->at) {           // unmapped a head
                    it->off += static_cast<std::int64_t>(hi - it->at);
                    it->len -= hi - it->at;
                    it->at = hi;
                } else if (drop && hi == it->at + it->len) {   // ... a tail
                    it->len = lo - it->at;
                }
                ++it;
            }
            return 0;
        });
        const auto ram = machine_.ram();
        for (const Job& j : jobs) {
            // Never write past the file's end: the mapping can be longer
            // than the file (its tail reads as zeros and does not exist).
            struct ::stat st{};
            std::uint64_t n = j.n;
            if (::fstat(j.fd, &st) == 0) {
                const auto size = static_cast<std::int64_t>(st.st_size);
                n = j.off >= size ? 0 : std::min<std::uint64_t>(n, static_cast<std::uint64_t>(size - j.off));
            }
            const auto win = n ? ram.at(j.from, n) : decltype(ram.at(0, 0)){};
            for (std::uint64_t done = 0; done < win.size();) {
                const ::ssize_t w = ::pwrite(j.fd, win.data() + done, win.size() - done,
                                             static_cast<off_t>(j.off) + static_cast<off_t>(done));
                if (w <= 0) break;
                done += static_cast<std::uint64_t>(w);
            }
            if (j.close) ::close(j.fd);
        }
    }

    // -- Page protection in the guest's own page tables ----------------------
    // The stage-1 tables start RWX everywhere guest-visible; mmap/mprotect
    // narrow ranges (HvfMachine::protect) and munmap puts them back. The
    // touched window rides through fork (the tables are in the snapshot)
    // and is reset at exec, so a new image starts from the default.
    void set_pte_prot(std::uint64_t at, std::uint64_t len, GuestProt p) {
        if (!len) return;
        machine_.protect(at, len, has(p, GuestProt::read) || has(p, GuestProt::write),
                         has(p, GuestProt::write), has(p, GuestProt::exec));
        proc_.pte_lo = std::min(proc_.pte_lo, at);
        proc_.pte_hi = std::max(proc_.pte_hi, at + len);
        // Other threads may hold old translations: the stub's tlbi is
        // broadcast (inner-shareable), so this vCPU running it before the
        // syscall returns drops them for every vCPU of the VM.
        cpu_.flush_tlb_on_entry();
    }
    // A file this process maps shared changed size (truncate/ftruncate).
    // The host maps whole 16 KiB pages, so a page of the file that is now
    // past EOF but shares a host page with one that isn't still reads as
    // zeros on the host -- where Linux, with 4 KiB pages, raises SIGBUS. So
    // the GUEST's page tables say what the file can back: no access past
    // EOF (the abort becomes SIGBUS in report_fault, see past_file_end),
    // the mapping's own protection where it grew back.
    void file_resized(int fd) {
        struct ::stat fs{};
        if (::fstat(fd, &fs) != 0) return;
        const auto size = static_cast<std::uint64_t>(fs.st_size);
        std::vector<std::pair<std::uint64_t, std::uint64_t>> dead, live;
        proc_.with_backings([&](auto& v) {
            for (const auto& b : v) {
                struct ::stat bs{};
                if (::fstat(b.fd, &bs) != 0 || bs.st_ino != fs.st_ino || bs.st_dev != fs.st_dev) continue;
                const auto off = static_cast<std::uint64_t>(b.off);
                // first guest page of the mapping that starts at or past EOF
                const std::uint64_t cut = size <= off ? 0
                    : std::min<std::uint64_t>(b.len, AddressSpace::page_up(size - off));
                if (cut < b.len) dead.emplace_back(b.at + cut, b.len - cut);
                if (cut) live.emplace_back(b.at, cut);
            }
            return 0;
        });
        for (const auto& [at, n] : dead) set_pte_prot(at, n, GuestProt::none);
        for (const auto& [at, n] : live) {
            const Vma* v = proc_.with_space([&](AddressSpace& t) { return t.find(at); });
            if (v) set_pte_prot(at, n, v->prot);
        }
    }
    void reset_pte_prot(std::uint64_t at, std::uint64_t len) {
        if (!len || proc_.pte_hi <= proc_.pte_lo) return;      // nothing narrowed yet
        machine_.protect(at, len, true, true, true);
        cpu_.flush_tlb_on_entry();
    }
    // -- memfd seals ---------------------------------------------------------
    // A write a seal forbids is EPERM. Only memfds carry seals, and checking
    // is a host xattr read, so it runs only once this process has seen one
    // (created, inherited or received: an unlinked regular file is the
    // cheap tell, and a memfd is always unlinked).
    [[nodiscard]] std::int64_t seal_denies(int h, std::int64_t at, std::size_t n) {
        if (!memfds_) {
            struct ::stat st{};
            if (::fstat(h, &st) != 0 || st.st_nlink != 0 || !S_ISREG(st.st_mode)) return 0;
            memfds_ = true;
        }
        const auto s = memfd_seals(h);
        if (!s) return 0;
        if (*s & (kSealWrite | kSealFutureWrite)) return -1;          // EPERM
        if ((*s & kSealGrow) && n) {
            struct ::stat st{};
            (void)::fstat(h, &st);
            const std::int64_t from = at >= 0 ? at : ::lseek(h, 0, SEEK_CUR);
            if (from + static_cast<std::int64_t>(n) > st.st_size) return -1;
        }
        return 0;
    }

    // -- Real shared pages ---------------------------------------------------
    // Drop the shared backings inside [at, at+len): the guest range goes back
    // to private zero memory (munmap, MAP_FIXED over it, exec). A backing
    // only PARTLY covered stays shared whole: its host pages are bigger
    // than the guest's, and the guest still maps the rest of them.
    void drop_backings(std::uint64_t at, std::uint64_t len) {
        std::vector<ProcessState::Backing> gone;
        proc_.with_backings([&](auto& v) {
            for (auto it = v.begin(); it != v.end();) {
                if (it->at < at || it->at + it->len > at + len) { ++it; continue; }
                gone.push_back(*it);
                it = v.erase(it);
            }
            return 0;
        });
        for (const auto& b : gone) {
            (void)machine_.back_shared(b.at, b.len, -1, 0);
            ::close(b.fd);
        }
    }
    // Back [at, at+len) with `fd` at `off`, shared, and remember it. The
    // backing takes its own reference to the object.
    [[nodiscard]] bool add_backing(std::uint64_t at, std::uint64_t len, int fd, std::int64_t off) {
        const int own = ::fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (own < 0) return false;
        if (!machine_.back_shared(at, len, own, off)) { ::close(own); return false; }
        proc_.with_backings([&](auto& v) { v.push_back({at, len, own, off}); return 0; });
        return true;
    }
    // A fresh object for MAP_SHARED|MAP_ANONYMOUS: an unlinked shm object
    // of `len` bytes. Fork children map the same one, so the memory is
    // shared the way Linux shares it (and not merely copied at fork).
    [[nodiscard]] static int anon_shared_object(std::uint64_t len) {
        static std::atomic<unsigned> seq{0};
        char name[64];
        std::snprintf(name, sizeof name, "/lx%d.%u", ::getpid(), seq.fetch_add(1));
        const int fd = ::shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd < 0) return -1;
        ::shm_unlink(name);
        if (::ftruncate(fd, static_cast<off_t>(len)) < 0) { ::close(fd); return -1; }
        return fd;
    }

    [[nodiscard]] Maybe do_memory(abi::Sysno sc) {
        using S = abi::Sysno;
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1),
                            a2 = regs_.arg(2), a3 = regs_.arg(3);
        switch (sc) {
            case S::brk: {
                // Pages the break newly covers must read as zero, as fresh
                // kernel pages do: glibc's calloc skips clearing memory that
                // just came from sbrk. Guest RAM here is one flat region that
                // outlives exec and is copied on fork, so the bytes above the
                // old break were the PREVIOUS image's heap -- apt's http method
                // built libtasn1 trees out of apt-get's leftover strings and
                // crashed on every download.
                std::uint64_t before = 0, now = 0;
                proc_.with_space([&](AddressSpace& t) {
                    before = t.set_brk(0);
                    now = t.set_brk(a0);
                    return 0;
                });
                const std::uint64_t lo = AddressSpace::page_up(before), hi = AddressSpace::page_up(now);
                if (hi > lo) machine_.zero(lo, hi - lo);
                return static_cast<std::int64_t>(now);
            }
            case S::mmap: {
                // Guest MAP_* bits come from abi/wire/mmap.hpp. These used to be
                // redeclared inline right here (`kFixed = 0x10, kAnon = 0x20`),
                // which is how a constant ends up with no single place to fix.
                const bool anon = abi::wire::is_anonymous(a3);
                const std::uint64_t len = AddressSpace::page_up(a1);
                // MAP_FIXED_NOREPLACE: the address is pinned, but an overlap
                // is EEXIST -- it must never replace what is there.
                if (abi::wire::fixed_must_not_replace(a3)) {
                    if (a0 & (AddressSpace::kPageSize - 1)) return -22;
                    const bool used = proc_.with_space([&](AddressSpace& t) {
                        for (const Vma& v : t.vmas())
                            if (v.begin < a0 + len && v.end > a0) return true;
                        return false;
                    });
                    if (used) return -17;                          // EEXIST
                }
                // A MAP_FIXED map replaces whatever was there: a shared file
                // map it covers must reach its file first.
                if (abi::wire::wants_fixed(a3)) {
                    sync_shared(a0, len, /*drop=*/true);
                    drop_backings(a0, len);
                }
                const bool shared = abi::wire::has_map(a3, abi::wire::MapFlag::shared);
                const std::uint64_t hp = HvfMachine::host_page();
                // A shared map gets REAL shared pages, which the host only
                // has at its own page size: place it on a host page, and
                // round its span up (the tail is the object's, unseen).
                const bool host_shared = shared && (anon || (regs_.arg(5) % hp) == 0) &&
                                         (!abi::wire::wants_fixed(a3) || a0 % hp == 0);
                const std::uint64_t span = host_shared ? (len + hp - 1) / hp * hp : len;
                std::uint64_t at = proc_.with_space([&](AddressSpace& t) { return t.map(a0, host_shared ? span : a1, prot_from_linux(a2),
                                           abi::wire::wants_fixed(a3), anon,
                                           host_shared ? hp : AddressSpace::kPageSize); });
                if (at == AddressSpace::kFail) return -12;          // ENOMEM
                {
                    // the new range's permissions, enforced (the range may
                    // also carry a narrower one from an earlier mapping)
                    const GuestProt np = prot_from_linux(a2);
                    const GuestProt rwx = GuestProt::read | GuestProt::write | GuestProt::exec;
                    if (np != rwx) set_pte_prot(at, span, np);
                    else reset_pte_prot(at, span);
                }
                // (a shared map's host-page tail is part of its VMA: what
                // lies past the object's end faults there, as past EOF)
                proc_.unname(at, at + len);
                auto win = machine_.ram().at(at, len);
                if (win.empty()) return -12;

                if (anon) {
                    if (host_shared) {
                        const int obj = anon_shared_object(span);
                        const bool ok = obj >= 0 && add_backing(at, span, obj, 0);
                        if (obj >= 0) ::close(obj);
                        if (ok) {
                            proc_.name(at, at + len, "/dev/zero (deleted)");
                            return static_cast<std::int64_t>(at);
                        }
                    }
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
                if (shared) {
                    // A shared WRITABLE map needs a writable file (EACCES),
                    // and a memfd sealed against writing refuses it (EPERM).
                    const int fl = ::fcntl(ffd, F_GETFL);
                    if (abi::wire::has_prot(a2, abi::wire::Prot::write) && fl >= 0 &&
                        (fl & O_ACCMODE) == O_RDONLY) return -13;
                    if (abi::wire::has_prot(a2, abi::wire::Prot::write) && memfds_)
                        if (const auto s = memfd_seals(ffd); s && (*s & (kSealWrite | kSealFutureWrite)))
                            return -1;
                }
                if (char fp[PATH_MAX]; ::fcntl(ffd, F_GETPATH, fp) == 0)
                    proc_.name(at, at + len, unresolve_ ? unresolve_(fp) : std::string{fp});
                if (host_shared) {
                    // The file's own pages: coherent with read()/write() and
                    // every other process mapping it -- and with another
                    // mapping of it here (a JIT's RW view and RX view). Past
                    // EOF the host faults; the guest sees that as SIGBUS.
                    if (add_backing(at, span, ffd, foff)) {
                        if (has(prot_from_linux(a2), GuestProt::exec)) machine_.publish_code(at, span);
                        return static_cast<std::int64_t>(at);
                    }
                }
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
                // Writable and shared: remember it, so the guest's stores
                // are written back to the file (see ProcessState::SharedMap).
                if (abi::wire::has_map(a3, abi::wire::MapFlag::shared) &&
                    abi::wire::has_prot(a2, abi::wire::Prot::write)) {
                    const int own = ::fcntl(ffd, F_DUPFD_CLOEXEC, 3);
                    if (own >= 0)
                        proc_.with_shared_maps([&](auto& v) {
                            v.push_back({at, a1, own, static_cast<std::int64_t>(foff)});
                            return 0;
                        });
                }
                return static_cast<std::int64_t>(at);
            }
            case S::munmap: {
                std::uint64_t len = AddressSpace::page_up(a1);
                proc_.lock_pages(a0, len, false);        // unmapped memory isn't locked
                // A shared map's VMA spans whole host pages; unmapping the
                // part the guest asked for (its own length) releases them all.
                proc_.with_backings([&](auto& v) {
                    for (const auto& b : v)
                        if (b.at == a0 && b.len > len && b.len - len < HvfMachine::host_page()) len = b.len;
                    return 0;
                });
                sync_shared(a0, len, /*drop=*/true);
                drop_backings(a0, len);
                proc_.with_space([&](AddressSpace& t) { return t.unmap(a0, len); });
                proc_.unname(a0, a0 + len);
                reset_pte_prot(a0, len);
                return 0;
            }
            case S::mprotect: {
                // ENFORCED: the VMA map records it (/proc/self/maps) and the
                // guest's stage-1 entries carry it (AP/UXN), so a write to a
                // read-only page, any touch of PROT_NONE and a jump into
                // non-executable memory fault -- SIGSEGV, as on Linux. Code
                // flipped to executable is published to the I-cache.
                if (a0 % AddressSpace::kPageSize) return -22;
                const GuestProt p = prot_from_linux(a2);
                if (!proc_.with_space([&](AddressSpace& t) { return t.protect(a0, a1, p); })) return -12;
                set_pte_prot(a0, AddressSpace::page_up(a1), p);
                if (has(p, GuestProt::exec)) machine_.publish_code(a0, AddressSpace::page_up(a1));
                return 0;
            }
            // -- mlock family. Guest RAM is a single host mapping that
            //    linuxity already keeps resident, so locking a guest range
            //    means locking the host pages behind it -- which is exactly
            //    what a caller like gpg-agent wants (key material that can't
            //    be paged out). If the host refuses (RLIMIT_MEMLOCK), report
            //    ENOMEM/EPERM as Linux would, never ENOSYS: gpg treats ENOSYS
            //    as "this kernel can't protect memory" and degrades silently.
            case S::mlock: case S::munlock: case S::mlock2: {
                auto win = machine_.ram().clamp(a0, a1);
                if (win.empty() && a1) return -12;               // ENOMEM: unmapped
                const int rc = sc == S::munlock ? ::munlock(win.data(), win.size())
                                                : ::mlock(win.data(), win.size());
                if (rc < 0) return darwin::fail();
                proc_.lock_pages(a0, a1, sc != S::munlock);
                return 0;
            }
            case S::mlockall: case S::munlockall:
                // The whole guest is one mapping; locking all of it would pin
                // every byte of guest RAM. Accept: Linux grants mlockall to
                // root, and pinning is an optimisation the guest can't observe.
                return 0;
            case S::mincore: {
                // mincore(addr, len, vec): one byte per page, bit 0 =
                // resident. Guest RAM is a live host mapping, so ask the host.
                const std::uint64_t pages = AddressSpace::page_up(a1) / AddressSpace::kPageSize;
                auto vec = machine_.ram().clamp(a2, pages);
                if (vec.empty() && pages) return -14;
                if (!proc_.with_space([&](AddressSpace& sp) { return sp.find(a0) != nullptr; }))
                    return -12;                                  // ENOMEM: not mapped
                std::memset(vec.data(), 1, vec.size());          // resident
                return 0;
            }
            case S::msync: {
                // msync(addr, len, flags): write a shared file mapping's
                // pages back to its file (they live in guest RAM, not in the
                // host's page cache). Validate the range like Linux.
                if (a0 % AddressSpace::kPageSize) return -22;    // EINVAL
                if (!proc_.with_space([&](AddressSpace& sp) { return sp.find(a0) != nullptr; }))
                    return -12;
                sync_shared(a0, AddressSpace::page_up(a1), /*drop=*/false);
                return 0;
            }
            case S::madvise: {
                // Only MADV_DONTNEED changes visible state: anonymous pages
                // must read back as zero afterwards. glibc's malloc relies
                // on it when trimming. Every other advice is a hint.
                constexpr std::uint64_t kDontNeed = 4;
                if (a2 == kDontNeed) {
                    const Vma* v = proc_.with_space([&](AddressSpace& t) { return t.find(a0); });
                    // (a shared object keeps its contents: DONTNEED only
                    // drops OUR view of them, which then reads them back)
                    const bool backed = proc_.with_backings([&](auto& bv) {
                        for (const auto& b : bv) if (a0 >= b.at && a0 < b.at + b.len) return true;
                        return false;
                    });
                    if (v && v->anonymous && !backed) machine_.zero(a0, AddressSpace::page_up(a1));
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
                    reset_pte_prot(a0 + new_len, old_len - new_len);
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
                reset_pte_prot(a0, old_len);
                set_pte_prot(to, new_len, prot);
                return static_cast<std::int64_t>(to);
            }
            default:
                return std::nullopt;
        }
    }

    // One eventfd read or write (see do_io). The pipe holds the counter as
    // a run of 8-byte deltas; reading drains them into one sum.
    [[nodiscard]] std::int64_t eventfd_io(const FdTable::EventFdEnds& ev, bool reading,
                                          std::uint64_t buf, std::uint64_t len) {
        const GuestRam ram = machine_.ram();
        if (len < 8) return -22;                                         // EINVAL
        if (!reading) {
            std::uint64_t add = 0;
            if (!ram.get(buf, add)) return -14;
            if (add == ~std::uint64_t{0}) return -22;
            if (add == 0) return 8;
            return ::write(ev.write, &add, sizeof add) < 0 ? darwin::fail() : 8;
        }
        // Block (or EAGAIN) until there is a delta, like the pipe would.
        std::uint64_t first = 0;
        const ::ssize_t n = ::read(ev.read, &first, sizeof first);
        if (n < 0) return darwin::fail();
        if (n != 8) return -5;
        const int fl = ::fcntl(ev.read, F_GETFL);
        (void)::fcntl(ev.read, F_SETFL, fl | O_NONBLOCK);
        std::uint64_t sum = first, d = 0;
        while (::read(ev.read, &d, sizeof d) == 8) sum += d;
        std::uint64_t give = sum;
        if (ev.semaphore) {
            give = 1;
            const std::uint64_t rest = sum - 1;
            if (rest) (void)::write(ev.write, &rest, sizeof rest);
        }
        (void)::fcntl(ev.read, F_SETFL, fl);
        return ram.put(buf, give) ? 8 : -14;
    }

    [[nodiscard]] Maybe do_io(abi::Sysno sc) {
        using S = abi::Sysno;
        const auto gfd = static_cast<int>(regs_.arg(0));
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1),
                            a2 = regs_.arg(2), a3 = regs_.arg(3);
        const GuestRam ram = machine_.ram();

        // fd-table operations first: they don't need a resolved host fd.
        switch (sc) {
            case S::close: {
                dirs_.erase(gfd);                  // drop any directory stream
                epolls_.erase(gfd);                // and any epoll set
                const int rc = proc_.with_fds([&](FdTable& t) { return t.close(gfd); });
                // A pumped listener whose last guest fd just went: stop the
                // pump, refusing what it still holds (as Linux would).
                if (proc_.has_pumps())
                    proc_.with_pumps([&](ProcessState::Pumps& m) {
                        for (auto it = m.begin(); it != m.end();)
                            it = it->second->serves(it->first) ? std::next(it) : m.erase(it);
                        proc_.note_pumps(!m.empty());
                        return 0;
                    });
                return rc;
            }
            case S::dup:   return proc_.with_fds([&](FdTable& t) { return t.dup(gfd, std::nullopt, false); });
            case S::dup3: {
                if (static_cast<int>(a1) == gfd) return -22;          // EINVAL
                return proc_.with_fds([&](FdTable& t) { return t.dup(gfd, static_cast<int>(a1), (a2 & abi::wire::kOCloexec) != 0); });
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
                int p[2];
                if (::pipe(p) < 0) return darwin::fail();
                for (int e : p) {
                    ::fcntl(e, F_SETFD, FD_CLOEXEC);
                    if (a1 & abi::wire::kONonblock)
                        ::fcntl(e, F_SETFL, ::fcntl(e, F_GETFL) | O_NONBLOCK);
                }
                // One guest fd, both pipe ends: a read drains, a write
                // signals. The write end is kept alive by the EventFd record
                // so the read end never sees EOF.
                const int g = proc_.with_fds([&](FdTable& t) {
                    return t.install_eventfd(p[0], p[1], (a1 & abi::wire::kOCloexec) != 0,
                                             (a1 & 1u) /*EFD_SEMAPHORE*/ ? HostFd::Kind::eventfd_sem
                                                                        : HostFd::Kind::eventfd);
                });
                if (g < 0) { ::close(p[0]); ::close(p[1]); return -24; }
                if (a0) {
                    const std::uint64_t init = a0;
                    (void)::write(p[1], &init, sizeof init);
                }
                return g;
            }
            case S::sync:  ::sync(); return 0;

            // -- Kernel objects that are file descriptors. Linux exposes a
            //    lot of state as "an fd you can poll"; Darwin has the same
            //    capabilities in other shapes. See hvf_fdobj.hpp.
            case S::memfd_create: {
                // An anonymous, growable, mappable file. Used for shared
                // buffers and for passing an fd instead of a path.
                const std::string name = ram.cstr(a0, 251);
                if (name.size() > 249) return -22;                    // EINVAL: name too long
                if (a1 & ~0x7ull) return -22;                         // CLOEXEC|ALLOW_SEALING|HUGETLB
                const int h = make_memfd(name, (a1 & 2) != 0);       // MFD_ALLOW_SEALING
                memfds_ = true;
                if (h < 0) return darwin::fail();
                // MFD_CLOEXEC is 1, NOT O_CLOEXEC's 0x80000. memfd_create has
                // its own tiny flag space; using the open-flag bit here
                // silently fails to set close-on-exec and the fd leaks
                // through every later exec.
                return install_or_close(h, (a1 & abi::wire::kMfdCloexec) != 0);
            }
            case S::memfd_secret:
                // Memory no other process (not even the kernel) can map.
                // Darwin has no equivalent, and faking it would be a LIE
                // about a security property, so refuse as a kernel without
                // the feature does.
                return -38;
            case S::timerfd_create: {
                // A timer you can poll. The expiration count is delivered
                // through a pipe fed by the process timer wheel.
                int p[2];
                if (::pipe(p) < 0) return darwin::fail();
                for (int e : p) ::fcntl(e, F_SETFD, FD_CLOEXEC);
                if (a1 & abi::wire::kONonblock)
                    ::fcntl(p[0], F_SETFL, ::fcntl(p[0], F_GETFL) | O_NONBLOCK);
                const int g = proc_.with_fds([&](FdTable& t) {
                    return t.install_eventfd(p[0], p[1], (a1 & 1) != 0);
                });
                if (g < 0) { ::close(p[0]); ::close(p[1]); return -24; }
                // Each fire writes one u64 to the pipe, so a read yields the
                // count exactly as timerfd promises.
                const int write_end = p[1];
                timerfds_[g] = timers_.create(0, kSigevNone);
                timers_.set_notifier(timerfds_[g], [write_end] {
                    const std::uint64_t one = 1;
                    (void)::write(write_end, &one, sizeof one);
                });
                return g;
            }
            case S::timerfd_settime: {
                auto it = timerfds_.find(gfd);
                if (it == timerfds_.end()) return -22;
                constexpr std::uint64_t kAbstime = 1;        // TFD_TIMER_ABSTIME
                LinuxItimerspec v{};
                if (a2 && !ram.get(a2, v)) return -14;
                TimerSet::Interval next{
                    std::chrono::seconds{v.value.sec} + std::chrono::nanoseconds{v.value.nsec},
                    std::chrono::seconds{v.interval.sec} + std::chrono::nanoseconds{v.interval.nsec}};
                const auto prev = timers_.set_posix(it->second, next, (a1 & kAbstime) != 0);
                if (!prev) return -22;
                if (a3 && !ram.put(a3, to_itimerspec(*prev))) return -14;
                return 0;
            }
            case S::timerfd_gettime: {
                auto it = timerfds_.find(gfd);
                if (it == timerfds_.end()) return -22;
                const auto cur = timers_.get_posix(it->second);
                if (!cur) return -22;
                return ram.put(a1, to_itimerspec(*cur)) ? 0 : -14;
            }
            case S::signalfd4: {
                // Signals delivered as readable records, so a program can
                // select() on them instead of using a handler.
                std::uint64_t set = 0;
                if (a1 && !ram.get(a1, set)) return -14;
                if (gfd >= 0 && signalfds_.contains(gfd)) {   // re-arm an existing fd
                    signalfds_[gfd].mask = set;
                    return gfd;
                }
                int p[2];
                if (::pipe(p) < 0) return darwin::fail();
                for (int e : p) ::fcntl(e, F_SETFD, FD_CLOEXEC);
                if (a3 & abi::wire::kONonblock)
                    ::fcntl(p[0], F_SETFL, ::fcntl(p[0], F_GETFL) | O_NONBLOCK);
                const int g = proc_.with_fds([&](FdTable& t) {
                    return t.install_eventfd(p[0], p[1], (a3 & 1) != 0);
                });
                if (g < 0) { ::close(p[0]); ::close(p[1]); return -24; }
                signalfds_[g] = {set, p[1]};
                return g;
            }
            case S::inotify_init1: {
                if (!hub_) return -38;
                auto in = std::make_shared<InotifyFd>(*hub_);
                if (!in->valid()) return darwin::fail();
                const int rd = ::dup(in->read_end());        // the guest's pollable fd
                if (rd < 0) return darwin::fail();
                const auto g = install_or_close(rd, (a0 & 1) != 0);
                if (g < 0) return g;
                inotifies_[static_cast<int>(g)] = std::move(in);
                return g;
            }
            case S::inotify_add_watch: {
                auto it = inotifies_.find(gfd);
                if (it == inotifies_.end()) return -22;
                // The path arrives translated via the dispatcher's REDIRECT;
                // do_io has no path, so resolve it here.
                if (!resolve_) return -38;
                const std::string host = resolve_(ram.cstr(a1));
                if (host.empty()) return -2;
                const std::string guest = unresolve_ ? unresolve_(host) : ram.cstr(a1);
                return it->second->add_watch(guest, host, static_cast<std::uint32_t>(a2));
            }
            case S::inotify_rm_watch: {
                auto it = inotifies_.find(gfd);
                if (it == inotifies_.end()) return -22;
                return it->second->rm_watch(static_cast<int>(a1));
            }
            case S::pidfd_open: {
                auto h = pids_.host_of(static_cast<std::int32_t>(a0));
                if (!h) return -3;                           // ESRCH
                const int fd = make_pidfd(*h);
                if (fd < 0) return darwin::fail();
                const auto g = install_or_close(fd, true);
                if (g >= 0) pidfds_[static_cast<int>(g)] = static_cast<std::int32_t>(a0);
                return g;
            }
            case S::pidfd_send_signal: {
                auto it = pidfds_.find(gfd);
                if (it == pidfds_.end()) return -9;
                return deliver_signal(it->second, static_cast<std::int32_t>(a1));
            }
            case S::pidfd_getfd:
                // Steal an fd from another process's table. We would have to
                // reach into a sibling linuxity's FdTable; refuse rather
                // than hand back something that isn't that fd.
                return -38;
            case S::pipe2: {
                // pipe2(int fds[2], flags): a real Darwin pipe, installed
                // into the guest's table. Host ends are CLOEXEC regardless.
                int p[2];
                if (::pipe(p) < 0) return darwin::fail();
                for (int e : p) {
                    ::fcntl(e, F_SETFD, FD_CLOEXEC);
                    if (a1 & abi::wire::kONonblock)
                        ::fcntl(e, F_SETFL, ::fcntl(e, F_GETFL) | O_NONBLOCK);
                }
                const bool cx = (a1 & abi::wire::kOCloexec) != 0;
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
        // eventfd(2): a 64-bit counter over a pipe of 8-byte deltas. A read
        // takes the whole counter (or 1, under EFD_SEMAPHORE) and resets it
        // (or decrements it); a write adds; reads and writes of anything
        // but 8 bytes are EINVAL. The pipe gives poll/epoll and blocking for
        // free; the arithmetic is here. Passing the pipe's bytes straight
        // through made `write 5, write 7, read` return 5, not 12.
        if (sc == S::read || sc == S::write)
            if (const auto ev = proc_.with_fds([&](const FdTable& t) { return t.eventfd(gfd); }))
                return eventfd_io(*ev, sc == S::read, a1, a2);
        switch (sc) {
            case S::read: {
                if (!need_fd()) return -9;                          // EBADF
                auto win = ram.clamp(a1, a2);
                if (win.empty() && a2) return -14;                  // EFAULT
                // An inotify fd: records from linuxity's own fsnotify (see
                // InotifyFd); block like Linux unless the fd is nonblocking.
                // (A raw read on the kqueue would be ENXIO.)
                if (auto it = inotifies_.find(gfd); it != inotifies_.end()) {
                    const bool nb = (::fcntl(*hfd, F_GETFL) & O_NONBLOCK) != 0;
                    for (;;) {
                        const long n = it->second->drain(win);
                        if (n != 0) return n;                                  // records, or -EINVAL
                        if (nb) return -11;                                    // EAGAIN
                        pollfd p{*hfd, POLLIN, 0};
                        if (::poll(&p, 1, -1) < 0 && errno == EINTR) return -4;
                    }
                }
                auto n = ::read(*hfd, win.data(), win.size());
                return n < 0 ? darwin::fail() : n;
            }
            case S::write: {
                if (!need_fd()) return -9;
                auto win = ram.clamp(a1, a2);
                if (win.empty() && a2) return -14;
                if (const auto e = seal_denies(*hfd, 0, win.size())) return e;
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
                if (const auto e = seal_denies(*hfd, static_cast<std::int64_t>(a3), win.size())) return e;
                auto n = ::pwrite(*wfd, win.data(), win.size(), static_cast<off_t>(a3));
                return n < 0 ? darwin::fail() : n;
            }
            case S::readv: case S::writev:
                if (!need_fd()) return -9;
                return do_vector(sc == S::writev, sc == S::writev ? *wfd : *hfd, a1, a2);

            // -- Positional vectored I/O. preadv/pwritev take an offset;
            //    the v2 forms add a flags word whose bits (RWF_HIPRI,
            //    RWF_DSYNC, RWF_NOWAIT) are all hints we can honour by
            //    ignoring, except RWF_NOWAIT which we approximate by letting
            //    the fd's own O_NONBLOCK decide.
            case S::preadv: case S::pwritev:
            case S::preadv2: case S::pwritev2: {
                if (!need_fd()) return -9;
                const bool writing = sc == S::pwritev || sc == S::pwritev2;
                // The offset is split across two registers on 32-bit ABIs;
                // on both of ours it is a single argument.
                const auto off = static_cast<off_t>(a3);
                return do_vector_at(writing, writing ? *wfd : *hfd, a1, a2, off);
            }

            // -- sendfile(out, in, off*, count). A copy the kernel can do
            //    without bouncing through user space; Darwin's sendfile only
            //    works socket-bound, so use the same pread/pwrite loop as
            //    copy_file_range -- which is what Linux falls back to across
            //    filesystems anyway.
            case S::sendfile: {
                const int out = host_fd(gfd);
                const int in = host_fd(static_cast<int>(a1));
                if (out < 0 || in < 0) return -9;
                std::int64_t off = -1;
                if (a2) { std::int64_t v{}; if (!ram.get(a2, v)) return -14; off = v; }
                const std::int64_t moved = copy_between(in, out, off, -1, a3);
                if (moved < 0) return moved;
                if (a2 && !ram.put(a2, off + moved)) return -14;
                return moved;
            }

            // -- splice/tee/vmsplice: zero-copy pipe plumbing. The OBSERVABLE
            //    contract is "move N bytes between these descriptors", which
            //    a read/write loop satisfies; only the copy-avoidance is
            //    lost. Refusing instead breaks `tar | ssh`-style pipelines
            //    and Go's io.Copy fast path.
            case S::splice: {
                const int in = host_fd(gfd);
                const int out = host_fd(static_cast<int>(a2));
                if (in < 0 || out < 0) return -9;
                std::int64_t in_off = -1, out_off = -1;
                if (a1) { std::int64_t v{}; if (!ram.get(a1, v)) return -14; in_off = v; }
                if (a3) { std::int64_t v{}; if (!ram.get(a3, v)) return -14; out_off = v; }
                const std::int64_t moved = copy_between(in, out, in_off, out_off,
                                                        regs_.arg(4));
                if (moved < 0) return moved;
                if (a1 && in_off >= 0 && !ram.put(a1, in_off + moved)) return -14;
                if (a3 && out_off >= 0 && !ram.put(a3, out_off + moved)) return -14;
                return moved;
            }
            case S::tee: {
                // tee duplicates without consuming, which needs a peek we
                // cannot do on a pipe. Report 0 ("nothing copied"), the same
                // answer a caller gets from an empty pipe, so it falls back
                // to read/write rather than failing.
                return 0;
            }
            case S::vmsplice: {
                // Guest pages -> pipe. A plain writev to the pipe has the
                // same effect.
                if (!need_fd()) return -9;
                return do_vector(/*writing=*/true, *wfd, a1, a2);
            }

            // -- Allocation and flushing.
            case S::fallocate: {
                // fallocate(fd, mode, offset, len). Darwin's F_PREALLOCATE
                // reserves space; mode 0 means "allocate and extend", which
                // also needs the file length updated.
                if (!need_fd()) return -9;
                ::fstore_t st{};
                st.fst_flags = F_ALLOCATECONTIG | F_ALLOCATEALL;
                st.fst_posmode = F_PEOFPOSMODE;
                st.fst_offset = 0;
                st.fst_length = static_cast<off_t>(a3);
                (void)::fcntl(*hfd, F_PREALLOCATE, &st);   // best effort
                if (a1 == 0) {                             // extend the size
                    struct ::stat s{};
                    if (::fstat(*hfd, &s) == 0) {
                        const auto want = static_cast<off_t>(a2 + a3);
                        if (want > s.st_size && ::ftruncate(*hfd, want) < 0)
                            return darwin::fail();
                    }
                }
                return 0;
            }
            case S::syncfs:
                if (!need_fd()) return -9;
                ::sync();                                  // Darwin syncs all
                return 0;
            case S::sync_file_range:
                if (!need_fd()) return -9;
                return ::fsync(*hfd) < 0 ? darwin::fail() : 0;
            case S::readahead:
                return 0;                                  // advisory
            case S::lseek: {
                if (!need_fd()) return -9;
                // SEEK_DATA/SEEK_HOLE: Linux 3/4, Darwin 4/3 -- swapped.
                int wh = static_cast<int>(a2);
                if (wh == 3) wh = SEEK_DATA;
                else if (wh == 4) wh = SEEK_HOLE;
                else if (wh > 4 || wh < 0) return -22;
                auto off = ::lseek(*hfd, static_cast<off_t>(a1), wh);
                return off < 0 ? darwin::fail() : off;
            }
            case S::fsetxattr: case S::fgetxattr:
            case S::flistxattr: case S::fremovexattr:
                if (!need_fd()) return -9;
                return xattr_op(sc, *hfd, nullptr, false, 1);
            case S::fstat: {
                if (!need_fd()) return -9;
                struct ::stat st{};
                if (::fstat(*hfd, &st) < 0) return darwin::fail();
                auto ls = darwin::to_linux(st);
                if (S_ISSOCK(st.st_mode))
                    ls.st_ino = net::socket_inode(*hfd, static_cast<std::uint64_t>(st.st_ino));
                return ram.put(a1, ls) ? 0 : -14;
            }
            case S::ftruncate:
                if (!need_fd()) return -9;
                if (memfds_) {
                    if (const auto s = memfd_seals(*hfd)) {
                        struct ::stat st{};
                        (void)::fstat(*hfd, &st);
                        const auto want = static_cast<off_t>(a1);
                        if ((*s & kSealShrink) && want < st.st_size) return -1;   // EPERM
                        if ((*s & kSealGrow) && want > st.st_size) return -1;
                    }
                }
                if (::ftruncate(*hfd, static_cast<off_t>(a1)) < 0) return darwin::fail();
                file_resized(*hfd);
                return 0;
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
            // -- epoll. Every modern Linux event loop (systemd, nginx, Go's
            //    netpoller, libuv, asyncio) waits here and has no fallback,
            //    so this is implemented on kqueue rather than refused. See
            //    hvf_epoll.hpp for the level/edge and per-filter differences.
            case S::epoll_create1: {
                auto set = std::make_shared<EpollSet>();
                if (!set->valid()) return darwin::fail();
                // The guest holds an ordinary fd; /dev/null backs it so that
                // close(), dup() and the fd table need no special case.
                const int placeholder = ::open("/dev/null", O_RDWR | O_CLOEXEC);
                if (placeholder < 0) return darwin::fail();
                const int g = proc_.with_fds([&](FdTable& t) {
                    return t.install(placeholder, (a0 & abi::wire::kOCloexec) != 0);
                });
                if (g < 0) { ::close(placeholder); return -24; }
                epolls_[g] = std::move(set);
                return g;
            }
            case S::epoll_ctl: {
                auto it = epolls_.find(gfd);
                if (it == epolls_.end()) return -22;            // EINVAL: not an epoll fd
                const int target = static_cast<int>(a2);
                const int target_host = host_fd(target);
                if (target_host < 0) return -9;
                std::uint32_t mask = 0;
                std::uint64_t token = 0;
                if (static_cast<int>(a1) != kEpollCtlDel) {
                    LinuxEpollEvent ev{};
                    if (!ram.get(a3, ev)) return -14;
                    mask = ev.events;
                    token = ev.data;
                }
                return it->second->ctl(static_cast<int>(a1), target_host, target, mask, token);
            }
            case S::epoll_pwait: {
                auto it = epolls_.find(gfd);
                if (it == epolls_.end()) return -22;
                std::vector<LinuxEpollEvent> ready;
                const auto n = it->second->wait(ready, static_cast<int>(a2),
                                                static_cast<int>(static_cast<std::int32_t>(a3)));
                if (n < 0) return n;
                for (std::size_t i = 0; i < ready.size(); ++i)
                    if (!ram.put(a1 + i * sizeof(LinuxEpollEvent), ready[i])) return -14;
                return n;
            }

            case S::getdents64:
                if (!need_fd()) return -9;
                return do_getdents(gfd, *hfd, a1, a2);

            // -- copy_file_range(fd_in, off_in*, fd_out, off_out*, len, flags)
            //    coreutils' `cp` and `install` prefer it; Darwin has no
            //    equivalent that takes explicit offsets, so do it with
            //    pread/pwrite -- which is precisely the fallback Linux itself
            //    uses when the filesystems differ.
            case S::copy_file_range: {
                const int in = host_fd(gfd);
                const int out = host_fd(static_cast<int>(a2));
                if (in < 0 || out < 0) return -9;
                std::int64_t off_in = -1, off_out = -1;
                if (a1) { std::int64_t v{}; if (!ram.get(a1, v)) return -14; off_in = v; }
                if (a3) { std::int64_t v{}; if (!ram.get(a3, v)) return -14; off_out = v; }
                std::uint64_t remaining = regs_.arg(4), done = 0;
                std::vector<std::byte> buf(std::min<std::uint64_t>(remaining, 1u << 20));
                while (remaining) {
                    const auto want = std::min<std::uint64_t>(remaining, buf.size());
                    const auto got = off_in < 0
                        ? ::read(in, buf.data(), want)
                        : ::pread(in, buf.data(), want, static_cast<off_t>(off_in));
                    if (got < 0) return done ? static_cast<std::int64_t>(done) : darwin::fail();
                    if (got == 0) break;                       // EOF
                    const auto put = off_out < 0
                        ? ::write(out, buf.data(), static_cast<std::size_t>(got))
                        : ::pwrite(out, buf.data(), static_cast<std::size_t>(got),
                                   static_cast<off_t>(off_out));
                    if (put < 0) return done ? static_cast<std::int64_t>(done) : darwin::fail();
                    done += static_cast<std::uint64_t>(put);
                    remaining -= static_cast<std::uint64_t>(put);
                    if (off_in >= 0) off_in += put;
                    if (off_out >= 0) off_out += put;
                    if (put < got) break;
                }
                if (a1 && off_in >= 0 && !ram.put(a1, off_in)) return -14;
                if (a3 && off_out >= 0 && !ram.put(a3, off_out)) return -14;
                return static_cast<std::int64_t>(done);
            }
            case S::fadvise64:
                return 0;              // purely advisory; Darwin's F_RDAHEAD differs
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
            const std::size_t rec = abi::wire::dirent_reclen(e.name.size());
            if (used + rec > out.size()) {
                if (used == 0) return -22;           // EINVAL: buffer too small
                break;
            }
            // One encoder for every host (abi/wire/dirent64.hpp): d_ino and
            // d_type come straight from readdir, so this backend supplies
            // values and never touches the layout.
            const abi::wire::Dirent de{
                e.ino,
                static_cast<std::int64_t>(++ds.index),
                static_cast<abi::wire::DType>(e.type),   // DT_* values agree
                e.name,
            };
            const std::size_t n = abi::wire::encode_dirent64(
                std::span{out}.subspan(used, rec), de);
            if (n == 0) { if (used == 0) return -22; break; }
            used += n;
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

        // -- Record locks. F_SETLKW can BLOCK (that is the point: it waits
        //    for the holder to release), so it must run with no lock of ours
        //    held -- which is why the fd was resolved first.
        constexpr std::uint64_t kGetlk = 5, kSetlk = 6, kSetlkw = 7;
        constexpr std::uint64_t kOfdGetlk = 36, kOfdSetlk = 37, kOfdSetlkw = 38;
        if (cmd == kGetlk || cmd == kSetlk || cmd == kSetlkw ||
            cmd == kOfdGetlk || cmd == kOfdSetlk || cmd == kOfdSetlkw) {
            const GuestRam ram = machine_.ram();
            darwin::LinuxFlock lf{};
            if (!ram.get(arg, lf)) return -14;
            auto df = darwin::flock_to_darwin(lf);
            if (!df) return -22;
            // Darwin has OFD locks too (F_OFD_*: owned by the open file
            // description, so two opens of one file conflict even in one
            // process, and closing another fd doesn't drop them).
            const bool get = cmd == kGetlk || cmd == kOfdGetlk;
            const bool wait = cmd == kSetlkw || cmd == kOfdSetlkw;
            const bool ofd = cmd == kOfdGetlk || cmd == kOfdSetlk || cmd == kOfdSetlkw;
            int dcmd = get ? F_GETLK : (wait ? F_SETLKW : F_SETLK);
#if defined(F_OFD_SETLK)
            if (ofd) dcmd = get ? F_OFD_GETLK : (wait ? F_OFD_SETLKW : F_OFD_SETLK);
#endif
            if (ofd && lf.l_pid != 0) return -22;                     // Linux: must be 0
            if (::fcntl(h, dcmd, &*df) < 0) return darwin::fail();
            if (get) {
                // F_GETLK reports the CONFLICTING lock, or l_type=F_UNLCK if
                // the range is free -- with the holder's pid as the GUEST
                // numbers it (the host gives its own), and -1 for an OFD
                // query, which Linux reports for open-file-description locks.
                auto out = darwin::flock_to_linux(*df);
                if (df->l_type != F_UNLCK) {
                    const std::int32_t g = df->l_pid == ::getpid() ? tgid_ : pids_.guest_of(df->l_pid);
                    out.l_pid = (cmd == kOfdGetlk) ? -1 : (g > 0 ? g : 0);
                }
                return ram.put(arg, out) ? 0 : -14;
            }
            return 0;
        }

        switch (cmd) {
            case 1033: {                         // F_ADD_SEALS
                const auto s = memfd_seals(h);
                if (!s) return -22;              // EINVAL: not a memfd
                if (*s & kSealSeal) return -1;   // EPERM: sealing is sealed
                const auto add = static_cast<std::uint32_t>(arg);
                if (add & ~0x1fu) return -22;
                // F_SEAL_WRITE needs no writable shared mapping to exist
                // (EBUSY); a mapping of it here is a backing on this inode.
                if (add & kSealWrite) {
                    struct ::stat st{};
                    (void)::fstat(h, &st);
                    const bool mapped = proc_.with_backings([&](auto& v) {
                        for (const auto& b : v) {
                            struct ::stat bs{};
                            if (::fstat(b.fd, &bs) == 0 && bs.st_ino == st.st_ino && bs.st_dev == st.st_dev)
                                return true;
                        }
                        return false;
                    });
                    if (mapped) return -16;      // EBUSY
                }
                memfds_ = true;
                return set_memfd_seals(h, *s | add) ? 0 : darwin::fail();
            }
            case 1034: {                         // F_GET_SEALS
                const auto s = memfd_seals(h);
                return s ? static_cast<std::int64_t>(*s) : -22;
            }
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
    [[nodiscard]] std::int64_t do_ioctl(int hfd, std::uint64_t req64, std::uint64_t arg) {
        // ioctl(2)'s request is `unsigned int` in the kernel: only the low 32
        // bits exist. musl passes it as an int, so on a 64-bit register a
        // request with bit 31 set (every _IOR, e.g. TIOCGPTN 0x80045430)
        // arrives sign-extended; comparing all 64 bits made it ENOTTY, and
        // openpty() reported "out of pty devices".
        const std::uint32_t req = static_cast<std::uint32_t>(req64);
        const GuestRam ram = machine_.ram();
        // A PTY MASTER: Linux applies termios and window-size requests to
        // the slave's line discipline; Darwin refuses them on the master
        // (ENOTTY). apt/dpkg, script(1), tmux and expect all size and
        // configure the terminal they allocated through the master, so
        // every apt run printed "Setting TIOCSWINSZ for master fd failed".
        // Do it on the slave, which is the same terminal.
        struct SlaveFd {
            int fd{-1};
            ~SlaveFd() { if (fd >= 0) ::close(fd); }
        } slave;
        if (tty::is_termios_request(req)) {
            // a master is what ptsname answers for (Darwin's isatty() says
            // yes for a master too, yet refuses most requests on it)
            char name[128];
            if (::ptsname_r(hfd, name, sizeof name) == 0)
                slave.fd = ::open(name, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
            if (slave.fd >= 0) hfd = slave.fd;
        }
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
                // termios2 starts with a plain termios plus explicit speeds.
                const bool v2 = req == L_TCSETS2 || req == L_TCSETSW2 || req == L_TCSETSF2;
                LinuxTermios2 l2{};
                if (v2 ? !ram.get(arg, l2) : !ram.get(arg, l2.base)) return -14;
                struct ::termios t{};
                if (::tcgetattr(hfd, &t) < 0) return darwin::fail();
                to_darwin(l2.base, t);
                if (v2 && (l2.base.c_cflag & kCbaud) == 0010000 /*BOTHER*/) {
                    ::cfsetispeed(&t, l2.c_ispeed);
                    ::cfsetospeed(&t, l2.c_ospeed);
                }
                const int when = (req == L_TCSETS || req == L_TCSETS2)   ? TCSANOW
                               : (req == L_TCSETSW || req == L_TCSETSW2) ? TCSADRAIN
                                                                         : TCSAFLUSH;
                return ::tcsetattr(hfd, when, &t) < 0 ? darwin::fail() : 0;
            }
            // TCSBRK(0) is tcsendbreak, TCSBRK(nonzero) is tcdrain; TCSBRKP is
            // the POSIX tcsendbreak with a duration. On a PTY Linux has no
            // transmitter: drain returns once output is in the line
            // discipline, and a break is nothing to send. Darwin's pty drain
            // instead waits until the MASTER has read everything -- so a
            // program that drains before its reader reads (any test of
            // output, `script`, expect) hung forever, deaf to signals. A real
            // serial line keeps the host's semantics.
            case L_TCSBRK: case L_TCSBRKP: {
                char name[128];
                const bool pty = ::ttyname_r(hfd, name, sizeof name) == 0 &&
                                 lx::vfs::pty_slave_number(name) >= 0;
                if (pty) return ::isatty(hfd) ? 0 : -25;
                if (req == L_TCSBRK && arg != 0) return ::tcdrain(hfd) < 0 ? darwin::fail() : 0;
                return ::tcsendbreak(hfd, req == L_TCSBRKP ? static_cast<int>(arg) : 0) < 0
                           ? darwin::fail() : 0;
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
            // The controlling terminal is the host's (this guest process is
            // a real host process with a real session): claim or drop it
            // for real, so the host's job control -- ^C to the foreground
            // group, SIGHUP on hangup, tcgetpgrp -- works on it.
            case L_TIOCSCTTY:
                return ::ioctl(hfd, TIOCSCTTY, static_cast<int>(arg)) < 0 ? darwin::fail() : 0;
            case L_TIOCNOTTY:
                return ::ioctl(hfd, TIOCNOTTY) < 0 ? darwin::fail() : 0;
            case L_TCXONC: {
                // Linux TCOOFF 0, TCOON 1, TCIOFF 2, TCION 3 -> tcflow's
                constexpr int kAct[] = {TCOOFF, TCOON, TCIOFF, TCION};
                if (arg > 3) return -22;
                return ::tcflow(hfd, kAct[arg]) < 0 ? darwin::fail() : 0;
            }
            // -- Job control: tcgetpgrp/tcsetpgrp/tcgetsid -----------------
            // The terminal's foreground process group, in GUEST pids. bash
            // hands each foreground job the terminal (tcsetpgrp) and takes
            // it back; with ENOTTY job control silently degraded, and
            // Ctrl-C/Ctrl-Z reached the wrong group. Translate through the
            // shared pid space (a process group id is its leader's pid).
            case L_TIOCGPGRP: {
                const pid_t h = ::tcgetpgrp(hfd);
                if (h < 0) return darwin::fail();
                return ram.put(arg, guest_pid_of(h)) ? 0 : -14;
            }
            case L_TIOCSPGRP: {
                std::int32_t g = 0;
                if (!ram.get(arg, g)) return -14;
                const auto h = host_pid_of(g);
                if (!h) return -3;                                   // ESRCH
                // POSIX: tcsetpgrp from a BACKGROUND group raises SIGTTOU
                // unless the caller blocks/ignores it -- and bash does, in
                // the GUEST's mask. The host kernel only sees our host mask,
                // so the forked job stopped itself the instant it took the
                // terminal (^Z then froze the session; `cat` showed as
                // Stopped). Honour the guest's disposition on the host for
                // the duration of the call.
                const LinuxSigaction ttou =
                    proc_.with_signals([&](SignalDispositions& t) { return t.get(22); });
                const bool guest_shields = (task_.sig_mask & sigbit(22)) || ttou.handler == 1;
                sigset_t blk, old;
                sigemptyset(&blk); sigaddset(&blk, SIGTTOU);
                if (guest_shields) ::pthread_sigmask(SIG_BLOCK, &blk, &old);
                const int rc = ::tcsetpgrp(hfd, *h);
                const int e = errno;
                if (guest_shields) ::pthread_sigmask(SIG_SETMASK, &old, nullptr);
                errno = e;
                return rc < 0 ? darwin::fail() : 0;
            }
            case L_TIOCGSID: {
                const pid_t h = ::tcgetsid(hfd);
                if (h < 0) return darwin::fail();
                return ram.put(arg, guest_pid_of(h)) ? 0 : -14;
            }
            // -- Guest-created ptys (tmux, script, expect, Python's pty) ----
            // glibc's posix_openpt opens /dev/ptmx (the host's), then
            // unlockpt = TIOCSPTLCK(0) and ptsname = TIOCGPTN, and opens
            // "/dev/pts/<N>". Darwin has the same master but names the
            // slave /dev/ttysNNN, so: unlock with the host call, report the
            // number N from the host ptsname, and devfs maps /dev/pts/N to
            // /dev/ttysNNN. Without these, ENOTTY made every guest program
            // that needs its own terminal fail ("out of pty devices").
            case L_TIOCSPTLCK: {
                std::int32_t lock = 0;
                if (!ram.get(arg, lock)) return -14;
                if (lock) return 0;                      // relocking: harmless no-op
                return (::grantpt(hfd) < 0 || ::unlockpt(hfd) < 0) ? darwin::fail() : 0;
            }
            case L_TIOCGPTN: {
                char name[128];
                if (::ptsname_r(hfd, name, sizeof name) != 0) return -25;
                // "/dev/ttys012" -> 12
                const char* d = name + std::strlen(name);
                while (d > name && d[-1] >= '0' && d[-1] <= '9') --d;
                if (!*d) return -25;
                return ram.put(arg, static_cast<std::uint32_t>(std::atoi(d))) ? 0 : -14;
            }
            case L_TIOCGPTPEER: {
                // Open the slave of this master directly (O_NOCTTY etc. in arg).
                char name[128];
                if (::ptsname_r(hfd, name, sizeof name) != 0) return -25;
                const int s = ::open(name, O_RDWR | O_NOCTTY | O_CLOEXEC);
                if (s < 0) return darwin::fail();
                const int g = proc_.with_fds([&](FdTable& t) { return t.install(s, (arg & abi::wire::kOCloexec) != 0); });
                if (g < 0) { ::close(s); return -24; }
                return g;
            }
            default:
                return -25;                                          // ENOTTY
        }
    }

    // A blocking host poll that a guest SIGNAL must interrupt: the guest's
    // deliverable signals are checked first (EINTR without sleeping), and
    // the handler's self-pipe rides along in the set, so a signal landing
    // after the check still wakes it. Returns poll's answer with the wake
    // fd's own readiness removed, or -EINTR.
    [[nodiscard]] int signal_aware_poll(std::vector<struct ::pollfd>& p, int timeout) {
        g_pending.drain_wake();
        drain_mail();
        auto deliverable = [&] {
            return ((g_pending.bits.load(std::memory_order_relaxed)
                     | task_.pending.load(std::memory_order_relaxed)) & ~task_.sig_mask) != 0;
        };
        if (deliverable()) return -4;
        const int wfd = g_pending.wake_rd;
        if (wfd >= 0) p.push_back({wfd, POLLIN, 0});
        const int rc = ::poll(p.data(), static_cast<nfds_t>(p.size()), timeout);
        const bool woke = wfd >= 0 && (p.back().revents & POLLIN);
        if (wfd >= 0) p.pop_back();
        if (rc < 0) return errno == EINTR ? -4 : static_cast<int>(darwin::fail());
        const int n = rc - (woke ? 1 : 0);
        if (n == 0 && woke && deliverable()) return -4;          // a signal, nothing else
        return n;
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
        std::vector<struct ::pollfd> hv(h.begin(), h.end());
        const int rc = signal_aware_poll(hv, timeout);
        if (rc < 0) return rc;
        std::copy(hv.begin(), hv.end(), h.begin());
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
        const int rc = signal_aware_poll(p, timeout);
        if (rc < 0) return rc;
        for (auto& s : sets) std::fill(s.begin(), s.end(), 0);
        int ready = 0;
        for (std::size_t i = 0; i < p.size(); ++i) {
            const auto fd = static_cast<std::size_t>(guest[i]);
            const auto bit = static_cast<std::uint8_t>(1u << (fd % 8));
            if (p[i].revents & (POLLIN | POLLHUP | POLLERR)) { sets[0][fd / 8] |= bit; ++ready; }
            if (p[i].revents & POLLOUT) { sets[1][fd / 8] |= bit; ++ready; }
            if (p[i].revents & POLLPRI) { sets[2][fd / 8] |= bit; ++ready; }
        }
        for (int s = 0; s < 3; ++s)
            if (at[s] && bytes) std::memcpy(ram.at(at[s], bytes).data(), sets[s].data(), bytes);
        return ready;
    }

    // Install a host fd into the guest table, closing it if the table is
    // full so the descriptor never leaks.
    [[nodiscard]] std::int64_t install_or_close(int h, bool cloexec) {
        const int g = proc_.with_fds([&](FdTable& t) { return t.install(h, cloexec); });
        if (g < 0) { ::close(h); return -24; }               // EMFILE
        return g;
    }

    // readv/writev: one Darwin call per entry. Building a host iovec array
    // would need every guest base translated and bounds-checked anyway, and
    // real vectors are short (musl's stdio uses two).
    [[nodiscard]] std::int64_t do_vector(bool writing, int fd,
                                         std::uint64_t vec, std::uint64_t cnt) {
        return do_vector_at(writing, fd, vec, cnt, -1);
    }

    // The same walk, optionally at an explicit offset (preadv/pwritev).
    [[nodiscard]] std::int64_t do_vector_at(bool writing, int fd, std::uint64_t vec,
                                            std::uint64_t cnt, off_t off) {
        const GuestRam ram = machine_.ram();
        std::int64_t total = 0;
        constexpr std::uint64_t kIovMax = 1024;
        for (std::uint64_t i = 0; i < std::min(cnt, kIovMax); ++i) {
            GuestIovec iov{};
            if (!ram.get(vec + i * sizeof(GuestIovec), iov)) return total ? total : -14;
            if (iov.len == 0) continue;
            auto win = ram.clamp(iov.base, iov.len);
            if (win.empty()) return total ? total : -14;
            const auto n = off < 0
                ? (writing ? ::write(fd, win.data(), win.size())
                           : ::read(fd, win.data(), win.size()))
                : (writing ? ::pwrite(fd, win.data(), win.size(), off + total)
                           : ::pread(fd, win.data(), win.size(), off + total));
            if (n < 0) return total ? total : darwin::fail();
            total += n;
            if (static_cast<std::uint64_t>(n) < win.size()) break;  // short
        }
        return total;
    }

    // Move up to `len` bytes between two host fds, honouring explicit
    // offsets (-1 = use the fd's own position). Shared by sendfile, splice
    // and copy_file_range -- all three promise only that the bytes move.
    // Move up to `len` bytes, Linux-style: block only until SOME data is
    // available, then return what was moved. Looping until `len` (or EOF)
    // deadlocked pipelines: GNU cat splices 128 KiB from a pipe, got the
    // writer's few bytes, then blocked in read() again for the rest -- so it
    // never returned to write them out or notice the writer's exit, and
    // `echo x | cat` (and every `cmd | cat` / `| less`) hung forever. Only a
    // positional (pread) regular-file source keeps going, because a file
    // read never blocks and sendfile on a file is expected to move it all.
    [[nodiscard]] std::int64_t copy_between(int in, int out, std::int64_t& in_off,
                                            std::int64_t out_off, std::uint64_t len) {
        std::vector<std::byte> buf(std::min<std::uint64_t>(len, 1u << 20));
        struct ::stat st{};
        const bool stream = in_off < 0 &&
            (::fstat(in, &st) != 0 || !S_ISREG(st.st_mode));
        std::uint64_t done = 0;
        while (done < len) {
            const auto want = std::min<std::uint64_t>(len - done, buf.size());
            const auto got = in_off < 0
                ? ::read(in, buf.data(), want)
                : ::pread(in, buf.data(), want, static_cast<off_t>(in_off));
            if (got < 0) return done ? static_cast<std::int64_t>(done) : darwin::fail();
            if (got == 0) break;
            const auto put = out_off < 0
                ? ::write(out, buf.data(), static_cast<std::size_t>(got))
                : ::pwrite(out, buf.data(), static_cast<std::size_t>(got),
                           static_cast<off_t>(out_off + static_cast<std::int64_t>(done)));
            if (put < 0) return done ? static_cast<std::int64_t>(done) : darwin::fail();
            done += static_cast<std::uint64_t>(put);
            if (in_off >= 0) in_off += put;
            if (put < got) break;
            if (stream) break;          // pipe/socket/tty: one transfer, like Linux
        }
        return static_cast<std::int64_t>(done);
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
            if (const char* n = ::ttyname(hfd)) {
                // A pty slave is /dev/ttysNNN on Darwin but /dev/pts/N on
                // Linux, and glibc's ttyname() readlinks /proc/self/fd/N then
                // stat-compares the result: a Darwin name doesn't exist in
                // the guest, so `tty` printed "not a tty" inside script(1)
                // and tmux. Report the Linux name; devfs maps it back.
                std::string_view s{n};
                if (s.starts_with("/dev/ttys")) {
                    const std::string_view num = s.substr(9);
                    if (!num.empty() && num.find_first_not_of("0123456789") == std::string_view::npos)
                        return "/dev/pts/" + std::to_string(std::atoi(std::string{num}.c_str()));
                }
                return n;
            }
        }
        struct ::stat st{};
        if (::fstat(hfd, &st) == 0) {
            if (S_ISFIFO(st.st_mode)) return "pipe:[" + std::to_string(st.st_ino) + "]";
            if (S_ISSOCK(st.st_mode))
                return "socket:[" + std::to_string(net::socket_inode(hfd, static_cast<std::uint64_t>(st.st_ino))) + "]";
        }
        char buf[PATH_MAX];
        if (const auto mn = memfd_name(hfd)) return "/memfd:" + *mn + " (deleted)";
        if (::fcntl(hfd, F_GETPATH, buf) == 0) {
            std::string g = unresolve_ ? unresolve_(buf) : std::string{buf};
            // An unlinked file keeps its last name; Linux marks it.
            if (st.st_nlink == 0 && S_ISREG(st.st_mode)) g += " (deleted)";
            return g;
        }
        return "anon_inode:[unknown]";
    }

    // One xattr call, Linux arguments (from argument `first` on: name, value,
    // size, flags -- or buf, size for list), on a path (fd < 0) or an fd.
    [[nodiscard]] std::int64_t xattr_op(abi::Sysno sc, int fd, const char* path,
                                        bool nofollow, int first) {
        using S = abi::Sysno;
        const GuestRam ram = machine_.ram();
        const auto arg = [&](int i) { return regs_.arg(static_cast<std::size_t>(first + i)); };
        int opt = nofollow ? XATTR_NOFOLLOW : 0;
        auto fail = [] {
            const int e = errno;
            if (e == ENOATTR) return std::int64_t{-61};                   // ENODATA
            if (e == ENOTSUP) return std::int64_t{-95};                   // EOPNOTSUPP
            return darwin::fail();
        };
        switch (sc) {
            case S::listxattr: case S::llistxattr: case S::flistxattr: {
                auto buf = ram.clamp(arg(0), arg(1));
                if (buf.empty() && arg(1)) return -14;
                const ssize_t n = fd >= 0
                    ? ::flistxattr(fd, buf.empty() ? nullptr : reinterpret_cast<char*>(buf.data()), buf.size(), opt)
                    : ::listxattr(path, buf.empty() ? nullptr : reinterpret_cast<char*>(buf.data()), buf.size(), opt);
                if (n < 0) return errno == ERANGE ? -34 : fail();
                return n;
            }
            case S::getxattr: case S::lgetxattr: case S::fgetxattr: {
                const std::string name = ram.cstr(arg(0), 256);
                auto buf = ram.clamp(arg(1), arg(2));
                if (buf.empty() && arg(2)) return -14;
                const ssize_t n = fd >= 0
                    ? ::fgetxattr(fd, name.c_str(), buf.empty() ? nullptr : buf.data(), buf.size(), 0, opt)
                    : ::getxattr(path, name.c_str(), buf.empty() ? nullptr : buf.data(), buf.size(), 0, opt);
                if (n < 0) return errno == ERANGE ? -34 : fail();
                return n;
            }
            case S::setxattr: case S::lsetxattr: case S::fsetxattr: {
                const std::string name = ram.cstr(arg(0), 256);
                auto val = ram.at(arg(1), arg(2));
                if (val.empty() && arg(2)) return -14;
                const std::uint64_t lf = arg(3);           // XATTR_CREATE 1, XATTR_REPLACE 2
                if (lf & ~3ull) return -22;
                if (lf & 1) opt |= XATTR_CREATE;
                if (lf & 2) opt |= XATTR_REPLACE;
                const int rc = fd >= 0
                    ? ::fsetxattr(fd, name.c_str(), val.data(), val.size(), 0, opt)
                    : ::setxattr(path, name.c_str(), val.data(), val.size(), 0, opt);
                return rc < 0 ? fail() : 0;
            }
            case S::removexattr: case S::lremovexattr: case S::fremovexattr: {
                const std::string name = ram.cstr(arg(0), 256);
                const int rc = fd >= 0 ? ::fremovexattr(fd, name.c_str(), opt)
                                       : ::removexattr(path, name.c_str(), opt);
                return rc < 0 ? fail() : 0;
            }
            default: return -38;
        }
    }

    [[nodiscard]] Maybe do_path(abi::Sysno sc, const std::string* path,
                                const std::string* path2) {
        if (auto r = do_path_inner(sc, path, path2); r && *r == -36 && path &&
            path->size() >= host::kHostPathMax && (!path2 || path2->size() < host::kHostPathMax))
            return long_path_retry(sc, *path);
        else
            return r;
    }
    // A guest path deeper than Darwin's 1024-byte PATH_MAX (Linux: 4096):
    // the same call relative to the parent directory, reached a component at
    // a time. Covers what deep trees are made and taken apart with.
    [[nodiscard]] std::int64_t long_path_retry(abi::Sysno sc, const std::string& p) {
        using S = abi::Sysno;
        const std::uint64_t a2 = regs_.arg(2), a3 = regs_.arg(3);
        std::int64_t rc = -36;
        const bool walked = host::at_long_parent(p, [&](int dfd, const char* leaf) {
            int r = -1;
            struct ::stat st{};
            switch (sc) {
                case S::mkdirat:   r = ::mkdirat(dfd, leaf, static_cast<mode_t>(a2)); break;
                case S::unlinkat:  r = ::unlinkat(dfd, leaf, (a2 & 0x200) ? AT_REMOVEDIR : 0); break;
                case S::newfstatat: case S::statx: {
                    const std::uint64_t fl = sc == S::statx ? a2 : a3;
                    r = ::fstatat(dfd, leaf, &st, abi::wire::has_at(fl, abi::wire::AtFlag::symlink_nofollow)
                                                       ? AT_SYMLINK_NOFOLLOW : 0);
                    if (r == 0) {
                        const bool ok = sc == S::statx
                            ? machine_.ram().put(regs_.arg(4), darwin::statx_from_darwin(st))
                            : machine_.ram().put(a2, darwin::to_linux(st));
                        rc = ok ? 0 : -14;
                        return true;
                    }
                    break;
                }
                case S::faccessat: case S::faccessat2:
                    r = ::faccessat(dfd, leaf, static_cast<int>(a2), 0); break;
                case S::openat: {
                    const int fd = ::openat(dfd, leaf, darwin::open_flags(a2) | O_CLOEXEC,
                                            static_cast<mode_t>(a3));
                    if (fd < 0) break;
                    rc = proc_.with_fds([&](FdTable& t) { return t.install(fd, (a2 & abi::wire::kOCloexec) != 0); });
                    return true;
                }
                default: errno = ENAMETOOLONG; return false;
            }
            if (r == 0) { rc = 0; return true; }
            return false;
        });
        if (!walked && rc == -36) rc = errno == ENAMETOOLONG ? -36 : darwin::fail();
        return rc;
    }

    [[nodiscard]] Maybe do_path_inner(abi::Sysno sc, const std::string* path,
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
                // open/stat of /proc/self/fd/N reopen the SAME file. Linux
                // makes a NEW open file description (its own offset and
                // flags); Darwin's /dev/fd/K dups K instead, sharing the
                // offset -- so a regular file that still has a name reopens
                // by that name, and only the nameless (unlinked, pipes,
                // sockets) fall back to /dev/fd.
                fd_path_storage_ = "/dev/fd/" + std::to_string(*h);
                {
                    struct ::stat st{};
                    char p[PATH_MAX];
                    const bool reg = ::fstat(*h, &st) == 0 && S_ISREG(st.st_mode);
                    if (reg && st.st_nlink > 0 && ::fcntl(*h, F_GETPATH, p) == 0) {
                        fd_path_storage_ = p;
                    } else if (reg && (sc == S::openat || sc == S::open)) {
                        // Unlinked: no name to reopen. A READ-ONLY reopen
                        // (the common one: read what a deleted temp held)
                        // gets a copy-on-write clone of the content, opened
                        // and unlinked at once -- its own offset, as Linux.
                        const std::uint64_t fl = sc == S::openat ? regs_.arg(2) : regs_.arg(1);
                        if ((fl & 3) == 0) {
                            char tmpl[] = "/tmp/linuxity-reopen-XXXXXX";
                            if (const int t = ::mkstemp(tmpl); t >= 0) {
                                ::close(t);
                                ::unlink(tmpl);
                                if (::fclonefileat(*h, AT_FDCWD, tmpl, 0) == 0) {
                                    fd_path_storage_ = tmpl;
                                    unlink_after_open_ = true;
                                }
                            }
                        }
                    }
                }
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
                using OF = abi::wire::OpenFlag;
                constexpr auto A = abi::Arch::aarch64;
                int hflags = darwin::open_flags(lflags) | O_CLOEXEC;
                // O_TMPFILE: an unnamed file IN the directory named. Darwin
                // has no such open, so make one there and unlink it at once;
                // linkat("/proc/self/fd/N") later can still name it (a
                // clone of its content).
                const std::uint64_t tmpf = abi::wire::open_flag_for(A, OF::tmpfile);
                if ((lflags & tmpf) == tmpf) {
                    if ((lflags & 3) == 0) return -22;                // needs O_WRONLY/O_RDWR
                    std::string tmpl = *path + "/.lx-tmpfile-XXXXXX";
                    const int fd = ::mkstemp(tmpl.data());
                    if (fd < 0) return darwin::fail();
                    ::unlink(tmpl.c_str());
                    ::fchmod(fd, static_cast<mode_t>(lmode & 07777 & ~proc_.umask.load()));
                    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
                    return proc_.with_fds([&](FdTable& t) { return t.install(fd, (lflags & abi::wire::kOCloexec) != 0); });
                }
                // O_PATH: a handle on the NAME, no I/O. With O_NOFOLLOW on a
                // symlink it is the link itself (Darwin: O_SYMLINK); on a
                // file or directory, open for lookup only.
                if (abi::wire::has_for(A, lflags, OF::path)) {
                    struct ::stat lst{};
                    const bool link = ::lstat(path->c_str(), &lst) == 0 && S_ISLNK(lst.st_mode);
                    if (link && abi::wire::has_for(A, lflags, OF::nofollow)) {
                        hflags = O_SYMLINK | O_RDONLY | O_CLOEXEC;
                    } else {
                        struct ::stat st{};
                        if (::stat(path->c_str(), &st) != 0) return darwin::fail();
                        hflags = (S_ISDIR(st.st_mode) ? O_SEARCH | O_DIRECTORY : O_RDONLY) | O_CLOEXEC;
                        if (!S_ISDIR(st.st_mode) && ::access(path->c_str(), R_OK) != 0)
                            hflags = O_EXEC | O_CLOEXEC;
                        if (abi::wire::has_for(A, lflags, OF::directory) && !S_ISDIR(st.st_mode)) return -20;
                    }
                }
                int fd = ::open(path->c_str(), hflags, static_cast<mode_t>(lmode));
                if (fd < 0 && errno == ENAMETOOLONG && path->size() >= host::kHostPathMax) {
                    // a guest path deeper than Darwin's 1024-byte PATH_MAX
                    // (Linux allows 4096): walk to the parent a step at a time
                    (void)host::at_long_parent(*path, [&](int dfd, const char* leaf) {
                        fd = ::openat(dfd, leaf, hflags, static_cast<mode_t>(lmode));
                        return fd >= 0;
                    });
                }
                if (std::exchange(unlink_after_open_, false)) ::unlink(path->c_str());
                if (fd < 0) return darwin::fail();
                return proc_.with_fds([&](FdTable& t) { return t.install(fd, (lflags & abi::wire::kOCloexec) != 0); });
            }
            case S::newfstatat: {
                if (!path) return -2;
                struct ::stat st{};
                int rc = abi::wire::has_at(a3, abi::wire::AtFlag::symlink_nofollow) ? ::lstat(path->c_str(), &st)
                                          : ::stat(path->c_str(), &st);
                if (rc < 0) return darwin::fail();
                return ram.put(a2, darwin::to_linux(st)) ? 0 : -14;
            }
            case S::statx: {
                // statx(dirfd, path, flags, mask, buf). AT_EMPTY_PATH with an
                // empty path means "stat the fd itself" -- there is no
                // fstatat spelling for that, which is why refusing statx
                // breaks callers outright rather than making them fall back.
                struct ::stat st{};
                int rc;
                if (abi::wire::has_at(a2, abi::wire::AtFlag::empty_path) && (!path || path->empty())) {
                    const int h = host_fd(static_cast<int>(regs_.arg(0)));
                    if (h < 0) return -9;
                    rc = ::fstat(h, &st);
                } else if (path) {
                    rc = abi::wire::has_at(a2, abi::wire::AtFlag::symlink_nofollow) ? ::lstat(path->c_str(), &st)
                                          : ::stat(path->c_str(), &st);
                } else {
                    return -2;
                }
                if (rc < 0) return darwin::fail();
                return ram.put(regs_.arg(4), darwin::statx_from_darwin(st)) ? 0 : -14;
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
            case S::mknodat: {
                // mknodat(dirfd, path, mode, dev). FIFOs and regular files
                // are real on Darwin; device nodes need privilege we don't
                // take, and a guest's /dev is synthesized by the core
                // anyway, so report EPERM for those exactly as an
                // unprivileged Linux kernel does.
                if (!path) return -2;
                constexpr std::uint64_t kIfmt = 0170000, kIfifo = 0010000,
                                        kIfreg = 0100000, kIfsock = 0140000;
                const std::uint64_t fmt = a2 & kIfmt;
                const auto mode = static_cast<mode_t>(a2 & abi::wire::kPermMask);
                if (fmt == kIfifo)
                    return ::mkfifo(path->c_str(), mode) < 0 ? darwin::fail() : 0;
                if (fmt == 0 || fmt == kIfreg) {
                    const int fd = ::open(path->c_str(),
                                          O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, mode);
                    if (fd < 0) return darwin::fail();
                    ::close(fd);
                    return 0;
                }
                if (fmt == kIfsock) {
                    // A bound AF_UNIX socket creates its own node; mknod of
                    // one is vanishingly rare and needs no device number.
                    const int s = ::socket(AF_UNIX, SOCK_STREAM, 0);
                    if (s < 0) return darwin::fail();
                    ::sockaddr_un sun{};
                    if (path->size() >= sizeof sun.sun_path) { ::close(s); return -36; }
                    sun.sun_family = AF_UNIX;
                    std::memcpy(sun.sun_path, path->c_str(), path->size() + 1);
                    const int rc = ::bind(s, reinterpret_cast<::sockaddr*>(&sun),
                                          static_cast<socklen_t>(
                                              offsetof(::sockaddr_un, sun_path)
                                              + path->size() + 1));
                    ::close(s);
                    return rc < 0 ? darwin::fail() : 0;
                }
                return -1;                                       // EPERM: device node
            }
            case S::unlinkat: {
                if (!path) return -2;
                int rc = abi::wire::has_at(a2, abi::wire::AtFlag::removedir) ? ::rmdir(path->c_str())
                                           : ::unlink(path->c_str());
                return rc < 0 ? darwin::fail() : 0;
            }
            case S::renameat: case S::renameat2: {
                if (!path || !path2) return -2;
                // renameat2's NOREPLACE (1) / EXCHANGE (2) are Darwin's
                // renamex_np RENAME_EXCL / RENAME_SWAP. Ignoring them made
                // NOREPLACE silently clobber the target. WHITEOUT (4) has
                // no host equivalent.
                const std::uint64_t fl = sc == S::renameat2 ? regs_.arg(4) : 0;
                if (fl & ~std::uint64_t{3} || fl == 3) return -22;   // EINVAL
                if (fl) {
                    const unsigned hf = (fl & 1) ? RENAME_EXCL : RENAME_SWAP;
                    return ::renamex_np(path->c_str(), path2->c_str(), hf) < 0
                               ? darwin::fail() : 0;
                }
                return ::rename(path->c_str(), path2->c_str()) < 0
                           ? darwin::fail() : 0;
            }
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
                if (!path) {
                    auto h = proc_.with_fds([&](FdTable& t) { return t.host(static_cast<int>(regs_.arg(0))); });
                    if (!h) return -9;
                    return ::futimens(*h, ts) < 0 ? darwin::fail() : 0;
                }
                return ::utimensat(AT_FDCWD, path->c_str(), ts,
                                   abi::wire::has_at(a3, abi::wire::AtFlag::symlink_nofollow) ? AT_SYMLINK_NOFOLLOW : 0) < 0
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
            case S::fchmodat2: {
                // fchmodat2(dirfd, path, mode, flags) -- fchmodat with real
                // flag support. AT_SYMLINK_NOFOLLOW means "change the LINK's
                // mode, not its target's", which Darwin spells lchmod.
                //
                // Refusing this is not harmless: libarchive calls it for
                // every symlink it extracts, and `pacman -S git` turned the
                // ENOSYS into "warning ... (Can't set permissions to 0777)"
                // for each one and then failed the whole transaction.
                if (!path) return -2;
                const auto mode = static_cast<mode_t>(a2);
                const int rc = abi::wire::has_at(a3, abi::wire::AtFlag::symlink_nofollow) ? ::lchmod(path->c_str(), mode)
                                                : ::chmod(path->c_str(), mode);
                return rc < 0 ? darwin::fail() : 0;
            }
            case S::truncate: {
                if (!path) return -2;
                if (::truncate(path->c_str(), static_cast<off_t>(regs_.arg(1))) < 0) return darwin::fail();
                if (const int h = ::open(path->c_str(), O_RDONLY | O_CLOEXEC); h >= 0) {
                    file_resized(h);
                    ::close(h);
                }
                return 0;
            }
            // -- Extended attributes, on the translated path. Darwin has the
            //    same four calls with an extra `position` and its own flag
            //    bits (XATTR_NOFOLLOW is an option, not a separate l* call),
            //    and says ENOATTR where Linux says ENODATA.
            case S::setxattr: case S::lsetxattr:
            case S::getxattr: case S::lgetxattr:
            case S::listxattr: case S::llistxattr:
            case S::removexattr: case S::lremovexattr: {
                if (!path) return -2;
                const bool nf = sc == S::lsetxattr || sc == S::lgetxattr ||
                                sc == S::llistxattr || sc == S::lremovexattr;
                return xattr_op(sc, -1, path->c_str(), nf, 1);
            }
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
                    // bind(fd, {AF_UNIX}, 2): Linux AUTOBINDS an abstract name
                    // of five hex digits.
                    std::array<std::byte, 8> autoname{};
                    if (sc == S::bind && addr.size() == 2 &&
                        std::to_integer<int>(addr[0]) == 1 && std::to_integer<int>(addr[1]) == 0) {
                        char nm[8];
                        std::snprintf(nm, sizeof nm, "%05x",
                                      static_cast<unsigned>((static_cast<unsigned>(::getpid()) * 2654435761u + sock_ino(h)) & 0xfffff));
                        autoname[0] = std::byte{1};
                        std::memcpy(autoname.data() + 3, nm, 5);
                        addr = {autoname.data(), autoname.size()};
                    }
                    auto n = net::to_darwin(addr, ss);
                    if (!n) return -97;
                    slen = *n;
                    // An abstract name lives only as long as its socket. Ours
                    // are nodes in a shared directory, which outlive a dead
                    // owner: a bind that finds one nobody answers on takes it.
                    const auto* sun = reinterpret_cast<const ::sockaddr_un*>(&ss);
                    if (sc == S::bind && ss.ss_family == AF_UNIX &&
                        std::string_view(sun->sun_path).starts_with(net::abstract_dir())) {
                        // Probe with the OTHER socket type: a live socket says
                        // EPROTOTYPE, a dead node ECONNREFUSED, and nothing
                        // lands in a live listener's backlog.
                        int typ = SOCK_STREAM; socklen_t tl = sizeof typ;
                        (void)::getsockopt(h, SOL_SOCKET, SO_TYPE, &typ, &tl);
                        const int probe = ::socket(AF_UNIX, typ == SOCK_DGRAM ? SOCK_STREAM : SOCK_DGRAM, 0);
                        if (probe >= 0) {
                            const bool dead = ::connect(probe, reinterpret_cast<const ::sockaddr*>(&ss), slen) < 0 &&
                                              errno == ECONNREFUSED;
                            ::close(probe);
                            if (dead) ::unlink(sun->sun_path);
                        }
                    }
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
    // The thread-group id: this process's pid, i.e. its MAIN thread's tid.
    // A cloned thread keeps it while task_.tid becomes its own.
    std::int32_t tgid_{1};
    bool threaded_{false};        // a clone(CLONE_THREAD) has happened
    struct Child { std::int32_t guest; pid_t host; };
    std::vector<Child> children_;
    std::vector<ProcEvent> proc_events_;
    std::vector<ExitHook> exit_hooks_;
    // AF_UNIX: the guest's spelling of each path it bound, by translated
    // host path (so the listener, its accepted sockets and a datagram's
    // sender all read back the same), and the sockets that asked for
    // SO_PASSCRED / are emulated SEQPACKET, by host socket inode.
    std::unordered_map<std::string, std::string> bound_paths_;
    std::unordered_set<std::uint64_t> passcred_, seqpacket_;
    bool ready_announced_{false};   // PidSpace::ready: the kick handler is in
    Resolver resolve_;
    Resolver unresolve_;
    kernel::fsnotify::Hub* hub_{nullptr};
    std::function<void(std::int64_t)> on_result_;
    std::string fd_path_storage_;
    bool unlink_after_open_{false};   // fd_path_storage_ is a reopen clone
    bool memfds_{false};              // a memfd has been seen: check seals
    std::unordered_map<std::int32_t, std::int32_t> rt_prio_;   // sched_param of FIFO/RR tasks
    SpawnFork spawn_;
    SpawnThread spawn_thread_;
    std::vector<std::string> env_;
    bool execed_{false};
    bool thread_exited_{false};
    bool no_new_privs_{false};
    int pdeathsig_{0};
    std::int64_t seccomp_mode_{0};
    TimerSet timers_;
    // epoll sets, keyed by the guest fd that names them.
    std::map<int, std::shared_ptr<EpollSet>> epolls_;
    // timerfd/signalfd/inotify/pidfd state, keyed the same way.
    std::map<int, int> timerfds_;                 // guest fd -> TimerSet id
    struct SignalFd { std::uint64_t mask; int write_end; };
    std::map<int, SignalFd> signalfds_;
    std::map<int, std::shared_ptr<InotifyFd>> inotifies_;
    std::map<int, std::int32_t> pidfds_;          // guest fd -> guest pid
    // SysV shared-memory attachments: guest address -> segment. `span` is
    // the host-page-rounded size of a shared backing (0: the copy fallback);
    // `host` the Darwin attach held for nattch.
    struct ShmSeg { int id; std::uint64_t size; std::uint64_t span; void* host; };
    std::map<std::uint64_t, ShmSeg> shm_attached_;
    // The host shm object holding SysV segment `id`'s contents.
    [[nodiscard]] static std::string sysv_shm_name(int id) {
        return "/lxsv." + std::to_string(id);
    }
    [[nodiscard]] static int sysv_shm_object(int id, std::uint64_t span) {
        const int fd = ::shm_open(sysv_shm_name(id).c_str(), O_RDWR | O_CREAT, 0600);
        if (fd < 0) return -1;
        struct ::stat st{};
        // Darwin sizes a POSIX shm object once; the first attach does it.
        if (::fstat(fd, &st) != 0 ||
            (st.st_size == 0 && ::ftruncate(fd, static_cast<off_t>(span)) < 0) ||
            (st.st_size != 0 && static_cast<std::uint64_t>(st.st_size) < span)) {
            ::close(fd);
            return -1;
        }
        return fd;
    }
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
    [[nodiscard]] std::string exe_of_pid(std::int32_t pid) const {
        return trap_ ? trap_->exe_of_pid(pid) : std::string{};
    }
    // The HOST process behind guest pid `pid` (0 = the caller), or -1. Every
    // guest process is its own host process here, so per-process scheduler
    // state (nice, affinity) lives with it, and only it can answer.
    [[nodiscard]] int host_pid_of(std::int32_t pid) const {
        if (!trap_) return -1;
        if (pid == 0) return ::getpid();
        const auto h = trap_->host_pid_of(pid);
        return h ? static_cast<int>(*h) : -1;
    }
    // Per-process nice, in the tree-wide table (see PidSpace::set_nice).
    [[nodiscard]] int nice_of(std::int32_t pid) const {
        return trap_ ? trap_->pid_space().nice_of(pid ? pid : trap_->tgid()) : 0;
    }
    void set_nice(std::int32_t pid, int n) const {
        if (trap_) trap_->pid_space().set_nice(pid ? pid : trap_->tgid(), n);
    }
    // A task's affinity mask (0 = every CPU), or nullopt if no such task.
    // pid 0 is the CALLING thread: each thread has its own mask.
    [[nodiscard]] std::optional<std::uint64_t> affinity_of(std::int32_t pid) const {
        if (!trap_) return std::nullopt;
        const std::int32_t t = pid ? pid : trap_->tid();
        if (pid && !trap_->pid_space().host_of(t)) return std::nullopt;
        return trap_->pid_space().affinity_of(t);
    }

    // Tells the portable core this backend keeps REAL process groups and
    // sessions (the shared pid table), so set/getpgid and friends are
    // forwarded here instead of answered with the core's flat model.
    static constexpr void models_process_groups() noexcept {}

    // The host fd behind guest fd `gfd`, or -1. Lets the portable core ask
    // the host about an fd it has no path for (an inherited terminal, a
    // TIOCGPTPEER slave) the way ptrace asks /proc/<tid>/fd.
    [[nodiscard]] int host_fd_of(int gfd) const {
        return trap_ ? trap_->host_fd_of(gfd) : -1;
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

// The macOS backend against the written contract (runtime/backend.hpp).
// Checked here, where the class is defined, so a renamed or mistyped
// primitive is a build error naming it -- not a silent fallback in the run
// loop that forwards an untranslated guest path to the host.
static_assert(SyscallTrap<HvfTrap>, "HvfTrap must model SyscallTrap");
static_assert(RedirectsTwoPaths<HvfTrap>,
              "HvfTrap must take the scrub observer and the second path");
static_assert(ForwardsSynchronously<HvfTrap>,
              "HvfTrap must forward synchronously so dup fd bindings mirror");
static_assert(WalksLongPaths<HvfTrap>,
              "HvfTrap performs path calls itself: the loop must not rebase onto a dirfd");
static_assert(TranslatesSockets<HvfTrap>,
              "HvfTrap must translate AF_UNIX paths, else guest sockets land "
              "on the host filesystem");
static_assert(ExecsThroughInterp<HvfTrap>,
              "HvfTrap must rewrite a dynamic execve through the interpreter");
static_assert(DeliversSignals<HvfTrap>,
              "HvfTrap models guest pids, so it must deliver signals");

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
