# Roadmap: any distro, on any machine

linuxity's goal: `linuxity --root ./arch /bin/bash` gives you a working Arch
(or Alpine, Debian, ...) userland on Linux, macOS and Windows. It starts
instantly, needs no root, and runs no VM kernel. It is a **compatibility
tool**, not a security boundary. Running hostile code is claybin's job (gVisor,
microVMs).

## Architecture invariant

```
   linuxity core (abi/, kernel/, vfs/, loader/)   host-agnostic, header-only
                         │   SyscallTrap concept (runtime/trap.hpp)
   ┌─────────────┬───────┴───────┬─────────────────┬────────────────┐
 ptrace        seccomp-unotify   HVF               WHP
 Linux (today) Linux (faster)    macOS             Windows
```

The core must compile and pass its portable tests on every host. CI enforces
this on macOS (`.github/workflows/ci.yml`). Linux-only code lives in
`runtime/ptrace_trap.hpp`, `runtime/seccomp_filter.hpp` and `src/`.

On macOS and Windows there is no ptrace that can catch a Linux `syscall`. The
backend runs the guest ELF as user code inside a bare hypervisor address space
(Hypervisor.framework / WHP). There is no guest kernel: each `svc`/`syscall`
exits the VM into linuxity, which services it and resumes. Noah and gVisor's
KVM platform use this same model.

## Milestones

- [x] **M0: portable core.** abi/kernel/vfs build and pass unit tests on macOS
      (gcc and Apple clang). CI for Linux and macOS.
- [ ] **M5a: HVF backend (macOS arm64) — IN PROGRESS.** Runs aarch64 Linux
      binaries on Apple Silicon with no guest kernel: the ELF executes at EL0
      inside a bare Hypervisor.framework VM, and every `svc` traps to
      linuxity, which services it through the SAME portable core and the SAME
      `runtime::Cpu` loop the Linux ptrace backend uses.

      Working today against a real Arch Linux ARM rootfs:
        * `linuxity --root ~/arch /usr/bin/bash` is an interactive shell:
          prompt, job control, pipelines, scripts, `trap`, redirection.
        * **Threads.** `clone(CLONE_THREAD)` gives each guest thread its own
          host thread and vCPU over shared guest RAM, so threads run in
          parallel on the real cores (8 threads of CPU work: 0.167 s vs
          0.115 s for one). futex is REAL -- macOS 14's
          os_sync_wait_on_address has the same compare-and-sleep contract,
          including cross-process shared support.
        * **Processes.** fork via COW snapshot + spawn, execve (program +
          PT_INTERP + `#!` chains), wait4, a shared guest pid namespace.
        * **Signals.** Full rt_sigframe delivery with FP/SIMD state,
          sigreturn, sigaltstack, per-thread masks, sigsuspend, and
          group/broadcast kills confined to the guest's own process tree.
        * **Timers.** setitimer and the POSIX timer_* family on a timer
          wheel, so `timeout`, `alarm` and connect deadlines work.
        * **Sockets.** socket/bind/connect/send/recv/poll translated to
          Darwin, so the guest uses the Mac's real network. DNS resolves.
        * coreutils, `pacman -Q`, vim, ssh, openssl, tar, find/xargs, git.
      Remaining: TLS fails if the HOST clock is wrong (certificates look
      not-yet-valid), no write overlay on macOS yet (guest writes land in the
      rootfs directory), mprotect is tracked but not enforced in the page
      tables, and `ps` needs a fuller /proc.
- [ ] **M1: Linux completeness ladder.** Each rung is a release:
      1. busybox / coreutils / bash
      2. `pacman -Syu`, `apk add`, `apt install`
      3. git, make, gcc/clang, python, node
      4. threaded runtimes (Go, tokio, JVM): futex/epoll correctness
      5. servers: nginx, postgres
      6. interactive: vim, tmux, htop
- [ ] **M2: conformance.** Run the gVisor syscall tests / LTP subset in CI and
      track the pass rate.
- [ ] **M3: `linuxity pull <distro>`.** Fetch the official rootfs for the
      host's arch into a store that keeps Linux metadata (uid/gid, modes,
      devices, case-sensitivity) for hosts whose filesystems can't hold it.
- [ ] **M4: seccomp-unotify backend (Linux).** Faster than ptrace. The tracer
      opens files and injects fds (`SECCOMP_IOCTL_NOTIF_ADDFD`), so there is
      no path-rewrite race.
- [ ] **M5: HVF backend (macOS arm64).** See M5a above — started.
- [ ] **M6: WHP backend (Windows x86-64).**
- [ ] **M7 (optional): foreign arch.** x86-64 rootfs on arm64 via FEX.

## Non-goals

- Being a sandbox. Compatibility shims (accepting `setuid`, Landlock no-op)
  say yes on purpose. That said, holes that make the guest see the *host*
  filesystem instead of its rootfs are correctness bugs and get fixed (e.g.
  the seccomp filter returns ENOSYS for i386/x32/io_uring, which would bypass
  path translation).
- Booting a real Linux kernel. That is a microVM; use one.
