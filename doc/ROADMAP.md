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

How the syscall is intercepted differs per host, and on x86-64 the trick is
worth stating because it is what removes the need for a guest kernel:

| host | mechanism |
|---|---|
| Linux | ptrace / seccomp-unotify |
| macOS arm64 | `svc #0` traps to EL2 (HVF gives it to us) |
| Windows x86-64 | **`IA32_EFER.SCE = 0` makes `syscall` raise `#UD`**, and WHP's `ExceptionExitBitmap` routes vector 6 to the host |

So on Windows the guest stays wholly at CPL 3 with no LSTAR trampoline, no
ring-0 code and no IDT/TSS in its address space — one cleared EFER bit turns
every `syscall` into a VM exit.

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
        * **A real package manager.** `pacman -Sy`, `pacman -S git`,
          `pacman-key --init/--populate` all work against live mirrors:
          HTTPS downloads, gpg signature verification, the keyring, and
          package extraction with correct symlink permissions.
        * **git** clones, commits and logs. nano, vim, ssh, openssl, tar,
          coreutils, find/xargs, useradd/groupadd/chpasswd, flock, df, stat.
        * **Copy-on-write overlay.** The rootfs you extracted is NEVER
          mutated: writes copy up into an upper layer, deletes become
          whiteouts, and uid/mode changes go to a shadow journal.
          `--persist DIR` keeps that layer across runs (installs survive);
          without it, a per-run scratch dir.
        * **Threads.** `clone(CLONE_THREAD)` gives each guest thread its own
          host thread and vCPU over shared guest RAM, so threads run in
          parallel on the real cores (8 threads of CPU work: 0.167 s vs
          0.115 s for one). futex is REAL -- macOS 14's
          os_sync_wait_on_address has the same compare-and-sleep contract,
          including cross-process shared support.
        * **Processes.** fork via COW snapshot + spawn, execve (program +
          PT_INTERP + `#!` chains), wait4, a shared guest pid/tid namespace.
        * **Signals.** Full rt_sigframe delivery with FP/SIMD state,
          sigreturn, sigaltstack, per-thread masks, sigsuspend, and
          group/broadcast kills confined to the guest's own process tree.
        * **Timers.** setitimer and the POSIX timer_* family on a timer
          wheel, so `timeout`, `alarm` and connect deadlines work.
        * **Sockets + epoll.** The full BSD socket set translated to Darwin,
          and epoll implemented on kqueue (level/edge, oneshot, EPOLLRDHUP),
          so Linux event loops work rather than hitting ENOSYS.
        * **Locks and modern stat.** fcntl POSIX record locks (what
          `useradd`, git and sqlite use) and statx including AT_EMPTY_PATH.
        * **Syscall conformance: 327/327 aarch64 syscalls** are decoded and
          handled by name (tables generated from kernel headers and checked
          in CI). The ones we refuse are refused on purpose: EPERM for
          privileged operations (modules, kexec, reboot) and ENOSYS for
          missing subsystems (bpf, io_uring, aio, keyrings, mq_*).
        * **Toolchains.** gcc/g++ (cc1plus is a 42 MiB non-PIE image at
          0x400000) build and run threaded C++. A guest-owned window keeps
          fixed-address ET_EXEC images clear of the page tables.
        * **Synchronous signals.** Guest faults deliver catchable
          SIGSEGV/SIGBUS/SIGILL with si_addr and si_code at the faulting PC,
          so guard-page and JIT handlers work. With no handler the fault is
          fatal (139).
        * **TUIs.** agentty, vim, htop and cmatrix. If the rootfs has no entry
          for the host terminal (kitty, ghostty, ...), it is bridged in.
        * **Shared kernel state is locked.** One recursive mutex guards the
          namespace and process tables across guest threads. It is held for
          bookkeeping only, never across a blocking host syscall.
      Performance: a trapped syscall costs ~1.5 us; hv_vcpu_run alone is
      ~1.0 us. Every `svc` must exit to the host: with HCR_EL2.TGE set,
      EL0 exceptions can't be taken at a guest EL1 vector (we measured this),
      so the way to go faster is fewer exits (a vDSO for clocks), not
      cheaper ones. Overlay directory unions are built lazily, on first
      getdents: `pacman -S python` takes 4.4 s, down from 2m41s.
      Remaining: `mprotect` is tracked in the VMA map but not enforced in
      the page tables; `ps` needs a fuller /proc; CI does not yet build the
      macOS binary (it needs a signed binary and a rootfs).
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
- [ ] **M6: WHP backend (Windows x86-64) — CPU/MEMORY/TRAP LAYERS LANDED.**
      Guest syscalls are intercepted by clearing `IA32_EFER.SCE` so that
      `syscall` raises `#UD`, and routing vector 6 to the host through the
      partition's `ExceptionExitBitmap`. No guest kernel, no ring-0 code: the
      guest runs entirely at CPL 3 and its instructions execute bare on the
      CPU.

      In place and verified on real hardware (`linuxity --check`):
        * `runtime/whp_api.hpp` — WHP entry points resolved at RUNTIME via
          LoadLibrary, so the binary still starts (and explains itself) on a
          machine where the Hypervisor Platform feature is off, instead of
          dying in the loader with 0xC0000135.
        * `runtime/whp_vm.hpp` — partition setup, guest RAM shared with
          `WHvMapGpaRange`, 4-level page tables, a GDT, and a vCPU entered
          DIRECTLY in 64-bit long mode at CPL 3 (no real-mode bootstrap:
          a hypervisor lets us just set the architectural state).
        * `runtime/whp_regs.hpp` — the register working set batched into ONE
          hypercall in and one out, since WHP's register API is vectorized.
          Decodes the x86-64 Linux ABI (`rax`; `rdi rsi rdx r10 r8 r9` —
          note **r10, not rcx**, which `syscall` clobbers).
        * `runtime/whp_mem.hpp` — bounds-checked guest RAM spans plus the
          GVA→GPA page-table walk. x86-64 long mode REQUIRES paging, so
          unlike the flat arm64 space every guest pointer must be walked,
          and buffers that straddle non-contiguous pages are stitched.
        * `runtime/whp_win32.hpp` — the Linux/Win32 translation layer
          (open flags, `struct stat` with asserted offsets, errno, the
          1601↔1970 epoch, UTF-16 `\\?\` paths).
        * `runtime/whp_trap.hpp` — models `SyscallTrap`, so the SAME
          `runtime::Cpu` loop drives it. Distinguishes our syscall trap from
          a GENUINE `#UD` by checking the faulting bytes are `0F 05`, so a
          guest crash becomes SIGILL instead of a wild syscall dispatch.
        * `runtime/whp_load.hpp` — the ELF loader and SysV startup stack.
          Maps each PT_LOAD at 4KiB granularity with its declared
          permissions, so W^X is REAL (a read-only segment is genuinely
          unwritable); builds argc/argv/envp/auxv with AT_PHDR resolved via
          PT_PHDR or the file-offset fallback, and AT_RANDOM from
          RtlGenRandom.
        * `runtime/whp_fd.hpp` — the guest fd table over Win32 HANDLEs.
          stdio is DUPLICATED (a guest closing fd 1 must not close
          linuxity's stdout) and fds 3..8 are reserved so the guest's own
          descriptors start at 9, matching a real login session — the
          collision this prevents corrupted a database on the macOS backend.
          dup() shares the handle, so the file position is shared as Linux's
          open-file-description semantics require.
        * `runtime/whp_mm.hpp` — mmap/munmap/mprotect/brk. A bitmap frame
          allocator supplies guest-physical pages; the VIRTUAL bookkeeping
          reuses `hvf_vma.hpp`'s `AddressSpace` rather than reimplementing
          interval splitting. Anonymous memory is LAZY (overcommit), so a
          libc that maps a large arena and touches a fraction works on a
          small guest.
        * `runtime/whp_sys.hpp` — ~70 syscalls served against Win32: file
          I/O, stat, getdents64, directories, descriptors, time, identity,
          and `arch_prctl(ARCH_SET_FS)` (without which no TLS access, errno
          included, works). Rootfs paths resolve ".." LEXICALLY and clamp at
          the root, so a guest cannot escape the rootfs.
        * `host/win_posix.hpp` — the POSIX corners the Win32 CRT lacks
          (`mkdir` arity, `S_ISLNK`, `O_CLOEXEC`, `d_type`), confined to one
          header so the core stays free of `#ifdef`s.

      **The second half of the interception trick: `#PF` is intercepted too.**
      `WHvRunVpExitReasonMemoryAccess` reports only NESTED paging failures
      (a guest-physical page absent from the partition). A fault in the
      GUEST'S OWN page tables is an architectural `#PF` the guest must
      handle — and a guest with no kernel, IDT or handler escalates it
      `#PF -> #DF -> triple fault`, arriving as
      `UnrecoverableException` with no address. So vector 14 goes into the
      same `ExceptionExitBitmap` as `#UD`, making linuxity the guest's
      page-fault handler. That is what makes lazy mmap and a growing heap
      implementable without a guest kernel. The fault address comes from the
      exception context (CR2 is not yet architecturally visible on an
      intercepted exception), and a PROTECTION fault on a present page goes
      straight to SIGSEGV rather than looping forever trying to back a page
      that is already there.

      **Statically linked x86-64 binaries run end to end** with a working
      syscall surface: `tools/make_syscall_elf.py` generates a binary that
      exercises uname, a growing heap, a 1 MiB anonymous mmap with
      first/last-page writes, openat+read through the rootfs, and TLS via
      `%fs` — all six checks pass.

      Remaining: `ld.so` loading is wired (PT_INTERP resolved through the
      rootfs, AT_BASE set, control entering the interpreter) but needs a
      real rootfs to verify; then threads (clone), signal delivery, sockets,
      and fork/exec as NT processes.
- [ ] **M7 (optional): foreign arch.** x86-64 rootfs on arm64 via FEX.

## Non-goals

- Being a sandbox. Compatibility shims (accepting `setuid`, Landlock no-op)
  say yes on purpose. That said, holes that make the guest see the *host*
  filesystem instead of its rootfs are correctness bugs and get fixed (e.g.
  the seccomp filter returns ENOSYS for i386/x32/io_uring, which would bypass
  path translation).
- Booting a real Linux kernel. That is a microVM; use one.
