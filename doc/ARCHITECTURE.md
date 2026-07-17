# linuxity — Architecture & Internals

How linuxity runs a native Linux userland without a VM, an emulator, or root.
This is the *why* and the *how it works*; for the *how to use it* see
[`MANUAL.md`](MANUAL.md).

---

## Table of contents

1. [The thesis](#1-the-thesis)
2. [High-level flow](#2-high-level-flow)
3. [Source layout](#3-source-layout)
4. [The type discipline](#4-the-type-discipline)
5. [The trap backend (native execution)](#5-the-trap-backend-native-execution)
6. [Syscall fates: virtualize / forward / redirect / inject / signal](#6-syscall-fates)
7. [The seccomp fast path](#7-the-seccomp-fast-path)
8. [The filesystem namespace](#8-the-filesystem-namespace)
9. [The overlay (copy-on-write)](#9-the-overlay-copy-on-write)
10. [Shadow metadata (fake-root)](#10-shadow-metadata-fake-root)
11. [Process model & pid namespace](#11-process-model--pid-namespace)
12. [Signals](#12-signals)
13. [Synthesized /proc, /sys, /dev](#13-synthesized-proc-sys-dev)
14. [The loader & exec rewriting](#14-the-loader--exec-rewriting)
15. [Resource governance](#15-resource-governance)
16. [Extending linuxity](#16-extending-linuxity)

---

## 1. The thesis

**linuxity is a userspace re-implementation of the Linux kernel/user contract.**
A guest ELF binary executes its own instructions directly on the host CPU at
full native speed. The *only* thing linuxity intercepts is the syscall boundary:
when the guest issues a system call, control traps into linuxity, which either
services it from its own subsystems or forwards it to the host kernel acting on
the guest's behalf.

```
        Linux program (native ELF)
                  │
         Linux syscall ABI                ← abi/syscall.hpp
                  │
      ┌──────────────────────────┐
      │        Kernel            │        ← the product of subsystems
      │  VFS · Process · Memory  │        ← kernel/subsystem.hpp (concepts)
      │  /proc · /sys · /dev · … │
      └──────────────────────────┘
                  │
              PosixHost                    ← host/host.hpp (a tiny concept)
                  │
                Linux
```

Consequences of this design:

- **No VM, no `/dev/kvm`, no guest kernel.** Guest code is host code.
- **No emulation.** No interpreter, no JIT for the *common* (same-ISA) case.
- **No privilege.** Path translation replaces `chroot`; nothing needs root.
- **The ISA is decoupled from the distro.** You install the host-ISA build of a
  distro; the same ABI would sit above a binary-translation backend for a
  foreign ISA, but that is a plug-in, not the core.

---

## 2. High-level flow

`src/main.cpp` wires everything and starts the guest:

1. **Parse flags** (`--root`, `--bind`, resource limits).
2. **Build the `MachineSpec`** — one source of truth for the virtual machine
   (CPU count, RAM, kernel release). Resource limits *derive* it, so belief ==
   enforced reality.
3. **Mount the namespace** — `mount_host("/", rootfs, upper)` for the rootfs
   with a copy-on-write overlay, plus virtual `/proc`, `/sys`, `/dev`. Then
   `--bind` mounts and DNS auto-provisioning.
4. **Resolve the exec target** — translate the guest program path to its real
   host path, refuse a foreign-arch binary, and rewrite a dynamic ELF or `#!`
   script so its interpreter is exec'd correctly (see [§14](#14-the-loader--exec-rewriting)).
5. **Launch the trap** — `PtraceTrap` forks the child, which execs the guest;
   the parent traces it.
6. **Run the loop** — `runtime::Cpu` (in `trap.hpp`) drives the guest: for each
   trapped syscall it calls the dispatcher (`abi::Syscalls::dispatch`) and
   applies the chosen fate.

---

## 3. Source layout

| Path | Role |
|---|---|
| `abi/result.hpp` | `Result<T> = std::expected<T, Errno>`, the `Errno` enum. |
| `abi/types.hpp` | Strong newtypes: `UAddr`, `Id<Tag>`, `Regs`, `Arch`. |
| `abi/sysno.hpp` | Per-arch syscall number → canonical `Sysno` decode. |
| `abi/syscall.hpp` | **The dispatcher.** Classifies every syscall into a fate. |
| `kernel/subsystem.hpp` | The `Vfs` / `Process` / `Memory` concepts; `IsKernel`. |
| `kernel/kernel.hpp` | The production `Kernel` — the product of subsystems. |
| `kernel/authority.hpp` | The host-authority boundary. |
| `kernel/file_namespace.hpp` | Mount table + cwd + fd table + realm classifier + overlay. |
| `kernel/meta_store.hpp` | Shadow perms/owner journal (fake-root). |
| `kernel/process_table.hpp` | The live guest process table `/proc` is built from. |
| `kernel/machine.hpp` | `MachineSpec` — the virtual machine's canonical spec. |
| `kernel/resources.hpp` | `ResourceSpec` — limits + derived machine. |
| `vfs/{tmpfs,hostfs,procfs,sysfs,devfs,vfs,inode}.hpp` | Filesystem backends + synthesizers. |
| `loader/{elf,loader,interp,stack}.hpp` | ELF64 reader, PT_INTERP/shebang inspection, stack/auxv. |
| `mm/address_space.hpp` | Typed guest address space. |
| `runtime/trap.hpp` | The generic `Cpu` loop + the `SyscallTrap` concept. |
| `runtime/ptrace_trap.hpp` | The real Linux `ptrace` multi-process backend. |
| `runtime/seccomp_filter.hpp` | The BPF filter (`kTrappedX86_64`, `install_trap_filter`). |
| `runtime/resource_governor.hpp` | cgroup v2 / setrlimit enforcement. |
| `host/{host,posix_host}.hpp` | The `Host` concept and its POSIX backend. |
| `src/main.cpp` | The wiring / entry point. |

---

## 4. The type discipline

The whole runtime is written **once, generically**, over concepts — no virtual
dispatch in the hot path.

| Idea | Encoded as |
|---|---|
| A syscall is a total function `Args → Errno + Value` | `Result<T> = std::expected<T, Errno>` |
| errno can't be confused with a value/fd/pid | `enum class Errno`, `Id<Tag>` newtypes |
| read/write/open/mount is one subsystem | `concept Vfs` |
| the kernel is the product of subsystems | `concept IsKernel = Vfs && Process && Memory` |
| the host is a swappable primitive layer | `concept Host` (static polymorphism) |
| a guest pointer is never dereferenced un-validated | `UAddr` / `UserPtr<T>` |
| do-notation / `?` error propagation | `LX_TRY(expr)` |

Because subsystems and the host are concepts, the dispatcher instantiates
against the production kernel, a host-free `MockKernel` in tests, or a future
JIT-backed kernel — all with zero vtables.

---

## 5. The trap backend (native execution)

`runtime/ptrace_trap.hpp` is the Linux backend. The child executes its own
instructions on the CPU; each syscall stops back into the tracer at syscall
entry, where the tracer picks a fate.

Key properties:

- **Multi-process, event-driven.** It traces every descendant
  (`PTRACE_O_TRACEFORK | VFORK | CLONE | EXEC`), waits on *any* task, and never
  blocks on one task while another can run — so a parent's blocking `wait4`
  can't deadlock its child.
- **Shared guest memory.** `PtraceTrap` is both the trap backend *and* the
  guest-memory accessor: it reads/writes the child's real pages via
  `process_vm_readv`/`writev` (with a `/proc/<pid>/mem` fallback), so `copy_in`
  / `copy_out` operate on live guest memory.
- **Entry/exit disambiguation** uses the kernel's `rax == -ENOSYS` entry
  priming, robust across the fork/exec event stops.

The generic loop lives in `runtime/trap.hpp` (`Cpu`), written against the
`SyscallTrap` concept so it is backend-agnostic.

---

## 6. Syscall fates

`abi::Syscalls::dispatch(Regs)` returns an `Outcome` that is exactly one of:

| Fate | Meaning | Examples |
|---|---|---|
| **virtualize** | linuxity answers directly; no real syscall runs. | `getpid`, `uname`, `getdents64` on a virtual dir, job-control `ioctl`. |
| **forward** | Let the host kernel run it in the child unchanged. | `mmap`, `brk`, `mprotect`, `read`/`write` on a real fd, `rt_sigaction`. |
| **redirect** | Rewrite a path-argument register to the translated host path, then forward. | `openat`, `newfstatat`, `execve` of a static native ELF, the mutation family. |
| **inject** | Materialize synthesized bytes into a real fd (temp file / memfd) so the child gets a readable **and** mmappable fd. | opening a virtual file like `/proc/cpuinfo`. |
| **signal** | Deliver a signal to a guest pid, translated to the real host tid. | `kill`, `tgkill`, `tkill`. |
| **exec-interp** | Rewrite a dynamic-ELF/`#!` exec to run its interpreter. | dynamic distro binaries, shebang scripts. |

The dispatcher is arch-neutral: `sysno.hpp` decodes the raw per-arch number to a
canonical `Sysno`, and the switch is on that identity.

---

## 7. The seccomp fast path

Trapping *every* syscall via `PTRACE_SYSCALL` is slow. Instead
(`runtime/seccomp_filter.hpp`), linuxity installs a classic-BPF seccomp filter
in the guest that returns:

- `SECCOMP_RET_TRACE` **only** for the ~90 syscall numbers in `kTrappedX86_64`
  (path-carrying, identity, exec, wait, ioctl, uname, mutation, …), and
- `SECCOMP_RET_ALLOW` for everything else.

The tracer arms `PTRACE_O_TRACESECCOMP` and drives tasks with `PTRACE_CONT`, so
non-intercepted syscalls (`read`, `write`, `mmap`, `futex`, `lseek`, and any
pure-CPU code between them) run with **zero** ptrace overhead. Result: **~140×**
on a 2M-syscall microbenchmark (0.35 s vs 50 s).

**Bootstrap subtlety.** `execve`/`execveat`/`gettid`/`tgkill`/`tkill`/`close`
are deliberately **left native** (not in `kTrappedX86_64`): a trapped syscall in
the window between the child installing the filter and the tracer arming
`TRACESECCOMP` would `ENOSYS`-fail and abort the launch. Exec is still observed
via `PTRACE_EVENT_EXEC`, and guest binaries load through the (filtered,
path-translated) `openat`.

**Correctness.** The `run_seccomp` test proves the fast path is byte-for-byte
equivalent to the `PTRACE_SYSCALL` fallback. `LINUXITY_NO_SECCOMP=1` forces the
fallback (also auto-selected when the host lacks `CONFIG_SECCOMP_FILTER`).

> **Maintenance rule:** keep `kTrappedX86_64` in lock-step with the non-default
> cases of `dispatch()`. A *missing* number silently runs raw (a bug — an
> untranslated path could hit the host's `/usr`); an *extra* one only costs a
> needless stop. When in doubt, include it — except the six bootstrap-fragile
> ones above.

---

## 8. The filesystem namespace

`kernel/file_namespace.hpp` resolves every path-taking syscall (`openat`,
`newfstatat`, `statx`, `access`, `readlinkat`, `chdir`, `getcwd`, the mutation
family, …) through a **mount table + guest cwd + guest-fd table**, classifying
each path into one realm:

- **host-backed** (a rootfs or bind mount): the guest path is translated to the
  real host path under the mount base; the syscall is **redirected**. Because
  the child ends up with a real host fd, native `ld.so` can `mmap` the actual
  library file — this is what carries a dynamic distro binary to `main()`.
- **virtual** (`/proc`, `/sys`, `/dev`, overlays): bytes are synthesized and
  either written straight into guest memory (`read`/`stat`) or **injected** into
  a real fd. A virtual directory is backed by a real empty temp dir (so
  `O_DIRECTORY` opens succeed) and its `getdents64` is fully virtualized.
- **absent**: yields the appropriate errno.

**Mounts** are longest-prefix (like the real mount table). Rootfs **symlinks**
(absolute, like Alpine's `/bin/sh -> /bin/busybox`, or `/lib -> /usr/lib`) are
chased and re-rooted inside the mount; **cross-mount** links (e.g.
`/etc/mtab -> /proc/self/mounts`) re-classify through the whole namespace so a
virtual target correctly lands in the virtual realm.

---

## 9. The overlay (copy-on-write)

When `--root` is given, the rootfs is mounted with a writable **upper** layer
(`/tmp/linuxity-upper-<pid>`) stacked over the read-only rootfs **lower** —
exactly the overlayfs model:

- A **write-intent** open (`O_WRONLY`/`O_RDWR`/`O_CREAT`/`O_TRUNC`) or any
  mutation resolves to the upper layer, copying the file up from the lower on
  first write.
- Directories that exist only in the lower are **mirrored up** on first
  child-write, so a create in the upper doesn't `ENOENT` on a missing parent.
- Reads of not-yet-copied files fall through to the lower.
- `getdents64` on an overlay directory returns the **union** of both layers
  (upper wins on name collision), so `ls /` shows the rootfs even though the
  upper starts empty.

The pristine on-disk rootfs is **never mutated**.

The full **mutation family** — `mkdir`, `rmdir`, `unlink`, `rename`, `link`,
`symlink`, `chmod`, `chown`, `truncate`, `utimensat`, `mknod`, and their `*at`
forms — all resolve to the upper layer. Two-path ops (`rename`/`link`) rewrite
*both* operands; a `symlink`'s literal target is preserved as a guest path
(resolved later through the namespace, not the host).

---

## 10. Shadow metadata (fake-root)

The linuxity process is unprivileged, so it can't really `chown`, and a
host-backed `stat` would leak the host inode's owner/mode. `kernel/meta_store.hpp`
closes this:

- `chmod`/`fchmodat`/`fchmod`/`chown`/`lchown`/`fchown`/`fchownat` **record** the
  guest-intended `(mode, uid, gid)` in a per-path store.
- `stat`/`lstat`/`statx`/`newfstatat` **overlay** the recorded values onto the
  host result in the same stopped syscall-exit window (a post-redirect hook,
  before the guest can read the buffer): uid/gid default to root (0/0) but honor
  a recorded owner, and mode keeps the host file-type bits while taking the
  guest-intended permission+special bits (07777).

So `chmod 4755` + `chown 1000:1000` then `stat` returns `4755 1000:1000` — the
setuid bit and non-root owner survive even though the real inode never changed.

The store persists as one consolidated `.linuxity-meta` **journal** in the
overlay upper layer (never guest-visible — filtered from directory listings),
append-only with tombstones so `unlink`/`rename` stay accurate, and it replays
across runs. This is strictly better than proot's per-file `.proot-meta-file.*`
sidecars, which pollute the guest tree.

---

## 11. Process model & pid namespace

The `ptrace` backend observes every fork/vfork/exec/exit in the guest tree and
emits neutral lifecycle events; the loop folds them into the kernel's
`process_table`. Crucially, host tids are mapped into linuxity's **own tiny pid
space** (root = pid 1, ppid 0):

- `getpid`/`gettid`/`getppid`/`getpgid`/`getsid`/`setsid` answer from the trap's
  live task map, so a forked child sees its *own* pid with its parent's pid.
- `fork`/`clone`/`wait4` return values are translated host↔guest, and `wait4`'s
  pid argument is translated guest→host, so `$!`, `jobs`, and `wait` are
  coherent. (proot leaks host pids here — linuxity does not.)
- The pid-to-tid map is retained past child exit so `wait4` can still translate
  a reaped pid.

The live tree feeds `/proc`, so `htop`/`top`/`ps` show linuxity's real processes
with their real command lines.

---

## 12. Signals

A guest `kill`/`tgkill`/`tkill` names a pid in *linuxity's* namespace — the raw
number is never forwarded (it would hit an unrelated host task). The runtime
translates the target to the traced task's real host tid and delivers there:

- `kill`/`kill -9` work; `kill -0` probes liveness; an unknown pid returns
  `ESRCH`.
- Signal **dispositions and masks** (`rt_sigaction`/`rt_sigprocmask`) are
  forwarded to the real task, so a guest `SIGTERM` handler actually **runs**
  instead of the process being killed.

---

## 13. Synthesized /proc, /sys, /dev

- **`/proc`** (`vfs/procfs.hpp`): `/proc/{stat,meminfo,cpuinfo,uptime,loadavg,
  version,cmdline,filesystems,mounts,sys/...}` plus the per-process tree
  `/proc/<pid>/{stat,statm,status,cmdline,comm,io,maps,task/<tid>/...}`, all
  generated from the process table + `MachineSpec`. `/proc/self/exe`, `cwd`,
  `root` are synthesized against the namespace, so a program that locates its
  own binary reads the guest path.
- **`/sys`** (`vfs/sysfs.hpp`): CPU topology (`devices/system/cpu`,
  `cpufreq/policyN/...`), hwmon temperatures, a virtual block device, cgroup v2
  stubs — a hardware monitor discovers linuxity's machine.
- **`/dev`** (`vfs/devfs.hpp`): `/dev/null`, `/dev/zero`, `/dev/urandom`
  **redirect** to the host's real character devices (native `read`/`write`/`mmap`
  semantics), and `/dev/std{in,out,err}` map to `/proc/self/fd/{0,1,2}`.

All three read the **same** `MachineSpec` instance the resource limits derive,
so they can never disagree with `sysinfo`/`sched_getaffinity`.

---

## 14. The loader & exec rewriting

The host kernel resolves an exec target's `PT_INTERP` (the dynamic linker)
against the *host* root, where a guest rootfs's `/lib/ld-musl-*.so.1` doesn't
exist. `loader/interp.hpp` solves this without chroot:

- **`inspect_file_header()`** reads the first 256 bytes once and classifies the
  file: static ELF, dynamic ELF (with its `PT_INTERP`), foreign-arch ELF,
  shebang script (with its single optional arg), or non-executable. (This is
  termux-exec's `inspectFileHeader`, modernized into one pass.)
- **Foreign-arch refusal:** `read_elf_machine()` compares `e_machine` to the
  host ISA; a wrong-ISA target is refused with a clean `ENOEXEC` (in-guest) or a
  clear diagnostic (CLI) rather than a cryptic loader crash.
- **Dynamic ELF:** exec the interpreter directly with the program as its
  argument; the loader then opens the program and its libraries via ordinary
  (redirected) `openat` inside the rootfs.
- **`#!` script:** resolve the shebang ourselves and exec the interpreter with
  the script as a **guest** path (its own `openat` redirects), chaining the
  interpreter's own `ld.so` when the interpreter is itself dynamic — avoiding
  the double-rooting the host kernel would otherwise cause.

`loader/{elf,loader,stack}.hpp` also provide a full ELF64 loader (PT_LOAD,
`.bss` zero-fill) into a typed address space with SysV AMD64 stack/auxv init,
used by the non-ptrace paths and tests.

---

## 15. Resource governance

`kernel/resources.hpp` + `runtime/resource_governor.hpp` keep the guest's
**belief** (what it reads) equal to the **enforced reality** (what the host lets
it use):

- One `ResourceSpec` both writes the host-side bound and **derives** the
  `MachineSpec` (`--memory 512M` → `MemTotal: 524288 kB`; `--cpus 2` → `nproc`
  2), so a program sizes itself to the bound it will be held to.
- **cgroup v2** is preferred (`memory.max` / `cpu.max` / `pids.max` /
  `cpuset.cpus`). If controllers aren't delegated, linuxity re-execs itself
  through `systemd-run --user --scope` to obtain a delegated scope.
- **`setrlimit`** (`RLIMIT_AS`) is the fallback where no cgroup can be created.

The child adopts the enforcement via a pre-exec hook, so every descendant
inherits it.

---

## 16. Extending linuxity

**Add a virtualized syscall:**

1. Add a `case Sysno::foo:` in `abi/syscall.hpp::dispatch()` returning the
   appropriate `Outcome`.
2. If `foo` needs interception, add its number to `kTrappedX86_64` in
   `runtime/seccomp_filter.hpp` (and confirm the `sysno.hpp` decode).
3. Add a regression test under `tests/` and wire it into `tests/CMakeLists.txt`.

**Add a virtual file/dir:** extend the relevant producer in `vfs/procfs.hpp`,
`vfs/sysfs.hpp`, or `vfs/devfs.hpp` — they return synthesized bytes/entries the
namespace injects.

**Add a new host backend:** implement the `Host` concept
(`host/host.hpp`); the whole runtime instantiates against it with no other
changes. A non-`ptrace` platform would supply a different `SyscallTrap`
(`runtime/trap.hpp`) instead of `PtraceTrap`.

**Testing philosophy:** subsystems and the host are concepts, so most logic is
tested host-free (type algebra, VFS, loader, file namespace, meta store). The
`run_*` tests drive real static/dynamic binaries through the actual `ptrace`
backend end to end.

---

*See also: [`MANUAL.md`](MANUAL.md) (user guide),
[`README.md`](../README.md) (overview),
[`reference-study.md`](reference-study.md) (technique provenance from
proot/termux).*
