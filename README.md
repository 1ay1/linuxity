# linuxity

A **portable, type-theoretic implementation of the Linux userspace ABI**.

Not a VM. Not instruction emulation. `linuxity` is a userspace
re-implementation of the Linux kernel/user contract: guest ELF binaries run
**directly on the host CPU at native speed** while the runtime *is the
kernel* — it services their syscalls.

The distro you install is decoupled from the instruction set:

| | what it is | runs at |
|---|---|---|
| **the environment** | an Arch / Alpine / Debian rootfs — files, `/proc`, the package manager, the ABI contract | — |
| **the guest code** | ELF binaries in that rootfs | **native CPU speed** |
| **the ISA** | whatever the host is (x86-64 here) | native — no emulation |

So on an x86-64 host you install the **x86-64 build** of the distro and every
instruction runs bare on the CPU — no VM, no `/dev/kvm`, no interpreter. A
*foreign*-arch rootfs is the only case that needs a binary-translation
backend (FEX / Rosetta-style), and that plugs in behind the same ABI at the
ISA boundary — it is not the core.

```
            Linux program (AArch64 ELF)
                      │
             Linux syscall ABI            ← abi/syscall.hpp
                      │
        ┌──────────────────────────┐
        │        Kernel            │      ← the *product* of subsystems
        │  VFS · Process · Memory  │      ← kernel/subsystem.hpp (concepts)
        │  IPC · Net · /proc · …   │
        └──────────────────────────┘
             │        │        │
          PosixHost  Darwin   Windows      ← host/host.hpp (a tiny concept)
             │        │        │
          Linux    macOS/iOS  Windows
```

The guest **only ever talks to the runtime**, never the host OS.

## The design, in types

| Idea | Encoded as |
|------|-----------|
| A syscall is a total function `Args → Errno + Value` | `Result<T> = std::expected<T, Errno>` |
| errno can't be confused with a value/fd/pid | `enum class Errno`, strong `Id<Tag>` newtypes |
| `read` / `write` / `open` / `mount` are one subsystem | `concept Vfs` |
| the kernel is the *product* of subsystems | `concept IsKernel = Vfs && Process && Memory` |
| the host is a swappable primitive layer | `concept Host` (static polymorphism, zero vtables) |
| a guest pointer must never be dereferenced un-validated | `UAddr` / `UserPtr<T>` — un-dereferenceable by construction |
| do-notation / `?` for error propagation | `LX_TRY(expr)` |

Because subsystems and the host are **concepts**, the syscall dispatcher and
the whole runtime are written *once, generically*, and instantiated against:
the production kernel, a host-free `MockKernel` in tests, or a future
JIT-backed kernel — with no virtual dispatch in the hot path.

## Layout

- `include/linuxity/abi/`    — `result.hpp`, `types.hpp`, `syscall.hpp`
- `include/linuxity/kernel/` — `subsystem.hpp` (concepts), `authority.hpp` (the host-authority boundary), `file_namespace.hpp` (mount table + cwd + fd table + realm classifier), `kernel.hpp`
- `include/linuxity/vfs/`    — `inode.hpp` (FileSystem concept), `tmpfs.hpp` (in-memory backend), `hostfs.hpp` (on-disk rootfs backend), `procfs.hpp` (synthesized /proc), `vfs.hpp` (mount table + path resolution)
- `include/linuxity/host/`   — `host.hpp` (the concept), `posix_host.hpp` (Linux/Darwin backend)
- `src/main.cpp`             — wires host → kernel → ABI, issues guest syscalls
- `tests/`                   — host-free type-algebra, authority, and VFS tests

## Build

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build

# run a NATIVE Linux binary under the runtime (native speed, no VM):
./build/linuxity /path/to/binary [args...]

# ...including real distro binaries with the dynamic linker:
./build/linuxity /usr/bin/uname -a
#   -> Linux linuxity 6.6.0-linuxity #1 linuxity portable Linux ABI x86_64
./build/linuxity /usr/bin/id
#   -> uid=0(root) gid=0(root) ...      (identity VIRTUALIZED by linuxity)

# mount an extracted distro rootfs as the guest '/' (UNPRIVILEGED — no
# chroot, no root): every guest path is translated to the real host path
# under the rootfs before the syscall runs; /proc is synthesized.
./build/linuxity --root ./alpine-rootfs /bin/sh

# proof the guest lives in the rootfs, not the host:
./build/linuxity --root ./my-rootfs /bin/cat /etc/os-release
#   -> the ROOTFS os-release, even though the host's is different
./build/linuxity /bin/cat /proc/version
#   -> Linux version 6.6.0-linuxity (linuxity@linuxity) ...  (SYNTHESIZED)
```

Requires a C++23 compiler (`std::expected`, concepts). Tested with GCC 16.
Native execution uses a `ptrace` trap backend on Linux/x86-64: the guest runs
its own instructions on the CPU; each syscall is either **virtualized** by
linuxity's subsystems or **forwarded** to the host kernel acting on the guest.

## Status

**Real native Linux binaries — including dynamically-linked distro programs —
run under the runtime today, and the guest's ENTIRE filesystem view is now
linuxity's own virtual namespace.** `/bin/echo`, `/usr/bin/id`,
`/usr/bin/uname`, `date`, `cat` all execute natively on the CPU while
linuxity services their syscalls. Proofs of the model:

- `uname -a` reports **`Linux linuxity 6.6.0-linuxity`** (not the host
  kernel) — we intercept `uname`, synthesize linuxity's identity, and
  `copy_out` into the guest buffer.
- `id` / `whoami` report **`uid=0(root)`** — virtualized `getuid`/`getgid`
  return the virtual world's root.
- `cat /proc/version` reports **`Linux version 6.6.0-linuxity`**,
  `/proc/self/status` reports **`Pid: 1`, `Uid: 0`**, `/proc/mounts` reports
  **linuxity's** mount table — `/proc` is fully **synthesized**, not the host's.
- `--root <rootfs> /bin/cat /etc/os-release` reads the **rootfs** file, not
  the host's — and needs **no privilege and no chroot**.
- `--root <rootfs> /bin/sh -c '/bin/cat /etc/os-release | /bin/head -1'` runs a
  **shell that forks and execs coreutils**, and every child stays inside the
  rootfs — the whole process tree lives in linuxity's world, no host escape.
- the guest can **write** (`/tmp`, `/run`, `/var`, …) and the writes land in a
  copy-on-write **overlay upper** layer — the on-disk rootfs stays **pristine**,
  never mutated by the guest.
- **`htop` and `top` run as real process monitors** — they read linuxity's
  synthesized `/proc/stat`, `/proc/meminfo`, `/proc/uptime`, `/proc/loadavg`
  and `/sys` (CPU topology, cpufreq, hwmon temperatures), enumerate `/proc`
  and each `/proc/<pid>/task/<tid>` (virtualized `getdents64`), and render the
  **live process tree**: run a shell that backgrounds `sleep`/`yes` and `htop`
  shows every one with its real command line — `sh`, `sleep 10`, `yes`, `htop`
  — because the trap feeds every fork/exec/exit into linuxity's process table.
  `free`, `uptime`, `ls /proc`, `ls /proc/1` all work the same way.
- **Signals reach the right task.** A guest `kill`/`tgkill`/`tkill` names a pid
  in *linuxity's* namespace, so the raw number is never forwarded (it would
  signal an unrelated host task). The runtime translates the target to the
  traced task's real host tid and delivers the signal there — a shell can
  background `sleep 30 &` then `kill`/`kill -9` it, `kill -0` probes liveness,
  and an unknown pid returns `ESRCH`.

### How the filesystem is virtualized

Every path-taking syscall (`openat`, `newfstatat`, `statx`, `access`,
`readlinkat`, `chdir`, `getcwd`, …) is resolved through a **`FileNamespace`**
— a mount table + guest cwd + guest-fd table — and classified into one realm:

- **host-backed** (a rootfs mount): the guest path is translated to the real
  host path under the rootfs, and the syscall is **redirected** (its path
  register is rewritten in the child, then forwarded). Because the child ends
  up with a real host fd, native `ld.so` `mmap`s the actual library file —
  this is what carries a dynamically-linked distro binary to `main()`. A
  write-intent open (`O_WRONLY`/`O_RDWR`/`O_CREAT`/`O_TRUNC`) resolves to a
  copy-on-write **overlay upper** dir (copying the file up from the read-only
  lower first), so the pristine rootfs is never mutated.
- **virtual** (`/proc`, `/sys`, and future tmpfs, overlays): the bytes are
  synthesized and either written straight into guest memory (`read`/`stat`/
  `statx`) or materialized into a real fd the child can read *and* `mmap`
  (**inject**). A virtual **directory** is backed by a real empty temp dir (so
  `O_DIRECTORY` opens succeed) and its `getdents64` is fully virtualized — the
  entries are synthesized from linuxity's state.

`/proc` is comprehensive: `/proc/{stat,meminfo,cpuinfo,uptime,loadavg,version,
cmdline,filesystems,mounts,sys/...}` plus the per-process tree
`/proc/<pid>/{stat,statm,status,cmdline,comm,io,maps,task/<tid>/...}`, all
generated from linuxity's **process table** (pid 1 = init, uid 0, its own
numbers). `/sys` is synthesized too — CPU topology (`devices/system/cpu`,
`cpufreq/policyN/scaling_cur_freq`), `hwmon` temperatures, one virtual block
device, cgroup v2 stubs — so a hardware monitor discovers linuxity's virtual
machine, not the box it runs on. That is why a process/hardware monitor shows
linuxity's world.

So the guest never sees the host tree: `--root` makes `/` the rootfs and
`/proc` reports linuxity's world — all with zero privilege, no VM, no chroot.

**The trap traces the whole process tree.** A real shell forks and execs
children and blocks in `wait4()`/`read()` on them, so the `ptrace` backend is
multi-process and event-driven: it traces every descendant
(`PTRACE_O_TRACEFORK|VFORK|CLONE|EXEC`), waits on any task, and never blocks on
one while another can run — so a parent's blocking `wait4` doesn't deadlock its
child. Each task's syscall entry/exit is told apart robustly by the kernel's
`rax == -ENOSYS` entry priming. A forked `cat` in a pipeline therefore lives in
exactly the same virtual namespace as its parent shell; it never escapes to
the host filesystem.

Memory (`mmap`/`brk`/`mprotect`) stays forwarded so native libc reaches
`main()`; identity, credentials, lifecycle, `uname`, **signal delivery**, and
now the **whole file path** are virtualized. In place and proven by 11 test
suites:

- the type algebra, subsystem concept lattice, and authority boundary;
- a real **VFS** (mount table, path resolution) with **tmpfs** and a
  **HostFs** backend, plus the **`FileNamespace`** the syscall path routes
  through and a synthesized **procfs**;
- an **ELF64 loader** (PT_LOAD, .bss zero-fill, PT_INTERP) into a typed guest
  **address space**, plus SysV AMD64 **stack/auxv** init;
- an arch-neutral **syscall dispatcher** (per-arch tables → canonical `Sysno`)
  with a **virtualize / forward / redirect / inject / signal** classifier,
  driven by a concept-based **trap** loop and a real **multi-process** `ptrace`
  backend that traces the entire forked/exec'd process tree.

**The live process tree feeds `/proc`.** The `ptrace` backend observes every
fork/vfork/exec/exit in the guest tree and emits neutral lifecycle events; the
execution loop folds them into the kernel's process table (mapping host tids to
linuxity's own tiny pid space, root = pid 1, real argv captured at `exec`). So
`/proc` — and every monitor reading it — reflects linuxity's real, live
processes, not the host's.

The road ahead: `readlink` synthesis for `/proc/self/exe`, richer `futex`/
`epoll` coverage for heavily-threaded programs, and reaching an interactive
`/bin/sh` on a real Arch/Alpine rootfs. The architecture is fixed and
machine-checked.
