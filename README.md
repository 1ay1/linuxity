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

## Documentation

- **[doc/MANUAL.md](doc/MANUAL.md)** — the user manual: install, get a rootfs,
  every CLI flag and environment variable, a task cookbook, resource limits,
  bind mounts, DNS, fake-root, package managers, troubleshooting, and an FAQ.
  **Start here to *use* linuxity.**
- **[doc/ARCHITECTURE.md](doc/ARCHITECTURE.md)** — the internals: the trap
  backend, syscall fates, the seccomp fast path, the filesystem namespace and
  copy-on-write overlay, shadow-metadata fake-root, the pid namespace, signals,
  synthesized `/proc`/`/sys`/`/dev`, the loader/exec rewriting, resource
  governance, and how to extend it. **Read this to *understand* linuxity.**
- **[doc/reference-study.md](doc/reference-study.md)** — how the techniques map
  from proot / termux-exec / proot-distro / ish onto linuxity, and why.

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
  and an unknown pid returns `ESRCH`. Signal **dispositions and masks**
  (`rt_sigaction`/`rt_sigprocmask`) are forwarded to the real task, so a guest
  `SIGTERM` handler actually **runs** instead of the process being killed.
- **Every task has a coherent identity.** `getpid`/`gettid`/`getppid`/
  `getpgid`/`getsid`/`setsid` answer from the trap's live task map, so a forked
  child sees its *own* pid with its parent's pid — not a fixed “pid 1”. init is
  pid 1 with ppid 0.
- **`/proc/self/exe` (and `<pid>/exe`, `cwd`, `root`) are synthesized** against
  linuxity's namespace, so a dynamic loader or runtime that finds its own
  binary reads the guest path (`/bin/foo`), never the host path.
- **Shell pipelines work.** `echo a b | wc -w`, `... | tr ... | wc -l`, loops,
  `awk`, backgrounded jobs — the whole forked pipeline stays in linuxity's
  namespace and its members signal, wait on, and enumerate each other correctly.
- **A real distro runs.** Point `--root` at an extracted **Alpine** (musl)
  rootfs and `/bin/sh`, `/bin/ls`, `/bin/cat`, `busybox` and friends all run:
  dynamically-linked PIE binaries load through their **translated PT_INTERP**
  (the musl/glibc dynamic linker), absolute rootfs **symlinks** (`/bin/sh ->
  /bin/busybox`) re-root inside the rootfs, and nested `execve`s of dynamic
  programs are rewritten the same way — so a shell spawns real coreutils.
  `uname -a` reports linuxity, `cat /etc/alpine-release` reads the real distro
  file, `id` is root, a pipeline of 82 busybox applets counts correctly.
- **The guest sees a root-owned world.** A rootfs unpacked by an unprivileged
  user is owned on disk by *that* user, and a host-backed `stat` is redirected,
  so the host kernel fills the guest buffer with the host owner. linuxity
  scrubs the owner fields to `0` in the same stopped syscall-exit window (a
  post-redirect hook, before the task can read the buffer and race the write),
  so `ls -la` shows **`root root`** for every entry and a monitor's USER column
  reads `root` — the world is coherently owned by init, not the box's user.
- **A package manager installs into the world, and the installed program
  runs.** Alpine's real `apk` — reading its installed DB through the namespace,
  extracting a `.apk`, writing files, `chmod`/`chown`ing them, running triggers,
  updating the database — installs a package end to end (`OK: N packages`), and
  the freshly-written binary then executes and walks the rootfs. This works
  because the **whole mutating-path syscall family** (`mkdir`, `rmdir`,
  `unlink`, `rename`, `link`, `symlink`, `chmod`, `chown`, `truncate`,
  `utimensat`, `mknod`, and their `*at` forms) translates each guest path to
  the copy-on-write **overlay upper** layer — never the host's own `/usr`,
  `/etc` — with two-path ops (`rename`/`link`) rewriting *both* operands and
  `chown`-to-root accepted as a vacuous no-op (the world is already root-owned,
  the host process is unprivileged). The pristine lower rootfs is never touched.
- **`/dev` is a populated devtmpfs.** A bare rootfs ships an empty `/dev`, so
  every program that reaches for `/dev/null`, `/dev/zero`, `/dev/urandom` or the
  stdio nodes used to die on `can't open '/dev/null'`. linuxity synthesizes a
  `/dev` that **redirects the character devices to the host's real nodes** —
  the guest opens the true `/dev/null` (endless sink), `/dev/zero`, `/dev/urandom`
  (real CSPRNG) with native `read`/`write`/`mmap` semantics — and wires
  `/dev/std{in,out,err}` → `/proc/self/fd/{0,1,2}` so a shell's `> /dev/stdout`
  reaches the real fd. Zero emulation: the devices are real, we just mount them.
- **`#!` scripts run without double-rooting.** A rootfs scriptlet like
  `#!/bin/sh -e` used to have the host kernel relaunch its interpreter with the
  *host-translated* script path, which linuxity then re-translated
  (`<rootfs>/<rootfs>/...`). Now the exec dispatcher resolves the shebang
  itself and execs the interpreter — chaining its `ld.so` when the interpreter
  is dynamic — with the script as a **guest** path, so `openat` redirects it
  cleanly. Cross-mount **symlinks** resolve too: `/etc/mtab -> /proc/self/mounts`
  crosses from the rootfs into the virtual `/proc`, and following it lands in
  the virtual realm instead of fabricating a nonexistent host path.
- **Arch's `pacman` installs a package from the network, end to end.** On a
  real Arch/glibc bootstrap rootfs, glibc `bash` and `pacman` run, and
  `pacman -Sy <pkg> --noconfirm` **downloads the repo databases, resolves
  dependencies, downloads the package, and installs it**: the binary lands in
  the overlay, the package DB entry is written, and the post-transaction
  **systemd hook** (a `#!/bin/sh` scriptlet) runs. Networking is fully native —
  DNS, TLS, and HTTP are forwarded to the host kernel, identical to bare metal.
  Two subtleties fell along the way: (1) pacman's **multi-threaded libcurl**
  download workers create a short-lived wakeup `eventfd` and open the data file
  nearly at once; in a bare `0,1,2`-only guest both raced for fd `3`, so a
  sibling thread's 8-byte wakeup landed in `core.db` and corrupted it — fixed
  by reserving the low descriptors in the child (mirroring a shell-launched
  process that inherits open fds). (2) `pacman -U <pkg>.pkg.tar.zst` installs a
  local package the same way. pacman 7's download **sandbox** (`DownloadUser`,
  Landlock, seccomp) is accepted vacuously — setuid/Landlock are no-ops because
  linuxity's namespace already confines the guest — but the sandbox's forked
  download child relays completion to the parent over a pipe whose commit step
  is the remaining frontier; with the standard in-process download path it all
  works.

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
  lower first), so the pristine rootfs is never mutated. The full **mutation
  family** (`mkdir`/`rmdir`/`unlink`/`rename`/`link`/`symlink`/`chmod`/`chown`/
  `truncate`/`utimensat`/`mknod` and their `*at` forms) redirects the same way:
  each guest path resolves to the overlay upper layer, directories that exist
  only in the read-only lower are mirrored up on first child-write, two-path
  ops rewrite both operands, and a `symlink`'s literal target is preserved as a
  guest path (resolved later through the namespace, not the host).
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
numbers). Host-backed `stat`/`statx` are redirected but their **owner fields
are scrubbed to `0`** afterwards, so a rootfs unpacked by an unprivileged user
still presents as root-owned. `/sys` is synthesized too — CPU topology (`devices/system/cpu`,
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
`main()`; identity, credentials, lifecycle, `uname`, **signal delivery**,
**per-task pid/session identity**, **`/proc` symlinks**, and now the **whole
file path — reads AND mutations** — are virtualized. In place and proven by
18 test suites:

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

### Bounding the guest: two numbers, kept equal

linuxity is an ABI translator, not a hypervisor, so it never *partitions*
hardware — the guest runs native and draws memory/CPU straight from the host's
global pool via **forwarded** `mmap`/`brk`. But because the guest is a real
host process tree, it is **cgroup-able like any other process**, so "how much
it gets" becomes a policy the host kernel enforces:

```
linuxity --root /alpine --memory 512M --cpus 2 --pids 256 /sbin/apk add ...
```

There are **two** numbers a program cares about, and linuxity keeps them equal:

- **Belief** — what the guest *reads* (`sysinfo`, `/proc/meminfo`,
  `/proc/cpuinfo`, `sched_getaffinity`), so it sizes its caches and thread
  pools sensibly. This comes from the `MachineSpec`.
- **Enforced reality** — what the host kernel actually *lets* it consume.

A single `ResourceSpec` drives BOTH: it (a) writes the host-side bound and (b)
**derives** the `MachineSpec` the guest sees (`--memory 512M` → `MemTotal:
524288 kB`; `--cpus 2` → `nproc` = 2). So a program that sizes a cache to "half
of RAM" fits inside `memory.max` instead of being OOM-killed — belief == the
number you asked to be bounded to, by construction.

Enforcement is **best-effort with graceful fallback** (the Docker-rootless /
Termux discipline):

1. **cgroup v2** — a `payload` cgroup under linuxity's own delegated subtree
   gets `memory.max` / `cpu.max` / `pids.max` / `cpuset.cpus`. When the
   session's controllers aren't yet delegated (the common unprivileged case),
   linuxity **re-execs itself through `systemd-run --user --scope`** to obtain
   a delegated scope, then moves itself into a `supervisor` leaf so it can
   enable the controllers (cgroup v2's "no internal processes" rule). This is
   the precise, kernel-enforced bound.
2. **`setrlimit`** — where no cgroup can be created, `RLIMIT_AS` bounds address
   space as a coarse memory ceiling. (`--pids` is deliberately NOT mapped to
   `RLIMIT_NPROC`, which counts the whole login session, not just the guest
   tree.)

Proven: a guest touching 800 MB under `--memory 256M` is stopped by the host
kernel at ~240 MB (uncapped, the same binary reaches 800 MB); `--pids 32`
stops a fork bomb at 32 tasks; `apk add` installs a package unbounded AND under
a 400 MB cap. The default (no flags) is fully unbounded native speed — the
guest is just another host process.

The road ahead: overlay directory-read UNION (getdents merge of lower+upper),
live advancing `/proc` CPU counters, and richer `futex`/`epoll` coverage for
heavily-threaded programs. The architecture is fixed and machine-checked.

## A coherent uid-0 world (fake root, done right)

The host process is **unprivileged**, but the guest believes it is root — and
that belief has to survive a `stat`. Two holes the host filesystem can't back:
ownership (`chown 1000:1000 f` can't really change owner) and privileged mode
bits (`chmod 4755 f` — the host may drop the setuid bit). linuxity closes them
with a **shadow metadata store** (`kernel/meta_store.hpp`): chmod/chown/fchmod/
fchown RECORD the guest-intended `(mode, uid, gid)`, and every stat/lstat/statx/
newfstatat OVERLAYS them back onto the host inode result. So:

```
linuxity --root /arch /usr/bin/bash -c \
  'touch /tmp/z; chmod 4755 /tmp/z; chown 1000:1000 /tmp/z; stat -c "%a %u:%g" /tmp/z'
# -> 4755 1000:1000
```

round-trips exactly — setuid bit and non-root owner intact — even though the
real inode never changed owner and the host would have dropped the setuid bit.
Where proot scatters a `.proot-meta-file.<name>` **sidecar** beside every
touched file (polluting the guest tree), linuxity keeps ONE consolidated
`.linuxity-meta` journal in the overlay upper layer: never guest-visible,
persists and replays across runs, with tombstones so unlink/rename stay exact.

## Binding host directories in

`--bind host[:guest]` exposes a real host directory inside the guest tree at
`guest` (default: the same path) — proot's `-b`, bubblewrap's `--bind`, but
riding linuxity's path-translation namespace (no privilege, no real `mount(2)`):

```
linuxity --root /arch --bind ~/project:/work /usr/bin/bash
# /work in the guest IS ~/project on the host; writes land on the real files.
```

Binds register after the rootfs, so a deeper or explicit bind wins by
longest-prefix and can even shadow a rootfs directory. It's a thin wrapper over
the same `FileNamespace::mount_host` the `--root` overlay already uses.
